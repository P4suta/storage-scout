use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use storage_scout_core::event::{self, Event, Relevance};

pub use crate::coalesce::Coalescing;
use crate::coalesce::{self, Driven, Rendezvous};
use crate::observe::git;
use crate::owners::Owners;
use crate::platform::spawn;
use crate::store::{self, Held, Station};

#[must_use]
pub fn relevant(event: Event, arguments: &[String], input: &[u8], repository: &Path) -> bool {
    let updates = if event.reads_updates() {
        event::updates(input)
    } else {
        Vec::new()
    };
    match event::relevance(event, arguments, &updates, None) {
        Relevance::Relevant => true,
        Relevance::Irrelevant => false,
        Relevance::NeedsDefaults => match git::defaults(repository) {
            Ok(defaults) => matches!(
                event::relevance(event, arguments, &updates, Some(&defaults)),
                Relevance::Relevant
            ),
            Err(_unreadable) => true,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "detached", rename_all = "kebab-case")]
pub enum Detached {
    Handed,
    Spawned { pid: u32 },
}

pub fn detach(policy: &Path, arguments: &[OsString]) -> io::Result<Detached> {
    detach_from(policy, arguments, None)
}

pub fn detach_hook(
    policy: &Path,
    arguments: &[OsString],
    directory: &Path,
) -> io::Result<Detached> {
    detach_from(policy, arguments, Some(directory))
}

fn detach_from(
    policy: &Path,
    arguments: &[OsString],
    directory: Option<&Path>,
) -> io::Result<Detached> {
    let state = store::state_dir()?;
    let station = Station::for_policy(&state, policy);
    let request = Request::new(&station, directory);
    if coalesce::handed_off(&request)? {
        return Ok(Detached::Handed);
    }
    let program = std::env::current_exe()?;
    let pid = spawn::detached(&program, arguments, &state)?;
    Ok(Detached::Spawned { pid })
}

#[derive(Debug, thiserror::Error)]
pub enum CoalesceError<E> {
    #[error("the run lock or its flag could not be used: {0}")]
    Station(io::Error),
    #[error("{0}")]
    Run(E),
}

pub fn coalesced<T: Serialize, E>(
    policy: &Path,
    run: impl FnMut() -> Result<T, E>,
) -> Result<Coalescing, CoalesceError<E>> {
    coalesced_from(policy, None, run)
}

pub fn coalesced_hook<T: Serialize, E>(
    policy: &Path,
    directory: &Path,
    run: impl FnMut() -> Result<T, E>,
) -> Result<Coalescing, CoalesceError<E>> {
    coalesced_from(policy, Some(directory), run)
}

fn coalesced_from<T: Serialize, E>(
    policy: &Path,
    directory: Option<&Path>,
    mut run: impl FnMut() -> Result<T, E>,
) -> Result<Coalescing, CoalesceError<E>> {
    let state = store::state_dir().map_err(CoalesceError::Station)?;
    let station = Station::for_policy(&state, policy);
    let request = Request::new(&station, directory);
    coalesce::drive(&request, || {
        let document = run().map_err(Recorded::Run)?;
        station.record(&document).map_err(Recorded::Record)
    })
    .map_err(|driven| match driven {
        Driven::Io(error) | Driven::Run(Recorded::Record(error)) => CoalesceError::Station(error),
        Driven::Run(Recorded::Run(error)) => CoalesceError::Run(error),
    })
}

enum Recorded<E> {
    Run(E),
    Record(io::Error),
}

struct Request<'a> {
    station: &'a Station,
    repository: Option<PathBuf>,
}

impl<'a> Request<'a> {
    fn new(station: &'a Station, directory: Option<&Path>) -> Self {
        Self {
            station,
            repository: directory.and_then(|path| Owners::detect().repository(path)),
        }
    }
}

impl Rendezvous for Request<'_> {
    type Held = Held;

    fn raise(&self) -> io::Result<()> {
        self.station.raise_for(self.repository.as_deref())
    }

    fn lower(&self) -> io::Result<bool> {
        self.station.lower()
    }

    fn raised(&self) -> io::Result<bool> {
        self.station.raised()
    }

    fn hold(&self) -> io::Result<Option<Held>> {
        self.station.hold()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn manual_requests_are_global_and_hook_requests_name_the_repository() {
        let temp = testkit::tempdir("hook-request-scope");
        let repository = temp.path().join("repository");
        let nested = repository.join("nested");
        testkit::write_sized(&repository.join(".git/HEAD"), 0);
        testkit::write_sized(&nested.join("file"), 0);
        let station = Station::for_policy(temp.path(), &temp.path().join("auto.toml"));

        let manual = Request::new(&station, None);
        assert!(!manual.raised().unwrap());
        manual.raise().unwrap();
        assert!(manual.raised().unwrap());
        assert!(manual.hold().unwrap().is_some());
        assert_eq!(station.take().unwrap(), Some(BTreeSet::new()));
        assert!(!manual.raised().unwrap());

        let hook = Request::new(&station, Some(&nested));
        hook.raise().unwrap();
        manual.raise().unwrap();
        assert_eq!(station.take().unwrap(), Some(BTreeSet::new()));

        manual.raise().unwrap();
        hook.raise().unwrap();
        assert_eq!(station.take().unwrap(), Some(BTreeSet::new()));

        manual.raise().unwrap();
        assert!(manual.lower().unwrap());
        assert!(!manual.lower().unwrap());

        hook.raise().unwrap();
        assert_eq!(
            station.take().unwrap(),
            Some(BTreeSet::from([repository.join(".git")]))
        );
    }
}
