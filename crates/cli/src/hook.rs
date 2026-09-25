use std::ffi::OsString;
use std::io;
use std::path::Path;

use serde::Serialize;
use storage_scout_core::event::{self, Event, Relevance};

pub use crate::coalesce::Coalescing;
use crate::coalesce::{self, Driven};
use crate::observe::git;
use crate::platform::spawn;
use crate::store::{self, Station};

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
#[serde(rename_all = "kebab-case")]
pub enum Detached {
    Handed,
    Spawned,
}

pub fn detach(policy: &Path, arguments: &[OsString]) -> io::Result<Detached> {
    let state = store::state_dir()?;
    let station = Station::for_policy(&state, policy);
    if coalesce::handed_off(&station)? {
        return Ok(Detached::Handed);
    }
    let program = std::env::current_exe()?;
    spawn::detached(&program, arguments, &state)?;
    Ok(Detached::Spawned)
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
    mut run: impl FnMut() -> Result<T, E>,
) -> Result<Coalescing, CoalesceError<E>> {
    let state = store::state_dir().map_err(CoalesceError::Station)?;
    let station = Station::for_policy(&state, policy);
    coalesce::drive(&station, || {
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
