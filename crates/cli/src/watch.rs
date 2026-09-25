use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};

use serde::Serialize;
use storage_scout_core::location::Location;
use storage_scout_core::ownership::Admits;
use storage_scout_core::reject::Rejection;

use crate::apply::{Mode, Summary};
use crate::auto::{self, AutoPolicy};
use crate::dedupe::{DedupeRun, Focus, Pool};
use crate::platform::{Change, Watcher};
use crate::prune::{self, PruneRun};
use crate::scan::{self, Found, Reach, ScanOptions};
use crate::store::{self, Station};
use crate::{SCHEMA_VERSION, Scout, busy};

const PROFILE_PARTS: [&str; 4] = ["deps", "incremental", "build", "examples"];

#[derive(Debug)]
enum Signal {
    Changed(Change),
    Released(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cause {
    Start,
    Hook,
    Appeared,
    Written,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchRecord {
    pub schema_version: u32,
    pub command: &'static str,
    pub cause: Cause,
    pub watching: usize,
    pub reap: Option<Summary>,
    pub prune: Option<PruneRun>,
    pub dedupe: Option<DedupeRun>,
}

impl WatchRecord {
    #[must_use]
    pub fn eventful(&self) -> bool {
        let reaped = self
            .reap
            .as_ref()
            .is_some_and(|summary| !summary.outcomes.is_empty());
        let pruned = self
            .prune
            .as_ref()
            .is_some_and(|run| run.totals.files() > 0 || run.failed());
        let shared = self
            .dedupe
            .as_ref()
            .is_some_and(|run| run.totals.shared.files > 0 || run.totals.failed.files > 0);
        reaped || pruned || shared
    }

    #[must_use]
    pub fn failed(&self) -> bool {
        let reaped = self.reap.as_ref().is_some_and(Summary::failed_to_delete);
        let pruned = self.prune.as_ref().is_some_and(PruneRun::failed);
        let shared = self.dedupe.as_ref().is_some_and(DedupeRun::failed);
        reaped || pruned || shared
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("cannot watch for changes here: {0}")]
    Events(io::Error),
    #[error("cannot list the candidates: {0}")]
    Sight(Rejection),
    #[error("cannot coordinate with other runs: {0}")]
    Station(io::Error),
    #[error("cannot record a run: {0}")]
    Record(io::Error),
    #[error("the event stream ended")]
    Ended,
}

struct Hooks<'a> {
    station: Station,
    state: PathBuf,
    log: Option<PathBuf>,
    render: &'a dyn Fn(&WatchRecord) -> io::Result<()>,
}

impl Hooks<'_> {
    fn raised(&self) -> io::Result<bool> {
        self.station.lower()
    }

    fn record(&self, record: &WatchRecord) -> io::Result<()> {
        (self.render)(record)?;
        if let Some(log) = &self.log {
            store::append_line(log, record)?;
        }
        self.station.record(record)
    }
}

struct Session<'a> {
    scout: Scout,
    policy: &'a AutoPolicy,
    excludes: Vec<Location>,
    hooks: &'a Hooks<'a>,
    world: BTreeMap<PathBuf, Found>,
    hosts: BTreeSet<PathBuf>,
    dirty: BTreeSet<PathBuf>,
    waiting: BTreeSet<PathBuf>,
    pool: Pool,
    sender: Sender<Signal>,
    watcher: Watcher,
}

fn appeared_already(appeared: &[Found], path: &Path) -> bool {
    appeared.iter().any(|found| found.path() == path)
}

const fn let_go(found: &Found) -> bool {
    Admits::Settled.admits(found.candidate().settlement())
}

fn watched(root: &Path, survey: Option<&busy::Survey>) -> Vec<PathBuf> {
    let mut directories = vec![root.to_path_buf()];
    if let Some(parent) = root.parent() {
        directories.push(parent.to_path_buf());
    }
    for lock in survey.map_or(&[][..], |survey| survey.locks.as_slice()) {
        if let Some(profile) = lock.path().parent() {
            directories.push(profile.to_path_buf());
            directories.extend(PROFILE_PARTS.iter().map(|part| profile.join(part)));
        }
    }
    directories
}

fn surveyed(root: &Path) -> Option<busy::Survey> {
    match busy::survey(root) {
        Ok(survey) => Some(survey),
        Err(_unreadable) => None,
    }
}

fn wait_for(lock: PathBuf, root: PathBuf, sender: Sender<Signal>) -> io::Result<()> {
    std::thread::Builder::new()
        .name("storage-scout-waiter".to_owned())
        .spawn(move || {
            if let Ok(file) = File::open(&lock) {
                let _waited = file.lock();
            }
            let _closed = sender.send(Signal::Released(root));
        })
        .map(drop)
}

impl Session<'_> {
    fn owner(&self, directory: &Path) -> Option<PathBuf> {
        directory
            .ancestors()
            .find(|ancestor| self.world.contains_key(*ancestor))
            .map(Path::to_path_buf)
    }

    fn written(&self, root: &Path) -> bool {
        self.world
            .get(root)
            .is_some_and(|found| found.candidate().kind().protocol().is_some())
    }

    fn record(&self, record: &WatchRecord) -> Result<(), WatchError> {
        if record.eventful() || record.cause == Cause::Start {
            self.hooks.record(record).map_err(WatchError::Record)?;
        }
        Ok(())
    }

    fn follow(&self, root: &Path, survey: Option<&busy::Survey>) -> Result<(), WatchError> {
        let directories = watched(root, survey);
        let borrowed = directories.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        self.watcher.watch(&borrowed).map_err(WatchError::Events)
    }

    fn remember_hosts(&mut self, hosts: Vec<PathBuf>) -> Result<(), WatchError> {
        let fresh = hosts
            .into_iter()
            .filter(|host| self.hosts.insert(host.clone()))
            .collect::<Vec<_>>();
        self.follow_hosts(&fresh)
    }

    fn follow_hosts(&self, hosts: &[PathBuf]) -> Result<(), WatchError> {
        let borrowed = hosts.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        self.watcher.watch(&borrowed).map_err(WatchError::Events)
    }

    fn reap(&mut self, settled: &[&Found]) -> Option<Summary> {
        let summary = auto::reap(&self.scout, &self.policy.selection, settled, Mode::Execute);
        for found in settled {
            self.forget(found.path());
        }
        summary
    }

    fn forget(&mut self, root: &Path) {
        self.world.remove(root);
        self.dirty.remove(root);
        self.pool.forget(root);
    }

    fn adopt(&mut self, found: Found) -> Result<(), WatchError> {
        let root = found.path().to_path_buf();
        let survey = surveyed(&root);
        self.follow(&root, survey.as_ref())?;
        self.dirty.insert(root.clone());
        self.world.insert(root, found);
        Ok(())
    }

    fn start(&mut self) -> Result<(), WatchError> {
        let sighting = self
            .scout
            .sighting(&self.policy.selection.options(), Reach::Everything)
            .map_err(WatchError::Sight)?;
        self.remember_hosts(sighting.hosts)?;
        let sighted = sighting
            .report
            .candidates
            .into_iter()
            .filter(|found| self.policy.selection.admits(found.candidate()))
            .collect::<Vec<_>>();
        let (settled, remaining): (Vec<&Found>, Vec<&Found>) =
            sighted.iter().partition(|found| let_go(found));
        let reap = auto::reap(&self.scout, &self.policy.selection, &settled, Mode::Execute);
        let remaining = remaining.into_iter().cloned().collect::<Vec<_>>();
        let pruned = prune::run(
            &remaining,
            &self.excludes,
            self.scout.protection(),
            self.scout.owners(),
            Mode::Execute,
        );
        for found in &remaining {
            let _fresh = self
                .pool
                .stock(found, &self.excludes, self.scout.protection());
            let root = found.path().to_path_buf();
            let survey = surveyed(&root);
            self.follow(&root, survey.as_ref())?;
            self.world.insert(root, found.clone());
        }
        let shared = self.pool.share(
            &Focus::Everything,
            &self.excludes,
            self.scout.protection(),
            Mode::Execute,
        );
        self.record(&WatchRecord {
            schema_version: SCHEMA_VERSION,
            command: "watch",
            watching: self.world.len(),
            cause: Cause::Start,
            reap,
            prune: Some(pruned.summarized()),
            dedupe: Some(shared.summarized()),
        })
    }

    fn reown(&mut self) -> Result<(), WatchError> {
        let settled = self
            .world
            .iter()
            .filter(|(root, found)| {
                let markers = match found.candidate().kind().protocol() {
                    Some(_) => surveyed(root)
                        .map(|survey| survey.markers)
                        .unwrap_or_default(),
                    None => Vec::new(),
                };
                Admits::Settled.admits(self.scout.owners().of(root, &markers).settlement())
            })
            .map(|(_, found)| found.clone())
            .collect::<Vec<_>>();
        let reap = self.reap(&settled.iter().collect::<Vec<_>>());
        self.record(&WatchRecord {
            schema_version: SCHEMA_VERSION,
            command: "watch",
            watching: self.world.len(),
            cause: Cause::Hook,
            reap,
            prune: None,
            dedupe: None,
        })
    }

    fn refresh(&mut self) -> Result<(), WatchError> {
        if self.watcher.recursive() {
            self.reown()
        } else {
            self.resight()
        }
    }

    fn resight(&mut self) -> Result<(), WatchError> {
        let sighting = self
            .scout
            .sighting(&self.policy.selection.options(), Reach::Everything)
            .map_err(WatchError::Sight)?;
        self.remember_hosts(sighting.hosts)?;
        let sighted = sighting
            .report
            .candidates
            .into_iter()
            .filter(|found| self.policy.selection.admits(found.candidate()))
            .map(|found| (found.path().to_path_buf(), found))
            .collect::<BTreeMap<_, _>>();
        let vanished = self
            .world
            .keys()
            .filter(|root| !sighted.contains_key(*root))
            .cloned()
            .collect::<Vec<_>>();
        for root in vanished {
            self.forget(&root);
        }
        let settled = sighted
            .values()
            .filter(|found| let_go(found))
            .collect::<Vec<_>>();
        let reap = self.reap(&settled);
        for (root, found) in &sighted {
            if let_go(found) {
                continue;
            }
            if self.world.contains_key(root) {
                self.world.insert(root.clone(), found.clone());
            } else {
                self.adopt(found.clone())?;
            }
        }
        self.record(&WatchRecord {
            schema_version: SCHEMA_VERSION,
            command: "watch",
            watching: self.world.len(),
            cause: Cause::Hook,
            reap,
            prune: None,
            dedupe: None,
        })
    }

    fn appear(&mut self, directories: &BTreeSet<PathBuf>) -> Result<(), WatchError> {
        let mut pending = directories.iter().cloned().collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut appeared = Vec::new();
        while let Some(directory) = pending.pop() {
            if !visited.insert(directory.clone()) {
                continue;
            }
            let options = ScanOptions::sighting(
                std::slice::from_ref(&directory),
                &self.policy.selection.excludes,
            );
            let Ok(sighting) = self.scout.sighting(&options, Reach::Children) else {
                continue;
            };
            let hosts = sighting
                .hosts
                .into_iter()
                .filter(|host| self.hosts.insert(host.clone()))
                .collect::<Vec<_>>();
            self.follow_hosts(&hosts)?;
            pending.extend(hosts);
            let seen = sighting
                .report
                .candidates
                .into_iter()
                .filter(|found| self.policy.selection.admits(found.candidate()))
                .map(|found| (found.path().to_path_buf(), found))
                .collect::<BTreeMap<_, _>>();
            let gone = self
                .world
                .keys()
                .filter(|root| {
                    root.parent() == Some(directory.as_path()) && !seen.contains_key(*root)
                })
                .cloned()
                .collect::<Vec<_>>();
            for root in gone {
                self.forget(&root);
            }
            for found in seen.into_values() {
                if !self.world.contains_key(found.path())
                    && !appeared_already(&appeared, found.path())
                {
                    appeared.push(found);
                }
            }
        }
        let settled = appeared
            .iter()
            .filter(|found| let_go(found))
            .collect::<Vec<_>>();
        let reap = self.reap(&settled);
        for found in appeared.iter().filter(|found| !let_go(found)) {
            self.adopt(found.clone())?;
        }
        self.record(&WatchRecord {
            schema_version: SCHEMA_VERSION,
            command: "watch",
            watching: self.world.len(),
            cause: Cause::Appeared,
            reap,
            prune: None,
            dedupe: None,
        })
    }

    fn process(&mut self, root: &Path) -> Result<(), WatchError> {
        let Some(found) = self.world.get(root).cloned() else {
            self.dirty.remove(root);
            return Ok(());
        };
        let Ok(survey) = busy::survey(root) else {
            self.forget(root);
            return Ok(());
        };
        self.dirty.remove(root);
        match busy::held(&survey.locks) {
            busy::Holding::Free => {},
            busy::Holding::Unknown => return Ok(()),
            busy::Holding::Held(lock) => {
                wait_for(lock.to_path_buf(), root.to_path_buf(), self.sender.clone())
                    .map_err(WatchError::Events)?;
                self.waiting.insert(root.to_path_buf());
                return Ok(());
            },
        }
        let ownership = self.scout.owners().of(root, &survey.markers);
        if Admits::Settled.admits(ownership.settlement()) {
            let reap = self.reap(&[&found]);
            return self.record(&WatchRecord {
                schema_version: SCHEMA_VERSION,
                command: "watch",
                watching: self.world.len(),
                cause: Cause::Written,
                reap,
                prune: None,
                dedupe: None,
            });
        }
        let pruned = prune::run(
            std::slice::from_ref(&found),
            &self.excludes,
            self.scout.protection(),
            self.scout.owners(),
            Mode::Execute,
        );
        let identities = self
            .pool
            .stock(&found, &self.excludes, self.scout.protection());
        let roots = BTreeSet::from([root.to_path_buf()]);
        let shared = self.pool.share(
            &Focus::Fresh {
                roots: &roots,
                identities: &identities,
            },
            &self.excludes,
            self.scout.protection(),
            Mode::Execute,
        );
        self.record(&WatchRecord {
            schema_version: SCHEMA_VERSION,
            command: "watch",
            watching: self.world.len(),
            cause: Cause::Written,
            reap: None,
            prune: Some(pruned.summarized()),
            dedupe: Some(shared.summarized()),
        })
    }

    fn settle(&mut self) -> Result<(), WatchError> {
        let ready = self
            .dirty
            .iter()
            .filter(|root| !self.waiting.contains(*root))
            .cloned()
            .collect::<Vec<_>>();
        for root in ready {
            self.process(&root)?;
        }
        Ok(())
    }

    fn turn(&mut self, signals: Vec<Signal>) -> Result<(), WatchError> {
        self.scout = self.scout.refreshed();
        let hooked = self.hooks.raised().map_err(WatchError::Station)?;
        let mut lost = false;
        let mut appeared = BTreeSet::new();
        for signal in signals {
            match signal {
                Signal::Changed(Change::Lost) => {
                    lost = true;
                    self.dirty.extend(self.world.keys().cloned());
                },
                Signal::Changed(Change::Directory(directory)) => {
                    if directory.starts_with(&self.hooks.state) {
                        continue;
                    }
                    match self.owner(&directory) {
                        Some(root) if self.written(&root) => {
                            self.dirty.insert(root);
                        },
                        Some(_) => {},
                        None => {
                            appeared.insert(directory);
                        },
                    }
                },
                Signal::Released(root) => {
                    self.waiting.remove(&root);
                    self.dirty.insert(root);
                },
            }
        }
        if lost {
            self.resight()?;
        } else if hooked {
            self.refresh()?;
        } else if !appeared.is_empty() {
            self.appear(&appeared)?;
        }
        self.settle()
    }
}

pub(crate) fn watch(
    scout: &Scout,
    policy: &AutoPolicy,
    config: &Path,
    render: &dyn Fn(&WatchRecord) -> io::Result<()>,
) -> WatchError {
    match watching(scout, policy, config, render) {
        Ok(never) => match never {},
        Err(error) => error,
    }
}

fn watching(
    scout: &Scout,
    policy: &AutoPolicy,
    config: &Path,
    render: &dyn Fn(&WatchRecord) -> io::Result<()>,
) -> Result<std::convert::Infallible, WatchError> {
    let state = store::state_dir().map_err(WatchError::Station)?;
    let station = Station::for_policy(&state, config);
    let _held = station.wait().map_err(WatchError::Station)?;
    let hooks = Hooks {
        station,
        state,
        log: policy.log_file.clone(),
        render,
    };
    let hooks = &hooks;
    let (sender, receiver): (Sender<Signal>, Receiver<Signal>) = mpsc::channel();
    let mut paths = policy.selection.roots.clone();
    paths.push(hooks.state.clone());
    let deliver = sender.clone();
    let watcher = Watcher::start(&paths, move |change| {
        let _closed = deliver.send(Signal::Changed(change));
    })
    .map_err(WatchError::Events)?;
    let mut session = Session {
        scout: scout.refreshed(),
        policy,
        excludes: scan::excludes(&policy.selection.excludes),
        hooks,
        world: BTreeMap::new(),
        hosts: BTreeSet::new(),
        dirty: BTreeSet::new(),
        waiting: BTreeSet::new(),
        pool: Pool::default(),
        sender,
        watcher,
    };
    let _raised = hooks.raised().map_err(WatchError::Station)?;
    session.start()?;
    loop {
        let first = receiver.recv().map_err(|_closed| WatchError::Ended)?;
        let mut signals = vec![first];
        signals.extend(receiver.try_iter());
        session.turn(signals)?;
    }
}

#[cfg(test)]
mod tests {
    use storage_scout_core::size::Bytes;

    use super::*;
    use crate::dedupe::Totals;
    use crate::prune::Removed;

    fn record(cause: Cause) -> WatchRecord {
        WatchRecord {
            schema_version: SCHEMA_VERSION,
            command: "watch",
            cause,
            watching: 0,
            reap: None,
            prune: None,
            dedupe: None,
        }
    }

    fn pruned(removed: Removed, failures: Vec<prune::PruneFailure>) -> PruneRun {
        PruneRun {
            schema_version: SCHEMA_VERSION,
            command: "prune",
            mode: Mode::Execute,
            subjects: Vec::new(),
            totals: removed,
            failures,
            observed_freed: None,
        }
    }

    fn shared(totals: Totals) -> DedupeRun {
        DedupeRun {
            schema_version: SCHEMA_VERSION,
            command: "dedupe",
            mode: Mode::Execute,
            subjects: Vec::new(),
            totals,
            observed_freed: None,
            pairs: Vec::new(),
        }
    }

    #[test]
    fn only_a_step_that_changed_something_or_failed_is_worth_a_record() {
        let mut quiet = record(Cause::Written);
        quiet.prune = Some(pruned(Removed::default(), Vec::new()));
        quiet.dedupe = Some(shared(Totals::default()));
        quiet.reap = Some(Summary {
            schema_version: SCHEMA_VERSION,
            mode: Mode::Execute,
            predicted_freed: None,
            observed_freed: None,
            outcomes: Vec::new(),
        });
        assert!(!quiet.eventful());
        assert!(!quiet.failed());

        let mut removed = Removed::default();
        removed.stale_objects.add(1);
        let mut pruning = record(Cause::Written);
        pruning.prune = Some(pruned(removed, Vec::new()));
        assert!(pruning.eventful());

        let mut failing = record(Cause::Written);
        failing.prune = Some(pruned(
            Removed::default(),
            vec![prune::PruneFailure {
                rule: storage_scout_core::prune::Rule::StaleObject,
                rejection: Rejection::NoRoots,
            }],
        ));
        assert!(failing.eventful());
        assert!(failing.failed());

        let mut sharing = Totals::default();
        sharing.shared.add(1);
        let mut shares = record(Cause::Written);
        shares.dedupe = Some(shared(sharing));
        assert!(shares.eventful());
        assert!(!shares.failed());

        let mut broken = Totals::default();
        broken.failed.add(1);
        let mut breaks = record(Cause::Written);
        breaks.dedupe = Some(shared(broken));
        assert!(breaks.eventful());
        assert!(breaks.failed());
        assert_eq!(broken.failed.bytes, Bytes::new(1));
    }
}
