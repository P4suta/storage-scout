use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

use serde::Serialize;
use storage_scout_core::location::Location;
use storage_scout_core::lock::Protocol;
use storage_scout_core::ownership::Admits;
use storage_scout_core::reject::Rejection;

use crate::apply::{Mode, Summary};
use crate::auto::{self, AutoPolicy};
use crate::dedupe::{DedupeRun, Focus, Pool};
use crate::platform::{self, Change, Coverage, Event, Watcher};
use crate::prune::{self, PruneRun, Scope};
use crate::scan::{self, Found, Reach, ScanOptions};
use crate::store::{self, Station};
use crate::{SCHEMA_VERSION, Scout, busy, owners};

const PROFILE_PARTS: [&str; 4] = ["deps", "incremental", "build", "examples"];
const GIT_DIRECTORY: &str = ".git";
const EVIDENCE: [&str; 13] = [
    "Cargo.toml",
    "CACHEDIR.TAG",
    "owner.json",
    ".rustc_info.json",
    "pom.xml",
    "package.json",
    "pyproject.toml",
    "pyvenv.cfg",
    "CMakeCache.txt",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
];
const REFS: [&str; 4] = ["refs", "packed-refs", "HEAD", "worktrees"];

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
    fn taken(&self) -> io::Result<Option<BTreeSet<PathBuf>>> {
        self.station.take()
    }

    fn record(&self, record: &WatchRecord) -> io::Result<()> {
        (self.render)(record)?;
        if let Some(log) = &self.log {
            store::append_line(log, record)?;
        }
        self.station.record(record)
    }
}

struct Watched {
    found: Found,
    repository: Option<PathBuf>,
    survey: Option<busy::Survey>,
    changed: BTreeMap<PathBuf, Event>,
    whole: bool,
    resurvey: bool,
}

struct Session<'a> {
    scout: Scout,
    roots: Vec<PathBuf>,
    policy: &'a AutoPolicy,
    excludes: Vec<Location>,
    hooks: &'a Hooks<'a>,
    world: BTreeMap<PathBuf, Watched>,
    dirty: BTreeSet<PathBuf>,
    waiting: BTreeMap<PathBuf, JoinHandle<()>>,
    pool: Pool,
    sender: Sender<Signal>,
    watcher: Watcher,
    covered: bool,
    walked: BTreeSet<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GitArea {
    Refs(PathBuf),
    Other,
    Outside,
}

fn git_area(path: &Path) -> GitArea {
    let Some(repository) = path
        .ancestors()
        .find(|ancestor| ancestor.file_name() == Some(OsStr::new(GIT_DIRECTORY)))
    else {
        return GitArea::Outside;
    };
    match path
        .strip_prefix(repository)
        .map(|inside| inside.components().next())
    {
        Ok(Some(first)) if REFS.contains(&first.as_os_str().to_str().unwrap_or_default()) => {
            GitArea::Refs(repository.to_path_buf())
        },
        Ok(_) | Err(_) => GitArea::Other,
    }
}

fn evidence(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| {
            EVIDENCE
                .iter()
                .any(|known| name.eq_ignore_ascii_case(known))
        })
}

fn refs(directory: &Path) -> Vec<PathBuf> {
    let git = directory.join(GIT_DIRECTORY);
    if !is_directory(&git) {
        return Vec::new();
    }
    let mut found = vec![git.clone()];
    let mut pending = REFS
        .iter()
        .map(|part| git.join(part))
        .filter(|path| is_directory(path))
        .collect::<Vec<_>>();
    while let Some(next) = pending.pop() {
        pending.extend(
            fs::read_dir(&next)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|entry| matches!(entry.file_type(), Ok(kind) if kind.is_dir()))
                .map(|entry| entry.path()),
        );
        found.push(next);
    }
    found
}

fn is_directory(path: &Path) -> bool {
    matches!(fs::symlink_metadata(path), Ok(metadata) if metadata.is_dir())
}

fn bookkeeping(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        name == owners::MARKER_NAME || Protocol::of(name.as_encoded_bytes()).is_some()
    })
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

fn wait_for(lock: PathBuf, root: PathBuf, sender: Sender<Signal>) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("storage-scout-waiter".to_owned())
        .spawn(move || {
            if let Ok(file) = File::open(&lock) {
                let _waited = file.lock();
            }
            let _closed = sender.send(Signal::Released(root));
        })
}

impl Session<'_> {
    fn owner(&self, path: &Path) -> Option<PathBuf> {
        path.ancestors()
            .find(|ancestor| self.world.contains_key(*ancestor))
            .map(Path::to_path_buf)
    }

    fn written(&self, root: &Path) -> bool {
        self.world
            .get(root)
            .is_some_and(|watched| watched.found.candidate().kind().protocol().is_some())
    }

    fn record(&self, record: &WatchRecord) -> Result<(), WatchError> {
        if record.eventful() || record.cause == Cause::Start {
            self.hooks.record(record).map_err(WatchError::Record)?;
        }
        Ok(())
    }

    fn follow(&mut self, directories: &[PathBuf]) -> Result<(), WatchError> {
        let borrowed = directories.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        match self.watcher.watch(&borrowed).map_err(WatchError::Events)? {
            Coverage::Complete => {},
            Coverage::Partial => self.covered = false,
        }
        Ok(())
    }

    fn saw(&mut self, walked: &[PathBuf]) -> Result<(), WatchError> {
        self.walked.extend(walked.iter().cloned());
        if self.watcher.recursive() {
            return Ok(());
        }
        let mut directories = walked.to_vec();
        directories.extend(walked.iter().flat_map(|directory| refs(directory)));
        self.follow(&directories)
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

    fn adopt(&mut self, found: Found, state: Adopted) -> Result<(), WatchError> {
        let root = found.path().to_path_buf();
        let survey = surveyed(&root);
        self.follow(&watched(&root, survey.as_ref()))?;
        let whole = state == Adopted::Unprocessed;
        if whole {
            self.dirty.insert(root.clone());
        }
        self.world.insert(
            root.clone(),
            Watched {
                found,
                repository: owners::repository(&root),
                survey,
                changed: BTreeMap::new(),
                whole,
                resurvey: false,
            },
        );
        Ok(())
    }

    fn admitted(&self, sighting: scan::Sighting) -> Vec<Found> {
        sighting
            .report
            .candidates
            .into_iter()
            .filter(|found| self.policy.selection.admits(found.candidate()))
            .collect()
    }

    fn start(&mut self) -> Result<(), WatchError> {
        let sighting = self
            .scout
            .sighting(&self.policy.selection.options(), Reach::Everything)
            .map_err(WatchError::Sight)?;
        self.saw(&sighting.walked)?;
        let sighted = self.admitted(sighting);
        let (settled, remaining): (Vec<&Found>, Vec<&Found>) = sighted
            .iter()
            .partition(|found| auto::lets_go(&self.scout, found));
        let reap = auto::reap(&self.scout, &self.policy.selection, &settled, Mode::Execute);
        let remaining = remaining.into_iter().cloned().collect::<Vec<_>>();
        let pruned = prune::run(
            &remaining,
            &self.excludes,
            self.scout.protection(),
            self.scout.owners(),
            Mode::Execute,
        );
        for found in remaining {
            let _fresh = self
                .pool
                .stock(&found, &self.excludes, self.scout.protection());
            self.adopt(found, Adopted::Processed)?;
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

    fn reown(&mut self, scope: Option<&BTreeSet<PathBuf>>) -> Result<(), WatchError> {
        self.scout.owners().forget(scope);
        let settled = self
            .world
            .values()
            .filter(|watched| {
                scope.is_none_or(|repositories| {
                    watched
                        .repository
                        .as_ref()
                        .is_some_and(|repository| repositories.contains(repository))
                })
            })
            .filter(|watched| {
                let markers = watched
                    .survey
                    .as_ref()
                    .map_or(&[][..], |survey| survey.markers.as_slice());
                Admits::Settled.admits(
                    self.scout
                        .owners()
                        .of(watched.found.path(), markers)
                        .settlement(),
                )
            })
            .map(|watched| watched.found.clone())
            .filter(|found| auto::confirmed(&self.scout, found.path()))
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

    fn resight(&mut self, loss: Loss) -> Result<(), WatchError> {
        self.scout.owners().forget(None);
        let sighting = self
            .scout
            .sighting(&self.policy.selection.options(), Reach::Everything)
            .map_err(WatchError::Sight)?;
        self.saw(&sighting.walked)?;
        let sighted = self
            .admitted(sighting)
            .into_iter()
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
        let (settled, remaining): (Vec<&Found>, Vec<&Found>) = sighted
            .values()
            .partition(|found| auto::lets_go(&self.scout, found));
        let reap = self.reap(&settled);
        for found in remaining {
            match self.world.get_mut(found.path()) {
                Some(watched) => {
                    watched.found = found.clone();
                    if loss == Loss::Lost {
                        self.lost_track(found.path());
                    }
                },
                None => self.adopt(found.clone(), Adopted::Unprocessed)?,
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

    fn outside(&self, directory: &Path) -> bool {
        self.owner(directory).is_none() && self.roots.iter().any(|root| directory.starts_with(root))
    }

    fn targets(
        &self,
        appeared: &BTreeSet<PathBuf>,
        rescanned: &BTreeSet<PathBuf>,
    ) -> BTreeMap<PathBuf, Reach> {
        let mut targets = BTreeMap::new();
        for path in appeared {
            if evidence(path) {
                if let Some(directory) = path.parent() {
                    targets
                        .entry(directory.to_path_buf())
                        .or_insert(Reach::Children);
                }
            } else if is_directory(path) {
                targets.insert(path.clone(), Reach::Everything);
            }
        }
        for directory in rescanned {
            if !self.walked.contains(directory) {
                if is_directory(directory) {
                    targets.insert(directory.clone(), Reach::Everything);
                }
                continue;
            }
            for entry in fs::read_dir(directory).into_iter().flatten().flatten() {
                let path = entry.path();
                if matches!(entry.file_type(), Ok(kind) if kind.is_dir()) {
                    if !self.walked.contains(&path) && !self.world.contains_key(&path) {
                        targets.insert(path, Reach::Everything);
                    }
                } else if evidence(&path) {
                    targets.entry(directory.clone()).or_insert(Reach::Children);
                }
            }
        }
        targets.retain(|directory, _| self.outside(directory));
        let everything = targets
            .iter()
            .filter(|(_, reach)| **reach == Reach::Everything)
            .map(|(directory, _)| directory.clone())
            .collect::<BTreeSet<_>>();
        targets.retain(|directory, _| {
            !directory
                .ancestors()
                .skip(1)
                .any(|ancestor| everything.contains(ancestor))
        });
        targets
    }

    fn sight(&self, directory: &Path, reach: Reach) -> Option<scan::Sighting> {
        let excludes = &self.policy.selection.excludes;
        let sighting = match (
            self.roots.iter().any(|root| root == directory),
            directory.parent(),
            directory.file_name(),
        ) {
            (false, Some(parent), Some(name)) => {
                self.scout.sighting_into(parent, (name, reach), excludes)
            },
            (true, _, _) | (false, None, _) | (false, _, None) => self.scout.sighting(
                &ScanOptions::sighting(&[directory.to_path_buf()], excludes),
                reach,
            ),
        };
        match sighting {
            Ok(sighting) => Some(sighting),
            Err(_gone) => None,
        }
    }

    fn examine(&mut self, targets: BTreeMap<PathBuf, Reach>) -> Result<(), WatchError> {
        for (directory, reach) in &targets {
            tracing::debug!(directory = %directory.display(), ?reach, "examine");
        }
        let mut appeared = BTreeMap::new();
        let mut walked = Vec::new();
        for (directory, reach) in targets {
            if let Some(sighting) = self.sight(&directory, reach) {
                walked.extend(sighting.walked.iter().cloned());
                for found in self.admitted(sighting) {
                    if !self.world.contains_key(found.path()) {
                        appeared.insert(found.path().to_path_buf(), found);
                    }
                }
            }
        }
        self.saw(&walked)?;
        let (settled, remaining): (Vec<&Found>, Vec<&Found>) = appeared
            .values()
            .partition(|found| auto::lets_go(&self.scout, found));
        let reap = self.reap(&settled);
        for found in remaining {
            self.adopt(found.clone(), Adopted::Unprocessed)?;
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
        self.dirty.remove(root);
        let Some(entry) = self.world.get_mut(root) else {
            return Ok(());
        };
        let fresh_survey = entry.whole || entry.resurvey || entry.survey.is_none();
        if fresh_survey {
            entry.survey = surveyed(root);
            entry.resurvey = false;
        }
        let Some(survey) = entry.survey.clone() else {
            self.forget(root);
            return Ok(());
        };
        if fresh_survey {
            self.follow(&watched(root, Some(&survey)))?;
        }
        match busy::held(&survey.locks) {
            busy::Holding::Free => {},
            busy::Holding::Unknown => return Ok(()),
            busy::Holding::Held(lock) => {
                let waiter = wait_for(lock.to_path_buf(), root.to_path_buf(), self.sender.clone())
                    .map_err(WatchError::Events)?;
                self.waiting.insert(root.to_path_buf(), waiter);
                return Ok(());
            },
        }
        let Some(current) = self.world.get_mut(root) else {
            return Ok(());
        };
        let found = current.found.clone();
        let changed = std::mem::take(&mut current.changed);
        let whole = std::mem::replace(&mut current.whole, false);
        tracing::debug!(
            root = %root.display(),
            whole,
            changed = changed.len(),
            fresh_survey,
            "process"
        );
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
        let paths = changed.keys().cloned().collect::<BTreeSet<_>>();
        let scope = if whole {
            Scope::Everything
        } else {
            Scope::Changed(&paths)
        };
        let pruned = prune::run_changed(
            &found,
            &survey,
            scope,
            (&self.excludes, self.scout.protection(), self.scout.owners()),
        );
        let fresh = if whole {
            self.pool
                .stock(&found, &self.excludes, self.scout.protection())
        } else {
            self.pool.note(root, &changed)
        };
        let roots = BTreeSet::from([root.to_path_buf()]);
        let shared = self.pool.share(
            &Focus::Fresh {
                roots: &roots,
                fresh: &fresh,
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
            .filter(|root| !self.waiting.contains_key(*root))
            .cloned()
            .collect::<Vec<_>>();
        for root in ready {
            self.process(&root)?;
        }
        Ok(())
    }

    fn lost_track(&mut self, root: &Path) {
        if !self.written(root) {
            return;
        }
        if let Some(watched) = self.world.get_mut(root) {
            let parts = watched
                .survey
                .iter()
                .flat_map(|survey| &survey.locks)
                .filter_map(|lock| lock.path().parent())
                .flat_map(|profile| PROFILE_PARTS.iter().map(|part| profile.join(part)))
                .collect::<Vec<_>>();
            for part in parts {
                watched.changed.insert(part, Event::Unsure);
            }
            watched.resurvey = true;
        }
        self.dirty.insert(root.to_path_buf());
    }

    fn changed_within(&mut self, root: PathBuf, path: PathBuf, event: Event) {
        let direct =
            (path == root || path.parent() == Some(root.as_path())) && event != Event::Written;
        if let Some(watched) = self.world.get_mut(&root) {
            watched.resurvey |= direct || bookkeeping(&path);
            watched.changed.insert(path, event);
        }
        self.dirty.insert(root);
    }

    fn turn(&mut self, signals: Vec<Signal>) -> Result<(), WatchError> {
        let hooked = self.hooks.taken().map_err(WatchError::Station)?;
        let mut refs = BTreeSet::new();
        let mut lost = false;
        let mut appeared = BTreeSet::new();
        let mut rescanned = BTreeSet::new();
        for signal in signals {
            match signal {
                Signal::Changed(Change::Lost) => lost = true,
                Signal::Changed(Change::Entry { path, event }) => {
                    if path.starts_with(&self.hooks.state) {
                        continue;
                    }
                    match git_area(&path) {
                        GitArea::Refs(repository) => {
                            refs.insert(repository);
                            continue;
                        },
                        GitArea::Other => continue,
                        GitArea::Outside => {},
                    }
                    match (self.owner(&path), event) {
                        (Some(root), Event::Vanished) if root == path => self.forget(&root),
                        (Some(root), _) if self.written(&root) => {
                            self.changed_within(root, path, event);
                        },
                        (Some(_), _) => {},
                        (None, Event::Vanished) => {
                            self.walked.remove(&path);
                        },
                        (None, Event::Written) if !evidence(&path) => {},
                        (None, Event::Unsure) => {
                            rescanned.insert(path);
                        },
                        (None, Event::Appeared | Event::Written) => {
                            appeared.insert(path);
                        },
                    }
                },
                Signal::Released(root) => {
                    if let Some(waiter) = self.waiting.remove(&root) {
                        let _joined = waiter.join();
                    }
                    self.dirty.insert(root);
                },
            }
        }
        tracing::debug!(
            lost,
            hooked = ?hooked,
            refs = refs.len(),
            appeared = appeared.len(),
            rescanned = rescanned.len(),
            dirty = self.dirty.len(),
            "turn"
        );
        if lost {
            self.resight(Loss::Lost)?;
        } else {
            match (hooked, self.covered) {
                (Some(_), false) => self.resight(Loss::Kept)?,
                (Some(repositories), true) if repositories.is_empty() => self.reown(None)?,
                (Some(repositories), true) => {
                    refs.extend(repositories);
                    self.reown(Some(&refs))?;
                },
                (None, _) if !refs.is_empty() => self.reown(Some(&refs))?,
                (None, _) => {},
            }
            let targets = self.targets(&appeared, &rescanned);
            if !targets.is_empty() {
                self.examine(targets)?;
            }
        }
        self.settle()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Adopted {
    Processed,
    Unprocessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loss {
    Lost,
    Kept,
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

fn open<'a>(
    scout: &Scout,
    policy: &'a AutoPolicy,
    hooks: &'a Hooks<'a>,
) -> Result<(Session<'a>, Receiver<Signal>), WatchError> {
    let (sender, receiver): (Sender<Signal>, Receiver<Signal>) = mpsc::channel();
    let roots = policy
        .selection
        .roots
        .iter()
        .filter_map(|root| match fs::canonicalize(root) {
            Ok(canonical) => Some(canonical),
            Err(_absent) => None,
        })
        .collect::<Vec<_>>();
    let mut paths = roots.clone();
    paths.push(hooks.state.clone());
    let deliver = sender.clone();
    let watcher = Watcher::start(&paths, move |change| {
        let _closed = deliver.send(Signal::Changed(change));
    })
    .map_err(WatchError::Events)?;
    let session = Session {
        scout: scout.refreshed(),
        roots,
        policy,
        excludes: scan::excludes(&policy.selection.excludes),
        hooks,
        world: BTreeMap::new(),
        dirty: BTreeSet::new(),
        waiting: BTreeMap::new(),
        pool: Pool::default(),
        sender,
        watcher,
        covered: true,
        walked: BTreeSet::new(),
    };
    Ok((session, receiver))
}

fn watching(
    scout: &Scout,
    policy: &AutoPolicy,
    config: &Path,
    render: &dyn Fn(&WatchRecord) -> io::Result<()>,
) -> Result<std::convert::Infallible, WatchError> {
    let state = store::state_dir()
        .and_then(fs::canonicalize)
        .map_err(WatchError::Station)?;
    let station = Station::for_policy(&state, config);
    let _held = station.wait().map_err(WatchError::Station)?;
    let hooks = Hooks {
        station,
        state,
        log: policy.log_file.clone(),
        render,
    };
    let (mut session, receiver) = open(scout, policy, &hooks)?;
    platform::background();
    match rayon::ThreadPoolBuilder::new()
        .start_handler(|_| platform::background())
        .build_global()
    {
        Ok(()) | Err(_) => {},
    }
    let _raised = hooks.taken().map_err(WatchError::Station)?;
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
    use std::cell::RefCell;
    use std::fs;

    use storage_scout_core::size::Bytes;
    use testkit::{MarkerKeep, MarkerRole, write_sized};

    use super::*;
    use crate::dedupe::Totals;
    use crate::prune::Removed;

    type Records = RefCell<Vec<WatchRecord>>;

    fn watched(
        name: &str,
        setup: impl FnOnce(&Path),
        check: impl FnOnce(&mut Session<'_>, &Path, &Records),
    ) {
        let temp = testkit::tempdir(name);
        let base = fs::canonicalize(temp.path()).unwrap();
        let root = base.join("work");
        testkit::make_dir(&root);
        setup(&root);
        let state = base.join("state");
        testkit::make_dir(&state);
        let policy = AutoPolicy::parse(&format!(
            "[select]\nroots = [{:?}]\n",
            root.to_str().unwrap()
        ))
        .unwrap();
        let records = Records::default();
        let render = |record: &WatchRecord| {
            records.borrow_mut().push(record.clone());
            Ok(())
        };
        let hooks = Hooks {
            station: Station::for_policy(&state, &base.join("auto.toml")),
            state,
            log: None,
            render: &render,
        };
        let scout = Scout::with(testkit::open_protection()).confined(vec![base]);
        let (mut session, _receiver) = open(&scout, &policy, &hooks).unwrap();
        session.start().unwrap();
        check(&mut session, &root, &records);
    }

    fn entry(path: &Path, event: Event) -> Signal {
        Signal::Changed(Change::Entry {
            path: path.to_path_buf(),
            event,
        })
    }

    fn appeared(path: &Path) -> Signal {
        entry(path, Event::Appeared)
    }

    fn written(path: &Path) -> Signal {
        entry(path, Event::Written)
    }

    fn profile(root: &Path, name: &str) -> PathBuf {
        let project = root.join(name);
        write_sized(&project.join("Cargo.toml"), 1);
        testkit::write_cache_tag(&project.join("target"));
        let profile = project.join("target/debug");
        write_sized(&profile.join(".cargo-lock"), 0);
        testkit::make_dir(&profile.join(".fingerprint"));
        testkit::make_dir(&profile.join("deps"));
        profile
    }

    fn build(profile: &Path, unit: &str) -> PathBuf {
        let mut old = PathBuf::new();
        for (stamp, name) in [("a0", "aaa"), ("a1", "bbb")] {
            let directory = profile
                .join("incremental")
                .join(unit)
                .join(format!("s-{stamp}-x-{name}"));
            write_sized(&directory.join("query-cache.bin"), 4096);
            write_sized(
                &profile
                    .join("incremental")
                    .join(unit)
                    .join(format!("s-{stamp}-x.lock")),
                0,
            );
            if old.as_os_str().is_empty() {
                old = directory;
            }
        }
        old
    }

    fn last_cause(state: &Path) -> Option<String> {
        let last = fs::read_dir(state)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.to_string_lossy().ends_with(".last.json"))?;
        let document: serde_json::Value = serde_json::from_slice(&fs::read(last).unwrap()).unwrap();
        document["cause"].as_str().map(str::to_owned)
    }

    fn pruned_so_far(records: &Records) -> u64 {
        records
            .borrow()
            .iter()
            .filter_map(|record| record.prune.as_ref())
            .map(|run| run.totals.files())
            .sum()
    }

    fn reaped(records: &Records) -> usize {
        records
            .borrow()
            .iter()
            .filter_map(|record| record.reap.as_ref())
            .map(|summary| summary.outcomes.len())
            .sum()
    }

    #[test]
    fn a_write_is_pruned_as_soon_as_the_writer_lets_go() {
        watched(
            "watch-unit-build",
            |root| {
                let _debug = profile(root, "app");
            },
            |session, root, records| {
                let target = root.join("app/target");
                assert!(session.world.contains_key(&target));
                assert_eq!(records.borrow().len(), 1);
                assert_eq!(records.borrow()[0].cause, Cause::Start);
                assert_eq!(last_cause(&session.hooks.state).as_deref(), Some("start"));
                let debug = target.join("debug");
                let old = build(&debug, "one");
                session
                    .turn(vec![appeared(&debug.join("incremental/one"))])
                    .unwrap();
                assert_eq!(pruned_so_far(records), 1);
                testkit::assert_absent(&old);
                assert!(session.dirty.is_empty());
                let quiet = records.borrow().len();
                session
                    .turn(vec![written(&debug.join("deps/libx.rlib"))])
                    .unwrap();
                assert_eq!(records.borrow().len(), quiet);

                let batched = build(&debug, "three");
                let state = session.hooks.state.clone();
                session
                    .turn(vec![
                        appeared(&state.join("flag")),
                        appeared(&root.join("repo/.git/objects/ab")),
                        appeared(&debug.join("incremental/three")),
                    ])
                    .unwrap();
                assert_eq!(pruned_so_far(records), 2);
                testkit::assert_absent(&batched);

                let untouched = build(&debug, "four");
                let holder = File::open(debug.join(".cargo-lock")).unwrap();
                holder.lock().unwrap();
                let busy = build(&debug, "two");
                session
                    .turn(vec![appeared(&debug.join("incremental/two"))])
                    .unwrap();
                assert!(session.waiting.contains_key(&target));
                session
                    .turn(vec![written(&debug.join("deps/libx.rlib"))])
                    .unwrap();
                assert_eq!(pruned_so_far(records), 2);
                testkit::assert_present(&busy);
                drop(holder);
                session.waiting.remove(&target).unwrap().join().unwrap();
                session
                    .turn(vec![Signal::Released(target.clone())])
                    .unwrap();
                assert_eq!(pruned_so_far(records), 3);
                testkit::assert_absent(&busy);
                testkit::assert_present(&untouched);
                assert!(!session.waiting.contains_key(&target));
            },
        );
    }

    #[test]
    fn a_new_project_and_a_directory_that_becomes_owned_are_both_noticed() {
        watched(
            "watch-unit-appear",
            |root| {
                testkit::write_owner_marker(
                    &root.with_file_name("outside"),
                    MarkerRole::Scratch,
                    MarkerKeep::Released,
                    None,
                );
            },
            |session, root, records| {
                assert!(session.world.is_empty());
                let debug = profile(root, "late");
                session.turn(vec![appeared(&root.join("late"))]).unwrap();
                let target = root.join("late/target");
                assert!(
                    session.world.contains_key(&target),
                    "{:?}",
                    session.world.keys()
                );
                let old = build(&debug, "one");
                session
                    .turn(vec![appeared(&debug.join("incremental/one"))])
                    .unwrap();
                assert_eq!(pruned_so_far(records), 1);
                testkit::assert_absent(&old);

                let unannounced = build(&debug, "two");
                session
                    .turn(vec![written(&root.join("late/Cargo.toml"))])
                    .unwrap();
                let quiet = profile(root, "quiet");
                let state = session.hooks.state.clone();
                session.turn(vec![appeared(&state.join("flag"))]).unwrap();
                session
                    .turn(vec![written(&root.join("notes.txt"))])
                    .unwrap();
                assert!(!session.world.contains_key(&root.join("quiet/target")));
                let run = root.join("run");
                testkit::write_owner_lock(&run);
                write_sized(&run.join("scratch.bin"), 64);
                session.turn(vec![appeared(&run)]).unwrap();
                assert!(!session.world.contains_key(&run));
                testkit::write_owner_json(&run, MarkerRole::Scratch, MarkerKeep::Released, None);
                session
                    .turn(vec![appeared(&run.join("owner.json"))])
                    .unwrap();
                assert_eq!(reaped(records), 1);
                testkit::assert_absent(&run);
                assert!(!session.world.contains_key(&run));
                assert_eq!(pruned_so_far(records), 1);
                testkit::assert_present(&unannounced);
                session
                    .turn(vec![appeared(
                        &root.with_file_name("outside").join("owner.json"),
                    )])
                    .unwrap();
                testkit::assert_present(root.with_file_name("outside"));

                let deep = profile(root, "deep");
                session
                    .turn(vec![appeared(deep.parent().unwrap())])
                    .unwrap();
                assert!(session.world.contains_key(&root.join("deep/target")));
                drop(quiet);

                let _ab = profile(root, "ab");
                let _ac = profile(root, "ac");
                session
                    .turn(vec![
                        appeared(&root.join("ab")),
                        appeared(&root.join("ac")),
                        appeared(&root.join("zz-gone")),
                    ])
                    .unwrap();
                assert!(session.world.contains_key(&root.join("ab/target")));
                assert!(session.world.contains_key(&root.join("ac/target")));
            },
        );
    }

    #[test]
    fn an_owner_that_lets_go_is_reaped_and_a_vanished_candidate_is_forgotten() {
        watched(
            "watch-unit-owner",
            |root| {
                let _debug = profile(root, "gone");
                testkit::write_owner_marker(
                    &root.join("done"),
                    MarkerRole::Scratch,
                    MarkerKeep::Released,
                    None,
                );
            },
            |session, root, records| {
                assert_eq!(reaped(records), 1);
                testkit::assert_absent(root.join("done"));
                let run = root.join("run");
                testkit::write_owner_marker(&run, MarkerRole::Scratch, MarkerKeep::Released, None);
                let owner = testkit::claim(&run);
                session.turn(vec![appeared(&run)]).unwrap();
                assert!(session.waiting.contains_key(&run));
                assert_eq!(reaped(records), 1);
                drop(owner);
                session.waiting.remove(&run).unwrap().join().unwrap();
                session.turn(vec![Signal::Released(run.clone())]).unwrap();
                assert_eq!(reaped(records), 2);
                testkit::assert_absent(&run);

                let held = root.join("held");
                testkit::write_owner_marker(
                    &held,
                    MarkerRole::Cache,
                    MarkerKeep::Released,
                    Some(&root.join("missing")),
                );
                write_sized(&held.join("debug/.cargo-lock"), 0);
                let build = File::open(held.join("debug/.cargo-lock")).unwrap();
                build.lock().unwrap();
                session.turn(vec![appeared(&held)]).unwrap();
                assert!(session.waiting.contains_key(&held));
                assert_eq!(reaped(records), 2);
                drop(build);
                session.waiting.remove(&held).unwrap().join().unwrap();
                session.turn(vec![Signal::Released(held.clone())]).unwrap();
                assert_eq!(reaped(records), 3);
                testkit::assert_absent(&held);

                let sealed = root.join("sealed");
                testkit::write_owner_marker(
                    &sealed,
                    MarkerRole::Scratch,
                    MarkerKeep::Released,
                    None,
                );
                testkit::make_dir(&sealed.join("private"));
                if let Some(_restricted) = testkit::restrict(&sealed.join("private"), 0o000) {
                    session.turn(vec![appeared(&sealed)]).unwrap();
                    assert_eq!(reaped(records), 3);
                    assert!(!session.world.contains_key(&sealed));
                }

                let target = root.join("gone/target");
                assert!(session.world.contains_key(&target));
                testkit::remove_tree(&target);
                session.turn(vec![entry(&target, Event::Vanished)]).unwrap();
                assert!(!session.world.contains_key(&target));
            },
        );
    }

    #[test]
    fn a_hook_a_ref_update_and_a_lost_stream_ask_the_owners_again() {
        watched(
            "watch-unit-hook",
            |root| {
                let key = root.with_file_name("key");
                testkit::make_dir(&key);
                for name in ["cache", "guarded"] {
                    testkit::write_owner_marker(
                        &root.join(name),
                        MarkerRole::Cache,
                        MarkerKeep::Released,
                        Some(&key),
                    );
                }
                testkit::write_owner_marker(
                    &root.join("guarded/inner"),
                    MarkerRole::Scratch,
                    MarkerKeep::Kept,
                    None,
                );
                testkit::make_dir(&root.join("repo/.git/refs"));
                for (name, keyed) in [("repo/second", "key-two"), ("third", "key-three")] {
                    let keyed = root.with_file_name(keyed);
                    testkit::make_dir(&keyed);
                    testkit::write_owner_marker(
                        &root.join(name),
                        MarkerRole::Cache,
                        MarkerKeep::Released,
                        Some(&keyed),
                    );
                }
                let _app = profile(root, "app");
                let _doomed = profile(root, "doomed");
            },
            |session, root, records| {
                assert_eq!(session.world.len(), 6, "{:?}", session.world.keys());
                testkit::remove_tree(&root.with_file_name("key"));
                session.turn(vec![]).unwrap();
                assert_eq!(reaped(records), 0);
                let unannounced = build(&root.join("app/target/debug"), "one");
                let fresh = profile(root, "fresh");
                session.hooks.station.raise().unwrap();
                session.turn(vec![]).unwrap();
                assert_eq!(reaped(records), 1);
                assert_eq!(records.borrow().last().unwrap().cause, Cause::Hook);
                testkit::assert_absent(root.join("cache"));
                assert!(session.world.contains_key(&root.join("guarded")));
                assert!(
                    !session
                        .world
                        .contains_key(&fresh.parent().unwrap().to_path_buf())
                );
                assert_eq!(pruned_so_far(records), 0);
                testkit::assert_present(&unannounced);

                testkit::remove_tree(&root.with_file_name("key-two"));
                let refs = root.join("repo/.git/refs/remotes/origin/main");
                session.turn(vec![written(&refs)]).unwrap();
                assert_eq!(reaped(records), 2);
                testkit::assert_absent(root.join("repo/second"));

                let late = profile(root, "unseen");
                let waste = build(&late, "one");
                testkit::remove_tree(&root.with_file_name("key-three"));
                testkit::remove_tree(&root.join("doomed/target"));
                let before = records.borrow().len();
                session.turn(vec![Signal::Changed(Change::Lost)]).unwrap();
                assert!(
                    session
                        .world
                        .contains_key(&late.parent().unwrap().to_path_buf())
                );
                assert_eq!(reaped(records), 3);
                assert!(
                    records
                        .borrow()
                        .iter()
                        .skip(before)
                        .any(|record| record.cause == Cause::Hook && record.reap.is_some())
                );
                testkit::assert_absent(root.join("third"));
                assert!(!session.world.contains_key(&root.join("repo/second")));
                assert!(!session.world.contains_key(&root.join("doomed/target")));
                assert!(session.world.contains_key(&root.join("guarded")));
                assert_eq!(pruned_so_far(records), 2);
                testkit::assert_absent(&unannounced);
                testkit::assert_absent(&waste);
            },
        );
    }

    #[test]
    fn writes_the_watcher_itself_makes_or_no_writer_locks_change_nothing() {
        watched(
            "watch-unit-quiet",
            |root| {
                write_sized(&root.join("tool/tool.py"), 1);
                write_sized(&root.join("tool/__pycache__/tool.cpython-312.pyc"), 64);
            },
            |session, root, records| {
                assert_eq!(session.world.len(), 1, "{:?}", session.world.keys());
                let state = session.hooks.state.clone();
                session.turn(vec![appeared(&state.join("flag"))]).unwrap();
                session
                    .turn(vec![written(
                        &root.join("tool/__pycache__/tool.cpython-312.pyc"),
                    )])
                    .unwrap();
                assert!(session.dirty.is_empty());
                assert_eq!(records.borrow().len(), 1);
                session
                    .turn(vec![appeared(&root.join("repo/.git/objects/ab"))])
                    .unwrap();
                assert!(session.dirty.is_empty());
                assert_eq!(records.borrow().len(), 1);
            },
        );
    }

    #[test]
    fn a_waiter_reports_the_release_of_the_lock_it_waits_on() {
        let temp = testkit::tempdir("watch-unit-waiter");
        let lock = temp.path().join("owner.lock");
        write_sized(&lock, 0);
        let holder = File::open(&lock).unwrap();
        holder.lock().unwrap();
        let (sender, receiver) = mpsc::channel();
        let waiter = wait_for(lock, temp.path().to_path_buf(), sender).unwrap();
        drop(holder);
        waiter.join().unwrap();
        assert!(matches!(
            receiver.recv().unwrap(),
            Signal::Released(root) if root == temp.path()
        ));
    }

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
    fn a_ref_update_is_told_apart_from_other_git_writes() {
        let repository = PathBuf::from("/w/app/.git");
        for refs in [
            "/w/app/.git/refs/remotes/origin",
            "/w/app/.git/refs",
            "/w/app/.git/packed-refs",
            "/w/app/.git/HEAD",
            "/w/app/.git/worktrees/lies/HEAD",
        ] {
            assert_eq!(
                git_area(Path::new(refs)),
                GitArea::Refs(repository.clone()),
                "{refs}"
            );
        }
        assert_eq!(git_area(Path::new("/w/app/.git")), GitArea::Other);
        assert_eq!(git_area(Path::new("/w/app/.git/index")), GitArea::Other);
        assert_eq!(
            git_area(Path::new("/w/app/.git/objects/ab")),
            GitArea::Other
        );
        assert_eq!(git_area(Path::new("/w/app/src")), GitArea::Outside);
        assert_eq!(git_area(Path::new("/w/app/refs")), GitArea::Outside);
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
