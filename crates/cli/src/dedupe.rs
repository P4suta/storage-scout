mod capability;

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::ptr;

use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use storage_scout_core::area::Protection;
use storage_scout_core::candidate::{CandidateId, Identity};
use storage_scout_core::gate::{self, ShareCheck};
use storage_scout_core::location::Location;
use storage_scout_core::lock::Liveness;
use storage_scout_core::reject::{FsOp, Rejection};
use storage_scout_core::share::{
    self, Capability, Extras, Failure, Fingerprint, Group, MINIMUM, Method, Pair, Pairing, Record,
    Refusal, TEMPORARY_SUFFIX,
};
use storage_scout_core::size::Bytes;

use self::capability::Shareable;
use crate::apply::Mode;
use crate::measure::Volumes;
use crate::platform::{self, Event, FileFacts, Request};
use crate::scan::Found;
use crate::{SCHEMA_VERSION, busy, failure, host, observe};

const SAMPLE: u64 = 4096;
const SAMPLE_BYTES: usize = 4096;
const BLOCK: usize = 1 << 20;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Admission {
    Admitted {
        method: Method,
        files: usize,
        unreadable: usize,
    },
    Rejected {
        rejection: Rejection,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub id: CandidateId,
    pub location: Location,
    pub admission: Admission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum PairStatus {
    WouldShare,
    Shared,
    AlreadyShared,
    Refused { refusal: Refusal },
    Withheld { rejection: Rejection },
    Overtaken { failure: Failure },
    Failed { failure: Failure },
}

#[derive(Debug, Clone, Serialize)]
pub struct PairOutcome {
    pub keeper: Location,
    pub duplicate: Location,
    pub len: Bytes,
    pub status: PairStatus,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub files: u64,
    pub bytes: Bytes,
}

impl Tally {
    pub(crate) const fn add(&mut self, len: u64) {
        self.files = self.files.saturating_add(1);
        self.bytes = self.bytes.saturating_add(Bytes::new(len));
    }

    pub(crate) const fn merge(&mut self, other: Self) {
        self.files = self.files.saturating_add(other.files);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub shared: Tally,
    pub already_shared: Tally,
    pub refused: Tally,
    pub withheld: Tally,
    pub overtaken: Tally,
    pub failed: Tally,
}

#[derive(Debug, Clone, Serialize)]
pub struct DedupeRun {
    pub schema_version: u32,
    pub command: &'static str,
    pub mode: Mode,
    pub subjects: Vec<Subject>,
    pub totals: Totals,
    pub observed_freed: Option<Bytes>,
    pub pairs: Vec<PairOutcome>,
}

impl DedupeRun {
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.totals.failed.files > 0
    }

    #[must_use]
    pub const fn shared(&self) -> Bytes {
        self.totals.shared.bytes
    }

    #[must_use]
    pub(crate) fn summarized(mut self) -> Self {
        self.pairs
            .retain(|pair| matches!(pair.status, PairStatus::Failed { .. }));
        self
    }
}

struct Item<'f> {
    record: Record,
    found: &'f Found,
    path: PathBuf,
    relative: PathBuf,
}

impl Item<'_> {
    fn observed(&self) -> Self {
        let mut record = self.record.clone();
        record.extras = match record.method {
            Method::CloneAndSwap => platform::extras(&self.path, record.identity),
            Method::DedupeRange => Extras::Unobserved,
        };
        Self {
            record,
            found: self.found,
            path: self.path.clone(),
            relative: self.relative.clone(),
        }
    }
}

impl Borrow<Record> for Item<'_> {
    fn borrow(&self) -> &Record {
        &self.record
    }
}

struct Inventory {
    files: Vec<(PathBuf, PathBuf, FileFacts)>,
    unreadable: usize,
}

struct Terms<'a> {
    excludes: &'a [Location],
    protection: &'a Protection,
}

fn capability(path: &Path) -> Result<Capability, Rejection> {
    match platform::filesystem(path) {
        Ok(filesystem) => Ok(Capability::of(filesystem)),
        Err(error) => Err(failure::io(path, FsOp::FilesystemType, &error)),
    }
}

fn admit(found: &Found, terms: &Terms<'_>) -> Result<Method, Rejection> {
    let observed = observe::observe(found.path())?;
    let site = observed.site(terms.protection, terms.excludes);
    let survey = busy::survey(&observed.path)?;
    let liveness = match busy::probe(&survey.locks) {
        Ok(()) => Liveness::Free,
        Err(contention) => contention.liveness(),
    };
    let check = ShareCheck {
        recorded: found.candidate(),
        identity: observed.identity,
        liveness: &liveness,
        capability: capability(&observed.path)?,
    };
    gate::clear_share(&site, &check).map(|clearance| clearance.method())
}

fn hold(found: &Found, terms: &Terms<'_>) -> Result<Shareable, Rejection> {
    let observed = observe::observe(found.path())?;
    let site = observed.site(terms.protection, terms.excludes);
    let survey = busy::survey(&observed.path)?;
    let lease = busy::lease(&survey.locks);
    let liveness = match &lease {
        Ok(_) => Liveness::Free,
        Err(contention) => contention.liveness(),
    };
    let check = ShareCheck {
        recorded: found.candidate(),
        identity: observed.identity,
        liveness: &liveness,
        capability: capability(&observed.path)?,
    };
    let clearance = gate::clear_share(&site, &check)?;
    let lease = lease.map_err(|contention| contention.rejection(observed.location.clone()))?;
    Shareable::new(clearance, lease, &observed.path)
}

fn temporary(name: &OsStr) -> bool {
    name.as_encoded_bytes()
        .ends_with(TEMPORARY_SUFFIX.as_bytes())
}

fn inventory(root: &Path) -> Result<Inventory, Rejection> {
    inventory_under(root, root)
}

fn inventory_under(root: &Path, start: &Path) -> Result<Inventory, Rejection> {
    let top = fs::symlink_metadata(root).map_err(|e| failure::io(root, FsOp::Inspect, &e))?;
    let device = platform::device(&top);
    let mut pending = vec![start.to_path_buf()];
    let mut files = Vec::new();
    let mut unreadable = 0usize;
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|e| failure::io(&directory, FsOp::ReadDir, &e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| failure::io(&directory, FsOp::ReadEntry, &e))?;
        for entry in entries {
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| failure::io(&path, FsOp::FileType, &e))?;
            if kind.is_dir() {
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|e| failure::io(&path, FsOp::Inspect, &e))?;
                if platform::device(&metadata) == device {
                    pending.push(path);
                }
            } else if kind.is_file() && !temporary(&entry.file_name()) {
                let metadata = entry
                    .metadata()
                    .map_err(|e| failure::io(&path, FsOp::Metadata, &e))?;
                if metadata.len() >= MINIMUM
                    && let Ok(relative) = path.strip_prefix(root).map(Path::to_path_buf)
                {
                    match platform::file_facts(&path, &metadata) {
                        Ok(facts) => files.push((path, relative, facts)),
                        Err(_unreadable) => unreadable = unreadable.saturating_add(1),
                    }
                }
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Inventory { files, unreadable })
}

struct Hasher(Sha256);

impl Write for Hasher {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn opened(path: &Path, identity: Identity, capacity: usize) -> Option<BufReader<File>> {
    let file = match platform::open_regular(path) {
        Ok(file) => file,
        Err(_unreadable) => return None,
    };
    match platform::identity_of_file(&file) {
        Ok(found) if found == identity => Some(BufReader::with_capacity(capacity, file)),
        Ok(_) | Err(_) => None,
    }
}

fn copied(reader: &mut BufReader<File>, count: u64, hasher: &mut Hasher) -> bool {
    matches!(io::copy(&mut reader.take(count), hasher), Ok(copied) if copied == count)
}

fn sample(path: &Path, identity: Identity, len: u64) -> Option<Fingerprint> {
    let mut reader = opened(path, identity, SAMPLE_BYTES)?;
    let mut hasher = Hasher(Sha256::new());
    hasher.0.update(len.to_le_bytes());
    let mut whole = copied(&mut reader, len.min(SAMPLE), &mut hasher);
    if len > SAMPLE {
        let tail = len.saturating_sub(SAMPLE);
        whole = whole
            && matches!(reader.seek(SeekFrom::Start(tail)), Ok(at) if at == tail)
            && copied(&mut reader, SAMPLE, &mut hasher);
    }
    whole.then(|| Fingerprint(hasher.0.finalize().into()))
}

fn full(path: &Path, identity: Identity, len: u64) -> Option<Fingerprint> {
    let mut reader = opened(path, identity, BLOCK)?;
    let mut hasher = Hasher(Sha256::new());
    hasher.0.update(len.to_le_bytes());
    let whole =
        copied(&mut reader, len, &mut hasher) && matches!(reader.read(&mut [0u8; 1]), Ok(0));
    whole.then(|| Fingerprint(hasher.0.finalize().into()))
}

fn refine<'a, 'f>(
    groups: &[Group<'a, Item<'f>>],
    print: fn(&Path, Identity, u64) -> Option<Fingerprint>,
) -> Vec<Group<'a, Item<'f>>> {
    groups
        .par_iter()
        .flat_map(|group| {
            let prints = group
                .members
                .par_iter()
                .map(|member| print(&member.path, member.record.identity, member.record.len))
                .collect::<Vec<_>>();
            share::split(group, &prints)
        })
        .collect()
}

fn request<'a>(pair: &Pair<'a, Item<'_>>) -> Request<'a> {
    Request {
        keeper: &pair.keeper.path,
        keeper_identity: pair.keeper.record.identity,
        duplicate: &pair.duplicate.relative,
        duplicate_identity: pair.duplicate.record.identity,
        len: pair.len,
    }
}

type Held<'f> = Option<(&'f Found, Result<Shareable, Rejection>)>;

fn settle<'f>(
    pair: &Pair<'_, Item<'f>>,
    mode: Mode,
    held: &mut Held<'f>,
    terms: &Terms<'_>,
) -> PairStatus {
    match (pair.pairing, mode) {
        (Pairing::AlreadyShared, _) => PairStatus::AlreadyShared,
        (Pairing::Refused { refusal }, _) => PairStatus::Refused { refusal },
        (Pairing::Share, Mode::DryRun) => PairStatus::WouldShare,
        (Pairing::Share, Mode::Execute) => {
            let found = pair.duplicate.found;
            if !held
                .as_ref()
                .is_some_and(|(current, _)| ptr::eq(*current, found))
            {
                *held = None;
            }
            let (_, lease) = held.get_or_insert_with(|| (found, hold(found, terms)));
            match lease {
                Err(rejection) => PairStatus::Withheld {
                    rejection: rejection.clone(),
                },
                Ok(shareable) => match shareable.share(&request(pair)) {
                    Ok(()) => PairStatus::Shared,
                    Err(failure) if failure.overtaken() => PairStatus::Overtaken { failure },
                    Err(failure) => PairStatus::Failed { failure },
                },
            }
        },
    }
}

fn free_space<'f>(found: impl Iterator<Item = &'f Found>) -> Volumes {
    Volumes::sample(found.map(|each| {
        (
            each.candidate().identity().volume,
            each.path().parent().unwrap_or_else(|| each.path()),
        )
    }))
}

struct Stock {
    found: Found,
    subject: Subject,
    method: Option<Method>,
    files: BTreeMap<Box<Path>, FileFacts>,
}

type Member = (PathBuf, Box<Path>);

#[derive(Default)]
pub(crate) struct Pool {
    stocks: BTreeMap<PathBuf, Stock>,
    lengths: BTreeMap<u64, BTreeSet<Member>>,
}

pub(crate) enum Focus<'a> {
    Everything,
    Fresh {
        roots: &'a BTreeSet<PathBuf>,
        fresh: &'a BTreeMap<Identity, u64>,
    },
}

impl Focus<'_> {
    fn subject(&self, root: &Path) -> bool {
        match self {
            Self::Everything => true,
            Self::Fresh { roots, .. } => roots.contains(root),
        }
    }

    fn group<T: Borrow<Record>>(&self, group: &Group<'_, T>) -> bool {
        match self {
            Self::Everything => true,
            Self::Fresh { fresh, .. } => group
                .members
                .iter()
                .any(|member| fresh.contains_key(&(*member).borrow().identity)),
        }
    }
}

fn still_there(path: &Path, relative: &Path, recorded: &Path) -> bool {
    match recorded.strip_prefix(relative) {
        Ok(below) => below
            .components()
            .next()
            .is_some_and(|first| fs::symlink_metadata(path.join(first)).is_ok()),
        Err(_outside) => false,
    }
}

fn shallow(root: &Path, directory: &Path) -> Vec<(Box<Path>, FileFacts)> {
    fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| matches!(entry.file_type(), Ok(kind) if kind.is_file()))
        .flat_map(|entry| present(root, &entry.path(), Event::Written))
        .collect()
}

fn present(root: &Path, path: &Path, event: Event) -> Vec<(Box<Path>, FileFacts)> {
    let listed = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && event == Event::Unsure => {
            return shallow(root, path);
        },
        Ok(metadata) if metadata.is_dir() => match inventory_under(root, path) {
            Ok(listed) => listed.files,
            Err(_unreadable) => Vec::new(),
        },
        Ok(metadata)
            if metadata.is_file()
                && metadata.len() >= MINIMUM
                && !path.file_name().is_some_and(temporary) =>
        {
            match (
                path.strip_prefix(root),
                platform::file_facts(path, &metadata),
            ) {
                (Ok(relative), Ok(facts)) => {
                    vec![(path.to_path_buf(), relative.to_path_buf(), facts)]
                },
                (Ok(_) | Err(_), Ok(_) | Err(_)) => Vec::new(),
            }
        },
        Ok(_) | Err(_) => Vec::new(),
    };
    listed
        .into_iter()
        .map(|(_, relative, facts)| (relative.into_boxed_path(), facts))
        .collect()
}

impl Pool {
    #[cfg(test)]
    pub(crate) fn file_count(&self, root: &Path) -> usize {
        self.stocks.get(root).map_or(0, |stock| stock.files.len())
    }

    fn index(&mut self, root: &Path, files: &BTreeMap<Box<Path>, FileFacts>) {
        for (relative, facts) in files {
            self.lengths
                .entry(facts.len)
                .or_default()
                .insert((root.to_path_buf(), relative.clone()));
        }
    }

    fn unindex(&mut self, root: &Path, files: &BTreeMap<Box<Path>, FileFacts>) {
        for (relative, facts) in files {
            if let Some(members) = self.lengths.get_mut(&facts.len) {
                members.remove(&(root.to_path_buf(), relative.clone()));
                if members.is_empty() {
                    self.lengths.remove(&facts.len);
                }
            }
        }
    }

    pub(crate) fn stock(
        &mut self,
        found: &Found,
        excludes: &[Location],
        protection: &Protection,
    ) -> BTreeMap<Identity, u64> {
        let terms = Terms {
            excludes,
            protection,
        };
        let known = match self.stocks.remove(found.path()) {
            Some(old) => {
                self.unindex(found.path(), &old.files);
                old.files
                    .values()
                    .map(|facts| facts.identity)
                    .collect::<BTreeSet<_>>()
            },
            None => BTreeSet::new(),
        };
        let admitted = admit(found, &terms)
            .and_then(|method| inventory(found.path()).map(|listed| (method, listed)));
        let (admission, method, files) = match admitted {
            Err(rejection) => (Admission::Rejected { rejection }, None, BTreeMap::new()),
            Ok((method, listed)) => (
                Admission::Admitted {
                    method,
                    files: listed.files.len(),
                    unreadable: listed.unreadable,
                },
                Some(method),
                listed
                    .files
                    .into_iter()
                    .map(|(_, relative, facts)| (relative.into_boxed_path(), facts))
                    .collect::<BTreeMap<_, _>>(),
            ),
        };
        let fresh = files
            .values()
            .filter(|facts| !known.contains(&facts.identity))
            .map(|facts| (facts.identity, facts.len))
            .collect();
        self.index(found.path(), &files);
        self.stocks.insert(
            found.path().to_path_buf(),
            Stock {
                found: found.clone(),
                subject: Subject {
                    id: found.candidate().id().clone(),
                    location: found.candidate().location().clone(),
                    admission,
                },
                method,
                files,
            },
        );
        fresh
    }

    pub(crate) fn note(
        &mut self,
        root: &Path,
        changed: &BTreeMap<PathBuf, Event>,
    ) -> BTreeMap<Identity, u64> {
        let Some(stock) = self.stocks.get_mut(root) else {
            return BTreeMap::new();
        };
        if stock.method.is_none() {
            return BTreeMap::new();
        }
        let mut removed = BTreeMap::new();
        let mut added = BTreeMap::new();
        for (path, event) in changed {
            if let Ok(relative) = path.strip_prefix(root) {
                let below = stock
                    .files
                    .range::<Path, _>((Bound::Included(relative), Bound::Unbounded))
                    .take_while(|(recorded, _)| recorded.starts_with(relative))
                    .map(|(recorded, _)| recorded.clone())
                    .filter(|recorded| match event {
                        Event::Unsure => {
                            recorded.parent() == Some(relative)
                                || !still_there(path, relative, recorded)
                        },
                        Event::Appeared | Event::Vanished | Event::Written => true,
                    })
                    .collect::<Vec<_>>();
                for recorded in below {
                    if let Some(facts) = stock.files.remove(&recorded) {
                        removed.insert(recorded, facts);
                    }
                }
                added.extend(present(root, path, *event));
            }
        }
        let known = removed
            .values()
            .map(|facts| facts.identity)
            .collect::<BTreeSet<_>>();
        let fresh = added
            .values()
            .filter(|facts| !known.contains(&facts.identity))
            .map(|facts| (facts.identity, facts.len))
            .collect();
        stock.files.extend(added.clone());
        self.unindex(root, &removed);
        self.index(root, &added);
        fresh
    }

    pub(crate) fn forget(&mut self, root: &Path) {
        if let Some(stock) = self.stocks.remove(root) {
            self.unindex(root, &stock.files);
        }
    }

    fn lengths(&self, focus: &Focus<'_>) -> BTreeSet<u64> {
        let repeated = |len: &u64| {
            self.lengths
                .get(len)
                .is_some_and(|members| members.len() > 1)
        };
        match focus {
            Focus::Everything => self
                .lengths
                .keys()
                .filter(|len| repeated(len))
                .copied()
                .collect(),
            Focus::Fresh { fresh, .. } => fresh
                .values()
                .filter(|len| repeated(len))
                .copied()
                .collect(),
        }
    }

    fn items(&self, focus: &Focus<'_>) -> (Vec<Subject>, Vec<Item<'_>>) {
        let subjects = self
            .stocks
            .iter()
            .filter(|(root, _)| focus.subject(root))
            .map(|(_, stock)| stock.subject.clone())
            .collect();
        let mut seen = BTreeSet::new();
        let items = self
            .lengths(focus)
            .into_iter()
            .flat_map(|len| self.lengths.get(&len).into_iter().flatten())
            .filter_map(|(root, relative)| {
                let stock = self.stocks.get(root)?;
                Some((
                    root,
                    relative,
                    stock,
                    stock.method?,
                    stock.files.get(relative)?,
                ))
            })
            .filter(|(.., facts)| seen.insert(facts.identity))
            .filter_map(|(root, relative, stock, method, facts)| {
                let path = root.join(relative);
                match host::locate(&path) {
                    Ok(location) => Some(Item {
                        record: Record {
                            location,
                            len: facts.len,
                            identity: facts.identity,
                            method,
                            links: facts.links,
                            owner: facts.owner,
                            mode: facts.mode,
                            extras: Extras::Unobserved,
                            sharing: facts.sharing,
                        },
                        found: &stock.found,
                        path,
                        relative: relative.to_path_buf(),
                    }),
                    Err(_unnameable) => None,
                }
            })
            .collect();
        (subjects, items)
    }

    pub(crate) fn share(
        &self,
        focus: &Focus<'_>,
        excludes: &[Location],
        protection: &Protection,
        mode: Mode,
    ) -> DedupeRun {
        let terms = Terms {
            excludes,
            protection,
        };
        let (subjects, items) = self.items(focus);
        let found = || {
            items
                .iter()
                .map(|item| (item.found.path(), item.found))
                .collect::<BTreeMap<_, _>>()
                .into_values()
        };
        let before = match mode {
            Mode::Execute => Some(free_space(found())),
            Mode::DryRun => None,
        };
        let sized = share::groups(&items)
            .into_iter()
            .filter(|group| focus.group(group))
            .collect::<Vec<_>>();
        let sampled = refine(&sized, sample);
        let confirmed = refine(&sampled, full);
        let observed = confirmed
            .par_iter()
            .map(|group| {
                group
                    .members
                    .par_iter()
                    .map(|member| member.observed())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let groups = confirmed
            .iter()
            .zip(&observed)
            .map(|(group, members)| Group {
                len: group.len,
                members: members.iter().collect(),
            })
            .collect::<Vec<_>>();
        let mut pairs = share::plan(&groups);
        pairs.sort_by(|left, right| {
            left.duplicate
                .found
                .candidate()
                .location()
                .cmp(right.duplicate.found.candidate().location())
        });
        let mut held = None;
        let mut totals = Totals::default();
        let mut outcomes = Vec::with_capacity(pairs.len());
        for pair in &pairs {
            let status = settle(pair, mode, &mut held, &terms);
            let tally = match status {
                PairStatus::WouldShare | PairStatus::Shared => &mut totals.shared,
                PairStatus::AlreadyShared => &mut totals.already_shared,
                PairStatus::Refused { .. } => &mut totals.refused,
                PairStatus::Withheld { .. } => &mut totals.withheld,
                PairStatus::Overtaken { .. } => &mut totals.overtaken,
                PairStatus::Failed { .. } => &mut totals.failed,
            };
            tally.add(pair.len);
            outcomes.push(PairOutcome {
                keeper: pair.keeper.record.location.clone(),
                duplicate: pair.duplicate.record.location.clone(),
                len: Bytes::new(pair.len),
                status,
            });
        }
        drop(held);
        DedupeRun {
            schema_version: SCHEMA_VERSION,
            command: "dedupe",
            mode,
            subjects,
            totals,
            observed_freed: before.and_then(|before| before.gained(&free_space(found()))),
            pairs: outcomes,
        }
    }
}

pub(crate) fn run(
    found: &[Found],
    excludes: &[Location],
    protection: &Protection,
    mode: Mode,
) -> DedupeRun {
    let mut pool = Pool::default();
    for each in found {
        let _fresh = pool.stock(each, excludes, protection);
    }
    pool.share(&Focus::Everything, excludes, protection, mode)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sha2::{Digest, Sha256};

    use super::*;

    const LEN: u64 = SAMPLE * 3;

    fn written(root: &Path, name: &str, change: Option<u64>) -> (PathBuf, Identity) {
        let path = root.join(name);
        let mut bytes = (0..LEN)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        if let Some(at) = change {
            let at = usize::try_from(at).unwrap();
            bytes[at] = bytes[at].wrapping_add(1);
        }
        testkit::write_bytes(&path, &bytes);
        let identity = platform::identity(&path).unwrap();
        (path, identity)
    }

    #[test]
    fn the_sample_reads_the_head_and_the_tail_and_the_full_print_everything() {
        let temp = testkit::tempdir("dedupe-prints");
        let (base, base_id) = written(temp.path(), "base", None);
        let (head, head_id) = written(temp.path(), "head", Some(0));
        let (tail, tail_id) = written(temp.path(), "tail", Some(LEN - 1));
        let (middle, middle_id) = written(temp.path(), "middle", Some(LEN / 2));
        let sampled = sample(&base, base_id, LEN).unwrap();
        assert_ne!(sample(&head, head_id, LEN), Some(sampled));
        assert_ne!(sample(&tail, tail_id, LEN), Some(sampled));
        assert_eq!(sample(&middle, middle_id, LEN), Some(sampled));
        assert_ne!(full(&middle, middle_id, LEN), full(&base, base_id, LEN));
    }

    #[test]
    fn a_file_exactly_one_sample_long_is_read_once() {
        let temp = testkit::tempdir("dedupe-one-sample");
        let path = temp.path().join("one");
        let bytes = [7u8; 4096];
        testkit::write_bytes(&path, &bytes);
        let mut expected = Sha256::new();
        expected.update(SAMPLE.to_le_bytes());
        expected.update(bytes);
        assert_eq!(
            sample(&path, platform::identity(&path).unwrap(), SAMPLE),
            Some(Fingerprint(expected.finalize().into()))
        );
    }

    #[test]
    fn a_short_file_is_sampled_whole() {
        let temp = testkit::tempdir("dedupe-short");
        let one = temp.path().join("one");
        let two = temp.path().join("two");
        testkit::write_bytes(&one, &[1u8; 100]);
        testkit::write_bytes(&two, &[2u8; 100]);
        let one_id = platform::identity(&one).unwrap();
        let two_id = platform::identity(&two).unwrap();
        assert!(sample(&one, one_id, 100).is_some());
        assert_ne!(sample(&one, one_id, 100), sample(&two, two_id, 100));
    }

    #[test]
    fn the_full_print_is_the_hash_of_the_length_and_every_byte() {
        let temp = testkit::tempdir("dedupe-full");
        let (base, base_id) = written(temp.path(), "base", None);
        let mut expected = Sha256::new();
        expected.update(LEN.to_le_bytes());
        expected.update(fs::read(&base).unwrap());
        assert_eq!(
            full(&base, base_id, LEN),
            Some(Fingerprint(expected.finalize().into()))
        );
    }

    #[test]
    fn nothing_is_read_from_a_file_that_is_not_the_recorded_one() {
        let temp = testkit::tempdir("dedupe-identity");
        let (base, base_id) = written(temp.path(), "base", None);
        let (_, other_id) = written(temp.path(), "other", None);
        assert_eq!(sample(&base, other_id, LEN), None);
        assert_eq!(full(&base, other_id, LEN), None);
        assert_eq!(sample(&base, base_id, LEN + 1), None);
        assert_eq!(full(&base, base_id, LEN + 1), None);
        assert_eq!(full(&base, base_id, LEN - 1), None);
    }

    type Files<'a> = &'a [(u128, u64)];

    const TWICE: u64 = MINIMUM * 2;
    const THRICE: u64 = MINIMUM * 3;

    fn facts(file: u128, len: u64) -> FileFacts {
        FileFacts {
            identity: Identity { volume: 1, file },
            len,
            links: 1,
            owner: share::Owner::Caller,
            mode: share::Mode::Plain,
            sharing: share::Sharing::Unknown,
        }
    }

    fn pooled(root: &Path, stocks: &[(&str, Option<Method>, Files<'_>)]) -> (Pool, Vec<PathBuf>) {
        let root = fs::canonicalize(root).unwrap();
        let targets = stocks
            .iter()
            .map(|(name, _, _)| {
                let target = testkit::write_cargo_project(&root.join(name), 1);
                testkit::write_cache_tag(&target);
                target
            })
            .collect::<Vec<_>>();
        let sighted = crate::scan::sight(
            &crate::ScanOptions::sighting(std::slice::from_ref(&root), &[]),
            &testkit::open_protection(),
            &crate::owners::Owners::default(),
            crate::scan::Reach::Everything,
        );
        let mut pool = Pool::default();
        let mut roots = Vec::new();
        for ((_, method, files), path) in stocks.iter().zip(targets) {
            let found = sighted
                .report
                .candidates
                .iter()
                .find(|found| found.path() == path)
                .unwrap()
                .clone();
            let admission = match method {
                Some(method) => Admission::Admitted {
                    method: *method,
                    files: files.len(),
                    unreadable: 0,
                },
                None => Admission::Rejected {
                    rejection: Rejection::NoRoots,
                },
            };
            let files = files
                .iter()
                .map(|(file, len)| {
                    (
                        PathBuf::from(format!("f{file}")).into_boxed_path(),
                        facts(*file, *len),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            if method.is_some() {
                pool.index(&path, &files);
            }
            pool.stocks.insert(
                path.clone(),
                Stock {
                    subject: Subject {
                        id: found.candidate().id().clone(),
                        location: found.candidate().location().clone(),
                        admission,
                    },
                    found,
                    method: *method,
                    files,
                },
            );
            roots.push(path);
        }
        (pool, roots)
    }

    fn files(items: &[Item<'_>]) -> Vec<u128> {
        items.iter().map(|item| item.record.identity.file).collect()
    }

    #[test]
    fn only_lengths_shared_by_admitted_files_are_considered_and_fresh_files_narrow_them() {
        let temp = testkit::tempdir("dedupe-pool");
        let clone = Some(Method::CloneAndSwap);
        let (pool, roots) = pooled(
            temp.path(),
            &[
                ("a", clone, &[(1, MINIMUM), (2, TWICE), (3, THRICE)]),
                ("b", clone, &[(4, MINIMUM), (5, TWICE), (1, MINIMUM)]),
                ("c", None, &[(6, THRICE), (7, THRICE)]),
            ],
        );
        assert_eq!(
            pool.lengths(&Focus::Everything),
            BTreeSet::from([MINIMUM, TWICE])
        );
        let (subjects, items) = pool.items(&Focus::Everything);
        assert_eq!(subjects.len(), 3);
        assert_eq!(files(&items), [1, 4, 2, 5]);
        assert_eq!(
            items.first().map(|item| item.path.clone()),
            roots.first().map(|root| root.join("f1"))
        );

        let fresh_roots = BTreeSet::from([roots[0].clone()]);
        let fresh_identities = BTreeMap::from([(Identity { volume: 1, file: 5 }, TWICE)]);
        let fresh = Focus::Fresh {
            roots: &fresh_roots,
            fresh: &fresh_identities,
        };
        assert_eq!(pool.lengths(&fresh), BTreeSet::from([TWICE]));
        let (focused, narrowed) = pool.items(&fresh);
        assert_eq!(
            focused
                .iter()
                .map(|subject| subject.location.clone())
                .collect::<Vec<_>>(),
            [host::locate(&roots[0]).unwrap()]
        );
        assert_eq!(files(&narrowed), [2, 5]);

        let groups = share::groups(&items);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups
                .iter()
                .filter(|group| fresh.group(group))
                .map(|group| group.len)
                .collect::<Vec<_>>(),
            [TWICE]
        );
        let stale_identities = BTreeMap::from([(Identity { volume: 1, file: 6 }, THRICE)]);
        let stale = Focus::Fresh {
            roots: &fresh_roots,
            fresh: &stale_identities,
        };
        assert!(pool.lengths(&stale).is_empty());
        assert!(!groups.iter().any(|group| stale.group(group)));
        assert!(groups.iter().all(|group| Focus::Everything.group(group)));
    }

    #[test]
    fn a_stock_names_only_the_files_it_had_not_seen() {
        let temp = testkit::tempdir("dedupe-stock");
        let root = fs::canonicalize(temp.path()).unwrap();
        let target = testkit::write_cargo_project(&root.join("app"), 1);
        testkit::write_cache_tag(&target);
        testkit::write_sized(&target.join("debug/.cargo-lock"), 0);
        testkit::write_patterned(&target.join("debug/deps/one.rlib"), MINIMUM, 1);
        let sighted = crate::scan::sight(
            &crate::ScanOptions::sighting(std::slice::from_ref(&root), &[]),
            &testkit::open_protection(),
            &crate::owners::Owners::default(),
            crate::scan::Reach::Everything,
        );
        let found = sighted.report.candidates.first().unwrap().clone();
        let protection = testkit::open_protection();
        let mut pool = Pool::default();
        let first = pool.stock(&found, &[], &protection);
        let admitted = pool.stocks.get(found.path()).unwrap().method.is_some();
        if !admitted {
            let required = std::env::var_os("STORAGE_SCOUT_REQUIRE_SHARING").is_some();
            assert!(!required, "this volume must share blocks");
            let _skipped = testkit::Built::Unavailable(String::from("sharing is refused here"))
                .or_decline("a volume that shares blocks");
            return;
        }
        let one = platform::identity(&target.join("debug/deps/one.rlib")).unwrap();
        assert_eq!(first, BTreeMap::from([(one, MINIMUM)]));
        assert!(pool.stock(&found, &[], &protection).is_empty());
        assert!(pool.lengths(&Focus::Everything).is_empty());
        testkit::write_patterned(&target.join("debug/deps/two.rlib"), MINIMUM, 2);
        let two = platform::identity(&target.join("debug/deps/two.rlib")).unwrap();
        assert_eq!(
            pool.stock(&found, &[], &protection),
            BTreeMap::from([(two, MINIMUM)])
        );
        assert_eq!(pool.lengths(&Focus::Everything), BTreeSet::from([MINIMUM]));

        let three_path = target.join("debug/deps/three.rlib");
        testkit::write_patterned(&three_path, TWICE, 3);
        let changed = BTreeMap::from([(three_path.clone(), Event::Written)]);
        let three = platform::identity(&three_path).unwrap();
        assert_eq!(
            pool.note(found.path(), &changed),
            BTreeMap::from([(three, TWICE)])
        );
        assert!(pool.note(found.path(), &changed).is_empty());
        let deps = BTreeMap::from([(target.join("debug/deps"), Event::Unsure)]);
        assert!(pool.note(found.path(), &deps).is_empty());
        testkit::write_patterned(&target.join("debug/deps/four.rlib"), TWICE, 4);
        let four = platform::identity(&target.join("debug/deps/four.rlib")).unwrap();
        assert_eq!(
            pool.note(found.path(), &deps),
            BTreeMap::from([(four, TWICE)])
        );
        assert_eq!(
            pool.lengths(&Focus::Everything),
            BTreeSet::from([MINIMUM, TWICE])
        );
        testkit::remove_file(&three_path);
        let gone = BTreeMap::from([(three_path, Event::Vanished)]);
        assert!(pool.note(found.path(), &gone).is_empty());
        assert_eq!(pool.lengths(&Focus::Everything), BTreeSet::from([MINIMUM]));
        testkit::write_patterned(&target.join("debug/deps/nested/five.rlib"), TWICE, 5);
        let nested = BTreeMap::from([(target.join("debug/deps/nested"), Event::Appeared)]);
        assert_eq!(pool.note(found.path(), &nested).len(), 1);
        assert_eq!(
            pool.lengths(&Focus::Everything),
            BTreeSet::from([MINIMUM, TWICE])
        );
        testkit::remove_file(&target.join("debug/deps/four.rlib"));
        testkit::remove_tree(&target.join("debug/deps/nested"));
        assert!(pool.note(found.path(), &deps).is_empty());
        assert_eq!(pool.lengths(&Focus::Everything), BTreeSet::from([MINIMUM]));
        assert!(
            !pool
                .stocks
                .get(found.path())
                .unwrap()
                .files
                .contains_key(Path::new("debug/deps/nested/five.rlib"))
        );

        let method = pool.stocks.get_mut(found.path()).unwrap().method.take();
        let six = target.join("debug/deps/six.rlib");
        testkit::write_patterned(&six, TWICE, 6);
        assert!(
            pool.note(found.path(), &BTreeMap::from([(six, Event::Written)]))
                .is_empty()
        );
        assert_eq!(pool.stocks.get(found.path()).unwrap().files.len(), 2);
        pool.stocks.get_mut(found.path()).unwrap().method = method;
        pool.forget(found.path());
        assert!(pool.lengths.is_empty());
    }

    #[test]
    fn a_directory_event_only_relists_its_files_and_keeps_existing_subtrees() {
        let temp = testkit::tempdir("dedupe-directory-event");
        let root = fs::canonicalize(temp.path()).unwrap();
        let directory = root.join("deps");
        let direct = directory.join("direct.rlib");
        let nested = directory.join("nested/nested.rlib");
        let small = directory.join("small.rlib");
        let temporary = directory.join(format!("temporary{TEMPORARY_SUFFIX}"));
        testkit::write_patterned(&direct, MINIMUM, 1);
        testkit::write_patterned(&nested, MINIMUM, 2);
        testkit::write_patterned(&small, MINIMUM - 1, 3);
        testkit::write_patterned(&temporary, MINIMUM, 4);

        let shallow = present(&root, &directory, Event::Unsure);
        if shallow.is_empty() {
            assert!(
                std::env::var_os("STORAGE_SCOUT_REQUIRE_SHARING").is_none(),
                "this volume must share blocks"
            );
            let _skipped = testkit::Built::Unavailable(String::from("sharing is refused here"))
                .or_decline("a volume that shares blocks");
            return;
        }
        assert_eq!(
            shallow
                .iter()
                .map(|(path, _)| path.as_ref())
                .collect::<Vec<_>>(),
            [Path::new("deps/direct.rlib")]
        );
        let recursive = present(&root, &directory, Event::Appeared);
        assert_eq!(
            recursive
                .iter()
                .map(|(path, _)| path.as_ref())
                .collect::<Vec<_>>(),
            [
                Path::new("deps/direct.rlib"),
                Path::new("deps/nested/nested.rlib")
            ]
        );
        assert_eq!(present(&root, &direct, Event::Written).len(), 1);
        assert!(present(&root, &small, Event::Written).is_empty());
        assert!(present(&root, &temporary, Event::Written).is_empty());
        assert!(present(&root, &root.join("missing"), Event::Written).is_empty());

        let relative = Path::new("deps");
        let recorded = Path::new("deps/nested/nested.rlib");
        assert!(still_there(&directory, relative, recorded));
        testkit::remove_tree(&directory.join("nested"));
        assert!(!still_there(&directory, relative, recorded));
        assert!(!still_there(
            &directory,
            relative,
            Path::new("elsewhere/file")
        ));
    }
}
