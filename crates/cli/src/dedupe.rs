mod capability;

use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
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
use crate::platform::{self, FileFacts, Request};
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
    let top = fs::symlink_metadata(root).map_err(|e| failure::io(root, FsOp::Inspect, &e))?;
    let device = platform::device(&top);
    let mut pending = vec![root.to_path_buf()];
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
                    Err(failure) => PairStatus::Failed { failure },
                },
            }
        },
    }
}

fn free_space(found: &[Found]) -> Volumes {
    Volumes::sample(found.iter().map(|each| {
        (
            each.candidate().identity().volume,
            each.path().parent().unwrap_or_else(|| each.path()),
        )
    }))
}

fn survey<'f>(found: &'f [Found], terms: &Terms<'_>) -> (Vec<Subject>, Vec<Item<'f>>) {
    let mut subjects = Vec::with_capacity(found.len());
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    for each in found {
        let admitted = admit(each, terms)
            .and_then(|method| inventory(each.path()).map(|listed| (method, listed)));
        let admission = match admitted {
            Err(rejection) => Admission::Rejected { rejection },
            Ok((method, listed)) => {
                let files = listed.files.len();
                for (path, relative, facts) in listed.files {
                    if seen.insert(facts.identity)
                        && let Ok(location) = host::locate(&path)
                    {
                        items.push(Item {
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
                            found: each,
                            path,
                            relative,
                        });
                    }
                }
                Admission::Admitted {
                    method,
                    files,
                    unreadable: listed.unreadable,
                }
            },
        };
        subjects.push(Subject {
            id: each.candidate().id().clone(),
            location: each.candidate().location().clone(),
            admission,
        });
    }
    (subjects, items)
}

pub(crate) fn run(
    found: &[Found],
    excludes: &[Location],
    protection: &Protection,
    mode: Mode,
) -> DedupeRun {
    let terms = Terms {
        excludes,
        protection,
    };
    let before = match mode {
        Mode::Execute => Some(free_space(found)),
        Mode::DryRun => None,
    };
    let (subjects, items) = survey(found, &terms);
    let sized = share::groups(&items);
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
        observed_freed: before.and_then(|before| before.gained(&free_space(found))),
        pairs: outcomes,
    }
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
}
