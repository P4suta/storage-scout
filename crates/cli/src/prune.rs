mod capability;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Serialize;
use storage_scout_core::area::Protection;
use storage_scout_core::candidate::{CandidateId, Identity};
use storage_scout_core::gate::{self, PruneCheck};
use storage_scout_core::location::Location;
use storage_scout_core::lock::{Liveness, Protocol};
use storage_scout_core::macho::{self, MachError};
use storage_scout_core::prune::{self, Object, Rule, Session};
use storage_scout_core::reject::Rejection;
use storage_scout_core::size::Bytes;

use self::capability::Prunable;
use crate::apply::Mode;
use crate::dedupe::Tally;
use crate::measure::Volumes;
use crate::owners::Owners;
use crate::platform::{self, Pruned};
use crate::scan::Found;
use crate::{SCHEMA_VERSION, busy, observe};

const FINGERPRINT: &str = ".fingerprint";
const BUILD: &str = "build";
const LONGEST_NAME: u64 = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Removed {
    pub stale_objects: Tally,
    pub superseded_sessions: Tally,
    pub abandoned_sessions: Tally,
}

impl Removed {
    const fn slot(&mut self, rule: Rule) -> &mut Tally {
        match rule {
            Rule::StaleObject => &mut self.stale_objects,
            Rule::SupersededSession => &mut self.superseded_sessions,
            Rule::AbandonedSession => &mut self.abandoned_sessions,
        }
    }

    const fn add(&mut self, rule: Rule, len: u64) {
        self.slot(rule).add(len);
    }

    fn merge(&mut self, other: &Self) {
        for rule in Rule::ALL {
            let theirs = match rule {
                Rule::StaleObject => other.stale_objects,
                Rule::SupersededSession => other.superseded_sessions,
                Rule::AbandonedSession => other.abandoned_sessions,
            };
            self.slot(*rule).merge(theirs);
        }
    }

    #[must_use]
    pub const fn files(&self) -> u64 {
        self.stale_objects
            .files
            .saturating_add(self.superseded_sessions.files)
            .saturating_add(self.abandoned_sessions.files)
    }

    #[must_use]
    pub const fn bytes(&self) -> Bytes {
        self.stale_objects
            .bytes
            .saturating_add(self.superseded_sessions.bytes)
            .saturating_add(self.abandoned_sessions.bytes)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum PruneAdmission {
    Admitted { profiles: usize },
    Rejected { rejection: Rejection },
}

#[derive(Debug, Clone, Serialize)]
pub struct PruneSubject {
    pub id: CandidateId,
    pub location: Location,
    pub admission: PruneAdmission,
    pub removed: Removed,
    pub held: Tally,
    pub unreadable_images: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PruneFailure {
    pub rule: Rule,
    pub rejection: Rejection,
}

#[derive(Debug, Clone, Serialize)]
pub struct PruneRun {
    pub schema_version: u32,
    pub command: &'static str,
    pub mode: Mode,
    pub subjects: Vec<PruneSubject>,
    pub totals: Removed,
    pub failures: Vec<PruneFailure>,
    pub observed_freed: Option<Bytes>,
}

impl PruneRun {
    #[must_use]
    pub const fn failed(&self) -> bool {
        !self.failures.is_empty()
    }

    #[must_use]
    pub(crate) fn summarized(mut self) -> Self {
        self.subjects.retain(|subject| {
            subject.removed.files() > 0
                || subject.held.files > 0
                || matches!(
                    subject.admission,
                    PruneAdmission::Rejected {
                        rejection: Rejection::Io { .. }
                    }
                )
        });
        self
    }
}

pub(super) enum Doom {
    File,
    Session { lock: OsString },
}

pub(super) struct Doomed {
    relative: PathBuf,
    identity: Identity,
    len: u64,
    rule: Rule,
    doom: Doom,
}

struct Terms<'a> {
    excludes: &'a [Location],
    protection: &'a Protection,
    owners: &'a Owners,
}

fn named(bytes: &[u8]) -> Option<&OsStr> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(OsStr::new(text)),
        Err(_foreign) => None,
    }
}

fn listed(directory: &Path, wanted: fn(&fs::FileType) -> bool) -> Vec<OsString> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut names = entries
        .filter_map(|entry| match entry {
            Ok(entry) => match entry.file_type() {
                Ok(kind) if wanted(&kind) => Some(entry.file_name()),
                Ok(_) | Err(_) => None,
            },
            Err(_unreadable) => None,
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn weight(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(entry.path()),
                Ok(kind) if kind.is_file() => {
                    if let Ok(metadata) = entry.metadata() {
                        total = total.saturating_add(metadata.len());
                    }
                },
                Ok(_) | Err(_) => {},
            }
        }
    }
    total
}

fn relative(root: &Path, path: &Path) -> Option<PathBuf> {
    match path.strip_prefix(root) {
        Ok(relative) => Some(relative.to_path_buf()),
        Err(_outside) => None,
    }
}

fn sessions(root: &Path, profile: &Path, doomed: &mut Vec<Doomed>) {
    let incremental = profile.join(prune::INCREMENTAL);
    for unit in listed(&incremental, fs::FileType::is_dir) {
        let directory = incremental.join(&unit);
        let names = listed(&directory, fs::FileType::is_dir);
        let parsed = names
            .iter()
            .filter_map(|name| Session::parse(name.as_encoded_bytes()))
            .collect::<Vec<Session<'_>>>();
        for (session, rule) in prune::doomed(&parsed) {
            let lock_name = session.lock_name();
            let (Some(name), Some(lock)) = (named(session.name), named(&lock_name)) else {
                continue;
            };
            let path = directory.join(name);
            let (Ok(identity), Some(relative)) = (platform::identity(&path), relative(root, &path))
            else {
                continue;
            };
            doomed.push(Doomed {
                relative,
                identity,
                len: weight(&path),
                rule,
                doom: Doom::Session {
                    lock: lock.to_os_string(),
                },
            });
        }
    }
}

#[derive(Debug)]
enum ImageError {
    Absent,
    Io,
    Mach,
}

impl From<io::Error> for ImageError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::NotFound {
            Self::Absent
        } else {
            Self::Io
        }
    }
}

impl From<MachError> for ImageError {
    fn from(_malformed: MachError) -> Self {
        Self::Mach
    }
}

fn exactly(file: &mut File, at: u64, len: u64) -> Result<Vec<u8>, ImageError> {
    file.seek(SeekFrom::Start(at))?;
    let mut bytes = Vec::new();
    Read::take(&mut *file, len).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()) == Ok(len) {
        Ok(bytes)
    } else {
        Err(ImageError::Mach)
    }
}

fn debug_offsets(file: &mut File, symtab: &macho::Symtab) -> Result<Vec<u32>, ImageError> {
    file.seek(SeekFrom::Start(symtab.symbols))?;
    let mut symbols = BufReader::new(file);
    let mut symbol = [0u8; macho::SYMBOL_LEN];
    let mut offsets = Vec::new();
    for _ in 0..symtab.count {
        symbols.read_exact(&mut symbol)?;
        offsets.extend(macho::debug_objects(&symbol));
    }
    Ok(offsets)
}

fn debug_objects(path: &Path) -> Result<BTreeSet<Vec<u8>>, ImageError> {
    let mut file = platform::open_regular(path)?;
    let header = exactly(
        &mut file,
        0,
        u64::try_from(macho::HEADER_LEN).map_err(|_wide| ImageError::Mach)?,
    )?;
    let commands = macho::header(&header)?;
    let table = exactly(
        &mut file,
        u64::try_from(macho::HEADER_LEN).map_err(|_wide| ImageError::Mach)?,
        u64::from(commands.len),
    )?;
    let symtab = macho::symtab(&table, commands.count)?;
    let offsets = debug_offsets(&mut file, &symtab)?;
    let mut names = BTreeSet::new();
    for offset in offsets {
        let offset = u64::from(offset);
        let left = symtab
            .strings_len
            .checked_sub(offset)
            .ok_or(ImageError::Mach)?;
        let start = symtab.strings.checked_add(offset).ok_or(ImageError::Mach)?;
        let bytes = exactly(&mut file, start, left.min(LONGEST_NAME))?;
        let recorded = macho::terminated(&bytes).ok_or(ImageError::Mach)?;
        names.insert(macho::base_name(recorded).to_vec());
    }
    Ok(names)
}

fn referenced(directory: &Path, unit: &[u8]) -> Option<Result<BTreeSet<Vec<u8>>, ImageError>> {
    let mut found = false;
    let mut names = BTreeSet::new();
    for image in prune::images(unit) {
        let Some(image) = named(&image) else {
            return Some(Err(ImageError::Mach));
        };
        match debug_objects(&directory.join(image)) {
            Ok(objects) => {
                found = true;
                names.extend(objects);
            },
            Err(ImageError::Absent) => {},
            Err(error) => return Some(Err(error)),
        }
    }
    found.then_some(Ok(names))
}

fn object_directories(profile: &Path) -> Vec<PathBuf> {
    let mut directories = prune::OBJECT_DIRECTORIES
        .iter()
        .map(|name| profile.join(name))
        .collect::<Vec<_>>();
    let build = profile.join(BUILD);
    directories.extend(
        listed(&build, fs::FileType::is_dir)
            .into_iter()
            .map(|name| build.join(name)),
    );
    directories
}

fn objects(root: &Path, profile: &Path, doomed: &mut Vec<Doomed>) -> u64 {
    let mut unreadable = 0u64;
    for directory in object_directories(profile) {
        let names = listed(&directory, fs::FileType::is_file);
        let parsed = names
            .iter()
            .filter_map(|name| Object::parse(name.as_encoded_bytes()))
            .collect::<Vec<Object<'_>>>();
        let by_bytes = names
            .iter()
            .map(|name| (name.as_encoded_bytes(), name.as_os_str()))
            .collect::<BTreeMap<_, _>>();
        for unit in prune::mixed(&parsed) {
            let references = match referenced(&directory, unit) {
                None => continue,
                Some(Err(_unreadable)) => {
                    unreadable = unreadable.saturating_add(1);
                    continue;
                },
                Some(Ok(references)) => references,
            };
            for stale in prune::stale(&parsed, unit, &references) {
                let Some(name) = by_bytes.get(stale) else {
                    continue;
                };
                let path = directory.join(name);
                let (Ok(metadata), Some(relative)) =
                    (fs::symlink_metadata(&path), relative(root, &path))
                else {
                    continue;
                };
                let Ok(identity) = platform::identity(&path) else {
                    continue;
                };
                doomed.push(Doomed {
                    relative,
                    identity,
                    len: metadata.len(),
                    rule: Rule::StaleObject,
                    doom: Doom::File,
                });
            }
        }
    }
    unreadable
}

fn profiles(survey: &busy::Survey) -> Vec<PathBuf> {
    let mut found = survey
        .locks
        .iter()
        .filter(|lock| lock.protocol() == Protocol::Cargo)
        .filter_map(|lock| lock.path().parent())
        .filter(
            |profile| match fs::symlink_metadata(profile.join(FINGERPRINT)) {
                Ok(metadata) => metadata.is_dir(),
                Err(_absent) => false,
            },
        )
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    found.sort();
    found.dedup();
    found
}

struct Gathered {
    profiles: usize,
    doomed: Vec<Doomed>,
    unreadable: u64,
}

fn gather(root: &Path, survey: &busy::Survey) -> Gathered {
    let profiles = profiles(survey);
    let mut doomed = Vec::new();
    let mut unreadable = 0u64;
    for profile in &profiles {
        sessions(root, profile, &mut doomed);
        unreadable = unreadable.saturating_add(objects(root, profile, &mut doomed));
    }
    Gathered {
        profiles: profiles.len(),
        doomed,
        unreadable,
    }
}

struct Pass {
    subject: PruneSubject,
    failures: Vec<PruneFailure>,
}

fn rejected(found: &Found, rejection: Rejection) -> Pass {
    Pass {
        subject: PruneSubject {
            id: found.candidate().id().clone(),
            location: found.candidate().location().clone(),
            admission: PruneAdmission::Rejected { rejection },
            removed: Removed::default(),
            held: Tally::default(),
            unreadable_images: 0,
        },
        failures: Vec::new(),
    }
}

fn candidate(found: &Found, terms: &Terms<'_>, mode: Mode) -> Pass {
    let attempt = || -> Result<Pass, Rejection> {
        let observed = observe::observe(found.path())?;
        let site = observed.site(terms.protection, terms.excludes);
        let survey = busy::survey(&observed.path)?;
        let ownership = terms.owners.of(&observed.path, &survey.markers);
        let (lease, liveness) = match mode {
            Mode::DryRun => match busy::probe(&survey.locks) {
                Ok(()) => (None, Liveness::Free),
                Err(contention) => (None, contention.liveness()),
            },
            Mode::Execute => match busy::lease(&survey.locks) {
                Ok(lease) => (Some(lease), Liveness::Free),
                Err(contention) => (None, contention.liveness()),
            },
        };
        let clearance = gate::clear_prune(
            &site,
            &PruneCheck {
                recorded: found.candidate(),
                identity: observed.identity,
                ownership: &ownership,
                liveness: &liveness,
            },
        )?;
        let prunable = match lease {
            Some(lease) => Some(Prunable::new(clearance, lease, &observed.path)?),
            None => None,
        };
        let gathered = gather(&observed.path, &survey);
        let mut removed = Removed::default();
        let mut held = Tally::default();
        let mut failures = Vec::new();
        for doomed in &gathered.doomed {
            let outcome = match &prunable {
                None => Ok(Pruned::Removed),
                Some(prunable) => prunable.prune(doomed),
            };
            match outcome {
                Ok(Pruned::Removed) => removed.add(doomed.rule, doomed.len),
                Ok(Pruned::Held) => held.add(doomed.len),
                Ok(Pruned::Moved) => {},
                Err(rejection) => failures.push(PruneFailure {
                    rule: doomed.rule,
                    rejection,
                }),
            }
        }
        Ok(Pass {
            subject: PruneSubject {
                id: found.candidate().id().clone(),
                location: observed.location,
                admission: PruneAdmission::Admitted {
                    profiles: gathered.profiles,
                },
                removed,
                held,
                unreadable_images: gathered.unreadable,
            },
            failures,
        })
    };
    match attempt() {
        Ok(pass) => pass,
        Err(rejection) => rejected(found, rejection),
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

pub(crate) fn run(
    found: &[Found],
    excludes: &[Location],
    protection: &Protection,
    owners: &Owners,
    mode: Mode,
) -> PruneRun {
    let terms = Terms {
        excludes,
        protection,
        owners,
    };
    let before = match mode {
        Mode::Execute => Some(free_space(found)),
        Mode::DryRun => None,
    };
    let mut subjects = Vec::with_capacity(found.len());
    let mut failures = Vec::new();
    let mut totals = Removed::default();
    for each in found {
        let pass = candidate(each, &terms, mode);
        totals.merge(&pass.subject.removed);
        failures.extend(pass.failures);
        subjects.push(pass.subject);
    }
    PruneRun {
        schema_version: SCHEMA_VERSION,
        command: "prune",
        mode,
        subjects,
        totals,
        failures,
        observed_freed: before.and_then(|before| before.gained(&free_space(found))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_is_not_text_is_left_alone() {
        assert_eq!(named(b"s-a-b-c"), Some(OsStr::new("s-a-b-c")));
        assert_eq!(named(&[0xff, 0xfe]), None);
    }

    #[test]
    fn removals_add_up_per_rule() {
        let mut one = Removed::default();
        one.add(Rule::StaleObject, 10);
        one.add(Rule::SupersededSession, 20);
        let mut two = Removed::default();
        two.add(Rule::AbandonedSession, 5);
        two.add(Rule::StaleObject, 1);
        one.merge(&two);
        assert_eq!(one.stale_objects.files, 2);
        assert_eq!(one.stale_objects.bytes, Bytes::new(11));
        assert_eq!(one.files(), 4);
        assert_eq!(one.bytes(), Bytes::new(36));
    }
}
