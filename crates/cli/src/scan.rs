use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;
use serde::{Serialize, Serializer};
use storage_scout_core::area::{Area, Protection, SystemReason};
use storage_scout_core::artifact::{Entries, Listing};
use storage_scout_core::candidate::{Candidate, Measurement, Observed, Usage};
use storage_scout_core::gate::{self, Admission, Boundary, Shape, Site};
use storage_scout_core::location::Location;
use storage_scout_core::reject::{FsOp, Rejection};
use storage_scout_core::size::Bytes;

use crate::measure::{Measure, Tally};
use crate::owners::Owners;
use crate::{SCHEMA_VERSION, failure, host, observe, platform};

pub const DEFAULT_TOP: usize = 20;
pub const DEFAULT_MIN_SIZE: Bytes = Bytes::new(10 * 1024 * 1024);
pub(crate) const MAX_ISSUES: usize = 50;
const GIT_DIRECTORY: &str = ".git";
const CARGO_MANIFEST: &str = "Cargo.toml";

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub top: usize,
    pub min_size: Bytes,
    pub max_depth: Option<usize>,
    pub excludes: Vec<PathBuf>,
    pub threads: Option<usize>,
    pub measure: Measure,
}

impl ScanOptions {
    #[must_use]
    pub fn sighting(roots: &[PathBuf], excludes: &[PathBuf]) -> Self {
        Self {
            roots: roots.to_vec(),
            top: 0,
            min_size: Bytes::ZERO,
            max_depth: Some(0),
            excludes: excludes.to_vec(),
            threads: None,
            measure: Measure::Logical,
        }
    }

    #[must_use]
    pub const fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            top: DEFAULT_TOP,
            min_size: DEFAULT_MIN_SIZE,
            max_depth: Some(1),
            excludes: Vec::new(),
            threads: None,
            measure: Measure::Logical,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Found {
    path: PathBuf,
    candidate: Candidate,
}

impl Found {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn candidate(&self) -> &Candidate {
        &self.candidate
    }
}

impl Serialize for Found {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.candidate.serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryUsage {
    pub location: Location,
    pub depth: usize,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStats {
    pub directories: u64,
    pub files: u64,
    pub links_skipped: u64,
    pub mount_boundaries_skipped: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub roots: Vec<Location>,
    pub listing_limit: usize,
    pub usage: Usage,
    pub stats: ScanStats,
    pub largest_directories: Vec<DirectoryUsage>,
    pub candidates: Vec<Found>,
    pub issues: Vec<Rejection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Descent {
    Measure,
    Sight(Reach),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    Everything,
    Children,
}

#[derive(Debug, Clone)]
pub(crate) struct Sighting {
    pub report: ScanReport,
    pub hosts: Vec<PathBuf>,
}

struct Collector<'a> {
    options: &'a ScanOptions,
    descent: Descent,
    hosts: &'a Mutex<Vec<PathBuf>>,
    protection: &'a Protection,
    owners: &'a Owners,
    excludes: Vec<Location>,
    directories: Mutex<Vec<DirectoryUsage>>,
    candidates: Mutex<Vec<Found>>,
    issues: Mutex<Vec<Rejection>>,
    directory_count: AtomicU64,
    files: AtomicU64,
    links_skipped: AtomicU64,
    mount_boundaries_skipped: AtomicU64,
    errors: AtomicU64,
}

impl Collector<'_> {
    fn issue(&self, rejection: Rejection) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut issues) = self.issues.lock()
            && issues.len() < MAX_ISSUES
        {
            issues.push(rejection);
        }
    }

    fn excluded(&self, location: &Location) -> bool {
        self.excludes
            .iter()
            .any(|exclude| self.protection.contains(exclude, location))
    }
}

struct Contents {
    files: Vec<(PathBuf, Metadata)>,
    directories: Vec<(PathBuf, Metadata)>,
    names: Entries,
}

pub(crate) fn excludes(paths: &[PathBuf]) -> Vec<Location> {
    paths
        .iter()
        .filter_map(|path| {
            let absolute = match fs::canonicalize(path) {
                Ok(canonical) => canonical,
                Err(_absent) => match std::path::absolute(path) {
                    Ok(absolute) => absolute,
                    Err(_unresolvable) => return None,
                },
            };
            match host::locate(&absolute) {
                Ok(location) => Some(location),
                Err(_unnameable) => None,
            }
        })
        .collect()
}

pub(crate) fn scan(options: &ScanOptions, protection: &Protection, owners: &Owners) -> ScanReport {
    collect(
        options,
        protection,
        owners,
        Descent::Measure,
        &Mutex::new(Vec::new()),
    )
}

pub(crate) fn sight(
    options: &ScanOptions,
    protection: &Protection,
    owners: &Owners,
    reach: Reach,
) -> Sighting {
    let sighting = ScanOptions {
        measure: Measure::Logical,
        min_size: Bytes::ZERO,
        ..options.clone()
    };
    let hosts = Mutex::new(Vec::new());
    let report = collect(&sighting, protection, owners, Descent::Sight(reach), &hosts);
    let mut hosts = drain(hosts);
    hosts.sort();
    hosts.dedup();
    Sighting { report, hosts }
}

pub(crate) fn measured(found: &Found, protection: &Protection) -> Result<Found, Rejection> {
    let measurement = crate::measure::strictly(&found.path)?;
    Ok(Found {
        path: found.path.clone(),
        candidate: found.candidate.measured(&measurement, protection.case()),
    })
}

fn collect(
    options: &ScanOptions,
    protection: &Protection,
    owners: &Owners,
    descent: Descent,
    hosts: &Mutex<Vec<PathBuf>>,
) -> ScanReport {
    let collector = Collector {
        options,
        descent,
        hosts,
        protection,
        owners,
        excludes: excludes(&options.excludes),
        directories: Mutex::new(Vec::new()),
        candidates: Mutex::new(Vec::new()),
        issues: Mutex::new(Vec::new()),
        directory_count: AtomicU64::new(0),
        files: AtomicU64::new(0),
        links_skipped: AtomicU64::new(0),
        mount_boundaries_skipped: AtomicU64::new(0),
        errors: AtomicU64::new(0),
    };
    let roots = roots(options, &collector);
    let walk_all = || {
        roots
            .par_iter()
            .map(|(path, _)| enter(path, &collector))
            .reduce(|| Tally::empty(options.measure), Tally::merge)
    };
    let pool = options.threads.and_then(|threads| {
        match rayon::ThreadPoolBuilder::new().num_threads(threads).build() {
            Ok(pool) => Some(pool),
            Err(_unbuildable) => None,
        }
    });
    let total = match pool {
        Some(pool) => pool.install(walk_all),
        None => walk_all(),
    };

    let mut largest = drain(collector.directories);
    largest.sort_by(|left, right| {
        (Reverse(left.usage.logical), &left.location)
            .cmp(&(Reverse(right.usage.logical), &right.location))
    });
    largest.truncate(options.top);

    let mut candidates = drain(collector.candidates);
    candidates.sort_by(|left, right| {
        (
            Reverse(left.candidate.usage().logical),
            left.candidate.location(),
        )
            .cmp(&(
                Reverse(right.candidate.usage().logical),
                right.candidate.location(),
            ))
    });
    let mut seen = BTreeSet::new();
    candidates.retain(|found| seen.insert(found.candidate.location().key(protection.case())));

    ScanReport {
        schema_version: SCHEMA_VERSION,
        roots: roots.into_iter().map(|(_, location)| location).collect(),
        listing_limit: options.top,
        usage: total.usage(),
        stats: ScanStats {
            directories: collector.directory_count.load(Ordering::Relaxed),
            files: collector.files.load(Ordering::Relaxed),
            links_skipped: collector.links_skipped.load(Ordering::Relaxed),
            mount_boundaries_skipped: collector.mount_boundaries_skipped.load(Ordering::Relaxed),
            errors: collector.errors.load(Ordering::Relaxed),
        },
        largest_directories: largest,
        candidates,
        issues: drain(collector.issues),
    }
}

fn drain<T>(values: Mutex<Vec<T>>) -> Vec<T> {
    match values.into_inner() {
        Ok(values) => values,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn accepted(root: &Path, collector: &Collector<'_>) -> Option<(PathBuf, Location)> {
    let observed = match observe::observe(root) {
        Ok(observed) => observed,
        Err(rejection) => {
            collector.issue(rejection);
            return None;
        },
    };
    match observed.shape {
        Shape::Directory => Some((observed.path, observed.location)),
        Shape::Link => {
            collector.issue(Rejection::Link {
                location: observed.location,
            });
            None
        },
        Shape::File | Shape::Other => {
            collector.issue(Rejection::NotADirectory {
                location: observed.location,
            });
            None
        },
    }
}

fn roots(options: &ScanOptions, collector: &Collector<'_>) -> Vec<(PathBuf, Location)> {
    let mut roots: Vec<(PathBuf, Location)> = Vec::new();
    for (path, location) in options
        .roots
        .iter()
        .filter_map(|root| accepted(root, collector))
    {
        let covered = collector.excluded(&location)
            || roots
                .iter()
                .any(|(_, existing)| collector.protection.contains(existing, &location));
        if !covered {
            roots.retain(|(_, existing)| !collector.protection.contains(&location, existing));
            roots.push((path, location));
        }
    }
    roots
}

pub(crate) fn validate_root(path: &Path, protection: &Protection) -> Result<PathBuf, Rejection> {
    let observed = observe::observe(path)?;
    match observed.shape {
        Shape::Directory => {},
        Shape::Link => {
            return Err(Rejection::Link {
                location: observed.location,
            });
        },
        Shape::File | Shape::Other => {
            return Err(Rejection::NotADirectory {
                location: observed.location,
            });
        },
    }
    match protection.area_of(&observed.location) {
        Area::System(SystemReason::CurrentDirectory | SystemReason::RunningBinary)
        | Area::AppOwned(_)
        | Area::Open => Ok(observed.path),
        Area::System(
            area @ (SystemReason::FilesystemRoot
            | SystemReason::SystemArea { .. }
            | SystemReason::ProfileRoot
            | SystemReason::UsersRoot
            | SystemReason::VolumeRoot),
        ) => Err(Rejection::Protected {
            location: observed.location,
            area,
        }),
    }
}

fn enter(root: &Path, collector: &Collector<'_>) -> Tally {
    match fs::symlink_metadata(root) {
        Ok(metadata) => walk(root, &metadata, 0, Region::Root, collector),
        Err(error) => {
            collector.issue(failure::io(root, FsOp::Inspect, &error));
            Tally::empty(collector.options.measure)
        },
    }
}

#[derive(Debug, Clone, Copy)]
enum Region<'a> {
    Root,
    Open { parent: &'a Entries },
    Artifact,
}

struct Here<'a> {
    directory: &'a Path,
    metadata: &'a Metadata,
    location: &'a Location,
}

fn admission(
    here: &Here<'_>,
    region: Region<'_>,
    contents: &Contents,
    collector: &Collector<'_>,
) -> Option<Admission> {
    let Here {
        directory,
        metadata,
        location,
    } = *here;
    match region {
        Region::Root | Region::Artifact => None,
        Region::Open { parent } => {
            let listing = Listing::new(
                parent.clone(),
                contents.names.clone(),
                observe::tags(directory, &contents.names),
            );
            let site = Site {
                location,
                shape: Shape::Directory,
                boundary: match platform::device(metadata) {
                    Some(device) => Boundary::Same { device },
                    None => Boundary::Unreported,
                },
                listing: &listing,
                protection: collector.protection,
                excludes: &collector.excludes,
            };
            match gate::admit(&site) {
                Ok(admission) => Some(admission),
                Err(_not_a_candidate) => None,
            }
        },
    }
}

fn walk(
    directory: &Path,
    metadata: &Metadata,
    depth: usize,
    region: Region<'_>,
    collector: &Collector<'_>,
) -> Tally {
    let location = match host::locate(directory) {
        Ok(location) => location,
        Err(rejection) => {
            collector.issue(rejection);
            return Tally::empty(collector.options.measure);
        },
    };
    if collector.excluded(&location)
        || (collector.descent != Descent::Measure
            && directory.file_name() == Some(std::ffi::OsStr::new(GIT_DIRECTORY)))
    {
        return Tally::empty(collector.options.measure);
    }
    let Some(contents) = read(directory, metadata, collector) else {
        return Tally::empty(collector.options.measure);
    };
    collector.directory_count.fetch_add(1, Ordering::Relaxed);

    let here = Here {
        directory,
        metadata,
        location: &location,
    };
    let admission = match (
        collector.descent,
        admission(&here, region, &contents, collector),
    ) {
        (Descent::Sight(_), Some(admission)) => {
            sighted(directory, admission, collector);
            return Tally::empty(collector.options.measure);
        },
        (Descent::Sight(reach), None) => {
            if contents.names.has_file(CARGO_MANIFEST)
                && let Ok(mut hosts) = collector.hosts.lock()
            {
                hosts.push(directory.to_path_buf());
            }
            if reach == Reach::Children && depth > 0 {
                return Tally::empty(collector.options.measure);
            }
            None
        },
        (Descent::Measure, admission) => admission,
    };
    let inside = match (region, &admission) {
        (Region::Artifact, _) | (Region::Root | Region::Open { .. }, Some(_)) => true,
        (Region::Root | Region::Open { .. }, None) => false,
    };

    let mut tally = match collector.descent {
        Descent::Measure => {
            let mut tally = files(&contents.files, collector);
            if contents.names.has_file(crate::owners::MARKER_NAME) {
                tally.marker(directory);
            }
            tally
        },
        Descent::Sight(_) => Tally::empty(collector.options.measure),
    };
    let children = contents
        .directories
        .par_iter()
        .map(|(child, child_metadata)| {
            let next = if inside {
                Region::Artifact
            } else {
                Region::Open {
                    parent: &contents.names,
                }
            };
            walk(
                child,
                child_metadata,
                depth.saturating_add(1),
                next,
                collector,
            )
        })
        .reduce(|| Tally::empty(collector.options.measure), Tally::merge);
    tally = tally.merge(children);

    if let Some(admission) = admission {
        record(directory, admission, &tally, collector);
    } else if !inside
        && collector.descent == Descent::Measure
        && collector.options.max_depth.is_none_or(|max| depth <= max)
        && tally.logical() >= collector.options.min_size
        && let Ok(mut directories) = collector.directories.lock()
    {
        directories.push(DirectoryUsage {
            location,
            depth,
            usage: tally.usage(),
        });
    }
    tally
}

fn read(directory: &Path, metadata: &Metadata, collector: &Collector<'_>) -> Option<Contents> {
    let reader = match fs::read_dir(directory) {
        Ok(reader) => reader,
        Err(error) => {
            collector.issue(failure::io(directory, FsOp::ReadDir, &error));
            return None;
        },
    };
    let mut contents = Contents {
        files: Vec::new(),
        directories: Vec::new(),
        names: Entries::default(),
    };
    for entry in reader {
        match entry {
            Ok(entry) => admit_entry(&entry, metadata, &mut contents, collector),
            Err(error) => collector.issue(failure::io(directory, FsOp::ReadEntry, &error)),
        }
    }
    Some(contents)
}

fn admit_entry(
    entry: &fs::DirEntry,
    metadata: &Metadata,
    contents: &mut Contents,
    collector: &Collector<'_>,
) {
    let path = entry.path();
    let child = match fs::symlink_metadata(&path) {
        Ok(child) => child,
        Err(error) => {
            collector.issue(failure::io(&path, FsOp::Metadata, &error));
            return;
        },
    };
    let name = entry.file_name();
    match platform::shape(&child) {
        Shape::Link => {
            collector.links_skipped.fetch_add(1, Ordering::Relaxed);
        },
        Shape::Directory => {
            if let (Some(from), Some(to)) = (platform::device(metadata), platform::device(&child))
                && from != to
            {
                collector
                    .mount_boundaries_skipped
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            contents.names.dir(name.as_encoded_bytes());
            contents.directories.push((path, child));
        },
        Shape::File => {
            contents.names.file(name.as_encoded_bytes());
            contents.files.push((path, child));
        },
        Shape::Other => {},
    }
}

fn files(files: &[(PathBuf, Metadata)], collector: &Collector<'_>) -> Tally {
    let mut tally = Tally::empty(collector.options.measure);
    let count = match u64::try_from(files.len()) {
        Ok(count) => count,
        Err(_too_many) => u64::MAX,
    };
    collector.files.fetch_add(count, Ordering::Relaxed);
    for (path, metadata) in files {
        let mut identity = platform::identity_of_metadata(metadata);
        match collector.options.measure {
            Measure::Logical => {},
            Measure::Allocated => match platform::file_measure(path) {
                Ok(measured) => {
                    identity = Some(measured.identity);
                    tally.allocated(measured);
                },
                Err(error) => {
                    tally.unmeasurable();
                    collector.issue(failure::io(path, FsOp::AllocationInfo, &error));
                },
            },
        }
        tally.file(path, metadata.len(), identity);
    }
    tally
}

fn sighted(directory: &Path, admission: Admission, collector: &Collector<'_>) {
    let identity = match platform::identity(directory) {
        Ok(identity) => identity,
        Err(error) => {
            collector.issue(failure::io(directory, FsOp::FileId, &error));
            return;
        },
    };
    let markers = match admission.kind().protocol() {
        Some(_) => match crate::busy::survey(directory) {
            Ok(survey) => survey.markers,
            Err(rejection) => {
                collector.issue(rejection);
                Vec::new()
            },
        },
        None => Vec::new(),
    };
    let candidate = Candidate::new(
        admission,
        Observed {
            identity,
            measurement: Measurement::UNMEASURED,
            ownership: collector.owners.of(directory, &markers),
        },
        collector.protection.case(),
    );
    if let Ok(mut candidates) = collector.candidates.lock() {
        candidates.push(Found {
            path: directory.to_path_buf(),
            candidate,
        });
    }
}

fn record(directory: &Path, admission: Admission, tally: &Tally, collector: &Collector<'_>) {
    if tally.logical() < collector.options.min_size {
        return;
    }
    let identity = match platform::identity(directory) {
        Ok(identity) => identity,
        Err(error) => {
            collector.issue(failure::io(directory, FsOp::FileId, &error));
            return;
        },
    };
    let candidate = Candidate::new(
        admission,
        Observed {
            identity,
            measurement: tally.measurement(),
            ownership: collector.owners.of(directory, tally.markers()),
        },
        collector.protection.case(),
    );
    if let Ok(mut candidates) = collector.candidates.lock() {
        candidates.push(Found {
            path: directory.to_path_buf(),
            candidate,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sighting_names_every_project_it_passes_that_has_no_target_yet() {
        let temp = testkit::tempdir("scan-hosts");
        let root = fs::canonicalize(temp.path()).unwrap().join("work");
        let built = testkit::write_cargo_project(&root.join("built"), 1);
        testkit::write_cache_tag(&built);
        let deep = root.join("deep").join("down").join("bare");
        testkit::write_sized(&root.join("bare").join("Cargo.toml"), 1);
        testkit::write_sized(&deep.join("Cargo.toml"), 1);
        testkit::write_sized(&root.join("plain").join("readme"), 1);
        testkit::write_sized(
            &root
                .join("repo")
                .join(".git")
                .join("modules")
                .join("Cargo.toml"),
            1,
        );
        let options = ScanOptions::sighting(std::slice::from_ref(&root), &[]);
        let protection = testkit::open_protection();
        let owners = Owners::default();
        let everything = sight(&options, &protection, &owners, Reach::Everything);
        assert_eq!(
            everything.hosts,
            [root.join("bare"), root.join("built"), deep]
        );
        assert_eq!(
            everything
                .report
                .candidates
                .iter()
                .map(Found::path)
                .collect::<Vec<_>>(),
            [built.as_path()]
        );
        let children = sight(&options, &protection, &owners, Reach::Children);
        assert_eq!(children.hosts, [root.join("bare"), root.join("built")]);
        assert!(children.report.candidates.is_empty());
    }
}
