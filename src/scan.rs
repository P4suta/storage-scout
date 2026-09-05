//! Parallel, read-only filesystem traversal and allocation-aware measurement.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, UNIX_EPOCH};

use rayon::prelude::*;

use crate::artifact::{self, Evidence};
use crate::safety::{self, Classification, is_reparse_point};
use crate::windows::{self, FileIdentity};
use crate::{
    ArtifactCandidate, Bytes, DirectoryUsage, MAX_ISSUES, Measure, SCHEMA_VERSION, ScanIssue,
    ScanOptions, ScanReport, ScanStats, Usage, make_candidate_id,
};

#[derive(Debug, Clone, Copy)]
struct HardLink {
    allocation: u64,
    links: u32,
    occurrences: u32,
}

#[derive(Debug)]
struct Subtree {
    logical: u64,
    allocated_unlinked: u64,
    allocation_available: bool,
    hard_links: HashMap<FileIdentity, HardLink>,
    newest: u128,
}

impl Subtree {
    fn empty(measure: Measure) -> Self {
        Self {
            logical: 0,
            allocated_unlinked: 0,
            allocation_available: measure == Measure::Both,
            hard_links: HashMap::new(),
            newest: 0,
        }
    }

    fn merge(mut self, other: Self) -> Self {
        self.logical = self.logical.saturating_add(other.logical);
        self.allocated_unlinked = self
            .allocated_unlinked
            .saturating_add(other.allocated_unlinked);
        self.allocation_available &= other.allocation_available;
        self.newest = self.newest.max(other.newest);
        for (identity, value) in other.hard_links {
            self.hard_links
                .entry(identity)
                .and_modify(|current| {
                    current.occurrences = current.occurrences.saturating_add(value.occurrences);
                    current.links = current.links.max(value.links);
                    current.allocation = current.allocation.max(value.allocation);
                })
                .or_insert(value);
        }
        self
    }

    fn usage(&self) -> Usage {
        let allocated = self.allocation_available.then(|| {
            Bytes(
                self.hard_links
                    .values()
                    .fold(self.allocated_unlinked, |total, link| {
                        total.saturating_add(link.allocation)
                    }),
            )
        });
        let reclaimable = self.allocation_available.then(|| {
            Bytes(
                self.hard_links
                    .values()
                    .fold(self.allocated_unlinked, |total, link| {
                        if link.occurrences >= link.links {
                            total.saturating_add(link.allocation)
                        } else {
                            total
                        }
                    }),
            )
        });
        Usage {
            logical: Bytes(self.logical),
            allocated,
            reclaimable,
        }
    }
}

struct Collector<'a> {
    options: &'a ScanOptions,
    excludes: Vec<PathBuf>,
    directories: Mutex<Vec<DirectoryUsage>>,
    candidates: Mutex<Vec<ArtifactCandidate>>,
    issues: Mutex<Vec<ScanIssue>>,
    directory_count: AtomicU64,
    files: AtomicU64,
    reparse_skipped: AtomicU64,
    errors: AtomicU64,
}

impl Collector<'_> {
    fn issue(&self, path: &Path, operation: &str, error: impl std::fmt::Display) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut issues) = self.issues.lock()
            && issues.len() < MAX_ISSUES
        {
            issues.push(ScanIssue {
                path: path.to_path_buf(),
                operation: operation.to_owned(),
                error: error.to_string(),
            });
        }
    }
}

struct Entries {
    files: Vec<(PathBuf, Metadata)>,
    directories: Vec<PathBuf>,
    file_names: HashSet<String>,
    directory_names: HashSet<String>,
}

/// Scan roots without modifying the filesystem.
#[must_use]
pub fn scan(options: &ScanOptions) -> ScanReport {
    let start = Instant::now();
    let collector = Collector {
        options,
        excludes: safety::canonical_excludes(&options.excludes),
        directories: Mutex::new(Vec::new()),
        candidates: Mutex::new(Vec::new()),
        issues: Mutex::new(Vec::new()),
        directory_count: AtomicU64::new(0),
        files: AtomicU64::new(0),
        reparse_skipped: AtomicU64::new(0),
        errors: AtomicU64::new(0),
    };
    let roots = canonical_roots(options, &collector);
    let scan_roots = || {
        roots
            .par_iter()
            .map(|root| walk(root, 0, false, None, &collector))
            .reduce(|| Subtree::empty(options.measure), Subtree::merge)
    };
    let total = options
        .threads
        .filter(|threads| *threads > 0)
        .and_then(|threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .ok()
        })
        .map_or_else(scan_roots, |pool| pool.install(scan_roots));

    let mut largest_directories = collector.directories.into_inner().unwrap_or_default();
    largest_directories.sort_unstable_by_key(|entry| Reverse(entry.usage.logical));
    largest_directories.truncate(options.top);

    let mut candidates = collector.candidates.into_inner().unwrap_or_default();
    candidates.sort_unstable_by_key(|candidate| Reverse(candidate.usage.logical));
    let mut unique = HashSet::new();
    candidates.retain(|candidate| unique.insert(safety::normalized(&candidate.path)));

    ScanReport {
        schema_version: SCHEMA_VERSION,
        roots,
        listing_limit: options.top,
        usage: total.usage(),
        stats: ScanStats {
            directories: collector.directory_count.load(Ordering::Relaxed),
            files: collector.files.load(Ordering::Relaxed),
            reparse_skipped: collector.reparse_skipped.load(Ordering::Relaxed),
            errors: collector.errors.load(Ordering::Relaxed),
            elapsed_secs: start.elapsed().as_secs_f64(),
        },
        largest_directories,
        candidates,
        issues: collector.issues.into_inner().unwrap_or_default(),
    }
}

fn canonical_roots(options: &ScanOptions, collector: &Collector<'_>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for root in &options.roots {
        let metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) => {
                collector.issue(root, "metadata", error);
                continue;
            },
        };
        if !metadata.is_dir() {
            collector.issue(root, "validate-root", "root is not a directory");
            continue;
        }
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            collector.issue(root, "validate-root", "root is a symlink or reparse point");
            continue;
        }
        let canonical = match fs::canonicalize(root) {
            Ok(canonical) => canonical,
            Err(error) => {
                collector.issue(root, "canonicalize", error);
                continue;
            },
        };
        if collector
            .excludes
            .iter()
            .any(|exclude| safety::contains(exclude, &canonical))
        {
            continue;
        }
        if roots
            .iter()
            .any(|existing| safety::contains(existing, &canonical))
        {
            continue;
        }
        roots.retain(|existing| !safety::contains(&canonical, existing));
        roots.push(canonical);
    }
    roots
}

fn walk(
    directory: &Path,
    depth: usize,
    inside_artifact: bool,
    parent_evidence: Option<(&HashSet<String>, &HashSet<String>)>,
    collector: &Collector<'_>,
) -> Subtree {
    if collector
        .excludes
        .iter()
        .any(|exclude| safety::contains(exclude, directory))
    {
        return Subtree::empty(collector.options.measure);
    }
    let Some(entries) = read_entries(directory, collector) else {
        return Subtree::empty(collector.options.measure);
    };
    collector.directory_count.fetch_add(1, Ordering::Relaxed);

    let classification = if !inside_artifact && depth > 0 {
        parent_evidence.and_then(|(parent_files, parent_dirs)| {
            let name = directory.file_name()?.to_str()?;
            let evidence = Evidence {
                parent_files: parent_files.clone(),
                parent_dirs: parent_dirs.clone(),
                child_files: entries.file_names.clone(),
                child_dirs: entries.directory_names.clone(),
                cache_tag: safety::read_cache_tag(directory, &entries.file_names),
            };
            artifact::classify(name, &evidence).map(|kind| Classification {
                kind,
                provenance: artifact::provenance(&evidence),
            })
        })
    } else {
        None
    };
    let now_inside = inside_artifact || classification.is_some();

    let mut local = measure_files(&entries.files, collector);
    let child_total = entries
        .directories
        .par_iter()
        .map(|child| {
            walk(
                child,
                depth + 1,
                now_inside,
                Some((&entries.file_names, &entries.directory_names)),
                collector,
            )
        })
        .reduce(|| Subtree::empty(collector.options.measure), Subtree::merge);
    local = local.merge(child_total);

    if let Some(classification) = classification {
        record_candidate(directory, classification, &local, collector);
    } else if !inside_artifact
        && collector
            .options
            .max_depth
            .is_none_or(|max_depth| depth <= max_depth)
        && local.logical >= collector.options.min_size.as_u64()
        && let Ok(mut directories) = collector.directories.lock()
    {
        directories.push(DirectoryUsage {
            path: directory.to_path_buf(),
            depth,
            usage: local.usage(),
        });
    }
    local
}

fn read_entries(directory: &Path, collector: &Collector<'_>) -> Option<Entries> {
    let reader = match fs::read_dir(directory) {
        Ok(reader) => reader,
        Err(error) => {
            collector.issue(directory, "read-dir", error);
            return None;
        },
    };
    let mut entries = Entries {
        files: Vec::new(),
        directories: Vec::new(),
        file_names: HashSet::new(),
        directory_names: HashSet::new(),
    };
    for entry in reader {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                collector.issue(directory, "read-entry", error);
                continue;
            },
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                collector.issue(&path, "file-type", error);
                continue;
            },
        };
        if file_type.is_symlink() {
            collector.reparse_skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                collector.issue(&path, "metadata", error);
                continue;
            },
        };
        if is_reparse_point(&metadata) {
            collector.reparse_skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if file_type.is_dir() {
            entries.directory_names.insert(name);
            entries.directories.push(path);
        } else if file_type.is_file() {
            entries.file_names.insert(name);
            entries.files.push((path, metadata));
        }
    }
    Some(entries)
}

fn measure_files(files: &[(PathBuf, Metadata)], collector: &Collector<'_>) -> Subtree {
    let mut subtree = Subtree::empty(collector.options.measure);
    collector
        .files
        .fetch_add(files.len() as u64, Ordering::Relaxed);
    for (path, metadata) in files {
        subtree.logical = subtree.logical.saturating_add(metadata.len());
        subtree.newest = subtree.newest.max(modified_nanos(metadata));
        if collector.options.measure == Measure::Both {
            match windows::file_measure(path) {
                Ok(measure) if measure.links <= 1 => {
                    subtree.allocated_unlinked = subtree
                        .allocated_unlinked
                        .saturating_add(measure.allocation);
                },
                Ok(measure) => {
                    subtree
                        .hard_links
                        .entry(measure.identity)
                        .and_modify(|link| link.occurrences = link.occurrences.saturating_add(1))
                        .or_insert(HardLink {
                            allocation: measure.allocation,
                            links: measure.links,
                            occurrences: 1,
                        });
                },
                Err(error) => {
                    subtree.allocation_available = false;
                    collector.issue(path, "allocation-info", error);
                },
            }
        }
    }
    subtree
}

fn record_candidate(
    path: &Path,
    classification: Classification,
    subtree: &Subtree,
    collector: &Collector<'_>,
) {
    let Classification { kind, provenance } = classification;
    let usage = subtree.usage();
    if usage.logical < collector.options.min_size
        || safety::is_excluded(path, &collector.excludes).is_some()
        || safety::protected_reason(path, provenance).is_some()
    {
        return;
    }
    let canonical = match fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(error) => {
            collector.issue(path, "canonicalize-candidate", error);
            return;
        },
    };
    let identity = match windows::identity(&canonical) {
        Ok(identity) => identity,
        Err(error) => {
            collector.issue(path, "candidate-file-id", error);
            return;
        },
    };
    let id = make_candidate_id(identity, &canonical, kind, usage, subtree.newest);
    if let Ok(mut candidates) = collector.candidates.lock() {
        candidates.push(ArtifactCandidate {
            id,
            path: canonical,
            kind,
            provenance,
            tier: kind.tier(),
            usage,
            newest_mtime: u64::try_from(subtree.newest / 1_000_000_000).unwrap_or(u64::MAX),
            identity,
        });
    }
}

fn modified_nanos(metadata: &Metadata) -> u128 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos())
}

/// Strict, sequential remeasurement used by cleanup validation. Any reparse
/// point or read failure rejects the candidate instead of producing a partial
/// estimate.
pub(crate) fn measure_for_cleanup(paths: &[PathBuf]) -> Result<(Usage, u128), String> {
    let mut total = Subtree::empty(Measure::Both);
    for path in paths {
        total = total.merge(measure_cleanup_tree(path)?);
    }
    Ok((total.usage(), total.newest))
}

fn measure_cleanup_tree(directory: &Path) -> Result<Subtree, String> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(format!(
            "reparse point encountered at {}",
            directory.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!("not a directory: {}", directory.display()));
    }
    let reader = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    let mut total = Subtree::empty(Measure::Both);
    for entry in reader {
        let entry = entry.map_err(|error| format!("cannot read entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(format!("reparse point encountered at {}", path.display()));
        }
        if metadata.is_dir() {
            total = total.merge(measure_cleanup_tree(&path)?);
        } else if metadata.is_file() {
            total.logical = total.logical.saturating_add(metadata.len());
            total.newest = total.newest.max(modified_nanos(&metadata));
            let measure = windows::file_measure(&path)
                .map_err(|error| format!("allocation info for {}: {error}", path.display()))?;
            if measure.links <= 1 {
                total.allocated_unlinked =
                    total.allocated_unlinked.saturating_add(measure.allocation);
            } else {
                total
                    .hard_links
                    .entry(measure.identity)
                    .and_modify(|link| link.occurrences = link.occurrences.saturating_add(1))
                    .or_insert(HardLink {
                        allocation: measure.allocation,
                        links: measure.links,
                        occurrences: 1,
                    });
            }
        }
    }
    Ok(total)
}
