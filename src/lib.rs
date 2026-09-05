//! Windows-focused disk usage scanning and safety-first artifact cleanup.
//!
//! Cleanup is intentionally a two-phase API: [`create_cleanup_plan`] accepts
//! only candidates returned by [`scan`], and [`apply_cleanup_plan`] revalidates
//! every candidate immediately before any deletion. There is no public API that
//! deletes an arbitrary path.
//!
//! Unattended cleanup ([`evaluate_auto`]) composes the same two phases behind
//! a declarative [`AutoPolicy`]: a free-space [`Trigger`] decides *whether* to
//! act and the pure [`decide`] function chooses the smallest, stalest set of
//! candidates that restores the target.

mod age;
mod artifact;
mod auto;
mod bytes;
mod cleanup;
mod report;
mod safety;
mod scan;
mod windows;

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use age::Age;
pub use artifact::{ArtifactKind, Provenance};
pub use auto::{
    AutoEvaluation, AutoPolicy, Decision, Selection, Trigger, WithheldCandidate, decide,
    evaluate_auto,
};
pub use bytes::Bytes;
pub use cleanup::apply_cleanup_plan;
pub use report::{render_auto_human, render_clean_human, render_json, render_scan_human};
pub use scan::scan;

use windows::FileIdentity;

/// Version of every JSON document. Fields are only ever added within a
/// version; consumers should ignore unknown fields.
pub const SCHEMA_VERSION: u32 = 1;
/// Default number of largest directories to retain.
pub const DEFAULT_TOP: usize = 20;
/// Default listing threshold (10 MiB).
pub const DEFAULT_MIN_SIZE: Bytes = Bytes(10 * 1024 * 1024);
/// Default directory listing depth (root and direct children).
pub const DEFAULT_MAX_DEPTH: Option<usize> = Some(1);
/// Maximum detailed filesystem errors retained in a report.
pub const MAX_ISSUES: usize = 50;

/// How expensive an artifact is to regenerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    /// Recreated by a normal build or tool invocation.
    Routine,
    /// Requires restoring dependencies or recreating an environment.
    Reinstallable,
    /// Potentially long regeneration, such as a Unity import.
    Expensive,
}

impl RiskTier {
    /// Stable command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::Reinstallable => "reinstallable",
            Self::Expensive => "expensive",
        }
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RiskTier {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "routine" => Ok(Self::Routine),
            "reinstallable" => Ok(Self::Reinstallable),
            "expensive" => Ok(Self::Expensive),
            _ => Err(format!("unknown risk tier: {value}")),
        }
    }
}

/// Requested scan measurement detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Measure {
    /// Sum file lengths only; fastest.
    #[default]
    Logical,
    /// Also query Windows allocation, file ID, and hard-link metadata.
    Both,
}

/// Logical and physical usage estimates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Sum of file lengths.
    pub logical: Bytes,
    /// Unique allocated bytes when Windows reports them.
    pub allocated: Option<Bytes>,
    /// Allocated bytes expected to become free. Files with links outside the
    /// measured selection are excluded.
    pub reclaimable: Option<Bytes>,
}

/// Options shared by read-only scanning and artifact discovery.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Existing roots to scan.
    pub roots: Vec<PathBuf>,
    /// Number of largest directories retained in the result.
    pub top: usize,
    /// Minimum logical size for listed directories and candidates.
    pub min_size: Bytes,
    /// Maximum relative listing depth; traversal itself remains unlimited.
    pub max_depth: Option<usize>,
    /// Subtrees not to traverse.
    pub excludes: Vec<PathBuf>,
    /// Rayon worker count; `None` uses its platform default.
    pub threads: Option<usize>,
    /// Logical-only or logical plus allocation measurement.
    pub measure: Measure,
}

impl ScanOptions {
    /// Build options with library defaults.
    #[must_use]
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            ..Self::default()
        }
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            top: DEFAULT_TOP,
            min_size: DEFAULT_MIN_SIZE,
            max_depth: DEFAULT_MAX_DEPTH,
            excludes: Vec::new(),
            threads: None,
            measure: Measure::Logical,
        }
    }
}

/// An opaque, content-sensitive candidate identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidateId(String);

impl CandidateId {
    /// The lowercase hexadecimal SHA-256 digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CandidateId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err("candidate ID must be a 64-character SHA-256 hex digest".to_owned())
        }
    }
}

/// A directory authenticated as a known build artifact.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactCandidate {
    /// Content-sensitive candidate ID.
    pub id: CandidateId,
    /// Canonical artifact path.
    pub path: PathBuf,
    /// Artifact family.
    pub kind: ArtifactKind,
    /// Whether the directory declares itself a cache or was inferred from its
    /// name and a sibling manifest.
    pub provenance: Provenance,
    /// Regeneration risk.
    pub tier: RiskTier,
    /// Logical, allocated, and estimated reclaimable usage.
    pub usage: Usage,
    /// Newest descendant modification time, in Unix seconds (`0` if unknown).
    pub newest_mtime: u64,
    #[serde(skip)]
    pub(crate) identity: FileIdentity,
}

/// A largest-directory entry.
#[derive(Debug, Clone, Serialize)]
pub struct DirectoryUsage {
    /// Directory path.
    pub path: PathBuf,
    /// Relative depth from its scan root.
    pub depth: usize,
    /// Aggregated usage.
    pub usage: Usage,
}

/// A bounded filesystem error detail.
#[derive(Debug, Clone, Serialize)]
pub struct ScanIssue {
    /// Affected path.
    pub path: PathBuf,
    /// Operation that failed, such as `read-dir` or `allocation-info`.
    pub operation: String,
    /// Windows/IO error text, including its OS code when available.
    pub error: String,
}

/// Aggregate scan counters.
#[derive(Debug, Clone, Serialize)]
pub struct ScanStats {
    /// Directories opened successfully.
    pub directories: u64,
    /// Regular files observed.
    pub files: u64,
    /// Reparse points and symlinks skipped.
    pub reparse_skipped: u64,
    /// Total errors, including details omitted after [`MAX_ISSUES`].
    pub errors: u64,
    /// Wall-clock duration in seconds.
    pub elapsed_secs: f64,
}

/// Complete read-only scan result and stable JSON document.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Always [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Canonical roots actually scanned.
    pub roots: Vec<PathBuf>,
    /// Requested human listing limit.
    pub listing_limit: usize,
    /// Aggregate usage across roots.
    pub usage: Usage,
    /// Scan counters.
    pub stats: ScanStats,
    /// Largest directories, descending by logical bytes.
    pub largest_directories: Vec<DirectoryUsage>,
    /// Authenticated build-artifact candidates, descending by logical bytes.
    pub candidates: Vec<ArtifactCandidate>,
    /// Bounded detailed errors.
    pub issues: Vec<ScanIssue>,
}

/// Validate cleanup roots against the protected-area policy, then discover
/// candidates with the normal read-only scanner.
///
/// # Errors
/// Returns an explanation when a root is missing, broad, reparse-backed, or in
/// a protected Windows area.
pub fn discover_cleanup_candidates(options: &ScanOptions) -> Result<ScanReport, String> {
    let mut validated = options.clone();
    validated.roots = options
        .roots
        .iter()
        .map(|root| safety::validate_clean_root(root))
        .collect::<Result<Vec<_>, _>>()?;
    if validated.roots.is_empty() {
        return Err("at least one cleanup root is required".to_owned());
    }
    Ok(scan(&validated))
}

/// A plan built exclusively from discovered candidates.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupPlan {
    /// Always [`SCHEMA_VERSION`].
    pub schema_version: u32,
    #[serde(rename = "candidates")]
    selected: Vec<ArtifactCandidate>,
    excludes: Vec<PathBuf>,
    /// Selection-wide usage. Allocation/reclaim estimates deduplicate hard
    /// links across candidate boundaries.
    pub usage: Usage,
}

impl CleanupPlan {
    /// Selected candidates in deletion order.
    #[must_use]
    pub fn candidates(&self) -> &[ArtifactCandidate] {
        &self.selected
    }

    /// Exclusions that will be rechecked during apply.
    #[must_use]
    pub fn excludes(&self) -> &[PathBuf] {
        &self.excludes
    }
}

/// Create a cleanup plan from explicit candidate IDs.
///
/// This function never accepts paths. Unknown, duplicate, or stale IDs are
/// rejected rather than silently ignored.
///
/// # Errors
/// Returns an explanation for unknown/duplicate IDs or unavailable allocation
/// information.
pub fn create_cleanup_plan(
    candidates: &[ArtifactCandidate],
    ids: &[CandidateId],
    excludes: Vec<PathBuf>,
) -> Result<CleanupPlan, String> {
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut selected = Vec::with_capacity(ids.len());
    for id in ids {
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate candidate ID: {id}"));
        }
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.id == *id)
            .ok_or_else(|| format!("unknown or stale candidate ID: {id}"))?;
        if candidate.usage.allocated.is_none() || candidate.usage.reclaimable.is_none() {
            return Err(format!(
                "candidate {id} has no allocation estimate; discover cleanup candidates with Measure::Both"
            ));
        }
        selected.push(candidate.clone());
    }
    let usage = cleanup::measure_selection(&selected)?;
    Ok(CleanupPlan {
        schema_version: SCHEMA_VERSION,
        selected,
        excludes,
        usage,
    })
}

/// Options for applying a verified cleanup plan.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApplyOptions {
    /// `false` performs a fully validated dry-run; `true` deletes.
    pub execute: bool,
}

/// Disposition of one planned candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum CleanupStatus {
    /// Revalidated and retained during a dry-run.
    DryRun,
    /// Successfully removed.
    Deleted,
    /// Refused because state or safety evidence changed.
    Rejected(String),
    /// Deletion was attempted but failed.
    Failed(String),
}

/// Outcome for one candidate.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupOutcome {
    /// Candidate ID from the plan.
    pub id: CandidateId,
    /// Candidate path from the plan.
    pub path: PathBuf,
    /// Revalidated candidate usage, or zero/unknown when validation failed.
    pub usage: Usage,
    /// What happened.
    pub status: CleanupStatus,
}

/// Aggregate result of applying a plan.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupSummary {
    /// Always [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Whether deletion was enabled.
    pub executed: bool,
    /// Plan's allocation-aware prediction.
    pub predicted_freed: Option<Bytes>,
    /// Increase in volume free space observed after deletion.
    pub observed_freed: Option<Bytes>,
    /// Per-candidate outcomes.
    pub outcomes: Vec<CleanupOutcome>,
}

impl CleanupSummary {
    /// Whether any candidate was rejected or failed.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.outcomes.iter().any(|outcome| {
            matches!(
                outcome.status,
                CleanupStatus::Rejected(_) | CleanupStatus::Failed(_)
            )
        })
    }
}

pub(crate) fn make_candidate_id(
    identity: FileIdentity,
    path: &std::path::Path,
    kind: ArtifactKind,
    usage: Usage,
    newest_mtime_ns: u128,
) -> CandidateId {
    let mut hash = Sha256::new();
    for field in [
        identity.volume.to_string(),
        identity.file.to_string(),
        safety::normalized(path),
        kind.as_str().to_owned(),
        usage.logical.as_u64().to_string(),
        usage.allocated.map_or_else(
            || "unavailable".to_owned(),
            |value| value.as_u64().to_string(),
        ),
        newest_mtime_ns.to_string(),
    ] {
        hash.update(field.as_bytes());
        hash.update([0]);
    }
    CandidateId(format!("{:x}", hash.finalize()))
}
