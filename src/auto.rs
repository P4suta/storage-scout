//! Threshold-driven, unattended cleanup.
//!
//! An [`AutoPolicy`] is data: a [`Trigger`] naming the watched volume and its
//! free-space thresholds, and a [`Selection`] naming what may be considered.
//! [`decide`] is a pure function from the trigger, the observed free space,
//! and the eligible candidates to a [`Decision`]; [`evaluate_auto`] is the
//! thin shell that feeds it live measurements and turns a reclaim decision
//! into an ordinary [`CleanupPlan`]. Nothing here deletes: the caller still
//! applies the plan through [`apply_cleanup_plan`](crate::apply_cleanup_plan),
//! which revalidates every candidate.

use std::cmp::Reverse;
use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scan::measure_for_cleanup;
use crate::{
    Age, ArtifactCandidate, ArtifactKind, Bytes, CandidateId, CleanupPlan, DEFAULT_MIN_SIZE,
    Measure, RiskTier, ScanOptions, create_cleanup_plan, discover_cleanup_candidates, safety,
    windows,
};

/// When to act, expressed as free space on one volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Trigger {
    /// A path on the watched volume, typically its root such as `C:\`.
    pub volume: PathBuf,
    /// Act only while free space is below this.
    pub min_free: Bytes,
    /// Stop selecting once projected free space reaches this. `None` selects
    /// every eligible candidate.
    pub target_free: Option<Bytes>,
}

/// Which discovered candidates may be considered. Shared by `clean` filters
/// and `auto` policies so both spell the same rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selection {
    /// Explicit roots under which artifacts may be discovered.
    pub roots: Vec<PathBuf>,
    /// Artifact families to keep; empty keeps every family.
    pub kinds: Vec<ArtifactKind>,
    /// Minimum candidate logical size.
    pub min_size: Bytes,
    /// Keep only candidates whose newest file is at least this old.
    pub older_than: Option<Age>,
    /// Protected subtrees, rechecked during apply.
    pub excludes: Vec<PathBuf>,
    /// Non-routine tiers explicitly unlocked.
    pub include_tiers: Vec<RiskTier>,
}

impl Selection {
    /// A selection over `roots` with library defaults.
    #[must_use]
    pub const fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            kinds: Vec::new(),
            min_size: DEFAULT_MIN_SIZE,
            older_than: None,
            excludes: Vec::new(),
            include_tiers: Vec::new(),
        }
    }

    /// Discovery options equivalent to this selection.
    #[must_use]
    pub fn scan_options(&self) -> ScanOptions {
        ScanOptions {
            roots: self.roots.clone(),
            top: 0,
            min_size: self.min_size,
            max_depth: Some(0),
            excludes: self.excludes.clone(),
            threads: None,
            measure: Measure::Both,
        }
    }

    /// Tiers that may be selected: routine plus anything explicitly included.
    #[must_use]
    pub fn unlocked_tiers(&self) -> HashSet<RiskTier> {
        std::iter::once(RiskTier::Routine)
            .chain(self.include_tiers.iter().copied())
            .collect()
    }

    /// Whether the kind and age rules admit a candidate, given the current
    /// Unix time. Tier locking is deliberately separate so interactive callers
    /// can still show locked candidates.
    #[must_use]
    pub fn admits(&self, now_secs: u64, candidate: &ArtifactCandidate) -> bool {
        let kind_ok = self.kinds.is_empty() || self.kinds.contains(&candidate.kind);
        let age_ok = self.older_than.is_none_or(|age| {
            candidate.newest_mtime != 0
                && candidate.newest_mtime <= now_secs.saturating_sub(age.as_secs())
        });
        kind_ok && age_ok
    }
}

/// A complete unattended-cleanup policy, normally loaded from TOML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutoPolicy {
    /// When to act.
    pub trigger: Trigger,
    /// What may be considered.
    pub selection: Selection,
    /// Where to append one JSON line per run, if anywhere.
    pub log_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    trigger: TriggerFile,
    select: SelectFile,
    #[serde(default)]
    report: ReportFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TriggerFile {
    volume: PathBuf,
    min_free: String,
    target_free: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectFile {
    roots: Vec<PathBuf>,
    #[serde(default)]
    kinds: Vec<ArtifactKind>,
    min_size: Option<String>,
    older_than: Option<String>,
    #[serde(default)]
    exclude: Vec<PathBuf>,
    #[serde(default)]
    include_tier: Vec<RiskTier>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ReportFile {
    log_file: Option<PathBuf>,
}

impl AutoPolicy {
    /// Parse and validate a TOML policy document.
    ///
    /// # Errors
    /// Returns an explanation for syntax errors, unknown keys, unparsable
    /// sizes/ages, an empty root list, or a target below the trigger.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: PolicyFile = toml::from_str(text).map_err(|error| error.to_string())?;
        let min_free = file
            .trigger
            .min_free
            .parse::<Bytes>()
            .map_err(|error| format!("trigger.min_free: {error}"))?;
        let target_free = file
            .trigger
            .target_free
            .as_deref()
            .map(|value| {
                value
                    .parse::<Bytes>()
                    .map_err(|error| format!("trigger.target_free: {error}"))
            })
            .transpose()?;
        if target_free.is_some_and(|target| target <= min_free) {
            return Err("trigger.target_free must be greater than trigger.min_free".to_owned());
        }
        if file.trigger.volume.as_os_str().is_empty() {
            return Err("trigger.volume must name a path on the watched volume".to_owned());
        }
        if file.select.roots.is_empty() {
            return Err("select.roots must list at least one root".to_owned());
        }
        let min_size = file
            .select
            .min_size
            .as_deref()
            .map(|value| {
                value
                    .parse::<Bytes>()
                    .map_err(|error| format!("select.min_size: {error}"))
            })
            .transpose()?
            .unwrap_or(DEFAULT_MIN_SIZE);
        let older_than = file
            .select
            .older_than
            .as_deref()
            .map(|value| {
                value
                    .parse::<Age>()
                    .map_err(|error| format!("select.older_than: {error}"))
            })
            .transpose()?;
        Ok(Self {
            trigger: Trigger {
                volume: file.trigger.volume,
                min_free,
                target_free,
            },
            selection: Selection {
                roots: file.select.roots,
                kinds: file.select.kinds,
                min_size,
                older_than,
                excludes: file.select.exclude,
                include_tiers: file.select.include_tier,
            },
            log_file: file.report.log_file,
        })
    }
}

/// What a trigger says to do given the observed free space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "decision")]
pub enum Decision {
    /// Free space is at or above the trigger; nothing was scanned.
    Idle {
        /// Observed free space.
        free: Bytes,
    },
    /// Below the trigger, but no eligible candidate could help.
    NoCandidates {
        /// Observed free space.
        free: Bytes,
        /// Bytes needed to reach the target.
        deficit: Bytes,
    },
    /// Below the trigger; reclaim these candidates, stalest first.
    Reclaim {
        /// Observed free space.
        free: Bytes,
        /// Bytes needed to reach the target.
        deficit: Bytes,
        /// Selected candidate IDs in deletion order.
        selected: Vec<CandidateId>,
        /// Free space expected once the selection is reclaimed.
        projected_free: Bytes,
    },
}

/// Choose the smallest stalest-first prefix of `candidates` whose reclaimable
/// bytes lift `free` to the trigger's target. Pure: no filesystem access.
///
/// Candidates without a positive reclaimable estimate are never selected.
/// Ordering is by newest modification time ascending, then reclaimable bytes
/// descending, so the oldest and largest go first.
#[must_use]
pub fn decide(trigger: &Trigger, free: Bytes, candidates: &[ArtifactCandidate]) -> Decision {
    if free >= trigger.min_free {
        return Decision::Idle { free };
    }
    let goal = trigger.target_free.unwrap_or(Bytes::MAX);
    let deficit = goal.saturating_sub(free);
    let mut eligible = candidates
        .iter()
        .filter_map(|candidate| {
            candidate
                .usage
                .reclaimable
                .filter(|reclaimable| reclaimable.as_u64() > 0)
                .map(|reclaimable| (candidate, reclaimable))
        })
        .collect::<Vec<_>>();
    eligible
        .sort_by_key(|(candidate, reclaimable)| (candidate.newest_mtime, Reverse(*reclaimable)));

    let mut selected = Vec::new();
    let mut projected_free = free;
    for (candidate, reclaimable) in eligible {
        if projected_free >= goal {
            break;
        }
        selected.push(candidate.id.clone());
        projected_free = projected_free.saturating_add(reclaimable);
    }
    if selected.is_empty() {
        Decision::NoCandidates { free, deficit }
    } else {
        Decision::Reclaim {
            free,
            deficit,
            selected,
            projected_free,
        }
    }
}

/// An admitted candidate set aside before planning: a running tool owns it,
/// or it can no longer be measured strictly (for example a reparse point
/// appeared inside it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WithheldCandidate {
    /// Candidate ID.
    pub id: CandidateId,
    /// Candidate path.
    pub path: PathBuf,
    /// Why it was skipped.
    pub reason: String,
}

/// The outcome of evaluating a policy against the live system. No deletion
/// has happened yet.
#[derive(Debug, Clone, Serialize)]
pub struct AutoEvaluation {
    /// What the trigger decided.
    pub decision: Decision,
    /// Candidates admitted by the selection, in discovery order. Empty when
    /// the decision is [`Decision::Idle`] because nothing was scanned.
    pub candidates: Vec<ArtifactCandidate>,
    /// Admitted candidates set aside with the reason; never planned.
    pub withheld: Vec<WithheldCandidate>,
    /// The plan for a [`Decision::Reclaim`], built only from discovered IDs.
    pub plan: Option<CleanupPlan>,
}

/// Measure the trigger volume and, when below the trigger, discover and
/// select candidates and build a cleanup plan.
///
/// `now_secs` is the current Unix time used for age rules.
///
/// # Errors
/// Returns an explanation when the volume cannot be measured, a root is
/// invalid, or the plan cannot be built.
pub fn evaluate_auto(policy: &AutoPolicy, now_secs: u64) -> Result<AutoEvaluation, String> {
    let free = Bytes(
        windows::free_space(&policy.trigger.volume).map_err(|error| {
            format!(
                "cannot measure free space on {}: {error}",
                policy.trigger.volume.display()
            )
        })?,
    );
    if free >= policy.trigger.min_free {
        return Ok(AutoEvaluation {
            decision: Decision::Idle { free },
            candidates: Vec::new(),
            withheld: Vec::new(),
            plan: None,
        });
    }

    let selection = &policy.selection;
    let unlocked = selection.unlocked_tiers();
    let report = discover_cleanup_candidates(&selection.scan_options())?;
    let candidates = report
        .candidates
        .into_iter()
        .filter(|candidate| {
            unlocked.contains(&candidate.tier) && selection.admits(now_secs, candidate)
        })
        .collect::<Vec<_>>();

    let mut withheld = Vec::new();
    let mut eligible = Vec::new();
    for candidate in &candidates {
        match withhold_reason(candidate) {
            Some(reason) => withheld.push(WithheldCandidate {
                id: candidate.id.clone(),
                path: candidate.path.clone(),
                reason,
            }),
            None => eligible.push(candidate.clone()),
        }
    }

    let decision = decide(&policy.trigger, free, &eligible);
    let plan = match &decision {
        Decision::Reclaim { selected, .. } => Some(create_cleanup_plan(
            &eligible,
            selected,
            selection.excludes.clone(),
        )?),
        Decision::Idle { .. } | Decision::NoCandidates { .. } => None,
    };
    Ok(AutoEvaluation {
        decision,
        candidates,
        withheld,
        plan,
    })
}

/// Why an admitted candidate must not be planned right now. Planning and
/// apply would reject it anyway; withholding keeps one bad candidate from
/// aborting the whole run.
fn withhold_reason(candidate: &ArtifactCandidate) -> Option<String> {
    if let Some(reason) = safety::busy_reason(&candidate.path, candidate.kind) {
        return Some(format!("in use: {reason}"));
    }
    measure_for_cleanup(std::slice::from_ref(&candidate.path))
        .err()
        .map(|reason| format!("cannot be measured strictly: {reason}"))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{Provenance, Usage, windows::FileIdentity};

    fn candidate(seed: u8, newest_mtime: u64, reclaimable: Option<u64>) -> ArtifactCandidate {
        ArtifactCandidate {
            id: CandidateId::from_str(&format!("{seed:02x}").repeat(32)).unwrap(),
            path: PathBuf::from(format!("C:\\work\\{seed}\\target")),
            kind: ArtifactKind::RustTarget,
            provenance: Provenance::Inferred,
            tier: RiskTier::Routine,
            usage: Usage {
                logical: Bytes(reclaimable.unwrap_or(0)),
                allocated: reclaimable.map(Bytes),
                reclaimable: reclaimable.map(Bytes),
            },
            newest_mtime,
            identity: FileIdentity {
                volume: 1,
                file: u64::from(seed),
            },
        }
    }

    fn ids(candidates: &[ArtifactCandidate]) -> Vec<CandidateId> {
        candidates.iter().map(|c| c.id.clone()).collect()
    }

    const TRIGGER: Trigger = Trigger {
        volume: PathBuf::new(),
        min_free: Bytes(100),
        target_free: Some(Bytes(150)),
    };

    #[test]
    fn idle_at_or_above_the_trigger() {
        let candidates = [candidate(1, 10, Some(500))];
        assert_eq!(
            decide(&TRIGGER, Bytes(100), &candidates),
            Decision::Idle { free: Bytes(100) }
        );
        assert_eq!(
            decide(&TRIGGER, Bytes(999), &candidates),
            Decision::Idle { free: Bytes(999) }
        );
    }

    #[test]
    fn reclaims_stalest_first_and_stops_at_the_target() {
        let newest = candidate(1, 300, Some(1000));
        let oldest = candidate(2, 100, Some(30));
        let middle = candidate(3, 200, Some(40));
        let candidates = [newest, oldest.clone(), middle.clone()];
        assert_eq!(
            decide(&TRIGGER, Bytes(90), &candidates),
            Decision::Reclaim {
                free: Bytes(90),
                deficit: Bytes(60),
                selected: ids(&[oldest, middle]),
                projected_free: Bytes(160),
            }
        );
    }

    #[test]
    fn same_age_prefers_the_largest_reclaim() {
        let trigger = Trigger {
            target_free: Some(Bytes(140)),
            ..TRIGGER
        };
        let small = candidate(1, 100, Some(5));
        let large = candidate(2, 100, Some(50));
        assert_eq!(
            decide(&trigger, Bytes(99), &[small, large.clone()]),
            Decision::Reclaim {
                free: Bytes(99),
                deficit: Bytes(41),
                selected: ids(&[large]),
                projected_free: Bytes(149),
            }
        );
    }

    #[test]
    fn without_a_target_everything_eligible_is_selected() {
        let trigger = Trigger {
            target_free: None,
            ..TRIGGER
        };
        let a = candidate(1, 200, Some(10));
        let b = candidate(2, 100, Some(10));
        let unknown = candidate(3, 50, None);
        let empty = candidate(4, 60, Some(0));
        assert_eq!(
            decide(&trigger, Bytes(0), &[a.clone(), b.clone(), unknown, empty]),
            Decision::Reclaim {
                free: Bytes(0),
                deficit: Bytes::MAX,
                selected: ids(&[b, a]),
                projected_free: Bytes(20),
            }
        );
    }

    #[test]
    fn nothing_reclaimable_is_reported_not_silently_idle() {
        assert_eq!(
            decide(
                &TRIGGER,
                Bytes(10),
                &[candidate(1, 1, None), candidate(2, 1, Some(0))]
            ),
            Decision::NoCandidates {
                free: Bytes(10),
                deficit: Bytes(140),
            }
        );
        assert_eq!(
            decide(&TRIGGER, Bytes(10), &[]),
            Decision::NoCandidates {
                free: Bytes(10),
                deficit: Bytes(140),
            }
        );
    }

    #[test]
    fn selection_admits_by_kind_and_age_only() {
        let mut selection = Selection::new(vec![PathBuf::from("C:\\work")]);
        let fresh = candidate(1, 1_000, Some(1));
        let stale = candidate(2, 100, Some(1));
        assert!(selection.admits(1_000, &fresh));

        selection.older_than = Some(Age(500));
        assert!(!selection.admits(1_000, &fresh));
        assert!(selection.admits(1_000, &stale));
        let unknown_mtime = candidate(3, 0, Some(1));
        assert!(!selection.admits(1_000, &unknown_mtime));

        selection.kinds = vec![ArtifactKind::NodeModules];
        assert!(!selection.admits(1_000, &stale));
        selection.kinds = vec![ArtifactKind::NodeModules, ArtifactKind::RustTarget];
        assert!(selection.admits(1_000, &stale));

        assert_eq!(
            selection.unlocked_tiers(),
            HashSet::from([RiskTier::Routine])
        );
        selection.include_tiers = vec![RiskTier::Expensive];
        assert_eq!(
            selection.unlocked_tiers(),
            HashSet::from([RiskTier::Routine, RiskTier::Expensive])
        );
    }

    #[test]
    fn parses_a_complete_policy() {
        let policy = AutoPolicy::parse(
            r#"
            [trigger]
            volume = 'C:\'
            min_free = "40GiB"
            target_free = "80GiB"

            [select]
            roots = ['C:\work', 'C:\Users\me\AppData\Local\Temp']
            kinds = ["rust-target", "tagged-cache"]
            min_size = "100MiB"
            older_than = "3d"
            exclude = ['C:\work\keep']
            include_tier = ["reinstallable"]

            [report]
            log_file = 'C:\logs\auto.jsonl'
            "#,
        )
        .unwrap();
        assert_eq!(
            policy.trigger,
            Trigger {
                volume: PathBuf::from("C:\\"),
                min_free: Bytes(40 * 1024 * 1024 * 1024),
                target_free: Some(Bytes(80 * 1024 * 1024 * 1024)),
            }
        );
        assert_eq!(
            policy.selection,
            Selection {
                roots: vec![
                    PathBuf::from("C:\\work"),
                    PathBuf::from("C:\\Users\\me\\AppData\\Local\\Temp")
                ],
                kinds: vec![ArtifactKind::RustTarget, ArtifactKind::TaggedCache],
                min_size: Bytes(100 * 1024 * 1024),
                older_than: Some(Age(3 * 24 * 60 * 60)),
                excludes: vec![PathBuf::from("C:\\work\\keep")],
                include_tiers: vec![RiskTier::Reinstallable],
            }
        );
        assert_eq!(policy.log_file, Some(PathBuf::from("C:\\logs\\auto.jsonl")));
    }

    #[test]
    fn minimal_policy_takes_defaults() {
        let policy = AutoPolicy::parse(
            "[trigger]\nvolume = 'D:\\'\nmin_free = '1GiB'\n[select]\nroots = ['D:\\src']\n",
        )
        .unwrap();
        assert_eq!(policy.trigger.target_free, None);
        assert_eq!(policy.selection.min_size, DEFAULT_MIN_SIZE);
        assert_eq!(policy.selection.older_than, None);
        assert!(policy.selection.kinds.is_empty());
        assert_eq!(policy.log_file, None);
    }

    #[test]
    fn rejects_invalid_policies() {
        let base = "[trigger]\nvolume = 'C:\\'\nmin_free = '10GiB'\n";
        let err = |text: &str| AutoPolicy::parse(text).unwrap_err();
        assert!(
            err(&format!(
                "{base}target_free = '5GiB'\n[select]\nroots = ['C:\\a']\n"
            ))
            .contains("target_free")
        );
        assert!(err(&format!("{base}[select]\nroots = []\n")).contains("roots"));
        assert!(
            err(&format!(
                "{base}[select]\nroots = ['C:\\a']\nolder_than = '3'\n"
            ))
            .contains("older_than")
        );
        assert!(
            err(&format!(
                "{base}[select]\nroots = ['C:\\a']\nmin_size = 'lots'\n"
            ))
            .contains("min_size")
        );
        assert!(
            err(&format!(
                "{base}[select]\nroots = ['C:\\a']\nkinds = ['nope']\n"
            ))
            .contains("nope")
        );
        assert!(
            err(&format!(
                "{base}[select]\nroots = ['C:\\a']\nsurprise = 1\n"
            ))
            .contains("surprise")
        );
        assert!(
            err("[trigger]\nvolume = ''\nmin_free = '1G'\n[select]\nroots = ['C:\\a']\n")
                .contains("volume")
        );
        assert!(err("not toml at all [").contains("expected"));
    }
}
