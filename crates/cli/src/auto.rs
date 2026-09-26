use std::path::{Path, PathBuf};

use serde::Serialize;
use storage_scout_core::artifact::Kind;
use storage_scout_core::candidate::Candidate;
use storage_scout_core::gate::{Mandate, TierGrant};
use storage_scout_core::ownership::Admits;
use storage_scout_core::reject::Rejection;

use crate::apply::{Mode, Outcome, Status, Summary};
use crate::dedupe::{self, DedupeRun};
pub use crate::ingress::PolicyError;
use crate::prune::{self, PruneRun};
use crate::scan::{Found, ScanOptions};
use crate::{SCHEMA_VERSION, Scout, busy, ingress, scan};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selection {
    pub roots: Vec<PathBuf>,
    pub kinds: Vec<Kind>,
    pub excludes: Vec<PathBuf>,
    pub tiers: TierGrant,
}

impl Selection {
    #[must_use]
    pub fn options(&self) -> ScanOptions {
        ScanOptions::sighting(&self.roots, &self.excludes)
    }

    #[must_use]
    pub fn admits(&self, candidate: &Candidate) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&candidate.kind()))
            && self.tiers.admits(candidate.tier())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutoPolicy {
    pub selection: Selection,
    pub log_file: Option<PathBuf>,
}

impl AutoPolicy {
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        ingress::policy(text)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Reaping {
    pub selected: usize,
    pub summary: Option<Summary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoRun {
    pub schema_version: u32,
    pub command: &'static str,
    pub mode: Mode,
    pub policy: AutoPolicy,
    pub considered: usize,
    pub reap: Reaping,
    pub prune: PruneRun,
    pub dedupe: DedupeRun,
}

impl AutoRun {
    #[must_use]
    pub fn failed(&self) -> bool {
        let reaped = self
            .reap
            .summary
            .as_ref()
            .is_some_and(Summary::failed_to_delete);
        reaped || self.prune.failed() || self.dedupe.failed()
    }
}

fn sight(scout: &Scout, selection: &Selection) -> Result<Vec<Found>, Rejection> {
    let report = scout.sight(&selection.options())?;
    Ok(report
        .candidates
        .into_iter()
        .filter(|each| selection.admits(each.candidate()))
        .collect())
}

pub(crate) fn lets_go(scout: &Scout, found: &Found) -> bool {
    Admits::Settled.admits(found.candidate().settlement()) && confirmed(scout, found.path())
}

pub(crate) fn confirmed(scout: &Scout, root: &Path) -> bool {
    let Ok(survey) = busy::survey(root) else {
        return false;
    };
    matches!(busy::held(&survey.locks), busy::Holding::Free)
        && Admits::Settled.admits(scout.owners().of(root, &survey.markers).settlement())
}

pub(crate) fn reap(
    scout: &Scout,
    selection: &Selection,
    settled: &[&Found],
    mode: Mode,
) -> Option<Summary> {
    if settled.is_empty() {
        return None;
    }
    let mut measured = Vec::with_capacity(settled.len());
    let mut unmeasurable = Vec::new();
    for found in settled {
        match scan::measured(found, scout.protection()) {
            Ok(found) => measured.push(found),
            Err(rejection) => unmeasurable.push(Outcome {
                id: found.candidate().id().clone(),
                location: found.candidate().location().clone(),
                usage: None,
                status: Status::Rejected { rejection },
            }),
        }
    }
    let ids = measured
        .iter()
        .map(|found| found.candidate().id().clone())
        .collect::<Vec<_>>();
    let mandate = Mandate {
        tiers: selection.tiers,
        settlements: Admits::Settled,
    };
    let mut summary = match Scout::plan(&measured, &ids, mandate, &selection.excludes) {
        Ok(plan) => scout.apply(&plan, mode),
        Err(rejection) => Summary {
            schema_version: SCHEMA_VERSION,
            mode,
            predicted_freed: None,
            observed_freed: None,
            outcomes: measured
                .iter()
                .map(|found| Outcome {
                    id: found.candidate().id().clone(),
                    location: found.candidate().location().clone(),
                    usage: None,
                    status: Status::Rejected {
                        rejection: rejection.clone(),
                    },
                })
                .collect(),
        },
    };
    summary.outcomes.extend(unmeasurable);
    Some(summary)
}

pub(crate) fn run(scout: &Scout, policy: &AutoPolicy, mode: Mode) -> Result<AutoRun, Rejection> {
    let selection = &policy.selection;
    let sighted = sight(scout, selection)?;
    let (settled, remaining): (Vec<&Found>, Vec<&Found>) =
        sighted.iter().partition(|found| lets_go(scout, found));
    let summary = reap(scout, selection, &settled, mode);
    let remaining = remaining.into_iter().cloned().collect::<Vec<_>>();
    let excludes = scan::excludes(&selection.excludes);
    let pruned = prune::run(
        &remaining,
        &excludes,
        scout.protection(),
        scout.owners(),
        mode,
    );
    let shared = dedupe::run(&remaining, &excludes, scout.protection(), mode);
    Ok(AutoRun {
        schema_version: SCHEMA_VERSION,
        command: "auto",
        mode,
        policy: policy.clone(),
        considered: sighted.len(),
        reap: Reaping {
            selected: settled.len(),
            summary,
        },
        prune: pruned.summarized(),
        dedupe: shared.summarized(),
    })
}
