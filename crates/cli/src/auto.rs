use std::path::{Path, PathBuf};

use serde::Serialize;
use storage_scout_core::artifact::Kind;
use storage_scout_core::candidate::{Candidate, CandidateId};
use storage_scout_core::gate::{Mandate, TierGrant};
use storage_scout_core::location::Location;
use storage_scout_core::ownership::Admits;
use storage_scout_core::reject::{FsOp, Rejection};
use storage_scout_core::select::{self, Effect, Eviction, Pressed, Step, Stop, Trigger};
use storage_scout_core::size::Bytes;

use crate::apply::{Mode, Status, Summary};
use crate::dedupe::{self, DedupeRun};
pub use crate::ingress::PolicyError;
use crate::measure::Measure;
use crate::scan::{Found, ScanOptions};
use crate::{SCHEMA_VERSION, Scout, failure, ingress, platform, scan};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selection {
    pub roots: Vec<PathBuf>,
    pub kinds: Vec<Kind>,
    pub min_size: Bytes,
    pub excludes: Vec<PathBuf>,
    pub tiers: TierGrant,
}

impl Selection {
    #[must_use]
    pub fn options(&self) -> ScanOptions {
        ScanOptions {
            roots: self.roots.clone(),
            top: 0,
            min_size: self.min_size,
            max_depth: Some(0),
            excludes: self.excludes.clone(),
            threads: None,
            measure: Measure::Allocated,
        }
    }

    #[must_use]
    pub fn admits(&self, candidate: &Candidate) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&candidate.kind()))
            && self.tiers.admits(candidate.tier())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Watch {
    pub volume: PathBuf,
    pub trigger: Trigger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutoPolicy {
    pub watch: Option<Watch>,
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
pub struct EvictStep {
    pub id: CandidateId,
    pub location: Location,
    pub status: Status,
    pub free_after: Bytes,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evicting {
    pub free_before: Bytes,
    pub goal: Bytes,
    pub steps: Vec<EvictStep>,
    pub stopped: Stop,
}

#[derive(Debug, Clone, Serialize)]
pub struct Deduping {
    pub free_before: Bytes,
    pub free_after: Bytes,
    pub run: DedupeRun,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoRun {
    pub schema_version: u32,
    pub command: &'static str,
    pub mode: Mode,
    pub policy: AutoPolicy,
    pub candidates: Vec<Found>,
    pub reap: Reaping,
    pub dedupe: Option<Deduping>,
    pub evict: Option<Evicting>,
}

impl AutoRun {
    #[must_use]
    pub fn failed(&self) -> bool {
        let reaped = self
            .reap
            .summary
            .as_ref()
            .is_some_and(Summary::failed_to_delete);
        let evicted = self.evict.as_ref().is_some_and(|evict| {
            evict
                .steps
                .iter()
                .any(|step| matches!(step.status, Status::Failed { .. }))
        });
        let shared = self
            .dedupe
            .as_ref()
            .is_some_and(|dedupe| dedupe.run.failed());
        reaped || shared || evicted
    }
}

fn free_space(volume: &Path) -> Result<Bytes, Rejection> {
    platform::free_space(volume)
        .map(Bytes::new)
        .map_err(|e| failure::io(volume, FsOp::FreeSpace, &e))
}

fn step(
    scout: &Scout,
    found: &Found,
    mandate: Mandate,
    excludes: &[PathBuf],
    mode: Mode,
) -> Status {
    let plan = match Scout::plan(
        std::slice::from_ref(found),
        std::slice::from_ref(found.candidate().id()),
        mandate,
        excludes,
    ) {
        Ok(plan) => plan,
        Err(rejection) => return Status::Rejected { rejection },
    };
    match scout.apply(&plan, mode).outcomes.into_iter().next() {
        Some(outcome) => outcome.status,
        None => Status::Rejected {
            rejection: Rejection::UnknownCandidate {
                id: found.candidate().id().to_string(),
            },
        },
    }
}

struct Pressure<'a> {
    watch: &'a Watch,
    pressed: Pressed,
    free: Bytes,
}

fn evict(
    scout: &Scout,
    pressure: &Pressure<'_>,
    selection: &Selection,
    found: &[Found],
    mode: Mode,
) -> Result<Evicting, Rejection> {
    let free_before = pressure.free;
    let candidates = found
        .iter()
        .map(|each| each.candidate().clone())
        .collect::<Vec<_>>();
    let order = select::eviction_order(&candidates);
    let (mut eviction, mut next) = Eviction::resume(pressure.pressed, free_before, order);
    let mandate = Mandate {
        tiers: selection.tiers,
        settlements: Admits::Evictable,
    };
    let mut steps = Vec::new();
    let mut free = free_before;
    let stopped = loop {
        let id = match next {
            Step::Take(id) => id,
            Step::Stop(stop) => break stop,
        };
        let Some(chosen) = found.iter().find(|each| each.candidate().id() == &id) else {
            next = eviction.observe(Effect::Kept, free);
            continue;
        };
        let status = step(scout, chosen, mandate, &selection.excludes, mode);
        let effect = match status {
            Status::Deleted | Status::WouldDelete => Effect::Deleted,
            Status::Rejected { .. } | Status::Failed { .. } => Effect::Kept,
        };
        free = match (mode, &status) {
            (Mode::Execute, _) => free_space(&pressure.watch.volume)?,
            (Mode::DryRun, Status::WouldDelete) => free.saturating_add(
                chosen
                    .candidate()
                    .usage()
                    .reclaimable()
                    .unwrap_or(Bytes::ZERO),
            ),
            (Mode::DryRun, Status::Deleted | Status::Rejected { .. } | Status::Failed { .. }) => {
                free
            },
        };
        steps.push(EvictStep {
            id,
            location: chosen.candidate().location().clone(),
            status,
            free_after: free,
        });
        next = eviction.observe(effect, free);
    };
    Ok(Evicting {
        free_before,
        goal: eviction.goal(),
        steps,
        stopped,
    })
}

fn discover(scout: &Scout, selection: &Selection) -> Result<Vec<Found>, Rejection> {
    let report = scout.discover(&selection.options())?;
    Ok(report
        .candidates
        .into_iter()
        .filter(|each| selection.admits(each.candidate()))
        .collect())
}

fn relieve(
    scout: &Scout,
    watch: &Watch,
    selection: &Selection,
    remaining: &[Found],
    mode: Mode,
) -> Result<(Option<Deduping>, Evicting), Rejection> {
    let free_before = free_space(&watch.volume)?;
    let Some(pressed) = watch.trigger.pressure(free_before) else {
        return Ok((
            None,
            Evicting {
                free_before,
                goal: watch.trigger.goal(),
                steps: Vec::new(),
                stopped: Stop::NotBelowTrigger,
            },
        ));
    };
    let shared = dedupe::run(
        remaining,
        &scan::excludes(&selection.excludes),
        scout.protection(),
        mode,
    );
    let free = match mode {
        Mode::Execute => free_space(&watch.volume)?,
        Mode::DryRun => free_before.saturating_add(shared.shared()),
    };
    let found = discover(scout, selection)?;
    let deduping = Deduping {
        free_before,
        free_after: free,
        run: shared.summarized(),
    };
    let pressure = Pressure {
        watch,
        pressed,
        free,
    };
    let evicting = evict(scout, &pressure, selection, &found, mode)?;
    Ok((Some(deduping), evicting))
}

pub(crate) fn run(scout: &Scout, policy: &AutoPolicy, mode: Mode) -> Result<AutoRun, Rejection> {
    let selection = &policy.selection;
    let found = discover(scout, selection)?;
    let candidates = found
        .iter()
        .map(|each| each.candidate().clone())
        .collect::<Vec<_>>();
    let reaped = select::reap(&candidates);
    let summary = if reaped.is_empty() {
        None
    } else {
        let plan = Scout::plan(
            &found,
            &reaped,
            Mandate {
                tiers: selection.tiers,
                settlements: Admits::Settled,
            },
            &selection.excludes,
        )?;
        Some(scout.apply(&plan, mode))
    };
    let remaining = found
        .iter()
        .filter(|each| !reaped.contains(each.candidate().id()))
        .cloned()
        .collect::<Vec<_>>();
    let (deduping, evicting) = match &policy.watch {
        Some(watch) => {
            let (deduping, evicting) = relieve(scout, watch, selection, &remaining, mode)?;
            (deduping, Some(evicting))
        },
        None => (None, None),
    };
    Ok(AutoRun {
        schema_version: SCHEMA_VERSION,
        command: "auto",
        mode,
        policy: policy.clone(),
        candidates: found,
        reap: Reaping {
            selected: reaped.len(),
            summary,
        },
        dedupe: deduping,
        evict: evicting,
    })
}
