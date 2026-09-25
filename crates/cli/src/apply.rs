mod capability;

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::Serialize;
use storage_scout_core::area::Protection;
use storage_scout_core::candidate::{CandidateId, Usage};
use storage_scout_core::gate::{self, Mandate, Recheck, Verify};
use storage_scout_core::location::Location;
use storage_scout_core::lock::Liveness;
use storage_scout_core::reject::Rejection;
use storage_scout_core::size::Bytes;

use self::capability::Authorized;
use crate::measure::Volumes;
use crate::owners::Owners;
use crate::scan::Found;
use crate::{SCHEMA_VERSION, busy, measure, observe};

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    schema_version: u32,
    mandate: Mandate,
    candidates: Vec<Found>,
    excludes: Vec<Location>,
    usage: Option<Usage>,
}

impl Plan {
    #[must_use]
    pub fn candidates(&self) -> &[Found] {
        &self.candidates
    }

    #[must_use]
    pub const fn usage(&self) -> Option<&Usage> {
        self.usage.as_ref()
    }

    #[must_use]
    pub const fn mandate(&self) -> &Mandate {
        &self.mandate
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    DryRun,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Status {
    WouldDelete,
    Deleted,
    Rejected { rejection: Rejection },
    Failed { rejection: Rejection },
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub id: CandidateId,
    pub location: Location,
    pub usage: Option<Usage>,
    pub status: Status,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub schema_version: u32,
    pub mode: Mode,
    pub predicted_freed: Option<Bytes>,
    pub observed_freed: Option<Bytes>,
    pub outcomes: Vec<Outcome>,
}

impl Summary {
    #[must_use]
    pub fn failed_to_delete(&self) -> bool {
        self.outcomes.iter().any(|outcome| match outcome.status {
            Status::WouldDelete | Status::Deleted | Status::Rejected { .. } => false,
            Status::Failed { .. } => true,
        })
    }

    #[must_use]
    pub fn failed(&self) -> bool {
        self.outcomes.iter().any(|outcome| match outcome.status {
            Status::WouldDelete | Status::Deleted => false,
            Status::Rejected { .. } | Status::Failed { .. } => true,
        })
    }
}

pub(crate) fn plan(
    found: &[Found],
    ids: &[CandidateId],
    mandate: Mandate,
    excludes: &[PathBuf],
) -> Result<Plan, Rejection> {
    let mut seen = BTreeSet::new();
    let mut selected = Vec::with_capacity(ids.len());
    for id in ids {
        if !seen.insert(id.clone()) {
            return Err(Rejection::DuplicateCandidate { id: id.to_string() });
        }
        let Some(chosen) = found.iter().find(|each| each.candidate().id() == id) else {
            return Err(Rejection::UnknownCandidate { id: id.to_string() });
        };
        if chosen.candidate().usage().reclaimable().is_none() {
            return Err(Rejection::Unmeasured { id: id.to_string() });
        }
        selected.push(chosen.clone());
    }
    let paths = selected.iter().map(Found::path).collect::<Vec<_>>();
    let usage = match measure::selection(&paths) {
        Ok(usage) => Some(usage),
        Err(_unmeasurable) => None,
    };
    Ok(Plan {
        schema_version: SCHEMA_VERSION,
        mandate,
        candidates: selected,
        excludes: crate::scan::excludes(excludes),
        usage,
    })
}

enum Checked {
    Cleared(Usage),
    Authorized(Usage, Authorized),
}

enum Hold {
    Probed,
    Leased(busy::Lease),
}

struct Terms<'a> {
    mandate: &'a Mandate,
    excludes: &'a [Location],
    protection: &'a Protection,
    owners: &'a Owners,
}

fn check(found: &Found, terms: &Terms<'_>, mode: Mode) -> Result<Checked, Rejection> {
    let observed = observe::observe(found.path())?;
    let site = observed.site(terms.protection, terms.excludes);
    let survey = busy::survey(&observed.path)?;
    let ownership = terms.owners.of(&observed.path, &survey.markers);
    let hold = match mode {
        Mode::DryRun => busy::probe(&survey.locks).map(|()| Hold::Probed),
        Mode::Execute => busy::lease(&survey.locks).map(Hold::Leased),
    };
    let liveness = match &hold {
        Ok(_) => Liveness::Free,
        Err(contention) => contention.liveness(),
    };
    let recheck = Recheck {
        mandate: terms.mandate,
        recorded: found.candidate(),
        identity: observed.identity,
        ownership: &ownership,
        liveness: &liveness,
    };
    gate::recheck(&site, &recheck)?;
    let hold = hold.map_err(|contention| contention.rejection(observed.location.clone()))?;
    let measured = measure::strictly(&observed.path)?;
    let clearance = gate::clear(
        &site,
        &Verify {
            recheck,
            measured: &measured,
        },
    )?;
    match hold {
        Hold::Probed => Ok(Checked::Cleared(measured.usage)),
        Hold::Leased(lease) => Ok(Checked::Authorized(
            measured.usage,
            Authorized::new(clearance, lease, observed.path)?,
        )),
    }
}

fn settle(found: &Found, terms: &Terms<'_>, mode: Mode) -> Outcome {
    let (usage, status) = match check(found, terms, mode) {
        Err(rejection) => (None, Status::Rejected { rejection }),
        Ok(Checked::Cleared(usage)) => (Some(usage), Status::WouldDelete),
        Ok(Checked::Authorized(usage, authorized)) => match authorized.remove() {
            Ok(()) => (Some(usage), Status::Deleted),
            Err(rejection) => (Some(usage), Status::Failed { rejection }),
        },
    };
    Outcome {
        id: found.candidate().id().clone(),
        location: found.candidate().location().clone(),
        usage,
        status,
    }
}

pub(crate) fn apply(plan: &Plan, mode: Mode, protection: &Protection, owners: &Owners) -> Summary {
    let before = match mode {
        Mode::Execute => Some(free_space(plan)),
        Mode::DryRun => None,
    };
    let terms = Terms {
        mandate: &plan.mandate,
        excludes: &plan.excludes,
        protection,
        owners,
    };
    let outcomes = plan
        .candidates
        .iter()
        .map(|found| settle(found, &terms, mode))
        .collect();
    let observed_freed = before.and_then(|before| before.gained(&free_space(plan)));
    Summary {
        schema_version: SCHEMA_VERSION,
        mode,
        predicted_freed: plan.usage.and_then(|usage| usage.reclaimable()),
        observed_freed,
        outcomes,
    }
}

fn free_space(plan: &Plan) -> Volumes {
    Volumes::sample(plan.candidates.iter().map(|found| {
        (
            found.candidate().identity().volume,
            found.path().parent().unwrap_or_else(|| found.path()),
        )
    }))
}
