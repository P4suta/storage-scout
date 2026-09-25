use std::path::{Path, PathBuf};

use serde::Serialize;
use storage_scout_core::area::Protection;
use storage_scout_core::gate::{self, Inspection, Mandate, Outcome, Stage};
use storage_scout_core::location::Location;
use storage_scout_core::lock::Liveness;
use storage_scout_core::ownership::Ownership;
use storage_scout_core::reject::Rejection;

use crate::owners::Owners;
use crate::{SCHEMA_VERSION, busy, observe, scan};

#[derive(Debug, Clone, Serialize)]
pub struct Explanation {
    pub schema_version: u32,
    pub command: &'static str,
    pub location: Location,
    pub stages: Vec<Stage>,
    pub eligible: bool,
    pub rejection: Option<Rejection>,
    pub ownership: Option<Ownership>,
}

pub(crate) fn explain(
    path: &Path,
    excludes: &[PathBuf],
    mandate: Mandate,
    protection: &Protection,
    owners: &Owners,
) -> Result<Explanation, Rejection> {
    let observed = observe::observe(path)?;
    let excludes = scan::excludes(excludes);
    let site = observed.site(protection, &excludes);
    let unasked = gate::inspect(
        &site,
        &Inspection {
            tiers: mandate.tiers,
            settlements: mandate.settlements,
            ownership: None,
            liveness: None,
        },
    );
    let refused = unasked
        .iter()
        .any(|stage| matches!(stage.outcome, Outcome::Reject { .. }));
    let (stages, ownership) = if refused {
        (unasked, None)
    } else {
        let survey = busy::survey(&observed.path)?;
        let ownership = owners.of(&observed.path, &survey.markers);
        let liveness = match busy::probe(&survey.locks) {
            Ok(()) => Liveness::Free,
            Err(contention) => contention.liveness(),
        };
        let stages = gate::inspect(
            &site,
            &Inspection {
                tiers: mandate.tiers,
                settlements: mandate.settlements,
                ownership: Some(&ownership),
                liveness: Some(&liveness),
            },
        );
        (stages, Some(ownership))
    };
    let rejection = stages.iter().find_map(|stage| match &stage.outcome {
        Outcome::Reject { rejection } => Some(rejection.clone()),
        Outcome::Pass { .. } | Outcome::Abstain | Outcome::NotReached => None,
    });
    Ok(Explanation {
        schema_version: SCHEMA_VERSION,
        command: "explain",
        location: observed.location,
        eligible: rejection.is_none(),
        rejection,
        ownership,
        stages,
    })
}
