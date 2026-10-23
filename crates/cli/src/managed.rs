mod toolchains;
pub(crate) use toolchains::ToolchainRemoval;

use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Serialize;
use sha2::{Digest, Sha256};
use storage_scout_core::candidate::CandidateId;
use storage_scout_core::gate::TierGrant;
use storage_scout_core::managed::{
    self, Clearance, Completeness, References, Refusal, Request, Resource,
};
use storage_scout_core::size::{Bytes, Reclamation};

use crate::{Mode, SCHEMA_VERSION, ingress, platform};

pub(crate) const PRUNE_IMAGES: &str = "Prune all currently unused, untagged images";
pub(crate) const PRUNE_BUILD_CACHE: &str = "Prune all currently unused build cache";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    Docker,
    Rustup,
    Mise,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedUsage {
    pub resource: Resource,
    pub name: String,
    pub bytes: Option<Bytes>,
    pub references: References,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    DanglingImages,
    UnusedBuildCache,
    Toolchain {
        tool: String,
        version: String,
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedCandidate {
    pub id: CandidateId,
    pub resource: Resource,
    pub label: String,
    pub references: References,
    pub refusal: Option<Refusal>,
    #[serde(skip)]
    pub(crate) action: Action,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ManagedStatus {
    WouldRemove,
    Removed { manager_reclaimed: Option<Bytes> },
    Refused { reason: Refusal },
    Failed { error: String },
}

#[derive(Debug, Serialize)]
pub struct ManagedOutcome {
    pub id: CandidateId,
    pub result: ManagedStatus,
    pub observed_freed: Option<Bytes>,
}

#[derive(Debug, Serialize)]
pub struct ManagedReport {
    pub schema_version: u32,
    pub provider: Provider,
    pub scope: String,
    pub inventory: Vec<ManagedUsage>,
    pub candidates: Vec<ManagedCandidate>,
    pub outcomes: Vec<ManagedOutcome>,
    pub warnings: Vec<String>,
}

pub(crate) struct Survey {
    pub scope: String,
    pub completeness: Completeness,
    pub inventory: Vec<ManagedUsage>,
    pub candidates: Vec<ManagedCandidate>,
    pub warnings: Vec<String>,
}

pub(crate) trait Port {
    fn survey(&mut self, roots: &[PathBuf]) -> io::Result<Survey>;
    fn remove(&mut self, action: &Action, clearance: &Clearance) -> io::Result<Option<Bytes>>;
}

pub(crate) fn candidate(
    scope: &str,
    resource: Resource,
    label: String,
    references: References,
    action: Action,
) -> io::Result<ManagedCandidate> {
    let mut hash = Sha256::new();
    hash.update(b"storage-scout-managed-v1\0");
    hash.update(scope);
    hash.update([0]);
    hash.update(&label);
    hash.update([0]);
    hash.update(serde_json::to_vec(&resource).map_err(io::Error::other)?);
    Ok(ManagedCandidate {
        id: CandidateId::from_str(&hex::encode(hash.finalize())).map_err(io::Error::other)?,
        resource,
        label,
        references,
        refusal: None,
        action,
    })
}

fn clearance(
    recorded: &ManagedCandidate,
    current: &ManagedCandidate,
    completeness: Completeness,
    tiers: TierGrant,
) -> Result<Clearance, Refusal> {
    if recorded.action != current.action || recorded.resource != current.resource {
        return Err(Refusal::Stale);
    }
    managed::clear(&Request {
        resource: current.resource,
        references: current.references,
        completeness,
        recorded: &recorded.id,
        current: &current.id,
        tiers,
    })
}

struct Operation<'a> {
    provider: Provider,
    roots: &'a [PathBuf],
    tiers: TierGrant,
    ids: &'a [CandidateId],
    mode: Mode,
}

fn run(port: &mut impl Port, operation: &Operation<'_>) -> io::Result<ManagedReport> {
    let Operation {
        provider,
        roots,
        tiers,
        ids,
        mode,
    } = *operation;
    let mut survey = port.survey(roots)?;
    for candidate in &mut survey.candidates {
        candidate.refusal = clearance(candidate, candidate, survey.completeness, tiers).err();
    }
    let mut outcomes = Vec::new();
    let mut reviewed = std::collections::BTreeSet::new();
    for id in ids {
        if !reviewed.insert(id) {
            continue;
        }
        let result = match survey.candidates.iter().find(|item| item.id == *id) {
            Some(recorded) => apply(port, roots, recorded, tiers, mode),
            None => ManagedStatus::Refused {
                reason: Refusal::Stale,
            },
        };
        let observed_freed = match &result {
            ManagedStatus::WouldRemove => None,
            ManagedStatus::Refused { .. } => Reclamation::Unchanged.observed(),
            ManagedStatus::Removed { .. } | ManagedStatus::Failed { .. } => {
                Reclamation::Unattributable.observed()
            },
        };
        outcomes.push(ManagedOutcome {
            id: id.clone(),
            result,
            observed_freed,
        });
    }
    Ok(ManagedReport {
        schema_version: SCHEMA_VERSION,
        provider,
        scope: survey.scope,
        inventory: survey.inventory,
        candidates: survey.candidates,
        outcomes,
        warnings: survey.warnings,
    })
}

fn apply(
    port: &mut impl Port,
    roots: &[PathBuf],
    recorded: &ManagedCandidate,
    tiers: TierGrant,
    mode: Mode,
) -> ManagedStatus {
    let fresh = match port.survey(roots) {
        Ok(survey) => survey,
        Err(error) => {
            return ManagedStatus::Failed {
                error: error.to_string(),
            };
        },
    };
    let Some(current) = fresh.candidates.iter().find(|item| item.id == recorded.id) else {
        return ManagedStatus::Refused {
            reason: Refusal::Stale,
        };
    };
    let permit = match clearance(recorded, current, fresh.completeness, tiers) {
        Ok(permit) => permit,
        Err(reason) => return ManagedStatus::Refused { reason },
    };
    match mode {
        Mode::DryRun => ManagedStatus::WouldRemove,
        Mode::Execute => match port.remove(&current.action, &permit) {
            Ok(manager_reclaimed) => ManagedStatus::Removed { manager_reclaimed },
            Err(error) => ManagedStatus::Failed {
                error: error.to_string(),
            },
        },
    }
}

struct Engine {
    client: platform::engine::Engine,
}

impl Port for Engine {
    fn survey(&mut self, _roots: &[PathBuf]) -> io::Result<Survey> {
        let (scope, data) = self.client.usage()?;
        let inventory = ingress::engine_usage(data)?;
        let mut candidates = Vec::new();
        for (resource, label, action) in [
            (Resource::Image, PRUNE_IMAGES, Action::DanglingImages),
            (
                Resource::BuildCache,
                PRUNE_BUILD_CACHE,
                Action::UnusedBuildCache,
            ),
        ] {
            if !inventory.iter().any(|item| item.resource == resource) {
                continue;
            }
            let references = if inventory
                .iter()
                .any(|item| item.resource == resource && item.references == References::Unused)
            {
                References::Unused
            } else {
                References::Referenced
            };
            candidates.push(candidate(
                &scope,
                resource,
                label.to_owned(),
                references,
                action,
            )?);
        }
        Ok(Survey {
            scope,
            completeness: Completeness::Complete,
            inventory,
            candidates,
            warnings: Vec::new(),
        })
    }

    fn remove(&mut self, action: &Action, clearance: &Clearance) -> io::Result<Option<Bytes>> {
        let resource = match action {
            Action::DanglingImages => Resource::Image,
            Action::UnusedBuildCache => Resource::BuildCache,
            Action::Toolchain { .. } => return Err(io::Error::other("wrong managed provider")),
        };
        self.client.prune(resource, clearance)
    }
}

pub fn managed_store(
    provider: Provider,
    roots: &[PathBuf],
    tiers: TierGrant,
    ids: &[CandidateId],
    mode: Mode,
) -> io::Result<ManagedReport> {
    let operation = Operation {
        provider,
        roots,
        tiers,
        ids,
        mode,
    };
    match provider {
        Provider::Docker => run(
            &mut Engine {
                client: platform::engine::Engine::connect()?,
            },
            &operation,
        ),
        Provider::Rustup | Provider::Mise => {
            run(&mut toolchains::Manager::new(provider)?, &operation)
        },
    }
}

pub(crate) fn absolute(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute()
        || platform::shape(&std::fs::symlink_metadata(path)?)
            != storage_scout_core::gate::Shape::Directory
    {
        return Err(io::Error::other(
            "managed stores require an absolute, non-symbolic path",
        ));
    }
    path.canonicalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use storage_scout_core::artifact::Tier;

    struct Fake {
        surveys: VecDeque<Survey>,
        removed: Vec<Action>,
    }

    impl Port for Fake {
        fn survey(&mut self, _roots: &[PathBuf]) -> io::Result<Survey> {
            self.surveys
                .pop_front()
                .ok_or_else(|| io::Error::other("unexpected rediscovery"))
        }
        fn remove(&mut self, action: &Action, permit: &Clearance) -> io::Result<Option<Bytes>> {
            if permit.resource() != Resource::Toolchain {
                return Err(io::Error::other("wrong fake capability"));
            }
            self.removed.push(action.clone());
            Ok(None)
        }
    }

    fn survey(scope: &str, references: References, completeness: Completeness) -> Survey {
        Survey {
            scope: scope.to_owned(),
            completeness,
            inventory: Vec::new(),
            warnings: Vec::new(),
            candidates: vec![
                candidate(
                    scope,
                    Resource::Toolchain,
                    "rust@1.98.0".to_owned(),
                    references,
                    Action::Toolchain {
                        tool: "rust".to_owned(),
                        version: "1.98.0".to_owned(),
                        path: PathBuf::from("/tools/rust/1.98.0"),
                    },
                )
                .unwrap(),
            ],
        }
    }

    fn execute(fresh: Survey, mode: Mode) -> (Fake, ManagedReport) {
        let initial = survey("manager-a", References::Unused, Completeness::Complete);
        let id = initial.candidates.first().unwrap().id.clone();
        let mut port = Fake {
            surveys: VecDeque::from([initial, fresh]),
            removed: Vec::new(),
        };
        let report = run(
            &mut port,
            &Operation {
                provider: Provider::Rustup,
                roots: &[],
                tiers: TierGrant::ROUTINE.with(Tier::Reinstallable),
                ids: &[id.clone(), id],
                mode,
            },
        )
        .unwrap();
        (port, report)
    }

    #[test]
    fn a_new_reference_an_incomplete_survey_or_a_changed_manager_stops_removal() {
        for (fresh, expected) in [
            (
                survey("manager-a", References::Referenced, Completeness::Complete),
                Refusal::Referenced,
            ),
            (
                survey("manager-a", References::Unknown, Completeness::Complete),
                Refusal::Unknown,
            ),
            (
                survey("manager-a", References::Unused, Completeness::Incomplete),
                Refusal::Incomplete,
            ),
            (
                survey("manager-b", References::Unused, Completeness::Complete),
                Refusal::Stale,
            ),
        ] {
            let (port, report) = execute(fresh, Mode::Execute);
            assert_eq!(port.removed, Vec::<Action>::new());
            assert!(
                matches!(report.outcomes.first().unwrap().result, ManagedStatus::Refused { reason } if reason == expected)
            );
            assert_eq!(
                report.outcomes.first().unwrap().observed_freed,
                Some(Bytes::ZERO)
            );
        }
    }

    #[test]
    fn an_unreferenced_toolchain_uses_the_manager_once_and_a_dry_run_has_no_effect() {
        for mode in [Mode::DryRun, Mode::Execute] {
            let (port, report) = execute(
                survey("manager-a", References::Unused, Completeness::Complete),
                mode,
            );
            assert_eq!(report.outcomes.len(), 1);
            match mode {
                Mode::DryRun => {
                    assert_eq!(port.removed, Vec::<Action>::new());
                    assert!(matches!(
                        report.outcomes.first().unwrap().result,
                        ManagedStatus::WouldRemove
                    ));
                },
                Mode::Execute => {
                    assert_eq!(port.removed.len(), 1);
                    assert!(matches!(
                        report.outcomes.first().unwrap().result,
                        ManagedStatus::Removed {
                            manager_reclaimed: None
                        }
                    ));
                },
            }
            assert_eq!(report.outcomes.first().unwrap().observed_freed, None);
        }
    }

    #[test]
    fn a_changed_action_is_refused_even_when_a_provider_reuses_the_reviewed_identity() {
        let mut fresh = survey("manager-a", References::Unused, Completeness::Complete);
        fresh.candidates.first_mut().unwrap().action = Action::Toolchain {
            tool: "rust".to_owned(),
            version: "1.98.0".to_owned(),
            path: PathBuf::from("/tools/other/1.98.0"),
        };
        let (port, report) = execute(fresh, Mode::Execute);
        assert_eq!(port.removed, Vec::<Action>::new());
        assert!(matches!(
            report.outcomes.first().unwrap().result,
            ManagedStatus::Refused {
                reason: Refusal::Stale
            }
        ));
    }
}
