mod apply;
mod auto;
mod busy;
mod coalesce;
mod dedupe;
mod doctor;
mod explain;
mod failure;
pub mod hook;
mod host;
mod ingress;
mod measure;
mod observe;
mod owners;
mod platform;
mod report;
mod scan;
mod store;
pub mod trace;

use std::path::{Path, PathBuf};

pub use storage_scout_core as core;
use storage_scout_core::area::Protection;
use storage_scout_core::candidate::CandidateId;
use storage_scout_core::gate::Mandate;
use storage_scout_core::reject::Rejection;

pub use crate::apply::{Mode, Outcome, Plan, Status, Summary};
pub use crate::auto::{
    AutoPolicy, AutoRun, Deduping, EvictStep, Evicting, PolicyError, Reaping, Selection, Watch,
};
pub use crate::dedupe::{Admission, DedupeRun, PairOutcome, PairStatus, Subject, Tally, Totals};
pub use crate::doctor::{Diagnosis, PolicyFile, Warning};
pub use crate::explain::Explanation;
pub use crate::host::HostError;
pub use crate::measure::Measure;
pub use crate::report::{
    Color, render_auto, render_clean, render_dedupe, render_doctor, render_explain, render_json,
    render_scan,
};
pub use crate::scan::{
    DEFAULT_MIN_SIZE, DEFAULT_TOP, DirectoryUsage, Found, ScanOptions, ScanReport, ScanStats,
};

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone)]
pub struct Scout {
    protection: Protection,
    owners: owners::Owners,
}

impl Scout {
    pub fn detect() -> Result<Self, HostError> {
        host::detect().map(|protection| Self {
            protection,
            owners: owners::Owners::detect(),
        })
    }

    #[must_use]
    pub fn with(protection: Protection) -> Self {
        Self {
            protection,
            owners: owners::Owners::default(),
        }
    }

    #[must_use]
    pub fn confined(self, ceilings: Vec<PathBuf>) -> Self {
        Self {
            owners: owners::Owners::new(ceilings),
            ..self
        }
    }

    #[must_use]
    pub const fn protection(&self) -> &Protection {
        &self.protection
    }

    #[must_use]
    pub fn scan(&self, options: &ScanOptions) -> ScanReport {
        scan::scan(options, &self.protection, &self.owners)
    }

    pub fn discover(&self, options: &ScanOptions) -> Result<ScanReport, Rejection> {
        let mut roots = Vec::new();
        for root in &options.roots {
            match scan::validate_root(root, &self.protection) {
                Ok(validated) => roots.push(validated),
                Err(Rejection::Io {
                    failure:
                        storage_scout_core::reject::IoFailure {
                            kind: storage_scout_core::reject::IoKind::NotFound,
                            ..
                        },
                    ..
                }) => {},
                Err(rejection) => return Err(rejection),
            }
        }
        if roots.is_empty() {
            return Err(Rejection::NoRoots);
        }
        let validated = ScanOptions {
            roots,
            measure: Measure::Allocated,
            ..options.clone()
        };
        Ok(scan::scan(&validated, &self.protection, &self.owners))
    }

    pub fn plan(
        found: &[Found],
        ids: &[CandidateId],
        mandate: Mandate,
        excludes: &[PathBuf],
    ) -> Result<Plan, Rejection> {
        apply::plan(found, ids, mandate, excludes)
    }

    #[must_use]
    pub fn apply(&self, plan: &Plan, mode: Mode) -> Summary {
        apply::apply(plan, mode, &self.protection, &self.owners)
    }

    pub fn explain(
        &self,
        path: &Path,
        excludes: &[PathBuf],
        mandate: Mandate,
    ) -> Result<Explanation, Rejection> {
        explain::explain(path, excludes, mandate, &self.protection, &self.owners)
    }

    pub fn dedupe(
        &self,
        roots: &[PathBuf],
        excludes: &[PathBuf],
        mode: Mode,
    ) -> Result<DedupeRun, Rejection> {
        let report = self.discover(&ScanOptions {
            roots: roots.to_vec(),
            top: 0,
            min_size: storage_scout_core::size::Bytes::ZERO,
            max_depth: Some(0),
            excludes: excludes.to_vec(),
            threads: None,
            measure: Measure::Allocated,
        })?;
        Ok(dedupe::run(
            &report.candidates,
            &scan::excludes(excludes),
            &self.protection,
            mode,
        ))
    }

    pub fn auto(&self, policy: &AutoPolicy, mode: Mode) -> Result<AutoRun, Rejection> {
        auto::run(self, policy, mode)
    }

    #[must_use]
    pub fn diagnose(&self, default_policy: Option<PathBuf>) -> Diagnosis {
        doctor::diagnose(&self.protection, default_policy)
    }
}

pub fn append_log(path: &Path, document: &impl serde::Serialize) -> std::io::Result<()> {
    store::append_line(path, document)
}
