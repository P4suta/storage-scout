use std::path::{Path, PathBuf};

use storage_scout_core::gate::PruneClearance;
use storage_scout_core::reject::{FsOp, Rejection, StaleField};

use super::{Doom, Doomed};
use crate::busy::Lease;
use crate::platform::{Pruned, Pruning};
use crate::{failure, host};

#[must_use]
pub(super) struct Prunable {
    clearance: PruneClearance,
    _lease: Lease,
    tree: Pruning,
    root: PathBuf,
}

impl Prunable {
    pub(super) fn new(
        clearance: PruneClearance,
        lease: Lease,
        path: &Path,
    ) -> Result<Self, Rejection> {
        if &host::locate(path)? != clearance.location() {
            return Err(Rejection::Stale {
                location: clearance.location().clone(),
                field: StaleField::CanonicalPath,
            });
        }
        let tree = Pruning::open(path, clearance.identity())
            .map_err(|error| failure::walk(error, clearance.location(), FsOp::Open))?;
        Ok(Self {
            clearance,
            _lease: lease,
            tree,
            root: path.to_path_buf(),
        })
    }

    pub(super) fn prune(&self, doomed: &Doomed) -> Result<Pruned, Rejection> {
        let shown = self.root.join(&doomed.relative);
        match &doomed.doom {
            Doom::File => self
                .tree
                .prune_file(&doomed.relative, doomed.identity)
                .map_err(|error| failure::io(&shown, FsOp::Remove, &error)),
            Doom::Session { lock } => self
                .tree
                .prune_session(&doomed.relative, lock, doomed.identity, &shown)
                .map_err(|error| failure::walk(error, self.clearance.location(), FsOp::Remove)),
        }
    }
}
