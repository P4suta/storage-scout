use std::path::Path;

use storage_scout_core::gate::ShareClearance;
use storage_scout_core::reject::{FsOp, Rejection, StaleField};
use storage_scout_core::share::Failure;

use crate::busy::Lease;
use crate::platform::{Request, Tree};
use crate::{failure, host};

#[must_use]
pub(super) struct Shareable {
    clearance: ShareClearance,
    _lease: Lease,
    tree: Tree,
}

impl Shareable {
    pub(super) fn new(
        clearance: ShareClearance,
        lease: Lease,
        path: &Path,
    ) -> Result<Self, Rejection> {
        if &host::locate(path)? != clearance.location() {
            return Err(Rejection::Stale {
                location: clearance.location().clone(),
                field: StaleField::CanonicalPath,
            });
        }
        let tree = Tree::open(path, clearance.identity())
            .map_err(|error| failure::walk(error, clearance.location(), FsOp::Open))?;
        Ok(Self {
            clearance,
            _lease: lease,
            tree,
        })
    }

    pub(super) fn share(&self, request: &Request<'_>) -> Result<(), Failure> {
        self.tree.share(self.clearance.method(), request)
    }
}
