use std::path::PathBuf;

use storage_scout_core::gate::Clearance;
use storage_scout_core::reject::{FsOp, Rejection, StaleField};

use crate::busy::Lease;
use crate::platform;
use crate::{failure, host};

#[derive(Debug)]
#[must_use]
pub(super) struct Authorized {
    clearance: Clearance,
    lease: Lease,
    path: PathBuf,
}

impl Authorized {
    pub(super) fn new(
        clearance: Clearance,
        lease: Lease,
        path: PathBuf,
    ) -> Result<Self, Rejection> {
        if &host::locate(&path)? == clearance.location() {
            Ok(Self {
                clearance,
                lease,
                path,
            })
        } else {
            Err(Rejection::Stale {
                location: clearance.location().clone(),
                field: StaleField::CanonicalPath,
            })
        }
    }

    pub(super) fn remove(self) -> Result<(), Rejection> {
        let Self {
            clearance,
            lease,
            path: root,
        } = self;
        let keep = lease.keys();
        platform::remove_tree(&root, clearance.identity(), &keep, move || drop(lease))
            .map_err(|error| failure::walk(error, clearance.location(), FsOp::Remove))
    }
}
