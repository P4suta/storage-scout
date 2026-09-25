use std::fs::Metadata;
use std::io;
use std::path::Path;

use storage_scout_core::candidate::Identity;
use storage_scout_core::share::{Extras, Failure, Filesystem, Method, Step};

use super::{FileFacts, Request, WalkError, failed};

pub(super) struct Tree;

fn unsupported() -> io::Error {
    io::Error::from(io::ErrorKind::Unsupported)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature is shared with platforms that can fail"
)]
pub(super) const fn filesystem(_path: &Path) -> io::Result<Filesystem> {
    Ok(Filesystem::Other)
}

pub(super) fn facts(_path: &Path, _metadata: &Metadata) -> io::Result<FileFacts> {
    Err(unsupported())
}

pub(super) const fn extras(_path: &Path, _identity: Identity) -> Extras {
    Extras::Unobserved
}

pub(super) fn open(root: &Path, _expected: Identity) -> Result<Tree, WalkError> {
    Err(WalkError::Io {
        path: root.to_path_buf(),
        error: unsupported(),
    })
}

pub(super) fn share(_tree: &Tree, _method: Method, _request: &Request<'_>) -> Result<(), Failure> {
    Err(failed(Step::Open)(unsupported()))
}
