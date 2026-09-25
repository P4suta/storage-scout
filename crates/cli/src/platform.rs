use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use storage_scout_core::candidate::Identity;
use storage_scout_core::gate::{Boundary, Shape};
use storage_scout_core::share::{Extras, Failure, Filesystem, Method, Mode, Owner, Sharing, Step};

#[cfg_attr(unix, path = "platform/unix.rs")]
#[cfg_attr(windows, path = "platform/windows.rs")]
mod imp;
#[cfg_attr(target_os = "macos", path = "platform/share_macos.rs")]
#[cfg_attr(target_os = "linux", path = "platform/share_linux.rs")]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    path = "platform/share_none.rs"
)]
mod share;
pub(crate) mod spawn;

#[derive(Debug, Clone, Copy)]
pub(crate) struct FileMeasure {
    pub identity: Identity,
    pub allocation: u64,
    pub links: u32,
}

#[derive(Debug)]
pub(crate) enum WalkError {
    Moved {
        path: PathBuf,
    },
    #[cfg_attr(
        windows,
        expect(
            dead_code,
            reason = "a Windows mount point is a reparse point and is never entered"
        )
    )]
    Boundary {
        path: PathBuf,
        from: u64,
        to: u64,
    },
    Io {
        path: PathBuf,
        error: io::Error,
    },
}

pub(crate) fn identity(path: &Path) -> io::Result<Identity> {
    imp::identity(path)
}

pub(crate) fn identity_of_file(file: &File) -> io::Result<Identity> {
    imp::identity_of_file(file)
}

#[cfg_attr(
    windows,
    expect(clippy::missing_const_for_fn, reason = "const only on Windows")
)]
pub(crate) fn identity_of_metadata(metadata: &Metadata) -> Option<Identity> {
    imp::identity_of_metadata(metadata)
}

pub(crate) fn file_measure(path: &Path) -> io::Result<FileMeasure> {
    imp::file_measure(path)
}

pub(crate) fn free_space(path: &Path) -> io::Result<u64> {
    imp::free_space(path)
}

pub(crate) fn shape(metadata: &Metadata) -> Shape {
    let kind = metadata.file_type();
    if kind.is_symlink() || imp::is_reparse_point(metadata) {
        Shape::Link
    } else if kind.is_dir() {
        Shape::Directory
    } else if kind.is_file() {
        Shape::File
    } else {
        Shape::Other
    }
}

#[cfg_attr(
    windows,
    expect(clippy::missing_const_for_fn, reason = "const only on Windows")
)]
pub(crate) fn device(metadata: &Metadata) -> Option<u64> {
    imp::device(metadata)
}

pub(crate) fn boundary(parent: &Metadata, child: &Metadata) -> Boundary {
    match (device(parent), device(child)) {
        (Some(from), Some(to)) if from == to => Boundary::Same { device: to },
        (Some(from), Some(to)) => Boundary::Crossed { from, to },
        (None, _) | (_, None) => Boundary::Unreported,
    }
}

pub(crate) fn remove_tree(
    root: &Path,
    expected: Identity,
    keep: &BTreeSet<Identity>,
    release: impl FnOnce(),
) -> Result<(), WalkError> {
    imp::remove_tree(root, expected, keep, release)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FileFacts {
    pub identity: Identity,
    pub len: u64,
    pub links: u32,
    pub owner: Owner,
    pub mode: Mode,
    pub sharing: Sharing,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    expect(dead_code, reason = "this platform shares nothing")
)]
pub(crate) struct Request<'a> {
    pub keeper: &'a Path,
    pub keeper_identity: Identity,
    pub duplicate: &'a Path,
    pub duplicate_identity: Identity,
    pub len: u64,
}

fn failed(step: Step) -> impl Fn(io::Error) -> Failure {
    move |error| Failure::Io {
        step,
        error: crate::failure::describe(&error),
    }
}

#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    expect(
        clippy::missing_const_for_fn,
        reason = "const only where nothing is shared"
    )
)]
pub(crate) fn filesystem(path: &Path) -> io::Result<Filesystem> {
    share::filesystem(path)
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    imp::open_regular(path)
}

pub(crate) fn file_facts(path: &Path, metadata: &Metadata) -> io::Result<FileFacts> {
    share::facts(path, metadata)
}

#[cfg_attr(
    not(target_os = "macos"),
    expect(
        clippy::missing_const_for_fn,
        reason = "only APFS replacements read extras"
    )
)]
pub(crate) fn extras(path: &Path, identity: Identity) -> Extras {
    share::extras(path, identity)
}

pub(crate) struct Tree(share::Tree);

impl Tree {
    pub(crate) fn open(root: &Path, expected: Identity) -> Result<Self, WalkError> {
        share::open(root, expected).map(Self)
    }

    pub(crate) fn share(&self, method: Method, request: &Request<'_>) -> Result<(), Failure> {
        share::share(&self.0, method, request)
    }
}
