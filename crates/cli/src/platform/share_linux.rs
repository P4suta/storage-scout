#![expect(
    unsafe_code,
    reason = "sharing extents and reading filesystem types are system calls"
)]

use std::fs::{File, Metadata};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use storage_scout_core::candidate::Identity;
use storage_scout_core::share::{Extras, Failure, Filesystem, Method, Mode, Owner, Sharing, Step};

pub(super) use super::imp::Tree;
use super::imp::{self, Located};
use super::{FileFacts, Request, WalkError, failed};

#[repr(C)]
struct DedupeInfo {
    dest_fd: i64,
    dest_offset: u64,
    bytes_deduped: u64,
    status: i32,
    reserved: u32,
}

#[repr(C)]
struct DedupeRange {
    src_offset: u64,
    src_length: u64,
    dest_count: u16,
    reserved1: u16,
    reserved2: u32,
    info: DedupeInfo,
}

const _: () = assert!(size_of::<DedupeInfo>() == 32);
const _: () = assert!(size_of::<DedupeRange>() == 24 + 32);

#[cfg(target_env = "musl")]
const FIDEDUPERANGE: libc::Ioctl = i32::from_ne_bytes(0xC018_9436_u32.to_ne_bytes());
#[cfg(not(target_env = "musl"))]
const FIDEDUPERANGE: libc::Ioctl = 0xC018_9436;

const SAME: i32 = 0;
const DIFFERS: i32 = 1;
const CHUNK: u64 = 16 * 1024 * 1024;

pub(super) fn filesystem(path: &Path) -> io::Result<Filesystem> {
    let path = imp::c_path(path.as_os_str().as_bytes())?;
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` is a writable buffer of the exact type.
    let result = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `statfs` returned 0, so it initialised the buffer.
    let stat = unsafe { stat.assume_init() };
    let kind = signed(stat.f_type);
    let kinds = [
        (signed(libc::BTRFS_SUPER_MAGIC), Filesystem::Btrfs),
        (signed(libc::XFS_SUPER_MAGIC), Filesystem::Xfs),
    ];
    Ok(kinds
        .into_iter()
        .find(|(magic, _)| *magic == kind)
        .map_or(Filesystem::Other, |(_, filesystem)| filesystem))
}

fn signed<T: Into<i64>>(value: T) -> i64 {
    value.into()
}

fn caller() -> libc::uid_t {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

const fn size(stat: &libc::stat) -> u64 {
    stat.st_size.unsigned_abs()
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature is shared with platforms that read more than metadata"
)]
pub(super) fn facts(_path: &Path, metadata: &Metadata) -> io::Result<FileFacts> {
    Ok(FileFacts {
        identity: imp::identity_of(metadata),
        len: metadata.len(),
        links: imp::links_of(metadata),
        owner: if metadata.uid() == caller() {
            Owner::Caller
        } else {
            Owner::Other
        },
        mode: if metadata.mode() & 0o111 == 0 {
            Mode::Plain
        } else {
            Mode::Executable
        },
        sharing: Sharing::Unknown,
    })
}

pub(super) const fn extras(_path: &Path, _identity: Identity) -> Extras {
    Extras::Unobserved
}

fn dedupe(keeper: &File, duplicate: &File, offset: u64, length: u64) -> Result<u64, Failure> {
    let mut range = DedupeRange {
        src_offset: offset,
        src_length: length,
        dest_count: 1,
        reserved1: 0,
        reserved2: 0,
        info: DedupeInfo {
            dest_fd: i64::from(duplicate.as_raw_fd()),
            dest_offset: offset,
            bytes_deduped: 0,
            status: 0,
            reserved: 0,
        },
    };
    // SAFETY: `range` is a live `file_dedupe_range` with room for exactly `dest_count` entries.
    let result = unsafe { libc::ioctl(keeper.as_raw_fd(), FIDEDUPERANGE, &raw mut range) };
    if result != 0 {
        return Err(failed(Step::Dedupe)(io::Error::last_os_error()));
    }
    match range.info.status {
        SAME => Ok(range.info.bytes_deduped),
        DIFFERS => Err(Failure::ContentDiffers),
        negative => Err(failed(Step::Dedupe)(io::Error::from_raw_os_error(
            negative.saturating_neg(),
        ))),
    }
}

pub(super) fn share(tree: &Tree, method: Method, request: &Request<'_>) -> Result<(), Failure> {
    match method {
        Method::DedupeRange => {},
        Method::CloneAndSwap => {
            return Err(failed(Step::Clone)(io::Error::from(
                io::ErrorKind::Unsupported,
            )));
        },
    }
    let keeper = imp::open_regular(request.keeper).map_err(|_gone| Failure::KeeperChanged)?;
    let kept = imp::stat_fd(&keeper).map_err(failed(Step::Inspect))?;
    if imp::stat_identity(&kept) != request.keeper_identity || size(&kept) != request.len {
        return Err(Failure::KeeperChanged);
    }
    let (dir, name) = match tree.locate(request.duplicate).map_err(failed(Step::Open))? {
        Located::Found { dir, name } => (dir, name),
        Located::Moved => return Err(Failure::DuplicateChanged),
    };
    let duplicate = imp::regular(
        imp::open_at(
            dir.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
        .map_err(|_gone| Failure::DuplicateChanged)?,
    )
    .map_err(|_gone| Failure::DuplicateChanged)?;
    let found = imp::stat_fd(&duplicate).map_err(failed(Step::Inspect))?;
    if imp::stat_identity(&found) != request.duplicate_identity
        || size(&found) != request.len
        || found.st_uid != caller()
    {
        return Err(Failure::DuplicateChanged);
    }
    let mut offset = 0u64;
    while offset < request.len {
        let length = request.len.saturating_sub(offset).min(CHUNK);
        let shared = dedupe(&keeper, &duplicate, offset, length)?;
        if shared == 0 {
            return Err(failed(Step::Dedupe)(io::Error::from(
                io::ErrorKind::InvalidInput,
            )));
        }
        offset = offset.saturating_add(shared);
    }
    Ok(())
}

pub(super) fn open(root: &Path, expected: Identity) -> Result<Tree, WalkError> {
    Tree::open(root, expected)
}
