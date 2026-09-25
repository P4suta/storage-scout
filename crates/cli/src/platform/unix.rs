#![expect(
    unsafe_code,
    reason = "the platform layer is the one place that makes system calls"
)]

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, Metadata};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use storage_scout_core::candidate::Identity;

use super::{FileMeasure, WalkError};

const BLOCK_UNIT: u64 = 512;

fn identity_from(dev: u64, ino: u64) -> Identity {
    Identity {
        volume: dev,
        file: u128::from(ino),
    }
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "Windows has no identity on metadata to report"
)]
pub(super) fn identity_of_metadata(metadata: &Metadata) -> Option<Identity> {
    Some(identity_from(metadata.dev(), metadata.ino()))
}

pub(super) fn identity(path: &Path) -> io::Result<Identity> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(identity_from(metadata.dev(), metadata.ino()))
}

pub(super) fn identity_of_file(file: &File) -> io::Result<Identity> {
    let metadata = file.metadata()?;
    Ok(identity_from(metadata.dev(), metadata.ino()))
}

pub(super) fn file_measure(path: &Path) -> io::Result<FileMeasure> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(FileMeasure {
        identity: identity_from(metadata.dev(), metadata.ino()),
        allocation: metadata.blocks().saturating_mul(BLOCK_UNIT),
        links: match u32::try_from(metadata.nlink()) {
            Ok(links) => links.max(1),
            Err(_too_many) => u32::MAX,
        },
    })
}

pub(super) fn c_path(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_interior_nul| io::Error::from(io::ErrorKind::InvalidInput))
}

pub(super) fn free_space(path: &Path) -> io::Result<u64> {
    let path = c_path(path.as_os_str().as_bytes())?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` is a writable buffer of the exact type.
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `statvfs` returned 0, so it initialised the buffer.
    let stat = unsafe { stat.assume_init() };
    let block = if stat.f_frsize == 0 {
        stat.f_bsize
    } else {
        stat.f_frsize
    };
    Ok(widen(stat.f_bavail).saturating_mul(widen(block)))
}

fn widen<T: Into<u64>>(value: T) -> u64 {
    value.into()
}

pub(super) const fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[expect(clippy::unnecessary_wraps, reason = "Windows has no device to report")]
pub(super) fn device(metadata: &Metadata) -> Option<u64> {
    Some(metadata.dev())
}

#[cfg(target_os = "macos")]
pub(super) fn device_number(raw: libc::dev_t) -> u64 {
    u64::from_ne_bytes(i64::from(raw).to_ne_bytes())
}

#[cfg(not(target_os = "macos"))]
pub(super) const fn device_number(raw: libc::dev_t) -> u64 {
    raw
}

pub(super) fn stat_identity(stat: &libc::stat) -> Identity {
    identity_from(device_number(stat.st_dev), stat.st_ino)
}

const fn is_directory(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

pub(super) fn open_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated and `dir` is an open directory descriptor or `AT_FDCWD`.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` just returned this descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(super) fn open_directory(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    open_at(
        dir,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
}

pub(super) fn stat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is NUL-terminated and `stat` is a writable buffer of the exact type.
    let result = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstatat` returned 0, so it initialised the buffer.
    Ok(unsafe { stat.assume_init() })
}

pub(super) fn stat_fd(fd: &impl AsRawFd) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is open and `stat` is a writable buffer of the exact type.
    let result = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstat` returned 0, so it initialised the buffer.
    Ok(unsafe { stat.assume_init() })
}

pub(super) fn unlink_at(dir: &OwnedFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `name` is NUL-terminated and `dir` is an open directory descriptor.
    let result = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: `__error` has no preconditions.
    let slot = unsafe { libc::__error() };
    // SAFETY: `__error` returns this thread's errno location, which is always valid to write.
    unsafe { *slot = 0 };
}

#[cfg(not(target_os = "macos"))]
fn clear_errno() {
    // SAFETY: `__errno_location` has no preconditions.
    let slot = unsafe { libc::__errno_location() };
    // SAFETY: `__errno_location` returns this thread's errno location, which is always valid to write.
    unsafe { *slot = 0 };
}

struct Stream(*mut libc::DIR);

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: the stream came from a successful `fdopendir` and is closed exactly once.
        let _closed = unsafe { libc::closedir(self.0) };
    }
}

fn names(dir: &OwnedFd) -> io::Result<Vec<CString>> {
    let copy = open_directory(dir.as_raw_fd(), c".")?.into_raw_fd();
    // SAFETY: `copy` is an open directory descriptor; on success the stream owns it.
    let stream = unsafe { libc::fdopendir(copy) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed, so `copy` is still ours to close.
        drop(unsafe { OwnedFd::from_raw_fd(copy) });
        return Err(error);
    }
    let stream = Stream(stream);
    let mut names = Vec::new();
    loop {
        clear_errno();
        // SAFETY: the stream is open for as long as `stream` lives.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(0) | None => Ok(names),
                Some(_) => Err(error),
            };
        }
        // SAFETY: `readdir` returned a non-null entry that stays valid until the next call on this stream.
        let entry = unsafe { &*entry };
        // SAFETY: `d_name` is NUL-terminated within the entry.
        let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
        if name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    }
}

fn make_writable(dir: &OwnedFd, stat: &libc::stat) -> io::Result<()> {
    let wanted = stat.st_mode | libc::S_IRUSR | libc::S_IWUSR | libc::S_IXUSR;
    if wanted == stat.st_mode {
        return Ok(());
    }
    // SAFETY: `dir` is an open descriptor for the directory whose mode is being widened.
    let result = unsafe { libc::fchmod(dir.as_raw_fd(), wanted & !libc::S_IFMT) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct Walk<'a> {
    device: u64,
    keep: &'a BTreeSet<Identity>,
}

impl Walk<'_> {
    fn clear(&self, dir: &OwnedFd, path: &Path) -> Result<bool, WalkError> {
        let io = |error| WalkError::Io {
            path: path.to_path_buf(),
            error,
        };
        let own = stat_fd(dir).map_err(io)?;
        make_writable(dir, &own).map_err(io)?;
        let mut emptied = true;
        for name in names(dir).map_err(io)? {
            let child = path.join(OsStr::from_bytes(name.to_bytes()));
            let child_io = |error| WalkError::Io {
                path: child.clone(),
                error,
            };
            let stat = stat_at(dir.as_raw_fd(), &name).map_err(child_io)?;
            if is_directory(&stat) {
                let found = device_number(stat.st_dev);
                if found != self.device {
                    return Err(WalkError::Boundary {
                        path: child,
                        from: self.device,
                        to: found,
                    });
                }
                let opened = open_directory(dir.as_raw_fd(), &name).map_err(child_io)?;
                if stat_identity(&stat_fd(&opened).map_err(child_io)?) != stat_identity(&stat) {
                    return Err(WalkError::Moved { path: child });
                }
                if self.clear(&opened, &child)? {
                    drop(opened);
                    unlink_at(dir, &name, libc::AT_REMOVEDIR).map_err(child_io)?;
                } else {
                    emptied = false;
                }
            } else if self.keep.contains(&stat_identity(&stat)) {
                emptied = false;
            } else {
                unlink_at(dir, &name, 0).map_err(child_io)?;
            }
        }
        Ok(emptied)
    }
}

pub(super) fn open_regular(path: &Path) -> io::Result<File> {
    let name = c_path(path.as_os_str().as_bytes())?;
    regular(open_at(
        libc::AT_FDCWD,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?)
}

pub(super) fn regular(fd: OwnedFd) -> io::Result<File> {
    if stat_fd(&fd)?.st_mode & libc::S_IFMT == libc::S_IFREG {
        Ok(File::from(fd))
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

pub(super) fn identity_of(metadata: &Metadata) -> Identity {
    identity_from(metadata.dev(), metadata.ino())
}

pub(super) fn links_of(metadata: &Metadata) -> u32 {
    match u32::try_from(metadata.nlink()) {
        Ok(links) => links.max(1),
        Err(_too_many) => u32::MAX,
    }
}

struct Root {
    parent: OwnedFd,
    name: CString,
    fd: OwnedFd,
    stat: libc::stat,
}

fn open_root(root: &Path, expected: Identity) -> Result<Root, WalkError> {
    let moved = || WalkError::Moved {
        path: root.to_path_buf(),
    };
    let io = |error| WalkError::Io {
        path: root.to_path_buf(),
        error,
    };
    let (Some(parent), Some(name)) = (root.parent(), root.file_name()) else {
        return Err(moved());
    };
    let parent = open_at(
        libc::AT_FDCWD,
        &c_path(parent.as_os_str().as_bytes()).map_err(io)?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
    .map_err(io)?;
    let name = c_path(name.as_bytes()).map_err(io)?;
    let fd = open_directory(parent.as_raw_fd(), &name).map_err(io)?;
    let stat = stat_fd(&fd).map_err(io)?;
    if stat_identity(&stat) != expected {
        return Err(moved());
    }
    let from = device_number(stat_fd(&parent).map_err(io)?.st_dev);
    let to = device_number(stat.st_dev);
    if from != to {
        return Err(WalkError::Boundary {
            path: root.to_path_buf(),
            from,
            to,
        });
    }
    Ok(Root {
        parent,
        name,
        fd,
        stat,
    })
}

pub(super) struct Tree {
    root: OwnedFd,
    device: u64,
}

pub(super) enum Located {
    Found { dir: OwnedFd, name: CString },
    Moved,
}

fn vanished(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ELOOP | libc::ENOTDIR | libc::ENOENT)
    )
}

impl Tree {
    pub(super) fn open(root: &Path, expected: Identity) -> Result<Self, WalkError> {
        let opened = open_root(root, expected)?;
        Ok(Self {
            device: device_number(opened.stat.st_dev),
            root: opened.fd,
        })
    }

    pub(super) fn locate(&self, relative: &Path) -> io::Result<Located> {
        let mut names = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(name) => names.push(c_path(name.as_bytes())?),
                Component::Prefix(_)
                | Component::RootDir
                | Component::CurDir
                | Component::ParentDir => return Ok(Located::Moved),
            }
        }
        let Some((last, parents)) = names.split_last() else {
            return Ok(Located::Moved);
        };
        let mut dir = open_directory(self.root.as_raw_fd(), c".")?;
        for name in parents {
            let next = match open_directory(dir.as_raw_fd(), name) {
                Ok(next) => next,
                Err(error) if vanished(&error) => return Ok(Located::Moved),
                Err(error) => return Err(error),
            };
            if device_number(stat_fd(&next)?.st_dev) != self.device {
                return Ok(Located::Moved);
            }
            dir = next;
        }
        Ok(Located::Found {
            dir,
            name: last.clone(),
        })
    }
}

pub(super) fn remove_tree(
    root: &Path,
    expected: Identity,
    keep: &BTreeSet<Identity>,
    release: impl FnOnce(),
) -> Result<(), WalkError> {
    let moved = || WalkError::Moved {
        path: root.to_path_buf(),
    };
    let io = |error| WalkError::Io {
        path: root.to_path_buf(),
        error,
    };
    let Root {
        parent,
        name,
        fd,
        stat,
    } = open_root(root, expected)?;
    let device = device_number(stat.st_dev);
    let nothing = BTreeSet::new();
    Walk { device, keep }.clear(&fd, root)?;
    Walk {
        device,
        keep: &nothing,
    }
    .clear(&fd, root)?;
    drop(fd);
    if stat_identity(&stat_at(parent.as_raw_fd(), &name).map_err(io)?) != expected {
        return Err(moved());
    }
    unlink_at(&parent, &name, libc::AT_REMOVEDIR).map_err(io)?;
    release();
    Ok(())
}
