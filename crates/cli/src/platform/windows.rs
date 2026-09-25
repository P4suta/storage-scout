#![expect(
    unsafe_code,
    reason = "the platform layer is the one place that makes system calls"
)]

use std::collections::BTreeSet;
use std::fs::{self, File, Metadata, TryLockError};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr::{null, null_mut};

use storage_scout_core::candidate::Identity;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileStandardInfo, GetDiskFreeSpaceExW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_EXISTING,
};

use super::{FileMeasure, Pruned, WalkError};

const REPARSE_POINT: u32 = 0x0400;

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `CreateFileW` and is closed exactly once.
        let _closed = unsafe { CloseHandle(self.0) };
    }
}

pub(super) fn open_regular(path: &Path) -> io::Result<File> {
    let path = wide(path);
    // SAFETY: the UTF-16 path is NUL-terminated and every pointer argument is valid for the call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` just returned this handle and nothing else owns it.
    let file = File::from(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) });
    if file.metadata()?.file_type().is_file() {
        Ok(file)
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn open_metadata(path: &Path) -> io::Result<OwnedHandle> {
    let path = wide(path);
    // SAFETY: the UTF-16 path is NUL-terminated and every pointer argument is valid for the call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedHandle(handle))
    }
}

fn by_handle(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: an all-zero bit pattern is a valid value of this plain C struct.
    let mut info = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: the handle is open and the output buffer has the exact API type.
    let result = unsafe { GetFileInformationByHandle(handle, &raw mut info) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

fn identity_from(info: &BY_HANDLE_FILE_INFORMATION) -> Identity {
    Identity {
        volume: u64::from(info.dwVolumeSerialNumber),
        file: (u128::from(info.nFileIndexHigh) << 32) | u128::from(info.nFileIndexLow),
    }
}

pub(super) const fn identity_of_metadata(_metadata: &Metadata) -> Option<Identity> {
    None
}

pub(super) fn identity(path: &Path) -> io::Result<Identity> {
    let handle = open_metadata(path)?;
    Ok(identity_from(&by_handle(handle.0)?))
}

pub(super) fn identity_of_file(file: &File) -> io::Result<Identity> {
    Ok(identity_from(&by_handle(file.as_raw_handle())?))
}

pub(super) fn file_measure(path: &Path) -> io::Result<FileMeasure> {
    let handle = open_metadata(path)?;
    let basic = by_handle(handle.0)?;
    // SAFETY: an all-zero bit pattern is a valid value of this plain C struct.
    let mut standard = unsafe { zeroed::<FILE_STANDARD_INFO>() };
    let size = u32::try_from(size_of::<FILE_STANDARD_INFO>())
        .map_err(|_too_large| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the handle is open and the buffer is exactly `size` bytes of the requested class.
    let result = unsafe {
        GetFileInformationByHandleEx(handle.0, FileStandardInfo, (&raw mut standard).cast(), size)
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocation = u64::try_from(standard.AllocationSize)
        .map_err(|_negative| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(FileMeasure {
        identity: identity_from(&basic),
        allocation,
        links: standard.NumberOfLinks.max(1),
    })
}

pub(super) fn free_space(path: &Path) -> io::Result<u64> {
    let path = wide(path);
    let mut available = 0u64;
    // SAFETY: the UTF-16 path and the output pointer are valid for the call; optional outputs are null.
    let result =
        unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &raw mut available, null_mut(), null_mut()) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(available)
    }
}

pub(super) fn is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_attributes() & REPARSE_POINT != 0
}

pub(super) const fn device(_metadata: &Metadata) -> Option<u64> {
    None
}

#[expect(
    clippy::disallowed_methods,
    reason = "the one place a file is removed, reached only through apply::capability"
)]
fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let mut permissions = fs::symlink_metadata(path)?.permissions();
            #[expect(
                clippy::permissions_set_readonly_false,
                reason = "FILE_ATTRIBUTE_READONLY blocks deletion of a regenerable artifact"
            )]
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions)?;
            fs::remove_file(path)
        },
        Err(error) => Err(error),
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the one place a directory is removed, reached only through apply::capability"
)]
fn remove_dir(path: &Path) -> io::Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let mut permissions = fs::symlink_metadata(path)?.permissions();
            #[expect(
                clippy::permissions_set_readonly_false,
                reason = "FILE_ATTRIBUTE_READONLY blocks deletion of a regenerable artifact"
            )]
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions)?;
            fs::remove_dir(path)
        },
        Err(error) => Err(error),
    }
}

fn clear(dir: &Path, keep: &BTreeSet<Identity>) -> Result<bool, WalkError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |error| WalkError::Io { path, error }
    };
    let mut emptied = true;
    for entry in fs::read_dir(dir).map_err(io(dir))? {
        let path = entry.map_err(io(dir))?.path();
        let metadata = fs::symlink_metadata(&path).map_err(io(&path))?;
        if is_reparse_point(&metadata) || metadata.file_type().is_symlink() {
            if metadata.is_dir() {
                remove_dir(&path).map_err(io(&path))?;
            } else {
                remove_file(&path).map_err(io(&path))?;
            }
        } else if metadata.is_dir() {
            if clear(&path, keep)? {
                remove_dir(&path).map_err(io(&path))?;
            } else {
                emptied = false;
            }
        } else if keep.contains(&identity(&path).map_err(io(&path))?) {
            emptied = false;
        } else {
            remove_file(&path).map_err(io(&path))?;
        }
    }
    Ok(emptied)
}

pub(super) fn remove_tree(
    root: &Path,
    expected: Identity,
    keep: &BTreeSet<Identity>,
    release: impl FnOnce(),
) -> Result<(), WalkError> {
    let io = |error| WalkError::Io {
        path: root.to_path_buf(),
        error,
    };
    let metadata = fs::symlink_metadata(root).map_err(io)?;
    if is_reparse_point(&metadata) || identity(root).map_err(io)? != expected {
        return Err(WalkError::Moved {
            path: root.to_path_buf(),
        });
    }
    clear(root, keep)?;
    release();
    clear(root, &BTreeSet::new())?;
    remove_dir(root).map_err(io)
}

pub(super) struct Tree {
    root: PathBuf,
}

fn inside(root: &Path, relative: &Path) -> Option<PathBuf> {
    let mut components = relative.components().peekable();
    components.peek()?;
    components
        .all(|component| matches!(component, Component::Normal(_)))
        .then(|| root.join(relative))
}

fn vanished(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

enum SessionLock {
    Taken(File),
    Absent,
    Held,
}

fn session_lock(path: &Path) -> io::Result<SessionLock> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if vanished(&error) => return Ok(SessionLock::Absent),
        Err(error) => return Err(error),
    };
    match file.try_lock() {
        Ok(()) => Ok(SessionLock::Taken(file)),
        Err(TryLockError::WouldBlock) => Ok(SessionLock::Held),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    File,
    Directory,
}

fn same(path: &Path, expected: Identity, entry: Entry) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if vanished(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    let found = if metadata.is_dir() {
        Entry::Directory
    } else {
        Entry::File
    };
    if is_reparse_point(&metadata) || found != entry {
        return Ok(false);
    }
    Ok(identity(path)? == expected)
}

impl Tree {
    pub(super) fn open(root: &Path, expected: Identity) -> Result<Self, WalkError> {
        match same(root, expected, Entry::Directory) {
            Ok(true) => Ok(Self {
                root: root.to_path_buf(),
            }),
            Ok(false) => Err(WalkError::Moved {
                path: root.to_path_buf(),
            }),
            Err(error) => Err(WalkError::Io {
                path: root.to_path_buf(),
                error,
            }),
        }
    }

    pub(super) fn prune_file(&self, relative: &Path, expected: Identity) -> io::Result<Pruned> {
        let Some(path) = inside(&self.root, relative) else {
            return Ok(Pruned::Moved);
        };
        if !same(&path, expected, Entry::File)? {
            return Ok(Pruned::Moved);
        }
        match remove_file(&path) {
            Ok(()) => Ok(Pruned::Removed),
            Err(error) if vanished(&error) => Ok(Pruned::Moved),
            Err(error) => Err(error),
        }
    }

    pub(super) fn prune_session(
        &self,
        relative: &Path,
        lock: &std::ffi::OsStr,
        expected: Identity,
        shown: &Path,
    ) -> Result<Pruned, WalkError> {
        let io = |error| WalkError::Io {
            path: shown.to_path_buf(),
            error,
        };
        let Some(directory) = inside(&self.root, relative) else {
            return Ok(Pruned::Moved);
        };
        let lock = directory.with_file_name(lock);
        let held = match session_lock(&lock).map_err(io)? {
            SessionLock::Taken(file) => Some(file),
            SessionLock::Absent => None,
            SessionLock::Held => return Ok(Pruned::Held),
        };
        if !same(&directory, expected, Entry::Directory).map_err(io)? {
            return Ok(Pruned::Moved);
        }
        clear(&directory, &BTreeSet::new())?;
        remove_dir(&directory).map_err(io)?;
        if held.is_some() {
            match remove_file(&lock) {
                Ok(()) => {},
                Err(error) if vanished(&error) => {},
                Err(error) => return Err(io(error)),
            }
        }
        drop(held);
        Ok(Pruned::Removed)
    }
}
