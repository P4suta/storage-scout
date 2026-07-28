//! Small, audited wrappers around Windows file-information APIs.

use std::io;
use std::path::Path;

/// Stable on-volume identity used for stale-plan detection and hard-link
/// accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileIdentity {
    pub volume: u64,
    pub file: u64,
}

/// Allocation and link metadata for one regular file.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FileMeasure {
    pub identity: FileIdentity,
    pub allocation: u64,
    pub links: u32,
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileStandardInfo, GetDiskFreeSpaceExW,
        GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_EXISTING,
    };

    use super::{FileIdentity, FileMeasure, Path, io};

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: `OwnedHandle` is constructed only from a successful
            // `CreateFileW` call and owns the handle exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        OsStr::new(path.as_os_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn open_metadata(path: &Path) -> io::Result<OwnedHandle> {
        let path = wide(path);
        // SAFETY: the UTF-16 path is NUL-terminated and all pointer arguments
        // remain valid for the duration of the call.
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
        // SAFETY: the output buffer has the exact API type and is valid for the
        // call. The handle remains owned by the caller.
        let mut info = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
        // SAFETY: see above.
        if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(info)
        }
    }

    pub(super) fn identity(path: &Path) -> io::Result<FileIdentity> {
        let handle = open_metadata(path)?;
        let info = by_handle(handle.0)?;
        Ok(FileIdentity {
            volume: u64::from(info.dwVolumeSerialNumber),
            file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }

    pub(super) fn file_measure(path: &Path) -> io::Result<FileMeasure> {
        let handle = open_metadata(path)?;
        let basic = by_handle(handle.0)?;
        // SAFETY: the output buffer is correctly sized and aligned, and the
        // handle is live for the complete call.
        let mut standard = unsafe { zeroed::<FILE_STANDARD_INFO>() };
        #[allow(
            clippy::cast_possible_truncation,
            reason = "FILE_STANDARD_INFO is far smaller than u32::MAX"
        )]
        let buffer_size = size_of::<FILE_STANDARD_INFO>() as u32;
        // SAFETY: see above.
        if unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileStandardInfo,
                (&raw mut standard).cast(),
                buffer_size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let allocation = u64::try_from(standard.AllocationSize)
            .map_err(|_| io::Error::other("negative allocation size"))?;
        Ok(FileMeasure {
            identity: FileIdentity {
                volume: u64::from(basic.dwVolumeSerialNumber),
                file: (u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow),
            },
            allocation,
            links: standard.NumberOfLinks.max(1),
        })
    }

    pub(super) fn free_space(path: &Path) -> io::Result<u64> {
        let path = wide(path);
        let mut available = 0u64;
        // SAFETY: the UTF-16 path and output pointer are valid for the call;
        // optional outputs are null.
        if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &raw mut available, null_mut(), null_mut()) }
            == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(available)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{FileIdentity, FileMeasure, Path, io};

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "storage-scout cleanup is Windows-only",
        )
    }

    pub(super) fn identity(_path: &Path) -> io::Result<FileIdentity> {
        Err(unsupported())
    }

    pub(super) fn file_measure(_path: &Path) -> io::Result<FileMeasure> {
        Err(unsupported())
    }

    pub(super) fn free_space(_path: &Path) -> io::Result<u64> {
        Err(unsupported())
    }
}

pub(crate) fn identity(path: &Path) -> io::Result<FileIdentity> {
    imp::identity(path)
}

pub(crate) fn file_measure(path: &Path) -> io::Result<FileMeasure> {
    imp::file_measure(path)
}

pub(crate) fn free_space(path: &Path) -> io::Result<u64> {
    imp::free_space(path)
}
