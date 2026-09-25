use std::io;
use std::path::Path;

use storage_scout_core::location::Location;
use storage_scout_core::reject::{FsOp, IoFailure, IoKind, Rejection, StaleField};

use crate::host;
use crate::platform::WalkError;

#[must_use]
pub(crate) fn describe(error: &io::Error) -> IoFailure {
    let kind = match error.kind() {
        io::ErrorKind::NotFound => IoKind::NotFound,
        io::ErrorKind::PermissionDenied => IoKind::PermissionDenied,
        io::ErrorKind::AlreadyExists => IoKind::AlreadyExists,
        io::ErrorKind::WouldBlock => IoKind::WouldBlock,
        io::ErrorKind::InvalidInput => IoKind::InvalidInput,
        io::ErrorKind::DirectoryNotEmpty => IoKind::DirectoryNotEmpty,
        io::ErrorKind::ReadOnlyFilesystem => IoKind::ReadOnlyFilesystem,
        io::ErrorKind::ResourceBusy => IoKind::ResourceBusy,
        io::ErrorKind::CrossesDevices => IoKind::CrossesDevices,
        io::ErrorKind::Interrupted => IoKind::Interrupted,
        io::ErrorKind::Unsupported => IoKind::Unsupported,
        io::ErrorKind::NotADirectory => IoKind::NotADirectory,
        io::ErrorKind::IsADirectory => IoKind::IsADirectory,
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => IoKind::StorageFull,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::StaleNetworkFileHandle
        | io::ErrorKind::InvalidData
        | io::ErrorKind::TimedOut
        | io::ErrorKind::WriteZero
        | io::ErrorKind::NotSeekable
        | io::ErrorKind::FileTooLarge
        | io::ErrorKind::ExecutableFileBusy
        | io::ErrorKind::Deadlock
        | io::ErrorKind::TooManyLinks
        | io::ErrorKind::InvalidFilename
        | io::ErrorKind::ArgumentListTooLong
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::OutOfMemory
        | io::ErrorKind::Other
        | _ => IoKind::Other,
    };
    IoFailure {
        kind,
        code: error.raw_os_error(),
    }
}

#[must_use]
pub(crate) fn io(path: &Path, operation: FsOp, error: &io::Error) -> Rejection {
    let absolute = match std::path::absolute(path) {
        Ok(absolute) => absolute,
        Err(_unresolvable) => path.to_path_buf(),
    };
    match host::locate(&absolute) {
        Ok(location) => Rejection::Io {
            location,
            operation,
            failure: describe(error),
        },
        Err(unnameable) => unnameable,
    }
}

pub(crate) fn walk(error: WalkError, fallback: &Location, operation: FsOp) -> Rejection {
    match error {
        WalkError::Moved { path } => Rejection::Stale {
            location: match host::locate(&path) {
                Ok(location) => location,
                Err(_unnameable) => fallback.clone(),
            },
            field: StaleField::FileIdentity,
        },
        WalkError::Boundary { path, from, to } => match host::locate(&path) {
            Ok(location) => Rejection::MountBoundary { location, from, to },
            Err(unnameable) => unnameable,
        },
        WalkError::Io { path, error } => io(&path, operation, &error),
    }
}
