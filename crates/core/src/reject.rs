use alloc::string::String;
use core::fmt;

use serde::Serialize;

use crate::area::{AppOwned, SystemReason};
use crate::artifact::{Kind, Provenance, Tier};
use crate::location::Location;
use crate::lock::Protocol;
use crate::ownership::Settlement;
use crate::share::Filesystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaleField {
    CanonicalPath,
    FileIdentity,
    Content,
}

impl fmt::Display for StaleField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CanonicalPath => "the canonical path",
            Self::FileIdentity => "the volume/file ID",
            Self::Content => "the files it holds or their sizes",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FsOp {
    Inspect,
    ReadDir,
    ReadEntry,
    FileType,
    Metadata,
    Canonicalize,
    AllocationInfo,
    FileId,
    FreeSpace,
    FilesystemType,
    Open,
    Lock,
    Remove,
}

impl FsOp {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::ReadDir => "read-dir",
            Self::ReadEntry => "read-entry",
            Self::FileType => "file-type",
            Self::Metadata => "metadata",
            Self::Canonicalize => "canonicalize",
            Self::AllocationInfo => "allocation-info",
            Self::FileId => "file-id",
            Self::FreeSpace => "free-space",
            Self::FilesystemType => "filesystem-type",
            Self::Open => "open",
            Self::Lock => "lock",
            Self::Remove => "remove",
        }
    }
}

impl fmt::Display for FsOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IoKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    DirectoryNotEmpty,
    ReadOnlyFilesystem,
    ResourceBusy,
    CrossesDevices,
    Interrupted,
    Unsupported,
    NotADirectory,
    IsADirectory,
    StorageFull,
    Other,
}

impl fmt::Display for IoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "not found",
            Self::PermissionDenied => "permission denied",
            Self::AlreadyExists => "already exists",
            Self::WouldBlock => "would block",
            Self::InvalidInput => "invalid input",
            Self::DirectoryNotEmpty => "directory not empty",
            Self::ReadOnlyFilesystem => "read-only filesystem",
            Self::ResourceBusy => "resource busy",
            Self::CrossesDevices => "crosses devices",
            Self::Interrupted => "interrupted",
            Self::Unsupported => "unsupported",
            Self::NotADirectory => "not a directory",
            Self::IsADirectory => "is a directory",
            Self::StorageFull => "storage full",
            Self::Other => "other error",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct IoFailure {
    pub kind: IoKind,
    pub code: Option<i32>,
}

impl fmt::Display for IoFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "{} (os error {code})", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum Rejection {
    #[error("protected location: {area}")]
    Protected {
        location: Location,
        area: SystemReason,
    },
    #[error("{area}; only self-declared caches are eligible there (found {found})")]
    ProvenanceTooWeak {
        location: Location,
        area: AppOwned,
        found: Provenance,
    },
    #[error("intersects exclusion {exclude}")]
    Excluded {
        location: Location,
        exclude: Location,
    },
    #[error("risk tier {tier} is locked; pass --include-tier {tier}")]
    TierLocked { location: Location, tier: Tier },
    #[error("at least one cleanup root is required")]
    NoRoots,
    #[error("not a directory: {location}")]
    NotADirectory { location: Location },
    #[error("symlink or reparse point at {location}")]
    Link { location: Location },
    #[error("filesystem boundary crossed at {location} (device {from:#x} -> {to:#x})")]
    MountBoundary {
        location: Location,
        from: u64,
        to: u64,
    },
    #[error("{location} is not a path this platform can name")]
    Unnameable { location: String },
    #[error("{field} changed since discovery; candidate is stale")]
    Stale {
        location: Location,
        field: StaleField,
    },
    #[error("current name/project evidence no longer identifies a known artifact")]
    EvidenceLost { location: Location },
    #[error("artifact kind changed from {from} to {to}")]
    KindChanged {
        location: Location,
        from: Kind,
        to: Kind,
    },
    #[error("artifact provenance changed from {from} to {to}")]
    ProvenanceChanged {
        location: Location,
        from: Provenance,
        to: Provenance,
    },
    #[error("its owner still wants it ({settlement})")]
    Owned {
        location: Location,
        settlement: Settlement,
    },
    #[error("in use: {protocol} holds {lock}")]
    Busy {
        location: Location,
        lock: Location,
        protocol: Protocol,
    },
    #[error("cannot tell whether {protocol} holds {lock}")]
    LivenessUnknown {
        location: Location,
        lock: Location,
        protocol: Protocol,
    },
    #[error("{kind} has no lock storage-scout can hold while it rewrites files")]
    NoLockProtocol { location: Location, kind: Kind },
    #[error("{filesystem} cannot share blocks between files")]
    CannotShare {
        location: Location,
        filesystem: Filesystem,
    },
    #[error("duplicate candidate ID: {id}")]
    DuplicateCandidate { id: String },
    #[error("unknown or stale candidate ID: {id}")]
    UnknownCandidate { id: String },
    #[error("candidate {id} has no allocation measurement")]
    Unmeasured { id: String },
    #[error("{operation} failed on {location}: {failure}")]
    Io {
        location: Location,
        operation: FsOp,
        failure: IoFailure,
    },
}

impl Rejection {
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Protected { .. } => "protected",
            Self::ProvenanceTooWeak { .. } => "provenance-too-weak",
            Self::Excluded { .. } => "excluded",
            Self::TierLocked { .. } => "tier-locked",
            Self::NoRoots => "no-roots",
            Self::NotADirectory { .. } => "not-a-directory",
            Self::Link { .. } => "link",
            Self::MountBoundary { .. } => "mount-boundary",
            Self::Unnameable { .. } => "unnameable",
            Self::Stale { .. } => "stale",
            Self::EvidenceLost { .. } => "evidence-lost",
            Self::KindChanged { .. } => "kind-changed",
            Self::ProvenanceChanged { .. } => "provenance-changed",
            Self::Owned { .. } => "owned",
            Self::Busy { .. } => "busy",
            Self::LivenessUnknown { .. } => "liveness-unknown",
            Self::NoLockProtocol { .. } => "no-lock-protocol",
            Self::CannotShare { .. } => "cannot-share",
            Self::DuplicateCandidate { .. } => "duplicate-candidate",
            Self::UnknownCandidate { .. } => "unknown-candidate",
            Self::Unmeasured { .. } => "unmeasured",
            Self::Io { .. } => "io",
        }
    }

    #[must_use]
    pub const fn location(&self) -> Option<&Location> {
        match self {
            Self::Protected { location, .. }
            | Self::ProvenanceTooWeak { location, .. }
            | Self::Excluded { location, .. }
            | Self::TierLocked { location, .. }
            | Self::NotADirectory { location }
            | Self::Link { location }
            | Self::MountBoundary { location, .. }
            | Self::Stale { location, .. }
            | Self::EvidenceLost { location }
            | Self::KindChanged { location, .. }
            | Self::ProvenanceChanged { location, .. }
            | Self::Owned { location, .. }
            | Self::Busy { location, .. }
            | Self::LivenessUnknown { location, .. }
            | Self::NoLockProtocol { location, .. }
            | Self::CannotShare { location, .. }
            | Self::Io { location, .. } => Some(location),
            Self::NoRoots
            | Self::Unnameable { .. }
            | Self::DuplicateCandidate { .. }
            | Self::UnknownCandidate { .. }
            | Self::Unmeasured { .. } => None,
        }
    }
}
