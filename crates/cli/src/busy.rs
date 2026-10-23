use std::collections::BTreeSet;
use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use storage_scout_core::candidate::Identity;
use storage_scout_core::gate::Shape;
use storage_scout_core::location::Location;
use storage_scout_core::lock::{Liveness, Protocol};
use storage_scout_core::reject::{FsOp, Rejection};

use crate::{failure, host, platform};

const CARGO_INTERNALS: [&str; 5] = ["deps", "incremental", ".fingerprint", "build", "examples"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recognition {
    Artifacts,
    Owners,
}

#[derive(Debug, Clone)]
pub(crate) struct Lock {
    path: PathBuf,
    location: Location,
    protocol: Protocol,
}

impl Lock {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn protocol(&self) -> Protocol {
        self.protocol
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Survey {
    pub locks: Vec<Lock>,
    pub markers: Vec<PathBuf>,
}

impl Survey {
    pub(crate) fn owner(&mut self, path: PathBuf) -> Result<(), Rejection> {
        self.locks.push(Lock {
            location: host::locate(&path)?,
            path,
            protocol: Protocol::TempOwner,
        });
        Ok(())
    }

    pub(crate) fn order(&mut self) {
        self.locks.sort_by(|left, right| left.path.cmp(&right.path));
        self.locks.dedup_by(|left, right| left.path == right.path);
    }
}

pub(crate) fn survey(root: &Path) -> Result<Survey, Rejection> {
    let mut locks = Vec::new();
    let mut markers = Vec::new();
    let mut pending = vec![(root.to_path_buf(), Recognition::Artifacts)];
    while let Some((directory, recognition)) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|e| failure::io(&directory, FsOp::ReadDir, &e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| failure::io(&directory, FsOp::ReadEntry, &e))?;
        let profile = entries
            .iter()
            .any(|entry| entry.file_name() == ".fingerprint");
        let project = entries.iter().any(|entry| {
            ["Cargo.toml", "Package.swift", "gleam.toml", "package.json"]
                .iter()
                .any(|name| entry.file_name() == *name)
        });
        if swift_workspace(&directory, &entries)? {
            let path = platform::swift_lock_path(&directory)
                .map_err(|error| failure::io(&directory, FsOp::Lock, &error))?;
            locks.push(Lock {
                location: host::locate(&path)?,
                path,
                protocol: Protocol::SwiftPackage,
            });
        }
        for entry in entries {
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|e| failure::io(&path, FsOp::FileType, &e))?;
            let name = entry.file_name();
            if platform::shape(&metadata) == Shape::Directory {
                let next = if project {
                    Recognition::Artifacts
                } else if profile && CARGO_INTERNALS.iter().any(|internal| name == *internal) {
                    Recognition::Owners
                } else {
                    recognition
                };
                pending.push((path, next));
            } else if platform::shape(&metadata) == Shape::File {
                if name == crate::owners::MARKER_NAME {
                    markers.push(directory.clone());
                } else if let Some(protocol) = Protocol::of(name.as_encoded_bytes())
                    && (recognition == Recognition::Artifacts || protocol == Protocol::TempOwner)
                {
                    locks.push(Lock {
                        location: host::locate(&path)?,
                        path,
                        protocol,
                    });
                }
            }
        }
    }
    locks.sort_by(|left, right| left.path.cmp(&right.path));
    markers.sort();
    Ok(Survey { locks, markers })
}

fn swift_workspace(directory: &Path, entries: &[fs::DirEntry]) -> Result<bool, Rejection> {
    if !directory
        .file_name()
        .is_some_and(|name| name.as_encoded_bytes().eq_ignore_ascii_case(b".build"))
    {
        return Ok(false);
    }
    if entries
        .iter()
        .any(|entry| entry.file_name() == "workspace-state.json" || entry.file_name() == ".lock")
    {
        return Ok(true);
    }
    let Some(parent) = directory.parent() else {
        return Ok(false);
    };
    let manifest = parent.join("Package.swift");
    match fs::symlink_metadata(&manifest) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(failure::io(&manifest, FsOp::Metadata, &error)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockProbe {
    Held,
    Free,
    Missing,
    Unreadable,
}

pub(crate) fn owner_lock(path: &Path) -> LockProbe {
    let lock = Lock {
        path: path.to_path_buf(),
        location: match host::locate(path) {
            Ok(location) => location,
            Err(_unnameable) => return LockProbe::Unreadable,
        },
        protocol: Protocol::TempOwner,
    };
    match attempt(&lock) {
        Attempt::Vanished => LockProbe::Missing,
        Attempt::Taken(_) => LockProbe::Free,
        Attempt::Held => LockProbe::Held,
        Attempt::Unknown => LockProbe::Unreadable,
    }
}

enum Attempt {
    Vanished,
    Taken(File),
    Held,
    Unknown,
}

fn attempt(lock: &Lock) -> Attempt {
    let file = match File::open(&lock.path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return match lock.protocol.presence() {
                storage_scout_core::lock::Presence::Optional => Attempt::Vanished,
                storage_scout_core::lock::Presence::Required => Attempt::Unknown,
            };
        },
        Err(_unreadable) => return Attempt::Unknown,
    };
    match file.try_lock() {
        Ok(()) => Attempt::Taken(file),
        Err(TryLockError::WouldBlock) => Attempt::Held,
        Err(TryLockError::Error(_unlockable)) => Attempt::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Held,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Contention {
    lock: Location,
    protocol: Protocol,
    state: State,
}

impl Contention {
    fn of(lock: &Lock, state: State) -> Self {
        Self {
            lock: lock.location.clone(),
            protocol: lock.protocol,
            state,
        }
    }

    pub(crate) fn liveness(&self) -> Liveness {
        match self.state {
            State::Held => Liveness::Held {
                lock: self.lock.clone(),
                protocol: self.protocol,
            },
            State::Unknown => Liveness::Unknown {
                lock: self.lock.clone(),
                protocol: self.protocol,
            },
        }
    }

    pub(crate) fn rejection(self, location: Location) -> Rejection {
        match self.state {
            State::Held => Rejection::Busy {
                location,
                lock: self.lock,
                protocol: self.protocol,
            },
            State::Unknown => Rejection::LivenessUnknown {
                location,
                lock: self.lock,
                protocol: self.protocol,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) enum Holding<'a> {
    Free,
    Held(&'a Path),
    Unknown,
}

pub(crate) fn held(locks: &[Lock]) -> Holding<'_> {
    for lock in locks {
        match attempt(lock) {
            Attempt::Vanished | Attempt::Taken(_) => {},
            Attempt::Held => return Holding::Held(&lock.path),
            Attempt::Unknown => return Holding::Unknown,
        }
    }
    Holding::Free
}

pub(crate) fn probe(locks: &[Lock]) -> Result<(), Contention> {
    for lock in locks {
        match attempt(lock) {
            Attempt::Vanished | Attempt::Taken(_) => {},
            Attempt::Held => return Err(Contention::of(lock, State::Held)),
            Attempt::Unknown => return Err(Contention::of(lock, State::Unknown)),
        }
    }
    Ok(())
}

#[derive(Debug)]
#[must_use]
pub(crate) struct Lease {
    held: Vec<(File, Identity)>,
}

impl Lease {
    pub(crate) fn keys(&self) -> BTreeSet<Identity> {
        self.held.iter().map(|(_, identity)| *identity).collect()
    }
}

pub(crate) fn lease(locks: &[Lock]) -> Result<Lease, Contention> {
    let mut held = Vec::new();
    for lock in locks {
        match attempt(lock) {
            Attempt::Vanished => {},
            Attempt::Taken(file) => match platform::identity_of_file(&file) {
                Ok(identity) => held.push((file, identity)),
                Err(_unidentifiable) => return Err(Contention::of(lock, State::Unknown)),
            },
            Attempt::Held => return Err(Contention::of(lock, State::Held)),
            Attempt::Unknown => return Err(Contention::of(lock, State::Unknown)),
        }
    }
    Ok(Lease { held })
}
