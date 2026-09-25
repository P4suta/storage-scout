use std::collections::BTreeSet;
use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use storage_scout_core::candidate::Identity;
use storage_scout_core::location::Location;
use storage_scout_core::lock::{Liveness, Protocol};
use storage_scout_core::reject::{FsOp, Rejection};

use crate::{failure, host, platform};

const CARGO_INTERNALS: [&str; 5] = ["deps", "incremental", ".fingerprint", "build", "examples"];

#[derive(Debug, Clone)]
pub(crate) struct Lock {
    path: PathBuf,
    location: Location,
    protocol: Protocol,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Survey {
    pub locks: Vec<Lock>,
    pub markers: Vec<PathBuf>,
}

pub(crate) fn survey(root: &Path) -> Result<Survey, Rejection> {
    let mut locks = Vec::new();
    let mut markers = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|e| failure::io(&directory, FsOp::ReadDir, &e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| failure::io(&directory, FsOp::ReadEntry, &e))?;
        let profile = entries
            .iter()
            .any(|entry| entry.file_name() == ".fingerprint");
        for entry in entries {
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| failure::io(&path, FsOp::FileType, &e))?;
            let name = entry.file_name();
            if kind.is_dir() {
                let internal = CARGO_INTERNALS
                    .iter()
                    .any(|skip| name.as_encoded_bytes() == skip.as_bytes());
                if !(profile && internal) {
                    pending.push(path);
                }
            } else if kind.is_file() {
                if name == crate::owners::MARKER_NAME {
                    markers.push(directory.clone());
                } else if let Some(protocol) = Protocol::of(name.as_encoded_bytes()) {
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
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Attempt::Vanished,
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
