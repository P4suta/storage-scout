use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

const GLOBAL_REQUEST: &[u8] = b"\0";

#[expect(
    clippy::disallowed_methods,
    reason = "the store is the one module that writes files storage-scout owns"
)]
pub(crate) fn append(path: &Path) -> io::Result<File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

pub(crate) fn append_line(path: &Path, document: &impl Serialize) -> io::Result<()> {
    let mut file = append(path)?;
    serde_json::to_writer(&mut file, document).map_err(io::Error::other)?;
    writeln!(file)
}

pub(crate) fn state_dir() -> io::Result<PathBuf> {
    let base = match std::env::var_os("STORAGE_SCOUT_STATE_DIR") {
        Some(explicit) if !explicit.is_empty() => PathBuf::from(explicit),
        Some(_) | None => match std::env::var_os("XDG_STATE_HOME") {
            Some(state) if !state.is_empty() => PathBuf::from(state).join("storage-scout"),
            Some(_) | None => crate::host::home()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
                .join(".local/state/storage-scout"),
        },
    };
    create(&base)?;
    Ok(base)
}

#[expect(
    clippy::disallowed_methods,
    reason = "the store is the one module that creates directories storage-scout owns"
)]
fn create(directory: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)
}

#[derive(Debug, Clone)]
pub(crate) struct Station {
    lock: PathBuf,
    requests: PathBuf,
    signal: PathBuf,
    flag: PathBuf,
    last: PathBuf,
    notification: String,
}

#[derive(Debug)]
pub(crate) struct Held {
    _lock: File,
}

impl Station {
    pub(crate) fn for_policy(state: &Path, policy: &Path) -> Self {
        let digest = Sha256::digest(policy.as_os_str().as_encoded_bytes());
        let key = digest.iter().take(8).fold(String::new(), |mut key, byte| {
            let _written = write!(key, "{byte:02x}");
            key
        });
        let signal = state.join(format!("auto-{key}.signal"));
        Self {
            lock: state.join(format!("auto-{key}.lock")),
            requests: state.join(format!("auto-{key}.requests.lock")),
            flag: signal.join("pending"),
            signal,
            last: state.join(format!("auto-{key}.last.json")),
            notification: format!("Local\\storage-scout-{key}"),
        }
    }

    pub(crate) fn notification(&self) -> &str {
        &self.notification
    }

    pub(crate) fn signal(&self) -> io::Result<PathBuf> {
        create(&self.signal)?;
        Ok(self.signal.clone())
    }

    pub(crate) fn raise(&self) -> io::Result<()> {
        self.raise_for(None)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the store is the one module that writes files storage-scout owns"
    )]
    fn raise_from(&self, repository: Option<&Path>) -> io::Result<()> {
        {
            let _held = self.serialize_requests()?;
            create(&self.signal)?;
            let mut flag = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.flag)?;
            let mut line = match repository {
                Some(repository) => repository.as_os_str().as_encoded_bytes().to_vec(),
                None => GLOBAL_REQUEST.to_vec(),
            };
            let written = {
                line.push(b'\n');
                flag.write_all(&line)
            };
            drop(flag);
            written?;
        }
        crate::platform::wake(&self.notification)
    }

    pub(crate) fn raise_for(&self, repository: Option<&Path>) -> io::Result<()> {
        self.raise_from(repository)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the pending flag is the store's own file"
    )]
    pub(crate) fn take(&self) -> io::Result<Option<BTreeSet<PathBuf>>> {
        let _held = self.serialize_requests()?;
        let taken = self.flag.with_extension("taken");
        match fs::rename(&self.flag, &taken) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
        let bytes = fs::read(&taken)?;
        fs::remove_file(&taken)?;
        let named = if bytes
            .split(|byte| *byte == b'\n')
            .any(|line| line == GLOBAL_REQUEST)
        {
            Some(BTreeSet::new())
        } else {
            bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| match std::str::from_utf8(line) {
                    Ok(text) => Some(PathBuf::from(text)),
                    Err(_foreign) => None,
                })
                .collect::<Option<BTreeSet<_>>>()
        };
        Ok(Some(named.unwrap_or_default()))
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the pending flag is the store's own file"
    )]
    pub(crate) fn lower(&self) -> io::Result<bool> {
        let _held = self.serialize_requests()?;
        match fs::remove_file(&self.flag) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn raised(&self) -> io::Result<bool> {
        let _held = self.serialize_requests()?;
        match fs::symlink_metadata(&self.flag) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the run lock is the store's own file"
    )]
    pub(crate) fn hold(&self) -> io::Result<Option<Held>> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Held { _lock: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the run station is the one module that creates its request lock"
    )]
    fn serialize_requests(&self) -> io::Result<Held> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.requests)?;
        file.lock()?;
        Ok(Held { _lock: file })
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the run lock is the store's own file"
    )]
    pub(crate) fn wait(&self) -> io::Result<Held> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock)?;
        file.lock()?;
        Ok(Held { _lock: file })
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the last run record is the store's own file"
    )]
    pub(crate) fn record(&self, document: &impl Serialize) -> io::Result<()> {
        let text = serde_json::to_vec_pretty(document).map_err(io::Error::other)?;
        let staged = self.last.with_extension("json.staged");
        fs::write(&staged, text)?;
        fs::rename(&staged, &self.last)
    }
}
