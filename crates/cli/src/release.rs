use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

use serde::Serialize;
use sha2::{Digest, Sha256};
use storage_scout_core::candidate::Identity;
use storage_scout_core::gate::Shape;
use storage_scout_core::location::Location;
use storage_scout_core::ownership::{
    OwnerLock, RELEASE_RECORD_BYTES, ReleaseEvidence, ReleaseRecord,
};

use crate::{SCHEMA_VERSION, busy, host, ingress, platform, store};

const READ_BLOCK: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseReceipt {
    pub schema_version: u32,
    pub command: &'static str,
    pub location: Location,
    pub monitor_pid: u32,
}

struct Snapshot {
    record: ReleaseRecord,
    directories: Vec<PathBuf>,
}

fn hash_file(path: &Path, hash: &mut Sha256) -> io::Result<()> {
    let mut file = platform::open_regular(path)?;
    let mut bytes = vec![0; READ_BLOCK];
    loop {
        let read = file.read(&mut bytes)?;
        if read == 0 {
            return Ok(());
        }
        hash.update(
            bytes
                .get(..read)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?,
        );
    }
}

fn snapshot(root: &Path) -> io::Result<Snapshot> {
    let identity = platform::identity(root)?;
    let mut hash = Sha256::new();
    let mut directories = Vec::new();
    let mut links: BTreeMap<Identity, (u32, u32)> = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let id = platform::identity(&directory)?;
        if id.volume != identity.volume {
            return Err(io::Error::other("a checkout crosses a filesystem boundary"));
        }
        hash.update(id.file.to_le_bytes());
        directories.push(directory.clone());
        let mut entries = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(io::Error::other)?;
            hash.update(relative.as_os_str().as_encoded_bytes());
            hash.update([0]);
            let metadata = fs::symlink_metadata(&path)?;
            match platform::shape(&metadata) {
                Shape::Directory => {
                    hash.update(b"directory\0");
                    pending.push(path);
                },
                Shape::Link => {
                    hash.update(b"link\0");
                    hash.update(fs::read_link(&path)?.as_os_str().as_encoded_bytes());
                },
                Shape::File => {
                    let measured = platform::file_measure(&path)?;
                    hash.update(b"file\0");
                    hash.update(measured.identity.file.to_le_bytes());
                    hash.update(metadata.len().to_le_bytes());
                    hash.update([u8::from(metadata.permissions().readonly())]);
                    hash_file(&path, &mut hash)?;
                    links
                        .entry(measured.identity)
                        .and_modify(|stock| {
                            stock.0 = stock.0.max(measured.links);
                            stock.1 = stock.1.saturating_add(1);
                        })
                        .or_insert((measured.links, 1));
                },
                Shape::Other => {
                    return Err(io::Error::other(
                        "a checkout contains an unsupported filesystem entry",
                    ));
                },
            }
        }
    }
    if links.values().any(|(expected, seen)| seen < expected) {
        return Err(io::Error::other(
            "a checkout has hard links outside its monitored tree",
        ));
    }
    Ok(Snapshot {
        record: ReleaseRecord {
            identity,
            digest: hash.finalize().into(),
        },
        directories,
    })
}

fn writers(root: &Path) -> OwnerLock {
    match busy::survey(root) {
        Ok(survey) => match busy::probe(&survey.locks) {
            Ok(()) => OwnerLock::Free,
            Err(_) => OwnerLock::Held,
        },
        Err(_) => OwnerLock::Unreadable,
    }
}

fn bounded(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    match File::open(path).and_then(|file| file.take(limit).read_to_end(&mut bytes)) {
        Ok(_) => Some(bytes),
        Err(_) => None,
    }
}

pub(crate) fn evidence(root: &Path, state: &Path) -> Option<ReleaseEvidence> {
    const ENDPOINT_LIMIT: u64 = 8193;
    let record_limit = match u64::try_from(RELEASE_RECORD_BYTES) {
        Ok(length) => length.saturating_add(1),
        Err(_) => return None,
    };
    let (record_path, lock_path, endpoint) = store::release_paths(state, root);
    if busy::owner_lock(&lock_path) != busy::LockProbe::Held {
        return None;
    }
    let record = ingress::release(&bounded(&record_path, record_limit)?)?;
    let endpoint = ingress::release_endpoint(&bounded(&endpoint, ENDPOINT_LIMIT)?)?;
    let reply = match platform::release_socket::query(&endpoint) {
        Ok(reply) => reply,
        Err(_) => return None,
    };
    let observed = ingress::release(&reply)?;
    if busy::owner_lock(&lock_path) != busy::LockProbe::Held {
        return None;
    }
    Some(witness(record, observed, writers(root)))
}

const fn witness(
    record: ReleaseRecord,
    observed: ReleaseRecord,
    writers: OwnerLock,
) -> ReleaseEvidence {
    ReleaseEvidence {
        recorded_identity: record.identity,
        identity: observed.identity,
        recorded_digest: record.digest,
        digest: observed.digest,
        monitor: OwnerLock::Held,
        writers,
    }
}

#[derive(Debug)]
enum Phase {
    Preparing,
    Released,
    Revoked,
}

#[derive(Debug)]
struct LeaseState {
    phase: Phase,
    record: store::ReleaseFile,
}

impl LeaseState {
    fn revoke(&mut self) -> io::Result<()> {
        self.phase = Phase::Revoked;
        self.record.invalidate()
    }
}

#[derive(Debug)]
#[must_use]
pub struct CheckoutRelease {
    worker: Option<std::thread::JoinHandle<io::Result<()>>>,
    wake: platform::release_socket::Wake,
    state: Arc<Mutex<LeaseState>>,
    receipt: ReleaseReceipt,
}

fn joined(worker: std::thread::JoinHandle<io::Result<()>>) -> io::Result<()> {
    match worker.join() {
        Ok(result) => result,
        Err(_) => Err(io::Error::other("the checkout release monitor failed")),
    }
}

impl CheckoutRelease {
    #[must_use]
    pub const fn receipt(&self) -> &ReleaseReceipt {
        &self.receipt
    }

    pub fn wait(mut self) -> io::Result<()> {
        match self.worker.take() {
            Some(worker) => joined(worker),
            None => Ok(()),
        }
    }
}

impl Drop for CheckoutRelease {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            if let Ok(mut state) = self.state.lock() {
                let _revoked = state.revoke();
            }
            let _stopped = self.wake.send();
            let _joined = joined(worker);
        }
    }
}

const fn source_change(change: &platform::Change) -> bool {
    match change {
        platform::Change::Entry { .. } | platform::Change::Lost => true,
        platform::Change::Wake => false,
        #[cfg(target_os = "macos")]
        platform::Change::Checkpoint(_) => false,
    }
}

fn prepare(
    root: &Path,
    state_dir: &Path,
    endpoint: &Path,
    wake: platform::release_socket::Wake,
) -> io::Result<(platform::Watcher, Arc<Mutex<LeaseState>>, ReleaseRecord)> {
    if writers(root) != OwnerLock::Free {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    let lease = Arc::new(Mutex::new(LeaseState {
        phase: Phase::Preparing,
        record: store::ReleaseFile::begin(state_dir, root)?,
    }));
    let callback = Arc::clone(&lease);
    let watcher = platform::Watcher::release(&[root.to_path_buf()], move |change| {
        if source_change(&change) {
            if let Ok(mut locked) = callback.lock() {
                match locked.phase {
                    Phase::Preparing | Phase::Revoked => return,
                    Phase::Released => {
                        let _revoked = locked.revoke();
                    },
                }
            }
            let _stopped = wake.send();
        }
    })?;
    let before = snapshot(root)?;
    let paths = before
        .directories
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    if watcher.watch(&paths)? != platform::Coverage::Complete {
        return Err(io::Error::other(
            "release requires complete filesystem event coverage",
        ));
    }
    watcher.barrier()?;
    let after = snapshot(root)?;
    {
        let mut locked = lease
            .lock()
            .map_err(|_poisoned| io::Error::other("the release monitor lost its state"))?;
        if before.record != after.record {
            return Err(io::Error::other(
                "the checkout changed while recording its release",
            ));
        }
        if writers(root) != OwnerLock::Free {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        locked.record.record(after.record, endpoint)?;
        locked.phase = Phase::Released;
    }
    Ok((watcher, lease, after.record))
}

fn serve(
    listener: &platform::release_socket::Listener,
    root: &Path,
    watcher: &platform::Watcher,
    state: &Mutex<LeaseState>,
    recorded: ReleaseRecord,
) -> io::Result<()> {
    loop {
        let Some(peer) = listener.accept()? else {
            return Ok(());
        };
        {
            let state = state
                .lock()
                .map_err(|_poisoned| io::Error::other("the release monitor lost its state"))?;
            if !matches!(state.phase, Phase::Released) {
                return Ok(());
            }
        }
        let request = match peer.request() {
            Ok(Some(byte)) => ingress::release_request(byte),
            Ok(None) => return Ok(()),
            Err(_) => continue,
        };
        match request {
            None => continue,
            Some(ingress::ReleaseRequest::Stop) => return Ok(()),
            Some(ingress::ReleaseRequest::Check) => {},
        }
        watcher.barrier()?;
        let current = snapshot(root)?.record;
        let evidence = witness(recorded, current, writers(root));
        let mut state = state
            .lock()
            .map_err(|_poisoned| io::Error::other("the release monitor lost its state"))?;
        if !matches!(state.phase, Phase::Released) {
            return Ok(());
        }
        if recorded != current {
            state.revoke()?;
            drop(state);
            return Ok(());
        }
        if evidence.settlement() == storage_scout_core::ownership::Settlement::Released {
            let _replied = peer.reply(&recorded.encode());
        }
        drop(state);
    }
}

pub(crate) fn release(root: &Path, state: &Path) -> io::Result<CheckoutRelease> {
    if platform::shape(&fs::symlink_metadata(root)?) != Shape::Directory {
        return Err(io::Error::other(
            "release requires a real checkout directory",
        ));
    }
    let root = fs::canonicalize(root)?;
    if !matches!(
        platform::shape(&fs::symlink_metadata(root.join(".git"))?),
        Shape::File | Shape::Directory
    ) {
        return Err(io::Error::other("release requires a Git checkout"));
    }
    if std::path::absolute(state)?.starts_with(&root) {
        return Err(io::Error::other(
            "release records must live outside the checkout",
        ));
    }
    let location = host::locate(&root).map_err(io::Error::other)?;
    let state = state.to_path_buf();
    let (ready, receive) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("storage-scout-release".into())
        .spawn(move || {
            let listener = platform::release_socket::Listener::bind(&state)?;
            let wake = listener.waker();
            let (watcher, lease, record) =
                prepare(&root, &state, &listener.endpoint(), wake.clone())?;
            ready
                .send((
                    wake,
                    Arc::clone(&lease),
                    ReleaseReceipt {
                        schema_version: SCHEMA_VERSION,
                        command: "release",
                        location,
                        monitor_pid: std::process::id(),
                    },
                ))
                .map_err(io::Error::other)?;
            serve(&listener, &root, &watcher, &lease, record)
        })?;
    let (wake, lease, receipt) = match receive.recv() {
        Ok(receipt) => receipt,
        Err(_) => {
            joined(worker)?;
            return Err(io::Error::other(
                "the monitor stopped before recording the release",
            ));
        },
    };
    Ok(CheckoutRelease {
        worker: Some(worker),
        wake,
        state: lease,
        receipt,
    })
}

pub(crate) fn detached(checkout: &Path) -> io::Result<ReleaseReceipt> {
    let root = fs::canonicalize(checkout)?;
    let pid = platform::spawn::release_monitor(
        &std::env::current_exe()?,
        &root,
        &std::env::current_dir()?,
    )?;
    Ok(ReleaseReceipt {
        schema_version: SCHEMA_VERSION,
        command: "release",
        location: host::locate(&root).map_err(io::Error::other)?,
        monitor_pid: pid,
    })
}
