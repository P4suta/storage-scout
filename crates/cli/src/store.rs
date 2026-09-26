use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::ffi::OsStr;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "macos")]
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use storage_scout_core::candidate::Identity;
#[cfg(target_os = "macos")]
use storage_scout_core::share::{MINIMUM, Mode, Owner, Sharing};

#[cfg(target_os = "macos")]
use crate::platform::FileFacts;

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
    #[cfg(target_os = "macos")]
    watch: PathBuf,
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
            #[cfg(target_os = "macos")]
            watch: state.join(format!("auto-{key}.watch.redb")),
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

    #[cfg(target_os = "macos")]
    pub(crate) fn watch_cache(&self) -> io::Result<WatchCache> {
        WatchCache::open(&self.watch)
    }
}

#[cfg(target_os = "macos")]
const CACHE_SCHEMA: u64 = 1;
#[cfg(target_os = "macos")]
const META: TableDefinition<'static, &str, u64> = TableDefinition::new("meta");
#[cfg(target_os = "macos")]
const ROOTS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("roots");
#[cfg(target_os = "macos")]
const FILES: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("files");
#[cfg(target_os = "macos")]
const SCHEMA_KEY: &str = "schema";
#[cfg(target_os = "macos")]
const CHECKPOINT_KEY: &str = "checkpoint";

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) struct CachedStock {
    pub root: PathBuf,
    pub identity: Identity,
    pub unreadable: usize,
    pub files: BTreeMap<Box<Path>, FileFacts>,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) struct CachedPool {
    pub checkpoint: u64,
    pub stocks: BTreeMap<PathBuf, CachedStock>,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) struct InventoryRoot {
    pub root: PathBuf,
    pub identity: Identity,
    pub unreadable: usize,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub(crate) struct InventoryChanges {
    pub cleared: Vec<PathBuf>,
    pub roots: Vec<InventoryRoot>,
    pub files: Vec<(PathBuf, Box<Path>, Option<FileFacts>)>,
}

#[cfg(target_os = "macos")]
pub(crate) struct WatchCache {
    database: Database,
}

#[cfg(target_os = "macos")]
fn cache_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{error}"))
}

#[cfg(target_os = "macos")]
fn invalid_cache() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "the watcher cache is malformed")
}

#[cfg(target_os = "macos")]
fn take<const N: usize>(bytes: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = bytes.split_at_checked(N)?;
    let word = head.first_chunk::<N>()?;
    *bytes = tail;
    Some(*word)
}

#[cfg(target_os = "macos")]
fn root_value(identity: Identity, unreadable: usize) -> io::Result<Vec<u8>> {
    let unreadable =
        u64::try_from(unreadable).map_err(|_wide| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut value = Vec::with_capacity(32);
    value.extend_from_slice(&identity.volume.to_le_bytes());
    value.extend_from_slice(&identity.file.to_le_bytes());
    value.extend_from_slice(&unreadable.to_le_bytes());
    Ok(value)
}

#[cfg(target_os = "macos")]
fn parse_root_value(mut value: &[u8]) -> Option<(Identity, usize)> {
    let volume = u64::from_le_bytes(take(&mut value)?);
    let file = u128::from_le_bytes(take(&mut value)?);
    let unreadable = match usize::try_from(u64::from_le_bytes(take(&mut value)?)) {
        Ok(unreadable) => unreadable,
        Err(_wide) => return None,
    };
    value
        .is_empty()
        .then_some((Identity { volume, file }, unreadable))
}

#[cfg(target_os = "macos")]
fn facts_value(facts: FileFacts) -> Vec<u8> {
    let mut value = Vec::with_capacity(51);
    value.extend_from_slice(&facts.identity.volume.to_le_bytes());
    value.extend_from_slice(&facts.identity.file.to_le_bytes());
    value.extend_from_slice(&facts.len.to_le_bytes());
    value.extend_from_slice(&facts.links.to_le_bytes());
    value.push(match facts.owner {
        Owner::Caller => 0,
        Owner::Other => 1,
    });
    value.push(match facts.mode {
        Mode::Plain => 0,
        Mode::Executable => 1,
    });
    match facts.sharing {
        Sharing::Unknown => {
            value.push(0);
            value.extend_from_slice(&0u64.to_le_bytes());
        },
        Sharing::Cluster(cluster) => {
            value.push(1);
            value.extend_from_slice(&cluster.to_le_bytes());
        },
    }
    value
}

#[cfg(target_os = "macos")]
fn parse_facts_value(mut value: &[u8]) -> Option<FileFacts> {
    let volume = u64::from_le_bytes(take(&mut value)?);
    let file = u128::from_le_bytes(take(&mut value)?);
    let len = u64::from_le_bytes(take(&mut value)?);
    let links = u64::from_le_bytes(take(&mut value)?);
    let owner = match take::<1>(&mut value)? {
        [0] => Owner::Caller,
        [1] => Owner::Other,
        [_] => return None,
    };
    let mode = match take::<1>(&mut value)? {
        [0] => Mode::Plain,
        [1] => Mode::Executable,
        [_] => return None,
    };
    let sharing = match (
        take::<1>(&mut value)?,
        u64::from_le_bytes(take(&mut value)?),
    ) {
        ([0], 0) => Sharing::Unknown,
        ([1], cluster) => Sharing::Cluster(cluster),
        ([_], _) => return None,
    };
    if !value.is_empty() || len < MINIMUM || links == 0 {
        return None;
    }
    Some(FileFacts {
        identity: Identity { volume, file },
        len,
        links,
        owner,
        mode,
        sharing,
    })
}

#[cfg(target_os = "macos")]
fn file_key(root: &Path, relative: &Path) -> io::Result<Vec<u8>> {
    let root = root.as_os_str().as_bytes();
    let len =
        u32::try_from(root.len()).map_err(|_wide| io::Error::from(io::ErrorKind::InvalidInput))?;
    let relative = relative.as_os_str().as_bytes();
    let mut key = Vec::with_capacity(
        4usize
            .saturating_add(root.len())
            .saturating_add(relative.len()),
    );
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(root);
    key.extend_from_slice(relative);
    Ok(key)
}

#[cfg(target_os = "macos")]
fn split_file_key(mut key: &[u8]) -> Option<(&[u8], &[u8])> {
    let root_len = match usize::try_from(u32::from_be_bytes(take(&mut key)?)) {
        Ok(root_len) => root_len,
        Err(_wide) => return None,
    };
    let (root, relative) = key.split_at_checked(root_len)?;
    (!relative.is_empty()).then_some((root, relative))
}

#[cfg(target_os = "macos")]
fn absolute(bytes: &[u8]) -> Option<PathBuf> {
    let path = Path::new(OsStr::from_bytes(bytes));
    let ordinary = path.is_absolute()
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        });
    ordinary.then(|| path.to_path_buf())
}

#[cfg(target_os = "macos")]
fn relative(bytes: &[u8]) -> Option<Box<Path>> {
    let path = Path::new(OsStr::from_bytes(bytes));
    let ordinary = !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)));
    ordinary.then(|| path.to_path_buf().into_boxed_path())
}

#[cfg(target_os = "macos")]
fn remove_all<K, V>(table: &mut redb::Table<'_, K, V>) -> io::Result<()>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    let removed = table.extract_if(|_, _| true).map_err(cache_error)?;
    for entry in removed {
        let _removed = entry.map_err(cache_error)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
impl WatchCache {
    #[expect(
        clippy::disallowed_methods,
        reason = "the watcher cache is the store's own reconstructible file"
    )]
    fn open(path: &Path) -> io::Result<Self> {
        let database = match Database::create(path) {
            Ok(database) => database,
            Err(_damaged) => {
                match fs::remove_file(path) {
                    Ok(()) => {},
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                    Err(error) => return Err(error),
                }
                Database::create(path).map_err(cache_error)?
            },
        };
        let transaction = database.begin_write().map_err(cache_error)?;
        {
            let _meta = transaction.open_table(META).map_err(cache_error)?;
            let _roots = transaction.open_table(ROOTS).map_err(cache_error)?;
            let _files = transaction.open_table(FILES).map_err(cache_error)?;
        }
        transaction.commit().map_err(cache_error)?;
        Ok(Self { database })
    }

    pub(crate) fn load(&self) -> io::Result<Option<CachedPool>> {
        let transaction = self.database.begin_read().map_err(cache_error)?;
        let meta = transaction.open_table(META).map_err(cache_error)?;
        let schema = match meta.get(SCHEMA_KEY).map_err(cache_error)? {
            Some(schema) => schema.value(),
            None => return Ok(None),
        };
        let checkpoint = match meta.get(CHECKPOINT_KEY).map_err(cache_error)? {
            Some(checkpoint) => checkpoint.value(),
            None => return Ok(None),
        };
        if schema != CACHE_SCHEMA || checkpoint == 0 || checkpoint == u64::MAX {
            return Ok(None);
        }
        let roots = transaction.open_table(ROOTS).map_err(cache_error)?;
        let mut stocks = BTreeMap::new();
        for entry in roots.iter().map_err(cache_error)? {
            let (root, value) = entry.map_err(cache_error)?;
            let root = absolute(root.value()).ok_or_else(invalid_cache)?;
            let (identity, unreadable) =
                parse_root_value(value.value()).ok_or_else(invalid_cache)?;
            if stocks
                .insert(
                    root.clone(),
                    CachedStock {
                        root,
                        identity,
                        unreadable,
                        files: BTreeMap::new(),
                    },
                )
                .is_some()
            {
                return Err(invalid_cache());
            }
        }
        let files = transaction.open_table(FILES).map_err(cache_error)?;
        for entry in files.iter().map_err(cache_error)? {
            let (key, value) = entry.map_err(cache_error)?;
            let (root, raw_relative) = split_file_key(key.value()).ok_or_else(invalid_cache)?;
            let root = absolute(root).ok_or_else(invalid_cache)?;
            let relative = relative(raw_relative).ok_or_else(invalid_cache)?;
            let facts = parse_facts_value(value.value()).ok_or_else(invalid_cache)?;
            let stock = stocks.get_mut(&root).ok_or_else(invalid_cache)?;
            if facts.identity.volume != stock.identity.volume
                || stock.files.insert(relative, facts).is_some()
            {
                return Err(invalid_cache());
            }
        }
        Ok(Some(CachedPool { checkpoint, stocks }))
    }

    pub(crate) fn commit(&self, checkpoint: u64, changes: InventoryChanges) -> io::Result<()> {
        if checkpoint == 0 || checkpoint == u64::MAX {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let transaction = self.database.begin_write().map_err(cache_error)?;
        {
            let mut roots = transaction.open_table(ROOTS).map_err(cache_error)?;
            let mut files = transaction.open_table(FILES).map_err(cache_error)?;
            for root in &changes.cleared {
                let raw = root.as_os_str().as_bytes();
                let _root_removed = roots.remove(raw).map_err(cache_error)?;
                let removed = files
                    .extract_if(|key, _| {
                        split_file_key(key).is_some_and(|(stored, _)| stored == raw)
                    })
                    .map_err(cache_error)?;
                for entry in removed {
                    let _file_removed = entry.map_err(cache_error)?;
                }
            }
            for root in changes.roots {
                let key = root.root.as_os_str().as_bytes();
                let value = root_value(root.identity, root.unreadable)?;
                let _old = roots.insert(key, value.as_slice()).map_err(cache_error)?;
            }
            for (root, relative, facts) in changes.files {
                let key = file_key(&root, &relative)?;
                match facts {
                    Some(facts) => {
                        let value = facts_value(facts);
                        let _old = files
                            .insert(key.as_slice(), value.as_slice())
                            .map_err(cache_error)?;
                    },
                    None => {
                        let _old = files.remove(key.as_slice()).map_err(cache_error)?;
                    },
                }
            }
            drop(files);
            drop(roots);
            let mut meta = transaction.open_table(META).map_err(cache_error)?;
            let schema = meta.insert(SCHEMA_KEY, CACHE_SCHEMA).map_err(cache_error)?;
            drop(schema);
            let _checkpoint = meta
                .insert(CHECKPOINT_KEY, checkpoint)
                .map_err(cache_error)?;
        }
        transaction.commit().map_err(cache_error)
    }

    pub(crate) fn invalidate(&self) -> io::Result<()> {
        let transaction = self.database.begin_write().map_err(cache_error)?;
        {
            let mut files = transaction.open_table(FILES).map_err(cache_error)?;
            remove_all(&mut files)?;
            drop(files);
            let mut roots = transaction.open_table(ROOTS).map_err(cache_error)?;
            remove_all(&mut roots)?;
            drop(roots);
            let mut meta = transaction.open_table(META).map_err(cache_error)?;
            remove_all(&mut meta)?;
        }
        transaction.commit().map_err(cache_error)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod cache_tests {
    use super::*;

    const fn facts(volume: u64, file: u128, len: u64) -> FileFacts {
        FileFacts {
            identity: Identity { volume, file },
            len,
            links: 1,
            owner: Owner::Caller,
            mode: Mode::Executable,
            sharing: Sharing::Cluster(7),
        }
    }

    #[test]
    fn watcher_cache_applies_inventory_deltas_and_invalidation() {
        let temp = testkit::tempdir("store-watch-cache");
        let base = fs::canonicalize(temp.path()).unwrap();
        let root = base.join("target");
        let identity = Identity {
            volume: 11,
            file: 12,
        };
        let cache = WatchCache::open(&base.join("watch.redb")).unwrap();
        assert!(cache.load().unwrap().is_none());

        let one = facts(identity.volume, 21, MINIMUM);
        let two = facts(identity.volume, 22, MINIMUM * 2);
        cache
            .commit(
                40,
                InventoryChanges {
                    cleared: Vec::new(),
                    roots: vec![InventoryRoot {
                        root: root.clone(),
                        identity,
                        unreadable: 3,
                    }],
                    files: vec![
                        (
                            root.clone(),
                            PathBuf::from("debug/one").into_boxed_path(),
                            Some(one),
                        ),
                        (
                            root.clone(),
                            PathBuf::from("debug/two").into_boxed_path(),
                            Some(two),
                        ),
                    ],
                },
            )
            .unwrap();
        let initial = cache.load().unwrap().unwrap();
        assert_eq!(initial.checkpoint, 40);
        let stock = &initial.stocks[&root];
        assert_eq!(stock.root, root);
        assert_eq!(stock.identity, identity);
        assert_eq!(stock.unreadable, 3);
        let saved = stock.files[Path::new("debug/one")];
        assert_eq!(saved.identity, one.identity);
        assert_eq!(saved.len, one.len);
        assert_eq!(saved.links, one.links);
        assert_eq!(saved.owner, one.owner);
        assert_eq!(saved.mode, one.mode);
        assert_eq!(saved.sharing, one.sharing);

        let three = facts(identity.volume, 23, MINIMUM * 3);
        cache
            .commit(
                41,
                InventoryChanges {
                    cleared: Vec::new(),
                    roots: Vec::new(),
                    files: vec![
                        (
                            root.clone(),
                            PathBuf::from("debug/one").into_boxed_path(),
                            None,
                        ),
                        (
                            root.clone(),
                            PathBuf::from("debug/three").into_boxed_path(),
                            Some(three),
                        ),
                    ],
                },
            )
            .unwrap();
        let updated = cache.load().unwrap().unwrap();
        assert_eq!(updated.checkpoint, 41);
        assert_eq!(
            updated.stocks[&root]
                .files
                .keys()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            [Path::new("debug/three"), Path::new("debug/two")]
        );

        cache
            .commit(
                42,
                InventoryChanges {
                    cleared: vec![root],
                    roots: Vec::new(),
                    files: Vec::new(),
                },
            )
            .unwrap();
        let cleared = cache.load().unwrap().unwrap();
        assert_eq!(cleared.checkpoint, 42);
        assert!(cleared.stocks.is_empty());
        cache.invalidate().unwrap();
        assert!(cache.load().unwrap().is_none());
        assert!(cache.commit(0, InventoryChanges::default()).is_err());
        assert!(cache.commit(u64::MAX, InventoryChanges::default()).is_err());
    }

    #[test]
    fn watcher_cache_rejects_malformed_entries_and_recovers_a_damaged_file() {
        let temp = testkit::tempdir("store-watch-cache-malformed");
        let base = fs::canonicalize(temp.path()).unwrap();
        let root = base.join("target");
        let identity = Identity {
            volume: 31,
            file: 32,
        };
        let path = base.join("watch.redb");
        let cache = WatchCache::open(&path).unwrap();
        cache
            .commit(
                50,
                InventoryChanges {
                    cleared: Vec::new(),
                    roots: vec![InventoryRoot {
                        root: root.clone(),
                        identity,
                        unreadable: 0,
                    }],
                    files: Vec::new(),
                },
            )
            .unwrap();
        let transaction = cache.database.begin_write().unwrap();
        {
            let mut files = transaction.open_table(FILES).unwrap();
            let key = file_key(&root, Path::new("../outside")).unwrap();
            let value = facts_value(facts(identity.volume, 33, MINIMUM));
            let _old = files.insert(key.as_slice(), value.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
        assert_eq!(cache.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        cache.invalidate().unwrap();
        assert!(cache.load().unwrap().is_none());
        drop(cache);

        testkit::write_bytes(&path, b"not a redb database");
        let recovered = WatchCache::open(&path).unwrap();
        assert!(recovered.load().unwrap().is_none());
        assert!(absolute(b"relative").is_none());
        assert!(absolute(b"/work/../outside").is_none());
        assert!(relative(b"../outside").is_none());
        assert!(parse_root_value(&[0; 31]).is_none());
        assert!(parse_facts_value(&[0; 50]).is_none());
        let mut no_links = facts_value(facts(identity.volume, 34, MINIMUM));
        no_links[32..40].copy_from_slice(&0u64.to_le_bytes());
        assert!(parse_facts_value(&no_links).is_none());
    }
}
