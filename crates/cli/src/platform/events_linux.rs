#![expect(unsafe_code, reason = "inotify is reached through its system calls")]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::Change;

type Deliver = Box<dyn Fn(Change) + Send + Sync>;
type Watches = Arc<Mutex<BTreeMap<i32, PathBuf>>>;

const MASK: u32 = libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_CLOSE_WRITE
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_ONLYDIR
    | libc::IN_DONT_FOLLOW
    | libc::IN_EXCL_UNLINK;
const HEADER: usize = 16;
const BUFFER: usize = 64 * 1024;

fn field(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    match bytes.get(at..end) {
        Some(&[a, b, c, d]) => Some(u32::from_ne_bytes([a, b, c, d])),
        Some(_) | None => None,
    }
}

fn dispatch(bytes: &[u8], watches: &Watches, deliver: &Deliver) {
    let mut at = 0usize;
    while let (Some(wd), Some(mask), Some(len)) = (
        field(bytes, at),
        field(bytes, at.saturating_add(4)),
        field(bytes, at.saturating_add(12)),
    ) {
        let Ok(len) = usize::try_from(len) else {
            return;
        };
        let Some(next) = at
            .checked_add(HEADER)
            .and_then(|start| start.checked_add(len))
        else {
            return;
        };
        at = next;
        if mask & libc::IN_Q_OVERFLOW != 0 {
            deliver(Change::Lost);
            continue;
        }
        let Ok(wd) = i32::try_from(wd) else {
            continue;
        };
        let mut known = match watches.lock() {
            Ok(known) => known,
            Err(poisoned) => poisoned.into_inner(),
        };
        let directory = if mask & libc::IN_IGNORED != 0 {
            known.remove(&wd)
        } else {
            known.get(&wd).cloned()
        };
        drop(known);
        if let Some(directory) = directory {
            deliver(Change::Directory(directory));
        }
    }
}

pub(super) struct Source {
    fd: Arc<OwnedFd>,
    watches: Watches,
}

impl Source {
    #[expect(
        clippy::unused_self,
        reason = "each directory is watched on its own here"
    )]
    pub(super) const fn recursive(&self) -> bool {
        false
    }

    pub(super) fn start(paths: &[PathBuf], deliver: Deliver) -> io::Result<Self> {
        // SAFETY: `inotify_init1` takes only flags.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `inotify_init1` just returned this descriptor and nothing else owns it.
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let source = Self {
            fd,
            watches: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let roots = paths.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        source.watch(&roots)?;
        let reader = source.fd.try_clone()?;
        let watches = Arc::clone(&source.watches);
        std::thread::Builder::new()
            .name("storage-scout-events".to_owned())
            .spawn(move || {
                let mut file = File::from(reader);
                let mut buffer = vec![0u8; BUFFER];
                loop {
                    match file.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => dispatch(buffer.get(..read).unwrap_or(&[]), &watches, &deliver),
                    }
                }
            })?;
        Ok(source)
    }

    pub(super) fn watch(&self, directories: &[&Path]) -> io::Result<()> {
        for directory in directories {
            let name = super::imp::c_path(directory.as_os_str().as_bytes())?;
            // SAFETY: the descriptor is an inotify instance and `name` is NUL-terminated.
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), MASK) };
            if wd == -1 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES) => continue,
                    Some(_) | None => return Err(error),
                }
            }
            let mut known = match self.watches.lock() {
                Ok(known) => known,
                Err(poisoned) => poisoned.into_inner(),
            };
            known.insert(wd, directory.to_path_buf());
        }
        Ok(())
    }
}
