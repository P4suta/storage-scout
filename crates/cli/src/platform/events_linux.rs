#![expect(unsafe_code, reason = "inotify is reached through its system calls")]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{Change, Coverage, Event};

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

fn field(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    bytes.get(at..)?.first_chunk::<4>().copied()
}

const VANISHED: u32 = libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_IGNORED;
const APPEARED: u32 = libc::IN_CREATE | libc::IN_MOVED_TO;

const fn event(mask: u32) -> Event {
    if mask & VANISHED != 0 {
        Event::Vanished
    } else if mask & APPEARED != 0 {
        Event::Appeared
    } else if mask & libc::IN_CLOSE_WRITE != 0 {
        Event::Written
    } else {
        Event::Unsure
    }
}

fn dispatch(bytes: &[u8], watches: &Watches, deliver: &Deliver) {
    let mut at = 0usize;
    while let (Some(wd), Some(mask), Some(len)) = (
        field(bytes, at),
        field(bytes, at.saturating_add(4)),
        field(bytes, at.saturating_add(12)),
    ) {
        let (wd, mask) = (i32::from_ne_bytes(wd), u32::from_ne_bytes(mask));
        let Ok(len) = usize::try_from(u32::from_ne_bytes(len)) else {
            return;
        };
        let start = at.saturating_add(HEADER);
        let Some(name) = start.checked_add(len).and_then(|end| bytes.get(start..end)) else {
            return;
        };
        at = start.saturating_add(len);
        if mask & libc::IN_Q_OVERFLOW != 0 {
            deliver(Change::Lost);
            continue;
        }
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
            let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
            let path = if name.is_empty() {
                directory
            } else {
                directory.join(OsStr::from_bytes(name))
            };
            deliver(Change::Entry {
                path,
                event: event(mask),
            });
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
                        Ok(read) => {
                            if let Some((events, _)) = buffer.split_at_checked(read) {
                                dispatch(events, &watches, &deliver);
                            }
                        },
                    }
                }
            })?;
        Ok(source)
    }

    pub(super) fn watch(&self, directories: &[&Path]) -> io::Result<Coverage> {
        let mut coverage = Coverage::Complete;
        for directory in directories {
            let name = super::imp::c_path(directory.as_os_str().as_bytes())?;
            // SAFETY: the descriptor is an inotify instance and `name` is NUL-terminated.
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), MASK) };
            if wd == -1 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES) => continue,
                    Some(libc::ENOSPC) => {
                        coverage = Coverage::Partial;
                        continue;
                    },
                    Some(_) | None => return Err(error),
                }
            }
            let mut known = match self.watches.lock() {
                Ok(known) => known,
                Err(poisoned) => poisoned.into_inner(),
            };
            known.insert(wd, directory.to_path_buf());
        }
        Ok(coverage)
    }
}

pub(super) fn background() {
    // SAFETY: gettid takes no arguments and cannot fail.
    let thread = unsafe { libc::gettid() };
    if let Ok(thread) = u32::try_from(thread) {
        // SAFETY: a thread may lower its own priority without privilege.
        let _lowered = unsafe { libc::setpriority(libc::PRIO_PROCESS, thread, 19) };
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn raw(wd: i32, mask: u32, name: &[u8]) -> Vec<u8> {
        let padded = name.len().next_multiple_of(4);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&wd.to_ne_bytes());
        bytes.extend_from_slice(&mask.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&u32::try_from(padded).unwrap().to_ne_bytes());
        bytes.extend_from_slice(name);
        bytes.extend(std::iter::repeat_n(0, padded.saturating_sub(name.len())));
        bytes
    }

    fn collect(bytes: &[u8], watches: &Watches) -> Vec<Change> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let deliver: Deliver = Box::new(move |change| sink.lock().unwrap().push(change));
        dispatch(bytes, watches, &deliver);
        seen.lock().unwrap().clone()
    }

    fn entry(path: &str, event: Event) -> Change {
        Change::Entry {
            path: PathBuf::from(path),
            event,
        }
    }

    #[test]
    fn each_event_names_the_entry_and_what_happened_to_it() {
        let watches: Watches = Arc::new(Mutex::new(BTreeMap::from([
            (1, PathBuf::from("/w/deps")),
            (2, PathBuf::from("/w/incremental")),
        ])));
        let bytes = [
            raw(9, libc::IN_CREATE, b"unknown"),
            raw(1, libc::IN_CLOSE_WRITE, b"libx.rlib"),
            raw(1, libc::IN_CREATE, b"liby.rlib"),
            raw(1, libc::IN_MOVED_TO, b"libz.rlib"),
            raw(1, libc::IN_DELETE, b"libx.rlib"),
            raw(1, libc::IN_MOVED_FROM, b"liby.rlib"),
            raw(2, libc::IN_CREATE | libc::IN_ISDIR, b"app-1"),
            raw(2, libc::IN_DELETE_SELF, b""),
            raw(2, libc::IN_ATTRIB, b"app-1"),
        ]
        .concat();
        assert_eq!(
            collect(&bytes, &watches),
            vec![
                entry("/w/deps/libx.rlib", Event::Written),
                entry("/w/deps/liby.rlib", Event::Appeared),
                entry("/w/deps/libz.rlib", Event::Appeared),
                entry("/w/deps/libx.rlib", Event::Vanished),
                entry("/w/deps/liby.rlib", Event::Vanished),
                entry("/w/incremental/app-1", Event::Appeared),
                entry("/w/incremental", Event::Vanished),
                entry("/w/incremental/app-1", Event::Unsure),
            ]
        );
        let first = raw(1, libc::IN_CLOSE_WRITE, b"libx.rlib");
        assert_eq!(collect(&first[..20], &watches), vec![]);
    }

    #[test]
    fn an_overflow_is_a_lost_stream_and_a_dropped_watch_is_forgotten() {
        let watches: Watches = Arc::new(Mutex::new(BTreeMap::from([(1, PathBuf::from("/w"))])));
        let overflowed = [
            raw(-1, libc::IN_Q_OVERFLOW, b""),
            raw(1, libc::IN_CREATE, b"after"),
        ]
        .concat();
        assert_eq!(
            collect(&overflowed, &watches),
            vec![Change::Lost, entry("/w/after", Event::Appeared)]
        );
        let gone = [
            raw(1, libc::IN_IGNORED, b""),
            raw(1, libc::IN_CREATE, b"late"),
        ]
        .concat();
        assert_eq!(collect(&gone, &watches), vec![entry("/w", Event::Vanished)]);
        assert!(watches.lock().unwrap().is_empty());
    }

    #[test]
    fn a_directory_that_cannot_be_watched_is_passed_over() {
        let temp = testkit::tempdir("events-linux-watch");
        let there = temp.path().join("there");
        testkit::write_sized(&there.join("file"), 1);
        let missing = temp.path().join("missing");
        let source = Source::start(&[], Box::new(|_| {})).unwrap();
        source
            .watch(&[there.as_path(), missing.as_path(), temp.path()])
            .unwrap();
        let watched = source
            .watches
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(watched, vec![there, temp.path().to_path_buf()]);
    }
}
