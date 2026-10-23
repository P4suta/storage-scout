#![expect(unsafe_code, reason = "inotify is reached through its system calls")]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{Change, Coverage, Event, WatchDepth};

type Deliver = Box<dyn Fn(Change) + Send + Sync>;
type Watches = Arc<Mutex<BTreeMap<i32, PathBuf>>>;

const MASK: u32 = libc::IN_CREATE
    | libc::IN_MODIFY
    | libc::IN_ATTRIB
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
const EVENT_WORD_BYTES: usize = size_of::<u32>();
const MASK_OFFSET: usize = EVENT_WORD_BYTES;
const LENGTH_OFFSET: usize = 3 * EVENT_WORD_BYTES;
const LOWEST_PRIORITY: libc::c_int = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchFailure {
    Ignore,
    Partial,
    Return,
}

const fn watch_failure(code: Option<i32>) -> WatchFailure {
    match code {
        Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES) => WatchFailure::Ignore,
        Some(libc::ENOSPC) => WatchFailure::Partial,
        Some(_) | None => WatchFailure::Return,
    }
}

fn field(bytes: &[u8], at: usize) -> Option<[u8; EVENT_WORD_BYTES]> {
    bytes.get(at..)?.first_chunk::<EVENT_WORD_BYTES>().copied()
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
    } else if mask & (libc::IN_CLOSE_WRITE | libc::IN_MODIFY) != 0 {
        Event::Written
    } else {
        Event::Unsure
    }
}

fn dispatch(bytes: &[u8], watches: &Watches, deliver: &Deliver) {
    let mut at = 0usize;
    while let (Some(wd), Some(mask), Some(len)) = (
        field(bytes, at),
        field(bytes, at.saturating_add(MASK_OFFSET)),
        field(bytes, at.saturating_add(LENGTH_OFFSET)),
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
            let path = directory.join(OsStr::from_bytes(name));
            deliver(Change::Entry {
                path,
                event: event(mask),
            });
        }
    }
}

enum Control {
    Flush(std::sync::mpsc::SyncSender<io::Result<()>>),
    Stop,
}

pub(super) struct Source {
    fd: Arc<OwnedFd>,
    signal: Arc<OwnedFd>,
    watches: Watches,
    control: std::sync::mpsc::Sender<Control>,
    worker: Option<std::thread::JoinHandle<()>>,
}

fn notify(signal: &OwnedFd) -> io::Result<()> {
    let word = 1u64.to_ne_bytes();
    // SAFETY: the descriptor is an eventfd and the buffer contains one valid eventfd counter.
    let written = unsafe { libc::write(signal.as_raw_fd(), word.as_ptr().cast(), word.len()) };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn drain(file: &mut File, watches: &Watches, deliver: &Deliver) -> io::Result<()> {
    let mut buffer = vec![0; BUFFER];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            Ok(read) => {
                if let Some((bytes, _)) = buffer.split_at_checked(read) {
                    dispatch(bytes, watches, deliver);
                }
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            Err(error) => return Err(error),
        }
    }
}

fn drive(
    mut file: File,
    mut signal: File,
    watches: &Watches,
    commands: &std::sync::mpsc::Receiver<Control>,
    deliver: &Deliver,
) -> io::Result<()> {
    const POLL_FILES: libc::nfds_t = 2;
    let mut descriptors = [
        libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: signal.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: both pollfd entries hold live descriptors and poll may write their revents fields.
        if unsafe { libc::poll(descriptors.as_mut_ptr(), POLL_FILES, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptors
            .first()
            .is_some_and(|fd| fd.revents & libc::POLLIN != 0)
        {
            drain(&mut file, watches, deliver)?;
        }
        if descriptors
            .get(1)
            .is_some_and(|fd| fd.revents & libc::POLLIN != 0)
        {
            signal.read_exact(&mut [0; size_of::<u64>()])?;
            for command in commands.try_iter() {
                match command {
                    Control::Stop => return Ok(()),
                    Control::Flush(reply) => {
                        let _sent = reply.send(drain(&mut file, watches, deliver));
                    },
                }
            }
        }
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _sent = self.control.send(Control::Stop);
            let _notified = notify(&self.signal);
            let _joined = worker.join();
        }
    }
}

impl Source {
    pub(super) fn start_release(paths: &[PathBuf], deliver: Deliver) -> io::Result<Self> {
        for path in paths {
            local_events(path)?;
        }
        Self::start(paths, "", None, deliver)
    }

    pub(super) fn barrier(&self) -> io::Result<()> {
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        self.control
            .send(Control::Flush(reply))
            .map_err(io::Error::other)?;
        notify(&self.signal)?;
        result.recv().map_err(io::Error::other)?
    }

    #[expect(
        clippy::unused_self,
        reason = "each directory is watched on its own here"
    )]
    pub(super) const fn depth(&self) -> WatchDepth {
        WatchDepth::Named
    }

    pub(super) fn start(
        paths: &[PathBuf],
        _notification: &str,
        _checkpoint: Option<u64>,
        deliver: Deliver,
    ) -> io::Result<Self> {
        // SAFETY: inotify_init1 takes only flags.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful inotify_init1 call returned this uniquely owned descriptor.
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        // SAFETY: eventfd takes an initial counter and valid descriptor flags.
        let raw_signal = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if raw_signal == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful eventfd call returned this uniquely owned descriptor.
        let signal = Arc::new(unsafe { OwnedFd::from_raw_fd(raw_signal) });
        let (control, commands) = std::sync::mpsc::channel();
        let mut source = Self {
            fd,
            signal,
            control,
            watches: Arc::new(Mutex::new(BTreeMap::new())),
            worker: None,
        };
        source.watch(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>())?;
        let file = File::from(source.fd.try_clone()?);
        let signal_reader = File::from(source.signal.try_clone()?);
        let watches = Arc::clone(&source.watches);
        source.worker = Some(
            std::thread::Builder::new()
                .name("storage-scout-events".to_owned())
                .spawn(move || {
                    if drive(file, signal_reader, &watches, &commands, &deliver).is_err() {
                        deliver(Change::Lost);
                    }
                })?,
        );
        Ok(source)
    }

    pub(super) fn watch(&self, directories: &[&Path]) -> io::Result<Coverage> {
        let mut coverage = Coverage::Complete;
        for directory in directories {
            let name = super::imp::c_path(directory.as_os_str().as_bytes())?;
            // SAFETY: the descriptor is an inotify instance and name is NUL-terminated.
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), MASK) };
            if wd == -1 {
                let error = io::Error::last_os_error();
                match watch_failure(error.raw_os_error()) {
                    WatchFailure::Ignore => {},
                    WatchFailure::Partial => coverage = Coverage::Partial,
                    WatchFailure::Return => return Err(error),
                }
            } else {
                let mut known = match self.watches.lock() {
                    Ok(known) => known,
                    Err(poisoned) => poisoned.into_inner(),
                };
                known.insert(wd, directory.to_path_buf());
            }
        }
        Ok(coverage)
    }
}

fn local_events(path: &Path) -> io::Result<()> {
    fn number<T: Into<i64>>(value: T) -> i64 {
        value.into()
    }
    let path = super::imp::c_path(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the path is NUL-terminated and stat is a writable buffer of the exact type.
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful statfs call initialized the buffer.
    let stat = unsafe { stat.assume_init() };
    let supported = [
        number(libc::EXT4_SUPER_MAGIC),
        number(libc::BTRFS_SUPER_MAGIC),
        number(libc::XFS_SUPER_MAGIC),
        number(libc::TMPFS_MAGIC),
        number(libc::OVERLAYFS_SUPER_MAGIC),
    ];
    if supported.contains(&number(stat.f_type)) {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "raising a station notification has the same interface on every platform"
)]
pub(super) const fn wake(_notification: &str) -> io::Result<()> {
    Ok(())
}

pub(super) fn background() {
    // SAFETY: gettid takes no arguments and cannot fail.
    let thread = unsafe { libc::gettid() };
    if let Ok(thread) = u32::try_from(thread) {
        // SAFETY: a thread may lower its own priority without privilege.
        let _lowered = unsafe { libc::setpriority(libc::PRIO_PROCESS, thread, LOWEST_PRIORITY) };
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
        let source = Source::start(&[], "", None, Box::new(|_| {})).unwrap();
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

    #[test]
    fn watch_errors_distinguish_missing_capacity_and_failure() {
        for code in [libc::ENOENT, libc::ENOTDIR, libc::EACCES] {
            assert_eq!(watch_failure(Some(code)), WatchFailure::Ignore);
        }
        assert_eq!(watch_failure(Some(libc::ENOSPC)), WatchFailure::Partial);
        assert_eq!(watch_failure(Some(libc::EIO)), WatchFailure::Return);
        assert_eq!(watch_failure(None), WatchFailure::Return);
    }
}
