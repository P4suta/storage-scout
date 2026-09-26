#![expect(unsafe_code, reason = "FSEvents is reached through CoreServices")]

use std::ffi::{CStr, c_char, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use super::{Change, Coverage, Event, WatchDepth};

type Deliver = Box<dyn Fn(Change) + Send + Sync>;

type Callback =
    extern "C" fn(*const c_void, *mut c_void, usize, *mut c_void, *const u32, *const u64);

#[repr(C)]
struct Context {
    version: isize,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

#[repr(C)]
struct ArrayCallBacks {
    version: isize,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: ArrayCallBacks;
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        len: isize,
        encoding: u32,
        external: u8,
    ) -> *const c_void;
    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        count: isize,
        callbacks: *const ArrayCallBacks,
    ) -> *const c_void;
    fn CFRelease(object: *const c_void);
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: *const c_void,
        callback: Callback,
        context: *const Context,
        paths: *const c_void,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> *mut c_void;
    fn FSEventStreamSetDispatchQueue(stream: *mut c_void, queue: *mut c_void);
    fn FSEventStreamStart(stream: *mut c_void) -> u8;
    fn FSEventStreamStop(stream: *mut c_void);
    fn FSEventStreamInvalidate(stream: *mut c_void);
    fn FSEventStreamRelease(stream: *mut c_void);
    fn FSEventsGetCurrentEventId() -> u64;
}

unsafe extern "C" {
    fn dispatch_queue_attr_make_with_qos_class(
        attributes: *const c_void,
        class: libc::qos_class_t,
        relative: i32,
    ) -> *const c_void;
    fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> *mut c_void;
    fn dispatch_release(object: *mut c_void);
}

const UTF8: u32 = 0x0800_0100;
const NO_DEFER: u32 = 0x02;
const WATCH_ROOT: u32 = 0x04;
const IGNORE_SELF: u32 = 0x08;
const FULL_HISTORY: u32 = 0x80;
const COALESCED: f64 = 1.0;
const MUST_SCAN: u32 = 0x01;
const USER_DROPPED: u32 = 0x02;
const KERNEL_DROPPED: u32 = 0x04;
const IDS_WRAPPED: u32 = 0x08;
const HISTORY_DONE: u32 = 0x10;
const ROOT_CHANGED: u32 = 0x20;
const LOST: u32 = MUST_SCAN | USER_DROPPED | KERNEL_DROPPED | IDS_WRAPPED | ROOT_CHANGED;

struct Sink {
    deliver: Deliver,
    history: mpsc::SyncSender<()>,
}

fn change(bytes: &[u8], flag: u32) -> Change {
    if flag & LOST != 0 {
        tracing::debug!(flag, path = %String::from_utf8_lossy(bytes), "lost");
        Change::Lost
    } else {
        let trimmed = bytes.strip_suffix(b"/").unwrap_or(bytes);
        Change::Entry {
            path: PathBuf::from(std::ffi::OsStr::from_bytes(trimmed)),
            event: Event::Unsure,
        }
    }
}

extern "C" fn delivered(
    _stream: *const c_void,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    flags: *const u32,
    ids: *const u64,
) {
    // SAFETY: `info` is the `Sink` registered in `start`, alive until the stream is released.
    let sink = unsafe { &*info.cast_const().cast::<Sink>() };
    // SAFETY: without the CF-types flag FSEvents passes `count` C strings.
    let paths =
        unsafe { std::slice::from_raw_parts(paths.cast_const().cast::<*const c_char>(), count) };
    // SAFETY: FSEvents passes one flag word per path.
    let flags = unsafe { std::slice::from_raw_parts(flags, count) };
    // SAFETY: FSEvents passes one event ID per path.
    let ids = unsafe { std::slice::from_raw_parts(ids, count) };
    let mut latest: Option<u64> = None;
    let mut history_done = false;
    for ((path, flag), id) in paths.iter().zip(flags).zip(ids) {
        if flag & HISTORY_DONE != 0 {
            history_done = true;
        } else {
            // SAFETY: each path is a NUL-terminated string owned by FSEvents for this call.
            let bytes = unsafe { CStr::from_ptr(*path) }.to_bytes();
            (sink.deliver)(change(bytes, *flag));
            if *id != 0 {
                latest = Some(match latest {
                    Some(known) => known.max(*id),
                    None => *id,
                });
            }
        }
    }
    if let Some(checkpoint) = latest {
        (sink.deliver)(Change::Checkpoint(checkpoint));
    }
    if history_done {
        let _sent = sink.history.try_send(());
    }
}

struct Strings(Vec<*const c_void>);

impl Drop for Strings {
    fn drop(&mut self) {
        for string in &self.0 {
            // SAFETY: every entry came from `CFStringCreateWithBytes` and is released once.
            unsafe { CFRelease(*string) };
        }
    }
}

fn strings(paths: &[PathBuf]) -> io::Result<Strings> {
    let mut created = Strings(Vec::with_capacity(paths.len()));
    for path in paths {
        let bytes = path.as_os_str().as_bytes();
        let len = isize::try_from(bytes.len())
            .map_err(|_long| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `bytes` is valid for `len` bytes for the duration of the call.
        let string =
            unsafe { CFStringCreateWithBytes(std::ptr::null(), bytes.as_ptr(), len, UTF8, 0) };
        if string.is_null() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        created.0.push(string);
    }
    Ok(created)
}

pub(super) struct Source {
    stream: *mut c_void,
    queue: *mut c_void,
    sink: *mut Sink,
    checkpoint: u64,
}

impl Drop for Source {
    fn drop(&mut self) {
        // SAFETY: the stream was created, scheduled, and started by `start` and is torn down once.
        unsafe {
            FSEventStreamStop(self.stream);
        }
        // SAFETY: a stopped stream may be invalidated.
        unsafe {
            FSEventStreamInvalidate(self.stream);
        }
        // SAFETY: the stream is released exactly once, after it stopped delivering.
        unsafe {
            FSEventStreamRelease(self.stream);
        }
        // SAFETY: the queue came from `dispatch_queue_create` and is released once.
        unsafe {
            dispatch_release(self.queue);
        }
        // SAFETY: the stream no longer calls back, so the boxed sink can be reclaimed.
        drop(unsafe { Box::from_raw(self.sink) });
    }
}

impl Source {
    pub(super) fn start(
        paths: &[PathBuf],
        _notification: &str,
        checkpoint: Option<u64>,
        deliver: Deliver,
    ) -> io::Result<Self> {
        let strings = strings(paths)?;
        let count = isize::try_from(strings.0.len())
            .map_err(|_long| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `strings` holds `count` live CFStrings and the callbacks are CoreFoundation's own.
        let array = unsafe {
            CFArrayCreate(
                std::ptr::null(),
                strings.0.as_ptr(),
                count,
                &raw const kCFTypeArrayCallBacks,
            )
        };
        if array.is_null() {
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        let checkpoint = match checkpoint {
            Some(checkpoint) => checkpoint,
            // SAFETY: this function takes no arguments and returns the system-wide event ID.
            None => unsafe { FSEventsGetCurrentEventId() },
        };
        let (history, ready) = mpsc::sync_channel(1);
        let sink = Box::into_raw(Box::new(Sink { deliver, history }));
        let context = Context {
            version: 0,
            info: sink.cast::<c_void>(),
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        // SAFETY: `array` is a CFArray of CFStrings and `context` outlives the call; FSEvents copies both.
        let stream = unsafe {
            FSEventStreamCreate(
                std::ptr::null(),
                delivered,
                &raw const context,
                array,
                checkpoint,
                COALESCED,
                NO_DEFER | WATCH_ROOT | IGNORE_SELF | FULL_HISTORY,
            )
        };
        // SAFETY: the array was created above and the stream holds its own reference.
        unsafe { CFRelease(array) };
        drop(strings);
        if stream.is_null() {
            // SAFETY: no stream took ownership of the boxed sink.
            drop(unsafe { Box::from_raw(sink) });
            return Err(io::Error::other("FSEvents refused the stream"));
        }
        // SAFETY: a null attribute is the serial queue attribute the QoS class is added to.
        let attributes = unsafe {
            dispatch_queue_attr_make_with_qos_class(
                std::ptr::null(),
                libc::qos_class_t::QOS_CLASS_USER_INITIATED,
                0,
            )
        };
        // SAFETY: the label is NUL-terminated and the attributes came from libdispatch.
        let queue = unsafe { dispatch_queue_create(c"storage-scout.events".as_ptr(), attributes) };
        // SAFETY: the stream is live and the queue outlives it.
        unsafe { FSEventStreamSetDispatchQueue(stream, queue) };
        // SAFETY: the stream is scheduled on a queue, so it may start.
        let started = unsafe { FSEventStreamStart(stream) };
        if started == 0 {
            // SAFETY: a stream that never started may be invalidated.
            unsafe { FSEventStreamInvalidate(stream) };
            // SAFETY: the stream is released exactly once.
            unsafe { FSEventStreamRelease(stream) };
            // SAFETY: the queue came from `dispatch_queue_create` and is released once.
            unsafe { dispatch_release(queue) };
            // SAFETY: the released stream no longer holds the boxed sink.
            drop(unsafe { Box::from_raw(sink) });
            return Err(io::Error::other("FSEvents did not start"));
        }
        if ready.recv().is_err() {
            // SAFETY: the stream was started above and must stop before its queue and sink go away.
            unsafe { FSEventStreamStop(stream) };
            // SAFETY: a stopped stream may be invalidated.
            unsafe { FSEventStreamInvalidate(stream) };
            // SAFETY: the stream is released exactly once.
            unsafe { FSEventStreamRelease(stream) };
            // SAFETY: the queue came from `dispatch_queue_create` and is released once.
            unsafe { dispatch_release(queue) };
            // SAFETY: the released stream no longer holds the boxed sink.
            drop(unsafe { Box::from_raw(sink) });
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        Ok(Self {
            stream,
            queue,
            sink,
            checkpoint,
        })
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "event history has the same interface on every platform"
    )]
    pub(super) const fn checkpoint(&self) -> Option<u64> {
        Some(self.checkpoint)
    }

    #[expect(
        clippy::unused_self,
        reason = "the current event ID belongs to the live stream's system journal"
    )]
    pub(super) fn current_checkpoint(&self) -> u64 {
        // SAFETY: this function takes no arguments and returns the system-wide event ID.
        unsafe { FSEventsGetCurrentEventId() }
    }

    #[expect(
        clippy::unused_self,
        reason = "a stream always reports every directory below its roots"
    )]
    pub(super) const fn depth(&self) -> WatchDepth {
        WatchDepth::Recursive
    }

    #[expect(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "FSEvents already reports every directory below the roots"
    )]
    pub(super) const fn watch(&self, _directories: &[&Path]) -> io::Result<Coverage> {
        Ok(Coverage::Complete)
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
    // SAFETY: the call sets only the calling thread's own QoS class.
    let _lowered =
        unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_BACKGROUND, 0) };
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn dropped_events_are_lost_and_directories_are_trimmed() {
        for flag in [0x01, 0x02, 0x04, 0x08, 0x20] {
            assert_eq!(change(b"/work/target/", flag), Change::Lost);
        }
        assert_eq!(
            change(b"/work/target/", 0),
            Change::Entry {
                path: PathBuf::from("/work/target"),
                event: Event::Unsure,
            }
        );
        assert_eq!(
            change(b"/work/target", 0),
            Change::Entry {
                path: PathBuf::from("/work/target"),
                event: Event::Unsure,
            }
        );
    }

    #[test]
    fn callback_delivers_entries_and_checkpoint_before_history_completion() {
        let (sent, received) = mpsc::channel();
        let (history, ready) = mpsc::sync_channel(1);
        let mut sink = Sink {
            deliver: Box::new(move |change| sent.send(change).unwrap()),
            history,
        };
        let names = [
            CString::new("/work/target/").unwrap(),
            CString::new("/").unwrap(),
        ];
        let mut paths = names.iter().map(|name| name.as_ptr()).collect::<Vec<_>>();
        let flags = [0, HISTORY_DONE];
        let ids = [71, 0];
        delivered(
            std::ptr::null(),
            std::ptr::from_mut(&mut sink).cast::<c_void>(),
            paths.len(),
            paths.as_mut_ptr().cast::<c_void>(),
            flags.as_ptr(),
            ids.as_ptr(),
        );
        assert_eq!(
            received.try_recv().unwrap(),
            Change::Entry {
                path: PathBuf::from("/work/target"),
                event: Event::Unsure,
            }
        );
        assert_eq!(received.try_recv().unwrap(), Change::Checkpoint(71));
        let _empty = received.try_recv().unwrap_err();
        ready.try_recv().unwrap();
    }

    #[test]
    fn callback_does_not_complete_history_or_checkpoint_a_zero_id() {
        let (sent, received) = mpsc::channel();
        let (history, ready) = mpsc::sync_channel(1);
        let mut sink = Sink {
            deliver: Box::new(move |change| sent.send(change).unwrap()),
            history,
        };
        let names = [CString::new("/work/target/").unwrap()];
        let mut paths = names.iter().map(|name| name.as_ptr()).collect::<Vec<_>>();
        let flags = [0];
        let ids = [0];
        delivered(
            std::ptr::null(),
            std::ptr::from_mut(&mut sink).cast::<c_void>(),
            paths.len(),
            paths.as_mut_ptr().cast::<c_void>(),
            flags.as_ptr(),
            ids.as_ptr(),
        );
        assert_eq!(
            received.try_recv().unwrap(),
            Change::Entry {
                path: PathBuf::from("/work/target"),
                event: Event::Unsure,
            }
        );
        let _no_checkpoint = received.try_recv().unwrap_err();
        let _history_is_pending = ready.try_recv().unwrap_err();
    }
}
