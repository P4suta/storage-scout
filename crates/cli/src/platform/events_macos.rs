#![expect(unsafe_code, reason = "FSEvents is reached through CoreServices")]

use std::ffi::{CStr, c_char, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::Change;

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
}

unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> *mut c_void;
    fn dispatch_release(object: *mut c_void);
}

const UTF8: u32 = 0x0800_0100;
const SINCE_NOW: u64 = u64::MAX;
const NO_DEFER: u32 = 0x02;
const WATCH_ROOT: u32 = 0x04;
const IGNORE_SELF: u32 = 0x08;
const IMMEDIATELY: f64 = 0.0;
const LOST: u32 = 0x01 | 0x02 | 0x04 | 0x20;

extern "C" fn delivered(
    _stream: *const c_void,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    flags: *const u32,
    _ids: *const u64,
) {
    // SAFETY: `info` is the `Deliver` registered in `start`, alive until the stream is released.
    let deliver = unsafe { &*info.cast_const().cast::<Deliver>() };
    // SAFETY: without the CF-types flag FSEvents passes `count` C strings.
    let paths =
        unsafe { std::slice::from_raw_parts(paths.cast_const().cast::<*const c_char>(), count) };
    // SAFETY: FSEvents passes one flag word per path.
    let flags = unsafe { std::slice::from_raw_parts(flags, count) };
    for (path, flag) in paths.iter().zip(flags) {
        if flag & LOST != 0 {
            deliver(Change::Lost);
        }
        // SAFETY: each path is a NUL-terminated string owned by FSEvents for this call.
        let bytes = unsafe { CStr::from_ptr(*path) }.to_bytes();
        let trimmed = bytes.strip_suffix(b"/").unwrap_or(bytes);
        deliver(Change::Directory(PathBuf::from(
            std::ffi::OsStr::from_bytes(trimmed),
        )));
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
    deliver: *mut Deliver,
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
        drop(unsafe { Box::from_raw(self.deliver) });
    }
}

impl Source {
    pub(super) fn start(paths: &[PathBuf], deliver: Deliver) -> io::Result<Self> {
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
        let deliver = Box::into_raw(Box::new(deliver));
        let context = Context {
            version: 0,
            info: deliver.cast::<c_void>(),
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
                SINCE_NOW,
                IMMEDIATELY,
                NO_DEFER | WATCH_ROOT | IGNORE_SELF,
            )
        };
        // SAFETY: the array was created above and the stream holds its own reference.
        unsafe { CFRelease(array) };
        drop(strings);
        if stream.is_null() {
            // SAFETY: no stream took ownership of the boxed sink.
            drop(unsafe { Box::from_raw(deliver) });
            return Err(io::Error::other("FSEvents refused the stream"));
        }
        // SAFETY: the label is NUL-terminated and a null attribute asks for a serial queue.
        let queue =
            unsafe { dispatch_queue_create(c"storage-scout.events".as_ptr(), std::ptr::null()) };
        // SAFETY: the stream is live and the queue outlives it.
        unsafe { FSEventStreamSetDispatchQueue(stream, queue) };
        // SAFETY: the stream is scheduled on a queue, so it may start.
        if unsafe { FSEventStreamStart(stream) } == 0 {
            // SAFETY: a stream that never started may be invalidated.
            unsafe { FSEventStreamInvalidate(stream) };
            // SAFETY: the stream is released exactly once.
            unsafe { FSEventStreamRelease(stream) };
            // SAFETY: the queue came from `dispatch_queue_create` and is released once.
            unsafe { dispatch_release(queue) };
            // SAFETY: the released stream no longer holds the boxed sink.
            drop(unsafe { Box::from_raw(deliver) });
            return Err(io::Error::other("FSEvents did not start"));
        }
        Ok(Self {
            stream,
            queue,
            deliver,
        })
    }

    #[expect(
        clippy::unused_self,
        reason = "a stream always reports every directory below its roots"
    )]
    pub(super) const fn recursive(&self) -> bool {
        true
    }

    #[expect(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "FSEvents already reports every directory below the roots"
    )]
    pub(super) const fn watch(&self, _directories: &[&Path]) -> io::Result<()> {
        Ok(())
    }
}
