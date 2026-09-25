#![expect(
    unsafe_code,
    reason = "directory changes are read through ReadDirectoryChangesW"
)]

use std::ffi::OsString;
use std::io;
use std::mem::zeroed;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Arc, mpsc};

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    ReadDirectoryChangesW,
};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

use super::Change;

type Deliver = Box<dyn Fn(Change) + Send + Sync>;

const WORDS: usize = 16 * 1024;
const HEADER: usize = 12;
const FILTER: u32 = FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE;

struct Directory(OwnedHandle);

fn open(path: &Path) -> io::Result<Directory> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: the UTF-16 path is NUL-terminated and every pointer argument is valid for the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `CreateFileW` just returned this handle and nothing else owns it.
        Ok(Directory(unsafe { OwnedHandle::from_raw_handle(handle) }))
    }
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..)?
        .first_chunk::<4>()
        .map(|word| u32::from_le_bytes(*word))
}

fn changed(bytes: &[u8], root: &Path, deliver: &Deliver) {
    let mut at = 0usize;
    loop {
        let (Some(next), Some(len)) = (word(bytes, at), word(bytes, at.saturating_add(8))) else {
            return;
        };
        let Ok(len) = usize::try_from(len) else {
            return;
        };
        let start = at.saturating_add(HEADER);
        let Some(name) = start.checked_add(len).and_then(|end| bytes.get(start..end)) else {
            return;
        };
        let units = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        let path = root.join(OsString::from_wide(&units));
        deliver(Change::Directory(match path.parent() {
            Some(parent) => parent.to_path_buf(),
            None => path,
        }));
        let Ok(next) = usize::try_from(next) else {
            return;
        };
        if next == 0 {
            return;
        }
        at = at.saturating_add(next);
    }
}

fn arm(directory: &Directory, buffer: &mut [u32], overlapped: &mut OVERLAPPED) -> io::Result<()> {
    let capacity = u32::try_from(buffer.len().saturating_mul(4))
        .map_err(|_wide| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the handle is an open directory, the buffer is DWORD-aligned and `capacity` bytes long, and both it and `overlapped` stay in place until the read completes.
    let result = unsafe {
        ReadDirectoryChangesW(
            directory.0.as_raw_handle(),
            buffer.as_mut_ptr().cast(),
            capacity,
            1,
            FILTER,
            null_mut(),
            overlapped,
            None,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn follow(
    directory: &Directory,
    root: &Path,
    deliver: &Deliver,
    armed: &mpsc::SyncSender<io::Result<()>>,
) {
    let mut buffer = vec![0u32; WORDS];
    // SAFETY: an all-zero bit pattern is a valid value of this plain C struct.
    let mut overlapped = unsafe { zeroed::<OVERLAPPED>() };
    let first = arm(directory, &mut buffer, &mut overlapped);
    let refused = first.is_err();
    let _told = armed.send(first);
    if refused {
        return;
    }
    loop {
        let mut returned = 0u32;
        // SAFETY: a read was issued on this handle with this `overlapped`, which has not moved, and the call waits for it to complete.
        let completed = unsafe {
            GetOverlappedResult(
                directory.0.as_raw_handle(),
                &raw const overlapped,
                &raw mut returned,
                1,
            )
        };
        if completed == 0 {
            deliver(Change::Lost);
            return;
        }
        let bytes = match usize::try_from(returned) {
            Ok(returned) => buffer
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .take(returned)
                .collect::<Vec<_>>(),
            Err(_wide) => Vec::new(),
        };
        let rearmed = arm(directory, &mut buffer, &mut overlapped);
        if bytes.is_empty() {
            deliver(Change::Lost);
        } else {
            changed(&bytes, root, deliver);
        }
        if rearmed.is_err() {
            deliver(Change::Lost);
            return;
        }
    }
}

pub(super) struct Source;

impl Source {
    pub(super) fn start(paths: &[PathBuf], deliver: Deliver) -> io::Result<Self> {
        let deliver = Arc::new(deliver);
        for path in paths {
            let directory = open(path)?;
            let root = path.clone();
            let deliver = Arc::clone(&deliver);
            let (armed, ready) = mpsc::sync_channel(1);
            std::thread::Builder::new()
                .name("storage-scout-events".to_owned())
                .spawn(move || follow(&directory, &root, &deliver, &armed))?;
            match ready.recv() {
                Ok(outcome) => outcome?,
                Err(_ended) => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            }
        }
        Ok(Self)
    }

    #[expect(
        clippy::unused_self,
        reason = "a subtree watch reports every directory below its root"
    )]
    pub(super) const fn recursive(&self) -> bool {
        true
    }

    #[expect(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "ReadDirectoryChangesW already reports every directory below the roots"
    )]
    pub(super) const fn watch(&self, _directories: &[&Path]) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn a_change_made_as_soon_as_the_watch_starts_is_seen() {
        let temp = testkit::tempdir("events-windows-armed");
        let root = fs::canonicalize(temp.path()).unwrap();
        let (sender, receiver) = mpsc::channel();
        let _source = Source::start(
            std::slice::from_ref(&root),
            Box::new(move |change| {
                let _sent = sender.send(change);
            }),
        )
        .unwrap();
        testkit::write_sized(&root.join("file"), 1);
        assert_eq!(receiver.recv().unwrap(), Change::Directory(root));
    }
}
