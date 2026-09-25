#![expect(
    unsafe_code,
    reason = "cloning, swapping, and reading attributes are system calls"
)]

use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io;
use std::mem::{MaybeUninit, size_of_val};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::ptr::null_mut;

use sha2::{Digest, Sha256};
use storage_scout_core::candidate::Identity;
use storage_scout_core::share::{
    Attributes, Extras, Failure, Filesystem, Method, Mode, Owner, Sharing, Step, TEMPORARY_SUFFIX,
};

pub(super) use super::imp::Tree;
use super::imp::{self, Located};
use super::{FileFacts, Request, WalkError, failed};

const SUFFIX: &[u8] = TEMPORARY_SUFFIX.as_bytes();
const CHUNK: usize = 1 << 20;
const UNCHANGED: libc::uid_t = libc::uid_t::MAX;

pub(super) fn filesystem(path: &Path) -> io::Result<Filesystem> {
    let path = imp::c_path(path.as_os_str().as_bytes())?;
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` is a writable buffer of the exact type.
    let result = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `statfs` returned 0, so it initialised the buffer.
    let stat = unsafe { stat.assume_init() };
    let bytes = stat.f_fstypename.map(|each| each.to_ne_bytes()[0]);
    Ok(match CStr::from_bytes_until_nul(&bytes) {
        Ok(name) if name == c"apfs" => Filesystem::Apfs,
        Ok(_) | Err(_) => Filesystem::Other,
    })
}

fn same_bytes(left: &File, right: &File, len: u64) -> io::Result<bool> {
    let mut first = vec![0u8; CHUNK];
    let mut second = vec![0u8; CHUNK];
    let mut offset = 0u64;
    while offset < len {
        let wanted = match usize::try_from(len.saturating_sub(offset)) {
            Ok(remaining) => remaining.min(CHUNK),
            Err(_huge) => CHUNK,
        };
        let (Some(left_chunk), Some(right_chunk)) =
            (first.get_mut(..wanted), second.get_mut(..wanted))
        else {
            return Ok(false);
        };
        left.read_exact_at(left_chunk, offset)?;
        right.read_exact_at(right_chunk, offset)?;
        if left_chunk != right_chunk {
            return Ok(false);
        }
        offset = offset.saturating_add(widen(wanted));
    }
    Ok(true)
}

fn widen(len: usize) -> u64 {
    match u64::try_from(len) {
        Ok(len) => len,
        Err(_huge) => u64::MAX,
    }
}

fn size(stat: &libc::stat) -> Option<u64> {
    match u64::try_from(stat.st_size) {
        Ok(len) => Some(len),
        Err(_negative) => None,
    }
}

fn caller() -> libc::uid_t {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.at.checked_add(N)?;
        let slice = self.bytes.get(self.at..end)?;
        let mut taken = [0u8; N];
        taken.copy_from_slice(slice);
        self.at = end;
        Some(taken)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_ne_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_ne_bytes)
    }
}

struct Common {
    acl: bool,
    clone: Option<u64>,
}

enum Source<'a> {
    Open(&'a File),
    Named(&'a CStr),
}

fn common(source: &Source<'_>) -> io::Result<Common> {
    let mut list = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_EXTENDED_SECURITY,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: libc::ATTR_CMNEXT_CLONEID,
    };
    let mut buffer = [0u32; 512];
    let result = match source {
        // SAFETY: `list` and `buffer` are live, writable, and `buffer`'s size is passed exactly.
        Source::Open(file) => unsafe {
            libc::fgetattrlist(
                file.as_raw_fd(),
                (&raw mut list).cast(),
                buffer.as_mut_ptr().cast(),
                size_of_val(&buffer),
                libc::FSOPT_ATTR_CMN_EXTENDED,
            )
        },
        // SAFETY: `path` is NUL-terminated; `list` and `buffer` are live, writable, and sized exactly.
        Source::Named(path) => unsafe {
            libc::getattrlist(
                path.as_ptr(),
                (&raw mut list).cast(),
                buffer.as_mut_ptr().cast(),
                size_of_val(&buffer),
                libc::FSOPT_ATTR_CMN_EXTENDED | libc::FSOPT_NOFOLLOW,
            )
        },
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes = buffer
        .iter()
        .flat_map(|word| word.to_ne_bytes())
        .collect::<Vec<_>>();
    let malformed = || io::Error::from(io::ErrorKind::InvalidData);
    let mut cursor = Cursor {
        bytes: &bytes,
        at: 0,
    };
    let _length = cursor.u32().ok_or_else(malformed)?;
    let returned_common = cursor.u32().ok_or_else(malformed)?;
    let _returned_volume = cursor.u32().ok_or_else(malformed)?;
    let _returned_directory = cursor.u32().ok_or_else(malformed)?;
    let _returned_file = cursor.u32().ok_or_else(malformed)?;
    let returned_fork = cursor.u32().ok_or_else(malformed)?;
    let acl = returned_common & libc::ATTR_CMN_EXTENDED_SECURITY != 0;
    if acl {
        let _reference = cursor.u64().ok_or_else(malformed)?;
    }
    let clone = if returned_fork & libc::ATTR_CMNEXT_CLONEID == 0 {
        None
    } else {
        Some(cursor.u64().ok_or_else(malformed)?)
    };
    Ok(Common { acl, clone })
}

fn listed(file: &File) -> io::Result<Vec<u8>> {
    // SAFETY: a null buffer of size 0 asks only for the size.
    let size = unsafe { libc::flistxattr(file.as_raw_fd(), null_mut(), 0, 0) };
    let size = usize::try_from(size).map_err(|_negative| io::Error::last_os_error())?;
    let mut names = vec![0u8; size];
    // SAFETY: `names` is writable for exactly its length.
    let got =
        unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len(), 0) };
    let got = usize::try_from(got).map_err(|_negative| io::Error::last_os_error())?;
    names.truncate(got);
    Ok(names)
}

fn value(file: &File, name: &CStr) -> io::Result<Vec<u8>> {
    // SAFETY: `name` is NUL-terminated; a null buffer of size 0 asks only for the size.
    let size = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), null_mut(), 0, 0, 0) };
    let size = usize::try_from(size).map_err(|_negative| io::Error::last_os_error())?;
    let mut value = vec![0u8; size];
    // SAFETY: `name` is NUL-terminated and `value` is writable for exactly its length.
    let got = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    let got = usize::try_from(got).map_err(|_negative| io::Error::last_os_error())?;
    value.truncate(got);
    Ok(value)
}

fn attributes(file: &File) -> io::Result<Attributes> {
    let names = listed(file)?;
    let mut entries = Vec::new();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let key = CString::new(name).map_err(|_nul| io::Error::from(io::ErrorKind::InvalidData))?;
        let bytes = value(file, &key)?;
        entries.push((key, bytes));
    }
    entries.sort();
    let mut hash = Sha256::new();
    for (key, bytes) in &entries {
        hash.update(widen(key.as_bytes().len()).to_le_bytes());
        hash.update(key.as_bytes());
        hash.update(widen(bytes.len()).to_le_bytes());
        hash.update(bytes);
    }
    let mut short = [0u8; 16];
    for (slot, byte) in short.iter_mut().zip(hash.finalize()) {
        *slot = byte;
    }
    Ok(Attributes(short))
}

fn classify(file: &File, stat: &libc::stat, acl: Option<bool>) -> Extras {
    match acl {
        None => Extras::Unobserved,
        Some(true) => Extras::Special,
        Some(false) if stat.st_flags != 0 => Extras::Special,
        Some(false) => match attributes(file) {
            Ok(digest) => Extras::Plain(digest),
            Err(_unreadable) => Extras::Unobserved,
        },
    }
}

fn extras_of(file: &File, stat: &libc::stat) -> Extras {
    match common(&Source::Open(file)) {
        Ok(found) => classify(file, stat, Some(found.acl)),
        Err(_unreadable) => Extras::Unobserved,
    }
}

pub(super) fn facts(path: &Path, metadata: &Metadata) -> io::Result<FileFacts> {
    let name = imp::c_path(path.as_os_str().as_bytes())?;
    let sharing = match common(&Source::Named(&name)) {
        Ok(found) => found.clone.map_or(Sharing::Unknown, Sharing::Cluster),
        Err(_unreadable) => Sharing::Unknown,
    };
    Ok(FileFacts {
        identity: imp::identity_of(metadata),
        len: metadata.len(),
        links: imp::links_of(metadata),
        owner: if metadata.uid() == caller() {
            Owner::Caller
        } else {
            Owner::Other
        },
        mode: if metadata.mode() & 0o111 == 0 {
            Mode::Plain
        } else {
            Mode::Executable
        },
        sharing,
    })
}

pub(super) fn extras(path: &Path, identity: Identity) -> Extras {
    let Ok(file) = imp::open_regular(path) else {
        return Extras::Unobserved;
    };
    match imp::stat_fd(&file) {
        Ok(stat) if imp::stat_identity(&stat) == identity => extras_of(&file, &stat),
        Ok(_) | Err(_) => Extras::Unobserved,
    }
}

const fn executable(stat: &libc::stat) -> Mode {
    if stat.st_mode & 0o111 == 0 {
        Mode::Plain
    } else {
        Mode::Executable
    }
}

fn replaceable(stat: &libc::stat) -> bool {
    stat.st_nlink == 1
        && stat.st_uid == caller()
        && stat.st_flags == 0
        && matches!(executable(stat), Mode::Plain)
}

fn temporary(name: &CStr) -> Result<CString, Failure> {
    let mut bytes = Vec::with_capacity(
        name.to_bytes()
            .len()
            .saturating_add(SUFFIX.len())
            .saturating_add(1),
    );
    bytes.push(b'.');
    bytes.extend_from_slice(name.to_bytes());
    bytes.extend_from_slice(SUFFIX);
    CString::new(bytes).map_err(|_nul| Failure::DuplicateChanged)
}

fn clone_to(keeper: &File, dir: &OwnedFd, name: &CStr) -> io::Result<()> {
    // SAFETY: `keeper` and `dir` are open descriptors and `name` is NUL-terminated.
    let result =
        unsafe { libc::fclonefileat(keeper.as_raw_fd(), dir.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn swap(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is an open directory descriptor and both names are NUL-terminated.
    let result = unsafe {
        libc::renameatx_np(
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn carry(clone: &File, original: &libc::stat) -> io::Result<()> {
    let fd = clone.as_raw_fd();
    // SAFETY: `fd` is an open descriptor for the clone this process created.
    check(unsafe { libc::fchmod(fd, original.st_mode & 0o7777) })?;
    if imp::stat_fd(clone)?.st_gid != original.st_gid {
        // SAFETY: `fd` is open; `UNCHANGED` leaves the owner as it is.
        check(unsafe { libc::fchown(fd, UNCHANGED, original.st_gid) })?;
    }
    let times = [
        libc::timespec {
            tv_sec: original.st_atime,
            tv_nsec: original.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: original.st_mtime,
            tv_nsec: original.st_mtime_nsec,
        },
    ];
    // SAFETY: `fd` is open and `times` holds exactly the two entries `futimens` reads.
    check(unsafe { libc::futimens(fd, times.as_ptr()) })
}

const fn same_metadata(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_flags == right.st_flags
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
}

struct Opened {
    file: File,
    stat: libc::stat,
}

fn open_file(dir: &OwnedFd, name: &CStr) -> io::Result<Opened> {
    let file = imp::regular(imp::open_at(
        dir.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?)?;
    let stat = imp::stat_fd(&file)?;
    Ok(Opened { file, stat })
}

fn discard(dir: &OwnedFd, name: &CStr, identity: Identity) {
    if let Ok(found) = imp::stat_at(dir.as_raw_fd(), name)
        && imp::stat_identity(&found) == identity
    {
        let _abandoned = imp::unlink_at(dir, name, 0);
    }
}

fn reclaim(dir: &OwnedFd, name: &CStr, duplicate: &Opened, len: u64) -> Result<(), Failure> {
    let leftover = open_file(dir, name).map_err(|_unreadable| Failure::Leftover)?;
    if leftover.stat.st_size != duplicate.stat.st_size
        || !same_bytes(&leftover.file, &duplicate.file, len).map_err(failed(Step::Read))?
    {
        return Err(Failure::Leftover);
    }
    let identity = imp::stat_identity(&leftover.stat);
    let found = imp::stat_at(dir.as_raw_fd(), name).map_err(failed(Step::Inspect))?;
    if imp::stat_identity(&found) != identity {
        return Err(Failure::Leftover);
    }
    imp::unlink_at(dir, name, 0).map_err(failed(Step::Unlink))
}

fn prepare(clone: &Opened, duplicate: &Opened, wanted: Extras, len: u64) -> Result<(), Failure> {
    if clone.stat.st_size != duplicate.stat.st_size
        || !same_bytes(&clone.file, &duplicate.file, len).map_err(failed(Step::Read))?
    {
        return Err(Failure::ContentDiffers);
    }
    carry(&clone.file, &duplicate.stat).map_err(failed(Step::Carry))?;
    let carried = imp::stat_fd(&clone.file).map_err(failed(Step::Inspect))?;
    if !same_metadata(&carried, &duplicate.stat) || extras_of(&clone.file, &carried) != wanted {
        return Err(Failure::MetadataNotCarried);
    }
    Ok(())
}

struct Names<'a> {
    dir: &'a OwnedFd,
    name: &'a CStr,
    temporary: &'a CStr,
}

fn settled(names: &Names<'_>, clone: &Opened, duplicate: &Opened, len: u64) -> Result<(), Failure> {
    let dir = names.dir.as_raw_fd();
    let at_name = imp::stat_at(dir, names.name).map_err(failed(Step::Inspect))?;
    let at_temporary = imp::stat_at(dir, names.temporary).map_err(failed(Step::Inspect))?;
    let now = imp::stat_fd(&duplicate.file).map_err(failed(Step::Inspect))?;
    if imp::stat_identity(&at_name) != imp::stat_identity(&clone.stat)
        || imp::stat_identity(&at_temporary) != imp::stat_identity(&duplicate.stat)
        || !same_metadata(&now, &duplicate.stat)
    {
        return Err(Failure::DuplicateChanged);
    }
    if !same_bytes(&clone.file, &duplicate.file, len).map_err(failed(Step::Read))? {
        return Err(Failure::ContentDiffers);
    }
    Ok(())
}

fn restore(names: &Names<'_>, clone: &Opened, duplicate: &Opened) -> Result<(), Failure> {
    swap(names.dir, names.temporary, names.name).map_err(|_stuck| Failure::Stranded)?;
    let dir = names.dir.as_raw_fd();
    let back = imp::stat_at(dir, names.name).map_err(|_lost| Failure::Stranded)?;
    if imp::stat_identity(&back) != imp::stat_identity(&duplicate.stat) {
        return Err(Failure::Stranded);
    }
    discard(names.dir, names.temporary, imp::stat_identity(&clone.stat));
    Ok(())
}

fn open_keeper(request: &Request<'_>) -> Result<Opened, Failure> {
    let file = imp::open_regular(request.keeper).map_err(|_gone| Failure::KeeperChanged)?;
    let stat = imp::stat_fd(&file).map_err(failed(Step::Inspect))?;
    if imp::stat_identity(&stat) != request.keeper_identity || size(&stat) != Some(request.len) {
        return Err(Failure::KeeperChanged);
    }
    Ok(Opened { file, stat })
}

fn open_duplicate(dir: &OwnedFd, name: &CStr, request: &Request<'_>) -> Result<Opened, Failure> {
    let opened = open_file(dir, name).map_err(|_gone| Failure::DuplicateChanged)?;
    if imp::stat_identity(&opened.stat) != request.duplicate_identity
        || size(&opened.stat) != Some(request.len)
        || !replaceable(&opened.stat)
    {
        return Err(Failure::DuplicateChanged);
    }
    Ok(opened)
}

pub(super) fn share(tree: &Tree, method: Method, request: &Request<'_>) -> Result<(), Failure> {
    match method {
        Method::CloneAndSwap => {},
        Method::DedupeRange => {
            return Err(Failure::Io {
                step: Step::Dedupe,
                error: crate::failure::describe(&io::Error::from(io::ErrorKind::Unsupported)),
            });
        },
    }
    let keeper = open_keeper(request)?;
    let (dir, name) = match tree.locate(request.duplicate).map_err(failed(Step::Open))? {
        Located::Found { dir, name } => (dir, name),
        Located::Moved => return Err(Failure::DuplicateChanged),
    };
    let duplicate = open_duplicate(&dir, &name, request)?;
    let wanted = extras_of(&duplicate.file, &duplicate.stat);
    match (extras_of(&keeper.file, &keeper.stat), wanted) {
        (Extras::Plain(kept), Extras::Plain(found)) if kept == found => {},
        (Extras::Plain(_) | Extras::Special | Extras::Unobserved, _) => {
            return Err(Failure::DuplicateChanged);
        },
    }
    let temporary = temporary(&name)?;
    let names = Names {
        dir: &dir,
        name: &name,
        temporary: &temporary,
    };
    match clone_to(&keeper.file, &dir, &temporary) {
        Ok(()) => {},
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            reclaim(&dir, &temporary, &duplicate, request.len)?;
            clone_to(&keeper.file, &dir, &temporary).map_err(failed(Step::Clone))?;
        },
        Err(error) => return Err(failed(Step::Clone)(error)),
    }
    let clone = open_file(&dir, &temporary).map_err(failed(Step::Open))?;
    if let Err(failure) = prepare(&clone, &duplicate, wanted, request.len) {
        discard(&dir, &temporary, imp::stat_identity(&clone.stat));
        return Err(failure);
    }
    if let Err(error) = swap(&dir, &temporary, &name) {
        discard(&dir, &temporary, imp::stat_identity(&clone.stat));
        return Err(failed(Step::Swap)(error));
    }
    if let Err(failure) = settled(&names, &clone, &duplicate, request.len) {
        restore(&names, &clone, &duplicate)?;
        return Err(failure);
    }
    let original = imp::stat_at(dir.as_raw_fd(), &temporary).map_err(failed(Step::Inspect))?;
    if imp::stat_identity(&original) != imp::stat_identity(&duplicate.stat) {
        return Err(Failure::Stranded);
    }
    imp::unlink_at(&dir, &temporary, 0).map_err(failed(Step::Unlink))
}

pub(super) fn open(root: &Path, expected: Identity) -> Result<Tree, WalkError> {
    Tree::open(root, expected)
}
