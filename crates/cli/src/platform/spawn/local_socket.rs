use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Bind,
    Connect,
}

#[expect(
    unsafe_code,
    reason = "this function isolates the native descriptor-relative socket transport"
)]
pub(crate) fn open(directory: &Path, operation: Operation) -> io::Result<OwnedFd> {
    let directory = File::open(directory)?;
    let (mut receive, send) = UnixStream::pair()?;
    // SAFETY: socket receives a supported domain and type and no borrowed memory.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a fresh descriptor owned by this function.
    let socket = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: socket is live and F_SETFD takes an integer descriptor flag.
    if unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an all-zero sockaddr_un is valid storage before assigning its family and path.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).map_err(io::Error::other)?;
    for (slot, byte) in address.sun_path.iter_mut().zip(b"rpc\0") {
        *slot = libc::c_char::try_from(*byte).map_err(io::Error::other)?;
    }
    let length = libc::socklen_t::try_from(size_of_val(&address)).map_err(io::Error::other)?;
    let address = std::ptr::from_ref(&address).cast::<libc::sockaddr>();
    let directory = directory.as_raw_fd();
    let feedback = send.as_raw_fd();
    // SAFETY: the child executes only fchdir, bind/connect, write, and _exit, with prebuilt arguments.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        // SAFETY: directory remains open in the child; changing its cwd cannot affect the parent.
        let changed = unsafe { libc::fchdir(directory) };
        let result = if changed < 0 {
            changed
        } else {
            match operation {
                // SAFETY: descriptor and the initialized address remain live across fork.
                Operation::Bind => unsafe { libc::bind(descriptor, address, length) },
                // SAFETY: descriptor and the initialized address remain live across fork.
                Operation::Connect => unsafe { libc::connect(descriptor, address, length) },
            }
        };
        let status = u8::from(result == 0);
        // SAFETY: feedback is open and status is a live one-byte buffer.
        let _sent = unsafe { libc::write(feedback, std::ptr::from_ref(&status).cast(), 1) };
        // SAFETY: _exit terminates without running allocators, destructors, or inherited locks.
        unsafe { libc::_exit(i32::from(status == 0)) };
    }
    drop(send);
    let mut reply = [0];
    let received = receive.read_exact(&mut reply);
    let mut status = 0;
    loop {
        // SAFETY: child is this function's child and status points to writable storage.
        let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
        if waited >= 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    received?;
    if reply != [1] || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(io::Error::other(
            "the private local socket could not be opened",
        ));
    }
    Ok(socket)
}
