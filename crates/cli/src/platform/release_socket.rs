#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "the private local socket uses native descriptor polling and owner checks"
)]
mod native {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use storage_scout_core::ownership::RELEASE_RECORD_BYTES;

    use crate::platform::spawn::local_socket::{self, Operation};

    #[derive(Debug, Clone)]
    pub(crate) struct Wake(Arc<UnixStream>);

    impl Wake {
        pub(crate) fn send(&self) -> io::Result<()> {
            (&*self.0).write_all(b"!")
        }
    }

    #[derive(Debug)]
    pub(crate) struct Listener {
        socket: UnixListener,
        directory: tempfile::TempDir,
        wake: UnixStream,
        signal: Wake,
    }

    const LISTEN_BACKLOG: libc::c_int = 16;
    const PERMISSION_BITS: u32 = 0o777;
    const PRIVATE_DIRECTORY: u32 = 0o700;

    fn ready(descriptor: libc::c_int, wake: &UnixStream) -> io::Result<bool> {
        let mut descriptors = [
            libc::pollfd {
                fd: descriptor,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            // SAFETY: descriptors contains two initialized pollfd values for the duration of poll.
            let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let [peer, cancellation] = descriptors;
            if cancellation.revents != 0 {
                return Ok(false);
            }
            if peer.revents != 0 {
                return Ok(true);
            }
        }
    }

    impl Listener {
        pub(crate) fn bind(state: &Path) -> io::Result<Self> {
            let directory = crate::store::release_channel(state)?;
            let socket = UnixListener::from(local_socket::open(directory.path(), Operation::Bind)?);
            // SAFETY: socket is a bound Unix stream socket and the backlog is positive.
            if unsafe { libc::listen(socket.as_raw_fd(), LISTEN_BACKLOG) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let (wake, signal) = UnixStream::pair()?;
            Ok(Self {
                socket,
                directory,
                wake,
                signal: Wake(Arc::new(signal)),
            })
        }

        pub(crate) fn endpoint(&self) -> PathBuf {
            self.directory.path().join("rpc")
        }

        pub(crate) fn waker(&self) -> Wake {
            self.signal.clone()
        }

        pub(crate) fn accept(&self) -> io::Result<Option<Peer<'_>>> {
            if !ready(self.socket.as_raw_fd(), &self.wake)? {
                return Ok(None);
            }
            let (stream, _) = self.socket.accept()?;
            Ok(Some(Peer {
                stream,
                wake: &self.wake,
            }))
        }
    }

    pub(crate) struct Peer<'a> {
        stream: UnixStream,
        wake: &'a UnixStream,
    }

    impl Peer<'_> {
        pub(crate) fn request(&self) -> io::Result<Option<u8>> {
            if !ready(self.stream.as_raw_fd(), self.wake)? {
                return Ok(None);
            }
            let mut byte = [0];
            (&self.stream).read_exact(&mut byte)?;
            Ok(Some(byte[0]))
        }

        pub(crate) fn reply(&self, record: &[u8; RELEASE_RECORD_BYTES]) -> io::Result<()> {
            (&self.stream).write_all(record)
        }
    }

    pub(crate) fn query(endpoint: &Path) -> io::Result<[u8; RELEASE_RECORD_BYTES]> {
        let parent = endpoint
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let metadata = fs::symlink_metadata(parent)?;
        // SAFETY: geteuid takes no pointers and does not mutate process state.
        let owner = unsafe { libc::geteuid() };
        if !metadata.is_dir()
            || metadata.uid() != owner
            || metadata.permissions().mode() & PERMISSION_BITS != PRIVATE_DIRECTORY
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let mut stream = UnixStream::from(local_socket::open(parent, Operation::Connect)?);
        stream.write_all(b"?")?;
        let mut reply = [0; RELEASE_RECORD_BYTES];
        stream.read_exact(&mut reply)?;
        Ok(reply)
    }
}

#[cfg(not(unix))]
mod native {
    use std::convert::Infallible;
    use std::io;
    use std::path::{Path, PathBuf};
    use storage_scout_core::ownership::RELEASE_RECORD_BYTES;

    #[derive(Debug, Clone)]
    pub(crate) struct Wake(Infallible);

    impl Wake {
        pub(crate) const fn send(&self) -> io::Result<()> {
            match self.0 {}
        }
    }

    #[derive(Debug)]
    pub(crate) struct Listener(Infallible);

    impl Listener {
        pub(crate) fn bind(_state: &Path) -> io::Result<Self> {
            Err(io::ErrorKind::Unsupported.into())
        }
        pub(crate) const fn endpoint(&self) -> PathBuf {
            match self.0 {}
        }
        pub(crate) const fn waker(&self) -> Wake {
            match self.0 {}
        }
        pub(crate) const fn accept(&self) -> io::Result<Option<Peer>> {
            match self.0 {}
        }
    }

    pub(crate) struct Peer(Infallible);

    impl Peer {
        pub(crate) const fn request(&self) -> io::Result<Option<u8>> {
            match self.0 {}
        }
        pub(crate) const fn reply(&self, _record: &[u8; RELEASE_RECORD_BYTES]) -> io::Result<()> {
            match self.0 {}
        }
    }

    pub(crate) fn query(_endpoint: &Path) -> io::Result<[u8; RELEASE_RECORD_BYTES]> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

pub(crate) use native::{Listener, Wake, query};
