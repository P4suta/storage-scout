use std::io;
use std::path::{Path, PathBuf};

use super::{Change, Coverage, WatchDepth};

type Deliver = Box<dyn Fn(Change) + Send + Sync>;

pub(super) struct Source;

impl Source {
    #[expect(
        clippy::unused_self,
        reason = "each directory is watched on its own here"
    )]
    pub(super) const fn depth(&self) -> WatchDepth {
        WatchDepth::Named
    }

    pub(super) fn start(
        _paths: &[PathBuf],
        _notification: &str,
        _checkpoint: Option<u64>,
        _deliver: Deliver,
    ) -> io::Result<Self> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    #[expect(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "nothing is ever watched here"
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

pub(super) const fn background() {}
