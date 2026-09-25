use std::io;
use std::path::{Path, PathBuf};

use super::Change;

type Deliver = Box<dyn Fn(Change) + Send + Sync>;

pub(super) struct Source;

impl Source {
    #[expect(
        clippy::unused_self,
        reason = "each directory is watched on its own here"
    )]
    pub(super) const fn recursive(&self) -> bool {
        false
    }

    pub(super) fn start(_paths: &[PathBuf], _deliver: Deliver) -> io::Result<Self> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    #[expect(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "nothing is ever watched here"
    )]
    pub(super) const fn watch(&self, _directories: &[&Path]) -> io::Result<()> {
        Ok(())
    }
}
