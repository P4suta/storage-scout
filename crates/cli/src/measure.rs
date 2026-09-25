use std::collections::BTreeMap;
use std::fs::{self, Metadata};
use std::path::Path;

use storage_scout_core::candidate::{Allocation, Contents, Identity, Measurement, Usage};
use storage_scout_core::gate::Shape;
use storage_scout_core::reject::{FsOp, Rejection};
use storage_scout_core::size::Bytes;

use crate::{failure, host, platform};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measure {
    Logical,
    Allocated,
}

#[derive(Debug, Clone, Copy)]
struct Linked {
    allocation: u64,
    links: u32,
    seen: u32,
}

#[derive(Debug)]
pub(crate) struct Tally {
    logical: u64,
    unlinked: u64,
    allocation: AllocationState,
    linked: BTreeMap<Identity, Linked>,
    contents: Contents,
    markers: Vec<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocationState {
    Measured,
    Unmeasured,
}

impl Tally {
    pub(crate) const fn empty(measure: Measure) -> Self {
        Self {
            logical: 0,
            unlinked: 0,
            allocation: match measure {
                Measure::Allocated => AllocationState::Measured,
                Measure::Logical => AllocationState::Unmeasured,
            },
            linked: BTreeMap::new(),
            contents: Contents::ZERO,
            markers: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn merge(mut self, other: Self) -> Self {
        self.logical = self.logical.saturating_add(other.logical);
        self.unlinked = self.unlinked.saturating_add(other.unlinked);
        self.allocation = match (self.allocation, other.allocation) {
            (AllocationState::Measured, AllocationState::Measured) => AllocationState::Measured,
            (AllocationState::Unmeasured, _) | (_, AllocationState::Unmeasured) => {
                AllocationState::Unmeasured
            },
        };
        self.contents = self.contents.merge(other.contents);
        self.markers.extend(other.markers);
        for (identity, link) in other.linked {
            self.linked
                .entry(identity)
                .and_modify(|current| {
                    current.seen = current.seen.saturating_add(link.seen);
                    current.links = current.links.max(link.links);
                    current.allocation = current.allocation.max(link.allocation);
                })
                .or_insert(link);
        }
        self
    }

    pub(crate) const fn logical(&self) -> Bytes {
        Bytes::new(self.logical)
    }

    pub(crate) fn file(&mut self, path: &Path, len: u64, identity: Option<Identity>) {
        self.logical = self.logical.saturating_add(len);
        self.contents = self.contents.merge(Contents::file(
            path.as_os_str().as_encoded_bytes(),
            len,
            identity,
        ));
    }

    pub(crate) fn allocated(&mut self, measured: platform::FileMeasure) {
        if measured.links <= 1 {
            self.unlinked = self.unlinked.saturating_add(measured.allocation);
        } else {
            self.linked
                .entry(measured.identity)
                .and_modify(|link| link.seen = link.seen.saturating_add(1))
                .or_insert(Linked {
                    allocation: measured.allocation,
                    links: measured.links,
                    seen: 1,
                });
        }
    }

    pub(crate) fn marker(&mut self, directory: &Path) {
        self.markers.push(directory.to_path_buf());
    }

    pub(crate) fn markers(&self) -> &[std::path::PathBuf] {
        &self.markers
    }

    pub(crate) const fn unmeasurable(&mut self) {
        self.allocation = AllocationState::Unmeasured;
    }

    pub(crate) fn usage(&self) -> Usage {
        let allocation = match self.allocation {
            AllocationState::Unmeasured => Allocation::Unmeasured,
            AllocationState::Measured => {
                let (allocated, reclaimable) = self.linked.values().fold(
                    (self.unlinked, self.unlinked),
                    |(allocated, reclaimable), link| {
                        let allocated = allocated.saturating_add(link.allocation);
                        let reclaimable = if link.seen >= link.links {
                            reclaimable.saturating_add(link.allocation)
                        } else {
                            reclaimable
                        };
                        (allocated, reclaimable)
                    },
                );
                Allocation::Measured {
                    allocated: Bytes::new(allocated),
                    reclaimable: Bytes::new(reclaimable),
                }
            },
        };
        Usage {
            logical: Bytes::new(self.logical),
            allocation,
        }
    }

    pub(crate) fn measurement(&self) -> Measurement {
        Measurement {
            usage: self.usage(),
            contents: self.contents,
        }
    }
}

pub(crate) fn strictly(directory: &Path) -> Result<Measurement, Rejection> {
    let metadata =
        fs::symlink_metadata(directory).map_err(|e| failure::io(directory, FsOp::Inspect, &e))?;
    walk(directory, &metadata).map(|tally| tally.measurement())
}

fn walk(directory: &Path, metadata: &Metadata) -> Result<Tally, Rejection> {
    let location = || host::locate(directory);
    match platform::shape(metadata) {
        Shape::Directory => {},
        Shape::Link => {
            return Err(Rejection::Link {
                location: location()?,
            });
        },
        Shape::File | Shape::Other => {
            return Err(Rejection::NotADirectory {
                location: location()?,
            });
        },
    }
    let reader = fs::read_dir(directory).map_err(|e| failure::io(directory, FsOp::ReadDir, &e))?;
    let mut total = Tally::empty(Measure::Allocated);
    for entry in reader {
        let entry = entry.map_err(|e| failure::io(directory, FsOp::ReadEntry, &e))?;
        let path = entry.path();
        let child =
            fs::symlink_metadata(&path).map_err(|e| failure::io(&path, FsOp::Inspect, &e))?;
        match platform::shape(&child) {
            Shape::Link => {
                return Err(Rejection::Link {
                    location: host::locate(&path)?,
                });
            },
            Shape::Directory => {
                if let (Some(from), Some(to)) =
                    (platform::device(metadata), platform::device(&child))
                    && from != to
                {
                    return Err(Rejection::MountBoundary {
                        location: host::locate(&path)?,
                        from,
                        to,
                    });
                }
                total = total.merge(walk(&path, &child)?);
            },
            Shape::File => {
                let measured = platform::file_measure(&path)
                    .map_err(|e| failure::io(&path, FsOp::AllocationInfo, &e))?;
                total.file(&path, child.len(), Some(measured.identity));
                total.allocated(measured);
            },
            Shape::Other => {},
        }
    }
    Ok(total)
}

pub(crate) fn selection(paths: &[&Path]) -> Result<Usage, Rejection> {
    let mut total = Tally::empty(Measure::Allocated);
    for path in paths {
        let metadata =
            fs::symlink_metadata(path).map_err(|e| failure::io(path, FsOp::Inspect, &e))?;
        total = total.merge(walk(path, &metadata)?);
    }
    Ok(total.usage())
}

pub(crate) struct Volumes(BTreeMap<u64, u64>);

impl Volumes {
    pub(crate) fn sample<'a>(places: impl IntoIterator<Item = (u64, &'a Path)>) -> Self {
        let mut first: BTreeMap<u64, &Path> = BTreeMap::new();
        for (volume, path) in places {
            first.entry(volume).or_insert(path);
        }
        Self(
            first
                .into_iter()
                .filter_map(|(volume, path)| match platform::free_space(path) {
                    Ok(free) => Some((volume, free)),
                    Err(_unmeasurable) => None,
                })
                .collect(),
        )
    }

    pub(crate) fn gained(&self, after: &Self) -> Option<Bytes> {
        if self.0.is_empty() {
            return None;
        }
        self.0
            .iter()
            .try_fold(Bytes::ZERO, |total, (volume, before)| {
                let after = after.0.get(volume)?;
                Some(total.saturating_add(Bytes::new(after.saturating_sub(*before))))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_measured_is_nothing_observed() {
        let nothing = Volumes(BTreeMap::new());
        assert_eq!(nothing.gained(&Volumes(BTreeMap::new())), None);
        let before = Volumes(BTreeMap::from([(1, 10)]));
        assert_eq!(before.gained(&Volumes(BTreeMap::new())), None);
        assert_eq!(
            before.gained(&Volumes(BTreeMap::from([(1, 15)]))),
            Some(Bytes::new(5))
        );
        assert_eq!(
            before.gained(&Volumes(BTreeMap::from([(1, 5)]))),
            Some(Bytes::ZERO)
        );
    }
}
