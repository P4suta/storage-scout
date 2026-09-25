use alloc::vec::Vec;

use crate::candidate::{Candidate, CandidateId};
use crate::ownership::Admits;

#[must_use]
pub fn reap(candidates: &[Candidate]) -> Vec<CandidateId> {
    candidates
        .iter()
        .filter(|candidate| Admits::Settled.admits(candidate.settlement()))
        .map(|candidate| candidate.id().clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use super::*;
    use crate::area::Protection;
    use crate::artifact::{CacheTag, Entries, Listing, Tags, Tier};
    use crate::candidate::{Allocation, Contents, Identity, Measurement, Observed, Usage};
    use crate::gate::{Boundary, Shape, Site, admit};
    use crate::location::{Case, Location, Syntax};
    use crate::ownership::{Ownership, Worktree};
    use crate::size::Bytes;

    fn at(path: &str) -> Location {
        Location::parse_str(Syntax::Unix, path).unwrap()
    }

    fn candidate(seed: u64, tier: Tier, reclaimable: u64, ownership: Ownership) -> Candidate {
        let protection = Protection::new(
            Syntax::Unix,
            Case::Sensitive,
            at("/cwd"),
            at("/bin/x"),
            vec![],
        )
        .unwrap();
        let mut parent = Entries::default();
        let (name, tag) = match tier {
            Tier::Routine => {
                parent.file(b"Cargo.toml");
                ("target", CacheTag::Absent)
            },
            Tier::Reinstallable => ("cache", CacheTag::Verified),
            Tier::Expensive => {
                parent.dir(b"Assets");
                parent.dir(b"ProjectSettings");
                ("Library", CacheTag::Absent)
            },
        };
        let listing = Listing::new(parent, Entries::default(), Tags::cache(tag));
        let location = at(&format!("/work/{seed}/{name}"));
        let site = Site {
            location: &location,
            shape: Shape::Directory,
            boundary: Boundary::Same { device: 1 },
            listing: &listing,
            protection: &protection,
            excludes: &[],
        };
        let bytes = Bytes::new(reclaimable);
        Candidate::new(
            admit(&site).unwrap(),
            Observed {
                identity: Identity {
                    volume: 1,
                    file: u128::from(seed),
                },
                measurement: Measurement {
                    usage: Usage {
                        logical: bytes,
                        allocation: Allocation::Measured {
                            allocated: bytes,
                            reclaimable: bytes,
                        },
                    },
                    contents: Contents::ZERO,
                },
                ownership,
            },
            Case::Sensitive,
        )
    }

    fn landed() -> Ownership {
        Ownership::Worktree {
            worktree: Worktree::Orphaned { root: at("/work") },
        }
    }

    fn active() -> Ownership {
        Ownership::Worktree {
            worktree: Worktree::Primary { root: at("/work") },
        }
    }

    #[test]
    fn reaping_takes_exactly_what_has_been_let_go() {
        let settled = candidate(1, Tier::Routine, 10, landed());
        let working = candidate(2, Tier::Routine, 10, active());
        let unclaimed = candidate(3, Tier::Routine, 10, Ownership::Nothing);
        assert_eq!(
            reap(&[settled.clone(), working, unclaimed]),
            vec![settled.id().clone()]
        );
    }
}
