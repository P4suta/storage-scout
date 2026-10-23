use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::Serialize;

use crate::candidate::Identity;
use crate::location::Location;
use crate::reject::IoFailure;

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum Settlement {
        Released,
        Landed,
        Active,
        Kept,
        Unclaimed,
    }
}

impl Settlement {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::Landed => "landed",
            Self::Active => "active",
            Self::Kept => "kept",
            Self::Unclaimed => "unclaimed",
        }
    }
}

impl fmt::Display for Settlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Scratch,
    Cache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Keep {
    Kept,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerLock {
    Held,
    Free,
    Missing,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseEvidence {
    pub recorded_identity: Identity,
    pub identity: Identity,
    pub recorded_digest: [u8; 32],
    pub digest: [u8; 32],
    pub monitor: OwnerLock,
    pub writers: OwnerLock,
}

const RELEASE_TAG: &[u8; 16] = b"scout-release-v1";
const SHA256_BYTES: usize = 32;
pub const RELEASE_RECORD_BYTES: usize =
    RELEASE_TAG.len() + size_of::<u64>() + size_of::<u128>() + SHA256_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseRecord {
    pub identity: Identity,
    pub digest: [u8; 32],
}

impl ReleaseRecord {
    #[must_use]
    pub const fn encode(self) -> [u8; RELEASE_RECORD_BYTES] {
        let mut bytes = [0; RELEASE_RECORD_BYTES];
        let (tag, tail) = bytes.split_at_mut(RELEASE_TAG.len());
        let (volume, tail) = tail.split_at_mut(size_of::<u64>());
        let (file, digest) = tail.split_at_mut(size_of::<u128>());
        tag.copy_from_slice(RELEASE_TAG);
        volume.copy_from_slice(&self.identity.volume.to_le_bytes());
        file.copy_from_slice(&self.identity.file.to_le_bytes());
        digest.copy_from_slice(&self.digest);
        bytes
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        const TAG_BYTES: usize = RELEASE_TAG.len();
        const VOLUME_BYTES: usize = size_of::<u64>();
        const FILE_BYTES: usize = size_of::<u128>();
        if bytes.len() != RELEASE_RECORD_BYTES {
            return None;
        }
        let (tag, bytes) = bytes.split_first_chunk::<TAG_BYTES>()?;
        if tag != RELEASE_TAG {
            return None;
        }
        let (volume, bytes) = bytes.split_first_chunk::<VOLUME_BYTES>()?;
        let (file, bytes) = bytes.split_first_chunk::<FILE_BYTES>()?;
        let (digest, tail) = bytes.split_first_chunk::<SHA256_BYTES>()?;
        if !tail.is_empty() {
            return None;
        }
        Some(Self {
            identity: Identity {
                volume: u64::from_le_bytes(*volume),
                file: u128::from_le_bytes(*file),
            },
            digest: *digest,
        })
    }
}

impl ReleaseEvidence {
    #[must_use]
    pub fn settlement(&self) -> Settlement {
        if self.recorded_identity == self.identity
            && self.recorded_digest == self.digest
            && self.monitor == OwnerLock::Held
            && self.writers == OwnerLock::Free
        {
            Settlement::Released
        } else {
            Settlement::Active
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Key {
    Unkeyed,
    Present,
    Gone,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Marker {
    pub directory: Location,
    pub schema: String,
    pub role: Role,
    pub keep: Keep,
    pub lock: OwnerLock,
    pub key: Key,
}

impl Marker {
    #[must_use]
    pub const fn settlement(&self) -> Settlement {
        match (self.keep, self.lock, self.role, self.key) {
            (Keep::Kept, _, _, _) => Settlement::Kept,
            (
                Keep::Released,
                OwnerLock::Held | OwnerLock::Missing | OwnerLock::Unreadable,
                _,
                _,
            )
            | (
                Keep::Released,
                OwnerLock::Free,
                Role::Cache,
                Key::Unkeyed | Key::Present | Key::Unknown,
            ) => Settlement::Active,
            (Keep::Released, OwnerLock::Free, Role::Scratch, _)
            | (Keep::Released, OwnerLock::Free, Role::Cache, Key::Gone) => Settlement::Released,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Changes {
    Clean,
    Dirty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "head", rename_all = "kebab-case")]
pub enum Head {
    Branch { name: String, upstream: Upstream },
    Detached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "upstream", rename_all = "kebab-case")]
pub enum Upstream {
    None,
    Tracking { name: String },
    Gone { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "landing", rename_all = "kebab-case")]
pub enum Landing {
    NoDefaultBranch,
    NoOwnWork { into: String },
    Contained { into: String },
    NotContained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "worktree", rename_all = "kebab-case")]
pub enum Worktree {
    Released {
        root: Location,
        evidence: ReleaseEvidence,
    },
    Primary {
        root: Location,
    },
    Linked {
        root: Location,
        changes: Changes,
        head: Head,
        landing: Landing,
    },
    Orphaned {
        root: Location,
    },
    Unreadable {
        root: Location,
        failure: GitFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "cause", rename_all = "kebab-case")]
pub enum GitFailure {
    Unavailable {
        failure: IoFailure,
    },
    Refused {
        query: &'static str,
        code: Option<i32>,
    },
    Unparsable {
        query: &'static str,
    },
}

impl Worktree {
    #[must_use]
    pub fn settlement(&self) -> Settlement {
        match self {
            Self::Released { evidence, .. } => evidence.settlement(),
            Self::Primary { .. }
            | Self::Unreadable { .. }
            | Self::Linked {
                changes: Changes::Dirty,
                ..
            } => Settlement::Active,
            Self::Orphaned { .. } => Settlement::Released,
            Self::Linked {
                changes: Changes::Clean,
                head,
                landing,
                ..
            } => match (head, landing) {
                (
                    Head::Branch {
                        upstream: Upstream::Gone { .. },
                        ..
                    },
                    _,
                )
                | (Head::Branch { .. } | Head::Detached, Landing::Contained { .. })
                | (Head::Detached, Landing::NoOwnWork { .. }) => Settlement::Landed,
                (
                    Head::Branch {
                        upstream: Upstream::None | Upstream::Tracking { .. },
                        ..
                    },
                    Landing::NoOwnWork { .. } | Landing::NotContained | Landing::NoDefaultBranch,
                )
                | (Head::Detached, Landing::NotContained | Landing::NoDefaultBranch) => {
                    Settlement::Active
                },
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "kebab-case")]
pub enum Ownership {
    Markers {
        markers: Vec<Marker>,
    },
    Worktree {
        worktree: Worktree,
    },
    Holders {
        holders: Vec<Marker>,
        worktree: Option<Worktree>,
    },
    Nothing,
}

const fn protects(settlement: Settlement) -> bool {
    match settlement {
        Settlement::Active | Settlement::Kept => true,
        Settlement::Released | Settlement::Landed | Settlement::Unclaimed => false,
    }
}

fn strongest(settlements: impl Iterator<Item = Settlement>) -> Settlement {
    settlements
        .max_by_key(|settlement| protection(*settlement))
        .unwrap_or(Settlement::Unclaimed)
}

impl Ownership {
    #[must_use]
    pub fn resolve(own: Vec<Marker>, nested: Vec<Marker>, worktree: Option<Worktree>) -> Self {
        let holders = nested
            .into_iter()
            .filter(|marker| protects(marker.settlement()))
            .collect::<Vec<_>>();
        match (own.is_empty(), holders.is_empty(), worktree) {
            (false, _, _) => Self::Markers {
                markers: own.into_iter().chain(holders).collect(),
            },
            (true, false, worktree) => Self::Holders { holders, worktree },
            (true, true, Some(worktree)) => Self::Worktree { worktree },
            (true, true, None) => Self::Nothing,
        }
    }

    #[must_use]
    pub fn settlement(&self) -> Settlement {
        match self {
            Self::Markers { markers } => strongest(markers.iter().map(Marker::settlement)),
            Self::Worktree { worktree } => worktree.settlement(),
            Self::Holders { holders, worktree } => strongest(
                holders
                    .iter()
                    .map(Marker::settlement)
                    .chain(worktree.iter().map(Worktree::settlement)),
            ),
            Self::Nothing => Settlement::Unclaimed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Protection {
    Released,
    Landed,
    Unclaimed,
    Active,
    Kept,
}

const fn protection(settlement: Settlement) -> Protection {
    match settlement {
        Settlement::Kept => Protection::Kept,
        Settlement::Active => Protection::Active,
        Settlement::Unclaimed => Protection::Unclaimed,
        Settlement::Landed => Protection::Landed,
        Settlement::Released => Protection::Released,
    }
}

#[cfg(kani)]
mod proofs {
    use super::{Settlement, strongest};

    #[kani::proof]
    #[kani::unwind(4)]
    fn strongest_ownership_protection_is_ordered() {
        let ordered = [
            Settlement::Released,
            Settlement::Landed,
            Settlement::Unclaimed,
            Settlement::Active,
            Settlement::Kept,
        ];
        let left: usize = kani::any();
        let right: usize = kani::any();
        kani::assume(left < ordered.len() && right < ordered.len());
        let strongest = strongest([ordered[left], ordered[right]].into_iter());
        assert_eq!(strongest, ordered[left.max(right)]);
        kani::cover!(strongest == Settlement::Kept);
        kani::cover!(strongest == Settlement::Active);
        kani::cover!(strongest == Settlement::Released);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Admits {
    Anything,
    Settled,
    Unkept,
}

#[derive(Debug)]
pub(crate) struct DeletionGrant(());

impl DeletionGrant {
    pub(crate) const fn new(admits: Admits, settlement: Settlement) -> Option<Self> {
        if admits.deletion(settlement) {
            Some(Self(()))
        } else {
            None
        }
    }
}

impl Admits {
    #[must_use]
    pub const fn deletion(self, settlement: Settlement) -> bool {
        Self::Settled.admits(settlement) && self.admits(settlement)
    }

    #[must_use]
    pub const fn admits(self, settlement: Settlement) -> bool {
        match (self, settlement) {
            (Self::Anything, _)
            | (Self::Settled, Settlement::Released | Settlement::Landed)
            | (
                Self::Unkept,
                Settlement::Released
                | Settlement::Landed
                | Settlement::Active
                | Settlement::Unclaimed,
            ) => true,
            (Self::Settled, Settlement::Active | Settlement::Unclaimed | Settlement::Kept)
            | (Self::Unkept, Settlement::Kept) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::vec;

    use super::*;
    use crate::location::Syntax;

    fn at(path: &str) -> Location {
        Location::parse_str(Syntax::Unix, path).unwrap()
    }

    fn marker(role: Role, keep: Keep, lock: OwnerLock, key: Key) -> Marker {
        Marker {
            directory: at("/tmp/run"),
            schema: "njutest-temp-owner-v1".to_owned(),
            role,
            keep,
            lock,
            key,
        }
    }

    #[test]
    fn every_deletion_grant_requires_released_or_landed_ownership() {
        for admits in [Admits::Anything, Admits::Settled, Admits::Unkept] {
            for settlement in Settlement::ALL {
                let expected = matches!(settlement, Settlement::Released | Settlement::Landed);
                assert_eq!(DeletionGrant::new(admits, *settlement).is_some(), expected);
            }
        }
    }

    fn linked(changes: Changes, head: Head, landing: Landing) -> Worktree {
        Worktree::Linked {
            root: at("/work/tree"),
            changes,
            head,
            landing,
        }
    }

    fn branch(upstream: Upstream) -> Head {
        Head::Branch {
            name: "feat".to_owned(),
            upstream,
        }
    }

    #[test]
    fn a_marker_is_released_only_when_its_owner_let_go_of_a_scratch_or_a_forgotten_cache() {
        use {Keep::*, Key::*, OwnerLock::*, Role::*};
        assert_eq!(
            marker(Scratch, Released, Free, Unkeyed).settlement(),
            Settlement::Released
        );
        assert_eq!(
            marker(Cache, Released, Free, Gone).settlement(),
            Settlement::Released
        );
        assert_eq!(
            marker(Cache, Released, Free, Present).settlement(),
            Settlement::Active
        );
        assert_eq!(
            marker(Cache, Released, Free, Unknown).settlement(),
            Settlement::Active
        );
        assert_eq!(
            marker(Scratch, Released, Held, Unkeyed).settlement(),
            Settlement::Active
        );
        assert_eq!(
            marker(Scratch, Released, Missing, Unkeyed).settlement(),
            Settlement::Active
        );
        assert_eq!(
            marker(Scratch, Released, Unreadable, Unkeyed).settlement(),
            Settlement::Active
        );
        assert_eq!(
            marker(Scratch, Kept, Free, Unkeyed).settlement(),
            Settlement::Kept
        );
    }

    #[test]
    fn the_most_protective_marker_wins() {
        let released = marker(Role::Scratch, Keep::Released, OwnerLock::Free, Key::Unkeyed);
        let kept = marker(Role::Scratch, Keep::Kept, OwnerLock::Free, Key::Unkeyed);
        let held = marker(Role::Scratch, Keep::Released, OwnerLock::Held, Key::Unkeyed);
        let busy = Ownership::resolve(vec![released.clone(), held.clone()], Vec::new(), None);
        assert_eq!(busy.settlement(), Settlement::Active);
        let kept = Ownership::resolve(vec![held, kept, released], Vec::new(), None);
        assert_eq!(kept.settlement(), Settlement::Kept);
    }

    #[test]
    fn a_marker_inside_protects_what_holds_it_and_never_lets_it_go() {
        let released = marker(Role::Scratch, Keep::Released, OwnerLock::Free, Key::Unkeyed);
        let held = marker(Role::Scratch, Keep::Released, OwnerLock::Held, Key::Unkeyed);
        let kept = marker(Role::Scratch, Keep::Kept, OwnerLock::Free, Key::Unkeyed);
        let orphaned = Worktree::Orphaned { root: at("/work") };
        let primary = Worktree::Primary { root: at("/work") };
        assert_eq!(
            Ownership::resolve(Vec::new(), vec![released.clone()], Some(primary.clone())),
            Ownership::Worktree { worktree: primary }
        );
        assert_eq!(
            Ownership::resolve(Vec::new(), vec![released.clone()], None),
            Ownership::Nothing
        );
        let holding = Ownership::resolve(Vec::new(), vec![held.clone()], Some(orphaned.clone()));
        assert_eq!(holding.settlement(), Settlement::Active);
        assert_eq!(
            Ownership::resolve(Vec::new(), vec![released.clone()], Some(orphaned.clone()))
                .settlement(),
            Settlement::Released
        );
        assert_eq!(
            Ownership::resolve(Vec::new(), vec![kept.clone()], None).settlement(),
            Settlement::Kept
        );
        assert_eq!(
            Ownership::resolve(vec![released.clone()], vec![held], None).settlement(),
            Settlement::Active
        );
        assert_eq!(
            Ownership::resolve(vec![released.clone()], vec![released], None).settlement(),
            Settlement::Released
        );
        assert_eq!(
            Ownership::Holders {
                holders: vec![kept],
                worktree: Some(orphaned)
            }
            .settlement(),
            Settlement::Kept
        );
    }

    #[test]
    fn markers_govern_over_git() {
        let released = marker(Role::Scratch, Keep::Released, OwnerLock::Free, Key::Unkeyed);
        let primary = Worktree::Primary { root: at("/work") };
        assert_eq!(
            Ownership::resolve(vec![released], Vec::new(), Some(primary.clone())).settlement(),
            Settlement::Released
        );
        assert_eq!(
            Ownership::resolve(Vec::new(), Vec::new(), Some(primary)).settlement(),
            Settlement::Active
        );
        assert_eq!(
            Ownership::resolve(Vec::new(), Vec::new(), None).settlement(),
            Settlement::Unclaimed
        );
    }

    #[test]
    fn a_worktree_has_landed_only_when_clean_and_its_work_is_upstream() {
        let into = || "refs/remotes/origin/main".to_owned();
        let tracking = || Upstream::Tracking {
            name: "origin/feat".to_owned(),
        };
        let gone = || Upstream::Gone {
            name: "origin/feat".to_owned(),
        };
        let cases = [
            (
                Changes::Clean,
                branch(tracking()),
                Landing::Contained { into: into() },
                Settlement::Landed,
            ),
            (
                Changes::Clean,
                branch(gone()),
                Landing::NotContained,
                Settlement::Landed,
            ),
            (
                Changes::Clean,
                Head::Detached,
                Landing::NoOwnWork { into: into() },
                Settlement::Landed,
            ),
            (
                Changes::Clean,
                Head::Detached,
                Landing::Contained { into: into() },
                Settlement::Landed,
            ),
            (
                Changes::Clean,
                branch(tracking()),
                Landing::NoOwnWork { into: into() },
                Settlement::Active,
            ),
            (
                Changes::Clean,
                branch(tracking()),
                Landing::NotContained,
                Settlement::Active,
            ),
            (
                Changes::Clean,
                Head::Detached,
                Landing::NotContained,
                Settlement::Active,
            ),
            (
                Changes::Clean,
                Head::Detached,
                Landing::NoDefaultBranch,
                Settlement::Active,
            ),
            (
                Changes::Dirty,
                branch(gone()),
                Landing::Contained { into: into() },
                Settlement::Active,
            ),
            (
                Changes::Dirty,
                Head::Detached,
                Landing::NoOwnWork { into: into() },
                Settlement::Active,
            ),
        ];
        for (changes, head, landing, expected) in cases {
            let worktree = linked(changes, head.clone(), landing.clone());
            assert_eq!(
                worktree.settlement(),
                expected,
                "{changes:?} {head:?} {landing:?}"
            );
        }
        assert_eq!(
            Worktree::Primary { root: at("/work") }.settlement(),
            Settlement::Active
        );
        assert_eq!(
            Worktree::Orphaned { root: at("/work") }.settlement(),
            Settlement::Released
        );
    }

    #[test]
    fn nothing_admits_kept_but_a_person() {
        for settlement in Settlement::ALL {
            assert!(Admits::Anything.admits(*settlement));
        }
        assert!(!Admits::Settled.admits(Settlement::Active));
        assert!(!Admits::Settled.admits(Settlement::Kept));
        assert!(!Admits::Settled.admits(Settlement::Unclaimed));
        assert!(Admits::Settled.admits(Settlement::Released));
        assert!(Admits::Settled.admits(Settlement::Landed));
        assert!(!Admits::Unkept.admits(Settlement::Kept));
        assert!(Admits::Unkept.admits(Settlement::Active));
        assert!(Admits::Unkept.admits(Settlement::Unclaimed));
    }
}
