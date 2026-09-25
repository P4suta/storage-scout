use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::Serialize;

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
    pub const fn settlement(&self) -> Settlement {
        match self {
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
    Markers { markers: Vec<Marker> },
    Worktree { worktree: Worktree },
    Nothing,
}

impl Ownership {
    #[must_use]
    pub fn resolve(markers: Vec<Marker>, worktree: Option<Worktree>) -> Self {
        match (markers.is_empty(), worktree) {
            (false, _) => Self::Markers { markers },
            (true, Some(worktree)) => Self::Worktree { worktree },
            (true, None) => Self::Nothing,
        }
    }

    #[must_use]
    pub fn settlement(&self) -> Settlement {
        match self {
            Self::Markers { markers } => markers
                .iter()
                .map(Marker::settlement)
                .max_by_key(|settlement| protection(*settlement))
                .unwrap_or(Settlement::Unclaimed),
            Self::Worktree { worktree } => worktree.settlement(),
            Self::Nothing => Settlement::Unclaimed,
        }
    }
}

const fn protection(settlement: Settlement) -> u8 {
    match settlement {
        Settlement::Kept => 4,
        Settlement::Active => 3,
        Settlement::Unclaimed => 2,
        Settlement::Landed => 1,
        Settlement::Released => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Admits {
    Anything,
    Settled,
    Unkept,
}

impl Admits {
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
        let busy = Ownership::resolve(vec![released.clone(), held.clone()], None);
        assert_eq!(busy.settlement(), Settlement::Active);
        let kept = Ownership::resolve(vec![held, kept, released], None);
        assert_eq!(kept.settlement(), Settlement::Kept);
    }

    #[test]
    fn markers_govern_over_git() {
        let released = marker(Role::Scratch, Keep::Released, OwnerLock::Free, Key::Unkeyed);
        let primary = Worktree::Primary { root: at("/work") };
        assert_eq!(
            Ownership::resolve(vec![released], Some(primary.clone())).settlement(),
            Settlement::Released
        );
        assert_eq!(
            Ownership::resolve(Vec::new(), Some(primary)).settlement(),
            Settlement::Active
        );
        assert_eq!(
            Ownership::resolve(Vec::new(), None).settlement(),
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
