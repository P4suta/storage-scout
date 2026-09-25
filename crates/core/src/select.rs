use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cmp::Reverse;

use serde::Serialize;

use crate::candidate::{Candidate, CandidateId};
use crate::ownership::Admits;
use crate::size::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Trigger {
    pub min_free: Bytes,
    pub target_free: Option<Bytes>,
}

impl Trigger {
    #[must_use]
    pub fn goal(self) -> Bytes {
        self.target_free.unwrap_or(self.min_free)
    }

    #[must_use]
    pub fn pressure(self, free: Bytes) -> Option<Pressed> {
        (free < self.min_free).then(|| Pressed { goal: self.goal() })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pressed {
    goal: Bytes,
}

impl Pressed {
    #[must_use]
    pub const fn goal(self) -> Bytes {
        self.goal
    }

    #[must_use]
    pub fn relieved(self, free: Bytes) -> bool {
        free >= self.goal
    }
}

#[must_use]
pub fn reap(candidates: &[Candidate]) -> Vec<CandidateId> {
    candidates
        .iter()
        .filter(|candidate| Admits::Settled.admits(candidate.settlement()))
        .filter(|candidate| candidate.usage().reclaimable().is_some())
        .map(|candidate| candidate.id().clone())
        .collect()
}

#[must_use]
pub fn eviction_order(candidates: &[Candidate]) -> Vec<CandidateId> {
    let mut evictable = candidates
        .iter()
        .filter(|candidate| Admits::Evictable.admits(candidate.settlement()))
        .filter(|candidate| !Admits::Settled.admits(candidate.settlement()))
        .filter_map(|candidate| {
            candidate
                .usage()
                .reclaimable()
                .filter(|reclaimable| *reclaimable > Bytes::ZERO)
                .map(|reclaimable| (candidate, reclaimable))
        })
        .collect::<Vec<_>>();
    evictable.sort_by(|(left, left_bytes), (right, right_bytes)| {
        (left.tier(), Reverse(*left_bytes), left.location()).cmp(&(
            right.tier(),
            Reverse(*right_bytes),
            right.location(),
        ))
    });
    evictable
        .into_iter()
        .map(|(candidate, _)| candidate.id().clone())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stop {
    NotBelowTrigger,
    GoalReached,
    NoProgress,
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Take(CandidateId),
    Stop(Stop),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Deleted,
    Kept,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eviction {
    goal: Bytes,
    free: Bytes,
    queue: VecDeque<CandidateId>,
}

impl Eviction {
    #[must_use]
    pub fn begin(trigger: Trigger, free: Bytes, order: Vec<CandidateId>) -> (Self, Step) {
        match trigger.pressure(free) {
            Some(pressed) => Self::resume(pressed, free, order),
            None => (
                Self {
                    goal: trigger.goal(),
                    free,
                    queue: order.into(),
                },
                Step::Stop(Stop::NotBelowTrigger),
            ),
        }
    }

    #[must_use]
    pub fn resume(pressed: Pressed, free: Bytes, order: Vec<CandidateId>) -> (Self, Step) {
        let mut eviction = Self {
            goal: pressed.goal,
            free,
            queue: order.into(),
        };
        let step = eviction.next();
        (eviction, step)
    }

    #[must_use]
    pub const fn goal(&self) -> Bytes {
        self.goal
    }

    fn next(&mut self) -> Step {
        if self.free >= self.goal {
            return Step::Stop(Stop::GoalReached);
        }
        self.queue
            .pop_front()
            .map_or(Step::Stop(Stop::Exhausted), Step::Take)
    }

    pub fn observe(&mut self, effect: Effect, free: Bytes) -> Step {
        let progressed = free > self.free;
        self.free = free;
        match (effect, progressed) {
            (Effect::Deleted, false) => Step::Stop(Stop::NoProgress),
            (Effect::Deleted, true) | (Effect::Kept, _) => self.next(),
        }
    }
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

    #[test]
    fn eviction_orders_by_cost_then_size_then_path_and_leaves_settled_to_reaping() {
        let small = candidate(1, Tier::Routine, 10, active());
        let large = candidate(2, Tier::Routine, 20, Ownership::Nothing);
        let venv = candidate(3, Tier::Reinstallable, 100, active());
        let settled = candidate(4, Tier::Routine, 50, landed());
        let order = eviction_order(&[venv.clone(), small.clone(), settled, large.clone()]);
        assert_eq!(
            order,
            vec![large.id().clone(), small.id().clone(), venv.id().clone()]
        );
    }

    #[test]
    fn a_candidate_that_would_free_nothing_is_never_evicted() {
        let empty = candidate(1, Tier::Routine, 0, active());
        let full = candidate(2, Tier::Routine, 1, active());
        assert_eq!(
            eviction_order(&[empty, full.clone()]),
            vec![full.id().clone()]
        );
    }

    fn ids(count: u64) -> Vec<CandidateId> {
        (0..count)
            .map(|seed| candidate(seed, Tier::Routine, 1, active()).id().clone())
            .collect()
    }

    const TRIGGER: Trigger = Trigger {
        min_free: Bytes::new(100),
        target_free: Some(Bytes::new(150)),
    };

    #[test]
    fn at_or_above_the_trigger_nothing_is_taken() {
        let (_, step) = Eviction::begin(TRIGGER, Bytes::new(100), ids(3));
        assert_eq!(step, Step::Stop(Stop::NotBelowTrigger));
    }

    #[test]
    fn eviction_stops_exactly_when_the_measured_goal_is_reached() {
        let order = ids(3);
        let (mut eviction, first) = Eviction::begin(TRIGGER, Bytes::new(90), order.clone());
        assert_eq!(first, Step::Take(order[0].clone()));
        assert_eq!(
            eviction.observe(Effect::Deleted, Bytes::new(149)),
            Step::Take(order[1].clone())
        );
        assert_eq!(
            eviction.observe(Effect::Deleted, Bytes::new(150)),
            Step::Stop(Stop::GoalReached)
        );
    }

    #[test]
    fn a_deletion_that_frees_nothing_stops_the_eviction() {
        let (mut eviction, _) = Eviction::begin(TRIGGER, Bytes::new(90), ids(3));
        assert_eq!(
            eviction.observe(Effect::Deleted, Bytes::new(90)),
            Step::Stop(Stop::NoProgress)
        );
    }

    #[test]
    fn a_kept_candidate_moves_on_and_running_out_is_reported() {
        let order = ids(2);
        let (mut eviction, _) = Eviction::begin(TRIGGER, Bytes::new(90), order.clone());
        assert_eq!(
            eviction.observe(Effect::Kept, Bytes::new(90)),
            Step::Take(order[1].clone())
        );
        assert_eq!(
            eviction.observe(Effect::Kept, Bytes::new(90)),
            Step::Stop(Stop::Exhausted)
        );
    }

    #[test]
    fn without_a_target_the_goal_is_the_trigger() {
        let trigger = Trigger {
            min_free: Bytes::new(100),
            target_free: None,
        };
        let (eviction, _) = Eviction::begin(trigger, Bytes::ZERO, ids(1));
        assert_eq!(eviction.goal(), Bytes::new(100));
    }

    #[test]
    fn pressure_lasts_until_the_goal_even_above_the_trigger() {
        let pressed = TRIGGER.pressure(Bytes::new(90)).unwrap();
        assert_eq!(TRIGGER.pressure(Bytes::new(100)), None);
        assert!(!pressed.relieved(Bytes::new(105)));
        assert!(pressed.relieved(pressed.goal()));
        let (_, short) = Eviction::resume(pressed, Bytes::new(105), ids(2));
        assert!(matches!(short, Step::Take(_)));
        let (_, reached) = Eviction::resume(pressed, pressed.goal(), ids(2));
        assert_eq!(reached, Step::Stop(Stop::GoalReached));
    }
}
