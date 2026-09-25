#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "generated fixtures are small and a fixture that cannot be built is a broken test"
)]

use proptest::prelude::*;
use storage_scout_core::area::Protection;
use storage_scout_core::artifact::{CacheTag, Entries, Listing, Tags};
use storage_scout_core::candidate::{
    Allocation, Candidate, Contents, Identity, Measurement, Observed, Usage,
};
use storage_scout_core::gate::{Boundary, Shape, Site, admit};
use storage_scout_core::location::{Case, Location, Syntax};
use storage_scout_core::ownership::Ownership;
use storage_scout_core::select::{Effect, Eviction, Step, Stop, Trigger, eviction_order};
use storage_scout_core::size::Bytes;

fn component() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_-][a-zA-Z0-9._-]{0,7}")
        .unwrap()
        .prop_filter("navigation is not a name", |part| {
            part != "." && part != ".."
        })
}

fn location(parts: &[String]) -> Location {
    Location::parse_str(Syntax::Unix, &format!("/{}", parts.join("/"))).unwrap()
}

fn candidates(shapes: &[(u8, u64)]) -> Vec<Candidate> {
    let protection = Protection::new(
        Syntax::Unix,
        Case::Sensitive,
        Location::parse_str(Syntax::Unix, "/cwd").unwrap(),
        Location::parse_str(Syntax::Unix, "/bin/x").unwrap(),
        Vec::new(),
    )
    .unwrap();
    shapes
        .iter()
        .enumerate()
        .map(|(index, &(tier, size))| {
            let mut parent = Entries::default();
            let (name, tag) = match tier {
                0 => {
                    parent.file(b"Cargo.toml");
                    ("target", CacheTag::Absent)
                },
                1 => ("cache", CacheTag::Verified),
                _ => {
                    parent.dir(b"Assets");
                    parent.dir(b"ProjectSettings");
                    ("Library", CacheTag::Absent)
                },
            };
            let listing = Listing::new(parent, Entries::default(), Tags::cache(tag));
            let path = Location::parse_str(Syntax::Unix, &format!("/work/{index}/{name}")).unwrap();
            let site = Site {
                location: &path,
                shape: Shape::Directory,
                boundary: Boundary::Same { device: 1 },
                listing: &listing,
                protection: &protection,
                excludes: &[],
            };
            let bytes = Bytes::new(size * 1000);
            let measurement = Measurement {
                usage: Usage {
                    logical: bytes,
                    allocation: Allocation::Measured {
                        allocated: bytes,
                        reclaimable: bytes,
                    },
                },
                contents: Contents::ZERO,
            };
            let identity = Identity {
                volume: 1,
                file: u128::try_from(index).unwrap(),
            };
            Candidate::new(
                admit(&site).unwrap(),
                Observed {
                    identity,
                    measurement,
                    ownership: Ownership::Nothing,
                },
                Case::Sensitive,
            )
        })
        .collect()
}

proptest! {
    #[test]
    fn containment_is_reflexive(parts in prop::collection::vec(component(), 0..6)) {
        let path = location(&parts);
        prop_assert!(path.contains(&path, Case::Sensitive));
        prop_assert!(path.contains(&path, Case::Insensitive));
    }

    #[test]
    fn containment_is_transitive(
        a in prop::collection::vec(component(), 0..3),
        b in prop::collection::vec(component(), 0..3),
        c in prop::collection::vec(component(), 0..3),
    ) {
        let outer = location(&a);
        let middle = location(&[a.clone(), b.clone()].concat());
        let inner = location(&[a, b, c].concat());
        prop_assert!(outer.contains(&middle, Case::Sensitive));
        prop_assert!(middle.contains(&inner, Case::Sensitive));
        prop_assert!(outer.contains(&inner, Case::Sensitive));
    }

    #[test]
    fn containment_both_ways_is_sameness(
        left in prop::collection::vec(component(), 0..5),
        right in prop::collection::vec(component(), 0..5),
    ) {
        let (left, right) = (location(&left), location(&right));
        let both = left.contains(&right, Case::Sensitive) && right.contains(&left, Case::Sensitive);
        prop_assert_eq!(both, left.same(&right, Case::Sensitive));
    }

    #[test]
    fn a_longer_sibling_is_never_contained(base in component(), extra in "[a-z]{1,4}") {
        let outer = location(&["root".to_owned(), base.clone()]);
        let sibling = location(&["root".to_owned(), format!("{base}{extra}")]);
        prop_assert!(!outer.contains(&sibling, Case::Insensitive));
    }

    #[test]
    fn rendering_then_parsing_is_the_same_location(parts in prop::collection::vec(component(), 0..6)) {
        let path = location(&parts);
        let reparsed = Location::parse_str(Syntax::Unix, &path.to_string()).unwrap();
        prop_assert_eq!(reparsed, path);
    }

    #[test]
    fn every_rendered_size_parses_back_within_its_precision(raw in 0u64..u64::MAX / 2) {
        let parsed = Bytes::new(raw).to_string().parse::<Bytes>().unwrap().get();
        let drift = parsed.abs_diff(raw);
        prop_assert!(drift <= raw / 20 + 1024, "{raw} -> {parsed}");
    }

    #[test]
    fn small_sizes_round_trip_exactly(raw in 0u64..1024) {
        prop_assert_eq!(Bytes::new(raw).to_string().parse::<Bytes>().unwrap(), Bytes::new(raw));
    }

    #[test]
    fn size_parsing_never_panics(text in ".*") {
        let _parsed = text.parse::<Bytes>();
    }

    #[test]
    fn at_or_above_the_trigger_nothing_is_taken(min_free in 0u64..1_000_000, excess in 0u64..1_000_000) {
        let trigger = Trigger { min_free: Bytes::new(min_free), target_free: None };
        let order = eviction_order(&candidates(&[(0, 1), (1, 2)]));
        let (_, step) = Eviction::begin(trigger, Bytes::new(min_free.saturating_add(excess)), order);
        prop_assert_eq!(step, Step::Stop(Stop::NotBelowTrigger));
    }

    #[test]
    fn eviction_takes_a_prefix_of_one_order_whatever_the_input_order_and_stops_at_the_goal(
        shapes in prop::collection::vec((0u8..3, 1u64..8), 1..8),
        rotation in 0usize..8,
        excess in 1u64..100_000,
    ) {
        let candidates = candidates(&shapes);
        let order = eviction_order(&candidates);
        let mut rotated = candidates.clone();
        rotated.rotate_left(rotation % candidates.len());
        prop_assert_eq!(&eviction_order(&rotated), &order);

        let trigger = Trigger { min_free: Bytes::new(1_000_000), target_free: Some(Bytes::new(1_000_000 + excess)) };
        let (mut eviction, mut step) = Eviction::begin(trigger, Bytes::ZERO, order.clone());
        let mut free = Bytes::ZERO;
        let mut taken = Vec::new();
        while let Step::Take(id) = step {
            let freed = candidates
                .iter()
                .find(|candidate| candidate.id() == &id)
                .and_then(|candidate| candidate.usage().reclaimable())
                .unwrap();
            free = free.saturating_add(freed);
            taken.push(id);
            step = eviction.observe(Effect::Deleted, free);
        }
        prop_assert_eq!(&taken[..], &order[..taken.len()]);
        match step {
            Step::Stop(Stop::GoalReached) => prop_assert!(free >= eviction.goal()),
            Step::Stop(Stop::Exhausted) => prop_assert_eq!(taken.len(), order.len()),
            other @ (Step::Take(_) | Step::Stop(Stop::NotBelowTrigger | Stop::NoProgress)) => {
                prop_assert!(false, "unexpected {other:?}");
            },
        }
    }
}
