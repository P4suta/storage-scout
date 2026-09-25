use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use serde::Serialize;

pub const OBJECT_SUFFIX: &[u8] = b".rcgu.o";
pub const INCREMENTAL: &str = "incremental";
pub const OBJECT_DIRECTORIES: [&str; 2] = ["deps", "examples"];
pub const LOCK_SUFFIX: &[u8] = b".lock";

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum Rule {
        StaleObject,
        SupersededSession,
        AbandonedSession,
    }
}

impl Rule {
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::StaleObject => {
                "debug object of an earlier rustc run that the unit's linked image no longer names"
            },
            Self::SupersededSession => {
                "incremental session older than the one rustc loads next and deletes the rest"
            },
            Self::AbandonedSession => "incremental session whose rustc ended before finishing it",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Object<'a> {
    pub name: &'a [u8],
    pub unit: &'a [u8],
    pub invocation: &'a [u8],
}

impl<'a> Object<'a> {
    #[must_use]
    pub fn parse(name: &'a [u8]) -> Option<Self> {
        let stem = name.strip_suffix(OBJECT_SUFFIX)?;
        let mut parts = stem.split(|byte| *byte == b'.');
        let unit = parts.next()?;
        let unit_part = parts.next()?;
        let invocation = parts.next()?;
        if parts.next().is_some()
            || [unit, unit_part, invocation]
                .iter()
                .any(|part| part.is_empty())
        {
            return None;
        }
        Some(Self {
            name,
            unit,
            invocation,
        })
    }
}

#[must_use]
pub fn mixed<'a>(objects: &[Object<'a>]) -> BTreeSet<&'a [u8]> {
    let mut invocations = BTreeMap::<&[u8], BTreeSet<&[u8]>>::new();
    for object in objects {
        invocations
            .entry(object.unit)
            .or_default()
            .insert(object.invocation);
    }
    invocations
        .into_iter()
        .filter(|(_, seen)| seen.len() > 1)
        .map(|(unit, _)| unit)
        .collect()
}

#[must_use]
pub fn images(unit: &[u8]) -> [Vec<u8>; 2] {
    [unit.to_vec(), [b"lib", unit, b".dylib"].concat()]
}

#[must_use]
pub fn stale<'a>(
    objects: &[Object<'a>],
    unit: &[u8],
    referenced: &BTreeSet<Vec<u8>>,
) -> Vec<&'a [u8]> {
    objects
        .iter()
        .filter(|object| object.unit == unit && !referenced.contains(object.name))
        .map(|object| object.name)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Finalized { stamp: u128 },
    Working,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session<'a> {
    pub name: &'a [u8],
    pub lock: &'a [u8],
    pub stage: Stage,
}

fn base36(digits: &[u8]) -> Option<u128> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u128, |value, digit| {
        let digit = match digit {
            b'0'..=b'9' => digit.checked_sub(b'0'),
            b'a'..=b'z' => digit.checked_sub(b'a').and_then(|at| at.checked_add(10)),
            _ => None,
        }?;
        value.checked_mul(36)?.checked_add(u128::from(digit))
    })
}

impl<'a> Session<'a> {
    #[must_use]
    pub fn parse(name: &'a [u8]) -> Option<Self> {
        let mut parts = name.split(|byte| *byte == b'-');
        if parts.next()? != b"s" {
            return None;
        }
        let stamp = parts.next()?;
        let random = parts.next()?;
        let last = parts.next()?;
        if parts.next().is_some() || base36(random).is_none() {
            return None;
        }
        let stamp = base36(stamp)?;
        let stage = if last == b"working" {
            Stage::Working
        } else {
            base36(last)?;
            Stage::Finalized { stamp }
        };
        let lock = name.get(..name.len().checked_sub(last.len())?.checked_sub(1)?)?;
        Some(Self { name, lock, stage })
    }

    #[must_use]
    pub fn lock_name(&self) -> Vec<u8> {
        [self.lock, LOCK_SUFFIX].concat()
    }
}

#[must_use]
pub fn doomed<'a>(sessions: &[Session<'a>]) -> Vec<(Session<'a>, Rule)> {
    let newest = sessions
        .iter()
        .filter_map(|session| match session.stage {
            Stage::Finalized { stamp } => Some(stamp),
            Stage::Working => None,
        })
        .max();
    sessions
        .iter()
        .filter_map(|session| match (session.stage, newest) {
            (Stage::Working, _) => Some((*session, Rule::AbandonedSession)),
            (Stage::Finalized { stamp }, Some(newest)) if stamp < newest => {
                Some((*session, Rule::SupersededSession))
            },
            (Stage::Finalized { .. }, _) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn an_object_name_is_a_unit_a_codegen_unit_and_an_invocation() {
        let object = Object::parse(b"njutest-67b3.01jb2x.1tf6hyx.rcgu.o").unwrap();
        assert_eq!(object.unit, b"njutest-67b3");
        assert_eq!(object.invocation, b"1tf6hyx");
        for name in [
            &b"njutest-67b3.01jb2x.rcgu.o"[..],
            b"a.b.c.d.rcgu.o",
            b".b.c.rcgu.o",
            b"a..c.rcgu.o",
            b"a.b..rcgu.o",
            b"a.b.c.o",
            b"libx-1.rlib",
        ] {
            assert_eq!(Object::parse(name), None, "{name:?}");
        }
    }

    fn objects<'a>(names: &[&'a [u8]]) -> Vec<Object<'a>> {
        names
            .iter()
            .map(|name| Object::parse(name).unwrap())
            .collect()
    }

    #[test]
    fn only_a_unit_with_objects_from_two_runs_can_hold_stale_ones() {
        let found = objects(&[
            b"a-1.x.one.rcgu.o",
            b"a-1.y.one.rcgu.o",
            b"b-2.x.one.rcgu.o",
            b"b-2.x.two.rcgu.o",
        ]);
        assert_eq!(mixed(&found), BTreeSet::from([&b"b-2"[..]]));
    }

    #[test]
    fn stale_objects_are_those_of_the_unit_its_images_do_not_name() {
        let found = objects(&[
            b"b-2.x.one.rcgu.o",
            b"b-2.x.two.rcgu.o",
            b"b-2.y.two.rcgu.o",
            b"c-3.x.one.rcgu.o",
        ]);
        let named = BTreeSet::from([b"b-2.x.two.rcgu.o".to_vec(), b"b-2.y.two.rcgu.o".to_vec()]);
        assert_eq!(
            stale(&found, b"b-2", &named),
            vec![&b"b-2.x.one.rcgu.o"[..]]
        );
        assert_eq!(
            stale(&found, b"b-2", &BTreeSet::new()),
            vec![
                &b"b-2.x.one.rcgu.o"[..],
                b"b-2.x.two.rcgu.o",
                b"b-2.y.two.rcgu.o"
            ]
        );
        assert_eq!(images(b"b-2"), [b"b-2".to_vec(), b"libb-2.dylib".to_vec()]);
    }

    #[test]
    fn a_session_name_carries_its_stage_and_lock() {
        let finalized = Session::parse(b"s-hml9l00hya-1spx8v6-503beytbg5g2o7").unwrap();
        assert_eq!(finalized.lock, b"s-hml9l00hya-1spx8v6");
        assert_eq!(finalized.lock_name(), b"s-hml9l00hya-1spx8v6.lock");
        assert!(matches!(finalized.stage, Stage::Finalized { .. }));
        let working = Session::parse(b"s-hml9l00hya-1spx8v6-working").unwrap();
        assert_eq!(working.stage, Stage::Working);
        assert_eq!(working.lock, b"s-hml9l00hya-1spx8v6");
        for name in [
            &b"s-hml9l00hya-1spx8v6.lock"[..],
            b"s-hml9l00hya-1spx8v6",
            b"s-hml9l00hya-1spx8v6-abc-def",
            b"x-hml9l00hya-1spx8v6-abc",
            b"s-HML9-1spx8v6-abc",
            b"s--1spx8v6-abc",
            b"s-a-b-",
            b"s-a--c",
            b"s-a-b-c!",
        ] {
            assert_eq!(Session::parse(name), None, "{name:?}");
        }
    }

    #[test]
    fn stamps_order_as_rustc_orders_them() {
        assert_eq!(base36(b"0"), Some(0));
        assert_eq!(base36(b"z"), Some(35));
        assert_eq!(base36(b"10"), Some(36));
        assert_eq!(base36(b"a0"), Some(360));
        assert_eq!(base36(&[b'z'; 30]), None);
        assert_eq!(base36(b""), None);
        assert_eq!(base36(b"a/"), None);
        assert_eq!(base36(b"a{"), None);
    }

    fn session(name: &'static [u8]) -> Session<'static> {
        Session::parse(name).unwrap()
    }

    #[test]
    fn rustc_keeps_its_newest_session_and_drops_the_rest() {
        let old = session(b"s-a1-x-aaa");
        let new = session(b"s-b1-y-bbb");
        let tied = session(b"s-b1-z-ccc");
        let working = session(b"s-c1-w-working");
        assert_eq!(
            doomed(&[new, working, old, tied]),
            vec![
                (working, Rule::AbandonedSession),
                (old, Rule::SupersededSession)
            ]
        );
        assert_eq!(doomed(&[new]), vec![]);
        assert_eq!(doomed(&[working]), vec![(working, Rule::AbandonedSession)]);
    }
}
