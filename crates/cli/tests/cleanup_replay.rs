#![expect(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "replay builds real fixtures and malformed traces fail the test"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use storage_scout::core::area::{Reach, Rule, SystemReason};
use storage_scout::core::gate::Mandate;
use storage_scout::{Mode, Plan, ScanOptions, Scout, Status};

#[derive(Debug, Deserialize)]
struct Trace {
    states: Vec<Frame>,
}

#[derive(Debug, Deserialize)]
struct Frame {
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Empty,
    Planned,
    Deleted,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Owner {
    Released,
    Active,
    Kept,
    Unclaimed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Init,
    Plan,
    Owner,
    Protect,
    Replace,
    Modify,
    Interrupt,
    Apply,
    Idle,
}

#[derive(Debug, Deserialize)]
struct Integer {
    #[serde(rename = "#bigint")]
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct State {
    phase: Phase,
    owner: Owner,
    protected: bool,
    identity: Integer,
    contents: Integer,
    planned_identity: Integer,
    planned_contents: Integer,
    operation: Operation,
    allowed: bool,
}

fn owner(root: &Path, owner: Owner) {
    match owner {
        Owner::Released => testkit::write_owner_marker(
            root,
            testkit::MarkerRole::Scratch,
            testkit::MarkerKeep::Released,
            None,
        ),
        Owner::Kept => testkit::write_owner_marker(
            root,
            testkit::MarkerRole::Scratch,
            testkit::MarkerKeep::Kept,
            None,
        ),
        Owner::Active => {
            testkit::write_owner_marker(
                root,
                testkit::MarkerRole::Scratch,
                testkit::MarkerKeep::Released,
                None,
            );
            fs::remove_file(root.join("owner.lock")).unwrap();
        },
        Owner::Unclaimed => {
            for path in [root.join("owner.json"), root.join("owner.lock")] {
                match fs::remove_file(path) {
                    Ok(()) => {},
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}"),
                }
            }
        },
    }
}

fn scout(target: &Path, state: &State) -> Scout {
    let rules = if state.protected {
        vec![Rule::system(
            SystemReason::SystemArea { label: "replay" },
            testkit::location(target),
            Reach::Exact,
        )]
    } else {
        Vec::new()
    };
    Scout::with(testkit::protection(rules)).confined(vec![testkit::ceiling()])
}

fn replay(trace: Trace, operations: &mut BTreeSet<Operation>) {
    assert!(trace.states.len() > 1);
    let temp = testkit::tempdir("cleanup-replay");
    let root = temp.path().join("work");
    let target = testkit::write_cargo_project(&root, 64);
    owner(&root, Owner::Released);
    let mut plan: Option<Plan> = None;
    let mut previous = Phase::Empty;
    for frame in trace.states {
        let state = frame.state;
        operations.insert(state.operation);
        for integer in [
            &state.identity,
            &state.contents,
            &state.planned_identity,
            &state.planned_contents,
        ] {
            assert!(matches!(integer.value.as_str(), "0" | "1"));
        }
        match state.operation {
            Operation::Init => assert_eq!(state.phase, Phase::Empty),
            Operation::Plan => {
                let survey =
                    Scout::with(testkit::open_protection()).confined(vec![testkit::ceiling()]);
                let report = survey
                    .discover(&ScanOptions::sighting(std::slice::from_ref(&root), &[]))
                    .unwrap();
                let candidates = report
                    .candidates
                    .iter()
                    .filter(|found| found.path() == target)
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(candidates.len(), 1);
                let ids = candidates
                    .iter()
                    .map(|found| found.candidate().id().clone())
                    .collect::<Vec<_>>();
                plan = Some(Scout::plan(&candidates, &ids, Mandate::default(), &[]).unwrap());
            },
            Operation::Owner => owner(&root, state.owner),
            Operation::Protect | Operation::Idle => {},
            Operation::Replace => {
                fs::rename(&target, root.join("old")).unwrap();
                let _replacement = testkit::write_cargo_project(&root, 64);
                if state.contents.value == "1" {
                    testkit::write_bytes(&target.join("new"), b"changed");
                }
            },
            Operation::Modify => testkit::write_bytes(&target.join("new"), b"changed"),
            Operation::Interrupt => {
                plan = None;
            },
            Operation::Apply => {
                let summary = scout(&target, &state).apply(plan.as_ref().unwrap(), Mode::Execute);
                assert_eq!(summary.outcomes.len(), 1);
                let deleted = matches!(summary.outcomes.first().unwrap().status, Status::Deleted);
                assert_eq!(deleted, state.allowed, "{state:?}: {summary:?}");
                if !deleted {
                    assert!(matches!(
                        summary.outcomes.first().unwrap().status,
                        Status::Rejected { .. }
                    ));
                }
            },
        }
        assert_eq!(plan.is_some(), state.phase != Phase::Empty);
        if state.phase == Phase::Deleted {
            testkit::assert_absent(&target);
        } else {
            testkit::assert_present(&target);
        }
        if previous == Phase::Deleted {
            assert_eq!(state.phase, Phase::Deleted);
        }
        previous = state.phase;
    }
}

#[test]
fn replay_quint_cleanup_traces() {
    let directory = std::env::var_os("STORAGE_SCOUT_REPLAY_DIR");
    let directory = match directory {
        Some(path) => std::path::PathBuf::from(path),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/traces"),
    };
    let mut operations = BTreeSet::new();
    let mut count = 0usize;
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let trace: Trace = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            replay(trace, &mut operations);
            count = count.saturating_add(1);
        }
    }
    assert!(count > 0, "model replay needs nonempty traces");
    assert_eq!(
        operations,
        BTreeSet::from([
            Operation::Init,
            Operation::Plan,
            Operation::Owner,
            Operation::Protect,
            Operation::Replace,
            Operation::Modify,
            Operation::Interrupt,
            Operation::Apply,
            Operation::Idle
        ])
    );
}
