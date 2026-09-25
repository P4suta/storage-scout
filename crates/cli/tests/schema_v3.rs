#![expect(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "the schema record is read and blessed from disk"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Value, json};
use storage_scout::core::artifact::{Kind, Provenance, Tier};
use storage_scout::core::gate::{Gate, Mandate};
use storage_scout::core::reject::{IoFailure, IoKind, Rejection};
use storage_scout::core::share::{Failure, PairGate, Refusal, Step};
use storage_scout::core::size::Bytes;
use storage_scout::{Measure, Mode, PairOutcome, PairStatus, SCHEMA_VERSION, ScanOptions, Scout};
use testkit::{tempdir, write_cache_tag, write_cargo_project, write_patterned, write_sized};

const RECORD: &str = "tests/schema/v3.json";

fn field_paths(value: &Value, prefix: &str, into: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                into.insert(path.clone());
                field_paths(child, &path, into);
            }
        },
        Value::Array(items) => {
            for item in items {
                field_paths(item, &format!("{prefix}[]"), into);
            }
        },
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {},
    }
}

fn pairs(place: &storage_scout::core::location::Location) -> [PairOutcome; 6] {
    [
        PairStatus::WouldShare,
        PairStatus::Shared,
        PairStatus::AlreadyShared,
        PairStatus::Refused {
            refusal: Refusal::HardLinked { links: 2 },
        },
        PairStatus::Withheld {
            rejection: Rejection::NoRoots,
        },
        PairStatus::Failed {
            failure: Failure::Io {
                step: Step::Clone,
                error: IoFailure {
                    kind: IoKind::Other,
                    code: Some(1),
                },
            },
        },
    ]
    .map(|status| PairOutcome {
        keeper: place.clone(),
        duplicate: place.clone(),
        len: Bytes::new(1),
        status,
    })
}

fn subjects(place: &storage_scout::core::location::Location) -> [storage_scout::Subject; 2] {
    let id = "0"
        .repeat(64)
        .parse::<storage_scout::core::candidate::CandidateId>()
        .unwrap();
    [
        storage_scout::Admission::Admitted {
            method: storage_scout::core::share::Method::CloneAndSwap,
            files: 1,
            unreadable: 0,
        },
        storage_scout::Admission::Rejected {
            rejection: Rejection::NoRoots,
        },
    ]
    .map(|admission| storage_scout::Subject {
        id: id.clone(),
        location: place.clone(),
        admission,
    })
}

fn documents() -> BTreeMap<String, Value> {
    let temp = tempdir("schema");
    let root = temp.path();
    let target = write_cargo_project(&root.join("proj"), 64 * 1024);
    write_cache_tag(&root.join("cache"));
    write_sized(&root.join("cache/blob"), 64 * 1024);
    testkit::write_owner_marker(
        &root.join("run"),
        testkit::MarkerRole::Cache,
        testkit::MarkerKeep::Released,
        Some(&root.join("proj")),
    );
    write_sized(&root.join("run/scratch"), 64 * 1024);
    let scout = Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()]);
    let options = ScanOptions {
        roots: vec![root.to_path_buf()],
        top: 10,
        min_size: Bytes::ZERO,
        max_depth: Some(2),
        excludes: Vec::new(),
        threads: Some(1),
        measure: Measure::Allocated,
    };
    let scan = scout.scan(&options);
    let discovery = scout.discover(&options).unwrap();
    let ids = discovery
        .candidates
        .iter()
        .map(|found| found.candidate().id().clone())
        .collect::<Vec<_>>();
    let plan = Scout::plan(&discovery.candidates, &ids, Mandate::default(), &[]).unwrap();
    let summary = scout.apply(&plan, Mode::DryRun);
    let eligible = scout.explain(&target, &[], Mandate::default()).unwrap();
    let refused = scout.explain(root, &[], Mandate::default()).unwrap();
    let shared = root.join("shared");
    for name in ["one", "two"] {
        write_cache_tag(&shared.join(name));
        write_patterned(&shared.join(name).join("blob"), 128 * 1024, 1);
    }
    let dedupe = scout.dedupe(&[shared], &[], Mode::DryRun).unwrap();
    let pruned = scout
        .prune(&[root.to_path_buf()], &[], Mode::DryRun)
        .unwrap();
    let policy = storage_scout::AutoPolicy::parse(&format!(
        "[select]\nroots = [{:?}]\n",
        root.to_str().unwrap()
    ))
    .unwrap();
    let auto = scout.auto(&policy, Mode::DryRun).unwrap();
    let watched = storage_scout::WatchRecord {
        schema_version: SCHEMA_VERSION,
        command: "watch",
        cause: storage_scout::Cause::Written,
        watching: 1,
        reap: Some(summary.clone()),
        prune: Some(pruned.clone()),
        dedupe: Some(dedupe.clone()),
    };
    let place = testkit::location(root);
    let pairs = pairs(&place);
    let to_value = |value: &dyn erased::Erased| value.value();
    let mut documents = BTreeMap::new();
    documents.insert("scan".to_owned(), to_value(&scan));
    documents.insert("discovery".to_owned(), to_value(&discovery));
    documents.insert("plan".to_owned(), to_value(&plan));
    documents.insert("summary".to_owned(), to_value(&summary));
    documents.insert("explain".to_owned(), to_value(&eligible));
    documents.insert("explain-refused".to_owned(), to_value(&refused));
    documents.insert("doctor".to_owned(), to_value(&scout.diagnose(None)));
    documents.insert("dedupe".to_owned(), to_value(&dedupe));
    documents.insert("prune".to_owned(), to_value(&pruned));
    let mut auto = to_value(&auto);
    *auto.pointer_mut("/dedupe/subjects").unwrap() = to_value(&subjects(&place));
    documents.insert("auto".to_owned(), auto);
    documents.insert("watch".to_owned(), to_value(&watched));
    documents.insert(
        "detached".to_owned(),
        json!({
            "spawned": to_value(&storage_scout::hook::Detached::Spawned { pid: 1 }),
            "handed": to_value(&storage_scout::hook::Detached::Handed),
        }),
    );
    documents.insert(
        "dedupe-pairs".to_owned(),
        json!({ "pairs": to_value(&pairs) }),
    );
    documents.insert("vocabulary".to_owned(), vocabulary());
    documents
}

fn vocabulary() -> Value {
    let to_value = |value: &dyn erased::Erased| value.value();
    json!({
        "kinds": Kind::ALL.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
        "tiers": Tier::ALL.iter().map(|tier| tier.as_str()).collect::<Vec<_>>(),
        "provenance": Provenance::ALL.iter().map(|provenance| provenance.as_str()).collect::<Vec<_>>(),
        "gates": Gate::ALL.iter().map(|gate| gate.name()).collect::<Vec<_>>(),
        "pair-gates": to_value(&PairGate::ALL),
        "prune-rules": to_value(&storage_scout::core::prune::Rule::ALL),
        "watch-causes": to_value(&[
            storage_scout::Cause::Start,
            storage_scout::Cause::Hook,
            storage_scout::Cause::Appeared,
            storage_scout::Cause::Written,
        ]),
    })
}

mod erased {
    pub(crate) trait Erased {
        fn value(&self) -> serde_json::Value;
    }

    impl<T: serde::Serialize> Erased for T {
        fn value(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap()
        }
    }
}

#[test]
fn every_document_declares_the_current_schema_version() {
    for (name, document) in documents() {
        if let Some(version) = document.get("schema_version") {
            assert_eq!(version, SCHEMA_VERSION, "{name}");
        }
    }
}

#[test]
fn no_recorded_field_has_disappeared() {
    let current = documents()
        .into_iter()
        .map(|(name, document)| {
            let mut paths = BTreeSet::new();
            field_paths(&document, "", &mut paths);
            (name, paths)
        })
        .collect::<BTreeMap<_, _>>();
    if std::env::var_os("STORAGE_SCOUT_BLESS_SCHEMA").is_some() {
        std::fs::write(
            RECORD,
            format!("{}\n", serde_json::to_string_pretty(&current).unwrap()),
        )
        .unwrap();
        return;
    }
    let recorded: BTreeMap<String, BTreeSet<String>> =
        serde_json::from_str(&std::fs::read_to_string(RECORD).unwrap()).unwrap();
    let missing = recorded
        .iter()
        .flat_map(|(document, fields)| {
            let present = current.get(document);
            fields
                .iter()
                .filter(|field| testkit::reports_devices() || !field.ends_with(".note.device"))
                .filter(move |field| present.is_none_or(|present| !present.contains(*field)))
                .map(move |field| format!("{document}.{field}"))
        })
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "fields are only added within a version; gone: {missing:#?}"
    );
}

#[test]
fn the_record_is_committed() {
    assert!(Path::new(RECORD).is_file(), "{RECORD} must be committed");
}
