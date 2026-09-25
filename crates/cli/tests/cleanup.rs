#![expect(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests build and inspect real trees"
)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use storage_scout::core::area::{Reach, Rule};
use storage_scout::core::artifact::{Kind, Provenance, Tier};
use storage_scout::core::candidate::{Allocation, CandidateId};
use storage_scout::core::gate::{Mandate, TierGrant};
use storage_scout::core::lock::Protocol;
use storage_scout::core::reject::{Rejection, StaleField};
use storage_scout::core::size::Bytes;
use storage_scout::{Found, Measure, Mode, Plan, ScanOptions, ScanReport, Scout, Status, Summary};
use testkit::{
    Built, hard_link, link_dir, sparse_file, tempdir, write_cache_tag, write_cargo_project,
    write_declared_target, write_sized,
};

fn scout() -> Scout {
    Scout::with(testkit::open_protection())
}

fn options(root: &Path) -> ScanOptions {
    ScanOptions {
        roots: vec![root.to_path_buf()],
        top: 0,
        min_size: Bytes::ZERO,
        max_depth: Some(0),
        excludes: Vec::new(),
        threads: None,
        measure: Measure::Allocated,
    }
}

fn discover(root: &Path) -> ScanReport {
    scout().discover(&options(root)).unwrap()
}

fn plan(found: &[Found], ids: &[CandidateId], excludes: &[PathBuf]) -> Result<Plan, Rejection> {
    Scout::plan(found, ids, Mandate::default(), excludes)
}

fn ids(found: &[Found]) -> Vec<CandidateId> {
    found
        .iter()
        .map(|found| found.candidate().id().clone())
        .collect()
}

fn only(report: &ScanReport) -> &Found {
    match report.candidates.as_slice() {
        [found] => found,
        other => panic!("expected one candidate, found {other:#?}"),
    }
}

fn apply(plan: &Plan, mode: Mode) -> Summary {
    scout().apply(plan, mode)
}

fn status(summary: &Summary) -> &Status {
    &summary.outcomes.first().unwrap().status
}

fn make_all_artifacts(root: &Path) {
    write_sized(&root.join("rust/Cargo.toml"), 1);
    write_sized(&root.join("rust/target/debug/app.exe"), 100);
    write_sized(&root.join("dotnet/App.csproj"), 1);
    write_sized(&root.join("dotnet/bin/Debug/App.dll"), 101);
    write_sized(&root.join("dotnet/obj/project.assets.json"), 102);
    write_sized(&root.join("solution/App.slnx"), 1);
    write_sized(&root.join("solution/build/App.dll"), 103);
    write_sized(&root.join("solution/.vs/cache.bin"), 104);
    write_sized(&root.join("gradle/build.gradle.kts"), 1);
    write_sized(&root.join("gradle/build/classes/App.class"), 105);
    write_sized(&root.join("maven/pom.xml"), 1);
    write_sized(&root.join("maven/target/app.jar"), 106);
    write_sized(&root.join("web/package.json"), 1);
    write_sized(&root.join("web/dist/bundle.js"), 107);
    write_sized(&root.join("web/node_modules/pkg/index.js"), 108);
    write_sized(
        &root.join("web/node_modules/pkg/node_modules/nested/index.js"),
        9,
    );
    write_sized(&root.join("python/main.py"), 1);
    write_sized(&root.join("python/__pycache__/main.pyc"), 109);
    write_sized(&root.join("python/.venv/pyvenv.cfg"), 1);
    write_sized(&root.join("python/.venv/Lib/site.py"), 110);
    write_sized(&root.join("cmake/build/CMakeCache.txt"), 1);
    write_sized(&root.join("cmake/build/app.exe"), 111);
    fs::create_dir_all(root.join("unity/Assets")).unwrap();
    fs::create_dir_all(root.join("unity/ProjectSettings")).unwrap();
    write_sized(&root.join("unity/Library/cache.bin"), 112);
    write_sized(&root.join("unity/Temp/temp.bin"), 113);
    write_sized(&root.join("unity/obj/game.dll"), 114);
    write_cache_tag(&root.join("tagged"));
    write_sized(&root.join("tagged/blob.bin"), 115);
    testkit::write_owner_marker(
        &root.join("run"),
        testkit::MarkerRole::Scratch,
        testkit::MarkerKeep::Released,
        None,
    );
    write_sized(&root.join("run/scratch.bin"), 116);
    testkit::write_owner_marker(
        &root.join("cache-run"),
        testkit::MarkerRole::Cache,
        testkit::MarkerKeep::Released,
        None,
    );
    write_sized(&root.join("cache-run/cache.bin"), 117);
}

fn by_kind(report: &ScanReport, kind: Kind) -> &Found {
    report
        .candidates
        .iter()
        .find(|found| found.candidate().kind() == kind)
        .unwrap_or_else(|| panic!("missing {kind}"))
}

#[test]
fn every_artifact_family_is_detected_with_its_tier_and_provenance() {
    let temp = tempdir("families");
    make_all_artifacts(temp.path());
    let report = discover(temp.path());
    let kinds = report
        .candidates
        .iter()
        .map(|found| found.candidate().kind())
        .collect::<BTreeSet<_>>();
    assert_eq!(kinds, Kind::ALL.iter().copied().collect());
    let tagged = by_kind(&report, Kind::TaggedCache).candidate();
    assert_eq!(
        (tagged.tier(), tagged.provenance()),
        (Tier::Reinstallable, Provenance::Declared)
    );
    assert_eq!(
        by_kind(&report, Kind::RustTarget).candidate().provenance(),
        Provenance::Inferred
    );
    assert_eq!(
        by_kind(&report, Kind::UnityOutput).candidate().tier(),
        Tier::Expensive
    );
}

#[test]
fn decoys_and_nested_artifacts_are_not_candidates() {
    let temp = tempdir("decoys");
    for decoy in [
        "decoy/target/app",
        "decoy/build/output",
        "decoy/bin/output",
        "decoy/.vs/cache.bin",
        "decoy/cmake-build-debug/app",
        "decoy/__pycache__/main.pyc",
        "decoy/node_modules/pkg/index.js",
        "decoy/Library/cache.bin",
    ] {
        write_sized(&temp.path().join(decoy), 10);
    }
    write_sized(&temp.path().join("web/package.json"), 1);
    write_sized(&temp.path().join("web/node_modules/a/index.js"), 10);
    write_sized(
        &temp
            .path()
            .join("web/node_modules/a/node_modules/b/index.js"),
        10,
    );
    let report = discover(temp.path());
    assert_eq!(only(&report).candidate().kind(), Kind::NodeModules);
}

#[test]
fn a_logical_scan_says_allocation_is_unmeasured() {
    let temp = tempdir("logical");
    write_sized(&temp.path().join("data/file.bin"), 12_345);
    let report = scout().scan(&ScanOptions {
        measure: Measure::Logical,
        max_depth: None,
        ..options(temp.path())
    });
    assert_eq!(report.usage.logical, Bytes::new(12_345));
    assert_eq!(report.usage.allocation, Allocation::Unmeasured);
}

#[test]
fn missing_roots_are_reported_as_typed_issues() {
    let temp = tempdir("missing");
    let report = scout().scan(&ScanOptions::new(vec![temp.path().join("absent")]));
    assert!(report.roots.is_empty());
    assert!(
        matches!(report.issues.as_slice(), [Rejection::Io { .. }]),
        "{:#?}",
        report.issues
    );
}

#[test]
fn excluded_subtrees_are_neither_walked_nor_offered() {
    let temp = tempdir("excludes");
    let _keep = write_cargo_project(&temp.path().join("keep"), 100);
    let _skip = write_cargo_project(&temp.path().join("skip"), 200);
    let report = scout().discover(&ScanOptions {
        excludes: vec![temp.path().join("skip")],
        ..options(temp.path())
    });
    let report = report.unwrap();
    assert!(only(&report).path().ends_with("keep/target"));
}

#[test]
fn an_exclusion_inside_a_candidate_protects_the_whole_candidate() {
    let temp = tempdir("inner-exclude");
    let target = write_cargo_project(&temp.path().join("proj"), 100);
    let future = target.join("future-child");
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[future]).unwrap();
    let summary = apply(&plan, Mode::Execute);
    testkit::assert_present(&target);
    assert!(matches!(
        status(&summary),
        Status::Rejected {
            rejection: Rejection::Excluded { .. }
        }
    ));
}

#[test]
fn a_dry_run_revalidates_and_deletes_nothing() {
    let temp = tempdir("dry-run");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let report = discover(temp.path());
    let summary = apply(
        &plan(&report.candidates, &ids(&report.candidates), &[]).unwrap(),
        Mode::DryRun,
    );
    testkit::assert_present(&target);
    assert_eq!(status(&summary), &Status::WouldDelete);
    assert!(summary.predicted_freed.is_some());
    assert_eq!(summary.observed_freed, None);
}

#[test]
fn executing_deletes_only_the_discovered_candidate() {
    let temp = tempdir("execute");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    write_sized(&temp.path().join("proj/src/main.rs"), 10);
    let report = discover(temp.path());
    let summary = apply(
        &plan(&report.candidates, &ids(&report.candidates), &[]).unwrap(),
        Mode::Execute,
    );
    assert_eq!(status(&summary), &Status::Deleted);
    testkit::assert_absent(&target);
    testkit::assert_present(temp.path().join("proj/src/main.rs"));
    assert!(summary.observed_freed.is_some());
}

#[test]
fn unknown_and_duplicate_ids_are_refused_when_planning() {
    let temp = tempdir("ids");
    let _target = write_cargo_project(&temp.path().join("proj"), 4096);
    let report = discover(temp.path());
    let id = only(&report).candidate().id().clone();
    let unknown = CandidateId::from_str(&"a".repeat(64)).unwrap();
    assert!(matches!(
        plan(&report.candidates, &[unknown], &[]),
        Err(Rejection::UnknownCandidate { .. })
    ));
    assert!(matches!(
        plan(&report.candidates, &[id.clone(), id], &[]),
        Err(Rejection::DuplicateCandidate { .. })
    ));
}

#[test]
fn a_file_added_after_discovery_makes_the_plan_stale() {
    let temp = tempdir("stale-added");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    write_sized(&target.join("new-file"), 10);
    let summary = apply(&plan, Mode::Execute);
    testkit::assert_present(&target);
    assert!(matches!(
        status(&summary),
        Status::Rejected {
            rejection: Rejection::Stale {
                field: StaleField::Content,
                ..
            }
        }
    ));
}

#[test]
fn a_replaced_directory_is_a_different_candidate() {
    let temp = tempdir("replaced");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    fs::rename(&target, temp.path().join("proj/old-target")).unwrap();
    write_sized(&target.join("debug/app"), 4096);
    let summary = apply(&plan, Mode::Execute);
    testkit::assert_present(&target);
    assert!(matches!(
        status(&summary),
        Status::Rejected {
            rejection: Rejection::Stale {
                field: StaleField::FileIdentity,
                ..
            }
        }
    ));
}

#[test]
fn a_same_size_replacement_of_a_file_is_stale() {
    let temp = tempdir("same-size");
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let payload = temp.path().join("proj/target/app");
    write_sized(&payload, 64);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let replacement = payload.with_extension("new");
    fs::write(&replacement, [2u8; 64]).unwrap();
    fs::rename(&replacement, &payload).unwrap();
    let summary = apply(&plan, Mode::Execute);
    testkit::assert_present(&payload);
    assert!(matches!(
        status(&summary),
        Status::Rejected {
            rejection: Rejection::Stale { .. }
        }
    ));
}

#[test]
fn a_link_inserted_after_discovery_is_never_followed() {
    let temp = tempdir("link-inserted");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let elsewhere = temp.path().join("elsewhere");
    write_sized(&elsewhere.join("payload"), 10);
    if link_dir(&target.join("link"), &elsewhere)
        .or_skip("a directory link")
        .is_none()
    {
        return;
    }
    let summary = apply(&plan, Mode::Execute);
    testkit::assert_present(&target);
    testkit::assert_present(elsewhere.join("payload"));
    assert!(matches!(
        status(&summary),
        Status::Rejected {
            rejection: Rejection::Link { .. }
        }
    ));
}

#[test]
fn a_linked_root_is_refused() {
    let temp = tempdir("linked-root");
    let real = temp.path().join("real");
    let _target = write_cargo_project(&real, 10);
    let Some(link) = link_dir(&temp.path().join("linked"), &real).or_skip("a directory link")
    else {
        return;
    };
    assert!(matches!(
        scout().discover(&options(&link)),
        Err(Rejection::Link { .. })
    ));
}

#[test]
fn a_broad_root_is_refused_but_a_root_around_the_current_directory_only_protects_it() {
    let detected = Scout::detect().unwrap();
    let cwd = std::env::current_dir().unwrap();
    let root = cwd.ancestors().last().unwrap().to_path_buf();
    assert!(matches!(
        detected.discover(&options(&root)),
        Err(Rejection::Protected { .. })
    ));
    let temp = tempdir("cwd-root");
    let standing = write_cargo_project(&temp.path().join("standing"), 100);
    let beside = write_cargo_project(&temp.path().join("beside"), 100);
    let scout = Scout::with(testkit::protection_at(&standing.join("debug"), Vec::new()));
    let report = scout.discover(&options(temp.path())).unwrap();
    let paths = report
        .candidates
        .iter()
        .map(|found| found.path().to_path_buf())
        .collect::<Vec<_>>();
    assert_eq!(paths, vec![fs::canonicalize(&beside).unwrap()]);
}

#[test]
fn a_hard_link_to_the_outside_is_not_reclaimable() {
    let temp = tempdir("hard-link-out");
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let inside = temp.path().join("proj/target/app.bin");
    write_sized(&inside, 64 * 1024);
    if hard_link(&temp.path().join("outside.bin"), &inside)
        .or_skip("a hard link")
        .is_none()
    {
        return;
    }
    let report = discover(temp.path());
    let Allocation::Measured {
        allocated,
        reclaimable,
    } = only(&report).candidate().usage().allocation
    else {
        panic!("a discovered candidate is measured");
    };
    assert!(allocated > Bytes::ZERO);
    assert_eq!(reclaimable, Bytes::ZERO);
}

#[test]
fn links_across_selected_candidates_count_once() {
    let temp = tempdir("hard-link-across");
    write_sized(&temp.path().join("proj/App.csproj"), 1);
    let first = temp.path().join("proj/bin/app.dll");
    write_sized(&first, 64 * 1024);
    if hard_link(&temp.path().join("proj/obj/app.dll"), &first)
        .or_skip("a hard link")
        .is_none()
    {
        return;
    }
    let report = discover(temp.path());
    assert_eq!(report.candidates.len(), 2);
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let Allocation::Measured {
        allocated,
        reclaimable,
    } = plan.usage().unwrap().allocation
    else {
        panic!("a plan is measured");
    };
    assert!(reclaimable > Bytes::ZERO);
    assert!(allocated < Bytes::new(128 * 1024));
}

#[test]
fn a_sparse_file_is_measured_by_what_it_occupies() {
    let temp = tempdir("sparse");
    write_sized(&temp.path().join("sparse/Cargo.toml"), 1);
    if sparse_file(
        &temp.path().join("sparse/target/sparse.bin"),
        8 * 1024 * 1024,
    )
    .or_skip("a sparse file")
    .is_none()
    {
        return;
    }
    let report = discover(temp.path());
    let usage = *only(&report).candidate().usage();
    let Allocation::Measured { allocated, .. } = usage.allocation else {
        panic!("a discovered candidate is measured");
    };
    assert!(usage.logical >= Bytes::new(8 * 1024 * 1024));
    assert!(allocated < usage.logical);
}

#[test]
fn self_declared_targets_and_tagged_caches_are_found_wherever_they_live() {
    let temp = tempdir("declared");
    write_declared_target(&temp.path().join("sbt"), "debug");
    write_sized(&temp.path().join("sbt/debug/app"), 4096);
    write_cache_tag(&temp.path().join("registry"));
    write_sized(&temp.path().join("registry/crate.crate"), 2048);
    write_sized(&temp.path().join("info-only/.rustc_info.json"), 2);
    write_sized(&temp.path().join("profile-only/debug/app"), 1024);
    write_sized(&temp.path().join("bad-tag/CACHEDIR.TAG"), 16);
    write_sized(&temp.path().join("bad-tag/data.bin"), 1024);
    let report = discover(temp.path());
    let mut found = report
        .candidates
        .iter()
        .map(|found| {
            let candidate = found.candidate();
            (
                found
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                candidate.kind(),
                candidate.provenance(),
            )
        })
        .collect::<Vec<_>>();
    found.sort();
    assert_eq!(
        found,
        [
            (
                "registry".to_owned(),
                Kind::TaggedCache,
                Provenance::Declared
            ),
            ("sbt".to_owned(), Kind::RustTarget, Provenance::Declared),
        ]
    );
}

#[test]
fn an_application_owned_area_admits_only_declared_caches() {
    let temp = tempdir("app-owned");
    let area = testkit::location(temp.path());
    let scout = Scout::with(testkit::protection(vec![Rule::app_owned(
        "test area",
        area,
        Reach::Subtree,
    )]));
    let _inferred = write_cargo_project(&temp.path().join("proj"), 4096);
    write_declared_target(&temp.path().join("sbt"), "debug");
    write_sized(&temp.path().join("sbt/debug/app"), 4096);
    let report = scout.discover(&options(temp.path())).unwrap();
    assert!(only(&report).path().ends_with("sbt"));
}

#[test]
fn a_build_holding_its_lock_blocks_deletion_until_it_lets_go() {
    let temp = tempdir("busy");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let lock = target.join("debug/.cargo-lock");
    write_sized(&lock, 0);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let holder = File::open(&lock).unwrap();
    holder.lock().unwrap();
    let refused = apply(&plan, Mode::Execute);
    testkit::assert_present(&target);
    assert!(matches!(
        status(&refused),
        Status::Rejected {
            rejection: Rejection::Busy {
                protocol: Protocol::Cargo,
                ..
            }
        }
    ));
    holder.unlock().unwrap();
    let deleted = apply(&plan, Mode::Execute);
    assert_eq!(status(&deleted), &Status::Deleted, "{deleted:#?}");
    assert!(!deleted.failed());
    assert!(!deleted.failed_to_delete());
    testkit::assert_absent(&target);
}

#[test]
fn a_lock_in_a_nested_target_counts_too() {
    let temp = tempdir("nested-busy");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    write_sized(&target.join("debug/deps/libx.rlib"), 1024);
    let nested = target.join("pre-push/debug/.cargo-lock");
    write_sized(&nested, 0);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let holder = File::open(&nested).unwrap();
    holder.lock().unwrap();
    let refused = apply(&plan, Mode::Execute);
    testkit::assert_present(&target);
    assert!(matches!(
        status(&refused),
        Status::Rejected {
            rejection: Rejection::Busy { .. }
        }
    ));
    drop(holder);
    assert_eq!(status(&apply(&plan, Mode::Execute)), &Status::Deleted);
}

fn refused_while_held(target: &Path, lock_dir: &Path) {
    testkit::write_owner_marker(
        lock_dir,
        testkit::MarkerRole::Scratch,
        testkit::MarkerKeep::Released,
        None,
    );
    let root = target.parent().and_then(Path::parent).unwrap();
    let report = discover(root);
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let holder = testkit::claim(lock_dir);
    let refused = apply(&plan, Mode::Execute);
    testkit::assert_present(target);
    assert!(
        matches!(
            status(&refused),
            Status::Rejected {
                rejection: Rejection::Busy {
                    protocol: Protocol::TempOwner,
                    ..
                }
            }
        ),
        "{} was not found: {refused:#?}",
        lock_dir.display()
    );
    drop(holder);
}

#[test]
fn a_lock_anywhere_outside_cargos_own_directories_is_found() {
    let temp = tempdir("busy-anywhere");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    fs::create_dir_all(target.join("debug/.fingerprint")).unwrap();
    write_sized(&target.join("debug/deps/libx.rlib"), 1024);
    let Built::Yes(_) = link_dir(&target.join("a-link"), temp.path()) else {
        return;
    };
    refused_while_held(&target, &target.join("debug/scratch/run"));
    refused_while_held(&target, &target.join("tmp/build/run"));
}

#[test]
fn a_directory_that_cannot_be_read_keeps_the_whole_target() {
    let temp = tempdir("busy-unreadable");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let private = target.join("private");
    write_sized(&private.join("secret"), 16);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let Some(restricted) = testkit::restrict(&private, 0o000) else {
        return;
    };
    let refused = apply(&plan, Mode::Execute);
    drop(restricted);
    testkit::assert_present(private.join("secret"));
    assert!(
        matches!(
            status(&refused),
            Status::Rejected {
                rejection: Rejection::Io { .. }
            }
        ),
        "{refused:#?}"
    );
}

#[test]
fn a_lock_that_cannot_be_opened_is_never_taken_for_free() {
    let temp = tempdir("busy-sealed");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let lock = target.join("debug/.cargo-lock");
    write_sized(&lock, 0);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let Some(restricted) = testkit::restrict(&lock, 0o000) else {
        return;
    };
    let previewed = apply(&plan, Mode::DryRun);
    let refused = apply(&plan, Mode::Execute);
    drop(restricted);
    testkit::assert_present(&lock);
    assert!(
        matches!(
            status(&previewed),
            Status::Rejected {
                rejection: Rejection::LivenessUnknown { .. }
            }
        ),
        "{previewed:#?}"
    );
    assert!(
        matches!(
            status(&refused),
            Status::Rejected {
                rejection: Rejection::LivenessUnknown {
                    protocol: Protocol::Cargo,
                    ..
                }
            }
        ),
        "{refused:#?}"
    );
    assert!(refused.failed());
    assert!(!refused.failed_to_delete());
}

#[test]
fn a_removal_the_filesystem_refuses_is_a_failure_not_a_refusal() {
    let temp = tempdir("remove-refused");
    let project = temp.path().join("proj");
    let target = write_cargo_project(&project, 4096);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let Some(restricted) = testkit::restrict(&project, 0o555) else {
        return;
    };
    let summary = apply(&plan, Mode::Execute);
    drop(restricted);
    testkit::assert_present(&target);
    assert!(
        matches!(
            status(&summary),
            Status::Failed {
                rejection: Rejection::Io { .. }
            }
        ),
        "{summary:#?}"
    );
    assert!(summary.failed());
    assert!(summary.failed_to_delete());
}

#[test]
fn a_cache_tag_without_the_signature_is_not_evidence() {
    let temp = tempdir("forged-tag");
    let cache = temp.path().join("cache");
    let forged = vec![b'x'; testkit::CACHE_TAG.len()];
    testkit::write_bytes(&cache.join("CACHEDIR.TAG"), &forged);
    write_sized(&cache.join("blob"), 4096);
    assert!(discover(temp.path()).candidates.is_empty());
    write_cache_tag(&cache);
    assert_eq!(
        only(&discover(temp.path())).candidate().kind(),
        Kind::TaggedCache
    );
}

fn with_roots(roots: Vec<PathBuf>) -> ScanOptions {
    ScanOptions {
        roots,
        ..options(Path::new("."))
    }
}

#[test]
fn issues_are_counted_in_full_but_listed_only_up_to_the_limit() {
    let temp = tempdir("scan-issues");
    let missing = (0..51)
        .map(|index| temp.path().join(format!("missing-{index}")))
        .collect::<Vec<_>>();
    let report = scout().scan(&with_roots(missing));
    assert_eq!(report.stats.errors, 51);
    assert_eq!(report.issues.len(), 50);
}

#[test]
fn every_usable_root_is_scanned_once_whatever_comes_before_it() {
    let temp = tempdir("scan-roots");
    let root = temp.path();
    let _target = write_cargo_project(&root.join("proj"), 4096);
    write_sized(&root.join("file"), 1);
    let Built::Yes(link) = link_dir(&root.join("link"), &root.join("proj")) else {
        return;
    };
    for roots in [
        vec![
            root.join("missing"),
            link,
            root.join("file"),
            root.to_path_buf(),
        ],
        vec![root.to_path_buf(), root.join("proj")],
        vec![root.join("proj"), root.to_path_buf()],
    ] {
        let report = scout().scan(&with_roots(roots.clone()));
        assert_eq!(report.candidates.len(), 1, "{roots:?}");
        if roots.len() == 4 {
            assert_eq!(report.stats.errors, 3);
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| matches!(issue, Rejection::Link { .. }))
            );
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| matches!(issue, Rejection::NotADirectory { .. }))
            );
        }
        assert_eq!(report.roots, vec![testkit::location(root)], "{roots:?}");
    }
}

#[test]
fn an_excluded_root_or_directory_is_not_scanned() {
    let temp = tempdir("scan-excluded");
    let root = temp.path();
    let _target = write_cargo_project(&root.join("proj"), 4096);
    write_sized(&root.join("docs/manual"), 8192);
    let excluded = ScanOptions {
        excludes: vec![root.to_path_buf()],
        ..options(root)
    };
    assert!(scout().scan(&excluded).candidates.is_empty());
    let inner = ScanOptions {
        excludes: vec![root.join("docs")],
        max_depth: None,
        ..options(root)
    };
    let report = scout().scan(&inner);
    assert_eq!(report.usage.logical, Bytes::new(4096 + 1));
    assert!(
        report
            .largest_directories
            .iter()
            .all(|directory| directory.location != testkit::location(&root.join("docs")))
    );
}

#[test]
fn an_artifact_inside_an_artifact_is_part_of_it() {
    let temp = tempdir("scan-nested");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let _inner = write_cargo_project(&target.join("tmp/vendored"), 4096);
    let report = discover(temp.path());
    assert_eq!(only(&report).path(), fs::canonicalize(&target).unwrap());
}

#[test]
fn the_size_floor_keeps_what_reaches_it_exactly() {
    let temp = tempdir("scan-floor");
    let _target = write_cargo_project(&temp.path().join("proj"), 4096);
    write_sized(&temp.path().join("docs/manual"), 4096);
    for (floor, expected) in [(4096, 1), (4097, 0)] {
        let options = ScanOptions {
            min_size: Bytes::new(floor),
            max_depth: None,
            top: 100,
            ..options(temp.path())
        };
        let report = scout().scan(&options);
        assert_eq!(report.candidates.len(), expected, "{floor}");
        let docs = report
            .largest_directories
            .iter()
            .filter(|directory| directory.location == testkit::location(&temp.path().join("docs")))
            .count();
        assert_eq!(docs, expected, "{floor}");
        assert!(
            report
                .largest_directories
                .iter()
                .all(|directory| !directory.location.to_string().contains("target")),
            "{floor}"
        );
    }
}

#[test]
fn a_lock_name_inside_cargos_own_directories_is_not_a_lock() {
    let temp = tempdir("busy-decoys");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    fs::create_dir_all(target.join("debug/.fingerprint")).unwrap();
    let decoy = target.join("debug/deps/.cargo-lock");
    write_sized(&decoy, 0);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let decoy_holder = File::open(&decoy).unwrap();
    decoy_holder.lock().unwrap();
    let summary = apply(&plan, Mode::Execute);
    assert_eq!(status(&summary), &Status::Deleted, "{summary:#?}");
}

#[test]
fn a_marker_that_appears_after_discovery_is_heard_before_deletion() {
    let temp = tempdir("owned-late");
    let run = temp.path().join("run");
    testkit::write_owner_marker(
        &run,
        testkit::MarkerRole::Scratch,
        testkit::MarkerKeep::Released,
        None,
    );
    let target = write_cargo_project(&run.join("proj"), 4096);
    let report = discover(temp.path());
    let settled = report.candidates.clone();
    assert_eq!(settled.len(), 1, "{report:#?}");
    assert_eq!(
        settled[0].candidate().settlement(),
        storage_scout::core::ownership::Settlement::Released
    );
    let plan = Scout::plan(
        &settled,
        &ids(&settled),
        Mandate {
            tiers: TierGrant::ROUTINE,
            settlements: storage_scout::core::ownership::Admits::Settled,
        },
        &[],
    )
    .unwrap();
    let kept = target.join("tmp/kept");
    testkit::write_owner_marker(
        &kept,
        testkit::MarkerRole::Scratch,
        testkit::MarkerKeep::Kept,
        None,
    );
    fs::remove_file(kept.join("owner.lock")).unwrap();
    let summary = apply(&plan, Mode::Execute);
    assert!(
        matches!(
            status(&summary),
            Status::Rejected {
                rejection: Rejection::Owned {
                    settlement: storage_scout::core::ownership::Settlement::Kept,
                    ..
                }
            }
        ),
        "{summary:#?}"
    );
    testkit::assert_present(&target);
}

#[test]
fn a_candidate_measured_only_by_length_cannot_be_planned() {
    let temp = tempdir("plan-unmeasured");
    let _target = write_cargo_project(&temp.path().join("proj"), 4096);
    let logical = ScanOptions {
        measure: Measure::Logical,
        ..options(temp.path())
    };
    let report = scout().scan(&logical);
    assert!(matches!(
        plan(&report.candidates, &ids(&report.candidates), &[]),
        Err(Rejection::Unmeasured { .. })
    ));
}

#[test]
fn a_declared_target_is_still_declared_when_it_is_deleted() {
    let temp = tempdir("declared-delete");
    let target = temp.path().join("sbt");
    write_declared_target(&target, "debug");
    write_sized(&target.join("debug/app"), 4096);
    let report = discover(temp.path());
    assert_eq!(only(&report).candidate().provenance(), Provenance::Declared);
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    let summary = apply(&plan, Mode::Execute);
    assert_eq!(status(&summary), &Status::Deleted, "{summary:#?}");
}

#[test]
fn a_manifest_replaced_by_a_link_is_no_longer_evidence() {
    let temp = tempdir("manifest-link");
    let project = temp.path().join("proj");
    let target = write_cargo_project(&project, 4096);
    let report = discover(temp.path());
    let plan = plan(&report.candidates, &ids(&report.candidates), &[]).unwrap();
    write_sized(&temp.path().join("elsewhere.toml"), 1);
    fs::remove_file(project.join("Cargo.toml")).unwrap();
    let Built::Yes(_) = testkit::symlink_file(
        &project.join("Cargo.toml"),
        &temp.path().join("elsewhere.toml"),
    ) else {
        return;
    };
    let summary = apply(&plan, Mode::Execute);
    assert!(
        matches!(
            status(&summary),
            Status::Rejected {
                rejection: Rejection::EvidenceLost { .. }
            }
        ),
        "{summary:#?}"
    );
    testkit::assert_present(&target);
}

#[test]
fn a_locked_tier_is_refused_by_the_gate() {
    let temp = tempdir("tier");
    write_cache_tag(&temp.path().join("cache"));
    write_sized(&temp.path().join("cache/blob"), 4096);
    let report = discover(temp.path());
    let refused = Scout::plan(
        &report.candidates,
        &ids(&report.candidates),
        Mandate::default(),
        &[],
    )
    .unwrap();
    assert!(matches!(
        status(&apply(&refused, Mode::Execute)),
        Status::Rejected {
            rejection: Rejection::TierLocked {
                tier: Tier::Reinstallable,
                ..
            }
        }
    ));
    let granted = Scout::plan(
        &report.candidates,
        &ids(&report.candidates),
        Mandate {
            tiers: TierGrant::ROUTINE.with(Tier::Reinstallable),
            ..Mandate::default()
        },
        &[],
    )
    .unwrap();
    assert_eq!(status(&apply(&granted, Mode::Execute)), &Status::Deleted);
}

#[test]
fn a_read_only_tree_is_still_removed() {
    let temp = tempdir("read-only");
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let sealed = target.join("debug/sealed");
    write_sized(&sealed.join("file"), 10);
    let mut permissions = fs::metadata(&sealed).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&sealed, permissions).unwrap();
    let report = discover(temp.path());
    let summary = apply(
        &plan(&report.candidates, &ids(&report.candidates), &[]).unwrap(),
        Mode::Execute,
    );
    assert_eq!(status(&summary), &Status::Deleted, "{summary:#?}");
}

#[test]
fn a_missing_root_is_skipped_and_no_root_at_all_is_refused() {
    let temp = tempdir("missing-root");
    let _target = write_cargo_project(&temp.path().join("proj"), 100);
    let report = scout()
        .discover(&ScanOptions {
            roots: vec![temp.path().join("absent"), temp.path().to_path_buf()],
            ..options(temp.path())
        })
        .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert!(matches!(
        scout().discover(&options(&temp.path().join("absent"))),
        Err(Rejection::NoRoots)
    ));
}
