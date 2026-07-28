//! v0.2 API and CLI integration tests. Real deletion is confined to temporary
//! directories created under this repository.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test setup should fail immediately and readably"
)]

use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::str::FromStr;

use storage_scout::{
    ApplyOptions, ArtifactCandidate, ArtifactKind, Bytes, CandidateId, CleanupStatus, Measure,
    RiskTier, SCHEMA_VERSION, ScanOptions, apply_cleanup_plan, create_cleanup_plan,
    discover_cleanup_candidates, scan,
};

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(".storage-scout-test-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap()
}

fn write_sized(path: &Path, size: u64) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    File::create(path).unwrap().set_len(size).unwrap();
}

fn scan_all(root: &Path) -> storage_scout::ScanReport {
    scan(&ScanOptions {
        roots: vec![root.to_path_buf()],
        top: 100,
        min_size: Bytes(0),
        max_depth: None,
        excludes: Vec::new(),
        threads: Some(2),
        measure: Measure::Both,
    })
}

fn clean_discovery(root: &Path) -> storage_scout::ScanReport {
    discover_cleanup_candidates(&ScanOptions {
        roots: vec![root.to_path_buf()],
        top: 0,
        min_size: Bytes(0),
        max_depth: Some(0),
        excludes: Vec::new(),
        threads: Some(2),
        measure: Measure::Both,
    })
    .unwrap()
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
}

fn find_candidate(candidates: &[ArtifactCandidate], kind: ArtifactKind) -> &ArtifactCandidate {
    candidates
        .iter()
        .find(|candidate| candidate.kind == kind)
        .unwrap_or_else(|| panic!("missing {kind:?}: {candidates:#?}"))
}

#[test]
fn detects_every_artifact_family_and_tier() {
    let temp = tempdir();
    make_all_artifacts(temp.path());
    let report = scan_all(temp.path());
    let found = report
        .candidates
        .iter()
        .map(|candidate| candidate.kind)
        .collect::<HashSet<_>>();
    let expected = [
        ArtifactKind::RustTarget,
        ArtifactKind::DotNetOutput,
        ArtifactKind::SolutionBuild,
        ArtifactKind::VisualStudioCache,
        ArtifactKind::GradleOutput,
        ArtifactKind::MavenTarget,
        ArtifactKind::JsOutput,
        ArtifactKind::PythonCache,
        ArtifactKind::CmakeOutput,
        ArtifactKind::NodeModules,
        ArtifactKind::PythonVenv,
        ArtifactKind::UnityOutput,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    assert_eq!(found, expected);
    assert_eq!(
        find_candidate(&report.candidates, ArtifactKind::NodeModules).tier,
        RiskTier::Reinstallable
    );
    assert_eq!(
        find_candidate(&report.candidates, ArtifactKind::UnityOutput).tier,
        RiskTier::Expensive
    );
    assert!(
        report
            .candidates
            .iter()
            .filter(|candidate| candidate.kind == ArtifactKind::DotNetOutput)
            .count()
            >= 2
    );
}

#[test]
fn rejects_decoys_and_nested_candidates() {
    let temp = tempdir();
    write_sized(&temp.path().join("decoy/target/app"), 10);
    write_sized(&temp.path().join("decoy/build/output"), 10);
    write_sized(&temp.path().join("decoy/bin/output"), 10);
    write_sized(&temp.path().join("decoy/obj/output"), 10);
    write_sized(&temp.path().join("decoy/.vs/cache.bin"), 10);
    write_sized(&temp.path().join("decoy/.gradle/cache.bin"), 10);
    write_sized(&temp.path().join("decoy/cmake-build-debug/app"), 10);
    write_sized(&temp.path().join("decoy/dist/bundle.js"), 10);
    write_sized(&temp.path().join("decoy/__pycache__/main.pyc"), 10);
    write_sized(&temp.path().join("decoy/venv/Lib/site.py"), 10);
    write_sized(&temp.path().join("decoy/.venv/pyvenv.cfg"), 1);
    write_sized(&temp.path().join("decoy/node_modules/pkg/index.js"), 10);
    write_sized(&temp.path().join("decoy/Library/cache.bin"), 10);
    write_sized(&temp.path().join("decoy/Temp/temp.bin"), 10);
    write_sized(&temp.path().join("web/package.json"), 1);
    write_sized(&temp.path().join("web/node_modules/a/index.js"), 10);
    write_sized(
        &temp
            .path()
            .join("web/node_modules/a/node_modules/b/index.js"),
        10,
    );
    let report = scan_all(temp.path());
    assert_eq!(report.candidates.len(), 1, "{:#?}", report.candidates);
    assert_eq!(report.candidates[0].kind, ArtifactKind::NodeModules);
}

#[test]
fn multiple_manifests_have_deterministic_precedence() {
    let temp = tempdir();
    write_sized(&temp.path().join("mixed/Cargo.toml"), 1);
    write_sized(&temp.path().join("mixed/pom.xml"), 1);
    write_sized(&temp.path().join("mixed/target/app"), 10);
    let report = scan_all(temp.path());
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].kind, ArtifactKind::RustTarget);
}

#[test]
fn logical_scan_has_explicitly_unavailable_allocation() {
    let temp = tempdir();
    write_sized(&temp.path().join("data/file.bin"), 12_345);
    let report = scan(&ScanOptions {
        roots: vec![temp.path().to_path_buf()],
        top: 10,
        min_size: Bytes(0),
        max_depth: None,
        excludes: Vec::new(),
        threads: None,
        measure: Measure::Logical,
    });
    assert_eq!(report.usage.logical, Bytes(12_345));
    assert_eq!(report.usage.allocated, None);
    assert_eq!(report.usage.reclaimable, None);
}

#[test]
fn scan_errors_retain_bounded_path_operation_and_os_details() {
    let temp = tempdir();
    let roots = (0..(storage_scout::MAX_ISSUES + 7))
        .map(|index| temp.path().join(format!("missing-{index}")))
        .collect::<Vec<_>>();
    let report = scan(&ScanOptions::new(roots));
    assert_eq!(report.stats.errors, (storage_scout::MAX_ISSUES + 7) as u64);
    assert_eq!(report.issues.len(), storage_scout::MAX_ISSUES);
    assert!(report.issues.iter().all(|issue| {
        !issue.path.as_os_str().is_empty()
            && issue.operation == "metadata"
            && !issue.error.is_empty()
    }));
}

#[test]
fn excludes_are_not_traversed_or_discovered() {
    let temp = tempdir();
    write_sized(&temp.path().join("keep/Cargo.toml"), 1);
    write_sized(&temp.path().join("keep/target/app"), 100);
    write_sized(&temp.path().join("skip/Cargo.toml"), 1);
    write_sized(&temp.path().join("skip/target/app"), 200);
    let report = scan(&ScanOptions {
        roots: vec![temp.path().to_path_buf()],
        top: 10,
        min_size: Bytes(0),
        max_depth: None,
        excludes: vec![temp.path().join("skip")],
        threads: None,
        measure: Measure::Both,
    });
    assert_eq!(report.candidates.len(), 1);
    assert!(report.candidates[0].path.ends_with("keep/target"));
}

#[test]
fn nonexistent_excluded_child_still_protects_its_candidate() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let target = temp.path().join("proj/target");
    write_sized(&target.join("app"), 100);
    let future_child = target.join("future-protected-child");

    let mut options = ScanOptions::new(vec![temp.path().to_path_buf()]);
    options.min_size = Bytes(0);
    options.measure = Measure::Both;
    options.excludes = vec![future_child.clone()];
    let report = discover_cleanup_candidates(&options).unwrap();
    assert!(report.candidates.is_empty());

    let report = clean_discovery(temp.path());
    let plan = create_cleanup_plan(
        &report.candidates,
        &[report.candidates[0].id.clone()],
        vec![future_child],
    )
    .unwrap();
    let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: true });
    assert!(target.exists());
    assert!(matches!(
        summary.outcomes[0].status,
        CleanupStatus::Rejected(_)
    ));
}

#[test]
fn dry_run_revalidates_and_deletes_nothing() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let target = temp.path().join("proj/target");
    write_sized(&target.join("app"), 4096);
    let report = clean_discovery(temp.path());
    let id = report.candidates[0].id.clone();
    let plan = create_cleanup_plan(&report.candidates, &[id], Vec::new()).unwrap();
    let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: false });
    assert!(target.exists());
    assert!(matches!(summary.outcomes[0].status, CleanupStatus::DryRun));
    assert!(summary.predicted_freed.is_some());
    assert_eq!(summary.observed_freed, None);
}

#[test]
fn execute_deletes_only_a_discovered_candidate() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let target = temp.path().join("proj/target");
    write_sized(&target.join("app"), 4096);
    let report = clean_discovery(temp.path());
    let plan = create_cleanup_plan(
        &report.candidates,
        &[report.candidates[0].id.clone()],
        Vec::new(),
    )
    .unwrap();
    let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: true });
    assert!(!target.exists());
    assert!(matches!(summary.outcomes[0].status, CleanupStatus::Deleted));
    assert!(summary.observed_freed.is_some());
}

#[test]
fn unknown_duplicate_excluded_and_stale_candidates_are_rejected() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let target = temp.path().join("proj/target");
    write_sized(&target.join("app"), 4096);
    let report = clean_discovery(temp.path());
    let id = report.candidates[0].id.clone();
    let unknown = CandidateId::from_str(&"a".repeat(64)).unwrap();
    assert!(create_cleanup_plan(&report.candidates, &[unknown], Vec::new()).is_err());
    assert!(
        create_cleanup_plan(&report.candidates, &[id.clone(), id.clone()], Vec::new()).is_err()
    );

    let excluded = create_cleanup_plan(
        &report.candidates,
        std::slice::from_ref(&id),
        vec![target.clone()],
    )
    .unwrap();
    let summary = apply_cleanup_plan(&excluded, ApplyOptions { execute: true });
    assert!(target.exists());
    assert!(matches!(
        summary.outcomes[0].status,
        CleanupStatus::Rejected(_)
    ));

    let stale = create_cleanup_plan(&report.candidates, &[id], Vec::new()).unwrap();
    write_sized(&target.join("new-file"), 10);
    let summary = apply_cleanup_plan(&stale, ApplyOptions { execute: true });
    assert!(target.exists());
    assert!(matches!(
        summary.outcomes[0].status,
        CleanupStatus::Rejected(_)
    ));
}

#[test]
fn replaced_candidate_identity_is_rejected() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let target = temp.path().join("proj/target");
    write_sized(&target.join("app"), 4096);
    let report = clean_discovery(temp.path());
    let plan = create_cleanup_plan(
        &report.candidates,
        &[report.candidates[0].id.clone()],
        Vec::new(),
    )
    .unwrap();
    fs::remove_dir_all(&target).unwrap();
    write_sized(&target.join("app"), 4096);
    let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: true });
    assert!(target.exists());
    assert!(matches!(
        summary.outcomes[0].status,
        CleanupStatus::Rejected(_)
    ));
}

#[test]
fn same_size_content_change_makes_candidate_stale() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let payload = temp.path().join("proj/target/app");
    fs::create_dir_all(payload.parent().unwrap()).unwrap();
    fs::write(&payload, [1u8; 64]).unwrap();
    let report = clean_discovery(temp.path());
    let plan = create_cleanup_plan(
        &report.candidates,
        &[report.candidates[0].id.clone()],
        Vec::new(),
    )
    .unwrap();
    fs::write(&payload, [2u8; 64]).unwrap();
    let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: true });
    assert!(payload.exists());
    assert!(matches!(
        summary.outcomes[0].status,
        CleanupStatus::Rejected(_)
    ));
}

#[cfg(windows)]
#[test]
fn reparse_inserted_after_discovery_is_rejected() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let target = temp.path().join("proj/target");
    write_sized(&target.join("app"), 4096);
    let report = clean_discovery(temp.path());
    let plan = create_cleanup_plan(
        &report.candidates,
        &[report.candidates[0].id.clone()],
        Vec::new(),
    )
    .unwrap();
    let elsewhere = temp.path().join("elsewhere");
    write_sized(&elsewhere.join("payload"), 10);
    let junction = target.join("junction");
    let junction_text = junction.display().to_string().replace('\'', "''");
    let elsewhere_text = elsewhere.display().to_string().replace('\'', "''");
    let script = format!(
        "New-Item -ItemType Junction -Path '{junction_text}' -Target '{elsewhere_text}' | Out-Null"
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .unwrap();
    assert!(status.success());
    let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: true });
    assert!(target.exists());
    assert!(elsewhere.exists());
    assert!(matches!(
        summary.outcomes[0].status,
        CleanupStatus::Rejected(_)
    ));
}

#[cfg(windows)]
#[test]
fn junction_and_symlink_cleanup_roots_are_rejected() {
    use std::os::windows::fs::symlink_dir;

    let temp = tempdir();
    let real = temp.path().join("real-project");
    write_sized(&real.join("Cargo.toml"), 1);
    write_sized(&real.join("target/app"), 10);
    let junction = temp.path().join("project-junction");
    let junction_text = junction.display().to_string().replace('\'', "''");
    let real_text = real.display().to_string().replace('\'', "''");
    let script = format!(
        "New-Item -ItemType Junction -Path '{junction_text}' -Target '{real_text}' | Out-Null"
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(discover_cleanup_candidates(&ScanOptions::new(vec![junction])).is_err());

    let symlink = temp.path().join("project-symlink");
    if symlink_dir(&real, &symlink).is_ok() {
        assert!(discover_cleanup_candidates(&ScanOptions::new(vec![symlink])).is_err());
    }
}

#[test]
fn current_directory_and_profile_roots_are_refused_for_clean() {
    let cwd = std::env::current_dir().unwrap();
    assert!(
        discover_cleanup_candidates(&ScanOptions::new(vec![cwd])).is_err(),
        "current directory must not be a broad clean root"
    );
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        assert!(
            discover_cleanup_candidates(&ScanOptions::new(vec![PathBuf::from(profile)])).is_err()
        );
    }
    if let Some(app_data) = std::env::var_os("LOCALAPPDATA") {
        assert!(
            discover_cleanup_candidates(&ScanOptions::new(vec![PathBuf::from(app_data)])).is_err()
        );
    }
    for variable in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
    ] {
        if let Some(path) = std::env::var_os(variable) {
            assert!(
                discover_cleanup_candidates(&ScanOptions::new(vec![PathBuf::from(path)])).is_err(),
                "{variable} must be protected"
            );
        }
    }
    let drive_root = std::env::current_dir()
        .unwrap()
        .ancestors()
        .last()
        .unwrap()
        .to_path_buf();
    assert!(discover_cleanup_candidates(&ScanOptions::new(vec![drive_root])).is_err());
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let users_root = PathBuf::from(profile).parent().unwrap().to_path_buf();
        assert!(discover_cleanup_candidates(&ScanOptions::new(vec![users_root])).is_err());
    }
}

#[cfg(windows)]
#[test]
fn hard_links_are_deduplicated_and_external_links_are_not_reclaimable() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let inside = temp.path().join("proj/target/app.bin");
    write_sized(&inside, 64 * 1024);
    let outside = temp.path().join("outside-app.bin");
    fs::hard_link(&inside, &outside).unwrap();
    let report = clean_discovery(temp.path());
    let candidate = find_candidate(&report.candidates, ArtifactKind::RustTarget);
    assert!(candidate.usage.allocated.unwrap() > Bytes(0));
    assert_eq!(candidate.usage.reclaimable, Some(Bytes(0)));
}

#[cfg(windows)]
#[test]
fn links_across_selected_candidates_count_once_and_become_reclaimable() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/App.csproj"), 1);
    let first = temp.path().join("proj/bin/app.dll");
    let second = temp.path().join("proj/obj/app.dll");
    write_sized(&first, 64 * 1024);
    fs::create_dir_all(second.parent().unwrap()).unwrap();
    fs::hard_link(&first, &second).unwrap();
    let report = clean_discovery(temp.path());
    assert_eq!(report.candidates.len(), 2);
    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| candidate.usage.reclaimable == Some(Bytes(0)))
    );
    let ids = report
        .candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect::<Vec<_>>();
    let plan = create_cleanup_plan(&report.candidates, &ids, Vec::new()).unwrap();
    assert!(plan.usage.reclaimable.unwrap() > Bytes(0));
    assert!(plan.usage.allocated.unwrap() < Bytes(128 * 1024));
}

#[cfg(windows)]
#[test]
fn compressed_and_sparse_files_use_allocation_size() {
    use std::io::{Seek, SeekFrom, Write};

    let temp = tempdir();
    write_sized(&temp.path().join("compressed/Cargo.toml"), 1);
    let compressed = temp.path().join("compressed/target/zeros.bin");
    fs::create_dir_all(compressed.parent().unwrap()).unwrap();
    fs::write(&compressed, vec![0u8; 1024 * 1024]).unwrap();
    let compact = Command::new("compact")
        .args(["/C", "/I", "/Q"])
        .arg(&compressed)
        .status()
        .unwrap();

    write_sized(&temp.path().join("sparse/Cargo.toml"), 1);
    let sparse = temp.path().join("sparse/target/sparse.bin");
    fs::create_dir_all(sparse.parent().unwrap()).unwrap();
    File::create(&sparse).unwrap();
    let sparse_flag = Command::new("fsutil")
        .args(["sparse", "setflag"])
        .arg(&sparse)
        .status()
        .unwrap();
    if !compact.success() || !sparse_flag.success() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "filesystem does not support compression/sparse test operations"
        );
        return;
    }
    let mut sparse_file = fs::OpenOptions::new().write(true).open(&sparse).unwrap();
    sparse_file.set_len(8 * 1024 * 1024).unwrap();
    sparse_file.seek(SeekFrom::End(-1)).unwrap();
    sparse_file.write_all(&[1]).unwrap();

    let report = clean_discovery(temp.path());
    let compressed_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.path.ends_with("compressed/target"))
        .unwrap();
    let sparse_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.path.ends_with("sparse/target"))
        .unwrap();
    assert!(
        compressed_candidate.usage.allocated.unwrap() < compressed_candidate.usage.logical,
        "compressed usage: {:?}",
        compressed_candidate.usage
    );
    assert!(
        sparse_candidate.usage.allocated.unwrap() < sparse_candidate.usage.logical,
        "sparse usage: {:?}",
        sparse_candidate.usage
    );
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_storage-scout"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_help_syntax_strict_and_scan_json_exit_codes() {
    let help = cli(&[]);
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));

    let syntax = cli(&["reclaim"]);
    assert_eq!(syntax.status.code(), Some(2));
    let removed_all = cli(&["clean", ".", "--all"]);
    assert_eq!(removed_all.status.code(), Some(2));

    let missing = cli(&["scan", "definitely-missing", "--json", "--strict"]);
    assert_eq!(missing.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert!(json["stats"]["errors"].as_u64().unwrap() >= 1);
    assert_eq!(json["issues"][0]["operation"], "metadata");
    assert!(json["issues"][0]["path"].is_string());
    assert!(json["issues"][0]["error"].is_string());
}

#[test]
fn cli_json_id_dry_run_non_tty_guard_and_execute_yes() {
    let temp = tempdir();
    write_sized(&temp.path().join("proj/Cargo.toml"), 1);
    let target = temp.path().join("proj/target");
    write_sized(&target.join("app"), 4096);
    let root = temp.path().to_str().unwrap();

    let discovery = cli(&["clean", root, "--min-size", "0", "--json"]);
    assert_eq!(discovery.status.code(), Some(0));
    let document: serde_json::Value = serde_json::from_slice(&discovery.stdout).unwrap();
    assert_eq!(document["schema_version"], SCHEMA_VERSION);
    assert_eq!(document["mode"], "discovery");
    let id = document["candidates"][0]["id"].as_str().unwrap();

    let dry_run = cli(&["clean", root, "--min-size", "0", "--id", id, "--json"]);
    assert_eq!(dry_run.status.code(), Some(0));
    assert!(target.exists());
    let dry_json: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_json["mode"], "dry-run");

    let unsafe_non_tty = cli(&["clean", root, "--min-size", "0", "--id", id, "--execute"]);
    assert_eq!(unsafe_non_tty.status.code(), Some(1));
    assert!(target.exists());

    let execute = cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--id",
        id,
        "--execute",
        "--yes",
        "--json",
    ]);
    assert_eq!(execute.status.code(), Some(0), "{execute:#?}");
    assert!(!target.exists());
    let execute_json: serde_json::Value = serde_json::from_slice(&execute.stdout).unwrap();
    assert_eq!(execute_json["mode"], "executed");
    assert!(execute_json["summary"]["observed_freed"].is_number());
}

#[test]
fn cli_stale_id_and_locked_tier_fail_safely() {
    let temp = tempdir();
    write_sized(&temp.path().join("web/package.json"), 1);
    write_sized(&temp.path().join("web/node_modules/pkg/index.js"), 4096);
    let root = temp.path().to_str().unwrap();
    let discovery = cli(&["clean", root, "--min-size", "0", "--json"]);
    let document: serde_json::Value = serde_json::from_slice(&discovery.stdout).unwrap();
    let id = document["candidates"][0]["id"].as_str().unwrap();

    let locked = cli(&["clean", root, "--min-size", "0", "--id", id, "--json"]);
    assert_eq!(locked.status.code(), Some(1));

    write_sized(&temp.path().join("web/node_modules/new.js"), 1);
    let stale = cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--include-tier",
        "reinstallable",
        "--id",
        id,
        "--execute",
        "--yes",
        "--json",
    ]);
    assert_eq!(stale.status.code(), Some(1));
    assert!(temp.path().join("web/node_modules").exists());
}

#[test]
fn cli_kind_and_age_filters_are_explicit() {
    let temp = tempdir();
    write_sized(&temp.path().join("rust/Cargo.toml"), 1);
    write_sized(&temp.path().join("rust/target/app"), 100);
    write_sized(&temp.path().join("web/package.json"), 1);
    write_sized(&temp.path().join("web/dist/app.js"), 100);
    let root = temp.path().to_str().unwrap();

    let kind = cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--kind",
        "rust-target",
        "--json",
    ]);
    assert_eq!(kind.status.code(), Some(0));
    let document: serde_json::Value = serde_json::from_slice(&kind.stdout).unwrap();
    assert_eq!(document["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(document["candidates"][0]["kind"], "rust-target");

    let old = cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--older-than",
        "30d",
        "--json",
    ]);
    assert_eq!(old.status.code(), Some(0));
    let document: serde_json::Value = serde_json::from_slice(&old.stdout).unwrap();
    assert!(document["candidates"].as_array().unwrap().is_empty());

    assert_eq!(
        cli(&["clean", root, "--kind", "unknown-kind"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        cli(&["scan", root, "--threads", "0"]).status.code(),
        Some(2)
    );
}
