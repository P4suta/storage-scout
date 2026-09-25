#![expect(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "tests build and inspect real trees and mounts"
)]

use std::fs;
use std::path::Path;

use storage_scout::core::candidate::CandidateId;
use storage_scout::core::gate::Mandate;
use storage_scout::core::reject::Rejection;
use storage_scout::core::size::Bytes;
use storage_scout::{Measure, Mode, ScanOptions, Scout};
use testkit::{scratch_mount, tempdir, write_declared_target, write_sized};

fn scout() -> Scout {
    Scout::with(testkit::open_protection()).confined(vec![testkit::ceiling()])
}

fn options(root: &Path) -> ScanOptions {
    ScanOptions {
        roots: vec![root.to_path_buf()],
        top: 10,
        min_size: Bytes::ZERO,
        max_depth: Some(3),
        excludes: Vec::new(),
        threads: Some(1),
        measure: Measure::Allocated,
    }
}

fn with_mount(name: &str, body: impl FnOnce(&Path, &Path)) {
    let temp = tempdir(name);
    let root = temp.path().join("root");
    fs::create_dir_all(&root).unwrap();
    match scratch_mount(&root, "mounted") {
        Ok(mount) => body(&root, &mount.path),
        Err(reason) => {
            let skipped =
                format!("skipping {name}: cannot mount a scratch filesystem ({reason})\n");
            std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes()).unwrap();
        },
    }
}

#[test]
fn a_scan_counts_the_boundary_and_not_what_is_behind_it() {
    with_mount("mount-scan", |root, mounted| {
        write_sized(&root.join("here.bin"), 64 * 1024);
        write_sized(&mounted.join("elsewhere.bin"), 512 * 1024);
        let report = scout().scan(&options(root));
        assert_eq!(report.stats.mount_boundaries_skipped, 1);
        assert!(report.usage.logical < Bytes::new(512 * 1024));
        assert!(report.usage.logical >= Bytes::new(64 * 1024));
    });
}

#[test]
fn a_candidate_beside_a_mount_never_reaches_into_it() {
    with_mount("mount-beside", |root, mounted| {
        write_sized(&root.join("proj/Cargo.toml"), 32);
        write_sized(&root.join("proj/target/debug/app"), 64 * 1024);
        write_sized(&mounted.join("payload.bin"), 128 * 1024);
        let discovery = scout().discover(&options(root)).unwrap();
        assert!(
            discovery
                .candidates
                .iter()
                .all(|found| !found.path().starts_with(mounted))
        );
        let ids = discovery
            .candidates
            .iter()
            .map(|found| found.candidate().id().clone())
            .collect::<Vec<CandidateId>>();
        let plan = Scout::plan(&discovery.candidates, &ids, Mandate::default(), &[]).unwrap();
        let summary = scout().apply(&plan, Mode::Execute);
        assert!(!summary.failed(), "{summary:#?}");
        testkit::assert_present(mounted.join("payload.bin"));
    });
}

#[test]
fn a_tree_that_contains_a_mount_is_refused_whole() {
    with_mount("mount-inside", |root, mounted| {
        write_declared_target(root, "debug");
        write_sized(&root.join("debug/app"), 64 * 1024);
        write_sized(&mounted.join("payload.bin"), 64 * 1024);
        let parent = root.parent().unwrap();
        let discovery = scout().discover(&options(parent)).unwrap();
        let Some(found) = discovery
            .candidates
            .iter()
            .find(|found| found.path().ends_with("root"))
        else {
            return;
        };
        let planned = Scout::plan(
            &discovery.candidates,
            std::slice::from_ref(found.candidate().id()),
            Mandate::default(),
            &[],
        );
        match planned {
            Err(rejection) => assert!(
                matches!(rejection, Rejection::MountBoundary { .. }),
                "{rejection:?}"
            ),
            Ok(plan) => assert!(scout().apply(&plan, Mode::Execute).failed()),
        }
        testkit::assert_present(mounted.join("payload.bin"));
    });
}
