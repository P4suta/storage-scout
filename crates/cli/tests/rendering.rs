#![expect(clippy::unwrap_used, reason = "rendering to a buffer cannot fail")]

use storage_scout::core::artifact::{Kind, Tier};
use storage_scout::core::gate::{Mandate, TierGrant};
use storage_scout::core::size::Bytes;
use storage_scout::{
    Color, Measure, Mode, ScanOptions, Scout, render_clean, render_explain, render_scan,
};
use testkit::{tempdir, write_cache_tag, write_cargo_project, write_sized};

fn render(write: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
    let mut buffer = Vec::new();
    write(&mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

macro_rules! stable {
    ($body:expr) => {{
        let mut settings = insta::Settings::clone_current();
        settings.add_filter(r"[A-Za-z]:\\[^\s]*\.storage-scout-[^\s]*", "<PATH>");
        settings.add_filter(r"/[^\s]*\.storage-scout-[^\s]*", "<PATH>");
        settings.add_filter(r"\b[0-9a-f]{64}\b", "<ID>");
        settings.add_filter(r"storage-scout \d+\.\d+\.\d+", "storage-scout <VERSION>");
        settings.add_filter(r"same device \(0x[0-9a-f]+\)", "same device (<DEVICE>)");
        settings.add_filter(
            r"mount points appear as reparse points here",
            "same device (<DEVICE>)",
        );
        settings.add_filter(
            r"Predicted reclaimable: [^\n]+",
            "Predicted reclaimable: <BYTES>",
        );
        settings.bind(|| $body);
    }};
}

fn fixture(root: &std::path::Path) {
    let _target = write_cargo_project(&root.join("proj"), 64 * 1024);
    write_cache_tag(&root.join("cache"));
    write_sized(&root.join("cache/blob"), 32 * 1024);
}

fn options(root: &std::path::Path) -> ScanOptions {
    ScanOptions {
        roots: vec![root.to_path_buf()],
        top: 5,
        min_size: Bytes::ZERO,
        max_depth: Some(1),
        excludes: Vec::new(),
        threads: Some(1),
        measure: Measure::Logical,
    }
}

#[test]
fn a_scan_report() {
    let temp = tempdir("render-scan");
    fixture(temp.path());
    let report = Scout::with(testkit::open_protection())
        .confined(vec![temp.path().to_path_buf()])
        .scan(&options(temp.path()));
    stable!(insta::assert_snapshot!(render(|out| render_scan(
        &report,
        Color::Never,
        out
    ))));
}

#[test]
fn a_dry_run() {
    let temp = tempdir("render-clean");
    fixture(temp.path());
    let scout = Scout::with(testkit::open_protection()).confined(vec![temp.path().to_path_buf()]);
    let report = scout.discover(&options(temp.path())).unwrap();
    let ids = report
        .candidates
        .iter()
        .map(|found| found.candidate().id().clone())
        .collect::<Vec<_>>();
    let mandate = Mandate {
        tiers: TierGrant::ROUTINE.with(Tier::Reinstallable),
        ..Mandate::default()
    };
    let plan = Scout::plan(&report.candidates, &ids, mandate, &[]).unwrap();
    let summary = scout.apply(&plan, Mode::DryRun);
    stable!(insta::assert_snapshot!(render(|out| render_clean(
        &plan,
        &summary,
        Color::Never,
        out
    ))));
}

#[test]
fn an_explanation_that_holds_and_one_that_refuses() {
    let temp = tempdir("render-explain");
    fixture(temp.path());
    let scout = Scout::with(testkit::open_protection()).confined(vec![temp.path().to_path_buf()]);
    let eligible = scout
        .explain(&temp.path().join("proj/target"), &[], Mandate::default())
        .unwrap();
    let refused = scout
        .explain(&temp.path().join("cache"), &[], Mandate::default())
        .unwrap();
    stable!(insta::assert_snapshot!(render(|out| {
        render_explain(&eligible, out)?;
        render_explain(&refused, out)
    })));
}

#[test]
fn the_vocabulary_a_consumer_switches_on_is_stable() {
    let kinds = Kind::ALL
        .iter()
        .map(|kind| format!("{:<20} {:<14} {}", kind.as_str(), kind.tier(), kind.label()))
        .collect::<Vec<_>>()
        .join("\n");
    insta::assert_snapshot!(kinds);
}
