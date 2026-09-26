#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::unwrap_used,
    reason = "tests build real trees and compare their files"
)]

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use storage_scout::core::reject::Rejection;
use storage_scout::core::share::{Failure, MINIMUM, Method, Refusal, TEMPORARY_SUFFIX};
use storage_scout::core::size::Bytes;
use storage_scout::{Admission, AutoPolicy, DedupeRun, Mode, PairStatus, Scout};
use testkit::{Built, tempdir, write_cache_tag, write_patterned, write_sized};

const LEN: u64 = 256 * 1024;
const RLIB: &str = "debug/deps/libx.rlib";
const EDGE: &str = "debug/deps/libedge.rmeta";

fn project(root: &Path, name: &str) -> PathBuf {
    write_sized(&root.join(name).join("Cargo.toml"), 1);
    let target = root.join(name).join("target");
    write_sized(&target.join("debug/.cargo-lock"), 0);
    target
}

fn scout(root: &Path) -> Scout {
    Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()])
}

fn dedupe(root: &Path, mode: Mode) -> DedupeRun {
    scout(root)
        .dedupe(&[root.to_path_buf()], &[], mode)
        .unwrap()
}

fn method(run: &DedupeRun) -> Option<Method> {
    run.subjects
        .iter()
        .find_map(|subject| match &subject.admission {
            Admission::Admitted { method, .. } => Some(*method),
            Admission::Rejected { .. } => None,
        })
}

fn capable(root: &Path) -> Option<Method> {
    let run = dedupe(root, Mode::DryRun);
    let found = method(&run);
    if found.is_none() {
        let required = std::env::var_os("STORAGE_SCOUT_REQUIRE_SHARING").is_some();
        let reasons = run
            .subjects
            .iter()
            .map(|subject| match &subject.admission {
                Admission::Rejected { rejection } => rejection.to_string(),
                Admission::Admitted { .. } => String::from("admitted"),
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("; ");
        assert!(!required, "this volume must share blocks: {reasons}");
        let _skipped = Built::Unavailable(reasons).or_decline("a volume that shares blocks");
    }
    found
}

fn statuses(run: &DedupeRun) -> Vec<&PairStatus> {
    run.pairs.iter().map(|pair| &pair.status).collect()
}

fn identity(path: &Path) -> (u64, std::time::SystemTime, fs::Permissions) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (
        metadata.len(),
        metadata.modified().unwrap(),
        metadata.permissions(),
    )
}

#[test]
fn identical_build_outputs_come_to_share_their_blocks_without_changing_a_byte() {
    let temp = tempdir("dedupe-share");
    let root = temp.path();
    let targets = ["a", "b", "c"].map(|name| project(root, name));
    let [a, b, c] = &targets;
    for target in &targets {
        write_patterned(&target.join(RLIB), LEN, 1);
    }
    write_patterned(&a.join(EDGE), MINIMUM, 12);
    write_patterned(&b.join(EDGE), MINIMUM, 12);
    write_patterned(&a.join("debug/deps/liby.rlib"), LEN, 2);
    write_patterned(&b.join("debug/deps/liby.rlib"), LEN, 3);
    write_patterned(&a.join("debug/deps/small.rmeta"), MINIMUM - 1, 4);
    write_patterned(&b.join("debug/deps/small.rmeta"), MINIMUM - 1, 4);
    let Some(method) = capable(root) else {
        return;
    };
    let before = [b.join(RLIB), c.join(RLIB), b.join(EDGE)].map(|path| identity(&path));

    let dry = dedupe(root, Mode::DryRun);
    assert_eq!(statuses(&dry), vec![&PairStatus::WouldShare; 3], "{dry:#?}");
    assert_eq!(dry.shared().get(), LEN * 2 + MINIMUM);

    let run = dedupe(root, Mode::Execute);
    assert!(!run.failed(), "{run:#?}");
    assert_eq!(statuses(&run), vec![&PairStatus::Shared; 3]);
    assert!(run.observed_freed.is_some());
    for target in [b, c] {
        assert_eq!(
            fs::read(a.join(RLIB)).unwrap(),
            fs::read(target.join(RLIB)).unwrap()
        );
    }
    assert_eq!(
        fs::read(a.join(EDGE)).unwrap(),
        fs::read(b.join(EDGE)).unwrap()
    );
    assert_ne!(
        fs::read(a.join("debug/deps/liby.rlib")).unwrap(),
        fs::read(b.join("debug/deps/liby.rlib")).unwrap()
    );
    assert_eq!(
        [b.join(RLIB), c.join(RLIB), b.join(EDGE)].map(|path| identity(&path)),
        before
    );
    if let Some(shared) = testkit::shares_extents(&b.join(RLIB)) {
        assert!(shared, "the kernel does not report the extents as shared");
    }

    let again = dedupe(root, Mode::DryRun);
    match method {
        Method::CloneAndSwap => assert!(again.pairs.is_empty(), "{again:#?}"),
        Method::DedupeRange => {
            assert_eq!(statuses(&again), vec![&PairStatus::WouldShare; 3]);
        },
    }
}

#[test]
fn a_file_that_cannot_be_replaced_is_kept_and_the_plain_copy_is_shared_with_it() {
    let temp = tempdir("dedupe-refuse");
    let root = temp.path();
    let targets = ["a", "b", "c", "d", "e"].map(|name| project(root, name));
    let [first, second, third, fourth, plain_target] = &targets;
    for target in [first, second] {
        write_patterned(&target.join("debug/app"), LEN, 5);
        let Some(_) =
            testkit::executable(&target.join("debug/app")).or_decline("an executable file")
        else {
            return;
        };
    }
    for target in [third, fourth, plain_target] {
        write_patterned(&target.join(RLIB), LEN, 6);
    }
    for target in [third, fourth] {
        let Some(_) = testkit::hard_link(&target.join("debug/linked.rlib"), &target.join(RLIB))
            .or_decline("a hard link")
        else {
            return;
        };
    }
    let Some(method) = capable(root) else {
        return;
    };
    let run = dedupe(root, Mode::DryRun);
    let mut found = run
        .pairs
        .iter()
        .map(|pair| format!("{:?}", pair.status))
        .collect::<Vec<_>>();
    found.sort();
    let expected = match method {
        Method::CloneAndSwap => vec![
            PairStatus::Refused {
                refusal: Refusal::Executable,
            },
            PairStatus::Refused {
                refusal: Refusal::HardLinked { links: 2 },
            },
            PairStatus::WouldShare,
        ],
        Method::DedupeRange => vec![PairStatus::WouldShare; 3],
    };
    let mut expected = expected
        .iter()
        .map(|status| format!("{status:?}"))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(found, expected, "{run:#?}");
    if method == Method::CloneAndSwap {
        let plain = run
            .pairs
            .iter()
            .find(|pair| pair.status == PairStatus::WouldShare)
            .unwrap();
        assert_eq!(
            plain.duplicate,
            testkit::location(&fs::canonicalize(plain_target.join(RLIB)).unwrap())
        );
    }
}

#[test]
fn a_running_build_keeps_its_whole_target_out_of_reach() {
    let temp = tempdir("dedupe-busy");
    let root = temp.path();
    let a = project(root, "a");
    let b = project(root, "b");
    write_patterned(&a.join(RLIB), LEN, 7);
    write_patterned(&b.join(RLIB), LEN, 7);
    if capable(root).is_none() {
        return;
    }
    let holder = File::open(b.join("debug/.cargo-lock")).unwrap();
    holder.lock().unwrap();
    let before = fs::read(b.join(RLIB)).unwrap();
    let run = dedupe(root, Mode::Execute);
    assert!(run.pairs.is_empty(), "{run:#?}");
    assert!(run.subjects.iter().any(|subject| matches!(
        &subject.admission,
        Admission::Rejected {
            rejection: Rejection::Busy { .. }
        }
    )));
    assert_eq!(fs::read(b.join(RLIB)).unwrap(), before);
    holder.unlock().unwrap();
}

#[test]
fn a_target_with_a_directory_that_cannot_be_read_is_left_whole() {
    let temp = tempdir("dedupe-unreadable");
    let root = temp.path();
    let a = project(root, "a");
    let b = project(root, "b");
    write_patterned(&a.join(RLIB), LEN, 15);
    write_patterned(&b.join(RLIB), LEN, 15);
    fs::create_dir_all(b.join("debug/.fingerprint")).unwrap();
    let secret = b.join("debug/deps/secret");
    write_sized(&secret.join("file"), 16);
    let private = b.join("debug/private");
    write_sized(&private.join("file"), 16);
    if capable(root).is_none() {
        return;
    }
    for sealed in [&secret, &private] {
        let Some(restricted) = testkit::restrict(sealed, 0o000) else {
            testkit::decline("a restricted path");
            return;
        };
        let run = dedupe(root, Mode::Execute);
        drop(restricted);
        assert!(run.pairs.is_empty(), "{run:#?}");
        assert!(run.subjects.iter().any(|subject| matches!(
            &subject.admission,
            Admission::Rejected {
                rejection: Rejection::Io { .. }
            }
        )));
    }
}

#[test]
fn only_a_regular_lock_file_holds_a_target() {
    let temp = tempdir("dedupe-linked-lock");
    let root = temp.path();
    let a = project(root, "a");
    let b = project(root, "b");
    write_patterned(&a.join(RLIB), LEN, 16);
    write_patterned(&b.join(RLIB), LEN, 16);
    let elsewhere = root.join("elsewhere.lock");
    write_sized(&elsewhere, 0);
    let Some(_) = testkit::symlink_file(&b.join("debug/.cargo-build-lock"), &elsewhere)
        .or_decline("a file link")
    else {
        return;
    };
    if capable(root).is_none() {
        return;
    }
    let holder = File::open(&elsewhere).unwrap();
    holder.lock().unwrap();
    let run = dedupe(root, Mode::DryRun);
    assert_eq!(statuses(&run), vec![&PairStatus::WouldShare], "{run:#?}");
}

#[test]
fn extended_attributes_decide_whether_a_replacement_would_be_faithful() {
    let temp = tempdir("dedupe-xattr");
    let root = temp.path();
    let a = project(root, "a");
    let b = project(root, "b");
    let c = project(root, "c");
    for target in [&a, &b, &c] {
        write_patterned(&target.join(RLIB), LEN, 17);
    }
    if capable(root) != Some(Method::CloneAndSwap) {
        return;
    }
    for (target, value) in [(&a, "one"), (&b, "one"), (&c, "two")] {
        let Some(_) = testkit::set_xattr(&target.join(RLIB), "storage-scout.test", value)
            .or_decline("an extended attribute")
        else {
            return;
        };
    }
    let run = dedupe(root, Mode::DryRun);
    let mut found = statuses(&run)
        .into_iter()
        .map(|status| format!("{status:?}"))
        .collect::<Vec<_>>();
    found.sort();
    let mut expected = [
        PairStatus::WouldShare,
        PairStatus::Refused {
            refusal: Refusal::AttributesDiffer,
        },
    ]
    .iter()
    .map(|status| format!("{status:?}"))
    .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(found, expected, "{run:#?}");
}

#[test]
fn a_file_named_like_a_temporary_is_never_paired() {
    let temp = tempdir("dedupe-temporary-name");
    let root = temp.path();
    let a = project(root, "a");
    let b = project(root, "b");
    write_patterned(&a.join(RLIB), LEN, 18);
    write_patterned(&leftover(&b), LEN, 18);
    if capable(root).is_none() {
        return;
    }
    assert!(dedupe(root, Mode::DryRun).pairs.is_empty());
}

#[test]
fn a_cache_whose_writer_takes_no_lock_is_never_rewritten() {
    let temp = tempdir("dedupe-protocol");
    let root = temp.path();
    for name in ["one", "two"] {
        write_cache_tag(&root.join(name));
        write_patterned(&root.join(name).join("blob"), LEN, 8);
    }
    let run = dedupe(root, Mode::Execute);
    assert!(run.pairs.is_empty());
    assert_eq!(run.subjects.len(), 2);
    assert!(run.subjects.iter().all(|subject| matches!(
        &subject.admission,
        Admission::Rejected {
            rejection: Rejection::NoLockProtocol { .. }
        }
    )));
}

fn leftover(target: &Path) -> PathBuf {
    target.join(format!("debug/deps/.libx.rlib{TEMPORARY_SUFFIX}"))
}

#[test]
fn an_interrupted_swap_is_finished_only_when_the_leftover_matches() {
    let temp = tempdir("dedupe-leftover");
    let root = temp.path();
    let a = project(root, "a");
    let b = project(root, "b");
    write_patterned(&a.join(RLIB), LEN, 9);
    write_patterned(&b.join(RLIB), LEN, 9);
    if capable(root) != Some(Method::CloneAndSwap) {
        return;
    }
    write_patterned(&leftover(&b), LEN, 10);
    let blocked = dedupe(root, Mode::Execute);
    assert_eq!(
        statuses(&blocked),
        vec![&PairStatus::Failed {
            failure: Failure::Leftover
        }]
    );
    testkit::assert_present(leftover(&b));

    write_patterned(&leftover(&b), LEN, 9);
    let finished = dedupe(root, Mode::Execute);
    assert_eq!(
        statuses(&finished),
        vec![&PairStatus::Shared],
        "{finished:#?}"
    );
    testkit::assert_absent(leftover(&b));
    assert_eq!(
        fs::read(a.join(RLIB)).unwrap(),
        fs::read(b.join(RLIB)).unwrap()
    );
}

fn policy(root: &Path) -> AutoPolicy {
    AutoPolicy::parse(&format!(
        "[select]\nroots = [{root:?}]\n",
        root = root.to_str().unwrap(),
    ))
    .unwrap()
}

#[test]
fn auto_shares_identical_files_whenever_it_runs_and_deletes_nothing_owned() {
    let temp = tempdir("dedupe-auto");
    let root = temp.path();
    let a = project(root, "a");
    let b = project(root, "b");
    write_patterned(&a.join(RLIB), LEN, 11);
    write_patterned(&b.join(RLIB), LEN, 11);

    if capable(root).is_none() {
        return;
    }
    let dry = scout(root).auto(&policy(root), Mode::DryRun).unwrap();
    assert_eq!(dry.reap.selected, 0, "{dry:#?}");
    assert_eq!(dry.dedupe.totals.shared.bytes, Bytes::new(LEN), "{dry:#?}");

    let run = scout(root).auto(&policy(root), Mode::Execute).unwrap();
    assert!(!run.failed(), "{run:#?}");
    assert_eq!(run.dedupe.totals.shared.bytes, Bytes::new(LEN), "{run:#?}");
    assert_eq!(
        fs::read(a.join(RLIB)).unwrap(),
        fs::read(b.join(RLIB)).unwrap()
    );
    testkit::assert_present(&a);
    testkit::assert_present(&b);
}
