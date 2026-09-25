#![expect(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "tests build real trees and check what is left"
)]

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use storage_scout::core::ownership::Settlement;
use storage_scout::core::reject::{IoFailure, IoKind, Rejection};
use storage_scout::core::size::Bytes;
use storage_scout::{AutoPolicy, Mode, PruneAdmission, PruneRun, Scout};
use testkit::{Built, MarkerKeep, MarkerRole, tempdir, write_macho_image, write_sized};

fn scout(root: &Path) -> Scout {
    Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()])
}

fn prune(root: &Path, mode: Mode) -> PruneRun {
    scout(root).prune(&[root.to_path_buf()], &[], mode).unwrap()
}

fn unsupported(run: &PruneRun) -> bool {
    run.subjects.iter().any(|subject| {
        matches!(
            &subject.admission,
            PruneAdmission::Rejected {
                rejection: Rejection::Io {
                    failure: IoFailure {
                        kind: IoKind::Unsupported,
                        ..
                    },
                    ..
                }
            }
        )
    })
}

fn pruned(root: &Path) -> Option<PruneRun> {
    let run = prune(root, Mode::Execute);
    if unsupported(&run) {
        let _skipped = Built::Unavailable(String::from("pruning in place is not supported"))
            .or_skip("a platform that prunes in place");
        return None;
    }
    Some(run)
}

fn profile(root: &Path, name: &str) -> PathBuf {
    let project = root.join(name);
    write_sized(&project.join("Cargo.toml"), 1);
    testkit::write_cache_tag(&project.join("target"));
    let profile = project.join("target/debug");
    write_sized(&profile.join(".cargo-lock"), 0);
    fs::create_dir_all(profile.join(".fingerprint")).unwrap();
    profile
}

fn lock_of(session: &Path) -> PathBuf {
    let name = session.file_name().unwrap().to_str().unwrap();
    let (stem, _) = name.rsplit_once('-').unwrap();
    session.with_file_name(format!("{stem}.lock"))
}

fn session(profile: &Path, unit: &str, name: &str) -> PathBuf {
    let directory = profile.join("incremental").join(unit).join(name);
    write_sized(&directory.join("query-cache.bin"), 4096);
    write_sized(&directory.join("work/product.o"), 1024);
    write_sized(&lock_of(&directory), 0);
    directory
}

fn subject(run: &PruneRun) -> &storage_scout::PruneSubject {
    assert_eq!(run.subjects.len(), 1, "{run:#?}");
    run.subjects.first().unwrap()
}

#[test]
fn rustc_keeps_only_its_newest_session_and_the_rest_goes() {
    let temp = tempdir("prune-sessions");
    let root = temp.path();
    let debug = profile(root, "app");
    let old = session(&debug, "app-1", "s-a1-x-aaa");
    let new = session(&debug, "app-1", "s-b1-y-bbb");
    let working = session(&debug, "app-1", "s-c1-w-working");
    let lone = session(&debug, "lib-2", "s-a1-z-ccc");
    let _linked = testkit::symlink_file(&old.join("linked"), &root.join("a/target/far/away"));

    let dry = prune(root, Mode::DryRun);
    assert_eq!(dry.totals.superseded_sessions.files, 1, "{dry:#?}");
    assert_eq!(dry.totals.superseded_sessions.bytes, Bytes::new(5120));
    assert_eq!(dry.totals.abandoned_sessions.files, 1);
    testkit::assert_present(&old);
    testkit::assert_present(&working);

    let Some(run) = pruned(root) else {
        return;
    };
    assert!(!run.failed(), "{run:#?}");
    assert_eq!(run.totals.superseded_sessions.files, 1);
    assert_eq!(run.totals.abandoned_sessions.files, 1);
    for gone in [&old, &working] {
        testkit::assert_absent(gone);
        testkit::assert_absent(lock_of(gone));
    }
    for kept in [&new, &lone] {
        testkit::assert_present(kept);
        testkit::assert_present(lock_of(kept));
    }
    testkit::assert_present(debug.join(".cargo-lock"));

    let again = prune(root, Mode::Execute);
    assert_eq!(again.totals.files(), 0, "{again:#?}");
}

#[test]
fn a_session_its_rustc_still_holds_is_left_alone() {
    let temp = tempdir("prune-held-session");
    let root = temp.path();
    let debug = profile(root, "app");
    let old = session(&debug, "app-1", "s-a1-x-aaa");
    let _new = session(&debug, "app-1", "s-b1-y-bbb");
    let Some(holder) = testkit::hold_session_lock(&lock_of(&old)) else {
        return;
    };
    let Some(run) = pruned(root) else {
        return;
    };
    assert!(!run.failed(), "{run:#?}");
    assert_eq!(subject(&run).held.files, 1, "{run:#?}");
    assert_eq!(run.totals.superseded_sessions.files, 0);
    testkit::assert_present(&old);
    drop(holder);
    let released = prune(root, Mode::Execute);
    assert_eq!(
        released.totals.superseded_sessions.files, 1,
        "{released:#?}"
    );
    testkit::assert_absent(&old);
}

#[test]
fn a_directory_is_a_profile_only_with_cargos_own_lock_and_fingerprints() {
    let temp = tempdir("prune-not-profiles");
    let root = temp.path();
    let loose = profile(root, "loose");
    fs::remove_dir(loose.join(".fingerprint")).unwrap();
    let linked = profile(root, "linked");
    let elsewhere = root.join("elsewhere.lock");
    write_sized(&elsewhere, 0);
    fs::remove_file(linked.join(".cargo-lock")).unwrap();
    let Built::Yes(_) = testkit::symlink_file(&linked.join(".cargo-lock"), &elsewhere) else {
        return;
    };
    let olds = [&loose, &linked].map(|debug| {
        let _new = session(debug, "app-1", "s-b1-y-bbb");
        session(debug, "app-1", "s-a1-x-aaa")
    });
    let run = prune(root, Mode::Execute);
    assert_eq!(run.totals.files(), 0, "{run:#?}");
    for old in &olds {
        testkit::assert_present(old);
    }
}

fn object(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    write_sized(&path, 2048);
    path
}

fn named(directory: &Path, names: &[&str]) -> Vec<String> {
    let parent = directory.file_name().unwrap().to_str().unwrap();
    names
        .iter()
        .map(|name| format!("/build/{parent}/{name}"))
        .collect()
}

fn image(path: &Path, objects: &[String]) {
    let mut references = objects.iter().map(String::as_str).collect::<Vec<_>>();
    references.push("/elsewhere/libdep-9.rlib(dep-9.dep.one.rcgu.o)");
    write_macho_image(path, &references);
}

#[test]
fn only_objects_the_unit_image_no_longer_names_are_stale() {
    let temp = tempdir("prune-objects");
    let root = temp.path();
    let debug = profile(root, "app");
    let deps = debug.join("deps");

    let current = ["app-1.a.new.rcgu.o", "app-1.b.new.rcgu.o"];
    let kept = current.map(|name| object(&deps, name));
    let stale = ["app-1.a.old.rcgu.o", "app-1.c.old.rcgu.o"].map(|name| object(&deps, name));
    image(&deps.join("app-1"), &named(&deps, &current));

    let dylib = object(&deps, "mac-5.a.new.rcgu.o");
    let dylib_stale = object(&deps, "mac-5.a.old.rcgu.o");
    image(
        &deps.join("libmac-5.dylib"),
        &named(&deps, &["mac-5.a.new.rcgu.o"]),
    );

    let build = debug.join("build/pkg-9");
    let script = object(&build, "build_script_build-9.a.new.rcgu.o");
    let script_stale = object(&build, "build_script_build-9.a.old.rcgu.o");
    image(
        &build.join("build_script_build-9"),
        &named(&build, &["build_script_build-9.a.new.rcgu.o"]),
    );

    let imageless = ["lib-2.a.one.rcgu.o", "lib-2.a.two.rcgu.o"].map(|name| object(&deps, name));
    let unreadable = ["bad-3.a.one.rcgu.o", "bad-3.a.two.rcgu.o"].map(|name| object(&deps, name));
    write_sized(&deps.join("bad-3"), 64);
    let single = object(&deps, "one-4.a.x.rcgu.o");
    let directory = deps.join("app-1.d.old.rcgu.o");
    write_sized(&directory.join("inside"), 16);
    image(&deps.join("one-4"), &[]);
    let unnamed = ["tiny-6.a.one.rcgu.o", "tiny-6.a.two.rcgu.o"].map(|name| object(&deps, name));
    write_macho_image(&deps.join("tiny-6"), &[]);
    let cut = ["cut-7.a.new.rcgu.o", "cut-7.a.old.rcgu.o"].map(|name| object(&deps, name));
    let truncated = deps.join("cut-7");
    image(&truncated, &named(&deps, &["cut-7.a.new.rcgu.o"]));
    let whole = fs::read(&truncated).unwrap();
    fs::write(&truncated, whole.split_last().unwrap().1).unwrap();

    let dry = prune(root, Mode::DryRun);
    assert_eq!(dry.totals.stale_objects.files, 6, "{dry:#?}");
    let Some(run) = pruned(root) else {
        return;
    };
    assert!(!run.failed(), "{run:#?}");
    assert_eq!(run.totals.stale_objects.files, 6, "{run:#?}");
    assert_eq!(run.totals.stale_objects.bytes, Bytes::new(6 * 2048));
    assert_eq!(subject(&run).unreadable_images, 2);
    for gone in stale
        .iter()
        .chain(&unnamed)
        .chain([&dylib_stale, &script_stale])
    {
        testkit::assert_absent(gone);
    }
    for present in kept
        .iter()
        .chain(&imageless)
        .chain(&unreadable)
        .chain(&cut)
        .chain([&dylib, &script, &single, &directory])
    {
        testkit::assert_present(present);
    }
    testkit::assert_present(deps.join("app-1"));
}

#[test]
fn an_image_that_cannot_be_read_keeps_every_object_of_its_unit() {
    let temp = tempdir("prune-sealed-image");
    let root = temp.path();
    let deps = profile(root, "app").join("deps");
    let objects = ["app-1.a.new.rcgu.o", "app-1.a.old.rcgu.o"].map(|name| object(&deps, name));
    let sealed = deps.join("app-1");
    image(&sealed, &named(&deps, &["app-1.a.new.rcgu.o"]));
    let Some(_restricted) = testkit::restrict(&sealed, 0o000) else {
        return;
    };
    let run = prune(root, Mode::Execute);
    assert_eq!(run.totals.files(), 0, "{run:#?}");
    assert_eq!(subject(&run).unreadable_images, 1, "{run:#?}");
    for present in &objects {
        testkit::assert_present(present);
    }
}

#[test]
fn what_its_owner_keeps_is_not_pruned_and_a_running_build_is_waited_for() {
    let temp = tempdir("prune-refused");
    let root = temp.path();
    let kept = profile(root, "kept");
    let kept_old = session(&kept, "app-1", "s-a1-x-aaa");
    let _kept_new = session(&kept, "app-1", "s-b1-y-bbb");
    testkit::write_owner_marker(
        &kept.parent().unwrap().join("tmp/keep"),
        MarkerRole::Scratch,
        MarkerKeep::Kept,
        None,
    );
    let busy = profile(root, "busy");
    let busy_old = session(&busy, "app-1", "s-a1-x-aaa");
    let _busy_new = session(&busy, "app-1", "s-b1-y-bbb");
    let holder = File::open(busy.join(".cargo-lock")).unwrap();
    holder.lock().unwrap();

    for mode in [Mode::DryRun, Mode::Execute] {
        let run = prune(root, mode);
        assert_eq!(run.totals.files(), 0, "{run:#?}");
        let reasons = run
            .subjects
            .iter()
            .map(|subject| match &subject.admission {
                PruneAdmission::Rejected { rejection } => rejection.clone(),
                PruneAdmission::Admitted { .. } => panic!("{run:#?}"),
            })
            .collect::<Vec<_>>();
        assert!(
            reasons.iter().any(|rejection| matches!(
                rejection,
                Rejection::Owned {
                    settlement: Settlement::Kept,
                    ..
                }
            )),
            "{reasons:#?}"
        );
        assert!(
            reasons
                .iter()
                .any(|rejection| matches!(rejection, Rejection::Busy { .. })),
            "{reasons:#?}"
        );
    }
    testkit::assert_present(&kept_old);
    testkit::assert_present(&busy_old);
    drop(holder);
}

#[test]
fn auto_prunes_whenever_it_runs_and_reports_only_what_it_touched() {
    let temp = tempdir("prune-auto");
    let root = temp.path();
    let debug = profile(root, "app");
    let old = session(&debug, "app-1", "s-a1-x-aaa");
    let _new = session(&debug, "app-1", "s-b1-y-bbb");
    let idle = profile(root, "idle");
    let _alone = session(&idle, "app-1", "s-a1-x-aaa");
    let busy = profile(root, "busy");
    let busy_old = session(&busy, "app-1", "s-a1-x-aaa");
    let _busy_new = session(&busy, "app-1", "s-b1-y-bbb");
    let holder = testkit::hold_session_lock(&lock_of(&busy_old));
    let policy = AutoPolicy::parse(&format!(
        "[select]\nroots = [{:?}]\n",
        root.to_str().unwrap()
    ))
    .unwrap();
    let run = scout(root).auto(&policy, Mode::Execute).unwrap();
    if unsupported(&run.prune) {
        return;
    }
    assert!(!run.failed(), "{run:#?}");
    let expected = if holder.is_some() { 1 } else { 2 };
    assert_eq!(
        run.prune.totals.superseded_sessions.files, expected,
        "{run:#?}"
    );
    testkit::assert_absent(&old);
    let reported = run
        .prune
        .subjects
        .iter()
        .map(|subject| subject.location.clone())
        .collect::<Vec<_>>();
    assert_eq!(reported.len(), 2, "{run:#?}");
    for touched in ["app", "busy"] {
        assert!(
            reported.contains(&testkit::location(&root.join(touched).join("target"))),
            "{touched}: {run:#?}"
        );
    }
    drop(holder);
}
