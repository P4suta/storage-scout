#![expect(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    reason = "tests drive a real watcher over real trees"
)]

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Lines};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use testkit::{Built, MarkerKeep, MarkerRole, Scratch, tempdir, write_sized};

struct Watching {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
    _temp: Scratch,
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
    ceiling: PathBuf,
}

impl Drop for Watching {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

impl Watching {
    fn start(name: &str, setup: impl FnOnce(&Path)) -> Option<Self> {
        let temp = tempdir(name);
        let root = temp.path().join("work");
        fs::create_dir_all(&root).unwrap();
        setup(&root);
        let state = temp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let config = temp.path().join("auto.toml");
        fs::write(
            &config,
            format!("[select]\nroots = [{:?}]\n", root.to_str().unwrap()),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_storage-scout"))
            .args(["watch", "--config", config.to_str().unwrap()])
            .env("GIT_CEILING_DIRECTORIES", temp.path())
            .env("STORAGE_SCOUT_STATE_DIR", &state)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let Some(started) = lines.next() else {
            let output = child.wait_with_output().unwrap();
            let complaint = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                complaint.contains("cannot watch for changes here"),
                "{complaint}"
            );
            let _skipped = Built::Unavailable(complaint).or_decline("a filesystem watcher");
            return None;
        };
        let started = started.unwrap();
        assert!(started.starts_with("start: watching"), "{started}");
        Some(Self {
            child,
            lines,
            ceiling: temp.path().to_path_buf(),
            _temp: temp,
            root,
            config,
            state,
        })
    }

    fn next(&mut self) -> String {
        self.lines.next().unwrap().unwrap()
    }
}

fn profile(root: &Path, name: &str) -> PathBuf {
    let project = root.join(name);
    write_sized(&project.join("Cargo.toml"), 1);
    testkit::write_cache_tag(&project.join("target"));
    let profile = project.join("target/debug");
    write_sized(&profile.join(".cargo-lock"), 0);
    fs::create_dir_all(profile.join(".fingerprint")).unwrap();
    fs::create_dir_all(profile.join("deps")).unwrap();
    fs::create_dir_all(profile.join("incremental")).unwrap();
    profile
}

fn session(profile: &Path, unit: &str, name: &str) -> PathBuf {
    let directory = profile.join("incremental").join(unit).join(name);
    write_sized(&directory.join("query-cache.bin"), 4096);
    let (stem, _) = name.rsplit_once('-').unwrap();
    write_sized(&directory.with_file_name(format!("{stem}.lock")), 0);
    directory
}

fn build(profile: &Path, unit: &str, stamp: &str) -> PathBuf {
    let old = session(profile, unit, &format!("s-{stamp}0-x-aaa"));
    let _new = session(profile, unit, &format!("s-{stamp}1-y-bbb"));
    write_sized(&profile.join(format!("deps/lib{unit}.rmeta")), 128);
    old
}

#[test]
fn a_build_is_pruned_once_it_ends_and_not_while_it_runs() {
    let Some(mut watching) = Watching::start("watch-build", |root| {
        let _debug = profile(root, "app");
    }) else {
        return;
    };
    let debug = watching.root.join("app/target/debug");
    let old = build(&debug, "one", "a");
    let first = watching.next();
    assert!(first.contains("pruned 1 entry"), "{first}");
    testkit::assert_absent(&old);

    let holder = File::open(debug.join(".cargo-lock")).unwrap();
    holder.lock().unwrap();
    let busy = build(&debug, "two", "b");
    let waited = build(&debug, "three", "c");
    testkit::assert_present(&busy);
    drop(holder);
    let released = watching.next();
    assert!(released.contains("pruned 2 entries"), "{released}");
    testkit::assert_absent(&busy);
    testkit::assert_absent(&waited);
}

#[test]
fn released_scratch_is_reaped_the_moment_its_owner_lets_go() {
    let Some(mut watching) = Watching::start("watch-owner", |_| {}) else {
        return;
    };
    let run = watching.root.join("run");
    testkit::write_owner_lock(&run);
    let owner = testkit::claim(&run);
    write_sized(&run.join("scratch.bin"), 1024);
    testkit::write_owner_json(&run, MarkerRole::Scratch, MarkerKeep::Released, None);
    drop(owner);
    loop {
        let line = watching.next();
        if line.contains("reaped 1") {
            break;
        }
        assert!(!line.contains("FAILURES"), "{line}");
    }
    testkit::assert_absent(&run);
}

#[test]
fn a_build_that_repeats_another_projects_bytes_is_shared_when_it_ends() {
    let Some(mut watching) = Watching::start("watch-share", |root| {
        let one = profile(root, "one");
        testkit::write_patterned(&one.join("deps/libdep-1.rlib"), 256 * 1024, 7);
    }) else {
        return;
    };
    if !capable(&watching.root) {
        return;
    }
    let one = watching.root.join("one/target/debug");
    let two = profile(&watching.root.clone(), "two");
    testkit::write_patterned(&two.join("deps/libdep-1.rlib"), 256 * 1024, 7);
    loop {
        let line = watching.next();
        assert!(!line.contains("FAILURES"), "{line}");
        if line.contains("shared 1 file") {
            break;
        }
    }
    assert_eq!(
        fs::read(one.join("deps/libdep-1.rlib")).unwrap(),
        fs::read(two.join("deps/libdep-1.rlib")).unwrap()
    );
}

fn capable(root: &Path) -> bool {
    let run = storage_scout::Scout::with(testkit::open_protection())
        .confined(vec![root.to_path_buf()])
        .dedupe(&[root.to_path_buf()], &[], storage_scout::Mode::DryRun)
        .unwrap();
    let admitted = run
        .subjects
        .iter()
        .any(|subject| matches!(subject.admission, storage_scout::Admission::Admitted { .. }));
    if !admitted {
        assert!(
            std::env::var_os("STORAGE_SCOUT_REQUIRE_SHARING").is_none(),
            "this volume must share blocks: {run:#?}"
        );
        let _skipped = Built::Unavailable(String::from("no block sharing"))
            .or_decline("a volume that shares blocks");
    }
    admitted
}

#[test]
fn a_cache_whose_key_is_gone_is_reaped_as_soon_as_a_hook_says_so() {
    let Some(mut watching) = Watching::start("watch-hook", |root| {
        let key = root.with_file_name("key");
        fs::create_dir_all(&key).unwrap();
        let cache = root.join("cache");
        testkit::write_owner_marker(&cache, MarkerRole::Cache, MarkerKeep::Released, Some(&key));
        write_sized(&cache.join("blob"), 1024);
    }) else {
        return;
    };
    let cache = watching.root.join("cache");
    fs::remove_dir(watching.root.with_file_name("key")).unwrap();
    let poked = Command::new(env!("CARGO_BIN_EXE_storage-scout"))
        .args([
            "auto",
            "--config",
            watching.config.to_str().unwrap(),
            "--execute",
            "--detach",
            "--json",
        ])
        .env("GIT_CEILING_DIRECTORIES", &watching.ceiling)
        .env("STORAGE_SCOUT_STATE_DIR", &watching.state)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&poked.stdout).contains("handed"),
        "{poked:#?}"
    );
    loop {
        let line = watching.next();
        assert!(!line.contains("FAILURES"), "{line}");
        if line.starts_with("hook:") && line.contains("reaped 1") {
            break;
        }
    }
    testkit::assert_absent(&cache);
}

#[test]
fn writes_inside_a_cache_nobody_locks_change_nothing() {
    let Some(mut watching) = Watching::start("watch-unlocked", |root| {
        testkit::write_cache_tag(&root.join("cache"));
        let _debug = profile(root, "app");
    }) else {
        return;
    };
    let cache = watching.root.join("cache");
    write_sized(&cache.join("blob"), 4096);
    let old = build(&watching.root.join("app/target/debug"), "one", "a");
    let first = watching.next();
    assert!(first.contains("pruned 1 entry"), "{first}");
    testkit::assert_absent(&old);
    testkit::assert_present(cache.join("blob"));
}

#[test]
fn work_that_lands_is_reaped_when_the_remote_ref_moves_without_any_hook() {
    if !testkit::watches_subtrees() {
        return;
    }
    let mut feat = PathBuf::new();
    let mut work = PathBuf::new();
    let mut upstream = PathBuf::new();
    let Some(mut watching) = Watching::start("watch-refs", |root| {
        let git = testkit::Git::isolated(root.parent().unwrap());
        upstream = root.with_file_name("upstream");
        fs::create_dir_all(&upstream).unwrap();
        git.run(&upstream, &["init", "--quiet"]);
        git.commit_file(&upstream, "Cargo.toml", "[package]\nname = \"x\"\n");
        git.commit_file(&upstream, ".gitignore", "target/\n");
        git.commit_file(&upstream, "src/lib.rs", "pub fn one() {}\n");
        work = root.join("work");
        git.run(
            root,
            &[
                "clone",
                "--quiet",
                upstream.to_str().unwrap(),
                work.to_str().unwrap(),
            ],
        );
        feat = root.join("feat");
        git.run(
            &work,
            &[
                "worktree",
                "add",
                "--quiet",
                "-b",
                "feat",
                feat.to_str().unwrap(),
                "origin/main",
            ],
        );
        git.commit_file(&feat, "src/lib.rs", "pub fn one() {}\npub fn two() {}\n");
        testkit::write_cache_tag(&feat.join("target"));
        write_sized(&feat.join("target/debug/app"), 4096);
    }) else {
        return;
    };
    let git = testkit::Git::isolated(watching.root.parent().unwrap());
    git.commit_file(
        &upstream,
        "src/lib.rs",
        "pub fn one() {}\npub fn two() {}\n",
    );
    git.run(&work, &["fetch", "--quiet"]);
    loop {
        let line = watching.next();
        assert!(!line.contains("FAILURES"), "{line}");
        if line.starts_with("hook:") && line.contains("reaped 1") {
            break;
        }
    }
    testkit::assert_absent(feat.join("target"));
    testkit::assert_present(feat.join("src/lib.rs"));
}
