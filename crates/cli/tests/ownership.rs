#![expect(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests build real repositories and trees"
)]

use std::fs;
use std::path::{Path, PathBuf};

use storage_scout::core::ownership::Settlement;
use storage_scout::core::size::Bytes;
use storage_scout::{AutoPolicy, Measure, Mode, ScanOptions, Scout, Status};
use testkit::{
    Built, Git, MarkerKeep, MarkerRole, claim, tempdir, write_bytes, write_owner_marker,
    write_sized,
};

struct Repo {
    temp: testkit::Scratch,
    git: Git,
    upstream: PathBuf,
    work: PathBuf,
}

impl Repo {
    fn new(name: &str) -> Self {
        let temp = tempdir(name);
        let git = Git::isolated(temp.path());
        let upstream = temp.path().join("upstream");
        fs::create_dir_all(&upstream).unwrap();
        git.run(&upstream, &["init", "--quiet"]);
        git.commit_file(&upstream, "Cargo.toml", "[package]\nname = \"x\"\n");
        git.commit_file(&upstream, ".gitignore", "target/\n");
        git.commit_file(&upstream, "src/lib.rs", "pub fn one() {}\n");
        let work = temp.path().join("work");
        git.run(
            temp.path(),
            &[
                "clone",
                "--quiet",
                upstream.to_str().unwrap(),
                work.to_str().unwrap(),
            ],
        );
        Self {
            temp,
            git,
            upstream,
            work,
        }
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }

    fn worktree(&self, name: &str, args: &[&str]) -> PathBuf {
        let path = self.root().join(name);
        let mut full = vec!["worktree", "add", "--quiet"];
        full.extend_from_slice(args);
        full.push(path.to_str().unwrap());
        full.push("origin/main");
        self.git.run(&self.work, &full);
        path
    }

    fn scout(&self) -> Scout {
        Scout::with(testkit::open_protection()).confined(vec![self.root().to_path_buf()])
    }

    fn settlement(&self, target: &Path) -> Settlement {
        settlement(&self.scout(), self.root(), target)
    }
}

fn build(worktree: &Path) -> PathBuf {
    let target = worktree.join("target");
    write_sized(&target.join("debug/app"), 4096);
    target
}

fn settlement(scout: &Scout, root: &Path, target: &Path) -> Settlement {
    let report = scout
        .discover(&ScanOptions {
            roots: vec![root.to_path_buf()],
            top: 0,
            min_size: Bytes::ZERO,
            max_depth: Some(0),
            excludes: Vec::new(),
            threads: None,
            measure: Measure::Allocated,
        })
        .unwrap();
    let canonical = fs::canonicalize(target).unwrap();
    let candidate = report
        .candidates
        .iter()
        .find(|found| found.path() == canonical)
        .unwrap_or_else(|| {
            panic!(
                "{} is not a candidate: {:#?}",
                target.display(),
                report.candidates
            )
        })
        .candidate();
    if std::env::var_os("SCOUT_DEBUG_OWNERSHIP").is_some() {
        let shown = format!(
            "{}\n",
            serde_json::to_string(candidate.ownership()).unwrap()
        );
        std::io::Write::write_all(&mut std::io::stderr(), shown.as_bytes()).unwrap();
    }
    candidate.settlement()
}

#[test]
fn the_primary_worktree_is_always_in_use() {
    let repo = Repo::new("own-primary");
    let target = build(&repo.work);
    assert_eq!(repo.settlement(&target), Settlement::Active);
}

#[test]
fn a_named_branch_without_its_own_commits_is_about_to_be_worked_on() {
    let repo = Repo::new("own-fresh");
    let fresh = repo.worktree("fresh", &["-b", "fresh"]);
    assert_eq!(repo.settlement(&build(&fresh)), Settlement::Active);
}

#[test]
fn a_detached_checkout_of_main_has_nothing_of_its_own() {
    let repo = Repo::new("own-detached");
    let detached = repo.worktree("detached", &["--detach"]);
    assert_eq!(repo.settlement(&build(&detached)), Settlement::Landed);
}

#[test]
fn unmerged_work_is_active_and_a_squash_merge_lands_it() {
    let repo = Repo::new("own-squash");
    let feat = repo.worktree("feat", &["-b", "feat"]);
    repo.git
        .commit_file(&feat, "src/lib.rs", "pub fn one() {}\npub fn two() {}\n");
    let target = build(&feat);
    assert_eq!(repo.settlement(&target), Settlement::Active);

    repo.git.commit_file(
        &repo.upstream,
        "src/lib.rs",
        "pub fn one() {}\npub fn two() {}\n",
    );
    repo.git.run(&repo.work, &["fetch", "--quiet"]);
    assert_eq!(repo.settlement(&target), Settlement::Landed);
}

#[test]
fn a_squash_merge_is_still_found_after_main_changes_the_same_file() {
    let repo = Repo::new("own-history");
    let feat = repo.worktree("feat", &["-b", "feat"]);
    repo.git
        .commit_file(&feat, "src/lib.rs", "pub fn one() {}\npub fn two() {}\n");
    let target = build(&feat);
    repo.git.commit_file(
        &repo.upstream,
        "src/lib.rs",
        "pub fn one() {}\npub fn two() {}\n",
    );
    repo.git.commit_file(
        &repo.upstream,
        "src/lib.rs",
        "pub fn one() {}\npub fn two() {}\npub fn three() {}\n",
    );
    repo.git.run(&repo.work, &["fetch", "--quiet"]);
    assert_eq!(repo.settlement(&target), Settlement::Landed);
}

#[test]
fn uncommitted_changes_keep_a_landed_worktree_in_use() {
    let repo = Repo::new("own-dirty");
    let detached = repo.worktree("detached", &["--detach"]);
    let target = build(&detached);
    fs::write(detached.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    assert_eq!(repo.settlement(&target), Settlement::Active);
}

#[test]
fn a_branch_whose_upstream_was_deleted_has_landed() {
    let repo = Repo::new("own-gone");
    let feat = repo.worktree("feat", &["-b", "gone"]);
    repo.git
        .commit_file(&feat, "src/other.rs", "pub fn other() {}\n");
    repo.git
        .run(&feat, &["push", "--quiet", "-u", "origin", "gone"]);
    let target = build(&feat);
    assert_eq!(repo.settlement(&target), Settlement::Active);
    repo.git
        .run(&repo.upstream, &["branch", "-m", "gone", "renamed"]);
    repo.git.run(&repo.work, &["fetch", "--quiet", "--prune"]);
    assert_eq!(repo.settlement(&target), Settlement::Landed);
}

#[test]
fn work_that_main_never_took_stays_active_even_when_main_touched_the_same_file() {
    let repo = Repo::new("own-diverged");
    let feat = repo.worktree("feat", &["-b", "feat"]);
    repo.git
        .commit_file(&feat, "src/lib.rs", "pub fn one() {}\npub fn two() {}\n");
    let target = build(&feat);
    repo.git
        .commit_file(&repo.upstream, "src/lib.rs", "pub fn other() {}\n");
    repo.git.run(&repo.work, &["fetch", "--quiet"]);
    assert_eq!(repo.settlement(&target), Settlement::Active);
}

#[test]
fn a_squash_that_main_took_in_two_commits_has_landed() {
    let repo = Repo::new("own-split");
    let feat = repo.worktree("feat", &["-b", "feat"]);
    repo.git
        .commit_file(&feat, "src/lib.rs", "pub fn one() {}\npub fn two() {}\n");
    repo.git
        .commit_file(&feat, "src/other.rs", "pub fn other() {}\n");
    let target = build(&feat);
    repo.git.commit_file(
        &repo.upstream,
        "src/lib.rs",
        "pub fn one() {}\npub fn two() {}\n",
    );
    repo.git
        .commit_file(&repo.upstream, "src/other.rs", "pub fn other() {}\n");
    repo.git.run(&repo.work, &["fetch", "--quiet"]);
    assert_eq!(repo.settlement(&target), Settlement::Landed);
}

#[test]
fn a_detached_commit_that_changed_nothing_has_no_work_of_its_own() {
    let repo = Repo::new("own-empty");
    let detached = repo.worktree("detached", &["--detach"]);
    repo.git.run(
        &detached,
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "own-empty nothing",
        ],
    );
    assert_eq!(repo.settlement(&build(&detached)), Settlement::Landed);
}

#[test]
fn the_nearest_repository_owns_what_is_inside_it() {
    let temp = tempdir("own-nearest");
    let root = temp.path();
    let outer = root.join("outer");
    write_bytes(&outer.join(".git"), b"gitdir: /nonexistent/storage-scout\n");
    let inner = outer.join("inner");
    fs::create_dir_all(&inner).unwrap();
    let git = Git::isolated(root);
    git.run(&inner, &["init", "--quiet"]);
    git.commit_file(&inner, "Cargo.toml", "[package]\nname = \"inner\"\n");
    git.commit_file(&inner, ".gitignore", "target/\n");
    let target = build(&inner);
    let scout = Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()]);
    assert_eq!(settlement(&scout, root, &target), Settlement::Active);
}

#[test]
fn a_repository_that_names_no_default_branch_keeps_its_work_and_says_why() {
    let repo = Repo::new("own-headless");
    let detached = repo.worktree("detached", &["--detach"]);
    repo.git
        .run(&repo.work, &["remote", "set-head", "origin", "--delete"]);
    let target = build(&detached);
    let report = repo
        .scout()
        .discover(&ScanOptions {
            roots: vec![repo.root().to_path_buf()],
            top: 0,
            min_size: Bytes::ZERO,
            max_depth: Some(0),
            excludes: Vec::new(),
            threads: None,
            measure: Measure::Allocated,
        })
        .unwrap();
    let canonical = fs::canonicalize(&target).unwrap();
    let found = report
        .candidates
        .iter()
        .find(|each| each.path() == canonical)
        .unwrap();
    assert_eq!(found.candidate().settlement(), Settlement::Active);
    let basis = serde_json::to_value(found.candidate().ownership()).unwrap();
    assert_eq!(
        basis.pointer("/worktree/landing/landing"),
        Some(&serde_json::Value::from("no-default-branch")),
        "{basis}"
    );
}

#[test]
fn a_history_unrelated_to_main_is_active() {
    let repo = Repo::new("own-unrelated");
    let lonely = repo.worktree("lonely", &["--detach"]);
    repo.git
        .run(&lonely, &["switch", "--quiet", "--orphan", "lonely"]);
    repo.git
        .commit_file(&lonely, "Cargo.toml", "[package]\nname = \"lonely\"\n");
    repo.git.commit_file(&lonely, ".gitignore", "target/\n");
    assert_eq!(repo.settlement(&build(&lonely)), Settlement::Active);
}

#[test]
fn a_worktree_that_names_its_repository_relatively_is_still_understood() {
    let repo = Repo::new("own-relative");
    let relative = repo.worktree("relative", &["--detach"]);
    write_bytes(
        &relative.join(".git"),
        b"gitdir: ../work/.git/worktrees/relative\n",
    );
    repo.git.run(&relative, &["status", "--short"]);
    assert_eq!(repo.settlement(&build(&relative)), Settlement::Landed);
}

#[test]
fn a_worktree_whose_repository_cannot_be_read_is_not_called_forgotten() {
    let repo = Repo::new("own-sealed");
    let detached = repo.worktree("detached", &["--detach"]);
    let target = build(&detached);
    let Some(restricted) = testkit::restrict(&repo.work.join(".git/worktrees"), 0o000) else {
        return;
    };
    let settled = repo.settlement(&target);
    drop(restricted);
    assert_eq!(settled, Settlement::Active);
}

#[test]
fn a_worktree_git_refuses_to_read_keeps_its_work_and_says_git_refused() {
    let repo = Repo::new("own-refused");
    let broken = repo.worktree("broken", &["--detach"]);
    let target = build(&broken);
    fs::remove_file(repo.work.join(".git/worktrees/broken/HEAD")).unwrap();
    let report = repo
        .scout()
        .discover(&ScanOptions {
            roots: vec![repo.root().to_path_buf()],
            top: 0,
            min_size: Bytes::ZERO,
            max_depth: Some(0),
            excludes: Vec::new(),
            threads: None,
            measure: Measure::Allocated,
        })
        .unwrap();
    let canonical = fs::canonicalize(&target).unwrap();
    let found = report
        .candidates
        .iter()
        .find(|each| each.path() == canonical)
        .unwrap();
    assert_eq!(found.candidate().settlement(), Settlement::Active);
    let basis = serde_json::to_value(found.candidate().ownership()).unwrap();
    assert_eq!(basis["worktree"]["failure"]["cause"], "refused", "{basis}");
    assert_eq!(basis["worktree"]["failure"]["query"], "status", "{basis}");
}

#[test]
fn a_git_link_that_is_a_symbolic_link_is_not_trusted() {
    let temp = tempdir("own-linked-git");
    let root = temp.path();
    let project = root.join("proj");
    write_sized(&project.join("Cargo.toml"), 1);
    let target = build(&project);
    write_bytes(
        &root.join("elsewhere/gitfile"),
        b"gitdir: /nonexistent/storage-scout\n",
    );
    let Built::Yes(_) =
        testkit::symlink_file(&project.join(".git"), &root.join("elsewhere/gitfile"))
    else {
        return;
    };
    let scout = Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()]);
    assert_eq!(settlement(&scout, root, &target), Settlement::Active);
}

#[test]
fn a_worktree_whose_repository_forgot_it_is_released() {
    let repo = Repo::new("own-orphan");
    let orphan = repo.worktree("orphan", &["--detach"]);
    fs::write(orphan.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
    let target = build(&orphan);
    fs::remove_dir_all(repo.work.join(".git/worktrees/orphan")).unwrap();
    assert_eq!(repo.settlement(&target), Settlement::Released);
}

fn marked(
    root: &Path,
    name: &str,
    role: MarkerRole,
    keep: MarkerKeep,
    keyed_to: Option<&Path>,
) -> PathBuf {
    let directory = root.join(name);
    write_owner_marker(&directory, role, keep, keyed_to);
    write_sized(&directory.join("payload.bin"), 4096);
    directory
}

#[test]
fn a_marker_says_who_owns_a_directory_and_whether_they_let_go() {
    let temp = tempdir("own-markers");
    let root = temp.path();
    let scout = Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()]);
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    let released = marked(
        root,
        "released",
        MarkerRole::Scratch,
        MarkerKeep::Released,
        None,
    );
    let held = marked(
        root,
        "held",
        MarkerRole::Scratch,
        MarkerKeep::Released,
        None,
    );
    let kept = marked(root, "kept", MarkerRole::Scratch, MarkerKeep::Kept, None);
    let keyed = marked(
        root,
        "keyed",
        MarkerRole::Cache,
        MarkerKeep::Released,
        Some(&source),
    );
    let forgotten = marked(
        root,
        "forgotten",
        MarkerRole::Cache,
        MarkerKeep::Released,
        Some(&root.join("gone")),
    );
    let _owner = claim(&held);
    for (directory, expected) in [
        (&released, Settlement::Released),
        (&held, Settlement::Active),
        (&kept, Settlement::Kept),
        (&keyed, Settlement::Active),
        (&forgotten, Settlement::Released),
    ] {
        assert_eq!(
            settlement(&scout, root, directory),
            expected,
            "{}",
            directory.display()
        );
    }
}

#[test]
fn a_key_that_cannot_be_looked_at_keeps_the_cache() {
    let temp = tempdir("own-sealed-key");
    let root = temp.path();
    let sealed = root.join("sealed");
    fs::create_dir_all(sealed.join("source")).unwrap();
    let cache = marked(
        root,
        "cache",
        MarkerRole::Cache,
        MarkerKeep::Released,
        Some(&sealed.join("source")),
    );
    let scout = Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()]);
    let Some(restricted) = testkit::restrict(&sealed, 0o000) else {
        return;
    };
    let settled = settlement(&scout, root, &cache);
    drop(restricted);
    assert_eq!(settled, Settlement::Active);
}

#[test]
fn a_marker_inside_a_target_protects_the_whole_target() {
    let repo = Repo::new("own-nested");
    let detached = repo.worktree("detached", &["--detach"]);
    let target = build(&detached);
    let run = target.join("tmp/run");
    write_owner_marker(&run, MarkerRole::Scratch, MarkerKeep::Released, None);
    let _owner = claim(&run);
    assert_eq!(repo.settlement(&target), Settlement::Active);
}

#[test]
fn a_marker_is_read_even_where_its_owner_never_took_a_lock() {
    let temp = tempdir("own-lockless");
    let root = temp.path();
    let scout = Scout::with(testkit::open_protection()).confined(vec![root.to_path_buf()]);
    let target = root.join("proj/target");
    write_sized(&root.join("proj/Cargo.toml"), 1);
    write_sized(&target.join("debug/app"), 4096);
    let kept = target.join("tmp/kept");
    write_owner_marker(&kept, MarkerRole::Scratch, MarkerKeep::Kept, None);
    fs::remove_file(kept.join("owner.lock")).unwrap();
    assert_eq!(settlement(&scout, root, &target), Settlement::Kept);
}

#[test]
fn auto_reaps_what_was_let_go_and_nothing_else() {
    let repo = Repo::new("own-auto");
    let active = build(&repo.worktree("active", &["-b", "active"]));
    let landed = build(&repo.worktree("landed", &["--detach"]));
    let released = marked(
        repo.root(),
        "released",
        MarkerRole::Scratch,
        MarkerKeep::Released,
        None,
    );
    let kept = marked(
        repo.root(),
        "kept",
        MarkerRole::Scratch,
        MarkerKeep::Kept,
        None,
    );
    let policy = AutoPolicy::parse(&format!(
        "[select]\nroots = [{:?}]\n",
        repo.root().to_str().unwrap()
    ))
    .unwrap();

    let dry = repo.scout().auto(&policy, Mode::DryRun).unwrap();
    let summary = dry.reap.summary.as_ref().unwrap();
    assert_eq!(summary.outcomes.len(), 2, "{summary:#?}");
    assert!(
        summary
            .outcomes
            .iter()
            .all(|outcome| outcome.status == Status::WouldDelete)
    );

    let run = repo.scout().auto(&policy, Mode::Execute).unwrap();
    assert!(!run.failed(), "{run:#?}");
    testkit::assert_absent(&landed);
    testkit::assert_absent(&released);
    testkit::assert_present(&active);
    testkit::assert_present(&kept);
    testkit::assert_present(repo.root().join("landed/src/lib.rs"));
}
