#![expect(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "tests build and inspect real trees and run the real binary"
)]

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use storage_scout::core::area::Area;
use storage_scout::{SCHEMA_VERSION, Scout};
use testkit::{link_dir, tempdir, write_cargo_project, write_sized};

#[path = "support/user.rs"]
mod user;
use user::run as isolated_user;

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_storage-scout"))
        .args(args)
        .env("GIT_CEILING_DIRECTORIES", testkit::ceiling())
        .env("STORAGE_SCOUT_STATE_DIR", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn pending(state: &Path) -> Option<std::path::PathBuf> {
    fs::read_dir(state).unwrap().flatten().find_map(|entry| {
        fs::read_dir(entry.path())
            .into_iter()
            .flatten()
            .flatten()
            .find(|child| child.file_name() == "pending")
            .map(|child| child.path())
    })
}

fn run_lock(state: &Path) -> std::path::PathBuf {
    fs::read_dir(state)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
                && path
                    .file_stem()
                    .is_some_and(|stem| !stem.to_string_lossy().ends_with(".requests"))
        })
        .unwrap()
}

fn open_space(root: &Path) -> bool {
    let scout = Scout::detect().unwrap();
    let open = scout.protection().area_of(&testkit::location(root)) == Area::Open;
    if !open {
        let skipped = format!("skipping: {} is protected on this host\n", root.display());
        std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes()).unwrap();
    }
    open
}

#[test]
fn help_syntax_and_strict_exit_codes() {
    assert_eq!(cli(&[]).status.code(), Some(0));
    assert_eq!(cli(&["reclaim"]).status.code(), Some(2));
    assert_eq!(cli(&["clean", ".", "--all"]).status.code(), Some(2));
    assert_eq!(
        cli(&["clean", ".", "--older-than", "30d"]).status.code(),
        Some(2)
    );
    assert_eq!(cli(&["scan", ".", "--threads", "0"]).status.code(), Some(2));
    let missing = cli(&["scan", "definitely-missing", "--json", "--strict"]);
    assert_eq!(missing.status.code(), Some(1));
    let document = json(&missing);
    assert_eq!(document["schema_version"], SCHEMA_VERSION);
    assert_eq!(document["issues"][0]["reason"], "io");
}

#[test]
fn git_is_not_asked_above_a_ceiling() {
    let temp = tempdir("cli-ceiling");
    let target = write_cargo_project(&temp.path().join("proj"), 16);
    testkit::write_cache_tag(&target);
    let explained = cli(&["explain", target.to_str().unwrap(), "--json"]);
    assert_eq!(
        json(&explained)["ownership"]["basis"],
        "nothing",
        "{}",
        String::from_utf8_lossy(&explained.stdout)
    );
}

#[test]
fn clean_discovers_dry_runs_refuses_unconfirmed_and_executes_by_id() {
    let temp = tempdir("cli-clean");
    testkit::write_orphaned_worktree(temp.path());
    if !open_space(temp.path()) {
        return;
    }
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let root = temp.path().to_str().unwrap();
    let discovery = cli(&["clean", root, "--min-size", "0", "--json"]);
    assert_eq!(discovery.status.code(), Some(0));
    let document = json(&discovery);
    assert_eq!(document["stage"], "discovery");
    let id = document["candidates"][0]["id"].as_str().unwrap().to_owned();

    let dry_run = cli(&["clean", root, "--min-size", "0", "--id", &id, "--json"]);
    assert_eq!(dry_run.status.code(), Some(0));
    assert_eq!(
        json(&dry_run)["summary"]["outcomes"][0]["status"]["status"],
        "would-delete"
    );
    testkit::assert_present(&target);

    let unconfirmed = cli(&["clean", root, "--min-size", "0", "--id", &id, "--execute"]);
    assert_eq!(unconfirmed.status.code(), Some(1));
    testkit::assert_present(&target);

    let execute = cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--id",
        &id,
        "--execute",
        "--yes",
        "--json",
    ]);
    assert_eq!(execute.status.code(), Some(0), "{execute:#?}");
    assert_eq!(
        json(&execute)["summary"]["outcomes"][0]["status"]["status"],
        "deleted"
    );
    testkit::assert_absent(&target);
}

#[test]
fn explicit_manual_selection_never_deletes_an_unclaimed_artifact() {
    let temp = tempdir("cli-unclaimed");
    if !open_space(temp.path()) {
        return;
    }
    let target = write_cargo_project(&temp.path().join("proj"), 4096);
    let root = temp.path().to_str().unwrap();
    let discovery = json(&cli(&["clean", root, "--min-size", "0", "--json"]));
    let id = discovery["candidates"][0]["id"].as_str().unwrap();
    let output = cli(&[
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
    assert_eq!(output.status.code(), Some(1));
    let status = &json(&output)["summary"]["outcomes"][0]["status"];
    assert_eq!(status["status"], "rejected");
    assert_eq!(status["rejection"]["reason"], "owned");
    assert_eq!(status["rejection"]["settlement"], "unclaimed");
    testkit::assert_present(target);
}

#[test]
fn a_locked_tier_and_a_stale_id_fail_without_deleting() {
    let temp = tempdir("cli-locked");
    if !open_space(temp.path()) {
        return;
    }
    write_sized(&temp.path().join("web/package.json"), 1);
    write_sized(&temp.path().join("web/node_modules/pkg/index.js"), 4096);
    let root = temp.path().to_str().unwrap();
    let id = json(&cli(&["clean", root, "--min-size", "0", "--json"]))["candidates"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let locked = cli(&["clean", root, "--min-size", "0", "--id", &id, "--json"]);
    assert_eq!(locked.status.code(), Some(1));
    assert_eq!(
        json(&locked)["summary"]["outcomes"][0]["status"]["rejection"]["reason"],
        "tier-locked"
    );
    write_sized(&temp.path().join("web/node_modules/new.js"), 1);
    let stale = cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--include-tier",
        "reinstallable",
        "--id",
        &id,
        "--execute",
        "--yes",
        "--json",
    ]);
    assert_eq!(stale.status.code(), Some(1));
    testkit::assert_present(temp.path().join("web/node_modules"));
}

#[test]
fn a_kind_filter_narrows_discovery() {
    let temp = tempdir("cli-kind");
    if !open_space(temp.path()) {
        return;
    }
    let _target = write_cargo_project(&temp.path().join("rust"), 100);
    write_sized(&temp.path().join("web/package.json"), 1);
    write_sized(&temp.path().join("web/dist/app.js"), 100);
    let root = temp.path().to_str().unwrap();
    let document = json(&cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--kind",
        "rust-target",
        "--json",
    ]));
    assert_eq!(document["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(document["candidates"][0]["kind"], "rust-target");
    assert_eq!(
        cli(&["clean", root, "--kind", "unknown-kind"])
            .status
            .code(),
        Some(2)
    );
}

fn write_policy(path: &Path, roots: &Path, log: &Path) {
    let policy = format!(
        "[select]\nroots = [{roots:?}]\n\n[report]\nlog_file = {log:?}\n",
        roots = roots.to_str().unwrap(),
        log = log.to_str().unwrap(),
    );
    fs::write(path, policy).unwrap();
}

fn released_cache(directory: &Path, retired: &Path) {
    testkit::write_owner_marker(
        directory,
        testkit::MarkerRole::Cache,
        testkit::MarkerKeep::Released,
        Some(retired),
    );
    write_sized(&directory.join("artifact"), 4096);
}

#[test]
fn swift_build_links_are_unlinked_only_after_the_real_workspace_lock_is_free() {
    let temp = tempdir("swift-links");
    let home = temp.path().join("home");
    let project = home.join("project");
    testkit::write_orphaned_worktree(&project);
    write_sized(&project.join("Package.swift"), 1);
    let build = project.join(".build");
    write_sized(&build.join("debug/app"), 32);
    write_sized(&build.join("checkouts/dependency/.git/HEAD"), 16);
    let outside = home.join("outside");
    write_sized(&outside.join("payload"), 1024);
    let Some(_) =
        link_dir(&build.join("release"), &build.join("debug")).or_decline("a directory link")
    else {
        return;
    };
    let Some(_) = link_dir(&build.join("external"), &outside).or_decline("a directory link") else {
        return;
    };
    let absent = isolated_user(&["explain", build.to_str().unwrap(), "--json"], &home);
    let absent = json(&absent);
    if !testkit::native_checkout_events() {
        assert_eq!(absent["eligible"], false);
        assert_eq!(absent["rejection"]["reason"], "io");
        return;
    }
    assert_eq!(
        absent["rejection"]["reason"], "liveness-unknown",
        "{absent:#}"
    );
    let path = std::path::PathBuf::from(absent["rejection"]["lock"].as_str().unwrap());
    assert!(path.starts_with(fs::canonicalize(home.join("temporary")).unwrap()));
    write_sized(&path, 0);
    let lock = File::open(path).unwrap();
    lock.lock().unwrap();
    let held = isolated_user(&["explain", build.to_str().unwrap(), "--json"], &home);
    assert_eq!(json(&held)["rejection"]["reason"], "busy");
    let discovery = isolated_user(
        &[
            "clean",
            project.to_str().unwrap(),
            "--min-size",
            "0",
            "--json",
        ],
        &home,
    );
    let document = json(&discovery);
    let id = document["candidates"][0]["id"].as_str().unwrap();
    let args = [
        "clean",
        project.to_str().unwrap(),
        "--min-size",
        "0",
        "--id",
        id,
        "--execute",
        "--yes",
        "--json",
    ];
    let blocked = isolated_user(&args, &home);
    assert_eq!(
        json(&blocked)["summary"]["outcomes"][0]["status"]["rejection"]["reason"],
        "busy"
    );
    testkit::assert_present(&build);
    drop(lock);
    let executed = isolated_user(&args, &home);
    assert_eq!(executed.status.code(), Some(0), "{executed:?}");
    assert_eq!(
        json(&executed)["summary"]["outcomes"][0]["status"]["status"],
        "deleted"
    );
    testkit::assert_absent(build);
    assert_eq!(fs::read(outside.join("payload")).unwrap(), vec![b'x'; 1024]);
    testkit::assert_present(project.join("Package.swift"));
}

#[test]
fn gleam_build_links_and_checkouts_respect_the_producers_locks() {
    let temp = tempdir("gleam-links");
    let home = temp.path().join("home");
    let project = home.join("project");
    testkit::write_orphaned_worktree(&project);
    write_sized(&project.join("gleam.toml"), 1);
    let build = project.join("build");
    write_sized(&build.join("dev/erlang/app/app.beam"), 32);
    write_sized(&build.join("packages/dependency/.git/HEAD"), 16);
    let outside = home.join("outside");
    write_sized(&outside.join("payload"), 1024);
    let Some(_) =
        link_dir(&build.join("dev/erlang/app/priv"), &outside).or_decline("a directory link")
    else {
        return;
    };
    for name in [
        "gleam.lock",
        "gleam-dev-erlang.lock",
        "gleam-prod-javascript.lock",
        "gleam-lsp-erlang.lock",
    ] {
        write_sized(&build.join(name), 0);
    }
    let discovery = isolated_user(
        &[
            "clean",
            project.to_str().unwrap(),
            "--min-size",
            "0",
            "--json",
        ],
        &home,
    );
    let document = json(&discovery);
    let id = document["candidates"][0]["id"].as_str().unwrap();
    let args = [
        "clean",
        project.to_str().unwrap(),
        "--min-size",
        "0",
        "--id",
        id,
        "--execute",
        "--yes",
        "--json",
    ];
    for name in [
        "gleam.lock",
        "gleam-dev-erlang.lock",
        "gleam-prod-javascript.lock",
        "gleam-lsp-erlang.lock",
    ] {
        let holder = File::open(build.join(name)).unwrap();
        holder.lock().unwrap();
        let explained = isolated_user(&["explain", build.to_str().unwrap(), "--json"], &home);
        let blocked = isolated_user(&args, &home);
        assert_eq!(json(&explained)["rejection"]["reason"], "busy", "{name}");
        assert_eq!(
            json(&blocked)["summary"]["outcomes"][0]["status"]["rejection"]["reason"],
            "busy",
            "{name}"
        );
        testkit::assert_present(&build);
    }
    let executed = isolated_user(&args, &home);
    assert_eq!(executed.status.code(), Some(0), "{executed:?}");
    testkit::assert_absent(build);
    assert_eq!(fs::read(outside.join("payload")).unwrap(), vec![b'x'; 1024]);
    testkit::assert_present(project.join("gleam.toml"));
}

#[test]
fn known_tool_caches_are_attributed_without_becoming_candidates() {
    let temp = tempdir("tool-cache-attribution");
    let home = temp.path().join("home");
    let cache = home.join(".cache/uv");
    write_sized(&cache.join("wheels/payload"), 8192);
    let output = isolated_user(
        &[
            "scan",
            home.to_str().unwrap(),
            "--measure",
            "both",
            "--min-size",
            "0",
            "--json",
        ],
        &home,
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = json(&output);
    assert_eq!(report["tool_caches"][0]["tool"], "uv");
    assert_eq!(report["tool_caches"][0]["usage"]["logical"], 8192);
    assert_eq!(report["candidates"], serde_json::json!([]));
    testkit::assert_present(cache.join("wheels/payload"));
}

#[test]
fn release_starts_a_monitor_and_auto_reaps_a_primary_checkout_target() {
    if !testkit::native_checkout_events() {
        testkit::decline("native checkout release events");
        return;
    }
    let temp = tempdir("cli-primary-release");
    let home = temp.path().join("home");
    let work = home.join("work");
    testkit::make_dir(&work);
    let git = testkit::Git::isolated(temp.path());
    git.run(&work, &["init", "--quiet"]);
    git.commit_file(&work, "Cargo.toml", "[package]\nname = 'x'\n");
    git.commit_file(&work, ".gitignore", "target/\n");
    let target = write_cargo_project(&work, 4096);
    let release = isolated_user(&["release", work.to_str().unwrap(), "--json"], &home);
    assert_eq!(release.status.code(), Some(0), "{release:?}");
    assert!(
        json(&release)["monitor_pid"]
            .as_u64()
            .is_some_and(|pid| pid > 0)
    );
    let policy = home.join("policy.toml");
    fs::write(
        &policy,
        format!(
            "[select]\nroots = [{}]\n",
            serde_json::to_string(&work).unwrap()
        ),
    )
    .unwrap();
    let output = isolated_user(
        &[
            "auto",
            "--config",
            policy.to_str().unwrap(),
            "--execute",
            "--json",
        ],
        &home,
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(json(&output)["reap"]["selected"], 1);
    testkit::assert_absent(target);
    testkit::assert_present(work.join("Cargo.toml"));
}

#[test]
fn no_policy_uses_user_defaults_and_preserves_unreleased_work() {
    let temp = tempdir("default-user-policy");
    let home = temp.path().join("home");
    let cache = home.join(".cache");
    let released = cache.join("released");
    released_cache(&released, &home.join("retired"));
    let active = cache.join("active");
    let key = home.join("current-project");
    write_sized(&key, 1);
    released_cache(&active, &key);
    let unclaimed = write_cargo_project(&cache.join("unclaimed"), 4096);
    let dry = isolated_user(&["auto", "--json"], &home);
    assert_eq!(dry.status.code(), Some(0), "{dry:?}");
    assert_eq!(json(&dry)["reap"]["selected"], 1);
    assert_eq!(
        json(&dry)["policy"]["selection"]["tiers"]["reinstallable"],
        false
    );
    assert_eq!(
        json(&dry)["policy"]["selection"]["tiers"]["expensive"],
        false
    );
    testkit::assert_present(&released);
    let executed = isolated_user(&["auto", "--execute", "--json"], &home);
    assert_eq!(executed.status.code(), Some(0), "{executed:?}");
    testkit::assert_absent(&released);
    testkit::assert_present(&active);
    testkit::assert_present(&unclaimed);
    testkit::assert_absent(home.join(".config/storage-scout/auto.toml"));
}

#[test]
fn an_existing_default_policy_replaces_the_default_roots() {
    let temp = tempdir("configured-user-policy");
    let home = temp.path().join("home");
    let unselected = home.join(".cache/released");
    released_cache(&unselected, &home.join("retired"));
    let configured = home.join("selected");
    let selected = configured.join("released");
    released_cache(&selected, &home.join("retired"));
    let config = home.join(".config/storage-scout/auto.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    write_policy(&config, &configured, &home.join("auto.jsonl"));
    let executed = isolated_user(&["auto", "--execute", "--json"], &home);
    assert_eq!(executed.status.code(), Some(0), "{executed:?}");
    testkit::assert_absent(&selected);
    testkit::assert_present(&unselected);
}

#[test]
fn missing_explicit_and_invalid_default_policies_never_enable_defaults() {
    let temp = tempdir("invalid-user-policy");
    let home = temp.path().join("home");
    let released = home.join(".cache/released");
    released_cache(&released, &home.join("retired"));
    let missing = home.join("missing.toml");
    let executed = isolated_user(
        &[
            "auto",
            "--config",
            missing.to_str().unwrap(),
            "--execute",
            "--json",
        ],
        &home,
    );
    assert_eq!(executed.status.code(), Some(1));
    testkit::assert_present(&released);
    testkit::write_bytes(
        &home.join(".config/storage-scout/auto.toml"),
        b"invalid policy",
    );
    let invalid = isolated_user(&["auto", "--execute", "--json"], &home);
    assert_eq!(invalid.status.code(), Some(1));
    testkit::assert_present(&released);
}

#[test]
fn a_reviewed_batch_discovers_once_and_revalidates_every_candidate() {
    let temp = tempdir("cli-batch-discovery");
    testkit::write_orphaned_worktree(temp.path());
    if !open_space(temp.path()) {
        return;
    }
    let first = write_cargo_project(&temp.path().join("first"), 4096);
    let second = write_cargo_project(&temp.path().join("second"), 4096);
    let root = temp.path().to_str().unwrap();
    let discovered = cli(&["clean", root, "--min-size", "0", "--json"]);
    assert_eq!(discovered.status.code(), Some(0));
    let document = json(&discovered);
    let candidates = document["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 2);
    let ids = candidates
        .iter()
        .map(|candidate| candidate["id"].as_str().unwrap())
        .collect::<Vec<_>>()
        .join(",");
    let trace = temp.path().join("batch.jsonl");
    let executed = cli(&[
        "clean",
        root,
        "--min-size",
        "0",
        "--id",
        &ids,
        "--execute",
        "--yes",
        "--json",
        "--trace-file",
        trace.to_str().unwrap(),
    ]);
    assert_eq!(executed.status.code(), Some(0), "{executed:?}");
    assert_eq!(
        json(&executed)["summary"]["outcomes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    testkit::assert_absent(first);
    testkit::assert_absent(second);
    let discoveries = fs::read_to_string(trace)
        .unwrap()
        .lines()
        .filter(|line| {
            let event: Value = serde_json::from_str(line).unwrap();
            event["fields"]["event"] == "discovery"
        })
        .count();
    assert_eq!(discoveries, 1);
}

#[test]
fn shared_temporary_storage_is_not_a_default_cleanup_root() {
    let temp = tempdir("default-shared-temporary");
    let home = temp.path().join("home");
    let temporary = home.join("temporary");
    fs::create_dir_all(&temporary).unwrap();
    let Some(_permissions) = testkit::restrict(&temporary, 0o1777) else {
        testkit::decline("Unix temporary-directory permissions");
        return;
    };
    let output = isolated_user(&["auto", "--execute", "--json"], &home);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        json(&output)["policy"]["selection"]["roots"],
        serde_json::json!([])
    );
    testkit::assert_absent(home.join(".config/storage-scout/auto.toml"));
}

#[test]
fn unused_toolchains_are_removed_by_rustup_and_checkout_pins_are_preserved() {
    let temp = tempdir("cli-managed-rustup");
    let home = temp.path().join("home");
    let checkout = temp.path().join("checkout");
    let unused = "1.83.0-x86_64-unknown-linux-gnu";
    let pinned = "1.84.0-x86_64-unknown-linux-gnu";
    for version in [unused, pinned] {
        testkit::write_bytes(
            &home
                .join(".rustup/toolchains")
                .join(version)
                .join("bin/rustc"),
            b"fixture compiler",
        );
    }
    testkit::write_bytes(&home.join(".rustup/settings.toml"), b"version = '12'\n");
    testkit::write_bytes(
        &checkout.join("rust-toolchain.toml"),
        b"[toolchain]\nchannel = '1.84.0'\n",
    );
    let root = checkout.to_str().unwrap();
    let discovered = isolated_user(
        &[
            "stores",
            root,
            "--provider",
            "rustup",
            "--include-tier",
            "reinstallable",
            "--json",
        ],
        &home,
    );
    assert_eq!(discovered.status.code(), Some(0), "{discovered:?}");
    let document = json(&discovered);
    assert_eq!(document["warnings"], serde_json::json!([]));
    let candidates = document["candidates"].as_array().unwrap();
    let find = |version: &str| {
        candidates
            .iter()
            .find(|candidate| candidate["label"] == format!("rust@{version}"))
            .unwrap()
    };
    assert_eq!(find(unused)["refusal"], Value::Null);
    assert_eq!(find(pinned)["refusal"], "referenced");
    let ids = format!(
        "{},{}",
        find(unused)["id"].as_str().unwrap(),
        find(pinned)["id"].as_str().unwrap()
    );
    let executed = isolated_user(
        &[
            "stores",
            root,
            "--provider",
            "rustup",
            "--include-tier",
            "reinstallable",
            "--id",
            &ids,
            "--execute",
            "--yes",
            "--json",
        ],
        &home,
    );
    assert_eq!(executed.status.code(), Some(1), "{executed:?}");
    testkit::assert_absent(home.join(".rustup/toolchains").join(unused));
    testkit::assert_present(home.join(".rustup/toolchains").join(pinned));
    assert!(
        json(&executed)["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|outcome| outcome["result"]["status"] == "removed")
    );
}

#[test]
fn mise_removes_only_an_unused_installation_and_preserves_a_checkout_pin() {
    let temp = tempdir("cli-managed-mise");
    let home = temp.path().join("home");
    let checkout = temp.path().join("checkout");
    let installs = home.join("mise-data/installs/node");
    for version in ["18.1.0", "20.1.0"] {
        for binary in ["node", "node.exe"] {
            testkit::write_bytes(
                &installs.join(version).join("bin").join(binary),
                b"fixture runtime",
            );
        }
    }
    testkit::write_bytes(&checkout.join("mise.toml"), b"[tools]\nnode = '20.1.0'\n");
    let root = checkout.to_str().unwrap();
    let discovered = isolated_user(
        &[
            "stores",
            root,
            "--provider",
            "mise",
            "--include-tier",
            "reinstallable",
            "--json",
        ],
        &home,
    );
    assert_eq!(discovered.status.code(), Some(0), "{discovered:?}");
    let document = json(&discovered);
    assert_eq!(document["warnings"], serde_json::json!([]));
    let candidates = document["candidates"].as_array().unwrap();
    let find = |version: &str| {
        candidates
            .iter()
            .find(|candidate| candidate["label"] == format!("node@{version}"))
            .unwrap()
    };
    assert_eq!(find("18.1.0")["refusal"], Value::Null);
    assert_eq!(find("20.1.0")["refusal"], "referenced");
    let id = find("18.1.0")["id"].as_str().unwrap();
    let executed = isolated_user(
        &[
            "stores",
            root,
            "--provider",
            "mise",
            "--include-tier",
            "reinstallable",
            "--id",
            id,
            "--execute",
            "--yes",
            "--json",
        ],
        &home,
    );
    assert_eq!(executed.status.code(), Some(0), "{executed:?}");
    testkit::assert_absent(installs.join("18.1.0"));
    testkit::assert_present(installs.join("20.1.0"));
}

#[test]
fn auto_reaps_a_released_cache_with_links_and_preserves_their_targets() {
    let temp = tempdir("cli-auto-linked-cache");
    if !open_space(temp.path()) {
        return;
    }
    let work = temp.path().join("work");
    let cache = work.join("cache");
    testkit::write_owner_marker(
        &cache,
        testkit::MarkerRole::Cache,
        testkit::MarkerKeep::Released,
        Some(&temp.path().join("retired-checkout")),
    );
    write_sized(&cache.join("target/app"), 8192);
    let outside = temp.path().join("outside");
    write_sized(&outside.join("payload"), 4096);
    let Some(_) =
        link_dir(&cache.join("tree/target/release"), &outside).or_decline("a directory link")
    else {
        return;
    };
    let policy = temp.path().join("auto.toml");
    write_policy(&policy, &work, &temp.path().join("auto.jsonl"));
    let config = policy.to_str().unwrap();
    let dry = cli(&["auto", "--config", config, "--json"]);
    assert_eq!(dry.status.code(), Some(0), "{dry:?}");
    assert_eq!(
        json(&dry)["reap"]["summary"]["outcomes"][0]["status"]["status"],
        "would-delete"
    );
    testkit::assert_present(&cache);
    let executed = cli(&["auto", "--config", config, "--execute", "--json"]);
    assert_eq!(executed.status.code(), Some(0), "{executed:?}");
    assert_eq!(
        json(&executed)["reap"]["summary"]["outcomes"][0]["status"]["status"],
        "deleted"
    );
    testkit::assert_absent(&cache);
    assert_eq!(fs::read(outside.join("payload")).unwrap(), vec![b'x'; 4096]);
}

#[test]
fn auto_reaps_released_work_and_never_deletes_what_is_still_owned() {
    let temp = tempdir("cli-auto");
    if !open_space(temp.path()) {
        return;
    }
    let work = temp.path().join("work");
    let busy = write_cargo_project(&work.join("busy"), 4096);
    write_sized(&busy.join("debug/.cargo-lock"), 0);
    let free = write_cargo_project(&work.join("free"), 8192);
    let linked = write_cargo_project(&work.join("linked"), 2048);
    let elsewhere = temp.path().join("elsewhere");
    write_sized(&elsewhere.join("payload"), 10);
    let _link = link_dir(&linked.join("link"), &elsewhere).or_skip("a directory link");
    let released = work.join("run");
    testkit::write_owner_marker(
        &released,
        testkit::MarkerRole::Scratch,
        testkit::MarkerKeep::Released,
        None,
    );
    write_sized(&released.join("scratch.bin"), 1024);
    let policy = temp.path().join("auto.toml");
    let log = temp.path().join("logs/auto.jsonl");
    let config = policy.to_str().unwrap();

    write_policy(&policy, &work, &log);
    let dry_run = cli(&["auto", "--config", config, "--json"]);
    assert_eq!(dry_run.status.code(), Some(0), "{dry_run:#?}");
    let document = json(&dry_run);
    assert_eq!(document["mode"], "dry-run");
    assert_eq!(document["reap"]["selected"], 1);
    assert_eq!(
        document["reap"]["summary"]["outcomes"][0]["status"]["status"],
        "would-delete"
    );
    assert!(document.get("evict").is_none());
    testkit::assert_present(&released);
    testkit::assert_absent(&log);

    let holder = File::open(busy.join("debug/.cargo-lock")).unwrap();
    holder.lock().unwrap();
    let executed = cli(&["auto", "--config", config, "--execute", "--json"]);
    assert_eq!(executed.status.code(), Some(0), "{executed:#?}");
    assert_eq!(json(&executed)["reap"]["selected"], 1);
    testkit::assert_absent(&released);
    testkit::assert_present(&free);
    testkit::assert_present(&busy);
    testkit::assert_present(&linked);
    testkit::assert_present(elsewhere.join("payload"));
    drop(holder);

    let again = json(&cli(&["auto", "--config", config, "--execute", "--json"]));
    assert_eq!(again["reap"]["selected"], 0);
    testkit::assert_present(&free);
    assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 2);

    fs::write(
        &policy,
        "[trigger]\nvolume = '/'\nmin_free = '1G'\n[select]\nroots = ['/x']\n",
    )
    .unwrap();
    let triggered = cli(&["auto", "--config", config]);
    assert_eq!(triggered.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&triggered.stderr).contains("not when the disk fills"));

    fs::write(&policy, "[select]\nroots = ['/x']\nolder_than = '3d'\n").unwrap();
    let retired = cli(&["auto", "--config", config]);
    assert_eq!(retired.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&retired.stderr).contains("no longer judges by age"));
}

#[test]
fn a_trace_file_carries_no_timestamps() {
    let temp = tempdir("cli-trace");
    if !open_space(temp.path()) {
        return;
    }
    let _target = write_cargo_project(&temp.path().join("proj"), 100);
    let trace = temp.path().join("trace.jsonl");
    let output = cli(&[
        "scan",
        temp.path().to_str().unwrap(),
        "--min-size",
        "0",
        "--json",
        "--trace-file",
        trace.to_str().unwrap(),
        "-vvv",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:#?}");
    for line in fs::read_to_string(&trace).unwrap().lines() {
        let record: Value = serde_json::from_str(line).unwrap();
        assert!(record.get("timestamp").is_none(), "{record}");
    }
    let document = json(&output);
    assert!(document["stats"].get("elapsed_secs").is_none());
}

fn hooked(args: &[&str], state: &Path, input: &[u8]) -> Output {
    use std::io::Write as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_storage-scout"))
        .args(args)
        .env("GIT_CEILING_DIRECTORIES", testkit::ceiling())
        .env("STORAGE_SCOUT_STATE_DIR", state)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn event_fixture(
    name: &str,
) -> Option<(
    testkit::Scratch,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
)> {
    let temp = tempdir(name);
    if !open_space(temp.path()) {
        return None;
    }
    let work = temp.path().join("work");
    let released = work.join("run");
    testkit::write_owner_marker(
        &released,
        testkit::MarkerRole::Scratch,
        testkit::MarkerKeep::Released,
        None,
    );
    write_sized(&released.join("scratch.bin"), 1024);
    let policy = temp.path().join("auto.toml");
    let log = temp.path().join("auto.jsonl");
    write_policy(&policy, &work, &log);
    let state = temp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    Some((temp, policy, released, state))
}

#[test]
fn an_irrelevant_event_does_nothing_and_a_relevant_one_reaps() {
    let Some((temp, policy, released, state)) = event_fixture("cli-event") else {
        return;
    };
    let config = policy.to_str().unwrap();
    let file_checkout = hooked(
        &[
            "auto",
            "--config",
            config,
            "--execute",
            "--event",
            "post-checkout",
            "--",
            "a",
            "b",
            "0",
        ],
        &state,
        b"",
    );
    assert_eq!(file_checkout.status.code(), Some(0), "{file_checkout:#?}");
    testkit::assert_present(&released);
    let local_ref = hooked(
        &["auto", "--config", config, "--execute", "--event", "reference-transaction", "--", "committed"],
        &state,
        b"0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/x\n",
    );
    assert_eq!(local_ref.status.code(), Some(0), "{local_ref:#?}");
    testkit::assert_present(&released);
    let merged = hooked(
        &[
            "auto",
            "--config",
            config,
            "--execute",
            "--event",
            "post-merge",
            "--",
            "0",
        ],
        &state,
        b"",
    );
    assert_eq!(merged.status.code(), Some(0), "{merged:#?}");
    testkit::assert_absent(&released);
    assert_eq!(
        fs::read_to_string(temp.path().join("auto.jsonl"))
            .unwrap()
            .lines()
            .count(),
        1
    );
}

#[test]
fn a_run_while_another_holds_the_station_is_handed_over() {
    let Some((_temp, policy, released, state)) = event_fixture("cli-coalesce") else {
        return;
    };
    let config = policy.to_str().unwrap();
    let owner = testkit::claim(&released);
    let first = hooked(&["auto", "--config", config, "--execute"], &state, b"");
    assert_eq!(first.status.code(), Some(0), "{first:#?}");
    drop(owner);
    testkit::assert_present(&released);
    let lock = run_lock(&state);
    let holder = File::open(&lock).unwrap();
    holder.lock().unwrap();
    let handed = hooked(&["auto", "--config", config, "--execute"], &state, b"");
    assert_eq!(handed.status.code(), Some(0), "{handed:#?}");
    assert!(String::from_utf8_lossy(&handed.stderr).contains("in progress"));
    testkit::assert_present(&released);
    let request = pending(&state).expect("the request must wait for the holder");
    assert_eq!(fs::read(request).unwrap(), b"\0\n");
    drop(holder);
    let served = hooked(&["auto", "--config", config, "--execute"], &state, b"");
    assert_eq!(served.status.code(), Some(0), "{served:#?}");
    testkit::assert_absent(&released);
}

#[test]
fn a_detached_run_finishes_in_the_background() {
    let Some((_temp, policy, released, state)) = event_fixture("cli-detach") else {
        return;
    };
    let config = policy.to_str().unwrap();
    let detached = hooked(
        &[
            "auto",
            "--config",
            config,
            "--execute",
            "--detach",
            "--json",
        ],
        &state,
        b"",
    );
    assert_eq!(detached.status.code(), Some(0), "{detached:#?}");
    let answer = json(&detached);
    assert_eq!(answer["detached"], "spawned", "{answer}");
    assert!(
        answer["pid"].as_u64().is_some_and(|pid| pid > 0),
        "{answer}"
    );
    while pending(&state).is_some() {
        std::thread::yield_now();
    }
    let lock = run_lock(&state);
    File::open(&lock).unwrap().lock().unwrap();
    testkit::assert_absent(&released);
    let recorded = fs::read_dir(&state).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".last.json")
    });
    assert!(recorded);
}
