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

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_storage-scout"))
        .args(args)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_MANIFEST_DIR"))
        .env("STORAGE_SCOUT_STATE_DIR", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
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
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_MANIFEST_DIR"))
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
    let lock = fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
        })
        .unwrap();
    let holder = File::open(&lock).unwrap();
    holder.lock().unwrap();
    let handed = hooked(&["auto", "--config", config, "--execute"], &state, b"");
    assert_eq!(handed.status.code(), Some(0), "{handed:#?}");
    assert!(String::from_utf8_lossy(&handed.stderr).contains("in progress"));
    testkit::assert_present(&released);
    let pending = fs::read_dir(&state).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|extension| extension == "pending")
    });
    assert!(pending, "the request must wait for the holder");
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
    let flag = |path: &Path| {
        path.extension()
            .is_some_and(|extension| extension == "pending")
    };
    while fs::read_dir(&state)
        .unwrap()
        .any(|entry| flag(&entry.unwrap().path()))
    {
        std::thread::yield_now();
    }
    let lock = fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
        })
        .unwrap();
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
