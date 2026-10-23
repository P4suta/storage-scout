#![expect(
    clippy::disallowed_methods,
    reason = "the verification adapter writes owned snapshots and starts the pinned verifiers"
)]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, ensure};
use quote::ToTokens;
use sha2::{Digest, Sha256};

use super::ingress;

const PROBE: &str = "proofs::deletion_never_accepts_an_unsettled_owner";
const NATIVE_BACKENDS: &[(&str, &[&str])] = &[
    ("events_linux.rs", &["linux"]),
    ("events_macos.rs", &["macos"]),
    ("events_windows.rs", &["windows"]),
    ("events_none.rs", &[]),
    ("share_linux.rs", &["linux"]),
    ("share_macos.rs", &["macos"]),
    ("share_none.rs", &["windows"]),
    ("unix.rs", &["linux", "macos"]),
    ("windows.rs", &["windows"]),
    ("spawn/local_socket.rs", &["linux", "macos"]),
];

fn mutation_command(root: &Path, args: &[OsString], scratch: Option<&Path>) -> Command {
    let mut command = Command::new("cargo");
    command.args([
        "mutants",
        "--jobs",
        "1",
        "--jobserver-tasks",
        "2",
        "--no-shuffle",
        "--timeout",
        "60",
        "--build-timeout",
        "300",
    ]);
    for (file, hosts) in NATIVE_BACKENDS {
        if !hosts.contains(&std::env::consts::OS) {
            command
                .arg("--exclude")
                .arg(format!("crates/cli/src/platform/{file}"));
        }
    }
    if args.iter().any(|argument| argument == "--no-config") {
        command.args([
            "--test-workspace=true",
            "--cargo-arg=--locked",
            "--cargo-test-arg=--all-targets",
        ]);
    }
    command.args(args).current_dir(root);
    if let Some(scratch) = scratch {
        mutation_environment(&mut command, scratch);
    }
    command
}

fn mutation_environment(command: &mut Command, scratch: &Path) {
    for variable in ["TMPDIR", "TMP", "TEMP"] {
        command.env(variable, scratch);
    }
    command.env("CARGO_TARGET_DIR", scratch.join("target"));
    command.env("RUST_TEST_THREADS", "2");
}

pub(crate) fn mutation(root: &Path, args: &[OsString], out: &mut dyn Write) -> Result<ExitStatus> {
    if args == [OsString::from("--list"), OsString::from("--json")] {
        let result = mutation_command(root, args, None)
            .output()
            .context("list cargo-mutants catalog")?;
        out.write_all(&result.stderr)?;
        if result.status.success() {
            let count = ingress::mutation_catalog_len(&result.stdout)?;
            let catalog = root.join("target/mutation-catalog.json");
            fs::create_dir_all(root.join("target"))?;
            fs::write(&catalog, &result.stdout)?;
            writeln!(out, "mutation: {count} catalogued; {}", catalog.display())?;
        }
        return Ok(result.status);
    }
    if args.iter().any(|argument| {
        matches!(
            argument.to_str(),
            Some("--list" | "--list-files" | "--help" | "-h" | "--version" | "--check")
        )
    }) {
        return mutation_command(root, args, None)
            .status()
            .context("inspect cargo-mutants");
    }
    let parent = match std::env::var_os("STORAGE_SCOUT_MUTATION_TMPDIR") {
        Some(parent) => PathBuf::from(parent),
        None => root.join("target"),
    };
    ensure!(
        parent.is_absolute(),
        "the mutation temporary root must be absolute"
    );
    fs::create_dir_all(&parent)?;
    let scratch = tempfile::Builder::new()
        .prefix("mutation-")
        .tempdir_in(parent)?;
    let reports = root.join("target/mutation-reports");
    fs::create_dir_all(&reports)?;
    let report = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(reports)?
        .keep();
    let digest = snapshot(root, &report.join("source"))?;
    let source = scratch.path().join("source");
    ensure!(
        digest == snapshot(root, &source)?,
        "source changed while preparing mutation testing"
    );
    fs::write(report.join("source-before.sha256"), format!("{digest}\n"))?;
    let version = ingress::mutation_version(&source)?;
    writeln!(out, "mutation: evidence {}", report.display())?;
    let baseline_log = fs::File::create(report.join("workspace-baseline.log"))?;
    let mut baseline = Command::new("cargo");
    baseline
        .args(["test", "--workspace", "--all-targets", "--locked"])
        .current_dir(&source)
        .stdout(Stdio::from(baseline_log.try_clone()?))
        .stderr(Stdio::from(baseline_log));
    mutation_environment(&mut baseline, scratch.path());
    let baseline = baseline
        .status()
        .context("check the mutation workspace baseline")?;
    if !baseline.success() {
        return Ok(baseline);
    }
    writeln!(out, "mutation: workspace baseline passed")?;
    let status = mutation_command(&source, args, Some(scratch.path()))
        .arg("--output")
        .arg(&report)
        .status()
        .context("start pinned cargo-mutants");
    if args.iter().any(|argument| argument == "--leak-dirs") {
        let _retained = scratch.keep();
    }
    let status = status?;
    if status.success() {
        ingress::mutation_report(&report.join("mutants.out"), &version)?;
        ensure!(
            digest == snapshot(root, &report.join("final-source"))?,
            "source changed during mutation testing; results are stale"
        );
        fs::write(report.join("source.sha256"), format!("{digest}\n"))?;
        writeln!(out, "mutation: all selected results passed for {digest}")?;
    }
    Ok(status)
}

pub(crate) fn container(host: Option<&str>) -> Command {
    let mut command = Command::new("docker");
    if let Some(host) = host {
        command
            .args(["--host", host])
            .env_remove("DOCKER_CONTEXT")
            .env_remove("DOCKER_HOST");
    }
    command
}
const INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "clippy.toml",
    "README.md",
    "mise.toml",
    "mise.lock",
    ".mise/locks",
    "tools",
    "assurance.toml",
    "crates",
    "xtask",
    "fuzz",
    "specs",
    ".cargo",
];

fn copy(source: &Path, destination: &Path, digest: &mut Sha256) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "verification inputs cannot be symlinks: {}",
        source.display()
    );
    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            if name == "target"
                || name == "artifacts"
                || name.to_string_lossy().starts_with(".storage-scout-")
            {
                continue;
            }
            digest.update(name.as_encoded_bytes());
            copy(&entry.path(), &destination.join(name), digest)?;
        }
    } else {
        let bytes = fs::read(source)?;
        digest.update(bytes.len().to_le_bytes());
        digest.update(&bytes);
        fs::write(destination, bytes)?;
    }
    Ok(())
}

fn snapshot(root: &Path, destination: &Path) -> Result<String> {
    fs::create_dir_all(destination)?;
    let mut digest = Sha256::new();
    for input in INPUTS {
        digest.update(input.as_bytes());
        copy(&root.join(input), &destination.join(input), &mut digest)?;
    }
    let tools = match fs::read(root.join("mise.toml")) {
        Ok(tools) => tools,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::read(root.join("verification-tools.toml"))?
        },
        Err(error) => return Err(error.into()),
    };
    digest.update(&tools);
    fs::write(destination.join("verification-tools.toml"), tools)?;
    Ok(hex::encode(digest.finalize()))
}

fn command(
    root: &Path,
    binary: &str,
    args: &[&str],
    environment: &[(&str, &Path)],
) -> Result<ExitStatus> {
    let mut command = Command::new(binary);
    command
        .args(args)
        .current_dir(root)
        .env("RUSTC_WRAPPER", "");
    for (key, value) in environment {
        command.env(key, value);
    }
    command.status().with_context(|| format!("start {binary}"))
}

fn required(root: &Path, binary: &str, args: &[&str], environment: &[(&str, &Path)]) -> Result<()> {
    let status = command(root, binary, args, environment)?;
    ensure!(status.success(), "{binary} {args:?} failed with {status}");
    Ok(())
}

fn corrupt_deletion(file: &Path) -> Result<()> {
    let mut source = syn::parse_file(&fs::read_to_string(file)?)?;
    let mut changed = 0usize;
    for item in &mut source.items {
        if let syn::Item::Impl(implementation) = item
            && matches!(implementation.self_ty.as_ref(), syn::Type::Path(path) if path.path.is_ident("Admits"))
        {
            for member in &mut implementation.items {
                if let syn::ImplItem::Fn(function) = member
                    && function.sig.ident == "deletion"
                {
                    function.block = syn::parse_quote!({ true });
                    function.sig.inputs = syn::parse_quote!(self, _settlement: Settlement);
                    changed = changed.saturating_add(1);
                }
            }
        }
    }
    ensure!(
        changed == 1,
        "probe did not find exactly one deletion decision"
    );
    fs::write(file, source.to_token_stream().to_string())?;
    Ok(())
}

fn kani(root: &Path, package: &str, result: &Path, extra: &[&str]) -> Result<ExitStatus> {
    let result = result.to_str().context("non-UTF8 result path")?;
    let mut args = vec![
        "kani",
        "-p",
        package,
        "--output-format",
        "terse",
        "-Z",
        "unstable-options",
        "--export-json",
        result,
        "--harness-timeout",
        "180s",
    ];
    args.extend_from_slice(extra);
    command(root, "cargo", &args, &[])
}

fn formal(
    source: &Path,
    work: &Path,
    config: &ingress::Inventory,
    out: &mut dyn Write,
) -> Result<()> {
    writeln!(out, "assurance: Kani implementation proofs")?;
    let result = work.join("kani.json");
    ensure!(
        kani(source, "storage-scout-core", &result, &["--lib"])?.success(),
        "Kani failed; evidence {}",
        result.display()
    );
    ingress::report(&result, &config.harnesses)?;

    let gate_result = work.join("gate.json");
    ensure!(
        kani(source, "xtask", &gate_result, &[])?.success(),
        "assurance gate proof failed"
    );
    ingress::report(
        &gate_result,
        &["assurance::ingress::proofs::incomplete_or_vacuous_results_never_pass".to_owned()],
    )?;

    writeln!(out, "assurance: reject an owned-path eligibility defect")?;
    let probe = work.join("probe");
    let _probe_digest = snapshot(source, &probe)?;
    corrupt_deletion(&probe.join("crates/core/src/ownership.rs"))?;
    let rejected = work.join("probe.json");
    let status = kani(
        &probe,
        "storage-scout-core",
        &rejected,
        &["--lib", "--harness", PROBE, "--exact"],
    )?;
    ensure!(!status.success(), "the unsafe deletion probe passed");
    ingress::rejected_probe(&rejected, PROBE)?;
    Ok(())
}

fn model(source: &Path, work: &Path, out: &mut dyn Write) -> Result<()> {
    writeln!(out, "assurance: Quint/TLA+ reachable-state model")?;
    required(
        source,
        "quint",
        &[
            "verify",
            "specs/cleanup.qnt",
            "--backend",
            "tlc",
            "--invariant",
            "safety",
            "--apalache-version",
            "0.56.1",
            "--tlc-config",
            "specs/tlc.json",
            "--verbosity",
            "3",
        ],
        &[],
    )?;
    let traces = work.join("traces");
    fs::create_dir_all(&traces)?;
    let generated = traces.join("generated-{seq}.itf.json");
    required(
        source,
        "quint",
        &[
            "run",
            "specs/cleanup.qnt",
            "--invariant",
            "safety",
            "--seed",
            "16",
            "--max-samples",
            "32",
            "--n-traces",
            "32",
            "--max-steps",
            "12",
            "--backend",
            "typescript",
            "--verbosity",
            "0",
            "--out-itf",
            generated.to_str().context("non-UTF8 trace path")?,
        ],
        &[],
    )?;
    let witnesses = traces.join("witness-{test}.itf.json");
    required(
        source,
        "quint",
        &[
            "test",
            "specs/cleanup.qnt",
            "--match",
            "Witness",
            "--seed",
            "16",
            "--backend",
            "typescript",
            "--out-itf",
            witnesses.to_str().context("non-UTF8 trace path")?,
        ],
        &[],
    )?;
    writeln!(
        out,
        "assurance: replay model transitions against Scout::apply"
    )?;
    required(
        source,
        "cargo",
        &[
            "test",
            "--locked",
            "-p",
            "storage-scout",
            "--test",
            "cleanup_replay",
        ],
        &[("STORAGE_SCOUT_REPLAY_DIR", &traces)],
    )?;
    Ok(())
}

fn inputs(source: &Path, work: &Path, out: &mut dyn Write) -> Result<()> {
    let nightly = ingress::miri_toolchain(source)?;
    required(
        source,
        "rustup",
        &[
            "toolchain",
            "install",
            &nightly,
            "--component",
            "miri",
            "--profile",
            "minimal",
        ],
        &[],
    )?;
    writeln!(out, "assurance: parser corpus and bounded fuzz exploration")?;
    for (package, test) in [
        ("storage-scout-core", "corpus"),
        ("storage-scout", "policy_corpus"),
    ] {
        required(
            source,
            "cargo",
            &["test", "--locked", "-p", package, "--test", test],
            &[],
        )?;
    }
    for target in ["auto_policy", "core_parsers"] {
        required(
            source,
            "rustup",
            &[
                "run",
                &nightly,
                "cargo",
                "fuzz",
                "run",
                target,
                "--",
                "-runs=1024",
                "-max_len=1024",
                "-seed=16",
            ],
            &[],
        )?;
    }

    writeln!(out, "assurance: Miri production core tests")?;
    let sysroot = work.join("miri-sysroot");
    required(
        source,
        "rustup",
        &["run", &nightly, "cargo", "miri", "setup"],
        &[("MIRI_SYSROOT", &sysroot)],
    )?;
    required(
        source,
        "rustup",
        &[
            "run",
            &nightly,
            "cargo",
            "miri",
            "test",
            "--locked",
            "-p",
            "storage-scout-core",
            "--lib",
        ],
        &[("MIRI_SYSROOT", &sysroot)],
    )?;
    Ok(())
}

pub(super) fn run(root: &Path, out: &mut dyn Write) -> Result<()> {
    fs::create_dir_all(root.join("target"))?;
    let work: PathBuf = tempfile::Builder::new()
        .prefix("assurance-")
        .tempdir_in(root.join("target"))?
        .keep();
    let source = work.join("source");
    let digest = snapshot(root, &source)?;
    super::inventory(&source)?;
    let config = ingress::inventory(&source)?;
    writeln!(
        out,
        "assurance: source {digest}; evidence {}",
        work.display()
    )?;
    formal(&source, &work, &config, out)?;
    model(&source, &work, out)?;
    inputs(&source, &work, out)?;
    let final_copy = work.join("final-source");
    ensure!(
        digest == snapshot(root, &final_copy)?,
        "source changed during verification; receipts are stale"
    );
    fs::write(work.join("source.sha256"), format!("{digest}\n"))?;
    writeln!(out, "assurance: all required layers passed for {digest}")?;
    Ok(())
}

#[cfg(test)]
mod mutation_tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn a_mutation_child_uses_the_selected_scratch_for_every_temporary_variable() {
        let root = testkit::tempdir("mutation-command");
        let scratch = root.path().join("isolated");
        let args = [
            OsString::from("--file"),
            OsString::from("crates/core/src/managed.rs"),
        ];
        let command = mutation_command(root.path(), &args, Some(&scratch));
        assert_eq!(command.get_current_dir(), Some(root.path()));
        let actual = command.get_args().collect::<Vec<_>>();
        let requested = args.iter().map(OsString::as_os_str).collect::<Vec<_>>();
        assert!(actual.ends_with(&requested));
        for variable in ["TMPDIR", "TMP", "TEMP"] {
            assert_eq!(
                command
                    .get_envs()
                    .find(|(key, _)| *key == OsStr::new(variable)),
                Some((OsStr::new(variable), Some(scratch.as_os_str())))
            );
        }
        assert_eq!(command.get_program(), OsStr::new("cargo"));
        assert_eq!(command.get_args().next(), Some(OsStr::new("mutants")));
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new("CARGO_TARGET_DIR")),
            Some((
                OsStr::new("CARGO_TARGET_DIR"),
                Some(scratch.join("target").as_os_str())
            ))
        );
        assert_eq!(
            mutation_command(root.path(), &args, None)
                .get_envs()
                .count(),
            0
        );
    }
}
