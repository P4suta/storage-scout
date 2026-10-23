use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::assurance::runner::container;

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Validate,
    Extract,
}

fn local_host() -> Result<String> {
    let explicit_context =
        std::env::var_os("DOCKER_CONTEXT").is_some_and(|value| !value.is_empty());
    let host = if explicit_context {
        None
    } else {
        match std::env::var("DOCKER_HOST") {
            Ok(host) => {
                if host.is_empty() {
                    None
                } else {
                    Some(host)
                }
            },
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(error.into()),
        }
    };
    let host = match host {
        Some(host) => host,
        None => {
            let inspected = container(None)
                .args([
                    "context",
                    "inspect",
                    "--format",
                    "{{.Endpoints.docker.Host}}",
                ])
                .output()
                .context("inspect the local container endpoint")?;
            ensure!(
                inspected.status.success(),
                "container endpoint inspection failed"
            );
            String::from_utf8(inspected.stdout)?.trim().to_owned()
        },
    };
    ensure!(
        host.strip_prefix("unix://")
            .is_some_and(|path| Path::new(path).is_absolute())
            || host == "npipe:////./pipe/docker_engine",
        "verification requires a local container endpoint"
    );
    Ok(host)
}

pub(super) fn run(root: &Path, mode: Mode) -> Result<()> {
    let host = local_host()?;
    let built = container(Some(&host))
        .args(["build", "--quiet"])
        .arg(root.join("tools/renovate"))
        .output()
        .context("build the pinned Renovate verifier image")?;
    ensure!(
        built.status.success(),
        "Renovate image build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let image = String::from_utf8(built.stdout)?;
    let mut command = container(Some(&host));
    command
        .args([
            "run",
            "--rm",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--cpus",
            "2",
            "--memory",
            "1g",
            "--pids-limit",
            "256",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=512m",
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/tmp",
            "--env",
            "RENOVATE_BASE_DIR=/tmp/renovate",
            "--env",
            "RENOVATE_CACHE_DIR=/tmp/cache",
            "--env",
            "RENOVATE_BINARY_SOURCE=global",
            "--mount",
        ])
        .arg(format!(
            "type=bind,source={},target=/workspace,readonly",
            root.display()
        ));
    match mode {
        Mode::Validate => {
            command.args([
                "--entrypoint",
                "renovate-config-validator",
                "--",
                image.trim(),
                "--strict",
                "renovate.json",
            ]);
        },
        Mode::Extract => {
            command.args([
                "--env",
                "LOG_LEVEL=debug",
                "--entrypoint",
                "renovate",
                "--",
                image.trim(),
                "--platform=local",
                "--dry-run=extract",
                "--onboarding=false",
                "--require-config=required",
            ]);
        },
    }
    ensure!(command.status()?.success(), "Renovate verification failed");
    Ok(())
}
