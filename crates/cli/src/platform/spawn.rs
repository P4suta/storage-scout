use std::ffi::OsString;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(unix)]
pub(crate) mod local_socket;

#[expect(
    clippy::disallowed_methods,
    reason = "the platform owns manager process creation"
)]
fn manager(program: &str, arguments: &[&str]) -> io::Result<std::process::Output> {
    let mut command = Command::new(program);
    if let Some(home) = crate::host::home() {
        command.current_dir(&home).env("MISE_CEILING_PATHS", home);
    }
    command
        .args(arguments)
        .env_remove("MISE_CONFIG_FILE")
        .env_remove("MISE_EXTRA_CONFIG_FILES")
        .env_remove("__MISE_DIFF")
        .env_remove("__MISE_SESSION")
        .env_remove("__MISE_SHIM")
        .env_remove("__MISE_SHIM_FALLBACK_CHAIN")
        .env_remove("__MISE_ORIG_PATH")
        .env("MISE_NO_ENV", "1")
        .env("MISE_NO_HOOKS", "1")
        .env("MISE_AUTO_INSTALL", "0")
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
}

fn manager_text(program: &str, arguments: &[&str]) -> io::Result<String> {
    let result = manager(program, arguments)?;
    if !result.status.success() || !result.stderr.is_empty() {
        return Err(io::Error::other(format!(
            "{program} {arguments:?} did not provide a complete inventory: {}",
            String::from_utf8_lossy(&result.stderr)
        )));
    }
    String::from_utf8(result.stdout).map_err(io::Error::other)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ManagerQuery {
    MiseTracked,
    MiseInstalled,
    MisePrunable,
    RustupOverrides,
    RustupToolchains,
}

impl ManagerQuery {
    const fn command(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::MiseTracked => ("mise", &["config", "ls", "--tracked-configs"]),
            Self::MiseInstalled => ("mise", &["ls", "--installed", "--json"]),
            Self::MisePrunable => ("mise", &["ls", "--prunable", "--json"]),
            Self::RustupOverrides => ("rustup", &["override", "list"]),
            Self::RustupToolchains => ("rustup", &["toolchain", "list"]),
        }
    }

    pub(crate) fn read(self) -> io::Result<std::process::Output> {
        let (program, arguments) = self.command();
        manager(program, arguments)
    }

    pub(crate) fn complete(self) -> io::Result<String> {
        let (program, arguments) = self.command();
        manager_text(program, arguments)
    }
}

pub(crate) fn uninstall(removal: &crate::managed::ToolchainRemoval<'_>) -> io::Result<()> {
    let (provider, tool, version) = removal.operation()?;
    let result = match provider {
        crate::managed::Provider::Rustup => {
            manager("rustup", &["toolchain", "uninstall", "--", version])?
        },
        crate::managed::Provider::Mise => {
            manager("mise", &["uninstall", "--", &format!("{tool}@{version}")])?
        },
        crate::managed::Provider::Docker => {
            return Err(io::Error::other("wrong toolchain provider"));
        },
    };
    if !result.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&result.stderr).into_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn docker_endpoint() -> io::Result<String> {
    let explicit_context =
        std::env::var_os("DOCKER_CONTEXT").is_some_and(|value| !value.is_empty());
    let host = if explicit_context {
        None
    } else {
        match std::env::var("DOCKER_HOST") {
            Ok(host) if !host.is_empty() => Some(host),
            Ok(_) | Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(io::Error::other(error)),
        }
    };
    let host = match host {
        Some(host) => host,
        None => manager_text(
            "docker",
            &[
                "context",
                "inspect",
                "--format",
                "{{.Endpoints.docker.Host}}",
            ],
        )?
        .trim()
        .to_owned(),
    };
    if !host
        .strip_prefix("unix://")
        .is_some_and(|path| Path::new(path).is_absolute())
        && host != "npipe:////./pipe/docker_engine"
    {
        return Err(io::Error::other(
            "managed cleanup requires a local container endpoint",
        ));
    }
    Ok(host)
}

pub(crate) fn detached(
    program: &Path,
    arguments: &[OsString],
    directory: &Path,
) -> io::Result<u32> {
    background(program, arguments, directory)
        .spawn()
        .map(|child| child.id())
}

#[expect(
    clippy::disallowed_methods,
    reason = "the platform owns background process creation"
)]
fn background(program: &Path, arguments: &[OsString], directory: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    command
}

pub(crate) fn release_monitor(
    program: &Path,
    checkout: &Path,
    directory: &Path,
) -> io::Result<u32> {
    let arguments = [
        OsString::from("release"),
        checkout.as_os_str().to_owned(),
        OsString::from("--monitor"),
    ];
    let mut child = background(program, &arguments, directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut ready = [0; crate::ingress::RELEASE_READY_BYTES];
    let read = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("the release monitor has no readiness channel"))?
        .read_exact(&mut ready);
    if read.is_err() || !crate::ingress::release_ready(&ready) {
        let _stopped = child.kill();
        let _reaped = child.wait();
        return Err(io::Error::other(
            "the release monitor could not record the checkout release",
        ));
    }
    Ok(child.id())
}
