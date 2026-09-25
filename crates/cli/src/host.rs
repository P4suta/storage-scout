use std::path::{Path, PathBuf};
use std::{env, fs, io};

use storage_scout_core::area::{Protection, ProtectionError};
use storage_scout_core::location::{Location, LocationError, Syntax};
use storage_scout_core::platform::Platform;
use storage_scout_core::reject::Rejection;
use storage_scout_core::table::{self, Host};

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("cannot resolve the current directory: {0}")]
    CurrentDirectory(io::Error),
    #[error("cannot locate the running binary: {0}")]
    Executable(io::Error),
    #[error("{} is not a path this platform can name", .0.display())]
    Unnameable(PathBuf),
    #[error("a protected-area table did not build: {0}")]
    Table(LocationError),
    #[error(transparent)]
    Protection(ProtectionError),
}

pub(crate) fn locate(path: &Path) -> Result<Location, Rejection> {
    match Location::parse(Syntax::HOST, path.as_os_str().as_encoded_bytes()) {
        Ok(location) => Ok(location),
        Err(_unnameable) => Err(Rejection::Unnameable {
            location: path.display().to_string(),
        }),
    }
}

fn host_location(path: &Path) -> Result<Location, HostError> {
    match Location::parse(Syntax::HOST, path.as_os_str().as_encoded_bytes()) {
        Ok(location) => Ok(location),
        Err(_unnameable) => Err(HostError::Unnameable(path.to_path_buf())),
    }
}

fn resolved(path: Option<PathBuf>) -> Result<Option<Location>, HostError> {
    let Some(path) = path else {
        return Ok(None);
    };
    match fs::canonicalize(&path) {
        Ok(canonical) => host_location(&canonical).map(Some),
        Err(_absent) => Ok(None),
    }
}

fn variable(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub(crate) fn home() -> Option<PathBuf> {
    let (first, second) = if cfg!(windows) {
        ("USERPROFILE", "HOME")
    } else {
        ("HOME", "USERPROFILE")
    };
    variable(first).or_else(|| variable(second))
}

fn program_areas() -> Result<Vec<(&'static str, Location)>, HostError> {
    let mut areas = Vec::new();
    for (label, name) in [
        ("Windows", "SystemRoot"),
        ("Program Files", "ProgramFiles"),
        ("Program Files (x86)", "ProgramFiles(x86)"),
        ("Program Files", "ProgramW6432"),
        ("ProgramData", "ProgramData"),
    ] {
        if let Some(location) = resolved(variable(name))? {
            areas.push((label, location));
        }
    }
    Ok(areas)
}

pub(crate) fn detect() -> Result<Protection, HostError> {
    let platform = Platform::HOST;
    let host = Host {
        home: resolved(home())?,
        temp: resolved(Some(env::temp_dir()))?,
        xdg_cache: resolved(variable("XDG_CACHE_HOME"))?,
        program_areas: match platform {
            Platform::Windows => program_areas()?,
            Platform::MacOs | Platform::Linux => Vec::new(),
        },
    };
    let rules = table::rules(platform, &host).map_err(HostError::Table)?;
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(HostError::CurrentDirectory)?;
    let exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(HostError::Executable)?;
    Protection::new(
        platform.syntax(),
        platform.case(),
        host_location(&cwd)?,
        host_location(&exe)?,
        rules,
    )
    .map_err(HostError::Protection)
}
