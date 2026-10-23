use std::collections::{BTreeMap, BTreeSet};
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
    #[error("cannot inspect user area {}: {source}", path.display())]
    UserArea { path: PathBuf, source: io::Error },
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

pub(crate) fn tool_caches() -> BTreeMap<PathBuf, &'static str> {
    const LAYOUTS: [(&str, &str); 14] = [
        ("uv", "uv"),
        ("pip", "pip"),
        ("npm", "npm"),
        ("pnpm", "pnpm"),
        ("yarn", "yarn"),
        ("go-build", "go"),
        ("sccache", "sccache"),
        ("ccache", "ccache"),
        ("mise", "mise"),
        ("Homebrew", "homebrew"),
        ("org.swift.swiftpm", "swiftpm"),
        ("ms-playwright", "playwright"),
        ("JetBrains", "jetbrains"),
        ("com.apple.dt.Xcode", "xcode"),
    ];
    let Some(home) = home() else {
        return BTreeMap::new();
    };
    let xdg = variable("XDG_CACHE_HOME")
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".cache"));
    let mut bases = vec![xdg];
    match Platform::HOST {
        Platform::MacOs => bases.push(home.join("Library/Caches")),
        Platform::Windows => bases.push(
            variable("LOCALAPPDATA")
                .filter(|path| path.is_absolute())
                .unwrap_or_else(|| home.join("AppData/Local")),
        ),
        Platform::Linux => {},
    }
    let mut roots = BTreeMap::new();
    for base in bases {
        for (suffix, tool) in LAYOUTS {
            cache_root(&mut roots, base.join(suffix), tool);
        }
    }
    let cargo = variable("CARGO_HOME")
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".cargo"));
    for suffix in ["registry", "git"] {
        cache_root(&mut roots, cargo.join(suffix), "cargo");
    }
    for (suffix, tool) in [
        (".npm", "npm"),
        (".gradle/caches", "gradle"),
        ("Library/Developer/Xcode/DerivedData", "xcode"),
    ] {
        cache_root(&mut roots, home.join(suffix), tool);
    }
    roots
}

fn cache_root(roots: &mut BTreeMap<PathBuf, &'static str>, path: PathBuf, tool: &'static str) {
    let canonical = match fs::canonicalize(&path) {
        Ok(canonical) => canonical,
        Err(_unavailable) => path,
    };
    roots.insert(canonical, tool);
}

pub(crate) fn default_roots() -> Result<Vec<PathBuf>, HostError> {
    const CACHE: &str = ".cache";
    const STATE: &str = ".local/state";
    const DATA: &str = ".local/share";
    const MAC_CACHE: &str = "Library/Caches";
    const MAC_STATE: &str = "Library/Application Support";
    const WINDOWS_LOCAL: &str = "AppData/Local";
    const WINDOWS_ROAMING: &str = "AppData/Roaming";
    let mut paths = Vec::new();
    let temporary = env::temp_dir();
    match crate::platform::user_temporary(&temporary) {
        Ok(true) => paths.push(temporary),
        Ok(false) => {},
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(source) => {
            return Err(HostError::UserArea {
                path: temporary,
                source,
            });
        },
    }
    if let Some(home) = home() {
        for (name, suffix) in [
            ("XDG_CACHE_HOME", CACHE),
            ("XDG_STATE_HOME", STATE),
            ("XDG_DATA_HOME", DATA),
        ] {
            paths.push(match variable(name).filter(|path| path.is_absolute()) {
                Some(path) => path,
                None => home.join(suffix),
            });
        }
        match Platform::HOST {
            Platform::MacOs => paths.extend([home.join(MAC_CACHE), home.join(MAC_STATE)]),
            Platform::Windows => {
                for (name, suffix) in [
                    ("LOCALAPPDATA", WINDOWS_LOCAL),
                    ("APPDATA", WINDOWS_ROAMING),
                ] {
                    paths.push(match variable(name).filter(|path| path.is_absolute()) {
                        Some(path) => path,
                        None => home.join(suffix),
                    });
                }
            },
            Platform::Linux => {},
        }
    }
    let mut roots = BTreeSet::new();
    for path in paths {
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                let canonical = fs::canonicalize(&path).map_err(|source| HostError::UserArea {
                    path: path.clone(),
                    source,
                })?;
                roots.insert(canonical);
            },
            Ok(_) => {
                return Err(HostError::UserArea {
                    path,
                    source: io::Error::from(io::ErrorKind::NotADirectory),
                });
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(source) => return Err(HostError::UserArea { path, source }),
        }
    }
    Ok(roots.into_iter().collect())
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
