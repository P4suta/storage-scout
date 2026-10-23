use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use storage_scout_core::managed::{
    Clearance, Completeness, PINNED_DATE_WIDTHS, References, Resource, version_reference,
};
use storage_scout_core::platform::Platform;
use storage_scout_core::size::Bytes;

use super::{Action, ManagedUsage, Port, Provider, Survey, absolute, candidate};
use crate::ingress::{self, Installation, ToolPin};
use crate::platform::spawn::ManagerQuery;
use crate::{host, platform};

pub(crate) struct ToolchainRemoval<'a> {
    provider: Provider,
    tool: &'a str,
    version: &'a str,
    clearance: &'a Clearance,
}

impl ToolchainRemoval<'_> {
    pub(crate) fn operation(&self) -> io::Result<(Provider, &str, &str)> {
        if self.clearance.resource() != Resource::Toolchain {
            return Err(io::Error::other("wrong toolchain capability"));
        }
        Ok((self.provider, self.tool, self.version))
    }
}

pub(super) struct Manager {
    provider: Provider,
    root: PathBuf,
}

struct Pins {
    versions: Vec<ToolPin>,
    completeness: Completeness,
    warnings: Vec<String>,
}

fn configuration(path: &Path) -> bool {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| {
            matches!(
                name,
                "Cargo.toml"
                    | "rust-toolchain"
                    | "rust-toolchain.toml"
                    | "lean-toolchain"
                    | "mise.lock"
                    | "mise.toml"
                    | ".mise.toml"
                    | ".tool-versions"
            ) || ((name.starts_with("mise.") || name.starts_with(".mise."))
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("toml")))
        })
}

fn collect(root: &Path, files: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    let root = match absolute(root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut seen = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        if !seen.insert(platform::identity(&directory)?) {
            return Err(io::Error::other(
                "the checkout reference walk encountered an aliased directory",
            ));
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let shape = platform::shape(&fs::symlink_metadata(&path)?);
            match shape {
                storage_scout_core::gate::Shape::Link if configuration(&path) => {
                    return Err(io::Error::other(
                        "a checkout tool configuration is a symbolic link",
                    ));
                },
                storage_scout_core::gate::Shape::Directory if entry.file_name() != ".git" => {
                    pending.push(path);
                },
                storage_scout_core::gate::Shape::File if configuration(&path) => {
                    files.insert(path);
                },
                storage_scout_core::gate::Shape::Directory
                | storage_scout_core::gate::Shape::File
                | storage_scout_core::gate::Shape::Link
                | storage_scout_core::gate::Shape::Other => {},
            }
        }
    }
    Ok(())
}

fn pins(roots: &[PathBuf]) -> io::Result<Pins> {
    if roots.is_empty() {
        return Err(io::Error::other(
            "toolchain discovery requires the policy's checkout roots",
        ));
    }
    let mut files = BTreeSet::new();
    for name in ["MISE_CONFIG_FILE", "MISE_EXTRA_CONFIG_FILES"] {
        if let Some(paths) = std::env::var_os(name) {
            files.extend(std::env::split_paths(&paths));
        }
    }
    for root in roots {
        collect(root, &mut files)?;
    }
    match ManagerQuery::MiseTracked.complete() {
        Ok(tracked) => {
            for path in tracked.lines().filter(|line| !line.trim().is_empty()) {
                files.insert(PathBuf::from(path));
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error),
    }
    let mut result = Pins {
        versions: Vec::new(),
        completeness: Completeness::Complete,
        warnings: Vec::new(),
    };
    for path in files {
        let read = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::read_to_string(&path)
            },
            Ok(_) => Err(io::Error::other(
                "a tracked configuration is not a regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => Err(error),
        };
        match read.and_then(|text| ingress::tool_pins(&path, &text)) {
            Ok(versions) => result.versions.extend(versions),
            Err(error) => {
                result.completeness = Completeness::Incomplete;
                result.warnings.push(format!("{}: {error}", path.display()));
            },
        }
    }
    Ok(result)
}

fn reference(pins: &[ToolPin], tool: &str, version: &str) -> References {
    let mut state = References::Unused;
    for pin in pins
        .iter()
        .filter(|pin| pin.tool == tool || pin.tool.strip_prefix("core:") == Some(tool))
    {
        match version_reference(&pin.version, version) {
            References::Referenced => return References::Referenced,
            References::Unknown => state = References::Unknown,
            References::Unused => {},
        }
    }
    state
}

fn rust_channel(name: &str) -> Option<&str> {
    let (first, rest) = name.split_once('-')?;
    if matches!(first, "stable" | "beta" | "nightly") {
        let date = rest
            .split('-')
            .take(PINNED_DATE_WIDTHS.len())
            .collect::<Vec<_>>();
        if date.iter().map(|part| part.len()).eq(PINNED_DATE_WIDTHS)
            && date
                .iter()
                .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return name.get(
                ..first
                    .len()
                    .saturating_add(1)
                    .saturating_add("2000-01-01".len()),
            );
        }
        Some(first)
    } else if first
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        Some(first)
    } else {
        None
    }
}

impl Manager {
    pub(super) fn new(provider: Provider) -> io::Result<Self> {
        let home = host::home().ok_or_else(|| io::Error::other("the user home is unavailable"))?;
        let root = match provider {
            Provider::Rustup => {
                std::env::var_os("RUSTUP_HOME").map_or_else(|| home.join(".rustup"), PathBuf::from)
            },
            Provider::Mise => std::env::var_os("MISE_DATA_DIR").map_or_else(
                || match std::env::var_os("XDG_DATA_HOME") {
                    Some(data) => PathBuf::from(data).join("mise"),
                    None => match Platform::HOST {
                        Platform::Windows => std::env::var_os("LOCALAPPDATA").map_or_else(
                            || home.join("AppData/Local/mise"),
                            |data| PathBuf::from(data).join("mise"),
                        ),
                        Platform::MacOs | Platform::Linux => home.join(".local/share/mise"),
                    },
                },
                PathBuf::from,
            ),
            Provider::Docker => {
                return Err(io::Error::other(
                    "the container engine is not a toolchain manager",
                ));
            },
        };
        Ok(Self {
            provider,
            root: absolute(&root)?,
        })
    }

    fn installations(&self, pins: &mut Pins) -> io::Result<Vec<(String, Installation)>> {
        match self.provider {
            Provider::Rustup => {
                let overrides = ManagerQuery::RustupOverrides.complete()?;
                if overrides.trim() != "no overrides" {
                    for line in overrides.lines() {
                        let version = line
                            .split_whitespace()
                            .last()
                            .ok_or_else(|| io::Error::other("invalid rustup override"))?;
                        let version = rust_channel(version).ok_or_else(|| {
                            io::Error::other("a custom rustup override cannot be resolved")
                        })?;
                        pins.versions.push(ToolPin {
                            tool: "rust".to_owned(),
                            version: version.to_owned(),
                        });
                    }
                }
                let listed = ManagerQuery::RustupToolchains.complete()?;
                if listed.trim() == "no installed toolchains" {
                    return Ok(Vec::new());
                }
                listed
                    .lines()
                    .map(|line| {
                        let mut fields = line.split_whitespace();
                        let version = fields
                            .next()
                            .ok_or_else(|| io::Error::other("invalid rustup toolchain"))?;
                        Ok((
                            "rust".to_owned(),
                            Installation {
                                version: version.to_owned(),
                                install_path: self.root.join("toolchains").join(version),
                                installed: true,
                                active: fields.next().is_some(),
                            },
                        ))
                    })
                    .collect()
            },
            Provider::Mise => {
                let listed = ManagerQuery::MiseInstalled.complete()?;
                Ok(ingress::mise_installations(&listed)?
                    .into_iter()
                    .flat_map(|(tool, versions)| {
                        versions
                            .into_iter()
                            .map(move |version| (tool.clone(), version))
                    })
                    .collect())
            },
            Provider::Docker => Err(io::Error::other("wrong toolchain provider")),
        }
    }
}

impl Port for Manager {
    fn survey(&mut self, roots: &[PathBuf]) -> io::Result<Survey> {
        let mut pins = pins(roots)?;
        let installed = self.installations(&mut pins)?;
        let mut prunable = BTreeSet::new();
        if self.provider == Provider::Mise {
            let result = ManagerQuery::MisePrunable.read()?;
            if !result.status.success() || !result.stderr.is_empty() {
                pins.completeness = Completeness::Incomplete;
                pins.warnings
                    .push(String::from_utf8_lossy(&result.stderr).into_owned());
            } else {
                for (tool, versions) in ingress::mise_installations(
                    &String::from_utf8(result.stdout).map_err(io::Error::other)?,
                )? {
                    for version in versions {
                        prunable.insert((tool.clone(), version.version));
                    }
                }
            }
        }
        let mut survey = Survey {
            scope: self.root.to_string_lossy().into_owned(),
            completeness: pins.completeness,
            inventory: Vec::new(),
            candidates: Vec::new(),
            warnings: pins.warnings,
        };
        for (tool, installation) in installed {
            if !installation.installed {
                continue;
            }
            let mut references = if installation.active
                || (self.provider == Provider::Mise
                    && (tool == "rust"
                        || !prunable.contains(&(tool.clone(), installation.version.clone()))))
            {
                References::Referenced
            } else {
                match self.provider {
                    Provider::Rustup => match rust_channel(&installation.version) {
                        Some(channel) => reference(&pins.versions, &tool, channel),
                        None => References::Unknown,
                    },
                    Provider::Mise => reference(&pins.versions, &tool, &installation.version),
                    Provider::Docker => return Err(io::Error::other("wrong toolchain provider")),
                }
            };
            let path = match absolute(&installation.install_path) {
                Ok(path) if path.starts_with(&self.root) => path,
                Ok(_) | Err(_) => {
                    references = References::Unknown;
                    installation.install_path.clone()
                },
            };
            let identity = platform::identity(&path)?;
            let scope = format!("{}:{}:{}", survey.scope, identity.volume, identity.file);
            let label = format!("{tool}@{}", installation.version);
            survey.inventory.push(ManagedUsage {
                resource: Resource::Toolchain,
                name: label.clone(),
                bytes: None,
                references,
                labels: vec![path.to_string_lossy().into_owned()],
            });
            survey.candidates.push(candidate(
                &scope,
                Resource::Toolchain,
                label,
                references,
                Action::Toolchain {
                    tool,
                    version: installation.version,
                    path,
                },
            )?);
        }
        Ok(survey)
    }

    fn remove(&mut self, action: &Action, clearance: &Clearance) -> io::Result<Option<Bytes>> {
        let Action::Toolchain {
            tool,
            version,
            path,
        } = action
        else {
            return Err(io::Error::other("wrong toolchain action"));
        };
        if clearance.resource() != Resource::Toolchain {
            return Err(io::Error::other("wrong toolchain capability"));
        }
        let identity = platform::identity(path)?;
        let scope = format!(
            "{}:{}:{}",
            self.root.to_string_lossy(),
            identity.volume,
            identity.file
        );
        let current = candidate(
            &scope,
            Resource::Toolchain,
            format!("{tool}@{version}"),
            References::Unused,
            action.clone(),
        )?;
        if &current.id != clearance.id() {
            return Err(io::Error::other(
                "the toolchain identity changed before removal",
            ));
        }
        platform::spawn::uninstall(&ToolchainRemoval {
            provider: self.provider,
            tool,
            version,
            clearance,
        })?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_checkouts_release_pins_and_directory_links_are_not_followed() {
        let temp = testkit::tempdir("managed-reference-roots");
        let root = temp.path().join("checkout");
        let foreign = temp.path().join("outside");
        testkit::write_bytes(
            &root.join("Cargo.toml"),
            b"[package]\nrust-version='1.98'\n",
        );
        testkit::write_bytes(&foreign.join("rust-toolchain"), b"1.84.0\n");
        if testkit::link_dir(&foreign, &root.join("linked"))
            .or_decline("a directory symbolic link")
            .is_none()
        {
            return;
        }
        let mut files = BTreeSet::new();
        collect(&root, &mut files).unwrap();
        assert_eq!(files, BTreeSet::from([root.join("Cargo.toml")]));
        collect(&temp.path().join("removed-checkout"), &mut files).unwrap();
        assert_eq!(files.len(), 1);
    }
}
