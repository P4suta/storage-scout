//! Centralized cleanup safety invariants.

use std::fs::{self, Metadata};
use std::path::{Component, Path, PathBuf};

use crate::ArtifactKind;
use crate::artifact::{self, Evidence};

/// Canonicalized exclusions. A missing path is retained as an absolute lexical
/// path so a requested protected child cannot be silently dropped.
pub(crate) fn canonical_excludes(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|path| {
            fs::canonicalize(path)
                .or_else(|_| std::path::absolute(path))
                .ok()
        })
        .collect()
}

pub(crate) fn is_excluded(path: &Path, excludes: &[PathBuf]) -> Option<PathBuf> {
    excludes
        .iter()
        .find(|exclude| contains(exclude, path) || contains(path, exclude))
        .cloned()
}

pub(crate) fn contains(outer: &Path, inner: &Path) -> bool {
    let outer = normalized(outer);
    let inner = normalized(inner);
    inner == outer
        || inner
            .strip_prefix(&outer)
            .is_some_and(|rest| rest.starts_with('\\'))
}

pub(crate) fn normalized(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\").to_lowercase();
    if let Some(without_prefix) = value.strip_prefix(r"\\?\") {
        value = without_prefix.to_owned();
    }
    while value.len() > 3 && value.ends_with('\\') {
        value.pop();
    }
    value
}

/// Validate a cleanup discovery root. Scanning has no such restriction;
/// cleanup deliberately refuses roots whose scope is too broad or sensitive.
pub(crate) fn validate_clean_root(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect cleanup root {}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "cleanup root is not a directory: {}",
            path.display()
        ));
    }
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(format!(
            "cleanup root is a symlink or reparse point: {}",
            path.display()
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize {}: {error}", path.display()))?;
    if let Some(reason) = protected_reason(&canonical) {
        return Err(format!(
            "refusing cleanup root {}: {reason}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// Return a reason when a directory is never eligible for cleanup.
pub(crate) fn protected_reason(path: &Path) -> Option<String> {
    if normal_component_count(path) == 0 {
        return Some("drive/filesystem roots are protected".to_owned());
    }

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|value| fs::canonicalize(value).ok());
    if cwd.as_deref().is_some_and(|value| contains(path, value)) {
        return Some("it is the current directory or contains it".to_owned());
    }
    let executable = std::env::current_exe()
        .ok()
        .and_then(|value| fs::canonicalize(value).ok());
    if executable
        .as_deref()
        .is_some_and(|value| contains(path, value))
    {
        return Some("it contains the running storage-scout binary".to_owned());
    }

    for (label, variable) in [
        ("Windows", "SystemRoot"),
        ("Program Files", "ProgramFiles"),
        ("Program Files (x86)", "ProgramFiles(x86)"),
        ("Program Files", "ProgramW6432"),
        ("ProgramData", "ProgramData"),
    ] {
        if let Some(protected) = env_canonical(variable)
            && contains(&protected, path)
        {
            return Some(format!("the {label} system area is protected"));
        }
    }

    if let Some(profile) = env_canonical("USERPROFILE") {
        if normalized(&profile) == normalized(path) {
            return Some("a user-profile root is protected".to_owned());
        }
        let app_data = profile.join("AppData");
        if contains(&app_data, path) {
            return Some("AppData is protected".to_owned());
        }
        if let Some(users) = profile.parent() {
            if normalized(users) == normalized(path) {
                return Some("the Users root is protected".to_owned());
            }
            if let Ok(relative) = path.strip_prefix(users) {
                let components = relative.components().collect::<Vec<_>>();
                if components.len() == 1 {
                    return Some("a user-profile root is protected".to_owned());
                }
                if components.get(1).is_some_and(|component| {
                    matches!(component, Component::Normal(name) if name.to_string_lossy().eq_ignore_ascii_case("AppData"))
                }) {
                    return Some("AppData is protected".to_owned());
                }
            }
        }
    }
    None
}

fn env_canonical(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok())
}

fn normal_component_count(path: &Path) -> usize {
    path.components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count()
}

/// Re-authenticate a known artifact using its current parent and child marker
/// files. This is called both during discovery and immediately before deletion.
pub(crate) fn classify_path(path: &Path) -> Result<ArtifactKind, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "artifact has no parent directory".to_owned())?;
    let mut evidence = Evidence::default();
    let parent_entries = fs::read_dir(parent)
        .map_err(|error| format!("cannot read parent {}: {error}", parent.display()))?;
    for entry in parent_entries {
        let entry = entry.map_err(|error| format!("cannot read parent entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if file_type.is_file() {
            evidence.parent_files.insert(name);
        } else if file_type.is_dir() && !file_type.is_symlink() {
            evidence.parent_dirs.insert(name);
        }
    }
    let child_entries = fs::read_dir(path)
        .map_err(|error| format!("cannot read artifact {}: {error}", path.display()))?;
    for entry in child_entries {
        let entry = entry.map_err(|error| format!("cannot read artifact entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if file_type.is_file() {
            evidence
                .child_files
                .insert(entry.file_name().to_string_lossy().to_ascii_lowercase());
        }
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "artifact name is not valid Unicode".to_owned())?;
    artifact::classify(name, &evidence).ok_or_else(|| {
        "current name/project evidence no longer identifies a known artifact".to_owned()
    })
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) const fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_is_case_insensitive_and_component_aware() {
        assert!(contains(Path::new(r"C:\Work"), Path::new(r"c:\work\a")));
        assert!(!contains(Path::new(r"C:\Work"), Path::new(r"C:\Worker")));
    }

    #[test]
    fn drive_roots_are_protected() {
        assert!(protected_reason(Path::new(r"C:\")).is_some());
    }

    #[test]
    fn cwd_and_running_binary_are_protected() {
        let cwd = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert!(protected_reason(&cwd).is_some());
        let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert!(protected_reason(executable.parent().unwrap()).is_some());
    }

    #[test]
    fn app_data_is_protected_for_every_user_profile() {
        let profile = env_canonical("USERPROFILE").unwrap();
        let users = profile.parent().unwrap();
        let other_app_data = users.join("another-user/AppData/Local/cache");
        assert!(protected_reason(&other_app_data).is_some());
    }
}
