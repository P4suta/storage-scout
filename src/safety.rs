//! Centralized cleanup safety invariants.
//!
//! Three independent gates decide whether a directory may ever be deleted:
//!
//! * [`Area`]: *where* it is. System areas refuse everything, opaque user
//!   areas admit only self-declared caches, everything else is open.
//! * [`Classification`]: *what* it is and *who says so*, re-derived from the
//!   live filesystem immediately before deletion.
//! * [`busy_reason`]: whether a running tool currently owns it.

use std::collections::HashSet;
use std::fs::{self, File, Metadata, TryLockError};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::artifact::{self, CACHE_TAG_NAME, CACHE_TAG_SIGNATURE, Evidence};
use crate::{ArtifactKind, Provenance};

/// Lock files Cargo holds for the duration of a build, found at a target root
/// and inside each profile directory.
const CARGO_LOCK_NAMES: [&str; 3] = [".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock"];

/// The kind and provenance of one authenticated directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Classification {
    pub kind: ArtifactKind,
    pub provenance: Provenance,
}

/// How much trust a location extends to candidates found within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Area {
    /// Never eligible: drive roots, the running binary, the current
    /// directory, Windows, Program Files, `ProgramData`, and profile roots.
    System(String),
    /// Application-owned data such as `AppData`, where directory names mean
    /// nothing but a directory's own cache declaration still does.
    UserOpaque(String),
    /// Ordinary project space.
    Open,
}

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
/// Opaque user areas are acceptable roots because every candidate found
/// there is still gated by its provenance.
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
    if let Area::System(reason) = area_of(&canonical) {
        return Err(format!(
            "refusing cleanup root {}: {reason}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// Return a reason when a directory with the given provenance is never
/// eligible for cleanup.
pub(crate) fn protected_reason(path: &Path, provenance: Provenance) -> Option<String> {
    match area_of(path) {
        Area::System(reason) => Some(reason),
        Area::UserOpaque(reason) if provenance == Provenance::Inferred => Some(format!(
            "{reason}; only self-declared caches are eligible there"
        )),
        Area::UserOpaque(_) | Area::Open => None,
    }
}

/// Classify the location of a directory.
pub(crate) fn area_of(path: &Path) -> Area {
    if normal_component_count(path) == 0 {
        return Area::System("drive/filesystem roots are protected".to_owned());
    }

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|value| fs::canonicalize(value).ok());
    if cwd.as_deref().is_some_and(|value| contains(path, value)) {
        return Area::System("it is the current directory or contains it".to_owned());
    }
    let executable = std::env::current_exe()
        .ok()
        .and_then(|value| fs::canonicalize(value).ok());
    if executable
        .as_deref()
        .is_some_and(|value| contains(path, value))
    {
        return Area::System("it contains the running storage-scout binary".to_owned());
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
            return Area::System(format!("the {label} system area is protected"));
        }
    }

    if let Some(profile) = env_canonical("USERPROFILE") {
        if normalized(&profile) == normalized(path) {
            return Area::System("a user-profile root is protected".to_owned());
        }
        let app_data = profile.join("AppData");
        if contains(&app_data, path) {
            return Area::UserOpaque("AppData is application-owned".to_owned());
        }
        if let Some(users) = profile.parent() {
            if normalized(users) == normalized(path) {
                return Area::System("the Users root is protected".to_owned());
            }
            if let Ok(relative) = path.strip_prefix(users) {
                let components = relative.components().collect::<Vec<_>>();
                if components.len() == 1 {
                    return Area::System("a user-profile root is protected".to_owned());
                }
                if components.get(1).is_some_and(|component| {
                    matches!(component, Component::Normal(name) if name.to_string_lossy().eq_ignore_ascii_case("AppData"))
                }) {
                    return Area::UserOpaque("AppData is application-owned".to_owned());
                }
            }
        }
    }
    Area::Open
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

/// Whether `directory` holds a `CACHEDIR.TAG` with the specification's
/// signature. `child_files` are the lowercase names already listed for it.
pub(crate) fn read_cache_tag(directory: &Path, child_files: &HashSet<String>) -> bool {
    if !child_files.contains(CACHE_TAG_NAME) {
        return false;
    }
    let Ok(mut file) = File::open(directory.join("CACHEDIR.TAG")) else {
        return false;
    };
    let mut header = [0u8; CACHE_TAG_SIGNATURE.len()];
    file.read_exact(&mut header).is_ok() && header == CACHE_TAG_SIGNATURE
}

/// Re-authenticate a known artifact using its current parent and child marker
/// files. This is called both during discovery and immediately before deletion.
pub(crate) fn classify_path(path: &Path) -> Result<Classification, String> {
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
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if file_type.is_file() {
            evidence.child_files.insert(name);
        } else if file_type.is_dir() && !file_type.is_symlink() {
            evidence.child_dirs.insert(name);
        }
    }
    evidence.cache_tag = read_cache_tag(path, &evidence.child_files);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "artifact name is not valid Unicode".to_owned())?;
    let kind = artifact::classify(name, &evidence).ok_or_else(|| {
        "current name/project evidence no longer identifies a known artifact".to_owned()
    })?;
    Ok(Classification {
        kind,
        provenance: artifact::provenance(&evidence),
    })
}

/// Return a reason when a running tool currently owns the artifact.
///
/// Cargo takes an exclusive file lock on its build-directory lock files for
/// the whole build; probing the same lock is exactly the mechanism a second
/// `cargo` invocation uses to wait ("Blocking waiting for file lock").
pub(crate) fn busy_reason(path: &Path, kind: ArtifactKind) -> Option<String> {
    match kind {
        ArtifactKind::RustTarget => cargo_lock_holder(path),
        _ => None,
    }
}

fn cargo_lock_holder(target: &Path) -> Option<String> {
    let profiles = fs::read_dir(target)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path());
    std::iter::once(target.to_path_buf())
        .chain(profiles)
        .flat_map(|directory| {
            CARGO_LOCK_NAMES
                .iter()
                .map(move |name| directory.join(name))
        })
        .find(|lock| is_locked_by_another_process(lock))
        .map(|lock| format!("a running cargo build holds {}", lock.display()))
}

fn is_locked_by_another_process(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        },
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(_)) => false,
    }
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

    fn tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(".storage-scout-safety-test-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap()
    }

    #[test]
    fn contains_is_case_insensitive_and_component_aware() {
        assert!(contains(Path::new(r"C:\Work"), Path::new(r"c:\work\a")));
        assert!(!contains(Path::new(r"C:\Work"), Path::new(r"C:\Worker")));
    }

    #[test]
    fn drive_roots_are_protected() {
        assert!(protected_reason(Path::new(r"C:\"), Provenance::Declared).is_some());
    }

    #[test]
    fn cwd_and_running_binary_are_protected() {
        let cwd = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert!(protected_reason(&cwd, Provenance::Declared).is_some());
        let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert!(protected_reason(executable.parent().unwrap(), Provenance::Declared).is_some());
    }

    #[test]
    fn app_data_admits_only_declared_caches_for_every_user_profile() {
        let profile = env_canonical("USERPROFILE").unwrap();
        let users = profile.parent().unwrap();
        let other_app_data = users.join("another-user/AppData/Local/cache");
        assert!(matches!(area_of(&other_app_data), Area::UserOpaque(_)));
        assert!(protected_reason(&other_app_data, Provenance::Inferred).is_some());
        assert!(protected_reason(&other_app_data, Provenance::Declared).is_none());

        let own_temp = profile.join("AppData/Local/Temp/sbt");
        assert!(protected_reason(&own_temp, Provenance::Inferred).is_some());
        assert!(protected_reason(&own_temp, Provenance::Declared).is_none());
        assert!(matches!(area_of(&profile), Area::System(_)));
    }

    #[test]
    fn cache_tag_requires_the_exact_signature() {
        let temp = tempdir();
        let names = HashSet::from(["cachedir.tag".to_owned()]);
        assert!(!read_cache_tag(temp.path(), &names));
        fs::write(temp.path().join("CACHEDIR.TAG"), b"Signature: nope").unwrap();
        assert!(!read_cache_tag(temp.path(), &names));
        fs::write(
            temp.path().join("CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n# created by cargo",
        )
        .unwrap();
        assert!(read_cache_tag(temp.path(), &names));
        assert!(!read_cache_tag(temp.path(), &HashSet::new()));
    }

    #[test]
    fn classify_path_reports_kind_and_provenance() {
        let temp = tempdir();
        let orphan = temp.path().join("sbt");
        fs::create_dir_all(orphan.join("debug")).unwrap();
        fs::write(orphan.join(".rustc_info.json"), b"{}").unwrap();
        assert_eq!(
            classify_path(&orphan).unwrap(),
            Classification {
                kind: ArtifactKind::RustTarget,
                provenance: Provenance::Declared,
            }
        );

        let project = temp.path().join("project");
        fs::create_dir_all(project.join("target")).unwrap();
        fs::write(project.join("Cargo.toml"), b"[package]").unwrap();
        assert_eq!(
            classify_path(&project.join("target")).unwrap(),
            Classification {
                kind: ArtifactKind::RustTarget,
                provenance: Provenance::Inferred,
            }
        );
        assert!(classify_path(&temp.path().join("missing")).is_err());
    }

    #[test]
    fn a_held_cargo_lock_marks_the_target_busy() {
        let temp = tempdir();
        let target = temp.path().join("target");
        fs::create_dir_all(target.join("debug")).unwrap();
        let lock_path = target.join("debug/.cargo-lock");
        fs::write(&lock_path, b"").unwrap();
        assert_eq!(busy_reason(&target, ArtifactKind::RustTarget), None);

        let holder = File::open(&lock_path).unwrap();
        holder.lock().unwrap();
        let reason = busy_reason(&target, ArtifactKind::RustTarget).unwrap();
        assert!(reason.contains(".cargo-lock"), "{reason}");
        assert_eq!(busy_reason(&target, ArtifactKind::NodeModules), None);

        holder.unlock().unwrap();
        assert_eq!(busy_reason(&target, ArtifactKind::RustTarget), None);
    }
}
