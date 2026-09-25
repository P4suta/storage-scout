use alloc::collections::BTreeSet;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::location::Name;
use crate::lock::Protocol;

pub const CACHE_TAG_NAME: &str = "CACHEDIR.TAG";
pub const CACHE_TAG_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
const RUSTC_INFO_NAME: &str = ".rustc_info.json";

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum Kind {
        RustTarget,
        DotNetOutput,
        SolutionBuild,
        VisualStudioCache,
        GradleOutput,
        MavenTarget,
        JsOutput,
        PythonCache,
        CmakeOutput,
        NodeModules,
        PythonVenv,
        UnityOutput,
        TaggedCache,
        OwnedScratch,
        OwnedCache,
    }
}

impl Kind {
    #[must_use]
    pub const fn protocol(self) -> Option<Protocol> {
        match self {
            Self::RustTarget => Some(Protocol::Cargo),
            Self::OwnedScratch | Self::OwnedCache => Some(Protocol::TempOwner),
            Self::DotNetOutput
            | Self::SolutionBuild
            | Self::VisualStudioCache
            | Self::GradleOutput
            | Self::MavenTarget
            | Self::JsOutput
            | Self::PythonCache
            | Self::CmakeOutput
            | Self::NodeModules
            | Self::PythonVenv
            | Self::UnityOutput
            | Self::TaggedCache => None,
        }
    }

    #[must_use]
    pub const fn tier(self) -> Tier {
        match self {
            Self::NodeModules | Self::PythonVenv | Self::TaggedCache => Tier::Reinstallable,
            Self::UnityOutput => Tier::Expensive,
            Self::RustTarget
            | Self::DotNetOutput
            | Self::SolutionBuild
            | Self::VisualStudioCache
            | Self::GradleOutput
            | Self::MavenTarget
            | Self::JsOutput
            | Self::PythonCache
            | Self::CmakeOutput
            | Self::OwnedScratch
            | Self::OwnedCache => Tier::Routine,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RustTarget => "Rust target",
            Self::DotNetOutput => ".NET bin/obj",
            Self::SolutionBuild => "solution build",
            Self::VisualStudioCache => "Visual Studio .vs",
            Self::GradleOutput => "Gradle output",
            Self::MavenTarget => "Maven target",
            Self::JsOutput => "JS build output",
            Self::PythonCache => "Python cache",
            Self::CmakeOutput => "CMake output",
            Self::NodeModules => "node_modules",
            Self::PythonVenv => "Python venv",
            Self::UnityOutput => "Unity output",
            Self::TaggedCache => "CACHEDIR.TAG cache",
            Self::OwnedScratch => "owned scratch",
            Self::OwnedCache => "owned cache",
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustTarget => "rust-target",
            Self::DotNetOutput => "dotnet-output",
            Self::SolutionBuild => "solution-build",
            Self::VisualStudioCache => "visual-studio-cache",
            Self::GradleOutput => "gradle-output",
            Self::MavenTarget => "maven-target",
            Self::JsOutput => "js-output",
            Self::PythonCache => "python-cache",
            Self::CmakeOutput => "cmake-output",
            Self::NodeModules => "node-modules",
            Self::PythonVenv => "python-venv",
            Self::UnityOutput => "unity-output",
            Self::TaggedCache => "tagged-cache",
            Self::OwnedScratch => "owned-scratch",
            Self::OwnedCache => "owned-cache",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown artifact kind")]
pub struct UnknownKind;

impl FromStr for Kind {
    type Err = UnknownKind;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str().eq_ignore_ascii_case(value))
            .ok_or(UnknownKind)
    }
}

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum Tier {
        Routine,
        Reinstallable,
        Expensive,
    }
}

impl Tier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::Reinstallable => "reinstallable",
            Self::Expensive => "expensive",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown risk tier")]
pub struct UnknownTier;

impl FromStr for Tier {
    type Err = UnknownTier;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|tier| tier.as_str().eq_ignore_ascii_case(value))
            .ok_or(UnknownTier)
    }
}

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum Provenance {
        Declared,
        Inferred,
    }
}

impl Provenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Inferred => "inferred",
        }
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheTag {
    Absent,
    Verified,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerTag {
    Absent,
    Scratch,
    Cache,
    Foreign,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tags {
    pub cache: CacheTag,
    pub owner: OwnerTag,
}

impl Tags {
    #[must_use]
    pub const fn cache(cache: CacheTag) -> Self {
        Self {
            cache,
            owner: OwnerTag::Absent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    parent_files: BTreeSet<String>,
    parent_dirs: BTreeSet<String>,
    child_files: BTreeSet<String>,
    child_dirs: BTreeSet<String>,
    tags: Tags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Identification {
    pub kind: Kind,
    pub provenance: Provenance,
}

impl Listing {
    #[must_use]
    pub fn new(parent: Entries, child: Entries, tags: Tags) -> Self {
        Self {
            parent_files: parent.files,
            parent_dirs: parent.dirs,
            child_files: child.files,
            child_dirs: child.dirs,
            tags,
        }
    }

    #[must_use]
    pub const fn tags(&self) -> &Tags {
        &self.tags
    }

    #[must_use]
    pub fn identify(&self, name: &Name) -> Option<Identification> {
        let kind = self.kind(name)?;
        let provenance = if matches!(self.tags.cache, CacheTag::Verified)
            || matches!(self.tags.owner, OwnerTag::Scratch | OwnerTag::Cache)
            || self.declares_rust_target()
        {
            Provenance::Declared
        } else {
            Provenance::Inferred
        };
        Some(Identification { kind, provenance })
    }

    fn kind(&self, name: &Name) -> Option<Kind> {
        let name = String::from_utf8_lossy(name.as_bytes()).to_ascii_lowercase();
        let files = &self.parent_files;
        let dirs = &self.parent_dirs;
        let child = &self.child_files;

        match self.tags.owner {
            OwnerTag::Scratch => return Some(Kind::OwnedScratch),
            OwnerTag::Cache => return Some(Kind::OwnedCache),
            OwnerTag::Absent | OwnerTag::Foreign => {},
        }
        if self.declares_rust_target() {
            return Some(Kind::RustTarget);
        }
        if dirs.contains("assets")
            && dirs.contains("projectsettings")
            && matches!(name.as_str(), "library" | "temp" | "obj")
        {
            return Some(Kind::UnityOutput);
        }
        if name == "target" && files.contains("cargo.toml") {
            return Some(Kind::RustTarget);
        }
        if name == "target" && files.contains("pom.xml") {
            return Some(Kind::MavenTarget);
        }
        if matches!(name.as_str(), "bin" | "obj")
            && any_extension(files, &["csproj", "fsproj", "vbproj", "vcxproj", "proj"])
        {
            return Some(Kind::DotNetOutput);
        }
        if name == ".vs" && any_extension(files, &["sln", "slnx"]) {
            return Some(Kind::VisualStudioCache);
        }
        if matches!(name.as_str(), "build" | ".gradle")
            && files.iter().any(|file| {
                matches!(
                    file.as_str(),
                    "build.gradle"
                        | "build.gradle.kts"
                        | "settings.gradle"
                        | "settings.gradle.kts"
                        | "gradlew"
                        | "gradlew.bat"
                )
            })
        {
            return Some(Kind::GradleOutput);
        }
        if (name == "build" || name.starts_with("cmake-build-") || name == "out")
            && child.contains("cmakecache.txt")
        {
            return Some(Kind::CmakeOutput);
        }
        if name == "build" && any_extension(files, &["sln", "slnx"]) {
            return Some(Kind::SolutionBuild);
        }
        if matches!(
            name.as_str(),
            "dist" | "build" | "out" | ".next" | ".nuxt" | ".turbo" | "coverage"
        ) && files.contains("package.json")
        {
            return Some(Kind::JsOutput);
        }
        let python = any_extension(files, &["py"])
            || files.iter().any(|file| {
                matches!(
                    file.as_str(),
                    "pyproject.toml"
                        | "requirements.txt"
                        | "setup.py"
                        | "setup.cfg"
                        | "pipfile"
                        | "poetry.lock"
                )
            });
        if matches!(
            name.as_str(),
            "__pycache__" | ".mypy_cache" | ".pytest_cache" | ".ruff_cache" | ".tox"
        ) && python
        {
            return Some(Kind::PythonCache);
        }
        if name == "node_modules" && files.contains("package.json") {
            return Some(Kind::NodeModules);
        }
        if matches!(name.as_str(), ".venv" | "venv") && python && child.contains("pyvenv.cfg") {
            return Some(Kind::PythonVenv);
        }
        match self.tags.cache {
            CacheTag::Verified => Some(Kind::TaggedCache),
            CacheTag::Absent | CacheTag::Invalid => None,
        }
    }

    fn declares_rust_target(&self) -> bool {
        self.child_files.contains(RUSTC_INFO_NAME)
            && (self.child_dirs.contains("debug") || self.child_dirs.contains("release"))
    }
}

fn any_extension(files: &BTreeSet<String>, extensions: &[&str]) -> bool {
    files.iter().any(|file| {
        file.rsplit_once('.')
            .is_some_and(|(stem, extension)| !stem.is_empty() && extensions.contains(&extension))
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entries {
    files: BTreeSet<String>,
    dirs: BTreeSet<String>,
}

impl Entries {
    pub fn file(&mut self, name: &[u8]) {
        self.files.insert(lower(name));
    }

    pub fn dir(&mut self, name: &[u8]) {
        self.dirs.insert(lower(name));
    }

    #[must_use]
    pub fn has_file(&self, name: &str) -> bool {
        self.files.contains(&name.to_ascii_lowercase())
    }
}

fn lower(name: &[u8]) -> String {
    String::from_utf8_lossy(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::location::Syntax;

    fn entries(files: &[&str], dirs: &[&str]) -> Entries {
        let mut entries = Entries::default();
        for file in files {
            entries.file(file.as_bytes());
        }
        for dir in dirs {
            entries.dir(dir.as_bytes());
        }
        entries
    }

    fn identify(
        name: &str,
        parent: Entries,
        child: Entries,
        tag: CacheTag,
    ) -> Option<Identification> {
        Listing::new(parent, child, Tags::cache(tag))
            .identify(&Name::new(name.as_bytes(), Syntax::Unix).unwrap())
    }

    #[test]
    fn a_name_alone_is_never_enough() {
        for name in [
            "target",
            "node_modules",
            "build",
            "bin",
            ".venv",
            "__pycache__",
        ] {
            assert_eq!(
                identify(
                    name,
                    Entries::default(),
                    Entries::default(),
                    CacheTag::Absent
                ),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn a_manifest_turns_a_name_into_an_inferred_artifact() {
        let target = identify(
            "target",
            entries(&["Cargo.toml"], &[]),
            Entries::default(),
            CacheTag::Absent,
        );
        assert_eq!(
            target,
            Some(Identification {
                kind: Kind::RustTarget,
                provenance: Provenance::Inferred
            })
        );
        let modules = identify(
            "node_modules",
            entries(&["package.json"], &[]),
            Entries::default(),
            CacheTag::Absent,
        );
        assert_eq!(modules.map(|found| found.kind), Some(Kind::NodeModules));
    }

    #[test]
    fn cargo_declares_a_target_wherever_it_lives() {
        let found = identify(
            "anything",
            Entries::default(),
            entries(&[".rustc_info.json"], &["debug"]),
            CacheTag::Absent,
        );
        assert_eq!(
            found,
            Some(Identification {
                kind: Kind::RustTarget,
                provenance: Provenance::Declared
            })
        );
        assert_eq!(
            identify(
                "anything",
                Entries::default(),
                entries(&[".rustc_info.json"], &[]),
                CacheTag::Absent
            ),
            None
        );
    }

    #[test]
    fn only_a_verified_tag_declares_a_cache() {
        let found = identify(
            "blobs",
            Entries::default(),
            Entries::default(),
            CacheTag::Verified,
        );
        assert_eq!(
            found,
            Some(Identification {
                kind: Kind::TaggedCache,
                provenance: Provenance::Declared
            })
        );
        assert_eq!(
            identify(
                "blobs",
                Entries::default(),
                Entries::default(),
                CacheTag::Invalid
            ),
            None
        );
    }

    #[test]
    fn a_cmake_tree_is_any_of_three_names_plus_its_cache_file() {
        for name in ["build", "cmake-build-debug", "out"] {
            let found = identify(
                name,
                Entries::default(),
                entries(&["CMakeCache.txt"], &[]),
                CacheTag::Absent,
            );
            assert_eq!(
                found.map(|found| found.kind),
                Some(Kind::CmakeOutput),
                "{name}"
            );
        }
    }

    #[test]
    fn an_extension_needs_a_stem() {
        assert_eq!(
            identify(
                "bin",
                entries(&[".csproj"], &[]),
                Entries::default(),
                CacheTag::Absent
            ),
            None
        );
        let found = identify(
            "bin",
            entries(&["app.csproj"], &[]),
            Entries::default(),
            CacheTag::Absent,
        );
        assert_eq!(found.map(|found| found.kind), Some(Kind::DotNetOutput));
    }

    #[test]
    fn every_kind_has_a_distinct_spelling_that_parses_back() {
        for kind in Kind::ALL {
            assert_eq!(kind.as_str().parse::<Kind>(), Ok(*kind));
        }
        for tier in Tier::ALL {
            assert_eq!(tier.as_str().parse::<Tier>(), Ok(*tier));
        }
    }

    #[test]
    fn an_owner_marker_declares_its_directory() {
        let listing = Listing::new(
            Entries::default(),
            Entries::default(),
            Tags {
                cache: CacheTag::Absent,
                owner: OwnerTag::Scratch,
            },
        );
        let identified = listing
            .identify(&Name::new(b"run", Syntax::Unix).unwrap())
            .unwrap();
        assert_eq!(identified.kind, Kind::OwnedScratch);
        assert_eq!(identified.provenance, Provenance::Declared);
    }

    #[test]
    fn a_unity_folder_needs_both_project_folders_and_its_own_name() {
        let unity = entries(&[], &["Assets", "ProjectSettings"]);
        for (parent, name, expected) in [
            (unity.clone(), "Library", Some(Kind::UnityOutput)),
            (entries(&[], &["Assets"]), "Library", None),
            (entries(&[], &["ProjectSettings"]), "Library", None),
            (unity, "Packages", None),
        ] {
            assert_eq!(
                identify(name, parent, Entries::default(), CacheTag::Absent)
                    .map(|found| found.kind),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn a_virtual_environment_needs_a_python_project_and_its_own_config() {
        let config = entries(&["pyvenv.cfg"], &[]);
        for (parent, child, expected) in [
            (
                entries(&["pyproject.toml"], &[]),
                config.clone(),
                Some(Kind::PythonVenv),
            ),
            (entries(&["pyproject.toml"], &[]), Entries::default(), None),
            (Entries::default(), config, None),
        ] {
            assert_eq!(
                identify(".venv", parent, child, CacheTag::Absent).map(|found| found.kind),
                expected
            );
        }
    }

    #[test]
    fn a_listing_holds_only_the_files_it_was_given() {
        let listing = entries(&["Cargo.toml"], &["src"]);
        assert!(listing.has_file("cargo.toml"));
        assert!(!listing.has_file("src"));
        assert!(!listing.has_file("pom.xml"));
    }
}
