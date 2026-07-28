//! Pure build-artifact classification rules.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::RiskTier;

/// A recognized build-artifact family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// Cargo's `target` directory.
    RustTarget,
    /// .NET/MSBuild `bin` and `obj` directories.
    DotNetOutput,
    /// A solution-adjacent `build` directory.
    SolutionBuild,
    /// Visual Studio's `.vs` directory.
    VisualStudioCache,
    /// Gradle `build` and `.gradle` output.
    GradleOutput,
    /// Maven's `target` directory.
    MavenTarget,
    /// JavaScript framework/bundler output.
    JsOutput,
    /// Python bytecode and tool caches.
    PythonCache,
    /// A `CMake` build tree containing `CMakeCache.txt`.
    CmakeOutput,
    /// Dependency installation under `node_modules`.
    NodeModules,
    /// A Python virtual environment.
    PythonVenv,
    /// Unity `Library`, `Temp`, or `obj` output.
    UnityOutput,
}

pub(crate) const ALL_KINDS: [ArtifactKind; 12] = [
    ArtifactKind::RustTarget,
    ArtifactKind::DotNetOutput,
    ArtifactKind::SolutionBuild,
    ArtifactKind::VisualStudioCache,
    ArtifactKind::GradleOutput,
    ArtifactKind::MavenTarget,
    ArtifactKind::JsOutput,
    ArtifactKind::PythonCache,
    ArtifactKind::CmakeOutput,
    ArtifactKind::NodeModules,
    ArtifactKind::PythonVenv,
    ArtifactKind::UnityOutput,
];

impl ArtifactKind {
    /// The risk tier assigned to this family.
    #[must_use]
    pub const fn tier(self) -> RiskTier {
        match self {
            Self::NodeModules | Self::PythonVenv => RiskTier::Reinstallable,
            Self::UnityOutput => RiskTier::Expensive,
            _ => RiskTier::Routine,
        }
    }

    /// A compact human-readable label.
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
        }
    }

    /// Stable command-line spelling.
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
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ArtifactKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ALL_KINDS
            .into_iter()
            .find(|kind| kind.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| format!("unknown artifact kind: {value}"))
    }
}

/// Immediate evidence around a possible artifact directory. All names are
/// normalized to lowercase before classification.
#[derive(Debug, Default)]
pub(crate) struct Evidence {
    pub parent_files: HashSet<String>,
    pub parent_dirs: HashSet<String>,
    pub child_files: HashSet<String>,
}

/// Classify a directory only when its name and independent project evidence
/// agree. The ordering resolves intentionally overlapping names such as
/// `target`, `build`, and `obj`.
#[must_use]
pub(crate) fn classify(name: &str, evidence: &Evidence) -> Option<ArtifactKind> {
    let name = name.to_ascii_lowercase();
    let files = &evidence.parent_files;
    let dirs = &evidence.parent_dirs;
    let child = &evidence.child_files;

    if is_unity_project(dirs) && matches!(name.as_str(), "library" | "temp" | "obj") {
        return Some(ArtifactKind::UnityOutput);
    }
    if name == "target" && files.contains("cargo.toml") {
        return Some(ArtifactKind::RustTarget);
    }
    if name == "target" && files.contains("pom.xml") {
        return Some(ArtifactKind::MavenTarget);
    }
    if matches!(name.as_str(), "bin" | "obj") && has_project_file(files) {
        return Some(ArtifactKind::DotNetOutput);
    }
    if name == ".vs" && has_solution(files) {
        return Some(ArtifactKind::VisualStudioCache);
    }
    if matches!(name.as_str(), "build" | ".gradle") && has_gradle(files) {
        return Some(ArtifactKind::GradleOutput);
    }
    if (name == "build" || name.starts_with("cmake-build-") || name == "out")
        && child.contains("cmakecache.txt")
    {
        return Some(ArtifactKind::CmakeOutput);
    }
    if name == "build" && has_solution(files) {
        return Some(ArtifactKind::SolutionBuild);
    }
    if matches!(
        name.as_str(),
        "dist" | "build" | "out" | ".next" | ".nuxt" | ".turbo" | "coverage"
    ) && files.contains("package.json")
    {
        return Some(ArtifactKind::JsOutput);
    }
    if matches!(
        name.as_str(),
        "__pycache__" | ".mypy_cache" | ".pytest_cache" | ".ruff_cache" | ".tox"
    ) && has_python(files)
    {
        return Some(ArtifactKind::PythonCache);
    }
    if name == "node_modules" && files.contains("package.json") {
        return Some(ArtifactKind::NodeModules);
    }
    if matches!(name.as_str(), ".venv" | "venv")
        && has_python(files)
        && child.contains("pyvenv.cfg")
    {
        return Some(ArtifactKind::PythonVenv);
    }
    None
}

fn has_project_file(files: &HashSet<String>) -> bool {
    files.iter().any(|name| {
        matches!(
            name.rsplit_once('.').map(|(_, ext)| ext),
            Some("csproj" | "fsproj" | "vbproj" | "vcxproj" | "proj")
        )
    })
}

fn has_solution(files: &HashSet<String>) -> bool {
    files.iter().any(|name| {
        std::path::Path::new(name)
            .extension()
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("sln") || extension.eq_ignore_ascii_case("slnx")
            })
    })
}

fn has_gradle(files: &HashSet<String>) -> bool {
    files.iter().any(|name| {
        matches!(
            name.as_str(),
            "build.gradle"
                | "build.gradle.kts"
                | "settings.gradle"
                | "settings.gradle.kts"
                | "gradlew"
                | "gradlew.bat"
        )
    })
}

fn has_python(files: &HashSet<String>) -> bool {
    files.iter().any(|name| {
        std::path::Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("py"))
            || matches!(
                name.as_str(),
                "pyproject.toml"
                    | "requirements.txt"
                    | "setup.py"
                    | "setup.cfg"
                    | "pipfile"
                    | "poetry.lock"
            )
    })
}

fn is_unity_project(dirs: &HashSet<String>) -> bool {
    dirs.contains("assets") && dirs.contains("projectsettings")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(parent_files: &[&str], parent_dirs: &[&str], child_files: &[&str]) -> Evidence {
        Evidence {
            parent_files: parent_files.iter().map(|s| (*s).to_owned()).collect(),
            parent_dirs: parent_dirs.iter().map(|s| (*s).to_owned()).collect(),
            child_files: child_files.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn ambiguous_names_require_the_right_evidence() {
        assert_eq!(
            classify("target", &evidence(&["cargo.toml"], &[], &[])),
            Some(ArtifactKind::RustTarget)
        );
        assert_eq!(
            classify("target", &evidence(&["pom.xml"], &[], &[])),
            Some(ArtifactKind::MavenTarget)
        );
        assert_eq!(classify("target", &Evidence::default()), None);
        assert_eq!(classify("build", &Evidence::default()), None);
    }

    #[test]
    fn detects_solution_dotnet_cmake_and_unity_outputs() {
        assert_eq!(
            classify("bin", &evidence(&["app.csproj"], &[], &[])),
            Some(ArtifactKind::DotNetOutput)
        );
        assert_eq!(
            classify("build", &evidence(&["app.slnx"], &[], &[])),
            Some(ArtifactKind::SolutionBuild)
        );
        assert_eq!(
            classify("build", &evidence(&[], &[], &["cmakecache.txt"])),
            Some(ArtifactKind::CmakeOutput)
        );
        assert_eq!(
            classify(
                "Library",
                &evidence(&[], &["assets", "projectsettings"], &[])
            ),
            Some(ArtifactKind::UnityOutput)
        );
    }

    #[test]
    fn risk_tiers_are_conservative() {
        assert_eq!(ArtifactKind::RustTarget.tier(), RiskTier::Routine);
        assert_eq!(ArtifactKind::NodeModules.tier(), RiskTier::Reinstallable);
        assert_eq!(ArtifactKind::UnityOutput.tier(), RiskTier::Expensive);
    }
}
