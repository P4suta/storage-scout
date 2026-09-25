use alloc::vec::Vec;
use core::fmt;

use serde::Serialize;

use crate::location::{Case, Location, Syntax};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SystemReason {
    FilesystemRoot,
    CurrentDirectory,
    RunningBinary,
    SystemArea { label: &'static str },
    ProfileRoot,
    UsersRoot,
    VolumeRoot,
}

impl fmt::Display for SystemReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FilesystemRoot => f.write_str("drive/filesystem roots are protected"),
            Self::CurrentDirectory => f.write_str("it is the current directory or contains it"),
            Self::RunningBinary => f.write_str("it contains the running storage-scout binary"),
            Self::SystemArea { label } => write!(f, "the {label} system area is protected"),
            Self::ProfileRoot => f.write_str("a user-profile root is protected"),
            Self::UsersRoot => f.write_str("the user-profiles root is protected"),
            Self::VolumeRoot => f.write_str("a volume mount point is protected"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct AppOwned {
    pub label: &'static str,
}

impl fmt::Display for AppOwned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is application-owned", self.label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    System(SystemReason),
    AppOwned(AppOwned),
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "trust", rename_all = "kebab-case")]
pub enum Class {
    System { reason: SystemReason },
    AppOwned { area: AppOwned },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "scope", content = "name", rename_all = "kebab-case")]
pub enum Reach {
    Subtree,
    Exact,
    EachChild,
    EachChildSubtree(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    pub class: Class,
    pub anchor: Location,
    pub reach: Reach,
}

impl Rule {
    #[must_use]
    pub const fn system(reason: SystemReason, anchor: Location, reach: Reach) -> Self {
        Self {
            class: Class::System { reason },
            anchor,
            reach,
        }
    }

    #[must_use]
    pub const fn app_owned(label: &'static str, anchor: Location, reach: Reach) -> Self {
        Self {
            class: Class::AppOwned {
                area: AppOwned { label },
            },
            anchor,
            reach,
        }
    }

    #[must_use]
    pub fn reaches(&self, location: &Location, case: Case) -> bool {
        let Some(rest) = self.anchor.relative(location, case) else {
            return false;
        };
        match self.reach {
            Reach::Subtree => true,
            Reach::Exact => rest.is_empty(),
            Reach::EachChild => rest.len() == 1,
            Reach::EachChildSubtree(name) => {
                rest.get(1).is_some_and(|second| second.matches(name, case))
            },
        }
    }

    #[must_use]
    pub const fn area(&self) -> Area {
        match self.class {
            Class::System { reason } => Area::System(reason),
            Class::AppOwned { area } => Area::AppOwned(area),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    syntax: Syntax,
    case: Case,
    cwd: Location,
    exe: Location,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtectionError {
    #[error("the current directory is not a {0:?} location")]
    CurrentDirectory(Syntax),
    #[error("the running binary is not a {0:?} location")]
    Executable(Syntax),
    #[error("a protected-area rule is not a {0:?} location")]
    Rule(Syntax),
}

impl Protection {
    pub fn new(
        syntax: Syntax,
        case: Case,
        cwd: Location,
        exe: Location,
        rules: Vec<Rule>,
    ) -> Result<Self, ProtectionError> {
        if cwd.syntax() != syntax {
            return Err(ProtectionError::CurrentDirectory(syntax));
        }
        if exe.syntax() != syntax {
            return Err(ProtectionError::Executable(syntax));
        }
        if rules.iter().any(|rule| rule.anchor.syntax() != syntax) {
            return Err(ProtectionError::Rule(syntax));
        }
        Ok(Self {
            syntax,
            case,
            cwd,
            exe,
            rules,
        })
    }

    #[must_use]
    pub const fn syntax(&self) -> Syntax {
        self.syntax
    }

    #[must_use]
    pub const fn case(&self) -> Case {
        self.case
    }

    #[must_use]
    pub const fn cwd(&self) -> &Location {
        &self.cwd
    }

    #[must_use]
    pub const fn exe(&self) -> &Location {
        &self.exe
    }

    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    #[must_use]
    pub fn area_of(&self, location: &Location) -> Area {
        if location.syntax() != self.syntax || location.names().is_empty() {
            return Area::System(SystemReason::FilesystemRoot);
        }
        if location.contains(&self.cwd, self.case) {
            return Area::System(SystemReason::CurrentDirectory);
        }
        if location.contains(&self.exe, self.case) {
            return Area::System(SystemReason::RunningBinary);
        }
        self.rules
            .iter()
            .find(|rule| rule.reaches(location, self.case))
            .map_or(Area::Open, Rule::area)
    }

    #[must_use]
    pub fn contains(&self, outer: &Location, inner: &Location) -> bool {
        outer.contains(inner, self.case)
    }

    #[must_use]
    pub fn intersects(&self, left: &Location, right: &Location) -> bool {
        self.contains(left, right) || self.contains(right, left)
    }
}
