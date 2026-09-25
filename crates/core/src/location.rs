use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Syntax {
    Unix,
    Windows,
}

impl Syntax {
    pub const HOST: Self = if cfg!(windows) {
        Self::Windows
    } else {
        Self::Unix
    };

    const fn separator(self) -> char {
        match self {
            Self::Unix => '/',
            Self::Windows => '\\',
        }
    }

    const fn is_separator(self, byte: u8) -> bool {
        match self {
            Self::Unix => byte == b'/',
            Self::Windows => byte == b'/' || byte == b'\\',
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocationError {
    #[error("the path is not absolute")]
    Relative,
    #[error("the path contains `.` or `..` navigation")]
    Navigation,
    #[error("a path component is empty")]
    Empty,
    #[error("a path component contains a separator or NUL")]
    Separator,
    #[error("a UNC path names no share")]
    MissingShare,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(Vec<u8>);

impl Name {
    pub fn new(raw: &[u8], syntax: Syntax) -> Result<Self, LocationError> {
        match raw {
            [] => Err(LocationError::Empty),
            b"." | b".." => Err(LocationError::Navigation),
            _ if raw
                .iter()
                .any(|byte| *byte == 0 || syntax.is_separator(*byte)) =>
            {
                Err(LocationError::Separator)
            },
            _ => Ok(Self(raw.to_vec())),
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    #[must_use]
    pub fn folded(&self, case: Case) -> Vec<u8> {
        fold(&self.0, case)
    }

    #[must_use]
    pub fn matches(&self, literal: &str, case: Case) -> bool {
        self.folded(case) == fold(literal.as_bytes(), case)
    }
}

fn fold(raw: &[u8], case: Case) -> Vec<u8> {
    match case {
        Case::Sensitive => raw.to_vec(),
        Case::Insensitive => match core::str::from_utf8(raw) {
            Ok(text) => text.to_lowercase().into_bytes(),
            Err(_invalid) => raw.to_ascii_lowercase(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Root {
    Unix,
    Drive(u8),
    Unc { server: Name, share: Name },
}

impl Root {
    fn same(&self, other: &Self, case: Case) -> bool {
        match (self, other) {
            (Self::Unix, Self::Unix) => true,
            (Self::Drive(left), Self::Drive(right)) => left == right,
            (
                Self::Unc { server, share },
                Self::Unc {
                    server: other_server,
                    share: other_share,
                },
            ) => {
                server.folded(Case::Insensitive) == other_server.folded(Case::Insensitive)
                    && share.folded(case) == other_share.folded(case)
            },
            (Self::Unix | Self::Drive(_) | Self::Unc { .. }, _) => false,
        }
    }

    fn key(&self, case: Case, into: &mut Vec<u8>) {
        match self {
            Self::Unix => into.push(b'/'),
            Self::Drive(letter) => {
                into.push(*letter);
                into.extend_from_slice(b":\\");
            },
            Self::Unc { server, share } => {
                into.extend_from_slice(b"\\\\");
                into.extend(server.folded(Case::Insensitive));
                into.push(b'\\');
                into.extend(share.folded(case));
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Location(Box<Parts>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Parts {
    syntax: Syntax,
    root: Root,
    names: Vec<Name>,
}

impl Location {
    fn from_parts(syntax: Syntax, root: Root, names: Vec<Name>) -> Self {
        Self(Box::new(Parts {
            syntax,
            root,
            names,
        }))
    }

    pub fn parse(syntax: Syntax, raw: &[u8]) -> Result<Self, LocationError> {
        match syntax {
            Syntax::Unix => parse_unix(raw),
            Syntax::Windows => parse_windows(raw),
        }
    }

    pub fn parse_str(syntax: Syntax, raw: &str) -> Result<Self, LocationError> {
        Self::parse(syntax, raw.as_bytes())
    }

    #[must_use]
    pub const fn syntax(&self) -> Syntax {
        self.0.syntax
    }

    #[must_use]
    pub const fn root(&self) -> &Root {
        &self.0.root
    }

    #[must_use]
    pub fn names(&self) -> &[Name] {
        &self.0.names
    }

    #[must_use]
    pub fn file_name(&self) -> Option<&Name> {
        self.0.names.last()
    }

    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let (_, parent) = self.0.names.split_last()?;
        Some(Self::from_parts(
            self.0.syntax,
            self.0.root.clone(),
            parent.to_vec(),
        ))
    }

    #[must_use]
    pub fn join(&self, name: Name) -> Self {
        let mut names = self.0.names.clone();
        names.push(name);
        Self::from_parts(self.0.syntax, self.0.root.clone(), names)
    }

    pub fn child(&self, raw: &str) -> Result<Self, LocationError> {
        Ok(self.join(Name::new(raw.as_bytes(), self.0.syntax)?))
    }

    #[must_use]
    pub fn relative<'a>(&self, inner: &'a Self, case: Case) -> Option<&'a [Name]> {
        if self.0.syntax != inner.0.syntax || !self.0.root.same(&inner.0.root, case) {
            return None;
        }
        let (prefix, rest) = inner.0.names.split_at_checked(self.0.names.len())?;
        prefix
            .iter()
            .zip(&self.0.names)
            .all(|(left, right)| left.folded(case) == right.folded(case))
            .then_some(rest)
    }

    #[must_use]
    pub fn contains(&self, inner: &Self, case: Case) -> bool {
        self.relative(inner, case).is_some()
    }

    #[must_use]
    pub fn same(&self, other: &Self, case: Case) -> bool {
        self.relative(other, case).is_some_and(<[Name]>::is_empty)
    }

    #[must_use]
    pub fn key(&self, case: Case) -> Vec<u8> {
        let mut key = Vec::new();
        self.0.root.key(case, &mut key);
        for (index, name) in self.0.names.iter().enumerate() {
            if index > 0 {
                key.push(0);
            }
            key.extend(name.folded(case));
        }
        key
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let separator = self.0.syntax.separator();
        match &self.0.root {
            Root::Unix => f.write_str("/")?,
            Root::Drive(letter) => write!(f, "{}:\\", char::from(*letter))?,
            Root::Unc { server, share } => {
                write!(f, "\\\\{}\\{}", server.text(), share.text())?;
                if !self.0.names.is_empty() {
                    write!(f, "{separator}")?;
                }
            },
        }
        for (index, name) in self.0.names.iter().enumerate() {
            if index > 0 {
                write!(f, "{separator}")?;
            }
            f.write_str(&name.text())?;
        }
        Ok(())
    }
}

impl Serialize for Location {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn names(raw: &[u8], syntax: Syntax) -> Result<Vec<Name>, LocationError> {
    raw.split(|byte| syntax.is_separator(*byte))
        .filter(|part| !part.is_empty() && *part != b".")
        .map(|part| Name::new(part, syntax))
        .collect()
}

fn parse_unix(raw: &[u8]) -> Result<Location, LocationError> {
    let Some(rest) = raw.strip_prefix(b"/") else {
        return Err(LocationError::Relative);
    };
    Ok(Location::from_parts(
        Syntax::Unix,
        Root::Unix,
        names(rest, Syntax::Unix)?,
    ))
}

fn parse_windows(raw: &[u8]) -> Result<Location, LocationError> {
    for prefix in [br"\\?\UNC\", br"\\.\UNC\"] {
        if let Some(rest) = raw.strip_prefix(prefix.as_slice()) {
            return unc(rest);
        }
    }
    for prefix in [br"\\?\", br"\\.\"] {
        if let Some(rest) = raw.strip_prefix(prefix.as_slice()) {
            return drive(rest);
        }
    }
    match raw {
        [first, second, rest @ ..]
            if Syntax::Windows.is_separator(*first) && Syntax::Windows.is_separator(*second) =>
        {
            unc(rest)
        },
        _ => drive(raw),
    }
}

fn unc(rest: &[u8]) -> Result<Location, LocationError> {
    let mut parts = names(rest, Syntax::Windows)?.into_iter();
    let (Some(server), Some(share)) = (parts.next(), parts.next()) else {
        return Err(LocationError::MissingShare);
    };
    Ok(Location::from_parts(
        Syntax::Windows,
        Root::Unc { server, share },
        parts.collect(),
    ))
}

fn drive(raw: &[u8]) -> Result<Location, LocationError> {
    match raw {
        [letter, b':', separator, rest @ ..]
            if letter.is_ascii_alphabetic() && Syntax::Windows.is_separator(*separator) =>
        {
            Ok(Location::from_parts(
                Syntax::Windows,
                Root::Drive(letter.to_ascii_uppercase()),
                names(rest, Syntax::Windows)?,
            ))
        },
        [letter, b':'] if letter.is_ascii_alphabetic() => Ok(Location::from_parts(
            Syntax::Windows,
            Root::Drive(letter.to_ascii_uppercase()),
            Vec::new(),
        )),
        _ => Err(LocationError::Relative),
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn unix(raw: &str) -> Location {
        Location::parse_str(Syntax::Unix, raw).unwrap()
    }

    fn windows(raw: &str) -> Location {
        Location::parse_str(Syntax::Windows, raw).unwrap()
    }

    #[test]
    fn containment_is_by_component_not_by_text() {
        assert!(unix("/work").contains(&unix("/work/a"), Case::Sensitive));
        assert!(!unix("/work").contains(&unix("/worker"), Case::Sensitive));
        assert!(unix("/").contains(&unix("/anything"), Case::Sensitive));
        assert!(!unix("/work/a").contains(&unix("/work"), Case::Sensitive));
    }

    #[test]
    fn case_folding_applies_only_when_asked() {
        assert!(unix("/Work").contains(&unix("/work/a"), Case::Insensitive));
        assert!(!unix("/Work").contains(&unix("/work/a"), Case::Sensitive));
        assert!(windows(r"C:\Work").contains(&windows(r"c:\WORK\a"), Case::Insensitive));
    }

    #[test]
    fn windows_prefixes_and_separators_name_the_same_place() {
        let plain = windows(r"C:\Users\me");
        for other in [
            r"\\?\C:\Users\me",
            r"C:/Users/me",
            r"c:\Users\\me\",
            r"\\.\C:\Users\me",
        ] {
            assert!(plain.same(&windows(other), Case::Insensitive), "{other}");
        }
        let share = windows(r"\\server\share\dir");
        assert!(share.same(&windows(r"\\?\UNC\server\share\dir"), Case::Insensitive));
        assert!(!share.same(&windows(r"\\other\share\dir"), Case::Insensitive));
    }

    #[test]
    fn relative_and_navigating_paths_are_not_locations() {
        assert_eq!(
            Location::parse_str(Syntax::Unix, "work"),
            Err(LocationError::Relative)
        );
        assert_eq!(
            Location::parse_str(Syntax::Unix, "/a/../b"),
            Err(LocationError::Navigation)
        );
        assert_eq!(
            Location::parse_str(Syntax::Windows, r"\Users"),
            Err(LocationError::Relative)
        );
        assert_eq!(
            Location::parse_str(Syntax::Windows, r"C:Users"),
            Err(LocationError::Relative)
        );
        assert_eq!(
            Location::parse_str(Syntax::Windows, r"\\server"),
            Err(LocationError::MissingShare)
        );
    }

    #[test]
    fn a_name_cannot_smuggle_a_separator() {
        assert_eq!(
            Name::new(b"a/b", Syntax::Unix),
            Err(LocationError::Separator)
        );
        assert_eq!(
            Name::new(b"a\\b", Syntax::Windows),
            Err(LocationError::Separator)
        );
        Name::new(b"a\\b", Syntax::Unix).unwrap();
        assert_eq!(
            Name::new(b"..", Syntax::Unix),
            Err(LocationError::Navigation)
        );
    }

    #[test]
    fn a_location_renders_in_its_own_syntax() {
        assert_eq!(unix("/a//b/./c").to_string(), "/a/b/c");
        assert_eq!(unix("/").to_string(), "/");
        assert_eq!(windows(r"\\?\c:\a/b").to_string(), r"C:\a\b");
        assert_eq!(windows("C:").to_string(), r"C:\");
        assert_eq!(windows(r"\\srv\share\x").to_string(), r"\\srv\share\x");
    }

    #[test]
    fn parent_and_join_are_inverse() {
        let path = unix("/a/b");
        let name = path.file_name().unwrap().clone();
        assert_eq!(path.parent().unwrap().join(name), path);
        assert_eq!(unix("/").parent(), None);
    }

    #[test]
    fn non_unicode_names_are_kept_exactly() {
        let raw = b"/work/\xff\xfe";
        let path = Location::parse(Syntax::Unix, raw).unwrap();
        let other = Location::parse(Syntax::Unix, b"/work/\xff\xfd").unwrap();
        assert!(!path.same(&other, Case::Insensitive));
        assert_eq!(path.file_name().unwrap().as_bytes(), b"\xff\xfe");
    }
}
