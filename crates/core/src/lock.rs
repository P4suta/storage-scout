use core::fmt;

use serde::Serialize;

use crate::location::Location;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Cargo,
    TempOwner,
}

impl Protocol {
    pub const CARGO_NAMES: [&'static str; 3] =
        [".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock"];
    pub const TEMP_OWNER_NAME: &'static str = "owner.lock";

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::TempOwner => "owner.lock",
        }
    }

    #[must_use]
    pub fn of(name: &[u8]) -> Option<Self> {
        if Self::CARGO_NAMES
            .iter()
            .any(|cargo| cargo.as_bytes() == name)
        {
            Some(Self::Cargo)
        } else if name == Self::TEMP_OWNER_NAME.as_bytes() {
            Some(Self::TempOwner)
        } else {
            None
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cargo => "a running build",
            Self::TempOwner => "its owner",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Liveness {
    Free,
    Held { lock: Location, protocol: Protocol },
    Unknown { lock: Location, protocol: Protocol },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_known_lock_names_are_locks() {
        assert_eq!(Protocol::of(b".cargo-lock"), Some(Protocol::Cargo));
        assert_eq!(Protocol::of(b"owner.lock"), Some(Protocol::TempOwner));
        assert_eq!(Protocol::of(b"owner.json"), None);
        assert_eq!(Protocol::of(b"Cargo.lock"), None);
    }
}
