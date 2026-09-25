use core::fmt;

use serde::Serialize;

use crate::location::{Case, Syntax};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Windows,
    MacOs,
    Linux,
}

impl Platform {
    pub const HOST: Self = if cfg!(windows) {
        Self::Windows
    } else if cfg!(target_os = "macos") {
        Self::MacOs
    } else {
        Self::Linux
    };

    #[must_use]
    pub const fn syntax(self) -> Syntax {
        match self {
            Self::Windows => Syntax::Windows,
            Self::MacOs | Self::Linux => Syntax::Unix,
        }
    }

    #[must_use]
    pub const fn case(self) -> Case {
        match self {
            Self::Windows | Self::MacOs => Case::Insensitive,
            Self::Linux => Case::Sensitive,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
