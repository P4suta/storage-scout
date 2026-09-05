//! A duration value type spelled the way people write file ages (`3d`).
//!
//! Like [`Bytes`](crate::Bytes), one [`FromStr`] impl owns the parsing rules
//! for both the command line and policy files, and the JSON form is a plain
//! number of seconds.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// An age in whole seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Age(pub u64);

impl Age {
    /// The underlying number of seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Age {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HOUR: u64 = 60 * 60;
        const DAY: u64 = 24 * HOUR;
        const WEEK: u64 = 7 * DAY;
        let seconds = self.0;
        if seconds != 0 && seconds.is_multiple_of(WEEK) {
            write!(f, "{}w", seconds / WEEK)
        } else if seconds != 0 && seconds.is_multiple_of(DAY) {
            write!(f, "{}d", seconds / DAY)
        } else if seconds != 0 && seconds.is_multiple_of(HOUR) {
            write!(f, "{}h", seconds / HOUR)
        } else {
            write!(f, "{seconds}s")
        }
    }
}

impl FromStr for Age {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let split = value
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(value.len());
        let (number, suffix) = value.split_at(split);
        let count = number
            .parse::<u64>()
            .map_err(|_| format!("invalid age: {value}"))?;
        let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
            "s" => 1,
            "h" => 60 * 60,
            "d" => 24 * 60 * 60,
            "w" => 7 * 24 * 60 * 60,
            _ => return Err("age must use s, h, d, or w (for example 30d)".to_owned()),
        };
        count
            .checked_mul(multiplier)
            .map(Self)
            .ok_or_else(|| "age is too large".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_suffixed_ages() {
        assert_eq!(Age::from_str("30d"), Ok(Age(30 * 24 * 60 * 60)));
        assert_eq!(Age::from_str("2w"), Ok(Age(14 * 24 * 60 * 60)));
        assert_eq!(Age::from_str(" 6H "), Ok(Age(6 * 60 * 60)));
        assert_eq!(Age::from_str("90s"), Ok(Age(90)));
        assert!(Age::from_str("3").is_err());
        assert!(Age::from_str("3m").is_err());
        assert!(Age::from_str("d").is_err());
        assert!(Age::from_str("99999999999999999999d").is_err());
    }

    #[test]
    fn displays_the_largest_exact_unit() {
        assert_eq!(Age(14 * 24 * 60 * 60).to_string(), "2w");
        assert_eq!(Age(3 * 24 * 60 * 60).to_string(), "3d");
        assert_eq!(Age(5 * 60 * 60).to_string(), "5h");
        assert_eq!(Age(90).to_string(), "90s");
        assert_eq!(Age(0).to_string(), "0s");
    }

    #[test]
    fn serializes_as_seconds() {
        assert_eq!(serde_json::to_string(&Age(3600)).unwrap(), "3600");
    }
}
