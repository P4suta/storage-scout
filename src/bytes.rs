//! A byte-count value type that renders itself with binary units.
//!
//! Using a dedicated type instead of a bare `u64` keeps sizes self-describing:
//! one [`Display`] impl owns the human formatting (`30.4 GiB`), while
//! `#[serde(transparent)]` keeps the JSON representation a plain number for
//! machine consumers. The two output formats never drift apart.

use std::fmt;
use std::iter::Sum;
use std::ops::Add;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A size in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bytes(pub u64);

impl Bytes {
    /// The largest representable size.
    pub const MAX: Self = Self(u64::MAX);

    /// The underlying byte count.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Saturating addition.
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction.
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl FromStr for Bytes {
    type Err = String;

    /// Parse `10MiB`, `1.5GB`, `4096`, and similar. Binary suffixes (`KiB`, or
    /// the bare letter `K`) are powers of 1024; decimal suffixes (`KB`) are
    /// powers of 1000.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let value = input.trim();
        let split = value
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(value.len());
        let (number, suffix) = value.split_at(split);
        let number = number
            .parse::<f64>()
            .map_err(|_| format!("invalid size: {input}"))?;
        if !number.is_finite() || number.is_sign_negative() {
            return Err(format!("invalid non-negative size: {input}"));
        }
        let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1.0,
            "k" | "kib" => 1024.0,
            "kb" => 1_000.0,
            "m" | "mib" => 1024.0 * 1024.0,
            "mb" => 1_000_000.0,
            "g" | "gib" => 1024.0 * 1024.0 * 1024.0,
            "gb" => 1_000_000_000.0,
            "t" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
            "tb" => 1_000_000_000_000.0,
            _ => return Err(format!("unknown size suffix: {suffix}")),
        };
        let bytes = number * multiplier;
        if bytes >= 18_446_744_073_709_551_616.0 {
            return Err("size is too large".to_owned());
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "finite non-negative value was range-checked above; byte fractions are truncated"
        )]
        Ok(Self(bytes as u64))
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        let bytes = self.0;
        if bytes < 1024 {
            return write!(f, "{bytes} B");
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "display only; f64 precision is ample for byte sizes"
        )]
        let mut size = bytes as f64;
        let mut unit = 0;
        while size >= 1024.0 && unit < UNITS.len() - 1 {
            size /= 1024.0;
            unit += 1;
        }
        write!(f, "{size:.1} {}", UNITS[unit])
    }
}

impl Add for Bytes {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sum for Bytes {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Self(iter.map(|b| b.0).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_uses_binary_units() {
        assert_eq!(Bytes(0).to_string(), "0 B");
        assert_eq!(Bytes(512).to_string(), "512 B");
        assert_eq!(Bytes(1024).to_string(), "1.0 KiB");
        assert_eq!(Bytes(1536).to_string(), "1.5 KiB");
        assert_eq!(Bytes(1024 * 1024).to_string(), "1.0 MiB");
        assert_eq!(Bytes(3 * 1024 * 1024 * 1024).to_string(), "3.0 GiB");
    }

    #[test]
    fn serializes_as_a_plain_number() {
        assert_eq!(serde_json::to_string(&Bytes(4096)).unwrap(), "4096");
    }

    #[test]
    fn sum_adds_byte_counts() {
        let total: Bytes = [Bytes(10), Bytes(20), Bytes(12)].into_iter().sum();
        assert_eq!(total, Bytes(42));
    }

    #[test]
    fn parses_binary_and_decimal_suffixes() {
        assert_eq!(Bytes::from_str("4096"), Ok(Bytes(4096)));
        assert_eq!(Bytes::from_str("10MiB"), Ok(Bytes(10 * 1024 * 1024)));
        assert_eq!(Bytes::from_str("1.5 gib"), Ok(Bytes(1_610_612_736)));
        assert_eq!(Bytes::from_str("2KB"), Ok(Bytes(2000)));
        assert_eq!(Bytes::from_str("3G"), Ok(Bytes(3 * 1024 * 1024 * 1024)));
        assert!(Bytes::from_str("-1").is_err());
        assert!(Bytes::from_str("1x").is_err());
        assert!(Bytes::from_str("abc").is_err());
        assert!(Bytes::from_str("99999999999999999999").is_err());
    }
}
