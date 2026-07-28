//! A byte-count value type that renders itself with binary units.
//!
//! Using a dedicated type instead of a bare `u64` keeps sizes self-describing:
//! one [`Display`] impl owns the human formatting (`30.4 GiB`), while
//! `#[serde(transparent)]` keeps the JSON representation a plain number for
//! machine consumers. The two output formats never drift apart.

use std::fmt;
use std::iter::Sum;
use std::ops::Add;

use serde::{Deserialize, Serialize};

/// A size in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bytes(pub u64);

impl Bytes {
    /// The underlying byte count.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
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
}
