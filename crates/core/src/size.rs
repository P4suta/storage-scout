use core::fmt;
use core::str::FromStr;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize)]
#[serde(transparent)]
pub struct Bytes(u64);

impl Bytes {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    #[must_use]
    pub fn total(values: impl IntoIterator<Item = Self>) -> Self {
        values.into_iter().fold(Self::ZERO, Self::saturating_add)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SizeError {
    #[error("a size needs a number")]
    NoNumber,
    #[error("a size may have at most one decimal point")]
    Malformed,
    #[error("unknown size suffix")]
    Suffix,
    #[error("the size does not fit in 64 bits")]
    Overflow,
}

const UNITS: [(&str, u128); 17] = [
    ("", 1),
    ("b", 1),
    ("k", 1 << 10),
    ("kib", 1 << 10),
    ("kb", 1_000),
    ("m", 1 << 20),
    ("mib", 1 << 20),
    ("mb", 1_000_000),
    ("g", 1 << 30),
    ("gib", 1 << 30),
    ("gb", 1_000_000_000),
    ("t", 1 << 40),
    ("tib", 1 << 40),
    ("tb", 1_000_000_000_000),
    ("p", 1 << 50),
    ("pib", 1 << 50),
    ("pb", 1_000_000_000_000_000),
];

impl FromStr for Bytes {
    type Err = SizeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let text = input.trim();
        let split = text
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(text.len());
        let (number, suffix) = text.split_at_checked(split).ok_or(SizeError::Malformed)?;
        let suffix = suffix.trim().to_ascii_lowercase();
        let multiplier = UNITS
            .iter()
            .find(|(name, _)| *name == suffix)
            .map(|(_, multiplier)| *multiplier)
            .ok_or(SizeError::Suffix)?;
        let (whole, fraction) = match number.split_once('.') {
            Some((whole, fraction)) if !fraction.contains('.') => (whole, fraction),
            Some(_) => return Err(SizeError::Malformed),
            None => (number, ""),
        };
        if whole.is_empty() && fraction.is_empty() {
            return Err(SizeError::NoNumber);
        }
        let whole_value = digits(whole)?;
        let fraction_value = digits(fraction)?;
        let scale = match u32::try_from(fraction.len()) {
            Ok(places) => 10u128.checked_pow(places).ok_or(SizeError::Overflow)?,
            Err(_too_long) => return Err(SizeError::Overflow),
        };
        let value = whole_value
            .checked_mul(multiplier)
            .and_then(|scaled| {
                fraction_value
                    .checked_mul(multiplier)?
                    .checked_div(scale)?
                    .checked_add(scaled)
            })
            .ok_or(SizeError::Overflow)?;
        u64::try_from(value)
            .map(Self)
            .map_err(|_overflow| SizeError::Overflow)
    }
}

fn digits(text: &str) -> Result<u128, SizeError> {
    text.bytes().try_fold(0u128, |total, digit| {
        total
            .checked_mul(10)
            .and_then(|total| total.checked_add(u128::from(digit.wrapping_sub(b'0'))))
            .ok_or(SizeError::Overflow)
    })
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        let value = u128::from(self.0);
        let mut unit = 0usize;
        let mut divisor = 1u128;
        while unit < 5 && value >= divisor.saturating_mul(1024) {
            unit = unit.saturating_add(1);
            divisor = divisor.saturating_mul(1024);
        }
        let name = NAMES.get(unit).copied().unwrap_or("B");
        if unit == 0 {
            return write!(f, "{value} {name}");
        }
        let tenths = value
            .saturating_mul(10)
            .saturating_add(divisor / 2)
            .checked_div(divisor)
            .unwrap_or(0);
        write!(f, "{}.{} {name}", tenths / 10, tenths % 10)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn every_suffix_means_exactly_what_it_says() {
        const K: u64 = 1024;
        for (text, expected) in [
            ("0", 0),
            ("12", 12),
            ("12b", 12),
            ("1k", K),
            ("1KiB", K),
            ("1kb", 1_000),
            ("1.5MiB", 3 * K * K / 2),
            ("2GiB", 2 * K * K * K),
            ("1TB", 1_000_000_000_000),
            ("1PiB", K * K * K * K * K),
            (" 10 MiB ", 10 * K * K),
            (".5k", K / 2),
        ] {
            assert_eq!(text.parse::<Bytes>(), Ok(Bytes(expected)), "{text}");
        }
    }

    #[test]
    fn nonsense_is_refused_rather_than_guessed() {
        assert_eq!("".parse::<Bytes>(), Err(SizeError::NoNumber));
        assert_eq!("lots".parse::<Bytes>(), Err(SizeError::Suffix));
        assert_eq!("1.2.3k".parse::<Bytes>(), Err(SizeError::Malformed));
        assert_eq!("-1".parse::<Bytes>(), Err(SizeError::Suffix));
        assert_eq!("99999999999PiB".parse::<Bytes>(), Err(SizeError::Overflow));
    }

    #[test]
    fn display_uses_the_largest_whole_unit() {
        assert_eq!(Bytes(0).to_string(), "0 B");
        assert_eq!(Bytes(1023).to_string(), "1023 B");
        assert_eq!(Bytes(1024).to_string(), "1.0 KiB");
        assert_eq!(Bytes(1536).to_string(), "1.5 KiB");
        assert_eq!(Bytes(64 * 1024).to_string(), "64.0 KiB");
        assert_eq!(Bytes::MAX.to_string(), "16384.0 PiB");
    }

    #[test]
    fn arithmetic_saturates() {
        assert_eq!(Bytes::MAX.saturating_add(Bytes(1)), Bytes::MAX);
        assert_eq!(Bytes(1).saturating_sub(Bytes(2)), Bytes::ZERO);
        assert_eq!(Bytes::total([Bytes(1), Bytes(2), Bytes::MAX]), Bytes::MAX);
    }
}
