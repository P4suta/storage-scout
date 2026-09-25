use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::artifact::{Kind, Provenance, Tier};
use crate::gate::Admission;
use crate::location::{Case, Location};
use crate::ownership::{Ownership, Settlement};
use crate::size::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Identity {
    pub volume: u64,
    pub file: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Allocation {
    Unmeasured,
    Measured {
        allocated: Bytes,
        reclaimable: Bytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Usage {
    pub logical: Bytes,
    pub allocation: Allocation,
}

impl Usage {
    #[must_use]
    pub const fn reclaimable(&self) -> Option<Bytes> {
        match self.allocation {
            Allocation::Measured { reclaimable, .. } => Some(reclaimable),
            Allocation::Unmeasured => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Contents(u128);

impl Contents {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub fn file(path: &[u8], len: u64, identity: Option<Identity>) -> Self {
        let mut hash = Sha256::new();
        hash.update(path);
        hash.update([0]);
        hash.update(len.to_le_bytes());
        match identity {
            Some(identity) => {
                hash.update([1]);
                hash.update(identity.volume.to_le_bytes());
                hash.update(identity.file.to_le_bytes());
            },
            None => hash.update([0]),
        }
        let digest = hash.finalize();
        let mut bytes = [0u8; 16];
        for (slot, byte) in bytes.iter_mut().zip(digest.iter()) {
            *slot = *byte;
        }
        Self(u128::from_le_bytes(bytes))
    }

    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        Self(self.0.wrapping_add(other.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Measurement {
    pub usage: Usage,
    pub contents: Contents,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CandidateId(String);

impl CandidateId {
    #[must_use]
    pub fn derive(
        identity: Identity,
        location: &Location,
        kind: Kind,
        measurement: &Measurement,
        case: Case,
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(identity.volume.to_le_bytes());
        hash.update(identity.file.to_le_bytes());
        hash.update(location.key(case));
        hash.update([0]);
        hash.update(kind.as_str());
        hash.update([0]);
        hash.update(measurement.usage.logical.get().to_le_bytes());
        match measurement.usage.allocation {
            Allocation::Measured {
                allocated,
                reclaimable,
            } => {
                hash.update([1]);
                hash.update(allocated.get().to_le_bytes());
                hash.update(reclaimable.get().to_le_bytes());
            },
            Allocation::Unmeasured => hash.update([0]),
        }
        hash.update(measurement.contents.0.to_le_bytes());
        Self(format!("{:x}", hash.finalize()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a candidate ID is a 64-character SHA-256 hex digest")]
pub struct MalformedId;

impl FromStr for CandidateId {
    type Err = MalformedId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(MalformedId)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    id: CandidateId,
    location: Location,
    kind: Kind,
    provenance: Provenance,
    tier: Tier,
    usage: Usage,
    settlement: Settlement,
    ownership: Ownership,
    #[serde(skip)]
    identity: Identity,
}

#[derive(Debug, Clone)]
pub struct Observed {
    pub identity: Identity,
    pub measurement: Measurement,
    pub ownership: Ownership,
}

impl Candidate {
    #[must_use]
    pub fn new(admission: Admission, found: Observed, case: Case) -> Self {
        let Observed {
            identity,
            measurement,
            ownership,
        } = found;
        let measurement = &measurement;
        let (location, identification) = admission.into_parts();
        Self {
            settlement: ownership.settlement(),
            ownership,
            id: CandidateId::derive(identity, &location, identification.kind, measurement, case),
            kind: identification.kind,
            provenance: identification.provenance,
            tier: identification.kind.tier(),
            usage: measurement.usage,
            identity,
            location,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &CandidateId {
        &self.id
    }

    #[must_use]
    pub const fn location(&self) -> &Location {
        &self.location
    }

    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    #[must_use]
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }

    #[must_use]
    pub const fn tier(&self) -> Tier {
        self.tier
    }

    #[must_use]
    pub const fn usage(&self) -> &Usage {
        &self.usage
    }

    #[must_use]
    pub const fn identity(&self) -> Identity {
        self.identity
    }

    #[must_use]
    pub const fn settlement(&self) -> Settlement {
        self.settlement
    }

    #[must_use]
    pub const fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    #[must_use]
    pub fn describe(&self) -> String {
        self.location.to_string()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn an_id_is_exactly_sixty_four_hexadecimal_digits() {
        let hex = "aB".repeat(32);
        let id = hex.parse::<CandidateId>().unwrap();
        assert_eq!(id.as_str(), hex.to_ascii_lowercase());
        assert_eq!(id.to_string(), hex.to_ascii_lowercase());
        assert_eq!("ab".repeat(31).parse::<CandidateId>(), Err(MalformedId));
        assert_eq!("zz".repeat(32).parse::<CandidateId>(), Err(MalformedId));
    }
}
