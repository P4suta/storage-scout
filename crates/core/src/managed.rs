use crate::artifact::Tier;
use crate::candidate::CandidateId;
use crate::gate::TierGrant;
use serde::Serialize;

pub const PINNED_DATE_WIDTHS: [usize; 3] = [4, 2, 2];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[serde(rename_all = "kebab-case")]
pub enum Resource {
    Toolchain,
    Image,
    BuildCache,
    Volume,
    Container,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[serde(rename_all = "kebab-case")]
pub enum References {
    Unused,
    Referenced,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Completeness {
    Complete,
    Incomplete,
}

#[must_use]
pub fn version_reference(request: &str, installed: &str) -> References {
    version_bytes(request.as_bytes(), installed.as_bytes())
}

pub(crate) fn version_bytes(request: &[u8], installed: &[u8]) -> References {
    if request == installed {
        return if request.is_empty() || request == b"v" {
            References::Unknown
        } else {
            References::Referenced
        };
    }
    let request = normalized_version(request);
    let installed = normalized_version(installed);
    if request.is_empty() || installed.is_empty() {
        return References::Unknown;
    }
    if request == installed {
        return References::Referenced;
    }
    let numeric = request
        .split(|byte| *byte == b'.')
        .all(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit));
    if numeric {
        if installed
            .strip_prefix(request)
            .is_some_and(|suffix| suffix.starts_with(b"."))
        {
            return References::Referenced;
        }
        return References::Unused;
    }
    if matches!(request, b"stable" | b"beta" | b"nightly")
        || request.strip_prefix(b"nightly-").is_some_and(|date| {
            date.split(|byte| *byte == b'-')
                .map(<[u8]>::len)
                .eq(PINNED_DATE_WIDTHS)
                && date
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || *byte == b'-')
        })
    {
        References::Unused
    } else {
        References::Unknown
    }
}

pub(crate) const fn normalized_version(version: &[u8]) -> &[u8] {
    match version.split_first() {
        Some((b'v', suffix)) => suffix,
        Some(_) | None => version,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    #[error("volumes and containers are preserved")]
    Preserved,
    #[error("the reinstallable tier was not granted")]
    Tier,
    #[error("the reference survey is incomplete")]
    Incomplete,
    #[error("the manager still references this resource")]
    Referenced,
    #[error("the manager did not report the reference state")]
    Unknown,
    #[error("the reviewed resource changed")]
    Stale,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub resource: Resource,
    pub references: References,
    pub completeness: Completeness,
    pub recorded: &'a CandidateId,
    pub current: &'a CandidateId,
    pub tiers: TierGrant,
}

#[derive(Debug)]
pub struct Clearance {
    id: CandidateId,
    resource: Resource,
}

impl Clearance {
    #[must_use]
    pub const fn id(&self) -> &CandidateId {
        &self.id
    }

    #[must_use]
    pub const fn resource(&self) -> Resource {
        self.resource
    }
}

pub fn clear(request: &Request<'_>) -> Result<Clearance, Refusal> {
    match request.resource {
        Resource::Volume | Resource::Container => return Err(Refusal::Preserved),
        Resource::Toolchain | Resource::Image | Resource::BuildCache => {},
    }
    if !request.tiers.admits(Tier::Reinstallable) {
        return Err(Refusal::Tier);
    }
    if request.completeness == Completeness::Incomplete {
        return Err(Refusal::Incomplete);
    }
    match request.references {
        References::Referenced => return Err(Refusal::Referenced),
        References::Unknown => return Err(Refusal::Unknown),
        References::Unused => {},
    }
    if request.recorded != request.current {
        return Err(Refusal::Stale);
    }
    Ok(Clearance {
        id: request.current.clone(),
        resource: request.resource,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn version_prefixes_do_not_match_other_minor_versions_and_dynamic_pins_remain_unknown() {
        for (request, installed, expected) in [
            ("1.98", "1.98.1", References::Referenced),
            ("1.9", "1.99.1", References::Unused),
            ("v4.29.0", "4.29.0", References::Referenced),
            (
                "nightly-2026-10-01",
                "nightly-2026-07-15",
                References::Unused,
            ),
            ("nightly", "nightly", References::Referenced),
            ("latest", "1.99.1", References::Unknown),
            ("{{ vars.rust }}", "1.99.1", References::Unknown),
            ("", "1.99.1", References::Unknown),
            ("", "", References::Unknown),
            ("v", "v", References::Unknown),
            ("1.98.1", "", References::Unknown),
            ("1.98.1", "v", References::Unknown),
        ] {
            assert_eq!(version_reference(request, installed), expected);
        }
    }

    #[test]
    fn a_review_never_overrides_references_uncertainty_or_preserved_data() {
        let id = CandidateId::from_str(&"1".repeat(64)).unwrap();
        let other = CandidateId::from_str(&"2".repeat(64)).unwrap();
        let mut request = Request {
            resource: Resource::Toolchain,
            references: References::Unused,
            completeness: Completeness::Complete,
            recorded: &id,
            current: &id,
            tiers: TierGrant::ROUTINE.with(Tier::Reinstallable),
        };
        assert_eq!(clear(&request).unwrap().id(), &id);
        for resource in [Resource::Volume, Resource::Container] {
            request.resource = resource;
            assert!(matches!(clear(&request), Err(Refusal::Preserved)));
        }
        request.resource = Resource::Image;
        request.references = References::Referenced;
        assert!(matches!(clear(&request), Err(Refusal::Referenced)));
        request.references = References::Unknown;
        assert!(matches!(clear(&request), Err(Refusal::Unknown)));
        request.references = References::Unused;
        request.completeness = Completeness::Incomplete;
        assert!(matches!(clear(&request), Err(Refusal::Incomplete)));
        request.completeness = Completeness::Complete;
        request.current = &other;
        assert!(matches!(clear(&request), Err(Refusal::Stale)));
        request.current = &id;
        request.tiers = TierGrant::ROUTINE;
        assert!(matches!(clear(&request), Err(Refusal::Tier)));
    }
}
