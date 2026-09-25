use alloc::vec::Vec;
use core::fmt;

use serde::Serialize;

use crate::area::{AppOwned, Area, Protection};
use crate::artifact::{Identification, Listing, Provenance, Tier};
use crate::candidate::{Candidate, CandidateId, Identity, Measurement};
use crate::location::Location;
use crate::lock::Liveness;
use crate::lock::Protocol;
use crate::ownership::{Admits, Ownership, Settlement};
use crate::reject::{Rejection, StaleField};
use crate::share::{Capability, Filesystem, Method};

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum Gate {
        Shape,
        Mount,
        Area,
        Exclusion,
        Evidence,
        Tier,
        Ownership,
        Protocol,
        Capability,
        Busy,
        Identity,
        Freshness,
    }
}

impl Gate {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Shape => "shape",
            Self::Mount => "mount",
            Self::Area => "area",
            Self::Exclusion => "exclusion",
            Self::Evidence => "evidence",
            Self::Tier => "tier",
            Self::Ownership => "ownership",
            Self::Protocol => "protocol",
            Self::Capability => "capability",
            Self::Busy => "busy",
            Self::Identity => "identity",
            Self::Freshness => "freshness",
        }
    }

    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::Shape => "the path is a real directory, not a link to one",
            Self::Mount => "the directory is on the same filesystem as its parent",
            Self::Area => "the location admits candidates of this provenance",
            Self::Exclusion => "no requested exclusion covers the path",
            Self::Evidence => "live evidence still names a known artifact family",
            Self::Tier => "the regeneration cost was accepted by the caller",
            Self::Ownership => "whoever owns it has let it go, as far as the caller requires",
            Self::Protocol => "the tool that writes it takes a lock storage-scout can hold",
            Self::Capability => "the filesystem can share blocks between identical files",
            Self::Busy => "no running tool holds the directory",
            Self::Identity => "the path still names the same directory as at discovery",
            Self::Freshness => "nothing inside changed since it was measured",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Shape {
    Directory,
    Link,
    File,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "boundary", rename_all = "kebab-case")]
pub enum Boundary {
    NoParent,
    Same { device: u64 },
    Crossed { from: u64, to: u64 },
    Unreported,
}

#[derive(Debug, Clone, Copy)]
pub struct Site<'a> {
    pub location: &'a Location,
    pub shape: Shape,
    pub boundary: Boundary,
    pub listing: &'a Listing,
    pub protection: &'a Protection,
    pub excludes: &'a [Location],
}

impl Site<'_> {
    fn identify(&self) -> Option<Identification> {
        self.listing.identify(self.location.file_name()?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
pub struct TierGrant {
    reinstallable: bool,
    expensive: bool,
}

impl TierGrant {
    pub const ROUTINE: Self = Self {
        reinstallable: false,
        expensive: false,
    };

    #[must_use]
    pub const fn with(self, tier: Tier) -> Self {
        match tier {
            Tier::Routine => self,
            Tier::Reinstallable => Self {
                reinstallable: true,
                ..self
            },
            Tier::Expensive => Self {
                expensive: true,
                ..self
            },
        }
    }

    #[must_use]
    pub fn of(tiers: impl IntoIterator<Item = Tier>) -> Self {
        tiers.into_iter().fold(Self::ROUTINE, Self::with)
    }

    #[must_use]
    pub const fn admits(self, tier: Tier) -> bool {
        match tier {
            Tier::Routine => true,
            Tier::Reinstallable => self.reinstallable,
            Tier::Expensive => self.expensive,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Mandate {
    pub tiers: TierGrant,
    pub settlements: Admits,
}

impl Default for Mandate {
    fn default() -> Self {
        Self {
            tiers: TierGrant::ROUTINE,
            settlements: Admits::Anything,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Recheck<'a> {
    pub mandate: &'a Mandate,
    pub recorded: &'a Candidate,
    pub identity: Identity,
    pub ownership: &'a Ownership,
    pub liveness: &'a Liveness,
}

#[derive(Debug, Clone, Copy)]
pub struct Inspection<'a> {
    pub tiers: TierGrant,
    pub settlements: Admits,
    pub ownership: Option<&'a Ownership>,
    pub liveness: Option<&'a Liveness>,
}

#[derive(Debug, Clone, Copy)]
pub struct Verify<'a> {
    pub recheck: Recheck<'a>,
    pub measured: &'a Measurement,
}

#[derive(Debug, Clone, Copy)]
pub struct ShareCheck<'a> {
    pub recorded: &'a Candidate,
    pub identity: Identity,
    pub liveness: &'a Liveness,
    pub capability: Capability,
}

#[derive(Debug, Clone, Copy)]
enum Ask<'a> {
    Discover,
    Inspect(&'a Inspection<'a>),
    Recheck(&'a Recheck<'a>),
    Verify(&'a Verify<'a>),
    Share(&'a ShareCheck<'a>),
}

impl<'a> Ask<'a> {
    const fn recorded(self) -> Option<(&'a Candidate, Identity)> {
        match self {
            Self::Discover | Self::Inspect(_) => None,
            Self::Recheck(recheck) => Some((recheck.recorded, recheck.identity)),
            Self::Verify(verify) => Some((verify.recheck.recorded, verify.recheck.identity)),
            Self::Share(share) => Some((share.recorded, share.identity)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "note", rename_all = "kebab-case")]
pub enum Note {
    Directory,
    SameDevice { device: u64 },
    DeviceUnreported,
    Open,
    DeclaredIn { area: AppOwned },
    OutsideExclusions,
    Identified { identification: Identification },
    TierAccepted { tier: Tier },
    Settled { settlement: Settlement },
    Locks { protocol: Protocol },
    Shares { filesystem: Filesystem },
    Free,
    SameIdentity,
    SameContents,
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory => f.write_str("directory, not a link"),
            Self::SameDevice { device } => write!(f, "same device ({device:#x})"),
            Self::DeviceUnreported => f.write_str("mount points appear as reparse points here"),
            Self::Open => f.write_str("open project space"),
            Self::DeclaredIn { area } => write!(f, "{area}, and the cache declares itself"),
            Self::OutsideExclusions => f.write_str("outside every exclusion"),
            Self::Identified { identification } => write!(
                f,
                "kind={}, provenance={}",
                identification.kind, identification.provenance
            ),
            Self::TierAccepted { tier } => write!(f, "{tier} (accepted)"),
            Self::Settled { settlement } => write!(f, "{settlement}"),
            Self::Locks { protocol } => write!(f, "writers take {} locks", protocol.label()),
            Self::Shares { filesystem } => write!(f, "{filesystem} shares blocks"),
            Self::Free => f.write_str("no running tool holds it"),
            Self::SameIdentity => f.write_str("same path and volume/file ID as at discovery"),
            Self::SameContents => f.write_str("same files, sizes, and allocation"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Pass(Note),
    Abstain,
    Reject(Rejection),
}

fn check(gate: Gate, site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    match gate {
        Gate::Shape => shape(site),
        Gate::Mount => mount(site),
        Gate::Area => area(site),
        Gate::Exclusion => exclusion(site),
        Gate::Evidence => evidence(site, ask),
        Gate::Tier => tier(site, ask),
        Gate::Ownership => ownership(site, ask),
        Gate::Protocol => protocol(site, ask),
        Gate::Capability => capability(site, ask),
        Gate::Busy => busy(site, ask),
        Gate::Identity => identity(site, ask),
        Gate::Freshness => freshness(site, ask),
    }
}

fn shape(site: &Site<'_>) -> Verdict {
    let location = site.location.clone();
    match site.shape {
        Shape::Directory => Verdict::Pass(Note::Directory),
        Shape::Link => Verdict::Reject(Rejection::Link { location }),
        Shape::File | Shape::Other => Verdict::Reject(Rejection::NotADirectory { location }),
    }
}

fn mount(site: &Site<'_>) -> Verdict {
    match site.boundary {
        Boundary::NoParent => Verdict::Abstain,
        Boundary::Same { device } => Verdict::Pass(Note::SameDevice { device }),
        Boundary::Unreported => Verdict::Pass(Note::DeviceUnreported),
        Boundary::Crossed { from, to } => Verdict::Reject(Rejection::MountBoundary {
            location: site.location.clone(),
            from,
            to,
        }),
    }
}

fn area(site: &Site<'_>) -> Verdict {
    match site.protection.area_of(site.location) {
        Area::System(area) => Verdict::Reject(Rejection::Protected {
            location: site.location.clone(),
            area,
        }),
        Area::AppOwned(area) => {
            let found = site
                .identify()
                .map_or(Provenance::Inferred, |identified| identified.provenance);
            match found {
                Provenance::Declared => Verdict::Pass(Note::DeclaredIn { area }),
                Provenance::Inferred => Verdict::Reject(Rejection::ProvenanceTooWeak {
                    location: site.location.clone(),
                    area,
                    found,
                }),
            }
        },
        Area::Open => Verdict::Pass(Note::Open),
    }
}

fn exclusion(site: &Site<'_>) -> Verdict {
    site.excludes
        .iter()
        .find(|exclude| site.protection.intersects(exclude, site.location))
        .map_or(Verdict::Pass(Note::OutsideExclusions), |exclude| {
            Verdict::Reject(Rejection::Excluded {
                location: site.location.clone(),
                exclude: exclude.clone(),
            })
        })
}

fn evidence(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    let location = site.location.clone();
    let Some(identification) = site.identify() else {
        return Verdict::Reject(Rejection::EvidenceLost { location });
    };
    if let Some((recorded, _)) = ask.recorded() {
        if identification.kind != recorded.kind() {
            return Verdict::Reject(Rejection::KindChanged {
                location,
                from: recorded.kind(),
                to: identification.kind,
            });
        }
        if identification.provenance != recorded.provenance() {
            return Verdict::Reject(Rejection::ProvenanceChanged {
                location,
                from: recorded.provenance(),
                to: identification.provenance,
            });
        }
    }
    Verdict::Pass(Note::Identified { identification })
}

fn tier(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    let grant = match ask {
        Ask::Discover | Ask::Share(_) => return Verdict::Abstain,
        Ask::Inspect(inspection) => inspection.tiers,
        Ask::Recheck(recheck) => recheck.mandate.tiers,
        Ask::Verify(verify) => verify.recheck.mandate.tiers,
    };
    let Some(identification) = site.identify() else {
        return Verdict::Reject(Rejection::EvidenceLost {
            location: site.location.clone(),
        });
    };
    let tier = identification.kind.tier();
    if grant.admits(tier) {
        Verdict::Pass(Note::TierAccepted { tier })
    } else {
        Verdict::Reject(Rejection::TierLocked {
            location: site.location.clone(),
            tier,
        })
    }
}

fn ownership(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    let (ownership, admits) = match ask {
        Ask::Discover | Ask::Share(_) => return Verdict::Abstain,
        Ask::Inspect(inspection) => match inspection.ownership {
            Some(ownership) => (ownership, inspection.settlements),
            None => return Verdict::Abstain,
        },
        Ask::Recheck(recheck) => (recheck.ownership, recheck.mandate.settlements),
        Ask::Verify(verify) => (verify.recheck.ownership, verify.recheck.mandate.settlements),
    };
    let settlement = ownership.settlement();
    if admits.admits(settlement) {
        Verdict::Pass(Note::Settled { settlement })
    } else {
        Verdict::Reject(Rejection::Owned {
            location: site.location.clone(),
            settlement,
        })
    }
}

fn protocol(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    match ask {
        Ask::Discover | Ask::Inspect(_) | Ask::Recheck(_) | Ask::Verify(_) => Verdict::Abstain,
        Ask::Share(share) => {
            let kind = share.recorded.kind();
            match kind.protocol() {
                Some(protocol) => Verdict::Pass(Note::Locks { protocol }),
                None => Verdict::Reject(Rejection::NoLockProtocol {
                    location: site.location.clone(),
                    kind,
                }),
            }
        },
    }
}

fn capability(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    match ask {
        Ask::Discover | Ask::Inspect(_) | Ask::Recheck(_) | Ask::Verify(_) => Verdict::Abstain,
        Ask::Share(share) => match share.capability {
            Capability::Shares { filesystem, .. } => Verdict::Pass(Note::Shares { filesystem }),
            Capability::Unsupported { filesystem } => Verdict::Reject(Rejection::CannotShare {
                location: site.location.clone(),
                filesystem,
            }),
        },
    }
}

fn busy(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    let liveness = match ask {
        Ask::Discover => return Verdict::Abstain,
        Ask::Share(share) => share.liveness,
        Ask::Inspect(inspection) => match inspection.liveness {
            Some(liveness) => liveness,
            None => return Verdict::Abstain,
        },
        Ask::Recheck(recheck) => recheck.liveness,
        Ask::Verify(verify) => verify.recheck.liveness,
    };
    match liveness {
        Liveness::Free => Verdict::Pass(Note::Free),
        Liveness::Held { lock, protocol } => Verdict::Reject(Rejection::Busy {
            location: site.location.clone(),
            lock: lock.clone(),
            protocol: *protocol,
        }),
        Liveness::Unknown { lock, protocol } => Verdict::Reject(Rejection::LivenessUnknown {
            location: site.location.clone(),
            lock: lock.clone(),
            protocol: *protocol,
        }),
    }
}

fn identity(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    let Some((recorded, identity)) = ask.recorded() else {
        return Verdict::Abstain;
    };
    let location = site.location.clone();
    if !site
        .location
        .same(recorded.location(), site.protection.case())
    {
        return Verdict::Reject(Rejection::Stale {
            location,
            field: StaleField::CanonicalPath,
        });
    }
    if identity != recorded.identity() {
        return Verdict::Reject(Rejection::Stale {
            location,
            field: StaleField::FileIdentity,
        });
    }
    Verdict::Pass(Note::SameIdentity)
}

fn freshness(site: &Site<'_>, ask: Ask<'_>) -> Verdict {
    let verify = match ask {
        Ask::Discover | Ask::Inspect(_) | Ask::Recheck(_) | Ask::Share(_) => {
            return Verdict::Abstain;
        },
        Ask::Verify(verify) => verify,
    };
    let recorded = verify.recheck.recorded;
    let recomputed = CandidateId::derive(
        verify.recheck.identity,
        site.location,
        recorded.kind(),
        verify.measured,
        site.protection.case(),
    );
    if &recomputed == recorded.id() {
        Verdict::Pass(Note::SameContents)
    } else {
        Verdict::Reject(Rejection::Stale {
            location: site.location.clone(),
            field: StaleField::Content,
        })
    }
}

fn run(site: &Site<'_>, ask: Ask<'_>) -> Result<Identification, Rejection> {
    let mut identified = None;
    for gate in Gate::ALL {
        match check(*gate, site, ask) {
            Verdict::Pass(Note::Identified { identification }) => {
                identified = Some(identification);
            },
            Verdict::Pass(_) | Verdict::Abstain => {},
            Verdict::Reject(rejection) => return Err(rejection),
        }
    }
    identified.ok_or_else(|| Rejection::EvidenceLost {
        location: site.location.clone(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    location: Location,
    identification: Identification,
}

impl Admission {
    pub(crate) fn into_parts(self) -> (Location, Identification) {
        (self.location, self.identification)
    }
}

pub fn admit(site: &Site<'_>) -> Result<Admission, Rejection> {
    run(site, Ask::Discover).map(|identification| Admission {
        location: site.location.clone(),
        identification,
    })
}

pub fn recheck(site: &Site<'_>, recheck: &Recheck<'_>) -> Result<(), Rejection> {
    run(site, Ask::Recheck(recheck)).map(|_| ())
}

#[derive(Debug)]
#[must_use]
pub struct Clearance {
    location: Location,
    identity: Identity,
    identification: Identification,
}

impl Clearance {
    #[must_use]
    pub const fn location(&self) -> &Location {
        &self.location
    }

    #[must_use]
    pub const fn identity(&self) -> Identity {
        self.identity
    }

    #[must_use]
    pub const fn identification(&self) -> Identification {
        self.identification
    }
}

pub fn clear(site: &Site<'_>, verify: &Verify<'_>) -> Result<Clearance, Rejection> {
    run(site, Ask::Verify(verify)).map(|identification| Clearance {
        location: site.location.clone(),
        identity: verify.recheck.identity,
        identification,
    })
}

#[derive(Debug)]
#[must_use]
pub struct ShareClearance {
    location: Location,
    identity: Identity,
    method: Method,
}

impl ShareClearance {
    #[must_use]
    pub const fn location(&self) -> &Location {
        &self.location
    }

    #[must_use]
    pub const fn identity(&self) -> Identity {
        self.identity
    }

    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }
}

pub fn clear_share(site: &Site<'_>, share: &ShareCheck<'_>) -> Result<ShareClearance, Rejection> {
    run(site, Ask::Share(share))?;
    match share.capability {
        Capability::Shares { method, .. } => Ok(ShareClearance {
            location: site.location.clone(),
            identity: share.identity,
            method,
        }),
        Capability::Unsupported { filesystem } => Err(Rejection::CannotShare {
            location: site.location.clone(),
            filesystem,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    Pass { note: Note },
    Abstain,
    Reject { rejection: Rejection },
    NotReached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Stage {
    pub gate: Gate,
    pub outcome: Outcome,
}

#[must_use]
pub fn inspect(site: &Site<'_>, inspection: &Inspection<'_>) -> Vec<Stage> {
    let ask = Ask::Inspect(inspection);
    let mut refused = false;
    Gate::ALL
        .iter()
        .map(|gate| {
            let outcome = if refused {
                Outcome::NotReached
            } else {
                match check(*gate, site, ask) {
                    Verdict::Pass(note) => Outcome::Pass { note },
                    Verdict::Abstain => Outcome::Abstain,
                    Verdict::Reject(rejection) => {
                        refused = true;
                        Outcome::Reject { rejection }
                    },
                }
            };
            Stage {
                gate: *gate,
                outcome,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::area::{Reach, Rule, SystemReason};
    use crate::artifact::{CacheTag, Entries, Kind, Tags};
    use crate::candidate::{Allocation, Contents, Observed, Usage};
    use crate::location::{Case, Syntax};
    use crate::lock::Protocol;
    use crate::size::Bytes;

    fn at(path: &str) -> Location {
        Location::parse_str(Syntax::Unix, path).unwrap()
    }

    fn protection(rules: Vec<Rule>) -> Protection {
        Protection::new(
            Syntax::Unix,
            Case::Sensitive,
            at("/cwd"),
            at("/bin/scout"),
            rules,
        )
        .unwrap()
    }

    fn cargo_listing() -> Listing {
        let mut parent = Entries::default();
        parent.file(b"Cargo.toml");
        Listing::new(parent, Entries::default(), Tags::cache(CacheTag::Absent))
    }

    fn tagged_listing() -> Listing {
        Listing::new(
            Entries::default(),
            Entries::default(),
            Tags::cache(CacheTag::Verified),
        )
    }

    struct Fixture {
        location: Location,
        listing: Listing,
        protection: Protection,
        excludes: Vec<Location>,
        shape: Shape,
        boundary: Boundary,
    }

    impl Fixture {
        fn target() -> Self {
            Self {
                location: at("/work/app/target"),
                listing: cargo_listing(),
                protection: protection(Vec::new()),
                excludes: Vec::new(),
                shape: Shape::Directory,
                boundary: Boundary::Same { device: 1 },
            }
        }

        fn site(&self) -> Site<'_> {
            Site {
                location: &self.location,
                shape: self.shape,
                boundary: self.boundary,
                listing: &self.listing,
                protection: &self.protection,
                excludes: &self.excludes,
            }
        }
    }

    const IDENTITY: Identity = Identity { volume: 1, file: 7 };

    const fn inspection(tiers: TierGrant) -> Inspection<'static> {
        Inspection {
            tiers,
            settlements: Admits::Anything,
            ownership: None,
            liveness: Some(&Liveness::Free),
        }
    }

    fn measured(logical: u64) -> Measurement {
        Measurement {
            usage: Usage {
                logical: Bytes::new(logical),
                allocation: Allocation::Measured {
                    allocated: Bytes::new(logical),
                    reclaimable: Bytes::new(logical),
                },
            },
            contents: Contents::file(b"/work/app/target/x", logical, Some(IDENTITY)),
        }
    }

    fn discovered(fixture: &Fixture, measurement: &Measurement) -> Candidate {
        let admission = admit(&fixture.site()).unwrap();
        Candidate::new(
            admission,
            Observed {
                identity: IDENTITY,
                measurement: *measurement,
                ownership: Ownership::Nothing,
            },
            Case::Sensitive,
        )
    }

    #[test]
    fn the_pipeline_is_the_gate_declaration_order() {
        let position = |gate: Gate| Gate::ALL.iter().position(|each| *each == gate).unwrap();
        assert!(position(Gate::Shape) < position(Gate::Area));
        assert!(position(Gate::Area) < position(Gate::Evidence));
        assert!(position(Gate::Evidence) < position(Gate::Tier));
        assert!(position(Gate::Tier) < position(Gate::Busy));
        assert!(position(Gate::Busy) < position(Gate::Identity));
        assert!(position(Gate::Identity) < position(Gate::Freshness));
    }

    #[test]
    fn an_ordinary_target_is_admitted_and_cleared_when_nothing_changed() {
        let fixture = Fixture::target();
        let measurement = measured(100);
        let candidate = discovered(&fixture, &measurement);
        let mandate = Mandate::default();
        let verify = Verify {
            recheck: Recheck {
                mandate: &mandate,
                recorded: &candidate,
                identity: IDENTITY,
                ownership: &Ownership::Nothing,
                liveness: &Liveness::Free,
            },
            measured: &measurement,
        };
        let clearance = clear(&fixture.site(), &verify).unwrap();
        assert_eq!(clearance.identity(), IDENTITY);
        assert_eq!(clearance.identification().kind, Kind::RustTarget);
    }

    #[test]
    fn the_most_fundamental_reason_is_reported_first() {
        let mut fixture = Fixture::target();
        fixture.protection = protection(vec![Rule::system(
            SystemReason::SystemArea { label: "/work" },
            at("/work"),
            Reach::Subtree,
        )]);
        fixture.listing = Listing::new(
            Entries::default(),
            Entries::default(),
            Tags::cache(CacheTag::Absent),
        );
        assert!(matches!(
            admit(&fixture.site()),
            Err(Rejection::Protected { .. })
        ));
    }

    #[test]
    fn a_grant_lists_exactly_the_tiers_it_names() {
        let grant = TierGrant::of([Tier::Reinstallable]);
        assert!(grant.admits(Tier::Routine));
        assert!(grant.admits(Tier::Reinstallable));
        assert!(!grant.admits(Tier::Expensive));
    }

    #[test]
    fn a_filesystem_root_is_protected_before_it_is_even_identified() {
        let mut fixture = Fixture::target();
        fixture.location = at("/");
        assert!(matches!(
            admit(&fixture.site()),
            Err(Rejection::Protected { .. })
        ));
    }

    #[test]
    fn a_link_or_a_file_is_refused_before_anything_else() {
        let mut fixture = Fixture::target();
        fixture.shape = Shape::Link;
        assert!(matches!(
            admit(&fixture.site()),
            Err(Rejection::Link { .. })
        ));
        fixture.shape = Shape::File;
        assert!(matches!(
            admit(&fixture.site()),
            Err(Rejection::NotADirectory { .. })
        ));
    }

    #[test]
    fn a_mount_point_is_refused() {
        let mut fixture = Fixture::target();
        fixture.boundary = Boundary::Crossed { from: 1, to: 2 };
        assert!(matches!(
            admit(&fixture.site()),
            Err(Rejection::MountBoundary { .. })
        ));
    }

    #[test]
    fn an_application_owned_area_admits_declared_but_not_inferred() {
        let rules = vec![Rule::app_owned("~/Library", at("/work"), Reach::Subtree)];
        let mut fixture = Fixture::target();
        fixture.protection = protection(rules);
        assert!(matches!(
            admit(&fixture.site()),
            Err(Rejection::ProvenanceTooWeak {
                found: Provenance::Inferred,
                ..
            })
        ));
        fixture.listing = tagged_listing();
        admit(&fixture.site()).unwrap();
    }

    #[test]
    fn an_exclusion_protects_in_both_directions() {
        for exclude in ["/work", "/work/app/target/debug"] {
            let mut fixture = Fixture::target();
            fixture.excludes = vec![at(exclude)];
            assert!(
                matches!(admit(&fixture.site()), Err(Rejection::Excluded { .. })),
                "{exclude}"
            );
        }
    }

    #[test]
    fn inspect_stops_at_the_refusal_and_says_so() {
        let mut fixture = Fixture::target();
        fixture.boundary = Boundary::Crossed { from: 1, to: 2 };
        let stages = inspect(&fixture.site(), &inspection(TierGrant::ROUTINE));
        assert_eq!(stages.len(), Gate::ALL.len());
        let refusal = stages
            .iter()
            .position(|stage| matches!(stage.outcome, Outcome::Reject { .. }))
            .unwrap();
        assert_eq!(
            stages.get(refusal).map(|stage| stage.gate),
            Some(Gate::Mount)
        );
        assert!(
            stages
                .iter()
                .skip(refusal + 1)
                .all(|stage| stage.outcome == Outcome::NotReached)
        );
    }

    #[test]
    fn a_tier_is_accepted_only_when_granted() {
        let mut fixture = Fixture::target();
        fixture.listing = tagged_listing();
        let refused = inspect(&fixture.site(), &inspection(TierGrant::ROUTINE));
        assert!(refused.iter().any(|stage| matches!(
            stage.outcome,
            Outcome::Reject {
                rejection: Rejection::TierLocked {
                    tier: Tier::Reinstallable,
                    ..
                }
            }
        )));
        let granted = inspect(
            &fixture.site(),
            &inspection(TierGrant::ROUTINE.with(Tier::Reinstallable)),
        );
        assert!(
            granted
                .iter()
                .all(|stage| !matches!(stage.outcome, Outcome::Reject { .. }))
        );
    }

    #[test]
    fn liveness_refuses_a_held_or_unknowable_lock() {
        let fixture = Fixture::target();
        let measurement = measured(100);
        let candidate = discovered(&fixture, &measurement);
        let mandate = Mandate::default();
        let lock = at("/work/app/target/debug/.cargo-lock");
        for (liveness, busy) in [
            (
                Liveness::Held {
                    lock: lock.clone(),
                    protocol: Protocol::Cargo,
                },
                true,
            ),
            (
                Liveness::Unknown {
                    lock,
                    protocol: Protocol::TempOwner,
                },
                false,
            ),
        ] {
            let result = recheck(
                &fixture.site(),
                &Recheck {
                    mandate: &mandate,
                    recorded: &candidate,
                    identity: IDENTITY,
                    ownership: &Ownership::Nothing,
                    liveness: &liveness,
                },
            );
            if busy {
                assert!(matches!(
                    result,
                    Err(Rejection::Busy {
                        protocol: Protocol::Cargo,
                        ..
                    })
                ));
            } else {
                assert!(matches!(result, Err(Rejection::LivenessUnknown { .. })));
            }
        }
    }

    #[test]
    fn a_changed_identity_or_content_is_stale() {
        let fixture = Fixture::target();
        let measurement = measured(100);
        let candidate = discovered(&fixture, &measurement);
        let mandate = Mandate::default();
        let other = Identity { volume: 1, file: 8 };
        let result = recheck(
            &fixture.site(),
            &Recheck {
                mandate: &mandate,
                recorded: &candidate,
                identity: other,
                ownership: &Ownership::Nothing,
                liveness: &Liveness::Free,
            },
        );
        assert!(matches!(
            result,
            Err(Rejection::Stale {
                field: StaleField::FileIdentity,
                ..
            })
        ));

        let grown = measured(101);
        let verify = Verify {
            recheck: Recheck {
                mandate: &mandate,
                recorded: &candidate,
                identity: IDENTITY,
                ownership: &Ownership::Nothing,
                liveness: &Liveness::Free,
            },
            measured: &grown,
        };
        assert!(matches!(
            clear(&fixture.site(), &verify),
            Err(Rejection::Stale {
                field: StaleField::Content,
                ..
            })
        ));
    }

    #[test]
    fn a_different_path_is_stale_even_with_the_same_identity() {
        let fixture = Fixture::target();
        let measurement = measured(100);
        let candidate = discovered(&fixture, &measurement);
        let mut moved = Fixture::target();
        moved.location = at("/work/other/target");
        let mandate = Mandate::default();
        let result = recheck(
            &moved.site(),
            &Recheck {
                mandate: &mandate,
                recorded: &candidate,
                identity: IDENTITY,
                ownership: &Ownership::Nothing,
                liveness: &Liveness::Free,
            },
        );
        assert!(matches!(
            result,
            Err(Rejection::Stale {
                field: StaleField::CanonicalPath,
                ..
            })
        ));
    }

    const APFS: Capability = Capability::Shares {
        filesystem: Filesystem::Apfs,
        method: Method::CloneAndSwap,
    };

    fn share_check<'a>(candidate: &'a Candidate, liveness: &'a Liveness) -> ShareCheck<'a> {
        ShareCheck {
            recorded: candidate,
            identity: IDENTITY,
            liveness,
            capability: APFS,
        }
    }

    #[test]
    fn sharing_needs_a_lock_protocol_a_capable_filesystem_and_no_writer() {
        let fixture = Fixture::target();
        let candidate = discovered(&fixture, &measured(100));
        let cleared =
            clear_share(&fixture.site(), &share_check(&candidate, &Liveness::Free)).unwrap();
        assert_eq!(cleared.method(), Method::CloneAndSwap);
        assert_eq!(cleared.identity(), IDENTITY);

        let mut unsupported = share_check(&candidate, &Liveness::Free);
        unsupported.capability = Capability::of(Filesystem::Other);
        assert!(matches!(
            clear_share(&fixture.site(), &unsupported),
            Err(Rejection::CannotShare {
                filesystem: Filesystem::Other,
                ..
            })
        ));

        let held = Liveness::Held {
            lock: at("/work/app/target/debug/.cargo-lock"),
            protocol: Protocol::Cargo,
        };
        assert!(matches!(
            clear_share(&fixture.site(), &share_check(&candidate, &held)),
            Err(Rejection::Busy { .. })
        ));
    }

    #[test]
    fn a_cache_without_a_known_lock_is_never_rewritten() {
        let mut fixture = Fixture::target();
        fixture.listing = tagged_listing();
        let candidate = discovered(&fixture, &measured(100));
        assert!(matches!(
            clear_share(&fixture.site(), &share_check(&candidate, &Liveness::Free)),
            Err(Rejection::NoLockProtocol {
                kind: Kind::TaggedCache,
                ..
            })
        ));
    }

    #[test]
    fn sharing_loses_nothing_so_tier_ownership_and_contents_do_not_matter() {
        let fixture = Fixture::target();
        let candidate = discovered(&fixture, &measured(100));
        let stages = Gate::ALL
            .iter()
            .map(|gate| {
                (
                    *gate,
                    matches!(
                        check(
                            *gate,
                            &fixture.site(),
                            Ask::Share(&share_check(&candidate, &Liveness::Free))
                        ),
                        Verdict::Abstain
                    ),
                )
            })
            .filter(|(_, abstained)| *abstained)
            .map(|(gate, _)| gate)
            .collect::<Vec<_>>();
        assert_eq!(stages, vec![Gate::Tier, Gate::Ownership, Gate::Freshness]);
    }

    #[test]
    fn deletion_never_asks_about_locks_protocols_or_filesystems() {
        let fixture = Fixture::target();
        let candidate = discovered(&fixture, &measured(100));
        let mandate = Mandate::default();
        let recheck = Recheck {
            mandate: &mandate,
            recorded: &candidate,
            identity: IDENTITY,
            ownership: &Ownership::Nothing,
            liveness: &Liveness::Free,
        };
        for gate in [Gate::Protocol, Gate::Capability] {
            assert_eq!(
                check(gate, &fixture.site(), Ask::Recheck(&recheck)),
                Verdict::Abstain
            );
        }
    }

    #[test]
    fn what_its_owner_still_wants_is_refused_unless_the_caller_takes_it() {
        let fixture = Fixture::target();
        let candidate = discovered(&fixture, &measured(100));
        let settled_only = Mandate {
            tiers: TierGrant::ROUTINE,
            settlements: Admits::Settled,
        };
        let ask = |mandate: &Mandate| {
            recheck(
                &fixture.site(),
                &Recheck {
                    mandate,
                    recorded: &candidate,
                    identity: IDENTITY,
                    ownership: &Ownership::Nothing,
                    liveness: &Liveness::Free,
                },
            )
        };
        assert!(matches!(
            ask(&settled_only),
            Err(Rejection::Owned {
                settlement: Settlement::Unclaimed,
                ..
            })
        ));
        ask(&Mandate::default()).unwrap();
    }

    #[test]
    fn a_target_that_stopped_declaring_itself_is_refused_on_recheck() {
        let mut declared = Fixture::target();
        let mut child = Entries::default();
        child.file(b".rustc_info.json");
        child.dir(b"debug");
        let mut parent = Entries::default();
        parent.file(b"Cargo.toml");
        declared.listing = Listing::new(parent, child, Tags::cache(CacheTag::Absent));
        let candidate = discovered(&declared, &measured(100));
        assert_eq!(candidate.provenance(), Provenance::Declared);
        let inferred = Fixture::target();
        let mandate = Mandate::default();
        let result = recheck(
            &inferred.site(),
            &Recheck {
                mandate: &mandate,
                recorded: &candidate,
                identity: IDENTITY,
                ownership: &Ownership::Nothing,
                liveness: &Liveness::Free,
            },
        );
        assert!(matches!(result, Err(Rejection::ProvenanceChanged { .. })));
    }

    #[test]
    fn a_changed_kind_is_refused_on_recheck() {
        let fixture = Fixture::target();
        let measurement = measured(100);
        let candidate = discovered(&fixture, &measurement);
        let mut changed = Fixture::target();
        changed.listing = tagged_listing();
        let mandate = Mandate {
            tiers: TierGrant::ROUTINE.with(Tier::Reinstallable),
            settlements: Admits::Anything,
        };
        let result = recheck(
            &changed.site(),
            &Recheck {
                mandate: &mandate,
                recorded: &candidate,
                identity: IDENTITY,
                ownership: &Ownership::Nothing,
                liveness: &Liveness::Free,
            },
        );
        assert!(matches!(result, Err(Rejection::KindChanged { .. })));
    }
}
