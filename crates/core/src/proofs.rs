use alloc::string::String;

use crate::location::{Location, Syntax};
use crate::ownership::{
    Admits, Changes, Head, Keep, Key, Landing, Marker, OwnerLock, Ownership, Role, Settlement,
    Upstream, Worktree,
};
use crate::prune::{Rule, Session, Stage, doomed};
use crate::size::Bytes;

#[kani::proof]
#[kani::unwind(80)]
fn managed_removal_requires_current_complete_unreferenced_reinstallable_evidence() {
    use crate::artifact::Tier;
    use crate::candidate::CandidateId;
    use crate::gate::TierGrant;
    use crate::managed::{self, Completeness, References, Request, Resource};
    use core::str::FromStr;
    let id =
        CandidateId::from_str("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let other =
        CandidateId::from_str("2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();
    let same: bool = kani::any();
    let granted: bool = kani::any();
    let resource: Resource = kani::any();
    let references: References = kani::any();
    let completeness: Completeness = kani::any();
    let current = if same { &id } else { &other };
    let tiers = if granted {
        TierGrant::ROUTINE.with(Tier::Reinstallable)
    } else {
        TierGrant::ROUTINE
    };
    let accepted = managed::clear(&Request {
        resource,
        references,
        completeness,
        recorded: &id,
        current,
        tiers,
    });
    let expected = matches!(
        resource,
        Resource::Toolchain | Resource::Image | Resource::BuildCache
    ) && references == References::Unused
        && completeness == Completeness::Complete
        && granted
        && same;
    assert_eq!(accepted.is_ok(), expected);
    if let Ok(clearance) = accepted {
        assert_eq!(clearance.id(), &id);
        assert_eq!(clearance.resource(), resource);
    }
    kani::cover!(expected);
    kani::cover!(!expected);
}

#[kani::proof]
#[kani::unwind(18)]
fn concrete_version_requests_preserve_their_exact_installation() {
    use crate::managed::{References, version_bytes};
    let bytes: [u8; 16] = kani::any();
    assert_eq!(version_bytes(&bytes, &bytes), References::Referenced);
    kani::cover!(bytes.starts_with(b"v"));
    kani::cover!(!bytes.starts_with(b"v"));
}

#[kani::proof]
#[kani::unwind(18)]
fn version_normalization_removes_only_one_optional_ascii_prefix() {
    use crate::managed::normalized_version;
    let bytes: [u8; 17] = kani::any();
    if bytes.starts_with(b"v") {
        assert_eq!(normalized_version(&bytes), &bytes[1..]);
    } else {
        assert_eq!(normalized_version(&bytes), &bytes);
    }
    kani::cover!(bytes.starts_with(b"v"));
    kani::cover!(!bytes.starts_with(b"v"));
}

#[kani::proof]
#[kani::unwind(24)]
fn session_locks_are_single_components_or_are_refused() {
    let bytes: [u8; 16] = kani::any();
    if let Ok(name) = crate::prune::lock_name_bytes(&bytes) {
        kani::cover!(true);
        assert!(
            !name
                .as_bytes()
                .iter()
                .any(|byte| matches!(byte, 0 | b'/' | b'\\'))
        );
        assert!(
            name.as_bytes()
                .ends_with(crate::prune::LOCK_SUFFIX.as_bytes())
        );
        assert!(name.as_bytes().starts_with(&bytes));
    }
}

#[kani::proof]
fn source_checkouts_are_disposable_only_within_the_producers_contract() {
    use crate::artifact::{GitEntry, Kind, SourceArea, SourceDisposition, TreeContents};
    let kind = choose(Kind::ALL);
    let area = choose(&[
        SourceArea::Checkouts,
        SourceArea::Repositories,
        SourceArea::Packages,
        SourceArea::Git,
        SourceArea::Other,
    ]);
    let entry = choose(&[GitEntry::RepositoryDirectory, GitEntry::LinkedCheckout]);
    let expected = matches!(kind, Kind::OwnedScratch | Kind::OwnedCache)
        || (entry == GitEntry::RepositoryDirectory
            && ((kind == Kind::SwiftPackageBuild
                && matches!(area, SourceArea::Checkouts | SourceArea::Repositories))
                || (kind == Kind::GleamBuild
                    && matches!(area, SourceArea::Packages | SourceArea::Git))));
    kani::cover!(expected);
    kani::cover!(!expected);
    assert_eq!(
        kind.contents().git(area, entry) == SourceDisposition::Disposable,
        expected
    );
    if kind.contents() == TreeContents::Artifacts {
        assert_eq!(
            kind.contents().git(area, entry),
            SourceDisposition::Preserve
        );
    }
}

#[kani::proof]
#[kani::unwind(73)]
fn checkout_release_requires_a_live_unchanged_unlocked_witness() {
    use crate::ownership::{OwnerLock, ReleaseEvidence};
    let evidence = ReleaseEvidence {
        recorded_identity: Identity {
            volume: kani::any(),
            file: kani::any(),
        },
        identity: Identity {
            volume: kani::any(),
            file: kani::any(),
        },
        recorded_digest: kani::any(),
        digest: kani::any(),
        monitor: choose(&[
            OwnerLock::Held,
            OwnerLock::Free,
            OwnerLock::Missing,
            OwnerLock::Unreadable,
        ]),
        writers: choose(&[
            OwnerLock::Held,
            OwnerLock::Free,
            OwnerLock::Missing,
            OwnerLock::Unreadable,
        ]),
    };
    let valid = evidence.recorded_identity == evidence.identity
        && evidence.recorded_digest == evidence.digest
        && evidence.monitor == OwnerLock::Held
        && evidence.writers == OwnerLock::Free;
    kani::cover!(valid);
    kani::cover!(!valid);
    assert_eq!(evidence.settlement() == Settlement::Released, valid);
    assert_eq!(evidence.settlement() == Settlement::Active, !valid);
}

#[kani::proof]
#[kani::unwind(73)]
fn release_records_round_trip_and_reject_truncated_or_extended_inputs() {
    use crate::ownership::{RELEASE_RECORD_BYTES, ReleaseRecord};
    let record = ReleaseRecord {
        identity: Identity {
            volume: kani::any(),
            file: kani::any(),
        },
        digest: kani::any(),
    };
    let encoded = record.encode();
    assert_eq!(ReleaseRecord::decode(&encoded), Some(record));
    let length: usize = kani::any();
    kani::assume(length < RELEASE_RECORD_BYTES);
    assert!(ReleaseRecord::decode(&encoded[..length]).is_none());
    let mut extended = [0; RELEASE_RECORD_BYTES + 1];
    extended[..RELEASE_RECORD_BYTES].copy_from_slice(&encoded);
    assert!(ReleaseRecord::decode(&extended).is_none());
    kani::cover!(length == 0);
    kani::cover!(length == RELEASE_RECORD_BYTES - 1);
}

#[kani::proof]
fn volume_attribution_accounts_for_every_used_byte() {
    let used = Bytes::new(kani::any());
    let measured = Bytes::new(kani::any());
    let report = crate::size::Reconciliation::new(used, measured);
    kani::cover!(measured > used);
    kani::cover!(measured < used);
    assert!(report.attributed <= used);
    assert_eq!(
        u128::from(report.attributed.get()) + u128::from(report.unattributed.get()),
        u128::from(used.get())
    );
    assert_eq!(
        u128::from(report.attributed.get()) + u128::from(report.overcount.get()),
        u128::from(measured.get())
    );
}

#[kani::proof]
fn an_incomplete_measurement_never_grants_reclamation() {
    use crate::candidate::{Allocation, Usage};
    let failures: u64 = kani::any();
    kani::assume(failures > 0);
    let usage = Usage {
        logical: Bytes::new(kani::any()),
        allocation: Allocation::Measured {
            allocated: Bytes::new(kani::any()),
            reclaimable: Bytes::new(kani::any()),
        },
        failures,
    };
    assert!(usage.reclaimable().is_none());
    kani::cover!(true);
}

#[kani::proof]
fn reclamation_never_attributes_volume_counters() {
    use crate::size::Reclamation;

    let changed: bool = kani::any();
    kani::cover!(changed);
    kani::cover!(!changed);
    let result = if changed {
        Reclamation::Unattributable
    } else {
        Reclamation::Unchanged
    };
    assert_eq!(
        result.observed(),
        if changed { None } else { Some(Bytes::ZERO) }
    );
}

use crate::candidate::Identity;
use crate::share::{Attributes, Extras, Method, Mode, Owner, Pairing, Record, Sharing, pair};

#[cfg(kani)]
fn choose<T: Copy>(values: &[T]) -> T {
    let index: usize = kani::any();
    kani::assume(index < values.len());
    values[index]
}

#[cfg(kani)]
fn root() -> Location {
    Location::parse_str(Syntax::Unix, "/").unwrap()
}

#[kani::proof]
#[kani::unwind(4)]
fn worktree_landing_requires_clean_and_upstream_evidence() {
    let changes = choose(&[Changes::Clean, Changes::Dirty]);
    let upstream = match choose(&[0u8, 1, 2]) {
        0 => Upstream::None,
        1 => Upstream::Tracking {
            name: String::new(),
        },
        _ => Upstream::Gone {
            name: String::new(),
        },
    };
    let gone = matches!(upstream, Upstream::Gone { .. });
    let detached: bool = kani::any();
    let head = if detached {
        Head::Detached
    } else {
        Head::Branch {
            name: String::new(),
            upstream,
        }
    };
    let landing = match choose(&[0u8, 1, 2, 3]) {
        0 => Landing::NoDefaultBranch,
        1 => Landing::NoOwnWork {
            into: String::new(),
        },
        2 => Landing::Contained {
            into: String::new(),
        },
        _ => Landing::NotContained,
    };
    let supported = (!detached && gone)
        || matches!(landing, Landing::Contained { .. })
        || (detached && matches!(landing, Landing::NoOwnWork { .. }));
    let worktree = Worktree::Linked {
        root: root(),
        changes,
        head,
        landing,
    };
    assert_eq!(
        worktree.settlement() == Settlement::Landed,
        changes == Changes::Clean && supported
    );
    kani::cover!(worktree.settlement() == Settlement::Landed);
    kani::cover!(worktree.settlement() == Settlement::Active);
}

#[kani::proof]
#[kani::unwind(5)]
fn nested_markers_protect_but_never_release_their_parent() {
    let keep = choose(&[Keep::Kept, Keep::Released]);
    let lock = choose(&[
        OwnerLock::Held,
        OwnerLock::Free,
        OwnerLock::Missing,
        OwnerLock::Unreadable,
    ]);
    let marker = Marker {
        directory: root(),
        schema: String::new(),
        role: Role::Scratch,
        keep,
        lock,
        key: Key::Unkeyed,
    };
    let expected = marker.settlement();
    let resolved = Ownership::resolve(alloc::vec![], alloc::vec![marker], None).settlement();
    assert_eq!(
        resolved,
        if matches!(expected, Settlement::Active | Settlement::Kept) {
            expected
        } else {
            Settlement::Unclaimed
        }
    );
    kani::cover!(resolved == Settlement::Unclaimed);
    kani::cover!(resolved == Settlement::Active);
    kani::cover!(resolved == Settlement::Kept);
}

#[kani::proof]
fn reaping_projects_only_settled_candidate_ids() {
    let settlement = choose(Settlement::ALL);
    let value: u64 = kani::any();
    let selected = crate::select::eligible(settlement, &value);
    let settled = matches!(settlement, Settlement::Released | Settlement::Landed);
    assert_eq!(selected.is_some(), settled);
    if let Some(selected) = selected {
        assert!(core::ptr::eq(selected, &value));
    }
    kani::cover!(settled);
    kani::cover!(!settled);
}

#[cfg(kani)]
fn record() -> Record {
    Record {
        location: root(),
        len: kani::any(),
        identity: Identity {
            volume: kani::any(),
            file: kani::any(),
        },
        method: choose(&[Method::CloneAndSwap, Method::DedupeRange]),
        links: kani::any(),
        owner: choose(&[Owner::Caller, Owner::Other]),
        mode: choose(&[Mode::Plain, Mode::Executable]),
        extras: match choose(&[0u8, 1, 2]) {
            0 => Extras::Plain(Attributes(kani::any())),
            1 => Extras::Special,
            _ => Extras::Unobserved,
        },
        sharing: if kani::any() {
            Sharing::Unknown
        } else {
            Sharing::Cluster(kani::any())
        },
    }
}

#[kani::proof]
#[kani::unwind(18)]
fn sharing_preserves_identity_ownership_and_replacement_attributes() {
    let keeper = record();
    let duplicate = record();
    let outcome = pair(&keeper, &duplicate);
    if matches!(outcome, Pairing::Share | Pairing::AlreadyShared) {
        assert_ne!(keeper.identity, duplicate.identity);
        assert_eq!(keeper.identity.volume, duplicate.identity.volume);
        assert_eq!(keeper.len, duplicate.len);
    }
    if outcome == Pairing::Share {
        assert_eq!(duplicate.owner, Owner::Caller);
        if duplicate.method == Method::CloneAndSwap {
            assert!(duplicate.links <= 1);
            assert_eq!(duplicate.mode, Mode::Plain);
            assert!(
                matches!((keeper.extras, duplicate.extras), (Extras::Plain(left), Extras::Plain(right)) if left == right)
            );
        }
    }
    kani::cover!(outcome == Pairing::Share);
    kani::cover!(outcome == Pairing::AlreadyShared);
    kani::cover!(matches!(outcome, Pairing::Refused { .. }));
}

#[kani::proof]
fn settled_admission_is_exact() {
    let settlement = choose(Settlement::ALL);
    let admitted = Admits::Settled.admits(settlement);
    assert_eq!(
        admitted,
        matches!(settlement, Settlement::Released | Settlement::Landed)
    );
    kani::cover!(admitted);
    kani::cover!(!admitted);
}

#[kani::proof]
fn owner_locks_require_presence() {
    let protocol = choose(&[
        crate::lock::Protocol::Cargo,
        crate::lock::Protocol::SwiftPackage,
        crate::lock::Protocol::Gleam,
        crate::lock::Protocol::TempOwner,
    ]);
    let presence = protocol.presence();
    assert_eq!(
        presence == crate::lock::Presence::Required,
        matches!(
            protocol,
            crate::lock::Protocol::TempOwner | crate::lock::Protocol::SwiftPackage
        )
    );
    kani::cover!(presence == crate::lock::Presence::Required);
    kani::cover!(presence == crate::lock::Presence::Optional);
}

#[kani::proof]
fn deletion_never_accepts_an_unsettled_owner() {
    let settlement = choose(Settlement::ALL);
    let admits = choose(&[Admits::Anything, Admits::Settled, Admits::Unkept]);
    let permitted = admits.deletion(settlement);
    assert_eq!(
        permitted,
        matches!(settlement, Settlement::Released | Settlement::Landed)
    );
    assert_eq!(
        crate::ownership::DeletionGrant::new(admits, settlement).is_some(),
        permitted
    );
    kani::cover!(permitted);
    kani::cover!(!permitted);
}

#[kani::proof]
#[kani::unwind(4)]
fn marker_release_requires_owner_clearance() {
    let marker = Marker {
        directory: root(),
        schema: String::new(),
        role: choose(&[Role::Scratch, Role::Cache]),
        keep: choose(&[Keep::Kept, Keep::Released]),
        lock: choose(&[
            OwnerLock::Held,
            OwnerLock::Free,
            OwnerLock::Missing,
            OwnerLock::Unreadable,
        ]),
        key: choose(&[Key::Unkeyed, Key::Present, Key::Gone, Key::Unknown]),
    };
    let settlement = marker.settlement();
    let released = marker.keep == Keep::Released
        && marker.lock == OwnerLock::Free
        && (marker.role == Role::Scratch || marker.key == Key::Gone);
    assert_eq!(settlement == Settlement::Released, released);
    assert_eq!(settlement == Settlement::Kept, marker.keep == Keep::Kept);
    assert!(!matches!(
        settlement,
        Settlement::Landed | Settlement::Unclaimed
    ));
    kani::cover!(settlement == Settlement::Released);
    kani::cover!(settlement == Settlement::Active);
    kani::cover!(settlement == Settlement::Kept);
}

#[kani::proof]
#[kani::solver(z3)]
fn byte_arithmetic_matches_mathematical_clamping() {
    let left: u64 = kani::any();
    let right: u64 = kani::any();
    let sum = u128::from(left) + u128::from(right);
    let clamped = sum.min(u128::from(u64::MAX));
    assert_eq!(
        u128::from(Bytes::new(left).saturating_add(Bytes::new(right)).get()),
        clamped
    );
    let difference = Bytes::new(left).saturating_sub(Bytes::new(right)).get();
    if left >= right {
        assert_eq!(difference, left - right);
    } else {
        assert_eq!(difference, 0);
    }
    kani::cover!(sum > u128::from(u64::MAX));
    kani::cover!(left < right);
}

#[kani::proof]
#[kani::unwind(5)]
fn pruning_preserves_every_newest_finalized_session() {
    let stamps: [u128; 3] = kani::any();
    let finalized: [bool; 3] = kani::any();
    let sessions = core::array::from_fn::<_, 3, _>(|index| Session {
        name: ["a", "b", "c"][index],
        lock: "lock",
        stage: if finalized[index] {
            Stage::Finalized {
                stamp: stamps[index],
            }
        } else {
            Stage::Working
        },
    });
    let removed = doomed(&sessions);
    for (index, session) in sessions.iter().enumerate() {
        let newer = sessions.iter().any(|other| {
            matches!((session.stage, other.stage),
            (Stage::Finalized { stamp }, Stage::Finalized { stamp: other }) if other > stamp)
        });
        let expected = match session.stage {
            Stage::Working => Some(Rule::AbandonedSession),
            Stage::Finalized { .. } if newer => Some(Rule::SupersededSession),
            Stage::Finalized { .. } => None,
        };
        let actual = removed
            .iter()
            .find(|(removed, _)| removed.name == session.name)
            .map(|(_, rule)| *rule);
        assert_eq!(actual, expected);
        kani::cover!(finalized[index] && !newer);
        kani::cover!(newer);
    }
    assert!(removed.len() <= sessions.len());
}

#[kani::proof]
#[kani::solver(z3)]
#[kani::unwind(5)]
fn byte_total_is_associative_and_saturating() {
    let values: [u64; 3] = kani::any();
    let bytes = values.map(Bytes::new);
    let exact = values.into_iter().map(u128::from).sum::<u128>();
    assert_eq!(
        u128::from(Bytes::total(bytes).get()),
        exact.min(u128::from(u64::MAX))
    );
    assert_eq!(
        bytes[0].saturating_add(bytes[1]).saturating_add(bytes[2]),
        bytes[0].saturating_add(bytes[1].saturating_add(bytes[2]))
    );
    kani::cover!(exact > u128::from(u64::MAX));
    kani::cover!(exact == 0);
}
