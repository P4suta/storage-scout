use super::*;

#[kani::proof]
#[kani::unwind(4)]
fn tier_grants_preserve_previous_permissions_and_add_only_the_requested_cost() {
    let previous = TierGrant {
        reinstallable: kani::any(),
        expensive: kani::any(),
    };
    let next: usize = kani::any();
    let queried: usize = kani::any();
    kani::assume(next < Tier::ALL.len() && queried < Tier::ALL.len());
    let next = Tier::ALL[next];
    let queried = Tier::ALL[queried];
    assert_eq!(
        previous.with(next).admits(queried),
        previous.admits(queried) || queried == next
    );
    kani::cover!(next == Tier::Expensive);
    kani::cover!(next == Tier::Reinstallable);
}

#[kani::proof]
#[kani::unwind(14)]
fn pipeline_never_ignores_a_refusal() {
    let rejected: [bool; 12] = kani::any();
    assert_eq!(rejected.len(), Gate::ALL.len());
    let identification = Identification {
        kind: Kind::RustTarget,
        provenance: Provenance::Inferred,
    };
    let mut index = 0usize;
    let outcome = pipeline(|_| {
        let rejects = rejected[index];
        index += 1;
        if rejects {
            Verdict::Reject(Rejection::NoRoots)
        } else {
            Verdict::Pass(Note::Identified { identification })
        }
    });
    assert_eq!(
        outcome.is_ok(),
        !rejected.into_iter().any(core::convert::identity)
    );
    if let Ok(found) = &outcome {
        assert_eq!(*found, Some(identification));
        assert_eq!(index, Gate::ALL.len());
    }
    kani::cover!(outcome.is_ok());
    kani::cover!(matches!(outcome, Err(Rejection::NoRoots)));
}

#[kani::proof]
#[kani::unwind(14)]
fn pipeline_requires_identification_and_accepts_abstentions() {
    let identifies: bool = kani::any();
    let identification = Identification {
        kind: Kind::RustTarget,
        provenance: Provenance::Declared,
    };
    let outcome = pipeline(|gate| {
        if identifies && gate == Gate::Evidence {
            Verdict::Pass(Note::Identified { identification })
        } else {
            Verdict::Abstain
        }
    });
    assert_eq!(
        outcome,
        Ok(if identifies {
            Some(identification)
        } else {
            None
        })
    );
    kani::cover!(identifies);
    kani::cover!(!identifies);
}
