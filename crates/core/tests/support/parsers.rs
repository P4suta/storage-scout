use storage_scout_core::artifact::{Kind, SourceArea, Tier};
use storage_scout_core::candidate::CandidateId;
use storage_scout_core::location::{Case, Location, Syntax};
use storage_scout_core::macho;
use storage_scout_core::prune::{Object, Session};
use storage_scout_core::size::Bytes;

pub(crate) fn check(input: &[u8]) {
    let area = SourceArea::of(input);
    assert_eq!(
        area != SourceArea::Other,
        [
            b"checkouts".as_slice(),
            b"repositories",
            b"packages",
            b"git"
        ]
        .contains(&input)
    );
    if let Some(record) = storage_scout_core::ownership::ReleaseRecord::decode(input) {
        assert_eq!(record.encode().as_slice(), input);
    }
    let _header = macho::header(input);
    let _symtab = macho::symtab(input, u32::MAX);
    let _debug_objects = macho::debug_objects(input).count();
    if let Some(object) = Object::parse(input) {
        assert_eq!(object.name, input);
        assert_ne!(object.unit, []);
        assert_ne!(object.invocation, []);
        assert_eq!(Object::parse(object.name), Some(object));
    }
    for syntax in [Syntax::Unix, Syntax::Windows] {
        if let Ok(location) = Location::parse(syntax, input) {
            for case in [Case::Sensitive, Case::Insensitive] {
                assert!(location.contains(&location, case));
                assert!(location.same(&location, case));
                if let Some(parent) = location.parent() {
                    assert!(parent.contains(&location, case));
                    assert!(!location.contains(&parent, case));
                }
            }
            if core::str::from_utf8(input).is_ok() {
                assert_eq!(
                    Location::parse_str(syntax, &location.to_string()),
                    Ok(location)
                );
            }
        }
    }
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let normalized = match text.strip_prefix('v') {
        Some(version) => version,
        None => text,
    };
    let expected = if normalized.is_empty() {
        storage_scout_core::managed::References::Unknown
    } else {
        storage_scout_core::managed::References::Referenced
    };
    assert_eq!(
        storage_scout_core::managed::version_reference(text, text),
        expected
    );
    for installed in ["1.98.1", "nightly-2026-10-01", "v4.29.0"] {
        let _reference = storage_scout_core::managed::version_reference(text, installed);
    }
    if let Ok(kind) = text.parse::<Kind>() {
        assert_eq!(kind.as_str().parse::<Kind>(), Ok(kind));
    }
    if let Ok(tier) = text.parse::<Tier>() {
        assert_eq!(tier.as_str().parse::<Tier>(), Ok(tier));
    }
    if let Ok(id) = text.parse::<CandidateId>() {
        assert_eq!(id.as_str().parse::<CandidateId>(), Ok(id.clone()));
        assert_eq!(id.as_str().len(), 64);
    }
    if let Ok(bytes) = text.parse::<Bytes>() {
        assert_eq!(bytes.get().to_string().parse::<Bytes>(), Ok(bytes));
    }
    if let Some(session) = Session::parse(text) {
        assert_eq!(Session::parse(session.name), Some(session));
        assert_eq!(
            session.lock_name().map(|name| name.as_bytes().to_vec()),
            Ok(format!("{}.lock", session.lock).into_bytes())
        );
        assert!(session.name.starts_with(session.lock));
    }
}
