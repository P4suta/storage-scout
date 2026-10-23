use std::path::{Path, PathBuf};

use serde::Serialize;
use storage_scout::AutoPolicy;
use storage_scout::core::artifact::{Kind, Tier};

#[derive(Serialize)]
struct Document<'a> {
    select: Select<'a>,
    report: Report<'a>,
}

#[derive(Serialize)]
struct Select<'a> {
    roots: &'a [PathBuf],
    kinds: &'a [Kind],
    exclude: &'a [PathBuf],
    include_tier: Vec<Tier>,
}

#[derive(Serialize)]
struct Report<'a> {
    log_file: Option<&'a Path>,
}

#[expect(
    clippy::unwrap_used,
    reason = "encoding an admitted policy is a verification obligation"
)]
pub(crate) fn check(input: &[u8]) {
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let Ok(policy) = AutoPolicy::parse(text) else {
        return;
    };
    assert_ne!(policy.selection.roots, Vec::<PathBuf>::new());
    let document = Document {
        select: Select {
            roots: &policy.selection.roots,
            kinds: &policy.selection.kinds,
            exclude: &policy.selection.excludes,
            include_tier: Tier::ALL
                .iter()
                .copied()
                .filter(|tier| policy.selection.tiers.admits(*tier))
                .collect(),
        },
        report: Report {
            log_file: policy.log_file.as_deref(),
        },
    };
    let encoded = toml::to_string(&document).unwrap();
    assert_eq!(AutoPolicy::parse(&encoded), Ok(policy));
}
