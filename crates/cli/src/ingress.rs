use std::path::PathBuf;

use serde::Deserialize;
use storage_scout_core::artifact::{Kind, Tier};
use storage_scout_core::gate::TierGrant;
use storage_scout_core::ownership::{Keep, Role};

use crate::auto::{AutoPolicy, Selection};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Syntax(String),
    #[error("select.older_than was removed: storage-scout no longer judges by age")]
    RetiredAge,
    #[error("select.min_size was removed: waste of any size is waste")]
    RetiredMinSize,
    #[error(
        "[trigger] was removed: storage-scout removes waste when it appears, not when the disk fills"
    )]
    RetiredTrigger,
    #[error("select.roots must list at least one root")]
    NoRoots,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    select: SelectDocument,
    report: Option<ReportDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectDocument {
    roots: Vec<PathBuf>,
    kinds: Option<Vec<Kind>>,
    exclude: Option<Vec<PathBuf>>,
    include_tier: Option<Vec<Tier>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportDocument {
    log_file: Option<PathBuf>,
}

pub(crate) fn policy(text: &str) -> Result<AutoPolicy, PolicyError> {
    let table = toml::from_str::<toml::Table>(text)
        .map_err(|error| PolicyError::Syntax(error.to_string()))?;
    if table
        .get("select")
        .and_then(toml::Value::as_table)
        .is_some_and(|select| select.contains_key("older_than"))
    {
        return Err(PolicyError::RetiredAge);
    }
    if table.contains_key("trigger") {
        return Err(PolicyError::RetiredTrigger);
    }
    if table
        .get("select")
        .and_then(toml::Value::as_table)
        .is_some_and(|select| select.contains_key("min_size"))
    {
        return Err(PolicyError::RetiredMinSize);
    }
    let document = toml::from_str::<PolicyDocument>(text)
        .map_err(|error| PolicyError::Syntax(error.to_string()))?;
    if document.select.roots.is_empty() {
        return Err(PolicyError::NoRoots);
    }
    Ok(AutoPolicy {
        selection: Selection {
            roots: document.select.roots,
            kinds: document.select.kinds.unwrap_or_default(),
            excludes: document.select.exclude.unwrap_or_default(),
            tiers: TierGrant::of(document.select.include_tier.unwrap_or_default()),
        },
        log_file: document.report.and_then(|report| report.log_file),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub schema: String,
    pub role: Role,
    pub keep: Keep,
    pub keyed_to: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RoleDocument {
    Scratch,
    Cache,
}

#[derive(Deserialize)]
struct OwnerDocument {
    schema: String,
    kept: bool,
    role: Option<RoleDocument>,
    keyed_to: Option<PathBuf>,
}

pub(crate) const OWNER_SCHEMA_SUFFIX: &str = "-temp-owner-v1";
pub(crate) const OWNER_LIMIT: u64 = 64 * 1024;

pub(crate) fn owner(bytes: &[u8]) -> Option<Declaration> {
    let document = match serde_json::from_slice::<OwnerDocument>(bytes) {
        Ok(document) => document,
        Err(_foreign) => return None,
    };
    if !document.schema.ends_with(OWNER_SCHEMA_SUFFIX) {
        return None;
    }
    Some(Declaration {
        schema: document.schema,
        role: match document.role {
            None | Some(RoleDocument::Scratch) => Role::Scratch,
            Some(RoleDocument::Cache) => Role::Cache,
        },
        keep: if document.kept {
            Keep::Kept
        } else {
            Keep::Released
        },
        keyed_to: document.keyed_to,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_names_only_where_to_look() {
        let policy = policy(
            "[select]\nroots = ['/work']\nkinds = ['rust-target']\nexclude = ['/work/keep']\ninclude_tier = ['reinstallable']\n[report]\nlog_file = '/log'\n",
        )
        .unwrap();
        assert_eq!(policy.selection.roots, vec![PathBuf::from("/work")]);
        assert_eq!(policy.selection.kinds, vec![Kind::RustTarget]);
        assert_eq!(policy.selection.excludes, vec![PathBuf::from("/work/keep")]);
        assert!(policy.selection.tiers.admits(Tier::Reinstallable));
        assert_eq!(policy.log_file, Some(PathBuf::from("/log")));
    }

    #[test]
    fn retired_settings_are_refused_with_the_reason() {
        for (text, error) in [
            (
                "[select]\nroots = ['/work']\nolder_than = '3d'\n",
                PolicyError::RetiredAge,
            ),
            (
                "[select]\nroots = ['/work']\nmin_size = '0'\n",
                PolicyError::RetiredMinSize,
            ),
            (
                "[trigger]\nmin_free = '1G'\n[select]\nroots = ['/work']\n",
                PolicyError::RetiredTrigger,
            ),
            ("[select]\nroots = []\n", PolicyError::NoRoots),
        ] {
            assert_eq!(policy(text), Err(error), "{text}");
        }
        assert!(matches!(
            policy("[select]\nroots = ['/work']\nguess = 1\n"),
            Err(PolicyError::Syntax(_))
        ));
    }
}
