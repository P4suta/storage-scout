use std::path::PathBuf;

use serde::Deserialize;
use storage_scout_core::artifact::{Kind, Tier};
use storage_scout_core::gate::TierGrant;
use storage_scout_core::ownership::{Keep, Role};
use storage_scout_core::select::Trigger;
use storage_scout_core::size::{Bytes, SizeError};

use crate::auto::{AutoPolicy, Selection, Watch};
use crate::scan::DEFAULT_MIN_SIZE;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Syntax(String),
    #[error("select.older_than was removed: storage-scout no longer judges by age")]
    RetiredAge,
    #[error("{field}: {error}")]
    Size {
        field: &'static str,
        error: SizeError,
    },
    #[error("trigger.target_free must be greater than trigger.min_free")]
    TargetNotAboveTrigger,
    #[error("trigger.volume must name a path on the watched volume")]
    EmptyVolume,
    #[error("select.roots must list at least one root")]
    NoRoots,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    trigger: Option<TriggerDocument>,
    select: SelectDocument,
    report: Option<ReportDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TriggerDocument {
    volume: PathBuf,
    min_free: String,
    target_free: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectDocument {
    roots: Vec<PathBuf>,
    kinds: Option<Vec<Kind>>,
    min_size: Option<String>,
    exclude: Option<Vec<PathBuf>>,
    include_tier: Option<Vec<Tier>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportDocument {
    log_file: Option<PathBuf>,
}

fn size(field: &'static str, text: &str) -> Result<Bytes, PolicyError> {
    text.parse::<Bytes>()
        .map_err(|error| PolicyError::Size { field, error })
}

fn watch(trigger: TriggerDocument) -> Result<Watch, PolicyError> {
    let min_free = size("trigger.min_free", &trigger.min_free)?;
    let target_free = trigger
        .target_free
        .as_deref()
        .map(|target| size("trigger.target_free", target))
        .transpose()?;
    if target_free.is_some_and(|target| target <= min_free) {
        return Err(PolicyError::TargetNotAboveTrigger);
    }
    if trigger.volume.as_os_str().is_empty() {
        return Err(PolicyError::EmptyVolume);
    }
    Ok(Watch {
        volume: trigger.volume,
        trigger: Trigger {
            min_free,
            target_free,
        },
    })
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
    let document = toml::from_str::<PolicyDocument>(text)
        .map_err(|error| PolicyError::Syntax(error.to_string()))?;
    let watch = document.trigger.map(watch).transpose()?;
    if document.select.roots.is_empty() {
        return Err(PolicyError::NoRoots);
    }
    let min_size = document
        .select
        .min_size
        .as_deref()
        .map(|minimum| size("select.min_size", minimum))
        .transpose()?
        .unwrap_or(DEFAULT_MIN_SIZE);
    Ok(AutoPolicy {
        watch,
        selection: Selection {
            roots: document.select.roots,
            kinds: document.select.kinds.unwrap_or_default(),
            min_size,
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
