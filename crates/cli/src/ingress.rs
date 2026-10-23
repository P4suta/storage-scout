use std::path::PathBuf;

use serde::Deserialize;
use storage_scout_core::artifact::{Kind, Tier};
use storage_scout_core::gate::TierGrant;
use storage_scout_core::ownership::{Keep, Role};

use crate::auto::{AutoPolicy, Selection};

#[cfg(test)]
mod managed_tests {
    use super::*;
    use serde_json::json;
    use storage_scout_core::managed::{References, Resource, version_reference};

    #[test]
    fn engine_usage_keeps_exact_bytes_and_unknown_reference_states() {
        let data = json!({
            "ImageUsage": {"TotalCount": 3, "Items": [
                {"Id":"tagged", "RepoTags":["app:latest"], "RepoDigests":[], "Containers":0, "Size":12345},
                {"Id":"dangling", "RepoTags":[], "RepoDigests":[], "Containers":0, "Size":6789},
                {"Id":"unknown", "RepoTags":[], "RepoDigests":[], "Containers":-1, "Size":-1}
            ]},
            "BuildCacheUsage": {"TotalCount":2, "Items":[
                {"ID":"unused-cache", "InUse":false, "Size":321},
                {"ID":"busy-cache", "InUse":true, "Size":654}
            ]},
            "VolumeUsage": {"TotalCount":1, "Items":[{"Name":"source-data", "UsageData":{"Size":9876, "RefCount":0}}]},
            "ContainerUsage": {"TotalCount":1, "Items":[{"Id":"stopped", "Names":["/work"], "SizeRw":42}]}
        });
        let usage = engine_usage(serde_json::from_value(data.clone()).unwrap()).unwrap();
        let find = |name: &str| usage.iter().find(|entry| entry.name == name).unwrap();
        assert_eq!(find("tagged").bytes.unwrap().get(), 12345);
        assert_eq!(find("tagged").references, References::Referenced);
        assert_eq!(find("dangling").references, References::Unused);
        assert_eq!(find("unknown").references, References::Unknown);
        assert_eq!(find("unknown").bytes, None);
        assert_eq!(find("busy-cache").references, References::Referenced);
        assert_eq!(find("source-data").resource, Resource::Volume);
        assert_eq!(find("stopped").resource, Resource::Container);
        let mut truncated = data;
        truncated["ImageUsage"]["TotalCount"] = json!(4);
        assert_eq!(
            engine_usage(serde_json::from_value(truncated).unwrap())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Other
        );
        assert_eq!(
            engine_usage(bollard::models::SystemDataUsageResponse::default())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Other
        );
    }

    #[test]
    fn an_explicit_zero_count_allows_an_omitted_engine_item_list() {
        let empty = json!({
            "ImageUsage": {"TotalCount":0},
            "BuildCacheUsage": {"TotalCount":0},
            "VolumeUsage": {"TotalCount":0},
            "ContainerUsage": {"TotalCount":0}
        });
        assert!(
            engine_usage(serde_json::from_value(empty.clone()).unwrap())
                .unwrap()
                .is_empty()
        );
        let mut incomplete = empty;
        *incomplete
            .pointer_mut("/BuildCacheUsage/TotalCount")
            .unwrap() = json!(1);
        assert_eq!(
            engine_usage(serde_json::from_value(incomplete).unwrap())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Other
        );
    }

    #[test]
    fn engine_zero_values_may_be_omitted_but_missing_details_are_refused() {
        let empty = json!({
            "ImageUsage": {},
            "BuildCacheUsage": {},
            "VolumeUsage": {},
            "ContainerUsage": {}
        });
        assert!(
            engine_usage(serde_json::from_value(empty.clone()).unwrap())
                .unwrap()
                .is_empty()
        );
        for summary in [
            json!({"TotalCount":1}),
            json!({"TotalCount":-1}),
            json!({"ActiveCount":1}),
            json!({"TotalSize":1}),
            json!({"Reclaimable":1}),
        ] {
            let mut incomplete = empty.clone();
            *incomplete.pointer_mut("/BuildCacheUsage").unwrap() = summary;
            assert_eq!(
                engine_usage(serde_json::from_value(incomplete).unwrap())
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::Other
            );
        }
    }

    #[test]
    fn every_supported_pin_layout_protects_its_version_without_running_configuration() {
        for (name, text, tool, version) in [
            ("rust-toolchain", "1.98.1\n", "rust", "1.98.1"),
            (
                "rust-toolchain.toml",
                "[toolchain]\nchannel='nightly-2026-10-01'",
                "rust",
                "nightly-2026-10-01",
            ),
            (
                "Cargo.toml",
                "[package]\nrust-version='1.98'",
                "rust",
                "1.98.1",
            ),
            (
                "mise.toml",
                "[tools]\nrust=[{version='1.99.1'},'1.98.1']",
                "rust",
                "1.98.1",
            ),
            (
                "mise.toml",
                "[tasks.proof.tools]\nlean='v4.29.0'",
                "lean",
                "4.29.0",
            ),
            (
                "mise.toml",
                "[tools]\n'cargo:runner'={version='1',install_env={RUSTUP_TOOLCHAIN='1.99.1'}}",
                "rust",
                "1.99.1",
            ),
            (
                "mise.lock",
                "[[tools.rust]]\nversion='1.98.1'\nbackend='core:rust'",
                "rust",
                "1.98.1",
            ),
            (
                "lean-toolchain",
                "leanprover/lean4:v4.29.0\n",
                "lean",
                "4.29.0",
            ),
            (
                ".tool-versions",
                "rust 1.98.1 # retained\n",
                "rust",
                "1.98.1",
            ),
        ] {
            let pins = tool_pins(std::path::Path::new(name), text).unwrap();
            assert!(
                pins.iter().any(|pin| pin.tool == tool
                    && version_reference(&pin.version, version) == References::Referenced),
                "{name}"
            );
        }
        for text in [
            "[tools]\nrust=1",
            "[tools]\nrust={path='/external'}",
            "[tools\nrust='1.98.1'",
        ] {
            assert_eq!(
                tool_pins(std::path::Path::new("mise.toml"), text)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::Other
            );
        }
        let dynamic = tool_pins(
            std::path::Path::new("mise.toml"),
            "[tools]\nrust='{{ exec(command=\"dangerous\") }}'",
        )
        .unwrap();
        assert!(
            dynamic
                .iter()
                .all(|pin| version_reference(&pin.version, "1.99.1") == References::Unknown)
        );
    }
}

#[derive(Deserialize)]
struct EngineImage {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoTags")]
    tags: Option<Vec<String>>,
    #[serde(rename = "RepoDigests")]
    digests: Option<Vec<String>>,
    #[serde(rename = "Containers")]
    containers: Option<i64>,
    #[serde(rename = "Size")]
    size: Option<i64>,
}

#[derive(Deserialize)]
struct EngineCache {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "InUse")]
    in_use: Option<bool>,
    #[serde(rename = "Size")]
    size: Option<i64>,
}

#[derive(Deserialize)]
struct EngineVolume {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "UsageData")]
    usage: Option<bollard::models::VolumeUsageData>,
}

#[derive(Deserialize)]
struct EngineContainer {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Names")]
    names: Option<Vec<String>>,
    #[serde(rename = "SizeRw")]
    size: Option<i64>,
}

pub(crate) fn reported_bytes(value: Option<i64>) -> Option<storage_scout_core::size::Bytes> {
    match value {
        Some(value) => match u64::try_from(value) {
            Ok(bytes) => Some(storage_scout_core::size::Bytes::new(bytes)),
            Err(_negative) => None,
        },
        None => None,
    }
}

fn engine_items<T: serde::de::DeserializeOwned>(
    items: Option<Vec<serde_json::Value>>,
    count: Option<i64>,
    totals: [Option<i64>; 3],
) -> std::io::Result<Vec<T>> {
    let count = count.unwrap_or_default();
    let items = match items {
        Some(items) => items,
        None if count == 0 => Vec::new(),
        None => {
            return Err(std::io::Error::other(
                "the engine did not report detailed usage; API 1.53 or later is required",
            ));
        },
    };
    let length = i64::try_from(items.len()).map_err(std::io::Error::other)?;
    if count != length || (items.is_empty() && totals.into_iter().flatten().any(|total| total != 0))
    {
        return Err(std::io::Error::other(
            "the engine usage inventory is incomplete",
        ));
    }
    items
        .into_iter()
        .map(|value| serde_json::from_value(value).map_err(std::io::Error::other))
        .collect()
}

pub(crate) fn engine_usage(
    data: bollard::models::SystemDataUsageResponse,
) -> std::io::Result<Vec<crate::managed::ManagedUsage>> {
    use crate::managed::ManagedUsage;
    use storage_scout_core::managed::{References, Resource};
    let images = data
        .image_usage
        .ok_or_else(|| std::io::Error::other("missing engine image usage"))?;
    let cache = data
        .build_cache_usage
        .ok_or_else(|| std::io::Error::other("missing engine build cache usage"))?;
    let volumes = data
        .volume_usage
        .ok_or_else(|| std::io::Error::other("missing engine volume usage"))?;
    let containers = data
        .container_usage
        .ok_or_else(|| std::io::Error::other("missing engine container usage"))?;
    let mut inventory = Vec::new();
    for item in engine_items::<EngineImage>(
        images.items,
        images.total_count,
        [images.active_count, images.reclaimable, images.total_size],
    )? {
        let references = match (&item.tags, &item.digests, item.containers) {
            (Some(tags), Some(digests), Some(0)) if tags.is_empty() && digests.is_empty() => {
                References::Unused
            },
            (Some(tags), Some(digests), _) if !tags.is_empty() || !digests.is_empty() => {
                References::Referenced
            },
            (_, _, Some(count)) if count > 0 => References::Referenced,
            _ => References::Unknown,
        };
        let mut labels = item.tags.unwrap_or_default();
        labels.extend(item.digests.unwrap_or_default());
        inventory.push(ManagedUsage {
            resource: Resource::Image,
            name: item.id,
            bytes: reported_bytes(item.size),
            references,
            labels,
        });
    }
    for item in engine_items::<EngineCache>(
        cache.items,
        cache.total_count,
        [cache.active_count, cache.reclaimable, cache.total_size],
    )? {
        let references = match item.in_use {
            Some(true) => References::Referenced,
            Some(false) => References::Unused,
            None => References::Unknown,
        };
        inventory.push(ManagedUsage {
            resource: Resource::BuildCache,
            name: item.id,
            bytes: reported_bytes(item.size),
            references,
            labels: Vec::new(),
        });
    }
    for item in engine_items::<EngineVolume>(
        volumes.items,
        volumes.total_count,
        [
            volumes.active_count,
            volumes.reclaimable,
            volumes.total_size,
        ],
    )? {
        let references = match item.usage.as_ref().map(|usage| usage.ref_count) {
            Some(0) => References::Unused,
            Some(count) if count > 0 => References::Referenced,
            Some(_) | None => References::Unknown,
        };
        inventory.push(ManagedUsage {
            resource: Resource::Volume,
            name: item.name,
            bytes: reported_bytes(item.usage.map(|usage| usage.size)),
            references,
            labels: Vec::new(),
        });
    }
    for item in engine_items::<EngineContainer>(
        containers.items,
        containers.total_count,
        [
            containers.active_count,
            containers.reclaimable,
            containers.total_size,
        ],
    )? {
        inventory.push(ManagedUsage {
            resource: Resource::Container,
            name: item.id,
            bytes: reported_bytes(item.size),
            references: References::Referenced,
            labels: item.names.unwrap_or_default(),
        });
    }
    Ok(inventory)
}

#[derive(Debug, Deserialize)]
pub(crate) struct Installation {
    pub version: String,
    pub install_path: PathBuf,
    pub installed: bool,
    pub active: bool,
}

pub(crate) fn mise_installations(
    text: &str,
) -> std::io::Result<std::collections::BTreeMap<String, Vec<Installation>>> {
    serde_json::from_str(text).map_err(std::io::Error::other)
}

#[derive(Debug)]
pub(crate) struct ToolPin {
    pub tool: String,
    pub version: String,
}

fn tool_versions(tool: &str, value: &toml::Value, pins: &mut Vec<ToolPin>) -> std::io::Result<()> {
    match value {
        toml::Value::String(version) => pins.push(ToolPin {
            tool: tool.to_owned(),
            version: version.clone(),
        }),
        toml::Value::Array(values) => {
            for element in values {
                tool_versions(tool, element, pins)?;
            }
        },
        toml::Value::Table(table) => {
            let version = table
                .get("version")
                .ok_or_else(|| std::io::Error::other("a tracked tool has no static version"))?;
            tool_versions(tool, version, pins)?;
            if let Some(environment) = table.get("install_env").and_then(toml::Value::as_table)
                && let Some(compiler) = environment.get("RUSTUP_TOOLCHAIN")
            {
                tool_versions("rust", compiler, pins)?;
            }
        },
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {
            return Err(std::io::Error::other(
                "a tracked tool version has an unsupported shape",
            ));
        },
    }
    Ok(())
}

fn mise_tools(table: &toml::Table, pins: &mut Vec<ToolPin>) -> std::io::Result<()> {
    if let Some(tools) = table.get("tools") {
        let tools = tools
            .as_table()
            .ok_or_else(|| std::io::Error::other("a tracked tools section is not a table"))?;
        for (tool, version) in tools {
            tool_versions(tool, version, pins)?;
        }
    }
    if let Some(tasks) = table.get("tasks").and_then(toml::Value::as_table) {
        for task in tasks.values().filter_map(toml::Value::as_table) {
            mise_tools(task, pins)?;
        }
    }
    if let Some(environment) = table.get("env").and_then(toml::Value::as_table)
        && let Some(version) = environment.get("RUSTUP_TOOLCHAIN")
    {
        tool_versions("rust", version, pins)?;
    }
    Ok(())
}

fn workspace_msrv(path: &std::path::Path, pins: &mut Vec<ToolPin>) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("a manifest has no parent"))?;
    for directory in parent.ancestors() {
        let manifest = directory.join("Cargo.toml");
        let text = match std::fs::read_to_string(&manifest) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let table: toml::Table = toml::from_str(&text).map_err(std::io::Error::other)?;
        if let Some(value) = table
            .get("workspace")
            .and_then(|value| value.get("package"))
            .and_then(|value| value.get("rust-version"))
        {
            return tool_versions("rust", value, pins);
        }
    }
    Err(std::io::Error::other(
        "an inherited rust-version could not be resolved",
    ))
}

pub(crate) fn tool_pins(path: &std::path::Path, text: &str) -> std::io::Result<Vec<ToolPin>> {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| std::io::Error::other("a tool configuration has no UTF-8 name"))?;
    let mut pins = Vec::new();
    match name {
        "lean-toolchain" => {
            let version = match text.trim().rsplit_once(':') {
                Some((_repository, version)) => version,
                None => text.trim(),
            };
            pins.push(ToolPin {
                tool: "lean".to_owned(),
                version: version.to_owned(),
            });
        },
        ".tool-versions" => {
            for line in text
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            {
                let mut words = line.split_whitespace();
                let tool = words
                    .next()
                    .ok_or_else(|| std::io::Error::other("missing tracked tool name"))?;
                for version in words {
                    if version.starts_with('#') {
                        break;
                    }
                    pins.push(ToolPin {
                        tool: tool.to_owned(),
                        version: version.to_owned(),
                    });
                }
            }
        },
        "rust-toolchain" if !text.trim_start().starts_with('[') => pins.push(ToolPin {
            tool: "rust".to_owned(),
            version: text.trim().to_owned(),
        }),
        _ => {
            let table: toml::Table = toml::from_str(text).map_err(std::io::Error::other)?;
            match name {
                "rust-toolchain.toml" | "rust-toolchain" => {
                    let channel = table
                        .get("toolchain")
                        .and_then(|value| value.get("channel"))
                        .ok_or_else(|| std::io::Error::other("missing Rust toolchain channel"))?;
                    tool_versions("rust", channel, &mut pins)?;
                },
                "Cargo.toml" => {
                    for section in [
                        table.get("package"),
                        table
                            .get("workspace")
                            .and_then(|value| value.get("package")),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        if let Some(version) = section.get("rust-version") {
                            if version.get("workspace").and_then(toml::Value::as_bool) == Some(true)
                            {
                                workspace_msrv(path, &mut pins)?;
                            } else {
                                tool_versions("rust", version, &mut pins)?;
                            }
                        }
                    }
                },
                _ => mise_tools(&table, &mut pins)?,
            }
        },
    }
    Ok(pins)
}

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

pub(crate) fn release(bytes: &[u8]) -> Option<storage_scout_core::ownership::ReleaseRecord> {
    storage_scout_core::ownership::ReleaseRecord::decode(bytes)
}

pub(crate) const RELEASE_READY_BYTES: usize = 9;

pub(crate) fn release_ready(bytes: &[u8]) -> bool {
    bytes == b"released\n"
}

pub(crate) enum ReleaseRequest {
    Check,
    Stop,
}

pub(crate) const fn release_request(byte: u8) -> Option<ReleaseRequest> {
    match byte {
        b'?' => Some(ReleaseRequest::Check),
        b'!' => Some(ReleaseRequest::Stop),
        _ => None,
    }
}

pub(crate) fn release_endpoint(bytes: &[u8]) -> Option<PathBuf> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return None,
    };
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path.file_name()? != "rpc"
        || !path
            .parent()?
            .file_name()?
            .as_encoded_bytes()
            .starts_with(b".storage-scout-release-")
    {
        return None;
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return None;
    }
    Some(path)
}

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
