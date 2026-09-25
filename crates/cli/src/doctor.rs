use std::fs;
use std::io;
use std::path::PathBuf;

use serde::Serialize;
use storage_scout_core::area::{Class, Protection, Rule};
use storage_scout_core::gate::Gate;
use storage_scout_core::location::Location;
use storage_scout_core::platform::Platform;
use storage_scout_core::size::Bytes;

use crate::{SCHEMA_VERSION, platform};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyFile {
    Present,
    Absent,
    Unreadable,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Warning {
    NoSystemAreas,
    FreeSpaceUnknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateInfo {
    pub gate: Gate,
    pub purpose: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnosis {
    pub schema_version: u32,
    pub command: &'static str,
    pub platform: Platform,
    pub arch: &'static str,
    pub os: &'static str,
    pub cwd: Location,
    pub exe: Location,
    pub default_policy: Option<PathBuf>,
    pub policy_file: PolicyFile,
    pub rules: Vec<Rule>,
    pub gates: Vec<GateInfo>,
    pub free_here: Option<Bytes>,
    pub warnings: Vec<Warning>,
}

pub(crate) fn diagnose(protection: &Protection, default_policy: Option<PathBuf>) -> Diagnosis {
    let policy_file = match &default_policy {
        None => PolicyFile::Unresolved,
        Some(path) => match fs::metadata(path) {
            Ok(_) => PolicyFile::Present,
            Err(error) if error.kind() == io::ErrorKind::NotFound => PolicyFile::Absent,
            Err(_unreadable) => PolicyFile::Unreadable,
        },
    };
    let free_here = match std::env::current_dir() {
        Ok(cwd) => match platform::free_space(&cwd) {
            Ok(free) => Some(Bytes::new(free)),
            Err(_unmeasurable) => None,
        },
        Err(_unresolvable) => None,
    };
    let mut warnings = Vec::new();
    if !protection
        .rules()
        .iter()
        .any(|rule| matches!(rule.class, Class::System { .. }))
    {
        warnings.push(Warning::NoSystemAreas);
    }
    if free_here.is_none() {
        warnings.push(Warning::FreeSpaceUnknown);
    }
    Diagnosis {
        schema_version: SCHEMA_VERSION,
        command: "doctor",
        platform: Platform::HOST,
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
        cwd: protection.cwd().clone(),
        exe: protection.exe().clone(),
        default_policy,
        policy_file,
        rules: protection.rules().to_vec(),
        gates: Gate::ALL
            .iter()
            .map(|gate| GateInfo {
                gate: *gate,
                purpose: gate.purpose(),
            })
            .collect(),
        free_here,
        warnings,
    }
}
