//! Validation and application of opaque cleanup plans.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::safety::{self, is_reparse_point};
use crate::scan::measure_for_cleanup;
use crate::windows;
use crate::{
    ApplyOptions, ArtifactCandidate, Bytes, CleanupOutcome, CleanupPlan, CleanupStatus,
    CleanupSummary, SCHEMA_VERSION, Usage, make_candidate_id,
};

pub(crate) fn measure_selection(candidates: &[ArtifactCandidate]) -> Result<Usage, String> {
    let paths = candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();
    measure_for_cleanup(&paths).map(|(usage, _)| usage)
}

/// Revalidate and optionally apply a cleanup plan.
///
/// No deletion is attempted unless `options.execute` is true. A failure for one
/// candidate does not bypass validation or abort reporting for the remainder.
#[must_use]
pub fn apply_cleanup_plan(plan: &CleanupPlan, options: ApplyOptions) -> CleanupSummary {
    apply_cleanup_plan_with(plan, options, remove_dir_all_robust)
}

fn apply_cleanup_plan_with(
    plan: &CleanupPlan,
    options: ApplyOptions,
    remover: impl Fn(&Path) -> std::io::Result<()>,
) -> CleanupSummary {
    let excludes = safety::canonical_excludes(plan.excludes());
    let volume_samples = options
        .execute
        .then(|| capture_volume_free(plan.candidates()));
    let mut outcomes = Vec::with_capacity(plan.candidates().len());

    for candidate in plan.candidates() {
        let validated = match revalidate(candidate, &excludes) {
            Ok(usage) => usage,
            Err(reason) => {
                outcomes.push(CleanupOutcome {
                    id: candidate.id.clone(),
                    path: candidate.path.clone(),
                    usage: Usage::default(),
                    status: CleanupStatus::Rejected(reason),
                });
                continue;
            },
        };

        let status = if options.execute {
            match remover(&candidate.path) {
                Ok(()) => CleanupStatus::Deleted,
                Err(error) => CleanupStatus::Failed(error.to_string()),
            }
        } else {
            CleanupStatus::DryRun
        };
        outcomes.push(CleanupOutcome {
            id: candidate.id.clone(),
            path: candidate.path.clone(),
            usage: validated,
            status,
        });
    }

    let observed_freed = volume_samples.as_ref().and_then(observe_volume_free);
    CleanupSummary {
        schema_version: SCHEMA_VERSION,
        executed: options.execute,
        predicted_freed: plan.usage.reclaimable,
        observed_freed,
        outcomes,
    }
}

fn revalidate(candidate: &ArtifactCandidate, excludes: &[PathBuf]) -> Result<Usage, String> {
    let metadata = fs::symlink_metadata(&candidate.path)
        .map_err(|error| format!("candidate is missing or unreadable: {error}"))?;
    if !metadata.is_dir() {
        return Err("candidate is no longer a directory".to_owned());
    }
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err("candidate is now a symlink or reparse point".to_owned());
    }
    let canonical = fs::canonicalize(&candidate.path)
        .map_err(|error| format!("cannot canonicalize candidate: {error}"))?;
    if safety::normalized(&canonical) != safety::normalized(&candidate.path) {
        return Err("canonical path changed since discovery".to_owned());
    }
    if let Some(reason) = safety::protected_reason(&canonical) {
        return Err(format!("protected location: {reason}"));
    }
    if let Some(exclude) = safety::is_excluded(&canonical, excludes) {
        return Err(format!("intersects exclusion {}", exclude.display()));
    }
    let identity = windows::identity(&canonical)
        .map_err(|error| format!("cannot read current volume/file ID: {error}"))?;
    if identity != candidate.identity {
        return Err("volume/file ID changed; candidate is stale".to_owned());
    }
    let kind = safety::classify_path(&canonical)?;
    if kind != candidate.kind {
        return Err(format!(
            "artifact kind changed from {} to {}",
            candidate.kind, kind
        ));
    }
    let (usage, newest) = measure_for_cleanup(std::slice::from_ref(&canonical))?;
    let current_id = make_candidate_id(identity, &canonical, kind, usage, newest);
    if current_id != candidate.id {
        return Err(
            "size, allocation, or modification time changed; candidate is stale".to_owned(),
        );
    }
    Ok(usage)
}

struct VolumeSample {
    path: PathBuf,
    before: Option<u64>,
}

fn capture_volume_free(candidates: &[ArtifactCandidate]) -> HashMap<u64, VolumeSample> {
    let mut samples = HashMap::new();
    for candidate in candidates {
        samples.entry(candidate.identity.volume).or_insert_with(|| {
            let path = candidate
                .path
                .parent()
                .unwrap_or(&candidate.path)
                .to_path_buf();
            let before = windows::free_space(&path).ok();
            VolumeSample { path, before }
        });
    }
    samples
}

fn observe_volume_free(samples: &HashMap<u64, VolumeSample>) -> Option<Bytes> {
    let mut total = 0u64;
    for sample in samples.values() {
        let before = sample.before?;
        let after = windows::free_space(&sample.path).ok()?;
        total = total.saturating_add(after.saturating_sub(before));
    }
    Some(Bytes(total))
}

fn remove_dir_all_robust(path: &Path) -> std::io::Result<()> {
    if matches!(fs::remove_dir_all(path), Ok(())) {
        Ok(())
    } else {
        clear_readonly_recursive(path);
        fs::remove_dir_all(path)
    }
}

#[cfg(windows)]
fn clear_readonly_recursive(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return;
    }
    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        #[allow(
            clippy::permissions_set_readonly_false,
            reason = "Windows FILE_ATTRIBUTE_READONLY must be cleared before retrying removal"
        )]
        permissions.set_readonly(false);
        let _ = fs::set_permissions(path, permissions);
    }
    if metadata.is_dir()
        && let Ok(entries) = fs::read_dir(path)
    {
        for entry in entries.flatten() {
            clear_readonly_recursive(&entry.path());
        }
    }
}

#[cfg(not(windows))]
const fn clear_readonly_recursive(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Measure, ScanOptions, create_cleanup_plan, discover_cleanup_candidates};

    #[test]
    fn deletion_failure_does_not_stop_remaining_candidates() {
        let temporary = tempfile::Builder::new()
            .prefix(".storage-scout-cleanup-test-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        for (project, size) in [("fail", 4096), ("pass", 2048)] {
            let project = temporary.path().join(project);
            fs::create_dir_all(project.join("target")).unwrap();
            fs::write(project.join("Cargo.toml"), b"[package]").unwrap();
            fs::write(project.join("target/app.exe"), vec![0u8; size]).unwrap();
        }
        let report = discover_cleanup_candidates(&ScanOptions {
            roots: vec![temporary.path().to_path_buf()],
            top: 0,
            min_size: Bytes(0),
            max_depth: Some(0),
            excludes: Vec::new(),
            threads: None,
            measure: Measure::Both,
        })
        .unwrap();
        let ids = report
            .candidates
            .iter()
            .map(|candidate| candidate.id.clone())
            .collect::<Vec<_>>();
        let plan = create_cleanup_plan(&report.candidates, &ids, Vec::new()).unwrap();
        let summary = apply_cleanup_plan_with(&plan, ApplyOptions { execute: true }, |path| {
            if path.parent().is_some_and(|parent| parent.ends_with("fail")) {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected deletion failure",
                ))
            } else {
                remove_dir_all_robust(path)
            }
        });
        assert!(summary.has_failures());
        assert!(
            summary
                .outcomes
                .iter()
                .any(|outcome| matches!(outcome.status, CleanupStatus::Failed(_)))
        );
        assert!(
            summary
                .outcomes
                .iter()
                .any(|outcome| matches!(outcome.status, CleanupStatus::Deleted))
        );
        assert!(temporary.path().join("fail/target").exists());
        assert!(!temporary.path().join("pass/target").exists());
    }

    #[test]
    fn missing_before_free_space_is_reported_as_unavailable() {
        let samples = HashMap::from([(
            1,
            VolumeSample {
                path: PathBuf::from("unused"),
                before: None,
            },
        )]);
        assert_eq!(observe_volume_free(&samples), None);
    }
}
