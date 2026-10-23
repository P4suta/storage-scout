use std::fs;
use std::path::Path;

use anyhow::{Result, ensure};
use serde::Deserialize;

const PINNED_DATE_WIDTHS: [usize; 3] = [4, 2, 2];

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
struct MutationCounts {
    total_mutants: usize,
    missed: usize,
    caught: usize,
    timeout: usize,
    unviable: usize,
    success: usize,
}

impl MutationCounts {
    const fn complete(&self, expected: usize) -> bool {
        expected > 0
            && self.total_mutants == expected
            && self.caught > 0
            && self.missed == 0
            && self.timeout == 0
            && self.success == 0
            && matches!(self.caught.checked_add(self.unviable), Some(total) if total == expected)
    }
}

#[derive(Debug, Deserialize)]
struct Mutation {
    name: String,
}

#[derive(Debug, Deserialize)]
enum MutationScenario {
    Baseline,
    Mutant(Mutation),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum MutationSummary {
    Success,
    Failure,
    Unviable,
    CaughtMutant,
    MissedMutant,
    Timeout,
}

#[derive(Debug, Deserialize)]
struct MutationOutcome {
    scenario: MutationScenario,
    summary: MutationSummary,
}

#[derive(Debug, Deserialize)]
struct MutationReport {
    total_mutants: usize,
    missed: usize,
    caught: usize,
    timeout: usize,
    unviable: usize,
    success: usize,
    outcomes: Vec<MutationOutcome>,
    cargo_mutants_version: String,
    end_time: Option<String>,
}

pub(super) fn mutation_version(root: &Path) -> Result<String> {
    let config: toml::Value = toml::from_str(&fs::read_to_string(root.join("mise.toml"))?)?;
    let version = config
        .get("tasks")
        .and_then(|tasks| tasks.get("mutants:tool"))
        .and_then(|task| task.get("tools"))
        .and_then(|tools| tools.get("cargo:cargo-mutants"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing pinned cargo-mutants version"))?;
    Ok(version.to_owned())
}

pub(super) fn mutation_report(directory: &Path, version: &str) -> Result<()> {
    use std::collections::BTreeSet;
    let catalog: Vec<Mutation> =
        serde_json::from_slice(&fs::read(directory.join("mutants.json"))?)?;
    let mut pending = catalog
        .iter()
        .map(|mutant| mutant.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        pending.len() == catalog.len() && !pending.contains(""),
        "duplicate or empty mutation identity"
    );
    let report: MutationReport =
        serde_json::from_slice(&fs::read(directory.join("outcomes.json"))?)?;
    let counts = MutationCounts {
        total_mutants: report.total_mutants,
        missed: report.missed,
        caught: report.caught,
        timeout: report.timeout,
        unviable: report.unviable,
        success: report.success,
    };
    ensure!(
        report.cargo_mutants_version == version,
        "wrong cargo-mutants version"
    );
    ensure!(
        report
            .end_time
            .as_ref()
            .is_some_and(|value| !value.is_empty()),
        "mutation run did not finish"
    );
    ensure!(
        counts.complete(catalog.len()),
        "mutation results are empty, incomplete, missed, or timed out"
    );
    let mut baseline = None;
    let mut caught = 0usize;
    let mut unviable = 0usize;
    for outcome in report.outcomes {
        match outcome.scenario {
            MutationScenario::Baseline => {
                ensure!(
                    baseline.is_none() && outcome.summary == MutationSummary::Success,
                    "missing, duplicate, or failed mutation baseline"
                );
                baseline = Some(());
            },
            MutationScenario::Mutant(mutant) => {
                ensure!(
                    pending.remove(mutant.name.as_str()),
                    "duplicate or unknown mutation result"
                );
                match outcome.summary {
                    MutationSummary::CaughtMutant => caught = caught.saturating_add(1),
                    MutationSummary::Unviable => unviable = unviable.saturating_add(1),
                    MutationSummary::Success
                    | MutationSummary::Failure
                    | MutationSummary::MissedMutant
                    | MutationSummary::Timeout => {
                        anyhow::bail!("mutation did not produce a supported result")
                    },
                }
            },
        }
    }
    ensure!(
        baseline.is_some() && pending.is_empty(),
        "missing mutation baseline or results"
    );
    ensure!(
        caught == counts.caught && unviable == counts.unviable,
        "mutation counts disagree with their results"
    );
    Ok(())
}

pub(super) fn mutation_catalog_len(bytes: &[u8]) -> Result<usize> {
    let catalog: Vec<Mutation> = serde_json::from_slice(bytes)?;
    ensure!(!catalog.is_empty(), "empty mutation catalog");
    Ok(catalog.len())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MiriConfiguration {
    toolchain: MiriToolchain,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MiriToolchain {
    channel: String,
    components: Vec<String>,
    profile: String,
}

pub(super) fn miri_toolchain(root: &Path) -> Result<String> {
    let configuration: MiriConfiguration = toml::from_str(&fs::read_to_string(
        root.join("tools/miri/rust-toolchain.toml"),
    )?)?;
    let toolchain = configuration.toolchain;
    let date = toolchain
        .channel
        .strip_prefix("nightly-")
        .ok_or_else(|| anyhow::anyhow!("Miri requires a pinned nightly"))?;
    ensure!(
        date.split('-').map(str::len).eq(PINNED_DATE_WIDTHS)
            && date
                .split('-')
                .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
            && toolchain.components == ["miri"]
            && toolchain.profile == "minimal",
        "invalid Miri toolchain pin"
    );
    Ok(toolchain.channel)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    pub harnesses: Vec<String>,
    pub modules: Vec<Module>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Module {
    pub path: String,
    pub symbols: Vec<String>,
    pub harnesses: Vec<String>,
    pub domain: String,
}

pub(super) fn inventory(root: &Path) -> Result<Inventory> {
    Ok(toml::from_str(&fs::read_to_string(
        root.join("assurance.toml"),
    )?)?)
}

#[derive(Debug, Deserialize)]
struct Report {
    metadata: Metadata,
    verification_results: Results,
    property_details: Vec<Properties>,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    kani_version: String,
}

#[derive(Debug, Deserialize)]
struct Results {
    results: Vec<Harness>,
}

#[derive(Debug, Deserialize)]
struct Harness {
    #[serde(rename = "harness_id")]
    id: String,
    status: String,
    checks: Vec<Check>,
}

#[derive(Debug, Deserialize)]
struct Check {
    status: String,
    category: String,
}

#[derive(Debug, Deserialize)]
struct Properties {
    harness_id: String,
    property_details: Counts,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
struct Counts {
    passed: usize,
    failed: usize,
    undetermined: usize,
    solver_error: usize,
    satisfied: usize,
    unsatisfiable: usize,
}

impl Counts {
    const fn complete(&self) -> bool {
        self.passed > 0
            && self.failed == 0
            && self.undetermined == 0
            && self.solver_error == 0
            && self.satisfied > 0
            && self.unsatisfiable == 0
    }
}

pub(super) fn report(path: &Path, expected: &[String]) -> Result<()> {
    ensure!(!expected.is_empty(), "empty required proof inventory");
    let report: Report = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        report.metadata.kani_version == "0.68.0",
        "wrong Kani version"
    );
    let found = report
        .verification_results
        .results
        .iter()
        .map(|h| h.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        found == expected.iter().cloned().collect(),
        "missing or unexpected proof harnesses"
    );
    ensure!(
        report.verification_results.results.len() == expected.len(),
        "duplicate proof results"
    );
    ensure!(
        report.property_details.len() == expected.len(),
        "incomplete property results"
    );
    for harness in report.verification_results.results {
        ensure!(
            harness.status == "Success" && !harness.checks.is_empty(),
            "{} did not complete",
            harness.id
        );
        ensure!(
            harness.checks.iter().all(|check| matches!(
                check.status.as_str(),
                "Success" | "Satisfied" | "Unreachable"
            )),
            "{} has an incomplete check",
            harness.id
        );
        let properties = report
            .property_details
            .iter()
            .find(|p| p.harness_id == harness.id)
            .ok_or_else(|| anyhow::anyhow!("missing property result"))?;
        let counts = &properties.property_details;
        ensure!(
            counts.complete(),
            "{} has incomplete or unreachable obligations",
            harness.id
        );
    }
    Ok(())
}

#[cfg(kani)]
mod proofs {
    use super::{Counts, MutationCounts};

    #[kani::proof]
    fn incomplete_or_vacuous_results_never_pass() {
        let counts: Counts = kani::any();
        let accepted = counts.complete();
        if accepted {
            assert!(counts.passed > 0 && counts.satisfied > 0);
            assert_eq!(counts.failed, 0);
            assert_eq!(counts.undetermined, 0);
            assert_eq!(counts.solver_error, 0);
            assert_eq!(counts.unsatisfiable, 0);
        }
        kani::cover!(accepted);
        kani::cover!(!accepted);
        let mutations: MutationCounts = kani::any();
        let expected: usize = kani::any();
        let complete = mutations.complete(expected);
        if complete {
            assert!(expected > 0 && mutations.caught > 0);
            assert_eq!(mutations.total_mutants, expected);
            assert_eq!(mutations.missed, 0);
            assert_eq!(mutations.timeout, 0);
            assert_eq!(mutations.success, 0);
            assert_eq!(
                mutations.caught as u128 + mutations.unviable as u128,
                expected as u128
            );
        }
        kani::cover!(complete);
        kani::cover!(!complete);
    }
}

pub(super) fn rejected_probe(path: &Path, expected: &str) -> Result<()> {
    let report: Report = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        report.verification_results.results.len() == 1,
        "probe ran the wrong harness count"
    );
    let harness = report
        .verification_results
        .results
        .first()
        .ok_or_else(|| anyhow::anyhow!("probe ran no harness"))?;
    ensure!(
        harness.id == expected && harness.status == "Failure",
        "probe did not fail verification"
    );
    ensure!(
        harness
            .checks
            .iter()
            .any(|check| check.status == "Failure" && check.category == "assertion"),
        "probe failed without rejecting the false claim"
    );
    ensure!(
        harness
            .checks
            .iter()
            .all(|check| check.status != "Failure" || check.category == "assertion"),
        "probe failed for an unrelated safety check"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "mutation reports are written only inside repository-owned temporary directories"
    )]
    fn mutation_reports_require_a_complete_nonempty_catalog_and_a_passing_baseline() {
        let temp = testkit::tempdir("mutation-receipt");
        let catalog = json!([{"name":"caught-a"}, {"name":"unviable-b"}]);
        let valid = json!({
            "total_mutants":2, "caught":1, "unviable":1, "missed":0, "timeout":0, "success":0,
            "cargo_mutants_version":"27.1.0", "end_time":"recorded",
            "outcomes":[
                {"scenario":"Baseline", "summary":"Success"},
                {"scenario":{"Mutant":{"name":"caught-a"}}, "summary":"CaughtMutant"},
                {"scenario":{"Mutant":{"name":"unviable-b"}}, "summary":"Unviable"}
            ]
        });
        let catalog_path = temp.path().join("mutants.json");
        let result_path = temp.path().join("outcomes.json");
        fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
        fs::write(&result_path, serde_json::to_vec(&valid).unwrap()).unwrap();
        mutation_report(temp.path(), "27.1.0").unwrap();
        for (pointer, value, message) in [
            ("/cargo_mutants_version", json!("0"), "wrong cargo-mutants"),
            ("/end_time", serde_json::Value::Null, "did not finish"),
            ("/caught", json!(0), "empty, incomplete"),
            ("/missed", json!(1), "empty, incomplete"),
            ("/timeout", json!(1), "empty, incomplete"),
            ("/total_mutants", json!(1), "empty, incomplete"),
            (
                "/outcomes/0/summary",
                json!("Failure"),
                "failed mutation baseline",
            ),
            (
                "/outcomes/1/summary",
                json!("MissedMutant"),
                "supported result",
            ),
            (
                "/outcomes/1/scenario/Mutant/name",
                json!("unknown"),
                "unknown mutation",
            ),
            ("/outcomes", json!([]), "missing mutation baseline"),
        ] {
            let mut invalid = valid.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            fs::write(&result_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(
                mutation_report(temp.path(), "27.1.0")
                    .unwrap_err()
                    .to_string()
                    .contains(message),
                "{pointer}"
            );
        }
        fs::write(&result_path, serde_json::to_vec(&valid).unwrap()).unwrap();
        for invalid in [json!([]), json!([{"name":"caught-a"}, {"name":"caught-a"}])] {
            fs::write(&catalog_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            let _rejection = mutation_report(temp.path(), "27.1.0").unwrap_err();
        }
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "receipt fixtures are written only inside repository-owned temporary directories"
    )]
    fn missing_failed_and_vacuous_receipts_are_rejected() {
        let temp = testkit::tempdir("assurance-receipt");
        let path = temp.path().join("result.json");
        let valid = json!({
            "metadata": { "kani_version": "0.68.0" },
            "verification_results": { "results": [{ "harness_id": "policy", "status": "Success", "checks": [{ "status": "Success", "category": "assertion" }] }] },
            "property_details": [{ "harness_id": "policy", "property_details": { "passed": 1, "failed": 0, "undetermined": 0, "solver_error": 0, "satisfied": 1, "unsatisfiable": 0 } }]
        });
        let required = ["policy".to_owned()];
        fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        report(&path, &required).unwrap();
        assert!(report(&path, &[]).is_err());
        assert!(report(&path, &["missing".to_owned()]).is_err());
        for status in ["Failure", "Undetermined", "SolverError", "Unsatisfiable"] {
            let mut invalid = valid.clone();
            invalid["verification_results"]["results"][0]["checks"][0]["status"] = json!(status);
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(report(&path, &required).is_err(), "{status}");
        }
        for (field, value) in [
            ("passed", 0),
            ("satisfied", 0),
            ("failed", 1),
            ("undetermined", 1),
            ("solver_error", 1),
            ("unsatisfiable", 1),
        ] {
            let mut invalid = valid.clone();
            invalid["property_details"][0]["property_details"][field] = json!(value);
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(report(&path, &required).is_err(), "{field}");
        }
        let mut missing = valid;
        missing["verification_results"]["results"] = json!([]);
        fs::write(&path, serde_json::to_vec(&missing).unwrap()).unwrap();
        assert!(report(&path, &required).is_err());
    }
}
