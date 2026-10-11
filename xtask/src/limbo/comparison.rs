//! Go's and OpenSSL's results for the same cases, from limbo's published runs.

use super::cases::{self, Case, LIMBO_COMMIT};
use crate::{Result, fetch};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// limbo's published results for the verifiers it runs. It holds the latest run only.
const RESULTS_URL: &str = "https://x509-limbo.com/_api/all-results.json";

/// The verifiers the report compares with: a name, and the start of limbo's harness name.
pub const COMPARED: [(&str, &str); 2] = [("Go", "gocryptox509-"), ("OpenSSL", "openssl-3.6")];

/// The file holding their results, which `update` writes from `RESULTS_URL`.
const FILE: &str = "go-openssl-comparison.tsv";
const TEXT: &str = include_str!("go-openssl-comparison.tsv");

/// The compared verifiers' harness names, and their results for each case that one of them got
/// wrong or skipped. A case not listed is one both got right.
pub struct Comparison<'a> {
    pub names: Vec<&'a str>,
    results: HashMap<&'a str, Vec<&'a str>>,
}

impl Comparison<'static> {
    pub fn load() -> Result<Self> {
        Comparison::parse(TEXT)
    }
}

impl<'a> Comparison<'a> {
    /// Reads `text`, which `extract` wrote. Its first line names the limbo commit it is for.
    pub(super) fn parse(text: &'a str) -> Result<Self> {
        if text.lines().next() != Some(&format!("# x509-limbo {LIMBO_COMMIT}")) {
            return Err(format!(
                "{FILE} is not for x509-limbo {LIMBO_COMMIT}. Run cargo xtask limbo \
                 --update-comparison."
            )
            .into());
        }
        let mut lines = text.lines().filter(|line| !line.starts_with('#'));
        let header = lines.next().ok_or(format!("{FILE} has no header"))?;
        let names = header.split('\t').skip(1).collect();
        let results = lines
            .filter_map(|line| {
                let mut fields = line.split('\t');
                Some((fields.next()?, fields.collect()))
            })
            .collect();
        Ok(Self { names, results })
    }

    /// Each compared verifier's result for `case`, such as "SUCCESS".
    pub fn results(&self, case: &Case) -> Vec<&'a str> {
        let expected = || vec![case.expected_result.result(); self.names.len()];
        self.results
            .get(case.id.as_str())
            .cloned()
            .unwrap_or_else(expected)
    }
}

/// One verifier's published results.
#[derive(Deserialize)]
struct Harness {
    harness: String,
    results: Vec<HarnessResult>,
}

#[derive(Deserialize)]
struct HarnessResult {
    id: String,
    actual_result: String,
}

/// Writes `FILE` from limbo's published results, which must be for the cases in the pinned
/// `limbo.json`.
pub fn update() -> Result<()> {
    let (_, limbo) = cases::load()?;
    let (body, modified) = fetch::get(RESULTS_URL)?;
    let harnesses: Vec<Harness> = serde_json::from_slice(&body)?;
    let modified = modified.unwrap_or_else(|| "at an unknown date".to_string());
    let text = extract(
        &limbo.testcases,
        &harnesses,
        &format!("{RESULTS_URL}, {modified}"),
    )?;
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/limbo")
        .join(FILE);
    std::fs::write(&path, text)?;
    println!("Wrote {}", path.display());
    Ok(())
}

/// The text of `FILE`: the compared verifiers' results for `cases`, from `harnesses`, which were
/// published at `source`.
fn extract(cases: &[Case], harnesses: &[Harness], source: &str) -> Result<String> {
    let mut names = Vec::new();
    let mut results = Vec::new();
    for (name, prefix) in COMPARED {
        let harness = harnesses
            .iter()
            .find(|harness| harness.harness.starts_with(prefix))
            .ok_or(format!("the published results have no {name} results"))?;
        let by_id: HashMap<&str, &str> = harness
            .results
            .iter()
            .map(|result| (result.id.as_str(), result.actual_result.as_str()))
            .collect();
        if by_id.len() != cases.len()
            || cases
                .iter()
                .any(|case| !by_id.contains_key(case.id.as_str()))
        {
            return Err(format!(
                "The published results are for another limbo commit than {LIMBO_COMMIT}. Move \
                 LIMBO_COMMIT and LIMBO_SHA256 to the commit limbo's site was built from, then run \
                 this again."
            )
            .into());
        }
        names.push(harness.harness.as_str());
        results.push(by_id);
    }

    let mut text = format!(
        "# x509-limbo {LIMBO_COMMIT}\n# From {source}.\n# Lists the cases where a result differs \
         from limbo's expected result.\n# Written by cargo xtask limbo --update-comparison.\nid\t{}\n",
        names.join("\t")
    );
    for case in cases {
        let row: Vec<&str> = results
            .iter()
            .map(|by_id| by_id[case.id.as_str()])
            .collect();
        if row
            .iter()
            .any(|result| *result != case.expected_result.result())
        {
            text += &format!("{}\t{}\n", case.id, row.join("\t"));
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limbo::cases::{Expected, case};

    fn harness(name: &str, results: &[(&str, &str)]) -> Harness {
        Harness {
            harness: name.to_string(),
            results: results
                .iter()
                .map(|(id, result)| HarnessResult {
                    id: id.to_string(),
                    actual_result: result.to_string(),
                })
                .collect(),
        }
    }

    fn cases() -> Vec<Case> {
        vec![
            case("a::right", "SERVER", &[], Expected::Success),
            case("a::accepted-bad", "SERVER", &[], Expected::Failure),
            case("a::skipped", "SERVER", &[], Expected::Success),
            case("a::rejected-valid", "SERVER", &[], Expected::Success),
        ]
    }

    /// Go gets one case wrong and skips one. OpenSSL 3.6 rejects one valid chain. A second
    /// OpenSSL version, which is not compared, gets everything wrong.
    fn published() -> Vec<Harness> {
        let go = [
            ("a::right", "SUCCESS"),
            ("a::accepted-bad", "SUCCESS"),
            ("a::skipped", "SKIPPED"),
            ("a::rejected-valid", "SUCCESS"),
        ];
        let openssl = [
            ("a::right", "SUCCESS"),
            ("a::accepted-bad", "FAILURE"),
            ("a::skipped", "SUCCESS"),
            ("a::rejected-valid", "FAILURE"),
        ];
        let other = go.map(|(id, _)| (id, "SKIPPED"));
        vec![
            harness("openssl-3.5.4", &other),
            harness("gocryptox509-go1.26.8", &go),
            harness("openssl-3.6.4", &openssl),
        ]
    }

    fn data_lines(text: &str) -> Vec<&str> {
        text.lines().filter(|line| !line.starts_with('#')).collect()
    }

    #[test]
    fn the_file_lists_only_the_cases_a_compared_verifier_did_not_get_right() {
        let text = extract(&cases(), &published(), "a test").unwrap();
        assert_eq!(
            data_lines(&text),
            [
                "id\tgocryptox509-go1.26.8\topenssl-3.6.4",
                "a::accepted-bad\tSUCCESS\tFAILURE",
                "a::skipped\tSKIPPED\tSUCCESS",
                "a::rejected-valid\tSUCCESS\tFAILURE",
            ]
        );
    }

    #[test]
    fn results_for_a_missing_case_are_refused() {
        let mut published = published();
        published[1].results.pop();
        assert!(extract(&cases(), &published, "a test").is_err());
    }

    #[test]
    fn results_for_an_extra_case_are_refused() {
        let mut published = published();
        published[2].results.push(HarnessResult {
            id: "a::new".to_string(),
            actual_result: "SUCCESS".to_string(),
        });
        assert!(extract(&cases(), &published, "a test").is_err());
    }

    #[test]
    fn results_for_as_many_cases_but_another_one_are_refused() {
        let mut published = published();
        published[2].results[3].id = "a::new".to_string();
        assert!(extract(&cases(), &published, "a test").is_err());
    }

    #[test]
    fn results_without_a_compared_verifier_are_refused() {
        let published: Vec<Harness> = published().into_iter().skip(1).take(1).collect();
        assert!(extract(&cases(), &published, "a test").is_err());
    }

    #[test]
    fn a_case_the_file_lists_takes_its_results_and_any_other_the_expected_result() {
        let text = extract(&cases(), &published(), "a test").unwrap();
        let comparison = Comparison::parse(&text).unwrap();
        let [right, accepted_bad, skipped, _] = &cases()[..] else {
            unreachable!()
        };
        assert_eq!(comparison.names, ["gocryptox509-go1.26.8", "openssl-3.6.4"]);
        assert_eq!(comparison.results(right), ["SUCCESS", "SUCCESS"]);
        assert_eq!(comparison.results(accepted_bad), ["SUCCESS", "FAILURE"]);
        assert_eq!(comparison.results(skipped), ["SKIPPED", "SUCCESS"]);
        let unlisted_bad = case("b::bad", "SERVER", &[], Expected::Failure);
        assert_eq!(comparison.results(&unlisted_bad), ["FAILURE", "FAILURE"]);
    }

    #[test]
    fn a_file_for_another_limbo_commit_is_refused() {
        let text = extract(&cases(), &published(), "a test").unwrap();
        let text = text.replace(LIMBO_COMMIT, "0000000000000000000000000000000000000000");
        assert!(Comparison::parse(&text).is_err());
    }

    #[test]
    fn the_committed_file_is_for_the_pinned_limbo_commit() {
        assert!(Comparison::load().is_ok());
    }
}
