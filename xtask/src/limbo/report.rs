//! Prints the report, and writes each verifier's result for every case.

use super::cases::{Case, Expected};
use super::comparison::{COMPARED, Comparison};
use super::verify::{Outcome, VERIFIERS};
use crate::Result;
use comfy_table::{CellAlignment, Table, presets::NOTHING};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

/// What each group of cases tests, from `limbo/testcases/` in x509-limbo.
const GROUPS: &[(&str, &str)] = &[
    (
        "bettertls",
        "Netflix BetterTLS: name constraints, path building",
    ),
    ("cve", "Chains from named CVEs"),
    ("invalid", "An invalid issuer key"),
    ("online", "Real servers' chains"),
    ("pathlen", "Path length limits"),
    ("pathological", "Cycles and unusual chain shapes"),
    ("rfc5280", "RFC 5280 rules"),
    ("webpki", "Web PKI (CA/Browser Forum) rules"),
];

/// A table each for the bad and the valid chains, then the lines that count the chains rejected
/// for their length and the panics.
pub fn report(cases: &[Case], results: &[Vec<Outcome>], comparison: &Comparison) -> String {
    let mut report = table(cases, results, comparison, Expected::Failure);
    report += &table(cases, results, comparison, Expected::Success);
    report += &format!(
        "\n{} results are from limbo's published runs, in \
         xtask/src/limbo/go-openssl-comparison.tsv.\n",
        comparison.names.join(" and ")
    );

    // For each verifier, how many cases match `wanted`.
    let summary = |wanted: fn(&Case, &Outcome) -> bool| {
        let counts = VERIFIERS.iter().zip(results).map(|((name, _), outcomes)| {
            let matching = cases
                .iter()
                .zip(outcomes)
                .filter(|(case, o)| wanted(case, o));
            format!("{name} {}", matching.count())
        });
        counts.collect::<Vec<_>>().join(", ")
    };
    let too_long = summary(|case, outcome| {
        case.expected_result == Expected::Success
            && matches!(outcome, Err(e) if e.contains("InsufficientSpace"))
    });
    let panics = summary(|_, outcome| matches!(outcome, Err(e) if e == "panicked"));
    report +=
        &format!("\nValid chains rejected for holding more than 16 certificates: {too_long}\n");
    report + &format!("Panics: {panics}\n")
}

/// Writes `<verifier>.tsv` in `dir` for each verifier: each case's expected result, the verifier's,
/// Go's and OpenSSL's, and the verifier's errors.
pub fn write(
    dir: &Path,
    cases: &[Case],
    results: &[Vec<Outcome>],
    comparison: &Comparison,
) -> Result<()> {
    println!("\nEach case's result, with Go's and OpenSSL's for the same case:");
    for ((name, _), outcomes) in VERIFIERS.iter().zip(results) {
        let path = dir.join(format!("{name}.tsv"));
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path)?);
        writeln!(
            out,
            "id\texpected\t{name}\t{}\tdetail",
            comparison.names.join("\t")
        )?;
        for (case, outcome) in cases.iter().zip(outcomes) {
            let (result, detail) = match outcome {
                Ok(()) => ("SUCCESS", ""),
                Err(detail) => ("FAILURE", detail.as_str()),
            };
            let expected = case.expected_result.result();
            let compared = comparison.results(case).join("\t");
            writeln!(
                out,
                "{}\t{expected}\t{result}\t{compared}\t{detail}",
                case.id
            )?;
        }
        println!("  {}", path.display());
    }
    Ok(())
}

/// The table for the chains that expect `expected`, then the comparison with Go and OpenSSL.
fn table(
    cases: &[Case],
    results: &[Vec<Outcome>],
    comparison: &Comparison,
    expected: Expected,
) -> String {
    let (chains, verb, wrong) = match expected {
        Expected::Failure => ("Bad chains", "accepted", "Accepted"),
        Expected::Success => ("Valid chains", "rejected", "Rejected"),
    };

    let header = ["Group", "What it tests", chains].map(String::from);
    let verifiers = VERIFIERS.iter().map(|(name, _)| format!("{name} {verb}"));
    let mut table = new_table(header.into_iter().chain(verifiers), 2);
    for (group, counts) in groups(cases, results, expected) {
        let description = GROUPS
            .iter()
            .find(|(name, _)| *name == group)
            .map_or("", |(_, description)| description);
        let cells = [group, description].map(String::from);
        table.add_row(cells.into_iter().chain(counts.iter().map(usize::to_string)));
    }
    let groups = format!("\n{chains} {verb}. The target is 0.\n\n{table}\n");

    let names: Vec<&str> = COMPARED.iter().map(|(name, _)| *name).collect();
    let also = names.iter().map(|name| format!("{name} also {verb}"));
    let header = ["Verifier".to_string(), wrong.to_string()]
        .into_iter()
        .chain(also);
    let mut table = new_table(header.chain([format!("Neither {verb}")]), 1);
    let counts = shared(cases, results, comparison, expected);
    for ((name, _), counts) in VERIFIERS.iter().zip(counts) {
        table.add_row(
            [name.to_string()]
                .into_iter()
                .chain(counts.iter().map(usize::to_string)),
        );
    }
    groups
        + &format!(
            "\nOf the {} each verifier {verb}, the same chains {verb} by {}:\n\n{table}\n",
            chains.to_lowercase(),
            names.join(" and ")
        )
}

/// Whether a verifier got wrong a case that expects `expected`.
fn is_wrong(outcome: &Outcome, expected: Expected) -> bool {
    outcome.is_ok() == (expected == Expected::Failure)
}

/// For each group, largest first, then a `Total` row: the number of its cases that expect
/// `expected`, then how many of them each verifier got wrong.
fn groups<'a>(
    cases: &'a [Case],
    results: &[Vec<Outcome>],
    expected: Expected,
) -> Vec<(&'a str, Vec<usize>)> {
    let mut groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, case) in cases.iter().enumerate() {
        if case.expected_result != expected {
            continue;
        }
        let group = case.id.split("::").next().unwrap_or_default();
        let counts = groups
            .entry(group)
            .or_insert_with(|| vec![0; 1 + results.len()]);
        counts[0] += 1;
        for (count, outcomes) in counts[1..].iter_mut().zip(results) {
            *count += usize::from(is_wrong(&outcomes[i], expected));
        }
    }
    let mut rows: Vec<(&str, Vec<usize>)> = groups.into_iter().collect();
    rows.sort_by_key(|(_, counts)| std::cmp::Reverse(counts[0]));
    let mut totals = vec![0; 1 + results.len()];
    for (_, counts) in &rows {
        for (total, count) in totals.iter_mut().zip(counts) {
            *total += count;
        }
    }
    rows.push(("Total", totals));
    rows
}

/// For each verifier: how many cases that expect `expected` it got wrong, then how many of the
/// same cases each compared verifier also got wrong, then how many no compared verifier got wrong.
fn shared(
    cases: &[Case],
    results: &[Vec<Outcome>],
    comparison: &Comparison,
    expected: Expected,
) -> Vec<Vec<usize>> {
    // The result a compared verifier records when it makes the same mistake.
    let mistake = match expected {
        Expected::Failure => "SUCCESS",
        Expected::Success => "FAILURE",
    };
    results
        .iter()
        .map(|outcomes| {
            let mut counts = vec![0; 2 + COMPARED.len()];
            for (case, outcome) in cases.iter().zip(outcomes) {
                if case.expected_result != expected || !is_wrong(outcome, expected) {
                    continue;
                }
                counts[0] += 1;
                let mut any = false;
                for (count, result) in counts[1..].iter_mut().zip(comparison.results(case)) {
                    *count += usize::from(result == mistake);
                    any |= result == mistake;
                }
                counts[1 + COMPARED.len()] += usize::from(!any);
            }
            counts
        })
        .collect()
}

/// A table without borders, whose columns from `numbers` on hold numbers and align right.
fn new_table(header: impl IntoIterator<Item = String>, numbers: usize) -> Table {
    let mut table = Table::new();
    table.load_preset(NOTHING);
    table.set_header(header);
    for column in table.column_iter_mut().skip(numbers) {
        column.set_cell_alignment(CellAlignment::Right);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limbo::cases::{LIMBO_COMMIT, case};

    fn accepted() -> Outcome {
        Ok(())
    }

    fn rejected() -> Outcome {
        Err("InvalidCertificate".to_string())
    }

    #[test]
    fn each_verifier_s_file_has_a_line_per_case_beside_the_compared_results() {
        let text =
            format!("# x509-limbo {LIMBO_COMMIT}\nid\tgo-1\topenssl-1\na::bad\tSUCCESS\tFAILURE\n");
        let comparison = Comparison::parse(&text).unwrap();
        let cases = [
            case("a::bad", "SERVER", &[], Expected::Failure),
            case("a::valid", "SERVER", &[], Expected::Success),
        ];
        let results = [vec![accepted(), rejected()], vec![rejected(), accepted()]];
        let dir = std::env::temp_dir().join(format!("xtask-limbo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write(&dir, &cases, &results, &comparison).unwrap();
        let rustpki = std::fs::read_to_string(dir.join("rustpki.tsv")).unwrap();
        let webpki = std::fs::read_to_string(dir.join("webpki.tsv")).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            rustpki,
            "id\texpected\trustpki\tgo-1\topenssl-1\tdetail\n\
             a::bad\tFAILURE\tSUCCESS\tSUCCESS\tFAILURE\t\n\
             a::valid\tSUCCESS\tFAILURE\tSUCCESS\tSUCCESS\tInvalidCertificate\n"
        );
        assert!(
            webpki.contains("a::bad\tFAILURE\tFAILURE\tSUCCESS\tFAILURE\tInvalidCertificate\n")
        );
    }

    #[test]
    fn the_report_shows_each_group_comparison_and_count() {
        let text = format!(
            "# x509-limbo {LIMBO_COMMIT}\nid\tgo-1\topenssl-1\nwebpki::bad\tSUCCESS\tFAILURE\n"
        );
        let comparison = Comparison::parse(&text).unwrap();
        let cases = [
            case("online::long", "SERVER", &[], Expected::Success),
            case("online::short", "SERVER", &[], Expected::Success),
            case("webpki::bad", "SERVER", &[], Expected::Failure),
        ];
        let results = [
            vec![Err("InsufficientSpace".to_string()), accepted(), accepted()],
            vec![accepted(), Err("panicked".to_string()), rejected()],
        ];
        let report = report(&cases, &results, &comparison);
        let lines: Vec<String> = report
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        for expected in [
            "Bad chains accepted. The target is 0.",
            "Group What it tests Bad chains rustpki accepted webpki accepted",
            "webpki Web PKI (CA/Browser Forum) rules 1 1 0",
            "Total 1 1 0",
            "Verifier Accepted Go also accepted OpenSSL also accepted Neither accepted",
            "rustpki 1 1 0 0",
            "webpki 0 0 0 0",
            "Valid chains rejected. The target is 0.",
            "online Real servers' chains 2 1 1",
            "Total 2 1 1",
            "rustpki 1 0 0 1",
            "webpki 1 0 0 1",
            "go-1 and openssl-1 results are from limbo's published runs, in xtask/src/limbo/go-openssl-comparison.tsv.",
            "Valid chains rejected for holding more than 16 certificates: rustpki 1, webpki 0",
            "Panics: rustpki 0, webpki 1",
        ] {
            assert!(
                lines.iter().any(|line| line == expected),
                "{expected:?} not in\n{report}"
            );
        }
    }

    #[test]
    fn groups_count_each_verifier_s_mistakes_largest_group_first() {
        let cases = [
            case("aa::bad", "SERVER", &[], Expected::Failure),
            case("zz::bad-1", "SERVER", &[], Expected::Failure),
            case("zz::bad-2", "SERVER", &[], Expected::Failure),
            case("zz::valid", "SERVER", &[], Expected::Success),
        ];
        let results = [
            vec![accepted(), accepted(), rejected(), rejected()],
            vec![rejected(), rejected(), rejected(), accepted()],
        ];
        assert_eq!(
            groups(&cases, &results, Expected::Failure),
            [
                ("zz", vec![2, 1, 0]),
                ("aa", vec![1, 1, 0]),
                ("Total", vec![3, 2, 0])
            ]
        );
        assert_eq!(
            groups(&cases, &results, Expected::Success),
            [("zz", vec![1, 1, 0]), ("Total", vec![1, 1, 0])]
        );
    }

    #[test]
    fn a_compared_verifier_shares_a_mistake_only_by_making_it_on_the_same_chain() {
        let text = format!(
            "# x509-limbo {LIMBO_COMMIT}\nid\tgo\topenssl\n\
             a::both\tSUCCESS\tSUCCESS\n\
             a::go\tSUCCESS\tFAILURE\n\
             a::skipped\tSKIPPED\tFAILURE\n\
             a::right\tSUCCESS\tSUCCESS\n\
             a::valid\tFAILURE\tSUCCESS\n"
        );
        let comparison = Comparison::parse(&text).unwrap();
        let cases = [
            case("a::both", "SERVER", &[], Expected::Failure),
            case("a::go", "SERVER", &[], Expected::Failure),
            case("a::skipped", "SERVER", &[], Expected::Failure),
            case("a::unlisted", "SERVER", &[], Expected::Failure),
            case("a::right", "SERVER", &[], Expected::Failure),
            case("a::valid", "SERVER", &[], Expected::Success),
        ];
        let results = [vec![
            accepted(),
            accepted(),
            accepted(),
            accepted(),
            rejected(),
            rejected(),
        ]];
        assert_eq!(
            shared(&cases, &results, &comparison, Expected::Failure),
            [vec![4, 2, 1, 2]]
        );
        assert_eq!(
            shared(&cases, &results, &comparison, Expected::Success),
            [vec![1, 1, 0, 0]]
        );
    }
}
