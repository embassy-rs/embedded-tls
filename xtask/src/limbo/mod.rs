//! Runs the x509-limbo test suite through each certificate verifier, and prints how many chains
//! each one gets wrong, beside Go's and OpenSSL's results for the same chains.

mod cases;
pub mod comparison;
mod report;
mod verify;

use crate::Result;
use cases::Case;
use comparison::Comparison;
use verify::{Outcome, VERIFIERS};

/// Features no verifier here can be given. A case that needs one is skipped.
const UNSUPPORTED: &[&str] = &["has-crl", "has-mldsa", "max-chain-depth"];

pub fn run() -> Result<()> {
    let (dir, limbo) = cases::load()?;
    let comparison = Comparison::load()?;
    let total = limbo.testcases.len();
    let (cases, client, unsupported) = select(limbo.testcases);

    // A verifier that panics fails that case, and the report counts it.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let results: Vec<Vec<Outcome>> = VERIFIERS
        .iter()
        .map(|&(_, verify)| {
            cases
                .iter()
                .map(|case| verify::check(case, verify))
                .collect()
        })
        .collect();
    std::panic::set_hook(hook);

    println!(
        "x509-limbo {}: {total} cases, {} run. Skipped: {client} client certificates, \
         {unsupported} that need a revocation list, an ML-DSA key or a chain depth limit.",
        &cases::LIMBO_COMMIT[..7],
        cases.len(),
    );
    print!("{}", report::report(&cases, &results, &comparison));
    report::write(&dir, &cases, &results, &comparison)
}

/// The cases a server-certificate verifier can be given, then how many cases were skipped for
/// checking a client certificate, and how many for needing a feature in `UNSUPPORTED`.
fn select(cases: Vec<Case>) -> (Vec<Case>, usize, usize) {
    let (server, client): (Vec<Case>, Vec<Case>) = cases
        .into_iter()
        .partition(|case| case.validation_kind == "SERVER");
    let (run, unsupported): (Vec<Case>, Vec<Case>) = server.into_iter().partition(|case| {
        !case
            .features
            .iter()
            .any(|feature| UNSUPPORTED.contains(&feature.as_str()))
    });
    (run, client.len(), unsupported.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cases::{Expected, case};

    #[test]
    fn client_cases_and_cases_needing_an_unsupported_feature_are_skipped() {
        let cases = vec![
            case("a::server", "SERVER", &[], Expected::Success),
            case("a::client", "CLIENT", &[], Expected::Success),
            case("a::client-crl", "CLIENT", &["has-crl"], Expected::Failure),
            case("a::crl", "SERVER", &["has-crl"], Expected::Failure),
            case(
                "a::mldsa",
                "SERVER",
                &["pedantic-rfc5280", "has-mldsa"],
                Expected::Success,
            ),
            case(
                "a::depth",
                "SERVER",
                &["max-chain-depth"],
                Expected::Failure,
            ),
            case(
                "a::pedantic",
                "SERVER",
                &["pedantic-rfc5280"],
                Expected::Failure,
            ),
        ];
        let (run, client, unsupported) = select(cases);
        let ids: Vec<&str> = run.iter().map(|case| case.id.as_str()).collect();
        assert_eq!(
            (ids, client, unsupported),
            (vec!["a::server", "a::pedantic"], 2, 3)
        );
    }
}
