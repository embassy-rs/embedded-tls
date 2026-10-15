//! Tasks for this repository, run with `cargo xtask <task>`.

mod fetch;
mod limbo;

use clap::Parser;
use std::process::ExitCode;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(about = "Tasks for this repository.")]
enum Task {
    /// Runs the x509-limbo test suite through the certificate verifiers.
    Limbo {
        /// Rewrites xtask/src/limbo/go-openssl-comparison.tsv, Go's and OpenSSL's results, from
        /// limbo's published runs.
        #[arg(long)]
        update_comparison: bool,
    },
}

fn main() -> ExitCode {
    let result = match Task::parse() {
        Task::Limbo { update_comparison } if update_comparison => limbo::comparison::update(),
        Task::Limbo { .. } => limbo::run(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
