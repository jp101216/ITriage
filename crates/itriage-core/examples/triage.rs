//! The command line, runnable without building the app. The installed app is
//! the same command line: `itriage --help` (or `itriage.exe --help`).
//!
//!   cargo run -p itriage-core --example triage -- --list
//!   cargo run -p itriage-core --example triage                    # every read-only check
//!   cargo run -p itriage-core --example triage -- --preset triage --target intranet.example.org
//!   cargo run -p itriage-core --example triage -- --preset tuneup --what-if
//!   cargo run -p itriage-core --example triage -- --json > report.json
//!
//! Exit codes: 0 finished, 1 nothing could run, 2 incomplete, 3010 (3 on
//! Linux) restart required.

fn main() {
    std::process::exit(itriage_core::cli::main(std::env::args().skip(1).collect()));
}
