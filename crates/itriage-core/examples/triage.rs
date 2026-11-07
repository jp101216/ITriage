//! Headless runner for itriage-core. Useful on boxes without a desktop, over
//! SSH, and for exercising modules while developing.
//!
//!   cargo run -p itriage-core --example triage -- --list
//!   cargo run -p itriage-core --example triage                  # every read-only module
//!   cargo run -p itriage-core --example triage -- proc.services eventlog.errors
//!   cargo run -p itriage-core --example triage -- --json update.scan
//!
//! Mutating modules only run when named explicitly.

use itriage_core::{host_context, registry, RunContext};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");

    if args.iter().any(|a| a == "--list") {
        for m in registry() {
            let i = m.info();
            let mut tags = Vec::new();
            if i.mutating {
                tags.push("mutating");
            }
            if i.requires_admin {
                tags.push("admin");
            }
            let tags = if tags.is_empty() { String::new() } else { format!("  [{}]", tags.join(", ")) };
            println!("{:<18} {}{tags}", i.id, i.title);
        }
        return;
    }

    let ids: Vec<String> = args.iter().filter(|a| !a.starts_with("--")).cloned().collect();
    let modules: Vec<_> = registry()
        .into_iter()
        .filter(|m| {
            let i = m.info();
            if ids.is_empty() {
                !i.mutating
            } else {
                ids.contains(&i.id)
            }
        })
        .collect();
    if modules.is_empty() {
        eprintln!("No matching modules. Try --list.");
        std::process::exit(2);
    }

    let host = host_context();
    eprintln!(
        "itriage · {} · {} · {}",
        host.hostname,
        host.os,
        if host.elevated { "elevated" } else { "standard user" }
    );

    let log = |line: &str| eprintln!("    · {line}");
    let ctx = RunContext::new(&log);
    let mut results = Vec::new();
    for m in &modules {
        eprintln!("▶ {}", m.info().title);
        results.push(m.run(&ctx));
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&results).expect("results serialize"));
        return;
    }

    println!();
    for r in &results {
        let status = format!("{:?}", r.status()).to_uppercase();
        let summary = match &r.error {
            Some(_) => "FAILED",
            None => r.summary.as_str(),
        };
        println!("[{status}] {} ({} ms): {summary}", r.title, r.duration_ms);
        if let Some(e) = &r.error {
            println!("    error: {e}");
        }
        for f in &r.findings {
            println!("    {:<9} {}: {}", format!("{:?}", f.severity).to_lowercase(), f.label, f.value);
            if let Some(d) = &f.detail {
                println!("              {d}");
            }
        }
        println!();
    }
}
