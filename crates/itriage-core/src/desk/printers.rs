//! Printers & print queue. Read-only.
//!
//! The print service first (nothing prints without it), then every real
//! printer with its state, the default printer, label printers called out,
//! and jobs stuck behind a printer that's in an error state.
//!
//! On Windows, also the Point and Print policy behind "adding the ward
//! printer asks for an administrator": who may install drivers from a print
//! server, which servers are approved, whether drivers must be
//! package-aware, and Windows protected print mode. Value names are from
//! Windows' own Printing.admx (the package settings are per-user policy).

use crate::actions::offer;
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::plural;

pub struct Printers;

impl TriageModule for Printers {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Print Spooler state, every printer's status, stuck jobs, the default printer, and label printers."
        } else {
            "CUPS scheduler state, every queue's status, stuck jobs and the default printer."
        };
        ModuleInfo::new("desk.printers", "Printers & print queue", Category::Workstation, description)
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        imp::check()
    }
}

/// One printer's row: state text, severity, and the queue fix when jobs are
/// stuck behind a problem.
fn printer_row(label: String, problems: &[String], notes: &[String], jobs: usize, detail: String) -> Finding {
    let mut parts: Vec<String> = if problems.is_empty() { vec!["ready".into()] } else { problems.to_vec() };
    parts.extend(notes.iter().cloned());
    let stuck = jobs > 0 && !problems.is_empty();
    if jobs > 0 {
        parts.push(format!("{jobs} job{} {}", plural(jobs), if stuck { "stuck" } else { "queued" }));
    }
    let severity = if !problems.is_empty() {
        Severity::Warning
    } else if !notes.is_empty() {
        Severity::Info
    } else {
        Severity::Ok
    };
    let mut f = Finding::new(label, parts.join(" · "), severity).with_detail(detail);
    if stuck {
        f = f.with_action(offer("clear-print-queue", None));
    }
    f
}

/// The Point and Print policy as the registry holds it (`None`: not set).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PointAndPrint {
    /// `RestrictDriverInstallationToAdministrators`; unset means 1 since KB5005652.
    pub restrict_to_admins: Option<u32>,
    /// Point and Print Restrictions on, and its approved-server list.
    pub restricted: Option<u32>,
    pub trusted_servers: Option<u32>,
    pub servers: Vec<String>,
    /// 1: no warning or elevation when installing.
    pub no_warning_on_install: Option<u32>,
    /// Package Point and Print: only package-aware drivers, and its server list.
    pub package_only: Option<u32>,
    pub package_list_on: Option<u32>,
    pub package_servers: Vec<String>,
    /// `WindowsProtectedPrintGroupPolicyState` (Windows 11 24H2 and later).
    pub protected_print: Option<u32>,
}

/// One connected printer, for the policy checks.
#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub name: String,
    pub server: String,
    pub driver: String,
    pub package_aware: Option<bool>,
}

fn host_of(server: &str) -> String {
    server.trim().trim_start_matches('\\').split(['\\', '.']).next().unwrap_or_default().to_ascii_lowercase()
}

/// Is `server` on a list of server names (short or fully qualified)?
fn listed(server: &str, list: &[String]) -> bool {
    let short = host_of(server);
    list.iter().any(|s| host_of(s) == short)
}

/// What the Point and Print policy means for the printers this PC uses.
pub fn point_and_print(policy: &PointAndPrint, printers: &[Connection]) -> Vec<Finding> {
    let mut out = Vec::new();
    let restricted = policy.restrict_to_admins.unwrap_or(1) != 0;
    out.push(if restricted {
        Finding::info("Printer driver installs", "administrators only (Windows' default since 2021)").with_detail(
            "A standard user can connect to a printer whose driver is already on this PC. Adding one that needs a new driver from the print server asks for an administrator: pre-install the driver, or deploy the printer by policy.",
        )
    } else if policy.no_warning_on_install == Some(1) {
        Finding::crit("Printer driver installs", "anyone, with no warning or elevation").with_detail(
            "RestrictDriverInstallationToAdministrators = 0 with NoWarningNoElevationOnInstall = 1 lets any print server install a driver silently: the PrintNightmare exposure that KB5005652 closed.",
        )
    } else {
        Finding::warn("Printer driver installs", "standard users may install drivers from print servers").with_detail(
            "RestrictDriverInstallationToAdministrators = 0 undoes the PrintNightmare hardening (KB5005652). Keep it only with an approved-server list.",
        )
    });
    let approved = policy.restricted == Some(1) && policy.trusted_servers == Some(1);
    let package_list = policy.package_list_on == Some(1);
    if approved {
        out.push(Finding::info("Approved print servers", if policy.servers.is_empty() { "none listed".to_string() } else { policy.servers.join(", ") }));
    }
    if package_list {
        out.push(Finding::info("Approved package print servers", if policy.package_servers.is_empty() { "none listed".to_string() } else { policy.package_servers.join(", ") }));
    }
    let mut servers: Vec<&str> = printers.iter().map(|p| p.server.as_str()).filter(|s| !s.is_empty()).collect();
    servers.sort_by_key(|s| s.to_ascii_lowercase());
    servers.dedup_by_key(|s| s.to_ascii_lowercase());
    for server in servers {
        let off_list = (approved && !listed(server, &policy.servers)) || (package_list && !listed(server, &policy.package_servers));
        if off_list {
            out.push(
                Finding::warn(format!("Print server {}", server.trim_start_matches('\\')), "not on the approved list")
                    .with_detail("Connecting to a printer on it warns, or asks for an administrator to install its driver. Add it to the Point and Print approved servers if it's the site's own."),
            );
        }
    }
    if policy.package_only == Some(1) {
        for p in printers.iter().filter(|p| p.package_aware == Some(false)) {
            out.push(Finding::warn(format!("{}: driver", p.name), format!("{} isn't package-aware", p.driver)).with_detail(
                "Package Point and Print only is on, so this driver can't be installed from the server on another PC. The print team needs a package-aware (v4 or signed package) driver for it.",
            ));
        }
    }
    if policy.protected_print == Some(1) {
        out.push(Finding::info("Windows protected print mode", "on: only Microsoft's inbox (IPP class) driver loads"));
        for p in printers.iter().filter(|p| !p.driver.to_ascii_lowercase().starts_with("microsoft")) {
            out.push(Finding::warn(format!("{}: driver", p.name), format!("{} won't load under protected print mode", p.driver)).with_detail(
                "Protected print mode blocks third-party drivers. This printer needs to work with Microsoft's IPP class driver (Mopria), or protected print turned off for this PC.",
            ));
        }
    }
    out
}

fn summarise(physical: usize, attention: usize) -> String {
    match (physical, attention) {
        (0, _) => "Print service running · no printers installed".into(),
        (n, 0) => format!("{n} printer{} ready", plural(n)),
        (n, a) => format!("{n} printer{} · {a} need{} attention", plural(n), if a == 1 { "s" } else { "" }),
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::parse::printer::{is_label_printer, is_virtual, windows_status};
    use super::{point_and_print, Connection, PointAndPrint};
    use crate::win::{printing, scm};

    pub fn check() -> Result<Output, String> {
        match scm::query("Spooler")? {
            None => {
                return Ok(Output::new(
                    "Printing isn't installed on this machine",
                    vec![Finding::info("Print Spooler", "not installed")],
                ))
            }
            // Servers often disable the spooler on purpose (PrintNightmare hardening).
            Some(s) if !s.running && s.start == scm::StartMode::Disabled => {
                return Ok(Output::new(
                    "Printing is turned off on this machine",
                    vec![Finding::info("Print Spooler", "disabled · printing is turned off here")],
                ))
            }
            Some(s) if !s.running => {
                return Ok(Output::new(
                    "The Print Spooler isn't running, so nothing can print",
                    vec![Finding::crit("Print Spooler", format!("{} · nothing can print", s.state))
                        .with_action(offer("restart-spooler", None))],
                ))
            }
            Some(_) => {}
        }
        let mut findings = vec![Finding::ok("Print Spooler", "running")];
        let printers = printing::printers().map_err(|e| crate::win::err("can't list printers", &e))?;
        let default = printing::default_printer();

        let (mut virtuals, mut physical, mut attention) = (0usize, 0usize, 0usize);
        for p in &printers {
            if is_virtual(&p.name, &p.port) {
                virtuals += 1;
                continue;
            }
            physical += 1;
            let (problems, notes) = windows_status(p.status, p.attributes);
            let mut tags = Vec::new();
            if default.as_deref() == Some(p.name.as_str()) {
                tags.push("default");
            }
            if is_label_printer(&p.name, &p.driver) {
                tags.push("label printer");
            }
            let label = if tags.is_empty() { p.name.clone() } else { format!("{} ({})", p.name, tags.join(", ")) };
            let problems: Vec<String> = problems.iter().map(|s| s.to_string()).collect();
            let notes: Vec<String> = notes.iter().map(|s| s.to_string()).collect();
            if !problems.is_empty() {
                attention += 1;
            }
            findings.push(printer_row(
                label,
                &problems,
                &notes,
                p.jobs as usize,
                format!("{} · port {}", p.driver, p.port),
            ));
        }
        findings.push(match &default {
            Some(d) => Finding::info("Default printer", d.clone()),
            None => Finding::info("Default printer", "none set"),
        });
        if virtuals > 0 {
            findings.push(Finding::info("Software printers (PDF, XPS, OneNote, fax)", virtuals.to_string()));
        }
        let drivers = printing::drivers();
        let connections: Vec<Connection> = printers
            .iter()
            .filter(|p| !is_virtual(&p.name, &p.port))
            .map(|p| Connection {
                name: p.name.clone(),
                server: if p.server.is_empty() && p.name.starts_with("\\\\") { p.name.rsplit_once('\\').map(|(s, _)| s).unwrap_or_default().to_string() } else { p.server.clone() },
                driver: p.driver.clone(),
                package_aware: drivers.iter().find(|(d, _)| d.eq_ignore_ascii_case(&p.driver)).map(|(_, aware)| *aware),
            })
            .collect();
        findings.extend(point_and_print(&policy(), &connections));
        Ok(Output::new(summarise(physical, attention), findings))
    }

    /// The Point and Print policy: machine policy, then the signed-in
    /// user's (the package settings are user policy).
    fn policy() -> PointAndPrint {
        use crate::win::registry::{read_dword, read_string, values, HKLM};
        const PNP: &str = r"Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
        const PACKAGE: &str = r"Software\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint";
        const WPP: &str = r"Software\Policies\Microsoft\Windows NT\Printers\WPP";
        let user_hive = crate::win::session::person().ok().map(|p| (p.root, p.prefix));
        let dword = |name: &str, key: &str| {
            read_dword(HKLM, key, name).or_else(|| user_hive.as_ref().and_then(|(root, prefix)| read_dword(*root, &format!("{prefix}{key}"), name)))
        };
        let list = |text: Option<String>| -> Vec<String> {
            text.map(|t| t.split(';').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()).unwrap_or_default()
        };
        // The approved package servers are values under ListofServers; Group
        // Policy writes the server as the value's data (and sometimes its
        // name), so both are read.
        let package_servers = {
            let key = format!(r"{PACKAGE}\ListofServers");
            let mut found: Vec<String> = Vec::new();
            for (root, prefix) in [(HKLM, String::new())].into_iter().chain(user_hive.clone()) {
                for (name, data) in values(root, &format!("{prefix}{key}")) {
                    let server = data.filter(|d| !d.trim().is_empty()).unwrap_or(name);
                    if !server.trim().is_empty() && !found.iter().any(|f| f.eq_ignore_ascii_case(server.trim())) {
                        found.push(server.trim().to_string());
                    }
                }
            }
            found
        };
        PointAndPrint {
            restrict_to_admins: dword("RestrictDriverInstallationToAdministrators", PNP),
            restricted: dword("Restricted", PNP),
            trusted_servers: dword("TrustedServers", PNP),
            servers: list(read_string(HKLM, PNP, "ServerList").or_else(|| user_hive.as_ref().and_then(|(r, p)| read_string(*r, &format!("{p}{PNP}"), "ServerList")))),
            no_warning_on_install: dword("NoWarningNoElevationOnInstall", PNP),
            package_only: dword("PackagePointAndPrintOnly", PACKAGE),
            package_list_on: dword("PackagePointAndPrintServerList", PACKAGE),
            package_servers,
            protected_print: read_dword(HKLM, WPP, "WindowsProtectedPrintGroupPolicyState"),
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::parse::printer::{cups_default, cups_job_counts, cups_printers};
    use crate::util::{capture, cmd, command_exists};

    fn lpstat(args: &[&str]) -> String {
        let mut c = cmd("lpstat");
        c.args(args).env("LC_ALL", "C");
        capture(c).map(|o| o.stdout).unwrap_or_default()
    }

    pub fn check() -> Result<Output, String> {
        if !command_exists("lpstat") {
            return Ok(Output::new(
                "No print system installed",
                vec![Finding::info("CUPS", "not installed (no lpstat)")],
            ));
        }
        if !lpstat(&["-r"]).contains("scheduler is running") {
            return Ok(Output::new(
                "The CUPS scheduler isn't running, so nothing can print",
                vec![Finding::crit("CUPS scheduler", "not running").with_action(offer("restart-spooler", None))],
            ));
        }
        let mut findings = vec![Finding::ok("CUPS scheduler", "running")];
        let queues = cups_printers(&lpstat(&["-p"]));
        let default = cups_default(&lpstat(&["-d"]));
        let jobs = cups_job_counts(&lpstat(&["-o"]));

        let mut attention = 0;
        for q in &queues {
            let mut problems = Vec::new();
            if !q.enabled {
                problems.push(match &q.reason {
                    Some(r) => format!("stopped ({r})"),
                    None => "stopped".to_string(),
                });
                attention += 1;
            }
            let notes: Vec<String> = if q.printing { vec!["printing".into()] } else { Vec::new() };
            let label = if default.as_deref() == Some(q.name.as_str()) {
                format!("{} (default)", q.name)
            } else {
                q.name.clone()
            };
            let detail = if q.enabled { q.reason.clone().unwrap_or_default() } else { String::new() };
            let row = printer_row(label, &problems, &notes, jobs.get(&q.name).copied().unwrap_or(0), detail);
            // "printing" is good news, not a note worth an info dot.
            findings.push(if q.printing && problems.is_empty() { Finding { severity: Severity::Ok, ..row } } else { row });
        }
        findings.push(Finding::info("Default printer", default.unwrap_or_else(|| "none set".into())));
        Ok(Output::new(summarise(queues.len(), attention), findings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ward(server: &str, driver: &str, package_aware: Option<bool>) -> Connection {
        Connection { name: format!(r"{server}\Ward 4 Laser"), server: server.into(), driver: driver.into(), package_aware }
    }

    #[test]
    fn the_default_is_admins_only_and_a_server_off_the_list_is_flagged() {
        let policy = PointAndPrint {
            restricted: Some(1),
            trusted_servers: Some(1),
            servers: vec!["PRN01.corp.example.org".into(), "prn02".into()],
            ..PointAndPrint::default()
        };
        let printers = [ward(r"\\prn01", "HP Universal Printing PCL 6", Some(true)), ward(r"\\PRN09.corp.example.org", "Brother Laser Type1 Class Driver", Some(true))];
        let rows = point_and_print(&policy, &printers);
        assert_eq!((rows[0].label.as_str(), rows[0].severity), ("Printer driver installs", Severity::Info));
        assert_eq!(rows[1].value, "PRN01.corp.example.org, prn02");
        let off: Vec<&str> = rows.iter().filter(|r| r.label.starts_with("Print server ")).map(|r| r.label.as_str()).collect();
        assert_eq!(off, ["Print server PRN09.corp.example.org"], "short and full names match each other, whatever their case");
    }

    #[test]
    fn opened_up_installs_are_graded_by_how_far() {
        let silent = PointAndPrint { restrict_to_admins: Some(0), no_warning_on_install: Some(1), ..PointAndPrint::default() };
        assert_eq!(point_and_print(&silent, &[])[0].severity, Severity::Critical);
        let open = PointAndPrint { restrict_to_admins: Some(0), ..PointAndPrint::default() };
        assert_eq!(point_and_print(&open, &[])[0].severity, Severity::Warning);
        assert_eq!(point_and_print(&PointAndPrint { restrict_to_admins: Some(1), no_warning_on_install: Some(1), ..PointAndPrint::default() }, &[])[0].severity, Severity::Info, "admins-only wins over the warning settings");
    }

    #[test]
    fn package_only_and_protected_print_flag_the_drivers_that_wont_work() {
        let policy = PointAndPrint { package_only: Some(1), package_list_on: Some(1), package_servers: vec!["prn01".into()], protected_print: Some(1), ..PointAndPrint::default() };
        let printers = [ward(r"\\prn01", "Old Ward Driver v3", Some(false)), ward(r"\\prn01", "Microsoft IPP Class Driver", Some(true)), ward(r"\\prn01", "Unknown", None)];
        let rows = point_and_print(&policy, &printers);
        let driver_rows: Vec<&str> = rows.iter().filter(|r| r.label.ends_with(": driver")).map(|r| r.value.as_str()).collect();
        assert_eq!(driver_rows, ["Old Ward Driver v3 isn't package-aware", "Old Ward Driver v3 won't load under protected print mode", "Unknown won't load under protected print mode"]);
        assert!(rows.iter().any(|r| r.label == "Windows protected print mode"));
        assert!(!rows.iter().any(|r| r.label.starts_with("Print server ")), "prn01 is on the package list");
    }
}
