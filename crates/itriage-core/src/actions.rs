//! One-click fixes offered on findings ("Restart Print Spooler").
//!
//! Every fix is a fixed, built-in procedure. A site profile can only switch
//! fixes off (its `fixes` allowlist), never define new commands, and the one
//! fix that takes a target (`start-service`) validates the service name before
//! using it. Each attempt is checked against the policy again at run time,
//! whatever the UI showed, and audited whether it succeeds or not.

use crate::model::FixRef;
use crate::profile::Profile;

pub struct FixSpec {
    pub id: &'static str,
    pub label: &'static str,
    /// What the confirmation dialog says the fix does.
    pub description: &'static str,
    /// Takes a target (a service name).
    pub targeted: bool,
}

pub const FIXES: &[FixSpec] = &[
    FixSpec {
        id: "restart-spooler",
        label: "Restart Print Spooler",
        description: "Restarts the print service (Print Spooler or CUPS). A job that is printing right now starts over.",
        targeted: false,
    },
    FixSpec {
        id: "clear-print-queue",
        label: "Clear print queue",
        description: "Stops the print service, deletes every waiting print job, and starts it again. People will need to print those documents again.",
        targeted: false,
    },
    FixSpec {
        id: "resync-time",
        label: "Resync clock",
        description: "Tells the time service to synchronise with its time source now.",
        targeted: false,
    },
    FixSpec {
        id: "gpupdate",
        label: "Refresh Group Policy",
        description: "Runs gpupdate /force to reapply computer and user policy. It can take a minute.",
        targeted: false,
    },
    FixSpec {
        id: "start-service",
        label: "Start service",
        description: "Starts the stopped service.",
        targeted: true,
    },
    FixSpec {
        id: "flush-dns",
        label: "Flush DNS cache",
        description: "Clears cached DNS lookups so names are looked up fresh.",
        targeted: false,
    },
];

pub fn spec(id: &str) -> Option<&'static FixSpec> {
    FIXES.iter().find(|f| f.id == id)
}

/// Does this fix need administrator/root rights on this OS?
pub fn requires_admin(id: &str) -> bool {
    !matches!(id, "gpupdate" | "flush-dns")
}

/// The button a module attaches to a finding. Panics on an unknown id, which
/// is a programming error caught by the tests.
pub fn offer(id: &str, target: Option<&str>) -> FixRef {
    let spec = spec(id).unwrap_or_else(|| panic!("unknown fix id {id}"));
    let label = match target {
        Some(t) if id == "start-service" => format!("Start {t}"),
        _ => spec.label.to_string(),
    };
    FixRef {
        id: id.to_string(),
        label,
        target: target.map(str::to_string),
        requires_admin: requires_admin(id),
    }
}

/// Service and unit names: letters, digits and `_ . - @ : $`, not starting
/// with `-` (so a name can never be read as an option).
pub fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-@:$".contains(c))
}

/// Run a fix: check it exists, validate the target, re-check the site
/// policy, run it, and audit the outcome. Blocking; may take a minute.
pub fn run(id: &str, target: Option<&str>, profile: &Profile) -> Result<String, String> {
    let spec = spec(id).ok_or_else(|| format!("Unknown fix `{id}`."))?;
    if spec.targeted && target.is_none() {
        return Err(format!("The {} fix needs a target.", spec.label));
    }
    let target = if spec.targeted { target } else { None };
    if let Some(t) = target {
        if !valid_service_name(t) {
            return Err(format!("`{t}` isn't a valid service name."));
        }
    }
    if !profile.fix_allowed(id, target) {
        let outcome = Err("Blocked by site policy: this fix isn't allowed on this machine.".to_string());
        crate::audit::fix_ran(id, target, &outcome);
        return outcome;
    }
    let outcome = imp::run(id, target);
    crate::audit::fix_ran(id, target, &outcome);
    outcome
}

#[cfg(windows)]
mod imp {
    use crate::parse::text::first_line;
    use crate::util::{capture, cmd, exit_label, require_admin, stream};
    use crate::win::scm;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(30);

    pub fn run(id: &str, target: Option<&str>) -> Result<String, String> {
        match id {
            "restart-spooler" => {
                require_admin()?;
                scm::stop("Spooler", WAIT)?;
                scm::start("Spooler", WAIT)?;
                Ok("Print Spooler restarted.".into())
            }
            "clear-print-queue" => {
                require_admin()?;
                scm::stop("Spooler", WAIT)?;
                let removed = clear_spool_folder();
                let started = scm::start("Spooler", WAIT);
                let removed = removed?;
                started?;
                Ok(format!(
                    "Removed {removed} spooled file{} and restarted the Print Spooler.",
                    crate::util::plural(removed)
                ))
            }
            "resync-time" => {
                require_admin()?;
                if !scm::query("W32Time")?.is_some_and(|s| s.running) {
                    scm::start("W32Time", WAIT)?;
                }
                // Plain /resync first; /rediscover also re-finds the source
                // (a new DC, a changed NTP setting) and takes a little longer.
                let w32tm = |args: &[&str]| {
                    let mut c = cmd("w32tm");
                    c.args(args);
                    capture(c)
                };
                let mut out = w32tm(&["/resync"])?;
                if !out.success() {
                    out = w32tm(&["/resync", "/rediscover"])?;
                }
                if out.success() {
                    Ok("Clock resynchronised with its time source.".into())
                } else {
                    Err(format!(
                        "w32tm couldn't resync ({}): {}",
                        exit_label(out.code),
                        first_line(&out.combined())
                    ))
                }
            }
            "gpupdate" => {
                let mut c = cmd("gpupdate");
                c.args(["/force", "/wait:120"]);
                let out = stream(c, &crate::module::RunContext::silent(), Duration::from_secs(300))?;
                if out.success() {
                    Ok("Group Policy refreshed.".into())
                } else {
                    Err(format!(
                        "gpupdate reported a problem ({}): {}",
                        exit_label(out.code),
                        crate::parse::text::truncate_chars(&crate::parse::text::collapse_whitespace(&out.stdout), 300)
                    ))
                }
            }
            "start-service" => {
                require_admin()?;
                let name = target.ok_or("No service named.")?;
                scm::start(name, WAIT)?;
                Ok(format!("{name} started."))
            }
            "flush-dns" => crate::fixes::dns::flush().map(|(_, said)| said),
            other => Err(format!("Fix `{other}` isn't available on Windows.")),
        }
    }

    /// Delete everything in the spool folder while the spooler is stopped.
    fn clear_spool_folder() -> Result<usize, String> {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let dir = std::path::Path::new(&root).join(r"System32\spool\PRINTERS");
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("can't open {}: {e}", dir.display()))?;
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::parse::text::first_line;
    use crate::util::{capture, command_exists, exit_label, pkexec_error, privileged};

    pub fn run(id: &str, target: Option<&str>) -> Result<String, String> {
        match id {
            "restart-spooler" => root("systemctl", &["restart", "cups"]).map(|_| "CUPS restarted.".into()),
            "clear-print-queue" => root("cancel", &["-a", "-x"]).map(|_| "Every queued print job was cancelled.".into()),
            "resync-time" => {
                if command_exists("chronyc") {
                    root("chronyc", &["makestep"]).map(|_| "chrony stepped the clock to its sources.".into())
                } else {
                    root("systemctl", &["restart", "systemd-timesyncd"])
                        .map(|_| "systemd-timesyncd restarted; it syncs within a few seconds.".into())
                }
            }
            "start-service" => {
                let unit = target.ok_or("No unit named.")?;
                root("systemctl", &["start", "--", unit]).map(|_| format!("{unit} started."))
            }
            "flush-dns" => crate::fixes::dns::flush().map(|(_, said)| said),
            "gpupdate" => Err("Group Policy is a Windows feature.".into()),
            other => Err(format!("Fix `{other}` isn't available on Linux.")),
        }
    }

    /// Run as root through pkexec (argument array, no shell).
    fn root(program: &str, args: &[&str]) -> Result<String, String> {
        let (c, via_pkexec) = privileged(program, args)?;
        let out = capture(c)?;
        if via_pkexec {
            if let Some(why) = pkexec_error(out.code) {
                return Err(why.to_string());
            }
        }
        if out.success() {
            Ok(out.combined())
        } else {
            Err(format!("`{program}` failed ({}): {}", exit_label(out.code), first_line(&out.combined())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fix_can_be_offered() {
        for f in FIXES {
            let r = offer(f.id, f.targeted.then_some("Spooler"));
            assert_eq!(r.id, f.id);
        }
        assert_eq!(offer("start-service", Some("W32Time")).label, "Start W32Time");
        assert!(!offer("gpupdate", None).requires_admin);
    }

    #[test]
    fn validates_service_names() {
        assert!(valid_service_name("Spooler"));
        assert!(valid_service_name("MSSQL$SQLEXPRESS"));
        assert!(valid_service_name("getty@tty1.service"));
        assert!(!valid_service_name("--now"));
        assert!(!valid_service_name("cups; reboot"));
        assert!(!valid_service_name("a b"));
        assert!(!valid_service_name(""));
    }

    #[test]
    fn refuses_unknown_bad_and_blocked_fixes() {
        let open = Profile::default();
        assert!(run("format-disk", None, &open).unwrap_err().contains("Unknown"));
        assert!(run("start-service", None, &open).unwrap_err().contains("target"));
        assert!(run("start-service", Some("x;y"), &open).unwrap_err().contains("valid"));
        let locked = Profile::fail_closed();
        assert!(run("flush-dns", None, &locked).unwrap_err().contains("policy"));
    }
}
