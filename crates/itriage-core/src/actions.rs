//! One-click fixes offered on findings ("Restart Print Spooler").
//!
//! Every fix is a fixed, built-in procedure. A site profile can only switch
//! fixes off (its `fixes` allowlist), never define new commands. The fixes
//! that take a target validate it before using it: a service name, an OEM
//! tool from the built-in list, or a Windows Update identity (a GUID). Each
//! attempt is checked against the policy (and remote-safe mode, for fixes
//! that could drop a session or restart the PC) again at run time, whatever
//! the UI showed, and audited whether it succeeds or not.

use crate::model::FixRef;
use crate::profile::Profile;

pub struct FixSpec {
    pub id: &'static str,
    pub label: &'static str,
    /// What the confirmation dialog says the fix does.
    pub description: &'static str,
    /// Takes a target (a service name, an OEM tool's winget id, an update id).
    pub targeted: bool,
    /// Drops a remote session or restarts the PC: remote-safe mode blocks it.
    pub disruptive: bool,
    /// Installs software: the policy's `allow_installs` must be on too.
    pub install: bool,
    /// Offered to technicians only: the self-service view never shows it.
    pub technician_only: bool,
}

pub const FIXES: &[FixSpec] = &[
    FixSpec {
        id: "restart-spooler",
        label: "Restart Print Spooler",
        description: "Restarts the print service (Print Spooler or CUPS). A job that is printing right now starts over.",
        targeted: false,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "clear-print-queue",
        label: "Clear print queue",
        description: "Stops the print service, deletes every waiting print job, and starts it again. People will need to print those documents again.",
        targeted: false,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "resync-time",
        label: "Resync clock",
        description: "Tells the time service to synchronise with its time source now.",
        targeted: false,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "gpupdate",
        label: "Refresh Group Policy",
        description: "Runs gpupdate /force to reapply computer and user policy. It can take a minute, and network policies can blip connections.",
        targeted: false,
        disruptive: true,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "start-service",
        label: "Start service",
        description: "Starts the stopped service.",
        targeted: true,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "flush-dns",
        label: "Flush DNS cache",
        description: "Clears cached DNS lookups so names are looked up fresh.",
        targeted: false,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "restart-computer",
        label: "Restart in 60 s",
        description: "Restarts this PC in 60 seconds. The signed-in user is warned to save their work, and Cancel restart stops it.",
        targeted: false,
        disruptive: true,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "cancel-restart",
        label: "Cancel restart",
        description: "Cancels a scheduled restart.",
        targeted: false,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "install-oem-tool",
        label: "Install the OEM tool",
        description: "Installs the manufacturer's driver and BIOS tool with winget, so driver and firmware updates can go through it.",
        targeted: true,
        disruptive: false,
        install: true,
        technician_only: true,
    },
    FixSpec {
        id: "install-update",
        label: "Install this update",
        description: "Downloads and installs this one update from Windows Update. A restart may be needed afterwards.",
        targeted: true,
        disruptive: false,
        install: true,
        technician_only: true,
    },
    FixSpec {
        id: "clear-saved-credentials",
        label: "Remove saved credentials",
        description: "Removes the credentials saved in Credential Manager under the signed-in account's name (file servers, Remote Desktop hosts, Office sign-ins). Windows asks for the password the next time each is used. Other accounts' saved credentials are left alone.",
        targeted: false,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "logoff-session",
        label: "Sign out the session",
        description: "Signs out this person's disconnected session on this PC. Programs still open in it are closed, and unsaved work in it is lost.",
        targeted: true,
        disruptive: false,
        install: false,
        technician_only: true,
    },
    FixSpec {
        id: "unlock-account",
        label: "Unlock the account",
        description: "Clears the account's lockout. It needs an account that's allowed to unlock users. If something is still using the old password, the account locks again.",
        targeted: true,
        disruptive: false,
        install: false,
        technician_only: true,
    },
    FixSpec {
        id: "purge-kerberos-tickets",
        label: "Clear Kerberos tickets",
        description: "Removes the Kerberos tickets cached for this sign-in (klist purge). Windows gets new ones the next time each file share, intranet site or app is opened; nothing else changes. It acts on the account ITriage runs as, so run ITriage as the signed-in user, not elevated.",
        targeted: false,
        disruptive: false,
        install: false,
        technician_only: false,
    },
    FixSpec {
        id: "revert-tuneup",
        label: "Revert tune-up",
        description: "Puts TCP receive autotuning and the adapters' sleep settings back to what they were before TCP autotuning & NIC power last changed them. Adapter settings apply the next time each adapter restarts.",
        targeted: false,
        disruptive: true,
        install: false,
        technician_only: true,
    },
];

pub fn spec(id: &str) -> Option<&'static FixSpec> {
    FIXES.iter().find(|f| f.id == id)
}

/// Does this fix need administrator/root rights on this OS?
pub fn requires_admin(id: &str) -> bool {
    if cfg!(windows) {
        !matches!(id, "gpupdate" | "flush-dns" | "restart-computer" | "cancel-restart" | "clear-saved-credentials" | "purge-kerberos-tickets")
    } else {
        !matches!(id, "gpupdate" | "flush-dns" | "clear-saved-credentials" | "purge-kerberos-tickets")
    }
}

/// The button a module attaches to a finding. Panics on an unknown id, which
/// is a programming error caught by the tests.
pub fn offer(id: &str, target: Option<&str>) -> FixRef {
    let spec = spec(id).unwrap_or_else(|| panic!("unknown fix id {id}"));
    let label = match target {
        Some(t) if id == "start-service" => format!("Start {t}"),
        Some(t) if id == "logoff-session" => format!("Sign out session {t}"),
        Some(t) if id == "unlock-account" => format!("Unlock {t}"),
        Some(t) if id == "install-oem-tool" => crate::update::oem::tool_name(t)
            .map(|n| format!("Install {n}"))
            .unwrap_or_else(|| spec.label.to_string()),
        _ => spec.label.to_string(),
    };
    FixRef {
        id: id.to_string(),
        label,
        target: target.map(str::to_string),
        requires_admin: requires_admin(id),
    }
}

/// A Windows Update identity: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn valid_update_id(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Check a fix's target for what that fix takes.
fn validate_target(id: &str, target: &str) -> Result<(), String> {
    let ok = match id {
        "start-service" => valid_service_name(target),
        "install-oem-tool" => crate::update::oem::tool_name(target).is_some(),
        "install-update" => valid_update_id(target),
        "logoff-session" => target.len() <= 6 && !target.is_empty() && target.chars().all(|c| c.is_ascii_digit()),
        "unlock-account" => crate::desk::account::valid_account_name(target),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(match id {
            "install-oem-tool" => format!("`{target}` isn't one of the OEM tools ITriage installs."),
            "install-update" => format!("`{target}` isn't a Windows Update identity."),
            "logoff-session" => format!("`{target}` isn't a session number."),
            "unlock-account" => format!("`{target}` isn't an account name."),
            _ => format!("`{target}` isn't a valid service name."),
        })
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

/// What a fix would do here, changing nothing: the preview (what-if) for
/// one-click fixes. Fixes that act on something countable say how much;
/// the rest repeat what the confirmation says. The policy is checked the
/// same way a real run checks it.
pub fn preview(id: &str, target: Option<&str>, profile: &Profile, remote_safe: bool) -> Result<String, String> {
    let spec = spec(id).ok_or_else(|| format!("Unknown fix `{id}`."))?;
    let target = if spec.targeted { target } else { None };
    if let Some(t) = target {
        validate_target(id, t)?;
    }
    if !profile.fix_allowed(id, target) {
        return Err("Blocked by site policy: this fix isn't allowed on this machine.".into());
    }
    if spec.install && !profile.policy.allow_installs {
        return Err("Blocked by site policy: software is deployed centrally here.".into());
    }
    if spec.disruptive && remote_safe {
        return Err("Remote-safe mode is on: this could drop the remote session or restart the PC.".into());
    }
    let specific = imp::preview(id, target);
    Ok(format!("Preview: {}", specific.unwrap_or_else(|| format!("{}. Nothing was changed.", spec.description.trim_end_matches('.')))))
}

/// Run a fix: check it exists, validate the target, re-check the site
/// policy and remote-safe mode, run it, and audit the outcome. Blocking; an
/// update install can take many minutes.
pub fn run(id: &str, target: Option<&str>, profile: &Profile, remote_safe: bool) -> Result<String, String> {
    run_for(id, target, profile, remote_safe, None)
}

/// [`run`], with the ticket the fix is for, which goes into the audit trail.
pub fn run_for(id: &str, target: Option<&str>, profile: &Profile, remote_safe: bool, ticket: Option<&str>) -> Result<String, String> {
    let ticket = ticket.and_then(crate::report::clean_ticket);
    let ticket = ticket.as_deref();
    let spec = spec(id).ok_or_else(|| format!("Unknown fix `{id}`."))?;
    if spec.targeted && target.is_none() {
        return Err(format!("The {} fix needs a target.", spec.label));
    }
    let target = if spec.targeted { target } else { None };
    if let Some(t) = target {
        validate_target(id, t)?;
    }
    let blocked = if !profile.fix_allowed(id, target) {
        Some("Blocked by site policy: this fix isn't allowed on this machine.")
    } else if spec.install && !profile.policy.allow_installs {
        Some("Blocked by site policy: software is deployed centrally here.")
    } else if spec.disruptive && remote_safe {
        Some("Remote-safe mode is on: this could drop the remote session or restart the PC.")
    } else {
        None
    };
    if let Some(why) = blocked {
        crate::audit::fix_refused(id, target, why, ticket);
        return Err(why.to_string());
    }
    let outcome = imp::run(id, target);
    crate::audit::fix_ran(id, target, &outcome, ticket);
    outcome
}

/// A fix's message, with the services that had to be stopped and started
/// along with it. One that didn't come back makes the whole fix an error:
/// the technician needs to know something is now down.
#[cfg_attr(not(windows), allow(dead_code))]
fn with_dependents(done: String, restarted: &[(String, Result<(), String>)]) -> Result<String, String> {
    let ok: Vec<&str> = restarted.iter().filter(|(_, r)| r.is_ok()).map(|(n, _)| n.as_str()).collect();
    let failed: Vec<String> = restarted
        .iter()
        .filter_map(|(n, r)| r.as_ref().err().map(|e| format!("{n} ({e})")))
        .collect();
    let also = if ok.is_empty() { String::new() } else { format!(" Also restarted, because they depend on it: {}.", ok.join(", ")) };
    if failed.is_empty() {
        Ok(format!("{done}{also}"))
    } else {
        Err(format!("{done}{also} But these were stopped for it and didn't start again: {}.", failed.join("; ")))
    }
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
                // Fax, LPD and some vendors' print services depend on the
                // spooler; Windows won't stop it while they run.
                let dependents = scm::stop_with_dependents("Spooler", WAIT)?;
                scm::start("Spooler", WAIT)?;
                super::with_dependents("Print Spooler restarted.".into(), &start_again(&dependents))
            }
            "clear-print-queue" => {
                require_admin()?;
                let dependents = scm::stop_with_dependents("Spooler", WAIT)?;
                let removed = clear_spool_folder();
                let started = scm::start("Spooler", WAIT);
                // Whatever happened to the queue, bring back what was stopped.
                let restarted = if started.is_ok() { start_again(&dependents) } else { Vec::new() };
                let removed = removed?;
                started?;
                super::with_dependents(
                    format!("Removed {removed} spooled file{} and restarted the Print Spooler.", crate::util::plural(removed)),
                    &restarted,
                )
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
            "restart-computer" => crate::fixes::maintenance::schedule_restart().map(|s| format!("Restart {s}.")),
            "cancel-restart" => crate::fixes::maintenance::cancel_restart(),
            "install-oem-tool" => {
                require_admin()?;
                crate::update::oem::install_tool(target.ok_or("No tool named.")?, &crate::module::RunContext::silent())
            }
            "install-update" => {
                require_admin()?;
                crate::win::wua::install_update(target.ok_or("No update named.")?, &crate::module::RunContext::silent())
            }
            "revert-tuneup" => crate::fixes::undo::revert(),
            "clear-saved-credentials" => crate::desk::account::clear_saved_credentials(),
            "logoff-session" => {
                require_admin()?;
                crate::desk::account::logoff_session(target.ok_or("No session named.")?)
            }
            // No local elevation check: what it needs is the right to unlock
            // users in the directory, which the call itself reports on.
            "unlock-account" => crate::desk::account::unlock_account(target.ok_or("No account named.")?),
            "purge-kerberos-tickets" => {
                crate::investigate::identity::require_user_context()?;
                let before = crate::win::kerberos::tickets().map(|t| t.len()).unwrap_or(0);
                crate::win::kerberos::purge()?;
                Ok(format!(
                    "Cleared {before} Kerberos ticket{} for this sign-in. New ones are fetched as each server is used.",
                    crate::util::plural(before)
                ))
            }
            other => Err(format!("Fix `{other}` isn't available on Windows.")),
        }
    }

    /// Specifics for a preview, where there's something to count.
    pub fn preview(id: &str, _target: Option<&str>) -> Option<String> {
        match id {
            "purge-kerberos-tickets" => Some(match crate::investigate::identity::require_user_context() {
                Err(why) => format!("it would refuse: {why} Nothing was changed."),
                Ok(()) => match crate::win::kerberos::tickets() {
                    Ok(t) => format!(
                        "would clear {} Kerberos ticket{} cached for {}. Nothing was changed.",
                        t.len(),
                        crate::util::plural(t.len()),
                        crate::win::session::current_account().unwrap_or_else(|| "this sign-in".into())
                    ),
                    Err(e) => format!("couldn't list the tickets to clear ({e}). Nothing was changed."),
                },
            }),
            _ => None,
        }
    }

    /// Start the services that were stopped to let the spooler stop. Each
    /// with how it went.
    fn start_again(services: &[String]) -> Vec<(String, Result<(), String>)> {
        services.iter().map(|s| (s.clone(), scm::start(s, WAIT))).collect()
    }

    /// Delete everything in the spool folder while the spooler is stopped.
    fn clear_spool_folder() -> Result<usize, String> {
        let dir = crate::win::dirs::system32().join(r"spool\PRINTERS");
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
    use crate::util::{capture_for, command_exists, exit_label, pkexec_error, privileged, PROMPTED};

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
            "restart-computer" => crate::fixes::maintenance::schedule_restart().map(|s| format!("Restart {s}.")),
            "cancel-restart" => crate::fixes::maintenance::cancel_restart(),
            "gpupdate" => Err("Group Policy is a Windows feature.".into()),
            "install-oem-tool" | "install-update" => Err("That's a Windows Update / winget fix; on Linux, use Install OS & app updates.".into()),
            "revert-tuneup" => crate::fixes::undo::revert(),
            "clear-saved-credentials" => crate::desk::account::clear_saved_credentials(),
            "logoff-session" => crate::desk::account::logoff_session(target.ok_or("No session named.")?),
            "unlock-account" => crate::desk::account::unlock_account(target.ok_or("No account named.")?),
            "purge-kerberos-tickets" => {
                crate::investigate::identity::require_user_context()?;
                if !command_exists("kdestroy") {
                    return Err("kdestroy isn't installed, so there are no Kerberos tickets to clear.".into());
                }
                let out = crate::util::capture(crate::util::cmd("kdestroy"))?;
                if out.success() {
                    Ok("Cleared this sign-in's Kerberos tickets (kdestroy). Run kinit, or sign in again, for new ones.".into())
                } else {
                    Err(format!("kdestroy failed ({}): {}", exit_label(out.code), first_line(&out.combined())))
                }
            }
            other => Err(format!("Fix `{other}` isn't available on Linux.")),
        }
    }

    pub fn preview(id: &str, _target: Option<&str>) -> Option<String> {
        match id {
            "purge-kerberos-tickets" => Some(match crate::investigate::identity::require_user_context() {
                Err(why) => format!("it would refuse: {why} Nothing was changed."),
                Ok(()) => "would run kdestroy, which clears this account's Kerberos ticket cache. Nothing was changed.".into(),
            }),
            _ => None,
        }
    }

    /// Run as root through pkexec (argument array, no shell).
    fn root(program: &str, args: &[&str]) -> Result<String, String> {
        let (c, via_pkexec) = privileged(program, args)?;
        // Long enough for someone to type a password into the prompt.
        let out = capture_for(c, PROMPTED)?;
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
            assert!(f.description.len() > 20 && !f.label.is_empty());
            assert_eq!(r.id, f.id);
        }
        assert_eq!(offer("start-service", Some("W32Time")).label, "Start W32Time");
        assert_eq!(offer("install-oem-tool", Some("Dell.CommandUpdate")).label, "Install Dell Command | Update");
        assert!(!offer("gpupdate", None).requires_admin);
    }

    #[test]
    fn validates_update_ids_and_tools() {
        assert!(valid_update_id("c9cbc7a0-29e0-4f93-9e37-7d8d6c0f5b2a"));
        assert!(!valid_update_id("c9cbc7a0-29e0-4f93-9e37"));
        assert!(!valid_update_id("c9cbc7a0-29e0-4f93-9e37-7d8d6c0f5b2'"));
        assert!(validate_target("install-oem-tool", "HP.ImageAssistant").is_ok());
        assert!(validate_target("install-oem-tool", "Evil.Package").is_err());
    }

    #[test]
    fn remote_safe_and_install_policy_block_fixes() {
        let open = Profile::default();
        assert!(run("restart-computer", None, &open, true).unwrap_err().contains("Remote-safe"));
        assert!(run("gpupdate", None, &open, true).unwrap_err().contains("Remote-safe"));
        let mut central = Profile::default();
        central.policy.allow_installs = false;
        let err = run("install-update", Some("c9cbc7a0-29e0-4f93-9e37-7d8d6c0f5b2a"), &central, false).unwrap_err();
        assert!(err.contains("centrally"), "{err}");
    }

    #[test]
    fn a_fix_reports_the_services_it_had_to_restart() {
        assert_eq!(with_dependents("Print Spooler restarted.".into(), &[]), Ok("Print Spooler restarted.".into()));
        let both = [("Fax".to_string(), Ok(())), ("LPDSVC".to_string(), Ok(()))];
        assert_eq!(
            with_dependents("Print Spooler restarted.".into(), &both).unwrap(),
            "Print Spooler restarted. Also restarted, because they depend on it: Fax, LPDSVC."
        );
        let one_down = [("Fax".to_string(), Ok(())), ("LPDSVC".to_string(), Err("LPDSVC is still starting after 30 s".to_string()))];
        let err = with_dependents("Print Spooler restarted.".into(), &one_down).unwrap_err();
        assert!(err.contains("Also restarted, because they depend on it: Fax.") && err.contains("didn't start again: LPDSVC (LPDSVC is still starting"), "{err}");
    }

    #[test]
    fn account_fixes_validate_what_they_act_on() {
        assert!(validate_target("logoff-session", "3").is_ok());
        for bad in ["", "-1", "3; reboot", "1234567", "three"] {
            assert!(validate_target("logoff-session", bad).is_err(), "{bad:?}");
        }
        assert!(validate_target("unlock-account", r"CORP\\jparker").is_ok());
        assert!(validate_target("unlock-account", "--reset").is_err());
        assert!(validate_target("unlock-account", "a;b").is_err());
        assert_eq!(offer("unlock-account", Some(r"CORP\\jparker")).label, r"Unlock CORP\\jparker");
        assert_eq!(offer("logoff-session", Some("3")).label, "Sign out session 3");
        assert!(!requires_admin("clear-saved-credentials"), "it acts on the user's own saved credentials");
        // Fixes that act on someone else's sign-in aren't for the self-service view.
        for id in ["logoff-session", "unlock-account", "install-update", "install-oem-tool"] {
            assert!(spec(id).unwrap().technician_only, "{id}");
        }
        assert!(!spec("clear-saved-credentials").unwrap().technician_only);
        let open = Profile::default();
        assert!(run("logoff-session", Some("x"), &open, false).unwrap_err().contains("session number"));
        let locked = Profile::fail_closed();
        assert!(run("unlock-account", Some("jparker"), &locked, false).unwrap_err().contains("policy"));
    }

    #[test]
    fn previews_check_the_policy_and_change_nothing() {
        let open = Profile::default();
        let said = preview("flush-dns", None, &open, false).unwrap();
        assert!(said.starts_with("Preview: Clears cached DNS lookups") && said.ends_with("Nothing was changed."), "{said}");
        assert!(preview("restart-computer", None, &open, true).unwrap_err().contains("Remote-safe"));
        assert!(preview("flush-dns", None, &Profile::fail_closed(), false).unwrap_err().contains("policy"));
        assert!(preview("unlock-account", Some("a;b"), &open, false).is_err());
        assert!(preview("purge-kerberos-tickets", None, &open, false).unwrap().contains("Nothing was changed."));
        assert!(!requires_admin("purge-kerberos-tickets"), "it acts on the user's own tickets");
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
        assert!(run("format-disk", None, &open, false).unwrap_err().contains("Unknown"));
        assert!(run("start-service", None, &open, false).unwrap_err().contains("target"));
        assert!(run("start-service", Some("x;y"), &open, false).unwrap_err().contains("valid"));
        let locked = Profile::fail_closed();
        assert!(run("flush-dns", None, &locked, false).unwrap_err().contains("policy"));
    }
}
