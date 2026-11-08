//! The Endpoint Tune-Up's network repair phase, one module per step so each
//! can be picked, previewed and locked on its own. All MUTATING; all of them
//! can drop a remote session, so remote-safe mode locks them.
//!
//! * `fix.netcache`: purge the ARP/neighbour cache and the NetBIOS name cache.
//! * `fix.tcp`: TCP receive autotuning back to `normal`, and NIC sleep
//!   settings (DeviceSleepOnDisconnect, SelectiveSuspend) off.
//! * `fix.netstack`: Winsock and TCP/IP (v4 and v6) reset; needs a restart.
//!   Refused when any address is set by hand, because the reset wipes it.
//! * `fix.adapters`: restart the physical adapters that are up, wait for
//!   them to come back, then DHCP release/renew.
//!
//! Not here, deliberately (as in the Tune-Up): firewall resets and WinHTTP
//! proxy resets, which break managed proxies (Zscaler, GPO) and security policy.

use super::{step, tally, OnError};
use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use crate::net;
use crate::parse::net::{stack_reset_safety, StackSafety};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(120);

// ------------------------------------------------------------- fix.netcache

pub struct PurgeCaches;

impl TriageModule for PurgeCaches {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Purges the ARP cache (netsh interface ip delete arpcache) and the NetBIOS name cache (nbtstat -R / -RR)."
        } else {
            "Flushes the ARP/neighbour cache (ip neigh flush all)."
        };
        ModuleInfo::new("fix.netcache", "Purge ARP & NetBIOS caches", Category::Repair, description)
            .mutating()
            .admin()
            .disruptive()
            .warning("Forgets every cached neighbour address; connections pause for a moment while they're looked up again.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let steps: &[&str] = if cfg!(windows) {
            &["netsh interface ip delete arpcache", "nbtstat -R", "nbtstat -RR"]
        } else {
            &["ip neigh flush all"]
        };
        Ok(would("would purge the address caches", steps))
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        imp::purge_caches(ctx)
    }
}

// ------------------------------------------------------------------ fix.tcp

pub struct NetworkTuning;

/// Reports each physical adapter's sleep settings, changing nothing.
const NIC_POWER_READ: &str = r#"
$ErrorActionPreference = 'Stop'
$rows = @()
foreach ($adapter in @(Get-NetAdapter -Physical)) {
  try {
    $pm = Get-NetAdapterPowerManagement -Name $adapter.Name
    $on = @(foreach ($p in 'DeviceSleepOnDisconnect','SelectiveSuspend') { if ([string]$pm.$p -in @('Enabled','2')) { $p } })
    if ($on.Count -gt 0) { $rows += [pscustomobject]@{ Item = $adapter.Name; Status = 'Skipped'; Detail = 'would turn off ' + ($on -join ', ') } }
    else { $rows += [pscustomobject]@{ Item = $adapter.Name; Status = 'Already'; Detail = 'sleep settings already off' } }
  } catch { $rows += [pscustomobject]@{ Item = $adapter.Name; Status = 'Skipped'; Detail = $_.Exception.Message } }
}
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @($rows) -Compress)
"#;

/// Invoke-EndpointTuneUp's NIC sleep step: turn off the supported sleep
/// settings with the adapter restart deferred, then verify them.
const NIC_POWER_OFF: &str = r#"
$ErrorActionPreference = 'Stop'
$rows = @()
foreach ($adapter in @(Get-NetAdapter -Physical)) {
  try {
    $pm = Get-NetAdapterPowerManagement -Name $adapter.Name
    $changes = @{}
    $supported = 0
    foreach ($p in 'DeviceSleepOnDisconnect','SelectiveSuspend') {
      $v = [string]$pm.$p
      if ($v -in @('Enabled','2')) { $changes[$p] = $true; $supported++ }
      elseif ($v -in @('Disabled','1')) { $supported++ }
    }
    if ($supported -eq 0) { $rows += [pscustomobject]@{ Item = $adapter.Name; Status = 'Skipped'; Detail = 'the adapter has no supported sleep setting' }; continue }
    if ($changes.Count -gt 0) {
      Disable-NetAdapterPowerManagement -InputObject $pm @changes -NoRestart -Confirm:$false | Out-Null
      $verified = Get-NetAdapterPowerManagement -Name $adapter.Name
      foreach ($p in $changes.Keys) { if ([string]$verified.$p -notin @('Disabled','1')) { throw "The $p setting could not be verified." } }
      $rows += [pscustomobject]@{ Item = $adapter.Name; Status = 'Changed'; Detail = (($changes.Keys) -join ', ') + ' turned off (applies at the next adapter restart)' }
    } else { $rows += [pscustomobject]@{ Item = $adapter.Name; Status = 'Already'; Detail = 'sleep settings were already off' } }
  } catch { $rows += [pscustomobject]@{ Item = $adapter.Name; Status = 'Failed'; Detail = $_.Exception.Message } }
}
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @($rows) -Compress)
"#;

impl TriageModule for NetworkTuning {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.tcp",
            "TCP autotuning & NIC power",
            Category::Repair,
            "Sets TCP receive autotuning back to normal and turns off the adapters' sleep settings (DeviceSleepOnDisconnect, SelectiveSuspend).",
        )
        .only("windows")
        .mutating()
        .admin()
        .disruptive()
        .warning("Changes TCP and adapter power settings. The adapter settings apply the next time each adapter restarts.")
    }

    fn preview(&self, ctx: &RunContext) -> Result<Output, String> {
        let mut out = would("would normalise TCP and adapter power settings", &["netsh int tcp set global autotuninglevel=normal"]);
        out.findings.extend(imp::powershell_rows(NIC_POWER_READ, ctx));
        Ok(out)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        crate::util::require_admin_here()?;
        let mut findings = vec![
            step(ctx, "TCP receive autotuning", "netsh", &["int", "tcp", "set", "global", "autotuninglevel=normal"], &[0], OnError::Fail, WAIT).finding,
        ];
        findings.extend(imp::powershell_rows(NIC_POWER_OFF, ctx));
        let (ok, failed) = tally(&findings);
        let summary = if failed == 0 {
            format!("TCP autotuning normal; NIC sleep settings off ({ok} step{})", crate::util::plural(ok))
        } else {
            format!("{failed} of {} steps failed", findings.len())
        };
        Ok(Output::new(summary, findings))
    }
}

// ------------------------------------------------------------- fix.netstack

pub struct ResetStack;

/// The Tune-Up's safety check: every address must come from DHCP, router
/// advertisements or the system itself.
fn safety() -> (StackSafety, Vec<String>) {
    let Ok(list) = net::interfaces() else {
        return (StackSafety::Unknown, Vec::new());
    };
    let mut origins = Vec::new();
    let mut manual = Vec::new();
    for i in list.iter().filter(|i| !i.loopback) {
        for a in &i.addresses {
            if a.ip.is_loopback() {
                continue;
            }
            origins.push(a.origin);
            if a.origin == crate::parse::net::AddrOrigin::Manual {
                manual.push(format!("{} on {}", a.ip, i.name));
            }
        }
    }
    (stack_reset_safety(&origins), manual)
}

fn safety_finding(s: &StackSafety, manual: &[String]) -> Finding {
    match s {
        StackSafety::Clear => Finding::ok("Static address check", "every address is from DHCP or autoconfiguration"),
        StackSafety::Static(n) => Finding::warn(
            "Static address check",
            format!("{n} address{} set by hand: the reset would wipe {}", if *n == 1 { "" } else { "es" }, if *n == 1 { "it" } else { "them" }),
        )
        .with_detail(manual.join(", ")),
        StackSafety::Unknown => Finding::warn("Static address check", "couldn't confirm every address is from DHCP"),
    }
}

impl TriageModule for ResetStack {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.netstack",
            "Reset network stack",
            Category::Repair,
            "Resets the Winsock catalog and the TCP/IP stack (IPv4 and IPv6). Applies after a restart. Refused when any address is static.",
        )
        .only("windows")
        .mutating()
        .admin()
        .disruptive()
        .warning("Resets Winsock and TCP/IP to defaults. Static IP settings would be lost (ITriage refuses if it finds any), and a restart is needed.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let (s, manual) = safety();
        let mut out = if s == StackSafety::Clear {
            would(
                "would reset Winsock and TCP/IP; a restart would be needed",
                &["netsh winsock reset", "netsh int ip reset", "netsh int ipv6 reset"],
            )
        } else {
            Output::new("Preview: the reset would be skipped (static or unknown addresses). Nothing was changed.", Vec::new())
        };
        out.findings.insert(0, safety_finding(&s, &manual));
        Ok(out)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        crate::util::require_admin_here()?;
        let (s, manual) = safety();
        let check = safety_finding(&s, &manual);
        if s != StackSafety::Clear {
            ctx.log("Skipping the stack reset: the address check didn't pass.");
            return Ok(Output::new("Skipped: protected by the static address check", vec![check]));
        }
        let mut findings = vec![check];
        let winsock = step(ctx, "netsh winsock reset", "netsh", &["winsock", "reset"], &[0], OnError::Fail, WAIT);
        let reset_any = winsock.ok;
        findings.push(winsock.finding);
        let ip = step(ctx, "netsh int ip reset", "netsh", &["int", "ip", "reset"], &[0], OnError::Fail, WAIT);
        let reset_any = reset_any || ip.ok;
        findings.push(ip.finding);
        findings.push(step(ctx, "netsh int ipv6 reset", "netsh", &["int", "ipv6", "reset"], &[0], OnError::Fail, WAIT).finding);
        let (_, failed) = tally(&findings);
        let summary = if failed == 0 {
            "Network stack reset; restart to apply"
        } else {
            "Network stack reset partly failed; restart, then check again"
        };
        Ok(Output::new(summary, findings).restart_required(reset_any))
    }
}

// ------------------------------------------------------------- fix.adapters

pub struct RestartAdapters;

/// Restart every physical adapter that's up, then wait (up to 60 s) for each
/// to come back. A missing adapter counts as still down.
#[cfg_attr(not(windows), allow(dead_code))]
const RESTART_ADAPTERS: &str = r#"
$ErrorActionPreference = 'Stop'
$rows = @()
$up = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
$failed = @()
foreach ($a in $up) {
  try { Restart-NetAdapter -Name $a.Name -Confirm:$false }
  catch { $failed += $a.Name; $rows += [pscustomobject]@{ Item = $a.Name; Status = 'Failed'; Detail = $_.Exception.Message } }
}
$names = @($up | ForEach-Object { $_.Name })
$down = @()
if ($names.Count -gt $failed.Count) {
  $deadline = (Get-Date).AddSeconds(60)
  do {
    Start-Sleep -Seconds 3
    $current = @(Get-NetAdapter -Name $names -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name })
    $down = @($names | Where-Object { $current -notcontains $_ })
  } until ($down.Count -eq 0 -or (Get-Date) -ge $deadline)
}
foreach ($n in $names | Where-Object { $failed -notcontains $_ }) {
  if ($down -contains $n) { $rows += [pscustomobject]@{ Item = $n; Status = 'Failed'; Detail = 'did not come back up within 60 seconds' } }
  else { $rows += [pscustomobject]@{ Item = $n; Status = 'Changed'; Detail = 'restarted and back up' } }
}
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @($rows) -Compress)
"#;

/// What the restart script would restart: physical adapters that are up.
#[cfg_attr(not(windows), allow(dead_code))]
const PHYSICAL_UP: &str = r#"
$ErrorActionPreference = 'Stop'
$rows = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [pscustomobject]@{ Item = $_.Name; Status = 'Skipped'; Detail = $_.InterfaceDescription } })
'ITRIAGE-ROWS ' + (ConvertTo-Json -InputObject @($rows) -Compress)
"#;

impl TriageModule for RestartAdapters {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "Restarts every physical network adapter that's up, waits for each to come back, then renews DHCP (ipconfig /release, /renew)."
        } else {
            "Reconnects every wired and Wi-Fi device through NetworkManager, which also renews its DHCP lease."
        };
        ModuleInfo::new("fix.adapters", "Restart adapters & renew DHCP", Category::Repair, description)
            .mutating()
            .admin()
            .disruptive()
            .warning("Every network connection drops for up to a minute. A remote session will disconnect and should reconnect on its own.")
    }

    fn preview(&self, _ctx: &RunContext) -> Result<Output, String> {
        let targets = match imp::restart_targets() {
            Ok(t) => t,
            Err(why) => {
                return Ok(Output::new(
                    "Preview: a real run couldn't restart anything here. Nothing was changed.",
                    vec![Finding::warn("Would skip", why)],
                ))
            }
        };
        let mut out = if cfg!(windows) {
            would("would restart these adapters and renew DHCP", &["ipconfig /release", "ipconfig /renew"])
        } else {
            would("would reconnect these devices", &[])
        };
        if targets.is_empty() {
            out.findings.insert(0, Finding::info("Would restart", "nothing: no connected adapters"));
        }
        for (name, addrs) in targets.into_iter().rev() {
            out.findings.insert(0, Finding::info(format!("Would restart {name}"), addrs));
        }
        Ok(out)
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let before = up_adapters();
        for (name, addrs) in &before {
            ctx.log(format!("Before: {name}: {addrs}"));
        }
        let mut findings = imp::restart_adapters(ctx)?;
        let after = up_adapters();
        for (name, addrs) in &after {
            ctx.log(format!("After: {name}: {addrs}"));
        }
        for (name, addrs) in after {
            findings.push(Finding::info(format!("{name} now"), addrs));
        }
        let (_, failed) = tally(&findings);
        let summary = if failed == 0 {
            "Adapters restarted and addresses renewed".to_string()
        } else {
            format!("{failed} step{} failed", crate::util::plural(failed))
        };
        Ok(Output::new(summary, findings))
    }
}

/// Connected, non-loopback, non-tunnel adapters and their addresses.
fn up_adapters() -> Vec<(String, String)> {
    net::interfaces()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| {
            i.up && !i.loopback
                && !crate::parse::net::is_vpn_adapter(&i.description)
                && !crate::parse::net::is_tunnel_interface(&i.name)
                && i.usable_addresses().next().is_some()
        })
        .map(|i| (i.name.clone(), i.address_list()))
        .collect()
}

/// A preview listing the commands a module would run. A command whose
/// program isn't installed here is listed as skipped, as a real run would
/// fail it.
pub(crate) fn would(summary: &str, commands: &[&str]) -> Output {
    let findings: Vec<Finding> = commands
        .iter()
        .map(|command| {
            let program = command.split_whitespace().next().unwrap_or(command);
            if crate::util::command_exists(program) {
                Finding::info("Would run", *command)
            } else {
                Finding::warn("Would skip", format!("{command} ({program} isn't installed here)"))
            }
        })
        .collect();
    let skipped = findings.iter().filter(|f| f.severity != crate::model::Severity::Info).count();
    let summary = if skipped == 0 {
        format!("Preview: {summary}. Nothing was changed.")
    } else {
        format!(
            "Preview: {summary}, but {skipped} step{} can't run here. Nothing was changed.",
            crate::util::plural(skipped)
        )
    };
    Output::new(summary, findings)
}

#[cfg(windows)]
mod imp {
    use super::*;

    pub fn purge_caches(ctx: &RunContext) -> Result<Output, String> {
        crate::util::require_admin_here()?;
        let findings = vec![
            step(ctx, "ARP cache", "netsh", &["interface", "ip", "delete", "arpcache"], &[0], OnError::Fail, WAIT).finding,
            step(ctx, "NetBIOS name cache (purge)", "nbtstat", &["-R"], &[0], OnError::Warn, WAIT).finding,
            step(ctx, "NetBIOS names (re-register)", "nbtstat", &["-RR"], &[0], OnError::Warn, WAIT).finding,
        ];
        let (_, failed) = tally(&findings);
        let summary = if failed == 0 { "ARP and NetBIOS caches purged" } else { "Purging the ARP cache failed" };
        Ok(Output::new(summary, findings))
    }

    pub fn powershell_rows(script: &'static str, ctx: &RunContext) -> Vec<Finding> {
        match crate::win::ps::run(script, ctx, Duration::from_secs(180)) {
            Ok(out) => match crate::fixes::rows(&out.stdout) {
                Some(list) if list.is_empty() => vec![Finding::info("Physical adapters", "none found")],
                Some(list) => list.iter().map(|r| r.finding()).collect(),
                None => vec![Finding::crit(
                    "Adapter settings",
                    format!("PowerShell gave no result ({})", crate::util::exit_label(out.code)),
                )],
            },
            Err(e) => vec![Finding::crit("Adapter settings", e)],
        }
    }

    /// What a real run restarts, asked the same way the restart script
    /// asks (physical adapters that are up), with their addresses.
    pub fn restart_targets() -> Result<Vec<(String, String)>, String> {
        let out = crate::win::ps::run(PHYSICAL_UP, &RunContext::silent(), Duration::from_secs(60))?;
        let rows = crate::fixes::rows(&out.stdout).ok_or_else(|| {
            format!("PowerShell couldn't list the adapters ({})", crate::util::exit_label(out.code))
        })?;
        let addrs = up_adapters();
        Ok(rows
            .into_iter()
            .map(|r| {
                let a = addrs.iter().find(|(n, _)| *n == r.item).map_or_else(|| "no address".to_string(), |(_, a)| a.clone());
                (r.item, a)
            })
            .collect())
    }

    pub fn restart_adapters(ctx: &RunContext) -> Result<Vec<Finding>, String> {
        crate::util::require_admin_here()?;
        ctx.log("Restarting physical adapters; the connection will drop for a moment…");
        let mut findings = powershell_rows(RESTART_ADAPTERS, ctx);
        // A mixed static/DHCP machine reports per-adapter errors here while
        // the rest renew, so a non-zero exit only warns.
        findings.push(step(ctx, "DHCP release", "ipconfig", &["/release"], &[0], OnError::Warn, WAIT).finding);
        findings.push(step(ctx, "DHCP renew", "ipconfig", &["/renew"], &[0], OnError::Warn, Duration::from_secs(180)).finding);
        Ok(findings)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::util::{capture, cmd, command_exists, pkexec_error, privileged};

    pub fn purge_caches(ctx: &RunContext) -> Result<Output, String> {
        let (c, via_pkexec) = privileged("ip", &["neigh", "flush", "all"])?;
        if via_pkexec {
            ctx.log("Asking for your password (pkexec)…");
        }
        let out = capture(c)?;
        if via_pkexec {
            if let Some(why) = pkexec_error(out.code) {
                return Err(why.to_string());
            }
        }
        let f = if out.success() {
            Finding::ok("Neighbour (ARP) cache", "flushed")
        } else {
            Finding::crit("Neighbour (ARP) cache", out.combined())
        };
        Ok(Output::new("Neighbour cache flushed", vec![f]))
    }

    #[allow(dead_code)]
    pub fn powershell_rows(_script: &'static str, _ctx: &RunContext) -> Vec<Finding> {
        Vec::new()
    }

    /// NetworkManager devices that are connected and physical.
    fn devices() -> Vec<String> {
        let mut c = cmd("nmcli");
        c.args(["-t", "-f", "DEVICE,TYPE,STATE", "device"]).env("LC_ALL", "C");
        let out = capture(c).ok().filter(|o| o.success()).map(|o| o.stdout).unwrap_or_default();
        out.lines()
            .map(crate::parse::net::nmcli_fields)
            .filter(|f| f.len() >= 3 && matches!(f[1].as_str(), "ethernet" | "wifi") && f[2].starts_with("connected"))
            .map(|f| f[0].clone())
            .collect()
    }

    const NO_NMCLI: &str = "NetworkManager (nmcli) isn't installed, so adapters can't be restarted from here.";

    /// What a real run reconnects: NetworkManager's connected wired and
    /// Wi-Fi devices, with their addresses.
    pub fn restart_targets() -> Result<Vec<(String, String)>, String> {
        if !command_exists("nmcli") {
            return Err(NO_NMCLI.into());
        }
        let addrs = up_adapters();
        Ok(devices()
            .into_iter()
            .map(|d| {
                let a = addrs.iter().find(|(n, _)| *n == d).map_or_else(|| "no address".to_string(), |(_, a)| a.clone());
                (d, a)
            })
            .collect())
    }

    pub fn restart_adapters(ctx: &RunContext) -> Result<Vec<Finding>, String> {
        if !command_exists("nmcli") {
            return Err(NO_NMCLI.into());
        }
        let list = devices();
        if list.is_empty() {
            return Ok(vec![Finding::info("Network devices", "none connected")]);
        }
        let mut findings = Vec::new();
        for dev in list {
            ctx.log(format!("Reconnecting {dev}…"));
            let run = |args: &[&str]| {
                let mut c = cmd("nmcli");
                c.args(args).env("LC_ALL", "C");
                capture(c)
            };
            let down = run(&["device", "disconnect", &dev]);
            let up = run(&["device", "connect", &dev]);
            findings.push(match (down, up) {
                (_, Ok(o)) if o.success() => Finding::ok(dev.clone(), "reconnected"),
                (_, Ok(o)) => Finding::crit(dev.clone(), crate::parse::text::first_line(&o.combined()).to_string()),
                (_, Err(e)) => Finding::crit(dev.clone(), e),
            });
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn previews_list_commands_and_change_nothing() {
        let shell = if cfg!(windows) { "cmd /c exit" } else { "sh -c true" };
        let out = would("would purge", &[shell, shell]);
        assert_eq!(out.summary, "Preview: would purge. Nothing was changed.");
        assert_eq!(out.findings.len(), 2);
        assert!(out.findings.iter().all(|f| f.severity == Severity::Info && f.label == "Would run"));

        let out = would("would purge", &[shell, "itriage-no-such-tool --flush"]);
        assert_eq!(out.summary, "Preview: would purge, but 1 step can't run here. Nothing was changed.");
        assert_eq!(out.findings[1].severity, Severity::Warning);
        assert_eq!(out.findings[1].value, "itriage-no-such-tool --flush (itriage-no-such-tool isn't installed here)");
    }

    #[test]
    fn static_addresses_block_the_reset() {
        let f = safety_finding(&StackSafety::Static(1), &["10.0.0.5 on Ethernet".into()]);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.value.contains("wipe it"));
        assert_eq!(safety_finding(&StackSafety::Clear, &[]).severity, Severity::Ok);
    }

    #[test]
    fn every_repair_module_is_disruptive() {
        for m in [
            Box::new(PurgeCaches) as Box<dyn TriageModule>,
            Box::new(NetworkTuning),
            Box::new(ResetStack),
            Box::new(RestartAdapters),
        ] {
            let i = m.info();
            assert!(i.mutating && i.disruptive, "{}", i.id);
        }
    }
}
