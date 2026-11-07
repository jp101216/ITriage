# itriage

[![CI](https://github.com/jp101216/itriage/actions/workflows/ci.yml/badge.svg)](https://github.com/jp101216/itriage/actions/workflows/ci.yml)

A cross-platform IT triage, repair and update tool for Windows and Linux: one
desktop app that is also a command line. The app has two views:

* **Technician console.** Pick checks, repairs and updates (or a preset), run
  them, and get streamed, severity-coded results with one-click fixes and
  knowledge-base links. Every run is saved, and the next run on that machine
  shows what changed, measurements included. Results export as ticket text, a
  full transcript, rich text for TeamDynamix, Markdown, or JSON.
* **Self-service check.** A calm page for the person at the PC: their computer
  name up front (with a copy button), one "Check my computer" button, results
  in plain words, a few safe fixes, and "Copy details for the service desk".

Given arguments, the same program runs without a window
(`itriage --preset triage`) and returns the PowerShell toolkit's exit codes,
for remote shells, scheduled tasks and RMM tools.

**Try the interface in your browser:**
[jp101216.github.io/ITriage](https://jp101216.github.io/ITriage/) runs the
app's own frontend on sample data, with nothing to install. It redeploys
whenever the frontend changes on `main` (`.github/workflows/pages.yml`).

A **site profile** tailors it to an environment: which services, apps,
servers and devices a machine must have, which fixes are allowed, whether
installs are locked, the alert thresholds, which network probes run, and which
KB articles go with which problems.

> **Working name.** `itriage` is a placeholder. Rename the crates and the
> window title whenever you've landed on the real name.

---

## Coming from the PowerShell toolkit

itriage carries over the four maintained scripts of
[Powershell-Ops-IR-Toolkit](https://github.com/jp101216/Powershell-Ops-IR-Toolkit)
3.0.0. `Invoke-LiveResponse.ps1` stays out of scope: incident response lives in
[LiveResponse-NG](https://github.com/jp101216/LiveResponse-NG).

| Script | In itriage |
|---|---|
| `Invoke-NetTriage.ps1` | the **Slowness triage** preset (`--preset triage`) |
| `Compare-NetTriage.ps1` | an automatic before/after after every run, **History → tick two → Compare**, and `--compare OLD NEW` |
| `Invoke-EndpointTuneUp.ps1` | the **Tune-up** preset (`--preset tuneup`), plus opt-in Recycle Bin, DISM/SFC and restart modules |
| `Invoke-UpdateSystem.ps1` | the **Drivers & firmware** preset (`--preset updates`), plus an install button beside each pending update |

A preset is a starting point: pick it, then tick or untick modules.

### Invoke-NetTriage → Slowness triage

| NetTriage | itriage |
|---|---|
| System baseline, pending reboot, uptime | **System information**: make, model, serial, BIOS, motherboard, signed-in user, uptime, restart pending (and why) |
| CPU, memory, disk free and disk latency, top processes by real-time CPU% | **Top processes** (overall CPU load first), **Memory usage**, **Disk space & latency** |
| Adapters, IPv4/IPv6, gateway, DNS | **Network connectivity**: adapters, the route in use, its gateway and DNS servers, each server asked directly |
| VPN indicators (Cisco Secure Client, Zscaler) | **Wi-Fi & VPN**, which tells a running client from an active tunnel |
| Proxy (WinHTTP and per-user WinINet) | **Proxy settings**, read from the signed-in user's settings even when itriage runs elevated |
| RTT and packet loss to the gateway and DNS, DNS resolve time | **Latency & packet loss**; the timed lookup is in Network connectivity |
| TCP reachability for `CoreInfrastructure.json` | **Site services & endpoints**, from the profile's `[[require.endpoint]]` entries |
| `-TargetDestination`, `-TargetPorts` | **Destination test**: the field on its card, or `--target fileserver01:445,3389` (`--ports` also works) |
| Egress IP | Network connectivity (public IP) |
| `-DnsProbeName`, `-SkipPublicProbes`, `-SkipExternalIP` | `[network]` `dns_probe`, `public_probes = false`, `egress_url = ""` |
| Thresholds | the same defaults, changeable under `[thresholds]` |
| `-ExportPath`, `-RetainCount` | every run is saved to history (`--out PATH` writes a copy anywhere); `[history] keep` |
| `-Quiet` (summary to the clipboard) | **Export → Ticket text**; on the command line, the text report (pipe it to `clip`) |

### Compare-NetTriage → before and after

When a run finishes, itriage compares it with the earlier run on that machine
that shares the most checks (the newest of those), so a triage is compared
with the last triage even if a tune-up ran in between. The comparison shows:

* problems that were **resolved** (recovered), are **new** (regressions), are
  **still failing**, or **changed** severity;
* **measurements** with before, after and whether each got better or worse:
  round trips, packet loss, DNS and TCP connect times, disk latency, CPU,
  memory, free space, Wi-Fi signal and uptime. A move within the noise
  (2 ms, 1 point, or 10% of the earlier value) counts as the same;
* checks that ran only this time or only last time, and **gaps**: a
  measurement one run has and the other doesn't, or a different site profile.

To compare any two saved runs: **History**, tick two, **Compare**; or
`itriage --compare before.json after.json` (add `--out comparison.json` to save
the comparison as JSON with a text summary beside it, as Compare-NetTriage's
`-ExportPath` does). They must be from the same computer.

### Invoke-EndpointTuneUp → Tune-up

| Tune-Up step | itriage module |
|---|---|
| DNS flush and re-registration | Flush & re-register DNS |
| ARP and NetBIOS purge | Purge ARP & NetBIOS caches |
| TCP autotuning reset, NIC power saving off | TCP autotuning & NIC power |
| Winsock / TCP-IP reset, skipped on static addresses | Reset network stack: refused when any address is static; asks for a restart |
| Adapter restart, DHCP release/renew | Restart adapters & renew DHCP |
| Temp files across all profiles | Clear temp files (24-hour minimum age, `[cleanup] temp_min_age_hours`) |
| `-ClearRecycleBin` | Empty Recycle Bin (not in the preset: ask the user first) |
| `-DeepClean` (DISM + SFC) | Clean up & check system files (not in the preset: 15–45 minutes) |
| Volume TRIM / defrag | Optimize system drive |
| `gpupdate /force` | Refresh Group Policy |
| SCCM/MECM policy and inventory triggers | Run Configuration Manager actions |
| `-Reboot` | Restart the PC (runs last, 60-second warning), or **Restart in 60 s** on the banner when a step needs one |
| `-Phase`, `-SkipStackReset`, `-SkipAdapterRestart`, `-SkipTempCleanup` | untick the module, or name modules on the command line |
| `-WhatIf` | the **PREVIEW** switch, or `--what-if` |
| `-RemoteSafe` | the **REMOTE-SAFE** switch, `--remote-safe`, or `[policy] remote_safe = true` |

Like the script, it never clears event logs, resets firewall policy or the
WinHTTP proxy, clears prefetch, or empties the Windows Update, Delivery
Optimization or WER caches. Batch steps report per item (each adapter, each
Configuration Manager cycle) as changed, already set, skipped or failed.

### Invoke-UpdateSystem → Drivers & firmware

| UpdateSystem | itriage |
|---|---|
| `-ScanOnly` | Available updates |
| `-AutoInstall` | Install drivers & firmware |
| OEM routing | the same ten manufacturers, matched on the SMBIOS manufacturer, then the model, then the motherboard. Dell Command \| Update, HP Image Assistant and Lenovo Thin Installer run unattended; Surface firmware comes through Windows Update; MyASUS, MSI Center, GIGABYTE Control Center, ASRock, Acer Care Center and Samsung Update are named for the technician to run. itriage never flashes a BIOS itself. |
| `-UpdateId` | **Install this update** beside each pending update (`--fix install-update <id>`) |
| `-IncludeApps` | Install OS & app updates: pending Windows Update software updates, then `winget upgrade --all` |
| `-Force` for OEM-tool installs | **Install …** beside a missing OEM tool, allowed by `[policy] allow_installs` |
| `-WhatIf` | **PREVIEW** / `--what-if` |
| AC power check | Install drivers & firmware won't start on battery |

### Exit codes

The same as the toolkit's:

| Code | Meaning |
|---|---|
| 0 | Finished, including a diagnostic run that found problems |
| 1 | Nothing could run, bad arguments, or the `--out` report couldn't be written |
| 2 | Incomplete: a module couldn't run, a change partly failed, or the run was cancelled |
| 3010 | Changes finished and need a restart (3 on Linux, where exit codes stop at 255) |

Each saved report records its `exit_code` and the `tool_version` that made it.

### Not carried over

* `Invoke-LiveResponse.ps1`: see LiveResponse-NG.
* Copying to the clipboard from the command line: pipe the output to `clip`
  (Windows) or `xclip` instead.
* `-RebootDelaySeconds`: the restart warning is always 60 seconds.
* The ProgramData log folders: runs are saved per user in the history folder,
  and `--out` writes a copy wherever you need it.

## Modules

**Checks** (read-only; "All checks" selects only these):

| Module | Windows | Linux |
|---|---|---|
| System information | sysinfo, SMBIOS (firmware table, registry fallback), console user (WTS), pending restart from Servicing, Windows Update and pending file renames | sysinfo, `/sys/class/dmi`, `loginctl`, `reboot-required` / `needs-restarting` |
| Disk space & latency | free space per volume (warns at 15% free); latency and queue length from the `PhysicalDisk` performance counters | same; latency from `/proc/diskstats` |
| Memory usage | RAM and page file (warns at 80% used) | RAM and swap |
| Top processes | overall CPU load (warns at 75%), busiest processes, biggest memory users | same |
| Services | **native SCM**: Automatic services not running, exit codes decoded | `systemctl`: failed units and `is-system-running` |
| Network connectivity | IP Helper: adapters, route in use, gateway, DNS servers (each asked directly); a timed lookup, an outbound TCP probe, the public IP | `ip -j` (or `/proc/net/route`), `resolvectl` / `resolv.conf`, `curl` for the public IP |
| Latency & packet loss | ICMP (IcmpSendEcho) to the gateway and first DNS server: round trip and loss | `ping` (iputils or BusyBox) |
| Proxy settings | WinHTTP, and the signed-in user's proxy, PAC script or auto-detect | proxy environment variables, GNOME proxy settings |
| Destination test | for a host you give: DNS, a TCP connect per port (every address it resolves to), the route and interface the PC picks (noting a VPN), ping | same |
| Recent errors | **native Evt\* API**: System + Application, Critical/Error, last 24 h, grouped by provider + event ID | `journalctl -p err`, grouped by source + normalised message |
| Clock & time sync | W32Time source, **SNTP offset** vs. the DC or configured server, time zone | `timedatectl`, SNTP vs. the timesyncd/chrony source |
| Domain & Group Policy | domain join, **DC vs. cached-credential sign-in**, AD site, last computer policy refresh | n/a |
| Printers & print queue | **spooler API**: status flags, stuck jobs, default and label printers | CUPS `lpstat` |
| Devices & peripherals | **SetupAPI**: Device Manager problem codes, microphones, cameras, card readers | USB devices from sysfs |
| Wi-Fi & VPN | **WLAN API**: SSID, signal (warns at 70%), security, radio, channel, link rates; Cisco Secure Client and Zscaler clients and tunnels | `nmcli`, VPN clients and tunnel interfaces |
| Machine certificates | LocalMachine\My expiry; warns 14 days out | n/a |
| Battery health | design vs. full-charge capacity (`powercfg /batteryreport`), cycles | sysfs `power_supply` |
| Required & clinical apps | the profile's required apps and minimum versions, plus a watchlist of clinical clients | dpkg / rpm / pacman packages |
| Site services & endpoints | the profile's required services; its servers checked by DNS + TCP, in parallel, with connect times | systemd units; same |
| Available updates | **WUA COM** search (KB, MSRC severity) with an install button per update, Windows Update drivers, pending restart, winget, current BIOS, the OEM tool's state | apt/dnf/pacman/zypper (no root), fwupd, reboot required |

**Repairs and maintenance** (change the machine; picked on purpose and confirmed):

| Module | Windows | Linux | Admin | Remote-safe |
|---|---|---|:-:|:-:|
| Flush & re-register DNS | `ipconfig /flushdns`, then `/registerdns` when elevated | `resolvectl flush-caches` | | runs |
| Purge ARP & NetBIOS caches | `netsh interface ip delete arpcache`, `nbtstat -R`, `nbtstat -RR` | `ip neigh flush all` | ✔ | locked |
| TCP autotuning & NIC power | `netsh int tcp set global autotuninglevel=normal`; adapter sleep settings off | n/a | ✔ | locked |
| Reset network stack | `netsh winsock reset`, `netsh int ip reset`, `netsh int ipv6 reset`; refused with any static address | n/a | ✔ | locked |
| Restart adapters & renew DHCP | restart physical adapters that are up, wait for each, `ipconfig /release` and `/renew` | `nmcli device disconnect` / `connect` | ✔ | locked |
| Clear temp files | every profile's temp folder and `Windows\Temp` (your own without admin); older than 24 h; skips files in use and links | your own files in the temp folder; refuses as root | | runs |
| Empty Recycle Bin | all drives, for the account itriage runs as | `~/.local/share/Trash` | | runs |
| Clean up & check system files | `DISM /StartComponentCleanup`, then `sfc /scannow` | n/a | ✔ | runs |
| Optimize system drive | `defrag C: /O /U` (TRIM on SSD, defrag on HDD) | `fstrim -av` | ✔ | runs |
| Refresh Group Policy | `gpupdate /force` | n/a | | locked |
| Run Configuration Manager actions | machine policy, application deployment and hardware inventory cycles, if the client is running | n/a | ✔ | locked |
| Restart the PC | restart in 60 s with a save-your-work message; runs last | `shutdown -r +1` | ✔ | locked |

**Updates** (change the machine; locked when `allow_installs = false`):

| Module | Windows | Linux |
|---|---|---|
| Install OS & app updates | **WUA COM** download + install (optional/preview skipped), then `winget upgrade --all` | full non-interactive upgrade with the detected package manager |
| Install drivers & firmware | the OEM tool (see the routing above), plus Windows Update drivers when there's no OEM tool (`[updates] windows_update_drivers = "always"` installs them after the tool too); won't run on battery | `fwupdmgr` (LVFS) |

Install modules are split by risk, so you can patch the OS without also
flashing a BIOS.

The workstation checks answer the questions a desk asks first on a shared or
clinical PC. A few details:

* **Clock**: Kerberos refuses domain sign-in past 5 minutes of drift. The
  offset is a warning over 10 s and critical over 3 minutes.
* **Domain**: a user signed in with cached credentials (no DC answered) gets a
  warning, because password changes, new groups and policy won't apply.
* **Printers**: jobs queued behind a printer in an error state are called out
  as stuck. Zebra-style label printers are tagged. A Print Spooler that's
  disabled on purpose (PrintNightmare hardening on servers) isn't flagged.
* **Wi-Fi**: Windows 11 24H2 hides network names from apps without location
  access; the check says so instead of showing a blank.
* **Clinical apps** watchlist: Citrix Workspace, VMware/Omnissa Horizon,
  Imprivata, Epic Hyperspace/Hyperdrive, Dragon Medical/PowerMic, common VPN
  clients and EDR agents. It only reports what's installed; requirements come
  from the profile.

### Fewer false positives in the Services check

A plain `StartMode = Auto and State != Running` query flags dozens of healthy
services. Services skips the ones that are stopped by design:

* trigger-start services, which Windows starts on an event and lets stop again;
* per-user service templates (`CDPUserSvc` and friends), since only their
  per-session copies run;
* a short, documented list of self-stopping updaters (`sppsvc`, Google/Edge/Brave
  updaters, …).

What's left is ranked. An Automatic service that **crashed** (non-zero exit code,
decoded to text such as *"The process terminated unexpectedly"*) is critical. A
plain stopped Automatic service is a warning, and a stopped *delayed-start* one
is informational.

Recent errors similarly downgrades DCOM 10016/10010, which Microsoft documents
as expected noise.

## Preview, remote-safe and restarts

**Preview** (the PREVIEW switch, or `--what-if`) turns every module that
would change the machine into a dry run. Each one says exactly what it would
do: the commands it would run, the adapters it would restart, the temp files
it would delete (counted for real), the updates and app upgrades it would
install. Steps that couldn't run on this machine show as skipped. Nothing is
changed, and read-only checks run as usual.

**Remote-safe** (the REMOTE-SAFE switch, `--remote-safe`, or
`[policy] remote_safe = true`) locks anything that could drop a remote
session or restart the PC: cache purges, TCP and adapter power changes, the
stack reset, adapter restarts, Group Policy and Configuration Manager
triggers, and restarts. DNS flush and re-registration stay available, as in
the script. The engine checks it again when a module or fix runs, whatever
the UI showed.

When a change needs a restart to finish (a stack reset, Windows updates,
DISM), a banner names the step and offers **Restart in 60 s** (the signed-in
user gets a save-your-work message) and **Cancel restart**.

## Site profiles

A profile is a TOML file. itriage uses the first one it finds:

1. **Machine-wide**: `%ProgramData%\itriage\profile.toml` (Windows) or
   `/etc/itriage/profile.toml` (Linux). Deploy it with your management tool;
   only administrators can edit it there.
2. `ITRIAGE_PROFILE=<file>`, for testing a profile.
3. **Personal**: `%APPDATA%\itriage\profile.toml` or `~/.config/itriage/profile.toml`.
4. The built-in default: everything allowed, nothing required.

A machine-wide profile that doesn't parse **fails closed**: itriage runs
read-only and shows the parse error in a banner, rather than quietly ignoring
the policy.

```toml
name = "Clinical workstation"

[policy]
allow_installs = false            # patching comes from SCCM/Intune: lock the install modules
fixes = ["restart-spooler", "clear-print-queue", "gpupdate", "start-service:Spooler"]
start_in = "self-service"         # or "technician"
technician_view = true            # false = kiosk: self-service only
remote_safe = true                # start with session-dropping changes locked

[time]
server = "dc01.example.org"       # measure the clock against this
zone = "Eastern Standard Time"    # flag a wrong time zone

[network]
public_probes = false             # no www.microsoft.com, 8.8.8.8 or public-IP lookups
dns_probe = "intranet.example.org"
tcp_probe = "ehr-gateway.example.org:443"

[thresholds]
wifi_signal_pct = { warn = 70, crit = 50 }

[[require.service]]
name = "Spooler"

[[require.app]]
name = "Citrix Workspace"
min_version = "24.2"

[[require.endpoint]]
label = "EHR gateway"
host = "ehr-gateway.example.org"
port = 443

[[require.device]]
label = "Badge reader"
match = "pcProx"

[[kb]]
module = "desk.printers"
match = "stuck"
title = "Clear a stuck print queue"
url = "https://kb.example.org/printing/stuck-queue"
```

Every setting, with its default:

| Setting | Default | |
|---|---|---|
| `[policy] allow_changes` | `true` | anything that changes the machine |
| `[policy] allow_installs` | `true` | the two install modules and the install buttons |
| `[policy] fixes` | every fix | one-click fixes that may run; `start-service:<name>` allows one service |
| `[policy] start_in` | `"technician"` | or `"self-service"` |
| `[policy] technician_view` | `true` | `false` keeps the app in self-service mode |
| `[policy] remote_safe` | `false` | start in remote-safe mode (technicians can switch it off) |
| `[time] server`, `zone` | the machine's own source; none | clock offset and time zone checks |
| `[network] public_probes` | `true` | the public DNS name, TCP probe and public-IP lookup |
| `[network] dns_probe` | `"www.microsoft.com"` | the timed lookup (an explicit name runs even with public probes off) |
| `[network] tcp_probe` | `"8.8.8.8:53"` | the outbound TCP probe (same rule) |
| `[network] egress_url` | `"https://ifconfig.me/ip"` | public-IP lookup (falls back to api.ipify.org); `""` skips it |
| `[network] target_ports` | `[443, 80, 445, 3389]` | the destination test's ports when none are given |
| `[network] tcp_timeout_ms` | `1500` | per TCP check, shared by every address a name resolves to |
| `[network] ping_count`, `ping_timeout_ms` | `4`, `1000` | ICMP echoes per probe and the wait for each |
| `[thresholds]` | NetTriage's | `uptime_days` 7/14, `cpu_pct` 75/90, `memory_pct` 80/90, `disk_free_pct` 15/10, `disk_latency_ms` 15/30, `wifi_signal_pct` 70/50, `gateway_rtt_ms` 20/50, `network_rtt_ms` 80/150, `dns_ms` 100/300, `packet_loss_pct` 1/10, each as `{ warn, crit }` |
| `[privacy] redact_serial` | `false` | show REDACTED for the serial number (also `--redact-serial`) |
| `[updates] windows_update_drivers` | `"auto"` | `"always"` installs Windows Update drivers after the OEM tool too |
| `[cleanup] temp_min_age_hours` | `24` | temp files changed more recently are kept |
| `[history] keep` | `100` | saved runs kept; `0` keeps them all |
| `[[require.service]]`, `[[require.app]]`, `[[require.endpoint]]`, `[[require.device]]` | none | what this machine must have |
| `[[kb]]` | none | knowledge-base links for matching findings |

Two complete examples live in [`profiles/`](profiles/): a clinical workstation
and a home lab. Their hosts and articles are placeholders to replace with your
own. Click the profile tag in the header to see which profile is active,
where it came from and what it allows.

## One-click fixes

Findings can carry a fix button. Every fix is a fixed, built-in procedure: a
profile can switch fixes off but never define new commands. Before running,
the policy (and remote-safe mode) is checked again in the engine, whatever the
UI showed. Every attempt, allowed, refused or failed, is written to the audit
log (`audit.jsonl` in the app's state folder) **and** to the Windows
Application event log (source `itriage`) or syslog. After a fix runs, the
module re-checks itself so you see whether it worked.

| Fix | Offered when | Windows | Linux | Admin |
|---|---|---|---|:-:|
| Restart Print Spooler | the print service is down | stop + start Spooler | `systemctl restart cups` | ✔ |
| Clear print queue | jobs are stuck behind a printer error | stop Spooler, empty `spool\PRINTERS`, start | `cancel -a -x` | ✔ |
| Resync clock | clock drift over 10 s | `w32tm /resync` (then `/rediscover`) | `chronyc makestep`, or restart timesyncd | ✔ |
| Refresh Group Policy | policy older than 24 h | `gpupdate /force` (locked by remote-safe) | n/a | |
| Start service | a stopped Automatic or required service | SCM start | `systemctl start` | ✔ |
| Flush DNS cache | DNS resolution failed | `ipconfig /flushdns` | `resolvectl flush-caches` | |
| Restart in 60 s | a restart is pending | `shutdown /r /t 60` with a message (locked by remote-safe) | `shutdown -r +1` | Linux |
| Cancel restart | after a scheduled restart | `shutdown /a` | `shutdown -c` | Linux |
| Install this update | beside each pending Windows update | download and install that one update | n/a | ✔ |
| Install the OEM tool | the manufacturer's tool is missing | `winget install` of that tool (needs `allow_installs`) | n/a | ✔ |

Targets are validated before use (a service name, a Windows Update ID, one of
the known OEM tool IDs), and on Linux every privileged command is an argument
array passed to `pkexec`, never a shell string.

## Run history and compare

Every run is saved as a JSON report, with a plain-text transcript beside it, in
the history folder (`%LOCALAPPDATA%\itriage\history` or
`~/.local/share/itriage/history`, last 100 kept). When a run finishes, it's
compared with the most comparable earlier run on that machine (see
[Compare-NetTriage](#compare-nettriage--before-and-after) above): a banner
counts problems that are **new**, **resolved**, **still failing** or
**changed**, and measurements that got **better** or **worse**. Findings are
badged in place, and **Details** opens the full comparison with a
before/after table.

* **History** lists saved runs. Open one to read it with its own comparison,
  or tick two and compare them.
* **Open** loads a report exported elsewhere: another machine's run, or the
  command line's `--json` or `--out` output. It's added to the history, so the
  next report from that machine is compared against it.

## Ticket exports

**Export** copies the run (or the saved report you're viewing) as:

* **Ticket text**: plain text with key findings first, for ServiceNow, email
  and work notes;
* **Full transcript**: the same plus every module's log, for an escalation;
* **Rich text**: an inline-styled table that survives pasting into TeamDynamix
  and Outlook (falls back to plain text where rich copy isn't available);
* **Markdown**: for Teams, GitHub and wikis;
* **JSON report**: re-opens in itriage.

Each includes the host, OS, privilege level, profile, the before/after summary
and KB links.

## Command line

The installed program switches to the command line whenever it's given
arguments. On Windows it attaches to the console that started it; use
`start /wait` (cmd) or `Start-Process -Wait` (PowerShell) so the shell waits
for it and gets the exit code:

```bat
start "" /wait "%ProgramFiles%\itriage\itriage.exe" --preset triage --target fileserver01:445,3389 --out C:\Temp\triage.json
echo %ERRORLEVEL%
```

```powershell
$p = Start-Process "$env:ProgramFiles\itriage\itriage.exe" -ArgumentList '--preset', 'tuneup', '--remote-safe', '--what-if' -NoNewWindow -Wait -PassThru
$p.ExitCode
```

Adjust the path to wherever the installer put it. RMM tools and scheduled
tasks that wait for the process and read its output need nothing special.

```text
itriage [OPTIONS] [MODULE...]

  With no modules, every read-only check runs. Modules that change the
  machine run only when named (or picked by a preset), and the site
  profile's policy still applies to them.

  --list                 List modules and presets, then exit
  --preset NAME          triage, tuneup or updates
  --target HOST[:PORTS]  Test one destination (adds the Destination test)
  --ports LIST           Ports for --target (default 443,80,445,3389)
  --what-if              Preview: changes say what they would do, and don't
  --remote-safe          Refuse anything that could drop a remote session or
                         restart the PC (--no-remote-safe overrides the profile)
  --redact-serial        Show REDACTED instead of the serial number
  --json                 Print the full JSON report instead of text
  --log                  Include each module's transcript in the text
  --out PATH             Also write the JSON report (or comparison) to PATH,
                         with the text beside it as PATH.txt
  --no-history           Don't save this run in the history folder
  --quiet                No progress lines on stderr
  --fix ID [TARGET]      Run one one-click fix
  --compare OLD NEW      Compare two saved reports from the same computer
```

Progress goes to stderr and the report to stdout, so `> report.txt` captures
just the report. From a source checkout, `cargo run -p itriage-core --example triage -- <options>`
runs the same command line.

## Cancel

While a sequence runs, the run button becomes **Abort sequence**. Modules stop
at the next safe point: Windows Update stops between downloads and before the
install batch (downloads stay cached), and winget is skipped. An install that
has started always finishes, so nothing is left half-installed.

## Live progress

Modules can stream progress lines while they run (`RunContext::log`). The Tauri
shell forwards each line to the UI as a `module-log` event, so a 30-minute
Windows Update run shows *Downloading 2/5: …* and winget's output as it happens
rather than a frozen spinner. The lines are kept with the result (up to 600 per
module) for the transcript export.

The process runner (`util::stream`) handles the problems that show up with real
installers:

* **progress-bar redraws** (`\r` without `\n`) are dropped, and ANSI codes are
  stripped, so the log stays readable;
* **grandchild processes holding the pipes open** (installers that spawn
  background services) don't hang the module. Once the direct child exits,
  the runner waits only a short grace period;
* **hung tools** are killed after a per-module timeout;
* on Windows, every child is spawned with `CREATE_NO_WINDOW`, so a GUI app
  doesn't flash a console window per command.

## Interface

The technician console is a red HUD-style diagnostic console:

* **Live telemetry strip** across the top. Five scopes are fed once a second by
  `itriage_core::telemetry::Sampler`: CPU (big trace), network ↓/↑, per-core
  bars, memory, and disk read/write. The browser preview runs a clearly
  labelled simulated feed instead.
* **Host readout**: TARGET (hostname), OS, PRIV (`[USER]` / `[ADMIN]` /
  `[ROOT]`, with an Elevate button on Windows), and STATUS (`READY`,
  `RUNNING`, then `COMPLETE`, `CAUTION`, `ALERT` or `CANCELLED`).
* **Profile tag** (`MANAGED`, `PERSONAL`, `TEST` or `DEFAULT`), PREVIEW and
  REMOTE-SAFE tags when those modes are on, and a switch to the self-service
  view.
* **Presets** above the module list, and the **PREVIEW** and **REMOTE-SAFE**
  switches beside the run button (which reads "Run preview" in preview).
* **Module cards** with short codes (`[SYS-INF]`, `[NET-LAT]` …), WIN/LIN chips
  lit for the current OS, mini-glyphs (four of them live), a **DISRUPTIVE**
  badge on changes that remote-safe locks, and the destination field on the
  Destination test card. Modules the profile or remote-safe blocks show
  **LOCKED** with the reason.
* **Banners** above the results for a needed restart (with Restart in 60 s and
  Cancel restart), a preview, and the comparison with the last run; the run's
  summary line says "restart needed" or "preview" too.
* Findings carry **fix buttons**, **KB links**, **NEW / WORSE / BETTER / STILL**
  badges and measurement changes (`+26 ms`) after a compare.

The self-service view is deliberately quieter: teal, no scanlines, big type,
plain words. Type throughout: Rajdhani (display), Chakra Petch (interface),
Share Tech Mono (data), all bundled. Animations respect
`prefers-reduced-motion`.

## Privilege model

| | Windows | Linux |
|---|---|---|
| Read-only checks | standard user | standard user |
| Changes, installs and admin fixes | fail fast with a clear message unless the app is elevated | ask for a password **per task** through `pkexec` (polkit) |
| Getting rights | **Relaunch as admin** button in the header (UAC `runas`) | automatic; the GUI itself never runs as root |

The header always shows whether you're running elevated, and fix buttons that
need admin rights say so before you click. A preview needs no rights.

## Architecture

```
itriage/
├── crates/itriage-core/        # the engine: GUI-agnostic, no Tauri
│   ├── src/
│   │   ├── model.rs            # Severity / Finding (+metric, fix, KB) / ModuleInfo / ModuleResult / Target
│   │   ├── module.rs           # TriageModule trait, RunContext (preview, remote-safe, target,
│   │   │                       #   progress, cancel, profile), registry(), presets, exit codes
│   │   ├── cli.rs              # the command line
│   │   ├── profile.rs          # site profiles: discovery, policy, settings, requirements, KB rules
│   │   ├── actions.rs          # one-click fixes: policy-checked, validated, audited
│   │   ├── audit.rs            # audit.jsonl + Windows event log / syslog
│   │   ├── report.rs           # saved runs, history, before/after comparison, text rendering
│   │   ├── host.rs  paths.rs  util.rs  telemetry.rs
│   │   ├── parse/              # PURE parsers, unit-tested on any OS: SMBIOS, ping, routes,
│   │   │                       #   diskstats, DNS replies, SNTP, versions, printer status, battery
│   │   │                       #   reports, nmcli, Device Manager codes, winget, event XML, …
│   │   ├── win/                # thin native Windows wrappers (windows crate): WUA, SCM, Evt*,
│   │   │                       #   IP Helper, WinHTTP, PDH, SMBIOS, WTS, spooler, SetupAPI, WLAN,
│   │   │                       #   Crypt32, NetAPI, registry, and the fixed PowerShell runner
│   │   ├── triage/             # system, disk, memory, processes, services, network, eventlog
│   │   ├── net/                # latency, proxy, destination test, and the network layer
│   │   ├── desk/               # time, domain, printers, devices, wifi, certs, battery
│   │   ├── site/               # required apps, required services + endpoints
│   │   ├── fixes/              # dns, netrepair, temp, maintenance (the Tune-up modules)
│   │   └── update/             # scan, apply, firmware, winget, oem (table-driven), pkgmgr
│   └── examples/triage.rs      # the command line, for `cargo run --example`
├── profiles/                   # example site profiles
├── src-tauri/                  # desktop shell: commands + events (and the CLI switch)
└── src/                        # frontend (vanilla JS, no bundler, fonts bundled)
```

**The engine is the product; the GUI is a shell.** Each module is a
`TriageModule` with `info()` (the checklist entry), `execute(ctx)` (do the
work) and, for changes, `preview(ctx)` (say what it would do). OS-specific
code stays thin (call the API or tool, hand the result to a parser in
`parse/`), which is why every output format, including the Windows-only ones,
is unit-tested.

## Run it

Installers for Windows (`.msi`, setup `.exe`) and Linux (`.deb`) are on the
[Releases](https://github.com/jp101216/itriage/releases) page. CI also builds
them on every push, under each run's artifacts.

To build yourself you need Rust (stable) and the Tauri CLI (`cargo install tauri-cli`).

* **Windows**: the WebView2 runtime (preinstalled on Windows 11).
* **Linux**: WebKitGTK and friends, e.g. on Debian/Ubuntu:
  `sudo apt install libwebkit2gtk-4.1-dev build-essential libssl-dev librsvg2-dev`
* No Node.js needed. The frontend is static files.

```bash
cargo tauri dev        # run the app
cargo tauri build      # release bundle / installer
```

Headless from a checkout:

```bash
cargo run -p itriage-core --example triage -- --list
cargo run -p itriage-core --example triage                     # every read-only module
cargo run -p itriage-core --example triage -- --preset triage --target fileserver01:445
cargo run -p itriage-core --example triage -- --preset tuneup --what-if
cargo run -p itriage-core --example triage -- --json > report.json   # open it in the app
ITRIAGE_PROFILE=profiles/home-lab.toml cargo run -p itriage-core --example triage -- site.checks
```

## Releasing

1. Bump the version in `crates/itriage-core/Cargo.toml`, `src-tauri/Cargo.toml`
   and `src-tauri/tauri.conf.json`.
2. Add the notes as `release-notes/vX.Y.Z.md`, and merge to `main`.
3. On GitHub: **Actions → Release → Run workflow** (on `main`). There's nothing
   to type; it works from the GitHub mobile app too.

The Release workflow runs the full CI build and tests, then tags that commit
with the version from `tauri.conf.json` and publishes the release with the
Windows and Linux installers attached. It stops before publishing if that
version has already been released. Pushing a `vX.Y.Z` tag from a clone does
the same, but leaves the release as a draft to review first.

## Security notes

* Strict CSP in `tauri.conf.json`: the window loads nothing remote, and the
  fonts are bundled (OFL).
* The only network traffic is what a module you run asks for: the
  connectivity checks (a timed lookup of `www.microsoft.com`, a TCP connect to
  `8.8.8.8:53` and the public IP from `ifconfig.me`, falling back to
  `api.ipify.org`, all switchable in the profile), ICMP echoes to the gateway
  and DNS server, a destination you type, the SNTP probe, the profile's
  endpoints, and update checks.
* Fixed procedures only. No input is ever interpolated into a shell command;
  a profile can switch fixes off but can't add commands.
* KB links open only if they're `https://`; history files can only be loaded
  from the history folder (other reports come in by content, through Open).
* A run and a fix never overlap, and every fix attempt is audited.
* Windows checks use native APIs rather than spawning PowerShell, which is
  faster and still works where PowerShell is locked down. Three Tune-up steps
  need cmdlets with no plain API (adapter power settings and adapter restarts
  through the NetAdapter module, and the Configuration Manager client's
  triggers). They run short scripts compiled into itriage, passed with
  `-EncodedCommand` and never built from input. Where PowerShell is blocked,
  those steps report it and the rest of the run carries on.

## Verification status (v0.5)

| What | How | Result |
|---|---|---|
| Workspace, Linux | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Core crate, Windows | clippy-clean for `x86_64-pc-windows-msvc` via `-Zbuild-std` | clean |
| Engine | 129 unit tests: parsers (SMBIOS, ping, routes, diskstats, DNS replies, SNTP, versions, printers, battery, nmcli, Device Manager codes, winget, event XML, journald, package managers), destination parsing, thresholds, presets and exit codes, previews, temp cleanup on a throwaway folder, profiles and policy, fix validation, history and the before/after comparison | all pass |
| Command line, Linux | every read-only module and the triage preset (with a destination) run for real; the Tune-up and update modules previewed; exit codes checked | working |
| Desktop app, Linux | built and run against WebKitGTK 4.1: the new commands exercised over IPC (presets, destination parsing, preview runs, remote-safe refusals, two triage runs compared, transcripts, fix validation, concurrent-run refusal) and the tune-up preview screen rendered | working |
| Interface | the browser preview driven through every v0.5 flow (presets, preview, restart banner, destination, remote-safe locks, comparison, transcript, narrow layout), no console errors | working |
| Windows, CI | `windows-latest` (Windows Server 2025): 122 unit tests, clippy, every read-only module (SMBIOS, PDH, IP Helper, ICMP, WinHTTP, the signed-in user's proxy, WUA, winget), the triage preset with a destination, and previews of the Tune-up and update modules (which run the PowerShell adapter queries read-only); installers built | passing |
| Repairs, installs and OEM tools on real hardware | not yet run on a physical Windows workstation | ⚠ next step |

A CI runner is a server VM with no Wi-Fi, battery, printers or domain, so those
checks report "none" there. The paths that need hardware (WLAN, battery report,
spooler with real printers, SetupAPI problem codes, domain and Group Policy)
need a pass on a real workstation, and so do the Tune-up repairs, the update
installs and the OEM tools' flags and exit codes, which come from vendor
documentation. Try them with PREVIEW on first.

Re-run the Windows check from Linux (needs the `rust-src` component):

```bash
RUSTC_BOOTSTRAP=1 cargo clippy -Zbuild-std=std,panic_abort \
  --target x86_64-pc-windows-msvc -p itriage-core --all-targets -- -D warnings
```

## Next ideas

* Per-percent Windows Update download progress (`IDownloadProgressChangedCallback`).
* Gateway and DNS latency over the destination's route, as NetTriage does, rather than the default route.
* Secure-channel check for domain trust (needs elevation).
* More OEMs, plus flatpak/snap on Linux.
* Code signing for the Windows installer.

## License

Not licensed yet, so all rights are reserved until a license is chosen. The
bundled fonts (Rajdhani, Chakra Petch, Share Tech Mono) are under the SIL
Open Font License 1.1; see the `src/fonts/LICENSE-*.txt` files.
