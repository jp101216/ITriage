# itriage

[![CI](https://github.com/jp101216/itriage/actions/workflows/ci.yml/badge.svg)](https://github.com/jp101216/itriage/actions/workflows/ci.yml)

A cross-platform IT triage & update tool for Windows and Linux, built as one
desktop app. It has two views:

* **Technician console.** Tick the checks you want, run them, and get streamed,
  severity-coded results with one-click fixes and knowledge-base links. Every
  run is saved, so the next run on that machine shows what changed. Results
  export as ticket text, rich text for TeamDynamix, Markdown, or JSON.
* **Self-service check.** A calm page for the person at the PC: their computer
  name up front (with a copy button), one "Check my computer" button, results
  in plain words, a few safe fixes, and "Copy details for the service desk".

A **site profile** tailors it to an environment: which services, apps,
servers and devices a machine must have, which fixes are allowed, whether
installs are locked, and which KB articles go with which problems.

This is the Rust successor to the service-desk side of the PowerShell Ops IR
toolkit (`Invoke-EndpointTriage` + `Invoke-NetTriage` + `Update-System`), fused
into a single desktop app.

> **Working name.** `itriage` is a placeholder. Rename the crates and the
> window title whenever you've landed on the real name.

---

## Modules

| Module | Category | Changes system | Admin | Windows | Linux |
|---|---|:-:|:-:|---|---|
| System information | System | | | sysinfo + SMBIOS (registry), edition + build | sysinfo + `/sys/class/dmi` |
| Disk usage | System | | | per-volume free space; warns < 10%, critical < 5% | same |
| Memory usage | System | | | RAM + page file | RAM + swap |
| Top processes | Processes & services | | | top 10 by memory **plus CPU hogs**; flags > 80% of a core or > 25% of RAM | same (threads filtered out) |
| Services | Processes & services | | | **native SCM**: Automatic services not running, exit codes decoded | `systemctl`: failed units + `is-system-running` |
| Network connectivity | Network | | | interface IPs, DNS resolve, outbound TCP probe | same |
| Recent errors | Event log | | | **native Evt\* API**: System + Application, Critical/Error, last 24 h, grouped by provider + event ID | `journalctl -p err`, grouped by source + normalised message |
| Clock & time sync | Workstation | | | W32Time source (registry), **SNTP offset** vs. the DC or configured server, time zone | `timedatectl`, SNTP vs. the timesyncd/chrony source |
| Domain & Group Policy | Workstation | | | domain join, **DC vs. cached-credential sign-in**, AD site, last computer policy refresh | n/a |
| Printers & print queue | Workstation | | | **spooler API**: status flags, stuck jobs, default and label printers | CUPS `lpstat` |
| Devices & peripherals | Workstation | | | **SetupAPI**: Device Manager problem codes, microphones, cameras, card readers | USB devices from sysfs |
| Wi-Fi & VPN | Workstation | | | **WLAN API**: SSID, signal, WPA/802.1X level, link rate; VPN adapters (IP Helper) | `nmcli`, tunnel interfaces |
| Machine certificates | Workstation | | | LocalMachine\My expiry; warns 14 days out | n/a |
| Battery health | Workstation | | | design vs. full-charge capacity (`powercfg /batteryreport`), cycles | sysfs `power_supply` |
| Required & clinical apps | Site & clinical | | | the profile's required apps and minimum versions, plus a watchlist of clinical clients | dpkg / rpm / pacman packages |
| Site services & endpoints | Site & clinical | | | the profile's required services; its servers checked by DNS + TCP, in parallel | systemd units; same |
| Clear temp files | Fixes | ✔ | | user temp dir, skips locked files | same |
| Flush DNS cache | Fixes | ✔ | | `ipconfig /flushdns` | `resolvectl flush-caches` |
| Available updates | Updates | | | **WUA COM** search (KB, MSRC severity), pending restart, winget table, OEM tool status | apt/dnf/pacman/zypper (no root), fwupd, `/var/run/reboot-required` |
| Install OS & app updates | Updates | ✔ | ✔ | **WUA COM** download + install (optional/preview skipped), then `winget upgrade --all` | full non-interactive upgrade via the detected package manager |
| Install drivers & firmware | Updates | ✔ | ✔ | OEM tool (Dell DCU / HP HPIA / Lenovo Thin Installer), else Windows Update drivers | `fwupdmgr` (LVFS) |

Install modules are split by risk, so you can patch the OS without also
flashing a BIOS. "All checks" selects only read-only modules; anything that
changes the system has to be ticked on purpose and goes through a confirmation
dialog that spells out what it will do.

The workstation checks answer the questions a desk asks first on a shared or
clinical PC. A few details:

* **Clock**: Kerberos refuses domain sign-in past 5 minutes of drift. The
  offset is a warning over 10 s and critical over 3 minutes.
* **Domain**: a user signed in with cached credentials (no DC answered) gets a
  warning, because password changes, new groups and policy won't apply.
* **Printers**: jobs queued behind a printer in an error state are called out
  as stuck. Zebra-style label printers are tagged. A Print Spooler that's
  disabled on purpose (PrintNightmare hardening on servers) isn't flagged.
* **Wi-Fi**: under 35% signal is a warning, since carts that roam a ward drop
  remote sessions on weak signal. Windows 11 24H2 hides network names from apps
  without location access; the check says so instead of showing a blank.
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

[time]
server = "dc01.example.org"       # measure the clock against this
zone = "Eastern Standard Time"    # flag a wrong time zone

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

Two complete examples live in [`profiles/`](profiles/): a clinical workstation
and a home lab. Their hosts and articles are placeholders to replace with your
own. Click the profile tag in the header to see which profile is active,
where it came from and what it allows.

## One-click fixes

Findings can carry a fix button. Every fix is a fixed, built-in procedure: a
profile can switch fixes off but never define new commands. Before running,
the policy is checked again in the engine, whatever the UI showed. Every
attempt, allowed, refused or failed, is written to the audit log
(`audit.jsonl` in the app's state folder) **and** to the Windows Application
event log (source `itriage`) or syslog. After a fix runs, the module re-checks
itself so you see whether it worked.

| Fix | Offered when | Windows | Linux | Admin |
|---|---|---|---|:-:|
| Restart Print Spooler | the print service is down | stop + start Spooler | `systemctl restart cups` | ✔ |
| Clear print queue | jobs are stuck behind a printer error | stop Spooler, empty `spool\PRINTERS`, start | `cancel -a -x` | ✔ |
| Resync clock | clock drift over 10 s | `w32tm /resync` (then `/rediscover`) | `chronyc makestep`, or restart timesyncd | ✔ |
| Refresh Group Policy | policy older than 24 h | `gpupdate /force` | n/a | |
| Start service | a stopped Automatic or required service | SCM start | `systemctl start` | ✔ |
| Flush DNS cache | DNS resolution failed | `ipconfig /flushdns` | `resolvectl flush-caches` | |

The service name for **Start service** is validated before use, and on Linux
every privileged command is an argument array passed to `pkexec`, never a
shell string.

## Run history and compare

Every run is saved as a JSON report in the history folder
(`%LOCALAPPDATA%\itriage\history` or `~/.local/share/itriage/history`, last 100
kept). When a run finishes, it's compared with the previous run on that
machine: a banner counts problems that are **new**, **resolved** or
**changed**, and findings are badged in place.

* **History** lists saved runs; open one to read it, with its own compare.
* **Open** loads a report exported elsewhere: another machine's run, or the
  CLI's `--json` output from a remote shell. It's added to the history, so the
  next report from that machine is compared against it.

## Ticket exports

**Export** copies the run (or the saved report you're viewing) as:

* **Ticket text**: plain text for ServiceNow, email and work notes;
* **Rich text**: an inline-styled table that survives pasting into TeamDynamix
  and Outlook (falls back to plain text where rich copy isn't available);
* **Markdown**: for Teams, GitHub and wikis;
* **JSON report**: re-opens in itriage.

Each includes the host, OS, privilege level, profile, the change summary and
KB links.

## Cancel

While a sequence runs, the run button becomes **Abort sequence**. Modules stop
at the next safe point: Windows Update stops between downloads and before the
install batch (downloads stay cached), and winget is skipped. An install that
has started always finishes, so nothing is left half-installed.

## Live progress

Modules can stream progress lines while they run (`RunContext::log`). The Tauri
shell forwards each line to the UI as a `module-log` event, so a 30-minute
Windows Update run shows *Downloading 2/5: …* and winget's output as it happens
rather than a frozen spinner.

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
* **Profile tag** (`MANAGED`, `PERSONAL`, `TEST` or `DEFAULT`) and a switch to
  the self-service view.
* **Module cards** with short codes (`[SYS-INF]`, `[PRN-QUE]` …), WIN/LIN chips
  lit for the current OS, and mini-glyphs, four of them live. Modules the
  profile blocks show **LOCKED** with the reason.
* Findings carry **fix buttons**, **KB links**, and **NEW / WORSE / BETTER**
  badges after a compare.

The self-service view is deliberately quieter: teal, no scanlines, big type,
plain words. Type throughout: Rajdhani (display), Chakra Petch (interface),
Share Tech Mono (data), all bundled. Animations respect
`prefers-reduced-motion`.

## Privilege model

| | Windows | Linux |
|---|---|---|
| Read-only checks | standard user | standard user |
| Install modules and admin fixes | fail fast with a clear message unless the app is elevated | ask for a password **per task** through `pkexec` (polkit) |
| Getting rights | **Relaunch as admin** button in the header (UAC `runas`) | automatic; the GUI itself never runs as root |

The header always shows whether you're running elevated, and fix buttons that
need admin rights say so before you click.

## Architecture

```
itriage/
├── crates/itriage-core/        # the engine: GUI-agnostic, no Tauri
│   ├── src/
│   │   ├── model.rs            # Severity / Finding (+detail, fix, KB) / ModuleInfo / ModuleResult
│   │   ├── module.rs           # TriageModule trait, RunContext (progress, cancel, profile), registry()
│   │   ├── profile.rs          # site profiles: discovery, policy, requirements, KB rules
│   │   ├── actions.rs          # one-click fixes: policy-checked, validated, audited
│   │   ├── audit.rs            # audit.jsonl + Windows event log / syslog
│   │   ├── report.rs           # saved runs, history, compare
│   │   ├── host.rs  paths.rs  util.rs  telemetry.rs
│   │   ├── parse/              # PURE parsers, unit-tested on any OS: SNTP, versions, printer
│   │   │                       #   status + lpstat, battery reports, nmcli, Device Manager codes,
│   │   │                       #   winget, event XML, journald, package managers, …
│   │   ├── win/                # thin native Windows wrappers (windows crate): WUA, SCM, Evt*,
│   │   │                       #   spooler, SetupAPI, WLAN, IP Helper, Crypt32, NetAPI, registry
│   │   ├── triage/             # system, disk, memory, processes, services, network, eventlog
│   │   ├── desk/               # time, domain, printers, devices, wifi, certs, battery
│   │   ├── site/               # required apps, required services + endpoints
│   │   ├── fixes/              # temp, dns
│   │   └── update/             # scan, apply, firmware, winget, oem (table-driven), pkgmgr
│   └── examples/triage.rs      # headless CLI runner
├── profiles/                   # example site profiles
├── src-tauri/                  # desktop shell: commands + events only
└── src/                        # frontend (vanilla JS, no bundler, fonts bundled)
```

**The engine is the product; the GUI is a shell.** Each check is a
`TriageModule` with `info()` (the checklist entry) and `execute(ctx)` (do the
work). OS-specific code stays thin (call the API or tool, hand the result to a
parser in `parse/`), which is why every output format, including the
Windows-only ones, is unit-tested.

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

Headless (servers, SSH sessions, quick checks):

```bash
cargo run -p itriage-core --example triage -- --list
cargo run -p itriage-core --example triage                    # every read-only module
cargo run -p itriage-core --example triage -- desk.printers site.checks
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
  fonts are bundled (OFL). The only network traffic is what you ask for: the
  connectivity probe (example.com, 1.1.1.1), the SNTP probe, the profile's
  endpoints, and update checks.
* Fixed procedures only. No input is ever interpolated into a shell command;
  a profile can switch fixes off but can't add commands.
* KB links open only if they're `https://`; history files can only be loaded
  from the history folder (other reports come in by content, through Open).
* A run and a fix never overlap, and every fix attempt is audited.
* Windows checks use native APIs rather than spawning PowerShell, which is
  faster and still works where PowerShell is locked down (Constrained
  Language Mode or AppLocker).

## Verification status (v0.4)

| What | How | Result |
|---|---|---|
| Workspace, Linux | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Core crate, Windows | type-checked and clippy-clean for `x86_64-pc-windows-msvc` via `-Zbuild-std` | clean |
| Engine | 69 unit tests: parsers (SNTP, versions, printer flags, lpstat, battery XML/sysfs, nmcli, Device Manager codes, winget, event XML, journald, package managers), profiles and policy, fix validation, history save and compare, endpoint probes | all pass |
| Desktop app, Linux | built and run against WebKitGTK 4.1: every command exercised over IPC (profile, locks, run, save, history, compare, import, fix validation, path and URL guards, re-check, concurrent-run refusal), both views rendered | working |
| Engine, Windows | the same suite on `windows-latest` (65 tests; a few are Linux-only) plus clippy with the runner's newer toolchain | all pass |
| Read-only modules, Windows | CI smoke run on `windows-latest` (Windows Server 2025): native SCM, Event Log, WUA, registry, winget | working |
| Workstation & site modules, Windows | CI smoke run, with and without the example profile: SNTP offset measured against time.windows.com, machine certificates read (it caught the runner's expired ones), spooler, SetupAPI problem codes, WLAN/adapters, Uninstall keys, policy locks, time-zone and requirement checks | working |
| Fixes, installs, OEM tools on real hardware | not run on a physical Windows workstation yet | ⚠ next step |

A CI runner is a server VM with no Wi-Fi, battery, printers or domain, so those
checks report "none" there. The paths that need hardware (WLAN, battery report,
spooler with real printers, SetupAPI problem codes, domain and Group Policy)
need a pass on a real workstation, as do the OEM tools' flags and exit codes,
which come from vendor documentation.

Re-run the Windows type-check from Linux (needs the `rust-src` component):

```bash
RUSTC_BOOTSTRAP=1 cargo check -Zbuild-std=std,panic_abort \
  --target x86_64-pc-windows-msvc -p itriage-core --all-targets
```

## Next ideas

* Per-percent Windows Update download progress (`IDownloadProgressChangedCallback`).
* Secure-channel check for domain trust (needs elevation).
* More OEMs, plus flatpak/snap on Linux.
* Code signing for the Windows installer.

## License

Not licensed yet, so all rights are reserved until a license is chosen. The
bundled fonts (Rajdhani, Chakra Petch, Share Tech Mono) are under the SIL
Open Font License 1.1; see the `src/fonts/LICENSE-*.txt` files.
