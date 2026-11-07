# itriage

[![CI](https://github.com/jp101216/itriage/actions/workflows/ci.yml/badge.svg)](https://github.com/jp101216/itriage/actions/workflows/ci.yml)

A cross-platform IT triage & update tool. Tick the checks you want, run them,
and get streamed, severity-coded results you can export as JSON or as plain
ticket-pasteable text. It runs on Windows and Linux as one desktop app with a
modern GUI.

This is the Rust successor to the service-desk side of the PowerShell Ops IR
toolkit (`Invoke-EndpointTriage` + `Invoke-NetTriage` + `Update-System`), fused
into a single desktop app.

> **Working name.** `itriage` is a placeholder. Rename the crates and the
> window title whenever you've landed on the real name.

---

## Modules

| Module | Category | Changes system | Admin | Windows | Linux |
|---|---|:-:|:-:|---|---|
| System information | System | | | sysinfo + SMBIOS (registry) | sysinfo + `/sys/class/dmi` |
| Disk usage | System | | | per-volume free space; warns < 10%, critical < 5% | same |
| Memory usage | System | | | RAM + page file | RAM + swap |
| Top processes | Processes & services | | | top 10 by memory **plus CPU hogs**; flags > 80% of a core or > 25% of RAM | same (threads filtered out) |
| Services | Processes & services | | | **native SCM**: Automatic services not running, exit codes decoded | `systemctl`: failed units + `is-system-running` |
| Network connectivity | Network | | | interface IPs, DNS resolve, outbound TCP probe | same |
| Recent errors | Event log | | | **native Evt\* API**: System + Application, Critical/Error, last 24 h, grouped by provider + event ID | `journalctl -p err`, grouped by source + normalised message |
| Clear temp files | Fixes | ✔ | | user temp dir, skips locked files | same |
| Flush DNS cache | Fixes | ✔ | | `ipconfig /flushdns` | `resolvectl flush-caches` |
| Available updates | Updates | | | **WUA COM** search (KB, MSRC severity), pending restart, winget table, OEM tool status | apt/dnf/pacman/zypper (no root), fwupd, `/var/run/reboot-required` |
| Install OS & app updates | Updates | ✔ | ✔ | **WUA COM** download + install (optional/preview skipped), then `winget upgrade --all` | full non-interactive upgrade via the detected package manager |
| Install drivers & firmware | Updates | ✔ | ✔ | OEM tool (Dell DCU / HP HPIA / Lenovo Thin Installer), else Windows Update drivers | `fwupdmgr` (LVFS) |

Install modules are split by risk, so you can patch the OS without also
flashing a BIOS. "All checks" selects only read-only modules; anything that
changes the system has to be ticked on purpose and goes through a confirmation
dialog that spells out what it will do.

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

A red HUD-style diagnostic console:

* **Live telemetry strip** across the top. Five scopes are fed once a second by
  `itriage_core::telemetry::Sampler`: CPU (big trace), network ↓/↑, per-core
  bars, memory, and disk read/write. The sampler is stateful because CPU% and
  throughput are deltas. It skips loopback interfaces and counts each physical
  disk once, even when it's mounted several times. The browser preview runs a
  clearly labelled simulated feed instead.
* **Host readout**: TARGET (hostname), OS, PRIV (`[USER]` / `[ADMIN]` /
  `[ROOT]`, with an Elevate button on Windows), and STATUS (`READY`,
  `RUNNING`, then `COMPLETE`, `CAUTION` or `ALERT` depending on the worst
  result).
* **Module cards** with short codes (`[SYS-INF]`, `[DSK-USE]` …), WIN/LIN
  chips lit for the current OS, and mini-glyphs. Four of them are live (CPU,
  memory, per-core load, fullest-volume gauge with a warning mark at ≥ 90%).
  After a run, each card gets a status LED.
* **Run Diagnostic Sequence** button with hazard stripes that animate while a
  sequence runs; results stream into the report pane with live tool output.
* Type: Rajdhani (display), Chakra Petch (interface), Share Tech Mono (data),
  all bundled. Animations respect `prefers-reduced-motion`.

## Privilege model

| | Windows | Linux |
|---|---|---|
| Read-only checks | standard user | standard user |
| Install modules | fail fast with a clear message unless the app is elevated | ask for a password **per task** through `pkexec` (polkit) |
| Getting rights | **Relaunch as admin** button in the header (UAC `runas`) | automatic; the GUI itself never runs as root |

The header always shows whether you're running elevated.

## Architecture

```
itriage/
├── crates/itriage-core/        # the engine: GUI-agnostic, no Tauri
│   ├── src/
│   │   ├── model.rs            # Severity / Finding (+detail) / ModuleInfo / ModuleResult
│   │   ├── module.rs           # TriageModule trait, RunContext (progress), registry()
│   │   ├── host.rs             # host context, elevation, relaunch, manufacturer
│   │   ├── util.rs             # PATH lookup, capture / stream / privileged runners
│   │   ├── telemetry.rs        # stateful sampler behind the live HUD scopes
│   │   ├── parse/              # PURE parsers, unit-tested on any OS
│   │   │   ├── winget.rs  evtxml.rs  journal.rs  pkg.rs  systemd.rs  text.rs  time.rs
│   │   ├── win/                # thin native Windows wrappers (windows crate)
│   │   │   ├── wua.rs          # Windows Update Agent: search / download / install
│   │   │   ├── scm.rs          # Service Control Manager enumeration
│   │   │   ├── eventlog.rs     # EvtQuery / EvtRender / EvtFormatMessage
│   │   │   ├── token.rs  shell.rs  registry.rs  com.rs
│   │   ├── triage/             # system, disk, memory, processes, services, network, eventlog
│   │   ├── fixes/              # temp, dns
│   │   └── update/             # scan, apply, firmware, winget, oem (table-driven), pkgmgr
│   └── examples/triage.rs      # headless CLI runner
├── src-tauri/                  # desktop shell, ~100 lines
└── src/                        # frontend (vanilla JS, no bundler, fonts bundled)
```

**The engine is the product; the GUI is a shell.** Each check is a
`TriageModule` with `info()` (the checklist entry) and `execute(ctx)` (do the
work). OS-specific code stays thin (call the API or tool, hand the text to a
parser in `parse/`), which is why every output format, including the
Windows-only ones, is unit-tested.

## Run it

Prerequisites: Rust (stable) and the Tauri CLI (`cargo install tauri-cli`).

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
cargo run -p itriage-core --example triage -- proc.services eventlog.errors
cargo run -p itriage-core --example triage -- --json update.scan
```

## Security notes

* Strict CSP in `tauri.conf.json`: the window loads nothing remote, and the
  fonts are bundled (OFL). The only network traffic is what you ask for: the
  connectivity probe (example.com, 1.1.1.1) and update checks.
* Fixed scripts only. No user input is ever interpolated into a shell command.
* Windows checks use native APIs rather than spawning PowerShell, which is
  faster and still works where PowerShell is locked down (Constrained
  Language Mode or AppLocker).

## Verification status (v0.3)

| What | How | Result |
|---|---|---|
| Workspace, Linux | `cargo clippy --workspace --all-targets` | clean, zero warnings |
| Core crate, Windows | type-checked for `x86_64-pc-windows-msvc` via `-Zbuild-std` (see below) + clippy | clean, zero warnings |
| Parsers, runner, sampler | 30 unit tests (winget tables, event XML, journald JSON, apt/dnf/pacman/zypper/fwupd, ISO-8601, stream redraws/timeouts/grandchildren, telemetry) | all pass |
| Linux modules | run live on Ubuntu 24.04, including a real `apt` upgrade through **Install OS & app updates** | working |
| Desktop app, Linux | built and launched against WebKitGTK 4.1 under Xvfb: IPC, live `module-log` streaming, **live telemetry scopes**, strict CSP, bundled fonts | working |
| Windows runtime | **not run on Windows yet** | ⚠ next step |

What "type-checked for Windows" means: every Win32/COM call compiles against
the real `windows` 0.62 bindings, but nothing has executed on a Windows box
yet. Runtime behaviour (WUA result codes, SCM edge cases, event-message
formatting) needs a pass on real hardware. The OEM tools' flags and exit codes
come from vendor documentation and are untested on Dell/HP/Lenovo hardware.

Re-run the Windows type-check from Linux (needs the `rust-src` component):

```bash
RUSTC_BOOTSTRAP=1 cargo check -Zbuild-std=std,panic_abort \
  --target x86_64-pc-windows-msvc -p itriage-core --all-targets
```

## Next ideas

* Cancel button for long installs (with a safe stopping point between packages).
* Per-percent Windows Update download progress (`IDownloadProgressChangedCallback`).
* More OEMs, plus flatpak/snap on Linux.
* Code signing for the Windows installer.

## License

Not licensed yet, so all rights are reserved until a license is chosen. The
bundled fonts (Rajdhani, Chakra Petch, Share Tech Mono) are under the SIL
Open Font License 1.1; see the `src/fonts/LICENSE-*.txt` files.
