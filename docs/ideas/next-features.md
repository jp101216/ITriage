# ITriage: Next Feature Ideas (round 3) and how to build them

> **Status, November 2026.** Built on `main` (0.9.0) *without* the
> advanced-features package, which never reached the repository. So `print.path`,
> `app.paths`, the flight recorder, `advanced/hypotheses.rs` and
> `advanced/cases.rs` don't exist, and the ideas were adapted: #9 extends
> `desk.printers`, #10 and #13 build on the existing recorder
> (`investigate/recording.rs`), and the hypothesis hooks are rules in
> `insight.rs`. Where an idea names a verified-repair mapping, the fix is
> audited and re-checks its module instead. Each phase's pull request says
> what was adapted.

Target baseline: ITriage 0.9.0 **with the advanced-features package applied**
(`ITriage-Claude-Package.zip`). Every idea below was checked against that package
and against the two earlier idea lists, so nothing here repeats work that already
exists. Module IDs follow the registry's naming (`desk.*`, `net.*`, `sec.*`, …).

---

## Part 1: What to do, step by step

### Step 1: Land the advanced-features package first (prerequisite)

Half of these ideas extend code that only exists after the package is applied
(`print.path`, `app.paths`, the flight recorder, verified-repair cases,
`hypotheses.rs`). Apply it before starting anything here.

1. In the full repository, create a branch: `git switch -c feat/advanced-package`
2. Check the baseline: `python apply_package.py /path/to/ITriage --check`
3. If it matches, apply it: `python apply_package.py /path/to/ITriage --apply`
   (if it doesn't match, ask Claude Code to do a reviewed merge, as
   `CLAUDE_START_HERE.md` describes)
4. Run the checks:
   - `cargo test -p itriage-core --all-targets`
   - `cargo clippy -p itriage-core --all-targets -- -D warnings`
5. Have Claude Code mount `integration/advanced-panel.js` in the technician view
   (the ready-made prompt is in `CLAUDE_START_HERE.md`).
6. Merge the branch.

### Step 2: Put this file in the repo

- Save it as `docs/ideas/next-features.md`. You can also put your two earlier
  lists beside it, e.g. `docs/ideas/ideas-round1.txt` and `ideas-round2.txt`.
- Commit it on its own small branch and merge it. Claude Code can then read it in
  every future session.

### Step 3: Set up lab targets once (reused by every feature)

Most of these features can be tested in your GOAD lab. Add these targets:

| Target | Used for |
|---|---|
| Windows 11 Enterprise evaluation VM joined to a GOAD domain (e.g. `north.sevenkingdoms.local`) | sign-in waterfall, Kerberos, ASR/AppLocker blocks, Point and Print, IE-mode site list, Event Log audit, watch mode |
| GOAD's ADCS CA (ESSOS) | certificate revocation checks |
| Ubuntu VM joined with `realm join` | Linux domain parity, AppArmor denials |
| Any SIEM in the lab (Wazuh, Splunk Free or Elastic) | audit forwarding demo |
| A real laptop, when available | throttling and hardware errors (VMs don't throttle) |

Wired 802.1X and Outlook/Teams can be built from fixtures first. Validate them
later on real hardware or a real tenant.

### Step 4: Build one feature per branch, in the order in Part 3

For each feature:

1. `git switch -c feat/<module-id>` (e.g. `feat/sec-blocks`)
2. Open Claude Code in the repo and paste the prompt from Part 2, with the
   feature's number filled in.
3. **Review its plan before it writes code.** Check that it reuses the existing
   wrapper or parser named in the idea instead of writing a new one.
4. Let it implement the feature and run the Definition of Done checks (Part 2).
5. Run the lab check listed under the idea yourself, on the VM.
6. Open a PR, read the diff, and merge.

### Step 5: Release in batches

- After Phases 1–2, cut **v0.10.0**:
  - bump the version in the workspace `Cargo.toml` and `tauri.conf.json`
  - sign the Windows build with Azure Artifact Signing
  - write GitHub release notes, then publish your usual release posts
- Cut later phases as v0.11.0 and up.
- Update the README's "Next ideas" section each time, so it doesn't list shipped
  work.

---

## Part 2: Instructions for Claude Code

### Prompt to paste (one feature per session)

```text
Read the repository's own instructions (CLAUDE.md / README) and then
docs/ideas/next-features.md. Implement ONLY idea #<N>: <title>.

Before writing code:
1. Read the files the idea extends, plus module.rs, model.rs, profile.rs,
   actions.rs, insight.rs, advanced/hypotheses.rs and the src/parse/ conventions.
2. Tell me your plan in a few bullets: files you will add/change, which existing
   wrappers/parsers you will reuse, any `windows` crate features you need to
   enable, and any new profile keys with their defaults.
3. Wait for my OK.

Then follow the "Conventions" and "Definition of done" sections in that file.
Keep the module read-only unless the idea names a fix. Do not add new runtime
crates without asking. Work on the current branch. When done, summarize what
changed, what could not be runtime-validated on this machine, and the exact lab
steps I should run.
```

### Conventions (taken from the current code)

- **Modules.** A module is a struct implementing `TriageModule::info()` and
  `execute()`. Register it in `module::registry()` in its category group. Set
  `platforms` in `ModuleInfo` so `catalogue()` hides it on the wrong OS.
- **OS-specific code.** Put it behind `#[cfg(windows)]` / `#[cfg(not(windows))]`
  inside the module. Native Windows wrappers belong in `win/`. Parsers belong in
  `src/parse/`, are pure and OS-independent, and are unit-tested on any host with
  captured fixtures.
- **PowerShell.** Use it only where a native API is impractical. Each fixed script
  is registered in the `win/ps.rs` parser-test registry. Inputs reach scripts
  through environment variables and are never interpolated into code.
- **Profile keys.** New keys are `#[serde(default)]`, so old profiles parse
  unchanged. A managed profile that fails to parse still fails *closed*; don't
  weaken that.
- **Fixes.** Each new fix goes through `actions.rs` with:
  - the `policy.fixes` allowlist
  - preview/what-if output
  - correct `mutating` / `disruptive` flags, so remote-safe mode works
  - an audit entry carrying the ticket

  Also add the fix to the scope map and label matcher in `advanced/cases.rs`
  (the `"restart-spooler" => Some("desk.printers")` table), so verified repairs
  can measure before and after.
- **Stable finding labels.** `--compare`, `--baseline` and `--trends` match
  findings by label, so labels must not change between runs. Record
  measurements with `.with_metric(value, unit, higher_is_worse)`.
- **Honest evidence.** A healthy service, a TCP handshake or a nearby event is
  not proof. Word findings as "candidate" or "possible", as `timeline.rs` does,
  and put missing evidence in as an explicit gap finding.
- **Privacy.** New identifiers must appear in the bundle redaction preview. That
  includes UPNs, SPNs, file paths that contain usernames, CRL URLs and device
  serials.
- **Dependencies.** `sha2`, `regex`, `libc`, `serde_json`, `sysinfo` and
  `windows` are already in the tree. There's no XML crate; extend the existing
  hand-rolled `parse::evtxml` approach. Enabling more `windows` crate features
  is fine.

### Definition of done (every feature)

- [ ] `cargo test -p itriage-core --all-targets` passes
- [ ] `cargo clippy -p itriage-core --all-targets -- -D warnings` passes
- [ ] `cargo check -p itriage-core --all-targets --target x86_64-pc-windows-msvc`
      (or `-gnu` when cross-checking from Linux) passes
- [ ] Parser tests use sanitized **real** captures (event XML / tool output),
      not hand-typed guesses
- [ ] Module registered; preset/runbook updated where the idea says so;
      `presets_name_real_modules` still passes
- [ ] An old profile without the new keys still parses (add a test)
- [ ] Any fix has a preview, policy gating, an audit entry and a verified-repair mapping
- [ ] `itriage --json <module.id>` runs on the dev machine
- [ ] README module table and CHANGELOG updated
- [ ] PR description lists everything that wasn't runtime-validated

---

## Part 3: Build order

| Phase | Ideas | Why this order |
|---|---|---|
| 1. Quick wins | #1 `sec.blocks`, #2 `desk.logon`, #3 `system.hardware` | Read-only event and counter work through existing parsers; covers very frequent tickets |
| 2. Identity & trust | #4 revocation, #5 Kerberos, #6 audit to Event Log | The biggest outages, plus the security story for a tool that runs elevated |
| 3. Clinical desk | #7 `desk.m365`, #8 `desk.browser`, #9 Point and Print, #10 peripheral drops | User-context and HKCU work; two new fixes |
| 4. Network & Linux | #11 `net.wired-auth`, #12 Linux domain parity | Needs fixtures first, then real hardware or a domain-joined Linux VM |
| 5. Platform | #13 `--watch`, #14 major-incident feed | Long-running behavior and new profile sections; design review first |

---

## Part 4: Status of the earlier idea lists

Check this before re-implementing anything from rounds 1–2:

| Earlier idea | Status after the package | What's still open |
|---|---|---|
| Temporary / corrupt profile detection | Partial: `vdi.profile` reads User Profile Service events 1511/1515 and FSLogix logs | `ProfileList\<SID>` State bit 0x0800, `.bak` duplicate keys, a high-priority `insight.rs` rule |
| Printer network port reachability | Mostly done: `print.path` reads host and port and tests TCP | WSD/IPP port URLs |
| VDI session protocol & redirection | Open | `WTSClientProtocolType` / `WTSClientName` / `WTSClientAddress`; redirection channel health |
| Display, dock & monitor topology | Open | All of it |
| Route-aware gateway & DNS latency | Partial: `app.paths` reports each route's gateway and DNS | Actually pinging and timing them in `net.target` |
| VPN path MTU probe | Open | All of it |
| Per-process attribution in recordings | Partial: the flight recorder keeps hot processes | Plain `--record` `Sample`; `GetExtendedTcpTable` socket owners |
| Hosts file override audit | Open | All of it |
| Domain secure-channel check & repair | Partial: `domain.trust` does a read-only check through `Test-ComputerSecureChannel` | Native `I_NetLogonControl2`; the repair action |
| Lockout source tracing on the DC | Done: `lockouts` / `query-lockouts` (exact allowlisted DC) | — |
| Per-percent WUA download progress | Open | All of it |
| Flatpak / Snap / more OEMs | Open | All of it |
| `--fail-on-crit` compliance exit code | Open | All of it |
| `wifi-drop` and `call-quality` runbooks | Open | All of it |

---

## Part 5: The ideas

### 1. "Why won't this app run?" policy-block explainer (`sec.blocks`)

**Type:** new read-only module · Security · Windows + Linux

**Why it fits:** `sec.posture` reports whether Defender, the firewall and Secure
Boot are on. But tickets like "the Dragon plugin won't launch" or "Save to
Documents fails" usually come from one specific block event, not from a posture
setting. Today nothing in ITriage names the rule that blocked the user.

**How to build it:**
- Query the last 7 days (the same window as `system.changes`) through the existing
  event-log wrapper and `parse::evtxml`:
  - `Microsoft-Windows-Windows Defender/Operational`:
    - 1121 / 1122: ASR rule block / audit
    - 1123 / 1124: Controlled Folder Access block / audit
    - 1116 / 1117: detection / action taken
  - `Microsoft-Windows-AppLocker/EXE and DLL`: 8004 blocked, 8003 audit
  - `Microsoft-Windows-AppLocker/MSI and Script`: 8007 blocked, 8006 audit
  - `Microsoft-Windows-CodeIntegrity/Operational`: 3077 WDAC enforced block, 3076 audit
- Add a pure table, `parse/asr.rs`, that maps ASR rule GUIDs to friendly names.
  **Copy the table from Microsoft's "Attack surface reduction rules reference"
  page; don't type it from memory.** Add a test that GUIDs are unique and lowercase.
- Group the findings by (rule, path), with a count and first/last seen time:
  - Crit: an enforced block in the last 24 h on a path that matches a
    `[[require.app]]` or the app the technician named
  - Warn: any other enforced block
  - Info: audit-only events
- Add a "Policy block" kind to `kind_of()` in `investigate/timeline.rs`, so
  `--problem-at` lines blocks up with the reported time.
- Add a branch to the `slow-app` runbook in `investigate/guided.rs`. Add an
  `insight.rs` rule: "Blocked by ASR rule '<name>' 3× today".
- **Linux:** parse AppArmor `apparmor="DENIED"` and SELinux AVC denials from the
  kernel/audit journal into the same finding shape.
- **Privacy:** blocked paths contain usernames, so run them through bundle redaction.

**Lab check:** On the Windows 11 VM, enable one ASR rule with
`Set-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Enabled`,
turn on Controlled Folder Access, and trigger each one. Then add an AppLocker
path rule and run a blocked exe. On Ubuntu, put a profile in enforce mode and
trigger a denial.

---

### 2. Sign-in duration waterfall (`desk.logon`)

**Type:** new read-only module · Workstation · Windows

**Why it fits:** "Please wait for the Group Policy Client" is one of the most
common slow-sign-in tickets in hospitals. `timeline.rs` already collects
GroupPolicy events 8000/8001, but only as start and end markers. Nothing says
*which* part of sign-in was slow.

**How to build it:**
- `Microsoft-Windows-GroupPolicy/Operational`:
  - 4001 → 8001: user policy start/end (8001 carries the total elapsed time)
  - 4000 → 8000: computer policy start/end
  - 5016: one client-side extension (CSE) finished, with its elapsed ms
  - 6016 / 7016: a CSE finished with a warning / an error
  - 5312 / 5313: applied / filtered-out GPO lists
- System log, GroupPolicy provider:
  - 1129: no connectivity to a DC
  - 1058: couldn't read `gpt.ini` (a SYSVOL/DFS problem)
- `Microsoft-Windows-User Profile Service/Operational`: event 1 (logon notification
  received) → event 2 (finished), which gives the profile load time.
- Group the events of one processing cycle by their **ActivityID**.
- Write a pure parser, `parse/gplogon.rs`, that returns
  `Waterfall { phases: Vec<Phase>, total_ms }`. Take field names from a captured
  fixture. Some of Microsoft's GP field names are misspelled ("Elasped"), so trust
  the capture, not the docs.
- Findings:
  - the total sign-in time as a metric (so `--trends` tracks it)
  - the three slowest CSEs
  - failures
  - the GPO count
- Add a `Thresholds` band, `logon_seconds` (default warn 60, crit 120).
- Add an `insight.rs` rule: "Folder Redirection took 41 s of a 58 s sign-in."
- Add to the `sign-in` runbook. Reuse `timeline.rs`'s GroupPolicy query; don't
  duplicate it.

**Lab check:** On the Windows 11 VM joined to GOAD, link a GPO with a logon script
that runs `Start-Sleep 30`, sign out and back in, and confirm the waterfall points
at the Scripts CSE. Then remove the DC from DNS to provoke 1129.

---

### 3. Throttling and hardware errors (`system.hardware`)

**Type:** new read-only module plus a telemetry addition · System · Windows + Linux

**Why it fits:** a "slow" docked laptop is often limited by firmware, from the
wrong power brick or from heat. The CPU shows 100% while running at 40% of its
clock speed. The flight recorder would then blame whichever process happens to
be busiest.

**How to build it:**
- Windows System log:
  - `Microsoft-Windows-Kernel-Processor-Power` event 37: processor speed limited
    by firmware, including the number of seconds it was limited
  - `Microsoft-Windows-WHEA-Logger` 17 / 18 / 19 / 47: corrected PCIe / fatal /
    corrected machine-check / corrected memory errors. Confirm the mapping
    against Microsoft's docs when writing the fixtures.
- Telemetry: add the PDH counter `\Processor Information(_Total)\% of Maximum Frequency`
  to `telemetry::Sampler` (the PDH wrapper already exists). The HUD and flight
  samples then carry clock %.
- Linux:
  - `/sys/devices/system/cpu/cpu*/thermal_throttle/{core,package}_throttle_count`
  - `cpufreq/scaling_cur_freq` against `cpuinfo_max_freq`
  - EDAC `/sys/devices/system/edac/mc/mc*/{ce_count,ue_count}`
- `hypotheses.rs`: high CPU plus low clock % (or event 37 inside the window)
  becomes a "firmware/thermal throttling" candidate, and *contradicts* "a process
  is hogging the CPU".
- Add to the `slow-pc` runbook and the `health` preset. When the PC is on AC
  power (`desk.battery`) and event 37 keeps recurring, hint: "check the adapter
  wattage or the dock".

**Lab check:** VMs don't throttle, so build it from fixture XML. Validate on a real
laptop on battery or a weak charger while it's under CPU load.

---

### 4. Certificate revocation reachability (extends `desk.certs`)

**Type:** extension of a read-only module · Workstation · Windows (Linux later)

**Why it fits:** an expired CRL on the issuing CA quietly breaks EAP-TLS,
smart-card sign-in and VPN for the whole fleet at once. It's the classic "nobody
can get on the network at 7 a.m." outage. CryptoAPI caches CRLs, so a chain build
can still pass on a cached CRL while the distribution point is already down.

**How to build it:**
- For every certificate `desk.certs` already evaluates, call `CryptGetObjectUrl`
  with:
  - `URL_OID_CERTIFICATE_CRL_DIST_POINT`
  - `URL_OID_CERTIFICATE_OCSP`
  - `URL_OID_CERTIFICATE_ISSUER`
- Fetch HTTP(S) URLs with the existing WinHTTP wrapper, which uses the same
  proxy logic as `net.proxy`. For LDAP CDP URLs, report "checked by chain build
  only"; don't hand-roll LDAP.
- Parse each CRL with `CertCreateCRLContext` and read `ThisUpdate` / `NextUpdate`:
  - Crit: `NextUpdate` has passed
  - Warn: within `[security] crl_warn_hours` (new key, default 24)
- Also run `CertGetCertificateChain` with
  `CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`, and report
  `CERT_TRUST_IS_REVOKED`, `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` and
  `CERT_TRUST_IS_OFFLINE_REVOCATION`. Show both results: the live fetch and the
  cached chain.
- `hypotheses.rs`: an 802.1X failure (`net.wifi-auth`, later `net.wired-auth`)
  plus "revocation unknown" makes a strong candidate.
- Cargo: the `Win32_Security_Cryptography` feature (probably already on for
  `desk.certs`).
- Linux later would need the `x509-parser` crate. That's a new dependency, so ask
  first.

**Lab check:** Use the GOAD ADCS CA (Web Enrollment gives it an HTTP CDP). Enroll
the Windows 11 VM for a machine cert. On the CA, shorten the CRL period
(`certutil -setreg CA\CRLPeriodUnits 1`, `CRLPeriod Hours`), publish, then block
HTTP to the CDP. Confirm that "unreachable" is reported now and "expired" after
`NextUpdate`.

---

### 5. Kerberos ticket cache and a purge fix (`desk.identity`)

**Type:** extension plus a new fix `purge-kerberos-tickets` · Workstation · Windows + Linux

**Why it fits:** "the file share keeps asking for my password" after a password
change or a PC rename. RC4 tickets are also becoming a risk as Microsoft phases
RC4 out of Kerberos on domain controllers. The package doesn't include
`desk.identity`'s source, so **read it first** and only add what's missing.

**How to build it:**
- **Run it in the signed-in user's own logon session.** A UAC-elevated token has
  a different logon session and sees different tickets (that's why `klist` differs
  in an admin prompt). Collect it the same way `app.paths` collects the running
  user's proxy/PAC context.
- `LsaConnectUntrusted` → `LsaLookupAuthenticationPackage("Kerberos")` →
  `LsaCallAuthenticationPackage(KerbQueryTicketCacheExMessage, LogonId = 0)`.
  From each `KERB_TICKET_CACHE_INFO_EX`, report:
  - client and server (the SPN)
  - EncryptionType
  - start, end and renew times
  - flags
- Findings:
  - TGT present, and its expiry
  - service tickets using RC4 (etype 23): Warn
  - the KDC
  - the ticket count
- System log `Microsoft-Windows-Security-Kerberos` event 4
  (`KRB_AP_ERR_MODIFIED`) is Crit, with the server name. It means a duplicate SPN
  or a stale computer-account password.
- `insight.rs`: if `desk.time`'s offset is over 5 minutes (the default Kerberos
  tolerance), say so.
- **Fix `purge-kerberos-tickets`:** `KerbPurgeTicketCacheMessage` for the current
  session. It's mutating but not disruptive. Map it to `desk.identity` in
  `advanced/cases.rs`.
- **Linux:** parse `klist -e` (MIT Kerberos) for the user's ccache.
- Cargo: the `Win32_Security_Authentication_Identity` feature.

**Lab check:** On the Windows 11 VM, as a GOAD domain user, open `\\<dc>\SYSVOL`
and confirm tickets are listed. Register the same SPN on a second account
(`setspn -A`; note that `-S` refuses duplicates) to provoke event 4. Then run the
purge fix and re-verify.

---

### 6. ITriage's own actions to the Event Log / journald, with a hash-chained audit

**Type:** platform feature (`audit.rs`, installer) · Windows + Linux

**Why it fits:** ITriage runs elevated and changes machines. Sending every change
to the OS log makes it visible to WEF, Splunk or Sentinel with no new agent, and
it's a strong blue-team story for the project.

**How to build it:**
- **Installer:** the Tauri bundler's NSIS/WiX hook creates
  `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\ITriage`, with
  `EventMessageFile` and `TypesSupported`. This needs admin rights, so it belongs
  in the installer, not at runtime.
- **Message table:** compile a small `.mc` file into `itriage.exe` at build time,
  and point `EventMessageFile` at the exe. `embed-resource` would be a build
  dependency only, not a runtime one.
- **Runtime:** from `audit::module_ran` and the fix path, call
  `RegisterEventSourceW(None, "ITriage")` and then `ReportEventW`.
  - Suggested IDs:
    - 1000: module changed the machine
    - 1001: fix ran
    - 1002: fix refused by policy
    - 1003: verified-repair outcome
  - Fields: ticket, run-as account, elevated?, module/fix ID, outcome.
  - If the source isn't registered, record a gap; don't fail.
- **Hash chain:** each line in the local audit file carries `prev = SHA-256(previous line)`
  (`sha2` is already in the tree). Add `itriage --verify-audit` to check the chain.
- **Linux:** `libc::syslog` with ident `itriage`; journald picks it up.
- Profile: `[audit] event_log = true` (default on; it's only a local log).

**Lab check:** Run a fix on the Windows 11 VM and confirm it in Event Viewer. Edit
one line of the audit file and confirm that `--verify-audit` fails. Optionally,
forward the events to a lab SIEM and screenshot them for a post.

---

### 7. Outlook / Teams / OneDrive health (`desk.m365`) and a `clear-teams-cache` fix

**Type:** new module plus a user-scope fix · Workstation · Windows

**Why it fits:** these are very common Tier 1 calls. `site.apps` can confirm that
Office is installed, but nothing looks inside it.

**How to build it:**
- **Read the signed-in user's hive** (`HKEY_USERS\<SID>`), using the SID that
  `desk.account` already resolves with `win::session::sid_of`. An elevated
  technician account would otherwise read its own HKCU.
- **Outlook:**
  - Report the sizes of `*.ost` files under `%LOCALAPPDATA%\Microsoft\Outlook` and
    of PSTs in the usual places.
  - Compare them with `MaxLargeFileSize` / `WarnLargeFileSize` from policy, or the
    defaults: 51200 MB / 48640 MB.
- **Click-to-Run:** read `HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration`
  (`VersionToReport`, `UpdateChannel`/`CDNBaseUrl`, `Platform`). Map the channel
  with a pure table copied from Microsoft's docs. Compare the version with
  `site.apps`' `min_version` when Office is required.
- **OneDrive:**
  - Check whether `Desktop`, `Personal` (Documents) and `My Pictures` under
    `...\Explorer\User Shell Folders` point inside the OneDrive folder
    (`HKCU\Software\Microsoft\OneDrive\Accounts\Business1\UserFolder`).
  - Check whether `OneDrive.exe` is running in the user's session.
  - Warn when folders are redirected but OneDrive isn't running, because nothing
    is syncing.
- **Teams:** report the size of the new Teams cache under
  `%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache`. Report leftover
  classic-Teams folders as Info.
- **Sign-in broker:** errors in `Microsoft-Windows-AAD/Operational` over the last
  24 h (the "Need password" loop), and whether `Microsoft.AAD.BrokerPlugin` is
  present. Give a KB link only; no auto-fix, because re-registering it is fragile.
- **Fix `clear-teams-cache`:**
  - user scope
  - **refuses while `ms-teams.exe` is running**
  - the preview shows the size that would be freed
  - clears the folder Microsoft documents for resetting the new Teams cache
    (confirm the current path in Microsoft's Teams docs)
  - audited, and in the `advanced/cases.rs` map

**Lab check:** Without a tenant, use fixtures plus a fake large `.ost` file and a
redirected Documents folder on the Windows 11 VM. Validate against a real Office
install when you have one.

---

### 8. Edge IE-mode Enterprise Site List health (`desk.browser`)

**Type:** new read-only module · Workstation · Windows

**Why it fits:** older clinical and departmental web apps often only work in IE
mode. If the site list is stale, unreachable or missing an entry, they break for
every user at once, and it looks like an application outage.

**How to build it:**
- Read the policies `InternetExplorerIntegrationLevel` and
  `InternetExplorerIntegrationSiteList` under
  `HKLM\SOFTWARE\Policies\Microsoft\Edge` (and the user's hive).
- Fetch the list:
  - HTTP(S) through the WinHTTP wrapper, with the same proxy behavior
  - UNC or file paths with `std::fs`
- Write a pure parser, `parse/sitelist.rs`, for the v2 schema:
  `<site-list version="N">` containing `<site url="…">` entries with
  `<compat-mode>` and `<open-in>`. For the legacy v1 schema, report the version
  and mark it as legacy.
- Findings:
  - policy configured?
  - list reachable?
  - list version, entry count and fetch time
  - Edge version (the `msedge.exe` file version)
- For each `[[require.application]]` URL and the `--target`, do a longest-match
  lookup and report "opens in IE mode" or "opens in Edge".

**Lab check:** Put a site list XML on a GOAD share, set the policy with local GPO
on the Windows 11 VM, and test it reachable, unreachable and with a URL missing.

---

### 9. Point and Print restrictions (extends `print.path`)

**Type:** extension of a read-only module · Workstation · Windows

**Why it fits:** since the PrintNightmare hardening, "adding the ward printer asks
for admin" is a daily ticket. `print.path` sees drivers, ports and the server,
but not the policy that blocks the driver install.

**How to build it:**
- Read `HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint`:
  - `RestrictDriverInstallationToAdministrators`
  - `Restricted`
  - `TrustedServers` / `ServerList`
  - `NoWarningNoElevationOnInstall`
  - `UpdatePromptSettings`
- Read `...\Printers\PackagePointAndPrint`: `PackagePointAndPrintServerList` and
  the `ListofServers` subkey.
- Compare against the `Server` field `print.path` already collects. Flag:
  - "this print server isn't in the approved list, so a standard user will be
    asked for admin"
  - a non-package-aware driver when package-only is enforced
- On Windows 11 24H2 and later, detect **Windows protected print mode** through
  its Group Policy value (confirm the exact value name on a 24H2 machine). Flag it
  when the printer needs a third-party driver.

**Lab check:** Share a printer from a GOAD server. On the Windows 11 VM set
`RestrictDriverInstallationToAdministrators=1`, connect as a standard user, then
add the server to the approved list and compare.

---

### 10. Peripheral drop tracking and USB power settings (extends `desk.devices` and the recorder)

**Type:** extension plus an optional fix `keep-usb-awake` · Workstation · Windows + Linux

**Why it fits:** barcode scanners for medication administration, badge readers,
signature pads and label printers drop out mid-shift. The profile already has
`[[require.device]]` match patterns, which can be reused.

**How to build it:**
- **During `--record` and flight captures:** register `CM_Register_Notification`
  (device-interface arrival/removal) on Windows, or a udev netlink monitor on
  Linux, for devices matching `[[require.device]]`. Timestamp each removal and
  arrival as a marker in the capture.
- **Static checks** (skip any that `desk.devices` already does):
  - the device problem code (`CM_Get_DevNode_Status`; the SetupAPI wrapper exists)
  - **USB selective suspend** in the active power plan: `PowerGetActiveScheme` →
    `PowerReadACValueIndex` / `PowerReadDCValueIndex`, subgroup
    `2a737441-1930-4402-8d77-b2bebba308a3`, setting
    `48e6b7a6-50f5-4782-a5d4-53bb8f07e226`
  - per device: `EnhancedPowerManagementEnabled`, `AllowIdleIrpInD3` and
    `SelectiveSuspendEnabled` under
    `HKLM\SYSTEM\CurrentControlSet\Enum\USB\<id>\<instance>\Device Parameters`
- **Optional fix `keep-usb-awake`** (the profile must allowlist it):
  - turns selective suspend off in the active scheme
    (`PowerWriteACValueIndex` + `PowerSetActiveScheme`)
  - stores the previous values for revert, following the `revert-tuneup` pattern
  - preview note: a GPO-managed power plan may override it
- Add to the `call-quality` runbook once it exists.

**Lab check:** Pass a USB device (a mouse is fine) through to the VM, start a
recording, then unplug and replug it. Confirm both markers appear.

---

### 11. Wired 802.1X and NAC quarantine detection (`net.wired-auth`)

**Type:** new read-only module · Network · Windows

**Why it fits:** `net.wifi-auth` covers wireless, but nothing covers PCs on wall
jacks behind ISE or ClearPass. A PC that NAC put in a remediation VLAN looks like
"the network works but nothing loads".

**How to build it:**
- Check the `dot3svc` (Wired AutoConfig) service state through the SCM wrapper.
- **Primary evidence:** the `Microsoft-Windows-Wired-AutoConfig/Operational` log.
  Event 15514 is a failed authentication, with the reason and root cause. Capture
  real success and failure fixtures to pin down the other IDs in the 155xx range.
- **Secondary evidence:** `netsh lan show interfaces`, through a pure parser.
  **netsh output is localized**, so treat it as best-effort and keep the events as
  the source of truth.
- New profile key: `[network] quarantine_subnets = ["10.250.0.0/16"]` (default
  empty). It's Crit when the wired adapter's address falls inside one: "NAC placed
  this PC in a remediation VLAN — check ISE/ClearPass for the posture failure."
- `hypotheses.rs`: a 15514 with a certificate reason, plus a `desk.certs`
  revocation finding (#4), makes a strong candidate.
- Add to the `triage` preset when the active route is wired.

**Lab check:** Start with fixtures. For live testing you need an 802.1X-capable
switch, or a Linux box running `hostapd` with `driver=wired` and FreeRADIUS as a
lab authenticator.

---

### 12. Linux domain-join parity (`desk.domain` on Linux)

**Type:** extension of a module, Linux branch · Workstation · Linux

**Why it fits:** it brings the Linux side closer to Windows. Its counterpart to
`domain.trust` is a read-only machine-account test.

**How to build it:** (pure parsers for each tool's output)
- `realm list`: configured realm, client software, login formats.
- `sssctl domain-status <domain>`: online/offline and the active server. This
  needs SSSD's InfoPipe responder on some distros; report a gap if it's missing.
- `adcli testjoin`: read-only machine-account check (needs root).
- `klist -k /etc/krb5.keytab`: principals and KVNO (needs root).
- Check that `/etc/sssd/sssd.conf` is mode 0600 and owned by root (SSSD won't
  start otherwise).
- The `sssd` service state comes from the existing `proc.services`. Clock skew
  comes from `desk.time`.

**Lab check:** On an Ubuntu VM, run `realm join north.sevenkingdoms.local` against
GOAD. Then break it on purpose: `chmod 644 sssd.conf`, stop the DC, and reset the
computer password on the DC so `adcli testjoin` fails.

---

### 13. Unattended intermittent-issue watch mode (`--watch`)

**Type:** workflow feature on top of `advanced/flight.rs` · Windows + Linux

**Why it fits:** for "it froze around 2 yesterday." The flight recorder only
captures when someone presses the marker.

**How to build it:**
- New profile keys, **off by default**:
  ```toml
  [advanced]
  watch = false
  watch_max_mb = 200
  watch_keep_days = 7
  watch_triggers = ["cpu", "gateway_loss", "app_paths", "app_hang"]
  ```
- `itriage --install-watch` (admin, audited) creates a scheduled task that runs
  **as the signed-in user at logon**, at below-normal priority. On Linux it's a
  systemd user unit. Add a matching `--uninstall-watch`.
- Reuse the flight ring buffer. Save a capture automatically when:
  - a `Thresholds` band stays crossed for N seconds
  - a required `app.paths` URL fails
  - `EvtSubscribe` sees Application Hang 1002 or Application Error 1000
- Debounce to one capture per 15 minutes. Enforce the disk quota and retention.
- Save captures through `report::save` with role `watch`, so `--timeline
  --problem-at` and history line them up.
- Every capture includes a privacy notice row.

**Lab check:** On the Windows 11 VM, cross the CPU band with a busy-loop script,
then disconnect the VM's network to trip gateway loss. Check the quota and
retention by lowering `watch_max_mb`.

---

### 14. Major-incident awareness feed

**Type:** profile and report feature · Windows + Linux

**Why it fits:** during an outage, technicians each troubleshoot their own caller
from scratch. ITriage could say "this matches a known incident" in the first ten
seconds.

**How to build it:**
- New profile section, **honored only from a managed profile**, so a user can't
  point it at a fake banner:
  ```toml
  [status]
  url = "https://itstatus.example.org/itriage.json"
  timeout_ms = 2000
  ```
- JSON format:
  ```json
  { "updated": "2026-11-12T13:05:00Z",
    "incidents": [ { "id": "INC0012345", "title": "VPN gateway outage",
      "module": "net.target", "match": "vpn\\.example\\.org",
      "subnets": ["10.20.0.0/16"], "url": "https://..." } ] }
  ```
- Match findings with the same module-plus-regex logic `KbRule` already uses.
- HTTPS only, with a short timeout and one fetch per run. If the fetch fails,
  record a silent Info gap.
- Add a defaulted `known_incidents` field to `Report`. Show a technician-view
  banner: "Matches known incident INC… — attach this report and stop
  troubleshooting". Include the line in the ticket summary from `render_text`.

**Lab check:** Serve the JSON over HTTPS from a GOAD IIS server, with a cert from
the GOAD CA. Make an incident's regex match a failing `--target` and confirm the
banner appears.

---

## Out of scope on purpose

Persistence hunting, autoruns and forensic collection are left out. They fit the
separate live-response tool better than ITriage, which stays focused on IT triage
and repair.
