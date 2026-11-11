# Investigation cases

These workflows are available in the technician view. The desktop and CLI use
the same Rust engine. They inspect evidence; they never automatically run a
repair, enable event logging, start a packet trace, or upload a bundle.

## Application connection checks

Add endpoints to an administrator-managed site profile. Choose a health URL
whose GET is appropriate for diagnostics; ITriage supplies no credentials,
cookies or request body and does not follow redirects.

```toml
name = "Clinical workstations"
role = "clinical-workstation"

[[require.application]]
label = "Clinical portal"
url = "https://portal.example.org/health" # replace this placeholder
expected_status = [200, 401]
timeout_ms = 8000
slow_ms = 2000
```

Only absolute HTTP/HTTPS URLs are accepted, with no embedded credentials or
fragment. Query strings are sent when configured but omitted from diagnostic
URL labels/logs. Avoid secrets in URLs and labels. A 401 or 403 proves an
authentication response, not an unreachable server; declare the expected
statuses for the chosen endpoint. A TLS success means the client's chain and
hostname checks passed, not that the endpoint or application is secure.

DNS resolution is bounded to three seconds; direct TCP shares a 750 ms budget
across resolved addresses. A direct failure is informational because a proxy
may still reach the application. At most 16 URLs run, one at a time, with
cancellation checked between endpoints. HTTP timeouts are bounded to 500–15000
ms (per WinHTTP phase on Windows; total transfer on Linux). First-response
timing includes proxy discovery, connection and TLS; it is not server-only time.

Windows uses WinHTTP automatic proxy discovery under the account running
ITriage, with automatic authentication, cookies and redirects disabled. The
signed-in user's proxy/PAC configuration is displayed separately. This does
not reproduce browser SSO, PAC behavior or proxy authentication in every user
context. Linux needs `curl`, ignores curlrc, validates TLS normally and uses
the process's proxy environment. It reads no credential store and retains no
response body. Configured site URLs remain explicit site probes even when
automatic public probes are disabled.

## Intermittent recordings

Use **Record issue**, choose 5–1800 seconds and a 1–10 second interval, optionally
set a TCP target, then reproduce the failure. **Problem happened now** adds a
timestamped note (100 markers maximum, 200 characters each). **Stop recording**
or the main run button stops at a safe point and retains completed samples.
Closing the recording dialog leaves collection running; the main Stop control
remains available. Normal window-close protection still waits for safe completion.

Recordings retain at most 1800 samples: whole-system CPU/RAM, disk and network
byte rates, short TCP connection results, DNS results and available Wi-Fi state.
TCP has a 250 ms budget per sample. DNS and Wi-Fi are sampled every fifth
sample; intervening Wi-Fi values carry the last observation. Slow collection
can leave gaps and does not generate catch-up bursts. The target is resolved
once at the start; a DNS answer change during a recording is not tracked.
Probe scheduling and the host's tools determine the actual cadence.

CPU load and the disk and network rates are differences between two readings,
so the first sample is taken an interval (a second at most) after the counters
are first read: every sample, the first included, covers a real stretch of
time. (0.8.0 took its first sample at once; its CPU figure was made up, could
be reported as the recording's peak, and its disk and network rates were
zero.)

Each Wi-Fi reading keeps the signal and the access point's address (BSSID)
beside the description. A different address on the same network is a move to
another access point; the recording's result counts them ("signal 41–72% ·
moved between access points 2 times"). Wi-Fi is read every fifth sample, so
two quick moves between readings count once, and a weak signal or a move at
the moment of a marker is worth a look, not a verdict. Windows 11 24H2 and
later withhold the network name and address from apps without location
access; the signal still comes through.

An explicit target or profile target is used for TCP. Automatic public targets
and DNS names obey `[network] public_probes`; no configured target means that
part of the recording is unavailable, not successful. Wi-Fi reads existing
adapter state (native WLAN on Windows; `nmcli --rescan no` on Linux).
This is lightweight polling, not a trace of every CPU spike, packet or roam.

Recordings attach to the displayed report only when its hostname/platform match
this PC. Existing check timestamps still describe their original collection;
`recording.started` and each sample/marker describe the later capture.

**Replay recording** draws CPU, RAM and Wi-Fi signal over the capture, with a
numbered line at each marker, a mark where the PC moved access point, and a
mark under the axis at each failed connection or DNS probe; pointing at the
chart reads out the nearest sample. The table under it shows all samples (up
to 120 rows), the failed connections only, or the ten seconds around a marker.
Each marker is written against the first sample taken at or after it, in the
table and in `recording.csv`, which also has the Wi-Fi signal and access point
for each sample. Full JSON and case ZIPs retain all samples and markers.
A recording's peaks depend on how long it ran, so they aren't followed in
Trends. CLI example:

```sh
itriage --record 60 --interval-ms 1000 --target appserver:443 --ticket INC123 --out recording.json
```

Interactive markers are a desktop feature. The CLI writes the bounded capture
when its duration completes. No process command lines, packet bodies,
screenshots or authentication tokens are collected by the recorder.

## Identity and network authentication

`desk.identity` is Windows-only and allowlists diagnostic fields from
`dsregcmd /status`; device IDs, key-container IDs and tokens are not retained.
Device authentication requires online Entra access. When automatic public
probes are disabled, the cloud query is skipped explicitly; local account and
domain checks remain available. PRT/WAM/Hello fields are graded only when
ITriage is unelevated and its account matches the running Windows session.
An administrator's absent PRT does not establish an affected user's failure.
Missing/NO Hello or WAM state can be intentional. Shared-PC diagnostic attempts
may belong to another user; inspect the reported identity and evidence.

`net.wifi-auth` reads existing WLAN-AutoConfig, Wired-AutoConfig, EapHost and
CAPI2 channels on Windows (last 24 hours, up to 40 recent events per channel,
80 summarized event rows). Each row is the event as Windows words it
("WLAN AutoConfig service has successfully connected to a wireless network."),
labelled with its time and a short name for its log (`Wi-Fi 8001`,
`Wired 802.1X`, `EAP`, `Certificates`); the reason fields are underneath.
Failed connections, associations and 802.1X authentications are flagged
whatever level they were logged at. When someone has switched the CAPI2 log
on, it records every certificate check on the PC, so only its failures are
read. Disabled or inaccessible logs remain coverage gaps; no logs are
enabled. Some event formats have no supported reason fields; their
timestamp/provider/ID still identify the source event to inspect.
Linux reads up to 160 recent NetworkManager / wpa_supplicant journal entries
from 24 hours and retains matching authentication/roaming/certificate messages.
It needs journal permissions and the relevant services' existing logging.

Association/disconnect counts are counts of collected events, not an exhaustive
roaming audit. A disconnect, roam or certificate event alone does not prove an
802.1X fault. Match time, connection identity and reason evidence.

## Changes near the problem's onset

`system.changes` reads seven days of Windows update, installer, driver,
service-configuration, policy and restart activity. Each kind has its own
query (the most recent 32 to 64 events of it), so a week of one kind can't
push the others out of what is read:

| Kind | From |
|---|---|
| Windows update | Windows Update's installs, failures and restart requests (System log), and package changes in the Setup log |
| Application installer | Windows Installer: installed, removed, updated, restart needed, and its errors |
| Driver or device | driver installations (UserPnp) and drivers that failed to load |
| Service configuration | a service installed, or its start type changed (BITS switching itself between automatic and manual is left out) |
| Group Policy | computer policy at startup and user policy at sign-in, with how long each took, and policy errors; not every background refresh |
| Restart, Unexpected shutdown | who or what asked for a restart and why, each start of Windows, and starts that followed a crash or power loss |

Rows are sentences: "Installed Contoso Client 24.2.0.187", "Service Print
Spooler: start type changed from auto start to disabled", "Restart started by
winlogon.exe for NT AUTHORITY\SYSTEM: Operating System: Upgrade (Planned)".
An event ITriage has no sentence for is shown as Windows words it, and its
fields are underneath either way. Times are UTC to the second.

A burst of one kind (a cumulative update's packages, one `apt install`) is
folded into one row: "40 events until 12:03:57: …; and 37 more". The row is
filed at the burst's start and matches an onset search anywhere in its span.
A burst is at least four events no more than two minutes apart, and is cut
off after thirty minutes. Up to 200 rows are kept.

Linux uses the last 2 MiB of the current dpkg log ("Upgraded curl 8.0 → 8.1"),
available package-service journal entries, and the start that is still
running. Rotated logs and other package managers can leave gaps. dpkg's local
times use the host's time zone conversion.

**Timeline** combines collected changes and network-authentication events.
**Collect change and network-authentication history** refreshes those checks in
this PC's displayed case while retaining its recording, markers and earlier
findings. Use it after reproducing a problem to include post-incident logs in
the same bundle. The original case creation time remains; `evidence_updated`
records the later collection. Local evidence cannot be appended to another
PC's report. A failed refresh preserves the existing case.
History orders and retains these snapshots by their latest evidence update.
Copied performance findings in a case snapshot are not counted as new trend
measurements or automatically chosen as a previous diagnostic run.
Enter the onset in local time and a 15-minute, 1-hour or 24-hour window either
side, or choose **Everything collected**. The table shows each row's local
time, where it sits against the onset ("12 min before"), its kind, what
happened and the evidence. Missing events do not rule out a change; log
retention, privilege and collection limits apply. Installer activity is not
proof of installation success, and temporal proximity is not causation.

A card for either history check shows its newest twelve event rows and folds
the rest behind "Show N older event rows". The ticket text, Markdown and rich
text exports keep the newest eight and say how many they left out; anything
flagged is always kept. The full transcript, the JSON report and a case
bundle keep every row.

```sh
itriage system.changes net.wifi-auth --out changes.json
itriage --timeline changes.json --problem-at 2026-11-10T12:30:00Z
```

The CLI onset must be an actual UTC time ending in `Z`; it uses a one-hour
window. The desktop converts the local input to UTC before querying.

## Working-PC baselines

Run configuration checks on a known-working and affected PC, using the same
site profile and top-level `role`, then import the working PC's JSON through
**Open**. Display the affected report, select **Working PC**, and choose the
known-working report in History. Different platforms, cancelled reports and
explicitly mismatched roles are refused. Missing roles/profiles are visible
comparison caveats, not silently assumed matches.

Configuration observations include OS/model/BIOS, required app versions,
selected service/site requirements, device and security posture, the proxy
settings (machine-wide and the signed-in user's, compared without the account
name), where the clock comes from and its time zone, and the domain and AD
site. Unique identifiers, addresses and live metrics are excluded.

The picker lists reports from other PCs only: a PC isn't its own working
example. With none imported, the dialog says how to bring one in. The
comparison is shown on the report, and its differences are named in every
text export. Only observed findings
are compared: "not observed" does not mean a component is missing. The working
baseline and current-PC direction is explicit, independent of report age.

```sh
itriage --baseline working-pc.json affected-pc.json --out baseline.json
```

The attached comparison is included in JSON and case exports. Original saved
reports stay available for audit. This is configuration drift evidence, not a
hardware compatibility checker or automatic proof of the incident's cause.

## Guided symptom workflows

**Troubleshoot** offers `printing`, `vpn`, `sign-in`, `slow-app` and
`slow-pc`. Each starts with checks closest to the symptom, then selects
related site/network, identity or change checks. Printing and sign-in branch
on problem/unavailable results; VPN and slow-app also check configured
application dependencies. `slow-pc` looks at load, memory, free space and
startup speed, then at the drive's health and recent changes; it adds up
what's using the space (which takes up to 25 seconds) only when the disk is
the problem.
Plans contain fixed read-only module IDs, not generated shell commands.
Every phase and its reason are kept in the report. Unavailable evidence stays
unavailable. Cancellation retains completed checks and an incomplete trace.

```sh
itriage --runbook vpn --target appserver:443 --ticket INC123 --out vpn.json
```

Configure application URLs and site dependencies to make these workflows
specific to the environment. Finishing a runbook means its planned checks
finished; it does not mean the user's problem was fixed. Existing offered
repairs still use policy checks and confirmation. No repair is run automatically.

## Escalation bundles and privacy

**Case bundle** freezes the displayed report, excludes logs by default and
offers consistent pseudonyms plus up to 100 extra privacy terms. Preview
lists filenames, sizes and SHA-256 digests and lets the technician inspect the
exact contents of every file. Changing options invalidates the preview.
Export writes a new local ZIP under ITriage's data folder, `cases/`, and
offers **Open cases folder**. It never overwrites another case or uploads it.

Contents: `report.json`, ticket text, producer/exporter versions, `timeline.json`,
optional `recording.csv`, attached `baseline.json` / `runbook.json`, and
optional already-collected module logs. Full recording state and markers are
also in `report.json`. `manifest.json` hashes the evidence files;
`SHA256SUMS.txt` additionally hashes the manifest (neither recursively hashes
itself). ZIP CRC-32 supports archive validation. Limits are 20 MiB and 512
files, with deterministic fixed timestamps and safe generated filenames.

Pseudonyms cover these, consistently across every file:

| Replaced | With | Recognised by |
|---|---|---|
| This PC's name, a baseline PC's, the domain controller that signed it in | `[host-N]` | the report's own fields |
| Serial number | `[serial-N]` | its finding (a value like "not reported by the firmware" is left alone) |
| Account names, with or without their domain, and in `C:\Users\…` or `/home/…` paths | `[account-N]` | the signed-in user and account findings; `DOMAIN\user`, e-mail and home-folder shapes anywhere |
| The domain (`corp.example.org`, and `CORP` in `CORP\user`) and the AD site | `[domain-N]`, `[site-N]` | the Domain & Group Policy findings; the part before the backslash |
| Wi-Fi network names | `[network-N]` | the Wi-Fi check, Wi-Fi event fields (SSID, profile), a recording's samples |
| MAC addresses and access-point addresses | `[network-N]` | their shape |
| Certificate thumbprints | `[identifier-N]` | their finding |
| IP addresses | `[private-address-N]`, `[public-address-N]`, `[link-local-address-N]` | their shape |
| Extra privacy terms | `[custom-N]` | what you typed |

The same person is the same pseudonym with and without the domain, and in a
path: `CORP\jparker` becomes `[domain-1]\[account-1]`, and
`C:\Users\jparker` becomes `C:\Users\[account-1]`. An address keeps what
kind it is, so a report still shows that an adapter had a 169.254 address or
that the public IP differs from the gateway's.

Left readable on purpose: loopback and unspecified addresses, masks, the
public resolvers a check names itself (8.8.8.8, 1.1.1.1 and their pairs),
version numbers that look like addresses (`24.2.0.187`, and anything in the
app, update, driver and posture checks), Windows paths and registry keys,
built-in accounts (`NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`), and
generic names such as `Administrator`.

Free text, URLs, server names the site profile lists, organization names
outside the domain and unrecognized identifiers may still be sensitive:
**review every included file**. This is not a guarantee of anonymity. No pseudonym dictionary is
exported. Digests detect changes relative to the supplied manifest; they are
not a digital signature or independent proof of origin. Keep an original
report under your incident-handling procedures when needed.

```sh
itriage --bundle-preview recording.json --out preview.json
itriage --bundle recording.json --out case.zip
# Explicit options, after reviewing their effect:
itriage --bundle-preview recording.json --include-logs --no-redact
```

The CLI prints all previewed file contents; desktop review is usually easier.
No new event-log collection or arbitrary file attachments happen at export.
If evidence was not collected, collect its check first or record the gap.

## Platform references

- [Microsoft: interpreting dsregcmd status](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd)
- [Microsoft: WinHTTP option flags](https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags)
- [curl: command-line options and timing](https://curl.se/docs/manpage.html)
