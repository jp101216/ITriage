#!/usr/bin/env python3
"""Give a test account a real temporary profile on this Windows runner, then
check User profile & FSLogix reports it; and check Why updates fail and
Intune enrollment & apps read this PC's real history and enrollments.

The temporary profile is made the way it happens in the field: a program
holds the account's NTUSER.DAT open while Windows loads the profile. Windows
then logs 1508, 1545 (naming the program), 1502, 1515 and 1511, sets the
profile aside as <SID>.bak, and signs the account in with a temporary one.

Usage: check-profile.py COMMAND [ARG...]
  e.g. check-profile.py cargo run -q -p itriage-core --example triage --
"""
import json
import os
import re
import secrets
import subprocess
import sys

USER = "itrtempcheck"

# Load the profile once (so it exists), then again while this PowerShell
# holds NTUSER.DAT open with no sharing.
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$sec = ConvertTo-SecureString $env:ITR_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:ITR_USER, $sec)
Start-Process cmd.exe -ArgumentList '/c','exit' -Credential $cred -LoadUserProfile -Wait -WorkingDirectory C:\ -WindowStyle Hidden
Start-Sleep 3
$dat = "C:\Users\$($env:ITR_USER)\NTUSER.DAT"
$lock = [System.IO.File]::Open($dat, 'Open', 'ReadWrite', 'None')
try {
  Start-Process cmd.exe -ArgumentList '/c','exit' -Credential $cred -LoadUserProfile -Wait -WorkingDirectory C:\ -WindowStyle Hidden
  Start-Sleep 3
} finally { $lock.Close() }
"""

# module -> label -> (severity, pattern the value must match, pattern the detail must match)
EXPECT = {
    "desk.profile": {
        "Profiles set aside (.bak)": ("warning", USER, r"\.bak"),
        "Temporary-profile sign-ins (7 days)": ("warning", r"^(once|twice|\d+ times) · last ", USER),
        "Program holding a profile's registry file": ("warning", r"(?i)powershell\.exe", r"(?i)WindowsPowerShell"),
        "Profile load failures (7 days)": ("warning", r" · last ", r"(?i)ntuser\.dat"),
        "Signed-in profile": ("ok", r".", r""),
    },
    "update.history": {
        "Installs in the last 90 days": (None, r"(installed · \d+ failed|none recorded)", r""),
    },
    "desk.intune": {
        # A GitHub runner isn't managed by Intune; Windows' own built-in
        # enrollments mustn't be mistaken for it.
        "Intune enrollment": ("info", r"^not enrolled", r""),
    },
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def main():
    command = sys.argv[1:]
    password = "Itr!" + secrets.token_hex(8) + "aA9"
    made = run(["net", "user", USER, password, "/add", "/y"])
    if made.returncode != 0:
        print(f"::error::couldn't create {USER}: {made.stdout} {made.stderr}")
        return 1
    load = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", SCRIPT], env={**os.environ, "ITR_USER": USER, "ITR_PW": password})
    print(f"profile loads: exit {load.returncode} {load.stderr.strip()[:300]}")

    out = run(command + list(EXPECT) + ["--json", "--no-history", "--quiet"])
    if out.returncode not in (0, 2):
        print(f"::error::exit {out.returncode}: {out.stderr}")
        return 1
    report = json.loads(out.stdout)
    bad = []
    for module, rows in EXPECT.items():
        result = next((r for r in report["results"] if r["module_id"] == module), None)
        if result is None or result.get("error"):
            bad.append(f"{module}: {'missing' if result is None else result['error']}")
            continue
        found = {f["label"]: f for f in result["findings"]}
        for label, (severity, value, detail) in rows.items():
            row = found.get(label)
            if row is None:
                bad.append(f"{module} · {label}: missing (got {sorted(found)})")
            elif (severity and row["severity"] != severity) or not re.search(value, row["value"]) or not re.search(detail, row.get("detail") or ""):
                bad.append(f"{module} · {label}: {row['severity']} · {row['value']} · {row.get('detail')}")
            else:
                print(f"ok  {module} · {label}: {row['severity']} · {row['value']}")
        print(f"    {module}: {result['summary']}")
    if bad:
        for b in bad:
            print(f"::error::{b}")
        return 1
    print("User profile, update history and Intune checks: all came out as expected against real Windows state")
    return 0


if __name__ == "__main__":
    sys.exit(main())
