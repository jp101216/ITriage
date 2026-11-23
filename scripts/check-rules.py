#!/usr/bin/env python3
"""Run Site custom checks for real against values every Windows machine has,
and check each one came out as expected. Exercises the registry reads (text,
expandable text as stored, a DWORD, a list), a file's version resource, an
event-log query that has to match real events, a service and a process.

Usage: check-rules.py COMMAND [ARG...]
  e.g. check-rules.py cargo run -q -p itriage-core --example triage --
"""
import json
import os
import re
import subprocess
import sys

PROFILE = r"""
name = "Custom checks smoke test"
[network]
public_probes = false

[[check]]
label = "text value"
kind = "registry"
key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
value = "ProductName"
contains = "windows"

[[check]]
label = "number value"
kind = "registry"
key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
value = "CurrentMajorVersionNumber"
min = 10

[[check]]
label = "list value"
kind = "registry"
key = 'HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder'
value = "List"
equals = "System Reserved"

[[check]]
label = "expandable value as stored"
kind = "registry"
key = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System'
value = "File"
contains = "%SystemRoot%"

[[check]]
label = "missing value"
kind = "registry"
key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
value = "NoSuchValueITriage"
exists = false

[[check]]
label = "file version"
kind = "file"
platform = "windows"
path = '%SystemRoot%\System32\kernel32.dll'
# Windows still stamps its system DLLs' file version 6.2 for compatibility.
min_version = "6.2"

[[check]]
label = "boot events"
kind = "event"
log = "System"
provider = "Microsoft-Windows-Kernel-General"
ids = [12, 13]
within_hours = 720
severity = "info"

[[check]]
label = "event log service"
kind = "service"
name = "EventLog"

[[check]]
label = "service host"
kind = "process"
platform = "windows"
name = "svchost.exe"
"""

# label -> (expected severity, pattern the value must match)
EXPECT = {
    "text value": ("ok", r"^ProductName = \"Windows"),
    "number value": ("ok", r"^CurrentMajorVersionNumber = 1\d "),
    "list value": ("ok", r"^List = \"System Reserved"),
    "expandable value as stored": ("ok", r"%SystemRoot%"),
    "missing value": ("ok", r"not set"),
    "file version": ("ok", r"^version 6\.2\.\d+\."),
    # The runner has started at least once in 30 days: the query must find it.
    "boot events": ("info", r"^\d+\+? in the last 30 days · 0 allowed"),
    "event log service": ("ok", r"running"),
    "service host": ("ok", r"^running"),
}


def main():
    command = sys.argv[1:]
    with open("rules-smoke.toml", "w", encoding="utf-8") as f:
        f.write(PROFILE)
    env = dict(os.environ, ITRIAGE_PROFILE="rules-smoke.toml")
    out = subprocess.run(command + ["site.rules", "--json", "--no-history", "--quiet"], capture_output=True, text=True, encoding="utf-8", env=env)
    if out.returncode not in (0, 2):
        print(f"::error::exit {out.returncode}: {out.stderr}")
        return 1
    report = json.loads(out.stdout)
    result = next(r for r in report["results"] if r["module_id"] == "site.rules")
    rows = {f["label"]: f for f in result["findings"]}
    bad = []
    for label, (severity, pattern) in EXPECT.items():
        row = rows.get(label)
        if row is None:
            bad.append(f"{label}: missing")
        elif row["severity"] != severity or not re.search(pattern, row["value"]):
            bad.append(f"{label}: {row['severity']} · {row['value']}")
        else:
            print(f"ok  {label}: {row['value']}")
    if bad:
        for b in bad:
            print(f"::error::custom check {b}")
        return 1
    print(f"Site custom checks on Windows: all {len(EXPECT)} came out as expected ({result['summary']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
