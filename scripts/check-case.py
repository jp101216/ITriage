"""Independent ZIP/JSON/CSV validation for the CLI case smoke test."""
import csv
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

source, preview_path, archive = map(Path, sys.argv[1:])
original = json.loads(source.read_text(encoding="utf-8"))
preview = json.loads(preview_path.read_text(encoding="utf-8"))
assert original["recording"]["samples"], "recording must contain real samples"
with zipfile.ZipFile(archive) as case:
    assert case.testzip() is None, "ZIP CRC validation failed"
    names = set(case.namelist())
    assert {"report.json", "report.txt", "versions.txt", "timeline.json", "recording.csv", "manifest.json", "SHA256SUMS.txt"} <= names
    assert not any(n.startswith("logs/") or ".." in n.split("/") for n in names)
    assert names == set(preview["contents"]), "preview and export file sets differ"
    for name in names:
        assert case.read(name) == preview["contents"][name].encode("utf-8"), f"export differs from reviewed preview: {name}"
    for entry in json.loads(case.read("manifest.json")):
        data = case.read(entry["name"])
        assert len(data) == entry["bytes"]
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    for line in case.read("SHA256SUMS.txt").decode("utf-8").splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256(case.read(name)).hexdigest() == digest
    report = json.loads(case.read("report.json"))
    assert report["host"]["hostname"] != original["host"]["hostname"], "hostname was not pseudonymized"
    samples = list(csv.DictReader(io.StringIO(case.read("recording.csv").decode("utf-8"))))
    assert len(samples) == len(original["recording"]["samples"])
print(f"Validated {len(names)} reviewed files, {len(samples)} samples, ZIP CRCs and SHA-256 digests")
