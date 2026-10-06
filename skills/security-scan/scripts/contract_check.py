#!/usr/bin/env python3
"""Check a finished scan against the run contract shared by every host.

    python3 contract_check.py OUT_DIR [--no-pdf] [--allow NAME ...]

OUT_DIR holds findings.json and the rendered outputs. The contract (SKILL.md,
"Run contract") fixes what differs between hosts when left to judgment: record
format, ID scheme, where D-* findings come from, perspective coverage, the
fields every code finding carries, and the output file set. It checks shape
and provenance markers only; it cannot tell whether a finding is true.

Exit codes: 0 contract holds, 1 violations listed on stderr, 2 unreadable input.
"""
import argparse
import json
from pathlib import Path
import re
import sys

SKILL = Path(__file__).resolve().parents[1]
OUTPUTS = {"findings.json", "deps.json", "dashboard.html", "assessment.html", "assessment.pdf", "evidence"}
CODE_ID = re.compile(r"^F-(\d{3})$")
DEP_ID = re.compile(r"^D-\d{3}$")
LOCATION = re.compile(r"^[^\s:]+:\d+(?:-\d+)?$")
VERDICTS = {"Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable"}
CODE_FIELDS = ("actor", "request", "impact", "fix")


def perspective_names():
    """Canonical names, read from the table in reference/perspectives.md."""
    names = []
    for line in (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and len(cells) == 2 and cells[0] not in ("Perspective", "") \
                and not set(cells[0]) <= set("-: "):
            names.append(cells[0])
    return names


def blank(value):
    return not isinstance(value, str) or not value.strip()


def check(data, out_dir, pdf=True, allow=()):
    problems = []
    add = problems.append
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    findings = [f for f in data.get("findings", []) if isinstance(f, dict)]

    if data.get("schema_version") != 2 or not isinstance(data.get("assessment"), dict):
        add("record: schema_version 2 with an assessment pin is required (run evidence_capture.py)")
    elif meta.get("commit") != data["assessment"].get("commit"):
        add("record: meta.commit must equal assessment.commit")
    for key in ("project", "date", "assessor"):
        if blank(meta.get(key)):
            add(f"meta.{key}: required; assessor names the host and model, e.g. 'Codex (gpt-5)'")

    ids = [str(f.get("id", "")) for f in findings]
    for i in sorted({i for i in ids if ids.count(i) > 1}):
        add(f"{i}: duplicate id")
    code = [f for f in findings if CODE_ID.match(str(f.get("id", "")))]
    deps = [f for f in findings if DEP_ID.match(str(f.get("id", "")))]
    for f in findings:
        if f not in code and f not in deps:
            add(f"{f.get('id')}: ids are F-NNN (code findings) or D-NNN (deps_scan.py only)")
    numbers = sorted(int(CODE_ID.match(f["id"]).group(1)) for f in code)
    if numbers != list(range(1, len(numbers) + 1)):
        add("F-*: number code findings F-001..F-%03d without gaps" % len(numbers))

    stamp = data.get("dependency_scan")
    if not isinstance(stamp, dict) or stamp.get("tool") != "deps_scan.py":
        add("dependency_scan: missing; run deps_scan.py <repo> [--audit] --into findings.json")
    elif stamp.get("findings") != len(deps):
        add(f"D-*: {len(deps)} present but deps_scan.py wrote {stamp.get('findings')}; "
            "never hand-write, merge or split D-* findings")

    names = perspective_names()
    recorded = [p.get("name") for p in data.get("perspectives", []) if isinstance(p, dict)]
    for name in names:
        if recorded.count(name) != 1:
            add(f"perspectives: record '{name}' exactly once (findings, N/A + reason, or Not checked + need)")
    for name in sorted({str(n) for n in recorded} - set(names)):
        add(f"perspectives: '{name}' is not a name from reference/perspectives.md")
    for p in data.get("perspectives", []):
        if isinstance(p, dict) and p.get("name") in names and blank(p.get("result")):
            add(f"perspectives: '{p['name']}' has no result")

    for f in code:
        fid = f["id"]
        if f.get("category") not in names:
            add(f"{fid}: category must be a perspective name")
        if blank(f.get("location")) or not LOCATION.match(f["location"]):
            add(f"{fid}: location must be path:line or path:start-end")
        for key in CODE_FIELDS:
            if blank(f.get(key)):
                add(f"{fid}: {key} is required")
        validation = f.get("validation") if isinstance(f.get("validation"), dict) else {}
        if validation.get("verdict") not in VERDICTS:
            add(f"{fid}: validation.verdict must be recorded explicitly")
        if not isinstance(f.get("verification"), dict):
            add(f"{fid}: structured verification (four claims, falsification) is required")

    present = {p.name for p in out_dir.iterdir()}
    expected = {"findings.json", "dashboard.html", "assessment.html"} | ({"assessment.pdf"} if pdf else set())
    for name in sorted(expected - present):
        add(f"outputs: {name} missing; run render.py findings.json --out {out_dir}")
    for name in sorted(present - OUTPUTS - set(allow)):
        add(f"outputs: unexpected '{name}'; write only the contract outputs unless the requester asked for more")
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out_dir", type=Path)
    p.add_argument("--no-pdf", action="store_true", help="the PDF was skipped on purpose")
    p.add_argument("--allow", action="append", default=[], help="an extra output the requester asked for")
    a = p.parse_args(argv)
    try:
        data = json.loads((a.out_dir / "findings.json").read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("findings.json must hold a JSON object")
    except (OSError, ValueError) as exc:
        print(f"contract_check.py: {exc}", file=sys.stderr)
        return 2
    problems = check(data, a.out_dir, pdf=not a.no_pdf, allow=a.allow)
    for line in problems:
        print(f"FAIL {line}", file=sys.stderr)
    if problems:
        print(f"contract_check: {len(problems)} violation(s)", file=sys.stderr)
        return 1
    print(f"contract ok - {len(data.get('findings', []))} findings, schema 2, perspectives complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
