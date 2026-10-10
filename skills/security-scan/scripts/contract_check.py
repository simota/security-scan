#!/usr/bin/env python3
"""Check a finished scan against the run contract shared by every host.

    python3 contract_check.py OUT_DIR [--no-pdf] [--allow NAME ...]

OUT_DIR holds findings.json and the rendered outputs. The contract (SKILL.md,
"Run contract") fixes what differs between hosts when left to judgment: record
format, ID scheme, where D-* findings come from, perspective coverage, the
fields every code finding carries, the limitations the contract requires
(no PDF, no invariant ledger) and the output file set. It checks shape
and provenance markers only; it cannot tell whether a finding is true.

Exit codes: 0 contract holds, 1 violations listed on stderr, 2 unreadable input.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SKILL = Path(__file__).resolve().parents[1]
OUTPUTS = {"findings.json", "deps.json", "dashboard.html", "assessment.html", "assessment.pdf", "evidence"}
# Used with fullmatch: ASCII digits only and no trailing newline. Paths may
# contain spaces (render.py accepts them) but not control characters.
CODE_ID = re.compile(r"F-([0-9]{3})")
DEP_ID = re.compile(r"D-[0-9]{3}")
LOCATION = re.compile(r"[^:\s\x00-\x1f\x7f](?:[^:\x00-\x1f\x7f]*[^:\s\x00-\x1f\x7f])?:[0-9]+(?:-[0-9]+)?")
VERDICTS = {"Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable"}
CODE_FIELDS = ("actor", "request", "impact", "fix")
CLAIMS = ("reachability", "preconditions", "defenses", "impact")
SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
RENDERED = ("dashboard.html", "assessment.html")
NO_PDF = "assessment.pdf not produced"
NO_LEDGER = "invariant ledger and close-check not machine-checked"
SOURCE_STAMP = re.compile(rb'<meta name="security-scan-source" content="sha256:([0-9a-f]{64})">')


MAX_JSON_DEPTH = 200  # Newer Pythons parse very deep JSON without RecursionError.


def json_depth(value):
    depth, pending = 0, [(value, 1)]
    while pending:
        item, level = pending.pop()
        if isinstance(item, (dict, list)):
            depth = max(depth, level)
            if level > MAX_JSON_DEPTH:
                return level
            pending.extend((child, level + 1) for child in (item.values() if isinstance(item, dict) else item))
    return depth


def perspective_names():
    """Canonical names, read from the table in reference/perspectives.md."""
    names, in_table = [], False
    for line in (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|"):
            if names:
                break  # Only the first table under the "| Perspective |" header names perspectives.
            continue
        if cells[0] == "Perspective":
            in_table = True
        elif in_table and len(cells) == 2 and cells[0] and not set(cells[0]) <= set("-: "):
            names.append(cells[0])
    return names


def blank(value):
    return not isinstance(value, str) or not value.strip()


def check(data, out_dir, pdf=True, allow=()):
    problems = []
    add = problems.append
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    if not isinstance(data.get("findings"), list):
        add("findings: required list")
    raw_findings = data.get("findings")
    findings = [f for f in raw_findings if isinstance(f, dict)] if isinstance(raw_findings, list) else []
    perspectives = data.get("perspectives") if isinstance(data.get("perspectives"), list) else []

    def commit(value):
        return value.lower() if isinstance(value, str) else value

    if data.get("schema_version") != 2 or not isinstance(data.get("assessment"), dict):
        add("record: schema_version 2 with an assessment pin is required (run evidence_capture.py)")
    elif commit(meta.get("commit")) != commit(data["assessment"].get("commit")):
        add("record: meta.commit must equal assessment.commit")
    for key in ("project", "date", "assessor"):
        if blank(meta.get(key)):
            add(f"meta.{key}: required; assessor names the host and model, e.g. 'Codex (gpt-5)'")

    ids = [str(f.get("id", "")) for f in findings]
    for i in sorted({i for i in ids if ids.count(i) > 1}):
        add(f"{i}: duplicate id")
    code = [f for f in findings if CODE_ID.fullmatch(str(f.get("id", "")))]
    deps = [f for f in findings if DEP_ID.fullmatch(str(f.get("id", "")))]
    for f in findings:
        if f not in code and f not in deps:
            add(f"{f.get('id')}: ids are F-NNN (code findings) or D-NNN (deps_scan.py only)")
    numbers = sorted(int(CODE_ID.fullmatch(f["id"]).group(1)) for f in code)
    if numbers != list(range(1, len(numbers) + 1)):
        add("F-*: number code findings F-001..F-%03d without gaps" % len(numbers))
    # Excluded findings keep their ID when a later review rules them out, so
    # only included findings must follow severity order.
    ranks = [SEVERITY_RANK.get(f.get("severity"), len(SEVERITY_RANK))
             for f in sorted(code, key=lambda f: f["id"])
             if not (isinstance(f.get("validation"), dict)
                     and f["validation"].get("verdict") in ("FalsePositive", "NotApplicable"))]
    if ranks != sorted(ranks):
        add("F-*: number code findings in severity order (High first), then path")

    stamp = data.get("dependency_scan")
    if not isinstance(stamp, dict) or stamp.get("tool") != "deps_scan.py":
        add("dependency_scan: missing; run deps_scan.py <repo> [--audit] --into findings.json")
    elif stamp.get("findings") != len(deps):
        add(f"D-*: {len(deps)} present but deps_scan.py wrote {stamp.get('findings')}; "
            "never hand-write or split D-* findings; merge only their validation/verification")

    # Limitations SKILL.md requires verbatim, matched case-insensitively as substrings.
    limits = [str(x).lower() for x in data.get("limitations", [])] if isinstance(data.get("limitations"), list) else []
    if not pdf and not any(NO_PDF in x for x in limits):
        add('limitations: --no-pdf requires "assessment.pdf not produced: no PDF engine"')
    # A stale PDF left from an earlier render contradicts the limitation in --no-pdf mode too.
    if (out_dir / "assessment.pdf").is_file() and any(NO_PDF in x for x in limits):
        add('limitations: says "assessment.pdf not produced", but assessment.pdf exists; '
            'merge {"remove": {"limitations": [<that entry>]}} and re-render')
    ledger_line = any(NO_LEDGER in x for x in limits)
    if "invariant_ledger" not in data and not ledger_line:
        add('limitations: without invariant_ledger, state "invariant ledger and close-check not machine-checked '
            '(no invariant_ledger opt-in)"')
    elif "invariant_ledger" in data and ledger_line:
        add("limitations: says the invariant ledger is not machine-checked, but invariant_ledger is recorded")

    names = perspective_names()
    recorded = [p.get("name") for p in perspectives if isinstance(p, dict)]
    for name in names:
        if recorded.count(name) != 1:
            add(f"perspectives: record '{name}' exactly once (findings, N/A + reason, or Not checked + need)")
    for name in sorted({str(n) for n in recorded} - set(names)):
        add(f"perspectives: '{name}' is not a name from reference/perspectives.md")
    for p in perspectives:
        if isinstance(p, dict) and p.get("name") in names and blank(p.get("result")):
            add(f"perspectives: '{p['name']}' has no result")

    for f in code:
        fid = f["id"]
        if f.get("category") not in names:
            add(f"{fid}: category must be a perspective name")
        if blank(f.get("location")) or not LOCATION.fullmatch(f["location"]):
            add(f"{fid}: location must be path:line or path:start-end")
        for key in CODE_FIELDS:
            if blank(f.get(key)):
                add(f"{fid}: {key} is required")
        validation = f.get("validation") if isinstance(f.get("validation"), dict) else {}
        if validation.get("verdict") not in VERDICTS:
            add(f"{fid}: validation.verdict must be recorded explicitly")
        verification = f.get("verification")
        claims = verification.get("claims") if isinstance(verification, dict) else None
        checks = verification.get("falsification") if isinstance(verification, dict) else None
        if (not isinstance(claims, dict) or any(not isinstance(claims.get(k), dict) for k in CLAIMS)
                or not isinstance(checks, list) or not checks):
            add(f"{fid}: structured verification (four claims, at least one falsification check) is required")

    # Hidden entries (.DS_Store and the like) are file-manager noise, not outputs.
    present = {p.name for p in out_dir.iterdir() if not p.name.startswith(".")}
    expected = {"findings.json", "deps.json", "dashboard.html", "assessment.html"} | ({"assessment.pdf"} if pdf else set())
    if data.get("schema_version") == 2:
        expected.add("evidence")
    hints = {"deps.json": "run deps_scan.py <repo> [--audit] --out {out}/deps.json --into {out}/findings.json",
             "evidence": "run evidence_capture.py <repo> --findings {out}/findings.json <paths>",
             "assessment.pdf": "run render.py {out}/findings.json --repo <repo> --out {out} (if it exits 3 with "
                               "no PDF engine: merge the limitation 'assessment.pdf not produced: no PDF engine', "
                               "re-run render.py with --repo, then contract_check.py --no-pdf)"}
    for name in sorted(expected - present):
        hint = hints.get(name, "run render.py {out}/findings.json --repo <repo> --out {out}").format(out=out_dir)
        add(f"outputs: {name} missing; {hint}")
    # A report rendered before the last merge or --into does not show the record.
    # render.py stamps each page with the digest of the findings.json it read;
    # bytes, not mtimes, so copies and same-second writes are judged correctly.
    try:
        recorded = hashlib.sha256((out_dir / "findings.json").read_bytes()).hexdigest()
        for name in RENDERED:
            if name in present:
                stamp = SOURCE_STAMP.search((out_dir / name).read_bytes()[:4096])
                if not stamp or stamp.group(1).decode() != recorded:
                    add(f"outputs: {name} was not rendered from the current findings.json; "
                        "render after the last merge or --into")
    except OSError:
        pass
    extra = {"run"} if "expert" in data else set()  # expert grade keeps its run records beside the report
    for name in sorted(present - OUTPUTS - extra - set(allow)):
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
        if json_depth(data) > MAX_JSON_DEPTH:
            raise RecursionError
        if not isinstance(data, dict):
            raise ValueError("findings.json must hold a JSON object")
    except RecursionError:
        print("contract_check.py: findings.json nesting is too deep", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"contract_check.py: {exc}", file=sys.stderr)
        return 2
    problems = check(data, a.out_dir, pdf=not a.no_pdf, allow=a.allow)
    for line in problems:
        print(f"FAIL {line}", file=sys.stderr)
    if problems:
        print(f"contract_check: {len(problems)} violation(s)", file=sys.stderr)
        return 1
    print(f"contract ok - {len(data['findings'])} findings, schema 2, perspectives complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
