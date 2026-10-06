#!/usr/bin/env python3
"""Merge finding fragments into findings.json without writing ad-hoc scripts.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta` is merged key by key; `findings` and `evidence` records are matched by
`id`, a known record updated key by key (so a later fragment can add just
`verification` to F-003) and a new one appended; the list sections (`perspectives`, `checked_ok`, `decisions`,
`limitations`, `next_steps`) are appended without duplicates. FINDINGS is
created when absent. `schema_version` and `assessment` are set only by
evidence_capture.py, never by a fragment. The merged report must pass render.py's schema check
before anything is written.

Finding text describes the weakness, not an attack: the request shape is the
method, path and parameter names, with placeholders such as `<other tenant's
order id>`. Literal payload strings in a finding's prose fields are refused, so
the report never carries a working exploit.

Exit codes: 0 merged, 1 a fragment was refused (reason on stderr), 2 unreadable
input or schema error.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

LISTS = ("perspectives", "checked_ok", "decisions", "limitations", "next_steps")
OBJECTS = ("meta",)
RECORDS = ("findings", "evidence")
PROSE = ("title", "actor", "request", "impact", "fix")
# Literal attack strings, not descriptions of them. Prose names the weakness
# and the parameter; the payload itself never belongs in the report.
PAYLOAD = re.compile(
    r"<script\b|javascript:|onerror\s*=|'\s*(?:or|and)\s+['\d]|union\s+select|"
    r"(?:\.\./){2,}|;\s*(?:rm|curl|wget|nc|bash|sh)\s|\$\(\s*(?:curl|wget|id|cat)\b|"
    r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|169\.254\.169\.254|/etc/passwd",
    re.IGNORECASE,
)


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as e:
        raise render.SchemaError(f"{path}: {e}") from None


def payload_problems(fragment, name):
    problems = []
    for f in fragment.get("findings", []):
        if not isinstance(f, dict):
            continue
        for key in PROSE:
            value = f.get(key)
            if isinstance(value, str) and PAYLOAD.search(value):
                problems.append(f"{name}: {f.get('id', '?')}.{key} contains a literal attack string; "
                                "describe the weakness and name the parameter with a placeholder instead")
    return problems


def upsert(items, updates):
    """Merge records by id: a known id is updated key by key, a new one appended."""
    by_id = {r.get("id"): r for r in items if isinstance(r, dict)}
    for r in updates:
        if isinstance(r, dict) and r.get("id") in by_id:
            by_id[r["id"]].update(r)
        else:
            items.append(r)
            if isinstance(r, dict):
                by_id[r.get("id")] = r


def merge(base, fragment):
    for key in OBJECTS:
        if isinstance(fragment.get(key), dict):
            base.setdefault(key, {}).update(fragment[key])
    for key in RECORDS:
        upsert(base.setdefault(key, []), fragment.get(key, []))
    for key in LISTS:
        items = base.setdefault(key, [])
        for item in fragment.get(key, []):
            if item not in items:
                items.append(item)
    return base


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into FINDINGS")
    m.add_argument("findings", type=Path)
    m.add_argument("fragments", nargs="+", type=Path)
    args = p.parse_args(argv)

    try:
        base = read_json(args.findings) if args.findings.exists() else {}
        fragments = [(str(path), read_json(path)) for path in args.fragments]
    except render.SchemaError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    refused = []
    for name, fragment in fragments:
        if not isinstance(fragment, dict):
            refused.append(f"{name}: a fragment must be a JSON object")
        elif fragment.keys() - {*OBJECTS, *RECORDS, *LISTS}:
            refused.append(f"{name}: unsupported keys {sorted(fragment.keys() - {*OBJECTS, *RECORDS, *LISTS})}; "
                           "schema_version and assessment come from evidence_capture.py")
        elif any(not isinstance(fragment.get(k, []), list) for k in (*RECORDS, *LISTS)):
            refused.append(f"{name}: {', '.join((*RECORDS, *LISTS))} must be lists")
        else:
            refused += payload_problems(fragment, name)
    if refused:
        print("\n".join(refused), file=sys.stderr)
        return 1
    for _, fragment in fragments:
        base = merge(base, fragment)
    try:
        render.validate_data(copy.deepcopy(base))
    except render.SchemaError as e:
        print(f"error: merged report does not match the schema: {e}", file=sys.stderr)
        return 2
    args.findings.write_text(json.dumps(base, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"merged {len(fragments)} fragment(s) into {args.findings}: {len(base['findings'])} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
