#!/usr/bin/env python3
"""Merge finding fragments into findings.json without writing ad-hoc scripts.

    python3 findings.py merge FINDINGS FRAGMENT [FRAGMENT ...]

A fragment is a JSON file written with the host's file-write tool (never a
shell heredoc or a generated script). It holds any of these top-level keys:
`meta`, `expert`, `three_pass`, `evidence_integrity` and the opt-in
`invariant_ledger` are merged key by key; nested values (including phase lists
and the ledger's `entries`, so send the whole list in one fragment) are
replaced, not recursively merged. `findings`, `evidence` and `test_runs` records are matched by
`id`, a known record updated key by key (so a later fragment can add just
`verification` to F-003) and a new one appended; a `perspectives` entry
replaces the recorded entry with the same `name` (so a later fragment can
correct a result), and the other list sections (`checked_ok`, `decisions`,
`limitations`, `next_steps`) are appended without duplicates; a fragment's
`remove` object (e.g. {"limitations": ["exact text"]}) first deletes exact
entries from those lists, and an entry that is not recorded is refused. FINDINGS is
created when absent and written atomically, under the same writer lock as
verification_workflow.py, only if no other writer changed it meanwhile. Profiles and test runs require a captured version-2 record.
`schema_version`, `assessment`, `meta.commit` and `kind: "source"` evidence come only from
evidence_capture.py (a fragment may change only a source record's `summary`);
workflow journals come only from verification_workflow.py. The merged report
must pass render.py's schema check
before anything is written.

Finding text describes the weakness, not an attack: the request shape is the
method, path and parameter names, with placeholders such as `<other tenant's
order id>`. Literal payload strings in a finding's prose fields are refused, so
the report never carries a working exploit.

A fragment adds at most five new findings (updates to recorded ones are not
counted), so a refused write loses at most that batch.

`D-*` findings belong to deps_scan.py: a fragment may only add `validation` or
`verification` to an existing `D-*` ID, never create one or change its other fields.

Exit codes: 0 merged, 1 a fragment was refused (reason on stderr), 2 unreadable
input or schema error.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402
from contract_check import read_regular  # noqa: E402
from expert import derive_expert  # noqa: E402

LISTS = ("perspectives", "checked_ok", "decisions", "limitations", "next_steps")
REMOVABLE = LISTS[1:]  # `remove` deletes exact entries from these lists
PROFILES = ("expert", "three_pass", "evidence_integrity", "invariant_ledger")
OBJECTS = ("meta", *PROFILES)
RECORDS = ("findings", "evidence", "test_runs")
EXPERT_FIELDS = {"version", "mode", "host", "consent", "preflight", "spawns", "recon",
                 "reconciliation", "discovery", "variants", "omission", "panels",
                 "calibration", "ratings", "severity_resolutions", "reception", "qa"}
RESERVED_FINDING = {"verification_workflow", "verdict", "source_link", "snippet"}
# D-* findings belong to deps_scan.py; a fragment may only record their review.
DEP_REVIEW = {"id", "validation", "verification"}
# Captured source evidence belongs to evidence_capture.py; a fragment may only reword it.
SOURCE_EDITABLE = {"id", "summary"}
# SKILL.md: write results in batches of one to five findings, so a refused write loses at most one batch.
MAX_NEW_FINDINGS = 5
# Merged finding ids match contract_check.py CODE_ID / DEP_ID (ASCII digits, no padding or case variants).
FINDING_ID = re.compile(r"[FD]-[0-9]{3}")
PROSE = ("title", "actor", "request", "impact", "fix")
# Literal attack strings, not descriptions of them. Prose names the weakness
# and the parameter; the payload itself never belongs in the report.
PAYLOAD = re.compile(
    r"<script\b|<(?:svg|img|iframe|body|details|video|audio|input|object)\b[^>]*\bon[a-z]+\s*=|"
    r"\bon(?:error|load)\s*=|javascript:(?!\s|$)|"
    # SQL tautologies (' OR '1'='1, " or "a"="a, OR 1=1), not prose such as "'admin' or 'member'".
    r"\b(?:or|and)\s+(['\"]?)(\w+)\1\s*=\s*['\"]?\2\b|union\s+(?:all\s+)?select\b|"
    # Traversal: repeated ../ or ..\\, or any URL-encoded segment; a single "../" is prose.
    r"(?:\.\.[/\\]){2,}|\.\.(?:%2f|%5c)|%2e%2e(?:%2f|%5c|[/\\])|"
    r";\s*(?:rm|curl|wget|nc|bash|sh)\s|[;|]\s*(?:id|whoami)\s*(?:$|[;&`])|\$\(\s*(?:curl|wget|id|cat)\b|"
    # Template and expression probes.
    r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|[$#]\{\s*\d+\s*\*\s*\d+\s*\}|"
    r"\{\{\s*(?:config|self|request|settings|lipsum|cycler)\b|\$\{\s*(?:jndi|env|java|script):|"
    r"169\.254\.169\.254|/etc/(?:passwd|shadow)\b",
    re.IGNORECASE,
)


def read_json(path, raw=None):
    try:
        # A FIFO or device would block or stream forever; only a regular file is read.
        raw = read_regular(path) if raw is None else raw
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        # Deeper input would overflow copy/validation recursion later.
        if render.json_depth(value) > render.MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting deeper than {render.MAX_JSON_DEPTH} levels")
        return value
    except RecursionError:
        # Older Pythons stop decoding deep input themselves; report it the same way.
        raise render.SchemaError(f"{path}: JSON nesting deeper than {render.MAX_JSON_DEPTH} levels") from None
    except (OSError, UnicodeError, ValueError) as e:
        raise render.SchemaError(f"{path}: {e}") from None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def fragment_problems(fragment, name, base=None):
    """Check patch structure before applying it, including writer-owned fields.

    base is the report being merged into; captured `source` evidence is checked against it.
    """
    if not isinstance(fragment, dict):
        return [f"{name}: a fragment must be a JSON object"]
    unsupported = fragment.keys() - {*OBJECTS, *RECORDS, *LISTS, "remove"}
    if unsupported:
        return [f"{name}: unsupported keys {sorted(unsupported)}; schema_version and assessment "
                "come from evidence_capture.py"]
    problems = []
    for key in OBJECTS:
        if key in fragment and not isinstance(fragment[key], dict):
            problems.append(f"{name}: {key} must be an object")
    for key in (*RECORDS, *LISTS):
        if key in fragment and not isinstance(fragment[key], list):
            problems.append(f"{name}: {key} must be a list")
    remove = fragment.get("remove", {})
    if not isinstance(remove, dict) or remove.keys() - set(REMOVABLE) or any(
            not isinstance(v, list) or not all(isinstance(x, str) for x in v) for v in remove.values()):
        problems.append(f"{name}: remove must map {', '.join(REMOVABLE)} to lists of exact entries")
    if problems:
        return problems
    if "commit" in fragment.get("meta", {}):
        problems.append(f"{name}: meta.commit comes from evidence_capture.py")
    unknown_expert = fragment.get("expert", {}).keys() - EXPERT_FIELDS
    if unknown_expert:
        problems.append(f"{name}: unsupported expert fields {sorted(unknown_expert)}")
    for key in RECORDS:
        seen = set()
        for record in fragment.get(key, []):
            identifier = record.get("id") if isinstance(record, dict) else None
            if not isinstance(identifier, str) or not identifier.strip():
                problems.append(f"{name}: {key} records need a nonblank id")
                continue
            if identifier in seen:
                problems.append(f"{name}: duplicate {key} id {identifier}")
            seen.add(identifier)
            if key == "findings" and RESERVED_FINDING.intersection(record):
                problems.append(f"{name}: {identifier}: workflow journals and derived fields cannot be merged")
            if key == "findings" and not FINDING_ID.fullmatch(identifier):
                problems.append(f"{name}: finding id {identifier!r} must be F-NNN (code) or D-NNN (deps_scan.py)")
                continue
            if key == "findings" and identifier.startswith("D-") and record.keys() - DEP_REVIEW:
                problems.append(f"{name}: {identifier}: D-* scanner fields {sorted(record.keys() - DEP_REVIEW)} "
                                "come only from deps_scan.py; merge only validation/verification")
            if key == "evidence":
                problems += source_evidence_problems(record, identifier, name, base)
    recorded = base.get("findings") if isinstance(base, dict) else None
    known = {f.get("id") for f in recorded if isinstance(f, dict) and isinstance(f.get("id"), str)} \
        if isinstance(recorded, list) else set()
    new = {r.get("id") for r in fragment.get("findings", []) if isinstance(r, dict)
           and isinstance(r.get("id"), str)} - known
    if len(new) > MAX_NEW_FINDINGS:
        problems.append(f"{name}: {len(new)} new findings in one fragment; write at most {MAX_NEW_FINDINGS} "
                        "per fragment and merge each batch before writing the next")
    pending = [fragment]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if any(key.startswith("_") for key in value):
                problems.append(f"{name}: internal/derived fields cannot be merged")
                break
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return problems or payload_problems(fragment, name)


def source_evidence_problems(record, identifier, name, base):
    """Captured source evidence belongs to evidence_capture.py; a fragment may only reword its summary."""
    recorded = base.get("evidence") if isinstance(base, dict) else None
    existing = next((r for r in recorded if isinstance(r, dict) and r.get("id") == identifier), None) \
        if isinstance(recorded, list) else None
    if isinstance(existing, dict) and existing.get("kind") == "source":
        changed = sorted(k for k in record.keys() - SOURCE_EDITABLE if record[k] != existing.get(k))
        if changed:
            return [f"{name}: evidence {identifier}: captured source fields {changed} come only from "
                    "evidence_capture.py; a fragment may change only its summary"]
    elif record.get("kind") == "source":
        return [f"{name}: evidence {identifier}: source evidence is created only by evidence_capture.py; "
                "capture the path and cite the ID it prints"]
    return []


def _strings(value, path):
    """(path, string) for every string inside VALUE (dicts and lists walked)."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")


# Free-text fields of a finding's structured verification that reach the reports.
VERIFICATION_TEXT = ("reason", "check")


def payload_problems(fragment, name):
    """Literal attack strings in any report prose a fragment writes: finding
    prose, validation evidence, verification/falsification/review reasons,
    reference titles, perspective name/result/note, checked_ok, decisions,
    limitations, next_steps and meta strings."""
    problems = []
    hint = "contains a literal attack string; describe the weakness and name the parameter with a placeholder instead"

    def check(where, value):
        if isinstance(value, str) and PAYLOAD.search(value):
            problems.append(f"{name}: {where} {hint}")

    for f in fragment.get("findings", []):
        if not isinstance(f, dict):
            continue
        ident = f.get("id", "?")
        validation = f.get("validation") if isinstance(f.get("validation"), dict) else {}
        fields = [(key, f.get(key)) for key in PROSE] + [("validation.evidence", validation.get("evidence"))]
        for key, value in fields:
            check(f"{ident}.{key}", value)
        for where, value in _strings(f.get("verification"), f"{ident}.verification"):
            if where.rsplit(".", 1)[-1] in VERIFICATION_TEXT:
                check(where, value)
        references = f.get("references") if isinstance(f.get("references"), list) else []
        for index, ref in enumerate(references):
            if isinstance(ref, dict):
                check(f"{ident}.references[{index}].title", ref.get("title"))
    for key in ("checked_ok", "decisions", "limitations", "next_steps"):
        for where, value in _strings(fragment.get(key), key):
            check(where, value)
    for index, entry in enumerate(fragment.get("perspectives") or []):
        if isinstance(entry, dict):
            for field in ("name", "result", "note"):
                check(f"perspectives[{index}].{field}", entry.get(field))
    meta = fragment.get("meta") if isinstance(fragment.get("meta"), dict) else {}
    for key, value in meta.items():
        check(f"meta.{key}", value)
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
    for key, entries in fragment.get("remove", {}).items():
        base[key] = [item for item in base.get(key, []) if item not in entries]
    for key in OBJECTS:
        if isinstance(fragment.get(key), dict):
            base.setdefault(key, {}).update(fragment[key])
    for key in RECORDS:
        if key in fragment or key == "findings":
            upsert(base.setdefault(key, []), fragment.get(key, []))
    for key in LISTS:
        items = base.setdefault(key, [])
        for item in fragment.get(key, []):
            if key == "perspectives" and isinstance(item, dict) and "name" in item:
                same = [i for i, old in enumerate(items) if isinstance(old, dict) and old.get("name") == item["name"]]
                if same:
                    items[same[0]] = item
                    for i in reversed(same[1:]):
                        del items[i]
                    continue
            if item not in items:
                items.append(item)
    return base


class MergeConflict(Exception):
    pass


def write_report(path, base, original):
    """Replace path atomically unless another writer changed it since it was read."""
    def current():
        return path.read_bytes() if path.exists() else None

    lock = path.with_name(path.name + ".workflow.lock")
    try:
        fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise MergeConflict(f"{lock}: a writer lock exists; check the other writer before removing a stale lock")
    os.close(fd)
    temp = None
    try:
        if path.is_symlink() or current() != original:
            raise MergeConflict(f"{path}: file changed concurrently; no update written")
        mode = stat.S_IMODE(path.stat().st_mode) if original is not None else None
        fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(base, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode if mode is not None else 0o666 & ~current_umask())
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None and os.path.exists(temp):
            os.unlink(temp)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def current_umask():
    mask = os.umask(0)
    os.umask(mask)
    return mask


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="merge fragments into FINDINGS")
    m.add_argument("findings", type=Path)
    m.add_argument("fragments", nargs="+", type=Path)
    args = p.parse_args(argv)

    try:
        original = read_regular(args.findings) if os.path.lexists(args.findings) else None
        base = read_json(args.findings, original) if original is not None else {}
        fragments = [(str(path), read_json(path)) for path in args.fragments]
    except (render.SchemaError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    refused = []
    known = {f.get("id") for f in base.get("findings", []) if isinstance(f, dict) and isinstance(f.get("id"), str)} \
        if isinstance(base, dict) and isinstance(base.get("findings"), list) else set()
    for name, fragment in fragments:
        refused += fragment_problems(fragment, name, base)
        if isinstance(fragment, dict) and isinstance(fragment.get("findings"), list):
            refused += [f"{name}: {f['id']}: D-* findings are created only by deps_scan.py --into"
                        for f in fragment["findings"] if isinstance(f, dict) and isinstance(f.get("id"), str)
                        and f["id"].startswith("D-") and f["id"] not in known]
    if refused:
        print("\n".join(refused), file=sys.stderr)
        return 1
    try:
        if not isinstance(base, dict):
            raise render.SchemaError("existing report must be an object")
        if base:
            render.validate_data(copy.deepcopy(base))
            derive_expert(base, render.SchemaError)
        for name, fragment in fragments:
            if any(key in fragment for key in (*PROFILES, "test_runs")) and base.get("schema_version") != 2:
                raise render.SchemaError("extension profiles and test_runs require evidence_capture.py first")
            # Evidence IDs come from evidence_capture.py; records citing guessed IDs
            # merged earlier would make the capture itself fail, with no way to remove them.
            if base.get("schema_version") != 2 and ("evidence" in fragment or any(
                    isinstance(f, dict) and "verification" in f for f in fragment.get("findings", []))):
                raise render.SchemaError("verification and evidence require evidence_capture.py first; "
                                         "cite the IDs it prints")
            # A missing entry is refused, so a typo cannot leave the old text in place.
            missing = [f"{name}: remove.{key}: {entry!r} is not recorded"
                       for key, entries in fragment.get("remove", {}).items()
                       for entry in entries if entry not in base.get(key, [])]
            if missing:
                print("\n".join(missing), file=sys.stderr)
                return 1
            base = merge(base, fragment)
        render.validate_data(copy.deepcopy(base))
        # Shape errors fail; incomplete later phases are permitted and stay held.
        derive_expert(base, render.SchemaError)
    except render.SchemaError as e:
        print(f"error: merged report does not match the schema: {e}", file=sys.stderr)
        return 2
    try:
        write_report(args.findings, base, original)
    except (MergeConflict, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"merged {len(fragments)} fragment(s) into {args.findings}: {len(base['findings'])} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
