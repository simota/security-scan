"""The findings.json contract: enumerations, input validation and parsing.

Shared by every tool that reads or writes a report record (findings.py,
evidence_capture.py, expert_audit.py, scan_run.py) and by render.py, so a
record tool never has to load the renderer to check its input.
Standard library only.
"""
import json
import math
import re
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

from invariant_ledger import validate_ledger
from secret_redaction import JWT_RE, TOKEN_RE
from three_pass import enabled as three_pass_enabled
from verification import validate_verification
from verification_workflow import validate_workflows

SEVERITIES = ["High", "Medium", "Low", "Info"]
CONFIDENCES = ["Confirmed", "Environment-dependent", "Suspected"]
STATUSES = ["Open", "Fixed", "Accepted"]
VERDICTS = ["Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable"]
EXCLUDED = {"FalsePositive", "NotApplicable"}
# ASCII digits only, no trailing newline: the number becomes part of a link.
CWE_RE = re.compile(r"CWE-[0-9]{1,5}")
LOC_RE = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")


class SchemaError(Exception):
    pass


def invisible_or_control(ch):
    """C0/C1 controls, format characters (bidi overrides, zero-width) and line/paragraph separators."""
    return unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp")


def http_url(value, field="url"):
    """Validate every href, not just its HTML escaping."""
    if (not isinstance(value, str) or not value or "\\" in value
            or any(ch.isspace() or invisible_or_control(ch) for ch in value)):
        raise SchemaError(f"{field}: must be an absolute http(s) URL without whitespace or controls")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            raise ValueError("unsafe URL")
        parsed.port  # Reject malformed/out-of-range ports too.
        # Webhook and bot URLs carry the credential in the path, where dropping the query cannot help.
        if TOKEN_RE.search(unquote(parsed.netloc + parsed.path)) or JWT_RE.search(unquote(parsed.path)):
            raise ValueError("credential in path")
    except ValueError:
        raise SchemaError(f"{field}: must be an absolute http(s) URL without credentials") from None
    return value


def text_field(obj, key, where, *, required=False, default=""):
    """Validate before coercion, hashing, sorting, or rendering can hide bad input."""
    value = obj.get(key, default)
    field = f"{where}.{key}" if where else key
    if not isinstance(value, str):
        raise SchemaError(f"{field}: must be a string")
    if required and not value.strip():
        raise SchemaError(f"{field}: required nonblank string")
    return value


def validate_json_values(data):
    """Reject values that UTF-8 HTML or the dashboard's JSON parser cannot read."""
    pending = [("", data)]
    while pending:
        where, value = pending.pop()
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise SchemaError(f"{where or 'top level'}: must contain valid Unicode text") from None
        elif isinstance(value, float) and not math.isfinite(value):
            raise SchemaError(f"{where or 'top level'}: number must be finite")
        elif isinstance(value, list):
            pending.extend((f"{where}[{i}]", entry) for i, entry in enumerate(value))
        elif isinstance(value, dict):
            for key, entry in value.items():
                # Validate the key before using it in an error message.
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise SchemaError(f"{where or 'top level'}: invalid Unicode object key") from None
                # Keys go into error messages: show control/format characters escaped.
                shown = key if key.isprintable() else ascii(key)
                pending.append((f"{where}.{shown}" if where else shown, entry))


def load(path, raw=None):
    """Parse and validate findings; raw is the exact bytes when the caller already read them."""
    def invalid_constant(value):
        raise SchemaError(f"{path}: invalid JSON constant {value}")

    try:
        raw = Path(path).read_bytes() if raw is None else raw
        data = json.loads(raw.decode("utf-8"), parse_constant=invalid_constant)
        if json_depth(data) > MAX_JSON_DEPTH:
            raise SchemaError(f"{path}: JSON nesting is too deep")
    except json.JSONDecodeError as e:
        raise SchemaError(f"{path}: invalid JSON: {e}")
    except UnicodeError:
        raise SchemaError(f"{path}: must be UTF-8 text") from None
    except ValueError:
        raise SchemaError(f"{path}: invalid JSON numeric value") from None
    except RecursionError:
        raise SchemaError(f"{path}: JSON nesting is too deep") from None
    return validate_data(data)


# Records are shallow. Newer Pythons parse very deep JSON without
# RecursionError, so the depth is checked explicitly.
MAX_JSON_DEPTH = 200


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


def validate_data(data):
    """Validate and normalize a parsed report using the same contract as the CLI."""
    validate_json_values(data)
    if not isinstance(data, dict):
        raise SchemaError("top level must be an object")
    # Fresh verification is an explicit in-memory argument, never input JSON.
    data.pop("_evidence_integrity", None)
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise SchemaError("meta: required object")
    for k in ("project", "date"):
        text_field(meta, k, "meta", required=True)
    for k in ("assessor", "scope", "method", "commit"):
        text_field(meta, k, "meta")
    if meta.get("source_url") not in (None, ""):
        meta["source_url"] = http_url(meta["source_url"], "meta.source_url")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise SchemaError("findings: required list")
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            raise SchemaError(f"{where}: must be an object")
        # These are derived output fields, never trusted JSON input.
        f.pop("source_link", None)
        f.pop("snippet", None)
        f.pop("_evidence_integrity", None)
        for k in ("id", "title", "severity", "confidence", "location"):
            text_field(f, k, where, required=True)
        if any(invisible_or_control(char) for char in f["location"]):
            raise SchemaError(f"{where}.location: must not contain control characters")
        match = LOC_RE.match(f["location"].strip())
        if match:
            try:
                int(match.group("start"))
                int(match.group("end") or match.group("start"))
            except ValueError:
                raise SchemaError(f"{where}.location: line numbers cannot be parsed") from None
        if f["id"] in seen:
            raise SchemaError(f"{where}.id: duplicate {f['id']}")
        seen.add(f["id"])
        if f["severity"] not in SEVERITIES:
            raise SchemaError(f"{where}.severity: one of {SEVERITIES}")
        if f["confidence"] not in CONFIDENCES:
            raise SchemaError(f"{where}.confidence: one of {CONFIDENCES}")
        f["status"] = text_field(f, "status", where, default="Open")
        if f["status"] not in STATUSES:
            raise SchemaError(f"{where}.status: one of {STATUSES}")
        for k in ("category", "actor", "request", "impact", "fix"):
            f[k] = text_field(f, k, where)
        if "cwe" in f:
            # Optional text fields may be an empty string (findings-schema.md).
            if not text_field(f, "cwe", where):
                del f["cwe"]
            elif not CWE_RE.fullmatch(f["cwe"]):
                raise SchemaError(f"{where}.cwe: CWE-<number>")
        if not f["category"]:
            f["category"] = "Uncategorized"
        val = f.get("validation", {})
        if not isinstance(val, dict):
            raise SchemaError(f"{where}.validation: must be an object")
        val["verdict"] = text_field(val, "verdict", f"{where}.validation", default="Unverified")
        if val["verdict"] not in VERDICTS:
            raise SchemaError(f"{where}.validation.verdict: one of {VERDICTS}")
        evidence = text_field(val, "evidence", f"{where}.validation")
        text_field(val, "method", f"{where}.validation")
        if val["verdict"] in ("Valid", "FalsePositive", "NotApplicable") and not evidence.strip():
            raise SchemaError(f"{where}.validation.evidence: required when verdict is {val['verdict']}")
        val["evidence"] = evidence
        f["validation"] = val
        f["verdict"] = val["verdict"]
        if "previous_validation" in f:
            previous = f["previous_validation"]
            if not isinstance(previous, dict):
                raise SchemaError(f"{where}.previous_validation: must be an object")
            for k in ("verdict", "evidence", "method"):
                text_field(previous, k, f"{where}.previous_validation")
        refs = f.get("references", [])
        if not isinstance(refs, list):
            raise SchemaError(f"{where}.references: must be a list")
        clean = []
        for j, r in enumerate(refs):
            if isinstance(r, str):
                r = {"url": r}
            if not isinstance(r, dict):
                raise SchemaError(f"{where}.references[{j}]: must be an object or URL")
            ref_where = f"{where}.references[{j}]"
            http_url(r.get("url"), f"{ref_where}.url")
            clean.append({"type": text_field(r, "type", ref_where) or "web", "url": r["url"],
                          "title": text_field(r, "title", ref_where)})
        f["references"] = clean
    for k in ("checked_ok", "decisions", "limitations", "next_steps"):
        v = data.get(k, [])
        if not isinstance(v, list):
            raise SchemaError(f"{k}: must be a list")
        for j, entry in enumerate(v):
            if not isinstance(entry, str):
                raise SchemaError(f"{k}[{j}]: must be a string")
        data[k] = v
    lens = data.get("perspectives", [])
    if not isinstance(lens, list):
        raise SchemaError("perspectives: must be a list")
    for j, perspective in enumerate(lens):
        where = f"perspectives[{j}]"
        if not isinstance(perspective, dict):
            raise SchemaError(f"{where}: must be an object")
        text_field(perspective, "name", where, required=True)
        for k in ("result", "note"):
            text_field(perspective, k, where)
    data["perspectives"] = lens
    # A versionless or version-1 "three_pass" key is uninterpreted legacy data, not the opt-in.
    if three_pass_enabled(data) or "expert" in data:
        # These gates select code findings by F-NNN; any other id would be
        # silently outside them, letting an open finding pass "complete".
        for f in findings:
            if not re.fullmatch(r"[FD]-[0-9]{3}", str(f["id"])):
                raise SchemaError(f"{f['id']}: three-pass and expert records need F-NNN or D-NNN ids")
    validate_verification(data, SchemaError)
    validate_workflows(data, SchemaError)
    validate_ledger(data, SchemaError)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    # code findings before dependency advisories (D-*) at the same severity
    findings.sort(key=lambda f: (rank[f["severity"]], str(f["id"]).startswith("D-"), f["id"]))
    return data
