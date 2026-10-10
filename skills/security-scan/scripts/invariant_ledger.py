"""Opt-in invariant ledger and static-reproduction gate (schema version 2).

A schema-version-2 findings.json that carries `invariant_ledger` opts in: the
ledger summary is validated and rendered into the assessment, and every active
`F-*` finding must carry the static reproduction shape (`request` with
`Preconditions:`, `Steps:` and `Contrast:`; `fix` with `Test:`; `impact` with
an expected-then-actual pair; Japanese reports may write 前提条件 / 手順 / 対比 /
テスト and 期待 / 実際, with an ASCII or full-width colon), and a unit marked `closed` must match its
close-check. Without the key nothing changes. This checks recorded text only; it reads no source code.
"""
import html
import re

FAMILIES = ("OWN", "ROLE", "PROP", "STATE", "QTY", "ID", "TRUST")
STATUSES = ("holds", "violated", "partial", "not_checked", "not_applicable")
# Each marker in English or Japanese, followed by an ASCII or full-width colon.
REQUEST_MARKERS = (("Preconditions:", r"(?:Preconditions|前提条件)[:：]"),
                   ("Steps:", r"(?:Steps|手順)[:：]"),
                   ("Contrast:", r"(?:Contrast|対比)[:：]"))
FIX_MARKERS = (("Test:", r"(?:Test|テスト)[:：]"),)
EXCLUDED = ("FalsePositive", "NotApplicable")
ENTRY_KEYS = {"id", "family", "invariant", "source", "status", "paths_read", "paths_total"}
ENTRY_OPTIONAL = {"finding_ids", "reason"}
UNIT_KEYS = {"unit", "record_inputs", "trace_rows", "blank_cells"}
UNIT_OPTIONAL = {"closed"}
# English or Japanese ("期待" ... "実際"): the expected outcome first, then the actual one.
EXPECTED_ACTUAL = re.compile(r"(\bexpected\b|期待).*(\bactual\b|実際)", re.IGNORECASE | re.DOTALL)
INV_RE = re.compile(r"INV-[0-9]{2,}")  # fullmatch: ASCII digits, no trailing newline

LABELS = {
    "en": {"title": "Invariant ledger", "id": "ID", "family": "Family", "invariant": "Invariant",
           "source": "Source", "status": "Status", "units": "Review units (close-check)", "unit": "Unit",
           "inputs": "Record-naming inputs", "rows": "Trace rows", "blank": "Blank cells", "state": "State",
           "closed": "closed", "open": "open",
           "holds": "holds on all {total} paths", "partial": "holds on {read}/{total}, rest not read",
           "violated": "violated ({findings}); {read}/{total} paths read", "not_checked": "not checked ({reason})",
           "not_applicable": "N/A ({reason})"},
    "ja": {"title": "不変条件台帳", "id": "ID", "family": "分類", "invariant": "不変条件",
           "source": "根拠", "status": "状態", "units": "レビュー単位（クローズチェック）", "unit": "単位",
           "inputs": "レコード指定入力", "rows": "トレース行", "blank": "空欄", "state": "状態",
           "closed": "完了", "open": "未完了",
           "holds": "全 {total} 経路で成立", "partial": "{read}/{total} 経路で成立、残りは未読",
           "violated": "違反（{findings}）。{read}/{total} 経路を確認", "not_checked": "未確認（{reason}）",
           "not_applicable": "対象外（{reason}）"},
}


def enabled(data):
    return isinstance(data, dict) and data.get("schema_version") == 2 and "invariant_ledger" in data


def _count(obj, key, where, fail):
    value = obj.get(key)
    if type(value) is not int or value < 0:
        fail(f"{where}.{key}: must be a non-negative integer")
    return value


def _text(obj, key, where, fail):
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"{where}.{key}: required nonblank string")
    return value


def validate_ledger(data, error_type=ValueError):
    """Validate the opted-in ledger and the reproduction shape; return None when not opted in."""
    if not enabled(data):
        return None

    def fail(message):
        raise error_type(message)

    ledger = data["invariant_ledger"]
    if not isinstance(ledger, dict) or not {"version", "entries"} <= set(ledger) <= {"version", "entries", "units"}:
        fail("invariant_ledger: requires version and entries, optionally units")
    if type(ledger["version"]) is not int or ledger["version"] != 1:
        fail("invariant_ledger.version: must be 1")
    entries = ledger["entries"]
    if not isinstance(entries, list) or not entries:
        fail("invariant_ledger.entries: requires a nonempty list")
    finding_ids = {f["id"] for f in data["findings"] if str(f.get("id", "")).startswith("F-")}
    excluded_ids = {f["id"] for f in data["findings"]
                    if isinstance(f.get("validation"), dict)
                    and f["validation"].get("verdict") in ("FalsePositive", "NotApplicable")}
    seen = set()
    for i, entry in enumerate(entries):
        at = f"invariant_ledger.entries[{i}]"
        if not isinstance(entry, dict) or not ENTRY_KEYS <= set(entry) <= ENTRY_KEYS | ENTRY_OPTIONAL:
            fail(f"{at}: requires {', '.join(sorted(ENTRY_KEYS))}; optional {', '.join(sorted(ENTRY_OPTIONAL))}")
        identifier = _text(entry, "id", at, fail)
        if not INV_RE.fullmatch(identifier) or identifier in seen:
            fail(f"{at}.id: INV-<nn>, unique")
        seen.add(identifier)
        if entry["family"] not in FAMILIES:
            fail(f"{at}.family: one of {FAMILIES}")
        _text(entry, "invariant", at, fail)
        _text(entry, "source", at, fail)
        status = entry["status"]
        if status not in STATUSES:
            fail(f"{at}.status: one of {STATUSES}")
        read, total = _count(entry, "paths_read", at, fail), _count(entry, "paths_total", at, fail)
        if read > total:
            fail(f"{at}.paths_read: cannot exceed paths_total")
        refs = entry.get("finding_ids", [])
        if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in finding_ids for ref in refs) or len(set(refs)) != len(refs):
            fail(f"{at}.finding_ids: unique IDs of F-* findings in this report")
        if status == "holds" and (total == 0 or read != total):
            fail(f"{at}.status: holds requires every path read (paths_read == paths_total >= 1)")
        if status == "partial" and read >= total:
            fail(f"{at}.status: partial requires paths_read < paths_total")
        if status == "violated" and not any(ref not in excluded_ids for ref in refs):
            fail(f"{at}.finding_ids: violated requires an included (not ruled-out) finding")
        if status == "holds" and refs:
            fail(f"{at}.finding_ids: an invariant that holds cites no findings")
        if status in ("not_checked", "not_applicable"):
            _text(entry, "reason", at, fail)
        if status == "not_applicable" and refs:
            fail(f"{at}.finding_ids: an invariant that does not apply cites no findings")
    units = ledger.get("units", [])
    if not isinstance(units, list):
        fail("invariant_ledger.units: must be a list")
    for i, unit in enumerate(units):
        at = f"invariant_ledger.units[{i}]"
        if not isinstance(unit, dict) or not UNIT_KEYS <= set(unit) <= UNIT_KEYS | UNIT_OPTIONAL:
            fail(f"{at}: requires {', '.join(sorted(UNIT_KEYS))}; optional closed")
        _text(unit, "unit", at, fail)
        for key in ("record_inputs", "trace_rows", "blank_cells"):
            _count(unit, key, at, fail)
        closed = unit.get("closed", False)
        if type(closed) is not bool:
            fail(f"{at}.closed: must be true or false")
        if closed and (unit["trace_rows"] != unit["record_inputs"] or unit["blank_cells"]):
            fail(f"{at}.closed: a closed unit requires trace_rows == record_inputs and blank_cells == 0")
    for i, finding in enumerate(data["findings"]):
        verdict = (finding.get("validation") or {}).get("verdict", "Unverified")
        if not str(finding.get("id", "")).startswith("F-") or verdict in EXCLUDED:
            continue
        for key, markers in (("request", REQUEST_MARKERS), ("fix", FIX_MARKERS)):
            missing = [m for m, pattern in markers if not re.search(pattern, str(finding.get(key) or ""))]
            if missing:
                fail(f"findings[{i}].{key}: {finding['id']} lacks {', '.join(missing)} "
                     "(static reproduction steps are required once invariant_ledger is opted in)")
        if not EXPECTED_ACTUAL.search(str(finding.get("impact") or "")):
            fail(f"findings[{i}].impact: {finding['id']} lacks the expected vs actual pair "
                 "(expected outcome first, then actual)")
    return ledger


def status_text(entry, labels):
    return labels[entry["status"]].format(read=entry["paths_read"], total=entry["paths_total"],
                                          findings=", ".join(entry.get("finding_ids", [])),
                                          reason=entry.get("reason", ""))


def ledger_html(data, lang="en"):
    """Escaped HTML section for the assessment; empty when not opted in."""
    if not enabled(data):
        return ""
    L = LABELS.get(lang, LABELS["en"])
    esc = html.escape
    ledger = data["invariant_ledger"]
    rows = "".join(
        f"<tr data-ledger='{esc(e['id'])}' data-ledger-status='{esc(e['status'])}'><td>{esc(e['id'])}</td>"
        f"<td>{esc(e['family'])}</td><td>{esc(e['invariant'])}</td><td><code>{esc(e['source'])}</code></td>"
        f"<td>{esc(status_text(e, L))}</td></tr>" for e in ledger["entries"])
    head = "".join(f"<th scope='col'>{esc(L[k])}</th>" for k in ("id", "family", "invariant", "source", "status"))
    out = (f"<section class='invariant-ledger' id='invariant-ledger'><h3>{esc(L['title'])}</h3>"
           f"<table class='coverage'><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
    units = ledger.get("units", [])
    if units:
        unit_head = "".join(f"<th scope='col'>{esc(L[k])}</th>" for k in ("unit", "inputs", "rows", "blank", "state"))
        unit_rows = "".join(
            f"<tr><td>{esc(u['unit'])}</td><td>{u['record_inputs']}</td><td>{u['trace_rows']}</td>"
            f"<td>{u['blank_cells']}</td><td>{esc(L['closed'] if u.get('closed') else L['open'])}</td></tr>"
            for u in units)
        out += f"<h4>{esc(L['units'])}</h4><table class='coverage'><thead><tr>{unit_head}</tr></thead><tbody>{unit_rows}</tbody></table>"
    return out + "</section>"
