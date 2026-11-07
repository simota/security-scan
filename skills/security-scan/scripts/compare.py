#!/usr/bin/env python3
"""Compare two assessments of the same application: what is new, what persists, what is gone.

    python3 compare.py BASELINE CURRENT [--json OUT] [--markdown OUT] [--lang en|ja]
                       [--fail-on High|Medium|Low|Info] [--as-of YYYY-MM-DD]

BASELINE and CURRENT are findings.json files (or the output directories that
hold them) from two independent runs, typically before and after a round of
fixes. IDs are assigned per run, so findings are matched by what they
describe: the part (code or dependency), file, weakness class (CWE or
perspective), line proximity and title similarity, or package and advisory
for dependency findings.

Each included finding of CURRENT is `new`, `persisting` (with any change of
severity, confidence, verdict or status) or `reopened` (ruled out before,
included now). Each included finding of BASELINE that CURRENT does not
report is `not_reported`: an independent static review that does not repeat a
finding does not prove it fixed, so the report says whether the current run
recorded the finding's perspective as checked. Findings ruled out in CURRENT
are `ruled_out`.

With `--fail-on SEVERITY` the exit code is 1 when any new or reopened
finding at that severity or above is still open, or a persisting open
finding there was raised into that range or recorded Fixed before (a
regressed fix), which lets CI hold a change that introduces one. An
`Accepted` finding whose recorded review date (triage.py) has passed by
`--as-of` (default today, UTC) counts as open, and a persisting finding whose
acceptance has expired blocks at its severity, so a risk acceptance cannot
outlive its review date unnoticed. Exit codes: 0 compared (gate passed or not
requested), 1 gate failed, 2 unreadable or invalid input or output.
The comparison reads both records only; it writes nothing unless asked.
"""
import argparse
import datetime
from functools import cached_property
import json
from pathlib import Path
import sys

from finding_keys import fingerprint, included, location, part, title_tokens, token_similarity
from output_files import OutputError, shareable, write_file
from report_schema import SEVERITIES, SchemaError, acceptance_expired, iso_date, load

RANK = {s: i for i, s in enumerate(SEVERITIES)}
TRACKED = ("severity", "confidence", "verdict", "status")
# A pair below this score is two different findings.
MATCH_THRESHOLD = 5.0

LABELS = {
    "en": {
        "title": "Assessment comparison", "baseline": "Baseline", "current": "Current",
        "summary": "Summary", "new": "New", "reopened": "Reopened", "persisting": "Persisting",
        "changed": "of which changed", "not_reported": "Not reported in the current run",
        "ruled_out": "Ruled out in the current run", "fixed_recorded": "Persisting and recorded as Fixed",
        "gate": "Gate", "gate_pass": "passed: no open new, reopened, escalated or regressed finding at {sev} or above",
        "gate_fail": "failed: {n} open new, reopened, escalated or regressed finding(s) at {sev} or above",
        "none": "None.", "col_id": "ID", "col_sev": "Severity", "col_title": "Title",
        "col_loc": "Location", "col_was": "Baseline ID", "col_change": "Change",
        "col_note": "Note", "unchecked": "perspective not recorded as checked in the current run",
        "checked": "perspective checked in the current run",
        "absent_note": "A finding the current run does not repeat is not proof of a fix: confirm it with a "
                       "regression test or a retest record before closing it.",
        "match_note": "Findings are matched by part, file, weakness class, line proximity and title, not by ID.",
        "project_mismatch": "The two records name different projects ({a} / {b}); check that they assess the same system.",
        "regressed": "{n} persisting finding(s) were recorded Fixed in the baseline and are open again.",
        "expired": "{n} finding(s) carry a risk acceptance whose review date has passed (as of {date}); "
                   "they count as open until a new decision is recorded.",
        "col_owner": "Owner",
    },
    "ja": {
        "title": "診断結果の比較", "baseline": "前回", "current": "今回",
        "summary": "概要", "new": "新規", "reopened": "再発（前回は除外）", "persisting": "継続",
        "changed": "うち変化あり", "not_reported": "今回の診断で報告されなかった指摘",
        "ruled_out": "今回の診断で除外された指摘", "fixed_recorded": "継続中で Fixed と記録された指摘",
        "gate": "ゲート", "gate_pass": "合格：{sev} 以上の未対応の新規・再発・深刻度上昇・修正後退の指摘はありません",
        "gate_fail": "不合格：{sev} 以上の未対応の新規・再発・深刻度上昇・修正後退の指摘が {n} 件あります",
        "none": "なし。", "col_id": "ID", "col_sev": "深刻度", "col_title": "タイトル",
        "col_loc": "場所", "col_was": "前回の ID", "col_change": "変化",
        "col_note": "備考", "unchecked": "今回の診断ではこの観点が確認済みとして記録されていません",
        "checked": "今回の診断でこの観点は確認済みです",
        "absent_note": "今回報告されなかったことは修正の証明ではありません。回帰テストまたは再検査の記録で確認してから"
                       "クローズしてください。",
        "match_note": "指摘は ID ではなく、区分・ファイル・脆弱性の種類・行の近さ・タイトルで対応付けています。",
        "project_mismatch": "2 つの記録の対象プロジェクト名が異なります（{a} / {b}）。同じシステムの診断か確認してください。",
        "regressed": "前回 Fixed と記録された指摘のうち {n} 件が、今回再び未対応として報告されています。",
        "expired": "見直し期限（{date} 時点）を過ぎたリスク受容が {n} 件あります。新しい判断を記録するまで未対応として扱います。",
        "col_owner": "担当",
    },
}


def read_record(path):
    path = Path(path)
    if path.is_dir():
        path = path / "findings.json"
    if path.is_symlink() or not path.is_file():
        raise SchemaError(f"{path}: not a regular findings.json file")
    return load(path)


class _Keys:
    """The values score() reads from one finding, each computed at most once.

    Values are computed on first use, in the order score() reads them, so a
    malformed finding raises where it always did. Findings are not modified
    while they are compared.
    """

    def __init__(self, finding):
        self.finding = finding

    @cached_property
    def part(self):
        return part(self.finding)

    @cached_property
    def fingerprint(self):
        return fingerprint(self.finding)

    @cached_property
    def location(self):
        return location(self.finding)

    @cached_property
    def tokens(self):
        return title_tokens(self.finding["title"])

    @cached_property
    def advisories(self):
        return set(self.finding.get("advisory_ids") or [])


def _deps_score(a, b):
    """Dependency findings are scanner-written: package and advisory, or file and title."""
    adv_a = a.advisories
    adv_b = b.advisories
    package_a, package_b = a.finding.get("package"), b.finding.get("package")
    if package_a or package_b:
        if package_a != package_b:
            return 0.0
        if adv_a or adv_b:
            return 10.0 if adv_a & adv_b else 0.0
    if a.location[0] != b.location[0]:
        return 0.0
    similarity = token_similarity(a.tokens, b.tokens)
    return 10.0 if similarity >= 0.999 else 6.0 * similarity


def _score(a, b):
    if a.part != b.part:
        return 0.0
    if a.part == "deps":
        return _deps_score(a, b)
    if a.fingerprint == b.fingerprint:
        return 20.0
    path_a, start_a, _ = a.location
    path_b, start_b, _ = b.location
    similarity = token_similarity(a.tokens, b.tokens)
    total = 0.0
    if path_a == path_b:
        total += 4.0
    elif similarity < 0.999:
        # Different files only match when the titles are the same words.
        return 0.0
    if a.finding.get("cwe") and b.finding.get("cwe"):
        total += 2.0 if a.finding["cwe"] == b.finding["cwe"] else -2.0
    if a.finding.get("category") == b.finding.get("category"):
        total += 1.0
    if path_a == path_b and start_a is not None and start_b is not None:
        distance = abs(start_a - start_b)
        total += 1.5 if distance <= 3 else 1.0 if distance <= 25 else 0.0
    return total + 4.0 * similarity


def score(a, b):
    """How likely two findings from different runs describe the same root cause."""
    return _score(_Keys(a), _Keys(b))


# Two different token sets reach a Jaccard similarity of 0.999 only when they
# share at least this many tokens; smaller similar sets are equal sets.
_SIMILAR_TOKENS = 999


def _indexable(finding):
    """A validated finding: the fields an index groups by have known types."""
    if not isinstance(finding, dict) or not isinstance(finding.get("id"), str) \
            or not isinstance(finding.get("title"), str):
        return False
    if part(finding) == "code":
        return True
    advisories = finding.get("advisory_ids")
    return (finding.get("package") is None or isinstance(finding["package"], str)) and (
        advisories is None or isinstance(advisories, list) and all(isinstance(a, str) for a in advisories))


def _labels(keys):
    """The groups one finding belongs to; only findings sharing one can score above zero.

    A code pair scores above zero only with the same fingerprint, the same
    file or near-identical title tokens; a dependency pair only with the same
    package or the same file.
    """
    if keys.part == "code":
        labels = [("fingerprint", keys.fingerprint), ("path", keys.location[0])]
        if keys.tokens:
            labels.append(("tokens", frozenset(keys.tokens)))
        if len(keys.tokens) >= _SIMILAR_TOKENS:
            labels.append(("many tokens", None))
        return labels
    labels = [("deps path", keys.location[0])]
    if keys.finding.get("package"):
        labels.append(("package", keys.finding["package"]))
    return labels


def _candidate_pairs(base_keys, cur_keys):
    """Every (i, j) whose score can be above zero; the rest score 0.0.

    Pairs are produced per baseline finding, so memory stays bounded by one
    finding's candidates rather than by every pair.
    """
    index = {}
    for j, keys in enumerate(cur_keys):
        for label in _labels(keys):
            index.setdefault(label, []).append(j)
    for i, keys in enumerate(base_keys):
        members = set()
        for label in _labels(keys):
            members.update(index.get(label, ()))
        for j in sorted(members):
            yield i, j


def match(baseline, current):
    """Greedy one-to-one pairing by descending score; ties broken by IDs for determinism."""
    base_keys = [_Keys(f) for f in baseline]
    cur_keys = [_Keys(f) for f in current]
    if all(map(_indexable, baseline)) and all(map(_indexable, current)):
        scored = _candidate_pairs(base_keys, cur_keys)
    else:
        # Unvalidated extension values: score every pair, as before.
        scored = ((i, j) for i in range(len(baseline)) for j in range(len(current)))
    candidates = []
    for i, j in scored:
        s = _score(base_keys[i], cur_keys[j])
        if s >= MATCH_THRESHOLD:
            candidates.append((-s, baseline[i]["id"], current[j]["id"], i, j))
    candidates.sort()
    used_a, used_b, pairs = set(), set(), []
    for neg, _, _, i, j in candidates:
        if i in used_a or j in used_b:
            continue
        used_a.add(i)
        used_b.add(j)
        pairs.append((i, j, -neg))
    return pairs


def brief(finding):
    entry = {"id": finding["id"], "part": part(finding), "severity": finding["severity"],
             "confidence": finding["confidence"], "verdict": finding["verdict"], "status": finding["status"],
             "title": shareable(finding["title"]), "location": shareable(finding["location"]),
             "category": finding.get("category", ""), "cwe": finding.get("cwe", ""),
             "fingerprint": fingerprint(finding)}
    triage = finding.get("triage")
    if isinstance(triage, dict):
        entry["triage"] = {k: shareable(triage[k]) for k in ("owner", "review_by", "ticket") if triage.get(k)}
    return entry


def checked_perspectives(data):
    checked = set()
    for entry in data.get("perspectives", []):
        result = str(entry.get("result", "")).strip().lower()
        if not result.startswith("not checked"):
            checked.add(entry["name"])
    return checked


def compare(base_data, current_data, fail_on=None, as_of=None):
    as_of = as_of or datetime.datetime.now(datetime.timezone.utc).date()
    base, cur = base_data["findings"], current_data["findings"]
    expired = set()
    pairs = match(base, cur)
    matched_base = {i: (j, s) for i, j, s in pairs}
    matched_cur = {j: i for i, j, _ in pairs}
    result = {"new": [], "reopened": [], "persisting": [], "not_reported": [], "ruled_out": []}
    for j, f in enumerate(cur):
        if j in matched_cur:
            old = base[matched_cur[j]]
            if included(f) and not included(old):
                result["reopened"].append({**brief(f), "baseline_id": old["id"]})
            elif included(f):
                changes = {k: {"from": old[k], "to": f[k]} for k in TRACKED if old[k] != f[k]}
                entry = {**brief(f), "baseline_id": old["id"], "changes": changes}
                # Expired now, or expired in the baseline and not decided again since.
                if acceptance_expired(f, as_of) or (acceptance_expired(old, as_of) and f["status"] == "Open"):
                    entry["acceptance_expired"] = True
                    expired.add(f["id"])
                result["persisting"].append(entry)
            elif included(old):
                result["ruled_out"].append({**brief(f), "baseline_id": old["id"]})
        elif included(f):
            result["new"].append(brief(f))
            if acceptance_expired(f, as_of):
                result["new"][-1]["acceptance_expired"] = True
                expired.add(f["id"])
    checked = checked_perspectives(current_data)
    for i, f in enumerate(base):
        if i not in matched_base and included(f):
            entry = brief(f)
            entry["perspective_checked"] = part(f) == "deps" or f.get("category") in checked
            result["not_reported"].append(entry)
    gate = None
    if fail_on:
        limit = RANK[fail_on]
        # Escalated into the gated range, or recorded Fixed before and open again (a regressed fix).
        raised = [f for f in result["persisting"]
                  if ("severity" in f["changes"] and RANK[f["changes"]["severity"]["from"]] > limit)
                  or f["changes"].get("status", {}).get("from") == "Fixed" or f.get("acceptance_expired")]
        # An acceptance past its review date no longer holds: the finding counts as open.
        blocking = [f["id"] for f in result["new"] + result["reopened"] + raised
                    if RANK[f["severity"]] <= limit and (f["status"] == "Open" or f["id"] in expired)]
        gate = {"fail_on": fail_on, "passed": not blocking, "blocking": blocking}
    def meta(data):
        m = data["meta"]
        return {k: shareable(m.get(k, "")) for k in ("project", "date", "commit", "assessor")}
    summary = {k: len(v) for k, v in result.items()}
    summary["changed"] = sum(1 for f in result["persisting"] if f["changes"])
    summary["acceptance_expired"] = len(expired)
    summary["regressed"] = sum(1 for f in result["persisting"]
                               if f["changes"].get("status", {}).get("from") == "Fixed" and f["status"] == "Open")
    summary["fixed_recorded"] = sum(1 for f in result["persisting"] if f["status"] == "Fixed")
    summary["severity_raised"] = sum(1 for f in result["persisting"] if "severity" in f["changes"]
                                     and RANK[f["changes"]["severity"]["to"]] < RANK[f["changes"]["severity"]["from"]])
    summary["severity_lowered"] = sum(1 for f in result["persisting"] if "severity" in f["changes"]
                                      and RANK[f["changes"]["severity"]["to"]] > RANK[f["changes"]["severity"]["from"]])
    return {"comparison_version": 1, "as_of": as_of.isoformat(), "baseline": meta(base_data), "current": meta(current_data),
            "summary": summary, "gate": gate, **result}


def _cell(value):
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def markdown(report, lang="en"):
    L = LABELS[lang]
    b, c = report["baseline"], report["current"]
    lines = [f"# {L['title']}: {_cell(c['project'] or b['project'])}", ""]
    for key, m in (("baseline", b), ("current", c)):
        rev = f" @ {_cell(m['commit'][:12])}" if m["commit"] else ""
        lines.append(f"- **{L[key]}:** {_cell(m['date'])}{rev} — {_cell(m['assessor'])}")
    if b["project"] and c["project"] and b["project"] != c["project"]:
        lines += ["", "> " + L["project_mismatch"].format(a=_cell(b["project"]), b=_cell(c["project"]))]
    s = report["summary"]
    lines += ["", f"## {L['summary']}", "",
              f"| {L['new']} | {L['reopened']} | {L['persisting']} ({L['changed']}) | {L['not_reported']} | {L['ruled_out']} |",
              "|---:|---:|---:|---:|---:|",
              f"| {s['new']} | {s['reopened']} | {s['persisting']} ({s['changed']}) | {s['not_reported']} | {s['ruled_out']} |",
              "", L["match_note"]]
    if s["regressed"]:
        lines += ["", "> " + L["regressed"].format(n=s["regressed"])]
    if s["acceptance_expired"]:
        lines += ["", "> " + L["expired"].format(n=s["acceptance_expired"], date=report["as_of"])]
    gate = report["gate"]
    if gate:
        text = (L["gate_pass"].format(sev=gate["fail_on"]) if gate["passed"]
                else L["gate_fail"].format(sev=gate["fail_on"], n=len(gate["blocking"])))
        lines += ["", f"**{L['gate']}:** {text}"]

    def table(key, columns, rows):
        lines.extend(["", f"## {L[key]}", ""])
        if not rows:
            lines.append(L["none"])
            return
        lines.append("| " + " | ".join(L[col] for col, _ in columns) + " |")
        lines.append("|" + "---|" * len(columns))
        for row in rows:
            lines.append("| " + " | ".join(_cell(fn(row)) for _, fn in columns) + " |")

    base_cols = [("col_id", lambda f: f["id"]), ("col_sev", lambda f: f["severity"]),
                 ("col_title", lambda f: f["title"]), ("col_loc", lambda f: f["location"])]
    table("new", base_cols, report["new"])
    table("reopened", base_cols + [("col_was", lambda f: f["baseline_id"])], report["reopened"])

    def changes(f):
        text = [f"{k}: {v['from']} → {v['to']}" for k, v in f["changes"].items()]
        if f.get("acceptance_expired"):
            text.append("acceptance expired")
        return ", ".join(text) or "—"
    table("persisting", base_cols + [("col_was", lambda f: f["baseline_id"]), ("col_change", changes)],
          report["persisting"])
    table("not_reported", base_cols + [("col_note", lambda f: L["checked"] if f["perspective_checked"]
                                         else L["unchecked"])], report["not_reported"])
    if report["not_reported"]:
        lines += ["", "> " + L["absent_note"]]
    table("ruled_out", base_cols + [("col_was", lambda f: f["baseline_id"]),
                                    ("col_change", lambda f: f["verdict"])], report["ruled_out"])
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("baseline", help="earlier findings.json or its output directory")
    p.add_argument("current", help="later findings.json or its output directory")
    p.add_argument("--json", dest="json_out", help="write the comparison as JSON to this file")
    p.add_argument("--markdown", dest="md_out", help="write the comparison as Markdown to this file")
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--fail-on", choices=SEVERITIES,
                   help="exit 1 when an open new, reopened, escalated or regressed finding is at this severity or above")
    p.add_argument("--as-of", dest="as_of", help="date that decides whether an acceptance has expired (default: today, UTC)")
    args = p.parse_args(argv)
    try:
        as_of = iso_date(args.as_of, "--as-of") if args.as_of else None
        base = read_record(args.baseline)
        cur = read_record(args.current)
    except (SchemaError, OSError) as exc:
        print(f"compare: {exc}", file=sys.stderr)
        return 2
    report = compare(base, cur, args.fail_on, as_of)
    text = markdown(report, args.lang)
    try:
        if args.json_out:
            write_file(args.json_out, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        if args.md_out:
            write_file(args.md_out, text)
    except (OutputError, OSError) as exc:
        print(f"compare: {exc}", file=sys.stderr)
        return 2
    if not args.md_out:
        sys.stdout.write(text)
    else:
        s = report["summary"]
        print(f"compared: {s['new']} new, {s['reopened']} reopened, {s['persisting']} persisting "
              f"({s['changed']} changed), {s['not_reported']} not reported, {s['ruled_out']} ruled out")
    gate = report["gate"]
    if gate and not gate["passed"]:
        print(f"compare: gate failed at {gate['fail_on']}: {', '.join(gate['blocking'])}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
