#!/usr/bin/env python3
"""Export findings.json to the formats other tools consume: SARIF, CSV and issue drafts.

    python3 export.py sarif  FINDINGS --out results.sarif [--include-fixed] [--as-of YYYY-MM-DD] [--id ID ...]
    python3 export.py csv    FINDINGS --out findings.csv  [--bom] [--id ID ...]
    python3 export.py issues FINDINGS --out DIR [--lang en|ja] [--all] [--id ID ...]

FINDINGS is a findings.json file or the output directory holding it.

- `sarif` writes SARIF 2.1.0 for code-scanning services and IDEs: one rule per
  finding (its title), the location as a repository-relative region, a level
  and `security-severity` from the severity, and a run-independent
  `partialFingerprints` entry so an alert follows its finding across rescans.
  Ruled-out findings are emitted as suppressed results and `Accepted` ones as
  accepted suppressions carrying the recorded triage reason, owner and review
  date; an acceptance past its review date (`--as-of`, default today, UTC) is
  emitted unsuppressed so the alert returns. `Fixed` findings are left out unless
  `--include-fixed`. A finding whose location is not a relative `path:line`
  is not emitted (named on stderr), since code scanning needs a file.
- `csv` writes one row per finding for trackers and spreadsheets, including
  the triage owner, review date, ticket and decision reason. Cells that
  a spreadsheet would read as a formula are prefixed with `'`.
- `issues` writes one Markdown issue draft per open, included finding (all
  included findings with `--all`) following `templates/issue.<lang>.md`, plus
  `index.md`. An open High or Medium is marked for a private tracker or
  security advisory. Drafts carry no source excerpts. Filing them is the
  requester's step.

Every text field is masked for secret-looking values the way the rendered
reports are. Exports are derived files: write them outside the scan's output
directory, or name them with `contract_check.py --allow NAME`.
Exit codes: 0 written, 2 unreadable or invalid input, unsafe output path or
an unknown `--id`.
"""
import argparse
import csv
import datetime
import io
import json
import re
from pathlib import Path, PurePosixPath
import sys
from urllib.parse import quote

from finding_keys import fingerprint, included, location, part, rule_id
from output_files import OutputError, check_target, shareable, write_file
from report_schema import SchemaError, acceptance_expired, iso_date, load

TOOL_URI = "https://github.com/simota/security-scan"
SARIF_LEVEL = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
# GitHub code scanning reads 7.0-8.9 as high, 4.0-6.9 medium, 0.1-3.9 low.
SECURITY_SEVERITY = {"High": "8.0", "Medium": "5.5", "Low": "2.0"}
CSV_COLUMNS = ("id", "part", "severity", "confidence", "verdict", "status", "verification", "retest",
               "category", "cwe", "location", "title", "actor", "request", "impact", "fix",
               "references", "fingerprint", "owner", "review_by", "ticket", "decision_reason", "decided")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

LABELS = {
    "en": {
        "owner": "Owner", "ticket": "Ticket", "decision": "Triage decision", "review_by": "Review by",
        "title": "Title", "summary": "Summary", "item": "Item", "value": "Value", "severity": "Severity",
        "confidence": "Confidence", "verdict": "Verdict", "method": "method", "verification": "Verification",
        "retest": "Retest", "perspective": "Perspective", "cwe": "CWE", "location": "Location",
        "revision": "Assessed revision", "date": "Date / assessor", "happens": "What happens",
        "repro": "Static reproduction", "actor": "Actor", "request": "Request shape and steps",
        "evidence": "Evidence", "fix": "Fix direction", "refs": "References", "questions": "Open questions",
        "done": "Done when", "private": "Visibility: PRIVATE. This is an unfixed {sev} finding: file it in a "
        "private tracker or as a GitHub Security Advisory (private vulnerability reporting), never as a public issue.",
        "internal": "Visibility: follow the repository's own confidentiality; no source excerpts are included.",
        "env_question": "Confidence is Environment-dependent: confirm the deployment setting this finding depends on.",
        "suspected_question": "Confidence is Suspected: confirm the path end to end before scheduling the fix.",
        "no_questions": "None recorded.", "none": "Not recorded.",
        "done_items": ["The fix is merged", "A regression test fails before the fix and passes after it",
                       "The legitimate path (positive control) still passes",
                       "`status` in findings.json is `Fixed` (record an independent retest separately)"],
        "index": "Issue drafts", "index_note": "Drafts generated from findings.json. Review each one before filing; "
        "filing or sending is the requester's step.", "file": "Draft", "visibility": "Visibility",
        "vis_private": "private", "vis_internal": "repository", "generated": "Generated from",
        "level": {"legacy": "Detailed verification evidence not recorded (legacy)",
                  "incomplete": "Verification incomplete", "static_supported": "Supported by static evidence",
                  "runtime_supported": "Reproduced in an isolated local environment",
                  "environment_unverified": "Environment conditions unverified"},
        "retests": {"not_requested": "Retest not recorded", "fix_claimed": "Fix recorded; retest unverified",
                    "verified": "Complete before/after and control retest records",
                    "incomplete": "Retest incomplete"},
    },
    "ja": {
        "owner": "担当", "ticket": "チケット", "decision": "トリアージの判断", "review_by": "見直し期限",
        "title": "タイトル", "summary": "概要", "item": "項目", "value": "値", "severity": "深刻度",
        "confidence": "確度", "verdict": "検証判定", "method": "方法", "verification": "検証の根拠",
        "retest": "再テスト", "perspective": "観点", "cwe": "CWE", "location": "場所",
        "revision": "対象リビジョン", "date": "診断日 / 診断者", "happens": "何が起きるか",
        "repro": "再現手順（静的）", "actor": "実行できる主体", "request": "リクエストの形と手順",
        "evidence": "根拠", "fix": "修正方針", "refs": "参考", "questions": "未確定事項",
        "done": "対応完了の条件", "private": "公開範囲：非公開。未修正の {sev} の指摘です。公開 issue ではなく、"
        "非公開のトラッカーまたは GitHub Security Advisory（非公開の脆弱性報告）で起票してください。",
        "internal": "公開範囲：リポジトリと同じ機密区分に従ってください。ソースの抜粋は含めていません。",
        "env_question": "確度が Environment-dependent です。この指摘が前提とするデプロイ設定を確認してください。",
        "suspected_question": "確度が Suspected です。修正を計画する前に経路を最後まで確認してください。",
        "no_questions": "記録なし。", "none": "記録なし。",
        "done_items": ["修正がマージされた", "修正前に失敗し、修正後に成功する回帰テストが追加された",
                       "正当な利用経路（positive control）が引き続き成功する",
                       "findings.json の `status` を `Fixed` に更新した（独立した再テストは別途記録する）"],
        "index": "issue 下書き", "index_note": "findings.json から生成した下書きです。起票前に必ず内容を確認してください。"
        "起票・送付は依頼者が行います。", "file": "下書き", "visibility": "公開範囲",
        "vis_private": "非公開", "vis_internal": "リポジトリと同じ", "generated": "生成元",
        "level": {"legacy": "詳細な検証根拠なし（従来形式）", "incomplete": "検証未完了",
                  "static_supported": "静的根拠で成立", "runtime_supported": "隔離されたローカル環境で再現",
                  "environment_unverified": "環境条件が未確認"},
        "retests": {"not_requested": "再検査記録なし", "fix_claimed": "修正の申告あり・再検査は未確認",
                    "verified": "修正前後・対照条件の再検査記録あり", "incomplete": "再検査未完了"},
    },
}


class ExportError(Exception):
    pass


def read_record(path):
    path = Path(path)
    if path.is_dir():
        path = path / "findings.json"
    if path.is_symlink() or not path.is_file():
        raise SchemaError(f"{path}: not a regular findings.json file")
    return load(path)


def select(data, ids):
    findings = data["findings"]
    if not ids:
        return findings
    known = {f["id"] for f in findings}
    missing = [i for i in ids if i not in known]
    if missing:
        raise ExportError("unknown finding id: " + ", ".join(missing))
    wanted = set(ids)
    return [f for f in findings if f["id"] in wanted]


def triage(finding):
    record = finding.get("triage")
    return record if isinstance(record, dict) else {}


def state(finding):
    view = finding.get("_verification") or {}
    return view.get("level", "legacy"), view.get("retest", "not_requested")


def relative_uri(path):
    """A repository-relative URI for SARIF, or None for absolute or escaping paths."""
    if not path or path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        return None
    parts = PurePosixPath(path).parts
    if not parts or ".." in parts:
        return None
    return quote("/".join(parts), safe="/-._~")


# --- SARIF ---------------------------------------------------------------

def sarif(data, findings, include_fixed=False, as_of=None):
    as_of = as_of or datetime.datetime.now(datetime.timezone.utc).date()
    rules, results, skipped = [], [], []
    meta = data["meta"]
    for f in findings:
        if f["status"] == "Fixed" and not include_fixed:
            continue
        path, start, end = location(f)
        uri = relative_uri(path) if start is not None else None
        if uri is None:
            skipped.append(f["id"])
            continue
        fp = fingerprint(f)
        rid = rule_id(f)
        rule_key = f"{rid}/{fp[:8]}"
        level, retest = state(f)
        tags = ["security", f.get("category", "")] + ([f["cwe"]] if f.get("cwe") else [])
        properties = {"tags": [shareable(t) for t in tags if t], "precision": {
            "Confirmed": "high", "Environment-dependent": "medium", "Suspected": "low"}[f["confidence"]]}
        if f["severity"] in SECURITY_SEVERITY:
            properties["security-severity"] = SECURITY_SEVERITY[f["severity"]]
        rule = {"id": rule_key, "name": rid,
                "shortDescription": {"text": shareable(f["title"])},
                "fullDescription": {"text": shareable(f.get("impact") or f["title"])},
                "defaultConfiguration": {"level": SARIF_LEVEL[f["severity"]]},
                "properties": properties}
        if f.get("fix"):
            rule["help"] = {"text": shareable(f["fix"]), "markdown": shareable(f["fix"])}
        if f.get("cwe"):
            rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{f['cwe'][4:]}.html"
        rules.append(rule)
        message = shareable(f["title"])
        if f.get("impact"):
            message += "\n\n" + shareable(f["impact"])
        if f.get("actor"):
            message += "\n\nActor: " + shareable(f["actor"])
        result = {
            "ruleId": rule_key, "ruleIndex": len(rules) - 1, "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, start), "endLine": max(1, end)}}}],
            "partialFingerprints": {"securityScanFinding/v1": fp},
            "properties": {"findingId": f["id"], "part": part(f), "severity": f["severity"],
                           "confidence": f["confidence"], "verdict": f["verdict"], "status": f["status"],
                           "verification": level, "retest": retest},
        }
        if not included(f):
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": shareable(f"{f['verdict']}: {f['validation'].get('evidence', '')}")}]
        elif f["status"] == "Accepted" and acceptance_expired(f, as_of):
            # The decision has lapsed: the alert comes back until it is decided again.
            result["properties"]["acceptanceExpired"] = True
        elif f["status"] == "Accepted":
            decision = triage(f)
            justification = "Risk accepted (status: Accepted)"
            if decision.get("reason"):
                justification = "Risk accepted: " + shareable(decision["reason"])
                details = [f"owner {shareable(decision['owner'])}" if decision.get("owner") else "",
                           f"review by {decision['review_by']}" if decision.get("review_by") else ""]
                if any(details):
                    justification += " (" + "; ".join(d for d in details if d) + ")"
            result["suppressions"] = [{"kind": "external", "status": "accepted", "justification": justification}]
        results.append(result)
    run_properties = {"project": shareable(meta.get("project", "")), "date": shareable(meta.get("date", "")),
                      "assessor": shareable(meta.get("assessor", "")), "method": shareable(meta.get("method", ""))}
    if skipped:
        run_properties["unlocatedFindings"] = skipped
    run = {"tool": {"driver": {"name": "security-scan", "informationUri": TOOL_URI, "rules": rules}},
           "results": results, "columnKind": "unicodeCodePoints", "properties": run_properties}
    commit = meta.get("commit") or (data.get("assessment") or {}).get("commit", "")
    if isinstance(commit, str) and commit:
        run["properties"]["commit"] = shareable(commit)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}
    return doc, skipped


# --- CSV -----------------------------------------------------------------

def spreadsheet_safe(value):
    text = shareable(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def csv_text(findings):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        level, retest = state(f)
        row = {"id": f["id"], "part": part(f), "severity": f["severity"], "confidence": f["confidence"],
               "verdict": f["verdict"], "status": f["status"], "verification": level, "retest": retest,
               "category": f.get("category", ""), "cwe": f.get("cwe", ""), "location": f["location"],
               "title": f["title"], "actor": f.get("actor", ""), "request": f.get("request", ""),
               "impact": f.get("impact", ""), "fix": f.get("fix", ""),
               "references": " ".join(r["url"] for r in f.get("references", [])),
               "fingerprint": fingerprint(f), "owner": triage(f).get("owner", ""),
               "review_by": triage(f).get("review_by", ""), "ticket": triage(f).get("ticket", ""),
               "decision_reason": triage(f).get("reason", ""), "decided": triage(f).get("decided", "")}
        writer.writerow([spreadsheet_safe(row[c]) for c in CSV_COLUMNS])
    return buffer.getvalue()


# --- Issue drafts ----------------------------------------------------------

def _md(value):
    """Record text as inert Markdown: HTML is escaped, so a draft cannot carry markup."""
    return shareable(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cell(value):
    return _md(value).replace("|", "\\|").replace("\n", " ")


def _code(value):
    text = shareable(value).replace("\n", " ")
    fence = "``" if "`" in text else "`"
    return f"{fence} {text} {fence}" if fence == "``" else f"`{text}`"


def _link(url):
    """A validated http(s) URL with the characters that end a Markdown link target encoded."""
    return "".join("%{:02X}".format(ord(ch)) if ch in "()<>[]" else ch for ch in url)


def private(finding):
    return finding["status"] == "Open" and finding["severity"] in ("High", "Medium") and included(finding)


def issue(data, f, lang):
    L = LABELS[lang]
    meta = data["meta"]
    level, retest = state(f)
    v = f.get("validation", {})
    commit = meta.get("commit") or (data.get("assessment") or {}).get("commit", "") or ""
    lines = [f"**{L['title']}:** [{f['severity']}] {_md(f['title'])} ({f['id']})", "",
             "> " + (L["private"].format(sev=f["severity"]) if private(f) else L["internal"]), "",
             f"## {L['summary']}", "", f"| {L['item']} | {L['value']} |", "|---|---|",
             f"| ID | {f['id']} |", f"| {L['severity']} | {f['severity']} |",
             f"| {L['confidence']} | {f['confidence']} |",
             f"| {L['verdict']} | {v.get('verdict', 'Unverified')} ({L['method']}: {_cell(v.get('method') or '—')}) |",
             f"| {L['verification']} | {L['level'].get(level, level)} |",
             f"| {L['retest']} | {L['retests'].get(retest, retest)} |",
             f"| {L['perspective']} | {_cell(f.get('category', ''))} |",
             f"| {L['cwe']} | {f.get('cwe') or '—'} |",
             f"| {L['location']} | {_code(f['location'])} |",
             f"| {L['revision']} | {_cell(str(commit)) or '—'} |",
             f"| {L['date']} | {_cell(meta.get('date', ''))} / {_cell(meta.get('assessor', '') or '—')} |",
             *triage_rows(f, L),
             "", f"## {L['happens']}", "", _md(f.get("impact")) or L["none"], "",
             f"## {L['repro']}", "", f"**{L['actor']}:** {_md(f.get('actor')) or L['none']}", "",
             f"**{L['request']}:**", "", _md(f.get("request")) or L["none"], "",
             f"## {L['evidence']}", "", _md(v.get("evidence")) or L["none"], "",
             f"## {L['fix']}", "", _md(f.get("fix")) or L["none"], "", f"## {L['refs']}", ""]
    refs = f.get("references", [])
    lines += [f"- [{_md(r['title'] or r['url'])}]({_link(r['url'])}) ({_md(r['type'])})" for r in refs] or [L["none"]]
    questions = []
    if f["confidence"] == "Environment-dependent":
        questions.append(L["env_question"])
    elif f["confidence"] == "Suspected":
        questions.append(L["suspected_question"])
    lines += ["", f"## {L['questions']}", ""] + ([f"- {q}" for q in questions] or [L["no_questions"]])
    lines += ["", f"## {L['done']}", ""] + [f"- [ ] {item}" for item in L["done_items"]]
    return "\n".join(lines) + "\n"


def triage_rows(f, L):
    decision = triage(f)
    rows = []
    if decision.get("owner"):
        rows.append(f"| {L['owner']} | {_cell(decision['owner'])} |")
    if decision.get("ticket"):
        rows.append(f"| {L['ticket']} | <{_link(decision['ticket'])}> |")
    if decision.get("reason"):
        rows.append(f"| {L['decision']} | {decision['status']} ({_cell(decision['decided'])}): {_cell(decision['reason'])} |")
    if decision.get("review_by"):
        rows.append(f"| {L['review_by']} | {_cell(decision['review_by'])} |")
    return rows


def write_issues(data, findings, out, lang, everything=False):
    out = Path(out)
    if out.is_symlink() or (out.exists() and not out.is_dir()):
        raise OutputError(f"{out}: must be a directory, not a symlink or file")
    if out.exists() and any(out.iterdir()):
        raise OutputError(f"{out}: directory is not empty; choose a new one so earlier drafts are not mixed in")
    out.mkdir(parents=True, exist_ok=True)
    L = LABELS[lang]
    chosen = [f for f in findings if included(f) and (everything or f["status"] == "Open")]
    rows = []
    for n, f in enumerate(chosen, 1):
        # Legacy records allow any ID text; only a plain one becomes a file name.
        name = f"{f['id']}.md" if SAFE_NAME.fullmatch(f["id"]) else f"finding-{n:03d}.md"
        write_file(check_target(out / name), issue(data, f, lang))
        rows.append(f"| [{f['id']}]({quote(name)}) | {f['severity']} | {_cell(f['title'])} | "
                    f"{L['vis_private'] if private(f) else L['vis_internal']} |")
    index = [f"# {L['index']}: {_md(data['meta'].get('project', ''))}", "", L["index_note"], "",
             f"| {L['file']} | {L['severity']} | {L['title']} | {L['visibility']} |", "|---|---|---|---|", *rows]
    write_file(out / "index.md", "\n".join(index) + "\n")
    return chosen


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("format", choices=("sarif", "csv", "issues"))
    p.add_argument("findings", help="findings.json or the output directory holding it")
    p.add_argument("--out", required=True, help="output file (sarif, csv) or new directory (issues)")
    p.add_argument("--id", dest="ids", action="append", default=[], help="export only this finding (repeatable)")
    p.add_argument("--lang", choices=sorted(LABELS), default="en", help="issue draft language")
    p.add_argument("--all", action="store_true", help="issues: draft every included finding, not only Open ones")
    p.add_argument("--include-fixed", action="store_true", help="sarif: also emit findings recorded as Fixed")
    p.add_argument("--bom", action="store_true", help="csv: start with a UTF-8 byte-order mark (for Excel)")
    p.add_argument("--as-of", dest="as_of", help="sarif: date that decides whether an acceptance has expired "
                   "(default: today, UTC)")
    args = p.parse_args(argv)
    try:
        as_of = iso_date(args.as_of, "--as-of") if args.as_of else None
        data = read_record(args.findings)
        findings = select(data, args.ids)
    except (SchemaError, OSError, ExportError) as exc:
        print(f"export: {exc}", file=sys.stderr)
        return 2
    try:
        if args.format == "sarif":
            doc, skipped = sarif(data, findings, args.include_fixed, as_of)
            write_file(args.out, json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
            if skipped:
                print("export: not emitted (location is not a relative path:line): " + ", ".join(skipped),
                      file=sys.stderr)
            print(f"export: {len(doc['runs'][0]['results'])} SARIF results written to {args.out}")
        elif args.format == "csv":
            text = csv_text(findings)
            write_file(args.out, ("\ufeff" if args.bom else "") + text)
            print(f"export: {len(findings)} rows written to {args.out}")
        else:
            chosen = write_issues(data, findings, args.out, args.lang, args.all)
            print(f"export: {len(chosen)} issue drafts and index.md written to {args.out}")
    except (OutputError, OSError) as exc:
        print(f"export: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
