"""Render a common-format report (docs/format.md) into dashboard.html and report.html.

Standard library only. The visual system is docs/design.md; the stylesheets and
the dashboard runtime come from style.py so every scan shares one look.
"""

import html
import json
import re
from datetime import date
from unicodedata import normalize
from urllib.parse import unquote, urlsplit

from . import style

FORMAT = "scan-report/1"
SEVERITIES = ["High", "Medium", "Low", "Info"]
STATUSES = ["Open", "Fixed", "Accepted"]
LIST_KEYS = ("limitations", "decisions", "next_steps", "checked_ok")
META_KEYS = ("project", "date", "assessor", "scope", "method", "commit")
REPORT_KEYS = ("kind", "title", "dashboard_title", "running_footer")
FINDING_KEYS = ("id", "title", "severity", "status", "confidence", "verdict", "category", "location", "excluded")
# Line numbers must stay exact in both Python and the JavaScript dashboard.
MAX_LINE_NUMBER = 2 ** 53 - 1
LINE_BREAKS = re.compile(r"[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]")

LABELS = {
    "en": {
        "kind": "Assessment", "title": "Assessment Report", "dashboard_title": "Assessment Results",
        "running_footer": "ASSESSMENT",
        "date": "Date", "assessor": "Assessor", "scope": "Scope", "method": "Method", "commit": "Commit",
        "abstract": "Abstract", "summary": "Summary", "no_summary": "No summary was recorded.",
        "severity": "Severity", "status": "Status", "confidence": "Confidence", "verdict": "Verdict",
        "category": "Category", "location": "Location", "title_col": "Finding", "action": "Next action",
        "open_by_severity": "Open findings by severity", "open": "Open", "closed": "Fixed or accepted",
        "total": "Total", "limitations": "Limitations", "limitations_empty": "No limitations were recorded.",
        "priority": "Priority", "priority_note": "Open findings, most severe first.",
        "priority_caption": "Open findings in priority order", "ref": "Ref",
        "no_open": "No open findings.", "no_findings": "No findings were recorded.",
        "decisions": "Decisions", "next_steps": "Next steps", "checked_ok": "Checked without findings",
        "not_recorded": "Not recorded.", "coverage": "Coverage",
        "coverage_note": "What was examined, and with what result.", "coverage_caption": "Perspectives examined",
        "perspective": "Perspective", "result": "Result", "note": "Note",
        "coverage_missing": "No coverage was recorded.",
        "register": "Finding register", "register_note": "Every included finding, by severity.",
        "register_caption": "Finding register", "details": "Findings",
        "excluded": "Excluded records", "excluded_note": "Recorded but excluded from the counts above.",
        "excluded_short": "Excluded", "snippet": "Source excerpt", "references": "References",
        "source": "source", "none": "—",
        "risk_summary": "{n} open High or Medium findings need attention.",
        "risk_summary_one": "1 open High or Medium finding needs attention.",
        "open_summary": "{n} open findings, none High or Medium.",
        "open_summary_one": "1 open finding, not High or Medium.",
        "urgent": "Open High + Medium", "open_total": "Open", "closed_total": "Fixed / Accepted",
        "included": "Included", "excluded_count": "Excluded",
        "report_link": "Printable report", "theme": "Theme", "jump": "Skip to findings",
        "overview": "Overview", "by_severity": "By severity", "by_category": "By category", "by_status": "By status",
        "count_basis": "Counts cover included findings only.",
        "filters_record_set": "Records", "included_set": "Included", "excluded_set": "Excluded", "all_records": "All",
        "all": "All", "search": "Search ID, title, location, text", "sort": "Sort",
        "sort_priority": "Priority", "sort_id": "ID", "reset": "Reset",
        "showing": "Showing {shown} of {total}", "no_matches": "No records match the filters.",
        "no_records": "No records.", "show_details": "Show details", "hide_details": "Hide details",
        "copy_llm": "Copy for LLM", "copied": "Copied", "copy_failed": "Copy failed", "link": "Link",
        "view_all": "View all findings", "queue_more": "Showing {shown} of {total} open findings.",
        "source_note": "Generated from the recorded report data; this page changes nothing.",
        "no_script": "This dashboard needs JavaScript. Read the printable report instead:",
    },
    "ja": {
        "kind": "診断", "title": "診断報告書", "dashboard_title": "診断結果", "running_footer": "診断報告書",
        "date": "日付", "assessor": "実施者", "scope": "範囲", "method": "方法", "commit": "コミット",
        "abstract": "要旨", "summary": "概要", "no_summary": "概要は記録されていません。",
        "severity": "重大度", "status": "状態", "confidence": "確度", "verdict": "判定",
        "category": "分類", "location": "場所", "title_col": "指摘", "action": "次の対応",
        "open_by_severity": "重大度別の未対応指摘", "open": "未対応", "closed": "修正済み・受容",
        "total": "合計", "limitations": "制約", "limitations_empty": "制約は記録されていません。",
        "priority": "優先順位", "priority_note": "未対応の指摘を重大度の高い順に示します。",
        "priority_caption": "優先順の未対応指摘", "ref": "参照",
        "no_open": "未対応の指摘はありません。", "no_findings": "指摘は記録されていません。",
        "decisions": "判断事項", "next_steps": "次の手順", "checked_ok": "問題が見つからなかった確認",
        "not_recorded": "記録されていません。", "coverage": "確認範囲",
        "coverage_note": "何を確認し、どのような結果だったかを示します。", "coverage_caption": "確認した観点",
        "perspective": "観点", "result": "結果", "note": "備考",
        "coverage_missing": "確認範囲は記録されていません。",
        "register": "指摘一覧", "register_note": "除外を除くすべての指摘を重大度順に示します。",
        "register_caption": "指摘一覧", "details": "指摘",
        "excluded": "除外した記録", "excluded_note": "記録はありますが、上の件数には含めていません。",
        "excluded_short": "除外", "snippet": "ソース抜粋", "references": "参考資料",
        "source": "ソース", "none": "—",
        "risk_summary": "対応が必要な High・Medium の未対応指摘が{n}件あります。",
        "open_summary": "未対応の指摘が{n}件あります（High・Medium はありません）。",
        "urgent": "未対応 High + Medium", "open_total": "未対応", "closed_total": "修正済み / 受容",
        "included": "対象", "excluded_count": "除外",
        "report_link": "印刷用報告書", "theme": "表示切替", "jump": "指摘一覧へ移動",
        "overview": "概要グラフ", "by_severity": "重大度別", "by_category": "分類別", "by_status": "状態別",
        "count_basis": "件数は除外を除く指摘のみを数えています。",
        "filters_record_set": "記録", "included_set": "対象", "excluded_set": "除外", "all_records": "すべて",
        "all": "すべて", "search": "ID・タイトル・場所・本文を検索", "sort": "並び順",
        "sort_priority": "優先度", "sort_id": "ID", "reset": "リセット",
        "showing": "{total}件中{shown}件を表示", "no_matches": "条件に一致する記録はありません。",
        "no_records": "記録はありません。", "show_details": "詳細を表示", "hide_details": "詳細を隠す",
        "copy_llm": "LLM 用にコピー", "copied": "コピーしました", "copy_failed": "コピーできませんでした",
        "link": "リンク",
        "view_all": "すべての指摘を見る", "queue_more": "未対応{total}件中{shown}件を表示しています。",
        "source_note": "記録されたレポートデータから生成しています。このページは何も変更しません。",
        "no_script": "このダッシュボードには JavaScript が必要です。印刷用報告書をご覧ください:",
    },
}
LABEL_KEYS = set().union(*(labels.keys() for labels in LABELS.values()))


class FormatError(Exception):
    pass


def _string(value, where):
    if not isinstance(value, str):
        raise FormatError(f"{where}: expected a string")
    if "\x00" in value:
        raise FormatError(f"{where}: expected Unicode text without NUL characters")
    if re.search(r"[\ud800-\udfff]", value):
        raise FormatError(f"{where}: expected Unicode text without surrogate code points")
    return value


def _text(obj, key, where, *, required=False):
    value = _string(obj.get(key, ""), f"{where}.{key}")
    if required and not value.strip():
        raise FormatError(f"{where}.{key}: required")
    return value


def _strings(data, key):
    value = data.get(key, [])
    if not isinstance(value, list):
        raise FormatError(f"{key}: expected a list of strings")
    for i, item in enumerate(value):
        _string(item, f"{key}[{i}]")
    return value


def http_url(value, where):
    _string(value, where)
    # Do not let urlsplit silently strip controls or accept a URL that a
    # browser interprets differently (notably backslashes in the authority).
    if any(char.isspace() or ord(char) < 32 or 127 <= ord(char) < 160 or char == "\\" for char in value):
        raise FormatError(f"{where}: expected an http(s) URL")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        valid = parts.scheme in ("http", "https") and bool(host)
        # Accessing port validates its numeric syntax and range.
        parts.port
        if valid:
            if re.search(r"%(?![0-9a-fA-F]{2})", host):
                valid = False
            else:
                # urlsplit separates components; it does not validate domain
                # names. Check decoded and NFKC-normalized host text so encoded
                # delimiters cannot hide an unusable host. Keep paths/queries
                # untouched and retain the original URL in the report. Python's
                # IDNA2003 codec rejects valid modern IDNs (e.g. RTL labels ending
                # in digits), so do not use it as a domain validity gate.
                decoded = unquote(host, encoding="utf-8", errors="strict")
                bracketed = parts.netloc.rsplit("@", 1)[-1].startswith("[")
                normalized = normalize("NFKC", decoded)
                forbidden = "#/<>?@[\\]^|\ufffd" + ("" if bracketed else ":%")
                valid = not any(char.isspace() or ord(char) < 32 or 127 <= ord(char) < 160
                                or char in forbidden for char in decoded + normalized)
    except ValueError:
        raise FormatError(f"{where}: expected an http(s) URL") from None
    if not valid:
        raise FormatError(f"{where}: expected an http(s) URL")
    return value


def _object(value, where):
    if not isinstance(value, dict):
        raise FormatError(f"{where}: expected an object")
    return value


def validate(data):
    """Check data against docs/format.md and return it; raises FormatError."""
    _object(data, "report")
    if data.get("format") != FORMAT:
        raise FormatError(f"format: expected {FORMAT!r}")
    meta = _object(data.get("meta"), "meta")
    for key in META_KEYS:
        _text(meta, key, "meta", required=key in ("project", "date"))
    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", meta["date"]):
            raise ValueError
        date.fromisoformat(meta["date"])
    except ValueError:
        raise FormatError("meta.date: expected a valid date in YYYY-MM-DD form") from None
    report = _object(data.get("report", {}), "report")
    for key in REPORT_KEYS:
        _text(report, key, "report")
    labels = _object(data.get("labels", {}), "labels")
    for key, value in labels.items():
        _string(key, "labels key")
        _string(value, f"labels.{key}")
    _text(data, "summary", "report")
    for key in LIST_KEYS:
        _strings(data, key)
    perspectives = data.get("perspectives", [])
    if not isinstance(perspectives, list):
        raise FormatError("perspectives: expected a list")
    for i, p in enumerate(perspectives):
        _object(p, f"perspectives[{i}]")
        _text(p, "name", f"perspectives[{i}]", required=True)
        _text(p, "result", f"perspectives[{i}]")
        _text(p, "note", f"perspectives[{i}]")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise FormatError("findings: expected a list")
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        _object(f, where)
        fid = _text(f, "id", where, required=True)
        if fid in seen:
            raise FormatError(f"{where}.id: duplicate {fid!r}")
        seen.add(fid)
        title = _text(f, "title", where, required=True)
        if LINE_BREAKS.search(title):
            raise FormatError(f"{where}.title: expected one line")
        if f.get("severity") not in SEVERITIES:
            raise FormatError(f"{where}.severity: expected one of {SEVERITIES}")
        if f.get("status") not in STATUSES:
            raise FormatError(f"{where}.status: expected one of {STATUSES}")
        for key in ("category", "location", "confidence", "verdict"):
            _text(f, key, where)
        if not isinstance(f.get("excluded", False), bool):
            raise FormatError(f"{where}.excluded: expected a boolean")
        if "action" in f:
            action = _object(f["action"], f"{where}.action")
            _text(action, "label", f"{where}.action", required=True)
            _text(action, "text", f"{where}.action")
        fields = f.get("fields", [])
        if not isinstance(fields, list):
            raise FormatError(f"{where}.fields: expected a list")
        for j, field in enumerate(fields):
            _object(field, f"{where}.fields[{j}]")
            _text(field, "label", f"{where}.fields[{j}]", required=True)
            _text(field, "text", f"{where}.fields[{j}]")
        if "snippet" in f:
            s = _object(f["snippet"], f"{where}.snippet")
            hit = s.get("hit")
            if (type(s.get("start")) is not int or not 1 <= s["start"] <= MAX_LINE_NUMBER
                    or not isinstance(s.get("lines"), list)
                    or not (isinstance(hit, list) and len(hit) == 2 and all(type(n) is int for n in hit))):
                raise FormatError(f"{where}.snippet: expected start >= 1, lines and hit [first, last]")
            if not 1 <= hit[0] <= hit[1] <= MAX_LINE_NUMBER:
                raise FormatError(f"{where}.snippet.hit: expected ordered positive line numbers <= {MAX_LINE_NUMBER}")
            if s["start"] + len(s["lines"]) - 1 > MAX_LINE_NUMBER:
                raise FormatError(f"{where}.snippet: displayed line numbers must be <= {MAX_LINE_NUMBER}")
            for j, line in enumerate(s["lines"]):
                _string(line, f"{where}.snippet.lines[{j}]")
                if LINE_BREAKS.search(line):
                    raise FormatError(f"{where}.snippet.lines[{j}]: expected one line")
        refs = f.get("references", [])
        if not isinstance(refs, list):
            raise FormatError(f"{where}.references: expected a list")
        for j, ref in enumerate(refs):
            _object(ref, f"{where}.references[{j}]")
            http_url(ref.get("url"), f"{where}.references[{j}].url")
            _text(ref, "type", f"{where}.references[{j}]")
            _text(ref, "title", f"{where}.references[{j}]")
    return data


def labels_for(data, lang):
    """Built-in labels for lang, then the report's own kind/title strings, then its overrides."""
    if not isinstance(lang, str) or lang not in LABELS:
        raise FormatError(f"lang: expected one of {list(LABELS)}")
    L = dict(LABELS[lang])
    names = data.get("report", {})
    L.update({k: names[k] for k in REPORT_KEYS if names.get(k)})
    L.update({k: v for k, v in data.get("labels", {}).items() if k in LABEL_KEYS})
    return L


def esc(s):
    return html.escape(str(s or ""))


def plural(L, key, n):
    """The label for count n; a `_one` variant carries the singular form."""
    return L[key + "_one" if n == 1 and key + "_one" in L else key].replace("{n}", str(n))


def anchor(index):
    return f"finding-{index + 1}"


def included(data):
    return [f for f in data["findings"] if not f.get("excluded")]


def priority(findings):
    """Open findings first, then by severity; ties keep their recorded order."""
    return sorted(findings, key=lambda f: (f["status"] != "Open", SEVERITIES.index(f["severity"])))


def counts(data):
    fs = included(data)
    by = {(s, st): 0 for s in SEVERITIES for st in STATUSES}
    for f in fs:
        by[(f["severity"], f["status"])] += 1
    open_count = sum(by[(s, "Open")] for s in SEVERITIES)
    urgent = by[("High", "Open")] + by[("Medium", "Open")]
    return {"by": by, "open": open_count, "urgent": urgent, "included": len(fs),
            "excluded": len(data["findings"]) - len(fs),
            "fixed": sum(by[(s, "Fixed")] for s in SEVERITIES),
            "accepted": sum(by[(s, "Accepted")] for s in SEVERITIES)}


def headline(data, L):
    c = counts(data)
    if not c["included"]:
        return L["no_findings"]
    if c["urgent"]:
        return plural(L, "risk_summary", c["urgent"])
    return plural(L, "open_summary", c["open"]) if c["open"] else L["no_open"]


def snippet_html(snippet):
    first, last = snippet["hit"]
    rows = []
    for i, line in enumerate(snippet["lines"]):
        n = snippet["start"] + i
        cls = " class='hit'" if first <= n <= last else ""
        rows.append(f"<span{cls}><b>{n:>5}</b> {esc(line)}</span>")
    return "<pre class='snippet'>" + "".join(rows) + "</pre>"


def refs_html(refs, L):
    if not refs:
        return ""
    items = "".join(f"<li><span class='rt'>{esc(r.get('type') or L['source'])}</span> "
                    f"<a href='{esc(r['url'])}'>{esc(r.get('title') or r['url'])}</a></li>" for r in refs)
    return f"<ul class='refs'>{items}</ul>"


def render_document(data, lang):
    """The printable report (report.html), typeset per docs/design.md; print it with pdf.to_pdf."""
    validate(data)
    L = labels_for(data, lang)
    m, c = data["meta"], counts(data)
    anchors = {id(f): anchor(i) for i, f in enumerate(data["findings"])}
    fs = priority(included(data))
    excluded = [f for f in data["findings"] if f.get("excluded")]

    def value(text):
        return esc(text) if str(text or "").strip() else esc(L["none"])

    def bullets(items, empty):
        return ("<ul>" + "".join(f"<li class='prose'>{esc(x)}</li>" for x in items) + "</ul>"
                if items else f"<p class='small'>{esc(L[empty])}</p>")

    meta = "".join(f"<p class='meta-line'><strong>{esc(L[k])}</strong> {esc(m[k])}</p>"
                   for k in META_KEYS[1:] if m.get(k))
    sev_head = "".join(f"<th scope='col' class='{s}'>{s}</th>" for s in SEVERITIES)
    def metric_cell(severity, statuses):
        n = sum(c["by"][(severity, st)] for st in statuses)
        urgent = statuses == ("Open",) and severity in ("High", "Medium") and n
        return f"<td class='metric-urgent'>{n}</td>" if urgent else f"<td>{n}</td>"

    metric_rows = "".join(f"<tr><th scope='row'>{esc(L[label])}</th>"
                          + "".join(metric_cell(s, statuses) for s in SEVERITIES) + "</tr>"
                          for label, statuses in (("open", ("Open",)), ("closed", ("Fixed", "Accepted"))))
    metrics = (f"<table class='metrics'><caption>{esc(L['open_by_severity'])}</caption>"
               f"<thead><tr><th scope='col'></th>{sev_head}</tr></thead><tbody>{metric_rows}</tbody></table>")

    open_fs = [f for f in fs if f["status"] == "Open"]
    queue_rows = "".join(
        f"<tr><td><a href='#{anchors[id(f)]}'>{esc(f['id'])}</a><br><span class='badge {f['severity']}'>{f['severity']}</span></td>"
        f"<td><div class='queue-title'>{esc(f['title'])}</div>"
        f"<div class='queue-location'><code>{esc(f.get('location'))}</code></div></td>"
        f"<td class='queue-action'>"
        + (f"<strong>{esc(f['action']['label'])}</strong>{esc(f['action'].get('text'))}" if f.get("action") else esc(L["none"]))
        + "</td></tr>" for f in open_fs)
    queue = (f"<table class='queue'><caption>{esc(L['priority_caption'])}</caption>"
             "<colgroup><col class='ref-col'><col class='finding-col'><col class='action-col'></colgroup>"
             f"<thead><tr><th scope='col'>{esc(L['ref'])}</th><th scope='col'>{esc(L['title_col'])}</th>"
             f"<th scope='col'>{esc(L['action'])}</th></tr></thead><tbody>{queue_rows}</tbody></table>"
             if open_fs else f"<p class='small'>{esc(L['no_open'])}</p>")

    lists = "".join(f"<section id='{k.replace('_', '-')}'><h2>{esc(L[k])}</h2>{bullets(data.get(k, []), 'not_recorded')}</section>"
                    for k in ("decisions", "next_steps") if data.get(k))

    coverage_rows = "".join(f"<tr><td>{esc(p['name'])}</td><td>{value(p.get('result'))}</td><td>{value(p.get('note'))}</td></tr>"
                            for p in data.get("perspectives", []))
    coverage = (f"<table class='coverage'><caption>{esc(L['coverage_caption'])}</caption>"
                "<colgroup><col class='perspective-col'><col class='result-col'><col class='note-col'></colgroup>"
                f"<thead><tr><th scope='col'>{esc(L['perspective'])}</th><th scope='col'>{esc(L['result'])}</th>"
                f"<th scope='col'>{esc(L['note'])}</th></tr></thead><tbody>{coverage_rows}</tbody></table>"
                if coverage_rows else f"<p class='small'>{esc(L['coverage_missing'])}</p>")

    index_rows = "".join(
        f"<tr role='row'><td role='cell' data-label='{esc(L['title_col'])}'><a class='index-title' href='#{anchors[id(f)]}'>{esc(f['title'])}</a>"
        f"<span class='index-id'>{esc(f['id'])}</span></td>"
        f"<td role='cell' data-label='{esc(L['severity'])}'><span class='badge {f['severity']}'>{f['severity']}</span></td>"
        f"<td role='cell' data-label='{esc(L['status'])}'>{esc(f['status'])}</td>"
        f"<td role='cell' data-label='{esc(L['location'])}'><code>{value(f.get('location'))}</code></td></tr>" for f in fs)
    index = (f"<table class='index' role='table'><caption>{esc(L['register_caption'])}</caption>"
             "<colgroup><col class='finding-col'><col class='severity-col'><col class='status-col'><col class='evidence-col'></colgroup>"
             f"<thead role='rowgroup'><tr role='row'><th scope='col' role='columnheader'>{esc(L['title_col'])}</th>"
             f"<th scope='col' role='columnheader'>{esc(L['severity'])}</th>"
             f"<th scope='col' role='columnheader'>{esc(L['status'])}</th>"
             f"<th scope='col' role='columnheader'>{esc(L['location'])}</th></tr></thead>"
             f"<tbody role='rowgroup'>{index_rows}</tbody></table>" if fs else f"<p class='small'>{esc(L['no_findings'])}</p>")

    def card(f):
        state = "".join(f"<tr><th scope='row'>{esc(L[k])}</th><td>"
                        + (f"<span class='badge {f['severity']}'>{f['severity']}</span>" if k == "severity" else value(f.get(k)))
                        + "</td></tr>" for k in ("severity", "status", "confidence", "verdict", "category", "location"))
        action = (f"<div class='finding-field'><h4>{esc(f['action']['label'])}</h4><p class='prose'>{esc(f['action'].get('text'))}</p></div>"
                  if f.get("action") and f["status"] == "Open" and not f.get("excluded") else "")
        fields = "".join(f"<div class='finding-field'><h4>{esc(x['label'])}</h4>"
                         + (f"<p class='prose'>{esc(x['text'])}</p>" if x.get("text", "").strip()
                            else f"<p class='empty-value'>{esc(L['not_recorded'])}</p>") + "</div>"
                         for x in f.get("fields", []))
        snippet = (f"<div class='finding-field'><h4>{esc(L['snippet'])}</h4>{snippet_html(f['snippet'])}</div>"
                   if f.get("snippet") else "")
        refs = (f"<div class='finding-field'><h4>{esc(L['references'])}</h4>{refs_html(f['references'], L)}</div>"
                if f.get("references") else "")
        cls = "finding excluded" if f.get("excluded") else f"finding sev-{f['severity']}"
        return (f"<article class='{cls}' id='{anchors[id(f)]}'><div class='finding-header'>"
                f"<span class='finding-id'>{esc(f['id'])}</span><h3>{esc(f['title'])}</h3>"
                f"<table class='finding-state'><tbody>{state}</tbody></table></div>"
                f"{action}{fields}{snippet}{refs}</article>")

    details = (f"<section id='finding-details'><h2>{esc(L['details'])}</h2>" + "".join(card(f) for f in fs) + "</section>"
               if fs else "")
    excluded_html = (f"<section class='excluded-section' id='excluded'><h2>{esc(L['excluded'])}</h2>"
                     f"<p class='section-note'>{esc(L['excluded_note'])}</p>" + "".join(card(f) for f in excluded) + "</section>"
                     if excluded else "")
    summary = data.get("summary", "").strip()
    return f"""<!doctype html>
<html lang="{esc(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(L['title'])} - {esc(m['project'])}</title><style>{style.document_css(L['running_footer'])}</style></head><body>
<header class="report-header"><p class="kicker">{esc(L['kind'])}</p><h1>{esc(L['title'])}</h1>
<p class="project">{esc(m['project'])}</p>{meta}</header>
<main>
<p class="lead prose">{esc(summary) if summary else esc(L['no_summary'])}</p>
<section class="summary-section" id="summary"><h2>{esc(L['summary'])}</h2><p>{esc(headline(data, L))}</p>{metrics}
<h3 class="limit-heading">{esc(L['limitations'])}</h3><div class="limits">{bullets(data.get('limitations', []), 'limitations_empty')}</div></section>
<section id="priority-queue"><h2>{esc(L['priority'])}</h2><p class="section-note">{esc(L['priority_note'])}</p>{queue}</section>
{lists}
<section id="recorded-coverage"><h2>{esc(L['coverage'])}</h2><p class="section-note">{esc(L['coverage_note'])}</p>{coverage}
<h3>{esc(L['checked_ok'])}</h3>{bullets(data.get('checked_ok', []), 'not_recorded')}</section>
<section id="finding-register"><h2>{esc(L['register'])}</h2><p class="section-note">{esc(L['register_note'])}</p>{index}</section>
{details}{excluded_html}
</main></body></html>
"""


DASHBOARD = """<!doctype html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
__CSS__
</style>
</head>
<body>
<a class="skip" href="#findings" data-l="jump"></a>
<main>
<header class="masthead"><span class="brand" data-l="kind"></span><div class="tools"><a class="button" href="report.html" data-l="report_link"></a><button id="theme" type="button" data-l="theme"></button></div></header>
<div class="hero"><div><div class="eyebrow" data-l="dashboard_title"></div><h1 id="h"></h1><div class="meta" id="meta"></div></div></div>
<div class="summary-banner" id="summary"></div>
<div class="cards" id="cards"></div>
<section aria-labelledby="priority-heading"><div class="section-head"><div><h2 id="priority-heading" data-l="priority"></h2><p data-l="priority_note"></p></div><a href="#findings" data-l="view_all"></a></div><div class="priority-list" id="priority"></div><p class="report-note" id="queue-note"></p></section>
<details class="panel coverage" id="coverage" open><summary><span data-l="coverage"></span><span class="small" id="coverage-count"></span></summary><p data-l="coverage_note"></p><dl class="scope-meta" id="scope-meta"></dl><div class="coverage-columns"><div id="perspectives"></div><div><h3 data-l="limitations"></h3><div id="limitations"></div></div></div></details>
<details class="chart-section"><summary data-l="overview"></summary><p class="section-note" data-l="count_basis"></p><div class="grid"><div class="panel"><h3 data-l="by_severity"></h3><div id="c-sev"></div></div><div class="panel"><h3 data-l="by_category"></h3><div id="c-cat"></div></div><div class="panel"><h3 data-l="by_status"></h3><div id="c-status"></div></div></div></details>
<section id="findings" tabindex="-1" aria-labelledby="findings-heading"><div class="section-head"><div><h2 id="findings-heading" data-l="register"></h2><p data-l="register_note"></p></div></div>
<div class="panel filters-panel"><div class="filters">
<label><span data-l="filters_record_set"></span><select id="f-scope"></select></label><label><span data-l="severity"></span><select id="f-sev"></select></label><label><span data-l="status"></span><select id="f-status"></select></label><label><span data-l="category"></span><select id="f-cat"></select></label>
<label class="search"><span data-l="search"></span><input id="f-q" type="search"></label><label><span data-l="sort"></span><select id="f-sort"></select></label>
</div><div class="filter-bottom"><p class="result-count" id="result-count" aria-live="polite"></p><button id="reset" type="button" data-l="reset"></button></div></div>
<div class="tablewrap"><table class="register" role="table"><thead role="rowgroup"><tr role="row"><th scope="col" role="columnheader">ID</th><th scope="col" role="columnheader" data-l="severity"></th><th scope="col" role="columnheader" data-l="confidence"></th><th scope="col" role="columnheader" data-l="status"></th><th scope="col" role="columnheader" data-l="verdict"></th><th scope="col" role="columnheader" data-l="title_col"></th><th scope="col" role="columnheader" data-l="category"></th></tr></thead><tbody id="rows" role="rowgroup"></tbody></table></div></section>
<div class="lists" id="lists"></div><footer class="footer" data-l="source_note"></footer>
<noscript><p>__NOSCRIPT__ <a href="report.html">__REPORT__</a></p></noscript>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
__JS__
</script>
</body>
</html>
"""


def _finding_payload(finding, index):
    """Copy only the validated contract fields; extensions never enter the page."""
    payload = {k: finding[k] for k in FINDING_KEYS if k in finding}
    payload["anchor"] = anchor(index)
    for key, keys in (("action", ("label", "text")), ("snippet", ("start", "hit", "lines"))):
        if key in finding:
            payload[key] = {k: finding[key][k] for k in keys if k in finding[key]}
    for key, keys in (("fields", ("label", "text")), ("references", ("type", "title", "url"))):
        if key in finding:
            payload[key] = [{k: item[k] for k in keys if k in item} for item in finding[key]]
    return payload


def render_dashboard(data, lang):
    """The interactive dashboard (dashboard.html): self-contained, offline, light and dark themes."""
    validate(data)
    L = labels_for(data, lang)
    payload = {
        "meta": {k: data["meta"][k] for k in META_KEYS if data["meta"].get(k)},
        "labels": L, "headline": headline(data, L), "summary": data.get("summary", ""),
        "findings": [_finding_payload(f, i) for i, f in enumerate(data["findings"])],
        "order": {"severity": SEVERITIES, "status": STATUSES},
        "perspectives": [{k: p[k] for k in ("name", "result", "note") if k in p} for p in data.get("perspectives", [])],
        **{k: data.get(k, []) for k in LIST_KEYS},
    }
    # Escape every less-than sign: <!-- and <script also change HTML parsing.
    blob = json.dumps(payload, ensure_ascii=False, allow_nan=False).replace("<", "\\u003c")
    replacements = {"__LANG__": esc(lang), "__TITLE__": esc(f"{L['dashboard_title']} - {data['meta']['project']}"),
                    "__NOSCRIPT__": esc(L["no_script"]), "__REPORT__": esc(L["report_link"]), "__DATA__": blob,
                    "__CSS__": style.dashboard_css(), "__JS__": style.dashboard_js()}
    # Substitute only template tokens, in one pass, never tokens inside report data.
    return re.sub(r"__(?:LANG|TITLE|NOSCRIPT|REPORT|DATA|CSS|JS)__", lambda mt: replacements[mt.group(0)], DASHBOARD)
