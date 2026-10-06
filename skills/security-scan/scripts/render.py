#!/usr/bin/env python3
"""Render a security-scan findings.json into a dashboard and an assessment document.

    python3 render.py findings.json --out DIR [--lang ja|en] [--no-pdf]

Writes DIR/dashboard.html (self-contained), DIR/assessment.html and DIR/assessment.pdf
(PDF via headless Chrome, or WeasyPrint as a fallback; set CHROME to pick a binary).
Standard library only.
"""
import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

SEVERITIES = ["High", "Medium", "Low", "Info"]
CONFIDENCES = ["Confirmed", "Environment-dependent", "Suspected"]
STATUSES = ["Open", "Fixed", "Accepted"]
VERDICTS = ["Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable"]
EXCLUDED = {"FalsePositive", "NotApplicable"}

LABELS = {
    "en": {
        "title": "Security Assessment Report",
        "dash_title": "Security Findings",
        "summary": "Executive summary",
        "scope": "Scope and method",
        "project": "System", "date": "Date", "assessor": "Assessor",
        "scope_l": "Scope", "method": "Method", "commit": "Revision",
        "overview": "Results overview",
        "by_sev": "By severity", "by_conf": "By confidence", "by_cat": "By category",
        "by_status": "By status",
        "details": "Findings",
        "location": "Location", "actor": "Actor", "request": "Request",
        "impact": "Impact", "fix": "Fix direction", "confidence": "Confidence",
        "category": "Category", "status": "Status", "severity": "Severity",
        "checked_ok": "Checked and sound",
        "decisions": "Decisions required",
        "limitations": "Limitations",
        "next_steps": "Recommended next steps",
        "none": "None.",
        "total": "Total findings",
        "open_hm": "Open High/Medium",
        "summary_line": "{total} findings: {counts}. {open_hm} High/Medium findings remain open.",
        "search": "Search", "all": "All",
        "count": "Count",
        "perspectives": "Coverage by perspective", "perspective": "Perspective",
        "result": "Result", "note": "Note", "title_col": "Title",
        "verdict": "Validation", "by_verdict": "By validation", "evidence": "Validation evidence",
        "references": "References", "snippet": "Source", "source_link": "View source",
        "excluded": "Excluded findings (false positive / not applicable)",
        "excluded_line": "{n} findings were excluded after validation and are listed at the end.",
    },
    "ja": {
        "title": "セキュリティ診断書",
        "dash_title": "セキュリティ診断結果",
        "summary": "総括",
        "scope": "診断対象と方法",
        "project": "対象システム", "date": "診断日", "assessor": "診断者",
        "scope_l": "範囲", "method": "方法", "commit": "リビジョン",
        "overview": "結果概要",
        "by_sev": "重大度別", "by_conf": "確度別", "by_cat": "分類別",
        "by_status": "対応状況別",
        "details": "指摘事項",
        "location": "場所", "actor": "実行できる者", "request": "リクエスト",
        "impact": "影響", "fix": "対応方針", "confidence": "確度",
        "category": "分類", "status": "状況", "severity": "重大度",
        "checked_ok": "問題がなかった確認項目",
        "decisions": "判断が必要な事項",
        "limitations": "制約事項",
        "next_steps": "推奨する対応順",
        "none": "なし",
        "total": "指摘総数",
        "open_hm": "未対応の高・中",
        "summary_line": "指摘は計{total}件（{counts}）。未対応の高・中リスクは{open_hm}件です。",
        "search": "検索", "all": "すべて",
        "count": "件数",
        "perspectives": "観点別の診断結果", "perspective": "観点",
        "result": "結果", "note": "備考", "title_col": "件名",
        "verdict": "妥当性", "by_verdict": "妥当性別", "evidence": "妥当性の根拠",
        "references": "参照", "snippet": "該当ソース", "source_link": "ソースを開く",
        "excluded": "除外した指摘（誤検知・対象外）",
        "excluded_line": "妥当性確認により{n}件を除外しました（末尾に記載）。",
    },
}


class SchemaError(Exception):
    pass


def load(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SchemaError(f"{path}: invalid JSON: {e}")
    if not isinstance(data, dict):
        raise SchemaError("top level must be an object")
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise SchemaError("meta: required object")
    for k in ("project", "date"):
        if not str(meta.get(k, "")).strip():
            raise SchemaError(f"meta.{k}: required")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise SchemaError("findings: required list")
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            raise SchemaError(f"{where}: must be an object")
        for k in ("id", "title", "severity", "confidence", "location"):
            if not str(f.get(k, "")).strip():
                raise SchemaError(f"{where}.{k}: required")
        if f["id"] in seen:
            raise SchemaError(f"{where}.id: duplicate {f['id']}")
        seen.add(f["id"])
        if f["severity"] not in SEVERITIES:
            raise SchemaError(f"{where}.severity: one of {SEVERITIES}")
        if f["confidence"] not in CONFIDENCES:
            raise SchemaError(f"{where}.confidence: one of {CONFIDENCES}")
        f.setdefault("status", "Open")
        if f["status"] not in STATUSES:
            raise SchemaError(f"{where}.status: one of {STATUSES}")
        for k in ("category", "actor", "request", "impact", "fix"):
            f[k] = str(f.get(k) or "")
        if not f["category"]:
            f["category"] = "Uncategorized"
        val = f.get("validation") or {}
        if not isinstance(val, dict):
            raise SchemaError(f"{where}.validation: must be an object")
        val.setdefault("verdict", "Unverified")
        if val["verdict"] not in VERDICTS:
            raise SchemaError(f"{where}.validation.verdict: one of {VERDICTS}")
        if val["verdict"] in ("Valid", "FalsePositive", "NotApplicable") and not str(val.get("evidence", "")).strip():
            raise SchemaError(f"{where}.validation.evidence: required when verdict is {val['verdict']}")
        val["evidence"] = str(val.get("evidence") or "")
        f["validation"] = val
        f["verdict"] = val["verdict"]
        refs = f.get("references") or []
        if not isinstance(refs, list):
            raise SchemaError(f"{where}.references: must be a list")
        clean = []
        for j, r in enumerate(refs):
            if isinstance(r, str):
                r = {"url": r}
            if not isinstance(r, dict) or not str(r.get("url", "")).startswith(("https://", "http://")):
                raise SchemaError(f"{where}.references[{j}].url: must be an http(s) URL")
            clean.append({"type": str(r.get("type") or "web"), "url": r["url"], "title": str(r.get("title") or "")})
        f["references"] = clean
    for k in ("checked_ok", "decisions", "limitations", "next_steps"):
        v = data.get(k, [])
        if not isinstance(v, list):
            raise SchemaError(f"{k}: must be a list")
        data[k] = [str(x) for x in v]
    lens = data.get("perspectives", [])
    if not isinstance(lens, list) or not all(isinstance(p, dict) and p.get("name") for p in lens):
        raise SchemaError("perspectives: list of objects with a name")
    data["perspectives"] = lens
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    # code findings before dependency advisories (D-*) at the same severity
    findings.sort(key=lambda f: (rank[f["severity"]], str(f["id"]).startswith("D-"), f["id"]))
    return data


def active(data):
    return [f for f in data["findings"] if f["verdict"] not in EXCLUDED]


def stats(data):
    fs = active(data)
    return {
        "verdict": Counter(f["verdict"] for f in data["findings"]),
        "excluded": len(data["findings"]) - len(fs),
        "severity": Counter(f["severity"] for f in fs),
        "confidence": Counter(f["confidence"] for f in fs),
        "category": Counter(f["category"] for f in fs),
        "status": Counter(f["status"] for f in fs),
        "open_hm": sum(1 for f in fs if f["status"] == "Open" and f["severity"] in ("High", "Medium")),
    }


def esc(s):
    return html.escape(str(s or ""))


ASSESSMENT_CSS = """
@page{size:A4;margin:18mm 16mm 20mm}
*{box-sizing:border-box}
body{margin:0;color:#1d1d1f;font:10.5pt/1.6 "Hiragino Sans","Noto Sans JP","Yu Gothic",system-ui,sans-serif}
.cover{height:240mm;display:flex;flex-direction:column;justify-content:center;page-break-after:always}
.cover h1{font-size:26pt;margin:0 0 6mm}
.cover .sub{font-size:14pt;color:#555;margin-bottom:14mm}
.cover table{width:auto}
h2{font-size:14pt;border-bottom:2px solid #3949ab;padding-bottom:2mm;margin:9mm 0 4mm;page-break-after:avoid}
h3{font-size:11.5pt;margin:6mm 0 2mm;page-break-after:avoid}
table{border-collapse:collapse;width:100%;margin:2mm 0 4mm}
th,td{border:1px solid #d5d5dc;padding:1.6mm 2.4mm;text-align:left;vertical-align:top}
th{background:#f0f1f7;font-weight:600}
.index td:first-child,.index td:nth-child(2){white-space:nowrap}
code{font-family:Menlo,monospace;font-size:9pt;word-break:break-all}
.badge{display:inline-block;padding:0 2.4mm;border-radius:3mm;color:#fff;font-weight:600;font-size:9pt}
.High{background:#c62828}.Medium{background:#ef6c00}.Low{background:#1565c0}.Info{background:#607d8b}
.finding{border:1px solid #d5d5dc;border-left:4px solid #999;border-radius:1.5mm;padding:2mm 4mm;margin:3mm 0;page-break-inside:avoid}
.finding.sev-High{border-left-color:#c62828}.finding.sev-Medium{border-left-color:#ef6c00}
.finding.sev-Low{border-left-color:#1565c0}.finding.sev-Info{border-left-color:#607d8b}
.finding dl{display:grid;grid-template-columns:28mm 1fr;gap:1mm 3mm;margin:2mm 0 0}
.finding dt{color:#666}.finding dd{margin:0;white-space:pre-wrap}
.summary{background:#f6f7fb;border-radius:2mm;padding:4mm 5mm}
.bar{display:inline-block;height:3mm;background:#3949ab;vertical-align:middle}
.snippet{white-space:pre;font:8pt/1.45 Menlo,monospace;background:#f6f7fb;border:1px solid #e1e3ee;border-radius:1.5mm;padding:2mm;margin:0;overflow:hidden}
.snippet span{display:block}.snippet .hit{background:#fff1c2}.snippet b{color:#999;font-weight:400}
.refs{margin:0;padding-left:4mm}.refs li{word-break:break-all}.refs a{color:#283593}
.rt{display:inline-block;min-width:16mm;color:#666;font-size:8.5pt}
"""


LOC_RE = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")
SECRET_RE = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)"
    r"[\w.-]*['\"]?\s*(?:=>|:=|[:=])\s*['\"]?)"
    r"(?!\$|[A-Za-z_][\w.]*\(|process\.env|os\.environ|null\b|None\b|true\b|false\b)([^'\"\s,;)]{4,})")


def redact(line):
    return SECRET_RE.sub(lambda m: m.group(1) + "********", line)


def attach_sources(data, repo, context=3):
    """Add a redacted source excerpt and an optional link for findings with path:line locations."""
    base = str(data["meta"].get("source_url") or "").rstrip("/")
    root = Path(repo).resolve() if repo else None
    for f in data["findings"]:
        m = LOC_RE.match(f["location"].strip())
        if not m:
            continue
        rel, start = m.group("path"), int(m.group("start"))
        end = int(m.group("end") or start)
        if base:
            f["source_link"] = f"{base}/{rel}#L{start}" + (f"-L{end}" if end != start else "")
        if not root:
            continue
        path = (root / rel).resolve()
        if root not in path.parents or not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        lo, hi = max(1, start - context), min(len(lines), end + context)
        f["snippet"] = {"start": lo, "hit": [start, end],
                        "lines": [redact(lines[i - 1])[:240] for i in range(lo, hi + 1)]}


def snippet_html(f):
    sn = f.get("snippet")
    if not sn:
        return ""
    rows = []
    for n, text in enumerate(sn["lines"], sn["start"]):
        hit = " class='hit'" if sn["hit"][0] <= n <= sn["hit"][1] else ""
        rows.append(f"<span{hit}><b>{n:>5}</b> {esc(text)}</span>")
    return "<pre class='snippet'>" + "".join(rows) + "</pre>"


def refs_html(f):
    items = []
    if f.get("source_link"):
        items.append(("source", f["source_link"], ""))
    items += [(r["type"], r["url"], r["title"]) for r in f.get("references", [])]
    if not items:
        return ""
    lis = "".join(f"<li><span class='rt'>{esc(t)}</span> <a href='{esc(u)}'>{esc(title or u)}</a></li>"
                  for t, u, title in items)
    return f"<ul class='refs'>{lis}</ul>"


def render_assessment_html(data, L, lang):
    m, st, fs = data["meta"], stats(data), active(data)
    excluded = [f for f in data["findings"] if f["verdict"] in EXCLUDED]
    meta_rows = [("project", m.get("project")), ("date", m.get("date")), ("assessor", m.get("assessor")),
                 ("scope_l", m.get("scope")), ("method", m.get("method")), ("commit", m.get("commit"))]
    meta_table = "".join(f"<tr><th>{esc(L[k])}</th><td>{esc(v)}</td></tr>" for k, v in meta_rows if v)
    counts = ", ".join(f"{s} {st['severity'][s]}" for s in SEVERITIES if st["severity"][s])
    summary = L["summary_line"].format(total=len(fs), counts=counts or "0", open_hm=st["open_hm"])
    if excluded:
        summary += " " + L["excluded_line"].format(n=len(excluded))

    def count_table(head, counter, order=None):
        keys = order or [k for k, _ in counter.most_common()]
        mx = max([counter[k] for k in keys] + [1])
        rows = "".join(
            f"<tr><td>{esc(k)}</td><td>{counter[k]}</td>"
            f"<td><span class='bar' style='width:{counter[k] / mx * 60:.1f}mm'></span></td></tr>"
            for k in keys)
        return f"<table><tr><th>{esc(head)}</th><th>{esc(L['count'])}</th><th></th></tr>{rows}</table>"

    lens = data.get("perspectives", [])
    lens_html = ""
    if lens:
        lens_rows = "".join(
            f"<tr><td>{esc(p.get('name'))}</td><td>{esc(p.get('result'))}</td><td>{esc(p.get('note'))}</td></tr>"
            for p in lens)
        lens_html = (f"<h2>{esc(L['perspectives'])}</h2><table><tr><th>{esc(L['perspective'])}</th>"
                     f"<th>{esc(L['result'])}</th><th>{esc(L['note'])}</th></tr>{lens_rows}</table>")

    index = "".join(
        f"<tr><td>{esc(f['id'])}</td><td><span class='badge {f['severity']}'>{esc(f['severity'])}</span></td>"
        f"<td>{esc(f['confidence'])}</td><td>{esc(f['verdict'])}</td><td>{esc(f['status'])}</td>"
        f"<td>{esc(f['title'])}</td></tr>" for f in fs)

    def card(f):
        items = [(k, esc(f[k])) for k in ("confidence", "verdict", "status", "category")]
        items.append(("location", f"<code>{esc(f['location'])}</code>"))
        items += [(k, esc(f[k])) for k in ("actor", "request", "impact", "fix") if f[k]]
        if f["validation"]["evidence"]:
            items.append(("evidence", esc(f["validation"]["evidence"])))
        if f.get("snippet"):
            items.append(("snippet", snippet_html(f)))
        if f.get("references") or f.get("source_link"):
            items.append(("references", refs_html(f)))
        dl = "".join(f"<dt>{esc(L[k])}</dt><dd>{v}</dd>" for k, v in items)
        return (f"<div class='finding sev-{f['severity']}'><h3>{esc(f['id'])} "
                f"<span class='badge {f['severity']}'>{esc(f['severity'])}</span> {esc(f['title'])}</h3><dl>{dl}</dl></div>")

    details = [card(f) for f in fs]
    excluded_html = (f"<h2>{esc(L['excluded'])}</h2>" + "".join(card(f) for f in excluded)) if excluded else ""

    def bullet(key):
        items = data[key]
        body = "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>" if items else f"<p>{esc(L['none'])}</p>"
        return f"<h2>{esc(L[key])}</h2>{body}"

    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8"><title>{esc(L['title'])} - {esc(m['project'])}</title>
<style>{ASSESSMENT_CSS}</style></head><body>
<section class="cover"><h1>{esc(L['title'])}</h1><div class="sub">{esc(m['project'])}</div>
<table>{meta_table}</table></section>
<h2>{esc(L['summary'])}</h2><div class="summary">{esc(summary)}</div>
<h2>{esc(L['overview'])}</h2>
{count_table(L['severity'], st['severity'], SEVERITIES)}
{count_table(L['category'], st['category'])}
{count_table(L['verdict'], st['verdict'], [v for v in VERDICTS if st['verdict'][v]])}
{lens_html}
<table class="index"><tr><th>ID</th><th>{esc(L['severity'])}</th><th>{esc(L['confidence'])}</th><th>{esc(L['verdict'])}</th><th>{esc(L['status'])}</th><th>{esc(L['title_col'])}</th></tr>{index}</table>
<h2>{esc(L['details'])}</h2>{''.join(details) or f"<p>{esc(L['none'])}</p>"}
{bullet('checked_ok')}{bullet('decisions')}{bullet('limitations')}{bullet('next_steps')}
{excluded_html}
</body></html>
"""


CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
]


def to_pdf(html_path, pdf_path):
    """Print html_path to pdf_path with headless Chrome, else WeasyPrint. Returns the engine used or None."""
    chrome = os.environ.get("CHROME")
    cands = [chrome] if chrome else CHROME_CANDIDATES
    for c in cands:
        exe = c if os.path.isabs(c) and os.path.exists(c) else shutil.which(c)
        if not exe:
            continue
        pdf = Path(pdf_path)
        pdf.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory() as profile:
            proc = subprocess.Popen(
                [exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                 f"--user-data-dir={profile}", f"--print-to-pdf={pdf}", Path(html_path).resolve().as_uri()],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Chrome on some platforms keeps running after the PDF is written:
            # wait for the file to appear and stop growing, then stop the process.
            last, deadline = -1, time.monotonic() + 120
            while time.monotonic() < deadline:
                if proc.poll() is not None and not pdf.exists():
                    break
                size = pdf.stat().st_size if pdf.exists() else -1
                if size > 0 and size == last:
                    break
                last = size
                time.sleep(0.5)
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if pdf.exists() and pdf.stat().st_size > 0:
            return "chrome"
    wp = shutil.which("weasyprint")
    if wp:
        r = subprocess.run([wp, str(html_path), str(pdf_path)], capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and Path(pdf_path).exists():
            return "weasyprint"
    return None


DASHBOARD = """<!doctype html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f7f7f8;--panel:#fff;--text:#1d1d1f;--muted:#6b6b73;--line:#e3e3e8;
--high:#c62828;--medium:#ef6c00;--low:#1565c0;--info:#607d8b;--accent:#3949ab}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121214;--panel:#1c1c20;--text:#ececf0;
--muted:#9a9aa3;--line:#2e2e34;--high:#ef5350;--medium:#ffa726;--low:#64b5f6;--info:#90a4ae;--accent:#8c9eff}}
:root[data-theme="dark"]{--bg:#121214;--panel:#1c1c20;--text:#ececf0;--muted:#9a9aa3;--line:#2e2e34;
--high:#ef5350;--medium:#ffa726;--low:#64b5f6;--info:#90a4ae;--accent:#8c9eff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}
.meta{color:var(--muted);margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .n{font-size:28px;font-weight:700}
.card .l{color:var(--muted);font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.panel h2{font-size:14px;margin:0 0 10px}
.bar{display:grid;grid-template-columns:minmax(80px,40%) 1fr 32px;gap:8px;align-items:center;margin:6px 0}
.bar .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .track{background:var(--line);border-radius:4px;height:10px;overflow:hidden}
.bar .fill{height:100%;background:var(--accent)}
.bar .v{text-align:right;color:var(--muted)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.filters select,.filters input{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
.filters input{flex:1;min-width:160px}
.tablewrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:720px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}
tr.row{cursor:pointer}
tr.row:hover{background:color-mix(in srgb,var(--accent) 6%,transparent)}
tr.detail td{background:color-mix(in srgb,var(--line) 35%,transparent)}
tr.detail dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}
tr.detail dt{color:var(--muted)}
tr.detail dd{margin:0;white-space:pre-wrap}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.High{background:var(--high)}.Medium{background:var(--medium)}.Low{background:var(--low)}.Info{background:var(--info)}
.lists{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:16px}
.lists ul{margin:0;padding-left:18px}
.empty{color:var(--muted);padding:16px}
.snippet{margin:0;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);overflow-x:auto;font:12px/1.5 ui-monospace,Menlo,monospace;white-space:pre}
.snippet span{display:block}.snippet .hit{background:color-mix(in srgb,var(--medium) 22%,transparent)}.snippet b{color:var(--muted);font-weight:400}
.refs{margin:0;padding-left:18px}.refs li{word-break:break-all}.refs a{color:var(--accent)}
.rt{display:inline-block;min-width:64px;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<main>
<h1 id="h"></h1>
<div class="meta" id="meta"></div>
<div class="cards" id="cards"></div>
<div class="grid">
  <div class="panel"><h2 data-l="by_sev"></h2><div id="c-sev"></div></div>
  <div class="panel"><h2 data-l="by_conf"></h2><div id="c-conf"></div></div>
  <div class="panel"><h2 data-l="by_cat"></h2><div id="c-cat"></div></div>
  <div class="panel"><h2 data-l="by_status"></h2><div id="c-status"></div></div>
  <div class="panel"><h2 data-l="by_verdict"></h2><div id="c-verdict"></div></div>
</div>
<div class="filters">
  <select id="f-sev"></select><select id="f-conf"></select><select id="f-cat"></select><select id="f-status"></select><select id="f-verdict"></select>
  <input id="f-q" type="search">
</div>
<div class="tablewrap"><table><thead><tr>
<th>ID</th><th data-l="severity"></th><th data-l="confidence"></th><th data-l="status"></th>
<th data-l="verdict"></th><th data-l="title_col"></th><th data-l="category"></th><th data-l="location"></th></tr></thead>
<tbody id="rows"></tbody></table></div>
<div class="lists" id="lists"></div>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent);
var L=D.labels, ALL=D.findings, F=ALL.filter(function(f){return D.excluded_verdicts.indexOf(f.verdict)<0;}), SEV=D.order.severity, CONF=D.order.confidence, ST=D.order.status;
function el(t,a,txt){var e=document.createElement(t);if(a)for(var k in a)e.setAttribute(k,a[k]);if(txt!=null)e.textContent=txt;return e;}
document.title=L.dash_title+' - '+D.meta.project;
document.getElementById('h').textContent=L.dash_title+' - '+D.meta.project;
document.getElementById('meta').textContent=[D.meta.date,D.meta.assessor,D.meta.scope,D.meta.method].filter(Boolean).join(' / ');
document.querySelectorAll('[data-l]').forEach(function(e){e.textContent=L[e.getAttribute('data-l')];});
function count(key){var c={};F.forEach(function(f){c[f[key]]=(c[f[key]]||0)+1;});return c;}
var cs=count('severity');
var cards=[[L.total,F.length,''],[L.open_hm,D.open_hm,'']].concat(SEV.map(function(s){return [s,cs[s]||0,s];}));
cards.forEach(function(c){var d=el('div',{'class':'card'});var n=el('div',{'class':'n'},c[1]);
if(c[2])n.style.color='var(--'+c[2].toLowerCase()+')';d.appendChild(n);d.appendChild(el('div',{'class':'l'},c[0]));
document.getElementById('cards').appendChild(d);});
function bars(id,key,order,colored){var c=count(key),keys=order||Object.keys(c).sort(function(a,b){return c[b]-c[a];});
var max=Math.max.apply(null,keys.map(function(k){return c[k]||0;}).concat([1]));var box=document.getElementById(id);
keys.forEach(function(k){var r=el('div',{'class':'bar'});r.appendChild(el('span',{'class':'t',title:k},k));
var t=el('div',{'class':'track'}),f=el('div',{'class':'fill'});f.style.width=((c[k]||0)/max*100)+'%';
if(colored)f.style.background='var(--'+k.toLowerCase()+')';t.appendChild(f);r.appendChild(t);
r.appendChild(el('span',{'class':'v'},c[k]||0));box.appendChild(r);});}
bars('c-sev','severity',SEV,true);bars('c-conf','confidence',CONF);bars('c-cat','category');bars('c-status','status',ST);(function(){var keep=F;F=ALL;bars('c-verdict','verdict',D.order.verdict.filter(function(x){return ALL.some(function(f){return f.verdict===x;});}));F=keep;})();
function opts(id,label,vals){var s=document.getElementById(id);s.appendChild(el('option',{value:''},label+': '+L.all));
vals.forEach(function(v){s.appendChild(el('option',{value:v},v));});s.onchange=draw;}
var cats=Object.keys(count('category')).sort();
opts('f-sev',L.severity,SEV);opts('f-conf',L.confidence,CONF);opts('f-cat',L.category,cats);opts('f-status',L.status,ST);opts('f-verdict',L.verdict,D.order.verdict);
var q=document.getElementById('f-q');q.placeholder=L.search;q.oninput=draw;
function v(id){return document.getElementById(id).value;}
function draw(){var tb=document.getElementById('rows');tb.textContent='';var term=q.value.toLowerCase();
var pool=v('f-verdict')?ALL:F;var shown=pool.filter(function(f){return (!v('f-sev')||f.severity===v('f-sev'))&&(!v('f-conf')||f.confidence===v('f-conf'))
&&(!v('f-cat')||f.category===v('f-cat'))&&(!v('f-status')||f.status===v('f-status'))&&(!v('f-verdict')||f.verdict===v('f-verdict'))
&&(!term||JSON.stringify(f).toLowerCase().indexOf(term)>=0);});
if(!shown.length){var tr=el('tr'),td=el('td',{colspan:8,'class':'empty'},L.none);tr.appendChild(td);tb.appendChild(tr);return;}
shown.forEach(function(f){var tr=el('tr',{'class':'row'});tr.appendChild(el('td',null,f.id));
var sd=el('td');sd.appendChild(el('span',{'class':'badge '+f.severity},f.severity));tr.appendChild(sd);
tr.appendChild(el('td',null,f.confidence));tr.appendChild(el('td',null,f.status));tr.appendChild(el('td',null,f.verdict));tr.appendChild(el('td',null,f.title));
tr.appendChild(el('td',null,f.category));var lc=el('td');lc.appendChild(el('code',null,f.location));tr.appendChild(lc);
var dt=el('tr',{'class':'detail'});dt.hidden=true;var td=el('td',{colspan:8}),dl=el('dl');
['actor','request','impact','fix'].forEach(function(k){if(f[k]){dl.appendChild(el('dt',null,L[k]));dl.appendChild(el('dd',null,f[k]));}});
if(f.validation&&f.validation.evidence){dl.appendChild(el('dt',null,L.evidence));dl.appendChild(el('dd',null,f.validation.evidence));}
if(f.snippet){var pre=el('pre',{'class':'snippet'});f.snippet.lines.forEach(function(t,i){var n=f.snippet.start+i;
var ln=el('span',{'class':(n>=f.snippet.hit[0]&&n<=f.snippet.hit[1])?'hit':''});ln.appendChild(el('b',null,(n+'').padStart(5,' ')+' '));
ln.appendChild(document.createTextNode(t));pre.appendChild(ln);});dl.appendChild(el('dt',null,L.snippet));var sd=el('dd');sd.appendChild(pre);dl.appendChild(sd);}
var refs=(f.source_link?[{type:'source',url:f.source_link,title:L.source_link}]:[]).concat(f.references||[]);
if(refs.length){var ul=el('ul',{'class':'refs'});refs.forEach(function(r){var li=el('li');li.appendChild(el('span',{'class':'rt'},r.type));
var a=el('a',{href:r.url,target:'_blank',rel:'noopener noreferrer'},r.title||r.url);li.appendChild(a);ul.appendChild(li);});
dl.appendChild(el('dt',null,L.references));var rd=el('dd');rd.appendChild(ul);dl.appendChild(rd);}
td.appendChild(dl);dt.appendChild(td);tr.onclick=function(){dt.hidden=!dt.hidden;};tb.appendChild(tr);tb.appendChild(dt);});}
draw();
if(D.perspectives.length){var pp=el('div',{'class':'panel'});pp.style.gridColumn='1/-1';
pp.appendChild(el('h2',null,L.perspectives));var tw=el('div',{'class':'tablewrap'}),pt=el('table'),hr=el('tr');
[L.perspective,L.result,L.note].forEach(function(h){hr.appendChild(el('th',null,h));});pt.appendChild(hr);
D.perspectives.forEach(function(p){var r=el('tr');[p.name,p.result,p.note].forEach(function(x){r.appendChild(el('td',null,x||''));});pt.appendChild(r);});
tw.appendChild(pt);pp.appendChild(tw);document.getElementById('lists').appendChild(pp);}
['checked_ok','decisions','limitations','next_steps'].forEach(function(k){var p=el('div',{'class':'panel'});
p.appendChild(el('h2',null,L[k]));var items=D[k];if(!items.length)p.appendChild(el('div',{'class':'empty'},L.none));
else{var ul=el('ul');items.forEach(function(x){ul.appendChild(el('li',null,x));});p.appendChild(ul);}
document.getElementById('lists').appendChild(p);});
})();
</script>
</body>
</html>
"""


def render_dashboard(data, L, lang):
    payload = {
        "meta": data["meta"], "findings": data["findings"], "labels": L,
        "open_hm": stats(data)["open_hm"],
        "order": {"severity": SEVERITIES, "confidence": CONFIDENCES, "status": STATUSES, "verdict": VERDICTS},
        "excluded_verdicts": sorted(EXCLUDED),
        **{k: data[k] for k in ("checked_ok", "decisions", "limitations", "next_steps", "perspectives")},
    }
    blob = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    title = html.escape(f"{L['dash_title']} - {data['meta']['project']}")
    return DASHBOARD.replace("__LANG__", lang).replace("__TITLE__", title).replace("__DATA__", blob)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    p.add_argument("--repo", help="audited repository root: embeds redacted source excerpts for path:line locations")
    a = p.parse_args(argv)
    try:
        data = load(a.findings)
    except (SchemaError, OSError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    attach_sources(data, a.repo)
    L = LABELS[a.lang]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "dashboard.html").write_text(render_dashboard(data, L, a.lang), encoding="utf-8")
    html_path = out / "assessment.html"
    html_path.write_text(render_assessment_html(data, L, a.lang), encoding="utf-8")
    print(f"wrote {out / 'dashboard.html'}")
    print(f"wrote {html_path}")
    if a.no_pdf:
        return 0
    engine = to_pdf(html_path, out / "assessment.pdf")
    if not engine:
        print("render.py: no PDF engine found (Chrome/Chromium or weasyprint); "
              "assessment.html is ready to print", file=sys.stderr)
        return 3
    print(f"wrote {out / 'assessment.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
