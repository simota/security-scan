#!/usr/bin/env python3
"""Record, carry forward and summarize triage decisions on a finished findings.json.

    python3 triage.py set     FINDINGS ID [ID ...] [--status Open|Fixed|Accepted] [--reason TEXT]
                              [--owner NAME] [--review-by YYYY-MM-DD] [--ticket URL] [--date YYYY-MM-DD]
    python3 triage.py apply   FINDINGS DECISIONS [--date YYYY-MM-DD]
    python3 triage.py carry   BASELINE FINDINGS [--as-of YYYY-MM-DD] [--dry-run] [--json OUT]
    python3 triage.py summary FINDINGS [--as-of YYYY-MM-DD] [--due-within DAYS] [--markdown OUT]
                              [--json OUT] [--lang en|ja] [--fail-on-overdue]

A finding's `status` says where it stands; its `triage` record says who
decided that, why, and until when:

    "triage": {"status": "Accepted", "reason": "...", "owner": "...", "decided": "YYYY-MM-DD",
               "review_by": "YYYY-MM-DD", "ticket": "https://...", "history": [...]}

- `set` records one decision for one or more findings (bulk). `Accepted`
  needs a reason and a review date; `Fixed` needs a reason (the change that
  fixed it); moving back to `Open` from either needs a reason. Without
  `--status` the finding keeps its status and only the owner or ticket
  changes (an assignment). Owner and ticket carry over from the previous
  decision unless given (`--owner ""` clears it); the previous decision is
  kept in `history`.
- `apply` records a file of decisions: `{"decisions": [{"id": "F-001",
  "status": "Accepted", "reason": "...", "review_by": "..."}, ...]}`. Every
  decision is checked first; one refused decision writes nothing.
- `carry` copies decisions from an earlier assessment onto the matching
  findings of a later one (the matching is compare.py's). A risk acceptance
  is carried only while it is unexpired and the severity has not risen;
  owners and tickets are carried for open work. A baseline `Fixed` finding
  that is reported again is a regression and stays Open. Findings that
  already have a decision in FINDINGS keep it. Nothing else changes: verdicts,
  confidence and evidence are never carried.
- `summary` lists the remediation state: open work by severity and owner,
  open High/Medium without an owner, acceptances whose review date has passed
  or falls within `--due-within` days (default 30), and Accepted records that
  lack a reason or review date. `--fail-on-overdue` exits 1 when any
  acceptance is overdue, so CI can hold a release on expired risk decisions.

Triage records a human decision about remediation. It is not evidence: a
recorded `Fixed` stays a claim until a retest record verifies it
(`reference/fix-verification.md`), and an acceptance never changes the
verdict. Ruled-out (FalsePositive / NotApplicable) findings are not triaged:
change their validation instead. Writes use findings.py's writer lock and
atomic replace; re-render the reports afterwards.

Exit codes: 0 done, 1 a decision was refused (reason on stderr) or
`--fail-on-overdue` found an overdue acceptance, 2 unreadable or invalid
input, unsafe output path, or a concurrent change.
"""
import argparse
import copy
import datetime
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report_schema  # noqa: E402
from compare import match  # noqa: E402
from contract_check import read_regular  # noqa: E402
from expert import derive_expert  # noqa: E402
from finding_keys import included  # noqa: E402
from findings import MergeConflict, read_json, write_report  # noqa: E402
from output_files import OutputError, shareable, write_file  # noqa: E402
from payloads import PAYLOAD  # noqa: E402
from secret_redaction import JWT_RE, TOKEN_RE, redact  # noqa: E402

RANK = {s: i for i, s in enumerate(report_schema.SEVERITIES)}
DECISION_KEYS = {"id", "status", "reason", "owner", "review_by", "ticket"}
MAX_REASON = 2000
MAX_LABEL = 200
# Query or fragment parameters that carry credentials in a link.
SECRET_PARAM = re.compile(r"[?#&](?:[a-z_]*token|key|apikey|api_key|secret|password|sig|signature|auth)=",
                          re.IGNORECASE)


class Refused(Exception):
    pass


def today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_date(value, flag):
    try:
        return report_schema.iso_date(value, flag)
    except report_schema.SchemaError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


# --- reading and writing -------------------------------------------------------

def findings_path(path):
    path = Path(path)
    return path / "findings.json" if path.is_dir() else path


def read_raw(path):
    """The exact bytes, the raw record (written back) and a validated copy (read)."""
    original = read_regular(path)
    raw = read_json(path, original)
    if not isinstance(raw, dict):
        raise report_schema.SchemaError(f"{path}: top level must be an object")
    checked = report_schema.validate_data(copy.deepcopy(raw))
    return original, raw, checked


def save(path, raw, original):
    """Validate the whole record as findings.py merge does, then replace it atomically."""
    report_schema.validate_data(copy.deepcopy(raw))
    derive_expert(raw, report_schema.SchemaError)
    write_report(path, raw, original)


def raw_findings(raw):
    return {f["id"]: f for f in raw["findings"] if isinstance(f, dict) and isinstance(f.get("id"), str)}


# --- recording a decision ------------------------------------------------------

def text_problems(where, value, limit, one_line, url=False):
    if not isinstance(value, str):
        return [f"{where}: must be a string"]
    problems = []
    if len(value) > limit:
        problems.append(f"{where}: longer than {limit} characters")
    if one_line and any(report_schema.invisible_or_control(ch) for ch in value):
        problems.append(f"{where}: must be one line without control characters")
    if PAYLOAD.search(value):
        problems.append(f"{where}: contains a literal attack string; describe the decision instead")
    if url:
        # Links are checked whole: a token in the query or fragment is still a token.
        if TOKEN_RE.search(unquote(value)) or JWT_RE.search(unquote(value)) or SECRET_PARAM.search(value):
            problems.append(f"{where}: looks like it holds a secret value; link without the token")
    elif any(redact(line) != line for line in value.split("\n")):
        problems.append(f"{where}: looks like it holds a secret value; refer to it without the value")
    return problems


def decide(finding, decision, decided):
    """The finding's new triage record for DECISION, or Refused with every problem."""
    ident = finding["id"]
    current = finding.get("status", "Open")
    previous = finding.get("triage") if isinstance(finding.get("triage"), dict) else None
    problems = []
    if not included(finding):
        problems.append(f"{ident}: ruled out ({finding['validation']['verdict']}); change its validation, not its triage")
    status = decision.get("status") or current
    if status not in report_schema.STATUSES:
        problems.append(f"{ident}: status must be one of {report_schema.STATUSES}")
    for key, limit, one_line in (("reason", MAX_REASON, False), ("owner", MAX_LABEL, True),
                                 ("review_by", 10, True), ("ticket", 2048, True)):
        if key in decision and decision[key] is not None:
            problems += text_problems(f"{ident}.{key}", decision[key], limit, one_line, url=key == "ticket")
    if problems:
        raise Refused(problems)
    reason = (decision.get("reason") or "").strip()
    inherited = previous or {}
    owner = decision["owner"] if decision.get("owner") is not None else inherited.get("owner", "")
    ticket = decision["ticket"] if decision.get("ticket") is not None else inherited.get("ticket", "")
    review_by = decision.get("review_by") or ""
    if status == "Accepted":
        if not reason:
            problems.append(f"{ident}: Accepted needs --reason (why the risk is acceptable)")
        if not review_by:
            problems.append(f"{ident}: Accepted needs --review-by (when the acceptance is reviewed again)")
    elif review_by:
        problems.append(f"{ident}: --review-by applies to Accepted only")
    if status == "Fixed" and not reason:
        problems.append(f"{ident}: Fixed needs --reason (the change that fixed it, e.g. a commit or pull request)")
    if status == "Open" and current != "Open" and not reason:
        problems.append(f"{ident}: reopening a {current} finding needs --reason")
    if review_by:
        try:
            if report_schema.iso_date(review_by, "review_by") < decided:
                problems.append(f"{ident}: --review-by {review_by} is before the decision date {decided}")
        except report_schema.SchemaError as exc:
            problems.append(f"{ident}: {exc}")
    if ticket:
        try:
            report_schema.http_url(ticket, "ticket")
        except report_schema.SchemaError:
            problems.append(f"{ident}: --ticket must be an absolute http(s) URL without credentials")
    if status == current and not reason and owner == inherited.get("owner", "") \
            and ticket == inherited.get("ticket", "") and not review_by:
        problems.append(f"{ident}: nothing to record; the decision is unchanged")
    if problems:
        raise Refused(problems)
    record = {"status": status, "decided": decided.isoformat()}
    for key, value in (("reason", reason), ("owner", owner), ("review_by", review_by), ("ticket", ticket)):
        if value:
            record[key] = value
    history = list(inherited.get("history", []))
    if previous:
        history.append({k: v for k, v in previous.items() if k != "history"})
    if history:
        record["history"] = history
    return record


def record_decisions(path, decisions, decided):
    """Check every decision, then write them all at once (or nothing)."""
    original, raw, checked = read_raw(path)
    by_id = raw_findings(raw)
    validated = {f["id"]: f for f in checked["findings"]}
    problems, updates, seen = [], {}, set()
    for decision in decisions:
        ident = decision.get("id")
        if ident in seen:
            problems.append(f"{ident}: more than one decision in one call")
            continue
        seen.add(ident)
        if ident not in by_id:
            problems.append(f"{ident}: no such finding in {path}")
            continue
        view = {**validated[ident], "triage": by_id[ident].get("triage")}
        try:
            updates[ident] = decide(view, decision, decided)
        except Refused as exc:
            problems += exc.args[0]
    if problems:
        raise Refused(problems)
    for ident, record in updates.items():
        by_id[ident]["status"] = record["status"]
        by_id[ident]["triage"] = record
    save(path, raw, original)
    return updates


def load_decisions(path):
    data = read_json(path)
    entries = data.get("decisions") if isinstance(data, dict) else data
    if isinstance(data, dict) and data.keys() - {"decisions"}:
        raise report_schema.SchemaError(f"{path}: only a `decisions` list is supported")
    if not isinstance(entries, list) or not entries:
        raise report_schema.SchemaError(f"{path}: needs a nonempty `decisions` list")
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise report_schema.SchemaError(f"{path}: decisions[{i}] needs an `id`")
        unknown = entry.keys() - DECISION_KEYS
        if unknown:
            raise report_schema.SchemaError(f"{path}: decisions[{i}]: unsupported keys {sorted(unknown)}")
    return entries


# --- carrying decisions to a rescan --------------------------------------------

def carry_plan(base, cur_checked, cur_raw, as_of):
    """What `carry` would record, and why each other matched decision is not carried."""
    pairs = match(base["findings"], cur_checked["findings"])
    raw_by_id = raw_findings(cur_raw)
    plan = {"carried": [], "assigned": [], "not_carried": [], "kept": []}
    for i, j, _ in sorted(pairs, key=lambda p: cur_checked["findings"][p[1]]["id"]):
        old, new = base["findings"][i], cur_checked["findings"][j]
        old_triage = old.get("triage") if isinstance(old.get("triage"), dict) else None
        entry = {"id": new["id"], "baseline_id": old["id"], "severity": new["severity"],
                 "title": shareable(new["title"]), "baseline_status": old["status"]}
        if not old_triage and old["status"] == "Open":
            continue
        if not included(new):
            continue
        if "triage" in raw_by_id[new["id"]] or new["status"] != "Open":
            # A decision or status recorded in the current run is the requester's latest word.
            plan["kept"].append(entry)
            continue
        carried_from = {"baseline_id": old["id"], "date": base["meta"].get("date", ""),
                        "project": base["meta"].get("project", "")}
        assignment = {k: old_triage[k] for k in ("owner", "ticket") if old_triage and old_triage.get(k)}
        reason = None
        if old["status"] == "Accepted":
            if not old_triage:
                reason = "accepted_unrecorded"
            elif report_schema.acceptance_expired(old, as_of):
                reason = "acceptance_expired"
            elif RANK[new["severity"]] < RANK[old["severity"]]:
                reason = "severity_raised"
            else:
                record = {k: v for k, v in old_triage.items()}
                record["carried_from"] = carried_from
                plan["carried"].append({**entry, "record": record})
                continue
        elif old["status"] == "Fixed":
            reason = "regressed_fix"
        if reason:
            plan["not_carried"].append({**entry, "reason": reason})
        if assignment:
            record = {"status": "Open", "decided": as_of.isoformat(), **assignment, "carried_from": carried_from}
            if old_triage:
                record["history"] = [*old_triage.get("history", []),
                                     {k: v for k, v in old_triage.items() if k != "history"}]
            plan["assigned"].append({**entry, "record": record})
    return plan


def apply_plan(path, plan, cur_raw, original):
    by_id = raw_findings(cur_raw)
    for item in plan["carried"] + plan["assigned"]:
        by_id[item["id"]]["status"] = item["record"]["status"]
        by_id[item["id"]]["triage"] = item["record"]
    save(path, cur_raw, original)


# --- remediation summary -------------------------------------------------------

LABELS = {
    "en": {
        "title": "Remediation status", "as_of": "As of", "by_status": "Included findings by status",
        "col_status": "Status", "col_id": "ID", "col_sev": "Severity", "col_title": "Title",
        "col_owner": "Owner", "col_review": "Review by", "col_open": "Open", "col_hm": "of which High/Medium",
        "col_ticket": "Ticket", "col_reason": "Reason", "col_retest": "Retest verified",
        "unassigned": "Open High and Medium findings without an owner",
        "overdue": "Acceptances past their review date", "due": "Acceptances due for review within {days} days",
        "unrecorded": "Accepted findings without a recorded reason or review date",
        "owners": "Open work by owner", "nobody": "(no owner)", "none": "None.",
        "fixed": "Recorded Fixed", "fixed_note": "A recorded Fixed is a claim until a retest record verifies it.",
        "note": "Triage records decisions; it does not change verdicts, confidence or verification.",
    },
    "ja": {
        "title": "対応状況", "as_of": "基準日", "by_status": "対応状況別の指摘数（除外を除く）",
        "col_status": "対応状況", "col_id": "ID", "col_sev": "深刻度", "col_title": "タイトル",
        "col_owner": "担当", "col_review": "見直し期限", "col_open": "未対応", "col_hm": "うち High/Medium",
        "col_ticket": "チケット", "col_reason": "理由", "col_retest": "再検査で確認済み",
        "unassigned": "担当者が決まっていない未対応の High・Medium",
        "overdue": "見直し期限を過ぎたリスク受容", "due": "{days} 日以内に見直し期限を迎えるリスク受容",
        "unrecorded": "理由または見直し期限が記録されていない Accepted",
        "owners": "担当者別の未対応件数", "nobody": "（担当なし）", "none": "なし。",
        "fixed": "Fixed と記録された指摘", "fixed_note": "Fixed の記録は、再検査の記録で確認されるまでは申告です。",
        "note": "トリアージは判断の記録です。検証判定・確度・検証の根拠は変更しません。",
    },
}


def brief(f):
    triage = f.get("triage") if isinstance(f.get("triage"), dict) else {}
    return {"id": f["id"], "severity": f["severity"], "status": f["status"], "title": shareable(f["title"]),
            "owner": shareable(triage.get("owner", "")), "review_by": triage.get("review_by", ""),
            "ticket": triage.get("ticket", ""), "reason": shareable(triage.get("reason", "")),
            "retest": (f.get("_verification") or {}).get("retest", "not_requested")}


def summarize(data, as_of, due_within=30):
    fs = [f for f in data["findings"] if included(f)]
    horizon = as_of + datetime.timedelta(days=due_within)
    by_status = {s: {sev: 0 for sev in report_schema.SEVERITIES} for s in report_schema.STATUSES}
    for f in fs:
        by_status[f["status"]][f["severity"]] += 1
    open_fs = [f for f in fs if f["status"] == "Open"]
    accepted = [f for f in fs if f["status"] == "Accepted"]
    recorded = [f for f in accepted if isinstance(f.get("triage"), dict) and f["triage"].get("review_by")]
    owners = {}
    for f in open_fs:
        owner = (f.get("triage") or {}).get("owner", "") if isinstance(f.get("triage"), dict) else ""
        row = owners.setdefault(owner, {"owner": shareable(owner), "open": 0, "high_medium": 0})
        row["open"] += 1
        row["high_medium"] += f["severity"] in ("High", "Medium")
    return {
        "summary_version": 1, "as_of": as_of.isoformat(), "due_within_days": due_within,
        "project": shareable(data["meta"].get("project", "")), "date": shareable(data["meta"].get("date", "")),
        "by_status": by_status,
        "unassigned": [brief(f) for f in open_fs if f["severity"] in ("High", "Medium")
                       and not (isinstance(f.get("triage"), dict) and f["triage"].get("owner"))],
        "overdue": [brief(f) for f in recorded if report_schema.acceptance_expired(f, as_of)],
        "due_soon": [brief(f) for f in recorded if not report_schema.acceptance_expired(f, as_of)
                     and report_schema.iso_date(f["triage"]["review_by"], "review_by") <= horizon],
        "unrecorded": [brief(f) for f in accepted if f not in recorded],
        "fixed": [brief(f) for f in fs if f["status"] == "Fixed"],
        "owners": sorted(owners.values(), key=lambda r: (r["owner"] == "", -r["high_medium"], -r["open"], r["owner"])),
    }


def _cell(value):
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def markdown(report, lang="en"):
    L = LABELS[lang]
    sevs = report_schema.SEVERITIES
    lines = [f"# {L['title']}: {_cell(report['project'])}", "",
             f"- **{L['as_of']}:** {report['as_of']}", "", f"## {L['by_status']}", "",
             f"| {L['col_status']} | " + " | ".join(sevs) + " |", "|---|" + "---:|" * len(sevs)]
    for status, counts in report["by_status"].items():
        lines.append(f"| {status} | " + " | ".join(str(counts[s]) for s in sevs) + " |")

    def table(title, columns, rows):
        lines.extend(["", f"## {title}", ""])
        if not rows:
            lines.append(L["none"])
            return
        lines.append("| " + " | ".join(L[c] for c, _ in columns) + " |")
        lines.append("|" + "---|" * len(columns))
        lines.extend("| " + " | ".join(_cell(fn(r)) for _, fn in columns) + " |" for r in rows)

    base = [("col_id", lambda r: r["id"]), ("col_sev", lambda r: r["severity"]), ("col_title", lambda r: r["title"])]
    review = base + [("col_owner", lambda r: r["owner"] or "—"), ("col_review", lambda r: r["review_by"]),
                     ("col_reason", lambda r: r["reason"])]
    table(L["unassigned"], base, report["unassigned"])
    table(L["overdue"], review, report["overdue"])
    table(L["due"].format(days=report["due_within_days"]), review, report["due_soon"])
    table(L["unrecorded"], base, report["unrecorded"])
    table(L["owners"], [("col_owner", lambda r: r["owner"] or L["nobody"]), ("col_open", lambda r: r["open"]),
                        ("col_hm", lambda r: r["high_medium"])], report["owners"])
    table(L["fixed"], base + [("col_reason", lambda r: r["reason"] or "—"),
                              ("col_retest", lambda r: "yes" if r["retest"] == "verified" else "no")],
          report["fixed"])
    if report["fixed"]:
        lines += ["", "> " + L["fixed_note"]]
    lines += ["", L["note"]]
    return "\n".join(lines) + "\n"


# --- command line ------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set", help="record a decision for one or more findings")
    s.add_argument("findings", type=Path)
    s.add_argument("ids", nargs="+")
    s.add_argument("--status", choices=report_schema.STATUSES)
    s.add_argument("--reason")
    s.add_argument("--owner")
    s.add_argument("--review-by", dest="review_by", type=lambda v: parse_date(v, "--review-by").isoformat())
    s.add_argument("--ticket")
    s.add_argument("--date", type=lambda v: parse_date(v, "--date"), help="decision date (default: today, UTC)")
    a = sub.add_parser("apply", help="record a file of decisions")
    a.add_argument("findings", type=Path)
    a.add_argument("decisions", type=Path)
    a.add_argument("--date", type=lambda v: parse_date(v, "--date"))
    c = sub.add_parser("carry", help="carry decisions from an earlier assessment to matching findings")
    c.add_argument("baseline")
    c.add_argument("findings")
    c.add_argument("--as-of", dest="as_of", type=lambda v: parse_date(v, "--as-of"))
    c.add_argument("--dry-run", action="store_true", help="show the plan; write nothing")
    c.add_argument("--json", dest="json_out", help="write the plan as JSON to this file")
    m = sub.add_parser("summary", help="remediation status: owners, overdue and due acceptances")
    m.add_argument("findings")
    m.add_argument("--as-of", dest="as_of", type=lambda v: parse_date(v, "--as-of"))
    m.add_argument("--due-within", dest="due_within", type=int, default=30)
    m.add_argument("--markdown", dest="md_out")
    m.add_argument("--json", dest="json_out")
    m.add_argument("--lang", choices=sorted(LABELS), default="en")
    m.add_argument("--fail-on-overdue", action="store_true", help="exit 1 when an acceptance is past its review date")
    args = p.parse_args(argv)
    try:
        if args.cmd in ("set", "apply"):
            return cmd_record(args)
        if args.cmd == "carry":
            return cmd_carry(args)
        return cmd_summary(args)
    except Refused as exc:
        print("\n".join(exc.args[0]), file=sys.stderr)
        return 1
    except (report_schema.SchemaError, OSError, OutputError, MergeConflict) as exc:
        print(f"triage: {exc}", file=sys.stderr)
        return 2


def cmd_record(args):
    path = findings_path(args.findings)
    if args.cmd == "set":
        decision = {k: getattr(args, k) for k in ("status", "reason", "owner", "review_by", "ticket")}
        decisions = [{"id": ident, **decision} for ident in args.ids]
    else:
        decisions = load_decisions(args.decisions)
    updates = record_decisions(path, decisions, args.date or today())
    for ident, record in updates.items():
        extra = "".join(f", {k} {record[k]}" for k in ("owner", "review_by") if record.get(k))
        print(f"{ident}: {record['status']}{extra}")
    print(f"triage: recorded {len(updates)} decision(s) in {path}; re-render the reports to show them")
    return 0


def cmd_carry(args):
    base = read_baseline(args.baseline)
    path = findings_path(args.findings)
    original, raw, checked = read_raw(path)
    as_of = args.as_of or today()
    plan = carry_plan(base, checked, raw, as_of)
    if args.json_out:
        write_file(args.json_out, json.dumps({"carry_version": 1, "as_of": as_of.isoformat(), **plan},
                                             ensure_ascii=False, indent=2) + "\n")
    for item in plan["carried"]:
        print(f"carried  {item['id']} <- {item['baseline_id']}: Accepted until {item['record']['review_by']}")
    for item in plan["assigned"]:
        print(f"assigned {item['id']} <- {item['baseline_id']}: owner/ticket of open work")
    for item in plan["not_carried"]:
        print(f"decide   {item['id']} <- {item['baseline_id']}: {item['reason'].replace('_', ' ')}")
    for item in plan["kept"]:
        print(f"kept     {item['id']}: already has a decision in {path}")
    writes = plan["carried"] or plan["assigned"]
    if args.dry_run or not writes:
        print(f"triage: {len(plan['carried'])} acceptance(s) and {len(plan['assigned'])} assignment(s) to carry; "
              + ("dry run, nothing written" if args.dry_run else "nothing to write"))
        return 0
    apply_plan(path, plan, raw, original)
    print(f"triage: carried {len(plan['carried'])} acceptance(s) and {len(plan['assigned'])} assignment(s) "
          f"into {path}; {len(plan['not_carried'])} need a new decision; re-render the reports")
    return 0


def read_baseline(path):
    path = findings_path(path)
    if path.is_symlink() or not path.is_file():
        raise report_schema.SchemaError(f"{path}: not a regular findings.json file")
    return report_schema.load(path, read_regular(path))


def cmd_summary(args):
    path = findings_path(args.findings)
    if path.is_symlink() or not path.is_file():
        raise report_schema.SchemaError(f"{path}: not a regular findings.json file")
    data = report_schema.load(path, read_regular(path))
    if args.due_within < 0:
        raise report_schema.SchemaError("--due-within must not be negative")
    report = summarize(data, args.as_of or today(), args.due_within)
    text = markdown(report, args.lang)
    if args.json_out:
        write_file(args.json_out, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if args.md_out:
        write_file(args.md_out, text)
    elif not args.json_out:
        sys.stdout.write(text)
    if args.md_out or args.json_out:
        print(f"triage: {len(report['unassigned'])} unassigned High/Medium, {len(report['overdue'])} overdue "
              f"and {len(report['due_soon'])} due acceptance(s)")
    if args.fail_on_overdue and report["overdue"]:
        print("triage: acceptance past its review date: " + ", ".join(r["id"] for r in report["overdue"]),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
