#!/usr/bin/env python3
"""Gate an expert-grade assessment: run contract, three-pass, expert records and run files.

    python3 expert_audit.py OUT_DIR [--no-pdf]

OUT_DIR holds findings.json, the rendered report and run/ (spawn prompts and
returns, gate and preflight records). On top of expert.py's record gates this
opens every recorded file and checks that each reception stop-span occurs in the
rendered assessment. A file existing is not proof that a worker ran.

Exit codes: 0 complete, 3 held or degraded (each gap on stderr), 2 unreadable input.
"""
import argparse
import html
import json
from pathlib import Path, PurePosixPath
import re
import sys

import contract_check
from expert import derive_expert


def run_file(out_dir, rel):
    """A recorded path must be relative, inside run/, and a nonempty regular file."""
    pure = PurePosixPath(str(rel))
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != "run":
        return False
    path = out_dir / pure
    return path.is_file() and not path.is_symlink() and path.stat().st_size > 0


def visible_text(markup):
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", markup, flags=re.S | re.I)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text)).split())


def audit(data, out_dir, pdf=True):
    state = derive_expert(data, ValueError)
    if not state["opted_in"]:
        return {"status": "not-expert", "gaps": ["expert record missing"], "counts": {}}
    gaps = list(state["gaps"])
    gaps += ["contract: " + p for p in contract_check.check(data, out_dir, pdf=pdf)]
    record = data["expert"]
    paths = [("consent", record["consent"]["record"])]
    paths += [(f"preflight:{p['engine']}", p["record"]) for p in record.get("preflight", [])]
    for s in record.get("spawns", []):
        paths += [(f"spawn:{s['id']}:prompt", s["prompt"]), (f"spawn:{s['id']}:return", s["return"])]
    for label, rel in paths:
        if not run_file(out_dir, rel):
            gaps.append(f"run_file_missing:{label}:{rel}")
    assessment = out_dir / "assessment.html"
    report = visible_text(assessment.read_text(encoding="utf-8")) if assessment.is_file() else ""
    for r in record.get("reception", []):
        if " ".join(r["stop_span"].split()) not in report:
            gaps.append(f"reception_span_not_in_report:{r['persona']}")
    status = "held" if state["status"] == "complete" and gaps else state["status"]
    return {"status": status, "gaps": gaps,
            "counts": state["counts"], "engines": state["engines"], "mode": state["mode"]}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out_dir", type=Path)
    p.add_argument("--no-pdf", action="store_true", help="the PDF was skipped on purpose")
    a = p.parse_args(argv)
    try:
        data = json.loads((a.out_dir / "findings.json").read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("findings.json must hold a JSON object")
        result = audit(data, a.out_dir, pdf=not a.no_pdf)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"expert_audit.py: {exc}", file=sys.stderr)
        return 2
    for line in result["gaps"]:
        print(f"GAP {line}", file=sys.stderr)
    print(json.dumps({k: result[k] for k in ("status", "mode", "engines", "counts") if k in result},
                     ensure_ascii=False))
    return 0 if result["status"] == "complete" else 3


if __name__ == "__main__":
    sys.exit(main())
