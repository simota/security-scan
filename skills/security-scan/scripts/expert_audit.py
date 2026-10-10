#!/usr/bin/env python3
"""Gate an expert-grade assessment: run contract, three-pass, expert records and run files.

    python3 expert_audit.py OUT_DIR [--no-pdf] [--evidence-root ROOT --evidence-repository REPO]

OUT_DIR holds findings.json, the rendered report and run/ (spawn prompts and
returns, gate and preflight records). On top of expert.py's record gates this
opens every recorded file and checks that each reception stop-span occurs in the
rendered assessment. A file existing is not proof that a worker ran.
Explicit evidence roots trigger fresh byte/source verification in this process;
saved receipts never substitute for it, including when integrity is required.

Exit codes: 0 complete, 3 held or degraded (each gap on stderr), 2 unreadable input.
"""
import argparse
import copy
import html
import json
from pathlib import Path, PurePosixPath
import re
import sys

# Sibling modules must import under python3 -I / PYTHONSAFEPATH as well.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract_check
from expert import derive_expert
import render


def run_file(out_dir, rel):
    """A recorded path must be relative, inside run/, and a nonempty regular file."""
    pure = PurePosixPath(str(rel))
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != "run":
        return False
    # Every component, not just the last: a symlinked run/ would resolve outside OUT_DIR.
    path = out_dir
    for part in pure.parts:
        path = path / part
        if path.is_symlink():
            return False
    return path.is_file() and path.stat().st_size > 0


def visible_text(markup):
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", markup, flags=re.S | re.I)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text)).split())


def audit(data, out_dir, pdf=True, evidence_root=None, evidence_repository=None):
    if evidence_repository is not None and evidence_root is None:
        raise ValueError("--evidence-repository requires --evidence-root")
    integrity = None
    if evidence_root is not None:
        from evidence_integrity import verify_evidence
        integrity = verify_evidence(data, evidence_root, repository=evidence_repository)
    state = derive_expert(data, ValueError, integrity=integrity)
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
    p.add_argument("--evidence-root", type=Path, help="explicit root for fresh evidence byte checks")
    p.add_argument("--evidence-repository", type=Path, help="owned local Git repository for source binding")
    a = p.parse_args(argv)
    if a.evidence_repository is not None and a.evidence_root is None:
        p.error("--evidence-repository requires --evidence-root")
    try:
        data = json.loads(contract_check.read_regular(a.out_dir / "findings.json").decode("utf-8"))
        if contract_check.json_depth(data) > contract_check.MAX_JSON_DEPTH:
            raise RecursionError
        if not isinstance(data, dict):
            raise ValueError("findings.json must hold a JSON object")
        # The record gates below assume render.py's schema (meta an object, and so on).
        render.validate_data(copy.deepcopy(data))
        result = audit(data, a.out_dir, pdf=not a.no_pdf, evidence_root=a.evidence_root,
                       evidence_repository=a.evidence_repository)
    except RecursionError:
        print("expert_audit.py: findings.json nesting is too deep", file=sys.stderr)
        return 2
    except render.SchemaError as exc:
        print(f"expert_audit.py: findings.json does not match the schema: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"expert_audit.py: {exc}", file=sys.stderr)
        return 2
    for line in result["gaps"]:
        print(f"GAP {line}", file=sys.stderr)
    print(json.dumps({k: result[k] for k in ("status", "mode", "engines", "counts") if k in result},
                     ensure_ascii=False))
    return 0 if result["status"] == "complete" else 3


if __name__ == "__main__":
    sys.exit(main())
