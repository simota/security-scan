#!/usr/bin/env python3
"""Run synthetic assurance-gate regressions, never detectors or recorded commands.

The hand-authored fixture describes expected gate outcomes. This program supplies
invented observations to the real controller and compares its derived result.
It measures neither vulnerability detection accuracy nor actual reviewer quality.
Only Python's standard library and this repository's controller are used.
"""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import three_pass
import verification_workflow as workflow

FIXTURE = ROOT / "tests/fixtures/three_pass_cases.json"
SAMPLE = ROOT / "examples/findings.three-pass.sample.json"
CLAIM_REFS = {
    "reachability": ["route-source"],
    "preconditions": ["route-source"],
    "defenses": ["policy-source"],
    "impact": ["policy-source"],
}
SCENARIOS = {
    "supported", "false_positive", "not_applicable", "untracked_candidate",
    "dropped_candidate", "unchecked_route", "missing_discovery", "zero_findings",
    "unchallenged_benign", "unchallenged_na", "unchallenged_candidate",
    "scope_contradiction", "scope_unresolved", "unknown_environment",
    "unsupported_runtime", "dissent", "missing_own_coverage",
    "missing_negative_claim", "unresolved_negative", "stale_evidence",
    "stale_discovery", "unknown_coverage", "duplicate_coverage",
    "unknown_evidence", "duplicate_evidence",
}


def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def finding(data, identifier="F-001"):
    return next(item for item in data["findings"] if item["id"] == identifier)


def submission(data, stage, identifier="F-001"):
    """An inert observation payload, generated against the current handoff pin."""
    state = workflow.derive_workflow(data, finding(data, identifier))
    actor = {"conditions": "synthetic-conditions", "falsification": "synthetic-challenge",
             "decision": "synthetic-coordinator"}[stage]
    output = {
        "stage": stage, "actor": actor, "status": "complete",
        "summary": "Invented source-review observations for gate regression only.",
        "evidence_ids": ["route-source", "policy-source", "scope-source"],
        "input_digest": state["input_digest"],
    }
    if stage == "conditions":
        output.update(
            claims={claim: {"status": "supported", "reason": "Invented source trace supports this claim.",
                            "evidence_ids": list(refs)} for claim, refs in CLAIM_REFS.items()},
            environment={"status": "not_required", "reason": "Source-only synthetic assertion; no deployed applicability claimed.",
                         "evidence_ids": []})
    elif stage == "falsification":
        output.update(
            checks=[{"claim": claim, "check": "Try to disprove the " + claim + " claim.",
                     "result": "clear", "reason": "Invented negative check retained the source-scoped assessment.",
                     "evidence_ids": list(refs)} for claim, refs in CLAIM_REFS.items()],
            reviews=[{"reviewer": actor, "conclusion": "agree", "reason": "Invented independent reread of all claim evidence.",
                      "evidence_ids": ["route-source", "policy-source"]}],
            coverage_checks=[{"coverage_id": row["id"], "result": "clear",
                              "reason": "Invented independent challenge of candidate, benign, or N/A scope.",
                              "evidence_ids": ["scope-source"]} for row in data["three_pass"]["coverage"]])
    else:
        output.update(validation={"verdict": "Valid", "method": "Synthetic source review",
                                  "evidence": "Invented evidence-backed gate decision, not a real finding."}, run_ids=[])
    return output


def complete(data, identifier="F-001", transform=None):
    """Submit only while the controller permits advancement; keep held findings."""
    state = workflow.initialize(data, identifier, "synthetic-coordinator")
    for stage in workflow.STAGES:
        if state["status"] != "ready":
            break
        output = submission(data, stage, identifier)
        if transform is not None:
            transform(stage, output)
        state = workflow.submit(data, identifier, output)
    return state


def _prepare(data, scenario):
    checks = data["three_pass"]["discovery"]["checks"]
    if scenario in ("false_positive", "not_applicable"):
        data["evidence"][0]["summary"] = "Synthetic counterevidence: the required attacker-controlled precondition is absent."
    elif scenario == "untracked_candidate":
        candidate = copy.deepcopy(data["findings"][0])
        candidate.update(id="F-002", title="Synthetic additional untracked candidate")
        data["findings"].append(candidate)
    elif scenario == "dropped_candidate":
        data["findings"] = []
    elif scenario == "unchecked_route":
        checks[1].update(status="not_checked", reason="Synthetic route not yet inspected.", evidence_ids=[])
    elif scenario == "missing_discovery":
        del checks[1]
    elif scenario == "zero_findings":
        data["findings"] = []
        checks[0]["finding_ids"] = []
    elif scenario == "unsupported_runtime":
        data["test_runs"] = [{
            "id": "synthetic-unsupported", "case_id": "owner-boundary", "commit": data["assessment"]["commit"],
            "role": "security", "context": {"environment": "local", "configuration": "invented-v1",
            "fixture": "invented-tenants", "test_version": "invented-v1", "boundary": "unknown"},
            "result": "unsupported", "failure_kind": "none", "exit_code": None,
            "expected": "Owner boundary is enforced.", "observed": "Synthetic record: environment unsupported.",
            "command": "SYNTHETIC RECORD ONLY; NEVER EXECUTE", "recorded_at": "2026-10-06T00:00:00Z",
            "evidence_ids": [],
        }]


def _transform(scenario, stage, output):
    if stage == "conditions":
        if scenario in ("false_positive", "not_applicable"):
            output["claims"]["preconditions"].update(status="contradicted", reason="Invented counterevidence proves required precondition absent.")
        elif scenario == "unknown_environment":
            output["environment"].update(status="unknown", reason="Environment applicability is unknown.")
    elif stage == "falsification":
        if scenario in ("false_positive", "not_applicable"):
            output["checks"][1].update(result="contradiction", reason="Invented negative check contradicts the required precondition.")
        elif scenario.startswith("unchallenged_"):
            omitted = {"unchallenged_benign": "order-list", "unchallenged_na": "admin-route",
                       "unchallenged_candidate": "order-detail"}[scenario]
            output["coverage_checks"] = [row for row in output["coverage_checks"] if row["coverage_id"] != omitted]
        elif scenario in ("scope_contradiction", "scope_unresolved"):
            output["coverage_checks"][1]["result"] = "contradiction" if scenario == "scope_contradiction" else "unresolved"
        elif scenario == "dissent":
            original = output["reviews"][0]
            output["reviews"].extend(dict(copy.deepcopy(original), reviewer="synthetic-agreement-" + str(i)) for i in range(4))
            output["reviews"].append(dict(copy.deepcopy(original), reviewer="synthetic-dissent", conclusion="disagree"))
        elif scenario == "missing_own_coverage":
            output["reviews"].append(dict(copy.deepcopy(output["reviews"][0]), reviewer="someone-else"))
            output["reviews"][0]["evidence_ids"] = ["route-source"]
        elif scenario == "missing_negative_claim":
            output["checks"].pop()
        elif scenario == "unresolved_negative":
            output["checks"][0]["result"] = "unresolved"
        elif scenario == "unknown_coverage":
            output["coverage_checks"][0]["coverage_id"] = "unplanned-route"
        elif scenario == "duplicate_coverage":
            output["coverage_checks"].append(copy.deepcopy(output["coverage_checks"][0]))
        elif scenario == "unknown_evidence":
            output["checks"][0]["evidence_ids"] = ["unregistered-evidence"]
        elif scenario == "duplicate_evidence":
            output["checks"][0]["evidence_ids"] *= 2
    elif stage == "decision":
        if scenario in ("false_positive", "not_applicable"):
            output["validation"]["verdict"] = "FalsePositive" if scenario == "false_positive" else "NotApplicable"
            output["exclusion"] = {"basis": "condition_absent" if scenario == "false_positive" else "not_applicable",
                                   "reason": "Invented counterevidence establishes exclusion.", "evidence_ids": ["route-source"]}
        elif scenario == "unsupported_runtime":
            output["run_ids"] = ["synthetic-unsupported"]


def execute_case(case):
    """Return fresh input and audit state; malformed input raises ValueError."""
    scenario = case["scenario"]
    if scenario not in SCENARIOS:
        raise ValueError("Unknown benchmark scenario: " + str(scenario))
    data = sample()
    _prepare(data, scenario)
    discovery = three_pass.discovery_state(data)
    if discovery["status"] == "complete" and data["findings"]:
        complete(data, transform=lambda stage, output: _transform(scenario, stage, output))
    if scenario == "stale_evidence":
        data["evidence"][0]["sha256"] = "a" * 64
    elif scenario == "stale_discovery":
        data["three_pass"]["discovery"]["summary"] = "Discovery changed after the reviewed round."
    return data, three_pass.derive_three_pass(data)


def evaluate(case):
    try:
        data, audit = execute_case(case)
        disposition = "held"
        if audit["status"] == "complete":
            disposition = "excluded" if all(item["validation"]["verdict"] in ("FalsePositive", "NotApplicable")
                                            for item in data["findings"]) else "kept"
        actual = {"audit": audit["status"], "disposition": disposition}
        reasons = sorted(set(audit["reasons"]) | {reason for state in audit["findings"].values()
                                                for reason in state["reasons"] if reason != "stages_complete"})
        detail = {"reasons": reasons}
    except ValueError as exc:
        actual = {"audit": "rejected", "disposition": "rejected"}
        detail = {"error": str(exc)}
    return {"id": case["id"], "category": case["category"], "description": case["description"],
            "expected": case["expected"], "actual": actual, "matched": actual == case["expected"], **detail}


def run_benchmark(path=FIXTURE):
    fixture = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = fixture["cases"]
    ids = [case["id"] for case in cases]
    if not cases or len(set(ids)) != len(ids):
        raise ValueError("Benchmark cases must be nonempty with unique IDs")
    for case in cases:
        if case["scenario"] not in SCENARIOS or case["category"] not in fixture["categories"]:
            raise ValueError("Unknown scenario or category in case " + case["id"])
        if set(case["expected"]) != {"audit", "disposition"}:
            raise ValueError("Expected gate outcome requires audit and disposition")
    results = [evaluate(case) for case in cases]
    categories = {}
    for category, definition in fixture["categories"].items():
        selected = [row for row in results if row["category"] == category]
        categories[category] = {"definition": definition, "cases": len(selected),
                                "matched": sum(row["matched"] for row in selected),
                                "mismatched": sum(not row["matched"] for row in selected)}
    return {
        "benchmark": "synthetic-three-pass-gates", "version": 1,
        "limitations": fixture["description"],
        "case_count": len(results), "matched": sum(row["matched"] for row in results),
        "mismatched": sum(not row["matched"] for row in results),
        "expected_audit_counts": dict(sorted(Counter(row["expected"]["audit"] for row in results).items())),
        "actual_audit_counts": dict(sorted(Counter(row["actual"]["audit"] for row in results).items())),
        "categories": categories, "results": results,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--json", action="store_true", help="Print a machine-readable report without generated journals")
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(args.fixture)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("benchmark error: " + str(exc), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(report["limitations"])
        for row in report["results"]:
            expected = "/".join(row["expected"][key] for key in ("audit", "disposition"))
            actual = "/".join(row["actual"][key] for key in ("audit", "disposition"))
            print("{} [{}] {}: expected {}; actual {}".format("PASS" if row["matched"] else "FAIL", row["category"], row["id"], expected, actual))
            if not row["matched"]:
                print("  " + row.get("error", ", ".join(row.get("reasons", []))))
        print("Cases: {case_count}; matched: {matched}; mismatched: {mismatched}".format(**report))
        print("Category cases: " + ", ".join("{}={}".format(name, row["cases"]) for name, row in report["categories"].items()))
        print("Expected audit counts: " + json.dumps(report["expected_audit_counts"], sort_keys=True))
        print("Actual audit counts: " + json.dumps(report["actual_audit_counts"], sort_keys=True))
    return 1 if report["mismatched"] else 0


if __name__ == "__main__":
    sys.exit(main())
