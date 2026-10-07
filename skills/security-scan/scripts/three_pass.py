"""Opt-in discovery/conditions/challenge assurance, using the existing journal.

This validates submitted observations. It neither discovers vulnerabilities nor
runs reviewers, recorded commands, application code, or network requests.
"""
import re

from verification import CLAIMS, _Validator, integrity_state

CODE_ID = re.compile(r"^F-\d{3}$")

REASONS = (
    "three_pass_discovery_incomplete", "three_pass_candidates_untracked",
    "three_pass_independence_missing", "three_pass_negative_checks_incomplete",
    "three_pass_review_coverage_incomplete", "three_pass_scope_challenge_incomplete",
    "three_pass_scope_contradiction", "three_pass_workflow_missing",
    "three_pass_no_candidates", "three_pass_workflows_incomplete",
)


def enabled(data):
    return data.get("schema_version") == 2 and "three_pass" in data


def validate_profile(data, error_type=ValueError):
    """Validate only the explicit schema-2 profile; missing work is not success."""
    if not enabled(data):
        return None
    validator = _Validator(data, error_type)
    validator.setup()
    def exact(obj, fields, where):
        validator.obj(obj, where)
        if set(obj) != set(fields):
            validator.error(where, "requires only " + ", ".join(fields))
    policy = data["three_pass"]
    exact(policy, ("version", "coverage", "discovery"), "three_pass")
    if type(policy["version"]) is not int or policy["version"] != 1:
        validator.error("three_pass.version", "must be 1")
    coverage = validator.items(policy["coverage"], "three_pass.coverage")
    if not coverage:
        validator.error("three_pass.coverage", "requires a nonempty explicit coverage plan")
    coverage_ids = set()
    for i, row in enumerate(coverage):
        at = "three_pass.coverage[{}]".format(i)
        exact(row, ("id", "perspective", "target"), at)
        for key in ("id", "perspective", "target"):
            validator.text(row, key, at)
        if row["id"] in coverage_ids:
            validator.error(at + ".id", "duplicate coverage ID")
        coverage_ids.add(row["id"])
    discovery = policy["discovery"]
    exact(discovery, ("actor", "summary", "checks"), "three_pass.discovery")
    for key in ("actor", "summary"):
        validator.text(discovery, key, "three_pass.discovery")
    finding_ids = {finding["id"] for finding in data["findings"]}
    seen = set()
    for i, check in enumerate(validator.items(discovery["checks"], "three_pass.discovery.checks")):
        at = "three_pass.discovery.checks[{}]".format(i)
        exact(check, ("coverage_id", "status", "reason", "evidence_ids", "finding_ids"), at)
        identifier = validator.text(check, "coverage_id", at)
        if identifier not in coverage_ids or identifier in seen:
            validator.error(at + ".coverage_id", "unknown or duplicate coverage ID")
        seen.add(identifier)
        status = validator.enum(check, "status", ("checked", "not_applicable", "not_checked"), at)
        validator.text(check, "reason", at)
        refs = validator.current_refs(check, at, required=status != "not_checked")
        if status != "not_checked" and not any(validator.evidence[ref]["kind"] == "source" for ref in refs):
            validator.error(at + ".evidence_ids", "completed discovery requires current source evidence")
        refs = validator.items(check["finding_ids"], at + ".finding_ids")
        if any(not isinstance(ref, str) or ref not in finding_ids for ref in refs):
            validator.error(at + ".finding_ids", "unknown finding ID")
        if len(set(refs)) != len(refs):
            validator.error(at + ".finding_ids", "duplicate finding ID")
        if status != "checked" and refs:
            validator.error(at + ".finding_ids", "only checked coverage can contain candidates")
    return policy


def validate_coverage_checks(data, checks, error_type=ValueError):
    policy = validate_profile(data, error_type)
    if policy is None:
        raise error_type("coverage_checks: requires the three_pass profile")
    validator = _Validator(data, error_type)
    validator.setup()
    planned = {row["id"] for row in policy["coverage"]}
    seen = set()
    for i, check in enumerate(validator.items(checks, "coverage_checks")):
        at = "coverage_checks[{}]".format(i)
        validator.obj(check, at)
        if set(check) != {"coverage_id", "result", "reason", "evidence_ids"}:
            validator.error(at, "requires coverage_id, result, reason and evidence_ids only")
        identifier = validator.text(check, "coverage_id", at)
        if identifier not in planned or identifier in seen:
            validator.error(at + ".coverage_id", "unknown or duplicate coverage ID")
        seen.add(identifier)
        result = validator.enum(check, "result", ("clear", "contradiction", "unresolved"), at)
        validator.text(check, "reason", at)
        refs = validator.current_refs(check, at, required=result != "unresolved")
        if result != "unresolved" and not any(validator.evidence[ref]["kind"] == "source" for ref in refs):
            validator.error(at + ".evidence_ids", "scope challenge requires current source evidence")
    return checks


def discovery_state(data, integrity=None, error_type=ValueError):
    policy = validate_profile(data, error_type)
    if policy is None:
        return None
    checks = policy["discovery"]["checks"]
    checked = {row["coverage_id"] for row in checks if row["status"] != "not_checked"}
    planned = {row["id"] for row in policy["coverage"]}
    tracked = {ref for row in checks if row["status"] == "checked" for ref in row["finding_ids"]}
    code_findings = [f for f in data["findings"] if CODE_ID.match(str(f.get("id", "")))]
    missing = sorted(planned - checked)
    untracked = sorted({finding["id"] for finding in code_findings} - tracked)
    evidence_ids = sorted({ref for row in checks for ref in row["evidence_ids"]})
    reasons = (["three_pass_discovery_incomplete"] if missing else [])
    if untracked:
        reasons.append("three_pass_candidates_untracked")
    provenance = integrity_state(data, evidence_ids, integrity)
    if provenance["status"] == "incomplete":
        reasons.append("evidence_integrity_failed")
    elif data.get("evidence_integrity", {}).get("required") and provenance["status"] != "checked":
        reasons.append("evidence_integrity_unchecked")
    return {"status": "held" if reasons else "complete", "reasons": reasons,
            "actor": policy["discovery"]["actor"], "coverage_total": len(planned),
            "coverage_complete": len(checked), "missing_coverage_ids": missing,
            "untracked_finding_ids": untracked, "evidence_ids": evidence_ids}


def stage_gaps(data, finding, stages, integrity=None, error_type=ValueError):
    """Fresh profile gates for the submitted current round, not historical votes."""
    discovery = discovery_state(data, integrity, error_type)
    if discovery is None:
        return []
    gaps = list(discovery["reasons"])
    by_stage = {stage["stage"]: stage for stage in stages}
    actors = [discovery["actor"].strip().casefold()]
    for stage in ("conditions", "falsification"):
        if stage in by_stage:
            actor = by_stage[stage]["actor"].strip().casefold()
            if actor in actors:
                gaps.append("three_pass_independence_missing")
            actors.append(actor)
    if "falsification" not in by_stage:
        return sorted(set(gaps))
    verification = finding.get("verification", {})
    checks = verification.get("falsification", [])
    if any(check.get("claim") not in CLAIMS for check in checks) or not set(CLAIMS).issubset({check.get("claim") for check in checks if isinstance(check.get("claim"), str)}):
        gaps.append("three_pass_negative_checks_incomplete")
    actor = by_stage["falsification"]["actor"].strip().casefold()
    claim_refs = {ref for claim in verification.get("claims", {}).values() for ref in claim.get("evidence_ids", [])}
    if not any(review["reviewer"].strip().casefold() == actor and
               claim_refs.issubset(review.get("evidence_ids", [])) and
               (review["conclusion"] == "agree" or "resolution" in review)
               for review in verification.get("reviews", [])):
        gaps.append("three_pass_review_coverage_incomplete")
    coverage_checks = validate_coverage_checks(data, verification.get("coverage_checks", []), error_type)
    associated = {row["coverage_id"] for row in data["three_pass"]["discovery"]["checks"] if finding["id"] in row["finding_ids"]}
    clear = {row["coverage_id"] for row in coverage_checks if row["result"] == "clear"}
    if not associated.issubset(clear) or any(row["result"] == "unresolved" for row in coverage_checks):
        gaps.append("three_pass_scope_challenge_incomplete")
    if any(row["result"] == "contradiction" for row in coverage_checks):
        gaps.append("three_pass_scope_contradiction")
    provenance = integrity_state(data, sorted({ref for row in coverage_checks for ref in row["evidence_ids"]}), integrity)
    if provenance["status"] == "incomplete":
        gaps.append("evidence_integrity_failed")
    elif data.get("evidence_integrity", {}).get("required") and provenance["status"] != "checked":
        gaps.append("evidence_integrity_unchecked")
    return sorted(set(gaps))


def derive_three_pass(data, error_type=ValueError, integrity=None):
    """Aggregate audit, including empty discovery cells and excluded candidates."""
    discovery = discovery_state(data, integrity, error_type)
    if discovery is None:
        return {"opted_in": False, "status": "not_requested", "reasons": [], "passes": [], "findings": {}}
    from verification_workflow import derive_workflow
    code_findings = [f for f in data["findings"] if CODE_ID.match(str(f.get("id", "")))]
    workflows = {finding["id"]: derive_workflow(data, finding, error_type, integrity) for finding in code_findings}
    reasons = list(discovery["reasons"])
    if not workflows:
        reasons.append("three_pass_no_candidates")
    if any(state["status"] != "complete" for state in workflows.values()):
        reasons.append("three_pass_workflows_incomplete")
    rows, accepted_rows = [], []
    for finding in code_findings:
        state = workflows[finding["id"]]
        if state["status"] != "stale" and any(stage["stage"] == "falsification" for stage in state["stages"]):
            observed = validate_coverage_checks(data, finding.get("verification", {}).get("coverage_checks", []), error_type)
            rows.extend(observed)
            if any(stage["stage"] == "falsification" and stage["status"] == "complete" for stage in state["stages"]):
                accepted_rows.extend(observed)
    planned = {row["id"] for row in data["three_pass"]["coverage"]}
    clear = {row["coverage_id"] for row in accepted_rows if row["result"] == "clear"}
    blocked = {row["coverage_id"] for row in rows if row["result"] != "clear"}
    covered = clear - blocked
    missing = sorted(planned - covered)
    scope_reasons = ["three_pass_scope_challenge_incomplete"] if missing else []
    if any(row["result"] == "contradiction" for row in rows):
        scope_reasons.append("three_pass_scope_contradiction")
    reasons.extend(scope_reasons)
    total = len(workflows)
    conditions = sum(state["status"] != "stale" and any(stage["stage"] == "conditions" and stage["status"] == "complete" for stage in state["stages"]) for state in workflows.values())
    complete = sum(state["status"] == "complete" for state in workflows.values())
    def status(done, count):
        return "complete" if count and done == count else "held"
    return {"opted_in": True, "status": "held" if reasons else "complete", "reasons": sorted(set(reasons)),
            "passes": [{"id": "discovery", "status": discovery["status"], "completed": discovery["coverage_complete"], "total": discovery["coverage_total"]},
                       {"id": "conditions", "status": status(conditions, total), "completed": conditions, "total": total},
                       {"id": "challenge", "status": "complete" if total and complete == total and not scope_reasons else "held", "completed": complete, "total": total}],
            "discovery": discovery, "coverage_challenge": {"status": "held" if scope_reasons else "complete", "reasons": scope_reasons, "completed": len(covered), "total": len(planned), "missing_coverage_ids": missing},
            "findings": workflows}
