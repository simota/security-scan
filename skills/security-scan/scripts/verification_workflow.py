#!/usr/bin/env python3
"""Offline, manually supplied verification stages; never execute a recorded command.

The journal enforces ordering and detects input drift. Actors, hashes and evidence
are declarations, not authenticated identities or artifact attestations.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone

# Sibling modules must import under python3 -I / PYTHONSAFEPATH as well.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verification import CLAIMS, DEFINITIVE, derive_verification, integrity_state, parse_timestamp
from three_pass import (REASONS as THREE_PASS_REASONS, enabled as three_pass_enabled,
                        validate_profile, validate_coverage_checks, discovery_state, stage_gaps, derive_three_pass)

STAGES = ("conditions", "falsification", "decision")
OUTCOMES = ("complete", "held", "error", "unknown", "conflict")
STATUSES = ("not_started", "ready", "held", "error", "unknown", "conflict", "stale", "complete")
REASONS = ("not_started", "awaiting_submission", "stages_complete", "input_changed",
           "manually_invalidated", "stage_held", "stage_error", "stage_unknown",
           "stage_conflict", "claims_incomplete", "falsification_incomplete",
           "verification_incomplete", "environment_unknown", "review_disagreement",
           "runtime_contradiction", "runtime_incomplete", "runtime_boundary_unverified",
           "evidence_integrity_unchecked", "evidence_integrity_failed") + THREE_PASS_REASONS
# Keys render.py strips or derives; excluding them keeps the CLI's and the
# report's input digests identical.
_DERIVED = {"_verification", "_workflow", "_evidence_integrity", "verdict", "source_link", "snippet"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class WorkflowError(ValueError):
    pass


def _error(where, message):
    raise WorkflowError("{}: {}".format(where, message))


def _object(value, where):
    if not isinstance(value, dict):
        _error(where, "must be an object")
    return value


def _text(obj, key, where):
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        _error(where + "." + key, "required nonblank string")
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        _error(where + "." + key, "must not contain control characters or lone surrogates")
    return value


def _list(value, where):
    if not isinstance(value, list):
        _error(where, "must be a list")
    return value


def _digest(value, where):
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        _error(where, "must be a lowercase SHA-256 digest")
    return value


def _timestamp(value, where):
    if not isinstance(value, str):
        _error(where, "must be an ISO-8601 timestamp with timezone")
    try:
        parse_timestamp(value)
    except ValueError:
        _error(where, "must be an ISO-8601 timestamp with timezone")


def _json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        _error("input", "must contain finite JSON values")


def _hash(value):
    try:
        return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()
    except UnicodeError:
        _error("input", "must not contain lone surrogates")


def _normalized_finding(finding):
    """Match render.load's benign defaults without omitting substantive inputs."""
    result = copy.deepcopy({k: v for k, v in finding.items()
                            if k not in _DERIVED and k != "verification_workflow"})
    result.setdefault("status", "Open")
    for key in ("actor", "request", "impact", "fix"):
        result.setdefault(key, "")
    result["category"] = result.get("category") or "Uncategorized"
    validation = result.setdefault("validation", {})
    if isinstance(validation, dict):
        for key, value in (("verdict", "Unverified"), ("method", ""), ("evidence", "")):
            validation.setdefault(key, value)
    refs = []
    for value in result.get("references", []):
        value = {"url": value} if isinstance(value, str) else value
        refs.append({"type": value.get("type") or "web", "url": value.get("url"),
                     "title": value.get("title", "")})
    result["references"] = refs
    return result


def _references(value, evidence, runs):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_ids" and isinstance(item, list):
                evidence.update(x for x in item if isinstance(x, str))
            elif key in ("run_ids", "positive_control_run_ids", "regression_run_ids") and isinstance(item, list):
                runs.update(x for x in item if isinstance(x, str))
            elif key in ("before_run_id", "after_run_id") and isinstance(item, str):
                runs.add(item)
            _references(item, evidence, runs)
    elif isinstance(value, list):
        for item in value:
            _references(item, evidence, runs)


def input_digest(data, finding):
    """Pin this finding and its referenced records, not unrelated finding progress."""
    source = _normalized_finding(finding)
    evidence_ids, run_ids = set(), set()
    _references(source, evidence_ids, run_ids)
    if three_pass_enabled(data):
        _references(data["three_pass"], evidence_ids, run_ids)
    scope = _scope(finding)
    if scope is None:
        scope = _catalog_scope(data)
    evidence_ids.update(scope["evidence_ids"])
    run_ids.update(scope["run_ids"])
    selected_runs = [run for run in data.get("test_runs", []) if run.get("id") in run_ids]
    _references(selected_runs, evidence_ids, set())
    return _hash({"schema_version": data.get("schema_version", 1),
                  "assessment": data.get("assessment"), "finding": source, "scope": scope,
                  "round_id": _round_id(finding),
                  "evidence": sorted((x for x in data.get("evidence", []) if x.get("id") in evidence_ids), key=lambda x: x["id"]),
                  "test_runs": sorted(selected_runs, key=lambda x: x["id"]),
                  **({"evidence_integrity": data["evidence_integrity"]} if "evidence_integrity" in data else {}),
                  **({"three_pass": data["three_pass"], "finding_ids": sorted(item["id"] for item in data["findings"])} if three_pass_enabled(data) else {})})


def _catalog_scope(data):
    return {"evidence_ids": sorted(item["id"] for item in data.get("evidence", [])),
            "run_ids": sorted(item["id"] for item in data.get("test_runs", []))}


def _scope(finding):
    workflow = finding.get("verification_workflow")
    if not isinstance(workflow, dict):
        return None
    scope = None
    for event in workflow.get("history", []):
        if event.get("action") == "init" or (event.get("action") == "resume" and event.get("restart")):
            scope = event.get("scope")
    return scope


def _round_id(finding):
    workflow = finding.get("verification_workflow", {})
    if not isinstance(workflow, dict):
        return None
    identifier = None
    for event in workflow.get("history", []):
        if event.get("action") == "init" or (event.get("action") == "resume" and event.get("restart")):
            identifier = event.get("round_id")
    return identifier


def _seal(event, previous=None):
    event["previous_event_digest"] = previous["event_digest"] if previous else None
    event["event_digest"] = _hash({key: value for key, value in event.items() if key != "event_digest"})


def _validate_base(data):
    # Import lazily: render uses this module to derive workflow states, but its
    # shared validator is only called from controller entry points, never derive.
    from render import SchemaError, validate_data
    try:
        validate_data(copy.deepcopy(data))
    except SchemaError as exc:
        raise WorkflowError(str(exc)) from None


def _finding(data, finding_id):
    if data.get("schema_version") != 2 or type(data.get("schema_version")) is not int:
        _error("schema_version", "workflow requires schema_version 2")
    findings = _list(data.get("findings"), "findings")
    found, seen = None, set()
    for value in findings:
        _object(value, "finding")
        identifier = _text(value, "id", "finding")
        if identifier in seen:
            _error("findings", "duplicate finding ID")
        seen.add(identifier)
        if identifier == finding_id:
            found = value
    if found is None:
        _error("finding", "unknown finding ID " + finding_id)
    return found


def _refs_shape(refs, where):
    _list(refs, where)
    if any(not isinstance(ref, str) or not ref.strip() for ref in refs):
        _error(where, "must contain nonblank evidence IDs")
    if len(set(refs)) != len(refs):
        _error(where, "duplicate evidence ID")


def _submission_shape(output):
    _object(output, "submission")
    for key in ("stage", "actor", "status", "summary"):
        _text(output, key, "submission")
    if output["stage"] not in STAGES:
        _error("submission.stage", "unknown stage")
    if output["status"] not in OUTCOMES:
        _error("submission.status", "one of " + ", ".join(OUTCOMES))
    _digest(output.get("input_digest"), "submission.input_digest")
    _refs_shape(output.get("evidence_ids"), "submission.evidence_ids")
    common = {"stage", "actor", "status", "summary", "evidence_ids", "input_digest"}
    fields = {"conditions": {"claims", "environment"}, "falsification": {"checks", "reviews", "coverage_checks"},
              "decision": {"validation", "run_ids", "exclusion"}}[output["stage"]]
    if set(output) - common - fields:
        _error("submission", "unknown or wrong-stage fields")
    if output["status"] != "complete":
        if set(output) - common:
            _error("submission", "blocked outcomes contain observations only, not unapplied patches")
        return
    if not output["evidence_ids"]:
        _error("submission.evidence_ids", "completion requires evidence references")
    required = fields - {"exclusion", "coverage_checks"}
    if not required.issubset(output):
        _error("submission", "missing stage output: " + ", ".join(sorted(required - set(output))))
    if output["stage"] == "conditions":
        claims = _object(output["claims"], "submission.claims")
        if set(claims) != set(CLAIMS):
            _error("submission.claims", "requires exactly all four claims")
        _object(output["environment"], "submission.environment")
    elif output["stage"] == "falsification":
        if not _list(output["checks"], "submission.checks"):
            _error("submission.checks", "at least one falsification check is required")
        _list(output["reviews"], "submission.reviews")
    else:
        validation = _object(output["validation"], "submission.validation")
        for key in ("verdict", "method", "evidence"):
            _text(validation, key, "submission.validation")
        if validation["verdict"] not in DEFINITIVE:
            _error("submission.validation.verdict", "requires Valid, FalsePositive or NotApplicable")
        _refs_shape(output["run_ids"], "submission.run_ids")


def _replay(workflow):
    """Validate the journal's state machine, including retained historical rounds."""
    _object(workflow, "verification_workflow")
    if set(workflow) != {"version", "input_digest", "history"}:
        _error("verification_workflow", "requires version, input_digest and history only")
    if type(workflow["version"]) is not int or workflow["version"] != 1:
        _error("verification_workflow.version", "must be 1")
    digest = _digest(workflow["input_digest"], "verification_workflow.input_digest")
    history = _list(workflow["history"], "verification_workflow.history")
    if not history:
        _error("verification_workflow.history", "initialization event required")
    chain, stages, invalidated, previous_event = None, [], False, None
    rounds = set()
    for index, event in enumerate(history):
        at = "verification_workflow.history[{}]".format(index)
        _object(event, at)
        expected_previous = previous_event["event_digest"] if previous_event else None
        if event.get("previous_event_digest") != expected_previous:
            _error(at, "broken event digest chain")
        _digest(event.get("event_digest"), at + ".event_digest")
        if event["event_digest"] != _hash({key: value for key, value in event.items() if key != "event_digest"}):
            _error(at, "event body differs from its recorded digest")
        previous_event = event
        action = _text(event, "action", at)
        if action == "init" or (action == "resume" and event.get("restart")):
            if not isinstance(event.get("round_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", event["round_id"]):
                _error(at + ".round_id", "must be a unique round identifier")
            if event["round_id"] in rounds:
                _error(at + ".round_id", "must not reuse an earlier round")
            rounds.add(event["round_id"])
            scope = _object(event.get("scope"), at + ".scope")
            if set(scope) != {"evidence_ids", "run_ids"}:
                _error(at + ".scope", "requires evidence_ids and run_ids")
            for key in ("evidence_ids", "run_ids"):
                _refs_shape(scope[key], at + ".scope." + key)
        _text(event, "actor", at)
        _text(event, "reason", at)
        _timestamp(event.get("recorded_at"), at + ".recorded_at")
        before = _digest(event.get("input_digest"), at + ".input_digest")
        after = _digest(event.get("output_digest"), at + ".output_digest")
        if index == 0:
            if action != "init" or before != after:
                _error(at, "first event must initialize an unchanged input")
            chain = after
            continue
        if action == "init" or before != chain:
            _error(at, "broken digest chain or repeated initialization")
        if action == "submit":
            output = event.get("submission")
            _submission_shape(output)
            if invalidated or (stages and stages[-1]["status"] != "complete"):
                _error(at, "resume is required before submitting")
            if len(stages) == len(STAGES) or output["stage"] != STAGES[len(stages)]:
                _error(at, "out-of-order stage or skipped stage")
            if output["input_digest"] != before or output["actor"] != event["actor"]:
                _error(at, "submission identity or digest mismatch")
            if output["stage"] == "falsification" and output["actor"].strip().casefold() == stages[0]["actor"].strip().casefold():
                _error(at, "conditions and falsification require different declared actors")
            status = event.get("status")
            if status not in OUTCOMES or (output["status"] != "complete" and status != output["status"]):
                _error(at + ".status", "invalid effective outcome")
            reasons = _list(event.get("reasons"), at + ".reasons")
            if any(not isinstance(reason, str) or reason not in REASONS for reason in reasons):
                _error(at + ".reasons", "unknown workflow reason")
            if status == "complete" and reasons:
                _error(at, "completed stage cannot have blocking reasons")
            if status == "complete" and output["stage"] == "conditions":
                if any(not isinstance(claim, dict) or claim.get("status") not in ("supported", "contradicted")
                       for claim in output["claims"].values()):
                    _error(at, "completed conditions cannot contain unknown claims")
            if status == "complete" and output["stage"] == "falsification":
                if any(not isinstance(check, dict) or check.get("result") not in ("clear", "contradiction")
                       for check in output["checks"]):
                    _error(at, "completed falsification cannot contain unresolved checks")
                reviews = output["reviews"]
                if any(not isinstance(review, dict) or
                       (review.get("conclusion") != "agree" and "resolution" not in review) for review in reviews):
                    _error(at, "completed falsification cannot contain unresolved dissent")
                if not any(str(review.get("reviewer", "")).strip().casefold() == output["actor"].strip().casefold()
                           for review in reviews):
                    _error(at, "falsification must include its declared actor's review")
            if status != "complete" and not reasons:
                _error(at, "blocked stage requires reasons")
            _object(event.get("previous_fields"), at + ".previous_fields")
            stages.append({key: copy.deepcopy(event[key]) for key in
                           ("actor", "status", "input_digest", "output_digest", "recorded_at", "reasons")})
            stages[-1].update(stage=output["stage"], summary=output["summary"], evidence_ids=output["evidence_ids"])
        elif action == "invalidate":
            if before != after:
                _error(at, "invalidate cannot repin inputs")
            invalidated = True
        elif action == "resume":
            if type(event.get("restart")) is not bool:
                _error(at + ".restart", "must be a boolean")
            if event["restart"]:
                stages, invalidated = [], False
            else:
                if invalidated or not stages or stages[-1]["status"] == "complete" or before != after:
                    _error(at, "resume without restart requires a blocked stage and unchanged inputs")
                stages.pop()
        else:
            _error(at + ".action", "unknown event")
        chain = after
    if chain != digest:
        _error("verification_workflow.input_digest", "does not match journal tip")
    return stages, invalidated


def _verification_state(data, finding, integrity=None):
    # Evaluate this finding independently so another malformed finding cannot
    # accidentally contribute evidence or block an otherwise valid stage.
    scoped = dict(data, findings=[finding])
    return derive_verification(scoped, WorkflowError, integrity)[finding["id"]]


def _decision_result(state):
    gaps = state["gaps"]
    conflicts = [x for x in ("review_disagreement", "runtime_contradiction") if x in gaps]
    if conflicts:
        return "conflict", conflicts
    if "environment_unknown" in gaps:
        return "unknown", ["environment_unknown"]
    integrity_gaps = [x for x in ("evidence_integrity_unchecked", "evidence_integrity_failed") if x in gaps]
    if integrity_gaps:
        return "held", integrity_gaps
    runtime_gaps = [x for x in ("runtime_incomplete", "runtime_boundary_unverified") if x in gaps]
    if runtime_gaps:
        return "held", runtime_gaps
    if state["level"] not in ("static_supported", "runtime_supported"):
        return "held", ["verification_incomplete"]
    return "complete", []


def derive_workflow(data, finding, error_type=ValueError, integrity=None):
    """Return fresh workflow state; no stored derived status is trusted."""
    try:
        result = {"opted_in": False, "status": "not_started", "next_stage": "conditions",
                  "reason": "not_started", "reasons": ["not_started"], "input_digest": None,
                  "stages": [], "history": []}
        if data.get("schema_version", 1) != 2 or "verification_workflow" not in finding:
            if three_pass_enabled(data):
                result.update(reason="three_pass_workflow_missing", reasons=["three_pass_workflow_missing"])
            return result
        workflow = finding["verification_workflow"]
        stages, invalidated = _replay(workflow)
        current = input_digest(data, finding)
        result.update(opted_in=True, input_digest=current, stages=stages, history=copy.deepcopy(workflow["history"]))
        if invalidated or current != workflow["input_digest"]:
            result.update(status="stale", next_stage="conditions", reasons=["manually_invalidated" if invalidated else "input_changed"])
        elif stages and stages[-1]["status"] != "complete":
            result.update(status=stages[-1]["status"], next_stage=stages[-1]["stage"], reasons=stages[-1]["reasons"])
        elif len(stages) < len(STAGES):
            result.update(status="ready", next_stage=STAGES[len(stages)], reasons=["awaiting_submission"])
        else:
            status, reasons = _decision_result(_verification_state(data, finding, integrity))
            result.update(status=status, next_stage=None if status == "complete" else "decision",
                          reasons=reasons or ["stages_complete"])
        if three_pass_enabled(data) and result["status"] != "stale":
            gaps = stage_gaps(data, finding, stages, integrity, WorkflowError)
            if gaps and result["status"] == "complete":
                result.update(status="conflict" if "three_pass_scope_contradiction" in gaps else "held", next_stage="decision", reasons=gaps)
        result["reason"] = result["reasons"][0]
        return result
    except WorkflowError as exc:
        raise error_type(str(exc)) from None


def validate_workflows(data, error_type=ValueError, integrity=None):
    profile = validate_profile(data, error_type)
    if profile:
        for finding in data["findings"]:
            verification = finding.get("verification", {})
            if isinstance(verification, dict):
                if "coverage_checks" in verification:
                    validate_coverage_checks(data, verification["coverage_checks"], error_type)
                for check in verification.get("falsification", []):
                    if "claim" in check and check["claim"] not in CLAIMS:
                        raise error_type("three_pass.falsification.claim: must name one of the four claims")
    for finding in data["findings"]:
        finding.pop("_workflow", None)
    states = [(finding, derive_workflow(data, finding, error_type, integrity)) for finding in data["findings"]]
    for finding, state in states:
        finding["_workflow"] = state
    return data


def _event(action, actor, reason, before, after, **fields):
    _text({"actor": actor, "reason": reason}, "actor", "event")
    _text({"reason": reason}, "reason", "event")
    result = dict(action=action, actor=actor, reason=reason, input_digest=before, output_digest=after,
                  recorded_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    result.update(fields)
    return result


def initialize(data, finding_id, actor, reason="Initialize sequential verification", integrity=None):
    _validate_base(data)
    finding = _finding(data, finding_id)
    _verification_state(data, finding, integrity)
    discovery = discovery_state(data, integrity, WorkflowError)
    if discovery and discovery["status"] != "complete":
        _error("three_pass.discovery", "finish discovery before initialization: " + ", ".join(discovery["reasons"]))
    if "verification_workflow" in finding:
        return derive_workflow(data, finding, WorkflowError, integrity)
    candidate = copy.deepcopy(finding)
    event = _event("init", actor, reason, "0" * 64, "0" * 64,
                   scope=_catalog_scope(data), round_id=uuid.uuid4().hex,
                   **({"three_pass_snapshot": copy.deepcopy(data["three_pass"])} if three_pass_enabled(data) else {}))
    candidate["verification_workflow"] = dict(version=1, input_digest="0" * 64, history=[event])
    digest = input_digest(data, candidate)
    event["input_digest"] = event["output_digest"] = digest
    candidate["verification_workflow"]["input_digest"] = digest
    _seal(event)
    result = derive_workflow(data, candidate, WorkflowError, integrity)
    finding.clear()
    finding.update(candidate)
    return result


def _validate_observations(data, finding, output):
    scope = _scope(finding)
    evidence_ids, run_ids = set(), set()
    _references(output, evidence_ids, run_ids)
    if not evidence_ids.issubset(scope["evidence_ids"]) or not run_ids.issubset(scope["run_ids"]):
        _error("submission", "references evidence outside the frozen handoff scope; invalidate and resume to repin")
    catalog = {item["id"]: item for item in data.get("evidence", [])}
    pin = data["assessment"]
    for ref in output["evidence_ids"]:
        if ref not in catalog:
            _error("submission.evidence_ids", "unknown evidence ID " + ref)
        record = catalog[ref]
        if (record["commit"].lower(), record.get("diff_sha256", "").lower()) != (pin["commit"].lower(), pin.get("diff_sha256", "").lower()):
            _error("submission.evidence_ids", "evidence must match assessment commit/worktree pin")


def submit(data, finding_id, output, integrity=None):
    """Apply one manually supplied stage transactionally; identical retries are no-ops."""
    _submission_shape(output)
    _validate_base(data)
    finding = _finding(data, finding_id)
    state = derive_workflow(data, finding, WorkflowError, integrity)
    if not state["opted_in"]:
        _error("workflow", "initialize before submitting")
    workflow = finding["verification_workflow"]
    if state["status"] == "stale":
        _error("workflow", "input changed or invalidated; resume to start a new round")
    # The exact last accepted payload can be retried, including a held result.
    if workflow["history"][-1]["action"] == "submit" and workflow["history"][-1]["submission"] == output:
        return state
    if state["status"] != "ready" or output["stage"] != state["next_stage"]:
        _error("submission.stage", "out-of-order submission; use next or resume")
    if output["input_digest"] != state["input_digest"]:
        _error("submission.input_digest", "stale handoff")
    if output["stage"] == "falsification" and output["actor"].strip().casefold() == state["stages"][0]["actor"].strip().casefold():
        _error("submission.actor", "conditions and falsification require different declared actors")
    if three_pass_enabled(data) and output["stage"] in ("conditions", "falsification"):
        discovery_actor = data["three_pass"]["discovery"]["actor"].strip().casefold()
        if output["actor"].strip().casefold() == discovery_actor:
            _error("submission.actor", "three-pass discovery, conditions and falsification require different declared actors")
    if "coverage_checks" in output:
        validate_coverage_checks(data, output["coverage_checks"], WorkflowError)
    _verification_state(data, finding, integrity)
    _validate_observations(data, finding, output)
    candidate = copy.deepcopy(finding)
    previous = {}
    status, reasons = output["status"], [] if output["status"] == "complete" else ["stage_" + output["status"]]
    if status == "complete":
        previous = {key: copy.deepcopy(finding[key]) for key in ("verification", "validation") if key in finding}
        if output["stage"] == "conditions":
            prior_verification = finding.get("verification", {})
            if not isinstance(prior_verification, dict):
                prior_verification = {}
            candidate["verification"] = {"reviewer": output["actor"], "claims": copy.deepcopy(output["claims"]),
                                         "environment": copy.deepcopy(output["environment"]),
                                         "falsification": copy.deepcopy(prior_verification.get("falsification", [])),
                                         "reviews": copy.deepcopy(prior_verification.get("reviews", [])),
                                         "run_ids": copy.deepcopy(prior_verification.get("run_ids", [])),
                                         **({"coverage_checks": copy.deepcopy(prior_verification.get("coverage_checks", []))} if three_pass_enabled(data) else {})}
            candidate["validation"] = {"verdict": "Unverified", "method": "sequential verification",
                                       "evidence": "Conditions recorded; independent falsification and decision pending."}
            verification = _verification_state(data, candidate, integrity)
            if "claims_incomplete" in verification["gaps"] and not any(c["status"] == "contradicted" for c in output["claims"].values()):
                status, reasons = "unknown", ["claims_incomplete"]
            if any(c["status"] == "unknown" for c in output["claims"].values()):
                status, reasons = "unknown", ["claims_incomplete"]
        elif output["stage"] == "falsification":
            for check in finding["verification"].get("falsification", []):
                if check["result"] != "clear" and check not in output["checks"]:
                    _error("submission.checks", "cannot drop active counterevidence; correct the source record explicitly and restart")
            for review in finding["verification"].get("reviews", []):
                if review["conclusion"] != "agree" and "resolution" not in review:
                    if not any(all(candidate_review.get(key) == value for key, value in review.items())
                               for candidate_review in output["reviews"] if isinstance(candidate_review, dict)):
                        _error("submission.reviews", "cannot drop unresolved dissent; retain it with an evidence-backed resolution")
            if three_pass_enabled(data):
                checks = output.get("coverage_checks", [])
                for check in finding["verification"].get("coverage_checks", []):
                    if check["result"] != "clear" and check not in checks:
                        _error("submission.coverage_checks", "cannot drop active scope counterevidence; correct the source record explicitly and restart")
                candidate["verification"]["coverage_checks"] = copy.deepcopy(checks)
            candidate["verification"]["falsification"] = copy.deepcopy(output["checks"])
            candidate["verification"]["reviews"] = copy.deepcopy(output["reviews"])
            if not any(isinstance(review, dict) and str(review.get("reviewer", "")).strip().casefold() == output["actor"].strip().casefold() for review in output["reviews"]):
                _error("submission.reviews", "must include the falsification actor's own review")
            verification = _verification_state(data, candidate, integrity)
            if "falsification_incomplete" in verification["gaps"]:
                status, reasons = "unknown", ["falsification_incomplete"]
            elif "review_disagreement" in verification["gaps"]:
                status, reasons = "conflict", ["review_disagreement"]
        else:
            if not set(finding["verification"].get("run_ids", [])).issubset(output["run_ids"]):
                _error("submission.run_ids", "cannot drop active runtime observations; correct the source record explicitly and restart")
            candidate["validation"] = copy.deepcopy(output["validation"])
            candidate["verification"]["run_ids"] = copy.deepcopy(output["run_ids"])
            if "exclusion" in output:
                candidate["verification"]["exclusion"] = copy.deepcopy(output["exclusion"])
            else:
                candidate["verification"].pop("exclusion", None)
            verification = _verification_state(data, candidate, integrity)
            status, reasons = _decision_result(verification)
            if status != "complete":
                # Keep the candidate unresolved; requested conclusions remain in
                # the journal for review, never as an accepted finding verdict.
                candidate = copy.deepcopy(finding)
                candidate["verification"]["run_ids"] = copy.deepcopy(output["run_ids"])
                # Preserve newly submitted counterevidence even when the requested
                # definitive verdict is withheld. Existing verdict stays unresolved.
    if status == "complete" and three_pass_enabled(data):
        profile_stages = state["stages"] + [{"stage": output["stage"], "actor": output["actor"]}]
        gaps = stage_gaps(data, candidate, profile_stages, integrity, WorkflowError)
        if gaps:
            status = "conflict" if "three_pass_scope_contradiction" in gaps else "held"
            reasons = gaps
            if output["stage"] == "decision":
                candidate = copy.deepcopy(finding)
                candidate["verification"]["run_ids"] = copy.deepcopy(output["run_ids"])
    # Accepted patches and every journal body are pinned independently.
    history = candidate["verification_workflow"]["history"]
    event = _event("submit", output["actor"], output["summary"], state["input_digest"], state["input_digest"],
                   submission=copy.deepcopy(output), status=status, reasons=reasons, previous_fields=previous)
    history.append(event)
    after = input_digest(data, candidate)
    event["output_digest"] = after
    _seal(event, history[-2])
    candidate["verification_workflow"]["input_digest"] = after
    result = derive_workflow(data, candidate, WorkflowError, integrity)
    finding.clear()
    finding.update(candidate)
    return result


def invalidate(data, finding_id, actor, reason, integrity=None):
    finding = _finding(data, finding_id)
    state = derive_workflow(data, finding, WorkflowError, integrity)
    if not state["opted_in"]:
        _error("workflow", "initialize before invalidating")
    workflow = finding["verification_workflow"]
    event = _event("invalidate", actor, reason, workflow["input_digest"], workflow["input_digest"])
    _seal(event, workflow["history"][-1])
    workflow["history"].append(event)
    return derive_workflow(data, finding, WorkflowError, integrity)


def resume(data, finding_id, actor, reason, integrity=None):
    finding = _finding(data, finding_id)
    state = derive_workflow(data, finding, WorkflowError, integrity)
    if not state["opted_in"]:
        _error("workflow", "initialize before resuming")
    if state["status"] in ("ready", "complete"):
        return state
    if (state["status"] != "stale" and len(state["stages"]) == len(STAGES)
            and state["stages"][-1]["status"] == "complete"):
        # Every stage is recorded; the hold comes from present evidence, not a
        # blocked stage, so there is nothing to resume without a new round.
        _error("workflow", "all stages are recorded; status {} ({}) comes from the current evidence. "
               "Re-check with the evidence flags, or invalidate and then resume to start a new round"
               .format(state["status"], ", ".join(state["reasons"])))
    candidate = copy.deepcopy(finding)
    workflow = candidate["verification_workflow"]
    restart = state["status"] == "stale"
    event = _event("resume", actor, reason, workflow["input_digest"], workflow["input_digest"], restart=restart)
    if restart:
        event["scope"] = _catalog_scope(data)
        event["round_id"] = uuid.uuid4().hex
        if three_pass_enabled(data):
            event["three_pass_snapshot"] = copy.deepcopy(data["three_pass"])
    workflow["history"].append(event)
    after = input_digest(data, candidate)
    event["output_digest"] = after
    _seal(event, workflow["history"][-2])
    workflow["input_digest"] = after
    result = derive_workflow(data, candidate, WorkflowError, integrity)
    finding.clear()
    finding.update(candidate)
    return result


def next_handoff(data, finding_id, integrity=None):
    finding = _finding(data, finding_id)
    state = derive_workflow(data, finding, WorkflowError, integrity)
    if state["status"] != "ready":
        _error("workflow", "next requires a ready workflow; initialize or resume first")
    stage = state["next_stage"]
    template = dict(stage=stage, actor="REPLACE_WITH_DECLARED_REVIEWER", status="complete",
                    summary="REPLACE_WITH_EVIDENCE_BASED_OBSERVATIONS", evidence_ids=[], input_digest=state["input_digest"])
    if stage == "conditions":
        template.update(claims={key: {"status": "unknown", "reason": "REPLACE_WITH_OBSERVATION", "evidence_ids": []} for key in CLAIMS},
                        environment={"status": "unknown", "reason": "REPLACE_WITH_SCOPE_AND_LIMITS", "evidence_ids": []})
    elif stage == "falsification":
        template.update(checks=[{"check": "REPLACE_WITH_SPECIFIC_COUNTERCHECK", "result": "unresolved",
                                 "reason": "REPLACE_WITH_OBSERVATION", "evidence_ids": []}],
                        reviews=[{"reviewer": "REPLACE_WITH_INDEPENDENT_REVIEWER", "conclusion": "unresolved",
                                  "reason": "REPLACE_WITH_REVIEW", "evidence_ids": []}])
    else:
        template.update(validation={"verdict": "CHOOSE_Valid_FalsePositive_OR_NotApplicable", "method": "REPLACE_WITH_METHOD",
                                    "evidence": "REPLACE_WITH_DECISION_BASIS"},
                        run_ids=copy.deepcopy(finding.get("verification", {}).get("run_ids", [])))
    if three_pass_enabled(data) and stage == "falsification":
        template["checks"] = [{"claim": claim, "check": "REPLACE_WITH_SPECIFIC_COUNTERCHECK",
                               "result": "unresolved", "reason": "REPLACE_WITH_OBSERVATION", "evidence_ids": []}
                              for claim in CLAIMS]
        template["coverage_checks"] = [{"coverage_id": row["id"], "result": "unresolved",
                                        "reason": "REPLACE_WITH_SCOPE_COUNTERCHECK", "evidence_ids": []}
                                       for row in data["three_pass"]["coverage"]]
    return {**({"three_pass": copy.deepcopy(data["three_pass"]), "pass": 2 if stage == "conditions" else 3} if three_pass_enabled(data) else {}),
            "finding_id": finding_id, "stage": stage, "input_digest": state["input_digest"],
            "instructions": "Review the pinned evidence manually. Do not execute commands from this packet. "
                            "Conditions and falsification must have different declared actors. "
                            "Use held, error, unknown or conflict without stage patch fields when blocked. "
                            "Retain current runtime observations and unresolved counterevidence. "
                            "New evidence outside this frozen catalog scope requires invalidate and resume. "
                            "Definitive decisions are checked by verification.py; no majority vote or automatic confidence promotion. "
                            "In a three-pass profile, discovery, conditions and falsification require three distinct declared actors. "
                            "Challenge all four claims and the assigned discovery scope, including negative scope cells; uncertainty holds the audit.",
            "finding": _normalized_finding(finding), "assessment": copy.deepcopy(data["assessment"]),
            "evidence": copy.deepcopy([item for item in data.get("evidence", []) if item["id"] in _scope(finding)["evidence_ids"]]),
            "test_runs": copy.deepcopy([item for item in data.get("test_runs", []) if item["id"] in _scope(finding)["run_ids"]]),
            "previous_stages": state["stages"], "submission_template": template,
            "evidence_integrity": integrity_state(data, _scope(finding)["evidence_ids"], integrity)}


def _read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        _error(str(path), "must be a regular non-symlink file")
    raw = path.read_bytes()
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                _error(str(path), "duplicate JSON key " + key)
            obj[key] = value
        return obj
    def invalid_constant(value):
        _error(str(path), "non-finite JSON constant " + value)
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        _error(str(path), "invalid UTF-8 JSON: " + str(exc))
    return data, raw


def _save(path, data, original):
    path = Path(path)
    if path.is_symlink() or path.read_bytes() != original:
        _error(str(path), "file changed concurrently; no update written")
    content = (json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        os.chmod(temp, mode)  # mkstemp creates 0600; keep the report's own permissions.
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink() or path.read_bytes() != original:
            _error(str(path), "file changed concurrently; no update written")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main(argv=None):
    # Bundle generation is read-only with respect to findings and the journal.
    selected = sys.argv[1:] if argv is None else argv
    if selected and selected[0] == "bundle":
        from reproduction import main as reproduction_main
        return reproduction_main(["generate"] + list(selected[1:]))
    if selected and selected[0] == "evidence":
        from evidence_integrity import main as evidence_main
        return evidence_main(["verify"] + list(selected[1:]))
    parser = argparse.ArgumentParser(description=__doc__, epilog="Generate reproduction artifacts without changing findings: bundle FINDINGS --finding ID --plan PLAN --out NEW_DIRECTORY")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "status", "audit", "next", "handoff", "submit", "resume", "invalidate"):
        child = sub.add_parser(command)
        child.add_argument("findings", type=Path)
        child.add_argument("--evidence-root", type=Path)
        child.add_argument("--evidence-repository", type=Path)
        if command != "audit":
            child.add_argument("--finding", required=command != "status")
        if command in ("status", "audit"):
            child.add_argument("--require-complete", action="store_true", help="exit 3 unless the requested workflow or whole three-pass audit is complete")
        if command in ("init", "resume", "invalidate"):
            child.add_argument("--actor", required=True)
            child.add_argument("--reason", required=command != "init", default="Initialize sequential verification")
        if command == "submit":
            child.add_argument("--submission", type=Path, required=True)
        if command in ("next", "handoff", "audit"):
            child.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.evidence_repository and not args.evidence_root:
        parser.error("--evidence-repository requires --evidence-root")
    lock = None
    try:
        if args.command in ("init", "submit", "resume", "invalidate"):
            lock_path = args.findings.with_name(args.findings.name + ".workflow.lock")
            try:
                fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                _error(str(lock_path), "workflow writer lock exists; check the other writer before removing a stale lock")
            os.close(fd)
            lock = lock_path
        data, raw = _read_json(args.findings)
        _object(data, "input")
        _validate_base(data)
        integrity = None
        if args.evidence_root:
            from evidence_integrity import verify_evidence
            try:
                integrity = verify_evidence(data, args.evidence_root, repository=args.evidence_repository)
            except (ValueError, OSError):
                _error("evidence_integrity", "cannot check the explicit local evidence roots")
        # Derived caches are renderer-only and never written by the controller.
        for finding in data["findings"]:
            finding.pop("_workflow", None)
            finding.pop("_verification", None)
        if args.command == "audit":
            result = derive_three_pass(data, WorkflowError, integrity)
        elif args.command == "init":
            result = initialize(data, args.finding, args.actor, args.reason, integrity)
        elif args.command == "submit":
            output, _ = _read_json(args.submission)
            result = submit(data, args.finding, output, integrity)
        elif args.command in ("resume", "invalidate"):
            result = globals()[args.command](data, args.finding, args.actor, args.reason, integrity)
        elif args.command in ("next", "handoff"):
            result = next_handoff(data, args.finding, integrity)
        else:
            selected = [_finding(data, args.finding)] if args.finding else data["findings"]
            result = {finding["id"]: derive_workflow(data, finding, WorkflowError, integrity) for finding in selected}
        if lock is not None:
            _save(args.findings, data, raw)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if getattr(args, "out", None):
            with args.out.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        else:
            print(rendered, end="")
        if args.command == "audit" and args.require_complete and result["status"] != "complete":
            return 3
        if args.command == "status" and args.require_complete and (not result or any(not state["opted_in"] or state["status"] != "complete" for state in result.values())):
            return 3
        return 0
    except RecursionError:
        print("workflow error: input: JSON nesting is too deep", file=sys.stderr)
        return 2
    except (WorkflowError, ValueError, OSError, KeyError, TypeError) as exc:
        print("workflow error: " + str(exc), file=sys.stderr)
        return 2
    finally:
        if lock is not None:
            try:
                lock.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    sys.exit(main())
