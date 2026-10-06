"""Validate recorded verification structure; never execute tests or prove a claim.

Only explicit schema version 2 findings with structured ``verification`` opt in.
Other findings retain their historical verdict but receive no verification credit.
Artifact paths, hashes and reviewer identities are records, not attestations.
"""
import re
from datetime import datetime

CLAIMS = ("reachability", "preconditions", "defenses", "impact")
LEVELS = ("legacy", "incomplete", "static_supported", "runtime_supported", "environment_unverified")
RETESTS = ("not_requested", "fix_claimed", "verified", "incomplete")
GAPS = (
    "legacy_details_missing", "verdict_unresolved", "claims_incomplete", "falsification_incomplete",
    "review_missing", "review_disagreement", "environment_unknown",
    "runtime_incomplete", "runtime_contradiction", "runtime_boundary_unverified", "retest_missing",
    "retest_before_unverified", "retest_after_unverified", "retest_case_mismatch",
    "retest_context_mismatch", "retest_version_mismatch", "retest_control_missing",
    "retest_control_failed", "retest_regression_missing", "retest_regression_failed",
    "retest_verification_incomplete",
    "evidence_integrity_unchecked", "evidence_integrity_failed",
)
DEFINITIVE = ("Valid", "FalsePositive", "NotApplicable")


class _Validator:
    def __init__(self, data, error_type, integrity=None):
        self.data, self.error_type = data, error_type
        self.integrity = integrity
        self.integrity_required = False
        self.evidence, self.runs = {}, {}
        self.assessment_pin = None
        self.structured = False

    def error(self, where, message):
        raise self.error_type("{}: {}".format(where, message))

    def obj(self, value, where):
        if not isinstance(value, dict):
            self.error(where, "must be an object")
        return value

    def text(self, obj, key, where, optional=False):
        if optional and key not in obj:
            return ""
        value = obj.get(key)
        if not isinstance(value, str) or not value.strip():
            self.error(where + "." + key, "required nonblank string")
        if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
            self.error(where + "." + key, "must not contain control characters")
        return value

    def enum(self, obj, key, allowed, where):
        value = self.text(obj, key, where)
        if value not in allowed:
            self.error(where + "." + key, "one of " + ", ".join(allowed))
        return value

    def items(self, value, where):
        if not isinstance(value, list):
            self.error(where, "must be a list")
        return value

    def pin(self, obj, where):
        commit = self.text(obj, "commit", where)
        if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", commit):
            self.error(where + ".commit", "must be a full 40- or 64-character Git object ID")
        diff = self.text(obj, "diff_sha256", where, optional=True)
        if diff and not re.fullmatch(r"[0-9a-fA-F]{64}", diff):
            self.error(where + ".diff_sha256", "must be a SHA-256 hex digest")
        return commit.lower(), diff.lower()

    def refs(self, obj, key, where, catalog, required=False, pin=None, kind=None):
        refs = self.items(obj.get(key, []), where + "." + key)
        seen = set()
        for i, ref in enumerate(refs):
            at = "{}.{}[{}]".format(where, key, i)
            if not isinstance(ref, str) or not ref.strip():
                self.error(at, "must be a nonblank ID")
            if ref in seen:
                self.error(at, "duplicate ID")
            seen.add(ref)
            if ref not in catalog:
                self.error(at, "unknown ID")
            if pin is not None and self.pin(catalog[ref], at) != pin:
                self.error(at, "does not match the required commit/worktree pin")
            if kind and catalog[ref].get("kind") != kind:
                self.error(at, "must reference " + kind + " evidence")
        if required and not refs:
            self.error(where + "." + key, "at least one evidence reference is required")
        return refs

    def catalog(self, key, callback):
        result = {}
        for i, value in enumerate(self.items(self.data.get(key, []), key)):
            where = "{}[{}]".format(key, i)
            item = self.obj(value, where)
            identifier = self.text(item, "id", where)
            if identifier in result:
                self.error(where + ".id", "duplicate ID")
            callback(item, where)
            result[identifier] = item
        return result

    def evidence_record(self, record, where):
        self.enum(record, "kind", ("source", "runtime", "environment"), where)
        self.pin(record, where)
        for key in ("location", "summary", "sha256"):
            self.text(record, key, where)
        if "source_path" in record:
            self.text(record, "source_path", where)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", record["sha256"]):
            self.error(where + ".sha256", "must be a SHA-256 hex digest")

    def run_record(self, run, where):
        pin = self.pin(run, where)
        for key in ("case_id", "expected", "observed", "command", "recorded_at"):
            self.text(run, key, where)
        try:
            timestamp = datetime.fromisoformat(run["recorded_at"].replace("Z", "+00:00"))
            if timestamp.utcoffset() is None:
                raise ValueError()
        except ValueError:
            self.error(where + ".recorded_at", "must be an ISO-8601 timestamp with timezone")
        self.enum(run, "role", ("security", "positive_control", "regression"), where)
        result = self.enum(run, "result", ("pass", "fail", "not_run", "blocked", "unsupported", "error", "skip"), where)
        failure = self.enum(run, "failure_kind", ("none", "assertion", "infrastructure"), where)
        code = run.get("exit_code")
        if code is not None and type(code) is not int:
            self.error(where + ".exit_code", "must be an integer or null")
        if result == "pass" and (code != 0 or failure != "none"):
            self.error(where, "pass requires exit_code 0 and failure_kind none")
        if result == "fail" and (code is None or code == 0 or failure == "none"):
            self.error(where, "fail requires nonzero exit_code and a failure_kind")
        context = self.obj(run.get("context"), where + ".context")
        self.enum(context, "environment", ("local", "throwaway"), where + ".context")
        self.enum(context, "boundary", ("real", "mocked", "unknown"), where + ".context")
        for key in ("configuration", "fixture", "test_version"):
            self.text(context, key, where + ".context")
        self.refs(run, "evidence_ids", where, self.evidence,
                  required=result in ("pass", "fail"), pin=pin, kind="runtime")

    def setup(self):
        version = self.data.get("schema_version", 1)
        if type(version) is not int or version not in (1, 2):
            self.error("schema_version", "must be 1 or 2")
        if version != 2:
            # Version 1 allowed arbitrary extension fields. Preserve them as
            # historical records without interpreting them as new proof.
            return
        self.structured = True
        if "evidence_integrity" in self.data:
            policy = self.obj(self.data["evidence_integrity"], "evidence_integrity")
            if set(policy) != {"required"} or type(policy.get("required")) is not bool:
                self.error("evidence_integrity", "requires only a boolean required field")
            self.integrity_required = policy["required"]
        assessment = self.obj(self.data.get("assessment"), "assessment")
        self.text(assessment, "repository", "assessment")
        self.assessment_pin = self.pin(assessment, "assessment")
        worktree = self.enum(assessment, "worktree", ("clean", "dirty"), "assessment")
        if (worktree == "dirty") != bool(self.assessment_pin[1]):
            self.error("assessment.diff_sha256", "required exactly when worktree is dirty")
        meta_commit = self.data.get("meta", {}).get("commit", "")
        if meta_commit and meta_commit.lower() != self.assessment_pin[0]:
            self.error("meta.commit", "must match assessment.commit")
        self.evidence = self.catalog("evidence", self.evidence_record)
        self.runs = self.catalog("test_runs", self.run_record)

    def current_refs(self, obj, where, required=False):
        return self.refs(obj, "evidence_ids", where, self.evidence,
                         required=required, pin=self.assessment_pin)

    def resolution(self, record, where):
        if "resolution" not in record:
            return False
        resolution = self.obj(record["resolution"], where + ".resolution")
        self.text(resolution, "reason", where + ".resolution")
        reviewer = self.text(resolution, "reviewer", where + ".resolution")
        if reviewer.strip().casefold() != record["reviewer"].strip().casefold():
            self.error(where + ".resolution.reviewer", "must be the dissenting reviewer")
        self.current_refs(resolution, where + ".resolution", required=True)
        return True

    @staticmethod
    def legitimate_red(run):
        return (run["role"] == "security" and run["result"] == "fail"
                and run["failure_kind"] == "assertion" and run["exit_code"] > 0
                and run["context"]["boundary"] == "real")

    @staticmethod
    def passed(run, role):
        return run["role"] == role and run["result"] == "pass" and run["context"]["boundary"] == "real"

    @staticmethod
    def context(run):
        return tuple(run["context"][key] for key in
                     ("environment", "configuration", "fixture", "test_version", "boundary"))

    def retest(self, finding, verification, level, where):
        if "remediation" not in finding:
            return ("fix_claimed", ["retest_missing"]) if finding.get("status") == "Fixed" else ("not_requested", [])
        remediation = self.obj(finding["remediation"], where + ".remediation")
        at = where + ".remediation"
        fixed_pin = self.pin(remediation, at)
        gaps = []
        pairs = {}
        for key in ("before_run_id", "after_run_id"):
            if key in remediation:
                ref = self.text(remediation, key, at)
                if ref not in self.runs:
                    self.error(at + "." + key, "unknown run ID")
                pairs[key] = self.runs[ref]
        before, after = pairs.get("before_run_id"), pairs.get("after_run_id")
        if not before or not self.legitimate_red(before) or remediation.get("before_run_id") not in verification.get("run_ids", []):
            gaps.append("retest_before_unverified")
        if not after or not self.passed(after, "security"):
            gaps.append("retest_after_unverified")
        if before and self.pin(before, at) != self.assessment_pin:
            gaps.append("retest_version_mismatch")
        if after and self.pin(after, at) != fixed_pin:
            gaps.append("retest_version_mismatch")
        if fixed_pin == self.assessment_pin:
            gaps.append("retest_version_mismatch")
        if before and after:
            if before["case_id"] != after["case_id"] or before["expected"] != after["expected"]:
                gaps.append("retest_case_mismatch")
            if self.context(before) != self.context(after):
                gaps.append("retest_context_mismatch")
        for key, role, label in (("positive_control_run_ids", "positive_control", "control"),
                                 ("regression_run_ids", "regression", "regression")):
            refs = self.refs(remediation, key, at, self.runs)
            if not refs:
                gaps.append("retest_" + label + "_missing")
            for ref in refs:
                run = self.runs[ref]
                if not self.passed(run, role):
                    gaps.append("retest_" + label + "_failed")
                if self.pin(run, at) != fixed_pin:
                    gaps.append("retest_version_mismatch")
                if after and self.context(run) != self.context(after):
                    gaps.append("retest_context_mismatch")
                if after and run["case_id"] == after["case_id"]:
                    gaps.append("retest_case_mismatch")
        if level != "runtime_supported" or finding.get("validation", {}).get("verdict") != "Valid":
            gaps.append("retest_verification_incomplete")
        return ("incomplete" if gaps else "verified"), gaps

    def finding(self, finding, where):
        # A historical free-text verification note is not structured evidence.
        if not self.structured or "verification" not in finding or isinstance(finding["verification"], str):
            if self.structured and "remediation" in finding:
                self.error(where + ".remediation", "requires structured verification")
            return {"level": "legacy", "retest": "fix_claimed" if finding.get("status") == "Fixed" else "not_requested",
                    "gaps": ["legacy_details_missing"] + (["retest_missing"] if finding.get("status") == "Fixed" else []),
                    "evidence_ids": [], "run_ids": [], "integrity": integrity_state(self.data, [], None)}
        verification = self.obj(finding["verification"], where + ".verification")
        at = where + ".verification"
        reviewer = self.text(verification, "reviewer", at)
        claims = self.obj(verification.get("claims"), at + ".claims")
        claim_refs = set()
        all_refs = set()
        statuses = []
        static_claims = True
        for key in CLAIMS:
            claim_at = at + ".claims." + key
            claim = self.obj(claims.get(key), claim_at)
            status = self.enum(claim, "status", ("supported", "contradicted", "unknown"), claim_at)
            self.text(claim, "reason", claim_at)
            refs = self.current_refs(claim, claim_at, required=status != "unknown")
            claim_refs.update(refs)
            statuses.append(status)
            static_claims = static_claims and any(self.evidence[ref]["kind"] == "source" for ref in refs)
        all_refs.update(claim_refs)
        verdict = finding.get("validation", {}).get("verdict", "Unverified")
        if verdict == "Valid" and any(status != "supported" for status in statuses):
            self.error(at + ".claims", "Valid requires all four claims supported with evidence")
        if verdict in ("FalsePositive", "NotApplicable"):
            exclusion = self.obj(verification.get("exclusion"), at + ".exclusion")
            basis = self.enum(exclusion, "basis", ("condition_absent", "not_applicable"), at + ".exclusion")
            if basis != ("condition_absent" if verdict == "FalsePositive" else "not_applicable"):
                self.error(at + ".exclusion.basis", "does not match the verdict")
            self.text(exclusion, "reason", at + ".exclusion")
            all_refs.update(self.current_refs(exclusion, at + ".exclusion", required=True))
            if "contradicted" not in statuses:
                self.error(at + ".claims", "exclusion requires an evidence-backed contradicted claim")
        elif "exclusion" in verification:
            self.error(at + ".exclusion", "only allowed for FalsePositive or NotApplicable")
        checks = self.items(verification.get("falsification", []), at + ".falsification")
        if verdict in DEFINITIVE and not checks:
            self.error(at + ".falsification", "definitive verdict requires evidence-backed falsification checks")
        check_results = []
        for i, value in enumerate(checks):
            check_at = at + ".falsification[{}]".format(i)
            check = self.obj(value, check_at)
            for key in ("check", "reason"):
                self.text(check, key, check_at)
            result = self.enum(check, "result", ("clear", "contradiction", "unresolved"), check_at)
            all_refs.update(self.current_refs(check, check_at, required=result != "unresolved"))
            check_results.append(result)
        if verdict == "Valid" and any(result != "clear" for result in check_results):
            self.error(at + ".falsification", "Valid cannot contain unresolved or contradictory checks")
        gaps = []
        if verdict not in DEFINITIVE:
            gaps.append("verdict_unresolved")
        if "unknown" in statuses or not static_claims or (verdict not in ("FalsePositive", "NotApplicable") and "contradicted" in statuses):
            gaps.append("claims_incomplete")
        if not checks or "unresolved" in check_results:
            gaps.append("falsification_incomplete")
        reviews = self.items(verification.get("reviews", []), at + ".reviews")
        independent = False
        for i, value in enumerate(reviews):
            review_at = at + ".reviews[{}]".format(i)
            review = self.obj(value, review_at)
            author = self.text(review, "reviewer", review_at)
            self.text(review, "reason", review_at)
            conclusion = self.enum(review, "conclusion", ("agree", "disagree", "unresolved"), review_at)
            refs = self.current_refs(review, review_at, required=True)
            all_refs.update(refs)
            resolved = self.resolution(review, review_at)
            if resolved:
                all_refs.update(review["resolution"]["evidence_ids"])
            if conclusion != "agree" and not resolved:
                gaps.append("review_disagreement")
            if author.strip().casefold() != reviewer.strip().casefold() and (conclusion == "agree" or resolved) and claim_refs.issubset(refs):
                independent = True
        if finding.get("severity") == "High" and verdict in DEFINITIVE and not independent:
            gaps.append("review_missing")
        environment = self.obj(verification.get("environment"), at + ".environment")
        status = self.enum(environment, "status", ("not_required", "verified", "unknown"), at + ".environment")
        self.text(environment, "reason", at + ".environment")
        all_refs.update(self.refs(environment, "evidence_ids", at + ".environment", self.evidence,
                                 required=status == "verified", pin=self.assessment_pin, kind="environment"))
        if status == "unknown":
            gaps.append("environment_unknown")
        run_ids = self.refs(verification, "run_ids", at, self.runs, pin=self.assessment_pin)
        runtime = False
        for ref in run_ids:
            run = self.runs[ref]
            if self.legitimate_red(run):
                runtime = True
            else:
                gaps.append("runtime_incomplete")
            if ((verdict == "Valid" and self.passed(run, "security"))
                    or (verdict in ("FalsePositive", "NotApplicable") and self.legitimate_red(run))):
                gaps.append("runtime_contradiction")
            if run["context"]["boundary"] != "real":
                gaps.append("runtime_boundary_unverified")
        blocking = set(gaps) - {"runtime_incomplete", "runtime_boundary_unverified", "environment_unknown"}
        runtime = runtime and "runtime_incomplete" not in gaps
        level = "incomplete" if blocking else ("runtime_supported" if runtime and verdict == "Valid" else "static_supported")
        if status == "unknown" and not blocking:
            level = "environment_unverified"
        retest, retest_gaps = self.retest(finding, verification, level, where)
        gaps.extend(retest_gaps)
        all_runs = set(run_ids)
        remediation = finding.get("remediation", {})
        for key in ("before_run_id", "after_run_id"):
            if key in remediation:
                all_runs.add(remediation[key])
        for key in ("positive_control_run_ids", "regression_run_ids"):
            all_runs.update(remediation.get(key, []))
        for ref in all_runs:
            all_refs.update(self.runs[ref].get("evidence_ids", []))
        provenance = integrity_state(self.data, sorted(all_refs), self.integrity)
        # Recorded declarations retain their previous interpretation. Explicit
        # required policy, or a freshly observed contrary file check, cannot be
        # bypassed by a supplied verdict, historical receipt or completed journal.
        if provenance["status"] == "incomplete" or (self.integrity_required and provenance["status"] != "checked"):
            gaps.append("evidence_integrity_failed" if provenance["status"] == "incomplete" else "evidence_integrity_unchecked")
            level = "incomplete"
            if retest == "verified":
                retest = "incomplete"
                gaps.append("retest_verification_incomplete")
        # Derived output is intentionally codes/IDs only; report text is escaped by its renderer.
        return {"level": level, "retest": retest, "gaps": sorted(set(gaps)),
                "evidence_ids": sorted(all_refs), "run_ids": sorted(all_runs), "integrity": provenance}


def integrity_state(data, evidence_ids, integrity=None):
    """Curate fresh byte/source checks separately from recorded support levels."""
    # Old schemas allow arbitrary extension records and IDs. Merely rendering
    # their declarations must not opt into the stricter local-reader contract.
    if integrity is None or data.get("schema_version", 1) != 2:
        return {"status": "declared", "reasons": ["not_checked"], "records": [],
                "bytes_checked": 0, "sources_checked": 0, "evidence_total": len(evidence_ids)}
    from evidence_integrity import provenance_state
    result = provenance_state(data, evidence_ids, integrity)
    records = result.get("records", [])
    result.update(bytes_checked=sum(item.get("bytes") == "matched" for item in records),
                  sources_checked=sum(item.get("source") == "matched" for item in records),
                  evidence_total=len(evidence_ids))
    return result


def derive_verification(data, error_type=ValueError, integrity=None):
    """Return fresh per-finding states without mutating/trusting derived input.

    Base finding fields are validated by render.load before this function. Errors
    use the supplied SchemaError type so malformed new records retain CLI exit 2.
    """
    validator = _Validator(data, error_type, integrity)
    validator.setup()
    return {finding["id"]: validator.finding(finding, "findings[{}]".format(i))
            for i, finding in enumerate(data["findings"])}


def validate_verification(data, error_type=ValueError, integrity=None):
    """Validate and replace every user-supplied derived finding state."""
    for finding in data["findings"]:
        finding.pop("_verification", None)
    states = derive_verification(data, error_type, integrity)
    for finding in data["findings"]:
        finding["_verification"] = states[finding["id"]]
    return data
