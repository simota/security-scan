#!/usr/bin/env python3
"""Validate and aggregate sealed, static source-review detection evidence.

This adapter never runs a target, scanner, judge, or network request. It only
validates recorded JSON and derives bounded measurements from it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import statistics
import sys
import tempfile


METHOD_VERSION = "security-scan-detection-v3"
SCHEMA_VERSION = 3
MODALITY = "static-source-review"
ARTEX_MODALITY = "black-box-execution"
MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 32
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
PIN = re.compile(r"(?:git:[0-9a-f]{40}|sha256:[0-9a-f]{64})")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
GATES = ("component", "class", "keywords", "proof")
GATE_WEIGHTS = {"component": 1, "class": 2, "keywords": 1, "proof": 1}


class Refusal(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def refuse(condition, code, message):
    if condition:
        raise Refusal(code, message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        refuse(key in value, "duplicate_json_key", f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def json_depth(value):
    pending = [(value, 1)]
    deepest = 0
    while pending:
        item, depth = pending.pop()
        deepest = max(deepest, depth)
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return deepest


def read_json(path):
    path = Path(path)
    try:
        info = path.lstat()
        refuse(stat.S_ISLNK(info.st_mode), "unsafe_input", f"{path}: symbolic links are not accepted")
        refuse(not stat.S_ISREG(info.st_mode), "unsafe_input", f"{path}: input must be a regular file")
        refuse(info.st_size > MAX_BYTES, "input_too_large", f"{path}: exceeds {MAX_BYTES} bytes")
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                Refusal("invalid_json_number", f"{path}: non-finite number {token}")),
        )
        # A \ud800-style escape decodes to a lone surrogate that sealing cannot encode.
        canonical(value)
    except Refusal:
        raise
    except (OSError, ValueError, RecursionError) as error:
        # ValueError covers JSONDecodeError, Unicode errors and integer literals
        # longer than the interpreter's int-string conversion limit.
        raise Refusal("unreadable_input", f"{path}: {error}") from None
    refuse(json_depth(value) > MAX_DEPTH, "input_too_deep", f"{path}: JSON nesting exceeds {MAX_DEPTH}")
    return value, raw


def read_source_artifact(source_root, relative_path):
    text(relative_path, "ground_truth.source.artifact_path")
    logical = PurePosixPath(relative_path)
    refuse(not logical.parts or logical.is_absolute() or ".." in logical.parts or "\\" in relative_path,
           "unsafe_source_artifact", "ground_truth.source.artifact_path: safe relative POSIX path required")
    target = Path(source_root)
    try:
        for index, part in enumerate(logical.parts):
            target = target / part
            info = target.lstat()
            refuse(stat.S_ISLNK(info.st_mode), "unsafe_source_artifact",
                   f"{target}: symbolic links are not accepted")
            if index < len(logical.parts) - 1:
                refuse(not stat.S_ISDIR(info.st_mode), "unsafe_source_artifact",
                       f"{target}: source-artifact parent must be a directory")
        refuse(not stat.S_ISREG(info.st_mode), "unsafe_source_artifact",
               f"{target}: source artifact must be a regular file")
        refuse(info.st_size > MAX_BYTES, "source_artifact_too_large",
               f"{target}: exceeds {MAX_BYTES} bytes")
        raw = target.read_bytes()
        rendered = raw.decode("utf-8")
    except Refusal:
        raise
    except (OSError, UnicodeError) as error:
        raise Refusal("missing_source_artifact", f"{target}: {error}") from None
    return raw, source_lines(rendered)


def source_lines(rendered):
    # Number lines by LF (tolerating CRLF) like editors and file:line references;
    # str.splitlines() would also split on FF, VT, NEL, and U+2028/U+2029.
    lines = rendered.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sealed(document):
    result = dict(document)
    result["seal"] = {"algorithm": "sha256", "payload_sha256": digest(canonical(document))}
    return result


def verify_seal(document, where):
    refuse(not isinstance(document, dict), "invalid_result", f"{where}: result must be an object")
    seal = document.get("seal")
    refuse(not isinstance(seal, dict) or set(seal) != {"algorithm", "payload_sha256"},
           "invalid_result_seal", f"{where}: missing or malformed result seal")
    refuse(seal.get("algorithm") != "sha256", "invalid_result_seal", f"{where}: unsupported seal algorithm")
    payload = dict(document)
    payload.pop("seal")
    expected = digest(canonical(payload))
    refuse(seal.get("payload_sha256") != expected, "result_identity_mismatch",
           f"{where}: result payload does not match its seal")


def exact_keys(value, required, optional, where):
    refuse(not isinstance(value, dict), "invalid_schema", f"{where}: must be an object")
    missing = required - set(value)
    extra = set(value) - required - optional
    refuse(bool(missing), "invalid_schema", f"{where}: missing keys {sorted(missing)}")
    refuse(bool(extra), "invalid_schema", f"{where}: unsupported keys {sorted(extra)}")


def text(value, where, *, identifier=False, allow_tab=False):
    refuse(not isinstance(value, str) or not value.strip(), "invalid_schema", f"{where}: nonblank string required")
    refuse(len(value) > 4096, "invalid_schema", f"{where}: string is too long")
    refuse(any(ord(character) < 32 and not (allow_tab and character == "\t") for character in value),
           "invalid_schema", f"{where}: control characters are not allowed")
    if identifier:
        refuse(not IDENTIFIER.fullmatch(value), "invalid_schema", f"{where}: invalid identifier")
    return value


def integer(value, where):
    refuse(type(value) is not int or value < 0, "invalid_schema", f"{where}: non-negative integer required")
    return value


def number(value, where):
    refuse(type(value) not in (int, float), "invalid_schema", f"{where}: non-negative finite number required")
    try:
        finite = math.isfinite(float(value))
    except OverflowError:
        finite = False
    refuse(not finite or value < 0, "invalid_schema", f"{where}: non-negative finite number required")
    return value


def validate_ground_truth(data, source_root):
    required = {"schema_version", "benchmark_id", "version", "modality", "source", "cases"}
    exact_keys(data, required, set(), "ground_truth")
    refuse(data["schema_version"] != SCHEMA_VERSION, "unsupported_schema",
           f"ground_truth.schema_version: must be {SCHEMA_VERSION}")
    text(data["benchmark_id"], "ground_truth.benchmark_id", identifier=True)
    text(data["version"], "ground_truth.version")
    refuse(data["modality"] != MODALITY, "non_comparable_modality",
           f"ground_truth.modality: {data['modality']!r} is not {MODALITY!r}")
    exact_keys(data["source"], {"kind", "uri", "artifact_path", "revision", "artifact_sha256", "license"}, set(),
               "ground_truth.source")
    refuse(data["source"]["kind"] not in ("public", "synthetic"), "invalid_schema",
           "ground_truth.source.kind: must be public or synthetic")
    text(data["source"]["uri"], "ground_truth.source.uri")
    revision = text(data["source"]["revision"], "ground_truth.source.revision")
    refuse(not PIN.fullmatch(revision), "unpinned_source",
           "ground_truth.source.revision: use git:<40 lowercase hex> or sha256:<64 lowercase hex>")
    artifact_sha = text(data["source"]["artifact_sha256"], "ground_truth.source.artifact_sha256")
    refuse(not SHA256.fullmatch(artifact_sha), "invalid_schema",
           "ground_truth.source.artifact_sha256: sha256:<64 lowercase hex> required")
    text(data["source"]["license"], "ground_truth.source.license")
    artifact_raw, artifact_lines = read_source_artifact(source_root, data["source"]["artifact_path"])
    refuse(digest(artifact_raw) != artifact_sha, "source_artifact_mismatch",
           "ground_truth.source.artifact_sha256 does not match the local artifact bytes")
    if data["source"]["kind"] == "synthetic":
        refuse(revision != artifact_sha, "input_identity_mismatch",
               "synthetic source revision must equal the verified source-artifact SHA-256")
    cases = data["cases"]
    refuse(not isinstance(cases, list) or not cases, "invalid_schema", "ground_truth.cases: nonempty list required")
    seen = set()
    for index, case in enumerate(cases):
        where = f"ground_truth.cases[{index}]"
        exact_keys(case, {"id", "disposition", "title", "location", "component", "vulnerability_class",
                          "mechanism", "gate_expectations"}, set(), where)
        identifier = text(case["id"], where + ".id", identifier=True)
        refuse(identifier in seen, "duplicate_case", f"{where}.id: duplicate {identifier}")
        seen.add(identifier)
        refuse(case["disposition"] not in ("vulnerable", "benign"), "invalid_schema",
               f"{where}.disposition: must be vulnerable or benign")
        for key in ("title", "location", "component", "vulnerability_class", "mechanism"):
            text(case[key], f"{where}.{key}")
        try:
            location_path, line_text = case["location"].rsplit(":", 1)
            line_number = int(line_text)
        except (ValueError, AttributeError):
            raise Refusal("invalid_source_location", f"{where}.location: artifact_path:line required") from None
        refuse(location_path != data["source"]["artifact_path"] or line_number < 1 or
               line_number > len(artifact_lines), "invalid_source_location",
               f"{where}.location: does not identify a line in the verified source artifact")
        refuse(not artifact_lines[line_number - 1].strip(), "invalid_source_location",
               f"{where}.location: source line is blank")
        exact_keys(case["gate_expectations"], set(GATES), set(), where + ".gate_expectations")
        for gate in GATES:
            expectation = case["gate_expectations"][gate]
            exact_keys(expectation, {"finding_terms", "source_terms"}, set(),
                       f"{where}.gate_expectations.{gate}")
            for key in ("finding_terms", "source_terms"):
                terms = expectation[key]
                refuse(not isinstance(terms, list) or not terms, "invalid_schema",
                       f"{where}.gate_expectations.{gate}.{key}: nonempty list required")
                for term_index, term in enumerate(terms):
                    text(term, f"{where}.gate_expectations.{gate}.{key}[{term_index}]")
    dispositions = {case["disposition"] for case in cases}
    refuse(dispositions != {"vulnerable", "benign"}, "invalid_schema",
           "ground_truth.cases: requires at least one vulnerable and one reviewed benign case")
    return ({case["id"]: case for case in cases}, artifact_lines)


def validate_byte_record(record, where):
    exact_keys(record, {"encoding", "content", "sha256"}, set(), where)
    refuse(record["encoding"] != "utf-8", "invalid_schema", f"{where}.encoding: must be utf-8")
    content = record["content"]
    refuse(not isinstance(content, str) or not content or len(content.encode("utf-8")) > MAX_BYTES,
           "invalid_schema", f"{where}.content: nonempty bounded UTF-8 text required")
    declared = text(record["sha256"], where + ".sha256")
    refuse(not SHA256.fullmatch(declared), "invalid_schema", f"{where}.sha256: invalid SHA-256")
    refuse(digest(content.encode("utf-8")) != declared, "input_bytes_mismatch",
           f"{where}.sha256 does not match the embedded UTF-8 bytes")
    return declared


def execution_input_fingerprint(manifest, ground_truth, gt_sha, configuration_sha, input_set_sha):
    return digest(canonical({
        "method_version": manifest["method_version"],
        "ground_truth_sha256": gt_sha,
        "source_artifact_sha256": ground_truth["source"]["artifact_sha256"],
        "scanner": manifest["scanner"],
        "scanner_configuration_sha256": configuration_sha,
        "input_set_sha256": input_set_sha,
        "condition": manifest["condition"],
    }))


def validate_manifest(manifest, ground_truth, gt_sha):
    required = {
        "schema_version", "method_version", "run_id", "status", "modality",
        "ground_truth_sha256", "benchmark_id", "benchmark_version", "source_revision",
        "scanner", "scanner_configuration", "input_set", "condition", "resources", "adjudicator",
    }
    exact_keys(manifest, required, set(), "run.manifest")
    refuse(manifest["schema_version"] != SCHEMA_VERSION, "unsupported_schema",
           f"run.manifest.schema_version: must be {SCHEMA_VERSION}")
    refuse(manifest["method_version"] != METHOD_VERSION, "unsupported_method",
           f"run.manifest.method_version: must be {METHOD_VERSION}")
    text(manifest["run_id"], "run.manifest.run_id", identifier=True)
    refuse(manifest["status"] != "complete", "incomplete_run", "run.manifest.status: only complete runs can be measured")
    refuse(manifest["modality"] != MODALITY, "non_comparable_modality",
           f"run.manifest.modality: {manifest['modality']!r} is not {MODALITY!r}")
    refuse(not isinstance(manifest["ground_truth_sha256"], str) or not SHA256.fullmatch(manifest["ground_truth_sha256"]),
           "invalid_schema", "run.manifest.ground_truth_sha256: sha256:<64 lowercase hex> required")
    refuse(manifest["ground_truth_sha256"] != gt_sha, "input_identity_mismatch",
           "run.manifest.ground_truth_sha256 does not match the supplied ground-truth bytes")
    identities = (
        ("benchmark_id", ground_truth["benchmark_id"]),
        ("benchmark_version", ground_truth["version"]),
        ("source_revision", ground_truth["source"]["revision"]),
    )
    for key, expected in identities:
        text(manifest[key], f"run.manifest.{key}")
        refuse(manifest[key] != expected, "input_identity_mismatch",
               f"run.manifest.{key} does not match ground truth")
    exact_keys(manifest["scanner"], {"name", "version", "configuration", "subject_model", "subject_role"},
               set(), "run.manifest.scanner")
    for key in ("name", "version", "configuration", "subject_model", "subject_role"):
        text(manifest["scanner"][key], f"run.manifest.scanner.{key}")
    configuration_sha = validate_byte_record(manifest["scanner_configuration"],
                                             "run.manifest.scanner_configuration")
    input_set_sha = validate_byte_record(manifest["input_set"], "run.manifest.input_set")
    exact_keys(manifest["condition"], {"id", "source_access"}, set(), "run.manifest.condition")
    text(manifest["condition"]["id"], "run.manifest.condition.id", identifier=True)
    refuse(manifest["condition"]["source_access"] != "full-source", "non_comparable_modality",
           "run.manifest.condition.source_access: must be full-source")
    exact_keys(manifest["resources"],
               {"wall_seconds", "worker_count", "model_calls", "input_tokens", "output_tokens",
                "estimated_cost_usd"},
               set(), "run.manifest.resources")
    for key in ("wall_seconds", "worker_count", "model_calls", "input_tokens", "output_tokens"):
        value = manifest["resources"][key]
        integer(value, f"run.manifest.resources.{key}")
    number(manifest["resources"]["estimated_cost_usd"], "run.manifest.resources.estimated_cost_usd")
    refuse(manifest["resources"]["wall_seconds"] == 0, "invalid_schema",
           "run.manifest.resources.wall_seconds: completed runs require a positive duration")
    refuse(manifest["resources"]["worker_count"] == 0, "invalid_schema",
           "run.manifest.resources.worker_count: completed runs require at least one worker")
    exact_keys(manifest["adjudicator"], {"kind", "identity"}, set(), "run.manifest.adjudicator")
    refuse(manifest["adjudicator"]["kind"] not in ("independent-human", "fixture-oracle"), "invalid_schema",
           "run.manifest.adjudicator.kind: must be independent-human or fixture-oracle")
    text(manifest["adjudicator"]["identity"], "run.manifest.adjudicator.identity")
    return (configuration_sha, input_set_sha,
            execution_input_fingerprint(manifest, ground_truth, gt_sha, configuration_sha, input_set_sha))


def finding_text(finding):
    return " ".join(value.strip() for key in ("summary", "report", "impact", "request")
                    if isinstance((value := finding.get(key)), str) and value.strip())


def validate_findings(findings):
    refuse(not isinstance(findings, list), "invalid_schema", "run.findings: must be a list")
    seen = set()
    valid = {}
    invalid = []
    for index, finding in enumerate(findings):
        where = f"run.findings[{index}]"
        refuse(not isinstance(finding, dict), "invalid_schema", f"{where}: must be an object")
        identifier = text(finding.get("id"), where + ".id", identifier=True)
        refuse(identifier in seen, "duplicate_finding", f"{where}.id: duplicate {identifier}")
        seen.add(identifier)
        title = finding.get("title", finding.get("name", ""))
        if title is not None:
            refuse(not isinstance(title, str), "invalid_schema", f"{where}.title: must be a string")
            # The title is only a display label; fold control characters and
            # whitespace runs so the sealed result passes its own validation.
            title = " ".join("".join(" " if ord(character) < 32 else character for character in title).split())
        evidence = finding_text(finding)
        if not evidence:
            invalid.append({"id": identifier, "reason": "no summary, report, impact, or request evidence"})
        else:
            valid[identifier] = {
                "id": identifier,
                "title": (title or "untitled")[:200].rstrip(),
                "evidence": evidence,
            }
    return valid, invalid


def validate_source_evidence(evidence, case, artifact_lines, where, *, finding_text_value=None):
    required = {"source_location", "source_excerpt"}
    if finding_text_value is not None:
        required.add("finding_excerpt")
    exact_keys(evidence, required, set(), where)
    source_location = text(evidence["source_location"], where + ".source_location")
    refuse(source_location != case["location"], "unrelated_evidence",
           f"{where}.source_location: does not match ground truth")
    line_number = int(source_location.rsplit(":", 1)[1])
    source_excerpt = text(evidence["source_excerpt"], where + ".source_excerpt", allow_tab=True)
    refuse(source_excerpt != artifact_lines[line_number - 1], "unrelated_evidence",
           f"{where}.source_excerpt: does not match verified source bytes")
    if finding_text_value is not None:
        finding_excerpt = text(evidence["finding_excerpt"], where + ".finding_excerpt")
        refuse(finding_excerpt not in finding_text_value, "unrelated_evidence",
               f"{where}.finding_excerpt: is not quoted from the matched finding")
        return finding_excerpt, source_excerpt
    return None, source_excerpt


def expected_gates(case, finding_excerpt, source_excerpt):
    observed = {}
    for gate in GATES:
        expectation = case["gate_expectations"][gate]
        finding_lower = finding_excerpt.casefold()
        source_lower = source_excerpt.casefold()
        observed[gate] = (
            all(term.casefold() in finding_lower for term in expectation["finding_terms"])
            and all(term.casefold() in source_lower for term in expectation["source_terms"])
        )
    return observed


def validate_adjudications(adjudications, cases, valid_findings, artifact_lines):
    refuse(not isinstance(adjudications, list), "invalid_schema", "run.adjudications: must be a list")
    seen_cases = set()
    matched_findings = set()
    accepted = []
    for index, record in enumerate(adjudications):
        where = f"run.adjudications[{index}]"
        exact_keys(record, {"ground_truth_id", "detected", "matched_finding_id", "gates", "evidence", "reason"},
                   set(), where)
        case_id = text(record["ground_truth_id"], where + ".ground_truth_id", identifier=True)
        refuse(case_id not in cases, "unknown_case", f"{where}.ground_truth_id: {case_id} is not in ground truth")
        refuse(cases[case_id]["disposition"] != "vulnerable", "invalid_adjudication",
               f"{where}.ground_truth_id: {case_id} is a benign case")
        refuse(case_id in seen_cases, "duplicate_adjudication", f"{where}.ground_truth_id: duplicate {case_id}")
        seen_cases.add(case_id)
        refuse(type(record["detected"]) is not bool, "invalid_schema", f"{where}.detected: boolean required")
        exact_keys(record["gates"], set(GATES), set(), where + ".gates")
        refuse(any(type(record["gates"][gate]) is not bool for gate in GATES), "invalid_schema",
               f"{where}.gates: every gate must be boolean")
        text(record["reason"], where + ".reason")
        matched = record["matched_finding_id"]
        if record["detected"]:
            text(matched, where + ".matched_finding_id", identifier=True)
            refuse(matched not in valid_findings, "invalid_match",
                   f"{where}.matched_finding_id: {matched!r} is missing or invalid")
            refuse(matched in matched_findings, "reused_finding",
                   f"{where}.matched_finding_id: {matched!r} already supports another detection")
            finding_excerpt, source_excerpt = validate_source_evidence(
                record["evidence"], cases[case_id], artifact_lines, where + ".evidence",
                finding_text_value=valid_findings[matched]["evidence"])
            refuse(record["gates"] != expected_gates(cases[case_id], finding_excerpt, source_excerpt),
                   "unsupported_detection", f"{where}.gates: do not follow the verified evidence and expectations")
            refuse(not record["gates"]["component"] or not record["gates"]["class"], "unsupported_detection",
                   f"{where}: detected requires component and class gates")
            matched_findings.add(matched)
        else:
            refuse(matched is not None, "invalid_adjudication", f"{where}: an undetected case cannot name a finding")
            refuse(any(record["gates"].values()), "invalid_adjudication", f"{where}: an undetected case cannot pass gates")
            refuse(record["evidence"] is not None, "invalid_adjudication",
                   f"{where}: an undetected case cannot carry matched evidence")
        accepted.append(record)
    missing = {identifier for identifier, case in cases.items() if case["disposition"] == "vulnerable"} - seen_cases
    refuse(bool(missing), "missing_adjudication", f"run.adjudications: missing ground-truth IDs {sorted(missing)}")
    return accepted, matched_findings


def validate_benign_adjudications(adjudications, cases, valid_findings, already_matched, artifact_lines):
    refuse(not isinstance(adjudications, list), "invalid_schema", "run.benign_adjudications: must be a list")
    seen_cases = set()
    matched_findings = set()
    accepted = []
    for index, record in enumerate(adjudications):
        where = f"run.benign_adjudications[{index}]"
        exact_keys(record, {"ground_truth_id", "outcome", "matched_finding_ids", "evidence", "reason"}, set(), where)
        case_id = text(record["ground_truth_id"], where + ".ground_truth_id", identifier=True)
        refuse(case_id not in cases, "unknown_case", f"{where}.ground_truth_id: {case_id} is not in ground truth")
        refuse(cases[case_id]["disposition"] != "benign", "invalid_adjudication",
               f"{where}.ground_truth_id: {case_id} is a vulnerable case")
        refuse(case_id in seen_cases, "duplicate_adjudication", f"{where}.ground_truth_id: duplicate {case_id}")
        seen_cases.add(case_id)
        refuse(record["outcome"] not in ("false_positive", "true_negative"), "invalid_adjudication",
               f"{where}.outcome: must be false_positive or true_negative")
        validate_source_evidence(record["evidence"], cases[case_id], artifact_lines, where + ".evidence")
        text(record["reason"], where + ".reason")
        matched = record["matched_finding_ids"]
        refuse(not isinstance(matched, list), "invalid_schema", f"{where}.matched_finding_ids: list required")
        refuse(len(matched) != len(set(matched)), "reused_finding",
               f"{where}.matched_finding_ids: duplicate finding")
        if record["outcome"] == "false_positive":
            refuse(not matched, "invalid_adjudication",
                   f"{where}: a false-positive case requires at least one matched finding")
            for matched_id in matched:
                text(matched_id, where + ".matched_finding_ids[]", identifier=True)
                refuse(matched_id not in valid_findings, "invalid_match",
                       f"{where}.matched_finding_ids: {matched_id!r} is missing or invalid")
                refuse(matched_id in already_matched or matched_id in matched_findings, "reused_finding",
                       f"{where}.matched_finding_ids: {matched_id!r} already supports another outcome")
                matched_findings.add(matched_id)
        else:
            refuse(bool(matched), "invalid_adjudication",
                   f"{where}: a true-negative case cannot name findings")
        accepted.append(record)
    missing = {identifier for identifier, case in cases.items() if case["disposition"] == "benign"} - seen_cases
    refuse(bool(missing), "missing_adjudication",
           f"run.benign_adjudications: missing ground-truth IDs {sorted(missing)}")
    return accepted, matched_findings


def wilson(successes, total, z=1.96):
    if total == 0:
        return [0.0, 0.0]
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    half = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def confusion_metrics(tp, fp, fn, tn):
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    false_positive_rate = ratio(fp, fp + tn)
    f1 = round(2 * tp / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else None
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
    }


def result_observation_fingerprint(adjudications, score):
    vulnerable = [{
        "ground_truth_id": record["ground_truth_id"],
        "detected": record["detected"],
        "gates": record["gates"],
        "evidence": record["evidence"],
    } for record in adjudications["vulnerable"]]
    benign = [{
        "ground_truth_id": record["ground_truth_id"],
        "outcome": record["outcome"],
        "matched_finding_count": len(record["matched_finding_ids"]),
        "evidence": record["evidence"],
    } for record in adjudications["benign"]]
    partition_fields = {
        "true_positive_findings": ("ground_truth_id", "title"),
        "false_positive_findings": ("ground_truth_id", "title", "evidence"),
        "false_negative_cases": ("location",),
        "true_negative_cases": ("location", "evidence"),
        "discovery_candidates": ("title",),
        "invalid_findings_excluded": ("reason",),
    }
    partitions = {
        name: sorted(
            ({key: item[key] for key in keys} for item in score[name]),
            key=lambda item: canonical(item),
        )
        for name, keys in partition_fields.items()
    }
    return digest(canonical({
        "vulnerable": sorted(vulnerable, key=lambda item: item["ground_truth_id"]),
        "benign": sorted(benign, key=lambda item: item["ground_truth_id"]),
        "partitions": partitions,
    }))


def measurement(ground_truth, gt_sha, run, run_sha, source_root):
    cases, artifact_lines = validate_ground_truth(ground_truth, source_root)
    exact_keys(run, {"manifest", "findings", "adjudications", "benign_adjudications"}, set(), "run")
    configuration_sha, input_set_sha, execution_sha = validate_manifest(run["manifest"], ground_truth, gt_sha)
    valid, invalid = validate_findings(run["findings"])
    adjudications, matched = validate_adjudications(run["adjudications"], cases, valid, artifact_lines)
    benign_adjudications, false_positive_ids = validate_benign_adjudications(
        run["benign_adjudications"], cases, valid, matched, artifact_lines)
    all_scored = matched | false_positive_ids
    candidates = [
        {"id": identifier, "title": valid[identifier]["title"]}
        for identifier in sorted(set(valid) - all_scored)
    ]
    vulnerable = {identifier for identifier, case in cases.items() if case["disposition"] == "vulnerable"}
    tp = sum(1 for record in adjudications if record["detected"])
    fn = len(vulnerable) - tp
    fp = len(false_positive_ids)
    tn = sum(1 for record in benign_adjudications if record["outcome"] == "true_negative")
    metrics = confusion_metrics(tp, fp, fn, tn)
    gate_scores = {}
    for gate in GATES:
        passed = sum(1 for record in adjudications if record["detected"] and record["gates"][gate])
        gate_scores[gate] = {
            "passed": passed,
            "denominator": tp,
            "rate_over_detected": round(passed / tp, 4) if tp else None,
            "weight": GATE_WEIGHTS[gate],
        }
    weighted = sum(item["passed"] * item["weight"] for item in gate_scores.values())
    weighted_max = tp * sum(GATE_WEIGHTS.values())
    precision_lower = ratio(tp, tp + fp + len(candidates) + len(invalid))
    precision_upper = metrics["precision"]
    manifest = run["manifest"]
    document = {
        "schema_version": SCHEMA_VERSION,
        "method_version": METHOD_VERSION,
        "status": "measured",
        "run_id": manifest["run_id"],
        "input_identity": {
            "ground_truth_sha256": gt_sha,
            "run_envelope_sha256": run_sha,
            "benchmark_id": manifest["benchmark_id"],
            "benchmark_version": manifest["benchmark_version"],
            "source_revision": manifest["source_revision"],
            "source_artifact_sha256": ground_truth["source"]["artifact_sha256"],
            "scanner_configuration_sha256": configuration_sha,
            "input_set_sha256": input_set_sha,
            "execution_input_sha256": execution_sha,
            "observation_sha256": None,
        },
        "target": {
            "benchmark_id": manifest["benchmark_id"],
            "benchmark_version": manifest["benchmark_version"],
            "source_kind": ground_truth["source"]["kind"],
            "source_uri": ground_truth["source"]["uri"],
            "source_artifact_path": ground_truth["source"]["artifact_path"],
            "source_revision": manifest["source_revision"],
            "source_artifact_sha256": ground_truth["source"]["artifact_sha256"],
            "source_license": ground_truth["source"]["license"],
        },
        "scanner": manifest["scanner"],
        "bound_inputs": {
            "scanner_configuration": manifest["scanner_configuration"],
            "input_set": manifest["input_set"],
        },
        "condition": manifest["condition"],
        "resources": manifest["resources"],
        "adjudicator": manifest["adjudicator"],
        "adjudications": {
            "vulnerable": adjudications,
            "benign": benign_adjudications,
        },
        "comparability": {
            "measured_modality": MODALITY,
            "artex_reference_modality": ARTEX_MODALITY,
            "artex_outcome_comparable": False,
            "scope": "security-scan-only",
            "reason": "Static source review has no target execution or flag-capture oracle; no paired ARTEX run was performed.",
        },
        "score": {
            "confusion_matrix": {"true_positive": tp, "false_positive": fp,
                                 "false_negative": fn, "true_negative": tn},
            "metrics": metrics,
            "detected": tp,
            "total": len(vulnerable),
            "denominator": len(vulnerable),
            "detection_rate": metrics["recall"],
            "detection_rate_wilson95": wilson(tp, len(vulnerable)),
            "gate_scores_over_detected": gate_scores,
            "weighted_gate_points": weighted,
            "weighted_gate_points_available": weighted_max,
            "precision_bounds_until_candidates_verified": [precision_lower, precision_upper],
            "true_positive_findings": [
                {"id": record["matched_finding_id"], "ground_truth_id": record["ground_truth_id"],
                 "title": valid[record["matched_finding_id"]]["title"]}
                for record in adjudications if record["detected"]
            ],
            "false_positive_findings": [
                {"id": identifier, "ground_truth_id": record["ground_truth_id"],
                 "title": valid[identifier]["title"], "evidence": record["evidence"]["source_excerpt"]}
                for record in benign_adjudications if record["outcome"] == "false_positive"
                for identifier in record["matched_finding_ids"]
            ],
            "false_negative_cases": [
                {"id": record["ground_truth_id"], "location": cases[record["ground_truth_id"]]["location"]}
                for record in adjudications if not record["detected"]
            ],
            "true_negative_cases": [
                {"id": record["ground_truth_id"], "location": cases[record["ground_truth_id"]]["location"],
                 "evidence": record["evidence"]["source_excerpt"]}
                for record in benign_adjudications if record["outcome"] == "true_negative"
            ],
            "invalid_findings_excluded": invalid,
            "discovery_candidates": candidates,
            "scanner_findings_total": len(run["findings"]),
        },
    }
    document["input_identity"]["observation_sha256"] = result_observation_fingerprint(
        document["adjudications"], document["score"])
    return sealed(document)


def spread(values):
    return {
        "mean": round(statistics.fmean(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "sample_stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
    }


def defined_spread(values):
    # Precision is undefined for a run with no TP and no FP (or no findings at
    # all for its lower bound). Such a run stays in the pooled totals; its
    # per-run value is counted as undefined rather than blocking aggregation.
    defined = [value for value in values if value is not None]
    result = spread(defined) if defined else {"mean": None, "min": None, "max": None, "sample_stdev": None}
    result["undefined_runs"] = len(values) - len(defined)
    return result


def validate_result(result, where):
    required = {
        "schema_version", "method_version", "status", "run_id", "input_identity", "target", "scanner",
        "bound_inputs", "condition", "resources", "adjudicator", "adjudications", "comparability", "score", "seal",
    }
    exact_keys(result, required, set(), where)
    verify_seal(result, where)
    refuse(result["schema_version"] != SCHEMA_VERSION or result["method_version"] != METHOD_VERSION,
           "incompatible_run", f"{where}: incompatible schema or method")
    refuse(result["status"] != "measured", "incompatible_run", f"{where}: status is not measured")
    text(result["run_id"], where + ".run_id", identifier=True)
    identity = result["input_identity"]
    exact_keys(identity, {"ground_truth_sha256", "run_envelope_sha256", "benchmark_id",
                          "benchmark_version", "source_revision", "source_artifact_sha256",
                          "scanner_configuration_sha256", "input_set_sha256", "execution_input_sha256",
                          "observation_sha256"},
               set(), where + ".input_identity")
    for key in ("ground_truth_sha256", "run_envelope_sha256", "source_artifact_sha256",
                "scanner_configuration_sha256", "input_set_sha256", "execution_input_sha256",
                "observation_sha256"):
        refuse(not isinstance(identity[key], str) or not SHA256.fullmatch(identity[key]), "invalid_result",
               f"{where}.input_identity.{key}: invalid SHA-256")
    text(identity["benchmark_id"], where + ".input_identity.benchmark_id", identifier=True)
    text(identity["benchmark_version"], where + ".input_identity.benchmark_version")
    refuse(not isinstance(identity["source_revision"], str) or not PIN.fullmatch(identity["source_revision"]),
           "invalid_result", f"{where}.input_identity.source_revision: invalid pin")
    target = result["target"]
    exact_keys(target, {"benchmark_id", "benchmark_version", "source_kind", "source_uri", "source_artifact_path",
                        "source_revision", "source_artifact_sha256", "source_license"}, set(), where + ".target")
    refuse(target["benchmark_id"] != identity["benchmark_id"] or
           target["benchmark_version"] != identity["benchmark_version"] or
           target["source_revision"] != identity["source_revision"] or
           target["source_artifact_sha256"] != identity["source_artifact_sha256"],
           "invalid_result", f"{where}.target: does not match input identity")
    refuse(target["source_kind"] not in ("public", "synthetic"), "invalid_result",
           f"{where}.target.source_kind: unsupported")
    refuse(target["source_kind"] == "synthetic" and
           target["source_revision"] != target["source_artifact_sha256"], "invalid_result",
           f"{where}.target: synthetic revision must equal verified artifact digest")
    for key in ("source_uri", "source_artifact_path", "source_license"):
        text(target[key], f"{where}.target.{key}")
    exact_keys(result["scanner"], {"name", "version", "configuration", "subject_model", "subject_role"},
               set(), where + ".scanner")
    for key in result["scanner"]:
        text(result["scanner"][key], f"{where}.scanner.{key}")
    bound_inputs = result["bound_inputs"]
    exact_keys(bound_inputs, {"scanner_configuration", "input_set"}, set(), where + ".bound_inputs")
    configuration_sha = validate_byte_record(bound_inputs["scanner_configuration"],
                                             where + ".bound_inputs.scanner_configuration")
    input_set_sha = validate_byte_record(bound_inputs["input_set"], where + ".bound_inputs.input_set")
    refuse(configuration_sha != identity["scanner_configuration_sha256"] or
           input_set_sha != identity["input_set_sha256"], "invalid_result",
           f"{where}.bound_inputs: digests do not match input identity")
    exact_keys(result["condition"], {"id", "source_access"}, set(), where + ".condition")
    text(result["condition"]["id"], where + ".condition.id", identifier=True)
    refuse(result["condition"]["source_access"] != "full-source", "non_comparable_modality",
           f"{where}.condition.source_access: must be full-source")
    exact_keys(result["resources"],
               {"wall_seconds", "worker_count", "model_calls", "input_tokens", "output_tokens",
                "estimated_cost_usd"},
               set(), where + ".resources")
    for key in ("wall_seconds", "worker_count", "model_calls", "input_tokens", "output_tokens"):
        integer(result["resources"][key], f"{where}.resources.{key}")
    number(result["resources"]["estimated_cost_usd"], f"{where}.resources.estimated_cost_usd")
    refuse(result["resources"]["wall_seconds"] == 0 or result["resources"]["worker_count"] == 0,
           "invalid_result", f"{where}.resources: completed runs require duration and workers")
    exact_keys(result["adjudicator"], {"kind", "identity"}, set(), where + ".adjudicator")
    refuse(result["adjudicator"]["kind"] not in ("independent-human", "fixture-oracle"), "invalid_result",
           f"{where}.adjudicator.kind: unsupported")
    text(result["adjudicator"]["identity"], where + ".adjudicator.identity")
    retained = result["adjudications"]
    exact_keys(retained, {"vulnerable", "benign"}, set(), where + ".adjudications")
    refuse(not isinstance(retained["vulnerable"], list) or not isinstance(retained["benign"], list),
           "invalid_result", f"{where}.adjudications: lists required")
    for index, record in enumerate(retained["vulnerable"]):
        record_where = f"{where}.adjudications.vulnerable[{index}]"
        exact_keys(record, {"ground_truth_id", "detected", "matched_finding_id", "gates", "evidence", "reason"},
                   set(), record_where)
        text(record["ground_truth_id"], record_where + ".ground_truth_id", identifier=True)
        refuse(type(record["detected"]) is not bool, "invalid_result", record_where + ".detected: boolean required")
        exact_keys(record["gates"], set(GATES), set(), record_where + ".gates")
        refuse(any(type(value) is not bool for value in record["gates"].values()), "invalid_result",
               record_where + ".gates: booleans required")
        text(record["reason"], record_where + ".reason")
        if record["detected"]:
            text(record["matched_finding_id"], record_where + ".matched_finding_id", identifier=True)
            exact_keys(record["evidence"], {"finding_excerpt", "source_location", "source_excerpt"}, set(),
                       record_where + ".evidence")
            for key in record["evidence"]:
                text(record["evidence"][key], f"{record_where}.evidence.{key}", allow_tab=key == "source_excerpt")
        else:
            refuse(record["matched_finding_id"] is not None or record["evidence"] is not None or
                   any(record["gates"].values()), "invalid_result",
                   record_where + ": missed cases cannot carry matched evidence or passed gates")
    for index, record in enumerate(retained["benign"]):
        record_where = f"{where}.adjudications.benign[{index}]"
        exact_keys(record, {"ground_truth_id", "outcome", "matched_finding_ids", "evidence", "reason"},
                   set(), record_where)
        text(record["ground_truth_id"], record_where + ".ground_truth_id", identifier=True)
        refuse(record["outcome"] not in ("false_positive", "true_negative") or
               not isinstance(record["matched_finding_ids"], list), "invalid_result",
               record_where + ": invalid outcome or matched findings")
        refuse(len(record["matched_finding_ids"]) != len(set(record["matched_finding_ids"])), "invalid_result",
               record_where + ".matched_finding_ids: duplicates")
        for matched_id in record["matched_finding_ids"]:
            text(matched_id, record_where + ".matched_finding_ids[]", identifier=True)
        refuse((record["outcome"] == "false_positive") != bool(record["matched_finding_ids"]),
               "invalid_result", record_where + ": outcome and matched findings disagree")
        exact_keys(record["evidence"], {"source_location", "source_excerpt"}, set(), record_where + ".evidence")
        for key in record["evidence"]:
            text(record["evidence"][key], f"{record_where}.evidence.{key}", allow_tab=key == "source_excerpt")
        text(record["reason"], record_where + ".reason")
    comparable = result["comparability"]
    exact_keys(comparable, {"measured_modality", "artex_reference_modality", "artex_outcome_comparable",
                            "scope", "reason"}, set(), where + ".comparability")
    refuse(comparable["measured_modality"] != MODALITY or
           comparable["artex_reference_modality"] != ARTEX_MODALITY or
           comparable["artex_outcome_comparable"] is not False or
           comparable["scope"] != "security-scan-only", "non_comparable_modality",
           f"{where}: invalid comparability label")
    text(comparable["reason"], where + ".comparability.reason")
    expected_execution = digest(canonical({
        "method_version": result["method_version"],
        "ground_truth_sha256": identity["ground_truth_sha256"],
        "source_artifact_sha256": identity["source_artifact_sha256"],
        "scanner": result["scanner"],
        "scanner_configuration_sha256": configuration_sha,
        "input_set_sha256": input_set_sha,
        "condition": result["condition"],
    }))
    refuse(identity["execution_input_sha256"] != expected_execution, "invalid_result",
           f"{where}.input_identity.execution_input_sha256: inconsistent fingerprint")
    score = result["score"]
    exact_keys(score, {"confusion_matrix", "metrics", "detected", "total", "denominator",
                       "detection_rate", "detection_rate_wilson95",
                       "gate_scores_over_detected", "weighted_gate_points", "weighted_gate_points_available",
                       "precision_bounds_until_candidates_verified", "invalid_findings_excluded",
                       "true_positive_findings", "false_positive_findings", "false_negative_cases",
                       "true_negative_cases", "discovery_candidates", "scanner_findings_total"},
               set(), where + ".score")
    confusion = score["confusion_matrix"]
    exact_keys(confusion, {"true_positive", "false_positive", "false_negative", "true_negative"},
               set(), where + ".score.confusion_matrix")
    for key, value in confusion.items():
        integer(value, f"{where}.score.confusion_matrix.{key}")
    tp, fp = confusion["true_positive"], confusion["false_positive"]
    fn, tn = confusion["false_negative"], confusion["true_negative"]
    metrics = score["metrics"]
    exact_keys(metrics, {"precision", "recall", "f1", "false_positive_rate"}, set(), where + ".score.metrics")
    for key, value in metrics.items():
        refuse(value is not None and type(value) not in (int, float), "invalid_result",
               f"{where}.score.metrics.{key}: number or null required")
    refuse(metrics != confusion_metrics(tp, fp, fn, tn), "invalid_result",
           f"{where}.score.metrics: inconsistent with confusion matrix")
    detected = integer(score["detected"], where + ".score.detected")
    total = integer(score["total"], where + ".score.total")
    denominator = integer(score["denominator"], where + ".score.denominator")
    refuse(total == 0 or denominator != total or detected != tp or total != tp + fn, "invalid_result",
           f"{where}.score: inconsistent detection denominator")
    expected_rate = metrics["recall"]
    refuse(type(score["detection_rate"]) not in (int, float), "invalid_result",
           f"{where}.score.detection_rate: number required")
    refuse(score["detection_rate"] != expected_rate or score["detection_rate_wilson95"] != wilson(detected, total),
           "invalid_result", f"{where}.score: detection rate or interval is inconsistent")
    gates = score["gate_scores_over_detected"]
    exact_keys(gates, set(GATES), set(), where + ".score.gate_scores_over_detected")
    weighted = 0
    for gate in GATES:
        item = gates[gate]
        exact_keys(item, {"passed", "denominator", "rate_over_detected", "weight"}, set(), f"{where}.score.gates.{gate}")
        passed = integer(item["passed"], f"{where}.score.gates.{gate}.passed")
        gate_denominator = integer(item["denominator"], f"{where}.score.gates.{gate}.denominator")
        weight = integer(item["weight"], f"{where}.score.gates.{gate}.weight")
        refuse(item["rate_over_detected"] is not None and type(item["rate_over_detected"]) not in (int, float),
               "invalid_result", f"{where}.score.gates.{gate}.rate_over_detected: number or null required")
        expected_gate_rate = round(passed / detected, 4) if detected else None
        refuse(passed > detected or gate_denominator != detected or
               item["rate_over_detected"] != expected_gate_rate or weight != GATE_WEIGHTS[gate],
               "invalid_result", f"{where}.score.gates.{gate}: inconsistent gate score")
        weighted += passed * GATE_WEIGHTS[gate]
    weighted_points = integer(score["weighted_gate_points"], where + ".score.weighted_gate_points")
    weighted_available = integer(score["weighted_gate_points_available"],
                                 where + ".score.weighted_gate_points_available")
    refuse(weighted_points != weighted or weighted_available != detected * sum(GATE_WEIGHTS.values()),
           "invalid_result", f"{where}.score: inconsistent weighted gate score")
    partitions = (
        ("true_positive_findings", score["true_positive_findings"], {"id", "ground_truth_id", "title"}),
        ("false_positive_findings", score["false_positive_findings"],
         {"id", "ground_truth_id", "title", "evidence"}),
        ("false_negative_cases", score["false_negative_cases"], {"id", "location"}),
        ("true_negative_cases", score["true_negative_cases"], {"id", "location", "evidence"}),
        ("discovery_candidates", score["discovery_candidates"], {"id", "title"}),
        ("invalid_findings_excluded", score["invalid_findings_excluded"], {"id", "reason"}),
    )
    partition_ids = {}
    for name, values, keys in partitions:
        refuse(not isinstance(values, list), "invalid_result", f"{where}.score.{name}: list required")
        ids = []
        for index, item in enumerate(values):
            exact_keys(item, keys, set(), f"{where}.score.{name}[{index}]")
            ids.append(text(item["id"], f"{where}.score.{name}[{index}].id", identifier=True))
            for key in keys - {"id"}:
                text(item[key], f"{where}.score.{name}[{index}].{key}", identifier=key == "ground_truth_id",
                     allow_tab=key == "evidence")
        refuse(len(ids) != len(set(ids)), "invalid_result", f"{where}.score.{name}: duplicate IDs")
        partition_ids[name] = set(ids)
    refuse(len(score["true_positive_findings"]) != tp or len(score["false_positive_findings"]) != fp or
           len(score["false_negative_cases"]) != fn or len(score["true_negative_cases"]) != tn,
           "invalid_result", f"{where}.score: partition counts do not match confusion matrix")
    finding_groups = ("true_positive_findings", "false_positive_findings", "discovery_candidates",
                      "invalid_findings_excluded")
    finding_ids = set()
    for name in finding_groups:
        refuse(bool(finding_ids & partition_ids[name]), "invalid_result",
               f"{where}.score: finding partitions overlap")
        finding_ids |= partition_ids[name]
    candidates = score["discovery_candidates"]
    invalid = score["invalid_findings_excluded"]
    scanner_total = integer(score["scanner_findings_total"], where + ".score.scanner_findings_total")
    refuse(scanner_total != tp + fp + len(candidates) + len(invalid), "invalid_result",
           f"{where}.score.scanner_findings_total: inconsistent finding count")
    lower = ratio(tp, tp + fp + len(candidates) + len(invalid))
    upper = metrics["precision"]
    refuse(score["precision_bounds_until_candidates_verified"] != [lower, upper],
           "invalid_result", f"{where}.score: inconsistent precision bounds")
    retained_tp = sum(1 for record in retained["vulnerable"] if record["detected"])
    retained_fp = sum(len(record["matched_finding_ids"]) for record in retained["benign"])
    retained_tn = sum(1 for record in retained["benign"] if record["outcome"] == "true_negative")
    refuse((retained_tp, retained_fp, len(retained["vulnerable"]) - retained_tp, retained_tn) !=
           (tp, fp, fn, tn), "invalid_result", f"{where}.adjudications: counts do not match score")
    refuse(identity["observation_sha256"] != result_observation_fingerprint(retained, score),
           "invalid_result", f"{where}.input_identity.observation_sha256: inconsistent fingerprint")


def summary(results, min_runs):
    refuse(type(min_runs) is not int or min_runs < 3, "insufficient_replication", "--min-runs must be at least 3")
    refuse(len(results) < min_runs, "insufficient_replication",
           f"need at least {min_runs} runs; received {len(results)}")
    for index, result in enumerate(results):
        validate_result(result, f"runs[{index}]")
    run_ids = [result.get("run_id") for result in results]
    envelope_ids = [result.get("input_identity", {}).get("run_envelope_sha256") for result in results]
    observation_ids = [result.get("input_identity", {}).get("observation_sha256") for result in results]
    refuse(len(set(run_ids)) != len(run_ids), "duplicate_run", "run IDs must be unique")
    refuse(len(set(envelope_ids)) != len(envelope_ids), "duplicate_run", "run envelope identities must be unique")
    refuse(len(set(observation_ids)) != len(observation_ids), "duplicate_observation",
           "substantively duplicate observations cannot be aggregated")
    first = results[0]
    identity_keys = ("ground_truth_sha256", "benchmark_id", "benchmark_version", "source_revision",
                     "source_artifact_sha256", "scanner_configuration_sha256", "input_set_sha256",
                     "execution_input_sha256")
    for index, result in enumerate(results[1:], 1):
        refuse(any(result["input_identity"].get(key) != first["input_identity"].get(key) for key in identity_keys),
               "incomparable_inputs", f"runs[{index}]: ground-truth identity differs")
        refuse(result.get("scanner") != first.get("scanner"), "incomparable_inputs",
               f"runs[{index}]: scanner identity or configuration differs")
        refuse(result.get("target") != first.get("target"), "incomparable_inputs",
               f"runs[{index}]: target provenance differs")
        refuse(result.get("condition") != first.get("condition"), "incomparable_inputs",
               f"runs[{index}]: source-review condition differs")
    metric_values = {
        key: [result["score"]["metrics"][key] for result in results]
        for key in ("precision", "recall", "f1", "false_positive_rate")
    }
    precision_low = [result["score"]["precision_bounds_until_candidates_verified"][0] for result in results]
    precision_high = [result["score"]["precision_bounds_until_candidates_verified"][1] for result in results]
    totals = {
        key: sum(result["score"]["confusion_matrix"][key] for result in results)
        for key in ("true_positive", "false_positive", "false_negative", "true_negative")
    }
    micro = confusion_metrics(totals["true_positive"], totals["false_positive"],
                              totals["false_negative"], totals["true_negative"])
    gate_observations = {}
    for gate in GATES:
        values = [result["score"]["gate_scores_over_detected"][gate]["rate_over_detected"] for result in results]
        measured = [value for value in values if value is not None]
        gate_observations[gate] = spread(measured) if measured else None
    document = {
        "schema_version": SCHEMA_VERSION,
        "method_version": METHOD_VERSION,
        "status": "summarized",
        "run_count": len(results),
        "run_ids": run_ids,
        "observation_sha256s": observation_ids,
        "input_identity": {key: first["input_identity"][key] for key in identity_keys},
        "target": first["target"],
        "scanner": first["scanner"],
        "condition": first["condition"],
        "comparability": first["comparability"],
        "aggregate": {
            "confusion_matrix_totals": totals,
            "micro_metrics": micro,
            "per_run_metrics": {key: defined_spread(values) for key, values in metric_values.items()},
            "detection_rate": spread(metric_values["recall"]),
            "precision_lower_bound": defined_spread(precision_low),
            "precision_upper_bound": defined_spread(precision_high),
            "discovery_candidate_count": spread([
                len(result["score"]["discovery_candidates"]) for result in results]),
            "invalid_finding_count": spread([
                len(result["score"]["invalid_findings_excluded"]) for result in results]),
            "gate_rate_observations_over_detected": gate_observations,
            "gate_note": "Gate observations describe recorded evidence quality; confusion-derived recall is separate.",
        },
        "resources": {
            "wall_seconds_total": sum(result["resources"]["wall_seconds"] for result in results),
            "model_calls_total": sum(result["resources"]["model_calls"] for result in results),
            "input_tokens_total": sum(result["resources"]["input_tokens"] for result in results),
            "output_tokens_total": sum(result["resources"]["output_tokens"] for result in results),
            "estimated_cost_usd_total": round(sum(
                result["resources"]["estimated_cost_usd"] for result in results), 6),
            "per_run": [{"run_id": result["run_id"], **result["resources"]} for result in results],
        },
    }
    return sealed(document)


def human_summary(value):
    def render_metrics(metrics):
        return ", ".join(
            f"{name}={'undefined' if metrics[name] is None else format(metrics[name], '.4f')}"
            for name in ("precision", "recall", "f1", "false_positive_rate"))

    if value["status"] == "measured":
        confusion = value["score"]["confusion_matrix"]
        metrics = value["score"]["metrics"]
        fields = render_metrics(metrics)
        context = (f"target={value['target']['benchmark_id']}@{value['target']['benchmark_version']} "
                   f"source={value['target']['source_revision']} subject={value['scanner']['subject_model']} "
                   f"role={value['scanner']['subject_role']} condition={value['condition']['id']} "
                   f"cost_usd={value['resources']['estimated_cost_usd']:.6f}")
        return (f"run {value['run_id']}: TP={confusion['true_positive']} FP={confusion['false_positive']} "
                f"FN={confusion['false_negative']} TN={confusion['true_negative']}; {fields}; "
                f"candidates={len(value['score']['discovery_candidates'])} "
                f"invalid={len(value['score']['invalid_findings_excluded'])}; {context}; "
                "modality=static-source-review ARTEX-comparable=no")
    totals = value["aggregate"]["confusion_matrix_totals"]
    metrics = value["aggregate"]["micro_metrics"]
    fields = render_metrics(metrics)
    context = (f"target={value['target']['benchmark_id']}@{value['target']['benchmark_version']} "
               f"source={value['target']['source_revision']} subject={value['scanner']['subject_model']} "
               f"role={value['scanner']['subject_role']} condition={value['condition']['id']} "
               f"cost_usd={value['resources']['estimated_cost_usd_total']:.6f}")
    return (f"summary {value['run_count']} runs: pooled TP={totals['true_positive']} "
            f"FP={totals['false_positive']} FN={totals['false_negative']} TN={totals['true_negative']}; "
            f"{fields}; {context}; modality=static-source-review ARTEX-comparable=no")


def write_result(value, output):
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output is None or str(output) == "-":
        sys.stdout.write(rendered)
        return
    target = Path(output)
    refuse(target.exists(), "output_exists", f"{target}: refusing to replace sealed evidence")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + target.name + ".", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
    except FileExistsError:
        raise Refusal("output_exists", f"{target}: refusing to replace sealed evidence") from None
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print(human_summary(value))


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate one run and emit sealed measurement JSON")
    validate.add_argument("--ground-truth", required=True)
    validate.add_argument("--findings", required=True, help="run manifest containing findings and adjudications")
    validate.add_argument("--out", help="new output path; existing files are never replaced (default: stdout)")
    summarize = commands.add_parser("summarize", help="aggregate comparable sealed run results")
    summarize.add_argument("--runs", nargs="+", required=True)
    summarize.add_argument("--min-runs", type=int, default=3)
    summarize.add_argument("--out", help="new output path; existing files are never replaced (default: stdout)")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            ground_truth, gt_raw = read_json(args.ground_truth)
            run, run_raw = read_json(args.findings)
            result = measurement(ground_truth, digest(gt_raw), run, digest(run_raw),
                                 Path(args.ground_truth).resolve().parent)
        else:
            result = summary([read_json(path)[0] for path in args.runs], args.min_runs)
        write_result(result, args.out)
        return 0
    except Refusal as error:
        print(json.dumps({"status": "refused", "code": error.code, "message": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
