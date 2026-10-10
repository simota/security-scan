#!/usr/bin/env python3
"""Generate and replay bounded, synthetic reproduction bundles; never run target code."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

# Sibling modules must import under python3 -I / PYTHONSAFEPATH as well.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import reproduction_runtime as runtime
from verification_workflow import _finding, _validate_base, input_digest

BundleError = runtime.BundleError
ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
COMMIT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
LIMITATION = "Synthetic model only; no target application code, real boundary, credentials or network is executed."


def safe_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise BundleError("IDs must be bounded alphanumeric identifiers with - or _")
    from render import redact
    if redact(value) != value or re.match(r"(?i)(?:gh[opusr]_|github_pat_|sk-|xox[baprs]-|AKIA[A-Z0-9]{16})", value):
        raise BundleError("Secret-bearing identifier refused")
    return value


def validate_plan(plan):
    result = runtime.validate_plan(plan)
    safe_id(result["case_id"])
    for ref in result["evidence_ids"]:
        safe_id(ref)
    return result


def source_bytes(action):
    raw = runtime.read_bytes(Path(__file__).with_name("reproduction_runtime.py"))
    return raw + ('\n\nif __name__ == "__main__":\n    sys.exit(entry("%s"))\n' % action).encode("ascii")


def adapter_record(plan, finding_id):
    return {"adapter_contract_version": 1, "status": "requires_target_review", "finding_id": finding_id,
            "case_id": plan["case_id"], "source_evidence_ids": plan["evidence_ids"],
            "boundary": "mocked", "implemented_template": plan["template"],
            "target_binding": {"entrypoint": None, "framework": None, "seed_factory": None,
                               "cleanup_ownership": None, "isolated_environment": None,
                               "pinned_dependencies": None, "before_revision_checked": False,
                               "after_revision_checked": False, "real_boundary_exercised": False},
            "secure_expectation": "Actor B must not read Actor A's resource; legitimate owner access must still work.",
            "instructions": "Review source evidence and adapt to the owned project's test framework under explicit authorization. "
                            "This contract is not executed. Do not enter secrets or personal data. "
                            "Modified scripts cannot run through the trusted bundle runner. "
                            "Record real target evidence separately; a successful model is not target reproduction."}


def generated_files(plan, finding_id):
    files = {name: source_bytes(name[:-3]) for name in runtime.SCRIPTS}
    files["adapter.todo.json"] = runtime.canonical(adapter_record(plan, finding_id)) + b"\n"
    return files


def check_evidence(data, evidence_ids, evidence_root=None, evidence_repository=None):
    from evidence_integrity import verify_evidence
    from verification import integrity_state
    if evidence_repository and not evidence_root:
        raise BundleError("An explicit evidence root is required")
    checked = None
    if evidence_root is not None:
        checked = verify_evidence(data, evidence_root, repository=evidence_repository,
                                  evidence_ids=evidence_ids)
    state = integrity_state(data, evidence_ids, checked)
    required = data.get("evidence_integrity", {}).get("required", False)
    if state["status"] == "incomplete" or (required and state["status"] != "checked"):
        raise BundleError("Source evidence requires current byte and commit verification")
    return checked


def build_manifest(findings_path, finding_id, plan, evidence_root=None, evidence_repository=None):
    plan = validate_plan(plan)
    safe_id(finding_id)
    findings_path = runtime.safe_path(findings_path, False)
    raw = runtime.read_bytes(findings_path)
    data = runtime.parse_json(raw)
    _validate_base(data)
    finding = _finding(data, finding_id)
    if str(finding.get("category", "")).strip().casefold() == "secrets":
        raise BundleError("Secret findings require a manually reviewed, redacted test design")
    evidence = {item["id"]: item for item in data.get("evidence", [])}
    selected = []
    for ref in plan["evidence_ids"]:
        if ref not in evidence or evidence[ref]["kind"] != "source":
            raise BundleError("Each selected evidence ID must name source evidence")
        item = evidence[ref]
        if item["commit"].lower() != data["assessment"]["commit"].lower() or item.get("diff_sha256", "").lower() != data["assessment"].get("diff_sha256", "").lower():
            raise BundleError("Source evidence must match the assessment revision and worktree")
        selected.append({"id": ref, "sha256": item["sha256"].lower()})
    checked = check_evidence(data, plan["evidence_ids"], evidence_root, evidence_repository)
    pin = {key: data["assessment"][key] for key in ("commit", "diff_sha256", "worktree") if key in data["assessment"]}
    base = {"bundle_version": 1, "finding_id": finding_id, "findings_sha256": runtime.digest(raw),
            "finding_input_sha256": input_digest(data, finding), "assessment": pin,
            "source_evidence": selected, "plan": plan, "tools": runtime.tools_record(),
            "template_version": runtime.VERSION, "template_sha256": runtime.digest(source_bytes("run")),
            "status": "not_run", "boundary": "mocked", "limitation": LIMITATION,
            "expectations": {"before_security": "fail:assertion", "after_security": "pass",
                             "owner_positive_control": "pass", "missing_resource_negative_control": "pass"}}
    if checked is not None:
        # A checked bundle cannot be replayed later without the same fresh
        # checks. Only a digest is stored, never local roots or artifact content.
        base["evidence_receipt_sha256"] = runtime.digest(runtime.canonical(checked.receipt))
    identifier = runtime.digest(runtime.canonical(base))
    base.update(bundle_id=identifier, namespace="ss-" + identifier[:20])
    files = generated_files(plan, finding_id)
    base["files"] = {name: runtime.digest(raw) for name, raw in files.items()}
    base["fixture_sha256"] = runtime.digest(runtime.canonical(runtime.fixture_data(base)))
    base["configuration_sha256"] = runtime.digest(runtime.canonical(plan))
    return base, files


def new_directory(path):
    path = runtime.safe_path(path, True)
    # No implicit parent creation or replacement of an existing directory.
    runtime.safe_path(path.parent, True)
    if not path.parent.is_dir():
        raise BundleError("Output parent must already exist")
    path.mkdir(mode=0o700)
    return path


def write_raw_new(path, raw):
    path = runtime.safe_path(path, False)
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def generate(findings, finding_id, plan, out, evidence_root=None, evidence_repository=None):
    manifest, files = build_manifest(findings, finding_id, plan, evidence_root, evidence_repository)
    out = new_directory(out)
    for name, raw in files.items():
        write_raw_new(out / name, raw)
    runtime.write_new(out / "manifest.json", manifest)
    runtime.write_new(out / "manifest.sha256.json", {"sha256": runtime.digest(runtime.canonical(manifest))})
    return {"status": "not_run", "bundle_id": manifest["bundle_id"], "template": plan["template"], "limitation": LIMITATION}


def verify(bundle, findings, evidence_root=None, evidence_repository=None):
    bundle = runtime.safe_path(bundle, True)
    # This bypass is local to the trusted verifier: build_manifest below must
    # recompute the receipt from actual files before this function returns.
    manifest = runtime.manifest_at(bundle, findings, evidence_checked=True)
    # Rebuild from trusted generator + current inputs, not just self-reported hashes.
    expected, files = build_manifest(findings, manifest.get("finding_id"), manifest.get("plan"),
                                     evidence_root, evidence_repository)
    # Generation and replay Python/SQLite versions may differ; record both, don't
    # mislabel tool changes as a byte-for-byte environment reproduction.
    expected["tools"] = manifest.get("tools")
    # The bundle ID includes the generation tool versions. Recreate that ID.
    identity = {k: v for k, v in expected.items() if k not in ("bundle_id", "namespace", "files", "fixture_sha256", "configuration_sha256")}
    expected["bundle_id"] = runtime.digest(runtime.canonical(identity))
    expected["namespace"] = "ss-" + expected["bundle_id"][:20]
    expected["fixture_sha256"] = runtime.digest(runtime.canonical(runtime.fixture_data(expected)))
    if manifest != expected:
        raise BundleError("Manifest differs from trusted template or current findings")
    allowed = set(files) | {"manifest.json", "manifest.sha256.json", ".fixture", ".fixture.lock"}
    if set(p.name for p in bundle.iterdir()) - allowed:
        raise BundleError("Unexpected bundle contents")
    return manifest


def export_records(manifest, result, out):
    records = {"record_version": 1, "status": result["status"], "evidence": [], "test_runs": [],
               "finding_id": manifest["finding_id"], "bundle_id": manifest["bundle_id"],
               "limitation": LIMITATION + " Manual review/import only; never change a finding verdict automatically."}
    evidence_dir = out / "evidence"
    evidence_dir.mkdir(mode=0o700)
    # Only a completed, repeatable replay is evidence. A stale, failed, timed-out
    # or partly errored ("incomplete") replay exports nothing.
    cycles = result.get("cycles", []) if result["status"] == "completed" and result.get("repeatable") is True else []
    for cycle in cycles:
        for case in cycle.get("reproduction", {}).get("cases", []):
            identifier = "repro-{}-{}-{}-{}".format(manifest["bundle_id"][:12], cycle["cycle"], case["phase"], case["role"])
            pin = {"commit": manifest["assessment"]["commit"] if case["phase"] == "before" else manifest["plan"]["after"]["commit"]}
            if case["phase"] == "before" and "diff_sha256" in manifest["assessment"]:
                pin["diff_sha256"] = manifest["assessment"]["diff_sha256"]
            raw = runtime.canonical(case) + b"\n"
            write_raw_new(evidence_dir / (identifier + ".json"), raw)
            records["evidence"].append({"id": identifier, "kind": "runtime", **pin,
                                        "location": "evidence/" + identifier + ".json",
                                        "summary": "Executed synthetic SQLite model only; target revision is declared, not checked out.",
                                        "sha256": runtime.digest(raw)})
            records["test_runs"].append({"id": identifier, **pin, "case_id": case["case_id"],
                "role": case["role"], "expected": json.dumps(case["expected"]), "observed": json.dumps(case["actual"]),
                "command": "Auditor-owned isolated synthetic template; no target command",
                "recorded_at": result["recorded_at"], "result": case["result"], "failure_kind": case["failure_kind"],
                "exit_code": case["exit_code"], "evidence_ids": [identifier],
                "context": {"environment": "throwaway", "boundary": "mocked",
                            "configuration": manifest["configuration_sha256"], "fixture": manifest["fixture_sha256"],
                            "test_version": manifest["template_sha256"]}})
    runtime.write_new(out / "records.json", records)
    return records


def child_timeout(timeout):
    """The child runtime's own deadline: a quarter of the run, at least 2 s, is margin,
    except that the child always keeps 1 s, so --timeout 2 leaves a 1 s margin."""
    return max(1, timeout - max(2, timeout // 4))


def run(bundle, findings, out, timeout=10, evidence_root=None, evidence_repository=None):
    if type(timeout) is not int or not 2 <= timeout <= 60:
        raise BundleError("Timeout must be an integer 2..60 seconds")
    manifest = verify(bundle, findings, evidence_root, evidence_repository)
    bundle = runtime.safe_path(bundle, True)
    out = runtime.safe_path(out, True)
    if bundle == out or bundle in out.parents or out in bundle.parents:
        raise BundleError("Results must be separate from the bundle")
    out = new_directory(out)
    started = datetime.now(timezone.utc).isoformat()
    result = {"status": "not_run", "repeatable": False, "cycles": [], "recorded_at": started,
              "bundle_id": manifest["bundle_id"], "manifest_sha256": runtime.digest(runtime.canonical(manifest)),
              "tools": runtime.tools_record(), "boundary": "mocked", "limitation": LIMITATION}
    if manifest["plan"]["template"] == "manual-target-v1":
        result.update(status="unsupported", reason="Adapter requires target-specific review; no application code or fixture was run.")
    else:
        try:
            # Isolate imports/environment; execute only byte-checked auditor source.
            # No shell, plan-derived argv, project hooks, imports or stored commands.
            program = ("__file__ = " + repr(str(bundle / "run.py")) + "\n" +
                       runtime.read_bytes(Path(__file__).with_name("reproduction_runtime.py")).decode("utf-8") +
                       # The child stops well before the parent would kill it (startup,
                       # the evidence check and one action plus cleanup fit in the margin),
                       # so a slow replay reports "timeout" itself and cleans up its fixture.
                       '\n\nif __name__ == "__main__":\n    sys.exit(entry("run", evidence_checked=True, timeout={}))\n'
                       .format(child_timeout(timeout)))
            process = subprocess.run([sys.executable, "-I", "-S", "-c", program,
                                      "--findings", str(runtime.safe_path(findings, False))],
                                     cwd=str(bundle), env={"PATH": os.defpath}, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
            try:
                observed = json.loads(process.stdout)
            except (ValueError, UnicodeError):
                observed = None
            if isinstance(observed, dict) and observed.get("bundle_id") == manifest["bundle_id"] and observed.get("manifest_sha256") == result["manifest_sha256"]:
                result = observed
                if process.returncode != 0 and result.get("status") == "completed":
                    result.update(status="error", repeatable=False)
            else:
                result.update(status="error", reason="Trusted runner did not return a matching result")
            result["runner_exit_code"] = process.returncode
        except subprocess.TimeoutExpired:
            result.update(status="timeout", cleanup_status="manual_review_required", reason="Runner exceeded the explicit timeout; no pass recorded. Inspect any remaining owned fixture and lock before cleanup.")
        except OSError:
            result.update(status="error", reason="Runner could not start; no pass recorded")
    result["timeout_seconds"] = timeout
    result["generation_tools"] = manifest["tools"]
    result["tool_versions_match"] = result["tools"] == manifest["tools"]
    result["reproducibility_scope"] = "semantic results within this run; byte-identical environment not guaranteed"
    # Re-read before evidence publication; changed source/bundle invalidates success.
    try:
        verify(bundle, findings, evidence_root, evidence_repository)
    except (BundleError, OSError, ValueError):
        result.update(status="stale", repeatable=False, reason="Inputs changed during replay; do not use results as current evidence")
    runtime.write_new(out / "results.json", result)
    export_records(manifest, result, out)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    generate_parser = sub.add_parser("generate")
    generate_parser.add_argument("findings", type=Path)
    generate_parser.add_argument("--finding", required=True)
    generate_parser.add_argument("--plan", type=Path, required=True)
    generate_parser.add_argument("--out", type=Path, required=True)
    generate_parser.add_argument("--evidence-root", type=Path)
    generate_parser.add_argument("--evidence-repository", type=Path)
    for command in ("verify", "run"):
        child = sub.add_parser(command)
        child.add_argument("bundle", type=Path)
        child.add_argument("--findings", type=Path, required=True)
        child.add_argument("--evidence-root", type=Path)
        child.add_argument("--evidence-repository", type=Path)
        if command == "run":
            child.add_argument("--out", type=Path, required=True)
            child.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        if args.action == "generate":
            result = generate(args.findings, args.finding, runtime.load_json(args.plan), args.out,
                              args.evidence_root, args.evidence_repository)
        elif args.action == "verify":
            manifest = verify(args.bundle, args.findings, args.evidence_root, args.evidence_repository)
            result = {"status": "not_run", "integrity": "checked", "bundle_id": manifest["bundle_id"], "limitation": LIMITATION}
        else:
            result = run(args.bundle, args.findings, args.out, args.timeout,
                         args.evidence_root, args.evidence_repository)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0 if result["status"] in ("not_run", "completed") else 3
    except RecursionError:
        print("reproduction error: input JSON nesting is too deep.", file=sys.stderr)
        return 2
    except (BundleError, OSError, ValueError, KeyError, TypeError) as exc:
        # Errors can contain arbitrary findings strings. Never echo those values.
        print("reproduction error: {}. Check the documented input contract and unchanged owned files.".format(type(exc).__name__), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
