"""Auditor-owned synthetic fixture runtime. No target code, SQL or commands as input.

This source is copied into each generated entrypoint. Always use Python -I.
It exercises a MODEL, not the application's real authorization boundary.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import sys
import time

VERSION = "2"
TEMPLATES = ("sqlite-owner-scope-v1", "manual-target-v1")
SCRIPTS = ("seed.py", "reproduce.py", "cleanup.py", "run.py")
MAX_BYTES = 4 * 1024 * 1024


class BundleError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def safe_path(path, directory=None):
    path = Path(os.path.abspath(str(path)))
    for part in (path,) + tuple(path.parents):
        if part.is_symlink():
            raise BundleError("Symlinks are not allowed")
    if path.exists():
        info = path.stat()
        if directory is True and not stat.S_ISDIR(info.st_mode):
            raise BundleError("Expected a directory")
        if directory is False and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise BundleError("Expected a regular, unlinked file")
    return path


def read_bytes(path):
    path = safe_path(path, False)
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise BundleError("File exceeds the bundle size limit")
    return data


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BundleError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid(value):
        raise BundleError("Nonfinite JSON is not allowed")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError):
        raise BundleError("Invalid UTF-8 JSON") from None


def load_json(path):
    return parse_json(read_bytes(path))


def write_new(path, value):
    path = safe_path(path, False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
COMMIT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")


def safe_identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise BundleError("IDs must be bounded alphanumeric identifiers")
    return value


def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {"plan_version", "template", "case_id", "seed", "before", "after", "fixture", "evidence_ids"}:
        raise BundleError("Plan requires exactly the documented declarative fields; commands/SQL are unsupported")
    if type(plan["plan_version"]) is not int or plan["plan_version"] != 1 or plan["template"] not in TEMPLATES:
        raise BundleError("Unsupported plan or template version")
    safe_identifier(plan["case_id"])
    if type(plan["seed"]) is not int or not 0 <= plan["seed"] <= 2147483647:
        raise BundleError("Seed must be an integer between 0 and 2147483647")
    if plan["before"] != {"policy": "unscoped"}:
        raise BundleError("Before policy must be unscoped for this model")
    after = plan["after"]
    if not isinstance(after, dict) or set(after) != {"policy", "commit"} or after["policy"] != "owner_scoped" or not isinstance(after["commit"], str) or not COMMIT.fullmatch(after["commit"]):
        raise BundleError("After requires owner_scoped and a full lowercase declared commit")
    fixture = plan["fixture"]
    if not isinstance(fixture, dict) or set(fixture) != {"owners", "resources_per_owner"} or any(type(x) is not int or not 2 <= x <= 10 for x in fixture.values()):
        raise BundleError("Fixture owners and resources_per_owner must be integers 2..10")
    refs = plan["evidence_ids"]
    if not isinstance(refs, list) or not refs or len(refs) > 50:
        raise BundleError("Select 1..50 source evidence IDs for reviewer target binding")
    for ref in refs:
        safe_identifier(ref)
    if len(set(refs)) != len(refs):
        raise BundleError("Duplicate evidence ID")
    return json.loads(canonical(plan))



def tools_record():
    return {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
            "runtime": VERSION, "implementation": platform.python_implementation()}


def manifest_at(bundle, findings, evidence_checked=False):
    bundle = safe_path(bundle, True)
    manifest = load_json(bundle / "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("bundle_version") != 1:
        raise BundleError("Unsupported manifest")
    seal = load_json(bundle / "manifest.sha256.json")
    if seal != {"sha256": digest(canonical(manifest))}:
        raise BundleError("Manifest digest mismatch")
    findings_bytes = read_bytes(findings)
    if digest(findings_bytes) != manifest.get("findings_sha256"):
        raise BundleError("Stale findings input; generate a new bundle")
    findings_data = parse_json(findings_bytes)
    if not isinstance(findings_data, dict) or type(findings_data.get("schema_version")) is not int or findings_data["schema_version"] != 2:
        raise BundleError("Source findings must retain schema version 2")
    policy = findings_data.get("evidence_integrity", {})
    if (not isinstance(policy, dict) or ("evidence_integrity" in findings_data and
            (set(policy) != {"required"} or type(policy.get("required")) is not bool))):
        raise BundleError("Invalid source evidence policy")
    required = policy.get("required") is True
    if (required or "evidence_receipt_sha256" in manifest) and not evidence_checked:
        raise BundleError("This bundle requires the repository runner's fresh evidence checks")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(SCRIPTS) | {"adapter.todo.json"}:
        raise BundleError("Unexpected bundle file inventory")
    for name, expected in files.items():
        if digest(read_bytes(bundle / name)) != expected:
            raise BundleError("Bundle file digest mismatch")
    validate_plan(manifest.get("plan"))
    identifier = manifest.get("bundle_id")
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise BundleError("Invalid bundle identity")
    identity = {key: value for key, value in manifest.items()
                if key not in ("bundle_id", "namespace", "files", "fixture_sha256", "configuration_sha256")}
    if digest(canonical(identity)) != identifier:
        raise BundleError("Bundle identity does not bind the current manifest")
    if manifest.get("namespace") != "ss-" + identifier[:20]:
        raise BundleError("Invalid fixture namespace")
    versions = manifest.get("tools")
    if not isinstance(versions, dict) or set(versions) != {"python", "sqlite", "runtime", "implementation"}:
        raise BundleError("Invalid tool-version record")
    if any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9.+_-]{1,40}", v) for v in versions.values()):
        raise BundleError("Invalid tool-version value")
    return manifest


def fixture_data(manifest):
    plan = manifest["plan"]
    namespace = manifest["namespace"]
    rows = []
    for owner in range(plan["fixture"]["owners"]):
        for resource in range(plan["fixture"]["resources_per_owner"]):
            key = "{}:{}:{}:{}".format(namespace, plan["seed"], owner, resource)
            rows.append({"id": digest(key.encode())[:24], "owner": "synthetic-owner-{}".format(owner),
                         "value": "synthetic-value-{}-{}".format(owner, resource)})
    return rows


def owner_record(manifest):
    return {"bundle_id": manifest["bundle_id"], "namespace": manifest["namespace"],
            "fixture_sha256": digest(canonical(fixture_data(manifest)))}


def scratch_path(bundle, manifest, required=False):
    scratch = safe_path(bundle / ".fixture", True)
    if not scratch.exists():
        if required:
            raise BundleError("Fixture is not seeded")
        return scratch
    if set(p.name for p in scratch.iterdir()) != {"owner.json", "fixture.sqlite3"}:
        raise BundleError("Unexpected fixture contents; leave them for manual review")
    for name in ("owner.json", "fixture.sqlite3"):
        safe_path(scratch / name, False)
    if load_json(scratch / "owner.json") != {**owner_record(manifest), "database_sha256": digest(read_bytes(scratch / "fixture.sqlite3"))}:
        raise BundleError("Fixture ownership mismatch")
    return scratch


def connection(scratch, readonly=False):
    # Callers close it: sqlite3's own context manager only commits, and an open
    # handle would keep Windows from deleting the fixture during cleanup.
    path = safe_path(scratch / "fixture.sqlite3", False)
    # URI path comes only from an owned, fixed local path; escape URI syntax.
    if readonly:
        return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
    return sqlite3.connect(str(path), timeout=1)


def seed(bundle, manifest):
    scratch = scratch_path(bundle, manifest)
    rows = fixture_data(manifest)
    if scratch.exists():
        with closing(connection(scratch, True)) as db, db:
            actual = db.execute("SELECT id, owner, value FROM resources ORDER BY id").fetchall()
        expected = sorted((r["id"], r["owner"], r["value"]) for r in rows)
        if actual != expected:
            raise BundleError("Existing fixture differs; cleanup before seeding")
        return {"status": "seeded", "idempotent": True, **owner_record(manifest)}
    scratch.mkdir(mode=0o700)
    # Reserve only our fixed filename, never open or overwrite an existing DB.
    fd = os.open(str(scratch / "fixture.sqlite3"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with closing(connection(scratch)) as db, db:
        db.execute("CREATE TABLE resources (id TEXT PRIMARY KEY, owner TEXT NOT NULL, value TEXT NOT NULL)")
        db.executemany("INSERT INTO resources VALUES (?, ?, ?)", [(r["id"], r["owner"], r["value"]) for r in rows])
    write_new(scratch / "owner.json", {**owner_record(manifest), "database_sha256": digest(read_bytes(scratch / "fixture.sqlite3"))})
    return {"status": "seeded", "idempotent": False, **owner_record(manifest)}


def cleanup(bundle, manifest):
    scratch = scratch_path(bundle, manifest)
    if not scratch.exists():
        return {"status": "clean", "idempotent": True}
    # No recursive removal, arbitrary paths, globbing, or target cleanup hooks.
    for name in ("fixture.sqlite3", "owner.json"):
        safe_path(scratch / name, False).unlink()
    scratch.rmdir()
    return {"status": "clean", "idempotent": False}


def reproduce(bundle, manifest):
    scratch = scratch_path(bundle, manifest, required=True)
    rows = fixture_data(manifest)
    with closing(connection(scratch, True)) as db, db:
        actual = db.execute("SELECT id, owner, value FROM resources ORDER BY id").fetchall()
        if actual != sorted((r["id"], r["owner"], r["value"]) for r in rows):
            raise BundleError("Fixture contents changed")
        cases = []
        for phase in ("before", "after"):
            policy = manifest["plan"][phase]["policy"]
            def query(resource, actor):
                if policy == "unscoped":
                    return db.execute("SELECT value FROM resources WHERE id = ?", (resource,)).fetchall()
                if policy == "owner_scoped":
                    return db.execute("SELECT value FROM resources WHERE id = ? AND owner = ?", (resource, actor)).fetchall()
                raise BundleError("Unsupported query policy")
            for role, suffix, actor, resource, expected, expected_result in (
                ("security", "", "synthetic-owner-1", rows[0]["id"], [], "fail" if phase == "before" else "pass"),
                ("positive_control", "-owner", rows[0]["owner"], rows[0]["id"], [(rows[0]["value"],)], "pass"),
                ("regression", "-missing", rows[0]["owner"], "synthetic-missing-resource", [], "pass"),
            ):
                observed = query(resource, actor)
                result = "pass" if observed == expected else "fail"
                cases.append({"phase": phase, "role": role, "case_id": manifest["plan"]["case_id"] + suffix,
                              "expected": expected, "actual": observed, "result": result,
                              "expected_result": expected_result, "matched": result == expected_result,
                              "exit_code": 0 if result == "pass" else 1,
                              "failure_kind": "none" if result == "pass" else "assertion"})
    return {"status": "completed" if all(c["matched"] for c in cases) else "mismatch",
            "boundary": "mocked", "cases": cases, **owner_record(manifest)}


def repeat(bundle, manifest, timeout=10):
    deadline = time.monotonic() + timeout
    cycles = []
    for index in range(2):
        result = {"cycle": index + 1, "status": "not_run", "steps": []}
        try:
            for action in (cleanup, seed, reproduce):
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                observation = action(bundle, manifest)
                result["steps"].append({"action": action.__name__, "observation": observation})
                if action == reproduce:
                    result["reproduction"] = observation
                    result["semantic_sha256"] = digest(canonical(observation))
                    result["status"] = observation["status"]
        except (BundleError, OSError, sqlite3.Error, TimeoutError) as exc:
            result["status"] = "timeout" if isinstance(exc, TimeoutError) else "error"
            # Do not echo exception data, SQL, paths, environment, or source text.
            result["error"] = type(exc).__name__
        finally:
            try:
                result["steps"].append({"action": "cleanup", "observation": cleanup(bundle, manifest)})
            except (BundleError, OSError, sqlite3.Error) as exc:
                result["status"] = "error"
                result["cleanup_error"] = type(exc).__name__
        cycles.append(result)
        if result["status"] not in ("completed", "mismatch"):
            break
    repeatable = len(cycles) == 2 and all(x["status"] == "completed" for x in cycles) and cycles[0]["semantic_sha256"] == cycles[1]["semantic_sha256"]
    return {"status": "completed" if repeatable else "incomplete", "repeatable": repeatable,
            "cycles": cycles, "boundary": "mocked", "tools": tools_record(),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "bundle_id": manifest["bundle_id"], "manifest_sha256": digest(canonical(manifest)),
            "limitation": "Synthetic fixture only. No target application code or real boundary was executed."}


def acquire_lock(bundle):
    lock = safe_path(bundle / ".fixture.lock", False)
    fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    return lock


def entry(action, argv=None, evidence_checked=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True, help="Unchanged findings file used to generate this bundle")
    args = parser.parse_args(argv)
    lock = None
    try:
        bundle = safe_path(Path(__file__).absolute().parent, True)
        # Cleanup grants no evidence credit and must remain usable when source
        # evidence disappears. It still checks immutable inputs, bundle identity
        # and the exact owned fixture inventory/hash before deleting anything.
        manifest = manifest_at(bundle, args.findings, evidence_checked=evidence_checked or action == "cleanup")
        if manifest["plan"]["template"] == "manual-target-v1":
            print(json.dumps({"status": "unsupported", "reason": "Target adapter requires review and implementation; nothing executed."}))
            return 3
        lock = acquire_lock(bundle)
        result = {"seed": seed, "reproduce": reproduce, "cleanup": cleanup, "run": repeat}[action](bundle, manifest)
        print(json.dumps(result, sort_keys=True))
        # reproduce follows the secure assertion: the expected vulnerable case is red.
        if action == "reproduce":
            return 1 if any(c["result"] == "fail" for c in result["cases"]) else 0
        return 0 if result["status"] in ("seeded", "clean", "completed") else 3
    except (BundleError, OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": type(exc).__name__, "reason": "Bundle safety or input check failed; nothing is a pass."}))
        return 2
    finally:
        if lock is not None:
            try:
                safe_path(lock, False).unlink()
            except OSError:
                pass
