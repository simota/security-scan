#!/usr/bin/env python3
"""Measure offline scan/excerpt workloads against any local scripts checkout.

Fixture creation, warmup, copying and result hashing are outside the timed
region. Output digests allow comparisons between revisions without claiming
that synthetic timings represent complete audits or PDF rendering.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def measure(prepare, operation, repeats):
    operation(prepare())  # Warm imports and filesystem caches consistently.
    samples, expected = [], None
    for _ in range(repeats):
        payload = prepare()
        started = time.perf_counter()
        result = operation(payload)
        samples.append(time.perf_counter() - started)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if expected is not None and digest != expected:
            raise RuntimeError("benchmark output changed between repetitions")
        expected = digest
    return {"median_seconds": statistics.median(samples),
            "samples_seconds": samples, "output_sha256": expected}


def workspace_fixture(root, count):
    (root / "package.json").write_text(json.dumps({
        "name": "benchmark-workspace", "private": True,
        "workspaces": ["packages/*"],
    }), encoding="utf-8")
    (root / "package-lock.json").write_text(json.dumps({
        "name": "benchmark-workspace", "lockfileVersion": 3, "packages": {},
    }), encoding="utf-8")
    for index in range(count):
        package = root / "packages" / ("p%04d" % index)
        package.mkdir(parents=True)
        (package / "package.json").write_text(json.dumps({
            "name": "p%04d" % index, "dependencies": {"react": "^18.0.0"},
        }), encoding="utf-8")


def excerpt_fixture(root, count, lines):
    text = "value = 42\n" * lines
    (root / "app.py").write_text(text, encoding="utf-8")
    return {"meta": {}, "findings": [
        {"id": "F-%03d" % (index + 1), "category": "Input handling",
         "location": "app.py:%d" % (1 + index * 17 % lines)}
        for index in range(count)
    ]}, len(text.encode("utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts-dir", type=Path,
                        default=ROOT / "skills/security-scan/scripts",
                        help="scripts directory from the local revision to measure")
    parser.add_argument("--repeats", type=positive_int, default=5)
    parser.add_argument("--workspaces", type=positive_int, default=600)
    parser.add_argument("--findings", type=positive_int, default=500)
    parser.add_argument("--source-lines", type=positive_int, default=10000)
    args = parser.parse_args(argv)
    scripts = args.scripts_dir.resolve()
    for name in ("deps_scan.py", "render.py"):
        if not (scripts / name).is_file():
            parser.error("scripts directory is missing " + name)
    sys.path.insert(0, str(scripts))
    import deps_scan
    import render

    with tempfile.TemporaryDirectory(prefix="security-scan-benchmark-") as temporary:
        base = Path(temporary).resolve()
        workspace, source = base / "workspace", base / "source"
        workspace.mkdir()
        source.mkdir()
        workspace_fixture(workspace, args.workspaces)
        document, source_bytes = excerpt_fixture(source, args.findings, args.source_lines)

        def excerpts(data):
            render.attach_sources(data, source)
            return data

        result = {
            "python": platform.python_version(), "platform": platform.platform(),
            "scripts_dir": str(scripts), "repeats": args.repeats,
            "workloads": {
                "offline_workspaces": {
                    "members": args.workspaces,
                    **measure(lambda: workspace, lambda root: deps_scan.scan(root, False), args.repeats),
                },
                "shared_source_excerpts": {
                    "findings": args.findings, "source_lines": args.source_lines,
                    "source_bytes": source_bytes,
                    **measure(lambda: copy.deepcopy(document), excerpts, args.repeats),
                },
            },
        }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
