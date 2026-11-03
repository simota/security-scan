#!/usr/bin/env python3
"""Measure complete offline scan/contract/report paths and isolated Git hashing.

Use the same harness with --scripts-dir pointing at each revision. Fixtures,
warmup, input copying and output hashing are outside the timed regions. Git
object hashing uses an inert in-memory cat-file response: it does not measure
Git subprocess latency. No target application or advisory command is executed.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile

from benchmark_performance import measure, positive_int, process_peak_rss


ROOT = Path(__file__).resolve().parents[2]
SIZES = {
    "small": {"services": 3, "extensions": 2, "workflows": 1, "steps": 8,
              "source_files": 32, "contract_findings": 10, "report_findings": 10,
              "renumber_findings": 10, "evidence": 10, "runs": 5, "url_strings": 100, "blob_bytes": 64},
    "normal": {"services": 64, "extensions": 16, "workflows": 12, "steps": 48,
               "source_files": 1500, "contract_findings": 200, "report_findings": 100,
               "renumber_findings": 300, "evidence": 100, "runs": 50, "url_strings": 1000, "blob_bytes": 1024 * 1024},
    "high": {"services": 1500, "extensions": 1000, "workflows": 48, "steps": 160,
             "source_files": 10000, "contract_findings": 1800, "report_findings": 400,
             "renumber_findings": 999, "evidence": 500, "runs": 200, "url_strings": 10000, "blob_bytes": 16 * 1024 * 1024},
}
WORKLOADS = ("compose", "workflow_remote", "workflow_local", "source_tree",
             "contract", "renumber", "verification_catalog", "url_plain", "url_dense", "url_symbols",
             "git_object_sha1", "git_object_sha256")


def compose_fixture(root, services, extensions):
    lines = ["name: performance-fixture", 'version: "3.9"']
    for number in range(extensions):
        lines += ["x-template-%d: &template_%d" % (number, number),
                  "  image: nginx" if number % 7 == 0 else "  image: nginx:1.27",
                  "  restart: unless-stopped"]
    lines.append("services:")
    for number in range(services):
        lines += ["  service-%d:" % number,
                  "    image: redis" if number % 11 == 0 else "    image: redis:7.2",
                  "    environment:", "      INSTANCE: %d" % number]
        if number % 19 == 0:
            lines.append("    build: ./local-image")
    lines += ["networks:", "  default: {}", "volumes:", "  data: {}"]
    (root / "compose.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def workflow_fixture(root, workflows, steps, local=False):
    directory = root / ".github/workflows"
    directory.mkdir(parents=True)
    for number in range(workflows):
        trigger = ("pull_request", "workflow_dispatch", "pull_request_target")[number % 3]
        lines = ["name: fixture-%d" % number, "on: " + trigger, "jobs:", "  test:",
                 "    runs-on: ubuntu-latest", "    steps:",
                 "      - uses: actions/checkout@" + "0" * 40]
        for step in range(steps):
            lines += ["      - name: inspect-%d" % step, "        run: |",
                      "          echo fixture-%d-%d" % (number, step)]
            if step % 31 == 0:
                lines.append("          echo '${{ github.event.pull_request.title }}'")
        if local:
            lines += ["      - uses: ./fixture-action", "        with:",
                      "          ref: ${{ github.event.pull_request.head.sha }}"]
        (directory / ("fixture-%04d.yml" % number)).write_text("\n".join(lines) + "\n", encoding="utf-8")
    if local:
        action = root / "fixture-action"
        action.mkdir()
        (action / "action.yml").write_text(
            "name: Local fixture\ninputs:\n  ref:\n    required: true\nruns:\n"
            "  using: composite\n  steps:\n    - uses: actions/checkout@" + "0" * 40 +
            "\n      with:\n        ref: ${{ inputs.ref }}\n    - run: echo fixture\n      shell: bash\n",
            encoding="utf-8")


def sources_fixture(root, count):
    for number in range(count):
        directory = root / ("src-%04d" % (number // 100))
        directory.mkdir(exist_ok=True)
        suffix = ("py", "js", "ts", "go", "rb", "md", "json", "yaml")[number % 8]
        (directory / ("module-%05d.%s" % (number, suffix))).write_text("# inert fixture\n", encoding="utf-8")
    (root / "requirements.txt").write_text("fixture-package==1.0.0\n", encoding="utf-8")


def contract_fixture(contract, root, count):
    code_count = min((count + 1) // 2, 999)
    names = contract.perspective_names()
    findings = []
    for index in range(count):
        code = index < code_count
        number = index + 1 if code else index - code_count + 1
        findings.append({
            "id": ("F-" if code else "D-") + "%03d" % number,
            "title": "Synthetic finding %04d" % index, "severity": "High",
            "confidence": "Confirmed", "category": names[0],
            "location": "src/module_%04d.py:2" % index,
            "actor": "synthetic actor", "request": "synthetic request",
            "impact": "synthetic impact", "fix": "synthetic fix",
            "validation": {"verdict": "Likely", "evidence": "synthetic evidence", "method": "review"},
            "verification": {"claims": {key: {} for key in contract.CLAIMS}, "falsification": [{}]},
        })
    data = {
        "schema_version": 2,
        "meta": {"project": "Synthetic contract benchmark", "date": "2026-11-04",
                 "assessor": "Synthetic fixture", "commit": "a" * 40},
        "assessment": {"repository": "synthetic", "commit": "a" * 40, "worktree": "clean"},
        "findings": findings,
        "perspectives": [{"name": name, "result": "N/A - synthetic fixture"} for name in names],
        "dependency_scan": {"tool": "deps_scan.py", "audit": True, "findings": count - code_count, "not_run": 0},
        "limitations": ["assessment.pdf not produced: no PDF engine",
                        "invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)"],
    }
    raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    (root / "findings.json").write_bytes(raw)
    (root / "deps.json").write_text('{"findings": [], "not_run": []}\n', encoding="utf-8")
    (root / "evidence").mkdir()
    stamp = '<meta name="security-scan-source" content="sha256:%s">' % hashlib.sha256(raw).hexdigest()
    for name in ("dashboard.html", "assessment.html"):
        (root / name).write_text(stamp, encoding="utf-8")
    problems = contract.check(data, root, pdf=False)
    if problems:
        raise ValueError("invalid contract fixture: " + repr(problems))
    return data


def report_fixture(render, dimensions):
    data = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
    original = data["findings"][0]
    data["findings"] = [dict(copy.deepcopy(original), id="F-%04d" % (index + 1))
                        for index in range(dimensions["report_findings"])]
    for key, target in (("evidence", dimensions["evidence"]), ("test_runs", dimensions["runs"])):
        original = data[key][0]
        data[key].extend(dict(copy.deepcopy(original), id="extra-%s-%04d" % (key, index))
                         for index in range(max(0, target - len(data[key]))))
    return render.validate_data(data)


def renumber_fixture(count):
    return [{"id": "F-%03d" % (count - index),
             "severity": ("High", "Medium", "Low", "Info")[index % 4],
             "location": "src/module_%03d.py:%d" % (index % 23, index + 1),
             "validation": {"verdict": "FalsePositive" if index % 2 else "Likely"}}
            for index in range(count)]


def url_fixture(name, count):
    if name == "url_plain":
        return [("Confirmed", "ordinary report text", "接続先の説明", "module.py")[index % 4]
                for index in range(count)]
    if name == "url_dense":
        # Long source lines expose per-match costs that short field values hide.
        line = " ".join("'https://host-%02d.invalid/path?token=synthetic'" % (index % 64)
                        for index in range(500))
        return [line] * max(1, count // 500)
    # A delimiter at the end forces the syntax prefilter to scan the whole line.
    return [("ordinary non-URL text " * 1024) + (":" if index % 2 else "%")
            for index in range(max(1, count // 100))]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts-dir", type=Path, default=ROOT / "skills/security-scan/scripts")
    parser.add_argument("--size", choices=SIZES, default="normal")
    parser.add_argument("--workloads", nargs="+", choices=WORKLOADS, default=list(WORKLOADS))
    parser.add_argument("--repeats", type=positive_int, default=21)
    parser.add_argument("--memory", action="store_true",
                        help="measure peak Python allocations in three separate untimed runs")
    parser.add_argument("--lang", choices=("en", "ja"), default="en")
    args = parser.parse_args(argv)
    scripts = args.scripts_dir.resolve()
    for name in ("deps_scan.py", "contract_check.py", "render.py", "evidence_integrity.py"):
        if not (scripts / name).is_file():
            parser.error("scripts directory is missing " + name)
    sys.path.insert(0, str(scripts))
    import contract_check
    import deps_scan
    import evidence_integrity
    import findings
    import render
    import url_redaction

    dimensions = SIZES[args.size]
    results = {}
    with tempfile.TemporaryDirectory(prefix="security-scan-pipeline-") as temporary:
        base = Path(temporary).resolve()
        for name in args.workloads:
            root = base / name
            root.mkdir()
            if name in ("compose", "workflow_remote", "workflow_local", "source_tree"):
                if name == "compose":
                    compose_fixture(root, dimensions["services"], dimensions["extensions"])
                elif name.startswith("workflow_"):
                    workflow_fixture(root, dimensions["workflows"], dimensions["steps"], name == "workflow_local")
                else:
                    sources_fixture(root, dimensions["source_files"])
                results[name] = measure(lambda: root, lambda path: deps_scan.scan(path, False),
                                        args.repeats, args.memory, metrics=True)
            elif name == "contract":
                data = contract_fixture(contract_check, root, dimensions["contract_findings"])
                results[name] = measure(lambda: data, lambda record: contract_check.check(record, root, pdf=False),
                                        args.repeats, args.memory, metrics=True)
            elif name == "verification_catalog":
                data = report_fixture(render, dimensions)
                labels = render.LABELS[args.lang]
                def reports(record):
                    return {"dashboard": render.render_dashboard(record, labels, args.lang),
                            "assessment": render.render_assessment_html(record, labels, args.lang)}
                results[name] = measure(lambda: copy.deepcopy(data), reports, args.repeats, args.memory, metrics=True)
            elif name == "renumber":
                data = renumber_fixture(dimensions["renumber_findings"])
                results[name] = measure(lambda: data, findings.renumber_map, args.repeats, args.memory, metrics=True)
            elif name.startswith("url_"):
                data = url_fixture(name, dimensions["url_strings"])
                def redacted_fields(fields):
                    return [url_redaction.redact_urls(value) for value in fields]
                results[name] = measure(lambda: data, redacted_fields, args.repeats, args.memory, metrics=True)
            else:
                raw = b"x" * dimensions["blob_bytes"]
                algorithm = hashlib.sha1 if name == "git_object_sha1" else hashlib.sha256
                header = b"blob " + str(len(raw)).encode("ascii") + b"\0"
                digest = algorithm(header)
                digest.update(raw)
                oid = digest.hexdigest()
                snapshot = object.__new__(evidence_integrity._GitSnapshot)
                snapshot.object_length = len(oid)
                snapshot._command = lambda command, limit: raw
                def checked_blob(_):
                    result = snapshot.object(oid, "blob")
                    if result is not raw:
                        raise RuntimeError("Git object method did not retain the original bytes")
                    return {"oid": oid, "bytes": len(result)}
                results[name] = measure(lambda: None, checked_blob, args.repeats, args.memory, metrics=True)
    print(json.dumps({"python": platform.python_version(), "platform": platform.platform(),
                      "scripts_dir": str(scripts), "size": args.size, "dimensions": dimensions,
                      "repeats": args.repeats, "language": args.lang, "workloads": results,
                      "process_peak_rss_bytes": process_peak_rss(),
                      "rss_includes_tracemalloc": args.memory}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
