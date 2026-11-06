#!/usr/bin/env python3
"""Measure offline scan, advisory and report workloads against a local checkout.

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


def osv_fixture(count, group_size):
    """Synthetic advisory records; no scanner, advisory service or target runs."""
    records, groups = [], []
    for index in range(count):
        identifier = "BENCH-%06d" % index
        records.append({
            "id": identifier, "summary": "Synthetic advisory %d" % index,
            "aliases": ["CVE-2099-%06d" % index],
            "affected": [{"package": {"name": "benchmark-package"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.2.%d" % index}]}]}],
            "references": [{"type": "FIX", "url": "https://example.invalid/fixes/%d" % index}],
        })
        if group_size:
            if index % group_size == 0:
                groups.append({"ids": [], "max_severity": "7.5"})
            groups[-1]["ids"].append(identifier)
    return {"results": [{"source": {"path": "package-lock.json", "type": "lockfile"},
                         "packages": [{"package": {"name": "benchmark-package", "version": "1.0.0"},
                                       "vulnerabilities": records, "groups": groups}]}]}


def verification_fixture(render, count):
    document = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
    finding = document["findings"][0]
    document["findings"] = [dict(copy.deepcopy(finding), id="F-%04d" % (index + 1))
                            for index in range(count)]
    return render.validate_data(document)


def triage_fixture(deps_scan, root, source_files, source_lines, findings):
    """An ecosystem without source-reference inference still needs triage."""
    text = "value = 42\n" * source_lines
    for index in range(source_files):
        (root / ("module_%04d.py" % index)).write_text(text, encoding="utf-8")
    lock = root / "requirements.txt"
    lock.write_text("benchmark-package==1.0.0\n", encoding="utf-8")
    collector = deps_scan.Collector(root)
    for index in range(findings):
        deps_scan.vuln(collector, "high", "benchmark-package", "1.0.0",
                       ["BENCH-%06d" % index], "Synthetic advisory", lock, "benchmark")
    return collector, len(text.encode("utf-8")) * source_files


def integrity_fixture(render, integrity, root, findings, evidence_count):
    """Check inert local artifacts once, then time only their report projection.

    Source revision checks intentionally remain incomplete: no Git repository or
    recorded application command is executed by this fixture.
    """
    document = verification_fixture(render, findings)
    if not len(document["evidence"]) <= evidence_count <= integrity.MAX_EVIDENCE:
        raise ValueError("integrity evidence count must be between %d and %d" %
                         (len(document["evidence"]), integrity.MAX_EVIDENCE))
    content = b"Synthetic benchmark evidence; no application execution.\n"
    digest = hashlib.sha256(content).hexdigest()
    for index in range(evidence_count - len(document["evidence"])):
        document["evidence"].append({
            "id": "extra-%04d" % index, "kind": "runtime",
            "commit": document["assessment"]["commit"],
            "summary": "Synthetic unreferenced evidence", "location": "", "sha256": digest,
        })
    for index, record in enumerate(document["evidence"]):
        record["location"] = "evidence-%04d.txt" % index
        record["sha256"] = digest
        (root / record["location"]).write_bytes(content)
    document = render.validate_data(document)
    return document, integrity.verify_evidence(document, root)


def comparison_fixture(render, count):
    """Two validated rescans: line drift, reworded titles, new and unreported findings."""
    words = ("tenant", "order", "export", "session", "token", "upload", "query", "redirect")

    def finding(index, line, reworded=False):
        title = "%s check missing in handler %d" % (words[index % len(words)].capitalize(), index)
        return {"id": "F-%04d" % (index + 1), "severity": ("High", "Medium", "Low")[index % 3],
                "confidence": "Suspected", "category": "Category %d" % (index % 7),
                "title": title + (" (revised)" if reworded else ""),
                "location": "src/module_%03d.py:%d" % (index // 4, line)}

    meta = {"project": "benchmark", "date": "2026-01-01"}
    baseline = [finding(index, 10 + index % 40) for index in range(count)]
    current = [finding(index, 12 + index % 40, reworded=index % 5 == 0)
               for index in range(count) if index % 10 != 9]
    current += [finding(count + index, 5) for index in range(count // 10)]
    for number, record in enumerate(current, 1):
        record["id"] = "F-%04d" % number
    return tuple(render.validate_data({"meta": meta, "findings": findings, "perspectives": []})
                 for findings in (baseline, current))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts-dir", type=Path,
                        default=ROOT / "skills/security-scan/scripts",
                        help="scripts directory from the local revision to measure")
    parser.add_argument("--repeats", type=positive_int, default=5)
    parser.add_argument("--workspaces", type=positive_int, default=600)
    parser.add_argument("--findings", type=positive_int, default=500)
    parser.add_argument("--source-lines", type=positive_int, default=10000)
    parser.add_argument("--osv-records", type=positive_int, default=2000)
    parser.add_argument("--report-findings", type=positive_int, default=400)
    parser.add_argument("--triage-findings", type=positive_int, default=100)
    parser.add_argument("--triage-source-files", type=positive_int, default=600)
    parser.add_argument("--integrity-findings", type=positive_int, default=200)
    parser.add_argument("--integrity-evidence", type=positive_int, default=500)
    parser.add_argument("--compare-findings", type=positive_int, default=300)
    args = parser.parse_args(argv)
    scripts = args.scripts_dir.resolve()
    for name in ("deps_scan.py", "render.py"):
        if not (scripts / name).is_file():
            parser.error("scripts directory is missing " + name)
    sys.path.insert(0, str(scripts))
    import deps_scan
    import render
    import evidence_integrity
    # Revisions before compare.py existed have no rescan comparison to measure.
    compare = __import__("compare") if (scripts / "compare.py").is_file() else None

    with tempfile.TemporaryDirectory(prefix="security-scan-benchmark-") as temporary:
        base = Path(temporary).resolve()
        workspace, source = base / "workspace", base / "source"
        triage_source, evidence = base / "triage", base / "evidence"
        workspace.mkdir()
        source.mkdir()
        triage_source.mkdir()
        evidence.mkdir()
        workspace_fixture(workspace, args.workspaces)
        document, source_bytes = excerpt_fixture(source, args.findings, args.source_lines)
        report = verification_fixture(render, args.report_findings)
        triage_data, triage_bytes = triage_fixture(deps_scan, triage_source, args.triage_source_files,
                                                  args.source_lines, args.triage_findings)
        try:
            integrity_report, live_result = integrity_fixture(render, evidence_integrity, evidence,
                                                               args.integrity_findings, args.integrity_evidence)
        except ValueError as error:
            parser.error(str(error))

        def excerpts(data):
            render.attach_sources(data, source)
            return data

        def advisories(data):
            collector = deps_scan.Collector(workspace)
            deps_scan.parse_osv(collector, data, workspace, workspace / "package-lock.json")
            return collector.findings

        def reports(data, integrity=None):
            labels = render.LABELS["en"]
            return {"dashboard": render.render_dashboard(data, labels, "en", integrity=integrity),
                    "assessment": render.render_assessment_html(data, labels, "en", integrity=integrity)}

        def triage(collector):
            deps_scan.triage(collector, triage_source)
            return collector.findings

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
                "structured_verification_report": {
                    "findings": args.report_findings, "language": "en", "html_outputs": 2,
                    **measure(lambda: copy.deepcopy(report), reports, args.repeats),
                },
                "triage_without_source_model": {
                    "findings": args.triage_findings, "ecosystem": "python",
                    "source_files": args.triage_source_files, "source_bytes": triage_bytes,
                    **measure(lambda: copy.deepcopy(triage_data), triage, args.repeats),
                },
                "live_integrity_report": {
                    "findings": args.integrity_findings, "evidence_records": args.integrity_evidence,
                    "language": "en", "html_outputs": 2,
                    **measure(lambda: copy.deepcopy(integrity_report),
                              lambda data: reports(data, live_result), args.repeats),
                },
            },
        }
        for name, group_size in (("osv_distinct_groups", 1), ("osv_alias_pairs", 2), ("osv_ungrouped", 0)):
            payload = osv_fixture(args.osv_records, group_size)
            result["workloads"][name] = {
                "vulnerability_records": args.osv_records,
                "groups": len(payload["results"][0]["packages"][0]["groups"]),
                **measure(lambda: copy.deepcopy(payload), advisories, args.repeats),
            }
        if compare is not None:
            comparison = comparison_fixture(render, args.compare_findings)
            result["workloads"]["rescan_comparison"] = {
                "baseline_findings": len(comparison[0]["findings"]),
                "current_findings": len(comparison[1]["findings"]),
                **measure(lambda: copy.deepcopy(comparison),
                          lambda pair: compare.compare(pair[0], pair[1], "High"), args.repeats),
            }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
