"""compare.py (rescan delta and CI gate) and export.py (SARIF, CSV, issue drafts)."""
from __future__ import annotations

import contextlib
import copy
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))

import compare  # noqa: E402
import export  # noqa: E402
import finding_keys  # noqa: E402

META = {"project": "demo", "date": "2026-10-07", "assessor": "Claude Code (test)"}


def finding(fid, title, severity="High", location="src/orders.py:42", **extra):
    base = {"id": fid, "title": title, "severity": severity, "confidence": "Confirmed",
            "category": "Actor and tenant", "location": location, "actor": "any signed-in user",
            "request": "GET /orders/{id} with <other tenant's order id>",
            "impact": "reads another tenant's order", "fix": "scope the query by tenant"}
    base.update(extra)
    return base


BASELINE = {"meta": META, "findings": [
    finding("F-001", "Order detail lacks a tenant check", cwe="CWE-639"),
    finding("F-002", "Page size has no upper bound", "Medium", "src/api/util.py:7", category="Availability"),
    finding("F-003", "Debug output enabled", "Low", "deploy/php.ini:9", category="Configuration"),
    finding("F-004", "Report export reads any tenant", "High", "src/api/reports.py:88",
            validation={"verdict": "FalsePositive", "evidence": "the query is tenant scoped at reports.py:80"}),
    finding("D-001", "Known vulnerability in left-pad", "High", "package-lock.json:18",
            package="left-pad", version="1.0.0", advisory_ids=["GHSA-aaaa-bbbb-cccc"]),
], "perspectives": [{"name": "Actor and tenant", "result": "1 High"},
                    {"name": "Configuration", "result": "Not checked: out of budget"}]}


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-compare-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def current(self):
        cur = copy.deepcopy(BASELINE)
        f = cur["findings"]
        # A new run numbers differently, words titles differently and code moved.
        f[0].update(id="F-002", title="Order detail endpoint lacks tenant check", location="src/orders.py:45")
        f[1].update(id="F-003", severity="High")
        del f[2]  # Debug output not reported again (its perspective was not checked)
        f[2]["validation"] = {"verdict": "Valid", "evidence": "reports.py:88 loads by id alone"}
        f[2]["id"] = "F-001"
        f[3].update(id="D-002", version="1.0.1", location="package-lock.json:20")
        f.append(finding("F-004", "Admin export lacks a role guard", "High", "src/admin.py:5",
                         category="Role and privilege"))
        return cur

    def run_compare(self, base, cur, fail_on=None):
        b = compare.read_record(self.write("base.json", base))
        c = compare.read_record(self.write("cur.json", cur))
        return compare.compare(b, c, fail_on)

    def test_matches_across_renumbering_rewording_and_line_drift(self):
        report = self.run_compare(BASELINE, self.current())
        pairs = {f["id"]: f["baseline_id"] for f in report["persisting"]}
        self.assertEqual(pairs, {"F-002": "F-001", "F-003": "F-002", "D-002": "D-001"})
        self.assertEqual([f["id"] for f in report["new"]], ["F-004"])
        self.assertEqual([(f["id"], f["baseline_id"]) for f in report["reopened"]], [("F-001", "F-004")])
        self.assertEqual([f["id"] for f in report["not_reported"]], ["F-003"])
        self.assertFalse(report["not_reported"][0]["perspective_checked"])
        changed = {f["id"]: f["changes"] for f in report["persisting"] if f["changes"]}
        self.assertEqual(changed, {"F-003": {"severity": {"from": "Medium", "to": "High"}}})
        self.assertEqual(report["summary"]["severity_raised"], 1)

    def test_identical_records_compare_as_all_persisting(self):
        report = self.run_compare(BASELINE, BASELINE, "Low")
        self.assertEqual(report["summary"]["persisting"], 4)
        for key in ("new", "reopened", "not_reported", "ruled_out"):
            self.assertEqual(report[key], [], key)
        self.assertTrue(report["gate"]["passed"])

    def test_different_files_with_different_titles_never_match(self):
        cur = copy.deepcopy(BASELINE)
        cur["findings"][0].update(location="src/billing.py:42", title="Invoice total trusts the client")
        report = self.run_compare(BASELINE, cur)
        self.assertIn("F-001", [f["id"] for f in report["new"]])
        self.assertIn("F-001", [f["id"] for f in report["not_reported"]])

    def test_dependency_advisory_change_is_not_the_same_finding(self):
        cur = copy.deepcopy(BASELINE)
        cur["findings"][4]["advisory_ids"] = ["GHSA-zzzz-yyyy-xxxx"]
        report = self.run_compare(BASELINE, cur)
        self.assertEqual([f["id"] for f in report["new"]], ["D-001"])
        self.assertEqual([f["id"] for f in report["not_reported"]], ["D-001"])

    def test_ruled_out_in_current_run(self):
        cur = copy.deepcopy(BASELINE)
        cur["findings"][1]["validation"] = {"verdict": "NotApplicable", "evidence": "limit enforced by the proxy"}
        report = self.run_compare(BASELINE, cur)
        self.assertEqual([(f["id"], f["verdict"]) for f in report["ruled_out"]], [("F-002", "NotApplicable")])

    def test_gate_counts_new_reopened_and_escalated_open_findings_only(self):
        report = self.run_compare(BASELINE, self.current(), "High")
        self.assertFalse(report["gate"]["passed"])
        self.assertEqual(sorted(report["gate"]["blocking"]), ["F-001", "F-003", "F-004"])
        cur = self.current()
        for f in cur["findings"]:
            f["status"] = "Accepted"
        self.assertTrue(self.run_compare(BASELINE, cur, "High")["gate"]["passed"])

    def test_gate_holds_a_regressed_fix(self):
        base = copy.deepcopy(BASELINE)
        base["findings"][0]["status"] = "Fixed"
        report = self.run_compare(base, BASELINE, "High")
        self.assertEqual(report["gate"]["blocking"], ["F-001"])
        self.assertEqual(report["summary"]["regressed"], 1)
        self.assertTrue(self.run_compare(base, BASELINE, "High")["persisting"][0]["changes"]["status"])

    def test_cli_exit_codes_and_outputs(self):
        base, cur = self.write("b.json", BASELINE), self.write("c.json", self.current())
        out_dir = self.tmp / "out"
        out_dir.mkdir()
        (out_dir / "findings.json").write_bytes(cur.read_bytes())
        md, js = self.tmp / "delta.md", self.tmp / "delta.json"
        cmd = [sys.executable, str(SCRIPTS / "compare.py"), str(base), str(out_dir),
               "--markdown", str(md), "--json", str(js), "--lang", "ja"]
        done = subprocess.run(cmd + ["--fail-on", "High"], capture_output=True, text=True)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("gate failed", done.stderr)
        self.assertIn("今回の診断で報告されなかった指摘", md.read_text(encoding="utf-8"))
        self.assertEqual(json.loads(js.read_text(encoding="utf-8"))["summary"]["new"], 1)
        self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
        bad = self.write("bad.json", {"meta": {}, "findings": []})
        self.assertEqual(subprocess.run([sys.executable, str(SCRIPTS / "compare.py"), str(base), str(bad)],
                                        capture_output=True).returncode, 2)

    def test_refuses_symlinked_output(self):
        base = self.write("b.json", BASELINE)
        target = self.tmp / "elsewhere.md"
        target.write_text("keep", encoding="utf-8")
        link = self.tmp / "link.md"
        link.symlink_to(target)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = compare.main([str(base), str(base), "--markdown", str(link)])
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_markdown_is_inert_and_masks_secrets(self):
        cur = copy.deepcopy(BASELINE)
        cur["findings"].append(finding("F-009", "Token api_key=sk_live_abcdefghijklmnop1234 <b>x</b> | y",
                                       "Medium", "src/x.py:1"))
        text = compare.markdown(self.run_compare(BASELINE, cur))
        self.assertNotIn("sk_live_abcdefghijklmnop1234", text)
        self.assertNotIn("<b>", text)
        self.assertIn("\\|", text)


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_ignores_id_and_line(self):
        a = finding("F-001", "Order detail lacks a tenant check", location="src/orders.py:42")
        b = finding("F-007", "Order detail lacks a tenant check", location="./src/orders.py:90")
        self.assertEqual(finding_keys.fingerprint(a), finding_keys.fingerprint(b))
        c = finding("F-001", "Order detail lacks a tenant check", location="src/other.py:42")
        self.assertNotEqual(finding_keys.fingerprint(a), finding_keys.fingerprint(c))

    def test_japanese_titles_have_similarity(self):
        self.assertGreater(finding_keys.title_similarity("注文詳細でテナント確認がない", "注文詳細のテナント確認が欠落"), 0.3)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-export-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        data = copy.deepcopy(BASELINE)
        data["findings"][1]["status"] = "Fixed"
        data["findings"][2]["status"] = "Accepted"
        data["findings"].append(finding("F-005", "=HYPERLINK(\"http://example.invalid\") in title", "Info",
                                        "platform runtime", category="Dependencies and platform",
                                        impact="password = 'hunter2hunter2'"))
        self.path = self.tmp / "findings.json"
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def run_export(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return export.main([*args])

    def test_sarif_structure_levels_suppressions_and_fingerprints(self):
        out = self.tmp / "r.sarif"
        self.assertEqual(self.run_export("sarif", str(self.path), "--out", str(out)), 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        results = {r["properties"]["findingId"]: r for r in run["results"]}
        # Fixed left out; the unlocated platform finding cannot be placed in a file.
        self.assertEqual(sorted(results), ["D-001", "F-001", "F-003", "F-004"])
        self.assertEqual(run["properties"]["unlocatedFindings"], ["F-005"])
        self.assertEqual(results["F-001"]["level"], "error")
        self.assertEqual(results["F-003"]["level"], "note")
        self.assertEqual(results["F-001"]["locations"][0]["physicalLocation"]["region"]["startLine"], 42)
        self.assertNotIn("suppressions", results["F-001"])
        self.assertEqual(results["F-003"]["suppressions"][0]["status"], "accepted")
        self.assertIn("FalsePositive", results["F-004"]["suppressions"][0]["justification"])
        rules = run["tool"]["driver"]["rules"]
        for r in run["results"]:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])
        f001_rule = rules[results["F-001"]["ruleIndex"]]
        self.assertEqual(f001_rule["properties"]["security-severity"], "8.0")
        self.assertEqual(f001_rule["helpUri"], "https://cwe.mitre.org/data/definitions/639.html")
        self.assertEqual(results["F-001"]["partialFingerprints"]["securityScanFinding/v1"],
                         finding_keys.fingerprint(BASELINE["findings"][0]))
        self.assertEqual(self.run_export("sarif", str(self.path), "--out", str(out), "--include-fixed"), 0)
        ids = [r["properties"]["findingId"] for r in json.loads(out.read_text())["runs"][0]["results"]]
        self.assertIn("F-002", ids)

    def test_sarif_never_emits_escaping_or_absolute_paths(self):
        for loc in ("../outside.py:3", "/etc/app.py:3", "C:/app.py:3"):
            self.assertIsNone(export.relative_uri(finding_keys.location({"location": loc})[0]), loc)
        self.assertEqual(export.relative_uri("src/a b.py"), "src/a%20b.py")

    def test_csv_neutralizes_formulas_and_masks_secrets(self):
        out = self.tmp / "f.csv"
        self.assertEqual(self.run_export("csv", str(self.path), "--out", str(out), "--bom"), 0)
        raw = out.read_bytes()
        self.assertTrue(raw.startswith("\ufeff".encode("utf-8")))
        rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
        self.assertEqual(len(rows), 6)
        row = next(r for r in rows if r["id"] == "F-005")
        self.assertTrue(row["title"].startswith("'="))
        self.assertNotIn("hunter2hunter2", out.read_text(encoding="utf-8-sig"))
        self.assertEqual(rows[0]["fingerprint"], finding_keys.fingerprint(BASELINE["findings"][0]))

    def test_issue_drafts_cover_open_included_findings_with_visibility(self):
        out = self.tmp / "issues"
        self.assertEqual(self.run_export("issues", str(self.path), "--out", str(out)), 0)
        names = sorted(p.name for p in out.iterdir())
        # Fixed (F-002), Accepted (F-003) and FalsePositive (F-004) get no draft.
        self.assertEqual(names, ["D-001.md", "F-001.md", "F-005.md", "index.md"])
        f001 = (out / "F-001.md").read_text(encoding="utf-8")
        self.assertIn("PRIVATE", f001)
        self.assertIn("[High] Order detail lacks a tenant check (F-001)", f001)
        self.assertIn("&lt;other tenant's order id&gt;", f001)
        self.assertNotIn("PRIVATE", (out / "F-005.md").read_text(encoding="utf-8"))
        self.assertNotIn("hunter2hunter2", (out / "F-005.md").read_text(encoding="utf-8"))
        # A non-empty directory is refused, so earlier drafts are never mixed in.
        self.assertEqual(self.run_export("issues", str(self.path), "--out", str(out)), 2)
        ja = self.tmp / "ja"
        self.assertEqual(self.run_export("issues", str(self.path), "--out", str(ja), "--lang", "ja", "--all"), 0)
        self.assertIn("F-002.md", [p.name for p in ja.iterdir()])
        self.assertIn("公開範囲：非公開", (ja / "F-001.md").read_text(encoding="utf-8"))

    def test_unsafe_ids_never_become_paths(self):
        data = {"meta": META, "findings": [finding("../../escape", "Path-like id", "Low", "src/a.py:1"),
                                           finding(".hidden", "Dot id", "Low", "src/b.py:1")]}
        path = self.tmp / "odd.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        out = self.tmp / "odd"
        self.assertEqual(self.run_export("issues", str(path), "--out", str(out)), 0)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["finding-001.md", "finding-002.md", "index.md"])
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["findings.json", "odd", "odd.json"])

    def test_id_selection_and_unknown_ids(self):
        out = self.tmp / "one.csv"
        self.assertEqual(self.run_export("csv", str(self.path), "--out", str(out), "--id", "F-001"), 0)
        self.assertEqual(len(out.read_text(encoding="utf-8").strip().splitlines()), 2)
        self.assertEqual(self.run_export("csv", str(self.path), "--out", str(out), "--id", "F-999"), 2)

    def test_invalid_record_and_symlink_targets_exit_2(self):
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"meta": META, "findings": [{"id": "F-001"}]}), encoding="utf-8")
        self.assertEqual(self.run_export("csv", str(bad), "--out", str(self.tmp / "x.csv")), 2)
        target = self.tmp / "keep.txt"
        target.write_text("keep", encoding="utf-8")
        link = self.tmp / "link.sarif"
        os.symlink(target, link)
        self.assertEqual(self.run_export("sarif", str(self.path), "--out", str(link)), 2)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_every_sample_exports(self):
        for sample in sorted((REPO / "examples").glob("findings*.json")):
            with self.subTest(sample=sample.name):
                out = self.tmp / sample.stem
                self.assertEqual(self.run_export("sarif", str(sample), "--out", str(out) + ".sarif"), 0)
                self.assertEqual(self.run_export("csv", str(sample), "--out", str(out) + ".csv"), 0)
                self.assertEqual(self.run_export("issues", str(sample), "--out", str(out)), 0)


if __name__ == "__main__":
    unittest.main()
