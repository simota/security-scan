"""triage.py: recording decisions, carrying them to a rescan, the remediation
summary, and how compare/export/render/deps_scan treat a triage record."""
from __future__ import annotations

import contextlib
import copy
import csv
import datetime
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))

import compare  # noqa: E402
import deps_scan  # noqa: E402
import export  # noqa: E402
import findings as findings_tool  # noqa: E402
import render  # noqa: E402
import report_schema  # noqa: E402
import triage  # noqa: E402

META = {"project": "demo", "date": "2026-10-07", "assessor": "Claude Code (test)"}
D = "2026-11-01"


def finding(fid, title, severity="High", location="src/orders.py:42", **extra):
    base = {"id": fid, "title": title, "severity": severity, "confidence": "Confirmed",
            "category": "Actor and tenant", "location": location, "actor": "any signed-in user",
            "request": "GET /orders/{id} with <other tenant's order id>",
            "impact": "reads another tenant's order", "fix": "scope the query by tenant"}
    base.update(extra)
    return base


RECORD = {"meta": META, "findings": [
    finding("F-001", "Order detail lacks a tenant check", cwe="CWE-639"),
    finding("F-002", "Page size has no upper bound", "Medium", "src/api/util.py:7", category="Availability"),
    finding("F-003", "Debug output enabled", "Low", "deploy/php.ini:9", category="Configuration"),
    finding("F-004", "Report export reads any tenant", "High", "src/api/reports.py:88",
            validation={"verdict": "FalsePositive", "evidence": "the query is tenant scoped at reports.py:80"}),
]}


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = triage.main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class TriageCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-triage-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, data):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def read(self, path):
        return {f["id"]: f for f in json.loads(path.read_text(encoding="utf-8"))["findings"]}

    def accept(self, path, ident="F-001", review="2026-12-31", *extra):
        return run("set", path, ident, "--status", "Accepted", "--reason", "only reachable from the admin VPN",
                   "--review-by", review, "--date", D, *extra)


class RecordTests(TriageCase):
    def test_accept_records_status_reason_owner_and_review_date(self):
        path = self.write("findings.json", RECORD)
        code, out, err = self.accept(path, "F-001", "2026-12-31", "--owner", "payments",
                                     "--ticket", "https://tracker.example.com/SEC-1")
        self.assertEqual(code, 0, err)
        f = self.read(path)["F-001"]
        self.assertEqual(f["status"], "Accepted")
        self.assertEqual(f["triage"], {"status": "Accepted", "decided": D, "reason": "only reachable from the admin VPN",
                                       "owner": "payments", "review_by": "2026-12-31",
                                       "ticket": "https://tracker.example.com/SEC-1"})
        # Verdict and evidence are untouched.
        self.assertNotIn("validation", f)

    def test_accept_requires_reason_and_review_date(self):
        path = self.write("findings.json", RECORD)
        before = path.read_bytes()
        code, _, err = run("set", path, "F-001", "--status", "Accepted", "--date", D)
        self.assertEqual(code, 1)
        self.assertIn("needs --reason", err)
        self.assertIn("needs --review-by", err)
        self.assertEqual(path.read_bytes(), before)

    def test_fixed_needs_reason_and_reopen_needs_reason(self):
        path = self.write("findings.json", RECORD)
        self.assertEqual(run("set", path, "F-001", "--status", "Fixed", "--date", D)[0], 1)
        self.assertEqual(run("set", path, "F-001", "--status", "Fixed", "--reason", "commit abc123", "--date", D)[0], 0)
        code, _, err = run("set", path, "F-001", "--status", "Open", "--date", D)
        self.assertEqual(code, 1)
        self.assertIn("reopening a Fixed finding needs --reason", err)

    def test_review_date_rules(self):
        path = self.write("findings.json", RECORD)
        code, _, err = self.accept(path, "F-001", "2026-10-01")
        self.assertEqual(code, 1)
        self.assertIn("before the decision date", err)
        code, _, err = run("set", path, "F-002", "--owner", "a", "--review-by", "2026-12-01", "--date", D)
        self.assertEqual(code, 1)
        self.assertIn("applies to Accepted only", err)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            triage.main(["set", str(path), "F-001", "--review-by", "2026-02-30"])

    def test_assignment_keeps_status_and_history_keeps_previous_decision(self):
        path = self.write("findings.json", RECORD)
        self.assertEqual(run("set", path, "F-002", "--owner", "alice", "--ticket",
                             "https://tracker.example.com/SEC-2", "--date", D)[0], 0)
        self.assertEqual(run("set", path, "F-002", "--status", "Fixed", "--reason", "PR 41", "--date", "2026-11-03")[0], 0)
        f = self.read(path)["F-002"]
        self.assertEqual(f["status"], "Fixed")
        # Owner and ticket carry over; the earlier assignment is history.
        self.assertEqual(f["triage"]["owner"], "alice")
        self.assertEqual(f["triage"]["ticket"], "https://tracker.example.com/SEC-2")
        self.assertEqual(f["triage"]["history"], [{"status": "Open", "decided": D, "owner": "alice",
                                                   "ticket": "https://tracker.example.com/SEC-2"}])
        self.assertEqual(run("set", path, "F-002", "--owner", "", "--reason", "handed over", "--date", "2026-11-04")[0], 0)
        self.assertNotIn("owner", self.read(path)["F-002"]["triage"])

    def test_unchanged_decision_is_refused(self):
        path = self.write("findings.json", RECORD)
        self.assertEqual(run("set", path, "F-002", "--owner", "alice", "--date", D)[0], 0)
        code, _, err = run("set", path, "F-002", "--owner", "alice", "--date", D)
        self.assertEqual(code, 1)
        self.assertIn("nothing to record", err)
        code, _, err = run("set", path, "F-001", "--status", "Open", "--date", D)
        self.assertEqual(code, 1)
        self.assertIn("nothing to record", err)

    def test_bulk_set_is_all_or_nothing(self):
        path = self.write("findings.json", RECORD)
        before = path.read_bytes()
        code, _, err = run("set", path, "F-001", "F-004", "F-999", "--owner", "bob", "--date", D)
        self.assertEqual(code, 1)
        self.assertIn("F-004: ruled out (FalsePositive)", err)
        self.assertIn("F-999: no such finding", err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(run("set", path, "F-001", "F-002", "--owner", "bob", "--date", D)[0], 0)
        self.assertEqual({k: v.get("triage", {}).get("owner") for k, v in self.read(path).items()},
                         {"F-001": "bob", "F-002": "bob", "F-003": None, "F-004": None})

    def test_text_checks_refuse_payloads_secrets_and_bad_tickets(self):
        path = self.write("findings.json", RECORD)
        for args, expected in (
                (("--reason", "<script>alert(1)</script>"), "literal attack string"),
                (("--reason", "rotated ghp_" + "a" * 36), "secret value"),
                (("--owner", "two\nlines"), "one line"),
                (("--ticket", "javascript:alert(1)"), "F-001.ticket"),
                (("--ticket", "ftp://tracker.example.com/1"), "http(s) URL"),
                (("--ticket", "https://user:pw@tracker.example.com/1"), "without credentials")):
            with self.subTest(args=args):
                code, _, err = run("set", path, "F-001", "--status", "Fixed", "--reason", "x", *args, "--date", D) \
                    if args[0] != "--reason" else run("set", path, "F-001", "--status", "Fixed", *args, "--date", D)
                self.assertEqual(code, 1, err)
                self.assertIn(expected, err)

    def test_apply_decisions_file(self):
        path = self.write("findings.json", RECORD)
        decisions = self.write("decisions.json", {"decisions": [
            {"id": "F-001", "status": "Accepted", "reason": "internal only", "review_by": "2027-01-31"},
            {"id": "F-002", "owner": "carol"}]})
        code, out, err = run("apply", path, decisions, "--date", D)
        self.assertEqual(code, 0, err)
        found = self.read(path)
        self.assertEqual(found["F-001"]["status"], "Accepted")
        self.assertEqual(found["F-002"]["triage"]["owner"], "carol")
        bad = self.write("bad.json", {"decisions": [{"id": "F-001", "verdict": "Valid"}]})
        self.assertEqual(run("apply", path, bad)[0], 2)

    def test_output_directory_is_accepted_as_findings_path(self):
        path = self.write("out/findings.json", RECORD)
        self.assertEqual(run("set", path.parent, "F-002", "--owner", "dan", "--date", D)[0], 0)
        self.assertEqual(self.read(path)["F-002"]["triage"]["owner"], "dan")


class SchemaTests(TriageCase):
    def validate(self, f):
        return report_schema.validate_data({"meta": META, "findings": [f]})

    def test_status_must_match_triage(self):
        f = finding("F-001", "x", status="Open",
                    triage={"status": "Accepted", "decided": D, "reason": "r", "review_by": "2026-12-01"})
        with self.assertRaisesRegex(report_schema.SchemaError, "does not match the finding's status"):
            self.validate(f)

    def test_accepted_needs_reason_and_review_date(self):
        f = finding("F-001", "x", status="Accepted", triage={"status": "Accepted", "decided": D})
        with self.assertRaisesRegex(report_schema.SchemaError, "reason: required"):
            self.validate(f)
        f["triage"]["reason"] = "r"
        with self.assertRaisesRegex(report_schema.SchemaError, "review_by: required"):
            self.validate(f)

    def test_unknown_fields_and_bad_values(self):
        for triage_value, message in (
                ({"status": "Open", "decided": D, "verdict": "Valid"}, "unsupported fields"),
                ({"status": "Open", "decided": "2026-13-01"}, "not a calendar date"),
                ({"status": "Open", "decided": D, "ticket": "ftp://x"}, "http"),
                ({"status": "Open", "decided": D, "history": {}}, "history: must be a list"),
                ("Accepted", "must be an object")):
            with self.subTest(value=triage_value):
                with self.assertRaisesRegex(report_schema.SchemaError, message):
                    self.validate(finding("F-001", "x", triage=triage_value))

    def test_legacy_accepted_without_triage_stays_valid(self):
        self.validate(finding("F-001", "x", status="Accepted"))

    def test_merge_fragment_cannot_write_triage_or_desync_status(self):
        path = self.write("findings.json", RECORD)
        self.assertEqual(self.accept(path)[0], 0)
        fragment = self.write("frag.json", {"findings": [{"id": "F-002", "triage": {"status": "Open", "decided": D}}]})
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(findings_tool.main(["merge", str(path), str(fragment)]), 1)
        self.assertIn("triage.py", err.getvalue())
        fragment = self.write("frag2.json", {"findings": [{"id": "F-001", "status": "Open"}]})
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(findings_tool.main(["merge", str(path), str(fragment)]), 2)
        self.assertIn("record status changes with triage.py", err.getvalue())

    def test_renumber_keeps_carried_baseline_id(self):
        data = copy.deepcopy(RECORD)
        data["findings"][2]["triage"] = {"status": "Open", "decided": D, "owner": "x", "reason": "see F-003",
                                         "carried_from": {"baseline_id": "F-001", "date": "2026-09-01"}}
        moved = findings_tool.renumber(copy.deepcopy(data), {"F-001": "F-009", "F-003": "F-007"})
        record = next(f for f in moved["findings"] if f["id"] == "F-007")["triage"]
        self.assertEqual(record["carried_from"]["baseline_id"], "F-001")
        self.assertEqual(record["reason"], "see F-007")


class CarryTests(TriageCase):
    def rescan(self):
        cur = copy.deepcopy(RECORD)
        for f in cur["findings"]:
            f.pop("status", None)
            f.pop("triage", None)
        # A new run numbers and words its findings differently.
        f = cur["findings"]
        f[0].update(id="F-002", title="Order detail endpoint lacks tenant check", location="src/orders.py:45")
        f[1].update(id="F-003")
        f[2].update(id="F-001")
        cur["meta"] = {**META, "date": "2026-11-06"}
        return cur

    def test_carries_unexpired_acceptance_and_assignments(self):
        base = self.write("a/findings.json", RECORD)
        self.assertEqual(self.accept(base, "F-001", "2026-12-31", "--owner", "payments")[0], 0)
        self.assertEqual(run("set", base, "F-002", "--owner", "alice", "--date", D)[0], 0)
        cur = self.write("b/findings.json", self.rescan())
        code, out, err = run("carry", base.parent, cur.parent, "--as-of", "2026-11-07")
        self.assertEqual(code, 0, err)
        found = self.read(cur)
        self.assertEqual(found["F-002"]["status"], "Accepted")
        self.assertEqual(found["F-002"]["triage"]["review_by"], "2026-12-31")
        self.assertEqual(found["F-002"]["triage"]["carried_from"],
                         {"baseline_id": "F-001", "date": "2026-10-07", "project": "demo"})
        self.assertEqual(found["F-003"]["status"], "Open")
        self.assertEqual(found["F-003"]["triage"]["owner"], "alice")
        self.assertNotIn("triage", found["F-001"])
        # Verdicts are never carried.
        self.assertEqual(found["F-004"]["validation"]["verdict"], "FalsePositive")

    def test_expired_acceptance_raised_severity_and_regressed_fix_are_not_carried(self):
        base = self.write("a/findings.json", RECORD)
        self.assertEqual(self.accept(base, "F-001", "2026-11-05", "--owner", "payments")[0], 0)
        self.assertEqual(self.accept(base, "F-003", "2027-01-31")[0], 0)
        self.assertEqual(run("set", base, "F-002", "--status", "Fixed", "--reason", "PR 9", "--date", D)[0], 0)
        cur_data = self.rescan()
        cur_data["findings"][2]["severity"] = "Medium"  # F-003 -> now F-001, raised from Low
        cur = self.write("b/findings.json", cur_data)
        plan_path = self.tmp / "plan.json"
        code, out, err = run("carry", base, cur, "--as-of", "2026-11-07", "--json", plan_path)
        self.assertEqual(code, 0, err)
        plan = json.loads(plan_path.read_text())
        self.assertEqual({(i["id"], i["reason"]) for i in plan["not_carried"]},
                         {("F-002", "acceptance_expired"), ("F-001", "severity_raised"), ("F-003", "regressed_fix")})
        found = self.read(cur)
        self.assertEqual({k: f.get("status", "Open") for k, f in found.items()},
                         {"F-001": "Open", "F-002": "Open", "F-003": "Open", "F-004": "Open"})
        # Ownership of the expired acceptance stays with its owner for the new decision.
        self.assertEqual(found["F-002"]["triage"]["owner"], "payments")

    def test_current_decisions_are_kept_and_dry_run_writes_nothing(self):
        base = self.write("a/findings.json", RECORD)
        self.assertEqual(self.accept(base)[0], 0)
        cur = self.write("b/findings.json", self.rescan())
        self.assertEqual(run("set", cur, "F-002", "--owner", "zed", "--date", D)[0], 0)
        before = cur.read_bytes()
        code, out, _ = run("carry", base, cur, "--as-of", "2026-11-07", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("kept     F-002", out)
        self.assertEqual(cur.read_bytes(), before)


class SummaryTests(TriageCase):
    def test_summary_lists_unassigned_overdue_due_and_owners(self):
        data = copy.deepcopy(RECORD)
        data["findings"].append(finding("F-005", "Legacy acceptance", "Medium", "src/x.py:1", status="Accepted"))
        path = self.write("findings.json", data)
        self.assertEqual(self.accept(path, "F-001", "2026-11-05")[0], 0)
        self.assertEqual(self.accept(path, "F-003", "2026-11-20")[0], 0)
        out_json = self.tmp / "summary.json"
        code, out, err = run("summary", path, "--as-of", "2026-11-07", "--json", out_json, "--fail-on-overdue")
        self.assertEqual(code, 1)
        self.assertIn("F-001", err)
        report = json.loads(out_json.read_text())
        self.assertEqual([r["id"] for r in report["unassigned"]], ["F-002"])
        self.assertEqual([r["id"] for r in report["overdue"]], ["F-001"])
        self.assertEqual([r["id"] for r in report["due_soon"]], ["F-003"])
        self.assertEqual([r["id"] for r in report["unrecorded"]], ["F-005"])
        self.assertEqual(report["by_status"]["Accepted"], {"High": 1, "Medium": 1, "Low": 1, "Info": 0})
        self.assertEqual(report["owners"], [{"owner": "", "open": 1, "high_medium": 1}])
        code, out, _ = run("summary", path, "--as-of", "2026-11-01", "--lang", "ja")
        self.assertEqual(code, 0)
        self.assertIn("対応状況", out)


class IntegrationTests(TriageCase):
    def test_compare_gate_blocks_expired_acceptance(self):
        base = copy.deepcopy(RECORD)
        base["findings"][0]["status"] = "Accepted"
        base["findings"][0]["triage"] = {"status": "Accepted", "decided": D, "reason": "r", "review_by": "2026-11-05"}
        cur = copy.deepcopy(base)
        b = compare.read_record(self.write("b.json", base))
        c = compare.read_record(self.write("c.json", cur))
        report = compare.compare(b, c, "High", datetime.date(2026, 11, 7))
        self.assertFalse(report["gate"]["passed"])
        self.assertEqual(report["gate"]["blocking"], ["F-001"])
        self.assertEqual(report["summary"]["acceptance_expired"], 1)
        self.assertIn("acceptance", compare.markdown(report))
        report = compare.compare(b, c, "High", datetime.date(2026, 11, 1))
        self.assertTrue(report["gate"]["passed"])
        # Fresh rescan (status Open) after the baseline acceptance expired also blocks.
        cur["findings"][0].pop("triage")
        cur["findings"][0]["status"] = "Open"
        c = compare.read_record(self.write("c2.json", cur))
        self.assertEqual(compare.compare(b, c, "High", datetime.date(2026, 11, 7))["gate"]["blocking"], ["F-001"])
        self.assertTrue(compare.compare(b, c, "High", datetime.date(2026, 11, 1))["gate"]["passed"])

    def test_exports_carry_the_decision(self):
        path = self.write("findings.json", RECORD)
        self.assertEqual(self.accept(path, "F-001", "2026-11-05", "--owner", "payments")[0], 0)
        data = export.read_record(path)
        doc, _ = export.sarif(data, data["findings"], as_of=datetime.date(2026, 11, 1))
        result = next(r for r in doc["runs"][0]["results"] if r["properties"]["findingId"] == "F-001")
        self.assertIn("only reachable from the admin VPN", result["suppressions"][0]["justification"])
        self.assertIn("review by 2026-11-05", result["suppressions"][0]["justification"])
        doc, _ = export.sarif(data, data["findings"], as_of=datetime.date(2026, 11, 7))
        result = next(r for r in doc["runs"][0]["results"] if r["properties"]["findingId"] == "F-001")
        self.assertNotIn("suppressions", result)
        self.assertTrue(result["properties"]["acceptanceExpired"])
        rows = list(csv.DictReader(io.StringIO(export.csv_text(data["findings"]))))
        row = next(r for r in rows if r["id"] == "F-001")
        self.assertEqual((row["owner"], row["review_by"], row["decided"]), ("payments", "2026-11-05", D))
        self.assertIn("| Owner | payments |", export.issue(data, data["findings"][0], "en"))

    def test_render_shows_triage_in_both_outputs(self):
        path = self.write("findings.json", RECORD)
        self.assertEqual(self.accept(path, "F-001", "2026-12-31", "--owner", "payments",
                                     "--ticket", "https://tracker.example.com/SEC-1#L2")[0], 0)
        data = report_schema.load(path)
        for lang in ("en", "ja"):
            L = render.LABELS[lang]
            dashboard = render.render_dashboard(copy.deepcopy(data), L, lang)
            assessment = render.render_assessment_html(copy.deepcopy(data), L, lang)
            self.assertIn('"owner": "payments"', dashboard)
            self.assertIn("payments", assessment)
            self.assertIn(L["triage"], assessment)
            self.assertIn("https://tracker.example.com/SEC-1#L2", assessment)
        # A credential-bearing ticket link is refused before it is recorded.
        code, _, err = run("set", path, "F-002", "--owner", "x", "--ticket",
                           "https://tracker.example.com/1?private_token=" + "a" * 24, "--date", D)
        self.assertEqual(code, 1, err)

    def test_deps_rescan_keeps_triage_of_the_same_advisory(self):
        dep = finding("D-001", "Known vulnerability in left-pad", "High", "package-lock.json:18",
                      package="left-pad", version="1.0.0", advisory_ids=["GHSA-aaaa-bbbb-cccc"],
                      status="Accepted", triage={"status": "Accepted", "decided": D, "reason": "not reachable",
                                                 "review_by": "2027-01-01"})
        data = copy.deepcopy(RECORD)
        data["findings"].append(dep)
        path = self.write("findings.json", data)
        fresh = copy.deepcopy(dep)
        for key in ("status", "triage"):
            fresh.pop(key)
        deps_scan.merge_into(path, {"findings": [fresh], "not_run": []})
        found = self.read(path)["D-001"]
        self.assertEqual(found["status"], "Accepted")
        self.assertEqual(found["triage"]["reason"], "not reachable")
        report_schema.load(path)


if __name__ == "__main__":
    unittest.main()
