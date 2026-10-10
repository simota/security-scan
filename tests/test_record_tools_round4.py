"""Round-4 regressions: excerpt size cap, secret capture refusal, scanner-owned D-*,
unreviewed scanner findings, workflow actors and gates, limitation removal and
contract lines, headline counts, action labels, hints and error messages."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_run_contract import git
from test_security_scan import import_module

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/security-scan"
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))
import render  # noqa: E402
import verification  # noqa: E402
import verification_workflow as workflow  # noqa: E402

META = {"project": "demo", "date": "2026-10-10", "assessor": "Test host (model)"}
FINDING = {"id": "F-001", "title": "Order detail lacks an owner check", "severity": "High",
           "confidence": "Confirmed", "category": "Actor and tenant", "location": "src/orders.py:2",
           "actor": "any signed-in user", "request": "GET /orders/{order_id}",
           "impact": "reads another user's order", "fix": "scope the query to the caller", "status": "Open",
           "validation": {"verdict": "Valid", "method": "review", "evidence": "handler reads by id only"}}
DEP = {"id": "D-001", "title": "Synthetic package has a known advisory", "severity": "Medium",
       "confidence": "Confirmed", "category": "Dependencies and platform", "location": "package-lock.json:1",
       "actor": "", "request": "", "impact": "synthetic", "fix": "upgrade", "status": "Open",
       "validation": {"verdict": "Unverified", "method": "auto", "evidence": "scanner"}}
NO_LEDGER = "invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)"


def sample():
    return json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))


def quiet(function, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = function(*args)
    return code, out.getvalue(), err.getvalue()


class Temp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-round4-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)


class SourceExcerptTests(Temp):
    def test_huge_source_file_gets_no_excerpt(self):
        (self.tmp / "src").mkdir()
        small, huge = self.tmp / "src/orders.py", self.tmp / "src/huge.py"
        small.write_text("a = 1\nb = 2\n")
        with huge.open("wb") as stream:
            stream.write(b"a = 1\nb = 2\n")
            stream.truncate(16 * 1024 * 1024 + 1)  # Sparse: cheap on disk, over the cap.
        data = {"meta": dict(META), "findings": [dict(FINDING), dict(FINDING, id="F-002", location="src/huge.py:2")]}
        render.attach_sources(data, self.tmp)
        self.assertIn("snippet", data["findings"][0])
        self.assertNotIn("snippet", data["findings"][1])


class SecretCaptureTests(Temp):
    @classmethod
    def setUpClass(cls):
        cls.capture = import_module(SCRIPTS / "evidence_capture.py", "round4_capture")

    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "app"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src/orders.py").write_text("def show(order_id):\n    return Order.get(order_id)\n")
        # Synthetic, not a real credential.
        (self.repo / "src/config.js").write_text('const API_TOKEN = "synthetic-not-a-real-token-0000";\n')
        (self.repo / "src/db.py").write_text('DSN = "postgres://app:synthetic-pw@db.invalid/app"\n')
        (self.repo / "settings.yml").write_text("password: synthetic-value\n")
        (self.repo / "src/login.js").write_text("const password = req.body.password;\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "init")
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.findings = self.out / "findings.json"
        self.findings.write_text(json.dumps({"meta": META, "findings": [FINDING]}))

    def test_secret_looking_file_is_refused_and_not_copied(self):
        for path in ("src/config.js", "src/db.py", "settings.yml"):
            with self.subTest(path=path):
                before = self.findings.read_bytes()
                with self.assertRaisesRegex(self.capture.CaptureError, "secret-looking value; cite it by location"):
                    self.capture.capture(self.repo, self.findings, ["src/orders.py", path])
                self.assertEqual(self.findings.read_bytes(), before)
                self.assertFalse((self.out / "evidence").exists())

    def test_ordinary_auth_code_is_still_captured(self):
        mapping = self.capture.capture(self.repo, self.findings, ["src/orders.py", "src/login.js"])
        self.assertEqual(sorted(mapping), ["src/login.js", "src/orders.py"])


class FindingsMergeTests(Temp):
    @classmethod
    def setUpClass(cls):
        cls.tool = import_module(SCRIPTS / "findings.py", "round4_findings")

    def setUp(self):
        super().setUp()
        self.out = self.tmp / "findings.json"

    def fragment(self, data, name="frag.json"):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def merge(self, *fragments):
        return quiet(self.tool.main, ["merge", str(self.out), *fragments])

    def test_d_findings_accept_only_review_fields(self):
        # deps_scan.py --into writes D-* directly; stand in for it with the file itself.
        self.out.write_text(json.dumps({"meta": META, "findings": [FINDING, DEP]}))
        before = self.out.read_bytes()
        for record in ({"id": "D-001", "severity": "Info", "title": "benign"},
                       {"id": "D-001", "previous_validation": {"verdict": "Valid"}},
                       {"id": "D-002", "validation": {"verdict": "Unverified", "method": "auto", "evidence": "x"}}):
            with self.subTest(record=record):
                code, _, err = self.merge(self.fragment({"findings": [record]}))
                self.assertEqual(code, 1, err)
                self.assertIn("deps_scan.py", err)
                self.assertEqual(self.out.read_bytes(), before)
        review = {"id": "D-001", "validation": {"verdict": "Valid", "method": "manual", "evidence": "import reached"}}
        self.assertEqual(self.merge(self.fragment({"findings": [review]}))[0], 0)
        dep = json.loads(self.out.read_text())["findings"][1]
        self.assertEqual((dep["severity"], dep["validation"]["verdict"]), ("Medium", "Valid"))

    def test_limitations_can_be_removed_exactly(self):
        self.assertEqual(self.merge(self.fragment({"meta": META, "limitations": ["keep", "drop"]}))[0], 0)
        before = self.out.read_bytes()
        code, _, err = self.merge(self.fragment({"remove": {"limitations": ["drp"]}}))
        self.assertEqual(code, 1)
        self.assertIn("'drp' is not recorded", err)
        self.assertEqual(self.out.read_bytes(), before)
        self.assertEqual(self.merge(self.fragment({"remove": {"limitations": ["drop"]}, "limitations": ["new"]}))[0], 0)
        self.assertEqual(json.loads(self.out.read_text())["limitations"], ["keep", "new"])
        self.assertEqual(self.merge(self.fragment({"remove": {"findings": ["F-001"]}}))[0], 1)

    def test_deep_fragment_reports_nesting_depth_on_every_python(self):
        deep = self.tmp / "deep.json"
        deep.write_text("[" * 5000 + "]" * 5000)
        code, _, err = self.merge(str(deep))
        self.assertEqual(code, 2)
        self.assertIn("nesting deeper than 200 levels", err)
        # Python 3.9's decoder raises RecursionError itself; the message must not change.
        with patch.object(self.tool.json, "loads",
                          side_effect=RecursionError("maximum recursion depth exceeded while decoding")):
            code, _, err = self.merge(str(deep))
        self.assertEqual(code, 2)
        self.assertIn("nesting deeper than 200 levels", err)
        self.assertNotIn("maximum recursion", err)


class ScannerVerificationTests(unittest.TestCase):
    def data(self):
        data = sample()
        dep = dict(copy.deepcopy(data["findings"][0]), **copy.deepcopy(DEP))
        dep.pop("verification")
        dep.pop("remediation", None)
        data["findings"].append(dep)
        return data

    def test_fresh_d_finding_in_version_two_is_unreviewed_not_legacy(self):
        data = self.data()
        state = verification.derive_verification(data)["D-001"]
        self.assertEqual((state["level"], state["gaps"]), ("incomplete", ["scanner_unreviewed"]))
        for lang, text in (("en", "Scanner finding — not yet reviewed"), ("ja", "スキャナー検出・未レビュー")):
            with self.subTest(lang=lang):
                L = render.LABELS[lang]
                view = render.verification_view(data, data["findings"][1], state, lang)
                self.assertEqual(view["level"], L["v_incomplete"])
                self.assertTrue(any(text in str(gap) for gap in view["gaps"]), view["gaps"])
                page = render.render_dashboard(load(data), L, lang)
                self.assertIn(text, page)
                self.assertNotIn(L["v_legacy"], render.render_assessment_html(load(data), L, lang))

    def test_legacy_labels_stay_for_old_records(self):
        data = self.data()
        data.pop("schema_version")
        self.assertEqual(verification.derive_verification(data)["D-001"]["level"], "legacy")
        data = self.data()
        data["findings"][0].pop("verification")
        data["findings"][0].pop("remediation", None)
        state = verification.derive_verification(data)["F-001"]
        self.assertEqual((state["level"], state["gaps"][0]), ("legacy", "legacy_details_missing"))


def load(data):
    return render.validate_data(copy.deepcopy(data))


class HeadlineTests(unittest.TestCase):
    def data(self):
        data = sample()
        first = data["findings"][0]
        first["validation"] = {"verdict": "Unverified", "method": "review", "evidence": "pending"}
        first.pop("remediation", None)
        first["status"] = "Open"
        second = dict(copy.deepcopy(first), id="F-002", validation={"verdict": "Valid", "method": "review",
                                                                    "evidence": "read"})
        second.pop("verification")
        data["findings"].append(second)
        return data

    def test_assessment_and_dashboard_state_both_counts_grammatically(self):
        data = self.data()
        page = render.render_assessment_html(load(data), render.LABELS["en"], "en")
        self.assertIn("1 High finding remains Unverified. 1 High finding has a recorded verdict but "
                      "insufficient verification. 2 findings are open:", page)
        self.assertNotIn("1 High findings", page)
        dashboard = render.render_dashboard(load(data), render.LABELS["en"], "en")
        self.assertIn("1 included finding is Unverified, including 1 High. 1 High finding has a recorded "
                      "verdict but insufficient verification.", dashboard)
        ja = render.render_assessment_html(load(data), render.LABELS["ja"], "ja")
        self.assertIn("重大度 High のうち1件が Unverified（未検証）です。判定は記録済みでも検証根拠が不足している "
                      "High の指摘は1件です。未対応は2件で、", ja)
        self.assertIn("判定は記録済みでも検証根拠が不足している High の指摘が 1 件あります。",
                      render.render_dashboard(load(data), render.LABELS["ja"], "ja"))
        data["findings"].append(dict(copy.deepcopy(data["findings"][1]), id="F-003"))
        page = render.render_assessment_html(load(data), render.LABELS["en"], "en")
        self.assertIn("2 High findings have a recorded verdict but insufficient verification.", page)

    def test_one_label_per_language_for_verify_first(self):
        for lang, text in (("en", "Verify first"), ("ja", "先に検証する")):
            with self.subTest(lang=lang):
                self.assertEqual(render.LABELS[lang]["verify_first"], text)
                self.assertEqual(render.ASSESSMENT_LABELS[lang]["a_verify_first"], text)


class HintTests(Temp):
    @classmethod
    def setUpClass(cls):
        cls.contract = import_module(SCRIPTS / "contract_check.py", "round4_contract")

    def test_missing_outputs_and_no_pdf_engine_name_repo_and_fallback(self):
        problems = self.contract.check({"findings": [], "limitations": [NO_LEDGER]}, self.tmp)
        hints = [p for p in problems if "assessment.pdf missing" in p or "dashboard.html missing" in p]
        self.assertEqual(len(hints), 2)
        self.assertTrue(all("--repo <repo>" in p for p in hints), hints)
        path = self.tmp / "findings.json"
        path.write_text(json.dumps(sample()))
        with patch.object(render, "to_pdf", return_value=None):
            code, _, err = quiet(render.main, [str(path), "--out", str(self.tmp / "out")])
        self.assertEqual(code, 3)
        self.assertIn("--repo", err)
        self.assertIn("assessment.pdf not produced: no PDF engine", err)
        skill = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertRegex(skill, r"merge the limitation \"assessment.pdf not produced: no PDF engine\".*"
                                r"re-run `render.py --repo <repo> --no-pdf`, then `contract_check.py <out> --no-pdf`")

    def test_required_limitation_lines(self):
        def limits(data, pdf):
            return [p for p in self.contract.check(data, self.tmp, pdf=pdf) if p.startswith("limitations:")]
        self.assertEqual(len(limits({"findings": []}, False)), 2)
        self.assertEqual(limits({"findings": [], "limitations": [NO_LEDGER, "assessment.pdf not produced: "
                                                                           "no PDF engine"]}, False), [])
        self.assertEqual(limits({"findings": [], "limitations": [NO_LEDGER]}, True), [])
        contradictory = limits({"findings": [], "invariant_ledger": {}, "limitations": [NO_LEDGER]}, True)
        self.assertEqual(len(contradictory), 1)
        self.assertIn("invariant_ledger is recorded", contradictory[0])
        self.assertEqual(limits({"findings": [], "invariant_ledger": {}}, True), [])


class WorkflowTests(Temp):
    def setUp(self):
        super().setUp()
        self.data = sample()
        self.finding = self.data["findings"][0]
        self.reference = copy.deepcopy(self.finding["verification"])
        self.finding.pop("verification")
        self.finding.pop("remediation")
        self.finding.update(status="Open", confidence="Suspected")
        self.finding["validation"] = {"verdict": "Unverified", "evidence": "", "method": ""}

    def output(self, actor, status="complete"):
        state = workflow.derive_workflow(self.data, self.finding)
        stage = state["next_stage"]
        output = dict(stage=stage, actor=actor, status=status, summary="Synthetic observations only.",
                      evidence_ids=["source-before"], input_digest=state["input_digest"])
        if status == "complete":
            if stage == "conditions":
                output.update(claims=copy.deepcopy(self.reference["claims"]),
                              environment=copy.deepcopy(self.reference["environment"]))
            elif stage == "falsification":
                reviews = copy.deepcopy(self.reference["reviews"])
                reviews[0]["reviewer"] = actor
                output.update(checks=copy.deepcopy(self.reference["falsification"]), reviews=reviews)
            else:
                output.update(validation={"verdict": "Valid", "method": "Synthetic review",
                                          "evidence": "Pinned synthetic evidence."}, run_ids=[])
        return output

    def test_one_actor_may_record_a_blocked_falsification(self):
        workflow.initialize(self.data, "F-001", "coordinator")
        workflow.submit(self.data, "F-001", self.output("author"))
        for status in ("held", "error", "unknown"):
            with self.subTest(status=status):
                workflow.submit(self.data, "F-001", self.output(" AUTHOR ", status))
                self.assertEqual(workflow.derive_workflow(self.data, self.finding)["status"], status)
                workflow.validate_workflows(copy.deepcopy(self.data))  # The journal replays.
                workflow.resume(self.data, "F-001", "coordinator", "Retry the blocked stage")
        with self.assertRaisesRegex(workflow.WorkflowError, "different declared actors"):
            workflow.submit(self.data, "F-001", self.output("author"))
        workflow.submit(self.data, "F-001", self.output("independent"))
        self.assertEqual(workflow.derive_workflow(self.data, self.finding)["next_stage"], "decision")
        doc = (SKILL / "reference/verification-workflow.md").read_text(encoding="utf-8")
        self.assertIn("resets the verdict to `Unverified`", doc)
        self.assertIn("Do not opt in when no second reviewer can submit", doc)

    def test_require_complete_counts_only_opted_in_findings(self):
        path = self.tmp / "findings.json"
        other = dict(copy.deepcopy(self.finding), id="F-002")
        self.data["findings"].append(other)
        path.write_text(json.dumps(self.data))
        code, _, err = quiet(workflow.main, ["status", str(path), "--require-complete"])
        self.assertEqual(code, 3)
        self.assertIn("no finding has opted in", err)
        workflow.initialize(self.data, "F-001", "coordinator")
        for actor in ("author", "independent", "judge"):
            workflow.submit(self.data, "F-001", self.output(actor))
        self.assertEqual(workflow.derive_workflow(self.data, self.finding)["status"], "complete")
        path.write_text(json.dumps(self.data))
        self.assertEqual(quiet(workflow.main, ["status", str(path), "--require-complete"])[0], 0)
        self.assertEqual(quiet(workflow.main, ["status", str(path), "--require-complete",
                                               "--finding", "F-002"])[0], 3)


class ReproductionTimeoutTests(unittest.TestCase):
    def test_documented_margin_matches_child_timeout(self):
        reproduction = import_module(SCRIPTS / "reproduction.py", "round4_reproduction")
        doc = " ".join((SKILL / "reference/reproduction-bundles.md").read_text(encoding="utf-8").split())
        margins = {t: t - reproduction.child_timeout(t) for t in range(2, 61)}
        self.assertTrue(all(m == max(2, t // 4) for t, m in margins.items() if t > 2))
        self.assertIn(f"`--timeout 2` leaves a {margins[2]}-second margin", doc)
        self.assertIn("--timeout 2 leaves a 1 s margin", " ".join(reproduction.child_timeout.__doc__.split()))


if __name__ == "__main__":
    unittest.main()
