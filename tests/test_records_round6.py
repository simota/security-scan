"""Round-6 regressions for the record tools: contract_check, expert, expert_audit,
findings merge, invariant_ledger and verification."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))

import contract_check  # noqa: E402
import expert  # noqa: E402
import expert_audit  # noqa: E402
import findings as merge_tool  # noqa: E402
import invariant_ledger  # noqa: E402
import render  # noqa: E402
import verification_workflow as workflow  # noqa: E402

import test_run_contract  # noqa: E402  (module import, so its tests are not collected twice)
import test_expert  # noqa: E402
import test_invariant_ledger  # noqa: E402

EXAMPLES = ROOT / "examples"
CLAIMS = ("reachability", "preconditions", "defenses", "impact")


def quiet(function, *args):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = function(*args)
    return code, err.getvalue()


def run_cli(script, *args, cwd=None):
    """Run a tool in a child process; a hang (FIFO input) shows up as a timeout."""
    done = subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], cwd=cwd,
                          capture_output=True, timeout=20, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return done.returncode, done.stderr.decode("utf-8", "replace")


class ContractCheckRound6Tests(unittest.TestCase):
    # Reuse the conforming-run fixture without re-running its tests.
    setUpClass = test_run_contract.RunContractTests.__dict__["setUpClass"]
    setUp = test_run_contract.RunContractTests.setUp
    base = test_run_contract.RunContractTests.base
    build = test_run_contract.RunContractTests.build
    render = test_run_contract.RunContractTests.render
    problems = test_run_contract.RunContractTests.problems

    def conforming(self):
        data = self.build()
        self.render()
        self.assertEqual(self.problems(data), [])
        return data

    def test_unreadable_page_does_not_hide_the_other_pages_staleness(self):
        data = self.conforming()
        # A later merge changed findings.json bytes; both pages are now stale.
        self.findings.write_text(json.dumps(data, indent=1))
        (self.out / "dashboard.html").unlink()
        (self.out / "dashboard.html").mkdir()
        problems = self.problems(data)
        self.assertTrue(any("cannot read dashboard.html" in p for p in problems), problems)
        self.assertTrue(any("assessment.html was not rendered from the current findings.json" in p
                            for p in problems), problems)

    def test_symlinked_page_is_not_accepted(self):
        data = self.conforming()
        page = self.out / "dashboard.html"
        copy_path = self.tmp / "dashboard-copy.html"
        page.rename(copy_path)
        page.symlink_to(copy_path)
        problems = self.problems(data)
        self.assertTrue(any("cannot read dashboard.html" in p for p in problems), problems)

    def test_unhashable_severity_and_verdict_are_violations_not_crashes(self):
        data = self.conforming()
        for mutate in (lambda f: f.__setitem__("severity", []),
                       lambda f: f["validation"].__setitem__("verdict", {}),
                       lambda f: f.__setitem__("category", ["Actor and tenant"])):
            changed = copy.deepcopy(data)
            mutate(changed["findings"][0])
            with self.subTest(finding=changed["findings"][0]):
                self.assertTrue(self.problems(changed))
        # Anything still unanticipated is unreadable input (exit 2), not a traceback.
        with mock.patch.object(self.contract, "check", side_effect=TypeError("boom")):
            code, err = quiet(self.contract.main, [str(self.out), "--no-pdf"])
        self.assertEqual(code, 2)
        self.assertIn("unexpected shape", err)

    def test_invalid_severity_is_named_as_such(self):
        data = self.conforming()
        data["findings"][0]["severity"] = "Critical"
        problems = self.problems(data)
        self.assertIn("F-001: severity must be one of High, Medium, Low, Info", problems)
        self.assertFalse(any("severity order" in p for p in problems), problems)

    def test_evidence_and_deps_json_must_have_the_right_type(self):
        data = self.conforming()
        shutil.rmtree(self.out / "evidence")
        (self.out / "evidence").write_text("not a directory\n")
        self.assertTrue(any("evidence must be the directory" in p for p in self.problems(data)))
        for content in ("[]", "not json", None):
            deps = self.out / "deps.json"
            if deps.is_dir():
                deps.rmdir()
            else:
                deps.unlink()
            if content is None:
                deps.mkdir()
            else:
                deps.write_text(content)
            with self.subTest(content=content):
                self.assertTrue(any("deps.json must be deps_scan.py's JSON report" in p
                                    for p in self.problems(data)))

    def test_render_hint_names_no_pdf(self):
        data = self.conforming()
        problems = self.contract.check(data, self.out, pdf=True)
        hint = [p for p in problems if p.startswith("outputs: assessment.pdf missing")]
        self.assertEqual(len(hint), 1, problems)
        self.assertIn(f"--out {self.out} --no-pdf, then contract_check.py {self.out} --no-pdf", hint[0])


class ContractOrderAndLimitationTests(unittest.TestCase):
    def check(self, data):
        return contract_check.check(data, Path(tempfile.gettempdir()))

    def order_violation(self, *locations):
        findings = [{"id": "F-%03d" % i, "severity": "High", "location": loc}
                    for i, loc in enumerate(locations, 1)]
        return "F-*: number code findings in severity order (High first), then path" in self.check(
            {"findings": findings})

    def test_path_then_line_order_within_a_severity(self):
        self.assertTrue(self.order_violation("src/z.py:1", "src/a.py:1"))
        self.assertTrue(self.order_violation("src/a.py:10", "src/a.py:9"))
        self.assertFalse(self.order_violation("src/a.py:9", "src/a.py:10-12", "src/b.py:1"))

    def test_examples_follow_the_documented_order(self):
        for name in ("findings.sample.json", "findings.sample.ja.json"):
            data = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
            with self.subTest(name=name):
                self.assertNotIn("F-*: number code findings in severity order (High first), then path",
                                 self.check(data))

    def dep_problems(self, stamp, limitations):
        data = {"findings": [], "dependency_scan": dict({"tool": "deps_scan.py", "findings": 0}, **stamp),
                "limitations": limitations}
        return [p for p in self.check(data) if "Dependency audit not run" in p or "not requested" in p]

    def test_dependency_limitations_written_by_into_must_remain(self):
        declined = "Dependency audit not run: vulnerability audit - not requested (--audit); advisories not matched"
        self.assertTrue(self.dep_problems({"audit": False, "not_run": 1}, []))
        self.assertEqual(self.dep_problems({"audit": False, "not_run": 1}, [declined]), [])
        missing_tool = "Dependency audit not run: npm audit - npm not installed"
        self.assertTrue(self.dep_problems({"audit": True, "not_run": 2}, [missing_tool]))
        self.assertEqual(self.dep_problems({"audit": True, "not_run": 1}, [missing_tool]), [])
        # A declined audit must keep its own line, not just any not-run line.
        self.assertTrue(self.dep_problems({"audit": False, "not_run": 1}, [missing_tool]))


class FifoInputTests(unittest.TestCase):
    def setUp(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("POSIX FIFOs required")
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-fifo-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_fifo_inputs_are_refused_without_blocking(self):
        out = self.tmp / "out"
        out.mkdir()
        os.mkfifo(str(out / "findings.json"))
        for script, args in (("contract_check.py", (out, "--no-pdf")), ("expert_audit.py", (out, "--no-pdf"))):
            with self.subTest(script=script):
                code, err = run_cli(script, *args)
                self.assertEqual(code, 2, err)
                self.assertIn("not a regular file", err)
                self.assertNotIn("Traceback", err)
        fragment = self.tmp / "frag.json"
        fragment.write_text('{"limitations": ["x"]}')
        code, err = run_cli("findings.py", "merge", out / "findings.json", fragment)
        self.assertEqual((code, "not a regular file" in err), (2, True), err)
        fifo_fragment = self.tmp / "fifo-frag.json"
        os.mkfifo(str(fifo_fragment))
        code, err = run_cli("findings.py", "merge", self.tmp / "new.json", fifo_fragment)
        self.assertEqual((code, "not a regular file" in err), (2, True), err)
        self.assertFalse((self.tmp / "new.json").exists())


class ExpertQaIndependenceTests(unittest.TestCase):
    def with_dependency(self, reviewer, journal_actor=None):
        data = test_expert.complete_data()
        ev = data["evidence"][0]["id"]
        claims = {k: {"status": "supported", "reason": "read the lockfile", "evidence_ids": [ev]} for k in CLAIMS}
        data["findings"].append({
            "id": "D-001", "title": "Advisory in a dependency", "severity": "Low", "confidence": "Suspected",
            "location": "package-lock.json:1", "category": "Dependencies and platform",
            "validation": {"verdict": "Likely", "method": "review", "evidence": "reviewed the advisory"},
            "verification": {"reviewer": reviewer, "claims": claims,
                             "falsification": [{"check": "c", "result": "clear", "reason": "r", "evidence_ids": [ev]}],
                             "reviews": [], "environment": {"status": "not_required", "reason": "r",
                                                            "evidence_ids": []}, "run_ids": []}})
        data["dependency_scan"]["findings"] = 1
        if journal_actor:
            workflow.initialize(data, "D-001", journal_actor, "verifies this dependency")
        return data

    def gaps(self, data):
        return expert.derive_expert(data)["gaps"]

    def test_dependency_reviewer_cannot_be_qa(self):
        self.assertNotIn("qa_not_independent", self.gaps(self.with_dependency("synthetic-conditions")))
        self.assertIn("qa_not_independent", self.gaps(self.with_dependency("qa-1")))

    def test_dependency_journal_actor_cannot_be_qa(self):
        self.assertIn("qa_not_independent",
                      self.gaps(self.with_dependency("synthetic-conditions", journal_actor="qa-1")))

    def test_dependency_review_and_resolution_reviewers_count(self):
        data = self.with_dependency("synthetic-conditions")
        data["findings"][-1]["verification"]["reviews"] = [{"reviewer": "qa-1"}]
        self.assertEqual(expert._finding_actors(data["findings"][-1]),
                         {expert._actor_key("synthetic-conditions"), expert._actor_key("qa-1")})
        self.assertEqual(expert._finding_actors({"verification": {"reviews": [
            {"reviewer": "a", "resolution": {"reviewer": "b"}}, "junk"]}, "verification_workflow": {"history": [5]}}),
            {expert._actor_key("a"), expert._actor_key("b")})


class ExpertAuditShapeTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="security-scan-audit-")).resolve()
        self.addCleanup(shutil.rmtree, self.out, True)

    def test_malformed_meta_exits_2_without_traceback(self):
        for meta in ([], {"project": "p", "date": "2026-10-10", "commit": 5}):
            data = test_expert.complete_data()
            data["meta"] = meta
            (self.out / "findings.json").write_text(json.dumps(data))
            with self.subTest(meta=meta):
                code, err = quiet(expert_audit.main, [str(self.out), "--no-pdf"])
                self.assertEqual(code, 2, err)
                self.assertIn("expert_audit.py:", err)


class SourceEvidenceMergeTests(unittest.TestCase):
    def setUp(self):
        self.base = json.loads((EXAMPLES / "findings.verification.sample.json").read_text(encoding="utf-8"))
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-source-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def refused(self, *records):
        return merge_tool.fragment_problems({"evidence": list(records)}, "frag", self.base)

    def test_captured_source_records_are_writer_owned(self):
        commit = self.base["evidence"][0]["commit"]
        self.assertEqual(self.refused({"id": "source-before", "summary": "Reworded observation."}), [])
        self.assertEqual(self.refused(dict(self.base["evidence"][0], summary="Reworded.")), [])
        self.assertTrue(self.refused({"id": "source-before", "sha256": "f" * 64}))
        self.assertTrue(self.refused({"id": "source-before", "location": "src/other.py"}))
        self.assertTrue(self.refused({"id": "source-before", "kind": "runtime"}))
        self.assertTrue(self.refused({"id": "SRC-099", "kind": "source", "commit": commit,
                                      "location": "evidence/source/x.py", "source_path": "x.py",
                                      "summary": "fabricated", "sha256": "0" * 64}))
        # A runtime record cannot be turned into source evidence either.
        self.assertTrue(self.refused({"id": "test-before", "kind": "source"}))
        self.assertEqual(self.refused({"id": "RUN-LOG-9", "kind": "runtime", "commit": commit,
                                       "location": "artifacts/log.txt", "summary": "log",
                                       "sha256": "0" * 64}), [])

    def test_cli_refuses_rewriting_source_evidence(self):
        findings = self.tmp / "findings.json"
        findings.write_text(json.dumps(self.base))
        fragment = self.tmp / "frag.json"
        fragment.write_text(json.dumps({"evidence": [{"id": "source-before", "sha256": "f" * 64}]}))
        code, err = quiet(merge_tool.main, ["merge", str(findings), str(fragment)])
        self.assertEqual(code, 1, err)
        self.assertIn("come only from evidence_capture.py", err)
        self.assertEqual(json.loads(findings.read_text()), self.base)
        fragment.write_text(json.dumps({"evidence": [{"id": "source-before", "summary": "Reworded observation."}]}))
        code, err = quiet(merge_tool.main, ["merge", str(findings), str(fragment)])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(findings.read_text())["evidence"][0]["summary"], "Reworded observation.")


class PayloadFilterTests(unittest.TestCase):
    PROSE_OK = ("Visible to other members' and 2 admins' sessions", "The role field accepts 'admin' or 'member'",
                "Path traversal via ../ segments", "Accepts javascript: URLs in the profile link",
                "Template injection in the {{name}} placeholder", "Install step pipes curl | sh",
                "role = admin or role = owner")
    PAYLOADS = ("GET /items?id=1 OR 1=1", 'q=" or "a"="a', "q=x' or 'a'='a", "file=..\\..\\win.ini",
                "file=%2e%2e%2fsecret", "file=..%2fsecret", "<svg onload=alert(1)>", "{{config.items()}}",
                "${jndi:ldap://host/a}", "name=a;id", "cat /etc/shadow", "${7*7}")

    def problems(self, fragment):
        return merge_tool.payload_problems(fragment, "frag")

    def test_prose_is_accepted_and_payload_shapes_refused(self):
        for text in self.PROSE_OK:
            with self.subTest(prose=text):
                self.assertEqual(self.problems({"findings": [{"id": "F-001", "impact": text}]}), [])
        for text in self.PAYLOADS:
            with self.subTest(payload=text):
                self.assertTrue(self.problems({"findings": [{"id": "F-001", "request": text}]}))

    def test_validation_evidence_and_checked_ok_are_checked(self):
        self.assertTrue(self.problems({"findings": [{"id": "F-001", "validation": {
            "verdict": "Likely", "evidence": "sent id=1 OR 1=1"}}]}))
        self.assertTrue(self.problems({"checked_ok": ["Search rejects ' OR '1'='1"]}))
        self.assertEqual(self.problems({"checked_ok": ["Search binds the q parameter"]}), [])


class BatchSizeTests(unittest.TestCase):
    def fragment(self, count):
        return {"findings": [{"id": "F-%03d" % i} for i in range(1, count + 1)]}

    def test_at_most_five_new_findings_per_fragment(self):
        too_many = merge_tool.fragment_problems(self.fragment(6), "frag", {})
        self.assertTrue(any("6 new findings in one fragment" in p for p in too_many), too_many)
        self.assertEqual(merge_tool.fragment_problems(self.fragment(5), "frag", {}), [])
        # Updates to recorded findings are not new findings.
        base = {"findings": [{"id": "F-%03d" % i} for i in range(1, 7)]}
        self.assertEqual(merge_tool.fragment_problems(self.fragment(6), "frag", base), [])


class InvariantLedgerRound6Tests(unittest.TestCase):
    def validate(self, data):
        return render.validate_data(copy.deepcopy(data))

    def test_ledger_ids_are_ascii_without_trailing_newline(self):
        for identifier in ("INV-01\n", "INV-١٢", "INV-1"):
            data = test_invariant_ledger.sample()
            data["invariant_ledger"]["entries"][0]["id"] = identifier
            with self.subTest(identifier=identifier):
                with self.assertRaisesRegex(render.SchemaError, "INV-<nn>"):
                    self.validate(data)

    def test_japanese_markers_are_accepted(self):
        data = test_invariant_ledger.sample()
        data["findings"][0].update(
            request="前提条件：1. テナント B に注文がある\n手順：1. GET /orders/<テナント B の注文 ID>\n"
                    "対比: GET /orders は src/orders.py:9 でテナントを絞り込む",
            fix="注文は呼び出し元のテナント内でのみ読み込む。テスト：テナント A がテナント B の注文を読むと not-found",
            impact="期待: not-found（INV-01 違反）。実際: src/orders.py:20 がテナント B の注文を返す")
        self.validate(data)
        data["findings"][0]["fix"] = "注文は呼び出し元のテナント内でのみ読み込む"
        with self.assertRaisesRegex(render.SchemaError, "Test:"):
            self.validate(data)

    def test_not_applicable_status_needs_a_reason_and_renders_as_na(self):
        data = test_invariant_ledger.sample()
        data["invariant_ledger"]["entries"].append(
            {"id": "INV-02", "family": "QTY", "invariant": "No money or quotas in this app", "source": "baseline",
             "status": "not_applicable", "paths_read": 0, "paths_total": 0, "reason": "no billing or quotas"})
        self.validate(data)
        self.assertIn("N/A (no billing or quotas)", invariant_ledger.ledger_html(data, "en"))
        self.assertIn("対象外（no billing or quotas）", invariant_ledger.ledger_html(data, "ja"))
        del data["invariant_ledger"]["entries"][1]["reason"]
        with self.assertRaisesRegex(render.SchemaError, "reason"):
            self.validate(data)


class ValidSecretHintTests(unittest.TestCase):
    def test_valid_without_supported_claims_explains_the_secret_case(self):
        data = json.loads((EXAMPLES / "findings.verification.sample.json").read_text(encoding="utf-8"))
        data["findings"][0]["verification"]["claims"]["impact"] = {
            "status": "unknown", "reason": "value not captured", "evidence_ids": []}
        with self.assertRaisesRegex(render.SchemaError, "record it as Likely"):
            render.validate_data(data)


if __name__ == "__main__":
    unittest.main()
