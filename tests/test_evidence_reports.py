"""Offline evidence-file provenance in reports; no assessed application is run.

Git repositories, logs and source bytes below are synthetic fixtures. Optional
browser/PDF tests use the same network-blocked report harness as existing tests.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_ci_report_artifacts as pdf_helpers
import test_report_outputs as report_helpers
import test_verification_reports as verification_helpers


REPO = Path(__file__).resolve().parents[1]
BROWSER_TESTS = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"
RAW_MARKER = "ARTIFACT_BYTES_MUST_NOT_APPEAR_IN_REPORT"


class EvidenceReportTests(unittest.TestCase):
    setUp = report_helpers.ReportOutputTests.setUp
    payload = report_helpers.ReportOutputTests.payload
    start_browser = report_helpers.ReportOutputTests.start_browser
    save_browser_artifact = report_helpers.ReportOutputTests.save_browser_artifact

    @classmethod
    def setUpClass(cls):
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)

    def load_data(self, source):
        path = self.root / "findings.json"
        path.write_text(json.dumps(source, ensure_ascii=False), encoding="utf-8")
        return self.renderer.load(path)

    def output(self, data, lang="en", integrity=None):
        labels = self.renderer.LABELS[lang]
        return tuple(report_helpers.ReportHTML(renderer(data, labels, lang, integrity=integrity)).root
                     for renderer in (self.renderer.render_dashboard, self.renderer.render_assessment_html))

    def checked_fixture(self):
        base = Path(tempfile.mkdtemp(prefix="private-evidence-root-", dir=self.root))
        repository, evidence_root = base / "repository", base / "evidence"
        repository.mkdir()
        evidence_root.mkdir()
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME="Synthetic Test", GIT_AUTHOR_EMAIL="synthetic@example.invalid",
                   GIT_COMMITTER_NAME="Synthetic Test", GIT_COMMITTER_EMAIL="synthetic@example.invalid")

        def git(*args):
            return subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgsign=false", *args],
                                  cwd=repository, env=env, check=True, capture_output=True, text=True,
                                  timeout=15).stdout.strip()

        git("init", "-q")
        (repository / "src").mkdir()
        source_bytes = (("# " + RAW_MARKER + "\n") * 30).encode()
        (repository / "src/orders.py").write_bytes(source_bytes)
        git("add", "src/orders.py")
        git("commit", "-qm", "Synthetic before fixture")
        before = git("rev-parse", "HEAD")
        (repository / "src/orders.py").write_bytes(source_bytes + b"# Synthetic later blob\n")
        git("add", "src/orders.py")
        git("commit", "-qm", "Synthetic after fixture")
        after = git("rev-parse", "HEAD")
        source = verification_helpers.fixture()
        source["evidence_integrity"] = {"required": True}
        source["meta"]["commit"] = before
        source["assessment"]["commit"] = before
        for record in source["evidence"]:
            record["commit"] = before if record["id"] in ("source-before", "test-before") else after
            relative = record["location"].split(":", 1)[0]
            record["location"] = relative
            if record["kind"] == "source":
                record["source_path"] = relative
            body = source_bytes if record["kind"] == "source" else (RAW_MARKER + " " + record["id"] + "\n").encode()
            path = evidence_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            record["sha256"] = hashlib.sha256(body).hexdigest()
        for run in source["test_runs"]:
            run["commit"] = before if run["id"] == "before" else after
        source["findings"][0]["remediation"]["commit"] = after
        return self.load_data(source), evidence_root, repository

    def verify(self, data, root, repository=None):
        return self.renderer.verify_evidence(data, root, repository=repository)

    def assert_private_inputs_absent(self, markup, root, repository):
        for private in (RAW_MARKER, str(root), str(repository)):
            self.assertNotIn(private, markup)

    def test_legacy_references_are_explicitly_declared_in_both_languages(self):
        data = self.load_data(verification_helpers.fixture())
        self.assertEqual(self.renderer.report_model(data)["verification"]["F-001"]["retest"], "verified")
        for lang in ("en", "ja"):
            labels = self.renderer.LABELS[lang]
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            self.assertEqual(payload["integrity_summary"]["counts"], {"checked": 0, "incomplete": 0, "declared": 1})
            self.assertIn(payload["integrity_summary"]["text"], assessment.text())
            for label in ("i_declared", "i_note", "i_bytes_declared", "i_source_declared"):
                self.assertIn(labels[label], assessment.text())
                self.assertIn(labels[label], "\n".join(verification_helpers.view_texts(payload["verification_views"]["F-001"])))

    def test_fresh_bytes_and_commit_binding_display_without_claiming_execution(self):
        data, root, repository = self.checked_fixture()
        integrity = self.verify(data, root, repository)
        before = copy.deepcopy(data)
        model = self.renderer.report_model(data, integrity=integrity)
        self.assertEqual(model["verification"]["F-001"]["retest"], "verified")
        for lang in ("en", "ja"):
            labels = self.renderer.LABELS[lang]
            dashboard, assessment = self.output(data, lang, integrity)
            payload = self.payload(dashboard)
            self.assertEqual(payload["report"], model)
            self.assertEqual(payload["integrity_summary"]["counts"], {"checked": 1, "incomplete": 0, "declared": 0})
            view = payload["verification_views"]["F-001"]
            for value in verification_helpers.view_texts(view):
                self.assertIn(value, assessment.text())
            for key in ("i_checked", "i_bytes_matched", "i_source_matched", "i_source_declared", "i_note"):
                self.assertIn(labels[key], assessment.text())
            self.assert_private_inputs_absent(json.dumps(payload), root, repository)
            self.assert_private_inputs_absent(assessment.text(), root, repository)
            self.assertEqual(set(payload["report"]["verification"]["F-001"]), {"level", "retest", "gaps"})
        self.assertEqual(data, before)

    def test_missing_mismatched_and_unbound_evidence_remain_incomplete(self):
        for failure in ("missing", "mismatch", "no_repository"):
            with self.subTest(failure=failure):
                data, root, repository = self.checked_fixture()
                artifact = root / "artifacts/after.txt"
                if failure == "missing":
                    artifact.unlink()
                elif failure == "mismatch":
                    artifact.write_text("Changed synthetic bytes", encoding="utf-8")
                integrity = self.verify(data, root, None if failure == "no_repository" else repository)
                model = self.renderer.report_model(data, integrity=integrity)
                state = model["verification"]["F-001"]
                self.assertEqual(state["level"], "incomplete")
                self.assertEqual(state["retest"], "incomplete")
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang, integrity)
                    self.assertEqual(self.payload(dashboard)["integrity_summary"]["counts"]["incomplete"], 1)
                    self.assertIn(self.renderer.LABELS[lang]["i_incomplete"], assessment.text())
                    if failure == "mismatch":
                        self.assertIn(self.renderer.LABELS[lang]["i_bytes_mismatch"], assessment.text())
                self.assertEqual(data["findings"][0]["status"], "Fixed")
                self.assertEqual(data["findings"][0]["verdict"], "Valid")

    def test_optional_checks_cannot_hide_a_fresh_mismatch(self):
        data, root, repository = self.checked_fixture()
        data.pop("evidence_integrity")
        (root / "artifacts/before.txt").write_bytes(b"mismatch")
        integrity = self.verify(data, root, repository)
        self.assertEqual(self.renderer.report_model(data)["verification"]["F-001"]["level"], "runtime_supported")
        self.assertEqual(self.renderer.report_model(data, integrity=integrity)["verification"]["F-001"]["level"], "incomplete")

    def test_matching_hash_with_wrong_commit_blob_is_not_checked(self):
        data, root, repository = self.checked_fixture()
        changed = b"# Different synthetic source bytes\n"
        (root / "src/orders.py").write_bytes(changed)
        data["evidence"][0]["sha256"] = hashlib.sha256(changed).hexdigest()
        integrity = self.verify(data, root, repository)
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang, integrity)
            self.assertEqual(self.payload(dashboard)["integrity_summary"]["counts"]["incomplete"], 1)
            self.assertIn(self.renderer.LABELS[lang]["i_source_mismatch"], assessment.text())
            self.assertIn(self.renderer.LABELS[lang]["i_reason_git_source_bytes_mismatch"], assessment.text())

    def test_fresh_context_is_forwarded_to_workflow_models_and_views(self):
        data, root, repository = self.checked_fixture()
        integrity = self.verify(data, root, repository)
        workflow = sys.modules["verification_workflow"]
        with patch.object(sys, "path", [str(REPO / "skills/security-scan/scripts")] + sys.path):
            workflow.initialize(data, "F-001", "synthetic-coordinator", integrity=integrity)
        for render in (lambda: self.renderer.report_model(data, integrity=integrity),
                       lambda: self.renderer.render_dashboard(data, self.renderer.LABELS["en"], "en", integrity=integrity),
                       lambda: self.renderer.render_assessment_html(data, self.renderer.LABELS["ja"], "ja", integrity=integrity)):
            with patch.object(self.renderer, "derive_workflow", wraps=self.renderer.derive_workflow) as derive:
                render()
                self.assertTrue(derive.called)
                for call in derive.call_args_list:
                    self.assertIs(call.kwargs["integrity"], integrity)

    def test_saved_receipt_and_json_roots_never_trigger_checks_or_promote(self):
        data, root, repository = self.checked_fixture()
        receipt = self.verify(data, root, repository).receipt
        source = copy.deepcopy(data)
        source.update(_evidence_integrity=receipt, evidence_root=str(root), evidence_repository=str(repository))
        source["meta"]["evidence_root"] = str(root)
        source["findings"][0].update(_evidence_integrity=receipt, evidence_integrity=receipt,
                                       evidence_root=str(root), integrity={"status": "checked"})
        loaded = self.load_data(source)
        self.assertNotIn("_evidence_integrity", loaded)
        self.assertNotIn("_evidence_integrity", loaded["findings"][0])
        self.assertEqual(self.renderer.report_model(loaded)["verification"]["F-001"]["level"], "incomplete")
        with patch.object(self.renderer, "verify_evidence", side_effect=AssertionError("JSON must not request filesystem reads")):
            with patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(self.renderer.main([str(self.root / "findings.json"), "--out", str(self.root / "out"), "--no-pdf"]), 0)
        for path in (self.root / "out").glob("*.html"):
            self.assert_private_inputs_absent(path.read_text(encoding="utf-8"), root, repository)
        dashboard, _ = self.output(loaded)
        self.assertEqual(self.payload(dashboard)["integrity_summary"]["counts"]["checked"], 0)
        # Even passing a serialized receipt explicitly cannot recreate freshness.
        self.assertNotEqual(self.renderer.report_model(data, integrity=receipt)["verification"]["F-001"]["retest"], "verified")

    def test_changed_declarations_invalidate_an_in_memory_result(self):
        data, root, repository = self.checked_fixture()
        integrity = self.verify(data, root, repository)
        data["evidence"][0]["sha256"] = "f" * 64
        self.assertFalse(integrity.matches(data))
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang, integrity)
            self.assertEqual(self.payload(dashboard)["report"]["verification"]["F-001"]["level"], "incomplete")
            self.assertNotIn(self.renderer.LABELS[lang]["i_checked"], assessment.text())

    def test_cli_passes_only_explicit_roots_and_fresh_result_to_both_outputs(self):
        data, root, repository = self.checked_fixture()
        output = self.root / "cli-output"
        with patch.object(self.renderer, "verify_evidence", wraps=self.renderer.verify_evidence) as verify:
            with patch("sys.stdout", new=io.StringIO()):
                code = self.renderer.main([str(self.root / "findings.json"), "--out", str(output), "--no-pdf",
                                           "--evidence-root", str(root), "--evidence-repository", str(repository), "--lang", "ja"])
        self.assertEqual(code, 0)
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[1], str(root))
        self.assertEqual(verify.call_args.kwargs, {"repository": str(repository)})
        dashboard = report_helpers.ReportHTML((output / "dashboard.html").read_text(encoding="utf-8")).root
        self.assertEqual(self.payload(dashboard)["integrity_summary"]["counts"]["checked"], 1)
        assessment = (output / "assessment.html").read_text(encoding="utf-8")
        self.assertIn(self.renderer.LABELS["ja"]["i_checked"], assessment)
        self.assert_private_inputs_absent(assessment, root, repository)

    def test_cli_requires_root_and_hides_private_setup_errors(self):
        self.load_data(verification_helpers.fixture())
        output = self.root / "not-created"
        args = [str(self.root / "findings.json"), "--out", str(output), "--no-pdf"]
        with patch("sys.stderr", new=io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as raised:
                self.renderer.main(args + ["--evidence-repository", "/private/repository"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("requires --evidence-root", stderr.getvalue())
        self.assertFalse(output.exists())
        with patch.object(self.renderer, "verify_evidence", side_effect=ValueError("/private/root SECRET")):
            with patch("sys.stderr", new=io.StringIO()) as stderr:
                self.assertEqual(self.renderer.main(args + ["--evidence-root", "/private/root"]), 2)
        self.assertNotIn("/private/root", stderr.getvalue())
        self.assertNotIn("SECRET", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_hostile_evidence_identifiers_are_redacted_and_escaped(self):
        source = verification_helpers.fixture()
        old = "source-before"
        hostile = "</script><svg onload='window.EVIDENCE_INJECTED=1'>日本語</svg> password=EVIDENCE_SECRET"
        source["evidence"][0]["id"] = hostile
        proof = source["findings"][0]["verification"]
        for record in [*proof["claims"].values(), *proof["falsification"], *proof["reviews"]]:
            record["evidence_ids"] = [hostile if item == old else item for item in record["evidence_ids"]]
        data = self.load_data(source)
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            self.assertNotIn("EVIDENCE_SECRET", json.dumps(payload))
            self.assertNotIn("EVIDENCE_SECRET", assessment.text())
            self.assertFalse(dashboard.find_all("svg"))
            self.assertFalse(assessment.find_all("svg"))
            self.assertIn("********", assessment.text())

    @unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium evidence integrity tests")
    def test_browser_integrity_provenance_both_languages_mobile(self):
        data, root, repository = self.checked_fixture()
        integrity = self.verify(data, root, repository)
        page = self.start_browser()
        page.set_viewport_size({"width": 375, "height": 812})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        for lang in ("en", "ja"):
            labels = self.renderer.LABELS[lang]
            for name, renderer in (("dashboard", self.renderer.render_dashboard), ("assessment", self.renderer.render_assessment_html)):
                with self.subTest(lang=lang, output=name):
                    page.goto("about:blank")
                    page.set_content(renderer(data, labels, lang, integrity=integrity), wait_until="domcontentloaded")
                    self.assertTrue(page.locator(".integrity-summary").is_visible())
                    self.assertIn(labels["i_note"], page.locator(".integrity-summary").inner_text())
                    if name == "dashboard":
                        page.locator(".finding-toggle").click()
                    text = page.locator(".verification-record").inner_text()
                    for key in ("i_checked", "i_bytes_matched", "i_source_matched", "i_note"):
                        self.assertIn(labels[key], text)
                    self.assert_private_inputs_absent(page.content(), root, repository)
                    self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"))
                    self.save_browser_artifact(page, lang + "-integrity-" + name + "-375px")
                    self.assertFalse(errors)


@unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium evidence integrity PDF tests")
class EvidencePDFTests(unittest.TestCase):
    setUp = pdf_helpers.ReportArtifactTests.setUp
    load_data = EvidenceReportTests.load_data
    checked_fixture = EvidenceReportTests.checked_fixture
    normalized = staticmethod(pdf_helpers.ReportArtifactTests.normalized)

    @classmethod
    def setUpClass(cls):
        pdf_helpers.ReportArtifactTests.setUpClass.__func__(cls)
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)

    def check_pdf(self, lang):
        data, root, repository = self.checked_fixture()
        output = self.artifacts / (lang + "-integrity")
        output.mkdir(parents=True, exist_ok=True)
        pdf = output / "assessment.pdf"
        pdf.unlink(missing_ok=True)
        result = subprocess.run([sys.executable, str(REPO / "skills/security-scan/scripts/render.py"),
                                 str(self.root / "findings.json"), "--out", str(output), "--lang", lang,
                                 "--evidence-root", str(root), "--evidence-repository", str(repository)],
                                env={**os.environ, "CHROME": self.chrome}, capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("(chrome)", result.stdout)
        self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
        text_path = output / "assessment.txt"
        subprocess.run(["pdftotext", "-enc", "UTF-8", str(pdf), str(text_path)],
                       capture_output=True, check=True, timeout=30)
        text = text_path.read_text(encoding="utf-8")
        for key in ("i_title", "i_checked", "i_bytes_matched", "i_source_matched", "i_note"):
            self.assertIn(self.normalized(self.renderer.LABELS[lang][key]), self.normalized(text))
        for private in (RAW_MARKER, str(root), str(repository)):
            self.assertNotIn(private, text)

    def test_english_integrity_pdf(self):
        self.check_pdf("en")

    def test_japanese_integrity_pdf(self):
        self.check_pdf("ja")


if __name__ == "__main__":
    unittest.main()
