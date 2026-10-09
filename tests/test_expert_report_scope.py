"""Expert report wording distinguishes declared gates from the final file audit."""
import json
from pathlib import Path
import tempfile
import unittest

from test_expert import SPAWNS, complete_data, expert, expert_audit, render


class ExpertReportScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="expert-report-scope-")
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        self.data = complete_data()
        self.findings = self.out / "findings.json"

    def pages(self, lang):
        self.findings.write_text(json.dumps(self.data), encoding="utf-8")
        (self.out / "deps.json").write_text('{"inventory": [], "findings": [], "not_run": []}\n')
        (self.out / "evidence").mkdir(exist_ok=True)
        self.assertEqual(render.main([str(self.findings), "--out", str(self.out),
                                      "--lang", lang, "--no-pdf"]), 0)
        return [(self.out / name).read_text(encoding="utf-8")
                for name in ("dashboard.html", "assessment.html")]

    def assert_scoped_notice(self, page, lang):
        if lang == "en":
            self.assertIn("Expert record gate state", page)
            self.assertIn("do not establish whether the final audit", page)
            self.assertNotIn("Every finding passed through independent discovery", page)
            self.assertNotIn("All expert-grade gates met", page)
        else:
            self.assertIn("エキスパート宣言レコードのゲート状態", page)
            self.assertIn("最終監査の合格を示すものではありません", page)
            self.assertNotIn("各指摘は、作成者以外のワーカーによる", page)
            self.assertNotIn("エキスパート品質のゲートをすべて充足", page)

    def test_missing_spawns_never_claim_completed_independent_reviews(self):
        self.data["expert"]["spawns"] = []
        self.assertEqual(expert.derive_expert(self.data)["status"], "held")
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                for page in self.pages(lang):
                    self.assert_scoped_notice(page, lang)
                    self.assertIn("Held:" if lang == "en" else "保留：", page)

    def test_record_completion_does_not_claim_a_missing_run_file_passed_audit(self):
        run = self.out / "run" / "spawns"
        run.mkdir(parents=True)
        (self.out / "run" / "gate.md").write_text("Synthetic consent and preflight\n")
        for sid, _, _ in SPAWNS:
            (run / f"{sid}.prompt.md").write_text("Synthetic prompt\n")
            (run / f"{sid}.return.md").write_text("Synthetic return\n")
        self.pages("en")
        self.assertEqual(expert_audit.audit(self.data, self.out, pdf=False)["status"], "complete")
        (run / "S-09.return.md").unlink()
        self.assertEqual(expert.derive_expert(self.data)["status"], "complete")
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                for page in self.pages(lang):
                    self.assert_scoped_notice(page, lang)
                    self.assertIn("final audit not established here" if lang == "en"
                                  else "最終監査の合否はこの表示では未検証", page)
                result = expert_audit.audit(self.data, self.out, pdf=False)
                self.assertEqual(result["status"], "held")
                self.assertIn("run_file_missing:spawn:S-09:return:run/spawns/S-09.return.md", result["gaps"])
                self.assertEqual(expert_audit.main([str(self.out), "--no-pdf"]), 3)


if __name__ == "__main__":
    unittest.main()
