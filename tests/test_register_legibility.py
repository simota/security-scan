"""Enumerated register values stay whole words.

Confidence and validation cells each hold one enumerated value
(Environment-dependent, Unverified, NotApplicable). The opt-in browser test
renders a sample and checks that no such value is split inside a word at
desktop, tablet and phone widths; a hyphen or space is an acceptable break.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RENDER = ROOT / "skills" / "security-scan" / "scripts" / "render.py"
BROWSER = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"

MID_WORD_BREAKS = """() => {
    const out = [];
    for (const td of document.querySelectorAll('#rows tr.row td:nth-child(3), #rows tr.row td:nth-child(5)')) {
        const node = [...td.childNodes].find(c => c.nodeType === 3 && c.textContent.trim());
        if (!node) continue;
        const text = node.textContent, range = document.createRange();
        let top = null;
        for (let i = 0; i < text.length; i++) {
            range.setStart(node, i); range.setEnd(node, i + 1);
            const y = Math.round(range.getBoundingClientRect().top);
            if (top !== null && y > top + 2 && !'- '.includes(text[i - 1])) out.push(text);
            top = y;
        }
    }
    return out;
}"""


@unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
class RegisterLegibilityBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        exe = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not exe:
            raise AssertionError("Required Chrome/Chromium not installed; set CHROME to its executable")
        from playwright.sync_api import sync_playwright
        cls.out = Path(tempfile.mkdtemp(prefix="security-scan-legibility-"))
        # The sample carries Environment-dependent, Unverified and an excluded FalsePositive record.
        subprocess.run([sys.executable, "-B", str(RENDER), str(ROOT / "examples" / "findings.sample.json"),
                        "--out", str(cls.out), "--no-pdf"], check=True, capture_output=True, timeout=120)
        cls.manager = sync_playwright().start()
        cls.browser = cls.manager.chromium.launch(executable_path=exe, headless=True, timeout=15000)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.manager.stop()
        shutil.rmtree(cls.out, ignore_errors=True)

    def test_enumerated_register_values_break_only_at_hyphens(self):
        for width in (1280, 900, 390):
            with self.subTest(width=width):
                page = self.browser.new_page(viewport={"width": width, "height": 900}, service_workers="block")
                self.addCleanup(page.close)
                page.set_default_timeout(10000)
                page.goto((self.out / "dashboard.html").as_uri())
                page.select_option("#f-scope", "all")
                values = page.locator("#rows tr.row td:nth-child(3), #rows tr.row td:nth-child(5)").all_inner_texts()
                self.assertTrue(any("Environment-dependent" in v for v in values), values)
                self.assertEqual(page.evaluate(MID_WORD_BREAKS), [])


if __name__ == "__main__":
    unittest.main()
