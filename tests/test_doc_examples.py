"""Documented temp-directory examples run as written, even where $TMPDIR is a symlink (macOS)."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ("README.md", "skills/security-scan/reference/reproduction-bundles.md",
        "skills/security-scan/reference/evidence-integrity.md")
BLOCK = re.compile(r"^```sh\n(.*?)^```", re.S | re.M)


def mktemp_examples():
    for doc in DOCS:
        for block in BLOCK.findall((ROOT / doc).read_text(encoding="utf-8")):
            if "mktemp -d" in block:
                yield doc, block


class DocumentedExampleTests(unittest.TestCase):
    def test_examples_exist(self):
        self.assertEqual(sorted({doc for doc, _ in mktemp_examples()}), sorted(DOCS))

    @unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and git")
    def test_examples_run_under_a_symlinked_tmpdir(self):
        with tempfile.TemporaryDirectory(prefix="security-scan-doc-examples-") as tmp:
            real = Path(tmp).resolve() / "real"
            real.mkdir()
            linked = Path(tmp) / "linked"
            linked.symlink_to(real, target_is_directory=True)
            env = dict(os.environ, TMPDIR=str(linked), PYTHONDONTWRITEBYTECODE="1")
            for doc, block in mktemp_examples():
                with self.subTest(doc=doc):
                    done = subprocess.run(["bash", "-euo", "pipefail", "-c", block], cwd=str(ROOT), env=env,
                                          capture_output=True, text=True, timeout=120)
                    self.assertEqual(done.returncode, 0, done.stdout[-2000:] + done.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
