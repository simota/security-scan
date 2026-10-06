"""Run contract: evidence capture, the deps_scan stamp and contract_check.py."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_security_scan import import_module

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts"
GIT = shutil.which("git") or "/usr/bin/git"


def git(repo: Path, *args: str) -> None:
    subprocess.run([GIT, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


class RunContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = import_module(SCRIPTS / "evidence_capture.py", "tested_evidence_capture")
        cls.contract = import_module(SCRIPTS / "contract_check.py", "tested_contract_check")
        cls.deps = import_module(SCRIPTS / "deps_scan.py", "tested_deps_scan_contract")
        cls.renderer = import_module(SCRIPTS / "render.py", "tested_renderer_contract")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-contract-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "app"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src/orders.py").write_text("def show(order_id):\n    return Order.get(order_id)\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "init")
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.findings = self.out / "findings.json"

    def base(self) -> dict:
        names = self.contract.perspective_names()
        return {
            "meta": {"project": "Synthetic app", "date": "2026-10-07", "assessor": "Test host (model)"},
            "findings": [{
                "id": "F-001", "title": "Order detail lacks an owner check", "severity": "High",
                "confidence": "Confirmed", "category": "Actor and tenant", "location": "src/orders.py:2",
                "actor": "any signed-in user", "request": "GET /orders/{order_id}",
                "impact": "reads another user's order", "fix": "scope the query to the caller",
                "validation": {"verdict": "Likely", "evidence": "handler reads by id only", "method": "review"},
            }],
            "perspectives": [{"name": n, "result": "1 High" if n == "Actor and tenant" else "N/A - synthetic"}
                             for n in names],
            "checked_ok": [], "decisions": [], "limitations": [], "next_steps": [],
        }

    def build(self) -> dict:
        self.findings.write_text(json.dumps(self.base()))
        mapping = self.capture.capture(self.repo, self.findings, ["src/orders.py"])
        data = json.loads(self.findings.read_text())
        ev = [mapping["src/orders.py"]]
        claim = {"status": "supported", "reason": "read in source", "evidence_ids": ev}
        data["findings"][0]["verification"] = {
            "reviewer": "unit-a",
            "claims": {k: dict(claim) for k in ("reachability", "preconditions", "defenses", "impact")},
            "falsification": [{"check": "looked for a policy", "result": "clear", "reason": "none",
                               "evidence_ids": ev}],
            "reviews": [],
            "environment": {"status": "not_required", "reason": "bounded to the handler", "evidence_ids": []},
            "run_ids": [],
        }
        self.findings.write_text(json.dumps(data))
        self.deps.merge_into(self.findings, {"findings": [], "not_run": []}, audit=True)
        return json.loads(self.findings.read_text())

    def render(self):
        code = self.renderer.main([str(self.findings), "--out", str(self.out), "--no-pdf"])
        self.assertEqual(code, 0)

    def problems(self, data: dict, **kw) -> list:
        return self.contract.check(data, self.out, pdf=False, **kw)

    def test_conforming_run_passes_and_renders(self):
        data = self.build()
        self.render()
        self.assertEqual(self.problems(data), [])
        self.assertEqual(data["schema_version"], 2)
        self.assertEqual(data["assessment"]["worktree"], "clean")
        record = data["evidence"][0]
        self.assertEqual(record["location"], "evidence/source/src/orders.py")
        self.assertEqual((self.out / record["location"]).read_bytes(),
                         (self.repo / "src/orders.py").read_bytes())
        self.assertEqual(data["dependency_scan"], {"tool": "deps_scan.py", "audit": True,
                                                    "findings": 0, "not_run": 0})

    def test_divergences_seen_between_hosts_are_rejected(self):
        data = self.build()
        self.render()
        cases = {
            "hand-written D-*": lambda d: d["findings"].append(
                dict(d["findings"][0], id="D-001", category="Dependencies and platform")),
            "foreign id prefix": lambda d: d["findings"].__setitem__(0, dict(d["findings"][0], id="PAY-01")),
            "id gap": lambda d: d["findings"][0].__setitem__("id", "F-002"),
            "legacy record": lambda d: d.pop("schema_version"),
            "no scanner stamp": lambda d: d.pop("dependency_scan"),
            "missing perspective": lambda d: d["perspectives"].pop(),
            "unknown perspective": lambda d: d["perspectives"].append({"name": "Misc", "result": "x"}),
            "no verdict": lambda d: d["findings"][0].pop("validation"),
            "no verification": lambda d: d["findings"][0].pop("verification"),
            "file-only location": lambda d: d["findings"][0].__setitem__("location", "src/orders.py"),
            "no assessor": lambda d: d["meta"].pop("assessor"),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                broken = copy.deepcopy(data)
                mutate(broken)
                self.assertTrue(self.problems(broken), name)

    def test_output_set_is_fixed_unless_allowed(self):
        data = self.build()
        self.render()
        (self.out / "README.md").write_text("summary")
        self.assertTrue(any("README.md" in p for p in self.problems(data)))
        self.assertEqual(self.problems(data, allow=["README.md"]), [])
        (self.out / "dashboard.html").unlink()
        self.assertTrue(any("dashboard.html missing" in p for p in self.problems(data, allow=["README.md"])))

    def test_cli_exit_codes(self):
        self.build()
        self.render()
        self.assertEqual(self.contract.main([str(self.out), "--no-pdf"]), 0)
        self.assertEqual(self.contract.main([str(self.out)]), 1)  # PDF expected by default
        self.assertEqual(self.contract.main([str(self.tmp / "missing")]), 2)

    def test_capture_is_idempotent_and_refuses_unsafe_input(self):
        self.findings.write_text(json.dumps(self.base()))
        first = self.capture.capture(self.repo, self.findings, ["src/orders.py"])
        again = self.capture.capture(self.repo, self.findings, ["src/orders.py"])
        self.assertEqual(first, again)
        self.assertEqual(len(json.loads(self.findings.read_text())["evidence"]), 1)
        for bad in ("../app/src/orders.py", "/etc/hosts", "src/./orders.py", "missing.py"):
            with self.subTest(bad), self.assertRaises(self.capture.CaptureError):
                self.capture.capture(self.repo, self.findings, [bad])
        (self.repo / "src/orders.py").write_text("changed\n")
        with self.assertRaises(self.capture.CaptureError):
            self.capture.capture(self.repo, self.findings, ["src/orders.py"])

    def test_capture_refuses_a_second_commit_pin(self):
        self.findings.write_text(json.dumps(self.base()))
        self.capture.capture(self.repo, self.findings, ["src/orders.py"])
        (self.repo / "src/other.py").write_text("y\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "second")
        with self.assertRaises(self.capture.CaptureError):
            self.capture.capture(self.repo, self.findings, ["src/other.py"])

    def test_capture_cli_prints_the_id_map(self):
        self.findings.write_text(json.dumps(self.base()))
        done = subprocess.run([sys.executable, str(SCRIPTS / "evidence_capture.py"), str(self.repo),
                               "src/orders.py", "--findings", str(self.findings)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout), {"src/orders.py": "SRC-001"})
        done = subprocess.run([sys.executable, str(SCRIPTS / "evidence_capture.py"), str(self.repo),
                               "nope.py", "--findings", str(self.findings)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)


if __name__ == "__main__":
    unittest.main()
