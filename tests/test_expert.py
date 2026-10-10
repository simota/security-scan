"""Expert-grade gates: record derivation, the run-file audit and the report summary."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import contract_check
import expert
import expert_audit
import render
import verification_workflow as workflow

SPEC = importlib.util.spec_from_file_location("expert_benchmark", ROOT / "scripts/ci/benchmark_three_pass.py")
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)

SPAWNS = [("S-01", "recon-a", "recon"), ("S-02", "recon-b", "recon"),
          ("S-03", "disc-entry", "discovery"), ("S-04", "disc-sink", "discovery"),
          ("S-05", "disc-control", "discovery"), ("S-06", "variant-1", "variant"),
          ("S-07", "synthetic-conditions", "conditions"), ("S-08", "synthetic-challenge", "falsification"),
          ("S-09", "skeptic-defense", "skeptic"), ("S-10", "skeptic-impact", "skeptic"),
          ("S-11", "rater-1", "rater"), ("S-12", "rater-2", "rater"), ("S-13", "omission-1", "omission"),
          ("S-14", "persona-exec", "persona"), ("S-15", "persona-eng", "persona"),
          ("S-16", "persona-audit", "persona"), ("S-17", "qa-1", "qa")]
SPAN = "Synthetic three-pass candidate"


def complete_data():
    data = benchmark.sample()
    data["findings"][0].update(category="Actor and tenant", actor="any user", request="GET /orders/{id}",
                               impact="reads another user's order", fix="scope the query", cwe="CWE-639")
    workflow.initialize(data, "F-001", "coordinator")
    for stage in workflow.STAGES:
        workflow.submit(data, "F-001", benchmark.submission(data, stage))
    cells = [c["id"] for c in data["three_pass"]["coverage"]]
    data["expert"] = {
        "version": 1, "mode": "full", "host": "claude-code",
        "consent": {"ceiling": 40, "engines": ["claude-code"], "data_boundary": "current host only",
                    "record": "run/gate.md"},
        "preflight": [{"engine": "claude-code", "exit": 0, "record": "run/gate.md"}],
        "spawns": [{"id": i, "actor": a, "role": r, "engine": "claude-code",
                    "prompt": f"run/spawns/{i}.prompt.md", "return": f"run/spawns/{i}.return.md"}
                   for i, a, r in SPAWNS],
        "recon": [{"actor": "recon-a", "routes": 3}, {"actor": "recon-b", "routes": 2}],
        "reconciliation": {"routes": 3, "disagreements": 1, "resolved": 1},
        "discovery": [
            {"actor": "disc-entry", "angle": "entry-first", "cells": list(cells), "candidates": ["F-001"], "raw_candidates": 2},
            {"actor": "disc-sink", "angle": "sink-first", "cells": list(cells), "candidates": ["F-001"], "raw_candidates": 1},
            {"actor": "disc-control", "angle": "control-first", "cells": list(cells), "candidates": [], "raw_candidates": 0}],
        "variants": [{"actor": "variant-1", "findings": ["F-001"], "pattern": "lookup by id without owner",
                      "search": "rg 'find\\(' app/", "hits": 1,
                      "dispositions": [{"location": "app/orders.py:9", "result": "same:F-001", "reason": "same handler"}]}],
        "omission": [{"actor": "omission-1", "added": [], "reason": "no missing class found in the route map"}],
        "panels": [{"finding": "F-001", "skeptics": [
            {"actor": "skeptic-defense", "angle": "defense-exists", "result": "survived", "reason": "no policy",
             "evidence_ids": ["route-source"]},
            {"actor": "skeptic-impact", "angle": "impact-overstated", "result": "survived", "reason": "data returned",
             "evidence_ids": ["route-source"]}]}],
        "calibration": [{"rater": r, "scores": dict(expert.ANCHOR_KEY)} for r in ("rater-1", "rater-2")],
        "ratings": [{"finding": "F-001", "rater": r, "severity": "High", "reason": "cross-tenant read"}
                    for r in ("rater-1", "rater-2")],
        "reception": [{"persona": p, "actor": a, "stop_span": SPAN, "disposition": "no change: read to the end"}
                      for p, a in (("executive", "persona-exec"), ("engineer", "persona-eng"),
                                   ("auditor", "persona-audit"))],
        "qa": {"actor": "qa-1", "result": "pass"},
    }
    data["dependency_scan"] = {"tool": "deps_scan.py", "audit": True, "findings": 0, "not_run": 0}
    data["meta"]["assessor"] = "Test host (model)"
    data["perspectives"] = [{"name": n, "result": "N/A - synthetic"} for n in contract_check.perspective_names()]
    data.setdefault("limitations", []).extend(["assessment.pdf not produced: no PDF engine",
                                               "invariant ledger and close-check not machine-checked "
                                               "(no invariant_ledger opt-in)"])
    return data


class ExpertDerivationTests(unittest.TestCase):
    def setUp(self):
        self.data = complete_data()

    def gaps(self, data=None):
        return expert.derive_expert(data or self.data)["gaps"]

    def test_complete_record_meets_every_gate(self):
        state = expert.derive_expert(self.data)
        self.assertEqual(state["gaps"], [])
        self.assertEqual(state["status"], "complete")
        self.assertEqual(state["counts"]["redundant_cells"], 3)
        self.assertFalse(state["cross_engine"])

    def test_each_shortcut_holds_the_assessment(self):
        x = self.data["expert"]
        cases = {
            "verifier_is_discoverer": lambda: x["discovery"].append(
                {"actor": "synthetic-conditions", "angle": "entry-first", "cells": ["order-detail"],
                 "candidates": ["F-001"], "raw_candidates": 1}),
            "cell_not_redundant": lambda: [d["cells"].remove("admin-route") for d in x["discovery"][1:]],
            "panel_missing": lambda: x["panels"].clear(),
            "panel_too_small": lambda: x["panels"][0]["skeptics"].pop(),
            "variant_missing": lambda: x["variants"].clear(),
            "variant_hits_unaccounted": lambda: x["variants"][0].__setitem__("hits", 2),
            "rater_not_calibrated": lambda: x["calibration"][0]["scores"].__setitem__("A1", "Low"),
            "severity_not_double_rated": lambda: x["ratings"].pop(),
            "severity_disagreement_unresolved": lambda: x["ratings"][1].__setitem__("severity", "Medium"),
            "reception_missing": lambda: x["reception"].pop(),
            "qa_missing": lambda: x.pop("qa"),
            "qa_imbalance": lambda: x["qa"].__setitem__("result", "imbalance"),
            "actor_reused_across_roles": lambda: x["spawns"].append(
                dict(x["spawns"][-1], id="S-99", role="rater")),
            "spawns_over_ceiling": lambda: x["consent"].__setitem__("ceiling", 3),
            "recon_not_redundant": lambda: x["recon"].pop(),
            "recon_disagreements_open": lambda: x["reconciliation"].__setitem__("resolved", 0),
            "omission_missing": lambda: x["omission"].clear(),
            "cwe_missing": lambda: self.data["findings"][0].pop("cwe"),
            "mode_without_host_preflight": lambda: x["preflight"][0].__setitem__("exit", 1),
            "panel_refutation_unresolved": lambda: [s.__setitem__("result", "refuted") for s in x["panels"][0]["skeptics"]],
        }
        pristine = copy.deepcopy(self.data)
        for code, mutate in cases.items():
            with self.subTest(code):
                self.data = copy.deepcopy(pristine)
                x = self.data["expert"]
                mutate()
                state = expert.derive_expert(self.data)
                self.assertEqual(state["status"], "held")
                self.assertTrue(any(g.split(":")[0] == code for g in state["gaps"]), state["gaps"])

    def test_resolution_and_exclusion_close_their_gates(self):
        x = self.data["expert"]
        x["ratings"][1]["severity"] = "Medium"
        x["severity_resolutions"] = [{"finding": "F-001", "reason": "re-read: no precondition, High stands"}]
        for skeptic in x["panels"][0]["skeptics"]:
            skeptic["result"] = "refuted"
        x["panels"][0]["resolution"] = "refutations rest on a guard that is not registered on this route"
        self.assertEqual(self.gaps(), [])

    def test_single_agent_is_degraded_never_complete(self):
        self.data["expert"]["mode"] = "single-agent"
        self.assertEqual(expert.derive_expert(self.data)["status"], "degraded")

    def test_cross_engine_requires_engine_spread(self):
        x = self.data["expert"]
        x["consent"]["engines"].append("codex")
        x["preflight"].append({"engine": "codex", "exit": 0, "record": "run/engines.md"})
        gaps = self.gaps()
        self.assertIn("panel_monoculture:F-001", gaps)
        self.assertTrue(any(g.startswith("cell_not_redundant") for g in gaps))
        for spawn in x["spawns"]:
            if spawn["actor"] in ("disc-sink", "skeptic-impact"):
                spawn["engine"] = "codex"
        self.assertEqual(self.gaps(), [])

    def test_calibration_tolerates_one_adjacent_miss_only(self):
        key = dict(expert.ANCHOR_KEY)
        self.assertTrue(expert.calibrated(key))
        self.assertTrue(expert.calibrated(dict(key, A2="High")))
        self.assertFalse(expert.calibrated(dict(key, A2="High", A4="Medium")))
        self.assertFalse(expert.calibrated(dict(key, A1="Low")))
        self.assertFalse(expert.calibrated({k: v for k, v in key.items() if k != "A9"}))

    def test_malformed_records_are_errors(self):
        for mutate in (lambda x: x.__setitem__("version", 2),
                       lambda x: x["spawns"][0].__setitem__("role", "boss"),
                       lambda x: x["discovery"][0].__setitem__("angle", "vibes"),
                       lambda x: x["panels"][0]["skeptics"][0].__setitem__("result", "maybe")):
            data = copy.deepcopy(self.data)
            mutate(data["expert"])
            with self.assertRaises(ValueError):
                expert.derive_expert(data)


class ExpertAuditTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="security-scan-expert-"))
        self.addCleanup(shutil.rmtree, self.out, True)
        self.data = complete_data()
        run = self.out / "run" / "spawns"
        run.mkdir(parents=True)
        (self.out / "run" / "gate.md").write_text("consent and preflight exit=0\n")
        for sid, _, _ in SPAWNS:
            (run / f"{sid}.prompt.md").write_text("prompt\n")
            (run / f"{sid}.return.md").write_text("return\n")
        self.write()

    def write(self):
        (self.out / "findings.json").write_text(json.dumps(self.data))
        (self.out / "deps.json").write_text('{"inventory": [], "findings": [], "not_run": []}\n')
        (self.out / "evidence").mkdir(exist_ok=True)
        self.assertEqual(render.main([str(self.out / "findings.json"), "--out", str(self.out), "--no-pdf"]), 0)

    def result(self):
        return expert_audit.audit(json.loads((self.out / "findings.json").read_text()), self.out, pdf=False)

    def test_complete_run_passes_and_report_shows_method_and_cwe(self):
        result = self.result()
        self.assertEqual(result["gaps"], [])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(expert_audit.main([str(self.out), "--no-pdf"]), 0)
        page = (self.out / "assessment.html").read_text()
        self.assertIn("expert-summary", page)
        self.assertIn("https://cwe.mitre.org/data/definitions/639.html", page)
        self.assertIn("expert-summary", (self.out / "dashboard.html").read_text())

    def test_missing_run_file_and_absent_stop_span_hold(self):
        (self.out / "run" / "spawns" / "S-09.return.md").unlink()
        self.data["expert"]["reception"][0]["stop_span"] = "A sentence the report never contained."
        self.write()
        gaps = self.result()["gaps"]
        self.assertIn("run_file_missing:spawn:S-09:return:run/spawns/S-09.return.md", gaps)
        self.assertIn("reception_span_not_in_report:executive", gaps)
        self.assertEqual(expert_audit.main([str(self.out), "--no-pdf"]), 3)

    def test_paths_outside_run_are_refused(self):
        self.data["expert"]["spawns"][0]["prompt"] = "../outside.md"
        self.write()
        self.assertTrue(any(g.startswith("run_file_missing:spawn:S-01:prompt") for g in self.result()["gaps"]))

    def test_invalid_cwe_is_a_schema_error(self):
        self.data["findings"][0]["cwe"] = "639"
        (self.out / "findings.json").write_text(json.dumps(self.data))
        (self.out / "deps.json").write_text('{"inventory": [], "findings": [], "not_run": []}\n')
        (self.out / "evidence").mkdir(exist_ok=True)
        self.assertEqual(render.main([str(self.out / "findings.json"), "--out", str(self.out), "--no-pdf"]), 2)


if __name__ == "__main__":
    unittest.main()
