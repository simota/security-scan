"""Expert gates over inert records and disposable local evidence repositories."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_expert as fixture
import evidence_integrity
import expert
import expert_audit
import render
import verification_workflow as workflow


def complete_round(data, actors=None, integrity=None, restart=False, extra_review=None):
    """Use the real workflow API, never forge journal events or their seals."""
    actors = actors or {}
    record = data.pop("expert")
    try:
        if restart:
            workflow.invalidate(data, "F-001", "coordinator", "Fresh synthetic review", integrity)
            workflow.resume(data, "F-001", "coordinator", "Restart synthetic review", integrity)
        else:
            data["findings"][0].pop("verification_workflow", None)
            workflow.initialize(data, "F-001", "coordinator", integrity=integrity)
        for stage in workflow.STAGES:
            output = fixture.benchmark.submission(data, stage)
            output["actor"] = actors.get(stage, output["actor"])
            if stage == "falsification":
                output["reviews"][0]["reviewer"] = output["actor"]
                if extra_review:
                    output["reviews"].append(dict(output["reviews"][0], reviewer=extra_review))
            workflow.submit(data, "F-001", output, integrity=integrity)
    finally:
        data["expert"] = record


def add_skeptic(data, actor="skeptic-third", angle="unreachable", result="survived"):
    record = data["expert"]
    record["spawns"].append(dict(record["spawns"][8], id="S-" + actor, actor=actor))
    record["panels"][0]["skeptics"].append(
        dict(record["panels"][0]["skeptics"][0], actor=actor, angle=angle, result=result))


class ExpertActorAssuranceTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture.complete_data()

    def assert_held(self, *gaps):
        state = expert.derive_expert(self.data)
        self.assertEqual(state["status"], "held")
        for gap in gaps:
            self.assertIn(gap, state["gaps"])
        return state

    def test_falsification_spawn_required_at_every_severity(self):
        for severity in expert.SEVERITY_ORDER:
            with self.subTest(severity=severity):
                self.data = fixture.complete_data()
                self.data["findings"][0]["severity"] = severity
                for rating in self.data["expert"]["ratings"]:
                    rating["severity"] = severity
                complete_round(self.data)
                self.data["expert"]["spawns"] = [s for s in self.data["expert"]["spawns"]
                                                    if s["role"] != "falsification"]
                self.assert_held("falsification_actor_not_spawned:F-001:synthetic-challenge")

    def test_qa_challenger_alias_is_not_independent(self):
        complete_round(self.data, {"falsification": " QA-1 "})
        self.assert_held("falsification_actor_not_spawned:F-001:qa-1", "qa_not_independent")

    def test_qa_decision_and_additional_review_are_participation(self):
        complete_round(self.data, {"decision": " QA-1 "})
        self.assert_held("qa_not_independent")
        self.data = fixture.complete_data()
        complete_round(self.data, extra_review=" QA-1 ")
        self.assert_held("reviewer_not_spawned:F-001:qa-1", "qa_not_independent")

    def test_qa_cannot_be_discovery_consolidator(self):
        self.data["three_pass"]["discovery"]["actor"] = " QA-1 "
        complete_round(self.data)
        self.assert_held("qa_not_independent")

    def test_qa_cannot_be_discovery_consolidator_in_retained_snapshots(self):
        for restart in (False, True):
            with self.subTest(snapshot_from_restart=restart):
                self.data = fixture.complete_data()
                original = self.data["three_pass"]["discovery"]["actor"]
                self.data["three_pass"]["discovery"]["actor"] = " QA-1 "
                complete_round(self.data, restart=restart)
                self.assert_held("qa_not_independent")
                self.data["three_pass"]["discovery"]["actor"] = original
                complete_round(self.data, restart=True)
                state = self.assert_held("qa_not_independent")
                self.assertNotIn("three_pass_incomplete", state["gaps"])

    def test_stage_roles_use_current_round_but_qa_checks_history(self):
        complete_round(self.data, {"falsification": " QA-1 "})
        complete_round(self.data, restart=True)
        state = self.assert_held("qa_not_independent")
        self.assertFalse(any(g.startswith("falsification_actor_not_spawned") for g in state["gaps"]))
        self.assertNotIn("three_pass_incomplete", state["gaps"])

    def test_qa_cannot_be_an_additional_reviewer_in_an_earlier_round(self):
        complete_round(self.data, extra_review=" QA-1 ")
        complete_round(self.data, restart=True)
        state = self.assert_held("qa_not_independent")
        self.assertFalse(any(g.startswith("reviewer_not_spawned") for g in state["gaps"]))

    def test_qa_cannot_be_a_reviewer_in_retained_previous_proof(self):
        for key in ("reviewer", "reviews"):
            with self.subTest(previous_role=key):
                self.data = fixture.complete_data()
                proof = self.data["findings"][0]["verification"]
                if key == "reviewer":
                    proof["reviewer"] = " QA-1 "
                else:
                    proof["reviews"].append(dict(proof["reviews"][0], reviewer=" QA-1 "))
                complete_round(self.data)
                state = self.assert_held("qa_not_independent")
                self.assertNotIn("three_pass_incomplete", state["gaps"])

    def test_registration_and_role_rows_share_actor_normalization(self):
        for spawn in self.data["expert"]["spawns"]:
            spawn["actor"] = " " + spawn["actor"].upper() + " "
        unchanged = copy.deepcopy(self.data)
        self.assertEqual(expert.derive_expert(self.data)["status"], "complete")
        self.assertEqual(self.data, unchanged)

    def test_actor_alias_cannot_create_a_second_discoverer(self):
        discovery = self.data["expert"]["discovery"]
        discovery.pop()
        discovery[1]["actor"] = " DISC-ENTRY "
        state = self.assert_held("cell_not_redundant:order-detail")
        self.assertEqual(state["counts"]["redundant_cells"], 0)

    def test_one_actor_cannot_receive_as_three_personas(self):
        for row in self.data["expert"]["reception"]:
            row["actor"] = " PERSONA-EXEC "
        self.assert_held("reception_actor_reused:persona-exec")

    def test_declared_role_alias_cannot_hide_qa_participation(self):
        self.data["expert"]["spawns"].append(
            dict(self.data["expert"]["spawns"][-1], id="S-extra", actor=" QA-1 ", role="persona"))
        self.assert_held("actor_reused_across_roles:qa-1", "qa_not_independent")

    def test_aliases_cannot_supply_independent_recon_or_severity_votes(self):
        mutations = (
            ("recon_not_redundant", lambda record: record["recon"][1].update(actor=" RECON-A ")),
            ("severity_not_double_rated:F-001", lambda record: record["ratings"][1].update(rater=" RATER-1 ")),
        )
        for gap, mutate in mutations:
            with self.subTest(gap=gap):
                self.data = fixture.complete_data()
                mutate(self.data["expert"])
                self.assert_held(gap)

    def test_normalized_actor_cannot_supply_cross_engine_independence(self):
        record = self.data["expert"]
        record["consent"]["engines"].append("codex")
        record["preflight"].append({"engine": "codex", "exit": 0, "record": "run/gate.md"})
        entry = next(spawn for spawn in record["spawns"] if spawn["actor"] == "disc-entry")
        record["spawns"].append(dict(entry, id="S-extra", actor=" DISC-ENTRY ", engine="codex"))
        for row in record["discovery"]:
            row["actor"] = "disc-entry" if row["angle"] == "entry-first" else " DISC-ENTRY "
        self.assert_held("actor_reused_across_roles:disc-entry", "cell_not_redundant:order-detail")

    def test_duplicate_persona_record_is_not_extra_reception_credit(self):
        reception = self.data["expert"]["reception"]
        reception.append(copy.deepcopy(reception[0]))
        with self.assertRaisesRegex(ValueError, "duplicate persona"):
            expert.derive_expert(self.data)


class ExpertPanelAssuranceTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture.complete_data()

    def test_repeating_surviving_vote_cannot_erase_refuted_majority(self):
        skeptics = self.data["expert"]["panels"][0]["skeptics"]
        for skeptic in skeptics:
            skeptic["result"] = "refuted"
        add_skeptic(self.data)
        state = expert.derive_expert(self.data)
        self.assertIn("panel_refutation_unresolved:F-001", state["gaps"])
        self.assertEqual(state["counts"]["skeptic_refuted"], 2)
        self.assertEqual(state["counts"]["skeptic_survived"], 1)
        skeptics.extend([copy.deepcopy(skeptics[-1]), copy.deepcopy(skeptics[-1])])
        with self.assertRaisesRegex(ValueError, "duplicate panel actor"):
            expert.derive_expert(self.data)

    def test_case_whitespace_alias_is_duplicate_panel_member(self):
        skeptics = self.data["expert"]["panels"][0]["skeptics"]
        skeptics[1]["actor"] = " SKEPTIC-DEFENSE "
        with self.assertRaisesRegex(ValueError, "duplicate panel actor"):
            expert.derive_expert(self.data)

    def test_duplicate_panel_and_angle_are_rejected(self):
        self.data["expert"]["panels"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate code finding"):
            expert.derive_expert(self.data)
        self.data = fixture.complete_data()
        self.data["expert"]["panels"][0]["skeptics"][1]["angle"] = "defense-exists"
        with self.assertRaisesRegex(ValueError, "duplicate panel angle"):
            expert.derive_expert(self.data)

    def test_two_or_three_distinct_members_pass_but_four_hold(self):
        self.assertEqual(expert.derive_expert(self.data)["status"], "complete")
        add_skeptic(self.data)
        self.assertEqual(expert.derive_expert(self.data)["status"], "complete")
        add_skeptic(self.data, "skeptic-fourth", "not-shipped")
        state = expert.derive_expert(self.data)
        self.assertEqual(state["status"], "held")
        self.assertIn("panel_too_large:F-001", state["gaps"])

    def test_unregistered_member_supplies_no_vote(self):
        self.data["expert"]["panels"][0]["skeptics"][0]["actor"] = "never-spawned"
        state = expert.derive_expert(self.data)
        self.assertEqual(state["status"], "held")
        self.assertEqual(state["counts"]["skeptic_survived"], 1)
        self.assertIn("panel_too_small:F-001", state["gaps"])

    def test_panel_evidence_uses_registered_unique_current_references(self):
        for refs, message in ((["missing-source"], "unknown ID"),
                              (["route-source", "route-source"], "duplicate ID"),
                              ([], "at least one evidence")):
            with self.subTest(refs=refs):
                data = copy.deepcopy(self.data)
                data["expert"]["panels"][0]["skeptics"][0]["evidence_ids"] = refs
                with self.assertRaisesRegex(ValueError, message):
                    expert.derive_expert(data)
        old = dict(self.data["evidence"][0], id="old-source", commit="2" * 40)
        self.data["evidence"].append(old)
        self.data["expert"]["panels"][0]["skeptics"][0]["evidence_ids"] = ["old-source"]
        with self.assertRaisesRegex(ValueError, "required commit/worktree pin"):
            expert.derive_expert(self.data)

    def test_unproven_may_have_no_evidence_but_is_counted_as_residual(self):
        self.data["expert"]["panels"][0]["skeptics"][0].update(result="unproven", evidence_ids=[])
        state = expert.derive_expert(self.data)
        self.assertEqual(state["status"], "complete")
        self.assertEqual(state["counts"]["skeptic_unproven"], 1)

    def test_panel_evidence_rejects_a_different_worktree_pin(self):
        record = dict(self.data["evidence"][0], id="other-worktree", diff_sha256="a" * 64)
        self.data["evidence"].append(record)
        self.data["expert"]["panels"][0]["skeptics"][0]["evidence_ids"] = [record["id"]]
        with self.assertRaisesRegex(ValueError, "required commit/worktree pin"):
            expert.derive_expert(self.data)


class ExpertAuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="expert-integrity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo, self.out = self.root / "repo", self.root / "out"
        self.repo.mkdir()
        (self.out / "evidence").mkdir(parents=True)
        self.env = dict(PATH=os.defpath, HOME=str(self.root), GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
                        GIT_AUTHOR_NAME="Synthetic fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="Synthetic fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.data = fixture.complete_data()
        self.git("init", "-q")
        for record in self.data["evidence"]:
            name = record["id"] + ".txt"
            payload = ("Synthetic inert source " + record["id"] + "\n").encode()
            (self.repo / name).write_bytes(payload)
            (self.out / "evidence" / name).write_bytes(payload)
            record.update(location="evidence/" + name, source_path=name,
                          sha256=hashlib.sha256(payload).hexdigest())
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic evidence")
        commit = self.git("rev-parse", "HEAD").strip()
        self.data["assessment"]["commit"] = self.data["meta"]["commit"] = commit
        for record in self.data["evidence"]:
            record["commit"] = commit
        self.data["evidence_integrity"] = {"required": True}
        self.checked = evidence_integrity.verify_evidence(self.data, self.out, repository=self.repo)
        self.assertEqual(self.checked.receipt["status"], "matched")
        complete_round(self.data, integrity=self.checked)
        (self.out / "run" / "spawns").mkdir(parents=True)
        (self.out / "run" / "gate.md").write_text("Synthetic consent and preflight\n")
        for spawn in self.data["expert"]["spawns"]:
            for key in ("prompt", "return"):
                (self.out / spawn[key]).write_text("Synthetic inert worker record\n")
        self.save_and_render()

    def git(self, *args):
        return subprocess.run(["/usr/bin/git", "-C", str(self.repo), *args], env=self.env,
                              check=True, capture_output=True, text=True, timeout=10).stdout

    def save_and_render(self):
        (self.out / "findings.json").write_text(json.dumps(self.data))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(render.main([str(self.out / "findings.json"), "--out", str(self.out),
                                          "--no-pdf", "--evidence-root", str(self.out),
                                          "--evidence-repository", str(self.repo)]), 0)

    def audit_cli(self, roots=True, repository=True):
        args = [str(self.out), "--no-pdf"]
        if roots:
            args += ["--evidence-root", str(self.out)]
        if repository:
            args += ["--evidence-repository", str(self.repo)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = expert_audit.main(args)
        return result, json.loads(stdout.getvalue()) if stdout.getvalue() else None, stderr.getvalue()

    def test_required_integrity_passes_end_to_end_with_explicit_roots(self):
        code, result, stderr = self.audit_cli()
        self.assertEqual((code, result["status"], stderr), (0, "complete", ""))
        direct = expert_audit.audit(self.data, self.out, pdf=False,
                                    evidence_root=self.out, evidence_repository=self.repo)
        self.assertEqual(direct["gaps"], [])
        self.assertTrue(self.data["evidence_integrity"]["required"])

    def test_missing_roots_and_missing_repository_hold_required_run(self):
        for roots in (False, True):
            with self.subTest(roots=roots):
                code, result, stderr = self.audit_cli(roots=roots, repository=False)
                self.assertEqual((code, result["status"]), (3, "held"))
                self.assertIn("three_pass_incomplete", stderr)

    def test_repository_without_evidence_root_is_usage_error(self):
        with self.assertRaises(SystemExit) as exc:
            self.audit_cli(roots=False)
        self.assertEqual(exc.exception.code, 2)
        with self.assertRaisesRegex(ValueError, "requires --evidence-root"):
            expert_audit.audit(self.data, self.out, pdf=False, evidence_repository=self.repo)

    def test_saved_receipt_cannot_replace_a_fresh_check(self):
        self.data["_evidence_integrity"] = self.checked.receipt
        (self.out / "findings.json").write_text(json.dumps(self.data))
        code, result, _ = self.audit_cli(roots=False, repository=False)
        self.assertEqual((code, result["status"]), (3, "held"))
        (self.out / "evidence" / "route-source.txt").write_text("Changed synthetic bytes\n")
        code, result, stderr = self.audit_cli()
        self.assertEqual((code, result["status"]), (3, "held"))
        self.assertIn("skeptic_evidence_integrity_failed:F-001", stderr)

    def test_missing_source_artifact_holds_even_after_prior_success(self):
        self.assertEqual(self.audit_cli()[0], 0)
        (self.out / "evidence" / "policy-source.txt").unlink()
        code, result, stderr = self.audit_cli()
        self.assertEqual((code, result["status"]), (3, "held"))
        self.assertIn("three_pass_incomplete", stderr)

    def test_wrong_source_repository_holds(self):
        self.repo = self.root / "unrelated-repo"
        self.repo.mkdir()
        self.git("init", "-q")
        code, result, _ = self.audit_cli()
        self.assertEqual((code, result["status"]), (3, "held"))

    def add_panel_only_source(self):
        record = dict(self.data["evidence"][0], id="panel-only-source",
                      location="evidence/panel-only-source.txt")
        payload = (self.out / self.data["evidence"][0]["location"]).read_bytes()
        (self.out / record["location"]).write_bytes(payload)
        self.data["evidence"].append(record)
        self.data["expert"]["panels"][0]["skeptics"][0]["evidence_ids"] = [record["id"]]
        checked = evidence_integrity.verify_evidence(self.data, self.out, repository=self.repo)
        complete_round(self.data, integrity=checked)
        return record

    def test_evidence_used_only_by_skeptics_also_requires_fresh_integrity(self):
        record = self.add_panel_only_source()
        self.save_and_render()
        self.assertEqual(self.audit_cli()[0], 0)
        (self.out / record["location"]).write_text("Changed panel-only bytes\n")
        code, result, stderr = self.audit_cli()
        self.assertEqual((code, result["status"]), (3, "held"))
        self.assertIn("skeptic_evidence_integrity_failed:F-001:skeptic-defense", stderr)
        self.assertNotIn("three_pass_incomplete", stderr)

    def test_partial_integrity_context_cannot_cover_panel_only_evidence(self):
        record = self.add_panel_only_source()
        selected = [item["id"] for item in self.data["evidence"] if item["id"] != record["id"]]
        checked = evidence_integrity.verify_evidence(self.data, self.out, repository=self.repo,
                                                    evidence_ids=selected)
        state = expert.derive_expert(self.data, integrity=checked)
        self.assertEqual(state["status"], "held")
        self.assertIn("skeptic_evidence_integrity_failed:F-001:skeptic-defense", state["gaps"])
        self.assertNotIn("three_pass_incomplete", state["gaps"])

    def test_observed_panel_failure_holds_without_required_integrity(self):
        record = self.add_panel_only_source()
        self.data.pop("evidence_integrity")
        complete_round(self.data)
        self.assertEqual(expert.derive_expert(self.data)["status"], "complete")
        (self.out / record["location"]).unlink()
        checked = evidence_integrity.verify_evidence(self.data, self.out, repository=self.repo)
        state = expert.derive_expert(self.data, integrity=checked)
        self.assertEqual(state["status"], "held")
        self.assertIn("skeptic_evidence_integrity_failed:F-001:skeptic-defense", state["gaps"])
        self.assertNotIn("three_pass_incomplete", state["gaps"])

    def test_participant_qa_holds_with_fresh_integrity_and_rendered_report(self):
        complete_round(self.data, {"falsification": "qa-1"}, integrity=self.checked)
        self.save_and_render()
        code, result, stderr = self.audit_cli()
        self.assertEqual((code, result["status"]), (3, "held"))
        self.assertIn("qa_not_independent", stderr)

    def test_duplicate_votes_are_cli_schema_error(self):
        skeptics = self.data["expert"]["panels"][0]["skeptics"]
        skeptics.append(copy.deepcopy(skeptics[0]))
        (self.out / "findings.json").write_text(json.dumps(self.data))
        code, result, stderr = self.audit_cli()
        self.assertEqual((code, result), (2, None))
        self.assertIn("duplicate panel actor", stderr)


if __name__ == "__main__":
    unittest.main()
