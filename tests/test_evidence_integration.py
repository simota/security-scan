"""Offline byte checks and gating using only synthetic files and local Git objects."""
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/security-scan/scripts'
sys.path.insert(0, str(SCRIPTS))
import evidence_integrity as evidence
import reproduction as repro
import verification
import verification_workflow as workflow


class EvidenceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.artifacts = self.root / 'evidence'
        self.artifacts.mkdir()
        self.env = {'PATH': os.defpath, 'HOME': str(self.root), 'GIT_CONFIG_NOSYSTEM': '1',
                    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
                    'GIT_AUTHOR_NAME': 'Synthetic fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                    'GIT_COMMITTER_NAME': 'Synthetic fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid',
                    'GIT_AUTHOR_DATE': '2026-01-01T00:00:00+00:00',
                    'GIT_COMMITTER_DATE': '2026-01-01T00:00:00+00:00'}
        self.git('init', '-q')
        self.before_bytes = b'# Synthetic before source. Never imported.\n'
        (self.repo / 'source.py').write_bytes(self.before_bytes)
        self.git('add', 'source.py')
        self.git('commit', '-qm', 'synthetic before')
        self.before = self.git('rev-parse', 'HEAD').strip()
        (self.repo / 'source.py').write_bytes(b'# Synthetic after source. Never imported.\n')
        self.git('add', 'source.py')
        self.git('commit', '-qm', 'synthetic after')
        self.after = self.git('rev-parse', 'HEAD').strip()
        text = (ROOT / 'examples/findings.verification.sample.json').read_text()
        self.data = json.loads(text.replace('1' * 40, self.before).replace('2' * 40, self.after))
        self.data['evidence_integrity'] = {'required': True}
        for record in self.data['evidence']:
            payload = self.before_bytes if record['kind'] == 'source' else ('Synthetic recorded log ' + record['id'] + '\n').encode()
            record['location'] = record['id'] + '.txt'
            (self.artifacts / record['location']).write_bytes(payload)
            record['sha256'] = hashlib.sha256(payload).hexdigest()
            if record['kind'] == 'source':
                record['source_path'] = 'source.py'
        self.finding = self.data['findings'][0]
        self.path = self.root / 'findings.json'
        self.save()

    def git(self, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(self.repo)] + list(args), env=self.env,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=10).stdout

    def save(self):
        self.path.write_text(json.dumps(self.data))

    def check(self):
        return evidence.verify_evidence(self.data, self.artifacts, repository=self.repo)

    def state(self, checked=None):
        return verification.derive_verification(self.data, integrity=checked)[self.finding['id']]

    def test_required_missing_check_is_incomplete_not_runtime_or_fixed(self):
        state = self.state()
        self.assertEqual(state['integrity']['status'], 'declared')
        self.assertEqual(state['level'], 'incomplete')
        self.assertEqual(state['retest'], 'incomplete')
        self.assertIn('evidence_integrity_unchecked', state['gaps'])

    def test_actual_bytes_and_git_source_enable_only_record_support(self):
        checked = self.check()
        state = self.state(checked)
        self.assertEqual(state['integrity']['status'], 'checked')
        self.assertEqual(state['integrity']['bytes_checked'], 5)
        self.assertEqual(state['integrity']['sources_checked'], 1)
        self.assertEqual(state['level'], 'runtime_supported')
        runtime = [x for x in checked.receipt['items'] if x['evidence_id'] == 'test-before'][0]
        self.assertEqual(runtime['source'], 'declared')
        self.assertEqual(self.state()['level'], 'incomplete')
        artifact_root = os.environ.get('SECURITY_SCAN_REPORT_ARTIFACTS')
        if artifact_root:
            # Retain only this test's invented files and local Git objects. No
            # executor configuration, paths, credentials or real app data.
            out = Path(artifact_root) / 'synthetic-evidence-integrity'
            out.mkdir(parents=True, exist_ok=True)
            (out / 'receipt.json').write_text(json.dumps(checked.receipt, indent=2) + '\n')
            (out / 'findings.json').write_text(json.dumps(self.data, indent=2) + '\n')
            shutil.copytree(self.artifacts, out / 'evidence', dirs_exist_ok=True)
            bare = out / 'repository'
            (bare / 'refs').mkdir(parents=True, exist_ok=True)
            shutil.copytree(self.repo / '.git' / 'objects', bare / 'objects', dirs_exist_ok=True)
            (bare / 'HEAD').write_text('ref: refs/heads/unborn\n')
            (bare / 'config').write_text('[core]\n\tbare = true\n\trepositoryformatversion = 0\n')
            (out / 'README.txt').write_text('Synthetic byte-verification test fixture only. No application test was executed.\n'
                'Use evidence_integrity.py verify findings.json --root evidence --repository repository --out NEW_RECEIPT.json.\n'
                'The stored receipt is historical; replay the check to inspect current bytes.\n')

    def test_historical_or_forged_receipt_cannot_grant_fresh_check(self):
        receipt = self.check().receipt
        self.assertEqual(self.state(receipt)['level'], 'incomplete')
        self.data['_evidence_integrity'] = receipt
        self.finding['_verification'] = {'level': 'runtime_supported', 'integrity': {'status': 'checked'}}
        self.assertEqual(self.state()['level'], 'incomplete')

    def test_mutated_declared_log_stales_result(self):
        checked = self.check()
        self.data['test_runs'][0]['observed'] += ' changed'
        self.assertFalse(checked.matches(self.data))
        self.assertEqual(self.state(checked)['integrity']['status'], 'incomplete')
        self.assertEqual(self.state(checked)['level'], 'incomplete')

    def test_artifact_change_is_found_by_fresh_check(self):
        self.check()
        (self.artifacts / 'test-before.txt').write_bytes(b'Changed after original check')
        state = self.state(self.check())
        self.assertEqual(state['level'], 'incomplete')
        self.assertIn('evidence_integrity_failed', state['gaps'])

    def test_optional_legacy_keeps_recorded_meaning_without_new_credit(self):
        self.data.pop('evidence_integrity')
        state = self.state()
        self.assertEqual(state['level'], 'runtime_supported')
        self.assertEqual(state['integrity']['status'], 'declared')
        self.assertEqual(state['integrity']['bytes_checked'], 0)
        (self.artifacts / 'test-before.txt').write_bytes(b'Changed')
        self.assertEqual(self.state(self.check())['level'], 'incomplete')

    def test_policy_shape_rejected(self):
        for value in ({'required': 'true'}, {'required': 1}, {'required': True, 'receipt': {}}, None):
            with self.subTest(value=value):
                self.data['evidence_integrity'] = value
                with self.assertRaises(ValueError):
                    self.state()

    def test_workflow_policy_change_stales_prior_round(self):
        self.data.pop('evidence_integrity')
        workflow.initialize(self.data, self.finding['id'], 'coordinator')
        self.data['evidence_integrity'] = {'required': True}
        self.assertEqual(workflow.derive_workflow(self.data, self.finding)['status'], 'stale')

    def test_required_workflow_decision_is_held_then_recheck_can_complete(self):
        reference = copy.deepcopy(self.finding['verification'])
        self.finding.pop('verification')
        self.finding.pop('remediation')
        self.finding.update(status='Open', confidence='Suspected')
        self.finding['validation'] = {'verdict': 'Unverified', 'method': '', 'evidence': ''}
        workflow.initialize(self.data, self.finding['id'], 'coordinator')
        def output(stage):
            state = workflow.derive_workflow(self.data, self.finding)
            actor = {'conditions': 'author', 'falsification': 'independent', 'decision': 'judge'}[stage]
            submission = {'stage': stage, 'actor': actor, 'status': 'complete', 'summary': 'Synthetic observations',
                          'evidence_ids': ['source-before'], 'input_digest': state['input_digest']}
            if stage == 'conditions':
                submission.update(claims=reference['claims'], environment=reference['environment'])
            elif stage == 'falsification':
                reviews = copy.deepcopy(reference['reviews'])
                reviews[0]['reviewer'] = 'independent'
                submission.update(checks=reference['falsification'], reviews=reviews)
            else:
                submission.update(validation={'verdict': 'Valid', 'method': 'Synthetic review', 'evidence': 'Synthetic checked source'}, run_ids=['before'])
            return submission
        for stage in ('conditions', 'falsification'):
            self.assertEqual(workflow.submit(self.data, self.finding['id'], output(stage))['status'], 'ready')
        held = workflow.submit(self.data, self.finding['id'], output('decision'))
        self.assertEqual(held['status'], 'held')
        self.assertIn('evidence_integrity_unchecked', held['reasons'])
        self.assertEqual(self.finding['validation']['verdict'], 'Unverified')
        checked = self.check()
        workflow.resume(self.data, self.finding['id'], 'coordinator', 'Fresh file checks available', integrity=checked)
        done = workflow.submit(self.data, self.finding['id'], output('decision'), integrity=checked)
        self.assertEqual(done['status'], 'complete')
        self.assertEqual(workflow.derive_workflow(self.data, self.finding)['status'], 'held')

    def plan(self):
        result = json.loads((ROOT / 'examples/reproduction.plan.sample.json').read_text())
        result['after']['commit'] = self.after
        return result

    def test_repro_required_source_check_precedes_generation(self):
        with self.assertRaises(ValueError):
            repro.generate(self.path, self.finding['id'], self.plan(), self.root / 'bundle')
        self.assertFalse((self.root / 'bundle').exists())

    def test_checked_bundle_requires_fresh_inputs_and_stays_mocked(self):
        bundle = self.root / 'bundle'
        repro.generate(self.path, self.finding['id'], self.plan(), bundle,
                       evidence_root=self.artifacts, evidence_repository=self.repo)
        with self.assertRaises(ValueError):
            repro.verify(bundle, self.path)
        result = repro.run(bundle, self.path, self.root / 'result', evidence_root=self.artifacts, evidence_repository=self.repo)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['boundary'], 'mocked')
        direct = subprocess.run([sys.executable, '-I', '-S', str(bundle / 'run.py'), '--findings', str(self.path)],
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(direct.returncode, 0)
        (self.artifacts / 'source-before.txt').write_bytes(self.before_bytes + b'x')
        with self.assertRaises(ValueError):
            repro.verify(bundle, self.path, self.artifacts, self.repo)

    def test_repro_post_run_evidence_change_prevents_current_success(self):
        bundle = self.root / 'bundle'
        repro.generate(self.path, self.finding['id'], self.plan(), bundle, self.artifacts, self.repo)
        original_run = repro.subprocess.run
        def run_then_change(*args, **kwargs):
            result = original_run(*args, **kwargs)
            if args and isinstance(args[0], list) and '-I' in args[0]:
                (self.artifacts / 'source-before.txt').write_bytes(self.before_bytes + b'x')
            return result
        with patch.object(repro.subprocess, 'run', side_effect=run_then_change):
            result = repro.run(bundle, self.path, self.root / 'result', evidence_root=self.artifacts, evidence_repository=self.repo)
        self.assertEqual(result['status'], 'stale')
        self.assertFalse(result['repeatable'])


if __name__ == '__main__':
    unittest.main()
