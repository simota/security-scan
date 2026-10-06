"""Offline journal/record tests, with no scans or target-application execution."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/security-scan/scripts'
sys.path.insert(0, str(SCRIPTS))
import verification_workflow as workflow


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / 'examples/findings.verification.sample.json').read_text())
        self.finding = self.data['findings'][0]
        self.reference = copy.deepcopy(self.finding['verification'])
        self.finding.pop('verification')
        self.finding.pop('remediation')
        self.finding.update(status='Open', confidence='Suspected')
        self.finding['validation'] = {'verdict': 'Unverified', 'evidence': '', 'method': ''}
        self.identifier = self.finding['id']

    def state(self):
        return workflow.derive_workflow(self.data, self.finding)

    def init(self):
        return workflow.initialize(self.data, self.identifier, 'coordinator')

    def output(self, stage=None, status='complete'):
        stage = stage or self.state()['next_stage']
        output = dict(stage=stage, actor={'conditions': 'author', 'falsification': 'independent', 'decision': 'judge'}[stage],
                      status=status, summary='Synthetic observations only.', evidence_ids=['source-before'],
                      input_digest=self.state()['input_digest'])
        if status == 'complete':
            if stage == 'conditions':
                output.update(claims=copy.deepcopy(self.reference['claims']), environment=copy.deepcopy(self.reference['environment']))
            elif stage == 'falsification':
                reviews = copy.deepcopy(self.reference['reviews'])
                reviews[0]['reviewer'] = 'independent'
                output.update(checks=copy.deepcopy(self.reference['falsification']), reviews=reviews)
            else:
                output.update(validation={'verdict': 'Valid', 'method': 'Synthetic review', 'evidence': 'Pinned synthetic evidence.'}, run_ids=[])
        return output

    def advance(self):
        return workflow.submit(self.data, self.identifier, self.output())

    def complete(self):
        self.init()
        for _ in range(3):
            self.advance()

    def test_candidate_reaches_decision_without_promoting_confidence(self):
        self.assertEqual(self.state()['status'], 'not_started')
        self.assertFalse(self.state()['opted_in'])
        self.init()
        self.assertEqual(self.state()['next_stage'], 'conditions')
        self.advance()
        self.assertEqual(self.finding['validation']['verdict'], 'Unverified')
        self.assertEqual(self.state()['next_stage'], 'falsification')
        self.advance()
        self.assertEqual(self.state()['next_stage'], 'decision')
        self.advance()
        self.assertEqual(self.state()['status'], 'complete')
        self.assertIsNone(self.state()['next_stage'])
        self.assertEqual(self.finding['validation']['verdict'], 'Valid')
        self.assertEqual(self.finding['confidence'], 'Suspected')
        self.assertEqual([s['stage'] for s in self.state()['stages']], list(workflow.STAGES))

    def test_legacy_workflow_extensions_are_not_interpreted(self):
        self.data.pop('schema_version')
        self.finding['verification_workflow'] = 'historical extension'
        self.assertFalse(self.state()['opted_in'])
        with self.assertRaisesRegex(workflow.WorkflowError, 'schema_version 2'):
            self.init()

    def test_out_of_order_missing_payload_and_unknown_fields_rejected_atomically(self):
        self.init()
        original = copy.deepcopy(self.data)
        for change in ({'stage': 'decision'}, {'claims': None}, {'execute': 'touch /tmp/never'}, {'status': 'skip'}):
            output = self.output()
            output.update(change)
            with self.subTest(change=change):
                with self.assertRaises(workflow.WorkflowError):
                    workflow.submit(self.data, self.identifier, output)
                self.assertEqual(self.data, original)
        output = self.output()
        del output['environment']
        with self.assertRaisesRegex(workflow.WorkflowError, 'missing stage output'):
            workflow.submit(self.data, self.identifier, output)

    def test_same_actor_is_not_independent_even_with_case_and_whitespace(self):
        self.init()
        self.advance()
        output = self.output()
        output['actor'] = ' AUTHOR '
        with self.assertRaisesRegex(workflow.WorkflowError, 'different declared actors'):
            workflow.submit(self.data, self.identifier, output)
        output['actor'] = 'independent'
        output['reviews'][0]['reviewer'] = 'someone-else'
        with self.assertRaisesRegex(workflow.WorkflowError, 'own review'):
            workflow.submit(self.data, self.identifier, output)

    def test_exact_last_retry_is_noop_but_changed_repeat_rejected(self):
        self.init()
        output = self.output()
        workflow.submit(self.data, self.identifier, output)
        original = copy.deepcopy(self.data)
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.data, original)
        output['summary'] = 'Changed result'
        with self.assertRaisesRegex(workflow.WorkflowError, 'out-of-order'):
            workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.data, original)

    def test_blocked_outcomes_require_explicit_resume(self):
        for status in ('held', 'error', 'unknown', 'conflict'):
            with self.subTest(status=status):
                self.setUp()
                self.init()
                output = self.output(status=status)
                workflow.submit(self.data, self.identifier, output)
                self.assertEqual(self.state()['status'], status)
                before = copy.deepcopy(self.data)
                workflow.submit(self.data, self.identifier, output)
                self.assertEqual(before, self.data)
                with self.assertRaises(workflow.WorkflowError):
                    self.advance()
                workflow.resume(self.data, self.identifier, 'coordinator', 'Blocker addressed')
                self.assertEqual(self.state()['status'], 'ready')
                self.assertEqual(self.state()['next_stage'], 'conditions')
                self.advance()
                self.assertEqual(len(self.state()['history']), 4)

    def test_unknown_conditions_hold_even_if_complete_requested(self):
        self.init()
        output = self.output()
        output['claims']['impact'].update(status='unknown', evidence_ids=[])
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.state()['status'], 'unknown')
        self.assertEqual(self.finding['validation']['verdict'], 'Unverified')
        self.assertEqual(self.state()['next_stage'], 'conditions')

    def test_unresolved_falsification_and_dissent_do_not_advance(self):
        for variant in ('unknown', 'conflict'):
            with self.subTest(variant=variant):
                self.setUp()
                self.init()
                self.advance()
                output = self.output()
                if variant == 'unknown':
                    output['checks'][0]['result'] = 'unresolved'
                else:
                    dissent = dict(output['reviews'][0], reviewer='dissent', conclusion='disagree')
                    output['reviews'] = output['reviews'] * 5 + [dissent]
                workflow.submit(self.data, self.identifier, output)
                self.assertEqual(self.state()['status'], variant)
                self.assertEqual(self.state()['next_stage'], 'falsification')

    def test_high_missing_review_coverage_holds_decision(self):
        extra = copy.deepcopy(self.data['evidence'][0])
        extra['id'] = 'other-source'
        self.data['evidence'].append(extra)
        self.init()
        self.advance()
        output = self.output()
        output['reviews'][0]['evidence_ids'] = ['other-source']
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.state()['next_stage'], 'decision')
        self.advance()
        self.assertEqual(self.state()['status'], 'held')
        self.assertEqual(self.finding['validation']['verdict'], 'Unverified')
        self.assertIn('verification_incomplete', self.state()['reasons'])

    def test_unknown_environment_holds_decision(self):
        self.init()
        output = self.output()
        output['environment']['status'] = 'unknown'
        workflow.submit(self.data, self.identifier, output)
        self.advance()
        self.advance()
        self.assertEqual(self.state()['status'], 'unknown')
        self.assertEqual(self.finding['validation']['verdict'], 'Unverified')

    def test_runtime_skips_and_errors_never_complete_decision(self):
        for outcome in ('not_run', 'blocked', 'error', 'skip', 'unsupported'):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.data['test_runs'][0].update(result=outcome, failure_kind='none', exit_code=None)
                self.init()
                self.advance()
                self.advance()
                output = self.output()
                output['run_ids'] = ['before']
                workflow.submit(self.data, self.identifier, output)
                self.assertEqual(self.state()['status'], 'held')
                self.assertIn('runtime_incomplete', self.state()['reasons'])
                self.assertEqual(self.finding['validation']['verdict'], 'Unverified')

    def test_passing_security_run_is_conflict_not_vote(self):
        self.data['test_runs'][0].update(result='pass', failure_kind='none', exit_code=0)
        self.init()
        self.advance()
        self.advance()
        output = self.output()
        output['run_ids'] = ['before']
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.state()['status'], 'conflict')
        self.assertEqual(self.finding['validation']['verdict'], 'Unverified')

    def test_exclusion_requires_and_accepts_positive_counterevidence(self):
        for verdict, basis in (('FalsePositive', 'condition_absent'), ('NotApplicable', 'not_applicable')):
            with self.subTest(verdict=verdict):
                self.setUp()
                self.init()
                output = self.output()
                output['claims']['preconditions']['status'] = 'contradicted'
                workflow.submit(self.data, self.identifier, output)
                self.advance()
                output = self.output()
                output['validation']['verdict'] = verdict
                before = copy.deepcopy(self.data)
                with self.assertRaisesRegex(workflow.WorkflowError, 'exclusion'):
                    workflow.submit(self.data, self.identifier, output)
                self.assertEqual(before, self.data)
                output['exclusion'] = dict(basis=basis, reason='Evidence-backed absent condition', evidence_ids=['source-before'])
                workflow.submit(self.data, self.identifier, output)
                self.assertEqual(self.state()['status'], 'complete')
                self.assertEqual(self.finding['validation']['verdict'], verdict)

    def test_relevant_input_changes_stale_and_resume_restarts_preserving_history(self):
        mutations = [lambda: self.finding.update(title='Changed claim'),
                     lambda: self.finding['validation'].update(evidence='Changed conclusion'),
                     lambda: self.finding['verification']['claims']['impact'].update(reason='Changed source trace'),
                     lambda: self.data['evidence'][0].update(sha256='d' * 64),
                     lambda: self.data['assessment'].update(repository='another/repository')]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp()
                self.init()
                self.advance()
                history = copy.deepcopy(self.state()['history'])
                mutate()
                self.assertEqual(self.state()['status'], 'stale')
                with self.assertRaisesRegex(workflow.WorkflowError, 'resume'):
                    self.advance()
                workflow.resume(self.data, self.identifier, 'coordinator', 'Re-review changed inputs')
                self.assertEqual(self.state()['status'], 'ready')
                self.assertEqual(self.state()['next_stage'], 'conditions')
                self.assertEqual(self.state()['history'][:len(history)], history)

    def test_decision_only_run_and_extra_observation_evidence_are_pinned(self):
        self.init()
        self.advance()
        self.advance()
        output = self.output()
        output['run_ids'] = ['before']
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.state()['status'], 'complete')
        self.data['test_runs'][0]['observed'] = 'Changed recorded output'
        self.assertEqual(self.state()['status'], 'stale')

    def test_missing_referenced_evidence_is_stale_not_silently_accepted(self):
        self.complete()
        self.data['evidence'] = self.data['evidence'][1:]
        self.assertEqual(self.state()['status'], 'stale')

    def test_unrelated_findings_and_catalog_additions_do_not_invalidate(self):
        other = copy.deepcopy(self.finding)
        other['id'] = 'F-OTHER'
        self.data['findings'].append(other)
        self.init()
        self.advance()
        digest = self.state()['input_digest']
        workflow.initialize(self.data, other['id'], 'other-person')
        other['title'] = 'Unrelated change'
        extra = dict(self.data['evidence'][0], id='unrelated')
        self.data['evidence'].append(extra)
        self.assertEqual(self.state()['status'], 'ready')
        self.assertEqual(self.state()['input_digest'], digest)

    def test_invalidate_does_not_erase_evidence_or_journal(self):
        self.complete()
        before = copy.deepcopy(self.finding['verification'])
        workflow.invalidate(self.data, self.identifier, 'coordinator', 'Request a fresh review')
        self.assertEqual(self.state()['status'], 'stale')
        workflow.resume(self.data, self.identifier, 'coordinator', 'Start again')
        self.assertEqual(self.state()['next_stage'], 'conditions')
        self.assertEqual(self.finding['verification'], before)
        self.assertEqual(len(self.state()['history']), 6)

    def test_old_records_are_preserved_in_submission_history(self):
        self.finding['verification'] = copy.deepcopy(self.reference)
        self.finding['validation'].update(verdict='Valid', evidence='Original recorded evidence')
        original = copy.deepcopy(self.finding['verification'])
        self.init()
        self.advance()
        event = self.state()['history'][-1]
        self.assertEqual(event['previous_fields']['verification'], original)
        self.assertEqual(event['previous_fields']['validation']['verdict'], 'Valid')

    def test_injected_derived_cache_is_ignored_and_removed_before_error(self):
        self.init()
        self.finding['_workflow'] = {'status': 'complete'}
        self.assertEqual(self.state()['status'], 'ready')
        self.finding['verification_workflow']['history'] = []
        with self.assertRaises(ValueError):
            workflow.validate_workflows(self.data)
        self.assertNotIn('_workflow', self.finding)

    def test_journal_skips_broken_chains_and_unsupported_states_rejected(self):
        self.complete()
        original = copy.deepcopy(self.data)
        changes = [lambda h: h.pop(1),
                   lambda h: h[2].update(input_digest='a' * 64),
                   lambda h: h[1].update(status='skip'),
                   lambda h: h[0].update(action='submit'),
                   lambda h: h[1].update(reasons=['invented']),
                   lambda h: h[2]['submission'].update(actor='author')]
        for change in changes:
            with self.subTest(change=change):
                self.data = copy.deepcopy(original)
                self.finding = self.data['findings'][0]
                change(self.finding['verification_workflow']['history'])
                with self.assertRaises(ValueError):
                    self.state()

    def test_digest_survives_renderer_normalization(self):
        self.complete()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'findings.json'
            path.write_text(json.dumps(self.data))
            import render
            normalized = render.load(path)
            self.assertEqual(workflow.derive_workflow(normalized, normalized['findings'][0])['status'], 'complete')

    def test_handoff_is_inert_and_template_cannot_be_blindly_submitted(self):
        self.init()
        handoff = workflow.next_handoff(self.data, self.identifier)
        self.assertEqual(handoff['stage'], 'conditions')
        self.assertEqual(set(handoff['submission_template']['claims']), set(workflow.CLAIMS))
        with self.assertRaisesRegex(workflow.WorkflowError, 'evidence references'):
            workflow.submit(self.data, self.identifier, handoff['submission_template'])
        self.assertIn('Do not execute commands', handoff['instructions'])

    def test_cli_init_status_next_submit_and_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'findings.json'
            path.write_text(json.dumps(self.data))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(workflow.main(['init', str(path), '--finding', self.identifier, '--actor', 'coordinator']), 0)
            self.data = json.loads(path.read_text())
            self.finding = self.data['findings'][0]
            submission = Path(tmp) / 'submission.json'
            submission.write_text(json.dumps(self.output()))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(workflow.main(['submit', str(path), '--finding', self.identifier, '--submission', str(submission)]), 0)
                self.assertEqual(workflow.main(['status', str(path)]), 0)
            handoff = Path(tmp) / 'handoff.json'
            self.assertEqual(workflow.main(['next', str(path), '--finding', self.identifier, '--out', str(handoff)]), 0)
            self.assertEqual(json.loads(handoff.read_text())['stage'], 'falsification')
            original = path.read_bytes()
            lock = path.with_name(path.name + '.workflow.lock')
            lock.write_text('busy')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(workflow.main(['init', str(path), '--finding', self.identifier, '--actor', 'coordinator']), 2)
            self.assertEqual(path.read_bytes(), original)
            self.assertTrue(lock.exists())

    def test_cli_rejects_symlinks_duplicate_keys_and_failed_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'findings.json'
            path.write_text(json.dumps(self.data))
            link = Path(tmp) / 'link.json'
            link.symlink_to(path)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(workflow.main(['init', str(link), '--finding', self.identifier, '--actor', 'coordinator']), 2)
            self.assertNotIn('verification_workflow', json.loads(path.read_text())['findings'][0])
            path.write_text('{"schema_version": 2, "schema_version": 1}')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(workflow.main(['status', str(path)]), 2)
            path.write_text(json.dumps(self.data))
            raw = path.read_bytes()
            with patch.object(workflow.os, 'replace', side_effect=OSError('simulated interrupted write')):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(workflow.main(['init', str(path), '--finding', self.identifier, '--actor', 'coordinator']), 2)
            self.assertEqual(path.read_bytes(), raw)
            self.assertFalse(path.with_name(path.name + '.workflow.lock').exists())

    def test_save_detects_external_edit_and_leaves_it_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'findings.json'
            path.write_text('{}')
            original = path.read_bytes()
            path.write_text('{"changed": true}')
            with self.assertRaisesRegex(workflow.WorkflowError, 'concurrently'):
                workflow._save(path, self.data, original)
            self.assertEqual(path.read_text(), '{"changed": true}')

    def test_starter_fixture_initializes_without_prefilled_verification(self):
        starter = json.loads((ROOT / 'examples/findings.workflow.sample.json').read_text())
        finding = starter['findings'][0]
        self.assertNotIn('verification', finding)
        state = workflow.initialize(starter, finding['id'], 'reviewer')
        self.assertEqual(state['next_stage'], 'conditions')

    def test_status_require_complete_is_an_explicit_machine_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'findings.json'
            def status(expected):
                path.write_text(json.dumps(self.data))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(workflow.main(['status', str(path), '--require-complete']), expected)
                    self.assertEqual(workflow.main(['status', str(path)]), 0)
            status(3)
            self.init()
            status(3)
            for _ in range(3):
                self.advance()
            status(0)
            workflow.invalidate(self.data, self.identifier, 'coordinator', 'New review required')
            status(3)
            self.data['findings'] = []
            status(3)

    def test_base_schema_is_validated_before_initialization(self):
        for field, value in (('severity', 'HIGH'), ('confidence', 'definitely'), ('references', [7]),
                             ('location', None), ('title', ''), ('status', 'Resolved')):
            with self.subTest(field=field):
                self.setUp()
                self.finding[field] = value
                original = copy.deepcopy(self.data)
                with self.assertRaises(workflow.WorkflowError):
                    self.init()
                self.assertEqual(self.data, original)

    def test_new_evidence_needs_explicit_scope_restart(self):
        self.init()
        extra = dict(self.data['evidence'][0], id='new-source')
        self.data['evidence'].append(extra)
        output = self.output()
        output['evidence_ids'] = ['new-source']
        with self.assertRaisesRegex(workflow.WorkflowError, 'frozen handoff scope'):
            workflow.submit(self.data, self.identifier, output)
        handoff = workflow.next_handoff(self.data, self.identifier)
        self.assertNotIn('new-source', [item['id'] for item in handoff['evidence']])
        workflow.invalidate(self.data, self.identifier, 'coordinator', 'Review new source record')
        workflow.resume(self.data, self.identifier, 'coordinator', 'Repin evidence catalog')
        output['input_digest'] = self.state()['input_digest']
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.state()['next_stage'], 'falsification')

    def test_rejected_decision_preserves_new_counterevidence_on_retry(self):
        self.data['test_runs'][0].update(result='pass', failure_kind='none', exit_code=0)
        self.init()
        self.advance()
        self.advance()
        output = self.output()
        output['run_ids'] = ['before']
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.state()['status'], 'conflict')
        self.assertEqual(self.finding['verification']['run_ids'], ['before'])
        workflow.resume(self.data, self.identifier, 'coordinator', 'Review the counterevidence')
        self.assertEqual(workflow.next_handoff(self.data, self.identifier)['submission_template']['run_ids'], ['before'])
        output = self.output()
        with self.assertRaisesRegex(workflow.WorkflowError, 'cannot drop active runtime'):
            workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.finding['validation']['verdict'], 'Unverified')

    def test_historical_record_hashes_cover_full_body_and_chain(self):
        self.complete()
        history = self.finding['verification_workflow']['history']
        self.assertIsNone(history[0]['previous_event_digest'])
        for previous, event in zip(history, history[1:]):
            self.assertEqual(event['previous_event_digest'], previous['event_digest'])
        history[1]['previous_fields']['validation']['evidence'] = 'Tampered historical observation'
        with self.assertRaisesRegex(ValueError, 'event body'):
            self.state()

    def test_explicit_round_restart_rejects_identical_old_handoff(self):
        self.init()
        self.advance()
        original = self.output()
        workflow.submit(self.data, self.identifier, original)
        workflow.invalidate(self.data, self.identifier, 'coordinator', 'New independent review')
        workflow.resume(self.data, self.identifier, 'coordinator', 'Restart unchanged candidate')
        self.advance()
        self.assertNotEqual(self.state()['input_digest'], original['input_digest'])
        with self.assertRaisesRegex(workflow.WorkflowError, 'stale handoff'):
            workflow.submit(self.data, self.identifier, original)

    def test_runtime_only_claims_do_not_complete_conditions(self):
        self.init()
        output = self.output()
        for claim in output['claims'].values():
            claim['evidence_ids'] = ['test-before']
        workflow.submit(self.data, self.identifier, output)
        self.assertEqual(self.state()['status'], 'unknown')

    def test_journal_recorded_command_is_never_executed(self):
        self.data['test_runs'][0]['command'] = 'touch /tmp/THIS_MUST_NEVER_EXECUTE'
        with patch('subprocess.run', side_effect=AssertionError('No execution allowed')):
            self.complete()
            self.assertEqual(self.state()['status'], 'complete')

    def test_consistent_hashes_do_not_bypass_historical_stage_semantics(self):
        for stage in ('conditions', 'falsification', 'dissent', 'actor'):
            with self.subTest(stage=stage):
                self.setUp()
                self.complete()
                history = self.finding['verification_workflow']['history']
                if stage == 'conditions':
                    history[1]['submission']['claims']['impact']['status'] = 'unknown'
                elif stage == 'falsification':
                    history[2]['submission']['checks'][0]['result'] = 'unresolved'
                elif stage == 'dissent':
                    history[2]['submission']['reviews'][0]['conclusion'] = 'disagree'
                else:
                    history[2]['submission']['reviews'][0]['reviewer'] = 'someone-else'
                for index, event in enumerate(history):
                    workflow._seal(event, history[index - 1] if index else None)
                with self.assertRaises(ValueError):
                    self.state()


if __name__ == '__main__':
    unittest.main()
