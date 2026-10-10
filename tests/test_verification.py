"""Offline tests of recorded verification, never tests against a target app."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('verification_model', ROOT / 'skills/security-scan/scripts/verification.py')
VERIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFICATION)


class RecordError(ValueError):
    pass


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / 'examples/findings.verification.sample.json').read_text(encoding='utf-8'))
        self.finding = self.data['findings'][0]
        self.record = self.finding['verification']

    def derive(self):
        return VERIFICATION.derive_verification(self.data, RecordError)[self.finding['id']]

    def invalid(self, pattern):
        with self.assertRaisesRegex(RecordError, pattern):
            self.derive()

    def static(self):
        self.finding['status'] = 'Open'
        self.finding.pop('remediation')
        self.record['run_ids'] = []

    def test_synthetic_complete_runtime_and_retest(self):
        state = self.derive()
        self.assertEqual(state['level'], 'runtime_supported')
        self.assertEqual(state['retest'], 'verified')
        self.assertEqual(state['gaps'], [])
        self.assertEqual(state['run_ids'], ['after', 'before', 'control', 'regression'])
        self.assertEqual(state['evidence_ids'], sorted(e['id'] for e in self.data['evidence']))

    def test_derivation_does_not_mutate_or_trust_injected_fields(self):
        self.static()
        self.finding['_verification'] = {'level': 'runtime_supported', 'retest': 'verified'}
        original = copy.deepcopy(self.data)
        self.assertEqual(self.derive()['level'], 'static_supported')
        self.assertEqual(self.data, original)
        VERIFICATION.validate_verification(self.data, RecordError)
        self.assertEqual(self.finding['_verification']['level'], 'static_supported')
        self.assertEqual(self.finding['_verification']['retest'], 'not_requested')

    def test_derived_verdict_is_not_authoritative(self):
        self.finding['verdict'] = 'Valid'
        self.finding['validation']['verdict'] = 'Likely'
        self.record['claims']['reachability']['status'] = 'unknown'
        self.assertEqual(self.derive()['level'], 'incomplete')

    def test_injected_state_is_stripped_before_validation_failure(self):
        self.finding['_verification'] = {'level': 'runtime_supported'}
        self.record['claims']['impact']['evidence_ids'] = ['missing']
        with self.assertRaises(RecordError):
            VERIFICATION.validate_verification(self.data, RecordError)
        self.assertNotIn('_verification', self.finding)

    def test_legacy_preserves_original_fields_without_promotion(self):
        original = json.loads((ROOT / 'examples/findings.sample.json').read_text(encoding='utf-8'))
        before = copy.deepcopy(original)
        states = VERIFICATION.derive_verification(original, RecordError)
        self.assertTrue(all(s['level'] == 'legacy' for s in states.values()))
        self.assertEqual(states['F-003']['retest'], 'fix_claimed')
        self.assertEqual(original, before)

    def test_mixed_missing_or_free_text_verification_is_legacy(self):
        for note in (None, 'Historical free text, not structured proof.'):
            with self.subTest(note=note):
                clone = copy.deepcopy(self.finding)
                clone['id'] = 'D-NEW'
                clone.pop('verification')
                clone.pop('remediation')
                if note is not None:
                    clone['verification'] = note
                self.data['findings'] = [self.finding, clone]
                state = VERIFICATION.derive_verification(self.data)['D-NEW']
                # An absent record on a version-2 scanner finding is pending review, not legacy.
                self.assertEqual(state['level'], 'legacy' if note else 'incomplete')
                if note is None:
                    self.assertIn(state['gaps'][0], ('scanner_unreviewed', 'legacy_details_missing'))

    def test_new_records_require_version_two(self):
        for version in ('2', 2.0, True, 3):
            with self.subTest(version=version):
                self.data['schema_version'] = version
                self.invalid('schema_version')

    def test_legacy_arbitrary_extensions_never_opt_in_or_promote(self):
        for version in (None, 1):
            with self.subTest(version=version):
                if version is None:
                    self.data.pop('schema_version', None)
                else:
                    self.data['schema_version'] = version
                self.data['evidence'] = 'Unstructured historical extension'
                self.finding['remediation'] = 'Historical fix note'
                original = copy.deepcopy(self.data)
                self.assertEqual(self.derive()['level'], 'legacy')
                self.assertEqual(self.derive()['retest'], 'fix_claimed')
                self.assertEqual(original, self.data)

    def test_null_or_wrong_types_are_schema_errors(self):
        for key in ('claims', 'environment', 'reviews', 'falsification', 'run_ids'):
            old = self.record[key]
            for value in (None, True, 2, 'bad'):
                with self.subTest(key=key, value=value):
                    self.record[key] = value
                    self.invalid(key)
            self.record[key] = old
        for value in (None, [], False, 3):
            self.finding['verification'] = value
            self.invalid('verification')

    def test_missing_required_claim_and_reason_are_errors(self):
        del self.record['claims']['defenses']
        self.invalid('defenses')
        self.record['claims']['defenses'] = {'status': 'supported', 'evidence_ids': ['source-before']}
        self.invalid('reason')

    def test_valid_requires_all_claims_and_evidence(self):
        for status in ('unknown', 'contradicted'):
            self.record['claims']['impact']['status'] = status
            self.invalid('all four claims')
        self.record['claims']['impact']['status'] = 'supported'
        self.record['claims']['impact']['evidence_ids'] = []
        self.invalid('evidence_ids')

    def test_unknown_claim_is_incomplete_for_nondefinitive_verdict(self):
        self.finding['validation']['verdict'] = 'Likely'
        self.record['claims']['preconditions'].update(status='unknown', evidence_ids=[])
        self.assertEqual(self.derive()['level'], 'incomplete')
        self.assertIn('claims_incomplete', self.derive()['gaps'])

    def test_unsettled_verdict_never_claims_supported_even_with_complete_evidence(self):
        for verdict in ('Unverified', 'Likely', 'Unlikely'):
            with self.subTest(verdict=verdict):
                self.finding['validation']['verdict'] = verdict
                state = self.derive()
                self.assertEqual(state['level'], 'incomplete')
                self.assertIn('verdict_unresolved', state['gaps'])
                self.assertNotEqual(state['retest'], 'verified')
        self.static()
        self.record['reviews'] = []
        self.assertEqual(self.derive()['level'], 'incomplete')

    def test_dangling_duplicate_and_stale_evidence_rejected(self):
        for refs in (['missing'], ['source-before', 'source-before'], ['test-after']):
            self.record['claims']['impact']['evidence_ids'] = refs
            self.invalid('evidence_ids')

    def test_duplicate_catalog_ids_are_rejected(self):
        self.data['evidence'].append(copy.deepcopy(self.data['evidence'][0]))
        self.invalid('duplicate ID')
        self.data['evidence'].pop()
        self.data['test_runs'].append(copy.deepcopy(self.data['test_runs'][0]))
        self.invalid('duplicate ID')

    def test_full_commit_and_digest_required(self):
        for value in ('main', 'abcdef0', '1' * 39, 'x' * 40):
            self.data['assessment']['commit'] = value
            self.invalid('assessment.commit')
        self.data['assessment']['commit'] = '1' * 40
        self.data['evidence'][0]['sha256'] = 'bad'
        self.invalid('sha256')

    def test_meta_commit_matches_assessment(self):
        self.data['meta']['commit'] = '2' * 40
        self.invalid('meta.commit')

    def test_dirty_worktree_requires_matching_diff_pins(self):
        self.data['assessment']['worktree'] = 'dirty'
        self.invalid('diff_sha256')
        self.data['assessment']['diff_sha256'] = 'd' * 64
        self.invalid('required commit/worktree pin')
        for evidence in self.data['evidence']:
            if evidence['commit'] == '1' * 40:
                evidence['diff_sha256'] = 'd' * 64
        self.data['test_runs'][0]['diff_sha256'] = 'd' * 64
        self.assertEqual(self.derive()['retest'], 'verified')
        self.data['assessment']['worktree'] = 'clean'
        self.invalid('diff_sha256')

    def test_definitive_falsification_required_and_negative_checked(self):
        self.record['falsification'] = []
        self.invalid('falsification')
        for result in ('unresolved', 'contradiction'):
            self.record['falsification'] = [{'check': 'Check guard', 'result': result,
                                              'evidence_ids': ['source-before'], 'reason': 'Pending check'}]
            self.invalid('falsification')

    def test_high_requires_independent_complete_review(self):
        original = copy.deepcopy(self.record['reviews'])
        for reviews in ([], [dict(original[0], reviewer='synthetic-author')],
                        [dict(original[0], reviewer='  SYNTHETIC-AUTHOR  ')]):
            self.record['reviews'] = reviews
            state = self.derive()
            self.assertEqual(state['level'], 'incomplete')
            self.assertIn('review_missing', state['gaps'])
            self.assertNotEqual(state['retest'], 'verified')

    def test_independent_review_must_cover_all_claim_evidence(self):
        extra = dict(self.data['evidence'][0], id='another-source')
        self.data['evidence'].append(extra)
        self.record['claims']['impact']['evidence_ids'] = ['another-source']
        self.assertIn('review_missing', self.derive()['gaps'])

    def test_review_disagreement_is_not_a_vote(self):
        dissent = dict(self.record['reviews'][0], reviewer='dissenting-reviewer', conclusion='disagree')
        self.record['reviews'] = self.record['reviews'] * 4 + [dissent]
        state = self.derive()
        self.assertEqual(state['level'], 'incomplete')
        self.assertIn('review_disagreement', state['gaps'])
        dissent['resolution'] = {'reviewer': 'dissenting-reviewer', 'reason': 'Re-read specific source evidence.', 'evidence_ids': ['source-before']}
        self.assertEqual(self.derive()['level'], 'runtime_supported')
        dissent['resolution']['reviewer'] = 'synthetic-author'
        self.invalid('dissenting reviewer')

    def test_unknown_environment_not_promoted_to_runtime(self):
        self.record['environment']['status'] = 'unknown'
        state = self.derive()
        self.assertEqual(state['level'], 'environment_unverified')
        self.assertIn('environment_unknown', state['gaps'])
        self.assertEqual(state['retest'], 'incomplete')

    def test_environment_confirmation_requires_environment_evidence(self):
        self.record['environment']['status'] = 'verified'
        self.invalid('evidence_ids')
        self.record['environment']['evidence_ids'] = ['source-before']
        self.invalid('environment evidence')
        self.data['evidence'].append(dict(self.data['evidence'][0], id='environment', kind='environment'))
        self.record['environment']['evidence_ids'] = ['environment']
        self.assertEqual(self.derive()['level'], 'runtime_supported')
        self.assertIn('environment', self.derive()['evidence_ids'])

    def test_static_does_not_imply_execution(self):
        self.static()
        self.assertEqual(self.derive()['level'], 'static_supported')

    def test_runtime_evidence_without_source_trace_does_not_promote(self):
        for claim in self.record['claims'].values():
            claim['evidence_ids'] = ['test-before']
        self.record['reviews'][0]['evidence_ids'] = ['test-before']
        self.assertEqual(self.derive()['level'], 'incomplete')

    def test_non_execution_and_infrastructure_never_promoted(self):
        run = self.data['test_runs'][0]
        for result in ('not_run', 'blocked', 'unsupported', 'error', 'skip'):
            with self.subTest(result=result):
                run.update(result=result, failure_kind='infrastructure', exit_code=None)
                state = self.derive()
                self.assertEqual(state['level'], 'static_supported')
                self.assertIn('runtime_incomplete', state['gaps'])
                self.assertEqual(state['retest'], 'incomplete')
        run.update(result='fail', failure_kind='infrastructure', exit_code=1)
        self.assertEqual(self.derive()['level'], 'static_supported')
        self.assertIn('retest_before_unverified', self.derive()['gaps'])

    def test_mocked_boundary_does_not_promote(self):
        self.data['test_runs'][0]['context']['boundary'] = 'mocked'
        state = self.derive()
        self.assertEqual(state['level'], 'static_supported')
        self.assertIn('runtime_boundary_unverified', state['gaps'])
        self.assertNotEqual(state['retest'], 'verified')

    def test_favorable_runtime_run_cannot_hide_an_inconclusive_or_conflicting_run(self):
        run = dict(copy.deepcopy(self.data['test_runs'][0]), id='repeat')
        self.data['test_runs'].append(run)
        self.record['run_ids'].append('repeat')
        for result in ('pass', 'skip', 'not_run', 'blocked', 'unsupported', 'error'):
            with self.subTest(result=result):
                run.update(result=result, failure_kind='none', exit_code=0 if result == 'pass' else None)
                state = self.derive()
                self.assertEqual(state['level'], 'incomplete' if result == 'pass' else 'static_supported')
                self.assertEqual(state['retest'], 'incomplete')
                self.assertIn('runtime_incomplete', state['gaps'])
                if result == 'pass':
                    self.assertIn('runtime_contradiction', state['gaps'])

    def test_passing_before_is_not_a_red_reproduction(self):
        self.data['test_runs'][0].update(result='pass', failure_kind='none', exit_code=0)
        self.assertEqual(self.derive()['level'], 'incomplete')
        self.assertIn('retest_before_unverified', self.derive()['gaps'])

    def test_pass_and_fail_outcomes_cannot_disagree_with_exit_status(self):
        for result, failure, code in (('pass', 'none', 1), ('pass', 'assertion', 0),
                                      ('pass', 'none', False), ('fail', 'assertion', 0),
                                      ('fail', 'none', 1), ('fail', 'assertion', None)):
            with self.subTest(result=result, failure=failure, code=code):
                self.data['test_runs'][0].update(result=result, failure_kind=failure, exit_code=code)
                self.invalid('test_runs')

    def test_run_timestamp_and_local_scope_required(self):
        self.data['test_runs'][0]['recorded_at'] = '2026-10-06T09:00:00'
        self.invalid('recorded_at')
        self.data['test_runs'][0]['recorded_at'] = '2026-10-06T09:00:00Z'
        self.data['test_runs'][0]['context']['environment'] = 'production'
        self.invalid('context.environment')

    def test_run_evidence_matches_exact_version_and_kind(self):
        self.data['test_runs'][0]['evidence_ids'] = ['test-after']
        self.invalid('commit/worktree pin')
        self.data['test_runs'][0]['evidence_ids'] = ['source-before']
        self.invalid('runtime evidence')

    def test_verification_run_must_match_assessment(self):
        self.record['run_ids'] = ['after']
        self.invalid('commit/worktree pin')

    def test_fixed_claim_and_risk_acceptance_are_not_retest_success(self):
        self.finding.pop('remediation')
        self.assertEqual(self.derive()['retest'], 'fix_claimed')
        self.finding['status'] = 'Accepted'
        self.assertEqual(self.derive()['retest'], 'not_requested')

    def test_no_before_can_record_after_without_verified_fix(self):
        del self.finding['remediation']['before_run_id']
        state = self.derive()
        self.assertEqual(state['retest'], 'incomplete')
        self.assertIn('retest_before_unverified', state['gaps'])
        self.assertIn('after', state['run_ids'])

    def test_retest_run_references_are_not_unchecked_strings(self):
        self.finding['remediation']['before_run_id'] = 'missing'
        self.invalid('before_run_id')

    def test_retest_cannot_switch_case_or_secure_expectation(self):
        after = self.data['test_runs'][1]
        for field in ('case_id', 'expected'):
            old = after[field]
            after[field] = 'different'
            self.assertIn('retest_case_mismatch', self.derive()['gaps'])
            self.assertEqual(self.derive()['retest'], 'incomplete')
            after[field] = old

    def test_retest_context_is_consistent(self):
        for field in ('configuration', 'fixture', 'test_version', 'environment', 'boundary'):
            with self.subTest(field=field):
                context = self.data['test_runs'][1]['context']
                old = context[field]
                context[field] = {'environment': 'throwaway', 'boundary': 'mocked'}.get(field, 'changed')
                self.assertIn('retest_context_mismatch', self.derive()['gaps'])
                self.assertEqual(self.derive()['retest'], 'incomplete')
                context[field] = old

    def test_retest_requires_explicit_fixed_version_and_correct_controls(self):
        self.finding['remediation']['commit'] = '3' * 40
        self.assertIn('retest_version_mismatch', self.derive()['gaps'])
        self.assertEqual(self.derive()['retest'], 'incomplete')
        del self.finding['remediation']['commit']
        self.invalid('remediation.commit')

    def test_all_postfix_cases_need_same_target_and_context(self):
        self.data['test_runs'][2]['commit'] = '3' * 40
        self.data['evidence'][3]['commit'] = '3' * 40
        self.assertIn('retest_version_mismatch', self.derive()['gaps'])
        self.data['test_runs'][2]['context']['fixture'] = 'changed'
        self.assertIn('retest_context_mismatch', self.derive()['gaps'])

    def test_controls_and_regressions_are_both_required_and_must_pass(self):
        for index, key, gap in ((2, 'positive_control_run_ids', 'control'), (3, 'regression_run_ids', 'regression')):
            with self.subTest(key=key):
                refs = self.finding['remediation'][key]
                self.finding['remediation'][key] = []
                self.assertIn('retest_' + gap + '_missing', self.derive()['gaps'])
                self.finding['remediation'][key] = refs
                run = self.data['test_runs'][index]
                for result in ('fail', 'skip', 'not_run', 'blocked', 'unsupported', 'error'):
                    run.update(result=result, failure_kind='assertion' if result == 'fail' else 'none', exit_code=1 if result == 'fail' else None)
                    self.assertIn('retest_' + gap + '_failed', self.derive()['gaps'])
                    self.assertEqual(self.derive()['retest'], 'incomplete')
                run.update(result='pass', failure_kind='none', exit_code=0)

    def test_retest_cannot_reuse_security_case_as_control(self):
        self.data['test_runs'][2]['case_id'] = self.data['test_runs'][1]['case_id']
        self.assertIn('retest_case_mismatch', self.derive()['gaps'])

    def test_exclusions_need_positive_evidence_and_matching_basis(self):
        self.static()
        for verdict, basis in (('FalsePositive', 'condition_absent'), ('NotApplicable', 'not_applicable')):
            with self.subTest(verdict=verdict):
                self.finding['validation']['verdict'] = verdict
                self.record.pop('exclusion', None)
                self.invalid('exclusion')
                self.record['exclusion'] = {'basis': basis, 'reason': 'Specific condition checked.', 'evidence_ids': ['source-before']}
                self.record['claims']['preconditions']['status'] = 'supported'
                self.invalid('contradicted claim')
                self.record['claims']['preconditions']['status'] = 'contradicted'
                self.assertEqual(self.derive()['level'], 'static_supported')
                self.record['exclusion']['evidence_ids'] = []
                self.invalid('exclusion.evidence_ids')

    def test_real_security_assertion_failure_contradicts_an_exclusion(self):
        self.finding.pop('remediation')
        self.finding['status'] = 'Open'
        for verdict, basis in (('FalsePositive', 'condition_absent'), ('NotApplicable', 'not_applicable')):
            with self.subTest(verdict=verdict):
                self.finding['validation']['verdict'] = verdict
                self.record['claims']['preconditions']['status'] = 'contradicted'
                self.record['exclusion'] = {'basis': basis, 'reason': 'Specific condition checked.',
                                             'evidence_ids': ['source-before']}
                state = self.derive()
                self.assertEqual(state['level'], 'incomplete')
                self.assertIn('runtime_contradiction', state['gaps'])
                self.assertEqual(self.finding['validation']['verdict'], verdict)

    def test_secure_pass_is_not_counterevidence_to_an_exclusion(self):
        self.finding.pop('remediation')
        self.finding['status'] = 'Open'
        self.record['claims']['preconditions']['status'] = 'contradicted'
        self.data['test_runs'][0].update(result='pass', failure_kind='none', exit_code=0)
        for verdict, basis in (('FalsePositive', 'condition_absent'), ('NotApplicable', 'not_applicable')):
            with self.subTest(verdict=verdict):
                self.finding['validation']['verdict'] = verdict
                self.record['exclusion'] = {'basis': basis, 'reason': 'Specific condition checked.',
                                           'evidence_ids': ['source-before']}
                state = self.derive()
                self.assertEqual(state['level'], 'static_supported')
                self.assertEqual(state['gaps'], [])
                self.assertEqual(state['run_ids'], ['before'])
                self.assertEqual(state['retest'], 'not_requested')

    def test_all_gap_and_level_codes_are_declared(self):
        self.record['reviews'] = []
        state = self.derive()
        self.assertIn(state['level'], VERIFICATION.LEVELS)
        self.assertIn(state['retest'], VERIFICATION.RETESTS)
        self.assertTrue(set(state['gaps']).issubset(VERIFICATION.GAPS))


if __name__ == '__main__':
    unittest.main()
