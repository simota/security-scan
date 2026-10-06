"""Malformed report input must fail predictably before any output is written."""
import copy
from contextlib import redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'skills/security-scan/scripts/render.py'
BAD_TYPES = (None, True, False, 0, 1.5, [], ['value'], {}, {'value': 'text'})


class InputSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('input_schema_renderer', SCRIPT)
        cls.renderer = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'path', [str(SCRIPT.parent)] + sys.path):
            spec.loader.exec_module(cls.renderer)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='security-scan-schema-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / 'findings.json'
        self.base = {
            'meta': {'project': 'Synthetic fixture', 'date': '2026-10-06'},
            'findings': [{'id': 'F-001', 'title': 'Synthetic finding', 'severity': 'High',
                          'confidence': 'Confirmed', 'location': 'src/example.py:1'}],
        }

    def load(self, data):
        self.path.write_text(json.dumps(data), encoding='utf-8')
        return self.renderer.load(self.path)

    def assert_invalid(self, data, field):
        with self.assertRaisesRegex(self.renderer.SchemaError, re.escape(field)):
            self.load(data)

    def test_required_meta_fields_are_nonblank_strings(self):
        for field in ('project', 'date'):
            for value in BAD_TYPES + ('', ' \n\t'):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.base)
                    data['meta'][field] = value
                    self.assert_invalid(data, 'meta.' + field)
            data = copy.deepcopy(self.base)
            del data['meta'][field]
            self.assert_invalid(data, 'meta.' + field)

    def test_required_finding_fields_are_nonblank_strings(self):
        for field in ('id', 'title', 'severity', 'confidence', 'location'):
            for value in BAD_TYPES + ('', ' \n\t'):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.base)
                    data['findings'][0][field] = value
                    self.assert_invalid(data, 'findings[0].' + field)
            data = copy.deepcopy(self.base)
            del data['findings'][0][field]
            self.assert_invalid(data, 'findings[0].' + field)

    def test_optional_meta_and_finding_text_is_not_coerced(self):
        groups = (('meta', ('assessor', 'scope', 'method', 'commit')),
                  ('finding', ('category', 'actor', 'request', 'impact', 'fix')))
        for group, fields in groups:
            for field in fields:
                for value in BAD_TYPES:
                    with self.subTest(group=group, field=field, value=value):
                        data = copy.deepcopy(self.base)
                        target = data['meta'] if group == 'meta' else data['findings'][0]
                        target[field] = value
                        self.assert_invalid(data, ('meta.' if group == 'meta' else 'findings[0].') + field)

    def test_enums_reject_wrong_types_before_membership_checks(self):
        for field in ('status', 'validation.verdict'):
            for value in BAD_TYPES + ('Unknown',):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.base)
                    if field == 'status':
                        data['findings'][0][field] = value
                    else:
                        data['findings'][0]['validation'] = {'verdict': value}
                    self.assert_invalid(data, 'findings[0].' + field)

    def test_validation_and_history_are_objects_when_present(self):
        for field in ('validation', 'previous_validation'):
            for value in (None, False, 0, '', [], ['value']):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.base)
                    data['findings'][0][field] = value
                    self.assert_invalid(data, 'findings[0].' + field)

    def test_validation_and_history_text_is_not_coerced(self):
        for parent, fields in (('validation', ('method', 'evidence')),
                               ('previous_validation', ('verdict', 'method', 'evidence'))):
            for field in fields:
                for value in BAD_TYPES:
                    with self.subTest(parent=parent, field=field, value=value):
                        data = copy.deepcopy(self.base)
                        data['findings'][0][parent] = {field: value}
                        self.assert_invalid(data, 'findings[0].' + parent + '.' + field)

    def test_references_require_a_list_and_safe_string_fields(self):
        for value in (None, False, 0, '', {}, {'url': 'https://example.invalid'}):
            data = copy.deepcopy(self.base)
            data['findings'][0]['references'] = value
            self.assert_invalid(data, 'findings[0].references')
        for field in ('url', 'title', 'type'):
            for value in BAD_TYPES:
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.base)
                    reference = {'url': 'https://example.invalid/advisory', field: value}
                    data['findings'][0]['references'] = [reference]
                    self.assert_invalid(data, 'findings[0].references[0].' + field)
        for value in (None, False, 0, []):
            data = copy.deepcopy(self.base)
            data['findings'][0]['references'] = [value]
            self.assert_invalid(data, 'findings[0].references[0]')

    def test_report_lists_require_strings_with_indexed_errors(self):
        for field in ('checked_ok', 'decisions', 'limitations', 'next_steps'):
            for value in BAD_TYPES:
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.base)
                    data[field] = ['Good entry', value]
                    self.assert_invalid(data, field + '[1]')

    def test_perspective_names_and_optional_text_are_typed(self):
        for value in (None, False, 0, '', [], {}):
            data = copy.deepcopy(self.base)
            data['perspectives'] = [value]
            self.assert_invalid(data, 'perspectives[0]')
        for field in ('name', 'result', 'note'):
            for value in BAD_TYPES + (('', ' \n') if field == 'name' else ()):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.base)
                    data['perspectives'] = [{'name': 'Dependencies', field: value}]
                    self.assert_invalid(data, 'perspectives[0].' + field)

    def test_defaults_and_empty_optional_strings_remain_compatible(self):
        data = copy.deepcopy(self.base)
        data['meta'].update({key: '' for key in ('assessor', 'scope', 'method', 'commit', 'source_url')})
        data['findings'][0].update({key: '' for key in ('category', 'actor', 'request', 'impact', 'fix')})
        data['findings'][0]['previous_validation'] = {'verdict': 'NotApplicable', 'method': 'review', 'evidence': 'Old revision only'}
        data['findings'][0]['references'] = ['https://example.invalid/a', {'url': 'https://example.invalid/b', 'title': '', 'type': ''}]
        data['perspectives'] = [{'name': 'Dependencies', 'result': '', 'note': ''}]
        result = self.load(data)
        finding = result['findings'][0]
        self.assertEqual(finding['status'], 'Open')
        self.assertEqual(finding['verdict'], 'Unverified')
        self.assertEqual(finding['category'], 'Uncategorized')
        self.assertEqual(finding['previous_validation']['verdict'], 'NotApplicable')
        self.renderer.attach_sources(result, None)
        for lang in ('ja', 'en'):
            self.assertTrue(self.renderer.render_dashboard(result, self.renderer.LABELS[lang], lang))
            self.assertTrue(self.renderer.render_assessment_html(result, self.renderer.LABELS[lang], lang))

    def test_mixed_id_types_are_rejected_before_sorting(self):
        data = copy.deepcopy(self.base)
        second = copy.deepcopy(data['findings'][0])
        second['id'] = 2
        data['findings'].append(second)
        self.assert_invalid(data, 'findings[1].id')

    def test_invalid_unicode_is_rejected_in_text_and_extension_fields(self):
        for field in ('title', 'extension'):
            for value in ('\ud800', '\udfff'):
                with self.subTest(field=field, value=repr(value)):
                    data = copy.deepcopy(self.base)
                    data['findings'][0][field] = value
                    self.assert_invalid(data, 'findings[0].' + field)
        data = copy.deepcopy(self.base)
        data['meta']['\ud800'] = 'value'
        self.assert_invalid(data, 'meta: invalid Unicode object key')

    def test_json_nonfinite_constants_and_overflow_are_rejected(self):
        for value in ('NaN', 'Infinity', '-Infinity', '1e999'):
            with self.subTest(value=value):
                text = json.dumps(self.base)[:-1] + ', "extension": ' + value + '}'
                self.path.write_text(text, encoding='utf-8')
                with self.assertRaises(self.renderer.SchemaError):
                    self.renderer.load(self.path)

    def test_malformed_file_encoding_and_excessive_nesting_are_schema_errors(self):
        self.path.write_bytes(b'\xff')
        with self.assertRaisesRegex(self.renderer.SchemaError, re.escape(str(self.path))):
            self.renderer.load(self.path)
        self.path.write_text('{}', encoding='utf-8')
        with patch.object(self.renderer.json, 'loads', side_effect=RecursionError('Synthetic parser limit')):
            with self.assertRaisesRegex(self.renderer.SchemaError, re.escape(str(self.path))):
                self.renderer.load(self.path)

    def test_location_controls_are_rejected_but_plain_locations_still_work(self):
        for value in ('bad\x00file.py:1', 'bad\nfile.py:1', 'bad\tfile.py:1', 'file.py:1\x7f'):
            data = copy.deepcopy(self.base)
            data['findings'][0]['location'] = value
            self.assert_invalid(data, 'findings[0].location')
        data = copy.deepcopy(self.base)
        data['findings'][0]['location'] = 'package-lock.json'
        self.renderer.attach_sources(self.load(data), self.root)

    def test_location_integer_conversion_errors_are_named(self):
        data = copy.deepcopy(self.base)
        data['findings'][0]['location'] = 'file.py:12345'
        original_int = int

        def limited_int(value, *args, **kwargs):
            if value == '12345':
                raise ValueError('Synthetic platform integer limit')
            return original_int(value, *args, **kwargs)

        with patch.dict(self.renderer.__dict__, {'int': limited_int}):
            self.assert_invalid(data, 'findings[0].location')

    def test_renderer_nesting_failure_exits_two_before_output(self):
        self.path.write_text(json.dumps(self.base), encoding='utf-8')
        for renderer in ('render_dashboard', 'render_assessment_html'):
            with self.subTest(renderer=renderer):
                out = self.root / renderer
                error = io.StringIO()
                with patch.object(self.renderer, renderer, side_effect=RecursionError), redirect_stderr(error):
                    status = self.renderer.main([str(self.path), '--out', str(out), '--no-pdf'])
                self.assertEqual(status, 2)
                self.assertIn('report: JSON nesting', error.getvalue())
                self.assertNotIn('Traceback', error.getvalue())
                self.assertFalse(out.exists())

    def test_cli_invalid_input_exits_two_without_outputs_or_traceback(self):
        cases = [('id', []), ('location', None), ('title', None), ('severity', {}),
                 ('title', '\ud800'), ('location', 'bad\x00file.py:1')]
        if getattr(sys, 'get_int_max_str_digits', lambda: 0)():
            cases.append(('location', 'file.py:' + '1' * (sys.get_int_max_str_digits() + 1)))
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field, index=index):
                data = copy.deepcopy(self.base)
                data['findings'][0][field] = value
                self.path.write_text(json.dumps(data), encoding='utf-8')
                out = self.root / ('out-' + str(index))
                process = subprocess.run([sys.executable, str(SCRIPT), str(self.path), '--out', str(out),
                                          '--repo', str(self.root), '--no-pdf'],
                                         capture_output=True, text=True, timeout=15)
                self.assertEqual(process.returncode, 2, process.stderr)
                self.assertIn('findings[0].' + field, process.stderr)
                self.assertNotIn('Traceback', process.stderr)
                self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
