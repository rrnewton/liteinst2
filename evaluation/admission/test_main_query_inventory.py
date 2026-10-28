"""Additive source census and closed PROCMAP_QUERY cleanup parser calibrations."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import unittest

import backing_cleanup as old_cleanup
import backing_cleanup_query as cleanup
import core_cc846_inventory as inventory
import parsing
import run
from test_backing_cleanup import (HEADER, OLD, records as old_records,
                                 specification as old_specification,
                                 transcript as old_transcript)
from test_parsing import counts, header, summary

NEW_NAMES = [
    'admitted_exec_native_backing_query_preserves_cleanup',
    'admitted_exec_native_backing_enotty_uses_exact_legacy_projection',
]


def records():
    old = old_records()
    return [old[0] | {'controls': 5, 'trajectories': 6}, *old[1:-1],
            {'schema_version': 1, 'kind': 'trajectory', 'index': 4,
             'id': 'query_error', 'control': NEW_NAMES[0], 'outcome': 'native_query_error',
             'probes': 1, 'errno': 14, 'terminal': 'exit0', 'owner_cleanup': True,
             'physical_cleanup': True, 'receipt_authenticated': True},
            {'schema_version': 1, 'kind': 'trajectory', 'index': 5,
             'id': 'legacy', 'control': NEW_NAMES[1], 'outcome': 'native_enotty_fallback',
             'probes': 6, 'errno': 0, 'terminal': 'exit0', 'owner_cleanup': True,
             'physical_cleanup': True, 'receipt_authenticated': True},
            old[-1] | {'controls': 5, 'trajectories': 6}]


def transcript(rows=None):
    return HEADER + ''.join(cleanup.PREFIX + json.dumps(row) + '\n'
                            for row in (records() if rows is None else rows))


def corpus():
    return {'harness_test_counts': {'workspace_tests': {'test/example': counts(2)}},
            'backing_cleanup_harnesses': {name: [cleanup.specification()]
                                         for name in ('workspace_tests', 'serial_launch')}}


class MainQueryInventoryTests(unittest.TestCase):
    def separate(self, text, successful=True):
        return cleanup.separate(text, [cleanup.specification()], successful)

    def test_exact_sources_catalog_and_historical_denominators(self):
        declared = json.loads(Path(__file__).with_name('corpus.json').read_bytes())
        inventory.require_current(declared)
        old = inventory.before_cc846(declared)
        self.assertEqual(inventory.digest(old), inventory.PREVIOUS)
        self.assertEqual(old['recorder_tests'], 330)
        self.assertEqual(declared['recorder_tests'], 340)
        for name, harnesses, tests, ignored in [('workspace_tests', 100, 2535, 4),
                                                ('serial_launch', 27, 1036, 0)]:
            rows = declared['harness_test_counts'][name]
            self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                              sum(x['ignored'] for x in rows.values())), (harnesses, tests, ignored))
        self.assertEqual(sum(len(row['added']) for row in inventory.DATA['methods'].values()), 68)
        self.assertEqual(declared['native_validation_fixtures'][108:], inventory.DATA['exec_parser_controls'])
        declared = inventory.before_exec_parser(declared)
        self.assertEqual(inventory.digest(declared), inventory.DATA['before_exec_parser_corpus_sha256'])
        for name in ('native_cases', 'dynamic_admission_fixtures', 'dynamic_matrix_cases',
                     'native_validation_fixtures'):
            self.assertEqual(declared[name], old[name])

    def test_catalog_source_and_python_mutations_cannot_enter_history(self):
        declared = json.loads(Path(__file__).with_name('corpus.json').read_bytes())
        for key in declared:
            changed = copy.deepcopy(declared)
            changed[key] = None
            with self.subTest(field=key), self.assertRaises(parsing.InvalidEvidence):
                inventory.before_cc846(changed)
        for path, row in inventory.DATA['projections'].items():
            data = (inventory.ROOT / path).read_bytes()
            restored = inventory.source_before_cc846(path, data, 'source_changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            with self.subTest(path=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^source_changed$'):
                inventory.source_before_cc846(path, data + b'\n', 'source_changed')
        identities = []
        for path in sorted(Path(__file__).parent.glob('test_*.py')):
            for cls in ast.parse(path.read_text()).body:
                if isinstance(cls, ast.ClassDef):
                    identities.extend(path.stem + '.' + cls.name + '.' + method.name
                                      for method in cls.body if isinstance(method, ast.FunctionDef)
                                      and method.name.startswith('test_'))
        self.assertEqual(len(inventory.peel_python(identities)), 330)
        self.assertEqual(inventory.digest(identities), inventory.PYTHON_CURRENT)
        for changed in (identities[:-1], list(reversed(identities)), identities + [identities[0]]):
            self.assertEqual(inventory.peel_python(changed), changed)

    def test_new_harness_and_exact_242_child_shape(self):
        ordinary = '     Running unittests ordinary-interval/main.rs (target/debug/deps/ordinary_interval-123abc)'
        valid = '\n'.join((ordinary, 'running 14 tests', summary(14)))
        self.assertEqual(parsing.parse_harnesses(valid, {'unit/ordinary_interval/main': counts(14)}, 0)[0]['outer']['passed'], 14)
        for changed in (valid.replace('ordinary-interval/', 'other/'),
                        valid.replace('ordinary_interval-', 'other-'),
                        valid.replace('running 14 tests', 'running 13 tests')):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(changed, {'unit/ordinary_interval/main': counts(14)}, 0)
        valid = '\n'.join((header('liteinst2'), 'running 242 tests', 'running 1 test',
                           summary(241, ignored=1)))
        parsed = parsing.parse_harnesses(valid, {'unit/liteinst2/lib': counts(242, 1)}, 0)[0]
        self.assertEqual(parsed['outer']['passed'], 241)
        self.assertEqual(parsed['unmatched_nested_starts'], 1)
        for total, child, ignored in ((241, 1, 1), (243, 1, 1), (242, 2, 1), (242, 1, 0)):
            bad = '\n'.join((header('liteinst2'), f'running {total} tests', f'running {child} tests',
                             summary(total - ignored, ignored=ignored)))
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, {'unit/liteinst2/lib': counts(total, ignored)}, 0)

    def test_complete_new_protocol_keeps_all_four_old_trajectories(self):
        for text in (transcript() + OLD, OLD + transcript()):
            remaining, rows, error = self.separate(text)
            self.assertIsNone(error)
            self.assertEqual(remaining, OLD)
            self.assertEqual(rows[0]['observations'], records())
            self.assertEqual(rows[0]['observations'][1:5], old_records()[1:5])
            self.assertEqual([x['status'] for x in rows[0]['controls']], ['complete'] * 5)
            self.assertTrue(cleanup.is_complete(rows[0]))
            self.assertFalse(rows[0]['qualified_run'])
            self.assertFalse(old_cleanup.is_complete(rows[0]))
        self.assertEqual([x['trajectories'] for x in rows[0]['controls'][-2:]],
                         [['query_error'], ['legacy']])

    def test_every_new_record_field_requires_exact_value_and_type(self):
        for index, row in enumerate(records()):
            for field, value in row.items():
                variants = [None, False if type(value) is int else 0 if type(value) is bool else 'PRIVATE_SENTINEL']
                for variant in variants:
                    changed = records()
                    changed[index][field] = variant
                    _, observed, error = self.separate(transcript(changed))
                    self.assertEqual(error, 'backing_cleanup_record_differs')
                    self.assertEqual(observed[0]['observations'], records()[:index])
                    self.assertFalse(cleanup.is_complete(observed[0]))
                    self.assertNotIn('PRIVATE_SENTINEL', json.dumps(observed))

    def test_every_partial_duplicate_reordered_and_extra_protocol_refuses(self):
        for length in range(len(records())):
            _, observed, error = self.separate(transcript(records()[:length]))
            self.assertEqual(error, 'incomplete_backing_cleanup_protocol')
            self.assertEqual(observed[0]['observations'], records()[:length])
            self.assertFalse(cleanup.is_complete(observed[0]))
        for rows in (records() + [records()[-1]], records()[:6] + [records()[5]] + records()[6:],
                     records()[:5] + [records()[6], records()[5]] + records()[7:]):
            _, observed, error = self.separate(transcript(rows))
            self.assertIsNotNone(error)
            self.assertFalse(cleanup.is_complete(observed[0]))

    def test_old_descriptor_and_protocol_cannot_replace_live_new_inventory(self):
        good = corpus()
        cleanup.require_inventory(good)
        for changed in ({}, good | {'backing_cleanup_harnesses': {}},
                        good | {'backing_cleanup_harnesses': {
                            name: [old_specification()] for name in ('workspace_tests', 'serial_launch')}}):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^invalid_backing_cleanup_inventory$'):
                cleanup.require_inventory(changed)
        with self.assertRaises(parsing.InvalidEvidence):
            cleanup.separate(old_transcript(), [old_specification()], True)
        _, rows, error = self.separate(old_transcript())
        self.assertEqual(error, 'backing_cleanup_record_differs')
        self.assertEqual(rows[0]['observations'], [])
        self.assertTrue(old_cleanup.is_complete(old_cleanup.separate(old_transcript(), [old_specification()], True)[1][0]))

    def test_header_duplicate_keys_and_nonfinite_values_cannot_hide_old_logs(self):
        wrong = [transcript().replace('tests/exec_backing_cleanup.rs', 'tests/foreign.rs'),
                 transcript().replace('deps/exec_backing_cleanup-', 'deps/foreign-'),
                 transcript().replace('"controls": 5', '"controls": 5, "controls": 5', 1),
                 transcript().replace('"controls": 5', '"controls": NaN', 1),
                 transcript() + transcript()]
        for text in wrong:
            remaining, rows, error = self.separate(OLD + text)
            self.assertIsNotNone(error)
            self.assertTrue(remaining.startswith(OLD))
            self.assertFalse(cleanup.is_complete(rows[0]))
            self.assertFalse(rows[0]['qualified_run'])

    def test_command_failure_preserves_prefix_without_qualification(self):
        for successful in (True, False):
            command = {'id': 'workspace_tests', 'status': 'passed' if successful else 'failed',
                       'exit_code': 0 if successful else 1}
            run.command_evidence(command, OLD + transcript(records()[:6]), corpus())
            self.assertEqual(command['status'], 'invalid_evidence' if successful else 'failed')
            self.assertEqual(command['backing_cleanup_harnesses'][0]['observations'], records()[:6])
            self.assertFalse(command['backing_cleanup_harnesses'][0]['qualified_run'])
        command = {'id': 'workspace_tests', 'status': 'passed', 'exit_code': 0}
        run.command_evidence(command, OLD + transcript(), corpus())
        self.assertEqual(command['status'], 'passed')
        self.assertTrue(cleanup.is_complete(command['backing_cleanup_harnesses'][0]))

    def test_final_qualification_requires_new_rows_and_complete_unchanged_run(self):
        row = self.separate(transcript())[1][0]
        good = {'source_unchanged': True, 'configuration_unchanged': True,
                'backing_cleanup_required': True, 'backing_cleanup_query_required': True,
                'commands': [{'id': name, 'status': 'passed', 'backing_cleanup_harnesses': [copy.deepcopy(row)]}
                             for name in ('workspace_tests', 'serial_launch')]}
        run.qualify(good)
        self.assertEqual(good['status'], 'passed')
        for variant in ('old', 'partial', 'failed', 'source', 'configuration'):
            bad = copy.deepcopy(good)
            if variant == 'old':
                bad['commands'][1]['backing_cleanup_harnesses'] = old_cleanup.separate(old_transcript(), [old_specification()], True)[1]
            elif variant == 'partial':
                bad['commands'][1]['backing_cleanup_harnesses'] = self.separate(transcript(records()[:6]))[1]
            elif variant == 'failed':
                bad['commands'][1]['status'] = 'failed'
            else:
                bad[variant + '_unchanged'] = False
            run.qualify(bad)
            self.assertEqual(bad['status'], 'failed')
            self.assertTrue(all(not r['qualified_run'] for c in bad['commands'] for r in c['backing_cleanup_harnesses']))
