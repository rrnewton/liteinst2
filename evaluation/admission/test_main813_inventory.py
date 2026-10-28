"""Pure fixed-source and supplied-output controls for the main813 successor."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_813_inventory as main813
import core_5cda_inventory as main5c
import core_cc846_inventory as inventory
import precontext_native as protocol
import parsing
import run
from test_parsing import counts, header, summary

HEADER = '     Running tests/precontext_native.rs (target/debug/deps/precontext_native-0123456789abcdef)\n'


def terminal():
    # Independent supplied fixture, never output from a native process.
    return {'schema': 1, 'profile': 'precontext-v1', 'status': 'PASS',
            'scope': 'fixed-core-no-frontend-or-performance',
            'pairs': [dict(mode=mode, seed=seed, initial_selector=selected,
                ret_offset=27 if mode == 0 else 20, comparisons=18 if mode == 0 else 19,
                original_steps=100, candidate_steps=1000, callback_events=2 if selected else 0,
                observer_entries=2 if selected else 0, subject_returns=2, outer_returns=2,
                flip_acknowledgements=2, helper_joins=2)
                for seed in (0x1234567887654320, 0xfedcba9801234567)
                for mode in (0, 1) for selected in (False, True)],
            'malformed': [dict(tag=tag, sigill=True, local_ud2=True, original_heads=0,
                callback_events=0, observer_entries=0, subject_returns=0, outer_returns=0,
                cleanup='SIGKILL_REAP_ECHILD', steps=12) for tag in ('phase', 'choice')],
            'totals': dict(pairs=8, positive_children=16, malformed_children=2,
                comparisons=148, callback_events=8, subject_returns=16, outer_returns=16, helper_joins=16),
            'pure_controls': ['gate_displacement', 'scratch_layout', 'ack_fields',
                              'duplicate_ack_tail', 'slow_ret_log']}


def text(value=None):
    return HEADER + json.dumps(terminal() if value is None else value, separators=(',', ':')) + '\n'


class Main813InventoryTests(unittest.TestCase):
    def parse(self, raw, succeeded=True):
        return protocol.separate(raw, [protocol.specification()], succeeded)

    def test_exact_inventory_sources_docs_and_historical_denominators(self):
        declared = json.loads(Path(__file__).with_name('corpus.json').read_bytes())
        inventory.require_current(declared)
        self.assertEqual(declared['recorder_tests'], 350)
        for cohort, wanted in [('workspace_tests', (101, 2678, 11)), ('serial_launch', (27, 1039, 0))]:
            rows = declared['harness_test_counts'][cohort]
            self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                              sum(x['ignored'] for x in rows.values())), wanted)
        self.assertEqual(sum(len(x['all']) for x in main813.DATA['methods'].values()), 54)
        self.assertEqual(sum(len(x['ignored']) for x in main813.DATA['methods'].values()), 2)
        self.assertEqual(sum(len(x) for p, x in main813.DATA['doctests'].items() if p.startswith('src/')), 8)
        self.assertEqual(sum(len(x) for p, x in main813.DATA['doctests'].items() if p.startswith('tools/')), 20)
        previous = main813.before_current(declared)
        self.assertEqual(main813.digest(previous), main5c.CURRENT)
        self.assertEqual(previous['harness_test_counts']['workspace_tests']['doc/rapid_profiler'], counts(15))
        self.assertEqual(len(previous['native_validation_fixtures']), 110)
        self.assertEqual(previous['native_validation_fixtures'], declared['native_validation_fixtures'])
        self.assertEqual(previous['backing_cleanup_harnesses'], declared['backing_cleanup_harnesses'])
        identities = main5c.python_identities(Path(__file__).parent)
        self.assertEqual(len(identities), 350)
        self.assertEqual(len(main813.peel_python(identities)), 345)
        self.assertEqual(len(inventory.peel_python(identities)), 330)
        for key in declared:
            changed = copy.deepcopy(declared); changed[key] = None
            with self.subTest(field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_current(changed)
        for old in (previous, main5c.before_current(previous)):
            with self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(old)
        read_bytes = Path.read_bytes
        for path in main813.DATA['sources']:
            def changed(candidate):
                raw = read_bytes(candidate)
                return raw + b'\n' if candidate == main813.ROOT / path else raw
            with self.subTest(path=path), patch.object(Path, 'read_bytes', changed):
                with self.assertRaises(parsing.InvalidEvidence):
                    main813.before_current(declared)
        for path, row in main813.DATA['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before(path, bad, 'changed')

    def test_exact_precontext_header_scope_and_old_bytes(self):
        old = header('example') + '\nrunning 1 test\n' + summary(1) + '\n'
        for raw in (text() + old, old + text()):
            remaining, rows, error = self.parse(raw)
            self.assertIsNone(error)
            self.assertEqual(remaining, old)
            self.assertTrue(protocol.is_complete(rows[0]))
            self.assertFalse(rows[0]['qualified_run'])
            self.assertEqual(rows[0]['observations'], terminal())
        for raw in ('', text().removeprefix(HEADER), text() + text(),
                    text().replace('tests/precontext_native.rs', 'tests/wrong.rs'),
                    text().replace('precontext_native-0123', 'wrong-0123'),
                    text().replace('target/debug/deps/', 'target/release/deps/'),
                    text() + 'unexpected native diagnostic\n', HEADER + old):
            with self.subTest(raw=raw[:80]):
                _, rows, error = self.parse(raw)
                self.assertIsNotNone(error)
                self.assertFalse(protocol.is_complete(rows[0]))

    def test_core_parser_rejects_field_type_scope_population_and_partial_changes(self):
        good = terminal()
        for name in ('pairs', 'malformed', 'pure_controls'):
            for index in range(len(good[name])):
                changed = copy.deepcopy(good); changed[name].pop(index)
                _, rows, error = self.parse(text(changed))
                self.assertEqual(error, 'invalid_precontext_protocol')
                self.assertIsNone(rows[0]['observations'])
        for section in ('pairs', 'malformed'):
            for index, row in enumerate(good[section]):
                for key, value in row.items():
                    bad = None if type(value) is bool else True if type(value) is int else 'PRIVATE_SENTINEL'
                    changed = copy.deepcopy(good); changed[section][index][key] = bad
                    with self.subTest(section=section, index=index, key=key):
                        _, rows, error = self.parse(text(changed))
                        self.assertIsNotNone(error)
                        self.assertIsNone(rows[0]['observations'])
        for key in good['totals']:
            changed = copy.deepcopy(good); changed['totals'][key] -= 1
            self.assertIsNotNone(self.parse(text(changed))[2])
        for raw in (text()[:-1], text() + text().removeprefix(HEADER),
                    text().replace('"schema":1', '"schema":1,"schema":1'),
                    text().replace('"schema":1', '"schema":NaN'),
                    text().replace('"scope":"fixed-core-no-frontend-or-performance"', '"scope":"performance"'),
                    HEADER + '{"PRIVATE_SENTINEL":' + 'x' * 65536 + '\n'):
            _, rows, error = self.parse(raw)
            self.assertIsNotNone(error)
            self.assertFalse(protocol.is_complete(rows[0]))
            self.assertNotIn('PRIVATE_SENTINEL', json.dumps(rows))

    def test_whole_run_qualification_needs_exact_native_protocol_and_success(self):
        old = header('example') + '\nrunning 1 test\n' + summary(1) + '\n'
        corpus = {'harness_test_counts': {'workspace_tests': {'unit/example/lib': counts(1)}},
                  'precontext_native_harnesses': {'workspace_tests': [protocol.specification()]}}
        protocol.require_inventory(corpus)
        for missing in (None, {}, {'workspace_tests': []}):
            with self.assertRaises(parsing.InvalidEvidence):
                protocol.require_inventory(corpus | {'precontext_native_harnesses': missing})
        command = {'id': 'workspace_tests', 'status': 'passed', 'exit_code': 0}
        run.command_evidence(command, text() + old, corpus)
        self.assertEqual(command['status'], 'passed')
        record = {'source_unchanged': True, 'configuration_unchanged': True,
                  'precontext_native_required': True, 'commands': [command]}
        run.qualify(record)
        self.assertEqual(record['status'], 'passed')
        self.assertTrue(command['precontext_native_harnesses'][0]['qualified_run'])
        for key, value in (('source_unchanged', False), ('configuration_unchanged', False)):
            bad = copy.deepcopy(record); bad[key] = value
            run.qualify(bad)
            self.assertEqual(bad['status'], 'failed')
            self.assertFalse(bad['commands'][0]['precontext_native_harnesses'][0]['qualified_run'])
        for rows in ([], command['precontext_native_harnesses'] * 2):
            bad = copy.deepcopy(record); bad['commands'][0]['precontext_native_harnesses'] = rows
            run.qualify(bad); self.assertEqual(bad['status'], 'failed')
        for exit_code, raw in ((1, text()), (0, HEADER), (0, text().replace('"status":"PASS"', '"status":"FAILED"'))):
            item = {'id': 'workspace_tests', 'status': 'passed' if exit_code == 0 else 'failed', 'exit_code': exit_code}
            run.command_evidence(item, raw + old, corpus)
            bad = record | {'commands': [item]}
            run.qualify(bad)
            self.assertEqual(bad['status'], 'failed')
            self.assertFalse(item['precontext_native_harnesses'][0]['qualified_run'])

    def test_new_core_child_tuple_is_exact_and_old_shapes_survive(self):
        for total in (176, 184, 208, 213, 219, 227, 242, 248):
            raw = '\n'.join((header('liteinst2'), f'running {total} tests', 'running 1 test', summary(total - 1, ignored=1)))
            row = parsing.parse_harnesses(raw, {'unit/liteinst2/lib': counts(total, 1)}, 0)[0]
            self.assertEqual(row['outer']['passed'], total - 1)
            self.assertEqual(row['unmatched_nested_starts'], 1)
        for total, ignored, nested in ((247, 1, 1), (249, 1, 1), (248, 0, 1), (248, 1, 2)):
            raw = '\n'.join((header('liteinst2'), f'running {total} tests', f'running {nested} tests', summary(total - ignored, ignored=ignored)))
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(raw, {'unit/liteinst2/lib': counts(total, ignored)}, 0)
