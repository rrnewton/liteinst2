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
        actual = copy.deepcopy(declared)
        declared = main813.before_e797(declared)
        live = copy.deepcopy(declared)
        declared = main813.before_c1(declared)
        newest = copy.deepcopy(declared)
        declared = main813.before_c0(declared)
        latest = copy.deepcopy(declared)
        declared = main813.before_690(declared)
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

        # The live successor must be complete before any historical projection.
        self.assertEqual(latest['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'], counts(304, 7))
        rows = latest['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (101, 2694, 11))
        self.assertEqual(sum(len(x['all']) for x in main813.MAIN690['methods'].values()), 16)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAIN690['methods'].values()), 0)
        self.assertEqual(main813.digest(main813.before_690(latest)), main813.CURRENT)
        latest = actual  # Later live-source mutations must reach the current guard.
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(declared)
        for key in latest:
            changed = copy.deepcopy(latest); changed[key] = None
            with self.subTest(main690_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_690(changed)
        for value in (288, 303, 305, True, 304.0):
            changed = copy.deepcopy(latest)
            changed['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']['tests'] = value
            with self.subTest(main690_count=value), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for path in main813.MAIN690['sources']:
            for missing in (False, True):
                def changed(candidate):
                    if candidate == main813.ROOT / path:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(main690_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(latest)
        for path, row in main813.MAIN690['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_690(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(main690_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_690(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_c0(newest)), main813.CURRENT690)
        rows = newest['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (101, 2716, 11))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINC0['methods'].values()), 22)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINC0['methods'].values()), 0)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_c0(newest))
        live = actual
        for name, change in main813.MAINC0['workspace_changes'].items():
            self.assertEqual(rows[name], change['current'])
            for value in (change['previous']['tests'], change['current']['tests'] - 1,
                          change['current']['tests'] + 1, True, float(change['current']['tests'])):
                changed = copy.deepcopy(live)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainc0_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
        for key in newest:
            changed = copy.deepcopy(newest); changed[key] = None
            with self.subTest(mainc0_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_c0(changed)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(newest)
        newest = actual  # Source mutation controls authenticate the actual current catalog.
        for path in main813.MAINC0['sources']:
            for missing in (False, True):
                def changed(candidate):
                    if candidate == main813.ROOT / path:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainc0_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(newest)
        for path, row in main813.MAINC0['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_c0(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainc0_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_c0(path, bad, 'changed')

        live = copy.deepcopy(main813.before_e797(actual))
        self.assertEqual(main813.digest(main813.before_c1(live)), main813.CURRENTC0)
        rows = live['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (101, 2752, 11))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINC1['methods'].values()), 31)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINC1['methods'].values()), 0)
        self.assertEqual(sum(len(main813.MAINC1['methods'][p]['all']) * len(v)
                             for p, v in main813.MAINC1['instances'].items()), 36)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_c1(live))
        live = actual
        for name, change in main813.MAINC1['workspace_changes'].items():
            self.assertEqual(rows[name], change['current'])
            for value in (change['previous']['tests'], change['current']['tests'] - 1,
                          change['current']['tests'] + 1, True, float(change['current']['tests'])):
                changed = copy.deepcopy(live)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainc1_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
        for key in live:
            changed = copy.deepcopy(live); changed[key] = None
            with self.subTest(mainc1_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_c1(changed)
        for path in main813.MAINC1['sources']:
            for missing in (False, True):
                def changed(candidate):
                    if candidate == main813.ROOT / path:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainc1_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(live)
        for path, row in main813.MAINC1['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_c1(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainc1_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_c1(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_e797(actual)), main813.CURRENTC1)
        current_rows = main813.before_f0ef(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2845, 12))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINE797['methods'].values()), 64)
        self.assertEqual(sum(len(main813.MAINE797['methods'][p]['all']) * len(v)
                             for p, v in main813.MAINE797['instances'].items()), 75)
        self.assertEqual(sum(len(x) for x in main813.MAINE797['doctests'].values()), 18)
        self.assertEqual(sum(len(x['ignored']) for x in main813.MAINE797['methods'].values()), 1)
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_e797(actual))
        for name, change in main813.MAINE797['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            for value in (change['current']['tests'] - 1, change['current']['tests'] + 1,
                          True, float(change['current']['tests'])):
                changed = copy.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(maine797_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = copy.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(maine797_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = copy.deepcopy(actual); changed[key] = None
            with self.subTest(maine797_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_e797(changed)
        for path in main813.MAINE797['sources']:
            for missing in (False, True):
                def changed(candidate):
                    if candidate == main813.ROOT / path:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(maine797_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAINE797['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_e797(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(maine797_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_e797(path, bad, 'changed')

        self.assertEqual(main813.digest(main813.before_f0ef(actual)), main813.CURRENTE797)
        current_rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(current_rows), sum(x['tests'] for x in current_rows.values()),
                          sum(x['ignored'] for x in current_rows.values())), (103, 2854, 12))
        self.assertEqual(sum(len(x['all']) for x in main813.MAINF0EF['methods'].values()), 9)
        self.assertEqual(sum(len(main813.MAINF0EF['methods'][p]['all']) * len(v)
                             for p, v in main813.MAINF0EF['instances'].items()), 9)
        self.assertEqual(main813.MAINF0EF['declared_delta'],
                         {'rust_tests': 9, 'doctests': 0, 'ignored': 0, 'harnesses': 0})
        with self.assertRaises(parsing.InvalidEvidence):
            inventory.require_current(main813.before_f0ef(actual))
        for name, change in main813.MAINF0EF['workspace_changes'].items():
            self.assertEqual(current_rows[name], change['current'])
            for value in (change['current']['tests'] - 1, change['current']['tests'] + 1,
                          True, float(change['current']['tests'])):
                changed = copy.deepcopy(actual)
                changed['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.subTest(mainf0ef_count=(name, value)), self.assertRaises(parsing.InvalidEvidence):
                    inventory.require_current(changed)
            changed = copy.deepcopy(actual)
            del changed['harness_test_counts']['workspace_tests'][name]
            with self.subTest(mainf0ef_missing=name), self.assertRaises(parsing.InvalidEvidence):
                inventory.require_current(changed)
        for key in actual:
            changed = copy.deepcopy(actual); changed[key] = None
            with self.subTest(mainf0ef_field=key), self.assertRaises(parsing.InvalidEvidence):
                main813.before_f0ef(changed)
        for path in main813.MAINF0EF['sources']:
            for missing in (False, True):
                def changed(candidate):
                    if candidate == main813.ROOT / path:
                        if missing:
                            raise FileNotFoundError(path)
                        return read_bytes(candidate) + b'\n'
                    return read_bytes(candidate)
                with self.subTest(mainf0ef_source=path, missing=missing), patch.object(Path, 'read_bytes', changed):
                    with self.assertRaises(parsing.InvalidEvidence):
                        inventory.require_current(actual)
        for path, row in main813.MAINF0EF['projections'].items():
            raw = (main813.ROOT / path).read_bytes()
            restored = main813.source_before_f0ef(path, raw, 'changed')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for bad in (raw + b'\n', raw[:-1], restored):
                with self.subTest(mainf0ef_inverse=path), self.assertRaisesRegex(parsing.InvalidEvidence, '^changed$'):
                    main813.source_before_f0ef(path, bad, 'changed')

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

        # Exact new cohort: keep all old rows/assertions and refuse neighbors.
        raw = '\n'.join((header('liteinst2'), 'running 255 tests', 'running 1 test',
                         'test trampoline::tests::live::ptrace_stopped_hook_executes_on_owned_stack ... ok',
                         summary(254, ignored=1)))
        row = parsing.parse_harnesses(raw, {'unit/liteinst2/lib': counts(255, 1)}, 0)[0]
        self.assertEqual(row['outer']['passed'], 254)
        self.assertEqual(row['outer']['ignored'], 1)
        self.assertEqual(row['unmatched_nested_starts'], 1)
        for total, ignored, nested in ((254, 1, 1), (256, 1, 1), (255, 0, 1), (255, 1, 2)):
            bad = '\n'.join((header('liteinst2'), f'running {total} tests', f'running {nested} tests',
                             summary(total - ignored, ignored=ignored)))
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, {'unit/liteinst2/lib': counts(total, ignored)}, 0)

        doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                         'running 36 tests', summary(36),
                         'all doctests ran in 0.51s; merged doctests compilation took 0.21s'))
        expected = {'doc/rapid_profiler': counts(38)}
        row = parsing.parse_harnesses(doc, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=38, failed=0, ignored=0, measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([p['declared_tests'] for p in row['partitions']], [2, 36])
        self.assertEqual([p['summary']['passed'] for p in row['partitions']], [2, 36])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        changes = [doc.replace('rapid_profiler', 'example'),
                   doc.replace('running 2 tests', 'running 3 tests'),
                   doc.replace('running 36 tests', 'running 35 tests'),
                   doc.replace('running 36 tests', 'running 37 tests'),
                   doc.replace(summary(2), summary(1)),
                   doc.replace(summary(36), summary(35)),
                   doc.replace(summary(2), summary(2, filtered=1)),
                   doc.replace(summary(36), summary(36, filtered=1)),
                   doc.replace(summary(36), summary(35, ignored=1)),
                   doc.replace(summary(36), summary(35, measured=1)),
                   doc.replace(summary(36), summary(35, failed=1)),
                   doc.replace(summary(36), summary(36, result='FAILED')),
                   doc.replace('running 36 tests', 'running 36 tests\nrunning 36 tests'),
                   doc.replace(summary(2), summary(2)+'\n'+summary(2)),
                   doc.replace(summary(36), ''),
                   doc.replace(summary(2), ''),
                   '\n'.join(doc.splitlines()[:-1]),
                   doc+'\n'+doc.splitlines()[-1],
                   doc+'\nrunning 1 test\n'+summary(1),
                   doc.replace('all doctests ran in 0.51s;', 'all doctests ran in NaNs;')]
        for bad in changes:
            with self.subTest(doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        for total, ignored in ((37, 0), (39, 0), (38, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = doc.replace(summary(36), summary(35, failed=1))
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']), ('FAILED', 37, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)
