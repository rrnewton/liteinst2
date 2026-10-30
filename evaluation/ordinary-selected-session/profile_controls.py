#!/usr/bin/env python3
"""Additive profile-isolation controls; fabricated data, no native authority."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
runner = load('_selected_profile_runner_fixture', HERE / 'runner_controls.py')
driver = load('_selected_profile_driver', HERE / 'reproduce.py')
owner = load('_selected_profile_owner', HERE / 'owner.py')
OLD = 'selected-session-functional-v1'
WHOLE = 'selected-session-whole-functional-v1'


def fixture(index=0, leg='installed'):
    plan, rows, args, data = runner.plan_fixture(index, leg)
    plan['profile'] = WHOLE
    args['profile'] = WHOLE
    for leaf in plan['table']:
        leaf['policy'] = 'whole'
    for leaf in args['table']:
        leaf['policy'] = 'whole'
    plan['argv'] = ['whole' if arg == 'certified' else arg for arg in plan['argv']]
    for row in rows:
        if row[0] == 'LEAF':
            row[4] = 'whole'
    return plan, rows, args, data


def owner_options(phase):
    result = dict(phase=phase, revision='a' * 40, **{
        'reservation-tag': 'fabricated-profile', 'owner': '/fabricated/owner.json',
        'raw': '/fabricated/output', 'toolchain': '/fabricated/toolchain',
        'user-home': '/fabricated/user', 'cargo-home': '/fabricated/cargo',
        'hardware': 'fabricated host'})
    for key in owner.EXTRAS[phase]:
        result[key] = 'b' * 64 if key.endswith('-sha') else '/fabricated/' + key + '.json'
    return result


class Controls(unittest.TestCase):
    def test_explicit_owner_profile_forwards_only_controls_and_campaign(self):
        for phase in ('controls', 'campaign'):
            options = owner_options(phase)
            original, child = owner.commands(options, '/fabricated/python', str(HERE / 'owner.py'))
            options['profile'] = WHOLE
            opted, opted_child = owner.commands(options, '/fabricated/python', str(HERE / 'owner.py'))
            self.assertEqual(opted, original + ['--profile', WHOLE])
            self.assertEqual(opted_child, child + ['--profile', WHOLE])
            self.assertEqual(opted_child[2], str(HERE / 'reproduce.py'))
            class BeforeDispatch(Exception):
                pass
            actual_commands = owner.commands
            def stop_before_dispatch(actual, python, script):
                self.assertEqual(actual, options)
                observed, forwarded = actual_commands(actual, python, script)
                self.assertEqual(observed[-2:], ['--profile', WHOLE])
                self.assertEqual(forwarded[-2:], ['--profile', WHOLE])
                raise BeforeDispatch()
            # Exercise the real argparse/main forwarding and stop before Git,
            # process ownership, file creation or any child dispatch.
            with patch.object(owner.sys, 'argv', opted[2:]), \
                    patch.object(owner, 'commands', side_effect=stop_before_dispatch):
                with self.assertRaises(BeforeDispatch):
                    owner.main()
        for phase in ('products', 'tests'):
            for profile in (OLD, WHOLE):
                options = owner_options(phase)
                options['profile'] = profile
                with self.assertRaises(AssertionError):
                    owner.commands(options, '/fabricated/python', str(HERE / 'owner.py'))

    def test_old_default_and_unknown_profile_dispatch_stay_strict(self):
        self.assertEqual(driver.selected_profile(SimpleNamespace()), OLD)
        for profile in (OLD, WHOLE):
            self.assertEqual(driver.selected_profile(SimpleNamespace(profile=profile)), profile)
        for profile in ('whole', '', 'other', None, True):
            with self.assertRaises(AssertionError):
                driver.selected_profile(SimpleNamespace(profile=profile))
            options = owner_options('campaign')
            options['profile'] = profile
            with self.assertRaises(AssertionError):
                owner.commands(options, '/fabricated/python', str(HERE / 'owner.py'))
        for phase in owner.EXTRAS:
            options = owner_options(phase)
            invocation, child = owner.commands(options, '/fabricated/python', str(HERE / 'owner.py'))
            self.assertNotIn('--profile', invocation)
            self.assertNotIn('--profile', child)
            options['unexpected-profile'] = WHOLE
            with self.assertRaises(AssertionError):
                owner.commands(options, '/fabricated/python', str(HERE / 'owner.py'))

    def test_whole_profile_binds_all_eight_plans_and_exact_whole_argv(self):
        for leg in ('reference', 'installed'):
            calls = 0
            for index in range(4):
                plan, rows, args, data = fixture(index, leg)
                case, checked = runner.producer.plan_arguments(plan, runner.oracle, runner.checker)
                self.assertEqual(checked, args)
                self.assertEqual(case['data'], data)
                self.assertEqual(case['records'], runner.oracle.records(plan['k']))
                self.assertEqual(checked['profile'], WHOLE)
                self.assertEqual([leaf['policy'] for leaf in checked['table']], ['whole', 'whole'])
                self.assertEqual(plan['argv'].count('whole'), 2 if leg == 'installed' else 0)
                result, raw, errors = runner.envelope(plan, rows, args, data)
                run = runner.Run()
                joined = runner.dispatch(run, plan, result, raw, errors)
                self.assertEqual(joined['status'], 'PASS')
                self.assertEqual(joined['observations']['values'], result['original_values'])
                self.assertTrue(run.safe)
                self.assertEqual(run.events[-2:], ['unchanged', 'complete'])
                self.assertFalse(run.budget.active)
                calls += 2 * len(case['records'])
            self.assertEqual(calls, 4052)

    def test_profile_policy_and_mixed_tables_cannot_cross(self):
        for original in (runner.plan_fixture, fixture):
            for leg in ('reference', 'installed'):
                good, _, _, _ = original(0, leg)
                for profile in (OLD, WHOLE, 'unknown'):
                    for policies in (('certified', 'certified'), ('whole', 'whole'),
                                     ('certified', 'whole'), ('whole', 'certified')):
                        changed = copy.deepcopy(good)
                        changed['profile'] = profile
                        for leaf, policy in zip(changed['table'], policies):
                            leaf['policy'] = policy
                        if leg == 'installed':
                            # Rebind argv coherently so the profile/table check is decisive.
                            changed['argv'] = changed['argv'][:8]
                            for leaf in changed['table']:
                                changed['argv'] += [str(leaf['function_id']), leaf['operation'],
                                    str(leaf['elf_va']), str(leaf['extent']), leaf['policy']]
                        positive = (profile, policies) in (
                            (OLD, ('certified', 'certified')), (WHOLE, ('whole', 'whole')))
                        if positive:
                            runner.producer.plan_arguments(changed, runner.oracle, runner.checker)
                        else:
                            with self.assertRaises(AssertionError):
                                runner.producer.plan_arguments(changed, runner.oracle, runner.checker)
        old, _, _, _ = runner.plan_fixture()
        _, checked = runner.producer.plan_arguments(old, runner.oracle, runner.checker)
        self.assertNotIn('profile', checked)  # Exact inherited call shape.

    def test_whole_geometry_retains_exact_extent_return_and_identity_bounds(self):
        _, _, args, _ = fixture()
        for extent in (5, 80):
            table = tuple(dict(row, elf_va=4096+128*i, extent=extent, returns=(extent-1,))
                          for i, row in enumerate(args['table']))
            runner.checker.geometry(table, args['caller'], args['cpus'], profile=WHOLE)
            for bad in (0, 4, 81, 256, True):
                changed = copy.deepcopy(table)
                changed[0]['extent'] = bad
                changed[0]['returns'] = (0,)
                with self.assertRaises(AssertionError):
                    runner.checker.geometry(changed, args['caller'], args['cpus'], profile=WHOLE)
        for key, value in (('function_id', 202), ('operation', 'csv_fields'),
                           ('returns', (48,)), ('returns', (47, 17)), ('elf_va', 0)):
            changed = copy.deepcopy(args['table'])
            changed[0][key] = value
            with self.assertRaises(AssertionError):
                runner.checker.geometry(changed, args['caller'], args['cpus'], profile=WHOLE)
        with self.assertRaises(AssertionError):
            runner.checker.geometry(args['table'], args['caller'], args['cpus'])

    def test_whole_wire_checks_both_complete_populations_without_projection(self):
        for index, count in ((0, 12), (1, 1001)):
            _, rows, args, _ = fixture(index)
            raw = runner.wire.prior.encode(rows)
            checked = runner.checker.check(raw, b'', **args)
            self.assertEqual(checked['raw'], raw)
            self.assertEqual(checked['stderr'], b'')
            self.assertEqual(checked['status'], 'SELECTED_SESSION_WIRE_PASS')
            self.assertEqual(checked['rows']['READY'][0]['version'], 'selected-session-v1')
            self.assertEqual([row['policy'] for row in checked['rows']['LEAF']], ['whole', 'whole'])
            self.assertEqual(len(checked['rows']['CALL']), 2*count)
            self.assertEqual(len(checked['rows']['RESULT']), count)
            for row, payload in zip(checked['rows']['RESULT'], runner.oracle.records(args['k'])):
                self.assertEqual((row['value_0'], row['value_1']), runner.oracle.values(payload))
            self.assertEqual(checked['totals']['calls'], 2*count)
            without_profile = dict(args)
            del without_profile['profile']
            with self.assertRaises(AssertionError):
                runner.checker.check(raw, b'', **without_profile)

    def test_whole_wire_keeps_every_row_family_and_scalar_join(self):
        _, rows, args, _ = fixture()
        for tag in ('READY', 'LEAF', 'RET', 'HISTORY', 'REPORT', 'CALL', 'RESULT',
                    'SAMPLE', 'COVERAGE', 'IO', 'DONE'):
            at = next(i for i, row in enumerate(rows) if row[0] == tag)
            for duplicate in (False, True):
                bad = copy.deepcopy(rows)
                if duplicate:
                    bad.insert(at, copy.deepcopy(bad[at]))
                else:
                    del bad[at]
                with self.assertRaises(AssertionError, msg=tag):
                    runner.checker.check(runner.wire.prior.encode(bad), b'', **args)
        for tag, column, value in (('LEAF', 4, 'certified'), ('CALL', 13, 1 << 32),
                                   ('RESULT', 4, 1), ('DONE', 1, 'INPUT_INCOMPLETE')):
            bad = copy.deepcopy(rows)
            next(row for row in bad if row[0] == tag)[column] = value
            with self.assertRaises(AssertionError, msg=tag):
                runner.checker.check(runner.wire.prior.encode(bad), b'', **args)

    def test_cross_profile_child_receipts_refuse_before_safe_release(self):
        for make, wrong in ((runner.plan_fixture, WHOLE), (fixture, OLD)):
            for leg in ('reference', 'installed'):
                plan, rows, args, data = make(0, leg)
                result, raw, errors = runner.envelope(plan, rows, args, data)
                result['profile'] = wrong
                run = runner.Run()
                with self.assertRaises(AssertionError):
                    runner.dispatch(run, plan, result, raw, errors)
                self.assertFalse(run.safe)
                self.assertTrue(run.budget.active)
                self.assertNotIn('complete', run.events)

    def test_geometry_and_controls_scope_must_match_selected_profile(self):
        for expected, wrong in ((OLD, WHOLE), (WHOLE, OLD)):
            driver.profile_record({'profile': expected}, expected)
            driver.profile_record({'scope': expected}, expected, 'scope')
            run = SimpleNamespace(a=SimpleNamespace(profile=expected), retained={})
            path = Path('/fabricated/receipt.json')
            run.retained[str(path)] = {'sha256': 'a' * 64}
            build = {'revision': 'b' * 40, 'products': {}}
            geometry = dict(kind='selected-session-geometry-acceptance-v1',
                build_result_sha256='a' * 64, build_revision=build['revision'], products={},
                status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION', scope=wrong)
            with patch.object(driver, 'read_json', return_value=geometry):
                with self.assertRaisesRegex(AssertionError, 'selected profile mismatch'):
                    driver.accept_geometry(run, None, None, build, path, path, 'c' * 64)
            with patch.object(driver, 'read_json', return_value={'profile': wrong}):
                with self.assertRaisesRegex(AssertionError, 'selected profile mismatch'):
                    driver.replay_controls(run, None, None, None, path, 'c' * 64,
                                           path, 'd' * 64, build, path, None)
            for field in ('profile', 'scope'):
                for actual in (wrong, 'other', None, True):
                    with self.assertRaisesRegex(AssertionError, 'selected profile mismatch'):
                        driver.profile_record({field: actual}, expected, field)

    def test_profile_control_inventory_only_appends_to_unchanged_default(self):
        leaf = SimpleNamespace(CHECKER_CONTROLS=tuple('w'+str(i) for i in range(14)),
            RUNNER_CONTROLS=tuple('r'+str(i) for i in range(9)),
            REFERENCE_CONTROLS=tuple('o'+str(i) for i in range(6)))
        recipe = SimpleNamespace(PYTHON_CONTROLS=tuple('m'+str(i) for i in range(26)))
        old = driver.python_suites(leaf, recipe)
        explicit = driver.python_suites(leaf, recipe, OLD)
        whole = driver.python_suites(leaf, recipe, WHOLE)
        self.assertEqual(old, explicit)
        self.assertEqual(whole[:-1], old)
        self.assertEqual(sum(row['count'] for row in old), 94)
        self.assertEqual(sum(row['count'] for row in whole), 104)
        self.assertEqual(driver.control_stage_labels(), driver.CONTROL_STAGE_LABELS)
        self.assertEqual(driver.control_stage_labels(WHOLE)[:-1], driver.CONTROL_STAGE_LABELS)
        self.assertEqual(len(driver.CONTROL_STAGE_LABELS), 12)
        self.assertEqual(whole[-1]['expected'], driver.PROFILE_CONTROLS)
        self.assertEqual(len(driver.DRIVER_CONTROLS), 9)
        self.assertEqual(len(driver.SELECTED_RUST), 24)
        for function in (driver.control_stage_labels, driver.python_control_count):
            with self.assertRaises(AssertionError):
                function('unknown')


if __name__ == '__main__':
    unittest.main()
