#!/usr/bin/env python3
"""Pure fixed-plan/child-envelope controls; fabricated files, no child execution."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
producer = load('_selected_runner_producer', HERE / 'produce.py')
closure = load('_selected_runner_closure', HERE / 'closure.py')
wire = load('_selected_runner_fixture', HERE / 'wire_controls.py')
checker, oracle = wire.output, wire.oracle


def digest(data):
    return hashlib.sha256(data).hexdigest()


def plan_fixture(index=0, leg='installed'):
    variant, k = producer.CELLS[index]
    rows, args = wire.fixture(k)
    data = b''.join(record + b'\n' for record in args['records'])
    plan = dict(profile='selected-session-functional-v1', revision='a' * 40,
                index=index, variant=variant, k=k, n=2, epochs=520, leg=leg,
                name=f'{leg}-{variant}-k{k}', cpus=[2, 4, 6],
                table=copy.deepcopy(args['table']), caller=copy.deepcopy(args['caller']),
                data_sha256=digest(data), table_sha256=digest(oracle.table(k)),
                binary='/frozen/ordinary-interval', candidate='/frozen/candidate.so',
                trusted='/frozen/trusted.so', expected_table='/frozen/expected.txt',
                taskset='/frozen/taskset', reference_binary='/frozen/reference',
                reference_dso='/frozen/reference.so')
    if leg == 'installed':
        argv = [plan['binary'], 'normal-selected-session', plan['candidate'],
                plan['trusted'], plan['expected_table'], str(k), '520', '2']
        for leaf in plan['table']:
            argv.extend([str(leaf['function_id']), leaf['operation'], str(leaf['elf_va']),
                         str(leaf['extent']), leaf['policy']])
    else:
        argv = [plan['taskset'], '--cpu-list', '4', plan['reference_binary'],
                plan['reference_dso'], str(len(args['records']))]
    plan['argv'] = argv
    return plan, rows, args, data


class Budget:
    def __init__(self, events):
        self.events, self.active = events, True

    def complete(self):
        # Match the real complete() seam: the caller must check active itself.
        self.events.append('complete')
        self.active = False


class Run:
    def __init__(self):
        self.safe, self.events, self.changed = True, [], False
        self.budget = Budget(self.events)

    def remember(self, path, cap):
        self.events.append(('remember', str(path), cap))

    def unchanged(self):
        self.events.append('unchanged')
        assert not self.changed, 'source changed'


class Recipe:
    def __init__(self, files):
        self.files = files

    def read(self, path, cap):
        data = self.files[str(path)]
        assert len(data) <= cap
        return data

    @staticmethod
    def pin(data):
        return {'sha256': digest(data)}


def envelope(plan, rows, args, data):
    result = {key: plan[key] for key in closure.IDENTITY}
    result.update(status='PASS', child_pid=123, child_exit=0, normal_reaps=1,
                  rescue=False, cleanup_error=None, sent_bytes=len(data),
                  original_values=[[i, len(record), oracle.fnv(record), *oracle.values(record)]
                                   for i, record in enumerate(args['records'], 1)])
    if plan['leg'] == 'installed':
        raw = wire.prior.encode(rows)
        checked = checker.check(raw, b'', **args)
        result.update(totals=checked['totals'], done=checked['rows']['DONE'][0],
                      write_blocked=checked['rows']['IO'][0]['write_blocked'])
    else:
        lines = [f'ORIGINAL,{i},{oracle.values(record)[0]},{oracle.values(record)[1]}'
                 for i, record in enumerate(args['records'], 1)]
        lines.append(f'ORIGINAL_DONE,{len(args["records"])},{2 * len(args["records"])}')
        raw = ('\n'.join(lines) + '\n').encode('ascii')
        result.update(records=len(args['records']), calls=2 * len(args['records']))
    result.update(stdout_sha256=digest(raw), stderr_sha256=digest(b''))
    return result, raw, b''


def dispatch(run, plan, result, raw, errors=b'', code=0, outer_errors=b''):
    # No subprocess: this models the additional app_files join after Run.bounded.
    encoded = json.dumps(result, sort_keys=True).encode('ascii')
    recipe = Recipe({'/fabricated/result.json': encoded,
                     '/fabricated/stdout.txt': raw, '/fabricated/stderr.txt': errors})
    return closure.complete_closed_cell(run, recipe, producer, oracle, checker, plan,
                                        Path('/fabricated'), code, encoded, outer_errors)


class Controls(unittest.TestCase):
    def test_all_eight_plans_bind_complete_population_exact_argv_and_cpu_roles(self):
        for leg in ('reference', 'installed'):
            calls = 0
            for index in range(4):
                plan, _, args, data = plan_fixture(index, leg)
                case, checked = producer.plan_arguments(plan, oracle, checker)
                self.assertEqual(case['data'], data)
                self.assertEqual(case['records'], oracle.records(plan['k']))
                self.assertEqual(checked, args)
                self.assertEqual(checked['cpus'], (2, 4))
                calls += 2 * len(case['records'])
            self.assertEqual(calls, 4052)

    def test_fixed_plan_rejects_changed_population_labels_cpus_hashes_and_argv(self):
        plan, _, _, _ = plan_fixture()
        mutations = [('profile', 'other'), ('revision', 'a' * 39), ('revision', 'A' * 40),
                     ('index', True), ('index', 4), ('variant', 'stripped'), ('k', True),
                     ('k', 1000), ('n', True), ('n', 1), ('epochs', 519), ('epochs', True),
                     ('leg', 'benchmark'), ('name', 'installed-unstripped-k1000'),
                     ('cpus', [2, 2, 6]), ('cpus', [6, 4, 2]), ('cpus', [2, 4, 1024]),
                     ('cpus', [False, 4, 6]), ('data_sha256', '0' * 64),
                     ('table_sha256', '0' * 64), ('argv', plan['argv'][:-1])]
        for key, value in mutations:
            changed = copy.deepcopy(plan)
            changed[key] = value
            with self.assertRaises(AssertionError, msg=key):
                producer.plan_arguments(changed, oracle, checker)
        for key, value in (('function_id', 102), ('operation', 'csv_fields'),
                           ('policy', 'whole'), ('extent', 257)):
            changed = copy.deepcopy(plan)
            changed['table'][0][key] = value
            with self.assertRaises(AssertionError, msg=key):
                producer.plan_arguments(changed, oracle, checker)

    def test_ready_gate_binds_actual_child_pid_and_only_selected_version(self):
        _, rows, _, _ = plan_fixture()
        ready = next(row for row in rows if row[0] == 'READY')
        producer.ready_row(wire.prior.encode([ready]).rstrip(b'\n'), 123, checker)
        for column, value in ((1, 'leaf-set-session-v1'), (11, 124), (12, 124)):
            changed = list(ready)
            changed[column] = value
            with self.assertRaises(AssertionError):
                producer.ready_row(wire.prior.encode([changed]).rstrip(b'\n'), 123, checker)
        for raw, pid in ((b'x' * 350, 123), (b'READY,selected-session-v1', 123),
                         (wire.prior.encode([ready]).rstrip(b'\n'), True)):
            with self.assertRaises(AssertionError):
                producer.ready_row(raw, pid, checker)

    def test_both_legs_all_cells_require_full_join_before_budget_and_safe(self):
        for leg in ('reference', 'installed'):
            for index in range(4):
                plan, rows, args, data = plan_fixture(index, leg)
                result, raw, errors = envelope(plan, rows, args, data)
                run = Run()
                value = dispatch(run, plan, result, raw, errors)
                self.assertEqual(value['status'], 'PASS')
                self.assertTrue(run.safe)
                self.assertFalse(run.budget.active)
                self.assertEqual(run.events[-2:], ['unchanged', 'complete'])
                self.assertEqual(value['observations']['values'], result['original_values'])
                self.assertEqual(value['observations']['source'],
                                 'actual-original-stdout' if leg == 'reference' else 'actual-installed-wire')

    def test_inactive_reservation_refuses_before_child_files_are_remembered(self):
        plan, rows, args, data = plan_fixture()
        result, raw, errors = envelope(plan, rows, args, data)
        run = Run()
        run.budget.active = False
        with self.assertRaises(AssertionError):
            dispatch(run, plan, result, raw, errors)
        self.assertFalse(run.safe)
        self.assertEqual(run.events, [])

    def test_normally_closed_failure_is_retained_without_scalar_success_credit(self):
        plan, rows, args, data = plan_fixture()
        result, _, _ = envelope(plan, rows, args, data)
        raw, errors = b'partial\n', b'actual refusal\n'
        result.update(status='FAILED', child_exit=101, sent_bytes=0,
                      stdout_sha256=digest(raw), stderr_sha256=digest(errors),
                      error='AssertionError: actual rejection')
        run = Run()
        value = dispatch(run, plan, result, raw, errors, code=1)
        self.assertEqual(value['status'], 'FAILED')
        self.assertIsNone(value['observations'])
        self.assertEqual(value['error'], result['error'])
        self.assertTrue(run.safe)
        self.assertEqual(run.events[-2:], ['unchanged', 'complete'])

    def test_unknown_or_rescued_envelope_never_completes_or_becomes_safe(self):
        plan, rows, args, data = plan_fixture()
        result, raw, errors = envelope(plan, rows, args, data)
        mutations = [('revision', 'b' * 40), ('index', False), ('status', 'UNKNOWN'),
                     ('normal_reaps', 0), ('normal_reaps', True), ('rescue', True),
                     ('cleanup_error', 'failed wait'), ('child_pid', 0), ('child_exit', None),
                     ('child_exit', 1), ('stdout_sha256', '0' * 64),
                     ('stderr_sha256', '0' * 64), ('sent_bytes', -1), ('sent_bytes', True)]
        for key, value in mutations:
            changed, run = copy.deepcopy(result), Run()
            changed[key] = value
            with self.assertRaises(AssertionError, msg=key):
                dispatch(run, plan, changed, raw, errors)
            self.assertFalse(run.safe)
            self.assertTrue(run.budget.active)
            self.assertNotIn('complete', run.events)
        for code, stderr in ((True, b''), (1, b''), (0, b'outer warning\n')):
            run = Run()
            with self.assertRaises(AssertionError):
                dispatch(run, plan, result, raw, errors, code=code, outer_errors=stderr)
            self.assertFalse(run.safe)
            self.assertNotIn('complete', run.events)

    def test_contradictory_pass_manifest_cannot_be_downgraded_to_safe_failure(self):
        for leg in ('reference', 'installed'):
            plan, rows, args, data = plan_fixture(0, leg)
            result, raw, errors = envelope(plan, rows, args, data)
            mutants = []
            changed = copy.deepcopy(result)
            changed['original_values'][0][3] += 1
            mutants.append(changed)
            changed = copy.deepcopy(result)
            changed['sent_bytes'] -= 1
            mutants.append(changed)
            if leg == 'reference':
                changed = copy.deepcopy(result)
                changed['calls'] -= 1
            else:
                changed = copy.deepcopy(result)
                changed['child_pid'] += 1
            mutants.append(changed)
            for changed in mutants:
                run = Run()
                with self.assertRaises(AssertionError):
                    dispatch(run, plan, changed, raw, errors)
                self.assertFalse(run.safe)
                self.assertNotIn('complete', run.events)

    def test_actual_raw_corruption_rejected_even_with_coherent_manifest_hash(self):
        for leg in ('reference', 'installed'):
            plan, rows, args, data = plan_fixture(0, leg)
            result, raw, errors = envelope(plan, rows, args, data)
            if leg == 'reference':
                bad_raw = raw.replace(b'ORIGINAL,1,0,0\n', b'ORIGINAL,1,1,0\n', 1)
            else:
                bad_rows = copy.deepcopy(rows)
                next(row for row in bad_rows if row[0] == 'RESULT')[4] += 1
                bad_raw = wire.prior.encode(bad_rows)
            self.assertNotEqual(bad_raw, raw)
            result['stdout_sha256'] = digest(bad_raw)
            run = Run()
            with self.assertRaises(AssertionError):
                dispatch(run, plan, result, bad_raw, errors)
            self.assertFalse(run.safe)
            self.assertNotIn('complete', run.events)

    def test_changed_first_pin_after_complete_output_stops_before_release(self):
        plan, rows, args, data = plan_fixture()
        result, raw, errors = envelope(plan, rows, args, data)
        run = Run()
        run.changed = True
        with self.assertRaises(AssertionError):
            dispatch(run, plan, result, raw, errors)
        self.assertFalse(run.safe)
        self.assertTrue(run.budget.active)
        self.assertEqual(run.events[-1], 'unchanged')
        self.assertNotIn('complete', run.events)


if __name__ == '__main__':
    unittest.main()
