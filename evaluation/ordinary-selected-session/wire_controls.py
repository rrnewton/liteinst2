#!/usr/bin/env python3
"""Pure full-wire controls with fabricated data; no native/closure/state credit."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
from pathlib import Path
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
output = load('_selected_full_wire_controls', HERE / 'output.py')
prior = load('_selected_prior_wire_fixture',
             HERE.parent / 'ordinary-leaf-set-session/controls.py')
oracle = output._oracle


def fixture(k=10):
    records = oracle.records(k)
    truths = tuple((payload, tuple(output._shared.truths(payload)[name]
                                  for name in prior.OPERATIONS)) for payload in records)
    rows, args = prior.fixture(n=2, count=len(records), k=k, arms=1, records=truths)
    table = tuple(dict(leaf, function_id=output.FUNCTIONS[i], operation=output.OPERATIONS[i],
                       policy='certified') for i, leaf in enumerate(args['table']))
    args.update(table=table, epochs=520)
    for row in rows:
        if row[0] == 'READY':
            row[1], row[3] = 'selected-session-v1', 520
        elif row[0] == 'LEAF':
            index = row[1]
            row[2:5] = [table[index]['function_id'], table[index]['operation'], 'certified']
        elif row[0] == 'RESULT':
            row[4:6] = oracle.values(records[row[1] - 1])
    return rows, args


def check(rows, args):
    return output.check(prior.encode(rows), b'', **args)


class Controls(unittest.TestCase):
    def test_both_fixed_populations_retain_actual_wire_and_all_values(self):
        for k, count in ((10, 12), (1000, 1001)):
            rows, args = fixture(k)
            raw = prior.encode(rows)
            result = check(rows, args)
            self.assertEqual(result['status'], 'SELECTED_SESSION_WIRE_PASS')
            self.assertEqual(result['raw'], raw)
            self.assertEqual(result['stderr'], b'')
            self.assertEqual(result['rows']['READY'][0]['version'], 'selected-session-v1')
            self.assertEqual(tuple(row['operation'] for row in result['rows']['LEAF']), output.OPERATIONS)
            self.assertEqual(len(result['rows']['CALL']), 2 * count)
            self.assertEqual(len(result['rows']['RESULT']), count)
            for row, payload in zip(result['rows']['RESULT'], oracle.records(k)):
                self.assertEqual((row['value_0'], row['value_1']), oracle.values(payload))
            self.assertEqual(result['totals']['records'], count)
            self.assertEqual(result['totals']['calls'], 2 * count)

    def test_old_public_wrapper_keeps_old_vocabulary_status_and_refusals(self):
        rows, args = prior.fixture(n=2, count=3)
        raw = prior.encode(rows)
        result = output._shared.check(raw, b'', **args)
        self.assertEqual(result['status'], 'LEAF_SET_WIRE_PASS')
        self.assertEqual(result['raw'], raw)
        self.assertEqual(result['rows']['READY'][0]['version'], 'leaf-set-session-v1')
        self.assertEqual(tuple(row['operation'] for row in result['rows']['LEAF']),
                         ('csv_fields', 'length'))
        selected_rows, selected_args = fixture()
        with self.assertRaises(AssertionError):
            output._shared.check(prior.encode(selected_rows), b'', **selected_args)
        with self.assertRaises(AssertionError):
            check(rows, args)

    def test_selected_geometry_and_input_population_are_frozen(self):
        rows, args = fixture()
        for key, value in (('function_id', 202), ('operation', 'uppercase_count'),
                           ('policy', 'whole'), ('extent', 257), ('returns', (48,)),
                           ('elf_va', 0)):
            bad = copy.deepcopy(args)
            bad['table'][0][key] = value
            with self.assertRaises(AssertionError):
                check(rows, bad)
        for key, value in (('records', args['records'][:-1]),
                           ('records', (b'x', *args['records'][1:])),
                           ('table', tuple(reversed(args['table']))), ('epochs', 519),
                           ('outcome', 'input_incomplete'), ('input_error', 'syntax'),
                           ('cpus', (2, 2)), ('caller', dict(extent=32, continuation=32))):
            bad = dict(args)
            bad[key] = value
            with self.assertRaises(AssertionError):
                check(rows, bad)

    def test_every_wire_family_remains_required_and_unique_where_bounded(self):
        rows, args = fixture()
        for tag in ('READY', 'LEAF', 'RET', 'HISTORY', 'REPORT', 'CALL', 'RESULT',
                    'SAMPLE', 'COVERAGE', 'IO', 'DONE'):
            index = next(i for i, row in enumerate(rows) if row[0] == tag)
            missing = copy.deepcopy(rows)
            del missing[index]
            with self.assertRaises(AssertionError, msg=tag):
                check(missing, args)
            duplicate = copy.deepcopy(rows)
            duplicate.insert(index, copy.deepcopy(rows[index]))
            with self.assertRaises(AssertionError, msg=tag):
                check(duplicate, args)

    def test_scalar_coordinates_and_unmodified_structural_checks_refuse_drift(self):
        rows, args = fixture()
        changes = (
            ('READY', 1, 'leaf-set-session-v1'), ('READY', 2, 1000),
            ('LEAF', 3, 'csv_fields'), ('RET', 2, 18),
            ('HISTORY', 2, 2), ('REPORT', 2, 0),
            ('CALL', 8, 18), ('CALL', 9, 0x9000), ('CALL', 10, 0x800012),
            ('CALL', 13, 1 << 32), ('CALL', 15, 'checkpoint'),
            ('RESULT', 4, 1), ('RESULT', 6, 2),
            ('SAMPLE', 9, 99), ('COVERAGE', 2, 11),
            ('DONE', 1, 'INPUT_INCOMPLETE'), ('DONE', 2, 'EpochLimit'),
        )
        for tag, column, value in changes:
            mutated = copy.deepcopy(rows)
            row = next(row for row in mutated if row[0] == tag)
            self.assertNotEqual(row[column], value)
            row[column] = value
            with self.assertRaises(AssertionError, msg=(tag, column)):
                check(mutated, args)
        with self.assertRaises(AssertionError):
            output.check(prior.encode(rows), b'warning\n', **args)

    def test_shared_semantic_rows_are_complete_guarded_u64_values(self):
        rows, args = fixture()
        semantics = output._semantic_rows(args['records'])
        malformed = [semantics[:-1], semantics + (semantics[0],)]
        for key, value in (('first_equal', True), ('first_equal', -1),
                           ('first_equal', 1 << 64), ('csv_fields', 0)):
            changed = copy.deepcopy(semantics)
            changed[0][key] = value
            malformed.append(changed)
        missing = copy.deepcopy(semantics)
        del missing[0]['uppercase_count']
        malformed.append(missing)
        extra = copy.deepcopy(semantics)
        extra[0]['extra'] = 0
        malformed.append(extra)
        for semantic_rows in malformed:
            with self.assertRaises(AssertionError):
                output._shared._check(
                    prior.encode(rows), b'', **args, operations=output.OPERATIONS,
                    version='selected-session-v1', semantic_rows=semantic_rows,
                    command='normal-selected-session', status='SELECTED_SESSION_WIRE_PASS')


if __name__ == '__main__':
    unittest.main()
