"""Strict selected transcript controls. Synthetic values have no native credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import importlib.util
from pathlib import Path
import subprocess
import unittest

spec = importlib.util.spec_from_file_location('selected_check', Path(__file__).with_name('check_output.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def state_fixture():
    rows = []
    for seed in (0x1234567887654320, 0xfedcba9801234567):
        for length in (1, 64):
            value = sum(((((128+j)*37+11+seed) & 255) ^ 90) for j in range(length)) ^ 11400714819323198485
            rows.append([str(seed), str(length), 'PASS', '2', '20', '9', '25', '800', str(value)])
    return rows


def state(rows, terminal=None, stderr=b''):
    data = ('seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value\n' +
            ''.join(','.join(row)+'\n' for row in rows)).encode()
    stdout = b'native-selected:selection=selected-checksum-v1:required=4:pairs=4:children=8:comparisons=80:real-outer-ret=8:complete\n'
    return check.state(data, stdout if terminal is None else terminal, stderr)


def work_fixture():
    values = (11400714819323198532, 11400714819323198638, 11400714819323198204,
              11400714819323190453, 11400714819323198687, 11400714819323190321,
              11400714819323199253, 11400714819323196293)
    lengths = (1, 2, 17, 64, 3, 63, 7, 32)
    owners = ('sampled', 'sampled', 'closed', 'closed', 'removed', 'sampled', 'sampled', 'closed')
    inv = ('0', '1', '', '', '', '0', '1', '')
    prefixes = (1, 1, 1, 1, 2, 3, 3, 3)
    return [[str(x) for x in (i+1, lengths[i], owners[i], 7 if i < 5 else 19, inv[i],
        prefixes[i], 27, values[i], values[i], 100+i*20, 110+i*20, 3, 3, 10)] for i in range(8)]


def work(rows, terminal=None, stderr=b''):
    text = check.WORK_COMMENT+'\n'+check.WORK_HEADER+'\n'+''.join(','.join(r)+'\n' for r in rows)
    text += (check.WORK_TERMINAL if terminal is None else terminal)+'\n'
    return check.work(text.encode(), stderr, 64)


class Recipe(unittest.TestCase):
    def test_complete_fixed_population_has_literal_values_and_actual_generation_ids(self):
        self.assertEqual(state(state_fixture())['summary']['comparisons'], 80)
        result = work(work_fixture())
        self.assertEqual(result['summary']['generations'], [7, 19])
        self.assertEqual(result['summary']['reports'], [2, 2])
        self.assertEqual([r['invocation'] for r in result['rows']], [0, 1, None, None, None, 0, 1, None])
        # Equal timestamp endpoints are allowed; no minimum-duration filter.
        r = work_fixture(); r[0][10] = r[0][9]; r[0][13] = '0'
        self.assertEqual(work(r)['rows'][0]['elapsed_ticks'], 0)

    def test_state_rows_require_order_population_counts_and_independent_scalar(self):
        for column, bad in ((0, '1'), (1, '2'), (2, 'FAILED'), (3, '1'),
                (4, '9'), (4, '26'), (5, '0'), (6, '20001'), (7, '19'), (8, '0')):
            rows = state_fixture(); rows[1][column] = bad
            with self.subTest(column=column, bad=bad), self.assertRaises(AssertionError): state(rows)
        for transform in (lambda r: r[:-1], lambda r: r + [r[0]], lambda r: r[::-1], lambda r: [r[0], r[0], *r[2:]]):
            with self.assertRaises(AssertionError): state(transform(state_fixture()))
        for stdout in (b'', b'native-selected:complete\n',
                b'native-selected:selection=selected-checksum-v1:required=4:pairs=4:children=8:comparisons=81:real-outer-ret=8:complete\n'):
            with self.assertRaises(AssertionError): state(state_fixture(), stdout)

    def test_every_work_identity_owner_prefix_and_value_field_is_required(self):
        for column, bad in ((0, '2'), (1, '64'), (2, 'closed'), (3, '0'), (4, ''),
                (4, '1'), (5, '2'), (6, '0'), (6, '64'), (7, '0'), (8, '0')):
            rows = work_fixture(); rows[0][column] = bad
            with self.subTest(column=column), self.assertRaises(AssertionError): work(rows)
        for row, column, bad in ((4, 2, 'closed'), (2, 4, '0'), (5, 3, '7'), (6, 3, '20')):
            rows = work_fixture(); rows[row][column] = bad
            with self.assertRaises(AssertionError): work(rows)
        for transform in (lambda r: r[:-1], lambda r: r + [r[0]], lambda r: r[::-1], lambda r: [r[0], r[0], *r[2:]]):
            with self.assertRaises(AssertionError): work(transform(work_fixture()))

    def test_timestamp_arithmetic_unsigned_domains_and_canonical_decimals(self):
        for column, bad in ((9, '111'), (10, '99'), (11, '4294967296'),
                (12, '4'), (13, '11')):
            rows = work_fixture(); rows[0][column] = bad
            with self.subTest(column=column), self.assertRaises(AssertionError): work(rows)
        for column in range(14):
            if column == 2: continue
            for bad in ('-1', '+1', '01', ' 1', str(1 << 64)):
                rows = work_fixture(); rows[0][column] = bad
                with self.subTest(column=column, bad=bad), self.assertRaises(AssertionError): work(rows)

    def test_work_terminal_and_structure_cannot_credit_partial_or_forged_pass(self):
        for before, after in (('originals=8', 'originals=7'), ('sampled=4', 'sampled=5'),
                ('reports=2+2', 'reports=4'), ('actions=4', 'actions=3'),
                ('joined=true', 'joined=false'), ('PASS', 'FAILED')):
            with self.assertRaises(AssertionError): work(work_fixture(), check.WORK_TERMINAL.replace(before, after))
        valid = (check.WORK_COMMENT+'\n'+check.WORK_HEADER+'\n'+''.join(','.join(r)+'\n' for r in work_fixture())+check.WORK_TERMINAL+'\n').encode()
        for data in (valid[:-1], valid+b'\n', valid.replace(b'\n', b'\r\n'), valid.replace(b',', b'\t', 1), b'0'*(check.MIB+1)):
            with self.assertRaises(AssertionError): check.work(data, b'', 64)
        with self.assertRaises(AssertionError): check.work(valid, b'diagnostic', 64)
        with self.assertRaises(AssertionError): state(state_fixture(), stderr=b'diagnostic')

    def test_refusals_are_exact_three_errors_and_no_subject_calls(self):
        data = ('case,status,refusal\n'+'\n'.join(check.REFUSALS)+'\n'+check.REFUSAL_TERMINAL+'\n').encode()
        self.assertEqual(check.refusals(data, b'')['subject_calls'], 0)
        for mutated in (data.replace(b'SourceBytes', b'SymbolOwner', 1),
                data.replace(b'subject_calls=0', b'subject_calls=1'),
                data.replace((check.REFUSALS[1]+'\n').encode(), b''), data+data,
                data.replace(b'expected-refusal', b'PASS', 1)):
            with self.assertRaises(AssertionError): check.refusals(mutated, b'')
        with self.assertRaises(AssertionError): check.refusals(data, b'diagnostic')

    def test_actual_libtest_census_names_counts_and_clean_completion_join(self):
        names = ['module::one', 'module::two', 'other::old']
        listed = b'module::one: test\nmodule::two: test\nother::old: test\n\n3 tests, 0 benchmarks\n'
        self.assertEqual(check.census(listed, b''), names)
        run = b'\nrunning 2 tests\ntest module::one ... ok\ntest module::two ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n\n'
        self.assertEqual(check.controls(run, b'', names[:2], names)['passed'], 2)
        one = b'\nrunning 1 test\ntest module::one ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n\n'
        self.assertEqual(check.controls(one, b'', names[:1], names)['passed'], 1)
        for bad in (one.replace(b'running 1 test\n', b'running 1 tests\n'),
                one.replace(b'2 filtered', b'1 filtered'), one.replace(b'1 passed', b'0 passed'),
                one.replace(b'module::one', b'module::two'),
                one.replace(b'... ok', b'... ignored'), one + b'extra\n'):
            with self.assertRaises(AssertionError): check.controls(bad, b'', names[:1], names)
        with self.assertRaises(AssertionError):
            check.controls(run.replace(b'running 2 tests\n', b'running 2 test\n'), b'', names[:2], names)
        for bad in (run.replace(b'module::two', b'module::one'), run.replace(b'module::two', b'module::bad'),
                run.replace(b'1 filtered', b'2 filtered'), run.replace(b'0 failed', b'1 failed'),
                run.replace(b'... ok', b'... ignored', 1), run.replace(b'test module::two ... ok\n', b'')):
            with self.assertRaises(AssertionError): check.controls(bad, b'', names[:2], names)
        for bad in (listed.replace(b'3 tests', b'2 tests'), listed.replace(b'module::two', b'module::one'), listed+b'extra\n'):
            with self.assertRaises(AssertionError): check.census(bad, b'')

    def test_all_python_entrypoints_refuse_optimized_before_work(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root/'verify_selected_interval.py', Path(__file__).with_name('provenance.py'),
                     Path(__file__), Path(__file__).with_name('test_provenance.py'), Path(__file__).with_name('check_output.py')):
            for args in ((str(path),), ('-c', 'import runpy; runpy.run_path('+repr(str(path))+')')):
                p = subprocess.run([sys.executable, '-B', '-O', *args], capture_output=True, timeout=5, check=False)
                self.assertEqual((p.returncode, p.stdout, p.stderr), (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
