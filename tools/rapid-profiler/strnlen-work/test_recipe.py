"""Fabricated protocol/build-input controls; no compiler or native evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

_path = Path(__file__).resolve().with_name('check_output.py')
_spec = importlib.util.spec_from_file_location('strnlen_output_controls', _path)
assert _spec is not None and _spec.loader is not None
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


def state_fixture():
    rows = []
    for seed in (0x1234567887654320, 0xfedcba9801234567):
        for i, (case, bound, value) in enumerate(zip(check.CASES, (0, 1, 1, 2, 17, 64, 64, 64), (0, 0, 1, 1, 8, 0, 63, 64))):
            rows.append([str(x) for x in (seed, case, bound, 'PASS', 2, 23, 12, 25, 800, value,
                0 if i == 0 else 1, 0 if i == 0 else 1, 6, 5, 8, 9, 2, 40 if i == 0 else 34)])
    return rows


STATE_TERMINAL = b'native-strnlen:selection=freebsd-strnlen-14.1-v1:required=16:pairs=16:children=32:comparisons=368:input-reads=14:input-bytes=14:coverage-seeds=2:real-outer-ret=32:complete\n'


def state(rows, terminal=STATE_TERMINAL, stderr=b''):
    return check.state((check.STATE_HEADER + '\n' + ''.join(','.join(r) + '\n' for r in rows)).encode(), terminal, stderr, 41)


def work_fixture():
    return [[str(x) for x in (i + 1, case, bound, owner, 7 if i < 5 else 19, invocation, prefix,
        40 if i == 0 else 34, value, value, 100 + 20 * i, 110 + 20 * i, 3, 3, 10)]
        for i, (case, bound, value, owner, invocation, prefix) in enumerate(zip(check.CASES,
            (0, 1, 1, 2, 17, 64, 64, 64), (0, 0, 1, 1, 8, 0, 63, 64),
            ('sampled', 'sampled', 'closed', 'closed', 'removed', 'sampled', 'sampled', 'closed'),
            ('0', '1', '', '', '', '0', '1', ''), (1, 1, 1, 1, 2, 3, 3, 3)))]


def work_bytes(rows):
    return (check.WORK_COMMENT + '\n' + check.WORK_HEADER + '\n' + ''.join(','.join(r) + '\n' for r in rows) + check.WORK_TERMINAL + '\n').encode()


def macro_fixture():
    return b'\n'.join(b'#define ' + name + b' ' + value for name, value in (
        (b'__SIZEOF_POINTER__', b'8'), (b'__SIZEOF_SIZE_T__', b'8'), (b'__SIZEOF_LONG__', b'8'),
        (b'__SIZEOF_INT__', b'4'), (b'__CHAR_BIT__', b'8'), (b'__LP64__', b'1'), (b'_LP64', b'1'),
        (b'__x86_64__', b'1'), (b'__linux__', b'1'), (b'__STDC_HOSTED__', b'1'),
        (b'__BYTE_ORDER__', b'__ORDER_LITTLE_ENDIAN__'), (b'__ORDER_LITTLE_ENDIAN__', b'1234'),
        (b'__SIZE_TYPE__', b'long unsigned int'))) + b'\n'


class Recipe(unittest.TestCase):
    def test_complete_zero_early_and_bound_population_has_literal_scalar_values(self):
        self.assertEqual([check.expected(i) for i in range(8)], [0, 0, 1, 1, 8, 0, 63, 64])
        self.assertEqual(state(state_fixture())['summary']['comparisons'], 368)
        result = check.work(work_bytes(work_fixture()), b'', 41)
        self.assertEqual(result['summary']['generations'], [7, 19])
        self.assertEqual(result['summary']['reports'], [2, 2])
        check.join(state(state_fixture()), result)
        rows = work_fixture(); rows[1][7] = '40'
        with self.assertRaises(AssertionError): check.join(state(state_fixture()), check.work(work_bytes(rows), b'', 41))

    def test_every_state_field_and_complete_order_is_required(self):
        for column, bad in enumerate(('0', 'full-bound', '1', 'FAILED', '1', '24', '0', '20', '20001',
                                      '1', '1', '1', '9', '10', '0', '17', '3', '0')):
            rows = state_fixture(); rows[0][column] = bad
            with self.subTest(column=column), self.assertRaises(AssertionError): state(rows)
        for mutate in (lambda r: r[:-1], lambda r: r + [r[0]], lambda r: r[::-1], lambda r: [r[0], r[0], *r[2:]]):
            with self.assertRaises(AssertionError): state(mutate(state_fixture()))
        rows = state_fixture()
        for row in rows[8:]: row[17] = '35'
        with self.assertRaises(AssertionError): state(rows)
        for terminal in (b'', STATE_TERMINAL[:-1], STATE_TERMINAL.replace(b'pairs=16', b'pairs=15'), STATE_TERMINAL + b'extra\n'):
            with self.assertRaises(AssertionError): state(state_fixture(), terminal)

    def test_every_work_identity_owner_and_scalar_field_is_required(self):
        for column, bad in enumerate(('2', 'single-empty', '1', 'closed', '0', '', '2', '0', '1', '1',
                                      '111', '99', '4', '4', '11')):
            rows = work_fixture(); rows[0][column] = bad
            with self.subTest(column=column), self.assertRaises(AssertionError): check.work(work_bytes(rows), b'', 41)
        for i, column, bad in ((2, 5, '0'), (4, 3, 'closed'), (5, 4, '7'), (6, 4, '20')):
            rows = work_fixture(); rows[i][column] = bad
            with self.assertRaises(AssertionError): check.work(work_bytes(rows), b'', 41)
        for mutate in (lambda r: r[:-1], lambda r: r + [r[0]], lambda r: r[::-1], lambda r: [r[0], r[0], *r[2:]]):
            with self.assertRaises(AssertionError): check.work(work_bytes(mutate(work_fixture())), b'', 41)

    def test_ticks_remain_uncalibrated_with_equal_endpoints_and_checked_arithmetic(self):
        rows = work_fixture(); rows[0][11] = rows[0][10]; rows[0][14] = '0'
        self.assertEqual(check.work(work_bytes(rows), b'', 41)['rows'][0]['elapsed_ticks'], 0)
        for column, bad in ((10, str(1 << 64)), (12, str(1 << 32)), (13, '4'), (14, '18446744073709551615')):
            rows = work_fixture(); rows[0][column] = bad
            with self.assertRaises(AssertionError): check.work(work_bytes(rows), b'', 41)
        with self.assertRaises(AssertionError): check.work(work_bytes(work_fixture()), b'notice\n', 41)
        with self.assertRaises(AssertionError): state(state_fixture(), stderr=b'notice\n')

    def test_ascii_exact_lf_headers_columns_terminal_and_canonical_numbers(self):
        good = work_bytes(work_fixture())
        for bad in (good[:-1], good + b'\n', good.replace(b'\n', b'\r\n'), good.replace(b'\n', b'\v', 1),
                    good.replace(b'\n', b'\x1c', 1), good.replace(b'ordinal,case', b'case,ordinal'),
                    good.replace(b'calls=8', b'calls=7'), good + b'PASS\n', b'\xff' + good):
            with self.assertRaises(AssertionError): check.work(bad, b'', 41)
        for bad in ('01', '+1', '-1', '1.0', '1e0', ' 1', '', str(1 << 64)):
            rows = work_fixture(); rows[0][0] = bad
            with self.assertRaises(AssertionError): check.work(work_bytes(rows), b'', 41)
        for extra in (True, False):
            rows = work_fixture()
            if extra: rows[0].append('0')
            else: rows[0].pop()
            with self.assertRaises(AssertionError): check.work(work_bytes(rows), b'', 41)

    def test_all_three_preload_refusals_are_exact_and_have_no_subject_calls(self):
        good = ('case,status,refusal\n' + '\n'.join(check.REFUSALS) + '\n' + check.REFUSAL_TERMINAL + '\n').encode()
        self.assertEqual(check.refusals(good, b'')['subject_calls'], 0)
        for bad in (good.replace(b'SymbolOwner', b'SourceBytes'), good.replace(b'subject_calls=0', b'subject_calls=1'),
                    good.replace((check.REFUSALS[1] + '\n').encode(), b''), good + good, good.replace(b'expected-refusal', b'PASS')):
            with self.assertRaises(AssertionError): check.refusals(bad, b'')
        with self.assertRaises(AssertionError): check.refusals(good, b'panic\n')

    def test_make_dependency_grammar_requires_exact_absolute_nonduplicate_inputs(self):
        good = b'strnlen-inputs: /repo/strnlen.c \\\n /usr/include/string.h\n'
        self.assertEqual(check.dependencies(good), ['/repo/strnlen.c', '/usr/include/string.h'])
        for bad in (good.replace(b'strnlen-inputs:', b'other:'), good + b'other: /etc/a\n',
                    good.replace(b'/usr/include/string.h', b'/repo/strnlen.c'), good.replace(b'/repo/', b'../'),
                    good.replace(b'/usr/include/', b'/usr/../include/'), good.replace(b' ', b'\v'), b'strnlen-inputs:\n'):
            with self.assertRaises(AssertionError): check.dependencies(bad)

    def test_preprocessed_body_and_linux_lp64_authority_are_not_substitutable(self):
        source = Path(__file__).resolve().with_name('strnlen.c').read_bytes()
        expanded = ('typedef long unsigned int size_t;\n' + check.BODY + '\n').encode()
        macros = macro_fixture()
        self.assertEqual(check.preprocessing(source, expanded, macros)['size_t_bits'], 64)
        for bad in (expanded.replace(b'!*s', b'*s'), expanded + b'int extra;\n', expanded + expanded,
                    expanded.replace(b'long unsigned int', b'unsigned int')):
            with self.assertRaises(AssertionError): check.preprocessing(source, bad, macros)
        for bad in (macros.replace(b'__SIZEOF_POINTER__ 8', b'__SIZEOF_POINTER__ 4'),
                    macros.replace(b'__linux__ 1', b'__linux__ 0'), macros + b'#define strnlen substituted\n',
                    macros + b'#define __SIZE_TYPE__ long unsigned int\n'):
            with self.assertRaises(AssertionError): check.preprocessing(source, expanded, bad)
        with self.assertRaises(AssertionError): check.preprocessing(source + b'\n', expanded, macros)

    def test_module_is_loaded_by_own_path_and_optimization_refuses_before_work(self):
        self.assertEqual(Path(check.__file__).resolve(), _path)
        with tempfile.TemporaryDirectory() as directory:
            for path in (_path, _path.parents[1] / 'verify_strnlen_interval.py'):
                result = subprocess.run([sys.executable, '-B', '-O', str(path)], cwd=directory,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
                with self.subTest(path=path.name):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr, b'assertions required\n')


if __name__ == '__main__':
    unittest.main()
