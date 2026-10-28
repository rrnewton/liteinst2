#!/usr/bin/env python3
"""Fabricated protocol tests only; no project/native execution."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('batch_owners', Path(__file__).with_name('verify_batch_owners.py'))
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


def output(case):
    return ('\nrunning 1 test\ntest '+owner.PREFIX+case[0]+' ... '+owner.expected(case)+
        '\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1200 filtered out; finished in 0.25s\n\n').encode('ascii')


def pure_output():
    return ('\nrunning 10 tests\n'+''.join('test '+owner.PURE_PREFIX+name+' ... ok\n' for name in owner.PURE_TESTS)+
        '\ntest result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 374 filtered out; finished in 0.25s\n\n').encode('ascii')


class BatchOwnerProtocol(unittest.TestCase):
    def test_complete_finite_population_and_separate_outcomes(self):
        self.assertEqual(len(owner.CASES), 19)
        self.assertEqual(len({c[0] for c in owner.CASES}), 19)
        self.assertEqual([sum(c[i] for c in owner.CASES) for i in (1, 2, 3, 5)], [29, 61, 8, 2])
        for case in owner.CASES:
            got = owner.parse(case, output(case), b'')
            self.assertEqual((got['case'], got['status'], got['successful_batch_finishes']), (case[0], 'PASS', case[3]))
            self.assertEqual(got['expected_refusal'], case[4])

    def test_every_terminal_field_and_named_case_is_required(self):
        for case in owner.CASES:
            good = output(case)
            for field in owner.expected(case).split():
                bad = good.replace(field.encode('ascii'), (field+'X').encode('ascii'), 1)
                with self.assertRaises(AssertionError):
                    owner.parse(case, bad, b'')
            for other in owner.CASES:
                if other != case:
                    with self.assertRaises(AssertionError):
                        owner.parse(case, output(other), b'')

    def test_actual_pure_inventory_and_harness_refusals(self):
        good = pure_output()
        result = owner.parse_pure(good, b'')
        self.assertEqual((result['passed'], result['failed'], result['ignored'], result['filtered']), (10, 0, 0, 374))
        self.assertEqual(set(result['names']), set(owner.PURE_TESTS))
        lines = good.splitlines(keepends=True)
        for index in range(2, 12):
            missing = b''.join(lines[:index]+lines[index+1:])
            duplicate = b''.join(lines[:index]+[lines[2 if index != 2 else 3]]+lines[index+1:])
            wrong = b''.join(lines[:index]+[lines[index].replace(b' ... ok', b'_unknown ... ok')]+lines[index+1:])
            failed = b''.join(lines[:index]+[lines[index].replace(b' ... ok', b' ... FAILED')]+lines[index+1:])
            for bad in (missing, duplicate, wrong, failed):
                with self.assertRaises(AssertionError):
                    owner.parse_pure(bad, b'')
        for first, second in ((b'running 10', b'running 9'), (b'10 passed', b'9 passed'),
                (b'0 failed', b'1 failed'), (b'0 ignored', b'1 ignored'), (b'0 measured', b'1 measured'),
                (b'374 filtered', b'373 filtered'), (b'374 filtered', b'375 filtered'),
                (owner.PURE_PREFIX.encode('ascii'), b'wrong::')):
            with self.assertRaises(AssertionError):
                owner.parse_pure(good.replace(first, second), b'')
        for bad in (b'', good[:-1], good+b'\n', good+good, good.replace(b'\n', b'\r\n')):
            with self.assertRaises(AssertionError):
                owner.parse_pure(bad, b'')
        with self.assertRaises(AssertionError):
            owner.parse_pure(good, b'warning\n')

    def test_accessor_first_case_is_additive_and_exact(self):
        self.assertEqual(owner.ALL_CASES[:19], owner.CASES)
        self.assertEqual(len(owner.ALL_CASES), 20)
        self.assertEqual(len({c[0] for c in owner.ALL_CASES}), 20)
        self.assertEqual([sum(c[i] for c in owner.ALL_CASES) for i in (1, 2, 3, 5)], [29, 62, 8, 2])
        case = owner.TOTALS_CASE
        self.assertEqual(case, ('installed_totals_first_error', 0, 1, 0, 'ControllerReentry', 0, True))
        got = owner.parse(case, output(case), b'')
        self.assertEqual((got['installed_roots'], got['successful_batch_finishes'], got['expected_refusal'], got['retained_poison']), (1, 0, 'ControllerReentry', True))
        good = output(case)
        for field in owner.expected(case).split():
            with self.assertRaises(AssertionError):
                owner.parse(case, good.replace(field.encode('ascii'), (field+'X').encode('ascii'), 1), b'')
        for other in owner.CASES:
            with self.assertRaises(AssertionError):
                owner.parse(case, output(other), b'')
            with self.assertRaises(AssertionError):
                owner.parse(other, good, b'')
        for bad in (b'', good[:-1], good+b'\n', good+good, good.replace(b'0 failed;', b'1 failed;')):
            with self.assertRaises(AssertionError):
                owner.parse(case, bad, b'')
        with self.assertRaises(AssertionError):
            owner.parse(case, good, b'warning\n')

    def test_exact_libtest_envelope_and_empty_stderr(self):
        for case in owner.CASES:
            good = output(case)
            for bad in (b'', good[:-1], good+b'\n', good.replace(b'\n', b'\r\n'),
                    good.replace(b'1 passed; 0 failed;', b'0 passed; 1 failed;'),
                    good.replace(b'0 ignored;', b'1 ignored;'), good.replace(b' ... ', b' ... ignored '),
                    good.replace(b'PASS', b'SKIP'), good.replace(owner.PREFIX.encode('ascii'), b'other::')):
                with self.assertRaises(AssertionError):
                    owner.parse(case, bad, b'')
            with self.assertRaises(AssertionError):
                owner.parse(case, good, b'warning\n')


if __name__ == '__main__':
    unittest.main()
