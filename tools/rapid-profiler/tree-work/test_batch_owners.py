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
