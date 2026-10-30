#!/usr/bin/env python3
"""Pure fixed-population/byte-comparator controls. No subprocesses or ELF exec."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('li2_n01', Path(__file__).with_name('n01.py'))
n01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n01)


class Population(unittest.TestCase):
    def test_exact_twenty_pairs_forty_invocations(self):
        rows = n01.planned_rows()
        self.assertEqual(len(rows), 40)
        self.assertEqual(len(n01.pairs(rows)), 20)
        self.assertTrue(all(r['status'] == 'UNRUN' and not r['attempted'] for r in rows))
        self.assertEqual([r['dataset'] for r in rows[:20:2]], list(n01.DATASETS))
        self.assertEqual([r['dataset'] for r in rows[20::2]], list(n01.DATASETS))

    def test_positive_full_population_uses_independent_expected_and_baseline(self):
        rows = n01.planned_rows()
        for i, row in enumerate(rows):
            wanted = bytes([i // 2])
            self.assertTrue(n01.compare_output(0, wanted, b'', wanted,
                            candidate=row['lane'] == 'candidate', original=wanted))
            row['status'] = 'PASS'
        self.assertTrue(all(p['status'] == 'PASS' for p in n01.pairs(rows)))

    def test_missing_extra_duplicate_and_reordered_cases_refuse(self):
        rows = n01.planned_rows()
        for changed in (rows[:-1], rows+[rows[-1]], rows[:-1]+[rows[0]], list(reversed(rows))):
            with self.assertRaises(ValueError): n01.pairs(changed)

    def test_unrun_after_failure_is_not_erased_or_promoted(self):
        rows = n01.planned_rows(); rows[0]['status'] = 'FAILED'
        pairs = n01.pairs(rows)
        self.assertEqual(pairs[0]['status'], 'FAILED')
        self.assertEqual(sum(p['status'] == 'UNRUN' for p in pairs), 19)
        self.assertEqual(len(rows), 40)


class Comparator(unittest.TestCase):
    def test_changed_byte_refuses(self):
        self.assertFalse(n01.compare_output(0,b'abd',b'',b'abc',candidate=False,original=None))
    def test_both_identically_wrong_refuse(self):
        self.assertFalse(n01.compare_output(0,b'abd',b'',b'abc',candidate=True,original=b'abd'))
    def test_suffix_and_short_output_refuse(self):
        for output in (b'abcX',b'ab'):
            self.assertFalse(n01.compare_output(0,output,b'',b'abc',candidate=False,original=None))
    def test_stderr_refuses(self):
        self.assertFalse(n01.compare_output(0,b'abc',b'warning',b'abc',candidate=False,original=None))
    def test_nonzero_signal_and_bool_exit_refuse(self):
        for code in (1,125,-9,-4,False,True,None):
            self.assertFalse(n01.compare_output(code,b'abc',b'',b'abc',candidate=False,original=None))
    def test_candidate_without_successful_original_refuses(self):
        self.assertFalse(n01.compare_output(0,b'abc',b'',b'abc',candidate=True,original=None))
    def test_candidate_differs_from_successful_original_refuses(self):
        self.assertFalse(n01.compare_output(0,b'abc',b'',b'abc',candidate=True,original=b'abd'))
    def test_empty_expected_output_remains_byte_exact(self):
        self.assertTrue(n01.compare_output(0,b'',b'',b'',candidate=True,original=b''))
        self.assertFalse(n01.compare_output(0,b'\0',b'',b'',candidate=True,original=b''))


if __name__ == '__main__':
    unittest.main()
