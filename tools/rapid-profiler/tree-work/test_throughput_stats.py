#!/usr/bin/env python3
"""Finite estimator/protocol controls, with no native or measurement execution."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
import math
from pathlib import Path
import random
import unittest

SPEC = importlib.util.spec_from_file_location('throughput_stats', Path(__file__).with_name('throughput_stats.py'))
STATS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATS)


def fixture():
    records = []
    for request in STATS.plan():
        scale = {'original-sdk': 1, 'k1': 2, 'k10': 3, 'k24': 4}[request['mode']]
        base = 100000 * request['block']
        records.append(dict(request, status='FUNCTIONAL_PASS', roots=1536,
            whole_wall_ns=base*scale, whole_cpu_ns=base*scale//2,
            loop_wall_ns=base*scale//4, loop_cpu_ns=base*scale//8))
    return records


class ThroughputStatistics(unittest.TestCase):
    def test_frozen_randomized_order_and_complete_population(self):
        rng = random.Random(0x4c49544554524545)
        generated = []
        for _ in range(13):
            row = ['original-sdk', 'k1', 'k10', 'k24']; rng.shuffle(row); generated.append(tuple(row))
        self.assertEqual(tuple(generated), STATS.ORDER)
        self.assertEqual(len(STATS.plan()), 52)
        self.assertEqual(sum(r['phase'] == 'warmup' for r in STATS.plan()), 12)
        result = STATS.summarize(fixture())
        self.assertEqual(len(result['comparisons']), 12)
        for row in result['comparisons']:
            ratio = {'k1': 0.5, 'k10': 1/3, 'k24': 0.25}[row['mode']]
            self.assertAlmostEqual(row['geometric_ratio'], ratio, places=14)
            self.assertAlmostEqual(row['ratio_interval_low'], ratio, places=14)
            self.assertAlmostEqual(row['ratio_interval_high'], ratio, places=14)
            self.assertEqual(row['pairs'], 10)

    def test_exact_paired_log_estimator_and_conditional_interval(self):
        records = fixture()
        exponents = [-4, -3, -2, -1, 0, 0, 1, 2, 3, 4]
        for record in records:
            if record['phase'] == 'measured':
                value = 1024 if record['mode'] == 'original-sdk' else 2**(10-exponents[record['block']-1])
                for metric in STATS.METRICS: record[metric] = value
        rows = STATS.summarize(records)['comparisons']
        for row in rows:
            self.assertAlmostEqual(row['geometric_ratio'], 1.0, places=14)
            # Ten symmetric exponents have zero mean and sum of squares60.
            width = 2.2621571627409915 * math.sqrt(2/3)
            self.assertAlmostEqual(row['ratio_interval_low'], 2**(-width), places=14)
            self.assertAlmostEqual(row['ratio_interval_high'], 2**width, places=14)
            self.assertEqual(row['paired_ratios'], [2**e for e in exponents])
            self.assertAlmostEqual(row['cost_interval_low_percent'], 100*(2**(-width)-1), places=11)
            self.assertAlmostEqual(row['cost_interval_high_percent'], 100*(2**width-1), places=11)
            if row['metric'].endswith('_wall_ns'):
                self.assertAlmostEqual(row['loss_interval_low_percent'], 100*(1-2**width), places=11)
                self.assertAlmostEqual(row['loss_interval_high_percent'], 100*(1-2**(-width)), places=11)
            else:
                self.assertNotIn('throughput_loss_percent', row)

    def test_no_outlier_removal_clipping_or_warmup_selection(self):
        good = fixture(); expected = STATS.summarize(good)
        for row in good:
            if row['phase'] == 'warmup':
                for metric in STATS.METRICS: row[metric] = 2**64-1
        self.assertEqual(STATS.summarize(good), expected)
        faster = fixture()
        for row in faster:
            if row['mode'] != 'original-sdk':
                for metric in STATS.METRICS: row[metric] = 1
        for row in STATS.summarize(faster)['comparisons']:
            self.assertLess(row['cost_increase_percent'], 0)
            if row['metric'].endswith('_wall_ns'):
                self.assertLess(row['throughput_loss_percent'], 0)
        outlier = fixture()
        for row in outlier:
            if row['phase'] == 'measured' and row['mode'] == 'k1' and row['block'] == 10:
                row['whole_wall_ns'] *= 2**40
        changed = STATS.summarize(outlier)['comparisons'][0]
        self.assertEqual(len(changed['paired_ratios']), 10)
        self.assertLess(changed['geometric_ratio'], expected['comparisons'][0]['geometric_ratio'])
        self.assertGreater(changed['sample_sd_log_ratio'], 0)

    def test_every_missing_duplicate_reordered_or_failed_trial_refuses(self):
        good = fixture()
        for i in range(52):
            for bad in (good[:i]+good[i+1:], good[:i]+[good[i]]+good[i:]):
                with self.assertRaises(AssertionError): STATS.summarize(bad)
            for field, value in (('trial', 0), ('phase', 'skipped'), ('block', 0), ('position', 0),
                                 ('mode', 'other'), ('status', 'FAILED'), ('roots', 1535)):
                bad = copy.deepcopy(good); bad[i][field] = value
                with self.subTest(i=i, field=field), self.assertRaises(AssertionError): STATS.summarize(bad)
        bad = list(reversed(good))
        with self.assertRaises(AssertionError): STATS.summarize(bad)
        bad = copy.deepcopy(good);bad[1] = bad[0]
        with self.assertRaises(AssertionError): STATS.summarize(bad)
        bad = copy.deepcopy(good);bad[0]['trial'] = True
        with self.assertRaises(AssertionError): STATS.summarize(bad)
        bad = copy.deepcopy(good);bad[0]['roots'] = 1536.0
        with self.assertRaises(AssertionError): STATS.summarize(bad)

    def test_metric_domain_has_no_short_or_slow_exemption(self):
        good = fixture()
        for metric in STATS.METRICS:
            for value in (0, -1, 2**64, True, 1.0, '1', None):
                bad = copy.deepcopy(good);bad[0][metric] = value
                with self.subTest(metric=metric, value=value), self.assertRaises(AssertionError): STATS.summarize(bad)
        for row in good:
            for metric in STATS.METRICS: row[metric] = 1
        for result in STATS.summarize(good)['comparisons']:
            self.assertEqual(result['geometric_ratio'], 1)
            self.assertEqual(result['cost_increase_percent'], 0)
        for clock in ('wall', 'cpu'):
            bad = fixture();bad[0]['loop_'+clock+'_ns'] = bad[0]['whole_'+clock+'_ns'] + 1
            with self.assertRaises(AssertionError): STATS.summarize(bad)
        # The clocks have separate boundaries; CPU can exceed wall without
        # violating either clock's own nested-region relation.
        good = fixture()
        for row in good:
            row['whole_cpu_ns'] = 2*row['whole_wall_ns']
            row['loop_cpu_ns'] = 2*row['loop_wall_ns']
        self.assertEqual(len(STATS.summarize(good)['comparisons']), 12)


if __name__ == '__main__':
    unittest.main()
