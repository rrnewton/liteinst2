#!/usr/bin/env python3
"""Fabricated cohort controls only; no clocks, subprocesses or native workload."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('batch_comparison_stats', Path(__file__).with_name('batch_comparison_stats.py'))
STATS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATS)

MODES = ('native', 'original-sdk', 'k1', 'k10', 'k24',
         'original-sdk-batch8', 'k1-batch8', 'k10-batch8', 'k24-batch8')
METRICS = ('process_wall_ns', 'child_cpu_us', 'whole_wall_ns', 'whole_cpu_ns', 'loop_wall_ns', 'loop_cpu_ns')
WALL = {'process_wall_ns', 'whole_wall_ns', 'loop_wall_ns'}
SCALES = dict(zip(MODES, (4, 8, 12, 16, 20, 2, 16, 8, 40)))


def fixture():
    records = []
    for request in STATS.plan():
        base = 100000 * request['block'] * SCALES[request['mode']]
        records.append(dict(request, status='FUNCTIONAL_PASS', roots=1536,
            process_wall_ns=base*2, child_cpu_us=base//1000, whole_wall_ns=base,
            whole_cpu_ns=base//2, loop_wall_ns=base//4, loop_cpu_ns=base//8))
    return records


def identity(row):
    return (row['comparison'], row['numerator_mode'], row['denominator_mode'], row['metric'])


def indexed(result):
    rows = result['comparisons']
    out = {identity(row): row for row in rows}
    assert len(out) == len(rows) == 72
    return out


class BatchComparisonStatistics(unittest.TestCase):
    def refuses(self, records):
        with self.assertRaises((AssertionError, KeyError)):
            STATS.summarize(records)

    def test_full_frozen_order_catalog_and_old_five_projection(self):
        names = dict(zip(('N', 'O', '1', '10', '24', 'B', 'B1', 'B10', 'B24'), MODES))
        literal = (
            'B10 B1 B24 24 10 N O 1 B', 'O B24 N 10 B10 24 B1 1 B',
            'B O 10 B10 B24 N B1 1 24', 'O B10 24 1 B1 B B24 N 10',
            'B24 B1 O B10 N 24 10 B 1', 'O B10 B1 B N 24 B24 10 1',
            '1 B10 B N B24 10 24 O B1', '10 B24 B 24 O B10 N 1 B1',
            'O 1 10 24 B1 B B24 B10 N', 'B1 N B10 10 B24 B 24 1 O',
            'B10 N B24 10 O 24 B1 1 B', 'O 1 N B 10 B10 B1 24 B24',
            'N B B10 24 1 B24 10 B1 O',
        )
        old = ('24 10 N O 1', 'O N 10 24 1', 'O 10 N 1 24', 'O 24 1 N 10',
               'O N 24 10 1', 'O N 24 10 1', '1 N 10 24 O', '10 24 O N 1',
               'O 1 10 24 N', 'N 10 24 1 O', 'N 10 O 24 1', 'O 1 N 10 24', 'N 24 1 10 O')
        expected = []
        for block, words in enumerate(literal):
            order = tuple(names[word] for word in words.split())
            self.assertEqual(order, STATS.ORDER[block])
            self.assertEqual(tuple(mode for mode in order if mode in MODES[:5]),
                             tuple(names[word] for word in old[block].split()))
            for position, mode in enumerate(order, 1):
                expected.append(dict(trial=len(expected)+1, phase='warmup' if block < 3 else 'measured',
                    block=block+1 if block < 3 else block-2, position=position, mode=mode))
        self.assertEqual(STATS.MODES, MODES)
        self.assertEqual(STATS.METRICS, METRICS)
        self.assertEqual(STATS.plan(), expected)
        encoded = json.dumps(expected, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        self.assertEqual(len(encoded), 8532)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(),
                         '1db341efa8aef143ad51683db4812b0914d181a2f13fcb7e40bc0b268c408d71')
        self.assertEqual(len(expected), 117)
        self.assertEqual(sum(row['phase'] == 'warmup' for row in expected), 27)
        for mode in MODES:
            self.assertEqual(sum(row['mode'] == mode for row in expected), 13)
        result = STATS.summarize(fixture())
        self.assertEqual((result['processes'], result['warmup_processes'], result['measured_processes'],
                          result['roots_per_process']), (117, 27, 90, 1536))
        self.assertEqual(result['primary_metric'], 'process_wall_ns')
        self.assertEqual(len(result['comparisons']), 72)

    def test_constant_cost_speedup_regression_labels_and_raw_pairs(self):
        records = fixture()
        before = copy.deepcopy(records)
        measured = {(r['block'], r['mode']): r for r in records if r['phase'] == 'measured'}
        rows = indexed(STATS.summarize(records))
        self.assertEqual(records, before)
        # Literal C, cost increase%, wall loss%: faster SDK and slower batch are retained.
        cost = dict(zip(MODES[1:], ((2, 100, 50), (3, 200, 200/3), (4, 300, 75), (5, 400, 80),
                                   (0.5, -50, -100), (4, 300, 75), (2, 100, 50), (10, 900, 90))))
        counterpart = {'original-sdk': (4, 75), 'k1': (0.75, -100/3), 'k10': (2, 50), 'k24': (0.5, -100)}
        for key, row in rows.items():
            kind, numerator, denominator, metric = key
            self.assertEqual(row['status'], 'ESTIMATED')
            self.assertEqual(row['pairs'], 10)
            self.assertEqual(row['method'], 'geometric_mean_of_ten_within_block_paired_ratios')
            self.assertEqual(row['interval_method'], 'two_sided_95_percent_student_t9_on_mean_log_ratio')
            self.assertEqual(row['paired_values'], [[measured[(b, numerator)][metric], measured[(b, denominator)][metric]]
                                                   for b in range(1, 11)])
            if kind == 'sdk_vs_native':
                self.assertEqual(denominator, 'native')
                ratio, increase, loss = cost[numerator]
                self.assertEqual(row['ratio_name'], 'sdk_over_native_cost')
                for field in ('cost_increase_percent', 'cost_interval_low_percent', 'cost_interval_high_percent'):
                    self.assertAlmostEqual(row[field], increase, places=11)
                self.assertNotIn('cost_reduction_percent', row)
                if metric in WALL:
                    for field in ('throughput_loss_percent', 'loss_interval_low_percent', 'loss_interval_high_percent'):
                        self.assertAlmostEqual(row[field], loss, places=11)
                else:
                    self.assertNotIn('throughput_loss_percent', row)
                    self.assertNotIn('loss_interval_low_percent', row)
            else:
                self.assertEqual(kind, 'old_sdk_vs_batch_sdk')
                self.assertEqual(denominator, numerator+'-batch8')
                ratio, reduction = counterpart[numerator]
                self.assertEqual(row['ratio_name'], 'old_sdk_over_batch_sdk_wall_speedup' if metric in WALL
                                 else 'old_sdk_over_batch_sdk_cpu_cost')
                for field in ('cost_reduction_percent', 'reduction_interval_low_percent', 'reduction_interval_high_percent'):
                    self.assertAlmostEqual(row[field], reduction, places=11)
                self.assertNotIn('cost_increase_percent', row)
                self.assertNotIn('throughput_loss_percent', row)
            for field in ('geometric_ratio', 'ratio_interval_low', 'ratio_interval_high'):
                self.assertAlmostEqual(row[field], ratio, places=13)
            self.assertEqual(row['paired_ratios'], [ratio]*10)
        # The complete result is serializable without NaN/Infinity or tuple coercion.
        result = STATS.summarize(records)
        self.assertEqual(json.loads(json.dumps(result, allow_nan=False)), result)

    def test_varying_analytical_log_interval_and_reciprocal_transforms(self):
        records = fixture()
        # Mean exponent1; squared deviations sum60. No sample estimator is used here.
        exponents = (-3, -2, -1, 0, 1, 1, 2, 3, 4, 5)
        for record in records:
            if record['phase'] == 'measured':
                e = exponents[record['block']-1]
                power = 10 if record['mode'] == 'native' else 10-e if record['mode'].endswith('-batch8') else 10+e
                for metric in METRICS:
                    record[metric] = 2**power
        rows = indexed(STATS.summarize(records))
        width = 2.2621571627409915 * math.sqrt(2/3)
        for metric in METRICS:
            old = rows[('sdk_vs_native', 'original-sdk', 'native', metric)]
            new = rows[('sdk_vs_native', 'original-sdk-batch8', 'native', metric)]
            paired = rows[('old_sdk_vs_batch_sdk', 'original-sdk', 'original-sdk-batch8', metric)]
            for row, mean, spread, powers in ((old, 1, width, exponents),
                    (new, -1, width, [-e for e in exponents]),
                    (paired, 2, 2*width, [2*e for e in exponents])):
                self.assertEqual(row['paired_ratios'], [2**e for e in powers])
                self.assertAlmostEqual(row['geometric_ratio'], 2**mean, places=13)
                self.assertAlmostEqual(row['ratio_interval_low'], 2**(mean-spread), places=12)
                self.assertAlmostEqual(row['ratio_interval_high'], 2**(mean+spread), places=12)
            self.assertAlmostEqual(old['ratio_interval_low'], 1/new['ratio_interval_high'], places=12)
            self.assertAlmostEqual(old['ratio_interval_high'], 1/new['ratio_interval_low'], places=12)
            self.assertAlmostEqual(old['cost_interval_low_percent'], 100*(2**(1-width)-1), places=10)
            self.assertAlmostEqual(old['cost_interval_high_percent'], 100*(2**(1+width)-1), places=10)
            self.assertAlmostEqual(paired['reduction_interval_low_percent'], 100*(1-2**(-2+2*width)), places=10)
            self.assertAlmostEqual(paired['reduction_interval_high_percent'], 100*(1-2**(-2-2*width)), places=10)
            if metric in WALL:
                self.assertAlmostEqual(old['loss_interval_low_percent'], 100*(1-2**(-1+width)), places=10)
                self.assertAlmostEqual(old['loss_interval_high_percent'], 100*(1-2**(-1-width)), places=10)
            else:
                self.assertNotIn('throughput_loss_percent', old)
                self.assertNotIn('speedup', paired['ratio_name'])

    def test_all_missing_extra_duplicate_reordered_and_failed_trials_refuse(self):
        good = fixture()
        self.refuses(tuple(good))
        for i in range(117):
            with self.subTest(index=i):
                self.refuses(good[:i]+good[i+1:])
                self.refuses(good[:i]+[good[i]]+good[i:])
                bad = list(good); bad[i] = good[(i+1) % 117]; self.refuses(bad)
                bad = list(good); j = (i+1) % 117; bad[i], bad[j] = bad[j], bad[i]; self.refuses(bad)
                for status in ('FAILED', 'UNRUN'):
                    bad = copy.deepcopy(good); bad[i]['status'] = status; self.refuses(bad)
        self.refuses(list(reversed(good)))

    def test_all_request_required_field_types_and_wrong_population_refuse(self):
        good = fixture()
        class Text(str):
            pass
        for i in (0, 26, 27, 116):
            for field in ('trial', 'phase', 'block', 'position', 'mode', 'status', 'roots')+METRICS:
                bad = copy.deepcopy(good); del bad[i][field]; self.refuses(bad)
            for field in ('trial', 'phase', 'block', 'position', 'mode'):
                value = good[i][field]
                bad_values = (True, float(value), str(value), None, value+1) if type(value) is int else (
                    value.encode('ascii'), Text(value), None, True, 'other')
                for changed in bad_values:
                    bad = copy.deepcopy(good); bad[i][field] = changed; self.refuses(bad)
            for roots in (0, 1535, 1537, 1536.0, '1536', True, None):
                bad = copy.deepcopy(good); bad[i]['roots'] = roots; self.refuses(bad)
            for status in (None, True, 1, 'PASS'):
                bad = copy.deepcopy(good); bad[i]['status'] = status; self.refuses(bad)
            bad = list(good); bad[i] = None; self.refuses(bad)

    def test_each_metric_domain_bound_and_same_clock_nesting(self):
        for index in (0, 116):
            for metric in METRICS:
                invalid = (-1, 2**64, True, 1.0, '1', None)
                if metric != 'child_cpu_us': invalid += (0,)
                for value in invalid:
                    bad = fixture(); bad[index][metric] = value
                    with self.subTest(index=index, metric=metric, value=value): self.refuses(bad)
                valid = fixture()
                value = 30_000_000_000 if metric == 'process_wall_ns' else 2**64-1
                valid[index][metric] = value
                if metric.startswith('loop_'):
                    valid[index][metric.replace('loop_', 'whole_')] = value
                self.assertEqual(len(STATS.summarize(valid)['comparisons']), 72)
            bad = fixture(); bad[index]['process_wall_ns'] = 30_000_000_001; self.refuses(bad)
            for clock in ('wall', 'cpu'):
                bad = fixture(); bad[index]['loop_'+clock+'_ns'] = bad[index]['whole_'+clock+'_ns']+1
                self.refuses(bad)
        good = fixture()
        for row in good:
            for metric in METRICS: row[metric] = 1
        for row in STATS.summarize(good)['comparisons']:
            self.assertEqual(row['geometric_ratio'], 1)
        # Same-clock nesting is enforced; no CPU<=wall or resolution threshold.
        good = fixture()
        for row in good:
            row['whole_cpu_ns'] = 2*row['whole_wall_ns']; row['loop_cpu_ns'] = 2*row['loop_wall_ns']
        self.assertEqual(len(STATS.summarize(good)['comparisons']), 72)

    def test_every_measured_zero_cpu_endpoint_only_unresolves_its_comparisons(self):
        good = fixture(); expected = indexed(STATS.summarize(good))
        for i, record in enumerate(good):
            if record['phase'] != 'measured': continue
            mode = record['mode']; block = record['block']
            affected = {('sdk_vs_native', m, 'native', 'child_cpu_us')
                        for m in (MODES[1:] if mode == 'native' else (mode,))}
            if mode in MODES[1:5]:
                affected.add(('old_sdk_vs_batch_sdk', mode, mode+'-batch8', 'child_cpu_us'))
            elif mode in MODES[5:]:
                affected.add(('old_sdk_vs_batch_sdk', mode[:-7], mode, 'child_cpu_us'))
            bad = copy.deepcopy(good); bad[i]['child_cpu_us'] = 0
            result = indexed(STATS.summarize(bad))
            self.assertEqual({key for key, row in result.items() if row['status'] == 'UNRESOLVED_ZERO_CPU'}, affected)
            for key, row in result.items():
                if key not in affected:
                    self.assertEqual(row, expected[key]); continue
                pairs = copy.deepcopy(expected[key]['paired_values'])
                pairs[block-1][0 if key[1] == mode else 1] = 0
                self.assertEqual(row['paired_values'], pairs)
                self.assertEqual(row['pairs'], 10)
                self.assertEqual(len(row['paired_values']), 10)
                for field in ('geometric_ratio', 'paired_ratios', 'mean_log_ratio', 'cost_increase_percent', 'cost_reduction_percent'):
                    self.assertNotIn(field, row)
        for row in good:
            if row['phase'] == 'measured': row['child_cpu_us'] = 0
        result = STATS.summarize(good)['comparisons']
        self.assertEqual(sum(row['status'] == 'UNRESOLVED_ZERO_CPU' for row in result), 12)
        self.assertEqual(sum(row['status'] == 'ESTIMATED' for row in result), 60)

    def test_warmups_validated_but_excluded_and_outlier_never_removed(self):
        good = fixture(); expected = STATS.summarize(good)
        for row in good:
            if row['phase'] == 'warmup':
                for metric in METRICS: row[metric] = 30_000_000_000
                row['child_cpu_us'] = 0
        self.assertEqual(STATS.summarize(good), expected)
        # Invalid warmup still refuses; exclusion is statistical, not validation.
        good[0]['roots'] = 1535; self.refuses(good)
        outlier = fixture()
        for row in outlier:
            if row['phase'] == 'measured' and row['mode'] == 'original-sdk-batch8' and row['block'] == 10:
                row['whole_wall_ns'] *= 2**30
        old = indexed(expected); new = indexed(STATS.summarize(outlier))
        affected = {('sdk_vs_native', 'original-sdk-batch8', 'native', 'whole_wall_ns'),
                    ('old_sdk_vs_batch_sdk', 'original-sdk', 'original-sdk-batch8', 'whole_wall_ns')}
        for key in new:
            if key not in affected:
                self.assertEqual(new[key], old[key]); continue
            factor = 8 if key[0] == 'sdk_vs_native' else 1/8  # One factor2^30 in ten pairs.
            self.assertAlmostEqual(new[key]['geometric_ratio'], old[key]['geometric_ratio']*factor, places=12)
            self.assertGreater(new[key]['sample_sd_log_ratio'], 0)
            self.assertEqual(len(new[key]['paired_ratios']), 10)
            self.assertEqual(len(new[key]['paired_values']), 10)
            self.assertEqual(new[key]['paired_values'][:9], old[key]['paired_values'][:9])


if __name__ == '__main__':
    unittest.main()
