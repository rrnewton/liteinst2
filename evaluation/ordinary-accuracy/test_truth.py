#!/usr/bin/env python3
"""Controls for seeded input authority and the complete original population."""
import csv
import hashlib
import io
from pathlib import Path
import re
import unittest

import truth


MASTER = '16b3b34b02c2f1054381195ee3d0767b493b427ad041bbfd8924e630d0f369b1'


class TruthTests(unittest.TestCase):
    def test_literal_body_matches_the_entire_assembly_fixture(self):
        assembly = (Path(__file__).resolve().parents[2] /
                    'tools/rapid-profiler/exact-work/exact_work.S').read_text()
        raw = bytes(int(byte, 16) for line in assembly.splitlines()
                    if '.byte ' in line
                    for byte in re.findall(r'0x([0-9a-f]{2})', line.split('/*')[0]))
        self.assertEqual(raw, truth.BODY)
        self.assertEqual(len(raw), 37)
        self.assertEqual(raw[-1], 0xc3)

    def test_hand_results_include_one_real_return_for_short_and_long_bodies(self):
        self.assertEqual(truth.original(b'Z'), dict(length=1, value=0x9e3779b97f4a7c15,
            instructions=11, conditional_branches=1, taken_branches=0,
            input_bytes=1, return_bytes=8))
        self.assertEqual(truth.original(bytes(64)), dict(length=64,
            value=0x9e3779b97f4a6a95, instructions=389,
            conditional_branches=64, taken_branches=63, input_bytes=64, return_bytes=8))
        self.assertEqual(truth.original(b'Z\x00')['value'], 0x9e3779b97f4a7c4f)
        for value in (b'', bytes(65), bytearray(b'Z'), 'Z', None):
            with self.assertRaises(ValueError):
                truth.original(value)

    def test_every_length_preserves_original_work_and_input_order(self):
        # An independent loop walk: visit prologue 0,2; body 6..21; epilogue
        # 23,33,36. This consumes no predicted counts or profiler records.
        for length in range(1, 65):
            payload = bytes(range(length))
            heads = [0, 2]
            branch = []
            accumulated = 0
            index = 0
            while True:
                heads.extend([6, 9, 12, 15, 18, 21])
                accumulated += payload[index] ^ 0x5a
                index += 1
                branch.append(index < length)
                if not branch[-1]:
                    break
            heads.extend([23, 33, 36])
            row = truth.original(payload)
            self.assertEqual(row['instructions'], len(heads))
            self.assertEqual(row['conditional_branches'], len(branch))
            self.assertEqual(row['taken_branches'], sum(branch))
            self.assertEqual(row['value'], accumulated ^ 0x9e3779b97f4a7c15)

    def test_all_100_trials_in_each_phase_have_distinct_reproducible_seeds(self):
        seeds = [truth.trial_seed(MASTER, phase, trial)
                 for phase in truth.PHASES for trial in range(1, 101)]
        self.assertEqual(len(seeds), 300)
        self.assertEqual(len(set(seeds)), 300)
        self.assertEqual(seeds, [truth.trial_seed(MASTER, phase, trial)
            for phase in truth.PHASES for trial in range(1, 101)])
        # Domain separation changes streams as well as their metadata labels.
        words = [truth.Stream(seed, b'payload\0short').word() for seed in seeds]
        self.assertEqual(len(set(words)), 300)
        self.assertNotEqual(truth.Stream(seeds[0], b'payload\0short').word(),
                            truth.Stream(seeds[0], b'length\0short').word())

    def test_seed_and_trial_domains_refuse_noncanonical_or_missing_cases(self):
        for master in ('', MASTER.upper(), MASTER[:-1], 'g' * 64, bytes(32), None):
            with self.assertRaises(ValueError):
                truth.trial_seed(master, 'comparison', 1)
        for trial in (0, 101, -1, 1.0, True):
            with self.assertRaises(ValueError):
                truth.trial_seed(MASTER, 'comparison', trial)
        with self.assertRaises(ValueError):
            truth.trial_seed(MASTER, 'calibration_retry', 1)
        with self.assertRaises(ValueError):
            truth.population(MASTER, 'straight_line')

    def test_uniform_stream_rejects_tail_values_and_never_relabels_them(self):
        stream = truth.Stream(MASTER, b'test')
        values = iter([(1 << 64) - 1, 4])
        stream.word = lambda: next(values)
        self.assertEqual(stream.below(3), 1)  # MAX is rejected, 4 is accepted.
        stream.word = lambda: (1 << 64) - 1
        with self.assertRaises(ValueError):
            stream.below(3)
        for bound in (0, -1, True, 1.0, (1 << 64) + 1):
            with self.assertRaises(ValueError):
                truth.Stream(MASTER, b'test').below(bound)

    def test_every_workload_retains_all_input_rows_beyond_k1000(self):
        for workload in truth.WORKLOADS:
            rows = truth.population(MASTER, workload)
            self.assertEqual([r['record'] for r in rows], list(range(1, 2049)))
            self.assertTrue(all(1 <= len(r['payload']) <= 64 for r in rows))
            self.assertTrue(all(all(b in truth.ALPHABET for b in r['payload']) for r in rows))
            lengths = [r['length'] for r in rows]
            if workload == 'short':
                self.assertEqual(lengths, [1] * 2048)
            elif workload == 'long':
                self.assertEqual(lengths, [64] * 2048)
            elif workload == 'alternating':
                self.assertEqual(lengths, [1, 64] * 1024)
            elif workload == 'late_expensive':
                self.assertEqual(lengths, [1] * 1024 + [64] * 1024)
                self.assertEqual(sum(r['instructions'] for r in rows[:1000]), 11000)
                self.assertEqual(sum(r['instructions'] for r in rows[1024:]), 398336)
            elif workload == 'blocks':
                self.assertEqual(lengths, ([1] * 64 + [64] * 64) * 16)
            else:
                self.assertEqual(set(lengths), set(range(1, 65)))

    def test_full_policy_matrix_has_all_24_cells_and_original_cadences(self):
        policies = truth.policies(MASTER)
        self.assertEqual(len(policies), 24)
        self.assertEqual([(p['k'], p['period_ms'], p['phase']) for p in policies],
            [(k, ms, phase) for k in (1, 10, 100, 1000)
             for ms in (1, 10, 100) for phase in ('random', 'locked')])
        for p in policies:
            self.assertTrue(0 <= p['delay_ns'] < p['period_ms'] * 1_000_000)
            if p['phase'] == 'locked':
                self.assertEqual(p['delay_ns'], 0)
        for period in (1, 10, 100):
            self.assertEqual(len({p['delay_ns'] for p in policies
                                  if p['period_ms'] == period and p['phase'] == 'random'}), 1)

    def test_manifest_binds_same_bytes_table_results_and_complete_truth(self):
        files, manifest = truth.artifacts(MASTER, 'comparison', 17, 'late_expensive')
        self.assertEqual((files, manifest),
                         truth.artifacts(MASTER, 'comparison', 17, 'late_expensive'))
        self.assertEqual(manifest['body']['hex'], truth.BODY.hex())
        self.assertEqual(manifest['body']['sha256'], hashlib.sha256(truth.BODY).hexdigest())
        self.assertEqual(manifest['function'], 41)
        inputs = files['input.csv'].splitlines()
        table = files['selected.txt'].decode().splitlines()
        self.assertEqual(table[:2], ['LI2SELECTED 1 1 2048', 'functions 41'])
        self.assertEqual(table[-1], 'END')
        rows = list(csv.DictReader(io.StringIO(files['truth.csv'].decode())))
        self.assertEqual((len(inputs), len(rows), len(table)), (2048, 2048, 2051))
        for i, (payload, row, expected) in enumerate(zip(inputs, rows, table[2:-1]), 1):
            words = expected.split(' ')
            self.assertEqual(words[:3], ['record', str(i), payload.hex()])
            self.assertEqual(row['record'], str(i))
            self.assertEqual(int(words[3]), int(row['value']))
            self.assertEqual(int(row['value']), truth.original(payload)['value'])
        self.assertEqual(manifest['totals']['instructions'], 409600)
        self.assertEqual(manifest['totals']['return_bytes'], 16384)
        for name, raw in files.items():
            self.assertEqual(manifest['files'][name], truth.pin(raw))


if __name__ == '__main__':
    unittest.main()
