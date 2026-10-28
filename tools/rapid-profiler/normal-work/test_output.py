#!/usr/bin/env python3
"""Control the real output parser; synthetic rows supply no native credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).with_name('check_output.py')
spec = importlib.util.spec_from_file_location('normal_output', p)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def valid():
    lines = [check.HEADER]
    for i, (name, bound, value) in enumerate(check.CASES):
        owner = 'sampled' if i < 4 else 'closed' if i < 6 else 'removed'
        fields = [i+1, name, bound, value, owner, 7 if i < 2 else 11,
                  str(i % 2) if i < 4 else '', 1 if i < 2 else 3 if i < 6 else 4,
                  40 if i in (2, 7) else 34, (30, 48)[i % 2],
                  'checkpoint' if i == 7 else 'next-entry', 100+i*20, 110+i*20, 9, 9]
        lines.append(','.join(map(str, fields)))
    return ('\n'.join(lines+[check.TERMINAL])+'\n').encode()


def change(data, row, key, value):
    lines = data.decode().splitlines()
    words = lines[row+1].split(',')
    words[check.HEADER.split(',').index(key)] = value
    lines[row+1] = ','.join(words)
    return ('\n'.join(lines)+'\n').encode()


def native():
    lines = [check.STATE_HEADER]
    population = [('stable', seed, i) for seed in check.SEEDS for i in range(8)]
    population.append(('crossed-owner', check.SEEDS[0], 7))
    comparisons = reads_total = 0
    for mode, seed, i in population:
        name, bound, value = check.CASES[i]
        reads = value + int(value < bound)
        visits = 8 + 3*reads  # Synthetic parser input, never native evidence.
        count = 24 + 2*visits
        comparisons += count; reads_total += 2*reads
        fields = [mode, seed, name, bound, 'PASS', 2, count, visits, visits,
                  count, count+50, value, value, 2*value, reads, reads, reads, reads,
                  40 if i in (2, 7) else 34, 40 if i in (2, 7) else 34,
                  4, 4, 2, 2, int(mode == 'crossed-owner')]
        lines.append(','.join(map(str, fields)))
    terminal = (f'native-normal:selection=freebsd-strnlen-14.1-v1:stable-required=16:stable-pairs=16:'
                f'crossed-owner-pairs=1:pairs=17:children=34:comparisons={comparisons}:'
                f'input-reads={reads_total}:input-bytes={reads_total}:coverage-seeds=2:'
                f'target-calls=68:target-returns=68:real-outer-ret=34:helper-joins=1:complete\n')
    return ('\n'.join(lines)+'\n').encode(), terminal.encode()


class Output(unittest.TestCase):
    def refused(self, data):
        with self.assertRaises((AssertionError, ValueError, UnicodeError, TypeError)):
            check.functional(data)

    def test_exact_population_and_noninitial_generations(self):
        rows, table = check.functional(valid())
        self.assertEqual(len(rows), 8)
        self.assertEqual((rows[0]['generation'], rows[2]['generation']), (7, 11))
        self.assertEqual(len(table.splitlines()), 9)

    def test_missing_extra_reordered_and_truncated_rows_refuse(self):
        data = valid(); lines = data.splitlines(keepends=True)
        for altered in (b''.join(lines[:3]+lines[4:]), b''.join(lines[:3]+lines[2:]),
                        b''.join(lines[:1]+[lines[2],lines[1]]+lines[3:]),
                        data[:-1], data+b'\n', data.replace(b'\n', b'\r\n')):
            self.refused(altered)
        for at, byte in enumerate(data[:-1]):
            if byte == 10:
                for separator in (0, 11, 12, 13, 28, 29, 30, 127):
                    self.refused(data[:at]+bytes([separator])+data[at+1:])

    def test_every_call_identity_value_and_acknowledgement_is_required(self):
        for i in range(8):
            for key, value in [('ordinal','0'), ('case','unknown'), ('bound','65'),
                               ('value','65'), ('caller_continuation','31'),
                               ('ack','observed-physical-ret'), ('history_prefix','0')]:
                self.refused(change(valid(), i, key, value))
            self.refused(change(valid(), i, 'ack', 'next-entry' if i == 7 else 'checkpoint'))

    def test_owner_generation_and_invocation_cannot_be_reclassified(self):
        for i in range(8):
            for key, value in [('owner','cancelled'), ('generation','0'), ('invocation','999')]:
                self.refused(change(valid(), i, key, value))
        self.refused(change(valid(), 1, 'generation', '8'))
        self.refused(change(valid(), 4, 'owner', 'removed'))
        self.refused(change(valid(), 6, 'owner', 'closed'))

    def test_complete_return_coverage_and_raw_clock_consistency(self):
        for i in range(8):
            for key, value in [('ret_offset','80'), ('end_ticks','0'), ('end_aux','10')]:
                self.refused(change(valid(), i, key, value))
        for i in range(8):
            self.refused(change(valid(), i, 'ret_offset', '34' if i in (2, 7) else '40'))

    def test_noncanonical_numbers_header_and_completion_claims_refuse(self):
        for word in ('01', '+1', '-1', '1.0', ' 1', str(2**64)):
            self.refused(change(valid(), 0, 'ordinal', word))
        for before, after in [(b'worker_joins=1',b'worker_joins=0'),
                              (b'checkpoint_acknowledgements=1',b'checkpoint_acknowledgements=8'),
                              (b'ordinal,case',b'ordinal,case,extra')]:
            self.refused(valid().replace(before,after))

    def test_native_exact_population_and_cross_consumer_join(self):
        data, stdout = native()
        rows, totals = check.state(data, stdout, b'', 41)
        self.assertEqual(len(rows), 17)
        self.assertEqual(totals['input_reads'], 696)
        work, _ = check.functional(valid())
        check.join(rows, work)
        work[0]['ret_offset'] = 35
        with self.assertRaises(AssertionError):
            check.join(rows, work)

    def test_native_refuses_missing_comparisons_transfers_bounds_and_census(self):
        data, stdout = native()
        def refused(b, out=stdout, err=b''):
            with self.assertRaises((AssertionError, ValueError, TypeError)):
                check.state(b, out, err, 41)
        for row in range(17):
            for key, value in [('mode','other'), ('seed','0'), ('case','other'), ('bound','65'),
                               ('status','SKIP'), ('children','1'), ('comparisons','0'),
                               ('visits0','0'), ('visits1','0'), ('original_steps','20001'),
                               ('candidate_steps','20001'), ('value0','65'), ('value1','65'),
                               ('original_steps','1'), ('candidate_steps','1'),
                               ('outer_value','999'), ('input_reads0','65'), ('input_reads1','65'),
                               ('input_bytes0','65'), ('input_bytes1','65'), ('ret_offset0','0'),
                               ('ret_offset1','0'), ('target_calls','3'), ('target_returns','3'),
                               ('outer_returns','1'), ('normal_reaps','1'), ('helper_joins','2')]:
                lines = data.decode().splitlines(); words = lines[row+1].split(',')
                words[check.STATE_HEADER.split(',').index(key)] = value
                lines[row+1] = ','.join(words)
                refused(('\n'.join(lines)+'\n').encode())
        lines = data.splitlines(keepends=True)
        for bad in (b''.join(lines[:-1]), data+lines[-1], data[:-1], data.replace(b'\n',b'\v'),
                    b''.join(lines[:1]+[lines[2],lines[1]]+lines[3:])):
            refused(bad)
        refused(data, stdout.replace(b'coverage-seeds=2', b'coverage-seeds=1'))
        refused(data, stdout.replace(b'helper-joins=1', b'helper-joins=0'))
        refused(data, err=b'warning\n')
        for offset in (41, 79, 80):
            lines = data.decode().splitlines()
            # Preserve the complete two-path partition and cross-seed equality;
            # only the authenticated extent can reject this coordinated change.
            for i in range(1, len(lines)):
                words = lines[i].split(',')
                for key in ('ret_offset0', 'ret_offset1'):
                    at = check.STATE_HEADER.split(',').index(key)
                    if words[at] == '34':
                        words[at] = str(offset)
                lines[i] = ','.join(words)
            refused(('\n'.join(lines)+'\n').encode())
        for length in (True, 4, 81):
            with self.assertRaises(AssertionError):
                check.state(data, stdout, b'', length)

    def test_actual_lifecycle_markers_cannot_claim_ack_or_missing_join(self):
        for owner in ('sampled', 'function-closed'):
            data = check.DROP.format(owner).encode()
            check.lifecycle(data, owner)
            for bad in (data[:-1], data+b'\n', data.replace(b'checkpoints=0',b'checkpoints=1'),
                        data.replace(b'pending_after_tls_exit=1',b'pending_after_tls_exit=0'),
                        data.replace(b'worker_joins=1',b'worker_joins=0')):
                with self.assertRaises(AssertionError):
                    check.lifecycle(bad, owner)


if __name__ == '__main__':
    unittest.main()
