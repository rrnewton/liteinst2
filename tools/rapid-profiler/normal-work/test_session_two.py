#!/usr/bin/env python3
"""Fabricated protocol mutations through the actual checker; no native proof."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import copy
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch
from check_session_two import READY, check, checksum
from session_two_driver import cohort, refusal
from session_driver import reap


def fixture():
    # Seven requests per worker. Worker1's last two are FunctionClosed; worker2
    # contributes two admitted dropped completions. Distinct slot/rank/arrival
    # orders are deliberate; copied protocol is not a claimed concurrent trace.
    expected = [('CALL', 100+i, 3, b'a\0b') for i in range(14)]+[('FLUSH', 9)]
    rows = [['READY', 'normal-two-session-v1', '10', '1']+READY,
        ['WORKER', '1', '1', '111'], ['WORKER', '2', '2', '222'],
        ['HISTORY', '1', '1', 'published', '7']]
    samples, by_worker = [], {1: [], 2: []}
    for i in range(14):
        worker, ordinal = 1+i%2, i//2+1
        admitted = worker == 2 or ordinal <= 5
        slot = (ordinal-1)*2+(worker-1) if ordinal <= 5 else ordinal+4
        batch = 1 if ordinal <= 4 else 2
        ack = 'checkpoint' if ordinal in (4, 7) else 'next'
        start = 1000+100*i
        row = ['RESULT', str(100+i), str(worker), str(worker), str(ordinal), '3', '3',
            str(checksum(b'a\0b')), '1', 'sampled' if admitted else 'closed', '7',
            str(slot+1) if admitted else '0', '1', '34', ack, str(start), str(start+10), '3', '3', str(batch)]
        by_worker[worker].append(row)
        if admitted:
            kept = slot < 10
            rank = 2 if slot == 0 else (1 if slot == 1 else slot+1)
            samples.append(['SAMPLE', str(100+i), str(worker), str(worker), '7', str(slot), str(start),
                str(ordinal-1), 'retained' if kept else 'dropped', str(rank) if kept else '0',
                str(slot), 'value', str(start+10)])
    # Worker2 arrives first within each batch. No global invocation-order assertion.
    for first, last in ((0, 4), (4, 7)):
        for worker in (2, 1): rows.extend(by_worker[worker][first:last])
    rows += [['FLUSHED', '9', '7', '7', '2', '2', '5', '7'],
        ['HISTORY', '2', '2', 'removed', '7'], ['REPORT', '7', '12', '10', '2', '0', '0']]
    rows += list(reversed(samples))
    rows += [['WORKER_DONE', '1', '2', '7', '7', '7', '5', '2', '1', '1'],
        ['WORKER_DONE', '2', '2', '7', '7', '7', '7', '0', '1', '1'],
        ['IO', '0'], ['DONE', 'EpochLimit', '1', '2', '15', '14', '12', '10', '2', '2', '4', '1', '0', '0', '2', '2']]
    return expected, rows


def text(rows):
    return ''.join(','.join(row)+'\n' for row in rows)


class Controls(unittest.TestCase):
    def setUp(self):
        self.expected, self.rows = fixture()
    def valid(self, rows=None):
        return check(text(self.rows if rows is None else rows), self.expected, 10, 1, 'EpochLimit')
    def refuse(self, rows):
        with self.assertRaises((AssertionError, IndexError, KeyError, ValueError)):
            self.valid(rows)
    def changed(self, tag, field, value, occurrence=0):
        rows = copy.deepcopy(self.rows)
        row = [r for r in rows if r[0] == tag][occurrence]
        row[field] = value
        return rows
    def test_valid_independent_worker_slot_and_retention_orders(self):
        got = self.valid()
        self.assertEqual((got['calls'], got['admitted'], got['retained'], got['dropped'], got['unsampled']), (14, 12, 10, 2, 2))
        self.assertEqual([w['completed'] for w in got['workers']], [5, 7])
        rows = copy.deepcopy(self.rows)
        indices = [i for i, r in enumerate(rows) if r[0] == 'RESULT' and int(r[4]) >= 5]
        # Worker1's closed results may arrive before worker2's sampled results.
        tail = sorted((rows[i] for i in indices), key=lambda r: int(r[2]))
        for i, row in zip(indices, tail): rows[i] = row
        self.valid(rows)
    def test_every_declared_field_is_authenticated(self):
        for index, row in enumerate(self.rows):
            for field, value in enumerate(row):
                rows = copy.deepcopy(self.rows)
                # Invalid lexical form for numbers, impossible closed tag for words.
                rows[index][field] = '0'+value if value.isdecimal() else value+'!'
                with self.subTest(row=index, field=field): self.refuse(rows)
    def test_missing_duplicate_and_worker_order_refuse(self):
        for index in range(len(self.rows)):
            with self.subTest(index=index):
                self.refuse(self.rows[:index]+self.rows[index+1:])
                self.refuse(self.rows[:index]+[self.rows[index]]+self.rows[index:])
        rows = copy.deepcopy(self.rows); rows[1], rows[2] = rows[2], rows[1]; self.refuse(rows)
        self.refuse(self.changed('WORKER', 3, '111', 1))
        self.refuse(self.changed('RESULT', 2, '1'))
        self.refuse(self.changed('RESULT', 3, '1'))
    def test_local_ordinals_batch_ack_and_sequence_cannot_shift(self):
        for field, value in [(4, '2'), (14, 'checkpoint'), (19, '2')]:
            self.refuse(self.changed('RESULT', field, value))
        self.refuse(self.changed('SAMPLE', 7, '19'))
        rows = copy.deepcopy(self.rows)
        selected = [i for i, r in enumerate(rows) if r[0] == 'RESULT' and r[2] == '2']
        rows[selected[0]], rows[selected[1]] = rows[selected[1]], rows[selected[0]]
        self.refuse(rows)
    def test_global_slot_rank_terminal_and_dropped_payload_refuse(self):
        self.refuse(self.changed('RESULT', 11, '1'))  # duplicate another worker's slot
        for field, value in [(5, '4096'), (8, 'retained'), (9, '1'), (10, '0'), (12, '0')]:
            self.refuse(self.changed('SAMPLE', field, value))
        self.refuse(self.changed('SAMPLE', 9, '1', -1))  # slot0 would duplicate slot1's retained rank
        # Coherent relabels preserve the global slot/rank/count sets and every
        # payload endpoint. Only the worker-local causal constraints reject them.
        rows = copy.deepcopy(self.rows)
        earlier = next(r for r in rows if r[0] == 'RESULT' and r[1] == '108')
        later = next(r for r in rows if r[0] == 'RESULT' and r[1] == '110')
        earlier[9], earlier[11] = 'closed', '0'
        later[9], later[11] = 'sampled', '9'
        sample = next(r for r in rows if r[0] == 'SAMPLE' and r[1] == '108')
        sample[1], sample[6], sample[12] = '110', '2000', '2010'
        self.refuse(rows)
        rows = copy.deepcopy(self.rows)
        for id_, inv1, slot in [('100', '3', '2'), ('102', '1', '0')]:
            result = next(r for r in rows if r[0] == 'RESULT' and r[1] == id_)
            sample = next(r for r in rows if r[0] == 'SAMPLE' and r[1] == id_)
            result[11], sample[5], sample[10] = inv1, slot, slot
        self.refuse(rows)
        rows = copy.deepcopy(self.rows)
        first = next(r for r in rows if r[0] == 'SAMPLE' and r[1] == '100')
        second = next(r for r in rows if r[0] == 'SAMPLE' and r[1] == '102')
        first[9], second[9] = second[9], first[9]
        self.refuse(rows)
        rows = copy.deepcopy(self.rows)
        first = next(r for r in rows if r[0] == 'SAMPLE' and r[1] == '109')
        second = next(r for r in rows if r[0] == 'SAMPLE' and r[1] == '111')
        first[8:10], second[8:10] = second[8:10], first[8:10]
        self.refuse(rows)
    def test_complete_retained_dropped_report_budget_refuse(self):
        for field, value in [(2, '11'), (3, '9'), (4, '1'), (5, '1'), (6, '1')]:
            self.refuse(self.changed('REPORT', field, value))
        # A coherent relabel cannot hide a missing admitted Report row.
        rows = self.changed('RESULT', 9, 'closed')
        row = next(r for r in rows if r[0] == 'RESULT'); row[11] = '0'
        self.refuse(rows)
    def test_input_scalar_and_exact_ret_path_refuse(self):
        for field, value in [(1, '999'), (5, '2'), (6, '4'), (7, '0'), (8, '2'), (13, '40')]:
            self.refuse(self.changed('RESULT', field, value))
    def test_empty_maximum_id_nonzero_and_page_sized_inputs(self):
        for bound, data, value, ret in [(0, b'', 0, 34), (1, b'\xff', 1, 40),
                (4096, b'x'*4095+b'\0', 4095, 34), (4096, b'x'*4096, 4096, 40)]:
            expected, rows = fixture()
            id_ = (1 << 64)-1
            expected[0] = ('CALL', id_, bound, data)
            r = next(r for r in rows if r[0] == 'RESULT' and r[1] == '100')
            r[1], r[5], r[6], r[7], r[8], r[13] = map(str, (id_, bound, len(data), checksum(data), value, ret))
            sample = next(r for r in rows if r[0] == 'SAMPLE' and r[1] == '100')
            sample[1] = str(id_)
            self.assertEqual(check(text(rows), expected, 10, 1, 'EpochLimit')['calls'], 14)

    def test_history_owner_prefix_and_monotonic_local_join_refuse(self):
        for tag, field, value in [('HISTORY', 1, '2'), ('HISTORY', 2, '2'), ('HISTORY', 4, '8'),
                ('RESULT', 10, '8'), ('RESULT', 12, '0'), ('RESULT', 12, '3')]:
            self.refuse(self.changed(tag, field, value))
        self.refuse(self.changed('HISTORY', 4, '8', 1))
        # Final membership cannot repair an impossible earlier wire emission.
        for tag, before in [('RESULT', 'HISTORY'), ('REPORT', 'HISTORY'), ('SAMPLE', 'REPORT')]:
            rows = copy.deepcopy(self.rows)
            item = next(r for r in rows if r[0] == tag); rows.remove(item)
            rows.insert(next(i for i, r in enumerate(rows) if r[0] == before), item)
            with self.subTest(tag=tag, before=before): self.refuse(rows)
        # Publication alone cannot authorize retirement of a still-current epoch.
        rows = copy.deepcopy(self.rows)
        report = next(r for r in rows if r[0] == 'REPORT'); rows.remove(report)
        rows.insert(next(i for i, r in enumerate(rows) if r[0] == 'RESULT'), report)
        self.refuse(rows)
        # Closing HISTORY plus REPORT may precede exported RESULTs; this is not
        # a blanket RESULT-before-REPORT rule. SAMPLE still waits for its RESULT.
        removal = next(r for r in rows if r[0] == 'HISTORY' and r[3] == 'removed')
        rows.remove(removal)
        rows.insert(next(i for i, r in enumerate(rows) if r[0] == 'REPORT'), removal)
        self.valid(rows)
        sample = next(r for r in rows if r[0] == 'SAMPLE'); rows.remove(sample)
        rows.insert(next(i for i, r in enumerate(rows) if r[0] == 'RESULT'), sample)
        self.refuse(rows)
        rows = copy.deepcopy(self.rows)
        removal = next(r for r in rows if r[0] == 'HISTORY' and r[3] == 'removed')
        removal[1], removal[2], removal[4] = '3', '3', '8'
        rows.insert(next(i for i, r in enumerate(rows) if r[0] == 'RESULT'), ['HISTORY', '2', '2', 'published', '8'])
        report = next(r for r in rows if r[0] == 'REPORT'); rows.remove(report)
        rows.insert(next(i for i, r in enumerate(rows) if r[0] == 'RESULT'), report)
        empty = ['REPORT', '8', '0', '0', '0', '0', '0']
        rows.insert(rows.index(removal)+1, empty)
        rows[0][3] = '2'
        rows[-1][2:4] = ['2', '3']
        self.assertEqual(check(text(rows), self.expected, 10, 2, 'EpochLimit')['arms'], 2)
        rows.remove(empty); rows.insert(rows.index(removal), empty)
        with self.assertRaises(AssertionError): check(text(rows), self.expected, 10, 2, 'EpochLimit')
    def test_barrier_prefix_requires_both_workers_before_next_acceptance(self):
        for field in range(2, 8): self.refuse(self.changed('FLUSHED', field, '0'))
        rows = copy.deepcopy(self.rows)
        flush = next(r for r in rows if r[0] == 'FLUSHED'); rows.remove(flush); rows.insert(5, flush)
        self.refuse(rows)
    def test_endpoint_unavailability_precedence_and_no_global_clock_order(self):
        rows = copy.deepcopy(self.rows)
        r = next(r for r in rows if r[0] == 'RESULT')
        r[16], r[18] = '1', '4'  # both clock conditions fail; AUX mismatch has precedence.
        sample = next(s for s in rows if s[0] == 'SAMPLE' and s[1] == r[1])
        sample[11:13] = ['unavailable', '1']
        self.valid(rows)
        sample[12] = '2'; self.refuse(rows)
        sample[12], r[18] = '2', '3'; self.valid(rows)
        r[18] = str(1 << 32); self.refuse(rows)
    def test_exact_lifecycle_tail_and_counts_refuse(self):
        for field in range(2, 10): self.refuse(self.changed('WORKER_DONE', field, '0'))
        for field in range(2, 16):
            rows = self.changed('DONE', field, '1' if self.rows[-1][field] == '0' else '0')
            self.refuse(rows)
        self.refuse(self.rows[:-2]+[self.rows[-1], self.rows[-2]])
    def test_framing_bounds_and_numeric_canonicality_refuse(self):
        good = text(self.rows)
        for bad in [good[:-1], good+'\n', good.replace('\n', '\r\n'), good.replace('\n', '\v', 1),
                good.replace('\n', '\f', 1), good.replace('111', '+111', 1), good.replace('111', str(1 << 64), 1),
                good.replace('RESULT,', 'RESULT,"', 1), good.replace('IO,0', 'IO,'+'1'*350)]:
            with self.assertRaises((AssertionError, IndexError, KeyError, ValueError)):
                check(bad, self.expected, 10, 1, 'EpochLimit')
        rows = copy.deepcopy(self.rows); rows[1][3] = str((1 << 31)); self.refuse(rows)
    def test_refusal_exit_status_and_positive_cohort_denominators(self):
        for mode, message in [('duplicate', b'duplicate request ID'), ('eof', b'overlong or unterminated request')]:
            self.assertTrue(refusal(1, b'READY\n', b'normal-session-two FAILED: '+message, mode)['expected_refusal'])
            for code, out, err in [(0, b'', message), (101, b'', message), (1, b'DONE,', message), (1, b'', b'other')]:
                with self.assertRaises(AssertionError): refusal(code, out, err, mode)
        for mode, calls, flushes in [('full', 40, 5), ('stop', 64, 0), ('backpressure', 1024, 1)]:
            summary = dict(calls=calls, flushes=flushes, accepted=calls+flushes, detaches=2, joins=2,
                workers=[dict(worker=w, calls=calls//2, maximum_entry_prefix=513) for w in (1, 2)],
                arms=520, actions=521, stop_reason='Requested' if mode == 'stop' else 'EpochLimit', write_blocked_at_finalize=1)
            cohort(summary, mode)
            for key in ('calls', 'flushes', 'accepted', 'detaches', 'joins'):
                changed = copy.deepcopy(summary); changed[key] += 1
                with self.assertRaises(AssertionError): cohort(changed, mode)
            changed = copy.deepcopy(summary); changed['workers'][0]['calls'] -= 1
            with self.assertRaises(AssertionError): cohort(changed, mode)
        summary['write_blocked_at_finalize'] = 0
        with self.assertRaises(AssertionError): cohort(summary, 'backpressure')
    def test_absolute_reap_observation_and_optimization_refusals(self):
        child = Mock(); child.wait.return_value = 0
        with patch('session_driver.time.monotonic', side_effect=[9.0, 10.0]):
            with self.assertRaises(AssertionError): reap(child, 10.0)
        child.wait.assert_called_once_with(timeout=1.0)
        for name in ('check_session_two.py', 'session_two_driver.py', 'test_session_two.py'):
            run = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name(name))], capture_output=True, timeout=5)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, b'')
            self.assertIn(b'assertions required', run.stderr)


if __name__ == '__main__':
    unittest.main()
