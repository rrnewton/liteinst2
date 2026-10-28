#!/usr/bin/env python3
"""Fabricated protocol and arithmetic controls, not native execution evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import copy
from pathlib import Path
import subprocess
import unittest
from check_session_two import READY, check, check_exact, checksum
from exact_session import SCHEDULES, FIELDS, commands, measure, _reduce, encode, selection_error, work


def fixture(schedule='late-long', k=10, zero_worker=False):
    expected = commands(schedule, k)
    rows = [['READY', 'normal-two-exact-v1', str(k), '1']+READY,
        ['WORKER', '1', '1', '111'], ['WORKER', '2', '2', '222'],
        ['HISTORY', '1', '1', 'published', '7']]
    results, samples, completed = {1: [], 2: []}, [], {1: 0, 2: 0}
    for index, (_, id_, n, data) in enumerate(expected[:-1]):
        worker, ordinal = 1+index % 2, 1+index//2
        if zero_worker:
            admitted = worker == 2 and ordinal <= 10
            slot = ordinal-1
        else:
            admitted = k == 1000 or ordinal <= (5 if worker == 1 else 7)
            slot = index if k == 1000 or ordinal <= 5 else ordinal+4
        batch = (ordinal-1)//4+1
        ack = 'checkpoint' if ordinal % 4 == 0 else 'next'
        start, end = 1000+100*index, 1010+100*index
        value = sum(byte ^ 0x5a for byte in data) ^ 0x9e3779b97f4a7c15
        results[worker].append(['RESULT', str(id_), str(worker), str(worker), str(ordinal),
            str(n), str(n), str(checksum(data)), str(value), 'sampled' if admitted else 'closed',
            '7', str(slot+1) if admitted else '0', '1', '36', ack,
            str(start), str(end), '3', '3', str(batch)])
        if admitted:
            retained = slot < k
            samples.append(['SAMPLE', str(id_), str(worker), str(worker), '7', str(slot), str(start),
                str(completed[worker]), 'retained' if retained else 'dropped',
                str(slot+1) if retained else '0', str(slot), 'value', str(end)])
            completed[worker] += 1
    for worker in (2, 1): rows.extend(results[worker])
    admitted = sum(completed.values()); retained = min(k, admitted)
    rows += [['FLUSHED', str(expected[-1][1]), '24', '24', '6', '6', str(completed[1]), str(completed[2])],
        ['HISTORY', '2', '2', 'removed', '7'],
        ['REPORT', '7', str(admitted), str(retained), str(admitted-retained), '0', '0']]
    rows += list(reversed(samples))
    for worker in (1, 2):
        rows.append(['WORKER_DONE', str(worker), '6', '24', '24', '24', str(completed[worker]),
            str(24-completed[worker]), '1', '1'])
    rows += [['IO', '0'], ['DONE', 'EpochLimit', '1', '2', '49', '48', str(admitted),
        str(retained), str(admitted-retained), str(48-admitted), '12', '1', '0', '0', '2', '2']]
    return rows


def text(rows):
    return ''.join(','.join(row)+'\n' for row in rows)


class Controls(unittest.TestCase):
    def test_all_eight_cohorts_are_preassigned_and_complete(self):
        ids = []
        for schedule, population in zip(SCHEDULES, (528, 18672, 9600, 11112)):
            for k in (10, 1000):
                expected = commands(schedule, k)
                self.assertIsInstance(expected, tuple)
                self.assertEqual(len(expected), 49)
                self.assertEqual(sum(work(c[2])[0] for c in expected[:-1]), population)
                self.assertEqual(expected[-1][0], 'FLUSH')
                ids.extend(c[1] for c in expected)
        self.assertEqual(len(ids), 392); self.assertEqual(len(set(ids)), 392)

    def test_all_admitted_exact_protocol_matches_each_population(self):
        for schedule, population in zip(SCHEDULES, (528, 18672, 9600, 11112)):
            summary, rows = measure(text(fixture(schedule, 1000)), schedule, 1000, 1)
            self.assertEqual((summary['calls'], summary['retained']), (48, 48))
            self.assertEqual(rows[-1]['population_instructions'], population)
            self.assertEqual([r['error_numerator'] for r in rows], [0, 0, 0])
            self.assertLessEqual(len(encode(rows)), 8192)

    def test_dropped_and_closed_calls_remain_in_population(self):
        summary, rows = measure(text(fixture()), 'late-long', 10, 1)
        self.assertEqual((summary['admitted'], summary['retained'], summary['dropped'], summary['unsampled']), (12, 10, 2, 36))
        row = rows[-1]
        self.assertEqual((row['population_instructions'], row['retained_instructions'], row['dropped_instructions']), (11112, 110, 22))
        self.assertEqual((row['error_numerator'], row['error_denominator']), (-105840, 480))

    def test_unresolved_worker_and_both_arithmetic_error_signs(self):
        _, rows = measure(text(fixture('short', 10, True)), 'short', 10, 1)
        self.assertEqual((rows[0]['error_status'], rows[0]['error_numerator'], rows[0]['error_denominator']), ('unresolved', None, None))
        self.assertEqual(rows[-1]['error_numerator'], 0)
        self.assertIn(b',,,unresolved\n', encode(rows))
        self.assertEqual(selection_error(48, 9600, 10, 1200)['error_numerator'], -38400)
        self.assertEqual(selection_error(48, 9600, 10, 2800)['error_numerator'], 38400)
        with self.assertRaises(AssertionError): selection_error(24, 264, 0, 1)

    def test_profile_domain_scalar_and_return_refuse(self):
        rows = fixture()
        with self.assertRaises(AssertionError): check(text(rows), commands('late-long', 10), 10, 1, 'EpochLimit')
        for tag, field, value in [('READY', 1, 'normal-two-session-v1'), ('RESULT', 8, '1'), ('RESULT', 13, '34'), ('RESULT', 5, '0')]:
            bad = copy.deepcopy(rows); next(r for r in bad if r[0] == tag)[field] = value
            with self.assertRaises(AssertionError): measure(text(bad), 'late-long', 10, 1)
        for n in (0, 2, 65):
            expected = list(commands('late-long', 10)); expected[0] = ('CALL', expected[0][1], n, b'x'*n)
            with self.assertRaises(AssertionError): check_exact(text(rows), expected, 10, 1, 'EpochLimit')

    def test_reducer_joins_ids_inputs_and_all_partitions(self):
        summary, joined = check_exact(text(fixture('alternating')), commands('alternating', 10), 10, 1, 'EpochLimit')
        for bad in (joined[:-1], (joined[0],)*48):
            with self.assertRaises(AssertionError): _reduce(summary, bad, 'alternating', 10)
        bad = list(joined); bad[0] = bad[0]._replace(bound=bad[1].bound, data=bad[1].data)
        with self.assertRaises(AssertionError): _reduce(summary, bad, 'alternating', 10)
        bad = list(joined); index = next(i for i, r in enumerate(bad) if r.disposition == 'dropped')
        bad[index] = bad[index]._replace(disposition='unsampled')
        with self.assertRaises(AssertionError): _reduce(summary, bad, 'alternating', 10)
        bad_summary = copy.deepcopy(summary); bad_summary['dropped'] -= 1
        with self.assertRaises(AssertionError): _reduce(bad_summary, joined, 'alternating', 10)

    def test_common_causality_and_local_order_still_refuse(self):
        rows = fixture()
        bad = copy.deepcopy(rows); report = next(r for r in bad if r[0] == 'REPORT'); bad.remove(report)
        bad.insert(4, report)
        with self.assertRaises(AssertionError): measure(text(bad), 'late-long', 10, 1)
        bad = copy.deepcopy(rows)
        results = [r for r in bad if r[0] == 'RESULT' and r[2] == '1'][:2]
        samples = [next(r for r in bad if r[0] == 'SAMPLE' and r[1] == result[1]) for result in results]
        results[0][11], results[1][11] = results[1][11], results[0][11]
        for field in (5, 10): samples[0][field], samples[1][field] = samples[1][field], samples[0][field]
        with self.assertRaises(AssertionError): measure(text(bad), 'late-long', 10, 1)
        bad = copy.deepcopy(rows); samples = [r for r in bad if r[0] == 'SAMPLE' and r[2] == '1'][:2]
        samples[0][9], samples[1][9] = samples[1][9], samples[0][9]
        with self.assertRaises(AssertionError): measure(text(bad), 'late-long', 10, 1)

    def test_summary_bounds_and_optimized_entrypoints(self):
        _, rows = measure(text(fixture()), 'late-long', 10, 1)
        self.assertEqual(len(FIELDS), 41)
        bad = copy.deepcopy(rows); bad[0]['schedule'] = 'x'*33
        with self.assertRaises(AssertionError): encode(bad)
        for name in ('exact_session.py', 'check_session_two.py', Path(__file__).name):
            p = subprocess.run([sys.executable, '-B', '-O', str(Path(__file__).with_name(name))], capture_output=True, timeout=5, check=False)
            self.assertEqual((p.returncode, p.stdout, p.stderr), (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
