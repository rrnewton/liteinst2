"""Supplied numeric records test projection rejection, not native execution."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'evaluation/inprocess'))
import page_tf_interval_samples as samples


def supplied_batch():
    result = dict(status='passed', cpu=2, qualification_verified=True, source_unchanged=True,
                  error=None, final_errors=[], samples=[], commands=[])
    for order, (n, pair, lane) in enumerate(samples.ORDER):
        elapsed = (n + 5) * 1000 + (500 if lane == 'gated' else 0) + pair * 10
        start = 1000 + order * 1000000
        name = samples.command_name(n, pair, lane)
        terminal = dict(accepted=True, profile=samples.PROFILE[lane], operations=n,
                        pid=1000 + order, cpu=2, output_bytes=8, output_sha256='1' * 64)
        captures = {key: dict(bytes=0, sha256='0' * 64) for key in samples.CAPTURES}
        captures['stdout'] = dict(bytes=8, sha256='1' * 64)
        row = dict(name=name, profile=samples.PROFILE[lane], control='normal', accepted=True,
                   protocol_complete=True, reaped=True, timed_out=False, error=None,
                   cleanup_errors=[], exit=0, pid=1000 + order,
                   bounds=[5, 512 << 20, 16 << 20, 15],
                   descriptors=[dict(name=k, fd=3 + i, closed=True)
                                for i, k in enumerate(samples.DESCRIPTORS)],
                   captures=captures, start_ns=start, candidate_go_ns=start + 1000,
                   candidate_done_ns=start + 1000 + elapsed, deadline_ns=start + 15 * 10**9,
                   duration_ns=1100 + elapsed,
                   interval_ns=elapsed, terminal_validation=terminal)
        result['commands'].append(row)
        result['samples'].append(dict(operations=n, pair=pair, lane=lane, order=order,
                                      accepted=True, interval_ns=elapsed, pid=1000 + order,
                                      terminal_sha256=samples.digest(terminal)))
    return result


class IntervalSampleProjectionTests(unittest.TestCase):
    def test_fixed_populations_and_failed_batch_never_gets_credit(self):
        receipt = supplied_batch()
        projected = samples.summarize(receipt)
        self.assertEqual(projected['accepted_subjects'], 20)
        self.assertTrue(projected['performance_credit'])
        self.assertEqual(projected['aggregates'], [
            dict(operations=1, lane='native', samples=5, min_ns=6000, median_ns=6020, max_ns=6040),
            dict(operations=1, lane='gated', samples=5, min_ns=6500, median_ns=6520, max_ns=6540),
            dict(operations=256, lane='native', samples=5, min_ns=261000, median_ns=261020, max_ns=261040),
            dict(operations=256, lane='gated', samples=5, min_ns=261500, median_ns=261520, max_ns=261540),
        ])
        receipt['status'] = 'failed'
        receipt['source_unchanged'] = False
        receipt['final_errors'] = ['supplied source-change failure']
        failed = samples.summarize(receipt)
        self.assertEqual(failed['accepted_subjects'], 20)
        self.assertFalse(failed['performance_credit'])
        self.assertIsNone(failed['aggregates'])
        empty = dict(receipt, commands=[], samples=[])
        self.assertEqual(samples.summarize(empty)['attempted_subjects'], 0)

    def test_malformed_or_discarded_sample_cannot_make_a_pass(self):
        base = supplied_batch()
        def shift_clock(receipt, index, delta):
            row = receipt['commands'][index]
            for key in ('start_ns', 'candidate_go_ns', 'candidate_done_ns', 'deadline_ns'):
                row[key] += delta
        def continue_after_rejection(receipt):
            receipt['status'] = 'failed'
            receipt['commands'][0]['accepted'] = False
            receipt['samples'][0]['accepted'] = False
        changes = [
            ('missing sample', lambda r: r['samples'].pop()),
            ('removed first sample', lambda r: r['samples'].pop(0)),
            ('duplicate command', lambda r: r['commands'].append(copy.deepcopy(r['commands'][0]))),
            ('missing command', lambda r: r['commands'].pop()),
            ('discarded child', lambda r: r['samples'][0].update(accepted=False)),
            ('bool count', lambda r: r['samples'][0].update(operations=True)),
            ('wrong lane', lambda r: r['commands'][0].update(profile='native-reference')),
            ('control sample', lambda r: r['commands'][0].update(control='extra-done')),
            ('failed child', lambda r: r['commands'][0].update(exit=99)),
            ('bool exit', lambda r: r['commands'][0].update(exit=False)),
            ('unreaped child', lambda r: r['commands'][0].update(reaped=False)),
            ('timeout', lambda r: r['commands'][0].update(timed_out=True)),
            ('cleanup failure', lambda r: r['commands'][0]['cleanup_errors'].append('supplied close failure')),
            ('open descriptor', lambda r: r['commands'][0]['descriptors'][0].update(closed=False)),
            ('larger limit', lambda r: r['commands'][0]['bounds'].__setitem__(3, 16)),
            ('missing capture', lambda r: r['commands'][0]['captures'].pop('preparation')),
            ('observer in timing', lambda r: r['commands'][0]['captures']['record'].update(bytes=1)),
            ('malformed digest', lambda r: r['commands'][0]['captures']['stderr'].update(sha256='g' * 64)),
            ('relabelled PID', lambda r: r['samples'][0].update(pid=999)),
            ('relabelled interval', lambda r: r['samples'][0].update(interval_ns=1)),
            ('bool interval', lambda r: r['samples'][0].update(interval_ns=True)),
            ('interval mismatch', lambda r: r['commands'][0].update(interval_ns=1)),
            ('clock order', lambda r: r['commands'][0].update(candidate_go_ns=999999)),
            ('extended deadline', lambda r: r['commands'][0].update(deadline_ns=16 * 10**9 + 1000)),
            ('terminal mismatch', lambda r: r['samples'][0].update(terminal_sha256='0' * 64)),
            ('wrong terminal profile', lambda r: r['commands'][0]['terminal_validation'].update(profile='gated-timing')),
            ('wrong output', lambda r: r['commands'][0]['terminal_validation'].update(output_bytes=1)),
            ('wrong CPU', lambda r: r['commands'][0]['terminal_validation'].update(cpu=3)),
            ('unqualified source', lambda r: r.update(qualification_verified=False)),
            ('changed source', lambda r: r.update(source_unchanged=False)),
            ('record FD99', lambda r: r['commands'][0]['descriptors'][0].update(fd=99)),
            ('negative pipe FD', lambda r: r['commands'][0]['descriptors'][1].update(fd=-4)),
            ('negative clocks', lambda r: shift_clock(r, 0, -10**12)),
            ('overlapping children', lambda r: shift_clock(r, 1, -1000000)),
            ('missing cleanup list', lambda r: r['commands'][0].update(cleanup_errors=None)),
            ('boolean final errors', lambda r: r.update(final_errors=False)),
            ('unfinished duration', lambda r: r['commands'][0].update(duration_ns=0)),
            ('continue after rejection', continue_after_rejection),
        ]
        for label, change in changes:
            with self.subTest(label=label):
                changed = copy.deepcopy(base)
                change(changed)
                with self.assertRaises(ValueError):
                    samples.summarize(changed)


if __name__ == '__main__':
    unittest.main()
