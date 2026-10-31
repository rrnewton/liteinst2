"""Synthetic parser controls only; no project, process or native witness."""
import sys
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('use Python -I -B with assertions enabled')
import copy
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location('closed_stderr_under_test', Path(__file__).with_name('closed_stderr.py'))
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)

PREFIX = b'original population failure\n loop_trace_current=[original bytes]\n'
EXPECTED = dict(pid=7, tid=8, totals=dict(entered=2, ret_observed=2, confirmed=2, completed=2, unsampled=0))
REVISION = 'bcbbdfe2b54c58eae0d35ddf34c4bb9238b0c959'
DISABLED = ' controller_phase_totals_v1=[status=UNAVAILABLE reason=disabled]\n'


def fixture():
    # Explicit independent small values: eleven worker spans sum to66;
    # controller has two complete iterations and a six-boundary current prefix.
    names = ('receive', 'dispatch', 'input', 'setup', 'before_custody', 'invoke',
             'after_custody', 'checkpoint_custody', 'checkpoint', 'reply', 'cleanup')
    worker = (
        'worker_phase_v1 diagnostic_only=true pid=7 tid=8 terminal_totals=NormalTotals { entered: 2, ret_observed: 2, confirmed: 2, completed: 2, unsampled: 0 }\n'
        'worker_scope=after_ready_send_through_detach_postflight spans_not_operations=true wall_includes_observer_and_scheduler_cost=true\n'
        'worker_phases_v1 diagnostic_only status=VALID bucket_scope=complete_partition window_start_ns=0 observed_end_ns=66 partition_ns=66\n')
    worker += ''.join('worker_phase %s valid=true spans=1 sum_ns=%d min_ns=%d max_ns=%d\n' % (name, n, n, n)
                      for n, name in enumerate(names, 1))
    worker += ('custody_substages_v1 status=VALID started=3 completed=3 partition_ns=9 '
               'scope=nested_three_custody_phases_not_additive spans_not_operations=true\n')
    for name in ('before_custody', 'after_custody', 'checkpoint_custody'):
        worker += 'custody_parent %s valid=true spans=1 sum_ns=3 min_ns=3 max_ns=3\n' % name
    for i, name in enumerate(('identity', 'maps_read', 'maps_parse', 'mapping', 'tasks',
                               'stamp', 'file_read', 'file_compare', 'live_bytes', 'remainder')):
        worker += 'custody_stage ' + name + (' valid=true spans=3 sum_ns=3 min_ns=1 max_ns=1\n' if i < 3 else
                                             ' valid=true spans=0 sum_ns=0 min_ns=none max_ns=none\n')
    edges = ('poll->poll_returned', 'poll_returned->poll_arm', 'poll_arm->reply_history',
             'reply_history->retire', 'retire->input', 'input->dispatch', 'dispatch->finalize',
             'finalize->write', 'write->wait_bound', 'wait_bound->wait', 'wait->end')
    controller = (' controller_phase_totals_v1=[status=OBSERVED started=3 completed=2 current=1 zero_progress_completed=1 reply_calls=2 '
                  'decisions={arm:1,stop:0,wait:2,refused:0,other:0,} replies={batch:2,flushed:0,finished:1,other:0,} completed_boundary_spans_ns={')
    controller += ''.join(name + ':(valid=true spans=%d sum_ns=%d min_ns=1 max_ns=5),' %
                          ((3, 9) if i < 6 else (2, 6)) for i, name in enumerate(edges))
    controller += ('} inter_iteration_end_to_poll_ns=(valid=true spans=2 sum_ns=4 min_ns=1 max_ns=3) '
                   'unfinished_from=dispatch unfinished_through_error_ns=(valid=true spans=1 sum_ns=7 min_ns=7 max_ns=7) '
                   'scope=controller_wall_observations_not_worker_or_performance]\n')
    return PREFIX + (worker + controller).encode('ascii')


class Controls(unittest.TestCase):
    def parse(self, raw, expected=EXPECTED):
        return parser.parse(raw, revision=REVISION, runtime_status='FAILED', expected=expected)

    def refuses(self, raw, expected=EXPECTED):
        with self.assertRaises(parser.DiagnosticError):
            self.parse(raw, expected)

    def test_valid_partition_partial_controller_and_raw_failure_are_separate(self):
        raw = fixture()
        result = self.parse(raw)
        self.assertEqual(result['runtime_status'], 'FAILED')
        self.assertEqual(result['attribution'], 'OBSERVED')
        self.assertEqual(result['original_stderr'], PREFIX)
        self.assertEqual(result['original_stderr'] + result['diagnostic_stderr'], raw)
        self.assertEqual(result['worker']['totals'], EXPECTED['totals'])
        self.assertEqual(result['worker']['partition_ns'], 66)
        self.assertEqual(sum(b['sum_ns'] for b in result['worker']['buckets'].values()), 66)
        self.assertEqual([b['spans'] for b in result['controller']['boundaries'].values()], [3] * 6 + [2] * 5)
        self.assertEqual(result['controller']['tail']['sum_ns'], 7)
        self.assertNotIn('partition_ns', result['controller'])
        self.assertNotIn('cpu_time', result)
        self.assertEqual(result['custody']['partition_ns'], 9)
        self.assertEqual(sum(b['sum_ns'] for b in result['custody']['stages'].values()), 9)
        self.assertEqual(result['worker']['partition_ns'], 66)  # Never 66+9.
        self.assertEqual(result['custody']['scope'], 'NESTED_NOT_ADDITIVE_WALL_SPANS')
        opaque = raw.replace(PREFIX, b'original non-ASCII cause: \xff\n', 1)
        self.assertEqual(self.parse(opaque)['original_stderr'], b'original non-ASCII cause: \xff\n')

    def test_success_and_absent_publication_do_not_fabricate_measurements(self):
        result = parser.parse(b'', revision=REVISION, runtime_status='PASS')
        self.assertEqual((result['runtime_status'], result['attribution']), ('PASS', 'UNAVAILABLE'))
        self.assertIsNone(result['worker']); self.assertIsNone(result['controller'])
        with self.assertRaises(parser.DiagnosticError):
            parser.parse(fixture(), revision=REVISION, runtime_status='PASS', expected=EXPECTED)
        for raw in (b'', PREFIX):
            result = self.parse(raw, None)
            self.assertEqual(result['attribution'], 'UNAVAILABLE')
            self.assertEqual(result['original_stderr'], raw)
            self.assertEqual(result['diagnostic_stderr'], b'')
            self.assertIsNone(result['worker'])

    def test_unavailable_and_invalid_forms_retain_no_completion_claim(self):
        for reason in ('completion_not_authenticated', 'no_completed_snapshot'):
            raw = PREFIX + ('worker_phase_v1 status=UNAVAILABLE reason=' + reason + '\n' + DISABLED).encode()
            result = self.parse(raw, None)
            self.assertEqual(result['worker'], dict(status='UNAVAILABLE', reason=reason))
            self.assertEqual(result['attribution'], 'UNAVAILABLE')
        raw = PREFIX + ('worker_phase_v1 status=INVALID reason=completion_identity_or_totals\n' + DISABLED).encode()
        self.assertEqual(self.parse(raw, None)['attribution'], 'INVALID')
        raw = PREFIX + b'phase_totals_v1 status=INVALID reason=format_bound\n'
        result = self.parse(raw, None)
        self.assertEqual(result['attribution'], 'INVALID')
        self.assertEqual(result['original_stderr'] + result['diagnostic_stderr'], raw)
        self.assertIsNone(result['worker']); self.assertIsNone(result['controller'])
        raw = fixture().replace(b'status=VALID bucket_scope=complete_partition', b'status=INVALID bucket_scope=retained_valid_prefix').replace(b'partition_ns=66', b'partition_ns=none')
        raw = raw.replace(b'custody_substages_v1 status=VALID', b'custody_substages_v1 status=INVALID').replace(b'completed=3 partition_ns=9', b'completed=3 partition_ns=none')
        result = self.parse(raw)
        self.assertEqual(result['attribution'], 'INVALID')
        self.assertIsNone(result['worker']['partition_ns'])
        self.assertEqual(result['worker']['buckets']['receive']['sum_ns'], 1)
        raw = raw.replace(b'window_start_ns=0 observed_end_ns=66', b'window_start_ns=none observed_end_ns=none')
        self.assertIsNone(self.parse(raw)['worker']['window_start_ns'])
        nested_invalid = fixture().replace(b'custody_substages_v1 status=VALID', b'custody_substages_v1 status=INVALID').replace(b'completed=3 partition_ns=9', b'completed=2 partition_ns=none')
        result = self.parse(nested_invalid)
        self.assertEqual(result['attribution'], 'INVALID')
        self.assertEqual(result['worker']['status'], 'VALID')
        self.assertIsNone(result['custody']['partition_ns'])
        empty = fixture().replace(b'observed_end_ns=66 partition_ns=66', b'observed_end_ns=46 partition_ns=46')
        for name, ns in (('before_custody', 5), ('after_custody', 7), ('checkpoint_custody', 8)):
            old = ('worker_phase %s valid=true spans=1 sum_ns=%d min_ns=%d max_ns=%d' % (name, ns, ns, ns)).encode()
            new = ('worker_phase %s valid=true spans=0 sum_ns=0 min_ns=none max_ns=none' % name).encode()
            empty = empty.replace(old, new)
        rows = empty.splitlines(keepends=True)
        for i, row in enumerate(rows):
            if row.startswith((b'custody_parent ', b'custody_stage ')):
                rows[i] = re.sub(rb'valid=true spans=[0-9]+ sum_ns=[0-9]+ min_ns=(?:none|[0-9]+) max_ns=(?:none|[0-9]+)',
                                 b'valid=true spans=0 sum_ns=0 min_ns=none max_ns=none', row)
        empty = b''.join(rows).replace(b'custody_substages_v1 status=VALID started=3 completed=3 partition_ns=9',
                                      b'custody_substages_v1 status=UNAVAILABLE started=0 completed=0 partition_ns=none')
        result = self.parse(empty)
        self.assertEqual(result['attribution'], 'UNAVAILABLE')
        self.assertEqual(result['runtime_status'], 'FAILED')
        self.assertIsNone(result['custody']['partition_ns'])
        self.refuses(empty.replace(b'custody_stage tasks valid=true spans=0 sum_ns=0 min_ns=none max_ns=none',
                                  b'custody_stage tasks valid=true spans=1 sum_ns=0 min_ns=0 max_ns=0'))

    def test_independent_identity_and_every_terminal_word_are_mandatory(self):
        for key in ('pid', 'tid'):
            changed = copy.deepcopy(EXPECTED); changed[key] += 1
            self.refuses(fixture(), changed)
        for key in EXPECTED['totals']:
            changed = copy.deepcopy(EXPECTED); changed['totals'][key] += 1
            self.refuses(fixture(), changed)
        for expected in (None, {}, dict(EXPECTED, extra=1), dict(EXPECTED, pid=True),
                         dict(EXPECTED, totals=dict(EXPECTED['totals'], entered=True)),
                         dict(EXPECTED, totals={'entered': 2})):
            self.refuses(fixture(), expected)
        self.refuses(fixture().replace(b'pid=7 tid=8', b'pid=8 tid=7'))

    def test_missing_duplicate_reordered_and_unknown_fields_refuse(self):
        raw = fixture()
        rows = raw.splitlines(keepends=True)
        bucket_index = next(i for i, row in enumerate(rows) if row.startswith(b'worker_phase receive '))
        for changed in (rows[:bucket_index] + rows[bucket_index + 1:],
                        rows[:bucket_index] + [rows[bucket_index]] + rows[bucket_index:],
                        rows[:bucket_index] + [rows[bucket_index + 1], rows[bucket_index]] + rows[bucket_index + 2:]):
            self.refuses(b''.join(changed))
        for before, after in ((b'pid=7 tid=8', b'tid=8 pid=7'),
                              (b'unsampled: 0 }', b'unsampled: 0, extra: 1 }'),
                              (b'worker_phase input ', b'worker_phase unknown '),
                              (b'arm:1,stop:0,', b'stop:0,arm:1,'),
                              (b'worker_phases_v1', b'worker_phases_v2')):
            self.refuses(raw.replace(before, after, 1))

        rows = fixture().splitlines(keepends=True)
        index = next(i for i, row in enumerate(rows) if row.startswith(b'custody_stage identity '))
        for changed in (rows[:index] + rows[index + 1:],
                        rows[:index] + [rows[index]] + rows[index:],
                        rows[:index] + [rows[index + 1], rows[index]] + rows[index + 2:]):
            self.refuses(b''.join(changed))
        self.refuses(fixture().replace(b'custody_parent before_custody', b'custody_parent cleanup'))
        self.refuses(fixture().replace(b'custody_stage maps_parse', b'custody_stage unknown'))

    def test_numeric_domains_extrema_and_worker_conservation_refuse(self):
        raw = fixture()
        for before, after in ((b'pid=7', b'pid=4294967296'),
                              (b'tid=8', b'tid=18446744073709551616'),
                              (b'entered: 2', b'entered: 02'),
                              (b'unsampled: 0', b'unsampled: -1'),
                              (b'spans=1 sum_ns=1 ', b'spans=18446744073709551616 sum_ns=1 '),
                              (b'sum_ns=1 min_ns=1', b'sum_ns=340282366920938463463374607431768211456 min_ns=1'),
                              (b'sum_ns=1 min_ns=1 max_ns=1', b'sum_ns=1 min_ns=2 max_ns=1'),
                              (b'sum_ns=1 min_ns=1 max_ns=1', b'sum_ns=2 min_ns=1 max_ns=1'),
                              (b'partition_ns=66', b'partition_ns=67'),
                              (b'valid=true spans=1', b'valid=false spans=1')):
            self.refuses(raw.replace(before, after, 1))
        zero = raw.replace(b'spans=1 sum_ns=1 min_ns=1 max_ns=1', b'spans=1 sum_ns=0 min_ns=0 max_ns=0', 1).replace(b'observed_end_ns=66 partition_ns=66', b'observed_end_ns=65 partition_ns=65')
        self.assertEqual(self.parse(zero)['worker']['buckets']['receive']['min_ns'], 0)
        empty = raw.replace(b'spans=1 sum_ns=1 min_ns=1 max_ns=1', b'spans=0 sum_ns=0 min_ns=none max_ns=none', 1).replace(b'observed_end_ns=66 partition_ns=66', b'observed_end_ns=65 partition_ns=65')
        self.assertIsNone(self.parse(empty)['worker']['buckets']['receive']['min_ns'])
        self.refuses(empty.replace(b'spans=0 sum_ns=0 min_ns=none', b'spans=0 sum_ns=1 min_ns=none', 1))

        for before, after in (
                (b'custody_substages_v1 status=VALID started=3', b'custody_substages_v1 status=VALID started=18446744073709551616'),
                (b'completed=3 partition_ns=9', b'completed=2 partition_ns=9'),
                (b'completed=3 partition_ns=9', b'completed=3 partition_ns=10'),
                (b'custody_parent before_custody valid=true spans=1 sum_ns=3 min_ns=3 max_ns=3',
                 b'custody_parent before_custody valid=true spans=2 sum_ns=3 min_ns=1 max_ns=2'),
                (b'custody_parent before_custody valid=true spans=1 sum_ns=3 min_ns=3 max_ns=3',
                 b'custody_parent before_custody valid=true spans=1 sum_ns=6 min_ns=6 max_ns=6'),
                (b'custody_stage maps_read valid=true', b'custody_stage maps_read valid=false'),
                (b'custody_stage identity valid=true spans=3 sum_ns=3 min_ns=1 max_ns=1',
                 b'custody_stage identity valid=true spans=3 sum_ns=4 min_ns=1 max_ns=2'),
                (b'custody_stage identity valid=true spans=3 sum_ns=3 min_ns=1 max_ns=1',
                 b'custody_stage identity valid=true spans=3 sum_ns=340282366920938463463374607431768211456 min_ns=1 max_ns=340282366920938463463374607431768211456'),
                (b'custody_substages_v1 status=VALID', b'custody_substages_v1 status=INVALID')):
            self.refuses(raw.replace(before, after, 1))

        # Keep conservation and extrema true so these isolate parent joins.
        over = raw.replace(b'completed=3 partition_ns=9', b'completed=3 partition_ns=12')
        over = over.replace(b'custody_parent before_custody valid=true spans=1 sum_ns=3 min_ns=3 max_ns=3',
                            b'custody_parent before_custody valid=true spans=1 sum_ns=6 min_ns=6 max_ns=6')
        over = over.replace(b'custody_stage maps_read valid=true spans=3 sum_ns=3 min_ns=1 max_ns=1',
                            b'custody_stage maps_read valid=true spans=3 sum_ns=6 min_ns=2 max_ns=2')
        self.refuses(over)
        moved = raw.replace(b'completed=3 partition_ns=9', b'completed=3 partition_ns=6')
        moved = moved.replace(b'custody_parent before_custody valid=true spans=1 sum_ns=3 min_ns=3 max_ns=3',
                              b'custody_parent before_custody valid=true spans=2 sum_ns=3 min_ns=1 max_ns=2')
        moved = moved.replace(b'custody_parent after_custody valid=true spans=1 sum_ns=3 min_ns=3 max_ns=3',
                              b'custody_parent after_custody valid=true spans=0 sum_ns=0 min_ns=none max_ns=none')
        moved = moved.replace(b'custody_stage identity valid=true spans=3 sum_ns=3 min_ns=1 max_ns=1',
                              b'custody_stage identity valid=true spans=0 sum_ns=0 min_ns=none max_ns=none')
        self.refuses(moved)

    def test_controller_observed_prefix_tail_and_invalid_state_are_distinct(self):
        raw = fixture()
        for before, after in ((b'started=3', b'started=4'),
                              (b'zero_progress_completed=1', b'zero_progress_completed=3'),
                              (b'arm:1,', b'arm:2,'),
                              (b'finished:1,', b'finished:2,'),
                              (b'poll->poll_returned:(valid=true spans=3', b'poll->poll_returned:(valid=true spans=2'),
                              (b'current=1', b'current=0'),
                              (b'unfinished_from=dispatch', b'unfinished_from=wait'),
                              (b'unfinished_through_error_ns=(valid=true spans=1', b'unfinished_through_error_ns=(valid=true spans=2')):
            self.refuses(raw.replace(before, after, 1))
        no_tail = raw.replace(b'unfinished_through_error_ns=(valid=true spans=1 sum_ns=7 min_ns=7 max_ns=7)', b'unfinished_through_error_ns=UNAVAILABLE')
        self.assertIsNone(self.parse(no_tail)['controller']['tail'])
        invalid = raw.replace(b'controller_phase_totals_v1=[status=OBSERVED', b'controller_phase_totals_v1=[status=INVALID').replace(b'unfinished_through_error_ns=(valid=true spans=1 sum_ns=7 min_ns=7 max_ns=7)', b'unfinished_through_error_ns=(valid=false spans=0 sum_ns=0 min_ns=none max_ns=none)')
        result = self.parse(invalid)
        self.assertEqual(result['attribution'], 'INVALID')
        self.assertFalse(result['controller']['tail']['valid'])
        self.assertEqual(result['controller']['boundaries']['poll->poll_returned']['sum_ns'], 9)

    def test_suffix_is_unique_bounded_complete_ascii_and_unmodified(self):
        raw = fixture(); suffix = raw[len(PREFIX):]
        for changed in (raw[:-1], raw + suffix, raw + b'extra\n',
                        raw.replace(b'worker_phase_v1 ', b'worker_phase_v9 ', 1),
                        raw.replace(b'worker_scope=', b'worker_scope=\xff', 1),
                        raw.replace(b'worker_scope=', b'worker_scope=\r', 1),
                        PREFIX + b' controller_phase_totals_v1=[status=UNAVAILABLE reason=disabled]\n',
                        PREFIX + b'  controller_phase_totals_v1=[status=UNAVAILABLE reason=disabled]\n',
                        raw + b'x' * 16384 + b'\n'):
            self.refuses(changed)
        with self.assertRaises(parser.DiagnosticError):
            self.parse(b'x' * (8 * 1024 * 1024 + 1))
        for status in ('UNKNOWN', '', None, True):
            with self.assertRaises(parser.DiagnosticError):
                parser.parse(raw, revision=REVISION, runtime_status=status, expected=EXPECTED)
        with self.assertRaises(parser.DiagnosticError):
            parser.parse(raw, revision='0' * 40, runtime_status='FAILED', expected=EXPECTED)
        with self.assertRaises(parser.DiagnosticError):
            self.parse(bytearray(raw))

    def test_zero_unavailable_and_completed_controller_have_no_current_tail(self):
        line = fixture().splitlines()[-1].decode()
        zero = line.replace('status=OBSERVED started=3 completed=2 current=1 zero_progress_completed=1 reply_calls=2',
                            'status=UNAVAILABLE started=0 completed=0 current=0 zero_progress_completed=0 reply_calls=0')
        zero = zero.replace('arm:1,stop:0,wait:2,', 'arm:0,stop:0,wait:0,').replace('batch:2,flushed:0,finished:1,', 'batch:0,flushed:0,finished:0,')
        zero = re.sub(r'\(valid=true spans=[0-9]+ sum_ns=[0-9]+ min_ns=[0-9]+ max_ns=[0-9]+\)',
                      '(valid=true spans=0 sum_ns=0 min_ns=none max_ns=none)', zero)
        zero = zero.replace('unfinished_from=dispatch unfinished_through_error_ns=(valid=true spans=0 sum_ns=0 min_ns=none max_ns=none)',
                            'unfinished_from=none unfinished_through_error_ns=UNAVAILABLE')
        raw = PREFIX + b'worker_phase_v1 status=UNAVAILABLE reason=completion_not_authenticated\n' + zero.encode() + b'\n'
        result = self.parse(raw, None)
        self.assertEqual(result['controller']['started'], 0)
        self.assertEqual(result['controller']['status'], 'UNAVAILABLE')
        self.assertIsNone(result['controller']['tail'])
        self.refuses(raw.replace(b'reply_calls=0', b'reply_calls=1'), None)
        completed = line.replace('started=3 completed=2 current=1', 'started=2 completed=2 current=0')
        completed = completed.replace('wait:2,', 'wait:1,').replace('finished:1,', 'finished:0,')
        completed = completed.replace('spans=3 sum_ns=9 min_ns=1 max_ns=5', 'spans=2 sum_ns=6 min_ns=1 max_ns=5')
        completed = completed.replace('inter_iteration_end_to_poll_ns=(valid=true spans=2 sum_ns=4 min_ns=1 max_ns=3)',
                                      'inter_iteration_end_to_poll_ns=(valid=true spans=1 sum_ns=3 min_ns=3 max_ns=3)')
        completed = completed.replace('unfinished_from=dispatch unfinished_through_error_ns=(valid=true spans=1 sum_ns=7 min_ns=7 max_ns=7)',
                                      'unfinished_from=none unfinished_through_error_ns=UNAVAILABLE')
        raw = fixture().rsplit(b'\n', 2)[0] + b'\n' + completed.encode() + b'\n'
        result = self.parse(raw)
        self.assertEqual([b['spans'] for b in result['controller']['boundaries'].values()], [2] * 11)
        self.assertIsNone(result['controller']['tail'])


if __name__ == '__main__':
    unittest.main()
