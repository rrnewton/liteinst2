#!/usr/bin/env python3
"""Pure fabricated full-population wire controls; no PMU or native execution."""
import copy
from pathlib import Path
import sys
import unittest

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import output

HERE = Path(__file__).resolve().parent
prior = output._load('_accuracy_prior_fixture', HERE.parent / 'ordinary-leaf-set-session/controls.py')
selected = output._load('_accuracy_selected_fixture', HERE.parent / 'ordinary-selected-session/wire_controls.py')
ABSENT = ['0', '-', '-', '-', '-', '-']
REQUEST = bytes.fromhex('00000000800000000100000000000000'
                        '00000000000000000000000000000000'
                        '07000000000000006500100000000000' + '00' * 80)


def raw_control(operation, result=0, errno='-', data=None):
    data = bytes(32) if data is None else data
    size = 8 if operation == 0 and result == 0 else min(result, 32) if operation == 2 and result >= 0 else 0
    return ['1', str(operation), str(result), str(errno), str(size), data.hex()]


def counter_words(*values):
    return b''.join(value.to_bytes(8, 'little') for value in values)


def set_read(row, *, result=32, errno='-', values=(100, 100, 100, 77), data=None):
    row[11] = '-' if result != 32 or errno != '-' else str(int(values[3] == 77))
    row[12:] = raw_control(2, result, errno, counter_words(*values) if data is None else data)


def fixture(k=10, period=10, phase='locked', arms=1, prefixes=None):
    # The producer receives these independent original bytes; fixture generation
    # never calls native code or the selected function.
    files, manifest = output.truth.artifacts('12' * 32, 'calibration', 1, 'varied')
    truths = output.truth.population(manifest['seed'], manifest['workload'])
    old_records = tuple((r['payload'], (1, r['length'], 0, 0)) for r in truths)
    old, old_args = prior.fixture(n=1, count=2048, k=k, arms=arms, records=old_records,
                                  operations=('length',), prefixes=prefixes)
    policy = dict(next(p for p in manifest['policies'] if
                       (p['k'], p['period_ms'], p['phase']) == (k, period, phase)), epochs=520)
    table = (dict(function_id=41, operation='exact_work_nonempty', policy='whole',
                  elf_va=4096, extent=37, returns=(36,)),)
    args = dict(manifest_bytes=output.truth.canonical(manifest), input_bytes=files['input.csv'],
                selected_bytes=files['selected.txt'], truth_bytes=files['truth.csv'],
                table=table, caller=old_args['caller'], body_bytes=output.truth.BODY,
                abi=output.ABI, policy=policy, cpus=old_args['cpus'])
    attr = REQUEST
    acquire = [['PMUOPEN', 123, 124, 19, '-']]
    acquire.extend(['PMUATTR', kind, offset, attr[offset:offset + 64].hex()]
                   for kind in (0, 1) for offset in (0, 64))
    acquire += [['PMUCTL', 0, *raw_control(0, data=counter_words(77, 0, 0, 0))],
                ['PMUCTL', 1, *raw_control(1)]]
    rows = []
    for row in old:
        tag = row[0]
        if tag == 'READY':
            row[1], row[3], row[4] = output.VERSION, 520, period
        elif tag == 'LEAF':
            row[2:7] = [41, 'exact_work_nonempty', 'whole', 4096, 37]
            row[8], row[9] = row[7] + 37, 1
        elif tag == 'RET':
            if row[2] == 47:
                continue
            row[2] = 36
        elif tag == 'CALL':
            row[8], row[11], row[12] = 36, row[3] * 1000, row[3] * 1000 + 700
        elif tag == 'RESULT':
            row[4] = truths[row[1] - 1]['value']
        elif tag == 'SAMPLE':
            row[7], row[9] = row[1] * 1000, row[1] * 1000 + 700
        elif tag == 'COVERAGE':
            row[-2:] = [1, 1]
        rows.append(row)
        if tag == 'RET':
            rows.extend(copy.deepcopy(acquire))
        elif tag == 'HISTORY' and row[3] == 'published':
            due = (row[2] - 1) * period * 1000000
            rows.append(['ARM', row[2], row[4], due, due + 10, due + 20, 1])
        elif tag == 'RESULT':
            ordinal = row[1]
            for side in (0, 1):
                t = ordinal * 1000 + side * 700
                raw = counter_words(ordinal * 1000 + side * 100,
                                    ordinal * 1000 + side * 100,
                                    ordinal * 1000 + side * 100, 77)
                rows.append(['PMU', ordinal, 0, side, 123, 124, t + 10, 0, t + 20, 0,
                             1, 1, *raw_control(2, 32, data=raw)])
        elif tag == 'COVERAGE':
            rows.extend([['PMUCLOSE', 123, 124], ['PMUCTL', 3, *raw_control(3)],
                         ['PMUCTL', 4, *raw_control(4)]])
    # Test mutations use the exact serialized spelling, as does the decoder.
    return [[str(c) for c in row] for row in rows], args


def encode(rows):
    return prior.encode(rows)


def first(rows, tag):
    return next(i for i, r in enumerate(rows) if r[0] == tag)


def check(rows, args):
    return output.check(encode(rows), b'', **args)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.args = fixture()

    def copy(self):
        return copy.deepcopy(self.rows), copy.deepcopy(self.args)

    def refuses(self, rows, args, reason=None):
        raw = encode(rows)
        with self.assertRaises(output.Refused) as caught:
            output.check(raw, b'', **args)
        self.assertEqual(caught.exception.raw, raw)
        self.assertEqual(caught.exception.stderr, b'')
        if reason is not None:
            self.assertIn(reason, caught.exception.reason)

    def test_all_policy_domains_preserve_full_sampled_and_unsampled_population(self):
        for k, period, phase in ((1, 1, 'locked'), (10, 10, 'random'),
                                  (100, 100, 'locked'), (1000, 1, 'random')):
            rows, args = fixture(k, period, phase)
            result = check(rows, args)
            self.assertEqual(result['status'], 'STRUCTURALLY_COMPLETE')
            self.assertEqual((result['totals']['calls'], result['totals']['sampled'],
                              result['totals']['unsampled']), (2048, k, 2048 - k))
            self.assertEqual(len(result['calls']), 2048)
            self.assertEqual(len(result['numeric']['rows']['RESULT']), 2048)
            self.assertEqual(result['raw'], encode(rows))
            self.assertEqual(result['wire_rows'], rows)
            self.assertEqual(result['hardware_status'], 'UNRESOLVED')
            self.assertEqual(result['requested_phase_status'], 'UNRESOLVED')
            self.assertEqual(result['manifest']['phase'], 'calibration')
            self.assertEqual(result['policy']['phase'], phase)
            self.assertTrue(all(c['hardware_status'] == 'UNRESOLVED' for c in result['calls']))
            self.assertTrue(all(c['counter_arithmetic']['kind'] == 'full_running' for c in result['calls']))
            self.assertEqual(result['numeric']['raw'], encode([r for r in rows if r[0] in output.shared.FIELDS or r[0] == 'RESULT']))

    def test_authority_binds_every_original_byte_and_full_2048_denominator(self):
        for key in ('manifest_bytes', 'input_bytes', 'selected_bytes', 'truth_bytes', 'body_bytes'):
            rows, args = self.copy()
            args[key] = args[key][:-1]
            self.refuses(rows, args)
        rows, args = self.copy()
        args['manifest_bytes'] = args['manifest_bytes'].replace(b'"trial":1', b'"trial":1,"trial":1')
        self.refuses(rows, args, 'duplicate manifest key')
        rows, args = self.copy()
        at = next(i for i, r in enumerate(rows) if r[:2] == ['CALL', '2048'])
        del rows[at:at + 4]  # CALL, RESULT and both raw endpoints: no tail subset.
        self.refuses(rows, args, 'complete evidence population')
        rows, args = self.copy()
        rows[first(rows, 'RESULT')][4] = '0'
        self.refuses(rows, args)

    def test_actual_geometry_caller_abi_and_policy_are_separate_exact_inputs(self):
        for key, value in (('function_id', 42), ('operation', 'length'), ('policy', 'certified'),
                           ('extent', 38), ('returns', (35,)), ('elf_va', 8192)):
            rows, args = self.copy(); args['table'][0][key] = value
            self.refuses(rows, args)
        for key, value in (('abi', 'guessed'), ('cpus', (2, 2)),
                           ('caller', dict(extent=32, continuation=18))):
            rows, args = self.copy(); args[key] = value
            self.refuses(rows, args)
        for key, value in (('k', 2), ('k', True), ('period_ms', 2), ('epochs', 521),
                           ('phase', 'calibration'), ('delay_ns', 1), ('extra', 1)):
            rows, args = self.copy(); args['policy'][key] = value
            self.refuses(rows, args)

    def test_old_wrappers_and_new_reader_mutually_refuse_profiles(self):
        old, args = prior.fixture(n=1)
        self.assertEqual(prior.output.check(encode(old), b'', **args)['status'], 'LEAF_SET_WIRE_PASS')
        self.refuses(old, self.args)
        old, old_args = selected.fixture()
        self.assertEqual(selected.check(old, old_args)['status'], 'SELECTED_SESSION_WIRE_PASS')
        self.refuses(old, self.args)
        for module, old_args in ((prior.output, args), (selected.output, old_args)):
            with self.assertRaises(AssertionError):
                module.check(encode(self.rows), b'', **old_args)
        old, args = prior.fixture(n=1, k=1)
        with self.assertRaises(AssertionError):
            prior.output.check(encode(old), b'', **args)
        for version in ('leaf-set-session-v1', 'selected-session-v1'):
            rows, args = self.copy(); rows[0][1] = version
            self.refuses(rows, args, 'initial selected header')

    def test_all_new_families_required_ordered_and_unique(self):
        for tag in ('PMUOPEN', 'PMUATTR', 'PMUCTL', 'ARM', 'PMU', 'PMUCLOSE'):
            at = first(self.rows, tag)
            self.refuses(self.rows[:at] + self.rows[at + 1:], self.args)
            self.refuses(self.rows[:at] + [self.rows[at]] + self.rows[at:], self.args)
        rows, args = self.copy()
        at = first(rows, 'PMU'); rows[at], rows[at + 1] = rows[at + 1], rows[at]
        self.refuses(rows, args, 'endpoint order/key')
        rows, args = self.copy()
        at = first(rows, 'PMUATTR'); rows[at], rows[at + 1] = rows[at + 1], rows[at]
        self.refuses(rows, args, 'whole attribute ordering')
        self.refuses(self.rows + [['UNKNOWN']], self.args)

    def test_normal_identity_history_return_and_totals_still_refuse(self):
        for tag, column in (('READY', 12), ('LEAF', 8), ('RET', 2), ('HISTORY', 2),
                            ('REPORT', 2), ('CALL', 3), ('CALL', 10), ('SAMPLE', 5),
                            ('COVERAGE', 2), ('DONE', 6)):
            rows, args = self.copy(); at = first(rows, tag)
            rows[at][column] = str(int(rows[at][column]) + 1)
            self.refuses(rows, args)

    def test_all_four_attributes_retained_and_requested_event_not_negotiated(self):
        result = check(self.rows, self.args)
        self.assertEqual(result['acquisition']['requested_attributes'], REQUEST)
        self.assertEqual(len(result['acquisition']['requested_attributes']), 128)
        self.assertEqual(len(result['acquisition']['attributes_after_open']), 128)
        for kind in (0, 1):
            rows, args = self.copy()
            at = next(i for i, r in enumerate(rows) if r[:3] == ['PMUATTR', str(kind), '64'])
            rows[at][3] = '01' + rows[at][3][2:]
            if kind == 0:
                self.refuses(rows, args, 'exact requested event')
            else:
                result = check(rows, args)
                self.assertEqual(result['acquisition']['attributes_after_open'][64], 1)
                self.assertIn('attributes_changed', result['calls'][0]['observed_limitations'])

    def test_open_failure_keeps_errno_attributes_all_calls_and_absent_controls(self):
        rows, args = self.copy()
        rows[first(rows, 'PMUOPEN')][3:] = ['-1', '13']
        for r in rows:
            if r[0] == 'PMUCTL':
                r[2:] = ABSENT
            elif r[0] == 'PMU':
                r[11], r[12:] = '-', ABSENT
        result = check(rows, args)
        self.assertEqual(result['acquisition']['open'], dict(result=-1, errno=13))
        self.assertEqual(len(result['calls']), 2048)
        self.assertTrue(all(c['counter_arithmetic']['kind'] == 'missing' for c in result['calls']))
        self.assertTrue(all('open_failed' in c['observed_limitations'] for c in result['calls']))
        self.assertEqual(result['session_limitations'], ['disable_failed_or_absent', 'close_failed_or_absent'])

    def test_id_enable_disable_and_close_failures_stay_raw(self):
        for role in (0, 1, 3, 4):
            rows, args = self.copy()
            r = next(r for r in rows if r[:2] == ['PMUCTL', str(role)])
            r[2:] = raw_control(role, -1, 5, bytes(range(32)))
            if role == 0:
                for e in rows:
                    if e[0] == 'PMU': e[11] = '-'
            result = check(rows, args)
            raw = (result['acquisition']['id' if role == 0 else 'enable'] if role < 2 else
                   result['close']['disable' if role == 3 else 'close'])
            self.assertEqual((raw['result'], raw['errno'], raw['data']), (-1, 5, bytes(range(32))))
            self.assertEqual(len(result['calls']), 2048)
            self.assertEqual(result['hardware_status'], 'UNRESOLVED')
            if role >= 3:
                self.assertIn(('disable' if role == 3 else 'close') + '_failed_or_absent', result['session_limitations'])

    def test_every_short_read_error_and_overlong_return_retains_complete_buffer(self):
        for size in (*range(32), -1, 33):
            rows, args = self.copy(); at = first(rows, 'PMU')
            data = bytes(range(32))
            set_read(rows[at], result=size, errno=5 if size < 0 else '-', data=data)
            result = check(rows, args)
            read = result['calls'][0]['start']['read']
            self.assertEqual((read['result'], read['data'], read['data_len']),
                             (size, data, max(0, min(size, 32))))
            self.assertEqual(result['calls'][0]['counter_arithmetic']['kind'], 'missing')
            self.assertEqual(result['calls'][0]['counter_arithmetic']['missing'], 'start')
            self.assertEqual(len(result['calls']), 2048)

    def test_endpoint_id_and_owner_mismatches_are_visible_not_corrected(self):
        rows, args = self.copy(); at = first(rows, 'PMU')
        set_read(rows[at], values=(100, 100, 100, 88))
        result = check(rows, args)
        self.assertEqual(result['calls'][0]['start']['id_matches'], 0)
        self.assertIn('start_id_unresolved_or_mismatch', result['calls'][0]['observed_limitations'])
        rows[at][11] = '1'; self.refuses(rows, args, 'event ID comparison flag')
        rows, args = self.copy(); at = first(rows, 'PMU')
        rows[at][5], rows[at][10], rows[at][11], rows[at][12:] = '125', '0', '-', ABSENT
        result = check(rows, args)
        self.assertIn('start_owner_mismatch', result['calls'][0]['observed_limitations'])
        rows[at][10] = '1'; self.refuses(rows, args, 'endpoint owner flag')
        rows, args = self.copy(); rows[first(rows, 'PMUCLOSE')][2] = '125'
        for r in rows:
            if r[:2] in (['PMUCTL', '3'], ['PMUCTL', '4']): r[2:] = ABSENT
        self.assertIn('close_owner_mismatch', check(rows, args)['session_limitations'])

    def test_counter_arithmetic_does_not_scale_zero_multiplexed_or_regressed_values(self):
        for a, b, kind in (((100, 100, 100, 77), (100, 100, 100, 77), 'zero_running'),
                           ((100, 100, 50, 77), (120, 200, 100, 77), 'multiplexed'),
                           ((100, 100, 100, 77), (90, 200, 200, 77), 'rejected'),
                           ((100, 100, 101, 77), (120, 200, 202, 77), 'rejected'),
                           ((100, 100, 100, 77), (120, 100, 100, 77), 'rejected')):
            rows, args = self.copy(); at = first(rows, 'PMU')
            set_read(rows[at], values=a); set_read(rows[at + 1], values=b)
            c = check(rows, args)['calls'][0]
            self.assertEqual(c['counter_arithmetic']['kind'], kind)
            self.assertEqual(c['counter_arithmetic']['start'], a)
            self.assertEqual(c['counter_arithmetic']['end'], b)
            self.assertIn('counter_' + kind, c['observed_limitations'])
            self.assertNotIn('scaled', c['counter_arithmetic'])
            self.assertEqual(c['hardware_status'], 'UNRESOLVED')

    def test_endpoint_aux_clock_and_normal_unavailable_samples_remain_visible(self):
        for column, value, reason in ((9, '1', 'start_reader_aux_changed'),
                                      (8, '0', 'start_reader_ticks_regressed')):
            rows, args = self.copy(); at = first(rows, 'PMU'); rows[at][column] = value
            self.assertIn(reason, check(rows, args)['calls'][0]['observed_limitations'])
        rows, args = self.copy()
        rows[first(rows, 'CALL')][14] = '1'
        sample = rows[first(rows, 'SAMPLE')]; sample[8:] = ['unavailable', '1']
        result = check(rows, args)
        self.assertEqual(result['numeric']['rows']['SAMPLE'][0]['end_kind'], 'unavailable')
        self.assertIn('interval_aux_changed', result['calls'][0]['observed_limitations'])

    def test_arm_original_due_and_inclusive_2ms_gate_are_exact(self):
        rows, args = self.copy(); at = first(rows, 'ARM')
        rows[at][5] = '2000000'
        self.assertTrue(check(rows, args)['recorded_arm_deadlines_satisfied'])
        rows[at][5], rows[at][6] = '2000001', '0'
        self.refuses(rows, args, 'original 2ms ARM deadline failed')
        rows[at][6] = '1'; self.refuses(rows, args, 'ARM outcome mismatch')
        for column in (1, 2, 3):
            rows, args = self.copy(); at = first(rows, 'ARM')
            rows[at][column] = str(int(rows[at][column]) + 1)
            self.refuses(rows, args)

    def test_arm_binds_each_actual_publication_and_early_eof_keeps_empty_reports(self):
        rows, args = fixture(arms=3)
        result = check(rows, args)
        self.assertEqual([a['generation'] for a in result['arms']], [101, 102, 103])
        self.assertEqual([r['records'] for r in result['numeric']['rows']['REPORT']], [0, 0, 10])
        self.assertEqual(result['totals']['epochs'], 3)
        # Initial-disarmed CALL is valid; moving ARM past that returned group
        # still contradicts the producer's immediate publication observation.
        rows, args = fixture(prefixes=[0] + [1] * 2047)
        arm = rows.pop(first(rows, 'ARM'))
        rows.insert(first(rows, 'RESULT') + 3, arm)
        self.refuses(rows, args, 'ARM immediately follows publication')

    def test_counter_shape_presence_numbers_and_errno_flags_are_strict(self):
        for column, value in ((1, '01'), (2, '1'), (3, '2'), (4, '-1'), (7, str(1 << 32)),
                               (10, '2'), (11, '2'), (12, '2'), (13, '3'), (14, '+32'),
                               (15, '0'), (16, '31'), (17, '00' * 31)):
            rows, args = self.copy(); rows[first(rows, 'PMU')][column] = value
            self.refuses(rows, args)
        rows, args = self.copy(); rows[first(rows, 'PMUOPEN')][3:] = ['-1', '-']
        self.refuses(rows, args, 'syscall result/errno presence')
        rows, args = self.copy(); rows[first(rows, 'PMU')][12:] = ABSENT
        self.refuses(rows, args, 'endpoint read presence')

    def test_bounded_framing_and_terminal_failures_retain_original_streams(self):
        raw = encode(self.rows)
        variants = (b'', raw[:-1], raw.replace(b'\n', b'\r\n', 1), b'\xff\n',
                    b'A' * 350 + b'\n', b'A' * (output.CAP + 1),
                    b'X\n' * (5 * 2048 + 3 * 520 + 21))
        for bad in variants:
            with self.assertRaises(output.Refused) as caught:
                output.check(bad, b'', **self.args)
            self.assertEqual(caught.exception.raw, bad)
        error = b'normal-selected-accuracy-session FAILED: arm deadline\n'
        with self.assertRaises(output.Refused) as caught:
            output.check(raw, error, **self.args)
        self.assertEqual((caught.exception.raw, caught.exception.stderr), (raw, error))
        rows, args = self.copy(); del rows[-1]
        self.refuses(rows, args)


if __name__ == '__main__':
    unittest.main()
