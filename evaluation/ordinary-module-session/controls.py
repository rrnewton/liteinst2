#!/usr/bin/env python3
"""Fabricated wire/control tests; no native, source-custody or Schedule credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


def load(name):
    path = Path(__file__).resolve().with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('_session_control_' + name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


output = load('output')
produce = load('produce')


def fixture(n=3, k=10, arms=1, prefix=1, outcome='eof', error='none'):
    records = tuple((b'a,b', 2) for _ in range(n))
    args = dict(records=records, k=k, epochs=max(arms, 1), outcome=outcome, input_error=error,
                lengths=(37, 41), returns=((36,), (34, 40)), continuation=17, cpus=(2, 4))
    rows = [['READY', 'module-session-v1', k, args['epochs'], 10, 2, 64, 2048, 4, 1,
             0x6d6f6401, 123, 123, 124, 2, 4, 4096, 4160, 4133, 4201, 8192],
            ['RET', 101, 36], ['RET', 202, 34], ['RET', 202, 40]]
    for i in range(1, arms + 1):
        rows.append(['HISTORY', i, i, 'published', i + 100])
    calls, samples = [], []
    completed = 0
    generation = prefix + 100
    for ordinal in range(1, 2 * n + 1):
        function = 101 if ordinal % 2 else 202
        rank = (ordinal - 1) // 2
        sampled = rank < k
        slot = completed + 1 if sampled else 0
        batch = (ordinal - 1) // 4 + 1
        checkpoint = ordinal % 4 == 0 or ordinal == 2 * n
        row = ['CALL', (ordinal + 1) // 2, function, ordinal,
               'sampled' if sampled else 'closed', generation, slot, prefix,
               36 if function == 101 else 34, 4104, 8209, ordinal, ordinal + 1, 0, 0,
               'checkpoint' if checkpoint else 'next', 0 if checkpoint else ordinal + 1, batch, completed]
        calls.append(row)
        rows.append(row)
        if sampled:
            samples.append(['SAMPLE', (ordinal + 1) // 2, function, generation, completed, rank, completed, ordinal, 'value', ordinal + 1])
            completed += 1
        if ordinal % 2 == 0:
            rows.append(['RESULT', ordinal // 2, 3, 0xe6169119046025e6, 2, 3, ordinal - 1, ordinal])
    # The checksum constant is deliberately derived from a separate literal below.
    for row in rows:
        if row[0] == 'RESULT':
            value = 0xcbf29ce484222325
            for byte in (97, 44, 98):
                value = ((value ^ byte) * 0x100000001b3) % (1 << 64)
            row[3] = value
    rows.append(['HISTORY', arms + 1, arms + 1, 'removed', arms + 100])
    for i in range(1, arms + 1):
        rows.append(['REPORT', i + 100, completed if i == prefix else 0])
    rows.extend(samples)
    for function, declared in ((101, 1), (202, 2)):
        rows.append(['COVERAGE', function, n, min(n, k), max(0, n - k), 0, 0, declared, 1 if n else 0])
    rows.append(['IO', 0])
    status = {'eof': 'COMPLETE', 'input_error': 'INPUT_REFUSED', 'input_incomplete': 'INPUT_INCOMPLETE'}[outcome]
    eof = int(outcome == 'eof' or error == 'unterminated')
    rows.append(['DONE', status, 'EpochLimit' if outcome == 'input_incomplete' else 'Requested', arms, arms + 1,
                 n, 2 * n, 2 * n, 2 * n, completed, 2 * n - completed, (2 * n + 3) // 4,
                 2 * n, 3 * n, eof, error, int(outcome == 'eof'), 1, 1])
    return rows, args


def encode(rows):
    return ('\n'.join(','.join(map(str, row)) for row in rows) + '\n').encode('ascii')


def check(rows, args):
    # Prospective fabricated fixture streams; production always passes actual stderr.
    stderr = b''
    if args['outcome'] == 'input_error':
        stderr = b'normal-module-session INPUT_REFUSED: ' + args['input_error'].encode('ascii') + b'\n'
    elif args['outcome'] == 'input_incomplete':
        stderr = b'normal-module-session INPUT_INCOMPLETE\n'
    return output.check(encode(rows), stderr, **args)


class Controls(unittest.TestCase):
    def test_original_input_refusal_never_accepts_hard_failure(self):
        reasons = ('bad_magic', 'count_over_2048', 'truncated_length', 'truncated_payload',
                   'length_over_64', 'non_ascii_payload', 'malformed_csv', 'trailing_input_byte')
        self.assertEqual(output.ORIGINAL_REFUSALS, reasons)
        for reason in reasons:
            actual = b'module-session-original INPUT_REFUSED: ' + reason.encode('ascii') + b'\n'
            self.assertEqual(output.original_refusal(b'', actual, 2, reason)['reason'], reason)
            for code in (0, 1, -9, True, 3):
                with self.assertRaises(AssertionError): output.original_refusal(b'', actual, code, reason)
            for other in reasons:
                if other != reason:
                    with self.assertRaises(AssertionError): output.original_refusal(b'', actual, 2, other)
            for data in (b'', actual + b'FAILED\n', actual + b'\n', actual.replace(b'\n', b'\r\n'),
                         b'FAILED\n', actual[:-1], bytearray(actual)):
                with self.assertRaises(AssertionError): output.original_refusal(b'', data, 2, reason)
            with self.assertRaises(AssertionError): output.original_refusal(b'ORIGINAL_DONE,0,0,0\n', actual, 2, reason)
            with self.assertRaises(AssertionError): output.original_refusal(b'', actual, 2, 'unknown')

    def refuses(self, rows, args):
        with self.assertRaises((AssertionError, ValueError, UnicodeError, KeyError, IndexError)):
            check(rows, args)

    def test_complete_empty_closed_and_absolute_history_populations(self):
        for n, k, arms, prefix in ((0, 10, 1, 1), (13, 10, 1, 1), (2048, 1000, 520, 513)):
            rows, args = fixture(n, k, arms, prefix)
            result = check(rows, args)
            self.assertEqual(result['totals']['calls'], 2 * n)
            self.assertEqual(result['raw'], encode(rows))
            self.assertEqual(len(result['rows']['REPORT']), arms)

    def test_history_starts_at_one_and_preserves_multi_action_chunks(self):
        rows, args = fixture(1, 10, 520, 513)
        for width in (1, 8):
            grouped = copy.deepcopy(rows)
            for row in grouped:
                if row[0] == 'HISTORY':
                    row[1] = (row[2] - 1) // width + 1
            check(grouped, args)
            shifted = copy.deepcopy(grouped)
            for row in shifted:
                if row[0] == 'HISTORY':
                    row[1] -= 1
            self.refuses(shifted, args)
        oversized = copy.deepcopy(rows)
        for row in oversized:
            if row[0] == 'HISTORY':
                row[1] = (row[2] - 1) // 9 + 1
        self.refuses(oversized, args)

    def test_every_family_missing_duplicate_reorder_and_extra_refuses(self):
        rows, args = fixture()
        for tag in output.FIELDS:
            index = next(i for i, row in enumerate(rows) if row[0] == tag)
            for changed in (rows[:index] + rows[index + 1:], rows[:index] + [rows[index]] + rows[index:]):
                self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        calls = [i for i, row in enumerate(changed) if row[0] == 'CALL']
        changed[calls[0]], changed[calls[1]] = changed[calls[1]], changed[calls[0]]
        self.refuses(changed, args)
        self.refuses(rows + [['UNKNOWN', 0]], args)

    def test_scalar_input_fingerprint_and_complete_results_are_independent(self):
        rows, args = fixture()
        for tag, positions in (('RESULT', range(1, 8)), ('COVERAGE', range(1, 9))):
            index = next(i for i, row in enumerate(rows) if row[0] == tag)
            for position in positions:
                changed = copy.deepcopy(rows); changed[index][position] += 1
                self.refuses(changed, args)
        wrong = dict(args, records=((b'a,b', 3),) * 3)
        self.refuses(rows, wrong)

    def test_global_slots_function_ranks_closed_budget_and_report_order(self):
        rows, args = fixture(13)
        for tag, positions in (('CALL', (1, 2, 3, 5, 6, 7, 18)), ('SAMPLE', (1, 2, 3, 4, 5, 6, 7, 9)), ('REPORT', (1, 2))):
            index = next(i for i, row in enumerate(rows) if row[0] == tag)
            for position in positions:
                changed = copy.deepcopy(rows); changed[index][position] += 1
                self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        first = next(row for row in changed if row[0] == 'CALL')
        first[4], first[6] = 'closed', 0
        self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        sample_rows = [i for i, row in enumerate(changed) if row[0] == 'SAMPLE']
        changed[sample_rows[0]], changed[sample_rows[1]] = changed[sample_rows[1]], changed[sample_rows[0]]
        self.refuses(changed, args)

    def test_stack_continuation_ack_and_batch_boundaries(self):
        rows, args = fixture()
        index = next(i for i, row in enumerate(rows) if row[0] == 'CALL')
        for position, value in ((8, 35), (9, 8), (9, 120), (9, (1 << 64) - 1), (9, 4096), (10, 8210), (16, 0), (17, 0)):
            changed = copy.deepcopy(rows); changed[index][position] = value
            self.refuses(changed, args)
        changed = copy.deepcopy(rows)
        changed[index][15:18] = ['checkpoint', 0, 1]
        changed[index + 1][17] = 2
        self.refuses(changed, args)
        for value in (136, (1 << 64) - 24):
            changed = copy.deepcopy(rows)
            for row in changed:
                if row[0] == 'CALL': row[9] = value
            check(changed, args)

    def test_zero_maximum_and_raw_unavailable_are_retained(self):
        rows, args = fixture()
        for start, end, a, b, kind, value in ((0, 0, 0, 0, 'value', 0),
                (output.U64, output.U64, output.U32, output.U32, 'value', output.U64),
                (output.U64, 0, 0, 0, 'unavailable', 2), (0, output.U64, 0, 1, 'unavailable', 1)):
            changed = copy.deepcopy(rows)
            for row in changed:
                if row[0] == 'CALL': row[11:15] = [start, end, a, b]
                if row[0] == 'SAMPLE': row[7:10] = [start, kind, value]
            check(changed, args)
            for row in changed:
                if row[0] == 'SAMPLE': row[9] = (value + 1) & output.U64; break
            self.refuses(changed, args)

    def test_eof_typed_refusal_and_incomplete_are_distinct(self):
        for outcome, error in (('eof', 'none'), ('input_incomplete', 'none'),
                               ('input_error', 'syntax'), ('input_error', 'unterminated'), ('input_error', 'record_limit')):
            rows, args = fixture(outcome=outcome, error=error)
            check(rows, args)
            changed = copy.deepcopy(rows); changed[-1][1] = 'COMPLETE' if outcome != 'eof' else 'INPUT_REFUSED'
            self.refuses(changed, args)
            if error == 'unterminated':
                changed = copy.deepcopy(rows); changed[-1][14] = 0
                self.refuses(changed, args)
        rows, args = fixture()
        for position in range(3, 19):
            if position == 15: continue
            changed = copy.deepcopy(rows); changed[-1][position] += 1
            self.refuses(changed, args)

    def test_numeric_framing_actual_stderr_and_caps(self):
        rows, args = fixture()
        index = next(i for i, row in enumerate(rows) if row[0] == 'CALL')
        for bad in ('', '+1', '-1', '01', ' 1', '1 ', str(1 << 64), '١'):
            changed = copy.deepcopy(rows); changed[index][1] = bad
            with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                output.check(('\n'.join(','.join(map(str, row)) for row in changed) + '\n').encode(), b'', **args)
        data = encode(rows)
        for malformed in (data[:-1], data + b'\n', data.replace(b'\n', b'\r\n'), b'x' * (output.CAP + 1)):
            with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                output.check(malformed, b'', **args)
        with self.assertRaises(AssertionError): output.check(data, b'real stderr', **args)

    def test_actual_stderr_requires_exact_finalized_outcome_and_no_hard_diagnostic(self):
        outcomes = (
            ('eof', 'none', b''),
            ('input_incomplete', 'none', b'normal-module-session INPUT_INCOMPLETE\n'),
            ('input_error', 'syntax', b'normal-module-session INPUT_REFUSED: syntax\n'),
            ('input_error', 'overlong', b'normal-module-session INPUT_REFUSED: overlong\n'),
            ('input_error', 'unterminated', b'normal-module-session INPUT_REFUSED: unterminated\n'),
            ('input_error', 'record_limit', b'normal-module-session INPUT_REFUSED: record_limit\n'),
        )
        hard = b'normal-module-session FAILED: final-output; task retirement pending\n'
        for outcome, error, stderr in outcomes:
            rows, args = fixture(outcome=outcome, error=error)
            data = encode(rows)
            self.assertEqual(output.check(data, stderr, **args)['raw'], data)
            wrong = [other for _, _, other in outcomes if other != stderr]
            wrong += [stderr + hard, hard + stderr, stderr + b'\n', b' ' + stderr,
                      stderr + b'\xff', stderr.decode('ascii'), bytearray(stderr)]
            if stderr:
                wrong += [stderr[:-1], stderr.replace(b'\n', b'\r\n')]
            for actual in wrong:
                with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                    output.check(data, actual, **args)
            if outcome == 'input_error':
                # Coherent transcript+diagnostic changes still cannot change the
                # independently frozen expected reason passed by the producer.
                changed = copy.deepcopy(rows)
                other = 'overlong' if error == 'syntax' else 'syntax'
                changed[-1][15] = other
                actual = ('normal-module-session INPUT_REFUSED: ' + other + '\n').encode('ascii')
                with self.assertRaises(AssertionError):
                    output.check(encode(changed), actual, **args)
        original = encode([
            ['ORIGINAL_READY', 'module-original-v1', 9, 9, 4, 4096, 4133, 4160, 4201, 8192, 0],
            ['ORIGINAL_DONE', 0, 0, 0],
        ])
        output.original_check(original, b'', records=(), lengths=(37, 41), cpu=4)
        for actual in [hard] + [stderr for _, _, stderr in outcomes if stderr]:
            with self.assertRaises(AssertionError):
                output.original_check(original, actual, records=(), lengths=(37, 41), cpu=4)

    def test_original_reference_uses_all_values_and_exact_population(self):
        records = ((b'', 1), (b'a,b', 2))
        rows = [['ORIGINAL_READY', 'module-original-v1', 9, 9, 4, 4096, 4133, 4160, 4201, 8192, 2]]
        rows += [['ORIGINAL', i, len(data), output.fnv(data), count, len(data)] for i, (data, count) in enumerate(records, 1)]
        rows += [['ORIGINAL_DONE', 2, 4, 4]]
        output.original_check(encode(rows), b'', records=records, lengths=(37, 41), cpu=4)
        for index, positions in ((0, (2, 3, 4, 5, 6, 7, 8, 10)), (1, range(1, 6)), (3, range(1, 4))):
            for position in positions:
                changed = copy.deepcopy(rows); changed[index][position] += 1
                with self.assertRaises(AssertionError):
                    output.original_check(encode(changed), b'', records=records, lengths=(37, 41), cpu=4)

    def test_fixed_catalog_has_exact_special_inputs_and_error_classes(self):
        corpus = load('corpus')
        cases = [produce.case_spec(corpus, i) for i in range(32)]
        self.assertEqual(len({case['name'] for case in cases}), 32)
        self.assertEqual([case['input_error'] for case in cases[4:25]], ['syntax'] * 16 + ['overlong'] * 2 + ['unterminated'] * 3)
        self.assertEqual(cases[30]['records'], corpus.LITERALS * 3)
        self.assertEqual(len(cases[31]['records']), 2048)
        self.assertTrue(all(r.payload == b'x' * 64 and r.fields == 1 for r in cases[31]['records']))
        self.assertEqual([i for i, case in enumerate(cases) if not case['close']], [27, 28, 29])

    def test_optimization_refuses_before_production_checks(self):
        for name in ('output.py', 'produce.py', 'controls.py'):
            run = subprocess.run([sys.executable, '-O', '-B', str(Path(__file__).with_name(name))],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(run.stdout, b'')
            self.assertEqual(run.stderr, b'assertions required\n')


if __name__ == '__main__':
    unittest.main()
