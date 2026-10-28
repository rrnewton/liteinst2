#!/usr/bin/env python3
"""Fabricated batch protocol controls; no native subject or runtime evidence."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import copy
import importlib.util
import itertools
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve()
MODULE = SCRIPT.with_name('check_batch.py')
if not MODULE.is_file():
    raise SystemExit('missing sibling check_batch.py')
SPEC = importlib.util.spec_from_file_location('tree_batch_check', MODULE)
assert SPEC is not None and SPEC.loader is not None and Path(SPEC.origin).resolve() == MODULE
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
assert Path(CHECK.__file__).resolve() == MODULE

HEADER = ('seed,case,status,children,calls_per_child,full_indices,comparisons,original_visits,'
    'original_steps,candidate_steps,selected0_original_steps,selected0_candidate_steps,'
    'selected7_original_steps,selected7_candidate_steps,hardware_stops_original,'
    'hardware_stops_candidate,tree_transfers,outer_calls,outer_returns,normal_reaps,'
    'source_attested_finishes,candidate_rows,candidate_events,candidate_report_records,value')
FIELDS = tuple(HEADER.split(','))
TERMINAL = ('native-tree-batch:required=4:pairs=4:children=8:roots=64:selected-call-pairs=8:'
    'comparisons=2744:tree-transfers=192:outer-calls=64:outer-returns=64:hardware-stops=304:'
    'source-attested-finishes=8:candidate-rows=64:candidate-events=128:'
    'candidate-report-records=64:selected=0+7:middle=functional-only:complete\n').encode('ascii')
# Literal scalar fixtures from the existing independent population controls,
# arranged seed-major and with the actual caller's wrapping+1 already applied.
VALUES = ((13455538007910626262, 18114441086748040058),
          (14448916110156114966, 6122101979721109698))
NAMES = (
    'oracle::native_ordinary::tree_batch::tests::batch_armed_all_fields_and_retained_lifetime_refuse_corruption',
    'oracle::native_ordinary::tree_batch::tests::batch_checkpoint_exact_idle_refuses_missing_or_early_return',
    'oracle::native_ordinary::tree_batch::tests::batch_checkpoint_requires_exact_self_thread_signal',
    'oracle::native_ordinary::tree_batch::tests::batch_outer_call_checks_actual_instruction_successor_word_and_rf',
)


def controls(names=NAMES):
    return ('\nrunning 4 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in names)
        + '\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 91 filtered out; finished in 0.01s\n\n').encode('ascii')


def rows():
    result = []
    for s, seed in enumerate((0x1234567887654320, 0xfedcba9801234567)):
        for c, case in enumerate(('fit2', 'conflict3')):
            result.append(dict(seed=seed, case=case, status='PASS', children=2,
                calls_per_child=8, full_indices='0+7', comparisons=686, original_visits=664,
                original_steps=716, candidate_steps=8030, selected0_original_steps=343,
                selected0_candidate_steps=4000, selected7_original_steps=343,
                selected7_candidate_steps=4000, hardware_stops_original=38,
                hardware_stops_candidate=38, tree_transfers=48, outer_calls=16,
                outer_returns=16, normal_reaps=2, source_attested_finishes=2,
                candidate_rows=16, candidate_events=32, candidate_report_records=16,
                value=VALUES[s][c]))
    return result


def encode(source):
    return ('\n'.join([HEADER] + [','.join(str(row[key]) for key in FIELDS) for row in source]) + '\n').encode('ascii')


class BatchProtocol(unittest.TestCase):
    def accept(self, source):
        return CHECK.parse(encode(source), TERMINAL, b'')

    def refuse_bytes(self, data, terminal=TERMINAL, stderr=b''):
        with self.assertRaises((AssertionError, ValueError, UnicodeError)):
            CHECK.parse(data, terminal, stderr)

    def refuse(self, source):
        self.refuse_bytes(encode(source))

    def test_complete_population_and_candidate_step_boundaries(self):
        good = rows()
        got = self.accept(good)
        self.assertEqual(got['rows'], good)
        self.assertEqual(got['summary'], dict(status='PASS', pairs=4, children=8, roots=64,
            selected_call_pairs=8, comparisons=2744, selected_original_visits=2656,
            tree_transfers=192, outer_calls=64, outer_returns=64, hardware_stops=304,
            normal_reaps=8, source_attested_finishes=8, candidate_rows=64, candidate_events=128,
            candidate_report_records=64, full_indices=[0, 7], middle='functional-only'))
        self.assertIn('child-source assertions', got['source_attested'])
        self.assertIn('six middle calls', got['scope'])
        for first, last in ((343, 343), (343, 19627), (19627, 343)):
            changed = copy.deepcopy(good)
            for row in changed:
                row.update(selected0_candidate_steps=first, selected7_candidate_steps=last,
                    candidate_steps=first + last + 30)
            self.accept(changed)

    def test_every_field_of_every_row_is_required(self):
        good = rows()
        self.accept(good)
        for index in range(4):
            for field in FIELDS:
                changed = copy.deepcopy(good)
                old = changed[index][field]
                changed[index][field] = old + 1 if type(old) is int else old + 'x'
                self.refuse(changed)

    def test_step_counts_bounds_and_exact_continuous_join(self):
        good = rows()
        self.accept(good)
        steps = ('original_steps', 'candidate_steps', 'selected0_original_steps',
            'selected0_candidate_steps', 'selected7_original_steps', 'selected7_candidate_steps')
        for index in range(4):
            for field in steps:
                for bad in (0, 342, 20001):
                    changed = copy.deepcopy(good)
                    changed[index][field] = bad
                    self.refuse(changed)
            # Preserve sums while violating the original exact343 or candidate
            # comparison floor. Aggregate consistency alone is insufficient.
            for side in ('original', 'candidate'):
                changed = copy.deepcopy(good)
                changed[index]['selected0_' + side + '_steps'] = 342
                changed[index][side + '_steps'] = 342 + changed[index]['selected7_' + side + '_steps'] + 30
                self.refuse(changed)
            changed = copy.deepcopy(good)
            changed[index]['selected0_original_steps'] = 344
            changed[index]['original_steps'] = 717
            self.refuse(changed)
            for extra in (-1, 1):
                changed = copy.deepcopy(good)
                changed[index]['candidate_steps'] += extra
                self.refuse(changed)
        changed = copy.deepcopy(good)
        changed[0]['selected7_candidate_steps'] = 16000
        changed[0]['candidate_steps'] = 20030
        self.refuse(changed)

    def test_missing_duplicate_substituted_and_reordered_population(self):
        good = rows()
        self.accept(good)
        for index in range(4):
            self.refuse(good[:index] + good[index + 1:])
            self.refuse(good[:index] + [good[index]] + good[index:])
            changed = copy.deepcopy(good)
            changed[index] = copy.deepcopy(good[(index + 1) % 4])
            self.refuse(changed)
        for order in ([1, 0, 2, 3], [2, 3, 0, 1], [3, 2, 1, 0]):
            self.refuse([good[index] for index in order])
        changed = copy.deepcopy(good)
        changed[0]['comparisons'] += 1
        changed[1]['comparisons'] -= 1
        self.refuse(changed)

    def test_every_numeric_field_requires_canonical_u64(self):
        good = rows()
        self.accept(good)
        for index in range(4):
            for field in FIELDS:
                if type(good[index][field]) is not int:
                    continue
                for bad in ('', '-1', '+1', '01', '1.0', '1e0', ' 1', '1 ', '0x1', str(2**64), '9' * 100):
                    changed = copy.deepcopy(good)
                    changed[index][field] = bad
                    self.refuse(changed)

    def test_exact_ascii_lf_header_and_column_grammar(self):
        data = encode(rows())
        CHECK.parse(data, TERMINAL, b'')
        for bad in (b'', data[:-1], data + b'\n', data + b'extra\n', b'\n' + data,
                data.replace(b'\n', b'\r\n'), data.replace(b'PASS', b'"PASS"', 1),
                data.replace(b'PASS', b'PASS\x00', 1), data.replace(b'PASS', b'PASS\xff', 1),
                data.replace(b'PASS', b'PASS\t', 1), b'x' * 1048577):
            self.refuse_bytes(bad)
        for name in FIELDS:
            self.refuse_bytes(data.replace(name.encode('ascii'), (name + 'x').encode('ascii'), 1))
        lines = data.split(b'\n')
        for row in range(1, 5):
            words = lines[row].split(b',')
            for column in range(25):
                for replacement in (words[:column] + words[column + 1:], words[:column] + [words[column]] + words[column:]):
                    changed = lines.copy()
                    changed[row] = b','.join(replacement)
                    self.refuse_bytes(b'\n'.join(changed))
            for separator in (b'\x0b', b'\x0c', b'\x1c', b'\x1d', b'\x1e'):
                self.refuse_bytes(b'\n'.join(lines[:row]) + separator + b'\n'.join(lines[row:]))
        for args in ((data.decode('ascii'), TERMINAL, b''), (data, TERMINAL.decode('ascii'), b''),
                (data, TERMINAL, ''), (bytearray(data), TERMINAL, b'')):
            with self.assertRaises(AssertionError):
                CHECK.parse(*args)

    def test_entire_terminal_and_empty_stderr(self):
        data = encode(rows())
        CHECK.parse(data, TERMINAL, b'')
        for length in range(len(TERMINAL)):
            self.refuse_bytes(data, TERMINAL[:length])
        for index, byte in enumerate(TERMINAL):
            self.refuse_bytes(data, TERMINAL[:index] + bytes([byte ^ 1]) + TERMINAL[index + 1:])
        for bad in (TERMINAL + b'\n', TERMINAL + b'extra', TERMINAL.replace(b'\n', b'\r\n'),
                TERMINAL.replace(b'functional-only', b'full-state')):
            self.refuse_bytes(data, bad)
        for stderr in (b'\n', b'warning\n', b'error\n'):
            self.refuse_bytes(data, stderr=stderr)

    def test_four_named_controls_without_completion_order_assumption(self):
        for order in itertools.permutations(NAMES):
            got = CHECK.parse_controls(controls(order), b'')
            self.assertEqual((got['status'], got['passed'], got['failed'], got['ignored'],
                got['measured'], got['filtered'], got['tests']),
                ('PASS', 4, 0, 0, 0, 91, sorted(NAMES)))

    def test_control_omissions_duplicates_names_counts_and_failure_refuse(self):
        good = controls()
        CHECK.parse_controls(good, b'')
        bad_outputs = [b'', good[:-1], good + b'\n', good.replace(b'\n', b'\r\n'),
            good.replace(b'\n', b'\x0b', 1), good + b'extra\n', good.replace(b' ok\n', b' FAILED\n', 1),
            good.replace(b' ok\n', b' ignored\n', 1), good.replace(b'test result: ok.', b'test result: FAILED.')]
        for index in range(4):
            bad_outputs.append(controls(NAMES[:index] + NAMES[index + 1:]))
            bad_outputs.append(controls(NAMES[:index] + (NAMES[index],) + NAMES[index:]))
            names = list(NAMES)
            names[index] = NAMES[(index + 1) % 4]
            bad_outputs.append(controls(names))
            bad_outputs.append(good.replace(NAMES[index].encode('ascii'), b'other::test', 1))
        for before, after in ((b'running 4 tests', b'running 3 tests'), (b'running 4 tests', b'running 5 tests'),
                (b'4 passed', b'3 passed'), (b'4 passed', b'5 passed'), (b'0 failed', b'1 failed'),
                (b'0 ignored', b'1 ignored'), (b'0 measured', b'1 measured'),
                (b'91 filtered', b'90 filtered'), (b'91 filtered', b'92 filtered'),
                (b'4 passed', b'04 passed'), (b'0.01s', b'00.01s')):
            bad_outputs.append(good.replace(before, after))
        for bad in bad_outputs:
            with self.assertRaises(AssertionError):
                CHECK.parse_controls(bad, b'')
        for stderr in (b'\n', b'warning\n'):
            with self.assertRaises(AssertionError):
                CHECK.parse_controls(good, stderr)
        for args in ((good.decode('ascii'), b''), (good, ''), (bytearray(good), b'')):
            with self.assertRaises(AssertionError):
                CHECK.parse_controls(*args)

    def test_exact_sibling_import_and_early_optimization_refusal(self):
        self.assertEqual(Path(CHECK.__file__).resolve(), MODULE)
        case = 'BatchProtocol.test_complete_population_and_candidate_step_boundaries'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'check_batch.py').write_text('raise RuntimeError("wrong cwd import")\n', encoding='ascii')
            env = dict(os.environ, PYTHONPATH=temporary)
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), case], cwd=path,
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'Ran 1 test', result.stderr)
            self.assertTrue(result.stderr.endswith(b'OK\n'))
            missing = path / 'missing'
            missing.mkdir()
            copied = missing / SCRIPT.name
            copied.write_bytes(SCRIPT.read_bytes())
            result = subprocess.run([sys.executable, '-B', str(copied), case], cwd=path,
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                (1, b'', b'missing sibling check_batch.py\n'))
            for flag in ('-O', '-OO'):
                for script in (MODULE, SCRIPT, copied):
                    result = subprocess.run([sys.executable, '-B', flag, str(script)], cwd=path,
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                        (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
