#!/usr/bin/env python3
"""Corrupt the actual reference output parser, without running native subjects."""
import csv
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('reference_check', Path(__file__).with_name('check_output.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def encode(rows, header):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=header.split(','), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('ascii')


def pair_rows():
    return [dict(seed=seed, length=n, status='PASS', children=2, comparisons=6*n+23,
        original_visits=6*n+5, original_steps=6*n+100, candidate_steps=6*n+500,
        reader_checks=4, timestamp_joins=4, returned_records=2,
        value=sum(((((128+j)*37+11+seed) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15)
        for seed in CHECK.SEEDS for n in (1, 64)]


def call_rows():
    rows = []
    for position in range(48):
        original, index = position < 24, position % 24
        n = 1 if index % 2 == 0 else 64
        start = 1000000+position*1000
        row = dict(leg='original' if original else 'installed', external_id=0x72656600+index,
            gate_sequence=73+position, ordinal=index+1, length=n, owner='original' if original else 'sampled',
            generation=3, invocation=index, instructions=6*n+5, branches=n, taken_branches=n-1,
            input_byte_reads=n, return_read_bytes=8,
            value=sum((((j*37+11) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15,
            reference_start_ticks=start, reference_end_ticks=start+400, reference_start_aux=9, reference_end_aux=9,
            raw_start_ticks=start+100, raw_end_ticks=start+300, raw_start_aux=9, raw_end_aux=9,
            enclosure_ticks=400, raw_ticks=200, entry_gap_ticks=100, return_gap_ticks=100)
        if original:
            row.update({key: '' for key in CHECK.ORIGINAL_EMPTY})
        rows.append(row)
    return rows


def client_bytes(rows):
    return CHECK.SCOPE.encode('ascii')+b'\n'+encode(rows, CHECK.HEADER)+CHECK.PASS.encode('ascii')+b'\n'


class NativeProjection(unittest.TestCase):
    def test_full_calibration_population_no_ignored_or_duplicate_names(self):
        data = ('\nrunning 43 tests\n'+''.join(f'test oracle::control_{i} ... ok\n' for i in range(43))+
            '\ntest result: ok. 43 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n').encode('ascii')
        CHECK.calibrations(data, b'')
        for bad in (data[:-1], data+b'\n', data.replace(b'control_1 ', b'control_0 '),
                    data.replace(b'43 passed', b'42 passed'), data.replace(b'0 ignored', b'1 ignored'),
                    data.replace(b'control_1 ... ok', b'control_1 ... ignored')):
            with self.assertRaises(AssertionError):
                CHECK.calibrations(bad, b'')
        with self.assertRaises(AssertionError):
            CHECK.calibrations(data, b'warning\n')

    def test_complete_population_and_each_bound_identity_and_count(self):
        rows = pair_rows()
        terminal = CHECK.PAIR_PASS.encode('ascii')
        valid = encode(rows, CHECK.PAIR_HEADER)
        self.assertEqual(len(CHECK.pairs(valid, terminal, b'')), 4)
        for key in rows[0]:
            if key in ('original_steps', 'candidate_steps'):
                values = (0, rows[0]['comparisons']-1, 20001, 2**64)
            elif key == 'status':
                values = ('FAIL', 'UNRUN')
            else:
                values = (rows[0][key]+1, '01', '-1', 2**64)
            for value in values:
                bad = [dict(row) for row in rows]
                bad[0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(AssertionError):
                    CHECK.pairs(encode(bad, CHECK.PAIR_HEADER), terminal, b'')
        for bad in (rows[:3], rows+rows[:1], [rows[1], rows[0], *rows[2:]]):
            with self.assertRaises(AssertionError):
                CHECK.pairs(encode(bad, CHECK.PAIR_HEADER), terminal, b'')
        for bad in (valid[:-1], valid+b'\n', valid.replace(b'\n', b'\r\n'), valid.replace(b',PASS,', b',PASS,EXTRA,', 1)):
            with self.assertRaises(AssertionError):
                CHECK.pairs(bad, terminal, b'')
        for bad in (terminal[:-1], terminal+b'\n', terminal.replace(b'872', b'871'), terminal.replace(b'complete', b'partial')):
            with self.assertRaises(AssertionError):
                CHECK.pairs(valid, bad, b'')
        with self.assertRaises(AssertionError):
            CHECK.pairs(valid, terminal, b'warning\n')


class ClientProjection(unittest.TestCase):
    def test_all_rows_and_corrupted_columns_in_each_leg(self):
        rows = call_rows()
        parsed, csv_bytes = CHECK.functional(client_bytes(rows), b'')
        self.assertEqual(len(parsed), 48)
        self.assertEqual(csv_bytes, encode(rows, CHECK.HEADER))
        for index in (0, 24):
            for key, value in rows[index].items():
                bad = [dict(row) for row in rows]
                bad[index][key] = value+1 if isinstance(value, int) else 'wrong' if value else '0'
                with self.subTest(index=index, key=key), self.assertRaises(AssertionError):
                    CHECK.functional(client_bytes(bad), b'')
        for bad in (rows[:47], rows+rows[:1], [rows[1], rows[0], *rows[2:]], rows[24:]+rows[:24]):
            with self.assertRaises(AssertionError):
                CHECK.functional(client_bytes(bad), b'')

    def test_containment_aux_arithmetic_overflow_and_serial_identity(self):
        rows = call_rows()
        for changes in (
            {'raw_start_ticks': rows[24]['reference_start_ticks']-1},
            {'raw_end_ticks': rows[24]['reference_end_ticks']+1},
            {'raw_start_ticks': rows[24]['raw_end_ticks']+1},
            {'reference_end_ticks': rows[24]['reference_start_ticks']-1},
            {'reference_start_aux': 2**32, 'reference_end_aux': 2**32, 'raw_start_aux': 2**32, 'raw_end_aux': 2**32},
            {'gate_sequence': rows[0]['gate_sequence']},
            {'external_id': rows[25]['external_id']},
            {'generation': 0}, {'invocation': 24}, {'enclosure_ticks': 2**64},
        ):
            bad = [dict(row) for row in rows]
            bad[24].update(changes)
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                CHECK.functional(client_bytes(bad), b'')
        for key in ('gate_sequence', 'reference_start_ticks', 'enclosure_ticks'):
            for value in ('01', '-1', ' 1', 2**64):
                bad = [dict(row) for row in rows]
                bad[0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(AssertionError):
                    CHECK.functional(client_bytes(bad), b'')

    def test_exact_protocol_and_no_fabricated_original_hook_fields(self):
        data = client_bytes(call_rows())
        for bad in (data[:-1], data+b'\n', data.replace(b'\n', b'\r\n'),
                    data.replace(b'FUNCTIONAL_PASS', b'ACCURACY_PASS'), data.replace(b'originals=24', b'originals=23'),
                    data.replace(b'uncalibrated=true', b'uncalibrated=false')):
            with self.assertRaises(AssertionError):
                CHECK.functional(bad, b'')
        with self.assertRaises(AssertionError):
            CHECK.functional(data, b'warning\n')

    def test_chronology_spans_legs_and_equal_endpoints_remain_valid(self):
        for index in (1, 24, 25):
            rows = call_rows()
            for key in ('reference_start_ticks', 'reference_end_ticks', 'raw_start_ticks', 'raw_end_ticks'):
                if rows[index][key] != '':
                    rows[index][key] -= 1001
            with self.subTest(index=index), self.assertRaises(AssertionError):
                CHECK.functional(client_bytes(rows), b'')
        rows = call_rows()
        for index in (0, 24):
            start = rows[index]['reference_start_ticks']
            rows[index]['reference_end_ticks'] = start
            rows[index]['enclosure_ticks'] = 0
            if index == 24:
                rows[index].update(raw_start_ticks=start, raw_end_ticks=start, raw_ticks=0, entry_gap_ticks=0, return_gap_ticks=0)
        self.assertEqual(len(CHECK.functional(client_bytes(rows), b'')[0]), 48)


class RecipeAdmission(unittest.TestCase):
    def test_reference_requires_all_prior_modes_before_creating_output(self):
        repo = Path(__file__).resolve().parents[3]
        script = repo/'tools/rapid-profiler/verify_ordinary_interval.py'
        with tempfile.TemporaryDirectory(prefix='reference-parser-', dir=repo/'ignored') as temporary:
            raw = Path(temporary)/'must-not-exist'
            argv = [sys.executable, '-B', str(script), '--revision', '0'*40, '--raw', str(raw),
                '--toolchain', str(repo), '--user-home', str(repo), '--cargo-home', str(repo)]
            for flags in (['--reference-timing'], ['--exact-work', '--concurrent-epochs', '--retire-epochs',
                    '--drain-completed', '--streamed-epochs', '--stream-history', '--optional-frontend', '--reference-timing']):
                result = subprocess.run([*argv, *flags], capture_output=True, timeout=10, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'assert not a.reference_timing or a.optional_backoff_control', result.stderr)
                self.assertFalse(raw.exists())

    def test_optimized_recipe_refuses_before_argument_or_output_work(self):
        script = Path(__file__).resolve().parents[1]/'verify_ordinary_interval.py'
        for optimization in ('-O', '-OO'):
            result = subprocess.run([sys.executable, optimization, '-B', str(script)], capture_output=True, timeout=10, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b'assertions required\n')


if __name__ == '__main__':
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    unittest.main()
