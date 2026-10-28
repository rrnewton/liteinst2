#!/usr/bin/env python3
"""Fabricated protocol mutations through the actual parser, not native evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
from pathlib import Path
import subprocess
import unittest
import exact_native as check


# Literal positive expectations, not obtained from the parser's algebra.
HEADER = ('seed,length,status,children,comparisons,visits0,visits1,original_steps,'
    'candidate_steps,value0,value1,outer_value,instructions,conditional_branches,'
    'taken_branches,input_reads,return_reads,return_read_bytes,ret_offset0,'
    'ret_offset1,target_calls,target_returns,outer_returns,normal_reaps')
TERMINAL = (
    b'native-normal-exact:selection=normal-exact-37-v1:required=4:pairs=4:children=8:'
    b'comparisons=1696:instructions=1600:conditional=260:taken=252:input-reads=260:'
    b'return-reads=8:return-read-bytes=64:target-calls=16:target-returns=16:'
    b'real-outer-ret=8:normal-reaps=8:complete\n')


def fixture():
    return [list(map(str, row)) for row in (
        (1311768467139281696, 1, 'PASS', 2, 46, 11, 11, 47, 48,
         11400714819323198532, 11400714819323198532, 4354685564936845448,
         22, 2, 0, 2, 2, 16, 36, 36, 4, 4, 2, 2),
        (1311768467139281696, 64, 'PASS', 2, 802, 389, 389, 803, 804,
         11400714819323190453, 11400714819323190453, 4354685564936829290,
         778, 128, 126, 128, 2, 16, 36, 36, 4, 4, 2, 2),
        (18364758542526924135, 1, 'PASS', 2, 46, 11, 11, 47, 48,
         11400714819323198531, 11400714819323198531, 4354685564936845446,
         22, 2, 0, 2, 2, 16, 36, 36, 4, 4, 2, 2),
        (18364758542526924135, 64, 'PASS', 2, 802, 389, 389, 803, 804,
         11400714819323190389, 11400714819323190389, 4354685564936829162,
         778, 128, 126, 128, 2, 16, 36, 36, 4, 4, 2, 2),
    )]


def encode(rows, header=HEADER):
    return (header+'\n'+''.join(','.join(row)+'\n' for row in rows)).encode('ascii')


class Controls(unittest.TestCase):
    def refuse(self, rows, stdout=TERMINAL, stderr=b''):
        with self.assertRaises(AssertionError): check.check(encode(rows), stdout, stderr)

    def test_complete_population_and_independent_scalar_work_totals(self):
        got = check.check(encode(fixture()), TERMINAL, b'')
        self.assertEqual((got['status'], got['selection'], got['pairs']),
                         ('FUNCTIONAL_PASS', 'normal-exact-37-v1', 4))
        self.assertEqual(tuple(got[k] for k in ('children', 'comparisons', 'instructions',
            'conditional_branches', 'taken_branches', 'input_reads', 'return_reads',
            'return_read_bytes', 'target_calls', 'target_returns', 'outer_returns', 'normal_reaps')),
            (8, 1696, 1600, 260, 252, 260, 8, 64, 16, 16, 8, 8))
        self.assertEqual((got['original_steps'], got['candidate_steps']), (1700, 1704))
        self.assertEqual([r['value0'] for r in got['rows']], [11400714819323198532,
            11400714819323190453, 11400714819323198531, 11400714819323190389])
        self.assertEqual([r['outer_value'] for r in got['rows']], [4354685564936845448,
            4354685564936829290, 4354685564936845446, 4354685564936829162])
        self.assertTrue(all(type(v) is int for row in got['rows']
                            for key, v in row.items() if key != 'status'))

    def test_every_row_field_is_authenticated(self):
        for index, row in enumerate(fixture()):
            for field, value in enumerate(row):
                bad = fixture()
                bad[index][field] = 'FAILED' if field == 2 else (
                    '20001' if field in (7, 8) else str(int(value)+1))
                with self.subTest(row=index, field=field): self.refuse(bad)

    def test_step_bounds_are_inclusive_for_each_child_and_pair(self):
        for upper in (False, True):
            rows = fixture()
            for row in rows: row[7] = row[8] = '20000' if upper else row[4]
            got = check.check(encode(rows), TERMINAL, b'')
            self.assertEqual(got['original_steps'], 80000 if upper else 1696)
            self.assertEqual(got['candidate_steps'], 80000 if upper else 1696)
        for index in range(4):
            for field in (7, 8):
                for value in (str(int(fixture()[index][4])-1), '20001'):
                    rows = fixture(); rows[index][field] = value
                    with self.subTest(row=index, field=field, value=value): self.refuse(rows)

    def test_complete_order_header_and_column_shape_are_required(self):
        rows = fixture()
        for index in range(4):
            self.refuse(rows[:index]+rows[index+1:])
            self.refuse(rows[:index]+[rows[index]]+rows[index:])
            for other in range(index+1, 4):
                bad = fixture(); bad[index], bad[other] = bad[other], bad[index]
                self.refuse(bad)
            self.refuse(rows[:index]+[rows[index][:-1]]+rows[index+1:])
            self.refuse(rows[:index]+[rows[index]+['0']]+rows[index+1:])
            for field in range(24):
                bad = fixture(); bad[index][field] = ''; self.refuse(bad)
        for header in ('', HEADER+',extra', HEADER.replace('seed,', 'length,', 1),
                       HEADER.replace('visits0,visits1', 'visits1,visits0')):
            with self.assertRaises(AssertionError): check.check(encode(rows, header), TERMINAL, b'')
        data = encode(rows)
        for bad in (data.split(b'\n', 1)[1], data+b'\n', data+b'extra\n'):
            with self.assertRaises(AssertionError): check.check(bad, TERMINAL, b'')

    def test_all_numeric_cells_require_canonical_u64(self):
        self.assertEqual(check._u64('0'), 0)
        self.assertEqual(check._u64('18446744073709551615'), (1 << 64)-1)
        invalid = ('00', '+1', '-1', '1.0', ' 1', '1 ', '1e0', '18446744073709551616', '9'*21)
        for index in range(4):
            for field in range(24):
                if field == 2: continue
                for value in invalid:
                    rows = fixture(); rows[index][field] = value
                    with self.subTest(row=index, field=field, value=value): self.refuse(rows)

    def test_exact_ascii_lf_types_and_byte_caps(self):
        data = encode(fixture())
        for position, byte in enumerate(data):
            if byte != 10: continue
            for separator in (b'\r\n', b'\r', b'\v', b'\f'):
                bad = data[:position]+separator+data[position+1:]
                with self.assertRaises(AssertionError): check.check(bad, TERMINAL, b'')
        for bad in (b'', data[:-1], data+b'\xff', data.replace(b'PASS', b'PA\tSS', 1),
                    data.replace(b',1,', b',"1",', 1), b'x'*(check.CSV_CAP+1),
                    data.decode('ascii'), bytearray(data), None):
            with self.assertRaises(AssertionError): check.check(bad, TERMINAL, b'')
        for bad in (b'x'*(check.STDOUT_CAP+1), TERMINAL.decode('ascii'), bytearray(TERMINAL), None):
            with self.assertRaises(AssertionError): check.check(data, bad, b'')

    def test_exact_terminal_fields_and_empty_stderr(self):
        pieces = TERMINAL[:-1].split(b':')
        for index, piece in enumerate(pieces):
            if b'=' in piece:
                name, value = piece.split(b'=', 1)
                replacement = name+b'='+((str(int(value)+1).encode('ascii'))
                    if value.isdigit() else value+b'!')
            else: replacement = piece+b'!'
            bad = pieces[:]; bad[index] = replacement
            self.refuse(fixture(), b':'.join(bad)+b'\n')
            self.refuse(fixture(), b':'.join(pieces[:index]+pieces[index+1:])+b'\n')
            self.refuse(fixture(), b':'.join(pieces[:index]+[piece]+pieces[index:])+b'\n')
        for bad in (b'', TERMINAL[:-1], TERMINAL+b'\n', TERMINAL.replace(b'\n', b'\r\n'), b'prefix\n'+TERMINAL):
            self.refuse(fixture(), bad)
        for bad in (b'\n', b' ', b'warning\n', '', bytearray(), None):
            self.refuse(fixture(), stderr=bad)

    def test_coherent_wrong_truth_and_optimized_entrypoints_refuse(self):
        rows = fixture()
        for row in rows:
            for field in (4, 12): row[field] = str(int(row[field])+2)
            for field in (5, 6): row[field] = str(int(row[field])+1)
            row[7], row[8] = str(int(row[4])+1), str(int(row[4])+2)
        terminal = TERMINAL.replace(b'comparisons=1696', b'comparisons=1704').replace(
            b'instructions=1600', b'instructions=1608')
        self.refuse(rows, terminal)
        rows = fixture(); rows[0][9:12], rows[2][9:12] = rows[2][9:12], rows[0][9:12]
        self.refuse(rows)
        for name in ('exact_native.py', Path(__file__).name):
            process = subprocess.run([sys.executable, '-B', '-O', str(Path(__file__).with_name(name))],
                capture_output=True, timeout=5, check=False)
            self.assertEqual((process.returncode, process.stdout, process.stderr),
                             (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
