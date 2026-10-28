#!/usr/bin/env python3
"""Fabricated reference protocol controls; no native witness or timing credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
from pathlib import Path
import subprocess
import unittest
import reference_native as check

HEADER = ('seed,length,status,children,comparisons,visits0,visits1,original_steps,'
    'candidate_steps,value0,value1,outer_value,instructions,conditional_branches,'
    'taken_branches,input_reads,return_reads,return_read_bytes,ret_offset0,'
    'ret_offset1,target_calls,target_returns,outer_returns,normal_reaps,reader_checks,'
    'output_stores,helper_heads,interior_heads,returned_cells,'
    'original0_start_ticks,original0_start_aux,original0_end_ticks,original0_end_aux,'
    'original1_start_ticks,original1_start_aux,original1_end_ticks,original1_end_aux,'
    'candidate0_start_ticks,candidate0_start_aux,candidate0_end_ticks,candidate0_end_aux,'
    'candidate1_start_ticks,candidate1_start_aux,candidate1_end_ticks,candidate1_end_aux')
TERMINAL = (
    b'native-normal-reference:selection=normal-reference-exact-37-v1:required=4:pairs=4:children=8:'
    b'comparisons=1736:instructions=1600:conditional=260:taken=252:input-reads=260:'
    b'return-reads=8:return-read-bytes=64:target-calls=16:target-returns=16:'
    b'real-outer-ret=8:normal-reaps=8:reader-checks=32:output-stores=96:'
    b'helper-heads=640:interior-heads=368:returned-cells=16:complete\n')


def fixture():
    # Literal scalar/count expectations, independent of the parser's algebra.
    rows = (
        (1311768467139281696, 1, 'PASS', 2, 56, 11, 11, 102, 103,
         11400714819323198532, 11400714819323198532, 4354685564936845448,
         22, 2, 0, 2, 2, 16, 36, 36, 4, 4, 2, 2, 8, 24, 160, 92, 4),
        (1311768467139281696, 64, 'PASS', 2, 812, 389, 389, 858, 859,
         11400714819323190453, 11400714819323190453, 4354685564936829290,
         778, 128, 126, 128, 2, 16, 36, 36, 4, 4, 2, 2, 8, 24, 160, 92, 4),
        (18364758542526924135, 1, 'PASS', 2, 56, 11, 11, 102, 103,
         11400714819323198531, 11400714819323198531, 4354685564936845446,
         22, 2, 0, 2, 2, 16, 36, 36, 4, 4, 2, 2, 8, 24, 160, 92, 4),
        (18364758542526924135, 64, 'PASS', 2, 812, 389, 389, 858, 859,
         11400714819323190389, 11400714819323190389, 4354685564936829162,
         778, 128, 126, 128, 2, 16, 36, 36, 4, 4, 2, 2, 8, 24, 160, 92, 4),
    )
    # Each child's calls are ordered; its clock/AUX need not equal the other child.
    clocks = (100, 7, 110, 7, 120, 7, 130, 7, 20, 9, 30, 9, 40, 9, 50, 9)
    return [list(map(str, row+clocks)) for row in rows]


def encode(rows, header=HEADER):
    return (header+'\n'+''.join(','.join(row)+'\n' for row in rows)).encode('ascii')


class Controls(unittest.TestCase):
    def refuse(self, rows, terminal=TERMINAL, stderr=b''):
        with self.assertRaises(AssertionError): check.check(encode(rows), terminal, stderr)

    def test_complete_witness_population_and_independent_work(self):
        got = check.check(encode(fixture()), TERMINAL, b'')
        self.assertEqual((got['status'], got['selection'], got['pairs']),
            ('FUNCTIONAL_PASS', 'normal-reference-exact-37-v1', 4))
        keys = ('children', 'comparisons', 'instructions', 'conditional_branches', 'taken_branches',
            'input_reads', 'return_reads', 'return_read_bytes', 'target_calls', 'target_returns',
            'outer_returns', 'normal_reaps', 'reader_checks', 'output_stores', 'helper_heads',
            'interior_heads', 'returned_cells')
        self.assertEqual(tuple(got[k] for k in keys),
            (8, 1736, 1600, 260, 252, 260, 8, 64, 16, 16, 8, 8, 32, 96, 640, 368, 16))
        self.assertEqual((got['original_steps'], got['candidate_steps']), (1920, 1924))
        self.assertEqual([r['value0'] for r in got['rows']], [11400714819323198532,
            11400714819323190453, 11400714819323198531, 11400714819323190389])
        for actual, expected in zip(got['rows'], fixture()):
            self.assertEqual([str(actual[k]) for k in HEADER.split(',')], expected)
            self.assertTrue(all(type(v) is int for k, v in actual.items() if k != 'status'))

    def test_every_fixed_field_and_coherent_witness_changes_refuse(self):
        for index in range(4):
            for field in range(29):
                rows = fixture(); value = rows[index][field]
                rows[index][field] = 'FAILED' if field == 2 else (
                    '20001' if field in (7, 8) else str(int(value)+1))
                with self.subTest(row=index, field=field): self.refuse(rows)
        # Updating totals coherently cannot erase one reader, store or returned cell.
        for field, name in ((24, b'reader-checks'), (25, b'output-stores'), (26, b'helper-heads'),
                            (27, b'interior-heads'), (28, b'returned-cells')):
            rows = fixture(); old = int(rows[0][field])
            for row in rows: row[field] = str(old-1)
            terminal = TERMINAL.replace(name+b'='+str(4*old).encode(), name+b'='+str(4*(old-1)).encode())
            self.refuse(rows, terminal)
        rows = fixture()
        for row in rows:
            row[4] = str(int(row[4])+2); row[5] = row[6] = str(int(row[5])+1)
            row[12] = str(int(row[12])+2); row[7] = row[8] = str(int(row[4])+46)
        self.refuse(rows, TERMINAL.replace(b'comparisons=1736', b'comparisons=1744').replace(
            b'instructions=1600', b'instructions=1608'))
        rows = fixture(); rows[0][9:12], rows[2][9:12] = rows[2][9:12], rows[0][9:12]
        self.refuse(rows)

    def test_order_header_and_all45_columns_are_required(self):
        rows = fixture()
        for index in range(4):
            self.refuse(rows[:index]+rows[index+1:])
            self.refuse(rows[:index]+[rows[index]]+rows[index:])
            for other in range(index+1, 4):
                bad = fixture(); bad[index], bad[other] = bad[other], bad[index]; self.refuse(bad)
            self.refuse(rows[:index]+[rows[index][:-1]]+rows[index+1:])
            self.refuse(rows[:index]+[rows[index]+['0']]+rows[index+1:])
            for field in range(45):
                bad = fixture(); bad[index][field] = ''; self.refuse(bad)
        for header in ('', HEADER+',extra', HEADER.replace('seed,', 'length,', 1),
            HEADER.replace('helper_heads,interior_heads', 'interior_heads,helper_heads'),
            HEADER.replace('original0_start_ticks', 'candidate0_start_ticks', 1)):
            with self.assertRaises(AssertionError): check.check(encode(rows, header), TERMINAL, b'')

    def test_steps_include_all_reader_interiors_with_unchanged_ceiling(self):
        for maximum in (False, True):
            rows = fixture()
            for row in rows: row[7] = row[8] = '20000' if maximum else str(int(row[4])+46)
            got = check.check(encode(rows), TERMINAL, b'')
            self.assertEqual((got['original_steps'], got['candidate_steps']),
                (80000, 80000) if maximum else (1920, 1920))
        for index in range(4):
            for field in (7, 8):
                for value in (0, int(fixture()[index][4]), int(fixture()[index][4])+45, 20001):
                    rows = fixture(); rows[index][field] = str(value); self.refuse(rows)

    def test_each_child_clock_order_and_four_aux_are_joined(self):
        for index in range(4):
            for start in (29, 37):
                for edge in range(3):
                    rows = fixture(); before, after = start+2*edge, start+2*(edge+1)
                    rows[index][after] = str(int(rows[index][before])-1)
                    with self.subTest(row=index, child=start, edge=edge): self.refuse(rows)
                for component in range(4):
                    rows = fixture(); field = start+2*component+1
                    rows[index][field] = str(int(rows[index][field])+1); self.refuse(rows)
                rows = fixture()
                for component in range(4): rows[index][start+2*component+1] = '4294967296'
                self.refuse(rows)  # Consistent AUX still must fit u32.

    def test_zero_equal_maximum_and_cross_child_independence(self):
        for tick, aux in (('0', '0'), ('18446744073709551615', '4294967295')):
            rows = fixture()
            for row in rows:
                for field in range(29, 45, 2): row[field], row[field+1] = tick, aux
            got = check.check(encode(rows), TERMINAL, b'')
            for row in got['rows']:
                for field in HEADER.split(',')[29:]:
                    self.assertEqual(row[field], int(aux if field.endswith('_aux') else tick))
        # No inferred cross-child or cross-pair clock order/AUX identity.
        rows = fixture(); rows[3][29:37], rows[3][37:45] = rows[3][37:45], rows[3][29:37]
        got = check.check(encode(rows), TERMINAL, b'')
        self.assertGreater(got['rows'][0]['original0_start_ticks'], got['rows'][0]['candidate1_end_ticks'])
        self.assertNotEqual(got['rows'][0]['original0_start_aux'], got['rows'][0]['candidate0_start_aux'])
        self.assertLess(got['rows'][3]['original0_start_ticks'], got['rows'][3]['candidate1_end_ticks'])

    def test_all_numeric_cells_are_canonical_unsigned(self):
        self.assertEqual(check._u64('0'), 0)
        self.assertEqual(check._u64('18446744073709551615'), (1 << 64)-1)
        for index in range(4):
            for field in range(45):
                if field == 2: continue
                for value in ('00', '+1', '-1', '1.0', '1e0', ' 1', '1 ', '18446744073709551616', '9'*21):
                    rows = fixture(); rows[index][field] = value
                    with self.subTest(row=index, field=field, value=value): self.refuse(rows)

    def test_ascii_lf_types_caps_and_exact_terminal(self):
        data = encode(fixture())
        for position, byte in enumerate(data):
            if byte != 10: continue
            for separator in (b'\r\n', b'\r', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
                bad = data[:position]+separator+data[position+1:]
                with self.assertRaises(AssertionError): check.check(bad, TERMINAL, b'')
        for bad in (b'', data[:-1], data+b'\n', data+b'extra\n', data.split(b'\n', 1)[1],
            data+b'\xff', data.replace(b'PASS', b'PA\tSS', 1), data.replace(b',1,', b',"1",', 1),
            b'x'*(check.CSV_CAP+1), data.decode('ascii'), bytearray(data), None):
            with self.assertRaises(AssertionError): check.check(bad, TERMINAL, b'')
        pieces = TERMINAL[:-1].split(b':')
        for index, piece in enumerate(pieces):
            for replacement in ([], [piece, piece], [piece+b'!']):
                self.refuse(fixture(), b':'.join(pieces[:index]+replacement+pieces[index+1:])+b'\n')
        for bad in (b'', TERMINAL[:-1], TERMINAL+b'\n', b'prefix\n'+TERMINAL,
            TERMINAL.replace(b'\n', b'\r\n'), b'x'*(check.STDOUT_CAP+1),
            TERMINAL.decode('ascii'), bytearray(TERMINAL), None):
            self.refuse(fixture(), bad)
        for bad in (b'\n', b' ', b'warning\n', '', bytearray(), None): self.refuse(fixture(), stderr=bad)

    def test_optimized_entrypoints_refuse_and_parser_import_is_local(self):
        self.assertEqual(Path(check.__file__).resolve(), Path(__file__).with_name('reference_native.py').resolve())
        for name in ('reference_native.py', Path(__file__).name):
            process = subprocess.run([sys.executable, '-B', '-O', str(Path(__file__).with_name(name))],
                capture_output=True, timeout=5, check=False)
            self.assertEqual((process.returncode, process.stdout, process.stderr),
                (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
