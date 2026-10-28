#!/usr/bin/env python3
"""Pure synthetic protocol controls; no providers, build or native execution."""
import argparse
import ast
import csv
import io
from pathlib import Path
import re
import sys
import tempfile
import unittest

FUNCTIONS = {'exact_table', 'exact_number', 'exact_output', 'exact_native_output'}
CONSTANTS = {'MIB', 'EXACT_SCHEDULES', 'EXACT_SCOPE', 'EXACT_HEADER'}


def load(path):
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body if
        isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS or
        isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in CONSTANTS]
    assert len(nodes) == len(FUNCTIONS)+len(CONSTANTS)
    ns = dict(csv=csv, re=re)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)
    return ns


def csv_bytes(header, rows):
    output = io.StringIO(newline=''); writer = csv.writer(output, lineterminator='\n')
    writer.writerow(header.split(',')); writer.writerows(rows)
    return output.getvalue().encode('ascii')


def fixture(schedule='late-long', k=10):
    lengths = {'short': [1]*24, 'long': [64]*24, 'alternating': [1, 64]*12, 'late-long': [1]*10+[64]*14}[schedule]
    ordinal = ['short', 'long', 'alternating', 'late-long'].index(schedule)
    rows = []
    for i, n in enumerate(lengths):
        value = sum((((j*37+11) % 256) ^ 90) for j in range(n)) ^ 0x9e3779b97f4a7c15
        rows.append([schedule, k, ordinal*10000+k*100+i, i+1, n, 'sampled' if i < k else 'closed', 1,
            i if i < k else '', 6*n+5, n, n-1, n, 8, value, 1000+i*100, 1050+i*100, 7, 7])
    total, selected = sum(6*n+5 for n in lengths), sum(6*n+5 for n in lengths[:k])
    terminal = (f'exact-work PASS calls=24 retained={k} population_instructions={total} retained_instructions={selected} '
        f'selection_error_numerator={24*selected-k*total} selection_error_denominator={24*k} originals=24 raw_rows=24 input_unchanged=true joined=true\n')
    return rows, terminal


def encoded(rows, terminal):
    return P['EXACT_SCOPE'].encode('ascii')+b'\n'+csv_bytes(P['EXACT_HEADER'], rows)+terminal.encode('ascii')


class ExactParsers(unittest.TestCase):
    def refused(self, rows, terminal, schedule='late-long', k=10):
        with self.assertRaises(AssertionError): P['exact_output'](encoded(rows, terminal), schedule, k)

    def test_all_twelve_complete_populations_and_exact_fraction(self):
        for name in ('short', 'long', 'alternating', 'late-long'):
            for k in (24, 1, 10):
                rows, terminal = fixture(name, k)
                parsed, _, summary = P['exact_output'](encoded(rows, terminal), name, k)
                self.assertEqual(len(parsed), 24)
                self.assertEqual(sum(row['owner'] == 'closed' for row in parsed), 24-k)
                if name == 'late-long' and k == 10:
                    self.assertEqual((summary['selection_error_numerator'], summary['selection_error_denominator']), (-52920, 240))

    def test_missing_extra_duplicate_and_swapped_external_ids_refuse(self):
        rows, terminal = fixture(); self.refused(rows[:-1], terminal); self.refused(rows+[rows[-1]], terminal)
        for duplicate in (False, True):
            rows, terminal = fixture()
            rows[0][2], rows[1][2] = (rows[1][2], rows[1][2]) if duplicate else (rows[1][2], rows[0][2])
            self.refused(rows, terminal)

    def test_owner_generation_order_work_and_clock_refuse(self):
        # Each is a valid CSV field with one changed semantic value.
        for index, field, value in [(0, 3, 2), (0, 4, 64), (0, 5, 'closed'), (10, 5, 'sampled'),
                (0, 6, 2), (0, 7, 1), (10, 7, 10), (0, 8, 12), (0, 9, 2), (0, 10, 1),
                (0, 11, 2), (0, 12, 0), (0, 13, 0), (0, 15, 999), (0, 17, 8), (0, 16, 2**32)]:
            rows, terminal = fixture(); rows[index][field] = value
            with self.subTest(index=index, field=field): self.refused(rows, terminal)

    def test_terminal_fraction_and_complete_population_cannot_be_relabelled(self):
        rows, terminal = fixture()
        for old, new in [('calls=24', 'calls=10'), ('raw_rows=24', 'raw_rows=10'), ('originals=24', 'originals=10'),
                ('-52920', '-441'), ('denominator=240', 'denominator=2'), ('joined=true', 'joined=false')]:
            self.refused(rows, terminal.replace(old, new))

    def test_native_truth_pairs_and_terminal_join(self):
        pair_header = 'seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value'
        truth_header = 'seed,length,status,instructions,conditional_branches,taken_branches,input_reads,return_reads,value'
        pairs, truth = [], []
        for seed in (0x1234567887654320, 0xfedcba9801234567):
            for n in (1, 64):
                value = sum(((((128+j)*37+11+seed) % 256) ^ 90) for j in range(n)) ^ 0x9e3779b97f4a7c15
                instructions = 6*n+5
                pairs.append([seed, n, 'PASS', 2, instructions+10, instructions, instructions+100, instructions+200, value])
                truth.append([seed, n, 'PASS', instructions, n, n-1, n, 1, value])
        terminal = b'native-exact:required=4:pairs=4:children=8:comparisons=840:truth-instructions=800:conditional=130:taken=126:input-reads=130:return-reads=4:short-ret-refusals=1:real-outer-ret=8:complete\n'
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            def write():
                (directory/'exact-pairs.csv').write_bytes(csv_bytes(pair_header, pairs))
                (directory/'exact-truth.csv').write_bytes(csv_bytes(truth_header, truth))
                (directory/'exact-refusals.csv').write_bytes(b'case,status,reason\nempty_capable_symbol,PASS,NoPatchWindow\n')
            write(); self.assertEqual(P['exact_native_output'](directory, terminal)[-1], 840)
            concurrent = terminal.replace(b'native-exact:', b'native-exact-concurrent:')
            self.assertEqual(P['exact_native_output'](directory, concurrent, concurrent=True)[-1], 840)
            with self.assertRaises(AssertionError): P['exact_native_output'](directory, terminal, concurrent=True)
            with self.assertRaises(AssertionError): P['exact_native_output'](directory, concurrent)
            for table, row, column, wrong in [(pairs, 0, 0, 1), (pairs, 0, 5, 12), (pairs, 0, 6, 20001),
                    (truth, 1, 3, 388), (truth, 1, 5, 62), (truth, 0, 7, 0), (truth, 0, 8, 0)]:
                prior = table[row][column]; table[row][column] = wrong; write()
                with self.assertRaises(AssertionError): P['exact_native_output'](directory, terminal)
                table[row][column] = prior
            write()
            with self.assertRaises(AssertionError): P['exact_native_output'](directory, terminal.replace(b'840', b'841'))
            (directory/'exact-refusals.csv').write_bytes(b'case,status,reason\n')
            with self.assertRaises(AssertionError): P['exact_native_output'](directory, terminal)


if __name__ == '__main__':
    if sys.flags.optimize: raise SystemExit('assertions required')
    parser = argparse.ArgumentParser(); parser.add_argument('--runner', type=Path, required=True)
    args = parser.parse_args(); P = load(args.runner)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
