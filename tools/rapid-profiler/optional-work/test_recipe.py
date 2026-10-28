#!/usr/bin/env python3
"""Pure fabricated-output controls; no child, artifact or observed trace reads."""
import csv
import importlib.util
import io
from pathlib import Path
import sys
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('optional_check', Path(__file__).with_name('check_output.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def fixture(slow):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\n')
    writer.writerow('seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value,observer_entries,helper_joins'.split(','))
    for seed in (0x1234567887654320, 0xfedcba9801234567):
        for length in (1, 64):
            value = sum(((((128+j)*37+11+seed) & 255) ^ 0x5a) for j in range(length)) ^ 0x9e3779b97f4a7c15
            writer.writerow([seed, length, 'PASS', 2, 20, 9, 50, 150, value, 2 if slow else 0, 1])
    mode = 'slow' if slow else 'fast'
    terminal = f'native-optional-{mode}:required=4:pairs=4:children=8:comparisons=80:observer-entries={8 if slow else 0}:controller-transitions=4:helper-joins=4:short-ret-refusals=1:real-outer-ret=8:complete\n'.encode()
    return stream.getvalue().encode(), b'case,status,reason\nempty_capable_symbol,PASS,NoPatchWindow\n', terminal


class Projection(unittest.TestCase):
    def test_both_complete_populations(self):
        for slow in (False, True):
            rows, count = check.pairs(*fixture(slow), slow)
            self.assertEqual((len(rows), count), (4, 80))

    def test_population_value_budget_and_observers(self):
        table, refusal, terminal = fixture(True)
        for column, replacement in ((0, '7'), (1, '2'), (3, '1'), (4, '8'), (6, '20001'), (7, '20001'), (8, '0'), (9, '1'), (10, '0')):
            lines = table.decode().splitlines(); row = lines[1].split(','); row[column] = replacement; lines[1] = ','.join(row)
            with self.assertRaises(AssertionError): check.pairs(('\n'.join(lines)+'\n').encode(), refusal, terminal, True)
        with self.assertRaises(AssertionError): check.pairs(table.replace(b',64,PASS,', b',1,PASS,', 1), refusal, terminal, True)
        with self.assertRaises(AssertionError): check.pairs(table, refusal, terminal, False)

    def test_no_tail_failure_or_missing_refusal_credit(self):
        table, refusal, terminal = fixture(False)
        for a, b, c in ((table+b'\n', refusal, terminal), (table, b'', terminal), (table, refusal, terminal+b'PASS\n'),
                        (table.replace(b'PASS', b'FAIL', 1), refusal, terminal), (table, refusal, terminal.replace(b'helper-joins=4', b'helper-joins=3'))):
            with self.assertRaises(AssertionError): check.pairs(a, b, c, False)

    def test_exact_actual_single_test_protocol(self):
        protocol = '\nrunning 1 test\ntest '+check.TEST+' ... '+check.PASS+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.12s\n\n'
        result = check.functional(protocol.encode(), b'')
        self.assertEqual((result['calls'], result['events'], result['batches']), (96, 128, 3))
        for bad in (protocol.replace('calls=96', 'calls=95'), protocol.replace('0 failed;', '1 failed;'),
                    protocol.replace('running 1 test', 'running 0 tests'), protocol+'extra\n', protocol.replace('helper_joins=1', 'helper_joins=0')):
            with self.assertRaises(AssertionError): check.functional(bad.encode(), b'')
        with self.assertRaises(AssertionError): check.functional(protocol.encode(), b'diagnostic\n')


if __name__ == '__main__':
    unittest.main()
