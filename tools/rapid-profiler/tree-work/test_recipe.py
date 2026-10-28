#!/usr/bin/env python3
"""Finite tree protocol corruption controls; no native subject execution."""
import copy
import csv
import importlib.util
import io
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('tree_check', Path(__file__).with_name('check_output.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def encode(rows):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=CHECK.HEADER.split(','), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('ascii')


def rows():
    result = []
    for seed in (0x1234567887654320, 0xfedcba9801234567):
        for name, cycle in [('fit2', (0, 4)), ('conflict3', (0, 4, 8))]:
            # Independent synthetic fixture: header miss, payload/link pairs,
            # CALL-allocated stack line hit by both RETs.
            bits = ['0', '0']
            value = 0
            for i in range(64):
                payload = seed ^ ((cycle[i % len(cycle)]+1)*0x9e3779b97f4a7c15 % 2**64)
                value = (value+payload) % 2**64
                resident = i == 0 or name == 'fit2' and i >= 2
                bits.extend(['1' if resident else '0', '1'])
            bits.extend(['1', '1'])
            misses = bits.count('0')
            result.append(dict(seed=seed, case=name, status='PASS', children=2,
                comparisons=343, original_visits=332, original_steps=432, candidate_steps=5000,
                instructions=332, root_instructions=6, child_instructions=326,
                conditional_branches=64, taken_branches=63, input_reads=129, return_reads=2,
                call_stores=1, model_events=132, model_hits=132-misses, model_misses=misses,
                root_misses=1, child_misses=misses-1, model_writebacks=0, model_hit_bits=''.join(bits),
                value=((value ^ 0x9e3779b97f4a7c15)+1) % 2**64, transfers=6, real_outer_returns=2))
    return result


class TreeProtocol(unittest.TestCase):
    def accepted(self, source):
        return CHECK.pairs(encode(source), CHECK.TERMINAL.encode('ascii'), b'')

    def refused(self, source):
        with self.assertRaises((AssertionError, ValueError, UnicodeError, csv.Error)):
            self.accepted(source)

    def test_complete_population_and_every_numeric_join(self):
        good = rows()
        self.assertEqual(self.accepted(good), good)
        fields = set(good[0]) - {'case', 'status', 'model_hit_bits', 'original_steps', 'candidate_steps'}
        for index in range(4):
            for field in fields:
                changed = copy.deepcopy(good)
                changed[index][field] += 1
                self.refused(changed)
            for field in ('original_steps', 'candidate_steps'):
                for bad in (0, 342, 20001):
                    changed = copy.deepcopy(good)
                    changed[index][field] = bad
                    self.refused(changed)

    def test_missing_duplicate_substituted_or_reordered_pairs_refuse(self):
        good = rows()
        self.accepted(good)
        for i in range(4):
            self.refused(good[:i]+good[i+1:])
            self.refused(good[:i]+[good[i]]+good[i:])
            changed = copy.deepcopy(good)
            changed[i] = copy.deepcopy(good[(i+1) % 4])
            self.refused(changed)
        self.refused(list(reversed(good)))

    def test_balanced_totals_cannot_hide_wrong_function_or_transfer(self):
        good = rows()
        self.accepted(good)
        for positive, negative in [('root_misses', 'child_misses'),
                ('root_instructions', 'child_instructions'), ('return_reads', 'call_stores')]:
            changed = copy.deepcopy(good)
            changed[0][positive] += 1
            changed[0][negative] -= 1
            self.refused(changed)
        for field in ('transfers', 'real_outer_returns', 'model_misses', 'instructions'):
            changed = copy.deepcopy(good)
            changed[0][field] += 1
            changed[1][field] -= 1
            self.refused(changed)

    def test_every_event_bit_and_both_return_hits_are_required(self):
        good = rows()
        self.accepted(good)
        for i in range(4):
            bits = good[i]['model_hit_bits']
            for j in range(132):
                changed = copy.deepcopy(good)
                changed[i]['model_hit_bits'] = bits[:j]+('0' if bits[j] == '1' else '1')+bits[j+1:]
                self.refused(changed)
            for bad in (bits[1:], bits+'1', '1'+bits[1:130]+'0'+bits[131:], bits.replace('0','x',1)):
                changed = copy.deepcopy(good)
                changed[i]['model_hit_bits'] = bad
                self.refused(changed)

    def test_strict_decimal_status_and_record_grammar(self):
        good = rows()
        self.accepted(good)
        for field in set(good[0]) - {'case', 'status', 'model_hit_bits'}:
            for bad in ('-1', '+1', '01', '1.0', '', ' 1', 2**64):
                changed = copy.deepcopy(good)
                changed[0][field] = bad
                self.refused(changed)
        for field, bad in (('case','unsupported'),('status','SKIP'),('status','FAIL')):
            changed = copy.deepcopy(good)
            changed[0][field] = bad
            self.refused(changed)
        data = encode(good)
        for bad in (data[:-1], data+b'\n', data.replace(b'\n',b'\r\n'),
                data.replace(b'transfers',b'callbacks',1), data+b'extra\n'):
            with self.assertRaises((AssertionError, ValueError, UnicodeError, csv.Error)):
                CHECK.pairs(bad, CHECK.TERMINAL.encode('ascii'), b'')
        for separator in (b'\x0b',b'\x0c',b'\x1c',b'\x1d',b'\x1e'):
            for i in range(1,5):
                parts = data.split(b'\n')
                bad = b'\n'.join(parts[:i])+separator+b'\n'.join(parts[i:])
                with self.assertRaises((AssertionError, ValueError, UnicodeError, csv.Error)):
                    CHECK.pairs(bad,CHECK.TERMINAL.encode('ascii'),b'')

    def test_terminal_and_empty_stderr_are_mandatory(self):
        data = encode(rows())
        self.assertEqual(len(CHECK.pairs(data,CHECK.TERMINAL.encode('ascii'),b'')),4)
        for terminal in (b'',CHECK.TERMINAL[:-1].encode('ascii'),
                CHECK.TERMINAL.replace('pairs=4','pairs=3').encode('ascii'),
                CHECK.TERMINAL.replace('transfers=24','transfers=23').encode('ascii'),
                CHECK.TERMINAL.replace('real-outer-ret=8','real-outer-ret=7').encode('ascii')):
            with self.assertRaises(AssertionError):
                CHECK.pairs(data,terminal,b'')
        with self.assertRaises(AssertionError):
            CHECK.pairs(data,CHECK.TERMINAL.encode('ascii'),b'warning\n')


if __name__ == '__main__':
    unittest.main()
