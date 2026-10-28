#!/usr/bin/env python3
"""Corruption controls for the finite cache-work protocol; no native subjects."""
import copy
import csv
import importlib.util
import io
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('cache_check', Path(__file__).with_name('check_output.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def encode(rows, header=CHECK.HEADER):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=header.split(','), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('ascii')


def rows():
    result = []
    cycles = ((0, 1, 2, 3), tuple(range(16)), (0, 3, 6, 1, 4, 7, 2, 5), (0, 4), (0, 4, 8), tuple(range(12)))
    for seed in (0x1234567887654320, 0xfedcba9801234567):
        for name, cycle, n, misses in zip(('reuse4', 'cold16', 'chase8', 'fit2', 'conflict3', 'capacity12'),
                cycles, (64, 16, 64, 64, 64, 64), (5, 17, 9, 3, 65, 65)):
            value = 0
            for i in range(n):
                payload = seed ^ ((cycle[i % len(cycle)]+1)*0x9e3779b97f4a7c15 % 2**64)
                value = (value+payload) % 2**64
            instructions = 5*n+6
            bits = ['0']
            for i in range(n):
                resident = i == 0 or (name in ('reuse4', 'chase8', 'fit2') and i >= len(cycle))
                bits.extend(['1' if resident else '0', '1'])
            bits.append('0')
            result.append(dict(seed=seed, case=name, status='PASS', children=2,
                comparisons=instructions+11, original_visits=instructions,
                original_steps=instructions+100, candidate_steps=instructions+4000,
                instructions=instructions, conditional_branches=n, taken_branches=n-1,
                input_reads=2*n+1, return_reads=1, model_events=2*n+2,
                model_hits=2*n+2-misses, model_misses=misses, model_hit_bits=''.join(bits),
                value=value ^ 0x9e3779b97f4a7c15))
    return result


class CacheProtocol(unittest.TestCase):
    def accepted(self, source):
        return CHECK.pairs(encode(source), CHECK.TERMINAL.encode('ascii'), b'')

    def refused(self, source):
        with self.assertRaises((AssertionError, ValueError, UnicodeError, csv.Error)):
            self.accepted(source)

    def test_complete_fixed_population_and_every_numeric_join(self):
        good = rows()
        self.assertEqual(self.accepted(good), good)
        fields = set(good[0]) - {'case', 'status', 'model_hit_bits', 'original_steps', 'candidate_steps'}
        for index in range(12):
            for field in fields:
                changed = copy.deepcopy(good)
                changed[index][field] += 1
                self.refused(changed)
            for field in ('original_steps', 'candidate_steps'):
                for bad in (0, good[index]['comparisons']-1, 20001):
                    changed = copy.deepcopy(good)
                    changed[index][field] = bad
                    self.refused(changed)

    def test_missing_duplicate_substituted_and_reordered_cases_refuse(self):
        good = rows()
        self.accepted(good)
        for index in range(12):
            self.refused(good[:index]+good[index+1:])
            self.refused(good[:index]+[good[index]]+good[index:])
            changed = copy.deepcopy(good)
            changed[index] = copy.deepcopy(good[(index+1) % 12])
            self.refused(changed)
        self.refused(list(reversed(good)))

    def test_model_totals_cannot_hide_row_errors_or_omit_ret(self):
        good = rows()
        self.accepted(good)
        changed = copy.deepcopy(good)
        changed[0]['model_misses'] += 1
        changed[0]['model_hits'] -= 1
        changed[1]['model_misses'] -= 1
        changed[1]['model_hits'] += 1
        self.refused(changed)
        changed = copy.deepcopy(good)
        for row in changed:
            row['model_misses'] -= 1
            row['model_events'] -= 1
            row['return_reads'] = 0
        self.refused(changed)

    def test_every_model_event_is_required_even_when_totals_match(self):
        good = rows()
        self.accepted(good)
        for index in range(12):
            bits = good[index]['model_hit_bits']
            for offset in range(len(bits)):
                changed = copy.deepcopy(good)
                changed[index]['model_hit_bits'] = bits[:offset]+('0' if bits[offset] == '1' else '1')+bits[offset+1:]
                self.refused(changed)
            changed = copy.deepcopy(good)
            changed[index]['model_hit_bits'] = '10'+bits[2:]
            self.assertEqual(changed[index]['model_hit_bits'].count('1'), bits.count('1'))
            self.refused(changed)
            for bad in (bits[:-1], bits+'0', bits.replace('0', 'x', 1)):
                changed = copy.deepcopy(good)
                changed[index]['model_hit_bits'] = bad
                self.refused(changed)
    def test_decimal_types_status_and_exact_grammar_refuse(self):
        good = rows()
        self.accepted(good)
        for field in set(good[0]) - {'case', 'status', 'model_hit_bits'}:
            for bad in ('-1', '+1', '01', '1.0', '', ' 1', 2**64):
                changed = copy.deepcopy(good)
                changed[0][field] = bad
                self.refused(changed)
        for field, bad in (('case', 'unsupported'), ('status', 'SKIP'), ('status', 'FAIL')):
            changed = copy.deepcopy(good)
            changed[0][field] = bad
            self.refused(changed)
        data = encode(good)
        for bad in (data[:-1], data+b'\n', data.replace(b'\n', b'\r\n'),
                data.replace(b'model_events', b'events', 1), data+b'extra\n'):
            with self.assertRaises((AssertionError, ValueError, UnicodeError, csv.Error)):
                CHECK.pairs(bad, CHECK.TERMINAL.encode('ascii'), b'')

    def test_only_literal_lf_can_separate_csv_records(self):
        data = encode(rows())
        self.assertEqual(len(CHECK.pairs(data, CHECK.TERMINAL.encode('ascii'), b'')), 12)
        for separator in (b'\x0b', b'\x0c', b'\x1c', b'\x1d', b'\x1e'):
            for count in (1, 2, 7, 12):
                parts = data.split(b'\n')
                changed = b'\n'.join(parts[:count])+separator+b'\n'.join(parts[count:])
                with self.assertRaises((AssertionError, ValueError, UnicodeError, csv.Error)):
                    CHECK.pairs(changed, CHECK.TERMINAL.encode('ascii'), b'')

    def test_terminal_and_stderr_are_part_of_the_claim(self):
        data = encode(rows())
        self.assertEqual(len(CHECK.pairs(data, CHECK.TERMINAL.encode('ascii'), b'')), 12)
        for terminal in (b'', CHECK.TERMINAL[:-1].encode('ascii'),
                CHECK.TERMINAL.replace('pairs=12', 'pairs=11').encode('ascii'),
                CHECK.TERMINAL.replace('real-outer-ret=24', 'real-outer-ret=23').encode('ascii')):
            with self.assertRaises(AssertionError):
                CHECK.pairs(data, terminal, b'')
        with self.assertRaises(AssertionError):
            CHECK.pairs(data, CHECK.TERMINAL.encode('ascii'), b'warning\n')


if __name__ == '__main__':
    unittest.main()
