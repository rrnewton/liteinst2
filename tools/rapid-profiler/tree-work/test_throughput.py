#!/usr/bin/env python3
"""Adversarial fabricated transcripts, with no workload or clock execution."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('tree_throughput_check', Path(__file__).with_name('check_throughput.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

MODES = ('original-sdk', 'k1', 'k10', 'k24')
HEADER = ('mode,block,call_first,call_last,roots,node_rows,sampled,closed,batches,'
    'events,reports,generation,history_prefix,gate_first,gate_last,completed_before,'
    'completed_after,conflict_population,conflict_retained,selection_error_numerator,'
    'selection_error_denominator,root_inclusive_instructions,root_exclusive_instructions,'
    'child_instructions,checksum')
FIELDS = HEADER.split(',')
ABSENT = ('generation', 'history_prefix', 'gate_first', 'gate_last', 'completed_before',
    'completed_after', 'conflict_retained', 'selection_error_numerator', 'selection_error_denominator')
TERMINAL_FIELDS = ('mode blocks roots calls originals installed_roots node_rows sampled closed '
    'batches events reports epochs actions root_inclusive_instructions root_exclusive_instructions '
    'child_instructions input_unchanged records_joined clock_scope '
    's0_wall_before s0_cpu s0_wall_after s1_wall_before s1_cpu s1_wall_after '
    's2_wall_before s2_cpu s2_wall_after s3_wall_before s3_cpu s3_wall_after '
    'wall_resolution_ns cpu_resolution_ns whole_wall_lower_ns whole_wall_ns whole_cpu_ns '
    'loop_wall_lower_ns loop_wall_ns loop_cpu_ns').split()
# Literal independent scalar result and mode totals; no parser helper builds fixtures.
CHECKSUM = 14030166876264928576
TOTALS = {'original-sdk': (1536, 0, 0, 0, 0, 0, 0, 0, 0, 0),
          'k1': (0, 1536, 3072, 128, 2944, 192, 6144, 128, 64, 128),
          'k10': (0, 1536, 3072, 1280, 1792, 192, 6144, 1280, 64, 128),
          'k24': (0, 1536, 3072, 3072, 0, 192, 6144, 3072, 64, 128)}


def fixture(mode='k10'):
    k = {'original-sdk': 0, 'k1': 1, 'k10': 10, 'k24': 24}[mode]
    installed = mode != 'original-sdk'
    selected, numerator, denominator = {0: (None, None, None), 1: (0, -14, 24),
        10: (0, -140, 240), 24: (14, 0, 576)}[k]
    rows = []
    for b in range(64):
        rows.append(dict(mode=mode, block=b, call_first=24*b+1, call_last=24*b+24,
            roots=24, node_rows=48 if installed else 0, sampled=2*k,
            closed=48-2*k if installed else 0, batches=3 if installed else 0,
            events=96 if installed else 0, reports=2*k,
            generation=11+3*b if installed else None, history_prefix=2*b+1 if installed else None,
            gate_first=24*b+1 if installed else None, gate_last=24*b+24 if installed else None,
            completed_before=2*k*b if installed else None, completed_after=2*k*(b+1) if installed else None,
            conflict_population=14, conflict_retained=selected, selection_error_numerator=numerator,
            selection_error_denominator=denominator, root_inclusive_instructions=7968,
            root_exclusive_instructions=144, child_instructions=7824, checksum=CHECKSUM))
    totals = dict(zip(('originals', 'installed_roots', 'node_rows', 'sampled', 'closed',
        'batches', 'events', 'reports', 'epochs', 'actions'), TOTALS[mode]))
    terminal = dict(totals, mode=mode, blocks=64, roots=1536, calls=1536,
        root_inclusive_instructions=509952, root_exclusive_instructions=9216,
        child_instructions=500736, input_unchanged=True, records_joined=installed,
        clock_scope='guarded-consumer', s0_wall_before=100, s0_cpu=1000, s0_wall_after=110,
        s1_wall_before=200, s1_cpu=1500, s1_wall_after=220,
        s2_wall_before=500, s2_cpu=2500, s2_wall_after=540,
        s3_wall_before=700, s3_cpu=4000, s3_wall_after=750,
        wall_resolution_ns=1, cpu_resolution_ns=1,
        whole_wall_lower_ns=590, whole_wall_ns=650, whole_cpu_ns=3000,
        loop_wall_lower_ns=280, loop_wall_ns=340, loop_cpu_ns=1000)
    return rows, terminal


def recalculate(terminal):
    # Mutated clocks retain exact duration formulas so ordering controls must
    # reject the actual invalid endpoints, not merely a stale derived field.
    for prefix, first, last in (('whole', 0, 3), ('loop', 1, 2)):
        terminal[prefix+'_wall_lower_ns'] = terminal[f's{last}_wall_before'] - terminal[f's{first}_wall_after']
        terminal[prefix+'_wall_ns'] = terminal[f's{last}_wall_after'] - terminal[f's{first}_wall_before']
        terminal[prefix+'_cpu_ns'] = terminal[f's{last}_cpu'] - terminal[f's{first}_cpu']


def word(value):
    if value is None:
        return ''
    if type(value) is bool:
        return 'true' if value else 'false'
    return str(value)


def encode(rows, terminal):
    lines = [HEADER] + [','.join(word(row[name]) for name in FIELDS) for row in rows]
    lines.append('tree-throughput FUNCTIONAL_PASS ' + ' '.join(
        name+'='+word(terminal[name]) for name in TERMINAL_FIELDS))
    return ('\n'.join(lines)+'\n').encode('ascii')


class ThroughputProtocol(unittest.TestCase):
    def accept(self, rows, terminal, mode='k10'):
        return CHECK.parse(encode(rows, terminal), b'', mode)

    def refuse(self, rows, terminal, mode='k10'):
        with self.assertRaises(AssertionError):
            self.accept(rows, terminal, mode)

    def refuse_bytes(self, output, mode='k10', stderr=b''):
        with self.assertRaises(AssertionError):
            CHECK.parse(output, stderr, mode)

    def test_all_modes_exact_counts_checksum_and_permitted_boundaries(self):
        # Independent four root values and their per-block multiplicities.
        values = (13455538007910626262, 14448916110156114966,
                  18114441086748040058, 6122101979721109698)
        self.assertEqual((5*(values[0]+values[1])+7*(values[2]+values[3])) % 2**64, CHECKSUM)
        for mode in MODES:
            rows, terminal = fixture(mode)
            result = self.accept(rows, terminal, mode)
            self.assertEqual(result['summary'], dict(terminal, status='FUNCTIONAL_PASS'))
            self.assertEqual(result['rows'], rows)
            self.assertEqual(len(result['rows']), 64)
            self.assertGreater(terminal['whole_cpu_ns'], terminal['whole_wall_ns'])
            if mode == 'original-sdk':
                self.assertTrue(all(row[name] is None for row in result['rows'] for name in ABSENT))
            else:
                for b, row in enumerate(rows):
                    row['generation'] = 2**64-64+b
                self.accept(rows, terminal, mode)  # Last legitimate u64 generation.
            terminal.update(s2_wall_before=220, s2_wall_after=250,
                wall_resolution_ns=2**64-1, cpu_resolution_ns=2**64-1)
            recalculate(terminal)
            self.assertEqual(terminal['loop_wall_lower_ns'], 0)
            self.accept(rows, terminal, mode)  # No resolution-duration filter.
            for i in range(4):
                for key in ('wall_before', 'wall_after'):
                    terminal[f's{i}_{key}'] += 2**64-1-750
                terminal[f's{i}_cpu'] += 2**64-1-4000
            recalculate(terminal)
            self.accept(rows, terminal, mode)

    def test_missing_duplicate_reordered_or_replaced_blocks_refuse(self):
        rows, terminal = fixture()
        for i in range(64):
            self.refuse(rows[:i]+rows[i+1:], terminal)
            self.refuse(rows[:i]+[rows[i]]+rows[i:], terminal)
            bad = copy.deepcopy(rows); bad[i] = dict(rows[(i+1) % 64])
            self.refuse(bad, terminal)
        self.refuse(list(reversed(rows)), terminal)
        self.refuse(rows[32:]+rows[:32], terminal)
        self.refuse(rows[:63], terminal)

    def test_each_fixed_row_field_and_complete_row_terminal_joins(self):
        rows, terminal = fixture()
        for i in range(64):
            for name in FIELDS[1:]:
                if name == 'generation':
                    continue  # An arbitrary larger generation can be valid.
                bad = copy.deepcopy(rows); bad[i][name] += 1
                with self.subTest(row=i, field=name):
                    self.refuse(bad, terminal)
        for mode in MODES:
            rows, terminal = fixture(mode)
            for name in FIELDS[1:]:
                if name == 'generation' or rows[0][name] is None:
                    continue
                bad = copy.deepcopy(rows); bad[0][name] += 1
                self.refuse(bad, terminal, mode)
            # Forging both totals cannot rehabilitate a wrong block's work.
            bad = copy.deepcopy(rows); term = dict(terminal)
            bad[0]['roots'] += 1; term['roots'] += 1; term['calls'] += 1
            self.refuse(bad, term, mode)

    def test_real_generation_order_mode_identity_and_original_absences(self):
        rows, terminal = fixture()
        for i in range(64):
            for value in (0, 2**64):
                bad = copy.deepcopy(rows); bad[i]['generation'] = value
                self.refuse(bad, terminal)
            if i:
                for value in (rows[i-1]['generation'], rows[i-1]['generation']-1):
                    bad = copy.deepcopy(rows); bad[i]['generation'] = value
                    self.refuse(bad, terminal)
            bad = copy.deepcopy(rows); bad[i]['mode'] = 'k1'
            self.refuse(bad, terminal)
        for mode in MODES[1:]:
            rows, terminal = fixture(mode)
            for name in ABSENT:
                bad = copy.deepcopy(rows); bad[0][name] = None
                self.refuse(bad, terminal, mode)
        rows, terminal = fixture('original-sdk')
        for i in (0, 31, 63):
            for name in ABSENT:
                for value in (0, 1, 'None'):
                    bad = copy.deepcopy(rows); bad[i][name] = value
                    self.refuse(bad, terminal, 'original-sdk')
        for requested in ('k1', 'k10', 'k24', None, True, 1, 'original', 'K10', ''):
            self.refuse_bytes(encode(rows, terminal), requested)

    def test_terminal_counts_attributes_and_forged_success_refuse(self):
        for mode in MODES:
            rows, terminal = fixture(mode)
            for name, value in terminal.items():
                if name.startswith('s') and name[1:2].isdigit() or name.endswith('_ns'):
                    continue  # Clock fields have their own exact controls.
                term = dict(terminal)
                if type(value) is bool:
                    term[name] = not value
                elif type(value) is int:
                    term[name] += 1
                else:
                    term[name] += '-wrong'
                self.refuse(rows, term, mode)
            data = encode(rows, terminal)
            self.refuse_bytes(data.replace(b'FUNCTIONAL_PASS', b'PASS'), mode)
            self.refuse_bytes(data.replace(b'FUNCTIONAL_PASS', b'FAILED'), mode)
            prefix, last, empty = data.rsplit(b'\n', 2)
            self.assertEqual(empty, b'')
            parts = last.split(b' ')
            for i in range(2, len(parts)):
                self.refuse_bytes(prefix+b'\n'+b' '.join(parts[:i]+parts[i+1:])+b'\n', mode)
                self.refuse_bytes(prefix+b'\n'+b' '.join(parts[:i]+[parts[i]]+parts[i:])+b'\n', mode)
            parts[2], parts[3] = parts[3], parts[2]
            self.refuse_bytes(prefix+b'\n'+b' '.join(parts)+b'\n', mode)

    def test_all_clock_order_duration_formula_resolution_and_zero_boundaries(self):
        rows, terminal = fixture()
        for name in [n for n in TERMINAL_FIELDS if n.endswith('_ns') and 'resolution' not in n]:
            term = dict(terminal); term[name] += 1
            self.refuse(rows, term)
        for i in range(4):
            for part in ('wall_before', 'cpu', 'wall_after'):
                term = dict(terminal); term[f's{i}_{part}'] += 1
                self.refuse(rows, term)  # Raw change without its exact derived change.
            term = dict(terminal); term[f's{i}_wall_before'] = term[f's{i}_wall_after']+1
            recalculate(term); self.refuse(rows, term)
        for i in range(3):
            term = dict(terminal); term[f's{i+1}_wall_before'] = term[f's{i}_wall_after']-1
            recalculate(term); self.refuse(rows, term)
            term = dict(terminal); term[f's{i+1}_cpu'] = term[f's{i}_cpu']-1
            recalculate(term); self.refuse(rows, term)
        for name in ('wall_resolution_ns', 'cpu_resolution_ns'):
            term = dict(terminal); term[name] = 0
            self.refuse(rows, term)
        term = dict(terminal); term['s2_cpu'] = term['s1_cpu']
        recalculate(term); self.refuse(rows, term)
        term = dict(terminal)
        term.update(s1_wall_before=220, s2_wall_before=220, s2_wall_after=220)
        recalculate(term); self.refuse(rows, term)
        term = dict(terminal)
        for i in range(4):
            term.update({f's{i}_wall_before': 1, f's{i}_cpu': 1, f's{i}_wall_after': 1})
        recalculate(term); self.refuse(rows, term)
        term = dict(terminal); term['whole_wall_ns'] = term['whole_wall_lower_ns']
        self.refuse(rows, term)  # Primary upper must never be silently replaced.

    def test_numeric_grammar_ranges_and_signed_field_isolation(self):
        rows, terminal = fixture()
        for name in FIELDS[1:]:
            invalid = ('', '+1', '01', '-0', '1.0', 'true', ' 1', str(2**64))
            if name != 'selection_error_numerator':
                invalid += ('-1',)
            for value in invalid:
                bad = copy.deepcopy(rows); bad[0][name] = value
                with self.subTest(field=name, value=value):
                    self.refuse(bad, terminal)
        for value in (-(2**63)-1, 2**63, '-014'):
            bad = copy.deepcopy(rows); bad[0]['selection_error_numerator'] = value
            self.refuse(bad, terminal)
        for name, value in terminal.items():
            if type(value) is int:
                for invalid in ('', '-1', '+1', '01', '1.0', 'true', str(2**64)):
                    term = dict(terminal); term[name] = invalid
                    self.refuse(rows, term)
            elif type(value) is bool:
                for invalid in (0, 1, 'True', 'False'):
                    term = dict(terminal); term[name] = invalid
                    self.refuse(rows, term)

    def test_exact_ascii_lf_no_extras_stderr_or_wrong_input_types(self):
        rows, terminal = fixture(); data = encode(rows, terminal)
        for i, byte in enumerate(data):
            if byte == 10:
                for replacement in (b'\r', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
                    self.refuse_bytes(data[:i]+replacement+data[i+1:])
        for bad in (data[:-1], b'\n'+data, data+b'\n', data+b'extra\n', data.replace(b'\n', b'\r\n'),
                    data.replace(b'mode,block', b'block,mode', 1), b'\t'+data, b'\x7f'+data,
                    b'\x80'+data, data.replace(b'k10,0,', b'"k10",0,', 1), b'x'*1048577+b'\n'):
            self.refuse_bytes(bad)
        self.refuse_bytes(data, stderr=b'warning\n')
        for output, stderr in ((data.decode('ascii'), b''), (bytearray(data), b''), (data, '')):
            with self.assertRaises(AssertionError):
                CHECK.parse(output, stderr, 'k10')


if __name__ == '__main__':
    unittest.main()
