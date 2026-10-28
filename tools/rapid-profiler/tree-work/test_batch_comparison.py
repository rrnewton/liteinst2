#!/usr/bin/env python3
"""Fabricated transcript controls only; no workload, clock or SDK execution."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('tree_batch_comparison_check', Path(__file__).with_name('check_batch_comparison.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

OLD = ('native', 'original-sdk', 'k1', 'k10', 'k24')
NEW = ('original-sdk-batch8', 'k1-batch8', 'k10-batch8', 'k24-batch8')
BASE = dict(zip(NEW, OLD[1:]))
HEADER = ('mode,block,call_first,call_last,roots,node_rows,sampled,closed,batches,'
    'events,reports,generation,history_prefix,gate_first,gate_last,completed_before,'
    'completed_after,conflict_population,conflict_retained,selection_error_numerator,'
    'selection_error_denominator,root_inclusive_instructions,root_exclusive_instructions,'
    'child_instructions,checksum')
FIELDS = HEADER.split(',')
ABSENT = ('generation', 'history_prefix', 'gate_first', 'gate_last', 'completed_before',
    'completed_after', 'conflict_retained', 'selection_error_numerator', 'selection_error_denominator')
FIRST_KEYS = ('mode blocks roots calls originals installed_roots node_rows sampled closed batches '
    'events reports epochs actions root_inclusive_instructions root_exclusive_instructions '
    'child_instructions input_unchanged records_joined clock_scope collected_results').split()
POLICY_KEYS = ['source_batch_calls', 'source_batch_finishes', 'provenance_policy']
CLOCK_KEYS = ('s0_wall_before s0_cpu s0_wall_after s1_wall_before s1_cpu s1_wall_after '
    's2_wall_before s2_cpu s2_wall_after s3_wall_before s3_cpu s3_wall_after '
    'wall_resolution_ns cpu_resolution_ns whole_wall_lower_ns whole_wall_ns whole_cpu_ns '
    'loop_wall_lower_ns loop_wall_ns loop_cpu_ns').split()
KEYS = FIRST_KEYS + POLICY_KEYS + CLOCK_KEYS
# Literal scalar/checksum and aggregate expectations, independent of parser helpers.
CHECKSUM = 14030166876264928576
TOTALS = {'native': (1536, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'original-sdk': (1536, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'k1': (0, 1536, 3072, 128, 2944, 192, 6144, 128, 64, 128),
    'k10': (0, 1536, 3072, 1280, 1792, 192, 6144, 1280, 64, 128),
    'k24': (0, 1536, 3072, 3072, 0, 192, 6144, 3072, 64, 128)}


def fixture(mode='k10-batch8'):
    base = BASE.get(mode, mode)
    k = {'native': 0, 'original-sdk': 0, 'k1': 1, 'k10': 10, 'k24': 24}[base]
    installed = k != 0
    retained, numerator, denominator = {0: (None, None, None), 1: (0, -14, 24),
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
            conflict_population=14, conflict_retained=retained, selection_error_numerator=numerator,
            selection_error_denominator=denominator, root_inclusive_instructions=7968,
            root_exclusive_instructions=144, child_instructions=7824, checksum=CHECKSUM))
    totals = dict(zip(('originals', 'installed_roots', 'node_rows', 'sampled', 'closed',
        'batches', 'events', 'reports', 'epochs', 'actions'), TOTALS[base]))
    terminal = dict(totals, mode=mode, blocks=64, roots=1536, calls=1536,
        root_inclusive_instructions=509952, root_exclusive_instructions=9216,
        child_instructions=500736, input_unchanged=True, records_joined=installed,
        clock_scope='matched-consumer', collected_results=1536,
        s0_wall_before=100, s0_cpu=1000, s0_wall_after=110,
        s1_wall_before=200, s1_cpu=1500, s1_wall_after=220,
        s2_wall_before=500, s2_cpu=2500, s2_wall_after=540,
        s3_wall_before=700, s3_cpu=4000, s3_wall_after=750,
        wall_resolution_ns=1, cpu_resolution_ns=1,
        whole_wall_lower_ns=590, whole_wall_ns=650, whole_cpu_ns=3000,
        loop_wall_lower_ns=280, loop_wall_ns=340, loop_cpu_ns=1000)
    if mode in NEW:
        terminal.update(source_batch_calls=8, source_batch_finishes=192, provenance_policy='source-batch8')
    return rows, terminal


def word(value):
    if value is None: return ''
    if type(value) is bool: return 'true' if value else 'false'
    return str(value)


def encode(rows, terminal, batch=True):
    lines = [HEADER] + [','.join(word(row[name]) for name in FIELDS) for row in rows]
    prefix = 'tree-comparison-batch' if batch else 'tree-comparison'
    keys = KEYS if batch else FIRST_KEYS + CLOCK_KEYS
    lines.append(prefix+' FUNCTIONAL_PASS '+' '.join(name+'='+word(terminal[name]) for name in keys))
    return ('\n'.join(lines)+'\n').encode('ascii')


def recalculate(terminal):
    for prefix, first, last in (('whole', 0, 3), ('loop', 1, 2)):
        terminal[prefix+'_wall_lower_ns'] = terminal[f's{last}_wall_before'] - terminal[f's{first}_wall_after']
        terminal[prefix+'_wall_ns'] = terminal[f's{last}_wall_after'] - terminal[f's{first}_wall_before']
        terminal[prefix+'_cpu_ns'] = terminal[f's{last}_cpu'] - terminal[f's{first}_cpu']


class BatchComparisonProtocol(unittest.TestCase):
    def accept(self, rows, terminal, mode='k10-batch8'):
        return CHECK.parse(encode(rows, terminal), b'', mode)

    def refuse(self, rows, terminal, mode='k10-batch8'):
        self.refuse_bytes(encode(rows, terminal), mode)

    def refuse_bytes(self, data, mode='k10-batch8', stderr=b''):
        with self.assertRaises(AssertionError): CHECK.parse(data, stderr, mode)

    def test_literal_new_populations_actual_modes_and_valid_clock_boundaries(self):
        values = (13455538007910626262, 14448916110156114966, 18114441086748040058, 6122101979721109698)
        self.assertEqual((5*(values[0]+values[1])+7*(values[2]+values[3])) % 2**64, CHECKSUM)
        self.assertEqual((len(FIELDS), len(KEYS)), (25, 44))
        for mode in NEW:
            rows, terminal = fixture(mode)
            output = encode(rows, terminal)
            self.assertEqual(len(output.splitlines()), 66)
            result = self.accept(rows, terminal, mode)
            self.assertEqual(result['summary'], dict(terminal, status='FUNCTIONAL_PASS'))
            self.assertEqual(result['rows'], rows)
            self.assertGreater(terminal['whole_cpu_ns'], terminal['whole_wall_ns'])
            self.assertIn('source-attested', CHECK.parse.__doc__)
            self.assertIn('No performance result', result['scope'])
            if mode != NEW[0]:
                for i, row in enumerate(rows): row['generation'] = 2**64-64+i
            terminal.update(s2_wall_before=220, s2_wall_after=250,
                wall_resolution_ns=2**64-1, cpu_resolution_ns=2**64-1)
            recalculate(terminal)
            self.assertEqual(terminal['loop_wall_lower_ns'], 0)
            self.accept(rows, terminal, mode)

    def test_all_five_legacy_routes_delegate_without_policy_or_result_change(self):
        for mode in OLD:
            rows, terminal = fixture(mode); data = encode(rows, terminal, batch=False)
            self.assertEqual(CHECK.parse(data, b'', mode), CHECK.LEGACY.parse(data, b'', mode))
            self.refuse_bytes(data, NEW[0])
            self.refuse_bytes(data.replace(b' roots=1536 ', b' roots=1535 '), mode)
            self.refuse_bytes(data.replace(b' s0_wall_before=', b' source_batch_calls=8 s0_wall_before='), mode)
        for mode in NEW:
            rows, terminal = fixture(mode)
            for old in OLD: self.refuse_bytes(encode(rows, terminal), old)
        for mode in (None, True, 1, '', 'native-batch8', 'k2-batch8', 'K10-batch8', 'k10-batch8 '):
            self.refuse_bytes(encode(*fixture()), mode)

    def test_every_new_identity_and_marker_is_authenticated_before_projection(self):
        rows, terminal = fixture(); good = encode(rows, terminal)
        # A sentinel here makes accidental dispatch/mapping observable, rather
        # than allowing a later legacy failure to hide a missing identity guard.
        with patch.object(CHECK.LEGACY, 'parse', side_effect=RuntimeError('premature legacy delegation')):
            for i in range(64):
                for wrong in OLD + (NEW[0], 'k10-batch8-wrong'):
                    bad = copy.deepcopy(rows); bad[i]['mode'] = wrong
                    self.refuse(bad, terminal)
            for name, wrong in (('mode', 'k10'), ('mode', NEW[0]), ('source_batch_calls', 7),
                    ('source_batch_calls', 9), ('source_batch_finishes', 191), ('source_batch_finishes', 193),
                    ('provenance_policy', 'source-per-call'), ('provenance_policy', 'source-batch08')):
                term = dict(terminal); term[name] = wrong
                self.refuse(rows, term)
            for name in POLICY_KEYS:
                token = (name+'='+word(terminal[name])).encode('ascii')
                self.refuse_bytes(good.replace(b' '+token, b''))
            self.refuse_bytes(good.replace(b'tree-comparison-batch ', b'tree-comparison '))
            self.refuse_bytes(good.replace(b'FUNCTIONAL_PASS', b'PASS'))

    def test_whole_transcript_ascii_lf_columns_and_stderr_are_strict(self):
        rows, terminal = fixture(); data = encode(rows, terminal)
        for bad in (data[:-1], b'\n'+data, data+b'\n', data+b'extra\n',
                data.replace(b'\n', b'\r\n'), data.replace(b'mode,block', b'block,mode', 1),
                b'\t'+data, b'\x7f'+data, b'\x80'+data, b'x'*1048577+b'\n',
                data.replace(b'k10-batch8,0,', b'"k10-batch8",0,', 1)):
            self.refuse_bytes(bad)
        for i in (1, 32, 64):
            lines = data.split(b'\n')
            words = lines[i].split(b',')
            for row in (words[:-1], words+[b'0']):
                changed = list(lines); changed[i] = b','.join(row)
                self.refuse_bytes(b'\n'.join(changed))
        self.refuse_bytes(data, stderr=b'warning\n')
        for output, stderr in ((data.decode('ascii'), b''), (bytearray(data), b''), (data, '')):
            with self.assertRaises(AssertionError): CHECK.parse(output, stderr, NEW[2])

    def test_complete_order_fixed_row_fields_and_joint_total_forgery_refuse(self):
        rows, terminal = fixture()
        for i in range(64):
            self.refuse(rows[:i]+rows[i+1:], terminal)
            self.refuse(rows[:i]+[rows[i]]+rows[i:], terminal)
            bad = copy.deepcopy(rows); bad[i] = dict(rows[(i+1) % 64]); self.refuse(bad, terminal)
            for name in FIELDS[1:]:
                if name == 'generation': continue
                bad = copy.deepcopy(rows); bad[i][name] += 1
                with self.subTest(block=i, field=name): self.refuse(bad, terminal)
        self.refuse(list(reversed(rows)), terminal)
        for mode in NEW:
            rows, terminal = fixture(mode)
            for name in ('roots', 'node_rows', 'sampled', 'closed', 'batches', 'events', 'reports',
                         'root_inclusive_instructions', 'root_exclusive_instructions', 'child_instructions'):
                bad = copy.deepcopy(rows); term = dict(terminal)
                bad[0][name] += 1; term[name] += 1
                self.refuse(bad, term, mode)

    def test_observed_generation_order_and_original_absence_are_preserved(self):
        for mode in NEW[1:]:
            rows, terminal = fixture(mode)
            for i in range(64):
                invalid = [0, 2**64]
                if i: invalid += [rows[i-1]['generation'], rows[i-1]['generation']-1]
                for generation in invalid:
                    bad = copy.deepcopy(rows); bad[i]['generation'] = generation
                    self.refuse(bad, terminal, mode)
            for name in ABSENT:
                bad = copy.deepcopy(rows); bad[0][name] = None; self.refuse(bad, terminal, mode)
        rows, terminal = fixture(NEW[0])
        for i in (0, 31, 63):
            for name in ABSENT:
                for value in (0, 1, 'None'):
                    bad = copy.deepcopy(rows); bad[i][name] = value; self.refuse(bad, terminal, NEW[0])

    def test_all_terminal_fixed_fields_key_order_and_forged_success_refuse(self):
        for mode in NEW:
            rows, terminal = fixture(mode)
            for name in FIRST_KEYS + POLICY_KEYS:
                term = dict(terminal); value = term[name]
                term[name] = not value if type(value) is bool else value+1 if type(value) is int else value+'-wrong'
                self.refuse(rows, term, mode)
        rows, terminal = fixture(); data = encode(rows, terminal)
        prefix, last, empty = data.rsplit(b'\n', 2); self.assertEqual(empty, b'')
        parts = last.split(b' ')
        for i in range(2, len(parts)):
            self.refuse_bytes(prefix+b'\n'+b' '.join(parts[:i]+parts[i+1:])+b'\n')
            self.refuse_bytes(prefix+b'\n'+b' '.join(parts[:i]+[parts[i]]+parts[i:])+b'\n')
            if i+1 < len(parts):
                bad = list(parts); bad[i], bad[i+1] = bad[i+1], bad[i]
                self.refuse_bytes(prefix+b'\n'+b' '.join(bad)+b'\n')
        self.refuse_bytes(data.replace(b'FUNCTIONAL_PASS', b'FAILED'))

    def test_raw_clock_order_and_derived_upper_lower_cpu_arithmetic(self):
        rows, terminal = fixture()
        for name in CLOCK_KEYS:
            if 'resolution' in name: continue
            term = dict(terminal); term[name] += 1; self.refuse(rows, term)
        for i in range(4):
            term = dict(terminal); term[f's{i}_wall_before'] = term[f's{i}_wall_after']+1
            recalculate(term); self.refuse(rows, term)
        for i in range(3):
            term = dict(terminal); term[f's{i+1}_wall_before'] = term[f's{i}_wall_after']-1
            recalculate(term); self.refuse(rows, term)
            term = dict(terminal); term[f's{i+1}_cpu'] = term[f's{i}_cpu']-1
            recalculate(term); self.refuse(rows, term)
        for name in ('wall_resolution_ns', 'cpu_resolution_ns'):
            term = dict(terminal); term[name] = 0; self.refuse(rows, term)
        term = dict(terminal); term['s2_cpu'] = term['s1_cpu']; recalculate(term); self.refuse(rows, term)
        term = dict(terminal); term.update(s1_wall_before=220, s2_wall_before=220, s2_wall_after=220)
        recalculate(term); self.refuse(rows, term)
        term = dict(terminal)
        for i in range(4): term.update({f's{i}_wall_before': 1, f's{i}_wall_after': 1, f's{i}_cpu': 1})
        recalculate(term); self.refuse(rows, term)
        term = dict(terminal); term['whole_wall_ns'] = term['whole_wall_lower_ns']; self.refuse(rows, term)

    def test_canonical_numeric_boolean_and_unsigned_signed_domains(self):
        rows, terminal = fixture()
        for name in FIELDS[1:]:
            invalid = ('', '+1', '01', '-0', '1.0', 'true', ' 1', str(2**64))
            if name != 'selection_error_numerator': invalid += ('-1',)
            for value in invalid:
                bad = copy.deepcopy(rows); bad[0][name] = value; self.refuse(bad, terminal)
        for value in (-(2**63)-1, 2**63, '-014'):
            bad = copy.deepcopy(rows); bad[0]['selection_error_numerator'] = value; self.refuse(bad, terminal)
        for name, value in terminal.items():
            if type(value) is int:
                for invalid in ('', '-1', '+1', '01', '1.0', 'true', str(2**64)):
                    term = dict(terminal); term[name] = invalid; self.refuse(rows, term)
            elif type(value) is bool:
                for invalid in (0, 1, 'True', 'False'):
                    term = dict(terminal); term[name] = invalid; self.refuse(rows, term)


if __name__ == '__main__':
    unittest.main()
