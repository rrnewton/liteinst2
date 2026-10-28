#!/usr/bin/env python3
"""Adversarial fabricated population transcripts; no native subject execution."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('tree_population_check', Path(__file__).with_name('check_population.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

HEADER = ('k,external_id,seed,case,node,parent,function,ordinal,owner,generation,'
    'invocation,inclusive_instructions,exclusive_instructions,value,gate_sequence,'
    'start_ticks,end_ticks,start_aux,end_aux')
FIELDS = HEADER.split(',')
# Independently fixed scalar results: four input cases, child then caller+1.
VALUES = ((13455538007910626261, 14448916110156114965),
          (18114441086748040057, 6122101979721109697))
TERMINALS = {
    1: 'tree-population FUNCTIONAL_PASS k=1 originals=24 roots=24 nodes=48 sampled=2 closed=46 batches=3 events=96 reports=2 actions=2 conflict_population=14 conflict_retained=0 selection_error_numerator=-14 selection_error_denominator=24 root_inclusive_instructions=7968 root_exclusive_instructions=144 child_instructions=7824 input_unchanged=true records_joined=true uncalibrated=true',
    10: 'tree-population FUNCTIONAL_PASS k=10 originals=24 roots=24 nodes=48 sampled=20 closed=28 batches=3 events=96 reports=20 actions=2 conflict_population=14 conflict_retained=0 selection_error_numerator=-140 selection_error_denominator=240 root_inclusive_instructions=7968 root_exclusive_instructions=144 child_instructions=7824 input_unchanged=true records_joined=true uncalibrated=true',
    24: 'tree-population FUNCTIONAL_PASS k=24 originals=24 roots=24 nodes=48 sampled=48 closed=0 batches=3 events=96 reports=48 actions=2 conflict_population=14 conflict_retained=14 selection_error_numerator=0 selection_error_denominator=576 root_inclusive_instructions=7968 root_exclusive_instructions=144 child_instructions=7824 input_unchanged=true records_joined=true uncalibrated=true',
}


def rows(k):
    out = []
    for index in range(24):
        phase = int(index >= 10)
        seed = (0x1234567887654320, 0xfedcba9801234567)[index % 2]
        start = 1000 + 100 * index
        for node in (0, 1):
            out.append(dict(k=k, external_id=index+1, seed=seed,
                case=('fit2', 'conflict3')[phase], node=node,
                parent=index+1 if node else '', function=node+1, ordinal=2*index+node+1,
                owner='sampled' if index < k else 'closed', generation=7,
                invocation=2*index+node if index < k else '',
                inclusive_instructions=(332, 326)[node], exclusive_instructions=(6, 326)[node],
                value=VALUES[phase][index % 2]+1-node, gate_sequence=25+index,
                start_ticks=start+20*node, end_ticks=start+80-20*node, start_aux=9, end_aux=9))
    return out


def encode(source, k=10, terminal=None):
    # Literal unquoted grammar of Rust println!, independent of parser helpers.
    text = [HEADER, *(','.join(str(row[key]) for key in FIELDS) for row in source),
            TERMINALS[k] if terminal is None else terminal]
    return ('\n'.join(text)+'\n').encode('ascii')


class PopulationProtocol(unittest.TestCase):
    def accept(self, source, k=10, terminal=None):
        return CHECK.parse(encode(source, k, terminal), b'', k)

    def refuse(self, source, k=10, terminal=None):
        with self.assertRaises((AssertionError, ValueError, UnicodeError)):
            self.accept(source, k, terminal)

    def test_complete_all_three_policies_and_legal_numeric_boundaries(self):
        for k in (1, 10, 24):
            parsed = self.accept(rows(k), k)
            result = parsed['summary']
            self.assertEqual((result['sampled'], result['closed'], result['reports']), (2*k, 48-2*k, 2*k))
            self.assertEqual((len(parsed['rows']), result['generation'], result['aux']), (48, 7, 9))
            self.assertEqual((result['root_inclusive_instructions'], result['root_exclusive_instructions'], result['child_instructions']), (7968, 144, 7824))
            self.assertEqual(result['selection_error_numerator'], {1: -14, 10: -140, 24: 0}[k])
            good = rows(k)
            for row in good:
                row.update(generation=2**64-1, start_ticks=2**64-1, end_ticks=2**64-1,
                    start_aux=2**32-1, end_aux=2**32-1)
            self.accept(good, k)  # Equal ordered endpoints are legal raw observations.
        for k in (0, 2, 25, True, 1.0, '1'):
            with self.assertRaises(AssertionError):
                CHECK.parse(encode(rows(1), 1), b'', k)

    def test_missing_duplicate_reordered_nodes_and_batches_refuse(self):
        good = rows(10)
        self.accept(good)
        for i in range(48):
            self.refuse(good[:i]+good[i+1:])
            self.refuse(good[:i]+[good[i]]+good[i:])
            bad = copy.deepcopy(good)
            bad[i] = dict(good[(i+1) % 48])
            self.refuse(bad)
        self.refuse(list(reversed(good)))
        self.refuse(good[16:32]+good[:16]+good[32:])
        self.refuse([good[1], good[0], *good[2:]])

    def test_every_identity_work_value_parent_and_case_join(self):
        good = rows(10)
        for i in range(48):
            for key in ('k', 'external_id', 'seed', 'node', 'function', 'ordinal',
                        'inclusive_instructions', 'exclusive_instructions', 'value'):
                bad = copy.deepcopy(good); bad[i][key] += 1
                with self.subTest(i=i, key=key): self.refuse(bad)
            bad = copy.deepcopy(good)
            bad[i]['parent'] = 1 if good[i]['parent'] == '' else ''
            self.refuse(bad)
            bad = copy.deepcopy(good)
            bad[i]['case'] = 'conflict3' if good[i]['case'] == 'fit2' else 'fit2'
            self.refuse(bad)
        # Changing a label and scalar consistently still changes the frozen population.
        bad = copy.deepcopy(good)
        for node in (0, 1):
            bad[20+node].update(case='fit2', value=VALUES[0][0]+1-node)
        self.refuse(bad)

    def test_owner_invocation_and_closed_empty_fields_are_exact(self):
        for k in (1, 10, 24):
            good = rows(k)
            for i in range(48):
                bad = copy.deepcopy(good)
                if i < 2*k:
                    bad[i].update(owner='closed', invocation='')
                else:
                    bad[i].update(owner='sampled', invocation=i)
                self.refuse(bad, k)
                bad = copy.deepcopy(good)
                bad[i]['invocation'] = '' if i < 2*k else i
                self.refuse(bad, k)
                if i < 2*k:
                    bad = copy.deepcopy(good); bad[i]['invocation'] = (i+1) % (2*k)
                    self.refuse(bad, k)
            bad = copy.deepcopy(good); bad[0]['owner'] = 'removed'
            self.refuse(bad, k)

    def test_gate_baseline_and_common_nonzero_generation(self):
        good = rows(10)
        shifted = copy.deepcopy(good)
        for row in shifted: row['gate_sequence'] += 1
        self.refuse(shifted)  # Still consecutive, but contradicts the24 originals.
        for i in range(48):
            for key in ('gate_sequence', 'generation'):
                bad = copy.deepcopy(good); bad[i][key] += 1
                self.refuse(bad)
        for generation in (0, 2**64):
            bad = copy.deepcopy(good)
            for row in bad: row['generation'] = generation
            self.refuse(bad)
        bad = copy.deepcopy(good)
        for row in bad[1::2]: row['generation'] += 1
        self.refuse(bad)

    def test_timestamp_nesting_order_aux_and_one_tick_boundaries(self):
        good = rows(10)
        for i in range(48):
            bad = copy.deepcopy(good); bad[i]['end_ticks'] = bad[i]['start_ticks']-1
            self.refuse(bad)
            for key in ('start_aux', 'end_aux'):
                bad = copy.deepcopy(good); bad[i][key] += 1
                self.refuse(bad)
        for root in range(0, 48, 2):
            bad = copy.deepcopy(good); bad[root+1]['start_ticks'] = bad[root]['start_ticks']-1
            self.refuse(bad)  # Child itself remains monotonic.
            bad = copy.deepcopy(good); bad[root+1]['end_ticks'] = bad[root]['end_ticks']+1
            self.refuse(bad)
            bad = copy.deepcopy(good)
            for row in bad[root:root+2]: row.update(start_aux=10, end_aux=10)
            self.refuse(bad)  # Both nodes locally agree, but the population clock changes.
            if root:
                bad = copy.deepcopy(good); bad[root]['start_ticks'] = bad[root-2]['end_ticks']-1
                self.refuse(bad)

    def test_literal_lf_and_canonical_unsigned_field_grammar(self):
        good = rows(10); data = encode(good)
        numeric = set(FIELDS)-{'case', 'owner'}
        for key in numeric:
            for word in ('01', '-1', '+1', '1.0', '1e0', 'true', ' 1', str(2**64)):
                bad = copy.deepcopy(good); bad[1][key] = word
                with self.subTest(key=key, word=word): self.refuse(bad)
        for key in ('start_aux', 'end_aux'):
            bad = copy.deepcopy(good); bad[0][key] = 2**32
            self.refuse(bad)
        for index, byte in enumerate(data):
            if byte == 10:
                for separator in (b'\r', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
                    with self.assertRaises(AssertionError):
                        CHECK.parse(data[:index]+separator+data[index+1:], b'', 10)
        for changed in (data[:-1], data+b'\n', b'\n'+data, data.replace(b'\n', b'\r\n'),
                        data.replace(b'k,external_id', b'external_id,k', 1),
                        data.replace(b',fit2,', b',fit2,extra,', 1),
                        data.replace(b',fit2,', b',"fit2",', 1), b'x'*1048577):
            with self.assertRaises(AssertionError): CHECK.parse(changed, b'', 10)
        with self.assertRaises(AssertionError): CHECK.parse(data, b'warning\n', 10)

    def test_exact_terminal_no_partial_forged_or_extra_success(self):
        for k in (1, 10, 24):
            good = rows(k); terminal = TERMINALS[k]
            for token in terminal.split()[2:]:
                key, value = token.split('=')
                changed = 'false' if value == 'true' else str(int(value)+1)
                self.refuse(good, k, terminal.replace(token, key+'='+changed, 1))
            for changed in (terminal.replace('FUNCTIONAL_PASS', 'PASS'),
                            terminal.replace('FUNCTIONAL_PASS', 'FAILED'),
                            terminal+' extra=true', terminal+'\n'+terminal, '',
                            terminal.replace('input_unchanged=true ', '')):
                self.refuse(good, k, changed)


if __name__ == '__main__':
    unittest.main()
