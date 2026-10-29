#!/usr/bin/env python3
"""Fabricated wire controls; no physical calls, timing or native evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
from pathlib import Path
import subprocess
import unittest

_path = Path(__file__).resolve().with_name('backoff_work.py')
_spec = importlib.util.spec_from_file_location('_backoff_work_controls', _path)
if _spec is None or _spec.loader is None:
    raise RuntimeError('missing local back-off checker')
parser = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(parser)

COMMENT = '# normal observer backoff; complete fixed work and raw callback ticks; no timing, accuracy, cheap-off or 520-arm qualification'
HEADER = 'id,repetition,case,seed_index,length,input_fnv1a64,value,instructions,conditional,taken,input_bytes,ret_bytes,batch,owner,generation,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,ack,ack_ordinal,completed_sequence'
FIELDS = tuple(HEADER.split(','))
# Independent literal constants; neither fixture nor mutations call parser algebra.
CASES = ((0, 1, 7552869386198218469, 11400714819323198532, 11, 1, 0, 1, 8),
    (0, 64, 7552869386198218469, 11400714819323190453, 389, 64, 63, 64, 8),
    (1, 1, 8995313910352961381, 11400714819323198531, 11, 1, 0, 1, 8),
    (1, 64, 8995313910352961381, 11400714819323190389, 389, 64, 63, 64, 8))
U64 = 18446744073709551615


def fixture(k=10, prefixes=None, generations=(17, 29, 41, 53)):
    if prefixes is None:
        a, b = (17, 47) if k == 10 else (1007, 2050)
        prefixes = [1]*a+[2]*(b-a)+[4]*(3072-b)
    rows, counts, observed = [], [0]*len(generations), set()
    sequence, first_closed, after = 0, None, False
    for g, prefix in enumerate(prefixes):
        row = [g+1, g//24+1, g % 24+1, *CASES[(g % 8)//2]]
        at = prefix-1
        sampled = counts[at] < k
        if sampled:
            invocation, completed = counts[at], sequence
            counts[at] += 1
            sequence += 1
            after |= first_closed is not None and prefix > first_closed
        else:
            invocation, completed = '', ''
            if first_closed is None:
                first_closed = prefix
        observed.add(prefix)
        row += [g//24+1, 'sampled' if sampled else 'closed', generations[at],
            invocation, prefix, 0x800008+(g//2)*16,
            0x200000+(30 if g % 2 == 0 else 48), 1000+g*100, 1050+g*100,
            7, 7, 50, 'C' if g % 24 == 23 else 'N', '' if g % 24 == 23 else g+2,
            completed]
        rows.append(list(map(str, row)))
    arms = len(generations)
    history = [f'HISTORY,{i},published,{generation}' for i, generation in enumerate(generations, 1)]
    history.append(f'HISTORY,{arms+1},removed,{generations[-1]}')
    reports = [f'REPORT,{i},{generation},{count}'
        for i, (generation, count) in enumerate(zip(generations, counts), 1)]
    end = (f'normal-observer-backoff FUNCTIONAL_PASS k={k} policy=10ms-2ms epoch_limit=520'
        f' stop_reason=Requested arms={arms} committed_arms={arms} completed_arms={arms} pending_arm=none'
        ' repetitions=128 calls=3072 helper_calls=1536 instructions=614400 conditional=99840'
        ' taken=96768 input_bytes=99840 ret_bytes=24576 pid=4242 tid=4242 controller_tid=4243'
        ' app_cpu=2 controller_cpu=3 entry=1048576 caller=2097152 install=1851943729 function=1'
        f' batches=128 events=6144 rows=3072 sampled={sequence} unsampled={3072-sequence}'
        f' reports={arms} records={sequence} actions={arms+1} journal_words=65536'
        ' next_entry_acknowledgements=2944 checkpoint_acknowledgements=128 banks=3'
        f' observed_generations={len(observed)} rearmed={str(arms > 1).lower()}'
        f' sampled_after_closed={str(after).lower()} input_unchanged=true detached=true joined=1'
        ' deadline_scope=issued-arms-and-requested-shutdown all_elapsed_due_arms=unqualified'
        ' cheap_off=false timing=none')
    return dict(comment=COMMENT, header=HEADER, rows=rows, history=history, reports=reports, end=end)


def encode(wire):
    return ('\n'.join([wire['comment'], wire['header'],
        *(','.join(row) for row in wire['rows']), *wire['history'], *wire['reports'],
        wire['end']])+'\n').encode('ascii')


def row_change(wire, g, field, value):
    wire = copy.deepcopy(wire)
    wire['rows'][g][FIELDS.index(field)] = value
    return wire


def terminal_change(wire, key, value):
    wire = copy.deepcopy(wire)
    words = wire['end'].split(' ')
    assert sum(word.startswith(key+'=') for word in words) == 1
    wire['end'] = ' '.join(key+'='+value if word.startswith(key+'=') else word for word in words)
    return wire


class Controls(unittest.TestCase):
    def check(self, wire, k=10):
        return parser.check(encode(wire), b'', k, 2, 3)

    def refuse(self, wire, k=10):
        with self.assertRaises(AssertionError):
            self.check(wire, k)

    def test_complete_mixed_populations_and_lossless_tables(self):
        for k, sampled in ((10, 30), (1000, 3000)):
            wire = fixture(k)
            got = self.check(wire, k)
            self.assertEqual((got['status'], got['k'], got['calls'], got['sampled'], got['unsampled']),
                ('FUNCTIONAL_PASS', k, 3072, sampled, 3072-sampled))
            self.assertEqual((got['row_count'], len(got['rows']), got['terminal']['rows']), (3072,)*3)
            self.assertEqual(got['totals'], dict(instructions=614400, conditional=99840,
                taken=96768, input_bytes=99840, ret_bytes=24576))
            self.assertEqual(got['table'], (HEADER+'\n'+''.join(','.join(row)+'\n' for row in wire['rows'])).encode())
            self.assertEqual(got['history_table'], ('\n'.join(wire['history'])+'\n').encode())
            self.assertEqual(got['report_table'], ('\n'.join(wire['reports'])+'\n').encode())
            for raw, row in zip(wire['rows'], got['rows']):
                self.assertEqual(tuple('' if row[key] is None else str(row[key]) for key in FIELDS), tuple(raw))
            self.assertEqual(got['coverage']['published_but_unobserved'], [41])
            self.assertEqual(got['coverage']['sampled_generations'], [17, 29, 53])
            self.assertEqual(got['coverage']['closed_generations'], [17, 29, 53])
            self.assertEqual(got['coverage']['sampled_after_closed'], 'OBSERVED')
            self.assertEqual(got['zero_raw_spans'], 0)
            self.assertIn('does not contain', got['source_attested'])
            self.assertIn('UNEXERCISED', got['scope'])

    def test_unexercised_epochs_empty_reports_and_k_domains(self):
        one = self.check(fixture(prefixes=[1]*3072, generations=(U64,)))
        self.assertFalse(one['rearmed'])
        self.assertEqual(one['coverage']['later_generation_calls'], 'UNEXERCISED')
        self.assertEqual(one['coverage']['sampled_after_closed'], 'UNEXERCISED')
        all_sampled = fixture(1000, prefixes=[1]*768+[2]*768+[3]*768+[4]*768)
        got = self.check(all_sampled, 1000)
        self.assertEqual(got['unsampled'], 0)
        self.assertEqual(got['coverage']['function_closed'], 'UNEXERCISED')
        self.assertEqual(got['coverage']['sampled_after_closed'], 'UNEXERCISED')
        maximum = fixture(prefixes=[520]*3072, generations=tuple(range(1, 521)))
        got = self.check(maximum)
        self.assertEqual((len(encode(maximum).splitlines()), len(got['history']), len(got['reports_table'])), (4116, 521, 520))
        self.assertEqual(got['coverage']['published_but_unobserved'], list(range(1, 520)))
        self.assertEqual(got['observed_generations'], 1)
        self.assertTrue(got['rearmed'])
        for k in (0, 1, 9, 11, 999, 1001, True, '10', None):
            with self.assertRaises(AssertionError):
                parser.check(encode(fixture()), b'', k, 2, 3)
        self.refuse(fixture(1000))

    def test_all_fixed_work_population_and_column_mutations(self):
        wire = fixture()
        for g in (0, 23, 24, 3071):
            for count in (0, 2):
                bad = copy.deepcopy(wire)
                bad['rows'][g:g+1] = [bad['rows'][g]]*count
                self.refuse(bad)
        bad = copy.deepcopy(wire); bad['rows'][23], bad['rows'][24] = bad['rows'][24], bad['rows'][23]
        self.refuse(bad)
        for field in FIELDS[:12]:
            self.refuse(row_change(wire, 0, field, str(int(wire['rows'][0][FIELDS.index(field)])+1)))
        for field in FIELDS:
            bad = copy.deepcopy(wire); del bad['rows'][0][FIELDS.index(field)]
            self.refuse(bad)
        bad = copy.deepcopy(wire); bad['rows'][0].append('0'); self.refuse(bad)
        # A coherently inflated advertised work total is not independent work truth.
        bad = copy.deepcopy(wire)
        for row in bad['rows']:
            row[7] = str(int(row[7])+1)
        self.refuse(terminal_change(bad, 'instructions', '617472'))
        self.refuse(row_change(wire, 3071, 'value', str(int(wire['rows'][-1][6]) & 0xffffffff)))

    def test_sampled_closed_invocations_sequences_and_prefixes(self):
        wire = fixture()
        for g, field, value in ((0, 'owner', 'closed'), (0, 'owner', 'Initial'),
            (10, 'owner', 'sampled'), (0, 'invocation', '1'), (17, 'invocation', '10'),
            (17, 'completed_sequence', '0'), (0, 'completed_sequence', ''),
            (10, 'invocation', '0'), (10, 'completed_sequence', '10'),
            (0, 'history_prefix', '0'), (0, 'history_prefix', '5'),
            (17, 'history_prefix', '1'), (47, 'generation', '41'),
            (0, 'generation', '0'), (0, 'generation', '29')):
            self.refuse(row_change(wire, g, field, value))
        # Move a coherent generation/prefix backward after a newer binding.
        bad = row_change(wire, 48, 'generation', '29')
        bad = row_change(bad, 48, 'history_prefix', '2')
        self.refuse(bad)
        # Relabelling an early sampled row closed cannot erase required admission.
        bad = row_change(wire, 9, 'owner', 'closed')
        bad = row_change(bad, 9, 'invocation', '')
        self.refuse(row_change(bad, 9, 'completed_sequence', ''))
        bad = row_change(wire, 10, 'owner', 'sampled')
        bad = row_change(bad, 10, 'invocation', '10')
        self.refuse(row_change(bad, 10, 'completed_sequence', '10'))
        for g in (24, 48, 3060):
            if wire['rows'][g][13] == 'sampled':
                self.refuse(row_change(wire, g, 'completed_sequence', str(g)))
        self.refuse(row_change(fixture(1000), 2049, 'invocation', '1000'), 1000)

    def test_history_and_report_identity_counts_and_order(self):
        wire = fixture()
        for group in ('history', 'reports'):
            for i in range(len(wire[group])):
                bad = copy.deepcopy(wire); del bad[group][i]; self.refuse(bad)
                bad = copy.deepcopy(wire); bad[group].insert(i, bad[group][i]); self.refuse(bad)
            bad = copy.deepcopy(wire); bad[group][0], bad[group][1] = bad[group][1], bad[group][0]; self.refuse(bad)
        for i, line in ((0, 'HISTORY,1,published,0'), (1, 'HISTORY,2,published,17'),
            (1, 'HISTORY,2,published,16'), (2, 'HISTORY,3,removed,41'),
            (4, 'HISTORY,5,removed,41'), (0, 'HISTORY,01,published,17'),
            (0, 'HISTORY,1,published,17,extra')):
            bad = copy.deepcopy(wire); bad['history'][i] = line; self.refuse(bad)
        for i, line in ((0, 'REPORT,1,17,9'), (0, 'REPORT,1,17,11'),
            (2, 'REPORT,3,41,1'), (1, 'REPORT,2,17,10'),
            (0, 'REPORT,0,17,10'), (0, 'REPORT,1,17,10,extra')):
            bad = copy.deepcopy(wire); bad['reports'][i] = line; self.refuse(bad)
        bad = copy.deepcopy(wire)
        bad['reports'][0] = 'REPORT,1,17,9'
        bad['reports'][1] = 'REPORT,2,29,11'
        self.refuse(bad)  # Same total cannot substitute for per-owner equality.

    def test_stack_continuations_ack_and_batch_boundaries(self):
        wire = fixture()
        for g, field, value in ((0, 'entry_rsp', '0'), (0, 'entry_rsp', '120'),
            (0, 'entry_rsp', str(U64-7)), (0, 'entry_rsp', str(0x800000)),
            (1, 'entry_rsp', str(0x800018)), (0, 'return_word', str(0x200000+48)),
            (1, 'return_word', str(0x200000+30)), (0, 'ack', 'C'),
            (23, 'ack', 'N'), (23, 'ack_ordinal', '25'),
            (24, 'ack_ordinal', '2'), (24, 'batch', '1'), (3071, 'batch', '127')):
            self.refuse(row_change(wire, g, field, value))
        bad = row_change(wire, 0, 'entry_rsp', str(U64-23))
        bad = row_change(bad, 1, 'entry_rsp', str(U64-23))
        self.assertEqual(self.check(bad)['rows'][0]['entry_rsp'], U64-23)

    def test_raw_clock_aux_zero_max_and_no_cross_call_inference(self):
        wire = fixture()
        for g in range(3072):
            start, end = ((U64, U64) if g % 2 else (0, U64))
            for field, value in (('start_ticks', start), ('end_ticks', end),
                ('raw_ticks', end-start), ('start_aux', 4294967295), ('end_aux', 4294967295)):
                wire['rows'][g][FIELDS.index(field)] = str(value)
        got = self.check(wire)
        self.assertEqual(got['zero_raw_spans'], 1536)
        self.assertEqual(got['rows'][0]['raw_ticks'], U64)
        self.assertEqual(got['rows'][2]['start_ticks'], 0)  # No invented chronology.
        for g, field, value in ((0, 'end_ticks', str(U64-1)), (1, 'start_ticks', str(U64-1)),
            (1, 'end_ticks', str(U64-1)), (0, 'raw_ticks', '0'), (0, 'end_aux', '7'),
            (0, 'start_aux', '4294967296'), (0, 'start_ticks', str(U64+1))):
            self.refuse(row_change(wire, g, field, value))
        bad = row_change(wire, 0, 'start_aux', '4294967296')
        self.refuse(row_change(bad, 0, 'end_aux', '4294967296'))

    def test_terminal_census_identity_coverage_and_expected_request(self):
        wire = fixture()
        for key, value in (('pid', '0'), ('pid', '2147483648'), ('tid', '4243'),
            ('controller_tid', '4242'), ('controller_tid', '0'), ('controller_tid', '2147483648'),
            ('app_cpu', '3'), ('controller_cpu', '2'), ('entry', '0'), ('entry', str(U64-36)),
            ('caller', '0'), ('caller', str(U64-66)), ('policy', '10ms-3ms'),
            ('stop_reason', 'EpochLimit'), ('arms', '0'), ('arms', '521'),
            ('committed_arms', '3'), ('completed_arms', '3'), ('pending_arm', '0'),
            ('sampled', '29'), ('unsampled', '3043'), ('records', '29'),
            ('reports', '3'), ('actions', '6'), ('observed_generations', '4'),
            ('rearmed', 'false'), ('sampled_after_closed', 'false'),
            ('input_unchanged', 'false'), ('detached', 'false'), ('joined', '0'),
            ('all_elapsed_due_arms', 'qualified'), ('cheap_off', 'true'), ('timing', 'ns')):
            self.refuse(terminal_change(wire, key, value))
        words = wire['end'].split(' ')
        for i in range(len(words)):
            for replacement in ([], [words[i], words[i]], [words[i]+'!']):
                bad = copy.deepcopy(wire); bad['end'] = ' '.join(words[:i]+replacement+words[i+1:])
                self.refuse(bad)
        for i in range(2, len(words)-1):
            bad = copy.deepcopy(wire); shifted = list(words)
            shifted[i], shifted[i+1] = shifted[i+1], shifted[i]
            bad['end'] = ' '.join(shifted); self.refuse(bad)
        for key in ('epoch_limit', 'repetitions', 'calls', 'helper_calls', 'instructions',
            'conditional', 'taken', 'input_bytes', 'ret_bytes', 'install', 'function',
            'batches', 'events', 'rows', 'journal_words', 'next_entry_acknowledgements',
            'checkpoint_acknowledgements', 'banks'):
            word = next(word for word in words if word.startswith(key+'='))
            self.refuse(terminal_change(wire, key, str(int(word.split('=')[1])+1)))
        for a, c in ((2, 2), (-1, 3), (2, 1024), (True, 3), (2, '3'), (3, 2), (0, 3)):
            with self.assertRaises(AssertionError):
                parser.check(encode(wire), b'', 10, a, c)
        limits = terminal_change(wire, 'pid', '2147483647')
        limits = terminal_change(limits, 'tid', '2147483647')
        limits = terminal_change(limits, 'controller_tid', '2147483646')
        limits = terminal_change(limits, 'entry', str(U64-37))
        limits = terminal_change(limits, 'caller', str(U64-67))
        for g, row in enumerate(limits['rows']):
            row[18] = str(U64-67+(30 if g % 2 == 0 else 48))
        self.assertEqual(self.check(limits)['entry'], U64-37)
        limits = terminal_change(limits, 'app_cpu', '0')
        limits = terminal_change(limits, 'controller_cpu', '1023')
        got = parser.check(encode(limits), b'', 10, 0, 1023)
        self.assertEqual((got['app_cpu'], got['controller_cpu']), (0, 1023))

    def test_framing_canonical_domains_and_all_caps(self):
        wire = fixture(); data = encode(wire)
        for bad in (b'', data[:-1], data+b'\n', b'extra\n'+data, data+b'extra\n',
            data+b'\xff', b'x'*906305, data.decode(), bytearray(data), None):
            with self.assertRaises(AssertionError):
                parser.check(bad, b'', 10, 2, 3)
        for separator in (b'\r\n', b'\r', b'\t', b'\v', b'\f', b'\x1c', b'\x00'):
            with self.assertRaises(AssertionError):
                parser.check(data.replace(b'\n', separator, 1), b'', 10, 2, 3)
        for stderr in (b' ', b'warning\n', '', bytearray(), None):
            with self.assertRaises(AssertionError):
                parser.check(data, stderr, 10, 2, 3)
        for field in ('comment', 'header'):
            bad = copy.deepcopy(wire); bad[field] += 'extra'; self.refuse(bad)
        for value in ('', '00', '01', '+1', '-1', '1.0', '1e0', ' 1', '1 ', str(U64+1), '9'*21):
            for field in ('id', 'invocation', 'history_prefix', 'completed_sequence'):
                self.refuse(row_change(wire, 0, field, value))
        for field in ('generation', 'entry_rsp', 'return_word', 'end_ticks', 'end_aux', 'raw_ticks', 'ack_ordinal'):
            self.refuse(row_change(wire, 0, field, str(U64+1)))
        self.refuse(row_change(wire, 0, 'id', '9'*273))
        for group in ('history', 'reports'):
            bad = copy.deepcopy(wire); bad[group][0] += ' '*65; self.refuse(bad)
        bad = copy.deepcopy(wire); bad['end'] += ' '*4096; self.refuse(bad)

    def test_local_import_and_optimized_entrypoints_refuse(self):
        self.assertEqual(Path(parser.__file__).resolve(), Path(__file__).resolve().with_name('backoff_work.py'))
        for name in ('backoff_work.py', Path(__file__).name):
            path = str(Path(__file__).resolve().with_name(name))
            for tail in ([path], ['-c', 'import runpy,sys; runpy.run_path(sys.argv[1])', path]):
                child = subprocess.run([sys.executable, '-B', '-O', *tail],
                    capture_output=True, timeout=5, check=False)
                self.assertEqual((child.returncode, child.stdout, child.stderr),
                    (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
