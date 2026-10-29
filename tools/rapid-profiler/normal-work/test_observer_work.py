#!/usr/bin/env python3
"""Fabricated transcript mutations only; no execution or native-state evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
from pathlib import Path
import subprocess
import unittest
import observer_work as parser

COMMENT = '# normal observer work; semantic counts and raw callback ticks only; no accuracy or performance claim'
HEADER = 'id,repetition,case,seed_index,length,input_fnv1a64,value,instructions,conditional,taken,input_bytes,ret_bytes,batch,owner,generation,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,ack,ack_ordinal'
FIELDS = tuple(HEADER.split(','))
# Literal independent scalar/work/digest constants; never call parser._cases().
CASES = ((0, 1, 7552869386198218469, 11400714819323198532, 11, 1, 0, 1, 8),
    (0, 64, 7552869386198218469, 11400714819323190453, 389, 64, 63, 64, 8),
    (1, 1, 8995313910352961381, 11400714819323198531, 11, 1, 0, 1, 8),
    (1, 64, 8995313910352961381, 11400714819323190389, 389, 64, 63, 64, 8))


def terminal(mode):
    fixed = ('normal-observer-work FUNCTIONAL_PASS mode='+mode+
        ' selection=normal-exact-37-v1 repetitions=128 calls=3072 helper_calls=1536'
        ' instructions=614400 conditional=99840 taken=96768 input_bytes=99840 ret_bytes=24576'
        ' pid=4242 tid=4242 entry=1048576 caller=2097152')
    if mode == 'native':
        sdk = (' install=none function=none generation=none batches=0 events=0 reports=0'
            ' records=0 actions=0 journal_words=0 next_entry_acknowledgements=0 checkpoint_acknowledgements=0')
    else:
        sdk = (' install=1852793459 function=1 generation=17 batches=128 events=6144 reports=1'
            ' records=3072 actions=2 journal_words=65536 next_entry_acknowledgements=2944 checkpoint_acknowledgements=128')
    return fixed+sdk+' input_unchanged=true joined=true'


def fixture(mode):
    rows = []
    for g in range(3072):
        row = [g+1, g//24+1, g % 24+1, *CASES[(g % 8)//2]]
        if mode == 'native':
            row += ['']*14
        else:
            row += [g//24+1, 'sampled', 17, g, 1, 0x800008+(g//2)*16,
                0x200000+(30 if g % 2 == 0 else 48), 1000+g*100, 1050+g*100,
                7, 7, 50, 'C' if g % 24 == 23 else 'N', '' if g % 24 == 23 else g+2]
        rows.append(tuple(map(str, row)))
    return tuple(rows)


FIXTURES = {mode: fixture(mode) for mode in ('native', 'always-on')}


def encode(mode, rows=None, *, comment=COMMENT, header=HEADER, end=None):
    rows = FIXTURES[mode] if rows is None else rows
    return ('\n'.join([comment, header, *(','.join(row) for row in rows),
        terminal(mode) if end is None else end])+'\n').encode('ascii')


def changed(mode, index, field, value):
    rows = list(FIXTURES[mode]); row = list(rows[index]); row[field] = value
    rows[index] = row
    return rows


class Controls(unittest.TestCase):
    def refuse(self, mode='always-on', rows=None, **kwargs):
        with self.assertRaises(AssertionError):
            parser.check(encode(mode, rows, **kwargs), b'', mode)

    def test_complete_both_modes_and_lossless_projection(self):
        for mode in ('native', 'always-on'):
            rows = FIXTURES[mode]; got = parser.check(encode(mode), b'', mode)
            self.assertEqual((got['status'], got['mode'], got['calls'], got['helper_calls']),
                ('FUNCTIONAL_PASS', mode, 3072, 1536))
            self.assertEqual(got['selection'], 'normal-exact-37-v1')
            self.assertEqual(got['totals'], dict(instructions=614400, conditional=99840,
                taken=96768, input_bytes=99840, ret_bytes=24576))
            self.assertEqual(len(got['rows']), 3072)
            self.assertEqual(got['table'], (HEADER+'\n'+''.join(','.join(row)+'\n' for row in rows)).encode())
            for raw, actual in zip(rows, got['rows']):
                self.assertEqual(tuple('' if actual[k] is None else str(actual[k]) for k in FIELDS), raw)
            self.assertEqual((got['pid'], got['tid'], got['entry'], got['caller']), (4242, 4242, 1048576, 2097152))
            self.assertTrue(got['input_unchanged'] and got['joined'])
            self.assertEqual(got['zero_raw_spans'], None if mode == 'native' else 0)
            self.assertEqual(tuple(got[k] for k in ('batches', 'events', 'reports', 'records', 'actions',
                'journal_words', 'next_entry_acknowledgements', 'checkpoint_acknowledgements')),
                (0,)*8 if mode == 'native' else (128, 6144, 1, 3072, 2, 65536, 2944, 128))
            if mode == 'native':
                self.assertTrue(all(got[k] is None for k in ('install', 'function', 'generation')))
            self.assertIn('uncalibrated', got['scope'])
            self.assertIn('does not independently', got['source_attested'])

    def test_order_population_header_and_all_columns(self):
        for mode in ('native', 'always-on'):
            rows = FIXTURES[mode]
            for index in (0, 23, 24, 3055, 3071):
                self.refuse(mode, rows[:index]+rows[index+1:])
                self.refuse(mode, rows[:index]+(rows[index],)+rows[index:])
                bad = list(rows); other = (index+1) % len(rows)
                bad[index], bad[other] = bad[other], bad[index]; self.refuse(mode, bad)
            for field in range(26):
                bad = list(rows); bad[0] = rows[0][:field]+rows[0][field+1:]
                self.refuse(mode, bad)
            bad = list(rows); bad[0] = rows[0]+('0',); self.refuse(mode, bad)
            for header in ('', HEADER+',extra', HEADER.replace('id,', 'case,', 1),
                HEADER.replace('start_ticks,end_ticks', 'end_ticks,start_ticks')):
                self.refuse(mode, header=header)

    def test_every_fixed_column_and_coherent_work_corruption(self):
        for field in range(12):
            for mode in ('native', 'always-on'):
                self.refuse(mode, changed(mode, 0, field, str(int(FIXTURES[mode][0][field])+1)))
        for field in range(5, 12):
            rows = [list(row) for row in FIXTURES['always-on']]
            for row in rows: row[field] = str(int(row[field])+1)
            end = terminal('always-on')
            if field >= 7:
                name = FIELDS[field]; total = sum(int(row[field]) for row in rows)
                end = end.replace(name+'='+str(sum(int(row[field]) for row in FIXTURES['always-on'])), name+'='+str(total))
            self.refuse(rows=rows, end=end)
        # Same32-bit-low portion is insufficient for an actual full-u64 result.
        rows = changed('always-on', 3071, 6, str(int(FIXTURES['always-on'][3071][6]) & 0xffffffff))
        self.refuse(rows=rows)

    def test_native_absences_and_always_on_global_identity(self):
        for field in range(12, 26):
            self.refuse('native', changed('native', 0, field, FIXTURES['always-on'][0][field] or '0'))
            self.refuse(rows=changed('always-on', 0, field, ''))
        for field, value in ((12, '2'), (13, 'closed'), (14, '0'), (14, '18'), (15, '1'), (16, '2')):
            self.refuse(rows=changed('always-on', 0, field, value))
        # A different real generation is allowed only when every row and the terminal agree.
        rows = [list(row) for row in FIXTURES['always-on']]
        for row in rows: row[14] = '18446744073709551615'
        got = parser.check(encode('always-on', rows, end=terminal('always-on').replace('generation=17',
            'generation=18446744073709551615')), b'', 'always-on')
        self.assertEqual(got['generation'], (1 << 64)-1)
        self.refuse(rows=rows)

    def test_late_batch_resets_and_acknowledgement_boundaries(self):
        for index in (24, 1536, 3048, 3071):
            for field, value in ((0, str(index % 24+1)), (12, '1'), (15, str(index % 24)),
                (16, '0'), (14, '18')):
                self.refuse(rows=changed('always-on', index, field, value))
        for index in (22, 23, 24, 47, 3047, 3048, 3070, 3071):
            rows = list(FIXTURES['always-on']); row = list(rows[index])
            row[24:26] = ['N', str(index+2)] if index % 24 == 23 else ['C', '']
            rows[index] = row; self.refuse(rows=rows)
        self.refuse(rows=changed('always-on', 3070, 25, '24'))
        self.refuse(rows=changed('always-on', 3071, 25, '0'))

    def test_endpoint_arithmetic_aux_and_zero_extremes(self):
        for index in (0, 3071):
            start = int(FIXTURES['always-on'][index][19])
            for field, value in ((19, str(start+1)), (20, str(start-1)),
                    (20, str(start+51)), (23, '49'), (21, '8'), (22, '4294967296')):
                self.refuse(rows=changed('always-on', index, field, value))
        rows = [list(row) for row in FIXTURES['always-on']]
        for row in rows: row[21:23] = ['4294967296', '4294967296']
        self.refuse(rows=rows)  # Equality alone cannot authenticate the u32 domain.
        for start, end, aux in ((0, 0, 0), ((1 << 64)-1, (1 << 64)-1, (1 << 32)-1),
                (0, (1 << 64)-1, 0)):
            rows = [list(row) for row in FIXTURES['always-on']]
            for row in rows: row[19:24] = list(map(str, (start, end, aux, aux, end-start)))
            got = parser.check(encode('always-on', rows), b'', 'always-on')
            self.assertEqual(got['zero_raw_spans'], 3072 if start == end else 0)
            self.assertTrue(all(r['raw_ticks'] == end-start for r in got['rows']))
        rows = [list(row) for row in FIXTURES['always-on']]
        for g, row in enumerate(rows):
            start = 100000-g  # No cross-row chronology or shared AUX predicate exists.
            row[19:24] = list(map(str, (start, start+g, g % 9, g % 9, g)))
        got = parser.check(encode('always-on', rows), b'', 'always-on')
        self.assertEqual(got['rows'][-1]['raw_ticks'], 3071)

    def test_stack_pairs_and_terminal_continuations(self):
        for field, value in ((17, '0'), (17, '16'), (17, '18446744073709551608'),
                (18, str(0x200000+48))):
            self.refuse(rows=changed('always-on', 0, field, value))
        for index in (0, 3071):
            self.refuse(rows=changed('always-on', index, 17, str(int(FIXTURES['always-on'][index][17])+16)))
        rows = [list(row) for row in FIXTURES['always-on']]
        for g, row in enumerate(rows): row[18] = str(0x200000+(48 if g % 2 == 0 else 30))
        self.refuse(rows=rows)
        self.refuse(end=terminal('always-on').replace('caller=2097152', 'caller=2097168'))
        # Even a coherent pair must leave room for the producer's red zone.
        for rsp in (8, 120):
            bad = [list(row) for row in FIXTURES['always-on']]
            for g in (0, 1): bad[g][17] = str(rsp)
            self.refuse(rows=bad)
        # Legal address differences across helper pairs are preserved, not normalized.
        for g in (0, 1): rows[g][17] = '136'
        for g in (3070, 3071): rows[g][17] = str((1 << 64)-24)
        for g, row in enumerate(rows): row[18] = str(0x300000+(30 if g % 2 == 0 else 48))
        got = parser.check(encode('always-on', rows,
            end=terminal('always-on').replace('caller=2097152', 'caller=3145728')), b'', 'always-on')
        self.assertEqual(got['rows'][0]['entry_rsp'], 136)  # No VMA is exported or inferred.
        self.assertEqual(got['rows'][-1]['entry_rsp'], (1 << 64)-24)

    def test_canonical_numeric_domains(self):
        for field in range(26):
            if field in (13, 24): continue
            for value in ('', '00', '01', '+1', '-1', '1.0', '1e0', ' 1', '1 ',
                    '18446744073709551616', '9'*21):
                self.refuse(rows=changed('always-on', 0, field, value))
        for field in (19, 20, 23):
            self.refuse(rows=changed('always-on', 3071, field, '18446744073709551616'))

    def test_exact_terminal_all_keys_modes_and_counts(self):
        for mode in ('native', 'always-on'):
            words = terminal(mode).split(' ')
            for index, word in enumerate(words):
                for replacement in ([], [word, word], [word+'!']):
                    self.refuse(mode, end=' '.join(words[:index]+replacement+words[index+1:]))
            for name, value in (('pid', '0'), ('pid', '4294967296'), ('tid', '4243'),
                ('entry', '0'), ('entry', str((1 << 64)-37)), ('caller', '0'),
                ('caller', str((1 << 64)-67)), ('calls', '03072'), ('input_unchanged', 'false'),
                ('joined', 'false'), ('selection', 'normal-reference-exact-37-v1')):
                bad = [name+'='+value if word.startswith(name+'=') else word for word in words]
                self.refuse(mode, end=' '.join(bad))
            for index in range(2, len(words)-1):
                bad = list(words); bad[index], bad[index+1] = bad[index+1], bad[index]
                self.refuse(mode, end=' '.join(bad))
            other = 'native' if mode == 'always-on' else 'always-on'
            with self.assertRaises(AssertionError): parser.check(encode(mode), b'', other)
        self.refuse(end=terminal('always-on').replace('generation=17', 'generation=0'))
        for name in ('install', 'function', 'generation'):
            self.refuse('native', end=terminal('native').replace(name+'=none', name+'=0'))
        for key in ('batches', 'events', 'reports', 'records', 'actions', 'journal_words',
                'next_entry_acknowledgements', 'checkpoint_acknowledgements'):
            words = terminal('always-on').split(' ')
            bad = [key+'='+str(int(word.split('=')[1])+1) if word.startswith(key+'=') else word for word in words]
            self.refuse(end=' '.join(bad))
        end = terminal('native').replace('pid=4242', 'pid=4294967295').replace('tid=4242', 'tid=4294967295')
        end = end.replace('entry=1048576', 'entry='+str((1 << 64)-38))
        end = end.replace('caller=2097152', 'caller='+str((1 << 64)-68))
        got = parser.check(encode('native', end=end), b'', 'native')
        self.assertEqual((got['pid'], got['entry'], got['caller']),
            ((1 << 32)-1, (1 << 64)-38, (1 << 64)-68))

    def test_ascii_lf_types_and_caps(self):
        data = encode('always-on')
        for bad in (b'', data[:-1], data+b'\n', b'extra\n'+data, data+b'extra\n', data+b'\xff',
                data.replace(b',1,', b',"1",', 1), b'x'*(790528+1), data.decode(), bytearray(data), None):
            with self.assertRaises(AssertionError): parser.check(bad, b'', 'always-on')
        # Internal separators must not be accepted by generic splitlines().
        offsets = (data.index(b'\n'), data.index(b'\n', data.index(b'\n')+1), data.rfind(b'\n', 0, -1))
        for at in offsets:
            for separator in (b'\r\n', b'\r', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e', b'\x00', b'\t'):
                with self.assertRaises(AssertionError):
                    parser.check(data[:at]+separator+data[at+1:], b'', 'always-on')
        for stderr in (b' ', b'\n', b'warning\n', '', bytearray(), None):
            with self.assertRaises(AssertionError): parser.check(data, stderr, 'always-on')
        for mode in ('', 'always_on', 'other', b'always-on', None, True):
            with self.assertRaises(AssertionError): parser.check(data, b'', mode)
        for comment in ('', COMMENT+'!', COMMENT.replace('no accuracy', 'accuracy')):
            self.refuse(comment=comment)
        self.refuse(rows=changed('always-on', 0, 0, '9'*249))

    def test_optimized_entrypoints_refuse_and_parser_import_is_local(self):
        self.assertEqual(Path(parser.__file__).resolve(), Path(__file__).with_name('observer_work.py').resolve())
        for name in ('observer_work.py', Path(__file__).name):
            path = str(Path(__file__).with_name(name))
            for tail in ([path], ['-c', 'import runpy,sys; runpy.run_path(sys.argv[1])', path]):
                process = subprocess.run([sys.executable, '-B', '-O', *tail], capture_output=True,
                    timeout=5, check=False)
                self.assertEqual((process.returncode, process.stdout, process.stderr),
                    (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
