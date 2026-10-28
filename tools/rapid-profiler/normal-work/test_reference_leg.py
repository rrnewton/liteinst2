#!/usr/bin/env python3
"""Fabricated single-leg protocol controls; no native, timing or campaign credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import reference_leg as check

COMMENT = '# normal reference leg; raw same-call endpoints are uncalibrated; no accuracy or performance claim'
HEADER = 'phase,trial,leg,id,repeat,seed_index,seed,length,input_fnv1a64,value,instructions,conditional_branches,taken_branches,input_bytes,ret_bytes,reference_sequence,reference_start_ticks,reference_end_ticks,reference_start_aux,reference_end_aux,reference_rsp,reference_ticks,pid,tid,registration,install,function,generation,ordinal,owner,invocation,history_prefix,entry_pc,return_pc,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,entry_gap_ticks,return_gap_ticks,ack,ack_ordinal'
FIELDS = tuple(HEADER.split(','))
CASES = ((0, 1311768467139281696, 1, 7552869386198218469, 11400714819323198532, 11, 1, 0),
    (0, 1311768467139281696, 64, 7552869386198218469, 11400714819323190453, 389, 64, 63),
    (1, 18364758542526924135, 1, 8995313910352961381, 11400714819323198531, 11, 1, 0),
    (1, 18364758542526924135, 64, 8995313910352961381, 11400714819323190389, 389, 64, 63))


def terminal(phase, trial, leg):
    counts = ('batches=0 events=0 reports=0 records=0 actions=0 entered=0 ret_observed=0 '
        'confirmed=0 completed=0 unsampled=0 whole_journal_words=0' if leg == 'original' else
        'batches=1 events=48 reports=1 records=24 actions=2 entered=24 ret_observed=24 '
        'confirmed=24 completed=24 unsampled=0 whole_journal_words=512')
    return (f'normal-reference-leg FUNCTIONAL_PASS phase={phase} trial={trial} leg={leg} '
        'selection=normal-reference-exact-37-v1 calls=24 helper_calls=12 reference_cells=24 '
        +counts+' instructions=4800 conditional=780 taken=756 input_bytes=780 ret_bytes=192 '
        'input_unchanged=true joined=true')


def fixture(phase='qualification', trial=1, leg='original'):
    rows = []
    for index in range(24):
        seed_index, seed, length, digest, value, instructions, branches, taken = CASES[(index % 8)//2]
        ordinal = index+1; a, b, rsp = 1000+index*1000, 1100+index*1000, 0x800000+(index//2)*4096
        row = [phase, trial, leg, ordinal, index//8+1, seed_index, seed, length, digest, value,
            instructions, branches, taken, length, 8, ordinal, a, b, 7, 7, rsp, 100, 4242, 4242]
        row += (['']*21 if leg == 'original' else
            [1, 1852990822, 1, 17, ordinal, 'sampled', index, 1, 0x100000, 0x100024,
             rsp-8, 0x200000+(80 if index % 2 == 0 else 216), a+10, b-10, 7, 7,
             80, 10, 10, 'next-entry' if index < 23 else 'caller-checkpoint',
             ordinal+1 if index < 23 else ''])
        rows.append(list(map(str, row)))
    return rows


def put(rows, index, **fields):
    for name, value in fields.items(): rows[index][FIELDS.index(name)] = str(value)


def encode(rows, phase='qualification', trial=1, leg='original', comment=COMMENT, header=HEADER, final=None):
    return ('\n'.join([comment, header, *(','.join(row) for row in rows),
        terminal(phase, trial, leg) if final is None else final])+'\n').encode('ascii')


class Controls(unittest.TestCase):
    def refuse(self, rows, leg='original', **wire):
        with self.assertRaises(AssertionError):
            check.check(encode(rows, leg=leg, **wire), b'', 'qualification', 1, leg)

    def test_complete_single_leg_keys_counts_and_verbatim_rows(self):
        expected = dict(instructions=4800, conditional_branches=780, taken_branches=756,
            input_bytes=780, ret_bytes=192)
        for phase in ('qualification', 'calibration', 'holdout', 'comparison'):
            for trial in (1, (1 << 64)-1):
                for leg in ('original', 'installed'):
                    rows = fixture(phase, trial, leg)
                    got = check.check(encode(rows, phase, trial, leg), b'', phase, trial, leg)
                    self.assertEqual((got['status'], got['phase'], got['trial'], got['leg'], got['calls'],
                        got['helper_calls'], got['reference_cells']), ('FUNCTIONAL_PASS', phase, trial, leg, 24, 12, 24))
                    counts = tuple(got[k] for k in ('batches', 'events', 'reports', 'records', 'actions',
                        'entered', 'ret_observed', 'confirmed', 'completed', 'whole_journal_words'))
                    self.assertEqual(counts, (0,)*10 if leg == 'original' else (1, 48, 1, 24, 2, 24, 24, 24, 24, 512))
                    self.assertEqual((got['work'], got['unsampled'], len(got['rows'])), (expected, 0, 24))
                    self.assertEqual(got['generation'], None if leg == 'original' else 17)
                    self.assertEqual(got['table'], (HEADER+'\n'+''.join(','.join(row)+'\n' for row in rows)).encode())
                    for actual, row in zip(got['rows'], rows):
                        self.assertEqual(['' if actual[n] is None else str(actual[n]) for n in FIELDS], row)
                    self.assertIn('Fresh-process', got['scope'])
                    self.assertIn('not an independent replay', got['source_attested'])

    def test_expected_manifest_key_types_and_coherent_mismatch_refuse(self):
        data = encode(fixture())
        for phase in ('', 'Qualification', 'other', 1, None):
            with self.assertRaises(AssertionError): check.check(data, b'', phase, 1, 'original')
        for trial in (0, -1, 1 << 64, True, False, 1.0, '1', None):
            with self.assertRaises(AssertionError): check.check(data, b'', 'qualification', trial, 'original')
        for leg in ('', 'Original', 'both', 1, None):
            with self.assertRaises(AssertionError): check.check(data, b'', 'qualification', 1, leg)
        for phase, trial, leg in (('calibration', 1, 'original'), ('qualification', 2, 'original'),
                ('qualification', 1, 'installed')):
            coherent = encode(fixture(phase, trial, leg), phase, trial, leg)
            with self.assertRaises(AssertionError): check.check(coherent, b'', 'qualification', 1, 'original')

    def test_each_fixed_field_and_coherent_work_relabel_refuses(self):
        for leg in ('original', 'installed'):
            for index in range(24):
                for field in range(16):
                    rows = fixture(leg=leg); old = rows[index][field]
                    rows[index][field] = 'other' if field in (0, 2) else str(int(old)+1)
                    with self.subTest(leg=leg, row=index, field=field): self.refuse(rows, leg)
            for name in ('input_fnv1a64', 'value', 'instructions', 'conditional_branches', 'taken_branches', 'input_bytes', 'ret_bytes'):
                rows = fixture(leg=leg)
                for row in rows: row[FIELDS.index(name)] = str(int(row[FIELDS.index(name)])+1)
                self.refuse(rows, leg)

    def test_absent_original_sdk_and_every_installed_witness_refuse(self):
        for index in range(24):
            for field in range(24, 45):
                rows = fixture(); rows[index][field] = fixture(leg='installed')[index][field] or '0'
                self.refuse(rows)
                rows = fixture(leg='installed'); old = rows[index][field]
                rows[index][field] = 'wrong' if field in (29, 43) else str(int(old or '0')+1)
                self.refuse(rows, 'installed')
        for index, ack, ordinal in ((0, 'caller-checkpoint', ''), (23, 'next-entry', '25')):
            rows = fixture(leg='installed'); put(rows, index, ack=ack, ack_ordinal=ordinal)
            self.refuse(rows, 'installed')

    def test_endpoint_equations_aux_and_zero_full_width_are_exact(self):
        for leg in ('original', 'installed'):
            for index in range(24):
                for name, value in (('reference_end_ticks', 999+index*1000), ('reference_ticks', 101),
                        ('reference_start_aux', 8), ('reference_end_aux', 1 << 32)):
                    rows = fixture(leg=leg); put(rows, index, **{name: value}); self.refuse(rows, leg)
            for tick, aux in ((0, 0), ((1 << 64)-1, (1 << 32)-1)):
                rows = fixture(leg=leg)
                for index in range(24):
                    put(rows, index, reference_start_ticks=tick, reference_end_ticks=tick,
                        reference_start_aux=aux, reference_end_aux=aux, reference_ticks=0)
                    if leg == 'installed': put(rows, index, start_ticks=tick, end_ticks=tick,
                        start_aux=aux, end_aux=aux, raw_ticks=0, entry_gap_ticks=0, return_gap_ticks=0)
                got = check.check(encode(rows, leg=leg), b'', 'qualification', 1, leg)
                self.assertEqual(got['zero_reference_spans'], 24)
                self.assertTrue(all(r['reference_start_ticks'] == tick for r in got['rows']))
            # A full-u64 enclosing interval is valid too; the other23 are equal/max.
            put(rows, 0, reference_start_ticks=0, reference_ticks=(1 << 64)-1)
            if leg == 'installed': put(rows, 0, start_ticks=0, raw_ticks=(1 << 64)-1)
            got = check.check(encode(rows, leg=leg), b'', 'qualification', 1, leg)
            self.assertEqual((got['rows'][0]['reference_ticks'], got['zero_reference_spans']), ((1 << 64)-1, 23))
        for index in range(24):
            for name, value in (('start_ticks', 999+index*1000), ('end_ticks', 1101+index*1000),
                ('start_aux', 8), ('end_aux', 1 << 32), ('raw_ticks', 81), ('entry_gap_ticks', 11), ('return_gap_ticks', 11)):
                rows = fixture(leg='installed'); put(rows, index, **{name: value}); self.refuse(rows, 'installed')

    def test_within_process_chronology_pair_stack_and_identity(self):
        for leg in ('original', 'installed'):
            for index in range(1, 24):
                rows = fixture(leg=leg); a = 1099+(index-1)*1000
                put(rows, index, reference_start_ticks=a, reference_end_ticks=a+100)
                if leg == 'installed': put(rows, index, start_ticks=a+10, end_ticks=a+90)
                self.refuse(rows, leg)
            for index in (0, 23):
                for p in (0, 128, 145, (1 << 64)-16, 0x900000):
                    rows = fixture(leg=leg); put(rows, index, reference_rsp=p)
                    if leg == 'installed': put(rows, index, entry_rsp=max(0, p-8))
                    self.refuse(rows, leg)
                rows = fixture(leg=leg); put(rows, index, pid=4243, tid=4243); self.refuse(rows, leg)
                rows = fixture(leg=leg); put(rows, index, reference_start_aux=8, reference_end_aux=8)
                if leg == 'installed': put(rows, index, start_aux=8, end_aux=8)
                self.refuse(rows, leg)
            for fields in (dict(pid=0), dict(pid=1 << 32), dict(tid=4243)):
                rows = fixture(leg=leg); put(rows, 0, **fields); self.refuse(rows, leg)

    def test_missing_duplicate_order_columns_and_old48_frame_refuse(self):
        for leg in ('original', 'installed'):
            rows = fixture(leg=leg)
            for index in range(24):
                self.refuse(rows[:index]+rows[index+1:], leg)
                self.refuse(rows[:index]+[rows[index]]+rows[index:], leg)
                bad = fixture(leg=leg); other = (index+1) % 24; bad[index], bad[other] = bad[other], bad[index]
                self.refuse(bad, leg)
                self.refuse(rows[:index]+[rows[index][:-1]]+rows[index+1:], leg)
                self.refuse(rows[:index]+[rows[index]+['0']]+rows[index+1:], leg)
            self.refuse(rows+rows, leg)
            for header in ('', HEADER+',extra', HEADER.replace('trial,', 'id,', 1), HEADER[12:]):
                self.refuse(rows, leg, header=header)

    def test_canonical_unsigned_fields_and_nonzero_trial(self):
        for leg in ('original', 'installed'):
            for index in (0, 23):
                for field, cell in enumerate(fixture(leg=leg)[index]):
                    if field in (0, 2, 29, 43) or cell == '': continue
                    for value in ('', '00', '+1', '-1', '1.0', '1e0', ' 1', '1 ', '18446744073709551616', '9'*21):
                        rows = fixture(leg=leg); rows[index][field] = value
                        with self.subTest(leg=leg, row=index, field=field, value=value): self.refuse(rows, leg)
            rows = fixture(leg=leg)
            for row in rows: row[1] = '0'
            self.refuse(rows, leg, final=terminal('qualification', 0, leg))

    def test_exact_terminal_scope_empty_stderr_and_lf_framing(self):
        for leg in ('original', 'installed'):
            rows = fixture(leg=leg); data = encode(rows, leg=leg); words = terminal('qualification', 1, leg).split(' ')
            for index, word in enumerate(words):
                for replacement in ([], [word, word], [word+'!']):
                    self.refuse(rows, leg, final=' '.join(words[:index]+replacement+words[index+1:]))
            for comment in ('', COMMENT+'!', COMMENT.replace('uncalibrated', 'calibrated')):
                self.refuse(rows, leg, comment=comment)
            for position, byte in enumerate(data):
                if byte != 10: continue
                for separator in (b'\r\n', b'\r', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
                    with self.assertRaises(AssertionError):
                        check.check(data[:position]+separator+data[position+1:], b'', 'qualification', 1, leg)
            for bad in (b'', data[:-1], data+b'\n', b'extra\n'+data, data+b'extra\n', data+b'\xff',
                    data.replace(b',1,', b',"1",', 1), data.replace(b'qualification', b'quali\tfication', 1),
                    b'x'*(check.MIB+1), data.decode(), bytearray(data), None):
                with self.assertRaises(AssertionError): check.check(bad, b'', 'qualification', 1, leg)
            for stderr in (b' ', b'\n', b'warning\n', '', bytearray(), None):
                with self.assertRaises(AssertionError): check.check(data, stderr, 'qualification', 1, leg)

    def test_local_sequence_owner_and_continuation_coherent_corruptions(self):
        for leg in ('original', 'installed'):
            rows = fixture(leg=leg)
            for row in rows: row[FIELDS.index('reference_sequence')] = str(int(row[FIELDS.index('reference_sequence')])+24)
            self.refuse(rows, leg)  # Installed does not inherit the old48 second-leg sequence.
            rows = fixture(leg=leg)
            for row in rows: row[FIELDS.index('id')] = str(int(row[FIELDS.index('id')])+100)
            self.refuse(rows, leg)
        for fields in (dict(generation=0), dict(entry_pc=(1 << 64)-32, return_pc=4)):
            rows = fixture(leg='installed'); put(rows, 0, **fields); self.refuse(rows, 'installed')
        rows = fixture(leg='installed')
        for index in (0, 1): put(rows, index, return_word=0x300000+(80 if index % 2 == 0 else 216))
        self.refuse(rows, 'installed')
        rows = fixture(leg='installed')
        for index in range(24): put(rows, index, return_word=0x200000+(216 if index % 2 == 0 else 80))
        self.refuse(rows, 'installed')
        rows = fixture(leg='installed')
        for index in range(24): put(rows, index, history_prefix=2)
        self.refuse(rows, 'installed', final=terminal('qualification', 1, 'installed').replace('actions=2', 'actions=3'))

    def test_separate_processes_need_no_counterpart_or_shared_observations(self):
        original = fixture(); installed = fixture(leg='installed')
        for i in range(24):
            p = 0xa00000+(i//2)*4096; a = i*1000
            put(installed, i, pid=99, tid=99, generation=2, reference_start_aux=8, reference_end_aux=8,
                start_aux=8, end_aux=8, reference_rsp=p, entry_rsp=p-8, entry_pc=0x300000,
                return_pc=0x300024, return_word=0x400000+(80 if i % 2 == 0 else 216),
                reference_start_ticks=a, reference_end_ticks=a+100, start_ticks=a+10, end_ticks=a+90)
        with patch.object(check.work, 'check', side_effect=AssertionError('old48 parser must not be called')):
            left = check.check(encode(original), b'', 'qualification', 1, 'original')
            right = check.check(encode(installed, leg='installed'), b'', 'qualification', 1, 'installed')
        self.assertEqual((left['pid'], right['pid'], left['generation'], right['generation']), (4242, 99, None, 2))
        self.assertEqual((len(left['rows']), len(right['rows'])), (24, 24))

    def test_optimized_entrypoints_refuse_and_imports_are_exact_siblings(self):
        here = Path(__file__).parent.resolve()
        self.assertEqual(Path(check.__file__).resolve(), here/'reference_leg.py')
        self.assertEqual(Path(check.work.__file__).resolve(), here/'reference_work.py')
        for name in ('reference_leg.py', Path(__file__).name):
            process = subprocess.run([sys.executable, '-B', '-O', str(here/name)],
                capture_output=True, timeout=5, check=False)
            self.assertEqual((process.returncode, process.stdout, process.stderr), (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
