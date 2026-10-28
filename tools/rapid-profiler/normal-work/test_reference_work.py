#!/usr/bin/env python3
"""Fabricated collector-protocol corruption controls; no native or timing credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
from pathlib import Path
import subprocess
import unittest
import reference_work as check

COMMENT = '# normal reference collector; raw same-call endpoints are uncalibrated; no accuracy or performance claim'
HEADER = 'leg,id,repeat,seed_index,seed,length,input_fnv1a64,value,instructions,conditional_branches,taken_branches,input_bytes,ret_bytes,reference_sequence,reference_start_ticks,reference_end_ticks,reference_start_aux,reference_end_aux,reference_rsp,reference_ticks,pid,tid,registration,install,function,generation,ordinal,owner,invocation,history_prefix,entry_pc,return_pc,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,entry_gap_ticks,return_gap_ticks,ack,ack_ordinal'
TERMINAL = 'normal-reference-work FUNCTIONAL_PASS selection=normal-reference-exact-37-v1 originals=24 installed=24 helper_calls=24 reference_cells=48 batches=1 events=48 reports=1 records=24 actions=2 entered=24 ret_observed=24 confirmed=24 completed=24 unsampled=0 whole_journal_words=512 per_leg_instructions=4800 per_leg_conditional=780 per_leg_taken=756 per_leg_input_bytes=780 per_leg_ret_bytes=192 input_unchanged=true joined=true'
FIELDS = HEADER.split(',')
# Literal expected source-model results; do not call the parser's expected helper.
CASES = ((0, 1311768467139281696, 1, 7552869386198218469, 11400714819323198532, 11, 1, 0),
    (0, 1311768467139281696, 64, 7552869386198218469, 11400714819323190453, 389, 64, 63),
    (1, 18364758542526924135, 1, 8995313910352961381, 11400714819323198531, 11, 1, 0),
    (1, 18364758542526924135, 64, 8995313910352961381, 11400714819323190389, 389, 64, 63))


def fixture():
    rows = []
    for leg in ('original', 'installed'):
        for index in range(24):
            seed_index, seed, length, digest, value, instructions, branches, taken = CASES[(index % 8)//2]
            ordinal = index+1; position = len(rows)
            a, b, rsp = 1000+position*1000, 1100+position*1000, 0x800000+(position//2)*4096
            row = [leg, ordinal, index//8+1, seed_index, seed, length, digest, value,
                instructions, branches, taken, length, 8, position+1, a, b, 7, 7, rsp, 100, 4242, 4242]
            if leg == 'original':
                row += ['']*21
            else:
                row += [1, 1852990822, 1, 17, ordinal, 'sampled', index, 1, 0x100000, 0x100024,
                    rsp-8, 0x200000+(80 if index % 2 == 0 else 216), a+10, b-10, 7, 7,
                    80, 10, 10, 'next-entry' if index < 23 else 'caller-checkpoint',
                    ordinal+1 if index < 23 else '']
            rows.append(list(map(str, row)))
    return rows


def encode(rows, comment=COMMENT, header=HEADER, terminal=TERMINAL):
    return ('\n'.join([comment, header, *(','.join(row) for row in rows), terminal])+'\n').encode('ascii')


class Controls(unittest.TestCase):
    def refuse(self, rows, **kwargs):
        with self.assertRaises(AssertionError): check.check(encode(rows, **kwargs), b'')

    def test_complete_population_exact_rows_and_work(self):
        rows = fixture(); got = check.check(encode(rows), b'')
        self.assertEqual((got['status'], got['originals'], got['installed'], got['reference_cells']),
            ('FUNCTIONAL_PASS', 24, 24, 48))
        self.assertEqual(tuple(got[k] for k in ('helper_calls', 'batches', 'events', 'reports',
            'records', 'actions', 'entered', 'ret_observed', 'confirmed', 'completed',
            'unsampled', 'whole_journal_words', 'zero_reference_spans')),
            (24, 1, 48, 1, 24, 2, 24, 24, 24, 24, 0, 512, 0))
        expected = dict(instructions=4800, conditional_branches=780, taken_branches=756,
            input_bytes=780, ret_bytes=192)
        self.assertEqual(got['work'], dict(original=expected, installed=expected))
        self.assertEqual(got['table'], (HEADER+'\n'+''.join(','.join(row)+'\n' for row in rows)).encode())
        self.assertEqual(len(got['rows']), 48)
        for actual, row in zip(got['rows'], rows):
            self.assertEqual(['' if actual[name] is None else str(actual[name]) for name in FIELDS], row)
        self.assertIn('uncalibrated', got['scope'])
        self.assertIn('not an independent replay', got['source_attested'])

    def test_every_fixed_column_and_coherent_changes_refuse(self):
        for index in range(48):
            for field in range(14):
                rows = fixture(); old = rows[index][field]
                rows[index][field] = 'other' if field == 0 else str(int(old)+1)
                with self.subTest(row=index, field=field): self.refuse(rows)
        for field in (8, 9, 10, 11, 12):
            rows = fixture()
            for row in rows: row[field] = str(int(row[field])+1)
            self.refuse(rows)
        rows = fixture()
        for row in rows: row[6] = str(int(row[6]) ^ 1)
        self.refuse(rows)  # Coherent integrity relabelling cannot replace the fixed bytes.
        rows = fixture()
        for row in rows: row[7] = str(int(row[7]) ^ 1)
        self.refuse(rows)

    def test_original_absence_and_installed_owner_stack_acknowledgement(self):
        for index in range(24):
            for field in range(22, 43):
                rows = fixture(); rows[index][field] = fixture()[24+index][field] or '0'
                with self.subTest(row=index, field=field): self.refuse(rows)
        for index in range(24, 48):
            for field in range(22, 43):
                rows = fixture(); old = rows[index][field]
                rows[index][field] = 'wrong' if field in (27, 41) else str(int(old or '0')+1)
                with self.subTest(row=index, field=field): self.refuse(rows)
        for index, ack, ordinal in ((24, 'caller-checkpoint', ''), (47, 'next-entry', '25')):
            rows = fixture(); rows[index][41:43] = [ack, ordinal]; self.refuse(rows)

    def test_endpoint_algebra_aux_domain_and_zero_maximum(self):
        for index in range(48):
            for field, value in ((15, str(int(fixture()[index][14])-1)), (19, '101'),
                                 (16, '8'), (17, '4294967296')):
                rows = fixture(); rows[index][field] = value; self.refuse(rows)
        for index in range(24, 48):
            for field, value in ((34, str(int(fixture()[index][14])-1)),
                (35, str(int(fixture()[index][15])+1)), (36, '8'), (37, '4294967296'),
                (38, '81'), (39, '11'), (40, '11')):
                rows = fixture(); rows[index][field] = value; self.refuse(rows)
        for ticks, aux in (('0', '0'), ('18446744073709551615', '4294967295')):
            rows = fixture()
            for row in rows:
                row[14:18] = [ticks, ticks, aux, aux]; row[19] = '0'
                if row[0] == 'installed': row[34:41] = [ticks, ticks, aux, aux, '0', '0', '0']
            got = check.check(encode(rows), b'')
            self.assertEqual(got['zero_reference_spans'], 48)
            self.assertTrue(all(row['reference_start_ticks'] == int(ticks) for row in got['rows']))
        # Sequential actual calls retain chronology across every boundary,
        # including original-to-installed. All local gaps remain coherent here.
        for index in range(1, 48):
            rows = fixture(); a = int(rows[index-1][15])-1
            rows[index][14:16] = [str(a), str(a+100)]
            if index >= 24: rows[index][34:36] = [str(a+10), str(a+90)]
            self.refuse(rows)

    def test_local_pair_rsp_and_global_identity_are_joined(self):
        for index in (0, 23, 24, 47):
            for value in ('0', '128', '145', '18446744073709551600'):
                rows = fixture(); rows[index][18] = value
                if index >= 24: rows[index][32] = str(max(0, int(value)-8))
                self.refuse(rows)
            rows = fixture(); rows[index][18] = str(int(rows[index][18])+16)
            if index >= 24: rows[index][32] = str(int(rows[index][32])+16)
            self.refuse(rows)  # Even internally coherent row cannot disagree with its helper pair.
            rows = fixture(); rows[index][20:22] = ['4243', '4243']; self.refuse(rows)
            rows = fixture(); rows[index][16:18] = ['8', '8']
            if index >= 24: rows[index][36:38] = ['8', '8']
            self.refuse(rows)
        for field, value in ((20, '0'), (21, '4243'), (20, '4294967296')):
            rows = fixture(); rows[0][field] = value; self.refuse(rows)
        rows = fixture(); rows[24][25] = '0'; self.refuse(rows)
        rows = fixture(); rows[24][30:32] = ['18446744073709551584', '4']; self.refuse(rows)

    def test_missing_extra_duplicate_reordered_rows_and_headers(self):
        rows = fixture()
        for index in range(48):
            self.refuse(rows[:index]+rows[index+1:])
            self.refuse(rows[:index]+[rows[index]]+rows[index:])
            other = (index+1) % 48; bad = fixture(); bad[index], bad[other] = bad[other], bad[index]
            self.refuse(bad)
            self.refuse(rows[:index]+[rows[index][:-1]]+rows[index+1:])
            self.refuse(rows[:index]+[rows[index]+['0']]+rows[index+1:])
        for header in ('', HEADER+',extra', HEADER.replace('id,', 'repeat,', 1),
                HEADER.replace('reference_start_ticks,reference_end_ticks', 'reference_end_ticks,reference_start_ticks')):
            self.refuse(rows, header=header)

    def test_canonical_unsigned_cells_and_full_width_domains(self):
        self.assertEqual(check._uint('0'), 0)
        self.assertEqual(check._uint('18446744073709551615'), (1 << 64)-1)
        for index in (0, 23, 24, 47):
            for field, cell in enumerate(fixture()[index]):
                if field in (0, 27, 41) or cell == '': continue
                for value in ('', '00', '+1', '-1', '1.0', '1e0', ' 1', '1 ', '18446744073709551616', '9'*21):
                    rows = fixture(); rows[index][field] = value
                    with self.subTest(row=index, field=field, value=value): self.refuse(rows)

    def test_exact_scope_terminal_stderr_and_lf_framing(self):
        rows = fixture(); data = encode(rows)
        words = TERMINAL.split(' ')
        for index, word in enumerate(words):
            for replacement in ([], [word, word], [word+'!']):
                self.refuse(rows, terminal=' '.join(words[:index]+replacement+words[index+1:]))
        for comment in ('', COMMENT+'!', COMMENT.replace('uncalibrated', 'calibrated')):
            self.refuse(rows, comment=comment)
        for position, byte in enumerate(data):
            if byte != 10: continue
            for separator in (b'\r\n', b'\r', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e'):
                bad = data[:position]+separator+data[position+1:]
                with self.assertRaises(AssertionError): check.check(bad, b'')
        for bad in (b'', data[:-1], data+b'\n', b'extra\n'+data, data+b'extra\n', data+b'\xff',
            data.replace(b'original', b'ori\tginal', 1), data.replace(b',1,', b',"1",', 1),
            b'x'*(check.MIB+1), data.decode(), bytearray(data), None):
            with self.assertRaises(AssertionError): check.check(bad, b'')
        for stderr in (b' ', b'\n', b'warning\n', '', bytearray(), None):
            with self.assertRaises(AssertionError): check.check(data, stderr)

    def test_coherent_case_leg_and_continuation_relabels_refuse(self):
        rows = fixture()
        for row in rows: row[1] = str(int(row[1])+100); row[13] = str(int(row[13])+100)
        self.refuse(rows)
        rows = fixture(); rows[:24], rows[24:] = rows[24:], rows[:24]; self.refuse(rows)
        rows = fixture()
        for index in (24, 25): rows[index][33] = str(int(rows[index][33])+4096)
        self.refuse(rows)  # A separate page-aligned helper identity is still wrong.
        rows = fixture()
        for row in rows[24:]: row[33] = str(0x200000+(216 if int(row[1]) % 2 else 80))
        self.refuse(rows)
        rows = fixture()
        for row in rows[24:]: row[29] = '2'
        self.refuse(rows, terminal=TERMINAL.replace('actions=2', 'actions=3'))

    def test_optimized_entrypoints_refuse_and_parser_import_is_local(self):
        self.assertEqual(Path(check.__file__).resolve(), Path(__file__).with_name('reference_work.py').resolve())
        for name in ('reference_work.py', Path(__file__).name):
            process = subprocess.run([sys.executable, '-B', '-O', str(Path(__file__).with_name(name))],
                capture_output=True, timeout=5, check=False)
            self.assertEqual((process.returncode, process.stdout, process.stderr),
                (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
