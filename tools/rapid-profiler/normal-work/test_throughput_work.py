#!/usr/bin/env python3
"""Fabricated wire controls only; no physical timing or throughput evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('_throughput_under_test', HERE/'throughput_work.py')
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('missing local throughput checker')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
U64 = (1 << 64)-1
PREFIX = 3075
COMMENT = '# normal throughput v1; segmented call-path and validated service elapsed wall nanoseconds; no subtraction, accuracy, or continuous-throughput claim'
HEADER = 'kind,index,start_ns,end_ns'
# Independent literal closed observer fixture constants, not parser._cases().
CASES = ((0, 1, 7552869386198218469, 11400714819323198532, 11, 1, 0, 1, 8),
    (0, 64, 7552869386198218469, 11400714819323190453, 389, 64, 63, 64, 8),
    (1, 1, 8995313910352961381, 11400714819323198531, 11, 1, 0, 1, 8),
    (1, 64, 8995313910352961381, 11400714819323190389, 389, 64, 63, 64, 8))


def prefix(mode):
    lines = [P.OBSERVER.COMMENT, P.OBSERVER.HEADER]
    for g in range(3072):
        row = [g+1, g//24+1, g % 24+1, *CASES[(g % 8)//2]]
        row += ['']*14 if mode == 'native' else [g//24+1, 'sampled', 17, g, 1,
            0x800008+(g//2)*16, 0x200000+(30 if g % 2 == 0 else 48),
            1000+g*100, 1050+g*100, 7, 7, 50, 'C' if g % 24 == 23 else 'N',
            '' if g % 24 == 23 else g+2]
        lines.append(','.join(map(str, row)))
    end = ('normal-observer-work FUNCTIONAL_PASS mode='+mode+
        ' selection=normal-exact-37-v1 repetitions=128 calls=3072 helper_calls=1536'
        ' instructions=614400 conditional=99840 taken=96768 input_bytes=99840 ret_bytes=24576'
        ' pid=4242 tid=4242 entry=1048576 caller=2097152')
    end += (' install=none function=none generation=none batches=0 events=0 reports=0'
        ' records=0 actions=0 journal_words=0 next_entry_acknowledgements=0 checkpoint_acknowledgements=0'
        if mode == 'native' else
        ' install=1852793459 function=1 generation=17 batches=128 events=6144 reports=1'
        ' records=3072 actions=2 journal_words=65536 next_entry_acknowledgements=2944 checkpoint_acknowledgements=128')
    return ('\n'.join([*lines, end+' input_unchanged=true joined=true'])+'\n').encode('ascii')


PREFIXES = {mode: prefix(mode) for mode in ('native', 'always-on')}


def encode(mode='always-on', rows=None, cpu=5):
    rows = ([('setup', 0, 0, 10), *(('body', i+1, 20+10*i, 25+10*i) for i in range(128)),
             ('service', 0, 20, 1300)] if rows is None else rows)
    end = ('normal-observer-throughput TIMING_COMPLETE mode='+mode+' cpu='+str(cpu)+
        ' clock=CLOCK_MONOTONIC_RAW units=ns timing_rows=130 setup_ns='+str(rows[0][3]-rows[0][2])+
        ' body_ns='+str(sum(row[3]-row[2] for row in rows[1:-1]))+
        ' service_ns='+str(rows[-1][3]-rows[-1][2]))
    return PREFIXES[mode]+('\n'.join([COMMENT, HEADER, *(','.join(map(str, row)) for row in rows), end])+'\n').encode('ascii')


def changed_line(data, index, change):
    lines = data[:-1].decode('ascii').split('\n')
    lines[index] = change(lines[index])
    return ('\n'.join(lines)+'\n').encode('ascii')


def cell(data, line, field, value):
    def change(text):
        parts = text.split(','); parts[field] = value
        return ','.join(parts)
    return changed_line(data, line, change)


class Controls(unittest.TestCase):
    def refuse(self, data, mode='always-on', stderr=b''):
        with self.assertRaises(AssertionError):
            P.check(data, stderr, mode)

    def test_complete_modes_delegate_exact_prefix_and_retain_every_endpoint(self):
        for mode in PREFIXES:
            data = encode(mode)
            with patch.object(P.OBSERVER, 'check', wraps=P.OBSERVER.check) as delegated:
                out = P.check(data, b'', mode)
                delegated.assert_called_once_with(PREFIXES[mode], b'', mode)
            self.assertEqual(out['functional'], P.OBSERVER.check(PREFIXES[mode], b'', mode))
            self.assertEqual((out['status'], out['mode'], out['cpu'], out['clock'], out['units']),
                ('TIMING_COMPLETE', mode, 5, 'CLOCK_MONOTONIC_RAW', 'ns'))
            self.assertEqual((out['timing_rows'], out['setup_ns'], out['body_ns'], out['service_ns']), (130, 10, 640, 1280))
            self.assertEqual(out['functional_prefix'], PREFIXES[mode])
            rows = [out['setup'], *out['body'], out['service']]
            rebuilt = HEADER+'\n'+''.join(','.join(str(row[k]) for k in ('kind', 'index', 'start_ns', 'end_ns'))+'\n' for row in rows)
            self.assertEqual(out['timing_table'], rebuilt.encode('ascii'))
            self.assertEqual(len(out['body']), 128)
            for i, row in enumerate(out['body']):
                self.assertEqual((row['index'], row['start_ns'], row['end_ns'], row['elapsed_ns']), (i+1, 20+10*i, 25+10*i, 5))
            self.assertEqual(out['zero_body_spans'], 0)
            self.assertEqual(set(out['division_status'].values()), {'NOT_COMPUTED'})
            self.assertIn('separate clock origin', out['scope'])
            self.assertIn('not those physical observations', out['source_attested'])
        with patch.object(P.OBSERVER, 'check', wraps=P.OBSERVER.check) as delegated:
            self.refuse(encode(), stderr=b'actual warning\n')
            delegated.assert_called_once_with(PREFIXES['always-on'], b'actual warning\n', 'always-on')

    def test_zero_and_maximal_endpoints_keep_unresolved_division(self):
        for mode in PREFIXES:
            for point, cpu in ((0, 0), (U64, 1023)):
                rows = [('setup', 0, point, point), *(('body', i, point, point) for i in range(1, 129)), ('service', 0, point, point)]
                out = P.check(encode(mode, rows, cpu), b'', mode)
                self.assertEqual((out['setup_ns'], out['body_ns'], out['service_ns'], out['zero_body_spans']), (0, 0, 0, 128))
                self.assertEqual(set(out['division_status'].values()), {'UNRESOLVED_ZERO'})
                self.assertTrue(all(row['division_status'] == 'UNRESOLVED_ZERO' for row in out['body']))
                self.assertEqual(out['service']['end_ns'], point)
            rows = [('setup', 0, 0, 0), ('body', 1, 0, U64),
                *(('body', i, U64, U64) for i in range(2, 129)), ('service', 0, 0, U64)]
            out = P.check(encode(mode, rows), b'', mode)
            self.assertEqual((out['body_ns'], out['service_ns'], out['zero_body_spans']), (U64, U64, 127))
            self.assertEqual(out['division_status']['setup_ns'], 'UNRESOLVED_ZERO')
            rows = [('setup', 0, 0, U64), *(('body', i, U64, U64) for i in range(1, 129)), ('service', 0, U64, U64)]
            out = P.check(encode(mode, rows), b'', mode)
            self.assertEqual((out['setup_ns'], out['body_ns'], out['service_ns']), (U64, 0, 0))

    def test_exact_framing_order_literals_modes_and_cpu(self):
        data = encode(); lines = data[:-1].split(b'\n')
        for index in range(PREFIX, 3208):
            self.refuse(b'\n'.join(lines[:index]+lines[index+1:])+b'\n')
            self.refuse(b'\n'.join(lines[:index]+[lines[index]]+lines[index:])+b'\n')
        for index in (3075, 3076, 3077, 3078, 3141, 3205, 3206):
            self.refuse(changed_line(data, index, lambda s: s+'!'))
        for index in (3077, 3078, 3141, 3205):
            bad = list(lines); bad[index], bad[index+1] = bad[index+1], bad[index]
            self.refuse(b'\n'.join(bad)+b'\n')
        for index in (3077, 3078, 3141, 3205, 3206):
            self.refuse(changed_line(data, index, lambda s: s+',0'))
            self.refuse(changed_line(data, index, lambda s: ','.join(s.split(',')[:-1])))
        self.refuse(cell(data, 3078, 1, '2'))
        self.refuse(cell(data, 3206, 0, 'body'))
        for bad in (data[:-1], data+b'\n', data+b'extra\n', b'prefix\n'+data,
                    data.replace(b'\n', b'\r\n', 1), data+b'\xff', b'x'*806913, data.decode(), bytearray(data), None):
            self.refuse(bad)
        for sep in (b'\r', b'\t', b'\v', b'\f', b'\x1c', b'\x00', b'\x7f'):
            self.refuse(data.replace(b'body,1,', b'body'+sep+b'1,', 1))
        for mode in ('native', 'other', 'always_on', None, True, b'always-on'):
            self.refuse(data, mode)
        for stderr in (b'\n', '', bytearray(), None):
            self.refuse(data, stderr=stderr)
        for old, new in (('cpu=5', 'cpu=1024'), ('clock=CLOCK_MONOTONIC_RAW', 'clock=CLOCK_MONOTONIC'),
                         ('units=ns', 'units=ticks'), ('timing_rows=130', 'timing_rows=129'),
                         ('mode=always-on', 'mode=native'), ('TIMING_COMPLETE', 'PASS')):
            self.refuse(changed_line(data, -1, lambda s: s.replace(old, new)))
        words = lines[-1].decode().split(' ')
        for i in range(len(words)):
            self.refuse(changed_line(data, -1, lambda s, i=i: ' '.join(words[:i]+words[i+1:])))
            self.refuse(changed_line(data, -1, lambda s, i=i: ' '.join(words[:i]+[words[i]]+words[i:])))
        for i in range(len(words)-1):
            bad = list(words); bad[i], bad[i+1] = bad[i+1], bad[i]
            self.refuse(changed_line(data, -1, lambda s: ' '.join(bad)))

    def test_canonical_numbers_checked_arithmetic_and_enclosure_joins(self):
        data = encode()
        for line in (3077, 3078, 3206):
            for field in (1, 2, 3):
                self.refuse(cell(data, line, field, '00'))
        for text in ('', '01', '+1', '-1', '1.0', '1e0', ' 1', '1 ', str(U64+1), '9'*21):
            self.refuse(cell(data, 3078, 2, text))
        for key in ('cpu', 'timing_rows', 'setup_ns', 'body_ns', 'service_ns'):
            for value in ('00', '-1', '+1', str(U64+1)):
                self.refuse(changed_line(data, -1, lambda s, key=key, value=value:
                    ' '.join(key+'='+value if word.startswith(key+'=') else word for word in s.split(' '))))
        for line, field, value in ((3077, 2, '11'), (3077, 3, '21'), (3078, 3, '19'),
                                   (3079, 2, '24'), (3206, 2, '19'), (3206, 3, '1294')):
            self.refuse(cell(data, line, field, value))
        # A coherent terminal cannot repair overlap, sum overflow or an omitted tail.
        rows = [('setup', 0, 0, 0), *(('body', i, 0, U64) for i in range(1, 129)), ('service', 0, 0, U64)]
        overflow = encode(rows=rows)
        overflow = changed_line(overflow, -1, lambda s: s.replace('body_ns='+str(128*U64), 'body_ns='+str(U64)))
        self.refuse(overflow)
        self.refuse(changed_line(data, -1, lambda s: s.replace('body_ns=640', 'body_ns=639')))
        self.refuse(changed_line(data, -1, lambda s: s.replace('setup_ns=10', 'setup_ns=11')))
        self.refuse(changed_line(data, -1, lambda s: s.replace('service_ns=1280', 'service_ns=1279')))
        self.refuse(cell(changed_line(data, -1, lambda s: s.replace('service_ns=1280', 'service_ns=1274')), 3206, 3, '1294'))

    def test_whole_old_prefix_corruption_remains_a_refusal(self):
        data = encode()
        for field in range(26):
            self.refuse(cell(data, 2, field, 'wrong'))
        # Equal aggregate results and work still cannot replace exact per-call rows.
        for field in (6, 7):
            first = data[:-1].decode().split('\n')[2].split(',')
            second = data[:-1].decode().split('\n')[3].split(',')
            bad = cell(data, 2, field, str(int(first[field])+1))
            self.refuse(cell(bad, 3, field, str(int(second[field])-1)))
        for field, value in ((12, '1'), (14, '18'), (15, '0'), (16, '2'), (24, 'N'), (25, '0')):
            self.refuse(cell(data, 3073, field, value))
        for old, new in (('journal_words=65536', 'journal_words=65535'), ('joined=true', 'joined=false'),
                         ('reports=1', 'reports=0'), ('input_unchanged=true', 'input_unchanged=false')):
            self.refuse(changed_line(data, 3074, lambda s: s.replace(old, new)))
        native = encode('native')
        self.refuse(cell(native, 2, 12, '1'), 'native')
        self.assertIn('does not independently', P.check(data, b'', 'always-on')['functional']['source_attested'])

    def test_source_local_import_and_optimization_guard(self):
        self.assertEqual(Path(P.OBSERVER.__file__).resolve(), HERE/'observer_work.py')
        with tempfile.TemporaryDirectory(prefix='throughput-check-', dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            for name in ('observer_work.py', 'throughput_work.py'):
                (root/name).write_text("raise RuntimeError('ambient import')\n")
            for name in ('throughput_work.py', 'test_throughput_work.py'):
                run = subprocess.run([sys.executable, '-B', '-O', str(HERE/name)], cwd=root,
                    capture_output=True, timeout=5, check=False)
                self.assertEqual((run.returncode, run.stdout, run.stderr), (1, b'', b'assertions required\n'))
            code = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('x',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.OBSERVER.__file__)")
            run = subprocess.run([sys.executable, '-B', '-c', code, str(HERE/'throughput_work.py')], cwd=root,
                capture_output=True, timeout=5, check=False)
            self.assertEqual((run.returncode, run.stdout, run.stderr),
                (0, (str(HERE/'observer_work.py')+'\n').encode(), b''))
            self.assertFalse((root/'__pycache__').exists())


if __name__ == '__main__':
    unittest.main()
