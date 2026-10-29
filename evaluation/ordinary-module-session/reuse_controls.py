#!/usr/bin/env python3
"""Fabricated reuse transcripts; no native, ownership or deadline proof."""
if not __debug__:
    raise SystemExit('assertions required')

import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True


def load():
    path = Path(__file__).resolve().with_name('reuse_output.py')
    spec = importlib.util.spec_from_file_location('_module_session_reuse_output', path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load()
U64, U32 = (1 << 64) - 1, (1 << 32) - 1


def encode(rows):
    return ('\n'.join(','.join(map(str, row)) for row in rows) + '\n').encode('utf-8')


def fixture(k=10, direction='csv-length', generations=(11, 19, 31), maximum_rets=False):
    """Independent literal wire fixture, not a loaded owner or a parser model."""
    a, b, c = generations
    h = (k + 3) // 4
    f = 0 if direction == 'csv-length' else 1
    g = 1 - f
    rets = ((4, 36, 72, 125), (4, 12, 24, 40)) if maximum_rets else ((36, 125), (40,))
    geometry = dict(csv_va=4096, csv_length=126, length_va=4224, length_length=41,
                    continuation=17, returns=rets)
    args = dict(k=k, direction=direction, geometry=geometry, cpus=(2, 5))
    rows = [
        ['META', 'run', 'module-session-reuse-v1', 'session-absolute-v1', 'not-run',
         k, direction, 0x6d6f6401, 123, 123, 124, 2, 5, 1],
        ['META', 'code', '6f' * 32, 69632, 1, 101, 202, 69632, 69758, 69760, 69801, 131072],
        ['META', 'memory', 196608, 204800, 131072, 135168],
        ['META', 'input', '612c622c63', 5, 3, 5],
    ]
    rows += [['META', 'ret', function, ret] for function, offsets in enumerate(rets) for ret in offsets]
    admissions = []

    def pair(n, function, generation, slot, prefix, batch, ack, rank, sequence):
        scalar = 3 if function == 0 else 5
        rows.append(['CALL', n, function, scalar, scalar, generation,
                     'closed' if slot is None else 'sampled', 0 if slot is None else slot + 1,
                     prefix, batch])
        rows.append(['RAW', n, 200712, 131089, rets[function][-1], 100, 110, 7, 7,
                     ack, n + 1 if ack == 'next' else 0])
        if slot is not None:
            admissions.append(['SAMPLE', generation, function, slot, rank, sequence, 100, 'value', 110])

    rows.append(['HISTORY', 1, 1, 'published', a])
    for n in range(1, k + 1):
        pair(n, f, a, n - 1, 1, (n + 3) // 4,
             'checkpoint' if n % 4 == 0 or n == k else 'next', n - 1, n - 1)
    rows.append(['PHASE', 'hot-exhaust', k, k, k, k, 0, h, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, 0, h, 0, 0, 'not-checked', 'not-checked', 0, 0, 0])
    pair(k + 1, g, a, k, 1, h + 1, 'checkpoint', 0, k)
    rows.append(['PHASE', 'cold-available', k+1, k+1, k+1, k+1, 0, h+1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, 0, h+1, 0, 0, 'not-checked', 'not-checked', 0, 0, 0])
    rows.append(['PHASE', 'held', k+2, k+2, k+1, k+1, 0, h+1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, 0, h+1, 0, 0, 'not-checked', 'not-checked', 0, 0, 0])
    rows += [['HISTORY', 2, 2, 'published', b], ['REPORT', a, k+1]]
    rows.append(['PHASE', 'refused-twice', k+2, k+2, k+1, k+1, 0, h+1, 1, b, 2, 1, 1, 2, 1, 1, 0, 1, 1, h+1, 0, 0, 'not-checked', 'not-checked', 1, 0, 0])
    rows.append(['PHASE', 'released-before-checkpoint', k+3, k+3, k+2, k+1, 1, h+1, 2, b, 2, 1, 1, 2, 0, 1, 0, 1, 1, h+1, 1, 0, 'not-checked', 'not-checked', 1, 0, 0])
    rows += [['HISTORY', 3, 3, 'published', c], ['META', 'epochs', a, b, c]]
    rows.append(['PHASE', 'recycled-armed', k+3, k+3, k+2, k+1, 1, h+1, 1, c, 3, 1, 1, 2, 0, 1, 1, 1, 1, h+1, 1, 1, 'pending', 'not-checked', 1, 0, 0])
    rows += [['REPORT', b, 1], ['HISTORY', 4, 4, 'removed', c]]
    rows.append(['PHASE', 'recycled-returned', k+5, k+5, k+4, k+3, 1, h+1, 2, 0, 4, 2, 1, 2, 0, 0, 1, 1, 1, h+1, 1, 1, 'copied', 'pending', 1, 0, 0])
    pair(k + 2, f, a, None, 1, h + 2, 'next', None, None)
    pair(k + 3, g, b, 0, 2, h + 2, 'next', 0, k + 1)
    pair(k + 4, f, c, 0, 3, h + 2, 'next', 0, k + 2)
    pair(k + 5, g, c, 1, 3, h + 2, 'checkpoint', 0, k + 3)
    rows += [['REPORT', c, 2]] + admissions
    rows.append(['PHASE', 'finish', k+5, k+5, k+5, k+4, 1, h+2, 3, 0, 4, 3, 1, 2, 0, 0, 0, 1, 1, h+3, 1, 1, 'copied', 'copied', 1, 1, 1])
    rows.append([f'module-session-reuse:profile=session-absolute-v1:schedule=not-run:k={k}:direction={direction}:calls={k+5}:confirmed={k+5}:sampled={k+4}:unsampled=1:batches={h+2}:reports=3:actions=4:banks=3:shared-owner-refusals=2:held-report-copies=1:reclaimed-before-checkpoint=1:restaged=1:worker-joins=1:complete'])
    return rows, args


class Controls(unittest.TestCase):
    def refuses(self, rows, args):
        with self.assertRaises((AssertionError, ValueError, UnicodeError)):
            C.check(encode(rows), b'', **args)

    def test_complete_four_cases_preserve_all_rows_and_bounds(self):
        total = 0
        for k in (10, 1000):
            for direction in ('csv-length', 'length-csv'):
                rows, args = fixture(k, direction, (U64-2, U64-1, U64), True)
                data = encode(rows)
                result = C.check(data, b'', **args)
                self.assertEqual(result['status'], 'REUSE_WIRE_PASS')
                self.assertEqual(result['stdout'], data)
                self.assertEqual(result['rows'], [[str(v) for v in row] for row in rows])
                self.assertEqual(result['counts'], dict(META=13, CALL=k+5, RAW=k+5, SAMPLE=k+4,
                                                        HISTORY=4, REPORT=3, PHASE=8, terminal=1))
                self.assertEqual(sum(result['counts'].values()), len(rows))
                self.assertEqual(len(rows), 3*k + 43)
                self.assertEqual([len(result[name]) for name in ('calls', 'raw', 'samples', 'phases', 'history', 'reports')],
                                 [k+5, k+5, k+4, 8, 4, 3])
                self.assertEqual([s['rank'] for s in result['samples'][-2:]], [0, 0])
                self.assertEqual([s['start_sequence'] for s in result['samples'][-2:]], [k+2, k+3])
                self.assertEqual([r['records'] for r in result['reports']], [k+1, 1, 2])
                self.assertLessEqual(len(data), (k+5)*420 + (k+4)*200 + 8192)
                total += result['totals']['calls']
        self.assertEqual(total, 2040)

    def test_numeric_domains_framing_and_caps(self):
        rows, args = fixture()
        selections = [(i, next(j for j, v in enumerate(row) if type(v) is int))
                      for i, row in enumerate(rows) if any(type(v) is int for v in row)]
        # Serialize first: malformed values must reach the parser, not fixture arithmetic.
        for i, j in selections:
            for value in ('', '+1', '-1', '01', ' 1', '1 ', str(U64+1), '١'):
                bad = copy.deepcopy(rows); bad[i][j] = value
                self.refuses(bad, args)
        data = encode(rows)
        for bad in (b'', data[:-1], data+b'\n', data.replace(b'\n', b'\r\n'),
                    data+b'x', b'x'*631093, b'\n'*3044, b'x'*350+b'\n', bytearray(data), data.decode()):
            with self.assertRaises((AssertionError, ValueError, UnicodeError)):
                C.check(bad, b'', **args)
        for tag, limit in C.ROW_LIMITS.items():
            i = next(i for i, row in enumerate(rows) if tuple(row[:len(tag)]) == tag)
            bad = copy.deepcopy(rows); bad[i][-1] = 'x'*limit
            self.refuses(bad, args)

    def test_expected_identity_geometry_and_continuation_are_exact(self):
        rows, args = fixture()
        mutations = (
            (0, 2, 'module-session-owner-v1'), (0, 3, 'finite'), (0, 4, 'run'),
            (0, 5, 1000), (0, 6, 'length-csv'), (0, 7, 0), (0, 8, 0),
            (0, 9, 124), (0, 10, 123), (0, 10, 1 << 31), (0, 11, 5),
            (0, 12, 2), (0, 13, 2),
            (2, 2, 0), (2, 3, 196608), (2, 4, 131073), (2, 5, 131089),
            (3, 2, '612c622c64'), (3, 3, 4), (3, 4, 2), (3, 5, 4),
        )
        for i, j, value in mutations:
            bad = copy.deepcopy(rows); bad[i][j] = value; self.refuses(bad, args)
        for j in range(2, len(rows[1])):
            bad = copy.deepcopy(rows)
            bad[1][j] = bad[1][j] + 1 if type(bad[1][j]) is int else bad[1][j] + 'x'
            self.refuses(bad, args)
        for name, values in (('k', (True, 16, '10')), ('direction', ('length-csv', 'unknown', 0)),
                             ('cpus', ((5, 2), (2, 2), (2, 1024), (True, 5), [2, 5]))):
            for value in values:
                with self.assertRaises(AssertionError): C.check(encode(rows), b'', **dict(args, **{name: value}))
        for key, values in dict(csv_va=(0, 4097, U64+1), length_va=(0, 4225, U64),
                                csv_length=(4, 257, 125), length_length=(4, 81, 40),
                                continuation=(0, True, 18, U64)).items():
            for value in values:
                bad = copy.deepcopy(args); bad['geometry'][key] = value
                with self.assertRaises(AssertionError): C.check(encode(rows), b'', **bad)
        for rets in ((), ((36, 36), (40,)), ((125, 36), (40,)), ((0,), (40,)),
                     ((126,), (40,)), ((36, 125), (41,)), ((True,), (40,))):
            bad = copy.deepcopy(args); bad['geometry']['returns'] = rets
            with self.assertRaises(AssertionError): C.check(encode(rows), b'', **bad)
        raw = next(i for i, r in enumerate(rows) if r[0] == 'RAW')
        for j, values in ((2, (8, 120, 196616, 204808, U64, 200713)),
                          (3, (131072, 131090, U64)), (4, (0, 126)), (7, (U32+1,)), (8, (U32+1,))):
            for value in values:
                bad = copy.deepcopy(rows); bad[raw][j] = value
                self.refuses(bad, args)
        for rsp, low, high in ((136, 8, 144), (U64-23, U64-151, U64)):
            changed = copy.deepcopy(rows); changed[2][2:4] = [low, high]
            for row in changed:
                if row[0] == 'RAW': row[2] = rsp
            C.check(encode(changed), b'', **args)
        # Self-reported IDs are domain-checked, not invented external PID witnesses.
        changed = copy.deepcopy(rows); changed[0][10] = 125
        self.assertEqual(C.check(encode(changed), b'', **args)['worker_tid'], 125)

    def test_generation_reset_and_sample_ranks_sequences(self):
        for generations in ((0, 19, 31), (11, 11, 31), (11, 19, 19), (11, 19, 11)):
            rows, args = fixture(generations=generations); self.refuses(rows, args)
        rows, args = fixture()
        for i, row in enumerate(rows):
            if row[0] == 'CALL':
                positions = (1, 2, 3, 4, 5, 7, 8, 9)
            elif row[0] == 'SAMPLE':
                positions = (1, 2, 3, 4, 5, 6, 8)
            else:
                continue
            for j in positions:
                bad = copy.deepcopy(rows); bad[i][j] += 1
                self.refuses(bad, args)
        # Coherently claim C-F remained closed after the K-exhausted bank reset.
        bad = copy.deepcopy(rows)
        call = next(r for r in bad if r[0] == 'CALL' and r[1] == 14)
        call[6:8] = ['closed', 0]
        bad = [r for r in bad if not (r[0] == 'SAMPLE' and r[1:4] == [31, 0, 0])]
        self.refuses(bad, args)

    def test_history_reports_and_retained_copy_claims(self):
        rows, args = fixture()
        for i, row in enumerate(rows):
            if row[0] not in ('HISTORY', 'REPORT') and row[:2] != ['META', 'epochs']:
                continue
            for j in range(1 if row[0] != 'META' else 2, len(row)):
                bad = copy.deepcopy(rows)
                bad[i][j] = bad[i][j] + 1 if type(bad[i][j]) is int else 'wrong'
                self.refuses(bad, args)
        reports = [i for i, r in enumerate(rows) if r[0] == 'REPORT']
        for i in reports[1:]:
            bad = copy.deepcopy(rows); bad[i] = list(rows[reports[0]])
            self.refuses(bad, args)
        # A's copy remains index one/emitted even after its live slot disappears.
        phase = next(i for i, r in enumerate(rows) if r[:2] == ['PHASE', 'recycled-armed'])
        for j in (14, 17, 18, 24):
            bad = copy.deepcopy(rows); bad[phase][j] = 1 - bad[phase][j]
            self.refuses(bad, args)

    def test_every_phase_field_and_order_are_exact(self):
        rows, args = fixture()
        positions = [i for i, r in enumerate(rows) if r[0] == 'PHASE']
        for i in positions:
            for j in range(1, len(rows[i])):
                bad = copy.deepcopy(rows)
                bad[i][j] = bad[i][j] + 1 if type(bad[i][j]) is int else bad[i][j] + 'x'
                self.refuses(bad, args)
        for left, right in zip(positions, positions[1:]):
            bad = copy.deepcopy(rows); bad[left], bad[right] = bad[right], bad[left]
            self.refuses(bad, args)

    def test_missing_extra_and_reordered_rows_refuse(self):
        rows, args = fixture()
        # Every row, including both delayed C calls, must occur exactly once.
        for i in range(len(rows)):
            self.refuses(rows[:i]+rows[i+1:], args)
            self.refuses(rows[:i]+[rows[i]]+rows[i:], args)
        for i in range(len(rows)-1):
            bad = copy.deepcopy(rows); bad[i], bad[i+1] = bad[i+1], bad[i]
            self.refuses(bad, args)
        self.refuses([['UNKNOWN', 0]]+rows, args)

    def test_final_four_acknowledgements_and_batch_boundaries(self):
        rows, args = fixture()
        result = C.check(encode(rows), b'', **args)
        self.assertEqual([(r['ack'], r['ack_ordinal']) for r in result['raw'][-4:]],
                         [('next', 13), ('next', 14), ('next', 15), ('checkpoint', 0)])
        self.assertEqual([r['prefix'] for r in result['calls'][-4:]], [1, 2, 3, 3])
        for i, row in enumerate(rows):
            if row[0] == 'RAW':
                for j, value in ((9, 'checkpoint' if row[9] == 'next' else 'next'), (10, row[10]+1)):
                    bad = copy.deepcopy(rows); bad[i][j] = value; self.refuses(bad, args)
            elif row[0] == 'CALL':
                bad = copy.deepcopy(rows); bad[i][9] += 1; self.refuses(bad, args)
        bad = copy.deepcopy(rows)
        for row in bad:
            if row[0] == 'RAW' and row[1] == 13: row[9:11] = ['checkpoint', 0]
            if row[0] == 'CALL' and row[1] >= 14: row[9] += 1
        self.refuses(bad, args)

    def test_zero_maximum_and_unavailable_clock_precedence(self):
        cases = ((0, 0, 0, 0, 'value', 0), (U64, U64, U32, U32, 'value', U64),
                 (0, U64, 0, 0, 'value', U64), (U64, 0, 0, 0, 'unavailable', 2),
                 (U64, 0, 0, 1, 'unavailable', 1))
        for start, end, a, b, kind, value in cases:
            rows, args = fixture()
            for row in rows:
                if row[0] == 'RAW': row[5:9] = [start, end, a, b]
                if row[0] == 'SAMPLE': row[6:9] = [start, kind, value]
            result = C.check(encode(rows), b'', **args)
            self.assertTrue(all(r['start_ticks'] == start and r['end_ticks'] == end for r in result['raw']))
            self.assertTrue(all(s['end_kind'] == kind and s['end_value'] == value for s in result['samples']))
            for wrong in ((start, kind, (value+1) & U64), (start, 'wrong', value)):
                bad = copy.deepcopy(rows)
                next(r for r in bad if r[0] == 'SAMPLE')[6:9] = wrong
                self.refuses(bad, args)
        # Neither cross-call chronology nor stable AUX is a wire prerequisite.
        rows, args = fixture()
        raws = [r for r in rows if r[0] == 'RAW']
        raws[0][5:9] = [U64, U64, U32, U32]
        next(r for r in rows if r[0] == 'SAMPLE')[6:9] = [U64, 'value', U64]
        C.check(encode(rows), b'', **args)

    def test_completion_and_actual_stderr_are_exact(self):
        rows, args = fixture(); data = encode(rows)
        for stderr in (b'\n', b'normal-module-session-reuse FAILED: deadline\n', b' ', b'\xff', '', bytearray()):
            with self.assertRaises(AssertionError): C.check(data, stderr, **args)
        for i, cell in enumerate(rows[-1][0].split(':')):
            bad = copy.deepcopy(rows); cells = bad[-1][0].split(':'); cells[i] = cell+'x'
            bad[-1][0] = ':'.join(cells); self.refuses(bad, args)
        self.refuses(rows+[['module-session-reuse:complete']], args)
        for schema in ('module-session-owner-v1', 'module-session-v1'):
            bad = copy.deepcopy(rows); bad[0][2] = schema; self.refuses(bad, args)

    def test_optimized_refusal_and_source_local_import(self):
        here = Path(__file__).resolve().parent
        self.assertEqual(Path(C.__file__).resolve(), here/'reuse_output.py')
        for path in (here/'reuse_output.py', Path(__file__).resolve()):
            run = subprocess.run([sys.executable, '-B', '-O', str(path)], capture_output=True, timeout=5)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (1, b'', b'assertions required\n'))
        # Tempfile obeys inherited TMPDIR; the hostile ambient module is never loaded.
        with tempfile.TemporaryDirectory(prefix='reuse-import-') as directory:
            path = Path(directory)
            (path/'reuse_output.py').write_text('raise RuntimeError("ambient import")\n')
            env = dict(os.environ, PYTHONPATH=directory, PYTHONDONTWRITEBYTECODE='1')
            script = ('import importlib.util, pathlib, sys; '
                      'p=pathlib.Path(sys.argv[1]); s=importlib.util.spec_from_file_location("probe",p); '
                      'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                      'assert pathlib.Path(m.C.__file__).resolve()==p.resolve().with_name("reuse_output.py")')
            run = subprocess.run([sys.executable, '-B', '-c', script, str(Path(__file__).resolve())],
                                 cwd=directory, env=env, capture_output=True, timeout=5)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b'', b''))
            self.assertFalse((path/'__pycache__').exists())


if __name__ == '__main__':
    unittest.main()
