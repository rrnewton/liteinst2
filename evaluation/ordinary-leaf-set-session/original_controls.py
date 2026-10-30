"""Fabricated transcript controls; no native reference or installed application."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().with_name('original_output.py')
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == 'daeed0309f62ac4fadc69afdd2c26ba758063d5c5599a148a831bf37972fa8aa'
_spec = importlib.util.spec_from_file_location('_original_controls_checked', SOURCE)
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)
PAYLOADS = (b'', b'a,b', b'"1 2", 3', b'"",42,  ', b'""""', b' ' * 64, b',' * 64, b'9' * 64)
VALUES = ((1, 0, 0, 0), (2, 3, 0, 0), (2, 8, 3, 2), (3, 8, 2, 2),
          (1, 4, 0, 0), (1, 64, 0, 64), (65, 64, 0, 0), (1, 64, 64, 0))
CALLER = dict(extent=20, continuation=15)


def fixture(n=4, payloads=PAYLOADS, expected=VALUES):
    table = tuple(dict(function_id=11 * (i + 1), operation=C.OPERATIONS[i], policy='whole' if i == 1 else 'certified',
                       elf_va=4096 + 64 * i, extent=16, returns=(7, 15)) for i in range(n))
    rows = [['LEAF_ORIGINAL_READY', 'leaf-original-v1', 31, 31, 2, n, 0x900000, len(payloads)]]
    for i, item in enumerate(table):
        entry = 0x1000000 + item['elf_va']
        rows.append(['LEAF_ORIGINAL_FUNCTION', i, item['function_id'], item['operation'], item['policy'], item['elf_va'], item['extent'], entry, entry + item['extent'], len(item['returns'])])
        rows.extend(['LEAF_ORIGINAL_RET', i, offset] for offset in item['returns'])
    rows.extend(['LEAF_ORIGINAL', i + 1, len(data), C.fnv(data), *values[:n]]
                for i, (data, values) in enumerate(zip(payloads, expected)))
    rows.append(['LEAF_ORIGINAL_DONE', len(payloads), n * len(payloads), n * len(payloads)])
    return rows, dict(records=payloads, table=table, caller=CALLER, cpu=2)


def wire(rows):
    return ('\n'.join(','.join(map(str, row)) for row in rows) + '\n').encode('ascii')


class Controls(unittest.TestCase):
    def refuse(self, raw, args, stderr=b''):
        with self.assertRaises((AssertionError, UnicodeError)):
            C.check(raw, stderr, **args)

    def test_original_all_cardinalities_operations_and_byte_truth(self):
        for n in range(1, 5):
            rows, args = fixture(n)
            checked = C.check(wire(rows), b'', **args)
            self.assertEqual(checked['status'], 'ORIGINAL_SCALAR_PASS')
            self.assertEqual(checked['raw'], wire(rows))
            self.assertEqual(checked['totals'], dict(records=8, calls=8*n, returns=8*n))
            self.assertEqual(checked['results'], [[i+1, len(data), C.fnv(data), *value[:n]] for i, (data, value) in enumerate(zip(PAYLOADS, VALUES))])
            self.assertEqual(len(checked['table']), n)
            self.assertEqual([row['return_count'] for row in checked['table']], [2] * n)
            rows, args = fixture(n, (), ())
            self.assertEqual(C.check(wire(rows), b'', **args)['results'], [])
        self.assertEqual(C.fnv(b''), 14695981039346656037)
        self.assertEqual(C.fnv(b'hello'), 0xa430d84680aabd0b)
        for data, expected in zip(PAYLOADS, VALUES):
            self.assertEqual(tuple(C.truths(data)[op] for op in C.OPERATIONS), expected)
        rows, args = fixture(); args = copy.deepcopy(args)
        args['table'][-1]['function_id'] = C.U64; rows[10][2] = C.U64
        rows[0][2:4] = [(1 << 32)-1] * 2
        rows[0][6] = C.U64 - CALLER['extent']
        self.assertEqual(C.check(wire(rows), b'', **args)['ready']['caller'], C.U64 - CALLER['extent'])

    def test_original_geometry_last_selection_ret_and_identity(self):
        rows, args = fixture()
        for index, column in [(0, 2), (0, 3), (0, 4), (0, 5), (0, 7), (10, 1), (10, 2), (10, 5), (10, 6), (10, 7), (10, 8), (10, 9), (11, 1), (12, 2)]:
            bad = copy.deepcopy(rows); bad[index][column] += 1; self.refuse(wire(bad), args)
        for key, value in [('function_id', 11), ('operation', 'csv_fields'), ('policy', 'gated'), ('extent', 257), ('elf_va', C.U64), ('returns', (7, 7)), ('returns', (16,)), ('returns', ())]:
            bad = copy.deepcopy(args); bad['table'][-1][key] = value; self.refuse(wire(rows), bad)
        for field, value in [('extent', 0), ('continuation', 0), ('continuation', 20)]:
            bad = copy.deepcopy(args); bad['caller'][field] = value; self.refuse(wire(rows), bad)
        for cpu in (-1, 1024, True):
            bad = dict(args, cpu=cpu); self.refuse(wire(rows), bad)
        bad = copy.deepcopy(rows); bad[0][6] = C.U64 - CALLER['extent'] + 1; self.refuse(wire(bad), args)
        # Coherent table + wire still refuses a third full page and a different load bias.
        bad, changed = copy.deepcopy(rows), copy.deepcopy(args)
        for i, va in enumerate((4096, 8192, 12288, 12352)):
            changed['table'][i]['elf_va'] = va
            bad[1+3*i][5] = va; bad[1+3*i][7:9] = [0x1000000+va, 0x1000000+va+16]
        self.refuse(wire(bad), changed)
        bad = copy.deepcopy(rows); bad[10][7] += 4096; bad[10][8] += 4096; self.refuse(wire(bad), args)

    def test_original_framing_numeric_order_and_totals(self):
        rows, args = fixture(); raw = wire(rows)
        for bad in (raw[:-1], raw+b'\n', raw.replace(b'\n', b'\r\n'), raw.replace(b'\n', b'\v', 1), b'\xff'+raw, b'x'*(4*1024*1024+1), wire(rows[:-1]), wire(rows+[rows[-1]]), wire(rows[:13]+rows[14:])):
            self.refuse(bad, args)
        self.refuse(raw, args, b'warning\n')
        for word in ('01', '-1', '+1', ' 1', '1 ', str(1 << 64), '1.0', ''):
            bad = copy.deepcopy(rows); bad[13][1] = word; self.refuse(wire(bad), args)
        for column in (1, 2, 3):
            bad = copy.deepcopy(rows); bad[-1][column] += 1; self.refuse(wire(bad), args)
        bad = copy.deepcopy(rows); bad[13], bad[14] = bad[14], bad[13]; self.refuse(wire(bad), args)
        bad = copy.deepcopy(rows); bad[10][0] = 'LEAF'; self.refuse(wire(bad), args)

    def test_original_values_and_same_aggregate_corruption(self):
        rows, args = fixture()
        for at in range(13, len(rows)-1):
            for column in range(1, 8):
                bad = copy.deepcopy(rows); bad[at][column] += 1; self.refuse(wire(bad), args)
        bad = copy.deepcopy(rows); bad[15][7] += 1; bad[16][7] -= 1
        self.assertEqual(sum(r[7] for r in bad[13:-1]), sum(r[7] for r in rows[13:-1]))
        self.refuse(wire(bad), args)
        bad = copy.deepcopy(args); bad['records'] = (*PAYLOADS[:-1], b'8'*64)
        self.refuse(wire(rows), bad)
        bad = copy.deepcopy(rows); bad[13][4:] = bad[14][4:]; self.refuse(wire(bad), args)

    def test_original_frames_and_inherited_refusals(self):
        self.assertEqual(C.frame((b'', b'a,b'), n=4), b'MODCSV1\0\x02\0\0\0\0\x03a,b')
        self.assertEqual(C.frame((), n=1), b'MODCSV1\0'+b'\0'*4)
        for n in range(1, 5):
            limit = min(2048, 4096//n)
            self.assertEqual(len(C.frame((b'',)*limit, n=n)), 12+limit)
            with self.assertRaises(AssertionError): C.frame((b'',)*(limit+1), n=n)
        for data in (b'a"b', b'"x', b'"x"z', b'\0', b'\n', b'\x7f', b'\xff', b'x'*65):
            with self.assertRaises(AssertionError): C.frame((data,), n=4)
        for n in (0, 5, True):
            with self.assertRaises(AssertionError): C.frame((), n=n)
        for reason in C.ORIGINAL_REFUSALS:
            error = b'module-session-original INPUT_REFUSED: '+reason.encode()+b'\n'
            self.assertEqual(C.refusal(b'', error, 2, reason)['status'], 'EXPECTED_INPUT_REFUSAL')
            for stdout, stderr, code in ((b'x', error, 2), (b'', error[:-1], 2), (b'', error, 0), (b'', error, -9)):
                with self.assertRaises(AssertionError): C.refusal(stdout, stderr, code, reason)
        with self.assertRaises(AssertionError): C.refusal(b'', b'', 2, 'unknown')

    def test_original_local_dependency_and_optimized_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); local = root/'local'; local.mkdir()
            copied = local/'original_output.py'; copied.write_bytes(SOURCE.read_bytes())
            (local/'output.py').write_bytes(SOURCE.with_name('output.py').read_bytes())
            (root/'output.py').write_text('raise RuntimeError("ambient import")\n')
            env = dict(os.environ, PYTHONPATH=str(root), PYTHONDONTWRITEBYTECODE='1')
            command = [sys.executable, '-B', str(copied)]
            good = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=10)
            self.assertEqual((good.returncode, good.stdout, good.stderr), (0, b'', b''))
            optimized = subprocess.run([sys.executable, '-O', '-B', str(copied)], cwd=root, env=env, capture_output=True, timeout=10)
            self.assertNotEqual(optimized.returncode, 0); self.assertEqual(optimized.stdout, b'')
            self.assertIn(b'assertions required', optimized.stderr)
            (local/'output.py').write_text('raise RuntimeError("must not import")\n')
            bad = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=10)
            self.assertNotEqual(bad.returncode, 0); self.assertNotIn(b'must not import', bad.stderr)
            self.assertFalse((local/'__pycache__').exists())


if __name__ == '__main__':
    unittest.main()
