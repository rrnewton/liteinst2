#!/usr/bin/env python3
"""Fabricated transcript/parser controls; never builds or calls the subject."""
import importlib.util
from pathlib import Path
import unittest
import tempfile


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
output = load('module_output_controls', HERE/'output.py')
runner = load('module_runner_controls', HERE/'reproduce.py')


def fixture(k):
    lines = [output.HEADER]
    csv_len = [0, 1, 5, 1, 2, 2, 2, 2, 5, 7, 9, 8, 4, 5, 24, 29]
    csv_value = [1, 1, 3, 2, 3, 2, 2, 1, 1, 2, 3, 2, 1, 2, 4, 3]
    bounds = [0, 1, 1, 2, 17, 64, 64, 64]; values = [0, 0, 1, 1, 8, 0, 63, 64]
    for i in range(32):
        f = i % 2; case = i//2 if f == 0 else (i//2) % 8
        bound = (csv_len, bounds)[f][case]; value = (csv_value, values)[f][case]
        row = [i+1, (101, 202)[f], case+1, bound, value, value, value, (89, 125)[(i//2) % 2] if f == 0 else (34, 40)[(i//2) % 2],
            1 if i < 2*k else 3, i+1 if i < 2*k else 0, 1, 32760, 8207,
            i*100, i*100+90, 3, 3, 2 if i == 31 else 1, 0 if i == 31 else i+2]
        lines.append(','.join(map(str, row)))
    fields = [k, 32, 32, 2, 1, 32, 2, 512, 2*k, 32-2*k, 31, 1, 17, 17, 3, 9, 4096, 4224, 126, 41, 8192, 2, 2, 0x6d6f6401, 101, 202, 1]
    lines.append('normal-module-work MODULE_FUNCTIONAL_PASS ' + ' '.join(f'{name}={value}' for name, value in zip(output.TERMINAL_KEYS, fields)))
    return ('\n'.join(lines)+'\n').encode('ascii')


def check(data, k, stderr=b''):
    return output.check(data, stderr, k, (126, 41), ([89, 125], [34, 40]), 15, 3)


class Controls(unittest.TestCase):
    def test_two_cohorts_full_corpora_and_sampling_boundaries(self):
        for k in (16, 1):
            result = check(fixture(k), k)
            self.assertEqual(len(result['rows']), 32)
            self.assertEqual(sum(row['owner'] == 1 for row in result['rows']), 2*k)
            self.assertEqual(sum(row['owner'] == 3 for row in result['rows']), 32-2*k)
            self.assertEqual(result['terminal']['shared_source_pages'], 1)

    def test_row_corruption_identity_global_slots_ret_and_acknowledgements(self):
        for k in (16, 1):
            source = fixture(k).decode().splitlines()
            for row_index, column, value in [(0, 1, 202), (1, 1, 101), (1, 9, 1), (0, 7, 34),
                    (0, 4, 0), (0, 5, 0), (0, 6, 0), (0, 8, 3), (31, 17, 1), (0, 18, 3),
                    (0, 12, 8208), (0, 16, 4), (0, 14, -1), (0, 0, '01')]:
                lines = source.copy(); words = lines[1+row_index].split(','); words[column] = str(value)
                lines[1+row_index] = ','.join(words)
                with self.subTest(k=k, row=row_index, column=column), self.assertRaises(AssertionError):
                    check(('\n'.join(lines)+'\n').encode(), k)

    def test_terminal_population_geometry_framing_and_stderr(self):
        for k in (16, 1):
            source = fixture(k)
            changes = [source[:-1], source+b'\n', source.replace(b'\n', b'\r\n'), source.replace(b'installed=32', b'installed=31'),
                source.replace(b'entry1=4224', b'entry1=8192'), source.replace(b'returns1=2', b'returns1=1'),
                source.replace(b'function1=202', b'function1=101'), source.replace(b'cpu=3', b'cpu=4'),
                source.replace(b'completed='+str(2*k).encode(), b'completed=0')]
            for data in changes:
                with self.assertRaises(AssertionError): check(data, k)
            with self.assertRaises(AssertionError): check(source, k, b'error\n')
            lines = source.decode().splitlines()
            with self.assertRaises(AssertionError): check(('\n'.join(lines[:32]+lines[33:])+'\n').encode(), k)

    def test_complete_symbol_and_disassembly_extents(self):
        symbols = ' 12: 0000000000001000 6 FUNC LOCAL DEFAULT 4 csv_fields\n'
        self.assertEqual(runner.symbol(symbols, 'csv_fields'), (4096, 6))
        with self.assertRaises(AssertionError): runner.symbol(symbols*2, 'csv_fields')
        with self.assertRaises(AssertionError): runner.symbol(symbols.replace('LOCAL', 'GLOBAL'), 'csv_fields')
        text = '0000000000001000 <csv_fields>:\n    1000:\tb8 01 00 00 00\tmov eax,0x1\n    1005:\tc3\tret\n'
        self.assertEqual(runner.returns(text, 'csv_fields', 4096, 6), [5])
        for bad in (text.replace('1005:', '1006:'), text.replace('c3\tret', '90\tnop'), text.replace('<csv_fields>', '<other>')):
            with self.assertRaises(AssertionError): runner.returns(bad, 'csv_fields', 4096, 6)


    def test_stack_extent_domains_and_full_width_zero_clocks(self):
        def changed(k, rsp, ticks):
            lines = fixture(k).decode().splitlines()
            for i in range(1, 33):
                row = lines[i].split(','); row[11] = str(rsp)
                row[13:17] = [str(ticks), str(ticks), str(2**32-1), str(2**32-1)]
                lines[i] = ','.join(row)
            return ('\n'.join(lines)+'\n').encode('ascii')
        for k in (16, 1):
            for rsp in (136, 2**64-24):
                for ticks in (0, 2**64-1):
                    self.assertEqual(len(check(changed(k, rsp, ticks), k)['rows']), 32)
            for rsp in (8, 120, 2**64-8):
                with self.subTest(k=k, rsp=rsp), self.assertRaises(AssertionError):
                    check(changed(k, rsp, 0), k)

    def test_original_pins_refuse_completed_file_drift(self):
        with tempfile.TemporaryDirectory(prefix='module-pin-control-', dir=runner.ROOT/'ignored') as name:
            directory = Path(name); pins = {}; original = {}
            for name in ('plan.json', 'command.json', 'native.json', 'stdout.txt',
                         'results.csv', 'readelf', 'controls.py', 'localize.map'):
                path = directory/name; digest = runner.save(path, {'source_control': name})
                runner.remember(pins, path, digest); original[path] = path.read_bytes()
            frozen = dict(pins)
            runner.check_pins(pins)
            for path, data in original.items():
                path.write_bytes(data+b'changed')
                with self.assertRaises(AssertionError): runner.check_pins(pins)
                with self.assertRaises(AssertionError): runner.remember(pins, path)
                with self.assertRaises(AssertionError): runner.remember(pins, path, runner.sha(path))
                self.assertEqual(pins, frozen)
                path.write_bytes(data)
                self.assertEqual(runner.remember(pins, path), frozen[str(path)])
                runner.check_pins(pins)
            bad = directory/'unaccepted'; bad.write_bytes(b'new')
            with self.assertRaises(AssertionError): runner.remember(pins, bad, '0'*64)
            self.assertEqual(pins, frozen)

    def test_caller_func_symbols_join_disassembled_extent(self):
        caller = dict(elf_va=4096, length=16)
        row = ' 12: 0000000000001000 16 FUNC GLOBAL DEFAULT 4 liteinst_csv_call_and_store\n'
        runner.caller_symbols(row, caller)
        runner.caller_symbols(row*2, caller)
        for bad in ('', row*3, row.replace('FUNC', 'OBJECT'), row.replace('GLOBAL', 'LOCAL'),
                    row.replace('DEFAULT', 'HIDDEN'), row.replace(' 4 ', ' ABS '),
                    row.replace('0000000000001000', '0000000000001001'),
                    row.replace(' 16 ', ' 15 '), row.replace('liteinst_csv_call_and_store', 'other')):
            with self.assertRaises(AssertionError): runner.caller_symbols(bad, caller)
        # Internally consistent but shortened disassembly cannot override the full ELF extent.
        with self.assertRaises(AssertionError): runner.caller_symbols(row, dict(elf_va=4096, length=15))

    def test_exact_module_and_csv_control_inventory(self):
        names = list(runner.MODULE_TESTS + runner.CSV_TESTS)
        runner.control_inventory(names)
        runner.control_inventory(list(reversed(names))+['normal::other::old_control'])
        for at in (0, 4):
            changed = names.copy(); changed[at] += '_renamed'
            with self.assertRaises(AssertionError): runner.control_inventory(changed)
        for changed in (names[:-1], names+[names[0]],
                        names+['normal::module::tests::unexpected'], names+['normal::csv::tests::unexpected']):
            with self.assertRaises(AssertionError): runner.control_inventory(changed)


if __name__ == '__main__':
    unittest.main()
