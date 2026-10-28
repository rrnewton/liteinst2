"""Synthetic file/metadata mutations; no compiler, loader or native test credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('selected_provenance', Path(__file__).with_name('provenance.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def fixture(stripped):
    # A deliberately small ELF envelope, independently laid out. The bytes are
    # never executed and are not claimed to be a compiler output or valid leaf.
    data = bytearray(0x3000)
    names = ['', '.dynsym', '.dynstr', '.text', '.dynamic', '.shstrtab']
    if not stripped:
        names += ['.strtab', '.symtab']
    text = b'\0' + b'\0'.join(name.encode() for name in names[1:]) + b'\0'
    name_at = {name: text.index(name.encode()) if name else 0 for name in names}
    dynstr = b'\0ordinary_checksum\0'
    symstr = b'\0ordinary_checksum_nonempty\0'
    data[0x300:0x300 + len(dynstr)] = dynstr
    data[0x340:0x370] = bytes(24) + struct.pack('<IBBHQQ', 1, 0x12, 0, 3, 0x1000, 8)
    data[0x380:0x390] = struct.pack('<IIII', 1, 1, 1, 0)
    data[0x1000:0x1040] = bytes(range(64))
    data[0x2500:0x2500 + len(text)] = text
    data[0x2600:0x2600 + len(symstr)] = symstr
    data[0x2700:0x2730] = bytes(24) + struct.pack('<IBBHQQ', 1, 2, 0, 3, 0x1020, 8)
    ph = [(1, 4, 0, 0, 0, 0x400, 0x400, 4096),
          (1, 5, 0x1000, 0x1000, 0x1000, 64, 64, 4096),
          (1, 6, 0x2000, 0x2000, 0x2000, 256, 256, 4096),
          (2, 6, 0x2000, 0x2000, 0x2000, 128, 128, 8),
          (0x6474e551, 6, 0, 0, 0, 0, 0, 16),
          (0x6474e552, 4, 0x2000, 0x2000, 0x2000, 256, 256, 1)]
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 3, 62, 1, 0, 64, 0x2800, 0, 64, 56, len(ph), 64, len(names), 5)
    for i, row in enumerate(ph):
        struct.pack_into('<IIQQQQQQ', data, 64 + 56 * i, *row)
    for i, row in enumerate(((0x6ffffef5, 0x380), (5, 0x300), (6, 0x340),
                             (10, len(dynstr)), (11, 24), (30, 8), (0x6ffffffb, 1), (0, 0))):
        struct.pack_into('<QQ', data, 0x2000 + i * 16, *row)
    # name,type,flags,address,file,size,link,info,alignment,entry-size
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_at['.dynsym'], 11, 2, 0x340, 0x340, 48, 2, 1, 8, 24),
        (name_at['.dynstr'], 3, 2, 0x300, 0x300, len(dynstr), 0, 0, 1, 0),
        (name_at['.text'], 1, 6, 0x1000, 0x1000, 64, 0, 0, 16, 0),
        (name_at['.dynamic'], 6, 3, 0x2000, 0x2000, 128, 2, 0, 8, 16),
        (name_at['.shstrtab'], 3, 0, 0, 0x2500, len(text), 0, 0, 1, 0)]
    if not stripped:
        sections += [(name_at['.strtab'], 3, 0, 0, 0x2600, len(symstr), 0, 0, 1, 0),
                     (name_at['.symtab'], 2, 0, 0, 0x2700, 48, 6, 2, 8, 24)]
    for i, row in enumerate(sections):
        struct.pack_into('<IIQQQQIIQQ', data, 0x2800 + 64 * i, *row)
    columns = '   Num:    Value          Size Type    Bind   Vis      Ndx Name\n'
    symbols = "Symbol table '.dynsym' contains 2 entries:\n" + columns
    symbols += '     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND\n'
    symbols += '     1: 0000000000001000     8 FUNC    GLOBAL DEFAULT    3 ordinary_checksum\n'
    if not stripped:
        symbols += "\nSymbol table '.symtab' contains 2 entries:\n" + columns
        symbols += '     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND\n'
        symbols += '     1: 0000000000001020     8 FUNC    LOCAL  DEFAULT    3 ordinary_checksum_nonempty\n'
    return bytes(data), symbols.encode('ascii')


def inputs():
    pre, pretext = fixture(False)
    post, posttext = fixture(True)
    return [pre, post, pretext, posttext]


def mutate(data, offset, fmt, value):
    output = bytearray(data)
    struct.pack_into(fmt, output, offset, value)
    return bytes(output)


class Provenance(unittest.TestCase):
    def test_complete_structural_manifest_has_exact_byte_authority(self):
        a = inputs()
        result = check.validate(*a)
        self.assertEqual((result['elf_va'], result['length'], result['file_offset']), (0x1020, 8, 0x1020))
        self.assertEqual(result['selected_code'], check.digest(bytes(range(32, 40))))
        self.assertEqual(result['prestrip'], check.digest(a[0]))
        self.assertEqual(result['final'], check.digest(a[1]))
        self.assertNotEqual(result['prestrip'], result['final'])
        self.assertEqual(len(result['geometry']), 6)
        self.assertFalse(result['selected_dynamic_definition'])
        self.assertFalse(result['final_static_symbols'])

    def test_selected_metadata_is_defined_local_complete_rx_function(self):
        for offset, fmt, value in ((0x271c, '<B', 0x12), (0x271c, '<B', 1),
                (0x271d, '<B', 2), (0x271e, '<H', 0), (0x2720, '<Q', 0x103f),
                (0x2728, '<Q', 0), (0x2728, '<Q', 257), (0x2800 + 3 * 64 + 8, '<Q', 7)):
            a = inputs(); a[0] = mutate(a[0], offset, fmt, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(AssertionError):
                check.validate(*a)
        a = inputs(); a[0] = a[0].replace(b'ordinary_checksum_nonempty\0', b'ordinary_checksum_nonemptx\0')
        with self.assertRaises(AssertionError): check.validate(*a)

    def test_strip_preserves_selected_and_complete_rx_bytes_and_geometry(self):
        for offset, fmt, value in ((0x1020, '<B', 99), (0x103f, '<B', 99),
                (64 + 56 + 32, '<Q', 63), (64 + 5 * 56 + 48, '<Q', 16),
                (64 + 4 * 56 + 4, '<I', 7)):
            a = inputs(); a[1] = mutate(a[1], offset, fmt, value)
            with self.subTest(offset=offset), self.assertRaises(AssertionError): check.validate(*a)
        a = inputs(); a[1], a[3] = a[0], a[2]
        with self.assertRaises(AssertionError): check.validate(*a)
        a = inputs(); a[1] = a[1].replace(b'.shstrtab', b'.debugxyz')
        with self.assertRaises(AssertionError): check.validate(*a)

    def test_global_elf_and_dynamic_sections_remain_restricted(self):
        for offset, fmt, value in ((16, '<H', 2), (18, '<H', 3),
                (64 + 56, '<I', 7), (64 + 56 + 4, '<I', 7),
                (64 + 56 + 40, '<Q', 65), (64 + 56 + 48, '<Q', 8192),
                (0x2000, '<Q', 12), (0x2000 + 2 * 16 + 8, '<Q', 0x350),
                (0x35c, '<B', 0x1a), (0x2800 + 3 * 64 + 4, '<I', 4)):
            a = inputs(); a[1] = mutate(a[1], offset, fmt, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(AssertionError): check.validate(*a)
        for truncated in (b'', inputs()[1][:63], inputs()[1][:0x2850], b'0' * (check.MIB + 1)):
            a = inputs(); a[1] = truncated
            with self.assertRaises(AssertionError): check.validate(*a)

    def test_external_metadata_must_join_binary_selected_value_size_and_kind(self):
        for before, after in ((b'contains 2 entries', b'contains 3 entries'),
                (b'1: 0000000000001020', b'2: 0000000000001020'),
                (b'0000000000001020', b'0000000000001021'),
                (b'8 FUNC    LOCAL', b'9 FUNC    LOCAL'),
                (b'8 FUNC    LOCAL', b'8 OBJECT  LOCAL'),
                (b'8 FUNC    LOCAL', b'8 FUNC    GLOBAL'),
                (b'ordinary_checksum_nonempty', b'wrong_selected_name')):
            a = inputs(); a[2] = a[2].replace(before, after)
            with self.subTest(after=after), self.assertRaises(AssertionError): check.validate(*a)
        for transform in (lambda b: b[:-1], lambda b: b + b'extra\n',
                lambda b: b.replace(b'\n', b'\r\n'), lambda b: b.replace(b'   Num:', b'\tNum:'),
                lambda b: b + b"Symbol table '.symtab' contains 2 entries:\n"):
            a = inputs(); a[2] = transform(a[2])
            with self.assertRaises(AssertionError): check.validate(*a)

    def test_extent_rejects_overflow_negative_and_boolean_coordinates(self):
        self.assertEqual(check.extent(b'1234', 1, 3), b'234')
        for start, size in ((-1, 1), (0, -1), (True, 1), (0, True),
                            ((1 << 64) - 1, 1), (1, 4)):
            with self.subTest(start=start, size=size), self.assertRaises(AssertionError):
                check.extent(b'1234', start, size)


if __name__ == '__main__':
    unittest.main()
