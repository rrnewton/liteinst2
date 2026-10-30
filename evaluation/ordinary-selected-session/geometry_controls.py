#!/usr/bin/env python3
"""Fabricated symbol text only; no ELF, tool, build or native validation credit."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import unittest
import geometry


def fixture(*, stripped=False):
    origins = ('.dynsym',) if stripped else ('.dynsym', '.symtab')
    tables = []
    for origin in origins:
        tables.append("Symbol table '" + origin + "' contains 3 entries:\n"
                      "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                      "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND\n"
                      "     1: 0000000000001000    27 FUNC    GLOBAL PROTECTED    4 first_equal\n"
                      "     2: 0000000000001040    31 FUNC    GLOBAL PROTECTED    4 uppercase_count\n")
    return ('\n' + '\n'.join(tables)).encode('ascii')


class Controls(unittest.TestCase):
    def refuses(self, raw, *, stripped=False):
        with self.assertRaises((AssertionError, ValueError, UnicodeError)):
            geometry.definitions(raw, stripped=stripped)

    def test_exact_named_origins_definitions_and_surviving_dynamic_table(self):
        before, after = fixture(), fixture(stripped=True)
        expected = (
            dict(name='first_equal', elf_va=4096, extent=27, symbol_type='FUNC',
                 binding='GLOBAL', visibility='PROTECTED', section_index=4),
            dict(name='uppercase_count', elf_va=4160, extent=31, symbol_type='FUNC',
                 binding='GLOBAL', visibility='PROTECTED', section_index=4))
        self.assertEqual(geometry.definitions(before, stripped=False), expected)
        self.assertEqual(geometry.definitions(after, stripped=True), expected)
        self.assertEqual(geometry.preserved(before, after), expected)
        self.refuses(before, stripped=True)
        self.refuses(after, stripped=False)

    def test_origin_cardinality_order_and_symbol_numbers_are_exact(self):
        raw = fixture()
        first = fixture(stripped=True)
        second = first.replace(b"'.dynsym'", b"'.symtab'")
        for bad in (raw + first, first + first, second + first,
                    raw.replace(b"'.symtab'", b"'.other'"),
                    raw.replace(b'contains 3 entries', b'contains 4 entries', 1),
                    raw.replace(b'contains 3 entries', b'contains 2 entries', 1),
                    raw.replace(b'     2:', b'     1:', 1),
                    raw.replace(b'     1:', b'     01:', 1),
                    raw.replace(b'Num:', b'Wrong:', 1)):
            self.assertNotEqual(bad, raw)
            self.refuses(bad)

    def test_duplicate_missing_undefined_and_versioned_names_are_refused(self):
        raw = fixture()
        for old, new in ((b'uppercase_count', b'first_equal'),
                         (b'first_equal', b'other_name'),
                         (b'first_equal', b'first_equal@VERSION'),
                         (b'first_equal', b'first_equal@@VERSION'),
                         (b'4 first_equal', b'UND first_equal'),
                         (b'4 first_equal', b'ABS first_equal'),
                         (b'4 first_equal', b'0 first_equal')):
            bad = raw.replace(old, new, 1)
            self.assertNotEqual(bad, raw)
            self.refuses(bad)
        # A valid duplicate has its own sequential index and declared count.
        duplicate = raw.replace(b'contains 3 entries', b'contains 4 entries', 1)
        row = b'     3: 0000000000001000    27 FUNC    GLOBAL PROTECTED    4 first_equal\n'
        duplicate = duplicate.replace(b"\nSymbol table '.symtab'", row + b"\nSymbol table '.symtab'", 1)
        self.refuses(duplicate)

    def test_every_definition_component_and_bounded_extent_must_match(self):
        raw = fixture()
        for old, new in ((b'0000000000001000', b'0000000000001001'),
                         (b'    27 FUNC', b'    28 FUNC'),
                         (b'FUNC    GLOBAL', b'OBJECT  GLOBAL'),
                         (b'GLOBAL PROTECTED', b'LOCAL  PROTECTED'),
                         (b'GLOBAL PROTECTED', b'GLOBAL DEFAULT'),
                         (b'4 first_equal', b'5 first_equal')):
            bad = raw.replace(old, new, 1)
            self.assertNotEqual(bad, raw)
            self.refuses(bad)
        for old, new in ((b'    27 FUNC', b'     4 FUNC'),
                         (b'    27 FUNC', b'   257 FUNC'),
                         (b'0000000000001000', b'0000000000000000'),
                         (b'0000000000001040', b'0000000000001010'),
                         (b'0000000000001040', b'fffffffffffffff0'),
                         (b'    27 FUNC', b'   -27 FUNC'),
                         (b'    27 FUNC', b'   027 FUNC')):
            bad = raw.replace(old, new)
            self.assertNotEqual(bad, raw)
            self.refuses(bad)

    def test_strip_preservation_is_full_definition_not_only_extent(self):
        before, after = fixture(), fixture(stripped=True)
        for old, new in ((b'0000000000001000', b'0000000000001001'),
                         (b'    27 FUNC', b'    28 FUNC'),
                         (b'4 first_equal', b'5 first_equal')):
            bad = after.replace(old, new)
            # These remain valid individually, so only the cross-file join refuses.
            geometry.definitions(bad, stripped=True)
            with self.assertRaises(AssertionError):
                geometry.preserved(before, bad)

    def test_framing_caps_and_unattributed_extra_text_are_refused(self):
        raw = fixture()
        for bad in (b'', raw[:-1], raw.replace(b'\n', b'\r\n'),
                    raw.replace(b'\n', b'\x0b', 1), b'\xff\n',
                    b'first_equal\n' + raw, raw + b'unattributed symbol\n',
                    b'X' * geometry.CAP + b'\n'):
            self.refuses(bad)
        for invalid in (0, 1, None, 'stripped'):
            self.refuses(raw, stripped=invalid)


if __name__ == '__main__':
    unittest.main()
