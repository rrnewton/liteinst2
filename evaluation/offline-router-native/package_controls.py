#!/usr/bin/env python3
"""Pure resolver controls and temporary-file custody controls; no ELF execution."""
import copy
import importlib.util
from pathlib import Path
import os
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('li2_native_package', Path(__file__).with_name('package.py'))
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)


def image(*, bss=False):
    raw = bytearray(0x4000)
    raw[:16] = b'\x7fELF\x02\x01\x01\0\0' + b'\0' * 7
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 3, 62, 1, 0, 64, 0x3000,
                     0, 64, 56, 1, 64, 4, 0)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 6, 0, 0, 0,
                     0x1000 if bss else 0x4000, 0x4000, 4096)
    # Symbol section, string table, object section. Their ranges are deliberately
    # independent: semantic mutants repair structural/table identities implicitly.
    struct.pack_into('<IIQQQQIIQQ', raw, 0x3000 + 64, 0, 2, 0, 0, 0x2000, 48, 2, 1, 8, 24)
    names = b'\0' + pkg.SYMBOL + b'\0'
    struct.pack_into('<IIQQQQIIQQ', raw, 0x3000 + 128, 0, 3, 0, 0, 0x2100, len(names), 0, 0, 1, 0)
    raw[0x2100:0x2100 + len(names)] = names
    struct.pack_into('<IIQQQQIIQQ', raw, 0x3000 + 192, 0, 8 if bss else 1, 3, 0x1000,
                     0x1000, 8, 0, 0, 8, 0)
    struct.pack_into('<IBBHQQ', raw, 0x2000 + 24, 1, 0x11, 2, 3, 0x1000, 8)
    return raw


class Completion(unittest.TestCase):
    def refused(self, raw, stage):
        with self.assertRaises(pkg.Refused) as got:
            pkg.Elf(bytes(raw)).completion()
        self.assertEqual(got.exception.stage, stage)

    def test_hidden_file_zero_object(self):
        found = pkg.Elf(bytes(image())).completion()
        self.assertEqual((found['address'], found['bytes'], found['file_offset'], found['visibility']),
                         (0x1000, 8, 0x1000, 2))

    def test_local_zero_object(self):
        raw = image(); raw[0x201c] = 1; raw[0x201d] = 0
        found = pkg.Elf(bytes(raw)).completion()
        self.assertEqual((found['binding'], found['visibility']), (0, 0))

    def test_bss_zero_object(self):
        self.assertIsNone(pkg.Elf(bytes(image(bss=True))).completion()['file_offset'])

    def test_default_preemptible_refuses(self):
        raw = image(); raw[0x201d] = 0
        self.refused(raw, 'completion-symbol')

    def test_protected_visibility_is_not_hidden(self):
        raw = image(); raw[0x201d] = 3
        self.refused(raw, 'completion-symbol')

    def test_tls_type_refuses(self):
        raw = image(); raw[0x201c] = 0x16
        self.refused(raw, 'completion-symbol')

    def test_function_type_refuses(self):
        raw = image(); raw[0x201c] = 0x12
        self.refused(raw, 'completion-symbol')

    def test_seven_byte_extent_refuses(self):
        raw = image(); struct.pack_into('<Q', raw, 0x2028, 7)
        self.refused(raw, 'completion-symbol')

    def test_unaligned_object_refuses(self):
        raw = image(); struct.pack_into('<Q', raw, 0x2020, 0x1001)
        self.refused(raw, 'completion-symbol')

    def test_nonzero_initial_value_refuses(self):
        raw = image(); raw[0x1000] = 1
        self.refused(raw, 'completion-symbol')

    def test_wrong_section_extent_refuses(self):
        raw = image(); struct.pack_into('<Q', raw, 0x30e0, 7)
        self.refused(raw, 'completion-symbol')

    def test_undefined_symbol_refuses(self):
        raw = image(); struct.pack_into('<H', raw, 0x201e, 0)
        self.refused(raw, 'completion-symbol')

    def test_missing_symbol_refuses(self):
        raw = image(); raw[0x2101] = ord('X')
        self.refused(raw, 'completion-symbol')

    def test_conflicting_second_definition_refuses(self):
        raw = image()
        struct.pack_into('<Q', raw, 0x3060, 72)
        struct.pack_into('<IBBHQQ', raw, 0x2030, 1, 0x11, 2, 3, 0x1008, 8)
        self.refused(raw, 'completion-symbol')

    def test_readonly_owner_refuses(self):
        raw = image(); struct.pack_into('<I', raw, 68, 4)
        self.refused(raw, 'completion-symbol')

    def test_relocation_target_overlaps_object(self):
        raw = image()
        struct.pack_into('<H', raw, 60, 5)
        struct.pack_into('<IIQQQQIIQQ', raw, 0x3100, 0, 4, 2, 0x2200,
                         0x2200, 24, 1, 0, 8, 24)
        struct.pack_into('<QQq', raw, 0x2200, 0x1000, 8, 0)
        self.refused(raw, 'completion-relocation')

    def test_relocation_references_object_at_other_address(self):
        raw = image()
        struct.pack_into('<H', raw, 60, 5)
        struct.pack_into('<IIQQQQIIQQ', raw, 0x3100, 0, 4, 2, 0x2200,
                         0x2200, 24, 1, 0, 8, 24)
        struct.pack_into('<QQq', raw, 0x2200, 0x1800, (1 << 32) | 1, 0)
        self.refused(raw, 'completion-relocation')

    def test_dynamic_relocation_table_cannot_hide_from_sections(self):
        raw = image()
        struct.pack_into('<H', raw, 56, 2)
        struct.pack_into('<IIQQQQQQ', raw, 120, 2, 6, 0x2300, 0x2300, 0x2300, 64, 64, 8)
        for offset, row in enumerate(((7, 0x2400), (8, 24), (9, 24), (0, 0))):
            struct.pack_into('<qQ', raw, 0x2300 + offset*16, *row)
        self.refused(raw, 'completion-relocation')


def dynamic_image(*, kind=4, plt=False):
    """A real mapped dynamic table, separate static/dynamic symbols and strings."""
    raw = image()
    struct.pack_into('<H', raw, 56, 2)
    struct.pack_into('<H', raw, 60, 7)
    names = b'\0' + pkg.SYMBOL + b'\0'
    width = 24 if kind == 4 else 16
    # Section indices 4=dynsym, 5=dynstr, 6=dynamic relocation table.
    struct.pack_into('<IIQQQQIIQQ', raw, 0x3100, 0, 11, 2, 0x2500, 0x2500, 48, 5, 1, 8, 24)
    raw[0x2500:0x2530] = raw[0x2000:0x2030]
    struct.pack_into('<IIQQQQIIQQ', raw, 0x3140, 0, 3, 2, 0x2600, 0x2600, len(names), 0, 0, 1, 0)
    raw[0x2600:0x2600 + len(names)] = names
    struct.pack_into('<IIQQQQIIQQ', raw, 0x3180, 0, kind, 2, 0x2400, 0x2400, width, 4, 0, 8, width)
    struct.pack_into('<QQ', raw, 0x2400, 0x1800, 8)
    tags = [(5, 0x2600), (6, 0x2500), (10, len(names)), (11, 24)]
    if plt:
        tags += [(23, 0x2400), (2, width), (20, 7 if kind == 4 else 17)]
    else:
        tags += [(7, 0x2400), (8, width), (9, width)] if kind == 4 else [(17, 0x2400), (18, width), (19, width)]
    tags.append((0, 0))
    struct.pack_into('<IIQQQQQQ', raw, 120, 2, 6, 0x2300, 0x2300, 0x2300, len(tags)*16, len(tags)*16, 8)
    for index, row in enumerate(tags):
        struct.pack_into('<qQ', raw, 0x2300 + index*16, *row)
    return raw


class DynamicOwnership(unittest.TestCase):
    def resolve_rebound(self, raw):
        # Each semantic mutation has valid fresh outer bytes/hash/stat custody.
        # Refusal must come from the ELF join, never an unrepaired outer pin.
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'bootstrap.so'
            path.write_bytes(raw)
            pin = dict(path=str(path), bytes=len(raw), sha256=pkg.digest(raw), stat=pkg.stamp(path.stat()))
            held = pkg.Custody()
            try:
                observed = held.retain(pin, 16*pkg.MIB)
                self.assertEqual(observed, bytes(raw))
                self.assertEqual(pkg.digest(observed), pin['sha256'])
                held.verify()
                return pkg.Elf(observed).completion()
            finally:
                held.close()

    def refused(self, raw):
        with self.assertRaises(pkg.Refused) as got:
            self.resolve_rebound(raw)
        self.assertEqual(got.exception.stage, 'completion-relocation')

    def test_actual_rela_table_and_dynamic_symbols_accept(self):
        self.assertEqual(self.resolve_rebound(dynamic_image())['address'], 0x1000)

    def test_actual_rel_table_and_dynamic_symbols_accept(self):
        self.assertEqual(self.resolve_rebound(dynamic_image(kind=9))['address'], 0x1000)

    def test_actual_jmprel_tables_accept_both_entry_kinds(self):
        for kind in (4, 9):
            with self.subTest(kind=kind):
                self.assertEqual(self.resolve_rebound(dynamic_image(kind=kind, plt=True))['address'], 0x1000)

    def test_same_tuple_rebound_section_offset_cannot_hide_completion_write(self):
        for kind, plt in ((4, False), (9, False), (4, True), (9, True)):
            with self.subTest(kind=kind, plt=plt):
                raw = dynamic_image(kind=kind, plt=plt)
                original_tuple = struct.unpack_from('<IIQQQQIIQQ', raw, 0x3180)
                raw[0x2700:0x2718] = raw[0x2400:0x2418]
                struct.pack_into('<Q', raw, 0x2400, 0x1000)  # Actual loader write.
                struct.pack_into('<Q', raw, 0x3180+24, 0x2700)  # Harmless section bytes.
                rebound = struct.unpack_from('<IIQQQQIIQQ', raw, 0x3180)
                self.assertEqual(tuple(original_tuple[i] for i in (3,5,1)),
                                 tuple(rebound[i] for i in (3,5,1)))
                self.assertNotEqual(rebound[4], rebound[3])
                self.refused(raw)

    def test_identical_table_copy_is_not_the_mapped_owner(self):
        raw = dynamic_image()
        raw[0x2700:0x2718] = raw[0x2400:0x2418]
        struct.pack_into('<Q', raw, 0x3180+24, 0x2700)
        self.assertEqual(raw[0x2400:0x2418], raw[0x2700:0x2718])
        self.refused(raw)

    def test_section_offset_in_another_load_cannot_cover_actual_table(self):
        raw = dynamic_image()
        struct.pack_into('<H', raw, 56, 3)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 6, 0, 0, 0, 0x3000, 0x3000, 4096)
        struct.pack_into('<IIQQQQQQ', raw, 176, 1, 4, 0x3000, 0x8000, 0x8000, 0x1000, 0x1000, 4096)
        raw[0x3400:0x3418] = raw[0x2400:0x2418]
        struct.pack_into('<Q', raw, 0x2400, 0x1000)
        struct.pack_into('<Q', raw, 0x3180+24, 0x3400)
        self.refused(raw)

    def test_pt_dynamic_file_offset_cannot_select_a_harmless_copy(self):
        raw = dynamic_image()
        raw[0x2900:0x2980] = raw[0x2300:0x2380]
        struct.pack_into('<Q', raw, 0x2300+4*16+8, 0x2800)
        struct.pack_into('<QQq', raw, 0x2800, 0x1000, 8, 0)
        struct.pack_into('<Q', raw, 120+8, 0x2900)
        self.refused(raw)

    def test_dynsym_file_offset_cannot_hide_a_completion_reference(self):
        raw = dynamic_image()
        raw[0x2700:0x2730] = raw[0x2500:0x2530]
        struct.pack_into('<I', raw, 0x2718, 0)  # Fake symbol has an empty name.
        struct.pack_into('<Q', raw, 0x2408, (1 << 32) | 1)
        struct.pack_into('<Q', raw, 0x3100+24, 0x2700)
        self.refused(raw)

    def test_dynstr_file_offset_cannot_rename_actual_completion_symbol(self):
        raw = dynamic_image()
        names = b'\0' + pkg.SYMBOL + b'\0'
        raw[0x2800:0x2800+len(names)] = names
        raw[0x2801] = ord('X')
        struct.pack_into('<Q', raw, 0x2408, (1 << 32) | 1)
        struct.pack_into('<Q', raw, 0x3140+24, 0x2800)
        self.refused(raw)

    def test_relocation_link_must_own_actual_dt_symtab(self):
        raw = dynamic_image()
        struct.pack_into('<I', raw, 0x3180+40, 1)  # Identical static symbols.
        self.assertEqual(raw[0x2000:0x2030], raw[0x2500:0x2530])
        self.refused(raw)

    def test_incomplete_dynamic_symbol_tags_refuse(self):
        raw = dynamic_image()
        struct.pack_into('<q', raw, 0x2300+3*16, 0x60000000)
        self.refused(raw)

    def test_duplicate_plt_size_tag_refuses(self):
        raw = dynamic_image(plt=True)
        # Keep the original terminator after a second well-formed PLTRELSZ.
        struct.pack_into('<qQ', raw, 0x2300+7*16, 2, 24)
        struct.pack_into('<qQ', raw, 0x2300+8*16, 0, 0)
        struct.pack_into('<QQ', raw, 120+32, 9*16, 9*16)
        self.refused(raw)

    def test_actual_table_completion_targets_remain_refused(self):
        for kind, plt in ((4, False), (9, False), (4, True), (9, True)):
            with self.subTest(kind=kind, plt=plt):
                raw = dynamic_image(kind=kind, plt=plt)
                struct.pack_into('<Q', raw, 0x2400, 0x1000)
                self.refused(raw)

    def test_dynamic_strsz_must_equal_owned_string_table(self):
        raw = dynamic_image()
        struct.pack_into('<Q', raw, 0x2300+2*16+8, len(pkg.SYMBOL)+1)
        self.refused(raw)


class Custody(unittest.TestCase):
    def test_owned_bytes_then_replaced_path_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'original'; p.write_bytes(b'abc')
            record = dict(path=str(p), bytes=3, sha256=pkg.digest(b'abc'), stat=pkg.stamp(p.stat()))
            custody = pkg.Custody()
            try:
                self.assertEqual(custody.retain(record, 3), b'abc')
                custody.verify()
                q = Path(root) / 'other'; q.write_bytes(b'abc'); q.replace(p)
                with self.assertRaises(pkg.Refused) as got: custody.verify()
                self.assertEqual(got.exception.stage, 'custody')
            finally:
                custody.close()

    def test_symlink_parent_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            real = Path(root) / 'real'; real.mkdir(); (real / 'x').write_bytes(b'x')
            alias = Path(root) / 'alias'; alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError): pkg.open_regular(str(alias / 'x'))

    def test_duplicate_json_and_unknown_keys_refuse(self):
        with self.assertRaises(pkg.Refused): pkg.decode(b'{"a":1,"a":2}')
        with self.assertRaises(pkg.Refused): pkg.keys({'known': 1, 'unknown': 2}, ('known',), 'test')

    def test_completion_and_claimed_receipt_never_grant_admission(self):
        for claimed in ({}, {'accepted': True}, {'completion': 1}, {'authority': 'fake'}):
            with self.assertRaises(pkg.Refused) as got:
                pkg.require_final_admission(claimed, [{'completion': 1}], None)
            self.assertEqual((got.exception.stage, got.exception.detail),
                             ('final-package-admission', 'NO_SUPPORTED_AUTHORITY'))


if __name__ == '__main__':
    unittest.main()
