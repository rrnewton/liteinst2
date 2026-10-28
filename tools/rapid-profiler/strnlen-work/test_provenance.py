"""Actual shared/profile validators on synthetic files; no build/native credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
check = load('strnlen_provenance', HERE / 'provenance.py')
shared = check._shared
legacy = load('strnlen_legacy_fixture', HERE.parent / 'selected-work' / 'test_provenance.py')
CHECKSUM = 'ordinary_checksum_nonempty'


def fixture(stripped, selected, null_only):
    # Adapt the independent existing metadata-only fixture, never an executable.
    # Field coordinates are ELF layout facts of that fixture, not compiler output.
    raw, symbols = legacy.fixture(stripped)
    data = bytearray(raw)
    if not stripped:
        string = b'\0' + selected.encode('ascii') + b'\0'
        assert len(string) <= 0x30
        data[0x2600:0x2630] = bytes(0x30)
        data[0x2600:0x2600 + len(string)] = string
        struct.pack_into('<Q', data, 0x2800 + 6 * 64 + 32, len(string))
        symbols = symbols.replace(b' ordinary_checksum_nonempty\n',
                                  b' ' + selected.encode('ascii') + b'\n')
    if null_only:
        data[0x300:0x340] = bytes(0x40)
        data[0x340:0x370] = bytes(0x30)
        struct.pack_into('<Q', data, 0x2000 + 3 * 16 + 8, 1)  # DT_STRSZ
        struct.pack_into('<Q', data, 0x2800 + 64 + 32, 24)  # dynsym size
        struct.pack_into('<Q', data, 0x2800 + 2 * 64 + 32, 1)  # dynstr size
        symbols = symbols.replace(b"Symbol table '.dynsym' contains 2 entries:",
                                  b"Symbol table '.dynsym' contains 1 entry:")
        symbols = symbols.replace(
            b'     1: 0000000000001000     8 FUNC    GLOBAL DEFAULT    3 ordinary_checksum\n', b'')
    return bytes(data), symbols


def inputs(selected, null_only=True):
    pre, pretext = fixture(False, selected, null_only)
    post, posttext = fixture(True, selected, null_only)
    return [pre, post, pretext, posttext]


def profiles():
    return ((CHECKSUM, shared.validate), ('strnlen', check.validate))


class StrnlenProvenance(unittest.TestCase):
    def test_both_profiles_preserve_complete_manifest_and_default_checksum(self):
        old = shared.validate(*legacy.inputs())
        self.assertEqual((old['name'], old['label']), (CHECKSUM, 'selected-checksum-v1'))
        self.assertEqual(old, shared._validate(*legacy.inputs(), shared.LABEL))
        for name, validate in profiles():
            a = inputs(name)
            result = validate(*a)
            with self.subTest(name=name):
                self.assertEqual(result['name'], name)
                self.assertEqual(result['label'], shared.LABEL if name == CHECKSUM else check.LABEL)
                self.assertEqual((result['elf_va'], result['length'], result['file_offset']),
                                 (0x1020, 8, 0x1020))
                self.assertEqual(result['selected_code'], shared.digest(bytes(range(32, 40))))
                self.assertEqual(result['prestrip'], shared.digest(a[0]))
                self.assertEqual(result['final'], shared.digest(a[1]))
                self.assertEqual(len(result['geometry']), 6)
                self.assertEqual(result['executable_loads'][0]['sha256'],
                                 hashlib.sha256(bytes(range(64))).hexdigest())
                self.assertFalse(result['selected_dynamic_definition'])
                self.assertFalse(result['final_static_symbols'])
                self.assertFalse(result['final_debug_sections'])

    def test_cross_profile_unknown_profile_and_swapped_metadata_refuse(self):
        with self.assertRaises(AssertionError): shared.validate(*inputs('strnlen'))
        with self.assertRaises(AssertionError): check.validate(*inputs(CHECKSUM))
        for profile in ('strnlen', 'arbitrary', '', None):
            with self.subTest(profile=profile), self.assertRaises(AssertionError):
                shared._validate(*inputs('strnlen'), profile)
        for name, validate in profiles():
            other = CHECKSUM if name == 'strnlen' else 'strnlen'
            a = inputs(name); a[2] = inputs(other)[2]
            with self.subTest(name=name), self.assertRaises(AssertionError): validate(*a)

    def test_null_only_tables_and_count_grammar_are_exact(self):
        for name, validate in profiles():
            a = inputs(name)
            self.assertEqual(shared.elf(a[0])['tables']['.dynsym'], [('', 0, 0, 0, 0, 0)])
            self.assertEqual(shared.elf(a[1])['tables']['.dynsym'], [('', 0, 0, 0, 0, 0)])
            validate(*a)
            for index, old, new in (
                    (2, b'contains 1 entry:', b'contains 1 entries:'),
                    (3, b'contains 1 entry:', b'contains 1 entries:'),
                    (2, b'contains 2 entries:', b'contains 2 entry:'),
                    (2, b'contains 1 entry:', b'contains 0 entry:'),
                    (2, b'contains 1 entry:', b'contains 0 entries:'),
                    (3, b'contains 1 entry:', b'contains 2 entries:'),
                    (2, b'contains 2 entries:', b'contains 3 entries:'),
                    (3, b'contains 1 entry:', b'contains 1 entrys:')):
                b = list(a); self.assertIn(old, b[index]); b[index] = b[index].replace(old, new)
                with self.subTest(name=name, index=index, new=new), self.assertRaises(AssertionError):
                    validate(*b)
        # The legacy plural non-null dynamic table remains valid.
        shared.validate(*legacy.inputs())
        a = legacy.inputs(); a[3] = a[3].replace(b'contains 2 entries:', b'contains 2 entry:')
        with self.assertRaises(AssertionError): shared.validate(*a)

    def test_selected_metadata_mutations_refuse_in_both_profiles(self):
        mutations = ((0x271c, '<B', 0x12), (0x271c, '<B', 1),
            (0x271d, '<B', 2), (0x271e, '<H', 0), (0x2720, '<Q', 0x103f),
            (0x2728, '<Q', 0), (0x2728, '<Q', 257), (0x2800 + 3 * 64 + 8, '<Q', 7))
        for name, validate in profiles():
            for offset, fmt, value in mutations:
                a = inputs(name); a[0] = legacy.mutate(a[0], offset, fmt, value)
                with self.subTest(name=name, offset=offset, value=value), self.assertRaises(AssertionError):
                    validate(*a)
            for old, new in ((b'0000000000001020', b'0000000000001021'),
                    (b'8 FUNC    LOCAL', b'9 FUNC    LOCAL'),
                    (b'8 FUNC    LOCAL', b'8 OBJECT  LOCAL'),
                    (b'8 FUNC    LOCAL', b'8 FUNC    GLOBAL')):
                a = inputs(name); self.assertIn(old, a[2]); a[2] = a[2].replace(old, new)
                with self.subTest(name=name, new=new), self.assertRaises(AssertionError): validate(*a)

    def test_selected_full_rx_and_load_geometry_mutations_refuse_in_both_profiles(self):
        for name, validate in profiles():
            for offset, fmt, value in ((0x1020, '<B', 99), (0x103f, '<B', 99),
                    (64 + 56 + 32, '<Q', 63), (64 + 5 * 56 + 48, '<Q', 16),
                    (64 + 4 * 56 + 4, '<I', 7), (0x2000, '<Q', 12)):
                a = inputs(name); a[1] = legacy.mutate(a[1], offset, fmt, value)
                with self.subTest(name=name, offset=offset), self.assertRaises(AssertionError): validate(*a)
            a = inputs(name); a[1], a[3] = a[0], a[2]
            with self.assertRaises(AssertionError): validate(*a)
            a = inputs(name); a[1] = a[1].replace(b'.shstrtab', b'.debugxyz')
            with self.assertRaises(AssertionError): validate(*a)

    def test_strnlen_all_local_profile_rejects_extra_dynamic_entries(self):
        # Even an unselected export violates the fixed strnlen all-local profile.
        with self.assertRaises(AssertionError): check.validate(*inputs('strnlen', False))
        # The old profile retains its old allowance for the other checksum export.
        shared.validate(*inputs(CHECKSUM, False))
        for name, validate in profiles():
            a = inputs(name, False)
            for index in (0, 1):
                data = bytearray(a[index]); value = b'\0' + name.encode('ascii') + b'\0'
                data[0x300:0x340] = bytes(0x40)
                data[0x300:0x300 + len(value)] = value
                struct.pack_into('<Q', data, 0x2000 + 3 * 16 + 8, len(value))
                struct.pack_into('<Q', data, 0x2800 + 2 * 64 + 32, len(value))
                a[index] = bytes(data)
                a[index + 2] = a[index + 2].replace(b' ordinary_checksum\n',
                                                   b' ' + name.encode('ascii') + b'\n')
            with self.subTest(name=name), self.assertRaises(AssertionError): validate(*a)
        a = inputs('strnlen'); a[1] = legacy.mutate(a[1], 0x2800 + 64 + 32, '<Q', 48)
        with self.assertRaises(AssertionError): check.validate(*a)

    def test_symbol_transcript_structure_stays_strict(self):
        for name, validate in profiles():
            for index in (2, 3):
                for transform in (lambda s: s[:-1], lambda s: s + b'extra\n',
                        lambda s: s.replace(b'\n', b'\r\n'),
                        lambda s: s.replace(b'   Num:', b'\tNum:'),
                        lambda s: s + b"Symbol table '.dynsym' contains 1 entry:\n"):
                    a = inputs(name); a[index] = transform(a[index])
                    with self.subTest(name=name, index=index), self.assertRaises(AssertionError): validate(*a)

    def test_vendored_source_metadata_and_localize_script_are_exact(self):
        source = (HERE / 'strnlen.c').read_bytes()
        upstream = json.loads((HERE / 'UPSTREAM.json').read_text())
        digest = '969eb826cd618ff799cdc4fcc9d61edd044a314bd39208479787eda622c4f336'
        self.assertEqual(hashlib.sha256(source).hexdigest(), digest)
        self.assertEqual(len(source), 1584)
        self.assertEqual(upstream['source_sha256'], digest)
        self.assertEqual(upstream['commit'], '10e31f0946d820d53adc58b7d013b969e4a9a8ed')
        self.assertEqual(upstream['blob'], 'b44f8ab2194710a91dfde4be07384f1fbdeec79a')
        self.assertEqual(upstream['path'], 'lib/libc/string/strnlen.c')
        self.assertIn(b'SPDX-License-Identifier: BSD-2-Clause', source)
        self.assertEqual((check.NAME, check.LABEL), ('strnlen', 'freebsd-strnlen-14.1-v1'))
        self.assertEqual((HERE / 'localize.map').read_bytes(), b'{ local: *; };\n')
        self.assertEqual(check.VERSION_SCRIPT, (HERE / 'localize.map').read_bytes())


if __name__ == '__main__':
    unittest.main()
