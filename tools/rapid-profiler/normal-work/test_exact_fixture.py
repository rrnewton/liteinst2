#!/usr/bin/env python3
"""Synthetic ELF/manifest authority controls; no compiler or native credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import exact_fixture as check

spec = importlib.util.spec_from_file_location('exact_fixture_envelope',
    Path(__file__).resolve().parents[1]/'selected-work/test_provenance.py')
envelope = importlib.util.module_from_spec(spec); spec.loader.exec_module(envelope)


def fixture(address=0x1000):
    data = bytearray(envelope.fixture(False)[0])
    name = b'\0exact_work_nonempty\0'
    for offset in (0x300, 0x2600): data[offset:offset+len(name)] = name
    for section in (2, 6): struct.pack_into('<Q', data, 0x2800+64*section+32, len(name))
    struct.pack_into('<Q', data, 0x2000+3*16+8, len(name))
    for offset in (0x358, 0x2718): struct.pack_into('<IBBHQQ', data, offset, 1, 0x12, 0, 3, address, 37)
    struct.pack_into('<Q', data, 64+56+16, address)
    struct.pack_into('<Q', data, 64+56+24, address)
    struct.pack_into('<Q', data, 0x2800+3*64+16, address)
    data[0x1000:0x1000+37] = check.CODE
    return bytes(data)


class Controls(unittest.TestCase):
    def test_complete_bytes_symbol_and_distinct_va_file_offset(self):
        result = check.describe(fixture(0x5000))
        self.assertEqual((result['elf_va'], result['file_offset'], result['length']), (0x5000, 0x1000, 37))
        self.assertEqual(result['head_offsets'], [0, 2, 6, 9, 12, 15, 18, 21, 23, 33, 36])
        self.assertEqual(result['return_offsets'], [36])
        self.assertEqual(result['final'], check.elf.digest(fixture(0x5000)))

    def test_every_subject_byte_and_extent_is_required(self):
        for index in range(37):
            data = bytearray(fixture()); data[0x1000+index] ^= 1
            with self.subTest(index=index), self.assertRaises(AssertionError): check.describe(bytes(data))
        for offset, fmt, value in ((0x35c, '<B', 2), (0x35d, '<B', 2), (0x35e, '<H', 0),
                (0x368, '<Q', 36), (0x2728, '<Q', 38), (0x2800+3*64+8, '<Q', 7)):
            data = bytearray(fixture()); struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(AssertionError): check.describe(bytes(data))
        with self.assertRaises(AssertionError): check.describe(fixture().replace(b'exact_work_nonempty', b'exact_work_nonemptx'))

    def test_manifest_hash_full_elf_and_distinct_candidate_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory); trusted, candidate, manifest = (d/n for n in ('trusted', 'candidate', 'selection'))
            data = fixture(); trusted.write_bytes(data); candidate.write_bytes(data)
            record = dict(check.describe(data), revision='1'*40)
            def publish(value):
                manifest.write_text(json.dumps(value, sort_keys=True)+'\n')
                return hashlib.sha256(manifest.read_bytes()).hexdigest()
            sha = publish(record)
            self.assertEqual(check.authenticate(candidate, trusted, 4096, 37, manifest, sha), check.describe(data))
            with self.assertRaises(AssertionError): check.authenticate(trusted, trusted, 4096, 37, manifest, sha)
            with self.assertRaises(AssertionError): check.authenticate(candidate, trusted, 4096, 37, manifest, '0'*64)
            candidate.write_bytes(data[:-1]+b'X')
            with self.assertRaises(AssertionError): check.authenticate(candidate, trusted, 4096, 37, manifest, sha)
            trusted.write_bytes(data[:-1]); candidate.write_bytes(data[:-1])
            with self.assertRaises(AssertionError): check.authenticate(candidate, trusted, 4096, 37, manifest, sha)
            trusted.write_bytes(data)
            candidate.write_bytes(data)
            for key, value in (('label', 'freebsd-strnlen-14.1-v1'), ('elf_va', 4097),
                    ('length', 41), ('return_offsets', [34, 40]), ('head_offsets', [0, 36]), ('schema', True)):
                bad = dict(record); bad[key] = value; sha = publish(bad)
                with self.subTest(key=key), self.assertRaises(AssertionError): check.authenticate(candidate, trusted, 4096, 37, manifest, sha)

    def test_duplicate_manifest_keys_and_malformed_elf_refuse(self):
        with self.assertRaises(AssertionError): json.loads('{"schema":1,"schema":1}', object_pairs_hook=check.unique)
        # Truncate a required section header, not unrelated trailing padding.
        for data in (b'', fixture()[:63], fixture()[:0x29ff], b'x'*(check.elf.MIB+1)):
            with self.assertRaises(AssertionError): check.describe(data)


if __name__ == '__main__':
    unittest.main()
