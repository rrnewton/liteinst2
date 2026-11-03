#!/usr/bin/env python3
"""Explicit metadata controls; no code decoding, subject execution or planning."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('stack_inventory_data', Path(__file__).with_name('direct_data.py'))
data = importlib.util.module_from_spec(spec)
spec.loader.exec_module(data)
ORIGINAL, LEDGER = 'a' * 64, 'b' * 64
ROWS = [[1, 4096, 2, 256, 4096, 8, 4096, 2, 'jump'],
        [2, 4098, 1, 258, 4096, 8, 4098, 6, 'push-r64'],
        [3, 4099, 1, 259, 4096, 8, 4098, 6, 'pop-r64']]
PREFIX = ('LI2DISASSEMBLY-INVENTORY\t1\nprofile\tjumps-gpr-stack64-v1\n'
          'selection_status\tclassified-unbound\noriginal_sha256\t' + ORIGINAL +
          '\nledger_sha256\t' + LEDGER + '\ncomplete_head_count\t4\n'
          'complete_site_count\t3\njump_count\t1\npush_r64_count\t1\n'
          'pop_r64_count\t1\nqualification_complete\tfalse\n')
HEADER = 'id\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\tclass\n'
FIXTURE = (PREFIX + HEADER + ''.join('\t'.join(map(str, row)) + '\n' for row in ROWS)).encode()


def parse(raw):
    return data.inventory(raw, ORIGINAL, LEDGER, selection_profile='jumps-gpr-stack64-v1')


class StackInventory(unittest.TestCase):
    def test_complete_union_and_legacy_identity_remain_separate(self):
        self.assertEqual(parse(FIXTURE), ROWS)
        legacy = ('LI2DISASSEMBLY-INVENTORY\t1\nprofile\telf-disassembly-null-jumps-shared-4096-v1\n'
                  'original_sha256\t' + ORIGINAL + '\nledger_sha256\t' + LEDGER +
                  '\ncomplete_jump_count\t1\nqualification_complete\tfalse\n' +
                  HEADER.removesuffix('\tclass\n') + '\n' +
                  '\t'.join(map(str, ROWS[0][:8])) + '\n').encode()
        self.assertEqual(data.inventory(legacy, ORIGINAL, LEDGER), [ROWS[0][:8]])
        with self.assertRaises((AssertionError, ValueError)):
            data.inventory(FIXTURE, ORIGINAL, LEDGER)
        with self.assertRaises((AssertionError, ValueError)):
            parse(legacy)

    def test_profile_population_and_geometry_mutations_refuse(self):
        for old, new in (
            (b'profile\tjumps-gpr-stack64-v1', b'profile\telf-disassembly-null-jumps-shared-4096-v1'),
            (b'original_sha256\t' + ORIGINAL.encode(), b'original_sha256\t' + LEDGER.encode()),
            (b'complete_site_count\t3', b'complete_site_count\t2'),
            (b'push_r64_count\t1', b'push_r64_count\t0'),
            (b'complete_head_count\t4', b'complete_head_count\t2'),
            (b'qualification_complete\tfalse', b'qualification_complete\ttrue'),
            (b'push-r64\n', b'push-memory\n'),
            (b'2\t4098\t1\t258', b'1\t4098\t1\t258'),
            (b'2\t4098\t1\t258', b'2\t4096\t1\t258'),
            (b'2\t4098\t1\t258', b'2\t4098\t1\t256'),
            (b'4098\t6\tpush-r64', b'4098\t7\tpush-r64'),
            (b'complete_site_count\t3\n', b'complete_site_count\t3\ncomplete_site_count\t3\n'),
        ):
            self.assertIn(old, FIXTURE)
            with self.subTest(mutation=new), self.assertRaises((AssertionError, ValueError)):
                parse(FIXTURE.replace(old, new))
        for raw in (FIXTURE[:-1], FIXTURE.rsplit(b'\n', 2)[0] + b'\n'):
            with self.assertRaises((AssertionError, ValueError)):
                parse(raw)

    def test_unbound_over_limit_population_is_retained_without_truncation(self):
        # Import inventory is evidence even when the later 4096-site bound
        # refuses. The parser must not discard or silently cap that denominator.
        count = 4097
        rows = [[i+1, 4096+i, 1, 256+i, 4096, count, 4096, count, 'push-r64'] for i in range(count)]
        prefix = PREFIX.replace('complete_head_count\t4', 'complete_head_count\t4097')
        prefix = prefix.replace('complete_site_count\t3', 'complete_site_count\t4097')
        prefix = prefix.replace('jump_count\t1', 'jump_count\t0').replace('pop_r64_count\t1', 'pop_r64_count\t0')
        prefix = prefix.replace('push_r64_count\t1', 'push_r64_count\t4097')
        raw = (prefix + HEADER + ''.join('\t'.join(map(str, row)) + '\n' for row in rows)).encode()
        self.assertEqual(parse(raw), rows)

    def test_complete_class_census_is_bound_to_every_row(self):
        fields = {'selection_profile': 'jumps-gpr-stack64-v1', 'complete_site_count': '3',
                  'jump_count': '1', 'push_r64_count': '1', 'pop_r64_count': '1'}
        data.stack_complete(fields, ROWS)
        for key in fields:
            changed = dict(fields)
            changed[key] = '0'
            with self.subTest(field=key), self.assertRaises(AssertionError):
                data.stack_complete(changed, ROWS)
        with self.assertRaises(AssertionError):
            data.stack_complete(fields, [ROWS[0], ROWS[1]])


if __name__ == '__main__':
    unittest.main()
