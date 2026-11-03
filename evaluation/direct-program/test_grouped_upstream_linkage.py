#!/usr/bin/env python3
"""Additive upstream transcript controls; no decoder, placement or native run."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('exact_group_fixture', Path(__file__).with_name('test_grouped_linkage.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
data = base.data
PROFILE = 'jumps-gpr-stack64-block-upstream-v1'
SITES = [[1, 4096, 1, 256, 4091, 11, 4091, 11, 'push-r64'],
         [2, 4100, 1, 260, 4091, 11, 4091, 11, 'pop-r64'], base.SITES[2]]
SOURCE = base.SOURCE.replace(b'region 4096 256 6\n', b'region 4091 251 11\nhead 4091 0f1f440000\n')
PHYSICAL_POLICY = (
    'physical_schedule\tsame-site-then-single-cache-line-then-nearest-upstream-v1\n'
    'max_physical_sites\t64\nmax_upstream_bytes\t64\nmax_displaced_bytes\t256\n'
    'image_candidates_per_physical\t1\nimage_mappings_per_physical\t1\nimage_bytes_per_physical\t4096\n'
    'physical_domain\tsame-block-heads-through-first-member\n'
    'membership\tfull-manifest-maximum-prefix-and-actual-window\n').encode()


def fixture(mode='complete'):
    # Keep the exact profile's declared population, outcomes and units. Only the
    # new policy and one group's actual displaced prefix differ in this fixture.
    record = base.fixture(mode)
    info, members, _ = record
    base.replace(record, 'grouping-policy.tsv', base.PROFILE.encode(), PROFILE.encode())
    base.replace(record, 'grouping-policy.tsv', b'group_attempts\t1\n', PHYSICAL_POLICY)
    members['binding-policy.tsv'] = data.grouped_binding_bytes(base.sha(base.SELECTION), base.ORIGINAL, 7,
                                                               base.sha(members['grouping-policy.tsv']), profile=PROFILE)
    base.replace(record, 'disassembly.txt', base.SOURCE, SOURCE)
    if mode in ('complete', 'group-only', 'carrier'):
        base.replace(record, 'plan-ledger.tsv', b'step\t1\t0\trelocation\t4096\t4096\t4096\t4101\n',
                     b'step\t1\t0\trelocation\t4096\t4091\t4091\t4101\n')
        base.replace(record, 'plan-ledger.tsv', b'route\t0\t4096\t65536\n',
                     b'route\t0\t4091\t65537\nroute\t0\t4096\t65536\n')
        base.replace(record, 'plan-ledger.tsv', b'restored-boundary\t0\t4096\t65560\n',
                     b'restored-boundary\t0\t4091\t65538\nrestored-boundary\t0\t4096\t65560\n')
    for key in ('profile', 'planner_profile', 'grouped_profile'):
        info['fields'][key] = PROFILE
    info['files'].update({name: base.pin(raw) for name, raw in members.items()})
    return record


def parse(record, sites=SITES, *, source_ledger=None, profile=PROFILE):
    info, members, complete = record
    report = data.li2_report(members['report.tsv'], sites, base.ORIGINAL, complete)
    return data.grouped_linkage(info, members, sites, base.ORIGINAL, 7, report,
                               source_ledger=base.pin(SOURCE) if source_ledger is None else source_ledger,
                               profile=profile)


class GroupedUpstreamLinkage(unittest.TestCase):
    def test_upstream_full_partition_preserves_all_local_and_final_outcomes(self):
        for mode, expected in [('complete', (2,3,2,3,'PASS')), ('group-only', (1,2,1,0,'FAILED')),
                               ('single-only', (1,1,1,0,'FAILED')), ('neither', (0,0,0,0,'FAILED')),
                               ('carrier', (2,3,2,0,'FAILED'))]:
            with self.subTest(mode=mode):
                record = fixture(mode); result = parse(record)
                self.assertEqual((result['policy_units'],result['requested']), (2,3))
                self.assertEqual(tuple(result[k] for k in ('accepted_units','accepted_members','unique_images','emitted','status')), expected)
                self.assertIn(base.PARTITION.encode(),record[1]['grouping-policy.tsv'])
                with self.assertRaises(AssertionError): parse(record,profile=base.PROFILE)
        self.assertEqual(base.parse(base.fixture())['status'],'PASS')

    def test_upstream_physical_head_window_schedule_and_limits_are_exact(self):
        for old, new in [
            (b'4096\t4091\t4091\t4101',b'4096\t4092\t4092\t4101'),
            (b'4096\t4091\t4091\t4101',b'4096\t4090\t4090\t4101'),
            (b'4096\t4091\t4091\t4101',b'4096\t4091\t4091\t4102'),
            (b'4096\t4091\t4091\t4101',b'4091\t4091\t4091\t4101'),
            (b'route\t0\t4091\t65537\n',b''),
            (b'restored-boundary\t0\t4091\t65538\n',b''),
        ]:
            record = fixture(); base.replace(record,'plan-ledger.tsv',old,new)
            with self.subTest(old=old,new=new), self.assertRaises(AssertionError): parse(record)
        for key, value in [('max_physical_sites','65'),('max_upstream_bytes','65'),
                           ('max_displaced_bytes','257'),('image_candidates_per_physical','2'),
                           ('image_mappings_per_physical','2'),('image_bytes_per_physical','4097')]:
            record = fixture()
            old = next(row for row in record[1]['grouping-policy.tsv'].splitlines(keepends=True) if row.startswith(key.encode()+b'\t'))
            base.replace(record,'grouping-policy.tsv',old,(key+'\t'+value+'\n').encode())
            with self.subTest(key=key), self.assertRaises(AssertionError): parse(record)

    def test_upstream_source_ledger_pin_prevents_coordinated_prefix_omission(self):
        record = fixture()
        base.replace(record,'disassembly.txt',b'head 4091 0f1f440000\n',b'')
        base.replace(record,'plan-ledger.tsv',b'route\t0\t4091\t65537\n',b'')
        base.replace(record,'plan-ledger.tsv',b'restored-boundary\t0\t4091\t65538\n',b'')
        self.assertNotEqual(record[0]['files']['disassembly.txt'],base.pin(SOURCE))
        with self.assertRaises(AssertionError): parse(record)
        # Even a newly supplied contradictory source pin cannot establish an
        # actual physical head after that head was deleted from its transcript.
        with self.assertRaises(AssertionError): parse(record,source_ledger=record[0]['files']['disassembly.txt'])

    def test_upstream_full_manifest_includes_already_accepted_prefix_singleton(self):
        record = fixture(); info,members,_ = record
        # Hostile but complete text roster: an independently accepted singleton
        # occupies the prefix. It is outside the selected-span group yet cannot
        # disappear merely because its own accepted-unit has already consumed it.
        foreign = [3,4091,5,251,4091,11,4091,5,'jump']
        sites = [foreign,*SITES[:2]]
        base.replace(record,'grouping-policy.tsv',b'unit\t1\tsingleton\t8192\t8197\t1\nmember\t1\t3\t8192\t5\tjump\n',
                     b'unit\t1\tsingleton\t4091\t4096\t1\nmember\t1\t3\t4091\t5\tjump\n')
        base.replace(record,'plan-ledger.tsv',b'step\t3\t0\trelocation\t8192\t8192\t8192\t8197\n',
                     b'step\t3\t0\trelocation\t4091\t4091\t4091\t4096\n')
        base.replace(record,'plan-ledger.tsv',b'member\t1\t3\t8192\t5\tjump\n',b'member\t1\t3\t4091\t5\tjump\n')
        rows = members['report.tsv'].splitlines(keepends=True)
        header = rows.index(base.HEADER.encode())
        row3 = rows[-1].replace(b'3\t8192\t512\t5\t',b'3\t4091\t251\t5\t')
        self.assertNotEqual(row3,rows[-1])
        members['report.tsv'] = b''.join(rows[:header+1]+[row3]+rows[header+1:-1])
        info['files']['report.tsv'] = base.pin(members['report.tsv'])
        # Full outcome geometry is valid before the independent membership check.
        self.assertEqual(data.li2_report(members['report.tsv'],sites,base.ORIGINAL,True)['requested'],3)
        with self.assertRaises(AssertionError): parse(record,sites)


if __name__ == '__main__':
    unittest.main(verbosity=2)
