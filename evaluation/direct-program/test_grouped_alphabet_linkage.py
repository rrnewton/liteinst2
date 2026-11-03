#!/usr/bin/env python3
"""Additive placement-policy joins; no decoder, placement or subject execution."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('min5_fixture', Path(__file__).with_name('test_grouped_min5_linkage.py'))
min5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(min5)
base, storage, data = min5.base, min5.storage, min5.data
PROFILE = 'jumps-gpr-stack64-block-min5-alphabet-upstream-v1'
PLACEMENT = b'group_relocation_placement\tentry-alphabet-v1\n'


def fixture(mode='complete', *, refused=None, compact=False):
    record = min5.fixture(mode, refused=refused)
    info, members, _ = record
    base.replace(record, 'grouping-policy.tsv', min5.PROFILE.encode(), PROFILE.encode())
    base.replace(record, 'grouping-policy.tsv', b'LI2GROUPING-POLICY\t2\n', b'LI2GROUPING-POLICY\t3\n')
    base.replace(record, 'grouping-policy.tsv', min5.WINDOW, min5.WINDOW+PLACEMENT)
    members['binding-policy.tsv'] = data.grouped_binding_bytes(base.sha(base.SELECTION), base.ORIGINAL, 7,
        base.sha(members['grouping-policy.tsv']), profile=PROFILE)
    for key in ('profile', 'planner_profile', 'grouped_profile'): info['fields'][key] = PROFILE
    info['fields'].update(grouping_policy_version='3', group_relocation_placement='entry-alphabet-v1')
    storage.repin(record)
    if compact:
        with patch.object(storage.base, 'fixture', return_value=record):
            record = storage.fixture(mode)
    return record


def parse(record, sites=min5.SITES, *, source=min5.SOURCE, profile=PROFILE, compact=False):
    return min5.parse(record, sites, source=source, profile=profile, compact=compact)


class GroupedAlphabetLinkage(unittest.TestCase):
    def test_alphabet_full_population_and_atomic_outcomes_keep_both_storage_modes(self):
        for mode, expected in [('complete',(2,3,2,3,'PASS')), ('group-only',(1,2,1,0,'FAILED')),
                               ('single-only',(1,1,1,0,'FAILED')), ('neither',(0,0,0,0,'FAILED')),
                               ('carrier',(2,3,2,0,'FAILED'))]:
            for compact in (False,True):
                with self.subTest(mode=mode,compact=compact):
                    record = fixture(mode,compact=compact)
                    result = parse(record,compact=compact)
                    self.assertEqual((result['requested'],result['policy_units']),(3,2))
                    self.assertEqual(tuple(result[k] for k in ('accepted_units','accepted_members','unique_images','emitted','status')),expected)
                    self.assertEqual(result['group_relocation_placement'],'entry-alphabet-v1')
                    self.assertEqual(result['grouping_policy_version'],'3')
                    self.assertIn(b'unit\t0\tgroup\t4096\t4100\t2\n'+min5.READY,record[1]['grouping-policy.tsv'])
                    if compact: self.assertEqual(result['ledger_storage']['storage'],data.CHUNK_STORAGE)
        for old_parse, old_fixture in [(base.parse,base.fixture),
                                      (min5.upstream.parse,min5.upstream.fixture),(min5.parse,min5.fixture)]:
            result = old_parse(old_fixture())
            self.assertEqual((result['requested'],result['emitted'],result['status']),(3,3,'PASS'))
            self.assertNotIn('group_relocation_placement',result)
            self.assertNotIn('grouping_policy_version',result)

    def test_alphabet_profile_mode_and_whole_policy_identity_cannot_be_relabelled(self):
        for old in (base.PROFILE,min5.upstream.PROFILE,min5.PROFILE):
            with self.subTest(profile=old),self.assertRaises(AssertionError): parse(fixture(),profile=old)
        for key,value in [('profile',min5.PROFILE),('planner_profile',min5.PROFILE),
                          ('grouped_profile',min5.PROFILE),('grouping_policy_version','2'),
                          ('group_relocation_placement','fixed06'),('window_sealing','unrecorded')]:
            record = fixture(); record[0]['fields'][key] = value
            with self.subTest(key=key),self.assertRaises(AssertionError): parse(record)
        record = fixture(); del record[0]['fields']['group_relocation_placement']
        with self.assertRaises(AssertionError): parse(record)
        for old,new in [(PLACEMENT,b''),(PLACEMENT,PLACEMENT+PLACEMENT),
                        (PLACEMENT,b'group_relocation_placement\tfixed06\n'),
                        (b'LI2GROUPING-POLICY\t3\n',b'LI2GROUPING-POLICY\t2\n')]:
            record = fixture();base.replace(record,'grouping-policy.tsv',old,new)
            with self.subTest(new=new),self.assertRaises(AssertionError): parse(record)
        record = fixture()
        record[1]['binding-policy.tsv'] = min5.fixture()[1]['binding-policy.tsv']
        storage.repin(record)
        with self.assertRaises(AssertionError): parse(record)

    def test_alphabet_keeps_exact_min5_source_membership_routes_and_numeric_limits(self):
        for end in (4100,4101,4103):
            record = fixture();base.replace(record,'grouping-policy.tsv',min5.READY,min5.READY.replace(b'4102',str(end).encode()))
            with self.subTest(end=end),self.assertRaises(AssertionError): parse(record)
        record = fixture()
        base.replace(record,'disassembly.txt',b'head 4100 6690\n',b'')
        for tag in ('route','restored-boundary'):
            base.replace(record,'plan-ledger.tsv',f'{tag}\t0\t4100\t65630\n'.encode(),b'')
        self.assertNotEqual(record[0]['files']['disassembly.txt'],base.pin(min5.SOURCE))
        with self.assertRaises(AssertionError): parse(record)
        with self.assertRaises(AssertionError): parse(record,source=record[1]['disassembly.txt'])
        record = fixture();site = [3,4100,2,260,4096,6,4100,2,'jump']
        min5.foreign_singleton(record,site)
        sites = [*min5.SITES[:2],site]
        self.assertEqual(data.li2_report(record[1]['report.tsv'],sites,base.ORIGINAL,True)['requested'],3)
        with self.assertRaises(AssertionError): parse(record,sites)
        for key,value in [('max_physical_sites','65'),('max_upstream_bytes','65'),
                          ('max_displaced_bytes','257'),('image_candidates_per_physical','2'),
                          ('image_mappings_per_physical','2'),('image_bytes_per_physical','4097')]:
            record = fixture()
            old = next(r for r in record[1]['grouping-policy.tsv'].splitlines(keepends=True) if r.startswith(key.encode()+b'\t'))
            base.replace(record,'grouping-policy.tsv',old,(key+'\t'+value+'\n').encode())
            with self.subTest(key=key),self.assertRaises(AssertionError): parse(record)

    def test_alphabet_refused_seals_and_withheld_members_never_become_emissions(self):
        for compact in (False,True):
            record = fixture('single-only',refused=min5.REFUSAL,compact=compact)
            result = parse(record,compact=compact)
            self.assertEqual((result['requested'],result['accepted_members'],result['emitted'],result['status']),(3,1,0,'FAILED'))
        record = fixture('single-only',refused=min5.REFUSAL)
        old = ('false\t'+'\t'.join(min5.REFUSAL)+'\n').encode()
        self.assertEqual(record[1]['report.tsv'].count(old),2)
        record[1]['report.tsv'] = record[1]['report.tsv'].replace(old,old.replace(min5.REFUSAL[2].encode(),b'78'),1)
        storage.repin(record)
        with self.assertRaises(AssertionError): parse(record)
        record = fixture('group-only')
        base.replace(record,'report.tsv',b'false\t10003\tatomic-selection',b'false\t9\tcore')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture('carrier')
        base.replace(record,'report.tsv',b'false\t10002\tcarrier',b'true\t10002\tcarrier')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture();base.replace(record,'grouping-policy.tsv',b'member\t0\t2\t4099\t1\tpop-r64\n',b'')
        with self.assertRaises(AssertionError): parse(record)


if __name__ == '__main__':
    unittest.main(verbosity=2)
