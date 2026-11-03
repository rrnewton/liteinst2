#!/usr/bin/env python3
"""Explicit grouped suffix-policy joins; no decoder, planner or native run."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('physical_fixture', Path(__file__).with_name('test_grouped_physical_linkage.py'))
physical = importlib.util.module_from_spec(spec)
spec.loader.exec_module(physical)
min5, base, storage, data = physical.min5, physical.base, physical.storage, physical.data
PROFILE = data.GROUPED_SUFFIX60_PROFILE
SUFFIX = b'group_routed_suffix\tsingle-byte60-v1\n'


def fixture(mode='complete', *, preflight=None, compact=False):
    record = physical.fixture(mode, preflight=preflight)
    info, members, _ = record
    base.replace(record, 'grouping-policy.tsv', physical.PROFILE.encode(), PROFILE.encode())
    base.replace(record, 'grouping-policy.tsv', b'LI2GROUPING-POLICY\t4\n', b'LI2GROUPING-POLICY\t5\n')
    base.replace(record, 'grouping-policy.tsv', physical.alphabet.PLACEMENT, physical.alphabet.PLACEMENT+SUFFIX)
    members['binding-policy.tsv'] = data.grouped_binding_bytes(base.sha(base.SELECTION), base.ORIGINAL, 7,
        base.sha(members['grouping-policy.tsv']), profile=PROFILE)
    for key in ('profile', 'planner_profile', 'grouped_profile'): info['fields'][key] = PROFILE
    info['fields'].update(grouping_policy_version='5', group_routed_suffix='single-byte60-v1')
    storage.repin(record)
    if compact:
        with patch.object(storage.base, 'fixture', return_value=record): record = storage.fixture(mode)
    return record


def parse(record, sites=min5.SITES, *, source=min5.SOURCE, compact=False, profile=PROFILE):
    return physical.parse(record, sites, source=source, compact=compact, profile=profile)


class GroupedSuffix60Linkage(unittest.TestCase):
    def test_suffix60_exact_profile_preserves_all_atomic_outcomes_and_storage(self):
        for mode, expected in [('complete',(2,3,2,3,'PASS')), ('group-only',(1,2,1,0,'FAILED')),
                               ('single-only',(1,1,1,0,'FAILED')), ('neither',(0,0,0,0,'FAILED')),
                               ('carrier',(2,3,2,0,'FAILED'))]:
            for compact in (False, True):
                result = parse(fixture(mode, compact=compact), compact=compact)
                self.assertEqual(tuple(result[k] for k in ('accepted_units','accepted_members','unique_images','emitted','status')), expected)
                self.assertEqual((result['requested'], result['policy_units']), (3, 2))
                self.assertEqual((result['grouping_policy_version'], result['group_routed_suffix']), ('5', 'single-byte60-v1'))
        old = physical.fixture()
        result = physical.parse(old)
        self.assertEqual((result['requested'], result['emitted'], result['status']), (3, 3, 'PASS'))
        self.assertEqual(result['grouping_policy_version'], '4')
        self.assertNotIn('group_routed_suffix', result)
        new = fixture()
        inverse = new[1]['grouping-policy.tsv'].replace(b'LI2GROUPING-POLICY\t5\n', b'LI2GROUPING-POLICY\t4\n').replace(PROFILE.encode(), physical.PROFILE.encode()).replace(SUFFIX, b'')
        self.assertEqual(inverse, old[1]['grouping-policy.tsv'])
        for name in ('selection.txt', 'report.tsv', 'disassembly.txt'):
            self.assertEqual(new[1][name], old[1][name])
        for name in ('plan-ledger.tsv', 'ledger.tsv'):
            self.assertEqual(new[1][name].replace(base.sha(new[1]['grouping-policy.tsv']).encode(),
                base.sha(old[1]['grouping-policy.tsv']).encode()), old[1][name])
        self.assertTrue(new[1]['binding-policy.tsv'].endswith(SUFFIX))
        self.assertNotIn(SUFFIX, old[1]['binding-policy.tsv'])

    def test_suffix60_stale_mode_binding_and_repinned_policy_are_refused(self):
        for profile in (base.PROFILE, min5.upstream.PROFILE, min5.PROFILE, physical.alphabet.PROFILE, physical.PROFILE):
            with self.subTest(profile=profile), self.assertRaises(AssertionError): parse(fixture(), profile=profile)
        with self.assertRaises(AssertionError): parse(physical.fixture())
        for key, value in [('grouping_policy_version','4'), ('group_routed_suffix','qualified62-v1'),
                           ('group_relocation_placement','fixed06'), ('window_sealing','minimum-whole-instruction-v1')]:
            record = fixture(); record[0]['fields'][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError): parse(record)
        record = fixture(); del record[0]['fields']['group_routed_suffix']
        with self.assertRaises(AssertionError): parse(record)
        for value in (b'', SUFFIX+SUFFIX, b'group_routed_suffix\tqualified62-v1\n'):
            record = fixture(); base.replace(record, 'grouping-policy.tsv', SUFFIX, value)
            with self.subTest(value=value), self.assertRaises(AssertionError): parse(record)
        record = fixture(); record[1]['binding-policy.tsv'] = physical.fixture()[1]['binding-policy.tsv']; storage.repin(record)
        with self.assertRaises(AssertionError): parse(record)
        record = fixture(); record[1]['binding-policy.tsv'] = record[1]['binding-policy.tsv'].replace(SUFFIX, b''); storage.repin(record)
        with self.assertRaises(AssertionError): parse(record)

    def test_suffix60_retains_full_membership_routes_and_numeric_ceiling(self):
        record = fixture(); site = [3,4100,2,260,4096,6,4100,2,'jump']; min5.foreign_singleton(record,site)
        with self.assertRaises(AssertionError): parse(record,[*min5.SITES[:2],site])
        for tag in ('route', 'restored-boundary'):
            record = fixture(); base.replace(record,'plan-ledger.tsv',f'{tag}\t0\t4100\t65630\n'.encode(),b'')
            with self.assertRaises(AssertionError): parse(record)
        for key, value in [('max_physical_sites','65'), ('max_upstream_bytes','65'),
                           ('max_displaced_bytes','257'), ('image_candidates_per_physical','2'),
                           ('image_mappings_per_physical','2'), ('image_bytes_per_physical','4097')]:
            record = fixture()
            old = next(r for r in record[1]['grouping-policy.tsv'].splitlines(keepends=True) if r.startswith(key.encode()+b'\t'))
            base.replace(record, 'grouping-policy.tsv', old, (key+'\t'+value+'\n').encode())
            with self.subTest(key=key), self.assertRaises(AssertionError): parse(record)

    def test_suffix60_refusal_bytes_and_atomic_withholding_are_never_promoted(self):
        refusal = ('10001','grouped-policy',b'whole unit refused'.hex())
        for compact in (False, True):
            result = parse(fixture('single-only', preflight=refusal, compact=compact), compact=compact)
            self.assertEqual((result['status'], result['requested'], result['accepted_members'], result['emitted']), ('FAILED',3,1,0))
        record = fixture('single-only', preflight=refusal); base.replace(record,'report.tsv',refusal[2].encode(),b'78')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture('group-only'); base.replace(record,'report.tsv',b'false\t10003\tatomic-selection',b'false\t9\tcore')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture('carrier'); base.replace(record,'report.tsv',b'false\t10002\tcarrier',b'true\t10002\tcarrier')
        with self.assertRaises(AssertionError): parse(record)


if __name__ == '__main__': unittest.main(verbosity=2)
