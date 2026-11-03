#!/usr/bin/env python3
"""Additive min5 text joins; no decoder, planner, chunk decoder or native run."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upstream = sibling('test_grouped_upstream_linkage')
base = upstream.base
storage = sibling('test_ledger_storage')
data = base.data
PROFILE = 'jumps-gpr-stack64-block-min5-upstream-v1'
SITES = [base.SITES[0], [2,4099,1,259,4096,6,4096,6,'pop-r64'], base.SITES[2]]
SOURCE = base.SOURCE.replace(b'head 4097 0f1f00\nhead 4100 58\nhead 4101 c3\n',
                           b'head 4097 6690\nhead 4099 58\nhead 4100 6690\n')
WINDOW = (b'window\tminimum-whole-instruction-through-last-selected-min5-v1\n'
          b'seal_source\timmutable-original\nseal_stage\tbefore-overlay-mutation\n')
READY = b'window-seal\t0\tready\t4102\t-\t-\t-\n'
REFUSAL = ('9', 'core', b'NoPatchWindow'.hex())


def fixture(mode='complete', *, refused=None, compact=False):
    record = base.fixture(mode)
    info, members, _ = record
    base.replace(record, 'grouping-policy.tsv', base.PROFILE.encode(), PROFILE.encode())
    base.replace(record, 'grouping-policy.tsv', b'LI2GROUPING-POLICY\t1\n', b'LI2GROUPING-POLICY\t2\n')
    base.replace(record, 'grouping-policy.tsv',
                 b'window\tfirst-selected-head-through-last-selected-instruction\n', WINDOW)
    base.replace(record, 'grouping-policy.tsv', b'group_attempts\t1\n', upstream.PHYSICAL_POLICY)
    seal = READY if refused is None else ('window-seal\t0\trefused\t-\t'+'\t'.join(refused)+'\n').encode()
    base.replace(record, 'grouping-policy.tsv', b'unit\t0\tgroup\t4096\t4101\t2\n',
                 b'unit\t0\tgroup\t4096\t4100\t2\n'+seal)
    base.replace(record, 'grouping-policy.tsv', b'member\t0\t2\t4100\t1\tpop-r64\n',
                 b'member\t0\t2\t4099\t1\tpop-r64\n')
    members['binding-policy.tsv'] = data.grouped_binding_bytes(base.sha(base.SELECTION), base.ORIGINAL, 7,
                                                               base.sha(members['grouping-policy.tsv']), profile=PROFILE)
    base.replace(record, 'disassembly.txt', base.SOURCE, SOURCE)
    base.replace(record, 'report.tsv', b'2\t4100\t260\t1\t', b'2\t4099\t259\t1\t')
    if mode in ('complete', 'group-only', 'carrier'):
        base.replace(record, 'plan-ledger.tsv', b'4096\t4096\t4096\t4101\n', b'4096\t4096\t4096\t4102\n')
        base.replace(record, 'plan-ledger.tsv', b'member\t0\t2\t4100\t1\tpop-r64\n', b'member\t0\t2\t4099\t1\tpop-r64\n')
        base.replace(record, 'plan-ledger.tsv', b'route\t0\t4100\t65600\n', b'route\t0\t4099\t65600\nroute\t0\t4100\t65630\n')
        base.replace(record, 'plan-ledger.tsv', b'restored-boundary\t0\t4100\t65620\n',
                     b'restored-boundary\t0\t4099\t65620\nrestored-boundary\t0\t4100\t65630\n')
        base.replace(record, 'plan-ledger.tsv', b'\t4100\t7\t4c6f676963616c5063\t', b'\t4099\t7\t4c6f676963616c5063\t')
    if refused is not None:
        assert mode in ('single-only', 'neither')
        base.replace(record, 'report.tsv', b'false\t9\tgrouped-core\tnone\n',
                     ('false\t'+'\t'.join(refused)+'\n').encode())
    for key in ('profile', 'planner_profile', 'grouped_profile'): info['fields'][key] = PROFILE
    info['fields'].update(grouping_policy_version='2', window_sealing='minimum-whole-instruction-v1')
    storage.repin(record)
    if compact:
        # Reuse the existing fixture writer over this same inline transcript.
        # Only the fixture factory is replaced, never the parser under test.
        with patch.object(storage.base, 'fixture', return_value=record):
            record = storage.fixture(mode)
    return record


def parse(record, sites=SITES, *, source=SOURCE, profile=PROFILE, compact=False):
    info, members, complete = record
    report = data.li2_report(members['report.tsv'], sites, base.ORIGINAL, complete)
    return data.grouped_linkage(info, members, sites, base.ORIGINAL, 7, report,
        source_ledger=base.pin(source), profile=profile,
        ledger_storage=data.CHUNK_STORAGE if compact else 'inline')


def foreign_singleton(record, site):
    """Move the existing complete third row, retaining its accepted-unit."""
    info, members, _ = record
    _, pc, length, offset, _, _, _, _, kind = site
    base.replace(record, 'grouping-policy.tsv',
        b'unit\t1\tsingleton\t8192\t8197\t1\nmember\t1\t3\t8192\t5\tjump\n',
        f'unit\t1\tsingleton\t{pc}\t{pc+length}\t1\nmember\t1\t3\t{pc}\t{length}\t{kind}\n'.encode())
    base.replace(record, 'plan-ledger.tsv', b'member\t1\t3\t8192\t5\tjump\n',
        f'member\t1\t3\t{pc}\t{length}\t{kind}\n'.encode())
    base.replace(record, 'plan-ledger.tsv', b'step\t3\t0\trelocation\t8192\t8192\t8192\t8197\n',
        f'step\t3\t0\trelocation\t{pc}\t{pc}\t{pc}\t{pc+length}\n'.encode())
    rows = members['report.tsv'].splitlines(keepends=True); at = rows.index(base.HEADER.encode())
    changed = rows[-1].replace(b'3\t8192\t512\t5\t', f'3\t{pc}\t{offset}\t{length}\t'.encode())
    assert changed != rows[-1]
    data_rows = [*rows[at+1:-1],changed]
    data_rows.sort(key=lambda row:int(row.split(b'\t')[1]))
    members['report.tsv'] = b''.join(rows[:at+1]+data_rows)
    storage.repin(record)


class GroupedMin5Linkage(unittest.TestCase):
    def test_min5_exact_tail_keeps_complete_outcomes_and_both_storage_modes(self):
        for mode, expected in [('complete',(2,3,2,3,'PASS')),('group-only',(1,2,1,0,'FAILED')),
                               ('single-only',(1,1,1,0,'FAILED')),('neither',(0,0,0,0,'FAILED')),
                               ('carrier',(2,3,2,0,'FAILED'))]:
            for compact in (False,True):
                with self.subTest(mode=mode,compact=compact):
                    record = fixture(mode,compact=compact); result = parse(record,compact=compact)
                    self.assertEqual((result['policy_units'],result['requested']),(2,3))
                    self.assertEqual(tuple(result[k]for k in ('accepted_units','accepted_members','unique_images','emitted','status')),expected)
                    self.assertIn(b'unit\t0\tgroup\t4096\t4100\t2\n'+READY,record[1]['grouping-policy.tsv'])
                    if compact: self.assertEqual(result['ledger_storage']['storage'],data.CHUNK_STORAGE)
        self.assertEqual(base.parse(base.fixture())['status'],'PASS')
        self.assertEqual(upstream.parse(upstream.fixture())['status'],'PASS')
        with self.assertRaises(AssertionError): parse(fixture(),profile=base.PROFILE)
        with self.assertRaises(AssertionError): parse(fixture(),profile=upstream.PROFILE)
        # The same minimal tail also joins an actual declared upstream prefix.
        record = fixture()
        source = SOURCE.replace(b'region 4096 256 6\n',b'region 4091 251 11\nhead 4091 0f1f440000\n')
        base.replace(record,'disassembly.txt',SOURCE,source)
        base.replace(record,'plan-ledger.tsv',b'4096\t4096\t4096\t4102\n',b'4096\t4091\t4091\t4102\n')
        base.replace(record,'plan-ledger.tsv',b'route\t0\t4096\t65536\n',b'route\t0\t4091\t65537\nroute\t0\t4096\t65536\n')
        base.replace(record,'plan-ledger.tsv',b'restored-boundary\t0\t4096\t65560\n',b'restored-boundary\t0\t4091\t65538\nrestored-boundary\t0\t4096\t65560\n')
        sites = [s[:4]+[4091,11,4091,11]+s[8:]for s in SITES[:2]]+[SITES[2]]
        self.assertEqual(parse(record,sites,source=source)['status'],'PASS')

    def test_min5_sealed_end_source_tiling_and_all_tail_routes_are_exact(self):
        for end in (4100,4101,4103):
            record = fixture(); base.replace(record,'grouping-policy.tsv',READY,READY.replace(b'4102',str(end).encode()))
            with self.subTest(end=end),self.assertRaises(AssertionError): parse(record)
        for tag in ('route','restored-boundary'):
            record = fixture(); base.replace(record,'plan-ledger.tsv',f'{tag}\t0\t4100\t65630\n'.encode(),b'')
            with self.subTest(tag=tag),self.assertRaises(AssertionError): parse(record)
        record = fixture(); base.replace(record,'disassembly.txt',b'head 4100 6690\n',b'')
        base.replace(record,'plan-ledger.tsv',b'route\t0\t4100\t65630\n',b'')
        base.replace(record,'plan-ledger.tsv',b'restored-boundary\t0\t4100\t65630\n',b'')
        self.assertNotEqual(record[0]['files']['disassembly.txt'],base.pin(SOURCE))
        with self.assertRaises(AssertionError): parse(record)
        # Repinning even the external source cannot invent the missing tail head.
        with self.assertRaises(AssertionError): parse(record,source=record[1]['disassembly.txt'])
        record = fixture(); base.replace(record,'disassembly.txt',b'head 4097 6690\n',b'head 4097 0f1f00\n')
        with self.assertRaises(AssertionError): parse(record,source=record[1]['disassembly.txt'])
        # Extending the declared block does not permit an additional nonminimal NOP.
        record = fixture(); changed = SOURCE.replace(b'region 4096 256 6\n',b'region 4096 256 7\n').replace(b'head 4100 6690\n',b'head 4100 6690\nhead 4102 90\n')
        base.replace(record,'disassembly.txt',SOURCE,changed)
        base.replace(record,'grouping-policy.tsv',READY,READY.replace(b'4102',b'4103'))
        sites = [s[:4]+[4096,7,4096,7]+s[8:] for s in SITES[:2]]+[SITES[2]]
        with self.assertRaises(AssertionError): parse(record,sites,source=changed)
        for key,value in [('max_physical_sites','65'),('max_upstream_bytes','65'),
                          ('max_displaced_bytes','257'),('image_candidates_per_physical','2'),
                          ('image_mappings_per_physical','2'),('image_bytes_per_physical','4097')]:
            record = fixture()
            old = next(row for row in record[1]['grouping-policy.tsv'].splitlines(keepends=True) if row.startswith(key.encode()+b'\t'))
            base.replace(record,'grouping-policy.tsv',old,(key+'\t'+value+'\n').encode())
            with self.subTest(key=key),self.assertRaises(AssertionError): parse(record)
        for key,value in [('grouping_policy_version','1'),('window_sealing','unrecorded')]:
            record = fixture();record[0]['fields'][key] = value
            with self.subTest(key=key),self.assertRaises(AssertionError): parse(record)

    def test_min5_full_manifest_retained_tail_upstream_and_straddlers_cannot_disappear(self):
        for site, source in [
            ([3,4100,2,260,4096,6,4100,2,'jump'],SOURCE),
            ([3,4094,5,254,4094,8,4094,5,'jump'],SOURCE.replace(b'region 4096 256 6\n',b'region 4094 254 8\nhead 4094 0f1f440000\n')),
        ]:
            record = fixture(); foreign_singleton(record,site)
            if source != SOURCE: base.replace(record,'disassembly.txt',SOURCE,source)
            sites = sorted([*SITES[:2],site],key=lambda s:s[1])
            self.assertEqual(data.li2_report(record[1]['report.tsv'],sites,base.ORIGINAL,True)['requested'],3)
            with self.subTest(site=site),self.assertRaises(AssertionError): parse(record,sites,source=source)
        source = SOURCE.replace(b'region 4096 256 6\n',b'region 4091 251 11\nhead 4091 0f1f440000\n')
        site = [3,4091,5,251,4091,11,4091,5,'jump']
        record = fixture(); foreign_singleton(record,site);base.replace(record,'disassembly.txt',SOURCE,source)
        population = [s[:4]+[4091,11,4091,11]+s[8:]for s in SITES[:2]]
        sites = [site,*population]
        self.assertEqual(data.li2_report(record[1]['report.tsv'],sites,base.ORIGINAL,True)['requested'],3)
        with self.assertRaises(AssertionError): parse(record,sites,source=source)

    def test_min5_refused_seals_keep_every_member_and_never_grant_local_acceptance(self):
        for refusal in (REFUSAL,('10001','grouped-membership',b'full manifest intersection'.hex())):
            for compact in (False,True):
                record = fixture('single-only',refused=refusal,compact=compact)
                result = parse(record,compact=compact)
                self.assertEqual((result['requested'],result['accepted_members'],result['emitted'],result['status']),(3,1,0,'FAILED'))
        record = fixture('single-only',refused=REFUSAL)
        old = ('false\t'+'\t'.join(REFUSAL)+'\n').encode()
        new = old.replace(REFUSAL[2].encode(),b'78')
        self.assertNotEqual(old,new)
        # A single member's divergent detail must not hide behind equal codes.
        raw = record[1]['report.tsv'];self.assertEqual(raw.count(old),2)
        record[1]['report.tsv'] = raw.replace(old,new,1);storage.repin(record)
        with self.assertRaises(AssertionError): parse(record)
        for old,new in [(READY,b''),(READY,READY+READY),(READY,READY.replace(b'\t0\t',b'\t1\t',1)),
                        (b'LI2GROUPING-POLICY\t2\n',b'LI2GROUPING-POLICY\t1\n')]:
            record = fixture();base.replace(record,'grouping-policy.tsv',old,new)
            with self.subTest(new=new),self.assertRaises(AssertionError): parse(record)
        record = fixture();refused = ('window-seal\t0\trefused\t-\t'+'\t'.join(REFUSAL)+'\n').encode()
        base.replace(record,'grouping-policy.tsv',READY,refused)
        with self.assertRaises(AssertionError): parse(record)
        record = fixture('single-only',refused=REFUSAL)
        base.replace(record,'grouping-policy.tsv',b'member\t0\t2\t4099\t1\tpop-r64\n',b'')
        with self.assertRaises(AssertionError): parse(record)


if __name__ == '__main__':
    unittest.main(verbosity=2)
