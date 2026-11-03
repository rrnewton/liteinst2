#!/usr/bin/env python3
"""Source-pinned text geometry/association controls; no ISA or chunk decoder."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('alphabet_fixture', Path(__file__).with_name('test_grouped_alphabet_linkage.py'))
alphabet = importlib.util.module_from_spec(spec); spec.loader.exec_module(alphabet)
min5, base, storage, data = alphabet.min5, alphabet.base, alphabet.storage, alphabet.data
PROFILE = data.GROUPED_PHYSICAL_PROFILE
DEPENDENCY = b'source_dependency\tcollector-examined-instruction-envelope-v1\n'
WINDOW = b'window\tper-physical-minimum-whole-instruction-v1\nseal_source\timmutable-original\nseal_stage\tbefore-overlay-mutation\n'
BYTES = bytes.fromhex('506690586690')
READY = (f'window-domain\t0\t1\t1\t0\nwindow-source\t0\t4096\t4102\t{base.sha(BYTES)}\n'
         'physical-window\t0\t0\t4096\tready\t4102\t-\t-\t-\n').encode()


def fixture(mode='complete', *, preflight=None, compact=False):
    record = alphabet.fixture(mode, refused=preflight)
    info, members, _ = record
    base.replace(record, 'grouping-policy.tsv', alphabet.PROFILE.encode(), PROFILE.encode())
    base.replace(record, 'grouping-policy.tsv', b'LI2GROUPING-POLICY\t3\n', b'LI2GROUPING-POLICY\t4\n')
    base.replace(record, 'grouping-policy.tsv', min5.WINDOW, WINDOW)
    base.replace(record, 'grouping-policy.tsv', alphabet.PLACEMENT, alphabet.PLACEMENT+DEPENDENCY)
    old = next(row for row in members['grouping-policy.tsv'].splitlines(keepends=True) if row.startswith(b'window-seal\t'))
    new = READY if preflight is None else ('unit-preflight\t0\trefused\t'+'\t'.join(preflight)+'\n').encode()
    base.replace(record, 'grouping-policy.tsv', old, new)
    members['binding-policy.tsv'] = data.grouped_binding_bytes(base.sha(base.SELECTION), base.ORIGINAL, 7,
        base.sha(members['grouping-policy.tsv']), profile=PROFILE)
    for key in ('profile', 'planner_profile', 'grouped_profile'): info['fields'][key] = PROFILE
    info['fields'].update(grouping_policy_version='4', window_sealing='physical-minimum-whole-instruction-v1')
    storage.repin(record)
    if compact:
        with patch.object(storage.base, 'fixture', return_value=record): record = storage.fixture(mode)
    return record


def parse(record, sites=min5.SITES, *, source=min5.SOURCE, compact=False, profile=PROFILE):
    return min5.parse(record, sites, source=source, compact=compact, profile=profile)


def prefix_fixture(*, earlier=False, refused_first=False):
    record = fixture()
    source = min5.SOURCE.replace(b'region 4096 256 6\n', b'region 4091 251 11\nhead 4091 0f1f440000\n')
    base.replace(record, 'disassembly.txt', min5.SOURCE, source)
    sites = [s[:4]+[4091,11,4091,11]+s[8:] for s in min5.SITES[:2]]+[min5.SITES[2]]
    first = 'refused\t-\t11\tcore\t'+b'UnsupportedInstruction'.hex() if refused_first else 'ready\t4102\t-\t-\t-'
    rows = (f'window-domain\t0\t2\t2\t0\nwindow-source\t0\t4091\t4102\t{base.sha(bytes.fromhex("0f1f440000")+BYTES)}\n'
            f'physical-window\t0\t0\t4096\t{first}\nphysical-window\t0\t1\t4091\tready\t4100\t-\t-\t-\n').encode()
    base.replace(record, 'grouping-policy.tsv', READY, rows)
    if earlier:
        base.replace(record, 'plan-ledger.tsv', b'4096\t4096\t4096\t4102\n', b'4096\t4091\t4091\t4100\n')
        for tag, address in [('route',65537), ('restored-boundary',65538)]:
            base.replace(record, 'plan-ledger.tsv', f'{tag}\t0\t4100\t65630\n'.encode(), b'')
            line = next(row for row in record[1]['plan-ledger.tsv'].splitlines(keepends=True) if row.startswith(f'{tag}\t0\t4096\t'.encode()))
            base.replace(record, 'plan-ledger.tsv', line, f'{tag}\t0\t4091\t{address}\n'.encode()+line)
    return record, sites, source


class GroupedPhysicalLinkage(unittest.TestCase):
    def test_physical_full_denominator_atomic_outcomes_and_both_storage_modes(self):
        for mode, expected in [('complete',(2,3,2,3,'PASS')), ('group-only',(1,2,1,0,'FAILED')),
                               ('single-only',(1,1,1,0,'FAILED')), ('neither',(0,0,0,0,'FAILED')),
                               ('carrier',(2,3,2,0,'FAILED'))]:
            for compact in (False, True):
                result = parse(fixture(mode,compact=compact),compact=compact)
                self.assertEqual(tuple(result[k] for k in ('accepted_units','accepted_members','unique_images','emitted','status')), expected)
                self.assertEqual(result['grouping_policy_version'], '4')
                self.assertEqual(result['requested'], 3)
        for old_parse, old_fixture in [(base.parse,base.fixture), (min5.upstream.parse,min5.upstream.fixture),
                                       (min5.parse,min5.fixture), (alphabet.parse,alphabet.fixture)]:
            self.assertEqual(old_parse(old_fixture())['status'], 'PASS')
        record, sites, source = prefix_fixture(earlier=True,refused_first=True)
        result = parse(record,sites,source=source)
        self.assertEqual(result['accepted_physical_ordinals'], {0:1})
        record, sites, source = prefix_fixture()
        self.assertEqual(parse(record,sites,source=source)['accepted_physical_ordinals'], {0:0})

    def test_physical_repinned_omission_order_end_source_and_actual_step_rejected(self):
        for mutation in range(7):
            record, sites, source = prefix_fixture()
            rows = record[1]['grouping-policy.tsv'].splitlines(keepends=True)
            later = next(row for row in rows if row.startswith(b'physical-window\t0\t1\t'))
            if mutation == 0: base.replace(record,'grouping-policy.tsv',later,b'')
            if mutation == 1: base.replace(record,'grouping-policy.tsv',later,later+later)
            if mutation == 2: base.replace(record,'grouping-policy.tsv',b'window-domain\t0\t2\t2\t0',b'window-domain\t0\t2\t1\t1')
            if mutation == 3: base.replace(record,'grouping-policy.tsv',later,later.replace(b'\t1\t4091',b'\t0\t4091'))
            if mutation == 4: base.replace(record,'grouping-policy.tsv',later,later.replace(b'4100',b'4102'))
            if mutation == 5: base.replace(record,'grouping-policy.tsv',b'window-source\t0\t4091\t4102',b'window-source\t0\t4096\t4102')
            if mutation == 6: base.replace(record,'plan-ledger.tsv',b'4096\t4096\t4096\t4102\n',b'4096\t4091\t4091\t4102\n')
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError): parse(record,sites,source=source)
        record = fixture(); base.replace(record,'disassembly.txt',b'head 4100 6690',b'head 4100 66f8')
        with self.assertRaises(AssertionError): parse(record)
        with self.assertRaises(AssertionError): parse(record,source=record[1]['disassembly.txt'])

    def test_physical_every_ready_window_membership_routes_and_policy_identity(self):
        record = fixture(); site = [3,4100,2,260,4096,6,4100,2,'jump']
        min5.foreign_singleton(record,site)
        with self.assertRaises(AssertionError): parse(record,[*min5.SITES[:2],site])
        for tag in ('route','restored-boundary'):
            record = fixture(); base.replace(record,'plan-ledger.tsv',f'{tag}\t0\t4100\t65630\n'.encode(),b'')
            with self.assertRaises(AssertionError): parse(record)
        # Even a ready row whose whole group is unaccepted must tile every
        # frozen source head. Repinning cannot hide an interior overlapping head.
        record = fixture('single-only')
        self.assertEqual(parse(record)['accepted_members'], 1)
        source = min5.SOURCE.replace(b'head 4100 6690\n', b'head 4100 6690\nhead 4101 90\n')
        self.assertNotEqual(source, min5.SOURCE)
        base.replace(record, 'disassembly.txt', min5.SOURCE, source)
        with self.assertRaises(AssertionError): parse(record, source=source)
        for profile in (base.PROFILE,min5.upstream.PROFILE,min5.PROFILE,alphabet.PROFILE):
            with self.assertRaises(AssertionError): parse(fixture(),profile=profile)
        for key, value in [('grouping_policy_version','3'), ('window_sealing','minimum-whole-instruction-v1'),
                           ('group_relocation_placement','fixed06')]:
            record=fixture(); record[0]['fields'][key]=value
            with self.assertRaises(AssertionError): parse(record)
        for old,new in [(DEPENDENCY,b''),(DEPENDENCY,DEPENDENCY+DEPENDENCY),
                        (b'window-domain\t0\t1\t1\t0',b'window-domain\t0\t01\t1\t0'),
                        (b'\n',b'\r\n'),(b'max_physical_sites\t64',b'max_physical_sites\t65')]:
            record=fixture();base.replace(record,'grouping-policy.tsv',old,new)
            with self.assertRaises(AssertionError): parse(record)

    def test_physical_global_refusal_is_exact_and_local_refusal_is_not_final_refusal(self):
        refusal=('10001','grouped-policy',b'whole unit refused'.hex())
        for compact in (False,True):
            result=parse(fixture('single-only',preflight=refusal,compact=compact),compact=compact)
            self.assertEqual((result['status'],result['requested'],result['accepted_members']),('FAILED',3,1))
        record=fixture('single-only',preflight=refusal)
        base.replace(record,'report.tsv',refusal[2].encode(),b'78')
        with self.assertRaises(AssertionError):parse(record)
        record, sites, source=prefix_fixture(earlier=True,refused_first=True)
        self.assertEqual(parse(record,sites,source=source)['status'],'PASS')
        record, sites, source=prefix_fixture(refused_first=True)
        with self.assertRaises(AssertionError):parse(record,sites,source=source)

    def test_physical_cap_start_fifteen_bytes_and_omitted_sixty_fifth_head(self):
        # Geometric fixture only: no encoded instruction is decoded here.
        heads={pc:1 for pc in range(4032,4352)};heads[4352]=15
        encoded={pc:b'\x90'*length for pc,length in heads.items()}
        sites=[[1,4096,1,0,4032,335,4032,335,'pop-r64'],[2,4352,15,256,4032,335,4032,335,'pop-r64']]
        domain=sorted(range(4032,4097),key=lambda pc:(pc!=4096,pc%64>56,4096-pc))
        self.assertEqual((len(domain),domain[0],domain[-1]),(65,4096,4089))
        rows=[['window-domain','0','65','64','1'],['window-source','0','4032','4367',base.sha(b'\x90'*335)]]
        rows += [['physical-window','0',str(i),str(pc),'refused','-','9','core',b'NoPatchWindow'.hex()] for i,pc in enumerate(domain[:64])]
        result=data.grouped_physical_seals(rows,[sites],sites,heads,encoded,int)
        self.assertEqual(result[0],rows)
        changed=[row[:] for row in rows];changed[1][3]='4366'
        with self.assertRaises(AssertionError):data.grouped_physical_seals(changed,[sites],sites,heads,encoded,int)
        changed=[row[:] for row in rows];changed[-1][3]=str(domain[-1])
        with self.assertRaises(AssertionError):data.grouped_physical_seals(changed,[sites],sites,heads,encoded,int)


if __name__ == '__main__': unittest.main(verbosity=2)
