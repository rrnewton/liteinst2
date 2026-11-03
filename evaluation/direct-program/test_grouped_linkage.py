#!/usr/bin/env python3
"""Small explicit text-protocol fixtures; no decoder, planner or subject run."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('grouped_data', Path(__file__).with_name('direct_data.py'))
data = importlib.util.module_from_spec(spec)
spec.loader.exec_module(data)
ORIGINAL = 'a' * 64
PROFILE = 'jumps-gpr-stack64-block-observation-v1'
HOOK_SHA = hashlib.sha256(b'\xc3').hexdigest()
SITES = [[1, 4096, 1, 256, 4096, 6, 4096, 6, 'push-r64'],
         [2, 4100, 1, 260, 4096, 6, 4096, 6, 'pop-r64'],
         [3, 8192, 5, 512, 8192, 5, 8192, 5, 'jump']]
SELECTION = ('LI2TOOL-SHARED-REGIONS 1\nprofile jumps-gpr-stack64-v1\n'
             f'hook 1 12288 1 {HOOK_SHA}\n').encode()
SOURCE = (f'LI2DISASM 1\noriginal {ORIGINAL}\n'
          'region 4096 256 6\nhead 4096 50\nhead 4097 0f1f00\n'
          'head 4100 58\nhead 4101 c3\nregion 8192 512 5\n'
          'head 8192 e900000000\nregion 12288 768 1\nhead 12288 c3\n').encode()
POLICY_PREFIX = (
    'LI2GROUPING-POLICY\t1\nprofile\t'+PROFILE+'\n'
    'schedule\tall-multisite-blocks-descending-then-singletons-descending-v1\n'
    'window\tfirst-selected-head-through-last-selected-instruction\n'
    'group_tactic\tRelocationOnly\ngroup_attempts\t1\ngroup_fallback\tnone\n'
    'member_budgets\tshared-not-summed\nentry_completeness\tAllInstructionHeads\n'
    'singleton_profile\twhole-program-packed-overlapping-neighbors-4096\n'
    'qualification_complete\tfalse\noriginal_sha256\t'+ORIGINAL+'\n')
PARTITION = ('unit\t0\tgroup\t4096\t4101\t2\n'
             'member\t0\t1\t4096\t1\tpush-r64\n'
             'member\t0\t2\t4100\t1\tpop-r64\n'
             'unit\t1\tsingleton\t8192\t8197\t1\n'
             'member\t1\t3\t8192\t5\tjump\n')
GROUP_MEMBERS = 'member\t0\t1\t4096\t1\tpush-r64\nmember\t0\t2\t4100\t1\tpop-r64\n'
SINGLE_MEMBER = 'member\t1\t3\t8192\t5\tjump\n'
GROUP_IMAGE = bytes(128)
SINGLE_IMAGE = bytes(64)
CANDIDATE = b'explicit-non-executed-fixture'
HEADER = 'site\tpc\tfile_offset\tlength\tcore_tactic\tcandidate_emitted\trefusal_code\tstage\tdetail_hex\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return dict(bytes=len(raw), sha256=sha(raw))


def fixture(mode='complete'):
    """Hand-specified two-unit transcripts, including retained refused units."""
    assert mode in ('complete', 'group-only', 'single-only', 'neither', 'carrier')
    accepted_group = mode in ('complete', 'group-only', 'carrier')
    accepted_single = mode in ('complete', 'single-only', 'carrier')
    complete = mode == 'complete'
    selection = sha(SELECTION)
    policy = (POLICY_PREFIX+f'selection_sha256\t{selection}\ncomplete_site_count\t3\n'+PARTITION).encode()
    plan = (f'LI2GROUPED-LEDGER\t1\noriginal_sha256\t{ORIGINAL}\nselection_sha256\t{selection}\n'
            'bias_policy\tfixed-exec-zero-bias-indexed-jump32-v1\nbias_domain\t7\n'
            'qualification_complete\tfalse\nexecution_authority\tnone\n'
            f'grouping\tcomplete-selected-block-units-v1\nhook\t1\t12288\t1\t{HOOK_SHA}\n')
    products = {'metadata.li2meta': pin(b'metadata'), 'target.tsv': pin(b'target'),
                'planning-profile.tsv': pin(b'profile')}
    if accepted_group:
        plan += ('step\t1\t0\trelocation\t4096\t4096\t4096\t4101\n'
                 f'image\t0\t1\t65536\t128\t{sha(GROUP_IMAGE)}\timage-0000.bin\n'
                 'route\t0\t4096\t65536\nroute\t0\t4097\t65580\nroute\t0\t4100\t65600\n'
                 'restored-boundary\t0\t4096\t65560\nrestored-boundary\t0\t4097\t65580\n'
                 'restored-boundary\t0\t4100\t65620\n'
                 'field\t0\t0\t8\tRelative64\t8\t4096\t7\t4c6f676963616c5063\t0000000000000000\n'
                 'field\t0\t8\t4\tRelative32\t12\t12288\t7\t486f6f6b43616c6c\t00000000\n'
                 'field\t0\t16\t8\tRelative64\t24\t4100\t7\t4c6f676963616c5063\t0000000000000000\n'
                 'field\t0\t24\t4\tRelative32\t28\t12288\t7\t486f6f6b43616c6c\t00000000\n')
        products.update({'image-0000.bin': pin(GROUP_IMAGE), 'group-0.diagnostics.txt': pin(b'Single\n')})
    if accepted_single:
        image = 1 if accepted_group else 0
        plan += (f'step\t3\t0\trelocation\t8192\t8192\t8192\t8197\n'
                 f'image\t{image}\t3\t131072\t64\t{sha(SINGLE_IMAGE)}\timage-{image:04}.bin\n')
        products[f'image-{image:04}.bin'] = pin(SINGLE_IMAGE)
    plan += f'GROUP-ASSOCIATIONS\t1\npolicy_sha256\t{sha(policy)}\n'
    if accepted_group:
        plan += 'accepted-unit\t0\t1\tgroup\t2\n'+GROUP_MEMBERS
    if accepted_single:
        plan += 'accepted-unit\t1\t3\tsingleton\t1\n'+SINGLE_MEMBER
    count = 2*accepted_group+accepted_single
    plan += f'accepted_member_count\t{count}\ncomplete_site_count\t3\nrequired-fixed-source\t{ORIGINAL}\t7\t1\t7\t0\n'
    report = (f'LI2REPORT\t1\noriginal_sha256\t{ORIGINAL}\nselection_sha256\t{selection}\n'
              f'candidate_complete\t{str(complete).lower()}\nqualification_complete\tfalse\n'+HEADER)
    for site in SITES:
        accepted = accepted_group if site[0] < 3 else accepted_single
        tactic = 'B1' if accepted else 'none'
        code, stage = ('none', 'none') if complete else (
            ('10002', 'carrier') if mode == 'carrier' else
            ('10003', 'atomic-selection') if accepted else ('9', 'grouped-core' if site[0] < 3 else 'core'))
        report += f'{site[0]}\t{site[1]}\t{site[3]}\t{site[2]}\t{tactic}\t{str(complete).lower()}\t{code}\t{stage}\tnone\n'
    final = plan
    if complete:
        products['candidate.elf'] = pin(CANDIDATE)
        final += f'CARRIER-EXTENSION\t1\ncandidate_sha256\t{sha(CANDIDATE)}\nfixed-output-readback\tchecked\n'
    members = {'grouping-policy.tsv': policy, 'selection.txt': SELECTION,
               'binding-policy.tsv': data.grouped_binding_bytes(selection, ORIGINAL, 7, sha(policy)),
               'plan-ledger.tsv': plan.encode(), 'ledger.tsv': final.encode(),
               'report.tsv': report.encode(), 'disassembly.txt': SOURCE}
    fields = dict(profile=PROFILE, planner_profile=PROFILE, grouped_profile=PROFILE,
                  singleton_planner_profile='whole-program-packed-overlapping-neighbors-4096',
                  grouping_policy='grouping-policy.tsv', grouping_ledger='LI2GROUPED-LEDGER-1',
                  portable_metadata_verification='checked',
                  embedded_metadata_binding='checked' if complete else 'not-complete',
                  selection_profile='jumps-gpr-stack64-v1', complete_site_count='3',
                  jump_count='1', push_r64_count='1', pop_r64_count='1')
    info = dict(fields=fields, files={**products, **{name: pin(raw) for name, raw in members.items()}})
    return info, members, complete


def parse(record, sites=SITES, report_override=None):
    info, members, complete = record
    report = data.li2_report(members['report.tsv'], sites, ORIGINAL, complete)
    return data.grouped_linkage(info, members, sites, ORIGINAL, 7,
                                report if report_override is None else report_override, source_ledger=pin(SOURCE))


def replace(record, name, old, new):
    """Repin mutated text so controls reach linkage, not merely file hashing."""
    info, members, _ = record
    assert old in members[name] and old != new
    before = members[name]
    members[name] = before.replace(old, new)
    assert members[name] != before
    if name == 'grouping-policy.tsv':
        old_hash, new_hash = sha(before).encode(), sha(members[name]).encode()
        for target in ('binding-policy.tsv', 'plan-ledger.tsv', 'ledger.tsv'):
            members[target] = members[target].replace(old_hash, new_hash)
    if name == 'plan-ledger.tsv':
        assert members['ledger.tsv'].startswith(before)
        members['ledger.tsv'] = members[name]+members['ledger.tsv'][len(before):]
    info['files'].update({key: pin(raw) for key, raw in members.items()})


class GroupedLinkage(unittest.TestCase):
    def test_full_population_local_acceptance_and_atomic_withholding_are_distinct(self):
        for mode, expected in [('complete', (2, 3, 2, 3, 'PASS')),
                               ('group-only', (1, 2, 1, 0, 'FAILED')),
                               ('single-only', (1, 1, 1, 0, 'FAILED')),
                               ('neither', (0, 0, 0, 0, 'FAILED')),
                               ('carrier', (2, 3, 2, 0, 'FAILED'))]:
            with self.subTest(mode=mode):
                result = parse(fixture(mode))
                self.assertEqual((result['policy_units'], result['requested']), (2, 3))
                self.assertEqual(tuple(result[k] for k in ('accepted_units', 'accepted_members', 'unique_images', 'emitted', 'status')), expected)

    def test_total_policy_partition_rejects_missing_duplicate_class_and_schedule_changes(self):
        for old, new in [
            (b'complete_site_count\t3', b'complete_site_count\t2'),
            (b'member\t0\t2\t4100\t1\tpop-r64\n', b''),
            (GROUP_MEMBERS.encode(), (GROUP_MEMBERS+GROUP_MEMBERS).encode()),
            (b'pop-r64', b'jump'),
            (b'group\t4096\t4101\t2', b'group\t4096\t4100\t2'),
            (b'group_fallback\tnone', b'group_fallback\tsingletons'),
            (b'member_budgets\tshared-not-summed', b'member_budgets\tsummed'),
        ]:
            record = fixture(); replace(record, 'grouping-policy.tsv', old, new)
            with self.subTest(mutation=new), self.assertRaises(AssertionError): parse(record)
        with self.assertRaises(AssertionError): parse(fixture(), [SITES[0], SITES[2]])

    def test_association_unique_images_all_heads_and_every_observer_field_are_required(self):
        for old, new in [
            (b'accepted-unit\t0\t1\tgroup\t2', b'accepted-unit\t0\t2\tgroup\t2'),
            (b'member\t0\t2\t4100\t1\tpop-r64\n', b''),
            (b'accepted_member_count\t3', b'accepted_member_count\t2'),
            (b'route\t0\t4097\t65580\n', b''),
            (b'restored-boundary\t0\t4100\t65620', b'restored-boundary\t0\t4100\t70000'),
            (b'\t4100\t7\t4c6f676963616c5063', b'\t4096\t7\t4c6f676963616c5063'),
            (b'\t12288\t7\t486f6f6b43616c6c', b'\t12289\t7\t486f6f6b43616c6c'),
            (b'step\t1\t0\trelocation', b'step\t2\t0\trelocation'),
            (b'image\t0\t1\t65536', b'image\t0\t2\t65536'),
            (b'hook\t1\t12288\t1', b'hook\t1\t12289\t1'),
        ]:
            record = fixture(); replace(record, 'plan-ledger.tsv', old, new)
            with self.subTest(mutation=new), self.assertRaises(AssertionError): parse(record)

    def test_refused_units_cannot_disappear_or_turn_local_acceptance_into_emission(self):
        record = fixture('group-only')
        replace(record, 'report.tsv', b'false\t10003\tatomic-selection', b'false\t9\tgrouped-core')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture('single-only')
        replace(record, 'report.tsv', b'false\t9\tgrouped-core', b'false\t10003\tatomic-selection')
        with self.assertRaises(AssertionError): parse(record)
        for mode, tactic in [('complete', b'T3'), ('group-only', b'none')]:
            record = fixture(mode); replace(record, 'report.tsv', b'B1', tactic)
            with self.subTest(mode=mode), self.assertRaises(AssertionError): parse(record)
        record = fixture('carrier')
        replace(record, 'report.tsv', b'false\t10002\tcarrier', b'true\t10002\tcarrier')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture('neither'); record[0]['files']['candidate.elf'] = pin(CANDIDATE)
        with self.assertRaises(AssertionError): parse(record)
        record = fixture(); report = data.li2_report(record[1]['report.tsv'], SITES, ORIGINAL, True)
        report['rows'][0]['stage'] = 'invented'
        with self.assertRaises(AssertionError): parse(record, report_override=report)

    def test_missing_or_stale_complete_metadata_and_final_carrier_identity_refuse(self):
        # All output self-pins agree, but an unselected source head and its
        # routes cannot disappear relative to the independently frozen input.
        record = fixture()
        replace(record, 'disassembly.txt', b'head 4097 0f1f00\n', b'')
        replace(record, 'plan-ledger.tsv', b'route\t0\t4097\t65580\n', b'')
        replace(record, 'plan-ledger.tsv', b'restored-boundary\t0\t4097\t65580\n', b'')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture(); record[1].pop('grouping-policy.tsv')
        with self.assertRaises(AssertionError): parse(record)
        record = fixture(); record[0]['files']['plan-ledger.tsv']['sha256'] = '0'*64
        with self.assertRaises(AssertionError): parse(record)
        for field, value in [('profile', 'jumps-gpr-stack64-v1'), ('portable_metadata_verification', 'unavailable'),
                             ('embedded_metadata_binding', 'not-complete'), ('complete_site_count', '2')]:
            record = fixture(); record[0]['fields'][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError): parse(record)
        for old, new in [(sha(CANDIDATE).encode(), b'0'*64),
                         (b'fixed-output-readback\tchecked', b'fixed-output-readback\tunavailable')]:
            record = fixture(); replace(record, 'ledger.tsv', old, new)
            with self.subTest(mutation=new), self.assertRaises(AssertionError): parse(record)
        record = fixture(); replace(record, 'binding-policy.tsv', b'generation\t1', b'generation\t2')
        with self.assertRaises(AssertionError): parse(record)


if __name__ == '__main__':
    unittest.main()
