#!/usr/bin/env python3
"""Small authenticated text-envelope controls; no chunk decoder or subject run."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('group_fixture', Path(__file__).with_name('test_grouped_linkage.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
data = base.data


def repin(record):
    info, members, _ = record
    info['files'].update({name: base.pin(raw) for name, raw in members.items()})


def fixture(mode='complete'):
    record = base.fixture(mode)
    info, members, _ = record
    table = b'LI2READ-CHUNKS\t1\t256\t0\n'
    old = members['plan-ledger.tsv']
    lines = []; canonical = []
    steps = 0
    for line in old.splitlines(keepends=True):
        lines.append(line); canonical.append(line)
        if line.startswith(b'step\t'):
            fields = line.decode().split('\t')
            site, step = fields[1:3]
            steps += 1
            canonical.append((f'live-prerequisites-not-receipts\t{site}\t{step}\ttrue\ttrue\tfalse\nstep-read\t{site}\t{step}\t4096\t\n').encode())
            lines.append((f'live-prerequisites-not-receipts\t{site}\t{step}\ttrue\ttrue\tfalse\n'
                          f'step-reads\t{site}\t{step}\t1\n'
                          f'step-read-ref\t{site}\t{step}\t0\t4096\t0\t{base.sha(b"")}\t-\n').encode())
    plan = b''.join(lines).replace(b'LI2GROUPED-LEDGER\t1\n',
        ('LI2GROUPED-LEDGER\t2\nread-storage\t'+data.CHUNK_STORAGE+'\t'+str(len(table))+'\t'+base.sha(table)+'\n').encode(), 1)
    canonical = b''.join(canonical) + members['ledger.tsv'][len(old):]
    members['ledger.tsv'] = plan + members['ledger.tsv'][len(old):]
    members['plan-ledger.tsv'] = plan
    members['read-chunks.tsv'] = table
    # The fixture declares the existing Rust verification result. This Python
    # control tests only its exact member closure, never semantic read decoding.
    proof = ('LI2LEDGER-VERIFICATION\t1\nstorage\t'+data.CHUNK_STORAGE+'\n'
             'original_sha256\t'+base.ORIGINAL+'\nselection_sha256\t'+base.sha(base.SELECTION)+'\n'
             'wire\tchecked\ncurrent_overlay_reads\tchecked-before-writes\n'
             'semantic_scope\tcurrent-reads-and-record-shape-only\nbootstrap\tunsupported\n'
             f'member_limit\t{64*data.M}\naggregate_limit\t{128*data.M}\n')
    for name in ('plan-ledger.tsv', 'ledger.tsv', 'read-chunks.tsv'):
        proof += f'member\t{name}\t{len(members[name])}\t{base.sha(members[name])}\n'
    proof += f'canonical_bytes\t{len(canonical)}\ncanonical_sha256\t{base.sha(canonical)}\nsteps\t{steps}\nreads\t{steps}\nreferences\t0\nqualification_complete\tfalse\n'
    members['ledger-verification.tsv'] = proof.encode()
    repin(record)
    bundle = 'LI2BUNDLE\t1\noriginal_sha256\t'+base.ORIGINAL+'\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n'
    for name, pin in sorted(info['files'].items()):
        bundle += f'file\t{name}\t{pin["bytes"]}\t{pin["sha256"]}\n'
    members['bundle-index.tsv'] = bundle.encode()
    info['fields'].update(ledger_storage=data.CHUNK_STORAGE, ledger_read_table='read-chunks.tsv',
        ledger_verification='ledger-verification.tsv', ledger_bootstrap='unsupported',
        ledger_wire_verification='checked', ledger_current_read_verification='checked-before-writes',
        grouping_ledger='LI2GROUPED-LEDGER-2')
    repin(record)
    return record


def parse(record, storage=data.CHUNK_STORAGE):
    info, members, complete = record
    report = data.li2_report(members['report.tsv'], base.SITES, base.ORIGINAL, complete)
    return data.grouped_linkage(info, members, base.SITES, base.ORIGINAL, 7, report,
        source_ledger=base.pin(base.SOURCE), ledger_storage=storage)


class LedgerStorage(unittest.TestCase):
    def test_compact_closure_keeps_every_atomic_outcome_and_legacy_default(self):
        for mode in ('complete', 'group-only', 'single-only', 'neither', 'carrier'):
            with self.subTest(mode=mode):
                old = base.parse(base.fixture(mode)); compact = parse(fixture(mode))
                self.assertEqual(compact.pop('grouping_ledger'), 'LI2GROUPED-LEDGER-2')
                self.assertEqual(compact.pop('ledger_storage')['storage'], data.CHUNK_STORAGE)
                self.assertEqual(old.pop('grouping_ledger'), 'LI2GROUPED-LEDGER-1')
                self.assertEqual(compact, old)
                self.assertEqual(compact['requested'], 3)
        self.assertEqual(base.parse(base.fixture())['status'], 'PASS')

    def test_table_binding_replay_member_and_bundle_pins_must_all_agree(self):
        for member in ('read-chunks.tsv', 'ledger-verification.tsv', 'bundle-index.tsv'):
            record = fixture(); record[1][member] += b'x\n'
            with self.subTest(member=member), self.assertRaises(AssertionError): parse(record)
        record = fixture(); record[1]['read-chunks.tsv'] += b'x\n'; repin(record)
        with self.assertRaises(AssertionError): parse(record)
        record = fixture()
        raw = record[1]['ledger-verification.tsv']
        changed = raw.replace(b'wire\tchecked\n', b'wire\tunavailable\n')
        self.assertNotEqual(changed, raw)
        record[1]['ledger-verification.tsv'] = changed; repin(record)
        with self.assertRaises(AssertionError): parse(record)
        record = fixture()
        raw = record[1]['bundle-index.tsv']
        pin = record[0]['files']['read-chunks.tsv']['sha256'].encode()
        changed = raw.replace(pin, b'0'*64)
        self.assertNotEqual(changed, raw)
        record[1]['bundle-index.tsv'] = changed; repin(record)
        with self.assertRaises(AssertionError): parse(record)

    def test_storage_version_scope_and_unrecorded_verification_never_pass(self):
        record = fixture()
        with self.assertRaises(AssertionError): parse(record, storage='inline')
        with self.assertRaises(AssertionError): parse(record, storage='read-chunks512-v1')
        for key, value in [('grouping_ledger', 'LI2GROUPED-LEDGER-1'),
                           ('ledger_wire_verification', 'unavailable'),
                           ('ledger_current_read_verification', 'unchecked'),
                           ('ledger_bootstrap', 'admitted')]:
            record = fixture(); record[0]['fields'][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError): parse(record)

    def test_repinned_current_read_census_and_source_membership_stay_strict(self):
        record = fixture()
        raw = record[1]['ledger-verification.tsv']
        self.assertIn(b'reads\t2\n', raw)
        record[1]['ledger-verification.tsv'] = raw.replace(b'reads\t2\n', b'reads\t1\n')
        repin(record)
        with self.assertRaises(AssertionError): parse(record)
        record = fixture()
        base.replace(record, 'disassembly.txt', b'head 4097 0f1f00\n', b'')
        base.replace(record, 'plan-ledger.tsv', b'route\t0\t4097\t65580\n', b'')
        base.replace(record, 'plan-ledger.tsv', b'restored-boundary\t0\t4097\t65580\n', b'')
        with self.assertRaises(AssertionError): parse(record)


if __name__ == '__main__':
    unittest.main()
