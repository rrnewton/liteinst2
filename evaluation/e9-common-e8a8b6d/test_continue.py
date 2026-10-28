#!/usr/bin/env python3
"""Synthetic schema controls only: no module main, provider or native execution."""
import argparse
import ast
import copy
import hashlib
from pathlib import Path
import types
import unittest


def functions(path, names):
    tree = ast.parse(path.read_bytes(), filename=str(path))
    selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in selected} == set(names)
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


class ContinuationControls(unittest.TestCase):
    def setUp(self):
        self.files = {}
        self.root = Path('/synthetic')
        self.ns = functions(Path(__file__).with_name('continue_null.py'), ('plan', 'closed', 'complete'))
        self.ns.update(CELLS=('null-heap-write-unstripped', 'null-heap-write-stripped', 'null-jump-site-unstripped', 'null-jump-site-stripped'), LANES=('stock-algorithm', 'bootstrap-patched-reference'))
        self.ns['B'] = types.SimpleNamespace(fields=functions(REPRODUCER, ('fields',))['fields'], read=lambda p: (self.files[p], None))

    def wire(self, path, header, values):
        self.files[path] = (header + '\n' + ''.join(k + '\t' + str(v) + '\n' for k, v in values.items())).encode()

    def fixture(self, expanded):
        self.wire(self.root / 'complete.tsv', 'LI2COMMONE9PAIRS\t1', dict(heads=87, normal_pairs=174, fault_pairs=2, children=352, comparisons=528,
            call_intermediate_checks=len(expanded), snapshots=880+len(expanded), files=8637+9*len(expanded), recording_hooks='UNIMPLEMENTED_UNRUN', normal_loader_validation='false', qualification_complete='false'))
        for i in range(176):
            directory = self.root / ('case-%03d' % i)
            self.wire(directory / 'pair.tsv', 'LI2E9PAIR\t1', dict(case=i, comparisons=3, children=2, call_intermediate_checks=int(i in expanded), normal_loader_validation='false', qualification_complete='false'))
            self.wire(directory / 'candidate/complete.tsv', 'LI2E9PAIRCHILD\t1', dict(case=i, steps=20000, physical_completion='0x1', logical_completion='0x2', fault='none', comparisons=3, call_intermediate_checks=int(i in expanded), reaped_echild='true', qualification_complete='false'))

    def test_exact_eight_cells_sixteen_stages(self):
        stages, cells = self.ns['plan']()
        self.assertEqual(len(cells), 8); self.assertEqual(len(stages), 16)
        self.assertEqual(stages, ['native-'+lane+'-'+cell+'-'+part for cell in self.ns['CELLS'] for lane in self.ns['LANES'] for part in ('witness', 'replay')])

    def test_parent_failure_refusals(self):
        row = dict(start_utc='2026-01-01T00:00:00+00:00', exit_code=0, termination=None, seconds=1, private_log_sha256='0'*64, cleanup_complete=True, reaped_descendants=0, child_discovery_strategy='proc_children')
        self.ns['closed'](row)
        for key, value in [('exit_code',1), ('exit_code',False), ('termination','wall'), ('cleanup_complete',False), ('reaped_descendants',1)]:
            changed = dict(row, **{key:value})
            with self.subTest(key=key, value=value), self.assertRaises(AssertionError): self.ns['closed'](changed)

    def test_complete_zero_and_twelve_call_intermediates(self):
        for expanded in ([], list(range(12))):
            self.fixture(expanded)
            self.assertEqual(self.ns['complete'](self.root, expanded), dict(pairs=176, children=352, comparisons=528))

    def test_exact_null_schema_and_population_refusals(self):
        self.fixture([]); original = copy.deepcopy(self.files)
        mutations = [('complete.tsv', b'files\t8637', b'files\t8636'), ('complete.tsv', b'snapshots\t880', b'snapshots\t881'),
            ('complete.tsv', b'LI2COMMONE9PAIRS', b'LI2COMMONE9RECORDINGPAIRS'), ('complete.tsv', b'recording_hooks\tUNIMPLEMENTED_UNRUN', b'E9\tUNIMPLEMENTED_UNRUN'),
            ('complete.tsv', b'qualification_complete\tfalse\n', b'qualification_complete\tfalse\nE9\tUNIMPLEMENTED_UNRUN\n'),
            ('complete.tsv', b'qualification_complete\tfalse\n', b'qualification_complete\tfalse\nrecording_profile\tbounded-journal-v1\n'),
            ('case-000/pair.tsv', b'comparisons\t3', b'comparisons\t2'), ('case-175/pair.tsv', b'case\t175', b'case\t174'),
            ('case-000/candidate/complete.tsv', b'steps\t20000', b'steps\t20001'), ('case-000/candidate/complete.tsv', b'reaped_echild\ttrue', b'reaped_echild\tfalse'),
            ('case-000/candidate/complete.tsv', b'call_intermediate_checks\t0', b'call_intermediate_checks\t1')]
        for name, before, after in mutations:
            self.files = dict(original); path = self.root / name; assert self.files[path].count(before) == 1
            self.files[path] = self.files[path].replace(before, after)
            with self.subTest(name=name, after=after), self.assertRaises(AssertionError): self.ns['complete'](self.root, [])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--reproducer', type=Path, required=True)
    args, remaining = parser.parse_known_args(); REPRODUCER = args.reproducer
    assert hashlib.sha256(REPRODUCER.read_bytes()).hexdigest() == '3ef4a5cd1a4c625c95aacc2d80adba750056ab686472a2508cf27a681dd72e78'
    unittest.main(argv=[__file__, *remaining])
