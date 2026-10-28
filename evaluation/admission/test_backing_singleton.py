#!/usr/bin/env python3
"""Fabricated cleanup protocol controls; no Cargo, provider or native execution."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import ast
import json
from pathlib import Path
import re
import unittest

REPO = Path('/fixture')
HEADER = '     Running tests/exec_backing_cleanup.rs (target/debug/deps/exec_backing_cleanup-0123456789abcdef)'
PREFIX = 'LITEINST_BACKING_CLEANUP_V1 '
# Independent current-harness fixture: never derive it from the parser's EXPECTED.
FIXTURE = '''{"schema_version":1,"kind":"begin","controls":5,"trajectories":6}
{"schema_version":1,"kind":"trajectory","index":0,"id":"complete","control":"admitted_exec_native_backing_probes_close_exact_owned_resources","outcome":"complete","probes":6,"errno":0,"terminal":"exit0","owner_cleanup":true,"physical_cleanup":true,"receipt_authenticated":true}
{"schema_version":1,"kind":"trajectory","index":1,"id":"read_error","control":"admitted_exec_native_backing_read_and_unwind_preserve_cleanup","outcome":"native_read_error","probes":1,"errno":14,"terminal":"exit0","owner_cleanup":true,"physical_cleanup":true,"receipt_authenticated":true}
{"schema_version":1,"kind":"trajectory","index":2,"id":"unwind","control":"admitted_exec_native_backing_read_and_unwind_preserve_cleanup","outcome":"injected_unwind","probes":1,"errno":0,"terminal":"exit0","owner_cleanup":true,"physical_cleanup":true,"receipt_authenticated":true}
{"schema_version":1,"kind":"trajectory","index":3,"id":"invalid_unmap","control":"exec_backing_native_invalid_unmap_aborts_isolated_owner","outcome":"expected_fail_stop","probes":1,"errno":22,"terminal":"sigabrt","owner_cleanup":false,"physical_cleanup":true,"receipt_authenticated":true}
{"schema_version":1,"kind":"trajectory","index":4,"id":"query_error","control":"admitted_exec_native_backing_query_preserves_cleanup","outcome":"native_query_error","probes":1,"errno":14,"terminal":"exit0","owner_cleanup":true,"physical_cleanup":true,"receipt_authenticated":true}
{"schema_version":1,"kind":"trajectory","index":5,"id":"legacy","control":"admitted_exec_native_backing_enotty_uses_exact_legacy_projection","outcome":"native_enotty_fallback","probes":6,"errno":0,"terminal":"exit0","owner_cleanup":true,"physical_cleanup":true,"receipt_authenticated":true}
{"schema_version":1,"kind":"complete","controls":5,"trajectories":6,"physical_cleanup":true}'''


def load(path):
    constants = {'MIB', 'PREFIX', 'CONTROL', 'ROLES', 'EXPECTED'}
    functions = {'object_', 'protocol'}
    tree = ast.parse(path.read_text())
    nodes = [n for n in tree.body if
        isinstance(n, ast.FunctionDef) and n.name in functions or
        isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id in constants]
    assert len(nodes) == len(constants)+len(functions)
    namespace = dict(json=json, re=re)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['protocol']


def records():
    return [json.loads(line) for line in FIXTURE.splitlines()]


def encoded(rows=None, header=HEADER):
    rows = records() if rows is None else rows
    body = '\n'.join(PREFIX+json.dumps(row, separators=(',', ':')) for row in rows)
    return ('    Finished `test` profile [unoptimized] target(s) in 0.01s\n'+header+'\n'+body+'\n').encode('ascii')


class BackingProtocol(unittest.TestCase):
    def refuse(self, data):
        with self.assertRaises((AssertionError, ValueError)):
            PROTOCOL(data, REPO)

    def test_exact_eight_records_accept_relative_and_owned_absolute_header(self):
        self.assertEqual(len(records()), 8)
        for header in (HEADER, HEADER.replace('(target/', '(/fixture/target/')):
            self.assertIsNone(PROTOCOL(encoded(header=header), REPO))

    def test_missing_duplicate_reordered_trailing_and_partial_records_refuse(self):
        for i in range(8):
            rows = records(); rows.pop(i)
            with self.subTest(missing=i): self.refuse(encoded(rows))
            rows = records(); rows.insert(i, rows[i])
            with self.subTest(duplicate=i): self.refuse(encoded(rows))
        rows = records(); rows[1], rows[2] = rows[2], rows[1]; self.refuse(encoded(rows))
        rows = records(); rows[0]['controls'] = rows[-1]['controls'] = 3
        rows[0]['trajectories'] = rows[-1]['trajectories'] = 4; self.refuse(encoded(rows[:5]+rows[-1:]))
        for bad in (encoded()+b'FAILED after completion\n', encoded()[:-1], encoded().replace(b'\n', b'\r\n'),
                encoded().replace(b'"kind":"complete"', b'"kind":'), encoded().replace(PREFIX.encode(), b'WRONG_PREFIX ', 1)):
            self.refuse(bad)

    def test_wrong_missing_duplicate_cargo_harness_and_unscoped_protocol_refuse(self):
        for header in ('', HEADER.replace('tests/exec_backing_cleanup.rs', 'tests/another.rs'),
                HEADER.replace('exec_backing_cleanup-0123', 'other_binary-0123'),
                HEADER.replace('(target/', '(/other/target/'), HEADER+'\n'+HEADER):
            with self.subTest(header=header): self.refuse(encoded(header=header))
        self.refuse((PREFIX+FIXTURE.splitlines()[0]+'\n').encode()+encoded())

    def test_exact_json_types_and_duplicate_keys_refuse(self):
        for i, row in enumerate(records()):
            for key, value in row.items():
                bad = [True, str(value), float(value)] if type(value) is int else [int(value), str(value)] if type(value) is bool else [1]
                for replacement in bad:
                    changed = records(); changed[i][key] = replacement
                    with self.subTest(row=i, key=key, replacement=replacement): self.refuse(encoded(changed))
            lines = encoded().decode().splitlines()
            lines[2+i] = lines[2+i].replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1)
            self.refuse(('\n'.join(lines)+'\n').encode())

    def test_probe_errno_control_identity_and_cleanup_claims_refuse(self):
        for i in range(1, 7):
            for key, value in (('probes', 99), ('errno', 99), ('control', 'different_control'),
                    ('id', 'different_role'), ('index', 99), ('outcome', 'different_outcome'),
                    ('terminal', 'exit1'), ('physical_cleanup', False), ('receipt_authenticated', False)):
                rows = records(); rows[i][key] = value
                with self.subTest(row=i, key=key): self.refuse(encoded(rows))
        rows = records(); rows[4]['owner_cleanup'] = True; self.refuse(encoded(rows))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', type=Path, required=True)
    args = parser.parse_args(); PROTOCOL = load(args.runner)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
