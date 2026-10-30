#!/usr/bin/env python3
"""Fault-injection tests for runner receipts, using a stub command owner.

These tests execute no Git, planner, tracee, or native stage. They check the
runner's failure handling; process ownership and native equivalence are separate.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'evaluation/adjacent-b2/native.py'
REVISION = 'a' * 40


class RunnerReceipts(unittest.TestCase):
    def campaign(self, fault=None):
        spec = importlib.util.spec_from_file_location('tested_adjacent_runner', SCRIPT)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory(prefix='adjacent-runner-', dir=ROOT / 'ignored') as name:
            root = Path(name)
            source = root / 'evaluation/adjacent-b2/native.py'
            source.parent.mkdir(parents=True)
            source.write_bytes(SCRIPT.read_bytes())
            helper = root / 'evaluation/admission/processes.py'
            helper.parent.mkdir(parents=True)
            helper.write_bytes((ROOT / 'evaluation/admission/processes.py').read_bytes())
            binary = root / 'target/debug/examples/adjacent_b2_native'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'unit-test stub; never executed')
            out = root / 'ignored/campaign'
            out.parent.mkdir()
            runner.__file__ = str(source)
            calls = []
            load_calls = []
            owner_returned = []
            observed_reads = []
            real_read_text = Path.read_text
            real_read_bytes = Path.read_bytes
            real_open = Path.open

            def read_text(path, *args, **kwargs):
                if str(path) == '/proc/loadavg':
                    load_calls.append(True)
                    if fault in ('load-after-return', 'uncertain-and-load') and len(load_calls) == 7:
                        raise OSError('injected post-command load failure')
                    return '1.00 2.00 3.00 1/1 1\n'
                return real_read_text(path, *args, **kwargs)

            def read_bytes(path):
                if owner_returned and owner_returned[-1] == 'uncertain':
                    observed_reads.append(str(path))
                return real_read_bytes(path)

            def open_path(path, mode='r', *args, **kwargs):
                if owner_returned and owner_returned[-1] == 'uncertain' and ('r' in mode or '+' in mode):
                    observed_reads.append(str(path))
                return real_open(path, mode, *args, **kwargs)

            def command(argv, _env, log, _limit, _cap):
                calls.append(list(argv))
                stage = argv[1]
                native = argv[0] != 'git'
                first_stage = native and stage == 'target'
                if first_stage and fault == 'owner-exception':
                    owner_returned.append('uncertain')
                    raise OSError('injected absent owner receipt')
                if not native:
                    raw = (REVISION + '\n').encode() if stage == 'rev-parse' else b''
                    if fault == 'revision-change' and stage == 'rev-parse' and len(calls) == 4:
                        raw = (('b' * 40) + '\n').encode()
                    if fault == 'final-guard' and stage == 'rev-parse' and len(calls) == 16:
                        raw = (('b' * 40) + '\n').encode()
                else:
                    destination = Path(argv[-1])
                    destination.mkdir()
                    binding = b'unit-test-only closed binding\n'
                    (destination / 'binding.tsv').write_bytes(binding)
                    raw = (hashlib.sha256(binding).hexdigest() + '\n').encode()
                    if first_stage and fault == 'bad-transcript':
                        raw = b'invalid hash transcript\n'
                    if first_stage and fault == 'binding-mismatch':
                        (destination / 'binding.tsv').write_bytes(b'different binding\n')
                    if first_stage and fault == 'binary-change':
                        binary.write_bytes(b'replaced test stub; never executed')
                log.write_bytes(raw)
                uncertain = first_stage and fault in ('uncertain', 'uncertain-and-load')
                owner_returned.append('uncertain' if uncertain else 'closed')
                return dict(exit_code=17 if native and stage == 'produce' and fault == 'stage-exit' else 0,
                            termination=None, cleanup_complete=not uncertain,
                            reaped_descendants=0, private_log_sha256=hashlib.sha256(raw).hexdigest())

            owner = SimpleNamespace(run_command=command)
            fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
            argv = [str(source), '--revision', REVISION, '--output', str(out), '--profile', 'debug']
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.object(runner.importlib.util, 'spec_from_file_location', return_value=fake_spec), \
                     patch.object(runner.importlib.util, 'module_from_spec', return_value=owner), \
                     patch.object(sys, 'argv', argv), patch.object(Path, 'read_text', read_text), \
                     patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'open', open_path), \
                     patch('builtins.print'):
                    with self.assertRaises(SystemExit) as stopped:
                        runner.main()
            finally:
                os.chdir(previous)
            terminals = [name for name in ('aborted.json', 'closed.json') if (out / name).exists()]
            self.assertEqual(len(terminals), 1, 'exactly one terminal receipt')
            terminal = terminals[0]
            expected_terminal = ('aborted.json' if fault in
                                 ('uncertain', 'uncertain-and-load', 'owner-exception') else 'closed.json')
            self.assertEqual(terminal, expected_terminal)
            result = json.loads((out / terminal).read_text())
            self.assertEqual(result['status'], 'passed' if fault is None else 'failed')
            self.assertEqual(result['cleanup_complete'], terminal == 'closed.json')
            self.assertFalse(result['qualification_complete'])
            receipts = {path.stem: json.loads(path.read_text()) for path in out.glob('*-receipt.json')}
            return result, receipts, calls, stopped.exception.code, terminal, observed_reads, len(load_calls)

    def test_complete_fixed_campaign(self):
        result, receipts, calls, code, terminal, _, _ = self.campaign()
        self.assertEqual((code, terminal, result['status'], result['unrun_stages']), (0, 'closed.json', 'passed', []))
        self.assertEqual(len(calls), 17)  # Five stages plus six two-command guards.
        self.assertEqual(len(receipts), 17)
        self.assertEqual([row['name'] for row in result['results']], ['target', 'produce', 'verify', 'controls', 'run'])
        self.assertFalse(result['qualification_complete'])

    def test_protocol_failure_retains_returned_outcome(self):
        for fault in ('bad-transcript', 'binding-mismatch', 'load-after-return'):
            with self.subTest(fault=fault):
                result, receipts, calls, code, terminal, _, _ = self.campaign(fault)
                self.assertEqual((code, terminal, len(calls)), (1, 'closed.json', 3))
                self.assertEqual(result['unrun_stages'], ['produce', 'verify', 'controls', 'run'])
                self.assertEqual(receipts['target-receipt']['result']['exit_code'], 0)
                self.assertEqual(receipts['target-receipt']['status'], 'failed')

    def test_uncertain_custody_never_reads_or_claims_closure(self):
        for fault in ('uncertain', 'uncertain-and-load', 'owner-exception'):
            with self.subTest(fault=fault):
                result, receipts, calls, code, terminal, reads, loads = self.campaign(fault)
                self.assertEqual((code, terminal, len(calls)), (1, 'aborted.json', 3))
                self.assertFalse(result['cleanup_complete'])
                self.assertEqual(reads, [])
                self.assertEqual(loads, 6)  # No post-owner load observation.
                self.assertEqual(result['unrun_stages'], ['produce', 'verify', 'controls', 'run'])
                outcome = receipts['target-receipt']['result']
                if fault == 'owner-exception':
                    self.assertIsNone(outcome)
                else:
                    self.assertFalse(outcome['cleanup_complete'])

    def test_stage_exit_blocks_all_dependent_consumers(self):
        result, receipts, calls, code, _, _, _ = self.campaign('stage-exit')
        self.assertEqual((code, len(calls)), (1, 6))
        self.assertEqual(result['unrun_stages'], ['verify', 'controls', 'run'])
        self.assertEqual(receipts['produce-receipt']['result']['exit_code'], 17)

    def test_observed_identity_change_blocks_next_stage(self):
        for fault in ('binary-change', 'revision-change'):
            with self.subTest(fault=fault):
                result, _, calls, code, _, _, _ = self.campaign(fault)
                self.assertEqual(code, 1)
                self.assertEqual([command[1] for command in calls if command[0] != 'git'], ['target'])
                self.assertEqual(result['unrun_stages'], ['produce', 'verify', 'controls', 'run'])

    def test_final_identity_failure_is_not_a_success(self):
        result, _, calls, code, _, _, _ = self.campaign('final-guard')
        self.assertEqual((code, len(calls)), (1, 16))
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['unrun_stages'], [])
        self.assertEqual(len(result['results']), 5)


if __name__ == '__main__':
    unittest.main()
