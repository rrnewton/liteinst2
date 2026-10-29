#!/usr/bin/env python3
"""Fabricated transcript/authority controls; never invokes a native subject."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def sibling(name):
    spec = importlib.util.spec_from_file_location('csv_control_' + name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = sibling('csv_native')
R = sibling('reproduce')


def fixture():
    rows = []
    for seed in C.SEEDS:
        for i, (length, value) in enumerate(zip(C.LENGTHS, C.VALUES)):
            rows.append(dict(zip(C.HEADER.split(','), (
                seed, i+1, length, 'PASS', 2, 30, 3, 3, 30, 31, value, value, 2*value,
                4, 4, 3, 3, 2, 2, 1, 4, 4, 2, 2))))
    coverage = [dict(zip(C.COVERAGE.split(','), (seed, 16, 3, 5, 2, 4, 1, 1))) for seed in C.SEEDS]
    return rows, coverage


def encode(rows, coverage):
    def table(header, rows):
        return (header+'\n'+''.join(','.join(str(r[n]) for n in header.split(','))+'\n' for r in rows)).encode()
    return (table(C.HEADER, rows), table(C.COVERAGE, coverage),
            (C.terminal(sum(r['comparisons'] for r in rows))+'\n').encode(), b'', 8)


class Controls(unittest.TestCase):
    def refuses(self, rows, covered):
        with self.assertRaises(AssertionError):
            C.check(*encode(rows, covered))

    def test_complete_population_and_descriptive_coverage(self):
        rows, coverage = fixture()
        args = encode(rows, coverage); got = C.check(*args)
        self.assertEqual(got['rows'], rows)
        self.assertEqual(got['coverage'], coverage)
        self.assertEqual((got['pairs_table'], got['coverage_table'], got['terminal']), args[:3])
        self.assertEqual((got['pairs'], got['normal_reaps'], got['target_calls'], got['comparisons']), (32, 64, 128, 960))
        self.assertLess(coverage[0]['observed_heads'], coverage[0]['declared_heads'])
        # Both declared returns, while head/edge coverage remains descriptive.
        for i, row in enumerate(rows):
            row['declared_returns'] = 2
            row['ret_offset0'] = row['ret_offset1'] = 3 + i % 2
        for c in coverage:
            c.update(declared_returns=2, observed_returns=2, observed_heads=4, observed_edges=3)
        self.assertEqual(C.check(*encode(rows, coverage))['coverage'], coverage)

    def test_framing_canonical_domains_and_exact_order(self):
        rows, coverage = fixture(); args = list(encode(rows, coverage))
        for index, data in ((0, args[0][:-1]), (0, args[0]+b'\n'), (1, args[1]+args[1].splitlines(keepends=True)[1]),
                            (2, args[2]+b'\n'), (3, b'warning\n'), (0, args[0].replace(b'PASS', b'pass', 1)),
                            (0, args[0].replace(b',PASS,', b',"PASS",', 1)), (0, b'x'*32769), (1, b'x'*1025)):
            bad = args.copy(); bad[index] = data
            with self.assertRaises(AssertionError): C.check(*bad)
        for value in ('00', '+1', '-1', ' 1', '1.0', str(1 << 64), '1'*100):
            bad = copy.deepcopy(rows); bad[0]['children'] = value
            self.refuses(bad, coverage)
        bad = copy.deepcopy(rows); bad[0], bad[1] = bad[1], bad[0]
        self.refuses(bad, coverage)
        self.refuses(rows, list(reversed(coverage)))
        for extent in (True, 4, 257):
            bad = args.copy(); bad[4] = extent
            with self.assertRaises(AssertionError): C.check(*bad)

    def test_scalar_values_lengths_and_two_call_conservation(self):
        rows, coverage = fixture()
        for key in ('length', 'value0', 'value1', 'outer_value', 'children', 'target_calls',
                    'target_returns', 'outer_returns', 'normal_reaps'):
            bad = copy.deepcopy(rows); bad[0][key] += 1
            self.refuses(bad, coverage)
        bad = copy.deepcopy(rows)
        for key in ('value0', 'value1', 'outer_value'):
            bad[0][key], bad[2][key] = bad[2][key], bad[0][key]
        self.assertEqual(sum(r['value0'] for r in rows), sum(r['value0'] for r in bad))
        self.refuses(bad, coverage)

    def test_comparison_step_and_terminal_conservation(self):
        rows, coverage = fixture()
        for key, value in (('comparisons', 31), ('visits0', 0), ('original_steps', 29),
                           ('candidate_steps', 20001), ('heads1', 2), ('edges0', 1)):
            bad = copy.deepcopy(rows); bad[0][key] = value
            self.refuses(bad, coverage)
        for r in rows: r['original_steps'] = r['candidate_steps'] = 20000
        self.assertEqual(C.check(*encode(rows, coverage))['comparisons'], 960)
        args = list(encode(rows, coverage))
        for source, target in ((b'comparisons=960', b'comparisons=959'), (b'normal-reaps=64', b'normal-reaps=63'),
                               (b'children=64', b'children=32'), (b'complete', b'incomplete')):
            bad = args.copy(); bad[2] = bad[2].replace(source, target)
            with self.assertRaises(AssertionError): C.check(*bad)

    def test_ret_union_geometry_and_partial_tables(self):
        rows, coverage = fixture()
        for key, value in (('ret_offset0', 0), ('ret_offset1', 8), ('declared_returns', 2)):
            bad = copy.deepcopy(rows); bad[0][key] = value
            self.refuses(bad, coverage)
        for key in ('cases', 'observed_returns', 'declared_returns', 'declared_heads', 'declared_edges'):
            bad = copy.deepcopy(coverage); bad[1][key] += 1
            self.refuses(rows, bad)
        bad = copy.deepcopy(rows)
        for r in bad[16:]: r['ret_offset0'] = r['ret_offset1'] = 5
        self.refuses(bad, coverage)
        bad = copy.deepcopy(coverage); bad[0]['observed_heads'] = 2
        self.refuses(rows, bad)
        self.refuses(rows[:-1], coverage)
        self.refuses(rows, coverage[:1])

    def test_source_local_import_and_optimization_refusal(self):
        self.assertEqual(Path(C.__file__).resolve(), HERE/'csv_native.py')
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            (cwd/'csv_native.py').write_text('raise RuntimeError("ambient import")\n')
            env = dict(os.environ, PYTHONPATH=str(cwd), PYTHONDONTWRITEBYTECODE='1')
            code = ('import importlib.util,pathlib; p=pathlib.Path('+repr(str(HERE/'controls.py'))+'); '
                    's=importlib.util.spec_from_file_location("owned_controls",p); '
                    'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                    'assert pathlib.Path(m.C.__file__).resolve()==p.parent/"csv_native.py"')
            done = subprocess.run([sys.executable, '-B', '-c', code], cwd=cwd, env=env,
                                  capture_output=True, timeout=10)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b'', b''))
            for name in ('csv_native.py', 'reproduce.py', 'controls.py'):
                done = subprocess.run([sys.executable, '-B', '-O', str(HERE/name)], cwd=cwd,
                                      env=env, capture_output=True, timeout=10)
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(done.stdout, b'')
                self.assertEqual(done.stderr, b'assertions required\n')
            self.assertFalse((cwd/'__pycache__').exists())

    def test_cargo_profile_symbol_and_request_authority(self):
        product = dict(reason='compiler-artifact', manifest_path=str(R.ROOT/'tools/rapid-profiler/Cargo.toml'),
            target=dict(name='frontend-native-oracle', src_path=str(R.ROOT/'tools/rapid-profiler/native-interval/main.rs'), kind=['bin'], crate_types=['bin']),
            profile=dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True), fresh=True,
            executable=str(R.ROOT/'target/release/frontend-native-oracle'))
        def messages(p): return b'\n'.join(json.dumps(x).encode() for x in (p, dict(reason='build-finished', success=True)))
        with patch.object(Path, 'resolve', lambda p, **kw: p):
            self.assertEqual(R.artifact(messages(product), 'frontend-native-oracle', 'native-interval/main.rs', 'bin', False)[1], product)
            for key, value in (('opt_level', '0'), ('debug_assertions', False), ('overflow_checks', False), ('debuginfo', False)):
                bad = copy.deepcopy(product); bad['profile'][key] = value
                with self.assertRaises(AssertionError): R.artifact(messages(bad), 'frontend-native-oracle', 'native-interval/main.rs', 'bin', False)
        sym = b' 1: 0000000000001000 96 FUNC GLOBAL DEFAULT 5 csv_fields\n 2: 0000000000001000 96 FUNC GLOBAL DEFAULT 5 csv_fields\n'
        self.assertEqual(R.selection(sym), (4096, 96))
        for bad in (sym.replace(b'96', b'4'), sym.replace(b'DEFAULT 5', b'DEFAULT UND'), sym.replace(b'96', b'97', 1), sym+sym):
            with self.assertRaises(AssertionError): R.selection(bad)
        raw = R.ROOT/'ignored'/'fabricated-request'
        argv = [str(R.ROOT/'target/release/frontend-native-oracle'), 'normal-csv-state', str(raw/'csv-candidate.so'), str(raw/'csv-trusted.so'),
                '4096', '96', str(raw/'caller-candidate.so'), str(raw/'caller-trusted.so'), str(raw/'native-output')]
        req = dict(argv=argv, cwd=str(R.ROOT), env={}, stdout=str(raw/'stdout.txt'), stderr=str(raw/'stderr.txt'),
                   pins={p: {} for p in (str(HERE/'reproduce.py'), argv[0], *argv[2:4], *argv[6:8])})
        with patch.object(Path, 'resolve', lambda p, **kw: p), patch.object(Path, 'exists', return_value=False):
            self.assertEqual(R.request_shape(req), raw)
            for index, value in ((1, 'normal-state'), (5, '096'), (4, str(1 << 64)), (8, str(raw/'other-output'))):
                bad = copy.deepcopy(req); bad['argv'][index] = value
                with self.assertRaises(AssertionError): R.request_shape(bad)

    def test_closure_and_changed_pin_refuse_printed_success(self):
        closed = dict(exit_code=0, termination=None, cleanup_complete=True, reaped_descendants=0)
        R.closed_ok(closed)
        for key, value in (('exit_code', 1), ('exit_code', -9), ('termination', 'timeout'),
                           ('cleanup_complete', False), ('reaped_descendants', 1)):
            bad = dict(closed, **{key: value})
            with self.assertRaises(AssertionError): R.closed_ok(bad)
        pin = dict(bytes=1, sha256='0'*64)
        with patch.object(R, 'digest', return_value=pin): R.pins_ok({'/fixed': pin})
        with patch.object(R, 'digest', return_value=dict(bytes=1, sha256='1'*64)):
            with self.assertRaises(AssertionError): R.pins_ok({'/fixed': pin})
        # A complete transcript has no power to override the actual closed exit.
        self.assertEqual(C.check(*encode(*fixture()))['pairs'], 32)
        with self.assertRaises(AssertionError): R.closed_ok(dict(closed, exit_code=1))
        expected = {'fixture::plain': False, 'fixture::refuses': True}
        transcript = ('\nrunning 3 tests\ntest fixture::plain ... ok\n'
            'test fixture::refuses - should panic ... ok\n'
            f'test {R.IGNORED} ... ignored, {R.IGNORE_REASON}\n\n'
            'test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n').encode()
        R.calibration_output(transcript, b'', expected)
        for old, new in ((b' - should panic', b''), (b'fixture::plain', b'fixture::other'), (b'0 failed', b'1 failed')):
            with self.assertRaises(AssertionError): R.calibration_output(transcript.replace(old, new), b'', expected)
        output = ''.join(f'{n} (__main__.Controls.{n}) ... ok\n' for n in sorted(R.PYTHON_CONTROLS))
        output += '\n----------------------------------------------------------------------\nRan 9 tests in 0.01s\n\nOK\n'
        R.python_output(b'', output.encode())
        with self.assertRaises(AssertionError): R.python_output(b'', output.replace('Ran 9', 'Ran 8').encode())
        # Exercise the same insert-once/final-publication path used by main().
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pins = {}
            names = ('plan.json', 'state-controls/stdout.txt', 'native-build/stdout.txt',
                     'native-build/receipt.json', 'native-build/request.json',
                     'native-build/command.json', 'native-build/state-before.json',
                     'native-build/closed.json', 'owner/native-build.log',
                     'native-build/parent.log', 'request.json', 'native-command.json',
                     'native-attempt.json', 'native-closed.json', 'owner/native.log',
                     'native-parent.log', 'native-output/normal-csv-pairs.csv')
            for name in names:
                p = root/name; p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'original\n'); R.retain(pins, p)
            original = copy.deepcopy(pins)
            def success():
                return dict(status='NATIVE_STATE_PASS', native=dict(status='NATIVE_STATE_PASS', attempts=1))
            result = success(); R.final_retention(result, pins, True)
            self.assertEqual(result['retained'], original)
            self.assertTrue(result['retention_verified'])
            self.assertEqual(result['status'], 'NATIVE_STATE_PASS')
            for name in names:
                p = root/name; p.write_bytes(b'altered!\n')  # Same length, different bytes.
                with self.assertRaises(AssertionError): R.retain(pins, p)
                result = success(); R.final_retention(result, pins, True)
                self.assertEqual((result['status'], result['native']['status']), ('FAILED', 'FAILED'))
                self.assertTrue(result['retention_error'])
                self.assertFalse(result['retention_verified'])
                self.assertEqual((pins, result['retained']), (original, original))
                with self.assertRaises(AssertionError): R.once(result['native'], lambda: self.fail('retry'))
                p.write_bytes(b'original\n')
            p = root/'native-closed.json'; p.unlink()
            result = success(); R.final_retention(result, pins, True)
            self.assertEqual(result['status'], 'FAILED')
            self.assertEqual((pins, result['retained']), (original, original))
            self.assertFalse(result['retention_verified'])
            # Uncertain custody exports the old expected pins without file reads.
            result = dict(status='FAILED', native=dict(status='FAILED', attempts=1))
            with patch.object(R, 'digest', side_effect=RuntimeError('must not read')):
                R.final_retention(result, pins, False)
            self.assertEqual(result['retained'], original)
            self.assertFalse(result['custody_closed'])
            self.assertFalse(result['retention_verified'])

    def test_once_only_native_failure_and_unrun_prerequisites(self):
        row = dict(status='UNRUN', attempts=0); called = []
        self.assertEqual(row, dict(status='UNRUN', attempts=0))
        def failed():
            called.append(1)
            return dict(exit_code=1, termination=None, cleanup_complete=True, reaped_descendants=0)
        R.once(row, failed)
        self.assertEqual((row['status'], row['attempts'], row['closed']['exit_code']), ('FAILED', 1, 1))
        with self.assertRaises(AssertionError): R.once(row, failed)
        self.assertEqual(called, [1])
        row = dict(status='UNRUN', attempts=0)
        def interrupted(): raise RuntimeError('no closure')
        with self.assertRaises(RuntimeError): R.once(row, interrupted)
        self.assertEqual(row, dict(status='FAILED', attempts=1))


if __name__ == '__main__':
    unittest.main()
