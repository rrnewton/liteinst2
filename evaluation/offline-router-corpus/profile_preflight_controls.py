"""Prospective pure controls; optional argv[1] selects the integrated script.

No native launcher or session callback is dispatched. All real preflight dependencies are
inert test doubles; the actual profiler/output/authentication code is exercised.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import sys

source = (Path(sys.argv.pop(1)) if len(sys.argv) > 1 else
          Path(__file__).with_name('profile_preflight.py'))
spec = importlib.util.spec_from_file_location('profile_preflight_under_test', source)
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'ignored').mkdir()
        self.calls = []
        self.fail = set()
        self.wire = dict(path=str(self.root / 'ignored/wire'), bytes=4,
                         sha256=P.sha(b'wire'), stat=[1, 2, 3, 4, 5, 6])
        self.work = dict(schema='LI2NATIVE-OBSERVE-CHILD-1', program='checksum',
                         main={'copy': True}, dataset={'empty': True}, wire=self.wire)
        self.args = types.SimpleNamespace(root=self.root,
            final_profile=self.root / 'ignored/profile.json', final_profile_sha256='1' * 64,
            accept_contract_sha256='2' * 64, child_request=self.root / 'ignored/child.json',
            child_request_sha256='', output=self.root / 'ignored/output')
        self.refresh()

    def refresh(self):
        self.raw = json.dumps(self.work).encode()
        self.args.child_request_sha256 = P.sha(self.raw)

    def step(self, name, result=None):
        def invoke(*_args):
            self.calls.append(name)
            if name in self.fail:
                raise RuntimeError(name)
            return result
        return invoke

    def launcher(self):
        session = types.SimpleNamespace(check_source=self.step('check_source', '3' * 64),
            bind_main_copy=self.step('bind_main_copy'), request=self.step('request', {'actual': True}),
            stable=self.step('session_stable'), close=self.step('close_session'))
        store = types.SimpleNamespace(close=self.step('close_build'))
        wire = types.SimpleNamespace(CAP=4096, encode=self.step('encode_request', b'wire'),
                                     sealed=self.step('FORBIDDEN_SEALED'))
        final = types.SimpleNamespace(no_capabilities=self.step('no_capabilities'))
        def read(path, _cap=P.MIB):
            if Path(path) == self.args.child_request:
                return self.raw, {'sha256': P.sha(self.raw)}
            self.calls.append('read_wire')
            return b'wire', self.wire
        return types.SimpleNamespace(NATIVE='evaluation/offline-router-native/',
            PROGRAMS=('checksum', 'rle-roundtrip'), need=P.need, sha=P.sha, decode=P.decode,
            open_session=self.step('open_session', (final, session)),
            source=self.step('load_wire', wire), read=read,
            observer_build=self.step('observer_build', (None, store, {'binary': True},
                                                       self.step('build_stable'))),
            child_signals=self.step('child_signals'))

    def run_profile(self, launch=None):
        with mock.patch.object(P, 'authenticate_launcher', return_value=(launch or self.launcher(), {})):
            code = P.run(self.args)
        report = json.loads((self.args.output / 'closed.json').read_bytes())
        for name in ('profile.pstats', 'profile.txt'):
            raw = (self.args.output / name).read_bytes()
            self.assertTrue(raw)
            self.assertEqual(report['files'][name], dict(bytes=len(raw), sha256=P.sha(raw)))
        self.assertFalse(report['memfd_created'])
        self.assertEqual(report['native_dispatches'], 0)
        self.assertFalse(report['qualification_complete'])
        self.assertFalse(report['performance_eligible'])
        self.assertNotIn('FORBIDDEN_SEALED', self.calls)
        return code, report

    def test_exact_read_only_sequence_closes_every_owner(self):
        code, report = self.run_profile()
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'DIAGNOSTIC_COMPLETE')
        self.assertEqual(self.calls, ['open_session', 'check_source', 'check_source', 'load_wire',
            'bind_main_copy', 'request', 'encode_request', 'read_wire', 'observer_build',
            'no_capabilities', 'build_stable', 'session_stable', 'child_signals',
            'close_build', 'close_session'])

    def test_capsule_digest_refuses_before_binding(self):
        self.args.child_request_sha256 = '0' * 64
        code, report = self.run_profile()
        self.assertEqual(code, 1)
        self.assertIn('exact prospective child request capsule', str(report['primary_error']))
        self.assertNotIn('bind_main_copy', self.calls)
        self.assertEqual(self.calls[-1], 'close_session')

    def test_coherent_extra_field_and_unknown_program_refuse(self):
        for key, value in [('extra', True), ('program', 'subset')]:
            with self.subTest(key=key):
                self.work[key] = value
                self.refresh()
                owners = []
                with self.assertRaisesRegex(ValueError, 'finite observer child schema'):
                    P.preflight(self.launcher(), self.args, lambda _name, fn: fn(), owners)
                self.assertNotIn('bind_main_copy', self.calls)
                for _name, owner in reversed(owners):
                    owner.close()
                self.work.pop('extra', None)

    def test_whole_wire_bytes_refuse_before_build(self):
        launch = self.launcher()
        original = launch.read
        launch.read = lambda path, cap=P.MIB: original(path, cap) if Path(path) == self.args.child_request else (b'bad!', self.wire)
        code, report = self.run_profile(launch)
        self.assertEqual(code, 1)
        self.assertIn('whole prospective Request reconstruction', str(report['primary_error']))
        self.assertNotIn('observer_build', self.calls)

    def test_primary_and_both_cleanup_errors_survive_with_stats(self):
        self.fail = {'build_stable', 'close_build', 'close_session'}
        code, report = self.run_profile()
        self.assertEqual(code, 1)
        self.assertEqual(report['primary_error'][0]['message'], 'build_stable')
        self.assertEqual([x['phase'] for x in report['cleanup_errors']], ['close_build', 'close_session'])
        self.assertFalse(report['preflight_complete'])

    def test_close_only_failure_is_not_complete(self):
        self.fail = {'close_session'}
        code, report = self.run_profile()
        self.assertEqual(code, 1)
        self.assertIsNone(report['primary_error'])
        self.assertFalse(report['preflight_complete'])
        self.assertEqual(report['cleanup_errors'][0]['phase'], 'close_session')

    def test_one_stats_write_failure_does_not_skip_other_diagnostics(self):
        original = P.Output.write
        def write(output, name, raw):
            if name == 'profile.pstats':
                raise OSError('injected pstats write failure')
            return original(output, name, raw)
        with mock.patch.object(P, 'authenticate_launcher', return_value=(self.launcher(), {})), \
                mock.patch.object(P.Output, 'write', write):
            self.assertEqual(P.run(self.args), 1)
        report = json.loads((self.args.output / 'closed.json').read_bytes())
        self.assertEqual(report['diagnostic_errors'][0]['file'], 'profile.pstats')
        self.assertTrue((self.args.output / 'profile.txt').read_bytes())
        self.assertFalse(report['preflight_complete'])

    def test_existing_output_is_never_reused(self):
        self.args.output.mkdir()
        sentinel = self.args.output / 'sentinel'
        sentinel.write_bytes(b'unchanged')
        with self.assertRaises(FileExistsError), mock.patch.object(P, 'authenticate_launcher') as loader:
            P.run(self.args)
        loader.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b'unchanged')

    def test_hashes_and_contract_checked_before_loading_exact_source_buffer(self):
        path = self.root / P.LAUNCHER
        path.parent.mkdir(parents=True)
        source = b'loaded_marker = 17\n'
        path.write_bytes(source)
        profile = dict(native_sources={P.LAUNCHER: P.sha(source)},
                       contract={'sha256': self.args.accept_contract_sha256})
        def save():
            raw = json.dumps(profile).encode()
            self.args.final_profile.write_bytes(raw)
            self.args.final_profile_sha256 = P.sha(raw)
        save()
        module, pins = P.authenticate_launcher(self.args)
        self.assertEqual(module.loaded_marker, 17)
        self.assertEqual(pins['launcher']['sha256'], P.sha(source))
        for mutant in ('profile', 'source', 'contract'):
            with self.subTest(mutant=mutant):
                save()
                if mutant == 'profile': self.args.final_profile_sha256 = '0' * 64
                elif mutant == 'source': profile['native_sources'][P.LAUNCHER] = '0' * 64; save()
                else: profile['native_sources'][P.LAUNCHER] = P.sha(source); profile['contract']['sha256'] = '0' * 64; save()
                with mock.patch('builtins.exec') as execute, self.assertRaises(ValueError):
                    P.authenticate_launcher(self.args)
                execute.assert_not_called()

    def test_duplicate_json_and_symlink_inputs_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            P.decode(b'{"x":1,"x":2}')
        target = self.root / 'ignored/target'
        target.write_bytes(b'input')
        link = self.root / 'ignored/link'
        link.symlink_to(target)
        with self.assertRaises(OSError):
            P.read(link)


if __name__ == '__main__':
    unittest.main()
