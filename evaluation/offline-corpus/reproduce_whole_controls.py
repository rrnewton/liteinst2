#!/usr/bin/env python3
"""Fabricated CLI/dispatch controls only; never run a capture, planner or child."""
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

if sys.flags.optimize:
    raise SystemExit('assertions required')
path = Path(__file__).resolve().with_name('reproduce_whole.py')
with path.open('rb') as stream:
    raw = stream.read(1048577)
assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == 'd9daa5018f2850bcca9199f48d7950aedb6d5c5e6c9fe8cab234ff2ecb0d62f0'
R = types.ModuleType('authenticated_whole_reproducer')
R.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), R.__dict__)


class WholeReproducerControls(unittest.TestCase):
    def test_fixed_cli_choices_and_unchanged_default(self):
        argv = ['--capture', '/synthetic-closed', '--capture-sha256', 'a' * 64,
                '--output', '/synthetic-new']
        default = R.arguments(argv)
        self.assertEqual(default.placement_profile, R.D.PROFILE)
        self.assertEqual(default.capture, Path('/synthetic-closed'))
        self.assertEqual(default.capture_sha256, 'a' * 64)
        self.assertEqual(default.output, Path('/synthetic-new'))
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE):
            explicit = R.arguments(argv + ['--placement-profile', profile])
            self.assertEqual(vars(explicit), dict(vars(default), placement_profile=profile))
        for suffix in (['--placement-profile', 'unknown'], ['--placement-profile']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                R.arguments(argv + suffix)
            self.assertEqual(error.exception.code, 2)

    def test_dispatch_is_once_and_preserves_refusal_or_exception(self):
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE):
            keywords = {} if profile == R.D.PROFILE else {'profile': R.D.WINDOW_PROFILE}
            for program in R.B.PROGRAMS:
                inputs, expected = object(), object()
                for status in ('MATERIALS_READY', 'MATERIALS_REFUSED'):
                    result = dict(status=status, qualification_complete=False, files={})
                    with mock.patch.object(R.D, 'attempt', return_value=result) as call:
                        self.assertIs(R.material_attempt(program, inputs, expected, profile), result)
                        call.assert_called_once_with(program, inputs, expected, **keywords)
                failure = RuntimeError('synthetic adapter refusal')
                with mock.patch.object(R.D, 'attempt', side_effect=failure) as call:
                    with self.assertRaises(RuntimeError) as error:
                        R.material_attempt(program, inputs, expected, profile)
                    self.assertIs(error.exception, failure)
                    call.assert_called_once_with(program, inputs, expected, **keywords)
        with mock.patch.object(R.D, 'attempt') as call:
            with self.assertRaises(AssertionError):
                R.material_attempt('checksum', object(), object(), 'unknown')
            call.assert_not_called()


    def test_broad_cli_dispatch_once_preserves_status_and_exception(self):
        argv = ['--capture', '/synthetic-closed', '--capture-sha256', 'a' * 64,
                '--output', '/synthetic-new']
        default = R.arguments(argv)
        explicit = R.arguments(argv + ['--placement-profile', R.D.BROAD_PROFILE])
        self.assertEqual(default.placement_profile, R.D.PROFILE)
        self.assertEqual(vars(explicit), dict(vars(default), placement_profile=R.D.BROAD_PROFILE))
        for program in R.B.PROGRAMS:
            inputs, expected = object(), object()
            for status in ('MATERIALS_READY', 'MATERIALS_REFUSED'):
                result = dict(status=status, qualification_complete=False, files={})
                with mock.patch.object(R.D, 'attempt', return_value=result) as call:
                    self.assertIs(R.material_attempt(program, inputs, expected, R.D.BROAD_PROFILE), result)
                    call.assert_called_once_with(program, inputs, expected, profile=R.D.BROAD_PROFILE)
            failure = RuntimeError('synthetic broad refusal')
            with mock.patch.object(R.D, 'attempt', side_effect=failure) as call:
                with self.assertRaises(RuntimeError) as error:
                    R.material_attempt(program, inputs, expected, R.D.BROAD_PROFILE)
                self.assertIs(error.exception, failure)
                call.assert_called_once_with(program, inputs, expected, profile=R.D.BROAD_PROFILE)


    def test_short_cli_material_dispatch_is_explicit_and_once(self):
        argv = ['--capture', '/synthetic-closed', '--capture-sha256', 'a' * 64,
                '--output', '/synthetic-new']
        default = R.arguments(argv)
        selected = R.arguments(argv + ['--placement-profile', R.D.SHORT_PROFILE])
        self.assertEqual(default.placement_profile, R.D.PROFILE)
        self.assertEqual(vars(selected), dict(vars(default), placement_profile=R.D.SHORT_PROFILE))
        for bad in ('short-only', R.D.SHORT_PROFILE + ' ', R.D.SHORT_PROFILE.replace('-v1', '-v2')):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                R.arguments(argv + ['--placement-profile', bad])
            self.assertEqual(error.exception.code, 2)
        for program in R.B.PROGRAMS:
            inputs, expected = object(), object()
            for status in ('MATERIALS_READY', 'MATERIALS_REFUSED'):
                result = dict(status=status, qualification_complete=False, files={})
                with mock.patch.object(R.D, 'attempt', return_value=result) as call:
                    self.assertIs(R.material_attempt(program, inputs, expected, R.D.SHORT_PROFILE), result)
                    call.assert_called_once_with(program, inputs, expected, profile=R.D.SHORT_PROFILE)
            failure = RuntimeError('synthetic short refusal')
            with mock.patch.object(R.D, 'attempt', side_effect=failure) as call:
                with self.assertRaises(RuntimeError) as error:
                    R.material_attempt(program, inputs, expected, R.D.SHORT_PROFILE)
                self.assertIs(error.exception, failure)
                call.assert_called_once_with(program, inputs, expected, profile=R.D.SHORT_PROFILE)

    def test_short_importer_argument_routing_and_stdout_contract(self):
        material = {'ledger.txt': b'synthetic ledger\n',
                    'policy.txt': b'LI2DISASM-POLICY 2\nneighbor-victims short-only\n'}
        paths = [Path('/binary'), Path('/original'), Path('/ledger'), Path('/policy'), Path('/product')]
        expected = ['/binary', '/original', '/ledger', hashlib.sha256(material['ledger.txt']).hexdigest(),
                    '/policy', hashlib.sha256(material['policy.txt']).hexdigest(), '/product']
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE, R.D.BROAD_PROFILE):
            self.assertEqual(R.importer_arguments(*paths, material, profile), expected)
            self.assertIsNone(R.importer_stdout(b'legacy output unchanged', profile, 2))
        self.assertEqual(R.importer_arguments(*paths, material, R.D.SHORT_PROFILE),
                         [expected[0], '--short-neighbors-only', *expected[1:]])
        for profile in ('unknown', 'short-only', None, True):
            with self.assertRaises(AssertionError):
                R.importer_arguments(*paths, material, profile)
        for code, complete in ((0, b'true'), (2, b'false')):
            raw = (b'profile=elf-disassembly-null-jumps-short-only-v1 neighbor_victims=short-only '
                   b'candidate_complete=' + complete + b' qualification_complete=false\n')
            self.assertIsNone(R.importer_stdout(raw, R.D.SHORT_PROFILE, code))
            for bad in (raw.replace(b'-short-only-v1', b'-v1'),
                        raw.replace(b' neighbor_victims=short-only', b''),
                        raw.replace(b'neighbor_victims=short-only', b'neighbor_victims=long-only'),
                        raw.replace(b'candidate_complete=' + complete,
                                    b'candidate_complete=' + (b'false' if code == 0 else b'true')),
                        raw + b'\n', raw[:-1]):
                with self.assertRaises(AssertionError):
                    R.importer_stdout(bad, R.D.SHORT_PROFILE, code)
        with self.assertRaises(AssertionError):
            R.importer_stdout(b'', R.D.SHORT_PROFILE, 1)

    def test_short_inventory_requires_exact_profile_family_and_complete_rows(self):
        # Independent supplied metadata, not an importer result or native observation.
        original = b'synthetic original'
        material = {'ledger.txt': b'synthetic ledger\n',
                    'source-inventory.tsv': (b'role\tindex\tpc\tfile_offset\tlength\tselected_jump\n'
                                             b'start\t0\t4198400\t4096\t2\t1\n')}
        digest = lambda raw: hashlib.sha256(raw).hexdigest()
        mode = b'profile\telf-disassembly-null-jumps-short-only-v1\nneighbor_victims\tshort-only\n'
        legacy = b'profile\telf-disassembly-null-jumps-v1\n'
        inventory = (b'LI2DISASSEMBLY-INVENTORY\t1\n' + mode +
                     f'original_sha256\t{digest(original)}\nledger_sha256\t{digest(material["ledger.txt"])}\n'.encode() +
                     b'complete_jump_count\t1\nqualification_complete\tfalse\n'
                     b'id\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\n'
                     b'1\t4198400\t2\t4096\t4198400\t16\t4198400\t2\n')
        base = {'disassembly-inventory.tsv': inventory,
                'program-failure.tsv': b'LI2DISASSEMBLY-FAILURE\t1\n' + mode,
                'planning-profile.tsv': b'LI2PLANNING\t1\n' + mode}

        def indexed(files, complete_mode=mode, code=2):
            result = dict(files)
            if code == 0:
                result.pop('program-failure.tsv', None)
                result['candidate.elf'] = b'synthetic candidate bytes, never executed'
            prefix = (b'LI2DISASSEMBLY-DIRECTORY\t1\n' + complete_mode +
                      f'observed_original_sha256\t{digest(original)}\ncandidate_complete\t{str(code == 0).lower()}\n'.encode() +
                      b'qualification_complete\tfalse\n')
            index = ''.join(f'file\t{name}\t{len(raw)}\t{digest(raw)}\n' for name, raw in result.items()).encode()
            result['COMPLETE'] = prefix + index
            return result

        def check(files, profile, code=2):
            with mock.patch.object(R, 'read', side_effect=lambda path, **_: files[Path(path).name]):
                return R.inventory(Path('/synthetic-product'), original, material, code, profile=profile)

        for code in (0, 2):
            self.assertEqual(check(indexed(base, code=code), R.D.SHORT_PROFILE, code), code == 0)
        with self.assertRaises(AssertionError):
            check(indexed({'disassembly-inventory.tsv': inventory}), R.D.SHORT_PROFILE)
        promoted = indexed(base, code=0)
        failure = base['program-failure.tsv']
        promoted['program-failure.tsv'] = failure
        promoted['COMPLETE'] += f'file\tprogram-failure.tsv\t{len(failure)}\t{digest(failure)}\n'.encode()
        with self.assertRaises(AssertionError):
            check(promoted, R.D.SHORT_PROFILE, 0)
        legacy_files = {name: raw.replace(mode, legacy) for name, raw in base.items()}
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE, R.D.BROAD_PROFILE):
            self.assertFalse(check(indexed(legacy_files, legacy), profile))
            with self.assertRaises(AssertionError):
                check(indexed(base), profile)
        with self.assertRaises(AssertionError):
            check(indexed(legacy_files, legacy), R.D.SHORT_PROFILE)
        mutations = (legacy, mode.replace(b'neighbor_victims\tshort-only\n', b''),
                     mode.replace(b'short-only\n', b'long-only\n'),
                     mode + b'neighbor_victims\tshort-only\n',
                     mode + b'profile\telf-disassembly-null-jumps-short-only-v1\n',
                     b'neighbor_victims\tshort-only\n' + mode.splitlines(keepends=True)[0])
        for changed in mutations:
            with self.assertRaises((AssertionError, KeyError, IndexError)):
                check(indexed(base, changed), R.D.SHORT_PROFILE)
            for name in base:
                altered = dict(base); altered[name] = altered[name].replace(mode, changed)
                with self.assertRaises((AssertionError, KeyError, IndexError)):
                    check(indexed(altered), R.D.SHORT_PROFILE)
        for changed in (inventory.replace(b'complete_jump_count\t1', b'complete_jump_count\t0'),
                        inventory.replace(b'1\t4198400\t2\t4096', b'1\t4198401\t2\t4096'),
                        inventory.rsplit(b'\n', 2)[0] + b'\n',
                        inventory + inventory.splitlines(keepends=True)[-1]):
            altered = dict(base, **{'disassembly-inventory.tsv': changed})
            with self.assertRaises((AssertionError, KeyError, IndexError)):
                check(indexed(altered), R.D.SHORT_PROFILE)


    def test_owned_short_material_dispatch_is_explicit_and_once(self):
        argv = ['--capture', '/synthetic-closed', '--capture-sha256', 'a' * 64,
                '--output', '/synthetic-new']
        default = R.arguments(argv)
        selected = R.arguments(argv + ['--placement-profile', R.D.SHORT_T3_OWNERSHIP_PROFILE])
        self.assertEqual(default.placement_profile, R.D.PROFILE)
        self.assertEqual(vars(selected), dict(vars(default), placement_profile=R.D.SHORT_T3_OWNERSHIP_PROFILE))
        for bad in ('short-only', R.D.SHORT_T3_OWNERSHIP_PROFILE + ' ', R.D.SHORT_T3_OWNERSHIP_PROFILE.replace('-v1', '-v2')):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                R.arguments(argv + ['--placement-profile', bad])
            self.assertEqual(error.exception.code, 2)
        for program in R.B.PROGRAMS:
            inputs, expected = object(), object()
            for status in ('MATERIALS_READY', 'MATERIALS_REFUSED'):
                result = dict(status=status, qualification_complete=False, files={})
                with mock.patch.object(R.D, 'attempt', return_value=result) as call:
                    self.assertIs(R.material_attempt(program, inputs, expected, R.D.SHORT_T3_OWNERSHIP_PROFILE), result)
                    call.assert_called_once_with(program, inputs, expected, profile=R.D.SHORT_T3_OWNERSHIP_PROFILE)
            failure = RuntimeError('synthetic short refusal')
            with mock.patch.object(R.D, 'attempt', side_effect=failure) as call:
                with self.assertRaises(RuntimeError) as error:
                    R.material_attempt(program, inputs, expected, R.D.SHORT_T3_OWNERSHIP_PROFILE)
                self.assertIs(error.exception, failure)
                call.assert_called_once_with(program, inputs, expected, profile=R.D.SHORT_T3_OWNERSHIP_PROFILE)


    def test_owned_short_importer_routing_and_stdout_contract(self):
        material = {'ledger.txt': b'synthetic ledger\n',
                    'policy.txt': b'LI2DISASM-POLICY 3\nneighbor-victims short-only\nneighbor-ownership inherited-t3\n'}
        paths = [Path('/binary'), Path('/original'), Path('/ledger'), Path('/policy'), Path('/product')]
        expected = ['/binary', '/original', '/ledger', hashlib.sha256(material['ledger.txt']).hexdigest(),
                    '/policy', hashlib.sha256(material['policy.txt']).hexdigest(), '/product']
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE, R.D.BROAD_PROFILE):
            self.assertEqual(R.importer_arguments(*paths, material, profile), expected)
            self.assertIsNone(R.importer_stdout(b'legacy output unchanged', profile, 2))
        self.assertEqual(R.importer_arguments(*paths, material, R.D.SHORT_T3_OWNERSHIP_PROFILE),
                         [expected[0], '--short-neighbors-owned', *expected[1:]])
        for profile in ('unknown', 'short-only', None, True):
            with self.assertRaises(AssertionError):
                R.importer_arguments(*paths, material, profile)
        for code, complete in ((0, b'true'), (2, b'false')):
            raw = (b'profile=elf-disassembly-null-jumps-short-t3-ownership-v1 neighbor_victims=short-only neighbor_ownership=inherited-t3 '
                   b'candidate_complete=' + complete + b' qualification_complete=false\n')
            self.assertIsNone(R.importer_stdout(raw, R.D.SHORT_T3_OWNERSHIP_PROFILE, code))
            for bad in (raw.replace(b'-short-t3-ownership-v1', b'-v1'),
                        raw.replace(b' neighbor_victims=short-only', b''),
                        raw.replace(b'neighbor_victims=short-only', b'neighbor_victims=long-only'),
                        raw.replace(b'candidate_complete=' + complete,
                                    b'candidate_complete=' + (b'false' if code == 0 else b'true')),
                        raw.replace(b' neighbor_ownership=inherited-t3', b''),
                         raw.replace(b'neighbor_ownership=inherited-t3', b'neighbor_ownership=local-only'),
                         raw + b'\n', raw[:-1]):
                with self.assertRaises(AssertionError):
                    R.importer_stdout(bad, R.D.SHORT_T3_OWNERSHIP_PROFILE, code)
        with self.assertRaises(AssertionError):
            R.importer_stdout(b'', R.D.SHORT_T3_OWNERSHIP_PROFILE, 1)


    def test_owned_short_inventory_binds_both_modes_and_complete_rows(self):
        # Independent supplied metadata, not an importer result or native observation.
        original = b'synthetic original'
        material = {'ledger.txt': b'synthetic ledger\n',
                    'source-inventory.tsv': (b'role\tindex\tpc\tfile_offset\tlength\tselected_jump\n'
                                             b'start\t0\t4198400\t4096\t2\t1\n')}
        digest = lambda raw: hashlib.sha256(raw).hexdigest()
        mode = b'profile\telf-disassembly-null-jumps-short-t3-ownership-v1\nneighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\n'
        legacy = b'profile\telf-disassembly-null-jumps-v1\n'
        inventory = (b'LI2DISASSEMBLY-INVENTORY\t1\n' + mode +
                     f'original_sha256\t{digest(original)}\nledger_sha256\t{digest(material["ledger.txt"])}\n'.encode() +
                     b'complete_jump_count\t1\nqualification_complete\tfalse\n'
                     b'id\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\n'
                     b'1\t4198400\t2\t4096\t4198400\t16\t4198400\t2\n')
        base = {'disassembly-inventory.tsv': inventory,
                'program-failure.tsv': b'LI2DISASSEMBLY-FAILURE\t1\n' + mode,
                'planning-profile.tsv': b'LI2PLANNING\t1\n' + mode}

        def indexed(files, complete_mode=mode, code=2):
            result = dict(files)
            if code == 0:
                result.pop('program-failure.tsv', None)
                result['candidate.elf'] = b'synthetic candidate bytes, never executed'
            prefix = (b'LI2DISASSEMBLY-DIRECTORY\t1\n' + complete_mode +
                      f'observed_original_sha256\t{digest(original)}\ncandidate_complete\t{str(code == 0).lower()}\n'.encode() +
                      b'qualification_complete\tfalse\n')
            index = ''.join(f'file\t{name}\t{len(raw)}\t{digest(raw)}\n' for name, raw in result.items()).encode()
            result['COMPLETE'] = prefix + index
            return result

        def check(files, profile, code=2):
            with mock.patch.object(R, 'read', side_effect=lambda path, **_: files[Path(path).name]):
                return R.inventory(Path('/synthetic-product'), original, material, code, profile=profile)

        for code in (0, 2):
            self.assertEqual(check(indexed(base, code=code), R.D.SHORT_T3_OWNERSHIP_PROFILE, code), code == 0)
        with self.assertRaises(AssertionError):
            check(indexed({'disassembly-inventory.tsv': inventory}), R.D.SHORT_T3_OWNERSHIP_PROFILE)
        promoted = indexed(base, code=0)
        failure = base['program-failure.tsv']
        promoted['program-failure.tsv'] = failure
        promoted['COMPLETE'] += f'file\tprogram-failure.tsv\t{len(failure)}\t{digest(failure)}\n'.encode()
        with self.assertRaises(AssertionError):
            check(promoted, R.D.SHORT_T3_OWNERSHIP_PROFILE, 0)
        legacy_files = {name: raw.replace(mode, legacy) for name, raw in base.items()}
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE, R.D.BROAD_PROFILE):
            self.assertFalse(check(indexed(legacy_files, legacy), profile))
            with self.assertRaises(AssertionError):
                check(indexed(base), profile)
        with self.assertRaises(AssertionError):
            check(indexed(legacy_files, legacy), R.D.SHORT_T3_OWNERSHIP_PROFILE)
        mutations = (legacy, mode.replace(b'neighbor_ownership\tinherited-t3\n', b''),
                     mode.replace(b'inherited-t3\n', b'local-only\n'),
                     mode + b'neighbor_ownership\tinherited-t3\n',
                     mode.replace(b'neighbor_victims\tshort-only\n', b''),
                     mode.replace(b'short-only\n', b'long-only\n'),
                     mode + b'neighbor_victims\tshort-only\n',
                     mode + b'profile\telf-disassembly-null-jumps-short-t3-ownership-v1\n',
                     b'neighbor_victims\tshort-only\n' + mode.splitlines(keepends=True)[0])
        for changed in mutations:
            with self.assertRaises((AssertionError, KeyError, IndexError)):
                check(indexed(base, changed), R.D.SHORT_T3_OWNERSHIP_PROFILE)
            for name in base:
                altered = dict(base); altered[name] = altered[name].replace(mode, changed)
                with self.assertRaises((AssertionError, KeyError, IndexError)):
                    check(indexed(altered), R.D.SHORT_T3_OWNERSHIP_PROFILE)
        for changed in (inventory.replace(b'complete_jump_count\t1', b'complete_jump_count\t0'),
                        inventory.replace(b'1\t4198400\t2\t4096', b'1\t4198401\t2\t4096'),
                        inventory.rsplit(b'\n', 2)[0] + b'\n',
                        inventory + inventory.splitlines(keepends=True)[-1]):
            altered = dict(base, **{'disassembly-inventory.tsv': changed})
            with self.assertRaises((AssertionError, KeyError, IndexError)):
                check(indexed(altered), R.D.SHORT_T3_OWNERSHIP_PROFILE)

        with self.assertRaises(AssertionError):
            check(indexed(base), R.D.SHORT_PROFILE)



if __name__ == '__main__':
    unittest.main()
