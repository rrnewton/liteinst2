#!/usr/bin/env python3
"""Prospective metadata controls only; no compiler, workload or provider reads."""
import ast
import errno
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fresh_native_reproduction', HERE / 'reproduce.py')
repro = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repro)


class ReproductionControls(unittest.TestCase):
    def test_retention_request_cap_and_failure_preserves_source(self):
        self.assertEqual(repro.retention_limit(241 * repro.MIB), 256 * repro.MIB)
        self.assertEqual(repro.retention_limit(1), 64 * repro.MIB + 1)
        for bad in (True, 0, -1):
            with self.assertRaises(AssertionError): repro.retention_limit(bad)
        repo = Path('/synthetic/repo'); directory = repo / 'ignored/retention/create'
        cap = repro.retention_limit(241 * repro.MIB)
        self.assertEqual(repro.retention_request(repo, directory, ['/synthetic/tar', '-cf', 'archive'], cap),
            dict(argv=['/synthetic/tar', '-cf', 'archive'], cwd=str(repo), env=dict(repro.ENV, TMPDIR=str(directory / 'tmp')),
                 cpu_seconds=60, wall_seconds=90, file_bytes=256 * repro.MIB,
                 stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt')))
        for bad in (True, 0, -1, 256 * repro.MIB + 1):
            with self.assertRaises(AssertionError): repro.retention_request(repo, directory, [], bad)
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp).resolve(); raw = repo / 'ignored/run'; key, lane = 'null-heap-write-unstripped', 'core'
            source = raw / 'native' / (key + '-' + lane) / 'captures'; source.mkdir(parents=True)
            (raw / 'retention').mkdir(); p = source / 'bytes.bin'; p.write_bytes(b'preserved original')
            expected = {'bytes.bin': repro.read(p)[1]}; before = repro.capture_inventory(repo, source, expected)
            def refusal(directory, name, argv, cap):
                self.assertEqual(name, 'create'); self.assertLessEqual(cap, 256 * repro.MIB)
                raise AssertionError('synthetic retention refusal')
            fake = SimpleNamespace(repo=repo, raw=raw, tools={'tar': '/synthetic/tar', 'zstd': '/synthetic/zstd'},
                retention_results=[dict(cell=key, lane=lane, status='UNRUN')], capacity=lambda n: dict(required_growth=n),
                retention_command=refusal, quiet=lambda value: None)
            with self.assertRaisesRegex(AssertionError, 'synthetic retention refusal'):
                repro.Campaign.retain_captures(fake, lane, key, source, expected)
            self.assertEqual(repro.capture_inventory(repo, source, expected), before)
            self.assertEqual(fake.retention_results[0]['status'], 'FAILED')
            self.assertFalse((raw / 'retention' / (key + '-' + lane) / 'verified.json').exists())

    def test_scoped_config_denial_and_readable_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); repo = root / 'repo'; (repo / '.cargo').mkdir(parents=True)
            config = repo / '.cargo/config'; config.write_bytes(b'[build]\njobs = 4\n')
            denied = root / '.cargo/config'
            fake = SimpleNamespace(repo=repo, tools={'cargo_home': str(root / 'cargo-home')})
            original_lstat = Path.lstat
            def observed_lstat(p, *args, **kwargs):
                if p == denied: raise PermissionError(errno.EPERM, 'synthetic metadata denial')
                if p.name in ('config', 'config.toml') and p != config: raise FileNotFoundError(errno.ENOENT, 'synthetic absence')
                return original_lstat(p, *args, **kwargs)
            # No real ancestor lookup: every metadata result is synthetic.
            with patch.object(Path, 'lstat', observed_lstat):
                snapshot = repro.Campaign.config_snapshot(fake)
                self.assertEqual(snapshot[str(denied)], dict(observation='READ_DENIED', operation='metadata_lookup', errno=errno.EPERM, exists=None, content_sha256=None))
                self.assertEqual(snapshot[str(config)]['sha256'], repro.sha(config.read_bytes()))
                self.assertEqual(snapshot[str(config)]['stat'], repro.read(config)[1]['stat'])
                self.assertTrue(snapshot[str(config)]['exists'])
                # A readable-path content denial remains fatal, not READ_DENIED metadata.
                with patch.object(repro, 'read', side_effect=PermissionError(errno.EACCES, 'synthetic content denial')):
                    with self.assertRaises(PermissionError): repro.Campaign.config_snapshot(fake)
            def unexpected(p, *args, **kwargs): raise PermissionError(errno.EIO, 'synthetic non-permission error')
            with patch.object(Path, 'lstat', unexpected):
                with self.assertRaises(AssertionError): repro.Campaign.config_snapshot(fake)

    def test_single_lookup_absence_then_denial(self):
        # Historical method name retained; V5 explicitly changes the negative-observation policy.
        repo = Path('/synthetic/repo'); selected = repo / '.cargo/config'
        fake = SimpleNamespace(repo=repo, tools={'cargo_home': '/synthetic/cargo-home'})
        for absent_type, absent_errno in ((FileNotFoundError, errno.ENOENT), (NotADirectoryError, errno.ENOTDIR)):
            for denied_errno in (errno.EPERM, errno.EACCES):
                for negatives in (1, 2):
                    with self.subTest(absent=absent_errno, denied=denied_errno, negatives=negatives):
                        calls = []
                        def lookup(p, *args, **kwargs):
                            if p == selected:
                                calls.append(p)
                                if len(calls) > negatives: raise PermissionError(denied_errno, 'synthetic changed lookup')
                            raise absent_type(absent_errno, 'synthetic absence')
                        with patch.object(Path, 'lstat', lookup), \
                             patch.object(Path, 'stat', side_effect=AssertionError('unexpected stat probe')), \
                             patch.object(Path, 'is_symlink', side_effect=AssertionError('unexpected symlink probe')):
                            first = repro.Campaign.config_snapshot(fake)
                            self.assertEqual(first[str(selected)], dict(observation='READ_DENIED', operation='metadata_lookup', errno=denied_errno, exists=None, content_sha256=None))
                            self.assertEqual(calls, [selected] * (negatives + 1))
                            second = repro.Campaign.config_snapshot(fake)
                            self.assertEqual(first, second)  # Equal classifications, different raw syscall sequences.
                            self.assertEqual(calls, [selected] * (negatives + 2))
                    # The prior two-probe hazard remains demonstrated, not attributed to F1/F2.
                    with patch.object(Path, 'stat', side_effect=absent_type(absent_errno, 'synthetic absence')), \
                         patch.object(Path, 'is_symlink', side_effect=PermissionError(denied_errno, 'synthetic changed lookup')):
                        try: selected.stat()
                        except (FileNotFoundError, NotADirectoryError): exists = False
                        with self.assertRaises(PermissionError):
                            if not exists and not selected.is_symlink(): pass

    def test_three_negative_lookup_bound_and_persistent_errors(self):
        fake = SimpleNamespace(repo=Path('/synthetic/repo'), tools={'cargo_home': '/synthetic/cargo-home'})
        for errors in ((errno.ENOENT,) * 3, (errno.ENOTDIR,) * 3, (errno.ENOENT, errno.ENOTDIR, errno.ENOENT)):
            calls = {}
            def lookup(p, *args, **kwargs):
                count = calls.get(p, 0); self.assertLess(count, 3); calls[p] = count + 1
                code = errors[count]
                raise (FileNotFoundError if code == errno.ENOENT else NotADirectoryError)(code, 'synthetic absence')
            with patch.object(Path, 'lstat', lookup), patch.object(Path, 'resolve', side_effect=AssertionError('absent path resolved')), patch.object(repro, 'read', side_effect=AssertionError('absent path read')):
                snapshot = repro.Campaign.config_snapshot(fake)
            self.assertEqual(snapshot, {str(p): dict(exists=False) for p in calls})
            self.assertTrue(calls); self.assertTrue(all(n == 3 for n in calls.values()))
        for error in (OSError(errno.EIO, 'persistent IO error'), FileNotFoundError(errno.EIO, 'wrong negative errno')):
            with patch.object(Path, 'lstat', side_effect=error) as lookup:
                with self.assertRaises(AssertionError if isinstance(error, FileNotFoundError) else OSError): repro.Campaign.config_snapshot(fake)
                self.assertEqual(lookup.call_count, 1)

    def test_negative_then_present_keeps_full_read_and_no_read_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); repo = root / 'repo'; (repo / '.cargo').mkdir(parents=True)
            config = repo / '.cargo/config'; config.write_bytes(b'[build]\njobs = 4\n')
            fake = SimpleNamespace(repo=repo, tools={'cargo_home': str(root / 'cargo-home')})
            original_lstat = Path.lstat
            for negatives in (1, 2):
                calls = []
                def lookup(p, *args, **kwargs):
                    if p.name in ('config', 'config.toml') and p != config: raise FileNotFoundError(errno.ENOENT, 'synthetic absence')
                    if p == config:
                        calls.append(p)
                        if len(calls) <= negatives: raise FileNotFoundError(errno.ENOENT, 'transient negative')
                    return original_lstat(p, *args, **kwargs)
                with patch.object(Path, 'lstat', lookup), patch.object(repro, 'read', wraps=repro.read) as reader:
                    row = repro.Campaign.config_snapshot(fake)[str(config)]
                    reader.assert_called_once_with(config)
                owner = original_lstat(config)
                six = [owner.st_dev, owner.st_ino, owner.st_mode, owner.st_size, owner.st_mtime_ns, owner.st_ctime_ns]
                self.assertEqual(row, dict(exists=True, resolved=str(config), sha256=repro.sha(config.read_bytes()), stat=six, lstat=six))
                self.assertEqual(len(calls), negatives + 4)  # Initial, read's is_symlink and path owner, final link owner.
                for error in (PermissionError(errno.EACCES, 'content denied'), FileNotFoundError(errno.ENOENT, 'content vanished')):
                    calls.clear()
                    with patch.object(Path, 'lstat', lookup), patch.object(repro, 'read', side_effect=error) as reader:
                        with self.assertRaises(type(error)): repro.Campaign.config_snapshot(fake)
                        reader.assert_called_once_with(config)
                        self.assertEqual(len(calls), negatives + 1)

    def test_classified_snapshot_mismatch_retains_exact_private_records(self):
        unknown = dict(observation='READ_DENIED', operation='metadata_lookup', errno=errno.EPERM, exists=None, content_sha256=None)
        absent = dict(exists=False)
        present = dict(exists=True, resolved='/synthetic/config', sha256='a' * 64, stat=[1,2,3,4,5,6], lstat=[1,2,3,4,5,6])
        for expected, observed in ((unknown, absent), (absent, unknown), (absent, present), (present, dict(present, stat=[1,2,3,4,5,7]))):
            with tempfile.TemporaryDirectory() as tmp:
                fake = SimpleNamespace(raw=Path(tmp), active='synthetic-stage', owners={}, product_owners={}, configs={'/synthetic/config': expected}, config_snapshot=lambda: {'/synthetic/config': observed})
                for count in range(3):
                    with self.assertRaises(AssertionError): repro.Campaign.stable(fake)
                    self.assertEqual(fake.config_mismatches, count + 1)
                self.assertEqual({p.name for p in fake.raw.iterdir()}, {'config-mismatch-1.json', 'config-mismatch-2.json'})
                for name in ('config-mismatch-1.json', 'config-mismatch-2.json'):
                    self.assertEqual(repro.js(fake.raw / name), dict(expected=fake.configs, observed={'/synthetic/config': observed}, stage='synthetic-stage', policy='three-consecutive-negative-v1'))

    def test_finish_saves_actual_checked_snapshot_without_second_lookup(self):
        # Execute the literal finish try-body only; no workload or public-report simulation.
        tree = ast.parse((HERE / 'reproduce.py').read_text())
        campaign = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Campaign')
        finish = next(n for n in campaign.body if isinstance(n, ast.FunctionDef) and n.name == 'finish')
        block = next(n for n in finish.body if isinstance(n, ast.Try))
        code = compile(ast.Module(body=block.body, type_ignores=[]), 'actual_finish_try_body', 'exec')
        for matches in (True, False):
            with tempfile.TemporaryDirectory() as tmp:
                baseline = {'/synthetic/config': dict(exists=False)}
                observed = {'/synthetic/config': dict(exists=False if matches else None)}
                self.assertIsNot(observed, baseline)
                saved = {}; fake = SimpleNamespace(raw=Path(tmp), active=None, configs=baseline,
                    owners={}, product_owners={}, archive_owners={}, repo=Path('/synthetic/repo'), before={})
                fake.p = SimpleNamespace(source=lambda repo: fake.before)
                fake.stable = lambda source=False: repro.Campaign.stable(fake, source)
                def save(path, value):
                    self.assertNotIn(path.name, saved); saved[path.name] = value
                with patch.object(fake, 'config_snapshot', create=True, side_effect=[observed, AssertionError('unexpected second lookup')]) as snapshot:
                    if matches:
                        exec(code, dict(self=fake, write=save, Path=Path))
                        self.assertIs(saved['config-after.json'], observed)
                        self.assertIsNot(saved['config-after.json'], baseline)
                    else:
                        with self.assertRaises(AssertionError): exec(code, dict(self=fake, write=save, Path=Path))
                        self.assertNotIn('config-after.json', saved)
                        self.assertEqual(repro.js(fake.raw / 'config-mismatch-1.json')['observed'], observed)
                    snapshot.assert_called_once_with()

    def test_existing_link_resolution_and_owner_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); repo = root / 'repo'; (repo / '.cargo').mkdir(parents=True)
            target = root / 'owned'; target.write_bytes(b'[build]\njobs = 4\n')
            config = repo / '.cargo/config'; config.symlink_to(target)
            fake = SimpleNamespace(repo=repo, tools={'cargo_home': str(root / 'cargo-home')})
            original_lstat = Path.lstat
            def observed_lstat(p, *args, **kwargs):
                if p.name in ('config', 'config.toml') and p != config:
                    raise FileNotFoundError(errno.ENOENT, 'synthetic absence')
                return original_lstat(p, *args, **kwargs)
            with patch.object(Path, 'lstat', observed_lstat):
                row = repro.Campaign.config_snapshot(fake)[str(config)]
                self.assertEqual(row['resolved'], str(target))
                self.assertEqual(row['sha256'], repro.sha(target.read_bytes()))
                with patch.object(Path, 'resolve', side_effect=PermissionError(errno.EACCES, 'synthetic existing-entry denial')):
                    with self.assertRaises(PermissionError): repro.Campaign.config_snapshot(fake)
                target.unlink()
                with self.assertRaises(FileNotFoundError): repro.Campaign.config_snapshot(fake)
                target.write_bytes(b'[build]\njobs = 4\n')
            names = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            before = original_lstat(config)
            for changed in (*names, 'late-denial'):
                with self.subTest(changed=changed):
                    calls = []
                    def changed_lstat(p, *args, **kwargs):
                        if p != config: return observed_lstat(p, *args, **kwargs)
                        calls.append(p)
                        if len(calls) == 1: return before
                        if changed == 'late-denial': raise PermissionError(errno.EPERM, 'synthetic final-owner denial')
                        return SimpleNamespace(**{n: getattr(before, n) + (n == changed) for n in names})
                    # Fix only resolution for this final-owner injection; read()
                    # still opens/hashes/checks the complete real target file.
                    resolve = Path.resolve
                    def resolved(p, *args, **kwargs):
                        return target if p == config else resolve(p, *args, **kwargs)
                    with patch.object(Path, 'lstat', changed_lstat), patch.object(Path, 'resolve', resolved):
                        with self.assertRaises(PermissionError if changed == 'late-denial' else AssertionError):
                            repro.Campaign.config_snapshot(fake)
                    self.assertEqual(calls, [config, config])

    def test_capture_inventory_and_archive_owner_refuse_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp).resolve(); source = repo / 'ignored/captures'; source.mkdir(parents=True)
            p = source / 'bytes.bin'; p.write_bytes(b'\x00\xffsample\n')
            expected = {'bytes.bin': repro.read(p)[1]}
            before = repro.capture_inventory(repo, source, expected)
            self.assertEqual(before['ignored/captures/bytes.bin']['sha256'], repro.sha(p.read_bytes()))
            p.write_bytes(b'\x00\xffmutate\n')
            with self.assertRaises(AssertionError): repro.capture_inventory(repo, source, expected)
            p.unlink()
            with self.assertRaises(AssertionError): repro.capture_inventory(repo, source, expected)
            outside = repo / 'outside'; outside.write_bytes(b'sentinel')
            p.symlink_to(outside)
            with self.assertRaises(AssertionError): repro.capture_inventory(repo, source, expected)
            p.unlink(); p.write_bytes(b'\x00\xffsample\n'); expected = {'bytes.bin': repro.read(p)[1]}
            alias = repo / 'alias'; os.link(p, alias)
            with self.assertRaises(AssertionError): repro.capture_inventory(repo, source, expected)
            alias.unlink()
            archive = repo / 'synthetic.archive'; archive.write_bytes(b'full synthetic archive bytes')
            owner = repro.archive_owner(archive, 1024)
            self.assertEqual(owner['sha256'], repro.sha(archive.read_bytes()))
            self.assertEqual(owner['bytes'], archive.stat().st_size)
            with self.assertRaises(AssertionError): repro.archive_owner(archive, owner['bytes'] - 1)
            archive.write_bytes(b'changed synthetic archive bytes')
            self.assertNotEqual(repro.archive_owner(archive, 1024), owner)
            archive.unlink(); archive.symlink_to(outside)
            with self.assertRaises(OSError): repro.archive_owner(archive, 1024)

    def test_full_target_projection_and_unknown_layout_refusals(self):
        compact = b'target xsave64 743 4:576:256 32:832:64 64:896:512 128:1408:1024 512:2432:8\n'
        full = (b'LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\n'
                b'page_bytes\t4096\nbias_domain\t1\nformat\txsave64-standard\n'
                b'allocation_bytes\t2496\nimage_bytes\t2440\nxcr0_mask\t743\nqualification_complete\tfalse\n'
                b'component\t4\t576\t256\ncomponent\t32\t832\t64\ncomponent\t64\t896\t512\n'
                b'component\t128\t1408\t1024\ncomponent\t512\t2432\t8\n')
        self.assertEqual(repro.full_target(compact),full)
        invalid = [compact.replace(b'743',b'231'),
                   compact.replace(b' 512:2432:8',b''),
                   compact.replace(b'\n',b' 1024:2440:8\n'),
                   compact.replace(b'4:576:256 32:832:64',b'32:832:64 4:576:256'),
                   compact.replace(b'512:2432:8',b'512:2433:8'),
                   compact.replace(b'512:2432:8',b'512:2432:4'),
                   b'target fxsave64\n',compact[:-1],bytearray(compact)]
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises(AssertionError): repro.full_target(value)

    def test_fixed_complete_plan(self):
        plan, native = repro.stage_plan()
        self.assertEqual(len(plan), 357)
        self.assertEqual(len(plan), len(set(plan)))
        self.assertEqual(sum(n.startswith('prepare-') for n in plan), 30)
        self.assertEqual(sum(n.startswith('ordinary-') for n in plan), 192)
        self.assertEqual(sum(n.startswith('observe-') for n in plan), 16)
        self.assertEqual(sum(n.startswith('native-') for n in plan), 32)
        self.assertEqual(len(native), 16)
        self.assertEqual(sum(176 for lane, key in native if lane == 'core' and key.startswith('null-')), 704)
        self.assertEqual(sum(176 for lane, key in native if key.startswith('journal-')), 2112)
        self.assertEqual(native[-1], ('bootstrap-patched-reference', 'journal-jump-site-stripped'))
        self.assertEqual(repro.DATASETS, ('empty', 'singleton', 'pair-reverse', 'equal-17', 'sorted-17', 'reverse-17', 'duplicates-17', 'mixed-64'))

    def test_literal_journal_and_capacity_refusals(self):
        def function(path):
            return next(n for n in ast.parse(path.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'journal')
        self.assertEqual(ast.dump(function(HERE / 'reproduce.py')), ast.dump(function(Path('evaluation/e9-common-app/run_candidates.py'))))
        pcs = struct.pack('<2Q', 0x401020, 0x401010)
        b = repro.journal(pcs)
        self.assertEqual(len(b), 131144)
        self.assertEqual(struct.unpack('<8Q', b[:64]), (0x6c69326a6f75726e, 1, 16384, 0, 2, 0, 0, 0))
        self.assertEqual(b[64:80], pcs)
        self.assertEqual(b[80:-8], bytes(131072 - 16))
        self.assertEqual(struct.unpack('<Q', b[-8:]), (0x7265636f72647321,))
        self.assertEqual(len(repro.journal(bytes(16384 * 8))), 131144)
        for invalid in (b'x', bytes(16384 * 8 + 8), bytearray()):
            with self.subTest(kind=type(invalid).__name__, length=len(invalid)):
                with self.assertRaises(AssertionError): repro.journal(invalid)

    def test_native_terminal_full_population_and_mutations(self):
        # A synthetic terminal tree tests the reporting reader, never native state.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            complete = b'LI2COMMONCORERECORDINGPAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\ncomparisons\t528\nfiles\t8636\nrecording_profile\tbounded-journal-v1\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n'
            (root / 'complete.tsv').write_bytes(complete)
            for i in range(176):
                d = root / ('case-%03d' % i); (d / 'candidate').mkdir(parents=True)
                (d / 'pair.tsv').write_text('LI2COREPAIR\t1\ncase\t%d\ncomparisons\t3\nchildren\t2\nE9\tUNIMPLEMENTED_UNRUN\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n' % i)
                (d / 'candidate/complete.tsv').write_text('LI2COREPAIRCHILD\t1\ncase\t%d\nsteps\t1\nphysical_completion\t0\nlogical_completion\t0\nfault\tNone\ncomparisons\t3\nreaped_echild\ttrue\nqualification_complete\tfalse\n' % i)
            def check(): return repro.native_complete(root, 'core', True, [])
            self.assertEqual(check(), dict(pairs=176, children=352, comparisons=528))
            changes = [('complete.tsv', b'heads\t87', b'heads\t86'),
                       ('complete.tsv', b'fault_pairs\t2', b'fault_pairs\t0'),
                       ('complete.tsv', b'children\t352', b'children\t350'),
                       ('complete.tsv', b'comparisons\t528', b'comparisons\t525'),
                       ('case-175/pair.tsv', b'case\t175', b'case\t174'),
                       ('case-175/pair.tsv', b'comparisons\t3', b'comparisons\t2'),
                       ('case-175/candidate/complete.tsv', b'steps\t1', b'steps\t20001'),
                       ('case-175/candidate/complete.tsv', b'reaped_echild\ttrue', b'reaped_echild\tfalse')]
            for name, before, after in changes:
                p = root / name; original = p.read_bytes()
                self.assertEqual(original.count(before), 1)
                p.write_bytes(original.replace(before, after))
                with self.subTest(path=name, mutation=after):
                    with self.assertRaises(AssertionError): check()
                p.write_bytes(original)
            p = root / 'case-175/pair.tsv'; original = p.read_bytes(); p.unlink()
            with self.assertRaises(FileNotFoundError): check()
            p.write_bytes(original)
            self.assertEqual(check(), dict(pairs=176, children=352, comparisons=528))


if __name__ == '__main__':
    unittest.main()
