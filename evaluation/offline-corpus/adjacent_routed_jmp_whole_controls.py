#!/usr/bin/env python3
"""Pure D01 union protocol controls; every synthetic artifact remains unverified."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

assert not sys.flags.optimize, 'assertions required'


def load(name, expected):
    path = Path(__file__).resolve().with_name(name)
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == expected
    module = types.ModuleType('authenticated_' + name.replace('.', '_')); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


C = load('adjacent_whole_controls.py', '131c48c34e34d81edadc5e06c7ecb00a26c384944b56884055f541b30fb02510')
A, B = C.A, C.B
N = load('build_adjacent_routed_jmp_whole.py', '00c5c95474dc9ee57bc8e0b534a0e8a4bdbdb289e2ef30a83652147fb05feb9f')
P = A.ROUTED
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
OLD_IMPORTER = 'elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1'
OLD_FAMILY = [['neighbor_victims', 'short-only'], ['neighbor_ownership', 'inherited-t3'],
              ['pending_selected', 'full-instruction-ownership'], ['adjacent_b2', 'fallback-two-site-v1']]
original_fixture = C.fixture
digest, tsv = C.digest, C.tsv


def indexed(files, original, code):
    with mock.patch.object(C, 'IMPORTER', P.importer):
        return C.indexed(files, original, code)


def fixture(program, complete=True, preparation=None):
    # Independently prescribed v6 transform of the existing synthetic protocol.
    # This is never passed to a real planner or counted as an ELF positive.
    with mock.patch.object(C, 'IMPORTER', OLD_IMPORTER), mock.patch.object(C, 'FAMILY', OLD_FAMILY):
        original, material, files = original_fixture(program, complete, preparation)
    old_policy = material['policy.txt']
    policy = old_policy.replace(b'LI2DISASM-POLICY 5\n', b'LI2DISASM-POLICY 6\n', 1).replace(
        b'adjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\n',
        b'adjacent-pairs original-geometry-jcc-or-routed-jmp-v1\nadjacent-pair-budgets 2 1 2\n', 1)
    material = dict(material, **{'policy.txt': policy})
    replacements = [(OLD_IMPORTER.encode(), P.importer.encode()),
        (b'adjacent_b2\tfallback-two-site-v1\n', b'adjacent_pairs\toriginal-geometry-jcc-or-routed-jmp-v1\n'),
        (old_policy, policy), (digest(old_policy).encode(), digest(policy).encode()),
        (b'adjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\n',
         b'adjacent-pairs original-geometry-jcc-or-routed-jmp-v1\nadjacent-pair-budgets 2 1 2\n')]
    old_selection = files.get('selection.txt')
    if old_selection is not None:
        selection = old_selection.replace(replacements[-1][0], replacements[-1][1])
        replacements.append((digest(old_selection).encode(), digest(selection).encode()))
    out = {}
    for name, raw in files.items():
        if name in ('COMPLETE', 'adjacent-b2-evidence.txt'):
            continue
        for before, after in replacements:
            raw = raw.replace(before, after)
        out[name] = raw
    if 'adjacent-b2-evidence.txt' in files:
        count = COUNTS[program][1]
        out[P.evidence] = tsv([['LI2ADJACENT-ROUTED-JMP-EVIDENCE', '1'],
            ['selection_sha256', digest(selection)], ['selected_count', str(count)],
            ['baseline_calls', str(count)], ['pair_calls', '0'], ['adjacent_counts', '0', '0', '0'],
            ['forward_jcc_calls', '0'], ['forward_jcc_counts', '0', '0', '0'],
            ['routed_jmp_calls', '0'], ['routed_jmp_counts', '0', '0', '0'],
            ['qualification_complete', 'false'], ['classification_complete', 'false'],
            ['legacy_image_slots', '0'], ['combined_image_work_upper_bound', '0']]) + b'resources\topaque\n\xffopaque Debug tail\n'
    return original, material, indexed(out, original, 0 if complete and preparation is None else 2)


def declaration(program, material, ready=True):
    heads, selected = COUNTS[program]
    return dict(profile=P.material, program=program, adjacent_pairs='original-geometry-jcc-or-routed-jmp-v1',
        adjacent_upper=2, adjacent_lower=1, adjacent_joint=2, neighbor_victims='short-only',
        neighbor_ownership='inherited-t3', pending_selected='full-instruction-ownership',
        qualification_complete=False, importer_verified=False, source_expected_heads=heads,
        source_expected_jumps=selected, roster_checked_heads=heads if ready else None,
        roster_checked_jumps=selected if ready else None,
        status='MATERIALS_READY' if ready else 'MATERIALS_REFUSED', files=material)


def run_frame(root, *, local=None, mutation=None, before_second=False):
    """Actual shared run/program/collector/custody path; capture/child only mocked."""
    ignored = root / 'ignored'; ignored.mkdir()
    with mock.patch.object(C, 'fixture', fixture), mock.patch.object(C, 'declaration', declaration), \
         mock.patch.object(C, 'IMPORTER', P.importer):
        frame = C.program_frame(ignored)
        frame.args.output.rmdir(); frame.args.capture.mkdir()
        frame.args.capture_sha256 = 'a' * 64
        frame.ctx.ROOT = root; frame.ctx.PINS = {}
        frame.captured['plan'] = {'synthetic': True}
        frame.captured['binary'] = root / 'target/release/examples/adjacent_routed_jmp_disassembly_sites'
        delegated = frame.ctx.D.attempt_adjacent_b2
        frame.captured['material_adapter'] = types.SimpleNamespace(attempt_adjacent_routed_jmp=delegated)
        frame.ctx.D.attempt_adjacent_b2 = mock.Mock(side_effect=AssertionError('wrong old material path'))
        if local == 'members':
            files = frame.products['checksum']
            for i in range(257 - len(files)):
                files[f'excess-{i:04}.txt'] = b''
            assert len(files) == 257
        elif local == 'name':
            frame.products['checksum']['bad name'] = b'initial malformed name'
        elif local == 'second':
            frame.products['rle-roundtrip'] = fixture('rle-roundtrip', False)[2]
        readers, saved = {}, {}
        old_adopt, old_product = A.OutputCustody.adopt, A.check_product
        def mutate():
            directory = frame.args.output / 'checksum'
            if mutation == 'file':
                (directory / 'policy.txt').write_bytes(b'changed retained bytes')
            elif mutation == 'directory':
                (directory / 'importer/product').rename(directory / 'importer/replaced')
                (directory / 'importer/product').mkdir()
            elif mutation == 'membership':
                (directory / 'importer/product/later.txt').write_bytes(b'added later')
            else:
                raise AssertionError('frozen mutation')
        def adopt(owner, program, row, reader):
            old_adopt(owner, program, row, reader)
            readers[program] = reader
            saved[program] = copy.deepcopy({k: row[k] for k in
                ('output_files', 'output_directories', 'output_read_bytes')})
            if program == 'checksum' and mutation and before_second:
                mutate()
        def authenticated(ctx, args, report, profile):
            assert ctx is frame.ctx and args is frame.args and profile is P
            report['configuration_complete'] = True
            return frame.captured
        def invoke(*args):
            result = frame.invoke(*args)
            if local == 'second' and args[1].parent.name == 'rle-roundtrip':
                stdout = f'profile={P.importer} candidate_complete=false qualification_complete=false\n'.encode()
                C.closure_fixture(args[1], *result, frame.ctx.B.HELPER_SHA, 2, stdout)
            return result
        def product(reader, program, *args):
            if program == 'rle-roundtrip' and mutation and not before_second:
                mutate()
            return old_product(reader, program, *args)
        with mock.patch.object(A, 'authenticate_capture', side_effect=authenticated), \
             mock.patch.object(A, 'invoke', side_effect=invoke), \
             mock.patch.object(A, 'check_product', side_effect=product), \
             mock.patch.object(A.OutputCustody, 'adopt', adopt):
            code = A.run(frame.args, frame.ctx, P)
        frame.ctx.D.attempt_adjacent_b2.assert_not_called()
    report = json.loads((frame.args.output / 'closed.json').read_bytes())
    return frame, code, report, readers, saved


class RoutedDiagnosticControls(unittest.TestCase):
    def test_rj18_fixed_capture_plan_release_and_legacy_descriptor_preservation(self):
        self.assertEqual(N.labels(), dict(B.labels(), capture_profile=P.capture,
            material_profile=P.material, importer_profile=P.importer))
        tools = {name: {'path': '/tool/bin/' + name} for name in ('cargo', 'as', 'ld', 'objdump')}
        args = (Path('/repo'), Path('/capture'), tools, Path('/repo/evaluation/offline-corpus'))
        old, new = B.phase_plan(*args), N.phase_plan(*args)
        expected = copy.deepcopy(old)
        expected[0]['name'] = 'build-adjacent_routed_jmp_disassembly_sites'
        expected[0]['argv'][-2] = 'adjacent_routed_jmp_disassembly_sites'
        expected[0]['product'] = '/repo/target/release/examples/adjacent_routed_jmp_disassembly_sites'
        expected[0]['product_name'] = 'adjacent_routed_jmp_disassembly_sites'
        self.assertEqual(new, expected)
        self.assertEqual(len(new), 13)
        self.assertEqual((A.OUTPUT_BYTES, A.FILE_BYTES, A.MEMBERS), (64*1048576,16*1048576,256))
        artifact = dict(reason='compiler-artifact', target=dict(name=P.producer, kind=['example']),
            executable=new[0]['product'], profile=dict(B.PROFILE))
        end = dict(reason='build-finished', success=True)
        wire = lambda rows: b'\n'.join(json.dumps(r).encode() for r in rows) + b'\n'
        N.check_artifact(wire([artifact,end]),new[0])
        for changed in [dict(artifact,executable=old[0]['product']),
            dict(artifact,target=dict(name='adjacent_b2_disassembly_sites',kind=['example'])),
            dict(artifact,profile=dict(B.PROFILE,test=True))]:
            with self.assertRaises(AssertionError):
                N.check_artifact(wire([changed,end]),new[0])
        for descriptor in [tuple(P), P._replace(version='5'), None, True]:
            with self.assertRaises(A.Failure):
                A.descriptor(descriptor)
        with self.assertRaises(AssertionError):
            B.descriptor(tuple(list(B.ROUTED)))

    def test_rj18_complete_new_capture_authentication_and_swapped_labels_refuse(self):
        proxy = types.SimpleNamespace(__file__=N.__file__, PROFILE=B.PROFILE,
            labels=N.labels, phase_plan=N.phase_plan, check_artifact=N.check_artifact)
        with mock.patch.object(C,'B',proxy):
            frame = C.capture_frame()
        shared = str(frame.ctx.HERE / 'build_adjacent_whole.py')
        frame.memory[shared] = b'synthetic shared capture implementation'
        pin = frame.ctx.B.identity(shared)
        frame.plan['inputs'][shared] = pin; frame.closed['files'][shared] = pin
        adapter = types.SimpleNamespace(__file__=str(frame.ctx.HERE / 'adjacent_routed_jmp_material.py'))
        frame.memory[adapter.__file__] = b'synthetic authenticated union material module'
        def loaded(name, digest):
            self.assertEqual((name,digest), (P.builder,P.builder_sha) if name==P.builder else
                ('adjacent_routed_jmp_material.py',A.MATERIAL_SHA))
            if name==P.builder:
                return proxy
            frame.ctx.read(Path(adapter.__file__),cap=1048576)
            return adapter
        frame.ctx.load = mock.Mock(side_effect=loaded); frame.refresh()
        with mock.patch.object(A.subprocess,'check_output',side_effect=frame.git):
            report = A.summary(P)
            result = A.authenticate_capture(frame.ctx,frame.args,report,P)
            result['stable']()
        self.assertEqual(result['binary'].name,P.producer)
        self.assertIs(result['material_adapter'],adapter)
        self.assertEqual(frame.ctx.load.call_count,2)
        self.assertIn(adapter.__file__,frame.ctx.PINS)
        self.assertEqual((report['expected_programs'],report['expected_heads'],report['expected_selected']),(2,187,42))
        self.assertTrue(all(report[k] is False for k in A.FALSE_FLAGS))
        for key,value in [('capture_profile',A.CAPTURE),('material_profile',A.PROFILE),
                          ('importer_profile',A.IMPORTER),('expected_selected',41)]:
            changed=dict(N.labels(),qualification_complete=False,**{})
            changed[key]=value
            with self.assertRaises(A.Failure):
                A.check_capture_labels(changed,dict(N.labels(),qualification_complete=False),proxy)

    def test_rj15_full_roster_protocol_and_strict_family_scalars(self):
        totals=[0,0]
        for program,counts in COUNTS.items():
            original,material,files=fixture(program)
            self.assertEqual(len(A.check_material(program,declaration(program,material),material,original,P)),counts[1])
            with tempfile.TemporaryDirectory() as temporary:
                C.product_directory(Path(temporary),files)
                reader=A.OutputReader(Path(temporary))
                try:
                    result=A.check_product(reader,program,original,material,0,P)
                    self.assertFalse(result['scalar_evidence']['debug_association_verified'])
                finally:
                    reader.close()
            for old,new in [(b'adjacent-pair-budgets 2 1 2',b'adjacent-pair-budgets 2 2 2'),
                (b' 1 4096 ',b' 2 4096 '),(b'2147483648',b'4294967296')]:
                changed=dict(material,**{'policy.txt':material['policy.txt'].replace(old,new)})
                with self.assertRaises(A.Failure):
                    A.check_material(program,declaration(program,changed),changed,original,P)
            selection=digest(files['selection.txt'])
            # Scalar-only synthetic two-family declaration, never association proof.
            evidence=files[P.evidence].replace(b'pair_calls\t0\n',b'pair_calls\t2\n').replace(
                b'adjacent_counts\t0\t0\t0',b'adjacent_counts\t3\t2\t3').replace(
                b'forward_jcc_calls\t0',b'forward_jcc_calls\t1').replace(
                b'forward_jcc_counts\t0\t0\t0',b'forward_jcc_counts\t2\t1\t2').replace(
                b'routed_jmp_calls\t0',b'routed_jmp_calls\t1').replace(
                b'routed_jmp_counts\t0\t0\t0',b'routed_jmp_counts\t1\t1\t1').replace(
                b'combined_image_work_upper_bound\t0',b'combined_image_work_upper_bound\t5')
            self.assertEqual(A.check_evidence(evidence,selection,counts[1],P)['pair_calls'],2)
            for old,new in [(b'\t1\nselection_sha256',b'\t2\nselection_sha256'),
                (b'routed_jmp_calls\t1',b'routed_jmp_calls\t0'),
                (b'adjacent_counts\t3\t2\t3',b'adjacent_counts\t4\t2\t3'),
                (b'forward_jcc_counts\t2\t1\t2',b'forward_jcc_counts\t2\t2\t2'),
                (b'combined_image_work_upper_bound\t5',b'combined_image_work_upper_bound\t4'),
                (b'qualification_complete\tfalse',b'qualification_complete\ttrue')]:
                with self.assertRaises(A.Failure):
                    A.check_evidence(evidence.replace(old,new),selection,counts[1],P)
            with self.assertRaises(A.Failure):
                A.check_evidence(evidence,selection,counts[1],A.LEGACY)
            totals=[a+b for a,b in zip(totals,counts)]
        self.assertEqual(totals,[187,42])

    def test_rj19_actual_run_stable_and_initial_local_refusals_continue_once(self):
        for local in (None,'members','name'):
            with self.subTest(local=local), tempfile.TemporaryDirectory() as temporary:
                frame,code,report,readers,saved=run_frame(Path(temporary),local=local)
                self.assertEqual(code,0 if local is None else 1)
                self.assertEqual(frame.material_calls,list(COUNTS));self.assertEqual(frame.dispatches,list(COUNTS))
                self.assertEqual((report['expected_programs'],report['expected_heads'],report['expected_selected']),(2,187,42))
                self.assertEqual(set(report['programs']),set(COUNTS))
                for program,row in report['programs'].items():
                    self.assertEqual((row['material_calls'],row['producer_dispatches']),(1,1))
                    self.assertEqual((row['observed_heads'],row['observed_selected']),COUNTS[program])
                    self.assertTrue(all(row[k] is False for k in A.FALSE_FLAGS))
                    self.assertLessEqual(row['output_read_bytes'],64*1048576)
                    self.assertEqual(readers[program].used,row['output_read_bytes'])
                    for key in saved[program]:
                        self.assertEqual(row[key],saved[program][key])
                    with self.assertRaises(OSError):
                        A.os.fstat(readers[program].fd)
                if local:
                    first=report['programs']['checksum']
                    self.assertEqual(first['failure']['stage'],'output-bound' if local=='members' else 'output-path')
                    self.assertEqual(first['output_stability'],'VERIFIED_INCOMPLETE')
                    self.assertFalse(first['output_membership_complete'])
                    self.assertFalse(report['diagnostic_capture_complete'])
                else:
                    self.assertTrue(report['diagnostic_capture_complete'])
                    self.assertTrue(report['retained_output_stability_complete'])
                self.assertTrue(all(report[k] is False for k in A.FALSE_FLAGS))

    def test_rj19_retained_mutation_during_later_refusal_never_promotes_or_retries(self):
        for mutation in ('file','directory','membership'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                frame,code,report,readers,saved=run_frame(Path(temporary),local='second',mutation=mutation)
                self.assertEqual(code,1)
                self.assertEqual(frame.dispatches,list(COUNTS))
                first,second=[report['programs'][p] for p in COUNTS]
                self.assertEqual((first['status'],first['producer_exit'],first['producer_candidate_complete']),
                    ('PRODUCER_COMPLETE_UNVERIFIED',0,True))
                self.assertEqual(second['producer_exit'],2)
                self.assertFalse(second['producer_candidate_complete'])
                self.assertEqual(first['output_stability'],'FAILED')
                self.assertFalse(report['diagnostic_capture_complete'])
                self.assertFalse(report['retained_output_stability_complete'])
                for key,value in saved['checksum'].items():
                    self.assertEqual(first[key],value)
                self.assertTrue(all(report[k] is False for k in A.FALSE_FLAGS))
                for reader in readers.values():
                    with self.assertRaises(OSError):
                        A.os.fstat(reader.fd)
        for local in (None,'members','name'):
            with self.subTest(local=local),tempfile.TemporaryDirectory() as temporary:
                frame,code,report,readers,saved=run_frame(Path(temporary),local=local,
                    mutation='file',before_second=True)
                self.assertEqual(code,1)
                self.assertEqual(frame.dispatches,['checksum'])
                self.assertEqual(frame.material_calls,['checksum'])
                self.assertEqual(set(report['programs']),set(COUNTS))
                self.assertEqual(report['error']['stage'],'retained-output-stability')
                self.assertEqual(report['programs']['checksum']['output_stability'],'FAILED')
                self.assertEqual(report['programs']['rle-roundtrip']['producer_dispatches'],0)
                self.assertIsNone(report['programs']['rle-roundtrip']['producer_exit'])


if __name__ == '__main__':
    unittest.main()
