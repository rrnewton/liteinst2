#!/usr/bin/env python3
"""Pure prospective controls. Synthetic ELF fixtures are not assembler/corpus results."""
import copy
from pathlib import Path
import struct
import types
import unittest
from unittest import mock
import startup_material as S
import startup_originals as O
from verify_saved_controls import A, C, M, W

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TOOLS = {name:dict(path='/tools/'+name) for name in ('python','cargo','as','ld','objdump','timeout')}


def context():
    def load(name, digest):
        assert name == 'adjacent_routed_jmp_material.py' and digest == A.MATERIAL_SHA
        return M
    return types.SimpleNamespace(D=M.D, load=load)


def readonly_inputs(program, short=False):
    inputs = C.fixture(program, short_jumps=short)
    inputs['linker'] = S.readonly_linker(M.D)
    inputs['header_pad_source'] = S.SEED_SOURCE
    # Metadata-only synthetic ET_REL; the actual seed's assembler command and
    # bytes are separately mandatory in the thirteen-phase captured build.
    inputs['header_pad_object'] = C.elf(1, [C.section('.li2.header_pad', b'\0', flags=2),
                                          C.section('.note.GNU-stack', b'')])
    return inputs


def replace_original(inputs, raw):
    before = ('original ' + S.sha(inputs['original']) + '\n').encode()
    after = ('original ' + S.sha(raw) + '\n').encode()
    assert inputs['heads'].count(before) == 1
    inputs['heads'] = inputs['heads'].replace(before, after, 1)
    inputs['original'] = raw


def padding_flags(inputs, flags):
    elf = M.D.Elf(inputs['original'], 2)
    raw = bytearray(inputs['original'])
    at = int.from_bytes(raw[40:48], 'little') + elf.by_name['.header_pad'] * 64 + 8
    struct.pack_into('<Q', raw, at, flags)
    replace_original(inputs, bytes(raw))


class OriginalProfiles(unittest.TestCase):
    def test_exact_additive_linker_and_seed_leave_legacy_sources_literal(self):
        old = (ROOT/'evaluation/offline-corpus/layout.ld').read_bytes()
        self.assertEqual(S.sha(old), 'c55eb8bfc9b91251be5486d99de4a9d0458c937540a936dcc9ac0a93d60a535c')
        self.assertEqual(old, M.D.C.LINKER.encode('ascii'))
        self.assertEqual(old.count(S.OLD_LINE), 1)
        self.assertEqual((HERE/'startup_layout.ld').read_bytes(), old.replace(S.OLD_LINE,S.NEW_LINE,1))
        self.assertEqual((HERE/'startup_header_pad.S').read_bytes(), S.SEED_SOURCE)
        self.assertNotIn(b'(READONLY)', (HERE/'startup_layout.ld').read_bytes())

    def test_new_thirteenth_seed_phase_preserves_every_original_command_and_limit(self):
        root, out = Path('/repo'), Path('/repo/ignored/capture')
        old = O.phases(root,out,TOOLS)
        new = O.phases(root,out,TOOLS,profile=O.READONLY_PROFILE)
        self.assertEqual(len(old),12); self.assertEqual(len(new),13)
        seed = new[2]
        self.assertEqual(seed, dict(name='header-pad-as',dependencies=[],limits=[60,90,128],
            argv=['/tools/as','--64','/repo/'+O.CRATE+'/startup_header_pad.S','-o',str(out/'header-pad.o')],
            outputs=[str(out/'header-pad.o')]))
        self.assertEqual([p['name'] for p in new if p is not seed], [p['name'] for p in old])
        expected = copy.deepcopy(old)
        for phase in expected:
            if phase['name'].endswith('-ld'):
                phase['dependencies'].append('header-pad-as')
                phase['argv'][phase['argv'].index('-T')+1] = '/repo/'+O.CRATE+'/startup_layout.ld'
                phase['argv'].insert(phase['argv'].index('-o'), str(out/'header-pad.o'))
        self.assertEqual([p for p in new if p is not seed],expected)
        self.assertEqual(sum('-disassemble-' in p['name'] for p in new),6)
        with self.assertRaisesRegex(ValueError,'explicit original capture profile'):
            O.phases(root,out,TOOLS,profile='automatic-fallback')

    def test_original_profile_is_bound_before_and_after_capture(self):
        for profile in (O.PROFILE,O.READONLY_PROFILE):
            self.assertEqual(O.capture_profile({'profile':profile},{'profile':profile}),profile)
        with self.assertRaisesRegex(ValueError,'same original capture profile'):
            O.capture_profile({'profile':O.PROFILE},{'profile':O.READONLY_PROFILE})
        with self.assertRaisesRegex(ValueError,'explicit original capture profile'):
            O.capture_profile({'profile':'unknown'},{'profile':'unknown'})

    def test_source_custody_roster_adds_the_exact_metadata_source(self):
        root = Path('/repo')
        ctx = types.SimpleNamespace(ROOT=root,HERE=root/'evaluation/offline-corpus')
        pins = types.SimpleNamespace(SOURCE_PINS={O.CRATE+'/startup_material.py':'1'*64})
        old = O.source_inputs(ctx,pins)
        new = O.source_inputs(ctx,pins,profile=O.READONLY_PROFILE)
        self.assertEqual(new,(old-{'/repo/evaluation/offline-corpus/layout.ld'}) |
            {'/repo/'+O.CRATE+'/startup_layout.ld','/repo/'+O.CRATE+'/startup_header_pad.S'})
        self.assertIn('/repo/'+O.CRATE+'/startup_material.py',new)
        for program in O.PROGRAMS:
            self.assertIn('/repo/evaluation/offline-corpus/'+program+'.S',new)

    def test_material_source_is_authenticated_before_compilation(self):
        raw = (HERE/'startup_material.py').read_bytes()
        ctx = types.SimpleNamespace(ROOT=ROOT,read=lambda *a,**k:raw)
        key = O.CRATE+'/startup_material.py'
        module = O.material_module(ctx,types.SimpleNamespace(SOURCE_PINS={key:S.sha(raw)}))
        self.assertEqual(module.READONLY,O.READONLY_PROFILE)
        for pins in ({}, {key:'0'*64}):
            with mock.patch('builtins.compile',side_effect=AssertionError('untrusted compile')) as compile_:
                with self.assertRaisesRegex(ValueError,'exact startup material source'):
                    O.material_module(ctx,types.SimpleNamespace(SOURCE_PINS=pins))
                compile_.assert_not_called()


class CompleteMaterials(unittest.TestCase):
    def ready(self, program, inputs):
        result = S.derive(context(),A,S.READONLY,program,inputs)
        self.assertEqual(result['status'],'MATERIALS_READY')
        self.assertEqual(result['profile'],S.PROFILE)
        self.assertNotEqual(result['profile'],A.ROUTED.material)
        self.assertEqual(result['original_profile'],S.READONLY)
        self.assertEqual([result['roster_checked_heads'],result['roster_checked_jumps']],list(A.COUNTS[program]))
        self.assertFalse(result['qualification_complete']); self.assertFalse(result['importer_verified'])
        self.assertEqual(result['expected_input_sha256'],{k:S.sha(v) for k,v in inputs.items()})
        return result

    def refused(self, program, inputs, stage):
        result = S.derive(context(),A,S.READONLY,program,inputs)
        self.assertEqual(result['status'],'MATERIALS_REFUSED')
        self.assertEqual(result['failure']['stage'],stage)
        self.assertEqual([result['source_expected_heads'],result['source_expected_jumps']],list(A.COUNTS[program]))
        self.assertFalse(result['qualification_complete'])

    def test_both_full_programs_and_short_near_rosters_keep_exact_material_and_wrapper_bytes(self):
        for program in A.PROGRAMS:
            for short in (False,True):
                old = C.fixture(program,short_jumps=short)
                new = readonly_inputs(program,short)
                result = self.ready(program,new)
                baseline = M.attempt_adjacent_routed_jmp(program,old,{k:S.sha(v) for k,v in old.items()},upper=2,lower=1,joint=2)
                self.assertEqual(baseline['status'],'MATERIALS_READY')
                self.assertEqual(result['files'],baseline['files'])
                expected = W.expected_files(context(),A,program,new,result['files'])
                self.assertEqual(expected,W.expected_files(context(),A,program,old,baseline['files']))
                self.assertEqual(len([r for r in expected['selection.txt'].splitlines() if r.startswith(b'site ')]),A.COUNTS[program][1])
                self.assertEqual(new['source'],old['source']); self.assertEqual(new['object'],old['object'])
                self.assertEqual(new['heads'],old['heads']); self.assertEqual(new['original'],old['original'])

    def test_old_entrypoint_and_default_capture_keep_actual_old_material_bytes(self):
        for program in A.PROGRAMS:
            old = C.fixture(program)
            padding_flags(old,3)  # Preserve the exact reported legacy source condition.
            expected = M.attempt_adjacent_routed_jmp(program,old,{k:S.sha(v) for k,v in old.items()},upper=2,lower=1,joint=2)
            self.assertEqual(expected['status'],'MATERIALS_READY')
            self.assertEqual(S.derive(context(),A,S.LEGACY,program,old),expected)
            # This legacy material acceptance is not carrier/startup acceptance.
            self.assertEqual(M.D.Elf(old['original'],2).section('.header_pad')[2],3)

    def test_linker_seed_and_profile_crossovers_are_not_relabelled(self):
        for program in A.PROGRAMS:
            good = readonly_inputs(program); self.ready(program,good)
            for field,value in [('linker',M.D.C.LINKER.encode()),('source',good['source']+b'\n'),
                                ('header_pad_source',S.SEED_SOURCE.replace(b'"a"',b'"aw"'))]:
                bad = dict(good); bad[field] = value
                self.refused(program,bad,'inputs')
            with self.assertRaisesRegex(ValueError,'exact readonly material input roster'):
                S.derive(context(),A,S.READONLY,program,C.fixture(program))
            with self.assertRaisesRegex(ValueError,'explicit original capture profile'):
                S.derive(context(),A,'auto',program,good)
            legacy = C.fixture(program); legacy['linker'] = good['linker']
            refused = S.derive(context(),A,S.LEGACY,program,legacy)
            self.assertEqual(refused['status'],'MATERIALS_REFUSED')
            self.assertEqual(refused['failure']['stage'],'inputs')

    def test_coherently_rebound_writable_padding_hits_exact_new_guard(self):
        for program in A.PROGRAMS:
            good = readonly_inputs(program); self.ready(program,good)
            bad = dict(good); padding_flags(bad,3)
            self.assertNotEqual(S.sha(bad['original']),S.sha(good['original']))
            self.refused(program,bad,'readonly-section-ownership')
            self.assertEqual(good['original'][0x1000:0x56000],bad['original'][0x1000:0x56000])
            self.assertEqual(M.D.Elf(good['original'],2).ph,M.D.Elf(bad['original'],2).ph)

    def test_coherent_original_object_head_and_target_mutants_reach_owned_checks(self):
        for program in A.PROGRAMS:
            good = readonly_inputs(program); self.ready(program,good)
            bad = dict(good); raw = bytearray(bad['original']); raw[420] = 1
            replace_original(bad,bytes(raw)); self.refused(program,bad,'object-elf-ownership')
            bad = dict(good); obj = M.D.Elf(bad['object'],1); raw = bytearray(bad['object'])
            raw[obj.section('.data.buffers')[4]] = 1
            before = ('object '+S.sha(bad['object'])+'\n').encode()
            bad['object'] = bytes(raw)
            after = ('object '+S.sha(bad['object'])+'\n').encode()
            self.assertEqual(bad['heads'].count(before),1)
            bad['heads'] = bad['heads'].replace(before,after,1)
            self.refused(program,bad,'object-elf-ownership')
            bad = dict(good); bad['heads'] = b'\n'.join(bad['heads'].splitlines()[:-1])+b'\n'
            self.refused(program,bad,'head-transport')
            bad = dict(good); bad['target'] = b'target xsave64 4\n'
            self.refused(program,bad,'policy')

    def test_new_material_checker_keeps_full_counts_limits_and_short_only_family(self):
        for program in A.PROGRAMS:
            inputs = readonly_inputs(program); good = self.ready(program,inputs)
            for field,value in [('source_expected_heads',A.COUNTS[program][0]-1),
                                ('roster_checked_jumps',A.COUNTS[program][1]-1),
                                ('neighbor_victims','all'),('adjacent_joint',3),
                                ('qualification_complete',True),('profile',A.ROUTED.material)]:
                bad = copy.deepcopy(good); bad[field] = value
                with self.subTest(program=program,field=field),self.assertRaises(ValueError):
                    S._check(A,program,bad,inputs['original'])
            bad = copy.deepcopy(good)
            bad['files']['policy.txt'] = bad['files']['policy.txt'].replace(b'2147483648',b'2147483649')
            with self.assertRaisesRegex(ValueError,'unchanged complete policy limits'):
                S._check(A,program,bad,inputs['original'])


if __name__ == '__main__':
    unittest.main()
