#!/usr/bin/env python3
"""Pure producer-capture contracts. No subprocess/build/candidate dispatch."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


def module(name):
    path=Path(__file__).with_name(name+'.py')
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


D=module('startup_produce')
O=module('startup_originals')
T=module('startup_target_from_root')
TOOLS={name:dict(path='/tools/'+name) for name in ('python','cargo','as','ld','objdump','timeout')}


class CapturePlan(unittest.TestCase):
    def test_fresh_twelve_phases_and_no_old_producer(self):
        phases=O.phases(Path('/repo'),Path('/repo/ignored/fresh'),TOOLS)
        self.assertEqual(len(phases),12)
        self.assertEqual([p['name'] for p in phases[:2]],['build-target','target'])
        self.assertEqual(phases[0]['argv'],['/tools/python','-B',
            '/repo/evaluation/adjacent-b2/artifact-verifier/startup_target_from_root.py','/tools/cargo','/repo'])
        self.assertEqual(phases[1]['argv'],['/repo/target/release/elf-exec-oracle','target'])
        joined=repr(phases)
        self.assertNotIn('adjacent_routed_jmp_disassembly_sites',joined)
        self.assertNotIn('offline_router_sites',joined)
        self.assertNotIn('bootstrap.so',joined)
        self.assertEqual(sum(p['name'].endswith('-as') for p in phases),2)
        self.assertEqual(sum(p['name'].endswith('-ld') for p in phases),2)
        self.assertEqual(sum('-disassemble-' in p['name'] for p in phases),6)

    def test_both_complete_programs_have_all_raw_symbol_captures(self):
        phases=O.phases(Path('/repo'),Path('/repo/ignored/fresh'),TOOLS)
        for name in O.PROGRAMS:
            own=[p for p in phases if p['name'].startswith(name+'-')]
            self.assertEqual(len(own),5)
            self.assertEqual([p['argv'][-2] for p in own[2:]],
                ['--disassemble=_start','--disassemble=kernel','--disassemble=null_hook'])
            self.assertEqual([p['dependencies'] for p in own],
                [[],[name+'-as'],[name+'-ld'],[name+'-ld'],[name+'-ld']])

    def test_finite_original_capture_limits_are_not_changed(self):
        phases=O.phases(Path('/repo'),Path('/repo/ignored/fresh'),TOOLS)
        self.assertEqual(phases[0]['limits'],[120,180,128])
        self.assertEqual(phases[1]['limits'],[20,30,16])
        for p in phases[2:]:
            self.assertEqual(p['limits'],[60,90,128] if p['name'].endswith(('-as','-ld')) else [20,30,16])

    def test_target_build_uses_only_named_root_manifest_release_target(self):
        with tempfile.TemporaryDirectory() as root:
            base=Path(root).resolve()
            env=dict(RUSTC='/tools/rustc',CARGO_TARGET_DIR=str(base/'target'))
            command=T.command(['launcher','/tools/cargo',str(base)],env)
            self.assertEqual(command,['/tools/cargo','build','--release','--locked','--offline',
                '--manifest-path',str(base/'Cargo.toml'),'--package','liteinst2','--bin','elf-exec-oracle','--message-format=json'])
            self.assertNotIn('run',command)
            with self.assertRaises(ValueError):T.command(['launcher','/else/cargo',str(base)],env)
            with self.assertRaises(ValueError):T.command(['launcher','/tools/cargo',str(base),'extra'],env)


class Policy(unittest.TestCase):
    def inputs(self):
        return dict(original=b'original bytes',ledger=b'complete ledger',policy=b'LI2DISASM-POLICY 6\nstrict\n')
    def dependencies(self):
        return {'/lib/ld.so':dict(sha256='1'*64),'/lib/libc.so':dict(sha256='2'*64)}
    def policy(self,program='checksum',**kw):
        fields=dict(inputs=self.inputs(),interpreter='/lib/ld.so',bootstrap='/package/checksum-bootstrap.so',
                    dependencies=self.dependencies(),contract='a'*64)
        fields.update(kw)
        return D.startup_policy(program,**fields)

    def test_exact_ordered_policy_with_actual_authored_stack(self):
        raw=self.policy();lines=raw.decode().splitlines()
        self.assertEqual(lines[:3],['LI2BOOTSTRAP-POLICY 1','profile linux-x86-64-static-exec-router-bootstrap-v1','program checksum'])
        self.assertEqual(lines[3:6],['original '+D.sha(self.inputs()['original']),
            'disassembly '+D.sha(self.inputs()['ledger']),'planning-policy '+D.sha(self.inputs()['policy'])])
        self.assertEqual(lines[8],'app-stack 4481024 65536')
        self.assertEqual(int(lines[8].split()[1]),0x446000)
        self.assertEqual(lines[10],'startup-limits 4096 4096 4097 112 16384 4096 65536 1048576')
        self.assertEqual(lines[11:],['dependency /lib/ld.so '+'1'*64,'dependency /lib/libc.so '+'2'*64])
        self.assertTrue(raw.endswith(b'\n'))

    def test_each_full_program_has_a_distinct_named_policy(self):
        checksum=self.policy()
        rle=self.policy('rle-roundtrip',bootstrap='/package/rle-roundtrip-bootstrap.so')
        self.assertIn(b'program checksum\n',checksum)
        self.assertIn(b'program rle-roundtrip\n',rle)
        self.assertNotEqual(checksum,rle)

    def test_old_planning_profile_cannot_be_relabelled(self):
        changed=self.inputs();changed['policy']=b'LI2DISASM-POLICY 4\n'
        with self.assertRaises(ValueError):self.policy(inputs=changed)

    def test_unreviewed_zero_contract_and_unknown_program_refuse(self):
        with self.assertRaises(ValueError):self.policy(contract='0'*64)
        with self.assertRaises(ValueError):self.policy(program='subset')

    def test_missing_interpreter_bootstrap_dependency_and_reordered_roster_refuse(self):
        bad=[{'/lib/libc.so':dict(sha256='2'*64)},
             {'/lib/ld.so':dict(sha256='1'*64),'/package/checksum-bootstrap.so':dict(sha256='3'*64)},
             {'/lib/libc.so':dict(sha256='2'*64),'/lib/ld.so':dict(sha256='1'*64)}]
        for dependencies in bad:
            with self.assertRaises(ValueError):self.policy(dependencies=dependencies)

    def test_alias_and_space_pathnames_refuse_before_generation(self):
        for path in ('relative','/x/../x/boot.so','/x//boot.so','/x/./boot.so','/x/boot file.so','/x/'):
            with self.assertRaises(ValueError):self.policy(bootstrap=path)


class StrictSourceOnly(unittest.TestCase):
    def test_json_writer_preserves_order_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'plan'
            D.write(path,dict(checksum=dict(original=1,ledger=2,policy=3,startup=4),
                              **{'rle-roundtrip':dict(original=5,ledger=6,policy=7,startup=8)}))
            import json
            value=json.loads(path.read_text())
            self.assertEqual(tuple(value),('checksum','rle-roundtrip'))
            self.assertEqual(tuple(value['checksum']),('original','ledger','policy','startup'))
            with self.assertRaises(FileExistsError):D.write(path,{})

    def test_exact_lowercase_digest_rejects_stale_shape(self):
        self.assertEqual(D.custody_digest('a'*64),'a'*64)
        for bad in ('A'*64,'a'*63,'g'*64,None,1):
            with self.assertRaises(ValueError):D.custody_digest(bad)


if __name__=='__main__':
    unittest.main()
