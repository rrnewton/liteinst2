#!/usr/bin/env python3
"""Source-level orchestration controls; fabricated receipts grant no native authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode=True
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
R=load('_pair_runner_controls',HERE/'reproduce.py')
F=load('_pair_wire_fixture',HERE/'controls.py')
N=load('_pair_native_helpers',ROOT/'evaluation/ordinary-module-native/reproduce.py')
L=load('_pair_leaf_helpers',ROOT/'evaluation/ordinary-leaf-set-native/reproduce.py')
O=load('_pair_copied_helpers',ROOT/'evaluation/ordinary-rust-invoke-native/reproduce.py')
C=load('_pair_caller_geometry',ROOT/'evaluation/ordinary-rust-invoke-native/caller.py')


def request():
    raw=ROOT/'ignored/fabricated-call-pair';cohort=raw/'native'
    argv=list(map(str,[raw/'application-candidate','normal-call-pair-state',raw/'module-candidate.so',raw/'module-trusted.so',4096,15,4352,9,raw/'application-candidate',raw/'application-trusted',cohort/'output',5]))
    return dict(argv=argv,cwd=str(ROOT),env={'LITEINST_EVALUATION':'1'},stdout=str(cohort/'stdout.txt'),stderr=str(cohort/'stderr.txt'),cpu=5,pins={str(HERE/'reproduce.py'):{},argv[0]:{},argv[2]:{},argv[3]:{},argv[9]:{}})


def caller_rows(base=8192):
    return [(base,b'\x53','push rbx'),(base+1,b'\x48\x89\xcb','mov rbx,rcx'),(base+4,b'\xff\xd0','call rax'),(base+6,b'\x48\x89\x03','mov QWORD PTR [rbx],rax'),(base+9,b'\x5b','pop rbx'),(base+10,b'\xc3','ret')]


def parent_rows(base=4096,child=4352):
    return [(base,b'\x56','push rsi'),(base+1,b'\xe8'+(child-(base+6)).to_bytes(4,'little',signed=True),f'call {child:x} <csv_fields>'),(base+6,b'\x5a','pop rdx'),(base+7,b'\x48\xc1\xe2\x20','shl rdx,0x20'),(base+11,b'\x48\x09\xd0','or rax,rdx'),(base+14,b'\xc3','ret')]


class Controls(unittest.TestCase):
    def test_fixed_catalog_stages_and_once_only_attempt(self):
        expected=[(k,s,c,v) for k in (10,1000) for s in R.SEEDS for c in range(1,17) for v in (1,2,3)]
        self.assertEqual(R.catalog(),expected);self.assertEqual(len(set(expected)),192)
        self.assertEqual(len(R.STAGES),len(set(R.STAGES)));self.assertEqual(len(R.STAGES),37)
        self.assertEqual(R.STAGES[-1],'native-outer');self.assertNotIn('legacy-native-outer',R.STAGES)
        r=R.initial_cohort();self.assertEqual((r['status'],r['attempts']),('UNRUN',0));L.begin(r)
        self.assertEqual((r['status'],r['attempts']),('FAILED',1))
        with self.assertRaises(AssertionError):L.begin(r)
        self.assertEqual(R.PROFILE,'normal-call-pair-original-rust-v1')

    def test_exact208_calibrations_preserve_old199(self):
        # Retain the published control name; eight additions now require216.
        peers={k:load('_pair_census_'+k,ROOT/N.MODULES[k]) for k in ('legacy','normal','whole')}
        prior=N.calibration_manifest(peers['legacy'],peers['normal'],peers['whole'])
        inventory=list(prior)+list(L.LEAF_CALIBRATIONS)+list(L.EFFICIENCY_CALIBRATIONS)+list(R.ORACLE_CONTROLS)+[N.IGNORED]
        got=R.calibration_inventory(L,prior,inventory,N.IGNORED);self.assertEqual(len(got),216)
        old=L.efficiency_calibration_inventory(prior,[n for n in inventory if n not in R.ORACLE_CONTROLS],N.IGNORED)
        self.assertEqual({n:got[n] for n in old},old);self.assertEqual(len(old),199)
        self.assertTrue(all(got[n] is False for n in R.ORACLE_CONTROLS))
        for name in inventory:
            with self.assertRaises(AssertionError):R.calibration_inventory(L,prior,[n for n in inventory if n!=name],N.IGNORED)
        for bad in (inventory+[inventory[0]],inventory+['unexpected::test']):
            with self.assertRaises(AssertionError):R.calibration_inventory(L,prior,bad,N.IGNORED)
        with self.assertRaises(AssertionError):R.calibration_inventory(L,prior,inventory,R.ORACLE_CONTROLS[0])

    def test_selected_native_sdk_core_censuses_are_exact(self):
        self.assertEqual((len(R.ORDINARY_CONTROLS),len(R.SDK_CONTROLS),len(R.CORE_CONTROLS)),(22,30,8))
        for names in (R.ORDINARY_CONTROLS,R.SDK_CONTROLS,R.CORE_CONTROLS):
            inventory=list(names)+['unrelated::test'];self.assertEqual(R.selected_inventory(inventory,names),names)
            for name in names:
                with self.assertRaises(AssertionError):R.selected_inventory([n for n in inventory if n!=name],names)
                with self.assertRaises(AssertionError):R.selected_inventory(inventory+[name],names)
            for prefix in {n.rsplit('::',1)[0]+'::' for n in names}:
                with self.assertRaises(AssertionError):R.selected_inventory(inventory+[prefix+'unexpected'],names)
        self.assertEqual((len(R.PYTHON_CONTROLS),len(R.RUNNER_CONTROLS)),(16,8))

    def test_request_original_executable_identity_geometry_and_cpu(self):
        req=request();cpus=[3,5,7]
        with patch.object(Path,'resolve',lambda p,strict=False:p):
            self.assertEqual(R.request_shape(req,cpus),Path(req['stdout']).parent)
            for index,value in [(0,str(ROOT/'target/release/ordinary-interval')),(1,'normal-rust-invoke-state'),(8,'other-app'),(9,req['argv'][8]),(10,'wrong-output'),(11,'3'),(4,'+4096'),(5,'81'),(7,'257'),(6,'4097'),(4,str((1<<64)-1))]:
                bad=copy.deepcopy(req);bad['argv'][index]=value
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for key,value in [('cpu',3),('cpu',True),('cwd','/'),('stdout',req['stderr'])]:
                bad=copy.deepcopy(req);bad[key]=value
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for key in req['pins']:
                bad=copy.deepcopy(req);del bad['pins'][key]
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for wrong in ([3,5],[3,3,7],[7,5,3],[3,5,1024]):
                with self.assertRaises(AssertionError):R.request_shape(req,wrong)
            bad=copy.deepcopy(req);bad['argv'][4:8]=['8191','15','16384','9']
            with self.assertRaises(AssertionError):R.request_shape(bad,cpus)

    def test_geometry_uses_complete_e8_target_and_historical_stack(self):
        p=R.parent_geometry(parent_rows(),4096,15,4352);self.assertEqual(p,F.geometry()[0])
        c=C.geometry(caller_rows(),8192,11);extra=R.stack_geometry(caller_rows(),8192,11,256)
        self.assertEqual((extra['delta'],extra['lowest_stack']),(16,8));c['lowest_stack']=extra['lowest_stack']
        self.assertEqual(c,F.geometry()[2])
        deep=[(8192,b'\x48\x81\xec\x00\x01\x00\x00','sub rsp,0x100'),(8199,b'\x48\x81\xc4\x00\x01\x00\x00','add rsp,0x100')]+caller_rows(8206)
        self.assertEqual(R.stack_geometry(deep,8192,25,256)['lowest_stack'],256)
        for mutate in (lambda r:r.__setitem__(1,(4097,b'\xe8\x00\x00\x00\x00','call 1100 <csv_fields>')),lambda r:r.__setitem__(5,(4110,b'\xc2','ret 0x8')),lambda r:r.pop(2)):
            rows=parent_rows();mutate(rows)
            with self.assertRaises((AssertionError,KeyError)):R.parent_geometry(rows,4096,15,4352)
        rows=parent_rows();rows[3]=(4103,b'\x48\xc1\xe2\x20','shl rdx,0x10')
        with self.assertRaises(AssertionError):R.parent_geometry(rows,4096,15,4352)
        rows=caller_rows();rows[0]=(8192,b'\x53','sub rsp,0x108')
        with self.assertRaises(AssertionError):R.stack_geometry(rows,8192,11,256)

    def test_prefix_retains_only_ordered_complete_rows(self):
        data=F.encoded(F.fixture())[0];header=F.W.HEADER
        rows,error=R.prefix_rows(data,header);self.assertEqual((len(rows),error),(192,None))
        short=b'\n'.join(data.split(b'\n')[:6])+b'\n';rows,error=R.prefix_rows(short,header)
        self.assertEqual((len(rows),error),(5,None))
        rows,error=R.prefix_rows(short+b'partial',header);self.assertEqual((len(rows),error),(5,'TRUNCATED_TAIL'))
        lines=data.splitlines();lines[2]=lines[1];rows,error=R.prefix_rows(b'\n'.join(lines)+b'\n',header)
        self.assertEqual((len(rows),error),(1,'FIRST_INVALID_ROW'))
        rows,error=R.prefix_rows(b'wrong\n',header);self.assertEqual((rows,error),([],'HEADER_OR_TRUNCATION'))
        lines=data.splitlines();words=lines[1].split(b',');words[0]=b'010';lines[1]=b','.join(words)
        self.assertEqual(R.prefix_rows(b'\n'.join(lines)+b'\n',header),([],'FIRST_INVALID_ROW'))

    def test_closed_failure_and_unrun_projection_remain_unqualified(self):
        result=dict(status='FAILED',revision='0'*40,cohort=R.initial_cohort(),custody_closed=False,retention_verified=False)
        p=R.public_projection(result);self.assertEqual(len(p['outcomes']),192);self.assertTrue(all(r['status']=='UNRUN' for r in p['outcomes']))
        row=result['cohort'];L.begin(row);row['observed']=F.fixture()[0][:3]
        p=R.public_projection(result);self.assertEqual([r['status'] for r in p['outcomes'][:4]],['OBSERVED_UNQUALIFIED']*3+['UNRUN'])
        self.assertEqual(p['status'],'UNQUALIFIED_PENDING_FINAL_RECEIPT');self.assertTrue(p['external_owner_required'])
        closed=dict(cleanup_complete=True,reaped_descendants=0,private_log_sha256=hashlib.sha256(b'').hexdigest(),exit_code=0,termination=None)
        L.closed_output(closed,b'');O.accept_closure(row,closed,b'')
        for key,value in [('exit_code',1),('exit_code',True),('cleanup_complete',False),('reaped_descendants',1),('termination','SIGKILL'),('private_log_sha256','0'*64)]:
            bad=dict(closed);bad[key]=value
            with self.assertRaises(AssertionError):O.accept_closure(row,bad,b'')
        signal=dict(closed,exit_code=-9);L.closed_output(signal,b'')
        with self.assertRaises(AssertionError):O.accept_closure(row,signal,b'')
        with self.assertRaises(AssertionError):L.closed_output(dict(closed,cleanup_complete=False),b'')

    def test_tool_alias_and_library_product_fail_closed(self):
        env={'PATH':'/fixed/toolchain:/usr/bin:/bin'};tools={'gcc':Path('/usr/bin/gcc-real')}
        with patch.object(Path,'resolve',lambda p,strict=False:Path('/usr/bin/gcc-real') if p==Path('/usr/bin/cc') else p):
            with patch.object(R.shutil,'which',return_value='/usr/bin/cc') as which:
                R.tool_alias(tools,env);which.assert_called_once_with('cc',path=env['PATH'])
            for selected in ('/fixed/toolchain/cc',None):
                with patch.object(R.shutil,'which',return_value=selected):
                    with self.assertRaises(AssertionError):R.tool_alias(tools,env)
        product=dict(reason='compiler-artifact',manifest_path=str(ROOT/'Cargo.toml'),target=dict(name='liteinst2',src_path=str(ROOT/'src/lib.rs'),kind=['lib'],crate_types=['lib']),profile=dict(opt_level='3',debuginfo=0,test=True,debug_assertions=True,overflow_checks=True),fresh=False,executable=str(ROOT/'target/release/deps/liteinst2-123abc'))
        def wire(p):return (json.dumps(p)+'\n'+json.dumps(dict(reason='build-finished',success=True))+'\n').encode()
        self.assertEqual(R.core_product(wire(product))[1],product)
        for mutate in (lambda p:p.update(manifest_path='/wrong'),lambda p:p['profile'].update(debug_assertions=False),lambda p:p.update(fresh=0),lambda p:p['target'].update(src_path='/wrong'),lambda p:p.update(executable=str(ROOT/'target/debug/deps/liteinst2-123abc'))):
            bad=copy.deepcopy(product);mutate(bad)
            with self.assertRaises(AssertionError):R.core_product(wire(bad))


if __name__=='__main__':unittest.main()
