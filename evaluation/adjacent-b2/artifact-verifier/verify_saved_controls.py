#!/usr/bin/env python3
"""Pure prospective W01 controls. Synthetic joins are not W01/corpus results."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import verify_saved as W

ROOT=Path(__file__).resolve().parents[3]
HERE=ROOT/'evaluation/offline-corpus'

def module(name,digest):
    path=HERE/name;raw=path.read_bytes()
    assert len(raw)<=W.MIB and W.sha(raw)==digest
    result=types.ModuleType('w01_control_'+name.replace('.','_'));result.__file__=str(path)
    exec(compile(raw,str(path),'exec'),result.__dict__)
    return result

A=module('adjacent_whole.py',W.DIAGNOSTIC)
C=module('disassembly_controls.py','f0d7f5572017fcc8a8f14c59e2980e97e50359e7d165c2b748de99439d93346d')
M=module('adjacent_routed_jmp_material.py','05e86b0652d7989a0f8abd825d5001d2e6fc5bcf4440504651633034b32834db')

def complete(program):
    h,n=W.COUNTS[program]
    return dict(status='STRUCTURAL_JOINS_COMPLETE',expected_heads=h,expected_selected=n,verifier_calls=1)

def report():
    return dict(expected_programs=2,expected_heads=187,expected_selected=42,
        configuration_complete=True,custody_complete=True,programs={p:complete(p) for p in W.PROGRAMS})

def response(program,candidate=b'candidate',images=16):
    return (f'LI2W01-PROGRAM\t1\nprogram\t{program}\nselected\t{W.COUNTS[program][1]}\nimages\t{images}\n'
        f'candidate_sha256\t{W.sha(candidate)}\nstructural_joins_complete\ttrue\nqualification_complete\tfalse\n'
        'classification_complete\tfalse\nnative_correctness_complete\tfalse\nperformance_eligible\tfalse\n').encode()

def handoff_fixture(program,auxiliary=False,routed=False):
    # This tests extraction after structural acceptance, not artifact admission.
    manifest=[];ledger=[];iid=0
    for owner in range(1,W.COUNTS[program][1]+1):
        pc=0x401000+owner*16
        manifest.append(f'site {owner} {pc} 2 0 0 1 0 1 0 1 1 observe original-decode')
        for local in range(2 if auxiliary and owner==1 else 1):
            chosen=local==0;logical=pc if chosen else pc+2;entry=0x500000+iid*4096
            ledger += [f'step\t{owner}\t{local}\trelocation\t{logical}\t{logical}\t{logical}\t{logical+5}',
                f'allocation\t{owner}\t{local}\t{entry}\t{entry+4096}\t4096']
            if routed and owner==1 and not chosen:
                ledger.append(f'entry-router-required\t{owner}\t{local}\t{logical+2}\t{entry+5}')
            ledger.append(f'image\t{iid}\t{owner}\t{entry}\t16\t'+W.sha(bytes(16))+f'\timage-{iid:04}.bin')
            requirements=[(1,0),(2,0),(3,0),(4,0),(7,0),(8,0)]+([(5,1)] if chosen else [])+([(6,0)] if routed and owner==1 else [])
            ledger += [f'unmet-requirement\t{iid}\t{code}\t{hook}' for code,hook in requirements];iid+=1
    return ('\n'.join(ledger)+'\n').encode(),('\n'.join(manifest)+'\n').encode()

class Controls(unittest.TestCase):
    def test_c01_nonempty_exact_source_inventory_and_build_contract(self):
        self.assertIn('Cargo.toml',W.VERIFIER_SOURCES)
        self.assertIn('src/verify/association.rs',W.VERIFIER_SOURCES)
        for name,pin in W.VERIFIER_SOURCES.items():
            self.assertEqual(W.sha((Path(W.__file__).parent/name).read_bytes()),pin)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);directory=root/'build';directory.mkdir();binary=root/'target/release/adjacent-b2-artifact-verifier'
            args=types.SimpleNamespace(verifier_build=directory,verifier_lock_sha256='1'*64)
            captured=dict(env={'fixed':'environment'},tools={name:dict(path='/tools/'+name) for name in ('cargo','python','helper','timeout')})
            ctx=types.SimpleNamespace(ROOT=root,load=mock.Mock(),closed=mock.Mock(return_value=(0,{'stdout':b'build-json'})))
            ctx.load.return_value.check_artifact=mock.Mock()
            manifest=root/W.CRATE/'Cargo.toml'
            argv=['/tools/cargo','build','--release','--locked','--offline','--manifest-path',str(manifest),'--bin','adjacent-b2-artifact-verifier','--message-format=json']
            request,command=W.request_and_command(ctx,captured,directory,argv,(120,180,128))
            controls=('request.json','command.json','parent-closed.json','receipt.json','stdout.txt','stderr.txt','helper.stdout','helper.stderr')
            pins={str(root/W.CRATE/name):dict(sha256=digest) for name,digest in W.VERIFIER_SOURCES.items()}
            pins.update({str(root/W.CRATE/'Cargo.lock'):dict(sha256='1'*64),str(binary):dict(sha256='2'*64)})
            pins.update({str(directory/name):dict(sha256='3'*64) for name in controls})
            closed=dict(schema='LI2W01-VERIFIER-BUILD-1',files=pins,lock_sha256='1'*64,configuration_complete=True)
            def check(value,cmd=command,code=0):
                raw=json.dumps(value).encode();args.verifier_build_sha256=W.sha(raw)
                def read(path,*unused,**kw):
                    return raw if path==directory/'closed.json' else json.dumps(cmd).encode() if path==directory/'command.json' else b'bound-source-or-stream'
                ctx.read=read;ctx.closed.return_value=(code,{'stdout':b'build-json'})
                return W.verifier_build(ctx,A,args,captured)
            self.assertEqual(check(closed),binary)
            ctx.closed.assert_called_with(directory,request)
            self.assertEqual(request['cpu_seconds'],120);self.assertEqual(command['parent_seconds'],205)
            for mutate in ('missing-source','extra-member','source-pin','lock','schema','configuration'):
                bad=copy.deepcopy(closed)
                if mutate=='missing-source':bad['files'].pop(str(manifest))
                elif mutate=='extra-member':bad['files']['unbound']=dict(sha256='0'*64)
                elif mutate=='source-pin':bad['files'][str(manifest)]['sha256']='0'*64
                elif mutate=='lock':bad['lock_sha256']='0'*64
                elif mutate=='schema':bad['schema']='other'
                else:bad['configuration_complete']=False
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):check(bad)
            with self.assertRaises(ValueError):check(closed,dict(command,parent_seconds=206))
            with self.assertRaises(ValueError):check(closed,code=1)

    def test_c02_exact_ten_rows_positive_before_each_response_mutant(self):
        for p in W.PROGRAMS:
            good=response(p);self.assertEqual(len(good.splitlines()),10)
            self.assertEqual(W.result_row(A,p,good,b'',0,b'candidate'),dict(complete(p),candidate_sha256=W.sha(b'candidate')))
            for row in good.splitlines(keepends=True):
                with self.subTest(program=p,row=row),self.assertRaises((ValueError,A.Failure)):
                    W.result_row(A,p,good.replace(row,b'',1),b'',0,b'candidate')
            for bad in (good+b'extra\tfalse\n',good.replace(b'\n',b'\r\n'),good[:-1],response(p,images=0),response(p,images=33),good.replace(b'false',b'true',1),good.replace(b'images\t16',b'images\t016'),response(p,b'other')):
                with self.assertRaises((ValueError,A.Failure)):W.result_row(A,p,bad,b'',0,b'candidate')
            for code,stderr in ((1,b''),(0,b'noise')):
                with self.assertRaises(ValueError):W.result_row(A,p,good,stderr,code,b'candidate')

    def test_c03_exact_body_and_framing_bound_before_file_creation(self):
        self.assertEqual(W.TRANSPORT_BYTES,70*1048576+264*256)
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'transport';expected={n:b'x' for n in W.EXPECTED_NAMES}
            digest=W.pack(path,'checksum',b'original',expected,{'candidate.elf':b'candidate'})
            raw=path.read_bytes();self.assertEqual(W.sha(raw),digest);self.assertTrue(raw.endswith(b'END\n'))
            for product in ({'../escape':b''},{'bad\nname':b''},{'x':b'x'*(16*W.MIB+1)}, {str(i):b'' for i in range(257)}):
                bad=Path(t)/'bad'
                with self.assertRaises(ValueError):W.pack(bad,'checksum',b'o',expected,product)
                self.assertFalse(bad.exists())
            body={str(i):16*W.MIB for i in range(4)}
            self.assertEqual(W.pack_sizes('checksum',W.MIB,{n:W.MIB for n in W.EXPECTED_NAMES},body),70*W.MIB)
            with self.assertRaises(ValueError):W.pack_sizes('checksum',W.MIB,{n:W.MIB for n in W.EXPECTED_NAMES},{**body,'extra':1})

    def test_n01_handoff_retains_auxiliary_routes_and_every_unresolved_requirement(self):
        for program in W.PROGRAMS:
            plain,selected=handoff_fixture(program)
            empty=W.runtime_handoff(A,plain,selected)
            self.assertTrue(empty['required_routes_empty']);self.assertEqual(empty['entry_router_required'],[])
            raw,selected=handoff_fixture(program,True,True)
            h=W.runtime_handoff(A,raw,selected)
            self.assertEqual(h['plan_ledger_sha256'],W.sha(raw));self.assertEqual(len(h['images']),W.COUNTS[program][1]+1)
            self.assertEqual(h['entry_router_required'],[dict(selected_id=1,step=1,image_id=1,original_pc=0x401014,target_pc=0x501005)])
            self.assertEqual([i['role'] for i in h['images'][:2]],['selected','auxiliary'])
            self.assertEqual(h['images'][1]['unresolved_requirements'],[dict(code=c,hook=0) for c in (1,2,3,4,7,8,6)])
            self.assertFalse(h['required_routes_empty']);self.assertFalse(h['execution_authorized']);self.assertEqual(h['N01'],'UNRUN')
            for row in raw.splitlines(keepends=True):
                if row.startswith((b'unmet-requirement\t',b'allocation\t',b'image\t',b'entry-router-required\t')):
                    with self.subTest(program=program,row=row),self.assertRaises((ValueError,KeyError,A.Failure)):
                        W.runtime_handoff(A,raw.replace(row,b'',1),selected)
            good=report();good['programs'][program]['runtime_handoff']=h
            other=next(p for p in W.PROGRAMS if p!=program);good['programs'][other]['runtime_handoff']=empty
            self.assertEqual(W.aggregate(good),0);self.assertFalse(good['required_routes_empty']);self.assertFalse(good['execution_authorized'])

    def test_v01_actual_authored_both_program_near_short_expected_wrappers(self):
        for program in W.PROGRAMS:
            for short in (False,True):
                inputs=C.fixture(program,short_jumps=short);pins={n:W.sha(b) for n,b in inputs.items()}
                material=M.attempt_adjacent_routed_jmp(program,inputs,pins,upper=2,lower=1,joint=2)['files']
                ctx=types.SimpleNamespace(D=M.D)
                expected=W.expected_files(ctx,A,program,inputs,material)
                self.assertEqual(set(expected),set(W.EXPECTED_NAMES))
                selection=expected['selection.txt'].decode().splitlines()
                sites=[line.split() for line in selection if line.startswith('site ')]
                self.assertEqual(len(sites),W.COUNTS[program][1]);self.assertEqual([int(s[1]) for s in sites],list(range(1,len(sites)+1)))
                self.assertIn('adjacent-pairs original-geometry-jcc-or-routed-jmp-v1',selection)
                self.assertIn('adjacent-pair-budgets 2 1 2',selection)
                self.assertEqual(expected['disassembly-policy.txt'],material['policy.txt'])
                for s in sites:
                    pc,block,size=map(int,(s[2],s[9],s[10]));self.assertLessEqual(block,pc);self.assertLess(pc,block+size)
                for key in ('original','object','heads'):
                    changed=dict(inputs);changed[key]=inputs[key][:-1]
                    with self.subTest(program=program,short=short,key=key),self.assertRaises((AssertionError,ValueError,IndexError,KeyError)):
                        W.expected_files(ctx,A,program,changed,material)

    def test_v06_complete_aggregation_and_every_either_program_failure(self):
        good=report();self.assertEqual(W.aggregate(good),0);self.assertTrue(good['W01'])
        for p in W.PROGRAMS:
            for status in ('UNRUN','FAILED','UNSATISFIED','PRODUCER_REFUSED','MATERIALS_REFUSED','PRODUCER_FAILED'):
                r=report();r['programs'][p]['status']=status;self.assertEqual(W.aggregate(r),1)
                self.assertFalse(r['W01']);self.assertEqual(tuple(r['programs']),W.PROGRAMS)
                self.assertTrue(all(r[k] is False for k in A.FALSE_FLAGS));self.assertEqual(r['N01'],'UNRUN')
        for key in ('configuration_complete','custody_complete'):
            r=report();r[key]=False;self.assertEqual(W.aggregate(r),1)
        for key in ('expected_programs','expected_heads','expected_selected'):
            r=report();r[key]-=1
            with self.assertRaises(ValueError):W.aggregate(r)

    def test_v06_prior_failure_labels_never_dispatch_material_or_verifier(self):
        for p in W.PROGRAMS:
            for status in ('UNRUN','FAILED','MATERIALS_REFUSED','PRODUCER_FAILED'):
                saved=dict(status=status,failure=dict(stage='original-failure',detail='retained'),output_membership_complete=False,output_stability='FAILED',blocked_by=dict(stage='original-retention'))
                ctx=types.SimpleNamespace(invoke=mock.Mock(side_effect=AssertionError('no dispatch')))
                with mock.patch.object(W,'material_inputs',side_effect=AssertionError('no new material attempt')):
                    row=W.check_saved(ctx,A,None,None,p,saved,None,[])
                self.assertEqual(row['status'],status);self.assertEqual(row['original_diagnostic'],saved)
                self.assertEqual(row['verifier_calls'],0);ctx.invoke.assert_not_called()

    def test_c05_actual_saved_adapter_calls_only_bound_verifier_once(self):
        for fault in ('none','response','closure','retained-change','transport-change'):
            with tempfile.TemporaryDirectory() as t:
                root=Path(t);program='checksum';diagnostic=root/'diagnostic';directory=diagnostic/program
                (directory/'importer/product').mkdir(parents=True);output=root/'output';output.mkdir()
                inputs={k:k.encode() for k in ('original','object','source','linker','target','heads')};objdump={'start':b'disassembly'}
                material={'ledger.txt':b'ledger','policy.txt':b'policy','source-inventory.tsv':b'inventory'}
                result=dict(status='MATERIALS_READY',files=material);expected={n:b'expected' for n in W.EXPECTED_NAMES}
                plan,expected['selection.txt']=handoff_fixture(program)
                blobs=dict(material);blobs.update({'heads.txt':inputs['heads'],
                    'input-hashes.json':json.dumps({k:W.sha(v) for k,v in inputs.items()}).encode(),
                    'raw-input-hashes.json':json.dumps(dict(inputs={k:W.sha(v) for k,v in inputs.items() if k!='heads'},objdump={k:W.sha(v) for k,v in objdump.items()})).encode(),
                    'materials.json':json.dumps(dict(status='MATERIALS_READY',files={n:dict(bytes=len(b),sha256=W.sha(b)) for n,b in material.items()})).encode(),
                    'importer/product/candidate.elf':b'candidate','importer/product/plan-ledger.tsv':plan})
                for name,raw in blobs.items():(directory/name).write_bytes(raw)
                previous=A.OutputReader(directory)
                try:
                    for name in blobs:previous.read(name)
                    files=previous.pins();dirs=previous.seal()
                finally:previous.close()
                saved=dict(status='PRODUCER_COMPLETE_UNVERIFIED',output_membership_complete=True,output_stability='VERIFIED',output_files=files,output_directories=dirs,
                    producer_dispatches=1,material_calls=1,producer_exit=0,producer_candidate_complete=True,selection_sha256='s'*64,producer_roster_join=True,diagnostic_capture_complete=True)
                if fault=='retained-change':(directory/'importer/product/candidate.elf').write_bytes(b'changed')
                args=types.SimpleNamespace(diagnostic=diagnostic,output=output,capture=root/'capture')
                captured=dict(binary=Path('/producer/never-dispatched'),env={},tools={n:dict(path='/tools/'+n) for n in ('python','helper','timeout')},stable=mock.Mock())
                invoke=mock.Mock(side_effect=RuntimeError('uncertain child closure')) if fault=='closure' else mock.Mock(return_value=(0,dict(stdout=response(program,b'wrong' if fault=='response' else b'candidate'),stderr=b'')))
                if fault=='transport-change':
                    def change_transport(attempt,argv,*unused):
                        Path(argv[1]).write_bytes(b'changed');return 0,dict(stdout=response(program),stderr=b'')
                    invoke.side_effect=change_transport
                ctx=types.SimpleNamespace(ROOT=root,B=types.SimpleNamespace(HELPER_SHA='h'*64),invoke=invoke,read=lambda path,**kw:Path(path).read_bytes())
                retained=[];verifier=Path('/bound/verifier')
                try:
                    with mock.patch.object(W,'material_inputs',return_value=(inputs,objdump,result,material,expected)),mock.patch.object(A,'check_closed',return_value=(0,dict(stdout=dict(data=b'producer'),stderr=dict(data=b'')))),mock.patch.object(A,'check_stdout'),mock.patch.object(A,'check_product',return_value=dict(selection_sha256='s'*64,producer_roster_join=True)):
                        if fault=='none':self.assertEqual(W.check_saved(ctx,A,args,captured,program,saved,verifier,retained)['status'],'STRUCTURAL_JOINS_COMPLETE')
                        else:
                            with self.assertRaises(A.CustodyFailure if fault in ('closure','retained-change','transport-change') else ValueError):W.check_saved(ctx,A,args,captured,program,saved,verifier,retained)
                    self.assertEqual(invoke.call_count,0 if fault=='retained-change' else 1)
                    if invoke.call_count:
                        argv=invoke.call_args.args[1];self.assertEqual(argv[0],str(verifier))
                        if fault!='transport-change':self.assertEqual(argv[2],W.sha(Path(argv[1]).read_bytes()))
                    self.assertEqual(saved['status'],'PRODUCER_COMPLETE_UNVERIFIED')
                    self.assertEqual(len(retained),1)
                    if fault!='retained-change':retained[0][1].verify_retained(dirs)
                finally:
                    for _,reader,_ in retained:reader.close()

    def frame(self,path):
        root=Path(path);(root/'ignored').mkdir();diagnostic=root/'ignored/diagnostic';diagnostic.mkdir()
        capture=root/'ignored/capture';capture.mkdir()
        saved=dict(milestone='D01_FULL_ROSTER_PRODUCER_DIAGNOSTIC',capture=str(capture),capture_sha256='c'*64,
            placement_profile=A.ROUTED.material,capture_profile=A.ROUTED.capture,importer_profile=A.ROUTED.importer,
            adjacent_upper=2,adjacent_lower=1,adjacent_joint=2,aggregate_output_read_bytes_per_program=64*W.MIB,
            expected_programs=2,expected_heads=187,expected_selected=42,configuration_complete=True,
            first_pins={},programs={p:dict(status='PRODUCER_COMPLETE_UNVERIFIED') for p in W.PROGRAMS},**dict.fromkeys(A.FALSE_FLAGS,False))
        raw=json.dumps(saved).encode();(diagnostic/'closed.json').write_bytes(raw)
        args=types.SimpleNamespace(output=root/'ignored/w01',capture=capture,capture_sha256='c'*64,diagnostic=diagnostic,diagnostic_sha256=W.sha(raw))
        B=types.SimpleNamespace(write=lambda p,v:p.write_text(json.dumps(v)),identity=mock.Mock(side_effect=AssertionError('unexpected pin')))
        ctx=types.SimpleNamespace(ROOT=root,B=B,invoke=mock.Mock(side_effect=AssertionError('producer/native dispatch forbidden')))
        captured=dict(stable=lambda:None)
        def authenticate(ctx,args,r,profile):
            self.assertIs(profile,A.ROUTED);r['configuration_complete']=True;return captured
        return args,ctx,captured,authenticate

    def test_v06_real_run_local_refusal_continues_once_global_abort_retains_unrun(self):
        for fault in ('none','local-first','local-second','custody-first','first-output-changes'):
            with tempfile.TemporaryDirectory() as t:
                args,ctx,captured,auth=self.frame(t);calls=[];readers=[]
                def action(ctx,a,args,captured,program,saved,binary,retain):
                    calls.append(program)
                    if fault=='custody-first':raise A.CustodyFailure('closure','uncertain')
                    if fault=='local-first' and program==W.PROGRAMS[0]:raise ValueError('closed local refusal')
                    if fault=='local-second' and program==W.PROGRAMS[1]:return dict(complete(program),status='PRODUCER_REFUSED',original_diagnostic=saved,verifier_calls=0)
                    p=args.output/program;p.mkdir();(p/'retained').write_bytes(b'unchanged')
                    reader=A.OutputReader(p);reader.read('retained');pins=reader.seal();retain.append((program,reader,dict(output_directories=pins)));readers.append(reader)
                    if fault=='first-output-changes' and program==W.PROGRAMS[1]:(args.output/W.PROGRAMS[0]/'retained').write_bytes(b'changed')
                    return complete(program)
                with mock.patch.object(A,'authenticate_capture',side_effect=auth),mock.patch.object(W,'verifier_build',return_value=Path('/bound/verifier')),mock.patch.object(W,'check_saved',side_effect=action):
                    code=W.run(args,ctx,A)
                r=json.loads((args.output/'closed.json').read_bytes());self.assertEqual(code,0 if fault=='none' else 1)
                self.assertEqual(calls,[W.PROGRAMS[0]] if fault=='custody-first' else list(W.PROGRAMS))
                self.assertEqual(tuple(r['programs']),W.PROGRAMS);self.assertEqual(r['producer_dispatches'],0);ctx.invoke.assert_not_called()
                self.assertEqual((r['expected_heads'],r['expected_selected'],r['expected_datasets_per_program'],r['N01_invocations']),(187,42,10,40))
                self.assertFalse(r['native_correctness_complete']);self.assertFalse(r['performance_eligible'])
                if fault=='custody-first':self.assertEqual(r['programs'][W.PROGRAMS[1]]['status'],'UNRUN')
                if fault=='first-output-changes':self.assertFalse(r['custody_complete']);self.assertIn('error',r)
                for reader in readers:
                    with self.assertRaises(OSError):reader.verify()

if __name__=='__main__':unittest.main()
