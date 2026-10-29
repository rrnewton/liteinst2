#!/usr/bin/env python3
"""Fabricated driver/authority controls; never launch qualification or native work."""
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
from types import SimpleNamespace
import unittest


def local(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    assert spec is not None and spec.loader is not None
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


HERE=Path(__file__).resolve().parent
D=local('_backoff_driver',HERE/'backoff_probe.py')
P=local('_backoff_shared_tests',HERE/'throughput_probe.py')
L=local('_backoff_legacy_tests',HERE/'test_throughput_probe.py')
C=local('_backoff_census_tests',HERE.parent/'selected-work/check_output.py')


class QualifiedFixture:
    """Synthetic retained files only; fixture authentication is an explicit spy."""
    def __init__(self, root, fault=None):
        self.repo=root/'repo';self.repo.mkdir();self.q=self.repo/'ignored/qualified';self.q.mkdir(parents=True)
        self.env={'LC_ALL':'C','CARGO_BUILD_JOBS':'4'};self.cpus=[2,3,7,9];self.revision='1'*40
        self.before={'tools/unwind-oracle/bounded_command.py':dict(bytes=9,sha256='e'*64)}
        self.pins=P.Pins();self.calls=[]
        def put(path, data):
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);return P.digest(path)
        def js(path, value):return put(path,P.encoded(value))
        self.put,self.js=put,js
        tool=self.repo/'tool';put(tool,b'fabricated tool');self.tools={'cargo':tool}
        old,names=L.qualified_fixture()
        self.prior=SimpleNamespace(STAGES=names[:10],REFERENCE_STAGES=names[10:23],
            REFERENCE_WORK_STAGES=names[23:26],REFERENCE_LEG_STAGES=names[26:30],OBSERVER_WORK_STAGES=names[30:])
        manifest=js(self.q/'sources-before.json',self.before)
        js(self.q/'sources-after.json',{} if fault=='source-after' else self.before)
        old['sources']=dict(count=len(self.before),manifest=manifest)
        nested=self.q/'strnlen-prerequisite';nested.mkdir()
        private=dict(env=self.env,affinity=self.cpus,tools={'cargo':str(tool)})
        if fault=='affinity':private['affinity']=[2,3,7]
        if fault=='environment':private['env']=dict(self.env,CARGO_BUILD_JOBS='5')
        js(nested/'private-environment.json',private)
        old['tools']={'cargo':P.digest(tool)}
        if fault=='tool-hash':old['tools']['cargo']=dict(bytes=0,sha256='0'*64)
        binary=self.repo/'target/release/ordinary-interval';put(binary,b'fabricated production image')
        test=self.repo/'target/release/deps/ordinary_interval-abcd';put(test,b'fabricated libtest image')
        profile=dict(opt_level='3',debuginfo=0,test=True,debug_assertions=True,overflow_checks=True)
        if fault=='profile':profile['overflow_checks']=False
        product=dict(reason='compiler-artifact',profile=profile,fresh=False,executable=str(test),
            manifest_path=str(self.repo/'tools/rapid-profiler/Cargo.toml'),target=dict(name='ordinary-interval',
            src_path=str(self.repo/'tools/rapid-profiler/ordinary-interval/main.rs'),kind=['bin'],crate_types=['bin']))
        messages=[product,dict(reason='build-finished',success=True)]
        if fault=='duplicate-product':messages.insert(0,copy.deepcopy(product))
        build=b''.join(P.encoded(m).replace(b'\n',b'')+b'\n' for m in messages)
        inventory=[*D.RUST,*D.OWNER_RUST,'other::literal_test']
        if fault=='inventory':inventory.append(D.PREFIX+'unexpected_test')
        listing=(''.join(n+': test\n' for n in inventory)+f'\n{len(inventory)} tests, 0 benchmarks\n').encode('ascii')
        def stage(directory,name,stdout=b''):
            directory.mkdir();(directory/'tmp').mkdir()
            request=P.request(['/fabricated-command'],self.repo,self.env,directory)
            if fault=='stage-cwd' and name==names[0]:request['cwd']='/wrong'
            request_pin=js(directory/'request.json',request)
            stdout_pin=put(directory/'stdout.txt',stdout);stderr_pin=put(directory/'stderr.txt',b'')
            closed,receipt,log,_,_,_,_=L.closure_fixture()
            receipt.update(request_sha256=request_pin['sha256'],helper_sha256=self.before['tools/unwind-oracle/bounded_command.py']['sha256'],
                stdout_sha256=stdout_pin['sha256'],stderr_sha256=stderr_pin['sha256'])
            if fault=='rescue' and name==names[0]:receipt['cleanup_events']=[{'fabricated':1}]
            receipt_pin=js(directory/'receipt.json',receipt)
            closed['private_log_sha256']=js(directory/'parent.log',log)['sha256']
            closed_pin=js(directory/'parent-closed.json',closed)
            return dict(name=name,status='PASS',request=request_pin,receipt=receipt_pin,stdout=stdout_pin,
                stderr=stderr_pin,closed=closed_pin,cpu_seconds=20,wall_seconds=30,file_bytes=P.MIB)
        old['stages']=[stage(self.q/name,name) for name in names]
        nested_result=dict(revision=self.revision,status='PASS',stages=[stage(nested/'work-validator-build','work-validator-build',build),
            stage(nested/'work-validator-list','work-validator-list',listing)],
            artifacts={'work-validator':dict(binary=P.digest(test),profile=profile,cargo_fresh=False)})
        # Group summaries retain the exact legacy names/statuses; all actual stage files join separately.
        parent_log=put(self.q/'prerequisite.log',b'fabricated closed parent\n')
        closed=dict(exit_code=0,termination=None,cleanup_complete=True,reaped_descendants=0,private_log_sha256=parent_log['sha256'])
        if fault=='parent-log':closed['private_log_sha256']='0'*64
        old['prerequisite']=dict(result=js(nested/'result.json',nested_result),
            command=js(self.q/'prerequisite-command.json',{'fabricated':True}),closed=js(self.q/'prerequisite-closed.json',closed))
        for name in ('reference-exact-candidate.so','reference-exact-final.so'):put(self.q/name,b'fabricated complete subject')
        for name in ('caller-candidate.so','caller.so'):put(self.q/name,b'fabricated complete caller')
        if fault=='helper-alias':
            (self.q/'caller-candidate.so').unlink();os.link(self.q/'caller.so',self.q/'caller-candidate.so')
        details=dict(revision=self.revision,elf_va=4096,length=37,label='normal-exact-37-v1')
        if fault=='selection-revision':details['revision']='2'*40
        js(self.q/'reference-exact-selection.json',details)
        authority={key:P.digest(path) for key,path in (
            ('binary',binary),('subject',self.q/'reference-exact-final.so'),('selection',self.q/'reference-exact-selection.json'),
            ('helper_candidate',self.q/'caller-candidate.so'),('helper',self.q/'caller.so'))}
        old['observer_work']['modes']=[dict(authority,mode=mode,status='PASS',calls=3072,
            observation=dict(calls=3072,helper_calls=1536,instructions=614400),process_cpu_seconds=20,process_wall_seconds=30,file_bytes=P.MIB)
            for mode in ('native','always-on')]
        if fault=='population':old['observer_work']['modes'][1]['observation']['instructions']=614399
        old['reference_exact']['subject']=dict(candidate=P.digest(self.q/'reference-exact-candidate.so'))
        old['artifacts']={'ordinary-interval':P.digest(binary),'caller':P.digest(self.q/'caller.so')}
        js(self.q/'result.json',old)
        self.old,self.details,self.inventory=old,details,inventory
        self.fixture=SimpleNamespace(authenticate=self.authenticate)

    def authenticate(self, subject, trusted, va, length, selection, sha):
        self.calls.append((subject,trusted,va,length,selection,sha))
        assert (subject,trusted,va,length,selection,sha)==(self.q/'reference-exact-candidate.so',
            self.q/'reference-exact-final.so',4096,37,self.q/'reference-exact-selection.json',P.digest(selection)['sha256'])
        assert subject.read_bytes()==trusted.read_bytes() and P.stamp(subject)[:2]!=P.stamp(trusted)[:2]
        return {k:v for k,v in self.details.items() if k!='revision'}

    def call(self):
        return P.qualified_inputs(self.repo,self.q,self.revision,self.env,self.cpus,self.before,self.tools,
            self.pins,self.prior,C,self.fixture,D.INVENTORY_PREFIX,D.RUST+D.OWNER_RUST)


class Controls(unittest.TestCase):
    def refuse(self, fn, *args):
        with self.assertRaises(AssertionError):fn(*args)

    def test_fixed_catalog_role_argv_and_request_bounds(self):
        expected=[dict(trial=i+1,qualification=i//2+1,k=(10,1000)[i%2]) for i in range(10)]
        self.assertEqual(D.catalog(),expected)
        for key in expected:
            argv=D.trial_argv('/taskset','/app',key,[2,3,7,9],'/candidate','/trusted',4096,'/caller-candidate','/caller')
            self.assertEqual(argv,['/taskset','--cpu-list','3,9','/app','normal-observer-backoff',str(key['k']),'3','9',
                '/candidate','/trusted','4096','37','/caller-candidate','/caller'])
            request=P.request(argv,Path('/repo'),{},Path('/output'));P.check_request(request,request)
            self.assertEqual((request['cpu_seconds'],request['wall_seconds'],request['file_bytes']),(20,30,1048576))
            bad=dict(request,wall_seconds=31);self.refuse(P.check_request,bad,bad)
        for cpus in ([2,3,3,9],[2,3,7],[2,3,7,1024],[9,7,3,2]):
            self.refuse(D.trial_argv,'/taskset','/app',expected[0],cpus,'/c','/t',4096,'/cc','/ct')
        self.refuse(D.trial_argv,'/t','/a',dict(expected[0],k=9),[2,3,7,9],'/c','/t',4096,'/cc','/ct')
        self.assertEqual([(r['control'],r['k'],r['hold_ordinal']) for r in D.owner_catalog()],[(1,10,22),(2,1000,1006)])
        for key in D.owner_catalog():
            argv=D.trial_argv('/t','/a',key,[2,3,7,9],'/c','/t',4096,'/cc','/ct',True)
            self.assertEqual(argv[4],'normal-observer-backoff-pending-owner')
            self.refuse(D.trial_argv,'/t','/a',key,[2,3,7,9],'/c','/t',4096,'/cc','/ct')

    def test_closed_exit_and_signal_failures_continue_without_pass(self):
        parsed=dict(status='FUNCTIONAL_PASS',calls=3072,row_count=3072,rows=[None]*3072,helper_calls=1536,instructions=614400,batches=128)
        self.assertEqual(D.outcome(0,parsed),('PASS',None))
        for code,reason in ((0,'FUNCTIONAL_OUTPUT_REFUSAL'),(1,'CLOSED_CHILD_NONZERO'),(-6,'CLOSED_CHILD_SIGNAL')):
            closed=P.closed_request(*L.closure_fixture(code));self.assertEqual(closed,code)
            self.assertEqual(D.outcome(code,None),('FAILED',reason))
            rows=[dict(k,status='UNRUN') for k in D.catalog()];D.advance(rows,0)
            rows[0].update(closed=True,exit=code,reason=reason);D.advance(rows,1)
            self.assertEqual(rows[0]['status'],'FAILED');self.assertEqual(rows[1]['status'],'FAILED')
        self.assertEqual(D.outcome(-6,parsed),('FAILED','CLOSED_CHILD_SIGNAL'))
        self.refuse(D.outcome,True,parsed);self.refuse(D.outcome,0,dict(parsed,row_count=3071))

    def test_custody_failures_and_changed_catalog_withhold_remainder(self):
        rows=[dict(k,status='UNRUN') for k in D.catalog()];D.advance(rows,0)
        self.refuse(D.advance,rows,1);self.assertEqual(sum(r['status']=='UNRUN' for r in rows),9)
        for index,key,value in ((0,'termination','wall'),(0,'cleanup_complete',False),(1,'absence_proof','unknown'),
                (1,'cleanup_events',[1]),(1,'inputs_unchanged',False),(1,'request_sha256','0'*64)):
            fixture=list(L.closure_fixture(-6));fixture[index][key]=value;self.refuse(P.closed_request,*fixture)
        rows[0]['closed']=True;bad=copy.deepcopy(rows);bad[1]['k']=10;self.refuse(D.advance,bad,1)
        bad=copy.deepcopy(rows);bad[3]['status']='PASS';self.refuse(D.advance,bad,1)
        D.advance(rows,1);self.assertEqual(rows[0]['status'],'FAILED')
        owners=[dict(k,status='PASS',closed=True) for k in D.owner_catalog()];D.owners_complete(owners)
        for status in ('FAILED','UNRUN'):
            bad=copy.deepcopy(owners);bad[0]['status']=status;self.refuse(D.owners_complete,bad)
        bad=copy.deepcopy(owners);bad[1]['closed']=False;self.refuse(D.owners_complete,bad)
        self.refuse(D.owners_complete,list(reversed(owners)))

    def test_projection_preserves_all_outcomes_and_raw_counts_without_timing(self):
        rows=[dict(k,status='UNRUN') for k in D.catalog()]
        rows[0].update(status='PASS',closed=True,wire_rows=3072,arms=1,sampled=10,unsampled=3062,
            files={'stdout.txt':dict(sha256='a'*64),'calls.csv':dict(sha256='b'*64)},private_path='/secret')
        rows[1].update(status='FAILED',closed=True,exit=-6,reason='CLOSED_CHILD_SIGNAL')
        pins={1:dict(bytes=2,sha256='c'*64),2:dict(bytes=3,sha256='d'*64)};saved=copy.deepcopy(rows)
        view=D.projection(rows,pins,False)
        self.assertEqual((view['pass_count'],view['failed_count'],view['unrun_count'],view['wire_rows']),(1,1,8,3072))
        self.assertEqual(view['trials'][1]['exit'],-6);self.assertEqual(view['trials'][0]['calls_sha256'],'b'*64)
        self.assertTrue(all(set(r)==set(D.FIELDS) for r in view['trials']));self.assertEqual(rows,saved)
        self.assertNotIn(b'/secret',P.encoded(view));self.assertNotIn('timing',view);self.refuse(D.projection,rows,pins,True)
        self.refuse(D.projection,rows,{1:dict(bytes=-1,sha256='z'*64)},False)
        full=[dict(k,status='PASS',closed=True,wire_rows=3072) for k in D.catalog()]
        allpins={i:dict(bytes=1,sha256=f'{i:064x}') for i in range(1,11)}
        self.assertEqual(D.projection(full,allpins,True)['wire_rows'],30720)
        full[4]['closed']=False;self.refuse(D.projection,full,allpins,True)

    def test_qualified_inputs_return_exact_authenticated_context(self):
        with tempfile.TemporaryDirectory() as temp:
            f=QualifiedFixture(Path(temp));result=f.call();f.pins.check()
            self.assertEqual(set(result),{'binary','test_binary','inventory','subject','trusted','selection','caller_candidate','caller',
                'details','selected','artifacts','prerequisite','old'})
            self.assertEqual(result['old'],f.old);self.assertEqual(result['inventory'],f.inventory)
            self.assertEqual(result['details'],f.details);self.assertEqual(len(f.calls),1)
            self.assertEqual(result['artifacts']['subject'],P.digest(result['subject']))
            self.assertEqual(result['prerequisite']['result'],P.digest(f.q/'result.json'))
            self.assertEqual(result['prerequisite']['closure']['owned_stages'],34)
            self.assertEqual(result['selected'],{k:v for k,v in f.details.items() if k!='revision'})
            # The helper retains every completed stage; it cannot refresh changed authority.
            (f.q/'stage-0/stdout.txt').write_bytes(b'drift')
            self.refuse(f.pins.check)

    def test_qualified_inputs_refuse_mutated_context_and_artifact_authority(self):
        for fault in ('source-after','affinity','environment','tool-hash','profile','duplicate-product','inventory',
                'stage-cwd','rescue','parent-log','helper-alias','selection-revision','population'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
                f=QualifiedFixture(Path(temp),fault);self.refuse(f.call)
                self.assertEqual(f.calls,[])
        with tempfile.TemporaryDirectory() as temp:
            f=QualifiedFixture(Path(temp));f.before['tools/unwind-oracle/bounded_command.py']['sha256']='0'*64
            self.refuse(f.call)

    def test_shared_closure_inventory_and_pins_remain_strict(self):
        methods=('test_a','test_b');source=b'class Controls:\n def test_a(self): pass\n def test_b(self): pass\n'
        P.python_census(source,'Controls',methods)
        P.python_controls(b'',b'..\n----------------------------------------------------------------------\nRan 2 tests in 0.001s\n\nOK\n',methods)
        self.refuse(P.python_census,source+b' def test_extra(self): pass\n','Controls',methods)
        self.refuse(P.python_controls,b'',b'.s\n---\nRan 2 tests in 0.001s\n\nOK (skipped=1)\n',methods)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'receipt';pins=P.Pins();P.freeze(path,b'original',pins);saved=copy.deepcopy(pins.values)
            path.write_bytes(b'changed');self.refuse(pins.retain,path);self.assertEqual(pins.values,saved)
        self.assertEqual(len(P.CONTROLS),10)

    def test_local_import_and_optimized_refusal(self):
        self.assertEqual(Path(D.__file__).resolve(),HERE/'backoff_probe.py')
        self.assertEqual(Path(P.__file__).resolve(),HERE/'throughput_probe.py')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in ('backoff_probe','throughput_probe','backoff_work'):
                (root/(name+'.py')).write_text('raise RuntimeError("ambient import")\n',encoding='ascii')
            env=dict(os.environ,PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
            for path in (HERE/'backoff_probe.py',Path(__file__).resolve()):
                child=subprocess.run([sys.executable,'-B','-O',str(path),'--help'],cwd=root,env=env,capture_output=True,timeout=5)
                self.assertNotEqual(child.returncode,0);self.assertEqual(child.stdout,b'')
                self.assertIn(b'assertions required',child.stderr)
            child=subprocess.run([sys.executable,'-B',str(HERE/'backoff_probe.py'),'--help'],cwd=root,env=env,capture_output=True,timeout=5)
            self.assertEqual(child.returncode,0);self.assertEqual(child.stderr,b'')
            self.assertIn(b'--revision',child.stdout)
            self.assertFalse(any(root.rglob('*.pyc')))


if __name__=='__main__':
    unittest.main()
