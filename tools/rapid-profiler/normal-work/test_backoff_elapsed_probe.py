#!/usr/bin/env python3
"""Fabricated four-mode authority controls; no qualification or native work."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


def local(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    assert spec is not None and spec.loader is not None
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


HERE=Path(__file__).resolve().parent
D=local('_elapsed_driver',HERE/'backoff_elapsed_probe.py')
P=local('_elapsed_shared',HERE/'throughput_probe.py')
B=local('_elapsed_backoff',HERE/'backoff_probe.py')
L=local('_elapsed_old_controls',HERE/'test_throughput_probe.py')
F=local('_elapsed_authority_controls',HERE/'test_backoff_probe.py')
T=local('_elapsed_timer',HERE.parent/'tree-work/process_timing.py')
TF=local('_elapsed_timer_fixture',HERE.parent/'tree-work/test_process_timing.py')
CPUS=[2,3,7,9]


def fixture(key):
    mode=key['mode'];value,_=L.observation_fixture(mode if mode in D.MODES[:2] else 'always-on')
    value['functional'].update(pid=124,tid=124,table=b'fabricated calls\n')
    if mode in D.MODES[2:]:
        k=10 if mode=='backoff-k10' else 1000
        value.pop('mode');value.pop('cpu');value.update(k=k,app_cpu=3,controller_cpu=9)
        value['functional'].pop('mode')
        value['functional'].update(k=k,app_cpu=3,controller_cpu=9,controller_tid=125,
            sampled=10,unsampled=3062,records=10,history_table=b'history\n',report_table=b'reports\n')
    def row(kind,index,start,end):
        return dict(kind=kind,index=index,start_ns=start,end_ns=end,elapsed_ns=end-start,
            division_status='UNRESOLVED_ZERO' if start==end else 'NOT_COMPUTED')
    value.update(setup=row('setup',0,2**63,2**63),
        body=[row('body',i+1,2**63+i,2**63+i+1) for i in range(128)],
        service=row('service',0,2**63,2**63+150),setup_ns=0,body_ns=128,service_ns=150,
        zero_body_spans=0,division_status=dict(setup_ns='UNRESOLVED_ZERO',body_ns='NOT_COMPUTED',service_ns='NOT_COMPUTED'))
    app=['/taskset','--cpu-list','3' if mode in D.MODES[:2] else '3,9','/app',mode]
    timer=TF.fixture();timer.update(token=T.token(app),argc=len(app))
    return value,timer,app


def completed_rows():
    rows=[]
    for key in D.catalog():
        value,timer,_=fixture(key)
        rows.append(dict(key,status='PASS',closed=True,identity_joined=True,timer=timer,
            setup_ns=0,body_ns=value['body_ns'],service_ns=value['service_ns'],
            timing=[value['setup'],*value['body'],value['service']],files={'stdout.txt':dict(sha256='a'*64),'stderr.txt':dict(sha256='b'*64)}))
    return rows,{i:dict(bytes=1,sha256=f'{i:064x}') for i in range(1,21)}


class Controls(unittest.TestCase):
    def refuse(self,fn,*args):
        with self.assertRaises(AssertionError):fn(*args)

    def test_fixed_twenty_catalog_and_exact_timer_role_argv(self):
        expected=('native','always-on','backoff-k10','backoff-k1000',
            'always-on','backoff-k10','backoff-k1000','native',
            'backoff-k10','backoff-k1000','native','always-on',
            'backoff-k1000','native','always-on','backoff-k10',
            'native','always-on','backoff-k10','backoff-k1000')
        self.assertEqual(tuple(k['mode'] for k in D.catalog()),expected)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);pins=P.Pins();plans=[]
            for i,key in enumerate(D.catalog()):
                self.assertEqual((key['trial'],key['block']),(i+1,i//4+1))
                d=root/str(i);d.mkdir();args=(P,'/taskset','/timer',d/'timing',T.token,'/app',key,CPUS,'/c','/f',4096,'/cc','/cf')
                argv,inner=D.timed_argv(*args)
                self.assertEqual(argv,['/taskset','--cpu-list','7','/timer',str(d/'timing'),T.token(inner),'--',*inner])
                self.assertEqual(inner[:4],['/taskset','--cpu-list','3' if key['mode'] in D.MODES[:2] else '3,9','/app'])
                self.assertEqual(inner[-6:],['/c','/f','4096','37','/cc','/cf'])
                if key['mode'] in D.MODES[:2]:self.assertEqual(inner[4:6],['normal-observer-throughput',key['mode']])
                else:self.assertEqual(inner[4:8],['normal-observer-backoff-elapsed','10' if key['mode']=='backoff-k10' else '1000','3','9'])
                r=P.request(argv,Path('/repo'),{},d);P.check_request(r,r);P.freeze(d/'request',P.encoded(r),pins);plans.append(r)
                for cpus in ([2,3,7],[2,3,3,9],[2,3,7,1024],[9,7,3,2]):
                    bad=list(args);bad[7]=cpus;self.refuse(D.timed_argv,*bad)
            self.assertEqual(len(plans),20);pins.check()
            self.assertEqual((plans[0]['cpu_seconds'],plans[0]['wall_seconds'],plans[0]['file_bytes']),(20,30,1048576))

    def test_all_four_observation_identities_and_raw_clock_separation(self):
        for key in D.catalog()[:4]:
            value,timer,app=fixture(key);seen=[]
            def check(*args):seen.append(args);return value
            measured,parsed,ok=D.observe(P,T,check,b'actual stdout',b'',TF.encode(timer),app,0,key,CPUS)
            self.assertTrue(ok);self.assertIs(parsed,value);self.assertEqual(measured,timer)
            expected=(b'actual stdout',b'',key['mode']) if key['mode'] in D.MODES[:2] else (
                b'actual stdout',b'',10 if key['mode']=='backoff-k10' else 1000,3,9)
            self.assertEqual(seen,[expected]) # RAW values intentionally have a different origin.
            for field in ('pid','tid'):
                bad=copy.deepcopy(value);bad['functional'][field]=126
                self.refuse(D.observation_join,P,bad,timer,key,CPUS)
            self.refuse(D.observation_join,P,value,dict(timer,wait_pid=126),key,CPUS)
            for name,wrong in (('clock','CLOCK_MONOTONIC'),('timing_rows',129),('body',[])):
                bad=copy.deepcopy(value);bad[name]=wrong;self.refuse(D.observation_join,P,bad,timer,key,CPUS)
            if key['mode'] in D.MODES[2:]:
                for name,wrong in (('k',11),('app_cpu',7),('controller_cpu',3)):
                    bad=copy.deepcopy(value);bad[name]=wrong;self.refuse(D.observation_join,P,bad,timer,key,CPUS)
                bad=copy.deepcopy(value);bad['functional']['controller_tid']=124;self.refuse(D.observation_join,P,bad,timer,key,CPUS)

    def test_printed_success_nonzero_is_failure_and_missing_identity_stops(self):
        key=D.catalog()[2];value,timer,app=fixture(key)
        for change in (dict(exit=1,wait_status=256),dict(exit=-1,signal=6,core=1,wait_status=134)):
            failed=dict(timer,**change)
            _,_,ok=D.observe(P,T,lambda *a:value,b'printed success',b'',TF.encode(failed),app,1,key,CPUS)
            self.assertFalse(ok)
            rows=[dict(k,status='UNRUN') for k in D.catalog()];D.advance(rows,0)
            rows[0].update(closed=True,identity_joined=True);D.advance(rows,1)
            self.assertEqual(rows[0]['status'],'FAILED')
        def strict(*args):
            self.assertEqual(args[1],b'actual panic stderr');raise AssertionError('strict refusal')
        with self.assertRaises(D.AppIdentityUnconfirmed):
            D.observe(P,T,strict,b'printed success',b'actual panic stderr',TF.encode(timer),app,0,key,CPUS)
        def missing(*args):raise AssertionError('no APP witness')
        with self.assertRaises(D.AppIdentityUnconfirmed):D.observe(P,T,missing,b'',b'',TF.encode(timer),app,0,key,CPUS)
        self.refuse(D.observe,P,T,lambda *a:value,b'',b'',TF.encode(dict(timer,token='0'*64)),app,0,key,CPUS)
        self.refuse(D.observe,P,T,lambda *a:value,b'',b'',TF.encode(timer),app,1,key,CPUS)

    def test_owner_prerequisites_and_custody_gate_the_frozen_remainder(self):
        owners=[dict(k,status='PASS',closed=True) for k in B.owner_catalog()];B.owners_complete(owners)
        self.assertEqual([(r['k'],r['hold_ordinal']) for r in owners],[(10,22),(1000,1006)])
        for status in ('FAILED','UNRUN'):
            bad=copy.deepcopy(owners);bad[0]['status']=status;self.refuse(B.owners_complete,bad)
        rows=[dict(k,status='UNRUN') for k in D.catalog()];D.advance(rows,0)
        rows[0]['closed']=True;self.refuse(D.advance,rows,1)
        rows[0]['identity_joined']=True;D.advance(rows,1)
        self.assertEqual(sum(r['status']=='UNRUN' for r in rows),18)
        rows[1].update(closed=True,identity_joined=True)
        ready=copy.deepcopy(rows);D.advance(ready,2);self.assertEqual(ready[2]['status'],'FAILED')
        for field,value in (('mode','native'),('block',1),('trial',1)):
            bad=copy.deepcopy(rows);bad[5][field]=value;self.refuse(D.advance,bad,2)
        bad=copy.deepcopy(rows);bad[1].update(closed=True,identity_joined=True);bad[6]['status']='PASS'
        self.refuse(D.advance,bad,2)

    def test_projection_keeps_all_rows_and_only_joined_nonzero_ratios(self):
        rows,pins=completed_rows();saved=copy.deepcopy(rows)
        view=D.projection(rows,pins,True)
        self.assertEqual((len(view['trials']),len(view['timing']),len(view['pairs'])),(20,2600,15))
        self.assertTrue(all(p['body']==dict(status='EXACT_RATIO',numerator=128,denominator=128) for p in view['pairs']))
        self.assertEqual(rows,saved)
        rows[0]['body_ns']=0;rows[1]['body_ns']=0
        view=D.projection(rows,pins,True);self.assertEqual(view['pairs'][0]['body'],dict(status='UNRESOLVED_ZERO',numerator=0,denominator=0))
        rows[2]['status']='FAILED';view=D.projection(rows,pins,True)
        self.assertIsNone(view['pairs'][1]['body']);self.assertEqual(len(view['timing']),2600)
        partial=D.projection(rows,pins,False);self.assertTrue(all(p['body'] is p['service'] is None for p in partial['pairs']))
        self.assertEqual(partial['failed_count'],1)
        rows[2]['identity_joined']=False;self.refuse(D.projection,rows,pins,True)
        blank=[dict(k,status='UNRUN') for k in D.catalog()];view=D.projection(blank,{},False)
        self.assertEqual((view['unrun_count'],len(view['timing'])),(20,0))
        self.refuse(D.projection,blank,{},True)

    def test_exact_old_and_new_censuses_and_authenticated_prerequisite(self):
        self.assertEqual((len(P.RUST),len(B.RUST),len(B.OWNER_RUST),len(B.ELAPSED_RUST)),(8,8,6,7))
        self.assertEqual((len(P.CHECKER),len(B.CHECKER),len(B.OWNER_CHECKER),len(D.CHECKER)),(6,10,8,11))
        self.assertEqual((len(P.CONTROLS),len(B.CONTROLS),len(D.CONTROLS),len(P.TIMER_CONTROLS)),(10,8,8,5))
        self.assertEqual(len(D.STAGES),14);self.assertIn('elapsed-rust-controls',B.STAGES)
        with tempfile.TemporaryDirectory() as temp:
            f=F.QualifiedFixture(Path(temp));q=f.call()
            self.assertTrue(set(B.RUST+B.OWNER_RUST+B.ELAPSED_RUST).issubset(q['inventory']))
            self.assertEqual(q['prerequisite']['closure']['owned_stages'],34);f.pins.check()
        for fault in ('missing-elapsed','inventory','profile','rescue','parent-log','source-after'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
                f=F.QualifiedFixture(Path(temp),fault);self.refuse(f.call)

    def test_request_closure_and_completed_pins_are_not_refreshable(self):
        for code in (0,1,-6):self.assertEqual(P.closed_request(*L.closure_fixture(code)),code)
        for index,key,value in ((0,'cleanup_complete',False),(0,'reaped_descendants',1),(1,'absence_proof','unknown'),
                (1,'request_sha256','0'*64),(1,'cleanup_events',[1]),(1,'inputs_unchanged',False)):
            f=list(L.closure_fixture());f[index][key]=value;self.refuse(P.closed_request,*f)
        request=P.request(['/app'],Path('/repo'),{},Path('/out'))
        for key,value in (('cpu_seconds',21),('wall_seconds',31),('file_bytes',1048577)):
            bad=dict(request,**{key:value});self.refuse(P.check_request,bad,bad)
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'result';pins=P.Pins();P.freeze(p,b'original',pins);old=copy.deepcopy(pins.values)
            p.write_bytes(b'changed');self.refuse(pins.check);self.assertEqual(pins.values,old)

    def test_local_import_optimized_refusal_and_exact_control_census(self):
        self.assertEqual(Path(D.__file__).resolve(),HERE/'backoff_elapsed_probe.py')
        P.python_census(Path(__file__).read_bytes(),'Controls',D.CONTROLS)
        methods=('test_a','test_b');source=b'class Controls:\n def test_a(self): pass\n def test_b(self): pass\n'
        self.refuse(P.python_census,source+b' def test_c(self): pass\n','Controls',methods)
        self.refuse(P.python_controls,b'',b'.s\n---\nRan 2 tests in 0.001s\n\nOK (skipped=1)\n',methods)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in ('backoff_elapsed_probe','backoff_probe','throughput_probe','backoff_elapsed_work'):
                (root/(name+'.py')).write_text('raise RuntimeError("ambient import")\n',encoding='ascii')
            env=dict(os.environ,PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
            for path in (HERE/'backoff_elapsed_probe.py',Path(__file__).resolve()):
                child=subprocess.run([sys.executable,'-B','-O',str(path),'--help'],cwd=root,env=env,capture_output=True,timeout=5)
                self.assertNotEqual(child.returncode,0);self.assertEqual(child.stdout,b'');self.assertIn(b'assertions required',child.stderr)
            child=subprocess.run([sys.executable,'-B',str(HERE/'backoff_elapsed_probe.py'),'--help'],cwd=root,env=env,capture_output=True,timeout=5)
            self.assertEqual(child.returncode,0);self.assertEqual(child.stderr,b'');self.assertIn(b'--revision',child.stdout)
            self.assertFalse(any(root.rglob('*.pyc')))


if __name__=='__main__':
    unittest.main()
