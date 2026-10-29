#!/usr/bin/env python3
"""Synthetic orchestration mutations; no native, reservation or timing authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

_path = Path(__file__).resolve().with_name('throughput_probe.py')
_spec = importlib.util.spec_from_file_location('_tested_throughput_probe', _path)
assert _spec is not None and _spec.loader is not None
P = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(P)


def token(argv):
    return hashlib.sha256(json.dumps(argv, ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()


def closure_fixture(direct=0):
    files = {n:dict(bytes=1,sha256=c*64) for n,c in (('parent.log','a'),('stdout.txt','b'),('stderr.txt','c'))}
    closed = dict(exit_code=0 if direct == 0 else 1, termination=None,cleanup_complete=True,
        reaped_descendants=0,private_log_sha256=files['parent.log']['sha256'])
    receipt = dict(exit=direct,wall_timeout=False,inputs_unchanged=True,absence_proof='ECHILD',
        unexpected_descendants=[],cleanup_events=[],cleanup_error=None,aborted=None,
        request_sha256='d'*64,helper_sha256='e'*64,stdout_sha256='b'*64,stderr_sha256='c'*64)
    log = dict(exit=direct,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=direct == 0)
    return closed,receipt,log,files,'d'*64,'e'*64,P.MIB


def observation_fixture(mode='native'):
    timer = dict(exec_errno=0,process_wall_ns=1,exit=0,signal=0,core=0,wait_status=0,child_pid=42,wait_pid=42)
    f = dict(status='FUNCTIONAL_PASS',mode=mode,pid=42,tid=42,calls=3072,helper_calls=1536,
        instructions=614400,rows=[None]*3072,records=0 if mode=='native' else 3072,batches=0 if mode=='native' else 128)
    value = dict(status='TIMING_COMPLETE',mode=mode,cpu=3,functional=f,clock='CLOCK_MONOTONIC_RAW',
        units='ns',timing_rows=130,body=[None]*128)
    return value,timer


def qualified_fixture():
    names = tuple('stage-'+str(i) for i in range(34))
    v = dict(revision='1'*40,status='PASS',stage='complete',stages=[dict(name=n,status='PASS') for n in names],
        closure=dict(owned_stages=34,nested_normal_helpers=46,nested_outer_owners=48,rescues=0),native=dict(pairs=17,children=34))
    offset = 10
    for label,count in (('reference_exact',13),('reference_work',3),('reference_leg',4),('observer_work',4)):
        v[label] = dict(status='PASS',stages=copy.deepcopy(v['stages'][offset:offset+count]),
            closure=dict(owned_stages=count,normal_helpers=count,outer_owners=count,rescues=0))
        offset += count
    v['reference_exact'].update(old_exact=dict(status='PASS'),reference=dict(status='PASS'))
    v['reference_work']['collector'] = dict(status='PASS')
    v['reference_leg']['legs'] = [dict(phase='qualification',trial=1,leg=leg,calls=24,status='PASS') for leg in ('original','installed')]
    return v,names


class Controls(unittest.TestCase):
    def refuse(self, fn, *args):
        with self.assertRaises(AssertionError): fn(*args)

    def test_catalog_and_complete_requests_are_frozen_before_trial_one(self):
        self.assertEqual(P.reservation_tag('a-0'), 'a-0')
        self.assertEqual(P.reservation_tag('a'*128), 'a'*128)
        for bad in ('', 'a'*129, 'A', 'a/b', 'x\n', '\u00e9', None): self.refuse(P.reservation_tag,bad)
        self.assertEqual([r['mode'] for r in P.catalog()], ['native','always-on','always-on','native','native','always-on','always-on','native','native','always-on'])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); pins = P.Pins(); planned = []
            for key in P.catalog():
                d = root/str(key['trial']);d.mkdir()
                app = ['/collector','normal-observer-throughput',key['mode']]
                argv,inner = P.timed_argv('/taskset','/timer',d/'timing',token,app,[2,3,7,9])
                self.assertEqual(inner,['/taskset','--cpu-list','3',*app])
                self.assertEqual(argv[:4],['/taskset','--cpu-list','7','/timer'])
                self.assertEqual(argv[5:7],[token(inner),'--'])
                r = P.request(argv,Path('/repo'),{'LANG':'C'},d)
                P.check_request(r,r); P.freeze(d/'request.json',P.encoded(r),pins); planned.append(r)
            self.assertEqual(len(pins.values),10);pins.check()
            rows = [dict(k,status='UNRUN') for k in P.catalog()];P.start_trial(rows,0)
            self.assertEqual(rows[0]['status'],'FAILED')
            bad = copy.deepcopy(planned[0]);bad['wall_seconds']=31
            self.refuse(P.check_request,bad,bad)
            bad = copy.deepcopy(planned[0]);bad['file_bytes']=2*P.MIB
            self.refuse(P.check_request,bad,bad)
            bad = copy.deepcopy(planned[0]);bad['argv'][-1]='wrong-mode'
            self.refuse(P.check_request,bad,planned[0])
            self.refuse(P.timed_argv,'/taskset','/timer','/record',token,app,[2,3,3,9])
            self.refuse(P.timed_argv,'/taskset','/timer','/record',token,app,[2,3,7,1024])

    def test_closure_joins_all_statuses_hashes_and_streams(self):
        for direct in (0,1): self.assertEqual(P.closed_request(*closure_fixture(direct)),direct)
        changes = [(0,'termination','wall'),(0,'cleanup_complete',False),(0,'reaped_descendants',1),
            (0,'private_log_sha256','0'*64),(0,'exit_code',True),(1,'wall_timeout',True),
            (1,'inputs_unchanged',False),(1,'absence_proof','unknown'),(1,'unexpected_descendants',[8]),
            (1,'cleanup_events',[8]),(1,'cleanup_error','error'),(1,'aborted','error'),
            (1,'request_sha256','0'*64),(1,'helper_sha256','0'*64),(1,'stdout_sha256','0'*64),
            (1,'stderr_sha256','0'*64),(1,'exit',False),(2,'success',False),(2,'descendants',1)]
        for index,key,value in changes:
            f=list(closure_fixture());f[index][key]=value;self.refuse(P.closed_request,*f)
        f=list(closure_fixture());f[3]['stdout.txt']['bytes']=P.MIB+1
        self.refuse(P.closed_request,*f)

    def test_timer_identity_and_functional_join_are_required(self):
        for mode in ('native','always-on'):
            value,timer=observation_fixture(mode)
            self.assertTrue(P.timer_status(timer,0));P.observation_join(value,timer,mode,3)
            for key,bad in (('cpu',7),('mode','wrong'),('status','PASS'),('clock','CLOCK_MONOTONIC'),('timing_rows',129)):
                v=copy.deepcopy(value);v[key]=bad;self.refuse(P.observation_join,v,timer,mode,3)
            for key,bad in (('pid',43),('tid',43),('calls',3071),('instructions',614399),('records',2),('rows',[])):
                v=copy.deepcopy(value);v['functional'][key]=bad;self.refuse(P.observation_join,v,timer,mode,3)
            self.refuse(P.observation_join,value,dict(timer,wait_pid=43),mode,3)
        _,timer=observation_fixture()
        for key,bad in (('exec_errno',2),('process_wall_ns',0),('process_wall_ns',30_000_000_001)):
            self.refuse(P.timer_status,dict(timer,**{key:bad}),0)
        self.refuse(P.timer_status,timer,1)
        failed=dict(timer,exit=1,wait_status=256)
        self.assertFalse(P.timer_status(failed,1));self.refuse(P.timer_status,failed,0)

    def test_qualification_and_release_artifact_joins_are_exact(self):
        v,names=qualified_fixture();P.qualification(v,'1'*40,names)
        for mutate in (
            lambda x:x.update(revision='2'*40),lambda x:x['stages'][9].update(status='UNRUN'),
            lambda x:x['stages'].reverse(),lambda x:x['closure'].update(rescues=1),
            lambda x:x['observer_work']['stages'][0].update(name='wrong'),
            lambda x:x['reference_exact']['old_exact'].update(status='FAILED'),
            lambda x:x['reference_leg']['legs'][0].update(calls=23)):
            bad=copy.deepcopy(v);mutate(bad);self.refuse(P.qualification,bad,'1'*40,names)
        repo=Path('/repo');profile=dict(opt_level='3',debuginfo=0,test=True,debug_assertions=True,overflow_checks=True)
        product=dict(reason='compiler-artifact',profile=profile,fresh=False,executable='/repo/target/release/deps/ordinary_interval-abc',
            manifest_path='/repo/tools/rapid-profiler/Cargo.toml',target=dict(name='ordinary-interval',src_path='/repo/tools/rapid-profiler/ordinary-interval/main.rs',kind=['bin'],crate_types=['bin']))
        actual=dict(bytes=100,sha256='a'*64);authority=dict(binary=actual,profile=profile,cargo_fresh=False)
        messages=[product,dict(reason='build-finished',success=True)]
        self.assertEqual(P.release_product(messages,repo,authority,actual),Path(product['executable']))
        for mutate in (lambda x:x['profile'].update(overflow_checks=False),lambda x:x.update(fresh=1),
            lambda x:x['target'].update(src_path='/other.rs'),lambda x:x.update(executable='/other/ordinary_interval-abc')):
            bad=copy.deepcopy(messages);mutate(bad[0]);self.refuse(P.release_product,bad,repo,authority,actual)
        self.refuse(P.release_product,[product,*messages],repo,authority,actual)
        self.refuse(P.release_product,messages,repo,authority,dict(actual,bytes=101))

    def test_completed_file_pins_never_refresh_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);pins=P.Pins()
            for name in ('request.json','stdout.txt','stderr.txt','parent.log','receipt.json','parent-closed.json','result.json'):
                p=root/name;P.freeze(p,b'original\n',pins)
            saved=copy.deepcopy(pins.values);pins.check()
            for name in ('request.json','result.json','parent.log'):
                p=root/name;p.write_bytes(b'changed\n')
                self.refuse(pins.retain,p);self.refuse(pins.check)
                self.assertEqual(pins.values,saved)
                # A fresh independent Pins object is used only to test the next mutation.
                p.write_bytes(b'original\n');pins=P.Pins()
                for q in root.iterdir():pins.retain(q)
                saved=copy.deepcopy(pins.values)
            self.refuse(pins.retain,root/'stdout.txt',dict(bytes=0,sha256='0'*64))

    def test_closed_failure_continues_but_custody_failure_leaves_unrun(self):
        rows=[dict(k,status='UNRUN') for k in P.catalog()]
        P.start_trial(rows,0);self.refuse(P.start_trial,rows,1)
        rows[0].update(closed=True,reason='FUNCTIONAL_EXIT')
        P.start_trial(rows,1)
        self.assertEqual(rows[0]['status'],'FAILED')
        P.stop_remaining(rows,'APP_EXEC_UNCONFIRMED')
        self.assertTrue(all(r['status']=='UNRUN' and r['reason']=='APP_EXEC_UNCONFIRMED' for r in rows[2:]))
        self.refuse(P.start_trial,rows,2)
        rows[1]['closed']=True;P.start_trial(rows,2)
        rows[2]['closed']=True
        changed=copy.deepcopy(rows);changed[3]['mode']='always-on'
        self.refuse(P.start_trial,changed,3)
        self.assertEqual(rows[0]['status'],'FAILED')

    def test_pair_projection_keeps_zero_and_failed_members(self):
        rows=[dict(k,status='PASS',closed=True,body_ns=0,service_ns=2) for k in P.catalog()]
        p=P.pairs(rows)
        self.assertEqual(p[0]['body'],dict(status='UNRESOLVED_ZERO',numerator=0,denominator=0))
        self.assertEqual(p[0]['service'],dict(status='EXACT_RATIO',numerator=2,denominator=2))
        rows[1]['body_ns']=2**64-1;rows[0]['body_ns']=1
        self.assertEqual(P.pairs(rows)[0]['body']['numerator'],2**64-1)
        rows[0]['status']='FAILED'
        self.assertEqual(P.pairs(rows)[0],dict(pair=1,status='UNRESOLVED_MEMBER',body=None,service=None))
        self.assertEqual(len(P.pairs(rows)),5)
        rows[2]['service_ns']=-1;self.refuse(P.pairs,rows)

    def test_python_controls_require_exact_methods_and_counts(self):
        source=b'class Controls:\n    def test_a(self): pass\n    def test_b(self): pass\n'
        P.python_census(source,'Controls',('test_a','test_b'))
        P.python_controls(b'',b'..\n----------------------------------------------------------------------\nRan 2 tests in 0.001s\n\nOK\n',('test_a','test_b'))
        self.refuse(P.python_census,source,'Controls',('test_a',))
        self.refuse(P.python_census,source,'Other',('test_a','test_b'))
        self.refuse(P.python_census,source+b'    def test_c(self): pass\n','Controls',('test_a','test_b'))
        for stderr in (b'.s\n---\nRan 2 tests in 0.001s\n\nOK (skipped=1)\n',b'..\n---\nRan 1 tests in 0.001s\n\nOK\n',b'..\n---\nRan 2 tests in 0.001s\n\nFAILED\n'):
            self.refuse(P.python_controls,b'',stderr,('test_a','test_b'))
        self.refuse(P.python_controls,b'unexpected',b'..\n---\nRan 2 tests in 0.001s\n\nOK\n',('test_a','test_b'))


    def test_projection_retains_all_outcomes_after_prerequisite_failure(self):
        rows=[dict(k,status='UNRUN') for k in P.catalog()]
        P.stop_remaining(rows,'SHARED_AUTHORITY_OR_CUSTODY_FAILURE')
        saved=copy.deepcopy(rows)
        view=P.projection(rows,{},False)
        self.assertEqual(view['status'],'INCOMPLETE_UNQUALIFIED')
        self.assertEqual(len(view['trials']),10);self.assertEqual(view['timing'],[])
        self.assertEqual(view['pairs'],[dict(pair=i,status='UNRESOLVED_MEMBER',body=None,service=None) for i in range(1,6)])
        for row,key in zip(view['trials'],P.catalog()):
            self.assertEqual({k:row[k] for k in key},key)
            self.assertEqual(row['status'],'UNRUN')
            self.assertEqual(row['reason'],'SHARED_AUTHORITY_OR_CUSTODY_FAILURE')
            self.assertEqual(set(row),set(P.TRIAL_FIELDS))
            self.assertTrue(all(row[k] is None for k in P.TRIAL_FIELDS if k not in {*key,'status','reason'}))
        self.assertEqual(rows,saved)
        self.refuse(P.projection,rows,{},True)
        bad=copy.deepcopy(rows);bad[0]['mode']='always-on';self.refuse(P.projection,bad,{},False)
        self.assertNotIn(b'/private',P.encoded(view))

    def test_projection_retains_partial_evidence_without_custody_ratios(self):
        # Synthetic retained metadata only: this test grants no native authority.
        rows=[dict(k,status='PASS',closed=True,cpu=3,pid=42,tid=42,setup_ns=0,body_ns=0,service_ns=7,
            timer=dict(process_wall_ns=9,child_user_us=1,child_system_us=2,child_cpu_us=3),
            files={'stdout.txt':dict(sha256='a'*64),'stderr.txt':dict(sha256='b'*64)},
            timing=[dict(kind='setup',index=0,start_ns=0,end_ns=0),
                *[dict(kind='body',index=i,start_ns=0,end_ns=0) for i in range(1,129)],
                dict(kind='service',index=0,start_ns=0,end_ns=7)]) for k in P.catalog()]
        pins={i:dict(bytes=1,sha256=('%064x'%i)) for i in range(1,11)}
        saved=copy.deepcopy(rows);saved_pins=copy.deepcopy(pins)
        tentative=P.projection(rows,pins,True)
        self.assertEqual(tentative['pairs'],P.pairs(rows))
        self.assertEqual(len(tentative['timing']),1300)
        # A failed final pin check must withhold every tentative ratio without mutation.
        refused=P.projection(rows,pins,False)
        self.assertTrue(all(p==dict(pair=i,status='UNQUALIFIED_CUSTODY',body=None,service=None)
                            for i,p in enumerate(refused['pairs'],1)))
        self.assertEqual(refused['timing'],tentative['timing'])
        self.assertEqual(rows,saved);self.assertEqual(pins,saved_pins)
        self.assertEqual(tentative['pairs'],P.pairs(saved))
        rows[2].update(status='FAILED',reason='FUNCTIONAL_EXIT')
        rows[3]=dict(P.catalog()[3],status='FAILED',reason='APP_EXEC_UNCONFIRMED',
            timer=dict(process_wall_ns=11),files={'stdout.txt':dict(sha256='c'*64)},private_path='/private/raw')
        rows[4:]=[dict(k,status='UNRUN') for k in P.catalog()[4:]]
        P.stop_remaining(rows,'APP_EXEC_UNCONFIRMED')
        partial=P.projection(rows,{i:pins[i] for i in range(1,5)},False)
        self.assertEqual(partial['status'],'INCOMPLETE_UNQUALIFIED')
        self.assertEqual([r['status'] for r in partial['trials']],['PASS','PASS','FAILED','FAILED']+['UNRUN']*6)
        self.assertEqual(len(partial['timing']),390)
        self.assertEqual(partial['timing'],tentative['timing'][:390])
        self.assertEqual(partial['trials'][3]['result_sha256'],pins[4]['sha256'])
        self.assertEqual(partial['trials'][3]['process_wall_ns'],11)
        self.assertEqual(partial['trials'][3]['stdout_sha256'],'c'*64)
        self.assertTrue(all(partial['trials'][3][k] is None for k in ('cpu','pid','tid','body_ns','child_cpu_us','stderr_sha256')))
        self.assertTrue(all(r['result_sha256'] is None for r in partial['trials'][4:]))
        self.assertEqual(partial['pairs'][0]['status'],'UNQUALIFIED_CUSTODY')
        self.assertTrue(all(p['status']=='UNRESOLVED_MEMBER' for p in partial['pairs'][1:]))
        self.assertTrue(all(p['body'] is p['service'] is None for p in partial['pairs']))
        self.assertNotIn(b'/private',P.encoded(partial))
        self.refuse(P.projection,rows,{i:pins[i] for i in range(1,5)},True)


if __name__ == '__main__':
    unittest.main()
