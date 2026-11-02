"""Remaining49 bounded retained-reader diagnostics; no guest or qualification."""
import json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected_process import invoke
from page_selected import ENV,fact,save
from checks import source
from run import hardware
cpu,=os.sched_getaffinity(0)
packet=Path(__file__).resolve().parent
script=packet/'read_one.py'
candidate=packet/'files/tools/page-entry/selected/tests/persistent_loop_effects_owner/source_decode.py'
assert fact(script)['sha256']=='8a63a711f02a0d121a09e38dfe816e145cb91b6ff280bbc6d72502edd04b8a4b'
assert fact(candidate)['sha256']=='5046f1286e180af2e5c3098c17206a2f5b5717914ebe85c926fda416511bc223'
old=ROOT/'target/evaluation/inprocess/tunables-effects-full19-r2-loop-owner/receipt.json'
prior=ROOT/'target/evaluation/inprocess/effects-pushfq-reader-replay-attempt-1/receipt.json'
assert fact(old)['sha256']=='02ed8e3106cb8add3f761dd4f7e9f80f745a5b8008694fc183a353635b3b849a'
assert fact(prior)['sha256']=='bce507db08f1f1c211fcd4736514bd0e5d3670f20bdecbaf6f182172c1bb327d'
original=json.loads(old.read_bytes());initial=json.loads(prior.read_bytes())
assert initial['status']=='diagnostic_pairs_passed' and initial['source_unchanged'] is initial['cleanup_complete'] is True
assert [c['name']for c in initial['commands']]==['reader-maintained-0-0','reader-maintained-5-0']
assert all(c['exit']==0 for c in initial['commands'])
assert original['status']=='failed' and len(original['cases'])==56
assert [(c['build_lane'],c['mode'],c['placement'])for c in original['cases']]==[(lane,mode,p)for lane in('maintained','differential')for mode in range(7)for p in range(4)]
runtime_failures=[c for c in original['cases']if c['exit']==-9]
assert [(c['build_lane'],c['mode'],c['placement'])for c in runtime_failures]==[('differential',5,3)]+[('differential',6,p)for p in range(4)]
readable=[c for c in original['cases']if c['exit']!=-9]
assert len(readable)==51 and all(c['exit']==c['expected_exit'] and c['status']=='failed' and c['errors']==['CoverageError: unimplemented independent source encoding at 0x200021031']for c in readable)
cases=[c for c in readable if(c['build_lane'],c['mode'],c['placement'])not in(('maintained',0,0),('maintained',5,0))]
assert len(cases)==49
out=ROOT/'target/evaluation/inprocess/effects-pushfq-reader-replay-attempt-2'
out.mkdir()
r=dict(schema=1,scope='retained_reader_diagnostic_only',cpu=cpu,hardware=hardware(cpu),source=source(),
       argv=[sys.executable,'-B',str(Path(__file__).resolve())],parent_driver=fact(__file__),driver=fact(script),candidate=fact(candidate),
       historical_owner=fact(old),prior_diagnostic=fact(prior),historical_revision=original['revision'],
       original_runtime_failures=[dict(lane=c['build_lane'],mode=c['mode'],placement=c['placement'],exit=c['exit'],expected_exit=c['expected_exit'],timed_out=c['timed_out'])for c in runtime_failures],
       commands=[],source_unchanged=False,cleanup_complete=False,error=None,original_owner_remains_failed=True,
       guest_launches=0,qualification_credit=False,performance_credit=False)
try:
    assert r['source']['revision']=='d6a4dcf5bfc719f191a01259fdb4e828c1b124fa'
    for c in cases:
        row=dict(name='reader-'+c['build_lane']+'-'+str(c['mode'])+'-'+str(c['placement']),profile='retained_reader_diagnostic',
                 argv=[sys.executable,'-B',str(script),'--case',str(c['mode']),'--placement',str(c['placement']),'--lane',c['build_lane'],
                       '--candidate',str(candidate),'--candidate-sha256',r['candidate']['sha256']],
                 bounds=[30,536870912,16777216,60],capture_limit=16777216,expected_exit=0,environment=ENV)
        r['commands'].append(row)
        stdout,stderr=invoke(row,out,cpu)
        print(json.dumps(dict(name=row['name'],exit=row['exit'],duration_ns=row['duration_ns'],stderr=stderr.decode()[-1500:])),flush=True)
    r['source_unchanged']=source()==r['source'] and fact(__file__)==r['parent_driver'] and fact(script)==r['driver'] and fact(candidate)==r['candidate'] and fact(old)==r['historical_owner'] and fact(prior)==r['prior_diagnostic']
except BaseException as error:r['error']=type(error).__name__+': '+str(error)
finally:
    r['cleanup_complete']=all(c.get('reaped')is True and c.get('cleanup_errors')==[] and
        type(c.get('descriptors'))is list and all(d.get('closed')is True for d in c['descriptors'])for c in r['commands'])
    r['status']='diagnostic_pairs_passed'if r['error']is None and r['source_unchanged']and r['cleanup_complete']and len(r['commands'])==49 and all(c['exit']==0 for c in r['commands'])else'failed'
    save(out/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],receipt=fact(out/'receipt.json'),error=r['error'])),flush=True)
raise SystemExit(int(r['status']=='failed'))
