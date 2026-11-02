"""Two bounded retained-reader diagnostics; no guest, build or qualification."""
import hashlib,json,os,sys
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
out=ROOT/'target/evaluation/inprocess/effects-pushfq-reader-replay-attempt-1'
out.mkdir()
r=dict(schema=1,scope='retained_reader_diagnostic_only',cpu=cpu,hardware=hardware(cpu),source=source(),
       argv=[sys.executable,'-B',str(Path(__file__).resolve())],driver=fact(script),candidate=fact(candidate),
       commands=[],source_unchanged=False,cleanup_complete=False,error=None,original_owner_remains_failed=True,
       guest_launches=0,qualification_credit=False,performance_credit=False,
       historical_revision='1b2028e795bac3b308114d73681311b67cf2da1a')
try:
    assert r['source']['revision']=='d6a4dcf5bfc719f191a01259fdb4e828c1b124fa'
    for mode in (0,5):
        row=dict(name='reader-maintained-'+str(mode)+'-0',profile='retained_reader_diagnostic',
                 argv=[sys.executable,'-B',str(script),'--case',str(mode),'--placement','0','--lane','maintained',
                       '--candidate',str(candidate),'--candidate-sha256',r['candidate']['sha256']],
                 bounds=[30,536870912,16777216,60],capture_limit=16777216,expected_exit=0,environment=ENV)
        r['commands'].append(row)
        stdout,stderr=invoke(row,out,cpu)
        print(json.dumps(dict(name=row['name'],exit=row['exit'],duration_ns=row['duration_ns'],stdout=stdout.decode(),stderr=stderr.decode()[-2500:])),flush=True)
    r['source_unchanged']=source()==r['source'] and fact(script)==r['driver'] and fact(candidate)==r['candidate']
except BaseException as error:r['error']=type(error).__name__+': '+str(error)
finally:
    r['cleanup_complete']=all(c.get('reaped')is True and c.get('cleanup_errors')==[] and
        type(c.get('descriptors'))is list and all(d.get('closed')is True for d in c['descriptors'])for c in r['commands'])
    r['status']='diagnostic_pairs_passed'if r['error']is None and r['source_unchanged']and r['cleanup_complete']and len(r['commands'])==2 and all(c['exit']==0 for c in r['commands'])else'failed'
    save(out/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],receipt=fact(out/'receipt.json'),error=r['error'])),flush=True)
raise SystemExit(int(r['status']=='failed'))
