#!/usr/bin/env python3
"""Sample the exact Main97 inventory test under its original limits.

Run from a clean checkout on one reserved CPU using Python 3.12. Output is
private and must be fresh under target/evaluation. This diagnostic cannot
qualify the four-worker recorder gate. The script may live outside the checkout.
"""
import argparse,hashlib,json,os,re,resource,shutil,sys
from pathlib import Path
root=Path.cwd().resolve();sys.path.insert(0,str(root/'evaluation/admission'))
import run as a
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--expect-revision',required=True)
ap.add_argument('--output',required=True,type=Path)
args=ap.parse_args()
REV=args.expect_revision
assert sys.version_info[:2]==(3,12) and not sys.flags.optimize
assert len(REV)==40 and all(c in '0123456789abcdef' for c in REV)
spy=shutil.which('py-spy');assert spy is not None
cpu,=os.sched_getaffinity(0)
out=args.output.resolve()
assert out.is_relative_to(root/'target/evaluation') and out!=root/'target/evaluation'
out.mkdir();(out/'tmp').mkdir()
before=a.source_state();assert before['revision']==REV and before['tracked_clean'] and before['head_sources_match']
def fact(p):
 b=Path(p).read_bytes();return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
inputs={str(Path(p).resolve(strict=True)):fact(p)for p in (__file__,sys.executable,'/usr/bin/prlimit',spy,root/'evaluation/admission/run.py',root/'evaluation/admission/processes.py',root/'evaluation/admission/test_main97ab_inventory.py',root/'evaluation/admission/corpus.json',root/'evaluation/admission/core_97ab_inventory.py',root/'evaluation/admission/core_97ab_inventory.json')}
methods=['test_main97ab_inventory.Main97abInventoryTests.test_exact_native_indexed_sources_and_historical_refusals']
argv=['/usr/bin/prlimit','--cpu=180:180','--as=536870912:536870912','--fsize=16777216:16777216',spy,'record','--format','raw','--rate','49','--dump-duration','10','--output',str(out/'profile.raw'),'--',sys.executable,'-B','-m','unittest','-v',*methods]
environment=a.controlled_environment(os.environ,out/'tmp')|{'PYTHONPATH':str(root/'evaluation/admission')}
r=dict(schema=1,profile='original-main97-sampling-diagnostic-v1',status='failed',source=before,hardware=a.hardware(),cpu=cpu,driver=fact(__file__),argv=argv,environment=environment,bounds=dict(cpu_seconds=180,wall_seconds=180,address_space_bytes=512<<20,file_size_bytes=16<<20,log_bytes=8<<20),qualification_credit=False,command=None,error=None,source_unchanged=False)
configuration=a.cargo_configuration(environment)
r.update(configuration=configuration,configuration_unchanged=False,inputs=inputs,inputs_unchanged=False,child_usage=None)
usage_before=resource.getrusage(resource.RUSAGE_CHILDREN)
try:
 r['command']=a.run_command(argv,environment,out/'measurement.log',180)
 assert r['command']['cleanup_complete'] is True
 if r['command']['exit_code']==0 and r['command']['termination'] is None:
  raw=(out/'measurement.log').read_text()
  assert len(re.findall(r'^Ran 1 test in [0-9.]+s$',raw,re.M))==1
  assert len(re.findall(r'^OK$',raw,re.M))==1
  assert raw.count(methods[0].split('.')[-1]+' (')==1
  r['status']='passed_isolated_only'
except BaseException as e:r['error']=type(e).__name__+': '+str(e)
finally:
 usage_after=resource.getrusage(resource.RUSAGE_CHILDREN)
 fields=('ru_utime','ru_stime','ru_minflt','ru_majflt','ru_inblock','ru_oublock','ru_nvcsw','ru_nivcsw')
 r['child_usage']={k:getattr(usage_after,k)-getattr(usage_before,k)for k in fields}
 r['child_usage']['cpu_seconds']=r['child_usage']['ru_utime']+r['child_usage']['ru_stime']
 r['child_usage']['wall_seconds']=None if r['command'] is None else r['command']['seconds']
 r['configuration_unchanged']=a.cargo_configuration(environment)==configuration
 r['inputs_unchanged']=all(fact(p)==v for p,v in inputs.items())
 r['source_unchanged']=a.source_state()==before and os.sched_getaffinity(0)=={cpu}
 if not all(r[k]for k in('source_unchanged','configuration_unchanged','inputs_unchanged')):r['status']='failed'
 if (out/'measurement.log').exists():r['log']=fact(out/'measurement.log')
 profiles=sorted(p for p in out.glob('profile*') if p.is_file())
 r['profile_samples']={p.name:fact(p) for p in profiles}
 if not profiles and r['status']=='passed_isolated_only':r['status']='failed';r['error']='missing sampling output'
 (out/'receipt.json').write_text(json.dumps(r,sort_keys=True)+'\n')
print(json.dumps(dict(status=r['status'],command=r['command'],error=r['error'],source_unchanged=r['source_unchanged'],receipt=fact(out/'receipt.json'))),flush=True)
raise SystemExit(r['status']!='passed_isolated_only')
