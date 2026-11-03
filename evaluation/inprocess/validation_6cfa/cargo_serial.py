import json,os,resource,sys
from pathlib import Path
root=Path.cwd();sys.path.insert(0,str(root/'evaluation/inprocess'))
import checks
a=checks.admission
assert len(os.sched_getaffinity(0))==4
out=root/'target/evaluation/inprocess/cargo-checks-6cfa-attempt-1';out.mkdir();(out/'tmp').mkdir()
before=checks.source();assert before['revision']=='6cfa572f2ba8d2cad10077f3674e0cca5de4a084'
env=a.controlled_environment(os.environ,out/'tmp');configuration=a.cargo_configuration(env)
corpus=json.loads((checks.ADMISSION/'corpus.json').read_bytes());a.core_cc846_inventory.require_current(corpus)
commands=[dict(id=n,argv=v,timeout_seconds=t,status='not_run',environment_delta={'LITEINST_EVALUATION':'1'} if n=='serial_launch' else {}) for n,v,t in checks.COMMANDS if n!='recorder_tests']
assert len(commands)==5
r=dict(schema=1,profile='required-cargo-and-serial-only',source=before,hardware=checks.hardware(min(os.sched_getaffinity(0))),configuration=configuration,commands=commands,status='failed',error=None,source_unchanged=False,configuration_unchanged=False,full_required_checks_passed=False,scope='Original four Cargo commands and original serial suite. Recorder180-second failure remains separate and failed; this run cannot qualify the complete required profile.')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
try:
 for c in commands:
  log=out/(c['id']+'.log');c.update(a.run_command(c['argv'],env|c['environment_delta'],log,c['timeout_seconds']))
  c['status']='passed' if c['exit_code']==0 and c['termination'] is None and c['cleanup_complete'] else 'failed'
  a.command_evidence(c,log.read_text(errors='replace'),corpus)
  print(json.dumps({k:c[k]for k in ('id','status','exit_code','seconds')}),flush=True)
  if c['status']!='passed':break
 r['source_unchanged']=checks.source()==before;r['configuration_unchanged']=a.cargo_configuration(env)==configuration
 if all(c['status']=='passed' for c in commands) and r['source_unchanged'] and r['configuration_unchanged']:r['status']='passed_cargo_and_serial_only'
except BaseException as e:r['error']=repr(e)
finally:
 for c in commands:checks.compact(c)
 (out/'receipt.json').write_text(json.dumps(r,sort_keys=True,indent=2)+'\n')
 print(json.dumps(dict(status=r['status'],error=r['error'],source_unchanged=r['source_unchanged'],receipt=str(out/'receipt.json'))),flush=True)
raise SystemExit(r['status']!='passed_cargo_and_serial_only')
