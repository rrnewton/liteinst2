#!/usr/bin/env python3
"""Fresh-path outer parent for the exact historical synthetic router caller."""
import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
if sys.flags.optimize:
 raise SystemExit('assertions are required')
parser=argparse.ArgumentParser(description=__doc__)
for name in ('repo','caller','binding','raw','new-launch'):
 parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--binding-sha256',required=True)
args=parser.parse_args()
root,caller,binding,raw,launch=args.repo,args.caller,args.binding,args.raw,args.new_launch
assert root.is_absolute() and root.resolve(strict=True)==root
for path in (caller,binding,raw,launch):
 assert path.is_absolute() and path.is_relative_to(root/'ignored')
 assert '..' not in path.parts and path.parent.resolve(strict=True)==path.parent
assert caller.is_file() and not caller.is_symlink() and binding.is_file() and not binding.is_symlink()
assert not raw.exists() and not raw.is_symlink() and not launch.exists() and not launch.is_symlink()
assert not raw.is_relative_to(launch) and not launch.is_relative_to(raw)
assert not caller.is_relative_to(raw) and not binding.is_relative_to(raw)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(caller)=='00661a3ab0b0f9abbae99403075dcdf0cec49fb1bb93368b8a9864c537bdf9fd'
assert sha(binding)==args.binding_sha256
assert json.loads(binding.read_bytes())['revision']=='3f388297f069432fbf5442d7003062dcf3962f95'
launch.mkdir()
argv=['/usr/bin/python3.9','-B',str(caller),'--binding',str(binding),'--binding-sha256',args.binding_sha256,'--raw',str(raw)]
env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'}
def save(name,value):
 with (launch/name).open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
save('command.json',dict(argv=argv,cwd=str(root),env=env,parent_timeout_seconds=145,caller_sha256=sha(caller),binding_sha256=args.binding_sha256,parent_source_sha256=sha(Path(__file__))))
start=time.monotonic();error=None
with (launch/'stdout.txt').open('xb') as stdout,(launch/'stderr.txt').open('xb') as stderr:
 child=subprocess.Popen(argv,cwd=root,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
 try:
  save('started.json',dict(pid=child.pid,monotonic=start))
  code=child.wait(timeout=145)
 except BaseException as exception:
  error='parent_timeout' if isinstance(exception,subprocess.TimeoutExpired) else repr(exception)
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  code=child.wait(timeout=10)
closed=dict(exit=code,parent_error=error,parent_wait_returned=True,pid=child.pid,seconds=time.monotonic()-start,stdout_sha256=sha(launch/'stdout.txt'),stderr_sha256=sha(launch/'stderr.txt'))
save('closed.json',closed)
print(json.dumps(closed,sort_keys=True));print((launch/'stdout.txt').read_text()[-10000:]);print((launch/'stderr.txt').read_text()[-10000:])
raise SystemExit(0 if code==0 and error is None else 1)
