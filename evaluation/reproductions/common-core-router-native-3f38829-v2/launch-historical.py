#!/usr/bin/env python3
"""Retain the direct outer parent of the bounded synthetic router caller."""
import hashlib,json,os,signal,subprocess,time
from pathlib import Path
root=Path.cwd();base=root/'ignored/a3/common-core-router-native-integration-v2'
caller=root/'ignored/a3/common-core-router-native-caller-proposal-v1/run.py'
binding=base/'binding.json'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(caller)=='00661a3ab0b0f9abbae99403075dcdf0cec49fb1bb93368b8a9864c537bdf9fd'
assert sha(binding)=='92089e9bd8544aba7d8ba4269de329b22cb74ee32601d4e3e91025cbcb762716'
launch=base/'launch';launch.mkdir()
raw=root/'ignored/a3/common-core-router-native-validation-v2'
argv=['/usr/bin/python3.9','-B',str(caller),'--binding',str(binding),'--binding-sha256',sha(binding),'--raw',str(raw)]
env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'}
def save(name,value):
 with (launch/name).open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
save('command.json',dict(argv=argv,cwd=str(root),env=env,parent_timeout_seconds=145,caller_sha256=sha(caller),binding_sha256=sha(binding),parent_source_sha256=sha(Path(__file__))))
start=time.monotonic();error=None
with (launch/'stdout.txt').open('xb') as stdout,(launch/'stderr.txt').open('xb') as stderr:
 child=subprocess.Popen(argv,cwd=root,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
 save('started.json',dict(pid=child.pid,monotonic=start))
 try:code=child.wait(timeout=145)
 except subprocess.TimeoutExpired:
  error='parent_timeout';os.killpg(child.pid,signal.SIGKILL);code=child.wait(timeout=10)
closed=dict(exit=code,parent_error=error,parent_wait_returned=True,pid=child.pid,seconds=time.monotonic()-start,stdout_sha256=sha(launch/'stdout.txt'),stderr_sha256=sha(launch/'stderr.txt'))
save('closed.json',closed)
print(json.dumps(closed,sort_keys=True));print((launch/'stdout.txt').read_text()[-10000:]);print((launch/'stderr.txt').read_text()[-10000:])
raise SystemExit(0 if code==0 and error is None else 1)
