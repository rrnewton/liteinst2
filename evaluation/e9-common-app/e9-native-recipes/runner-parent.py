from pathlib import Path
import datetime,hashlib,json,os,resource,subprocess,sys,time
if sys.flags.optimize: raise SystemExit("assertions required")
p=Path(__file__).resolve().parent
c=json.loads((p/'command.json').read_bytes())
assert hashlib.sha256(Path(c['argv'][2]).read_bytes()).hexdigest()==c['recipe_sha256']
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
os.sched_setaffinity(0,c['affinity'])
assert sorted(os.sched_getaffinity(0))==c['affinity']
started=time.monotonic()
with (p/'stdout.txt').open('xb') as out,(p/'stderr.txt').open('xb') as err:
 child=subprocess.Popen(c['argv'],cwd=c['cwd'],env=c['env'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
 with (p/'started.json').open('x') as f:json.dump(dict(pid=child.pid,start_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),command_sha256=hashlib.sha256((p/'command.json').read_bytes()).hexdigest()),f,indent=2)
 print('Recipe child started',child.pid,flush=True)
 code=child.wait()
row=dict(exit=code,pid=child.pid,parent_wait_returned=True,operational_seconds=time.monotonic()-started,stdout_sha256=hashlib.sha256((p/'stdout.txt').read_bytes()).hexdigest(),stderr_sha256=hashlib.sha256((p/'stderr.txt').read_bytes()).hexdigest(),scope='Actual caller wait on recipe child; helper descendant closure remains separately required.')
with (p/'closed.json').open('x') as f:json.dump(row,f,indent=2,sort_keys=True)
print(json.dumps(row,sort_keys=True),flush=True)
raise SystemExit(code)
