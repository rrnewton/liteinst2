#!/usr/bin/env python3
"""Replay fixed synthetic controls; no E9 producer or application execution."""
import hashlib,json,os,platform,signal,subprocess,time
from pathlib import Path
import argparse
parser=argparse.ArgumentParser(description="Reproduce the two finite E9 inventory control suites at their recorded source revision.")
parser.add_argument("--repo",type=Path,required=True)
parser.add_argument("--raw",type=Path,required=True)
args=parser.parse_args()
r=args.repo;raw=args.raw
assert r.is_absolute() and r.resolve(strict=True)==r
assert raw.is_absolute() and raw.parent.resolve(strict=True)==raw.parent and raw.is_relative_to(r/"ignored") and not raw.exists()
raw.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
save=lambda name,v:(raw/name).write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")
revision=subprocess.check_output(["git","rev-parse","HEAD"],cwd=r,text=True).strip()
assert revision=="e57a72c62fc569bd09c12815f7c9eec5162f3a50"
assert not subprocess.check_output(["git","diff","HEAD","--"],cwd=r)
names=subprocess.check_output(["git","ls-files","-z"],cwd=r).decode().rstrip("\0").split("\0")
before={n:sha(r/n) for n in names}
save("source-before.json",dict(revision=revision,files=before))
save("hardware.json",dict(host_label="AMD EPYC Zen 5 dev host",architecture=platform.machine(),cpu_model=next(x.split(":",1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name")),logical_cpus=os.cpu_count(),kernel_release=platform.release(),libc=platform.libc_ver()))
helper=r/"tools/unwind-oracle/bounded_command.py";hs=sha(helper)
assert hs=="c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
env=dict(PATH="/usr/bin:/bin",LC_ALL="C",PYTHONDONTWRITEBYTECODE="1")
save("tools.json",{str(p):dict(resolved=str(p.resolve()),sha256=sha(p.resolve())) for p in map(Path,["/usr/bin/python3.9","/usr/bin/timeout"])})
expected_adapter=b'accepted complete-two-sites\naccepted explicit-refusal-retained\naccepted explicit-traps-retained\nrefused missing-patch\nrefused extra-patch\nrefused wrong-descending-order\nrefused duplicate-instruction\nrefused changed-pc\nrefused changed-length\nrefused wrong-file-offset\nrefused stale-original\nrefused stale-selection\nrefused stale-producer-revision\nrefused missing-debug-site\nrefused duplicate-debug-site\nrefused extra-debug-site\nrefused debug-length-disagreement\nrefused contradictory-statistics\nrefused unknown-warning\nrefused absent-mapping-owner\nrefused loader-map-disagreement\nrefused trampoline-extent-outside-owner\nrefused gateway-wrong-target\nrefused unowned-original-byte-change\nrefused trap-not-declared\nrefused trap-request-not-emitted\nrefused stale-producer-bytes\ne9-sites controls: 3 accepted / 24 refused; synthetic only\n'
expected_comparator=b"comparison calibrations: one exact loss/trap inventory and five required refusals\ncomparison calibrations: original one/five retained; total three positives and 24 required refusals\n"
stages=[("adapter","tools/elf-rewrite/e9-sites-controls.py",expected_adapter),("comparator","tools/elf-rewrite/tests/compare_sites.py",expected_comparator)]
save("inventory.json",[dict(name=n,script=p,expected_stdout_sha256=hashlib.sha256(e).hexdigest(),accepted=3,refused=24) for n,p,e in stages])
results=[];complete=False
try:
 for name,source,expected in stages:
  d=raw/name;d.mkdir();(d/"tmp").mkdir()
  request=dict(argv=["/usr/bin/python3.9","-B",str(r/source)],cwd=str(r),env=dict(env,TMPDIR=str(d/"tmp")),stdout=str(d/"stdout.txt"),stderr=str(d/"stderr.txt"),cpu_seconds=20,wall_seconds=30,file_bytes=16777216)
  save(name+"/request.json",request)
  argv=["/usr/bin/timeout","--signal=TERM","--kill-after=10s","40s","/usr/bin/python3.9","-B",str(helper),"--request",str(d/"request.json"),"--receipt",str(d/"receipt.json")]
  save(name+"/command.json",dict(argv=argv,env=env,cwd=str(r),parent_timeout_seconds=55))
  t=time.monotonic()
  with (d/"helper.stdout").open("xb") as out,(d/"helper.stderr").open("xb") as err:
   proc=subprocess.Popen(argv,cwd=r,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
   timed=False
   try:rc=proc.wait(timeout=55)
   except subprocess.TimeoutExpired:
    timed=True;os.killpg(proc.pid,signal.SIGKILL);rc=proc.wait()
  result=dict(name=name,exit=rc,timed_out=timed,parent_wait_completed=True,elapsed_seconds=time.monotonic()-t)
  save(name+"/result.json",result);results.append(result)
  assert not timed and rc==0
  v=json.loads((d/"receipt.json").read_bytes())
  assert set(v)=={"request_sha256","helper_sha256","exit","wall_timeout","unexpected_descendants","absence_proof","stdout_sha256","stderr_sha256","elapsed_seconds","cleanup_events","cleanup_error","aborted","inputs_unchanged"}
  assert v["request_sha256"]==sha(d/"request.json") and v["helper_sha256"]==hs
  assert type(v["exit"]) is int and v["exit"]==0 and v["wall_timeout"] is False and v["inputs_unchanged"] is True
  assert v["unexpected_descendants"]==v["cleanup_events"]==[] and v["cleanup_error"] is None and v["aborted"] is None and v["absence_proof"]=="ECHILD"
  for stream in ["stdout","stderr"]:assert v[stream+"_sha256"]==sha(d/(stream+".txt"))
  terminal=dict(exit=0,wall_timeout=False,absence_proof="ECHILD",descendants=0,success=True)
  assert (d/"helper.stdout").read_bytes()==(json.dumps(terminal)+"\n").encode() and not (d/"helper.stderr").read_bytes()
  assert (d/"stdout.txt").read_bytes()==expected and not (d/"stderr.txt").read_bytes()
  print(name,"3 accepted / 24 refused; synthetic only",flush=True)
 complete=True
finally:
 after={n:sha(r/n) for n in names};save("source-after.json",dict(revision=subprocess.check_output(["git","rev-parse","HEAD"],cwd=r,text=True).strip(),files=after))
 assert after==before and revision==subprocess.check_output(["git","rev-parse","HEAD"],cwd=r,text=True).strip() and not subprocess.check_output(["git","diff","HEAD","--"],cwd=r)
 save("summary.json",dict(revision=revision,completed=complete,results=results,synthetic_only=True,producer_runs=0,native_runs=0,qualification_complete=False))
