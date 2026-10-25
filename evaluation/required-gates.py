#!/usr/bin/env python3
"""Exact-head required workspace checks. All outputs remain private."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--repo',type=Path,default=Path.cwd())
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
ROOT=args.repo.resolve()
OUT=args.output.resolve()
assert OUT.is_relative_to(ROOT/'ignored') and OUT!=ROOT/'ignored'
OUT.mkdir()
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def git(*args):return subprocess.check_output(['/usr/bin/git',*args],cwd=ROOT)
head=git('rev-parse','HEAD').decode().strip()
assert not git('diff','--binary','HEAD')
names=git('ls-files','-z').decode().split('\0')[:-1]
sources={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names}
assert 'BRIEF-li2core.md' not in names
env=dict(os.environ,CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_TARGET_DIR=str(ROOT/'target'),RUST_TEST_THREADS='4',CARGO_NET_OFFLINE='true',TMPDIR=str(OUT))
commands=[
 ('fmt',['cargo','fmt','--check']),
 ('clippy',['cargo','clippy','--workspace','--all-targets','--all-features','--','-D','warnings']),
 ('test',['cargo','test','--workspace']),
 ('check',['cargo','check','--workspace','--all-features','--all-targets']),
]
records=[]
for name,argv in commands:
 timeout=360 if name=='test' else 180
 start=time.monotonic();utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
 log=OUT/(name+'.log')
 with log.open('wb') as stream:
  process=subprocess.Popen(argv,cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
  try:code=process.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   os.killpg(process.pid,signal.SIGKILL);process.wait();code='timeout'
 record=dict(name=name,argv=argv,timeout_seconds=timeout,start_utc=utc,exit=code,seconds=time.monotonic()-start,log=str(log.relative_to(ROOT)),sha256=hashlib.sha256(log.read_bytes()).hexdigest())
 records.append(record)
 receipt=dict(head=head,tracked_diff_sha256=hashlib.sha256(b'').hexdigest(),source_sha256=sources,records=records)
 (OUT/'commands.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps(record),flush=True)
 if code!=0:
  print(log.read_text()[-10000:],flush=True)
  raise SystemExit('required workspace gate failed')
assert git('rev-parse','HEAD').decode().strip()==head
assert not git('diff','--binary','HEAD')
assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in sources.items())
print('PASS exact-head receipt '+str(OUT/'commands.json'),flush=True)
