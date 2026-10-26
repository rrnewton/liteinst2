#!/usr/bin/env python3
"""One explicitly requested private command with owned-descendant cleanup.

Copied ownership/absence implementation from the reviewed and calibrated parked
runner v5. This helper is not a sandbox. SIGKILL of this supervising process
cannot execute Python cleanup; normal command success/failure/timeout and
catchable supervisor interruption use the same bounded cleanup path.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

if sys.flags.optimize:
 raise SystemExit('Assertions required')
ROOT=Path(__file__).resolve().parents[2]
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
# This dedicated runner owns no unrelated children. Adoption keeps nested
# process groups within the cleanup boundary even if their watchdog dies.
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
libc.prctl.restype=ctypes.c_int
if libc.prctl(36,1,0,0,0)!=0: raise OSError(ctypes.get_errno(),'PR_SET_CHILD_SUBREAPER')
flag=ctypes.c_int()
if libc.prctl(37,ctypes.addressof(flag),0,0,0)!=0: raise OSError(ctypes.get_errno(),'PR_GET_CHILD_SUBREAPER')
assert flag.value==1
def owned_children(deadline):
 # Some kernels omit /proc/TID/children. Inspect only immediate numeric process
 # records, with a finite directory/read bound; this is not recursive traversal.
 if time.monotonic()>=deadline: raise RuntimeError('owned process inventory deadline')
 result=[];owner=os.getpid();count=0
 with os.scandir('/proc') as entries:
  for entry in entries:
   if time.monotonic()>=deadline: raise RuntimeError('owned process inventory deadline')
   count+=1
   if count>65536: raise RuntimeError('process inventory exceeds finite bound')
   if not entry.name.isascii() or not entry.name.isdecimal(): continue
   try:
    with open('/proc/'+entry.name+'/stat','rb') as stream: raw=stream.read(4097)
   except OSError as error:
    if error.errno in (errno.ENOENT,errno.ESRCH): continue
    raise
   assert len(raw)<=4096 and raw.startswith(entry.name.encode()+b' (')
   close=raw.rfind(b') ')
   assert close!=-1
   fields=raw[close+2:].split()
   assert len(fields)>=2
   if int(fields[1])==owner: result.append(int(entry.name))
 if time.monotonic()>=deadline: raise RuntimeError('owned process inventory deadline')
 return result
try: os.waitpid(-1,os.WNOHANG)
except ChildProcessError: pass
else: raise RuntimeError('dedicated runner started with an owned child')
def cleanup_children(direct):
 events=[];deadline=time.monotonic()+5
 while True:
  children=owned_children(deadline)
  if time.monotonic()>=deadline: raise RuntimeError('owned descendant cleanup exceeded five seconds')
  if not children:
   # Directory enumeration can race adoption/fork. ECHILD is the actual
   # terminal proof; zero means at least one owned child remains alive.
   try: dead,status=os.waitpid(-1,os.WNOHANG)
   except ChildProcessError: return events,'ECHILD'
   if dead:
    events.append(dict(pid=dead,event='reaped',status=status))
    if dead==direct.pid: direct.returncode=os.waitstatus_to_exitcode(status)
   time.sleep(.01)
   continue
  for pid in children:
   try: dead,status=os.waitpid(pid,os.WNOHANG)
   except ChildProcessError: continue
   if dead:
    events.append(dict(pid=pid,event='reaped',status=status))
    if pid==direct.pid: direct.returncode=os.waitstatus_to_exitcode(status)
    continue
   # An owned live child cannot recycle its PID before we reap it, including
   # the exit race between waitpid and kill. We never signal an arbitrary PID.
   try: os.kill(pid,signal.SIGKILL)
   except ProcessLookupError: pass
   events.append(dict(pid=pid,event='kill_requested'))
  time.sleep(.01)

def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--request',type=Path,required=True)
 parser.add_argument('--receipt',type=Path,required=True)
 args=parser.parse_args()
 request_path=args.request.resolve();receipt_path=args.receipt.resolve()
 assert request_path.is_relative_to(ROOT/'ignored') and receipt_path.is_relative_to(ROOT/'ignored')
 assert not receipt_path.exists() and receipt_path.parent.is_dir()
 request_digest=sha(request_path);helper_digest=sha(__file__)
 request=json.loads(request_path.read_text())
 assert set(request)=={'argv','cwd','env','stdout','stderr','cpu_seconds','wall_seconds','file_bytes'}
 assert isinstance(request['argv'],list) and request['argv'] and all(isinstance(x,str) and '\0' not in x for x in request['argv'])
 assert isinstance(request['env'],dict) and all(isinstance(k,str) and isinstance(v,str) and '\0' not in k+v and '=' not in k for k,v in request['env'].items())
 cwd=Path(request['cwd']).resolve()
 assert cwd.is_relative_to(ROOT) and cwd.is_dir()
 for key in ('cpu_seconds','wall_seconds','file_bytes'):
  assert type(request[key]) is int and request[key]>0
 assert request['cpu_seconds']<=120 and request['wall_seconds']<=180 and request['file_bytes']<=256*1024*1024
 stdout_path=Path(request['stdout']).resolve();stderr_path=Path(request['stderr']).resolve()
 assert len({stdout_path,stderr_path,request_path,receipt_path})==4
 for path in (stdout_path,stderr_path):
  assert path.is_relative_to(ROOT/'ignored') and path.parent.is_dir() and not path.exists()
 def limits():
  for kind,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_CPU,request['cpu_seconds']),(resource.RLIMIT_FSIZE,request['file_bytes'])):
   resource.setrlimit(kind,(value,value))
 def interrupt(signum,frame): raise KeyboardInterrupt('supervisor signal '+str(signum))
 old_handlers={sig:signal.signal(sig,interrupt) for sig in (signal.SIGTERM,signal.SIGHUP)}
 direct=SimpleNamespace(pid=-1,returncode=None)
 timed_out=False;aborted=None;cleanup_error=None;cleanup=[];absence=None
 started=time.monotonic()
 try:
  with stdout_path.open('xb') as stdout,stderr_path.open('xb') as stderr:
   direct=subprocess.Popen(request['argv'],cwd=cwd,env=request['env'],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,preexec_fn=limits)
   try: direct.wait(timeout=request['wall_seconds'])
   except subprocess.TimeoutExpired:
    timed_out=True
    try: os.killpg(direct.pid,signal.SIGKILL)
    except ProcessLookupError: pass
 except BaseException as error: aborted=type(error).__name__+': '+str(error)
 finally:
  try: cleanup,absence=cleanup_children(direct)
  except BaseException as error: cleanup_error=type(error).__name__+': '+str(error)
  for sig,handler in old_handlers.items(): signal.signal(sig,handler)
 descendants=sorted({row['pid'] for row in cleanup if row['pid']!=direct.pid})
 unchanged=sha(request_path)==request_digest and sha(__file__)==helper_digest
 receipt=dict(request_sha256=request_digest,helper_sha256=helper_digest,exit=direct.returncode,wall_timeout=timed_out,unexpected_descendants=descendants,absence_proof=absence,stdout_sha256=sha(stdout_path) if stdout_path.exists() else None,stderr_sha256=sha(stderr_path) if stderr_path.exists() else None,elapsed_seconds=time.monotonic()-started,cleanup_events=cleanup,cleanup_error=cleanup_error,aborted=aborted,inputs_unchanged=unchanged)
 with receipt_path.open('x') as stream: json.dump(receipt,stream,indent=2);stream.write('\n')
 success=direct.returncode==0 and not timed_out and not descendants and absence=='ECHILD' and cleanup_error is None and aborted is None and unchanged
 print(json.dumps(dict(exit=direct.returncode,wall_timeout=timed_out,absence_proof=absence,descendants=len(descendants),success=success)),flush=True)
 return 0 if success else 1

if __name__=='__main__': raise SystemExit(main())
