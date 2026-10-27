#!/usr/bin/env python3
"""Authenticate the complete private compiler tree, fchdir, then exec exact rustc."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import argparse, hashlib, json, os, stat
from pathlib import Path
CAP = 128 * 1024 * 1024

def six(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def file_at(directory, name, pin):
    assert name and '/' not in name and name not in ('.','..')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno());assert stat.S_ISREG(before.st_mode)
        assert six(before)==pin['stat'] and before.st_size==pin['bytes']<=CAP
        digest=hashlib.sha256();count=0
        while True:
            b=stream.read(1024*1024)
            if not b:break
            count+=len(b);digest.update(b)
        assert count==pin['bytes'] and digest.hexdigest()==pin['sha256']
        assert six(os.fstat(stream.fileno()))==six(os.stat(name,dir_fd=directory,follow_symlinks=False))==pin['stat']

ap=argparse.ArgumentParser();ap.add_argument('--job',type=Path,required=True);ap.add_argument('--job-sha256',required=True)
a=ap.parse_args();repo=Path(__file__).resolve().parents[4]
assert a.job.is_absolute() and a.job.is_relative_to(repo/'ignored') and a.job.resolve(strict=True)==a.job
with os.fdopen(os.open(a.job,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
    st=os.fstat(f.fileno());data=f.read(4*1024*1024+1)
    assert stat.S_ISREG(st.st_mode) and len(data)==st.st_size<=4*1024*1024
    assert six(st)==six(os.fstat(f.fileno()))==six(a.job.lstat())
assert hashlib.sha256(data).hexdigest()==a.job_sha256
def unique(pairs):
    out={}
    for key,value in pairs:assert key not in out;out[key]=value
    return out
job=json.loads(data,object_pairs_hook=unique);assert set(job)=={'schema','scope','input_root','directories','files','rustc','argv','env','entry'};assert job['schema']==1 and job['scope']=='DIRECT_RUSTC_CANONICAL_PRIVATE_INPUTS'
root=Path(job['input_root']);assert root.is_relative_to(repo/'ignored') and root.resolve(strict=True)==root
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
rootfd=os.open(root,flags);assert six(os.fstat(rootfd))==job['directories']['']==six(root.lstat())
os.fchdir(rootfd)
assert six(os.stat('.'))==job['directories'][''] and os.getcwd()==str(root)
assert set(os.listdir(rootfd))=={'src','deps'} and set(job['directories'])=={'','src','deps'}
fds={'':rootfd}
for name in ('src','deps'):
    fd=os.open(name,flags,dir_fd=rootfd);fds[name]=fd
    assert six(os.fstat(fd))==job['directories'][name]==six(os.stat(name,dir_fd=rootfd,follow_symlinks=False))
    expected={p.split('/')[1] for p in job['files'] if p.startswith(name+'/')}
    assert set(os.listdir(fd))==expected
for name,pin in job['files'].items():
    parts=name.split('/');assert len(parts)==2 and parts[0] in ('src','deps')
    file_at(fds[parts[0]],parts[1],pin)
for name,fd in fds.items():assert six(os.fstat(fd))==job['directories'][name]
# No /proc/self/fd paths are passed to rustc or its linker. The kernel cwd
# reference survives exec and child close_fds independently of these FD numbers.
tool=job['rustc'];rustc=Path(tool['resolved'])
assert rustc.is_absolute() and rustc.resolve(strict=True)==rustc
fd=os.open(rustc,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(os.dup(fd),'rb') as stream:
    st=os.fstat(stream.fileno());value=stream.read(CAP+1)
    assert stat.S_ISREG(st.st_mode) and st.st_mode&0o111 and len(value)==st.st_size<=CAP
    assert six(st)==tool['stat']==six(os.fstat(fd))==six(rustc.lstat()) and hashlib.sha256(value).hexdigest()==tool['sha256']
assert job['argv'][0]==str(rustc) and job['argv'][1:3]==['--crate-name','verify_common_core']
assert os.execve in os.supports_fd
entry=Path(job['entry']);assert entry.parent==a.job.parent and not entry.exists()
with entry.open('x') as stream:stream.write(json.dumps(dict(schema=1,job_sha256=a.job_sha256,pid=os.getpid(),cwd=str(root),cwd_owner=six(os.stat('.')),directories=job['directories'],files=job['files'],rustc=tool,argv=job['argv'],env=job['env'],scope='pre-exec authentication only; compiler receipt and parent closure remain required'),sort_keys=True,indent=2)+'\n')
os.execve(fd,job['argv'],job['env'])
