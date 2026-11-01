"""One native D3 fixture exec with the existing exact selected signal preparation."""
import sys
sys.dont_write_bytecode=True
import argparse,ctypes,json,os
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--original',type=Path,required=True)
    p.add_argument('--preparation',type=Path,required=True)
    a=p.parse_args()
    sys.path.insert(0,str(a.root/'evaluation/inprocess'))
    from page_selected_process import Action
    original=a.original.resolve(strict=True)
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    previous=ctypes.c_uint64();empty=ctypes.c_uint64();actual=ctypes.c_uint64(1)
    if libc.syscall(14,2,ctypes.byref(empty),ctypes.byref(previous),8):raise OSError('signal mask reset')
    observations=[]
    for number in range(1,65):
        if number in (9,19):continue
        before,zero,after=Action(),Action(),Action()
        if (libc.syscall(13,number,None,ctypes.byref(before),8) or
            libc.syscall(13,number,ctypes.byref(zero),None,8) or
            libc.syscall(13,number,None,ctypes.byref(after),8) or after.handler):
            raise OSError('signal action reset')
        observations.append(dict(signal=number,before=int(before.handler or 0),after=int(after.handler or 0)))
    if libc.syscall(14,2,None,ctypes.byref(actual),8) or actual.value:raise OSError('actual empty signal mask')
    argv=[str(original),'native']
    prep=dict(schema_version=1,status='prepared_not_executed',role='native',pid=os.getpid(),
              cpu=sorted(os.sched_getaffinity(0)),previous_mask=previous.value,reset_mask=actual.value,
              dispositions=observations,observer=None,argv=argv,default_rseq=False)
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0')
    mask=ctypes.c_uint64(((1<<64)-1)^sum(1<<(s-1) for s in (4,5,9,11,19,31)))
    if libc.syscall(14,2,ctypes.byref(mask),None,8) or libc.syscall(14,2,None,ctypes.byref(actual),8) or actual.value!=mask.value:
        raise OSError('exact selected native signal mask')
    prep['launch_mask']=actual.value
    env['LD_LIBRARY_PATH']='/usr/lib64'
    prep.update(environment=env)
    with a.preparation.open('x') as f:json.dump(prep,f,sort_keys=True)
    os.execve(original,argv,env)
    raise RuntimeError('exec returned')

if __name__=='__main__':main()
