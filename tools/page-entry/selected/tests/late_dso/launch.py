"""Actual native/gated late-DSO launch with an in-Python signal reset.

Preparation records observed process state, not target completion. Gated
carrier preparation separately records the complete final exec environment.
"""
import sys
sys.dont_write_bytecode = True
import argparse, ctypes, json, os, stat
from pathlib import Path

LD_SONAME = "libli2-late.so"


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--role',choices=('native','gated'),required=True)
    p.add_argument('--original',type=Path,required=True)
    p.add_argument('--library-root',type=Path,action='append',required=True)
    p.add_argument('--preparation',type=Path,required=True)
    p.add_argument('--namespace',type=Path)
    p.add_argument('--carrier',type=Path)
    p.add_argument('--record-fd',type=int)
    a=p.parse_args()
    sys.path[:0]=[str(a.root/'evaluation/inprocess'),str(a.root/'tools/page-entry')]
    from page_selected_process import Action
    import carrier
    original=a.original.resolve(strict=True)
    roots=[root.resolve(strict=True) for root in a.library_root]
    if not 1<=len(roots)<=8 or len(set(roots))!=len(roots) or any(not root.is_dir() or ':'in str(root) for root in roots):
        raise ValueError('bounded explicit native/gated library roots')
    observer=None
    if a.role=='gated':
        if a.record_fd is None or a.record_fd<3 or a.carrier is None or a.namespace is None:
            raise ValueError('complete actual gated command')
        prior=os.fstat(a.record_fd)
        if not stat.S_ISREG(prior.st_mode) or prior.st_size or os.lseek(a.record_fd,0,os.SEEK_CUR):
            raise ValueError('fresh actual private record file')
        os.dup2(a.record_fd,3,inheritable=True)
        if a.record_fd!=3:os.close(a.record_fd)
        held=os.fstat(3)
        if (held.st_dev,held.st_ino)!=(prior.st_dev,prior.st_ino) or not os.get_inheritable(3):
            raise ValueError('actual inherited observer descriptor')
        observer=dict(fd=3,device=held.st_dev,inode=held.st_ino)
    elif a.record_fd is not None or a.carrier is not None or a.namespace is not None:
        raise ValueError('native role does not prepare gated resources')
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
    prep=dict(schema_version=1,status='prepared_not_executed',role=a.role,pid=os.getpid(),
              cpu=sorted(os.sched_getaffinity(0)),previous_mask=previous.value,reset_mask=actual.value,
              dispositions=observations,observer=observer,argv=argv,default_rseq=True)
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1')
    if a.role=='gated':
        prep.update(launch_mask=actual.value,late_sonames=[LD_SONAME],environment_source=str(a.namespace.absolute()/'launch.json'))
        with a.preparation.open('x') as f:json.dump(prep,f,sort_keys=True)
        carrier.execute_loader(a.carrier,original,roots,a.namespace,argv,
                               disable_rseq=False,late_sonames=(LD_SONAME,))
        raise RuntimeError('exec returned')
    # Exact original native-reference launch policy. Gated starts reset/unblocked;
    # its runtime establishes the same selected application mask itself.
    mask=ctypes.c_uint64(((1<<64)-1)^sum(1<<(s-1) for s in (4,5,9,11,19,31)))
    if libc.syscall(14,2,ctypes.byref(mask),None,8) or libc.syscall(14,2,None,ctypes.byref(actual),8) or actual.value!=mask.value:
        raise OSError('exact selected native signal mask')
    prep['launch_mask']=actual.value
    env['LD_LIBRARY_PATH']=':'.join(str(root) for root in roots)
    prep.update(environment=env)
    with a.preparation.open('x') as f:json.dump(prep,f,sort_keys=True)
    os.execve(original,argv,env)
    raise RuntimeError('exec returned')


if __name__=='__main__':main()
