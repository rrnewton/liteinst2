"""Private normal-loader launch; target argv and default libc rseq stay intact."""
import sys
sys.dont_write_bytecode = True
import argparse, ctypes, fcntl, hashlib, json, os, stat
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--role',choices=('reference','gated'),required=True)
    p.add_argument('--original',type=Path,required=True)
    p.add_argument('--dso',type=Path,required=True)
    p.add_argument('--library-root',type=Path,action='append',required=True)
    p.add_argument('--namespace',type=Path,required=True)
    p.add_argument('--preparation',type=Path,required=True)
    p.add_argument('--tracer',type=Path);p.add_argument('--reference-output',type=Path)
    p.add_argument('--carrier',type=Path);p.add_argument('--record-fd',type=int)
    p.add_argument('--mode',choices=('state','stress'));p.add_argument('--policy',choices=('native','scripted'))
    a=p.parse_args()
    sys.path[:0]=[str(a.root/'evaluation/inprocess'),str(a.root/'tools/page-entry')]
    from page_selected_process import Action
    import namespace,carrier
    observer=None;fds=[]
    try:
        if a.role=='gated':
            if a.record_fd is None or a.carrier is None or a.mode is None or a.policy is None:
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
        # Same actual reset as provider_builtins/launch.py; only the independent
        # native tracer receives the exact selected mask before its real exec.
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
        prep=dict(role=a.role,pid=os.getpid(),cpu=sorted(os.sched_getaffinity(0)),
            previous_mask=previous.value,reset_mask=actual.value,dispositions=observations,observer=observer)
        env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1')
        if a.role=='gated':
            argv=[str(a.original),a.mode,a.policy]
            prep.update(argv=argv,environment=env,default_rseq=True)
            with a.preparation.open('x') as f:json.dump(prep,f,sort_keys=True)
            carrier.execute_loader(a.carrier,a.original,a.library_root,a.namespace,argv,disable_rseq=False)
            raise RuntimeError('exec returned')
        if a.tracer is None or a.reference_output is None or a.reference_output.exists():
            raise ValueError('fresh exact native reference output')
        source=a.original.read_bytes();interpreter=namespace.parse(source)['interpreter'].read_bytes()
        fds,directory=namespace.prepare(a.original,a.library_root,a.namespace,
            hashlib.sha256(source).digest(),hashlib.sha256(interpreter).digest())
        ns=json.loads((directory/'namespace.json').read_bytes())
        rows=[r for r in ns['objects'] if 'libli2-provider-app.so' in r['names']]
        expected=a.dso.read_bytes()
        if len(rows)!=1 or rows[0]['sha256']!=hashlib.sha256(expected).hexdigest() or rows[0]['size']!=len(expected):
            raise ValueError('exact sealed original DSO')
        main=namespace.sealed_bytes('li2-native-original',source,True);fds.append(main);st=os.fstat(main)
        mask=ctypes.c_uint64(((1<<64)-1)^sum(1<<(s-1) for s in (4,5,9,11,19,31)))
        if libc.syscall(14,2,ctypes.byref(mask),None,8) or libc.syscall(14,2,None,ctypes.byref(actual),8) or actual.value!=mask.value:
            raise OSError('exact selected native signal mask')
        argv=[str(a.tracer),'/proc/self/fd/'+str(main),'/proc/self/fd/'+str(rows[0]['fd']),str(a.reference_output)]
        env.update(LD_LIBRARY_PATH=str(directory))
        prep.update(argv=argv,environment=env,default_rseq=True,mask=actual.value,
            main=dict(fd=main,device=st.st_dev,inode=st.st_ino,bytes=st.st_size,
                      sha256=hashlib.sha256(source).hexdigest(),seals=fcntl.fcntl(main,fcntl.F_GET_SEALS)),
            dso_fd=rows[0]['fd'])
        with a.preparation.open('x') as f:json.dump(prep,f,sort_keys=True)
        os.execve(a.tracer,argv,env)
    finally:
        for fd in reversed(fds):os.close(fd)

if __name__=='__main__':main()
