"""Actual native/gated finite resident-dispatch launch with an in-Python signal reset.

Preparation records observed process state, not target completion. Gated
carrier preparation separately records the complete final exec environment.
"""
import sys
sys.dont_write_bytecode = True
import argparse, ctypes, hashlib, json, os, stat
from pathlib import Path



def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--role',choices=('native','gated'),required=True)
    p.add_argument('--mode',type=int,choices=(0,),required=True)
    p.add_argument('--control',type=int,choices=(0,),required=True)
    p.add_argument('--original',type=Path,required=True)
    p.add_argument('--library-root',type=Path,action='append',required=True)
    p.add_argument('--preparation',type=Path,required=True)
    p.add_argument('--namespace',type=Path)
    p.add_argument('--carrier',type=Path)
    p.add_argument('--record-fd',type=int)
    a=p.parse_args()
    sys.path[:0]=[str(a.root/'evaluation/inprocess'),str(a.root/'tools/page-entry')]
    from page_selected_process import Action
    from carrier import FOOT, META, PH, MAX_FILE
    globals().update(FOOT=FOOT,META=META,PH=PH,MAX_FILE=MAX_FILE)
    if a.control or a.mode!=0:
        raise ValueError('exact resident271 loop-only profile')
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
    argv=[str(original),str(a.mode),a.role]
    prep=dict(schema_version=1,status='prepared_not_executed',role=a.role,pid=os.getpid(),
              cpu=sorted(os.sched_getaffinity(0)),previous_mask=previous.value,reset_mask=actual.value,
              dispositions=observations,observer=observer,argv=argv,default_rseq=False,mode=a.mode,control=a.control)
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0')
    if a.role=='gated':
        prep.update(launch_mask=actual.value,late_sonames=[],environment_source=str(a.namespace.absolute()/'launch.json'))
        with a.preparation.open('x') as f:json.dump(prep,f,sort_keys=True)
        execute_dynamic_loader(a.carrier,original,roots,a.namespace,argv,capture_control=a.control,mode=a.mode)
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


def execute_dynamic_loader(carrier, original, roots, directory, argv, fork_fds=None, child_failure=0, disable_rseq=True, provider_policy=None, *, late_sonames=(), capture_control, mode):
    if type(mode)is not int or mode!=0 or type(capture_control)is not int or capture_control!=0 or fork_fds is not None or child_failure or disable_rseq is not True or provider_policy is not None or late_sonames:
        raise ValueError('exact finite resident-dispatch configuration')
    # This separate command intentionally supplies a private namespace and a
    # closed environment. The original fixture's make/exec path is unchanged.
    if provider_policy not in (None, "mask-random-v1", "deterministic-builtins-v1"):
        raise ValueError("unknown selected provider policy")
    import namespace
    with carrier.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if not FOOT.size + META.size <= len(data) <= MAX_FILE:
        raise ValueError("loader carrier size")
    magic, offset, size = FOOT.unpack_from(data, len(data) - FOOT.size)
    if magic != b"LI2END01" or offset + size != len(data) - FOOT.size or size < META.size:
        raise ValueError("loader carrier footer")
    meta = META.unpack_from(data, offset)
    if meta[0] != b"LI2BOOT1" or meta[1] != 1 or meta[9] != 0 or not 1 <= meta[4] <= 32:
        raise ValueError("loader carrier metadata")
    if size != META.size + meta[4] * PH.size + meta[6]:
        raise ValueError("loader carrier metadata extent")
    fds, directory = namespace.prepare(original, roots, directory, meta[10], meta[11], late_sonames=late_sonames)
    fd = None
    try:
        fd = namespace.sealed_bytes("li2-private-loader-carrier", data, False)
        argv = argv[1:] if argv[:1] == ["--"] else argv
        argv = argv or [str(original)]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
               "LD_LIBRARY_PATH": str(directory), "LD_BIND_NOW": "1",
               "LI2_DEPENDENCY_FDS": ",".join(str(item) for item in fds)}
        env['LI2_PERSISTENT_RESIDENT_APP_MODE']=str(mode)
        if provider_policy is not None:
            env["LI2_SELECTED_PROVIDER"] = provider_policy
        if disable_rseq:
            # Explicit named workload only; never inherit arbitrary caller tunables.
            env["GLIBC_TUNABLES"] = "glibc.pthread.rseq=0"
        if fork_fds is not None:
            if len(fork_fds) != 2 or fork_fds[0] == fork_fds[1] or any(item <= 2 for item in fork_fds):
                raise ValueError("distinct fork report descriptors")
            for item in fork_fds:
                if not stat.S_ISFIFO(os.fstat(item).st_mode):
                    raise ValueError("fork report descriptor is not a pipe")
            env["LI2_RAW_FORK"] = "1"
            env["LI2_FORK_REPORT_FDS"] = ",".join(str(item) for item in fork_fds)
            if child_failure:
                if child_failure not in (1, 2, 3, 4):
                    raise ValueError("child failure step")
                env["LI2_FORK_CHILD_FAILURE"] = str(child_failure)
        # Preparation is reproducible and retained even if exec fails. This is
        # not an execution receipt and cannot claim the linker used these files.
        (directory / "launch.json").write_text(json.dumps({
            "schema_version": 1, "scope": "first_entry_loader_candidate", "status": "prepared_not_executed",
            "carrier_sha256": hashlib.sha256(data).hexdigest(), "carrier_size": len(data),
            "argv": argv, "environment": env, "dependency_fds": fds,
        }, indent=2, sort_keys=True) + "\n")
        os.execve(fd, argv, env)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


if __name__=='__main__':main()
