"""Actual fresh-exec launcher with an owned private diagnostic FD3."""
import argparse,ctypes,importlib.util,json,os,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected_process import Action

def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['native','gated'],required=True)
    p.add_argument('--original',type=Path,required=True);p.add_argument('--carrier',type=Path)
    p.add_argument('--namespace',type=Path);p.add_argument('--library-root',type=Path,required=True)
    p.add_argument('--preparation',type=Path,required=True);p.add_argument('--record-fd',type=int,required=True)
    p.add_argument('--carrier-adapter',type=Path,required=True);a=p.parse_args()
    sys.path.insert(0,str(ROOT/'tools/page-entry'))
    import namespace
    spec=importlib.util.spec_from_file_location('oneshot_test_carrier',a.carrier_adapter)
    carrier=importlib.util.module_from_spec(spec);spec.loader.exec_module(carrier)
    # All imports complete before the unchanged actual signal reset.
    prior=os.fstat(a.record_fd)
    if not stat.S_ISREG(prior.st_mode)or prior.st_size or os.lseek(a.record_fd,0,os.SEEK_CUR):
        raise ValueError('fresh actual private record file')
    os.dup2(a.record_fd,3,inheritable=True)
    if a.record_fd!=3:os.close(a.record_fd)
    observer=os.fstat(3)
    if(observer.st_dev,observer.st_ino)!=(prior.st_dev,prior.st_ino)or not os.get_inheritable(3):
        raise ValueError('actual inherited observer descriptor')
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    previous=ctypes.c_uint64();empty=ctypes.c_uint64();actual=ctypes.c_uint64(1)
    if libc.syscall(14,2,ctypes.byref(empty),ctypes.byref(previous),8):raise OSError('signal mask reset')
    observations=[]
    for number in range(1,65):
        if number in (9,19):continue
        before,zero,after=Action(),Action(),Action()
        if libc.syscall(13,number,None,ctypes.byref(before),8) or libc.syscall(13,number,ctypes.byref(zero),None,8) or libc.syscall(13,number,None,ctypes.byref(after),8) or after.handler:
            raise OSError('signal action reset')
        observations.append(dict(signal=number,before=int(before.handler or 0),after=int(after.handler or 0)))
    if libc.syscall(14,2,None,ctypes.byref(actual),8) or actual.value:raise OSError('actual empty signal mask')
    argv=[str(a.original)]
    native_env={k:v for k,v in os.environ.items()if k!='PYTHONDONTWRITEBYTECODE'}
    with a.preparation.open('x') as f:json.dump(dict(previous_mask=previous.value,mask=actual.value,dispositions=observations,argv=argv,environment=native_env,observer=dict(fd=3,device=observer.st_dev,inode=observer.st_ino)),f,sort_keys=True)
    if a.mode=='native':os.execve(a.original,argv,native_env)
    if a.carrier is None or a.namespace is None:raise ValueError('actual gated inputs')
    carrier.execute_loader(a.carrier,a.original,[a.library_root],a.namespace,argv,disable_rseq=True)
if __name__=='__main__':main()
