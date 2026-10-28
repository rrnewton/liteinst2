"""Actual fresh-exec launcher; no observer FD or simulated application event."""
import argparse,ctypes,importlib.util,json,os,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected_process import Action

def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['native','gated'],required=True)
    p.add_argument('--original',type=Path,required=True);p.add_argument('--carrier',type=Path)
    p.add_argument('--namespace',type=Path);p.add_argument('--library-root',type=Path,required=True)
    p.add_argument('--preparation',type=Path,required=True);a=p.parse_args()
    sys.path.insert(0,str(ROOT/'tools/page-entry'))
    import carrier,namespace # imports finish before actual signal reset
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
    with a.preparation.open('x') as f:json.dump(dict(previous_mask=previous.value,mask=actual.value,dispositions=observations,argv=argv,environment=native_env),f,sort_keys=True)
    if a.mode=='native':os.execve(a.original,argv,native_env)
    if a.carrier is None or a.namespace is None:raise ValueError('actual gated inputs')
    carrier.execute_loader(a.carrier,a.original,[a.library_root],a.namespace,argv,disable_rseq=True)
if __name__=='__main__':main()
