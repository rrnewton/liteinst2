"""Real fresh exec, owned FD3, reset signals, and optional actual outer seccomp."""
import argparse,ctypes,json,os,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected_process import Action

class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):_fields_=[('length',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]

def deny(libc,mode):
    if mode=='none':return []
    args={'get':[0x1011],'set':[0x1012],'both':[0x1011,0x1012]}[mode]
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(6,0,0,0x80000000),
          (0x20,0,0,0),(0x15,0,2*len(args)+1,158),(0x20,0,0,16)]
    for a in args:rows.extend([(0x15,0,1,a),(6,0,0,0x50001)])
    rows.append((6,0,0,0x7fff0000))
    filters=(Filter*len(rows))(*(Filter(*r)for r in rows));program=Program(len(rows),filters)
    if libc.syscall(157,38,1,0,0,0)or libc.syscall(157,22,2,ctypes.byref(program),0,0):raise OSError('actual outer denial install')
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=('native','gated'),required=True)
    p.add_argument('--policy',choices=('raw','configured'),required=True)
    p.add_argument('--deny',choices=('none','get','set','both'),default='none')
    p.add_argument('--original',type=Path,required=True);p.add_argument('--carrier',type=Path);p.add_argument('--namespace',type=Path)
    p.add_argument('--library-root',type=Path,required=True);p.add_argument('--preparation',type=Path,required=True);p.add_argument('--record-fd',type=int,required=True)
    a=p.parse_args();sys.path.insert(0,str(ROOT/'tools/page-entry'));import carrier
    if a.mode=='native'and(a.policy!='raw'or a.deny!='none'):raise ValueError('native means actual unconfigured baseline')
    prior=os.fstat(a.record_fd)
    if not stat.S_ISREG(prior.st_mode)or prior.st_size or os.lseek(a.record_fd,0,os.SEEK_CUR):raise ValueError('fresh regular record')
    os.dup2(a.record_fd,3,inheritable=True)
    if a.record_fd!=3:os.close(a.record_fd)
    observer=os.fstat(3)
    if(observer.st_dev,observer.st_ino)!=(prior.st_dev,prior.st_ino)or not os.get_inheritable(3):raise ValueError('real observer fd identity')
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    previous=ctypes.c_uint64();wanted=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))if a.mode=='native'else 0
    empty=ctypes.c_uint64(wanted);actual=ctypes.c_uint64(1)
    if libc.syscall(14,2,ctypes.byref(empty),ctypes.byref(previous),8):raise OSError('signal mask reset')
    observations=[]
    for number in range(1,65):
        if number in(9,19):continue
        before,zero,after=Action(),Action(),Action()
        if libc.syscall(13,number,None,ctypes.byref(before),8)or libc.syscall(13,number,ctypes.byref(zero),None,8)or libc.syscall(13,number,None,ctypes.byref(after),8)or after.handler:raise OSError('signal action reset')
        observations.append(dict(signal=number,before=int(before.handler or 0),after=int(after.handler or 0)))
    if libc.syscall(14,2,None,ctypes.byref(actual),8)or actual.value!=wanted:raise OSError('actual declared native/bridge entry mask')
    filters=deny(libc,a.deny);argv=[str(a.original)]
    env={k:v for k,v in os.environ.items()if k!='PYTHONDONTWRITEBYTECODE'}
    with a.preparation.open('x')as f:json.dump(dict(previous_mask=previous.value,mask=actual.value,dispositions=observations,argv=argv,environment=env,
        observer=dict(fd=3,device=observer.st_dev,inode=observer.st_ino),denial=a.deny,installed=bool(filters),filter=filters,policy=a.policy),f,sort_keys=True)
    if a.mode=='native':os.execve(a.original,argv,env)
    if a.carrier is None or a.namespace is None:raise ValueError('genuine gated inputs')
    carrier.execute_loader(a.carrier,a.original,[a.library_root],a.namespace,argv,disable_rseq=True,
                           provider_policy='mask-random-v1'if a.policy=='configured'else None)
if __name__=='__main__':main()
