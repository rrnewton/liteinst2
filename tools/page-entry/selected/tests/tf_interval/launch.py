"""Fixed pipe fixture exec; FD provenance is observed, never supplied by argv."""
import argparse,ctypes,fcntl,json,os,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected_process import Action
from page_default_ls_release_provenance import observe

def need(ok,message):
 if not ok:raise ValueError(message)

def pipe(fd,access):
 need(type(fd)is int and 3<fd<=1000000,'actual pipe descriptor above record')
 s=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
 need(stat.S_ISFIFO(s.st_mode) and flags&os.O_ACCMODE==access and
      not flags&(os.O_NONBLOCK|os.O_PATH),'blocking FIFO endpoint and exact access')
 return dict(fd=fd,device=s.st_dev,inode=s.st_ino,mode=s.st_mode,flags=flags,
             inheritable=os.get_inheritable(fd))

def main():
 p=argparse.ArgumentParser()
 p.add_argument('--mode',choices=('native','reference','gated'),required=True)
 p.add_argument('--original',type=Path,required=True);p.add_argument('--carrier',type=Path);p.add_argument('--namespace',type=Path)
 p.add_argument('--library-root',type=Path,required=True);p.add_argument('--preparation',type=Path,required=True)
 p.add_argument('--record-fd',type=int,required=True);p.add_argument('--go-fd',type=int,required=True);p.add_argument('--notify-fd',type=int,required=True)
 p.add_argument('--control',choices=('0','1','2','3'),required=True)
 a=p.parse_args();sys.path.insert(0,str(ROOT/'tools/page-entry'));import carrier
 need(a.record_fd==3 and len({a.record_fd,a.go_fd,a.notify_fd})==3,'exact record and two distinct pipe ends')
 s=os.fstat(3)
 need(stat.S_ISREG(s.st_mode) and not s.st_size and not os.lseek(3,0,os.SEEK_CUR) and
      fcntl.fcntl(3,fcntl.F_GETFL)&os.O_ACCMODE==os.O_WRONLY and os.get_inheritable(3),'fresh inherited regular fd3')
 endpoints=[pipe(a.go_fd,os.O_RDONLY),pipe(a.notify_fd,os.O_WRONLY)]
 need(all(x['inheritable']is True for x in endpoints) and
      (endpoints[0]['device'],endpoints[0]['inode'])!=(endpoints[1]['device'],endpoints[1]['inode']),
      'two genuine independent inherited pipes')
 # observe() requires a nonstandard parent FD: use a real temporary same-OFD
 # duplicate of stdout, retain its identity, then close it before target exec.
 stdout_dup=fcntl.fcntl(1,fcntl.F_DUPFD_CLOEXEC,100)
 try:
  stdout=observe(stdout_dup)
  need(os.fstat(1).st_dev==stdout['identity'][0] and os.fstat(1).st_ino==stdout['identity'][1],
       'actual Popen stdout duplicate identity')
  fs=ctypes.create_string_buffer(120);libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
  result=libc.syscall(138,stdout_dup,ctypes.byref(fs))
  need(result==0 and int.from_bytes(fs.raw[:8],'little')==0x9123683e,'actual normal Btrfs stdout')
  stdout.update(fd=1,query_duplicate=stdout_dup,statfs_result=int(result),statfs_hex=fs.raw.hex())
 finally:os.close(stdout_dup)
 stdout['query_duplicate_closed']=True
 previous=ctypes.c_uint64();empty=ctypes.c_uint64();actual=ctypes.c_uint64(1)
 need(libc.syscall(14,2,ctypes.byref(empty),ctypes.byref(previous),8)==0,'signal mask reset')
 observations=[]
 for number in range(1,65):
  if number in(9,19):continue
  before,zero,after=Action(),Action(),Action()
  need(not libc.syscall(13,number,None,ctypes.byref(before),8) and
       not libc.syscall(13,number,ctypes.byref(zero),None,8) and
       not libc.syscall(13,number,None,ctypes.byref(after),8) and not after.handler,'signal action reset')
  observations.append(dict(signal=number,before=int(before.handler or 0),after=int(after.handler or 0)))
 need(not libc.syscall(14,2,None,ctypes.byref(actual),8) and not actual.value,'actual empty mask')
 argv=[str(a.original),a.mode,str(a.go_fd),str(a.notify_fd),a.control]
 env={k:v for k,v in os.environ.items()if k!='PYTHONDONTWRITEBYTECODE'}
 with a.preparation.open('x')as f:
  json.dump(dict(previous_mask=previous.value,mask=actual.value,dispositions=observations,argv=argv,
   environment=env,observer=dict(fd=3,device=s.st_dev,inode=s.st_ino),pipes=endpoints,stdout=stdout,
   mode=a.mode,control=int(a.control),affinity=sorted(os.sched_getaffinity(0))),f,sort_keys=True)
 if a.mode in('native','reference'):os.execve(a.original,argv,env)
 need(a.carrier is not None and a.namespace is not None,'genuine gated namespace inputs')
 carrier.execute_loader(a.carrier,a.original,[a.library_root],a.namespace,argv,disable_rseq=False)
if __name__=='__main__':main()
