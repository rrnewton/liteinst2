"""Four actual pre-exec descriptor refusals; never executes a test substitute."""
import argparse,fcntl,json,os,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
KINDS=('fd3-alias','nonfifo-go','wrong-direction','same-fifo')

def need(ok,message):
 if not ok:raise ValueError(message)

def descriptor(fd):
 s=os.fstat(fd)
 return dict(fd=fd,device=s.st_dev,inode=s.st_ino,mode=s.st_mode,
             flags=fcntl.fcntl(fd,fcntl.F_GETFL),inheritable=os.get_inheritable(fd))

def main():
 p=argparse.ArgumentParser();p.add_argument('--kind',choices=KINDS,required=True)
 for key in ('original','library-root','preparation','evidence'):p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--record-fd',type=int,required=True);a=p.parse_args()
 need(a.record_fd==3,'actual inherited record descriptor3')
 record=descriptor(3)
 need(stat.S_ISREG(record['mode'])and record['flags']&os.O_ACCMODE==os.O_WRONLY and
      record['inheritable']and os.fstat(3).st_size==0 and os.lseek(3,0,os.SEEK_CUR)==0,
      'fresh actual inherited regular record')
 need(not a.preparation.exists()and not a.evidence.exists(),'fresh negative capture paths')
 go_read,go_write=os.pipe2(os.O_CLOEXEC);notify_read,notify_write=os.pipe2(os.O_CLOEXEC)
 owned={go_read,go_write,notify_read,notify_write};go,notify=go_read,notify_write
 if a.kind=='fd3-alias':go=3
 elif a.kind=='nonfifo-go':
  path=a.evidence.with_suffix('.regular')
  fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
  go=os.open(path,os.O_RDONLY|os.O_CLOEXEC);owned.add(go)
 elif a.kind=='wrong-direction':go=go_write
 elif a.kind=='same-fifo':notify=go_write
 for fd in {3,go,notify}:os.set_inheritable(fd,True)
 for fd in sorted(owned-{go,notify}):os.close(fd)
 argv=[sys.executable,str(Path(__file__).with_name('launch.py').resolve()),'--mode','native',
       '--original',str(a.original),'--library-root',str(a.library_root),
       '--preparation',str(a.preparation),'--record-fd','3','--go-fd',str(go),
       '--notify-fd',str(notify),'--control','0']
 value=dict(schema=1,kind=a.kind,pid=os.getpid(),affinity=sorted(os.sched_getaffinity(0)),
            record=record,go=descriptor(go),notify=descriptor(notify),argv=argv,
            closed_unused=sorted(owned-{go,notify}),target_exec_attempted=False)
 with a.evidence.open('x')as f:json.dump(value,f,sort_keys=True,separators=(',',':'))
 os.execve(sys.executable,argv,dict(os.environ))
if __name__=='__main__':main()
