"""One external, bounded same-CPU contender; never a subject thread or writer."""
import json,os,resource,signal,subprocess,sys,time
from contextlib import contextmanager
from pathlib import Path
from page_selected import ENV,fact,need,save
BOUNDS=[5,512<<20,16<<20,15]

def start_identity(pid):
    raw=Path('/proc/'+str(pid)+'/stat').read_text();tail=raw[raw.rindex(')')+2:].split()
    need(len(tail)>=20 and tail[19].isdigit(),'actual contender start identity')
    return int(tail[19])

def prepare(cpu):
    os.sched_setaffinity(0,{cpu})
    for key,value in ((resource.RLIMIT_CPU,BOUNDS[0]),(resource.RLIMIT_AS,BOUNDS[1]),(resource.RLIMIT_FSIZE,BOUNDS[2]),(resource.RLIMIT_CORE,0)):
        resource.setrlimit(key,(value,value))
    signal.pthread_sigmask(signal.SIG_SETMASK,[])
    signal.signal(signal.SIGTERM,signal.SIG_DFL);signal.signal(signal.SIGALRM,signal.SIG_DFL)
    signal.setitimer(signal.ITIMER_REAL,BOUNDS[3])

def child(cpu):
    need(os.sched_getaffinity(0)=={cpu},'inherited actual contender affinity')
    print(json.dumps(dict(pid=os.getpid(),parent_pid=os.getppid(),process_group=os.getpgrp(),session=os.getsid(0),
        start_ticks=start_identity(os.getpid()),affinity=sorted(os.sched_getaffinity(0)),
        limits=[list(resource.getrlimit(k))for k in(resource.RLIMIT_CPU,resource.RLIMIT_AS,resource.RLIMIT_FSIZE,resource.RLIMIT_CORE)],
        blocked_signals=sorted(signal.pthread_sigmask(signal.SIG_BLOCK,[])),
        alarm_default=signal.getsignal(signal.SIGALRM)==signal.SIG_DFL,term_default=signal.getsignal(signal.SIGTERM)==signal.SIG_DFL,
        wall_timer=signal.getitimer(signal.ITIMER_REAL)[0]),separators=(',',':')),flush=True)
    while True:pass

@contextmanager
def active(name,private,cpu,python,pin,binary,receipt):
    private=Path(private);script=pin(Path(__file__).resolve());python=pin(python)
    need(type(cpu)is int and os.sched_getaffinity(0)=={cpu},'one actual contender/subject CPU')
    row=dict(name=name,argv=[str(python),str(script),'--child',str(cpu)],profile='rseq_native_contender',bounds=BOUNDS,
        environment=dict(ENV),capture_limit=4096,expected_exit=None,exit=None,reaped=False,timed_out=False,error=None,
        cleanup_errors=[],descriptors=[],ready=False,termination_requested=False)
    receipt['commands'].append(row);receipt['rseq_native_fixture'].setdefault('contenders',[]).append(row)
    paths={k:private/(name+'.'+k)for k in('stdout','stderr')};process=None;start=time.monotonic_ns()
    try:
        # Close both parent capture descriptors before invoke opens the subject's
        # fixed record FD3. Popen owns no pipe or pidfd in this context.
        with paths['stdout'].open('xb')as out,paths['stderr'].open('xb')as err:
            process=subprocess.Popen(row['argv'],cwd=private,env=ENV,stdout=out,stderr=err,start_new_session=True,close_fds=True,preexec_fn=lambda:prepare(cpu))
        row['pid']=process.pid
        until=time.monotonic()+3
        while True:
            need(process.poll()is None,'contender remains alive until subject entry')
            data=paths['stdout'].read_bytes();need(len(data)<=4096,'bounded actual contender readiness')
            if data.endswith(b'\n'):break
            need(time.monotonic()<until,'bounded contender readiness wait');time.sleep(0.005)
        ready=json.loads(data);row['ready_observation']=ready
        need(set(ready)=={'pid','parent_pid','process_group','session','start_ticks','affinity','limits','wall_timer','blocked_signals','alarm_default','term_default'} and ready['pid']==process.pid and
             ready['parent_pid']==os.getpid() and ready['process_group']==ready['session']==process.pid and
             ready['start_ticks']==start_identity(process.pid)>0 and os.getpgid(process.pid)==os.getsid(process.pid)==process.pid and
             ready['affinity']==[cpu] and os.sched_getaffinity(process.pid)=={cpu} and
             ready['limits']==[[x,x]for x in BOUNDS[:3]]+[[0,0]] and ready['blocked_signals']==[]and
             ready['alarm_default']is True and ready['term_default']is True and
             type(ready['wall_timer'])in(int,float) and 0<ready['wall_timer']<=BOUNDS[3],
             'actual PID, affinity, hard resource caps and armed real wall timer')
        need(process.poll()is None and not paths['stderr'].read_bytes(),'live ready contender without startup error')
        row['ready']=True
        yield row
    except BaseException as exc:
        row['error']=type(exc).__name__+': '+str(exc);raise
    finally:
        if process is not None:
            # Keep the unreaped leader until the single process-group kill.
            # A contender's termination is cleanup, never a native operation pass.
            if process.poll()is None:
                row['termination_requested']=True
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                except BaseException as exc:row['cleanup_errors'].append('terminate: '+repr(exc))
            try:row['exit']=process.wait(timeout=3);row['reaped']=True
            except BaseException as exc:
                row['cleanup_errors'].append('wait: '+repr(exc))
                try:os.killpg(process.pid,signal.SIGKILL);row['exit']=process.wait(timeout=3);row['reaped']=True
                except BaseException as other:row['cleanup_errors'].append('kill/reap: '+repr(other))
            row['timed_out']=row['exit']==-signal.SIGALRM
        row['duration_ns']=time.monotonic_ns()-start;row['captures']={}
        for key,path in paths.items():
            try:
                if path.exists():row['captures'][key]=dict(fact(binary(path)),file=path.name)
            except BaseException as exc:row['cleanup_errors'].append(key+': '+repr(exc))
        try:save(private/(name+'.json'),row);binary(private/(name+'.json'))
        except BaseException as exc:row['cleanup_errors'].append('command: '+repr(exc))
        if row['error']or not row['reaped']or row['timed_out']or row['cleanup_errors']:
            receipt['final_errors'].append('contender '+name+': failed preparation/cleanup')
    need(row['ready']and row['reaped']and not row['timed_out']and not row['cleanup_errors']and
         row['exit']in(-signal.SIGTERM,-signal.SIGKILL)and
         set(row['captures'])=={'stdout','stderr'}and row['captures']['stderr']['bytes']==0 and
         row['captures']['stdout']['bytes']<=4096,'actual bounded contender termination/closed captures')

if __name__=='__main__':
    need(len(sys.argv)==3 and sys.argv[1]=='--child'and sys.argv[2].isdigit(),'fixed contender invocation')
    child(int(sys.argv[2]))
