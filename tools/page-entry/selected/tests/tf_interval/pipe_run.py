"""Fixed READY/GO/DONE process seam; no benchmark entrypoint or implicit credit.

The enclosing fixed qualifier must supply its strict terminal/record reader.
This module never converts a protocol failure into an expected-case pass.
"""
import fcntl,os,resource,select,signal,stat,subprocess,time
from pathlib import Path
from page_selected import ENV,fact,need,save
from page_default_ls_release_provenance import observe,same
BOUNDS=[5,512<<20,16<<20,15]
READY=b'TFI-RDY\n'
DONE=b'TFI-DON\n'
CONTROLS={'normal':'0','bad-ready':'1','extra-done':'2','missing-done':'3','wrong-go':'0','eof-go':'0'}


def command(python,original,mode,library_root,carrier=None,namespace=None):
 need(mode in('native','reference','gated'),'fixed interval lane')
 argv=[str(python),str(Path(__file__).with_name('launch.py').resolve()),'--mode',mode,
       '--original',str(original),'--library-root',str(library_root),
       '--preparation','{preparation}','--record-fd','{record_fd}',
       '--go-fd','{go_fd}','--notify-fd','{notify_fd}','--control','{control}']
 if mode=='gated':
  need(carrier is not None and namespace is not None,'gated carrier and namespace')
  argv+=['--carrier',str(carrier),'--namespace',str(namespace)]
 else:need(carrier is None and namespace is None,'native has no carrier substitution')
 return argv

def endpoint(fd,access):
 s=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
 need(type(fd)is int and fd>3 and stat.S_ISFIFO(s.st_mode) and
      flags&os.O_ACCMODE==access and not flags&(os.O_NONBLOCK|os.O_PATH),
      'actual blocking parent pipe endpoint')
 return dict(fd=fd,device=s.st_dev,inode=s.st_ino,mode=s.st_mode,flags=flags,
             inheritable=os.get_inheritable(fd))

def invoke(row,directory,cpu,terminal_check):
 """One fixed invocation; interval_ns exists only after every terminal check.

 argv contains exactly one each of {record_fd}, {go_fd}, {notify_fd},
 {preparation}, {control}. terminal_check consumes the actual closed row,
 stdout/stderr/FD3 bytes and parsed preparation and must return accepted=True.
 No default reader or sample retry exists. The future enclosing driver owns
 exact source/build/qualification bindings and all sample aggregation.
 """
 import json
 need(not any(k in row for k in('pid','exit','accepted','interval_ns','captures')),'fresh invocation row')
 argv=row['argv'];flags=['--mode','--original','--library-root','--preparation','--record-fd','--go-fd','--notify-fd','--control']
 need(type(argv)is list and len(argv) in(18,22) and all(type(x)is str for x in argv) and
      Path(argv[1]).resolve()==Path(__file__).with_name('launch.py').resolve(),'fixed literal fixture launcher')
 if argv[3]=='gated':flags+=['--carrier','--namespace']
 need(argv[2::2]==flags and argv[3] in('native','reference','gated'),'exact fixed launcher flags')
 need(type(cpu)is int and cpu>=0 and callable(terminal_check) and row['bounds']==BOUNDS and
      all(type(v)is int for v in row['bounds']) and
      row['control']in CONTROLS and os.sched_getaffinity(0)=={cpu},'fixed bounds, control and one reserved CPU')
 directory=Path(directory);process=None;pidfd=None;owned={};start=time.monotonic_ns()
 deadline=start+BOUNDS[3]*10**9
 row.update(exit=None,pid=None,reaped=False,timed_out=False,error=None,cleanup_errors=[],
  accepted=False,protocol_complete=False,transcript=[],descriptors=[],start_ns=start,deadline_ns=deadline)
 paths={k:directory/(row['name']+'.'+k)for k in('stdout','stderr','record','preparation')}
 transcript=bytearray();eof=False;done_ns=None;go_ns=None
 def remaining():
  left=deadline-time.monotonic_ns()
  if left<=0:
   row['timed_out']=True;raise TimeoutError('single absolute interval-child deadline')
  return left/10**9
 def wait(readers,writers=()):
  r,w,_=select.select(readers,writers,[],remaining())
  if not r and not w:
   remaining();raise TimeoutError('single deadline readiness')
  return r,w
 def own(name,fd):
  need(fd not in owned,'unique owned FD');owned[fd]=name
  row['descriptors'].append(dict(name=name,fd=fd,closed=False));return fd
 def close(fd):
  name=owned.pop(fd)
  try:
   os.close(fd)
   next(x for x in row['descriptors']if x['fd']==fd)['closed']=True
  except BaseException as exc:
   row['cleanup_errors'].append(name+'_close: '+repr(exc));raise
 def kill():
  if process is None:return
  try:os.killpg(process.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  except BaseException as exc:row['cleanup_errors'].append('kill: '+repr(exc))
 def prepare():
  os.sched_setaffinity(0,{cpu})
  for key,value in((resource.RLIMIT_CPU,BOUNDS[0]),(resource.RLIMIT_AS,BOUNDS[1]),
                   (resource.RLIMIT_FSIZE,BOUNDS[2]),(resource.RLIMIT_CORE,0)):
   resource.setrlimit(key,(value,value))
 def receive(want):
  nonlocal eof
  data=bytearray()
  while len(data)<want:
   ready,_=wait([notify_read,pidfd])
   need(ready,'single deadline readiness')
   if notify_read not in ready:
    # A reaped-ready leader cannot make a future DONE; still collect pipe EOF.
    ready,_=wait([notify_read])
    need(ready,'closed leader pipe readiness')
   got=os.read(notify_read,want-len(data))
   row['transcript'].append(dict(kind='read',time_ns=time.monotonic_ns(),hex=got.hex()))
   need(len(row['transcript'])<=32,'fixed bounded IPC transcript')
   if not got:eof=True;break
   data+=got;transcript.extend(got)
   need(len(transcript)<=24,'bounded READY/DONE/extra bytes')
  return bytes(data)
 try:
  record=own('record',os.open(paths['record'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600))
  need(record==3,'actual fixed regular record fd3')
  rs=os.fstat(record);rf=fcntl.fcntl(record,fcntl.F_GETFL)
  need(stat.S_ISREG(rs.st_mode) and not rs.st_size and rf&os.O_ACCMODE==os.O_WRONLY and
       os.lseek(record,0,os.SEEK_CUR)==0,'fresh parent normal record descriptor')
  row['record_before']=dict(fd=3,device=rs.st_dev,inode=rs.st_ino,mode=rs.st_mode,flags=rf)
  go_read,go_write=os.pipe2(os.O_CLOEXEC);own('go_read',go_read);own('go_write',go_write)
  notify_read,notify_write=os.pipe2(os.O_CLOEXEC);own('notify_read',notify_read);own('notify_write',notify_write)
  row['pipe_before']=[endpoint(go_read,os.O_RDONLY),endpoint(go_write,os.O_WRONLY),
                      endpoint(notify_read,os.O_RDONLY),endpoint(notify_write,os.O_WRONLY)]
  need((row['pipe_before'][0]['device'],row['pipe_before'][0]['inode'])==
       (row['pipe_before'][1]['device'],row['pipe_before'][1]['inode']) and
       (row['pipe_before'][2]['device'],row['pipe_before'][2]['inode'])==
       (row['pipe_before'][3]['device'],row['pipe_before'][3]['inode']) and
       row['pipe_before'][0]['inode']!=row['pipe_before'][2]['inode'],'two actual independent pipe objects')
  replacements={'{record_fd}':str(record),'{go_fd}':str(go_read),'{notify_fd}':str(notify_write),
                '{preparation}':str(paths['preparation']),'{control}':CONTROLS[row['control']]}
  need(all(row['argv'].count(k)==1 for k in replacements),'one of every fixed launcher argument')
  row['argv']=[replacements.get(x,x)for x in row['argv']]
  row['pass_fds']=[record,go_read,notify_write]
  with paths['stdout'].open('xb')as stdout,paths['stderr'].open('xb')as stderr:
   row['stdout_before']=observe(stdout.fileno());remaining()
   process=subprocess.Popen(row['argv'],cwd=directory,env=ENV,stdin=subprocess.DEVNULL,
    stdout=stdout,stderr=stderr,start_new_session=True,pass_fds=tuple(row['pass_fds']),preexec_fn=prepare)
   row['pid']=process.pid;pidfd=os.pidfd_open(process.pid)
   close(go_read);close(notify_write)
   need(receive(len(READY))==READY and not eof,'exact READY without premature EOF')
   if row['control']=='eof-go':
    row['transcript'].append(dict(kind='go-eof',time_ns=time.monotonic_ns()));close(go_write)
   else:
    _,writable=wait([],[go_write]);need(writable,'GO writable within same deadline')
    go_ns=time.monotonic_ns();sent=os.write(go_write,b'X'if row['control']=='wrong-go'else b'G')
    row['transcript'].append(dict(kind='write',time_ns=go_ns,hex='58'if row['control']=='wrong-go'else'47',result=sent))
    need(sent==1,'one actual GO byte');close(go_write)
   done=receive(len(DONE));done_ns=time.monotonic_ns()
   row['candidate_go_ns']=go_ns;row['candidate_done_ns']=done_ns
   need(done==DONE and not eof and go_ns is not None,'exact DONE after actual GO')
   # The timestamp is provisional: require exact stream EOF, no extra data,
   # then actual successful reap and strict reports/full-record validation.
   extra=receive(9);need(eof and not extra and bytes(transcript)==READY+DONE,'exact transcript and EOF')
   ready,_=wait([pidfd]);need(ready,'actual terminal process before deadline')
   kill();row['exit']=process.wait(timeout=remaining());row['reaped']=True
   row['stdout_after']=observe(stdout.fileno());same(row['stdout_before'],row['stdout_after'])
   row['protocol_complete']=True
 except BaseException as exc:
  row['error']=type(exc).__name__+': '+str(exc)
 finally:
  if process is not None and process.returncode is None:
   kill()
   try:
    # Cleanup is bounded separately after an expired subject deadline; it
    # never adds time to a successful interval or rescues a timed-out sample.
    row['exit']=process.wait(timeout=3);row['reaped']=True
   except BaseException as exc:row['cleanup_errors'].append('wait: '+repr(exc))
  elif process is not None:row['exit']=process.returncode;row['reaped']=True
  if pidfd is not None:
   try:os.close(pidfd)
   except BaseException as exc:row['cleanup_errors'].append('pidfd_close: '+repr(exc))
  for fd in list(owned):
   try:close(fd)
   except BaseException:pass
  row['duration_ns']=time.monotonic_ns()-start;row['captures']={}
  for name,path in paths.items():
   if not path.exists():row['captures'][name]={'missing':True};continue
   try:row['captures'][name]=dict(fact(path),file=path.name)
   except BaseException as exc:row['cleanup_errors'].append(name+'_capture: '+repr(exc))
 try:
  need(row['control']=='normal' and row['protocol_complete']is True and type(row['exit'])is int and row['exit']==0 and
       row['reaped']is True and not row['timed_out'] and not row['error'] and not row['cleanup_errors'] and
       all(x['closed']is True for x in row['descriptors']),'complete successful normal process and FD closure')
  need(all('missing'not in c and c['bytes']<=BOUNDS[2]for c in row['captures'].values()),'all bounded captures')
  prep=json.loads(paths['preparation'].read_bytes())
  need(prep['affinity']==[cpu] and prep['mask']==0 and prep['control']==0 and
       [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)] and
       all(x['after']==0 for x in prep['dispositions']),'actual prepared CPU/signals and normal control')
  for parent,child in zip((row['pipe_before'][0],row['pipe_before'][3]),prep['pipes']):
   need({k:parent[k]for k in('fd','device','inode','mode','flags')}==
        {k:child[k]for k in('fd','device','inode','mode','flags')} and
        parent['inheritable']is False and child['inheritable']is True,'actual exact pass_fds pipe identity')
  need(len(prep['pipes'])==2 and prep['stdout']['identity']==row['stdout_before']['identity'] and
       prep['observer']=={k:row['record_before'][k]for k in('fd','device','inode')} and
       prep['stdout']['query_duplicate_closed']is True,'actual parent stdout and record joins')
  result=terminal_check(row,paths['stdout'].read_bytes(),paths['stderr'].read_bytes(),paths['record'].read_bytes(),prep)
  need(type(result)is dict and result.get('accepted')is True,'explicit strict terminal/state reader accepted')
  row['terminal_validation']=result
  need(type(go_ns)is int and type(done_ns)is int and start<=go_ns<done_ns<=deadline,'actual executable interval')
  row['interval_ns']=done_ns-go_ns;row['accepted']=True
 except BaseException as exc:
  if row['error']is None:row['error']=type(exc).__name__+': '+str(exc)
 save(directory/(row['name']+'.json'),row)
 return row
