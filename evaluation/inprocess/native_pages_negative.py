#!/usr/bin/env python3
"""Reproduce one native-page vsyscall integration negative on one reserved CPU.

Build the bridge through native_pages.py at the same committed revision, then
pass that completed receipt and the bridge's exact SHA256. Seven bounded
commands build/inspect the literal fixture, execute
a successful native baseline, make the real-loader carrier and require an
actual terminal602 refusal with verified native-page/owner cleanup. Raw data is
private under target/. --replay only checks saved data and never executes it.
"""
import argparse
from datetime import datetime,timezone
import hashlib,json,os,pathlib,platform,re,resource,shutil,signal,struct,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
ENV={'PATH':'/usr/bin:/bin:/usr/local/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','LD_BIND_NOW':'1','PYTHONDONTWRITEBYTECODE':'1','GLIBC_TUNABLES':'glibc.pthread.rseq=0'}
INPUTS=['tools/page-entry/selected/tests/native_pages/vsyscall.S','tools/page-entry/selected/tests/native_pages/vsyscall.ld','tools/page-entry/carrier.py','tools/page-entry/namespace.py','tools/page-entry/selected/build-native-pages.sh','tools/page-entry/selected/runtime_loader.c','tools/page-entry/selected/native_seccomp.h','tools/page-entry/selected/native_controller.inc','tools/page-entry/selected/native_epoch.c','tools/page-entry/selected/native_epoch.h','tools/page-entry/selected/native_policy.c','tools/page-entry/selected/native_lifecycle.inc','tools/page-entry/selected/lifecycle_loader.c','tools/page-entry/selected/rseq_guard.c','tools/page-entry/selected/rseq_report.inc']
def fact(p):
 p=pathlib.Path(p);b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'mode':p.stat().st_mode&0o777}
def need(t,s):
 if not t:raise ValueError(s)
def unique(rows):
 o={}
 for k,v in rows:
  need(k not in o,'duplicate JSON field');o[k]=v
 return o
def limits():
 resource.setrlimit(resource.RLIMIT_CPU,(15,15));resource.setrlimit(resource.RLIMIT_AS,(512<<20,512<<20));resource.setrlimit(resource.RLIMIT_FSIZE,(4<<20,4<<20));resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def execute(args):
 BASE=(ROOT/(args.private_dir or Path('target/evaluation/native-pages-negative')/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))).resolve()
 need(BASE.is_relative_to(ROOT/'target'),'private directory below target')
 BASE.mkdir(parents=True,exist_ok=False)
 BRIDGE=(ROOT/args.bridge).resolve();EXPECTED=args.bridge_sha256
 source_paths=list(INPUTS)+['evaluation/inprocess/native_pages_negative.py']
 # Capture the full direct runtime/decoder source context without publishing
 # host paths or claiming a fresh build of the separately supplied bridge.
 for directory,suffixes in [(ROOT/'tools/page-entry',{'.c','.h','.S'}),(ROOT/'tools/page-entry/selected',{'.c','.h','.S','.inc','.sh'}),(ROOT/'tools/page-entry/selected/decoder/src',{'.rs'})]:
  for path in sorted(directory.iterdir()):
   if path.is_file() and path.suffix in suffixes:
    relative=str(path.relative_to(ROOT))
    if relative not in source_paths:source_paths.append(relative)
 for relative in ('tools/page-entry/selected/decoder/Cargo.toml','tools/page-entry/selected/decoder/Cargo.lock'):
  if relative not in source_paths:source_paths.append(relative)
 r={'status':'failed','scope':'Expected negative: actual native-page legacy-vsyscall CALL must terminate602 after verified closure. Bridge build provenance is joined to a separate native_pages.py receipt.','affinity':sorted(os.sched_getaffinity(0)),'environment':ENV,'commands':[],'sources_before':[],'bridge_before':None,'expected_bridge_sha256':EXPECTED,'final_errors':[],'bounds':{'per_command_wall_seconds':15,'cpu_seconds':15,'address_space_bytes':512<<20}}
 def run(name,argv,expected=0):
  start=time.monotonic();out=BASE/(name+'.stdout');err=BASE/(name+'.stderr')
  with out.open('xb') as of,err.open('xb') as ef:
   p=subprocess.Popen(list(map(str,argv)),cwd=ROOT,env=ENV,stdout=of,stderr=ef,start_new_session=True,preexec_fn=limits)
   timeout=False
   try:rc=p.wait(timeout=15)
   except subprocess.TimeoutExpired:timeout=True;os.killpg(p.pid,signal.SIGKILL);rc=p.wait()
  row={'name':name,'argv':list(map(str,argv)),'exit':rc,'timed_out':timeout,'reaped':True,'seconds':time.monotonic()-start,'stdout':fact(out),'stderr':fact(err)};r['commands'].append(row)
  need(not timeout and rc==expected,'actual '+name+' process outcome');return out.read_bytes(),err.read_bytes()
 try:
  for path in source_paths:r['sources_before'].append(fact(ROOT/path))
  r['bridge_before']=fact(BRIDGE)
  need(len(r['affinity'])==1,'one CPU');need(r['bridge_before']['sha256']==EXPECTED,'exact historical bridge')
  r['base_revision']=run('revision',['git','rev-parse','HEAD'])[0].decode().strip()
  need(r['base_revision']==args.expect_revision,'exact requested base revision')
  r['build_join']=join_build(args.build_receipt,args.expect_revision,EXPECTED,True)
  r['hardware']={'machine':platform.machine(),'kernel_release':platform.release(),'cpu_model':next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),None)}
  for t in ['cc','nm','readelf']:
   r.setdefault('tools',{})[t]=fact(pathlib.Path(shutil.which(t,path=ENV['PATH'])).resolve())
  r['tools']['python']=fact(pathlib.Path(sys.executable).resolve())
  original=BASE/'vsyscall';carrier=BASE/'carrier';bridge=BASE/'bridge-native-pages.so'
  shutil.copyfile(BRIDGE,bridge);bridge.chmod(0o500);need(fact(bridge)['sha256']==EXPECTED,'retained exact bridge copy')
  run('compile',[r['tools']['cc']['path'],'-nostdlib','-pie','-Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2','-Wl,-T,tools/page-entry/selected/tests/native_pages/vsyscall.ld,-z,max-page-size=4096,--build-id=none,--no-as-needed','-l:ld-linux-x86-64.so.2',ROOT/INPUTS[0],'-o',original])
  out,err=run('elf',[r['tools']['readelf']['path'],'-lW','-dW',original]);need(not err,'ELF inspection stderr')
  need(b'Shared library: [ld-linux-x86-64.so.2]' in out,'real ld.so DT_NEEDED')
  image=original.read_bytes();eh=struct.unpack_from('<16sHHIQQQIHHHHHH',image);need(eh[0][:7]==b'\x7fELF\x02\x01\x01' and eh[1:4]==(3,62,1),'ET_DYN x86_64')
  ph=[struct.unpack_from('<IIQQQQQQ',image,eh[5]+i*eh[9]) for i in range(eh[10])]
  loads=[x for x in ph if x[0]==1];need([x[1] for x in loads]==[4,5,6],'R header/RX source/RW data')
  text=loads[1];need(text[2]==text[3]==4096 and text[5]==text[6]==12288,'three literal executable pages')
  window=image[8192-14:12288+14]
  cores=[bytes((0x0f,b)) for b in (0xa2,0x31,0x05,0x34,0xc7,0x01,0xae,0x07,0x35,0x37,0xaa)]+[bytes.fromhex(x) for x in ('cd80','c7f8','c6f8','0f38f5','0f38f6')]
  need(not any(c in window for c in cores) and 0xf2 not in window and 0xf3 not in window,'clean entire page plus both14-byte halos under actual core/HLE policy')
  r['clean_source_window']={'file_first':8192-14,'bytes':len(window),'sha256':hashlib.sha256(window).hexdigest(),'all_policy_cores_absent':True,'f2_f3_absent':True}
  out,err=run('symbols',[r['tools']['nm']['path'],'-n',original]);need(not err,'nm stderr')
  symbols={row.split()[2]:int(row.split()[0],16) for row in out.decode().splitlines() if len(row.split())==3}
  a=symbols['li2_vsyscall_call'];b=symbols['li2_vsyscall_return'];need(b==a+2 and image[a-10:b]==bytes.fromhex('48b8000460ffffffffff'+'ffd0'),'actual literal legacy CALL/continuation')
  r['call']={'target':0xffffffffff600400,'pc_offset':a,'return_offset':b,'bytes':image[a-10:b].hex()}
  prefix=struct.pack('<QQ',0x5653595343414c4c,1)
  out,err=run('baseline',[original]);need(not err and out[:16]==prefix and len(out)==48,'baseline exact reached/result extent')
  values=struct.unpack('<4Q',out[16:]);need(values[0]>0 and values[0]==values[1] and values[2]==0 and values[3]==0x434f4d504c455445,'actual successful time and original stack')
  r['baseline']={'completed':True,'values':values,'output_bytes':48}
  out,err=run('carrier',[sys.executable,ROOT/'tools/page-entry/carrier.py','make',original,bridge,carrier]);need(not err,'carrier stderr');meta=json.loads(out,object_pairs_hook=unique);need(meta['bridge_sha256']==EXPECTED and meta['original_sha256']==fact(original)['sha256'] and meta['main_pf_x_cleared'] is True,'actual carrier source join')
  out,err=run('gated',[sys.executable,ROOT/'tools/page-entry/carrier.py','exec-loader','--disable-rseq','--library-root','/usr/lib64','--namespace',BASE/'namespace',carrier,original,'--',original],125)
  need(out==prefix,'gated emitted only genuine pre-CALL marker, no completed operation')
  reports={}
  for line in err.decode().splitlines():
   tag,body=line.split(' ',1);need(tag not in reports and tag in {'LI2_LOADER','LI2_NATIVE','LI2_RSEQ','LI2_CHAIN','LI2_RUN'},'exact report rows');reports[tag]=json.loads(body,object_pairs_hook=unique)
  need(set(reports)=={'LI2_LOADER','LI2_NATIVE','LI2_RSEQ','LI2_CHAIN','LI2_RUN'},'all five actual reports')
  r['reports']=reports
  for value in reports.values():need(value['version']==1 and value['status']==125 and value['failure_code']==602,'all actual terminal602 statuses')
  loader,native,rseq,chain,cache=(reports[k] for k in ('LI2_LOADER','LI2_NATIVE','LI2_RSEQ','LI2_CHAIN','LI2_RUN'))
  need(loader['scope']=='partial_selected_native_pages' and loader['source_patches']==0 and loader['first_target_is_interpreter_entry']==loader['interpreter_entry_faults']==1,'original interpreter first instruction')
  need(loader['dependency_objects']==1 and loader['last_syscall']==1 and loader['rseq']==0 and loader['kernel_errors']==loader['partial_errors']==0,'loader dependency/syscall/rseq contract')
  need(native['admissions']>0 and native['admissions']==native['closed']==loader['admissions'] and native['admissions']==native['epoch_exits']+1,'terminal event while one actual native epoch remained open; all then closed')
  need(native['main_admissions']==1 and native['main_refaults']==0,'actual single main-page admission and no main straddler')
  need(native['epoch_error']==602 and native['close_error']==native['close_busy']==0 and native['close_complete']==1,'terminal native cleanup complete')
  need(chain['pending']==chain['proof_valid']==0 and all(chain[f's{i}_held']==0 for i in (0,1)),'no retained TRACE capability/borrow')
  need(cache['pending']==cache['publication_present']==0 and cache['active']==[0]*10,'no live generated owner/publication')
  need(rseq['owner'][0]==1 and rseq['owner'][1:7]==[0]*6 and rseq['counts']==[0]*9,'no registration or held rseq owner')
  ns=json.loads((BASE/'namespace/namespace.json').read_text());launch=json.loads((BASE/'namespace/launch.json').read_text());need(launch['carrier_sha256']==fact(carrier)['sha256'] and launch['environment']['GLIBC_TUNABLES']=='glibc.pthread.rseq=0' and ns['interpreter_sha256']==meta['interpreter_sha256'],'actual launch environment/interpreter')
  r['namespace']={name:fact(BASE/'namespace'/name) for name in ('namespace.json','launch.json')}
  r['result']={'baseline_operation_completed':True,'gated_operation_completed':False,'actual_exit':125,'failure_code':602,'native_admissions':native['admissions'],'native_closed':native['closed'],'all_owner_cleanup_closed':True,'gated_postcall_output_bytes':0,'siginfo_limit':'Runtime report retains terminal602 but not raw siginfo. Actual CALL is source/ELF-bound; standalone exact-filter probe separately observes SYS_SECCOMP and unchanged operand.'}
  r['status']='passed'
 except Exception as e:r['error']={'type':type(e).__name__,'message':str(e)}
 finally:
  r['sources_after']=[];r['artifacts']=[]
  for path in [ROOT/p for p in source_paths]:
   try:r['sources_after'].append(fact(path))
   except Exception as e:r['final_errors'].append({'phase':'source_final','type':type(e).__name__})
  r['source_unchanged']=r['sources_after']==r['sources_before']
  try:r['historical_bridge_unchanged']=fact(BRIDGE)==r['bridge_before']
  except Exception as e:r['historical_bridge_unchanged']=False;r['final_errors'].append({'phase':'bridge_final','type':type(e).__name__})
  for path in (BASE/'vsyscall',BASE/'carrier',BASE/'bridge-native-pages.so'):
   if path.exists():
    try:r['artifacts'].append(fact(path))
    except Exception as e:r['final_errors'].append({'phase':'artifact_final','type':type(e).__name__})
  if r.get('build_join'):
   try:need(join_build(args.build_receipt,args.expect_revision,EXPECTED,True)==r['build_join'],'build/source closure')
   except Exception as e:r['final_errors'].append({'phase':'build_final','type':type(e).__name__})
  if not r['source_unchanged'] or not r['historical_bridge_unchanged'] or r['final_errors']:r['status']='failed'
  (BASE/'receipt.json').write_text(json.dumps(r,sort_keys=True,indent=2)+'\n')
 return BASE/"receipt.json"

def read(path):
 return json.loads(Path(path).read_bytes(),object_pairs_hook=unique,
                   parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def join_build(path,revision,bridge_hash,current):
 """Retain the parent cohort status; accept only its actual closed build proof."""
 b=read(path)
 need(b['revision']==revision and b['bridge_sha256']==bridge_hash,'same committed head and exact rebuilt bridge')
 build=[c for c in b['commands'] if c['name']=='build']
 need(len(build)==1 and build[0]['command']==['sh','tools/page-entry/selected/build-native-pages.sh'] and build[0]['exit']==0,'actual native_pages release build')
 need(not b['final_errors'] and all(b[k] is True for k in ('source_unchanged','artifacts_unchanged','inputs_unchanged','tools_unchanged')),'complete build receipt closure')
 manifest=ROOT/'target/native-pages'/b['started_utc']/'source-manifest.json'
 binding=fact(manifest);need(binding['sha256']==b['source_manifest_sha256'],'exact native_pages source manifest')
 sources=read(manifest)
 if current:
  for name,h in sources.items():
   p=(ROOT/name).resolve();need(p.is_relative_to(ROOT) and fact(p)['sha256']==h,'current source equals actual committed build input')
 return {'receipt':fact(path),'source_manifest':binding,'revision':revision,'bridge_sha256':bridge_hash,'build_exit':0,'parent_cohort_passed':b['passed'],'source_count':len(sources),'source_unchanged':True,'artifacts_unchanged':True,'inputs_unchanged':True,'tools_unchanged':True}

def authenticate_receipt(path):
 """Authenticate complete saved captures and retained outputs, without rerun."""
 r=read(path)
 if r.get('build_join'):
  j=r['build_join'];need(fact(j['receipt']['path'])==j['receipt'] and join_build(j['receipt']['path'],r['base_revision'],r['bridge_before']['sha256'],False)==j,'saved actual build join')
 for command in r['commands']:
  for stream in ('stdout','stderr'):
   binding=command[stream];need(fact(binding['path'])==binding,'capture byte/mode binding')
 for binding in r.get('artifacts',[]):need(fact(binding['path'])==binding,'retained artifact byte/mode binding')
 need(r['sources_before']==r['sources_after'] and r['source_unchanged'] and
      r['historical_bridge_unchanged'] and not r['final_errors'],'saved source/final closure')
 return r

def verify_saved(path):
 r=authenticate_receipt(path);need(r['status']=='passed','saved expected-negative cohort passed')
 commands=r['commands'];need([c['name'] for c in commands]==['revision','compile','elf','symbols','baseline','carrier','gated'],'exact seven steps')
 need([c['exit'] for c in commands]==[0,0,0,0,0,0,125] and all(c['reaped'] and not c['timed_out'] for c in commands),'all actual exits/reaping')
 need(r['bounds']=={'per_command_wall_seconds':15,'cpu_seconds':15,'address_space_bytes':512<<20} and len(r['affinity'])==1,'original bounds and one CPU')
 capture=lambda i,s:Path(commands[i][s]['path']).read_bytes()
 need(capture(0,'stdout').decode().strip()==r['base_revision'],'actual revision command')
 need(all(not capture(i,'stderr') for i in range(6)),'all setup/baseline stderr empty')
 artifacts={Path(x['path']).name:x for x in r['artifacts']}
 image=Path(artifacts['vsyscall']['path']).read_bytes();eh=struct.unpack_from('<16sHHIQQQIHHHHHH',image)
 need(eh[0][:7]==b'\x7fELF\x02\x01\x01' and eh[1:4]==(3,62,1),'actual ET_DYN x86_64')
 ph=[struct.unpack_from('<IIQQQQQQ',image,eh[5]+i*eh[9]) for i in range(eh[10])];loads=[x for x in ph if x[0]==1]
 need([x[1] for x in loads]==[4,5,6] and loads[1][2]==loads[1][3]==4096 and loads[1][5]==loads[1][6]==12288,'exact R/RX/RW three-page geometry')
 need(b'Shared library: [ld-linux-x86-64.so.2]' in capture(2,'stdout'),'actual real-loader dependency')
 symbols={x.split()[2]:int(x.split()[0],16) for x in capture(3,'stdout').decode().splitlines() if len(x.split())==3}
 a=symbols['li2_vsyscall_call'];b=symbols['li2_vsyscall_return'];literal=bytes.fromhex('48b8000460ffffffffff'+'ffd0')
 need(b==a+2 and image[a-10:b]==literal and r['call']=={'target':0xffffffffff600400,'pc_offset':a,'return_offset':b,'bytes':literal.hex()},'actual original CALL/return bytes')
 window=image[8192-14:12288+14]
 cores=[bytes((0x0f,x)) for x in (0xa2,0x31,0x05,0x34,0xc7,0x01,0xae,0x07,0x35,0x37,0xaa)]+[bytes.fromhex(x) for x in ('cd80','c7f8','c6f8','0f38f5','0f38f6')]
 need(not any(c in window for c in cores) and 0xf2 not in window and 0xf3 not in window,'complete clean page plus both14-byte halos')
 need(r['clean_source_window']=={'file_first':8192-14,'bytes':len(window),'sha256':hashlib.sha256(window).hexdigest(),'all_policy_cores_absent':True,'f2_f3_absent':True},'saved all-start window identity')
 prefix=struct.pack('<QQ',0x5653595343414c4c,1);out=capture(4,'stdout')
 need(len(out)==48 and out[:16]==prefix,'baseline exact output');values=struct.unpack('<4Q',out[16:])
 need(values[0]>0 and values[0]==values[1] and values[2]==0 and values[3]==0x434f4d504c455445,'baseline real time and original stack')
 need(r['baseline']=={'completed':True,'values':list(values),'output_bytes':48},'baseline projection')
 meta=json.loads(capture(5,'stdout'),object_pairs_hook=unique)
 need(meta['bridge_sha256']==r['bridge_before']['sha256']==artifacts['bridge-native-pages.so']['sha256'] and meta['original_sha256']==artifacts['vsyscall']['sha256'] and meta['main_pf_x_cleared'] is True,'actual bridge/carrier/source join')
 need(capture(6,'stdout')==prefix,'gated pre-CALL marker only')
 reports={}
 for line in capture(6,'stderr').decode().splitlines():
  tag,body=line.split(' ',1);need(tag not in reports,'no duplicate report');reports[tag]=json.loads(body,object_pairs_hook=unique)
 need(set(reports)=={'LI2_LOADER','LI2_NATIVE','LI2_RSEQ','LI2_CHAIN','LI2_RUN'} and reports==r['reports'],'exact five reports')
 need(all(v['version']==1 and v['status']==125 and v['failure_code']==602 for v in reports.values()),'genuine terminal failure statuses')
 loader,native,rseq,chain,cache=(reports[k] for k in ('LI2_LOADER','LI2_NATIVE','LI2_RSEQ','LI2_CHAIN','LI2_RUN'))
 need(loader['scope']=='partial_selected_native_pages' and loader['source_patches']==0 and loader['first_target_is_interpreter_entry']==loader['interpreter_entry_faults']==1,'first interpreter instruction')
 need(loader['dependency_objects']==1 and loader['last_syscall']==1 and loader['rseq']==0 and loader['kernel_errors']==loader['partial_errors']==0,'loader dispatch state')
 need(native['admissions']>0 and native['admissions']==native['closed']==loader['admissions'] and native['admissions']==native['epoch_exits']+1,'actual open native epoch then full closure')
 need(native['main_admissions']==1 and native['main_refaults']==0,'actual main-page native entry')
 need(native['epoch_error']==602 and native['close_error']==native['close_busy']==0 and native['close_complete']==1,'initiating error preserved after verified close')
 need(chain['pending']==chain['proof_valid']==0 and all(chain[f's{i}_held']==0 for i in (0,1)),'TRACE release')
 need(cache['pending']==cache['publication_present']==0 and cache['active']==[0]*10,'cache release')
 need(rseq['owner'][0]==1 and rseq['owner'][1:7]==[0]*6 and rseq['counts']==[0]*9,'unregistered rseq profile')
 for x in r['namespace'].values():need(fact(x['path'])==x,'namespace capture binding')
 ns=read(r['namespace']['namespace.json']['path']);launch=read(r['namespace']['launch.json']['path'])
 need(launch['carrier_sha256']==artifacts['carrier']['sha256'] and launch['environment']['GLIBC_TUNABLES']=='glibc.pthread.rseq=0' and ns['interpreter_sha256']==meta['interpreter_sha256'],'actual namespace/environment')
 need(r['result']['baseline_operation_completed'] is True and r['result']['gated_operation_completed'] is False and r['result']['actual_exit']==125 and r['result']['failure_code']==602 and r['result']['native_admissions']==native['admissions'] and r['result']['native_closed']==native['closed'] and r['result']['all_owner_cleanup_closed'] is True and r['result']['gated_postcall_output_bytes']==0,'saved result facts')
 return r

def project(path,r,history=None):
 private=Path(path).resolve().parent
 def clean_arg(arg):return str(arg).replace(str(private),'<private>').replace(str(ROOT),'<repo>')
 def numeric(binding):return {k:binding[k] for k in ('bytes','sha256','mode') if binding and k in binding}
 def sources(rows):
  out=[]
  for x in rows:
   p=Path(x['path']);need(p.is_relative_to(ROOT),'source within repository')
   out.append(dict(path=str(p.relative_to(ROOT)),**numeric(x)))
  return out
 native=r.get('reports',{}).get('LI2_NATIVE',{})
 out={'schema':1,'profile':'native-pages-vsyscall-negative-v1','status':r['status'],
      'scope':'Expected-negative integration requires baseline legacy time completion and a failed gated operation. A fresh execution joins the separate same-revision native_pages.py build receipt; historical replay without that join grants no committed build or complete B2 qualification.',
      'base_revision':r.get('base_revision'),'source_unchanged':r.get('source_unchanged'),
      'sources':sources(r['sources_before']),'source_context_count':len(r['sources_before']),
      'bridge':numeric(r['bridge_before']),'bridge_unchanged':r.get('historical_bridge_unchanged'),
      'build_join':None if not r.get('build_join') else {**{k:v for k,v in r['build_join'].items() if k not in ('receipt','source_manifest')},'receipt':numeric(r['build_join']['receipt']),'source_manifest':numeric(r['build_join']['source_manifest'])},
      'hardware':r.get('hardware'),'hardware_observed':bool(r.get('hardware')),
      'bounds':r['bounds'],'environment':r['environment'],'affinity_count':len(r['affinity']),
      'private_receipt':numeric(fact(path)),'tools':{k:numeric(v) for k,v in r.get('tools',{}).items()},
      'artifacts':{Path(v['path']).name:numeric(v) for v in r.get('artifacts',[])},
      'commands':[{'name':c['name'],'argv':[clean_arg(x) for x in c['argv']],
                   'exit':c['exit'],'timed_out':c['timed_out'],'reaped':c['reaped'],
                   'stdout':numeric(c['stdout']),'stderr':numeric(c['stderr'])} for c in r['commands']],
      'command_count':len(r['commands']),'call':r.get('call'),'clean_source_window':r.get('clean_source_window'),
      'baseline':r.get('baseline'),'gated':r.get('result'),
      'native':{k:native.get(k) for k in ('admissions','main_admissions','main_refaults','closed','epoch_exits','epoch_error','close_complete','close_busy','close_error')},
      'final_error_count':len(r.get('final_errors',[])),'failure_type':(r.get('error') or {}).get('type'),
      'proof_limits':['Runtime report retains602, not raw SIGSYS metadata or post-termination operand memory. The separately qualified exact-filter gateway probe supplies those mechanism observations.','Both lanes explicitly disable glibc rseq for this candidate-free native epoch; no default-environment claim.','A historical working-tree bridge hash is not a committed whole-product qualification.','No timing or speedup result is claimed.'],
      'reproduce':{'bridge_build':['python3','evaluation/inprocess/native_pages.py','--expect-revision',r.get('base_revision'),'--output','<native_pages.py receipt at same revision>'],
                   'negative':['python3','evaluation/inprocess/native_pages_negative.py','--expect-revision',r.get('base_revision'),'--build-receipt','<native_pages.py receipt at same revision>','--bridge','target/page-entry/native-pages/bridge-native-pages.so','--bridge-sha256',(r.get('bridge_before') or {}).get('sha256',r.get('expected_bridge_sha256'))],
                   'note':'Run on one externally reserved CPU. Rebuild uses the complete corresponding source context; a different bridge hash requires a fresh receipt.'}}
 if history:
  h=authenticate_receipt(history);need(h['status']=='failed','historical failure must stay failed')
  n=h['reports']['LI2_NATIVE']
  out['historical_failed_attempt']={'receipt':numeric(fact(history)),'status':h['status'],'failure_type':h['error']['type'],'bridge':numeric(h['bridge_before']),'command_count':len(h['commands']),'baseline_exit':h['commands'][4]['exit'],'gated_exit':h['commands'][6]['exit'],'failure_code':h['reports']['LI2_LOADER']['failure_code'],'admissions':n['admissions'],'closed':n['closed'],'epoch_exits':n['epoch_exits'],'full_cleanup_verified':False,'note':'The initiating602 refusal occurred, but terminal native closure was not verified. This attempt remains failed.'}
 text=json.dumps(out,sort_keys=True,indent=2,allow_nan=False)+'\n'
 need(not any(x in text for x in (str(ROOT),str(Path.home()))) and not re.search(r'/home/|devbig[0-9]+|internalfb\.com',text),'public privacy')
 return text

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--expect-revision');p.add_argument('--bridge',type=Path);p.add_argument('--bridge-sha256')
 p.add_argument('--build-receipt',type=Path,help='completed native_pages.py receipt at the exact same revision/bridge hash')
 p.add_argument('--private-dir',type=Path);p.add_argument('--output',type=Path)
 p.add_argument('--replay',type=Path,help='file-only verify/project an existing private receipt')
 p.add_argument('--historical-failure',type=Path,help='bind an earlier failed attempt without changing its status')
 a=p.parse_args();need(sys.flags.optimize==0,'Python assertions enabled')
 if a.replay:
  need(not any((a.expect_revision,a.bridge,a.bridge_sha256,a.private_dir,a.build_receipt)),'replay and execution arguments distinct');path=a.replay;r=verify_saved(path)
 else:
  need(a.expect_revision and re.fullmatch('[0-9a-f]{40}',a.expect_revision) and a.bridge and a.bridge_sha256 and re.fullmatch('[0-9a-f]{64}',a.bridge_sha256) and a.build_receipt,'exact revision/bridge/build identity required')
  path=execute(a);r=read(path)
  if r['status']=='passed':r=verify_saved(path)
 text=project(path,r,a.historical_failure)
 if a.output:
  a.output.parent.mkdir(parents=True,exist_ok=True)
  with a.output.open('x') as f:f.write(text)
 print(text,end='');return int(r['status']!='passed')

if __name__=='__main__':raise SystemExit(main())
