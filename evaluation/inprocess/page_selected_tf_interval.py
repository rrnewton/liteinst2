#!/usr/bin/env python3
"""Fixed interval-protocol qualification after the full same-revision lease cohort.

Eight successful target children, five genuine protocol failures and four
pre-exec FD refusals. This finite qualification grants no performance credit.
"""
import argparse,functools,hashlib,importlib.util,json,os,platform,re,shlex,shutil,stat,sys
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from checks import source,admission
from run import hardware
from page_selected import ENV,fact,need,save,elf
from page_selected_process import invoke
from page_selected_generic_build import PROFILES
from page_selected_oneshot_build import commands,UNITS,MACROS
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
from page_default_ls_release_performance import qualified,decode,HARDWARE_KEYS
BOUNDS={'metadata':PROFILES['metadata'],'inspect':PROFILES['inspect'],
        'interval_build':[30,512<<20,16<<20,60],'interval':[5,512<<20,16<<20,15]}
LANES=('native-reference','gated-observed','native-timing','gated-timing')
CONTROLS=('bad-ready','extra-done','missing-done','wrong-go','eof-go')
FD_CONTROLS=('fd3-alias','nonfifo-go','wrong-direction','same-fifo')
SEMANTIC=('generic_tf_attempts','generic_tf_steps','source_syscalls','cpuid','rdtsc','selected_steps')
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(v):return H(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
def inventory(sealed_custody=False):
 need(type(sealed_custody)is bool,'explicit fixed interval mode')
 result=[('source-paths','metadata'),('interval-gdb-version','metadata'),('interval-objdump-version','metadata')]
 if sealed_custody:result += [('interval-unobserved-'+suffix,profile)for suffix,profile in(('headers','metadata'),('link','interval_build'),('undefined','inspect'),('symbols','inspect'),('memset','inspect'))]
 result += [('interval-observed-'+suffix,profile)for suffix,profile in
            (('headers','metadata'),('link','interval_build'),('undefined','inspect'),('symbols','inspect'),('memset','inspect'),('layout','metadata'))]
 for count in(1,256):
  name='interval-program-'+str(count)
  result += [(name+'-'+suffix,profile)for suffix,profile in
             (('headers','metadata'),('link','interval_build'),('undefined','inspect'),('symbols','inspect'),('layout','metadata'))]
  result += [('interval-'+str(count)+'-'+lane+'-make','metadata')for lane in('gated-observed','gated-timing')]
  result += [('interval-'+str(count)+'-'+lane,'interval')for lane in LANES]
 result += [('interval-control-'+c,'interval')for c in CONTROLS]
 result += [('interval-fd-'+c,'interval')for c in FD_CONTROLS]
 need(len(result)==(45 if sealed_custody else 40) and len({n for n,_ in result})==len(result),'fixed complete distinct command inventory')
 return result

def summary(r):
 sealed_custody=r['profile']=='page-selected-tf-interval-custody-v1'
 need(r['profile']in('page-selected-tf-interval-v1','page-selected-tf-interval-custody-v1'),'literal finite profile')
 cases=r['cases'];commands=r['commands'];plan=[(n,p,'normal')for n in(1,256)for p in LANES]
 plan += [(1,'gated-timing',c)for c in CONTROLS]+[(1,'launcher',c)for c in FD_CONTROLS]
 need(len(cases)<=17 and [(c['operations'],c['profile'],c['control'])for c in cases]==plan[:len(cases)],'exact attempted seventeen-child prefix')
 accepted=[]
 for c in cases:
  if c['status']!='passed':continue
  rows=[v for v in commands if v['name']==c['name']and v['profile']=='interval']
  need(len(rows)==1,'one real command for each qualified finite outcome');row=rows[0]
  need(type(row.get('pid'))is int and row['pid']>0 and row.get('reaped')is True and type(row.get('exit'))is int and
       row.get('timed_out')is False and not row.get('cleanup_errors')and c['pid']==row['pid']and c['exit']==row['exit'],
       'qualified finite row joins actual reaped child and unchanged outcome')
  if c['control']=='normal':need(row.get('accepted')is True and not row.get('error')and row['exit']==0,'all eight normal children accepted')
  elif c['profile']=='launcher':need(row['exit']==1 and not row.get('error')and c['operation_status']=='pre_exec_refusal','actual pre-exec launcher failure')
  else:need(row.get('accepted')is False and bool(row.get('error'))and 'interval_ns'not in row and c['operation_status']=='protocol_failed','actual protocol failure remains rejected')
  accepted.append(c)
 complete=r['status']=='passed'
 if complete:
  need(len(accepted)==17 and len(r['pairs'])==2 and all(x['comparison']['accepted']is True and x['comparison']['operations']==x['operations']for x in r['pairs'])and
       [(x['name'],x['profile'])for x in commands]==inventory(sealed_custody)and r['source_unchanged']and not r['error']and not r['final_errors'],
       'complete fixed cohort and all final custody before finite qualification')
 captures=[(c['name'],k,v)for c in commands for k,v in c.get('captures',{}).items()]
 value=dict(schema=1,profile=r['profile'],revision=r['expected_revision'],status=r['status'],
  prerequisite=r.get('qualification',{}).get('receipt'),hardware={k:r['hardware'][k]for k in HARDWARE_KEYS},reserved_cpu_count=1,
  bounds=BOUNDS,planned_children=17,attempted_children=len(cases),actual_children=sum(type(c.get('pid'))is int and c['pid']>0 for c in cases),
  closed_children=sum(c.get('reaped')is True for c in cases),qualified_outcomes=len(accepted),successful_targets=sum(c['control']=='normal'for c in accepted),
  required_protocol_failures=sum(c['control']in CONTROLS for c in accepted),required_pre_exec_refusals=sum(c['profile']=='launcher'for c in accepted),
  pairs=[dict(operations=x['operations'],comparison=x['comparison'],semantic_join=x.get('semantic_join',False))for x in r['pairs']],
  outcomes=[{k:c.get(k)for k in('operations','profile','control','status','operation_status','pid','exit','reaped','timed_out')}for c in cases],
  commands=len(commands),command_rows_sha256=digest(commands),capture_count=len(captures),capture_bytes=sum(v.get('bytes',0)for _,_,v in captures),
  capture_manifest_sha256=digest(captures),inputs_sha256=digest(r.get('inputs',{})),artifacts_sha256=digest(r.get('artifacts',{})),
  source_unchanged=r['source_unchanged'],finite_qualification=complete,performance_credit=False,full_b2_complete=False,full_b3_complete=False,
  error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),reproduce=r['reproduce'],
  scope='Same-revision original148 plus6/49/17 prerequisite; two actual native/observed full-state pairs, four output-only timing calibration lanes, five rejected protocols and four actual pre-exec descriptor refusals. No benchmark aggregates or unobserved BODY-local transfer claims.')
 if sealed_custody:
  for label,key in(('custody_prerequisite','custody_qualification'),('baseline_interval_prerequisite','baseline_interval_qualification')):
   prerequisite=r.get(key,{}).get('receipt')
   value[label]={k:prerequisite[k]for k in('bytes','sha256')}if prerequisite else None
  value['scope']='Same-revision original148 plus6/49/17, original interval17 and custody17 prerequisites; fresh custody N1/N256 full-state pairs and identical protocol/FD refusals. Explicit FRESH/RETAINED BODY authority; timing lanes have no binary or BODY-local custody claim. No benchmark credit.'
 text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
 need(len(text.encode())<64<<10 and not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded numeric public projection without private paths')
 return value

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--expect-revision',required=True);ap.add_argument('--qualification-receipt',type=Path,required=True)
 ap.add_argument('--qualification-sha256',required=True);ap.add_argument('--output',type=Path,required=True)
 ap.add_argument('--sealed-custody',action='store_true')
 ap.add_argument('--custody-receipt',type=Path);ap.add_argument('--custody-sha256')
 ap.add_argument('--baseline-interval-receipt',type=Path);ap.add_argument('--baseline-interval-sha256')
 a=ap.parse_args();os.chdir(ROOT)
 need(all(x is not None for x in(a.custody_receipt,a.custody_sha256,a.baseline_interval_receipt,a.baseline_interval_sha256))if a.sealed_custody else all(x is None for x in(a.custody_receipt,a.custody_sha256,a.baseline_interval_receipt,a.baseline_interval_sha256)),'explicit custody mode requires both complete additional prerequisite identities')
 if a.sealed_custody:need(all(re.fullmatch('[0-9a-f]{64}',x)for x in(a.custody_sha256,a.baseline_interval_sha256)),'exact additional prerequisite hashes')
 need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',a.expect_revision)and re.fullmatch('[0-9a-f]{64}',a.qualification_sha256)and len(os.sched_getaffinity(0))==1,
      'exact revision/receipt hash, assertions and one reserved CPU')
 private=a.output.resolve();need(private.is_relative_to(ROOT/'target')and not private.exists(),'fresh private output');private.mkdir(parents=True,mode=0o700)
 cpu=next(iter(os.sched_getaffinity(0)));selected=ROOT/'tools/page-entry/selected';fixture=selected/'tests/tf_interval'
 r=dict(schema=1,profile='page-selected-tf-interval-custody-v1'if a.sealed_custody else'page-selected-tf-interval-v1',expected_revision=a.expect_revision,source=None,source_unchanged=False,
        hardware=hardware(cpu),bounds=BOUNDS,status='failed',error=None,final_errors=[],commands=[],cases=[],pairs=[],builds=[],programs=[],generated={})
 r['reproduce']=['python3','-B','evaluation/inprocess/page_selected_tf_interval.py','--expect-revision',a.expect_revision,
  '--qualification-receipt','${SAME_REVISION_FULL_LEASE_RECEIPT}','--qualification-sha256',a.qualification_sha256,'--output','${FRESH_PRIVATE_OUTPUT}']
 if a.sealed_custody:r['reproduce'] += ['--sealed-custody','--custody-receipt','${SAME_REVISION_CUSTODY_RECEIPT}','--custody-sha256',a.custody_sha256,'--baseline-interval-receipt','${SAME_REVISION_BASELINE_INTERVAL_RECEIPT}','--baseline-interval-sha256',a.baseline_interval_sha256]
 pins={};aliases={};artifacts={};presence={};namespace_links={};pending=[]
 def pin(path):
  alias=str(Path(path).absolute());p=Path(alias).resolve(strict=True);v=fact(p)
  need(alias not in aliases or aliases[alias]==str(p),'input lexical alias unchanged');aliases[alias]=str(p)
  need(str(p)not in pins or pins[str(p)]==v,'input bytes unchanged');pins[str(p)]=v;return p
 def binary(path):
  p=Path(path);need(p.is_file()and not p.is_symlink(),'regular retained output');v=dict(fact(p),mode=p.stat().st_mode&0o777)
  need(str(p)not in artifacts or artifacts[str(p)]==v,'artifact bytes/mode unchanged');artifacts[str(p)]=v;return p
 def retain(path):
  if path.exists()or path.is_symlink():return fact(binary(path))
  return None
 def closure():
  if 'prerequisite_configuration'in r:
   v=r['prerequisite_configuration'];need(admission.cargo_configuration(v['environment'])==v['cargo_configuration'],'qualified Build configuration unchanged')
  need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r.get('qualified_namespace_aliases',{}).items()),'qualified namespace links unchanged')
  for name in('custody_namespace_aliases','baseline_interval_namespace_aliases'):
   need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r.get(name,{}).items()),'additional qualified namespace links unchanged')
  need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in namespace_links.items()),'new namespace links unchanged')
  need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
  need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'all input aliases unchanged')
  need(all(fact(p)==v for p,v in pins.items()),'all actual source/tool/input bytes unchanged')
  need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all actual retained artifacts unchanged')
 def start(name,argv,profile,env,expected=0):
  closure();i=len(r['commands']);plan=inventory(a.sealed_custody);need(i<len(plan)and(name,profile)==plan[i],'exact fixed-command ordered prefix')
  row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],environment=dict(env),capture_limit=16<<20,expected_exit=expected)
  r['commands'].append(row);return row
 def captured(row):
  for stream in('stdout','stderr','record','preparation'):
   path=private/(row['name']+'.'+stream)
   try:
    got=row.get('captures',{}).get(stream)
    if path.exists()or path.is_symlink():
     actual=fact(binary(path));need(got is not None and got.get('file')==path.name and actual=={k:got[k]for k in('bytes','sha256')},'exact complete or partial command capture')
    elif got is not None:need(got=={'missing':True},'recorded capture absence only')
   except BaseException as exc:r['final_errors'].append('capture '+row['name']+'.'+stream+': '+type(exc).__name__+': '+str(exc))
  path=private/(row['name']+'.json')
  try:
   binary(path);need(decode(path.read_bytes())==row,'exact immutable retained command row')
  except BaseException as exc:r['final_errors'].append('command row '+row['name']+': '+type(exc).__name__+': '+str(exc))
 def run(name,argv,profile='metadata',env=ENV,expected=0,record=False):
  row=start(name,argv,profile,env,expected)
  try:
   out,err=invoke(row,private,cpu,record=record)
   need(type(row['exit'])is int and(expected is None or row['exit']==expected),'actual fixed command exit '+name)
   return row,out,err
  finally:captured(row)
 def load(name,path):
  spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
 try:
  r['source']=source();need(r['source']['revision']==a.expect_revision,'exact clean current committed source')
  git=pin(shutil.which('git',path=ENV['PATH']))
  _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','--','tools/page-entry','evaluation/inprocess']);need(not err,'actual tracked source listing')
  r['required_source_inputs']={str(pin(ROOT/os.fsdecode(n))):fact(ROOT/os.fsdecode(n))for n in names.split(b'\0')if n and not n.startswith(b'evaluation/inprocess/results/')}
  tools,unobserved=qualified(a.qualification_receipt,a.qualification_sha256,r['source'],pin,binary,r,lease_mode=True)
  r['prerequisite_receipt']=dict(path=str(pin(a.qualification_receipt)),**fact(a.qualification_receipt))
  r['unobserved_bridge']=dict(path=str(unobserved),**fact(unobserved))
  if a.sealed_custody:r['prerequisite_bridge']=r.pop('unobserved_bridge')
  prerequisite=decode(pin(a.qualification_receipt).read_bytes());archive=pin(prerequisite['build']['artifacts']['decoder.a']['path'])
  builder=SimpleNamespace(tools=tools,environment=r['prerequisite_configuration']['environment'])
  r['archive']=dict(path=str(archive),**fact(archive))
  need(pin(sys.executable)==tools['python'],'exact qualified Python tool')
  gd=prerequisite['tf_same_page_fixture']['tools']['gdb'];tools['gdb']=pin(gd['path'])
  need(fact(tools['gdb'])=={k:gd[k]for k in('bytes','sha256')},'exact qualified actual-DWARF tool')
  r['tools']={k:dict(path=str(p),**fact(p))for k,p in tools.items()}
  if a.sealed_custody:
   baseline_auth=load('tci_baseline_auth',HERE/'page_tf_interval_qualified.py')
   scratch=dict(cpu=cpu,hardware=r['hardware'],required_source_inputs=r['required_source_inputs'])
   baseline_assets=baseline_auth.authenticate(a.baseline_interval_receipt,a.baseline_interval_sha256,r['source'],pin,binary,scratch)
   need(scratch['qualification']==r['qualification']and scratch['prerequisite_configuration']==r['prerequisite_configuration']and baseline_assets['tools']==tools,'same exact original lease prerequisite and baseline interval tools')
   r['baseline_interval_receipt']=dict(path=str(pin(a.baseline_interval_receipt)),**fact(a.baseline_interval_receipt))
   r['baseline_interval_qualification']=scratch['interval_qualification'];r['baseline_interval_namespace_aliases']=scratch['interval_namespace_aliases']
   custody_auth=load('tci_custody_auth',HERE/'page_tf_custody_qualified.py');r['cpu']=cpu
   custody_assets=custody_auth.authenticate(a.custody_receipt,a.custody_sha256,r['source'],pin,binary,r)
   need(custody_assets['tools']==tools and custody_assets['archive']==archive and custody_assets['prerequisite_bridge']==unobserved and custody_assets['prerequisite_configuration']==r['prerequisite_configuration'],'custody and interval prerequisites share exact original tools/archive/bridge/configuration')
   r['custody_receipt']=dict(path=str(pin(a.custody_receipt)),**fact(a.custody_receipt))
  prepare=load('tf_interval_prepare',fixture/('custody_prepare.py'if a.sealed_custody else'prepare.py'));check=load('tf_interval_check',fixture/('custody.py'if a.sealed_custody else'check.py'))
  pipe=load('tf_interval_pipe',fixture/'pipe_run.py');images=load('tf_interval_images',selected/'tests/provider_launch/interpreter.py')
  namespace=load('tf_interval_namespace',ROOT/'tools/page-entry/namespace.py')
  policy=load('tf_interval_policy',selected/'tests/oneshot_integrated/check.py')
  reports=check.reports if a.sealed_custody else load('tf_interval_reports',selected/'tests/tf_same_page/reports.py')
  need(pipe.BOUNDS==BOUNDS['interval']and pipe.CONTROLS=={'normal':'0','bad-ready':'1','extra-done':'2','missing-done':'3','wrong-go':'0','eof-go':'0'},'fixed actual protocol bounds and controls')
  for name in('launch.py','negative_launch.py','fixture.S','native_reference.c','record.h','linker.ld','build.sh','layout.py','observe.inc'):pin(fixture/name)
  for module in tuple(sys.modules.values()):
   path=getattr(module,'__file__',None)
   if path and Path(path).resolve().is_relative_to(ROOT)and Path(path).suffix=='.py':pin(path)
  for path in('/etc/ld.so.cache','/etc/ld.so.preload'):
   presence[path]=os.path.lexists(path)
   if presence[path]:pin(path)
  need(not presence['/etc/ld.so.preload'],'no global preload')
  output=private/'interval';output.mkdir();cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
  for name in('gdb','objdump'):
   _,out,err=run('interval-'+name+'-version',[tools[name],'--version'],env=gdb_env if name=='gdb'else builder.environment)
   need(out and not err,'actual inspection tool version '+name)
  def inspect(name,path,record,bridge=False):
   binary(path)
   if bridge:bridge_check(path)
   _,out,err=run(name+'-undefined',[tools['nm'],'-u',path],profile='inspect',env=builder.environment);need(out==err==b'','no unresolved actual ELF imports')
   _,symbols,err=run(name+'-symbols',[tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment);need(not err,'actual defined ELF symbols')
   result=dict(path=str(path),**fact(path))
   if bridge:
    _,assembly,err=run(name+'-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],profile='inspect',env=builder.environment)
    need(not err,'complete actual reset assembly');result['reset']=hidden_memset(path,body_check(path,symbols,assembly,'fast',symbol_name='memset'))
   if record is None:
    need(a.sealed_custody and name=='interval-unobserved'and bridge,'only the exact unobserved custody release artifact has no observation layout');return result
   _,out,err=run(name+'-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
    '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(path),'-x',fixture/('custody_layout.py'if a.sealed_custody else'layout.py')],env=gdb_env)
   need(not err,'actual file-only DWARF');layout=decode(out);result['layout']=layout
   rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[record.encode()]];_,_,ph=elf(path)
   need(layout['record']==record and len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b'and
    0<int(rows[0][1],16)==layout['types'][record]['bytes']<16<<20 and
    sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+int(rows[0][1],16)<=p[3]+p[6]for p in ph)==1,
    'complete actual native or gated record in one writable NX load')
   return result
  observed=output/'observed';r['adapters']=prepare.prepare(ROOT,observed,pin)
  generated_names=prepare.GENERATED if a.sealed_custody else(*prepare.FILES,'tf_interval_observe.inc','tf_interval_record.h','tf_interval_old_record.h')
  for name in generated_names:
   r['generated'][name]=fact(binary(observed/name))
  recipe_path=pin(selected/('build-tf-sealed-custody.sh'if a.sealed_custody else'build-tf-same-page-lease.sh'));argv=commands(recipe_path,builder,output,archive,pin)[0]
  units=[str(selected.parent/p)for p in UNITS[:-1]]
  macros=(MACROS-{'-DLI2_ONESHOT_PUBLICATION=1'})|{'-DLI2_CPUID_NX_ONLY=1','-DLI2_RSEQ_NATIVE=1','-DLI2_RSEQ_NATIVE_BOUNDARY=1','-DLI2_RSEQ_TCGETS_BTRFS=1','-DLI2_RSEQ_TIOCGWINSZ_BTRFS=1','-DLI2_TF_SAME_PAGE_LEASE=1'}
  if a.sealed_custody:macros=macros|{'-DLI2_TF_SEALED_CUSTODY=1'}
  need([x for x in argv if x.endswith(('.c','.S'))]==units and len(units)==15 and
       set(x for x in argv if x.startswith('-DLI2_'))==macros and sum(x.startswith('-DLI2_')for x in argv)==len(macros)==(14 if a.sealed_custody else 13) and
       argv[-2:]==['-o',str(output/('bridge-tf-sealed-custody.so'if a.sealed_custody else'bridge-tf-same-page-lease.so'))]and
       all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
       'unchanged exact fifteen-unit thirteen-macro release recipe')
  if a.sealed_custody:
   unobserved=output/'bridge-tf-sealed-custody.so';pending.append(unobserved)
   release=dict(name='interval-unobserved',recipe=fact(recipe_path),argv=argv,archive=fact(archive),translation_units=15,status='failed');r['builds'].append(release)
   headers('interval-unobserved-headers',argv,units,archive,builder,pin,aliases,run,release)
   try:run('interval-unobserved-link',argv,profile='interval_build',env=builder.environment)
   finally:release['artifact']=retain(unobserved)
   release['inspection']=inspect('interval-unobserved',unobserved,None,True);release['status']='passed'
   r['unobserved_bridge']=dict(path=str(unobserved),**fact(unobserved))
  actual=argv.copy();actual[-1]=str(output/'observed.so');sources=units.copy()
  for basename in('runtime_loader.c','lifecycle_loader.c'):
   old,new=str(selected/basename),str(observed/basename);need(actual.count(old)==1,'one exact observation TU replacement')
   actual=[new if x==old else x for x in actual];sources=[new if x==old else x for x in sources]
  build=dict(name='interval-observed',recipe=fact(recipe_path),argv=actual,archive=fact(archive),translation_units=15,status='failed');r['builds'].append(build)
  headers('interval-observed-headers',actual,sources,archive,builder,pin,aliases,run,build)
  need({str(observed/n)for n in generated_names}<=set(build['headers']),'complete actual generated observation include view')
  bridge=output/'observed.so';pending.append(bridge)
  try:run('interval-observed-link',actual,profile='interval_build',env=builder.environment)
  finally:build['artifact']=retain(bridge)
  build['inspection']=inspect('interval-observed',bridge,'tfi_record',True);build['status']='passed';gated_layout=build['inspection']['layout']
  interpreter,metadata=images.emit(output/'interpreter')
  for path in(interpreter,metadata):r['generated'][path.name]=dict(path=str(path),**fact(pin(binary(path))))
  carrier_tool=pin(ROOT/'tools/page-entry/carrier.py');programs={}
  def namespace_check(case,original,carrier,ns,objects,prep,mode,control):
   need(prep['mode']==mode and type(prep['control'])is int and prep['control']==control and prep['mask']==0 and prep['affinity']==[cpu]and
    [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
    'actual exact launch mode/control/CPU and reset signal dispositions/mask')
   env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
   need(prep['environment']==env and prep['argv']==[str(original),mode,str(prep['pipes'][0]['fd']),str(prep['pipes'][1]['fd']),str(control)],'actual original argv and default environment')
   if mode!='gated':return
   sealed=decode(pin(binary(ns/'namespace.json')).read_bytes());started=decode(pin(binary(ns/'launch.json')).read_bytes())
   need(sealed['original']==str(original)and sealed['original_sha256']==fact(original)['sha256']and sealed['interpreter_sha256']==fact(interpreter)['sha256']and len(sealed['objects'])==len(objects),'actual complete sealed original namespace')
   for got,item in zip(sealed['objects'],objects):
    need(got['names']==item['names']and got['sha256']==H(item['bytes'])and got['size']==len(item['bytes'])and got['seals']==namespace.SEALS and got['device']>0 and got['inode']>0,'actual immutable namespace object')
    for alias in got['names']:
     path=ns/alias;value='/proc/self/fd/'+str(got['fd']);need(path.is_symlink()and os.readlink(path)==value,'actual retained sealed alias');namespace_links[str(path)]=value
   env.update(LD_LIBRARY_PATH=str(ns),LD_BIND_NOW='1',LI2_DEPENDENCY_FDS=','.join(str(x['fd'])for x in sealed['objects']))
   need(started['argv']==prep['argv']and started['environment']==env and
        {k:started[v]for k,v in(('bytes','carrier_size'),('sha256','carrier_sha256'))}==fact(carrier)==case['backing'],
        'actual namespace launch and exact profile-specific sealed carrier extent/hash without policy override')
   case['namespace']=dict(manifest=fact(ns/'namespace.json'),launch=fact(ns/'launch.json'))
  def pipe_case(count,profile,control='normal'):
   program=programs[count];original=Path(program['path']);image=program['image'];mode=check.PROFILES[profile]
   name='interval-'+str(count)+'-'+profile if control=='normal'else'interval-control-'+control
   case=dict(name=name,operations=count,profile=profile,control=control,status='failed',operation_status='unobserved');r['cases'].append(case)
   carrier=Path(program['carriers'][profile]['path'])if mode=='gated'else None;ns=output/(name+'-namespace')if mode=='gated'else None
   if carrier is not None:
    case['backing']=fact(pin(binary(carrier)));image=dict(image,backing=case['backing'])
   command=tuple(pipe.command(tools['python'],original,mode,interpreter.parent,carrier,ns))
   layout=program['inspection']['layout']if profile=='native-reference'else gated_layout if profile=='gated-observed'else None
   callback=functools.partial(check.terminal,image=image,layout=layout,cpu=cpu,profile=profile,expected_command=command)
   row=start(name,command,'interval',ENV,0 if control=='normal'else None);row['control']=control
   try:pipe.invoke(row,private,cpu,callback)
   finally:
    captured(row)
    for path in((ns/'namespace.json',ns/'launch.json')if ns else()):
     if path.exists():binary(path)
    for key in('pid','exit','reaped','timed_out'):
     if key in row:case[key]=row[key]
   need(type(row.get('pid'))is int and row['pid']>0 and type(row.get('exit'))is int and row['reaped']and not row['timed_out']and not row['cleanup_errors'],'actual closed non-timeout subject with complete cleanup')
   stdout=pin(binary(private/(name+'.stdout'))).read_bytes();stderr=pin(binary(private/(name+'.stderr'))).read_bytes()
   record=pin(binary(private/(name+'.record'))).read_bytes();prep=decode(pin(binary(private/(name+'.preparation'))).read_bytes())
   namespace_check(case,original,carrier,ns,program['objects'],prep,mode,int(pipe.CONTROLS[control]))
   st=(private/(name+'.record')).stat();outst=(private/(name+'.stdout')).stat()
   need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and prep['stdout']['identity'][:2]==[outst.st_dev,outst.st_ino],
        'actual retained capture objects join child preparation identities')
   case['preparation']=prep;case['captures']=row['captures'];go,notify=(x['fd']for x in prep['pipes'])
   if control=='normal':
    need(row['accepted']is True and not row['error']and row['exit']==0 and row['terminal_validation']['accepted']is True,'complete strictly accepted interval child')
    case['comparison']=row['terminal_validation'];case['operation_status']='completed'
   else:case['comparison']=protocol_failure(control,row,stdout,stderr,record,prep,image,go,notify,check,reports,cpu);case['operation_status']='protocol_failed'
   case['status']='passed';return case,stdout,record,row
  fixture_recipe=pin(fixture/'build.sh');templates=recipe(fixture_recipe,'"$cc_bin"');need(len(templates)==1,'one exact native fixture recipe')
  for count in(1,256):
   name='interval-program-'+str(count);directory=output/name;directory.mkdir();original=directory/'original';pending.append(original)
   argv=expand(templates[0],{'$cc_bin':tools['cc'],'$fixture_dir':fixture,'$metadata':metadata,'$output':original,'$operations':count})
   units=[str(fixture/'fixture.S'),str(fixture/'native_reference.c'),str(metadata)]
   need([x for x in argv if x.endswith(('.c','.S'))]==units and argv[-2:]==['-o',str(original)]and argv.count('-DTFI_N='+str(count))==1 and
    all(x in argv for x in('-O2','-g','-Werror','-nostdlib','-no-pie','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-mcmodel=large')),'exact three-unit fixed N native fixture')
   program=dict(operations=count,path=str(original),recipe=fact(fixture_recipe),argv=argv,status='failed',carriers={});r['programs'].append(program)
   flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
   _,out,err=run(name+'-headers',[tools['cc'],*flags,'-M','-MT','tf_interval',*units],env=builder.environment)
   rules=out.decode().replace('\\\n',' ').splitlines();need(not err and len(rules)==3 and all(x.startswith('tf_interval: ')for x in rules),'complete actual three-TU fixture include closure')
   program['headers']={str(pin(t)):fact(pin(t))for line in rules for t in shlex.split(line.split(':',1)[1])};need(set(units)<=set(program['headers']),'all actual linked fixture sources')
   try:run(name+'-link',argv,profile='interval_build',env=builder.environment)
   finally:program['artifact']=retain(original)
   pin(binary(original));program['inspection']=inspect(name,original,'tfi_native_record');program['image']=check.elf(original.read_bytes(),interpreter,count,policy.native_policy)
   objects,description=namespace.plan(original,[interpreter.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
   program['namespace_plan']=description;program['dependencies']=[]
   for item in objects:
    need(fact(pin(item['path']))['sha256']==H(item['bytes']),'complete actual namespace source');program['dependencies'].append(dict(names=item['names'],**fact(pin(item['path']))))
    for alias in item['names']:pin(interpreter.parent/alias)
   for lane,actual_bridge in(('gated-observed',bridge),('gated-timing',unobserved)):
    carrier=directory/(lane+'-carrier');pending.append(carrier)
    try:_,out,err=run('interval-'+str(count)+'-'+lane+'-make',[tools['python'],carrier_tool,'make',original,actual_bridge,carrier])
    finally:retain(carrier)
    binary(carrier);v=decode(out);need(not err and v['original_sha256']==fact(original)['sha256']and v['bridge_sha256']==fact(actual_bridge)['sha256']and v['interpreter_sha256']==fact(interpreter)['sha256']and v['carrier_sha256']==fact(carrier)['sha256'],'same actual subject/carrier/interpreter and explicit profile bridge')
    program['carriers'][lane]=dict(path=str(carrier),**fact(carrier),identities=v)
   programs[count]=dict(program,objects=objects)
   native,nout,nrec,nrow=pipe_case(count,'native-reference');gated,gout,grec,grow=pipe_case(count,'gated-observed')
   comparison=check.pair(nrec,grec,nout,gout,{'native':program['inspection']['layout'],'gated':gated_layout},dict(program['image'],backing=gated['backing']),native['pid'],gated['pid'],cpu,
    native_fds=tuple(x['fd']for x in native['preparation']['pipes']),gated_fds=tuple(x['fd']for x in gated['preparation']['pipes']))
   need(comparison['accepted']is True and comparison['operations']==count and comparison['native']['accepted']is True and comparison['gated']['accepted']is True,'actual complete native/observed interval pair');pair=dict(operations=count,comparison=comparison,semantic_join=False);r['pairs'].append(pair)
   nt,ntout,_,_=pipe_case(count,'native-timing');gt,gtout,_,_=pipe_case(count,'gated-timing')
   observed_reports=reports.reports((private/(gated['name']+'.stderr')).read_bytes())
   timing_reports=reports.reports((private/(gt['name']+'.stderr')).read_bytes())
   reports.completed(observed_reports,gated['pid']);reports.completed(timing_reports,gt['pid'])
   need(observed_reports['lease']==timing_reports['lease']and all(observed_reports['loader'][k]==timing_reports['loader'][k]for k in SEMANTIC),
    'fixed complete lease and six semantic counters equal across actual observed/unobserved lanes')
   need(all(c['comparison']['output']['count']==count and c['comparison']['output']['cpu']==cpu for c in(native,gated,nt,gt)),
    'all four exact terminal output semantics retain N and reserved CPU')
   pair['semantic_join']=True;pair['semantic_fields']=list(SEMANTIC);program['status']='passed'
  for control in CONTROLS:pipe_case(1,'gated-timing',control)
  program=programs[1];original=Path(program['path'])
  for control in FD_CONTROLS:
   name='interval-fd-'+control;evidence=private/(name+'.evidence.json');preparation=private/(name+'.launch-preparation.json')
   case=dict(name=name,operations=1,profile='launcher',control=control,status='failed',operation_status='unobserved');r['cases'].append(case)
   argv=[tools['python'],fixture/'negative_launch.py','--kind',control,'--original',original,'--library-root',interpreter.parent,
    '--preparation',preparation,'--evidence',evidence,'--record-fd','{record_fd}']
   try:row,out,err=run(name,argv,profile='interval',expected=1,record=True)
   finally:
    if evidence.exists():binary(evidence)
    regular=evidence.with_suffix('.regular')
    if regular.exists():binary(regular)
    if preparation.exists():binary(preparation)
    rows=[x for x in r['commands']if x['name']==name]
    if rows:case.update({k:rows[0][k]for k in('pid','exit','reaped','timed_out')if k in rows[0]})
   ev=decode(pin(binary(evidence)).read_bytes());rec=pin(binary(private/(name+'.record'))).read_bytes()
   case['comparison']=launcher_failure(control,row,out,err,rec,ev,preparation,original,interpreter.parent,fixture,tools['python'],cpu,(private/(name+'.record')).stat())
   case['operation_status']='pre_exec_refusal';case['status']='passed'
  need(len(r['cases'])==17 and all(c['status']=='passed'for c in r['cases'])and len(r['pairs'])==2 and all(x['semantic_join']for x in r['pairs']),'all fixed interval positive and negative obligations')
  r['status']='passed'
 except BaseException as exc:
  r['error']=type(exc).__name__+': '+str(exc)
  if r['cases']and r['cases'][-1]['status']!='passed':r['cases'][-1]['error']=r['error']
 finally:
  for p in sorted(private.rglob('*')):
   if p.is_file()and not p.is_symlink():
    try:binary(p)
    except BaseException as exc:r['final_errors'].append('retain '+str(p)+': '+type(exc).__name__+': '+str(exc))
  try:closure()
  except BaseException as exc:r['final_errors'].append('closure: '+type(exc).__name__+': '+str(exc))
  try:r['source_after']=source();need(r['source_after']==r['source'],'exact committed source unchanged')
  except BaseException as exc:r['final_errors'].append('source: '+type(exc).__name__+': '+str(exc))
  r['source_unchanged']=r['source']is not None and r.get('source_after')==r['source']and not r['final_errors']
  r['inputs']=pins;r['aliases']=aliases;r['artifacts']=artifacts;r['configuration_presence']=presence;r['namespace_links']=namespace_links
  if r['error']or r['final_errors']or not r['source_unchanged']:r['status']='failed'
  save(private/'receipt.json',r);public=summary(r);public['private_receipt']=fact(private/'receipt.json')
  text=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n';need(len(text.encode())<64<<10,'final public size including private receipt identity')
  (private/'public.json').write_text(text)
  print(json.dumps(dict(status=r['status'],commands=len(r['commands']),receipt=str(private/'receipt.json'),public=str(private/'public.json'))))
 return 0 if r['status']=='passed'else 1

def protocol_failure(control,row,stdout,stderr,record,prep,image,go,notify,check,reports,cpu):
 need(control in CONTROLS and row['control']==control and row['accepted']is False and 'interval_ns'not in row and
      row['protocol_complete']is False and row['reaped']is True and row['timed_out']is False and not row['cleanup_errors']and
      all(x['closed']is True for x in row['descriptors'])and record==b'', 'actual rejected protocol with empty unobserved FD3 and complete cleanup')
 need(row['bounds']==BOUNDS['interval']and all(type(x)is int for x in row['bounds'])and
      type(row['start_ns'])is int and type(row['deadline_ns'])is int and row['deadline_ns']==row['start_ns']+15*10**9,
      'unchanged exact resource limits and one absolute protocol deadline')
 need([x['name']for x in row['descriptors']]==['record','go_read','go_write','notify_read','notify_write']and
      all(set(x)=={'name','fd','closed'}and type(x['fd'])is int for x in row['descriptors'])and
      len({x['fd']for x in row['descriptors']})==5 and row['descriptors'][0]['fd']==3 and
      row['pass_fds']==[3,go,notify]and len(row['pipe_before'])==4 and len(prep['pipes'])==2,
      'complete actual record and two-pipe descriptor inventory')
 parent=row['pipe_before']
 need([x['fd']for x in parent]==[x['fd']for x in row['descriptors'][1:]],'actual four parent descriptors match owned close inventory')
 for i,x in enumerate(parent):
  need(set(x)=={'fd','device','inode','mode','flags','inheritable'}and all(type(x[k])is int for k in('fd','device','inode','mode','flags'))and
       stat.S_ISFIFO(x['mode'])and x['flags']&os.O_ACCMODE==(0 if i in(0,2)else 1)and not x['flags']&(os.O_NONBLOCK|os.O_PATH)and x['inheritable']is False,
       'actual normal blocking pipe kinds/directions before controlled protocol failure')
 need((parent[0]['device'],parent[0]['inode'])==(parent[1]['device'],parent[1]['inode'])and
      (parent[2]['device'],parent[2]['inode'])==(parent[3]['device'],parent[3]['inode'])and
      (parent[0]['device'],parent[0]['inode'])!=(parent[2]['device'],parent[2]['inode']), 'actual two independent protocol pipes')
 need(check.capture_identity(row['stdout_before'],0)==check.capture_identity(prep['stdout'],0,True),
      'complete actual normal-open Btrfs capture provenance before failed protocol')
 for parent,child in zip((row['pipe_before'][0],row['pipe_before'][3]),prep['pipes']):
  need({k:parent[k]for k in('fd','device','inode','mode','flags')}=={k:child[k]for k in('fd','device','inode','mode','flags')}and
       parent['inheritable']is False and child['inheritable']is True,'actual failed-subject inherited FIFO joins')
 need(prep['observer']=={k:row['record_before'][k]for k in('fd','device','inode')}and
      prep['stdout']['identity']==row['stdout_before']['identity']and prep['stdout']['query_duplicate_closed']is True,
      'actual failed-subject record/stdout identity')
 transcript=row['transcript'];need(0<len(transcript)<=32,'bounded actual transcript')
 for t in transcript:
  need(type(t['time_ns'])is int and row['start_ns']<=t['time_ns']<=row['deadline_ns']and
       t['kind']in('read','write','go-eof'),'actual ordered protocol observations')
 need([x['time_ns']for x in transcript]==sorted(x['time_ns']for x in transcript),'monotonic transcript order')
 reads=[x for x in transcript if x['kind']=='read'];actions=[x for x in transcript if x['kind']!='read']
 data=b''.join(bytes.fromhex(x['hex'])for x in reads);eofs=sum(x['hex']==''for x in reads)
 if control=='bad-ready':
  need(data==b'TFI-BAD\n'and eofs==0 and not actions and row['exit']==-9 and stdout==stderr==b''and
       row['error']=='ValueError: exact READY without premature EOF',
       'actual wrong READY before GO; intentional parent cleanup, no successful target claim')
 else:
  need(eofs==1 and reads[-1]['hex']=='' and len(actions)==1,'one actual GO action and terminal FIFO EOF')
  if control=='eof-go':need(actions[0]['kind']=='go-eof'and row.get('candidate_go_ns')is None,'actual GO-write-end closure without byte')
  else:need(actions[0]['kind']=='write'and actions[0]['hex']==('58'if control=='wrong-go'else'47')and actions[0]['result']==1 and
            row['candidate_go_ns']==actions[0]['time_ns'],'exact single actual GO byte')
  if control=='extra-done':
   need(data==b'TFI-RDY\nTFI-DON\nTFI-DON\n'and row['error']=='ValueError: exact transcript and EOF','exact duplicate DONE and EOF rejection')
  else:need(data==b'TFI-RDY\n'and row['error']=='ValueError: exact DONE after actual GO','actual READY/GO then EOF without DONE')
  parsed=reports.reports(stderr)
  if control in('extra-done','missing-done'):
   need(row['exit']==0,'complete target despite rejected notify protocol');reports.completed(parsed,row['pid'])
   control_number=2 if control=='extra-done'else 3
   check.control_output(stdout,image,control_number,go,notify,cpu)
  else:
   need(row['exit']==99 and not stdout and parsed['loader']['status']==99 and parsed['loader']['failure_code']==0,
        'actual source-defined post-body rn_fail99, never unrelated runtime failure125')
   cpuid=parsed['cpuid_nx']
   need(cpuid['attempts']==cpuid['samples']==cpuid['commits']==parsed['loader']['cpuid']>0 and cpuid['raw']==cpuid['result']and
        cpuid['phase']==3 and cpuid['hardware_entered']==cpuid['hardware_returned']==1,'actual completed startup before rejected GO')
 return dict(qualified_refusal=True,operation_status='protocol_failed',control=control,exit=row['exit'],
             transcript_bytes=len(data),target_completed=control in('extra-done','missing-done'),performance_credit=False)

def launcher_failure(control,row,stdout,stderr,record,ev,preparation,original,library,fixture,python,cpu,record_stat):
 need(control in FD_CONTROLS and type(row['pid'])is int and row['pid']>0 and row['exit']==1 and row['reaped']and not row['timed_out']and
      not row['error']and not row['cleanup_errors']and row['descriptors']==[dict(name='record',fd=3,closed=True)]and stdout==record==b''and
      not preparation.exists(),'actual failed launcher with no target preparation/output and complete fd3 cleanup')
 need(ev['schema']==1 and ev['kind']==control and ev['pid']==row['pid']and ev['affinity']==[cpu]and ev['target_exec_attempted']is False,
      'actual same supervised descriptor-construction process')
 record_fact=ev['record'];go=ev['go'];notify=ev['notify']
 for x in(record_fact,go,notify):
  need(set(x)=={'fd','device','inode','mode','flags','inheritable'}and all(type(x[k])is int and x[k]>=0 for k in('fd','device','inode','mode','flags'))and type(x['inheritable'])is bool,'typed complete actual negative descriptor fact')
 need(record_fact['fd']==3 and stat.S_ISREG(record_fact['mode'])and record_fact['flags']&os.O_ACCMODE==os.O_WRONLY and
      record_fact['inheritable']is True and record_fact['device']==record_stat.st_dev and record_fact['inode']==record_stat.st_ino and
      record_fact['mode']==record_stat.st_mode and record_stat.st_size==0,
      'actual inherited fresh regular record descriptor')
 argv=[str(python),str(fixture/'launch.py'),'--mode','native','--original',str(original),'--library-root',str(library),
       '--preparation',str(preparation),'--record-fd','3','--go-fd',str(go['fd']),'--notify-fd',str(notify['fd']),'--control','0']
 need(ev['argv']==argv and notify['fd']>3 and stat.S_ISFIFO(notify['mode'])and notify['flags']&os.O_ACCMODE==os.O_WRONLY and
      go['inheritable']is True and notify['inheritable']is True and
      not any(x['flags']&(os.O_NONBLOCK|os.O_PATH)for x in(go,notify)),'actual fixed launcher argv and blocking inherited descriptors')
 if control=='fd3-alias':
  need(go==record_fact,'genuine record/GO alias');message='exact record and two distinct pipe ends'
 elif control=='nonfifo-go':
  need(go['fd']>3 and go['fd']!=notify['fd']and stat.S_ISREG(go['mode'])and go['flags']&os.O_ACCMODE==os.O_RDONLY,
       'actual normal regular GO input, not a FIFO');message='blocking FIFO endpoint and exact access'
 elif control=='wrong-direction':
  need(go['fd']>3 and go['fd']!=notify['fd']and stat.S_ISFIFO(go['mode'])and go['flags']&os.O_ACCMODE==os.O_WRONLY,
       'actual GO write endpoint');message='blocking FIFO endpoint and exact access'
 else:
  need(go['fd']>3 and go['fd']!=notify['fd']and stat.S_ISFIFO(go['mode'])and go['flags']&os.O_ACCMODE==os.O_RDONLY and
       (go['device'],go['inode'])==(notify['device'],notify['inode']),'actual opposite ends of one FIFO');message='two genuine independent inherited pipes'
 need(stderr.startswith(b'Traceback (most recent call last):\n')and stderr.endswith(('ValueError: '+message+'\n').encode())and
      ('File "'+str(fixture/'launch.py')+'", line ').encode()in stderr,'actual exact launcher guard refusal before source-ordered target exec')
 return dict(qualified_refusal=True,operation_status='pre_exec_refusal',control=control,exit=1,target_exec_claim=False,
             failure_guard=message,performance_credit=False)

if __name__=='__main__':raise SystemExit(main())
