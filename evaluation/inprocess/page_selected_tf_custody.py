#!/usr/bin/env python3
"""Seventeen finite sealed-page custody subjects after exact full lease qualification.

Original native0..4 captures are retained references, not newly executed subjects.
This additive cohort grants no interval or release-performance credit.
"""
import argparse,hashlib,importlib.util,json,os,platform,re,shlex,shutil,sys
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
from page_selected_tf_same_page import ENV as SUBJECT_ENV,BOUNDS as LEASE_BOUNDS
from page_default_ls_release_performance import qualified,decode,HARDWARE_KEYS
BOUNDS={'metadata':PROFILES['metadata'],'inspect':PROFILES['inspect'],
        'custody_build':[30,512<<20,16<<20,60],'custody':[5,512<<20,16<<20,15]}
VIEWS=('ordinary','warm','stack','overlap')
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(v):return H(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
def cases():
 return [('ordinary',c,'gated',0 if c<5 else 125)for c in range(10)]+[('stack',0,'native',0),('stack',0,'gated',0)]+[('warm',c,'gated',125)for c in range(6,10)]+[('overlap',5,'gated',125)]
def case_name(kind,case,lane):return 'custody-'+kind+'-'+str(case)+'-'+lane

def inventory():
 result=[('source-paths','metadata'),('custody-gdb-version','metadata'),('custody-objdump-version','metadata')]
 for kind in VIEWS:
  result += [('custody-'+kind+'-'+suffix,profile)for suffix,profile in
             (('headers','metadata'),('link','custody_build'),('undefined','inspect'),('symbols','inspect'),('memset','inspect'),('layout','metadata'))]
 for kind in('stack','overlap'):
  result += [('custody-program-'+kind+'-'+suffix,profile)for suffix,profile in
             (('headers','metadata'),('link','custody_build'),('undefined','inspect'),('symbols','inspect'))]
  if kind=='stack':result.append(('custody-program-stack-layout','metadata'))
 for kind,case,lane,_ in cases():
  name=case_name(kind,case,lane)
  if lane=='gated':result.append((name+'-make','metadata'))
  result.append((name,'custody'))
 need(len(result)==69 and len({n for n,_ in result})==69,'fixed sixty-nine commands, no additional subjects')
 return result

def summary(r):
 plan=cases();attempts=r['cases'];accepted=[]
 need(len(attempts)<=17 and [(c['kind'],c['index'],c['lane'],c['expected_exit'])for c in attempts]==plan[:len(attempts)],'exact attempted seventeen-subject prefix')
 for c in attempts:
  if c['status']!='passed':continue
  rows=[x for x in r['commands']if x['name']==c['name']and x['profile']=='custody']
  need(len(rows)==1,'one actual command for each accepted finite outcome');row=rows[0]
  need(type(row.get('pid'))is int and row['pid']>0 and row.get('reaped')is True and type(row.get('exit'))is int and
       row.get('timed_out')is False and not row.get('cleanup_errors')and not row.get('error')and
       c['pid']==row['pid']and c['exit']==row['exit']==c['expected_exit']and
       c['operation_status']==('completed'if c['exit']==0 else'failed'),
       'actual reaped outcome and failed effect labels retained')
  need(c['comparison']['accepted']is True,'complete original or explicit custody reader accepted actual record');accepted.append(c)
 complete=r['status']=='passed'
 if complete:
  need(len(accepted)==17 and len(r['native_references'])==5 and
       [x['index']for x in r['native_references']]==list(range(5))and
       all(type(x['pid'])is int and x['pid']>0 and x['exit']==0 for x in r['native_references'])and
       len(r['pairs'])==6 and all(x['comparison']['successful_pair']==1 for x in r['pairs'])and
       len(r['builds'])==4 and all(x['status']=='passed'for x in r['builds'])and
       len(r['programs'])==2 and all(x['status']=='passed'for x in r['programs'])and
       [(x['name'],x['profile'])for x in r['commands']]==inventory()and r['source_unchanged']and not r['error']and not r['final_errors'],
       'complete fixed cohort/builds/full pairs and final source custody')
 captures=[(c['name'],k,v)for c in r['commands']for k,v in c.get('captures',{}).items()]
 outcomes=[]
 for c in attempts:
  v={k:c.get(k)for k in('kind','index','lane','status','operation_status','pid','exit','expected_exit','reaped','timed_out')}
  if c['status']=='passed':
   result=c['comparison'];v['events']=result.get('events',result.get('frames',0));v['transfers']=result.get('transfers',0);v['real_closes']=result.get('real_closes',0)
   if 'custody'in result:v['custody']={k:result['custody'][k]for k in('fresh_stages','retained_stages','retained_checks','commits','events')}
  outcomes.append(v)
 value=dict(schema=1,profile=r['profile'],revision=r['expected_revision'],status=r['status'],
  prerequisite=r.get('qualification',{}).get('receipt'),hardware={k:r['hardware'][k]for k in HARDWARE_KEYS},reserved_cpu_count=1,bounds=BOUNDS,
  planned_subjects=17,attempted_subjects=len(attempts),actual_subjects=sum(type(c.get('pid'))is int and c['pid']>0 for c in attempts),
  reaped_subjects=sum(c.get('reaped')is True for c in attempts),qualified_outcomes=len(accepted),
  successful_operations=sum(c['exit']==0 for c in accepted),required_failed_operations=sum(c['exit']==125 for c in accepted),
  retained_native_references=len(r.get('native_references',[])),accepted_pairs=sum(x['comparison'].get('successful_pair')==1 for x in r['pairs']),
  outcomes=outcomes,commands=len(r['commands']),command_rows_sha256=digest(r['commands']),capture_count=len(captures),
  capture_bytes=sum(v.get('bytes',0)for _,_,v in captures),capture_manifest_sha256=digest(captures),inputs_sha256=digest(r.get('inputs',{})),
  artifacts_sha256=digest(r.get('artifacts',{})),source_unchanged=r['source_unchanged'],finite_qualification=complete,
  interval_qualification=False,performance_credit=False,full_b2_complete=False,full_b3_complete=False,
  error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),reproduce=r['reproduce'],
  scope='Same-revision original148 plus6/49/17 prerequisite. Ten original gated subjects with five retained actual native references, one new native/gated stack-growth pair, four later-transfer failure controls and one warm publication-overlap refusal. No new original native children or timing credit.')
 text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
 need(len(text.encode())<64<<10 and not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded numeric public projection without private paths')
 return value

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--expect-revision',required=True);ap.add_argument('--qualification-receipt',type=Path,required=True)
 ap.add_argument('--qualification-sha256',required=True);ap.add_argument('--output',type=Path,required=True)
 a=ap.parse_args();os.chdir(ROOT)
 need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',a.expect_revision)and re.fullmatch('[0-9a-f]{64}',a.qualification_sha256)and len(os.sched_getaffinity(0))==1,
      'exact revision/receipt hash, assertions and one reserved CPU')
 need(BOUNDS['custody']==LEASE_BOUNDS['tf_same_page']and BOUNDS['custody_build']==LEASE_BOUNDS['tf_same_page_build'],'unchanged original subject/build limits')
 private=a.output.resolve();need(private.is_relative_to(ROOT/'target')and not private.exists(),'fresh private output');private.mkdir(parents=True,mode=0o700)
 cpu=next(iter(os.sched_getaffinity(0)));selected=ROOT/'tools/page-entry/selected';fixture=selected/'tests/page_custody'
 r=dict(schema=1,profile='page-selected-tf-sealed-custody-v1',expected_revision=a.expect_revision,source=None,source_unchanged=False,
        hardware=hardware(cpu),bounds=BOUNDS,status='failed',error=None,final_errors=[],commands=[],cases=[],pairs=[],builds=[],programs=[],generated={},native_references=[])
 r['reproduce']=['python3','-B','evaluation/inprocess/page_selected_tf_custody.py','--expect-revision',a.expect_revision,
  '--qualification-receipt','${SAME_REVISION_FULL_LEASE_RECEIPT}','--qualification-sha256',a.qualification_sha256,'--output','${FRESH_PRIVATE_OUTPUT}']
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
 def partial(path):
  try:return retain(path)
  except BaseException as exc:
   r['final_errors'].append('partial artifact '+str(path)+': '+type(exc).__name__+': '+str(exc));return None
 def closure():
  if 'prerequisite_configuration'in r:
   v=r['prerequisite_configuration'];need(admission.cargo_configuration(v['environment'])==v['cargo_configuration'],'qualified Build configuration unchanged')
  need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in r.get('qualified_namespace_aliases',{}).items()),'qualified namespace links unchanged')
  need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in namespace_links.items()),'new namespace links unchanged')
  need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
  need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'all input aliases unchanged')
  need(all(fact(p)==v for p,v in pins.items()),'all actual source/tool/input bytes unchanged')
  need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all actual retained artifacts unchanged')
 def start(name,argv,profile,env,expected=0):
  closure();i=len(r['commands']);need(i<len(inventory()) and(name,profile)==inventory()[i],'exact fixed custody command prefix')
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
  tools,prior_unobserved=qualified(a.qualification_receipt,a.qualification_sha256,r['source'],pin,binary,r,lease_mode=True)
  r['prerequisite_receipt']=dict(path=str(pin(a.qualification_receipt)),**fact(a.qualification_receipt))
  r['prerequisite_unobserved_bridge']=dict(path=str(prior_unobserved),**fact(prior_unobserved))
  prerequisite=decode(pin(a.qualification_receipt).read_bytes());prior=a.qualification_receipt.resolve().parent;old_state=prerequisite['tf_same_page_fixture']
  need(prerequisite['hardware']['probe_cpu']==cpu and prerequisite['hardware']['affinity_cpu_count']==1,'same reserved CPU for retained actual native references')
  archive=pin(prerequisite['build']['artifacts']['decoder.a']['path']);builder=SimpleNamespace(tools=tools,environment=r['prerequisite_configuration']['environment'])
  r['archive']=dict(path=str(archive),**fact(archive));need(pin(sys.executable)==tools['python'],'exact qualified Python tool')
  gd=old_state['tools']['gdb'];tools['gdb']=pin(gd['path']);need(fact(tools['gdb'])=={k:gd[k]for k in('bytes','sha256')},'exact qualified actual-DWARF tool')
  r['tools']={k:dict(path=str(p),**fact(p))for k,p in tools.items()}
  prepare=load('page_custody_prepare',fixture/'prepare.py');check=load('page_custody_check',fixture/'check.py')
  old_check=load('page_custody_old_lease_check',selected/'tests/tf_same_page/check.py')
  stack_check=load('page_custody_stack_check',selected/'tests/page_custody_stack/check.py')
  overlap_check=load('page_custody_overlap_check',selected/'tests/page_custody_overlap/check.py')
  namespace=load('page_custody_namespace',ROOT/'tools/page-entry/namespace.py')
  policy=load('page_custody_policy',selected/'tests/oneshot_integrated/check.py')
  for name in('record.h','observe.inc','layout.py'):pin(fixture/name)
  for directory,names in((selected/'tests/page_custody_stack',('fixture.S','native_reference.c','record.h','stack.c','linker.ld','build.sh','layout.py')),
                        (selected/'tests/page_custody_overlap',('fixture.S','build.sh'))):
   for name in names:pin(directory/name)
  for module in tuple(sys.modules.values()):
   path=getattr(module,'__file__',None)
   if path and Path(path).resolve().is_relative_to(ROOT)and Path(path).suffix=='.py':pin(path)
  for path in('/etc/ld.so.cache','/etc/ld.so.preload'):
   presence[path]=os.path.lexists(path)
   if presence[path]:pin(path)
  need(not presence['/etc/ld.so.preload'],'no global preload')
  output=private/'custody';output.mkdir();cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
  for name in('gdb','objdump'):
   _,out,err=run('custody-'+name+'-version',[tools[name],'--version'],env=gdb_env if name=='gdb'else builder.environment)
   need(out and not err,'actual inspection tool version '+name)
  def inspect(name,path,record=None,layout_path=None,bridge=False,symbol=None):
   binary(path)
   if bridge:bridge_check(path)
   _,out,err=run(name+'-undefined',[tools['nm'],'-u',path],profile='inspect',env=builder.environment);need(out==err==b'','no unresolved actual ELF imports')
   _,symbols,err=run(name+'-symbols',[tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment);need(not err,'actual defined ELF symbols')
   result=dict(path=str(path),**fact(path))
   if bridge:
    _,assembly,err=run(name+'-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],profile='inspect',env=builder.environment)
    need(not err,'complete actual reset assembly');result['reset']=hidden_memset(path,body_check(path,symbols,assembly,'fast',symbol_name='memset'))
   if record:
    need(layout_path is not None,'explicit actual layout source')
    _,out,err=run(name+'-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
     '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(path),'-x',pin(layout_path)],env=gdb_env)
    need(not err,'actual file-only DWARF');layout=decode(out);result['layout']=layout
    rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[(symbol or record).encode()]];_,_,ph=elf(path)
    need(layout['record']==record and len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b'and
     0<int(rows[0][1],16)==layout['types'][record]['bytes']<16<<20 and
     sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+int(rows[0][1],16)<=p[3]+p[6]for p in ph)==1,
     'complete actual native or gated record in one writable NX load')
   return result
  recipe_path=pin(selected/'build-tf-sealed-custody.sh');argv=commands(recipe_path,builder,output,archive,pin)[0]
  units=[str(selected.parent/p)for p in UNITS[:-1]]
  macros=(MACROS-{'-DLI2_ONESHOT_PUBLICATION=1'})|{'-DLI2_CPUID_NX_ONLY=1','-DLI2_RSEQ_NATIVE=1','-DLI2_RSEQ_NATIVE_BOUNDARY=1','-DLI2_RSEQ_TCGETS_BTRFS=1','-DLI2_RSEQ_TIOCGWINSZ_BTRFS=1','-DLI2_TF_SAME_PAGE_LEASE=1','-DLI2_TF_SEALED_CUSTODY=1'}
  need([x for x in argv if x.endswith(('.c','.S'))]==units and len(units)==15 and
       set(x for x in argv if x.startswith('-DLI2_'))==macros and sum(x.startswith('-DLI2_')for x in argv)==len(macros)==14 and
       argv[-2:]==['-o',str(output/'bridge-tf-sealed-custody.so')]and
       all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
       'exact fifteen-unit release recipe plus only explicit custody macro')
  generated_names=(*prepare.FILES,'tf_lease_observe.inc','tf_lease_record.h','tf_lease_old_record.h','tf_lease_types.h','page_custody_record.h','page_custody_observe.inc','page_custody_config.h')
  need(len(prepare.FILES)==8 and len(generated_names)==15,'complete fixed generated observer view')
  bridges={}
  for kind in VIEWS:
   observed=output/(kind+'-view');config=dict(stack=kind=='stack',fault_event=int(kind=='warm'),overlap=kind=='overlap')
   build=dict(name='custody-'+kind,kind=kind,selector=config,recipe=fact(recipe_path),archive=fact(archive),translation_units=15,status='failed');r['builds'].append(build)
   try:build['adapters']=prepare.prepare(ROOT,observed,pin,**config)
   finally:
    build['generated']={name:partial(observed/name)for name in generated_names};r['generated'][kind]=build['generated']
   need((observed/'page_custody_config.h').read_bytes()==prepare.config(**config),'actual exact finite bridge selector')
   actual=argv.copy();bridge=output/(kind+'.so');actual[-1]=str(bridge);sources=units.copy()
   for basename in('runtime_loader.c','lifecycle_loader.c'):
    old,new=str(selected/basename),str(observed/basename);need(actual.count(old)==1,'one exact observation TU replacement')
    actual=[new if x==old else x for x in actual];sources=[new if x==old else x for x in sources]
   build['argv']=actual
   headers(build['name']+'-headers',actual,sources,archive,builder,pin,aliases,run,build)
   need({str(observed/n)for n in generated_names}<=set(build['headers']),'all actual generated runtime/outer-wrapper/config includes')
   try:run(build['name']+'-link',actual,profile='custody_build',env=builder.environment)
   finally:build['artifact']=partial(bridge)
   build['inspection']=inspect(build['name'],bridge,'cso_stream',fixture/'layout.py',True);build['status']='passed'
   bridges[kind]=(bridge,build['inspection']['layout'])
  interpreter=pin(binary(prior/'tf-same-page/interpreter/li2-provider-entry.so'));metadata=pin(binary(prior/'tf-same-page/interpreter/metadata.S'))
  need(fact(interpreter)==old_state['generated'][interpreter.name]and fact(metadata)==old_state['generated'][metadata.name],
       'exact retained qualified interpreter and metadata; no emitter or new native reference')
  r['interpreter']=dict(path=str(interpreter),**fact(interpreter));r['metadata']=dict(path=str(metadata),**fact(metadata))
  originals={};references={};prior_commands={c['name']:c for c in prerequisite['commands']}
  need(len(old_state['programs'])==10 and [x['index']for x in old_state['programs']]==list(range(10)),'all ten original qualified ELF sources')
  for program in old_state['programs']:
   case=program['index'];original=pin(binary(program['inspection']['path']));image=old_check.elf(original.read_bytes(),interpreter,case,policy.native_policy)
   need(program['status']=='passed'and program['image']==image and fact(original)==program['artifact']=={k:program['inspection'][k]for k in('bytes','sha256')},'exact original qualified ELF/geometry/full literal source')
   originals[case]=dict(path=original,image=image,layout=program['inspection']['layout'])
   if case<5:
    found=[x for x in old_state['cases']if x['index']==case and x['lane']=='native'];need(len(found)==1,'one exact retained real native reference');ref=found[0];cmd=prior_commands[ref['name']]
    need(ref['status']=='passed'and ref['operation_status']=='completed'and ref['exit']==cmd['exit']==0 and ref['pid']==cmd['pid']and ref['captures']==cmd['captures'],'actual prior native process and outcome')
    raw={}
    for stream in('stdout','stderr','record'):
     v=cmd['captures'][stream];path=pin(binary(prior/v['file']));need(v['file']==ref['name']+'.'+stream and fact(path)=={k:v[k]for k in('bytes','sha256')},'exact actual retained native capture')
     raw[stream]=path.read_bytes()
    need(not raw['stderr']and decode(json.dumps(old_check.native(raw['record'],program['inspection']['layout'],image,ref['pid'],0),allow_nan=False).encode())==ref['comparison'],'unchanged full actual retained native reader in its exact saved JSON representation')
    need(all(x==cpu for x in ref['comparison']['observed_cpus']),'retained native CPUs join actual reserved CPU')
    references[case]=dict(row=ref,record=raw['record'],stdout=raw['stdout'],layout=program['inspection']['layout'])
    r['native_references'].append(dict(index=case,pid=ref['pid'],exit=0,source_receipt=fact(a.qualification_receipt),command=ref['name'],captures=cmd['captures']))
  carrier_tool=pin(ROOT/'tools/page-entry/carrier.py');launch_tool=pin(selected/'tests/rseq_native/launch.py');programs={}
  for kind in('stack','overlap'):
   leaf=selected/('tests/page_custody_'+kind);name='custody-program-'+kind;directory=output/name;directory.mkdir();original=directory/'original'
   recipe_path=pin(leaf/'build.sh');templates=recipe(recipe_path,'"$cc_bin"');need(len(templates)==1,'one exact additive fixture link recipe')
   case=0 if kind=='stack'else 5
   values={'$cc_bin':tools['cc'],'$fixture_dir':leaf,'$donor_dir':selected/'tests/tf_same_page','$metadata':metadata,'$output':original,'$case_number':case}
   actual=expand(templates[0],values)
   units=[str(leaf/'fixture.S'),str(leaf/'native_reference.c'),str(leaf/'stack.c'),str(metadata)]if kind=='stack'else[str(leaf/'fixture.S'),str(selected/'tests/tf_same_page/native_reference.c'),str(metadata)]
   need([x for x in actual if x.endswith(('.c','.S'))]==units and actual[-2:]==['-o',str(original)]and actual.count('-DRN_CASE='+str(case))==1 and
        all(x in actual for x in('-O2','-g','-Werror','-nostdlib','-no-pie','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-mcmodel=large')),'exact fixed literal fixture recipe, no execution mode substitution')
   row=dict(kind=kind,index=case,path=str(original),recipe=fact(recipe_path),argv=actual,status='failed');r['programs'].append(row)
   flags=[x for x in actual[1:-2]if x not in units and not x.startswith('-Wl,')]
   _,out,err=run(name+'-headers',[tools['cc'],*flags,'-M','-MT','page_custody',*units],env=builder.environment)
   rules=out.decode().replace('\\\n',' ').splitlines();need(not err and len(rules)==len(units)and all(x.startswith('page_custody: ')for x in rules),'complete actual fixture compiler include closure')
   row['headers']={str(pin(t)):fact(pin(t))for line in rules for t in shlex.split(line.split(':',1)[1])};need(set(units)<=set(row['headers']),'all linked fixture sources in actual closure')
   try:run(name+'-link',actual,profile='custody_build',env=builder.environment)
   finally:row['artifact']=partial(original)
   pin(binary(original));row['inspection']=inspect(name,original,'pcs_native_record'if kind=='stack'else None,leaf/'layout.py'if kind=='stack'else None,symbol='lso_native_record'if kind=='stack'else None)
   image=(stack_check if kind=='stack'else overlap_check).elf(original.read_bytes(),interpreter,case,policy.native_policy)
   row['image']=image;row['status']='passed';programs[kind]=dict(path=original,image=image,layout=row['inspection'].get('layout'))
  def execute(kind,case,lane,expected_exit):
   native=lane=='native';program=originals[case]if kind in('ordinary','warm')else programs[kind]
   original,image,native_layout=program['path'],program['image'],program['layout']
   gated_bridge,gated_layout=bridges[kind];name=case_name(kind,case,lane);directory=output/name;directory.mkdir()
   row=dict(name=name,kind=kind,index=case,lane=lane,status='failed',operation_status='unobserved',expected_exit=expected_exit,error=None);r['cases'].append(row)
   objects,description=namespace.plan(original,[interpreter.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
   row['namespace_plan']=description;row['dependencies']=[]
   for item in objects:
    need(fact(pin(item['path']))['sha256']==H(item['bytes']),'complete actual namespace dependency source')
    row['dependencies'].append(dict(names=item['names'],**fact(pin(item['path']))))
    for alias in item['names']:pin(interpreter.parent/alias)
   prep=directory/'preparation.json';ns=directory/'namespace';carrier=directory/'carrier'
   argv=[tools['python'],launch_tool,'--mode','native'if native else'gated','--original',original,'--library-root',interpreter.parent,
    '--preparation',prep,'--record-fd','{record_fd}']
   if not native:
    try:
     _,out,err=run(name+'-make',[tools['python'],carrier_tool,'make',original,gated_bridge,carrier],env=SUBJECT_ENV)
     need(not err,'actual carrier construction stderr')
    finally:partial(carrier)
    binary(carrier);made=decode(out)
    need(made['original_sha256']==fact(original)['sha256']and made['bridge_sha256']==fact(gated_bridge)['sha256']and
         made['interpreter_sha256']==fact(interpreter)['sha256']and made['carrier_sha256']==fact(carrier)['sha256'],'actual same-original carrier identities')
    row['carrier']=made;row['backing']=fact(carrier);argv+=['--carrier',carrier,'--namespace',ns]
   row['invocation_attempted']=True
   try:command,out,err=run(name,argv,profile='custody',expected=None,env=SUBJECT_ENV,record=True)
   except BaseException as exc:
    row['error']=type(exc).__name__+': '+str(exc);raise
   finally:
    for path in(prep,private/(name+'.record'),ns/'namespace.json',ns/'launch.json'):partial(path)
    actual=[c for c in r['commands']if c['name']==name]
    if actual:row.update({k:actual[-1][k]for k in('exit','pid','captures','reaped','timed_out')if k in actual[-1]})
   need(type(command['exit'])is int and command['exit']==expected_exit and type(command['pid'])is int and command['pid']>0 and
        command['reaped']is True and not command['timed_out']and not command['error']and not command['cleanup_errors']and
        command['descriptors']==[dict(name='record',fd=3,closed=True)],'actual exact subject outcome and closed FD3')
   record_path=pin(binary(private/(name+'.record')));record=record_path.read_bytes()
   actual=decode(pin(binary(prep)).read_bytes());row['preparation']=actual;app_argv=[str(original)]+(['native']if native else[])
   need(actual['mode']==('native'if native else'gated')and actual['mask']==0 and actual['affinity']==[cpu]and
        [x['signal']for x in actual['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
        all(x['after']==0 for x in actual['dispositions'])and actual['argv']==app_argv and
        actual['environment']=={k:v for k,v in SUBJECT_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
        actual['observer']==dict(fd=3,device=record_path.stat().st_dev,inode=record_path.stat().st_ino),
        'actual reset signals/mask, same CPU, exact argv/environment and observed FD identity')
   if not native:
    sealed=decode(pin(binary(ns/'namespace.json')).read_bytes());started=decode(pin(binary(ns/'launch.json')).read_bytes())
    need(sealed['original']==str(original)and sealed['original_sha256']==fact(original)['sha256']and
         sealed['interpreter_sha256']==fact(interpreter)['sha256']and len(sealed['objects'])==len(objects),'actual complete original namespace')
    for got,item in zip(sealed['objects'],objects):
     need(got['names']==item['names']and got['sha256']==H(item['bytes'])and got['size']==len(item['bytes'])and
          got['seals']==namespace.SEALS and got['device']>0 and got['inode']>0,'actual immutable complete dependency object')
     for alias in got['names']:
      path=ns/alias;value='/proc/self/fd/'+str(got['fd']);need(path.is_symlink()and os.readlink(path)==value,'actual retained namespace alias');namespace_links[str(path)]=value
    env={k:v for k,v in SUBJECT_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'};env.update(LD_LIBRARY_PATH=str(ns),LD_BIND_NOW='1',LI2_DEPENDENCY_FDS=','.join(str(x['fd'])for x in sealed['objects']))
    need(started['argv']==app_argv and started['environment']==env and
         {k:started[v]for k,v in(('bytes','carrier_size'),('sha256','carrier_sha256'))}==fact(carrier)==row['backing'],
         'actual default-rseq launch and exact sealed carrier identity/extent, no configured policy')
    row['namespace']=dict(manifest=fact(ns/'namespace.json'),launch=fact(ns/'launch.json'));actual_image=dict(image,backing=row['backing'])
    context=None
    if kind=='stack':
     row['output']=stack_check.output(out,native_layout,image,command['pid'],False,cpu);context=row['output']['context']
    result=check.gated(record,gated_layout,actual_image,command['pid'],command['exit'],cpu,
                       fault_event=int(kind=='warm'),stack_context=context,overlap=kind=='overlap')
    need(result['accepted']is True and result['case']==case and result['exit_status']==expected_exit,'explicit actual custody record/selector/outcome')
    parsed=check.reports_join(err,record,gated_layout,actual_image,command['pid'],result);row['reports']=parsed
    need(parsed['loader']['status']==command['exit'],'actual report and process outcome agree')
    cpuid=parsed['cpuid_nx']
    need(cpuid['attempts']==cpuid['samples']==cpuid['commits']==parsed['loader']['cpuid']>0 and cpuid['raw']==cpuid['result']and
         cpuid['phase']==3 and cpuid['hardware_entered']==cpuid['hardware_returned']==1,'genuine raw first-interpreter CPUID completed before the finite case')
    if command['exit']==0:
     need(parsed['rseq_native']['admissions']>0 and parsed['rseq_boundary']['counts']==[0]*6,'actual registered epochs and no invented native-boundary retry')
    else:need(result['operation_status']=='failed'and out==b'','required failed effect remains failed without completed output')
    stdout_path=pin(binary(private/(name+'.stdout')));launch=parsed['tcgets']['launch'];st=stdout_path.stat()
    need(launch[:2]==[st.st_dev,st.st_ino]and launch[5]&0o170000==0o100000,'actual parent-created stdout identity joins production initialization')
    row['comparison']=result
   else:
    need(kind=='stack'and case==0 and not err,'only the actual new stack native reference, empty stderr')
    row['output']=stack_check.output(out,native_layout,image,command['pid'],True,cpu)
    result=stack_check.native(record,native_layout,image,command['pid'],command['exit'],row['output']['context'],cpu)
    need(result['accepted']is True and result['exit_status']==0 and result['observed_cpu']==cpu,'complete actual native stack output and four endpoints')
    row['comparison']=result
   if not native:need(all(x==cpu for x in result['observed_cpus']),'actual case CPUs join independent reserved affinity')
   if kind in('ordinary','warm')and case in(8,9):need(result['nested_sender_uid']==os.getuid(),'actual kernel self-tgkill sender joins invoking UID')
   if expected_exit!=0:need(out==b'','failed finite effect has no completed output')
   row['operation_status']='completed'if expected_exit==0 else'failed';row['status']='passed';return row,out,record
  stack_native=None
  for kind,case,lane,expected_exit in cases():
   row,out,record=execute(kind,case,lane,expected_exit)
   if kind=='ordinary'and case<5:
    ref=references[case];program=originals[case];image=dict(program['image'],backing=row['backing'])
    comparison=check.pair(ref['record'],record,ref['stdout'],out,dict(native=ref['layout'],gated=bridges['ordinary'][1]),image,ref['row']['pid'],row['pid'],cpu)
    need(comparison['successful_pair']==1,'full original native reference and actual new gated pair')
    r['pairs'].append(dict(kind=kind,index=case,native_dependency=True,comparison=comparison))
   elif kind=='stack'and lane=='native':stack_native=(row,out,record)
   elif kind=='stack':
    n,nout,nrecord=stack_native;program=programs['stack'];image=dict(program['image'],backing=row['backing'])
    comparison=check.stack_pair(nrecord,record,nout,out,dict(native=program['layout'],gated=bridges['stack'][1]),image,n['pid'],row['pid'],cpu)
    need(comparison['successful_pair']==1,'actual native/gated stack growth, full four endpoints and two episodes')
    r['pairs'].append(dict(kind=kind,index=0,native_dependency=False,comparison=comparison))
  need(len(r['cases'])==17 and all(c['status']=='passed'for c in r['cases'])and len(r['pairs'])==6 and len(r['native_references'])==5,
       'all seventeen actual subjects, six full pairs, five retained references and ten required failed effects')
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

if __name__=='__main__':raise SystemExit(main())
