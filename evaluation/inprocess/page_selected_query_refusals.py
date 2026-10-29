#!/usr/bin/env python3
"""Five actual registered-rseq readonly-query refusals before effect issue."""
import argparse,hashlib,importlib.util,json,os,platform,re,shlex,shutil,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_selected import ENV,fact,need,save,elf,interpreter
from checks import source
from run import hardware
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_oneshot_build import before_default,commands
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_register_time_compare import decode
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
from page_selected_effect_ls_reports import trace_prefix,trace_closed_counts
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/effect_provider'
BOUNDS={'query_build':[30,512<<20,16<<20,60],'query':[30,512<<20,16<<20,60]}
QUERY_ENV=dict(ENV,LD_BIND_NOW='1')
CASES=((1,158,8),(2,158,8),(3,14,8),(4,309,4),(5,309,4))
UNITS=('bridge.c','selected/runtime_loader.c','selected/lifecycle_loader.c','selected/entry.S',
    'selected/selected_effect.c','selected/selected_effect_native.c','selected/oneshot.c','selected/provider.c',
    'selected/step_owner.c','selected/selected_selftest.S','selected/support.c','selected/register_run_plan.c',
    'selected/register_run_owner.c','selected/register_run_publish.c','selected/register_run_reset.c',
    'selected/rseq_guard.c','selected/native_policy.c','selected/native_epoch.c')
MACROS=('EFFECT_PROVIDER','ONESHOT_REUSABLE','ONESHOT_PUBLICATION','TF_SEALED_CUSTODY','TF_SAME_PAGE_LEASE',
    'TF_HANDOFF','REGISTER_RUN','MAPS_PHASE_REUSE','RSEQ_INACTIVE','NATIVE_PAGES','CPUID_NX_ONLY',
    'RSEQ_NATIVE','RSEQ_NATIVE_BOUNDARY','RSEQ_TCGETS_BTRFS','RSEQ_TIOCGWINSZ_BTRFS','FAST_MEMSET','FAST_EQUAL')
REPORTS=('LOADER','NATIVE','SELECTED_EFFECT','CPUID_NX','ONESHOT','RSEQ','RSEQ_NATIVE','RSEQ_BOUNDARY',
         'RSEQ_BTRFS_TTY_QUERY','CHAIN','RUN','TRACE_RUN')
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())

def refusal(case,row,out,err):
    """Actual reports only; last[0:3] is historical instruction metadata."""
    index,number,width=case;reports={}
    need(type(row.get('pid'))is int and row['pid']>0 and type(row.get('exit'))is int and row['exit']==125 and
         row.get('reaped')is True and row.get('timed_out')is False and not row.get('error')and
         row.get('cleanup_errors')==[] and out==b'','closed required exit125 with no stdout')
    need(type(err)is bytes and 0<len(err)<=16<<20 and err.endswith(b'\n'),'bounded complete stderr reports')
    for line in err.splitlines():
        key,space,value=line.partition(b' ')
        need(space and key.startswith(b'LI2_')and key.decode('ascii')not in reports,'one structured row per report')
        reports[key.decode('ascii')]=decode(value)
    # runtime_loader.c emits REPEAT iff an actual repeat attempt occurred.
    # Its terminal is retained too; this control does not qualify repeat state.
    need(set(reports)-{'LI2_REPEAT'}=={'LI2_'+x for x in REPORTS},'complete effect-profile terminal reports')
    def exact(obj,key,value):
        need(type(obj.get(key))is type(value)and obj[key]==value,'exact typed report field '+key)
    def array(obj,key,count):
        value=obj.get(key);need(type(value)is list and len(value)==count and
            all(type(x)is int and 0<=x<1<<64 for x in value),'typed complete report array '+key);return value
    for report in reports.values():
        need(type(report)is dict,'terminal report object')
        exact(report,'status',125);exact(report,'failure_code',1205)
        for key in('detail_abs','detail_negative'):
            if key in report:exact(report,key,0)
    if 'LI2_REPEAT'in reports:
        repeat=reports['LI2_REPEAT'];exact(repeat,'version',1)
        need(type(repeat.get('attempts'))is int and repeat['attempts']>0,'repeat report only after an actual attempt')
    loader,rseq,effect=(reports['LI2_'+x]for x in('LOADER','RSEQ','SELECTED_EFFECT'))
    trace=reports['LI2_TRACE_RUN']
    trace_prefix(trace,reports['LI2_RUN'],reports['LI2_CHAIN'],loader)
    trace_summary=trace_closed_counts(trace)
    exact(loader,'version',1);exact(loader,'detail_abs',0);exact(loader,'detail_negative',0)
    exact(loader,'last_syscall',number);exact(loader,'rseq',1)
    exact(rseq,'version',1);exact(rseq,'scope','registered_inactive_prototype');exact(rseq,'maps_profile',1)
    owner=array(rseq,'owner',14);last=array(rseq,'last',5);tls=array(rseq,'tls',8)
    counts=array(rseq,'counts',9);transaction=array(rseq,'transaction',8);args=array(rseq,'args',6)
    address=owner[9]
    need(owner[:7]==[1,1,1,3,1205,0,0] and owner[7:9]==[row['pid'],row['pid']]and
         0<address<=(1<<64)-33 and address%32==0 and owner[10]==address&~4095 and
         owner[11:]==[32,0x53053053,1],'actual registered held owner/PID/area identity')
    need(tls[:6]==[1,1,0,0,0,0] and tls[6]>0 and counts[:4]==[1,1,0,0] and
         transaction==[1,1,1,0,0,0,1,0] and args[:4]==[address,32,0,0x53053053],
         'completed actual registration transaction and zero word, not supplied owner state')
    need(last[3:5]==[address+8,address+8+width],'exact actual query write overlaps registered word')
    exact(effect,'version',1);exact(effect,'scope','linked_full_input_effect')
    for key,value in dict(first_error=0,stage=2,busy=1,finished=0,kind=7,action=1,phase=2,error=0,
            native_entered=0,native_returned=0,raw_entered=0,raw_returned=0,committed=0,
            callback_entered=0,callback_returned=0,exit_entered=0,post_guards_complete=0,
            post_callback_entered=0,post_callback_returned=0,random_backend_returned=0,
            random_backend_status=0,fp_after_initialized=0).items():exact(effect,key,value)
    return dict(case=index,syscall=number,kind=7,write_bytes=width,exit=125,error=1205,detail=0,
        stdout_bytes=0,registered_word_joined=True,native_entered=0,raw_entered=0,raw_returned=0,
        accepted=True,trace_run=trace_summary,reports_sha256=digest(reports))

def finalize(r):
    for path,value in r.get('namespace_aliases',{}).items():
        need(Path(path).is_symlink()and os.readlink(path)==value,'actual sealed namespace aliases unchanged')

def cohort(builder,products,private,pin,binary,aliases,run,r):
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    output=private/'query';output.mkdir();bridge_recipe=pin(SELECTED/'build-effect-provider.sh')
    argv=commands(bridge_recipe,builder,output,archive,pin)[0];units=[str(SELECTED.parent/x)for x in UNITS]
    need([x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact unobserved18-TU17-macro release effect-provider recipe')
    state=r['query_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv)
    headers('query-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    bridge=Path(argv[-1]);run('query-bridge-link',argv,profile='query_build',env=builder.environment)
    state['bridge']=fact(binary(bridge));state['elf']=bridge_check(bridge)
    _,out,err=run('query-bridge-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(out==err==b'','actual effect bridge has no unresolved imports')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('query-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump identity')
    _,symbols,err=run('query-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset symbol inspection')
    _,assembly,err=run('query-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset disassembly');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    fixture_recipe=pin(FIXTURE/'build-query-refusal.sh');rows=recipe(fixture_recipe,'"$cc_bin"')
    need(len(rows)==1,'one exact query fixture compiler recipe')
    original=output/'query-refusal';src=pin(FIXTURE/'query_refusal.c')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$output':original})
    need(argv==list(map(str,[builder.tools['cc'],'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIE','-pie',
         '-Wl,-z,relro,-z,now,-z,noexecstack',src,'-o',original])),'unchanged real query fixture build flags')
    unit=state['fixture']=dict(recipe=fact(fixture_recipe),argv=argv,source=fact(src),headers={})
    flags=[x for x in argv[1:-2]if x!=str(src)and not x.startswith('-Wl,')]
    _,out,err=run('query-fixture-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_query',src],profile='query_build',env=builder.environment)
    need(not err,'actual query fixture include observation')
    rules=out.decode().replace('\\\n',' ').splitlines();need(len(rules)==1 and rules[0].startswith('li2_query: '),'one complete actual fixture include rule')
    for token in shlex.split(rules[0].split(':',1)[1]):
        p=pin(Path(token).absolute());unit['headers'][str(p)]=fact(p)
    need(str(src)in unit['headers'],'fixture source in actual compiler-M closure')
    run('query-fixture-link',argv,profile='query_build',env=builder.environment);unit['artifact']=fact(binary(original))
    _,head,segments=elf(original)
    need(head[1]==3 and head[2]==62 and any(p[0]==1 and p[1]&1 and p[3]<=head[4]<p[3]+p[6]for p in segments)and
         all(not(p[0]==1 and p[1]&3==3)for p in segments)and original.stat().st_mode&0o111,'actual executable PIE without W/X load')
    interp=pin(interpreter(original));carrier=output/'carrier';carrier_tool=pin(SELECTED.parent/'carrier.py')
    spec=importlib.util.spec_from_file_location('query_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    objects,description=namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    for item in objects:need(fact(pin(item['path']))['sha256']==H(item['bytes']),'all actual dependency sources pinned')
    r['namespace_plan']=description;r['namespace_aliases']={}
    _,out,err=run('query-carrier',[builder.tools['python'],'-B',carrier_tool,'make',original,bridge,carrier],profile='query',env=QUERY_ENV)
    need(not err,'actual carrier construction stderr');binary(carrier);identities=decode(out)
    need(all(identities[k+'_sha256']==fact(p)['sha256']for k,p in
         (('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier))),'actual carrier identities')
    state['carrier']=fact(carrier);state['status']='passed'
    for model in CASES:
        index=model[0];name='query-'+str(index);ns=output/('namespace-'+str(index))
        case=dict(case=index,status='failed',command=name);r['cases'].append(case)
        try:
            row,out,err=run(name,[builder.tools['python'],'-B',carrier_tool,'exec-loader','--library-root','/usr/lib64',
                '--namespace',ns,carrier,original,'--',original,str(index)],profile='query',expected=125,env=QUERY_ENV)
            actual=decode(binary(ns/'namespace.json').read_bytes());launch=decode(binary(ns/'launch.json').read_bytes())
            need(all(actual[k]==v for k,v in description.items())and actual['directory']==str(ns)and
                 actual['schema_version']==1 and actual['status']=='prepared_not_executed'and
                 len(actual['objects'])==len(objects),'actual complete namespace matches independent plan')
            fds=[]
            for obj,item in zip(actual['objects'],objects,strict=True):
                need(type(obj['fd'])is int and obj['fd']>2 and obj['fd']not in fds and
                     obj['source']==str(item['path'])and obj['names']==item['names']and obj['needed']==item['info']['needed']and
                     obj['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and
                     obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and obj['seals']==namespace.SEALS and
                     type(obj['device'])is int and obj['device']>0 and type(obj['inode'])is int and obj['inode']>0,
                     'actual complete sealed dependency identity')
                fds.append(obj['fd'])
                for alias in obj['names']:
                    path=ns/alias;value='/proc/self/fd/'+str(obj['fd'])
                    need(path.is_symlink()and os.readlink(path)==value,'actual sealed dependency alias')
                    r['namespace_aliases'][str(path)]=value
            expected_env={k:v for k,v in QUERY_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
            expected_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)))
            need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
                 carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],argv=[str(original),str(index)],
                 environment=expected_env,dependency_fds=fds),'actual exact launch; default rseq and Native binding')
            case['comparison']=refusal(model,row,out,err);case['status']='passed'
        except BaseException as error:case['error']=type(error).__name__+': '+str(error);raise

def publish(path,r,private):
    commands=r['commands'];captures=[(c['name'],k,v)for c in commands for k,v in c.get('captures',{}).items()]
    hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    value={k:r.get(k)for k in('schema','profile','scope','status','expected_revision','started_utc','source','source_unchanged',
                            'bounds','reproduce','cleanup_complete')}
    value.update(hardware=hw,private_receipt=fact(private/'receipt.json'),commands=len(commands),captures=len(captures),
        command_rows_sha256=digest(commands),capture_manifest_sha256=digest(captures),
        command_outcomes=dict(exited_zero=sum(c.get('exit')==0 for c in commands),
            exited_125=sum(c.get('exit')==125 for c in commands),reaped=sum(c.get('reaped')is True for c in commands),
            timeouts=sum(c.get('timed_out')is True for c in commands),cleanup_errors=sum(len(c.get('cleanup_errors',[]))for c in commands)),
        inputs_sha256=digest(r['inputs_before']),artifacts_sha256=digest(r['artifacts_before']),
        archive=r.get('archive'),build_status=r.get('build',{}).get('status'),
        configuration_unchanged=r.get('build',{}).get('configuration_unchanged',False),
        query_build_status=r.get('query_build',{}).get('status'),planned_subjects=5,
        actual_subjects=sum(type(c.get('pid'))is int for c in commands if c['name']in {'query-'+str(i)for i,_,_ in CASES}),
        accepted_refusals=sum(c['status']=='passed'for c in r['cases']),cases=[dict(case=c['case'],status=c['status'],
            comparison=c.get('comparison'))for c in r['cases']],
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
        full_b2_qualification=False,performance_credit=False,supplied_controls_kernel_registration_credit=False)
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<6144 and not any(x and len(x)>1 and x in text for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public receipt without raw/private paths')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-query-refusals-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS)
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-selected-query-refusals-v1',scope='Five real default-loader query write-overlap refusals before Native or raw issue. Exact registered word spans; no supplied-control kernel-registration, full-B2 or performance credit.',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[],error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_selected_query_refusals.py','--expect-revision',a.expect_revision])
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);f=fact(p)
        need(want is None or f=={k:want[k]for k in('bytes','sha256')},'exact requested input bytes')
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'input alias changed')
        need(str(p)not in pins or pins[str(p)]==f,'input bytes changed')
        aliases[str(alias)]=str(p);pins[str(p)]=f;return p
    def binary(path):
        p=Path(path).resolve(strict=True);f=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==f,'retained artifact changed');artifacts[str(p)]=f;return p
    def stable():
        need(all(Path(p).resolve(strict=True)==Path(v)for p,v in aliases.items()),'all lexical input aliases unchanged')
        need(all(fact(p)==v for p,v in pins.items()),'all input bytes unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all artifact bytes/modes unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
        finalize(r)
    def run(name,argv,profile='metadata',expected=0,env=None,record=False,step=False):
        stable();need(not any(x['name']==name for x in commands),'unique command/capture names')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=bounds[profile],capture_limit=16<<20,
                 environment=dict(ENV if env is None else env),expected_exit=expected);commands.append(row)
        try:
            out,err=invoke(row,private,cpu,record=record,step=step)
            need(type(row['exit'])is int and(expected is None or row['exit']==expected),'actual command exit '+name)
            return row,out,err
        finally:
            for stream in('stdout','stderr','record','preparation'):
                path=private/(name+'.'+stream)
                try:
                    observed=row.get('captures',{}).get(stream)
                    if path.exists()or path.is_symlink():
                        actual=fact(binary(path))
                        if observed is not None:need(observed['file']==path.name and actual=={k:observed[k]for k in('bytes','sha256')},'actual command capture binding')
                    else:need(observed is None,'retained command capture missing')
                except BaseException as error:r['final_errors'].append('capture '+name+'.'+stream+': '+type(error).__name__+': '+str(error))
            path=private/(name+'.json')
            try:
                if path.exists()or path.is_symlink():binary(path);need(digest(json.loads(path.read_bytes()))==digest(row),'actual retained command row')
            except BaseException as error:r['final_errors'].append('command row '+name+': '+type(error).__name__+': '+str(error))
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(r,private,pin,binary,build_run)
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err,'source enumeration stderr')
        for name in out.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT)and Path(p).suffix=='.py':pin(p)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload');r['configuration_presence']=presence
        products=builder.prepare();r['archive']=fact(products['archive'])
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==5 and [c['case']for c in r['cases']]==[x[0]for x in CASES]and
             all(c['status']=='passed'and c['comparison']['accepted']is True for c in r['cases'])and not r['final_errors'],
             'all five exact actual refusals; no substituted/skipped cases')
        r['status']='passed'
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            for m in tuple(sys.modules.values()):
                path=getattr(m,'__file__',None)
                if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        except BaseException as error:r['final_errors'].append('final imported source closure: '+repr(error))
        try:r['final_errors'].extend(builder.finish())
        except BaseException as error:r['final_errors'].append('build finalization: '+type(error).__name__+': '+str(error))
        for p in sorted(private.rglob('*')):
            if p.is_file()and not p.is_symlink():
                try:binary(p)
                except BaseException as error:r['final_errors'].append('retain '+str(p)+': '+type(error).__name__+': '+str(error))
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        for label,fn in(('closure',stable),('namespace',lambda:finalize(r))):
            try:fn()
            except BaseException as error:r['final_errors'].append(label+': '+type(error).__name__+': '+str(error))
        try:r['source_after']=source();need(r['source_after']==r['source'],'exact committed source unchanged')
        except BaseException as error:r['final_errors'].append('source: '+type(error).__name__+': '+str(error))
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in(('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),
                                  ('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as error:r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged']=r['source']is not None and r.get('source_after')==r['source']and r['inputs_before']==r['inputs_after']and r['aliases_before']==r['aliases_after']
        r['cleanup_complete']=all(type(c.get('exit'))is int and c.get('reaped')is True and
            c.get('timed_out')is False and not c.get('error')and c.get('cleanup_errors')==[] and
            all(d['closed']for d in c.get('descriptors',[]))for c in commands)
        if r['error']or r['final_errors']or not r['source_unchanged']or r['artifacts_before']!=r['artifacts_after']or not r['cleanup_complete']:r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),commands=len(commands),
                             failure_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
