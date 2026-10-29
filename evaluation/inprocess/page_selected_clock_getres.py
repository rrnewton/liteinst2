#!/usr/bin/env python3
"""Exact clock_getres kernel outcomes, full-state component and default-rseq application guards."""
import argparse,ctypes,hashlib,importlib.util,json,os,platform,re,resource,select,shlex,shutil,signal,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_selected import ENV,fact,need,save,elf,interpreter
from checks import source
from run import hardware
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke,Action
import page_default_ls_release_provenance as provenance
import page_selected_clock_getres_reports as reports
import page_selected_clock_getres_record as record
from page_selected_repeat_lease_ls import build_bridge
from page_selected_effect_ls import program_invoke,finalize
from page_selected_register_real import resolved_libraries
from page_selected_oneshot_build import before_default,commands
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_register_time_compare import decode
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/clock_getres'
BOUNDS={'release_build':[30,512<<20,16<<20,60],'program':[30,512<<20,16<<20,60],'finite':[5,512<<20,16<<20,15]}
PROGRAM_ENV=dict(ENV,LD_BIND_NOW='1')
UNITS=('bridge.c','selected/runtime_loader.c','selected/lifecycle_loader.c','selected/entry.S',
    'selected/selected_effect.c','selected/selected_effect_native.c','selected/oneshot.c','selected/provider.c',
    'selected/step_owner.c','selected/selected_selftest.S','selected/support.c','selected/register_run_plan.c',
    'selected/register_run_owner.c','selected/register_run_publish.c','selected/register_run_reset.c',
    'selected/rseq_guard.c','selected/native_policy.c','selected/native_epoch.c')
MACROS=('REPEAT_RX_LEASE','RUN_CACHE_REUSE','EFFECT_PROVIDER','ONESHOT_REUSABLE','ONESHOT_PUBLICATION','TF_SEALED_CUSTODY','TF_SAME_PAGE_LEASE',
    'TF_HANDOFF','REGISTER_RUN','MAPS_PHASE_REUSE','RSEQ_INACTIVE','NATIVE_PAGES','CPUID_NX_ONLY',
    'RSEQ_NATIVE','RSEQ_NATIVE_BOUNDARY','RSEQ_TCGETS_BTRFS','RSEQ_TIOCGWINSZ_BTRFS','FAST_MEMSET','FAST_EQUAL')
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())


def fixture_build(builder,private,pin,binary,run,r):
    output=private/'clock-fixture';output.mkdir()
    script=pin(FIXTURE/'build.sh');lines=recipe(script,'"$cc_bin"')
    need(len(lines)==3,'three fixed component/supplied/application compiler recipes')
    specs=(('component',['component.c',str(SELECTED/'tests/provider/xstate.c'),str(SELECTED/'tests/provider/machine.S')]),
           ('controls',['controls.c']),('subject',['subject.c']))
    builds=[]
    for line,(name,sources)in zip(lines,specs,strict=True):
        argv=expand(line,{'$cc_bin':builder.tools['cc'],'$fixture_dir':FIXTURE,
            '$provider_dir':SELECTED/'tests/provider','$output_dir':output})
        units=[str(pin(FIXTURE/p if not Path(p).is_absolute()else p))for p in sources]
        need([x for x in argv if x.endswith(('.c','.S'))]==units and argv[-2:]==['-o',str(output/name)]and
             not any(x.startswith('-D')or x.endswith('.a')for x in argv)and
             all(x in argv for x in('-O2','-g','-Wall','-Wextra','-Werror','-fno-builtin','-mgeneral-regs-only')),
             'actual fixed sources and compiler flags, no substituted oracle or archive')
        state=dict(name=name,argv=argv,recipe=fact(script),headers={});builds.append(state)
        flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
        for i,unit in enumerate(units):
            _,out,err=run('clock-headers-'+name+'-'+str(i),[builder.tools['cc'],*flags,'-M','-MT','li2_clock',unit],profile='release_build',env=builder.environment)
            lines=out.decode().replace('\\\n',' ').splitlines();need(not err and len(lines)==1 and lines[0].startswith('li2_clock: '),'actual complete compiler dependency rule')
            for dependency in shlex.split(lines[0].split(':',1)[1]):state['headers'][dependency]=dict(path=str(pin(dependency)),**fact(dependency))
        if name in('component','controls'):need(str(SELECTED/'rseq_guard.c')in {x['path']for x in state['headers'].values()},'actual guard translation unit included')
        _,out,err=run('clock-build-'+name,argv,profile='release_build',env=builder.environment)
        need(out==err==b'','exact quiet fixture compile/link');state['artifact']=fact(binary(output/name))
        _,h,ph=elf(output/name)
        need(h[1]==(3 if name=='subject'else 2)and h[2]==62 and not any(p[0]==1 and p[1]&3==3 for p in ph),'exact executable ELF type and no W/X load')
        loader=pin(interpreter(output/name));_,listing,err=run('clock-libraries-'+name,[loader,'--list',output/name],env=PROGRAM_ENV)
        need(not err,'actual fixture loader listing')
        expected={loader:set()};namespace=load('clock_fixture_namespace',pin(SELECTED.parent/'namespace.py'))
        objects,_=namespace.plan(output/name,[Path('/usr/lib64')],bytes.fromhex(fact(output/name)['sha256']),bytes.fromhex(fact(loader)['sha256']))
        for obj in objects:expected.setdefault(pin(obj['path']),set()).update(obj['names'])
        resolved_libraries(listing,expected,loader,pin)
    r['fixture_build']=builds;return output


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def namespace_check(ns,original,carrier,description,objects,namespace,argv,binary,r):
    observed=decode(binary(ns/'namespace.json').read_bytes());launch=decode(binary(ns/'launch.json').read_bytes())
    need(all(observed[k]==v for k,v in description.items())and observed['directory']==str(ns)and
         observed['schema_version']==1 and observed['status']=='prepared_not_executed'and len(observed['objects'])==len(objects),
         'actual complete sealed namespace matches independent plan')
    fds=[]
    for obj,item in zip(observed['objects'],objects,strict=True):
        need(type(obj['fd'])is int and obj['fd']>2 and obj['fd']not in fds and obj['source']==str(item['path'])and
             obj['names']==item['names']and obj['needed']==item['info']['needed']and
             obj['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and
             obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and obj['seals']==namespace.SEALS and
             type(obj['device'])is int and obj['device']>0 and type(obj['inode'])is int and obj['inode']>0,
             'actual complete sealed dependency identity')
        fds.append(obj['fd'])
        for alias in obj['names']:
            path=ns/alias;value='/proc/self/fd/'+str(obj['fd'])
            need(path.is_symlink()and os.readlink(path)==value,'actual sealed dependency alias');r['namespace_aliases'][str(path)]=value
    environment={k:v for k,v in PROGRAM_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
    environment.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)))
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
        carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],argv=argv,
        environment=environment,dependency_fds=fds),'exact default-rseq carrier/environment/argv/FD launch')


def cohort(builder,products,private,pin,binary,aliases,run,r):
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r)
    built=fixture_build(builder,private,pin,binary,run,r)
    provider=load('clock_provider_comparator',pin(SELECTED/'tests/provider/compare.py'))
    for mode in range(5):
        case=dict(kind='component',case=mode,status='failed',command='clock-component-'+str(mode));r['cases'].append(case)
        row,out,err=run('clock-component-'+str(mode),[built/'component',str(mode)],profile='finite',record=True,step=True)
        need(out==b'LI2_CLOCK_GETRES_COMPONENT 1\n'and err==b'','actual completed component terminal')
        data=(private/row['captures']['record']['file']).read_bytes()
        case['result']=record.component(data,mode,provider);case['controls']=record.component_controls(data,mode,provider);case['status']='passed'
    case=dict(kind='supplied',case=0,status='failed',command='clock-supplied');r['cases'].append(case)
    row,out,err=run('clock-supplied',[built/'controls'],profile='finite')
    need(out==b'LI2_CLOCK_GETRES_SUPPLIED 20 native_registration=0 kernel_queries=0\n'and err==b'','actual20 supplied controls, no native credit')
    case.update(status='passed',controls=20)
    original=binary(built/'subject');interp=pin(interpreter(original));carrier=private/'clock-carrier'
    namespace=load('clock_namespace',pin(SELECTED.parent/'namespace.py'));carrier_tool=pin(SELECTED.parent/'carrier.py')
    objects,description=namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    r['namespace_plan']=description;r['namespace_aliases']={}
    images=[];image_bytes=[];known={};store=private/'source-inputs';store.mkdir()
    for role,path in [('original',original),('interpreter',interp)]+[('dependency-'+str(i),obj['path'])for i,obj in enumerate(objects)]:
        path=pin(path);data=path.read_bytes();identity=fact(path)
        need(identity==dict(bytes=len(data),sha256=H(data)),'complete stable external ELF')
        if identity['sha256']in known:
            index=known[identity['sha256']];need(data==image_bytes[index],'same complete duplicate image bytes');images[index]['roles'].append(role);continue
        index=len(images);saved=store/(str(index)+'.elf')
        with saved.open('xb')as f:f.write(data)
        need(fact(binary(saved))==identity,'actual retained external ELF copy')
        images.append(dict(identity,roles=[role]));image_bytes.append(data);known[identity['sha256']]=index
    r['external_images']=images
    _,out,err=run('clock-carrier',[builder.tools['python'],'-B',carrier_tool,'make',original,bridge,carrier],profile='program',env=PROGRAM_ENV)
    need(not err,'actual carrier construction');binary(carrier);identity=decode(out)
    need(all(identity[k+'_sha256']==fact(p)['sha256']for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and
         interpreter(carrier)==bridge,'complete actual carrier/bridge/original/interpreter identity')
    carrier_bytes=carrier.read_bytes()
    for mode in range(9):
        native=None
        if mode<5:
            case=dict(kind='native',case=mode,status='failed',command='clock-native-'+str(mode));r['cases'].append(case)
            row,out,err=run('clock-native-'+str(mode),[original,str(mode)],profile='program',env=PROGRAM_ENV)
            need(err==b'','native no report or diagnostic');native=record.application(out,mode,row['pid']);case['status']='passed'
        case=dict(kind='gated'if mode<5 else'refusal',case=mode,status='failed',command='clock-gated-'+str(mode));r['cases'].append(case)
        ns=private/('clock-namespace-'+str(mode));argv=[str(original),str(mode)]
        row,out,err=run('clock-gated-'+str(mode),[builder.tools['python'],'-B',carrier_tool,'exec-loader','--library-root','/usr/lib64',
            '--namespace',ns,carrier,original,'--',*argv],profile='program',expected=0 if mode<5 else 125,env=PROGRAM_ENV)
        namespace_check(ns,original,carrier,description,objects,namespace,argv,binary,r)
        if mode<5:
            actual=record.application(out,mode,row['pid']);case['result']=record.pair(native,actual)
            parsed,summary=reports.completed(err,row['pid'],row['exit'],row['stdout_provenance_before'],images,image_bytes,fact(carrier),carrier_bytes)
            need(parsed['rseq']['owner'][9]==actual['address'],'actual application publication-word address joins actual owner')
            case['terminal']=summary;case['controls']=reports.completed_controls(err,row['pid'],row['exit'],row['stdout_provenance_before'],images,image_bytes,fact(carrier),carrier_bytes)
        else:
            case['result']=reports.refused(err,row,out,mode);case['controls']=reports.refusal_controls(err,row,out,mode)
        case['status']='passed'
    need(len(r['cases'])==20 and all(c['status']=='passed'for c in r['cases'])and
         sum(c['kind']=='component'for c in r['cases'])==5 and sum(c['kind']=='native'for c in r['cases'])==5 and
         sum(c['kind']=='gated'for c in r['cases'])==5 and sum(c['kind']=='refusal'for c in r['cases'])==4,
         'all5 complete pairs,5 whole-program native/gated pairs,4 actual preissue refusals and20 supplied controls')


def publish(path,r,private):
    hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    cases=[]
    for c in r['cases']:
        controls=c.get('controls',0);controls=controls if type(controls)is int else len(controls['refusals'])
        actual=[x for x in r['commands']if x['name']==c['command']]
        need(len(actual)<=1,'one actual command per case')
        outcome=actual[0]if actual else{}
        cases.append(dict(kind=c['kind'],case=c['case'],status=c['status'],result=c.get('result'),controls=controls,
            exit=outcome.get('exit'),duration_ns=outcome.get('duration_ns'),terminal_sha256=digest(c.get('terminal'))))
    value={k:r.get(k)for k in('schema','profile','scope','status','expected_revision','started_utc','source','source_unchanged','cpu','bounds','reproduce','cleanup_complete')}
    value.update(hardware=hw,cases=cases,commands=len(r['commands']),private_receipt=fact(private/'receipt.json'),
        command_sha256=digest(r['commands']),inputs_sha256=digest(r['inputs_before']),artifacts_sha256=digest(r['artifacts_before']),
        aliases_sha256=digest(r['aliases_before']),archive=r.get('archive'),build_status=r.get('build',{}).get('status'),
        release_build_status=r.get('release_build',{}).get('status'),configuration_unchanged=r.get('build',{}).get('configuration_unchanged',False),
        tool_versions=r.get('build',{}).get('numeric_versions'),tool_bindings_sha256=digest(r.get('build',{}).get('tools',{})),
        final_error_count=len(r['final_errors']),failure_type=r['error'].split(':',1)[0]if r['error']else None,
        full_bridge_xsave_comparison=False,component_kernel_registration_credit=False,performance_credit=False)
    text=json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n'
    need(len(text.encode())<16<<10 and not any(x and len(x)>1 and x in text for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact private-path-free public receipt')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-clock-getres-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS)
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-selected-clock-getres-v1',scope='Five full qualified-state native/NX component pairs using supplied guard state, twenty supplied arithmetic controls, five real default-rseq normal-loader native/gated query pairs and four actual pre-issue refusals. Components do not qualify production-dispatch XSAVE or kernel registration; actual application reports separately qualify registration/dispatch closure. No timing credit.',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[],error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_selected_clock_getres.py','--expect-revision',a.expect_revision])
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
            out,err=(program_invoke if name.startswith(('clock-native-','clock-gated-'))else invoke)(row,private,cpu,record=record,step=step)
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
        need(len(r['cases'])==20 and all(c['status']=='passed'for c in r['cases'])and not r['final_errors'],'complete fixed clock cohort')
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
