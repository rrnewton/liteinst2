#!/usr/bin/env python3
"""Current release retained-RX REP lease: native and gated real ls completion."""
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
import page_selected_repeat_lease_ls_reports as reports
from page_selected_effect_ls import program_invoke,finalize
from page_selected_register_real import resolved_libraries
from page_selected_oneshot_build import before_default,commands
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_register_time_compare import decode
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/effect_provider'
BOUNDS={'release_build':[30,512<<20,16<<20,60],'program':[30,512<<20,16<<20,60]}
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


def build_bridge(builder,products,private,pin,binary,aliases,run,r):
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    output=private/'release';output.mkdir();bridge_recipe=pin(SELECTED/'build-repeat-lease.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit retained-RX REP lease release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output});units=[str(SELECTED.parent/x)for x in UNITS]
    need(argv[-2:]==['-o',str(output/'bridge-repeat-lease.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact unobserved18-TU19-macro REP lease release recipe')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    bridge=Path(argv[-1]);run('release-bridge-link',argv,profile='release_build',env=builder.environment)
    state['bridge']=fact(binary(bridge));state['elf']=bridge_check(bridge)
    _,out,err=run('release-bridge-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(out==err==b'','actual effect bridge has no unresolved imports')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('release-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump identity')
    _,symbols,err=run('release-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset symbol inspection')
    _,assembly,err=run('release-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset disassembly');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    state['status']='passed';return bridge

def cohort(builder,products,private,pin,binary,aliases,run,r):
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r)
    original=pin('/bin/ls');interp=pin(interpreter(original));carrier=private/'ls-carrier'
    carrier_tool=pin(SELECTED.parent/'carrier.py')
    spec=importlib.util.spec_from_file_location('effect_ls_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    objects,description=namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    expected={interp:set()}
    for item in objects:
        p=pin(item['path']);need(fact(p)['sha256']==H(item['bytes']),'every actual namespace dependency pinned')
        expected.setdefault(p,set()).update(item['names'])
    r['namespace_plan']=description;r['namespace_aliases']={}
    r['system_inputs']=dict(original=fact(original),interpreter=fact(interp),dependencies=[dict(names=x['names'],**fact(x['path']))for x in objects])
    # Retain external file bytes independently before either subject. These
    # facts do not assert an application-reported load bias or allocation ID.
    source_directory=private/'lease-source-inputs';source_directory.mkdir()
    images=[];image_bytes=[];by_hash={}
    for role,path in [('original',original),('interpreter',interp)]+[('dependency-'+str(i),x['path'])for i,x in enumerate(objects)]:
        path=pin(path);data=path.read_bytes();identity=fact(path)
        need(identity==dict(bytes=len(data),sha256=H(data)),'stable exact independently retained external ELF')
        if identity['sha256']in by_hash:
            index=by_hash[identity['sha256']]
            need(data==image_bytes[index],'identical complete bytes for duplicate external content identity')
            images[index]['roles'].append(role);continue
        index=len(images);copy=source_directory/(str(index)+'.elf')
        with copy.open('xb')as f:f.write(data)
        need(fact(binary(copy))==identity,'complete retained external ELF copy')
        images.append(dict(identity,roles=[role]));image_bytes.append(data);by_hash[identity['sha256']]=index
    r['lease_source_inputs']=images
    _,out,err=run('native-libraries',[interp,'--list',original],env=PROGRAM_ENV)
    need(not err,'actual native loader listing stderr');resolved_libraries(out,expected,interp,pin)
    _,out,err=run('ls-carrier',[builder.tools['python'],'-B',carrier_tool,'make',original,bridge,carrier],profile='program',env=PROGRAM_ENV)
    need(not err,'actual carrier construction stderr');binary(carrier);identities=decode(out)
    need(all(identities[k+'_sha256']==fact(p)['sha256']for k,p in
        (('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,
        'actual original/interpreter/release bridge/carrier identities')
    carrier_bytes=carrier.read_bytes()
    native=dict(lane='native',status='failed');r['cases'].append(native)
    row,out,err=run('ls-native',[original,'-d','.'],profile='program',env=PROGRAM_ENV)
    native.update(pid=row['pid'],exit=row['exit'],whole_process_ns=row['duration_ns'],stdout=fact(private/'ls-native.stdout'))
    need(out==b'.\n'and err==b'','exact genuine native baseline output')
    native['status']='passed'
    gated=dict(lane='gated',status='failed');r['cases'].append(gated);ns=private/'ls-namespace'
    row,actual,stderr=run('ls-gated',[builder.tools['python'],'-B',carrier_tool,'exec-loader','--library-root','/usr/lib64',
        '--namespace',ns,carrier,original,'--',original,'-d','.'],profile='program',env=PROGRAM_ENV)
    gated.update(pid=row['pid'],exit=row['exit'],whole_process_ns=row['duration_ns'],stdout=fact(private/'ls-gated.stdout'))
    observed=decode(binary(ns/'namespace.json').read_bytes());launch=decode(binary(ns/'launch.json').read_bytes())
    need(all(observed[k]==v for k,v in description.items())and observed['directory']==str(ns)and
         observed['schema_version']==1 and observed['status']=='prepared_not_executed'and len(observed['objects'])==len(objects),
         'actual complete sealed namespace matches independent plan')
    fds=[]
    for obj,item in zip(observed['objects'],objects,strict=True):
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
    expected_env={k:v for k,v in PROGRAM_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
    expected_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)))
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
        carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],argv=[str(original),'-d','.'],
        environment=expected_env,dependency_fds=fds),'actual exact default-rseq launch/argv/environment/carrier/FD join')
    need(actual==out==b'.\n','complete exact native/gated output equality')
    parsed,summary=reports.check(stderr,row['pid'],row['exit'],row['stdout_provenance_before'],images,image_bytes,fact(carrier),carrier_bytes)
    r['terminal_reports']=parsed;gated['comparison']=summary
    r['reader_controls']=reports.supplied_controls(stderr,row['pid'],row['exit'],row['stdout_provenance_before'],images,image_bytes,fact(carrier),carrier_bytes)
    gated['status']='passed'

def publish(path,r,private):
    commands=r['commands'];captures=[(c['name'],k,v)for c in commands for k,v in c.get('captures',{}).items()]
    hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    value={k:r.get(k)for k in('schema','profile','scope','status','expected_revision','started_utc','source','source_unchanged',
        'cpu','bounds','reproduce','cleanup_complete','system_inputs')}
    value.update(hardware=hw,private_receipt=fact(private/'receipt.json'),commands=len(commands),captures=len(captures),
        command_rows_sha256=digest(commands),capture_manifest_sha256=digest(captures),
        inputs_sha256=digest(r['inputs_before']),artifacts_sha256=digest(r['artifacts_before']),
        archive=r.get('archive'),build_status=r.get('build',{}).get('status'),
        tool_versions=r.get('build',{}).get('numeric_versions'),tool_bindings_sha256=digest(r.get('build',{}).get('tools',{})),
        configuration_unchanged=r.get('build',{}).get('configuration_unchanged',False),
        release_build_status=r.get('release_build',{}).get('status'),bridge=r.get('release_build',{}).get('bridge'),
        planned_subjects=2,actual_subjects=sum(type(c.get('pid'))is int for c in commands if c['name']in('ls-native','ls-gated')),
        completed_subjects=sum(c['status']=='passed'for c in r['cases']),
        cases=[{k:v for k,v in c.items()if k!='pid'}for c in r['cases']],reader_controls=r.get('reader_controls'),
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
        command_outcomes=dict(exited_zero=sum(c.get('exit')==0 for c in commands),reaped=sum(c.get('reaped')is True for c in commands),
            timeouts=sum(c.get('timed_out')is True for c in commands),cleanup_errors=sum(len(c.get('cleanup_errors',[]))for c in commands)),
        failed_commands=[{k:c.get(k)for k in('name','profile','expected_exit','exit','timed_out','reaped')}for c in commands
            if c.get('error')or c.get('cleanup_errors')or c.get('timed_out')or not c.get('reaped')or c.get('exit')!=c['expected_exit']],
        command_recipe=dict(release=['sh','tools/page-entry/selected/build-repeat-lease.sh','${FRESH_ARCHIVE}','${OUTPUT}'],
            native=['/bin/ls','-d','.'],gated=['python3','-B','tools/page-entry/carrier.py','exec-loader',
                '--library-root','/usr/lib64','--namespace','${PRIVATE_NAMESPACE}','${CURRENT_RELEASE_CARRIER}',
                '/bin/ls','--','/bin/ls','-d','.'],environment='PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC LD_BIND_NOW=1; default rseq'),
        cache_reuse_demonstrated=r['status']=='passed',full_b2_qualification=False,application_stress_qualification=False,performance_credit=False,steady_state_throughput_credit=False,
        timing_scope='One native then gated fresh process. Whole-process duration includes parent capture/provenance setup, process launch through reap and capture/descriptor closure; gated also includes Python namespace sealing/exec. First_admission_ns and every retained revisit_ns measure admission work only, not whole-app first touch or steady execution. No warmup exclusion, multi-sample speedup or cache-cold claim.')
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<10<<10 and not any(x and len(x)>1 and x in text for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public receipt without raw/private paths')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-repeat-lease-ls-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS)
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-selected-repeat-lease-ls-v1',scope='Real /bin/ls -d . with default rseq, fixed64-page generated-code reuse, original-PC retained-RX REP D/Q and exact Native effects. Successful completion requires actual retirement/republication and complete REP lease closure. The last REP byte join is to one retained external RX ELF candidate, not independent ASLR or allocation provenance. Separate full-state/reuse-oracle/app9216 obligations remain; no performance credit.',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[],error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_selected_repeat_lease_ls.py','--expect-revision',a.expect_revision])
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
            out,err=(program_invoke if name in('ls-native','ls-gated')else invoke)(row,private,cpu,record=record,step=step)
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
        need([c['lane']for c in r['cases']]==['native','gated']and all(c['status']=='passed'for c in r['cases'])and
             r['cases'][1]['comparison']['application_completed']is True and not r['final_errors'],'complete actual native and gated ls; no skipped lane')
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
