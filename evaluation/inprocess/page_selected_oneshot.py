"""Reproduce the opt-in initial-main one-shot publication pair at an exact commit."""
import argparse,hashlib,importlib.util,json,os,platform,re,shlex,shutil,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected import fact,need,save
from checks import source as committed_source
from run import hardware
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
import page_selected_oneshot_build as build_api
from page_selected_process import invoke
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
from page_selected_register_time_build import bridge_check
from page_selected_register_real import resolved_libraries
FIXTURE=ROOT/'tools/page-entry/selected/tests/oneshot_integrated'
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',PYTHONDONTWRITEBYTECODE='1')
BOUNDS=dict(BUILD_PROFILES,link=[5,512<<20,16<<20,15],program=[30,512<<20,16<<20,60])
H=lambda b:hashlib.sha256(b).hexdigest()
def decode(b):
    def unique(items):
        out={}
        for k,v in items:need(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(b,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def publish(path,r,private):
    """Compact exact observations; paths/raw signal or program data stay private."""
    digest=lambda v:H(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
    build=r.get('build',{}); product=r.get('oneshot_build',{})
    substitutions=[(str(private),'${RUN}'),(str(ROOT),'${REPO_ROOT}')]
    substitutions += [(v['path'],'${TOOL_'+k.upper()+'}')for k,v in r.get('tools',{}).items()]
    substitutions.sort(key=lambda x:len(x[0]),reverse=True)
    def normalized(words):
        result=[]
        for word in words:
            for old,new in substitutions:word=word.replace(old,new)
            if word.startswith('/')or '/home/'in word:word='${PRIVATE_ARGUMENT_SHA256:'+H(word.encode())+'}'
            result.append(word)
        return result
    commands=[dict(name=c['name'],profile=c['profile'],bounds=c['bounds'],argv=normalized(c['argv']),
        actual_argv_sha256=digest(c['argv']),environment_sha256=digest(c['environment']),
        expected_exit=c['expected_exit'],exit=c.get('exit'),timed_out=c.get('timed_out'),reaped=c.get('reaped'),
        error_type=c.get('error','').split(':',1)[0]if c.get('error')else None,
        cleanup_error_count=len(c.get('cleanup_errors',[])),
        captures={k:{x:v[x]for x in ('bytes','sha256')}for k,v in c.get('captures',{}).items()})for c in r['commands']]
    reports=r.get('reports',{});native=reports.get('native',{});loader=reports.get('loader',{})
    value={k:r.get(k)for k in ('schema','profile','scope','status','expected_revision','started_utc','source',
        'source_unchanged','environment','hardware','bounds','reproduce')}
    value.update(command_count=len(commands),commands=commands,command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'),input_manifest_sha256=digest(r['inputs_before']),
        artifact_manifest_sha256=digest(r['artifacts_before']),
        cases=[{k:c[k]for k in ('name','status','exit','stdout','stderr','captures')if k in c}|{
            'error_type':c['error'].split(':',1)[0]if c.get('error')else None}for c in r['cases']],
        accepted_pairs=int(r['status']=='passed'),outputs=r.get('outputs'),
        oneshot={k:reports['oneshot'][k]for k in ('version','scope','status','failure_code','owners',
            'published','restored','completed','syscall_patches','rdtsc_patches','effect_started',
            'effect_returned','active_phase')if k in reports['oneshot']}if 'oneshot'in reports else None,
        native_pages={k:native[k]for k in ('status','failure_code','attempts','admissions','closed','blocked',
            'low_address_refusals','epoch_exits','refaults','main_admissions','main_refaults','epoch_error',
            'close_error','close_complete','close_busy')if k in native},
        loader={k:loader[k]for k in ('status','failure_code','source_patches',
            'nx_faults','selected_steps','cpuid','rdtsc','rdtscp','syscalls','forwarded','admissions')if k in loader},
        full_reports_sha256=digest(reports),
        planned_dependencies=r.get('namespace_plan',{}).get('objects',[]),
        build_status=build.get('status'),build_command_completed=build.get('command_completed'),
        tool_versions=build.get('numeric_versions'),tools={k:{x:v[x]for x in ('bytes','sha256')}for k,v in r.get('tools',{}).items()},
        registry_sources=[{k:v for k,v in item.items()if k!='root'}for item in build.get('registry_before',[])],
        dep_info=build.get('dep_info'),publisher_archive_exports=product.get('archive_exports'),
        oneshot_recipe=product.get('recipe'),translation_units=product.get('translation_units'),
        actual_bridge={k:r.get('bridge',{}).get(k)for k in ('bytes','sha256')},
        header_closure_sha256=digest({'default':r.get('default_include_closure'),'observer':r.get('generic_observer_headers'),'oneshot':product.get('headers')}),
        reset={k:r.get('reset',{}).get(k)for k in ('binding','type','visibility','bytes','sha256')},
        build_artifacts={k:{x:v[x]for x in ('bytes','sha256','mode')}for k,v in build.get('artifacts',{}).items()},
        failure_type=r['error'].split(':',1)[0]if r.get('error')else None,
        report_error_type=r.get('report_error','').split(':',1)[0]if r.get('report_error')else None,
        final_error_count=len(r['final_errors']),performance_credit=False,
        command_recipe={'default_build':['sh','tools/page-entry/selected/build.sh'],
            'oneshot':'Exact current build-oneshot.sh C link expanded with the retained current release archive; conditional includes inspected before compilation.',
            'fixture':['sh','tools/page-entry/selected/tests/oneshot_integrated/build.sh','<actual interpreter>','<library root>','${RUN}/original'],
            'gated':'Actual carrier and sealed dependency namespace with explicit glibc.pthread.rseq=0; original native has matching application environment.'})
    text=json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-data guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--library-root',type=Path,default=Path('/usr/lib64'));a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact HEAD/assertions/one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-oneshot-'+a.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,mode=0o700)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    pins={};aliases={};artifacts={};namespace_aliases={};commands=[]
    r=dict(schema=1,profile='page-selected-oneshot-v1',scope='Opt-in same-page initial-main temporary E9 publication; six owned sites in one freestanding dynamically linked program; no general B2/B3 or performance claim',status='failed',
           committed_product_evidence=True,expected_revision=a.expect_revision,started_utc=stamp,
           source=None,environment={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'},
           reproduce=['python3','evaluation/inprocess/page_selected_oneshot.py','--expect-revision',a.expect_revision,'--library-root',str(a.library_root)],
           bounds=BOUNDS,commands=commands,cases=[],error=None,final_errors=[],
           hardware=hardware(cpu))
    def pin(path,expected=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);f=fact(p)
        need(expected is None or f=={k:expected[k]for k in ('bytes','sha256')},'exact input '+str(alias))
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'input alias changed')
        need(str(p) not in pins or pins[str(p)]==f,'input bytes changed')
        aliases[str(alias)]=str(p);pins[str(p)]=f;return p
    def artifact(path):
        p=Path(path).resolve(strict=True);f=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p) not in artifacts or artifacts[str(p)]==f,'retained artifact changed')
        artifacts[str(p)]=f;return p
    def stable():
        need(all(Path(p).resolve(strict=True)==Path(v)for p,v in aliases.items()),'all lexical input aliases unchanged')
        need(all(fact(p)==v for p,v in pins.items()),'all inputs unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all artifacts unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in namespace_aliases.items()),'all sealed namespace alias texts unchanged')
    def run(name,argv,profile='metadata',expected=0,env=None):
        stable();row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],capture_limit=16<<20,
                         environment=dict(ENV if env is None else env),expected_exit=expected)
        commands.append(row);out,err=invoke(row,private,cpu)
        need(type(row['exit']) is int and (expected is None or row['exit']==expected),'actual command exit '+name)
        return row,out,err
    def imported():
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT) and Path(p).suffix=='.py':pin(p)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def prep(path):
        artifact(path);v=decode(path.read_bytes());need(v['mask']==0 and [x['signal']for x in v['dispositions']]==[x for x in range(1,65)if x not in(9,19)] and all(x['after']==0 for x in v['dispositions']),'genuine preparation with no inherited observer FD');return v
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        build_api.before_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(r,private,pin,artifact,build_run)
    try:
        r['source']=committed_source();need(r['source']['revision']==a.expect_revision,'exact clean committed source')
        tools={n:pin(shutil.which(n,path=ENV['PATH']))for n in ('git','objdump','basename','dirname')}
        _,out,err=run('source-paths',[tools['git'],'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err,'source enumeration stderr')
        for name in out.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        check=load('oneshot_fixture_check',FIXTURE/'check.py');report=load('oneshot_fixture_reports',FIXTURE/'reports.py')
        namespace=load('oneshot_namespace',ROOT/'tools/page-entry/namespace.py')
        pin(ROOT/'evaluation/inprocess/page_selected_rseq_schema.json');imported()
        products=builder.prepare();tools.update(builder.tools)
        r['tools']={k:dict(path=str(p),**fact(p))for k,p in tools.items()}
        r['context_revision']=r['source']['revision']
        bridge=build_api.link(builder,products,private,pin,artifact,aliases,run,r)
        r['bridge']=dict(path=str(bridge),**fact(bridge))
        _,out,err=run('bridge-symbols',[tools['nm'],'-S','--defined-only',bridge]);need(not err,'actual bridge symbols')
        names=[x.split()[-1]for x in out.decode().splitlines()if x.split()]
        for name in ('li2_admission_oneshot_plan','li2_admission_oneshot_bind','li2_admission_oneshot_transition','li2_admission_oneshot_fail'):need(names.count(name)==1,'actual retained publisher '+name)
        _,assembly,err=run('bridge-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',bridge]);need(not err,'actual bridge reset instructions')
        proof=body_check(bridge,out,assembly,'fast',symbol_name='memset');r['reset']=hidden_memset(bridge,proof)
        _,out,err=run('bridge-undefined',[tools['nm'],'-u',bridge]);need(not out and not err,'no bridge imports')
        r['bridge_elf']=bridge_check(bridge)
        pin('/bin/true');interp_name=namespace.parse(Path('/bin/true').read_bytes())['interpreter'];interp=pin(interp_name)
        root=a.library_root.resolve(strict=True);need(root.is_dir(),'actual dependency root')
        _,out,err=run('fixture-dependencies',[tools['cc'],'-M','-MT','oneshot',FIXTURE/'fixture.S']);need(not err and out.startswith(b'oneshot:'),'actual assembler compiler-M closure')
        for item in shlex.split(out.decode().replace('\\\n',' ').split(':',1)[1]):pin(item if Path(item).is_absolute()else private/item)
        original=private/'original';env=dict(ENV,LI2_CC=str(tools['cc']))
        try:
            run('fixture-link',[tools['sh'],FIXTURE/'build.sh',interp_name,root,original],profile='link',env=env)
        finally:
            try:
                if original.exists():artifact(original) # retain/hash failed linker partials too
            except BaseException as exc:r['final_errors'].append('fixture partial artifact: '+type(exc).__name__+': '+str(exc))
        r['fixture_elf']=check.elf(original.read_bytes(),str(interp_name))
        _,out,err=run('fixture-symbols',[tools['nm'],'-S','-n',original]);need(not err,'actual fixture symbol capture')
        _,out,err=run('fixture-assembly',[tools['objdump'],'-d','-w',original]);need(not err,'actual emitted fixture instruction capture')
        carrier=private/'carrier';carrier_tool=pin(ROOT/'tools/page-entry/carrier.py')
        try:_,out,err=run('carrier-make',[tools['python'],carrier_tool,'make',original,bridge,carrier]);need(not err,'actual carrier construction stderr')
        finally:
            try:
                if carrier.exists():artifact(carrier)
            except BaseException as exc:r['final_errors'].append('carrier partial artifact: '+type(exc).__name__+': '+str(exc))
        identities=decode(out);need(identities['original_sha256']==fact(original)['sha256']and identities['bridge_sha256']==fact(bridge)['sha256'] and identities['interpreter_sha256']==fact(interp)['sha256']and identities['carrier_sha256']==fact(carrier)['sha256'],'actual carrier identity')
        objects,description=namespace.plan(original,[root],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        expected={interp:set()}
        for item in objects:
            p=pin(item['path']);need(fact(p)['sha256']==H(item['bytes']),'complete dependency bytes');expected.setdefault(p,set()).update(item['names'])
            for alias in item['names']:
                if (root/alias).exists():need(pin(root/alias)==p,'actual dependency lexical alias')
        _,out,err=run('native-loader-list',[interp,'--list',original],profile='program');need(not err,'native loader listing stderr');resolved_libraries(out,expected,interp,pin)
        r['namespace_plan']=dict(description,objects=[dict(names=x['names'],sha256=H(x['bytes']),bytes=len(x['bytes']))for x in objects])
        outcomes={};ns=private/'namespace';launch=pin(FIXTURE/'launch.py')
        for mode in ('native','gated'):
            argv=[tools['python'],launch,'--mode',mode,'--original',original,'--library-root',root,'--preparation',private/(mode+'.preparation')]
            if mode=='gated':argv+=['--carrier',carrier,'--namespace',ns]
            c=dict(name=mode,status='failed',error=None);r['cases'].append(c)
            try:
                row,out,err=run(mode,argv,profile='program',expected=None);c.update(exit=row['exit'],pid=row['pid'],stdout=fact(private/(mode+'.stdout')),stderr=fact(private/(mode+'.stderr')))
                preparation=prep(private/(mode+'.preparation'));c['preparation']=preparation
                if mode=='native':need(preparation['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and preparation['argv']==[str(original)],'actual explicit native environment')
                outcomes[mode]=(row,out,err);c['status']='executed'
                if mode=='gated':
                    try:r['reports']=report.reports(err)
                    except Exception as exc:r['report_error']=type(exc).__name__+': '+str(exc)
            except Exception as exc:
                c['error']=type(exc).__name__+': '+str(exc)
                if commands and commands[-1]['name']==mode:
                    c.update({k:commands[-1][k]for k in ('exit','pid')if k in commands[-1]})
                    c['captures']=commands[-1].get('captures',{})
        need(set(outcomes)=={'native','gated'},'both actual program commands completed process cleanup')
        n,g=outcomes['native'],outcomes['gated'];need(n[0]['exit']==0 and not n[2] and g[0]['exit']==0,'both actual successful exits/native empty stderr')
        for name in ('namespace.json','launch.json'):artifact(ns/name)
        actual=decode((ns/'namespace.json').read_bytes());started=decode((ns/'launch.json').read_bytes())
        need(actual['original_sha256']==fact(original)['sha256']and actual['interpreter_sha256']==fact(interp)['sha256']and actual['original']==str(original),'actual namespace inputs')
        need(len(actual['objects'])==len(objects),'complete actual dependency namespace')
        for row,item in zip(actual['objects'],objects):
            need(row['names']==item['names']and row['sha256']==H(item['bytes'])and row['size']==len(item['bytes'])and row['seals']==namespace.SEALS and row['device']>0 and row['inode']>0,'actual sealed namespace row')
            for name in row['names']:
                alias=ns/name;target='/proc/self/fd/'+str(row['fd']);need(alias.is_symlink()and os.readlink(alias)==target,'actual sealed dependency alias');namespace_aliases[str(alias)]=target
        target_env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
        need(started['argv']==[str(original)]and started['carrier_sha256']==fact(carrier)['sha256']and started['environment']==dict(target_env,LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(str(x['fd'])for x in actual['objects'])),'actual explicit target environment, no hidden tunables')
        r['outputs']=check.compare_outputs(n[1],g[1]);r['reports']=report.reports(g[2]);report.completed(r['reports'],g[0]['pid'])
        r['status']='passed'
        for c in r['cases']:c['status']='completed'
    except Exception as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors'].extend(builder.finish())
        except BaseException as exc:r['final_errors'].append('build finalization: '+type(exc).__name__+': '+str(exc))
        # Keep every partial artifact and every actual capture; never replace
        # an initiating failure with secondary finalization errors.
        for p in sorted(private.rglob('*')):
            if p.is_file()and not p.is_symlink():
                try:artifact(p)
                except Exception as exc:r['final_errors'].append('retain '+str(p)+': '+type(exc).__name__+': '+str(exc))
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts);r['namespace_aliases']=dict(namespace_aliases)
        def final_context():
            r['source_after']=committed_source();need(r['source_after']==r['source'],'exact committed source unchanged')
        for label,fn in [('closure',stable),('context',final_context)]:
            try:fn()
            except Exception as exc:r['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed_paths,fn in [('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))]:
            for p in observed_paths:
                try:r[table][p]=fn(p)
                except Exception as exc:r['final_errors'].append(table+' '+p+': '+type(exc).__name__)
        r['source_unchanged']=r['source'] is not None and r.get('source_after')==r['source'] and r['inputs_before']==r['inputs_after']and r['aliases_before']==r['aliases_after']
        if r['final_errors']or not r['source_unchanged']or r['artifacts_before']!=r['artifacts_after']:r['status']='failed'
        save(private/'receipt.json',r)
        publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),commands=len(commands),error_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
