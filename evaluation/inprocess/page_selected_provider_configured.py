#!/usr/bin/env python3
"""Original provider385, configured callback51, and genuine configured carrier entries."""
import argparse,hashlib,importlib.util,json,os,platform,re,shlex,shutil,struct,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_selected import ENV,fact,need,save,elf
from checks import source
from run import hardware
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_component_build import provider as build_provider
from page_selected_oneshot_build import before_default
import page_selected_provider_callback as callback
import page_selected_provider_launch as launcher
from page_selected_provider_libraries import libraries as provider_libraries
SELECTED=ROOT/'tools/page-entry/selected'
BOUNDS=dict(BUILD_PROFILES,provider=[3,256<<20,1<<20,10],provider_build=[30,512<<20,64<<20,60],
            **callback.BOUNDS,**launcher.BOUNDS)
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())

def publish(path,r,private):
    commands=r['commands'];captures=[(c['name'],k,v)for c in commands for k,v in c.get('captures',{}).items()]
    original=r.get('original_provider',{})
    value={k:r.get(k)for k in ('schema','profile','scope','status','expected_revision','started_utc','source','source_unchanged','hardware','bounds','reproduce')}
    value.update(private_receipt=fact(private/'receipt.json'),command_count=len(commands),command_rows_sha256=digest(commands),
        command_counts={p:sum(c['profile']==p for c in commands)for p in sorted({c['profile']for c in commands})},
        capture_count=len(captures),capture_bytes=sum(v['bytes']for _,_,v in captures),capture_manifest_sha256=digest(captures),
        failures=[{k:c.get(k)for k in ('name','profile','expected_exit','exit','timed_out','reaped')}|dict(
            error_type=c['error'].split(':',1)[0]if c.get('error')else None,cleanup_error_count=len(c.get('cleanup_errors',[])))
            for c in commands if c.get('error')or c.get('cleanup_errors')or c.get('timed_out')or not c.get('reaped')or
            (c['expected_exit']is not None and c.get('exit')!=c['expected_exit'])],
        original_provider=dict(planned=385,attempted=len(original.get('cases',[])),accepted=sum(c.get('accepted')is True for c in original.get('cases',[])),
            cases_sha256=digest(original.get('cases',[])),cohort_sha256=original.get('cohort_sha256'),status=original.get('status','unexecuted')),
        callback=callback.summary(r),launcher=launcher.summary(r),input_manifest_sha256=digest(r['inputs_before']),
        alias_manifest_sha256=digest(r['aliases_before']),artifact_manifest_sha256=digest(r['artifacts_before']),
        build_status=r.get('build',{}).get('status'),build_command_completed=r.get('build',{}).get('command_completed'),
        archive=r.get('archive'),tool_versions=r.get('build',{}).get('numeric_versions'),
        tools={k:{x:v[x]for x in ('bytes','sha256')}for k,v in r.get('tools',{}).items()},
        final_error_count=len(r['final_errors']),failure_type=r['error'].split(':',1)[0]if r.get('error')else None,
        full_b2_qualification=False,performance_credit=False)
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<64<<10,'compact numeric configured-provider summary')
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-data guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def original_provider(builder,products,private,pin,binary,run,receipt):
    state=receipt['original_provider']=dict(status='failed',cases=[],headers={},link_inputs={})
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    compare=load('configured_original_provider_compare',SELECTED/'tests/provider/compare.py')
    cases=load('configured_original_provider_cases',SELECTED/'tests/provider/cases.py').cohort()
    need(len(cases)==385,'full original provider cohort');state['cohort_sha256']=digest(cases)
    for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a','libgcc_s.so.1','libc.so.6'):
        _,out,err=run('original-link-input-'+name,[builder.tools['cc'],'-print-file-name='+name],env=builder.environment)
        value=out.decode().strip();need(not err and Path(value).is_absolute(),'actual original C runtime link input')
        p=pin(value);state['link_inputs'][name]=dict(path=str(p),**fact(p))
    _,_,err=run('original-cc-specs',[builder.tools['cc'],'-dumpspecs'],env=builder.environment);need(not err,'actual original compiler specs')
    output=private/'original-provider';output.mkdir()
    def invoke_build(label,argv,build=False):
        need(build,'unchanged original provider build-only callback');argv=list(map(str,argv))
        if '-c'in argv:
            at=argv.index('-c');unit=argv[at+1];flags=argv[1:at]
            _,out,err=run('original-headers-'+label,[builder.tools['cc'],*flags,'-M','-MT','provider_original',unit],env=builder.environment)
            rules=out.decode().replace('\\\n',' ').splitlines()
            need(not err and len(rules)==1 and rules[0].startswith('provider_original: '),'one actual original conditional include rule')
            deps=shlex.split(rules[0].split(':',1)[1]);need(unit in deps,'actual original unit in header closure')
            state['headers'][label]={str(pin(p)):fact(p)for p in deps}
        result=Path(argv[-1])if len(argv)>2 and argv[-2]=='-o'else None
        try:
            _,out,err=run('original-'+label,argv,profile='provider_build',env=builder.environment)
            return out,err
        finally:
            try:
                if result is not None and (result.exists()or result.is_symlink()):binary(result)
            except BaseException as exc:receipt['final_errors'].append('original partial artifact: '+type(exc).__name__+': '+str(exc))
    built=build_provider(output,invoke_build,builder.tools,products['archive']);state['build']=built
    for name in ('normal','nested'):
        executable=binary(built[name]);image,_,segments=elf(executable);rows=[p for p in segments if p[0]==3]
        need(len(rows)==1,'one actual original interpreter');p=rows[0];name_bytes=image[p[2]:p[2]+p[5]]
        need(len(name_bytes)==p[5]and name_bytes[:1]==b'/'and name_bytes[-1:]==b'\0'and b'\0'not in name_bytes[:-1],'actual original interpreter string')
        interpreter=pin(Path(os.fsdecode(name_bytes[:-1])))
        _,out,err=run('original-'+name+'-libraries',[interpreter,'--list',executable],env=builder.environment);need(not err,'actual original loader list')
        state.setdefault('libraries',{})[name]=provider_libraries(ROOT,executable,interpreter,out,state['link_inputs'],pin)
    for case in cases:
        name='original-provider-'+case['name'];row=dict(name=name,case=case,accepted=False);state['cases'].append(row)
        nested=case['args'][4]==38;executable=built['nested'if nested else'normal']
        env=dict(ENV,**({'LI2_FIXTURE_SCRIPT_CF0':'1'}if case['cf0']else{}))
        _,out,err=run(name,[executable,'{record_fd}',*map(str,case['args'])],profile='provider',expected=125 if nested else 0,env=env,record=True)
        need(err==b''and out==(b''if nested else b'LI2_PROVIDER_CAPTURE 1\n'),'original provider capture protocol')
        path=private/(name+'.record');data=path.read_bytes();row['record']=fact(binary(path))
        if nested:
            row['comparison']=compare.nested(data);actual=struct.unpack('<64Q',data);bound=built['isolated_page']
            compare.need((actual[9],actual[10],actual[11])==(bound['start'],bound['code_end'],bound['end']),'nested.binary_binding')
        elif case['reject']:
            try:compare.check(data,case)
            except compare.Mismatch as error:
                compare.need(error.field==case['reject'],'negative.wrong_failure');row['precise_rejection']=error.field
            else:raise ValueError('original provider actual negative accepted')
        else:row['comparison']=compare.check(data,case)
        row['accepted']=True
    need(len(state['cases'])==385 and all(c['accepted']for c in state['cases']),'all385 unchanged original cases')
    state['status']='passed'


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact HEAD/assertions/one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-provider-configured-'+a.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,mode=0o700)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-selected-provider-configured-v1',scope='Configured CPUID mask and random/ID callbacks in the actual C launcher; original385 and callback51 plus four genuine interpreter/main carrier pairs; full B2 and performance remain unqualified',
           status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
           hardware=hardware(cpu),bounds=BOUNDS,commands=commands,error=None,final_errors=[],
           reproduce=['python3','evaluation/inprocess/page_selected_provider_configured.py','--expect-revision',a.expect_revision])
    def pin(path):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);f=fact(p)
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'input alias changed')
        need(str(p)not in pins or pins[str(p)]==f,'input bytes changed')
        aliases[str(alias)]=str(p);pins[str(p)]=f;return p
    def binary(path):
        p=Path(path).resolve(strict=True);f=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==f,'retained artifact changed');artifacts[str(p)]=f;return p
    def stable():
        need(all(Path(p).resolve(strict=True)==Path(v)for p,v in aliases.items()),'all lexical input aliases unchanged')
        need(all(fact(p)==v for p,v in pins.items()),'all inputs unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all artifacts unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
        launcher.finalize(r)
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        stable();row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],
            capture_limit=8192 if profile=='provider'else 16<<20,environment=dict(ENV if env is None else env),expected_exit=expected)
        if profile=='provider':row['nproc']=1
        commands.append(row)
        try:
            out,err=invoke(row,private,cpu,record=record)
            need(type(row['exit'])is int and(expected is None or row['exit']==expected),'actual command exit '+name)
            return row,out,err
        finally:
            # Bind each complete or partial capture before another child runs.
            # Secondary retention failures never replace the initiating error.
            for stream in ('stdout','stderr','record','preparation'):
                path=private/(name+'.'+stream)
                try:
                    observed=row.get('captures',{}).get(stream)
                    if path.exists()or path.is_symlink():
                        actual=fact(binary(path))
                        if observed is not None:
                            need(observed['file']==path.name and actual=={k:observed[k]for k in ('bytes','sha256')},'actual command capture binding '+name+'.'+stream)
                    else:need(observed is None,'retained command capture missing '+name+'.'+stream)
                except BaseException as exc:r['final_errors'].append('command capture '+name+'.'+stream+': '+type(exc).__name__+': '+str(exc))
            path=private/(name+'.json')
            try:
                if path.exists()or path.is_symlink():
                    binary(path);need(json.loads(path.read_bytes())==row,'retained command row binding '+name)
            except BaseException as exc:r['final_errors'].append('command row '+name+': '+type(exc).__name__+': '+str(exc))
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(r,private,pin,binary,build_run)
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        for name in out.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT)and Path(p).suffix=='.py':pin(p)
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload');r['configuration_presence']=presence
        products=builder.prepare();builder.tools['objdump']=pin(shutil.which('objdump',path=ENV['PATH']))
        r['tools']={k:dict(path=str(p),**fact(p))for k,p in builder.tools.items()};r['archive']=fact(products['archive'])
        original_provider(builder,products,private,pin,binary,run,r)
        callback.component(builder,products,ROOT,private,pin,binary,aliases,run,r)
        launcher.launch(builder,products,ROOT,private,pin,binary,aliases,run,r)
        need(r['original_provider']['status']==r['provider_callback']['status']==r['provider_launch']['status']=='passed','all three mandatory cohorts')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors'].extend(builder.finish())
        except BaseException as exc:r['final_errors'].append('build finalization: '+type(exc).__name__+': '+str(exc))
        for p in sorted(private.rglob('*')):
            if p.is_file()and not p.is_symlink():
                try:binary(p)
                except Exception as exc:r['final_errors'].append('retain '+str(p)+': '+type(exc).__name__+': '+str(exc))
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        for label,fn in (('closure',stable),('namespace',lambda:launcher.finalize(r))):
            try:fn()
            except BaseException as exc:r['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        try:r['source_after']=source();need(r['source_after']==r['source'],'exact committed source unchanged')
        except BaseException as exc:r['final_errors'].append('source: '+type(exc).__name__+': '+str(exc))
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in (('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as exc:r['final_errors'].append(table+' '+p+': '+type(exc).__name__)
        r['source_unchanged']=r['source']is not None and r.get('source_after')==r['source']and r['inputs_before']==r['inputs_after']and r['aliases_before']==r['aliases_after']
        if r['error']or r['final_errors']or not r['source_unchanged']or r['artifacts_before']!=r['artifacts_after']:r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),commands=len(commands),failure_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
