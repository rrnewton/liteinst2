#!/usr/bin/env python3
"""Original provider385, configured callback51, and finite native-page CPUID-NX routes."""
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
from page_selected_provider_configured import original_provider
from page_selected_oneshot_build import before_default
import page_selected_provider_callback as callback
import page_selected_cpuid_nx as qualification
from page_selected_provider_libraries import libraries as provider_libraries
SELECTED=ROOT/'tools/page-entry/selected'
BOUNDS=dict(BUILD_PROFILES,provider=[3,256<<20,1<<20,10],provider_build=[30,512<<20,64<<20,60],
            **callback.BOUNDS,**qualification.BOUNDS)
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())

def compact_nx(receipt):
    value=qualification.summary(receipt)
    for case in value['cases']:
        captures=case.pop('captures')
        case.update(capture_count=len(captures),capture_bytes=sum(v['bytes']for v in captures.values()),
                    capture_manifest_sha256=digest(captures))
    return value

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
        callback=callback.summary(r),cpuid_nx=compact_nx(r),input_manifest_sha256=digest(r['inputs_before']),
        alias_manifest_sha256=digest(r['aliases_before']),artifact_manifest_sha256=digest(r['artifacts_before']),
        build_status=r.get('build',{}).get('status'),build_command_completed=r.get('build',{}).get('command_completed'),
        archive=r.get('archive'),tool_versions=r.get('build',{}).get('numeric_versions'),
        tools={k:{x:v[x]for x in ('bytes','sha256')}for k,v in r.get('tools',{}).items()},
        final_error_count=len(r['final_errors']),failure_type=r['error'].split(':',1)[0]if r.get('error')else None,
        full_b2_qualification=False,performance_credit=False)
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<64<<10,'compact numeric CPUID-NX summary')
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'public private-data guard')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)



def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact HEAD/assertions/one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-cpuid-nx-'+a.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,mode=0o700)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-selected-cpuid-nx-v1',scope='Explicit native-page CPUID without GET/SET_CPUID controls; unchanged provider385 and callback51 plus all57 finite actual-entry, denial and boundary controls. Native and configured policies stay separate; no one-shot source publication, full B2 or performance credit',
           status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
           hardware=hardware(cpu),bounds=BOUNDS,commands=commands,error=None,final_errors=[],
           reproduce=['python3','evaluation/inprocess/page_selected_cpuid_nx_run.py','--expect-revision',a.expect_revision])
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
        qualification.finalize(r)
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
                    binary(path);need(digest(json.loads(path.read_bytes()))==digest(row),'retained command row binding '+name)
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
        qualification.qualify(builder,products,ROOT,private,pin,binary,aliases,run,r)
        need(r['original_provider']['status']==r['provider_callback']['status']==r['cpuid_nx']['status']=='passed','all385 original,51 callback and57 CPUID-NX controls')
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
        for label,fn in (('closure',stable),('namespace',lambda:qualification.finalize(r))):
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
