#!/usr/bin/env python3
"""Generation-aware64-page cache with unchanged normal-app full-state/stress lanes."""
import argparse,hashlib,importlib.util,json,os,platform,re,shutil,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_selected import ENV,fact,need,save
from checks import source
from run import hardware
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
import page_selected_run_reuse_app_lane as lane
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def process_counts(r,cases,planned):
    started=closed=accepted=0
    for case in cases:
        name=case.get('command');rows=[x for x in r['commands']if name is not None and x['name']==name]
        need(len(rows)<=1,'unique actual process command')
        if not rows:continue
        row=rows[0]
        if type(row.get('pid'))is not int or row['pid']<=0:continue
        started+=1
        if type(row.get('exit'))is not int or row.get('reaped')is not True or row.get('timed_out')is not False or row.get('error')or row.get('cleanup_errors')!=[]:continue
        closed+=1;accepted+=row['exit']==0 and case.get('status')=='passed'
    return dict(planned_processes=planned,attempted_cases=sum(c.get('command')is not None for c in cases),
                actual_processes=started,closed_processes=closed,accepted_processes=accepted)

def publish(path,r,private):
    commands=r['commands'];captures=[(c['name'],k,v)for c in commands for k,v in c.get('captures',{}).items()]
    app=r.get('app',{});build=r.get('build',{});hardware=dict(r['hardware'])
    flags=hardware.pop('isa_flags');hardware.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    value={k:r.get(k)for k in('schema','profile','scope','status','expected_revision','started_utc','source',
                            'source_unchanged','bounds','reproduce','cleanup_complete')}
    native=app.get('native_reference',{});seed=native.get('seed_profile',{})
    value.update(hardware=hardware,private_receipt=fact(private/'receipt.json'),command_count=len(commands),
        command_rows_sha256=digest(commands),capture_count=len(captures),capture_bytes=sum(v['bytes']for _,_,v in captures),
        capture_manifest_sha256=digest(captures),
        command_outcomes=dict(exited_zero=sum(c.get('exit')==0 for c in commands),reaped=sum(c.get('reaped')is True for c in commands),
            timeouts=sum(c.get('timed_out')is True for c in commands),cleanup_errors=sum(len(c.get('cleanup_errors',[]))for c in commands)),
        failed_commands=[{k:c.get(k)for k in('name','profile','expected_exit','exit','timed_out','reaped')}
            for c in commands if c.get('error')or c.get('cleanup_errors')or c.get('timed_out')or not c.get('reaped')or
            (c['expected_exit']is not None and c.get('exit')!=c['expected_exit'])],
        seed={k:seed.get(k)for k in('accepted','profile','cpu','record_bytes','record_sha256','elf_sha256','fip','fdp',
                                  'full_fxsave_sha256','architectural_bytes_normalized')},
        native_reference=dict(**process_counts(r,[{'command':app.get('native_reference_command'),
            'status':'passed'if native.get('native_complete')is True else 'unexecuted'}],1),
            native_complete=native.get('native_complete',False),raw_sha256=native.get('raw_sha256'),
            complete_operations=18 if native.get('native_complete')is True else None,
            complete_nt_states=36 if native.get('native_complete')is True else None),
        input_manifest_sha256=digest(r['inputs_before']),alias_manifest_sha256=digest(r['aliases_before']),
        artifact_manifest_sha256=digest(r['artifacts_before']),build_status=build.get('status'),
        configuration_unchanged=build.get('configuration_unchanged',False),
        build_command_completed=build.get('command_completed',False),archive=r.get('archive'),
        tool_versions=build.get('numeric_versions'),tool_hashes_sha256=digest({k:{x:v[x]for x in('bytes','sha256')}for k,v in build.get('tools',{}).items()}),
        app_input_build_status=r.get('app_input_build',{}).get('status','unexecuted'),
        app_artifacts=r.get('app_input_build',{}).get('artifacts',{}),
        final_error_count=len(r['final_errors']),failure_type=r['error'].split(':',1)[0]if r.get('error')else None,
        external_all_seven_and_masked_cpuid_prerequisites_required=True,full_b2_qualification=False,
        real_ls_completion=False,performance_credit=False,reports_replayed=app.get('status')=='passed',
        cache_reuse_demonstrated=app.get('status')=='passed',
        cache_limits=dict(pages=64,source_bytes=15,instructions=14,generated_bytes=29))
    value['cases']=[]
    for mode,policy in lane.LANES:
        found=[c for c in app.get('cases',[])if(c['mode'],c['policy'])==(mode,policy)]
        need(len(found)<=1,'one actual case per fixed app lane')
        case=found[0]if found else {};comparison=case.get('comparison',{});pair=case.get('native_pair',{})
        value['cases'].append(dict(mode=mode,policy=policy,status=case.get('status','unexecuted'),
            **process_counts(r,[case],1),application={k:case.get('application',{}).get(k)for k in
                ('application_completed','output_bytes','output_sha256')},
            comparison={k:comparison.get(k)for k in('accepted','operations','sampled','record_bytes','record_sha256',
                'global_counts','publication_qualified','capacity_stress_qualified','max_retained_at_fixture_retire')},
            native_xstate_joined=pair.get('native_xstate_joined',False),full_state_qualified=pair.get('full_state_qualified',False),
            reuse=case.get('cache_reuse'),trace_run=case.get('trace_run'),
            reports_replayed=case.get('reports_replayed',False),
            failure_type=case['error'].split(':',1)[0]if case.get('error')else None))
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<10240 and not any(x and len(x)>1 and x in text for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact numeric public receipt without private paths/names')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)



def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-run-reuse-app-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**lane.PUBLIC_BOUNDS)
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-selected-run-reuse-app-v1',scope='Normal main/DSO with default rseq and fixed64-page generation-aware MOV/NOP cache. Fresh seed and18-operation/36-state native reference; both unchanged Native/Scripted state18 pairs precede either9216-effect stress lane. Each lane requires real retirement/republication and exact terminal binary/report joins. All-seven/masked-CPUID and standalone cache oracle remain separate; no full-B2 or performance credit.',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_selected_run_reuse_app.py','--expect-revision',a.expect_revision])
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
        lane.finalize(r)
    def run(name,argv,profile='metadata',expected=0,env=None,record=False,step=False):
        stable();need(not any(x['name']==name for x in commands),'unique command/capture names')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=bounds[profile],capture_limit=16<<20,
                 environment=dict(ENV if env is None else env),expected_exit=expected);commands.append(row)
        try:
            out,err=(program_invoke if name in('state-native','state-scripted','stress-native','stress-scripted')else invoke)(row,private,cpu,record=record,step=step)
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
        lane.execute(builder,products,ROOT,private,pin,binary,aliases,run,r)
        need(r['app']['status']=='passed'and not r['final_errors'],
             'fresh source-built inputs, seed/native reference and all four complete app lanes')
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
        for label,fn in(('closure',stable),('namespace',lambda:lane.finalize(r))):
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
