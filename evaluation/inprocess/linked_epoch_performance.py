#!/usr/bin/env python3
"""Fixed62 release comparison after all reachable-mechanism prerequisites.

Ten native/linked/DynamoRIO samples per workload and two separate maps DIFF
subjects. The old failed82 profile remains a distinct, unchanged experiment.
"""
import argparse,csv,importlib.util,io,json,os,platform,re,shutil,statistics,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
from unrolled_hash_performance import (
    ROOT,HERE,ENV,need,fact,digest,save,Build,BUILD_PROFILES,BOUNDS,hardware,
    before_default,finalize,invoke,program_invoke,source,SELECTED,DEPENDENCIES,
    prerequisite as unrolled_prerequisite)
from page_cost_compare import PROGRAM_ENV,pair,build_dr,dr_diagnostics,LANE_ORDER
from linked_epoch_build import build_bridge
import maps_view as maps
import scalar_reuse_performance as reuse
import current_custody_performance as custody
import scalar_span_trace_performance as span
import linked_epoch as qualification
import linked_epoch_performance_reports as reports

LANES=('native','linked','dynamorio','differential')
ORDER=tuple((kind,repeat,'linked'if lane=='gated'else lane)for repeat in range(10)
    for kind in(('ls','true')if repeat%2==0 else('true','ls'))
    for lane in LANE_ORDER[repeat%6])+(('ls',0,'differential'),('true',0,'differential'))
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
RECEIPTS=('component_receipt','owner_receipt','region_decoder_receipt','region_component_receipt',
    'reuse_owner_receipt','current_component_receipt','current_owner_receipt',
    'span_component_receipt','linked_epoch_receipt')
REQUIRED=reuse.REQUIRED|custody.REQUIRED|set(span.component.LEAVES)|{
    'evaluation/inprocess/linked_epoch.py','evaluation/inprocess/linked_epoch_build.py',
    'evaluation/inprocess/linked_epoch_performance.py',
    'evaluation/inprocess/linked_epoch_performance_reports.py',
    'evaluation/inprocess/linked_epoch_terminal.py',
    'evaluation/inprocess/linked_epoch_cache_reports.py'}

def reproduce(a):
    return [x for key in RECEIPTS[2:]for x in('--'+key.replace('_','-'),str(getattr(a,key)))]+['--sdk','${SDK}']

def prerequisites(a,r,pin,binary):
    reuse.prerequisites(a,r,pin,binary)
    custody.prerequisites(a,r,pin,binary)
    r['prerequisites']['span_component']=span.span_component(a,r,pin,binary)
    r['prerequisites']['linked_epoch']=qualification.prerequisite(a.linked_epoch_receipt,r,pin,binary)
    need(r['prerequisites']['linked_epoch']['profile']=='linked-epoch-finite-v2',
         'only complete23 including actual retry witness and all four required helper failures')
    need(set(r['prerequisites'])=={'component','owner','region_decoder','region_component',
        'reuse_owner','current_component','current_owner','span_component','linked_epoch'},
        'all nine distinct same-source/CPU reachable-mechanism prerequisites')

def cohort(builder,products,private,pin,binary,aliases,run,r,a,builders):
    retained={k:dict(fact(v),mode=v.stat().st_mode&0o777)for k,v in products.items()}
    root=private/'linked-build';root.mkdir();state=r['linked_build']={}
    def labelled(name,argv,**kwargs):return run('linked-'+name,argv,**kwargs)
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,selected,pin,aliases,labelled,state)
        return labelled(name,argv,profile=profile,env=env,expected=expected)
    selected=Build(state,root,pin,binary,build_run,extra_decoder_sources=('region.rs',),
        scalar_span=True,linked_epoch=True)
    builders.append(selected);linked_products=selected.prepare()
    need({k:dict(fact(v),mode=v.stat().st_mode&0o777)for k,v in products.items()}==retained,
         'default retained artifacts remain exact after sequential linked build')
    r['linked_archive']=fact(linked_products['archive'])
    r['release_builds']={};bridges={};roots={}
    for lane in ('linked','differential'):
        root=private/lane;root.mkdir();roots[lane]=root;state=r['release_builds'][lane]={}
        def labelled(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
        bridges[lane]=build_bridge(selected,linked_products,root,pin,binary,aliases,labelled,state,
                                  ('MAPS_DIFFERENTIAL',)if lane=='differential'else())
        built=state['release_build'];qualified=r['prerequisites']['linked_epoch']
        need(built['archive']==qualified['archive']==r['linked_archive']and built['capture_config']is None,
             'same actual qualified linked archive, without protected capture instrumentation')
        need({k:built['linked_binding'][k]for k in('version','archive','policy_sha256','header')}==qualified['binding'],
             'same exact qualified immutable-proof policy/header')
    normal=r['release_builds']['linked']['release_build']['argv']
    diagnostic=r['release_builds']['differential']['release_build']['argv']
    need([x.replace(str(roots['differential']),str(roots['linked']))for x in diagnostic
         if x!='-DLI2_MAPS_DIFFERENTIAL=1']==normal,
         'DIFF and normal release differ only by diagnostic macro and output')
    spec=importlib.util.spec_from_file_location('linked_performance_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={};states={}
    for lane in ('linked','differential'):
        for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]:
            states[kind,lane]=pair.prepare_workload(kind+'-'+lane,path,args,bridges[lane],builder,private,pin,binary,run,r,namespace)
    for kind in ('ls','true'):
        need(all(r[key][kind+'-linked']==r[key][kind+'-differential']for key in
             ('system_inputs','namespace_plans','external_inputs')),'identical original/interpreter/dependency inputs')
    drrun,client,dr_env=build_dr(a.sdk,builder,private,pin,binary,run,r)
    dr_diagnostics(drrun,client,{k:states[k,'linked']for k in('ls','true')},private,pin,binary,run,r,dr_env)
    need(len(r['dr_diagnostics'])==3 and all(x['status']=='passed'for x in r['dr_diagnostics']),
         'actual DR target/client mappings and successful/failed target exit diagnostics')
    r['terminal_reports']={};r['reader_controls']={}
    for ordinal,(kind,repeat,lane)in enumerate(ORDER):
        name=NAMES[ordinal];s=states[kind,'differential'if lane=='differential'else'linked']
        case=r['cases'][ordinal];case['status']='failed';env=PROGRAM_ENV;ns=None
        if lane=='native':argv=s['argv']
        elif lane=='dynamorio':
            argv=[drrun,'-quiet','-64','-root',drrun.parent.parent,'-c',client,'--',*s['argv']];env=dr_env
        else:
            ns=private/(name+'-namespace')
            argv=[builder.tools['python'],'-B',s['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
                  '--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        start=len(r['commands'])
        try:
            row,out,err=run(name,argv,profile='program_dr'if lane=='dynamorio'else'program',env=env)
            need(out==(b'.\n'if kind=='ls'else b''),'exact complete real-program output')
            if ns is None:need(err==b'','native/DR stderr empty')
            else:
                pair.namespace_join(s,ns,binary,r,namespace)
                args=(row['pid'],row['exit'],row['stdout_provenance_before'],s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'])
                observed=reports.check(out,err,args,kind,lane)
                controls=reports.controls(out,err,args,kind,lane)
                r['terminal_reports'][name]=observed;r['reader_controls'][name]=controls
                case.update(observed=observed)
            case['status']='passed'
        except Exception as exc:
            case['error']=type(exc).__name__+': '+str(exc)
            if r['error']is None:r['error']=case['error']
            actual=r['commands'][start:]
            need(len(actual)==1 and actual[0]['name']==name and type(actual[0].get('exit'))is int and
                 actual[0].get('reaped')is True and actual[0].get('cleanup_errors')==[]and
                 all(d.get('closed')is True for d in actual[0].get('descriptors',[])),
                 'continue after failed subject only when actual process and descriptors are closed')
        finally:
            attempted=[c for c in r['commands'][start:]if c['name']==name]
            if attempted:
                row=attempted[-1];case.update({k:row.get(k)for k in('exit','process_ns','timed_out','reaped','user_cpu_ns','system_cpu_ns',
                    'minor_faults','major_faults','voluntary_switches','involuntary_switches')})
                case['captures']={k:{f:v[f]for f in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
            print(json.dumps({k:case.get(k)for k in('ordinal','workload','lane','status','exit','process_ns','error')}),flush=True)
    need(len(r['cases'])==62 and all(c['status']=='passed'for c in r['cases'])and r['error']is None,
         'all62 fixed attempts, both differential subjects, no dropped/replaced runs')

def publish(path,r,private):
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    linked_fields='offers closed resumed refaults hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed events plan_checks rseq_checks live_checks proof_checks'.split()
    native_fields='attempts admissions closed blocked epoch_exits refaults main_admissions main_refaults'.split()
    columns=fields+['maps.'+k for k in maps.KEYS]+['linked.'+k for k in linked_fields]+[
        'signals.'+k for k in('SEGV','TRAP','ILL','SYS','other')]+['physical_fresh_maps']+['native.'+k for k in native_fields]+[
        'linked_refused.'+k for k in('unsupported','boundary','graph','relocation')]+[
        'first_admission_ns','admission_revisit_samples','admission_revisit_sum_ns']
    rows=[]
    for c in r['cases']:
        observed=c.get('observed',{});view=observed.get('maps_view',{});linked=observed.get('linked',{})
        summary=observed.get('summary',{});native=summary.get('native',{});timing=summary.get('admission_timing',{})
        rows.append([c.get(k)for k in fields]+[view.get(k)for k in maps.KEYS]+[linked.get(k)for k in linked_fields]+
            linked.get('signals',[None]*5)+[view['refreshes']+view['comparisons']if view else None]+[native.get(k)for k in native_fields]+
            linked.get('refusals',[None]*4)+[timing.get('first_admission_ns'),timing.get('revisit_count'),
                sum(timing['revisit_ns'])if timing else None])
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns);writer.writerows(rows)
    data=stream.getvalue().encode();complete=r['status']=='passed'and r['source_unchanged']and r['cleanup_complete']and not r['final_errors']and len(r['cases'])==62 and all(c['status']=='passed'for c in r['cases'])
    stats={}
    for kind in('ls','true'):
        stats[kind]={}
        for lane in LANES:
            cases=[c for c in r['cases']if c['workload']==kind and c['lane']==lane]
            times=[c['process_ns']for c in cases if c['status']=='passed']
            row=stats[kind][lane]=dict(planned=1 if lane=='differential'else 10,passed=len(times),timing_credit=bool(complete and lane!='differential'))
            if row['timing_credit']:
                need(len(times)==10,'all ten actual times');q=statistics.quantiles(times,n=4,method='inclusive')
                row.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
        if complete:
            stats[kind]['linked_ratios']={lane:stats[kind]['linked']['median_ns']/stats[kind][lane]['median_ns']for lane in('native','dynamorio')}
            stats[kind]['within_10x_dynamorio']=stats[kind]['linked_ratios']['dynamorio']<=10
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu','bounds','reproduce','archive','linked_archive','prerequisites')}
    hw=dict(value['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags));value['hardware']=hw
    value.update(statistics=stats,columns=columns,rows=rows,private_receipt=fact(private/'receipt.json'),
        csv=dict(file=path.with_suffix('.csv').name,bytes=len(data),sha256=maps.H(data)),
        commands=len(r['commands']),commands_sha256=digest(r['commands']),
        case_error_types={str(c['ordinal']):c['error'].split(':',1)[0]for c in r['cases']if c.get('error')},
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
        reader_controls={name:dict(count=len(v['refusals']),sha256=digest(v))for name,v in r.get('reader_controls',{}).items()},
        retained_inputs_sha256=digest(r.get('inputs_before',{})),retained_artifacts_sha256=digest(r.get('artifacts_before',{})),
        sdk_files=len(r.get('dynamorio_sdk',{})),sdk_manifest_sha256=digest(r.get('dynamorio_sdk',{})),
        dynamorio_client=r.get('dynamorio_client'),dynamorio_build_commands_sha256=r.get('dynamorio_build_commands_sha256'),
        dr_diagnostics=[{k:v for k,v in x.items()if k!='error'}for x in r.get('dr_diagnostics',[])],
        qualification_scope='Distinct finite linked epoch. All reachable unchanged mechanism prerequisites plus linked metadata/native/fault/refusal/cache-replacement controls required. Old span failed82 remains failed. This is no claim of unrestricted application support.',
        timing_scope='Actual pre-Popen through reap, including startup and reports. Ten samples per ordinary lane/workload; medians and inclusive IQR only after all62 and final closure pass. DIFF and DR identity diagnostics have no timing credit.',
        count_scope='Actual terminal counters; physical fresh maps=refreshes+comparisons. Native/DR have no invented event counts. Entries are not inferred instruction counts or saved traps.',
        tool_versions={k:v.get('numeric_versions')for k,v in(('default',r.get('build',{})),('linked',r.get('linked_build',{}).get('build',{})))})
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<=96<<10 and len(data)<=32<<10 and not any(x and len(x)>1 and(x in text or x in stream.getvalue())for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded public numeric summary, no private paths or logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as out:out.write(data)
    with path.open('x')as out:out.write(text)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    for key in RECEIPTS:ap.add_argument('--'+key.replace('_','-'),type=Path,required=True)
    ap.add_argument('--sdk',type=Path,required=True)
    a=ap.parse_args();extra_builders=[];order=ORDER;names=NAMES
    for key in RECEIPTS:
        path=getattr(a,key).resolve(strict=True).relative_to(ROOT)
        need(path.parent==Path('evaluation/inprocess/results')and path.suffix=='.json','exact public prerequisite location')
        setattr(a,key,path)
    need(len({str(getattr(a,key))for key in RECEIPTS})==9,'nine distinct actual qualification receipts')
    a.sdk=a.sdk.resolve(strict=True)
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    a.component_receipt=a.component_receipt.resolve().relative_to(ROOT);a.owner_receipt=a.owner_receipt.resolve().relative_to(ROOT)
    need(all(p.parent==Path('evaluation/inprocess/results')and p.suffix=='.json'for p in(a.component_receipt,a.owner_receipt)),'public qualification receipts inside evaluation results')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-linked-epoch-performance-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS,finite=[5,512<<20,16<<20,15])
    bounds['program_dr']=[30,16<<30,16<<20,60]
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='linked-epoch-performance-v1',scope='Fixed62 native/linked/DynamoRIO and maps differential subjects after nine same-source/CPU prerequisites',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[dict(ordinal=i,workload=k,repeat=n,lane=l,status='not_run') for i,(k,n,l) in enumerate(order)],error=None,final_errors=[],
        finite_cases=[dict(mode=i,expected_exit=exit,status='not_run',qualified_case=0,supplied_return_control=(i==4),performance_credit=False)for i,exit in enumerate((0,125,125,125,125,0))],
        reproduce=['python3','evaluation/inprocess/linked_epoch_performance.py','--expect-revision',a.expect_revision,'--component-receipt',str(a.component_receipt),'--owner-receipt',str(a.owner_receipt)])
    r['reproduce']+=reproduce(a)
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
            out,err=(program_invoke if name in names else invoke)(row,private,cpu,record=record,step=step)
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
        required={b'evaluation/inprocess/maps_view.py',b'tools/page-entry/selected/maps_view.h',b'tools/page-entry/selected/maps_view.inc',
            *[('tools/page-entry/selected/tests/maps_view/'+x).encode()for x in('oracle.c','build.sh','check.py')]}
        required|={b'evaluation/inprocess/unrolled_hash_performance.py',b'evaluation/inprocess/unrolled_hash_build.py',b'evaluation/inprocess/unrolled_hash_reports.py',b'tools/page-entry/selected/build-unrolled-hash.sh',b'tools/page-entry/selected/unrolled_hash.h',b'tools/page-entry/selected/selected_unrolled_hash.inc'}
        required|={p.encode()for p in REQUIRED}
        need(required<=set(out.split(b'\0')),'new harness and maintained body are tracked at the requested revision')
        for name in out.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT)and Path(p).suffix=='.py':pin(p)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload');r['configuration_presence']=presence
        need(DEPENDENCIES,'fixed unchanged process/terminal/build helper inputs')
        for name,want in DEPENDENCIES.items():pin(ROOT/name,want)
        for name in('maps_view.h','maps_view.inc'):pin(SELECTED/name)
        for name in('oracle.c','build.sh','check.py'):pin(SELECTED/'tests/maps_view'/name)
        r['prerequisites']={k:unrolled_prerequisite(path,a.expect_revision,pin,binary,k)for k,path in(('component',a.component_receipt),('owner',a.owner_receipt))}
        prerequisites(a,r,pin,binary)
        r['reproduce']=['python3','evaluation/inprocess/linked_epoch_performance.py','--expect-revision',a.expect_revision,'--component-receipt',str(a.component_receipt.resolve().relative_to(ROOT)),'--owner-receipt',str(a.owner_receipt.resolve().relative_to(ROOT))]
        r['reproduce']+=reproduce(a)
        products=builder.prepare();r['archive']=fact(products['archive'])
        maps.finite(builder,private,pin,binary,aliases,run,r)
        cohort(builder,products,private,pin,binary,aliases,run,r,a,extra_builders)
        need(not r['final_errors'],'no retained command errors')
        r['status']='passed'
    except BaseException as error:
        if r['error']is None:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            for m in tuple(sys.modules.values()):
                path=getattr(m,'__file__',None)
                if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        except BaseException as error:r['final_errors'].append('final imported source closure: '+repr(error))
        for additional in extra_builders:
            try:r['final_errors'].extend(additional.finish())
            except BaseException as error:r['final_errors'].append('region build finalization: '+type(error).__name__+': '+str(error))
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
        save(private/'receipt.json',r)
        publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),commands=len(commands),
                             failure_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
