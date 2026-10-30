#!/usr/bin/env python3
"""Fixed retained-loop experiment, after same-revision hardware and owner qualification."""
import argparse,copy,csv,hashlib,importlib.util,io,json,os,platform,re,shutil,statistics,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_cost_compare import (ENV,fact,need,save,source,hardware,Build,BUILD_PROFILES,BOUNDS,
    SELECTED,UNITS,MACROS,PROGRAM_ENV,invoke,program_invoke,finalize,before_default,
    recipe,expand,headers,bridge_check,hidden_memset,body_check,pair,cost_reports,digest,
    elf,interpreter,resolved_libraries)
from page_selected_maps_headers import observe as observe_headers
import maps_view as maps
import unrolled_hash_reports as reports
from unrolled_hash_build import build_bridge
LANES=('observe','unrolled','differential')
EXTRA=(('UNROLLED_HASH_OBSERVE_ONLY',),(),('MAPS_DIFFERENTIAL',))
ORDER=tuple((kind,repeat,lane)for repeat in range(10)
    for kind in (('ls','true')if repeat%2==0 else('true','ls'))
    for lane in (LANES[:2]if repeat%2==0 else LANES[1::-1]))+(
    ('ls',0,'differential'),('true',0,'differential'))
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
H=lambda b:hashlib.sha256(b).hexdigest()
KEYS=maps.KEYS
ROUTES=maps.ROUTES
UNROLLED_KEYS=tuple(k for k in reports.KEYS if k not in ('current','signals'))
DEPENDENCIES=dict(maps.DEPENDENCIES,**{'evaluation/inprocess/maps_view.py':{'bytes': 34110, 'sha256': 'b4a0a9bd8fd72a35514416d32bed96bada9f3ae92e9e42f290b5e2f42a623687'}})


def prerequisite(public,revision,pin,binary,kind):
    """Bind complete retained qualification, including every immutable artifact."""
    public=pin(public)
    need(public.parent==HERE/'results'and public.suffix=='.json','tracked evaluation result location')
    value=json.loads(public.read_bytes());private=ROOT/'target/evaluation/inprocess'/public.stem/'receipt.json'
    need(fact(pin(private))==value['private_receipt'],'exact private qualification receipt')
    actual=json.loads(private.read_bytes())
    profile,status=('bounded-unrolled-hash-component-v1','passed_component')if kind=='component'else('unrolled-hash-owner-v1','passed')
    for record in(value,actual):
        need(record['profile']==profile and record['status']==status and record['expected_revision']==revision and
             record['source']==source()and record['source_unchanged']is True and record['cleanup_complete']is True,
             'complete same-revision '+kind+' qualification')
    need(actual['error']is None and actual['final_errors']==[]and value['final_error_count']==0 and value['totals']==actual['totals'],
         'no qualification failure and one exact total population')
    if kind=='component':
        need(actual['totals']==dict(required_modes=9,launch_attempts=9,launched=9,observed_exits=9,qualified=9,
             completed_chunks=7,completed_loops=6,required_read_failures=2,reader_refusals=373),
             'all nine hardware comparisons and373 refusal controls')
        need([c['mode']for c in actual['cases']]==list(range(9))and
             [c['status']for c in actual['cases']]==['qualified_component']*7+['qualified_required_failure']*2,
             'unchanged complete finite component population')
    else:
        required=dict(planned=25,launched=25,qualified=25,native=9,gated=9,owner_controls=7,qualified_pairs=9,
             required_read_faults=2,required_owner_refusals=7,completed_applications=14,required_reference_faults=2)
        need(all(type(actual['totals'].get(k))is int and actual['totals'][k]==v for k,v in required.items()),
             'all25 actual original/owner cases and two separate fault populations')
    need(actual['inputs_before']==actual['inputs_after']and actual['artifacts_before']==actual['artifacts_after'],
         'qualification input/artifact closure')
    for path,want in actual['inputs_before'].items():pin(path,want)
    for path,want in actual['artifacts_before'].items():
        retained=binary(path);need(dict(fact(retained),mode=retained.stat().st_mode&0o777)==want,'exact retained qualification artifact')
    aliases=actual.get('aliases_before',actual.get('aliases'))
    need(type(aliases)is dict and aliases and (actual.get('aliases_after',aliases)==aliases),'complete qualification alias closure')
    for lexical,resolved in aliases.items():need(str(pin(lexical))==resolved,'unchanged qualification alias')
    commands=actual['commands']
    need(commands and all(type(c.get('exit'))is int and c.get('reaped')is True and c.get('timed_out')is False and
         not c.get('error')and c.get('cleanup_errors')==[]and all(d.get('closed')is True for d in c.get('descriptors',[]))for c in commands),
         'every qualification command closed and reaped without timeout')
    need(actual['build']['status']=='passed'and actual['build']['command_completed']is True and
         all(c.get('expected_exit')is None or c['exit']==c['expected_exit']for c in commands),'completed exact build and every expected qualification outcome')
    expected=value.get('command_count',value.get('commands'))
    need(type(expected)is int and expected==len(commands)and value.get('commands_sha256',value.get('command_rows_sha256'))==digest(commands),
         'actual qualification command population and digest')
    csv_path=public.with_suffix('.csv');need(value['csv']['file']==csv_path.name and
         fact(pin(csv_path))=={k:value['csv'][k]for k in('bytes','sha256')},'qualification CSV binding')
    return dict(file=public.name,**fact(public),private_receipt=fact(private),profile=profile,status=status,totals=actual['totals'])


def cohort(builder,products,private,pin,binary,aliases,run,r):
    roots={};bridges={};r['release_builds']={}
    for lane,extra in zip(LANES,EXTRA,strict=True):
        root=private/lane;root.mkdir();roots[lane]=root;state=r['release_builds'][lane]={}
        def labelled(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
        bridges[lane]=build_bridge(builder,products,root,pin,binary,aliases,labelled,state,extra)
    plain=r['release_builds']['unrolled']['release_build']['argv']
    for lane,extra in zip(LANES,EXTRA,strict=True):
        argv=r['release_builds'][lane]['release_build']['argv']
        normalized=[x.replace(str(roots[lane]),str(roots['unrolled']))for x in argv
            if x not in['-DLI2_'+m+'=1'for m in extra]]
        need(normalized==plain,'only declared diagnostic macro and output directory differ')
    spec=importlib.util.spec_from_file_location('maps_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={};states={}
    for lane in LANES:
        for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]:
            states[kind,lane]=pair.prepare_workload(kind+'-'+lane,path,args,bridges[lane],builder,private,pin,binary,run,r,namespace)
    for kind in('ls','true'):
        for lane in LANES[1:]:
            need(all(r[key][kind+'-observe']==r[key][kind+'-'+lane]for key in('system_inputs','namespace_plans','external_inputs')),
                 'identical whole original/interpreter/dependency inputs across variants')
    r['terminal_reports']={};r['reader_controls']={}
    for ordinal,(kind,repeat,lane)in enumerate(ORDER):
        name=NAMES[ordinal];s=states[kind,lane];case=r['cases'][ordinal];case['status']='failed';ns=private/(name+'-namespace')
        argv=[builder.tools['python'],'-B',s['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
              '--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        try:
            row,out,err=run(name,argv,profile='program',env=PROGRAM_ENV)
            pair.namespace_join(s,ns,binary,r,namespace)
            args=(row['pid'],row['exit'],row['stdout_provenance_before'],s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'])
            parsed,summary,view,owner,suffix=reports.check(out,err,args,kind,lane)
            r['terminal_reports'][name]=parsed;r['reader_controls'][name]=reports.controls(out,err,args,kind,lane)
            routes=[parsed[k][f]for k,fields in ROUTES.items()for f in fields]
            need(all(type(x)is int and 0<=x<1<<64 for x in routes),'actual unsigned overlapping route counters')
            case.update(status='passed',comparison=summary,maps_view=view,unrolled=owner,routes=routes)
        except Exception as exc:
            case['error']=type(exc).__name__+': '+str(exc)
            if r['error']is None:r['error']=case['error']
            need(r['commands']and r['commands'][-1]['name']==name and r['commands'][-1].get('reaped')is True and
                 not r['commands'][-1].get('cleanup_errors')and
                 all(d['closed']for d in r['commands'][-1].get('descriptors',[])),
                 'continue only after this actual subject reaped with every descriptor closed')
        finally:
            attempted=[c for c in r['commands']if c['name']==name]
            if attempted:
                row=attempted[-1];case.update({k:row.get(k)for k in('exit','process_ns','timed_out','reaped','user_cpu_ns','system_cpu_ns',
                    'minor_faults','major_faults','voluntary_switches','involuntary_switches')})
                case['captures']={k:{f:v[f]for f in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
            print(json.dumps({k:case.get(k)for k in('ordinal','workload','lane','status','exit','process_ns','error')}),flush=True)
    need(len(r['cases'])==42 and all(c['status']=='passed'for c in r['cases'])and r['error']is None,
         'all42 fixed attempts complete; no replacement or dropped failure')


def publish(path,r,private):
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    columns=fields+['unrolled.'+k for k in UNROLLED_KEYS]+['signals.'+k for k in('SEGV','TRAP','ILL','SYS','other')]+['maps_view.'+k for k in KEYS]+['derived.physical_fresh_requests']+[k+'.'+f for k,fs in ROUTES.items()for f in fs]
    rows=[[c.get(k)for k in fields]+([c['unrolled'][k]for k in UNROLLED_KEYS]+c['unrolled']['signals']if c.get('unrolled')else[None]*(len(UNROLLED_KEYS)+5))+([c['maps_view'][k]for k in KEYS]if c.get('maps_view')else[None]*len(KEYS))+
          [c['maps_view']['refreshes']+c['maps_view']['comparisons']if c.get('maps_view')else None]+
          c.get('routes',[None]*sum(map(len,ROUTES.values())))for c in r['cases']]
    buf=io.StringIO(newline='');writer=csv.writer(buf,lineterminator='\n');writer.writerow(columns);writer.writerows(rows);data=buf.getvalue().encode()
    complete=r['status']=='passed'and r['source_unchanged']and r['cleanup_complete']and not r['final_errors']
    stats={}
    for kind in('ls','true'):
        stats[kind]={}
        for lane in LANES:
            cases=[c for c in r['cases']if c['workload']==kind and c['lane']==lane]
            times=[c['process_ns']for c in cases if c['status']=='passed']
            item=stats[kind][lane]=dict(planned=1 if lane=='differential'else 10,passed=len(times),timing_credit=complete and lane!='differential')
            if complete and lane!='differential':
                need(len(times)==10,'all10 actual measured samples retained')
                q=statistics.quantiles(times,n=4,method='inclusive');item.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
        if complete:
            a,b=(stats[kind][lane]['median_ns']for lane in LANES[:2])
            stats[kind]['unrolled_to_observe_median_ratio']=b/a
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu','bounds','reproduce','archive','carriers','system_inputs','prerequisites')}
    value.update(statistics=stats,quantiles='inclusive linear interpolation at (n-1)*p; all10 samples per measured lane/workload',
        scope='Required cohort: same-revision9-case hardware and25-case actual-owner qualification, six actual-TU maps modes, then42 real gated launches:40 observe-only/unrolled timing samples and2 differential validations. All old application/owner gates and limits retained. No native or DynamoRIO lane.',
        timing_scope='Actual pre-Popen through reap intervals include startup and reporting. Differential timing receives no performance credit. No dropped samples or fixed speed threshold.',
        count_scope='Maps counts include bootstrap; physical fresh requests=refreshes+comparisons. Actual handler events and disjoint SEGV/TRAP/ILL/SYS/other counts begin after existing nonreturning rseq entry guards and include bootstrap self-tests; failed runs claim no complete totals. Old routes overlap and are not summed. Observe-only retains both same fixed arenas and signal counters but never tries the new tactic. No ptrace inference.',
        columns=columns,rows=rows,commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'),csv=dict(file=path.with_suffix('.csv').name,bytes=len(data),sha256=H(data)),
        tool_versions=r.get('build',{}).get('numeric_versions'),
        finite_scope='Six required actual-TU modes; four required refusals include the supplied READ_IMPLIES_EXEC return control. No performance or application-completion credit.',
        finite_cases=[{k:v for k,v in c.items()if k!='error'}for c in r['finite_cases']],
        finite_error_types={str(c['mode']):c['error'].split(':',1)[0]for c in r['finite_cases']if c.get('error')},
        finite_build={k:r.get('finite_build',{})[k]for k in('status','executable','runtime_inputs')if k in r.get('finite_build',{})},
        release_builds={k:{n:s['release_build'][n]for n in('status','recipe','archive','bridge')if n in s.get('release_build',{})}for k,s in r.get('release_builds',{}).items()},
        reader_controls={k:dict(original=len(v['original']['original']['refusals']),maps_view=len(v['original']['maps_view_refusals']),unrolled=len(v['unrolled_refusals']),raw_stderr_sha256=v['original_stderr_sha256'])for k,v in r.get('reader_controls',{}).items()},
        captures={str(c['ordinal']):c.get('captures',{})for c in r['cases']},
        case_error_types={str(c['ordinal']):c['error'].split(':',1)[0]for c in r['cases']if c.get('error')},
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']))
    value['hardware']=dict(value['hardware']);flags=value['hardware'].pop('isa_flags');value['hardware']['isa_flags_sha256']=digest(flags)
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<96<<10 and len(data)<32<<10 and not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),
         'bounded public numeric result without host paths/logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as f:f.write(data)
    with path.open('x')as f:f.write(text)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);ap.add_argument('--component-receipt',type=Path,required=True);ap.add_argument('--owner-receipt',type=Path,required=True)
    ap.add_argument('--scalar-reuse',action='store_true')
    ap.add_argument('--current-custody',action='store_true')
    ap.add_argument('--current-component-receipt',type=Path)
    ap.add_argument('--current-owner-receipt',type=Path)
    for option in ('region-decoder-receipt','region-component-receipt','reuse-owner-receipt','sdk'):ap.add_argument('--'+option,type=Path)
    a=ap.parse_args();extension=None;extra_builders=[]
    need(not(a.scalar_reuse and a.current_custody),'one explicit performance profile')
    need(a.current_custody or(a.current_component_receipt is None and a.current_owner_receipt is None),
         'current receipts require explicit current-custody profile')
    if a.current_custody:
        import current_custody_performance as extension
        extension.arguments(a)
    elif a.scalar_reuse:
        import scalar_reuse_performance as extension
        extension.arguments(a)
    else:need(all(getattr(a,k)is None for k in ('region_decoder_receipt','region_component_receipt','reuse_owner_receipt','sdk')),
              'additional receipts/SDK require explicit scalar-reuse profile')
    order=extension.ORDER if extension else ORDER;names=extension.NAMES if extension else NAMES
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    a.component_receipt=a.component_receipt.resolve().relative_to(ROOT);a.owner_receipt=a.owner_receipt.resolve().relative_to(ROOT)
    need(all(p.parent==Path('evaluation/inprocess/results')and p.suffix=='.json'for p in(a.component_receipt,a.owner_receipt)),'public qualification receipts inside evaluation results')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+('-current-custody-performance-'if a.current_custody else '-scalar-reuse-performance-'if extension else'-unrolled-hash-performance-')+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS,finite=[5,512<<20,16<<20,15])
    if extension:bounds['program_dr']=[30,16<<30,16<<20,60]
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='unrolled-hash-performance-v1',scope='42 fixed observe-only/unrolled/differential attempts after full component/owner qualification; original limits and terminal gates retained',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[dict(ordinal=i,workload=k,repeat=n,lane=l,status='not_run') for i,(k,n,l) in enumerate(order)],error=None,final_errors=[],
        finite_cases=[dict(mode=i,expected_exit=exit,status='not_run',qualified_case=0,supplied_return_control=(i==4),performance_credit=False)for i,exit in enumerate((0,125,125,125,125,0))],
        reproduce=['python3','evaluation/inprocess/unrolled_hash_performance.py','--expect-revision',a.expect_revision,'--component-receipt',str(a.component_receipt),'--owner-receipt',str(a.owner_receipt)])
    if extension:r.update(profile='current-custody-performance-v1'if a.current_custody else'scalar-reuse-performance-v1',scope='All82 fixed launches after four same-revision prerequisites; no aggregate credit unless complete'if a.current_custody else'All82 fixed launches after five same-revision prerequisites; no aggregate credit unless complete',reproduce=r['reproduce']+extension.reproduce(a))
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
        if extension:required|={p.encode()for p in extension.REQUIRED}
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
        r['prerequisites']={k:prerequisite(path,a.expect_revision,pin,binary,k)for k,path in(('component',a.component_receipt),('owner',a.owner_receipt))}
        if extension:extension.prerequisites(a,r,pin,binary)
        r['reproduce']=['python3','evaluation/inprocess/unrolled_hash_performance.py','--expect-revision',a.expect_revision,'--component-receipt',str(a.component_receipt.resolve().relative_to(ROOT)),'--owner-receipt',str(a.owner_receipt.resolve().relative_to(ROOT))]
        if extension:r['reproduce']+=extension.reproduce(a)
        products=builder.prepare();r['archive']=fact(products['archive'])
        maps.finite(builder,private,pin,binary,aliases,run,r)
        if extension:extension.cohort(builder,products,private,pin,binary,aliases,run,r,a,extra_builders)
        else:cohort(builder,products,private,pin,binary,aliases,run,r)
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
        (extension.publish if extension else publish)(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),commands=len(commands),
                             failure_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
