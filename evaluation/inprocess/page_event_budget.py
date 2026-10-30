#!/usr/bin/env python3
"""Twelve fixed gated launches; additive same-run event/time diagnostic, no DR lane."""
import argparse,copy,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,statistics,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_cost_compare import (ENV,fact,need,save,source,hardware,Build,BUILD_PROFILES,BOUNDS,
    SELECTED,UNITS,MACROS,PROGRAM_ENV,invoke,program_invoke,finalize,before_default,
    recipe,expand,headers,bridge_check,hidden_memset,body_check,pair,cost_reports,digest)
ORDER=tuple((kind,repeat,lane)for repeat in range(3)
    for kind in (('ls','true')if repeat%2==0 else('true','ls'))
    for lane in (('unobserved','events')if repeat%2==0 else('events','unobserved')))
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
H=lambda b:hashlib.sha256(b).hexdigest()
MASK=(1<<64)-1
# Exact e4d3 C profile plus r1 timing and r2/r3 sealed-source diagnostic guards.
EVENT_SOURCES = {'tools/page-entry/selected/runtime_loader.c': {'bytes': 39736, 'sha256': '27cd97f9933dece289da635ba1da00afd1bf66c28ae596052055bd17d314627b'}, 'tools/page-entry/bridge.c': {'bytes': 16621, 'sha256': '82850e8ea24b7ab79fa18ca6187089c8455f9798f4433e6b675b3a6e18a22a21'}, 'tools/page-entry/selected/lifecycle_loader.c': {'bytes': 45157, 'sha256': '1cdffde5ba024977181085970b10bf0b0c7115d12aee844cfbae91c3f49c59fb'}, 'tools/page-entry/selected/native_pair_lifecycle.inc': {'bytes': 15945, 'sha256': '6a13112496323ed8f9d974d0ff78072bc67038922af3e9c821e72810f5bd7850'}, 'tools/page-entry/selected/decoder.h': {'bytes': 2884, 'sha256': 'c09bbc5fba41c268c42d31cdb1bb9946d8ec6aa994eb4093ee7ddb5563aba70e'}, 'tools/page-entry/selected/tf_owner.h': {'bytes': 5192, 'sha256': 'b3dc4dbcac4f86158831837ec306ef8b117846bfc7ade721fdb5d859c94f9a95'}, 'tools/page-entry/selected/write_footprint.h': {'bytes': 1518, 'sha256': '80444c8cab68d34ca40145637a82ad11ae986a2eaa708f12558c1be99079b1a2'}, 'tools/page-entry/selected/tf_chain.inc': {'bytes': 32537, 'sha256': 'cf4750d74cd0036eaac7a9497bcf49af8ee039a1ea005068620d51ee87e4a41a'}, 'tools/page-entry/selected/entry.S': {'bytes': 3579, 'sha256': 'b3f0075fd106658c6f1e61dc8302b7ba307e27f69957a2323ab60aae1061cba6'}, 'tools/page-entry/selected/event_profile.h': {'bytes': 1638, 'sha256': '86681792b4ed2ef3d41b84dd384f4648402a026d50e9410b40226c5c94aa332c'}, 'tools/page-entry/selected/event_profile.inc': {'bytes': 14186, 'sha256': '03773e7b2577eb2045f3f08abe97e73179d2974d3d66a00aed79c621d706413d'}, 'tools/page-entry/selected/native_pair.h': {'bytes': 6944, 'sha256': '13df301c8f8f1fad0f965f23b88fb60b1e70a45e17d5f2e4108a16a5cb135365'}, 'tools/page-entry/selected/native_pair_report.inc': {'bytes': 6251, 'sha256': '18c782b2860b80a5f4f195c68363e5425fa59005ae89016ced43bf526516a0ba'}}
import page_event_budget_read as event_read
check = event_read.check
controls = event_read.controls


def build_cost_bridge(builder,products,private,pin,binary,aliases,run,r):
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    output=private/'release';output.mkdir();bridge_recipe=pin(SELECTED/'build-native-pair.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit two-page native release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output});argv[1:1]=['-DLI2_COST_PROFILE=1','-DLI2_EVENT_PROFILE=1'];units=[str(SELECTED.parent/x)for x in UNITS]
    need(argv[-2:]==['-o',str(output/'bridge-native-pair.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_COST_PROFILE=1','-DLI2_EVENT_PROFILE=1']+['-DLI2_'+x+'=1'for x in MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact diagnostic18-TU22-macro native pair release recipe')
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
    state['observer_clock']=event_read.clock_elf(bridge,symbols)
    state['status']='passed';return bridge



def cohort(builder,products,private,pin,binary,aliases,run,r):
    roots={};bridges={};r['release_builds']={}
    for lane in('unobserved','events'):
        root=private/lane;root.mkdir();roots[lane]=root;state=r['release_builds'][lane]={}
        def labelled(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
        bridges[lane]=(pair.build_bridge if lane=='unobserved'else build_cost_bridge)(
            builder,products,root,pin,binary,aliases,labelled,state)
    plain=r['release_builds']['unobserved']['release_build']['argv'];cost=r['release_builds']['events']['release_build']['argv']
    normalized=[x.replace(str(roots['events']),str(roots['unobserved']))for x in cost if x not in('-DLI2_COST_PROFILE=1','-DLI2_EVENT_PROFILE=1')]
    need(normalized==plain,'only two diagnostic macros and output directory differ in release recipes')
    spec=importlib.util.spec_from_file_location('counter_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={};states={}
    for lane in('unobserved','events'):
        for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]:
            states[kind,lane]=pair.prepare_workload(kind+'-'+lane,path,args,bridges[lane],builder,private,pin,binary,run,r,namespace)
    for kind in('ls','true'):
        left,right=(kind+'-'+lane for lane in('unobserved','events'))
        need(all(r[key][left]==r[key][right]for key in('system_inputs','namespace_plans','external_inputs')),
             'identical complete original/interpreter/dependency inputs in both variants')
    r['terminal_reports']={};r['reader_controls']={}
    for ordinal,(kind,repeat,lane)in enumerate(ORDER):
        name=NAMES[ordinal];s=states[kind,lane];case=r['cases'][ordinal];case['status']='failed';ns=private/(name+'-namespace')
        argv=[builder.tools['python'],'-B',s['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
              '--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        try:
            row,out,err=run(name,argv,profile='program',env=PROGRAM_ENV)
            pair.namespace_join(s,ns,binary,r,namespace)
            args=(row['pid'],row['exit'],row['stdout_provenance_before'],s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'])
            parsed,summary,cost,event,event_summary,_=check(out,err,*args,workload=kind,observed=lane=='events',process_ns=row['process_ns'],process_start_ns=row['process_start_ns'],process_reaped_ns=row['process_reaped_ns'])
            r['terminal_reports'][name]=parsed;r['reader_controls'][name]=controls(out,err,args,workload=kind,observed=lane=='events',process_ns=row['process_ns'],process_start_ns=row['process_start_ns'],process_reaped_ns=row['process_reaped_ns'])
            case.update(status='passed',comparison=summary,cost=cost,event=event,event_summary=event_summary)
        except BaseException as exc:case['error']=type(exc).__name__+': '+str(exc)
        finally:
            attempted=[c for c in r['commands']if c['name']==name]
            if attempted:
                row=attempted[-1];case.update({k:row.get(k)for k in('exit','process_ns','timed_out','reaped','user_cpu_ns','system_cpu_ns',
                    'minor_faults','major_faults','voluntary_switches','involuntary_switches')})
                case['captures']={k:{f:v[f]for f in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
            print(json.dumps({k:case.get(k)for k in('ordinal','workload','lane','status','exit','process_ns','error')}),flush=True)
    need(len(r['cases'])==12 and all(c['status']=='passed'for c in r['cases']),
         'all twelve fixed event-observer attempts complete; no replacement or dropped failure')


def publish(path,r,private):
    buf=io.StringIO(newline='');writer=csv.writer(buf,lineterminator='\n')
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    cost_names=['admission_'+x for x in('initialized','valid','busy','overflow','count','sum_ns','min_ns','max_ns')]+[
        'maps_'+x for x in('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch','active','valid','poisoned','reserved')]
    event_names=['handler_entries','handler_returns','terminal_fences','observer_clock_calls','observed_envelope_ns','handler_ns','unmeasured_process_residual_ns']+[
        kind+'_'+name for kind in('calls','exclusive_ns','inclusive_ns') for name in event_read.REGIONS]+['internal_c_raw_ptrace_attempts','internal_c_raw_ptrace_returns','internal_c_raw_ptrace_negative_returns','site_total','site_unique','site_retained','site_other']
    writer.writerow(fields+cost_names+event_names)
    for c in r['cases']:
        values=['']*len(event_names)
        if c.get('event') is not None:
            e=c['event'];v=c['event_summary']
            values=e['handlers']+[e['clock'][0],v['observed_envelope_ns'],v['handler_ns'],v['unmeasured_process_residual_ns']]+e['region_calls']+e['exclusive_ns']+e['inclusive_ns']+e['raw'][11]+[e[k] for k in('site_total','site_unique','site_retained','site_other')]
        writer.writerow([c.get(k)for k in fields]+(c['cost']['admission']+c['cost']['maps']if c.get('cost')else ['']*18)+values)
    data=buf.getvalue().encode();stats={}
    for kind in('ls','true'):
        stats[kind]={}
        for lane in('unobserved','events'):
            rows=[c for c in r['cases']if c['workload']==kind and c['lane']==lane];times=[c['process_ns']for c in rows if c['status']=='passed']
            item=stats[kind][lane]=dict(planned=3,passed=len(times))
            if len(times)==3 and r['source_unchanged']and not r['final_errors']:
                q=statistics.quantiles(times,n=4,method='inclusive');item.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
        if all('median_ns'in stats[kind][lane]for lane in('unobserved','events')):
            a,b=(stats[kind][lane]['median_ns']for lane in('unobserved','events'))
            stats[kind]['observer_overhead']=dict(median_difference_ns=b-a,median_ratio=b/a)
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu','bounds','reproduce','archive','carriers','system_inputs')}
    value.update(statistics=stats,quantiles='inclusive linear interpolation at (n-1)*p; three samples per variant/workload',
        scope='Separate same-run event budget and observer overhead. Handler intervals follow mandatory ingress guards and end before normal return or first report write. Exact original outcomes remain mandatory.',
        timing_scope='Exclusive regions partition measured handler time; inclusive, signal and route views overlap. Signal/route time divided by its count is handler-body mean, not trap latency. Process residual includes all unmeasured work and observer edges, not isolated trap cost. Old COST admission uses separate CLOCK_MONOTONIC_RAW intervals.',
        overhead_scope='Whole pre-Popen through reap includes observer clock calls, updates, code/layout differences, final table digest and report. No subtraction from original benchmark or native/DR speedup credit.',
        ptrace_scope='Only actual ordinary C raw seam requests within measured handlers; specialized clock and unsafe direct exits excluded. External ptrace activity and ptrace stops remain unavailable.',
        sites_scope='Top32 of bounded16k exact retained sealed-source tuples; object IDs are descriptive. No independent DSO/symbol attribution, no complete distinct coverage if overflow. Full table digest is producer evidence, not an independent table capture.',
        region_names=event_read.REGIONS,raw_names=event_read.RAW,
        signal_names=['SIGSEGV','SIGTRAP','SIGSYS','SIGILL','other'],
        route_names=['NO_STEP','OLD_STEP','GENERIC_TF','REPEAT','ONESHOT','REGISTER_RUN','REPEAT_LEASE'],
        order=[dict(workload=k,repeat=n,lane=l)for k,n,l in ORDER],commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'),csv=dict(file=path.with_suffix('.csv').name,bytes=len(data),sha256=H(data)),
        tool_versions=r.get('build',{}).get('numeric_versions'),release_builds={k:v.get('release_build',{'status':'not_completed'})for k,v in r.get('release_builds',{}).items()},
        reader_controls={k:dict(original=len(v['original']['original']['refusals']),cost=len(v['original']['diagnostic_refusals']),event=len(v['event_refusals']))for k,v in r.get('reader_controls',{}).items()},
        cases=[{k:v for k,v in c.items()if k not in('error','comparison')}for c in r['cases']],
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']))
    value['release_builds']={k:{n:s[n]for n in('status','recipe','archive','bridge','observer_clock')if n in s}for k,s in value['release_builds'].items()}
    value['hardware']=dict(value['hardware']);flags=value['hardware'].pop('isa_flags');value['hardware']['isa_flags_sha256']=digest(flags)
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<64<<10 and len(data)<16<<10 and not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),
         'bounded public numeric diagnostic without host paths/logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as f:f.write(data)
    with path.open('x')as f:f.write(text)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-event-budget-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS)
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-event-budget-v1',scope='Twelve fixed observer-overhead attempts; original terminal gates and limits retained',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[dict(ordinal=i,workload=k,repeat=n,lane=l,status='not_run') for i,(k,n,l) in enumerate(ORDER)],error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_event_budget.py','--expect-revision',a.expect_revision])
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
            out,err=(program_invoke if name in NAMES else invoke)(row,private,cpu,record=record,step=step)
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
        need(EVENT_SOURCES,'fixed event source profile installed before execution')
        for name,want in EVENT_SOURCES.items():pin(ROOT/name,want)
        products=builder.prepare();r['archive']=fact(products['archive'])
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(not r['final_errors'],'no retained command errors')
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
