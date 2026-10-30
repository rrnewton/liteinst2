#!/usr/bin/env python3
"""Fixed release baseline/maintained comparison and separate maps differential runs."""
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
LANES=('baseline','maintained','differential')
EXTRA=((),('MAPS_MAINTAINED',),('MAPS_MAINTAINED','MAPS_DIFFERENTIAL'))
ORDER=tuple((kind,repeat,lane)for repeat in range(10)
    for kind in (('ls','true')if repeat%2==0 else('true','ls'))
    for lane in (LANES[:2]if repeat%2==0 else LANES[1::-1]))+(
    ('ls',0,'differential'),('true',0,'differential'))
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
H=lambda b:hashlib.sha256(b).hexdigest()
KEYS=('version queries hits refreshes updates invalidations comparisons mismatches unexplained '
      'stack_probes enabled differential poisoned reserved').split()
PREFIX=b'LI2_MAPS_VIEW '
ROUTES={'loader':('nx_faults','selected_steps','generic_tf_attempts','generic_tf_steps'),
    'chain':('nx_entries','trace_entries','steps','lease_transfers'),
    'trace_run':('candidates','preflight_misses','attempts','entries','completed','plan_misses','full_misses'),
    'native':('attempts','admissions','closed','blocked')}
# Immutable imported owner/reader/build and fixture inputs. Product inputs are bound to the
# requested clean Git revision, actual compiler-M closure and before/after facts.
DEPENDENCIES = {'evaluation/inprocess/page_cost_compare.py': {'bytes': 32256, 'sha256': 'ac8ea0af83b8b1c7a6d1571fdc6df2674dc39f504f85fd2320c4c6e807dd29fc'}, 'evaluation/inprocess/page_cost_reports.py': {'bytes': 17797, 'sha256': '3bcdfb8fcab5286cbe442226588e2dab4dcb2bd41c1a720424e494986216b9ee'}, 'evaluation/inprocess/page_native_pair_performance.py': {'bytes': 48569, 'sha256': '072b17b41fc5818543e0cfb8547259fd7ecac24840431439d2293862eddeb056'}, 'evaluation/inprocess/page_native_pair_reports.py': {'bytes': 40779, 'sha256': 'f80dc474cb2f68541aaf6d405ce96602b26a27240f9856a53ae3bd8db0965eb4'}, 'evaluation/inprocess/page_selected_generic_build.py': {'bytes': 17431, 'sha256': '95a83a2648a8ad04b352003f4be1b0b7dee5c5d776d7606ce52c106398ae739b'}, 'evaluation/inprocess/page_selected_process.py': {'bytes': 7089, 'sha256': '71cc09047a01bd62c79d994587998aac17655f0f65a4464c94f12df461f1f773'}, 'evaluation/inprocess/page_selected_register_time_build.py': {'bytes': 9738, 'sha256': 'c6354248d89f8622b328cb21c744a4e9c37221f0d152cd5c3fbed7f48e6fe84d'}, 'evaluation/inprocess/page_selected_oneshot_build.py': {'bytes': 4912, 'sha256': '2cb3555349feaf664ec9b3b08ec6ec30736740bfbf668b4e0e8b89871ab1a1de'}, 'evaluation/inprocess/page_default_ls_release_provenance.py': {'bytes': 1989, 'sha256': '1fe9f09c8f4628629dbb231fbce1049d0022e423dcaaf9458d359d5e2b2f7d88'}, 'evaluation/inprocess/page_selected_effect_ls.py': {'bytes': 28465, 'sha256': '7e9b42fc6862485b4e786d764818cf0afceab77756ced572de2a60648e092ae2'}, 'evaluation/inprocess/page_selected_maps_headers.py': {'bytes': 3508, 'sha256': 'a8123edbc80e2126b3aa0ddbca8b530111194cd03c066ad14a912c94c4ff47e4'}, 'tools/page-entry/selected/tests/maps_view/build.sh': {'bytes': 786, 'sha256': 'e2aa8751bd6dd7d313e93b85a93a679e138ce8df7a52ff6f6ef0c9714137e61f'}, 'tools/page-entry/selected/tests/maps_view/check.py': {'bytes': 2183, 'sha256': 'b8b9ae17ba31b93e825b683c5f212843a913cf3dbf2afee07551a4fccd2388d2'}, 'tools/page-entry/selected/tests/maps_view/oracle.c': {'bytes': 14279, 'sha256': 'c0f8d145b331a20359e94cd7c9ff55ae5c2583b79bf066a4a70d64269dbcc0c0'}}


def split_report(stderr,lane):
    need(lane in LANES and type(stderr)is bytes and stderr.endswith(b'\n'),'exact lane and complete report')
    rows=stderr[:-1].split(b'\n');count=sum(line.startswith(PREFIX)for line in rows)
    if lane=='baseline':
        need(count==0,'baseline has no maintained-view row');return None,stderr
    need(count==1 and rows[0].startswith(PREFIX)and len(rows[0])<=2048 and b'\r'not in rows[0],
         'one bounded first maps-view row followed by unchanged reports')
    v=pair.pair_reports.rseq.decode(rows[0][len(PREFIX):])
    need(type(v)is dict and list(v)==KEYS,'complete ordered maps-view schema without duplicate keys')
    need(all(type(v[k])is int and 0<=v[k]<(1<<(64 if k in KEYS[1:10]else 32))for k in KEYS),
         'exact unsigned counters and flags, no bool or float')
    need(v['version']==1 and v['enabled']==1 and v['differential']==int(lane=='differential')and
         v['poisoned']==v['reserved']==v['mismatches']==0,'successful exact enabled maps mode')
    need(v['queries']==v['hits']+v['refreshes']and
         v['comparisons']==(v['hits']if lane=='differential'else 0),'every query and differential hit accounted')
    need(v['hits']>0 and v['refreshes']>0 and v['stack_probes']>0 and v['updates']>0,
         'actual cache reuse, miss refresh, stack probe and mprotect update demonstrated')
    return v,b'\n'.join(rows[1:])+b'\n'


def check(stdout,stderr,args,kind,lane, *, cache_completed=None, chain_closure=None, true_repeat=None):
    view,original=split_report(stderr,lane)
    parsed,summary=cost_reports.check(stdout,original,*args,workload=kind,cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
    return parsed,summary,view,original


def controls(stdout,stderr,args,kind,lane, *, cache_completed=None, chain_closure=None, true_repeat=None):
    _,_,view,original=check(stdout,stderr,args,kind,lane,cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
    old=cost_reports.supplied_controls(stdout,original,*args,workload=kind,cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
    expected=60 if kind=='ls'else 218 if true_repeat is None else 38
    need(len(old['refusals'])==expected,'exact application and terminal controls for the explicit domain')
    trials=[]
    if view is None:
        trials=[('unexpected_row',PREFIX+b'{}\n'+stderr)]
    else:
        for key,value in [('version',2),('enabled',0),('differential',1-view['differential']),
            ('poisoned',1),('reserved',1),('mismatches',1),('queries',view['queries']+1),
            ('comparisons',view['comparisons']+1),('hits',-1),('refreshes',1<<64),
            ('unexplained',False),('stack_probes',1.0)]:
            changed=dict(view);changed[key]=value
            trials.append((key,PREFIX+json.dumps(changed,separators=(',',':')).encode()+b'\n'+original))
        for key in('hits','refreshes','stack_probes','updates'):
            changed=dict(view);changed[key]=0;changed['queries']=changed['hits']+changed['refreshes']
            changed['comparisons']=changed['hits']if lane=='differential'else 0
            trials.append(('unused_'+key,PREFIX+json.dumps(changed,separators=(',',':')).encode()+b'\n'+original))
        line=stderr.split(b'\n',1)[0]+b'\n'
        short=dict(view);short.pop('reserved')
        trials.extend([('missing',original),('duplicate',line+stderr),('late',original+line),
            ('truncated',stderr[:-1]),('short_schema',PREFIX+json.dumps(short).encode()+b'\n'+original),
            ('duplicate_key',line[:-2]+b',"version":1}\n'+original),
            ('wrong_order',PREFIX+json.dumps(dict(reversed(list(view.items())))).encode()+b'\n'+original)])
    refused=[]
    for name,changed in trials:
        caught=False
        try:check(stdout,changed,args,kind,lane,cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
        except ValueError:caught=True
        need(caught,'complete reader refuses supplied maps-view '+name);refused.append(name)
    need(len(refused)==len(set(refused))==(1 if lane=='baseline'else 23),'complete supplied maps-view population')
    need(old['original_stdout_sha256']==H(stdout)and old['original_stderr_sha256']==H(original),
         'original controls bind exact unchanged stdout and report suffix')
    return dict(original=old,maps_view_refusals=refused,actual_subjects=0,native_qualification_credit=False,
        raw_stderr_sha256=H(stderr),original_report_sha256=H(original),
        maps_line_sha256=H(stderr.split(b'\n',1)[0]+b'\n')if view is not None else None)


def build_bridge(builder,products,private,pin,binary,aliases,run,r,extra):
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    output=private/'release';output.mkdir();bridge_recipe=pin(SELECTED/'build-native-pair.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit two-page native release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output})
    argv[1:1]=['-DLI2_'+x+'=1'for x in extra];units=[str(SELECTED.parent/x)for x in UNITS]
    need(argv[-2:]==['-o',str(output/'bridge-native-pair.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in extra+MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact18-TU release recipe plus only the selected maps macros')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    need(str((SELECTED/'maps_phase.inc').resolve())in state['headers']and
         (str((SELECTED/'maps_view.inc').resolve())in state['headers'])==bool(extra),
         'compiler observes exactly the selected original or maintained maps body')
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


def finite(builder,private,pin,binary,aliases,run,r):
    fixture=SELECTED/'tests/maps_view';output=private/'finite';output.mkdir()
    state=r['finite_build']=dict(status='failed')
    build=pin(fixture/'build.sh');reader_path=pin(fixture/'check.py');oracle=pin(fixture/'oracle.c')
    substitutions={'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$fixture_dir':fixture,'$output_dir':output}
    observe_headers(build,substitutions,[],'finite-headers',builder,pin,run,state,aliases)
    rows=state['header_observations'];need(len(rows)==1 and rows[0]['complete'],'one complete actual-TU fixture recipe')
    argv=rows[0]['argv'];deps=rows[0]['headers']
    need([x for x in argv if x.endswith(('.c','.S'))]==[str(oracle)]and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_MAPS_PHASE_REUSE=1','-DLI2_MAPS_MAINTAINED=1','-DLI2_MAPS_DIFFERENTIAL=1']and
         all(str(SELECTED/x)in deps for x in('lifecycle_loader.c','maps_phase.inc','maps_view.inc','maps_view.h'))and
         all(x in argv for x in('-O2','-g','-fno-builtin','-mgeneral-regs-only','-Werror'))and
         argv[-2:]==['-o',str(output/'maps-view')],'exact whole actual-TU differential fixture before compilation')
    _,out,err=run('finite-link',argv,profile='finite',env=builder.environment)
    need(out==err==b'','complete fixture link without diagnostics')
    executable=binary(output/'maps-view');state['executable']=fact(executable)
    data,head,segments=elf(executable)
    need(head[1]in(2,3)and any(p[0]==1 and p[1]==5 and p[3]<=head[4]<p[3]+p[6]for p in segments)and
         all(not(p[1]&1 and p[1]&2)for p in segments if p[0]in(1,0x6474e551)),
         'actual executable entry, no writable executable loads or stack')
    interp=pin(interpreter(executable))
    spec=importlib.util.spec_from_file_location('maps_finite_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    need(pin(namespace.parse(data)['interpreter'])==interp,'literal native fixture PT_INTERP alias remains pinned')
    objects,description=namespace.plan(executable,[Path('/usr/lib64')],bytes.fromhex(H(data)),bytes.fromhex(fact(interp)['sha256']))
    expected={interp:set()}
    for obj in objects:
        path=pin(obj['path']);need(fact(path)['sha256']==H(obj['bytes']),'whole actual fixture library identity')
        expected.setdefault(path,set()).update(obj['names'])
    state['runtime_inputs']=dict(interpreter=fact(interp),dependencies=[dict(names=o['names'],**fact(o['path']))for o in objects])
    state['namespace_plan']=description
    _,out,err=run('finite-native-libraries',[interp,'--list',executable],env=PROGRAM_ENV)
    need(not err,'actual fixture loader listing stderr');resolved_libraries(out,expected,interp,pin)
    spec=importlib.util.spec_from_file_location('maps_finite_reader',reader_path)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    for case in r['finite_cases']:
        mode=case['mode'];name='finite-'+str(mode);case['status']='failed'
        try:
            row,out,err=run(name,[executable,str(mode)],profile='finite',expected=case['expected_exit'],env=PROGRAM_ENV)
            case['result']=reader.check(out,err,row['exit'],mode)
            case.update(status='qualified_success'if case['expected_exit']==0 else'qualified_required_refusal',qualified_case=1)
        except Exception as exc:
            case['error']=type(exc).__name__+': '+str(exc)
            if r['error']is None:r['error']=case['error']
            need(r['commands']and r['commands'][-1]['name']==name and r['commands'][-1].get('reaped')is True and
                 not r['commands'][-1].get('cleanup_errors')and all(d['closed']for d in r['commands'][-1].get('descriptors',[])),
                 'continue only after actual finite subject reaped with every descriptor closed')
        finally:
            observed=[c for c in r['commands']if c['name']==name]
            if observed:
                row=observed[-1];case.update({k:row.get(k)for k in('exit','duration_ns','timed_out','reaped')})
                case['captures']={k:{f:v[f]for f in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
    need(len(r['finite_cases'])==6 and all(c['qualified_case']==1 for c in r['finite_cases'])and r['error']is None,
         'all six actual-TU outcomes qualify before any performance launch')
    state['status']='passed'


def cohort(builder,products,private,pin,binary,aliases,run,r):
    roots={};bridges={};r['release_builds']={}
    for lane,extra in zip(LANES,EXTRA,strict=True):
        root=private/lane;root.mkdir();roots[lane]=root;state=r['release_builds'][lane]={}
        def labelled(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
        bridges[lane]=build_bridge(builder,products,root,pin,binary,aliases,labelled,state,extra)
    plain=r['release_builds']['baseline']['release_build']['argv']
    for lane,extra in zip(LANES[1:],EXTRA[1:],strict=True):
        argv=r['release_builds'][lane]['release_build']['argv']
        normalized=[x.replace(str(roots[lane]),str(roots['baseline']))for x in argv
            if x not in['-DLI2_'+m+'=1'for m in extra]]
        need(normalized==plain,'only declared maps macros and output directory differ')
    spec=importlib.util.spec_from_file_location('maps_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={};states={}
    for lane in LANES:
        for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]:
            states[kind,lane]=pair.prepare_workload(kind+'-'+lane,path,args,bridges[lane],builder,private,pin,binary,run,r,namespace)
    for kind in('ls','true'):
        for lane in LANES[1:]:
            need(all(r[key][kind+'-baseline']==r[key][kind+'-'+lane]for key in('system_inputs','namespace_plans','external_inputs')),
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
            parsed,summary,view,original=check(out,err,args,kind,lane)
            r['terminal_reports'][name]=parsed;r['reader_controls'][name]=controls(out,err,args,kind,lane)
            routes=[parsed[k][f]for k,fields in ROUTES.items()for f in fields]
            need(all(type(x)is int and 0<=x<1<<64 for x in routes),'actual unsigned overlapping route counters')
            case.update(status='passed',comparison=summary,maps_view=view,routes=routes)
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
    columns=fields+['maps_view.'+k for k in KEYS]+['derived.physical_fresh_requests']+[k+'.'+f for k,fs in ROUTES.items()for f in fs]
    rows=[[c.get(k)for k in fields]+([c['maps_view'][k]for k in KEYS]if c.get('maps_view')else[None]*len(KEYS))+
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
            stats[kind]['maintained_to_baseline_median_ratio']=b/a
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu','bounds','reproduce','archive','carriers','system_inputs')}
    value.update(statistics=stats,quantiles='inclusive linear interpolation at (n-1)*p; all10 samples per measured lane/workload',
        scope='Required cohort: six actual-TU modes and42 real gated launches:40 baseline/maintained timing samples and2 differential validations. Separate mode; all original application/owner gates retained. No native or DynamoRIO lane.',
        timing_scope='Actual pre-Popen through reap intervals include startup and reporting. Differential timing receives no performance credit. No dropped samples or fixed speed threshold.',
        count_scope='Maps counts include bootstrap. Physical fresh requests derive as refreshes+comparisons from producer control flow; differential hits add fresh comparisons. Baseline has no maps row, so no measured baseline open-count reduction. Routes overlap; no disjoint sum or ptrace inference.',
        columns=columns,rows=rows,commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'),csv=dict(file=path.with_suffix('.csv').name,bytes=len(data),sha256=H(data)),
        tool_versions=r.get('build',{}).get('numeric_versions'),
        finite_scope='Six required actual-TU modes; four required refusals include the supplied READ_IMPLIES_EXEC return control. No performance or application-completion credit.',
        finite_cases=[{k:v for k,v in c.items()if k!='error'}for c in r['finite_cases']],
        finite_error_types={str(c['mode']):c['error'].split(':',1)[0]for c in r['finite_cases']if c.get('error')},
        finite_build={k:r.get('finite_build',{})[k]for k in('status','executable','runtime_inputs')if k in r.get('finite_build',{})},
        release_builds={k:{n:s['release_build'][n]for n in('status','recipe','archive','bridge')if n in s.get('release_build',{})}for k,s in r.get('release_builds',{}).items()},
        reader_controls={k:dict(original=len(v['original']['refusals']),maps_view=len(v['maps_view_refusals']),raw_stderr_sha256=v['raw_stderr_sha256'],original_report_sha256=v['original_report_sha256'],maps_line_sha256=v['maps_line_sha256'])for k,v in r.get('reader_controls',{}).items()},
        captures={str(c['ordinal']):c.get('captures',{})for c in r['cases']},
        case_error_types={str(c['ordinal']):c['error'].split(':',1)[0]for c in r['cases']if c.get('error')},
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']))
    value['hardware']=dict(value['hardware']);flags=value['hardware'].pop('isa_flags');value['hardware']['isa_flags_sha256']=digest(flags)
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<64<<10 and len(data)<16<<10 and not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),
         'bounded public numeric result without host paths/logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as f:f.write(data)
    with path.open('x')as f:f.write(text)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-maps-view-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS,finite=[5,512<<20,16<<20,15])
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='maps-view-v1',scope='42 fixed baseline/maintained/differential attempts; original terminal gates and limits retained',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[dict(ordinal=i,workload=k,repeat=n,lane=l,status='not_run') for i,(k,n,l) in enumerate(ORDER)],error=None,final_errors=[],
        finite_cases=[dict(mode=i,expected_exit=exit,status='not_run',qualified_case=0,supplied_return_control=(i==4),performance_credit=False)for i,exit in enumerate((0,125,125,125,125,0))],
        reproduce=['python3','evaluation/inprocess/maps_view.py','--expect-revision',a.expect_revision])
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
        required={b'evaluation/inprocess/maps_view.py',b'tools/page-entry/selected/maps_view.h',b'tools/page-entry/selected/maps_view.inc',
            *[('tools/page-entry/selected/tests/maps_view/'+x).encode()for x in('oracle.c','build.sh','check.py')]}
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
        products=builder.prepare();r['archive']=fact(products['archive'])
        finite(builder,private,pin,binary,aliases,run,r)
        cohort(builder,products,private,pin,binary,aliases,run,r)
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
