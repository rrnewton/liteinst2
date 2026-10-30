"""Finite82 whole-profile TRACE experiment; no complete new-owner qualification.

Ten same-revision/same-CPU cohorts are mandatory. Old profiles remain exact;
new transfer failure/cache coverage beyond finite9 remains explicitly pending.
"""
import csv,importlib.util,io,json,platform,statistics
from pathlib import Path
from page_cost_compare import (Build,PROGRAM_ENV,SELECTED,need,fact,digest,source,
    before_default,pair,build_dr,dr_diagnostics)
from unrolled_hash_build import build_bridge as build_unrolled
from scalar_span_trace_build import build_bridge as build_span,fast_bytes_completed
import scalar_reuse_performance as reuse
import scalar_reuse_certificate_performance as certificate
import current_custody_performance as custody
import scalar_span_component as component
import scalar_span_trace as fixture
import scalar_span_trace_performance_reports as reports
import unrolled_hash_reports as unrolled_reports
import maps_view as maps

ROOT,HERE=reuse.ROOT,reuse.HERE
LANES=('unrolled','span-trace','differential','native','dynamorio')
ORDER=tuple((kind,repeat,'span-trace'if lane=='scalar-reuse'else lane)for kind,repeat,lane in reuse.ORDER)
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
RECEIPTS=('current_component_receipt','current_owner_receipt','span_component_receipt','span_trace_receipt')
REQUIRED=certificate.REQUIRED|custody.REQUIRED|set(component.LEAVES)|{
    'evaluation/inprocess/scalar_span_trace_performance.py',
    'evaluation/inprocess/scalar_span_trace_performance_reports.py',
    'evaluation/inprocess/scalar_span_trace.py','evaluation/inprocess/scalar_span_trace_reports.py',
    'evaluation/inprocess/scalar_span_trace_build.py','evaluation/inprocess/scalar_span_component.py',
    'tools/page-entry/selected/build-scalar-span-trace.sh',
    *('tools/page-entry/selected/'+name for name in
      ('span_fast_bytes.h','tests/span_fast_bytes/oracle.c','tests/span_fast_bytes/build.sh')),
    *('tools/page-entry/selected/'+name for name in('tf_span_transfer.h','tf_span_transfer.inc',
      'span_fetch.h','span_fetch.inc','span_source.h','span_source.inc','rseq_span.inc',
      'selected_scalar_span.inc','selected_scalar_span_reuse.inc',
      'span_trace_observe.h','span_trace_observe.inc','span_trace_observe_memory.h','span_trace_observe_memory.inc')),
    *('tools/page-entry/selected/tests/scalar_span_trace_owner/'+name for name in('read.py','wire.py','plan.py','layout.py')),
    *('tools/page-entry/selected/tests/scalar_span_trace_app/'+name for name in('main.c','pure.c','pure.ld','machine.S','app.h','build.sh','launch.py','read.py'))}


def arguments(a):
    certificate.arguments(a)
    for key in RECEIPTS:
        need(getattr(a,key)is not None,'every current/span qualification receipt is mandatory')
        path=getattr(a,key).resolve(strict=True).relative_to(ROOT)
        need(path.parent==Path('evaluation/inprocess/results')and path.suffix=='.json',
             'exact additional public receipt inside evaluation results')
        setattr(a,key,path)
    paths=[a.component_receipt,a.owner_receipt,a.region_decoder_receipt,a.region_component_receipt,
           a.reuse_owner_receipt,a.certificate_owner_receipt,*[getattr(a,k)for k in RECEIPTS]]
    need(len(set(map(lambda p:str(p.resolve(strict=True)),paths)))==10,'ten distinct actual prerequisite receipts')


def reproduce(a):
    return ['--scalar-span-trace',*certificate.reproduce(a)[1:],
            *[v for key in RECEIPTS for v in('--'+key.replace('_','-'),str(getattr(a,key)))]]


def archive(actual):
    need(actual['build']['decoder_features']==['scalar-region','scalar-span']and
         type(actual['build']['archive_text_exports']['li2_decoder_span_describe'])is int and
         actual['build']['archive_text_exports']['li2_decoder_span_describe']==1,
         'actual distinct span feature and exported typed decoder')
    row=actual['build']['artifacts']['decoder.a']
    return {key:row[key]for key in('bytes','sha256')}


def names(value,count,what):
    need(type(value)is list and len(value)==len(set(value))==count and
         all(type(x)is str for x in value),'exact unique supplied '+what+' refusals')


def span_component(a,r,pin,binary):
    public,actual=reuse.closed(a.span_component_receipt,r,pin,binary)
    expected=dict(planned=59,launched=59,qualified=59,metadata=1,hardware=58,completed_paths=56,
                  required_read_failures=2,reader_refusals=3022)
    need(public['profile']==actual['profile']=='scalar-span-component-v1'and
         public['status']==actual['status']=='passed_component'and
         digest(actual['totals'])==digest(expected)and digest(actual['bounds'])==digest(component.PROFILES)and
         public['whole_application_credit']is False and public['performance_credit']is False,
         'exact finite59 component, all3022 controls and unchanged bounds; no owner credit')
    arch=archive(actual);cases=actual['cases'];commands={x['name']:x for x in actual['commands']}
    order=[('metadata',None)]+[('native',m)for m in range(58)]
    need(digest([(c['kind'],c['mode'])for c in cases])==digest(order),'exact metadata plus all58 hardware cases')
    metadata=dict(schema=1,code_forms=131,accepted=1283,old_accepts=53,refusals=26,plan_controls=49,
                  none_checks=1283,max_register_rows=4,postseal_equal=1)
    need(digest(cases[0]['result'])==digest(public['metadata'])==digest(metadata),
         'complete typed actual131-form metadata/NONE/planner tuple')
    out=io.StringIO(newline='');writer=csv.writer(out,lineterminator='\n')
    writer.writerow(['kind','mode','status','expected_exit','exit','duration_ns','record_bytes','reader_controls'])
    for c,(kind,mode)in zip(cases,order,strict=True):
        native=kind=='native';label='span-'+str(mode)if native else'span-metadata';cmd=commands[label]
        fault=native and mode in(8,9);status='qualified_required_read_failure'if fault else'qualified_component'if native else'qualified_metadata'
        need(c['launched']is True and c['status']==status and
             type(c['exit'])is type(c['expected_exit'])is int and c['exit']==c['expected_exit']==cmd['exit']==(125 if fault else 0)and
             cmd['profile']==('native'if native else'span_metadata')and digest(cmd['bounds'])==digest([5,512<<20,16<<20,15]),
             'every actual metadata/hardware outcome and original bound')
        if native:
            names(c['reader_controls'],55 if fault else 52,'component')
            summary=c['result'];fixed=dict(schema=1,mode=mode,qualified_comparison=1,completed_path=int(not fault),
                required_read_failure=int(fault),cleanup=1,generated_trace=0,exit_kind=2 if fault else 1,
                authority_controls=4,postseal_equal=1)
            need(type(summary)is dict and set(summary)==set(fixed)|{'reference_trace','head_checks','interior_misses'}and
                 all(type(v)is int and 0<=v<1<<64 for v in summary.values())and
                 digest({k:summary[k]for k in fixed})==digest(fixed)and
                 c['record']=={k:cmd['captures']['record'][k]for k in('bytes','sha256')}and
                 type(c['record']['bytes'])is int and c['record']['bytes']==612096,
                 'typed full record/state/allocator summary binds each actual process')
        else:need(not c.get('reader_controls'),'metadata does not fabricate record control credit')
        writer.writerow([c[k]for k in('kind','mode','status','expected_exit','exit')]+
            [c.get('duration_ns',''),c.get('record',{}).get('bytes',''),len(c.get('reader_controls',[]))])
    need(pin(a.span_component_receipt.with_suffix('.csv')).read_bytes()==out.getvalue().encode(),
         'all59 public CSV rows exactly project actual cases')
    need(set(actual['component_build'])=={'metadata','native'}and
         all(x['status']=='passed'and x['archive']==arch for x in actual['component_build'].values())and
         actual['c_stack']['conservative_bytes']==2*max(actual['c_stack']['per_executable'].values())+65536<=524288 and
         actual['component_build']['native']['raw_gateway']['bytes']>0,
         'both actual executables/archive, emitted gateway and bounded C stack evidence')
    need(public['inputs_sha256']==digest(actual['inputs_before'])and
         public['artifacts_sha256']==digest(actual['artifacts_before']),
         'whole public component source/artifact manifest digests')
    return dict(file=a.span_component_receipt.name,**fact(pin(a.span_component_receipt)),
        private_receipt=public['private_receipt'],profile=actual['profile'],status=actual['status'],
        totals=expected,archive=arch,commands=len(actual['commands']),commands_sha256=digest(actual['commands']))


def span_trace(a,r,pin,binary):
    public,actual=reuse.closed(a.span_trace_receipt,r,pin,binary)
    expected=dict(planned=9,launched=9,qualified=9,native=4,gated=4,owner_controls=1,qualified_pairs=4,
        completed_applications=6,required_read_faults=1,required_reference_faults=1,required_owner_refusals=1,
        application_reader_refusals=112,terminal_reader_refusals=756,owner_reader_refusals=164)
    need(public['profile']==actual['profile']=='scalar-span-trace-finite-v1'and
         public['status']==actual['status']=='passed'and digest(actual['totals'])==digest(expected)and
         digest(actual['bounds'])==digest(fixture.BOUNDS)and public['performance_credit']is False and
         public['whole_ls_eligibility_credit']is False,
         'exact finite9 genuine TRACE prerequisite; no full cache/whole-program credit')
    arch=archive(actual);cases=actual['cases'];commands={x['name']:x for x in actual['commands']}
    need(digest([(c['lane'],c['mode'],c['control'])for c in cases])==digest(list(fixture.ORDER)),
         'all four actual native/gated references and the nested refusal')
    owner_counts={(0,0):32,(1,0):32,(2,0):32,(3,0):33,(0,1):35}
    terminal_counts={(0,0):152,(1,0):152,(2,0):152,(3,0):150,(0,1):150}
    rows=[]
    for c in cases:
        lane,mode,control=c['lane'],c['mode'],c['control'];cmd=commands[c['label']]
        status='qualified_native_reference'if lane=='native'else'qualified_required_nested_refusal'if control else\
            'qualified_required_read_failure'if mode==3 else'qualified_ordinary_resume'if mode==2 else'qualified_generated_transfer'
        need(c['launched']is True and c['status']==status and type(c['exit'])is type(c['expected_exit'])is int and
             c['exit']==c['expected_exit']==cmd['exit']==(125 if control or mode==3 else 0)and
             cmd['profile']=='program'and digest(cmd['bounds'])==digest([30,512<<20,16<<20,60]),
             'every finite TRACE outcome and actual program bound')
        if lane=='gated':
            oc,tc=c['owner_reader_controls'],c['terminal_controls']
            names(oc['refusals'],owner_counts[mode,control],'TRACE record')
            names(tc['refusals'],terminal_counts[mode,control],'TRACE terminal')
            need(type(oc['native_operations'])is int and oc['native_operations']==0 and
                 type(tc['native_operations'])is int and tc['native_operations']==0 and
                 oc['original_sha256']==cmd['captures']['record']['sha256']and
                 tc['original_stderr_sha256']==cmd['captures']['stderr']['sha256'],
                 'all supplied controls bind the exact actual protected record and terminal')
            if not control:
                need(type(c['pair']['qualified_case'])is int and c['pair']['qualified_case']==1 and
                     digest(c['application_controls'])==digest(dict(supplied_refusals=28,native_operations=0)),
                     'all four complete actual state comparisons and112 application controls')
        row={k:c[k]for k in('label','lane','mode','control','expected_exit','status','launched','exit',
            'whole_process_ns','timed_out','captures','pair','owner_summary','control_reference','error_type')if k in c}
        row.update(terminal_control_count=len(c.get('terminal_controls',{}).get('refusals',[])),
            terminal_controls_sha256=digest(c.get('terminal_controls',{})),
            application_control_count=c.get('application_controls',{}).get('supplied_refusals',0),
            owner_control_count=len(c.get('owner_reader_controls',{}).get('refusals',[])),
            owner_controls_sha256=digest(c.get('owner_reader_controls',{})))
        rows.append(row)
    need(digest(public['cases'])==digest(rows),'all9 complete public case values/types/presence equal retained actual cases')
    fields=('lane','mode','control','status','expected_exit','exit','whole_process_ns','application_control_count','terminal_control_count','owner_control_count')
    out=io.StringIO(newline='');writer=csv.writer(out,lineterminator='\n');writer.writerow(fields)
    for row in rows:writer.writerow([row.get(k,'')for k in fields])
    need(pin(a.span_trace_receipt.with_suffix('.csv')).read_bytes()==out.getvalue().encode(),
         'all9 exact public TRACE CSV rows')
    seed=actual['seed_prerequisite'];built=actual['release_build']
    fast_bytes_completed(built,actual['commands'],binary)
    seed_fixed=dict(status='passed',launched=True,exit=0,bounds=[5,512<<20,16<<20,15],owner_subjects=0,performance_credit=False)
    need(digest(actual['namespace_controls'])==digest(public['namespace_controls'])==digest(dict(status='passed',tests=12,existing=5,added=7))and
         digest({k:seed[k]for k in seed_fixed})==digest(seed_fixed)and
         built['status']=='passed'and built['archive']==arch and built['capture_config']is not None and
         '-DLI2_SCALAR_SPAN_CAPTURE=1'in built['argv']and actual['nested_emission']['status']=='passed'and
         actual['owner_layout']['bridge']==built['bridge'],
         'real namespace/seed/capture build, actual layout and complete emitted nested gateway proof')
    projected={k:v for k,v in seed.items()if k in('planned','status','launched','expected_exit','bounds','owner_subjects',
        'completed_applications','performance_credit','elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
    need(digest(public['seed_prerequisite'])==digest(projected)and
         public['input_manifest_sha256']==digest(actual['inputs_before'])and
         public['artifact_manifest_sha256']==digest(actual['artifacts_before']),
         'whole public seed and input/artifact manifest projections')
    return dict(file=a.span_trace_receipt.name,**fact(pin(a.span_trace_receipt)),private_receipt=public['private_receipt'],
        profile=actual['profile'],status=actual['status'],totals=expected,archive=arch,
        commands=len(actual['commands']),commands_sha256=digest(actual['commands']),complete_new_owner_qualification=False)


def prerequisites(a,r,pin,binary):
    certificate.prerequisites(a,r,pin,binary)
    custody.prerequisites(a,r,pin,binary)
    r['prerequisites']['span_component']=span_component(a,r,pin,binary)
    r['prerequisites']['span_trace']=span_trace(a,r,pin,binary)
    need(set(r['prerequisites'])=={'component','owner','region_decoder','region_component','reuse_owner',
        'certificate_owner','current_component','current_owner','span_component','span_trace'}and
         r['prerequisites']['span_component']['archive']==r['prerequisites']['span_trace']['archive'],
         'all ten exact cohorts and one actual qualified scalar-span archive')


def span_builder(private,pin,binary,aliases,run,r,builders):
    root=private/'span-build';root.mkdir();state=r['region_build']={}
    def labelled(name,argv,**kwargs):return run('span-'+name,argv,**kwargs)
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,aliases,labelled,state)
        return labelled(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(state,root,pin,binary,build_run,extra_decoder_sources=('region.rs',),scalar_span=True)
    builders.append(builder)
    return builder,builder.prepare()


def cohort(builder,products,private,pin,binary,aliases,run,r,a,builders):
    lanes,order,names=LANES,ORDER,NAMES
    active_build=build_span
    need(reports.SPAN_CONTROL_COUNT==113 and reports.CURRENT_CONTROL_COUNT==26,
         'exact source-bound additive span/current terminal populations')
    need(builder.extra_decoder_sources==()and builder.decoder_features==()and
         builder.record['decoder_features']==[],'old unrolled baseline uses the original default archive')
    retained={k:dict(fact(v),mode=v.stat().st_mode&0o777)for k,v in products.items()}
    selected,region_products=span_builder(private,pin,binary,aliases,run,r,builders)
    need({k:dict(fact(v),mode=v.stat().st_mode&0o777)for k,v in products.items()}==retained,
         'sequential region build leaves every retained default artifact byte/mode unchanged')
    r['region_archive']=fact(region_products['archive']);r['release_builds']={};bridges={};roots={}
    for lane in lanes[:3]:
        root=private/lane;root.mkdir();roots[lane]=root;state=r['release_builds'][lane]={}
        def labelled(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
        if lane=='unrolled':bridges[lane]=build_unrolled(builder,products,root,pin,binary,aliases,labelled,state,())
        else:bridges[lane]=active_build(selected,region_products,root,pin,binary,aliases,labelled,state,
                                      ('MAPS_DIFFERENTIAL',)if lane=='differential'else())
    normal=r['release_builds'][lanes[1]]['release_build']['argv']
    differential=r['release_builds']['differential']['release_build']['argv']
    need([x.replace(str(roots['differential']),str(roots[lanes[1]]))for x in differential
         if x!='-DLI2_MAPS_DIFFERENTIAL=1']==normal,'scalar normal/DIFF differ only by declared diagnostic macro and output')
    for lane in lanes[1:3]:
        built=r['release_builds'][lane]['release_build']
        need(built['archive']==r['prerequisites']['span_component']['archive']==
             r['prerequisites']['span_trace']['archive']==r['region_archive']and
             built['capture_config']is None and '-DLI2_SCALAR_SPAN_TRACE=1'in built['argv']and
             '-DLI2_MAPS_CURRENT_TF=1'in built['argv']and
             '-DLI2_SCALAR_REGION_REUSE_CERTIFICATE=1'not in built['argv'],
             'same actual qualified span archive, current-custody recipe and no capture/certificate')
    spec=importlib.util.spec_from_file_location('reuse_performance_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={};states={}
    for lane in lanes[:3]:
        for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]:
            states[kind,lane]=pair.prepare_workload(kind+'-'+lane,path,args,bridges[lane],builder,private,pin,binary,run,r,namespace)
    for kind in('ls','true'):
        for lane in lanes[1:3]:
            need(all(r[key][kind+'-unrolled']==r[key][kind+'-'+lane]for key in
                 ('system_inputs','namespace_plans','external_inputs')),'whole original/interpreter/dependency inputs match across profiles')
    drrun,client,dr_env=build_dr(a.sdk,builder,private,pin,binary,run,r)
    dr_diagnostics(drrun,client,{k:states[k,'unrolled']for k in('ls','true')},private,pin,binary,run,r,dr_env)
    need(len(r['dr_diagnostics'])==3 and all(x['status']=='passed'for x in r['dr_diagnostics']),
         'all original actual DR exec/target/client/exit proofs before measured launches')
    r['terminal_reports']={};r['reader_controls']={}
    for ordinal,(kind,repeat,lane)in enumerate(order):
        name=names[ordinal];s=states[kind,lane if lane in lanes[:3]else'unrolled'];case=r['cases'][ordinal]
        case['status']='failed';env=PROGRAM_ENV;ns=None
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
            need(out==(b'.\n'if kind=='ls'else b''),'complete exact actual program output')
            if ns is None:need(err==b'','native and DR stderr exactly empty')
            else:
                pair.namespace_join(s,ns,binary,r,namespace)
                args=(row['pid'],row['exit'],row['stdout_provenance_before'],s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'])
                if lane=='unrolled':
                    parsed,summary,view,owner,unused=unrolled_reports.check(out,err,args,kind,'unrolled')
                    controls=unrolled_reports.controls(out,err,args,kind,'unrolled');scalar=retirement=None
                else:
                    parsed,summary,view,owner,scalar,retirement,current,span,span_reuse=reports.check(out,err,args,kind,lane)
                    controls=reports.controls(out,err,args,kind,lane)
                    need(len(controls['scalar_reuse_refusals'])==86 and len(controls['current_refusals'])==26 and
                         len(controls['span_refusals'])==reports.SPAN_CONTROL_COUNT,
                         'all old scalar/current and fixed additive span terminal refusals')
                    case.update(current=current,span=span,span_reuse=span_reuse)
                routes=[parsed[k][f]for k,fields in maps.ROUTES.items()for f in fields]
                need(all(type(x)is int and 0<=x<1<<64 for x in routes),'actual unsigned overlapping route counters')
                r['terminal_reports'][name]=parsed;r['reader_controls'][name]=controls
                case.update(comparison=summary,maps_view=view,unrolled=owner,scalar=scalar,reuse=retirement,routes=routes)
            case['status']='passed'
        except Exception as exc:
            case['error']=type(exc).__name__+': '+str(exc)
            if r['error']is None:r['error']=case['error']
            actual=r['commands'][start:]
            need(len(actual)==1 and actual[0]['name']==name and type(actual[0].get('exit'))is int and
                 actual[0].get('reaped')is True and actual[0].get('cleanup_errors')==[]and
                 all(d.get('closed')is True for d in actual[0].get('descriptors',[])),
                 'continue only after the actual failed subject is completely reaped and closed')
        finally:
            attempted=[c for c in r['commands'][start:]if c['name']==name]
            if attempted:
                row=attempted[-1];case.update({k:row.get(k)for k in('exit','process_ns','timed_out','reaped','user_cpu_ns','system_cpu_ns',
                    'minor_faults','major_faults','voluntary_switches','involuntary_switches')})
                case['captures']={k:{f:v[f]for f in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
            print(json.dumps({k:case.get(k)for k in('ordinal','workload','lane','status','exit','process_ns','error')}),flush=True)
    need(len(r['cases'])==82 and all(c['status']=='passed'for c in r['cases'])and r['error']is None,
         'all82 fixed attempts, including both differential runs; no retries or replacements')



def counter_table(cases,key,fields):
    """Lossless shared columns for actual rows only; absent lanes gain no counts."""
    columns=['ordinal',*fields]
    rows=[[c['ordinal'],*[c[key][k]for k in fields]]for c in cases if c.get(key)is not None]
    need(len({x[0]for x in rows})==len(rows),'one complete numerical counter row per actual case')
    return dict(columns=columns,rows=rows)


def publish(path,r,private):
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    signals=('SEGV','TRAP','ILL','SYS','other')
    sk=('offers','closed','resumed','hash_misses','candidates','source_misses','plan_misses','capacity_misses',
        'entries','completed','publications','hits','plan_checks','rseq_checks')
    columns=fields+['signals.'+k for k in signals]+['maps_view.'+k for k in maps.KEYS]+[
        'derived.physical_fresh_requests']+['span.'+k for k in sk]
    rows=[]
    for c in r['cases']:
        rows.append([c.get(k)for k in fields]+(c['unrolled']['signals']if c.get('unrolled')else[None]*5)+
            [c['maps_view'][k]if c.get('maps_view')else None for k in maps.KEYS]+
            [c['maps_view']['refreshes']+c['maps_view']['comparisons']if c.get('maps_view')else None]+
            [c['span'][k]if c.get('span')else None for k in sk])
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns);writer.writerows(rows);data=stream.getvalue().encode()
    complete=(r['status']=='passed'and r['source_unchanged']and r['cleanup_complete']and not r['final_errors']and
        len(r['cases'])==82 and all(c['status']=='passed'for c in r['cases']))
    statistics_rows={}
    for kind in('ls','true'):
        result=statistics_rows[kind]={}
        for lane in LANES:
            cases=[c for c in r['cases']if c['workload']==kind and c['lane']==lane]
            times=[c['process_ns']for c in cases if c['status']=='passed']
            row=result[lane]=dict(planned=1 if lane=='differential'else 10,passed=len(times),timing_credit=bool(complete and lane!='differential'))
            if row['timing_credit']:
                need(len(times)==10,'all ten actual samples for this complete lane');q=statistics.quantiles(times,n=4,method='inclusive')
                row.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
        if complete:
            span=result['span-trace']['median_ns']
            result['span_trace_median_ratios']={lane:span/result[lane]['median_ns']for lane in('unrolled','native','dynamorio')}
    controls={}
    for name,v in r.get('reader_controls',{}).items():
        span='span_refusals'in v;prior=v['original']if span else v
        controls[name]=dict(original=len(prior['original']['original']['refusals']),maps_view=len(prior['original']['maps_view_refusals']),
            unrolled=len(prior['unrolled_refusals']),scalar_reuse=len(v['scalar_reuse_refusals'])if span else 0,
            current=len(v['current_refusals'])if span else 0,span=len(v['span_refusals'])if span else 0,
            raw_stderr_sha256=v['original_stderr_sha256'])
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu',
        'bounds','reproduce','archive','region_archive','carriers','system_inputs','prerequisites')}
    hw=dict(value['hardware']);flags=hw.pop('isa_flags');hw['isa_flags_sha256']=digest(flags);value['hardware']=hw
    value.update(statistics=statistics_rows,quantiles='inclusive linear interpolation at (n-1)*p; ten samples per complete measured lane/workload',
        scope='Finite82 experiment:40 ordinary unrolled/span-TRACE, two span-TRACE differential validations, then40 fresh native/DynamoRIO samples. Ten exact same-revision/same-CPU prerequisites and six actual-TU maps cases are mandatory. Whole-profile comparison includes current custody and old scalar reuse; no certificate or observer-only subtraction.',
        timing_scope='Actual pre-Popen through reap includes startup/reporting. No medians/IQR/ratios unless all82, every prerequisite and final closure pass. Differential and DR identity diagnostics receive no timing credit. No fixed speed threshold.',
        count_scope='Full actual producer rows are retained in shared-column counter tables. Successful observers have equal actual event/signal populations. Routes overlap and are not summed; physical fresh requests=refreshes+comparisons. Entries are not instruction counts or inferred traps saved. Absent current seeds/retained activity earns no current optimization credit. Native/DR have no invented counters.',
        qualification_scope='Finite9 establishes only its genuine TRACE paths. Full new-owner stale/repeated/capability/close/release/query/permission/retirement/late-fault/cache-generation qualification remains pending. Old43 is not a substitute; no landing or complete owner qualification is claimed.',
        complete_new_owner_qualification=False,
        sdk_scope='Existing exact DynamoRIO11.91.0 SDK and empty Release client. DR retains16GiB virtual address space; all other lanes512MiB. All previous failed cohorts remain failed.',
        columns=columns,rows=rows,commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'),csv=dict(file=path.with_suffix('.csv').name,bytes=len(data),sha256=maps.H(data)),
        sdk_files=len(r.get('dynamorio_sdk',{})),sdk_manifest_sha256=digest(r.get('dynamorio_sdk',{})),
        dynamorio_client=r.get('dynamorio_client'),dynamorio_build_commands_sha256=r.get('dynamorio_build_commands_sha256'),
        dr_diagnostics=[{k:v for k,v in x.items()if k!='error'}for x in r.get('dr_diagnostics',[])],
        dr_error_types={x['workload']:x['error'].split(':',1)[0]for x in r.get('dr_diagnostics',[])if x.get('error')},
        finite_cases=[{k:v for k,v in c.items()if k!='error'}for c in r['finite_cases']],
        finite_error_types={str(c['mode']):c['error'].split(':',1)[0]for c in r['finite_cases']if c.get('error')},
        finite_build={k:r.get('finite_build',{})[k]for k in('status','executable','runtime_inputs')if k in r.get('finite_build',{})},
        tool_versions={name:record.get('numeric_versions')for name,record in(('default',r.get('build',{})),('span',r.get('region_build',{}).get('build',{})))},
        release_builds={k:{n:s['release_build'][n]for n in('status','recipe','archive','bridge')if n in s.get('release_build',{})}for k,s in r.get('release_builds',{}).items()},
        reader_controls=None,captures=None,
        case_error_types={str(c['ordinal']):c['error'].split(':',1)[0]for c in r['cases']if c.get('error')},
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']))
    control_fields=('original','maps_view','unrolled','scalar_reuse','current','span','raw_stderr_sha256')
    control_rows=[[i,*[controls[name][k]for k in control_fields]]for i,name in enumerate(NAMES)if name in controls]
    need({NAMES[row[0]]:dict(zip(control_fields,row[1:],strict=True))for row in control_rows}==controls,
         'whole public control columns invert exactly to every actual control summary')
    value['reader_controls']=dict(columns=['ordinal',*control_fields],rows=control_rows)
    captured={str(c['ordinal']):c.get('captures',{})for c in r['cases']}
    capture_rows=[[int(ordinal),stream,row['bytes'],row['sha256']]
                  for ordinal,streams in captured.items()for stream,row in streams.items()]
    restored={str(c['ordinal']):{}for c in r['cases']}
    for ordinal,stream,size,sha in capture_rows:
        need(stream not in restored[str(ordinal)],'one actual capture stream per subject')
        restored[str(ordinal)][stream]=dict(bytes=size,sha256=sha)
    need(restored==captured,'whole public capture columns invert exactly; no omitted failed capture')
    value['captures']=dict(columns=['ordinal','stream','bytes','sha256'],rows=capture_rows)
    tables={}
    for key,keys in(('unrolled',unrolled_reports.KEYS),('scalar',reuse.reports.reuse.old.KEYS),('reuse',reuse.reports.reuse.KEYS),
                    ('current',custody.reports.KEYS),('span',fixture.reports.KEYS),('span_reuse',reuse.reports.reuse.KEYS)):
        tables[key]=counter_table(r['cases'],key,keys)
    route_keys=[k+'.'+f for k,fs in maps.ROUTES.items()for f in fs]
    tables['routes']=dict(columns=['ordinal',*route_keys],rows=[[c['ordinal'],*c['routes']]for c in r['cases']if 'routes'in c])
    value['counter_tables']=tables
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<96<<10 and len(data)<32<<10 and not any(x and len(x)>1 and(x in text or x in stream.getvalue())for x in
         (str(ROOT),str(Path.home()),platform.node(),'/home/')),'unchanged bounded public numerical output without host paths/logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as f:f.write(data)
    with path.open('x')as f:f.write(text)
