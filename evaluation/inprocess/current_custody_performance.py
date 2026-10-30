"""Four qualified prerequisites, then the fixed82 current-custody experiment.

This explicit profile retains the original process owner and all82 gates. The
old scalar-reuse and observe/unrolled profiles remain independently available.
"""
import csv,importlib.util,io,json,platform,statistics
from pathlib import Path
from page_cost_compare import (PROGRAM_ENV,SELECTED,need,fact,digest,source,
    pair,build_dr,dr_diagnostics)
from unrolled_hash_build import build_bridge as build_unrolled
from current_custody_production_build import build_bridge as build_current
from scalar_reuse_performance import closed
import scalar_region_owner as case_codec
from unrolled_hash_owner import BOUNDS as OWNER_BOUNDS, ORDER as OWNER_ORDER
import current_custody_profile as qualification
import current_custody_performance_reports as reports
import unrolled_hash_reports as unrolled_reports
import maps_view as maps

ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
LANES=('unrolled','current','differential','native','dynamorio')
ORDER=tuple((kind,repeat,lane)for repeat in range(10)
    for kind in(('ls','true')if repeat%2==0 else('true','ls'))
    for lane in(LANES[:2]if repeat%2==0 else LANES[1::-1]))+(
    ('ls',0,'differential'),('true',0,'differential'))+tuple(
    (kind,repeat,lane)for repeat in range(10)
    for kind in(('ls','true')if repeat%2==0 else('true','ls'))
    for lane in(LANES[3:]if repeat%2==0 else LANES[:2:-1]))
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
RECEIPTS=('current_component_receipt','current_owner_receipt')
REQUIRED=qualification.REQUIRED|{
    'evaluation/inprocess/current_custody_performance.py',
    'evaluation/inprocess/current_custody_performance_reports.py',
    'evaluation/inprocess/current_custody_production_build.py',
    'evaluation/inprocess/current_custody_reports.py',
    'evaluation/inprocess/scalar_reuse_performance.py',
    'evaluation/inprocess/dynamorio-null/CMakeLists.txt',
    'evaluation/inprocess/dynamorio-null/null.c',
    'tools/page-entry/selected/build-unrolled-hash.sh',
    'tools/page-entry/selected/tests/current_custody/extents.py'}


def arguments(a):
    need(all(getattr(a,key)is not None for key in (*RECEIPTS,'sdk')),
         'both current qualification receipts and an actual SDK are required')
    need(all(getattr(a,key)is None for key in
         ('region_decoder_receipt','region_component_receipt','reuse_owner_receipt')),
         'scalar receipts do not qualify the separate current-custody profile')
    for key in RECEIPTS:
        path=getattr(a,key).resolve().relative_to(ROOT)
        need(path.parent==Path('evaluation/inprocess/results')and path.suffix=='.json',
             'additional qualification receipt is tracked under evaluation results')
        setattr(a,key,path)
    a.sdk=a.sdk.resolve(strict=True)


def reproduce(a):
    return ['--current-custody',*[x for key in RECEIPTS for x in
        ('--'+key.replace('_','-'),str(getattr(a,key)))],'--sdk','${SDK}']


def prerequisites(a,r,pin,binary):
    for kind,path in(('component',a.component_receipt),('owner',a.owner_receipt)):
        _,actual=closed(path,r,pin,binary)
        if kind=='owner':
            need(all(actual['totals'][k]==v for k,v in dict(application_reader_refusals=234,
                 terminal_reader_refusals=542,owner_reader_refusals=472).items()),
                 'all original actual-owner supplied controls remain mandatory')
    qualification.prerequisites(a,r,pin,binary)
    r['prerequisites']['current_component']=r['current_prerequisites']['component28']
    public,actual=closed(a.current_owner_receipt,r,pin,binary)
    need(public['profile']==actual['profile']=='current-custody-owner-v1'and
         public['status']==actual['status']=='passed'and actual['current_custody']is True,
         'complete distinct current-custody owner qualification')
    expected=dict(planned=25,launched=25,qualified=25,native=9,gated=9,owner_controls=7,qualified_pairs=9,
        required_read_faults=2,required_owner_refusals=7,completed_applications=14,required_reference_faults=2,
        application_reader_refusals=234,terminal_reader_refusals=542,owner_reader_refusals=472)
    need(actual['totals']==expected and actual['build']['decoder_features']==[] and actual['bounds']==OWNER_BOUNDS and
         [(c['lane'],c['mode'],c['control'])for c in actual['cases']]==list(OWNER_ORDER) and
         all(c['launched']is True and c['exit']==c['expected_exit']and c['status'].startswith('qualified_')for c in actual['cases']),
         'all original25 outcomes, exact refusals and default archive in current profile')
    required=dict(status='passed',planned=27,launched=27,native=9,original_gated=16,
        extra_gated=2,native_prefix_frames=36,protected_prefix_frames=70,stale_refusals=1,physical_fallbacks=1,
        prefix_application_refusals=150,extra_application_refusals=26,extra_terminal_refusals=68,
        appendix_refusals=1073,current_terminal_refusals=468,extra_legacy_owner_refusals=29,compiled_storage_objects=9,compiled_storage_refusals=44,
        performance_credit=False)
    need(actual['current_qualification']==required and public['current_custody']['qualification']==required,
         'all27 actual subjects, full native prefix state, protected storage and all separate refusals')
    need(actual['current_prerequisites']==r['current_prerequisites'],
         'owner27 used exactly the selected same-revision/same-CPU component9 and component28')
    need([(c['label'],c['current_control'],c['physical_fallback'],c['expected_exit'],c['exit'],c['status'],c['launched'])for c in actual['current_cases']]==[
        ('subject-current-stale',1,False,125,125,'qualified_required_stale_refusal',True),
        ('subject-current-physical-fallback',0,True,0,0,'qualified_physical_fallback',True)],
        'both actual additional current-custody outcomes are present and independently qualified')
    rows=[]
    for c in actual['cases']:
        row={k:c[k]for k in ('label','lane','mode','control','expected_exit','status','launched','exit',
            'whole_process_ns','timed_out','captures','pair','owner_summary','control_reference','error_type')if k in c}
        row.update(terminal_control_count=len(c.get('terminal_controls',{}).get('refusals',[])),
            terminal_controls_sha256=digest(c.get('terminal_controls',{})),
            application_control_count=c.get('application_controls',{}).get('supplied_refusals',0),
            owner_control_count=len(c.get('owner_reader_controls',{}).get('refusals',[])),
            owner_controls_sha256=digest(c.get('owner_reader_controls',{})))
        rows.append(row)
    need(digest(case_codec.expand_cases(public))==digest(rows),'every original25 public value/type/presence matches its actual row')
    projected={'reproduce':[],'scope':''};qualification.project(projected,actual)
    need(digest(public['current_custody'])==digest(projected['current_custody']),'every extra actual outcome and current metadata projection matches')
    r['prerequisites']['current_owner']=dict(file=a.current_owner_receipt.name,**fact(pin(a.current_owner_receipt)),
        private_receipt=public['private_receipt'],profile=actual['profile'],status='passed',totals=expected,
        current_qualification=required,commands=len(actual['commands']),commands_sha256=digest(actual['commands']))


def cohort(builder,products,private,pin,binary,aliases,run,r,a,builders):
    need(builder.extra_decoder_sources==()and builder.decoder_features==()and
         builder.record['decoder_features']==[],'old unrolled baseline uses the original default archive')
    r['release_builds']={};bridges={};roots={}
    for lane in LANES[:3]:
        root=private/lane;root.mkdir();roots[lane]=root;state=r['release_builds'][lane]={}
        def labelled(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
        if lane=='unrolled':bridges[lane]=build_unrolled(builder,products,root,pin,binary,aliases,labelled,state,())
        else:bridges[lane]=build_current(builder,products,root,pin,binary,aliases,labelled,state,
                                      ('MAPS_CURRENT_TF','MAPS_DIFFERENTIAL')if lane=='differential'else('MAPS_CURRENT_TF',))
    normal=r['release_builds']['current']['release_build']['argv']
    differential=r['release_builds']['differential']['release_build']['argv']
    need([x.replace(str(roots['differential']),str(roots['current']))for x in differential
         if x!='-DLI2_MAPS_DIFFERENTIAL=1']==normal,'current normal/DIFF differ only by declared diagnostic macro and output')
    spec=importlib.util.spec_from_file_location('current_performance_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={};states={}
    for lane in LANES[:3]:
        for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]:
            states[kind,lane]=pair.prepare_workload(kind+'-'+lane,path,args,bridges[lane],builder,private,pin,binary,run,r,namespace)
    for kind in('ls','true'):
        for lane in LANES[1:3]:
            need(all(r[key][kind+'-unrolled']==r[key][kind+'-'+lane]for key in
                 ('system_inputs','namespace_plans','external_inputs')),'whole original/interpreter/dependency inputs match across profiles')
    drrun,client,dr_env=build_dr(a.sdk,builder,private,pin,binary,run,r)
    dr_diagnostics(drrun,client,{k:states[k,'unrolled']for k in('ls','true')},private,pin,binary,run,r,dr_env)
    need(len(r['dr_diagnostics'])==3 and all(x['status']=='passed'for x in r['dr_diagnostics']),
         'all original actual DR exec/target/client/exit proofs before measured launches')
    r['terminal_reports']={};r['reader_controls']={}
    for ordinal,(kind,repeat,lane)in enumerate(ORDER):
        name=NAMES[ordinal];s=states[kind,lane if lane in LANES[:3]else'unrolled'];case=r['cases'][ordinal]
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
                    controls=unrolled_reports.controls(out,err,args,kind,'unrolled');custody=None
                else:
                    parsed,summary,view,owner,custody=reports.check(out,err,args,kind,lane)
                    controls=reports.controls(out,err,args,kind,lane)
                routes=[parsed[k][f]for k,fields in maps.ROUTES.items()for f in fields]
                need(all(type(x)is int and 0<=x<1<<64 for x in routes),'actual unsigned overlapping route counters')
                r['terminal_reports'][name]=parsed;r['reader_controls'][name]=controls
                case.update(comparison=summary,maps_view=view,unrolled=owner,current=custody,routes=routes)
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



def publish(path,r,private):
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    uk=tuple(k for k in unrolled_reports.KEYS if k not in('current','signals'))
    groups=(('unrolled',uk),('current',reports.KEYS),('maps_view',maps.KEYS))
    columns=fields+[prefix+'.'+key for prefix,keys in groups for key in keys]+['signals.'+k for k in('SEGV','TRAP','ILL','SYS','other')]+[
        'derived.physical_fresh_requests']+[k+'.'+f for k,fs in maps.ROUTES.items()for f in fs]
    rows=[]
    for c in r['cases']:
        rows.append([c.get(k)for k in fields]+[c[prefix][k]if c.get(prefix)else None for prefix,keys in groups for k in keys]+
            (c['unrolled']['signals']if c.get('unrolled')else[None]*5)+
            [c['maps_view']['refreshes']+c['maps_view']['comparisons']if c.get('maps_view')else None]+
            c.get('routes',[None]*sum(map(len,maps.ROUTES.values()))))
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
            current=result['current']['median_ns']
            result['current_median_ratios']={lane:current/result[lane]['median_ns']for lane in('unrolled','native','dynamorio')}
    controls={}
    for name,v in r.get('reader_controls',{}).items():
        current='current_refusals'in v;prior=v['original']if current else v
        controls[name]=dict(original=len(prior['original']['original']['refusals']),maps_view=len(prior['original']['maps_view_refusals']),
            unrolled=len(prior['unrolled_refusals']),current=len(v['current_refusals'])if current else 0,
            raw_stderr_sha256=v['original_stderr_sha256'])
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu',
        'bounds','reproduce','archive','carriers','system_inputs','prerequisites')}
    hw=dict(value['hardware']);flags=hw.pop('isa_flags');hw['isa_flags_sha256']=digest(flags);value['hardware']=hw
    value.update(statistics=statistics_rows,quantiles='inclusive linear interpolation at (n-1)*p; ten samples per complete measured lane/workload',
        scope='All82 required:40 ordinary unrolled/current-custody samples, two current-custody differential validations, then40 fresh native/DynamoRIO samples. Four same-revision/same-CPU qualifications and six actual-TU maps modes are prerequisites. Whole-profile comparison; no observer-only subtraction.',
        timing_scope='Actual pre-Popen through reap includes startup/reporting. No medians, IQR or ratios unless the entire82 and all closure gates pass. Differential and separate DR identity diagnostics have no timing credit. No fixed speed threshold.',
        count_scope='Actual events/signals and overlapping route counters retain their producer scopes; routes are not summed. Maintained physical fresh requests=refreshes+comparisons. Native/DR have no invented handler or maps counts. Current counters do not replace independent full-state/current-custody qualification.',
        sdk_scope='Existing exact DynamoRIO11.91.0 SDK and empty Release client. DR retains its original16GiB virtual-address allowance; other lanes retain512MiB. Earlier failed cohorts remain failed.',
        columns=columns,rows=rows,commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'),csv=dict(file=path.with_suffix('.csv').name,bytes=len(data),sha256=maps.H(data)),
        sdk_files=len(r.get('dynamorio_sdk',{})),sdk_manifest_sha256=digest(r.get('dynamorio_sdk',{})),
        dynamorio_client=r.get('dynamorio_client'),dynamorio_build_commands_sha256=r.get('dynamorio_build_commands_sha256'),
        dr_diagnostics=[{k:v for k,v in x.items()if k!='error'}for x in r.get('dr_diagnostics',[])],
        dr_error_types={x['workload']:x['error'].split(':',1)[0]for x in r.get('dr_diagnostics',[])if x.get('error')},
        finite_cases=[{k:v for k,v in c.items()if k!='error'}for c in r['finite_cases']],
        finite_error_types={str(c['mode']):c['error'].split(':',1)[0]for c in r['finite_cases']if c.get('error')},
        finite_build={k:r.get('finite_build',{})[k]for k in('status','executable','runtime_inputs')if k in r.get('finite_build',{})},
        tool_versions={'default':r.get('build',{}).get('numeric_versions')},
        release_builds={k:{n:s['release_build'][n]for n in('status','recipe','archive','bridge')if n in s.get('release_build',{})}for k,s in r.get('release_builds',{}).items()},
        reader_controls=controls,captures={str(c['ordinal']):c.get('captures',{})for c in r['cases']},
        case_error_types={str(c['ordinal']):c['error'].split(':',1)[0]for c in r['cases']if c.get('error')},
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']))
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<96<<10 and len(data)<32<<10 and not any(x and len(x)>1 and x in text for x in
         (str(ROOT),str(Path.home()),platform.node(),'/home/')),'unchanged bounded public numerical output without host paths/logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as f:f.write(data)
    with path.open('x')as f:f.write(text)
