"""Explicit 82-attempt release profile; imported only with --scalar-reuse.

The original 42-attempt driver remains the default and owns every command,
input, artifact and final closure. This module supplies the new fixed schedule.
"""
import csv,importlib.util,io,json,platform,statistics
from pathlib import Path
from page_cost_compare import (Build,PROGRAM_ENV,SELECTED,need,fact,digest,source,
    before_default,pair,build_dr,dr_diagnostics)
from unrolled_hash_build import build_bridge as build_unrolled
from scalar_region_reuse_build import build_bridge as build_reuse
import scalar_region_owner as qualification
import scalar_case_strings
import scalar_region_mapping_controls as mapping
import scalar_reuse_performance_reports as reports
import unrolled_hash_reports as unrolled_reports
import maps_view as maps

ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
LANES=('unrolled','scalar-reuse','differential','native','dynamorio')
ORDER=tuple((kind,repeat,lane)for repeat in range(10)
    for kind in(('ls','true')if repeat%2==0 else('true','ls'))
    for lane in(LANES[:2]if repeat%2==0 else LANES[1::-1]))+(
    ('ls',0,'differential'),('true',0,'differential'))+tuple(
    (kind,repeat,lane)for repeat in range(10)
    for kind in(('ls','true')if repeat%2==0 else('true','ls'))
    for lane in(LANES[3:]if repeat%2==0 else LANES[:2:-1]))
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
RECEIPTS=('region_decoder_receipt','region_component_receipt','reuse_owner_receipt')
REQUIRED={
    'evaluation/inprocess/scalar_reuse_performance.py',
    'evaluation/inprocess/scalar_reuse_performance_reports.py',
    'evaluation/inprocess/scalar_reuse_reports.py',
    'evaluation/inprocess/scalar_region_owner.py',
    'evaluation/inprocess/scalar_case_strings.py',
    'evaluation/inprocess/scalar_region_reuse_build.py',
    'evaluation/inprocess/dynamorio-null/CMakeLists.txt',
    'evaluation/inprocess/dynamorio-null/null.c',
    'tools/page-entry/selected/build-scalar-region-reuse.sh',
    'tools/page-entry/selected/selected_scalar_reuse.inc',
    'tools/page-entry/selected/selected_scalar_region.inc',
    'tools/page-entry/selected/decoder/src/region.rs'}


def arguments(a):
    need(all(getattr(a,key)is not None for key in (*RECEIPTS,'sdk')),
         'all three additional same-revision receipts and an actual SDK are required')
    for key in RECEIPTS:
        path=getattr(a,key).resolve().relative_to(ROOT)
        need(path.parent==Path('evaluation/inprocess/results')and path.suffix=='.json',
             'additional qualification receipt is tracked under evaluation results')
        setattr(a,key,path)
    a.sdk=a.sdk.resolve(strict=True)


def reproduce(a):
    return ['--scalar-reuse',*[x for key in RECEIPTS for x in
        ('--'+key.replace('_','-'),str(getattr(a,key)))],'--sdk','${SDK}']


def closed(public,r,pin,binary):
    """Exact retained facts and closure, without reader or native replay."""
    public_path=pin(public);value=json.loads(public_path.read_bytes())
    if value.get('case_encoding')=='shared-numerical-columns-v2':value=scalar_case_strings.restore(value)
    private=ROOT/'target/evaluation/inprocess'/public_path.stem/'receipt.json'
    need(fact(pin(private))==value['private_receipt'],'exact prerequisite private receipt')
    actual=json.loads(private.read_bytes())
    need(actual['source']==r['source']==source()and actual['expected_revision']==r['expected_revision']and
         actual['cpu']==r['cpu']and actual['hardware']==r['hardware']and actual['source_unchanged']is True and
         actual['cleanup_complete']is True and actual['error']is None and actual['final_errors']==[],
         'same committed revision, actual reserved CPU/hardware and closed prerequisite')
    need(value['source']==actual['source']and value['expected_revision']==actual['expected_revision']and
         value['cpu']==actual['cpu']and value['source_unchanged']is True and value['cleanup_complete']is True and
         value['final_error_count']==0 and value['totals']==actual['totals']and value['bounds']==actual['bounds'],
         'public prerequisite identity, population, bounds and closure match private data')
    hw=dict(actual['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    need(value['hardware']==hw,'whole public hardware projection matches actual prerequisite')
    aliases=actual.get('aliases_before',actual.get('aliases'))
    need(actual['inputs_before']==actual['inputs_after']and actual['artifacts_before']==actual['artifacts_after']and
         type(aliases)is dict and aliases and actual.get('aliases_after',aliases)==aliases,
         'whole prerequisite input/artifact/alias closure')
    for path,want in actual['inputs_before'].items():pin(path,want)
    for path,want in actual['artifacts_before'].items():
        retained=binary(path);need(dict(fact(retained),mode=retained.stat().st_mode&0o777)==want,
                                  'whole retained prerequisite artifact and mode')
    for lexical,resolved in aliases.items():need(str(pin(lexical))==resolved,'exact prerequisite alias')
    commands=actual['commands']
    need(commands and len({c['name']for c in commands})==len(commands)and all(
        type(c.get('exit'))is int and c.get('reaped')is True and c.get('timed_out')is False and not c.get('error')and
        c.get('cleanup_errors')==[]and type(c.get('descriptors'))is list and all(d.get('closed')is True for d in c['descriptors'])and
        c['bounds']==actual['bounds'][c['profile']]and(c.get('expected_exit')is None or c['exit']==c['expected_exit'])for c in commands),
        'every prerequisite command has exact bounds, expected outcome and complete cleanup')
    need(actual['build']['status']=='passed'and actual['build']['command_completed']is True and
         value.get('command_count',value.get('commands'))==len(commands)and
         value.get('commands_sha256',value.get('command_rows_sha256'))==digest(commands),
         'actual complete prerequisite build and command digest')
    csv_path=public_path.with_suffix('.csv')
    need(value['csv']['file']==csv_path.name and fact(pin(csv_path))=={k:value['csv'][k]for k in('bytes','sha256')},
         'whole prerequisite CSV')
    return value,actual


def prerequisites(a,r,pin,binary):
    # The original validators have already accepted both old prerequisites.
    for kind,path in(('component',a.component_receipt),('owner',a.owner_receipt)):
        _,actual=closed(path,r,pin,binary)
        if kind=='owner':
            need(all(actual['totals'][k]==v for k,v in dict(application_reader_refusals=234,
                 terminal_reader_refusals=542,owner_reader_refusals=472).items()),
                 'all original actual-owner supplied controls remain mandatory')
    for kind,key in(('decoder','region_decoder_receipt'),('component','region_component_receipt')):
        path=getattr(a,key)
        r['prerequisites']['region_'+kind]=qualification.prerequisite(path,a.expect_revision,pin,binary,kind)
        closed(path,r,pin,binary)
    path=a.reuse_owner_receipt;public,actual=closed(path,r,pin,binary)
    need(public['profile']==actual['profile']=='scalar-region-reuse-owner-v1'and
         public['status']==actual['status']=='passed'and actual['reuse']is True,
         'distinct complete actual reuse-owner qualification')
    expected=dict(planned=43,launched=43,qualified=43,native=13,gated=13,owner_controls=17,qualified_pairs=13,
        completed_applications=14,required_read_faults=6,required_reference_faults=6,required_owner_refusals=17,
        application_reader_refusals=348,terminal_reader_refusals=1964,owner_reader_refusals=4102,boundary_metadata_commands=30)
    need(actual['totals']==expected and actual['bounds']==qualification.BOUNDS and
         actual['build']['decoder_features']==['scalar-region'],'all43 exact cases, controls, bounds and feature archive')
    cases=actual['cases']
    need([(c['lane'],c['mode'],c['control'])for c in cases]==list(qualification.REUSE_ORDER)and
         all(c['launched']is True and c['exit']==c['expected_exit']and c['status'].startswith('qualified_')for c in cases),
         'all actual original40 and additive3 subjects with their required outcomes')
    fields=('label','lane','mode','control','expected_exit','status','launched','exit','whole_process_ns','timed_out',
            'captures','pair','owner_summary','control_reference','boundary_observation','error_type')
    rows=[]
    for c in cases:
        row={k:c[k]for k in fields if k in c}
        row.update(terminal_control_count=len(c.get('terminal_controls',{}).get('refusals',[])),
            terminal_controls_sha256=digest(c.get('terminal_controls',{})),
            application_control_count=c.get('application_controls',{}).get('supplied_refusals',0),
            owner_control_count=len(c.get('owner_reader_controls',{}).get('refusals',[])),
            owner_controls_sha256=digest(c.get('owner_reader_controls',{})))
        rows.append(row)
    need(digest(qualification.expand_cases(public))==digest(rows),'every public owner outcome equals its actual closed row')
    state=actual['mapping_controls']
    need(state['planned']==8 and state['status']=='passed'and len(state['cases'])==8 and
         [c['name']for c in state['cases']]==[c[0]for c in mapping.CASES]and all(
         c['status']=='qualified_mapping_refusal'and c['launched']is True and c['exit']==125 and
         c['failure_code']==spec[-1]and c['reader_refusals']==19 and c['completed_applications']==0 and
         c['generated_owner_credit']is False for c,spec in zip(state['cases'],mapping.CASES,strict=True))and
         public['mapping_controls']==mapping.public_summary(state),'all eight separately qualified real mapping refusals')
    guard=actual['mapping_guard_summary'];seed=actual['seed_prerequisite']
    need(guard==public['mapping_guard_oracle']and guard['status']=='passed_predicate_only'and guard['exit']==0 and
         guard['result']==dict(version=1,predicate_only=1,cases=754,allowed=273,refused=481,live_rseq=0,live_owner=0)and
         seed['status']=='passed'and seed['launched']is True and seed['exit']==0 and seed['bounds']==[5,512<<20,16<<20,15],
         'all754 predicate cases and independent actual same-CPU seed prerequisite')
    r['prerequisites']['reuse_owner']=dict(file=path.name,**fact(pin(path)),private_receipt=public['private_receipt'],
        profile=actual['profile'],status=actual['status'],totals=expected,commands=len(actual['commands']),
        commands_sha256=digest(actual['commands']),mapping_refusals=8,mapping_reader_refusals=152,predicate_cases=754)


def region_builder(private,pin,binary,aliases,run,r,builders):
    root=private/'region-build';root.mkdir();state=r['region_build']={}
    def labelled(name,argv,**kwargs):return run('region-'+name,argv,**kwargs)
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,aliases,labelled,state)
        return labelled(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(state,root,pin,binary,build_run,extra_decoder_sources=('region.rs',))
    builders.append(builder)
    return builder,builder.prepare()


def cohort(builder,products,private,pin,binary,aliases,run,r,a,builders,*,certificate=False):
    lanes,order,names=LANES,ORDER,NAMES
    active_build,active_reports=build_reuse,reports
    if certificate:
        import scalar_reuse_certificate_performance as selected_profile
        import scalar_reuse_certificate_performance_reports as active_reports
        from scalar_region_reuse_certificate_build import build_bridge as active_build
        need(r['profile']=='scalar-reuse-certificate-performance-v1','explicit distinct certificate release profile')
        lanes,order,names=selected_profile.LANES,selected_profile.ORDER,selected_profile.NAMES
    need(builder.extra_decoder_sources==()and builder.decoder_features==()and
         builder.record['decoder_features']==[],'old unrolled baseline uses the original default archive')
    retained={k:dict(fact(v),mode=v.stat().st_mode&0o777)for k,v in products.items()}
    selected,region_products=region_builder(private,pin,binary,aliases,run,r,builders)
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
    if certificate:
        prerequisite=r['prerequisites']['certificate_owner']
        for lane in lanes[1:3]:
            built=r['release_builds'][lane]['release_build'];binding=built['certificate_binding']
            need(digest({k:binding[k]for k in('version','archive','policy','header')})==digest(prerequisite['binding'])and
                 digest(binding['policy_inputs'])==prerequisite['policy_inputs_sha256']and
                 binding['archive']==r['region_archive']and 'capture_config'not in built and
                 '-DLI2_MAPS_CURRENT_TF=1'not in built['argv']and
                 '-DLI2_SCALAR_REGION_REUSE_CERTIFICATE=1'in built['argv'],
                 'same qualified archive/policy/header; release certificate only, without current-TF or capture')
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
                    if certificate:
                        parsed,summary,view,owner,scalar,retirement,proof=active_reports.check(out,err,args,kind,lane)
                        case['certificate']=proof
                        controls=active_reports.controls(out,err,args,kind,lane)
                        need(len(controls['scalar_reuse_refusals'])==86 and len(controls['certificate_refusals'])==15,
                             'all original86 scalar/reuse and additional15 certificate terminal refusals')
                    else:
                        parsed,summary,view,owner,scalar,retirement=reports.check(out,err,args,kind,lane)
                        controls=reports.controls(out,err,args,kind,lane)
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


def publish(path,r,private,*,certificate=False):
    lanes=LANES
    if certificate:
        from scalar_reuse_certificate_performance import LANES as lanes
        from scalar_reuse_certificate_reports import CERTIFICATE_KEYS
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    uk=tuple(k for k in unrolled_reports.KEYS if k not in('current','signals'))
    sk=tuple(k for k in reports.reuse.old.KEYS if k not in('current','signals','refusals','exit_indices'))
    groups=(('unrolled',uk),('scalar',sk),('reuse',reports.reuse.KEYS),('maps_view',maps.KEYS))
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
        for lane in lanes:
            cases=[c for c in r['cases']if c['workload']==kind and c['lane']==lane]
            times=[c['process_ns']for c in cases if c['status']=='passed']
            row=result[lane]=dict(planned=1 if lane=='differential'else 10,passed=len(times),timing_credit=bool(complete and lane!='differential'))
            if row['timing_credit']:
                need(len(times)==10,'all ten actual samples for this complete lane');q=statistics.quantiles(times,n=4,method='inclusive')
                row.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
        if complete:
            scalar=result[lanes[1]]['median_ns']
            result['certificate_reuse_median_ratios'if certificate else'scalar_reuse_median_ratios']={lane:scalar/result[lane]['median_ns']for lane in('unrolled','native','dynamorio')}
    controls={}
    for name,v in r.get('reader_controls',{}).items():
        scalar='scalar_reuse_refusals'in v;prior=v['original']if scalar else v
        controls[name]=dict(original=len(prior['original']['original']['refusals']),maps_view=len(prior['original']['maps_view_refusals']),
            unrolled=len(prior['unrolled_refusals']),scalar_reuse=len(v['scalar_reuse_refusals'])if scalar else 0,
            raw_stderr_sha256=v['original_stderr_sha256'])
        if certificate:controls[name]['certificate']=len(v.get('certificate_refusals',[]))
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu',
        'bounds','reproduce','archive','region_archive','carriers','system_inputs','prerequisites')}
    hw=dict(value['hardware']);flags=hw.pop('isa_flags');hw['isa_flags_sha256']=digest(flags);value['hardware']=hw
    value.update(statistics=statistics_rows,quantiles='inclusive linear interpolation at (n-1)*p; ten samples per complete measured lane/workload',
        scope='All82 required:40 ordinary unrolled-normal/scalar-reuse-normal, two scalar-reuse differential validations, then40 fresh native/DynamoRIO samples. Five same-revision/same-CPU qualifications and six actual-TU maps modes are prerequisites. Whole-profile comparison; no observer-only subtraction.',
        timing_scope='Actual pre-Popen through reap includes startup/reporting. No medians, IQR or ratios unless the entire82 and all closure gates pass. Differential and separate DR identity diagnostics have no timing credit. No fixed speed threshold.',
        count_scope='Actual events/signals and overlapping route counters retain their producer scopes; routes are not summed. Maintained physical fresh requests=refreshes+comparisons. Native/DR have no invented handler or maps counts. Scalar terminal rows do not replace independent full-state/retirement qualification.',
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
        tool_versions={name:record.get('numeric_versions')for name,record in(('default',r.get('build',{})),('region',r.get('region_build',{}).get('build',{})))},
        release_builds={k:{n:s['release_build'][n]for n in('status','recipe','archive','bridge')if n in s.get('release_build',{})}for k,s in r.get('release_builds',{}).items()},
        reader_controls=controls,captures={str(c['ordinal']):c.get('captures',{})for c in r['cases']},
        case_error_types={str(c['ordinal']):c['error'].split(':',1)[0]for c in r['cases']if c.get('error')},
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']))
    if certificate:
        value['scope']='All82 required:40 ordinary unrolled-normal/certificate-reuse-normal, two certificate-reuse differential validations, then40 fresh native/DynamoRIO samples. Six same-revision/same-CPU qualifications (including all43 certificate owner cases and separate8 transaction cases) plus six actual-TU maps modes are prerequisites. Whole-profile comparison; no observer-only subtraction. CURRENT_TF is absent; its failed comparison remains failed.'
        value['count_scope']+=' Certificate static plan proofs=publications+retirement_attempts, static rseq proofs=publications, certificate comparisons=2*entries and live rseq guards=3*entries. These are actual producer counts, not inferred speedups.'
        value['certificate_rows']=dict(columns=['ordinal',*CERTIFICATE_KEYS],
            rows=[[case['ordinal'],*[case['certificate'][key]for key in CERTIFICATE_KEYS]]
                  for case in r['cases']if 'certificate'in case])
        value['certificate_bindings']={lane:{k:state['release_build']['certificate_binding'][k]
            for k in('version','archive','policy','header')}for lane,state in r.get('release_builds',{}).items()
            if 'certificate_binding'in state.get('release_build',{})}
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<96<<10 and len(data)<32<<10 and not any(x and len(x)>1 and x in text for x in
         (str(ROOT),str(Path.home()),platform.node(),'/home/')),'unchanged bounded public numerical output without host paths/logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as f:f.write(data)
    with path.open('x')as f:f.write(text)
