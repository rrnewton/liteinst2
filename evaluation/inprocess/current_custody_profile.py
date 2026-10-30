"""Explicit current-TF extension of the unchanged25 owner cohort.

Nine actual native references also observe four real prefix boundaries. The
two additional gated subjects exercise stale custody and physical fallback;
they never replace an original case or earn throughput/general-region credit.
"""
import hashlib,json,shutil
from pathlib import Path
from page_selected import ENV,fact,need
from checks import source
from current_custody_build import build_bridge
import maps_current_extents as extents
import current_custody_reports as reports
# This module is loaded only for the explicit current profile, before source closure.
import scalar_region_owner as cases
import scalar_case_strings as strings

ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
H=lambda b:hashlib.sha256(b).hexdigest()
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
EXTRAS=(('stale',1,False,125),('physical-fallback',0,True,0))
CURRENT_CONTROL_COUNTS={(control,0,False):60 for control in range(8)}
CURRENT_CONTROL_COUNTS.update({(0,1,False):52,(0,0,True):61})
REQUIRED={
    'evaluation/inprocess/current_custody_profile.py',
    'evaluation/inprocess/current_custody_reports.py',
    'evaluation/inprocess/current_custody_build.py',
    'evaluation/inprocess/unrolled_hash_build.py',
    'evaluation/inprocess/unrolled_hash_performance.py',
    'evaluation/inprocess/maps_view.py',
    'evaluation/inprocess/maps_current_extents.py',
    'evaluation/inprocess/maps_current_qualification.py',
    'evaluation/inprocess/scalar_region_owner.py',
    'evaluation/inprocess/scalar_case_strings.py',
    'tools/page-entry/selected/build-current-custody.sh',
    *('tools/page-entry/selected/'+x for x in ('current_tf_observe.h',
      'current_tf_observe.inc','current_tf_observe_lifecycle.inc')),
    *('tools/page-entry/selected/tests/current_custody_app/'+x for x in
      ('types.h','native.inc','read.py','build.sh')),
    *('tools/page-entry/selected/tests/current_custody_owner/'+x for x in ('read.py','layout.py','wire.py','stale.py')),
    'tools/page-entry/selected/tests/unrolled_hash_owner/layout.py'}


def digest(value):
    return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def arguments(a):
    paths=(a.component_receipt,a.current_component_receipt)
    need(all(p is not None for p in paths),'both same-revision component prerequisites required')
    for key in ('component_receipt','current_component_receipt'):
        p=getattr(a,key).resolve(strict=True)
        need(p.parent==HERE/'results'and p.suffix=='.json','component receipt in tracked evaluation results')
        setattr(a,key,p)


def closed(public,r,pin,binary):
    """Small exact retained-receipt join; no parser or native replay."""
    public_path=pin(public);value=json.loads(public_path.read_bytes())
    private=ROOT/'target/evaluation/inprocess'/public_path.stem/'receipt.json'
    need(fact(pin(private))==value['private_receipt'],'exact component prerequisite private receipt')
    actual=json.loads(private.read_bytes())
    for record in (value,actual):
        need(record['source']==r['source']==source()and record['expected_revision']==r['expected_revision']and
             record['cpu']==r['cpu']and record['source_unchanged']is True and record['cleanup_complete']is True,
             'same committed revision and reserved CPU with complete prerequisite closure')
    need(actual['hardware']==r['hardware']and actual['error']is None and actual['final_errors']==[]and
         value['final_error_count']==0 and value['failure_type']is None and value['bounds']==actual['bounds'],
         'same actual hardware and no prerequisite error or changed bounds')
    hw=dict(actual['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    need(value['hardware']==hw,'whole actual prerequisite hardware projection')
    aliases=actual.get('aliases_before',actual.get('aliases'))
    need(actual['inputs_before']==actual['inputs_after']and actual['artifacts_before']==actual['artifacts_after']and
         type(aliases)is dict and aliases and actual.get('aliases_after',aliases)==aliases,
         'complete input/artifact/alias prerequisite closure')
    for path,want in actual['inputs_before'].items():
        need(fact(pin(path))==want,'exact retained prerequisite input')
    for path,want in actual['artifacts_before'].items():
        retained=binary(path)
        need(dict(fact(retained),mode=retained.stat().st_mode&0o777)==want,'exact retained prerequisite artifact/mode')
    for lexical,resolved in aliases.items():need(str(pin(lexical))==resolved,'exact prerequisite alias')
    commands=actual['commands']
    need(commands and len({c['name']for c in commands})==len(commands)and all(
        type(c.get('exit'))is int and c.get('reaped')is True and c.get('timed_out')is False and
        not c.get('error')and c.get('cleanup_errors')==[]and type(c.get('descriptors'))is list and
        all(d.get('closed')is True for d in c['descriptors'])and c['bounds']==actual['bounds'][c['profile']]and
        (c.get('expected_exit')is None or c['exit']==c['expected_exit'])for c in commands),
        'every prerequisite command has original bounds, expected outcome and complete cleanup')
    for command in commands:
        for cap in command.get('captures',{}).values():
            path=(private.parent/cap['file']).resolve(strict=True)
            need(path.is_relative_to(private.parent)and fact(binary(path))=={k:cap[k]for k in ('bytes','sha256')},
                 'every actual prerequisite command capture matches the retained bytes')
        sidecar=private.parent/(command['name']+'.json')
        need(json.loads(binary(sidecar).read_bytes())==command,'every actual prerequisite command sidecar')
    need(actual['build']['status']=='passed'and actual['build']['command_completed']is True and
         actual['build']['decoder_features']==[]and value['command_count']==len(commands)and
         value['commands_sha256']==digest(commands),'complete default-archive build and actual command digest')
    csv_path=public_path.with_suffix('.csv')
    need(value['csv']['file']==csv_path.name and fact(pin(csv_path))=={k:value['csv'][k]for k in ('bytes','sha256')},
         'whole actual prerequisite CSV binding')
    return value,actual


def prerequisites(a,r,pin,binary):
    import unrolled_hash_performance as prior
    def exact_pin(path,want=None):
        p=pin(path)
        need(want is None or fact(p)=={k:want[k]for k in ('bytes','sha256')},'exact requested old component input')
        return p
    old=prior.prerequisite(a.component_receipt,a.expect_revision,exact_pin,binary,'component')
    old_public,old_actual=closed(a.component_receipt,r,pin,binary)
    need(old_actual['bounds']['native']==[5,512<<20,16<<20,15],
         'original nine-case component native resource bounds')
    old_rows=[dict({k:v for k,v in c.items()if k not in ('error','reader_controls')},
        reader_control_count=len(c.get('reader_controls',[])),
        reader_controls_sha256=digest(c.get('reader_controls',[])))for c in old_actual['cases']]
    need(old_public['cases']==old_rows,'every original component public row equals its actual retained outcome')
    value,actual=closed(a.current_component_receipt,r,pin,binary)
    need(value['profile']==actual['profile']=='maps-current-component-storage-v1'and
         value['status']==actual['status']=='passed','complete current component/storage prerequisite')
    cases=actual['component_cases'];order=[(p,m)for p in ('projected','verified')for m in range(14)]
    need([(c['profile'],c['mode'])for c in cases]==order and all(
        c['status']==('qualified_component'if m<3 else 'qualified_required_refusal')and c['launched']is True and
        c['exit']==c['expected_exit']==(0 if m<3 else 125)and c['controls']==dict(refusals=25,native_operations=0)
        for c,(p,m)in zip(cases,order,strict=True)), 'all28 actual lifecycle-TU outcomes and700 supplied refusals')
    need(actual['bounds']['finite']==[5,512<<20,16<<20,15]and
         set(actual['current_bridge_builds'])=={'physical','current','verified'},
         'unchanged current component bounds and all three production bridges')
    bridges=actual['current_bridge_builds']
    need(all(v['status']=='passed'and v['release_build']['status']=='passed'for v in bridges.values())and
         all(bridges[p]['storage_proof']['symbols']==9 and bridges[p]['storage_proof']['compiled_only']==1 and
             len(bridges[p]['storage_controls']['refusals'])==44 for p in ('current','verified')),
         'both enabled bridges retain all nine compiled extents and88 refusal controls')
    totals=dict(required_cases=28,launched=28,qualified=28,complete_component=6,required_api_refusals=22,
        supplied_record_refusals=700,compiled_storage_profiles=2,storage_refusals=88)
    need(value['totals']==totals and value['runtime_registration_observed']is False and
         value['genuine_tf_qualified']is False and value['full_frame_qualified']is False,
         'exact component-only totals; no invented genuine-TF prerequisite credit')
    rows=[]
    for c in cases:
        row={k:c.get(k)for k in ('profile','mode','expected_exit','status','exit','launched','duration_ns','timed_out','captures')}
        result=c['result']
        row.update(reader_refusals=c['controls']['refusals'],result_sha256=digest(result),io=result['io'],
            cleanup=result['cleanup'],event_count=len(result['events']),error_type=None)
        rows.append(row)
    need(value['cases']==rows and value['compiled_bridges']=={k:dict(status=v['status'],
        bridge=v['release_build']['bridge'],storage_sha256=digest(v['storage_proof'])if 'storage_proof'in v else None,
        symbols=v.get('storage_proof',{}).get('symbols',0))for k,v in bridges.items()},
        'all28 public outcomes and actual compiled-bridge identities match the private receipt')
    r['current_prerequisites']=dict(component9=old,component28=dict(file=Path(a.current_component_receipt).name,
        **fact(pin(a.current_component_receipt)),private_receipt=value['private_receipt'],profile=actual['profile'],
        status='passed',totals=totals))


def observed_layout(builder,bridge,private,pin,binary,run,r,old):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']))
    script=pin(SELECTED/'tests/current_custody_owner/layout.py')
    _,out,err=run('current-owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual current appendix DWARF row; no inferior')
    current=json.loads(out)
    need(current['record']=='cto_wire'and current['old_bytes']==old['types']['uho_wire']['bytes']and
         0<current['types']['cto_wire']['bytes'] and current['old_bytes']+current['types']['cto_wire']['bytes']+128<16<<20,
         'actual complete old+new wire under original capture bound')
    for key in ('uc_bytes','uc','si'):
        need(current[key]==old[key],'same actual signal ABI across both independent layouts')
    for name in set(current['types'])&set(old['types']):
        need(current['types'][name]==old['types'][name],'whole shared actual DWARF type equality')
    path=private/'current-dwarf-layout.json'
    with path.open('xb')as stream:stream.write(out)
    headers=r['release_build']['headers']
    proof=extents.check(bridge,current['storage'],headers)
    controls=extents.controls(bridge,current['storage'],headers)
    need(proof['symbols']==9 and proof['compiled_only']==1 and len(controls['refusals'])==44,
         'all nine complete fresh-bridge extents and all44 supplied refusals')
    r['current_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script),
        storage=proof,storage_controls=controls)
    return dict(old=old,current=current)


def frames(native,gated,owner):
    """Same actual NX/TRACE boundaries: no GREG/AF/FP mask or origin rewrite."""
    nh,gh=native['header'],gated['header'];c=owner['current_custody']
    need(nh[5]==1 and gh[5]==0 and nh[4]==gh[4]and nh[8:19]==gh[8:19]and
         native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in ('seed','source','stack','data')),
         'complete actual same-mode current-prefix source/hardware/input join')
    need(native['machine'][0]==gated['machine'][0]==MASK and native['machine'][3:]==gated['machine'][3:],
         'whole actual application masks and selectors')
    refs=native['current']['frames'];rows=c['rows'];count=2 if c['current_control']==1 else 4
    need(len(refs)==4 and len(rows)==count,'all real native boundaries and exact actual protected prefix')
    need((c['tls_origin']['fs'],c['tls_origin']['gs'])==gated['machine'][1:3],
         'actual pre-arm runtime TLS equals the gated application observation')
    for index,(observed,reference)in enumerate(zip(rows,refs,strict=False)):
        f=observed['before']
        need(type(f['greg'])is tuple and len(f['greg'])==23 and type(f['fp'])is bytes and len(f['fp'])==65536 and
             f['greg']==reference['greg']and f['fp']==reference['fp']and
             f['fp_bytes']==reference['fp_bytes']and f['mask']==reference['mask']==MASK,
             'all23 actual same-boundary GREGs, exact AF/TF/RF and all65536 FP bytes')
        need(observed['stack']==reference['stack']==native['stack']and
             observed['data']==reference['data']==native['data'],
             'whole actual same-boundary stack160 and data8192')
        need((reference['fs'],reference['gs'])==native['machine'][1:3],
             'independent native prefix TLS remains conserved')
    return dict(native_frames=4,runtime_frames=count,full_gregs=23,fp_bytes=65536,stack_bytes=160,data_bytes=8192)


def case_summary(case,owner):
    value=owner['current_custody']['summary']
    need(type(value)is dict and value and all(type(k)is str and type(v)is int and 0<=v<1<<64
         for k,v in value.items()),'compact actual numeric current-custody summary')
    case['current_summary']=value


def extras(driver,builder,private,pin,binary,run,r,reader,owner_reader,original,app_layout,
           seed_reference,bridge,layout,interp,roots,objects,description,images,raws,
           carrier,carrier_bytes,launcher,native_records):
    planned=[dict(label='subject-current-'+name,lane='gated',mode=0,control=0,current_control=control,
        physical_fallback=fallback,expected_exit=expected,status='unexecuted',launched=False)
        for name,control,fallback,expected in EXTRAS]
    need(r['current_custody']is True and r['current_cases']==planned,
         'one predeclared fixed additional current-TF schedule, including preparation failures')
    for c,(name,control,fallback,expected)in zip(r['current_cases'],EXTRAS,strict=True):
        label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role','gated','--mode','0','--control','0',
            '--current-custody','--current-control',str(control),'--original',original,
            '--preparation',directory/'preparation.json','--carrier',carrier,'--namespace',directory/'namespace',
            '--record-fd','{record_fd}']
        if fallback:argv+=['--physical-fallback']
        for path in roots:argv+=['--library-root',path]
        try:
            try:row,out,err=run(label,argv,profile='program',expected=expected,record=True)
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1]
                    c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),
                        timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in ('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=driver.preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            cap=row['captures']['record'];path=binary(private/cap['file'])
            need(fact(path)=={k:cap[k]for k in ('bytes','sha256')},'whole actual extra protected stream')
            record=path.read_bytes();image=driver.image_inventory(original,interp,carrier,objects,manifest)
            image.update(current_elf=app_layout['current'],current_bridge=bridge.read_bytes())
            def app_read(raw):
                if fallback:return reader.read(raw,0,False,0,app_layout,row['pid'],r['cpu'],seed_reference,fallback=True)
                need(type(raw)is bytes and len(raw)==reader.PREFIX and row['exit']==125,
                     'actual stale-custody prefix only; no hash completion or invented owner control')
                parsed=reader.legacy._prefix(raw,0,False,app_layout,row['pid'],r['cpu'],seed_reference)
                parsed['current']=None;return parsed
            parsed=app_read(out)
            owner=owner_reader.read(record,layout,image,parsed,row['pid'],r['cpu'],expected,
                control=0,current_control=control,fallback=fallback)
            args=(row['pid'],expected,row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,owner,owner_reader)
            terminal,c['terminal']=reports.check_current(err,*args);r['terminal_reports'][label]=terminal
            c['terminal_controls']=reports.controls_current(err,*args)
            need(len(c['terminal_controls']['refusals'])==(35 if fallback else 33),
                 'all fixed additional terminal refusals')
            need(0 in native_records,'independent original mode0 reference required for both additional cases')
            nout,npid=native_records[0]
            native=reader.read(nout,0,True,0,app_layout,npid,r['cpu'],seed_reference)
            c['current_prefix']=frames(native,parsed,owner)
            if fallback:
                def compare(n,g):
                    ref=reader.read(n,0,True,0,app_layout,npid,r['cpu'],seed_reference);app=app_read(g)
                    actual=owner_reader.read(record,layout,image,app,row['pid'],r['cpu'],0,control=0,fallback=True)
                    frames(ref,app,actual);return reader.pair(ref,app,actual)
                c['pair']=compare(nout,out)
                c['application_controls']=reader.controls(compare,nout,out,0)
                c['current_application_controls']=reader.current_controls(compare,nout,out,0)
                need(c['application_controls']==dict(supplied_refusals=26,native_operations=0)and
                     c['current_application_controls']==dict(supplied_refusals=15,native_operations=0),
                     'all26 old application and15 prefix controls for actual physical fallback')
            c['owner_reader_controls']=owner_reader.controls(record,layout,image,parsed,row['pid'],r['cpu'],expected,
                control=0,current_control=control,fallback=fallback)
            need(c['owner_reader_controls']['original_sha256']==H(record)and
                 c['owner_reader_controls']['native_operations']==0,
                 'supplied extra controls bind the whole actual protected stream')
            case_summary(c,owner)
            c['status']='qualified_physical_fallback'if fallback else 'qualified_required_stale_refusal'
        except Exception as error:
            c['status']='failed';c['error_type']=type(error).__name__;c['error']=type(error).__name__+': '+str(error)
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and
                isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise


def complete(r,owner_reader):
    need(len(r['cases'])==25 and all(c['launched']is True and c['status'].startswith('qualified_')for c in r['cases']),
         'all original25 actual native/application/control subjects remain mandatory')
    need(len(r['current_cases'])==2 and [c['status']for c in r['current_cases']]==
         ['qualified_required_stale_refusal','qualified_physical_fallback']and r['error']is None,
         'both additional actual custody outcomes remain mandatory')
    need(sum(c.get('current_application_controls',{}).get('supplied_refusals',0)for c in r['cases'])==135 and
         sum(len(c['terminal_controls']['refusals'])for c in r['current_cases'])==68,
         'all135 original-pair prefix refusals and68 separate terminal refusals')
    need(owner_reader.CURRENT_CONTROL_COUNTS==CURRENT_CONTROL_COUNTS,
         'exact independently bound appendix control table')
    cases=[c for c in r['cases']if c['lane']=='gated']+r['current_cases']
    key=lambda c:(c['control'],c.get('current_control',0),c.get('physical_fallback',False))
    need(len(cases)==18 and set(CURRENT_CONTROL_COUNTS)=={key(c)for c in cases},
         'exact eighteen protected-record control populations')
    for c in cases:
        terminal=c['terminal_controls'];names=terminal['current_row_refusals']
        need(len(names)==len(set(names))==reports.CURRENT_ROW_REFUSALS==26 and terminal['native_operations']==0 and
             terminal['original_stderr_sha256']==c['captures']['stderr']['sha256'],
             'all26 current-row refusals bind each whole actual stderr stream')
        controls=c['owner_reader_controls'];expected=CURRENT_CONTROL_COUNTS[key(c)]
        need(len(controls['current_refusals'])==len(set(controls['current_refusals']))==expected and
             controls['native_operations']==0,
             'all named supplied appendix refusals after actual protected-record acceptance')
        additional=controls['additional_legacy_refusals'];n=29 if c.get('physical_fallback',False)else 0
        need(len(additional)==len(set(additional))==n,
             'all29 unchanged old-record refusals remain separate on the additional physical fallback')
        if c.get('current_control',0)or c.get('physical_fallback',False):
            need(controls['refusals']==[],'additional subjects do not inflate the original472 control population')
    need(sum(len(c['terminal_controls']['current_row_refusals'])for c in cases)==468,
         'all468 current-row refusals in addition to original542 and extra68')
    need(sum(len(c['owner_reader_controls']['current_refusals'])for c in cases)==1073,
         'all1073 separately counted appendix refusals')
    need(sum(c['current_prefix']['native_frames']for c in r['cases']if c['lane']=='native')==36 and
         sum(c['current_prefix']['runtime_frames']for c in cases)==70 and
         all(c['launched']is True for c in r['current_cases']),
         'all actual36 native and70 protected prefix frames, not a planned count')
    r['current_qualification']=dict(status='passed',planned=27,launched=27,native=9,original_gated=16,
        extra_gated=2,native_prefix_frames=36,protected_prefix_frames=70,stale_refusals=1,physical_fallbacks=1,
        prefix_application_refusals=150,extra_application_refusals=26,extra_terminal_refusals=68,
        appendix_refusals=1073,current_terminal_refusals=468,extra_legacy_owner_refusals=29,compiled_storage_objects=9,compiled_storage_refusals=44,
        performance_credit=False)


def project(public,r):
    public['reproduce']+=['--current-custody',*r.get('current_reproduce',[])]
    public['scope']+=' The explicit current-custody profile additionally requires same-revision/same-CPU component9 and current component28 receipts, all actual prefix NX/TRACE native comparisons, runtime nine-object protection joins, one actual stale-custody refusal and one real physical fallback. These two subjects remain separately counted; no scalar-reuse or performance credit.'
    rows=[]
    for c in r['current_cases']:
        row={k:c[k]for k in ('label','lane','mode','control','current_control','physical_fallback','expected_exit',
            'status','launched','exit','whole_process_ns','timed_out','error_type','current_prefix','current_summary')if k in c}
        row.update(application_control_count=c.get('application_controls',{}).get('supplied_refusals',0),
            terminal_control_count=len(c.get('terminal_controls',{}).get('refusals',[])),
            current_terminal_control_count=len(c.get('terminal_controls',{}).get('current_row_refusals',[])),
            owner_control_count=len(c.get('owner_reader_controls',{}).get('current_refusals',[])))
        rows.append(row)
    public['current_custody']=dict(qualification=r['current_qualification'],cases=rows,
        prerequisites=r.get('current_prerequisites'),storage_sha256=digest(r.get('current_layout',{})),
        prefix_case_sha256=digest([{k:c.get(k)for k in ('label','current_prefix','current_application_controls')}
                                  for c in r['cases']]))


def encode_public(public):
    """Reuse the committed typed v2 codec; preserve every whole JSON value."""
    original=json.loads(json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False))
    packed=strings.project(cases.case_projection(original['cases']))
    encoded=dict(original,**packed)
    restored=strings.restore(encoded)
    restored['cases']=cases.expand_cases(restored)
    for key in packed:
        if key!='cases':
            if key in restored:del restored[key]
    need(json.dumps(restored,sort_keys=True,separators=(',',':'),allow_nan=False)==
         json.dumps(original,sort_keys=True,separators=(',',':'),allow_nan=False),
         'whole typed public receipt survives the unchanged v2 codec exactly')
    return encoded
