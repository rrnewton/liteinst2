"""Fixed lifecycle subjects and whole actual native/owner/control joins.

Reader/control/report modules are mandatory source dependencies. Their absence
raises inside the collector's retained attempt; no accepting stand-in exists.
"""
import json
from pathlib import Path
import shutil
from page_selected import ENV, fact, need
from persistent_dynamic import H, load, named, image_inventory, raw_emission, imported_sources, digest
from persistent_loop_lifecycle_native_build import FIXTURE, preparation
from persistent_loop_effects_lifecycle_build import build_bridge
from direct_frontier_loop_helpers import prepare_inputs
from persistent_loop_owner_build import inputs_completed
from persistent_loop_native import SCHEDULE as PAIRED_NATIVE_SCHEDULE
from persistent_loop_owner_helpers import LANE_SCHEDULE

ROOT=Path(__file__).resolve().parents[2]
OWNER=ROOT/'tools/page-entry/selected/tests/persistent_loop_effects_lifecycle_owner'
PROFILE='persistent-loop-effects-lifecycle-v1'
LANES=('maintained','differential')
NATIVE_ORDER=tuple((case,place)for case in range(2)for place in range(2))
ORDER=tuple((lane,case,place)for lane in LANES for case,place in NATIVE_ORDER)
# Only the three actual model symbol names differ in the retained build prefix.
NATIVE_BUILD_SCHEDULE=tuple((name.replace('lp_inputs','lc_inputs').replace(
    'lp_model_init','lc_model_init').replace('lp_advance','lc_advance'),profile)
    for name,profile in PAIRED_NATIVE_SCHEDULE[:54])
SCHEDULE=NATIVE_BUILD_SCHEDULE+tuple(('subject-native-'+str(c)+'-'+str(p),'program')
    for c,p in NATIVE_ORDER)+tuple((lane+'-'+name,profile)for lane in LANES
    for name,profile in LANE_SCHEDULE)+tuple(('subject-'+lane+'-'+str(c)+'-'+str(p),'program')
    for lane,c,p in ORDER)
RAW_BYTES=16744832
COVERAGE=('cold_policy12','cold_policy11_complete_no_envelope',
    'warm_mixed_transfer_and_completion','reversed_primary_order',
    'replacement_generation_and_old_permit_revocation',
    'held_cancellation_and_one_ordinary_replay','full_state_pairs_and_controls')


def contracts(native_controls,owner_reader,reports):
    """Exact source-owned populations, never expectations supplied by a receipt.

The new lifecycle control modules must define these literal values. They are
not inferred from paired-v2 populations or accepted from a passing summary.
"""
    n=native_controls.NATIVE_COUNTS;o=owner_reader.OWNER_COUNTS
    need(type(n)is tuple and n==(1222,1101)and type(o)is tuple and o==(723,723),
         'reviewed source-owned lifecycle native and owner control populations')
    values=dict(native=n,owner=o,application=native_controls.MAINTAINED_COUNT,
        metadata=native_controls.METADATA_COUNT,elf=native_controls.ELF_COUNT,
        pair=owner_reader.PAIR_COUNT,pf=owner_reader.PF_COUNT,terminal=reports.CONTROL_COUNT,
        effects=owner_reader.EFFECTS_COUNT)
    need(all(type(v)is int and v>0 for k,v in values.items()if k not in('native','owner'))and
         values['application']==596 and values['metadata']==24 and values['elf']==33 and
         values['pair']==1069 and values['pf']==36 and values['terminal']==360 and values['effects']==319,'all lifecycle control classes and whole full-state pair population')
    values['expected']=owner_reader.EXPECTED_COUNT
    need(type(values['expected'])is int and values['expected']==10,
         'separate actual lifecycle expected-value control population')
    return values


def providers(pin,native_controls):
    owner=load('loop_lifecycle_owner',OWNER/'read.py',pin)
    reports=load('loop_lifecycle_reports',ROOT/'evaluation/inprocess/persistent_loop_effects_lifecycle_reports.py',pin)
    return owner,reports,contracts(native_controls,owner,reports)


def native_summary(value,case,place):
    need(value['lane']==0 and value['mode']==case and value['placement']==place and
         value['native_reference_complete']is True and value['application_complete']is True and
         value['actual_fault']is False and value['native_instructions']==(50,42)[case]and
         value['native_frames']==len(value['frames'])==(51,43)[case]and
         all(value[k]is False for k in('owner_validated','mixed_policy_validated',
                                      'qualification_credit','performance_credit')),
         'complete actual lifecycle native reference with every full memory snapshot')
    return dict(case=case,placement=place,raw_sha256=value['raw_sha256'],
        native_instructions=value['native_instructions'],native_frames=value['native_frames'],
        actual_fault=False,native_reference_complete=True,application_complete=True,
        owner_validated=False,mixed_policy_validated=False,qualification_credit=False,performance_credit=False)


def application_controls(value,layout_names,count,raw_sha,expected_metadata,*,lane):
    names=value['refusals']
    need(type(lane)is int and lane in(0,1)and
         value['scope']==('supplied_native_reference_corruptions_only'if lane==0 else
                         'supplied_maintained_application_corruptions_only')and
         value['status']=='passed'and type(names)is list and value['count']==len(names)==len(set(names))==count and
         all(type(n)is str and n for n in names)and value['raw_sha256']==raw_sha and
         type(value['native_operations'])is int and value['native_operations']==0 and
         value['owner_pair_unavailable']is True and value['owner_validated']is False and
         value['mixed_policy_validated']is False and value['qualification_credit']is False and
         value['performance_credit']is False and value['layout_controls']==layout_names and
         type(layout_names)is list and all(type(n)is str and n for n in layout_names)and
         value['layout_count']==len(layout_names)==len(set(layout_names))==expected_metadata,
         'whole actual lifecycle application and layout corruption rosters')


def observed_layout(builder,bridge,private,pin,binary,run,r,*,completed=False):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment)
    need(out and not err,'actual no-inferior lifecycle DWARF tool')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one complete actual lifecycle DWARF row')
    layout=json.loads(out);extents=r['release_build']['capture_extents']
    need(layout['record']=='pdo_wire'and layout['types']['pdo_wire']['bytes']==extents['wire']==RAW_BYTES and
         extents['schema_version']==17 and
         extents['encoded']==extents['record_limit']==extents['stream_strictly_below']==4<<20,
         'whole actual schema17 layout and unchanged strict encoded4MiB cap')
    path=private/'owner-dwarf-layout.json'
    if completed:need(path.read_bytes()==out,'whole retained actual no-inferior lifecycle layout')
    else:
        with path.open('xb')as stream:stream.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script))
    return layout


def case_argv(builder,original,case,directory,roots,carrier,pin):
    role='native'if case['lane']==0 else'gated'
    argv=[builder.tools['python'],'-B',pin(FIXTURE/'launch.py'),'--root',ROOT,'--role',role,
        '--case',str(case['mode']),'--placement',str(case['placement']),'--control','0',
        '--original',original,'--preparation',directory/'preparation.json']
    for p in roots:argv+=['--library-root',p]
    if role=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
    return argv


def owner_summary(owner):
    keys=('mode','placement','plan_version','fallback_policy','schema_version','status','code','detail',
        'orientation','cold_publications','warm_entries','generated_entries','generated_completed','dual_entries',
        'completion_permits','original_branch_replays','ordinary_store_replays','interior_signals',
        'replacements','companion_replacements','permit_claims','replacement','single_orientation_only',
        'reversed_primary_order_validated','full_state_pair_validated','qualification_credit','performance_credit')
    need(owner['schema_version']==17 and owner['status']==owner['code']==owner['detail']==0 and
         owner['cold_publications']==3 and owner['warm_entries']==1 and
         owner['generated_entries']==owner['generated_completed']==4 and owner['dual_entries']==1 and
         owner['completion_permits']==5 and owner['original_branch_replays']==4 and
         owner['ordinary_store_replays']==owner['companion_replacements']==1 and owner['interior_signals']==0 and
         owner['single_orientation_only']is True and owner['reversed_primary_order_validated']is False and
         owner['qualification_credit']is False and owner['performance_credit']is False and
         type(owner['effects_stages'])is list and len(owner['effects_stages'])==16,
         'one genuine full lifecycle orientation, no invented cross-case qualification')
    return dict({k:owner[k]for k in keys},encoded_sha256=owner['encoded_sha256'],raw_sha256=owner['raw_sha256'],
        loop_terminal=owner['loop_terminal'],pf_refusals=owner['pf_refusals'],
        effects_terminal=owner['effects_terminal'],effects_snapshot_count=len(owner['effects_stages']))


def evaluate(case,row,stdout,stderr,record,layout,image,support,native,owner_reader,reports,
             counts,images,raws,carrier,*,progress=None):
    need(type(row['exit'])is int and row['exit']==row['expected_exit']==0 and row['timed_out']is False,
         'actual unchanged expected-zero lifecycle subject')
    mode,place=case['mode'],case['placement'];reader=support['reader'];seed=support['seed_reference']
    args=(stdout,1,mode,place,row['exit'],support['image'],row['pid'],case['cpu'],seed)
    app=reader.read(*args)
    owner_args=(record,layout,image,app,native,row['pid'],case['cpu'],row['exit'])
    owner=owner_reader.read(*owner_args);summary=owner_summary(owner)
    pair=owner_reader.pair(native,app,owner)
    need(pair['schema_version']==17 and pair['status']==0 and pair['case']==mode and pair['placement']==place and
         pair['native_instructions']==(50,42)[mode]and pair['native_full_frames']==(51,43)[mode]and
         pair['cold_policy12']==2 and pair['cold_policy11_complete_no_envelope']==1 and
         pair['warm_mixed_lifetimes']==pair['companion_replacements']==pair['held_cancellations']==
         pair['ordinary_store_replays']==1 and pair['generated_entries']==pair['generated_completed']==4 and
         pair['measured_interior_signals']==0 and pair['single_orientation_only']is True and
         pair['reversed_primary_order_validated']is False and pair['qualification_credit']is False and
         pair['performance_credit']is False,'complete actual native-state lifecycle comparison')
    terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),
        carrier.read_bytes(),owner,owner_reader,mode,app)
    terminal,terminal_summary=reports.check(stderr,*terminal_args,lane=case['build_lane'])
    result=dict(owner_summary=summary,pair=pair,terminal=terminal_summary,
        application=dict(raw_sha256=H(stdout),application_completed=True,native_frames=0,native_instructions=0))
    if progress is not None:progress.update(result)
    application=support['controls'].controls(reader,*args)
    metadata=support['controls'].metadata_controls(reader,support['image'])
    application_controls(application,metadata,counts['application'],H(stdout),counts['metadata'],lane=1)
    result.update(application_controls=application,application_layout_controls=metadata)
    for key,fn in (
        ('owner_reader_controls',lambda:owner_reader.controls(*owner_args)),
        ('pf_refusal_owner_controls',lambda:owner_reader.pf_refusal_controls(*owner_args)),
        ('effects_owner_controls',lambda:owner_reader.effects_controls(*owner_args)),
        ('pair_controls',lambda:owner_reader.pair_controls(native,app,owner)),
        ('terminal_controls',lambda:reports.controls(stderr,*terminal_args,lane=case['build_lane']))):
        result[key]=fn()
        if progress is not None:progress[key]=result[key]
    named(result['owner_reader_controls'],counts['owner'][mode],H(record))
    named(result['pf_refusal_owner_controls'],counts['pf'],H(record))
    named(result['effects_owner_controls'],counts['effects'],H(record))
    named(result['terminal_controls'],counts['terminal'],H(stderr),hash_key='original_stderr_sha256')
    p=result['pair_controls'];names=p['refusals']
    need(p['count']==len(names)==len(set(names))==counts['pair']and p['native_operations']==0 and
         p['qualification_credit']is False and all(type(n)is str and n for n in names),
         'every literal full-state lifecycle pair corruption rejected')
    result['expected_owner_controls']=owner_reader.expected_controls(*owner_args)
    named(result['expected_owner_controls'],counts['expected'],H(record))
    if progress is not None:progress['expected_owner_controls']=result['expected_owner_controls']
    return result


def builds(builder,products,private,pin,binary,aliases,run,r,support,*,completed=False):
    subjects={};original=support['original']
    for lane in LANES:
        directory=private/(lane+'-build')
        if completed:need(directory.is_dir(),'retained actual lifecycle lane directory')
        else:directory.mkdir()
        holder={}
        def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
            return run(lane+'-'+name,argv,profile=profile,expected=expected,env=env,record=record)
        bridge=build_bridge(builder,products,directory,pin,binary,aliases,lane_run,holder,original,
            capture=True,differential=lane=='differential',completed=completed)
        raw_emission(builder,bridge,pin,lane_run,holder)
        layout=observed_layout(builder,bridge,directory,pin,binary,lane_run,holder,completed=completed)
        values=(inputs_completed if completed else prepare_inputs)(original,bridge,builder,directory,
            pin,binary,lane_run,holder,support['application_build'])
        if completed:
            need(digest(holder)==digest(r['lanes'][lane]),'whole retained lifecycle build/layout/namespace observations')
        else:r['lanes'][lane]=holder
        subjects[lane]=(bridge,layout,*values)
    return subjects


def coverage(cases):
    need([(c['build_lane'],c['mode'],c['placement'])for c in cases]==list(ORDER)and
         all(c['status']=='observed_lifecycle'and c['exit']==c['expected_exit']==0 and
             'errors'not in c for c in cases),'all eight exact successful actual lifecycle subjects')
    for lane in LANES:
        for place in range(2):
            pair=[c for c in cases if c['build_lane']==lane and c['placement']==place]
            need([c['mode']for c in pair]==[0,1]and
                 [tuple(c['owner_summary']['orientation'])for c in pair]==[(12,11),(11,12)]and
                 all(c['pair']['primary_policy']==(12,11)[c['mode']]and
                     c['pair']['peer_policy']==(11,12)[c['mode']]for c in pair),
                 'actual complementary primary orientations at each placement and lane')
    return {name:True for name in COVERAGE}


def gated(builder,private,pin,binary,run,r,support,natives,subjects,owner_reader,reports,counts):
    imported_sources(pin)
    for case in r['cases']:
        label=case['label'];lane=case['build_lane'];case['status']='failed'
        directory=private/label;directory.mkdir();errors=[]
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects[lane]
        try:
            row,out,err=run(label,case_argv(builder,support['original'],case,directory,roots,carrier,pin),
                profile='program',record=True)
            manifest=preparation(case,row,directory,support['original'],roots,objects,description,
                carrier,private,binary,r)
            item=row['captures']['record'];record_path=binary(private/item['file'])
            need(128<item['bytes']<4<<20 and fact(record_path)=={k:item[k]for k in('bytes','sha256')},
                 'whole actual schema17 encoded record below unchanged4MiB cap')
            image=image_inventory(support['original'],interp,carrier,objects,manifest)
            image.update(bridge=bridge.read_bytes(),persistent_binding=r['lanes'][lane]['release_build']['persistent_binding'],
                headers=r['lanes'][lane]['release_build']['headers'],app_symbols=support['image']['symbols'])
            case.update(evaluate(case,row,out,err,record_path.read_bytes(),layout,image,support,
                natives[case['mode'],case['placement']],owner_reader,reports,counts,images,raws,carrier,progress=case))
            case['status']='observed_lifecycle'
        except Exception as error:errors.append(type(error).__name__+': '+str(error))
        last=r['commands'][-1]if r['commands']else{}
        if last.get('name')==label:
            case.update(exit=last.get('exit'),whole_process_ns=last.get('duration_ns'),timed_out=last.get('timed_out'),
                launched=type(last.get('pid'))is int,
                captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in last.get('captures',{}).items()})
        if errors:case['errors']=errors
        need(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and
             type(last.get('descriptors'))is list and all(d.get('closed')is True for d in last['descriptors']),
             'current lifecycle subject fully closed before the next, even after analysis failure')
    r['coverage']=coverage(r['cases'])
