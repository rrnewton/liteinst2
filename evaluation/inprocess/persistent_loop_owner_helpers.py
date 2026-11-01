"""Exact policy14 focal subject schedule and actual native/owner/report joins."""
import json
from pathlib import Path
import shutil
from page_selected import ENV, fact, need
from persistent_dynamic import H, load, named, image_inventory, raw_emission, imported_sources
from persistent_loop_build import build_bridge
from persistent_loop_native_build import FIXTURE, preparation
from direct_frontier_loop_helpers import prepare_inputs
import persistent_loop_reports as reports

ROOT=Path(__file__).resolve().parents[2]
OWNER=ROOT/'tools/page-entry/selected/tests/persistent_loop_owner'
PROFILE='persistent-loop-owner-v1'
LANES=('maintained','differential')
ORDER=tuple((lane,case,placement)for lane in LANES for case in range(7)for placement in range(4))
ARCHIVE_SCHEDULE=(('tracked-input-list','metadata'),
    *((('resolve-'+n),'metadata')for n in('cargo','rustc','cc1','collect2','as','ld')),
    *((('version-'+n),'metadata')for n in('cc','cargo','rustc','python')),
    ('cargo-metadata','metadata'),('default-headers-0','metadata'),('default-headers-1','metadata'),
    ('selected-build','build'),('archive-text-exports','inspect'),('bridge-undefined','inspect'),
    ('bridge-elf','inspect'),('generic-observer-headers','metadata'),('generic-observer-link','metadata'))
LANE_SCHEDULE=(('persistent-group-policy-binding','metadata'),('loop-capture-binding','metadata'),
    ('persistent-group-release-headers','metadata'),('persistent-group-release-link','release_build'),
    ('persistent-group-release-undefined','inspect'),('persistent-group-release-symbols','inspect'),
    ('persistent-group-objdump-version','metadata'),('persistent-group-release-memset','inspect'),
    ('persistent-group-gdb-version','inspect'),('persistent-group-protected-extents','inspect'),
    ('persistent-retained-two-extents','inspect'),('persistent-subentry-extents','inspect'),
    ('persistent-cross-pair-extents','inspect'),('persistent-direct-frontier-extents','inspect'),
    ('persistent-loop-extents','inspect'),('persistent-loop-capture-extents','inspect'),
    ('span-bytes-headers-0','metadata'),('span-bytes-link','release_build'),
    ('span-bytes-native-libraries','metadata'),('span-bytes-oracle','finite'),
    ('capture-raw-symbols','inspect'),('capture-raw-body','inspect'),
    ('layout-gdb-version','metadata'),('owner-layout','inspect'),('carrier','program'))
SCHEDULE=ARCHIVE_SCHEDULE+tuple((lane+'-'+name,profile)for lane in LANES for name,profile in LANE_SCHEDULE)+tuple(
    ('subject-'+lane+'-'+str(case)+'-'+str(place),'program')for lane,case,place in ORDER)
COVERAGE=('policy12_focal_full_state','native_pair_full_state','read_faults_before_effect','owner_and_pair_controls')
RAW_BYTES=4864896
OWNER_COUNTS=(226,226,226,226,226,225,225)
PAIR_COUNTS=(204,204,204,204,204,166,166)
APP_COUNTS=(532,532,532,532,532,190,190)


def expected_status(mode):
    return 'observed_required_read_fault'if mode>=5 else'observed_focal_completion'


def observed_layout(builder,bridge,private,pin,binary,run,r,*,completed=False):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment)
    need(out and not err,'actual no-inferior owner DWARF tool')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual complete owner DWARF observation')
    layout=json.loads(out);extents=r['release_build']['capture_extents']
    need(layout['record']=='pdo_wire'and layout['types']['pdo_wire']['bytes']==extents['wire']==RAW_BYTES and
         extents['schema_version']==14 and
         extents['encoded']==extents['record_limit']==extents['stream_strictly_below']==4<<20,
         'actual schema14 whole raw layout and unchanged strict encoded4MiB cap')
    path=private/'owner-dwarf-layout.json'
    if completed:need(path.read_bytes()==out,'whole retained actual no-inferior layout capture')
    else:
        with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script))
    return layout


def prefix_controls(reader,raw,mode,placement,status,image,pid,cpu,seed):
    """Actual failed prefix mutations only; never invent a success suffix."""
    need(type(status)is int and status==125 and mode in(5,6),'actual stopped read125 before prefix controls')
    reader.prefix(raw,1,mode,placement,image,pid,cpu,seed)
    source_at=4022 if placement&1 else 512
    tests=[('word_'+str(i),8*i)for i in range(64)]
    tests += [('cpuid_'+str(i),512+24*i)for i in range(67)]+[('cpuid_result',544)]
    tests += [('seed_gpr_'+str(i),2120+8*i)for i in range(16)]+[('seed_flags',2248)]
    tests += [('selector_'+str(i),2256+2*i)for i in range(6)]+[('seed_reserved',2268)]
    tests += [('machine_'+str(i),2272+8*i)for i in range(8)]
    tests += [('source_'+name,2336+offset)for name,offset in(('before',0),('first',source_at),
        ('last_head',source_at+86),('second_page',4096),('last',8191),('cut_a',source_at-124),
        ('cut_a_target',source_at-118),('cut_b',source_at+88),('cut_b_target',source_at+94),
        ('predecessor',source_at-5),('predecessor_displacement',source_at-4))]
    tests += [('data_'+str(i),10528+i)for i in(0,504,512,640,768,897,4096,4097,8191)]
    tests += [('stack_'+str(i),18720+i)for i in(0,127,128,223)]
    need(len(tests)==len({n for n,_ in tests})==188 and len(raw)==18944,'all literal failed-prefix controls')
    refused=[]
    def reject(name,changed):
        need(changed!=raw,'actual nonidentity prefix corruption')
        try:reader.prefix(changed,1,mode,placement,image,pid,cpu,seed)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied actual failed-prefix corruption '+name)
    for name,at in tests:
        changed=bytearray(raw);changed[at]^=1;reject(name,bytes(changed))
    reject('truncated',raw[:-1]);reject('extra',raw+b'\0')
    need(len(refused)==len(set(refused))==190,'every failed-prefix control refused')
    return dict(status='passed',scope='supplied_failed_prefix_corruptions_only',count=190,refusals=refused,
        raw_sha256=H(raw),native_operations=0,application_completed=False,owner_validated=False,
        mixed_policy_validated=False,qualification_credit=False,performance_credit=False)


def owner_summary(value):
    keys=('mode','placement','plan_version','fallback_policy','status','code','detail','cold_publications',
          'generated_entries','generated_completed','completion_permits','anchor_released','interior_signals',
          'focal_only','cold_warm_validated','mixed_policy_validated','replacement_validated',
          'held_cancellation_validated','qualification_credit','performance_credit')
    out={k:value[k]for k in keys}
    out.update({k:value[k]for k in('cleanup_closed_pages','original_branch_replays','actual_signal',
        'native_fault_signal','recovery_phase','guest_effects')if k in value})
    out.update(encoded_sha256=value['encoded_sha256'],raw_sha256=value['raw_sha256'],
        actual_entry=value['attempt'].get('actual_entry'),loop_terminal=value['loop_terminal'],
        pf_refusals=value['pf_refusals'])
    need(value['focal_only']is True and all(value[k]is False for k in('cold_warm_validated',
        'mixed_policy_validated','replacement_validated','held_cancellation_validated','qualification_credit','performance_credit')),
        'one actual focal lifetime never supplies pending lifecycle or performance credit')
    return out


def case_argv(builder,original,case,directory,roots,carrier,pin):
    argv=[builder.tools['python'],'-B',pin(FIXTURE/'launch.py'),'--root',ROOT,'--role','gated',
        '--case',str(case['mode']),'--placement',str(case['placement']),'--control','0',
        '--original',original,'--preparation',directory/'preparation.json']
    for p in roots:argv+=['--library-root',p]
    return [*argv,'--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']


def evaluate(case,row,stdout,stderr,record,layout,image,support,native,owner_reader,
             images,raws,carrier,*,run_controls,progress=None):
    mode,placement=case['mode'],case['placement'];failed=mode>=5
    status=125 if failed else 0;reader=support['reader'];seed=support['seed_reference'];appimage=support['image']
    need(type(row['exit'])is int and row['exit']==row['expected_exit']==status and row['timed_out']is False,
         'actual exact success0 or before-effect read125; no outcome relabelling')
    args=(stdout,1,mode,placement,row['exit'],appimage,row['pid'],case['cpu'],seed)
    app=(reader.prefix(stdout,1,mode,placement,appimage,row['pid'],case['cpu'],seed)if failed else reader.read(*args))
    owner_args=(record,layout,image,app,row['pid'],case['cpu'],row['exit'])
    owner=owner_reader.read(*owner_args)
    if progress is not None:progress['owner_summary']=owner_summary(owner)
    pair=owner_reader.pair(native,app,owner)
    if progress is not None:progress['pair']=pair
    terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),
        carrier.read_bytes(),owner,owner_reader,mode,app)
    terminal,summary=reports.check(stderr,*terminal_args,lane=case['build_lane'])
    result=dict(owner_summary=owner_summary(owner),pair=pair,terminal=summary,
        application=dict(raw_sha256=H(stdout),application_completed=not failed,
            actual_fault_prefix=failed,native_frames=0,native_instructions=0),
        pf_refusal_stages=owner['pf_refusal_stages'])
    if progress is not None:progress.update(result)
    if run_controls:
        application=(prefix_controls(reader,stdout,mode,placement,row['exit'],appimage,row['pid'],case['cpu'],seed)
                     if failed else support['controls'].controls(reader,*args))
        metadata=support['controls'].metadata_controls(reader,appimage)
        need(application['count']==len(application['refusals'])==len(set(application['refusals']))==APP_COUNTS[mode]and
             application['raw_sha256']==H(stdout)and application['native_operations']==0 and len(metadata)==len(set(metadata))==20,
             'all literal application or failed-prefix and actual-layout controls')
        if not failed:need(application['layout_controls']==metadata and application['layout_count']==20,'whole supplied maintained layout controls')
        result.update(application_controls=application,application_layout_controls=metadata)
        if progress is not None:progress.update(result)
        for name,fn in (
            ('owner_reader_controls',lambda:owner_reader.controls(*owner_args)),
            ('pf_refusal_owner_controls',lambda:owner_reader.pf_refusal_controls(*owner_args)),
            ('pair_controls',lambda:owner_reader.pair_controls(native,app,owner)),
            ('terminal_controls',lambda:reports.controls(stderr,*terminal_args,lane=case['build_lane']))):
            result[name]=fn()
            if progress is not None:progress[name]=result[name]
        control_join(result,mode,H(stdout),H(record),H(stderr))
    return result


def control_join(value,mode,stdout_sha,record_sha,stderr_sha):
    app=value['application_controls'];names=app['refusals']
    need(app['count']==len(names)==len(set(names))==APP_COUNTS[mode]and app['raw_sha256']==stdout_sha and
         app['native_operations']==0 and all(type(n)is str and n for n in names)and
         len(value['application_layout_controls'])==len(set(value['application_layout_controls']))==20,
         'whole actual supplied application/prefix control roster')
    named(value['owner_reader_controls'],OWNER_COUNTS[mode],record_sha)
    named(value['pf_refusal_owner_controls'],12,record_sha)
    named(value['terminal_controls'],335,stderr_sha,hash_key='original_stderr_sha256')
    pair=value['pair_controls'];names=pair['refusals']
    need(pair['count']==len(names)==len(set(names))==PAIR_COUNTS[mode]and
         pair['native_operations']==0 and pair['qualification_credit']is False and
         all(type(n)is str and n for n in names),'whole literal supplied native/owner pair controls')
    need(reports.CONTROL_COUNT==335,'fixed complete paired terminal controls')


def cohort(builder,products,private,pin,binary,aliases,run,r,cases,support):
    original=support['original'];owner_reader=load('loop_focal_owner',OWNER/'read.py',pin);subjects={}
    for lane in LANES:
        directory=private/(lane+'-build');directory.mkdir();holder=r['lanes'][lane]={}
        def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
            return run(lane+'-'+name,argv,profile=profile,expected=expected,env=env,record=record)
        bridge=build_bridge(builder,products,directory,pin,binary,aliases,lane_run,holder,original,
            capture=True,differential=lane=='differential')
        raw_emission(builder,bridge,pin,lane_run,holder)
        layout=observed_layout(builder,bridge,directory,pin,binary,lane_run,holder)
        inputs=prepare_inputs(original,bridge,builder,directory,pin,binary,lane_run,holder,support['application_build'])
        subjects[lane]=(bridge,layout,*inputs)
    imported_sources(pin)
    for case in r['cases']:
        lane=case['build_lane'];mode=case['mode'];placement=case['placement'];label=case['label']
        case['status']='failed';directory=private/label;directory.mkdir();errors=[]
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects[lane]
        try:
            row,stdout,stderr=run(label,case_argv(builder,original,case,directory,roots,carrier,pin),
                profile='program',expected=case['expected_exit'],record=True)
            manifest=preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r)
            capture=row['captures']['record'];record_path=binary(private/capture['file'])
            need(128<capture['bytes']<4<<20 and fact(record_path)=={k:capture[k]for k in('bytes','sha256')},
                 'whole actual protected record below original strict4MiB cap')
            image=image_inventory(original,interp,carrier,objects,manifest)
            image.update(bridge=bridge.read_bytes(),persistent_binding=r['lanes'][lane]['release_build']['persistent_binding'],
                headers=r['lanes'][lane]['release_build']['headers'],app_symbols=support['image']['symbols'])
            case.update(evaluate(case,row,stdout,stderr,record_path.read_bytes(),layout,image,support,
                cases[mode,placement],owner_reader,images,raws,carrier,run_controls=True,progress=case))
            case['status']=expected_status(mode)
        except Exception as error:errors.append(type(error).__name__+': '+str(error))
        finally:
            last=r['commands'][-1]if r['commands']else{}
            if last.get('name')==label:
                case.update(exit=last.get('exit'),whole_process_ns=last.get('duration_ns'),timed_out=last.get('timed_out'),
                    launched=type(last.get('pid'))is int,
                    captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in last.get('captures',{}).items()})
        if errors:case['errors']=errors
        need(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[] and
             type(last.get('descriptors'))is list and all(d.get('closed')is True for d in last['descriptors']),
             'current subject completely reaped before next fixed case, including any failed analysis')
    need(all(c['status']==expected_status(c['mode'])for c in r['cases']),
         'all56 actual focal/full-state/fault/control gates; every unexpected failure remains failed')
