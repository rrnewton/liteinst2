"""Three exact direct-frontier lanes; finite proof alone never grants profile qualification."""
import ctypes,json,os,shlex,shutil,re
from pathlib import Path
from page_selected import need,elf,ENV,fact,interpreter
from page_selected_register_time_build import recipe,expand,headers
from persistent_dynamic import (MASK,load,H,digest,named,counts,control_table,seed_prerequisite,
    image_inventory,raw_emission,imported_sources)
from persistent_block_build import build_bridge
import namespace
import persistent_active_domain as component
import persistent_direct_frontier_reports as reports
ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/persistent_block_app'
OWNER=SELECTED/'tests/persistent_block_owner'
APP_COUNTS={0:40};PAIR_COUNTS={0:36};TERMINAL_COUNTS={(0,0):73}
OWNER_COUNTS={0:204}
PAIR_EXPECTED=dict(observed_bounded_block=1,plan_version=10,unsupported_root_cancellations=1,ordinary_resumptions=1,invocations=1,generated_completed=3,cold_publications=2,
    warm_entries=1,dual_entries=1,retained_generations=2,shared_domain_lifetimes=1,joint_source_pairs=2,
    joint_source_pages=4,joint_closed_pages=34,modeled_joint_retired_instructions=11,
    modeled_final_frontier_instructions=1,modeled_cross_certificate_transfers=5,measured_interior_signals=0,
    native_instructions=20,native_full_frames=12,lifetime_mode=2,registration_epoch=0,
    registration_calls=0,word_observed=0,word_available=False,qualification_credit=False)
RETAINED_WIRE_BYTES=5421376
EXPECTED_STATUS={('native',0):'observed_native_bounded_block',
    ('maintained',0):'observed_generated_bounded_block_maintained',
    ('differential',0):'observed_generated_bounded_block_differential'}

from direct_frontier_loop_helpers import prepare_inputs, preparation, repeat_setup_completed, public_cases


# Exact fresh finite schedule. The old38 component commands remain mandatory
# inside the whole same-revision native41 prerequisite, before this cohort.
COMMAND_SCHEDULE = (
    ('tracked-input-list', 'metadata'),
    ('resolve-cargo', 'metadata'),
    ('resolve-rustc', 'metadata'),
    ('resolve-cc1', 'metadata'),
    ('resolve-collect2', 'metadata'),
    ('resolve-as', 'metadata'),
    ('resolve-ld', 'metadata'),
    ('version-cc', 'metadata'),
    ('version-cargo', 'metadata'),
    ('version-rustc', 'metadata'),
    ('version-python', 'metadata'),
    ('cargo-metadata', 'metadata'),
    ('default-headers-0', 'metadata'),
    ('default-headers-1', 'metadata'),
    ('selected-build', 'build'),
    ('archive-text-exports', 'inspect'),
    ('bridge-undefined', 'inspect'),
    ('bridge-elf', 'inspect'),
    ('generic-observer-headers', 'metadata'),
    ('generic-observer-link', 'metadata'),
    ('app-interpreter-headers', 'metadata'),
    ('app-interpreter-link', 'release_build'),
    ('app-interpreter-undefined', 'inspect'),
    ('app-interpreter-symbols', 'inspect'),
    ('app-headers', 'metadata'),
    ('app-link', 'release_build'),
    ('app-undefined', 'inspect'),
    ('app-elf', 'inspect'),
    ('app-objdump-version', 'metadata'),
    ('app-symbols', 'inspect'),
    ('app-body-main', 'inspect'),
    ('app-body-collect', 'inspect'),
    ('app-body-copy', 'inspect'),
    ('app-body-same', 'inspect'),
    ('app-body-ua_data_pattern', 'inspect'),
    ('app-body-ua_stack_pattern', 'inspect'),
    ('app-copy-headers', 'finite'),
    ('app-pure-preprocess', 'finite'),
    ('copy-pure-preprocess', 'finite'),
    ('app-copy-link', 'finite'),
    ('app-copy-symbols', 'finite'),
    ('app-copy-body', 'finite'),
    ('app-copy-libraries', 'finite'),
    ('app-copy-run', 'finite'),
    ('policy-headers', 'metadata'),
    ('policy-link', 'release_build'),
    ('seed-headers', 'metadata'),
    ('seed-link', 'release_build'),
    ('seed-libraries', 'inspect'),
    ('seed-prerequisite', 'seed'),
    ('maintained-persistent-group-policy-binding', 'metadata'),
    ('maintained-cross-pair-capture-binding', 'metadata'),
    ('maintained-persistent-group-release-headers', 'metadata'),
    ('maintained-persistent-group-release-link', 'release_build'),
    ('maintained-persistent-group-release-undefined', 'inspect'),
    ('maintained-persistent-group-release-symbols', 'inspect'),
    ('maintained-persistent-group-objdump-version', 'metadata'),
    ('maintained-persistent-group-release-memset', 'inspect'),
    ('maintained-persistent-group-gdb-version', 'inspect'),
    ('maintained-persistent-group-protected-extents', 'inspect'),
    ('maintained-persistent-retained-two-extents', 'inspect'),
    ('maintained-persistent-subentry-extents', 'inspect'),
    ('maintained-persistent-cross-pair-extents', 'inspect'),
    ('maintained-persistent-direct-frontier-extents', 'inspect'),
    ('maintained-persistent-block-capture-extents', 'inspect'),
    ('maintained-span-bytes-headers-0', 'metadata'),
    ('maintained-span-bytes-link', 'release_build'),
    ('maintained-span-bytes-native-libraries', 'metadata'),
    ('maintained-span-bytes-oracle', 'finite'),
    ('maintained-capture-raw-symbols', 'inspect'),
    ('maintained-capture-raw-body', 'inspect'),
    ('maintained-layout-gdb-version', 'metadata'),
    ('maintained-owner-layout', 'inspect'),
    ('maintained-carrier', 'program'),
    ('differential-persistent-group-policy-binding', 'metadata'),
    ('differential-cross-pair-capture-binding', 'metadata'),
    ('differential-persistent-group-release-headers', 'metadata'),
    ('differential-persistent-group-release-link', 'release_build'),
    ('differential-persistent-group-release-undefined', 'inspect'),
    ('differential-persistent-group-release-symbols', 'inspect'),
    ('differential-persistent-group-objdump-version', 'metadata'),
    ('differential-persistent-group-release-memset', 'inspect'),
    ('differential-persistent-group-gdb-version', 'inspect'),
    ('differential-persistent-group-protected-extents', 'inspect'),
    ('differential-persistent-retained-two-extents', 'inspect'),
    ('differential-persistent-subentry-extents', 'inspect'),
    ('differential-persistent-cross-pair-extents', 'inspect'),
    ('differential-persistent-direct-frontier-extents', 'inspect'),
    ('differential-persistent-block-capture-extents', 'inspect'),
    ('differential-span-bytes-headers-0', 'metadata'),
    ('differential-span-bytes-link', 'release_build'),
    ('differential-span-bytes-native-libraries', 'metadata'),
    ('differential-span-bytes-oracle', 'finite'),
    ('differential-capture-raw-symbols', 'inspect'),
    ('differential-capture-raw-body', 'inspect'),
    ('differential-layout-gdb-version', 'metadata'),
    ('differential-owner-layout', 'inspect'),
    ('differential-carrier', 'program'),
    ('subject-native-0-0', 'program'),
    ('subject-maintained-0-0', 'program'),
    ('subject-differential-0-0', 'program'),
)

def reader_support(builder,private,pin,binary,run,r):
    pin(OWNER/'direct_history.py')
    reader=load('persistent_block_app_read',FIXTURE/'read.py',pin)
    owner=load('persistent_block_owner_read',OWNER/'read.py',pin)
    policy=private/'native-policy.so';unit=pin(SELECTED/'native_policy.c')
    flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared']
    _,out,err=run('policy-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_policy',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_policy: '),'complete policy include rule')
    headers={str(pin(path)):fact(pin(path))for path in shlex.split(lines[0].split(':',1)[1])}
    need(str(unit)in headers and str(SELECTED/'native_policy.h')in headers,'actual policy sources')
    run('policy-link',[builder.tools['cc'],*flags,'-Wl,-z,noexecstack,--build-id=none',unit,'-o',policy],profile='release_build',env=builder.environment)
    r['reader_support']=dict(headers=headers,native_policy=fact(binary(policy)))
    lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
    return reader,owner,lambda data:lib.li2_native_policy(data,len(data))

def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='pdo_wire'and
        layout['types']['pdo_wire']['bytes']==r['release_build']['capture_extents']['wire']==RETAINED_WIRE_BYTES and
        r['release_build']['capture_extents']['encoded']==r['release_build']['capture_extents']['record_limit']==4<<20 and
        r['release_build']['capture_extents']['stream_strictly_below']==4<<20 and
        r['release_build']['capture_extents']['schema_version']==11,
        'actual full raw DWARF transcript with unchanged strict encoded4MiB record limit')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout

def cohort(builder,products,private,pin,binary,aliases,run,r,original):
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
    r['application_layout']['source_pairs']=[dict(bytes=len(value),sha256=H(value))
        for value in app_layout['source_pairs']]
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    subjects={}
    for lane in ('maintained','differential'):
        directory=private/(lane+'-build');directory.mkdir();holder=r['lanes'][lane]={}
        def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
            return run(lane+'-'+name,argv,profile=profile,expected=expected,env=env,record=record)
        bridge=build_bridge(builder,products,directory,pin,binary,aliases,lane_run,holder,original,
            capture=True,differential=lane=='differential')
        raw_emission(builder,bridge,pin,lane_run,holder)
        layout=observed_layout(builder,bridge,directory,pin,binary,lane_run,holder)
        inputs=prepare_inputs(original,bridge,builder,directory,pin,binary,lane_run,holder,r['application_build'])
        subjects[lane]=(bridge,layout,*inputs)
        need(holder['release_build']['status']=='passed'and
             holder['release_build']['profile']=='persistent-block-'+('differential'if lane=='differential'else'capture')+'-v1'and
             holder['release_build']['active_domain']['differential']==(lane=='differential')and
             holder['release_build']['active_domain']['native_probe']is True and
             holder['release_build']['persistent_binding']['native_probe']is True and
             holder['release_build']['active_domain']['parse_memo']is True and
             holder['release_build']['persistent_binding']['parse_memo']is True and
             holder['release_build']['active_domain']['subentry']is True and
             holder['release_build']['persistent_binding']['subentry']is True and
             holder['release_build']['active_domain']['cross_pair']is True and
             holder['release_build']['persistent_binding']['cross_pair']is True and
             holder['release_build']['active_domain']['direct_frontier']is True and
             holder['release_build']['persistent_binding']['direct_frontier']is True and
             holder['release_build']['persistent_binding']['bounded_block']is True and
             holder['release_build']['persistent_binding']['policy_version']==10 and
             holder['release_build']['bounded_block']==dict(version=1,policy_version=10,heads_max=128,shared_boundaries=8,active_members_max=2,call_ret=False) and
             holder['release_build']['direct_frontier']['policy_version']==10 and
             holder['release_build']['direct_frontier']['partition']=='first-direct-branch' and
             holder['release_build']['direct_frontier']['all_arms_directory']is True,
             'separate exact maintained/differential actual builds')
    need(digest(r['lanes']['maintained']['subject_artifacts']['original'])==
         digest(r['lanes']['differential']['subject_artifacts']['original'])==digest(fact(original)),
         'one unchanged original image across both independently built lanes')
    launcher=pin(FIXTURE.parent/'persistent_direct_frontier_app/launch.py');native_records={}
    imported_sources(pin)
    need(digest(counts(reader.APP_CONTROL_COUNTS))==digest(counts(APP_COUNTS))and
         digest(counts(reader.PAIR_CONTROL_COUNTS))==digest(counts(PAIR_COUNTS))and
         digest(counts(owner_reader.CONTROL_COUNTS))==digest(counts(OWNER_COUNTS))and
         digest(control_table(reports.CONTROL_COUNTS))==digest(control_table(TERMINAL_COUNTS)),
         'literal complete native-app, protected-owner, pair and terminal refusal populations')
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed'
        directory=private/label;directory.mkdir();role='native'if lane=='native'else'gated'
        selected_lane='maintained'if lane=='native'else lane
        holder=r['lanes'][selected_lane]
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects[selected_lane]
        carrier_bytes=carrier.read_bytes()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',role,'--mode',str(mode),'--control','0',
            '--original',original,'--preparation',directory/'preparation.json']
        for p in roots:argv+=['--library-root',p]
        if lane!='native':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,stdout,stderr=run(label,argv,profile='program',expected=c['expected_exit'],record=lane!='native')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            args=(stdout,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
            parsed=reader.read(*args)
            if lane=='native':
                need(stderr==b'','actual native reference stderr remains empty')
                c['application_controls']=reader.controls(*args)
                named(c['application_controls'],APP_COUNTS[mode],H(stdout));native_records[mode]=parsed
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(128<capture['bytes']<4<<20 and layout['types']['pdo_wire']['bytes']==RETAINED_WIRE_BYTES and
                    fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual encoded protected transcript within unchanged strict4MiB bound')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),persistent_binding=holder['release_build']['persistent_binding'],headers=holder['release_build']['headers'],app_symbols=app_layout['symbols'])
                owner_args=(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'])
                actual_owner=owner_reader.read(*owner_args)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(stderr,*terminal_args,lane=lane,application=parsed);r['terminal_reports'][label]=terminal
                repeat_setup_completed(stderr,app_layout,c['terminal']['repeat_lease'],parsed,
                    tuple((x['before']['fs'],x['before']['gs'])for x in actual_owner['attempts']))
                c['repeat_tls_controls']=reports.repeat_tls_controls(stderr,terminal,row['pid'],images,raws,
                    fact(carrier),carrier_bytes,actual_owner,parsed)
                named(c['repeat_tls_controls'],reports.REPEAT_TLS_CONTROLS,H(stderr),hash_key='original_stderr_sha256')
                c['native_probe_controls']=reports.probe_controls(stderr,terminal)
                named(c['native_probe_controls'],reports.probe.CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['effect_controls']=reports.effect_controls(stderr,terminal)
                named(c['effect_controls'],reports.EFFECT_CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['terminal_controls']=reports.controls(stderr,*terminal_args,lane=lane,application=parsed)
                named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],H(stderr),hash_key='original_stderr_sha256')
                c['subentry_controls']=reports.subentry_controls(stderr,actual_owner,owner_reader)
                named(c['subentry_controls'],reports.SUBENTRY_CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:actual_owner[k]for k in('mode','cold_publications','warm_entries','subentry_entries','dual_entries','replacements','permit_claims','interior_signals','lifetime_mode','registration_epoch','registration_calls','word_observed','tls_complete','code','detail','status')}
                need(all(type(v)is int and 0<=v<1<<64 for v in c['owner_summary'].values()),'only actual bounded owner counters')
                need(actual_owner['lifetime_mode']==2 and actual_owner['registration_epoch']==0 and
                     actual_owner['registration_calls']==0 and actual_owner['word_observed']==0 and
                     actual_owner['word_available']is False and actual_owner['tls_complete']==1,
                     'actual complete mode2 lifetime')
                need(mode==0 and mode in native_records,'actual same-mode complete native loop reference')
                c['pair']=reader.pair(native_records[mode],parsed,actual_owner)
                need(digest(c['pair'])==digest(PAIR_EXPECTED),'actual PB20 shared lifetime/cancellation and complete-state pair; no qualification')
                c['pair_controls']=reader.pair_controls(native_records[mode],parsed,actual_owner)
                names=c['pair_controls'];need(type(names['refusals'])is list and all(type(n)is str and n for n in names['refusals'])and
                    len(names['refusals'])==len(set(names['refusals']))==PAIR_COUNTS[mode]and
                    type(names['native_operations'])is int and names['native_operations']==0,'all exact cross-lane full-state controls')
                c['owner_reader_controls']=owner_reader.controls(*owner_args)
                named(c['owner_reader_controls'],OWNER_COUNTS[mode],H(record))
            c['status']=EXPECTED_STATUS[lane,mode]
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need(len(r['cases'])==3 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases'])and not r['error'],
         'all three actual loop outcomes required without skipped or relabelled failures')
    need(sum(c.get('pair',{}).get('observed_bounded_block',0)for c in r['cases'])==2 and
         sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases'])==APP_COUNTS[0] and
         sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==2*OWNER_COUNTS[0] and
         sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases'])==2*PAIR_COUNTS[0] and
         sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==2*TERMINAL_COUNTS[0,0],
         'two complete native/generated pairs and each separate exact supplied control population')
    need(sum(len(c.get('native_probe_controls',{}).get('refusals',[]))for c in r['cases'])==44 and
         reports.probe.CONTROL_COUNT==22,'both separate exact native-probe reader populations')
    need(sum(len(c.get('repeat_tls_controls',{}).get('refusals',[]))for c in r['cases'])==66 and
         reports.REPEAT_TLS_CONTROLS==33,'both separate exact observed-TLS REP reader populations')
    need(sum(len(c.get('subentry_controls',{}).get('refusals',[]))for c in r['cases'])==38 and
         reports.SUBENTRY_CONTROL_COUNT==19,'both separate exact actual-entry terminal reader populations')
    need(sum(len(c.get('effect_controls',{}).get('refusals',[]))for c in r['cases'])==24 and
         reports.EFFECT_CONTROL_COUNT==12,'both separate exact tiny-fixture effect populations')
