#!/usr/bin/env python3
"""Native392 and separate maintained/differential shared-domain finite pairs.

Five fresh old prerequisites remain mandatory on the same source/CPU/archive.
Two source-owned components and each full-state pair remain separate from LS
and performance qualification. All original process/output/record bounds remain.
"""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys,types
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/persistent_active_domain_app'
OWNER=SELECTED/'tests/persistent_joint_startup_owner'
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe,headers
from persistent_joint_startup_build import build_bridge
import namespace
import persistent_dynamic as previous
import persistent_joint_startup_reports as reports
from persistent_active_domain import (compile_subject,preparation,authority_component,dispatch_component,
    native_probe_component,maps_parse_component)
import persistent_resident as resident
import persistent_retained_two as retained
from persistent_retained_two_experiment import retained_prerequisite
from persistent_resident import group_prerequisite
from persistent_resident_experiment import resident_prerequisite
import persistent_group as group
from persistent_group import public_case,csv_projection,load,imported_sources,dynamic_prerequisite
from persistent_dynamic import (BOUNDS,MASK,H,digest,named,counts,control_table,
    seed_prerequisite,prepare_inputs,image_inventory,raw_emission,fixed_prerequisite)
ORDER=(('native',0,0),('maintained',0,0),('differential',0,0))
APP_COUNTS={0:24};OWNER_COUNTS={0:193}
PAIR_COUNTS={0:12};TERMINAL_COUNTS={(0,0):73}
PAIR_EXPECTED=dict(observed_active_domain_pair=1,invocations=1,generated_completed=3,
    cold_publications=2,warm_entries=1,dual_entries=1,retained_generations=2,
    shared_source_rseq_lifetimes=1,joint_closed_pages=34,architectural_joint_instructions=385,
    architectural_internal_transfers=127,measured_interior_signals=0,native_instructions=392,
    native_full_frames=12,qualification_credit=False)
EXPECTED_STATUS={('native',0):'observed_native_active_domain',
    ('maintained',0):'observed_generated_active_domain_maintained',
    ('differential',0):'observed_generated_active_domain_differential'}
COPY_COUNTS=dict(disjoint=2432,overlap=10032,guards=140,large=3)
COPY_STDOUT=b'active-app-copy disjoint=2432 overlap=10032 guards=140 large=3\n'
COMPONENT_ORDER=('active_authority','active_dispatch')
COMPONENT_INPUTS={'tests/persistent_active_domain/authority.c': {'bytes': 14511, 'sha256': '1f934a8708e9e44e194b9cf662a84f1d363a91a5ad39e5bfb8e659066ef50606'}, 'tests/persistent_active_domain/build-authority.sh': {'bytes': 1622, 'sha256': 'a1b94c84ed0f01c0fa1c76aa45735138ad90dbcfa4b24d40a7822776fcc0fdfd'}, 'tests/persistent_active_domain/build-dispatch.sh': {'bytes': 1057, 'sha256': '2cccefa5a9b8bab38769f140cbf421c90ea106601110fe2bca01f4e75affa351'}, 'tests/persistent_active_domain/dispatch.c': {'bytes': 11184, 'sha256': '7dd5b631264851945897d4c5d0dc77cebbeec62d397d95200cc2cb39451f7483'}, 'tests/persistent_active_domain/domain_model.c': {'bytes': 7488, 'sha256': '9776beb43b7d976d8502c9d5bc35abc989b02ce29e6b30e03c7bc98eae32b5df'}, 'tests/persistent_active_domain/prepare.py': {'bytes': 4041, 'sha256': 'd7a2e86f07c2de9aab525130758a2cd6175a7e5bf17999ead8b3704ca8e714a0'}}
COMPONENT_STDOUT={'active_authority': b'active-domain-authority positives=9 refusals=30 claims=2 reuse=3 bytes=2 blocked=3 directories=2 owners=17\n', 'active_dispatch': b'active-domain-dispatch proofs=2 descriptors=16 decoded=74 models=4930 handoffs=192 refusals=487 steps=416230 typed=43520\n'}
COMPONENT_SUMMARIES={
 'active_authority':dict(positives=9,refusals=30,claims=2,reuse=3,bytes=2,blocked=3,directories=2,owners=17,synthetic_observations=1,emitted_execution=0),
 'active_dispatch':dict(proofs=2,descriptors=16,decoded=74,models=4930,handoffs=192,refusals=487,steps=416230,typed=43520,synthetic_observations=1,emitted_execution=0)}
RETAINED_WIRE_BYTES=4181824
JOINT_READER_INPUTS={'evaluation/inprocess/persistent_joint_startup_reports.py': {'bytes': 17869, 'sha256': '8954799827afa4a65b3ca0d3259ad9a3a2360aa1aecc32d691ca00c6ef44851c'}, 'tools/page-entry/selected/tests/persistent_joint_startup_owner/layout.py': {'bytes': 6690, 'sha256': 'af545cf24619f7f4fe9be4de030848d768f9b1634cb798a615bed60b8938a0ef'}, 'tools/page-entry/selected/tests/persistent_joint_startup_owner/read.py': {'bytes': 63364, 'sha256': 'd5d753e672533005e16e7b31d44f8504e4084f17089873fb742c406692f8e5bc'}, 'tools/page-entry/selected/tests/persistent_joint_startup_owner/wire.py': {'bytes': 49597, 'sha256': 'd8bb81ae909fa026263f3cf8c988280d1c5a9884865331cba0bce336fb23b90a'}}

PROBE_INPUTS={'tests/linked_native_probe/oracle.c': {'bytes': 16859, 'sha256': '8542d8dc42fcb452eee31f81a7b3411c9f6b19ed3a597ed0408d6d64d792e434'}, 'tests/linked_native_probe/build.sh': {'bytes': 1786, 'sha256': 'b3e915e55786783eee7c1524fb9c04a20f1ace5acc517adb4983918c4860ec77'}}
PROBE_STDOUT=b'{"version":1,"component_only":1,"current_controls":25,"policy_controls":5,"refault_controls":6,"outcome_controls":27,"lifetime_cases":5,"terminal_controls":6,"actual_in_place_renewal":1,"raw_calls":0}\n'
PROBE_COUNTS={'version': 1, 'component_only': 1, 'current_controls': 25, 'policy_controls': 5, 'refault_controls': 6, 'outcome_controls': 27, 'lifetime_cases': 5, 'terminal_controls': 6, 'actual_in_place_renewal': 1, 'raw_calls': 0}
PROBE_PUBLIC_FIELDS=('status','launched','expected_exit','bounds','recipe','artifact','exit','duration_ns','timed_out','captures','counts','emitted_instruction_execution','hardware_subjects','performance_credit')
MAPS_PARSE_INPUTS = {'tests/maps_parse_memo/oracle.c': {'bytes': 11808, 'sha256': 'bf5df0a14673c7e0a6c0af6896d8935657b147ace9039d53e79f4a139eefdf71'}, 'tests/maps_parse_memo/build.sh': {'bytes': 848, 'sha256': '8e11ad01d85b8de4ef28dd36f706a6030d6036aa2fde24533bc01250481a6aca'}}
MAPS_PARSE_STDOUT = b'{"version":1,"cases":72,"byte_changes":52,"io_failures":3,"state_controls":5,"differential_controls":4}\n'
MAPS_PARSE_COUNTS = {'version': 1, 'cases': 72, 'byte_changes': 52, 'io_failures': 3, 'state_controls': 5, 'differential_controls': 4}
MAPS_PARSE_MACROS = ('LI2_MAPS_PHASE_REUSE=1','LI2_MAPS_MAINTAINED=1','LI2_MAPS_DIFFERENTIAL=1','LI2_MAPS_PARSE_MEMO=1','LI2_MAPS_PARSE_MEMO_TEST=1')




def reader_support(builder,private,pin,binary,run,r):
    for name,expected in JOINT_READER_INPUTS.items():
        need(fact(pin(ROOT/name))==expected,'exact new joint reader/report source '+name)
    reader=load('persistent_active_domain_app_read',FIXTURE/'read.py',pin)
    owner=load('persistent_active_domain_owner_read',OWNER/'read.py',pin)
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
    layout=json.loads(out);need(layout['record']=='pdao_wire'and
        layout['types']['pdao_wire']['bytes']==r['release_build']['capture_extents']['wire']==RETAINED_WIRE_BYTES and
        r['release_build']['capture_extents']['stream']==RETAINED_WIRE_BYTES+64<4<<20,'actual retained owner wire and original4MiB record bound')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout


def repeat_setup_completed(stderr,image,summary,application,protected_tls):
    """Exact positive fixture site and observed-TLS identity; no row rewriting."""
    parsed={}
    for key,prefix in (('repeat_lease',b'LI2_REPEAT_LEASE '),('rseq',b'LI2_RSEQ ')):
        lines=[x for x in stderr.splitlines()if x.startswith(prefix)]
        need(len(lines)==1,'one actual positive fixture REP/rseq row')
        parsed[key]=reports.maps_view.pair.pair_reports.rseq.decode(lines[0][len(prefix):])
        need(prefix+json.dumps(parsed[key],separators=(',',':'),allow_nan=False).encode()==lines[0],
             'canonical actual fixture REP/rseq row')
    observed=reports.repeat_observed_identity(parsed,application['header'][6],application,protected_tls)
    need(summary['observed_tls']==observed,'whole actual observed-TLS REP summary')
    row=parsed['repeat_lease']
    setup=image['repeat_setup'];pc=setup['pc'];destination=setup['destination']
    binding=summary['source_binding']
    need(row['request'][:4]==[pc,setup['next_pc'],346,3]and
         row['request'][5]==0xab48f3 and row['request'][6]&0x400==0 and
         setup['count']==8 and setup['width']==8 and setup['value']==0x8877665544332211 and
         row['progress'][0]==8 and row['frames'][2:4]==[8,destination]and
         row['frames'][9:11]==[0,destination+64]and
         summary['last_code']==346 and summary['last_initial_count']==8 and
         summary['registration_scope']==reports.REPEAT_TLS_SCOPE and
         binding['module']==summary['source_module']==0 and
         binding['file_offset']==summary['source_file_offset']==setup['file_offset']and
         binding['emitted_bytes']=='f348ab'and binding['image_sha256']==image['sha256'],
         'actual positive REP is the exact low fixture STOSQ and complete eight-word destination')


def cohort(builder,products,private,pin,binary,aliases,run,r):
    authority_component(builder,products,private,pin,binary,aliases,run,r)
    dispatch_component(builder,products,private,pin,binary,aliases,run,r)
    native_probe_component(builder,private,pin,binary,run,r)
    maps_parse_component(builder,private,pin,binary,run,r)
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
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
        inputs=prepare_inputs(original,bridge,builder,directory,pin,binary,lane_run,holder)
        subjects[lane]=(bridge,layout,*inputs)
        need(holder['release_build']['status']=='passed'and
             holder['release_build']['profile']=='persistent-joint-subentry-'+('differential'if lane=='differential'else'capture')+'-v1'and
             holder['release_build']['active_domain']['unregistered']is True and
             holder['release_build']['active_domain']['subentry']is True and
             holder['release_build']['persistent_binding']['unregistered']is True and
             holder['release_build']['persistent_binding']['subentry']is True and
             holder['release_build']['active_domain']['differential']==(lane=='differential')and
             holder['release_build']['active_domain']['native_probe']is True and
             holder['release_build']['persistent_binding']['native_probe']is True and
             holder['release_build']['active_domain']['parse_memo']is True and
             holder['release_build']['persistent_binding']['parse_memo']is True,
             'separate exact maintained/differential actual builds')
    need(digest(r['lanes']['maintained']['subject_artifacts']['original'])==
         digest(r['lanes']['differential']['subject_artifacts']['original'])==digest(fact(original)),
         'one unchanged original image across both independently built lanes')
    launcher=pin(FIXTURE/'launch.py');native_records={}
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
                need(capture['bytes']==layout['types']['pdao_wire']['bytes']+64<4<<20 and
                    fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected active-domain record within original4MiB bound')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),persistent_binding=holder['release_build']['persistent_binding'],headers=holder['release_build']['headers'])
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
                c['subentry_controls']=reports.subentry_controls(stderr,actual_owner,owner_reader)
                named(c['subentry_controls'],reports.SUBENTRY_CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['terminal_controls']=reports.controls(stderr,*terminal_args,lane=lane,application=parsed)
                named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:actual_owner[k]for k in('mode','cold_publications','warm_entries','dual_entries','replacements','permit_claims','interior_signals','word','code','detail','status')}
                need(all(type(v)is int and 0<=v<1<<64 for v in c['owner_summary'].values()),'only actual bounded owner counters')
                need(actual_owner['lifetime_mode']==1 and actual_owner['registration_epoch']==1 and
                     actual_owner['registration_calls']==1 and actual_owner['word_observed']==1 and
                     actual_owner['word_available']is True and actual_owner['tls_complete']==1,
                     'all focal joint lifetimes remain actually registered with exact observed word and TLS')
                need(actual_owner['subentry_entries']==0 and
                     all(x['actual_entry']==dict(pc=parsed['source_page_address']+(0x400 if i==1 else 0x200),
                         compiled_root=parsed['source_page_address']+(0x400 if i==1 else 0x200),head=0,
                         slot=x['slot'],generation=x['generation'],build_serial=x['build_serial'],subentry=False)
                         for i,x in enumerate(actual_owner['attempts'])),
                     'all three original focal activations remain exact compiled roots')
                c['actual_entries']=[x['actual_entry']for x in actual_owner['attempts']]
                mapping=actual_owner['rseq_mapping'];need(type(mapping)is list and len(mapping)==6 and
                    any(x['query_kind']==(3 if lane=='differential'else 4)for x in mapping),
                    'actual current-view rseq observation in each explicitly bound lane')
                c['rseq_mapping']=mapping
                need(mode==0 and mode in native_records,'actual same-mode complete native loop reference')
                c['pair']=reader.pair(native_records[mode],parsed,actual_owner)
                need(digest(c['pair'])==digest(PAIR_EXPECTED),'actual shared lifetime and full-state pair; no fault qualification')
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
    need(sum(c.get('pair',{}).get('observed_active_domain_pair',0)for c in r['cases'])==2 and
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
         reports.SUBENTRY_CONTROL_COUNT==19,'both separate exact actual-subentry terminal populations')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True);parser.add_argument('--fixed-receipt',type=Path,required=True);parser.add_argument('--dynamic-receipt',type=Path,required=True);parser.add_argument('--group-receipt',type=Path,required=True);parser.add_argument('--resident-receipt',type=Path,required=True);parser.add_argument('--retained-receipt',type=Path,required=True)
    args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);args.fixed_receipt=args.fixed_receipt.resolve(strict=True)
    args.dynamic_receipt=args.dynamic_receipt.resolve(strict=True);args.group_receipt=args.group_receipt.resolve(strict=True);args.resident_receipt=args.resident_receipt.resolve(strict=True);args.retained_receipt=args.retained_receipt.resolve(strict=True)
    need(all(p.parent==HERE/'results'and p.suffix=='.json'for p in(args.fixed_receipt,args.dynamic_receipt,args.group_receipt,args.resident_receipt,args.retained_receipt)),
         'all five old prerequisites are actual repository public receipts')
    cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-persistent-joint-subentry-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='persistent-joint-subentry-finite-v1',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=0,status='unexecuted',launched=False)for lane,mode,control in ORDER],
        namespace_aliases={},terminal_reports={},lanes={},bounds=BOUNDS,error=None,final_errors=[],
        maps_parse_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        native_probe_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        component_oracles=[dict(name=n,status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False)for n in COMPONENT_ORDER],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
            bounds=BOUNDS['seed'],owner_subjects=0,completed_applications=0,performance_credit=False))
    def pin(path):
        alias = Path(os.path.abspath(path))
        p = alias.resolve(strict=True)
        value = fact(p)
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable input bytes')
        aliases[str(alias)], pins[str(p)] = str(p), value
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable retained artifact')
        artifacts[str(p)] = value
        return p

    def stable():
        need(all(fact(p) == value for p, value in pins.items()), 'all input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()), 'all input aliases unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == value
                 for p, value in artifacts.items()), 'all artifact bytes unchanged')
        need(all(os.path.lexists(p) == value for p, value in presence.items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p, value in r['namespace_aliases'].items()),
             'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        stable()
        need(not any(c['name'] == name for c in r['commands']), 'unique command/capture name')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name.startswith('subject-') else invoke)(row, private, cpu, record=record)
            need(expected is None or row['exit'] == expected, 'actual command exit: ' + name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    p = private / item['file']
                    need(fact(binary(p)) == {k: item[k] for k in ('bytes', 'sha256')}, 'actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = private / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record ' + name + ': ' + repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder=Build(r,private,pin,binary,build_run,extra_decoder_sources=('region.rs',),scalar_span=True,linked_epoch=True,mov_guard=True)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        tracked={os.fsdecode(name)for name in names.split(b'\0')if name}
        required={str(p.relative_to(ROOT))for p in(Path(__file__),HERE/'persistent_joint_startup_reports.py',HERE/'persistent_resident.py',HERE/'persistent_resident_reports.py',HERE/'persistent_resident_experiment.py',HERE/'persistent_group.py',HERE/'persistent_group_reports.py',
            HERE/'persistent_group_build.py',HERE/'persistent_joint_startup_build.py',HERE/'persistent_dynamic.py',HERE/'persistent_dynamic_reports.py',
            HERE/'persistent_epoch.py',HERE/'persistent_epoch_reports.py',HERE/'persistent_epoch_build.py',
            HERE/'linked_epoch_reports.py',HERE/'linked_epoch_base_reports.py',HERE/'linked_epoch_build.py',HERE/'unrolled_hash_owner.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',
            OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',SELECTED/'tests/persistent_active_domain_owner/plan.py')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in('persistent_group_plan.h','persistent_group_plan.c',
            'persistent_group_compact.h','persistent_group_compact.c','persistent_group_lifetime.h','persistent_group_runtime.h',
            'persistent_group_source.inc','persistent_group_rseq.inc','persistent_group_controller.inc',
            'persistent_resident_binding.py','build-persistent-resident.sh','persistent_resident_capture_binding.py',
            'build-persistent-active-domain-capture.sh','persistent_resident_observe.h','persistent_resident_observe.inc',
            'persistent_resident_observe_memory.h','persistent_resident_observe_memory.inc',
            'persistent_group_binding.py','linked_jmp_dispatch.h','linked_jmp_dispatch.c',
            'persistent_plan.h','persistent_compact.h','persistent_epoch_binding.py','linked_mov_guard.h','linked_mov_guard.c',
            'decoder/src/mov_guard.rs')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('persistent_active_domain.inc','persistent_active_domain_binding.py','build-persistent-active-domain.sh',
             'persistent_active_domain_capture_binding.py','build-persistent-active-domain-capture.sh',
             'persistent_active_domain_observe.h','persistent_active_domain_observe.inc',
             'persistent_active_domain_observe_memory.h','persistent_active_domain_observe_memory.inc')}
        required|={'evaluation/inprocess/persistent_retained_two.py','evaluation/inprocess/persistent_retained_two_experiment.py',
            'evaluation/inprocess/persistent_retained_two_reports.py','evaluation/inprocess/persistent_retained_two_build.py'}
        required|={str((FIXTURE/name).relative_to(ROOT))for name in ('copy_oracle.c','build-copy-oracle.sh')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('persistent_active_domain.h','persistent_active_domain_types.inc','linked_jmp_domain.h','linked_jmp_domain_emit.inc',
             'rseq_current_data.h','rseq_current_data.inc','persistent_retained_two.inc',
             'build-persistent-active-domain-differential.sh','linked_native_probe.h','linked_native_probe.inc')}
        required|={str((SELECTED/'tests/provider_app/seed_probe'/n).relative_to(ROOT))for n in('probe.c','record.h','read.py','build.sh')}
        required.add(str((SELECTED/'tests/b2_reference/xstate.py').relative_to(ROOT)))
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('span_fast_bytes.h','tests/span_fast_bytes/oracle.c','tests/span_fast_bytes/build.sh')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in COMPONENT_INPUTS}
        required|={str((SELECTED/name).relative_to(ROOT))for name in PROBE_INPUTS}
        required|={str((SELECTED/name).relative_to(ROOT))for name in MAPS_PARSE_INPUTS}
        required.add('tools/page-entry/selected/maps_parse_memo.inc')
        required|={'evaluation/inprocess/linked_native_probe_reports.py',
            'tools/page-entry/selected/linked_native_probe_report.inc'}
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('persistent_joint_subentry_binding.py','persistent_joint_startup_capture_binding.py',
             'build-persistent-joint-subentry-capture.sh','build-persistent-joint-subentry-differential.sh',
             'persistent_subentry.h','persistent_subentry.inc','persistent_subentry_source.inc')}
        required|=set(JOINT_READER_INPUTS)
        required|={'tools/page-entry/selected/tests/persistent_active_domain_owner/read.py',
            'tools/page-entry/selected/tests/persistent_active_domain_owner/wire.py',
            'evaluation/inprocess/persistent_subentry_build.py'}
        need(required<=tracked,'all application/owner/build/reader sources committed')
        for name in sorted(tracked):
            if not name.startswith('evaluation/inprocess/results/'):pin(ROOT/name)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        temporary=private/'tmp';temporary.mkdir()
        _,out,err=run('namespace-controls',[pin(sys.executable),'-B','-m','unittest','discover','-s',SELECTED.parent,'-p','namespace*_tests.py','-v'],
            profile='program',env=dict(ENV,TMPDIR=str(temporary)))
        need(not out and re.search(rb'\nRan 12 tests in [0-9.]+s\n\nOK\n\Z',err)is not None,'all five existing and seven additive namespace controls')
        r['namespace_controls']=dict(status='passed',tests=12,existing=5,added=7)
        products=builder.prepare()
        imported_sources(pin)
        r['fixed_prerequisite']=fixed_prerequisite(args.fixed_receipt,r,pin,binary,products['archive'])
        r['dynamic_prerequisite']=dynamic_prerequisite(args.dynamic_receipt,r,pin,binary,products['archive'])
        r['group_prerequisite']=group_prerequisite(args.group_receipt,r,pin,binary,products['archive'])
        r['resident_prerequisite']=resident_prerequisite(args.resident_receipt,r,pin,binary,products['archive'],resident)
        r['retained_prerequisite']=retained_prerequisite(args.retained_receipt,r,pin,binary,products['archive'],retained)
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==3 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
             'all three exact active-domain outcomes required')
        need(all(s['status']=='passed'for s in r['component_oracles']),
             'both active components mandatory independently of the three hardware subjects')
        need(r['seed_prerequisite']['status']=='passed','independent seed prerequisite remains separately mandatory')
        need(r['native_probe_component']['status']=='passed','actual probe component mandatory before any hardware')
        need(r['maps_parse_component']['status']=='passed','actual maps parser component mandatory before any hardware')
        r['status']='passed'
    except BaseException as error:
        if r['error']is None:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            imported_sources(pin)
        except BaseException as error:
            r['final_errors'].append('final imported source closure: '+repr(error))
        for p in sorted(private.rglob('*')):
            if p.is_file() and not p.is_symlink():
                try:
                    binary(p)
                except BaseException as error:
                    r['final_errors'].append('partial artifact: ' + repr(error))
        for label, fn in (('build', builder.finish), ('closure', stable)):
            try:
                errors = fn()
                if errors:
                    r['final_errors'].extend(errors)
            except BaseException as error:
                r['final_errors'].append(label + ': ' + repr(error))
        try:
            r['source_after'] = source()
            need(r['source_after'] == r.get('source'), 'committed source unchanged')
        except BaseException as error:
            r['final_errors'].append('source: ' + repr(error))
        r['inputs'], r['aliases'], r['artifacts'] = pins, aliases, artifacts
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in(('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),
                                  ('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as error:r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged'] = r.get('source') is not None and r.get('source_after') == r['source'] and \
            r['inputs_before']==r['inputs_after'] and r['aliases_before']==r['aliases_after']
        r['cleanup_complete'] = all(type(c.get('exit'))is int and c.get('reaped') is True and c.get('timed_out')is False and
            not c.get('error') and c.get('cleanup_errors')==[] and all(d['closed'] for d in c.get('descriptors', []))
            for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or r['artifacts_before']!=r['artifacts_after'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['totals']=dict(planned=3,launched=sum(c['launched']for c in r['cases']),
            observed=sum(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
            native_references=sum(c['status']=='observed_native_active_domain'for c in r['cases']),
            generated_loops=sum(c['status']in('observed_generated_active_domain_maintained','observed_generated_active_domain_differential')for c in r['cases']),
            observed_pairs=sum(c.get('pair',{}).get('observed_active_domain_pair',0)for c in r['cases']if c['status']in('observed_generated_active_domain_maintained','observed_generated_active_domain_differential')),
            application_reader_refusals=sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            native_probe_reader_refusals=sum(len(c.get('native_probe_controls',{}).get('refusals',[]))for c in r['cases']),
            subentry_reader_refusals=sum(len(c.get('subentry_controls',{}).get('refusals',[]))for c in r['cases']),
            repeat_tls_reader_refusals=sum(len(c.get('repeat_tls_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            pair_reader_refusals=sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases']),
            cold_publications=sum(c.get('owner_summary',{}).get('cold_publications',0)for c in r['cases']),
            warm_entries=sum(c.get('owner_summary',{}).get('warm_entries',0)for c in r['cases']),
            interior_signals=sum(c.get('owner_summary',{}).get('interior_signals',0)for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls','fixed_prerequisite','dynamic_prerequisite','group_prerequisite','resident_prerequisite','retained_prerequisite')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['component_oracles']=[{k:v for k,v in s.items()if k in
            ('name','status','launched','expected_exit','bounds','emitted_instruction_execution','hardware_subjects','performance_credit',
             'recipe','archive','features','artifact','exit','duration_ns','timed_out','captures','summaries')}for s in r['component_oracles']]
        public['native_probe_component']={k:v for k,v in r['native_probe_component'].items()if k in PROBE_PUBLIC_FIELDS}
        public['maps_parse_component']={k:v for k,v in r['maps_parse_component'].items()if k in PROBE_PUBLIC_FIELDS}
        public['copy_oracle']={k:v for k,v in r.get('application_build',{}).get('copy_oracle',{}).items()if k in ('status','expected_counts','counts','recipe','artifact','body','exit','duration_ns','bounds','captures','qualification_credit','performance_credit')}
        public['cases']=[public_case(c)for c in r['cases']]
        public['rseq_mapping']={c['lane']:c.get('rseq_mapping')for c in r['cases']if c['lane']!='native'}
        public['native_probe']={c['lane']:dict(row=c.get('terminal',{}).get('native_probe'),
            controls=c.get('native_probe_controls'))for c in r['cases']if c['lane']!='native'}
        public['subentry']={c['lane']:dict(row=c.get('terminal',{}).get('subentry'),
            controls=c.get('subentry_controls'),actual_entries=c.get('actual_entries'))
            for c in r['cases']if c['lane']!='native'}
        public['repeat_tls']={c['lane']:dict(scope=c.get('terminal',{}).get('repeat_lease',{}).get('registration_scope'),
            controls=c.get('repeat_tls_controls'))for c in r['cases']if c['lane']!='native'}
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/persistent_joint_startup.py','--expect-revision',args.expect_revision,'--fixed-receipt',str(args.fixed_receipt.resolve().relative_to(ROOT)),'--dynamic-receipt',str(args.dynamic_receipt.resolve().relative_to(ROOT)),'--group-receipt',str(args.group_receipt.resolve().relative_to(ROOT)),'--resident-receipt',str(args.resident_receipt.resolve().relative_to(ROOT)),'--retained-receipt',str(args.retained_receipt.resolve().relative_to(ROOT))],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,group_fault_qualification=False,
            scope='Distinct joint-subentry finite proof with unchanged original comparisons: native392 with12 whole-state checkpoints; separate maintained and differential A cold/B cold/A joint lifetimes. A qualified pair must model127 internal transfers and measure zero interior signals; failed lanes provide no generated-state counts. No per-hit counter is invented. Five old prerequisites and all controls remain mandatory. No asynchronous fault, whole-LS or performance qualification.')
        raw=csv_projection(public['cases'])
        public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'three compact actual active-domain CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in raw.decode())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1


if __name__=='__main__':raise SystemExit(main())
