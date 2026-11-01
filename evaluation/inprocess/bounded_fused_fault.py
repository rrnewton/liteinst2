"""Four additive PF MOV negatives; the three original positive lanes stay exact."""
from pathlib import Path
from page_selected import need,fact
from persistent_dynamic import load,H,digest,named,image_inventory,imported_sources
from direct_frontier_loop_helpers import preparation
import bounded_fused_fault_reports as reports
import persistent_fused_refusal_reports as pf_reports
ROOT=Path(__file__).resolve().parents[2]
FIXTURE=ROOT/'tools/page-entry/selected/tests/persistent_fused_app'
OWNER=ROOT/'tools/page-entry/selected/tests/persistent_fused_owner'
ORDER=(('native',1),('maintained',1),('native',2),('maintained',2))
COMMAND_SCHEDULE=tuple(('subject-'+lane+'-'+str(mode)+'-0','program')for lane,mode in ORDER)
APP_CONTROL_COUNT=16
OWNER_CONTROL_COUNT=28
PAIR_CONTROL_COUNT=12
TERMINAL_CONTROL_COUNT=92
PF_REFUSAL_OWNER_CONTROLS=12
PF_REFUSAL_TERMINAL_CONTROLS=22
EXPECTED_STATUS={('native',1):'observed_native_write_fault',('maintained',1):'observed_pf_store_fault',
                 ('native',2):'observed_native_write_fault',('maintained',2):'observed_pf_guard_rejection'}


def pair_expected(mode,closed_pages):
    need(type(mode)is int and mode in(1,2)and closed_pages in(17,34),'exact PF negative mode and all installed NX pages')
    return dict(observed_pf_terminal_negative=1,mode=mode,plan_version=11,native_steps=6,
        native_full_frames=3,owner_full_frames=4,actual_signal=11 if mode==1 else 4,native_signal=11,
        recovery_phase=1 if mode==1 else 3,cold_publications=1,generated_entries=1,generated_completed=0,
        completion_permits=0,anchor_released=0,closed_pages=closed_pages,interior_signals=0,guest_effects=0,
        exit_status=125,whole_profile_qualified=False,performance_credit=False)


def cohort(builder,private,pin,binary,run,r,original,context):
    app_layout,seed_reference,subjects=context
    reader=load('persistent_fused_fault_app_read',FIXTURE/'fault_read.py',pin)
    owner_reader=load('persistent_fused_fault_owner_read',OWNER/'fault_read.py',pin)
    launcher=pin(FIXTURE/'launch.py')
    need(reader.CONTROL_COUNT==APP_CONTROL_COUNT and owner_reader.CONTROL_COUNT==OWNER_CONTROL_COUNT and
         owner_reader.PAIR_CONTROL_COUNT==PAIR_CONTROL_COUNT and reports.CONTROL_COUNT==TERMINAL_CONTROL_COUNT,
         'literal independent additive fault/reject control populations')
    imported_sources(pin)
    r['fault_cases']=[dict(label='subject-'+lane+'-'+str(mode)+'-0',lane=lane,mode=mode,control=0,
        expected_exit=0 if lane=='native'else 125,status='unexecuted',launched=False)for lane,mode in ORDER]
    native={}
    for c in r['fault_cases']:
        lane,mode,label=c['lane'],c['mode'],c['label'];c['status']='failed'
        directory=private/label;directory.mkdir();role='native'if lane=='native'else'gated'
        holder=r['lanes']['maintained']
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects['maintained']
        carrier_bytes=carrier.read_bytes()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',role,'--mode',str(mode),'--control','0',
            '--original',original,'--preparation',directory/'preparation.json']
        for p in roots:argv+=['--library-root',p]
        if lane!='native':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,stdout,stderr=run(label,argv,profile='program',expected=c['expected_exit'],record=lane!='native')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1]
                    c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),
                        timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            args=(stdout,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
            parsed=reader.read(*args)
            if lane=='native':
                need(stderr==b'','actual native fault observer stderr remains empty')
                c['application_controls']=reader.controls(*args)
                named(c['application_controls'],APP_CONTROL_COUNT,H(stdout));native[mode]=parsed
                c['native_summary']=dict(mode=mode,steps=6,full_frames=3,signal=11,
                    fault_pc=parsed['fault_pc'],fault_address=parsed['fault_address'],guest_effects=0,
                    completed_application=False,observer_exit=0)
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(128<capture['bytes']<4<<20 and layout['types']['pdo_wire']['bytes']==5421440 and
                     fact(record_path)=={k:capture[k]for k in('bytes','sha256')},
                     'whole real failed-owner record retains original strict4MiB transport bound')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),persistent_binding=holder['release_build']['persistent_binding'],
                    headers=holder['release_build']['headers'],app_symbols=app_layout['symbols'])
                owner_args=(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'])
                actual_owner=owner_reader.read(*owner_args)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,
                    fact(carrier),carrier_bytes,actual_owner,owner_reader,mode,parsed,app_layout)
                terminal,c['terminal']=reports.check(stderr,*terminal_args);r['terminal_reports'][label]=terminal
                c['pf_refusals']=actual_owner['pf_refusals']
                c['pf_refusal_stages']=actual_owner['pf_refusal_stages']
                c['pf_refusal_terminal_controls']=pf_reports.controls(stderr,actual_owner,owner_reader)
                named(c['pf_refusal_terminal_controls'],PF_REFUSAL_TERMINAL_CONTROLS,H(stderr),hash_key='original_stderr_sha256')
                c['terminal_controls']=reports.controls(stderr,*terminal_args)
                named(c['terminal_controls'],TERMINAL_CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:actual_owner[k]for k in('mode','status','code','detail','cold_publications',
                    'generated_entries','generated_completed','completion_permits','anchor_released',
                    'cleanup_closed_pages','interior_signals','native_fault_signal','actual_signal','recovery_phase')}
                need(mode in native,'complete original native write-fault reference precedes gated negative')
                c['pair']=owner_reader.pair(native[mode],parsed,actual_owner)
                need(c['pair']==pair_expected(mode,actual_owner['cleanup_closed_pages']),
                     'exact native fault/generated fault-or-rejection domains and no completion credit')
                c['pair_controls']=owner_reader.pair_controls(native[mode],parsed,actual_owner)
                controls=c['pair_controls'];names=controls['refusals']
                need(type(names)is list and len(names)==len(set(names))==PAIR_CONTROL_COUNT and
                     all(type(x)is str and x for x in names)and controls['native_operations']==0,
                     'all12 separate negative full-state pair controls')
                c['owner_reader_controls']=owner_reader.controls(*owner_args)
                named(c['owner_reader_controls'],OWNER_CONTROL_COUNT,H(record))
                c['pf_refusal_owner_controls']=owner_reader.pf_refusal_controls(*owner_args)
                named(c['pf_refusal_owner_controls'],PF_REFUSAL_OWNER_CONTROLS,H(record))
            c['status']=EXPECTED_STATUS[lane,mode]
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and
                   isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need([(c['lane'],c['mode'])for c in r['fault_cases']]==list(ORDER)and
         all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['fault_cases'])and not r['error'],
         'all four actual fault/reject observations required without skips or failure relabeling')
    for key,total in(('application_controls',32),('owner_reader_controls',56),('pair_controls',24),('terminal_controls',184)):
        need(sum(len(c.get(key,{}).get('refusals',[]))for c in r['fault_cases'])==total,
             'complete separate PF negative control census '+key)

    need(owner_reader.PF_REFUSAL_CONTROL_COUNT==PF_REFUSAL_OWNER_CONTROLS and pf_reports.CONTROL_COUNT==PF_REFUSAL_TERMINAL_CONTROLS and
         sum(len(c.get('pf_refusal_owner_controls',{}).get('refusals',[]))for c in r['fault_cases'])==24 and
         sum(len(c.get('pf_refusal_terminal_controls',{}).get('refusals',[]))for c in r['fault_cases'])==44,
         'both negative literal PF counter and terminal control populations')
