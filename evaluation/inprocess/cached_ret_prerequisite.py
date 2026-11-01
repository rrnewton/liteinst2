"""Read-only nine-case RET owner gate, including its mandatory high-bank chain.

No reader or mutation control is replayed. Every retained whole input, artifact,
command capture and typed result remains joined to the exact installed source.
The caller pins both bytes and modes until its final closure.
"""
import os
from pathlib import Path
import re
from types import SimpleNamespace
from call_owner import custody
from ret_owner import prerequisites as prior
from ret_owner import run as owner_api
from scalar_span_trace_build import fast_bytes_completed

RESULT = dict(native_subjects=3,gated_subjects=6,full_builds=2,byte_oracles=2,seed_prerequisites=1,
    native_frames=30,application_controls=180,owner_controls=1488,pair_controls=300,
    terminal_controls=438,tls_controls=198,probe_controls=132,subentry_controls=114,effect_controls=72,
    finite_prerequisites=4,owner_pairs=6,raw_bytes=1261760,record_bytes=1261824,record_limit=4194304,
    archive_builds=0,whole_profile_qualified=False,qualification_credit=False,performance_credit=False)
CASES = [('subject-'+lane+'-'+str(mode)+'-0',mode,lane)
         for mode in (0,1,2) for lane in ('native','maintained','differential')]
COMMANDS = prior.CALL_PREFIX+[lane+'-'+name.replace('whole-call-owner-layout','whole-ret-owner-layout')
    for lane in ('maintained','differential') for name in prior.CALL_LANE]+[x[0] for x in CASES]


def check(path, sha256, current, pin, binary, archive, fresh_build):
    need = prior.need
    def keep(name):
        p = pin(name)
        binary(p)  # Preserve whole modes as well as bytes through the caller's final closure.
        return p
    path = keep(path)
    need(re.fullmatch('[0-9a-f]{64}',sha256) is not None and custody.fact(path)['sha256']==sha256,
         'explicit complete RET owner prerequisite identity')
    old = custody.load(path)
    need(old['schema']==1 and old['profile']=='public-ret-owner-gated-v1' and old['status']=='passed' and
         old['revision']==current['revision'] and old['source']==current['source'] and
         old['cpu']==current['cpu']==3 and old['hardware']==current['hardware'] and
         old['bounds']==owner_api.BOUNDS and old['result']==RESULT and
         old['pending']==['original392','original522','ten_run_DR'] and
         old['qualification_credit'] is False and old['performance_credit'] is False and
         old['archive_builds']==0 and old['error'] is None and old['final_errors']==[] and
         all(old[k] is True for k in ('source_unchanged','inputs_unchanged','cleanup_complete')),
         'all nine original-bound RET cases on this clean source, CPU3 and hardware; finite scope only')
    for module in (custody,prior,owner_api):
        p=keep(module.__file__)
        need(old['inputs'][str(p)]==custody.fact(p),'same installed prerequisite and owner code')
    source_path=keep(custody.ROOT/'evaluation/inprocess/ret_owner/SOURCE.json')
    need(old['inputs'][str(source_path)]==custody.fact(source_path),'same full installed RET owner source manifest')
    manifest=custody.load(source_path)
    for name,wanted in manifest['artifacts'].items():
        q=keep(source_path.parent/name)
        need(custody.fact(q)==wanted==old['inputs'][str(q)],'exact executed installed owner artifact')
    for group in ('inputs','artifacts'):
        for name,wanted in old[group].items():
            need(custody.fact(keep(name))==wanted,'whole retained RET owner '+group)
    for name,target in old['aliases'].items():
        need(str(keep(name))==target,'same complete retained RET owner alias')
    need(old['context_links']=={} and old['namespace_aliases']=={},
         'installed natural source and exact no-DT_NEEDED fixture, no hidden facade or closed-FD alias')
    for name,present in old['loader_presence'].items():
        need(Path(name).exists()==present,'same loader configuration presence')
    for directory,names in manifest['source_roster'].items():
        for name in names:
            rel=str(Path(directory)/name);q=keep(custody.ROOT/rel)
            need(old['context'][rel]==dict(origin=rel,copy=False,**custody.fact(q)),
                 'complete installed source roster at the observed revision')
    need(len(old['context'])==sum(map(len,manifest['source_roster'].values())),
         'all and only source-owned installed context entries')
    need([x['name'] for x in old['commands']]==COMMANDS and len(COMMANDS)==85,
         'exact build/seed/two-byte-oracle/nine-subject schedule, no retries or missing cases')
    records={label for label,_,lane in CASES if lane!='native'}
    for c in old['commands']:
        need(type(c['exit']) is int and c['exit']==c['expected_exit']==0 and c['reaped'] is True and
             c['timed_out'] is False and c['error'] is None and c['cleanup_errors']==[] and
             all(x['closed'] is True for x in c['descriptors']) and
             c['bounds']==owner_api.BOUNDS[c['profile']] and c['capture_limit']==16<<20,
             'each exact original-bound owner command completed and was reaped')
        need(set(c['captures'])==({'stdout','stderr','record'} if c['name'] in records else {'stdout','stderr'}),
             'exact native/gated process stream ownership')
        for stream,f in c['captures'].items():
            q=path.parent/f['file']
            need(q.parent==path.parent and not q.is_symlink(),'contained actual whole owner capture')
            observed=custody.fact(keep(q))
            need(observed==old['artifacts'][str(q)] and prior.value(observed)==prior.value(f),
                 'whole command capture is the actual retained artifact')
            if stream=='record':need(f['bytes']==1261824<4<<20,'complete owner raw body and footer under unchanged cap')
    reuse=old['archive_reuse'];build=reuse['build']
    need(reuse['archive']==custody.fact(archive) and reuse['cpu']==3 and reuse['fresh_build'] is False and
         reuse['source_tools_features_verified'] is True and reuse['prior_status']=='passed' and
         reuse['prior_owner_credit'] is False,'same full decoder archive and original source-owned reuse contract')
    archive_path=prior.child(old,reuse['receipt'],keep)
    checked_archive,checked_build,_,_,_=custody.check_archive(
        archive_path,custody.fact(archive_path)['sha256'],current,keep)
    need(custody.fact(checked_archive)==custody.fact(archive) and checked_build==build and
         build['dep_info']==fresh_build['dep_info'] and build['decoder_features']==fresh_build['decoder_features'] and
         build['archive_text_exports']==fresh_build['archive_text_exports'] and
         build['cargo_configuration']==fresh_build['cargo_configuration'],
         'fresh program archive and prerequisite archive have identical full source/features/configuration/exports')
    need(set(build['tools'])==set(fresh_build['tools']) and
         all(prior.value(build['tools'][n])==prior.value(fresh_build['tools'][n]) for n in build['tools']),
         'all actual archive compiler and tool bytes remain identical')
    finite=old['finite_prerequisites'];args={}
    for key in ('call_owner','ret','ret15','runtime_compile'):
        p=prior.child(old,finite[key]['receipt'],keep)
        args[key+'_receipt']=p;args[key+'_receipt_sha256']=custody.fact(p)['sha256']
    checked=prior.check_all(SimpleNamespace(**args),current,keep,checked_archive,build)
    need(checked==finite and all(checked['ret'][k]==v for k,v in
         dict(ret32_cases=32,models=671,adapter_cases=16,adapter_lanes=24,
              planner_plans=8,planner_models=924,high_adapter_cases=16,high_adapter_lanes=24).items()),
         'same complete CALL217/model/native136, RET32/671/924/low/high, ordering15 and compile-only chain')
    seed=old['seed_prerequisite'];row=prior.row(old,'seed-prerequisite')
    need(seed['status']=='passed' and seed['launched'] is True and seed['exit']==0 and
         seed['timed_out'] is False and seed['pid']==row['pid'] and seed['format']['cpu']==3 and
         seed['bounds']==row['bounds']==owner_api.BOUNDS['seed'] and seed['whole_process_ns']==row['duration_ns'] and
         seed['captures']=={k:prior.value(v) for k,v in row['captures'].items()} and
         seed['profile']['record_sha256']==row['captures']['stdout']['sha256'] and
         seed['profile']['pid']==row['pid'] and seed['profile']['cpu']==3,
         'exact actual whole-state seed observation before every owner subject')
    need(set(old['lanes'])=={'maintained','differential'},'both real owner mapping lanes')
    for lane in ('maintained','differential'):
        state=old['lanes'][lane];b=state['release_build'];binding=b['persistent_binding']
        need(b['status']=='passed' and b['profile']=='persistent-ret-owner-'+
             ('differential' if lane=='differential' else 'capture')+'-v1' and
             b['capture'] is True and b['ret_owner_capture'] is True and
             b['archive']==prior.value(custody.fact(archive)) and binding['ret_dispatch'] is True and
             binding['call_dispatch'] is True and binding['typed_capture'] is True and
             binding['maps_differential']==(lane=='differential') and
             binding['archive']==prior.value(custody.fact(archive)) and
             state['schema']==dict(fields=1388,owner_credit=0,raw_bytes=1261760,
                 record_bytes_observed=0,schema_only=True,types=128),
             'both actual RET capture builds and exact whole independent schema')
        fast_bytes_completed(b,old['commands'],keep)
        layout=prior.row(old,lane+'-whole-ret-owner-layout')
        need(layout['captures']['stderr']['bytes']==0,'complete actual owner layout inspection')
    need([(x['label'],x['mode'],x['mapping_lane']) for x in old['cases']]==CASES,
         'all three fixed RET modes, native before each maintained/differential pair')
    for case,(label,mode,lane) in zip(old['cases'],CASES,strict=True):
        c=prior.row(old,label);gated=lane!='native'
        need(case['status']=='passed' and case['launched'] is True and case.get('error') is None and
             case['lane']==('gated' if gated else 'native') and case['control']==0 and
             case['exit']==case['expected_exit']==0 and case['timed_out'] is False and
             case['captures']==c['captures'] and case['whole_process_ns']==c['duration_ns'] and
             case['bounds']==c['bounds']==owner_api.BOUNDS['program' if gated else 'native'],
             'each typed RET result joins its actual bounded process and complete raw captures')
        if not gated:
            prior.ledger(case['application_controls'],60,c['captures']['stdout']['sha256'],'original_sha256')
            need(c['captures']['stderr']['bytes']==0,'actual native reference stderr empty')
            continue
        prior.ledger(case['owner_controls'],248,c['captures']['record']['sha256'],'source_sha256')
        prior.ledger(case['pair_controls'],(46,52,52)[mode])
        need(case['owner_record_sha256']==c['captures']['record']['sha256'],'complete protected record consumed by the owner reader')
        for key,count in (('terminal',73),('tls',33),('probe',22),('subentry',19),('effect',12)):
            prior.ledger(case[key+'_controls'],count,c['captures']['stderr']['sha256'])
        expected=dict(observed_ret_owner=1,mode=mode,invocations=1,native_instructions=9,native_full_frames=10,
            generated_completed=1,cold_publications=1,domain_members=1,closed_pages=17,
            modeled_completed_in_generated=5 if mode else 7,generated_ret_load=1,cached_call=1,
            cached_ret_hit=int(not mode),loaded_miss=int(bool(mode)),private_C3=int(bool(mode)),
            consumed_word_poisoned=int(mode==2),original_return_pc=old['application_layout']['page']+(0x600 if mode else 0x200)+13,
            stack_bytes=520,measured_interior_signals=int(bool(mode)),lifetime_mode=2,
            registration_epoch=0,registration_calls=0,word_observed=0,
            qualification_credit=False,performance_credit=False)
        need(case['pair']==expected,'complete native/owner full-state hit, loaded miss and poisoned-word result')
        need(case['owner_summary']==dict(mode=mode,cold_publications=1,completed=1,domain_members=1,
            closed_pages=17,anchor_released=1,interior_signals=int(bool(mode)),lifetime_mode=2,
            registration_epoch=0,registration_calls=0,word_observed=0,cached_ret_hits=int(not mode),
            loaded_misses=int(bool(mode)),consumed_word_poisoned=int(mode==2)),
            'exact typed owner completion summary; no inferred generic continuation credit')
    return dict(receipt=prior.value(custody.fact(path)),result=RESULT,
        prerequisites={k:prior.value(checked[k]['receipt']) for k in ('call_owner','ret','ret15','runtime_compile')},
        high_bank_cases=16,high_bank_lanes=24,planner_plans=8,planner_models=924,
        executions_here=0,controls_replayed=0,qualification_credit=False,performance_credit=False)
