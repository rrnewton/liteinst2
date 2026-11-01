"""Require the complete original NX/D3 audit before any certificate subject.

Reads existing full receipts/captures only; does not rerun a reader or subject.
"""
from pathlib import Path
from page_selected import ENV,need
from resident_three.audit_semantics import load

BUILD=[30,512<<20,16<<20,60]
NATIVE=[5,512<<20,16<<20,15]
INSPECT=[10,256<<20,4<<20,20]


def check(path,sha256,current,pin,fact):
    path=pin(path);need(fact(path)['sha256']==sha256,'whole explicit original full-state audit receipt')
    audit=load(path)
    def common(value):
        need(value['source']==current['source'] and value['hardware']==current['hardware'] and
             value['cpu']==current['cpu'] and value['revision']==current['revision'] and
             all(value[k]is True for k in ('source_unchanged','inputs_unchanged','cleanup_complete')) and
             value['error']is None and value['final_errors']==[] and
             all(value[k]is False for k in ('qualification_credit','performance_credit','equivalence_credit')),
             'same complete current-source baseline, original failed receipts never accepted')
        for table in ('inputs','artifacts'):
            for name,want in value.get(table,{}).items():need(fact(pin(name))==want,'whole retained baseline '+table)
        for alias,target in value['aliases'].items():need(str(pin(alias))==target,'whole retained baseline alias')
    common(audit)
    need(audit['profile']=='resident-three-offline-audit-v1' and audit['status']=='observed_unqualified' and
         audit['commands']==[] and audit['child_processes']==audit['subject_executions']==audit['builds']==0,
         'complete unchanged offline baseline audit, no inherited execution authority')
    semantic=audit['semantic'];need(semantic['status']=='observed_unqualified','full baseline semantic status')
    for key,n,field in (('native_app_controls',80,'refusals'),('gated_app_controls',80,'refusals'),
                       ('owner_controls',231,'refusals'),('pair_controls',44,'refusals'),
                       ('signal_controls',87,'refusals'),('prepared_fetch_controls',24,'refusals')):
        row=semantic[key];need(len(row[field])==len(set(row[field]))==n and row['native_operations']==0,
                             'all unchanged original baseline controls '+key)
    terminal=semantic['terminal_controls']
    need(terminal['controls']==141 and len(terminal['refusals'])==len(set(terminal['refusals']))==141 and
         terminal['native_operations']==0,'all unchanged successful baseline terminal-report mutations')
    boundary=terminal['nx_page_boundary']
    need(boundary['controls']==38 and len(boundary['refusals'])==len(set(boundary['refusals']))==38 and
         boundary['native_operations']==0,'all additional strict NX report controls')
    pair=semantic['pair']
    need(pair['cycles']==4 and pair['native_full_frames']==5 and pair['protected_full_frames']==3 and
         pair['cold_publications']==pair['resident_certificates']==3 and pair['entries']==pair['completed']==1 and
         pair['interior_signals']==0 and pair['closed_pages']==51 and pair['old_active_domain_limit']==2 and
         pair['fp_storage_per_frame']==65536 and pair['ucontext_bytes_per_frame']==968 and pair['stack_bytes']==520 and
         pair['qualification_credit']is False and pair['performance_credit']is False,'whole baseline finite full-state population')
    record=audit['receipt'];runpath=pin(record['path']);need(fact(runpath)=={k:record[k]for k in ('bytes','sha256','mode')},
                                                        'audit binds the whole actual baseline observation')
    old=load(runpath);common(old)
    need(old['profile']=='resident-three-observation-v1' and old['status']=='bounded_subjects_completed' and
         old['native_subjects']==old['gated_subjects']==1 and old['archive']==current['archive'] and
         old['result']==dict(independent_semantic_audit_pending=True,native_subjects=1,gated_subjects=1,
             app_bytes=341960,owner_bytes=2063104,qualification_credit=False,performance_credit=False,equivalence_credit=False),
         'same archive and complete original one-native/one-gated baseline')
    contract=load(pin(Path(__file__).resolve().parent/'CONTRACT.json'))
    need([x['name']for x in old['commands']]==contract['commands'] and len(old['commands'])==22,
         'all fixed original baseline build/seed/native/gated commands')
    for row in old['commands']:
        name=row['name'];bounds=NATIVE if name in ('span-bytes-oracle','native-fixture','seed-prerequisite')else INSPECT if name in ('seed-headers','seed-libraries')else BUILD
        env=dict(ENV)
        if name=='dwarf':env.update(MALLOC_ARENA_MAX='1',XDG_CACHE_HOME=str(runpath.parent/'gdb-cache'))
        if name in ('span-bytes-native-libraries','span-bytes-oracle'):env['LD_BIND_NOW']='1'
        need(row['bounds']==bounds and row['environment']==env and row['capture_limit']==16<<20 and
             row['exit']==row['expected_exit']==0 and row['error']is None and row['reaped']is True and
             row['timed_out']is False and row['cleanup_errors']==[] and all(d['closed']is True for d in row['descriptors']),
             'every actual original bounded baseline process remains successful and reaped')
        need(set(row['captures'])==({'stdout','stderr','record'}if name=='gated-fixture'else{'stdout','stderr'}),
             'entire exact baseline capture population')
        for value in row['captures'].values():
            q=runpath.parent/value['file'];need(q.parent==runpath.parent and
                 all(fact(pin(q))[k]==value[k]for k in ('bytes','sha256')) and old['artifacts'][str(q)]==fact(q),
                 'whole actual baseline capture/receipt/artifact join')
    return dict(audit=dict(path=str(path),**fact(path)),observation=dict(path=str(runpath),**fact(runpath)),
        status='complete_original_full_state_audit',same_source=True,same_cpu=True,same_hardware=True,same_archive=True,
        original_controls=dict(native=80,gated=80,owner=231,pair=44,signal=87,prepared_fetch=24,terminal=141,nx_boundary=38),
        qualification_credit=False,performance_credit=False)
