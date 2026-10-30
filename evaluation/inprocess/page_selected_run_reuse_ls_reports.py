"""Generation-aware cache reuse plus unchanged real effect-LS completion guards."""
import copy,hashlib,importlib.util,json
from pathlib import Path
from page_selected import need
import page_selected_generic_compare as generic
import page_selected_register_connected_compare as register
import page_selected_register_real as real
import page_selected_repeat_compare as repetition
import page_selected_chain_compare as chain
import page_selected_rseq_compare as rseq
import page_default_ls_release_lease_reports as lease
import page_default_ls_release_reports as tty
ROOT=Path(__file__).resolve().parents[2]
_spec=importlib.util.spec_from_file_location('effect_ls_original_boundary',ROOT/'tools/page-entry/selected/tests/rseq_native_boundary/reports.py')
boundary=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(boundary)
registered=boundary.old;nx=registered.old
_unsigned=nx._unsigned;NATIVE_KEYS=nx.NATIVE_KEYS;RSEQ_SCHEMA=nx.RSEQ_SCHEMA;ZERO=nx.ZERO
ORDER=['LOADER','NATIVE','SELECTED_EFFECT','CPUID_NX','ONESHOT','RSEQ','RSEQ_NATIVE','RSEQ_BOUNDARY','RSEQ_BTRFS_TTY_QUERY','CHAIN','RUN','RUN_REUSE','TRACE_RUN']
EFFECT=set('version status failure_code detail_abs first_error stage busy finished sequence attempts commits completed native_completed scripted_completed kind action phase error pc next_pc callback_entered callback_returned native_entered native_returned random_backend_returned random_backend_status exit_entered post_guards_complete post_callback_entered post_callback_returned committed fp_bytes fp_before_initialized fp_after_initialized raw_entered raw_returned'.split())
ONESHOT=set('version status failure_code detail_abs detail_negative attempted published restored completed retired refused cpuid_patches syscall_patches rdtsc_patches effect_started effect_returned active_phase resetting last_completed_sequence last_refused_sequence backend_prepared backend_completed rseq_phase rseq_error rseq_attempts rseq_retired retained_records generations'.split())

REUSE_SCALARS=set('version status failure_code detail_abs detail_negative snapshot_result_abs snapshot_result_negative'.split())
REUSE_ARRAYS=dict(state=7,current=4,last_completed=8,retired_handle=4,retirement=27,rx=13,revoked=13,writable=13,cleanup=13)

TRACE_RUN=set('version status failure_code detail_abs detail_negative candidates preflight_misses attempts entries plan_misses full_misses completed busy active proof_available pending route'.split())

def trace_prefix(t,run,c,loader):
    _unsigned(t,TRACE_RUN,scope='genuine_trace_to_register_run')
    need(all(type(run.get(k))is int and 0<=run[k]<1<<64
             for k in('cache_present','completed_runs','plan_misses','pending','route'))and
         run['cache_present']in(0,1)and type(c.get('fallbacks'))is int and 0<=c['fallbacks']<1<<64 and
         type(loader.get('step_route'))is int and 0<=loader['step_route']<1<<64,
         'typed actual enclosing TRACE counter operands')
    need(all(t[k]in(0,1)for k in('busy','active','proof_available','pending'))and
         t['completed']<=t['entries']<=t['attempts']and
         t['entries']+t['plan_misses']+t['full_misses']<=t['attempts']and
         t['attempts']+t['preflight_misses']<=t['candidates']<=c['fallbacks']and
         t['completed']<=run['completed_runs']and
         t['plan_misses']<=run['plan_misses']and t['pending']==run['pending']and
         t['route']==run['route']==loader['step_route'],
         'actual TRACE decisions, completed runs and unchanged enclosing owner counters')
    if run['cache_present']:
        need(type(run.get('cache'))is list and len(run['cache'])==register.ARRAYS['cache']and
             all(type(x)is int and 0<=x<1<<64 for x in run['cache']),
             'complete typed actual cache counters')
        need(t['full_misses']<=run['cache'][8]and
             t['entries']+t['full_misses']<=run['cache'][6],
             'TRACE publications and capacity refusals are subsets of actual cache attempts')
    else:
        need(t['attempts']==0,'no TRACE attempt without an initialized actual cache')

def trace_closed_counts(t):
    need(t['candidates']==t['attempts']+t['preflight_misses']and
         t['attempts']==t['entries']+t['plan_misses']+t['full_misses']and
         t['entries']==t['completed']and
         all(t[k]==0 for k in('busy','active','proof_available','pending','route')),
         'every actual TRACE handoff completed or released as a planner/capacity miss')
    return {k:t[k]for k in('candidates','preflight_misses','attempts','entries','plan_misses','full_misses','completed')}

def trace_completed(p):
    t=p['trace_run']
    need(all(t[k]==0 for k in('status','failure_code','detail_abs','detail_negative')),
         'successful TRACE report retains actual successful process outcome')
    return trace_closed_counts(t)

def reports(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete actual stderr')
    lines=stderr[:-1].split(b'\n');parts=[line.partition(b' ')for line in lines]
    names=[p[0]for p in parts];order=['LI2_'+x for x in ORDER]
    if b'LI2_REPEAT'in names:order.insert(4,'LI2_REPEAT')
    need(names==[s.encode()for s in order]and all(p[1]==b' 'and 0<len(line)+1<=4096 and b'\r'not in line for p,line in zip(parts,lines)),
         'exact bounded report order with no duplicate or unrecognized rows')
    values={name:rseq.decode(raw)for name,_,raw in parts}
    loader,native=values[b'LI2_LOADER'],values[b'LI2_NATIVE']
    run,c,registration=(values[k]for k in(b'LI2_RUN',b'LI2_CHAIN',b'LI2_RSEQ'))
    repeat=values.get(b'LI2_REPEAT')
    trace=values[b'LI2_TRACE_RUN']
    reuse=values[b'LI2_RUN_REUSE']
    _unsigned(reuse, REUSE_SCALARS, REUSE_ARRAYS)
    extension=dict(effect=values[b'LI2_SELECTED_EFFECT'],oneshot=values[b'LI2_ONESHOT'],
        cpuid_nx=values[b'LI2_CPUID_NX'],rseq_native=values[b'LI2_RSEQ_NATIVE'],
        rseq_boundary=values[b'LI2_RSEQ_BOUNDARY'],tcgets=values[b'LI2_RSEQ_BTRFS_TTY_QUERY'])
    # Preserve generic.parse's actual startup/attribution/lifecycle/vDSO facts.
    # Its zero-admission assertion belongs to the old profile and is replaced
    # here by the explicit native profile's actual positive-count contract.
    _unsigned(loader, generic.KEYS-{'scope'}, scope='partial_selected_reusable_effects')
    need(loader['selected_profile'] == loader['generic_tf_profile'] == 1 and
         loader['source_patches'] > 0, 'actual reusable selected publication mechanism')
    need(loader['selected_selftests'] == loader['first_target_is_interpreter_entry'] ==
         loader['interpreter_entry_faults'] == 1, 'actual startup and first interpreter entry')
    need(loader['nx_faults'] == loader['main_faults']+loader['interpreter_faults']+
         loader['dependency_faults'], 'actual fault attribution')
    records=extension['oneshot']
    need(type(records)is dict and type(records.get('retained_records'))is int and
         records['retained_records']==loader['retired']+loader['live_pages'], 'retained record equation')
    need(loader['sync_core'] >= loader['admissions'], 'actual admission sync prefix')
    need(loader['vdso_close_attempted'] == loader['vdso_close_observed'] == loader['vdso_closed'] == 1 and
         loader['vdso_close_result_abs'] == loader['vdso_close_result_negative'] == 0, 'actual vDSO closure')

    need(type(native) is dict and type(native.get('revisit_count')) is int and
         0 <= native['revisit_count'] <= 16, 'bounded actual revisit count')
    _unsigned(native, NATIVE_KEYS-{'revisit_ns'}, {'revisit_ns': native['revisit_count']})
    need(native['close_complete'] in (0, 1) and native['close_busy'] in (0, 1) and
         native['closed'] <= native['admissions'] <= native['attempts'] and
         native['main_admissions'] <= native['admissions'] and native['main_refaults'] <= native['refaults'],
         'actual native publication/close counts and main subsets')
    need(all(x > 0 for x in native['revisit_ns']), 'nonzero actual revisit intervals')
    need(native['first_source_offset'] % 4096 == 0 and
         native['revisit_count'] <= max(native['admissions']-1, 0),
         'page-aligned first source and revisits after an actual first admission')
    need(all(native[k] == loader[k] for k in ('status', 'failure_code')), 'same native terminal outcome')

    need(type(run) is dict and type(run.get('cache_present')) is int and
         type(run.get('publication_present')) is int and
         run['cache_present'] in (0, 1) and run['publication_present'] in (0, 1), 'actual RUN presence')
    arrays = {k: n for k, n in register.ARRAYS.items()
              if k not in ('cache', 'initialization', 'attempt', 'publication')}
    if run['cache_present']:
        arrays.update({k: register.ARRAYS[k] for k in ('cache', 'initialization', 'attempt')})
    if run['publication_present']:
        arrays['publication'] = register.ARRAYS['publication']
    run_schema(run, arrays)
    need(run['route'] == loader['step_route'], 'same actual RUN route')

    _unsigned(c, (chain.KEYS-{'scope'})|lease.EXTRA, scope='opt_in_same_page_tf_lease')
    need(c['active'] in (0, 1) and c['pending'] in (0, 1) and c['proof_valid'] in (0, 1) and
         c['attempts'] == loader['generic_tf_attempts'] and c['steps'] == loader['generic_tf_steps'],
         'actual chain route/counters')
    for index in (0, 1):
        slot = chain.slot(c, index)
        need(slot['phase'] <= 7 and slot['origin'] <= 2 and slot['fallback'] <= 6 and slot['owner_phase'] <= 6 and
             all(slot[k] in (0, 1) for k in ('prepare', 'prepared', 'retry', 'trace', 'held', 'query',
                                           'queried', 'release', 'released', 'unexpected')) and
             all(slot[k] <= 3 for k in ('open', 'opened', 'revoke', 'revoked')) and slot['length'] <= 15,
             'exact old chain slot domains')
    if any(c[k] for k in ZERO) or c['pending'] or c['error'] or c['proof_valid'] or loader['step_route']:
        chain.same_slot(loader, chain.slot(c, c['active']))

    _unsigned(registration, RSEQ_SCHEMA['scalar_keys'],
              {k: len(v) for k, v in RSEQ_SCHEMA['arrays'].items()}, RSEQ_SCHEMA['scope'])
    need(registration['maps_profile'] == 1, 'actual RSEQ maps profile')
    if repeat is not None:
        _unsigned(repeat, repetition.SCALARS, repetition.ARRAYS)
        need(repeat['attempts'] > 0 and repeat['completed'] <= repeat['attempts'] and
             repeat['route'] == loader['step_route'], 'actual optional REP prefix')
    trace_prefix(trace,run,c,loader)
    for row in (run, c, registration, trace, reuse)+(() if repeat is None else (repeat,)):
        need(all(row[k] == loader[k] for k in ZERO), 'same actual outcome in every old report')
    parsed=dict(loader=loader,native=native,repeat=repeat,run=run,chain=c,rseq=registration,
        lease={k:c[k]for k in lease.EXTRA},trace_run=trace,reuse=reuse,**extension)
    return parsed


def extensions(p):
    l=p['loader'];cp=p['cpuid_nx'];rn=p['rseq_native'];b=p['rseq_boundary'];t=p['tcgets']
    _unsigned(cp,nx.NX_SCALARS,{'raw':4,'result':4})
    need(cp['hardware_entered']in(0,1)and cp['hardware_returned']<=cp['hardware_entered']and
         cp['phase']<=3 and cp['commits']<=cp['samples']<=cp['attempts']and
         all(x<1<<32 for x in cp['raw']+cp['result'])and cp['leaf']<1<<32 and cp['subleaf']<1<<32,
         'truthful exact CPUID prefix')
    _unsigned(rn,registered.SCALARS,{'before':28,'after':28},'registered_native_epochs')
    need(rn['phase']<=4 and all(rn[k]in(0,1)for k in('unsafe_terminal','entry_checked','checking','detail_negative','first_detail_negative'))and
         all(rn[k]<1<<16 for k in('fs_selector_entry','gs_selector_entry','fs_selector_after','gs_selector_after')),
         'exact registered-native domains')
    need(rn['closed']<=rn['entries']<=rn['admissions']<=rn['attempts']and rn['tls_refreshes']<=rn['closed']and
         rn['entries']<=rn['preentries']and rn['admissions']<=p['native']['admissions'],'actual native epoch prefix')
    _unsigned(b,boundary.SCALARS,boundary.ARRAYS,'registered_current_pc_refault')
    need(b['phase']<=5 and all(b[k]in(0,1)for k in('entry_checked','detail_negative','first_detail_negative'))and
         all(x<1<<16 for x in b['tls'][4:]),'exact boundary scalar domains')
    a,perm,entry,observed,tls,closed=b['counts']
    need(closed<=tls<=observed<=entry<=perm<=a<=rn['admissions']and closed<=p['native']['refaults'],'actual boundary prefix')
    _unsigned(t,tty.SCALARS,tty.ARRAYS,'trusted_parent_capture_btrfs_tcgets_tiocgwinsz_v1')
    e=p['effect'];_unsigned(e,EFFECT,{'classes':7},'linked_full_input_effect')
    o=p['oneshot']
    need(type(o)is dict and set(o)==ONESHOT|{'scope'}and o['scope']=='singleton_reusable_sealed_temporary_e9'and
         all(type(o[k])is int and 0<=o[k]<1<<64 for k in ONESHOT)and o['version']==2,'exact reusable publication schema')
    for row in(cp,rn,b,t,e,o):
        need(all(row[k]==l[k]for k in('status','failure_code','detail_abs','detail_negative')if k in row),'same actual terminal outcome')

def effect_exit(p):
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']in(60,231)and l['source_syscalls']==l['syscalls']==l['forwarded']>0,'actual successful exit syscall path')
    need(all(e[k]==v for k,v in dict(first_error=0,stage=4,busy=1,finished=0,kind=7,action=1,phase=5,error=0,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=0,exit_entered=1,
        post_guards_complete=0,post_callback_entered=0,post_callback_returned=0,committed=0,
        random_backend_returned=0,random_backend_status=0,fp_after_initialized=0,raw_entered=0,raw_returned=0).items()),
        'literal report-before-raw nonreturning exit prefix; never completed')
    need(0<e['pc']<=(1<<64)-3 and e['next_pc']==e['pc']+2 and
         512<=e['fp_bytes']==e['fp_before_initialized']<=65536 and
         e['sequence']==e['attempts']==e['completed']+1 and e['completed']==e['commits']==e['native_completed']and
         e['scripted_completed']==0 and e['classes']==[l['cpuid'],l['rdrand'],l['rdseed'],l['rdpid'],l['rdtsc'],l['rdtscp'],l['syscalls']-1]and
         sum(e['classes'])==e['completed'],'every returning Native class accounted separately from final exit')
    need(o['published']>8 and o['attempted']==o['published']==o['restored']==o['effect_started']==o['backend_prepared']==l['source_patches']and
         o['completed']==o['retired']==o['effect_returned']==o['backend_completed']==o['last_completed_sequence']==o['published']-1 and
         o['refused']==o['resetting']==o['last_refused_sequence']==o['rseq_error']==0 and o['active_phase']==7 and
         o['rseq_phase']==6 and o['rseq_attempts']==o['published']and o['rseq_retired']==o['retired'],
         'all temporary patches restored; only final exit remains unreturned and unretired')
    need([o[k]for k in('cpuid_patches','syscall_patches','rdtsc_patches')]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0,'actual class publication and lifecycle accounting')
    # Each restored plan renews its fixed one or two source pages twice.
    # Page counts are not separately reported; do not invent an exact split.
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')
    need(p['rseq']['owner'][1:4]==[1,1,3]and l['rseq']==p['rseq']['counts'][0]>0,
         'real default inactive registration remains held through process exit')

def run_schema(run, arrays):
    need(type(run) is dict and set(run) == register.SCALARS | set(arrays),
         'exact generation-aware RUN fields')
    need(all(type(run[k]) is int and 0 <= run[k] < 1 << 64 for k in register.SCALARS),
         'unsigned generation-aware RUN scalars')
    for key, count in arrays.items():
        need(type(run[key]) is list and len(run[key]) == count and
             all(type(x) is int and 0 <= x < 1 << 64 for x in run[key]),
             'exact unsigned generation-aware RUN array '+key)
    need(run['version'] == 2, 'only explicit generation-aware RUN version2')


def retirement_query(q, entry, prot):
    need(q == [1, 1, entry, entry+4096, 1, prot, 0, prot, 0, 0, 0, 0, 0],
         'exact complete one-page permission query, no error or inferred cleanup')


def reuse_completed(run, reuse):
    """Cross-report joins; actual terminal reports are never rewritten."""
    need(all(reuse[k] == 0 for k in ('status', 'failure_code', 'detail_abs', 'detail_negative',
         'snapshot_result_abs', 'snapshot_result_negative')), 'successful complete private reuse snapshot')
    c, a, i, h = (run[k] for k in ('cache', 'attempt', 'initialization', 'last_complete'))
    generation, completions, retirements, cursor, lookup, leased, pending = reuse['state']
    need(generation == c[4]+retirements and c[4] == c[5] == 64 and retirements > 0 and
         completions == run['completed_runs'] == generation+c[7] and
         c[6] == generation+c[7]+c[8] and [lookup, leased, pending] == [0, 0, 0],
         'actual reuse beyond fixed64 slots; every publication/hit completed and quiesced')
    handle, done = reuse['current'], reuse['last_completed']
    need(handle[0] == 1 and 0 <= handle[1] < 64 and 0 < handle[2] <= generation and
         0 < handle[3] <= c[6] and done == [completions, run['copied_instructions'],
             1, handle[2], i[7]+handle[1]*4096, h[19], h[6], h[7]],
         'last completion binds actual value handle, generation, entry, fresh borrow and plan')
    if a[6]:
        need(handle[3] < a[0], 'capacity miss retains an earlier completed handle')
    else:
        p = run['publication']
        need(handle == [1, a[12], p[5], a[0]] and done[4] == p[7],
             'last successful current publication, handle and completion agree exactly')
        need(a[5] or p[5] == generation,
             'new publication receives the last monotonic generation; hit retains its actual generation')
    old, t = reuse['retired_handle'], reuse['retirement']
    need(old[0] == 1 and 0 <= old[1] < 64 and 0 < old[2] < generation and
         0 < old[3] < t[2] <= handle[3] and 0 < t[1] < completions and
         t[0] == 4 and t[3] == i[7]+old[1]*4096 and t[4:11] == [1]*7 and
         t[11:26] == [0]*15 and t[26] == 4096 and cursor == (old[1]+1)%64,
         'last consumed completed generation fully inspected, revoked, made writable and replaced')
    need((handle[1] == old[1]) == (handle[2] == generation),
         'latest generated identity belongs to exactly the last retired physical slot')
    retirement_query(reuse['rx'], t[3], 5)
    retirement_query(reuse['revoked'], t[3], 1)
    retirement_query(reuse['writable'], t[3], 3)
    need(reuse['cleanup'] == [0]*13, 'successful retirement has no fabricated recovery query')
    return dict(cache_pages=64, generations=generation, completed_runs=completions,
        copied_instructions=run['copied_instructions'], retirements=retirements,
        hits=c[7], capacity_misses=c[8], last_generation=handle[2],
        last_retired_generation=old[2], last_retirement_completed=True,
        pending_lookup=lookup, active_lease=leased, pending_reset=pending,
        source_byte_limit=15, instruction_limit=14, generated_byte_limit=29)


def run_completed(loader, repeat, run, reuse, *, cache_completed=None):
    """General last-owner closure; finite loop count predicates are unchanged elsewhere."""
    need(all(loader[k] == run[k] == 0 for k in ZERO) and run['pending'] == run['route'] == 0 and
         loader['source_syscalls'] == loader['syscalls'] == loader['forwarded'], 'actual successful whole process')
    generic.check_completed_owner(loader)
    if repeat is not None:
        repetition.completed(repeat)
        need(repeat['route'] == repeat['pending'] == 0, 'no pending REP owner')
    need(run['cache_present'] == 1 and run['completed_runs'] > 0, 'actual cache use required for cache completion credit')
    c = run['cache']; slots, attempts, hits, full = c[4], c[6], c[7], c[8]
    need(c[:4] == [2, 0, 0, 0] and 1 <= slots == c[5] <= 64 and c[9:] == [0]*5 and
         attempts == reuse['state'][0]+hits+full and run['completed_runs'] == reuse['state'][0]+hits and
         2*run['completed_runs'] <= run['copied_instructions'] <= 14*run['completed_runs'],
         'complete actual cache/history accounting')
    i = run['initialization']
    need(i[:7] == [1]*7 and i[7] > 0 and i[7] % 4096 == 0 and i[8] == 64*4096 and i[9] > 0 and
         i[10] == i[7] and i[11:16] == [0]*5 and i[16:] == [1, 1, 64], 'real complete fixed arena')
    a = run['attempt']
    need(a[0] == attempts and a[1] > 0 and a[2:5] == [1]*3 and a[5] in (0, 1) and a[6] in (0, 1) and
         a[5]+a[6] <= 1 and a[7:11] == [1, 0, 0, 0] and a[11] in ((1, 2) if a[6] else (2, 4)) and a[13:] == [1, 1, 0],
         'exact last held source/plan/attempt closure')
    if a[6]:
        need(full > 0 and slots == 64 and a[12] == 64 and run['publication_present'] == 0,
             'only actual full capacity can leave publication absent after a complete attempt')
    else:
        need(run['publication_present'] == 1 and 0 <= a[12] < slots and
             (hits > 0 if a[5] else (a[12] == slots-1 if reuse['state'][2] == 0 else a[12] == reuse['retired_handle'][1])), 'actual hit or final new publication')
        p = run['publication']
        need(p[:4] == [2, 0, 0, 0] and p[4] == 1 and 0 < p[5] <= reuse['state'][0] and 0 < p[6] <= a[1] and
             (a[5] or p[6] == a[1]) and p[7] == i[7]+a[12]*4096 and p[8] == p[10] == 4096 and
             16 <= p[9] <= 29 and p[11:16] == [1]*5 and p[16:27] == [0]*11 and
             p[27:] == [1, 1, 1, 1, 0, 0], 'complete exact W^X/sync/full-page publication prefix')
    h = run['last_complete']
    need(h[:6] == [1, 1, 0, 0, 0, 7] and 0 < h[6] < h[7] <= h[6]+15 and 2 <= h[8] <= 14 and
         h[9:17] == [1]*8 and h[17:19] == [0, 1] and 0 < h[19] <= a[1] and
         run['active'] == [0]*10 and run['interrupted'] == [0]*9, 'actual last NX guard/reset/query/release; no active failure')
    need(h[19] < a[1] if a[6] else h[19] == a[1], 'exact last completed attempt or earlier owner before full miss')
    b = run['private_brk']
    if not b[0]:
        need(b == [0]*10, 'no invented private brk observation')
    else:
        need(b[:2] == [1, 1] and b[2] > 0 and b[3] == b[6] > 0 and b[7:] == [0, 0, 0],
             'actual completed protected brk preflight')
        need(b[4:6] == ([(b[2]+4095)&~4095, (b[3]+4095)&~4095] if b[2] < b[3] else [0, 0]),
             'exact observed shrink interval or no shrink')
    (reuse_completed if cache_completed is None else cache_completed)(run, reuse)


def chain_completed(loader,repeat,run,c,reuse, *, cache_completed=None, chain_closure=None):
    # This call retains every prior cache/publication/private-brk and generic
    # close/query/flags/error assertion. No reconstruction of an owner is used.
    run_completed(loader,repeat,run,reuse,cache_completed=cache_completed)
    if chain_closure is not None:
        return chain_closure(loader,c)
    need(all(c[k]==0 for k in real.ZERO) and c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['nx_entries']==c['fallbacks']>0 and c['sequence']==c['trace_entries']>0 and
         c['preparations']>=c['steps'] and c['releases']==c['preparations']+c['fallbacks'] and
         c['nx_entries']<=loader['nx_faults'], 'complete real segments, actual NX and TRACE entries separately')
    active=chain.slot(c,c['active']);previous=chain.slot(c,c['active']^1)
    need(active['phase']==6 and active['origin']==2 and active['fallback']!=0 and active['prepare']==active['prepared']==1 and
         active['owner_phase']==active['owner_error']==active['open']==active['opened']==active['revoke']==active['revoked']==
         active['trace']==active['post_pc']==active['query']==active['queried']==active['query_pc']==active['unexpected']==0,
         'actual descriptive fallback is retained as unexecuted, not completed')
    for s in (active,previous):
        need(s['generation']>0 and 0<s['event']<=c['event'] and s['borrow']>0 and s['validations']>0 and
             s['held']==s['fetch_error']==0 and s['release']==s['released']==1,
             'each slot retains its own complete source release')
    chain.same_slot(loader,previous)
    p=previous;length=p['length'];pc=p['pc'];mask=1 if pc//4096==(pc+length-1)//4096 else 3
    need(p['phase']==5 and p['origin'] in (1,2) and p['fallback']==0 and 1<=length<=15 and pc>0 and
         p['owner_phase']==5 and p['owner_error']==p['unexpected']==0 and
         p['open']==p['opened']==p['revoke']==p['revoked']==mask and
         p['trace']==p['query']==p['queried']==1 and p['post_pc']==p['query_pc']==active['pc'] and
         p['borrow']<active['borrow'], 'retained completed predecessor, distinct original continuation borrow')
    need(loader['tf_pc']==pc and loader['tf_length']==length and loader['tf_code']==p['code'] and
         loader['tf_phase']==p['owner_phase'] and loader['tf_trace']==p['trace'] and
         loader['tf_query_attempted']==p['query'] and loader['tf_query_complete']==p['queried'] and
         loader['tf_release_started']==p['release'] and loader['tf_release_complete']==p['released'],
         'rich unchanged LOADER completion evidence binds the actual retained predecessor')


def rseq_completed(loader, repeat, run, c, r, pid, reuse, *, cache_completed=None, chain_closure=None):
    # Preserve all existing cache, chain, source, release and frame predicates.
    chain_completed(loader, repeat, run, c, reuse,cache_completed=cache_completed,chain_closure=chain_closure)
    owner, counts, t, args = r['owner'], r['counts'], r['transaction'], r['args']
    initialized, registered, held, phase = owner[:4]
    need(initialized == 1 and registered in (0,1) and held == registered and
         phase == (3 if registered else 0) and owner[4:7] == [0,0,0] and
         owner[7] == owner[8] == pid > 0,
         'real terminal IDLE or ACTIVE registration, no synthetic unregister')
    calls, registrations, unregistrations, errors = counts[:4]
    need(registrations == unregistrations+registered and owner[13] == registrations and
         calls == registrations+unregistrations+errors == loader['rseq'],
         'every actual rseq return accounted, including retained active registration')
    if registrations:
        need(r['identity'][0] == 1 and r['identity'][1] > 0 and r['identity'][2] > 0 and
             owner[9] > 0 and owner[9] & 31 == 0 and owner[10] == owner[9] & ~4095 and
             owner[9] <= (1 << 64)-32 and owner[11] == 32 and owner[12] < 1 << 32 and
             r['tls'][:6] == [1,1,0,0,0,0],
             'successful registration has actual mapping identity and successful TLS observations')
    else:
        need(r['identity'] == [0]*4 and r['tls'] == [0]*8,
             'no registration means no invented mapping or TLS success')
    if not calls:
        need(owner[9:14] == [0]*5 and t == [0]*8 and args == [0]*6 and
             r['before'] == r['after'] == [0]*28 and counts == [0]*9 and
             r['last'] == [0]*5 and r['footprint'] == [0]*8,
             'zero calls retain only initialized singleton identity')
        return
    need(t[:3] == [1,1,1] and t[3] in (0,1) and t[5] in (0,1) and
         t[6] in (0,1) and t[7] == 0 and (args[2] & 0xffffffff) in (0,1),
         'last actual transaction issued and returned with scoped flags')
    prior, flags = t[3], args[2] & 0xffffffff
    if t[4]:
        need(t[5] == 1 and 1 <= t[4] <= 4095 and errors > 0 and registered == prior,
             'actual kernel error preserves prior registration')
    else:
        need(t[5] == 0 and registered == int(not flags) and prior == flags and
             args[0] == owner[9] and args[1] & 0xffffffff == owner[11] and
             args[3] & 0xffffffff == owner[12], 'actual successful register/unregister tuple')
    if not prior and not flags:
        need(t[6:] == [1,0] and args[0] == owner[9] and args[1] & 0xffffffff == 32 and
             args[3] & 0xffffffff == owner[12], 'fresh registration observed actual zero input before issue')
        identity = rseq.observed_data(r['before'], owner, pid)
        if not t[4]:
            need(rseq.observed_data(r['after'], owner, pid) == identity == r['identity'] and
                 r['before'][:7] == r['after'][:7], 'same actual registration mapping before and after kernel')
            need(r['after'][26:] == [0,1] and r['after'][23] > r['before'][23] and
                 r['after'][25] > r['before'][25] and r['after'][24] == r['before'][24],
                 'actual raw registration invalidated maps before the fresh post-kernel query')
        else:
            need(r['after'] == [0]*28, 'failed raw registration has no invented post-registration query')
    else:
        need(t[6:] == [0,0] and r['before'] == r['after'] == [0]*28,
             'existing-registration or unregister transaction has no fabricated fresh mapping observation')


def native_completed(parsed, pid):
    """Keep every old owner assertion; require the caller's actual launch PID."""
    need(type(pid) is int and pid > 0, 'actual positive launch PID')
    loader, native = parsed['loader'], parsed['native']
    need(native['status'] == native['failure_code'] == native['epoch_error'] ==
         native['close_error'] == native['close_busy'] == 0 and native['close_complete'] == 1 and
         0 < native['admissions'] == native['closed'] == loader['admissions'] and
         loader['sync_core'] == native['admissions']+native['closed'] and
         native['first_admission_ns'] > 0, 'complete genuine native admission and revocation')
    # This calls unchanged chain, register, generic-TF, REP and rseq closure.
    # All positive admission/sync values and the new scope remain untouched.
    rseq_completed(loader, parsed['repeat'], parsed['run'], parsed['chain'], parsed['rseq'], pid, parsed['reuse'])


def registered_completed(parsed, pid):
    native_completed(parsed, pid)  # Every original NX/native/chain/register/REP/rseq completion guard.
    s = parsed['rseq_native']
    need(s['status'] == s['failure_code'] == s['phase'] == s['first_error'] ==
         s['first_detail_abs'] == s['first_detail_negative'] == s['unsafe_terminal'] == s['checking'] == 0,
         'no pending or failed registered-native epoch')
    need(s['attempts'] == s['admissions'] == s['preentries'] == s['entries'] == s['closed'] ==
         s['tls_refreshes'], 'every actual registered-native admission closed and refreshed once')
    if not s['attempts']:
        need(all(s[k] == 0 for k in registered.SCALARS-{'version'}) and s['before'] == s['after'] == [0]*28,
             'no invented registered-native work when no admission was attempted')
        return
    need(s['entry_checked'] == 1 and s['pid'] == s['tid'] == pid and s['pc'] >= 0x200000000 and
         s['address'] > 0 and s['address'] & 31 == 0 and s['address'] <= (1 << 64)-32 and
         s['page'] == s['address'] & ~4095 and s['length'] == 32 and s['signature'] < 1 << 32 and
         0 < s['registration_epoch'] <= parsed['rseq']['owner'][13], 'actual retained singleton registration')
    need(s['native_admissions_before'] == s['native_closed_before'] and
         s['native_admissions_before']+1 <= parsed['native']['admissions'] and
         s['word_before'] == s['word_entry'] == s['word_after'] == 0 and
         s['fs_selector_entry'] == s['fs_selector_after'] and
         s['gs_selector_entry'] == s['gs_selector_after'], 'original boundary words and actual refreshed selectors')
    registered._data(s['before'], s, pid); registered._data(s['after'], s, pid)
    if s['registration_epoch'] == parsed['rseq']['owner'][13]:
        owner, identity = parsed['rseq']['owner'], parsed['rseq']['identity']
        need([s[k] for k in ('address', 'page', 'length', 'signature')] == owner[9:13] and
             identity[0] == 1 and s['before'][2:5] == s['after'][2:5] == identity[1:4],
             'same current registration epoch joins exact old owner and actual allocation identity')
    need(s['before'][:7] == s['after'][:7] and s['after'][23] > s['before'][23] and
         s['after'][25] > s['before'][25], 'same pinned identity through distinct actual before/after acquisitions')


def boundary_completed(parsed, pid):
    registered_completed(parsed, pid)  # Every unchanged native/NX/rseq/chain/run/REP predicate.
    s = parsed['rseq_boundary']
    need(s['status'] == s['failure_code'] == s['phase'] == s['first_error'] ==
         s['first_detail_abs'] == s['first_detail_negative'] == 0, 'no failed or pending boundary token')
    a, p, e, o, t, c = s['counts']
    need(a == p == e == o == t == c, 'each attempted retry entered, observed, refreshed and completed once')
    if not a:
        need(all(s[k] == 0 for k in boundary.SCALARS-{'version'}) and
             all(s[k] == [0]*n for k, n in boundary.ARRAYS.items()), 'no invented boundary work')
        return
    identity, geometry = s['identity'], s['geometry']
    pc, fault, page = geometry
    need(s['entry_checked'] == 1 and identity[:2] == [pid, pid] and
         identity[2] > 0 and identity[2] & 31 == 0 and identity[2] <= (1 << 64)-32 and
         identity[3] == identity[2] & ~4095 and identity[4] == 32 and identity[5] < 1 << 32 and
         0 < identity[6] <= parsed['rseq']['owner'][13] and
         0 < identity[7] == identity[8] <= parsed['native']['admissions'], 'actual retained registration')
    need(pc >= 0x200000000 and page == pc & ~4095 and page <= (1 << 64)-1-4096 and
         fault == page+4096 and 0 < fault-pc <= 14, 'exact current-PC adjacent-page geometry')
    need(s['words'] == [0]*3 and s['tls'][:2] == s['tls'][2:4] and
         s['tls'][4:6] == s['tls'][6:8] == s['tls'][8:], 'actual zero words and unchanged fresh TLS')
    row = dict(address=identity[2], page=identity[3])
    registered._data(s['first_data'], row, pid); registered._data(s['second_data'], row, pid)
    need(s['first_data'][:7] == s['second_data'][:7] and
         s['second_data'][23] > s['first_data'][23] and s['second_data'][25] > s['first_data'][25],
         'same pin through separate fresh first/second observations')
    if identity[6] == parsed['rseq']['owner'][13]:
        need(identity[2:6] == parsed['rseq']['owner'][9:13] and
             parsed['rseq']['identity'][0] == 1 and
             s['first_data'][2:5] == s['second_data'][2:5] == parsed['rseq']['identity'][1:4],
             'same current epoch joins the unchanged rseq owner and allocation')
    first, second = s['first_close'], s['second_close']
    boundary._close(first, pid, 1, page); boundary._close(second, pid, 0, 0)
    need(first[0] < (1 << 64)-1 and second[0] == first[0]+1 and first[1:5] == second[1:5],
         'zero-page second observation follows the preserved one-page close without lifecycle mutation')


def gate(p,pid,exit_code,parent):
    o=p['tcgets']
    need(type(pid) is int and pid > 0 and type(exit_code) is int and exit_code in (0,125),
         'actual report-bearing terminal process')
    need(o['version'] == 1 and o['status'] == exit_code and
         all(o[k] == p['loader'][k] for k in ('status','failure_code','detail_abs','detail_negative')),
         'same terminal outcome, never a failed operation relabel')
    x,q,m = o['prefix'],o['query'],o['mount']
    need(x[0] == 1 and o['launch'] == parent['identity'] and
         all(v in (0,1) for v in (x[1],x[5],*q[:2],q[4],q[6],*m[:5],m[6],m[8],o['detail_negative'])) and
         x[2] <= 8 and x[11] <= x[10] <= x[9] <= x[8] <= x[7] and q[1] <= q[0] and
         m[9] <= 256<<10 and m[10] <= 2048 and m[11] <= 1,
         'actual normal-open launch identity and bounded truthful gate prefixes')
    need((x[1] == 0 and x[6] == 0) or (x[1] == 1 and x[6] == 3),
         'permanent invalidation records attempted close(1)')
    if x[8] and x[7] == x[8]:
        need(o['current'][:5] == o['launch'][:5] and
             o['current'][5] & 0o170000 == o['launch'][5] & 0o170000 == 0o100000 and
             not o['current'][6] & 0o10000000 and x[13] > 0 and x[14] > 0,
             'actual admitted descriptor identity and registration/check prefix')
    if x[11] and x[7] == x[11]:
        need(x[7] == x[8] == x[9] == x[10] == x[11] and q[5:] == [25,1] and
             q[:2] == [1,1] and m[:5] == [1]*5 and m[7:9] == [0,0] and
             m[9] > 0 and m[10] > 0 and m[11] == 1,
             'actual last completed result is -ENOTTY with full unique mount closure')
    commands=o['commands']
    need(commands[0]+commands[1]==x[11] and commands[2]in(0,0x5401,0x5413) and
         (commands[2]==0)==(x[7]==0),'exact per-command actual validated-return accounting')
    if x[11] and x[7]==x[11]:
        need(commands[0 if commands[2]==0x5401 else 1]>0,
             'actual last completed command belongs to its nonempty counter')
    completed = False
    if exit_code == 0:
        boundary_completed(p,pid)  # Same native/rseq/chain guards; explicit generation-aware cache closure.
        need(o['failure_code'] == o['detail_abs'] == o['detail_negative'] == x[3] == x[4] == x[5] == 0 and
             x[2] in (2,7) and x[7] == x[8] == x[9] == x[10] == x[11],
             'no pending or failed gate at application completion')
        if x[11]:
            need(x[2] == 7 and q[5:] == [25,1] and q[:2] == [1,1] and
                 m[:5] == [1]*5 and m[7:9] == [0,0] and m[9] > 0 and m[10] > 0 and m[11] == 1,
                 'actual last -ENOTTY and complete unique mount proof before commit')
        need(commands[0]>0 and commands[1]>0,
             'successful two-query diagnostic must actually validate both exact commands')
        completed = True
    else:
        refused = False
        try: boundary_completed(p,pid)
        except ValueError: refused = True
        need(refused, 'unchanged completed rejects failed operation')
    return o,p,dict(application_completed=completed,gate_result_validations=x[11],
        attempts=x[7],permitted=x[8],issued=x[9],returned=x[10],invalidated=x[1],
        tcgets_result_validations=commands[0],tiocgwinsz_result_validations=commands[1],last_command=commands[2],
        gate_phase=x[2],gate_first_error=x[3],gate_first_detail_abs=x[4],
        last_result_abs=q[5],last_result_negative=q[6],failure_code=o['failure_code'],
        detail_abs=o['detail_abs'],detail_negative=o['detail_negative'],
        original_completed_rejected=not completed)


def supplied_controls(stderr, pid, exit_code, parent):
    """Run only after this exact genuine report passed; no additional subject."""
    accepted, _ = check(stderr, pid, exit_code, parent)
    actual_hash = hashlib.sha256(stderr).hexdigest()
    cases = (
        ('generation', 'reuse', 'state', 0, accepted['reuse']['state'][0]+1),
        ('handle_slot', 'reuse', 'current', 1, (accepted['reuse']['current'][1]+1)%64),
        ('handle_attempt', 'reuse', 'current', 3, 0),
        ('completed_generation', 'reuse', 'last_completed', 3, accepted['reuse']['last_completed'][3]+1),
        ('copied_count', 'reuse', 'last_completed', 1, accepted['reuse']['last_completed'][1]+1),
        ('retired_completion', 'reuse', 'retirement', 1, 0),
        ('revoke_query', 'reuse', 'revoked', 1, 0),
        ('nx_permission', 'reuse', 'writable', 7, 7),
        ('cleanup_prefix', 'reuse', 'retirement', 11, 1),
        ('pending_lease', 'reuse', 'state', 5, 1),
        ('source_validation_passes', 'run', 'attempt', 11, 3),
    )
    names=[]
    for name, key, field, index, value in cases:
        changed=copy.deepcopy(accepted[key])
        need(changed[field][index]!=value, 'supplied mutation actually changes '+name)
        changed[field][index]=value
        prefix=b'LI2_RUN_REUSE 'if key=='reuse'else b'LI2_RUN '
        lines=stderr[:-1].split(b'\n')
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1, 'one exact original mutation target')
        lines[places[0]]=prefix+json.dumps(changed,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:check(b'\n'.join(lines)+b'\n',pid,exit_code,parent)
        except ValueError:refused=True
        need(refused, 'same complete reader refuses supplied '+name)
        names.append(name)
    need(hashlib.sha256(stderr).hexdigest()==actual_hash, 'actual report bytes unchanged')
    return dict(scope='supplied-reader mutations after actual completion',actual_subjects=0,
        original_stderr_sha256=actual_hash,refusals=names,native_qualification_credit=False)


def check(stderr,pid,exit_code,parent):
    need(type(exit_code)is int and exit_code==0,'actual successful process required')
    p=reports(stderr);extensions(p)
    _,same,gate_summary=gate(p,pid,exit_code,parent)
    need(same is p,'original actual report values retained')
    lease_summary=lease.counters(p);effect_exit(p)
    trace_summary=trace_completed(p)
    n=p['native'];e=p['effect'];o=p['oneshot']
    return p,dict(application_completed=True,default_rseq_registered=True,cache_reuse=reuse_completed(p['run'],p['reuse']),gate=gate_summary,lease=lease_summary,trace_run=trace_summary,
        selected=dict(attempts=e['attempts'],completed=e['completed'],classes=e['classes'],unreturned_exit=1),
        publication={k:o[k]for k in('attempted','published','restored','completed','retired','refused','cpuid_patches','syscall_patches','rdtsc_patches','rseq_attempts','rseq_retired','retained_records','generations')},
        native={k:n[k]for k in('attempts','admissions','closed','blocked','epoch_exits','refaults','main_admissions','main_refaults')},
        admission_timing=dict(first_admission_ns=n['first_admission_ns'],first_source_offset=n['first_source_offset'],revisit_count=n['revisit_count'],revisit_ns=n['revisit_ns']))
