"""Exact app binary/report joins plus the unchanged generation-aware closures.

The caller must first run the original full app reader/native pair. This leaf
does not reinterpret architecture, create frames or accept partial app output.
"""
import copy,hashlib,json,struct
from page_selected import need
import page_selected_run_reuse_ls_reports as shared

H=lambda b:hashlib.sha256(b).hexdigest()

def words(data):
    need(len(data)%8==0,'whole actual uint64 array')
    return list(struct.unpack('<'+'Q'*(len(data)//8),data))

def signed(v,name):
    value=v.number(name,True)
    return [abs(value),int(value<0)]

def rseq_data(d):
    m=d.sub('maps','li2_fetch_map_progress');o=m.sub('observation','li2_maps_observation')
    return ([d.number(k)for k in('address','page','allocation','generation','offset','pid','tid','attempted','complete','error')]+
        signed(d,'detail')+signed(m,'fd')+signed(m,'last_read')+signed(m,'close_result')+
        [m.number(k)for k in('bytes','rows','opened','close_started','closed')]+
        [o.number(k)for k in('acquisition_id','handler_id','mutation_epoch','kind','io_performed')])

def binary_join(p,raw,layout,result,record):
    need(type(raw)is bytes and 0<len(raw)<16<<20 and result['accepted']is True and
        result['record_bytes']==len(raw) and result['record_sha256']==H(raw),
        'same actual complete binary already accepted by the unchanged app reader')
    r=record.View(raw,layout,'pao_record')
    rounds=r.number('rounds');scripted=r.number('scripted');operations=result['operations']
    need(result['mode']in('state','stress')and result['policy']in('native','scripted')and
        rounds==(3 if result['mode']=='state'else 1536)and scripted==int(result['policy']=='scripted')and
        operations==6*rounds and r.number('terminal')==1 and r.number('status')==r.number('code')==
        r.number('detail_abs')==r.number('detail_negative')==0,'exact completed app lane and binary terminal')
    e=r.sub('terminal_effect','effect_runtime');o=e.sub('owner','li2_effect_owner')
    inp=o.sub('input','li2_effect_input');d=inp.sub('decoded','li2_decoded')
    decision=o.sub('decision','li2_effect_decision');raw_prefix=r.sub('terminal_raw','selected_effect_raw_prefix')
    effect=dict(version=1,scope='linked_full_input_effect',status=0,failure_code=0,detail_abs=0)
    for k in('first_error','stage','busy','finished','sequence','attempts','commits','completed',
             'native_completed','scripted_completed','random_backend_returned','random_backend_status','fp_bytes'):
        effect[k]=e.number(k)
    for k in('phase','callback_entered','callback_returned','native_entered','native_returned',
             'exit_entered','post_guards_complete','post_callback_entered','post_callback_returned','committed'):
        effect[k]=o.number(k)
    effect.update(kind=d.number('kind'),action=decision.number('action'),error=o.number('first_error'),
        pc=d.number('pc'),next_pc=d.number('next_pc'),fp_before_initialized=e.number('before_initialized'),
        fp_after_initialized=e.number('after_initialized'),raw_entered=raw_prefix.number('entered'),
        raw_returned=raw_prefix.number('returned'),classes=words(e.blob('classes')))
    need(p['effect']==effect,'every actual effect report field joins the complete binary terminal')
    need(effect['scripted_completed']==(operations if scripted else 0)and
        effect['native_completed']+effect['scripted_completed']==effect['completed']==effect['commits']and
        effect['sequence']==effect['attempts']==effect['completed']+1 and
        sum(effect['classes'])==effect['completed'],'only six authenticated fixture sites are Scripted; exit is not completed')
    need(all(effect[k]==v for k,v in dict(stage=4,busy=1,finished=0,kind=7,action=1,phase=5,
        first_error=0,error=0,callback_entered=1,callback_returned=1,native_entered=1,native_returned=0,
        exit_entered=1,post_guards_complete=0,post_callback_entered=0,post_callback_returned=0,committed=0,
        random_backend_returned=0,random_backend_status=0,fp_after_initialized=0,raw_entered=0,raw_returned=0).items()),
        'actual linked callback Native fallback and report-before-raw nonreturning exit')
    c=r.sub('terminal_counts','oneshot_counts');b=r.sub('terminal_reuse','li2_oneshot_reuse_stats')
    lc=r.sub('terminal_lifecycle','li2_lifecycle_counts');pin=r.sub('terminal_pin','li2_rseq_publication_state')
    publication=r.sub('terminal_publication','li2_oneshot_owner');state=publication.sub('state','li2_oneshot_admission_state')
    oneshot=dict(version=2,scope='singleton_reusable_sealed_temporary_e9',status=0,failure_code=0,detail_abs=0,detail_negative=0)
    for k in('attempted','published','restored','completed','retired','refused','effect_started','effect_returned'):
        oneshot[k]=c.number(k)
    for name,k in(('cpuid_patches','cpuid'),('syscall_patches','syscall'),('rdtsc_patches','rdtsc')):
        oneshot[name]=c.number(k)
    need(c.number('refused')==b.number('refused')==0,'no refused temporary publication hidden in a completed app')
    oneshot.update(active_phase=state.number('phase'),resetting=r.number('terminal_resetting'),
        last_completed_sequence=b.number('last_completed_sequence'),last_refused_sequence=0,
        backend_prepared=b.number('prepared'),backend_completed=b.number('completed'),
        rseq_phase=pin.number('phase'),rseq_error=pin.number('first_error'),rseq_attempts=pin.number('attempts'),
        rseq_retired=pin.number('retired'),retained_records=lc.number('retained_records'),generations=lc.number('generations'))
    need(p['oneshot']==oneshot,'complete actual temporary-publication report joins the original binary closure')
    l=p['loader']
    for k in('mappings','generations','retired','admissions','sync_core','kernel_errors','partial_errors','live_pages','last_phase'):
        need(l[k]==lc.number(k),'actual same terminal lifecycle '+k)
    need(l['last_mapping_syscall']==lc.number('last_syscall')and l['source_patches']==oneshot['published']and
        [l[k]for k in('cpuid','syscalls','rdtsc')]==[c.number(k)for k in('cpuid','syscall','rdtsc')],
        'same actual selected/lifecycle observations; no old count reconstruction')
    pre=inp.sub('before','li2_effect_state');g=words(pre.blob('gpr'))
    need(g[0]==l['last_syscall']==raw_prefix.number('number')and g[0]in(60,231)and g[7]==0 and
        l['source_syscalls']==l['syscalls']==l['forwarded']+(2*rounds if scripted else 0)and
        effect['classes']==[l['cpuid'],l['rdrand'],l['rdseed'],l['rdpid'],l['rdtsc'],l['rdtscp'],l['syscalls']-1],
        'actual normal zero-status exit and complete class accounting')
    delta=l['generations']-oneshot['retained_records']
    need(oneshot['attempted']==oneshot['published']==oneshot['restored']==oneshot['effect_started']==
        oneshot['backend_prepared'] and oneshot['published']>operations and
        oneshot['completed']==oneshot['retired']==oneshot['effect_returned']==oneshot['backend_completed']==
        oneshot['last_completed_sequence']==oneshot['published']-1 and
        oneshot['rseq_attempts']==oneshot['published']and oneshot['rseq_retired']==oneshot['retired']and
        delta%2==0 and 2*oneshot['published']<=delta<=4*oneshot['published'],
        'all real patches restored; only the actual final exit is unreturned, with two renewals per source page')
    cp=p['cpuid_nx'];native_cpuid=l['cpuid']-(2*rounds if scripted else 0)
    need(native_cpuid>=0 and cp['version']==1 and cp['hardware_entered']==cp['hardware_returned']==1 and
        cp['attempts']==cp['samples']==cp['commits']==native_cpuid and cp['raw']==cp['result'],
        'actual native-only CPUID backend; scripted fixture effects never invent hardware samples')
    if native_cpuid:
        need(cp['phase']==3 and cp['next_pc']==cp['pc']+2,'last actual hardware CPUID committed')
    else:
        need(all(cp[k]==0 for k in('phase','pc','next_pc','leaf','subleaf'))and
            cp['raw']==cp['result']==[0]*4,'no invented native CPUID sample in an all-scripted population')
    rs=r.sub('terminal_rseq','li2_rseq_state');t=rs.sub('transaction','li2_rseq_transaction')
    data=rs.sub('data','li2_rseq_data');f=rs.sub('last_footprint','li2_write_footprint')
    want=dict(version=1,scope='registered_inactive_prototype',status=0,failure_code=0,detail_abs=0,detail_negative=0,maps_profile=1)
    want['owner']=([rs.number(k)for k in('initialized','registered','held','phase','first_error')]+
        signed(rs,'first_detail')+[rs.number(k)for k in('pid','tid','address','page','length','signature','epoch')])
    want['tls']=[rs.number('tls_attempted'),rs.number('tls_complete')]+signed(rs,'fs_result')+signed(rs,'gs_result')+[rs.number('fs_base'),rs.number('gs_base')]
    want['counts']=[rs.number(k)for k in('calls','registrations','unregistrations','kernel_errors','instruction_checks','range_checks','repeat_checks','run_checks','syscall_checks')]
    want['last']=[rs.number(k)for k in('last_pc','last_code','last_policy','last_first','last_end')]
    want['footprint']=[f.number(k)for k in('abi_version','pc','next_pc','code','length','policy','first','end')]
    want['transaction']=[t.number(k)for k in('attempted','issued','returned','prior_registered')]+signed(t,'result')+[t.number('input_word_observed'),t.number('input_word')]
    want['args']=words(t.blob('args'));want['identity']=[data.number(k)for k in('complete','allocation','generation','offset')]
    want['before']=rseq_data(t.sub('before','li2_rseq_data'));want['after']=rseq_data(t.sub('after','li2_rseq_data'))
    need(p['rseq']==want and rs.number('pid')==rs.number('tid')==result['pid'],
        'every RSEQ report scalar/array exactly matches the complete binary registration snapshot')
    return dict(binary_sha256=H(raw),operations=operations,scripted_completed=effect['scripted_completed'],
        native_completed=effect['native_completed'],scripted_syscalls=2*rounds if scripted else 0,exit_entered_unreturned=True,all_overlapping_fields_joined=True)

# BEGIN EXACT APP GATE ADAPTER
# Exact old completion chain with one source-defined syscall-counter equation.
# These are immutable dependencies; the original module and observed reports
# are never patched. The binary/policy join supplies the exact replacement count.
ZERO=shared.ZERO
generic=shared.generic
repetition=shared.repetition
reuse_completed=shared.reuse_completed
real=shared.real
chain=shared.chain
rseq=shared.rseq
registered=shared.registered
boundary=shared.boundary

def run_completed(loader, repeat, run, reuse, scripted_syscalls):
    """General last-owner closure; finite loop count predicates are unchanged elsewhere."""
    need(all(loader[k] == run[k] == 0 for k in ZERO) and run['pending'] == run['route'] == 0 and
         loader['source_syscalls'] == loader['syscalls'] == loader['forwarded']+scripted_syscalls, 'actual successful whole process')
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
    reuse_completed(run, reuse)


def chain_completed(loader,repeat,run,c,reuse,scripted_syscalls):
    # This call retains every prior cache/publication/private-brk and generic
    # close/query/flags/error assertion. No reconstruction of an owner is used.
    run_completed(loader,repeat,run,reuse,scripted_syscalls)
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


def rseq_completed(loader, repeat, run, c, r, pid, reuse, scripted_syscalls):
    # Preserve all existing cache, chain, source, release and frame predicates.
    chain_completed(loader, repeat, run, c, reuse, scripted_syscalls)
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


def native_completed(parsed, pid, scripted_syscalls):
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
    rseq_completed(loader, parsed['repeat'], parsed['run'], parsed['chain'], parsed['rseq'], pid, parsed['reuse'], scripted_syscalls)


def registered_completed(parsed, pid, scripted_syscalls):
    native_completed(parsed, pid, scripted_syscalls)  # Every original NX/native/chain/register/REP/rseq completion guard.
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


def boundary_completed(parsed, pid, scripted_syscalls):
    registered_completed(parsed, pid, scripted_syscalls)  # Every unchanged native/NX/rseq/chain/run/REP predicate.
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


def gate(p,pid,exit_code,parent,scripted_syscalls):
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
        boundary_completed(p,pid,scripted_syscalls)  # Same native/rseq/chain guards; explicit generation-aware cache closure.
        need(o['failure_code'] == o['detail_abs'] == o['detail_negative'] == x[3] == x[4] == x[5] == 0 and
             x[2] in (2,7) and x[7] == x[8] == x[9] == x[10] == x[11],
             'no pending or failed gate at application completion')
        if x[11]:
            need(x[2] == 7 and q[5:] == [25,1] and q[:2] == [1,1] and
                 m[:5] == [1]*5 and m[7:9] == [0,0] and m[9] > 0 and m[10] > 0 and m[11] == 1,
                 'actual last -ENOTTY and complete unique mount proof before commit')
        if not x[7]:
            need(x[2]==2 and o['current']==[0]*7 and commands==[0]*3 and
                 x[12]>0 and x[13:]==[0,0] and q==[1,1,3,0,0,0,0] and
                 m[:5]==[1]*5 and m[5]<=2147483647 and m[6:9]==[0,0,0] and
                 m[9]>0 and m[10]>0 and m[11]==1,
                 'zero app ioctls retain the real startup close/query and complete unique mount proof')
        completed = True
    else:
        refused = False
        try: boundary_completed(p,pid,scripted_syscalls)
        except ValueError: refused = True
        need(refused, 'unchanged completed rejects failed operation')
    return o,p,dict(application_completed=completed,gate_result_validations=x[11],
        attempts=x[7],permitted=x[8],issued=x[9],returned=x[10],invalidated=x[1],
        tcgets_result_validations=commands[0],tiocgwinsz_result_validations=commands[1],last_command=commands[2],
        gate_phase=x[2],gate_first_error=x[3],gate_first_detail_abs=x[4],
        last_result_abs=q[5],last_result_negative=q[6],failure_code=o['failure_code'],
        detail_abs=o['detail_abs'],detail_negative=o['detail_negative'],
        original_completed_rejected=not completed)


def check(stderr,pid,exit_code,parent,raw,layout,result,record):
    need(type(pid)is int and pid>0 and type(exit_code)is int and exit_code==0 and
        result['pid']==pid,'actual successful app process and original binary reader identity')
    parsed=shared.reports(stderr);shared.extensions(parsed)
    joined=binary_join(parsed,raw,layout,result,record)
    _,same,tty=gate(parsed,pid,exit_code,parent,joined['scripted_syscalls'])
    need(same is parsed,'actual reports are never normalized or rewritten')
    lease=shared.lease.counters(parsed);trace=shared.trace_completed(parsed)
    cache=shared.reuse_completed(parsed['run'],parsed['reuse'])
    return parsed,dict(binary_join=joined,cache_reuse=cache,trace_run=trace,lease=lease,tty=tty,
        full_state_reader_unchanged=True,performance_credit=False)


def supplied_controls(stderr,pid,exit_code,parent,raw,layout,result,record):
    """Supplied report-only mutations after genuine acceptance; zero subjects."""
    accepted,_=check(stderr,pid,exit_code,parent,raw,layout,result,record)
    actual_hash=H(stderr);raw_hash=H(raw)
    cases=(
        ('generation','reuse','state',0,accepted['reuse']['state'][0]+1),
        ('handle_slot','reuse','current',1,(accepted['reuse']['current'][1]+1)%64),
        ('handle_attempt','reuse','current',3,0),
        ('completed_generation','reuse','last_completed',3,accepted['reuse']['last_completed'][3]+1),
        ('copied_count','reuse','last_completed',1,accepted['reuse']['last_completed'][1]+1),
        ('retired_completion','reuse','retirement',1,0),
        ('revoke_query','reuse','revoked',1,0),
        ('nx_permission','reuse','writable',7,7),
        ('cleanup_prefix','reuse','retirement',11,1),
        ('pending_lease','reuse','state',5,1),
        ('source_validation_passes','run','attempt',11,3),
        ('class_count','effect','classes',0,accepted['effect']['classes'][0]+1),
        ('scripted_count','effect','scripted_completed',None,accepted['effect']['scripted_completed']+1),
        ('exit_callback','effect','callback_returned',None,0),
        ('rseq_run_checks','rseq','counts',7,accepted['rseq']['counts'][7]+1),
        ('query_count','tcgets','commands',0,accepted['tcgets']['commands'][0]+1),
        ('forwarded_native_only','loader','forwarded',None,accepted['loader']['forwarded']+1),
        ('startup_query_returned','tcgets','query',1,0),
        ('startup_mount_complete','tcgets','mount',4,0),
    )
    prefixes=dict(reuse=b'LI2_RUN_REUSE ',run=b'LI2_RUN ',effect=b'LI2_SELECTED_EFFECT ',
                  rseq=b'LI2_RSEQ ',tcgets=b'LI2_RSEQ_BTRFS_TTY_QUERY ',loader=b'LI2_LOADER ')
    names=[]
    for name,key,field,index,value in cases:
        changed=copy.deepcopy(accepted[key]);before=changed[field]if index is None else changed[field][index]
        need(before!=value,'supplied mutation actually changes '+name)
        if index is None:changed[field]=value
        else:changed[field][index]=value
        prefix=prefixes[key];lines=stderr[:-1].split(b'\n');places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual report mutation target')
        lines[places[0]]=prefix+json.dumps(changed,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:check(b'\n'.join(lines)+b'\n',pid,exit_code,parent,raw,layout,result,record)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    need(H(stderr)==actual_hash and H(raw)==raw_hash,'actual stderr and whole binary record unchanged')
    return dict(scope='supplied report mutations after actual complete app lane',actual_subjects=0,
        stderr_sha256=actual_hash,record_sha256=raw_hash,refusals=names,native_qualification_credit=False)
