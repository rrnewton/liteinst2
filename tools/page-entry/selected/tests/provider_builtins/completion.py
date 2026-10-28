"""Builtin-only accounting successor; original validators and receipts remain unchanged.

All three complete bodies are exact inverses of the source-pinned predecessors.
Only the native-forward equation gains the independently proven replacement
count; no observed counter is rewritten or passed off as a raw syscall.
"""
from page_selected import need
import page_selected_register_real as old
import page_selected_chain_compare as chain
from page_selected_register_real import finite,repetition,ZERO
from page_selected_chain_compare import slot,same_slot
from page_selected_rseq_compare import observed_data

def register_completed(loader, repeat, run, replaced):
    """General last-owner closure; finite loop count predicates are unchanged elsewhere."""
    need(all(loader[k] == run[k] == 0 for k in ZERO) and run['pending'] == run['route'] == 0 and
         loader['source_syscalls'] == loader['syscalls'] == loader['forwarded']+replaced, 'actual successful whole process: native forwards plus independently proven replacements')
    finite.generic.check_completed_owner(loader)
    if repeat is not None:
        repetition.completed(repeat)
        need(repeat['route'] == repeat['pending'] == 0, 'no pending REP owner')
    need(run['cache_present'] == 1 and run['completed_runs'] > 0, 'actual cache use required for cache completion credit')
    c = run['cache']; slots, attempts, hits, full = c[4], c[6], c[7], c[8]
    need(c[:4] == [2, 0, 0, 0] and 1 <= slots == c[5] <= 64 and c[9:] == [0]*5 and
         attempts == slots+hits+full and run['completed_runs'] == slots+hits and
         2*run['completed_runs'] <= run['copied_instructions'] <= 14*run['completed_runs'],
         'complete actual cache/history accounting')
    i = run['initialization']
    need(i[:7] == [1]*7 and i[7] > 0 and i[7] % 4096 == 0 and i[8] == 64*4096 and i[9] > 0 and
         i[10] == i[7] and i[11:16] == [0]*5 and i[16:] == [1, 1, 64], 'real complete fixed arena')
    a = run['attempt']
    need(a[0] == attempts and a[1] > 0 and a[2:5] == [1]*3 and a[5] in (0, 1) and a[6] in (0, 1) and
         a[5]+a[6] <= 1 and a[7:11] == [1, 0, 0, 0] and a[11] in (1, 2) and a[13:] == [1, 1, 0],
         'exact last held source/plan/attempt closure')
    if a[6]:
        need(full > 0 and slots == 64 and a[12] == 64 and run['publication_present'] == 0,
             'only actual full capacity can leave publication absent after a complete attempt')
    else:
        need(run['publication_present'] == 1 and 0 <= a[12] < slots and
             (hits > 0 if a[5] else a[12] == slots-1), 'actual hit or final new publication')
        p = run['publication']
        need(p[:4] == [2, 0, 0, 0] and p[4:6] == [1, a[12]+1] and 0 < p[6] <= a[1] and
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

def chain_completed(loader,repeat,run,c,replaced):
    # This call retains every prior cache/publication/private-brk and generic
    # close/query/flags/error assertion. No reconstruction of an owner is used.
    register_completed(loader,repeat,run,replaced)
    need(all(c[k]==0 for k in old.ZERO) and c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['nx_entries']==c['fallbacks']>0 and c['sequence']==c['trace_entries']>0 and
         c['preparations']>=c['steps'] and c['releases']==c['preparations']+c['fallbacks'] and
         c['nx_entries']<=loader['nx_faults'], 'complete real segments, actual NX and TRACE entries separately')
    active=slot(c,c['active']);previous=slot(c,c['active']^1)
    need(active['phase']==6 and active['origin']==2 and active['fallback']!=0 and active['prepare']==active['prepared']==1 and
         active['owner_phase']==active['owner_error']==active['open']==active['opened']==active['revoke']==active['revoked']==
         active['trace']==active['post_pc']==active['query']==active['queried']==active['query_pc']==active['unexpected']==0,
         'actual descriptive fallback is retained as unexecuted, not completed')
    for s in (active,previous):
        need(s['generation']>0 and 0<s['event']<=c['event'] and s['borrow']>0 and s['validations']>0 and
             s['held']==s['fetch_error']==0 and s['release']==s['released']==1,
             'each slot retains its own complete source release')
    same_slot(loader,previous)
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

def completed(loader, repeat, run, c, r, pid, replaced):
    need(type(replaced)is int and replaced in(0,4),'finite independently proven replacement count')
    # Preserve all existing cache, chain, source, release and frame predicates.
    chain_completed(loader, repeat, run, c, replaced)
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
        identity = observed_data(r['before'], owner, pid)
        if not t[4]:
            need(observed_data(r['after'], owner, pid) == identity == r['identity'] and
                 r['before'][:7] == r['after'][:7], 'same actual registration mapping before and after kernel')
            need(r['after'][26:] == [0,1] and r['after'][23] > r['before'][23] and
                 r['after'][25] > r['before'][25] and r['after'][24] == r['before'][24],
                 'actual raw registration invalidated maps before the fresh post-kernel query')
        else:
            need(r['after'] == [0]*28, 'failed raw registration has no invented post-registration query')
    else:
        need(t[6:] == [0,0] and r['before'] == r['after'] == [0]*28,
             'existing-registration or unregister transaction has no fabricated fresh mapping observation')
