"""Distinct finite linked terminal guard composition.

Five original guard bodies are retained except the zero-registration footprint
case: full cold static NONE proof writes these fields without a syscall. The
actual complete rseq row is also joined to the protected capture by the caller.
No old helper or profile is changed.
"""
from page_selected import need
import page_native_pair_reports as prior
from page_selected_run_reuse_app_reports import chain_completed
rseq,registered,boundary=prior.rseq,prior.registered,prior.boundary
pair_completed=prior.pair_completed

def rseq_completed(loader, repeat, run, c, r, pid, reuse, scripted_syscalls, *, cache_completed=None, chain_closure=None):
    # Preserve all existing cache, chain, source, release and frame predicates.
    chain_completed(loader, repeat, run, c, reuse, scripted_syscalls,cache_completed=cache_completed,chain_closure=chain_closure)
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
        need(r['identity'] == [0]*4 and r['tls'][:6] == [1,1,0,0,0,0],
             'unregistered native pair observes actual TLS without a registration mapping')
    if not calls:
        need(owner[9:14] == [0]*5 and t == [0]*8 and args == [0]*6 and
             r['before'] == r['after'] == [0]*28 and counts == [0]*9,
             'zero registration calls retain their exact untouched transaction and counters')
        version,pc,nxt,code,length,policy,first,end=r['footprint']
        need(version==1 and 0<pc<=(1<<64)-1-length and 1<=length<=15 and
             nxt==pc+length and code>0 and policy==1 and first==end==0 and
             r['last']==[pc,code,1,0,0],
             'unregistered cold proof retains its complete actual static NONE footprint')
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

def native_completed(parsed, pid, scripted_syscalls, *, cache_completed=None, chain_closure=None):
    """Keep every old owner assertion; require the caller's actual launch PID."""
    need(type(pid) is int and pid > 0, 'actual positive launch PID')
    loader, native = parsed['loader'], parsed['native']
    need(native['status'] == native['failure_code'] == native['epoch_error'] ==
         native['close_error'] == native['close_busy'] == 0 and native['close_complete'] == 1 and
         0 < native['admissions'] == native['closed'] == loader['admissions'] and
         loader['sync_core'] == native['admissions']+parsed['native_pair']['counts'][3] and
         native['first_admission_ns'] > 0, 'complete genuine native admission and revocation')
    # This calls unchanged chain, register, generic-TF, REP and rseq closure.
    # All positive admission/sync values and the new scope remain untouched.
    rseq_completed(loader, parsed['repeat'], parsed['run'], parsed['chain'], parsed['rseq'], pid, parsed['reuse'], scripted_syscalls,cache_completed=cache_completed,chain_closure=chain_closure)

    pair_completed(parsed,pid)

def registered_completed(parsed, pid, scripted_syscalls, *, cache_completed=None, chain_closure=None):
    native_completed(parsed, pid, scripted_syscalls,cache_completed=cache_completed,chain_closure=chain_closure)  # Every original NX/native/chain/register/REP/rseq completion guard.
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

def boundary_completed(parsed, pid, scripted_syscalls, *, cache_completed=None, chain_closure=None):
    registered_completed(parsed, pid, scripted_syscalls,cache_completed=cache_completed,chain_closure=chain_closure)  # Every unchanged native/NX/rseq/chain/run/REP predicate.
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

def gate(p,pid,exit_code,parent,scripted_syscalls, *, cache_completed=None, chain_closure=None):
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
        boundary_completed(p,pid,scripted_syscalls,cache_completed=cache_completed,chain_closure=chain_closure)  # Same native/rseq/chain guards; explicit generation-aware cache closure.
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
        try: boundary_completed(p,pid,scripted_syscalls,cache_completed=cache_completed,chain_closure=chain_closure)
        except ValueError: refused = True
        need(refused, 'unchanged completed rejects failed operation')
    return o,p,dict(application_completed=completed,gate_result_validations=x[11],
        attempts=x[7],permitted=x[8],issued=x[9],returned=x[10],invalidated=x[1],
        tcgets_result_validations=commands[0],tiocgwinsz_result_validations=commands[1],last_command=commands[2],
        gate_phase=x[2],gate_first_error=x[3],gate_first_detail_abs=x[4],
        last_result_abs=q[5],last_result_negative=q[6],failure_code=o['failure_code'],
        detail_abs=o['detail_abs'],detail_negative=o['detail_negative'],
        original_completed_rejected=not completed)

# The low source contains67 CPUIDs. Direct syscall census is
# 3 identity +2 XCOMP +3 initial machine +5 map/protect +2 writes +3
# cleanup +7 per invocation; mode5 adds6 actual lifecycle effects.
def application_effect_exit(p,mode):
    need(type(mode)is int and mode in(0,1,4,5,6),'exact completed linked application mode')
    calls={0:25,1:25,4:25,5:66,6:473}[mode]
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
    need([o['cpuid_patches']+67,o['syscall_patches']+calls,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0,'exact application publication and unpatched class accounting')
    need(e['attempts']==o['published']+67+calls,
         'complete fixed application direct-effect partition')
    # Each restored plan renews its fixed one or two source pages twice.
    # Page counts are not separately reported; do not invent an exact split.
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')
    expected=2 if mode==5 else 0
    need(p['rseq']['owner'][1:4]==[0,0,0]and l['rseq']==p['rseq']['counts'][0]==expected and
         p['rseq']['counts'][1:4]==([1,1,0]if mode==5 else[0,0,0]),
         'exact explicit register/unregister lifecycle or genuinely unused registration')

from page_selected_repeat_lease_app_reports import lease_request,closed_io,query,carrier_extent,MASK
from page_selected_repeat_lease_ls_reports import external_source

def repeat_completed(p,pid,images,image_bytes,carrier,carrier_bytes):
    need(p['repeat_lease']['version']==1,'exact REP lease version')
    need(p['repeat']is None,'finite TRACE has no separate old-cycle REP observation')
    binding=external_source(p,images,image_bytes,carrier,carrier_bytes)
    r=p['repeat_lease'];pc,nxt,flags,mask,width=lease_request(r)
    n,remaining,traces,retained,final,post_pc,post_flags,started,complete,err,neg,checks=r['progress']
    need(all(r[k]==p['loader'][k]for k in ('status','failure_code','detail_abs','detail_negative')) and
         r['route']==p['loader']['step_route']==p['run']['route'] and r['pending']==p['run']['pending'],
         'prior completed REP retains actual global outcome and current distinct route')
    need(r['attempts']==r['completed']==r['closes']==r['releases']==r['queries']>0 and
         r['traces']==r['retained']+r['completed'] and r['traces']>=traces>=1 and
         r['retained']>=retained and retained==traces-1,
         'one real close/query/release per completed lease; retained transfers are separate')
    if r['attempts']==1:need(r['traces']==traces,'single lease owns every recorded trace')
    need((n==0 and traces==1)or(n>0 and traces<=n),'bounded real REP progress allows hardware chunks')
    need([remaining,final,post_pc,post_flags,started,complete,err,neg,checks]==
         [0,1,nxt,flags|0x100,1,1,0,0,traces+2],'exact final progress and pre/post-seed plus per-TRACE rseq guards')
    need(r['owner']==[5,0,0,0,0,1,0,0,0,0,1,1,1,1] and
         r['event']==[5,0,2,0,0,0,nxt,0,1],
         'actual complete accepted final TRACE, never an incomplete fault or nested event')
    f=r['frames']
    need(f[:3]==[pc,flags|0x10000,n] and f[4]<(1<<47) and 512<=f[5]<=65536 and f[6]==f[5] and
         f[7:10]==[nxt,flags|0x100,0] and f[11:]==[f[4],f[5],f[5]],
         'actual initial/final raw frame identity with complete initialized FP extent')
    expected=(f[3]+(-width if flags&0x400 else width)*n)&MASK
    need(f[10]==expected,'literal full-width final RDI progress')
    need(n<=MASK//width,'initial full REP destination span multiplication does not overflow')
    if n:
        size=n*width;first=f[3]
        if flags&0x400:
            need(first>=size-width and first<=MASK-width,'backward REP span endpoints do not overflow')
            first-=size-width
        need(first<=MASK-size,'complete initial REP write span does not wrap')
    closed_io(r['io'],1);query(r['query'],nxt)
    q=r['query'];source=r['source']
    if q[17]==source[0]:need(q[17:23]==source[:4]+[source[5],source[4]],
         'final query identity matches the same retained source page')
    need(r['release']==[1,1,0,0] and r['borrow'][1]==0 and r['writes']==[traces+2,0,0],
         'actual successful source release and every unconditional private-write guard')
    c=r['custody']
    need(c[:8]==[1,0,0,0,0,0,0,0] and c[9]==c[11]==c[15]==r['attempts'] and
         c[10]==traces and c[12]==c[13]==c[14]==r['traces'] and
         c[8]==c[11]+c[15]+c[16] and c[16]>=r['attempts'] and c[17]==3 and
         c[18]==r['borrow'][0] and c[19:]==[0,0],
         'actual once-only ticket/event chain is empty after all final releases; epochs count real invalidations')
    b=r['backing'];image=images[binding['module']]
    backing_bytes=carrier_extent(carrier,images[0]['bytes'])if binding['module']==0 else image['bytes']
    need(b[0]<=0x7fffffff and b[1]==0 and b[2]&15==15 and b[3:8]==[0,0,0,1,1] and
         b[8]==backing_bytes>0 and b[9]==0 and b[10]&0o170000==0o100000,
         'actual retained sealed regular-file stat/FD proof matches exact main carrier or original dependency extent')
    owner=p['rseq']['owner'];tls=p['rseq']['tls'];registration=r['registration']
    need(registration==[1,0,0,0,pid,pid]+[0]*8 and
         owner[:4]==[1,0,0,0] and owner[7:9]==[pid,pid] and
         owner[13]==p['rseq']['counts'][1]==p['rseq']['counts'][2] and
         p['rseq']['counts'][6]==0,
         'actual prior REP has whole unregistered identity; final explicit registration is balanced')
    return dict(attempts=r['attempts'],completed=r['completed'],traces=r['traces'],retained=r['retained'],
        closes=r['closes'],releases=r['releases'],queries=r['queries'],last_code=r['request'][2],
        last_initial_count=n,last_traces=traces,last_guard_checks=checks,source_module=binding['module'],
        source_file_offset=binding['file_offset'],custody_epoch=c[8],custody_invalidations=c[16],registration_scope='before_first_registration',source_binding=binding)
