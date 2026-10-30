"""Explicit two-page profile: actual rows and original application closures.

No old native epoch row is synthesized. Physical page counters, pair epochs,
and the unused one-page owners retain distinct meanings. Last-source slots
are terminal observations, not mapping authority or complete frame evidence.
"""
import copy,hashlib,json
from page_selected import need
import page_selected_run_reuse_ls_reports as shared
from page_selected_run_reuse_ls_reports import (ORDER,_unsigned,REUSE_SCALARS,REUSE_ARRAYS,
    rseq,generic,NATIVE_KEYS,register,run_schema,chain,lease,ZERO,RSEQ_SCHEMA,repetition,trace_prefix,
    registered,boundary,extensions,effect_exit,trace_completed,reuse_completed)
from page_selected_run_reuse_app_reports import rseq_completed
from page_selected_repeat_lease_app_reports import LEASE_SCALARS,LEASE_ARRAYS,lease_completed
from page_selected_repeat_lease_ls_reports import external_source
from page_late_dso_reports import legacy_source
MASK=(1<<64)-1
H=lambda b:hashlib.sha256(b).hexdigest()


PAIR_SCALARS='version status failure_code detail_negative detail_abs'.split()
PAIR_ARRAYS=dict(control=13,counts=10,last_nx=6,lifecycle=20,rseq=33,pin_before=6,pin_after=6,close=11)
PAIR_ORDER=PAIR_SCALARS+['control','counts','last_nx','lifecycle','slots','rseq','pin_before','pin_after','close']

def pair_schema(p):
    need(type(p)is dict and list(p)==PAIR_ORDER,'exact ordered native-pair row without duplicate fields')
    need(all(type(p[k])is int and 0<=p[k]<=MASK for k in PAIR_SCALARS)and p['version']==1,
         'typed distinct native-pair scalar schema')
    for key,n in PAIR_ARRAYS.items():
        need(type(p[key])is list and len(p[key])==n and
             all(type(x)is int and 0<=x<=MASK for x in p[key]),'complete typed native-pair '+key)
    need(type(p['slots'])is list and len(p['slots'])==2 and
         all(type(s)is list and len(s)==26 and all(type(x)is int and 0<=x<=MASK for x in s)for s in p['slots']),
         'two complete typed source-slot observations, never a scalar page-count permit')

def pair_completed(parsed,pid):
    p=parsed['native_pair'];n=parsed['native'];loader=parsed['loader']
    pair_schema(p)
    need(p['status']==p['failure_code']==p['detail_negative']==p['detail_abs']==0,
         'actual successful native-pair terminal outcome')
    c,k,l,r=p['control'],p['counts'],p['lifecycle'],p['rseq']
    events,seeds,extensions,closed,one,two,policy,capacity,refault,retried=k
    need(c[:8]==[1,2,0,0,0,0,0,0]and c[8]==1 and c[9]in(0,1)and
         c[10]in(1,2,3)and c[11:]==[pid,pid],
         'actual registered singleton pair owner IDLE, no live page or unconsumed ingress')
    need(seeds==closed==one+two>0 and extensions==two>0 and
         closed==policy+capacity+refault and refault==retried and capacity<=two,
         'every actual one/two-page epoch closed once; extension is demonstrated, not inferred')
    need((not c[9]or refault>0)and (policy,capacity,refault)[c[10]-1]>0,
         'last retry/close observations belong to actual nonempty lifetime populations')
    need(events>=l[11]>=seeds+extensions and events>=extensions+closed+retried and
         n['attempts']==l[11] and n['admissions']==n['closed']==seeds+extensions==one+2*two and
         n['epoch_exits']==n['refaults']==n['epoch_error']==0 and n['main_refaults']<=refault,
         'physical native page counters join pair epochs; old one-page owner remains unused')
    need(n['blocked']+n['low_address_refusals']<=n['attempts']-n['admissions'],
         'actual rejected preparation populations remain disjoint from publication')
    need(loader['sync_core']==n['admissions']+closed,
         'one sync per actual publication and per nonempty close set, not per closed page')
    event=p['last_nx']
    need(event[:3]==[11,2,0]and 0<event[3]<=event[4]<=event[3]+14<=MASK and event[5]&0x10100==0,
         'last genuine accepted NX envelope and imported logical flags, no invented terminal signal')
    need(l[:6]==[1,0,0,0,0,0]and l[6]==l[11]>0 and
         l[12]==l[13]==n['admissions'] and l[14]==closed+retried and
         l[15]>0 and l[16]<=7 and l[17:19]==[0,0]and l[19]in(0,1),
         'actual lifecycle quiet with every physical publication and close call accounted')
    need(l[7]>0 and 0<l[8]<=loader['generations'] and l[9]>0 and
         0<l[10]<=parsed['oneshot']['retained_records'],
         'last pair lifecycle epoch is retained evidence, not current mapping authority')
    pages=[]
    for index,s in enumerate(p['slots']):
        if s==[0]*26:continue
        need(s[0]in(0,1)and s[1]==s[0]==int(s[16]==0)and s[2]==index and
             0x200000000<=s[4]<=MASK-8192 and s[4]==s[3]&~4095 and
             s[5]>0 and s[6]>0 and s[7]%4096==0 and s[9:12]==[1,5,1],
             'retained exact source identity and original publication/policy disposition')
        need(s[12]in(0,14)and s[13]in(0,14)and s[14]==s[15]==s[12]+4096+s[13]and
             s[16]<=7 and s[17]<=0x7fffffff and s[18]&15==15 and s[19:22]==[1,1,0]and
             s[7]<=s[24] and 4096<=s[24]-s[7] and s[25]&0o170000==0o100000,
             'whole source page plus real halos, exact seals/stat/extent observations')
        need(s[4]not in pages,'retained source slots describe distinct actual pages');pages.append(s[4])
    need(r[0]==1 and r[1]in(0,1)and r[2:9]==[0]*7 and r[9:11]==[pid,pid]and
         r[11]==r[16]==seeds and r[12]==n['admissions'] and
         r[13]==r[14]==extensions+closed+retried and
         r[15]==extensions+2*(policy+capacity)+refault+retried,
         'every actual rseq pair seed, ingress, refresh and close has its source-defined count')
    need(r[22:25]==[0,0,0]and r[29:31]==r[31:33]and
         all(x<1<<16 for x in r[29:]),
         'all observed publication words are zero and actual helper selectors unchanged')
    # Native execution may change TLS bases. Compare only the helper's retained
    # selectors here; the finite retry oracle checks its stronger before/after.
    need(r[17]<=parsed['rseq']['owner'][13],'retained registration epoch cannot be from the future')
    if r[1]:
        need(0<r[17]and 0<r[18]<=MASK-32 and r[18]&31==0 and
             r[19]==r[18]&~4095 and r[20]==32 and r[21]<1<<32,
             'actual retained registered pair address, page, length and signature')
        before,after=p['pin_before'],p['pin_after']
        need(before==after and before[0]>0 and before[1]>0 and before[2]%4096==0 and
             before[3:]==[1,1,0],'same complete actual pinned allocation/generation through close')
        if r[17]==parsed['rseq']['owner'][13]:
            need(r[18:22]==parsed['rseq']['owner'][9:13] and
                 parsed['rseq']['identity']==[1]+before[:3],
                 'same registration epoch joins the original rseq owner and actual pin identity')
    else:
        need(r[18:25]==[0]*7 and p['pin_before']==p['pin_after']==[0]*6,
             'unregistered pair has no invented pin or publication-word observation')
    close=p['close']
    need(close[0]>=l[14]>0 and close[1:7]==[0]*6 and close[7:]==[1,0,0,0],
         'actual terminal exit performs a complete zero-page close after pair retirement')
    need(parsed['rseq_native']['attempts']==0 and parsed['rseq_boundary']['counts']==[0]*6,
         'old registered-native and one-page retry owners are unused, never synthesized')
    return dict(events=events,seeds=seeds,extensions=extensions,epochs_closed=closed,
        one_page_closes=one,two_page_closes=two,policy_closes=policy,capacity_closes=capacity,
        refaults=refault,refault_completed=retried,physical_pages=n['admissions'],
        rseq_entries=r[14],rseq_refreshes=r[15],last_registration_epoch=r[17])

def pair_controls(stderr,args,workload, *, chain_closure=None):
    accepted,_=check(stderr,*args,workload=workload,chain_closure=chain_closure);actual_hash=H(stderr)
    p=accepted['native_pair']
    cases=[('pair_live','control',6,1),('pair_pending','control',7,1),
        ('pair_closed','counts',3,p['counts'][3]+1),('pair_two_closes','counts',5,p['counts'][5]+1),
        ('pair_refault','counts',9,p['counts'][9]+1),('pair_publications','lifecycle',12,p['lifecycle'][12]+1),
        ('pair_close_calls','lifecycle',14,p['lifecycle'][14]+1),('pair_rseq_active','rseq',2,1),
        ('pair_rseq_refresh','rseq',15,p['rseq'][15]+1),('pair_word','rseq',24,1),
        ('pair_pin_complete','pin_after',4,0 if p['pin_after'][4]else 1),
        ('pair_close_complete','close',7,0),('pair_nx_code','last_nx',1,1)]
    for slot,s in enumerate(p['slots']):
        if s!=[0]*26:
            cases.extend((('pair_slot_allocation','slots',(slot,5),0),
                ('pair_slot_generation','slots',(slot,6),0),
                ('pair_slot_window','slots',(slot,15),s[15]-1),
                ('pair_slot_seals','slots',(slot,18),0)))
            break
    names=[]
    for name,key,index,value in cases:
        changed=copy.deepcopy(p)
        target=changed[key][index[0]]if type(index)is tuple else changed[key]
        at=index[1]if type(index)is tuple else index
        need(target[at]!=value,'actual supplied pair mutation '+name);target[at]=value
        lines=stderr[:-1].split(b'\n');prefix=b'LI2_NATIVE_PAIR '
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one exact native-pair report')
        lines[places[0]]=prefix+json.dumps(changed,separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:check(b'\n'.join(lines)+b'\n',*args,workload=workload,chain_closure=chain_closure)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    original=stderr[:-1].split(b'\n');prefix=b'LI2_NATIVE_PAIR '
    index=next(i for i,line in enumerate(original)if line.startswith(prefix))
    for name,changed in(('pair_missing_row',original[:index]+original[index+1:]),
                         ('pair_duplicate_row',original[:index]+[original[index]]+original[index:])):
        refused=False
        try:check(b'\n'.join(changed)+b'\n',*args,workload=workload,chain_closure=chain_closure)
        except ValueError:refused=True
        need(refused,'complete actual row order refuses supplied '+name);names.append(name)
    need(H(stderr)==actual_hash,'original complete pair stderr remains unchanged')
    return names


def reports(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete actual stderr')
    lines=stderr[:-1].split(b'\n');parts=[line.partition(b' ')for line in lines]
    names=[p[0]for p in parts];order=['LI2_'+x for x in ORDER]
    if b'LI2_REPEAT'in names:order.insert(4,'LI2_REPEAT')
    order.insert(order.index('LI2_ONESHOT'),'LI2_REPEAT_LEASE')
    order.insert(1,'LI2_NATIVE_PAIR')
    need(names==[s.encode()for s in order]and all(p[1]==b' 'and 0<len(line)+1<=4096 and b'\r'not in line for p,line in zip(parts,lines)),
         'exact bounded report order with no duplicate or unrecognized rows')
    values={name:rseq.decode(raw)for name,_,raw in parts}
    loader,native=values[b'LI2_LOADER'],values[b'LI2_NATIVE']
    pair=values[b'LI2_NATIVE_PAIR'];pair_schema(pair)
    run,c,registration=(values[k]for k in(b'LI2_RUN',b'LI2_CHAIN',b'LI2_RSEQ'))
    repeat=values.get(b'LI2_REPEAT')
    rep_lease=values[b'LI2_REPEAT_LEASE']
    _unsigned(rep_lease,set(LEASE_SCALARS),LEASE_ARRAYS)
    need(list(rep_lease)==LEASE_SCALARS+list(LEASE_ARRAYS) and rep_lease['version']==1,
         'exact ordered distinct REP lease row, not an old-cycle report')
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
         native['main_admissions'] <= native['admissions'] and native['main_refaults'] <= pair['counts'][8],
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
    for row in (run, c, registration, trace, reuse, rep_lease, pair)+(() if repeat is None else (repeat,)):
        need(all(row[k] == loader[k] for k in ZERO), 'same actual outcome in every old report')
    need(rep_lease['route']==loader['step_route'] and rep_lease['pending']==run['pending'],
         'same genuine terminal route and pending state in REP lease')
    parsed=dict(loader=loader,native=native,native_pair=pair,repeat=repeat,repeat_lease=rep_lease,run=run,chain=c,rseq=registration,
        lease={k:c[k]for k in lease.EXTRA},trace_run=trace,reuse=reuse,**extension)
    return parsed


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


def ls_gate(p,pid,exit_code,parent, *, chain_closure=None):
    # Preserve the original LS-specific Q/chain/rseq closure as well.
    if exit_code==0:shared.rseq_completed(p['loader'],p['repeat'],p['run'],p['chain'],p['rseq'],pid,p['reuse'],chain_closure=chain_closure)
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
        boundary_completed(p,pid,0,chain_closure=chain_closure)  # Same native/rseq/chain guards; explicit generation-aware cache closure.
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
        try: boundary_completed(p,pid,0,chain_closure=chain_closure)
        except ValueError: refused = True
        need(refused, 'unchanged completed rejects failed operation')
    return o,p,dict(application_completed=completed,gate_result_validations=x[11],
        attempts=x[7],permitted=x[8],issued=x[9],returned=x[10],invalidated=x[1],
        tcgets_result_validations=commands[0],tiocgwinsz_result_validations=commands[1],last_command=commands[2],
        gate_phase=x[2],gate_first_error=x[3],gate_first_detail_abs=x[4],
        last_result_abs=q[5],last_result_negative=q[6],failure_code=o['failure_code'],
        detail_abs=o['detail_abs'],detail_negative=o['detail_negative'],
        original_completed_rejected=not completed)


def check(stderr,pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,*,workload, chain_closure=None):
    need(workload in('ls','hot'),'exact explicit workload profile')
    need(type(exit_code)is int and exit_code==0,'actual successful process required')
    p=reports(stderr);extensions(p)
    _,same,gate_summary=(ls_gate(p,pid,exit_code,parent,chain_closure=chain_closure)if workload=='ls'else gate(p,pid,exit_code,parent,0,chain_closure=chain_closure))
    need(same is p,'original actual report values retained')
    lease_summary=lease.counters(p);effect_exit(p)
    trace_summary=trace_completed(p)
    binding=external_source(p,images,image_bytes,carrier,carrier_bytes)
    retained=lease_completed(p,pid,binding,images,carrier)
    legacy=legacy_source(p,images,image_bytes)if workload=='hot'else None
    n=p['native'];e=p['effect'];o=p['oneshot']
    return p,dict(native_pair=pair_completed(p,pid),application_completed=True,default_rseq_registered=True,cache_reuse=reuse_completed(p['run'],p['reuse']),gate=gate_summary,lease=lease_summary,trace_run=trace_summary,repeat_lease=retained,repeat_lease_source=binding,legacy_repeat_source=legacy,
        selected=dict(attempts=e['attempts'],completed=e['completed'],classes=e['classes'],unreturned_exit=1),
        publication={k:o[k]for k in('attempted','published','restored','completed','retired','refused','cpuid_patches','syscall_patches','rdtsc_patches','rseq_attempts','rseq_retired','retained_records','generations')},
        native={k:n[k]for k in('attempts','admissions','closed','blocked','epoch_exits','refaults','main_admissions','main_refaults')},
        admission_timing=dict(first_admission_ns=n['first_admission_ns'],first_source_offset=n['first_source_offset'],revisit_count=n['revisit_count'],revisit_ns=n['revisit_ns']))


def supplied_controls(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes,*,workload, chain_closure=None):
    """Run only after this exact genuine report passed; no additional subject."""
    accepted, _ = check(stderr, pid, exit_code, parent, images, image_bytes, carrier, carrier_bytes,workload=workload,chain_closure=chain_closure)
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
    rr=accepted['repeat_lease']
    cases+=(
        ('lease_literal','repeat_lease','request',5,rr['request'][5]^1),
        ('lease_following_byte','repeat_lease','request',5,rr['request'][5]^(1<<16)),
        ('lease_next_pc','repeat_lease','request',1,rr['request'][1]+1),
        ('lease_source_offset_alignment','repeat_lease','source',3,rr['source'][3]+1),
        ('lease_source_allocation_zero','repeat_lease','source',1,0),
        ('lease_two_page','repeat_lease','request',7,2),
        ('lease_available','repeat_lease','request',4,1),
        ('lease_progress','repeat_lease','frames',10,rr['frames'][10]^4),
        ('lease_close','repeat_lease','closes',None,rr['closes']+1),
        ('lease_retained','repeat_lease','retained',None,rr['retained']+1),
        ('lease_release','repeat_lease','release',1,0),
        ('lease_revoke','repeat_lease','io',3,0),
        ('lease_final_query','repeat_lease','query',3,0),
        ('lease_ticket','repeat_lease','custody',4,1),
        ('lease_event_count','repeat_lease','custody',10,rr['custody'][10]+1),
        ('lease_return_count','repeat_lease','custody',14,rr['custody'][14]+1),
        ('lease_epoch','repeat_lease','custody',8,rr['custody'][8]+1),
        ('lease_borrow','repeat_lease','borrow',1,1),
        ('lease_rseq_checks','repeat_lease','progress',11,rr['progress'][11]+1),
        ('lease_write_checks','repeat_lease','writes',0,rr['writes'][0]+1),
        ('lease_registration','repeat_lease','registration',10,rr['registration'][10]+1),
        ('lease_seals','repeat_lease','backing',2,0),
        ('lease_elf_size','repeat_lease','backing',8,rr['backing'][8]+1),
        ('lease_event_kind','repeat_lease','event',7,1),
        ('lease_event_complete','repeat_lease','event',8,0),
    )
    if workload=='hot'and accepted['repeat']is not None:
        cases+=(('legacy_rep_captured_byte','repeat','request',5,accepted['repeat']['request'][5]^(1<<16)),
                ('legacy_rep_file_page','repeat','source0',3,accepted['repeat']['source0'][3]+1))
    names=[]
    for name, key, field, index, value in cases:
        changed=copy.deepcopy(accepted[key])
        before=changed[field]if index is None else changed[field][index]
        need(before!=value, 'supplied mutation actually changes '+name)
        if index is None:changed[field]=value
        else:changed[field][index]=value
        prefix={"reuse":b'LI2_RUN_REUSE ',"run":b'LI2_RUN ',"repeat_lease":b'LI2_REPEAT_LEASE ',"repeat":b'LI2_REPEAT '}[key]
        lines=stderr[:-1].split(b'\n')
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1, 'one exact original mutation target')
        lines[places[0]]=prefix+json.dumps(changed,sort_keys=key!='repeat_lease',separators=(',',':'),allow_nan=False).encode()
        refused=False
        try:check(b'\n'.join(lines)+b'\n',pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,workload=workload,chain_closure=chain_closure)
        except ValueError:refused=True
        need(refused, 'same complete reader refuses supplied '+name)
        names.append(name)
    # Supplied external-input changes exercise the limited byte join, not
    # actual native events or changes to the retained production evidence.
    binding=external_source(accepted,images,image_bytes,carrier,carrier_bytes)
    for name in ('external_instruction_byte','external_duplicate_candidate'):
        altered_images=copy.deepcopy(images);altered_bytes=list(image_bytes)
        if name=='external_instruction_byte':
            i=binding['module'];data=bytearray(altered_bytes[i]);data[binding['file_offset']]^=1
            altered_bytes[i]=bytes(data);altered_images[i]['sha256']=H(altered_bytes[i])
        else:
            altered_images.append(copy.deepcopy(images[binding['module']]))
            altered_bytes.append(image_bytes[binding['module']])
        refused=False
        try:check(stderr,pid,exit_code,parent,altered_images,altered_bytes,carrier,carrier_bytes,workload=workload,chain_closure=chain_closure)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied '+name);names.append(name)
    changed_carrier=dict(carrier,bytes=carrier['bytes']+1);refused=False
    try:check(stderr,pid,exit_code,parent,images,image_bytes,changed_carrier,carrier_bytes,workload=workload,chain_closure=chain_closure)
    except ValueError:refused=True
    need(refused,'same complete reader refuses supplied mismatched carrier extent');names.append('carrier_extent')
    legacy=legacy_source(accepted,images,image_bytes)if workload=='hot'else None
    if legacy is not None:
        altered_images=copy.deepcopy(images);altered_bytes=list(image_bytes)
        i=legacy['module'];data=bytearray(altered_bytes[i]);data[legacy['file_offset']]^=1
        altered_bytes[i]=bytes(data);altered_images[i]['sha256']=H(altered_bytes[i])
        refused=False
        try:check(stderr,pid,exit_code,parent,altered_images,altered_bytes,carrier,carrier_bytes,workload=workload,chain_closure=chain_closure)
        except ValueError:refused=True
        need(refused,'same complete reader refuses supplied legacy external instruction byte')
        names.append('legacy_external_instruction_byte')
    names.extend(pair_controls(stderr,(pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes),workload,chain_closure=chain_closure))
    need(hashlib.sha256(stderr).hexdigest()==actual_hash, 'actual report bytes unchanged')
    return dict(scope='supplied-reader mutations after actual completion',actual_subjects=0,
        original_stderr_sha256=actual_hash,refusals=names,native_qualification_credit=False)
