"""Exact terminal contract for the separate paired-v2 loader-loop fixture.

This fixture has no REP or rseq call. Their exact untouched states are checked;
the existing exercised REP/native-probe PF cohort remains a separate mandatory
prerequisite. No old profile, row, outcome, check or qualification is rewritten.
"""
import copy
import json
from page_selected import need
import persistent_fused_reports as prior
import persistent_fused_refusal_reports as pf
import persistent_loop_counter_terminal as loop
from page_selected_repeat_lease_app_reports import LEASE_SCALARS, LEASE_ARRAYS
from persistent_dynamic_reports import rseq
H=prior.H
CONTROL_COUNT=335


def effect_exit(p):
    # Same paired-v2 binary: identity3 + hardware2 + prefix-machine3 +
    # mappings8 + prefix-write1 + pre-entry-machine3 + post-machine3 +
    # getcpu1 + source-mprotect1 + munmap3 + suffix-write1 + exit_group1.
    # The original interpreter and hardware() issue1+67 CPUIDs.
    calls=30
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']==231 and l['source_syscalls']==l['syscalls']==l['forwarded']==calls,'exact tiny fixture successful exit syscall path')
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
    need(o['published']==1 and o['attempted']==o['published']==o['restored']==o['effect_started']==o['backend_prepared']==l['source_patches']and
         o['completed']==o['retired']==o['effect_returned']==o['backend_completed']==o['last_completed_sequence']==o['published'] and
         o['refused']==o['resetting']==o['last_refused_sequence']==o['rseq_error']==0 and o['active_phase']==0 and
         o['rseq_phase']==0 and o['rseq_attempts']==o['published']and o['rseq_retired']==o['retired'],
         'sole interpreter CPUID patch restored completed and retired before direct exit')
    need([o['cpuid_patches']+67,o['syscall_patches']+calls,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0 and
         [o[k]for k in('cpuid_patches','syscall_patches','rdtsc_patches')]==[1,0,0]and
         all(l[k]==0 for k in('rdrand','rdseed','rdpid','rdtsc','rdtscp')),
         'exact tiny fixture publication and unpatched class accounting')
    need(e['attempts']==o['published']+67+calls,
         'complete fixed application direct-effect partition')
    # Retain the original general generation bound, then bind this one-page
    # interpreter-entry CPUID (first two bytes, no page straddle).
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(generation_delta==2,'exact one-page interpreter CPUID generation advances')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')


def effect_terminal(p):
    # Real returning prefix before copied CMP/MOVZX: identity3 + hardware2 +
    # prefix-machine3 + mappings8 + prefix-write1 + pre-entry-machine3.
    calls=20
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']==158 and l['source_syscalls']==l['syscalls']==l['forwarded']==calls,
         'exact paired pre-read returning syscall prefix')
    need(all(e[k]==v for k,v in dict(first_error=0,stage=8,busy=0,finished=1,kind=7,action=1,phase=9,error=0,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=1,exit_entered=0,
        post_guards_complete=1,post_callback_entered=0,post_callback_returned=0,committed=1,
        random_backend_returned=0,random_backend_status=0,raw_entered=1,raw_returned=1).items()),
        'literal completed last getter before terminal copied read; no nonreturning exit claim')
    need(0<e['pc']<=(1<<64)-3 and e['next_pc']==e['pc']+2 and
         512<=e['fp_bytes']==e['fp_before_initialized']==e['fp_after_initialized']<=65536 and
         e['sequence']==e['attempts']==e['completed']==e['commits']==e['native_completed'] and
         e['scripted_completed']==0 and e['classes']==[l['cpuid'],l['rdrand'],l['rdseed'],l['rdpid'],l['rdtsc'],l['rdtscp'],l['syscalls']]and
         sum(e['classes'])==e['completed'],'every actual returning effect accounted before the generated fault')
    need(o['published']==1 and o['attempted']==o['published']==o['restored']==o['effect_started']==o['backend_prepared']==l['source_patches']and
         o['completed']==o['retired']==o['effect_returned']==o['backend_completed']==o['last_completed_sequence']==o['published'] and
         o['refused']==o['resetting']==o['last_refused_sequence']==o['rseq_error']==0 and o['active_phase']==0 and
         o['rseq_phase']==0 and o['rseq_attempts']==o['published']and o['rseq_retired']==o['retired'],
         'sole interpreter CPUID patch restored completed and retired before direct exit')
    need([o['cpuid_patches']+67,o['syscall_patches']+calls,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0 and
         [o[k]for k in('cpuid_patches','syscall_patches','rdtsc_patches')]==[1,0,0]and
         all(l[k]==0 for k in('rdrand','rdseed','rdpid','rdtsc','rdtscp')),
         'exact tiny fixture publication and unpatched class accounting')
    need(e['attempts']==o['published']+67+calls,
         'complete fixed application direct-effect partition')
    # Retain the original general generation bound, then bind this one-page
    # interpreter-entry CPUID (first two bytes, no page straddle).
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(generation_delta==2,'exact one-page interpreter CPUID generation advances')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')


def registration_prefix(loader,r,pid,mode):
    need(type(mode)is int and 0<=mode<7 and loader['rseq']==0 and
         r['owner'][:4]==[1,0,0,0] and r['owner'][9:14]==[0]*5 and r['counts']==[0]*9,
         'paired fixture makes no registration call; exact initialized untouched lifecycle')
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


def probe_partition(p,l,n,d,c,q,status,code,detail):
    need((status,code,detail)in((0,0,0),(125,3304,11))and p['version']==1 and p['errors']==0 and
         all(row[k]==value for row in(p,l,d,c,q)for k,value in
             (('status',status),('failure_code',code),('detail_abs',detail),('detail_negative',0)))and
         n['status']==status and n['failure_code']==code,'actual paired terminal outcome in every probe row')
    need(p['pending']==0 and p['outcome_result_negative']==0,'native-probe completion has no pending or negative outcome')
    # These are different real refusal classes. Never inflate relocation
    # counts or rewrite a supplied old row to account for a GRAPH retry.
    need(l['refaults']<=l['refusals'][3],'native-probe preserves relocation refault class')
    need(p['refaults']<=l['refusals'][2],'native-probe refaults are actual graph refusals')
    need(p['lookups']==p['current_declines']+p['negative_hits']+p['policy_checks'],
         'native-probe lookup partition')
    need(p['policy_checks']==p['policy_blocked']+p['chosen'],'native-probe policy partition')
    need(p['chosen']==p['refaults']==p['next_nx']==p['admitted']+p['refused'],
         'native-probe real refault and NX outcome partition')
    need((not p['chosen']and p['outcome_complete']==p['outcome_result_abs']==0)or
         (p['chosen']>0 and p['outcome_complete']==1 and p['outcome_result_abs']in(0,1)and
          p['refused'if p['outcome_result_abs']==0 else'admitted']>0),
         'native-probe last actual outcome')
    need(p['admitted']<=n['admissions'] and p['admitted']<=q['counts'][1]<=q['counts'][0] and
         p['refused']<=q['counts'][0]-q['counts'][1] and p['next_nx']<=l['signals'][0],'native-probe outcomes join actual native and NX counters')
    need(l['offers']==l['closed']==l['entries']+l['resumed']+l['refaults']+p['refaults'],
         'native-probe exact linked offer partition')
    need(c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries'] and c['sequence']==c['trace_entries']and
         c['nx_entries']==c['fallbacks']+l['entries']+l['refaults']+p['refaults']+d['entries']and
         c['trace_entries']+c['fallbacks']<=c['preparations']<=2*(c['trace_entries']+c['fallbacks'])and
         c['releases']==c['preparations']+c['nx_entries'],
         'native-probe exact ordinary chain partition')
    return dict(p)


def repeat_idle(p):
    need(p['repeat'] is None,'paired source has no ordinary REP instruction')
    row=p['repeat_lease'];expected={key:0 for key in LEASE_SCALARS}
    expected.update(version=1,**{key:p['loader'][key] for key in
        ('status','failure_code','detail_abs','detail_negative')})
    expected.update({key:[0]*size for key,size in LEASE_ARRAYS.items()})
    expected['owner'][13]=1
    expected['custody'][0]=1
    need(row==expected,'whole initialized unused REP owner, custody and zero event history')
    return dict(attempts=0,completed=0,queries=0,source_exercised=False)


def parse(stderr,lane):
    new,original=loop.split(stderr)
    refusal,_=pf.split(original)
    subentry,without=prior.subentry_split(original)
    native_probe,original_stream=prior.probe_row_split(without)
    group,suffix=prior.split(original_stream);linked,linked_reuse,suffix=prior.prior.split(suffix)
    scalar,scalar_reuse,suffix=prior.reuse.split(suffix);u,suffix=prior.unrolled.split(suffix)
    cur,suffix=prior.current.split_current(suffix);view,original=prior.maps_view.split_report(suffix,lane)
    parsed=prior.old.reports(original);prior.old.extensions(parsed)
    parsed.update(group=group,linked=linked,linked_reuse=linked_reuse,scalar_region=scalar,
        scalar_reuse=scalar_reuse,unrolled=u,current_tf=cur,subentry=subentry,native_probe=native_probe,
        pf_refusals=refusal,loop_runtime=new)
    return parsed,view


def validate(p,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,
             owner,owner_reader,mode,application):
    need(type(mode)is int and 0<=mode<7 and application['mode']==owner['mode']==mode and
         application['lane']==1 and application['placement']==owner['placement'],
         'actual same paired-v2 case and placement')
    failed=mode>=5;status=125 if failed else 0;code=3304 if failed else 0;detail=11 if failed else 0
    need(type(exit_status)is int and exit_status==status and
         (owner['status'],owner['code'],owner['detail'])==(status,code,detail),
         'only actual complete zero or before-effect copied-read125 outcome')
    for name in('loader','group','linked','linked_reuse','scalar_region','scalar_reuse','unrolled','current_tf'):
        need(all(p[name][k]==value for k,value in
             (('status',status),('failure_code',code),('detail_abs',detail),('detail_negative',0))if k in p[name]),
             'same actual paired outcome '+name)
    terminal=owner_reader.terminal(p['group'],owner)
    subentry=owner_reader.subentry_terminal(p['subentry'],owner)
    refusal=owner_reader.pf_terminal(p['pf_refusals'],owner)
    new=owner_reader.loop_terminal(p['loop_runtime'],owner)
    gate=prior.gate_prefix(p,pid,exit_status,parent)
    registration_prefix(p['loader'],p['rseq'],pid,mode)
    machine=application['machine'];before=owner['attempt']['before']
    need(application['header'][4:8]==(mode,0,pid,pid)and type(machine)is tuple and len(machine)==8 and
         machine[1:3]==(0,0)and (before['fs'],before['gs'])==machine[1:3]and
         p['rseq']['tls']==[1,1,0,0,0,0,*machine[1:3]],
         'whole actual paired application, protected ingress and terminal unregistered TLS')
    (effect_terminal if failed else effect_exit)(p)
    return dict(application_completed=int(not failed),required_terminal_negative=int(failed),
        mode=mode,placement=application['placement'],status=status,code=code,signal=detail,
        generated_completed=int(not failed),terminal_join=terminal,subentry=subentry,pf_refusals=refusal,
        loop_runtime=new,gate=gate,maps_view=view,repeat_lease=repeat_idle(p),
        native_probe=probe_partition(p['native_probe'],p['linked'],p['native'],p['group'],p['chain'],
                                     p['native_pair'],status,code,detail),
        native_probe_exercise_credit=False,REP_exercise_credit=False,
        input_authentication=prior.prior.cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),
        whole_profile_qualified=False,legacy_protected_rows=False,performance_credit=False)


def check(stderr,*args,lane):
    need(lane in('maintained','differential'),'exact paired maintained/differential lane')
    parsed,view=parse(stderr,lane)
    return parsed,validate(parsed,view,*args)


def controls(stderr,*args,lane):
    parsed,view=parse(stderr,lane);validate(parsed,view,*args)
    refused=[]
    def reject(name,fn):
        try:fn()
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied paired terminal mutation '+name)
    def changed(row,key,index=None,value=None):
        p=copy.deepcopy(parsed)
        if index is None:p[row][key]=p[row][key]^1 if value is None else value
        else:p[row][key][index]^=1
        reject(row+'_'+key+(''if index is None else '_'+str(index)),lambda:validate(p,view,*args))
    for row in('group','subentry','pf_refusals','loop_runtime','native_probe','repeat_lease'):
        for key,value in parsed[row].items():
            if type(value)is int:changed(row,key,value=2 if row=='native_probe'and key=='outcome_result_abs'else None)
            else:
                need(type(value)is list and all(type(v)is int for v in value),'literal numeric terminal controls')
                for index in range(len(value)):changed(row,key,index)
    effect_fields=(('effect','sequence',None),('effect','fp_before_initialized',None),
        ('effect','classes',6),('effect','raw_returned',None),('effect','stage',None),
        ('effect','committed',None),('oneshot','cpuid_patches',None),('oneshot','syscall_patches',None),
        ('oneshot','retired',None),('loader','last_syscall',None),('loader','source_syscalls',None),
        ('loader','generations',None))
    for row,key,index in effect_fields:changed(row,key,index)
    for key,index in(('counts',0),('owner',3),('owner',13),('args',2),('tls',6),('tls',7)):
        changed('rseq',key,index)
    # Every malformed stream re-enters the complete parser; no normalized row
    # or zero-filled placeholder can stand in for the actual bytes.
    lines=stderr[:-1].split(b'\n')
    for index,prefix in enumerate((b'LI2_LOOP_RUNTIME ',b'LI2_PF_REFUSALS ',
                                  b'LI2_PERSISTENT_SUBENTRY ',b'LI2_PERSISTENT_UNREGISTERED ')):
        pos=next(i for i,line in enumerate(lines)if line.startswith(prefix))
        for kind,value in(('missing',b'\n'.join(lines[:pos]+lines[pos+1:])+b'\n'),
            ('duplicate',b'\n'.join(lines[:pos]+[lines[pos]]+lines[pos:])+b'\n'),
            ('version',stderr.replace(prefix+b'{"version":1,',prefix+b'{"version":0,',1))):
            need(value!=stderr,'causal terminal parser control')
            reject('stream_'+str(index)+'_'+kind,lambda value=value:check(value,*args,lane=lane))
    reject('stream_truncated',lambda:check(stderr[:-1],*args,lane=lane))
    # Existing maps schema/equations still run on both maintained and fresh-read
    # differential streams, including every mismatch and enabled-mode predicate.
    for key,value in(('version',2),('enabled',0),('differential',int(lane!='differential')),
        ('poisoned',1),('reserved',1),('mismatches',1),('queries',view['queries']+1),
        ('comparisons',view['comparisons']+1),('hits',0),('refreshes',0)):
        v=dict(view);v[key]=value;changed_lines=list(lines)
        changed_lines[0]=prior.maps_view.PREFIX+json.dumps(v,separators=(',',':'),allow_nan=False).encode()
        candidate=b'\n'.join(changed_lines)+b'\n';need(candidate!=stderr,'causal maps terminal mutation')
        reject('maps_'+key,lambda candidate=candidate:check(candidate,*args,lane=lane))
    need(len(refused)==len(set(refused))==CONTROL_COUNT,'whole fixed paired terminal refusal population')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))
