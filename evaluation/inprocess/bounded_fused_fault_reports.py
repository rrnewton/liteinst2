"""Typed terminal prefixes for two PF MOV negatives; never successful completions.

The mode0 report reader and every old control remain untouched. The prior REP,
native-probe and returning effects remain complete; only the focal generated
MOV ends in the separately authenticated 125/PE_EVENT outcome.
"""
import persistent_fused_refusal_reports as pf_refusals
import copy,json
from page_selected import need
import persistent_direct_frontier_reports as prior
from persistent_dynamic_reports import rseq
H=prior.H
CONTROL_COUNT=92

def effect_terminal(p):
    # Exactly the returning prefix before the first generated MOV: identity3,
    # hardware2, prefix-machine3, mappings5, prefix-write1, pre-entry-machine3.
    calls=17
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']==158 and l['source_syscalls']==l['syscalls']==l['forwarded']==calls,
         'exact PF pre-store returning syscall prefix')
    need(all(e[k]==v for k,v in dict(first_error=0,stage=8,busy=0,finished=1,kind=7,action=1,phase=9,error=0,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=1,exit_entered=0,
        post_guards_complete=1,post_callback_entered=0,post_callback_returned=0,committed=1,
        random_backend_returned=0,random_backend_status=0,raw_entered=1,raw_returned=1).items()),
        'literal completed last getter before terminal MOV; no nonreturning exit claim')
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
    need(type(mode)is int and mode in(1,2) and loader['rseq']==0 and
         r['owner'][:4]==[1,0,0,0] and r['owner'][9:14]==[0]*5 and r['counts']==[0]*9,
         'PF fault occurs before any registration call; exact initialized untouched lifecycle')
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


def probe_prefix(p,l,n,d,c,q,signal):
    need(all(row[k]==value for row in(p,l,d,c,q) for k,value in
             (('status',125),('failure_code',3304),('detail_abs',signal),('detail_negative',0)))and
         n['status']==125 and n['failure_code']==3304 and p['errors']==0,
         'actual failed PF outcome on each typed native-probe row')
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
    need(p['admitted']>0,'actual prior finite native-probe admission exercised before PF failure')
    return dict(p)


def repeat_prefix(p,pid,images,image_bytes,carrier,carrier_bytes,owner,application,image):
    result=prior._repeat_completed_positive(p,pid,images,image_bytes,carrier,carrier_bytes,0)
    mode=application['mode'];machine=application['machine'];fs,gs=machine[1:3]
    need(application['header'][4:8]==(mode,0,pid,pid)and mode in(1,2)and
         type(machine)is tuple and len(machine)==8 and fs==gs==0 and
         (owner['attempt']['before']['fs'],owner['attempt']['before']['gs'])==(fs,gs),
         'actual application and protected before-frame TLS before fault')
    need(p['repeat_lease']['registration']==[1,0,0,0,pid,pid,0,0,0,0,0,fs,gs,1]and
         p['rseq']['tls']==[1,1,0,0,0,0,fs,gs],
         'whole prior observed-TLS REP and still-unregistered terminal identity')
    row=p['repeat_lease'];setup=image['repeat_setup'];pc=setup['pc'];destination=setup['destination']
    binding=result['source_binding']
    need(row['request'][:4]==[pc,setup['next_pc'],346,3]and
         row['request'][5]==0xab48f3 and row['request'][6]&0x400==0 and
         setup['count']==8 and setup['width']==8 and setup['value']==0x8877665544332211 and
         row['progress'][0]==8 and row['frames'][2:4]==[8,destination]and
         row['frames'][9:11]==[0,destination+64]and
         result['last_code']==346 and result['last_initial_count']==8 and
         binding['module']==result['source_module']==0 and
         binding['file_offset']==result['source_file_offset']==setup['file_offset']and
         binding['emitted_bytes']=='f348ab'and binding['image_sha256']==image['sha256'],
         'actual completed REP is the exact low fixture STOSQ and whole eight-word destination')
    result.update(observed_tls=dict(fs_base=fs,gs_base=gs,protected_before_frames=1),
        registration_scope='before_first_registration_terminal_pf_fault')
    return result


def parse(stderr):
    pf,stderr=pf_refusals.split(stderr)
    subentry,without=prior.subentry_split(stderr)
    native_probe,original_stream=prior.probe_row_split(without)
    group,suffix=prior.split(original_stream);linked,linked_reuse,suffix=prior.prior.split(suffix)
    scalar,scalar_reuse,suffix=prior.reuse.split(suffix);u,suffix=prior.unrolled.split(suffix)
    cur,suffix=prior.current.split_current(suffix);view,original=prior.maps_view.split_report(suffix,'maintained')
    parsed=prior.old.reports(original);prior.old.extensions(parsed)
    parsed.update(group=group,linked=linked,linked_reuse=linked_reuse,scalar_region=scalar,
        scalar_reuse=scalar_reuse,unrolled=u,current_tf=cur,subentry=subentry,native_probe=native_probe)
    parsed['pf_refusals']=pf
    return parsed,view


def validate(p,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode,application,image):
    signal=11 if mode==1 else 4
    need(type(mode)is int and mode in(1,2)and exit_status==125 and owner['status']==125 and
         owner['code']==3304 and owner['detail']==signal and owner['mode']==mode,
         'only explicit PF fault/reject outcome; no successful completion')
    for name in('loader','group','linked','linked_reuse','scalar_region','scalar_reuse','unrolled','current_tf'):
        need(all(p[name][k]==value for k,value in
             (('status',125),('failure_code',3304),('detail_abs',signal),('detail_negative',0))if k in p[name]),
             'actual common failed PF outcome '+name)
    terminal=owner_reader.terminal(p['group'],owner)
    subentry=owner_reader.subentry_terminal(p['subentry'],owner)
    gate=prior.gate_prefix(p,pid,exit_status,parent)
    registration_prefix(p['loader'],p['rseq'],pid,mode)
    effect_terminal(p)
    return dict(required_terminal_negative=1,application_completed=0,generated_completed=0,
        mode=mode,status=125,code=3304,signal=signal,terminal_join=terminal,subentry=subentry,
        gate=gate,maps_view=view,pf_refusals=owner_reader.pf_terminal(p['pf_refusals'],owner),
        native_probe=probe_prefix(p['native_probe'],p['linked'],p['native'],p['group'],p['chain'],p['native_pair'],signal),
        repeat_lease=repeat_prefix(p,pid,images,image_bytes,carrier,carrier_bytes,owner,application,image),
        input_authentication=prior.prior.cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),
        whole_profile_qualified=False,legacy_protected_rows=False)


def check(stderr,*args):
    p,view=parse(stderr);return p,validate(p,view,*args)


def controls(stderr,*args):
    p,view=parse(stderr);validate(p,view,*args);owner,owner_reader,mode=args[-5:-2];refused=[]
    for key,index in [(key,None)for key in prior.SCALARS]+[('misses',i)for i in range(18)]:
        value=copy.deepcopy(p['group'])
        if index is None:value[key]^=1
        else:value[key][index]^=1
        try:owner_reader.terminal(value,owner)
        except ValueError:refused.append('protected_'+key+(''if index is None else '_'+str(index)))
        else:raise ValueError('accepted changed failed protected PF row')
    for key in prior.SUBENTRY_KEYS:
        value=dict(p['subentry']);value[key]^=1
        try:owner_reader.subentry_terminal(value,owner)
        except ValueError:refused.append('subentry_'+key)
        else:raise ValueError('accepted changed failed subentry row')
    for key,row,index in(('sequence','effect',None),('fp_after_initialized','effect',None),
        ('classes','effect',6),('raw_returned','effect',None),('stage','effect',None),
        ('committed','effect',None),('cpuid_patches','oneshot',None),('syscall_patches','oneshot',None),
        ('retired','oneshot',None),('last_syscall','loader',None),('source_syscalls','loader',None),
        ('generations','loader',None)):
        value=copy.deepcopy(p)
        if index is None:value[row][key]^=1
        else:value[row][key][index]^=1
        try:effect_terminal(value)
        except ValueError:refused.append(row+'_'+key)
        else:raise ValueError('accepted changed PF returning effect prefix')
    for key,index in(('counts',0),('owner',3),('owner',13),('args',2)):
        value=copy.deepcopy(p['rseq']);value[key][index]^=1
        try:registration_prefix(p['loader'],value,args[0],mode)
        except ValueError:refused.append('registration_'+key+'_'+str(index))
        else:raise ValueError('accepted changed pre-registration fault prefix')
    lines=stderr[:-1].split(b'\n')
    for name,value in(('missing',b'\n'.join(lines[:-1])+b'\n'),('truncated',stderr[:-1]),
        ('duplicate',stderr+lines[-1]+b'\n'),('version',stderr.replace(prior.PREFIX+b'{"version":1,',prior.PREFIX+b'{"version":0,',1))):
        need(value!=stderr,'causal malformed terminal stimulus')
        try:parse(value)
        except ValueError:refused.append('stream_'+name)
        else:raise ValueError('accepted malformed PF fault terminal stream')
    need(len(refused)==len(set(refused))==CONTROL_COUNT,'all92 separate PF terminal prefix controls')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))
