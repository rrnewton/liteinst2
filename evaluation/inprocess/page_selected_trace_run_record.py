"""Exact original-PC TRACE/run records; no execution or source normalization.

The enclosing evaluator authenticates the ELF, actual DWARF and raw capture.
The old whole-state/startup comparisons are reused without changing them.
"""
from page_selected import need
from page_selected_maps_record import unpack
from page_selected_chain_record import REGS, TF, RF, u, frame, equal_state, live, startup, query

ERRORS=[0,906,906,906,903,709,7]


def zero(value):
    if isinstance(value,dict):return all(zero(x) for x in value.values())
    if isinstance(value,(list,tuple)):return all(zero(x) for x in value)
    if isinstance(value,bytes):return not any(value)
    return value==0


def snapshot(s,layout):
    f=s['state']['frame'];frame(f)
    need(len(f['fp'])==65536 and not any(f['fp'][f['initialized']:]),'entire initialized FP plus zero retained tail')
    uc,si=s['uc'],s['si'];a,b=s['uc_address'],s['si_address']
    need(len(uc)==layout['uc_bytes'] and len(si)==layout['si_bytes'] and a>0 and b>0,
         'complete actual ucontext and siginfo extents')
    def value(raw,name,signed=False):
        at,n=layout[name];need(0<=at<=len(raw)-n,'actual DWARF field range')
        return int.from_bytes(raw[at:at+n],'little',signed=signed)
    at,n=layout['greg']
    need(n==23*8 and f['greg']==[int.from_bytes(uc[at+i*8:at+(i+1)*8],'little',signed=True) for i in range(23)],
         'all raw kernel greg bytes equal retained full frame')
    at,n=layout['mask']
    need(n>=8 and int.from_bytes(uc[at:at+8],'little')==f['mask'] and value(uc,'fp')==f['fp_address'],
         'actual mask and FP pointer, no reconstructed frame')
    need(value(si,'signo',True)==s['signal'] and value(si,'errno',True)==s['error'] and
         value(si,'code',True)==s['code'] and value(si,'address')==s['address'],
         'complete retained siginfo projections')
    regions=((a,uc),(b,si),(f['fp_address'],f['fp'][:f['initialized']]))
    for i,(left,x) in enumerate(regions):
        for right,y in regions[i+1:]:
            first,end=max(left,right),min(left+len(x),right+len(y))
            if first<end:need(x[first-left:end-left]==y[first-right:end-right],
                              'physical UC/siginfo/initialized-FP alias bytes agree')


def event(s,kind,pc,flags,layout):
    snapshot(s,layout);g=s['state']['frame']['greg']
    need(s['error']==0 and u(g[16])==pc and u(g[17])==flags and u(g[18])&0xffff==0x33,
         'actual original PC, whole flags and CS')
    if kind=='nx':
        need((s['signal'],s['code'],s['address'])==(11,2,pc) and g[19:21]==[21,14] and u(g[22])==pc,
             'genuine NX exception at unexecuted original instruction')
    elif kind=='trace':
        need((s['signal'],s['code'],s['address'])==(5,2,pc) and g[19:21]==[0,1],
             'genuine CPU TRACE, never a synthetic NX event')
    else:
        need(kind=='int3' and s['signal']==5 and s['code']==128 and g[19:21]==[0,3],
             'actual native INT3 after the independent instruction interval')


def uc_edit(a,b,layout,greg_index,value):
    need(a['uc_address']==b['uc_address'] and a['si_address']==b['si_address'] and a['si']==b['si'] and
         a['state']['frame']['fp_address']==b['state']['frame']['fp_address'],
         'same genuine handler objects and untouched full siginfo/FP address')
    want=bytearray(a['uc']);at=layout['greg'][0]+greg_index*8
    want[at:at+8]=u(value).to_bytes(8,'little')
    need(b['uc']==want,'whole actual ucontext with exactly its owned register edit')
    need(a['state']['frame']['fp']==b['state']['frame']['fp'] and
         all(a['state'][k]==b['state'][k] for k in ('stack','data','fs','gs')),
         'no hidden FP, private-stack, data or base edit')


def release(p,sequence=None):
    need(p['held']==0 and p['complete']==1 and p['first_error']==0 and p['sequence']>0,
         'actual closed/released borrow')
    if sequence is not None:need(p['sequence']==sequence,'release belongs to exact borrow')


def native(r,layout):
    count=1 if r['mode']==6 else 3;pc,s,g=r['pc'],r['run_pc'],r['guard']
    initial=[(0x123456789abcdef+0x101010101010101*i)&((1<<64)-1) for i in range(16)]
    initial[0]=0x7fffffffffffffff;initial[4]=r['subject_address']+4096
    initial[6]=r['fault_address'] if r['mode']==6 else r['data_address'];initial[7]=r['data_address']+8
    stack=bytes((i*29+11)&255 for i in range(8192));data=bytes((i*17+3)&255 for i in range(4096))
    for i,n in enumerate(r['native'][:count]):
        start=s if i==1 else pc;stop=s if i==0 else g;flags=0xa96 if i==1 else 0x247
        need(n['started']==1 and n['events']==2 and n['start']==start and n['stop']==stop,
             'each independent native interval actually started and observed both endpoints')
        event(n['before'],'nx',start,flags|RF,layout)
        before=n['before']['state'];want=list(initial)
        if i==1:want[0]=0x8000000000000000
        need([u(before['frame']['greg'][x]) for x in REGS]==want and before['stack']==stack and before['data']==data,
             'literal full original inputs and private-memory seeds')
        release(n['released'])
        if r['mode']==6:
            after=n['after'];snapshot(after,layout);f=after['state']['frame']
            need(n['fault']==1 and n['complete']==0 and (after['signal'],after['code'],after['error'],after['address'])==
                 (11,2,0,r['fault_address']) and u(f['greg'][16])==pc and f['greg'][19:21]==[4,14] and
                 u(f['greg'][22])==r['fault_address'] and u(f['greg'][17])==(0x247|RF),
                 'independent native failed memory read, no completed interval')
            equal_state(before,after['state'])
            lane=dict(before=before,after=after['state'],live=n['live'],fp=n['fp'])
            live(lane,lane,[0x247,0x247],r['xsave_bytes'])
        else:
            need(n['complete']==1 and n['fault']==0,'native reference completed without fault')
            event(n['after'],'int3',stop+1,0xa96,layout)
            after=n['after']['state'];want[0]=0x8000000000000000 if i==0 else 0x12345678
            if i:want[1]=0x12345678
            need([u(after['frame']['greg'][x]) for x in REGS]==want and after['stack']==stack and after['data']==data,
                 'independent ADD overflow and dependent MOV literal effect on all sixteen registers')
            need(all(before[k]==after[k] for k in ('fs','gs')) and before['frame']['mask']==after['frame']['mask'] and
                 before['frame']['greg'][18]==after['frame']['greg'][18] and before['frame']['fp']==after['frame']['fp'],
                 'native interval preserves full FP, selectors, bases and mask')
            lane=dict(before=before,after=after,live=n['live'],fp=n['fp'])
            live(lane,lane,[flags,0xa96],r['xsave_bytes'])
    need(all(zero(n) for n in r['native'][count:]),'unexecuted native references have no invented state')
    if count==3:
        p,b,w=r['native'];equal_state(p['before']['state'],w['before']['state'])
        equal_state(p['after']['state'],b['before']['state']);equal_state(b['after']['state'],w['after']['state'])


def handoff(r,l,layout):
    pc,s=r['pc'],r['run_pc'];n=r['native'][0]
    event(l['before'],'nx',pc,0x247|RF,layout);equal_state(l['before']['state'],n['before']['state'])
    event(l['trace'],'trace',s,0xa96|TF,layout);equal_state(l['trace']['state'],n['after']['state'])
    event(l['closed'],'trace',s,0xa96,layout);event(l['input'],'trace',s,0xa96,layout)
    uc_edit(l['trace'],l['closed'],layout,17,0xa96)
    need(l['closed']==l['input'],'prepare/publication/arm preserve the whole actual post-predecessor snapshot')
    c=l['closed_chain'];o=l['offered']
    need(c['initialized']==1 and c['first_error']==c['first_detail']==c['pending']==c['in_handler']==0 and
         not c['entry']['valid'] and o['issued']==1 and o['previous'] in (0,1) and o['next']==c['active']==o['previous']^1 and
         o['event_id']==c['event_id']>0 and o['pc']==s and o['flags']==0xa96 and
         all(o[k]==0 for k in ('consume_attempted','consumed','preflight_skipped','miss_released','run_borrow','result')),
         'actual opaque offer only at closed predecessor/OLD_STEP fallback')
    p,q=c['slots'][o['previous']],c['slots'][o['next']]
    need(p['phase']==5 and q['phase']==6 and q['fallback']==4 and p['generation']==o['previous_generation']>0 and
         q['generation']==o['next_generation']>0 and q['event_id']==o['event_id'],
         'exact prior/successor slot generations and fallback identity')
    for slot,seq in ((p,o['previous_borrow']),(q,o['next_borrow'])):
        need(slot['release']==dict(started=1,complete=1,result=0) and slot['fetch']['ref']['sequence']==seq and
             slot['fetch']['ref']['owner']>0,'both actual source owners and complete release callbacks')
        release(slot['fetch']['progress'],seq)
        need(slot['fetch']['pid']==slot['fetch']['tid']==r['pid'] and slot['fetch']['identity_observed']==1,
             'actual source borrow belongs to recorded singleton')
        at=pc if slot is p else s
        need(slot['fetch']['pc']==at and slot['fetch']['length']==15 and slot['fetch']['page_count']==1 and
             slot['fetch']['bytes']==r['literal'][at-r['mapping']:at-r['mapping']+15] and
             slot['fetch']['pages'][0]['address']==r['mapping'] and
             slot['fetch']['pages'][0]['closed_prot']==1 and slot['fetch']['pages'][0]['logical']==5 and
             slot['fetch']['pages'][0]['allocation']>0 and slot['fetch']['pages'][0]['generation']>0 and
             zero(slot['fetch']['pages'][1]), 'actual whole original held-source copy and one closed page')
    step=p['owner']['step']
    need(step['phase']==5 and not step['first_error'] and step['trace_seen']==1 and
         step['after']==l['trace']['state']['frame'] and p['owner']['actual_post_pc']==s and
         p['owner']['actual_post_flags']==0xa96|TF,'complete original predecessor frame retained in its owner')
    query(p['query'],s)
    need(step['request']['page_count']==1 and step['open_started']==step['opened']==step['revoke_started']==step['revoked']==[1,0] and
         step['open_result']==step['revoke_result']==[0,0] and step['open_sync']==step['revoke_sync']==0 and
         step['revoke_sync_started']==1,'predecessor original source actually opened, synchronized and revoked once')
    need(q['owner']['step']['phase']==0 and q['decoded']['pc']==s and q['decoded']['kind']==0 and
         q['decoded']['step_disposition']==1 and q['prepare_attempted']==q['prepare_complete']==
         q['decode_attempted']==q['decode_complete']==1 and q['prepare_result']==q['decode_result']==0,
         'actual unentered old-step successor, no manufactured source description')
    f=l['fresh'];need(f['held']==f['complete']==1 and f['first_error']==0 and
         o['previous_borrow']<o['next_borrow']<f['sequence'],'strict three distinct predecessor/fallback/fresh borrow lifetimes')
    plan=l['plan'];source=r['literal'][s-r['mapping']:s-r['mapping']+15]
    generated=source[:7]+bytes.fromhex('ff2500000000')+r['guard'].to_bytes(8,'little')
    need(plan['policy']==1 and plan['decoder_result']==0 and plan['pc']==s and plan['stop']==r['guard'] and
         plan['source_length']==15 and plan['source']==source and plan['run_length']==7 and
         plan['instruction_count']==2 and plan['generated_length']==21 and plan['generated']==generated+bytes(8),
         'exact original two-MOV plan and RIP-indirect return to unexecuted original guard')
    a,b=plan['instructions'][:2]
    need((a['offset'],a['length'],a['effect'],a['destination'],a['width'],a['immediate'])==(0,5,1,0,32,0x12345678) and
         (b['offset'],b['length'],b['effect'],b['destination'],b['source'],b['width'])==(5,2,2,1,0,32) and
         all(zero(x) for x in plan['instructions'][2:]),'literal ordered dependent effects and no unused instructions')
    need(q['decoded']['code']==a['code'] and q['decoded']['length']==5 and
         q['decoded']['available']==15 and q['decoded']['bytes']==source+b'\0',
         'descriptive old-step decoder agrees with exact held source and first run instruction')
    need(plan['guard']['pc']==r['guard'] and plan['guard']['next_pc']==r['guard']+2 and plan['guard']['length']==2,
         'actual complete retained noncopied guard')
    pub=l['publication'];need(pub['phase']==2 and pub['first_error']==pub['first_detail']==0 and
         pub['allocation']>0 and pub['generation']>0 and pub['entry']>0 and pub['entry']%4096==0 and
         pub['fill_bytes']==pub['verified_bytes']==4096 and pub['code_bytes']==21 and
         all(pub[k]==1 for k in ('rw_checked','rx_started','rx_complete','sync_started','sync_complete')) and
         all(pub[k]==0 for k in ('rx_result','sync_result','cleanup_started','cleanup_complete','cleanup_sync_started','cleanup_result','cleanup_sync_result')),
         'actual immutable W^X publication, full-page byte verification and sync')


def slot(s,plan,publication):
    need(all(s[k]==1 for k in ('attempted','owner_observed','mapping_observed','bytes_observed','complete')) and
         s['result']==s['callback_result']==s['writable_aliases']==0 and s['actual_prot']==5 and
         s['entry']==publication['entry'] and s['allocation']==publication['allocation'] and
         s['generation']==publication['generation'] and s['mapping_first']<=s['entry'] and
         s['entry']+21<=s['mapping_end'] and s['length']==21 and s['bytes']==plan['generated'],
         'actual full published bytes and private RX identity on each observation')


def completed(r,layout):
    need(r['native_completed']==3 and r['native_faults']==0 and r['completed_runs']==2 and
         r['complete']==1 and r['consume_calls']==2 and all(r[k]==0 for k in
         ('verified_failure','error','detail_abs','detail_negative','supplied_mutations','real_signals','guard_executed')),
         'exact complete genuine miss/hit process, no failed operation credit')
    for j,l in enumerate(r['lanes']):
        handoff(r,l,layout)
        c=l['closed_chain']
        need(c['nx_entries']==c['steps']==c['attempts']==c['fallbacks']==j+1 and c['trace_entries']==0 and
             c['event_id']==8+3*j,'native observations and exact genuine chain/run event chronology')
        need((l['started'],l['complete'],l['nx'],l['trace_events'],l['events'],l['returns'],l['reset'])==(1,1,2,1,3,3,1),
             'one genuine predecessor TRACE and one original guard NX per completed run')
        snapshot(l['redirected'],layout)
        need((l['redirected']['signal'],l['redirected']['code'],l['redirected']['error'],l['redirected']['address'])==
             (5,2,0,r['run_pc']),'redirect retains original real TRACE siginfo without changing its address')
        uc_edit(l['input'],l['redirected'],layout,16,l['publication']['entry'])
        event(l['after'],'nx',r['guard'],0xa96|RF,layout)
        equal_state(l['after']['state'],r['native'][1]['after']['state'])
        equal_state(l['after']['state'],r['native'][2]['after']['state'])
        live(dict(before=l['before']['state'],after=l['after']['state'],live=l['live'],fp=l['fp']),
             dict(live=r['native'][2]['live'],fp=r['native'][2]['fp']),[0x247,0xa96],r['xsave_bytes'])
        expected=dict(l['offered'],consume_attempted=1,consumed=1,run_borrow=l['fresh']['sequence'])
        need(l['consumed']==expected,'once-only genuine consumed proof and exact fresh source sequence')
        o=l['complete_owner'];need(o['phase']==7 and o['first_error']==o['first_detail']==o['failure_notified']==o['in_handler']==0 and
             o['redirected']==o['exit_seen']==o['release_started']==o['release_complete']==1 and
             o['fetch_view_started']==o['fetch_view_complete']==1 and o['release_result']==o['fetch_result']==0 and
             o['plan']==l['plan'] and o['logical_flags']==0xa96 and o['before']==l['input']['state']['frame'] and
             o['after']==l['after']['state']['frame'] and o['borrow']['sequence']==l['fresh']['sequence'] and
             o['page_count']==1 and o['pages']==l['closed_chain']['slots'][l['offered']['next']]['fetch']['pages'] and
             o['backing']==l['closed_chain']['slots'][l['offered']['next']]['fetch']['backing'] and
             zero(o['nested']),'complete entered/returned owner, all before/after kernel FP and GPR bytes')
        need(o['entry_event']==dict(number=5,code=2,error=0,address=r['run_pc'],observed=1) and
             o['exit_event']==dict(number=11,code=2,error=0,address=r['guard'],observed=1),
             'truthful TRACE entry and NX exit stored without relabelling')
        for name in ('armed_slot','entry_slot','exit_slot'):slot(o[name],l['plan'],l['publication'])
        query(o['pre_entry'],r['guard']);query(o['exit_query'],r['guard'])
        release(o['final_fetch'],o['borrow']['sequence']);need(l['final_fetch']==o['final_fetch'],'actual post-release/reset prefix exact')
        need((l['history_before'],l['history_after'])==(j,j+1),'history advances once only after complete exit')
        c=l['published'];need(c==l['finished'] and c['phase']==2 and c['slots_used']==c['complete_slots']==1 and
             c['attempts']==j+1 and c['hits']==j and c['full_misses']==0 and
             all(c[k]==0 for k in ('first_error','first_detail','interrupted','interrupted_again','interrupted_code','interrupted_detail')) and
             c['last_attempt']['hit']==j and c['last_attempt']['complete']==c['last_attempt']['source_complete']==c['last_attempt']['plan_complete']==1 and
             c['last_attempt']['borrow_sequence']==l['fresh']['sequence'] and c['last_attempt']['slot']==0,
             'actual first publication then exact cache hit, no hidden miss or interruption')
    first,last=r['lanes'];h=r['history']
    need(first['publication']==last['publication'] and r['cache']==last['finished'] and zero(r['final_owner']) and
         h['completed_runs']==2 and h['copied_instructions']==4 and h['reset_started']==h['reset_complete']==1 and
         h['first_error']==h['first_detail']==0 and h['last_complete']==last['complete_owner'] and
         r['final_origin']==last['consumed'],'retained immutable publication, complete reset and last exact history')
    release(r['final_fetch'],last['fresh']['sequence'])
    need(r['final_fetch']==last['final_fetch'] and
         r['final_chain']==dict(last['closed_chain'],event_id=last['closed_chain']['event_id']+1) and
         r['final_stats']==r['initial_stats'],'no later hidden source/chain/decoder mutation')


def failed(r,layout):
    mode=r['mode'];l=r['lanes'][0];o=r['final_owner'];detail=5 if mode==5 else 11 if mode==6 else 0
    need(r['verified_failure']==1 and r['complete']==r['completed_runs']==r['detail_negative']==r['guard_executed']==0 and
         (r['error'],r['detail_abs'])==(ERRORS[mode],detail) and zero(r['history']) and zero(r['lanes'][1]) and
         r['supplied_mutations']==int(mode in (1,2)) and r['real_signals']==int(mode==5) and
         r['consume_calls']==(2 if mode==3 else 0 if mode in (5,6) else 1),
         'exact required failed prefix; supplied mutations and real signals remain distinct')
    need(r['native_completed']==(0 if mode==6 else 3) and r['native_faults']==int(mode==6) and
         l['started']==1 and l['complete']==l['reset']==0 and zero(l['live']) and zero(l['fp']) and
         zero(l['after']) and zero(l['redirected']) and zero(l['complete_owner']) and zero(l['consumed']),
         'no completed run, generated entry, exit or live continuation invented on failure')
    if mode==6:
        event(l['before'],'nx',r['pc'],0x247|RF,layout);snapshot(l['trace'],layout)
        n=r['native'][0];equal_state(l['before']['state'],n['before']['state']);equal_state(l['trace']['state'],n['after']['state'])
        f=l['trace']['state']['frame'];nf=n['after']['state']['frame']
        need((l['trace']['signal'],l['trace']['code'],l['trace']['error'],l['trace']['address'])==(11,2,0,r['fault_address']) and
             f['greg'][16]==r['pc'] and f['greg'][19:21]==[4,14] and u(f['greg'][22])==r['fault_address'] and
             u(f['greg'][17])==(u(nf['greg'][17])|TF),
             'genuine predecessor operand fault matches native with owned TF distinction')
        c=r['final_chain'];p=c['slots'][c['active']]
        need(c['first_error']==7 and c['first_detail']==11 and p['phase']==7 and p['unexpected_frame_observed']==1 and
             p['unexpected']==f and not p['owner']['step']['trace_seen'] and
             zero(r['final_origin']) and zero(o) and zero(l['offered']) and zero(l['plan']) and zero(l['publication']),
             'failed predecessor never creates a run offer or publication')
        step=p['owner']['step']
        need(step['request']['page_count']==1 and step['open_started']==step['opened']==step['revoke_started']==step['revoked']==[1,0] and
             step['open_result']==step['revoke_result']==[0,0] and step['open_sync']==step['revoke_sync']==0 and
             step['revoke_sync_started']==1 and r['final_fetch']['held']==1 and
             r['cache']['slots_used']==r['cache']['attempts']==0,
             'actual failed source cleanup, retained borrow and no publication')
        need(l['events']==2 and l['returns']==1 and l['nx']==2 and l['trace_events']==0,'real NX then operand fault, no TRACE')
        return
    handoff(r,l,layout)
    need(l['events']==2 and l['returns']==1 and l['nx']==l['trace_events']==1 and
         o['phase']==8 and o['first_error']==ERRORS[mode] and o['first_detail']==detail and o['failure_notified']==1 and
         o['in_handler']==1 and o['redirected']==o['exit_seen']==o['release_started']==o['release_complete']==0 and
         o['plan']==l['plan'] and o['borrow']['sequence']==l['fresh']['sequence'],
         'run owner stops before redirect and keeps its real armed source/publication')
    slot(o['armed_slot'],l['plan'],l['publication'])
    need(zero(o['entry_slot']) and zero(o['exit_slot']) and zero(o['pre_entry']) and zero(o['exit_query']),
         'no permission/source/continuation success fabricated after rejected origin')
    expected=dict(l['offered'])
    if mode==5:
        s=r['delivered'];snapshot(s,layout)
        at,n=layout['sender_pid'];sender=int.from_bytes(s['si'][at:at+n],'little',signed=True)
        at,n=layout['sender_uid'];uid=int.from_bytes(s['si'][at:at+n],'little')
        need(s['signal']==5 and s['code']==-6 and s['error']==0 and o['after']==s['state']['frame'] and
             o['exit_event']==dict(number=5,code=-6,error=0,address=s['address'],observed=1) and zero(o['before']) and
             zero(o['entry_event']) and sender==r['pid'] and uid==r['uid'],
             'genuine same-process tgkill while armed, not a caller-created trap frame')
    else:
        want=dict(l['input']['state']['frame']);want['greg']=list(want['greg'])
        if mode==2:want['greg'][13]^=1
        need(o['before']==want and o['entry_event']==dict(number=5,code=2,error=0,address=r['run_pc'],observed=1) and
             zero(o['after']) and zero(o['exit_event']) and zero(r['delivered']),
             'actual original TRACE frame retained, with only the explicitly supplied RAX mutation')
        expected['result']=ERRORS[mode]
        if mode!=1:expected.update(consume_attempted=1,run_borrow=l['fresh']['sequence'])
        if mode==3:expected['consumed']=1
    need(r['final_origin']==expected and zero(o['nested']),'exact once-only failed proof advancement')
    need(r['cache']==l['published'] and
         r['final_chain']==dict(l['closed_chain'],event_id=l['closed_chain']['event_id']+int(mode==5)),
         'failure retains original completed predecessor and armed publication without reuse')
    if mode==4:release(r['final_fetch'],l['fresh']['sequence'])
    else:need(r['final_fetch']['held']==1 and r['final_fetch']['sequence']==l['fresh']['sequence'],
              'failed owner retains its real unreleased source prefix')


def check(data,layout,mode,pid):
    need(type(mode)is int and 0<=mode<=6 and set(layout)=={'tr','samples','frame'} and
         layout['samples']['kind']=='array' and layout['samples']['count']==21,'fixed seven-control layout')
    size=layout['tr']['bytes'];need(len(data)==size+layout['samples']['element']['bytes']<16<<20,'whole exact bounded record')
    r=unpack(data,layout['tr']);startup(unpack(data,layout['samples']['element'],size))
    need((r['magic'],r['version'],r['bytes'],r['mode'])==(0x3152554e5446324c,1,size,mode) and
         r['old_refusals']==47 and r['startup_pairs']==1 and r['fixture_failure']==0 and
         r['initial_stats']['phase']==2 and r['xcr0']&3==3 and 576<=r['xsave_bytes']<=65536,
         'fixed record, unchanged old refusal/startup and sealed decoder authority')
    need(type(pid)is int and r['pid']==r['tid']==pid>0 and 0<=r['uid']<=0xffffffff,
         'actual owned process PID joins singleton and sender identity')
    base=r['mapping'];pc=base+128;s=pc+(3 if mode==6 else 4);g=s+7
    need(base>0 and base%4096==0 and (r['pc'],r['run_pc'],r['guard'])==(pc,s,g) and
         all(r[k]>0 and r[k]%4096==0 for k in ('subject_address','data_address','fault_address')),
         'actual original source/private memory addresses')
    literal=bytearray(b'\xcc'*12288);literal[128:128+(s-pc)]=bytes.fromhex('488b06' if mode==6 else '4883c001')
    literal[s-base:s-base+9]=bytes.fromhex('b87856341289c101c0')
    need(r['literal']==literal,'entire literal original page bytes, no patched observation')
    for i,actual in enumerate(r['reference_source']):
        want=bytearray(literal)
        if mode==6 and i:want=bytes(12288)
        else:want[(s if i==0 else g)-base]=0xcc
        need(actual==want,'independent original native source with its explicit stop byte only')
    native(r,layout['frame'])
    if mode:failed(r,layout['frame'])
    else:completed(r,layout['frame'])
    return dict(operation='failed' if mode else 'completed',completed_runs=r['completed_runs'],
        native_completed=r['native_completed'],native_failed=r['native_faults'],old_startup_pairs=1,refusal_bytes=47,
        supplied_mutations=r['supplied_mutations'],real_signals=r['real_signals'],owner_error=r['error'],
        genuine_predecessor_traces=0 if mode==6 else (2 if not mode else 1),generated_traces=0,
        expected_failure_verified=bool(r['verified_failure']))


def controls(data,layout,pid):
    """Eight violating supplied records derived only from a passed real record.

    These are parser controls, never additional native/genuine signal cases.
    The coordinated predecessor mutation leaves the final MOV result intact.
    """
    check(data,layout,0,pid)
    def position(parts):
        node=layout['tr'];at=0
        for part in parts:
            if isinstance(part,str):
                fields=[x for x in node['fields'] if x['name']==part]
                need(len(fields)==1,'mutation targets actual unique field')
                at+=fields[0]['offset'];node=fields[0]['type']
            else:
                need(node['kind']=='array' and 0<=part<node['count'],'mutation actual array element')
                at+=part*node['element']['bytes'];node=node['element']
        return at
    mutations=[None,
        [('literal',132)],
        [('lanes',0,'consumed','event_id')],
        [('lanes',0,'complete_owner','first_error')],
        [('lanes',0,'after','state','frame','fp',160)],
        [('lanes',1,'after','state','stack',8191)],
        [('native',0,'after','state','frame','greg',13),('native',1,'before','state','frame','greg',13),
         ('native',0,'after','uc',layout['frame']['greg'][0]+13*8),
         ('native',1,'before','uc',layout['frame']['greg'][0]+13*8),
         ('native',0,'live',1,'gpr',0),('native',1,'live',0,'gpr',0)],
        [('lanes',0,'after','uc',layout['frame']['greg'][0]+13*8)]]
    for index,paths in enumerate(mutations):
        altered=bytearray(data)
        if paths is None:altered.pop()
        else:
            for path in paths:altered[position(path)]^=1
        try:check(bytes(altered),layout,0,pid)
        except ValueError as exc:
            if index==6:need(str(exc)=='independent ADD overflow and dependent MOV literal effect on all sixteen registers',
                             'coordinated supplied predecessor mutation is rejected by the independent literal effect')
        else:raise ValueError('supplied violating record was accepted: '+str(index))
    return len(mutations)
