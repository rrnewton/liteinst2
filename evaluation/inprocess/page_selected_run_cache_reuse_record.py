"""Strict fixed rotation/failed-prefix replay, using the old complete state oracles.
Intermediate ledger hashes bind checked observations; they are not full replay.
"""
from hashlib import sha256
from page_selected import need
from page_selected_maps_record import unpack
from page_selected_chain_record import REGS,TF,RF,u,equal_state,live,startup,query
from page_selected_trace_run_record import zero,snapshot,event,uc_edit,release,native,handoff,slot

FOCAL=[0,1,64,65,66,129]
ERRORS=[0,741,741,741,741,741,741,754,741,741,741,741,741,747,749,752,752,747,749,741,741,741,741,741,741,741]
DETAILS=[0,12,12,12,12,13,12,3,21,4,4,707,12,-13,-5,5,5,-1,-1,21,7,5,25,26,21,3]
STARTED=[130,130,68,130,1,1,1,1,1,1,1,1,1,65,65,65,65,65,65,1,1,1,1,1,1,1]
CHECKED=[130,129,67,129,0,0,0,0,0,0,0,0,0,64,64,64,64,64,64,0,0,0,0,0,0,0]


def node(layout,parts):
    at=0
    for k in parts:
        if type(k)is str:
            fields=[f for f in layout['fields']if f['name']==k];need(len(fields)==1,'unique retained field')
            at+=fields[0]['offset'];layout=fields[0]['type']
        else:
            need(type(k)is int and layout['kind']=='array' and 0<=k<layout['count'],'exact retained array index')
            at+=k*layout['element']['bytes'];layout=layout['element']
    return at,layout


def private_query(q,entry,prot):
    need(q['first']==entry and q['end']==entry+4096 and q['attempted']==q['complete']==1 and
         q['pages_checked']==1 and q['expected_prot']==q['actual_prot']==prot and q['result']==q['detail']==0 and
         q['first_vma']<=entry<entry+4096<=q['last_vma_end'],'actual full-page permission query')
    p=q['maps'];need(p['opened']==p['close_started']==p['closed']==1 and p['fd']>=0 and
        p['last_read']==p['close_result']==0 and p['bytes']>0 and p['rows']>0,'actual complete maps read/close')


def publication(p,entry,generation):
    need(p['phase']==2 and p['first_error']==p['first_detail']==0 and p['allocation']==1 and
         p['generation']==generation and p['borrow_sequence']>0 and p['entry']==entry>0 and entry%4096==0 and
         p['fill_bytes']==p['verified_bytes']==4096 and p['code_bytes']==21 and
         all(p[k]==1 for k in ('rw_checked','rx_started','rx_complete','sync_started','sync_complete')) and
         all(p[k]==0 for k in ('rx_result','sync_result','cleanup_started','cleanup_complete','cleanup_sync_started','cleanup_result','cleanup_sync_result')),
         'exact full-fill W^X and sync publication')
    private_query(p['before'],entry,3);private_query(p['after'],entry,5);need(zero(p['cleanup']),'no invented cleanup')


def shape(i):
    generation=i+1 if i<65 else i
    slot_id=i if i<64 else 0 if i<=65 else (i-1)%64
    retired=0 if i<64 else 1 if i==64 else i-64
    return generation,slot_id,retired


def ledger(r):
    slots={};last=None
    for i,q in enumerate(r['ledger'][:r['checked']]):
        generation,slot_id,retired=shape(i);route=2 if i in (1,64,66)else 1
        need((q['ordinal'],q['route'],q['started'],q['checked'],q['reset'],q['quiesced'],q['native_observed'])==
             (i,route,1,1,1,1,0 if i in (65,129)else 3),'every real ordinal has exact checked/reset/quiesced outcome')
        h=q['handle']['opaque'];need(h==[1,slot_id,generation,i+1],'captured generation-valued handle and fresh attempt')
        c=q['published'];need(q['finished']==c and c['phase']==2 and c['first_error']==c['first_detail']==0 and
             c['slots_used']==c['complete_slots']==min(i+1,64) and c['attempts']==i+1 and
             c['hits']==int(i>=65) and c['full_misses']==0 and
             all(c[k]==0 for k in ('interrupted','interrupted_again','interrupted_code','interrupted_detail')),
             'exact real cache counts; no hidden miss, failure or extra page')
        a=c['last_attempt'];need(a['ordinal']==i+1 and a['slot']==slot_id and a['hit']==int(i==65) and
             a['complete']==a['installed']==a['source_complete']==a['plan_complete']==1 and
             a['pages_validated']==2 and a['first_error']==a['first_detail']==a['miss_before_publication']==0 and
             a['view_result']==a['validation_result']==a['plan_result']==0 and
             a['fetch']['held']==a['fetch']['complete']==1 and a['borrow_sequence']==a['fetch']['sequence']>0,
             'two live source validation passes and fresh attempt, not cached validity')
        release(q['released'],a['borrow_sequence'])
        p=q['page'];need(p['address']==q['pc']&~4095 and p['allocation']>0 and p['generation']>0 and
             p['closed_prot']==1 and p['logical']==5 and p['address']%4096==0,'actual closed source identity')
        after=q['after'];need(after['generation']==generation and after['completions']==i+1 and
             after['copied_instructions']==2*(i+1) and after['retirements']==retired and
             after['cursor']==(retired%64) and after['lookup']==after['lease']==after['reset_pending']==0 and
             after['current']==q['handle'] and after['publication_present']==1,
             'actual private completion/quiescence and rotating cursor; no outstanding authority')
        publication(after['publication'],q['entry'],generation)
        need((q['before_generation'],q['before_completions'],q['before_retirements'])==
             ((last['generation'],last['completions'],last['retirements'])if last else (0,0,0)),
             'each publish starts from actual prior completion')
        if i<64:need(zero(after['retirement']),'unused slot does not invent retirement')
        elif i==65:
            need(after['retirement']==last['retirement'] and after['publication']==slots[slot_id]['after']['publication'],
                 'hit leaves prior retirement/publication exact and replaces only permit attempt')
        else:
            t=after['retirement'];old=slots[slot_id]
            need(t['phase']==4 and t['old_handle']==old['handle'] and
                 t['old_publication']==old['after']['publication'] and t['completion']==old['ordinal']+1 and
                 t['attempt']==i+1 and t['entry']==old['entry']==q['entry'] and
                 t['verified_bytes']==4096 and
                 all(t[k]==1 for k in ('consumed','rx_checked','revoke_started','revoke_complete','sync_started','writable_started','writable_complete')) and
                 all(t[k]==0 for k in ('first_error','first_detail','revoke_result','sync_result','writable_result','cleanup_started','cleanup_complete','cleanup_result','cleanup_sync_result')),
                 'retire actual older completed generation once, before real R/RW/RX transitions')
            private_query(t['rx'],q['entry'],5);private_query(t['revoked'],q['entry'],1);private_query(t['writable'],q['entry'],3)
            need(zero(t['cleanup']),'successful retirement has no fabricated cleanup')
        need(len(q['plan_sha256'])==len(q['full_case_sha256'])==32 and any(q['plan_sha256'])and any(q['full_case_sha256']),
             'every intermediate checked state has a retained digest; not external full replay')
        slots[slot_id]=q;last=after
    return slots,last


def context(r,f):
    return dict(mode=0,pc=f['pc'],run_pc=f['run_pc'],guard=f['guard'],mapping=f['mapping'],
        pid=r['pid'],subject_address=r['subject_address'],data_address=r['data_address'],fault_address=r['fault_address'],
        native=f['native'],literal=f['literal'],xsave_bytes=r['xsave_bytes'])


def focal(r,f,layout,complete):
    base=f['mapping'];need(base>0 and base%4096==0 and
        (f['pc'],f['run_pc'],f['guard'])==(base+128,base+132,base+139),'fixed actual original geometry')
    literal=bytearray(b'\xcc'*12288);literal[128:141]=bytes.fromhex('4883c001b87856341289c101c0')
    need(f['literal']==literal,'whole original bytes including nonexecuted guard')
    for i,raw in enumerate(f['reference_source']):
        want=bytearray(literal);want[(132 if i==0 else 139)]=0xcc
        need(raw==want,'native reference differs only at its explicit original-address stop')
    v=context(r,f);native(v,layout)
    l=f['lane'];route=f['route'];need(route==(2 if f['ordinal']in (1,64,66)else 1),'fixed genuine ingress route')
    if not complete:return
    if route==2:handoff(v,l,layout)
    else:
        event(l['before'],'nx',f['run_pc'],0xa96|RF,layout);event(l['input'],'nx',f['run_pc'],0xa96|RF,layout)
        need(l['before']==l['input'] and all(zero(l[k])for k in ('trace','closed','closed_chain','offered','consumed')),
             'NX path keeps its genuine frame and has no invented predecessor TRACE')
        equal_state(l['before']['state'],f['native'][1]['before']['state'])
    snapshot(l['redirected'],layout);uc_edit(l['input'],l['redirected'],layout,16,l['publication']['entry'])
    need((l['redirected']['signal'],l['redirected']['code'],l['redirected']['error'],l['redirected']['address'])==
         (5 if route==2 else 11,2,0,f['run_pc']),'redirect keeps original signal kind and full siginfo')
    event(l['after'],'nx',f['guard'],0xa96|RF,layout)
    equal_state(l['after']['state'],f['native'][1]['after']['state']);equal_state(l['after']['state'],f['native'][2]['after']['state'])
    n=f['native'][2 if route==2 else 1]
    live(dict(before=l['before']['state'],after=l['after']['state'],live=l['live'],fp=l['fp']),
         dict(live=n['live'],fp=n['fp']),[0x247 if route==2 else 0xa96,0xa96],r['xsave_bytes'])
    need((l['started'],l['complete'],l['nx'],l['trace_events'],l['events'],l['returns'],l['reset'])==
         (1,1,2,int(route==2),3 if route==2 else 2,3 if route==2 else 2,1),'every actual entry/exit and return counted')
    if route==2:
        need(l['consumed']==dict(l['offered'],consume_attempted=1,consumed=1,run_borrow=l['fresh']['sequence']),
             'genuine once-consumed predecessor proof retains its exact fresh borrow')
    o=l['complete_owner'];need(o['phase']==7 and o['first_error']==o['first_detail']==o['failure_notified']==o['in_handler']==0 and
         o['redirected']==o['exit_seen']==o['release_started']==o['release_complete']==1 and
         o['fetch_view_started']==o['fetch_view_complete']==1 and o['release_result']==o['fetch_result']==0 and
         o['plan']==l['plan'] and o['logical_flags']==0xa96 and o['before']==l['input']['state']['frame'] and
         o['after']==l['after']['state']['frame'] and o['borrow']['sequence']==l['fresh']['sequence'] and
         o['page_count']==1 and o['pages']==f['pages'] and o['backing']==f['backing'] and zero(o['nested']),
         'complete real owner and full before/after frame, source, FP and release')
    need(o['entry_event']==dict(number=5 if route==2 else 11,code=2,error=0,address=f['run_pc'],observed=1) and
         o['exit_event']==dict(number=11,code=2,error=0,address=f['guard'],observed=1),'actual route-specific events')
    for name in ('armed_slot','entry_slot','exit_slot'):slot(o[name],l['plan'],l['publication'])
    query(o['pre_entry'],f['guard']);query(o['exit_query'],f['guard']);release(o['final_fetch'],o['borrow']['sequence'])
    need(l['final_fetch']==o['final_fetch'] and (l['history_before'],l['history_after'])==(f['ordinal'],f['ordinal']+1),
         'reset follows exact complete owner once')
    q=r['ledger'][f['ordinal']]
    need(f['checked']==1 and f['handle']==q['handle'] and l['publication']==q['after']['publication'] and
         l['published']==q['published'] and l['finished']==q['finished'] and l['final_fetch']==q['released'] and
         f['pages'][0]==q['page'] and zero(f['pages'][1])and zero(f['backing'][1]),'focal state joins whole ledger')


def original_plan(f):
    l=f['lane'];p=l['plan'];s=f['run_pc'];g=f['guard'];raw=f['literal'][s-f['mapping']:s-f['mapping']+15]
    generated=raw[:7]+bytes.fromhex('ff2500000000')+g.to_bytes(8,'little')
    need(p['policy']==1 and p['decoder_result']==0 and p['pc']==s and p['stop']==g and
         p['source_length']==15 and p['source']==raw and p['run_length']==7 and
         p['instruction_count']==2 and p['generated_length']==21 and p['generated']==generated+bytes(8),
         'literal original two-MOV plan and unexecuted guard, for both NX and TRACE')
    a,b=p['instructions'][:2]
    need((a['offset'],a['length'],a['effect'],a['destination'],a['width'],a['immediate'])==(0,5,1,0,32,0x12345678) and
         (b['offset'],b['length'],b['effect'],b['destination'],b['source'],b['width'])==(5,2,2,1,0,32) and
         all(zero(x)for x in p['instructions'][2:]) and
         p['guard']['pc']==g and p['guard']['next_pc']==g+2 and p['guard']['length']==2,
         'all literal dependent register effects and unchanged full guard boundary')


def initialized(c):
    x=c['initialization'];q=x['mapping']
    need(all(x[k]==1 for k in ('metadata_started','metadata_complete','allocation_started','allocated',
        'arena_protection_started','arena_protection_complete','complete')) and
        x['allocation_result']==x['arena']>0 and x['arena']%4096==0 and x['arena_bytes']==64*4096 and
        x['metadata_bytes']>0 and x['metadata_result']==x['arena_protection_result']==0 and
        q['first']==x['arena'] and q['end']==x['arena']+64*4096 and q['pages_checked']==64 and
        q['attempted']==q['complete']==1 and q['expected_prot']==q['actual_prot']==3 and q['result']==q['detail']==0,
        'actual protected fixed64-page arena initialized once')
    m=q['maps'];need(m['opened']==m['close_started']==m['closed']==1 and m['fd']>=0 and
        m['last_read']==m['close_result']==0 and m['bytes']>0 and m['rows']>0 and zero(c['last_brk']),
        'complete initialization maps/close and no unrelated brk operation')


def closed_predecessor(r,l,layout):
    pc,s=r['pc'],r['run_pc'];n=r['native'][0]
    event(l['before'],'nx',pc,0x247|RF,layout);equal_state(l['before']['state'],n['before']['state'])
    event(l['trace'],'trace',s,0xa96|TF,layout);equal_state(l['trace']['state'],n['after']['state'])
    event(l['closed'],'trace',s,0xa96,layout)
    uc_edit(l['trace'],l['closed'],layout,17,0xa96)
    need(zero(l['input']),'failed publication has no subsequent arm/input snapshot')
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


def partial_ingress(r,f,layout):
    l=f['lane'];route=f['route'];original_plan(f)
    need(l['started']==1 and l['complete']==0 and zero(l['live'])and zero(l['fp']),
         'failed operation never fabricates a returned user capture or completed run')
    if route==2:
        event(l['before'],'nx',f['pc'],0x247|RF,layout)
        event(l['trace'],'trace',f['run_pc'],0xa96|TF,layout)
        event(l['closed'],'trace',f['run_pc'],0xa96,layout)
        equal_state(l['before']['state'],f['native'][0]['before']['state'])
        equal_state(l['trace']['state'],f['native'][0]['after']['state'])
        closed_predecessor(context(r,f),l,layout)
        q=l['closed_chain']['slots'][l['offered']['next']];plan=l['plan']
        need(q['decoded']['code']==plan['instructions'][0]['code'] and q['decoded']['length']==5 and
             q['decoded']['available']==15 and q['decoded']['bytes']==plan['source']+b'\0',
             'descriptive old-step decoder agrees with exact held source and first run instruction')
        need((l['nx'],l['trace_events'],l['events'],l['returns'])==(1,1,2,1),
             'failed TRACE operation stops in actual second handler before its return')
        anchor=l['closed']
    else:
        event(l['before'],'nx',f['run_pc'],0xa96|RF,layout)
        equal_state(l['before']['state'],f['native'][1]['before']['state'])
        need(all(zero(l[k])for k in ('trace','closed','closed_chain','offered','consumed')),
             'failed NX attempt does not manufacture TRACE proof')
        anchor=l['before']
    return anchor


def raw_failure(r,layout):
    mode=r['mode'];s=r['final_reuse'];t=s['retirement'];c=r['final_cache'];pub=s['publication']
    old=r['ledger'][0];code=ERRORS[mode];detail=DETAILS[mode]
    need(t['phase']==5 and t['old_handle']==old['handle'] and t['old_publication']==old['after']['publication'] and
         t['completion']==1 and t['attempt']==65 and t['entry']==old['entry'] and
         t['consumed']==t['rx_checked']==t['revoke_started']==1 and t['verified_bytes']==4096 and
         t['first_error']==code and t['first_detail']==detail and t['cleanup_started']==1 and
         s['generation']==(65 if mode==16 else 64) and s['completions']==64 and s['copied_instructions']==128 and
         s['retirements']==0 and s['cursor']==1 and s['lookup']==s['lease']==s['reset_pending']==0 and
         s['current']==r['ledger'][63]['handle'] and s['publication_present']==1,
         'actual installed retirement consumed only old completed slot0; failure grants no replacement')
    private_query(t['rx'],t['entry'],5)
    need(pub['phase']==3 and pub['first_error']==code and pub['first_detail']==detail and
         c['slots_used']==64 and c['complete_slots']==63 and c['attempts']==65 and c['hits']==c['full_misses']==0 and
         c['last_attempt']['slot']==0 and c['last_attempt']['complete']==0 and
         c['last_attempt']['first_error']==code and c['last_attempt']['first_detail']==detail and
         c['last_attempt']['pages_validated']==1 and c['last_attempt']['source_complete']==c['last_attempt']['plan_complete']==1 and
         zero(r['current'])and zero(r['final_owner']),
         'failed65th real publish retains its partial source and publication, zero returned handle/owner')
    need((t['revoke_result'],t['sync_started'],t['sync_result'],t['revoke_complete'],t['writable_started'],t['writable_complete'])==
         ((-13,0,0,0,0,0)if mode==13 else (0,1,-5,0,0,0)if mode==14 else
          (0,0,0,0,0,0)if mode==15 else (0,1,0,1,1,1)if mode==16 else
          (-1,0,0,0,0,0)if mode==17 else (0,1,-1,0,0,0)),
         'source-derived first failure prefix, not completed revoke/write/sync counters')
    if mode==16:
        private_query(t['revoked'],t['entry'],1);private_query(t['writable'],t['entry'],3)
        need(pub['generation']==65 and pub['borrow_sequence']==r['final_fetch']['sequence'] and
             pub['fill_bytes']==4096 and pub['code_bytes']==21 and pub['rw_checked']==pub['rx_started']==1 and
             pub['rx_complete']==pub['sync_started']==pub['sync_complete']==pub['verified_bytes']==0,
             'nested writable event is before actual RX call and new publication completion')
        private_query(pub['before'],t['entry'],3);need(zero(pub['after']),'no unobserved RX query')
    else:
        need(zero(t['revoked'])and zero(t['writable']) and
             pub==dict(t['old_publication'],phase=3,first_error=code,first_detail=detail),
             'old publication progress stays historical until new writing really starts')
    if mode in (17,18):
        need(t['cleanup_complete']==0 and t['cleanup_result']==(-1 if mode==17 else 0) and
             t['cleanup_sync_result']==(-1 if mode==18 else 0),'kernel denial remains effective during cleanup')
        if mode==18:private_query(t['cleanup'],t['entry'],1)
        else:
            q=t['cleanup'];need(q['attempted']==1 and q['complete']==0 and q['expected_prot']==1 and
                 q['actual_prot']==0 and q['pages_checked']==0 and q['result']==305 and q['detail']==0,
                 'failed expected-R query retains its incomplete prefix, never cleanup credit')
    else:
        need(t['cleanup_complete']==1 and t['cleanup_result']==t['cleanup_sync_result']==0,
             'independent real cleanup succeeds after single supplied failure or actual nested signal')
        private_query(t['cleanup'],t['entry'],1)
    need(c['interrupted']==int(mode in (15,16)) and c['interrupted_again']==0 and
         c['interrupted_code']==(752 if mode in (15,16)else 0) and
         c['interrupted_detail']==(5 if mode in (15,16)else 0),'actual interrupt prefix only for real signal children')
    rows=r['raw'][:r['raw_count']];need(r['raw_count']=={13:3,14:4,15:3,16:6,17:3,18:4}[mode] and
        all(zero(v)for v in r['raw'][r['raw_count']:]),'all raw calls retained in bounded exact prefix')
    want=([(10,1),(324,32),(10,3),(10,5),(10,1),(324,32)]if mode==16 else
        [(10,1),(324,32),(10,1),(324,32)]if mode in (14,18)else [(10,1),(10,1),(324,32)])
    need([(x['number'],x['args'][2]if x['number']==10 else x['args'][0])for x in rows]==want,
         'complete actual requested syscall order including interrupted/injected call')
    special=[v for v in rows if v['injected']or v['signal_sent']or v['kernel_filter']]
    need(len(special)==1,'exactly one supplied, signal or kernel trigger')
    v=special[0];need(v['args'][3:]==[0,0,0] and v['number']==(324 if mode in (14,18)else 10) and
         v['args'][:3]==([32,0,0]if mode in (14,18)else [t['entry'],4096,5 if mode==16 else 1]),
         'trigger is actual retirement/republication syscall with exact operands')
    for x in rows:
        need(x['number']in (10,324) and x['args'][3:]==[0,0,0] and
             x['args'][:3]==([32,0,0]if x['number']==324 else [t['entry'],4096,x['args'][2]]) and
             (x['number']!=10 or x['args'][2]in (1,3,5)), 'only exact retirement W^X/sync raw operations')
        if x['signal_sent']:
            need(mode in (15,16)and x['issued']==x['complete']==x['injected']==x['kernel_filter']==0 and
                 x['actual_result']==x['returned_result']==0,'interrupted call was never issued or assigned a fake result')
        elif x['injected']:
            need(mode in (13,14)and x['issued']==0 and x['complete']==1 and x['actual_result']==0 and
                 x['returned_result']==detail and x['kernel_filter']==0,'supplied raw error is not a kernel outcome')
        else:
            expected=-1 if (mode==17 and x['number']==10 and x['args'][2]==1)or(mode==18 and x['number']==324)else 0
            need(x['issued']==x['complete']==1 and x['actual_result']==x['returned_result']==expected,
                 'every actual syscall result including cleanup is retained exactly')
    if mode in (15,16):
        d=r['delivered'];snapshot(d,layout);at=layout['address'][0]
        need((d['signal'],d['code'],d['error'])==(5,-6,0) and
             int.from_bytes(d['si'][at:at+4],'little',signed=True)==r['pid'] and
             int.from_bytes(d['si'][at+4:at+8],'little')==r['uid'],
             'genuine tgkill siginfo sender PID/UID and complete nested frame')
    else:need(zero(r['delivered']),'no invented signal on supplied/kernel-return cases')


def failed(r,layout):
    mode=r['mode'];index=r['started']-1;f=r['focal'][FOCAL.index(index)if index in FOCAL else 5]
    l=f['lane'];o=r['final_owner'];s=r['final_reuse'];c=r['final_cache'];h=r['final_history']
    need(r['verified_failure']==1 and r['complete']==0 and
         (r['error'],-r['detail_abs']if r['detail_negative']else r['detail_abs'])==(ERRORS[mode],DETAILS[mode]) and
         r['supplied_mutations']==int(mode in (4,5,12,20,21,22,23,25)) and
         r['raw_injections']==int(mode in (13,14)) and r['real_signals']==int(mode in (15,16)) and
         r['kernel_filters']==int(mode in (17,18)) and r['runtime_failures']==0,
         'exact failed operation and separately typed supplied/native/kernel outcomes')
    anchor=partial_ingress(r,f,layout)
    completed_endpoint=mode in (7,8,24)
    need(zero(l['live'])and zero(l['fp'])and l['complete']==0 and f['checked']==0,
         'no full return or external completion credit for terminal process')
    if completed_endpoint:
        event(l['input'],'nx',f['run_pc'],0xa96|RF,layout);need(l['input']==l['before'],'actual unedited entry')
        snapshot(l['redirected'],layout);uc_edit(l['input'],l['redirected'],layout,16,l['publication']['entry'])
        event(l['after'],'nx',f['guard'],0xa96|RF,layout);equal_state(l['after']['state'],f['native'][1]['after']['state'])
        need(l['reset']==1 and (l['events'],l['nx'],l['returns'])==(2,2,1) and
             l['complete_owner']['phase']==7 and h['completed_runs']==1 and h['copied_instructions']==2 and
             h['last_complete']==l['complete_owner'] and h['reset_started']==h['reset_complete']==1 and zero(o),
             'actual exit/reset prefix retained without claiming final fixture return')
        for key in ('armed_slot','entry_slot','exit_slot'):slot(l['complete_owner'][key],l['plan'],l['publication'])
        need(l['complete_owner']['before']==l['input']['state']['frame'] and l['complete_owner']['after']==l['after']['state']['frame'] and
             l['complete_owner']['release_complete']==1 and l['complete_owner']['first_error']==0,
             'full actual completed owner independently joins both raw frames')
        release(l['final_fetch'],l['fresh']['sequence']);anchor=l['after']
        need(s['completions']==1 and s['copied_instructions']==2 and s['lookup']==s['lease']==0 and
             s['reset_pending']==int(mode!=8),'exact private reset/quiescence prefix')
        if mode==24:
            need(r['final_fetch']['held']==r['final_fetch']['complete']==1 and
                 r['final_fetch']['sequence']>l['final_fetch']['sequence'],'actual new unrelated held source prevents quiescence')
        else:need(r['final_fetch']==l['final_fetch'],'failed reset/quiesce keeps exact released source')
        need((h['first_error'],h['first_detail'])==((754,3)if mode==7 else (0,0)),
             'duplicate reset history failure is distinct from cache refusal')
    else:
        need(l['reset']==0 and zero(l['input'])and zero(l['redirected'])and zero(l['after'])and zero(l['complete_owner']),
             'failed pre-entry operation never reaches generated code, exit or owner completion')
        if f['route']==1:need((l['events'],l['nx'],l['returns'])==(1,1,0),'actual first NX failed prefix')
        if mode==11:release(r['final_fetch'],l['fresh']['sequence'])
        else:need(r['final_fetch']['held']==r['final_fetch']['complete']==1 and r['final_fetch']['first_error']==0,
                  'terminal failed operation retains genuine held source rather than claiming release')
    snapshot(r['failure_frame'],layout);need(r['failure_frame']==anchor,
         'complete actual failure frame/FP/private memory equals original endpoint, no hidden edit')
    need(c['phase']==(2 if mode==7 else 3) and
         (c['first_error'],c['first_detail'])==((0,0)if mode==7 else (741,14)if mode==25 else (ERRORS[mode],DETAILS[mode])),
         'first error preserved in correct owner without reclassifying failed cleanup')
    if mode not in range(20,24):
        expected_complete=r['checked']+int(completed_endpoint)
        need(h['completed_runs']==expected_complete and h['copied_instructions']==2*expected_complete and
             (h['reset_started'],h['reset_complete'])==((1,1)if expected_complete else (0,0)),
             'real completed/reset history prefix; no later failed operation adds a run')
        if not completed_endpoint:need(h['first_error']==h['first_detail']==0,'unrelated failed operation leaves prior history unchanged')
        if expected_complete==0:need(zero(h),'no fabricated prior complete owner')
    if mode not in range(13,19) and mode not in range(20,24):
        generation,slot_id,retired=shape(index)
        need(c['slots_used']==c['complete_slots']==min(index+1,64) and c['attempts']==index+1 and
             c['hits']==int(index>=65) and c['full_misses']==0 and
             s['generation']==generation and s['retirements']==retired and s['cursor']==retired%64 and
             s['current']==r['current'] and r['current']['opaque']==[1,slot_id,generation,index+1] and
             s['publication_present']==1 and l['publication']==s['publication'],
             'failed post-publish control retains exact genuine lookup generation/counters')
        publication(s['publication'],s['publication']['entry'],generation)
        a=c['last_attempt']
        need(a['complete']==a['installed']==a['source_complete']==a['plan_complete']==1 and
             a['ordinal']==index+1 and a['slot']==slot_id and a['hit']==0 and a['pages_validated']==2 and
             a['first_error']==a['first_detail']==a['miss_before_publication']==0 and
             a['fetch']['sequence']==a['borrow_sequence']==l['fresh']['sequence'],
             'successful publication is distinct from subsequent rejected authority operation')
        if index<64:need(zero(s['retirement']),'first-slot control has no retirement')
        else:
            victim=slot_id
            if index==129:victim=65
            old=r['ledger'][victim];t=s['retirement']
            need(t['phase']==4 and t['old_handle']==old['handle'] and t['completion']==victim+1 and
                 t['old_publication']==old['after']['publication'] and t['entry']==old['entry']==s['publication']['entry'] and
                 t['attempt']==index+1 and t['consumed']==t['rx_checked']==t['revoke_started']==t['revoke_complete']==
                 t['sync_started']==t['writable_started']==t['writable_complete']==1 and
                 t['verified_bytes']==4096 and all(t[k]==0 for k in ('first_error','first_detail','revoke_result','sync_result',
                 'writable_result','cleanup_started','cleanup_complete','cleanup_result','cleanup_sync_result')),
                 'stale handle denial follows a genuinely completed replacement of exact old slot')
            private_query(t['rx'],t['entry'],5);private_query(t['revoked'],t['entry'],1);private_query(t['writable'],t['entry'],3)
            need(zero(t['cleanup']),'completed replacement has no cleanup')
    if mode in range(13,19):
        need(l['published']==c if mode in (13,14,17,18)else zero(l['published']),
             'returned raw error and nested interruption retain distinct actual assignment prefixes')
        raw_failure(r,layout)
    else:
        need(r['raw_count']==0 and zero(r['raw'])and zero(r['delivered']),'no fictitious raw/signal trigger')
        if mode in (1,2,3):
            old=r['saved'][0 if mode==1 else 1 if mode==2 else 2]
            need(r['supplied']==old and r['current']!=old and s['lookup']==1 and s['lease']==0 and zero(o),
                 'stale value handle refuses against real fresh pending lookup')
            if mode in (1,3):
                first=r['focal'][0]
                need(f['pc']==first['pc'] and l['plan']==first['lane']['plan'] and f['native']==first['native'] and
                     l['publication']['entry']==first['lane']['publication']['entry'] and
                     (first['handle']['opaque'][2],r['current']['opaque'][2])==(1,129),
                     'stale A/B challenge occurs after identical original A plan at same address and slot')
        if mode in (4,9,12):need(s['lookup']==1 and s['lease']==0 and zero(o),'wrong recipient/value or pending second publish preserves lookup')
        if mode in (5,6,10,19,25):
            need(s['lookup']==0 and s['lease']==3 and o['phase']==3 and o['first_error']==0 and
                 o['plan']==l['plan'] and o['borrow']['sequence']==l['fresh']['sequence'] and o['logical_flags']==0xa96,
                 'legitimate real owner stays armed, never manually cancelled')
            slot(o['armed_slot'],l['plan'],l['publication'])
            need(zero(o['before'])and zero(o['after'])and zero(o['entry_event'])and zero(o['exit_event']),
                 'armed owner has no fake entered or returned observation')
        if mode==5:
            need(r['direct_publication']==o['publication']>0 and r['direct_publisher']==o['publisher'] and zero(r['clone']),
                 'direct API challenge uses actual bare publication and genuine copied publisher on zero clone')
        else:need(r['direct_publication']==0 and zero(r['direct_publisher']),'no unperformed pointer challenge')
        if mode==4:need(zero(r['clone']),'copied zero owner has no registered-owner authority')
        if mode==11:
            need(s['lease']==2 and s['lookup']==0 and o['phase']==8 and o['first_error']==707 and
                 o['fetch_view_started']==1 and o['fetch_view_complete']==0 and o['fetch_result']==302 and
                 zero(o['armed_slot']),'actual released source fails original live fetch check before slot observation')
        if mode==25:
            need(r['clone']==dict(o,phase=8,first_error=741,first_detail=3,failure_notified=1,final_fetch=r['final_fetch']),
                 'actual cloned armed owner is refused by mandatory entry check; registered owner unchanged')
        if mode==12:need(r['supplied']['opaque']==[1,0,(1<<64)-1,1],'explicitly supplied impossible generation')
        if 20<=mode<=23:
            need(zero(o)and zero(r['current'])and s['lookup']==s['lease']==s['reset_pending']==0 and
                 c['slots_used']==c['complete_slots']==c['hits']==c['full_misses']==0 and s['publication_present']==0,
                 'source-injected overflow never publishes, grants a lease or executes generated code')
            expected={20:((1<<64)-1,1,0,0),21:(0,(1<<64)-1,0,0),
                      22:(0,0,(1<<64)-1,0),23:(0,1,0,(1<<64)-2)}[mode]
            need((s['generation'],c['attempts'],s['completions'],s['copied_instructions'])==expected,
                 'exact supplied counter values; no actual gigantic completion credit')
            need(h['completed_runs']==s['completions'] and h['copied_instructions']==s['copied_instructions'],
                 'overflow history edits explicitly bound as supplied values')


def check(data,layout,mode,pid):
    need(type(mode)is int and 0<=mode<26 and set(layout)=={'ru','samples','frame'} and
         layout['samples']['kind']=='array' and layout['samples']['count']==21,'fixed26-operation layout')
    size=layout['ru']['bytes'];need(len(data)==size+layout['samples']['element']['bytes']<16<<20,'whole exact bounded reuse capture')
    r=unpack(data,layout['ru']);startup(unpack(data,layout['samples']['element'],size))
    need((r['magic'],r['version'],r['bytes'],r['mode'])==(0x315553455252324c,1,size,mode) and
         r['old_refusals']==47 and r['startup_pairs']==1 and r['fixture_failure']==0 and
         r['initial_stats']['phase']==2 and r['final_stats']==r['initial_stats'] and r['xcr0']&3==3 and
         576<=r['xsave_bytes']<=65536,'unchanged actual startup/refusals and sealed decoder closure')
    need(type(pid)is int and r['pid']==r['tid']==pid>0 and 0<=r['uid']<=0xffffffff and
         all(r[k]>0 and r[k]%4096==0 for k in ('subject_address','data_address','fault_address')),
         'actual singleton PID, sender identity and complete private-memory geometry')
    need(r['started']==STARTED[mode] and r['checked']==CHECKED[mode] and
         r['native_completed']==3*(r['started']-int(r['started']>65)-int(r['started']>129)) and
         r['retained']==sum(i<r['checked']for i in FOCAL),'exact genuine runs/native references and focal prefix')
    slots,last=ledger(r);initialized(r['final_cache'])
    if mode in range(13,19):calls=[66,64,64]
    elif mode in (20,21,22,23):calls=[int(mode==20),0,0]
    else:
        calls=[r['started']+shape(r['started']-1)[2],r['started'],
               r['checked']+int(mode==8)]
    need(r['runtime_calls']==calls,'exact actual linked interlock calls with no fabricated allow result')
    for q in r['ledger'][:r['checked']]:
        need(q['published']['initialization']==r['final_cache']['initialization'] and
             q['entry']==r['final_cache']['initialization']['arena']+4096*q['handle']['opaque'][1],
             'every generation reuses only its real fixed-arena slot')
    partial=r['started']-1 if mode else None
    used=set()
    for at,ordinal in enumerate(FOCAL):
        if ordinal<r['checked']:
            f=r['focal'][at];need(f['ordinal']==ordinal,'fixed complete focal order')
            focal(r,f,layout['frame'],True);original_plan(f);used.add(at)
            offset,n=node(layout['ru'],['focal',at]);q=r['ledger'][ordinal]
            need(sha256(data[offset:offset+n['bytes']]).digest()==q['full_case_sha256'],'whole focal raw hash joins actual checked ledger')
            offset,n=node(layout['ru'],['focal',at,'lane','plan'])
            need(sha256(data[offset:offset+n['bytes']]).digest()==q['plan_sha256'],'whole exact plan bytes join ledger')
    if mode:
        at=FOCAL.index(partial)if partial in FOCAL else 5;f=r['focal'][at];used.add(at)
        need(f['ordinal']==partial and f['native_observed']==(0 if partial in (65,129)else 3),'actual uncompleted current focal prefix')
        focal(r,f,layout['frame'],False);failed(r,layout['frame'])
        q=r['ledger'][partial]
        need((q['ordinal'],q['route'],q['started'],q['checked'],q['native_observed'],q['pc'])==
             (partial,f['route'],1,0,f['native_observed'],f['run_pc']) and
             all(zero(q[k])for k in ('reset','quiesced','entry','handle','page','released','published','finished','after','plan_sha256','full_case_sha256')),
             'partial ledger records only actually initialized fields, no completion status')
        need((q['before_generation'],q['before_completions'],q['before_retirements'])==
             ((last['generation'],last['completions'],last['retirements'])if last else (0,0,0)),
             'failed current publish starts from exact prior completed prefix')
    else:
        need(r['complete']==1 and all(r[k]==0 for k in ('verified_failure','error','detail_abs','detail_negative',
             'supplied_mutations','raw_injections','real_signals','kernel_filters','raw_count','runtime_failures','direct_publication')) and
             zero(r['raw'])and zero(r['delivered'])and zero(r['failure_frame'])and zero(r['clone'])and zero(r['direct_publisher'])and
             zero(r['supplied'])and zero(r['final_owner'])and r['final_reuse']==last and
             r['final_cache']==r['ledger'][129]['finished'] and r['current']==r['ledger'][129]['handle'],
             'complete130-run cohort has no failed, injected or unfinished operation')
        a,b,again=r['focal'][0],r['focal'][2],r['focal'][5]
        need(a['lane']['publication']['entry']==b['lane']['publication']['entry']==again['lane']['publication']['entry'] and
             a['pc']==again['pc'] and a['lane']['plan']==again['lane']['plan'] and a['native']==again['native'] and
             (a['handle']['opaque'][2],b['handle']['opaque'][2],again['handle']['opaque'][2])==(1,65,129),
             'same-address same-plan ABA occurs only after actual full rotation and new generation')
        h=r['final_history'];need(h['completed_runs']==130 and h['copied_instructions']==260 and
             h['reset_started']==h['reset_complete']==1 and h['first_error']==h['first_detail']==0 and
             h['last_complete']==again['lane']['complete_owner'] and r['final_fetch']==again['lane']['final_fetch'],
             'actual final complete history and released source exactly retained')
    need(all(zero(f)for i,f in enumerate(r['focal'])if i not in used)and
         all(zero(q)for q in r['ledger'][r['started']:]),'no unexecuted focal/ledger records')
    for i,ordinal in enumerate((0,1,64)):
        need(r['saved'][i]==r['ledger'][ordinal]['handle']if ordinal<r['checked']else zero(r['saved'][i]),
             'retained stale values originate only from real completed runs')
    return dict(operation='failed'if mode else 'completed',completed_runs=r['checked'],native_completed=r['native_completed'],
        full_focal_replays=sum(i<r['checked']for i in FOCAL),intermediate_in_fixture_comparisons=r['checked']-sum(i<r['checked']for i in FOCAL),
        actual_owner_resets=r['checked']+int(mode in (7,8,24)),
        publications=(129 if not mode else None),retirements=(65 if not mode else None),hits=int(r['checked']>65),
        supplied_mutations=r['supplied_mutations'],supplied_raw_errors=r['raw_injections'],real_signals=r['real_signals'],
        kernel_denials=r['kernel_filters'],owner_error=r['error'],expected_failure_verified=bool(r['verified_failure']))


def controls(data,layout,pid):
    """Copied-record refusals only; never native events or extra run credit."""
    check(data,layout,0,pid)
    mutations=[None,[['ledger',63,'checked']],[['ledger',64,'after','retirement','old_handle','opaque',2]],
        [['ledger',66,'after','retirement','completion']],[['ledger',129,'handle','opaque',2]],
        [['focal',0,'lane','after','state','frame','fp',160]],[['focal',4,'lane','after','state','stack',8191]],
        [['focal',2,'lane','consumed','event_id']],[['focal',5,'lane','after','uc',layout['frame']['greg'][0]+13*8]],
        [['focal',1,'native',0,'after','state','frame','greg',13],['focal',1,'native',1,'before','state','frame','greg',13],
         ['focal',1,'native',0,'after','uc',layout['frame']['greg'][0]+13*8],['focal',1,'native',1,'before','uc',layout['frame']['greg'][0]+13*8],
         ['focal',1,'native',0,'live',1,'gpr',0],['focal',1,'native',1,'live',0,'gpr',0]],
        [['final_reuse','retirements']],[['final_history','copied_instructions']]]
    for i,paths in enumerate(mutations):
        altered=bytearray(data)
        if paths is None:altered.pop()
        else:
            for path in paths:
                at,_=node(layout['ru'],path);altered[at]^=1
        try:check(bytes(altered),layout,0,pid)
        except ValueError:pass
        else:raise ValueError('supplied violating reuse record accepted: '+str(i))
    return len(mutations)


def failed_controls(data,layout,mode,pid):
    """Supplied mutations of an already accepted actual failed prefix."""
    check(data,layout,mode,pid)
    mutations=[[['error']]]
    if mode in (1,2,3):mutations.append([['final_reuse','retirement','old_handle','opaque',2]])
    if 13<=mode<=18:
        r=unpack(data,layout['ru']);f=r['focal'][2];previous=f['lane']['offered']['previous']
        mutations.extend([[['focal',2,'lane','closed_chain','slots',previous,'owner','step','after','greg',13]],
                          [['focal',2,'lane','closed_chain','slots',previous,'fetch','bytes',0]]])
    for i,paths in enumerate(mutations):
        altered=bytearray(data)
        for path in paths:
            at,_=node(layout['ru'],path);altered[at]^=1
        try:check(bytes(altered),layout,mode,pid)
        except ValueError:pass
        else:raise ValueError('supplied violating failed-prefix record accepted: '+str((mode,i)))
    return len(mutations)
