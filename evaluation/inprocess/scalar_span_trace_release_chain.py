"""Successful release-report TRACE closure; no protected-record authority.

The caller retains every original generic/cache/native/rseq/lease guard. Only
the chain-specific completion domain changes: a segment can end in a real
consumed span as well as the original descriptive fallback. A CLOSED slot can
follow either kind of earlier segment; a FALLBACK slot is never an execution.
"""
import copy
from page_selected import need
import page_selected_chain_compare as old

CONTROL_COUNT=11
SUPPLIED_LEASE_CONTROL_COUNT=2


def advanced_lease(c,active):
    need(c['lease_phase']==5 and c['lease_event']==active['event'] and
         ((c['lease_fetch_phase']==4 and
           c['lease_fetch_before']+1==c['lease_fetch_after']==active['borrow'])or
          (c['lease_fetch_phase']==5 and
           c['lease_fetch_before']==active['borrow'] and c['lease_fetch_after']==0)),
         'release TRACE advanced slot binds its exact closed lease and current borrow')


def supplied_lease_controls():
    """Two supplied tuple predicates only; no actual stream or native credit."""
    accepted=[];refused=[]
    for name,phase,before,after in (('committed',4,6,7),('cancelled',5,7,0)):
        # Both tuples describe the same completed event/borrow.  Cancellation
        # retains that borrow; successful commit advances it exactly once.
        active=dict(event=3,borrow=7)
        current=dict(lease_phase=5,lease_event=3,lease_fetch_phase=phase,
                     lease_fetch_before=before,lease_fetch_after=after)
        advanced_lease(current,active);accepted.append(name)
        unrelated=dict(current);unrelated['lease_event']=2
        caught=False
        try:advanced_lease(unrelated,active)
        except ValueError as exc:
            caught=str(exc)=='release TRACE advanced slot binds its exact closed lease and current borrow'
        need(caught,'supplied unrelated earlier lease must fail exact advanced-slot provenance')
        refused.append(name+'_unrelated_event')
    need(len(accepted)==len(refused)==SUPPLIED_LEASE_CONTROL_COUNT==2,
         'two exact supplied lease tuple baselines and refusals')
    return dict(scope='supplied tuple predicate only',positive_controls=accepted,refusals=refused,
                actual_stream_credit=False,native_operations=0)


def completed(loader,c,span):
    need(all(c[k]==span[k]==loader[k]==0 for k in
         ('status','failure_code','detail_abs','detail_negative'))and
         c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['sequence']==c['trace_entries']>0 and
         span['offers']==span['closed']==span['entries']+span['resumed'] and
         span['entries']==span['completed']>0 and
         c['nx_entries']==c['fallbacks']+span['entries'] and
         c['nx_entries']<=loader['nx_faults'],
         'release TRACE exact consumed-span segment partition')
    need(c['trace_entries']+c['fallbacks']<=c['preparations']<=2*(c['trace_entries']+c['fallbacks']),
         'release TRACE exact truncated-retry preparation domain')
    need(c['releases']==c['preparations']+c['nx_entries'],
         'release TRACE every prepared and incoming NX borrow released')
    slots=[old.slot(c,i)for i in (0,1)]
    need(sum(s['generation']for s in slots)==c['attempts']+c['fallbacks'],
         'release TRACE exact chain-next generation conservation')
    for s in slots:
        need(s['phase']in(5,6), 'release TRACE only completed or descriptive terminal slots')
        need(s['generation']>0 and 0<s['event']<=c['event'] and
             0<s['pc']<1<<64 and s['borrow']>0 and s['validations']>0 and
             s['held']==s['fetch_error']==s['owner_error']==s['unexpected']==0 and
             s['release']==s['released']==1,
             'release TRACE both actual slot borrows fully released')
        if s['phase']==5:
            pc,length=s['pc'],s['length']
            need(s['origin']in(1,2)and s['fallback']==0 and
                 s['prepare']==int(s['origin']==2)and s['prepared']==1 and
                 (s['origin']==2 or s['retry']==0)and
                 1<=length<=15 and pc<=(1<<64)-1-length and
                 s['owner_phase']==5 and s['trace']==s['query']==s['queried']==1 and
                 s['post_pc']==s['query_pc']>0,
                 'release TRACE complete actual closed slot query')
            mask=1 if pc//4096==(pc+length-1)//4096 else 3
            need(s['open']==s['opened']==s['revoke']==s['revoked']==mask,
                 'release TRACE exact closed slot permission masks')
        else:
            need(s['origin']==2 and 1<=s['fallback']<=6 and s['prepare']==s['prepared']==1 and
                 s['owner_phase']==s['open']==s['opened']==s['revoke']==s['revoked']==
                 s['trace']==s['post_pc']==s['query']==s['queried']==s['query_pc']==0,
                 'release TRACE descriptive fallback never executed or queried')
    active,previous=slots[c['active']],slots[c['active']^1]
    need(previous['event']<active['event'] and previous['borrow']<active['borrow'],
         'release TRACE actual resident slot chronology')
    if active['phase']==6:
        need(previous['phase']==5 and previous['post_pc']==previous['query_pc']==active['pc'],
             'release TRACE fallback retains its exact closed predecessor')
        selected=previous
    else:
        # Same-page leases may advance the decoded PC inside this generation.
        # An NX-origin slot is a separate real segment, with no invented edge.
        if active['origin']==2:
            start=previous['post_pc']
            need(previous['phase']==5 and (start==active['pc']or
                 (c['lease_transfers']>0 and start//4096==active['pc']//4096 and start<active['pc'])),
                 'release TRACE ordinary successor or actual forward same-page lease')
            if start!=active['pc']:advanced_lease(c,active)
        selected=active
    old.same_slot(loader,selected)
    need(loader['tf_pc']==selected['pc'] and loader['tf_length']==selected['length'] and
         loader['tf_code']==selected['code'],
         'release TRACE rich LOADER selects the actual source-defined terminal slot')
    t=span['transfer'];retained=slots[t[3]]
    need(0<t[2]<=c['event'] and 0<t[6]<=retained['generation'],
         'release TRACE last transfer is bounded by actual chain history')
    if t[6]==retained['generation']:
        need(retained['phase']==5 and retained['event']<t[2] and
             retained['borrow']==t[7] and retained['post_pc']==retained['query_pc']==t[9],
             'release TRACE resident transfer generation retains exact closed identity')
    return dict(scope='source-derived terminal reports only',protected_record_credit=False,
        consumed_spans=span['entries'],resumed_spans=span['resumed'],
        truncated_retries=c['preparations']-c['trace_entries']-c['fallbacks'],
        selected_slot=c['active']if active['phase']==5 else c['active']^1)


def mutations(loader,c,span):
    """Eleven additional meaningful failures; old populations remain separate."""
    trials=[]
    def add(name,error):
        a,b,s=copy.deepcopy(loader),copy.deepcopy(c),copy.deepcopy(span)
        trials.append((name,a,b,s,error));return a,b,s
    a,b,s=add('trace_segment_partition','release TRACE exact consumed-span segment partition')
    for key in ('fallbacks','preparations','releases'):b[key]+=1
    b['s0_generation']+=1
    a,b,s=add('trace_retry_partition','release TRACE exact truncated-retry preparation domain')
    b['preparations']=b['trace_entries']+b['fallbacks']-1;b['releases']=b['preparations']+b['nx_entries']
    a,b,s=add('trace_retry_upper_bound','release TRACE exact truncated-retry preparation domain')
    b['preparations']=2*(b['trace_entries']+b['fallbacks'])+1;b['releases']=b['preparations']+b['nx_entries']
    a,b,s=add('trace_release_partition','release TRACE every prepared and incoming NX borrow released');b['releases']+=1
    a,b,s=add('trace_generation_partition','release TRACE exact chain-next generation conservation');b['s0_generation']+=1
    a,b,s=add('trace_slot_phase','release TRACE only completed or descriptive terminal slots');b['s0_phase']=4
    a,b,s=add('trace_slot_release','release TRACE both actual slot borrows fully released');b['s0_released']=0
    closed=next(i for i in (0,1)if c['s%d_phase'%i]==5)
    a,b,s=add('trace_slot_query','release TRACE complete actual closed slot query');b['s%d_queried'%closed]=0
    a,b,s=add('trace_selected_code','release TRACE rich LOADER selects the actual source-defined terminal slot');a['tf_code']^=1
    a,b,s=add('trace_transfer_generation','release TRACE last transfer is bounded by actual chain history')
    s['transfer'][6]=b['s%d_generation'%s['transfer'][3]]+1
    a,b,s=add('trace_transfer_identity','release TRACE resident transfer generation retains exact closed identity')
    s['transfer'][3]=closed;s['transfer'][6]=b['s%d_generation'%closed];s['transfer'][7]=b['s%d_borrow'%closed]+1
    need(len(trials)==CONTROL_COUNT,'eleven fixed additional release TRACE chain controls')
    return trials
