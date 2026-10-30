"""Finite TRACE chain conservation, distinct from the old fallback contract.

A consumed span closes one ordinary owner without preparing a successor.
A resumed miss executes the unchanged ordinary prepare/arm/fallback tail.
These counters are observations, never source or execution authority. The
finite caller additionally joins every field to its actual protected capture.
"""
import copy
from page_selected import need
import page_selected_chain_compare as old

ROW_CONTROL_COUNT=88
CONTROL_COUNT=6


def quiet(loader,c,span):
    need(c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['sequence']==c['trace_entries']>0 and
         span['offers']==span['closed']==span['entries']+span['resumed'] and
         c['nx_entries']==c['fallbacks']+span['entries'] and
         c['preparations']>=c['trace_entries']+c['fallbacks'] and
         c['releases']==c['preparations']+c['nx_entries'] and
         c['nx_entries']<=loader['nx_faults'],
         'exact quiet TRACE close/consume/resume and truncated-retry conservation')
    slots=[old.slot(c,i)for i in (0,1)]
    need(sum(s['generation']for s in slots)==c['attempts']+c['fallbacks'],
         'every actual chain_next contributes one resident slot generation')
    for s in slots:
        length,pc=s['length'],s['pc']
        need(s['phase']==5 and s['origin']in(1,2)and s['fallback']==0 and
             s['prepare']==int(s['origin']==2)and s['prepared']==1 and
             s['generation']>0 and 0<s['event']<=c['event'] and 0<pc<1<<64 and
             1<=length<=15 and pc<=(1<<64)-1-length and
             s['owner_phase']==5 and s['owner_error']==s['unexpected']==0 and
             s['held']==s['fetch_error']==0 and s['borrow']>0 and s['validations']>0 and
             s['trace']==s['query']==s['queried']==s['release']==s['released']==1 and
             s['post_pc']==s['query_pc']>0,
             'finite TRACE retains two actual fully closed ordinary owners')
        mask=1 if pc//4096==(pc+length-1)//4096 else 3
        need(s['open']==s['opened']==s['revoke']==s['revoked']==mask,
             'both retained ordinary owners closed their exact source page masks')
    # selected_report_slot returns active for CLOSED; predecessor selection is
    # exclusively the old successful FALLBACK contract, retained in its donor.
    active=slots[c['active']]
    old.same_slot(loader,active)
    need(loader['tf_pc']==active['pc'] and loader['tf_length']==active['length'] and
         loader['tf_code']==active['code'],
         'rich LOADER completion selects the actual active CLOSED owner')
    return dict(consumed_spans=span['entries'],resumed_spans=span['resumed'],
        truncated_retries=c['preparations']-c['trace_entries']-c['fallbacks'])


def completed(loader,c,span):
    need(all(c[k]==span[k]==0 for k in ('status','failure_code','detail_abs','detail_negative'))and
         span['entries']==span['completed'],
         'successful TRACE chain closure never reclassifies a failed span')
    result=quiet(loader,c,span)
    active,previous=(old.slot(c,i)for i in (c['active'],c['active']^1))
    need(previous['post_pc']==previous['query_pc']==active['pc']and
         previous['borrow']<active['borrow']and previous['event']<active['event'],
         'finite successful terminal retains its real CLOSED-to-CLOSED predecessor')
    return result


def mutations(loader,c):
    """Six distinct new-contract failures; all old controls remain required."""
    trials=[]
    def add(name):
        a,b=copy.deepcopy(loader),copy.deepcopy(c);trials.append((name,a,b));return a,b
    a,b=add('chain_consumed_partition')
    for key in ('attempts','steps','nx_entries','releases'):b[key]+=1
    b['s0_generation']+=1;a['generic_tf_attempts']+=1;a['generic_tf_steps']+=1
    _,b=add('chain_retry_conservation');b['preparations']=b['trace_entries']+b['fallbacks']-1;b['releases']=b['preparations']+b['nx_entries']
    _,b=add('chain_release_conservation');b['releases']+=1
    _,b=add('chain_generation_conservation');b['s0_generation']+=1
    _,b=add('chain_active_closed');b['s%d_phase'%b['active']]=6
    _,b=add('chain_closed_predecessor')
    for key in ('post_pc','query_pc'):b['s%d_%s'%(b['active']^1,key)]+=1
    need(len(trials)==CONTROL_COUNT,'six exact finite TRACE chain obligations')
    return trials
