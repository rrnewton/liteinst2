"""Linked release's positive-use prior cache, with exact occupancy lifecycle.

The unchanged old LS/true profile still requires demonstrated retirement.
This new profile declares closure for1..64 virgin slots as well as retired
slots. It grants no exhaustion credit to a virgin cache. Every surrounding
old run/publication/native/rseq/source/REP guard remains mandatory.
"""
import copy
from page_selected import need
import page_selected_run_reuse_ls_reports as prior

CONTROL_COUNT=10
ZERO_FIELDS=dict(retired_handle=4,retirement=27,rx=13,revoked=13,writable=13,cleanup=13)


def completed(run,reuse):
    if reuse['state'][2]:
        # Once retirement actually occurred, every old retirement/query,
        # completion, monotonic identity and capacity predicate applies.
        return dict(prior.reuse_completed(run,reuse),resident_slots=64,
                    retirement_coverage=True)
    # With no retirement, each installed slot was published in ascending order.
    # Completed quiescence issues its permit, and only a later selected claim
    # consumes it. Thus even exactly64 completed virgin slots cannot have had
    # a no-permit full miss: a non-hit would retire one and leave this branch.
    need(all(reuse[k]==0 for k in ('status','failure_code','detail_abs','detail_negative',
         'snapshot_result_abs','snapshot_result_negative')),
         'successful complete private reuse snapshot')
    c,a,i,h=(run[k]for k in ('cache','attempt','initialization','last_complete'))
    generation,completions,retirements,cursor,lookup,leased,pending=reuse['state']
    need(0<generation==c[4]==c[5]<=64 and retirements==cursor==0 and
         completions==run['completed_runs']==generation+c[7]==c[6] and
         c[8]==0 and [lookup,leased,pending]==[0,0,0],
         'exact unretired cache generation, completion, capacity and quiet state')
    handle,done=reuse['current'],reuse['last_completed']
    need(handle[0]==1 and 0<=handle[1]<64 and 0<handle[2]<=generation and
         0<handle[3]<=c[6] and done==[completions,run['copied_instructions'],
             1,handle[2],i[7]+handle[1]*4096,h[19],h[6],h[7]],
         'last completion binds actual value handle, generation, entry, fresh borrow and plan')
    need(handle[2]==handle[1]+1,
         'unretired physical slot retains its exact initial publication generation')
    need(a[6]==0,'completed virgin cache cannot report a no-permit capacity miss')
    p=run['publication']
    need(handle==[1,a[12],p[5],a[0]] and done[4]==p[7],
         'last successful current publication, handle and completion agree exactly')
    need(a[5] or p[5]==generation,
         'new publication receives the last monotonic generation; hit retains its actual generation')
    for key,size in ZERO_FIELDS.items():
        need(reuse[key]==[0]*size,'unretired cache has whole-zero '+key)
    return dict(cache_pages=64,resident_slots=generation,generations=generation,
        completed_runs=completions,copied_instructions=run['copied_instructions'],retirements=0,
        hits=c[7],capacity_misses=0,last_generation=handle[2],last_retired_generation=0,
        last_retirement_completed=False,pending_lookup=0,active_lease=0,pending_reset=0,
        source_byte_limit=15,instruction_limit=14,generated_byte_limit=29,
        retirement_coverage=False)


def mutations(run,reuse):
    """Ten actual report mutations; original report controls remain separate."""
    trials=[]
    def item(name):
        a,b=copy.deepcopy(run),copy.deepcopy(reuse);trials.append((name,a,b));return a,b
    _,b=item('prior_cache_cursor');b['state'][3]^=1
    _,b=item('prior_cache_retirement_count');b['state'][2]+=1
    for key in ZERO_FIELDS:
        _,b=item('prior_cache_'+key);b[key][0]^=1
    a,b=item('prior_cache_capacity_accounting')
    a['cache'][8]+=1
    if reuse['state'][2]==0:
        # Preserve the old attempts=generations+hits+misses identity and all
        # current aliases; only the impossible no-permit miss before any retirement remains.
        a['cache'][6]+=1;a['attempt'][0]+=1;b['current'][3]+=1
    a,b=item('prior_cache_slot_generation')
    if reuse['state'][2]==0 and reuse['current'][1]!=0 and run['cache'][7]>0:
        # Preserve the old hit/publication/last-completion aliases while
        # claiming the current generation belongs to a different virgin slot.
        a['attempt'][5]=1;a['attempt'][12]=0;a['publication'][7]=a['initialization'][7]
        b['current'][1]=0;b['last_completed'][4]=a['initialization'][7]
    else:
        # The positive-retirement branch retains its unchanged strict handle
        # allocation check; no mutation is labelled refused without checking.
        b['current'][0]=2
    need(len(trials)==CONTROL_COUNT,'ten separate prior-cache contract mutations')
    return trials
