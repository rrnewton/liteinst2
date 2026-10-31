"""Typed preedge original26 terminal composition; no whole-profile credit.

The actual owner record and native frame comparison remain separate mandatory
checks. All old report readers stay unchanged; each new row is joined to the
actual protected snapshot before any successful completion is credited.
"""
import copy
import json
from page_selected import need
import current_custody_reports as current
import scalar_reuse_reports as reuse
import scalar_reuse_performance_reports as scalar_current
import unrolled_hash_app_reports as application
import linked_epoch_cache_reports as prior_cache
import scalar_span_trace_repeat_reports as prior_repeat
import scalar_span_trace_chain_reports as prior_chain
import linked_epoch_base_reports as linked_base
import linked_epoch_terminal as terminal
import page_selected_chain_compare as chain

old,maps_view,cost,unrolled=reuse.prior,reuse.maps_view,reuse.cost,reuse.unrolled
H=reuse.H
PREFIX=b'LI2_LINKED_PREEDGE '
REUSE_PREFIX=b'LI2_LINKED_PREEDGE_REUSE '
KEYS=('version status failure_code detail_abs detail_negative initialized first_error used offers closed '
      'resumed refaults hash_misses candidates source_misses plan_misses capacity_misses publications hits entries '
      'completed unexpected events plan_checks rseq_checks live_checks proof_checks active busy decoding closing resuming '
      'transfer signals refusals exit_indices current').split()
ARRAYS=dict(transfer=21,signals=5,refusals=4,exit_indices=8,current=37)
OUTCOME=('status','failure_code','detail_abs','detail_negative')
LINKED_ROW_REFUSALS=62
REFAULT_ROW_REFUSALS=8
CURRENT_ROW_REFUSALS=26
NATIVE_ROW_REFUSALS=20
CONTROL_COUNTS={(m,0):(298 if m in(2,3)else 318)for m in range(6)}
CONTROL_COUNTS.update({(0,1):298,(5,2):298,(0,3):298,(0,4):298,(6,0):318})
REFAULT_CONTROL_COUNTS={k:298 for k in(1,2,3,4)}
HINT_FAILURE_CONTROL_COUNTS={k:298 for k in(1,2,3)}
HINT_TERMINAL_CONTROL_COUNT=41


HINT_LINKED_KEYS=terminal.HINT_LINKED_KEYS[:terminal.HINT_LINKED_KEYS.index('active')]+['cut_exits']+terminal.HINT_LINKED_KEYS[terminal.HINT_LINKED_KEYS.index('active'):]
PREEDGE_TERMINAL_CONTROL_COUNT=3
CUT_ERROR='actual v2 cut exits are a subset of real completions'

def split_hint(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete explicit native-hint terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>3 and lines[-3].startswith(REUSE_PREFIX)and lines[-2].startswith(PREFIX)and
         lines[-1].startswith(terminal.HINT_PREFIX)and
         all(sum(x.startswith(prefix)for x in lines)==1 for prefix in(REUSE_PREFIX,PREFIX,terminal.HINT_PREFIX))and
         all(len(x)<=4096 and b'\r'not in x for x in lines[-3:])and
         not any(x.startswith((terminal.PREFIX,terminal.REUSE_PREFIX))for x in lines),
         'one final linked-reuse, linked and native-hint row in actual source order')
    decode=maps_view.pair.pair_reports.rseq.decode
    linked=decode(lines[-2][len(PREFIX):]);retirement=decode(lines[-3][len(REUSE_PREFIX):])
    hint=decode(lines[-1][len(terminal.HINT_PREFIX):])
    need(type(linked)is dict and list(linked)==HINT_LINKED_KEYS and
         all(type(linked[k])is int and 0<=linked[k]<1<<64 for k in HINT_LINKED_KEYS if k not in ARRAYS),
         'complete ordered unsigned native-hint linked schema')
    for key,size in ARRAYS.items():
        need(type(linked[key])is list and len(linked[key])==size and
             all(type(x)is int and 0<=x<1<<64 for x in linked[key]),'whole unsigned native-hint linked '+key)
    need(type(retirement)is dict and list(retirement)==reuse.KEYS and
         all(type(retirement[k])is int and 0<=retirement[k]<1<<64 for k in reuse.KEYS),
         'complete ordered unsigned native-hint linked-reuse schema')
    need(type(hint)is dict and list(hint)==terminal.HINT_KEYS and
         all(type(hint[k])is int and 0<=hint[k]<1<<64 for k in terminal.HINT_KEYS),
         'complete ordered unsigned actual27-field native-hint schema')
    need(linked['version']==retirement['version']==2 and hint['version']==1 and linked['status']in(0,125)and
         all(linked[k]in(0,1)for k in('detail_negative','initialized','active','busy','decoding','closing','resuming'))and
         all(retirement[k]in(0,1)for k in('detail_negative','pending','retiring'))and retirement['cursor']<64 and
         all(hint[k]in(0,1)for k in('ready','pending','outcome_complete','current_checked','current_hit')),
         'exact full preedge v2 versions, actual outcome, literal flags and bounded cursor')
    need(all(linked[k]==retirement[k]for k in OUTCOME)and
         all(linked[k]==hint[k]for k in('status','failure_code')),
         'all native-hint rows retain one actual terminal outcome')
    for row,prefix,line in((linked,PREFIX,lines[-2]),(retirement,REUSE_PREFIX,lines[-3]),(hint,terminal.HINT_PREFIX,lines[-1])):
        need(prefix+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==line,
             'canonical complete native-hint terminal row')
    return linked,retirement,hint,b'\n'.join(lines[:-3])+b'\n'


def split(stderr):
    linked,retirement,_,suffix=split_hint(stderr)
    return linked,retirement,suffix

def prior_scalar(row,retirement):
    """The old owner stays completed/quiet even when a distinct span fails.

    Its global outcome is joined separately, never rewritten to zero. These
    are the unchanged old successful ownership equations without attributing
    the new owner's global terminal outcome to the quiet old owner.
    """
    need(row['first_error']==row['active']==row['busy']==row['decoding']==row['unexpected']==
         retirement['pending']==retirement['retiring']==0 and row['initialized']==1,
         'prior scalar owner is initialized and quiet')
    need(row['events']==sum(row['signals'])>0 and all(row['signals'][i]>0 for i in (0,1,2))and
         row['signals'][3:]==[0,0],'complete actual prior scalar handler population')
    need(0<row['used']==min(row['publications'],64) and
         row['candidates']==row['source_misses']+row['plan_misses']+row['capacity_misses']+
             row['publications']+row['hits'] and row['plan_misses']==sum(row['refusals']) and
         row['entries']==row['publications']+row['hits']==row['completed']==sum(row['exit_indices']) and
         row['plan_checks']==row['publications']+2*row['entries']+retirement['retirement_attempts'] and
         row['rseq_checks']==row['publications']+3*row['entries'],
         'all prior scalar candidates, static proofs, live guards and original exits close')
    need(retirement['generation']==row['publications'] and
         retirement['retirement_attempts']==retirement['retirements']==row['publications']-row['used'] and
         retirement['claims']==retirement['permits_issued']==row['completed'] and
         retirement['cursor']==retirement['retirements']%64,
         'prior scalar monotonic generations and actual completed permits')
    scalar_current.current(row)


def chain_quiet(loader,c,linked,control,refault_control=0,hint_control=0):
    # nx_entries counts the ordinary segment's NX start, before its TRACE close.
    # A successful retry's later hardware NX is proved by the raw mode5 witness.
    held=int(control in(2,3))+int(refault_control in(1,3,4))+int(bool(hint_control))
    graph=linked.get('graph_refaults',0)
    need(c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['sequence']==c['trace_entries']>0 and
         linked['offers']==linked['closed']==linked['entries']+linked['resumed']+linked['refaults']+graph+held and
         c['nx_entries']==c['fallbacks']+linked['entries']+linked['refaults']+graph+held and
         c['trace_entries']+c['fallbacks']<=c['preparations']<=2*(c['trace_entries']+c['fallbacks']) and
         c['releases']==c['preparations']+c['nx_entries'] and c['nx_entries']<=loader['nx_faults'],
         'exact finite linked closed, consumed, resumed and held segment partition')
    slots=[chain.slot(c,i)for i in (0,1)]
    need(sum(x['generation']for x in slots)==c['attempts']+c['fallbacks'],
         'every actual ordinary chain_next retains its generation')
    for x in slots:
        pc,n=x['pc'],x['length']
        need(x['phase']==5 and x['origin']in(1,2)and x['fallback']==0 and
             x['prepare']==int(x['origin']==2)and x['prepared']==1 and
             x['generation']>0 and 0<x['event']<=c['event']and 0<pc<1<<64 and
             1<=n<=15 and pc<=(1<<64)-1-n and x['owner_phase']==5 and
             x['owner_error']==x['unexpected']==x['held']==x['fetch_error']==0 and
             x['borrow']>0 and x['validations']>0 and
             x['trace']==x['query']==x['queried']==x['release']==x['released']==1 and
             x['post_pc']==x['query_pc']>0,
             'finite linked retains both fully closed actual ordinary owners')
        mask=1 if pc//4096==(pc+n-1)//4096 else 3
        need(x['open']==x['opened']==x['revoke']==x['revoked']==mask,
             'both exact ordinary page masks are revoked before linked/fallback dispatch')
    active=slots[c['active']];chain.same_slot(loader,active)
    need(loader['tf_pc']==active['pc']and loader['tf_length']==active['length']and loader['tf_code']==active['code'],
         'actual rich LOADER selects the retained CLOSED ordinary owner')
    return dict(consumed_epochs=linked['entries'],resumed=linked['resumed'],refaults=linked['refaults'],held_failed=held,
        truncated_retries=c['preparations']-c['trace_entries']-c['fallbacks'])


def chain_completed(loader,c,linked):
    need(all(c[k]==linked[k]==loader[k]==0 for k in OUTCOME)and linked['entries']==linked['completed'],
         'completed finite linked never reclassifies failed execution')
    return chain_quiet(loader,c,linked,0)


def completed_tls(parsed):
    # Native-pair seed/refresh calls tls_observe regardless of registration.
    # At completed exit the last pair is closed; its final refresh is the last
    # TLS observation. The complete two rows also join protected actual bytes.
    tls=parsed['rseq']['tls'];pair=parsed['native_pair']['rseq']
    need(tls[:6]==[1,1,0,0,0,0],
         'complete finite TLS observation regardless of rseq registration')
    need(pair[0]==1 and pair[15]>0 and tls[6:]==pair[27:29],
         'finite terminal TLS equals the actual final native-pair refresh')


def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    native_hint=owner.get('native_hint',False);hint_control=owner.get('hint_control',0)
    need(native_hint is True and type(hint_control)is int and hint_control in range(4)and
         (not hint_control or(native_hint and mode==0 and owner['control']==owner.get('refault_control',0)==0)),
         'exact distinct native-hint finite profile and advisory selector')
    refault_control=owner.get('refault_control',0)
    need(type(refault_control)is int and refault_control in range(5)and
         (not refault_control or(mode==0 and owner['control']==0)),
         'distinct required-refault selector only on the completed mode0 focal graph')
    need(type(mode)is int and mode in range(7)and type(owner['control'])is int and
         (mode,owner['control'])in CONTROL_COUNTS and exit_status==(125 if mode in(2,3)or owner['control']or refault_control or hint_control else 0),
         'exact original six modes, reuse65, four owner and four distinct helper failures')
    if native_hint:
        span,retirement,hint,suffix=split_hint(stderr);terminal.hint_counts(span,hint)
        if exit_status==0:terminal.hint_refault_completed(span,hint)
        elif hint_control:terminal.hint_required(span,hint,hint_control)
        elif refault_control:terminal.refault_required(span,refault_control)
    else:
        span,retirement,suffix=split(stderr)
        terminal.refault_count(span)
        if exit_status==0:terminal.refault_completed(span)
        elif refault_control:terminal.refault_required(span,refault_control)
    need(span['cut_exits']<=span['completed'],CUT_ERROR)
    scalar,scalar_retirement,suffix=reuse.split(suffix)
    row,suffix=unrolled.split(suffix);current_row,suffix=current.split_current(suffix)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    if exit_status==0:completed_tls(parsed)
    _,same,gate=linked_base.gate(parsed,pid,exit_status,parent,0,cache_completed=prior_cache.completed,
        chain_closure=lambda loader,c:chain_completed(loader,c,span))
    need(same is parsed and all(all(value[k]==parsed['loader'][k]for k in OUTCOME)
         for value in (span,retirement,scalar,scalar_retirement,row))and
         current_row['status']==exit_status and current_row['failure_code']==parsed['loader']['failure_code'],
         'every complete terminal row preserves the actual outcome')
    parsed.update(linked_preedge=span,linked_preedge_reuse=retirement,current_tf=current_row,
                  scalar_region=scalar,scalar_reuse=scalar_retirement,unrolled=row)
    if native_hint:
        parsed['native_hint']=hint;terminal.hint_native(span,hint,parsed,finite=True)
        joined=owner_reader.terminal(parsed,owner,native_hint=True)
    else:joined=owner_reader.terminal(parsed,owner)
    chain_quiet(parsed['loader'],parsed['chain'],span,owner['control'],refault_control,hint_control)
    reuse.prior_unrolled(row);prior_scalar(scalar,scalar_retirement)
    # Span preentry precedes both old observers. A required fault/nested event
    # terminates there, so exactly that final event never reaches either old
    # counter. Successful exits return from preentry and reach all observers.
    expected_signals=list(row['signals'])
    interrupted=int(exit_status==125 and not refault_control and not hint_control and(owner['control']==1 or not owner['control']))
    if interrupted:expected_signals[int(owner['control']==1)]+=1
    need(scalar['events']==row['events'] and scalar['signals']==row['signals']and
         span['events']==row['events']+interrupted and span['signals']==expected_signals,
         'exact preentry-order signal partition including the nonreturning final span event')
    need(current_row['first_error']==current_row['first_detail_abs']==current_row['first_detail_negative']==0,
         'current custody stayed error-free before the distinct focal span outcome')
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=linked_base.repeat_completed(parsed,pid,images,image_bytes,carrier,carrier_bytes),
        input_authentication=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),maps_view=view,
        terminal_join=joined,required_refusal=int(exit_status==125),whole_program_qualification=False)
    if exit_status==0:
        reuse.scalar_completed(scalar,scalar_retirement);unrolled.completed(row,False)
        summary.update(lease=old.lease.counters(parsed),trace_run=old.trace_completed(parsed),
            native_pair=old.pair_completed(parsed,pid),cache_reuse=prior_cache.completed(parsed['run'],parsed['reuse']))
        # Original16 has18 fixed direct calls plus7 per invocation and6 real
        # lifecycle calls in mode5:25 or66. Separate reuse65 has14 prefix,
        #65*7 invocation and4 cleanup/suffix calls:473. All retain67 CPUID;
        # native-only signal setup never runs gated.
        linked_base.application_effect_exit(parsed,mode)
    else:
        need(gate['original_completed_rejected']is True and
             span['first_error']==span['failure_code']==owner['outcome']['failure_code']>0,
             'actual failed span keeps its first error and original completion refusal')
    return parsed,summary


def chain_mutations(loader,c):
    rows=prior_chain.mutations(loader,c)
    name,a,b=rows[-1]
    need(name=='chain_closed_predecessor','literal inherited sixth stimulus')
    a,b=copy.deepcopy(loader),copy.deepcopy(c)
    b['preparations']=2*(b['trace_entries']+b['fallbacks'])+1
    b['releases']=b['preparations']+b['nx_entries']
    return rows[:-1]+[('chain_retry_upper',a,b)]


def controls(stderr,*args):
    """Original65/67 report mutations plus fixed59 span and26 current rows."""
    parsed,_=check(stderr,*args);native_hint=args[-3].get('native_hint',False)
    if native_hint:span,retirement,hint,suffix=split_hint(stderr)
    else:span,retirement,suffix=split(stderr)
    scalar,scalar_retirement,suffix=reuse.split(suffix);row,suffix=unrolled.split(suffix)
    current_row,suffix=current.split_current(suffix);view,original=maps_view.split_report(suffix,'maintained')
    lines=stderr[:-1].split(b'\n');trials=[];specific=set();new=[];current_trials=[]
    def changed(name,prefix,record,dest=trials):
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied report target');data=list(lines)
        data[places[0]]=prefix+json.dumps(record,separators=(',',':'),allow_nan=False).encode()
        dest.append((name,b'\n'.join(data)+b'\n'))
    def removed(prefix):return b'\n'.join(x for x in lines if not x.startswith(prefix))+b'\n'
    for key in ('version','status','failure_code','first_error','initialized','entries','completed','used','events','plan_checks','rseq_checks','decoding'):
        value=copy.deepcopy(scalar);value[key]^=1;changed('scalar_'+key,reuse.old.PREFIX,value)
    for key in ('signals','refusals','exit_indices','current'):
        value=copy.deepcopy(scalar);value[key][0]^=1;changed('scalar_'+key,reuse.old.PREFIX,value)
    for key in ('version','status','failure_code','first_error','initialized','observe_only','entries','completed','used','events'):
        value=copy.deepcopy(row);value[key]^=1;changed('unrolled_'+key,unrolled.PREFIX,value)
    for key in ('signals','current'):
        value=copy.deepcopy(row);value[key][0]^=1;changed('unrolled_'+key,unrolled.PREFIX,value)
    for key in ('version','enabled','differential','poisoned','reserved','mismatches','queries','comparisons'):
        value=dict(view);value[key]^=1;changed('maps_'+key,maps_view.PREFIX,value)
    for name,key,field,index in (('pair_slot','native_pair','slots',(0,5)),
         ('pair_live','native_pair','control',6),('pair_closes','native_pair','counts',3),
         ('rseq_pin','rseq','identity',1),('rseq_epoch','rseq','owner',13),
         ('unused_owner','repeat_lease','owner',0),('unused_source','repeat_lease','source',0),
         ('unused_frame','repeat_lease','frames',0),('unused_custody','repeat_lease','custody',4)):
        value=copy.deepcopy(parsed[key]);target=value[field][index[0]]if type(index)is tuple else value[field]
        at=index[1]if type(index)is tuple else index;target[at]^=1
        prefix={'native_pair':b'LI2_NATIVE_PAIR ','rseq':b'LI2_RSEQ ','repeat_lease':b'LI2_REPEAT_LEASE '}[key]
        changed(name,prefix,value)
    if parsed['loader']['status']==0:
        for name,add,subtract in (('publication_cpuid_syscall','cpuid_patches','syscall_patches'),
                                 ('publication_syscall_rdtsc','syscall_patches','rdtsc_patches')):
            value=copy.deepcopy(parsed['oneshot']);need(value[subtract]>0,'actual positive class for supplied redistribution')
            value[add]+=1;value[subtract]-=1;changed(name,b'LI2_ONESHOT ',value);specific.add(name)
    scalar_line=next(x for x in lines if x.startswith(reuse.old.PREFIX))
    reuse_line=next(x for x in lines if x.startswith(reuse.PREFIX))
    trials.extend([('truncated',stderr[:-1]),('duplicate_scalar',stderr+scalar_line+b'\n'),
        ('missing_scalar',removed(reuse.old.PREFIX)),('missing_maps',removed(maps_view.PREFIX))])
    for key in reuse.KEYS:
        value=dict(scalar_retirement);value[key]^=1;changed('reuse_'+key,reuse.PREFIX,value)
    reordered=list(lines);at=reordered.index(reuse_line);need(reordered[at+1]==scalar_line,'actual old ordered adjacent rows')
    reordered[at:at+2]=[scalar_line,reuse_line]
    trials.extend([('duplicate_reuse',stderr+reuse_line+b'\n'),('missing_reuse',removed(reuse.PREFIX)),
        ('reordered_complete_rows',b'\n'.join(reordered)+b'\n')])
    legacy=67 if parsed['loader']['status']==0 else 65
    need(len(trials)==legacy,'every original scalar/reuse terminal refusal retained')
    for key in KEYS:
        value=copy.deepcopy(span)
        if key in ARRAYS:value[key][0]^=1
        else:value[key]^=1
        changed('linked_'+key,PREFIX,value,new)
    for key in reuse.KEYS:
        value=dict(retirement);value[key]^=1;changed('linked_reuse_'+key,REUSE_PREFIX,value,new)
    tail=3 if native_hint else 2
    for prefix,label,line in ((PREFIX,'span',lines[-tail+1]),(REUSE_PREFIX,'span_reuse',lines[-tail])):
        new.extend([(label+'_missing_row',removed(prefix)),(label+'_duplicate_row',stderr+line+b'\n')])
    order=list(lines);order[-tail],order[-tail+1]=order[-tail+1],order[-tail]
    new.append(('span_row_order',b'\n'.join(order)+b'\n'))
    for name,value in (('bool',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        v=dict(span);v['offers']=value;changed('span_type_'+name,PREFIX,v,new)
    v=dict(span);del v['first_error'];changed('span_missing_key',PREFIX,v,new)
    changed('span_key_order',PREFIX,dict(reversed(list(span.items()))),new)
    coherent=list(lines)
    for prefix,record in ((reuse.old.PREFIX,scalar),(unrolled.PREFIX,row)):
        value=copy.deepcopy(record);value['events']+=1;value['signals'][0]+=1
        at=next(i for i,line in enumerate(lines)if line.startswith(prefix))
        coherent[at]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
    new.append(('preentry_coherent_old_population',b'\n'.join(coherent)+b'\n'))
    need(len(new)==LINKED_ROW_REFUSALS,'all62 linked report refusals, retaining the original61')
    for key in current.CURRENT_KEYS:
        v=dict(current_row);v[key]^=1;changed('current_'+key,current.CURRENT_PREFIX,v,current_trials)
    for name,value in (('bool',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        v=dict(current_row);v['attempts']=value;changed('current_type_'+name,current.CURRENT_PREFIX,v,current_trials)
    v=dict(current_row);del v['first_error'];changed('current_missing_key',current.CURRENT_PREFIX,v,current_trials)
    v=dict(current_row);v['extra']=0;changed('current_extra_key',current.CURRENT_PREFIX,v,current_trials)
    changed('current_key_order',current.CURRENT_PREFIX,dict(reversed(list(current_row.items()))),current_trials)
    current_trials.extend([('current_absent',removed(current.CURRENT_PREFIX)),('current_duplicate',lines[0]+b'\n'+stderr),
        ('current_misplaced',b'\n'.join([lines[1],lines[0]]+lines[2:])+b'\n'),
        ('current_truncated',stderr[:-1]),('current_duplicate_key',lines[0][:-1]+b',"version":1}\n'+b'\n'.join(lines[1:])+b'\n')])
    need(len(current_trials)==CURRENT_ROW_REFUSALS,'all26 additional current-row refusals')
    # Every emitted native field is joined to the actual protected terminal
    # observation. Keep this population separate from all original controls.
    native_trials=[]
    need(len(parsed['native'])==NATIVE_ROW_REFUSALS,'all20 actual native terminal fields')
    for key in parsed['native']:
        value=copy.deepcopy(parsed['native'])
        if key=='revisit_ns':
            if value[key]:value[key][0]^=1
            else:value[key]=[1]
        else:value[key]^=1
        changed('native_'+key,b'LI2_NATIVE ',value,native_trials)
    # Also require each native field to reach the full protected equality,
    # even if its raw report mutation is rejected earlier by a schema gate.
    def protected_refusal(key,value):
        v=dict(parsed);v[key]=value;caught=False
        try:args[-2].terminal(v,args[-3],**(dict(native_hint=True)if native_hint else{}))
        except ValueError as error:caught=str(error)=='entire actual protected '+('reuse 'if args[-1]==6 else'')+'terminal row '+key
        need(caught,'every supplied '+key+' field reaches its full protected equality')
    for _,data in native_trials:
        line=next(x for x in data.splitlines()if x.startswith(b'LI2_NATIVE '))
        protected_refusal('native',json.loads(line[len(b'LI2_NATIVE '):]))
    chain_trials=[]
    need(len(parsed['chain'])==prior_chain.ROW_CONTROL_COUNT,'all88 actual chain/slot/lease terminal fields')
    for key in parsed['chain']:
        value=dict(parsed['chain']);value[key]='invalid_scope'if key=='scope'else value[key]^1
        protected_refusal('chain',value)
        changed('chain_field_'+key,b'LI2_CHAIN ',value,chain_trials)
    structural_trials=[]
    if parsed['loader']['status']==0:
        for name,loader_value,chain_value in chain_mutations(parsed['loader'],parsed['chain']):
            caught=False
            try:chain_completed(loader_value,chain_value,span)
            except ValueError:caught=True
            need(caught,'new finite TRACE conservation predicate refuses '+name)
            data=list(lines)
            for prefix,value in ((b'LI2_LOADER ',loader_value),(b'LI2_CHAIN ',chain_value)):
                at=next(i for i,line in enumerate(data)if line.startswith(prefix))
                data[at]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
            structural_trials.append((name,b'\n'.join(data)+b'\n'))
    need(len(chain_trials)==prior_chain.ROW_CONTROL_COUNT and
         len(structural_trials)==(prior_chain.CONTROL_COUNT if parsed['loader']['status']==0 else 0),
         'every chain field and each applicable finite conservation obligation')
    cache_trials=[]
    if parsed['loader']['status']==0:
        for name,run_value,reuse_value in prior_cache.mutations(parsed['run'],parsed['reuse']):
            data=list(lines)
            for prefix,value in ((b'LI2_RUN ',run_value),(b'LI2_RUN_REUSE ',reuse_value)):
                places=[i for i,line in enumerate(data)if line.startswith(prefix)]
                need(len(places)==1,'one actual old-cache supplied target')
                data[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
            cache_trials.append((name,b'\n'.join(data)+b'\n'))
    need(len(native_trials)==NATIVE_ROW_REFUSALS and
         len(cache_trials)==(prior_cache.CONTROL_COUNT if parsed['loader']['status']==0 else 0),
         'all actual native fields and applicable finite prior-cache obligations')
    tls_trials=[];tls_errors={}
    if parsed['loader']['status']==0:
        for name,index,error in (
            ('finite_tls_observation',0,'complete finite TLS observation regardless of rseq registration'),
            ('finite_tls_final_refresh',6,'finite terminal TLS equals the actual final native-pair refresh')):
            value=copy.deepcopy(parsed['rseq']);value['tls'][index]^=1
            changed(name,b'LI2_RSEQ ',value,tls_trials);tls_errors[name]=error
    need(len(tls_trials)==(2 if parsed['loader']['status']==0 else 0),
         'both source-causal completed TLS observation and final refresh refusals')
    refault_trials=[];refault_errors={}
    for field,indices in (('transfer',range(19,21)),('current',range(34,37))):
        for index in indices:
            value=copy.deepcopy(span);value[field][index]^=1
            changed('refault_'+field+'_'+str(index),PREFIX,value,refault_trials)
    need(len(refault_trials)==terminal.REFAULT_FIELD_CONTROL_COUNT,
         'all five appended refault fields receive actual-row mutations')
    for name,value,error in terminal.refault_causal_mutations(span):
        # The successful pure predicate gives each new causal mutation its
        # own exact reason. Failed prefixes retain the full raw-owner join.
        if parsed['loader']['status']==0 or name=='refault_above_relocation':
            caught=False
            try:
                if name=='refault_above_relocation':terminal.refault_count(value)
                else:terminal.refault_completed(value)
            except ValueError as exc:caught=str(exc)==error
            need(caught,'exact terminal refault causal refusal '+name)
            refault_errors[name]=error
        changed(name,PREFIX,value,refault_trials)
    value=terminal.refault_chain_mutation(span);caught=False
    try:chain_quiet(parsed['loader'],parsed['chain'],value,args[-3]['control'],args[-3].get('refault_control',0),args[-3].get('hint_control',0))
    except ValueError as exc:
        caught=str(exc)=='exact finite linked closed, consumed, resumed and held segment partition'
    need(caught,'an extra completed refault requires its already-started ordinary NX chain segment')
    changed('refault_missing_nx',PREFIX,value,refault_trials)
    need(len(refault_trials)==REFAULT_ROW_REFUSALS,
         'five fields, two phase/class causes and one exact NX-partition refusal')
    repeat_trials=[]
    for name,value in prior_repeat.mutations(parsed):changed(name,b'LI2_REPEAT_LEASE ',value,repeat_trials)
    need(len(repeat_trials)==29,'all29 prior completed REP controls')
    all_trials=trials+new+current_trials+native_trials+cache_trials+chain_trials+structural_trials+tls_trials+refault_trials+repeat_trials
    need(len(all_trials)==len({n for n,_ in all_trials})==(HINT_FAILURE_CONTROL_COUNTS[args[-3]['hint_control']]if args[-3].get('hint_control',0)else REFAULT_CONTROL_COUNTS[args[-3]['refault_control']]if args[-3].get('refault_control',0)else CONTROL_COUNTS[(args[-1],args[-3]['control'])]),
         'complete exact finite terminal-control population')
    names=[]
    for name,data in all_trials:
        rejected=False
        try:check(data,*args)
        except ValueError as error:
            if name in refault_errors:rejected=str(error)==refault_errors[name]
            elif name in tls_errors:rejected=str(error)==tls_errors[name]
            elif name=='preentry_coherent_old_population':
                rejected=str(error)=='exact preentry-order signal partition including the nonreturning final span event'
            else:rejected=name not in specific or str(error)=='exact application publication and unpatched class accounting'
        need(rejected,'complete TRACE terminal reader refuses '+name);names.append(name)
    return dict(refusals=names,legacy_refusals=names[:legacy],linked_refusals=names[legacy:legacy+LINKED_ROW_REFUSALS],
        current_row_refusals=names[legacy+LINKED_ROW_REFUSALS:legacy+LINKED_ROW_REFUSALS+CURRENT_ROW_REFUSALS],
        native_refusals=names[legacy+LINKED_ROW_REFUSALS+CURRENT_ROW_REFUSALS:legacy+LINKED_ROW_REFUSALS+CURRENT_ROW_REFUSALS+NATIVE_ROW_REFUSALS],
        prior_cache_refusals=[name for name,_ in cache_trials],
        chain_row_refusals=[name for name,_ in chain_trials],chain_refusals=[name for name,_ in structural_trials],
        finite_tls_refusals=[name for name,_ in tls_trials],
        refault_refusals=[name for name,_ in refault_trials],
        prior_repeat_refusals=names[-29:],native_operations=0,original_stderr_sha256=H(stderr))


def hint_controls(stderr,*args):
    """Additional actual hint report/typed schema/causal partition refusals."""
    parsed,_=check(stderr,*args);need(args[-3].get('native_hint')is True,'explicit hint terminal controls')
    linked,retirement,hint,suffix=split_hint(stderr);lines=stderr[:-1].split(b'\n');trials=[]
    def change(name,rows):
        changed=list(lines)
        for prefix,value in rows:
            at=[i for i,x in enumerate(changed)if x.startswith(prefix)];need(len(at)==1,'one actual hint mutation row')
            changed[at[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(changed)+b'\n'))
    for key in terminal.HINT_KEYS:
        value=dict(hint);value[key]^=1
        p=dict(parsed,native_hint=value);caught=False
        try:args[-2].terminal(p,args[-3],native_hint=True)
        except ValueError as exc:caught=str(exc)=='entire actual protected '+('reuse 'if args[-1]==6 else'')+'terminal row native_hint'
        need(caught,'every actual hint field reaches its complete protected equality')
        change('hint_field_'+key,[(terminal.HINT_PREFIX,value)])
    value=copy.deepcopy(linked);value['graph_refaults']+=1;change('graph_refaults_field',[(PREFIX,value)])
    for name,value in(('bool',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        row=dict(hint);row['lookups']=value;change('hint_type_'+name,[(terminal.HINT_PREFIX,row)])
    row=dict(hint);del row['ready'];change('hint_missing_key',[(terminal.HINT_PREFIX,row)])
    row=dict(hint);row['extra']=0;change('hint_extra_key',[(terminal.HINT_PREFIX,row)])
    change('hint_key_order',[(terminal.HINT_PREFIX,dict(reversed(list(hint.items()))))])
    trials.extend([('hint_missing_row',b'\n'.join(lines[:-1])+b'\n'),
                   ('hint_duplicate_row',stderr+lines[-1]+b'\n'),
                   ('hint_row_order',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n')])
    row=copy.deepcopy(linked);row['graph_refaults']=row['refusals'][2]+1;caught=False
    try:terminal.hint_counts(row,hint)
    except ValueError as exc:caught=str(exc)==terminal.HINT_CLASS_ERROR
    need(caught,'source-causal GRAPH count refusal');change('hint_above_graph',[(PREFIX,row)])
    value=dict(hint);value['publications']+=1;caught=False
    try:terminal.hint_counts(linked,value)
    except ValueError as exc:caught=str(exc)==terminal.HINT_LIFETIME_ERROR
    need(caught,'source-causal one-use receipt conservation');change('hint_unaccounted_publication',[(terminal.HINT_PREFIX,value)])
    row=copy.deepcopy(linked);value=dict(hint)
    for key in('offers','closed','candidates','graph_refaults','plan_misses'):row[key]+=1
    row['refusals'][2]+=1
    for key in('lookups','hits','next_nx','admitted','publications','receipt_publication'):value[key]+=1
    terminal.hint_counts(row,value);caught=False
    try:chain_quiet(parsed['loader'],parsed['chain'],row,args[-3]['control'],args[-3].get('refault_control',0),args[-3].get('hint_control',0))
    except ValueError as exc:caught=str(exc)=='exact finite linked closed, consumed, resumed and held segment partition'
    need(caught,'additional GRAPH completion requires its already-started ordinary NX segment')
    change('hint_missing_segment',[(PREFIX,row),(terminal.HINT_PREFIX,value)])
    need(len(trials)==len({name for name,_ in trials})==HINT_TERMINAL_CONTROL_COUNT,'fixed41 actual hint report refusals')
    names=[]
    for name,data in trials:
        rejected=False
        try:check(data,*args)
        except ValueError:rejected=True
        need(rejected,'complete hinted finite reader refuses '+name);names.append(name)
    return dict(hint_refusals=names,native_operations=0,original_stderr_sha256=H(stderr))


def preedge_controls(stderr,*args):
    """Separate typed-v2 report mutations; the old populations stay intact."""
    parsed,_=check(stderr,*args)
    linked,retirement,hint,_=split_hint(stderr);lines=stderr[:-1].split(b'\n');trials=[]
    def add(name,rows,error):
        data=list(lines)
        for prefix,value in rows:
            places=[i for i,x in enumerate(data)if x.startswith(prefix)]
            need(len(places)==1,'one actual typed report target')
            data[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(data)+b'\n',error))
    row=copy.deepcopy(linked);row['cut_exits']^=1
    p=dict(parsed,linked_preedge=row);caught=False
    try:args[-2].terminal(p,args[-3],native_hint=True)
    except ValueError as exc:caught=str(exc)=='entire actual protected '+('reuse 'if args[-1]==6 else'')+'terminal row linked_preedge'
    need(caught,'actual cut count joins the complete protected terminal row')
    add('actual_cut_exits',[(PREFIX,row)],None)
    row=copy.deepcopy(linked);row['cut_exits']=row['completed']+1
    add('cut_exits_above_completed',[(PREFIX,row)],CUT_ERROR)
    row=copy.deepcopy(linked);other=dict(retirement);row['version']=other['version']=1
    add('coherent_v1_rows_not_v2',[(PREFIX,row),(REUSE_PREFIX,other)],
        'exact full preedge v2 versions, actual outcome, literal flags and bounded cursor')
    need(len(trials)==PREEDGE_TERMINAL_CONTROL_COUNT,'three separately counted typed terminal controls')
    refused=[]
    for name,data,error in trials:
        need(data!=stderr,'actual typed terminal mutation')
        try:check(data,*args)
        except ValueError as exc:
            if error is not None:need(str(exc)==error,'exact typed terminal causal error '+name)
            refused.append(name)
        else:raise ValueError('supplied typed terminal row accepted '+name)
    return dict(preedge_refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))
