"""Typed preedge-v2 release accounting with explicit prior-cache closure.

These rows are terminal observations, not protected records or full-frame
evidence. The separate finite graph, linked owner and 65-entry reuse prerequisites remain mandatory.
The old positive-activity current-custody profile is unchanged; TRACE can close
its predecessor before the old current-stage route is reached.
Absent seed or retained activity receives no current-custody optimization credit.
"""
import copy
import json
from page_selected import need
import current_custody_reports as current
import scalar_reuse_reports as reuse
import scalar_reuse_performance_reports as scalar
import linked_epoch_terminal as fixture
import linked_preedge_full_reports as preedge
import linked_epoch_cache_reports as cache_reports
import scalar_span_trace_release_chain as chain_reports
import linked_true_repeat_reports as true_repeat_reports

LINKED_CONTROL_COUNT=121
REFAULT_CONTROL_COUNT=3
CACHE_CONTROL_COUNT=10
CONTROL_COUNTS=dict(ls=371,true=529)
HINT_CONTROL_COUNT=41
HINT_CONTROL_COUNTS=dict(ls=412,true=570)
POSITIVE_TRUE_CONTROL_COUNTS=dict(ls=412,true=445)
CURRENT_CONTROL_COUNT=26
CHAIN_CONTROL_COUNT=11
SUPPLIED_LEASE_CONTROL_COUNT=2
PREEDGE_CONTROL_COUNT=8
PREEDGE_CONTROL_COUNTS=dict(ls=420,true=453)


def chain_completed(loader,c,span):
    graph=span.get('graph_refaults',0)
    need(all(c[k]==span[k]==loader[k]==0 for k in
         ('status','failure_code','detail_abs','detail_negative'))and
         c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['sequence']==c['trace_entries']>0 and
         span['offers']==span['closed']==span['entries']+span['resumed']+span['refaults']+graph and
         span['entries']==span['completed']>0 and
         c['nx_entries']==c['fallbacks']+span['entries']+span['refaults']+graph and
         c['nx_entries']<=loader['nx_faults'],
         'release TRACE exact consumed-span segment partition')
    need(c['trace_entries']+c['fallbacks']<=c['preparations']<=2*(c['trace_entries']+c['fallbacks']),
         'release TRACE exact truncated-retry preparation domain')
    need(c['releases']==c['preparations']+c['nx_entries'],
         'release TRACE every prepared and incoming NX borrow released')
    slots=[chain_reports.old.slot(c,i)for i in (0,1)]
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
            if start!=active['pc']:chain_reports.advanced_lease(c,active)
        selected=active
    chain_reports.old.same_slot(loader,selected)
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
        consumed_spans=span['entries'],resumed_spans=span['resumed'],refaults=span['refaults'],
        truncated_retries=c['preparations']-c['trace_entries']-c['fallbacks'],
        selected_slot=c['active']if active['phase']==5 else c['active']^1)


def current_completed(row):
    need(row['version']==1 and all(row[k]==0 for k in
         ('status','failure_code','first_error','first_detail_abs','first_detail_negative')),
         'complete successful current-custody counter outcome')
    a,s,n,f,r,c,k,x=(row[key]for key in
        ('attempts','current_stages','current_seeds','physical_fallbacks','retained_stages','retained_checks','commits','cancels'))
    need(a==s+f and s>=n and s+r==k+x and n<=k<=n+r and c==r+k-n and
         (n>0 or r==k==c==0),
         'all actual current stages, seeds, physical fallback, retained checks and terminal cancellations close')


def current_linked(row):
    c=row['current']
    if c[0]:
        need(c[0]==1 and c[1]<row['used'] and c[2:5]==[1,1,1] and c[5]<8 and
             c[6:14]==[1]*8 and c[14:20]==[0,0,1,1,0,0] and c[20:24]==[0]*4 and
             c[24:29]==[4096,4096,4096,0,1] and c[29:31]in([0,0],[1,1]) and c[31]==0 and
             c[32]&~0xffff==0 and c[32]&16==0 and c[33]&~0x8d5==0 and c[34:]==[0,0,0],
             'actual linked current completed and closed full image/source with bounded union effects')
    else:
        expected=[0]*37;expected[16]=1
        if row['transfer'][0]==6:expected[34:36]=[1,1]
        if c[29:31]==[1,1]:
            need(c[31]in(1,2402,2403,2404) and
                 row['refusals'][(1,2402,2403,2404).index(c[31])]>0,
                 'actual final returned linked planner refusal counted in its exact class')
            expected[29:32]=c[29:32]
        else:
            need(row['source_misses']+row['capacity_misses']+row['hash_misses']>0,
                 'actual final linked non-entry has an observed source, capacity or hash decline')
        need(c==expected,'entire final linked non-entry prefix is canonical and owns no generated execution')


def completed(row,retirement,*,hint=None):
    graph=row["graph_refaults"]if hint is not None else 0
    if hint is None:fixture.refault_completed(row)
    else:fixture.hint_refault_completed(row,hint)
    need(row['status']==row['failure_code']==row['detail_abs']==row['detail_negative']==row['first_error']==
         row['active']==row['busy']==row['decoding']==row['closing']==row['resuming']==row['unexpected']==0 and
         row['initialized']==1 and retirement['status']==retirement['failure_code']==retirement['detail_abs']==
         retirement['detail_negative']==retirement['pending']==retirement['retiring']==0,
         'successful linked has no pending or failed owner')
    need(row['events']==sum(row['signals'])>0 and all(row['signals'][i]>0 for i in (0,1,2))and
         row['signals'][3:]==[0,0],'complete actual linked handler population')
    need(0<row['used']==min(row['publications'],64) and
         row['offers']==row['closed']==row['candidates']==row['entries']+row['resumed']+row['refaults']+graph and
         row['resumed']+row['refaults']+graph==row['hash_misses']+row['source_misses']+row['plan_misses']+row['capacity_misses'] and
         row['plan_misses']==sum(row['refusals']) and
         row['entries']==row['publications']+row['hits']==row['completed']==sum(row['exit_indices']) and
         row['plan_checks']==row['publications']+retirement['retirement_attempts'] and
         row['rseq_checks']==row['publications'] and
         row['live_checks']==3*row['publications']+4*row['hits'] and
         row['proof_checks']==2*row['publications']+3*row['hits'],
         'every genuine close completes, resumes or refaults; cold and retired static proofs, warm authority and live checks remain exact')
    need(retirement['generation']==row['publications'] and
         retirement['retirement_attempts']==retirement['retirements']==row['publications']-row['used'] and
         retirement['claims']==retirement['permits_issued']==row['completed'] and
         retirement['cursor']==retirement['retirements']%64,
         'actual linked generations, complete retirements and consumed/reissued permits')
    current_linked(row)
    t=row['transfer'];entered=bool(row['current'][0]);refault=t[0]==6
    need(t[0]==(3 if entered else 6 if refault else 5) and t[1]==row['offers'] and t[2]>0 and t[3]<2 and
         t[4:6]==([0,0]if entered or refault else[t[3]^1,1]) and t[6]>0 and 0<t[7]<t[8] and
         (t[9]>>47)in(0,0x1ffff) and t[9]%4096<=4096-15 and
         t[10]&0x10100==0 and t[11]==1 and
         t[12:16]==([1,1,0,0]if entered else[0,0,0,0]if refault else[0,0,1,1]) and
         t[16:19]==[0,0,0] and t[19:]==([1,1]if refault else[0,0]),
         'actual final one-use TRACE transfer has a newer borrow and exactly consumed, resumed or refaulted terminal state')


def check(stdout,stderr,args,kind,lane,*,native_hint=False,positive_true_repeat=False):
    need(native_hint is True and positive_true_repeat is True,
         'explicit typed v2 native-hint release with positive TRUE REP domain')
    need(lane in('linked','differential'),'explicit genuine-TRACE linked release profile')
    need(type(native_hint)is bool,'literal release advisory profile')
    need(type(positive_true_repeat)is bool and (not positive_true_repeat or native_hint),
         'explicit positive REP profile requires the native-hint linked reader')
    if native_hint:linked,retirement,hint,suffix=preedge.split_hint(stderr)
    else:linked,retirement,suffix=fixture.split(stderr)
    current_row,scalar_suffix=current.split_current(suffix)
    need(linked['cut_exits']<=linked['completed'],preedge.CUT_ERROR)
    current_completed(current_row);completed(linked,retirement,**(dict(hint=hint)if native_hint else{}))
    parsed,summary,view,unrolled,prior,prior_retirement=scalar.check(
        stdout,scalar_suffix,args,kind,'differential'if lane=='differential'else'scalar-reuse',
        cache_completed=cache_reports.completed,
        chain_closure=lambda loader,c:chain_completed(loader,c,linked),
        true_repeat=true_repeat_reports.PROFILE if positive_true_repeat and kind=='true'else None)
    need(all(linked[k]==retirement[k]==parsed['loader'][k]for k in fixture.OUTCOME)and
         current_row['status']==parsed['loader']['status']and
         current_row['failure_code']==parsed['loader']['failure_code'],
         'every actual current/linked/reuse row agrees with the complete original successful outcome')
    need(linked['events']==prior['events']==unrolled['events']and
         linked['signals']==prior['signals']==unrolled['signals'],
         'all successful linked and old preentry observers saw the same complete handler population')
    if native_hint:fixture.hint_native(linked,hint,parsed)
    result=dict(parsed=parsed,summary=summary,maps_view=view,unrolled=unrolled,
        scalar=prior,scalar_reuse=prior_retirement,current_tf=current_row,
        linked=linked,linked_reuse=retirement)
    if native_hint:result['native_hint']=hint
    if positive_true_repeat:result['positive_true_repeat']=True
    result['preedge']=dict(version=2,plan_bytes=40744,proof_payload_bytes=45288)
    return result


def controls(stdout,stderr,args,kind,lane,*,native_hint=False,positive_true_repeat=False):
    observed=check(stdout,stderr,args,kind,lane,native_hint=native_hint,positive_true_repeat=positive_true_repeat)
    parsed,unrolled,prior,current_row,linked,retirement=(observed[k]for k in
        ('parsed','unrolled','scalar','current_tf','linked','linked_reuse'))
    if native_hint:_,_,_,without_linked=preedge.split_hint(stderr)
    else:_,_,without_linked=fixture.split(stderr)
    _,without_current=current.split_current(without_linked)
    inherited=scalar.controls(stdout,without_current,args,kind,
        'differential'if lane=='differential'else'scalar-reuse',
        cache_completed=cache_reports.completed,
        chain_closure=lambda loader,c:chain_completed(loader,c,linked),
        true_repeat=true_repeat_reports.PROFILE if positive_true_repeat and kind=='true'else None)
    lines=stderr[:-1].split(b'\n');trials=[]
    def changed(name,prefix,value):
        rows=list(lines);places=[i for i,line in enumerate(rows)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied linked report target')
        rows[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(rows)+b'\n'))
    for key in fixture.KEYS:
        if key not in fixture.ARRAYS:
            value=copy.deepcopy(linked);value[key]+=1;changed('linked_'+key,preedge.PREFIX,value)
    for key in ('signals','refusals','exit_indices'):
        value=copy.deepcopy(linked);value[key][0]+=1;changed('linked_'+key,preedge.PREFIX,value)
    for index in range(21):
        value=copy.deepcopy(linked);t=value['transfer']
        if index in(2,6,7):t[index]=0
        elif index==3:t[index]=2
        elif index==8:t[index]=t[7]
        elif index==9:t[index]=(t[index]&~4095)|4095
        elif index==10:t[index]^=0x100
        else:t[index]^=1
        changed('linked_transfer_'+str(index),preedge.PREFIX,value)
    for index in range(37):
        value=copy.deepcopy(linked)
        value['current'][index]=2405 if index==31 else 1<<64 if index in(1,5,32,33)else value['current'][index]^1
        changed('linked_current_'+str(index),preedge.PREFIX,value)
    for key in reuse.KEYS:
        value=dict(retirement);value[key]+=1;changed('linked_reuse_'+key,preedge.REUSE_PREFIX,value)
    for name,value in(('bool',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        row=dict(linked);row['offers']=value;changed('linked_type_'+name,preedge.PREFIX,row)
    row=dict(linked);del row['first_error'];changed('linked_missing_key',preedge.PREFIX,row)
    row=dict(linked);row['extra']=0;changed('linked_extra_key',preedge.PREFIX,row)
    changed('linked_key_order',preedge.PREFIX,dict(reversed(list(linked.items()))))
    tail=3 if native_hint else 2;linked_at=len(lines)-tail+1
    duplicate=list(lines);duplicate[linked_at]=duplicate[linked_at][:-1]+b',"version":1}'
    trials.append(('linked_duplicate_key',b'\n'.join(duplicate)+b'\n'))
    for prefix,name,line in ((preedge.PREFIX,'linked',lines[-tail+1]),(preedge.REUSE_PREFIX,'linked_reuse',lines[-tail])):
        trials.extend([(name+'_missing_row',b'\n'.join(x for x in lines if not x.startswith(prefix))+b'\n'),
                       (name+'_duplicate_row',stderr+line+b'\n')])
    order=list(lines);order[-tail],order[-tail+1]=order[-tail+1],order[-tail]
    trials.extend([('linked_row_order',b'\n'.join(order)+b'\n'),
                   ('linked_truncated',stderr[:-1])])
    coherent=list(lines)
    for prefix,record in ((reuse.old.PREFIX,prior),(reuse.unrolled.PREFIX,unrolled)):
        value=copy.deepcopy(record);value['events']+=1;value['signals'][0]+=1
        at=next(i for i,line in enumerate(lines)if line.startswith(prefix))
        coherent[at]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
    trials.append(('linked_coherent_old_population',b'\n'.join(coherent)+b'\n'))
    need(len(trials)==len({name for name,_ in trials})==LINKED_CONTROL_COUNT,
         'all121 release linked/transfer/reuse refusals, retaining the original115')
    refused=[]
    for name,value in trials:
        caught=False
        try:check(stdout,value,args,kind,lane,native_hint=native_hint,positive_true_repeat=positive_true_repeat)
        except ValueError as error:
            caught=name!='linked_coherent_old_population'or str(error)==\
                'all successful linked and old preentry observers saw the same complete handler population'
        need(caught,'complete TRACE release reader refuses '+name);refused.append(name)
    # Preserve every original26 current-row mutation and its complete stream.
    # This profile checks its own source-derived terminal domain above; it does
    # not rewrite a current row to satisfy the old positive-activity profile.
    row,suffix=current.split_current(stderr)
    first=stderr.split(b'\n',1)[0];trials=[]
    def changed_current(name,value):
        trials.append((name,current.CURRENT_PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()+b'\n'+suffix))
    for key in current.CURRENT_KEYS:
        value=dict(row);value[key]^=1;changed_current('current_'+key,value)
    for name,value in(('boolean',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        changed_row=dict(row);changed_row['attempts']=value;changed_current('current_type_'+name,changed_row)
    short=dict(row);del short['first_error'];changed_current('current_missing_key',short)
    extra=dict(row);extra['extra']=0;changed_current('current_extra_key',extra)
    changed_current('current_reordered',dict(reversed(list(row.items()))))
    next_row,remaining=suffix.split(b'\n',1)
    trials.extend([('current_absent',suffix),('current_duplicate',first+b'\n'+stderr),
        ('current_misplaced',next_row+b'\n'+first+b'\n'+remaining),('current_truncated',stderr[:-1]),
        ('current_duplicate_key',first[:-1]+b',"version":1}\n'+suffix)])
    need(len(trials)==len({name for name,_ in trials})==CURRENT_CONTROL_COUNT,
         'all26 original production current-row refusals retained')
    current_refused=[]
    for name,value in trials:
        caught=False
        try:check(stdout,value,args,kind,lane,native_hint=native_hint,positive_true_repeat=positive_true_repeat)
        except ValueError:caught=True
        need(caught,'complete TRACE release reader refuses '+name);current_refused.append(name)
    # The pure source-derived predicate must reject for its exact new reason;
    # the complete actual stream must also reject through every original gate.
    chain_refused=[]
    for name,loader,chain,changed_linked,error in chain_reports.mutations(parsed['loader'],parsed['chain'],linked):
        caught=False
        try:chain_completed(loader,chain,changed_linked)
        except ValueError as exc:caught=str(exc)==error
        need(caught,'exact release TRACE causal refusal '+name)
        rows=list(lines)
        for prefix,value in ((b'LI2_LOADER ',loader),(b'LI2_CHAIN ',chain),(preedge.PREFIX,changed_linked)):
            places=[i for i,line in enumerate(rows)if line.startswith(prefix)]
            need(len(places)==1,'one original complete release TRACE mutation row')
            rows[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        changed=b'\n'.join(rows)+b'\n';need(changed!=stderr,'actual release TRACE mutation changes bytes')
        caught=False
        try:check(stdout,changed,args,kind,lane,native_hint=native_hint,positive_true_repeat=positive_true_repeat)
        except ValueError:caught=True
        need(caught,'complete release TRACE reader refuses '+name);chain_refused.append(name)
    need(len(chain_refused)==len(set(chain_refused))==CHAIN_CONTROL_COUNT==chain_reports.CONTROL_COUNT,
         'eleven additional release TRACE chain controls without changing any old population')
    refault_refused=[]
    for name,value,error in fixture.refault_causal_mutations(linked):
        caught=False
        try:fixture.refault_completed(value)
        except ValueError as exc:caught=str(exc)==error
        need(caught,'exact release refault cause '+name)
        rows=list(lines);rows[linked_at]=preedge.PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        caught=False
        try:check(stdout,b'\n'.join(rows)+b'\n',args,kind,lane,native_hint=native_hint,positive_true_repeat=positive_true_repeat)
        except ValueError as exc:caught=str(exc)==error
        need(caught,'complete release reader reaches refault cause '+name);refault_refused.append(name)
    value=fixture.refault_chain_mutation(linked);caught=False
    try:chain_completed(parsed['loader'],parsed['chain'],value)
    except ValueError as exc:caught=str(exc)=='release TRACE exact consumed-span segment partition'
    need(caught,'a completed refault requires its already-started ordinary NX segment')
    rows=list(lines);rows[linked_at]=preedge.PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
    caught=False
    try:check(stdout,b'\n'.join(rows)+b'\n',args,kind,lane,native_hint=native_hint,positive_true_repeat=positive_true_repeat)
    except ValueError:caught=True
    need(caught,'complete release reader rejects missing already-started ordinary NX segment');refault_refused.append('refault_missing_nx')
    need(len(refault_refused)==REFAULT_CONTROL_COUNT,'three additional causal refault refusals')
    supplied_lease=chain_reports.supplied_lease_controls()
    need(len(supplied_lease['positive_controls'])==len(supplied_lease['refusals'])==
         SUPPLIED_LEASE_CONTROL_COUNT==chain_reports.SUPPLIED_LEASE_CONTROL_COUNT,
         'two separately counted supplied lease tuple controls')
    cache_refused=[]
    for name,run,cache in cache_reports.mutations(parsed['run'],parsed['reuse']):
        caught=False
        try:cache_reports.completed(run,cache)
        except ValueError:caught=True
        need(caught,'exact linked prior-cache supplied refusal '+name)
        rows=list(lines)
        for prefix,value in ((b'LI2_RUN ',run),(b'LI2_RUN_REUSE ',cache)):
            places=[i for i,line in enumerate(rows)if line.startswith(prefix)]
            need(len(places)==1,'one actual linked prior-cache mutation row')
            rows[places[0]]=prefix+json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        data=b'\n'.join(rows)+b'\n'
        need(data!=stderr,'actual linked prior-cache mutation changes bytes')
        caught=False
        try:check(stdout,data,args,kind,lane,native_hint=native_hint,positive_true_repeat=positive_true_repeat)
        except ValueError:caught=True
        need(caught,'whole linked release reader refuses '+name);cache_refused.append(name)
    need(len(cache_refused)==len(set(cache_refused))==CACHE_CONTROL_COUNT==cache_reports.CONTROL_COUNT,
         'ten additional linked prior-cache lifecycle refusals')
    unroll=inherited['original'];maps=unroll['original'];base=maps['original']
    populations=dict(original=base['refusals'],maps=maps['maps_view_refusals'],
        unrolled=unroll['unrolled_refusals'],scalar=inherited['scalar_reuse_refusals'],
        current=current_refused,linked=refused,chain=chain_refused,cache=cache_refused,refault=refault_refused)
    positive=positive_true_repeat and kind=='true'
    expected=dict(original=60 if kind=='ls'else 38 if positive else 218,maps=23,unrolled=31,scalar=86,
        current=CURRENT_CONTROL_COUNT,linked=LINKED_CONTROL_COUNT,chain=CHAIN_CONTROL_COUNT,cache=CACHE_CONTROL_COUNT,refault=REFAULT_CONTROL_COUNT)
    need({k:len(v)for k,v in populations.items()}==expected,'every inherited and new linked release population retained')
    names=[group+'.'+name for group,items in populations.items()for name in items]
    if positive:
        additions=base['positive_repeat_refusals']
        need(base['positive_repeat_profile']==true_repeat_reports.PROFILE and
             len(additions)==len(set(additions))==true_repeat_reports.POSITIVE_CONTROL_COUNT==55,
             'separate55 positive REP controls; no unused180 control credit')
        populations['positive_repeat']=additions
        names+=['positive_repeat.'+name for name in additions]
    expected_total=404 if positive else CONTROL_COUNTS[kind]
    need(len(names)==len(set(names))==expected_total,'complete unique linked release refusal population')
    if native_hint:
        addition=hint_controls(stdout,stderr,args,kind,lane,observed,positive_true_repeat=positive_true_repeat)
        populations['native_hint']=addition
        names+=['native_hint.'+name for name in addition]
        expected_total=POSITIVE_TRUE_CONTROL_COUNTS[kind]if positive_true_repeat else HINT_CONTROL_COUNTS[kind]
        need(len(names)==len(set(names))==expected_total,'exact declared terminal domain plus separate advisory controls')
    addition=preedge_controls(stdout,stderr,args,kind,lane,observed)
    populations['preedge_v2']=addition
    names+=['preedge_v2.'+name for name in addition]
    need(len(names)==len(set(names))==PREEDGE_CONTROL_COUNTS[kind],
         'exact positive-domain release population plus eight typed v2 controls')
    return dict(refusals=names,populations=populations,native_operations=0,
        supplied_lease_controls=supplied_lease,original_stdout_sha256=reuse.H(stdout),
        original_stderr_sha256=reuse.H(stderr))


def hint_controls(stdout,stderr,args,kind,lane,observed,*,positive_true_repeat=False):
    """Separate source-derived terminal controls; no protected-record credit."""
    linked,hint,parsed=(observed[k]for k in('linked','native_hint','parsed'))
    lines=stderr[:-1].split(b'\n');trials=[]
    def change(name,rows):
        changed=list(lines)
        for prefix,value in rows:
            places=[i for i,line in enumerate(changed)if line.startswith(prefix)]
            need(len(places)==1,'one complete actual advisory report target')
            changed[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(changed)+b'\n'))
    replacements=dict(version=2,status=125,failure_code=1,ready=hint['ready']^1,pending=1,
        outcome_complete=hint['outcome_complete']^1,publications=hint['publications']+1,
        evictions=hint['evictions']+1,lookups=hint['hits']+hint['invalidations']-1,hits=hint['hits']+1,
        invalidations=hint['invalidations']+1,next_nx=hint['next_nx']+1,admitted=hint['admitted']+1,
        refused=hint['refused']+1,errors=1,receipt_sequence=0 if hint['publications']else 1,
        receipt_publication=hint['receipt_publication']+1,selected_publication=0 if hint['hits']else 1,
        selected_serial=0 if hint['hits']else 1,selected_event=parsed['native_pair']['counts'][0]if hint['hits']else 1,
        selected_pc=0 if hint['hits']else 1,selected_seeds=parsed['native_pair']['counts'][1]+1 if hint['hits']else 1,
        selected_published=hint['receipt_publication']+1 if hint['hits']else 1,outcome_result=2,
        current_checked=2,current_hit=2,current_publication=hint['selected_publication']+1 if hint['current_hit']else 1)
    need(list(replacements)==fixture.HINT_KEYS,'every actual advisory report field has a source-required refusal')
    for key,value in replacements.items():
        row=dict(hint);row[key]=value;need(row!=hint,'actual advisory field changes')
        change('field_'+key,[(fixture.HINT_PREFIX,row)])
    row=copy.deepcopy(linked);row['graph_refaults']+=1;change('graph_refaults',[(preedge.PREFIX,row)])
    for name,value in(('bool',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        row=dict(hint);row['lookups']=value;change('type_'+name,[(fixture.HINT_PREFIX,row)])
    row=dict(hint);del row['ready'];change('missing_key',[(fixture.HINT_PREFIX,row)])
    row=dict(hint);row['extra']=0;change('extra_key',[(fixture.HINT_PREFIX,row)])
    change('key_order',[(fixture.HINT_PREFIX,dict(reversed(list(hint.items()))))])
    trials.extend([('missing_row',b'\n'.join(lines[:-1])+b'\n'),('duplicate_row',stderr+lines[-1]+b'\n'),
        ('row_order',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n')])
    row=copy.deepcopy(linked);row['graph_refaults']=row['refusals'][2]+1;caught=False
    try:fixture.hint_counts(row,hint)
    except ValueError as exc:caught=str(exc)==fixture.HINT_CLASS_ERROR
    need(caught,'exact source GRAPH-class refusal');change('above_graph_class',[(preedge.PREFIX,row)])
    value=dict(hint);value['publications']+=1;caught=False
    try:fixture.hint_counts(linked,value)
    except ValueError as exc:caught=str(exc)==fixture.HINT_LIFETIME_ERROR
    need(caught,'exact one-use publication conservation');change('unaccounted_publication',[(fixture.HINT_PREFIX,value)])
    row=copy.deepcopy(linked);value=dict(hint)
    for key in('offers','closed','candidates','graph_refaults','plan_misses'):row[key]+=1
    row['refusals'][2]+=1
    for key in('lookups','hits','next_nx','admitted','publications','receipt_publication'):value[key]+=1
    fixture.hint_counts(row,value);caught=False
    try:chain_completed(parsed['loader'],parsed['chain'],row)
    except ValueError as exc:caught=str(exc)=='release TRACE exact consumed-span segment partition'
    need(caught,'one additional GRAPH retry requires its already-started ordinary NX segment')
    change('missing_ordinary_segment',[(preedge.PREFIX,row),(fixture.HINT_PREFIX,value)])
    need(len(trials)==len({name for name,_ in trials})==HINT_CONTROL_COUNT,'all41 separate source-causal advisory controls')
    names=[]
    for name,data in trials:
        caught=False
        try:check(stdout,data,args,kind,lane,native_hint=True,positive_true_repeat=positive_true_repeat)
        except ValueError:caught=True
        need(caught,'complete hinted release reader refuses '+name);names.append(name)
    return names


def preedge_controls(stdout,stderr,args,kind,lane,observed):
    """Report-only type/count obligations; no invented protected cut count."""
    linked,retirement=observed['linked'],observed['linked_reuse']
    lines=stderr[:-1].split(b'\n');trials=[]
    def add(name,rows,error):
        changed=list(lines)
        for prefix,value in rows:
            places=[i for i,line in enumerate(changed)if line.startswith(prefix)]
            need(len(places)==1,'one actual v2 release row')
            changed[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(changed)+b'\n',error))
    row=copy.deepcopy(linked);other=dict(retirement);row['version']=other['version']=1
    add('coherent_v1_rows',[(preedge.PREFIX,row),(preedge.REUSE_PREFIX,other)],
        'exact full preedge v2 versions, actual outcome, literal flags and bounded cursor')
    row=copy.deepcopy(linked);row['cut_exits']=row['completed']+1
    add('cut_exits_above_completed',[(preedge.PREFIX,row)],preedge.CUT_ERROR)
    schema='complete ordered unsigned native-hint linked schema'
    for name,value in(('boolean',True),('negative',-1),('float',0.5),('overflow',1<<64)):
        row=copy.deepcopy(linked);row['cut_exits']=value
        add('cut_exits_'+name,[(preedge.PREFIX,row)],schema)
    row=copy.deepcopy(linked);del row['cut_exits'];add('cut_exits_missing',[(preedge.PREFIX,row)],schema)
    row=copy.deepcopy(linked);value=row.pop('cut_exits');row['cut_exits']=value
    add('cut_exits_wrong_position',[(preedge.PREFIX,row)],schema)
    need(len(trials)==len({name for name,*_ in trials})==PREEDGE_CONTROL_COUNT,
         'eight distinct typed v2 release refusals')
    names=[]
    for name,data,error in trials:
        need(data!=stderr,'actual v2 release mutation')
        try:check(stdout,data,args,kind,lane,native_hint=True,positive_true_repeat=True)
        except ValueError as exc:need(str(exc)==error,'exact v2 release refusal '+name)
        else:raise ValueError('v2 release mutation accepted '+name)
        names.append(name)
    return names
