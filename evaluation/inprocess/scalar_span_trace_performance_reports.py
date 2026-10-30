"""Release-only TRACE/span accounting around unchanged original readers.

These rows are terminal observations, not protected records or full-frame
evidence. The separate finite component/owner prerequisites remain mandatory.
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
import scalar_span_trace_reports as fixture
import scalar_span_trace_release_chain as chain_reports

SPAN_CONTROL_COUNT=113
CURRENT_CONTROL_COUNT=26
CHAIN_CONTROL_COUNT=11
SUPPLIED_LEASE_CONTROL_COUNT=2


def current_completed(row):
    need(row['version']==1 and all(row[k]==0 for k in
         ('status','failure_code','first_error','first_detail_abs','first_detail_negative')),
         'complete successful current-custody counter outcome')
    a,s,n,f,r,c,k,x=(row[key]for key in
        ('attempts','current_stages','current_seeds','physical_fallbacks','retained_stages','retained_checks','commits','cancels'))
    need(a==s+f and s>=n and s+r==k+x and n<=k<=n+r and c==r+k-n and
         (n>0 or r==k==c==0),
         'all actual current stages, seeds, physical fallback, retained checks and terminal cancellations close')


def current_span(row):
    c=row['current']
    if c[0]:
        need(c[0]==1 and c[1]<row['used'] and c[2:5]==[1,1,1] and c[5]<8 and
             c[6:14]==[1]*8 and c[14:20]==[0,0,1,1,0,0] and c[20:24]==[0]*4 and
             c[24:29]==[4096,4096,4096,0,1] and c[29:31]in([0,0],[1,1]) and c[31]==0 and
             c[32]&~0xffff==0 and c[32]&16==0 and c[33]&~0x8d5==0,
             'actual span current completed and closed full image/source with bounded union effects')
    else:
        expected=[0]*34;expected[16]=1
        if c[29:31]==[1,1]:
            need(c[31]in(1,2402,2403,2404) and
                 row['refusals'][(1,2402,2403,2404).index(c[31])]>0,
                 'actual final returned span planner refusal counted in its exact class')
            expected[29:32]=c[29:32]
        else:
            need(row['source_misses']+row['capacity_misses']+row['hash_misses']>0,
                 'actual final span non-entry has an observed source, capacity or hash decline')
        need(c==expected,'entire final span non-entry prefix is canonical and owns no generated execution')


def completed(row,retirement):
    need(row['status']==row['failure_code']==row['detail_abs']==row['detail_negative']==row['first_error']==
         row['active']==row['busy']==row['decoding']==row['closing']==row['resuming']==row['unexpected']==0 and
         row['initialized']==1 and retirement['status']==retirement['failure_code']==retirement['detail_abs']==
         retirement['detail_negative']==retirement['pending']==retirement['retiring']==0,
         'successful span has no pending or failed owner')
    need(row['events']==sum(row['signals'])>0 and all(row['signals'][i]>0 for i in (0,1,2))and
         row['signals'][3:]==[0,0],'complete actual span handler population')
    need(0<row['used']==min(row['publications'],64) and
         row['offers']==row['closed']==row['candidates']==row['entries']+row['resumed'] and
         row['resumed']==row['hash_misses']+row['source_misses']+row['plan_misses']+row['capacity_misses'] and
         row['plan_misses']==sum(row['refusals']) and
         row['entries']==row['publications']+row['hits']==row['completed']==sum(row['exit_indices']) and
         row['plan_checks']==3*row['entries']+retirement['retirement_attempts'] and
         row['rseq_checks']==4*row['entries'],
         'every genuine close either completes a span or resumes a new ordinary owner with full static proofs')
    need(retirement['generation']==row['publications'] and
         retirement['retirement_attempts']==retirement['retirements']==row['publications']-row['used'] and
         retirement['claims']==retirement['permits_issued']==row['completed'] and
         retirement['cursor']==retirement['retirements']%64,
         'actual span generations, complete retirements and consumed/reissued permits')
    current_span(row)
    t=row['transfer'];entered=bool(row['current'][0])
    need(t[0]==(3 if entered else 5) and t[1]==row['offers'] and t[2]>0 and t[3]<2 and
         t[4:6]==([0,0]if entered else[t[3]^1,1]) and t[6]>0 and 0<t[7]<t[8] and
         (t[9]>>47)in(0,0x1ffff) and t[9]%4096<=4096-15 and
         t[10]&0x10100==0 and t[11]==1 and
         t[12:16]==([1,1,0,0]if entered else[0,0,1,1]) and t[16:]==[0,0,0],
         'actual final one-use TRACE transfer has a newer borrow and exactly consumed or resumed terminal state')


def check(stdout,stderr,args,kind,lane):
    need(lane in('span-trace','differential'),'explicit genuine-TRACE span release profile')
    span,retirement,suffix=fixture.split(stderr)
    current_row,scalar_suffix=current.split_current(suffix)
    current_completed(current_row);completed(span,retirement)
    parsed,summary,view,unrolled,prior,prior_retirement=scalar.check(
        stdout,scalar_suffix,args,kind,'differential'if lane=='differential'else'scalar-reuse',
        chain_closure=lambda loader,c:chain_reports.completed(loader,c,span))
    need(all(span[k]==retirement[k]==parsed['loader'][k]for k in fixture.OUTCOME)and
         current_row['status']==parsed['loader']['status']and
         current_row['failure_code']==parsed['loader']['failure_code'],
         'every actual current/span/reuse row agrees with the complete original successful outcome')
    need(span['events']==prior['events']==unrolled['events']and
         span['signals']==prior['signals']==unrolled['signals'],
         'all successful span and old preentry observers saw the same complete handler population')
    return parsed,summary,view,unrolled,prior,prior_retirement,current_row,span,retirement


def controls(stdout,stderr,args,kind,lane):
    parsed,_,_,unrolled,prior,_,current_row,span,retirement=check(stdout,stderr,args,kind,lane)
    _,_,without_span=fixture.split(stderr)
    _,without_current=current.split_current(without_span)
    inherited=scalar.controls(stdout,without_current,args,kind,
        'differential'if lane=='differential'else'scalar-reuse',
        chain_closure=lambda loader,c:chain_reports.completed(loader,c,span))
    lines=stderr[:-1].split(b'\n');trials=[]
    def changed(name,prefix,value):
        rows=list(lines);places=[i for i,line in enumerate(rows)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied span report target')
        rows[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(rows)+b'\n'))
    for key in fixture.KEYS:
        if key not in fixture.ARRAYS:
            value=copy.deepcopy(span);value[key]+=1;changed('span_'+key,fixture.PREFIX,value)
    for key in ('signals','refusals','exit_indices'):
        value=copy.deepcopy(span);value[key][0]+=1;changed('span_'+key,fixture.PREFIX,value)
    for index in range(19):
        value=copy.deepcopy(span);t=value['transfer']
        if index in(2,6,7):t[index]=0
        elif index==3:t[index]=2
        elif index==8:t[index]=t[7]
        elif index==9:t[index]=(t[index]&~4095)|4095
        elif index==10:t[index]^=0x100
        else:t[index]^=1
        changed('span_transfer_'+str(index),fixture.PREFIX,value)
    for index in range(34):
        value=copy.deepcopy(span)
        value['current'][index]=2405 if index==31 else 1<<64 if index in(1,5,32,33)else value['current'][index]^1
        changed('span_current_'+str(index),fixture.PREFIX,value)
    for key in reuse.KEYS:
        value=dict(retirement);value[key]+=1;changed('span_reuse_'+key,fixture.REUSE_PREFIX,value)
    for name,value in(('bool',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        row=dict(span);row['offers']=value;changed('span_type_'+name,fixture.PREFIX,row)
    row=dict(span);del row['first_error'];changed('span_missing_key',fixture.PREFIX,row)
    row=dict(span);row['extra']=0;changed('span_extra_key',fixture.PREFIX,row)
    changed('span_key_order',fixture.PREFIX,dict(reversed(list(span.items()))))
    trials.append(('span_duplicate_key',b'\n'.join(lines[:-1])+b'\n'+lines[-1][:-1]+b',"version":1}\n'))
    for prefix,name,line in ((fixture.PREFIX,'span',lines[-1]),(fixture.REUSE_PREFIX,'span_reuse',lines[-2])):
        trials.extend([(name+'_missing_row',b'\n'.join(x for x in lines if not x.startswith(prefix))+b'\n'),
                       (name+'_duplicate_row',stderr+line+b'\n')])
    trials.extend([('span_row_order',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n'),
                   ('span_truncated',stderr[:-1])])
    coherent=list(lines)
    for prefix,record in ((reuse.old.PREFIX,prior),(reuse.unrolled.PREFIX,unrolled)):
        value=copy.deepcopy(record);value['events']+=1;value['signals'][0]+=1
        at=next(i for i,line in enumerate(lines)if line.startswith(prefix))
        coherent[at]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
    trials.append(('span_coherent_old_population',b'\n'.join(coherent)+b'\n'))
    need(len(trials)==len({name for name,_ in trials})==SPAN_CONTROL_COUNT,
         'all113 additional release span/transfer/reuse refusals')
    refused=[]
    for name,value in trials:
        caught=False
        try:check(stdout,value,args,kind,lane)
        except ValueError as error:
            caught=name!='span_coherent_old_population'or str(error)==\
                'all successful span and old preentry observers saw the same complete handler population'
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
        try:check(stdout,value,args,kind,lane)
        except ValueError:caught=True
        need(caught,'complete TRACE release reader refuses '+name);current_refused.append(name)
    # The pure source-derived predicate must reject for its exact new reason;
    # the complete actual stream must also reject through every original gate.
    chain_refused=[]
    for name,loader,chain,changed_span,error in chain_reports.mutations(parsed['loader'],parsed['chain'],span):
        caught=False
        try:chain_reports.completed(loader,chain,changed_span)
        except ValueError as exc:caught=str(exc)==error
        need(caught,'exact release TRACE causal refusal '+name)
        rows=list(lines)
        for prefix,value in ((b'LI2_LOADER ',loader),(b'LI2_CHAIN ',chain),(fixture.PREFIX,changed_span)):
            places=[i for i,line in enumerate(rows)if line.startswith(prefix)]
            need(len(places)==1,'one original complete release TRACE mutation row')
            rows[places[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        changed=b'\n'.join(rows)+b'\n';need(changed!=stderr,'actual release TRACE mutation changes bytes')
        caught=False
        try:check(stdout,changed,args,kind,lane)
        except ValueError:caught=True
        need(caught,'complete release TRACE reader refuses '+name);chain_refused.append(name)
    need(len(chain_refused)==len(set(chain_refused))==CHAIN_CONTROL_COUNT==chain_reports.CONTROL_COUNT,
         'eleven additional release TRACE chain controls without changing any old population')
    supplied_lease=chain_reports.supplied_lease_controls()
    need(len(supplied_lease['positive_controls'])==len(supplied_lease['refusals'])==
         SUPPLIED_LEASE_CONTROL_COUNT==chain_reports.SUPPLIED_LEASE_CONTROL_COUNT,
         'two separately counted supplied lease tuple controls')
    return dict(original=inherited['original'],scalar_reuse_refusals=inherited['scalar_reuse_refusals'],
        current_refusals=current_refused,span_refusals=refused,chain_refusals=chain_refused,native_operations=0,
        supplied_lease_controls=supplied_lease,
        original_stderr_sha256=reuse.H(stderr))
