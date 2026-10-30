"""Finite pre-edge v2 terminal composition, separately joined to actual raw capture.

The four successful pairs do not qualify the old65, fault/nested, whole-program
or performance populations. Applicable inherited ownership/effect guards and
all318 successful finite terminal stimuli are retained, with two new v2 row
fields and41 separately counted native-advisory report stimuli per record.
"""
import copy,json
from page_selected import need
import linked_epoch_reports as prior
import linked_epoch_performance_reports as accounting
reuse,current,unrolled,maps_view=prior.reuse,prior.current,prior.unrolled,prior.maps_view
old,cost,linked_base=prior.old,prior.cost,prior.linked_base
prior_cache,prior_repeat,prior_chain=prior.prior_cache,prior.prior_repeat,prior.prior_chain
terminal,H=prior.terminal,prior.H
chain_quiet,chain_completed,chain_mutations=prior.chain_quiet,prior.chain_completed,prior.chain_mutations
completed_tls,prior_scalar=prior.completed_tls,prior.prior_scalar
PREFIX=b'LI2_LINKED_PREEDGE '
REUSE_PREFIX=b'LI2_LINKED_PREEDGE_REUSE '
KEYS=terminal.HINT_LINKED_KEYS[:terminal.HINT_LINKED_KEYS.index('active')]+['cut_exits']+terminal.HINT_LINKED_KEYS[terminal.HINT_LINKED_KEYS.index('active'):]
ARRAYS,OUTCOME=terminal.ARRAYS,terminal.OUTCOME
LINKED_ROW_REFUSALS=64
REFAULT_ROW_REFUSALS=8
CURRENT_ROW_REFUSALS=26
NATIVE_ROW_REFUSALS=20
CONTROL_COUNTS={(m,0):320 for m in range(4)}
HINT_TERMINAL_CONTROL_COUNT=41


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete distinct pre-edge v2 terminal stream')
    lines=stderr[:-1].split(b'\n');prefixes=(REUSE_PREFIX,PREFIX,terminal.HINT_PREFIX)
    need(len(lines)>3 and all(lines[-3+i].startswith(p)and sum(x.startswith(p)for x in lines)==1 for i,p in enumerate(prefixes))and
         not any(x.startswith((terminal.PREFIX,terminal.REUSE_PREFIX))for x in lines)and
         all(len(x)<=4096 and b'\r'not in x for x in lines[-3:]),
         'one final v2 reuse, v2 pre-edge and native-hint row; no v1 substitution')
    decode=maps_view.pair.pair_reports.rseq.decode
    retirement,linked,hint=(decode(line[len(prefix):])for prefix,line in zip(prefixes,lines[-3:],strict=True))
    for row,keys,arrays in((linked,KEYS,ARRAYS),(retirement,reuse.KEYS,{}),(hint,terminal.HINT_KEYS,{})):
        need(type(row)is dict and list(row)==keys and all(type(row[k])is int and 0<=row[k]<1<<64 for k in keys if k not in arrays),
             'whole ordered unsigned pre-edge row without alternate keys or types')
        for k,n in arrays.items():need(type(row[k])is list and len(row[k])==n and all(type(v)is int and 0<=v<1<<64 for v in row[k]),'complete pre-edge '+k)
    need(linked['version']==retirement['version']==2 and hint['version']==1 and
         all(linked[k]==retirement[k]==0 for k in OUTCOME)and hint['status']==hint['failure_code']==0,
         'only exact successful v2/actual-advisory terminal outcomes')
    need(all(linked[k]in(0,1)for k in('initialized','active','busy','decoding','closing','resuming'))and
         all(retirement[k]in(0,1)for k in('pending','retiring'))and retirement['cursor']<64 and
         all(hint[k]in(0,1)for k in('ready','pending','outcome_complete','current_checked','current_hit')),
         'literal complete owner and advisory flags')
    for row,prefix,line in zip((retirement,linked,hint),prefixes,lines[-3:],strict=True):
        need(prefix+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==line,'whole canonical pre-edge terminal row')
    return linked,retirement,hint,b'\n'.join(lines[:-3])+b'\n'


def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    need(type(mode)is int and mode in range(4)and type(exit_status)is int and exit_status==0 and
         type(owner['mode'])is int and owner['mode']==mode and type(owner['control'])is int and owner['control']==0,
         'four distinct successful pre-edge subjects, never failed-outcome substitution')
    span,retirement,hint,suffix=split(stderr)
    accounting.completed(span,retirement,hint=hint)
    need(int(mode!=3)<=span['cut_exits']<=span['completed'],'actual PAGE_CUT completions form a bounded subset of all completed epochs')
    scalar,scalar_retirement,suffix=reuse.split(suffix)
    row,suffix=unrolled.split(suffix);current_row,suffix=current.split_current(suffix)
    accounting.current_completed(current_row)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed);completed_tls(parsed)
    _,same,gate=linked_base.gate(parsed,pid,exit_status,parent,0,cache_completed=prior_cache.completed,
        chain_closure=lambda loader,c:chain_completed(loader,c,span))
    need(same is parsed and all(all(value[k]==parsed['loader'][k]for k in OUTCOME)
         for value in(span,retirement,scalar,scalar_retirement,row))and
         current_row['status']==current_row['failure_code']==0,'every inherited row preserves the same actual successful outcome')
    parsed.update(linked_preedge=span,linked_preedge_reuse=retirement,native_hint=hint,current_tf=current_row,
                  scalar_region=scalar,scalar_reuse=scalar_retirement,unrolled=row)
    terminal.hint_native(span,hint,parsed,finite=True)
    joined=owner_reader.terminal(parsed,owner)
    chain_quiet(parsed['loader'],parsed['chain'],span,0)
    reuse.prior_unrolled(row);prior_scalar(scalar,scalar_retirement)
    need(scalar['events']==row['events']==span['events']and scalar['signals']==row['signals']==span['signals'],
         'exact preentry-order signal partition including the nonreturning final span event')
    summary=dict(application_completed=True,gate=gate,repeat_lease=linked_base.repeat_completed(parsed,pid,images,image_bytes,carrier,carrier_bytes),
        input_authentication=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),maps_view=view,
        terminal_join=joined,required_refusal=0,whole_program_qualification=False)
    reuse.scalar_completed(scalar,scalar_retirement);unrolled.completed(row,False)
    summary.update(lease=old.lease.counters(parsed),trace_run=old.trace_completed(parsed),
        native_pair=old.pair_completed(parsed,pid),cache_reuse=prior_cache.completed(parsed['run'],parsed['reuse']))
    # Each new mode has18 fixed calls and7 for its one invocation,67 CPUID,
    # and no registration call. The unchanged pure guard's mode0 selects
    # precisely that source-derived25-call domain; no v1 frame/model is used.
    linked_base.application_effect_exit(parsed,0)
    return parsed,summary


def controls(stderr,*args):
    """Original65/67 report mutations plus fixed59 span and26 current rows."""
    parsed,_=check(stderr,*args);native_hint=True
    span,retirement,hint,suffix=split(stderr)
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
    need(len(new)==LINKED_ROW_REFUSALS,'all64 pre-edge row refusals: original62 plus graph_refaults and cut_exits')
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
        try:args[-2].terminal(v,args[-3])
        except ValueError as error:caught=str(error)=='entire actual protected terminal row '+key
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
    need(len(all_trials)==len({n for n,_ in all_trials})==CONTROL_COUNTS[(args[-1],args[-3]['control'])],
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
    parsed,_=check(stderr,*args)
    linked,retirement,hint,suffix=split(stderr);lines=stderr[:-1].split(b'\n');trials=[]
    def change(name,rows):
        changed=list(lines)
        for prefix,value in rows:
            at=[i for i,x in enumerate(changed)if x.startswith(prefix)];need(len(at)==1,'one actual hint mutation row')
            changed[at[0]]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(changed)+b'\n'))
    for key in terminal.HINT_KEYS:
        value=dict(hint);value[key]^=1
        p=dict(parsed,native_hint=value);caught=False
        try:args[-2].terminal(p,args[-3])
        except ValueError as exc:caught=str(exc)=='entire actual protected terminal row native_hint'
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

