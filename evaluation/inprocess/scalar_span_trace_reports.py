"""Finite genuine-TRACE terminal composition; no whole-program/cache credit.

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

old,maps_view,cost,unrolled=reuse.prior,reuse.maps_view,reuse.cost,reuse.unrolled
H=reuse.H
PREFIX=b'LI2_SCALAR_SPAN '
REUSE_PREFIX=b'LI2_SCALAR_SPAN_REUSE '
KEYS=('version status failure_code detail_abs detail_negative initialized first_error used offers closed '
      'resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries '
      'completed unexpected events plan_checks rseq_checks active busy decoding closing resuming '
      'transfer signals refusals exit_indices current').split()
ARRAYS=dict(transfer=19,signals=5,refusals=4,exit_indices=8,current=34)
OUTCOME=('status','failure_code','detail_abs','detail_negative')
SPAN_ROW_REFUSALS=59
CURRENT_ROW_REFUSALS=26
CONTROL_COUNTS={(0,0):152,(1,0):152,(2,0):152,(3,0):150,(0,1):150}


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete TRACE span terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>2 and lines[-2].startswith(REUSE_PREFIX)and lines[-1].startswith(PREFIX)and
         sum(x.startswith(REUSE_PREFIX)for x in lines)==sum(x.startswith(PREFIX)for x in lines)==1 and
         all(len(x)<=4096 and b'\r'not in x for x in lines[-2:]),
         'one final span-reuse row followed by one span row')
    decode=maps_view.pair.pair_reports.rseq.decode
    span=decode(lines[-1][len(PREFIX):]);retirement=decode(lines[-2][len(REUSE_PREFIX):])
    need(type(span)is dict and list(span)==KEYS and
         all(type(span[k])is int and 0<=span[k]<1<<64 for k in KEYS if k not in ARRAYS),
         'complete ordered unsigned span schema without duplicate keys or boolean values')
    for key,size in ARRAYS.items():
        need(type(span[key])is list and len(span[key])==size and
             all(type(x)is int and 0<=x<1<<64 for x in span[key]),'whole unsigned span '+key)
    need(type(retirement)is dict and list(retirement)==reuse.KEYS and
         all(type(retirement[k])is int and 0<=retirement[k]<1<<64 for k in reuse.KEYS),
         'complete ordered unsigned span-reuse schema')
    need(span['version']==retirement['version']==1 and span['status']in(0,125)and
         all(span[k]in(0,1)for k in ('detail_negative','initialized','active','busy','decoding','closing','resuming'))and
         all(retirement[k]in(0,1)for k in ('detail_negative','pending','retiring'))and retirement['cursor']<64,
         'exact span versions, outcome, boolean fields and bounded cursor')
    need(all(span[k]==retirement[k]for k in OUTCOME),'one actual span/reuse outcome')
    for row,prefix,line in ((span,PREFIX,lines[-1]),(retirement,REUSE_PREFIX,lines[-2])):
        need(prefix+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==line,
             'canonical complete span terminal row')
    return span,retirement,b'\n'.join(lines[:-2])+b'\n'


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


def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    need(type(mode)is int and mode in range(4)and type(owner['control'])is int and
         (mode,owner['control'])in CONTROL_COUNTS and exit_status==(125 if mode==3 or owner['control']else 0),
         'exact four TRACE cases or one required nested refusal')
    span,retirement,suffix=split(stderr);scalar,scalar_retirement,suffix=reuse.split(suffix)
    row,suffix=unrolled.split(suffix);current_row,suffix=current.split_current(suffix)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    _,same,gate=old.gate(parsed,pid,exit_status,parent,0)
    need(same is parsed and all(all(value[k]==parsed['loader'][k]for k in OUTCOME)
         for value in (span,retirement,scalar,scalar_retirement,row))and
         current_row['status']==exit_status and current_row['failure_code']==parsed['loader']['failure_code'],
         'every complete terminal row preserves the actual outcome')
    parsed.update(scalar_span=span,scalar_span_reuse=retirement,current_tf=current_row,
                  scalar_region=scalar,scalar_reuse=scalar_retirement,unrolled=row)
    joined=owner_reader.terminal(parsed,owner)
    reuse.prior_unrolled(row);prior_scalar(scalar,scalar_retirement)
    # Span preentry precedes both old observers. A required fault/nested event
    # terminates there, so exactly that final event never reaches either old
    # counter. Successful exits return from preentry and reach all observers.
    expected_signals=list(row['signals'])
    if exit_status:expected_signals[int(bool(owner['control']))]+=1
    need(scalar['events']==row['events'] and scalar['signals']==row['signals']and
         span['events']==row['events']+int(exit_status==125)and span['signals']==expected_signals,
         'exact preentry-order signal partition including the nonreturning final span event')
    need(current_row['first_error']==current_row['first_detail_abs']==current_row['first_detail_negative']==0,
         'current custody stayed error-free before the distinct focal span outcome')
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=application.unused_repeat(parsed),
        input_authentication=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),maps_view=view,
        terminal_join=joined,required_refusal=int(exit_status==125),whole_program_qualification=False)
    if exit_status==0:
        reuse.scalar_completed(scalar,scalar_retirement);unrolled.completed(row,False)
        summary.update(lease=old.lease.counters(parsed),trace_run=old.trace_completed(parsed),
            native_pair=old.pair_completed(parsed,pid),cache_reuse=old.reuse_completed(parsed['run'],parsed['reuse']))
        # The fixture has the exact original successful partition:67 CPUID;
        # identity/getcpu3,XCOMP2,machine6,map/protect4,writes2,getcpu1,unmap2.
        # Native-only signal setup and source protection never run gated.
        application.application_effect_exit(parsed)
    else:
        need(gate['original_completed_rejected']is True and
             span['first_error']==span['failure_code']==owner['outcome']['failure_code']>0,
             'actual failed span keeps its first error and original completion refusal')
    return parsed,summary


def controls(stderr,*args):
    """Original65/67 report mutations plus fixed59 span and26 current rows."""
    parsed,_=check(stderr,*args);span,retirement,suffix=split(stderr)
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
        changed('span_'+key,PREFIX,value,new)
    for key in reuse.KEYS:
        value=dict(retirement);value[key]^=1;changed('span_reuse_'+key,REUSE_PREFIX,value,new)
    for prefix,label,line in ((PREFIX,'span',lines[-1]),(REUSE_PREFIX,'span_reuse',lines[-2])):
        new.extend([(label+'_missing_row',removed(prefix)),(label+'_duplicate_row',stderr+line+b'\n')])
    new.append(('span_row_order',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n'))
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
    need(len(new)==SPAN_ROW_REFUSALS,'all59 additional span report refusals')
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
    all_trials=trials+new+current_trials
    need(len(all_trials)==len({n for n,_ in all_trials})==CONTROL_COUNTS[(args[-1],args[-3]['control'])],
         'complete exact finite terminal-control population')
    names=[]
    for name,data in all_trials:
        rejected=False
        try:check(data,*args)
        except ValueError as error:
            if name=='preentry_coherent_old_population':
                rejected=str(error)=='exact preentry-order signal partition including the nonreturning final span event'
            else:rejected=name not in specific or str(error)=='exact application publication and unpatched class accounting'
        need(rejected,'complete TRACE terminal reader refuses '+name);names.append(name)
    return dict(refusals=names,legacy_refusals=names[:legacy],span_refusals=names[legacy:legacy+SPAN_ROW_REFUSALS],
        current_row_refusals=names[legacy+SPAN_ROW_REFUSALS:],native_operations=0,original_stderr_sha256=H(stderr))
