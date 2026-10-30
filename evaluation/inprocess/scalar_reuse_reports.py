"""Typed terminal rows for LI2_SCALAR_REGION_REUSE=1 only.

This is schema/accounting support, not an actual-owner record validator. The
protected generation/permit/image records must be accepted independently.
Original scalar v1 and all prior terminal readers remain unchanged.
"""
from page_selected import need
import scalar_region_app_reports as old

PREFIX=b'LI2_SCALAR_REUSE '
KEYS=('version status failure_code detail_abs detail_negative generation retirement_attempts '
      'retirements claims permits_issued pending retiring cursor').split()


def split(stderr):
    """Return (actual scalar-v2 row, actual reuse-v1 row, untouched earlier rows)."""
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete reuse terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>2 and lines[-2].startswith(PREFIX) and lines[-1].startswith(old.PREFIX) and
         sum(x.startswith(PREFIX)for x in lines)==1 and
         sum(x.startswith(old.PREFIX)for x in lines)==1 and
         all(len(x)<=4096 and b'\r'not in x for x in lines[-2:]),
         'one bounded final reuse row followed by one scalar row')
    decode=old.maps_view.pair.pair_reports.rseq.decode
    reuse=decode(lines[-2][len(PREFIX):]);row=decode(lines[-1][len(old.PREFIX):])
    need(type(reuse)is dict and list(reuse)==KEYS and
         all(type(reuse[k])is int and 0<=reuse[k]<1<<64 for k in KEYS),
         'complete ordered duplicate-free reuse schema with unsigned integers')
    arrays=dict(signals=5,refusals=4,exit_indices=8,current=34)
    need(type(row)is dict and list(row)==old.KEYS and
         all(type(row[k])is int and 0<=row[k]<1<<64 for k in old.KEYS if k not in arrays),
         'complete ordered scalar-v2 schema with unsigned integers')
    for k,n in arrays.items():
        need(type(row[k])is list and len(row[k])==n and
             all(type(x)is int and 0<=x<1<<64 for x in row[k]),'whole unsigned scalar '+k)
    need(row['version']==2 and reuse['version']==1 and row['status']in(0,125) and
         all(row[k]in(0,1)for k in ('detail_negative','initialized','active','busy','decoding')) and
         all(reuse[k]in(0,1)for k in ('detail_negative','pending','retiring')) and reuse['cursor']<64,
         'distinct reuse versions, actual status, booleans and bounded cursor')
    need(all(row[k]==reuse[k]for k in ('status','failure_code','detail_abs','detail_negative')),
         'both rows retain the same actual terminal outcome')
    return row,reuse,b'\n'.join(lines[:-2])+b'\n'


def scalar_completed(row,reuse):
    """Successful complete accounting only; failures require their actual prefix."""
    need(row['status']==row['failure_code']==row['detail_abs']==row['detail_negative']==row['first_error']==
         row['active']==row['busy']==row['decoding']==row['unexpected']==0 and row['initialized']==1 and
         reuse['status']==reuse['failure_code']==reuse['detail_abs']==reuse['detail_negative']==
         reuse['pending']==reuse['retiring']==0,'successful reuse has no pending or failed owner')
    need(row['events']==sum(row['signals'])>0 and all(row['signals'][i]>0 for i in (0,1,2)) and
         row['signals'][3:]==[0,0],'complete actual scalar handler population')
    need(0<row['used']==min(row['publications'],64) and
         row['candidates']==row['source_misses']+row['plan_misses']+row['capacity_misses']+
             row['publications']+row['hits'] and row['plan_misses']==sum(row['refusals']) and
         row['entries']==row['publications']+row['hits']==row['completed']==sum(row['exit_indices']) and
         row['plan_checks']==row['publications']+2*row['entries']+reuse['retirement_attempts'] and
         row['rseq_checks']==row['publications']+3*row['entries'],
         'all actual candidates, static proofs, live guards and original exits close')
    need(reuse['generation']==row['publications'] and
         reuse['retirement_attempts']==reuse['retirements']==row['publications']-row['used'] and
         reuse['claims']==reuse['permits_issued']==row['completed'] and
         reuse['cursor']==reuse['retirements']%64,
         'monotonic generations, completed retirement and one consumed/reissued permit per entry')


import copy
import json
H=old.H
maps_view,cost,unrolled=old.maps_view,old.cost,old.unrolled
COUNTERS=old.COUNTERS
prior_unrolled,unused_repeat,application_effect_exit=old.prior_unrolled,old.unused_repeat,old.application_effect_exit
# Original generic terminal APIs stay unchanged.
prior=old.old

def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    scalar,reuse,suffix=split(stderr);row,suffix=unrolled.split(suffix)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=prior.reports(original);prior.extensions(parsed)
    _,same,gate=prior.gate(parsed,pid,exit_status,parent,0)
    need(same is parsed and all(scalar[k]==row[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative')),'all terminal rows retain one actual outcome')
    owner_reader.terminal(parsed,scalar,row,owner,reuse)
    inputs=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes)
    prior_unrolled(row);retained=unused_repeat(parsed)
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=retained,input_authentication=inputs,
        maps_view=view,reuse={k:reuse[k]for k in KEYS},scalar={k:scalar[k]for k in COUNTERS},unrolled={k:row[k]for k in unrolled.COUNTERS},
        required_refusal=int(exit_status==125))
    if exit_status==0:
        scalar_completed(scalar,reuse);unrolled.completed(row,False)
        summary.update(lease=prior.lease.counters(parsed),trace_run=prior.trace_completed(parsed),
            native_pair=prior.pair_completed(parsed,pid),cache_reuse=prior.reuse_completed(parsed['run'],parsed['reuse']))
        application_effect_exit(parsed,mode)
    else:
        need(exit_status==125 and gate['original_completed_rejected']is True and
             scalar['first_error']==scalar['failure_code']>0,
             'actual scalar failure retains first error and original completion refusal')
    return parsed,summary


def controls(stderr,*args):
    parsed,_=check(stderr,*args);scalar,reuse,suffix=split(stderr);row,suffix=unrolled.split(suffix)
    view,original=maps_view.split_report(suffix,'maintained');lines=stderr[:-1].split(b'\n');trials=[];specific=set()
    def changed(name,prefix,record):
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied report target');data=list(lines)
        data[places[0]]=prefix+json.dumps(record,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(data)+b'\n'))
    for key in ('version','status','failure_code','first_error','initialized','entries','completed','used','events','plan_checks','rseq_checks','decoding'):
        value=copy.deepcopy(scalar);value[key]^=1;changed('scalar_'+key,old.PREFIX,value)
    for key in ('signals','refusals','exit_indices','current'):
        value=copy.deepcopy(scalar);value[key][0]^=1;changed('scalar_'+key,old.PREFIX,value)
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
    trials.extend([('truncated',stderr[:-1]),('duplicate_scalar',stderr+lines[-1]+b'\n'),
        ('missing_scalar',b'\n'.join(lines[:-1])+b'\n'),('missing_maps',b'\n'.join(lines[1:])+b'\n')])
    for key in KEYS:
        value=dict(reuse);value[key]^=1;changed('reuse_'+key,PREFIX,value)
    trials.extend([('duplicate_reuse',stderr+lines[-2]+b'\n'),
        ('missing_reuse',b'\n'.join(lines[:-2]+lines[-1:])+b'\n'),
        ('reordered_complete_rows',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n')])
    total=67 if parsed['loader']['status']==0 else 65
    need(len(trials)==total and len({n for n,_ in trials})==total,'all fixed named scalar terminal refusals')
    names=[]
    for name,data in trials:
        rejected=False
        try:check(data,*args)
        except ValueError as error:
            rejected=name not in specific or str(error)=='exact application publication and unpatched class accounting'
        need(rejected,'complete scalar terminal reader rejects '+name);names.append(name)
    return dict(refusals=names,native_operations=0,original_stderr_sha256=H(stderr))
