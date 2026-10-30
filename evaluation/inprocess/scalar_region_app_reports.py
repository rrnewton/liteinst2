"""Distinct fixed40 scalar application reports. All original readers stay intact.

The protected actual record is accepted first. Failed operations keep125 and
must be refused by the original completion gate. No report manufactures state.
"""
import copy
import hashlib
import json
from page_selected import need
import maps_view
import page_cost_reports as cost
import page_native_pair_reports as old
import unrolled_hash_reports as unrolled
H=lambda b:hashlib.sha256(b).hexdigest()
PREFIX=b'LI2_SCALAR_REGION '
KEYS=('version status failure_code detail_abs detail_negative initialized first_error used candidates '
      'source_misses plan_misses capacity_misses publications hits entries completed unexpected events '
      'plan_checks rseq_checks active busy decoding signals refusals exit_indices current').split()
COUNTERS=('used candidates source_misses plan_misses capacity_misses publications hits entries completed '
          'unexpected events plan_checks rseq_checks').split()


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete actual scalar terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>1 and lines[-1].startswith(PREFIX) and len(lines[-1])<=4096 and
         b'\r'not in lines[-1] and sum(x.startswith(PREFIX)for x in lines)==1,
         'one final bounded scalar row')
    row=maps_view.pair.pair_reports.rseq.decode(lines[-1][len(PREFIX):])
    arrays=dict(signals=5,refusals=4,exit_indices=8,current=34)
    need(type(row)is dict and list(row)==KEYS,'complete ordered duplicate-free scalar schema')
    need(all(type(row[k])is int and 0<=row[k]<1<<64 for k in KEYS if k not in arrays),
         'exact unsigned scalar values; no boolean or float')
    for k,n in arrays.items():
        need(type(row[k])is list and len(row[k])==n and all(type(x)is int and 0<=x<1<<64 for x in row[k]),
             'whole unsigned scalar '+k)
    need(row['version']==1 and row['status']in(0,125) and all(row[k]in(0,1)for k in
         ('detail_negative','initialized','active','busy','decoding')),'exact scalar version/status/booleans')
    return row,b'\n'.join(lines[:-1])+b'\n'


def scalar_completed(row):
    need(row['status']==row['failure_code']==row['detail_abs']==row['detail_negative']==row['first_error']==
         row['active']==row['busy']==row['decoding']==row['unexpected']==0 and row['initialized']==1,
         'successful scalar owner has no pending or failed state')
    need(row['events']==sum(row['signals'])>0 and all(row['signals'][i]>0 for i in (0,1,2)) and row['signals'][3:]==[0,0],
         'complete actual scalar handler event population')
    need(0<row['used']==row['publications']<=64 and row['candidates']==row['source_misses']+row['plan_misses']+
         row['capacity_misses']+row['publications']+row['hits'] and row['plan_misses']==sum(row['refusals']) and
         row['entries']==row['publications']+row['hits']==row['completed']==sum(row['exit_indices']) and
         row['plan_checks']==row['publications']+2*row['entries'] and
         row['rseq_checks']==row['publications']+3*row['entries'],
         'all actual scalar attempts, refusal kinds, retained slots and completed exit counts close')
    # Generic candidates also include valid refusals after the last success.
    # The full current prefix is joined by the independent actual-wire reader.


def prior_unrolled(row):
    """Scalar ownership requires this distinct old owner quiet in all outcomes.

    Its global status/code belongs to the actual final scalar outcome. Every
    old owner counter/state predicate remains required; no row is rewritten.
    """
    need(row['observe_only']==0 and row['first_error']==row['active']==row['busy']==
         row['first_detail_abs']==row['first_detail_negative']==0 and row['initialized']==1,
         'actual retained unrolled owner remains initialized and quiet')
    need(row['events']==sum(row['signals']) and row['events']>0 and all(row['signals'][i]>0 for i in (0,1,2)) and
         row['signals'][3:]==[0,0],'whole prior unrolled event population')
    need(0<row['used']==row['publications']<=64 and row['candidates']==row['source_misses']+row['plan_misses']+
         row['capacity_misses']+row['publications']+row['hits'] and
         row['entries']==row['publications']+row['hits']==row['completed']==row['head_exits']+row['stop_exits'] and
         row['unexpected']==0 and row['head_exits']*64+row['stop_exits']<=row['iterations']<=64*row['completed'],
         'unchanged prior unrolled immutable-slot and completion equations')
    c=row['current']
    need(c[0]==1 and c[1]<row['used'] and c[2:5]==[1,1,1] and 1<=c[5]<=64 and
         c[6:14]==[1]*8 and c[14:20]==[0,0,1,1,0,0] and c[20:24]==[1,1,0,0] and
         c[24:]==[4096,4096,4096,0,1],'whole prior owner completed and released without cleanup/fault')


def unused_repeat(p):
    """Whole initialized unused owner; actual global terminal outcome retained."""
    r=p['repeat_lease'];expected=dict.fromkeys(old.LEASE_SCALARS,0);expected['version']=1
    for key in ('status','failure_code','detail_abs','detail_negative'):
        if key in expected:expected[key]=p['loader'][key]
    # These are global controller observations, not unused REP-owner fields.
    expected['route']=p['loader']['step_route'];expected['pending']=p['run']['pending']
    for key,size in old.LEASE_ARRAYS.items():expected[key]=[0]*size
    expected['owner'][-1]=1;expected['custody'][0]=1
    need(r==expected and p['repeat']is None,'complete canonical unused REP state with exact actual terminal status')
    return dict(attempts=0,completed=0,source_observed=False)


# Exact low original-PC effects: all67 CPUIDs;20 syscalls for one invocation,
# four additional machine/getcpu observations for the second, plus2 actual
# source mprotect calls in mode12. Both output writes must be whole writes.
def application_effect_exit(p,mode):
    need(type(mode)is int and mode in (0,1,2,3,4,11,12),'exact completed scalar application mode')
    direct_syscalls=26 if mode==12 else 24 if mode==11 else 20
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']in(60,231)and l['source_syscalls']==l['syscalls']==l['forwarded']>0,'actual successful exit syscall path')
    need(all(e[k]==v for k,v in dict(first_error=0,stage=4,busy=1,finished=0,kind=7,action=1,phase=5,error=0,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=0,exit_entered=1,
        post_guards_complete=0,post_callback_entered=0,post_callback_returned=0,committed=0,
        random_backend_returned=0,random_backend_status=0,fp_after_initialized=0,raw_entered=0,raw_returned=0).items()),
        'literal report-before-raw nonreturning exit prefix; never completed')
    need(0<e['pc']<=(1<<64)-3 and e['next_pc']==e['pc']+2 and
         512<=e['fp_bytes']==e['fp_before_initialized']<=65536 and
         e['sequence']==e['attempts']==e['completed']+1 and e['completed']==e['commits']==e['native_completed']and
         e['scripted_completed']==0 and e['classes']==[l['cpuid'],l['rdrand'],l['rdseed'],l['rdpid'],l['rdtsc'],l['rdtscp'],l['syscalls']-1]and
         sum(e['classes'])==e['completed'],'every returning Native class accounted separately from final exit')
    need(o['published']>8 and o['attempted']==o['published']==o['restored']==o['effect_started']==o['backend_prepared']==l['source_patches']and
         o['completed']==o['retired']==o['effect_returned']==o['backend_completed']==o['last_completed_sequence']==o['published']-1 and
         o['refused']==o['resetting']==o['last_refused_sequence']==o['rseq_error']==0 and o['active_phase']==7 and
         o['rseq_phase']==6 and o['rseq_attempts']==o['published']and o['rseq_retired']==o['retired'],
         'all temporary patches restored; only final exit remains unreturned and unretired')
    need([o['cpuid_patches']+67,o['syscall_patches']+direct_syscalls,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0,'exact application publication and unpatched class accounting')
    need(e['attempts']==o['published']+67+direct_syscalls,
         'complete fixed application direct-effect partition')
    # Each restored plan renews its fixed one or two source pages twice.
    # Page counts are not separately reported; do not invent an exact split.
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')
    need(p['rseq']['owner'][1:4]==[1,1,3]and l['rseq']==p['rseq']['counts'][0]>0,
         'real default inactive registration remains held through process exit')


def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    scalar,suffix=split(stderr);row,suffix=unrolled.split(suffix)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    _,same,gate=old.gate(parsed,pid,exit_status,parent,0)
    need(same is parsed and all(scalar[k]==row[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative')),'all terminal rows retain one actual outcome')
    owner_reader.terminal(parsed,scalar,row,owner)
    inputs=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes)
    prior_unrolled(row);retained=unused_repeat(parsed)
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=retained,input_authentication=inputs,
        maps_view=view,scalar={k:scalar[k]for k in COUNTERS},unrolled={k:row[k]for k in unrolled.COUNTERS},
        required_refusal=int(exit_status==125))
    if exit_status==0:
        scalar_completed(scalar);unrolled.completed(row,False)
        summary.update(lease=old.lease.counters(parsed),trace_run=old.trace_completed(parsed),
            native_pair=old.pair_completed(parsed,pid),cache_reuse=old.reuse_completed(parsed['run'],parsed['reuse']))
        application_effect_exit(parsed,mode)
    else:
        need(exit_status==125 and gate['original_completed_rejected']is True and
             scalar['first_error']==scalar['failure_code']>0,
             'actual scalar failure retains first error and original completion refusal')
    return parsed,summary


def controls(stderr,*args):
    parsed,_=check(stderr,*args);scalar,suffix=split(stderr);row,suffix=unrolled.split(suffix)
    view,original=maps_view.split_report(suffix,'maintained');lines=stderr[:-1].split(b'\n');trials=[];specific=set()
    def changed(name,prefix,record):
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied report target');data=list(lines)
        data[places[0]]=prefix+json.dumps(record,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(data)+b'\n'))
    for key in ('version','status','failure_code','first_error','initialized','entries','completed','used','events','plan_checks','rseq_checks','decoding'):
        value=copy.deepcopy(scalar);value[key]^=1;changed('scalar_'+key,PREFIX,value)
    for key in ('signals','refusals','exit_indices','current'):
        value=copy.deepcopy(scalar);value[key][0]^=1;changed('scalar_'+key,PREFIX,value)
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
    total=51 if parsed['loader']['status']==0 else 49
    need(len(trials)==total and len({n for n,_ in trials})==total,'all fixed named scalar terminal refusals')
    names=[]
    for name,data in trials:
        rejected=False
        try:check(data,*args)
        except ValueError as error:
            rejected=name not in specific or str(error)=='exact application publication and unpatched class accounting'
        need(rejected,'complete scalar terminal reader rejects '+name);names.append(name)
    return dict(refusals=names,native_operations=0,original_stderr_sha256=H(stderr))
