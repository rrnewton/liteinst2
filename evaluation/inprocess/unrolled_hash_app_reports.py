"""Application-owner terminal qualification; no ls/true reader is changed.

The actual full owner record must pass before this report join. Required failed
operations keep exit125 and must be rejected by the original completion gate.
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


# App-only exact partition: its low original-PC effects cannot acquire the
# existing >=8GiB one-shot landing. Successful gated modes0..6 execute all67
# hardware CPUID rows and exactly20 RAW calls: identity/getcpu3, XCOMP2,
# two machine observations6, map/protect4, output2, final getcpu1, unmap2.
# Both complete output records must each use one write; extra short writes
# refuse this finite accounting contract. Final libc exit remains published.
# Keep the shared LS/true completion function and every other predicate exact.
def application_effect_exit(p):
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
    need([o['cpuid_patches']+67,o['syscall_patches']+20,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0,'exact application publication and unpatched class accounting')
    need(e['attempts']==o['published']+87,
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


def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader):
    row,suffix=unrolled.split(stderr)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    _,same,gate=old.gate(parsed,pid,exit_status,parent,0)
    need(same is parsed and all(row[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative')),'all actual terminal rows have one unchanged outcome')
    need(row['observe_only']==0,'actual generated-owner qualification, never observe-only')
    owner_reader.terminal(parsed,row,owner)
    inputs=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes)
    retained=unused_repeat(parsed)
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=retained,
        input_authentication=inputs,maps_view=view,unrolled={k:row[k]for k in unrolled.COUNTERS},
        required_refusal=int(exit_status==125))
    if exit_status==0:
        unrolled.completed(row,False)
        summary.update(lease=old.lease.counters(parsed),trace_run=old.trace_completed(parsed),
            native_pair=old.pair_completed(parsed,pid),cache_reuse=old.reuse_completed(parsed['run'],parsed['reuse']))
        application_effect_exit(parsed)
    else:
        need(exit_status==125 and gate['original_completed_rejected']is True and
             row['first_error']==row['failure_code']>0,'required failed operation retains first error and cannot earn completion')
    return parsed,summary


def controls(stderr,*args):
    """Fixed supplied report changes after actual full-record/report acceptance."""
    parsed,_=check(stderr,*args);row,suffix=unrolled.split(stderr);view,original=maps_view.split_report(suffix,'maintained')
    lines=stderr[:-1].split(b'\n');trials=[];specific=set()
    def changed(name,prefix,record):
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied report target');data=list(lines)
        data[places[0]]=prefix+json.dumps(record,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(data)+b'\n'))
    for key in ('version','status','failure_code','first_error','initialized','observe_only','entries','completed','used','events'):
        value=copy.deepcopy(row);value[key]^=1;changed('owner_'+key,unrolled.PREFIX,value)
    for key in ('signals','current'):
        value=copy.deepcopy(row);value[key][0]^=1;changed('owner_'+key,unrolled.PREFIX,value)
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
            value=copy.deepcopy(parsed['oneshot'])
            need(value[subtract]>0,'actual positive publication class for supplied redistribution')
            value[add]+=1;value[subtract]-=1
            changed(name,b'LI2_ONESHOT ',value);specific.add(name)
    trials.extend([('truncated',stderr[:-1]),('duplicate_owner',stderr+lines[-1]+b'\n'),
        ('missing_owner',suffix),('missing_maps',b'\n'.join(lines[1:])+b'\n')])
    total=35 if parsed['loader']['status']==0 else 33
    need(len(trials)==total and len({n for n,_ in trials})==total,'complete fixed named terminal refusal population')
    names=[]
    for name,data in trials:
        rejected=False
        try:check(data,*args)
        except ValueError as error:
            rejected=name not in specific or str(error)=='exact application publication and unpatched class accounting'
        need(rejected,'complete actual terminal reader rejects '+name);names.append(name)
    return dict(refusals=names,native_operations=0,original_stderr_sha256=H(stderr))
