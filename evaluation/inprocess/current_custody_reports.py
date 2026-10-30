"""Two additive current-custody outcomes; original25 terminal checks stay exact."""
import copy
import hashlib
import json
from page_selected import need
import maps_view
import page_cost_reports as cost
import page_native_pair_reports as old
import unrolled_hash_reports as unrolled
import unrolled_hash_app_reports as application
from unrolled_hash_app_reports import unused_repeat
H=lambda b:hashlib.sha256(b).hexdigest()


# One real additional guest mprotect in the physical-fallback fixture. This
# whole donor function differs only in its name and exact20->21/87->88 counts.
def physical_fallback_effect_exit(p):
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
    need([o['cpuid_patches']+67,o['syscall_patches']+21,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0,'exact application publication and unpatched class accounting')
    need(e['attempts']==o['published']+88,
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
    current=owner['current_custody'];fallback=current['fallback'];control=current['current_control']
    need(type(fallback)is bool and type(control)is int and
         ((fallback and control==0 and exit_status==0)or(not fallback and control==1 and exit_status==125)),
         'one exact additional physical-fallback or stale-current outcome')
    row,suffix=unrolled.split(stderr);view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    _,same,gate=old.gate(parsed,pid,exit_status,parent,0)
    need(same is parsed and all(row[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative'))and row['observe_only']==0,
         'every additional terminal row retains one exact actual outcome')
    if fallback:owner_reader.terminal(parsed,row,owner)
    else:owner_reader.current_terminal(parsed,row,owner)
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=unused_repeat(parsed),
        input_authentication=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),maps_view=view,
        unrolled={k:row[k]for k in unrolled.COUNTERS},required_refusal=int(exit_status==125))
    if fallback:
        unrolled.completed(row,False)
        summary.update(lease=old.lease.counters(parsed),trace_run=old.trace_completed(parsed),
            native_pair=old.pair_completed(parsed,pid),cache_reuse=old.reuse_completed(parsed['run'],parsed['reuse']))
        physical_fallback_effect_exit(parsed)
    else:
        need(gate['original_completed_rejected']is True and row['first_error']==0,
             'actual stale chain failure is not relabelled as an unrolled failure or completion')
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


# Shared syntax is distinct from the required protected-record owner join.
CURRENT_PREFIX=b'LI2_MAPS_CURRENT_TF '
CURRENT_KEYS=('version status failure_code attempts current_stages current_seeds physical_fallbacks '
              'retained_stages retained_checks commits cancels first_error first_detail_abs first_detail_negative').split()
CURRENT_ROW_REFUSALS=26


def split_current(stderr):
    """Validate one complete first current row; return its unchanged old suffix."""
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete current-custody report stream')
    rows=stderr[:-1].split(b'\n')
    need(len(rows)>1 and rows[0].startswith(CURRENT_PREFIX)and
         sum(line.startswith(CURRENT_PREFIX)for line in rows)==1 and len(rows[0])<=4096 and
         b'\r'not in rows[0],'one bounded first current-custody row followed by unchanged reports')
    row=maps_view.pair.pair_reports.rseq.decode(rows[0][len(CURRENT_PREFIX):])
    need(type(row)is dict and list(row)==CURRENT_KEYS,'complete ordered current-custody schema without duplicate keys')
    need(all(type(row[k])is int and 0<=row[k]<(1<<(32 if k in('version','status','failure_code','first_error')else 64))for k in CURRENT_KEYS),
         'exact unsigned current-custody fields; no bool, float, negative or overflow')
    need(row['version']==1 and row['status']in(0,125)and row['first_detail_negative']in(0,1),
         'exact current-custody version, outcome and sign')
    need(CURRENT_PREFIX+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==rows[0],
         'canonical complete current-custody row')
    return row,b'\n'.join(rows[1:])+b'\n'


def join_current(row,owner,exit_status):
    expected=owner['current_custody']['terminal_current_expected']
    need(row==expected and row['status']==exit_status,
         'every current-custody report field equals the actual protected terminal snapshot')


def delegate(owner):
    current=owner['current_custody']
    return (check,controls)if current['current_control']or current['fallback']else(application.check,application.controls)


def check_current(stderr,*args):
    need(len(args)==9,'whole original terminal-check argument tuple')
    row,suffix=split_current(stderr);owner=args[-2];join_current(row,owner,args[1])
    checked,_=delegate(owner);parsed,summary=checked(suffix,*args)
    summary['maps_current_tf']=row
    return parsed,summary


def controls_current(stderr,*args):
    """Keep every old refusal; add separate full-row mutations after acceptance."""
    check_current(stderr,*args)
    row,suffix=split_current(stderr);_,original=delegate(args[-2]);retained=original(suffix,*args)
    first=stderr.split(b'\n',1)[0];trials=[];semantic=set()
    def changed(name,value):
        trials.append((name,CURRENT_PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()+b'\n'+suffix))
    for key in CURRENT_KEYS:
        value=dict(row);value[key]^=1;changed('current_'+key,value)
        if key not in('version','status'):semantic.add('current_'+key)
    for name,value in(('boolean',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        changed_row=dict(row);changed_row['attempts']=value;changed('current_type_'+name,changed_row)
    short=dict(row);del short['first_error'];changed('current_missing_key',short)
    extra=dict(row);extra['extra']=0;changed('current_extra_key',extra)
    changed('current_reordered',dict(reversed(list(row.items()))))
    next_row,remaining=suffix.split(b'\n',1)
    trials.extend([('current_absent',suffix),('current_duplicate',first+b'\n'+stderr),
        ('current_misplaced',next_row+b'\n'+first+b'\n'+remaining),('current_truncated',stderr[:-1]),
        ('current_duplicate_key',first[:-1]+b',"version":1}\n'+suffix)])
    need(len(trials)==len({name for name,_ in trials})==CURRENT_ROW_REFUSALS,
         'all26 additive current-row refusals; old terminal controls are separate')
    refused=[]
    for name,value in trials:
        caught=False
        try:check_current(value,*args)
        except ValueError as error:
            if name in semantic:need(str(error)=='every current-custody report field equals the actual protected terminal snapshot',
                'current scalar mutation reaches the exact protected-record join')
            caught=True
        need(caught,'complete current terminal reader refuses '+name);refused.append(name)
    return dict(retained,current_row_refusals=refused,native_operations=0,
        original_stderr_sha256=H(stderr),legacy_stderr_sha256=H(suffix))
