"""Three actual native/maintained/differential subjects; no asynchronous fault qualification.

Legacy report predicates are reused literally. The active-domain row has its own exact
schema and protected-owner join; no old version or prefix is normalized.
"""
import copy,json
from page_selected import need
from persistent_dynamic_reports import (prior,old,reuse,unrolled,current,maps_view,H,
    registration_completed,repeat_completed,effect_exit,gate_prefix)
PREFIX=b'LI2_PERSISTENT_ACTIVE_DOMAIN '
SCALARS='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
KEYS=SCALARS+['misses']
CONTROL_COUNTS={(0,0):73}


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete persistent terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>1 and lines[-1].startswith(PREFIX)and sum(x.startswith(PREFIX)for x in lines)==1 and
         len(lines[-1])<=4096 and b'\r'not in lines[-1],'one bounded final persistent row')
    row=maps_view.pair.pair_reports.rseq.decode(lines[-1][len(PREFIX):])
    need(type(row)is dict and list(row)==KEYS and all(type(row[k])is int and 0<=row[k]<1<<64 for k in SCALARS)and
         type(row['misses'])is list and len(row['misses'])==18 and
         all(type(n)is int and 0<=n<1<<64 for n in row['misses']),
         'complete ordered exact-int persistent row')
    need(row['version']==4 and PREFIX+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==lines[-1],
         'canonical distinct active-domain v4 row')
    return row,b'\n'.join(lines[:-1])+b'\n'


def validate(p,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode):
    need(type(mode)is int and mode==0 and type(exit_status)is int and exit_status==0 and owner['mode']==0,
         'actual active-domain loop-only outcome')
    for name in('loader','group','linked','linked_reuse','scalar_region','scalar_reuse','unrolled','current_tf'):
        need(all(p[name][k]==0 for k in('status','failure_code','detail_abs','detail_negative')if k in p[name]),
             'actual consistent successful loop outcome '+name)
    joined=owner_reader.terminal(p['group'],owner)
    gate=gate_prefix(p,pid,exit_status,parent)
    registration_completed(p['loader'],p['rseq'],pid,0)
    effect_exit(p)
    return dict(application_completed=1,required_failure=0,mode=0,terminal_join=joined,
        gate=gate,maps_view=view,repeat_lease=repeat_completed(p,pid,images,image_bytes,carrier,carrier_bytes,0),
        input_authentication=prior.cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),
        whole_profile_qualified=False,legacy_protected_rows=False,group_fault_qualification=False)


def check(stderr,*args,lane):
    need(lane in('maintained','differential'),'explicit active mapping lane')
    group,suffix=split(stderr);linked,linked_reuse,suffix=prior.split(suffix)
    scalar,scalar_reuse,suffix=reuse.split(suffix);u,suffix=unrolled.split(suffix)
    cur,suffix=current.split_current(suffix);view,original=maps_view.split_report(suffix,lane)
    parsed=old.reports(original);old.extensions(parsed)
    parsed.update(group=group,linked=linked,linked_reuse=linked_reuse,
        scalar_region=scalar,scalar_reuse=scalar_reuse,unrolled=u,current_tf=cur)
    return parsed,validate(parsed,view,*args)


def controls(stderr,*args,lane):
    p,_=check(stderr,*args,lane=lane);owner,owner_reader,mode=args[-3:];refused=[]
    for key,index in [(key,None)for key in SCALARS]+[('misses',i)for i in range(18)]:
        value=copy.deepcopy(p['group'])
        if index is None:value[key]^=1
        else:value[key][index]^=1
        try:owner_reader.terminal(value,owner)
        except ValueError as error:
            need(str(error)=='whole actual protected active-domain terminal row','exact isolated protected-row refusal')
            refused.append('protected_'+key+(''if index is None else '_'+str(index)))
        else:raise ValueError('accepted changed actual protected active-domain row')
    for name,row,key,index in(('effect_sequence','effect','sequence',None),('effect_fp','effect','fp_before_initialized',None),
        ('effect_class','effect','classes',6),('effect_raw_return','effect','raw_returned',None),
        ('direct_syscalls','oneshot','syscall_patches',None),('direct_cpuid','oneshot','cpuid_patches',None),
        ('retirement','oneshot','retired',None),('last_syscall','loader','last_syscall',None)):
        value=copy.deepcopy(p)
        if index is None:value[row][key]^=1
        else:value[row][key][index]^=1
        try:effect_exit(value)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed actual effect census')
    for name,key,index in(('registration_calls','counts',0),('registration_phase','owner',3),
                          ('registration_epoch','owner',13),('registration_flags','args',2)):
        value=copy.deepcopy(p['rseq']);value[key][index]^=1
        try:registration_completed(p['loader'],value,args[0],mode)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed actual registration')
    lines=stderr[:-1].split(b'\n')
    for name,data in(('missing_persistent',b'\n'.join(lines[:-1])+b'\n'),('truncated',stderr[:-1]),
        ('duplicate_persistent',stderr+lines[-1]+b'\n'),('wrong_version',stderr.replace(PREFIX+b'{"version":4,',PREFIX+b'{"version":3,',1))):
        need(data!=stderr,'actual causal parser control')
        try:split(data)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted malformed persistent terminal stream')
    need(len(refused)==len(set(refused))==CONTROL_COUNTS[mode,0],'all73 distinct active-domain terminal refusals')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))
