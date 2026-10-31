"""Three actual native/maintained/differential subjects; no asynchronous fault qualification.

Shared positive lease predicates are reused literally. This fixture requires an
exact observed-TLS, still-unregistered REP identity; old cohorts retain their
unobserved-TLS contract. No observed row or prefix is normalized.
"""
import copy,json
import linked_native_probe_reports as probe
from page_selected import need
from persistent_dynamic_reports import (prior,old,reuse,unrolled,current,maps_view,H,
    registration_completed,repeat_completed,_repeat_completed_positive,effect_exit,gate_prefix)
PREFIX=b'LI2_PERSISTENT_ACTIVE_DOMAIN '
SCALARS='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
KEYS=SCALARS+['misses']
CONTROL_COUNTS={(0,0):73}
REPEAT_TLS_CONTROLS=33
REPEAT_TLS_SCOPE='before_first_registration_after_tls_observation'


def repeat_observed_identity(p,pid,application,protected_tls):
    machine=application['machine']
    need(application['header'][5:8]==(0,pid,pid)and type(machine)is tuple and len(machine)==8 and
         all(type(v)is int and 0<=v<1<<64 for v in machine)and 0<machine[1]<1<<47 and machine[2]<1<<47,
         'actual same-process application GET_FS/GET_GS identity')
    fs,gs=machine[1:3]
    need(type(protected_tls)is tuple and len(protected_tls)==3 and
         all(type(v)is tuple and v==(fs,gs)for v in protected_tls),
         'three complete protected before frames match actual application TLS')
    need(p['repeat_lease']['registration']==[1,0,0,0,pid,pid,0,0,0,0,0,fs,gs,1],
         'actual observed-TLS REP has exact whole unregistered identity')
    owner=p['rseq']['owner']
    need(owner[:4]==[1,0,0,0]and owner[7:9]==[pid,pid]and
         owner[13]==p['rseq']['counts'][1]==1 and p['rseq']['counts'][2]==1 and
         p['rseq']['counts'][6]==0,
         'final persistent registration remains source-exact after observed-TLS REP')
    need(p['rseq']['tls']==[1,1,0,0,0,0,fs,gs],
         'actual completed rseq TLS matches application and protected frames')
    return dict(fs_base=fs,gs_base=gs,protected_before_frames=3)


def repeat_completed_observed(p,pid,images,image_bytes,carrier,carrier_bytes,owner,application):
    result=_repeat_completed_positive(p,pid,images,image_bytes,carrier,carrier_bytes,0)
    result['observed_tls']=repeat_observed_identity(p,pid,application,
        tuple((x['before']['fs'],x['before']['gs'])for x in owner['attempts']))
    result['registration_scope']=REPEAT_TLS_SCOPE
    return result


def repeat_tls_controls(stderr,p,pid,images,image_bytes,carrier,carrier_bytes,owner,application):
    protected=tuple((x['before']['fs'],x['before']['gs'])for x in owner['attempts'])
    repeat_observed_identity(p,pid,application,protected);refused=[]
    def changed(name,value,app=application,frames=protected,error='actual observed-TLS REP has exact whole unregistered identity'):
        try:repeat_observed_identity(value,pid,app,frames)
        except ValueError as actual:
            need(str(actual)==error,'exact causal observed-TLS REP refusal');refused.append(name)
        else:raise ValueError('accepted changed observed-TLS REP identity')
    for i in range(14):
        value=copy.deepcopy(p);value['repeat_lease']['registration'][i]^=1
        changed('repeat_registration_'+str(i),value)
    for i in range(8):
        value=copy.deepcopy(p);value['rseq']['tls'][i]^=1
        changed('terminal_tls_'+str(i),value,error='actual completed rseq TLS matches application and protected frames')
    for i in (1,2):
        app=copy.deepcopy(application);machine=list(app['machine']);machine[i]^=1;app['machine']=tuple(machine)
        changed('application_tls_'+str(i),p,app=app,error='three complete protected before frames match actual application TLS')
    for i in range(3):
        for j in range(2):
            frames=[list(x)for x in protected];frames[i][j]^=1
            changed('protected_tls_'+str(i)+'_'+str(j),p,frames=tuple(map(tuple,frames)),
                error='three complete protected before frames match actual application TLS')
    value=copy.deepcopy(p);value['repeat_lease']['registration']=[1,0,0,0,pid,pid]+[0]*8
    changed('unobserved_tls_is_not_active_scenario',value)
    value=copy.deepcopy(p);value['repeat_lease']['registration'][11]^=1;value['rseq']['tls'][6]^=1
    changed('coherent_owner_and_report_tls_disagrees_with_application',value,
        frames=tuple((fs^1,gs)for fs,gs in protected),
        error='three complete protected before frames match actual application TLS')
    try:repeat_completed(p,pid,images,image_bytes,carrier,carrier_bytes,0)
    except ValueError as error:
        need(str(error)=='actual prior REP has whole unregistered identity; final persistent registration is source-exact',
             'original default reader still refuses observed-TLS scenario')
        refused.append('old_default_rejects_observed_tls')
    else:raise ValueError('old default accepted observed-TLS REP')
    need(len(refused)==len(set(refused))==REPEAT_TLS_CONTROLS,'all33 separate exact observed-TLS identity refusals')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))


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


def validate(p,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode,application):
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
        gate=gate,maps_view=view,repeat_lease=repeat_completed_observed(p,pid,images,image_bytes,carrier,carrier_bytes,owner,application),
        input_authentication=prior.cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),
        whole_profile_qualified=False,legacy_protected_rows=False,group_fault_qualification=False)


def check(stderr,*args,lane,application):
    need(lane in('maintained','differential'),'explicit active mapping lane')
    native_probe,original_stream=probe.split(stderr)
    group,suffix=split(original_stream);linked,linked_reuse,suffix=prior.split(suffix)
    scalar,scalar_reuse,suffix=reuse.split(suffix);u,suffix=unrolled.split(suffix)
    cur,suffix=current.split_current(suffix);view,original=maps_view.split_report(suffix,lane)
    parsed=old.reports(original);old.extensions(parsed)
    parsed.update(group=group,linked=linked,linked_reuse=linked_reuse,
        scalar_region=scalar,scalar_reuse=scalar_reuse,unrolled=u,current_tf=cur)
    result=validate(parsed,view,*args,application)
    result['native_probe']=probe.completed(native_probe,linked,parsed['native'],group,
        parsed['chain'],parsed['native_pair'],exercise=True)
    parsed['native_probe']=native_probe
    return parsed,result


def controls(stderr,*args,lane,application):
    p,_=check(stderr,*args,lane=lane,application=application);owner,owner_reader,mode=args[-3:];refused=[]
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
