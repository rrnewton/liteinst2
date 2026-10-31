"""Two before-registration exact-root/subentry activations in native/maintained/differential lanes.

Shared positive lease predicates are reused literally. This fixture requires an
exact observed-TLS, still-unregistered REP identity; old cohorts retain their
unobserved-TLS contract. No observed row or prefix is normalized.
"""
import copy,json,hashlib
import linked_native_probe_reports as probe
from page_selected import need
from persistent_dynamic_reports import (prior,old,reuse,unrolled,current,maps_view,H,
    registration_completed,repeat_completed,_repeat_completed_positive,effect_exit as legacy_effect_exit,gate_prefix)
PREFIX=b'LI2_PERSISTENT_UNREGISTERED '
SCALARS='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
KEYS=SCALARS+['misses']
CONTROL_COUNTS={(0,0):73}
REPEAT_TLS_CONTROLS=31
REPEAT_TLS_SCOPE='before_first_registration_after_tls_observation'


def effect_exit(p):
    # Gated source census (main.c): identity3 + hardware2 + prefix-machine3 +
    # mappings5 + prefix-write1 + pre-entry-machine3 + post-entry-machine3 +
    # getcpu1 + rseq2 + munmap3 + suffix-write1 + entry.S exit_group1 = 28.
    # hardware() issues exactly67 CPUIDs; the40-byte interpreter issues one.
    # This exact fixture contract rejects extra/partial-write effect paths.
    calls=3+2+3+5+1+3+3+1+2+3+1+1
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']==231 and l['source_syscalls']==l['syscalls']==l['forwarded']==calls,'exact tiny fixture successful exit syscall path')
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
    need(o['published']==1 and o['attempted']==o['published']==o['restored']==o['effect_started']==o['backend_prepared']==l['source_patches']and
         o['completed']==o['retired']==o['effect_returned']==o['backend_completed']==o['last_completed_sequence']==o['published'] and
         o['refused']==o['resetting']==o['last_refused_sequence']==o['rseq_error']==0 and o['active_phase']==0 and
         o['rseq_phase']==0 and o['rseq_attempts']==o['published']and o['rseq_retired']==o['retired'],
         'sole interpreter CPUID patch restored completed and retired before direct exit')
    need([o['cpuid_patches']+67,o['syscall_patches']+calls,o['rdtsc_patches']]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0 and
         [o[k]for k in('cpuid_patches','syscall_patches','rdtsc_patches')]==[1,0,0]and
         all(l[k]==0 for k in('rdrand','rdseed','rdpid','rdtsc','rdtscp')),
         'exact tiny fixture publication and unpatched class accounting')
    need(e['attempts']==o['published']+67+calls,
         'complete fixed application direct-effect partition')
    # Retain the original general generation bound, then bind this one-page
    # interpreter-entry CPUID (first two bytes, no page straddle).
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(generation_delta==2,'exact one-page interpreter CPUID generation advances')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')

EFFECT_CONTROL_COUNT=12

def effect_controls(stderr,p):
    """Separate tiny-fixture controls; the original73 terminal controls remain."""
    effect_exit(p);refused=[]
    def changed(name,value,error):
        try:effect_exit(value)
        except ValueError as actual:
            need(str(actual)==error,'exact causal tiny effect refusal '+name);refused.append(name)
        else:raise ValueError('accepted changed tiny fixture effect partition '+name)
    publication='sole interpreter CPUID patch restored completed and retired before direct exit'
    census='exact tiny fixture publication and unpatched class accounting'
    calls='exact tiny fixture successful exit syscall path'
    value=copy.deepcopy(p);o=value['oneshot']
    for key in('completed','retired','effect_returned','backend_completed','last_completed_sequence','rseq_retired'):o[key]=0
    o['active_phase']=7;o['rseq_phase']=6
    changed('old_patched_final_exit_is_not_this_fixture',value,publication)
    for count in(0,2):
        value=copy.deepcopy(p);o=value['oneshot'];l=value['loader'];e=value['effect'];cp=value['cpuid_nx']
        for key in('attempted','published','restored','effect_started','backend_prepared','completed','retired',
                   'effect_returned','backend_completed','last_completed_sequence','rseq_attempts','rseq_retired','cpuid_patches'):o[key]=count
        l['source_patches']=count;l['cpuid']=cp['attempts']=cp['samples']=cp['commits']=67+count
        e['sequence']=e['attempts']=95+count
        e['completed']=e['commits']=e['native_completed']=94+count;e['classes'][0]=67+count
        changed('coherent_interpreter_publications_'+str(count),value,publication)
    value=copy.deepcopy(p);value['oneshot']['cpuid_patches']=0;value['oneshot']['syscall_patches']=1
    changed('wrong_published_effect_kind',value,census)
    value=copy.deepcopy(p);l=value['loader'];e=value['effect']
    for key in('source_syscalls','syscalls','forwarded'):l[key]+=1
    for key in('sequence','attempts','completed','commits','native_completed'):e[key]+=1
    e['classes'][6]+=1
    changed('coherent_extra_direct_syscall',value,calls)
    value=copy.deepcopy(p);l=value['loader'];e=value['effect'];cp=value['cpuid_nx']
    l['cpuid']-=1
    for key in('attempts','samples','commits'):cp[key]-=1
    for key in('sequence','attempts','completed','commits','native_completed'):e[key]-=1
    e['classes'][0]-=1
    changed('coherent_missing_direct_cpuid',value,census)
    value=copy.deepcopy(p);value['effect']['raw_entered']=1
    changed('exit_raw_claimed_before_report',value,'literal report-before-raw nonreturning exit prefix; never completed')
    value=copy.deepcopy(p);value['loader']['rdseed']=1;e=value['effect'];e['classes'][2]=1
    for key in('sequence','attempts','completed','commits','native_completed'):e[key]+=1
    changed('coherent_extra_random_effect',value,census)
    value=copy.deepcopy(p)
    for name in('loader','oneshot'):value[name]['generations']+=2
    changed('coherent_two_page_generation_claim',value,'exact one-page interpreter CPUID generation advances')
    value=copy.deepcopy(p);value['loader']['last_syscall']=60
    changed('different_exit_syscall',value,calls)
    value=copy.deepcopy(p);value['oneshot']['active_phase']=7
    changed('completed_patch_still_active',value,publication)
    try:legacy_effect_exit(p)
    except ValueError as error:
        need(str(error)=='all temporary patches restored; only final exit remains unreturned and unretired',
             'original libc-cohort effect reader remains unchanged')
        refused.append('original_effect_scope_remains_distinct')
    else:raise ValueError('old effect reader accepted tiny fixture partition')
    need(len(refused)==len(set(refused))==EFFECT_CONTROL_COUNT,'all12 separate exact tiny effect controls')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))


def repeat_observed_identity(p,pid,application,protected_tls):
    machine=application['machine']
    need(application['header'][5:8]==(0,pid,pid)and type(machine)is tuple and len(machine)==8 and
         all(type(v)is int and 0<=v<1<<64 for v in machine)and machine[1:3]==(0,0),
         'actual same-process application GET_FS/GET_GS identity')
    fs,gs=machine[1:3]
    need(type(protected_tls)is tuple and len(protected_tls)==2 and
         all(type(v)is tuple and v==(fs,gs)for v in protected_tls),
         'two complete protected before frames match actual application TLS')
    need(p['repeat_lease']['registration']==[1,0,0,0,pid,pid,0,0,0,0,0,fs,gs,1],
         'actual observed-TLS REP has exact whole unregistered identity')
    owner=p['rseq']['owner']
    need(owner[:4]==[1,0,0,0]and owner[7:9]==[pid,pid]and
         owner[13]==p['rseq']['counts'][1]==1 and p['rseq']['counts'][2]==1 and
         p['rseq']['counts'][6]==0,
         'final persistent registration remains source-exact after observed-TLS REP')
    need(p['rseq']['tls']==[1,1,0,0,0,0,fs,gs],
         'actual completed rseq TLS matches application and protected frames')
    return dict(fs_base=fs,gs_base=gs,protected_before_frames=2)


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
        changed('application_tls_'+str(i),p,app=app,error='actual same-process application GET_FS/GET_GS identity')
    for i in range(2):
        for j in range(2):
            frames=[list(x)for x in protected];frames[i][j]^=1
            changed('protected_tls_'+str(i)+'_'+str(j),p,frames=tuple(map(tuple,frames)),
                error='two complete protected before frames match actual application TLS')
    value=copy.deepcopy(p);value['repeat_lease']['registration']=[1,0,0,0,pid,pid]+[0]*8
    changed('unobserved_tls_is_not_active_scenario',value)
    value=copy.deepcopy(p);value['repeat_lease']['registration'][11]^=1;value['rseq']['tls'][6]^=1
    changed('coherent_owner_and_report_tls_disagrees_with_application',value,
        frames=tuple((fs^1,gs)for fs,gs in protected),
        error='two complete protected before frames match actual application TLS')
    try:repeat_completed(p,pid,images,image_bytes,carrier,carrier_bytes,0)
    except ValueError as error:
        need(str(error)=='actual prior REP has whole unregistered identity; final persistent registration is source-exact',
             'original default reader still refuses observed-TLS scenario')
        refused.append('old_default_rejects_observed_tls')
    else:raise ValueError('old default accepted observed-TLS REP')
    need(len(refused)==len(set(refused))==REPEAT_TLS_CONTROLS,'all31 separate exact observed-TLS identity refusals')
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
    need(row['version']==1 and PREFIX+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==lines[-1],
         'canonical distinct unregistered v1 row')
    return row,b'\n'.join(lines[:-1])+b'\n'


def validate(p,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader,mode,application):
    need(type(mode)is int and mode==0 and type(exit_status)is int and exit_status==0 and owner['mode']==0,
         'actual before-registration loader-loop outcome')
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
    subentry,without_subentry=subentry_split(stderr)
    native_probe,original_stream=probe_row_split(without_subentry)
    group,suffix=split(original_stream);linked,linked_reuse,suffix=prior.split(suffix)
    scalar,scalar_reuse,suffix=reuse.split(suffix);u,suffix=unrolled.split(suffix)
    cur,suffix=current.split_current(suffix);view,original=maps_view.split_report(suffix,lane)
    parsed=old.reports(original);old.extensions(parsed)
    parsed.update(group=group,linked=linked,linked_reuse=linked_reuse,
        scalar_region=scalar,scalar_reuse=scalar_reuse,unrolled=u,current_tf=cur)
    result=validate(parsed,view,*args,application)
    owner,owner_reader,mode=args[-3:];result['subentry']=owner_reader.subentry_terminal(subentry,owner);parsed['subentry']=subentry
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
            need(str(error)=='whole actual protected subentry terminal row','exact isolated protected-row refusal')
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
        try:registration_completed(p['loader'],value,args[0],0)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed actual registration')
    lines=stderr[:-1].split(b'\n')
    for name,data in(('missing_persistent',b'\n'.join(lines[:-1])+b'\n'),('truncated',stderr[:-1]),
        ('duplicate_persistent',stderr+lines[-1]+b'\n'),('wrong_version',stderr.replace(PREFIX+b'{"version":1,',PREFIX+b'{"version":0,',1))):
        need(data!=stderr,'actual causal parser control')
        try:split(data)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted malformed persistent terminal stream')
    need(len(refused)==len(set(refused))==CONTROL_COUNTS[mode,0],'all73 distinct active-domain terminal refusals')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))

SUBENTRY_PREFIX=b'LI2_PERSISTENT_SUBENTRY '
SUBENTRY_KEYS='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split()
SUBENTRY_CONTROL_COUNT=19

def subentry_split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete subentry terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>3 and lines[-1].startswith(PREFIX)and lines[-2].startswith(SUBENTRY_PREFIX)and
         sum(x.startswith(SUBENTRY_PREFIX)for x in lines)==1 and len(lines[-2])<=4096 and b'\r'not in lines[-2],
         'one actual subentry row immediately before final unregistered row')
    row=maps_view.pair.pair_reports.rseq.decode(lines[-2][len(SUBENTRY_PREFIX):])
    need(type(row)is dict and list(row)==SUBENTRY_KEYS and all(type(v)is int and 0<=v<1<<64 for v in row.values())and row['version']==1 and
         SUBENTRY_PREFIX+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==lines[-2],
         'canonical complete separate subentry row')
    return row,b'\n'.join(lines[:-2]+lines[-1:])+b'\n'

def probe_row_split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete native-probe terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>2 and lines[-1].startswith(PREFIX)and lines[-2].startswith(probe.PREFIX)and
         sum(x.startswith(probe.PREFIX)for x in lines)==1,'one native-probe row immediately before active row')
    return probe.decode(lines[-2]),b'\n'.join(lines[:-2]+lines[-1:])+b'\n'

def subentry_controls(stderr,owner,owner_reader):
    row,_=subentry_split(stderr);owner_reader.subentry_terminal(row,owner);refused=[]
    for key in SUBENTRY_KEYS:
        mutant=copy.deepcopy(row);mutant[key]^=1
        try:owner_reader.subentry_terminal(mutant,owner)
        except ValueError as error:need(str(error)=='whole actual protected subentry event row','exact subentry row refusal');refused.append(key)
        else:raise ValueError('accepted supplied subentry row mutation')
    lines=stderr[:-1].split(b'\n')
    cases=(('missing',b'\n'.join(lines[:-2]+lines[-1:])+b'\n'),('duplicate',b'\n'.join(lines[:-1]+lines[-2:])+b'\n'),
           ('version',stderr.replace(SUBENTRY_PREFIX+b'{"version":1,',SUBENTRY_PREFIX+b'{"version":0,',1)),('truncated',stderr[:-1]))
    for name,value in cases:
        need(value!=stderr,'actual causal subentry parser mutation')
        try:subentry_split(value)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted malformed subentry terminal row')
    need(len(refused)==SUBENTRY_CONTROL_COUNT,'all15 protected subentry cells and4 parser controls')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))

def probe_controls(stderr,parsed):
    original_stderr=stderr
    _,stderr=subentry_split(stderr)
    original,_=probe_row_split(stderr);refused=[]
    l,n,d,c,q=(parsed[k]for k in('linked','native','group','chain','native_pair'))
    probe.completed(original,l,n,d,c,q,exercise=True)
    def reject(name,fn,message):
        try:fn()
        except ValueError as error:
            need(str(error)==message,'exact native-probe causal refusal '+name);refused.append(name)
        else:raise ValueError('accepted native-probe corruption '+name)
    lines=stderr[:-1].split(b'\n');index=len(lines)-2
    for name,changed in(
        ('missing_row',lines[:index]+lines[index+1:]),
        ('duplicate_row',lines[:index]+[lines[index]]+lines[index:]),
        ('wrong_position',lines[:-2]+lines[-2:][::-1])):
        reject(name,lambda changed=changed:probe_row_split(b'\n'.join(changed)+b'\n'),
               'one native-probe row immediately before active row')
    row=dict(original);row['version']=2
    reject('wrong_version',lambda:probe.decode(probe.PREFIX+json.dumps(row,separators=(',',':')).encode()),
           'canonical exact native-probe schema')
    changes=(
        ('status',1,'successful native-probe outcome'),
        ('errors',1,'successful native-probe outcome'),
        ('pending',1,'native-probe completion has no pending or negative outcome'),
        ('outcome_result_negative',1,'native-probe completion has no pending or negative outcome'),
        ('lookups',original['lookups']+1,'native-probe lookup partition'),
        ('policy_checks',original['policy_checks']+1,'native-probe lookup partition'),
        ('policy_blocked',original['policy_blocked']+1,'native-probe policy partition'),
        ('chosen',original['chosen']+1,'native-probe policy partition'),
        ('next_nx',original['next_nx']+1,'native-probe real refault and NX outcome partition'),
        ('admitted',original['admitted']+1,'native-probe real refault and NX outcome partition'),
        ('refused',original['refused']+1,'native-probe real refault and NX outcome partition'),
        ('outcome_complete',1-original['outcome_complete'],'native-probe last actual outcome'),
        ('outcome_result_abs',2,'native-probe last actual outcome'))
    for key,value,message in changes:
        row=dict(original);row[key]=value
        reject(key,lambda row=row:probe.completed(row,l,n,d,c,q,exercise=True),message)
    row=dict(original);row['refaults']=l['refusals'][2]+1
    reject('graph_refusal_class',lambda:probe.completed(row,l,n,d,c,q,exercise=True),
           'native-probe refaults are actual graph refusals')
    linked=copy.deepcopy(l);linked['refaults']=linked['refusals'][3]+1
    reject('relocation_refusal_class',lambda:probe.completed(original,linked,n,d,c,q,exercise=True),
           'native-probe preserves relocation refault class')
    linked=copy.deepcopy(l);linked['offers']+=1
    reject('linked_partition',lambda:probe.completed(original,linked,n,d,c,q,exercise=True),
           'native-probe exact linked offer partition')
    chain=copy.deepcopy(c);chain['nx_entries']+=1
    reject('chain_partition',lambda:probe.completed(original,l,n,d,chain,q,exercise=True),
           'native-probe exact ordinary chain partition')
    native=copy.deepcopy(n);native['admissions']=original['admitted']-1
    reject('actual_native_admissions',lambda:probe.completed(original,l,native,d,c,q,exercise=True),
           'native-probe outcomes join actual native and NX counters')
    need(len(refused)==len(set(refused))==probe.CONTROL_COUNT,'all separate native-probe reader controls')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=hashlib.sha256(original_stderr).hexdigest())
