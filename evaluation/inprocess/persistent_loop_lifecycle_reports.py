"""Exact successful terminal contract for the separate schema15 lifecycle.

The real application has the same30-call successful syscall chronology and
67 application CPUIDs as paired-v2. Its four generated lifetimes, mixed warm
entry, held cancellation, original store replay and replacement are proved by
the distinct protected reader and actual native pair, never terminal counts.
The original exercised REP/native-probe cohort remains mandatory separately.
"""
import copy
import json
from page_selected import need
import persistent_loop_reports as focal
prior=focal.prior
H=focal.H
CONTROL_COUNT=335
parse=focal.parse
effect_exit=focal.effect_exit
registration_prefix=focal.registration_prefix
probe_partition=focal.probe_partition
repeat_idle=focal.repeat_idle


def validate(p,view,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,
             owner,owner_reader,mode,application):
    need(type(mode)is int and mode in(0,1)and application['mode']==owner['mode']==mode and
         application['lane']==1 and type(application['placement'])is int and
         application['placement']in(0,1)and application['placement']==owner['placement']and
         owner['schema_version']==15 and application['application_complete']is True and
         application['actual_fault']is False,
         'actual same successful schema15 orientation and placement')
    status=code=detail=0
    need(type(exit_status)is int and exit_status==0 and
         (owner['status'],owner['code'],owner['detail'])==(0,0,0),
         'only an actual complete zero companion outcome')
    for name in('loader','group','linked','linked_reuse','scalar_region','scalar_reuse','unrolled','current_tf'):
        need(all(p[name][k]==value for k,value in
             (('status',0),('failure_code',0),('detail_abs',0),('detail_negative',0))if k in p[name]),
             'same actual successful companion outcome '+name)
    terminal=owner_reader.terminal(p['group'],owner)
    subentry=owner_reader.subentry_terminal(p['subentry'],owner)
    refusal=owner_reader.pf_terminal(p['pf_refusals'],owner)
    new=owner_reader.loop_terminal(p['loop_runtime'],owner)
    gate=prior.gate_prefix(p,pid,exit_status,parent)
    registration_prefix(p['loader'],p['rseq'],pid,mode)
    machine=application['machine'];attempts=owner['attempts']
    need(application['header'][4:8]==(mode,0,pid,pid)and type(machine)is tuple and len(machine)==8 and
         machine[1:3]==(0,0)and type(attempts)is list and len(attempts)==4 and
         all((a['before']['fs'],a['before']['gs'])==machine[1:3]for a in attempts)and
         p['rseq']['tls']==[1,1,0,0,0,0,*machine[1:3]],
         'whole actual companion application, all protected ingress and terminal unregistered TLS')
    need(owner['orientation']==((12,11)if mode==0 else(11,12))and
         all(owner[k]==v for k,v in dict(cold_publications=3,warm_entries=1,
             generated_entries=4,generated_completed=4,dual_entries=1,completion_permits=5,
             original_branch_replays=4,ordinary_store_replays=1,interior_signals=0,
             companion_replacements=1).items()),
         'exact separate protected four-lifetime chronology, never inferred from global terminal counts')
    # Actual successful calls: identity3 + hardware2 + prefix-machine3 +
    # mappings8 + prefix-write1 + pre-entry-machine3 + post-machine3 +
    # getcpu1 + source-mprotect1 + munmap3 + suffix-write1 + exit_group1.
    # machine.S adds no syscall. The original interpreter adds one CPUID.
    effect_exit(p)
    return dict(application_completed=1,required_terminal_negative=0,
        mode=mode,placement=application['placement'],status=0,code=0,signal=0,
        generated_completed=4,terminal_join=terminal,subentry=subentry,pf_refusals=refusal,
        loop_runtime=new,gate=gate,maps_view=view,repeat_lease=repeat_idle(p),
        native_probe=probe_partition(p['native_probe'],p['linked'],p['native'],p['group'],p['chain'],
                                     p['native_pair'],status,code,detail),
        native_probe_exercise_credit=False,REP_exercise_credit=False,
        input_authentication=prior.prior.cost._retained_inputs(images,image_bytes,carrier,carrier_bytes),
        whole_profile_qualified=False,legacy_protected_rows=False,performance_credit=False)


def check(stderr,*args,lane):
    need(lane in('maintained','differential'),'exact paired maintained/differential lane')
    parsed,view=parse(stderr,lane)
    return parsed,validate(parsed,view,*args)


def controls(stderr,*args,lane):
    parsed,view=parse(stderr,lane);validate(parsed,view,*args)
    refused=[]
    def reject(name,fn):
        try:fn()
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied paired terminal mutation '+name)
    def changed(row,key,index=None,value=None):
        p=copy.deepcopy(parsed)
        if index is None:p[row][key]=p[row][key]^1 if value is None else value
        else:p[row][key][index]^=1
        reject(row+'_'+key+(''if index is None else '_'+str(index)),lambda:validate(p,view,*args))
    for row in('group','subentry','pf_refusals','loop_runtime','native_probe','repeat_lease'):
        for key,value in parsed[row].items():
            if type(value)is int:changed(row,key,value=2 if row=='native_probe'and key=='outcome_result_abs'else None)
            else:
                need(type(value)is list and all(type(v)is int for v in value),'literal numeric terminal controls')
                for index in range(len(value)):changed(row,key,index)
    effect_fields=(('effect','sequence',None),('effect','fp_before_initialized',None),
        ('effect','classes',6),('effect','raw_returned',None),('effect','stage',None),
        ('effect','committed',None),('oneshot','cpuid_patches',None),('oneshot','syscall_patches',None),
        ('oneshot','retired',None),('loader','last_syscall',None),('loader','source_syscalls',None),
        ('loader','generations',None))
    for row,key,index in effect_fields:changed(row,key,index)
    for key,index in(('counts',0),('owner',3),('owner',13),('args',2),('tls',6),('tls',7)):
        changed('rseq',key,index)
    # Every malformed stream re-enters the complete parser; no normalized row
    # or zero-filled placeholder can stand in for the actual bytes.
    lines=stderr[:-1].split(b'\n')
    for index,prefix in enumerate((b'LI2_LOOP_RUNTIME ',b'LI2_PF_REFUSALS ',
                                  b'LI2_PERSISTENT_SUBENTRY ',b'LI2_PERSISTENT_UNREGISTERED ')):
        pos=next(i for i,line in enumerate(lines)if line.startswith(prefix))
        for kind,value in(('missing',b'\n'.join(lines[:pos]+lines[pos+1:])+b'\n'),
            ('duplicate',b'\n'.join(lines[:pos]+[lines[pos]]+lines[pos:])+b'\n'),
            ('version',stderr.replace(prefix+b'{"version":1,',prefix+b'{"version":0,',1))):
            need(value!=stderr,'causal terminal parser control')
            reject('stream_'+str(index)+'_'+kind,lambda value=value:check(value,*args,lane=lane))
    reject('stream_truncated',lambda:check(stderr[:-1],*args,lane=lane))
    # Existing maps schema/equations still run on both maintained and fresh-read
    # differential streams, including every mismatch and enabled-mode predicate.
    for key,value in(('version',2),('enabled',0),('differential',int(lane!='differential')),
        ('poisoned',1),('reserved',1),('mismatches',1),('queries',view['queries']+1),
        ('comparisons',view['comparisons']+1),('hits',0),('refreshes',0)):
        v=dict(view);v[key]=value;changed_lines=list(lines)
        changed_lines[0]=prior.maps_view.PREFIX+json.dumps(v,separators=(',',':'),allow_nan=False).encode()
        candidate=b'\n'.join(changed_lines)+b'\n';need(candidate!=stderr,'causal maps terminal mutation')
        reject('maps_'+key,lambda candidate=candidate:check(candidate,*args,lane=lane))
    need(len(refused)==len(set(refused))==CONTROL_COUNT,'whole fixed paired terminal refusal population')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=H(stderr))
