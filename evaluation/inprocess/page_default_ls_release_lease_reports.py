"""Fixed lease report adapter over the unchanged release application checks.

Finite no-ioctl completion remains untouched. Real lease closes stay separate
from transfers and from the old owner's actual opening/revoke/release fields.
"""
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PROFILE='page-default-ls-tf-same-page-release-performance-v1'
EXTRA=set('lease_phase lease_active lease_candidates lease_misses lease_transfers lease_closed lease_event lease_fetch_phase lease_fetch_before lease_fetch_after'.split())
def need(ok,message):
    if not ok:raise ValueError(message)
def finite_reader():
    path=ROOT/'tools/page-entry/selected/tests/tf_same_page/reports.py'
    spec=importlib.util.spec_from_file_location('release_lease_finite_reports',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def counters(parsed):
    l,c=parsed['lease'],parsed['chain']
    need(type(l)is dict and set(l)==EXTRA and all(type(v)is int and 0<=v<1<<64 for v in l.values()),
         'complete typed actual lease fields')
    need(l['lease_phase']in(4,5)and l['lease_active']==0 and
         l['lease_transfers']+l['lease_misses']==l['lease_candidates']and
         0<l['lease_closed']<=l['lease_transfers']and l['lease_closed']<=c['steps']and
         0<l['lease_event']<=c['event']and l['lease_fetch_before']>0 and
         ((l['lease_fetch_phase']==4 and l['lease_fetch_after']==l['lease_fetch_before']+1)or
          (l['lease_fetch_phase']==5 and l['lease_fetch_after']==0))and
         (l['lease_phase']!=4 or l['lease_fetch_phase']==5),
         'exercised lease with balanced candidates, completed owner closures and terminal fetch/event state')
    return dict(candidates=l['lease_candidates'],misses=l['lease_misses'],transfers=l['lease_transfers'],
        completed_lease_closures=l['lease_closed'],actual_owner_steps=c['steps'],
        actual_preparations=c['preparations'],actual_releases=c['releases'],
        completed_generic_instructions=c['steps']+l['lease_transfers'],
        terminal_permission_masks=[{k:c['s'+str(i)+'_'+k]for k in('open','opened','revoke','revoked')}for i in(0,1)])
def check(stderr,pid,exit_code,parent,old,base):
    finite=finite_reader();parsed=finite.reports(stderr,lease=True)
    need(finite.EXTRA==EXTRA,'same exact finite lease field inventory')
    normalized=[]
    for line in stderr[:-1].split(b'\n'):
        prefix,sep,raw=line.partition(b' ')
        if prefix in(b'LI2_LOADER',b'LI2_CHAIN'):
            value=json.loads(raw,object_pairs_hook=base.unique)
            if prefix==b'LI2_LOADER':
                need(value['scope']=='partial_selected_same_page_tf_lease','actual lease loader scope')
                value['scope']='partial_selected_native_pages_cpuid_nx'
            else:
                need(value['scope']=='opt_in_same_page_tf_lease'and EXTRA<=set(value),'actual lease chain scope/fields')
                for key in EXTRA:del value[key]
                value['scope']='opt_in_trace_to_plain'
            line=prefix+b' '+json.dumps(value,separators=(',',':'),sort_keys=True).encode()
        normalized.append(line)
    gate,original,observed=base.check(b'\n'.join(normalized)+b'\n',pid,exit_code,parent,old)
    need(gate==parsed['tcgets']and original=={k:v for k,v in parsed.items()if k not in('tcgets','lease')},
         'unchanged complete application rows and TTY-query result joins')
    original['lease']=parsed['lease']
    if exit_code==0:counters(original)
    return gate,original,observed
def project(value,receipt):
    need(receipt['profile']==PROFILE,'explicit lease performance profile')
    for sample in receipt['samples']:
        if not sample['accepted']or sample['lane']!='gated':continue
        name='ls-'+str(sample['sample'])+'-gated'
        need(sample['same_page_lease']==counters(receipt['terminal_reports'][name]),
             'accepted public lease counters equal the actual retained terminal report')
    if value['performance_credit']:
        need(sum(s['accepted']and s['lane']=='gated'for s in receipt['samples'])==5,
             'every one of five gated measurements exercises and closes real leases')
    value['profile']=PROFILE
    value['lease_counter_scope']='Transfers are completed generic instructions without a new open/close; completed_lease_closures require the original actual revoke/release. Old owner steps/preparations/releases retain their meanings. Terminal permission masks cover only the two retained owner slots, not cumulative mprotect calls.'
