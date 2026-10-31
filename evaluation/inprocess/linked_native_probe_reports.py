"""Actual first-probe terminal evidence; no native authority or killed prefix."""
import copy
import hashlib
import json
from page_selected import need
import page_native_pair_reports as pair
CHAIN_KEYS=pair.chain.KEYS|pair.lease.EXTRA

PREFIX=b'LI2_LINKED_NATIVE_PROBE '
FINAL=b'LI2_PERSISTENT_ACTIVE_DOMAIN '
KEYS=('version status failure_code detail_abs detail_negative pending outcome_complete '
      'outcome_result_abs outcome_result_negative lookups current_declines negative_hits '
      'policy_checks policy_blocked chosen refaults next_nx admitted refused errors').split()
CONTROL_COUNT=22


def decode(line):
    need(type(line)is bytes and line.startswith(PREFIX)and len(line)<=4096 and b'\r'not in line,
         'bounded complete native-probe row')
    row=json.loads(line[len(PREFIX):])
    need(type(row)is dict and list(row)==KEYS and
         all(type(row[k])is int and 0<=row[k]<1<<64 for k in KEYS)and row['version']==1 and
         PREFIX+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==line,
         'canonical exact native-probe schema')
    return row


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete native-probe terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>2 and lines[-1].startswith(FINAL)and lines[-2].startswith(PREFIX)and
         sum(x.startswith(PREFIX)for x in lines)==1,'one native-probe row immediately before active row')
    return decode(lines[-2]),b'\n'.join(lines[:-2]+lines[-1:])+b'\n'


def chain_row(stderr):
    lines=[x for x in stderr.splitlines()if x.startswith(b'LI2_CHAIN ')]
    need(len(lines)==1 and len(lines[0])<=4096,'one actual complete probe chain row')
    row=json.loads(lines[0][10:])
    need(type(row)is dict and set(row)==CHAIN_KEYS and row['scope']=='opt_in_same_page_tf_lease'and
         row['version']==1 and all(type(v)is int and 0<=v<1<<64 for k,v in row.items()if k!='scope')and
         b'LI2_CHAIN '+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==lines[0],
         'whole actual probe chain schema')
    return row


def pair_row(stderr):
    lines=[x for x in stderr.splitlines()if x.startswith(b'LI2_NATIVE_PAIR ')]
    need(len(lines)==1 and len(lines[0])<=4096,'one actual complete probe native-pair row')
    row=json.loads(lines[0][16:]);pair.pair_schema(row)
    need(b'LI2_NATIVE_PAIR '+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==lines[0],
         'whole actual probe native-pair schema')
    return row


def completed(p,l,n,d,c,q,*,exercise=False):
    need(type(exercise)is bool,'explicit probe exercise scope')
    need(all(p[k]==0 for k in('status','failure_code','detail_abs','detail_negative','errors'))and
         all(row[k]==0 for row in(l,d,c,q)for k in('status','failure_code','detail_abs','detail_negative'))and
         n['status']==n['failure_code']==0,'successful native-probe outcome')
    need(p['pending']==0 and p['outcome_result_negative']==0,'native-probe completion has no pending or negative outcome')
    # These are different real refusal classes. Never inflate relocation
    # counts or rewrite a supplied old row to account for a GRAPH retry.
    need(l['refaults']<=l['refusals'][3],'native-probe preserves relocation refault class')
    need(p['refaults']<=l['refusals'][2],'native-probe refaults are actual graph refusals')
    need(p['lookups']==p['current_declines']+p['negative_hits']+p['policy_checks'],
         'native-probe lookup partition')
    need(p['policy_checks']==p['policy_blocked']+p['chosen'],'native-probe policy partition')
    need(p['chosen']==p['refaults']==p['next_nx']==p['admitted']+p['refused'],
         'native-probe real refault and NX outcome partition')
    need((not p['chosen']and p['outcome_complete']==p['outcome_result_abs']==0)or
         (p['chosen']>0 and p['outcome_complete']==1 and p['outcome_result_abs']in(0,1)and
          p['refused'if p['outcome_result_abs']==0 else'admitted']>0),
         'native-probe last actual outcome')
    need(p['admitted']<=n['admissions'] and p['admitted']<=q['counts'][1]<=q['counts'][0] and
         p['refused']<=q['counts'][0]-q['counts'][1] and p['next_nx']<=l['signals'][0],'native-probe outcomes join actual native and NX counters')
    need(l['offers']==l['closed']==l['entries']+l['resumed']+l['refaults']+p['refaults'],
         'native-probe exact linked offer partition')
    need(c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries'] and c['sequence']==c['trace_entries']and
         c['nx_entries']==c['fallbacks']+l['entries']+l['refaults']+p['refaults']+d['entries']and
         c['trace_entries']+c['fallbacks']<=c['preparations']<=2*(c['trace_entries']+c['fallbacks'])and
         c['releases']==c['preparations']+c['nx_entries'],
         'native-probe exact ordinary chain partition')
    if exercise:need(p['admitted']>0,'actual finite native-probe admission exercised')
    return dict(p)


def controls(stderr,parsed):
    original,_=split(stderr);refused=[]
    l,n,d,c,q=(parsed[k]for k in('linked','native','group','chain','native_pair'))
    completed(original,l,n,d,c,q,exercise=True)
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
        reject(name,lambda changed=changed:split(b'\n'.join(changed)+b'\n'),
               'one native-probe row immediately before active row')
    row=dict(original);row['version']=2
    reject('wrong_version',lambda:decode(PREFIX+json.dumps(row,separators=(',',':')).encode()),
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
        reject(key,lambda row=row:completed(row,l,n,d,c,q,exercise=True),message)
    row=dict(original);row['refaults']=l['refusals'][2]+1
    reject('graph_refusal_class',lambda:completed(row,l,n,d,c,q,exercise=True),
           'native-probe refaults are actual graph refusals')
    linked=copy.deepcopy(l);linked['refaults']=linked['refusals'][3]+1
    reject('relocation_refusal_class',lambda:completed(original,linked,n,d,c,q,exercise=True),
           'native-probe preserves relocation refault class')
    linked=copy.deepcopy(l);linked['offers']+=1
    reject('linked_partition',lambda:completed(original,linked,n,d,c,q,exercise=True),
           'native-probe exact linked offer partition')
    chain=copy.deepcopy(c);chain['nx_entries']+=1
    reject('chain_partition',lambda:completed(original,l,n,d,chain,q,exercise=True),
           'native-probe exact ordinary chain partition')
    native=copy.deepcopy(n);native['admissions']=original['admitted']-1
    reject('actual_native_admissions',lambda:completed(original,l,native,d,c,q,exercise=True),
           'native-probe outcomes join actual native and NX counters')
    need(len(refused)==len(set(refused))==CONTROL_COUNT,'all separate native-probe reader controls')
    return dict(refusals=refused,native_operations=0,original_stderr_sha256=hashlib.sha256(stderr).hexdigest())
