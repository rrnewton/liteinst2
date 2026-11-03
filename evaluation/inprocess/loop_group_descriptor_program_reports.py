"""Descriptor observations over every unchanged CACHE8 real-program check.

The shared descriptor parser consumes its actual producer row. Numerical
residuals are not attributed to traps, cold work or a particular fallback.
"""
import json
from functools import partial
from types import SimpleNamespace
from page_selected import need
from loop_ro_oracle_reports import row
import loop_cache8_program_reports as cache8
import loop_group_descriptor_reports as descriptor

prior=cache8.prior
DEFAULT=(cache8,descriptor,row)
CONTROL_COUNT=75


def joined(actual,result):
    owner=result['persistent'];counts=result['cache8']
    history=result['certificate']['history_certificate']
    bound=sum(counts['bound'+str(i)]for i in range(1,9))
    need(actual['status']==actual['failure_code']==0 and actual['initialized']==1 and
         actual['poisoned']in(0,1) and actual['overflows']==actual['disagreements']==0 and
         (actual['unclassified']==0 or actual['poisoned']==1),
         'actual successful descriptor owner and explicit exposure state without counter or proof failure')
    need(actual['descriptor_id']==actual['issues']==actual['directory_writes'] and
         actual['directory_queries']==actual['issues']+actual['hits']<=bound and
         bound==owner['entries']==owner['completed'],
         'actual descriptor issuance, query and complete CACHE8 binding conservation')
    need(1<=actual['writer_epoch']<=actual['raw_invalidations']+1 and
         actual['topology_differential']==actual['common_differential']==0,
         'actual monotone manifest exposure and separately bound release proof mode')
    need(actual['common_full']>=owner['completed']+actual['history_fallbacks'] and
         actual['history_fallbacks']<=history['misses']-history['issues'] and
         actual['common_hits']<=history['decisions']<=actual['common_hits']+actual['common_full'],
         'fresh first common proofs, independently exposed history fallback and actual receipt-call partition')
    return bound-actual['issues']-actual['hits']


def check(stdout,stderr,args,kind,mode,*,dependencies=None):
    program,shared,parse=DEFAULT if dependencies is None else dependencies
    need(mode=='release','the separate descriptor program recipe is exactly release')
    actual,ordinary,_=shared.split(stderr,parse)
    result=program.check(stdout,ordinary,args,kind,mode)
    residual=joined(actual,result)
    result.update(descriptor=actual,descriptor_binding_residual=residual,
        descriptor_count_scope='Actual directory hits, topology hits and common-proof hits are distinct. Binding residual is numerical only; no trap, syscall or fallback attribution.',
        profile='persistent-loop-group-descriptor-program-v1',qualification_credit=False)
    return result


def controls(stdout,stderr,args,kind,mode,*,dependencies=None):
    deps=DEFAULT if dependencies is None else dependencies
    program,shared,parse=deps
    baseline=check(stdout,stderr,args,kind,mode,dependencies=deps)
    actual,ordinary,index=shared.split(stderr,parse)
    inherited=program.controls(stdout,ordinary,args,kind,mode)
    lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'actual supplied whole descriptor-program mutation')
        try:check(stdout,changed,args,kind,mode,dependencies=deps)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted descriptor-program mutation '+label)
    def replace(label,value):
        changed=list(lines);changed[index]=shared.PREFIX+json.dumps(value,separators=(',',':')).encode()
        reject(label,b'\n'.join(changed)+b'\n')
    need(len(shared.FIELDS)==22,'the shared exact descriptor producer schema')
    for name in shared.FIELDS:
        value=dict(actual);del value[name];replace('missing.'+name,value)
        value=dict(actual);value[name]=bool(value[name]);replace('boolean.'+name,value)
    value=dict(actual);value['extra']=0;replace('extra',value)
    replace('key_order',dict(reversed(list(actual.items()))))
    changed=list(lines);changed[index]=lines[index][:-1]+b',"version":1}'
    reject('duplicate_key',b'\n'.join(changed)+b'\n')
    reject('missing_row',b'\n'.join(lines[:index]+lines[index+1:])+b'\n')
    reject('duplicate_row',b'\n'.join(lines[:index]+[lines[index]]+lines[index:])+b'\n')
    changed=list(lines);changed[index],changed[index+1]=changed[index+1],changed[index]
    reject('row_order',b'\n'.join(changed)+b'\n')
    reject('newline',stderr[:-1])
    changed=list(lines);changed[index]=lines[index].replace(b'{',b'{ ',1)
    reject('whitespace',b'\n'.join(changed)+b'\n')
    changed=list(lines);changed[index]+=b' '*4096
    reject('writer_bound',b'\n'.join(changed)+b'\n')
    owner=baseline['persistent'];history=baseline['certificate']['history_certificate']
    bound=sum(baseline['cache8']['bound'+str(i)]for i in range(1,9))
    semantic=(('version',0),('status',1),('failure_code',1),('initialized',0),
        ('poisoned',2),('descriptor_id',actual['issues']+1),('writer_epoch',0),
        ('writer_epoch_bound',actual['raw_invalidations']+2),('overflows',1),
        ('issues',actual['issues']+1),('hits',bound+1),('topology_differential',1),
        ('common_differential',1),('common_hits',history['decisions']+1),
        ('common_full',owner['completed']-1),('history_fallbacks',history['misses']+1),
        ('directory_writes',actual['directory_writes']+1),
        ('directory_queries',actual['directory_queries']+1),('disagreements',1))
    for label,value in semantic:
        fields=dict(actual);fields['writer_epoch'if label=='writer_epoch_bound'else label]=value
        replace('semantic.'+label,fields)
    fields=dict(actual)
    fields.update(issues=bound+1,descriptor_id=bound+1,directory_writes=bound+1,
                  directory_queries=bound+1+actual['hits'])
    replace('coherent_issue_partition',fields)
    fields=dict(actual);fields.update(hits=bound+1,directory_queries=actual['issues']+bound+1)
    replace('coherent_hit_partition',fields)
    fields=dict(actual);fields.update(poisoned=0,unclassified=max(1,actual['unclassified']))
    replace('coherent_unclassified_owner',fields)
    need(len(refusals)==len(set(refusals))==CONTROL_COUNT,
         'all44 schema,9 encoding,19 source-counter and3 coherent descriptor-program refusals')
    result=dict(inherited);result['descriptor_refusals']=refusals
    return result


def configured(program,shared,parse):
    dependencies=(program,shared,parse)
    return SimpleNamespace(prior=program.prior,check=partial(check,dependencies=dependencies),
                           controls=partial(controls,dependencies=dependencies))
