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
COVERAGE_ERROR='fresh full proofs plus measured revalidation cover every completed and historical proof'


def joined(actual,result,common_cache):
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
    need(actual['common_full']>=owner['completed'] and
         actual['history_fallbacks']<=history['misses']-history['issues'] and
         actual['common_hits']<=history['decisions']<=actual['common_hits']+actual['common_full'],
         'fresh first common proofs, independently exposed history fallback and actual receipt-call partition')
    need(actual['common_full']+common_cache['revalidated_hits']>=owner['completed']+actual['history_fallbacks'],
         COVERAGE_ERROR)
    return bound-actual['issues']-actual['hits']


def check(stdout,stderr,args,kind,mode,*,dependencies=None):
    program,shared,parse=DEFAULT if dependencies is None else dependencies
    need(mode=='release','the separate descriptor program recipe is exactly release')
    common_cache,without_cache,_=shared.split_cache(stderr,parse)
    actual,ordinary,_=shared.split(without_cache,parse)
    shared.join_cache(common_cache,actual)
    result=program.check(stdout,ordinary,args,kind,mode)
    residual=joined(actual,result,common_cache)
    result.update(descriptor=actual,common_cache=common_cache,descriptor_binding_residual=residual,
        descriptor_count_scope='Actual directory hits, topology hits and common-proof hits are distinct. Binding residual is numerical only; no trap, syscall or fallback attribution.',
        profile='persistent-loop-group-descriptor-program-v1',qualification_credit=False)
    return result


def controls(stdout,stderr,args,kind,mode,*,dependencies=None):
    deps=DEFAULT if dependencies is None else dependencies
    program,shared,parse=deps
    baseline=check(stdout,stderr,args,kind,mode,dependencies=deps)
    _,without_cache,cache_index=shared.split_cache(stderr,parse)
    actual,ordinary,index=shared.split(without_cache,parse)
    if cache_index<=index:index+=1
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
    validate=partial(check,stdout,args=args,kind=kind,mode=mode,dependencies=deps)
    result['common_cache_refusals']=shared.cache_controls(stderr,parse,validate)
    common_cache,_,cache_index=shared.split_cache(stderr,parse)
    history_positions=[i for i,line in enumerate(lines)if line.startswith(shared.HISTORY)]
    need(len(history_positions)==1,'one validated actual history row for coherent coverage controls')
    history_index=history_positions[0]
    need(json.loads(lines[history_index][len(shared.HISTORY):])==history,
         'whole actual history row joins the already validated application certificate')
    coverage=[]
    for label,extra in (('coherent_coverage.no_token',1),('coherent_coverage.token_repartition',2)):
        changed_history=dict(history)
        for name in ('misses','full_calls','decisions'):changed_history[name]+=extra
        fields=dict(actual)
        fields.update(common_full=owner['completed'],history_fallbacks=extra,
                      common_hits=changed_history['decisions'])
        cache=dict(common_cache)
        cache.update(lhc_hits=fields['common_hits']-(extra-1),revalidated_hits=extra-1)
        # Keep the release history equations, first-proof floor, exact hit
        # partition and remaining descriptor inequalities coherent. Only the
        # separate coverage theorem is short by one real proof obligation.
        changed=list(lines)
        for at,prefix,value in ((history_index,shared.HISTORY,changed_history),
                                (index,shared.PREFIX,fields),(cache_index,shared.CACHE_PREFIX,cache)):
            changed[at]=prefix+json.dumps(value,separators=(',',':')).encode()
        supplied=b'\n'.join(changed)+b'\n'
        need(supplied!=stderr,'distinct coherent whole program coverage mutation')
        try:validate(supplied)
        except ValueError as error:
            need(str(error)==COVERAGE_ERROR,'coherent mutation reaches the exact common coverage theorem')
            coverage.append(label)
        else:raise ValueError('accepted coherent common coverage mutation '+label)
    need(len(coverage)==len(set(coverage))==2,'both separate coherent common coverage refusals')
    result['common_coverage_refusals']=coverage
    return result


def configured(program,shared,parse):
    dependencies=(program,shared,parse)
    return SimpleNamespace(prior=program.prior,check=partial(check,dependencies=dependencies),
                           controls=partial(controls,dependencies=dependencies))
