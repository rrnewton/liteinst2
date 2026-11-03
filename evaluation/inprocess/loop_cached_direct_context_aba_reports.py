"""Exact stopped live-proof ABA outcome joined through the original terminal reader."""
import json
from functools import partial
from types import SimpleNamespace
from page_selected import need

CONTROL_COUNT=49

def read(stderr,record,control,mode,*,layout,aba_layout,dependencies):
    parse,common,descriptor,observer=dependencies
    need(type(stderr)is bytes and stderr.endswith(b'\n') and type(control)is int and control==1 and
         mode in('release','differential'),'literal complete live-proof ABA terminal')
    cache,without_cache,_=descriptor.split_cache(stderr,parse)
    actual,ordinary,_=descriptor.split(without_cache,parse)
    descriptor.join_cache(cache,actual)
    observation=partial(observer.terminal_observation,layout=layout,aba_layout=aba_layout)
    base=common.joined(ordinary,record,control,mode,last_epoch=1,observation=observation)
    need((actual['status'],actual['failure_code'],actual['initialized'],actual['poisoned'])==(125,3303,1,1) and
         actual['unclassified']==actual['overflows']==actual['disagreements']==0,
         'actual expected stopped ABA outcome and ordinary abort poison, without another failure')
    need(actual['descriptor_id']==actual['issues']==actual['directory_writes']>0 and
         actual['directory_queries']==actual['issues']+actual['hits'] and
         1<=actual['writer_epoch']<=actual['raw_invalidations']+1 and
         actual['topology_differential']==(actual['topology_hits']if mode=='differential'else 0) and
         actual['common_differential']==(actual['common_hits']if mode=='differential'else 0),
         'original descriptor issue/query conservation and every-hit differential checks')
    return dict(base,descriptor=actual,common_cache=cache,qualification_credit=False,performance_credit=False,
                scope='one actual live-proof ABA refusal; other causal and real-program gates remain separate')

def controls(stderr,record,control,mode,*,layout,aba_layout,dependencies):
    parse,common,descriptor,observer=dependencies
    baseline=read(stderr,record,control,mode,layout=layout,aba_layout=aba_layout,dependencies=dependencies)
    cache,without_cache,cache_index=descriptor.split_cache(stderr,parse)
    actual,ordinary,index=descriptor.split(without_cache,parse)
    if cache_index<=index:index+=1
    observation=partial(observer.terminal_observation,layout=layout,aba_layout=aba_layout)
    old=common.controls_joined(ordinary,record,control,mode,last_epoch=1,observation=observation)
    need(len(old['refusals'])==len(set(old['refusals']))==10,'all ten original shared terminal controls')
    lines=stderr[:-1].split(b'\n');refusals=['shared.'+n for n in old['refusals']]
    validate=partial(read,record=record,control=control,mode=mode,layout=layout,aba_layout=aba_layout,dependencies=dependencies)
    def reject(name,changed):
        need(changed!=stderr,'distinct supplied terminal corruption')
        try:validate(changed)
        except ValueError:refusals.append('descriptor.'+name)
        else:raise ValueError('accepted cached DIRECT terminal corruption '+name)
    for key,value in (('version',0),('status',0),('initialized',0),('poisoned',0),('unclassified',1),
            ('overflows',1),('issues',actual['issues']+1),('directory_writes',actual['directory_writes']+1),
            ('directory_queries',actual['directory_queries']+1),('common_differential',actual['common_differential']+1),
            ('topology_differential',actual['topology_differential']+1),('disagreements',1),('hits',actual['hits']+1)):
        fields=dict(actual);fields[key]=value;changed=list(lines)
        changed[index]=descriptor.PREFIX+json.dumps(fields,separators=(',',':')).encode()
        reject(key,b'\n'.join(changed)+b'\n')
    reject('missing',b'\n'.join(lines[:index]+lines[index+1:])+b'\n')
    reject('duplicate',b'\n'.join(lines[:index]+[lines[index]]+lines[index:])+b'\n')
    common_cache=descriptor.cache_controls(stderr,parse,validate)
    need(len(common_cache)==len(set(common_cache))==24,'all original common-hit partition controls')
    refusals+=['cache.'+n for n in common_cache]
    need(len(refusals)==len(set(refusals))==CONTROL_COUNT,'ten shared, fifteen descriptor and24 cache controls')
    return dict(refusals=refusals,native_operations=0)

def configured(parse,common,descriptor,observer):
    dependencies=(parse,common,descriptor,observer)
    return SimpleNamespace(read=partial(read,dependencies=dependencies),
        controls=partial(controls,dependencies=dependencies),CONTROL_COUNT=CONTROL_COUNT)
