#!/usr/bin/env python3
"""Retained-stderr tests of the unused REP helper, not full owner validation.

Supply positive, fault5 and fault6 in that order, each with an exact stderr SHA.
The labels select expected fixture outcomes; historical command/record custody
belongs to the caller. No subject, whole terminal or qualification is replayed.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import persistent_loop_reports as original
import persistent_loop_effects_reports as effects
from page_selected import need

SCALARS='version status failure_code detail_abs detail_negative attempts completed traces retained closes releases queries route pending'.split()
ARRAYS=dict(request=8,source=6,owner=14,event=9,progress=12,frames=14,io=17,query=31,
            release=4,writes=3,borrow=2,custody=21,backing=11,registration=14)
OUTCOME=('status','failure_code','detail_abs','detail_negative')
GLOBALS=(('loader','step_route'),('run','route'),('run','pending'))
SUMMARY=dict(attempts=0,completed=0,queries=0,source_exercised=False)


def controls(parsed,fn,failed):
    need(fn(parsed)==SUMMARY,'actual complete unused REP helper result')
    refused=[]
    def reject(name,change):
        p=copy.deepcopy(parsed);change(p)
        need(json.dumps(p,sort_keys=True)!=json.dumps(parsed,sort_keys=True),
             'every supplied helper mutation is causal including scalar types')
        try:fn(p)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted unused REP helper mutation '+name)
    def replace(row,key,value):
        return lambda p:p[row].__setitem__(key,value)
    for key in SCALARS:
        reject('rep_'+key,replace('repeat_lease',key,parsed['repeat_lease'][key]^1))
    for key,size in ARRAYS.items():
        for index in range(size):
            reject('rep_'+key+'_'+str(index),lambda p,key=key,index=index:
                   p['repeat_lease'][key].__setitem__(index,p['repeat_lease'][key][index]^1))
    for row,key in GLOBALS:
        reject(row+'_'+key,replace(row,key,parsed[row][key]^1))
        reject(row+'_'+key+'_bool',replace(row,key,bool(parsed[row][key])))
    for row in ('loader','run'):
        for key in OUTCOME:
            reject(row+'_'+key,replace(row,key,parsed[row][key]^1))
            reject(row+'_'+key+'_bool',replace(row,key,bool(parsed[row][key])))
    # Coherent wrong global/REP values must fail the literal fixture map even
    # when every cross-row equality still holds. Routes 1/2/3/5 are not waivers.
    for route in (0,1,2,3,4,5,(1<<64)-1):
        if route==parsed['loader']['step_route']:continue
        def wrong_route(p,route=route):
            p['loader']['step_route']=p['run']['route']=p['repeat_lease']['route']=route
        reject('coherent_route_'+str(route),wrong_route)
    for pending in (0,1,2,(1<<64)-1):
        if pending==parsed['run']['pending']:continue
        def wrong_pending(p,pending=pending):
            p['run']['pending']=p['repeat_lease']['pending']=pending
        reject('coherent_pending_'+str(pending),wrong_pending)
    reject('rep_missing',lambda p:p['repeat_lease'].pop('queries'))
    reject('rep_extra',lambda p:p['repeat_lease'].__setitem__('extra',0))
    reject('ordinary_rep_present',lambda p:p.__setitem__('repeat',{}))
    if failed:
        reject('fault_phase',replace('group','phase',14))
        reject('fault_phase_bool',replace('group','phase',True))
    need(len(refused)==len(set(refused))==(216 if failed else 214),
         'literal separate unused REP helper refusal population')
    return len(refused)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lane',required=True,choices=('maintained','differential'))
    ap.add_argument('--case',action='append',nargs=3,required=True,metavar=('LABEL','STDERR','SHA256'))
    a=ap.parse_args()
    need([x[0]for x in a.case]==['positive','fault5','fault6'],'exact three retained input labels')
    need(original.CONTROL_COUNT==335 and effects.CONTROL_COUNT==360,
         'original full-terminal control populations remain separate and unchanged')
    need(original.LEASE_SCALARS==effects.LEASE_SCALARS==SCALARS and
         original.LEASE_ARRAYS==effects.LEASE_ARRAYS==ARRAYS,
         'literal producer scalar and complete array shapes')
    results=[]
    for label,path,sha in a.case:
        need(len(sha)==64 and all(c in '0123456789abcdef'for c in sha),'whole input SHA256')
        b=Path(path).read_bytes()
        need(0<len(b)<=16<<20 and hashlib.sha256(b).hexdigest()==sha,'whole retained bounded stderr')
        p,_=effects.parse(b,a.lane);failed=label!='positive'
        outcome=(125,3304,11,0)if failed else(0,0,0,0)
        need(tuple(p['loader'][k]for k in OUTCOME)==outcome,
             'actual supplied terminal outcome agrees with diagnostic input label')
        counts={name:controls(p,fn,failed)for name,fn in
                (('original',original.repeat_idle),('effects',effects.repeat_idle))}
        results.append(dict(label=label,stderr=dict(bytes=len(b),sha256=sha),
                            outcome=list(outcome),route=p['loader']['step_route'],
                            pending=p['run']['pending'],controls=counts))
    print(json.dumps(dict(profile='unused-rep-global-controls-v1',inputs=results,
        helpers=2,positives=6,refusals=1292,full_terminal_controls_executed=False,
        owner_qualification=False,native_execution=False,performance_credit=False),
        sort_keys=True,separators=(',',':')))


if __name__=='__main__':main()
