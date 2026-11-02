#!/usr/bin/env python3
"""Additive source-only PF fallthrough model; no observed completion or guest run.

The effects case uses the literal retained lp_inputs bytes at0x403618. The old
API case substitutes its already-described CPUID stop, leaving its grammar
unchanged. Existing eight/136 history controls execute first and stay intact.
"""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
old_controls=load('frontier_existing_controls',HERE/'fused_history_controls.py')
old=load('frontier_original_history',HERE/'history.py')
effects=load('frontier_effects_history',HERE.parent/'persistent_loop_effects_owner/history.py')
need=old.need
# Exact retained source from failed e5d3635 maintained/differential mode6/place3.
PREFIX=bytes.fromhex('48b8001000000050000041c7810010000061623d0049890049894018482d000e0000498940304883c0804989404049c740481e00000085ff7521')
FALL=bytes.fromhex('41c681f80100000141c681800200000041c681000300007841c6818103000000c3')


def fixture(effect):
    page,bank,entry,pc,target=0x402000,0x6000000,0x403618,0x403650,0x403673
    need(len(PREFIX)==58 and PREFIX[-2:]==b'\x75\x21','literal retained JNE source and offset')
    source=bytearray(b'\xcc'*8192);source[entry-page:entry-page+len(PREFIX)]=PREFIX
    stop=FALL if effect else b'\x0f\xa2'+b'\xcc'*29
    source[pc+2-page:pc+2-page+len(stop)]=stop;source=bytes(source)
    window=source[pc-page:pc-page+15]
    decoded=struct.pack('<2Q10I',pc,pc+2,1,0,176,0,16,0,0,15,2,0)+window+bytes(1)
    original=bytearray(336);original[:72]=decoded
    struct.pack_into('<Q',original,72,target)
    struct.pack_into('<Q6I',original,80,target,4,0,64,1,8,0)
    struct.pack_into('<9I',original,256,1,1,0,1,5,1,0,0,0)
    struct.pack_into('<I',original,292,0x40)
    description=decoded+struct.pack('<2Q8I',target,pc+2,1,1,0,15,1,5,1,0)
    row=struct.pack('<8I',5,1,pc-(page+4096),2,2,128,129,217)
    raw=struct.pack('<8IQ',1,0,11,10,2,0,0,0,0x10002)+row+original+description
    need(len(raw)==528,'literal whole saved descriptor construction')
    layout=(bank,bank+0x10000,bank+0x20000,bank+0x21000,bank+0x22000,bank+0x23000)
    member=dict(header=dict(version=2,plan_policy=11,layout=struct.pack('<6Q',*layout),table=bank+0x40000),
        source=dict(entry=entry,page=[dict(identity={'address':page+4096*i},bytes=source[4096*i:4096*(i+1)])for i in range(2)]))
    check=old_controls.Values()
    if effect:check.image['persistent_binding']['encoding_domain']['policies']=[11,12,13]
    return check,dict(count=1,member=[member,{}],direct_exit=raw),source


def main():
    old_controls.main()
    positives=0;rejected=[]
    for effect,history in((False,old),(True,effects)):
        check,c,source=fixture(effect);result=history.direct_history(check,c)
        need(result['policy']==11 and result['heads']==11 and result['exits']==2 and
             result['head']==10 and result['tokens']==(128,129)and result['external_mask']==1 and
             result['pc']==0x403650 and result['target']==0x403673 and result['generated_length']==217,
             'exact independently described saved taken arm with unsupported ordinary fallthrough')
        rebuilt=history.fused.graph((0x402000,0x403000),source,0x403618)
        need(history.fused.unsupported_frontier(rebuilt,10,1)==0x403652,
             'ordinary frontier maps to literal original PC, never a generated slot or stub')
        # The prior head-only rule must reject this exact producer-valid shape.
        need(not rebuilt['heads'][10]['successors'][1]<len(rebuilt['heads']),
             'causal counterexample to the previous head-only predicate')
        positives+=1
        raw_tests=(('gap_token',64,'<I',11),('wrong_frontier_token',64,'<I',128),
            ('unbounded_token',64,'<I',130),('heads',8,'<I',12),('exits',16,'<I',3),
            ('selected_arm',24,'<I',1),('wrong_target',480,'<Q',0x403674),
            ('ready_frontier_source',None,None,None))
        for name,at,fmt,value in raw_tests:
            changed=copy.deepcopy(c)
            if at is None:
                member=changed['member'][0];data=bytearray(member['source']['page'][1]['bytes'])
                # Replace the first stop byte with an admitted NOP; whole source graph must change.
                data[0x652]=0x90;member['source']['page'][1]['bytes']=bytes(data)
            else:
                data=bytearray(changed['direct_exit']);struct.pack_into(fmt,data,at,value);changed['direct_exit']=bytes(data)
            need(changed!=c,'nonidentity full saved-completion corruption')
            try:history.direct_history(check,changed)
            except ValueError:rejected.append((effect,name))
            else:raise ValueError('accepted malformed historical frontier '+name)
        for name in('ready','no_refusal','wrong_pc','wrong_head','wrong_arm','backward_arm'):
            changed=copy.deepcopy(rebuilt);frontier=changed['exits'][1]
            if name in('ready','no_refusal','wrong_pc'):
                data=bytearray(frontier['original'])
                if name=='wrong_pc':struct.pack_into('<Q',data,0,0x403653)
                else:struct.pack_into('<I',data,260 if name=='ready'else 264,1 if name=='ready'else 0)
                frontier['original']=bytes(data)
            elif name=='wrong_head':frontier['head']=10
            elif name=='wrong_arm':frontier['arm']=1
            else:changed['heads'][10]['external']=2
            need(changed!=rebuilt,'nonidentity source-graph frontier corruption')
            try:history.fused.unsupported_frontier(changed,10,1)
            except ValueError:rejected.append((effect,name))
            else:raise ValueError('accepted malformed source-graph frontier '+name)
    need((positives,len(rejected))==(2,28),'fixed additive ordinary-frontier model population')
    print(json.dumps(dict(schema=1,scope='descriptive-model-only',positives=positives,
        negative_controls=len(rejected),subjects=0,actual_completions=0,qualification_credit=False),sort_keys=True))


if __name__=='__main__':main()
