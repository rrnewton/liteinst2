#!/usr/bin/env python3
"""Additive by-value model regression; no captured/native/owner observations.

Run after installing the reviewed sources. These descriptive dictionaries are
inputs to the actual saved-value checker, never evidence of a real completion.
The real collector still requires all original native/owner/lifecycle controls.
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
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
HERE=Path(__file__).resolve().parent
history=load('loop_fused_model_history',HERE/'history.py')
plan=load('loop_fused_model_plan',HERE.parent/'persistent_loop_lifecycle_owner/plan.py')
need=history.need
DOMAIN=dict(version=2,policies=[11,12],near_record=1,far_record=2,
    miss='source-derived-rel32-or-rip-indirect-u64',literal_bytes=8,literal_boundaries=0,old_pf_api=False)

class Values:
    def __init__(self):
        self.r=self;self.image={'persistent_binding':{'encoding_domain':copy.deepcopy(DOMAIN)}}
    def f(self,value,kind,field):return value[field]
    def i(self,value,kind,field):
        value=value[field];need(type(value)is int,'literal integer descriptive model field');return value
    def items(self,value,kind,field,child):return value[field]
    def eq(self,value,kind,**expected):
        for name,want in expected.items():need(value[name]==want,'exact descriptive '+kind+'.'+name)

def fixture(page,bank,mixed):
    source=plan.source_image(page,0x900000)
    layout=(bank,bank+0x10000,bank+0x20000,bank+0x21000,bank+0x22000,bank+0x23000)
    table_address=bank+0x40000
    ranges=[(page,page+8192),(bank,bank+0x8000),(bank+0x10000,bank+0x18000),
            (bank+0x20000,bank+0x26000),(table_address,table_address+4224)]
    table=plan.table(ranges,table_address)
    graph=plan.graph(source,page,page+256,layout,table,policy=11,endpoint=0x900000)
    head=3;model=graph['direct_models'][head];row=graph['head'][head*32:(head+1)*32]
    original=graph['original_rows'][head]
    member=int(mixed)
    raw=struct.pack('<8IQ',1,member,4,head,1,0,0,0,0x10002)+row+original+model['description']
    need(len(raw)==528,'whole descriptive saved exit, not a wire observation')
    def saved(entry,policy):
        return dict(header=dict(version=2,plan_policy=policy,layout=struct.pack('<6Q',*layout),table=table_address),
            source=dict(entry=entry,page=[dict(identity={'address':page+i*4096},bytes=source[i*4096:(i+1)*4096])for i in range(2)]))
    members=[saved(page+512,12),saved(page+256,11)]if mixed else[saved(page+256,11),{}]
    return Values(),dict(count=2 if mixed else 1,member=members,direct_exit=raw),graph

def main():
    positives=near=far=0;refused=[]
    for page in(0x4000000,0x700000000000):
        for bank in(0x6000000,0x700002000000):
            for mixed in(False,True):
                check,c,graph=fixture(page,bank,mixed);actual=history.direct_history(check,c)
                need(actual['policy']==11 and actual['heads']==4 and actual['exits']==1 and
                     actual['tokens']==(128,)and actual['pc']==page+266 and actual['target']==page+512,
                     'complete independently generated B11 historical cut')
                is_far=struct.unpack_from('<I',graph['direct_models'][3]['record'])[0]==2
                need(actual['generated_length']==215 if is_far else actual['generated_length']==206,
                     'one source-derived historical LD encoding extent')
                if not is_far:
                    old=history.old.direct_history(check,c)
                    need(all(actual[k]==v for k,v in old.items()),'every original near PF history result retained')
                positives+=1;far+=is_far;near+=not is_far
                tests=[]
                def raw(name,at,fmt,value):
                    def change(k,v):
                        data=bytearray(v['direct_exit']);struct.pack_into(fmt,data,at,value);v['direct_exit']=bytes(data)
                    tests.append((name,change))
                for name,at,value in(('heads',8,5),('exits',16,2),('index',20,1),('arm',24,1),('reserved',28,1)):
                    raw(name,at,'<I',value)
                raw('flags_tf',32,'<Q',0x10102)
                raw('row_token',40+20,'<I',129)
                raw('other_encoding_extent',40+28,'<I',206 if is_far else 215)
                raw('original_pc',72,'<Q',page+267)
                raw('description_target',408+72,'<Q',page+513)
                def header(k,v):v['member'][int(mixed)]['header']['plan_policy']=12
                tests.append(('header_policy',header))
                def geometry(k,v):
                    h=v['member'][int(mixed)]['header'];data=bytearray(h['layout'])
                    struct.pack_into('<Q',data,0,struct.unpack_from('<Q',data)[0]+1);h['layout']=bytes(data)
                tests.append(('unaligned_layout',geometry))
                def table(k,v):v['member'][int(mixed)]['header']['table']+=1
                tests.append(('unaligned_table',table))
                for key,value in(('version',1),('far_record',1),('literal_bytes',7),('near_record',True)):
                    def domain(k,v,key=key,value=value):k.image['persistent_binding']['encoding_domain'][key]=value
                    tests.append(('domain_'+key,domain))
                for name,change in tests:
                    k=copy.deepcopy(check);v=copy.deepcopy(c);change(k,v)
                    need(v!=c or json.dumps(k.image,sort_keys=True)!=json.dumps(check.image,sort_keys=True),'nonidentity descriptive negative')
                    try:history.direct_history(k,v)
                    except ValueError:refused.append((page,bank,mixed,name))
                    else:raise ValueError('accepted descriptive PF history corruption '+name)
    need((positives,near,far,len(refused))==(8,4,4,136),'fixed additive model populations')
    print(json.dumps(dict(schema=1,scope='descriptive-model-only',positives=positives,near=near,far=far,
        negative_controls=len(refused),subjects=0,actual_completions=0,qualification_credit=False),sort_keys=True))

if __name__=='__main__':main()
