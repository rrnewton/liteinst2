"""PB capture schema: old full fields plus one literal actual cancellation."""
import importlib.util
from pathlib import Path
_spec=importlib.util.spec_from_file_location('pb_donor_wire',Path(__file__).resolve().parents[1]/'persistent_direct_frontier_owner/wire.py')
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
need,zero,q=old.need,old.zero,old.q
GROUPS=dict(old.GROUPS)
REGISTERED=dict(old.REGISTERED)
for _name in ('pdo_wire','pdo_encoded'):
    _origin,_type=REGISTERED[_name];REGISTERED[_name]=('persistent_block_observe.inc',_type)
LIFETIME=old.LIFETIME
UNIONS=old.UNIONS
GROUPS.update({'li2_pg_miss': ((('version status reason site', 4, 4), ('pc detail', 8, 8)), 8),
 'pbo_cancel': ((('h', 128, 8),
                 ('before returned next', 'le_frame', 64),
                 ('held resumed', 'pdo_stage', 8),
                 ('initial_registry terminal_registry', 'pdo_registry', 8),
                 ('closed_slot resumed_slot', 'li2_tf_chain_slot', 64),
                 ('miss', 'li2_pg_miss', 8),
                 ('plan', 'pbo_miss_plan', 8)),
                64),
 'pbo_miss_plan': ((('version bytes ready result heads exits stores source_bytes source_mask decoder_result '
                     'guard_result reserved',
                     4,
                     4),
                    ('member_heads', 8, 4),
                    ('links reserved2', 4, 4),
                    ('page', 16, 8),
                    ('entry', 8, 8),
                    ('layout', 'li2_pg_layout', 8),
                    ('source', 8192, 1),
                    ('table', 'li2_mg_table', 8),
                    ('scan_started scan_complete scanned nonzero first_nonzero first_value', 8, 8)),
                   8)})
_fields,_alignment=GROUPS['pdo_wire']
GROUPS['pdo_wire']=(_fields+(('cancellation','pbo_cancel',64),),_alignment)

class Reader(old.Reader):
    def __init__(self,data,layout):
        self.data,self.layout,self.types=data,layout,dict(layout['types']);self.padding={}
        self.registered,self.lifetime=REGISTERED,LIFETIME
        need(set(layout)=={'record','types','edges','member_witnesses','symbols','registrations','retained_storage','uc_bytes','uc','si'}and layout['record']=='pdo_wire','distinct retained-two wire layout')
        need(layout['member_witnesses']=={'li2_step_frame.fp':dict(symbol='pdo_step_frame_fp_alignment',bytes=8,alignment=64)},'actual aligned FP witness')
        need(layout['uc_bytes']==968 and layout['uc']==dict(offsets=dict(flags=0,link=8,greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),widths=dict(flags=8,link=8,greg=184,fp_pointer=8,mask=128,stack_sp=8,stack_flags=4,stack_size=8)),'whole actual Linux UC ABI')
        need(layout['si']==dict(bytes=128,offsets=dict(signo=0,errno=4,code=8,addr=16,pid=16,uid=20),widths=dict(signo=4,errno=4,code=4,addr=8,pid=4,uid=4)),'whole actual SI ABI')
        need(set(self.types)==set(GROUPS)==set(layout['edges']),'all and only complete reachable types')
        expected={}
        for t,(declared,alignment)in GROUPS.items():
            fields={};edges={}
            for keys,size,a in declared:
                child=size if type(size)is str else size[0]if type(size)is tuple else None
                n=self.types[child]['bytes']*(size[1]if type(size)is tuple else 1)if child else size
                for k in keys.split():
                    need(k not in fields,'unique declared field');fields[k]=(n,a)
                    if child:edges[k]=child
            self.union_shape(t,fields,alignment)if t in UNIONS else self.shape(t,fields,alignment);expected[t]=edges
        need(layout['edges']==expected,'every exact embedded object and array')
        need(type(data)is memoryview and data.readonly and data.c_contiguous and len(data)==self.types['pdo_wire']['bytes']==5421376,'whole losslessly decoded cross-pair raw schema')
        self.walk(data,'pdo_wire')
        self.types['uh_frame']=self.types['le_frame'];self.padding['uh_frame']=self.padding['le_frame']

    def union_shape(self,t,fields,alignment):
        d=self.types[t]
        need(set(d)=={'bytes','alignment','fields'}and set(d['fields'])==set(fields)and d['alignment']==alignment,'exact typed union field inventory '+t)
        size=max(n for n,_ in fields.values());size=(size+alignment-1)&-alignment
        need(d['bytes']==size,'exact whole typed union extent '+t)
        for name,(n,a)in fields.items():
            f=d['fields'][name]
            need(set(f)=={'offset','bytes','alignment','type'}and(f['offset'],f['bytes'],f['alignment'])==(0,n,a)and type(f['type'])is str and f['type'],'exact typed union member '+t+'.'+name)
        self.padding[t]=[]

    def walk(self,b,t):
        if t in UNIONS:
            # The actual head kind selects an arm in Check.compact; full model
            # equality covers every byte, including unused arms/slot tails.
            need(len(b)==self.types[t]['bytes'],'whole captured typed union '+t)
            return
        return super().walk(b,t)
