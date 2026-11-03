"""Distinct retained-RX transport; exact independent declarations match actual DWARF."""
import importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
base=load('resident_rx_wire_donor',Path(__file__).resolve().parents[1]/'resident_generation_owner/wire.py')
need,zero,q=base.need,base.zero,base.q
REGISTERED={k:v for k,v in base.REGISTERED.items()if k!='rgo_bundle'}
REGISTERED['rrx_bundle']=('resident_rx_observe.inc','rrx_bundle')
LIFETIME=base.LIFETIME
UNIONS=base.UNIONS
DECLARATIONS=dict(base.GROUPS)
DECLARATIONS.pop('rgo_bundle')
DECLARATIONS['li2_r3_rx_call']=((('attempted succeeded',8,8),),8)
DECLARATIONS['li2_r3_rx_progress']=((('call',('li2_r3_rx_call',8),8),
    ('retained_entries execution_releases suspensions resumptions retirements terminal_attempted terminal_closed',8,8)),8)
DECLARATIONS['li2_r3_owner']=(base.GROUPS['li2_r3_owner'][0]+
    (('rx_lifetime',4,4),('rx_release','li2_fetch_progress',8)),64)
DECLARATIONS['r3o_state']=(base.GROUPS['r3o_state'][0]+
    (('rx_lifetime',4,4),('rx_release','li2_fetch_progress',8),
     ('rx_progress','li2_r3_rx_progress',8)),8)
_fields=list(base.GROUPS['r3o_wire'][0])
_at=next(i for i,row in enumerate(_fields)if row[0]=='generation_before')
_fields.insert(_at+1,('rx_before','li2_r3_rx_progress',8))
DECLARATIONS['r3o_wire']=(tuple(_fields),64)
DECLARATIONS['r3o_certificate']=(tuple(
    ('published opened released',size,align)if keys=='published opened drained'else(keys,size,align)
    for keys,size,align in base.GROUPS['r3o_certificate'][0]),8)
DECLARATIONS['rrx_replace_control']=((
    ('started quiet invalidated raw_started raw_returned complete',8,8),
    ('number',8,8),('args',48,8),('effect_result result sync_result seals stat_result',8,8),
    ('backing','stat',8),('rx',('li2_r3_rx_progress',3),8),
    ('source',('li2_rsl_progress',3),8),('generation',('li2_rsl_generation_progress',3),8),
    ('lifetime',12,4),('references closed',36,4),('page',('li2_fetch_page',12),8),
    ('page_backing',('li2_fetch_backing',12),8),('release',('li2_fetch_progress',12),8),
    ('code_revoked',('li2_sealed_code_query',9),8),('code_result',12,4),
    ('bytes_before bytes_after','r3o_scan',8),('source_after',24576,1)),8)
DECLARATIONS['rrx_bundle']=(base.GROUPS['rgo_bundle'][0]+(
    ('control',128,8),('mailbox_before mailbox_after',80,8),
    ('mailbox_query','li2_private_code_query',8),('attack_greg',184,8),
    ('attack_si',128,1),('attack_uc',968,1),('metadata_before',16,1),
    ('final_code',('li2_sealed_code_query',9),8),('final_code_result',12,4),
    ('replacement','rrx_replace_control',8)),64)
ROOT_TYPES=('rrx_bundle','li2_r3_owner','li2_pg_plan','li2_tf_chain','li2_ptr_slot')
GROUPS={}
def include(name):
    if name in GROUPS:return
    GROUPS[name]=DECLARATIONS[name]
    for _,size,_ in DECLARATIONS[name][0]:
        child=size if type(size)is str else size[0]if type(size)is tuple else None
        if child:include(child)
for _root in ROOT_TYPES:include(_root)
del _fields,_at,_root
# The complete independent declaration, not a captured sizeof, determines bounds.
SIZES={}
def extent(name):
    if name in SIZES:return SIZES[name]
    at=0;members=[];declared,alignment=GROUPS[name]
    for keys,size,a in declared:
        child=size if type(size)is str else size[0]if type(size)is tuple else None
        n=extent(child)*(size[1]if type(size)is tuple else 1)if child else size
        for key in keys.split():
            if name in UNIONS:members.append(n)
            else:at=(at+a-1)&-a;at+=n
    if name in UNIONS:at=max(members)
    SIZES[name]=(at+alignment-1)&-alignment
    return SIZES[name]
for _root in GROUPS:extent(_root)
del _root
RAW_BYTES=SIZES['rrx_bundle']
RECORD_BYTES=SIZES['r3o_wire']
OWNER_BYTES=SIZES['li2_r3_owner']
need((RAW_BYTES,RECORD_BYTES,OWNER_BYTES,len(GROUPS))==(4173888,2065920,1247040,116),
     'whole independently declared RX layout')
need(RAW_BYTES+64<4<<20,'unchanged strict complete-record ceiling')

class Reader(base.base.Reader):
    def __init__(self,data,layout):
        self.data,self.layout,self.types=data,layout,dict(layout['types']);self.padding={}
        self.registered,self.lifetime=REGISTERED,LIFETIME
        need(set(layout)=={'record','types','edges','member_witnesses','symbols','registrations','retained_storage','uc_bytes','uc','si'}and layout['record']=='rrx_bundle','distinct sealed three-resident wire layout')
        need(layout['member_witnesses']=={'li2_step_frame.fp':dict(symbol='r3o_step_frame_fp_alignment',bytes=8,alignment=64)},'actual aligned FP witness')
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
        need(all(self.types[t]['bytes']==SIZES[t]for t in GROUPS),'whole independent type extents')
        need(type(data)is memoryview and data.readonly and data.c_contiguous and len(data)==self.types['rrx_bundle']['bytes']==RAW_BYTES,'whole literal sealed three-resident raw schema')
        self.walk(data,'rrx_bundle')
        self.types['uh_frame']=self.types['le_frame'];self.padding['uh_frame']=self.padding['le_frame']

class RecordView(Reader):
    """An immutable member view after the whole bundle's literal validation."""
    def __init__(self,whole,ordinal):
        need(type(whole)is Reader and type(ordinal)is int and ordinal in(0,1),
             'actual complete schema before selecting one record')
        self.data=whole.items(whole.data,'rrx_bundle','record','r3o_wire')[ordinal]
        self.layout,self.types,self.padding=whole.layout,whole.types,whole.padding
        self.registered,self.lifetime=whole.registered,whole.lifetime
        self.whole,self.ordinal=whole,ordinal
