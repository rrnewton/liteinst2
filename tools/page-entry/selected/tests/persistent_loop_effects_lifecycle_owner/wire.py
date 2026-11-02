"""Distinct schema17 lifecycle structure, validated against actual ELF/DWARF.

All shared frame/owner types are literal policy14 declarations. The separate
wire has three immutable certificates/five offers/five next-event cells. Its
complete extent is derived from declared C fields, then joined to actual DWARF;
no policy14 offset or captured length supplies structure authority.
"""
import importlib.util
from pathlib import Path
_s=importlib.util.spec_from_file_location('lifecycle_focal_wire',
    Path(__file__).resolve().parents[1]/'persistent_loop_owner/wire.py')
focal=importlib.util.module_from_spec(_s);_s.loader.exec_module(focal)
old=focal.old
need,zero,q=old.need,old.zero,old.q
GROUPS=dict(focal.GROUPS)
del GROUPS['plo_selection']
GROUPS['plc_selection']=((('version protocol case_id placement lane',8,8),
    ('source_page',16,8),('root',24,8),('entry predecessor cancel stub high expected_offers expected_completed',8,8),
    ('source_checked source_compared',24,8),('predecessor_checked',40,8)),8)
GROUPS['pdo_wire']=((('h',512,8),('raw_ingress',48,8),('selection','plc_selection',8),
    ('sink_initial sink_terminal','stat',8),('main interpreter','image',8),
    ('hardware','li2_selected_hardware',4),('session','li2_step_session',8),('startup_registry','pdo_registry',8),
    ('initial_domain','pda_state',8),('certificates',('pdo_certificate',3),8),
    ('epochs',('pdo_epoch',5),64),('next',('pdo_next',5),64),('next_target',40,8),
    ('final_counts','pdo_counts',8),('final_progress','li2_pg_progress',8),('final_loop','plr_state',8),
    ('loop_row',120,8),('final_row',312,8),('final_subentry',120,8),('cancellation','pbo_cancel',64)),64)
GROUPS.update({
 'ple_counts': ((('chooser_attempts chooser_selected chooser_no_envelope publications13 hits13 entries_with13 completed_with13 historical_reconstructions actual_entries13',8,8),),8),
 'ple_state': ((('choice_complete',4,4),('counts','ple_counts',8),('choice check historical','li2_le_witness',8)),8),
 'ple_lifecycle_snapshot': ((('prefix',80,1),('reference',12,4),('reserved',4,4),('scan',('pdo_scan',3),8)),8),
 'ple_lifecycle_observation': ((('version bytes copied_mask pool_count',8,8),('snapshot',('ple_lifecycle_snapshot',18),8),('witness',('li2_le_witness',36),8),('terminal_row',144,8)),8)})
_old_wire,_wire_alignment=GROUPS['pdo_wire']
GROUPS['pdo_wire']=(_old_wire+(('effects','ple_lifecycle_observation',8),),_wire_alignment)
REGISTERED=dict(focal.REGISTERED)
for _name in('pdo_wire','pdo_encoded'):
    _origin,_type=REGISTERED[_name];REGISTERED[_name]=('persistent_loop_effects_lifecycle_observe.inc',_type)
LIFETIME,UNIONS=focal.LIFETIME,focal.UNIONS
class Reader(old.Reader):
    def __init__(self,data,layout):
        self.data,self.layout,self.types=data,layout,dict(layout['types']);self.padding={}
        self.registered,self.lifetime=REGISTERED,LIFETIME
        need(set(layout)=={'record','types','edges','member_witnesses','symbols','registrations','retained_storage','pf_refusals','loop_storage','effects_storage','uc_bytes','uc','si'}and layout['record']=='pdo_wire','distinct retained-two wire layout')
        pf=layout['pf_refusals'];fields=pf['fields'];last=pf['previous_last']
        need(set(pf)=={'version','reason','fields','previous_last'} and pf['version']==1 and pf['reason']==256 and
             set(fields)=={'pf_backward_refused','pf_backward_cancelled'} and set(last)=={'offset','bytes'} and
             all(type(v)is int and v>0 for v in last.values())and last==layout['retained_storage']['domain']and
             last['bytes']==self.types['pda_state']['bytes']==225880,'actual PF-only appended owner field witnesses')
        first=(last['offset']+last['bytes']+7)&-8
        for index,key in enumerate(('pf_backward_refused','pf_backward_cancelled')):
            need(fields[key]==dict(offset=first+8*index,bytes=8),'literal appended protected PF counter '+key)
        owner=layout['registrations']['pe'];alignment=owner['alignment']
        need(type(alignment)is int and alignment>=8 and alignment&(alignment-1)==0 and
             owner['bytes']==(first+16+alignment-1)&-alignment,'whole actual protected owner extent with appended PF counters')
        # Independent C-layout arithmetic, joined to actual compiler DWARF.
        # The new scratch is an explicit registered/excluded member, not padding.
        need(owner['bytes']==4498752 and owner['alignment']==64,
             'complete policy12 owner extent and alignment')
        prefix=2*self.types['li2_pg_progress']['bytes']+self.types['li2_pgs_entry']['bytes']+40
        prefix=(prefix+9*8+18*8+3*4+7)&~7
        size=self.types['li2_ptr_slot']['bytes'];selected=prefix+2*size
        selection=(selected+4+7)&~7
        need((prefix,size,selected,selection)==(1128,398136,797400,797408),
             'independent full owner-prefix and retained-slot layout arithmetic')
        need(layout['retained_storage']==dict(retained=dict(offset=prefix,bytes=2*size),
             selected_slot=dict(offset=selected,bytes=4),selection=dict(offset=selection,bytes=24),
             previous_selection=dict(offset=selection+24,bytes=24),domain=dict(offset=4272808,bytes=225880)),
             'literal complete retained identity and domain DWARF offsets')
        names=('chooser_attempts','chooser_selected','chooser_no_envelope','publications12',
               'hits12','entries_with12','completed_with12','historical_reconstructions','actual_entries12')
        need(layout['loop_storage']==dict(offset=3755736,bytes=260544,
             counts={name:dict(offset=8*i,bytes=8)for i,name in enumerate(names)}),
             'actual separate protected scratch and all nine literal counters')
        effects_names=('chooser_attempts','chooser_selected','chooser_no_envelope','publications13',
            'hits13','entries_with13','completed_with13','historical_reconstructions','actual_entries13')
        need(layout['effects_storage']==dict(offset=4016280,bytes=250040,
            counts={name:dict(offset=8*i,bytes=8)for i,name in enumerate(effects_names)}),
            'actual separate effects owner and all nine literal counter offsets')
        need(self.types['ple_state']['bytes']==250040 and
             self.types['li2_le_witness']['bytes']==83320 and
             self.types['pdo_scan']['bytes']==64 and
             self.types['ple_lifecycle_snapshot']['bytes']==288 and
             self.types['ple_lifecycle_observation']['bytes']==3004880 and
             self.types['pdo_wire']['bytes']==16744832 and
             self.types['pdo_wire']['fields']['effects']['offset']==13739904,
             'whole schema17 interning arithmetic and unchanged full old prefix/raw limit')
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
        need(type(data)is memoryview and data.readonly and data.c_contiguous and len(data)==self.types['pdo_wire']['bytes'] and len(data)<16*1024*1024,'whole independently declared schema17 extent and actual lossless body')
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
