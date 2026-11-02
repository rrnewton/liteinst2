"""Strict schema16 DWARF schema; old schema14 remains a separate reader.

Every field, embedded type, union extent, padding byte and registration witness
is checked. This module supplies structure only; it cannot qualify an owner.
"""
import importlib.util
from pathlib import Path
_spec=importlib.util.spec_from_file_location('loop_prior_wire',
    Path(__file__).resolve().parents[1]/'persistent_fused_owner/wire.py')
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
need,zero,q=old.need,old.zero,old.q
GROUPS=dict(old.GROUPS)
GROUPS.update({'pdo_certificate': ((('complete index slot generation entry proof_bytes code_bytes publication_bytes', 8, 8), ('payload', 'pe_payload', 8), ('tail', 1880, 1), ('code', 69632, 1)), 8), 'pdo_counts': ((('next_serial next_generation offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected', 8, 8), ('misses', 144, 8), ('subentry_selections subentry_hits subentry_entries subentry_completed', 8, 8), ('pf_backward_refused pf_backward_cancelled', 8, 8), ('loop', 'plr_counts', 8)), 8), 'pdo_epoch': ((('h', 256, 8), ('prior_counts', 'pdo_counts', 8), ('prior_loop', 'plr_state', 8), ('prior', 'pdo_slots', 8), ('prior_domain', 'pdo_domain_checkpoint', 8), ('initial_registry terminal_registry', 'pdo_registry', 8), ('predecessor', 'pdo_predecessor', 8), ('ingress before returned after', 'le_frame', 64), ('entered terminal', 'pdo_stage', 8), ('info', 'pdo_epoch_info', 8), ('before_memory after_memory', 'li2_pdo_memory', 8), ('initial_slots terminal_slots', 8192, 1), ('initial_spill terminal_spill', 8192, 1), ('initial_directory terminal_directory', 12288, 1), ('terminal_domain', 'pda_state', 8)), 64), 'pdo_stage': ((('progress', 'li2_pg_progress', 8), ('entry', 'li2_pgs_entry', 8), ('counts', 'pdo_counts', 8), ('slots', 'pdo_slots', 8), ('transfer', 'li2_span_transfer_progress', 8), ('source', 'li2_pg_source_progress', 8), ('domain_source', 'li2_pgd_source_progress', 8), ('rseq', 'li2_pg_rseq_progress', 8), ('state', 'li2_rseq_state', 8), ('fetch', 'li2_fetch_progress', 8), ('busy active failing resuming route pending', 4, 4), ('domain', 'pdo_domain_checkpoint', 8), ('loop', 'plr_state', 8)), 8), 'pdo_wire': ((('h', 512, 8), ('raw_ingress', 48, 8), ('selection', 'plo_selection', 8), ('sink_initial sink_terminal', 'stat', 8), ('main interpreter', 'image', 8), ('hardware', 'li2_selected_hardware', 4), ('session', 'li2_step_session', 8), ('startup_registry', 'pdo_registry', 8), ('initial_domain', 'pda_state', 8), ('certificates', ('pdo_certificate', 2), 8), ('epochs', ('pdo_epoch', 1), 64), ('next', 'pdo_next', 64), ('final_counts', 'pdo_counts', 8), ('final_progress', 'li2_pg_progress', 8), ('final_loop', 'plr_state', 8), ('loop_row', 120, 8), ('final_row', 312, 8), ('final_subentry', 120, 8), ('cancellation', 'pbo_cancel', 64)), 64), 'pe_header': ((('version serial generation registry generated spill table', 8, 8), ('layout', 'li2_pg_layout', 8), ('member_generation', 16, 8), ('plan_proof none_proof source_validations registered_epoch rseq_address rseq_length rseq_signature', 8, 8), ('lifetime_version lifetime_mode', 8, 8), ('archive policy', 32, 1), ('reserved', 32, 8), ('plan_policy', 8, 8)), 8), 'li2_pg_miss': ((('version status reason site', 4, 4), ('pc detail', 8, 8)), 8), 'pbo_cancel': ((('h', 128, 8), ('before returned next', 'le_frame', 64), ('held resumed', 'pdo_stage', 8), ('initial_registry terminal_registry', 'pdo_registry', 8), ('closed_slot resumed_slot', 'li2_tf_chain_slot', 64), ('miss', 'li2_pg_miss', 8), ('plan', 'pbo_miss_plan', 8)), 64), 'pbo_miss_plan': ((('version bytes ready result heads exits stores source_bytes source_mask decoder_result guard_result reserved', 4, 4), ('member_heads', 8, 4), ('links reserved2', 4, 4), ('page', 16, 8), ('entry', 8, 8), ('layout', 'li2_pg_layout', 8), ('source', 8192, 1), ('table', 'li2_mg_table', 8), ('scan_started scan_complete scanned nonzero first_nonzero first_value', 8, 8)), 8), 'plr_counts': ((('chooser_attempts chooser_selected chooser_no_envelope publications12 hits12 entries_with12 completed_with12 historical_reconstructions actual_entries12', 8, 8),), 8), 'plr_state': ((('scope route choice_complete', 4, 4), ('counts', 'plr_counts', 8), ('choice check historical', 'li2_le_witness', 8), ('pages', 16, 8), ('source', 8192, 1), ('direct', 'li2_dd_plan', 8)), 8), 'li2_le_decoded': ((('scalar', 'li2_span_decoded', 8), ('mov', 'li2_mg_store', 8), ('kind stop', 4, 4)), 8), 'li2_le_head': ((('pc', 8, 8), ('decoded kind flow successors', 4, 4), ('token', 8, 4), ('external_mask reserved', 4, 4)), 8), 'li2_le_arm': ((('target', 8, 8), ('head arm', 4, 4)), 8), 'li2_le_link': ((('head arm target reserved', 4, 4),), 4), 'li2_le_candidate': ((('first end latch', 8, 8), ('result heads exits links backwards stores source_bytes reserved', 4, 4)), 8), 'li2_le_shape': ((('choice', 'li2_le_candidate', 8), ('head', ('li2_le_head', 128), 8), ('exit', ('li2_le_arm', 8), 8), ('link', ('li2_le_link', 8), 4)), 8), 'li2_le_witness': ((('version bytes ready result', 4, 4), ('page', 16, 8), ('entry stop_pc', 8, 8), ('stop decoded candidates eligible', 4, 4), ('source', 8192, 1), ('node', ('li2_le_decoded', 128), 8), ('candidate', ('li2_le_candidate', 128), 8), ('selected', 'li2_le_shape', 8)), 8), 'plo_selection': ((('version protocol case_id placement lane source_page base predecessor entry', 8, 8), ('cut', 16, 8), ('high source_bytes template_bytes source_checked source_compared predecessor_checked expected_policy expected_epochs', 8, 8)), 8)})
GROUPS.update({
 'ple_counts': ((('chooser_attempts chooser_selected chooser_no_envelope publications13 hits13 entries_with13 completed_with13 historical_reconstructions actual_entries13',8,8),),8),
 'ple_state': ((('choice_complete',4,4),('counts','ple_counts',8),('choice check historical','li2_le_witness',8)),8),
 'ple_observation': ((('version bytes copied_mask reserved',8,8),('prior entered terminal final held resumed','ple_state',8),('terminal_row',144,8)),8)})
_old_wire,_wire_alignment=GROUPS['pdo_wire']
GROUPS['pdo_wire']=(_old_wire+(('effects','ple_observation',8),),_wire_alignment)
REGISTERED=dict(old.REGISTERED)
for _name in ('pdo_wire','pdo_encoded'):
    _origin,_type=REGISTERED[_name];REGISTERED[_name]=('persistent_loop_effects_observe.inc',_type)
LIFETIME=old.LIFETIME
UNIONS=old.UNIONS

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
            'actual separate effects owner extent and all nine counter offsets')
        need(self.types['ple_state']['bytes']==250040 and self.types['ple_observation']['bytes']==1500416,
            'complete new effects state and append-only sidecar extents')
        need(self.types['pdo_wire']['fields']['effects']['offset']==4864896,
            'every old wire field remains at its original offset')
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
        need(type(data)is memoryview and data.readonly and data.c_contiguous and len(data)==self.types['pdo_wire']['bytes']==6365312,'whole losslessly decoded cross-pair raw schema')
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
