"""Literal D3 capture schema; actual complete DWARF must match every field.

Inherit the unchanged direct-frontier walkers, not any old capture layout.
Sealed evidence is explicit in every query and grants no source authority.
"""
import importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
base=load('resident_three_wire_donor',Path(__file__).resolve().parents[1]/'persistent_direct_frontier_owner/wire.py')
need,zero,q=base.need,base.zero,base.q
REGISTERED={'selected_run_owner': ('selected_globals.inc', 'li2_run_owner'), 'selected_run_history': ('selected_globals.inc', 'li2_run_completion_history'), 'cache': ('register_run_publish.c', 'li2_run_cache'), 'selected_repeat_lease': ('selected_globals.inc', 'li2_repeat_lease_owner'), 'selected_session': ('selected_globals.inc', 'li2_step_session'), 'rep_custody': ('repeat_custody.inc', None), 'rep_custody_stats': ('repeat_custody.inc', 'li2_repeat_custody_observation'), 'selected_unrolled': ('selected_unrolled_hash.inc', None), 'selected_scalar_region': ('selected_scalar_region.inc', None), 'srr': ('selected_scalar_reuse.inc', None), 'selected_linked_epoch': ('linked_controller.inc', None), 'ler': ('linked_reuse.inc', None), 'lep': ('linked_controller.inc', None), 'linked_epoch': ('linked_source.inc', 'li2_link_epoch'), 'linked_registered': ('linked_source.inc', None), 'pe': ('persistent_group_controller.inc', 'li2_pg_epoch'), 'pg_source': ('persistent_group_source.inc', None), 'pg_rseq': ('persistent_group_rseq.inc', 'li2_pg_rseq_progress'), 'pg_rseq_previous': ('persistent_group_rseq.inc', 'li2_pg_rseq_progress'), 'r3o_wire': ('resident_three_observe.inc', 'r3o_wire'), 'r3_memory': ('resident_three_owner.inc', None), 'r3_work': ('resident_three_owner.inc', None), 'sg_owner': ('sealed_generation.inc', None), 'rsl': ('resident_source_lease.inc', None), 'rsl_initialization': ('runtime_loader.c', None)}
LIFETIME=base.LIFETIME+('rsl','rsl_initialization')
UNIONS=base.UNIONS

DECLARATIONS={'li2_sealed_identity': ((('fd device inode bytes generation code proof code_bytes proof_bytes', 8, 8),
                          ('code_live proof_live', 4, 4)),
                         8),
 'li2_sealed_evidence': ((('kind version', 4, 4),
                          ('identity', 'li2_sealed_identity', 8),
                          ('offset seals_result stat_result alias_vmas alias_pages', 8, 8),
                          ('alias_complete reserved', 4, 4)),
                         8),
 'li2_sealed_code_query': ((('first end first_vma last_vma_end pages_checked', 8, 8),
                            ('attempted complete expected_prot actual_prot result', 4, 4),
                            ('detail', 8, 8),
                            ('maps', 'li2_fetch_map_progress', 8),
                            ('sealed', 'li2_sealed_evidence', 8)),
                           8),
 'li2_private_code_query': ((('first end first_vma last_vma_end pages_checked', 8, 8),
                             ('attempted complete expected_prot actual_prot result', 4, 4),
                             ('detail', 8, 8),
                             ('maps', 'li2_fetch_map_progress', 8),
                             ('sealed', 'li2_sealed_evidence', 8)),
                            8),
 'li2_r3_token': ((('owner serial', 8, 8),), 8),
 'li2_r3_seed': ((('complete reserved', 4, 4),
                  ('serial', 8, 8),
                  ('held', 'li2_fetch_ref', 8),
                  ('session pid tid root', 8, 8)),
                 8),
 'li2_rsl_ref': ((('owner epoch', 8, 8),), 8),
 'li2_rsl_progress': ((('epoch bindings invalidations', 8, 8),
                       ('initialized valid pages reserved', 4, 4),
                       ('bound', 'li2_pg_token', 8)),
                      8),
 'li2_rsl_resident_progress': ((('bound', 'li2_r3_token', 8),
                                ('seed', 'li2_r3_seed', 8),
                                ('epoch last_serial bindings snapshots plans validations authentications '
                                 'fresh_maps_passes source_bytes plan_source_bytes guard_pages '
                                 'observation_seals',
                                 8,
                                 8)),
                               8),
 'li2_r3_rseq_progress': ((('token', 'li2_r3_token', 8),
                           ('session', 8, 8),
                           ('active checking registered seed_complete entry_complete close_complete', 4, 4),
                           ('epoch calls address page length signature fs gs raw_checks pid tid', 8, 8),
                           ('fs_selector gs_selector', 2, 2),
                           ('tls_complete word_observed', 4, 4),
                           ('word_before word_entry word_after', 8, 8),
                           ('before observed after', 'li2_rseq_data', 8),
                           ('cold', 12, 4)),
                          8),
 'li2_r3o_stack': ((('anchor origin_first origin_end first end origin_acquisition', 8, 8),
                    ('observation', 'li2_maps_observation', 8)),
                   8),
 'li2_r3o_memory': ((('attempted complete site copied result', 4, 4),
                     ('rsp', 8, 8),
                     ('origin', 'li2_r3o_stack', 8),
                     ('before after', 'li2_maps_stats', 8),
                     ('stack', 520, 1)),
                    8),
 'r3_header': ((('version bytes generation publication_serial index source_epoch root owner', 8, 8),
                ('layout', 'li2_pg_layout', 8),
                ('archive policy', 32, 1)),
               8),
 'r3_payload': ((('header', 'r3_header', 8),
                 ('source', 'li2_pg_source_key', 8),
                 ('plan', 'li2_pg_compact', 8)),
                8),
 'r3_certificate': ((('planned installed active_refs closed', 4, 4),
                     ('generation root proof', 8, 8),
                     ('layout', 'li2_pg_layout', 8),
                     ('identity', 'li2_sealed_identity', 8),
                     ('mirror', 'r3_payload', 8),
                     ('published opened drained', ('li2_sealed_code_query', 3), 8),
                     ('proof_query', ('li2_sealed_code_query', 2), 8)),
                    8),
 'li2_r3_owner': ((('initialized phase busy active first_error consumed released exit_seen', 4, 4),
                   ('first_detail serial publications entries completed cancelled unexpected ingresses arena '
                    'directory root',
                    8,
                    8),
                   ('count planned exit_member exit_index registry_count registry_bound', 4, 4),
                   ('registry', ('li2_fork_range', 128), 8),
                   ('token', 'li2_r3_token', 8),
                   ('session', 'li2_step_session', 8),
                   ('ticket', 8, 8),
                   ('transfer', 'li2_span_transfer_progress', 8),
                   ('held', 'li2_fetch_ref', 8),
                   ('fetch', 'li2_span_fetch_observation', 8),
                   ('source', 'li2_rsl_ref', 8),
                   ('source_pages', 4, 4),
                   ('flags gpr_written flags_written', 8, 8),
                   ('before after', 'le_frame', 64),
                   ('live', ('li2_link_rseq_live', 3), 8),
                   ('expected_directory', 'li2_jd_domain_directory', 8),
                   ('directory_query', 'li2_private_code_query', 8),
                   ('certificate', ('r3_certificate', 3), 8)),
                  64),
 'r3o_scan': ((('compared differences first_offset expected actual', 8, 8),), 8),
 'r3o_state': ((('phase busy active consumed released exit_seen first_error registry_bound', 4, 4),
                ('first_detail serial publications entries completed cancelled unexpected ingresses arena '
                 'directory root',
                 8,
                 8),
                ('count planned exit_member exit_index registry_count', 4, 4),
                ('token', 'li2_r3_token', 8),
                ('source', 'li2_rsl_ref', 8),
                ('source_pages', 4, 4),
                ('flags gpr_written flags_written', 8, 8),
                ('references closed installed', 12, 4),
                ('generation', 24, 8),
                ('fetch', 'li2_fetch_progress', 8),
                ('rseq', 'li2_r3_rseq_progress', 8),
                ('source_progress', 'li2_rsl_progress', 8),
                ('resident_progress', 'li2_rsl_resident_progress', 8),
                ('maps', 'li2_maps_stats', 8)),
               8),
 'r3o_certificate': ((('identity', 'li2_sealed_identity', 8),
                      ('payload', 'r3_payload', 8),
                      ('proof_tail', 2000, 1),
                      ('code', 69632, 1),
                      ('slots spill_entered spill_closed', 4096, 1),
                      ('published opened drained', ('li2_sealed_code_query', 3), 8),
                      ('proof', ('li2_sealed_code_query', 2), 8),
                      ('slot_query spill_query', ('li2_private_code_query', 2), 8),
                      ('proof_scan code_scan slot_scan', 'r3o_scan', 8)),
                     8),
 'r3o_wire': ((('h', 384, 8),
               ('ingress', 48, 8),
               ('bootstrap', 72, 8),
               ('sink_initial sink_terminal', 'stat', 8),
               ('main interpreter', 'image', 8),
               ('hardware', 'li2_selected_hardware', 4),
               ('session', 'li2_step_session', 8),
               ('transfer', 'li2_span_transfer_progress', 8),
               ('held', 'li2_span_fetch_observation', 8),
               ('entered terminal closed final', 'r3o_state', 8),
               ('before after next', 'le_frame', 64),
               ('memory', ('li2_r3o_memory', 3), 8),
               ('registry', ('li2_fork_range', 128), 8),
               ('source', ('li2_pg_source_page', 64), 8),
               ('certificate', ('r3o_certificate', 3), 8),
               ('directory', 12288, 1),
               ('directory_query', ('li2_private_code_query', 2), 8),
               ('directory_scan unexpected_scan', 'r3o_scan', 8),
               ('next_closed', 'li2_tf_chain_slot', 64)),
              64)}

_all=dict(base.GROUPS,**DECLARATIONS)
ROOT_TYPES=('r3o_wire', 'li2_r3_owner', 'li2_pg_plan', 'li2_tf_chain', 'li2_ptr_slot')
GROUPS={}
def include(name):
    if name in GROUPS:return
    GROUPS[name]=_all[name]
    for _,size,_ in _all[name][0]:
        child=size if type(size)is str else size[0]if type(size)is tuple else None
        if child:include(child)
for _root in ROOT_TYPES:include(_root)
del _all,_root

RAW_BYTES=2063040

class Reader(base.Reader):
    def __init__(self,data,layout):
        self.data,self.layout,self.types=data,layout,dict(layout['types']);self.padding={}
        self.registered,self.lifetime=REGISTERED,LIFETIME
        need(set(layout)=={'record','types','edges','member_witnesses','symbols','registrations','retained_storage','uc_bytes','uc','si'}and layout['record']=='r3o_wire','distinct sealed three-resident wire layout')
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
        need(type(data)is memoryview and data.readonly and data.c_contiguous and len(data)==self.types['r3o_wire']['bytes']==RAW_BYTES,'whole literal sealed three-resident raw schema')
        self.walk(data,'r3o_wire')
        self.types['uh_frame']=self.types['le_frame'];self.padding['uh_frame']=self.padding['le_frame']
