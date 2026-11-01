"""Distinct two-completion generation wire; every field requires actual DWARF.
Old capture/schema remains unchanged. No normalized or invented record bytes.
"""
import importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
base=load('resident_generation_wire_donor',Path(__file__).resolve().parents[1]/'resident_three_owner/wire.py')
need,zero,q=base.need,base.zero,base.q
REGISTERED={'selected_run_owner': ('selected_globals.inc', 'li2_run_owner'), 'selected_run_history': ('selected_globals.inc', 'li2_run_completion_history'), 'cache': ('register_run_publish.c', 'li2_run_cache'), 'selected_repeat_lease': ('selected_globals.inc', 'li2_repeat_lease_owner'), 'selected_session': ('selected_globals.inc', 'li2_step_session'), 'rep_custody': ('repeat_custody.inc', None), 'rep_custody_stats': ('repeat_custody.inc', 'li2_repeat_custody_observation'), 'selected_unrolled': ('selected_unrolled_hash.inc', None), 'selected_scalar_region': ('selected_scalar_region.inc', None), 'srr': ('selected_scalar_reuse.inc', None), 'selected_linked_epoch': ('linked_controller.inc', None), 'ler': ('linked_reuse.inc', None), 'lep': ('linked_controller.inc', None), 'linked_epoch': ('linked_source.inc', 'li2_link_epoch'), 'linked_registered': ('linked_source.inc', None), 'pe': ('persistent_group_controller.inc', 'li2_pg_epoch'), 'pg_source': ('persistent_group_source.inc', None), 'pg_rseq': ('persistent_group_rseq.inc', 'li2_pg_rseq_progress'), 'pg_rseq_previous': ('persistent_group_rseq.inc', 'li2_pg_rseq_progress'), 'r3_memory': ('resident_three_owner.inc', None), 'r3_work': ('resident_three_owner.inc', None), 'sg_owner': ('sealed_generation.inc', None), 'rsl': ('resident_source_lease.inc', None), 'rsl_initialization': ('runtime_loader.c', None), 'selected_flag_stack_failing': ('runtime_loader.c', None), 'rgo_bundle': ('resident_generation_observe.inc', 'rgo_bundle')}
LIFETIME=base.LIFETIME
UNIONS=base.UNIONS

DECLARATIONS={'li2_rsl_content_ref': ((('owner generation publication_epoch', 8, 8),), 8),
 'li2_rsl_generation_progress': ((('generation publication_epoch effects preserved invalidations '
                                   'source_mutations pending_epoch number',
                                   8,
                                   8),
                                  ('args', 48, 8),
                                  ('result', 8, 8),
                                  ('state pending', 4, 4)),
                                 8),
 'r3_header': ((('version bytes generation publication_serial index source_epoch root owner', 8, 8),
                ('content', 'li2_rsl_content_ref', 8),
                ('layout', 'li2_pg_layout', 8),
                ('archive policy', 32, 1)),
               8),
 'li2_r3_owner': ((('initialized phase busy active first_error consumed released exit_seen', 4, 4),
                   ('first_detail serial publications entries completed cancelled unexpected ingresses '
                    'arena directory root',
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
                   ('content', 'li2_rsl_content_ref', 8),
                   ('source_pages', 4, 4),
                   ('flags gpr_written flags_written', 8, 8),
                   ('before after', 'le_frame', 64),
                   ('live', ('li2_link_rseq_live', 3), 8),
                   ('expected_directory', 'li2_jd_domain_directory', 8),
                   ('directory_query', 'li2_private_code_query', 8),
                   ('certificate', ('r3_certificate', 3), 8)),
                  64),
 'r3o_state': ((('phase busy active consumed released exit_seen first_error registry_bound', 4, 4),
                ('first_detail serial publications entries completed cancelled unexpected ingresses '
                 'arena directory root',
                 8,
                 8),
                ('count planned exit_member exit_index registry_count', 4, 4),
                ('token', 'li2_r3_token', 8),
                ('source', 'li2_rsl_ref', 8),
                ('content', 'li2_rsl_content_ref', 8),
                ('generation_progress', 'li2_rsl_generation_progress', 8),
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
 'r3o_wire': ((('h', 384, 8),
               ('ingress', 48, 8),
               ('bootstrap', 72, 8),
               ('resident_before', 'li2_rsl_resident_progress', 8),
               ('generation_before', 'li2_rsl_generation_progress', 8),
               ('sink_initial sink_terminal', 'stat', 8),
               ('main interpreter', 'image', 8),
               ('hardware', 'li2_selected_hardware', 4),
               ('session', 'li2_step_session', 8),
               ('transfer', 'li2_span_transfer_progress', 8),
               ('held', 'li2_span_fetch_observation', 8),
               ('entered terminal closed handoff', 'r3o_state', 8),
               ('before after next', 'le_frame', 64),
               ('memory', ('li2_r3o_memory', 3), 8),
               ('registry', ('li2_fork_range', 128), 8),
               ('source', ('li2_pg_source_page', 64), 8),
               ('certificate', ('r3o_certificate', 3), 8),
               ('directory', 12288, 1),
               ('directory_query', ('li2_private_code_query', 2), 8),
               ('directory_scan unexpected_scan', 'r3o_scan', 8),
               ('next_closed', 'li2_tf_chain_slot', 64)),
              64),
 'r3o_certificate': ((('identity', 'li2_sealed_identity', 8),
                      ('payload', 'r3_payload', 8),
                      ('proof_tail', 1976, 1),
                      ('code', 69632, 1),
                      ('slots spill_entered spill_closed', 4096, 1),
                      ('published opened drained', ('li2_sealed_code_query', 3), 8),
                      ('proof', ('li2_sealed_code_query', 2), 8),
                      ('slot_query spill_query', ('li2_private_code_query', 2), 8),
                      ('proof_scan code_scan slot_scan', 'r3o_scan', 8)),
                     8),
 'rgo_bundle': ((('h', 128, 8),
                 ('ingress', 48, 8),
                 ('final', 'r3o_state', 8),
                 ('record', ('r3o_wire', 2), 64)),
                64)}
_all=dict(base.GROUPS,**DECLARATIONS)
ROOT_TYPES=('rgo_bundle','li2_r3_owner','li2_pg_plan','li2_tf_chain','li2_ptr_slot')
GROUPS={}
def include(name):
    if name in GROUPS:return
    GROUPS[name]=_all[name]
    for _,size,_ in _all[name][0]:
        child=size if type(size)is str else size[0]if type(size)is tuple else None
        if child:include(child)
for _root in ROOT_TYPES:include(_root)
del _all,_root

RAW_BYTES=4129856
RECORD_BYTES=2064000
OWNER_BYTES=1246784

class Reader(base.Reader):
    def __init__(self,data,layout):
        self.data,self.layout,self.types=data,layout,dict(layout['types']);self.padding={}
        self.registered,self.lifetime=REGISTERED,LIFETIME
        need(set(layout)=={'record','types','edges','member_witnesses','symbols','registrations','retained_storage','uc_bytes','uc','si'}and layout['record']=='rgo_bundle','distinct sealed three-resident wire layout')
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
        need(type(data)is memoryview and data.readonly and data.c_contiguous and len(data)==self.types['rgo_bundle']['bytes']==RAW_BYTES,'whole literal sealed three-resident raw schema')
        self.walk(data,'rgo_bundle')
        self.types['uh_frame']=self.types['le_frame'];self.padding['uh_frame']=self.padding['le_frame']

class RecordView(Reader):
    """An immutable member view after the whole bundle's literal validation."""
    def __init__(self,whole,ordinal):
        need(type(whole)is Reader and type(ordinal)is int and ordinal in(0,1),
             'actual complete schema before selecting one record')
        self.data=whole.items(whole.data,'rgo_bundle','record','r3o_wire')[ordinal]
        self.layout,self.types,self.padding=whole.layout,whole.types,whole.padding
        self.registered,self.lifetime=whole.registered,whole.lifetime
        self.whole,self.ordinal=whole,ordinal
