"""Exact RET owner schema; parsing supplies no execution or resume authority.

Reuse the unchanged CALL and direct-frontier field, padding and union walkers.
The committed ucontext is a literal owner transformation, never a kernel frame.
Private mmap addresses come from captured provenance, never ELF-time symbols.
"""
import importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
base=load('ret_owner_donor_wire',Path(__file__).resolve().parents[1]/'persistent_call_owner_owner/wire.py')
need,zero,q=base.need,base.zero,base.q
REGISTERED={k:v for k,v in base.REGISTERED.items() if k!='pclo_wire'}
REGISTERED.update(prto_wire=('persistent_ret_owner_observe.inc','prto_wire'),prr=('persistent_ret_resume.h',None))
LIFETIME=base.LIFETIME
UNIONS=base.UNIONS

DECLARATIONS={
 'li2_rd_window': ((('version owner serial first end',8,8),('reserved',24,8)),8),
 'li2_rd_descriptor': ((('decoded','li2_decoded',8),('tf','li2_tf_classification',8),
                       ('version ready refusal available',4,4),('reserved',16,4)),8),
 'li2_rd_record': ((('version ready result image_bytes boundaries load_offset save_offset commit_offset '
                    'transfer_offset miss_offset loaded_miss_offset reserved',4,4),
                   ('scratch_regs',16,4),('boundary',('li2_mg_boundary',64),4)),4),
 'li2_rd_binding': ((('rows',8,8),('image',16,8),('heads head',4,4),
                    ('directory window loaded_miss',8,8)),8),
 'li2_rd_plan': ((('record','li2_rd_record',4),('original','li2_rd_descriptor',8),
                 ('generated spill',8,8),('binding','li2_rd_binding',8),('image',512,1)),8),
 'li2_rd_recovered': ((('gpr',128,8),('flags original_pc original_rsp target',8,8),
                      ('phase complete target_valid reserved',4,4)),8),
 'li2_pg_ret_record': ((('image_bytes boundaries load_offset save_offset commit_offset '
                        'transfer_offset miss_offset loaded_miss_offset',4,4),
                       ('scratch_regs',16,4),('boundary',('li2_mg_boundary',64),4)),4),
 'li2_pg_layout': ((('generated',16,8),('stubs slots spill directory window ret_miss',8,8)),8),
 'li2_pg_guard': ((('mov','li2_mg_plan',8),('dispatch','li2_jd_plan',8),
                  ('call','li2_cd_plan',8),('ret','li2_rd_plan',8),
                  ('direct','li2_dd_plan',8),('bytes',6488,1)),8),
 'li2_pg_guard_record': ((('mov','li2_pe_guard_record',4),('dispatch','li2_jd_record',4),
                         ('call','li2_pg_call_record',4),('ret','li2_pg_ret_record',4),
                         ('direct','li2_dd_record',4)),4),
 'li2_pg_instruction': ((('mov','li2_mg_store',8),('dispatch','li2_jd_descriptor',8),
                        ('call','li2_cd_descriptor',8),('ret','li2_rd_descriptor',8),
                        ('direct','li2_dd_descriptor',8)),8),
 'pda_ret_exit': ((('complete member heads head',4,4),('landing',8,8),
                  ('row','li2_pe_head',4),('original','li2_span_decoded',8),
                  ('plan','li2_rd_plan',8),('recovered','li2_rd_recovered',8),
                  ('window','li2_rd_window',8),('stack','li2_maps_call_stack',8)),8),
 'pda_completion': ((('id serial',8,8),('count complete',4,4),
                    ('member',('pda_member_completion',2),8),
                    ('source','li2_pg_source_progress',8),('domain_source','li2_pgd_source_progress',8),
                    ('rseq','li2_pg_rseq_progress',8),('fetch','li2_fetch_progress',8),
                    ('directory_closed','li2_private_code_query',8),
                    ('ret_exit','pda_ret_exit',8),('direct_exit','pda_direct_exit',8)),8),
 'prr_attempt': ((('phase event terminal consumed',4,4),('serial completion_id',8,8),
                 ('loaded','pda_ret_exit',8),('interior logical','li2_rd_recovered',8),
                 ('interior_result',4,4),('after','le_frame',64),
                 ('before observed',('li2_private_code_query',2),8),
                 ('write seal','le_permission',8),('stack','li2_maps_call_stack',8)),64),
 'li2_prto_map_row': ((('first end offset major minor inode',8,8),('prot private',4,4)),8),
 'li2_prto_memory': ((('attempted complete rows_checked pages_checked site reserved source_copied '
                      'continuation_copied data_copied stack_copied result',4,4),
                     ('detail rsp',8,8),('stack_origin','li2_maps_call_stack',8),
                     ('maps','li2_fetch_map_progress',8),('before after','li2_maps_stats',8),
                     ('rows',('li2_prto_map_row',6),8),('pages',('li2_fetch_page',3),8),
                     ('backing',('li2_fetch_backing',3),8),('source',8192,1),
                     ('continuation',4096,1),('data',8192,1),('stack',520,1)),8),
 'prto_counts': ((('offers publications hits cold_attempts cancelled retirements permit_claims entries '
                   'completed unexpected',8,8),),8),
 'prto_scan': ((('compared differences first_offset expected actual',8,8),),8),
 'prto_phase': ((('complete ordinal phase pending busy pe_active pe_busy resuming handling '
                  'route step_pending serial completion_id last_consumed cell_value cell_serial',8,8),),8),
 'prto_private': ((('owner allocation code cell',8,8),('initialized registered',4,4),
                   ('prior_consumed prior_cell_value prior_cell_serial',8,8),
                   ('initial_code initial_cell','le_permission',8),
                   ('initial','li2_private_code_query',8),
                   ('code_page initial_operand_page operand_page',4096,1)),8),
 'prto_poison': ((('complete applied original_rsp word_address target before after changed_bytes',8,8),),8),
 'prto_wire': ((('h',768,8),('raw_ingress',48,8),('sink_initial sink_terminal','stat',8),
                ('main interpreter','image',8),('hardware','li2_selected_hardware',4),
                ('session','li2_step_session',8),
                ('prior_counts entered_counts terminal_counts final_counts','prto_counts',8),
                ('predecessor','li2_span_transfer_progress',8),
                ('before terminal next following loaded_ingress','le_frame',64),
                ('memory',('li2_prto_memory',5),8),('phase',('prto_phase',5),8),
                ('loaded','pda_ret_exit',8),('resume','prr_attempt',64),
                ('private_state','prto_private',8),('poison','prto_poison',8),
                ('committed',968,8),('payload','pe_payload',8),('proof_tail',1856,1),
                ('code',69632,1),('entered_generation','li2_pg_generation',8),
                ('entered_progress terminal_progress','li2_pg_progress',8),
                ('entered_source','li2_pg_source_progress',8),('entered_rseq','li2_pg_rseq_progress',8),
                ('entered_work terminal_work','pda_work',8),('completion','pda_completion',8),
                ('claim','li2_pgd_claim',8),('window_seed','pcw_seed',8),
                ('prepared_stack bound_stack','li2_maps_call_stack',8),
                ('expected_window','li2_cd_window',8),('window_write window_seal','le_permission',8),
                ('window',4096,1),('initial_directory terminal_directory',12288,1),
                ('proof_scan code_scan window_scan unexpected_scan private_scan','prto_scan',8),
                ('next_closed',135104,1),('recovered','li2_pg_recovered',8),
                ('final_row',312,8),('final_subentry',120,8),('final_misses',144,8)),64)
}

_all=dict(base.GROUPS,**DECLARATIONS)
ROOT_TYPES=('prto_wire','li2_pg_plan','li2_tf_chain','li2_ptr_slot')
GROUPS={}
def include(name):
    if name in GROUPS:return
    GROUPS[name]=_all[name]
    for _,size,_ in _all[name][0]:
        child=size if type(size)is str else size[0]if type(size)is tuple else None
        if child:include(child)
for _root in ROOT_TYPES:include(_root)
del _all,_root

RAW_BYTES=1261760
CLOSED_BYTES=135104

class Reader(base.Reader):
    def __init__(self,data,layout):
        self.data,self.layout,self.types=data,layout,dict(layout['types']);self.padding={}
        self.registered,self.lifetime=REGISTERED,LIFETIME
        need(set(layout)=={'record','types','edges','member_witnesses','symbols','registrations','retained_storage','uc_bytes','uc','si'}and layout['record']=='prto_wire','distinct RET owner wire layout')
        need(layout['member_witnesses']=={'li2_step_frame.fp':dict(symbol='prto_step_frame_fp_alignment',bytes=8,alignment=64)},'actual aligned FP witness')
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
        need(type(data)is memoryview and data.readonly and data.c_contiguous and len(data)==self.types['prto_wire']['bytes']==RAW_BYTES,'whole literal RET owner raw schema')
        self.walk(data,'prto_wire')
        self.types['uh_frame']=self.types['le_frame'];self.padding['uh_frame']=self.padding['le_frame']
