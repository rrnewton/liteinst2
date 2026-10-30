"""Actual scalar capture layout; common closure predicates remain in the old reader."""
import importlib.util
from pathlib import Path
import struct


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

old=load('scalar_owner_original_helpers',Path(__file__).resolve().parents[1]/'unrolled_hash_owner'/'read.py')
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
ALIASES={'uho_wire':'sro_wire','unrolled_owner':'scalar_owner','uho_entry':'sro_entry',
    'uh_frame':'sr_frame','uh_permission':'sr_permission','uho_owners':'sro_owners'}


def shapes(r):
    def form(name, groups, align=8):
        fields={}
        for keys,size,a in groups:
            for key in keys.split():fields[key]=(size,a)
        r.shape(name,fields,align)
    s=lambda t:r.types[t]['bytes']
    form('li2_step_frame',[('greg',184,8),('mask fp_address fp_bytes initialized',8,8),('fp',65536,64)],64)
    old.old_shapes(r)
    form('li2_maps_stats',[('fresh_calls acquisitions reuses invalidations handler_id mutation_epoch',8,8),('active valid poisoned reserved',4,4)])
    form('li2_fetch_ref',[('owner sequence',8,8)])
    form('li2_fetch_progress',[('held complete first_error identity_observed',4,4),
        ('first_detail pages_copied bytes_copied sequence validation_calls last_backing_page',8,8),
        ('last_backing_observed',4,4),('preparation validation',s('li2_fetch_map_progress'),8)])
    form('li2_decoded',[('pc next_pc',8,8),('abi_version decode_status code kind destination width_bits step_disposition available length reserved',4,4),('bytes',16,1)])
    form('li2_private_code_query',[('first end first_vma last_vma_end pages_checked',8,8),
        ('attempted complete expected_prot actual_prot result',4,4),('detail',8,8),('maps',s('li2_fetch_map_progress'),8)])
    form('li2_step_session',[('pid tid sync_register sync_query application_mask',8,8),('initialized self_test_complete',4,4)])
    form('li2_selected_hardware',[('abi_version reserved',4,4),('leaf0 leaf1 leaf7',16,4)],4)
    form('li2_native_counts',[('attempts admissions closed blocked low_address_refusals',8,8),('last_block',4,4),
        ('first_admission_ns first_source_offset revisit_count',8,8),('revisit_ns',128,8)])
    form('image',[('bias entry ph n source source_size',8,8),('backing_fd kind',4,4),('source_hash',32,1)])
    form('li2_rseq_native_state',[('phase checking first_error unsafe_terminal entry_checked',4,4),
        ('first_detail pid tid attempts admissions preentries entries closed tls_refreshes pc address page registration_epoch native_admissions_before native_closed_before',8,8),
        ('length signature',4,4),('word_before word_entry word_after fs_before gs_before fs_after gs_after',8,8),
        ('fs_selector_entry gs_selector_entry fs_selector_after gs_selector_after',2,2),('before after',s('li2_rseq_data'),8)])
    form('li2_region_operand',[('immediate',8,8),('kind reg width_bits access encoding_bits reserved',4,4)])
    form('li2_region_register',[('reg width_bits access reserved',4,4)],4)
    form('li2_region_memory',[('displacement',8,8),('base index scale width_bytes address_bits segment access reserved',4,4)])
    form('li2_region_decoded',[('decoded',s('li2_decoded'),8),('target',8,8),('operands',2*s('li2_region_operand'),8),
        ('registers',3*s('li2_region_register'),4),('memory',s('li2_region_memory'),8),
        ('version ready refusal flow condition operand_count register_count memory_count flags_read flags_written flags_set flags_cleared flags_undefined gpr_read gpr_write',4,4),('reserved',12,4)])
    form('li2_region_head',[('source_offset source_length generated_offset generated_length successor_count',4,4),('successors',8,4),('block',4,4)],4)
    form('li2_region_pc',[('version ready head_index kind source_offset source_length generated_offset generated_length',4,4),('original_pc generated_pc',8,8)])
    form('li2_region_plan',[('version ready heads blocks exits maps longest_path stop_reason source_bytes image_bytes decoder_calls decoder_result',4,4),
        ('page entry generated boundary_pc',8,8),('source image',4096,1),('original',64*s('li2_region_decoded'),8),
        ('boundary',s('li2_region_decoded'),8),('emitted',65*s('li2_region_decoded'),8),('head',64*s('li2_region_head'),4),('exit_pc',64,8),('map',65*s('li2_region_pc'),8)])
    form('li2_region_source_key',[('entry',8,8),('page',s('li2_fetch_page'),8),('backing',s('li2_fetch_backing'),8),('bytes',4096,1)])
    form('li2_region_source',[('ready',4,4),('borrow',s('li2_fetch_ref'),8),('key',s('li2_region_source_key'),8)])
    form('sr_frame',[('started si_saved uc_saved complete sig',4,4),('si',r.layout['si']['bytes'],8),('uc',r.layout['uc_bytes'],8),
        ('frame',s('li2_step_frame'),64),('fs gs fs_result gs_result',8,8),('tls_complete',4,4)],64)
    form('sr_permission',[('started returned sync_started sync_returned complete prot',4,4),('result sync_result',8,8),('query',s('li2_private_code_query'),8)])
    form('sr_slot',[('installed complete',4,4),('identity filled verified',8,8),('key',s('li2_region_source_key'),8),('plan',s('li2_region_plan'),8),
        ('writable',s('li2_private_code_query'),8),('publication',s('sr_permission'),8)])
    form('sr_record',[('slot_present slot redirected exit_seen completed release_started release_complete cleanup_started cleanup_complete unexpected_seen build_started build_returned release_result map_result build_result',4,4),
        ('flags gpr_written flags_written',8,8),('exit_index',4,4),('source',s('li2_region_source'),8),('before after unexpected',s('sr_frame'),64),('original',s('li2_region_pc'),8),
        ('idle live',s('li2_private_code_query'),8),('idle_bytes live_bytes closed_bytes',8,8),('open close cleanup',s('sr_permission'),8),('final_fetch',s('li2_fetch_progress'),8)],64)
    form('scalar_owner',[('initialized first_error metadata_registered arena_registered allocated low_arena_registered low_allocated',4,4),
        ('first_detail allocation_result low_allocation_result arena low_arena used candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected events',8,8),
        ('signals',40,8),('refusals',32,8),('exit_counts',64,8),('plan_checks rseq_checks',8,8),('session',s('li2_step_session'),8),('initial low_initial',s('li2_private_code_query'),8),
        ('scratch',s('li2_region_plan'),8),('slots',64*s('sr_slot'),8),('current last',s('sr_record'),64)],64)
    form('li2_sro_map_row',[('first end offset major minor inode',8,8),('prot private',4,4)])
    form('li2_sro_maps',[('maps',s('li2_fetch_map_progress'),8),('before after',s('li2_maps_stats'),8),('rows',8*s('li2_sro_map_row'),8),
        ('source generated',s('li2_sro_map_row'),8),('rows_checked source_checked generated_checked',4,4)])
    form('li2_sro_memory',[('attempted complete stage stack_kind data_copied stack_copied stack_missing stack_full restore_started restore_returned restore_verified result',4,4),
        ('detail restore_result rsp data_first stack_first generated',8,8),('initial restored',s('li2_sro_maps'),8),('data',8192,1),('stack stack_observed',224,1)])
    form('sro_owners',[('captured word_observed',4,4),('word',8,8),('rseq',s('li2_rseq_state'),8),('rseq_native',s('li2_rseq_native_state'),8),
        ('pair',s(old.P),64),('lifecycle',s(old.L),8),('rseq_pair',s(old.R),8)],64)
    form('sro_entry',[('present ordinal committed terminal source_bytes generated_bytes slot_observed',8,8),('global_before global_after',40,8),
        ('owner',s('sr_record'),64),('redirected',s('sr_frame'),64),('before_memory after_memory',s('li2_sro_memory'),8),('redirected_owners completed_owners',s('sro_owners'),64),
        ('source_page generated_page terminal_source_page',4096,1),('terminal_source_bytes',8,8)],64)
    form('uho_nested_fp',[('h',128,8),('zero ones',65536,64),('stack',524288,1)],64)
    form('sro_wire',[('h',512,8),('control',320,8),('focal',40,8),('focal_exits',64,8),('sink_initial sink_terminal main_backing',s('stat'),8),
        ('main interpreter',s('image'),8),('hardware',s('li2_selected_hardware'),4),('owner',s('scalar_owner'),64),('terminal_owners',s('sro_owners'),64),
        ('terminal_fetch',s('li2_fetch_progress'),8),('terminal_global_close',s('li2_native_close'),8),('terminal_native_counts',s('li2_native_counts'),8),('entries',2*s('sro_entry'),64),
        ('supplied_before',s('sr_frame'),64),('control_before',s('sr_record'),64),('original_source',4096,1),('generated',64*4096,1),('nested_fp',s('uho_nested_fp'),64)],64)

EDGES=(('li2_fetch_map_progress', 'li2_maps_observation', 'observation'), ('li2_fetch_backing', 'stat', 'stat'), ('li2_native_close', 'li2_fetch_map_progress', 'before after'), ('li2_native_pair_slot', 'li2_fetch_page', 'page'), ('li2_native_pair_slot', 'li2_fetch_backing', 'backing'), ('li2_native_pair_lifecycle', 'li2_fetch_map_progress', 'before after'), ('li2_native_pair_lifecycle', 'li2_native_pair_slot', 'slots'), ('li2_native_pair_lifecycle', 'li2_native_close', 'close'), ('li2_rseq_data', 'li2_fetch_map_progress', 'maps'), ('li2_rseq_transaction', 'li2_rseq_data', 'before after'), ('li2_rseq_state', 'li2_write_footprint', 'last_footprint'), ('li2_rseq_state', 'li2_rseq_data', 'data'), ('li2_rseq_state', 'li2_rseq_transaction', 'transaction'), ('li2_rseq_pair_progress', 'li2_rseq_data', 'before after'), ('li2_native_pair_progress', 'li2_step_frame', 'first second'), ('li2_native_pair_progress', 'li2_native_close', 'first_close'), ('li2_fetch_progress', 'li2_fetch_map_progress', 'preparation validation'), ('li2_private_code_query', 'li2_fetch_map_progress', 'maps'), ('li2_rseq_native_state', 'li2_rseq_data', 'before after'), ('li2_region_decoded', 'li2_decoded', 'decoded'), ('li2_region_decoded', 'li2_region_operand', 'operands'), ('li2_region_decoded', 'li2_region_register', 'registers'), ('li2_region_decoded', 'li2_region_memory', 'memory'), ('li2_region_plan', 'li2_region_decoded', 'original'), ('li2_region_plan', 'li2_region_decoded', 'boundary'), ('li2_region_plan', 'li2_region_decoded', 'emitted'), ('li2_region_plan', 'li2_region_head', 'head'), ('li2_region_plan', 'li2_region_pc', 'map'), ('li2_region_source_key', 'li2_fetch_page', 'page'), ('li2_region_source_key', 'li2_fetch_backing', 'backing'), ('li2_region_source', 'li2_fetch_ref', 'borrow'), ('li2_region_source', 'li2_region_source_key', 'key'), ('sr_frame', 'li2_step_frame', 'frame'), ('sr_permission', 'li2_private_code_query', 'query'), ('sr_slot', 'li2_region_source_key', 'key'), ('sr_slot', 'li2_region_plan', 'plan'), ('sr_slot', 'li2_private_code_query', 'writable'), ('sr_slot', 'sr_permission', 'publication'), ('sr_record', 'li2_region_source', 'source'), ('sr_record', 'sr_frame', 'before after unexpected'), ('sr_record', 'li2_region_pc', 'original'), ('sr_record', 'li2_private_code_query', 'idle live'), ('sr_record', 'sr_permission', 'open close cleanup'), ('sr_record', 'li2_fetch_progress', 'final_fetch'), ('scalar_owner', 'li2_step_session', 'session'), ('scalar_owner', 'li2_private_code_query', 'initial low_initial'), ('scalar_owner', 'li2_region_plan', 'scratch'), ('scalar_owner', 'sr_slot', 'slots'), ('scalar_owner', 'sr_record', 'current last'), ('li2_sro_maps', 'li2_fetch_map_progress', 'maps'), ('li2_sro_maps', 'li2_maps_stats', 'before after'), ('li2_sro_maps', 'li2_sro_map_row', 'rows'), ('li2_sro_maps', 'li2_sro_map_row', 'source generated'), ('li2_sro_memory', 'li2_sro_maps', 'initial restored'), ('sro_owners', 'li2_rseq_state', 'rseq'), ('sro_owners', 'li2_rseq_native_state', 'rseq_native'), ('sro_owners', 'li2_native_pair_progress', 'pair'), ('sro_owners', 'li2_native_pair_lifecycle', 'lifecycle'), ('sro_owners', 'li2_rseq_pair_progress', 'rseq_pair'), ('sro_entry', 'sr_record', 'owner'), ('sro_entry', 'sr_frame', 'redirected'), ('sro_entry', 'li2_sro_memory', 'before_memory after_memory'), ('sro_entry', 'sro_owners', 'redirected_owners completed_owners'), ('sro_wire', 'stat', 'sink_initial sink_terminal main_backing'), ('sro_wire', 'image', 'main interpreter'), ('sro_wire', 'li2_selected_hardware', 'hardware'), ('sro_wire', 'scalar_owner', 'owner'), ('sro_wire', 'sro_owners', 'terminal_owners'), ('sro_wire', 'li2_fetch_progress', 'terminal_fetch'), ('sro_wire', 'li2_native_close', 'terminal_global_close'), ('sro_wire', 'li2_native_counts', 'terminal_native_counts'), ('sro_wire', 'sro_entry', 'entries'), ('sro_wire', 'sr_frame', 'supplied_before'), ('sro_wire', 'sr_record', 'control_before'), ('sro_wire', 'uho_nested_fp', 'nested_fp'))

class Reader(old.Reader):
    def __init__(self,data,layout):
        self.data,self.layout,self.types=data,layout,dict(layout['types'])
        self.padding={}
        need(layout['record']=='sro_wire' and layout['member_witnesses']=={
            'li2_step_frame.fp':dict(symbol='sro_step_frame_fp_alignment',bytes=8,alignment=64),
            'uho_nested_fp.zero':dict(symbol='sro_nested_zero_alignment',bytes=8,alignment=64),
            'uho_nested_fp.ones':dict(symbol='sro_nested_ones_alignment',bytes=8,alignment=64)},'actual scalar symbol/member witnesses')
        need(layout['uc_bytes']==968 and layout['uc']==dict(
            offsets=dict(flags=0,link=8,greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),
            widths=dict(flags=8,link=8,greg=184,fp_pointer=8,mask=128,stack_sp=8,stack_flags=4,stack_size=8)),
            'complete actual x86-64 ucontext ABI')
        need(layout['si']==dict(bytes=128,offsets=dict(signo=0,errno=4,code=8,addr=16,pid=16,uid=20),
            widths=dict(signo=4,errno=4,code=4,addr=8,pid=4,uid=4)),'actual signal-info fields')
        shapes(self)
        need(set(self.types)==set(self.padding)==set(layout['edges']),'complete actual scalar transitive type inventory')
        expected={t:{} for t in self.types}
        for parent,child,keys in EDGES:
            for key in keys.split():expected[parent][key]=child
        need(layout['edges']==expected,'every scalar source-declared embedded object and array')
        need(type(data)is bytes and len(data)==self.types['sro_wire']['bytes']+64<8<<20,'whole scalar record plus footer')
        self.walk(data[:-64],'sro_wire')
        # Aliases share the EXACT source-identical frame/permission/owners ABI;
        # they only let unchanged donor methods address renamed scalar objects.
        for alias,actual in ALIASES.items():
            self.types[alias]=self.types[actual];self.padding[alias]=self.padding[actual]
