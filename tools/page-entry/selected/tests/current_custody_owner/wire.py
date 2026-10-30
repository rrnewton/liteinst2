"""Complete source-declared current-custody appendix, joined to actual old DWARF."""
import importlib.util
from pathlib import Path

_path=Path(__file__).resolve().parents[1]/'unrolled_hash_owner/read.py'
_spec=importlib.util.spec_from_file_location('current_custody_original_owner',_path)
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
need,zero,q=old.need,old.zero,old.q
PAGE=4096
NAMES=('maps_current','mct_physical_receipt','mct_physical_id','rx_current','rx_current_busy','cc','cc_candidate','cc_serial','cc_stats')
REGISTERED={
    'selected_run_owner':('selected_globals.inc','li2_run_owner'),
    'selected_run_history':('selected_globals.inc','li2_run_completion_history'),
    'cache':('register_run_publish.c','li2_run_cache'),
    'selected_repeat_lease':('selected_globals.inc','li2_repeat_lease_owner'),
    'selected_session':('selected_globals.inc','li2_step_session'),
    'rep_custody':('repeat_custody.inc',None),
    'rep_custody_stats':('repeat_custody.inc','li2_repeat_custody_observation'),
    'selected_unrolled':('selected_unrolled_hash.inc',None),
    'uho_wire':('unrolled_hash_observe.inc','uho_wire'),
    'cto_wire':('current_tf_observe.inc','cto_wire'),
}


class Reader(old.Reader):
    def __init__(self,data,layout,legacy):
        self.data,self.layout,self.types=data,layout,layout['types'];self.padding={}
        need(set(layout)=={'record','types','edges','member_witnesses','old_bytes','symbols','storage','registrations','uc_bytes','uc','si'} and layout['record']=='cto_wire','exact actual appendix metadata')
        need(layout['old_bytes']==legacy.types['uho_wire']['bytes'] and all(layout[k]==legacy.layout[k] for k in ('uc','uc_bytes','si')),'same compiled old extent and complete signal ABI')
        need(layout['member_witnesses']=={'li2_step_frame.fp':legacy.layout['member_witnesses']['li2_step_frame.fp']},'actual reachable aligned FP witness')
        need(set(layout['symbols'])=={'cto_wire','uho_wire','selected_chain','selected_unrolled','selected_session','protected','li2_raw6','li2_gateway_start','li2_gateway_end'} and all(type(v)is int and v>0 for v in layout['symbols'].values()),'complete actual emitted symbols')
        for k in set(layout['symbols'])&set(legacy.layout['symbols']):need(layout['symbols'][k]==legacy.layout['symbols'][k],'same ELF shared symbol '+k)
        self.edges={};self.new=set()
        for t in set(self.types)&set(legacy.types):
            need(self.types[t]==legacy.types[t] and layout['edges'][t]==legacy.layout['edges'][t],'same actual complete common type '+t)
            self.padding[t]=legacy.padding[t];self.edges[t]=legacy.layout['edges'][t]
        self.forms()
        need(set(self.types)==set(self.padding)==set(self.edges) and layout['edges']==self.edges,'all and only complete reachable source types and arrays')
        reached=set()
        def visit(t):
            if t in reached:return
            reached.add(t)
            for c in self.edges[t].values():visit(c)
        visit('cto_wire');need(reached==set(self.types),'no extraneous or omitted reachable type')
        need(type(data)is bytes and len(data)==self.types['cto_wire']['bytes']+64 and legacy.types['uho_wire']['bytes']+64+len(data)<16<<20,'complete combined record under original16MiB')
        self.walk(data[:-64],'cto_wire')

    def form(self,name,groups,align=8):
        fields={};edges={}
        for keys,size,a,child in groups:
            if type(size)is str:size=self.types[size]['bytes']
            elif type(size)is tuple:size=self.types[size[0]]['bytes']*size[1]
            for key in keys.split():
                need(key not in fields,'unique source field');fields[key]=(size,a)
                if child:edges[key]=child
        need(name not in self.edges,'new type separate from unchanged old schema')
        self.shape(name,fields,align);self.edges[name]=edges;self.new.add(name)

    def forms(self):
        f=self.form
        # Tuple fields: source names, exact extent (or child/count), alignment, child.
        f('li2_cto_storage',[('address bytes alignment',8,8,None)])
        f('li2_maps_view_stats',[('queries hits refreshes updates invalidations comparisons mismatches unexplained stack_probes',8,8,None),('enabled differential poisoned reserved',4,4,None)])
        f('li2_cto_view_state',[('stack_anchor stack_first stack_end',8,8,None),('stack_retired stack_pending',4,4,None),('view','li2_maps_view_stats',8,'li2_maps_view_stats')])
        f('Elf64_Phdr',[('p_type p_flags',4,4,None),('p_offset p_vaddr p_paddr p_filesz p_memsz p_align',8,8,None)])
        f('li2_fork_range',[('first end',8,8,None)])
        f('li2_decoder_stats',[('abi_version phase first_fatal_reason reserved',4,4,None),('arena_bytes retained_high_water allocation_calls deallocation_calls',8,8,None)])
        f('li2_step_page',[('address object generation offset',8,8,None),('closed_prot open_prot',4,4,None)])
        f('li2_step_request',[('decoded','li2_decoded',8,'li2_decoded'),('pages',('li2_step_page',2),8,'li2_step_page'),('page_count original_flags',8,8,None)])
        f('li2_step_hooks',[('context authenticate failure',8,8,None)])
        f('li2_step_owner',[('phase first_error in_handler self_test trace_seen revoke_sync_started',4,4,None),('first_detail session',8,8,None),('hooks','li2_step_hooks',8,'li2_step_hooks'),('request','li2_step_request',8,'li2_step_request'),('before after','li2_step_frame',64,'li2_step_frame'),('open_started opened revoke_started revoked',8,4,None),('open_result revoke_result',16,8,None),('open_sync revoke_sync',8,8,None),('signal_number signal_code signal_errno',4,4,None),('signal_address',8,8,None),('destination width',4,4,None),('immediate',8,8,None),('effect source',4,4,None)],64)
        f('li2_tf_classification',[('pc next_pc',8,8,None),('abi_version policy code length flow family',4,4,None)])
        f('li2_tf_hooks',[('step','li2_step_hooks',8,'li2_step_hooks'),('continue_closed',8,8,None)])
        f('li2_tf_shstk_observation',[('version attempted complete reserved seed_a seed_b value_a value_b',8,8,None)])
        f('li2_tf_owner',[('step','li2_step_owner',64,'li2_step_owner'),('classification','li2_tf_classification',8,'li2_tf_classification'),('hooks','li2_tf_hooks',8,'li2_tf_hooks'),('actual_post_pc actual_post_flags',8,8,None),('continuation_started continuation_complete unexpected_frame_observed continuation_result rdssp_query_attempted rdssp_query_complete',4,4,None),('rdssp_query_result rdssp_features',8,8,None),('rdssp_observation','li2_tf_shstk_observation',8,'li2_tf_shstk_observation'),('bnd_xcr0_attempted bnd_xcr0_complete',4,4,None),('bnd_xcr0',8,8,None)],64)
        f('li2_chain_fetch',[('ref','li2_fetch_ref',8,'li2_fetch_ref'),('progress','li2_fetch_progress',8,'li2_fetch_progress'),('pc length page_count pid tid',8,8,None),('identity_observed',4,4,None),('bytes',15,1,None),('pages',('li2_fetch_page',2),8,'li2_fetch_page'),('backing',('li2_fetch_backing',2),8,'li2_fetch_backing'),('last_backing','li2_fetch_backing',8,'li2_fetch_backing')])
        f('li2_chain_release',[('started complete result',4,4,None)],4)
        f('li2_tf_continuation',[('pc',8,8,None),('attempted page_observed complete result',4,4,None),('maps','li2_fetch_map_progress',8,'li2_fetch_map_progress'),('page','li2_fetch_page',8,'li2_fetch_page'),('backing','li2_fetch_backing',8,'li2_fetch_backing')])
        f('li2_tf_chain_slot',[('chain',8,8,None),('phase index origin fallback prepare_attempted prepare_complete decode_attempted decode_complete retry unexpected_frame_observed unexpected_signal unexpected_code unexpected_errno',4,4,None),('unexpected_address generation event_id',8,8,None),('owner','li2_tf_owner',64,'li2_tf_owner'),('decoded first_decoded','li2_decoded',8,'li2_decoded'),('descriptive_classification','li2_tf_classification',8,'li2_tf_classification'),('prepare_result decode_result classify_result',4,4,None),('fetch first_fetch','li2_chain_fetch',8,'li2_chain_fetch'),('release first_release','li2_chain_release',4,'li2_chain_release'),('query','li2_tf_continuation',8,'li2_tf_continuation'),('unexpected','li2_step_frame',64,'li2_step_frame')],64)
        f('li2_page_custody_receipt',[('kind provenance slot checks',4,4,None),('epoch origin_sequence owner_generation event chain owner session',8,8,None),('origin','li2_fetch_map_progress',8,'li2_fetch_map_progress')])
        f('li2_fetch_rx_view',[('phase complete result',4,4,None),('serial before_sequence after_sequence pc length pid tid',8,8,None),('bytes',15,1,None),('page','li2_fetch_page',8,'li2_fetch_page'),('backing','li2_fetch_backing',8,'li2_fetch_backing'),('maps','li2_fetch_map_progress',8,'li2_fetch_map_progress'),('maps_observed',4,4,None),('custody','li2_page_custody_receipt',8,'li2_page_custody_receipt')])
        f('li2_tf_same_page',[('phase origin_active slot',4,4,None),('candidates misses transfers closed_leases owner_generation origin_event origin_borrow completed_event',8,8,None),('opening previous','li2_step_request',8,'li2_step_request'),('opening_frame previous_before','li2_step_frame',64,'li2_step_frame'),('previous_fetch','li2_fetch_progress',8,'li2_fetch_progress'),('transfer','li2_fetch_rx_view',8,'li2_fetch_rx_view'),('next','li2_decoded',8,'li2_decoded'),('classification','li2_tf_classification',8,'li2_tf_classification')],64)
        f('li2_tf_trace_entry',[('valid previous next',4,4,None),('event_id sequence previous_generation next_generation pc flags previous_borrow_sequence',8,8,None)])
        f('li2_tf_chain',[('session failure',8,8,None),('initialized first_error active pending in_handler',4,4,None),('first_detail event_id sequence attempts steps nx_entries trace_entries fallbacks prepare_attempts releases unexpected_events',8,8,None),('initial_stats','li2_decoder_stats',8,'li2_decoder_stats'),('entry','li2_tf_trace_entry',8,'li2_tf_trace_entry'),('slots',('li2_tf_chain_slot',2),64,'li2_tf_chain_slot'),('lease','li2_tf_same_page',64,'li2_tf_same_page')],64)
        f('li2_maps_current_view',[('version complete result',4,4,None),('detail serial query_serial table stack_first stack_end rows',8,8,None),('physical query','li2_fetch_map_progress',8,'li2_fetch_map_progress')])
        f('li2_current_custody_provenance',[('version kind consumed complete',4,4,None),('epoch origin_sequence stage_serial',8,8,None),('origin','li2_maps_current_view',8,'li2_maps_current_view')])
        f('li2_current_custody_stats',[('attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels',8,8,None),('first_error',4,4,None),('first_detail',8,8,None)])
        f('li2_page_custody_stats',[('epoch seeds retained_stages retained_checks commits discards',8,8,None),('phase last_reason',4,4,None)])
        f('cto_registry',[('complete count',4,4,None),('table',8,8,None),('bridge','image',8,'image'),('ph',('Elf64_Phdr',32),8,'Elf64_Phdr'),('ranges',('li2_fork_range',128),8,'li2_fork_range'),('initial_code',128,1,None),('storage',('li2_cto_storage',9),8,'li2_cto_storage'),('intersects load_indices range_indices',36,4,None)])
        f('cto_snapshot',[('present point current_route result',4,4,None),('chain argument view event',8,8,None),('active pending in_handler first_error',4,4,None),('first_detail',8,8,None),('ref','li2_fetch_ref',8,'li2_fetch_ref'),('slot','li2_tf_chain_slot',64,'li2_tf_chain_slot'),('session','li2_step_session',8,'li2_step_session'),('physical current','li2_fetch_rx_view',8,'li2_fetch_rx_view'),('provenance','li2_current_custody_provenance',8,'li2_current_custody_provenance'),('counts','li2_current_custody_stats',8,'li2_current_custody_stats'),('custody','li2_page_custody_stats',8,'li2_page_custody_stats'),('maps','li2_maps_stats',8,'li2_maps_stats'),('view_state','li2_cto_view_state',8,'li2_cto_view_state'),('rseq','li2_rseq_state',8,'li2_rseq_state')],64)
        f('cto_row',[('present index after_present source_bytes data_bytes stack_bytes',4,4,None),('pc',8,8,None),('before after','uh_frame',64,'uh_frame'),('points',('cto_snapshot',7),64,'cto_snapshot'),('data',8192,1,None),('stack',160,1,None)],64)
        f('cto_wire',[('h',256,8,None),('initial_registry terminal_registry','cto_registry',8,'cto_registry'),('initial_memory','li2_uho_memory',8,'li2_uho_memory'),('tls_origin','uh_frame',64,'uh_frame'),('rows',('cto_row',4),64,'cto_row'),('stale_before stale_after','cto_snapshot',64,'cto_snapshot'),('joined_chain terminal_chain prefix_chain','li2_tf_chain',64,'li2_tf_chain'),('joined_counts terminal_counts','li2_current_custody_stats',8,'li2_current_custody_stats'),('joined_custody terminal_custody','li2_page_custody_stats',8,'li2_page_custody_stats'),('joined_view terminal_view','li2_cto_view_state',8,'li2_cto_view_state'),('original_source entry_source joined_source',4096,1,None),('source_offset',8,8,None)],64)
