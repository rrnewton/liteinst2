#!/usr/bin/env python3
"""One release original-address CallPair192 qualification, under a hard3CPU outer owner."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode=True
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import traceback

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
MIB=1048576
PROFILE='normal-call-pair-original-rust-v1'
SEEDS=(1311768467139281696,18364758542526924135)
SCOPE='Actual original-address admitted Rust caller and nested parent E8/body only; no threaded application, Schedule, K exhaustion, reuse, timing or full-A5 credit. External hard reservation and final exact-command outer closure remain required.'
STAGES=('tool-cc1', 'tool-collect2', 'tool-as', 'tool-ld', 'module-build', 'module-symbols', 'parent-disassembly', 'child-disassembly', 'application-build', 'application-caller-disassembly', 'application-caller-symbols', 'state-build', 'ordinary-build', 'sdk-build', 'core-build', 'state-list', 'state-controls', 'ordinary-list', 'ordinary-oracle-controls', 'ordinary-check-controls', 'ordinary-owner-controls', 'sdk-list', 'frontend-controls', 'site-controls', 'runtime-controls', 'core-list', 'stack-profile-controls', 'stack-trace-controls', 'legacy-python-controls', 'session-python-controls', 'copied-python-controls', 'copied-runner-controls', 'leaf-python-controls', 'leaf-runner-controls', 'python-controls', 'runner-controls', 'native-outer')
ORACLE_CONTROLS=('oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_case_matrix_and_profile_refuse_old_discriminators', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_ready_joins_original_caller_pages_functions_and_layout', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_nested_order_requires_physical_child_landing_before_ack', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_e8_target_stack_words_and_roles_are_exact', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_control_ack_preserves_own_generations_and_removed_child', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_complete_stack_capture_bounds_and_deep_tail_refuse', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_parent_effects_preserve_defined_flags_and_scalar', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_pair_population_and_full_cfg_coverage_refuse', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_all_journal_words_and_phase_counts_refuse', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_postflight_fits_without_reader_and_closes_after_one_send', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_postflight_rejects_empty_and_oversized_before_writing', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_postflight_drop_without_finish_emits_no_packet', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::postflight_codec_roundtrip_and_canonical_bounds_refuse', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_stable_rearm_removed_preserves_instruction_membership', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_rejects_changed_record_report_history_identity', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_rejects_shifted_and_duplicated_reference_boundaries', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_timestamp_consistency_preserves_observations')
ORDINARY_CONTROLS=('oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_case_matrix_and_profile_refuse_old_discriminators', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_ready_joins_original_caller_pages_functions_and_layout', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_nested_order_requires_physical_child_landing_before_ack', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_e8_target_stack_words_and_roles_are_exact', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_control_ack_preserves_own_generations_and_removed_child', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_complete_stack_capture_bounds_and_deep_tail_refuse', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_parent_effects_preserve_defined_flags_and_scalar', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_pair_population_and_full_cfg_coverage_refuse', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_all_journal_words_and_phase_counts_refuse', 'normal::call_pair_state::check::tests::call_pair_records_join_lifo_sequences_actual_and_sampled_children', 'normal::call_pair_state::check::tests::call_pair_reports_history_and_owner_closure_are_complete', 'normal::call_pair_state::caller::tests::running_caller_requires_distinct_files_actual_entry_and_load_bias', 'normal::call_pair_state::caller::tests::running_caller_rejects_mapping_device_inode_offset_and_bytes', 'normal::call_pair_state::caller::tests::running_caller_page_union_refuses_gaps_overlap_and_overflow', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_postflight_fits_without_reader_and_closes_after_one_send', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_postflight_rejects_empty_and_oversized_before_writing', 'oracle::native_ordinary::normal_caller::call_pair::tests::call_pair_postflight_drop_without_finish_emits_no_packet', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::postflight_codec_roundtrip_and_canonical_bounds_refuse', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_stable_rearm_removed_preserves_instruction_membership', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_rejects_changed_record_report_history_identity', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_rejects_shifted_and_duplicated_reference_boundaries', 'oracle::native_ordinary::normal_caller::call_pair::trace_join::tests::trace_join_timestamp_consistency_preserves_observations')
SDK_CONTROLS=('frontend_native::module::ordinary::call_pair::tests::parent_dataflow_accepts_distinct_frames_and_preserves_roles', 'frontend_native::module::ordinary::call_pair::tests::parent_rejects_edges_and_incomplete_geometry', 'frontend_native::module::ordinary::call_pair::tests::parent_rejects_wrong_arguments_clobber_and_uninitialized_stack', 'frontend_native::module::ordinary::call_pair::tests::parent_rejects_bad_frame_restoration_prefixes_and_unsupported_ops', 'frontend_native::module::ordinary::call_pair::tests::pair_selection_and_contract_require_independent_disjoint_source', 'frontend_native::module::ordinary::call_pair::tests::pair_overlay_and_page_union_preserve_call_and_untouched_bytes', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_plans_all_roles_with_original_call_and_full_reads', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_sparse_pages_and_reversed_roles_keep_canonical_union', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_refuses_source_identity_roles_and_short_regions', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_exclusion_refuses_displacement_write_and_lock_overlap', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_budget_refuses_excess_members_without_widening_old_paths', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair240_carries_exact_profile_for_every_planned_role', 'frontend_native::always_on::normal::call_pair::tests::profile_and_banks_reject_other_limits', 'frontend_native::always_on::normal::call_pair::tests::actual_receipts_child_ack_then_root_checkpoint', 'frontend_native::always_on::normal::call_pair::tests::ret_observation_is_not_ack_and_rejects_identity', 'frontend_native::always_on::normal::call_pair::tests::stack_envelope_requires_exact_layout_and_ranges', 'frontend_native::always_on::normal::call_pair::tests::wrong_role_pc_and_control_refuse', 'frontend_native::always_on::normal::call_pair::tests::transfer_checks_all_words_and_capacity_before_consume', 'frontend_native::always_on::normal::call_pair::tests::mixed_generations_keep_own_receipts', 'frontend_native::always_on::normal::call_pair::tests::removed_child_keeps_actual_tree', 'frontend_native::always_on::normal::call_pair::tests::function_closed_report_ready_but_reclaim_shared', 'frontend_native::always_on::normal::call_pair::tests::sampled_parent_blocks_report_until_root', 'frontend_native::always_on::normal::call_pair::tests::full_budget_keeps_global_slots_function_ranks', 'frontend_native::always_on::normal::call_pair::tests::completed_payload_wrong_function_or_children_refuse', 'frontend_native::always_on::normal::call_pair::tests::history_stream_and_batch_identity_are_exact', 'frontend_native::always_on::normal::call_pair::tests::lost_handle_retains_owner_and_sticky_failure', 'frontend_native::always_on::normal::call_pair::tests::order_failures_before_consumption', 'frontend_native::always_on::normal::call_pair::tests::old_profile_exclusions_remain', 'frontend_native::always_on::normal::call_pair::tests::report_global_slots_and_payload_child_counts_are_independent', 'frontend_native::always_on::normal::call_pair::tests::compact_journal_validation_keeps_all_words_at_every_phase')
CORE_CONTROLS=('trampoline::stack_profile_tests::explicit_legacy_matches_old_constructor_bytes_layout_maps_and_owners', 'trampoline::stack_profile_tests::nonlegacy_profile_refuses_mixed_modes_before_emission', 'trampoline::stack_profile_tests::profile_is_part_of_image_identity_not_a_byte_length_guess', 'trampoline::stack_profile_tests::call_pair240_has_distinct_geometry_and_image_identity', 'trampoline::stack_profile_tests::call_pair240_keeps_the_same_nonlegacy_mixed_mode_refusals', 'frame_trace::tests::call_pair_stack::call_pair240_all_bounded_roles_preserve_enclosing_window', 'frame_trace::tests::call_pair_stack::call_pair240_old144_overlaps_child_and_earlier_caller_excursions', 'frame_trace::tests::call_pair_stack::call_pair240_actual_reserve_recovery_restore_and_profile_mutations_refuse')
PYTHON_CONTROLS=('test_complete192_pairs_and12_groups_keep_exact_original_address_scope', 'test_matrix_order_missing_duplicate_and_coherent_subset_refuse', 'test_literal_csv_inputs_fields_and_packed_results', 'test_independent_complete_caller_parent_child_geometry', 'test_nested_stack_historical_excursion_and_child_delta', 'test_scenarios_generations_lifo_sequences_and_history', 'test_every_raw_counter_and_step_bound', 'test_csv_observed_union_and_all_declared_returns', 'test_canonical_bytes_numbers_framing_caps_and_stderr', 'test_terminal_population_comparisons_and_old_profiles', 'test_coherent_geometry_corruptions_require_external_authority', 'test_source_local_import_and_optimization_guard', 'test_work_complete384_rows_keep_removed_child_and_ret_boundaries', 'test_work_each_field_mutation_and_coherent_ret_shift_refuse', 'test_work_requires_complete_ordered_canonical_table', 'test_work_coherent_pid_and_address_changes_still_need_native_authority')
RUNNER_CONTROLS=('test_fixed_catalog_stages_and_once_only_attempt', 'test_exact208_calibrations_preserve_old199', 'test_selected_native_sdk_core_censuses_are_exact', 'test_request_original_executable_identity_geometry_and_cpu', 'test_geometry_uses_complete_e8_target_and_historical_stack', 'test_prefix_retains_only_ordered_complete_rows', 'test_closed_failure_and_unrun_projection_remain_unqualified', 'test_tool_alias_and_library_product_fail_closed')


def catalog():
    return [(k,seed,case,scenario) for k in (10,1000) for seed in SEEDS for case in range(1,17) for scenario in (1,2,3)]


def initial_cohort():
    keys=catalog(); assert len(keys) == len(set(keys)) == 192
    return dict(name='call-pair',status='UNRUN',attempts=0,required_pairs=192,catalog=keys,observed=[],prefix_error=None)


def calibration_inventory(leaf,prior,inventory,ignored):
    assert len(inventory) == len(set(inventory)) and set(ORACLE_CONTROLS) <= set(inventory)
    old=leaf.efficiency_calibration_inventory(prior,[n for n in inventory if n not in ORACLE_CONTROLS],ignored)
    assert len(old) == 199 and not set(old).intersection(ORACLE_CONTROLS)
    expected=old|{n:False for n in ORACLE_CONTROLS}
    assert len(expected) == 216 and set(inventory) == set(expected)|{ignored}
    return expected


def selected_inventory(inventory,wanted):
    assert type(inventory) is list and len(inventory) == len(set(inventory))
    assert len(wanted) == len(set(wanted))
    prefixes=tuple(sorted({n.rsplit('::',1)[0]+'::' for n in wanted}))
    assert {n for n in inventory if n.startswith(prefixes)} == set(wanted)
    return tuple(wanted)


def tool_alias(tools,env):
    selected=shutil.which('cc',path=env['PATH']); assert selected is not None
    assert Path(selected).resolve(strict=True) == tools['gcc']


def core_product(data):
    messages=[json.loads(line) for line in data.splitlines()]
    assert messages and messages[-1] == dict(reason='build-finished',success=True)
    products=[m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'liteinst2' and m['profile']['test'] is True]
    assert len(products) == 1
    p=products[0]; assert p['manifest_path'] == str(ROOT/'Cargo.toml') and p['target']['src_path'] == str(ROOT/'src/lib.rs')
    assert p['target']['kind'] == p['target']['crate_types'] == ['lib']
    assert p['profile'] == dict(opt_level='3',debuginfo=0,test=True,debug_assertions=True,overflow_checks=True)
    assert type(p['profile']['debuginfo']) is int and type(p['fresh']) is bool
    binary=Path(p['executable']); assert binary.is_absolute() and binary.parent == ROOT/'target/release/deps'
    assert re.fullmatch('liteinst2-[0-9a-f]+',binary.name)
    return binary,p


def stack_geometry(rows,va,length,limit,direct_child=None):
    """Independent emitted geometry only; native decoder retains instruction/dataflow authority."""
    reg=r'r(?:ax|bx|cx|dx|si|di|sp|bp|[89]|1[0-5])'
    stack={'rsp':0}; memory={}; low=0; call=None; delta=None
    at=va
    for i,(pc,code,asm) in enumerate(rows):
        assert pc == at and type(code) is bytes and 1 <= len(code) <= 15
        at += len(code); words=asm.split(None,1); op=words[0]; args=words[1] if len(words)==2 else ''
        def address(word):
            m=re.fullmatch(r'QWORD PTR \[('+reg+r')(?:(\+|-)0x([0-9a-f]+))?\]',word)
            assert m and m[1] in stack
            v=int(m[3],16) if m[3] else 0
            return stack[m[1]]+(-v if m[2]=='-' else v)
        if op == 'push':
            assert re.fullmatch(reg,args) and args != 'rsp'; value=stack.get(args)
            stack['rsp']-=8; memory[stack['rsp']]=value
        elif op == 'pop':
            assert re.fullmatch(reg,args) and args != 'rsp'
            value=memory.get(stack['rsp']); stack['rsp']+=8
            if value is None: stack.pop(args,None)
            else: stack[args]=value
        elif op == 'mov':
            operands=args.split(','); assert len(operands)==2; dst,src=operands
            value=stack.get(src) if re.fullmatch(reg,src) else (memory.get(address(src)) if direct_child is not None else None)
            if re.fullmatch(reg,dst):
                if dst == 'rsp': assert value is not None
                if value is None: stack.pop(dst,None)
                else: stack[dst]=value
            else:
                # Caller result pointers need no stack provenance. Parent stores do.
                if direct_child is not None: memory[address(dst)]=value
                else: assert re.fullmatch(r'QWORD PTR \['+reg+r'\]',dst)
        elif op == 'lea':
            m=re.fullmatch('('+reg+r'),\[('+reg+r')(?:(\+|-)0x([0-9a-f]+))?\]',args)
            assert m and m[2] in stack
            v=int(m[4],16) if m[4] else 0; stack[m[1]]=stack[m[2]]+(-v if m[3]=='-' else v)
        elif op in ('add','sub'):
            m=re.fullmatch(r'rsp,0x([0-9a-f]+)',args); assert m
            v=int(m[1],16); assert 0 < v <= limit and v%8 == 0
            stack['rsp']+=v if op=='add' else -v
        elif op == 'call':
            assert call is None and i+1 < len(rows) and (8+stack['rsp'])%16 == 0
            if direct_child is None: assert re.fullmatch(reg,args)
            else:
                m=re.fullmatch(r'([0-9a-f]+) <[^>]+>',args); assert m and int(m[1],16)==direct_child
                assert len(code)==5 and code[0]==0xe8 and pc+5+int.from_bytes(code[1:],'little',signed=True)==direct_child
            call=pc-va; delta=8-stack['rsp']
            for n in ('rax','rcx','rdx','rsi','rdi','r8','r9','r10','r11'): stack.pop(n,None)
        elif op == 'ret': assert i==len(rows)-1 and args=='' and code==b'\xc3' and stack['rsp']==0
        elif direct_child is not None and op in ('shl','or','nop'):
            if op=='shl': assert re.fullmatch(reg+r',0x20',args); stack.pop(args.split(',')[0],None)
            elif op=='or':
                assert re.fullmatch(reg+','+reg,args); stack.pop(args.split(',')[0],None)
            else: assert code==b'\x90' and args==''
        else: raise AssertionError('unsupported complete geometry')
        assert type(stack.get('rsp')) is int and -limit <= stack['rsp'] <= 0 and stack['rsp']%8==0
        low=max(low,-stack['rsp']); memory={p:v for p,v in memory.items() if p>=stack['rsp']}
    assert at == va+length and rows[-1][2]=='ret' and call is not None
    assert 16 <= delta <= limit and delta%16==0
    return dict(call_offset=call,continuation_offset=rows[[p-va for p,_,_ in rows].index(call)+1][0]-va,
                delta=delta,lowest_stack=low)


def parent_geometry(rows,va,length,child_va):
    assert type(va) is int and va>0 and 5 <= length <= 80 and va+length <= (1 << 64)-1
    g=stack_geometry(rows,va,length,64,child_va)
    return dict(elf_va=va,length=length,heads=[p-va for p,_,_ in rows],edges=len(rows)-1,returns=[length-1],
        call_offset=g['call_offset'],continuation_offset=g['continuation_offset'],child_delta=g['delta'],callee_entry=child_va,
        body_hex=b''.join(c for _,c,_ in rows).hex())


def request_shape(request,cpus):
    assert set(request)=={'argv','cwd','env','stdout','stderr','pins','cpu'}
    assert type(cpus) is list and len(cpus)==3 and cpus==sorted(set(cpus))
    assert all(type(x) is int and 0<=x<1024 for x in cpus)
    assert type(request['cpu']) is int and request['cpu']==cpus[1]
    a=request['argv']; assert type(a) is list and len(a)==12 and all(type(x) is str and '\0' not in x for x in a)
    cohort=Path(request['stdout']).parent; raw=cohort.parent
    assert raw.is_absolute() and raw.resolve(strict=True)==raw and raw.is_relative_to(ROOT/'ignored')
    assert cohort.name=='native' and cohort.resolve(strict=True)==cohort
    assert a[:4]==[str(raw/'application-candidate'),'normal-call-pair-state',str(raw/'module-candidate.so'),str(raw/'module-trusted.so')]
    assert a[8:]==list(map(str,[raw/'application-candidate',raw/'application-trusted',cohort/'output',cpus[1]]))
    assert all(re.fullmatch('[1-9][0-9]{0,19}',x) for x in a[4:8])
    pv,pl,cv,cl=map(int,a[4:8]); assert 5<=pl<=80 and 5<=cl<=256 and max(pv+pl,cv+cl)<1 << 64
    assert pv+pl<=cv or cv+cl<=pv
    assert len({v//4096 for v in (pv,pv+pl-1,cv,cv+cl-1)})<=2
    assert request['stdout']==str(cohort/'stdout.txt') and request['stderr']==str(cohort/'stderr.txt')
    assert request['cwd']==str(ROOT) and type(request['env']) is dict and request['env']['LITEINST_EVALUATION']=='1'
    assert {str(HERE/'reproduce.py'),a[0],a[2],a[3],a[9]} <= request['pins'].keys()
    return cohort


def native_exec(path,expected_hash):
    import stat
    assert re.fullmatch('[0-9a-f]{64}',expected_hash)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and 0<before.st_size<=MIB
        data=stream.read(MIB+1); after=os.fstat(stream.fileno()); assert before==after and len(data)==before.st_size
    assert hashlib.sha256(data).hexdigest()==expected_hash
    request=json.loads(data); cpus=sorted(os.sched_getaffinity(0)); cohort=request_shape(request,cpus)
    assert path==cohort/'request.json'
    helper=ROOT/'evaluation/ordinary-module-native/reproduce.py'; data=helper.read_bytes(); assert len(data)<=MIB
    assert request['pins'][str(helper)]==dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    spec=importlib.util.spec_from_file_location('_pair_native_limits',helper); assert spec and spec.loader
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module.pins_ok(request['pins'])
    os.sched_setaffinity(0,{request['cpu']}); assert sorted(os.sched_getaffinity(0))==[request['cpu']]
    module._native_exec(path,expected_hash,lambda value:request_shape(value,cpus))


def prefix_rows(data,header):
    assert type(data) is bytes and len(data)<=524288
    parts=data.split(b'\n'); tail=parts.pop(); fields=header.split(','); rows=[]
    if not parts or parts.pop(0)!=header.encode('ascii'): return rows,'HEADER_OR_TRUNCATION'
    for line in parts:
        try:
            assert len(rows)<192 and re.fullmatch(rb'[\x20-\x7e]+',line)
            values=line.decode('ascii').split(','); assert len(values)==len(fields)
            assert all(re.fullmatch(r'0|[1-9][0-9]{0,19}',v) for v in values)
            values=list(map(int,values)); assert all(v<(1 << 64) for v in values)
            row=dict(zip(fields,values)); assert tuple(row[n] for n in ('k','seed','case','scenario'))==catalog()[len(rows)]
            rows.append(row)
        except (AssertionError,ValueError,UnicodeError,KeyError): return rows,'FIRST_INVALID_ROW'
    return rows,('TRUNCATED_TAIL' if tail else None)


def public_projection(result):
    row=result['cohort']; assert row['catalog']==catalog() and len(row['observed'])<=192
    return dict(status='UNQUALIFIED_PENDING_FINAL_RECEIPT',local_status=result['status'],revision=result['revision'],profile=PROFILE,
        cohort_status=row['status'],attempts=row['attempts'],observed_rows=len(row['observed']),prefix_error=row['prefix_error'],
        outcomes=[dict(key=key,status='OBSERVED_UNQUALIFIED' if i<len(row['observed']) else 'UNRUN',
                       values=row['observed'][i] if i<len(row['observed']) else None) for i,key in enumerate(catalog())],
        custody_closed=result.get('custody_closed',False),retention_verified=result.get('retention_verified',False),
        external_owner_required=True,scope=SCOPE)


def capture_prefix(run,recipe,leaf,row,cohort,directory,closed,checker):
    assert run.safe
    parent_log=recipe.read(directory/'parent.log',MIB); leaf.closed_output(closed,parent_log)
    row.update(closed=closed,load_after=list(os.getloadavg()),affinity_after=sorted(os.sched_getaffinity(0)))
    output=cohort/'output'
    if output.exists(): assert output.is_dir() and not output.is_symlink()
    for name,cap in [('stdout.txt',MIB),('stderr.txt',MIB),('output/call-pair-state-pairs.csv',524288),('output/call-pair-state-coverage.csv',16384),('output/call-pair-state-work.csv',524288)]:
        p=cohort/name
        if p.exists(): run.remember(p,cap=cap)
    p=output/'call-pair-state-pairs.csv'
    if p.exists(): row['observed'],row['prefix_error']=prefix_rows(recipe.read(p,524288),checker.HEADER)
    else: row['prefix_error']='NO_PAIRS_FILE'
    return parent_log


def execute_cohort(run,recipe,copied,leaf,request,value,checker,parent,child,caller):
    row=run.result['cohort']; cohort=Path(request['stdout']).parent
    command=[run.tools['python'],'-B',HERE/'reproduce.py','--native-request',cohort/'request.json',value['sha256']]
    run.command('native-outer',command,510); leaf.begin(row)
    row.update(load_before=list(os.getloadavg()),affinity_before=sorted(os.sched_getaffinity(0)))
    run.freeze(cohort/'attempt.json',dict(status='FAILED',attempts=1))
    try: directory,closed=run.owned('native-outer',command,510,growth=16*MIB)
    except BaseException:
        stage=next((r for r in run.result['stages'] if r['name']=='native-outer'),None)
        if run.safe and stage is not None and 'closed' in stage:
            try: capture_prefix(run,recipe,leaf,row,cohort,run.raw/'native-outer',stage['closed'],checker)
            except BaseException: row['prefix_error']='RETENTION_CUSTODY_OR_PREFIX_REFUSED'
        raise
    parent_log=capture_prefix(run,recipe,leaf,row,cohort,directory,closed,checker)
    copied.accept_closure(row,closed,parent_log)
    output=cohort/'output'; assert output.is_dir() and not output.is_symlink()
    assert {p.name for p in output.iterdir()}=={'call-pair-state-pairs.csv','call-pair-state-coverage.csv','call-pair-state-work.csv'}
    parsed=checker.check_with_work(recipe.read(output/'call-pair-state-pairs.csv',524288),recipe.read(output/'call-pair-state-coverage.csv',16384),recipe.read(output/'call-pair-state-work.csv',524288),
        recipe.read(cohort/'stdout.txt',1024),recipe.read(cohort/'stderr.txt',MIB),parent=parent,child=child,caller=caller)
    assert parsed['status']=='CALL_PAIR_ORIGINAL_TRANSCRIPT_VALIDATED' and row['prefix_error'] is None
    assert len(row['observed'])==192 and parsed['rows']==row['observed']
    run.closed_inventory(cohort); run.budget.complete(); run.unchanged()
    row.update(status='LOCAL_NATIVE_CHECKS_COMPLETE',comparisons=parsed['comparisons'])


def main():
    started=time.monotonic(); ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision',required=True); ap.add_argument('--reservation-tag',required=True)
    for n in ('raw','toolchain','user-home','cargo-home'): ap.add_argument('--'+n,type=Path,required=True)
    a=ap.parse_args(); assert re.fullmatch('[0-9a-f]{40}',a.revision) and re.fullmatch('[A-Za-z0-9_.-]{1,128}',a.reservation_tag)
    assert HERE==ROOT/'evaluation/ordinary-call-pair-native'
    for p in (ROOT,a.toolchain,a.user_home,a.cargo_home): assert p.is_absolute() and p.resolve(strict=True)==p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True)==a.raw.parent and a.raw.is_relative_to(ROOT/'ignored')
    assert not os.path.lexists(a.raw) and not os.path.lexists(ROOT/'target/evaluation'/a.raw.name)
    os.chdir(ROOT)
    tools={n:(a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo','rustc','rustdoc')}
    tools.update({n:Path('/usr/bin',n).resolve(strict=True) for n in ('git','gcc','readelf','objdump','bash','rg')})
    tools['python']=Path(sys.executable).resolve(strict=True)
    env=dict(HOME=str(a.user_home),CARGO_HOME=str(a.cargo_home),PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(tools['rustc']),RUSTDOC=str(tools['rustdoc']),CC=str(tools['gcc']),CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_NET_OFFLINE='true',CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',LITEINST_EVALUATION='1',TMPDIR=str(a.raw/'tmp'))
    tool_alias(tools,env)
    def git(*args):
        data=subprocess.check_output(['/usr/bin/git','-C',ROOT,*args],env=env,timeout=15); assert len(data)<=32*MIB
        return data
    assert git('rev-parse','--show-toplevel').decode().strip()==str(ROOT)
    assert git('rev-parse','HEAD').decode().strip()==a.revision and git('status','--porcelain','--untracked-files=no')==b''
    for name in ('evaluation/ordinary-call-pair-native/reproduce.py','evaluation/ordinary-module-session/reproduce.py'):
        p=ROOT/name; assert not p.is_symlink() and p.is_file() and p.stat().st_size<=MIB
        assert p.read_bytes()==git('show',a.revision+':'+name)
    spec=importlib.util.spec_from_file_location('_call_pair_session',ROOT/'evaluation/ordinary-module-session/reproduce.py')
    assert spec and spec.loader; recipe=importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)
    required=set(recipe.MODULES.values())|{
        'evaluation/ordinary-module-native/controls.py','evaluation/ordinary-module-session/controls.py',
        'evaluation/ordinary-module-native/module_native.py','evaluation/ordinary-leaf-set-session/reproduce.py',
        'evaluation/ordinary-rust-invoke-native/reproduce.py','evaluation/ordinary-rust-invoke-native/rust_invoke.py',
        'evaluation/ordinary-rust-invoke-native/caller.py','evaluation/ordinary-rust-invoke-native/controls.py',
        'evaluation/ordinary-rust-invoke-native/runner_controls.py','evaluation/ordinary-module-session/reproduce.py',
        'evaluation/ordinary-leaf-set-native/reproduce.py','evaluation/ordinary-leaf-set-native/controls.py',
        'evaluation/ordinary-leaf-set-native/runner_controls.py','evaluation/ordinary-leaf-set-native/leaf_set_native.py',
        'tools/unwind-oracle/bounded_command.py','tests/call_tree_truth.rs','tools/rapid-profiler/normal-work/call_pair.c',
        'tools/rapid-profiler/normal-work/csv_fields.c','tools/rapid-profiler/strnlen-work/localize.map',
        'tests/support/native_call_pair.rs','tests/support/native_call_pair/tests.rs',
        'tests/support/native_call_pair/parent.rs','tests/support/native_call_pair/phase.rs','tests/support/native_call_pair/trace.rs',
        'tests/support/native_normal_caller.rs','tests/support/native_normal_module.rs','tests/support/native_copied_capture.rs',
        'tests/support/native_copied_rust.rs','tests/support/native_copied_rust/effects.rs',
        'tools/rapid-profiler/native-interval/normal/rust_invoke_artifact.rs',
        'tools/rapid-profiler/ordinary-interval/normal/call_pair_state.rs',
        'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/caller.rs',
        'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/check.rs',
        'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/check/tests.rs',
        'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/held.rs',
        'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/lifecycle.rs'}
    required.update('evaluation/ordinary-call-pair-native/'+n for n in ('reproduce.py','call_pair_native.py','controls.py','runner_controls.py','README.md'))
    names=git('ls-files','-z','--','src','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock','README.md','build.rs',':(glob)**/Cargo.toml',*sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names)==len(set(names)) and required<=set(names)
    sources={}
    for name in names:
        data=recipe.read(ROOT/name); assert data==git('show',a.revision+':'+name); sources[str(ROOT/name)]=recipe.pin(data)
    for name,expected in [('evaluation/admission/processes.py',recipe.OWNER_SHA),('tools/unwind-oracle/bounded_command.py',recipe.BOUNDED_SHA),('evaluation/ordinary-module-session/corpus.py',recipe.CORPUS_SHA)]:
        assert sources[str(ROOT/name)]['sha256']==expected
    tool_pins={str(p):recipe.pin(recipe.read(p,512*MIB)) for p in tools.values()}
    assert git('rev-parse','HEAD').decode().strip()==a.revision and git('status','--porcelain','--untracked-files=no')==b''
    modules={key:recipe.load(key,ROOT/path) for key,path in recipe.MODULES.items()}; native=modules['native']
    copied=recipe.load('call_pair_copied',ROOT/'evaluation/ordinary-rust-invoke-native/reproduce.py')
    caller_parser=recipe.load('call_pair_caller',ROOT/'evaluation/ordinary-rust-invoke-native/caller.py')
    leaf=recipe.load('call_pair_leaf',ROOT/'evaluation/ordinary-leaf-set-native/reproduce.py')
    library=recipe.load('call_pair_library',ROOT/'evaluation/ordinary-leaf-set-session/reproduce.py')
    checker=recipe.load('call_pair_output',HERE/'call_pair_native.py')
    assert sources[str(ROOT/'tools/rapid-profiler/normal-work/csv_fields.c')]['sha256']==native.CSV_SOURCE_SHA
    assert sources[str(ROOT/'tools/rapid-profiler/normal-work/call_pair.c')]['sha256']=='558705210e59a1226ef060c4fd6d0359a1fa24c8594c8191f96af84288ac91bd'
    assert checker.PROFILE==PROFILE and checker.catalog()==catalog()
    a.raw.mkdir(mode=0o700); (a.raw/'tmp').mkdir()
    run=recipe.Run(a,a.raw,tools,env,sources,modules,started,tool_pins); run.deadline=started+1200
    run.build_scratch=(a.raw/'tmp',)
    run.result.update(kind='call-pair-original-native-release-v1',scope=SCOPE,originals=[],installed=[],controls=[],prerequisites={},
        cohort=initial_cohort(),cpu_roles=dict(supervisor_build_controls=run.cpus,native_parent_and_tracees=run.cpus[1]),
        planned_stages=[dict(name=n,status='UNRUN') for n in STAGES])
    def stage(*args,**kwargs):
        tool_alias(tools,env); result=run.stage(*args,**kwargs); tool_alias(tools,env); return result
    try:
        run.result['sources_before']=run.freeze(a.raw/'sources-before.json',sources,cap=16*MIB)
        run.freeze(a.raw/'initial-plan.json',dict(revision=a.revision,stages=STAGES,catalog=catalog(),profile=PROFILE,
            attempts=1,retries=0,pairs=192,children=384,target_calls=768,target_returns=768,outer_returns=384,normal_reaps=384,
            pair_seconds=15,walk_steps=20000,native_cpu_seconds=480,native_wall_seconds=510,native_file_bytes=MIB,
            outer_seconds=1200,outer_log_bytes=8*MIB,reservation_tag=a.reservation_tag,affinity=run.cpus,
            reservation_authority='external hard owner only',scope=SCOPE))
        for name in ('cc1','collect2','as','ld'):
            out,err=stage('tool-'+name,[tools['gcc'],'-print-prog-name='+name]); assert err==b'' and out.endswith(b'\n') and out.count(b'\n')==1
            reported=out[:-1].decode('utf-8'); p=Path(reported) if '/' in reported else Path(shutil.which(reported,path=env['PATH']) or '')
            assert p.is_absolute(); p=p.resolve(strict=True); value=recipe.pin(recipe.read(p,512*MIB))
            if str(p) in run.tool_pins: assert run.tool_pins[str(p)]==value
            else: run.tool_pins[str(p)]=value
        run.result['tools']=run.freeze(a.raw/'tools.json',run.tool_pins)
        trusted=a.raw/'module-trusted.so'; candidate=a.raw/'module-candidate.so'
        out,err=stage('module-build',[tools['gcc'],*native.MODULE_FLAGS,ROOT/'tools/rapid-profiler/normal-work/call_pair.c','-o',trusted],generated=((trusted,MIB),))
        assert out==err==b''; leaf.copy_artifact(run,recipe,trusted,candidate)
        symbols,err=stage('module-symbols',[tools['readelf'],'--wide','--syms',trusted]); assert err==b''
        pv,pl=native.selection(symbols,'csv_summary',80); cv,cl=native.selection(symbols,'csv_fields',256)
        out,err=stage('parent-disassembly',[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble=csv_summary',trusted]); assert err==b''
        parent=parent_geometry(native.geometry(out,'csv_summary',pv,pl),pv,pl,cv)
        out,err=stage('child-disassembly',[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble=csv_fields',trusted]); assert err==b''
        child=dict(native.body_geometry(native.geometry(out,'csv_fields',cv,cl),cv,cl),elf_va=cv)
        cargo=['--locked','--offline','--release','--jobs','4','-p','rapid-profiler','--message-format=json-render-diagnostics']
        out,_=stage('application-build',[tools['cargo'],'build','--bin','ordinary-interval',*cargo],120,180,128*MIB)
        application,product=native.artifact(out,'ordinary-interval','ordinary-interval/main.rs','bin',False); run.remember(application)
        run.freeze(a.raw/'application-artifact.json',dict(product=product,binary=run.retained[str(application)]))
        app_trusted=a.raw/'application-trusted'; app_candidate=a.raw/'application-candidate'
        for p in (app_trusted,app_candidate): leaf.copy_artifact(run,recipe,application,p)
        app_candidate.chmod(0o700); assert app_candidate.stat().st_mode & 0o777 == 0o700
        assert len({(p.stat().st_dev,p.stat().st_ino) for p in (application,app_trusted,app_candidate)})==3
        out,err=stage('application-caller-disassembly',[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble=liteinst_csv_call_and_store',app_trusted]); assert err==b''
        shape=modules['csv'].caller_geometry(out.decode('ascii'))
        symbols,err=stage('application-caller-symbols',recipe.caller_symbol_command(tools,app_trusted)); assert err==b''
        modules['module'].caller_symbols(symbols.decode('ascii'),shape)
        decoded=native.geometry(out,'liteinst_csv_call_and_store',shape['elf_va'],shape['length'])
        caller=caller_parser.geometry(decoded,shape['elf_va'],shape['length'])
        extra=stack_geometry(decoded,shape['elf_va'],shape['length'],256)
        assert extra['delta']==caller['subject_rsp_delta'] and extra['call_offset']==caller['call_offset'] and extra['continuation_offset']==caller['continuation_offset']==shape['continuation_offset']
        caller['lowest_stack']=extra['lowest_stack']; checker.geometry(parent,child,caller)
        run.result['geometry']=run.freeze(a.raw/'geometry.json',dict(parent=parent,child=child,caller=caller))
        bins={}
        for label,target,source,kind,flags in [('state','frontend-native-calibrations','native-interval/calibrations.rs','test',['test','--test','frontend-native-calibrations','--no-run']),('ordinary','ordinary-interval','ordinary-interval/main.rs','bin',['test','--bin','ordinary-interval','--no-run'])]:
            out,_=stage(label+'-build',[tools['cargo'],*flags,*cargo],120,180,128*MIB)
            binary,product=native.artifact(out,target,source,kind,True); run.remember(binary); bins[label]=binary
            run.freeze(a.raw/(label+'-artifact.json'),dict(product=product,binary=run.retained[str(binary)]))
        out,_=stage('sdk-build',[tools['cargo'],'test','--lib','--no-run',*cargo],120,180,128*MIB)
        bins['sdk'],product=library.library_artifact(out); run.remember(bins['sdk']); run.freeze(a.raw/'sdk-artifact.json',dict(product=product,binary=run.retained[str(bins['sdk'])]))
        out,_=stage('core-build',[tools['cargo'],'test','--lib','--no-run','--locked','--offline','--release','--jobs','4','-p','liteinst2','--message-format=json-render-diagnostics'],120,180,128*MIB)
        bins['core'],product=core_product(out); assert bins['core'].resolve(strict=True)==bins['core']; run.remember(bins['core'])
        run.freeze(a.raw/'core-artifact.json',dict(product=product,binary=run.retained[str(bins['core'])]))
        peers={key:recipe.load('pair_'+key,ROOT/native.MODULES[key]) for key in ('legacy','normal','whole')}
        prior=native.calibration_manifest(peers['legacy'],peers['normal'],peers['whole'])
        out,err=stage('state-list',[bins['state'],'--list']); inventory=modules['census'].census(out,err)
        manifest=calibration_inventory(leaf,prior,inventory,native.IGNORED)
        run.freeze(a.raw/'controls.json',dict(calibrations=manifest,ignored={native.IGNORED:native.IGNORE_REASON},ordinary=ORDINARY_CONTROLS,sdk=SDK_CONTROLS,core=CORE_CONTROLS,
            old_python=[native.PYTHON_CONTROLS,recipe.PYTHON_CONTROLS,copied.PYTHON_CONTROLS,copied.RUNNER_CONTROLS,leaf.LEAF_CONTROLS,leaf.EFFICIENCY_RUNNER_CONTROLS],checker=PYTHON_CONTROLS,runner=RUNNER_CONTROLS))
        out,err=stage('state-controls',[bins['state'],'--test-threads=1']); native.calibration_output(out,err,manifest)
        groups=[('ordinary',ORDINARY_CONTROLS,[('ordinary-oracle-controls','oracle::native_ordinary::normal_caller::call_pair::'),('ordinary-check-controls','normal::call_pair_state::check::tests::'),('ordinary-owner-controls','normal::call_pair_state::caller::tests::')]),
            ('sdk',SDK_CONTROLS,[('frontend-controls','frontend_native::module::ordinary::call_pair::tests::'),('site-controls','frontend_native::always_on::site::ordinary::call_pair::tests::'),('runtime-controls','frontend_native::always_on::normal::call_pair::tests::')]),
            ('core',CORE_CONTROLS,[('stack-profile-controls','trampoline::stack_profile_tests::'),('stack-trace-controls','frame_trace::tests::call_pair_stack::')])]
        for target,wanted,subgroups in groups:
            out,err=stage(target+'-list',[bins[target],'--list']); inventory=modules['census'].census(out,err); selected_inventory(inventory,wanted)
            for name,prefix in subgroups:
                names=[n for n in wanted if n.startswith(prefix)]; assert names
                out,err=stage(name,[bins[target],prefix,'--test-threads=1']); modules['census'].controls(out,err,names,inventory)
        python=[('legacy-python-controls','evaluation/ordinary-module-native/controls.py',native.PYTHON_CONTROLS),('session-python-controls','evaluation/ordinary-module-session/controls.py',recipe.PYTHON_CONTROLS),('copied-python-controls','evaluation/ordinary-rust-invoke-native/controls.py',copied.PYTHON_CONTROLS),('copied-runner-controls','evaluation/ordinary-rust-invoke-native/runner_controls.py',copied.RUNNER_CONTROLS),('leaf-python-controls','evaluation/ordinary-leaf-set-native/controls.py',leaf.LEAF_CONTROLS),('leaf-runner-controls','evaluation/ordinary-leaf-set-native/runner_controls.py',leaf.EFFICIENCY_RUNNER_CONTROLS),('python-controls','evaluation/ordinary-call-pair-native/controls.py',PYTHON_CONTROLS),('runner-controls','evaluation/ordinary-call-pair-native/runner_controls.py',RUNNER_CONTROLS)]
        assert [len(n) for _,_,n in python]==[18,26,10,4,10,8,16,8]
        for name,path,names in python:
            out,err=stage(name,[tools['python'],'-B',ROOT/path,'-v'])
            if name=='legacy-python-controls': native.python_output(out,err)
            elif name=='session-python-controls': recipe.python_controls(out,err)
            else: copied.python_controls(out,err,names)
        cohort=a.raw/'native'; cohort.mkdir()
        argv=list(map(str,[app_candidate,'normal-call-pair-state',candidate,trusted,pv,pl,cv,cl,app_candidate,app_trusted,cohort/'output',run.cpus[1]]))
        request=dict(argv=argv,cwd=str(ROOT),env=env,stdout=str(cohort/'stdout.txt'),stderr=str(cohort/'stderr.txt'),cpu=run.cpus[1],pins=run.sources|run.tool_pins|run.retained)
        request_shape(request,run.cpus); value=run.freeze(cohort/'request.json',request)
        execute_cohort(run,recipe,copied,leaf,request,value,checker,parent,child,caller)
        assert tuple(r['name'] for r in run.result['stages'])==STAGES
        run.result['sources_after']=run.freeze(a.raw/'sources-after.json',sources,cap=16*MIB); tool_alias(tools,env)
        run.result['status']='CALL_PAIR_ORIGINAL_NATIVE_LOCAL_COMPLETE'
    except BaseException as error:
        run.result.update(error=type(error).__name__,traceback=traceback.format_exc())
    finally:
        run.budget.stopped()
        run.result.update(end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),load_after=list(os.getloadavg()),custody_closed=run.safe,
            retained=dict(run.retained),tool_pins=dict(run.tool_pins),evidence_budget=run.budget.summary(),build_space_exclusions=[str(p) for p in run.build_scratch])
        seen={r['name']:r for r in run.result['stages']}; run.result['planned_stages']=[seen.get(n,dict(name=n,status='UNRUN')) for n in STAGES]
        try:
            assert run.safe and not run.budget.exceeded
            run.closed_inventory(a.raw); assert run.budget.used<=recipe.EVIDENCE_LIMIT-recipe.FINAL_ALLOWANCE
            run.unchanged(); tool_alias(tools,env); run.result['retention_verified']=True
        except BaseException as error: run.result.update(status='FAILED',retention_verified=False,final_error=type(error).__name__)
        try:
            run.result['public_projection']=run.freeze(a.raw/'public-result.json',public_projection(run.result),cap=16*MIB)
            if run.safe: run.unchanged(); tool_alias(tools,env)
        except BaseException as error: run.result.update(status='FAILED',retention_verified=False,projection_error=type(error).__name__)
        run.result.update(retained=dict(run.retained),evidence_budget=run.budget.summary()); recipe.save(a.raw/'result.json',run.result,16*MIB)
    print(json.dumps(dict(status=run.result['status'],profile=PROFILE,cohort_status=run.result['cohort']['status'],attempts=run.result['cohort']['attempts'],observed_rows=len(run.result['cohort']['observed']),custody_closed=run.safe,external_owner_required=True,scope=SCOPE)))
    return 0 if run.result['status']=='CALL_PAIR_ORIGINAL_NATIVE_LOCAL_COMPLETE' else 1


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--native-request':
        try: native_exec(Path(sys.argv[2]),sys.argv[3])
        except BaseException as error:
            print('CallPair native exec FAILED: '+type(error).__name__,file=sys.stderr,flush=True); raise SystemExit(127)
    raise SystemExit(main())
