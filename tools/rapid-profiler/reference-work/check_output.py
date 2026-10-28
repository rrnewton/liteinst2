"""Finite reference-clock projections; no calibration or timing accuracy verdict."""
import csv
import re

PAIR_HEADER = 'seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,reader_checks,timestamp_joins,returned_records,value'
PAIR_PASS = ('native-exact-reference:required=4:pairs=4:children=8:comparisons=872:'
    'reader-checks=16:timestamp-joins=16:returned-records=8:truth-instructions=800:'
    'conditional=130:taken=126:input-reads=130:return-reads=4:subject-ret=8:real-outer-ret=8:complete\n')
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
SCOPE = '# uncalibrated real-CALL enclosures and hook endpoints; fixed-assembly work model, no timing-accuracy, frequency-conversion or performance claim'
HEADER = 'leg,external_id,gate_sequence,ordinal,length,owner,generation,invocation,instructions,branches,taken_branches,input_byte_reads,return_read_bytes,value,reference_start_ticks,reference_end_ticks,reference_start_aux,reference_end_aux,raw_start_ticks,raw_end_ticks,raw_start_aux,raw_end_aux,enclosure_ticks,raw_ticks,entry_gap_ticks,return_gap_ticks'
PASS = ('exact-reference FUNCTIONAL_PASS originals=24 installed=24 raw_rows=24 sampled=24 unsampled=0 report_records=24 '
    'original_instructions=4800 installed_instructions=4800 same_thread=true detached=true input_unchanged=true uncalibrated=true')
ORIGINAL_EMPTY = frozenset(('ordinal', 'generation', 'invocation', 'raw_start_ticks', 'raw_end_ticks', 'raw_start_aux', 'raw_end_aux', 'raw_ticks', 'entry_gap_ticks', 'return_gap_ticks'))


# Exact transitive frontend-native-calibrations inventory, including expected panics.
CALIBRATION_TESTS = {
    'oracle::native_ordinary::hardware::tests::hardware_event_requires_exact_owned_trap': False,
    'oracle::native_ordinary::hardware::tests::hardware_initial_owner_and_offsets_are_closed': False,
    'oracle::native_ordinary::hardware::tests::hardware_peek_preserves_valid_minus_one': False,
    'oracle::native_ordinary::hardware::tests::hardware_harness_only_removes_authenticated_rf': False,
    'oracle::native_ordinary::hardware::tests::hardware_partial_install_and_restore_keep_custody': False,
    'oracle::native_ordinary::hardware::tests::hardware_readback_and_exact_restoration': False,
    'oracle::native_ordinary::hardware::tests::hardware_cleanup_does_not_touch_running_or_terminal_child': False,
    'oracle::native_ordinary::hardware::tests::hardware_targets_authenticate_closed_tree_and_literal_bytes': False,
    'oracle::native_ordinary::native_call::tests::literal_native_profile_has_no_transient_exclusions_or_legacy_alias': False,
    'oracle::native_ordinary::native_call::tests::actual_target_input_length_and_alignment_are_required': False,
    'oracle::native_ordinary::native_call::tests::every_callee_save_must_restore_before_harness': False,
    'oracle::native_ordinary::native_call::tests::outer_call_requires_exact_instruction_target_stack_successor_and_saved_word': False,
    'oracle::native_ordinary::native_call::tests::callback_order_count_and_stack_geometry_are_exact': False,
    'oracle::native_ordinary::native_call::tests::wrapper_semantics_compare_all_unaffected_state_and_complete_stack': False,

    'oracle::native_ordinary::call_tree::refusal::tests::tree_refusal_injection_changes_only_the_authenticated_word': False,
    'oracle::native_ordinary::call_tree::refusal::tests::tree_refusal_requires_normal_exact_exit123': False,
    'oracle::native_ordinary::call_tree::refusal::tests::tree_refusal_rejects_application_or_gate_resumption': False,
    'oracle::native_ordinary::cache::model::tests::cache_model_foreign_cross_line_width_and_wrap_refused': False,
    'oracle::native_ordinary::cache::model::tests::cache_model_literal_case_totals_and_set_rotation': False,
    'oracle::native_ordinary::cache::model::tests::cache_model_literal_lru_policy_discriminator': False,
    'oracle::native_ordinary::cache::model::tests::cache_model_literal_per_operand_miss_positions': False,
    'oracle::native_ordinary::cache::model::tests::cache_model_missing_duplicate_reordered_or_relabelled_reads_refused': False,
    'oracle::native_ordinary::cache::model::tests::cache_model_ret_uses_full_address_and_each_call_starts_invalid': False,
    'oracle::native_ordinary::cache::tests::cache_actual_dec_jnz_requires_counter_zf_and_successor': False,
    'oracle::native_ordinary::cache::tests::cache_actual_qword_reads_require_address_width_and_all_bytes': False,
    'oracle::native_ordinary::cache::tests::cache_actual_ret_requires_full_word_and_physical_successor': False,
    'oracle::native_ordinary::cache::tests::cache_complete_visit_sequence_refuses_omission_insertion_and_reorder': False,
    'oracle::native_ordinary::cache::truth::tests::cache_all_cases_join_independent_cycles_scalar_counts_and_ret': False,
    'oracle::native_ordinary::cache::truth::tests::cache_every_changed_opcode_bit_is_refused': False,
    'oracle::native_ordinary::cache::truth::tests::cache_invalid_header_links_extent_and_wrap_are_refused': False,
    'oracle::native_ordinary::cache::truth::tests::cache_literal_fixture_and_first_iteration': False,
    'oracle::native_ordinary::cache::truth::tests::cache_valid_link_or_payload_mutation_cannot_relabel_the_case': False,
    'oracle::calibration::rejects_application_memory_corruption': True,
    'oracle::calibration::rejects_defined_flag_corruption': True,
    'oracle::calibration::rejects_fault_address_corruption': True,
    'oracle::calibration::rejects_gpr_corruption': True,
    'oracle::calibration::rejects_redzone_corruption': True,
    'oracle::calibration::rejects_simd_corruption': True,
    'oracle::campaign_initialization_calibration::campaign_initializer_keeps_default_memory_and_flags_exact': False,
    'oracle::campaign_initialization_calibration::campaign_initializer_matches_independent_memory_vectors_and_flags': False,
    'oracle::native_ordinary::optional_frontend::tests::optional_frontend_complete_frame_phase_and_owner_refuse': False,
    'oracle::native_ordinary::optional_frontend::tests::optional_frontend_gate_bytes_offsets_and_extent_refuse': False,
    'oracle::native_ordinary::optional_frontend::tests::optional_frontend_observer_omission_extra_and_order_refuse': False,
    'oracle::native_ordinary::optional_frontend::tests::optional_frontend_ready_full_mapping_and_observer_identity_refuse': False,
    'oracle::native_ordinary::reference::tests::reference_cell_cannot_alias_frame_data_stack_or_executable_ranges': False,
    'oracle::native_ordinary::reference::tests::reference_complete_cell_identity_spills_and_canary_are_material': False,
    'oracle::native_ordinary::reference::tests::reference_layout_requires_every_byte_and_actual_label': False,
    'oracle::native_ordinary::reference::tests::reference_profile_and_complete_ret_inventory_refuse_substitution': False,
    'oracle::native_ordinary::reference::tests::reference_reader_transparency_keeps_full_state_and_physical_pcs': False,
    'oracle::native_ordinary::reference::tests::reference_result_requires_both_restorations_real_rax_and_leg': False,
    'oracle::native_ordinary::reference::tests::reference_result_wire_rejects_clock_geometry_missing_duplicate_and_tail': False,
    'oracle::native_ordinary::reference::tests::reference_stores_require_actual_unique_rdtscp_outputs': False,
    'oracle::native_ordinary::tests::ordinary_actual_frame_data_and_tls_mismatch_refuse': False,
    'oracle::native_ordinary::tests::ordinary_full_data_and_redzone_comparator_refuses': False,
    'oracle::native_ordinary::tests::ordinary_gate_and_ready_identity_refuse': False,
    'oracle::native_ordinary::tests::ordinary_harness_resume_only_removes_debugger_tf': False,
    'oracle::native_ordinary::tests::ordinary_map_missing_and_duplicate_ret_refuse': False,
    'oracle::ordered_trace::boundary_signal::calibration::rejects_duplicate_roundtrip': True,
    'oracle::ordered_trace::boundary_signal::calibration::rejects_missing_terminal_roundtrip': True,
    'oracle::ordered_trace::boundary_signal::calibration::rejects_uncompleted_roundtrip': True,
    'oracle::ordered_trace::boundary_signal::calibration::rejects_wrong_logical_pc': True,
    'oracle::ordered_trace::boundary_signal::calibration::rejects_wrong_physical_pc': True,
    'oracle::ordered_trace::boundary_signal::calibration::repeated_boundaries_keep_order_and_physical_identity': False,
    'oracle::ordered_trace::parked_signal::calibration::rejects_extra_source_write': True,
    'oracle::ordered_trace::parked_signal::calibration::rejects_failed_publication_status': True,
    'oracle::ordered_trace::parked_signal::calibration::rejects_frame_mutation': True,
    'oracle::ordered_trace::parked_signal::calibration::rejects_old_source_after_publication': True,
    'oracle::ordered_trace::parked_signal::calibration::rejects_wrong_receipt_identity': True,
    'oracle::ordered_trace::word_sync::word_calibration::accepts_exact_child_publication_record': False,
    'oracle::ordered_trace::word_sync::word_calibration::rejects_failed_publication_status': True,
    'oracle::ordered_trace::word_sync::word_calibration::rejects_missing_synchronization': True,
    'oracle::ordered_trace::word_sync::word_calibration::rejects_trailing_receipt_field': True,
    'oracle::ordered_trace::word_sync::word_calibration::rejects_wrong_bound_patch_identity': True,
    'oracle::ordered_trace::word_sync::word_calibration::rejects_wrong_child_process': True,
    'oracle::ordered_trace::word_sync::word_calibration::rejects_wrong_transition_direction': True,
    'oracle::native_ordinary::call_tree::model::tests::tree_model_every_foreign_address_width_and_geometry_refuses': False,
    'oracle::native_ordinary::call_tree::model::tests::tree_model_lru_and_dirty_state_kernel_controls': False,
    'oracle::native_ordinary::call_tree::model::tests::tree_model_missing_reordered_wrong_function_and_kind_refuse': False,
    'oracle::native_ordinary::call_tree::model::tests::tree_model_no_write_allocate_and_child_reset_are_observable': False,
    'oracle::native_ordinary::call_tree::model::tests::tree_model_one_cache_exact_literal_vectors_and_attribution': False,
    'oracle::native_ordinary::call_tree::tests::tree_native_actual_payload_link_and_dec_flags_are_authenticated': False,
    'oracle::native_ordinary::call_tree::tests::tree_native_actual_transfer_bytes_pc_rsp_and_saved_word': False,
    'oracle::native_ordinary::call_tree::tests::tree_native_call_store_preserves_every_other_protected_byte': False,
    'oracle::native_ordinary::call_tree::tests::tree_native_closed_source_gap_heads_returns_and_call_map': False,
    'oracle::native_ordinary::call_tree::tests::tree_native_complete_shape_refuses_missing_extra_reordered_and_node': False,
    'oracle::native_ordinary::call_tree::tests::tree_native_pending_frame_rejects_idle_leaf_phase_and_each_word': False,
    'oracle::native_ordinary::call_tree::tests::tree_native_transfer_population_order_and_original_call_pc': False,
    'oracle::native_ordinary::call_tree::truth::tests::tree_truth_boundaries_and_non64_count_refuse': False,
    'oracle::native_ordinary::call_tree::truth::tests::tree_truth_every_opcode_bit_refuses_and_case_cannot_be_relabelled': False,
    'oracle::native_ordinary::call_tree::truth::tests::tree_truth_real_call_two_returns_and_nested_order': False,
}


def number(word):
    assert isinstance(word, str) and re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word)
    assert value < 2**64
    return value


def table(data, header, count):
    assert 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').split('\n')[:-1]
    assert len(lines) == count + 1 and lines[0] == header
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == count
    assert all(set(row) == set(header.split(',')) and all(isinstance(v, str) for v in row.values()) for row in rows)
    return rows


def pairs(data, terminal, stderr):
    assert stderr == b'' and terminal == PAIR_PASS.encode('ascii')
    rows = table(data, PAIR_HEADER, 4)
    for row, (seed, n) in zip(rows, [(seed, n) for seed in SEEDS for n in (1, 64)]):
        assert row['status'] == 'PASS'
        for key in set(row) - {'status'}:
            row[key] = number(row[key])
        assert (row['seed'], row['length'], row['children']) == (seed, n, 2)
        assert row['original_visits'] == 6*n + 5
        # Eighteen restored wrapper instruction heads are fixed by the separate
        # literal stencil. Reader transparency is counted independently below.
        assert row['comparisons'] == row['original_visits'] + 18
        assert row['comparisons'] <= min(row['original_steps'], row['candidate_steps'])
        assert max(row['original_steps'], row['candidate_steps']) <= 20000
        assert (row['reader_checks'], row['timestamp_joins'], row['returned_records']) == (4, 4, 2)
        expected = sum(((((128+j)*37+11+seed) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15
        assert row['value'] == expected
    assert sum(row['comparisons'] for row in rows) == 872
    return rows


# This newly added native prerequisite runs only in its own bounded process.
# None of the 82 inherited controls is ignored; eight new pure controls are added.
HARDWARE_IGNORED = ('test oracle::native_ordinary::hardware::control::'
    'owned_execution_breakpoint_restores_then_steps_then_stops ... ignored, '
    'requires explicit fresh-process release hardware-stop prerequisite')


def calibrations(stdout, stderr):
    assert stderr == b'' and 0 < len(stdout) <= 1048576
    text = stdout.decode('ascii')
    pattern = (r'\nrunning 91 tests\n((?:test [^\n]+\n){91})\n'
        r'test result: ok\. 90 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in [0-9]+\.[0-9]+s\n\n')
    match = re.fullmatch(pattern, text)
    assert match is not None
    lines = match.group(1).splitlines()
    assert lines.count(HARDWARE_IGNORED) == 1
    lines.remove(HARDWARE_IGNORED)
    assert all(re.fullmatch(r'test [A-Za-z0-9_:]+(?: - should panic)? \.\.\. ok', line) for line in lines)
    names = [line.split()[1] for line in lines]
    assert len(names) == len(set(names)) == 90
    observed = {line.split()[1]: ' - should panic ... ok' in line for line in lines}
    assert observed == CALIBRATION_TESTS


def functional(data, stderr):
    assert stderr == b'' and 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').split('\n')[:-1]
    assert len(lines) == 51 and lines[0] == SCOPE and lines[-1] == PASS
    csv_bytes = ('\n'.join(lines[1:-1])+'\n').encode('ascii')
    rows = table(csv_bytes, HEADER, 48)
    first_sequence = generation = aux = last_end = None
    for position, row in enumerate(rows):
        original = position < 24
        index = position % 24
        n = 1 if index % 2 == 0 else 64
        assert row['leg'] == ('original' if original else 'installed')
        assert row['owner'] == ('original' if original else 'sampled')
        empty = ORIGINAL_EMPTY if original else frozenset()
        assert all(row[key] == '' for key in empty)
        for key in set(row) - empty - {'leg', 'owner'}:
            row[key] = number(row[key])
        assert (row['external_id'], row['length']) == (0x72656600+index, n)
        assert (row['instructions'], row['branches'], row['taken_branches'], row['input_byte_reads'], row['return_read_bytes']) == (6*n+5, n, n-1, n, 8)
        expected = sum((((j*37+11) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15
        assert row['value'] == expected
        if position == 0:
            first_sequence, aux = row['gate_sequence'], row['reference_start_aux']
            assert 0 < first_sequence <= 2**64-48 and aux < 2**32
        assert row['gate_sequence'] == first_sequence+position
        assert row['reference_start_aux'] == row['reference_end_aux'] == aux
        start, end = row['reference_start_ticks'], row['reference_end_ticks']
        assert start <= end and row['enclosure_ticks'] == end-start
        assert last_end is None or start >= last_end
        last_end = end
        if not original:
            if index == 0:
                generation = row['generation']
                assert generation > 0
            assert (row['ordinal'], row['generation'], row['invocation']) == (index+1, generation, index)
            assert row['raw_start_aux'] == row['raw_end_aux'] == aux
            raw_start, raw_end = row['raw_start_ticks'], row['raw_end_ticks']
            assert start <= raw_start <= raw_end <= end
            assert row['raw_ticks'] == raw_end-raw_start
            assert row['entry_gap_ticks'] == raw_start-start
            assert row['return_gap_ticks'] == end-raw_end
            assert row['enclosure_ticks'] == row['entry_gap_ticks']+row['raw_ticks']+row['return_gap_ticks']
    assert sum(row['instructions'] for row in rows[:24]) == sum(row['instructions'] for row in rows[24:]) == 4800
    return rows, csv_bytes
