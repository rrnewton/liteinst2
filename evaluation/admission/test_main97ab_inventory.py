"""Exact native indexed-DSO successor; historical assertions remain in their original domains."""
import copy
import inventory_copy
import hashlib
import json
import re
from pathlib import Path
import unittest
from unittest.mock import patch

import core_97ab_inventory as current
import core_f353_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
from test_parsing import counts, summary


def cargo_mutation(test, observed, before, after):
    """Carry an existing Cargo declaration deletion through both exact new joins."""
    path = 'Cargo.toml'
    test.assertEqual(after, '')
    shared = current.source_before_3217b8ed(path, observed, 'cargo_mutation_baseline')
    native = current.source_before(path, observed, 'cargo_mutation_baseline')
    literal = before
    if before.startswith('[workspace]\nmembers = '):
        test.assertTrue(before.endswith('"crates/liteinst-inprocess"]'))
        literal = before[:-1] + ', "crates/liteinst-x86"]'
    test.assertEqual((observed.count(literal.encode()), shared.count(before.encode()),
                      native.count(before.encode())), (1, 1, 1))

    def transport(source, prior, source_literal, prior_literal, original):
        test.assertEqual(hashlib.sha256(source).hexdigest(), original['current_sha256'])
        test.assertEqual(hashlib.sha256(prior).hexdigest(), original['previous_sha256'])
        at = source.index(source_literal.encode()); stop = at + len(source_literal.encode())
        prior_at = prior.index(prior_literal.encode()); prior_stop = prior_at + len(prior_literal.encode())
        changed = source[:at] + source[stop:]
        changed_prior = prior[:prior_at] + prior[prior_stop:]
        test.assertNotEqual(changed, source)
        test.assertNotEqual(changed_prior, prior)
        def shifted(offset):
            return offset if offset <= at else offset - (stop-at) if offset >= stop else at
        edits = []; shift = 0
        for first, end, donor in original['edits']:
            data = donor.encode(); donor_at = first + shift
            begin = max(0, prior_at-donor_at); finish = min(len(data), prior_stop-donor_at)
            if begin < finish:
                data = data[:begin] + data[finish:]
            edits.append([shifted(first), shifted(end), data.decode()])
            shift += len(donor.encode()) - (end-first)
        row = copy.deepcopy(original)
        row.update(current_sha256=hashlib.sha256(changed).hexdigest(),
                   previous_sha256=hashlib.sha256(changed_prior).hexdigest(), edits=edits)
        test.assertEqual(current.inverse(path, changed, {path: row}, 'cargo_mutation_inverse'), changed_prior)
        return changed, changed_prior, row

    observed_wrong, shared_wrong, shared_row = transport(observed, shared, literal, before,
        current.DATA['source_successor_3217b8ed']['source_projections'][path])
    native_input, native_wrong, native_row = transport(shared, native, before, before,
        current.DATA['projections'][path])
    test.assertEqual(native_input, shared_wrong)
    with patch.dict(current.DATA['source_successor_3217b8ed']['source_projections'], {path: shared_row}), \
         patch.dict(current.DATA['projections'], {path: native_row}):
        test.assertEqual(current.source_before(path, observed_wrong, 'cargo_mutation_complete_join'), native_wrong)
    return dict(observed=observed_wrong, shared=shared_wrong, native=native_wrong,
                shared_row=shared_row, native_row=native_row)


def outer_declaration_mutation(test, path, observed, before, after):
    """Carry the same old stimulus through the two new, exact outer joins."""
    names = ('426ea6a', '0073fb6', 'f9c5982', '2294097', '9528851', '11cc419', '281c342', '064b48c', '79a4b8b', '3217b8ed')
    rows = {name: {} for name in names}
    baseline = current.source_before_65ee8ea(path, observed, 'declaration_outer_baseline')
    if path == 'Cargo.toml':
        cargo = cargo_mutation(test, observed, before, after)
        test.assertEqual(baseline.replace(before.encode(), after.encode()), cargo['shared'])
        rows['3217b8ed'][path] = cargo['shared_row']
        return dict(observed=cargo['observed'], baseline=baseline, changed=cargo['shared'],
                    rows=rows, native_row=cargo['native_row'], native=cargo['native'])
    changed_observed = observed.replace(before.encode(), after.encode())
    source = observed
    for name in names:
        table = current.DATA['source_successor_' + name]['source_projections']
        if path not in table:
            continue
        prior = current.inverse(path, source, table, 'declaration_outer_baseline')
        test.assertEqual((source.count(before.encode()), prior.count(before.encode())), (1, 1))
        at = source.index(before.encode()); stop = at + len(before.encode())
        delta = len(after.encode()) - len(before.encode())
        row = copy.deepcopy(table[path])
        for edit in row['edits']:
            test.assertTrue(edit[1] <= at or edit[0] >= stop)
            if edit[0] >= stop:
                edit[0] += delta; edit[1] += delta
        changed = source.replace(before.encode(), after.encode())
        changed_prior = prior.replace(before.encode(), after.encode())
        row.update(current_sha256=hashlib.sha256(changed).hexdigest(),
                   previous_sha256=hashlib.sha256(changed_prior).hexdigest())
        test.assertEqual(current.inverse(path, changed, {path: row},
                         'declaration_outer_mutated_inverse'), changed_prior)
        rows[name][path] = row
        source = prior
    # No unmodelled intermediate projection may be bypassed.
    test.assertEqual(source, baseline)
    return dict(observed=changed_observed, baseline=baseline,
                changed=source.replace(before.encode(), after.encode()), rows=rows)


class Main97abInventoryTests(unittest.TestCase):
    def test_exact_native_indexed_sources_and_historical_refusals(self):
        actual = json.loads(Path(__file__).with_name('corpus.json').read_bytes())
        # Nineteen physical-window methods extend three existing default harnesses.
        physical_window = current.DATA['source_successor_426ea6a']
        physical_window_prior = current.before_426ea6a(actual)
        physical_window_rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(physical_window_prior), current.PHYSICAL_WINDOW_PREVIOUS)
        self.assertEqual((len(physical_window_rows), sum(x['tests'] for x in physical_window_rows.values()),
                          sum(x['ignored'] for x in physical_window_rows.values())), (122, 4790, 43))
        self.assertEqual((physical_window['default_method_additions'], physical_window['new_method_declarations'],
                          physical_window['default_method_removals'], physical_window['default_harness_changes'],
                          physical_window['default_ignore_changes'], physical_window['default_doctest_additions'],
                          physical_window['recorder_identity_changes'], physical_window['feature_method_additions'],
                          physical_window['feature_method_removals']), (19, 19, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(physical_window['added_default_methods'], {'src/entry_router/imp/physical_window_native_tests.rs': ['physical_min5_every_entry_routes_through_production', 'physical_min5_ret_fault_preserves_prior_pop_and_callbacks', 'physical_min5_non06_pop_fault_preserves_uncommitted_state'], 'src/quiescent/artifact_window/physical/tests.rs': ['earlier_physical_head_recovers_short_span_with_actual_alphabet_image_and_all_routes', 'refused_call_suffix_is_custodied_and_qualified_once_without_retained_authority', 'cap_start_fifteen_byte_dependency_keeps_one_sixty_four_of_sixty_five_run', 'owned_schedule_binds_source_policy_population_and_domain_without_borrowed_authority', 'reached_row_mismatch_aborts_instead_of_skipping_or_double_counting', 'fixed06_same_extent_preserves_complete_existing_plan_and_failure_results', 'fresh_overlay_entry_pending_and_image_errors_keep_shared_order_and_atomicity', 'immutable_global_guards_and_collector_early_breaks_keep_exact_dependencies'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_physical_tests.rs': ['physical_cli_keeps_old_selectors_and_exact_storage_arity', 'physical_cli_full_population_and_repinned_policy_keep_portable_binding'], 'tools/elf-rewrite/src/grouped_artifact_frontend/physical/tests.rs': ['physical_min5_refused_same_site_keeps_earlier_minimum_and_actual_ordinal', 'physical_min5_refused_suffix_immediate_is_still_a_source_dependency', 'physical_min5_complete_manifest_rejects_consumed_and_straddling_foreign_members', 'physical_min5_serializes_first_sixty_four_rows_without_losing_omitted_prefix_membership', 'physical_min5_policy_refusal_has_no_invented_domain_and_atomic_failure_keeps_all_sites', 'physical_min5_storage_is_independent_and_carrier_refusal_cannot_promote_a_plan']})
        self.assertEqual(physical_window['default_method_instances'], {'src/entry_router/imp/physical_window_native_tests.rs': ['unit/liteinst2/lib'], 'src/quiescent/artifact_window/physical/tests.rs': ['unit/liteinst2/lib'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_physical_tests.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/src/grouped_artifact_frontend/physical/tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((physical_window['added_feature_methods'], physical_window['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(physical_window['source_paths']), len(physical_window['source_projections'])), (20, 20))
        self.assertEqual(physical_window['new_sources'], ['evaluation/direct-program/physical-window-result/README.md', 'evaluation/direct-program/physical-window-result/cases.csv', 'evaluation/direct-program/physical-window-result/receipt.json', 'evaluation/direct-program/test_grouped_physical_linkage.py', 'evaluation/direct-program/validate_physical_window.py', 'src/entry_router/imp/physical_window_native_tests.rs', 'src/quiescent/artifact_window/physical.rs', 'src/quiescent/artifact_window/physical/tests.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_physical_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/physical.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/physical/tests.rs'])
        self.assertEqual(physical_window['newly_bound_sources'], ['evaluation/direct-program/physical-window-result/README.md', 'evaluation/direct-program/physical-window-result/cases.csv', 'evaluation/direct-program/physical-window-result/receipt.json', 'evaluation/direct-program/test_grouped_physical_linkage.py', 'evaluation/direct-program/validate_physical_window.py', 'src/entry_router/imp/physical_window_native_tests.rs', 'src/quiescent/artifact_window/physical.rs', 'src/quiescent/artifact_window/physical/tests.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_physical_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/physical.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/physical/tests.rs'])
        self.assertEqual(physical_window_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], physical_window_prior['recorder_tests']), (366, 366))
        for name, change in physical_window['workspace_changes'].items():
            self.assertEqual(physical_window_rows[name], change['current'])
            self.assertEqual(physical_window_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(physical_window_rows[name][field]), physical_window_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_426ea6a(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_426ea6a(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_426ea6a(physical_window_prior)
        for path, row in physical_window['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_426ea6a(path, raw, 'physical_window_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (physical_window['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in physical_window['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^physical_window_source_inverse$'):
                    current.source_before_426ea6a(path, wrong, 'physical_window_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(physical_window['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^physical_window_source_inverse$'):
                        current.source_before_426ea6a(path, raw, 'physical_window_source_inverse')
        read = Path.read_bytes
        physical_window_stimuli = [(p, 'fn ' + n + '(') for p, names in physical_window['added_default_methods'].items() for n in names]
        physical_window_stimuli += [(p, literal) for p, literals in physical_window['module_chains'].items() for literal in literals]
        for path, literal in physical_window_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('physical_window declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        self.assertEqual(physical_window['declaration_transports'], {})
        # Twenty-four entry-alphabet methods extend three existing default harnesses.
        alphabet = current.DATA['source_successor_0073fb6']
        alphabet_prior = current.before_0073fb6(actual)
        alphabet_rows = physical_window_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(alphabet_prior), current.ALPHABET_PREVIOUS)
        self.assertEqual((len(alphabet_rows), sum(x['tests'] for x in alphabet_rows.values()),
                          sum(x['ignored'] for x in alphabet_rows.values())), (122, 4771, 43))
        self.assertEqual((alphabet['default_method_additions'], alphabet['new_method_declarations'],
                          alphabet['default_method_removals'], alphabet['default_harness_changes'],
                          alphabet['default_ignore_changes'], alphabet['default_doctest_additions'],
                          alphabet['recorder_identity_changes'], alphabet['feature_method_additions'],
                          alphabet['feature_method_removals']), (24, 24, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(alphabet['added_default_methods'], {'src/emission/placement/digits/tests.rs': ['all_entry_bytes_and_fixed_conflicts_are_exact_in_each_digit', 'digit_minimum_matches_finite_enumeration_across_carries', 'all_masks_match_small_signed_partial_and_full_page_oracle', 'fixed06_wrapper_matches_independent_argmin_for_every_mask', 'alphabet_geometry_does_not_change_fixed_profile_or_indexed_attempt_zero', 'clipped_signed_edges_empty_sets_and_interval_order_are_exact'], 'src/emission/placement/entry_alphabet/tests.rs': ['checked_target_preserves_seed_or_selects_one_alphabet_target', 'checked_target_rejoins_every_field_and_rejects_coherent_non_alphabet_bytes', 'consumption_rechecks_permits_occupancy_and_unchanged_one_page_policy'], 'src/entry_router/imp/entry_alphabet_native_tests.rs': ['alphabet_min5_every_entry_routes_through_production', 'alphabet_min5_ret_fault_preserves_prior_pop_and_callbacks', 'alphabet_min5_non06_pop_fault_preserves_uncommitted_state'], 'src/quiescent/artifact_window/placement_tests.rs': ['actual_prepared_window_uses_non06_target_with_all_entries_and_observations', 'explicit_fixed06_is_identical_to_legacy_success_and_refusal', 'one_failed_encode_has_no_indexed_proof_and_append_failure_keeps_image_acceptance', 'source_entry_current_overlay_and_size_refusals_keep_original_precedence', 'alphabet_authority_refuses_live_unprepared_and_mixed_control_paths'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_alphabet_tests.rs': ['alphabet_cli_selector_is_distinct_and_preserves_old_routes_and_storage', 'alphabet_cli_keeps_complete_union_and_whole_unit_refusals_in_both_storage_modes', 'alphabet_cli_rejects_old_profile_and_repinned_placement_or_embedded_metadata'], 'tools/elf-rewrite/src/grouped_artifact_frontend/alphabet_tests.rs': ['alphabet_group_keeps_every_observation_and_retained_entry_in_one_plan', 'alphabet_policy_and_binding_are_distinct_while_min5_geometry_and_caps_stay_exact', 'alphabet_does_not_repair_short_min5_seals_or_split_atomically_withheld_groups', 'alphabet_storage_is_independent_and_singletons_keep_the_legacy_engine']})
        self.assertEqual(alphabet['default_method_instances'], {'src/emission/placement/digits/tests.rs': ['unit/liteinst2/lib'], 'src/emission/placement/entry_alphabet/tests.rs': ['unit/liteinst2/lib'], 'src/entry_router/imp/entry_alphabet_native_tests.rs': ['unit/liteinst2/lib'], 'src/quiescent/artifact_window/placement_tests.rs': ['unit/liteinst2/lib'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_alphabet_tests.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/src/grouped_artifact_frontend/alphabet_tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((alphabet['added_feature_methods'], alphabet['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(alphabet['source_paths']), len(alphabet['source_projections'])), (24, 24))
        self.assertEqual(alphabet['new_sources'], ['evaluation/direct-program/entry-alphabet-result/README.md', 'evaluation/direct-program/entry-alphabet-result/cases.csv', 'evaluation/direct-program/entry-alphabet-result/receipt.json', 'evaluation/direct-program/test_grouped_alphabet_linkage.py', 'evaluation/direct-program/validate_entry_alphabet.py', 'src/emission/placement/digits.rs', 'src/emission/placement/digits/tests.rs', 'src/emission/placement/entry_alphabet.rs', 'src/emission/placement/entry_alphabet/tests.rs', 'src/entry_router/imp/entry_alphabet_native_tests.rs', 'src/quiescent/artifact_window/placement_tests.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_alphabet_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/alphabet_tests.rs'])
        self.assertEqual(alphabet['newly_bound_sources'], ['evaluation/direct-program/entry-alphabet-result/README.md', 'evaluation/direct-program/entry-alphabet-result/cases.csv', 'evaluation/direct-program/entry-alphabet-result/receipt.json', 'evaluation/direct-program/test_grouped_alphabet_linkage.py', 'evaluation/direct-program/validate_entry_alphabet.py', 'src/emission/placement/digits.rs', 'src/emission/placement/digits/tests.rs', 'src/emission/placement/entry_alphabet.rs', 'src/emission/placement/entry_alphabet/tests.rs', 'src/entry_router/imp/entry_alphabet_native_tests.rs', 'src/quiescent/artifact_window/placement_tests.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_alphabet_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/alphabet_tests.rs'])
        self.assertEqual(alphabet_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], alphabet_prior['recorder_tests']), (366, 366))
        for name, change in alphabet['workspace_changes'].items():
            self.assertEqual(alphabet_rows[name], change['current'])
            self.assertEqual(alphabet_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(alphabet_rows[name][field]), alphabet_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_0073fb6(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_0073fb6(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_0073fb6(alphabet_prior)
        for path, row in alphabet['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_0073fb6(path, raw, 'alphabet_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (alphabet['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in alphabet['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^alphabet_source_inverse$'):
                    current.source_before_0073fb6(path, wrong, 'alphabet_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(alphabet['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^alphabet_source_inverse$'):
                        current.source_before_0073fb6(path, raw, 'alphabet_source_inverse')
        read = Path.read_bytes
        alphabet_stimuli = [(p, 'fn ' + n + '(') for p, names in alphabet['added_default_methods'].items() for n in names]
        alphabet_stimuli += [(p, literal) for p, literals in alphabet['module_chains'].items() for literal in literals]
        for path, literal in alphabet_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('alphabet declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        self.assertEqual(alphabet['declaration_transports'], {'src/entry_router/imp/routed_jmp_native_tests.rs': {'previous': '#[path = "../../../tests/support/quiescent_oracle.rs"]\nmod oracle;', 'current': '#[path = "../../../tests/support/quiescent_oracle.rs"]\npub(super) mod oracle;'}})
        # Seventeen minimum-window methods extend three existing default harnesses.
        minimum = current.DATA['source_successor_f9c5982']
        minimum_prior = current.before_f9c5982(actual)
        minimum_rows = alphabet_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(minimum_prior), current.MINIMUM_PREVIOUS)
        self.assertEqual((len(minimum_rows), sum(x['tests'] for x in minimum_rows.values()),
                          sum(x['ignored'] for x in minimum_rows.values())), (122, 4747, 43))
        self.assertEqual((minimum['default_method_additions'], minimum['new_method_declarations'],
                          minimum['default_method_removals'], minimum['default_harness_changes'],
                          minimum['default_ignore_changes'], minimum['default_doctest_additions'],
                          minimum['recorder_identity_changes'], minimum['feature_method_additions'],
                          minimum['feature_method_removals']), (17, 17, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(minimum['added_default_methods'], {'src/entry_router/imp/routed_jmp_native_tests.rs': ['min5_every_entry_routes_through_production_and_preserves_ret_state', 'min5_unselected_ret_fault_preserves_prior_pop_and_callback_state'], 'src/quiescent/artifact_window/min5_tests.rs': ['seal_stops_at_first_whole_end_without_conflating_selected_and_retained_spans', 'final_unselected_ret_uses_existing_encoder_routes_mask_and_continuation', 'owned_seal_joins_exact_geometry_identity_bytes_and_supplied_population', 'source_and_population_failures_precede_collection_without_search_credit', 'block_and_displacement_bounds_keep_original_qualifier_precedence', 'seal_does_not_bypass_current_overlay_pending_or_terminal_entry_checks', 'seal_is_not_a_physical_budget_fitting_or_hook_binding_success'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_min5_tests.rs': ['min5_cli_selector_is_explicit_and_keeps_legacy_and_storage_routes', 'min5_cli_keeps_complete_population_for_retained_ret_and_preflight_refusal', 'min5_cli_binding_rejects_old_profile_replay_and_mutated_policy_or_carrier'], 'tools/elf-rewrite/src/grouped_artifact_frontend/min5_tests.rs': ['min5_retained_ret_reaches_actual_carrier_without_changing_selected_population', 'min5_preflight_failure_keeps_all_units_and_exact_member_refusals_atomic', 'min5_full_manifest_and_frozen_source_join_reject_consumed_straddling_or_changed_input', 'min5_named_bounds_and_final_carrier_refusal_never_relax_atomicity', 'min5_reuses_compact_codec_and_unchanged_singleton_engine']})
        self.assertEqual(minimum['default_method_instances'], {'src/entry_router/imp/routed_jmp_native_tests.rs': ['unit/liteinst2/lib'], 'src/quiescent/artifact_window/min5_tests.rs': ['unit/liteinst2/lib'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_min5_tests.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/src/grouped_artifact_frontend/min5_tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((minimum['added_feature_methods'], minimum['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(minimum['source_paths']), len(minimum['source_projections'])), (23, 23))
        self.assertEqual(minimum['new_sources'], ['evaluation/direct-program/minimum-window-result/README.md', 'evaluation/direct-program/minimum-window-result/cases.csv', 'evaluation/direct-program/minimum-window-result/receipt.json', 'evaluation/direct-program/minimum-window-validation/README.md', 'evaluation/direct-program/minimum-window-validation/receipt.json', 'evaluation/direct-program/test_grouped_min5_linkage.py', 'evaluation/direct-program/validate_minimum_window.py', 'src/quiescent/artifact_window/min5_tests.rs', 'tests/support/min5_native.rs', 'tests/support/router_witness.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_min5_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/min5_tests.rs'])
        self.assertEqual(minimum['newly_bound_sources'], ['evaluation/direct-program/minimum-window-result/README.md', 'evaluation/direct-program/minimum-window-result/cases.csv', 'evaluation/direct-program/minimum-window-result/receipt.json', 'evaluation/direct-program/minimum-window-validation/README.md', 'evaluation/direct-program/minimum-window-validation/receipt.json', 'evaluation/direct-program/test_grouped_min5_linkage.py', 'evaluation/direct-program/validate_minimum_window.py', 'src/entry_router/imp/routed_jmp_native_tests.rs', 'src/quiescent/artifact_window/min5_tests.rs', 'tests/support/min5_native.rs', 'tests/support/router_witness.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_min5_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/min5_tests.rs', 'src/entry_router.rs'])
        self.assertEqual(minimum_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], minimum_prior['recorder_tests']), (366, 366))
        for name, change in minimum['workspace_changes'].items():
            self.assertEqual(minimum_rows[name], change['current'])
            self.assertEqual(minimum_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(minimum_rows[name][field]), minimum_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_f9c5982(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_f9c5982(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_f9c5982(minimum_prior)
        for path, row in minimum['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_f9c5982(path, raw, 'minimum_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (minimum['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in minimum['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^minimum_source_inverse$'):
                    current.source_before_f9c5982(path, wrong, 'minimum_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(minimum['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^minimum_source_inverse$'):
                        current.source_before_f9c5982(path, raw, 'minimum_source_inverse')
        read = Path.read_bytes
        minimum_stimuli = [(p, 'fn ' + n + '(') for p, names in minimum['added_default_methods'].items() for n in names]
        minimum_stimuli += [(p, literal) for p, literals in minimum['module_chains'].items() for literal in literals]
        for path, literal in minimum_stimuli:
            # The same historical module stimulus at its exact new visibility.
            if path in alphabet['declaration_transports']:
                transport = alphabet['declaration_transports'][path]
                if literal == transport['previous']:
                    literal = transport['current']
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('minimum declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Twenty-six upstream/ledger methods extend four existing default harnesses.
        upstream = current.DATA['source_successor_2294097']
        upstream_prior = current.before_2294097(actual)
        upstream_rows = minimum_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(upstream_prior), current.UPSTREAM_PREVIOUS)
        self.assertEqual((len(upstream_rows), sum(x['tests'] for x in upstream_rows.values()),
                          sum(x['ignored'] for x in upstream_rows.values())), (122, 4730, 43))
        self.assertEqual((upstream['default_method_additions'], upstream['new_method_declarations'],
                          upstream['default_method_removals'], upstream['default_harness_changes'],
                          upstream['default_ignore_changes'], upstream['default_doctest_additions'],
                          upstream['recorder_identity_changes'], upstream['feature_method_additions'],
                          upstream['feature_method_removals']), (26, 26, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(upstream['added_default_methods'], {'crates/liteinst-artifact/src/lib.rs': ['incremental_empty_boundaries_and_many_updates_equal_exact_content_id'], 'src/quiescent/artifact_window/upstream_tests.rs': ['short_span_uses_one_legal_prefix_and_preserves_every_head_and_observer', 'constrained_offset_refuses_before_prefix_fits_in_the_same_arena', 'sixty_five_heads_share_one_sixty_four_site_domain_and_retain_omission', 'block_distance_displacement_call_and_nonfinal_transfer_remain_hard_boundaries', 'identity_pending_overlay_and_cet_checks_keep_predecessor_unchanged', 'oversized_certificate_is_not_rescued_by_an_earlier_head_or_unresolved_hook', 'population_allocation_and_per_head_symbol_failures_are_never_bypassed'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_upstream_tests.rs': ['upstream_cli_selector_is_distinct_and_legacy_arguments_are_literal', 'upstream_cli_short_group_uses_full_union_and_keeps_block_refusal', 'upstream_cli_metadata_requires_new_policy_identity_and_exact_product'], 'tools/elf-rewrite/examples/disassembly_sites/ledger_storage_tests.rs': ['chunk_storage_selector_is_independent_and_legacy_parse_remains_exact', 'chunk_storage_actual_group_preserves_inline_plans_images_outcomes_and_bindings', 'chunk_storage_table_proof_and_physical_embedded_plan_mutations_refuse', 'chunk_storage_replays_evolving_reads_and_retains_atomic_refusals'], 'tools/elf-rewrite/src/grouped_artifact_frontend/upstream_tests.rs': ['upstream_short_group_keeps_members_and_routes_unselected_prefix_once', 'upstream_full_manifest_rejects_consumed_and_straddling_prefix_members', 'upstream_named_bounds_and_final_carrier_failure_remain_atomic', 'upstream_nongroup_engine_matches_exact_images_and_outcomes'], 'tools/elf-rewrite/src/ledger_codec/tests.rs': ['same_real_multi_step_plans_expand_exactly_and_replay_current_overlay', 'repinned_stale_second_read_fails_overlay_not_only_container_hash', 'empty_repeated_same_address_and_short_tail_reads_keep_exact_ordinals', 'table_identity_canonical_ids_reference_order_and_lengths_are_checked', 'shared_extensions_preserve_grouped_and_fixed_canonical_records', 'advertised_work_and_aggregate_staging_refuse_without_expansion_allocation', 'first_codec_error_is_retained_but_existing_semantic_error_still_wins']})
        self.assertEqual(upstream['default_method_instances'], {'crates/liteinst-artifact/src/lib.rs': ['unit/liteinst_artifact/lib'], 'src/quiescent/artifact_window/upstream_tests.rs': ['unit/liteinst2/lib'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_upstream_tests.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/examples/disassembly_sites/ledger_storage_tests.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/src/grouped_artifact_frontend/upstream_tests.rs': ['unit/liteinst_rewrite/lib'], 'tools/elf-rewrite/src/ledger_codec/tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((upstream['added_feature_methods'], upstream['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(upstream['source_paths']), len(upstream['source_projections'])), (50, 50))
        self.assertEqual(upstream['new_sources'], ['evaluation/direct-program/grouped-upstream-result/README.md', 'evaluation/direct-program/grouped-upstream-result/receipt.json', 'evaluation/direct-program/grouped-upstream-result/results.csv', 'evaluation/direct-program/grouped-upstream-validation/README.md', 'evaluation/direct-program/grouped-upstream-validation/receipt.json', 'evaluation/direct-program/ledger-chunks-result/README.md', 'evaluation/direct-program/ledger-chunks-result/receipt.json', 'evaluation/direct-program/ledger-chunks-result/results.csv', 'evaluation/direct-program/ledger-chunks-validation/README.md', 'evaluation/direct-program/ledger-chunks-validation/receipt.json', 'evaluation/direct-program/test_grouped_upstream_linkage.py', 'evaluation/direct-program/test_ledger_storage.py', 'evaluation/direct-program/validate_grouped_upstream.py', 'evaluation/direct-program/validate_ledger_chunks.py', 'evaluation/shared-x86/decoder_facts_support.py', 'evaluation/shared-x86/freestanding-facts/README.md', 'evaluation/shared-x86/freestanding-facts/receipt.json', 'evaluation/shared-x86/validate_decoder_facts.py', 'src/quiescent/artifact_window/upstream_tests.rs', 'src/scalar_profile.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_upstream_tests.rs', 'tools/elf-rewrite/examples/disassembly_sites/ledger_storage_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/upstream_tests.rs', 'tools/elf-rewrite/src/ledger_codec.rs', 'tools/elf-rewrite/src/ledger_codec/tests.rs', 'tools/elf-rewrite/src/ledger_storage.rs'])
        self.assertEqual(upstream['newly_bound_sources'], ['crates/liteinst-artifact/src/lib.rs', 'crates/liteinst-launch/src/linux/remote/dynamic/owner/kernel_journal/tests/native.rs', 'evaluation/direct-program/grouped-upstream-result/README.md', 'evaluation/direct-program/grouped-upstream-result/receipt.json', 'evaluation/direct-program/grouped-upstream-result/results.csv', 'evaluation/direct-program/grouped-upstream-validation/README.md', 'evaluation/direct-program/grouped-upstream-validation/receipt.json', 'evaluation/direct-program/ledger-chunks-result/README.md', 'evaluation/direct-program/ledger-chunks-result/receipt.json', 'evaluation/direct-program/ledger-chunks-result/results.csv', 'evaluation/direct-program/ledger-chunks-validation/README.md', 'evaluation/direct-program/ledger-chunks-validation/receipt.json', 'evaluation/direct-program/test_grouped_upstream_linkage.py', 'evaluation/direct-program/test_ledger_storage.py', 'evaluation/direct-program/validate_grouped_upstream.py', 'evaluation/direct-program/validate_ledger_chunks.py', 'evaluation/shared-x86/decoder_facts_support.py', 'evaluation/shared-x86/freestanding-facts/README.md', 'evaluation/shared-x86/freestanding-facts/receipt.json', 'evaluation/shared-x86/validate_decoder_facts.py', 'src/quiescent/artifact_window/upstream_tests.rs', 'src/scalar_profile.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_upstream_tests.rs', 'tools/elf-rewrite/examples/disassembly_sites/ledger_storage_tests.rs', 'tools/elf-rewrite/examples/verify_common_core.rs', 'tools/elf-rewrite/examples/verify_elf_exec.rs', 'tools/elf-rewrite/examples/verify_elf_tactics.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/upstream_tests.rs', 'tools/elf-rewrite/src/ledger_codec.rs', 'tools/elf-rewrite/src/ledger_codec/tests.rs', 'tools/elf-rewrite/src/ledger_storage.rs', 'tools/elf-rewrite/src/offline_router.rs', 'tools/page-entry/selected/decoder/src/add_guard.rs', 'tools/page-entry/selected/decoder/src/mov_guard.rs', 'tools/page-entry/selected/decoder/src/region.rs', 'tools/page-entry/selected/decoder/src/tf.rs'])
        self.assertEqual(upstream_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], upstream_prior['recorder_tests']), (366, 366))
        for name, change in upstream['workspace_changes'].items():
            self.assertEqual(upstream_rows[name], change['current'])
            self.assertEqual(upstream_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(upstream_rows[name][field]), upstream_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_2294097(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_2294097(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_2294097(upstream_prior)
        for path, row in upstream['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_2294097(path, raw, 'upstream_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (upstream['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in upstream['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^upstream_source_inverse$'):
                    current.source_before_2294097(path, wrong, 'upstream_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(upstream['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^upstream_source_inverse$'):
                        current.source_before_2294097(path, raw, 'upstream_source_inverse')
        read = Path.read_bytes
        upstream_stimuli = [(p, 'fn ' + n + '(') for p, names in upstream['added_default_methods'].items() for n in names]
        upstream_stimuli += [(p, literal) for p, literals in upstream['module_chains'].items() for literal in literals]
        for path, literal in upstream_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('upstream declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Thirty grouped-artifact methods extend four existing default harnesses.
        grouped = current.DATA['source_successor_9528851']
        grouped_prior = current.before_9528851(actual)
        grouped_rows = upstream_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(grouped_prior), current.GROUPED_PREVIOUS)
        self.assertEqual((len(grouped_rows), sum(x['tests'] for x in grouped_rows.values()),
                          sum(x['ignored'] for x in grouped_rows.values())), (122, 4704, 43))
        self.assertEqual((grouped['default_method_additions'], grouped['new_method_declarations'],
                          grouped['default_method_removals'], grouped['default_harness_changes'],
                          grouped['default_ignore_changes'], grouped['default_doctest_additions'],
                          grouped['recorder_identity_changes'], grouped['feature_method_additions'],
                          grouped['feature_method_removals']), (30, 30, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(grouped['added_default_methods'], {'src/quiescent/artifact_window/tests.rs': ['exact_six_pop_has_one_plan_and_all_selected_and_unselected_entry_routes', 'outside_branch_entries_keep_both_head_kinds_and_an_internal_transfer_still_refuses', 'explicit_population_and_profile_guards_refuse_before_any_physical_attempt', 'identity_current_bytes_and_cet_refuse_at_their_original_stages', 'pending_outsider_is_checked_after_candidate_append_without_mutating_predecessor', 'exact_end_and_displacement_bounds_precede_unchanged_call_qualification', 'one_page_one_candidate_and_symbol_limits_remain_hard_refusals'], 'src/trampoline/artifact_window/tests.rs': ['single_observation_keeps_ordinary_symbolic_bytes_maps_and_requirements', 'stack_window_preserves_every_head_and_exact_callback_pc_fields', 'internal_branch_targets_selected_entry_not_restored_body', 'population_validation_preserves_existing_window_error_precedence', 'complete_action_accounting_rejects_missing_duplicated_and_wrong_fields', 'artifact_linking_keeps_original_field_error_before_missing_hook_and_fixed_obligation', 'final_link_and_size_refusals_leave_old_live_actions_unsupported'], 'src/trampoline/observer_sequence/tests.rs': ['instrumentation_refusal_precedes_restore_coordinate', 'successful_instrumentation_preserves_later_coordinate_refusal'], 'tests/quiescent_oracle.rs': ['artifact_window_native_every_entry', 'artifact_window_native_branch_paths', 'artifact_window_native_rsp_effects', 'artifact_window_native_later_operand_fault'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_tests.rs': ['grouped_cli_selector_keeps_legacy_routes_and_rejects_mixed_or_partial_forms', 'grouped_cli_uses_actual_typed_route_and_retains_complete_success_and_refusal_census', 'grouped_cli_metadata_rejects_policy_identity_and_embedded_product_corruption'], 'tools/elf-rewrite/src/grouped_artifact_frontend/tests.rs': ['grouped_six_pop_carrier_retains_all_members_routes_and_one_image', 'grouped_policy_and_both_metadata_forms_bind_total_partition', 'grouped_membership_mutations_refuse_without_singleton_fallback', 'grouped_jump_member_is_never_filtered_and_refusal_is_atomic', 'grouped_pending_and_resource_failures_leave_complete_draft_unmodified', 'grouped_carrier_refusal_withholds_all_six_and_preserves_original_identity', 'grouped_nongroup_route_retains_legacy_images_edits_and_outcomes']})
        self.assertEqual(grouped['default_method_instances'], {'src/quiescent/artifact_window/tests.rs': ['unit/liteinst2/lib'], 'src/trampoline/artifact_window/tests.rs': ['unit/liteinst2/lib'], 'src/trampoline/observer_sequence/tests.rs': ['unit/liteinst2/lib'], 'tests/quiescent_oracle.rs': ['test/quiescent_oracle'], 'tools/elf-rewrite/examples/disassembly_sites/grouped_tests.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/src/grouped_artifact_frontend/tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((grouped['added_feature_methods'], grouped['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(grouped['source_paths']), len(grouped['source_projections'])), (35, 35))
        self.assertEqual(grouped['new_sources'], ['evaluation/direct-program/artifact-window-validation/README.md', 'evaluation/direct-program/artifact-window-validation/receipt.json', 'evaluation/direct-program/grouped-program-result/README.md', 'evaluation/direct-program/grouped-program-result/receipt.json', 'evaluation/direct-program/grouped-program-result/results.csv', 'evaluation/direct-program/grouped-program-validation/README.md', 'evaluation/direct-program/grouped-program-validation/receipt.json', 'evaluation/direct-program/test_grouped_linkage.py', 'evaluation/direct-program/validate_artifact_window.py', 'evaluation/direct-program/validate_grouped_artifact.py', 'evaluation/direct-program/validate_grouped_program.py', 'src/quiescent/artifact_window.rs', 'src/quiescent/artifact_window/tests.rs', 'src/trampoline/artifact_window.rs', 'src/trampoline/artifact_window/tests.rs', 'src/trampoline/observer_sequence.rs', 'src/trampoline/observer_sequence/tests.rs', 'tests/support/artifact_window_native.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/tests.rs'])
        self.assertEqual(grouped['newly_bound_sources'], ['evaluation/direct-program/artifact-window-validation/README.md', 'evaluation/direct-program/artifact-window-validation/receipt.json', 'evaluation/direct-program/grouped-program-result/README.md', 'evaluation/direct-program/grouped-program-result/receipt.json', 'evaluation/direct-program/grouped-program-result/results.csv', 'evaluation/direct-program/grouped-program-validation/README.md', 'evaluation/direct-program/grouped-program-validation/receipt.json', 'evaluation/direct-program/test_grouped_linkage.py', 'evaluation/direct-program/validate_artifact_window.py', 'evaluation/direct-program/validate_grouped_artifact.py', 'evaluation/direct-program/validate_grouped_program.py', 'src/quiescent/artifact_window.rs', 'src/quiescent/artifact_window/tests.rs', 'src/trampoline/artifact_window.rs', 'src/trampoline/artifact_window/tests.rs', 'src/trampoline/observer_sequence.rs', 'src/trampoline/observer_sequence/tests.rs', 'tests/support/artifact_window_native.rs', 'tools/elf-rewrite/examples/disassembly_sites/grouped_tests.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend.rs', 'tools/elf-rewrite/src/grouped_artifact_frontend/tests.rs'])
        self.assertEqual(grouped_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], grouped_prior['recorder_tests']), (366, 366))
        for name, change in grouped['workspace_changes'].items():
            self.assertEqual(grouped_rows[name], change['current'])
            self.assertEqual(grouped_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(grouped_rows[name][field]), grouped_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_9528851(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_9528851(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_9528851(grouped_prior)
        for path, row in grouped['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_9528851(path, raw, 'grouped_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (grouped['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in grouped['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^grouped_source_inverse$'):
                    current.source_before_9528851(path, wrong, 'grouped_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(grouped['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^grouped_source_inverse$'):
                        current.source_before_9528851(path, raw, 'grouped_source_inverse')
        read = Path.read_bytes
        grouped_stimuli = [(p, 'fn ' + n + '(') for p, names in grouped['added_default_methods'].items() for n in names]
        grouped_stimuli += [(p, literal) for p, literals in grouped['module_chains'].items() for literal in literals]
        for path, literal in grouped_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('grouped declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Eighteen jump/register-stack methods extend five existing default harnesses.
        jump = current.DATA['source_successor_11cc419']
        jump_prior = current.before_11cc419(actual)
        jump_rows = grouped_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(jump_prior), current.JUMP_PREVIOUS)
        self.assertEqual((len(jump_rows), sum(x['tests'] for x in jump_rows.values()),
                          sum(x['ignored'] for x in jump_rows.values())), (122, 4674, 43))
        self.assertEqual((jump['default_method_additions'], jump['new_method_declarations'],
                          jump['default_method_removals'], jump['default_harness_changes'],
                          jump['default_ignore_changes'], jump['default_doctest_additions'],
                          jump['recorder_identity_changes'], jump['feature_method_additions'],
                          jump['feature_method_removals']), (18, 18, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(jump['added_default_methods'], {'crates/liteinst-x86/src/tests.rs': ['jump_fact_matches_the_complete_legacy_mnemonic_population', 'register_stack_union_keeps_all_registers_and_exact_code_boundaries'], 'tests/quiescent_oracle.rs': ['jump_stack_native_low_gprs', 'jump_stack_native_high_gprs', 'jump_stack_native_rsp_loaded_value', 'jump_stack_native_operand_faults'], 'tools/elf-rewrite/examples/disassembly_sites/whole_tests.rs': ['jump_stack_rewrite_selector_preserves_old_routes_and_rejects_mixing', 'jump_stack_rewrite_uses_typed_prepare_and_retains_every_imported_row_on_refusal'], 'tools/elf-rewrite/examples/full_program_bridge/input_tests.rs': ['jump_stack_material_selection_joins_every_rpc_patch_and_keeps_caps', 'jump_stack_input_selectors_keep_pin_type_and_mixed_mode_refusals', 'jump_stack_material_policy_files_keep_full_counts_on_policy_refusal'], 'tools/elf-rewrite/src/disassembly/tests.rs': ['jump_stack_import_keeps_complete_union_and_literal_old_inventory', 'jump_stack_import_preserves_shared_first_errors_and_global_target_checks', 'jump_stack_import_keeps_every_register_without_legacy_profile_promotion'], 'tools/elf-rewrite/src/disassembly/whole/tests.rs': ['complete_union_policy_and_shared_manifest_retain_rsp_prefixes_and_classes', 'union_projection_rejects_class_population_and_policy_replay_mutations', 'union_fixed_policy_keeps_ordered_permits_caps_and_first_errors', 'union_actual_fixed_transaction_emits_or_refuses_complete_population']})
        self.assertEqual(jump['default_method_instances'], {'crates/liteinst-x86/src/tests.rs': ['unit/liteinst_x86/lib'], 'tests/quiescent_oracle.rs': ['test/quiescent_oracle'], 'tools/elf-rewrite/examples/disassembly_sites/whole_tests.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/examples/full_program_bridge/input_tests.rs': ['unit/full_program_bridge/full_program_bridge'], 'tools/elf-rewrite/src/disassembly/tests.rs': ['unit/liteinst_rewrite/lib'], 'tools/elf-rewrite/src/disassembly/whole/tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((jump['added_feature_methods'], jump['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(jump['source_paths']), len(jump['source_projections'])), (30, 30))
        self.assertEqual(jump['new_sources'], ['evaluation/direct-program/jump-stack-profile.md', 'evaluation/direct-program/jump-stack-result/README.md', 'evaluation/direct-program/jump-stack-result/receipt.json', 'evaluation/direct-program/jump-stack-result/results.csv', 'evaluation/direct-program/jump-stack-validation/README.md', 'evaluation/direct-program/jump-stack-validation/receipt.json', 'evaluation/direct-program/test_stack_inventory.py', 'evaluation/direct-program/validate_stack.py', 'tests/support/jump_stack_native.rs', 'tools/elf-rewrite/src/disassembly/jump_stack.rs'])
        self.assertEqual(jump['newly_bound_sources'], ['evaluation/direct-program/direct_data.py', 'evaluation/direct-program/jump-stack-profile.md', 'evaluation/direct-program/jump-stack-result/README.md', 'evaluation/direct-program/jump-stack-result/receipt.json', 'evaluation/direct-program/jump-stack-result/results.csv', 'evaluation/direct-program/jump-stack-validation/README.md', 'evaluation/direct-program/jump-stack-validation/receipt.json', 'evaluation/direct-program/reproduce.py', 'evaluation/direct-program/test_stack_inventory.py', 'evaluation/direct-program/validate_stack.py', 'tests/quiescent_oracle.rs', 'tests/support/jump_stack_native.rs', 'tools/elf-rewrite/src/disassembly/jump_stack.rs'])
        self.assertEqual(jump_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], jump_prior['recorder_tests']), (366, 366))
        for name, change in jump['workspace_changes'].items():
            self.assertEqual(jump_rows[name], change['current'])
            self.assertEqual(jump_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(jump_rows[name][field]), jump_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_11cc419(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_11cc419(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_11cc419(jump_prior)
        for path, row in jump['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_11cc419(path, raw, 'jump_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (jump['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in jump['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^jump_source_inverse$'):
                    current.source_before_11cc419(path, wrong, 'jump_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(jump['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^jump_source_inverse$'):
                        current.source_before_11cc419(path, raw, 'jump_source_inverse')
        read = Path.read_bytes
        jump_stimuli = [(p, 'fn ' + n + '(') for p, names in jump['added_default_methods'].items() for n in names]
        jump_stimuli += [(p, literal) for p, literals in jump['module_chains'].items() for literal in literals]
        for path, literal in jump_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('jump declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Eight shared-CFG methods extend two existing default harnesses.
        cfg = current.DATA['source_successor_281c342']
        cfg_prior = current.before_281c342(actual)
        cfg_rows = jump_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(cfg_prior), current.CFG_PREVIOUS)
        self.assertEqual((len(cfg_rows), sum(x['tests'] for x in cfg_rows.values()),
                          sum(x['ignored'] for x in cfg_rows.values())), (122, 4656, 43))
        self.assertEqual((cfg['default_method_additions'], cfg['new_method_declarations'],
                          cfg['default_method_removals'], cfg['default_harness_changes'],
                          cfg['default_ignore_changes'], cfg['default_doctest_additions'],
                          cfg['recorder_identity_changes'], cfg['feature_method_additions'],
                          cfg['feature_method_removals']), (8, 8, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(cfg['added_default_methods'], {'src/backedge_clock/owned_region/cfg_shared_tests.rs': ['owned_cfg_shared_positive_graphs_and_distinct_scalar_profiles', 'owned_cfg_shared_refusals_and_exact_backedge_rosters', 'owned_cfg_shared_region_returnability_is_not_added_to_loop', 'owned_cfg_shared_size_address_and_supplied_scan_guards'], 'src/control_flow/tests.rs': ['shared_cut_collector_keeps_global_direct_facts_separate_from_local_edges', 'shared_cut_collector_preserves_policy_order_and_first_error'], 'tools/elf-rewrite/src/disassembly/tests.rs': ['imported_cuts_keep_cross_region_call_branch_and_xbegin_targets', 'imported_cuts_keep_global_contradictions_after_all_ledger_and_entry_checks']})
        self.assertEqual(cfg['default_method_instances'], {'src/backedge_clock/owned_region/cfg_shared_tests.rs': ['unit/liteinst2/lib'], 'src/control_flow/tests.rs': ['unit/liteinst2/lib'], 'tools/elf-rewrite/src/disassembly/tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((cfg['added_feature_methods'], cfg['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(cfg['source_paths']), len(cfg['source_projections'])), (14, 14))
        self.assertEqual(cfg['new_sources'], ['evaluation/shared-cfg/disassembly-cuts/README.md', 'evaluation/shared-cfg/disassembly-cuts/receipt.json', 'evaluation/shared-cfg/owned-clock/README.md', 'evaluation/shared-cfg/owned-clock/receipt.json', 'evaluation/shared-cfg/validate_clock.py', 'evaluation/shared-cfg/validate_cuts.py', 'src/backedge_clock/owned_region/cfg_shared_tests.rs'])
        self.assertEqual(cfg['newly_bound_sources'], ['A3-SHARED-ADMISSION.md', 'evaluation/shared-cfg/disassembly-cuts/README.md', 'evaluation/shared-cfg/disassembly-cuts/receipt.json', 'evaluation/shared-cfg/owned-clock/README.md', 'evaluation/shared-cfg/owned-clock/receipt.json', 'evaluation/shared-cfg/validate_clock.py', 'evaluation/shared-cfg/validate_cuts.py', 'src/backedge_clock/owned_loop.rs', 'src/backedge_clock/owned_region/cfg_shared_tests.rs'])
        self.assertEqual(cfg_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], cfg_prior['recorder_tests']), (366, 366))
        for name, change in cfg['workspace_changes'].items():
            self.assertEqual(cfg_rows[name], change['current'])
            self.assertEqual(cfg_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(cfg_rows[name][field]), cfg_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_281c342(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_281c342(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_281c342(cfg_prior)
        for path, row in cfg['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_281c342(path, raw, 'cfg_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (cfg['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in cfg['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^cfg_source_inverse$'):
                    current.source_before_281c342(path, wrong, 'cfg_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(cfg['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^cfg_source_inverse$'):
                        current.source_before_281c342(path, raw, 'cfg_source_inverse')
        read = Path.read_bytes
        cfg_stimuli = [(p, 'fn ' + n + '(') for p, names in cfg['added_default_methods'].items() for n in names]
        cfg_stimuli += [(p, literal) for p, literals in cfg['module_chains'].items() for literal in literals]
        for path, literal in cfg_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('cfg declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Twelve fixed-ET_EXEC methods extend three existing default harnesses.
        fixed = current.DATA['source_successor_064b48c']
        fixed_prior = current.before_064b48c(actual)
        fixed_rows = cfg_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(fixed_prior), current.FIXED_PREVIOUS)
        self.assertEqual((len(fixed_rows), sum(x['tests'] for x in fixed_rows.values()),
                          sum(x['ignored'] for x in fixed_rows.values())), (122, 4648, 43))
        self.assertEqual((fixed['default_method_additions'], fixed['new_method_declarations'],
                          fixed['default_method_removals'], fixed['default_harness_changes'],
                          fixed['default_ignore_changes'], fixed['default_doctest_additions'],
                          fixed['recorder_identity_changes'], fixed['feature_method_additions'],
                          fixed['feature_method_removals']), (12, 12, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(fixed['added_default_methods'], {'src/artifact_emission_tests.rs': ['fixed_exec_indexed_jump_producer_preserves_signed_fields_and_default_refusals', 'fixed_exec_keeps_non_jump_and_truncated_indexed_operand_refusals', 'fixed_exec_original_error_order_and_prepared_binding_remain_exact', 'fixed_exec_nop5_cannot_erase_binding_through_legacy_unwind_export'], 'src/artifact_fixups.rs': ['fixed_signed32_is_preserved_only_under_explicit_domain_and_exact_bytes'], 'tools/elf-rewrite/examples/disassembly_sites.rs': ['fixed_exec_selector_is_explicit_and_preserves_legacy_parsers'], 'tools/elf-rewrite/src/disassembly/whole/tests.rs': ['fixed_exec_actual_indexed_encoder_carrier_route_and_legacy_refusals', 'fixed_exec_binding_keeps_complete_atomic_refusals_and_both_pair_obligations', 'fixed_exec_writer_rejects_wrong_source_type_entry_and_original_load_records', 'fixed_exec_real_rela_write_on_original_disp32_refuses_after_core_success', 'fixed_exec_portable_and_embedded_metadata_require_exact_binding_policy', 'fixed_exec_readback_uses_actual_low_gap_high_interleaved_header_map']})
        self.assertEqual(fixed['default_method_instances'], {'src/artifact_emission_tests.rs': ['unit/liteinst2/lib'], 'src/artifact_fixups.rs': ['unit/liteinst2/lib'], 'tools/elf-rewrite/examples/disassembly_sites.rs': ['unit/disassembly_sites/disassembly_sites'], 'tools/elf-rewrite/src/disassembly/whole/tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((fixed['added_feature_methods'], fixed['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(fixed['source_paths']), len(fixed['source_projections'])), (14, 14))
        self.assertEqual(fixed['new_sources'], ['tools/elf-rewrite/src/fixed_exec.rs'])
        self.assertEqual(fixed['newly_bound_sources'], ['tools/elf-rewrite/examples/adjacent_b2_support/ledger.rs', 'tools/elf-rewrite/src/fixed_exec.rs'])
        self.assertEqual(fixed_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], fixed_prior['recorder_tests']), (366, 366))
        for name, change in fixed['workspace_changes'].items():
            self.assertEqual(fixed_rows[name], change['current'])
            self.assertEqual(fixed_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(fixed_rows[name][field]), fixed_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_064b48c(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_064b48c(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_064b48c(fixed_prior)
        for path, row in fixed['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_064b48c(path, raw, 'fixed_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (fixed['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in fixed['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^fixed_source_inverse$'):
                    current.source_before_064b48c(path, wrong, 'fixed_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(fixed['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^fixed_source_inverse$'):
                        current.source_before_064b48c(path, raw, 'fixed_source_inverse')
        read = Path.read_bytes
        fixed_stimuli = [(p, 'fn ' + n + '(') for p, names in fixed['added_default_methods'].items() for n in names]
        fixed_stimuli += [(p, literal) for p, literals in fixed['module_chains'].items() for literal in literals]
        for path, literal in fixed_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('fixed declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Nine direct-input/CFG methods extend three existing default harnesses.
        direct = current.DATA['source_successor_79a4b8b']
        direct_prior = current.before_79a4b8b(actual)
        direct_rows = fixed_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(direct_prior), current.DIRECT_PREVIOUS)
        self.assertEqual((len(direct_rows), sum(x['tests'] for x in direct_rows.values()),
                          sum(x['ignored'] for x in direct_rows.values())), (122, 4636, 43))
        self.assertEqual((direct['default_method_additions'], direct['new_method_declarations'],
                          direct['default_method_removals'], direct['default_harness_changes'],
                          direct['default_ignore_changes'], direct['default_doctest_additions'],
                          direct['recorder_identity_changes'], direct['feature_method_additions'],
                          direct['feature_method_removals']), (9, 9, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(direct['added_default_methods'], {'tools/elf-rewrite/examples/common_sites.rs': ['shared_graph_matches_complete_predecessor_corpus_and_invalid_functions', 'shared_graph_preserves_aggregate_errors_call_policy_and_unreachable_blocks', 'non64_branch_policy_keeps_fallthrough_but_does_not_add_a_target_cut'], 'tools/elf-rewrite/examples/full_program_bridge/input_tests.rs': ['explicit_input_preserves_legacy_selectors_and_rejects_mixed_or_unpinned_profiles', 'explicit_et_exec_keeps_independent_import_and_pin_before_elf_refusal', 'explicit_material_and_policy_cli_retain_complete_success_and_refusal_outputs'], 'tools/elf-rewrite/src/disassembly/policy_tests.rs': ['direct_policy_joins_actual_loads_complete_heads_target_and_ordered_permits', 'direct_policy_refuses_incomplete_or_widened_inputs_without_filtering_sites', 'direct_policy_original_c3_candidate_and_shared_reservation_keep_old_checks']})
        self.assertEqual(direct['default_method_instances'], {'tools/elf-rewrite/examples/common_sites.rs': ['unit/common_sites/common_sites'], 'tools/elf-rewrite/examples/full_program_bridge/input_tests.rs': ['unit/full_program_bridge/full_program_bridge'], 'tools/elf-rewrite/src/disassembly/policy_tests.rs': ['unit/liteinst_rewrite/lib']})
        self.assertEqual((direct['added_feature_methods'], direct['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(direct['source_paths']), len(direct['source_projections'])), (12, 12))
        self.assertEqual(direct['new_sources'], ['tools/elf-rewrite/examples/full_program_bridge/input.rs', 'tools/elf-rewrite/examples/full_program_bridge/input_tests.rs', 'tools/elf-rewrite/examples/full_program_bridge/policy_cli.rs', 'tools/elf-rewrite/src/disassembly/policy_tests.rs', 'tools/elf-rewrite/src/disassembly/whole/policy.rs'])
        self.assertEqual(direct['newly_bound_sources'], direct['new_sources'])
        self.assertEqual(direct_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], direct_prior['recorder_tests']), (366, 366))
        for name, change in direct['workspace_changes'].items():
            self.assertEqual(direct_rows[name], change['current'])
            self.assertEqual(direct_prior['harness_test_counts']['workspace_tests'][name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(direct_rows[name][field]), direct_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_79a4b8b(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_79a4b8b(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_79a4b8b(direct_prior)
        for path, row in direct['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_79a4b8b(path, raw, 'direct_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (direct['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in direct['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^direct_source_inverse$'):
                    current.source_before_79a4b8b(path, wrong, 'direct_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(direct['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^direct_source_inverse$'):
                        current.source_before_79a4b8b(path, raw, 'direct_source_inverse')
        read = Path.read_bytes
        direct_stimuli = [(p, 'fn ' + n + '(') for p, names in direct['added_default_methods'].items() for n in names]
        direct_stimuli += [(p, literal) for p, literals in direct['module_chains'].items() for literal in literals]
        for path, literal in direct_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('direct declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Twelve incoming top-level tests; nested child summaries are not new tests.
        shared = current.DATA['source_successor_3217b8ed']
        shared_prior = current.before_3217b8ed(actual)
        shared_rows = direct_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(shared_prior), current.SHARED_PREVIOUS)
        self.assertEqual((len(shared_rows), sum(x['tests'] for x in shared_rows.values()),
                          sum(x['ignored'] for x in shared_rows.values())), (122, 4627, 43))
        self.assertEqual((shared['default_method_additions'], shared['new_method_declarations'],
                          shared['default_method_removals'], shared['default_harness_changes'],
                          shared['default_ignore_changes'], shared['default_doctest_additions'],
                          shared['recorder_identity_changes'], shared['feature_method_additions'],
                          shared['feature_method_removals']), (12, 12, 0, 2, 0, 0, 0, 0, 0))
        self.assertEqual(shared['added_default_methods'], {'crates/liteinst-x86/src/tests.rs': ['selected_register_facts_preserve_every_width_and_rsp', 'decode_preserves_status_and_leaves_adapter_policy_unapplied', 'exact_form_and_mnemonic_views_remain_distinct'], 'src/control_flow/tests.rs': ['local_edges_keep_callees_multiplicity_and_padding_partitions_distinct', 'unresolved_rows_and_public_dimensions_refuse_without_reordering_callbacks'], 'src/quiescent/feasibility/tests.rs': ['staged_geometry_matches_predecessor_and_refuses_malformed_public_inputs', 'rel32_constraints_preserve_ordered_alphabet_and_all_mask_conflicts', 'actual_core_keeps_first_refusal_and_exact_qualification_evidence'], 'src/quiescent/whole_function/cfg_tests.rs': ['shared_whole_graph_preserves_profile_and_combined_fault_precedence'], 'tools/elf-rewrite/examples/common_sites.rs': ['shared_patterns_match_complete_predecessor_inventory_and_padding_cases'], 'tools/elf-rewrite/src/neighbor_catalogue_cfg_tests.rs': ['shared_neighbor_graph_preserves_broad_transfer_forms_and_first_errors'], 'tools/rapid-profiler/src/frontend_native/ordinary/cfg_shared_tests.rs': ['shared_cfg_preserves_complete_certificates_and_hostile_refusals']})
        self.assertEqual(shared['default_method_instances'], {'crates/liteinst-x86/src/tests.rs': ['unit/liteinst_x86/lib'], 'src/control_flow/tests.rs': ['unit/liteinst2/lib'], 'src/quiescent/feasibility/tests.rs': ['unit/liteinst2/lib'], 'src/quiescent/whole_function/cfg_tests.rs': ['unit/liteinst2/lib'], 'tools/elf-rewrite/examples/common_sites.rs': ['unit/common_sites/common_sites'], 'tools/elf-rewrite/src/neighbor_catalogue_cfg_tests.rs': ['unit/liteinst_rewrite/lib'], 'tools/rapid-profiler/src/frontend_native/ordinary/cfg_shared_tests.rs': ['unit/rapid_profiler/lib']})
        self.assertEqual((shared['added_feature_methods'], shared['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(shared['source_paths']), len(shared['source_projections'])), (26, 26))
        self.assertEqual(shared['new_sources'], ['crates/liteinst-x86/Cargo.toml', 'crates/liteinst-x86/src/lib.rs', 'crates/liteinst-x86/src/tests.rs', 'src/control_flow.rs', 'src/control_flow/tests.rs', 'src/quiescent/feasibility.rs', 'src/quiescent/feasibility/tests.rs', 'src/quiescent/whole_function/cfg_tests.rs', 'tools/elf-rewrite/src/neighbor_catalogue_cfg_tests.rs', 'tools/rapid-profiler/src/frontend_native/ordinary/cfg_shared_tests.rs'])
        self.assertEqual(current.DATA['doctests']['crates/liteinst-x86/src/lib.rs'], [])
        self.assertEqual(shared_rows['unit/liteinst_x86/lib'], counts(3))
        self.assertEqual(shared_rows['doc/liteinst_x86'], counts(0))
        self.assertNotIn('unit/liteinst_x86/lib', shared_prior['harness_test_counts']['workspace_tests'])
        self.assertNotIn('doc/liteinst_x86', shared_prior['harness_test_counts']['workspace_tests'])
        self.assertEqual(shared_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], shared_prior['recorder_tests']), (366, 366))
        for name, change in shared['workspace_changes'].items():
            self.assertEqual(shared_rows[name], change['current'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(shared_rows[name][field]), shared_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_3217b8ed(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_3217b8ed(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_3217b8ed(shared_prior)
        for path, row in shared['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_3217b8ed(path, raw, 'shared_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (shared['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in shared['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^shared_source_inverse$'):
                    current.source_before_3217b8ed(path, wrong, 'shared_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(shared['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^shared_source_inverse$'):
                        current.source_before_3217b8ed(path, raw, 'shared_source_inverse')
        read = Path.read_bytes
        shared_stimuli = [(p, 'fn ' + n + '(') for p, names in shared['added_default_methods'].items() for n in names]
        shared_stimuli += [(p, literal) for p, literals in shared['module_chains'].items() for literal in literals]
        for path, literal in shared_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('shared declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Five incoming default tests preserve every older catalog and test gate.
        flat = current.DATA['source_successor_03ed2c31']
        flat_prior = current.before_03ed2c31(actual)
        flat_rows = shared_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(flat_prior), current.FLAT_PREVIOUS)
        self.assertEqual((len(flat_rows), sum(x['tests'] for x in flat_rows.values()),
                          sum(x['ignored'] for x in flat_rows.values())), (120, 4615, 43))
        self.assertEqual(flat_rows['unit/rapid_profiler/lib'], counts(634, 37))
        self.assertEqual(flat_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(629, 37))
        self.assertEqual((flat['default_method_additions'], flat['new_method_declarations'],
                          flat['default_method_removals'], flat['default_harness_changes'],
                          flat['default_ignore_changes'], flat['default_doctest_additions'],
                          flat['recorder_identity_changes'], flat['feature_method_additions'],
                          flat['feature_method_removals']), (5, 5, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(flat['added_default_methods'], {'tools/rapid-profiler/src/frontend/interval_entry/tests.rs': ['checked_exit_preserves_actual_receipt_refusals_and_owner_followthrough', 'checked_exit_drop_and_actual_completion_hooks_preserve_partial_state'], 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/qualification/tests.rs': ['flat_witness_matches_typed_encoder_across_receipts_rearm_and_sparse_reset', 'flat_witness_copies_all_journal_words_and_keeps_actual_receipt_independent', 'flat_witness_preserves_refusals_sequence_panic_and_borrow_boundary']})
        self.assertEqual(flat['default_method_instances'],
                         {p: ['unit/rapid_profiler/lib'] for p in flat['added_default_methods']})
        self.assertEqual((flat['added_feature_methods'], flat['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(flat['source_paths']), len(flat['source_projections'])), (7, 7))
        self.assertEqual(flat['new_sources'], ['tools/rapid-profiler/src/frontend/completion.rs'])
        self.assertEqual(flat['newly_bound_sources'], [
            'tools/rapid-profiler/src/frontend/completion.rs',
            'tools/rapid-profiler/src/frontend/interval_entry/tests.rs'])
        self.assertEqual(flat_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], flat_prior['recorder_tests']), (366, 366))
        for path, row in flat['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_03ed2c31(path, raw, 'flat_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (flat['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in flat['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^flat_source_inverse$'):
                    current.source_before_03ed2c31(path, wrong, 'flat_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(flat['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^flat_source_inverse$'):
                        current.source_before_03ed2c31(path, raw, 'flat_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_03ed2c31(flat_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(actual['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field]),
                          actual['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_03ed2c31(wrong)
        wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_03ed2c31(wrong)
        read = Path.read_bytes
        flat_stimuli = [(p, 'fn ' + n + '(') for p, names in flat['added_default_methods'].items() for n in names]
        flat_stimuli += [(p, literal) for p, literals in flat['module_chains'].items() for literal in literals]
        for path, literal in flat_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('flat declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # The two row-prefix methods are ordinary default library tests.
        # Preserve the complete fe97 catalog and every historical source target.
        row_prefix = current.DATA['source_successor_4261826']
        row_prefix_prior = current.before_4261826(actual)
        row_prefix_rows = flat_prior['harness_test_counts']['workspace_tests']
        row_prefix_path = 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs'
        self.assertEqual(current.digest(row_prefix_prior), current.ROW_PREFIX_PREVIOUS)
        self.assertEqual((len(row_prefix_rows), sum(x['tests'] for x in row_prefix_rows.values()),
                          sum(x['ignored'] for x in row_prefix_rows.values())), (120, 4610, 43))
        self.assertEqual(row_prefix_rows['unit/rapid_profiler/lib'], counts(629, 37))
        self.assertEqual(row_prefix_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(627, 37))
        self.assertEqual((row_prefix['default_method_additions'], row_prefix['new_method_declarations'],
                          row_prefix['default_method_removals'], row_prefix['default_harness_changes'],
                          row_prefix['default_ignore_changes'], row_prefix['default_doctest_additions'],
                          row_prefix['recorder_identity_changes'], row_prefix['feature_method_additions'],
                          row_prefix['feature_method_removals']), (2, 2, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(row_prefix['added_default_methods'], {row_prefix_path: [
            'row_prefix_matches_full_shape_at_each_position_and_receipt_kind',
            'row_prefix_preserves_current_overflow_and_earlier_row_error_order']})
        self.assertEqual(row_prefix['default_method_instances'], {row_prefix_path: ['unit/rapid_profiler/lib']})
        self.assertEqual((row_prefix['added_feature_methods'], row_prefix['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(row_prefix['source_paths']), len(row_prefix['source_projections'])), (2, 2))
        self.assertEqual(row_prefix_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], row_prefix_prior['recorder_tests']), (366, 366))
        for path, row in row_prefix['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_4261826(path, raw, 'row_prefix_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (row_prefix['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'],
                             current.DATA['source_successor_f9f89ac']['sources'][path]
                             if path in current.DATA['source_successor_f9f89ac']['sources'] else
                             current.DATA['source_successor_bad32a8']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^row_prefix_source_inverse$'):
                    current.source_before_4261826(path, wrong, 'row_prefix_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(row_prefix['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^row_prefix_source_inverse$'):
                        current.source_before_4261826(path, raw, 'row_prefix_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_4261826(row_prefix_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(row_prefix_rows['unit/rapid_profiler/lib'][field]),
                          row_prefix_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_4261826(wrong)
        wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_4261826(wrong)
        read = Path.read_bytes
        row_prefix_stimuli = [(row_prefix_path, 'fn ' + name + '(')
                             for name in row_prefix['added_default_methods'][row_prefix_path]]
        row_prefix_stimuli += [(path, literal) for path, literals in row_prefix['module_chains'].items()
                              for literal in literals]
        for path, literal in row_prefix_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('row-prefix declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # The current publisher adds two feature-only declarations; the entire
        # default catalog and every historical source target remain exact.
        publisher = current.DATA['source_successor_fe97f683']
        publisher_path = 'tools/rapid-profiler/native-interval/normal/module/early_entry/publisher.rs'
        self.assertEqual((publisher['default_method_additions'], publisher['default_method_removals'],
                          publisher['default_harness_changes'], publisher['default_ignore_changes'],
                          publisher['default_doctest_additions'], publisher['recorder_identity_changes'],
                          publisher['feature_method_additions'], publisher['feature_method_removals']),
                         (0, 0, 0, 0, 0, 0, 2, 0))
        self.assertEqual(publisher['added_feature_methods'], {publisher_path: [
            'avx2_selection_requires_every_actual_image_and_complete_ymm_state',
            'selected_publisher_preserves_all640_cells_resets_partition_and_alignment']})
        self.assertEqual(publisher['feature_method_instances'], {publisher_path: [
            'test/frontend_native_calibrations [frontend-native-qualification]']})
        self.assertEqual((publisher['added_default_methods'], publisher['added_ignored_methods'],
                          publisher['workspace_changes']), ({}, {}, {}))
        self.assertEqual((publisher['current_corpus_sha256'], publisher['previous_corpus_sha256']),
                         (current.ROW_PREFIX_PREVIOUS, current.ROW_PREFIX_PREVIOUS))
        self.assertEqual(current.digest(actual), current.CURRENT)
        self.assertEqual((len(publisher['source_paths']), len(publisher['source_projections'])), (2, 2))
        self.assertEqual(current.DATA['methods'][publisher_path]['all'],
                         current.DATA['source_successor_65ee8ea']['feature_only_methods'][publisher_path]
                         + publisher['added_feature_methods'][publisher_path])
        for path, literals in publisher['module_chains'].items():
            self.assertEqual(literals, current.DATA['module_chains'][path])
            text = (current.ROOT / path).read_text()
            self.assertTrue(all(text.count(literal) == 1 for literal in literals))
        for path, row in publisher['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_fe97f683(path, raw, 'publisher_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (publisher['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'], current.DATA['source_successor_e691b0d']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^publisher_source_inverse$'):
                    current.source_before_fe97f683(path, wrong, 'publisher_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(publisher['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^publisher_source_inverse$'):
                        current.source_before_fe97f683(path, raw, 'publisher_source_inverse')
        read = Path.read_bytes
        target = current.ROOT / publisher_path
        raw = read(target)
        for name in publisher['added_feature_methods'][publisher_path]:
            literal = ('fn ' + name + '(').encode()
            self.assertEqual(raw.count(literal), 1)
            wrong = raw.replace(literal, ('fn ' + name + '_wrong(').encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {publisher_path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != publisher_path else (_ for _ in ()).throw(AssertionError('publisher declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Immutable binding and completed-PC diagnostics add six default instances.
        binding = current.DATA['source_successor_f9f89ac']
        binding_prior = current.before_f9f89ac(actual)
        binding_rows = row_prefix_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(binding_prior), current.BINDING_PREVIOUS)
        self.assertEqual((len(binding_rows), sum(x['tests'] for x in binding_rows.values()),
                          sum(x['ignored'] for x in binding_rows.values())), (120, 4608, 43))
        self.assertEqual({name: binding_rows[name] for name in binding['workspace_changes']}, {
            'unit/rapid_profiler/lib': counts(627, 37),
            'test/frontend_native_calibrations': counts(238, 1),
            'unit/ordinary_interval/main': counts(523, 1)})
        self.assertEqual((binding['default_method_additions'], binding['new_method_declarations'],
                          binding['default_method_removals'], binding['default_harness_changes'],
                          binding['default_ignore_changes'], binding['default_doctest_additions'],
                          binding['recorder_identity_changes'], binding['feature_method_additions'],
                          binding['feature_method_removals']), (6, 4, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(binding['added_default_methods'], {'tests/support/native_normal_module/early_entry/pc_counts.rs': ['counts_only_completed_transitions_and_preserves_each_pc', 'capacity_exhaustion_counts_drops_without_growing_or_losing_records'], 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/binding_envelope.rs': ['binding_envelope_preserves_malformed_profiles_and_fresh_error_order', 'binding_envelope_replacement_revalidates_and_retains_exact_arc']})
        self.assertEqual(binding['default_method_instances'], {'tests/support/native_normal_module/early_entry/pc_counts.rs': ['test/frontend_native_calibrations', 'unit/ordinary_interval/main'], 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/binding_envelope.rs': ['unit/rapid_profiler/lib']})
        self.assertEqual(sum(len(names) * len(binding['default_method_instances'][path])
                             for path, names in binding['added_default_methods'].items()), 6)
        self.assertEqual(binding['added_ignored_methods'], {})
        self.assertEqual((len(binding['source_paths']), len(binding['source_projections'])), (5, 3))
        self.assertEqual([path for path, value in binding['source_preimages'].items() if value is None],
                         ['tests/support/native_normal_module/early_entry/pc_counts.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/binding_envelope.rs'])
        self.assertEqual(binding_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], binding_prior['recorder_tests']), (366, 366))
        for path, row in binding['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_f9f89ac(path, raw, 'binding_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (binding['source_preimages'][path]['bytes'], row['previous_sha256']))
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^binding_source_inverse$'):
                    current.source_before_f9f89ac(path, wrong, 'binding_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(binding['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^binding_source_inverse$'):
                        current.source_before_f9f89ac(path, raw, 'binding_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_f9f89ac(binding_prior)
        for name in binding['workspace_changes']:
            for field in ('tests', 'ignored'):
                for value in (None, True, float(binding_rows[name][field]), binding_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_f9f89ac(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_f9f89ac(wrong)
        read = Path.read_bytes
        binding_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in binding['added_default_methods'].items() for name in names]
        binding_stimuli += [(path, literal, '')
            for path, literals in binding['module_chains'].items() for literal in literals]
        for path, literal, replacement in binding_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('binding declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in binding['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # Current-RET geometry adds two default tests; the complete physical
        # predecessor and every earlier historical target stay exact.
        current_ret = current.DATA['source_successor_bad32a8']
        current_ret_prior = current.before_bad32a8(actual)
        current_ret_rows = binding_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(current_ret_prior), current.CURRENT_RET_PREVIOUS)
        self.assertEqual((len(current_ret_rows), sum(x['tests'] for x in current_ret_rows.values()),
                          sum(x['ignored'] for x in current_ret_rows.values())), (120, 4602, 43))
        self.assertEqual(current_ret_rows['unit/rapid_profiler/lib'], counts(625, 37))
        self.assertEqual(current_ret_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(623, 37))
        self.assertEqual(current_ret_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((current_ret['default_method_additions'], current_ret['default_method_removals'],
                          current_ret['default_harness_changes'], current_ret['default_ignore_changes'],
                          current_ret['default_doctest_additions'], current_ret['recorder_identity_changes'],
                          current_ret['feature_method_additions'], current_ret['feature_method_removals']),
                         (2, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(current_ret['added_default_methods'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs': [
                'current_ret_geometry_preserves_paired_late_refusals_and_receipts',
                'current_ret_geometry_uses_actual_validation_with_foreign_rows_and_rearm']})
        self.assertEqual(current_ret['default_method_instances'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs':
                ['unit/rapid_profiler/lib']})
        self.assertEqual(sum(len(names) * len(current_ret['default_method_instances'][path])
                             for path, names in current_ret['added_default_methods'].items()), 2)
        self.assertEqual(current_ret['added_ignored_methods'], {})
        self.assertEqual((len(current_ret['source_paths']), len(current_ret['source_projections'])), (3, 3))
        self.assertTrue(all(value is not None for value in current_ret['source_preimages'].values()))
        self.assertEqual(current_ret_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], current_ret_prior['recorder_tests']), (366, 366))
        for path, row in current_ret['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_bad32a8(path, raw, 'current_ret_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (current_ret['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'], current.DATA['source_successor_e5462b7']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^current_ret_source_inverse$'):
                    current.source_before_bad32a8(path, wrong, 'current_ret_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(current_ret['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^current_ret_source_inverse$'):
                        current.source_before_bad32a8(path, raw, 'current_ret_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_bad32a8(current_ret_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(current_ret_rows['unit/rapid_profiler/lib'][field]),
                          current_ret_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_bad32a8(wrong)
        wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_bad32a8(wrong)
        read = Path.read_bytes
        current_ret_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in current_ret['added_default_methods'].items() for name in names]
        current_ret_stimuli += [(path, literal, '')
            for path, literals in current_ret['module_chains'].items() for literal in literals]
        for path, literal, replacement in current_ret_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('current-RET declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Physical slots and retained geometry add seven default library tests.
        # The complete e691 catalog and every earlier source target remain exact.
        physical = current.DATA['source_successor_e5462b7']
        physical_prior = current.before_e5462b7(actual)
        physical_rows = current_ret_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(physical_prior), current.PHYSICAL_PREVIOUS)
        self.assertEqual((len(physical_rows), sum(x['tests'] for x in physical_rows.values()),
                          sum(x['ignored'] for x in physical_rows.values())), (120, 4600, 43))
        self.assertEqual(physical_rows['unit/rapid_profiler/lib'], counts(623, 37))
        self.assertEqual(physical_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(616, 37))
        self.assertEqual(physical_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((physical['default_method_additions'], physical['default_method_removals'],
                          physical['default_harness_changes'], physical['default_ignore_changes'],
                          physical['default_doctest_additions'], physical['recorder_identity_changes'],
                          physical['feature_method_additions'], physical['feature_method_removals']),
                         (7, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(physical['added_default_methods'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs': [
                'physical_occupancy_matches_original_for_all_6480_metadata_patterns',
                'physical_occupancy_matches_original_live_prefixes_and_rearm',
                'geometry_facts_match_original_across_masks_rearm_and_reset',
                'geometry_facts_require_exact_owner_and_key_and_invalidate_on_replacement',
                'geometry_facts_preserve_original_geometry_error_precedence'],
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/physical_slots.rs': [
                'all_occupancies_and_replacements_match_original_array_queries',
                'out_of_range_replacements_preserve_all_values_masks_and_counts']})
        self.assertEqual(physical['default_method_instances'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs':
                ['unit/rapid_profiler/lib'],
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/physical_slots.rs':
                ['unit/rapid_profiler/lib']})
        self.assertEqual(sum(len(names) * len(physical['default_method_instances'][path])
                             for path, names in physical['added_default_methods'].items()), 7)
        self.assertEqual(physical['added_ignored_methods'], {})
        self.assertEqual((len(physical['source_paths']), len(physical['source_projections'])), (7, 6))
        self.assertEqual([path for path, value in physical['source_preimages'].items() if value is None],
                         ['tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/physical_slots.rs'])
        self.assertEqual(physical_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], physical_prior['recorder_tests']), (366, 366))
        for path, row in physical['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_e5462b7(path, raw, 'physical_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (physical['source_preimages'][path]['bytes'], row['previous_sha256']))
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^physical_source_inverse$'):
                    current.source_before_e5462b7(path, wrong, 'physical_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = inventory_copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(physical['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^physical_source_inverse$'):
                        current.source_before_e5462b7(path, raw, 'physical_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e5462b7(physical_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(physical_rows['unit/rapid_profiler/lib'][field]),
                          physical_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_e5462b7(wrong)
        wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e5462b7(wrong)
        read = Path.read_bytes
        physical_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in physical['added_default_methods'].items() for name in names]
        physical_stimuli += [(path, literal, '')
            for path, literals in physical['module_chains'].items() for literal in literals]
        for path, literal, replacement in physical_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in physical['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # The entry post-shape proof adds exactly two default library tests.
        # Changed feature-only publisher code contributes no new test methods.
        entry_normal = current.DATA['source_successor_e691b0d']
        entry_normal_prior = current.before_e691b0d(actual)
        entry_normal_rows = physical_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(entry_normal_prior), current.ENTRY_PROOF_PREVIOUS)
        self.assertEqual((len(entry_normal_rows), sum(x['tests'] for x in entry_normal_rows.values()),
                          sum(x['ignored'] for x in entry_normal_rows.values())), (120, 4593, 43))
        self.assertEqual(entry_normal_rows['unit/rapid_profiler/lib'], counts(616, 37))
        self.assertEqual(entry_normal_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(614, 37))
        self.assertEqual(entry_normal_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((entry_normal['default_method_additions'], entry_normal['default_method_removals'],
                          entry_normal['default_harness_changes'], entry_normal['default_ignore_changes'],
                          entry_normal['default_doctest_additions'], entry_normal['recorder_identity_changes'],
                          entry_normal['feature_method_additions'], entry_normal['feature_method_removals']),
                         (2, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(entry_normal['added_default_methods'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs': [
                'entry_normal_proof_matches_full_postshape_across_receipts_and_rearm',
                'entry_normal_proof_keeps_changed_fields_depth_and_late_error_order']})
        self.assertEqual(sum(len(names) * len(entry_normal['default_method_instances'][path])
                             for path, names in entry_normal['added_default_methods'].items()), 2)
        self.assertEqual(entry_normal['default_method_instances'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs':
                ['unit/rapid_profiler/lib']})
        self.assertEqual(entry_normal['unchanged_feature_only_methods'],
                         current.DATA['source_successor_65ee8ea']['feature_only_methods'])
        self.assertEqual(sum(map(len, entry_normal['unchanged_feature_only_methods'].values())), 3)
        self.assertEqual(entry_normal['added_ignored_methods'], {})
        self.assertEqual((len(entry_normal['source_paths']), len(entry_normal['source_projections'])), (4, 4))
        self.assertEqual(entry_normal_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], entry_normal_prior['recorder_tests']), (366, 366))
        for path, row in entry_normal['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_e691b0d(path, raw, 'entry_normal_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (entry_normal['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'], current.DATA['source_successor_65ee8ea']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^entry_normal_source_inverse$'):
                    current.source_before_e691b0d(path, wrong, 'entry_normal_source_inverse')
            malformed = inventory_copy.deepcopy(row)
            malformed['edits'][0][2] += '\n'
            with patch.dict(entry_normal['source_projections'], {path: malformed}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^entry_normal_source_inverse$'):
                    current.source_before_e691b0d(path, raw, 'entry_normal_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e691b0d(entry_normal_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(entry_normal_rows['unit/rapid_profiler/lib'][field]),
                          entry_normal_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_e691b0d(wrong)
        wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e691b0d(wrong)
        wrong = inventory_copy.deepcopy(actual)
        wrong['harness_test_counts']['workspace_tests']['test/frontend_native_calibrations'] = counts(239, 1)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e691b0d(wrong)
        read = Path.read_bytes
        entry_normal_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for group in ('added_default_methods', 'unchanged_feature_only_methods')
            for path, names in entry_normal[group].items() for name in names]
        entry_normal_stimuli += [(path, literal, '')
            for path, literals in entry_normal['module_chains'].items() for literal in literals]
        for path, literal, replacement in entry_normal_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in entry_normal['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # Current RET proofs add ten default tests; the publisher's three tests
        # remain feature-only and cannot increase the default calibration row.
        ret = current.DATA['source_successor_65ee8ea']
        ret_prior = current.before_65ee8ea(actual)
        ret_rows = entry_normal_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(ret_prior), current.RET_PROOF_PREVIOUS)
        self.assertEqual((len(ret_rows), sum(x['tests'] for x in ret_rows.values()),
                          sum(x['ignored'] for x in ret_rows.values())), (120, 4591, 43))
        self.assertEqual(ret_rows['unit/rapid_profiler/lib'], counts(614, 37))
        self.assertEqual(ret_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(604, 37))
        self.assertEqual(ret_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((ret['default_method_additions'], ret['default_method_removals'],
                          ret['default_harness_changes'], ret['default_ignore_changes'],
                          ret['default_doctest_additions'], ret['recorder_identity_changes']),
                         (10, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(ret['default_method_instances'][path])
                             for path, names in ret['added_default_methods'].items()), 10)
        self.assertEqual(sum(map(len, ret['feature_only_methods'].values())), 3)
        self.assertEqual(ret['added_ignored_methods'], {})
        self.assertEqual((len(ret['source_paths']), len(ret['source_projections'])), (5, 4))
        self.assertEqual([path for path, value in ret['source_preimages'].items() if value is None],
                         ['tools/rapid-profiler/native-interval/normal/module/early_entry/publisher.rs'])
        self.assertEqual(ret_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        for path, row in ret['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_65ee8ea(path, raw, 'ret_proof_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (ret['source_preimages'][path]['bytes'], row['previous_sha256']))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ret_proof_source_inverse$'):
                current.source_before_65ee8ea(path, raw + b'\n', 'ret_proof_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_65ee8ea(ret_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(ret_rows['unit/rapid_profiler/lib'][field]),
                          ret_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_65ee8ea(wrong)
        wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_65ee8ea(wrong)
        wrong = inventory_copy.deepcopy(actual)
        wrong['harness_test_counts']['workspace_tests']['test/frontend_native_calibrations'] = counts(239, 1)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_65ee8ea(wrong)
        read = Path.read_bytes
        ret_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for group in ('added_default_methods', 'feature_only_methods')
            for path, names in ret[group].items() for name in names]
        ret_stimuli += [(path, literal, '')
            for path, literals in ret['module_chains'].items() for literal in literals]
        for path, literal, replacement in ret_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in ret['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # The later snapshot implementation adds three tests in the same
        # Rapid library. Its prior source and complete catalog stay explicit.
        snapshot = current.DATA['source_successor_79b34bc']
        snapshot_prior = current.before_79b34bc(actual)
        snapshot_rows = ret_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(snapshot_prior), current.ENTRY_ADMISSION_CURRENT)
        self.assertEqual((len(snapshot_rows), sum(x['tests'] for x in snapshot_rows.values()),
                          sum(x['ignored'] for x in snapshot_rows.values())), (120, 4581, 43))
        self.assertEqual((snapshot['default_method_additions'], snapshot['default_method_removals'],
                          snapshot['default_harness_changes'], snapshot['default_ignore_changes'],
                          snapshot['default_doctest_additions'], snapshot['recorder_identity_changes']),
                         (3, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(snapshot['default_method_instances'][path])
                             for path, names in snapshot['added_default_methods'].items()), 3)
        self.assertEqual(snapshot_rows['unit/rapid_profiler/lib'], counts(604, 37))
        self.assertEqual(snapshot_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(601, 37))
        self.assertEqual(snapshot['added_ignored_methods'], {})
        for path, row in snapshot['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_79b34bc(path, raw, 'snapshot_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (snapshot['source_preimages'][path]['bytes'], row['previous_sha256']))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^snapshot_source_inverse$'):
                current.source_before_79b34bc(path, raw + b'\n', 'snapshot_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_79b34bc(snapshot_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(snapshot_rows['unit/rapid_profiler/lib'][field]),
                          snapshot_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_79b34bc(wrong)
        wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_79b34bc(wrong)
        read = Path.read_bytes
        snapshot_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in snapshot['added_default_methods'].items() for name in names]
        snapshot_stimuli += [(path, literal, '')
            for path, literals in snapshot['module_chains'].items() for literal in literals]
        for path, literal, replacement in snapshot_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in snapshot['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # Keep the merged typed entry-admission catalog distinct from every
        # earlier boundary, including its four explicitly ignored native tests.
        entry = current.DATA['source_successor_a8acec5']
        entry_prior = current.before_a8acec5(actual)
        entry_rows = snapshot_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(entry_prior), current.ENTRY_ADMISSION_PREVIOUS)
        self.assertEqual((len(entry_rows), sum(x['tests'] for x in entry_rows.values()),
                          sum(x['ignored'] for x in entry_rows.values())), (120, 4578, 43))
        self.assertEqual((entry['default_method_additions'], entry['default_doctest_additions'],
                          entry['default_method_removals'], entry['default_harness_changes'],
                          entry['default_ignore_changes'], entry['recorder_identity_changes']),
                         (33, 1, 0, 1, 4, 0))
        self.assertEqual(sum(len(names) * len(entry['default_method_instances'][path])
                             for path, names in entry['added_default_methods'].items()), 33)
        self.assertEqual(sum(map(len, entry['added_default_methods'].values())), 30)
        self.assertEqual(entry['default_method_instances']['tests/support/native_normal_module/early_entry.rs'],
                         ['test/frontend_native_calibrations', 'unit/ordinary_interval/main'])
        self.assertEqual(entry_rows['unit/ordinary_interval/main'], counts(521, 1))
        self.assertEqual(entry_prior['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'],
                         counts(518, 1))
        self.assertEqual(sum(len(names) for names in entry['added_ignored_methods'].values()), 4)
        self.assertEqual(sum(len(blocks) for blocks in entry['doctests'].values()), 1)
        self.assertEqual(entry_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], entry_prior['recorder_tests']), (366, 366))
        for path, row in entry['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_a8acec5(path, raw, 'entry_admission_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (entry['source_preimages'][path]['bytes'], row['previous_sha256']))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^entry_admission_source_inverse$'):
                current.source_before_a8acec5(path, raw + b'\n', 'entry_admission_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_a8acec5(entry_prior)
        for name, change in entry['workspace_changes'].items():
            self.assertEqual(entry_rows[name], change['current'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(entry_rows[name][field]), entry_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_a8acec5(wrong)
            wrong = inventory_copy.deepcopy(actual)
            del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_a8acec5(wrong)
        read = Path.read_bytes
        entry_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in entry['added_default_methods'].items() for name in names]
        entry_stimuli += [(path, literal, '')
            for path, literals in entry['module_chains'].items() for literal in literals]
        entry_stimuli += [(path, block, replacement)
            for path, blocks in entry['doctests'].items() for block in blocks
            for replacement in ('', block + '\n' + block, block.replace('compile_fail,E0277', 'ignore'))]
        entry_stimuli += [tuple(row) for row in entry['ignore_stimuli']]
        for path, literal, replacement in entry_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('entry-admission declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in entry['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # The merged benchmark contributes three real tests in one new harness.
        # Preserve the whole earlier catalog as a distinct, refused predecessor.
        point_prior = current.before_e5ab521(actual)
        point_rows = entry_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(point_prior), current.POINT_PREVIOUS)
        self.assertEqual((len(point_rows), sum(x['tests'] for x in point_rows.values()),
                          sum(x['ignored'] for x in point_rows.values())), (119, 4544, 39))
        self.assertEqual(point_rows['unit/point_throughput/main'], dict(tests=3, ignored=0))
        self.assertEqual(point_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e5ab521(point_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(point_rows['unit/point_throughput/main'][field]),
                          point_rows['unit/point_throughput/main'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/point_throughput/main'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_e5ab521(wrong)
        native_indexed = current.before_29859(actual)
        rows = native_indexed['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (112, 4255, 37))
        self.assertEqual(current.digest(native_indexed), current.NATIVE_INDEXED_CURRENT)
        phase_catalog = current.before_96378(actual)
        rows = phase_catalog['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (112, 4266, 37))
        self.assertEqual(current.DATA['default_test_additions'], 58)
        self.assertEqual(current.DATA['default_harness_changes'], 0)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual((actual['recorder_tests'], old['recorder_tests']), (366, 365))
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        with patch.object(inventory, 'require_historical365') as earlier:
            self.assertIsNone(inventory.require_current(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainf353_inventory_differs$'):
            previous.before_current(actual)
        self.assertEqual(previous.peel_current(actual, 'catalog_control', 'source_control'), previous.before_current(old))
        for key in actual:
            wrong = inventory_copy.deepcopy(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_current(wrong)
        for name in current.DATA['workspace_changes']:
            for field in ('tests', 'ignored'):
                for value in (rows[name][field]+1, True, float(rows[name][field])):
                    wrong = inventory_copy.deepcopy(actual); wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_current(wrong)
        identities = historical.python_identities(Path(__file__).parent)
        old_ids = current.before_python(identities)
        self.assertEqual((len(identities), len(old_ids)), (366, 365))
        self.assertEqual(current.digest(old_ids), previous.PYTHON_CURRENT)
        self.assertEqual(set(identities)-set(old_ids), {current.ADDED})
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainf353_python_inventory_differs$'):
            previous.before_python(identities)
        for wrong in (old_ids, identities+[identities[0]], list(reversed(identities))):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_python_inventory_differs$'):
                current.before_python(wrong)
        read = Path.read_bytes
        for kind, function in (('projections', current.source_before),
                               ('evaluation_projections', current.source_before_evaluation)):
            for path, row in current.DATA[kind].items():
                raw = read(current.ROOT/path)
                restored = function(path, raw, 'indexed_inverse_control')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
                for wrong in (raw+b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^indexed_inverse_control$'):
                        function(path, wrong, 'indexed_inverse_control')
                bad = inventory_copy.deepcopy(row); bad['edits'][0][2] += '\n'
                with patch.dict(current.DATA[kind], {path:bad}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^indexed_bad_inverse_control$'):
                        function(path, raw, 'indexed_bad_inverse_control')
        self.assertEqual(sum(len(current.DATA['added_default_methods'][p])*len(v)
            for p,v in current.DATA['default_method_instances'].items()), 58)
        stimuli = [(p, names[0], names[0]+'_wrong') for p,names in current.DATA['added_default_methods'].items()]
        stimuli += [(p, values[0], '') for p,values in current.DATA['module_chains'].items()]
        for path, before, after in stimuli:
            target = current.ROOT/path; raw = read(target)
            self.assertEqual(raw.count(before.encode()), 1)
            wrong = raw.replace(before.encode(), after.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path:hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('indexed declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in current.DATA['added_default_methods']:
            target = current.ROOT/path; raw = read(target)
            def changed(candidate): return raw+b'\n' if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Repair the outer hashes coherently so old declaration gates must fire.
        probes = (
            ('tools/elf-rewrite/examples/indexed_dso_support/elf.rs',
             'complete_symbol_snapshot_retains_hidden_and_localized_forms_and_exact_owners'),
            ('tools/elf-rewrite/tests/indexed_dso_source.rs',
             '#[path = "../examples/indexed_dso_support/caller.rs"]\nmod caller;'),
        )
        self.assertEqual(len(probes), 2)
        for path, literal in probes:
            target = current.ROOT / path; raw = read(target)
            prior = current.source_before(path, raw, 'native_indexed_old_inverse')
            self.assertEqual(hashlib.sha256(prior).hexdigest(), previous.DATA['sources'][path])
            self.assertEqual((raw.count(literal.encode()), prior.count(literal.encode())), (1, 1))
            altered = literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            changed_raw = raw.replace(literal.encode(), altered.encode())
            changed_prior = prior.replace(literal.encode(), altered.encode())
            self.assertNotEqual(changed_raw, raw)
            row = inventory_copy.deepcopy(current.DATA['projections'][path])
            row['current_sha256'] = hashlib.sha256(changed_raw).hexdigest()
            row['previous_sha256'] = hashlib.sha256(changed_prior).hexdigest()
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.dict(current.DATA['projections'], {path: row}):
                self.assertEqual(current.source_before(path, changed_raw,
                    'native_indexed_old_inverse'), changed_prior)
                with patch.object(Path, 'read_bytes', changed), \
                     patch.dict(previous.DATA['sources'], {path: hashlib.sha256(changed_prior).hexdigest()}), \
                     patch.object(previous, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('historical declaration gate omitted'))):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainf353_source_inventory_differs$'):
                        previous.require_sources()
        self.assertEqual(current.DATA['native_example'], dict(
            name='indexed_dso_native', test=False, bench=False, default_test_harness=False))
        self.assertNotIn('unit/indexed_dso_native/indexed_dso_native', rows)

        # Exact current phase diagnostics add eleven real tests in the existing
        # harness. The old native-indexed whole catalog remains a predecessor,
        # never an alternative accepted by the current qualification entrypoint.
        phase = current.DATA['source_successor_29859']
        self.assertEqual((phase['default_method_additions'], phase['default_method_removals'],
                          phase['default_harness_changes'], phase['default_ignore_changes'],
                          phase['recorder_identity_changes']), (11, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) for names in phase['added_default_methods'].values()), 11)
        self.assertEqual(phase['default_method_instances'], {
            path: ['unit/ordinary_interval/main'] for path in phase['added_default_methods']})
        self.assertEqual(entry_prior['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'],
                         dict(tests=518, ignored=1))
        self.assertEqual(native_indexed['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'],
                         dict(tests=507, ignored=1))
        for wrong in (native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_29859(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(rows['unit/ordinary_interval/main'][field]),
                          rows['unit/ordinary_interval/main'][field] + 1):
                wrong = inventory_copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'][field] = value
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_29859(wrong)
        new_stimuli = [(path, name, name + '_wrong')
                       for path, names in phase['added_default_methods'].items() for name in names]
        new_stimuli += [(path, literal, '')
                        for path, literals in phase['module_chains'].items() for literal in literals]
        self.assertEqual(len(new_stimuli), 22)
        for path, literal, replacement in new_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            # Repair the outer hash so the declaration/module gate, rather
            # than the inverse or stale whole-file pin, must reject the change.
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('phase declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in phase['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # This exact catalog is a new boundary. Neither historical complete
        # catalog, missing harness, changed count/type nor old ignore census
        # may substitute for the actual current workspace.
        incoming = current.DATA['source_successor_96378']
        live_rows = current.before_fd4c6(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(live_rows), sum(x['tests'] for x in live_rows.values()),
                          sum(x['ignored'] for x in live_rows.values())), (113, 4312, 39))
        self.assertEqual(current.digest(phase_catalog), current.PHASE_CURRENT)
        self.assertEqual((incoming['default_method_additions'], incoming['default_doctest_additions'],
                          incoming['default_method_removals'], incoming['default_harness_changes'],
                          incoming['default_ignore_changes'], incoming['recorder_identity_changes']),
                         (44, 2, 0, 1, 2, 0))
        self.assertEqual(sum(len(names) * len(incoming['default_method_instances'][path])
                             for path, names in incoming['added_default_methods'].items()), 44)
        self.assertEqual(sum(len(names) for names in incoming['added_ignored_methods'].values()), 2)
        self.assertEqual(sum(len(rows) for rows in incoming['doctests'].values()), 2)
        self.assertEqual(incoming['excluded_standalone'], dict(
            path='evaluation/custody-file-read-probe/probe.rs', default_test_harness=False,
            reason='No Cargo target or module includes this standalone diagnostic.'))
        for wrong in (phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_96378(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in incoming['workspace_changes'].items():
            self.assertEqual(live_rows[name], change['current'])
            # Mutate the current input; live_rows remains the exact historical boundary.
            current_row = actual['harness_test_counts']['workspace_tests'][name]
            for field in ('tests', 'ignored'):
                for value in (None, True, float(current_row[field]), current_row[field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_96378(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            self.assertNotEqual(current.digest(wrong), current.digest(actual))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_96378(wrong)
        incoming_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in incoming['added_default_methods'].items() for name in names]
        incoming_stimuli += [(path, literal, '')
            for path, literals in incoming['module_chains'].items() for literal in literals]
        incoming_stimuli += [(path, block, replacement)
            for path, blocks in incoming['doctests'].items() for block in blocks
            for replacement in ('', block + '\n' + block, block.replace('compile_fail,E0277', 'ignore'))]
        incoming_stimuli += [(path, literal, literal.replace('#[ignore', '#[cfg'))
            for path in incoming['added_ignored_methods']
            for literal in re.findall(r'#\[ignore[^\n]*', (current.ROOT / path).read_text())]
        for path, literal, replacement in incoming_stimuli:
            target = current.ROOT / path; raw = read(target)
            # The current export blocks grew; authenticate the old declarations
            # in their exact predecessor before mutating the complete new blocks.
            declaration = current.DATA['source_successor_a8acec5']['module_chain_changes'].get(path)
            if declaration is not None and literal == declaration['previous']:
                prior = current.source_before_a8acec5(path, raw, 'incoming_export_inverse')
                self.assertEqual(prior.count(literal.encode()), 1)
                literal = declaration['current']
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('incoming declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in incoming['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # Current placement adds thirteen tests to three existing harnesses.
        # Preserve the entire prior catalog and every earlier control above.
        placement = current.DATA['source_successor_fd4c6']
        placement_rows = current.before_b0a30(actual)['harness_test_counts']['workspace_tests']
        placement_before = current.before_fd4c6(actual)
        self.assertEqual(current.digest(placement_before), current.PLACEMENT_PREVIOUS)
        self.assertEqual((len(placement_rows), sum(x['tests'] for x in placement_rows.values()),
                          sum(x['ignored'] for x in placement_rows.values())), (113, 4325, 39))
        self.assertEqual((placement['default_method_additions'], placement['default_doctest_additions'],
                          placement['default_method_removals'], placement['default_harness_changes'],
                          placement['default_ignore_changes'], placement['recorder_identity_changes']),
                         (13, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(placement['default_method_instances'][path])
                             for path, names in placement['added_default_methods'].items()), 13)
        self.assertEqual((placement['added_ignored_methods'], placement['doctests']), ({}, {}))
        for wrong in (placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_fd4c6(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in placement['workspace_changes'].items():
            self.assertEqual(placement_rows[name], change['current'])
            self.assertEqual(placement_before['harness_test_counts']['workspace_tests'][name],
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(placement_rows[name][field]), placement_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_fd4c6(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_fd4c6(wrong)
        placement_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in placement['added_default_methods'].items() for name in names]
        placement_stimuli += [(path, literal, '')
            for path, literals in placement['module_chains'].items() for literal in literals]
        for path, literal, replacement in placement_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('placement declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in placement['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # Entry veneers add 55 methods to four existing harnesses. The
        # complete prior placement catalog remains an independent boundary.
        entry = current.DATA['source_successor_b0a30']
        entry_rows = current.before_b6fea(actual)['harness_test_counts']['workspace_tests']
        entry_before = current.before_b0a30(actual)
        self.assertEqual(current.digest(entry_before), current.ENTRY_PREVIOUS)
        self.assertEqual((len(entry_rows), sum(x['tests'] for x in entry_rows.values()),
                          sum(x['ignored'] for x in entry_rows.values())), (113, 4380, 39))
        self.assertEqual((entry['default_method_additions'], entry['default_doctest_additions'],
                          entry['default_method_removals'], entry['default_harness_changes'],
                          entry['default_ignore_changes'], entry['recorder_identity_changes']),
                         (55, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(entry['default_method_instances'][path])
                             for path, names in entry['added_default_methods'].items()), 55)
        self.assertEqual((entry['added_ignored_methods'], entry['doctests']), ({}, {}))
        for wrong in (entry_before, placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b0a30(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in entry['workspace_changes'].items():
            self.assertEqual(entry_rows[name], change['current'])
            self.assertEqual(entry_before['harness_test_counts']['workspace_tests'][name],
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(entry_rows[name][field]), entry_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_b0a30(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b0a30(wrong)
        entry_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in entry['added_default_methods'].items() for name in names]
        entry_stimuli += [(path, literal, '')
            for path, literals in entry['module_chains'].items() for literal in literals]
        for path, literal, replacement in entry_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('entry declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in entry['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # The new Linux loader is a real default integration harness. All
        # earlier complete catalogs and their assertions remain unchanged.
        rx = current.DATA['source_successor_b6fea']
        rx_rows = current.before_124521(actual)['harness_test_counts']['workspace_tests']
        rx_before = current.before_b6fea(actual)
        self.assertEqual(current.digest(rx_before), current.RX_PREVIOUS)
        self.assertEqual((len(rx_rows), sum(x['tests'] for x in rx_rows.values()),
                          sum(x['ignored'] for x in rx_rows.values())), (114, 4395, 39))
        self.assertEqual((rx['default_method_additions'], rx['default_doctest_additions'],
                          rx['default_method_removals'], rx['default_harness_changes'],
                          rx['default_ignore_changes'], rx['recorder_identity_changes']),
                         (15, 0, 0, 1, 0, 0))
        self.assertEqual(sum(len(names) * len(rx['default_method_instances'][path])
                             for path, names in rx['added_default_methods'].items()), 15)
        self.assertEqual((rx['added_ignored_methods'], rx['doctests']), ({}, {}))
        self.assertEqual(rx['default_method_instances']['tools/elf-rewrite/tests/rx_run_loader.rs'],
                         ['test/rx_run_loader'])
        for wrong in (rx_before, entry_before, placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b6fea(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in rx['workspace_changes'].items():
            self.assertEqual(rx_rows[name], change['current'])
            self.assertEqual(rx_before['harness_test_counts']['workspace_tests'].get(name),
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(rx_rows[name][field]), rx_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_b6fea(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b6fea(wrong)
        rx_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in rx['added_default_methods'].items() for name in names]
        rx_stimuli += [(path, literal, '')
            for path, literals in rx['module_chains'].items() for literal in literals]
        for path, literal, replacement in rx_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('RX-run declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in rx['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        loader = 'test/rx_run_loader'
        loader_header = ('     Running tests/rx_run_loader.rs '
                         '(target/debug/deps/rx_run_loader-0123456789abcdef)')
        loader_log = '\n'.join((loader_header, 'running 2 tests', summary(2)))
        loader_expected = {loader: counts(2)}
        self.assertEqual(parsing.harness_id(loader_header), loader)
        self.assertEqual(rx_rows[loader], loader_expected[loader])
        loader_row = parsing.parse_harnesses(loader_log, loader_expected, 0)[0]
        self.assertEqual(loader_row['outer'], dict(passed=2, failed=0, ignored=0,
                                                  measured=0, filtered=0, result='ok'))
        for bad in (loader_log.replace('running 2 tests', 'running 1 test'),
                    loader_log.replace('running 2 tests', 'running 3 tests'),
                    loader_log.replace(summary(2), summary(1, ignored=1)),
                    loader_log.replace(summary(2), summary(1, filtered=1)),
                    loader_log.replace(summary(2), ''), loader_log + '\n' + loader_log,
                    loader_log.replace('rx_run_loader-', 'other-')):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, loader_expected, 0)
        failed = loader_log.replace(summary(2), summary(1, failed=1))
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^successful_exit_with_failed_summary$'):
            parsing.parse_harnesses(failed, loader_expected, 0)
        loader_row = parsing.parse_harnesses(failed, loader_expected, 1)[0]
        self.assertEqual((loader_row['outer']['result'], loader_row['outer']['passed'],
                          loader_row['outer']['failed']), ('FAILED', 1, 1))


        # All twenty overlapping-relay methods remain mandatory on the same
        # four default harnesses, above the complete packed-RX predecessor.
        overlap = current.DATA['source_successor_124521']
        overlap_rows = current.before_abe7(actual)['harness_test_counts']['workspace_tests']
        overlap_before = current.before_124521(actual)
        self.assertEqual(current.digest(overlap_before), current.OVERLAP_PREVIOUS)
        self.assertEqual((len(overlap_rows), sum(x['tests'] for x in overlap_rows.values()),
                          sum(x['ignored'] for x in overlap_rows.values())), (114, 4415, 39))
        self.assertEqual((overlap['default_method_additions'], overlap['default_doctest_additions'],
                          overlap['default_method_removals'], overlap['default_harness_changes'],
                          overlap['default_ignore_changes'], overlap['recorder_identity_changes']),
                         (20, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(overlap['default_method_instances'][path])
                             for path, names in overlap['added_default_methods'].items()), 20)
        self.assertEqual((overlap['added_ignored_methods'], overlap['doctests']), ({}, {}))
        self.assertEqual(overlap_before['harness_test_counts']['workspace_tests'], rx_rows)
        for wrong in (overlap_before, rx_before, entry_before, placement_before,
                      phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_124521(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in overlap['workspace_changes'].items():
            self.assertEqual(overlap_rows[name], change['current'])
            self.assertEqual(overlap_before['harness_test_counts']['workspace_tests'][name],
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(actual['harness_test_counts']['workspace_tests'][name][field]), actual['harness_test_counts']['workspace_tests'][name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_124521(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_124521(wrong)
        overlap_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in overlap['added_default_methods'].items() for name in names]
        overlap_stimuli += [(path, literal, '')
            for path, literals in overlap['module_chains'].items() for literal in literals]
        for path, literal, replacement in overlap_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('overlap declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in overlap['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()


        # Incoming finite-region/batch source adds 30 methods and eight docs.
        # Every old catalog remains exact behind the new whole inverse.
        clock = current.DATA['source_successor_abe7']
        clock_rows = current.before_c110(actual)['harness_test_counts']['workspace_tests']
        clock_before = current.before_abe7(actual)
        self.assertEqual(current.digest(clock_before), current.CLOCK_PREVIOUS)
        self.assertEqual((len(clock_rows), sum(x['tests'] for x in clock_rows.values()),
                          sum(x['ignored'] for x in clock_rows.values())), (115, 4453, 39))
        self.assertEqual(clock_before['harness_test_counts']['workspace_tests'], overlap_rows)
        self.assertEqual((clock['default_method_additions'], clock['default_doctest_additions'],
                          clock['default_method_removals'], clock['default_harness_changes'],
                          clock['default_ignore_changes'], clock['recorder_identity_changes']),
                         (30, 8, 0, 1, 0, 0))
        self.assertEqual(sum(len(names) * len(clock['default_method_instances'][path])
                             for path, names in clock['added_default_methods'].items()), 30)
        self.assertEqual(clock['added_ignored_methods'], {})
        self.assertEqual({path: len(blocks) for path, blocks in clock['doctest_sources'].items()},
                         {'src/backedge_clock.rs': 3, 'src/backedge_clock/batch.rs': 8})
        self.assertEqual(sum(block.startswith('    ///') for block in
                             clock['doctest_sources']['src/backedge_clock/batch.rs']), 1)
        self.assertEqual((actual['recorder_tests'], actual['harness_test_counts']['serial_launch']),
                         (clock_before['recorder_tests'], clock_before['harness_test_counts']['serial_launch']))
        for wrong in (clock_before, overlap_before, rx_before, entry_before, placement_before,
                      phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_abe7(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in clock['workspace_changes'].items():
            self.assertEqual(clock_rows[name], change['current'])
            self.assertEqual(clock_before['harness_test_counts']['workspace_tests'].get(name), change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(clock_rows[name][field]), clock_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_abe7(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_abe7(wrong)
        clock_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in clock['added_default_methods'].items() for name in names]
        clock_stimuli += [(path, literal, '')
            for path, literals in clock['module_chains'].items() for literal in literals]
        clock_stimuli += [(path, block, block.replace('```compile_fail', '```'))
            for path, blocks in clock['doctest_sources'].items() for block in blocks]
        for path, literal, replacement in clock_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('clock declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in clock['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        clock_id = 'unit/owned_region_clock/owned_region_clock'
        clock_header = ('     Running unittests examples/owned_region_clock.rs '
                        '(target/debug/examples/owned_region_clock-0123456789abcdef)')
        clock_log = '\n'.join((clock_header, 'running 3 tests', summary(3)))
        clock_expected = {clock_id: counts(3)}
        self.assertEqual(clock_rows[clock_id], clock_expected[clock_id])
        self.assertEqual(parsing.harness_id(clock_header), clock_id)
        clock_row = parsing.parse_harnesses(clock_log, clock_expected, 0)[0]
        self.assertEqual(clock_row['outer'], dict(passed=3, failed=0, ignored=0,
                                                 measured=0, filtered=0, result='ok'))
        self.assertEqual((clock_row['declared_outer_tests'], clock_row['nested_starts'],
                          clock_row['unmatched_nested_starts']), (3, 0, 0))
        for malformed in (
                clock_header.replace('target/debug/examples/', 'target/debug/deps/'),
                clock_header.replace('unittests examples/owned_region_clock.rs',
                                     'unittests src/lib.rs').replace('target/debug/examples/', 'target/debug/deps/'),
                clock_header.replace('target/debug/examples/owned_region_clock-', 'target/debug/deps/other-'),
                clock_header.replace('target/debug/examples/owned_region_clock-', 'target/debug/examples/other-'),
                clock_header.replace('examples/owned_region_clock.rs', 'examples/other.rs'),
                clock_header.replace('owned_region_clock', 'owned_region_clock_extra'),
                clock_header.replace('target/debug/examples/', '/PRIVATE_SENTINEL/'),
                clock_header.replace('target/debug/examples/', 'target/debug/examples/../examples/'),
                clock_header.replace('-0123456789abcdef)', '-nothex)')):
            with self.subTest(clock_header=malformed), self.assertRaises(parsing.InvalidEvidence):
                parsing.harness_id(malformed)
        for bad in (clock_log.replace('running 3 tests', 'running 2 tests'),
                    clock_log.replace('running 3 tests', 'running 4 tests'),
                    clock_log.replace(summary(3), summary(2, filtered=1)),
                    clock_log.replace(summary(3), summary(2, ignored=1)),
                    clock_log.replace(summary(3), summary(2, measured=1)),
                    clock_log.replace('running 3 tests', 'running 3 tests\nrunning 1 test'),
                    clock_log.replace(summary(3), ''), clock_log + '\n' + summary(3),
                    clock_log + '\n' + clock_log):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, clock_expected, 0)
        failed = clock_log.replace(summary(3), summary(2, failed=1))
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^successful_exit_with_failed_summary$'):
            parsing.parse_harnesses(failed, clock_expected, 0)
        failed_row = parsing.parse_harnesses(failed, clock_expected, 1)[0]
        self.assertEqual((failed_row['outer']['result'], failed_row['outer']['passed'],
                          failed_row['outer']['failed']), ('FAILED', 2, 1))


        # Incoming admission comparison adds three exact tests, no new harness.
        # The complete former current catalog remains the sole predecessor.
        comparison = current.DATA['source_successor_c110']
        comparison_before = current.before_c110(actual)
        comparison_rows = current.before_667921(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(comparison_before), current.ADMISSION_PREVIOUS)
        self.assertEqual(comparison_before['harness_test_counts']['workspace_tests'], clock_rows)
        self.assertEqual((len(comparison_rows), sum(x['tests'] for x in comparison_rows.values()),
                          sum(x['ignored'] for x in comparison_rows.values())), (115, 4456, 39))
        self.assertEqual((comparison['default_method_additions'], comparison['default_doctest_additions'],
                          comparison['default_method_removals'], comparison['default_harness_changes'],
                          comparison['default_ignore_changes'], comparison['recorder_identity_changes']),
                         (3, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(comparison['default_method_instances'][path])
                             for path, names in comparison['added_default_methods'].items()), 3)
        self.assertEqual(comparison['added_ignored_methods'], {})
        self.assertEqual((actual['recorder_tests'], actual['harness_test_counts']['serial_launch']),
                         (comparison_before['recorder_tests'], comparison_before['harness_test_counts']['serial_launch']))
        for wrong in (comparison_before, clock_before, overlap_before, rx_before, entry_before,
                      placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_c110(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in comparison['workspace_changes'].items():
            self.assertEqual(comparison_rows[name], change['current'])
            self.assertEqual(clock_rows[name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(comparison_rows[name][field]), comparison_rows[name][field] + 1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_c110(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_c110(wrong)
        comparison_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in comparison['added_default_methods'].items() for name in names]
        comparison_stimuli += [(path, '#[test]\n    fn ' + name + '(',
                                '#[test]\n    #[ignore]\n    fn ' + name + '(')
            for path, names in comparison['added_default_methods'].items() for name in names]
        comparison_stimuli += [(path, literal, '')
            for path, literals in comparison['module_chains'].items() for literal in literals]
        self.assertEqual(len(comparison_stimuli), 10)
        for path, literal, replacement in comparison_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('comparison declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in comparison['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()


        # Early-control contributes 15 new declarations and two complete
        # inherited 35-test populations; all earlier catalogues remain exact.
        early = current.DATA['source_successor_667921']
        early_before = current.before_667921(actual)
        early_rows = point_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(early_before), current.EARLY_PREVIOUS)
        self.assertEqual(early_before['harness_test_counts']['workspace_tests'], comparison_rows)
        self.assertEqual((len(early_rows), sum(x['tests'] for x in early_rows.values()),
                          sum(x['ignored'] for x in early_rows.values())), (118, 4541, 39))
        self.assertEqual((early['default_method_additions'], early['new_method_declarations'],
                          early['inherited_test_instances'], early['default_harness_changes'],
                          early['default_method_removals'], early['default_doctest_additions'],
                          early['default_ignore_changes'], early['recorder_identity_changes']),
                         (85, 15, 70, 3, 0, 0, 0, 0))
        self.assertEqual(sum(len(v) * len(early['default_method_instances'][p])
                             for p,v in early['added_default_methods'].items()), 15)
        self.assertEqual(sum(len(v) * len(early['inherited_method_instances'][p])
                             for p,v in early['inherited_default_methods'].items()), 70)
        self.assertEqual(early['inherited_support']['tests'], 35)
        self.assertEqual((len(early['inherited_support']['files']), len(early['inherited_support']['edges'])), (37, 36))
        self.assertEqual(early['added_ignored_methods'], {})
        self.assertEqual((actual['recorder_tests'], actual['harness_test_counts']['serial_launch']),
                         (early_before['recorder_tests'], early_before['harness_test_counts']['serial_launch']))
        for wrong in (early_before, comparison_before, clock_before, overlap_before, rx_before,
                      entry_before, placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_667921(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in early['workspace_changes'].items():
            self.assertEqual(early_rows[name], change['current'])
            self.assertEqual(comparison_rows.get(name), change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(early_rows[name][field]), early_rows[name][field]+1):
                    wrong = inventory_copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_667921(wrong)
            wrong = inventory_copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_667921(wrong)
        early_stimuli = [(p, 'fn '+n+'(', 'fn '+n+'_wrong(')
            for p,names in early['added_default_methods'].items() for n in names]
        early_stimuli += [(p, literal, replacement) for p,literal,replacement in early['ignore_stimuli']]
        early_stimuli += [(p, literal, '') for p,literals in early['module_chains'].items() for literal in literals]
        self.assertEqual(len(early_stimuli), 44)
        for path, literal, replacement in early_stimuli:
            target=current.ROOT/path; raw=read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong=raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate==target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path:hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e:b if p!=path else (_ for _ in ()).throw(AssertionError('early declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in early['source_paths']:
            target=current.ROOT/path; raw=read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate!=target:return read(candidate)
                    if missing:raise FileNotFoundError(path)
                    return raw+b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # The new Cargo example has one exact source/binary/output-directory
        # identity. Its ten tests cannot be admitted under the generic matcher.
        example = 'unit/full_program_bridge/full_program_bridge'
        example_header = ('     Running unittests examples/full_program_bridge.rs '
                          '(target/debug/examples/full_program_bridge-0123456789abcdef)')
        example_log = '\n'.join((example_header, 'running 10 tests', summary(10)))
        expected = {example: counts(10)}
        self.assertEqual(live_rows[example], expected[example])
        self.assertEqual(parsing.harness_id(example_header), example)
        row = parsing.parse_harnesses(example_log, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=10, failed=0, ignored=0,
                                           measured=0, filtered=0, result='ok'))
        self.assertEqual((row['declared_outer_tests'], row['nested_starts'],
                          row['unmatched_nested_starts']), (10, 0, 0))
        for malformed in (
                example_header.replace('target/debug/examples/', 'target/debug/deps/'),
                example_header.replace('unittests examples/full_program_bridge.rs',
                                       'unittests src/lib.rs').replace('target/debug/examples/', 'target/debug/deps/'),
                example_header.replace('target/debug/examples/full_program_bridge-', 'target/debug/deps/other-'),
                example_header.replace('target/debug/examples/full_program_bridge-', 'target/debug/examples/other-'),
                example_header.replace('examples/full_program_bridge.rs', 'examples/other.rs'),
                example_header.replace('full_program_bridge', 'full_program_bridge_extra'),
                example_header.replace('target/debug/examples/', '/PRIVATE_SENTINEL/'),
                example_header.replace('target/debug/examples/', 'target/debug/examples/../examples/'),
                example_header.replace('-0123456789abcdef)', '-nothex)')):
            with self.subTest(full_program_header=malformed), self.assertRaises(parsing.InvalidEvidence):
                parsing.harness_id(malformed)
        for bad in (example_log.replace('running 10 tests', 'running 9 tests'),
                    example_log.replace('running 10 tests', 'running 11 tests'),
                    example_log.replace(summary(10), summary(9, filtered=1)),
                    example_log.replace(summary(10), summary(9, ignored=1)),
                    example_log.replace(summary(10), summary(9, measured=1)),
                    example_log.replace('running 10 tests', 'running 10 tests\nrunning 1 test'),
                    example_log.replace(summary(10), ''),
                    example_log + '\n' + summary(10), example_log + '\n' + example_log):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        failed = example_log.replace(summary(10), summary(9, failed=1))
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^successful_exit_with_failed_summary$'):
            parsing.parse_harnesses(failed, expected, 0)
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']),
                         ('FAILED', 9, 1))

        # Two source-bound compile-fail doctests extend the old 2+45 partition
        # to exactly 2+47. Both declarations, summaries and terminal are required.
        doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                         'running 47 tests', summary(47),
                         'all doctests ran in 0.51s; merged doctests compilation took 0.21s'))
        expected = {'doc/rapid_profiler': counts(49)}
        self.assertEqual(live_rows['doc/rapid_profiler'], expected['doc/rapid_profiler'])
        row = parsing.parse_harnesses(doc, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=49, failed=0, ignored=0,
                                           measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([part['declared_tests'] for part in row['partitions']], [2, 47])
        self.assertEqual([part['summary']['passed'] for part in row['partitions']], [2, 47])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        reordered = '\n'.join(('   Doc-tests rapid_profiler', 'running 47 tests', summary(47),
                               'running 2 tests', summary(2), doc.splitlines()[-1]))
        for bad in (doc.replace('rapid_profiler', 'example'), reordered,
                    doc.replace('running 2 tests', 'running 3 tests'),
                    doc.replace('running 47 tests', 'running 46 tests'),
                    doc.replace('running 47 tests', 'running 48 tests'),
                    doc.replace(summary(2), summary(1)),
                    doc.replace(summary(47), summary(46)),
                    doc.replace(summary(2), summary(2, filtered=1)),
                    doc.replace(summary(47), summary(47, filtered=1)),
                    doc.replace(summary(47), summary(46, ignored=1)),
                    doc.replace(summary(47), summary(46, measured=1)),
                    doc.replace(summary(47), summary(46, failed=1)),
                    doc.replace(summary(47), summary(47, result='FAILED')),
                    doc.replace('running 47 tests', 'running 47 tests\nrunning 47 tests'),
                    doc.replace(summary(2), summary(2) + '\n' + summary(2)),
                    doc.replace(summary(2), ''), doc.replace(summary(47), ''),
                    '\n'.join(doc.splitlines()[:-1]), doc + '\n' + doc.splitlines()[-1],
                    doc + '\nrunning 1 test\n' + summary(1),
                    doc.replace('all doctests ran in 0.51s;', 'all doctests ran in NaNs;')):
            with self.subTest(incoming_doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        for total, ignored in ((48, 0), (50, 0), (49, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = doc.replace(summary(47), summary(46, failed=1))
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']),
                         ('FAILED', 48, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)

        # The incoming source adds one compile-fail declaration. Require its
        # exact 2+48 rustdoc partition without changing the historical 2+47.
        entry_doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                               'running 48 tests', summary(48),
                               'all doctests ran in 0.67s; merged doctests compilation took 0.26s'))
        entry_expected = {'doc/rapid_profiler': counts(50)}
        self.assertEqual(snapshot_prior['harness_test_counts']['workspace_tests']['doc/rapid_profiler'],
                         entry_expected['doc/rapid_profiler'])
        row = parsing.parse_harnesses(entry_doc, entry_expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=50, failed=0, ignored=0,
                                           measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([part['declared_tests'] for part in row['partitions']], [2, 48])
        self.assertEqual([part['summary']['passed'] for part in row['partitions']], [2, 48])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        reordered = '\n'.join(('   Doc-tests rapid_profiler', 'running 48 tests', summary(48),
                               'running 2 tests', summary(2), entry_doc.splitlines()[-1]))
        for bad in (entry_doc.replace('rapid_profiler', 'example'), reordered,
                    entry_doc.replace('running 2 tests', 'running 3 tests'),
                    entry_doc.replace('running 48 tests', 'running 47 tests'),
                    entry_doc.replace('running 48 tests', 'running 49 tests'),
                    entry_doc.replace(summary(2), summary(1)),
                    entry_doc.replace(summary(48), summary(47)),
                    entry_doc.replace(summary(2), summary(2, filtered=1)),
                    entry_doc.replace(summary(48), summary(48, filtered=1)),
                    entry_doc.replace(summary(48), summary(47, ignored=1)),
                    entry_doc.replace(summary(48), summary(47, measured=1)),
                    entry_doc.replace(summary(48), summary(47, failed=1)),
                    entry_doc.replace(summary(48), summary(48, result='FAILED')),
                    entry_doc.replace('running 48 tests', 'running 48 tests\nrunning 48 tests'),
                    entry_doc.replace(summary(2), summary(2) + '\n' + summary(2)),
                    entry_doc.replace(summary(2), ''), entry_doc.replace(summary(48), ''),
                    '\n'.join(entry_doc.splitlines()[:-1]), entry_doc + '\n' + entry_doc.splitlines()[-1],
                    entry_doc + '\nrunning 1 test\n' + summary(1),
                    entry_doc.replace('all doctests ran in 0.67s;', 'all doctests ran in NaNs;')):
            with self.subTest(entry_doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, entry_expected, 0)
        for total, ignored in ((49, 0), (51, 0), (50, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(entry_doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = entry_doc.replace(summary(48), summary(47, failed=1))
        row = parsing.parse_harnesses(failed, entry_expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']),
                         ('FAILED', 49, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)


        # Exact projections return private graphs even when custom deepcopy
        # publishes a plain container. DATA patching must retain this behavior.
        def mutable_ids(value):
            pending = [value]; seen = set(); mutable = set()
            while pending:
                item = pending.pop()
                if not isinstance(item, (dict, list, tuple)) or id(item) in seen:
                    continue
                seen.add(id(item))
                if isinstance(item, (dict, list)):
                    mutable.add(id(item))
                pending.extend(item.keys() if isinstance(item, dict) else ())
                pending.extend(item.values() if isinstance(item, dict) else item)
            return mutable

        published = []
        class PublishedCopy(dict):
            def __deepcopy__(self, memo):
                result = {}; memo[id(self)] = result
                result.update((copy.deepcopy(k, memo), copy.deepcopy(v, memo))
                              for k, v in self.items())
                published.append(result)
                return result

        projections = ((current.before_96378, phase_catalog),
                       (current.before_29859, native_indexed),
                       (current.before_current, old))
        for function, expected_projection in ((current.before_03ed2c31, flat_prior), (current.before_4261826, row_prefix_prior), (current.before_f9f89ac, binding_prior), (current.before_bad32a8, current_ret_prior), (current.before_e5462b7, physical_prior), *projections):
            supplied = copy.deepcopy(actual)
            supplied['harness_test_counts']['serial_launch'] = PublishedCopy(
                supplied['harness_test_counts']['serial_launch'])
            published.clear()
            result = function(supplied)
            self.assertEqual(result, expected_projection)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))
        change = current.DATA['source_successor_96378']['workspace_changes']['doc/rapid_profiler']
        for function, expected_projection in projections[1:]:
            published.clear()
            with patch.dict(change, previous=PublishedCopy(change['previous'])):
                result = function(actual)
                self.assertEqual(result, expected_projection)
                self.assertEqual(len(published), 1)
                self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
                self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))
            self.assertEqual(actual['recorder_tests'], 366)

        # The new outer projection also returns a private graph under publishing deepcopy.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = current.DATA['source_successor_c110']['workspace_changes']['unit/liteinst_preempt/main']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(
                    supplied['harness_test_counts']['serial_launch'])
                result = current.before_c110(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_c110(supplied)
            self.assertEqual(result, comparison_before)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # Preserve private ownership through the newly added outer transition.
        for source in ('declared', 'metadata'):
            supplied=copy.deepcopy(actual)
            change=current.DATA['source_successor_667921']['workspace_changes']['unit/liteinst2/lib']
            published.clear()
            if source=='declared':
                supplied['harness_test_counts']['serial_launch']=PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result=current.before_667921(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result=current.before_667921(supplied)
            self.assertEqual(result, early_before)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        for path, literal in (("tools/rapid-profiler/point-throughput/main.rs", "#[cfg(test)]\nmod tests;"),
                              *(("tools/rapid-profiler/point-throughput/tests.rs", name)
                                for name in current.DATA['source_successor_e5ab521']['methods'])):
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            altered = literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), altered.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()

        # The latest metadata row may publish a copy too; the result stays private.
        published.clear()
        change = physical['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_e5462b7(actual)
            self.assertEqual(result, physical_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The new current-RET metadata transition also cannot publish its output.
        published.clear()
        change = current_ret['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_bad32a8(actual)
            self.assertEqual(result, current_ret_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The current metadata transition also cannot publish its private output.
        published.clear()
        change = binding['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_f9f89ac(actual)
            self.assertEqual(result, binding_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # New row-prefix metadata also cannot publish the private result.
        published.clear()
        change = row_prefix['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_4261826(actual)
            self.assertEqual(result, row_prefix_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # Incoming metadata must not publish a caller-owned catalog through deepcopy.
        published.clear()
        change = flat['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_03ed2c31(actual)
            self.assertEqual(result, flat_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The newest transition preserves private ownership for both input sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = shared['workspace_changes']['unit/liteinst2/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_3217b8ed(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_3217b8ed(supplied)
            self.assertEqual(result, shared_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = direct['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_79a4b8b(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_79a4b8b(supplied)
            self.assertEqual(result, direct_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = fixed['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_064b48c(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_064b48c(supplied)
            self.assertEqual(result, fixed_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = cfg['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_281c342(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_281c342(supplied)
            self.assertEqual(result, cfg_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = jump['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_11cc419(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_11cc419(supplied)
            self.assertEqual(result, jump_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = grouped['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_9528851(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_9528851(supplied)
            self.assertEqual(result, grouped_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = upstream['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_2294097(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_2294097(supplied)
            self.assertEqual(result, upstream_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = minimum['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_f9c5982(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_f9c5982(supplied)
            self.assertEqual(result, minimum_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = alphabet['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_0073fb6(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_0073fb6(supplied)
            self.assertEqual(result, alphabet_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The latest transition preserves private ownership for both sources.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = physical_window['workspace_changes']['unit/liteinst_rewrite/lib']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result = current.before_426ea6a(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_426ea6a(supplied)
            self.assertEqual(result, physical_window_prior)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # Sparse inverses retain exact edit ordering, including equal-position
        # insertions, and both whole-byte identity gates.
        raw = b'abcdef'
        for edits, expected_raw in (([], b'abcdef'),
                ([[1, 3, 'X'], [3, 5, 'Y']], b'aXYf'),
                ([[2, 2, 'X'], [2, 2, 'Y']], b'abXYcdef'),
                ([[0, 1, ''], [5, 6, '']], b'bcde')):
            inverse_row = dict(current_sha256=hashlib.sha256(raw).hexdigest(),
                previous_sha256=hashlib.sha256(expected_raw).hexdigest(), edits=edits)
            result = current.inverse('probe', raw, {'probe': inverse_row}, 'sparse_control')
            self.assertIs(type(result), bytes)
            self.assertEqual(result, expected_raw)
            for field in ('current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(inverse_row); malformed[field] = '0' * 64
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^sparse_control$'):
                    current.inverse('probe', raw, {'probe': malformed}, 'sparse_control')
        for edits in ([[3, 5, 'Y'], [1, 3, 'X']], [[1, 4, 'X'], [3, 5, 'Y']],
                      [[False, 1, 'X']], [[0, 7, 'X']], [[0, 1, b'X']]):
            malformed = dict(current_sha256=hashlib.sha256(raw).hexdigest(),
                previous_sha256=hashlib.sha256(raw).hexdigest(), edits=edits)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^sparse_control$'):
                current.inverse('probe', raw, {'probe': malformed}, 'sparse_control')
