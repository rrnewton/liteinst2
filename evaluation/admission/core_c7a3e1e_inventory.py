"""Exact outer history projection for the additive c7a3e1e core tests.

Production reads the full corpus. Historical readers authenticate the complete
new corpus/source files before recovering their unchanged predecessor bytes.
No result or baseline is synthesized here.
"""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from selected_inventory import peel_current
from inline_clock_inventory import source_before_inline

PRE_CORE_C7A3E1E_CORPUS_SHA256 = '25b48766c6213887ac19e799fc0329ef01973d2ade44e2a9cf8e4e722d4fdbd5'
CURRENT_CORE_C7A3E1E_CORPUS_SHA256 = 'f748315064e4590ee4a2721c97f3b05717d271405d03271f9429bdaf5cc55d25'
ADDED_HARNESSES = {'unit/liteinst_preempt/main': {'tests': 2, 'ignored': 0}}
CHANGED_HARNESSES = {'unit/rapid_profiler/lib': ({'tests': 119, 'ignored': 0}, {'tests': 160, 'ignored': 0})}
RUST_METHODS = {'tools/rapid-profiler/src/frontend/interval_entry/tests.rs': ('p01_initial_off_crosses_arm',
                                                               'p02_old_off_new_combined_keeps_reports',
                                                               'p03_function_closed_retains_original_owner_across_rearm',
                                                               'p04_real_lifo_nested_counts_only_admitted_children',
                                                               'p05_stale_action_counts_without_changing_binding',
                                                               'p06_existing_k_close_gap_keeps_dropped_admission',
                                                               'r01_writer_busy_is_nonblocking_and_resets_callback',
                                                               'r02_registry_busy_releases_writer_and_resets_callback',
                                                               'r03_writer_and_registry_poison_remain_errors',
                                                               'r04_terminal_after_mutation_is_never_disarmed',
                                                               'r05_wrong_install_and_unregistered_thread_precede_off_result',
                                                               'r06_unknown_function_is_not_an_off_pair',
                                                               'r07_receipts_require_exact_spec_and_registered_thread',
                                                               'r08_closed_present_epoch_is_not_removed',
                                                               'r09_inflight_and_record_storage_refusals_are_not_unsampled',
                                                               'r10_model_depth_limit_is_exact',
                                                               'r11_slot_reentry_and_both_counter_exhaustions_remain_exact',
                                                               'r13_non_top_and_full_frame_corruption_refuse_before_completion',
                                                               'r14_full_token_and_consumed_receipt_refuse',
                                                               'r15_model_drop_cancels_admission_but_unsampled_creates_no_terminal',
                                                               'r16_history_full_preserves_exact_prefix_and_current_owner',
                                                               'closed_function_receipt_alone_retains_e_permit_until_consumed',
                                                               'inconsistent_binding_or_history_is_an_error_not_off'),
 'tools/rapid-profiler/src/frontend_native/always_on/tests.rs': ('initial_off_pair_keeps_initial_stamp_across_real_publication',
                                                                 'admitted_removed_new_mixed_lifo_retains_exact_original_owner',
                                                                 'closed_function_pair_is_unsampled_and_keeps_old_report_unchanged',
                                                                 'old_admission_blocks_report_until_its_own_ret_after_new_arm',
                                                                 'journal_preserves_entire_page_literal_header_rows_and_zero_tail',
                                                                 'event_capacity_reserves_every_pending_exit_before_any_new_admission',
                                                                 'mixed_pair_depth_uses_minimum_of_fixed_four_and_model_limit',
                                                                 'ordinal_and_totals_exhaustion_refuse_before_model_mutation',
                                                                 'exit_capacity_refuses_before_receipt_consumption',
                                                                 'non_top_rsp_and_full_return_word_refuse_without_popping',
                                                                 'foreign_pair_and_dirty_unsampled_token_retain_receipt',
                                                                 'controller_rejects_foreign_epoch_stale_index_and_process_without_history_change',
                                                                 'stage_slots_and_old_owner_lifetime_are_never_recycled',
                                                                 'controller_drop_closes_present_epoch_without_disarmed_or_unsampled_relabel',
                                                                 'packed_fields_reject_overflow_or_inconsistent_binding_without_truncation',
                                                                 'attach_duplicate_preflight_does_not_consume_registration_and_empty_detach_works',
                                                                 'outstanding_detach_and_drop_poison_retain_tls_pairs',
                                                                 'activation_refuses_existing_tls_attachment_without_resetting_it'),
 'tools/software-preemption/main.rs': ('whole_authored_corpus_has_one_exact_near_backward_site',
                                       'unsupported_backedge_and_call_are_refused_before_publication')}
METHOD_CONTEXT = {'tools/rapid-profiler/src/frontend/interval_entry/tests.rs': ('unit/rapid_profiler/lib',
                                                               'frontend::interval_entry::tests::'),
 'tools/rapid-profiler/src/frontend_native/always_on/tests.rs': ('unit/rapid_profiler/lib',
                                                                 'frontend_native::always_on::tests::'),
 'tools/software-preemption/main.rs': ('unit/liteinst_preempt/main', 'tests::')}
SOURCE_SHA256 = {'Cargo.toml': '3c2ad9f468f22b0e6a36dc1487e1a5f5972fa0c2dd6eaf0f72e97facabd33794',
 'tests/support/native_interval_oracle.rs': '0b72e9ce64c71b839f15c097668fcfb95d2880442ec53cffe4ea73b70b580112',
 'tests/support/native_point.rs': '550e9c9ffbf262d8c3b2eee7ab991bb1b72591746da58e8b47efb912e9edc479',
 'tools/rapid-profiler/Cargo.toml': '263e2cf2ba4841754ae6bf143fe0879d7ccb7156901273faa2cc38cc3f35eca4',
 'tools/rapid-profiler/native-point/main.rs': '048c360a005888defc66998cc924014d9ecaebe7594ec92f20be40539d2a5645',
 'tools/rapid-profiler/src/frontend.rs': '82bc3c5a5f086673450190378b7ae3099cb8f9e968834e3bb28494edcacee4cd',
 'tools/rapid-profiler/src/frontend/interval_entry.rs': '163e87d7c10eedd4ea5ba3e1648848ffa6eaa1ff5678676651a2121eb8126d81',
 'tools/rapid-profiler/src/frontend/interval_entry/tests.rs': '5022697b2bfdde8a7367eaa01a9b96fd830578875e0fb3556fad22bcb6ecae62',
 'tools/rapid-profiler/src/frontend_native/always_on.rs': 'f309a3f0789e13ea10dba53e493099924ca405f60e8f047f810cbb33c7cb6f34',
 'tools/rapid-profiler/src/frontend_native/always_on/site.rs': '563c2e5b80d20dca30afba6b143bb716f7e470857303dc099d94425bcd6337d7',
 'tools/rapid-profiler/src/frontend_native/always_on/tests.rs': 'e5fd08f23ccddb054046014665d54d0ffbd365a40b6d8f0b96a9d2e614aa0fd0',
 'tools/rapid-profiler/src/frontend_native/mod.rs': '83f0f6284f5a216d41a121e5c8a63a39d3f2a2190c74676c40cb77126402d1df',
 'tools/rapid-profiler/src/lib.rs': '52b54ed20f6e8daa509846e2ac543ff5ef6e8099b1d69cc8623b94421e3c363d',
 'tools/software-preemption/corpus.rs': '4828b46eddf8146fa57f99d03a83ae6ced48ee22a820945c774565b87bfca20a',
 'tools/software-preemption/counter.rs': 'e78685e104b9e98e9ea68b6e6d108c36f4400571612e679a9f40fde3719eed59',
 'tools/software-preemption/main.rs': 'a43cb418030350aa6051acfb8d9706525ba3c5f16de26039dbf64cfeb9083a76'}
SOURCE_PROJECTIONS = {'Cargo.toml': {'current_sha256': '3c2ad9f468f22b0e6a36dc1487e1a5f5972fa0c2dd6eaf0f72e97facabd33794',
                'inverse': [('    "/tools/software-preemption/**",\n', ''),
                            ('\n'
                             '# Explicit finite software-preemption experiment; no automatic runtime '
                             'activation.\n'
                             '[[bin]]\n'
                             'name = "liteinst-preempt"\n'
                             'path = "tools/software-preemption/main.rs"\n'
                             'test = true\n'
                             'bench = false\n'
                             'doc = false\n',
                             '')],
                'previous_sha256': 'a7df2371afa488062bd99edc3e01da5a5f085925055982e1b124c0f0df2d03f3'},
 'tools/rapid-profiler/Cargo.toml': {'current_sha256': '263e2cf2ba4841754ae6bf143fe0879d7ccb7156901273faa2cc38cc3f35eca4',
                                     'inverse': [('\n'
                                                  '[[bin]]\n'
                                                  'name = "frontend-native-point"\n'
                                                  'path = "native-point/main.rs"\n'
                                                  'test = false\n'
                                                  'bench = false\n',
                                                  '')],
                                     'previous_sha256': '974d33800cf37d3e1401d451b8cad336481ab0b73084d30b36c73e17fc5d3250'},
 'tools/rapid-profiler/src/frontend.rs': {'current_sha256': '82bc3c5a5f086673450190378b7ae3099cb8f9e968834e3bb28494edcacee4cd',
                                          'inverse': [('mod interval_entry;\n'
                                                       'pub(crate) use interval_entry::{\n'
                                                       '    BindingChange, IntervalEntry, '
                                                       'IntervalEntryError, IntervalEntrySummary, '
                                                       'IntervalExitError,\n'
                                                       '    UnsampledSummary,\n'
                                                       '};\n'
                                                       '\n',
                                                       '')],
                                          'previous_sha256': 'ee82eb719f546491e636c6406032185a72796c6cb6d0f44fd48679648daab9f2'}}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_before_core_c7a3e1e(path, data, error):
    if path not in SOURCE_PROJECTIONS:
        return data
    row = SOURCE_PROJECTIONS[path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row["current_sha256"], error)
    restored = data
    for current, previous in reversed(row["inverse"]):
        require(restored.count(current.encode()) == 1, error)
        restored = restored.replace(current.encode(), previous.encode(), 1)
    require(hashlib.sha256(restored).hexdigest() == row["previous_sha256"], error)
    return restored


def require_current_core_c7a3e1e_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected in SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
            data = source_before_inline(path, data, "core_c7a3e1e_source_inventory_differs")
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "core_c7a3e1e_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == expected, "core_c7a3e1e_source_inventory_differs")
        if path in RUST_METHODS:
            require(re.findall(r"#\[test\]\s*(?:#\[[^\n]*\]\s*)*(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)\s*\(", source)
                    == list(RUST_METHODS.get(path, ()))
                    and not re.search(r"#\[ignore(?:\]|\()", source),
                    "core_c7a3e1e_source_inventory_differs")


def before_core_c7a3e1e(declared):
    declared = peel_current(declared)
    require(type(declared) is dict and digest(declared) == CURRENT_CORE_C7A3E1E_CORPUS_SHA256,
            "core_c7a3e1e_inventory_differs")
    previous = copy.deepcopy(declared)
    workspace = previous["harness_test_counts"]["workspace_tests"]
    for identity, expected in ADDED_HARNESSES.items():
        require(workspace.pop(identity) == expected, "core_c7a3e1e_inventory_differs")
    for identity, (prior, current) in CHANGED_HARNESSES.items():
        require(workspace[identity] == current, "core_c7a3e1e_inventory_differs")
        workspace[identity] = copy.deepcopy(prior)
    require(digest(previous) == PRE_CORE_C7A3E1E_CORPUS_SHA256, "core_c7a3e1e_inventory_differs")
    require_current_core_c7a3e1e_sources()
    return previous
