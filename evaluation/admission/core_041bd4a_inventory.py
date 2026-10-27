"""Closed historical corpus projection for the incoming041bd4a core.

Historical fixtures only:19 unit declarations and4 compile-fail doctests add23
workspace instances. Current production drivers require the whole current corpus.
No native result, baseline or successful qualification is manufactured here.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

PRE_CORE_041BD4A_CORPUS_SHA256 = 'b330c13e03db56ff7c6a34c121cd41e91d58c92928f71441b4427a771ecfbe3d'
CURRENT_CORE_041BD4A_CORPUS_SHA256 = 'ccc0d245bd3d006e7ac64f039f1725e8d538aae33c972d49b722626899146b57'
CHANGED_HARNESSES = {'doc/liteinst2': ({'ignored': 0, 'tests': 0}, {'ignored': 0, 'tests': 3}),
 'doc/rapid_profiler': ({'ignored': 0, 'tests': 10}, {'ignored': 0, 'tests': 11}),
 'unit/liteinst2/lib': ({'ignored': 1, 'tests': 213}, {'ignored': 1, 'tests': 219}),
 'unit/rapid_profiler/lib': ({'ignored': 0, 'tests': 106}, {'ignored': 0, 'tests': 119})}
RUST_METHODS = {'src/controls.rs': ('identity_is_shared_by_clones_and_independent_of_enabled_state',
                     'borrowed_token_has_one_word_layout_and_matches_only_its_live_owner',
                     'managed_clones_refuse_both_setters_and_writer_is_exactly_bound'),
 'src/rapid/managed_tests.rs': ('plan_and_image_retain_exact_managed_identity_and_callback',
                                'controlled_planning_preserves_geometry_and_stale_byte_refusals',
                                'managed_rapid_dispatch_changes_only_the_source_opcode',
                                'controlled_install_refuses_each_changed_byte_and_an_owned_tail'),
 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs': ('pending_releases_both_metadata_locks_and_refuses_reentrant_writer',
                                                             'all_closed_and_not_mandatory_select_exact_physical_group',
                                                             'stale_k_and_foreign_ticket_never_gain_a_store_or_completion',
                                                             'old_acquisition_refuses_after_rearm_but_old_reservation_finishes_with_old_owner',
                                                             'byte_store_then_barrier_refusal_is_terminal_without_rollback',
                                                             'word_receipts_preserve_pre_store_aborts_three_partial_barriers_and_unwind',
                                                             'complete_word_receipt_finalizes_only_the_exact_selected_points',
                                                             'panic_progress_is_recorded_before_resuming_the_same_unwind',
                                                             'dropped_pending_owner_retains_closed_failed_metadata_and_no_store',
                                                             'terminal_last_drop_retains_binding_and_physical_owners',
                                                             'physical_success_with_failed_final_join_keeps_physical_receipt_and_failed_owner',
                                                             'real_controlled_plans_bind_exact_owner_at_same_pc_and_never_expose_a_writer'),
 'tools/rapid-profiler/src/data_flag/tests.rs': ('actual_managed_points_force_close_rearm_k_groups_and_wrong_owner',)}
ADDED_RUST_METHODS = {'src/controls.rs': ('borrowed_token_has_one_word_layout_and_matches_only_its_live_owner',
                     'managed_clones_refuse_both_setters_and_writer_is_exactly_bound'),
 'src/rapid/managed_tests.rs': ('plan_and_image_retain_exact_managed_identity_and_callback',
                                'controlled_planning_preserves_geometry_and_stale_byte_refusals',
                                'managed_rapid_dispatch_changes_only_the_source_opcode',
                                'controlled_install_refuses_each_changed_byte_and_an_owned_tail'),
 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs': ('pending_releases_both_metadata_locks_and_refuses_reentrant_writer',
                                                             'all_closed_and_not_mandatory_select_exact_physical_group',
                                                             'stale_k_and_foreign_ticket_never_gain_a_store_or_completion',
                                                             'old_acquisition_refuses_after_rearm_but_old_reservation_finishes_with_old_owner',
                                                             'byte_store_then_barrier_refusal_is_terminal_without_rollback',
                                                             'word_receipts_preserve_pre_store_aborts_three_partial_barriers_and_unwind',
                                                             'complete_word_receipt_finalizes_only_the_exact_selected_points',
                                                             'panic_progress_is_recorded_before_resuming_the_same_unwind',
                                                             'dropped_pending_owner_retains_closed_failed_metadata_and_no_store',
                                                             'terminal_last_drop_retains_binding_and_physical_owners',
                                                             'physical_success_with_failed_final_join_keeps_physical_receipt_and_failed_owner',
                                                             'real_controlled_plans_bind_exact_owner_at_same_pc_and_never_expose_a_writer'),
 'tools/rapid-profiler/src/data_flag/tests.rs': ('actual_managed_points_force_close_rearm_k_groups_and_wrong_owner',)}
DOC_TESTS = ({'block_sha256': 'f6146fa763622ab3ca31e2f80d99e45a61bd111ac94b8e47a55938eb0969f554',
  'harness': 'doc/liteinst2',
  'item': 'controls::ControlIdentity',
  'line': 40,
  'path': 'src/controls.rs',
  'test': 'src/controls.rs - controls::ControlIdentity (line 40) - compile fail'},
 {'block_sha256': 'bcbbf0711fb0301878621357e716d2698505fb20aa0b8d0d264a4a6a5cb35d72',
  'harness': 'doc/liteinst2',
  'item': 'controls::ControlIdentity',
  'line': 49,
  'path': 'src/controls.rs',
  'test': 'src/controls.rs - controls::ControlIdentity (line 49) - compile fail'},
 {'block_sha256': 'faa91cc1f5c015e45b4916a1f036aa07a5966b528e16cc2a0afe64b14be5fd52',
  'harness': 'doc/liteinst2',
  'item': 'controls::ControlWriter',
  'line': 94,
  'path': 'src/controls.rs',
  'test': 'src/controls.rs - controls::ControlWriter (line 94) - compile fail'},
 {'block_sha256': '55805af18b4b9140f9100cb82a2844cfc295e0793993ff843bb68ac422228a82',
  'harness': 'doc/rapid_profiler',
  'item': 'data_flag::DataFlagSession',
  'line': 49,
  'path': 'tools/rapid-profiler/src/data_flag.rs',
  'test': 'tools/rapid-profiler/src/data_flag.rs - data_flag::DataFlagSession (line 49) - compile fail'})
COMPILED_METHODS = ({'harness': 'unit/liteinst2/lib',
  'kind': 'unit',
  'path': 'src/controls.rs',
  'test': 'controls::tests::borrowed_token_has_one_word_layout_and_matches_only_its_live_owner'},
 {'harness': 'unit/liteinst2/lib',
  'kind': 'unit',
  'path': 'src/controls.rs',
  'test': 'controls::tests::managed_clones_refuse_both_setters_and_writer_is_exactly_bound'},
 {'harness': 'unit/liteinst2/lib',
  'kind': 'unit',
  'path': 'src/rapid/managed_tests.rs',
  'test': 'rapid::tests::live::managed::plan_and_image_retain_exact_managed_identity_and_callback'},
 {'harness': 'unit/liteinst2/lib',
  'kind': 'unit',
  'path': 'src/rapid/managed_tests.rs',
  'test': 'rapid::tests::live::managed::controlled_planning_preserves_geometry_and_stale_byte_refusals'},
 {'harness': 'unit/liteinst2/lib',
  'kind': 'unit',
  'path': 'src/rapid/managed_tests.rs',
  'test': 'rapid::tests::live::managed::managed_rapid_dispatch_changes_only_the_source_opcode'},
 {'harness': 'unit/liteinst2/lib',
  'kind': 'unit',
  'path': 'src/rapid/managed_tests.rs',
  'test': 'rapid::tests::live::managed::controlled_install_refuses_each_changed_byte_and_an_owned_tail'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/tests.rs',
  'test': 'data_flag::tests::actual_managed_points_force_close_rearm_k_groups_and_wrong_owner'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::pending_releases_both_metadata_locks_and_refuses_reentrant_writer'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::all_closed_and_not_mandatory_select_exact_physical_group'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::stale_k_and_foreign_ticket_never_gain_a_store_or_completion'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::old_acquisition_refuses_after_rearm_but_old_reservation_finishes_with_old_owner'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::byte_store_then_barrier_refusal_is_terminal_without_rollback'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::word_receipts_preserve_pre_store_aborts_three_partial_barriers_and_unwind'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::complete_word_receipt_finalizes_only_the_exact_selected_points'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::panic_progress_is_recorded_before_resuming_the_same_unwind'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::dropped_pending_owner_retains_closed_failed_metadata_and_no_store'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::terminal_last_drop_retains_binding_and_physical_owners'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::physical_success_with_failed_final_join_keeps_physical_receipt_and_failed_owner'},
 {'harness': 'unit/rapid_profiler/lib',
  'kind': 'unit',
  'path': 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs',
  'test': 'data_flag::code_toggle::tests::real_controlled_plans_bind_exact_owner_at_same_pc_and_never_expose_a_writer'},
 {'harness': 'doc/liteinst2',
  'kind': 'compile_fail_doctest',
  'path': 'src/controls.rs',
  'test': 'src/controls.rs - controls::ControlIdentity (line 40) - compile fail'},
 {'harness': 'doc/liteinst2',
  'kind': 'compile_fail_doctest',
  'path': 'src/controls.rs',
  'test': 'src/controls.rs - controls::ControlIdentity (line 49) - compile fail'},
 {'harness': 'doc/liteinst2',
  'kind': 'compile_fail_doctest',
  'path': 'src/controls.rs',
  'test': 'src/controls.rs - controls::ControlWriter (line 94) - compile fail'},
 {'harness': 'doc/rapid_profiler',
  'kind': 'compile_fail_doctest',
  'path': 'tools/rapid-profiler/src/data_flag.rs',
  'test': 'tools/rapid-profiler/src/data_flag.rs - data_flag::DataFlagSession (line 49) - compile fail'})
SOURCE_SHA256 = {'Cargo.lock': 'd8f447b6869ecbb2638a96a82034e1c6485a00d4e0406ff547715e5d67db51b8',
 'Cargo.toml': 'cc8da284807082bbe47c265a4830ffced4bd173f95a9e2571ecdec6f568130c6',
 'src/controls.rs': 'e7fa95d7fb2fe6e3bc6b4fc998ca20fb9d44f01ed918d407329133c6d5d5857b',
 'src/lib.rs': '2e4cb57fb7be6c78d58a5582c5ab4e6408f373c1840243a30d71e49438db363a',
 'src/rapid.rs': 'b48dfb7b0db6791bb48e616ecb0e65210a299a2b60adf17f0163b08e15ab73ed',
 'src/rapid/managed_tests.rs': '98dcfd68416e511f99beae0c80c64a63fa064588bedc718bea23de147111e212',
 'src/trampoline.rs': '7abbe3d70ebb0d4e3dfb7e6ac22e2ae54332a47704a0184326b21dc4d40a2a1f',
 'tools/rapid-profiler/Cargo.toml': '974d33800cf37d3e1401d451b8cad336481ab0b73084d30b36c73e17fc5d3250',
 'tools/rapid-profiler/src/data_flag.rs': '7d0a7219e8344cf00c5c4edf862579d5ef26767eb694fce28b06d398131ca02f',
 'tools/rapid-profiler/src/data_flag/code_toggle.rs': 'e639f5b8de01f5251e8f7da7f17a07d4312e292456cccb65bbf080583226b426',
 'tools/rapid-profiler/src/data_flag/code_toggle/tests.rs': '9393594b88e8255d62a36ee614786b93a6c66c78ca527b59a69554311d6a213a',
 'tools/rapid-profiler/src/data_flag/tests.rs': 'ac7c030946e142ba53ff5160fca6008a03e2417b52cd6763b4e8336497c95ba7',
 'tools/rapid-profiler/src/frontend.rs': 'ee82eb719f546491e636c6406032185a72796c6cb6d0f44fd48679648daab9f2',
 'tools/rapid-profiler/src/frontend_tls.rs': 'ad5f71e59c39a7332d8021e21bfa83425548452bd9dde334f3b345912bab7942',
 'tools/rapid-profiler/src/lib.rs': '52b54ed20f6e8daa509846e2ac543ff5ef6e8099b1d69cc8623b94421e3c363d'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_core_041bd4a_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected_hash in SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "core_041bd4a_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == expected_hash,
                "core_041bd4a_source_inventory_differs")
        if path in RUST_METHODS:
            require(re.findall(r"#\[test\]\s*(?:#\[[^\n]*\]\s*)*(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)\s*\(", source)
                    == list(RUST_METHODS[path])
                    and not re.search(r"#\[ignore(?:\]|\()", source),
                    "core_041bd4a_source_inventory_differs")


def before_core_041bd4a(declared):
    """Authenticate the complete2290 corpus and recover the exact2267 corpus."""
    require(type(declared) is dict and digest(declared) == CURRENT_CORE_041BD4A_CORPUS_SHA256,
            "core_041bd4a_inventory_differs")
    workspace = declared["harness_test_counts"]["workspace_tests"]
    require(len(workspace) == 95, "core_041bd4a_inventory_differs")
    for identity, (_, current) in CHANGED_HARNESSES.items():
        observed = workspace[identity]
        require(type(observed) is dict and observed == current
                and all(type(value) is int for value in observed.values()),
                "core_041bd4a_inventory_differs")
    previous = copy.deepcopy(declared)
    for identity, (prior, _) in CHANGED_HARNESSES.items():
        previous["harness_test_counts"]["workspace_tests"][identity] = copy.deepcopy(prior)
    require(digest(previous) == PRE_CORE_041BD4A_CORPUS_SHA256,
            "core_041bd4a_inventory_differs")
    require_current_core_041bd4a_sources()
    return previous
