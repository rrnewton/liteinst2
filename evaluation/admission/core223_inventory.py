"""Authenticate main223e's 17 declarations and 107 compiled test instances before exact historical readers.

The current catalogue is complete. Sparse byte inverses require both complete
blob hashes; no Git history or execution claims are used at runtime.
"""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

PREVIOUS = '3de828ebb4d057e7fad20da36e59a90ea9ab09dedf5a2cb6ff7cf66068118f61'

CURRENT = '16a46b914968be06b73208c21ca085e7aaa23d546278eef99a2f5282e717498c'

CHANGED_HARNESSES = {'unit/liteinst_rewrite/lib': (79, 86),
 'unit/verify_common_core/verify_common_core': (16, 23),
 'test/e9_common_core_pages_contract': (9, 12),
 'test/a2_oracle': (43, 49),
 'test/boundary_signal_oracle': (30, 36),
 'test/call_return_oracle': (30, 36),
 'test/controlled_oracle': (30, 36),
 'test/entry_paths_oracle': (30, 36),
 'test/eviction_chain_extensions': (31, 37),
 'test/eviction_chain_oracle': (32, 38),
 'test/mandatory_prefix_oracle': (31, 37),
 'test/neighbor_eviction_oracle': (74, 80),
 'test/parked_context_oracle': (30, 36),
 'test/prefixed_pun_oracle': (30, 36),
 'test/quiescent_oracle': (33, 39),
 'test/rel32_endpoint_oracle': (30, 36),
 'test/successor_eviction_oracle': (34, 40),
 'test/exception_landing': (30, 36)}

SOURCE_SHA256 = {'tests/e9_common_core_pages_contract.rs': '376c4182651db051ef0906c6e7617c92121f79a1ab8c9ba0dad1fabc0b2cdfab',
 'tests/support/e9_common_core.rs': '0feda92bd5c0d5f0ae5cfb151fe39899f1afc3996ba9511fed99ed8526be3c32',
 'tests/support/e9_common_core_pages.rs': 'a23d6e230831f5ff54d19b95394ac21c5c0a5cd4dd083a62ad1416f3c44c620e',
 'tests/support/e9_common_e9.rs': '92712fecdfbb2a0f7d77cd86b4ae2b5f451e17eea2c87ac096ad64ed0673eae5',
 'tests/support/e9_common_image.rs': 'f112e774d705838c74fe51d7636140c8c4805830f1fb3a78c5007846f8c8e66e',
 'tests/support/e9_common_recording.rs': 'd0419f184093a5c1ef658028c7a8a2869dea8c849a5da44cd1f191c3b5085bc7',
 'tests/support/e9_common_recording_native.rs': 'a3e8d4e326bada12b9c77c4770cfab6d44dbb59a6eb82d4a5517542602d8d129',
 'tools/elf-rewrite/examples/emit_interleaved_carrier.rs': 'c5e8fc36c9799e2e709e86b23579519cbb58adf121f67c65c0e401de0fcd9202',
 'tools/elf-rewrite/examples/support/common_core_foreign.rs': '1109f454d1fc4052c2869b383eb3e4751fc2859982666baf2b6a2a46496a0e6c',
 'tools/elf-rewrite/examples/support/common_core_router.rs': 'ee4fc3b09ed9c6579291d68bfde8f8d7c3ba0303cc358c1b8d6d02d23194fc83',
 'tools/elf-rewrite/examples/verify_common_core.rs': '42374e3c7a42be44e534a9fc97ece05e3d6796d1d02dc9f41ddd919afb1f799b',
 'tools/elf-rewrite/src/carrier/image_fixtures.rs': 'dc4d4a95c5729a873b644fe89d873765d9dfefaaf3bd79c6739c0a6fb807cd3b',
 'tools/elf-rewrite/src/carrier/mod.rs': '835bc65d5a5537b2e51adf893525f81f992c82e55ef853f43740685a0eeadbac',
 'tools/elf-rewrite/src/lib.rs': '26844d6c499c2e5cfb7667f39fcdc2aa4b113d25f47118d38f9335a4fe3246a9',
 'tools/elf-rewrite/Cargo.toml': 'efa2528a5905f3a0d4d4424dfedff8d5fcba7365a03d63f969b4a613629e544f'}

# Each complete source hash binds a distinct Cargo test inclusion.
RECORDING_INCLUSIONS = {'test/a2_oracle': ('tests/a2_oracle.rs',
                    '3dc3b782e8530f93129f22591c91db04c5ce76a2a15caa443022a7db9da97c50'),
 'test/boundary_signal_oracle': ('tests/boundary_signal_oracle.rs',
                                 '44898d3621b5982f1d396f337299816934510c9796d3eec98c7a0b2567ed1a00'),
 'test/call_return_oracle': ('tests/call_return_oracle.rs',
                             '54dd4a1c895ed7a71255b8c03b0edf525ada18dbf5a19dae8a05e2ab06077a93'),
 'test/controlled_oracle': ('tests/controlled_oracle.rs',
                            'bb00ae7c089d3fa433506a0cf87cc33a7c0a64baefad8961b4d9287613380a7f'),
 'test/entry_paths_oracle': ('tests/entry_paths_oracle.rs',
                             '05a95a08e9e2de68db391f6b3b50aa461748aef993854cb328e33a1176312b50'),
 'test/eviction_chain_extensions': ('tests/eviction_chain_extensions.rs',
                                    '65bc955f0ab2a5653885a7844f3e97475aa80f42b8afa69c7ed7f3e85e80b33d'),
 'test/eviction_chain_oracle': ('tests/eviction_chain_oracle.rs',
                                '841e2d0c1ed09c2373f0c616426392a81c3aa7a2001b43110c3e2d16a07b4d23'),
 'test/mandatory_prefix_oracle': ('tests/mandatory_prefix_oracle.rs',
                                  'e093dd101451d136f73faee279365fa48fe48c89b560cb9b0ce65b03cff77b2b'),
 'test/neighbor_eviction_oracle': ('tests/neighbor_eviction_oracle.rs',
                                   '5b1f6d6a001d92d0ebf96b7d3f0f679ddd0506a73971901c7898af68865255eb'),
 'test/parked_context_oracle': ('tests/parked_context_oracle.rs',
                                'ef571fae32d7095f97b58dbec97ba10f77160fcb3098b7bae76703763d7f6341'),
 'test/prefixed_pun_oracle': ('tests/prefixed_pun_oracle.rs',
                              'c1538a91a3c34f8e743c459867883402a7f235e1457490ada8c805f36a921296'),
 'test/quiescent_oracle': ('tests/quiescent_oracle.rs',
                           'cd7ff42dd50da089f13ca538d09d8057f68dab93ff882ef24ed9b05825d1f8e2'),
 'test/rel32_endpoint_oracle': ('tests/rel32_endpoint_oracle.rs',
                                'cf00e1bf1f17a1fd3d7c8a65e790d8c7db0f11162d95409bed5e466f9be35642'),
 'test/successor_eviction_oracle': ('tests/successor_eviction_oracle.rs',
                                    'caa94cbd108de7b984057cb589c09dcb365977e7446e6f2632c8bbf1ac1b5ad5'),
 'test/exception_landing': ('tools/exception-oracle/tests/exception_landing.rs',
                            '0218bd7bc9a45606e8d1a2531b3e457c394ef1fd86fa17efbe1812614be2548b')}

SOURCE_SHA256.update({path: expected for path, expected in RECORDING_INCLUSIONS.values()})
SOURCE_SHA256.update({'Cargo.toml': '3c2ad9f468f22b0e6a36dc1487e1a5f5972fa0c2dd6eaf0f72e97facabd33794',
 'tools/exception-oracle/Cargo.toml': '13fde0b76cea61d1caecf580626d185ee30286278f5da92b6c4bea4995f207ee',
 'tests/support/quiescent_oracle.rs': 'e8c17e5daaf6e9720d6c515fd5e6f986307eca9c12ce115cdd51b465406dc756',
 'tests/support/elf_exec_oracle.rs': '1302da90836b31f9346cff5c20a458f4e5b3134b0f529e21f5027f78e4764c6b'})

RUST_METHODS = {'tests/e9_common_core_pages_contract.rs': ('mixed_load_order_retains_full_original_pages_and_generated_zero_tail',
                                            'half_open_original_window_preserves_high_only_and_both_adjacent_pages',
                                            'missing_changed_reordered_or_extra_original_owners_refuse',
                                            'original_overlap_and_lower_straddle_refuse',
                                            'generated_exact_and_rounded_overlap_refuse',
                                            'generated_permissions_remain_read_or_read_execute',
                                            'generated_page_and_load_count_limits_remain_exact',
                                            'whole_union_span_includes_lower_pages_and_keeps_exact_limit',
                                            'file_geometry_and_address_endpoint_refusals_remain',
                                            'interleaved_original_owners_keep_full_bytes_bss_and_generated_order',
                                            'interleaved_missing_changed_reordered_duplicate_originals_refuse',
                                            'interleaved_old_bss_generated_overlap_and_writable_pages_refuse'),
 'tests/support/e9_common_recording.rs': ('exact_trailing_profile_preserves_legacy_arguments_and_rejects_aliases',
                                          'entire_journal_append_and_unselected_state_are_exact',
                                          'journal_owner_header_tail_and_existing_record_mutations_refuse',
                                          'clean_call_stack_words_have_independent_offsets_and_full_tail',
                                          'exact_clean_template_encodes_logical_argument_call_and_return',
                                          'complete_hook_symbol_extent_and_load_bytes_are_exact'),
 'tools/elf-rewrite/examples/verify_common_core.rs': ('complete_policy_versions_preserve_caps_and_authenticate_original_owners',
                                                      'four_pivot_ceiling_matches_bounded_bruteforce_and_signed_edges',
                                                      'original_blocks_all_sites_and_heap_permit_have_independent_expected_coordinates',
                                                      'interleaved_full_carrier_reconstruction_matches_literal_header_ownership'),
 'tools/elf-rewrite/src/carrier/image_fixtures.rs': ('additive_exec_pie_and_dso_profiles_preserve_old_records_and_exact_rx_images',
                                                     'rela_rel_relr_and_jmprel_have_exact_widths_counts_and_zero_fill_ownership',
                                                     'every_supported_loader_write_width_is_exact_and_copy_is_not_guessed',
                                                     'relocation_in_unchanged_successor_or_padding_is_a_dependency_refusal',
                                                     'duplicate_or_partially_overlapping_loader_writes_refuse',
                                                     'unmapped_cross_boundary_and_overflowing_loader_fields_refuse',
                                                     'relr_bitmap_anchor_alignment_order_overflow_and_expansion_are_checked',
                                                     'dynamic_tag_shapes_termination_and_unknown_formats_fail_closed',
                                                     'dynamic_metadata_cannot_hide_in_executable_or_zero_fill_storage',
                                                     'dynamic_entry_and_record_limits_are_prospective',
                                                     'images_cannot_overlap_original_bss_other_images_or_ro_carrier',
                                                     'image_page_count_and_file_span_budgets_are_exact',
                                                     'interpreter_shape_order_and_gnu_property_remain_explicit_requirements',
                                                     'appended_image_pages_cannot_cover_original_declared_metadata_memory',
                                                     'dynamic_string_and_symbol_metadata_is_explicit_and_bounded',
                                                     'loader_symbol_record_cannot_hide_across_ro_rx_owner_boundary',
                                                     'sysv_hash_buckets_and_chains_cannot_cross_into_executable_source',
                                                     'gnu_hash_bloom_buckets_and_chains_cannot_cross_into_executable_source',
                                                     'versym_full_symbol_inventory_cannot_cross_into_executable_source',
                                                     'verdef_auxiliary_chain_cannot_hide_in_executable_source',
                                                     'verneed_auxiliary_chain_cannot_hide_in_executable_source',
                                                     'complete_hash_symbol_and_version_extents_retain_a_real_positive',
                                                     'metadata_work_is_aggregate_across_repeated_hash_bucket_walks',
                                                     'zero_write_relocation_cannot_hide_version_read_in_executable_source',
                                                     'zero_write_all_formats_preserve_bounded_symbol_references_and_valid_ownership',
                                                     'zero_write_symbol_indices_cannot_expand_complete_hash_or_evade_metadata_budget',
                                                     'mixed_relocation_reference_inventory_is_ordered_and_distinct_from_writes',
                                                     'interleaved_exec_low_gap_high_preserve_header_mapping_order_and_image_identity',
                                                     'interleaved_empty_load_ties_keep_original_first_and_phdr_interpreter_precedence',
                                                     'interleaved_all_original_pages_bss_crossings_and_new_load_overlaps_refuse',
                                                     'interleaved_metadata_and_original_header_ownership_are_not_exemptions',
                                                     'interleaved_union_span_and_all_allocation_budgets_have_exact_edges',
                                                     'interleaved_profile_is_explicit_exec_only_and_legacy_low_image_refusal_remains',
                                                     'interleaved_above_only_output_is_byte_identical_to_legacy_append_profile')}

COMPILED_METHODS = [{'source': 'tests/e9_common_core_pages_contract.rs',
  'harness': 'test/e9_common_core_pages_contract',
  'test': 'interleaved_original_owners_keep_full_bytes_bss_and_generated_order'},
 {'source': 'tests/e9_common_core_pages_contract.rs',
  'harness': 'test/e9_common_core_pages_contract',
  'test': 'interleaved_missing_changed_reordered_duplicate_originals_refuse'},
 {'source': 'tests/e9_common_core_pages_contract.rs',
  'harness': 'test/e9_common_core_pages_contract',
  'test': 'interleaved_old_bss_generated_overlap_and_writable_pages_refuse'},
 {'source': 'tests/support/e9_common_recording.rs',
  'harness': 'unit/verify_common_core/verify_common_core',
  'test': 'recording::tests::exact_trailing_profile_preserves_legacy_arguments_and_rejects_aliases'},
 {'source': 'tests/support/e9_common_recording.rs',
  'harness': 'unit/verify_common_core/verify_common_core',
  'test': 'recording::tests::entire_journal_append_and_unselected_state_are_exact'},
 {'source': 'tests/support/e9_common_recording.rs',
  'harness': 'unit/verify_common_core/verify_common_core',
  'test': 'recording::tests::journal_owner_header_tail_and_existing_record_mutations_refuse'},
 {'source': 'tests/support/e9_common_recording.rs',
  'harness': 'unit/verify_common_core/verify_common_core',
  'test': 'recording::tests::clean_call_stack_words_have_independent_offsets_and_full_tail'},
 {'source': 'tests/support/e9_common_recording.rs',
  'harness': 'unit/verify_common_core/verify_common_core',
  'test': 'recording::tests::exact_clean_template_encodes_logical_argument_call_and_return'},
 {'source': 'tests/support/e9_common_recording.rs',
  'harness': 'unit/verify_common_core/verify_common_core',
  'test': 'recording::tests::complete_hook_symbol_extent_and_load_bytes_are_exact'},
 {'source': 'tools/elf-rewrite/examples/verify_common_core.rs',
  'harness': 'unit/verify_common_core/verify_common_core',
  'test': 'placement_tests::interleaved_full_carrier_reconstruction_matches_literal_header_ownership'},
 {'source': 'tools/elf-rewrite/src/carrier/image_fixtures.rs',
  'harness': 'unit/liteinst_rewrite/lib',
  'test': 'carrier::image_fixtures::interleaved_exec_low_gap_high_preserve_header_mapping_order_and_image_identity'},
 {'source': 'tools/elf-rewrite/src/carrier/image_fixtures.rs',
  'harness': 'unit/liteinst_rewrite/lib',
  'test': 'carrier::image_fixtures::interleaved_empty_load_ties_keep_original_first_and_phdr_interpreter_precedence'},
 {'source': 'tools/elf-rewrite/src/carrier/image_fixtures.rs',
  'harness': 'unit/liteinst_rewrite/lib',
  'test': 'carrier::image_fixtures::interleaved_all_original_pages_bss_crossings_and_new_load_overlaps_refuse'},
 {'source': 'tools/elf-rewrite/src/carrier/image_fixtures.rs',
  'harness': 'unit/liteinst_rewrite/lib',
  'test': 'carrier::image_fixtures::interleaved_metadata_and_original_header_ownership_are_not_exemptions'},
 {'source': 'tools/elf-rewrite/src/carrier/image_fixtures.rs',
  'harness': 'unit/liteinst_rewrite/lib',
  'test': 'carrier::image_fixtures::interleaved_union_span_and_all_allocation_budgets_have_exact_edges'},
 {'source': 'tools/elf-rewrite/src/carrier/image_fixtures.rs',
  'harness': 'unit/liteinst_rewrite/lib',
  'test': 'carrier::image_fixtures::interleaved_profile_is_explicit_exec_only_and_legacy_low_image_refusal_remains'},
 {'source': 'tools/elf-rewrite/src/carrier/image_fixtures.rs',
  'harness': 'unit/liteinst_rewrite/lib',
  'test': 'carrier::image_fixtures::interleaved_above_only_output_is_byte_identical_to_legacy_append_profile'}]

COMPILED_METHODS += [
    {'source': 'tests/support/e9_common_recording.rs', 'harness': identity,
     'test': 'oracle::elf_exec_oracle::common_image::recording::tests::' + method}
    for identity in RECORDING_INCLUSIONS
    for method in RUST_METHODS['tests/support/e9_common_recording.rs']
]

PROJECTIONS = {
    'tests/e9_common_core_pages_contract.rs': {
        'current_sha256': '376c4182651db051ef0906c6e7617c92121f79a1ab8c9ba0dad1fabc0b2cdfab',
        'previous_sha256': '1b9a821b52b91d71986a911e737c1226d8596b9d6ffd59b426661c96ccc23e02',
        'edits': [
            (3904, 3974, '    refuses(&elf, LOADS[..3].to_vec(), "range end index 4");\n'),
            (8893, 12098, ''),
        ],
    },
    'tests/support/e9_common_core.rs': {
        'current_sha256': '0feda92bd5c0d5f0ae5cfb151fe39899f1afc3996ba9511fed99ed8526be3c32',
        'previous_sha256': 'e40a441970517aa0c0a32a9f5222480bea64ee554e3eb5b2a147d5b5dde5b88b',
        'edits': [
            (0, 308, '//! Controlled core-null pairs. Structural witness/hash authority is external;\n//! every consumed byte, route, state, memory owner and completion is checked here.\n//! No normal-loader, E9, recording-hook or whole-A3 qualification is inferred.\n'),
            (2167, 2190, ''),
            (2472, 2513, ''),
            (2709, 2731, ''),
            (3194, 3512, '        assert_eq!(\n            rows[1],\n            vec!["scope", "STRUCTURAL_CORE_NULL_WITNESSES_ONLY"]\n        );\n'),
            (7567, 8058, '        let (base, pages) = materialize_load_pages(elf, loads);\n'),
            (10792, 10981, '            while rows[cursor][0] == "walk" || (router.enabled() && rows[cursor][0] == "trap") {\n'),
            (11234, 11701, '                assert!(!b.is_empty() && b.len() <= 15);\n'),
            (12161, 12194, ''),
            (13149, 13170, ''),
            (18042, 18651, '        assert_eq!(\n            base, self.candidate.base,\n            "all candidate original pages including globals/journal remain exact"\n        );\n'),
            (21017, 21095, '    let has_hook = head.walk.iter().any(|w| w.next == HOOK);\n'),
            (23321, 23811, '        if w.trap {\n'),
            (27507, 27557, ''),
            (28670, 28686, ''),
            (28758, 28902, '    let original_view = original_pages(&original.bytes);\n'),
            (35290, 35753, ''),
        ],
    },
    'tests/support/e9_common_image.rs': {
        'current_sha256': 'f112e774d705838c74fe51d7636140c8c4805830f1fb3a78c5007846f8c8e66e',
        'previous_sha256': '99a4c285c1335a399800f692d63b03053c0b43d844b608e03236308d47f3d525',
        'edits': [
            (453, 568, ''),
        ],
    },
    'tools/elf-rewrite/examples/support/common_core_foreign.rs': {
        'current_sha256': '1109f454d1fc4052c2869b383eb3e4751fc2859982666baf2b6a2a46496a0e6c',
        'previous_sha256': '8942cae7f6948e05ae838c294eda690e2859e9a92289a6bcafb34ac1a8067e2c',
        'edits': [
            (11618, 12790, ''),
        ],
    },
    'tools/elf-rewrite/examples/support/common_core_router.rs': {
        'current_sha256': 'ee4fc3b09ed9c6579291d68bfde8f8d7c3ba0303cc358c1b8d6d02d23194fc83',
        'previous_sha256': '1ee59854e36795fc1df5e0eb4443724075c9ac5d0b884661ff91f67582472cda',
        'edits': [
            (7648, 8344, ''),
        ],
    },
    'tools/elf-rewrite/examples/verify_common_core.rs': {
        'current_sha256': '42374e3c7a42be44e534a9fc97ece05e3d6796d1d02dc9f41ddd919afb1f799b',
        'previous_sha256': 'f7f1021a80c0aa4992364ca356db9af1fb2f77edf56e1638efde7e591fc73cb1',
        'edits': [
            (1265, 2139, ''),
            (13285, 16362, ''),
            (35194, 35312, ''),
            (38869, 38941, '        ("hook", "null".to_owned()),\n'),
            (40437, 40799, '    assert_eq!((h.id, h.pc, h.length), (2, HOOK, 1));\n    assert_eq!(h.expected, ContentId::of(&[0xc3]));\n'),
            (43176, 43293, '        assert_eq!(x.hook, 2);\n'),
            (51350, 51838, ''),
            (52498, 52859, '            "2".to_owned(),\n            HOOK.to_string(),\n            "1".to_owned(),\n            hash(&[0xc3])\n'),
            (60053, 60484, ''),
            (66480, 66683, '                let expected = helper(entry, logical, s.target);\n'),
            (67595, 67664, '                        assert_eq!(i.near_branch_target(), HOOK);\n'),
            (67988, 68025, '                            HOOK,\n'),
            (68129, 68482, '                        walk.push((at, HOOK, raw));\n                        walk.push((HOOK, next, vec![0xc3]));\n'),
            (72462, 72701, '        common_core_router::requirements(&r, id, hooks, router, &router_declarations);\n'),
            (72889, 73038, '        pair.images(&all_heads, &images);\n'),
            (73375, 73432, '                .filter(|(_, next, _)| *next == HOOK)\n'),
            (73813, 74162, ''),
            (74178, 74199, '        carrier(\n'),
            (76749, 76998, ''),
            (83226, 83571, '            if router_routes.iter().any(|route| route.pc == pc) {\n'),
            (85227, 85557, '    println!(\n        "core null witness complete: heads=87 normal=174 faults=2 execution=false qualification_complete=false"\n    );\n'),
            (95705, 98893, ''),
        ],
    },
    'tools/elf-rewrite/src/carrier/image_fixtures.rs': {
        'current_sha256': 'dc4d4a95c5729a873b644fe89d873765d9dfefaaf3bd79c6739c0a6fb807cd3b',
        'previous_sha256': '0bf71be11629552e6fce25434b4ecdd7bfcc897d14f6f8cb2da42bbe6f5b8fa2',
        'edits': [
            (40299, 57589, ''),
        ],
    },
    'tools/elf-rewrite/src/carrier/mod.rs': {
        'current_sha256': '835bc65d5a5537b2e51adf893525f81f992c82e55ef853f43740685a0eeadbac',
        'previous_sha256': 'ad5facf8bdb2022b1393f960d1939e2929619507757338b6306c653203c6c2d0',
        'edits': [
            (1124, 1217, '    /// Maximum span from the lowest original load page to the new carrier end.\n'),
            (9313, 9328, ''),
            (10051, 10969, '    append_internal(input, request, edits, policy, true)\n'),
            (11125, 11148, ''),
            (19785, 19996, '            || start < last_page_end\n            || input\n                .segments(SegmentType::Load)\n                .any(|old| old.vaddr.0 > start)\n'),
            (20401, 21044, ''),
            (22988, 23142, ''),
            (23178, 23253, '        added.last().ok_or(Error::OutputInvariant)?.page_end - lowest_page,\n'),
            (23340, 23413, '    let phdr_index = old_phdrs.first().map_or(0, |item| item.index);\n'),
            (23473, 23513, '    let carrier_index = header_base\n'),
            (23916, 26852, '    if insert_phdr {\n        encode_phdr(\n            &mut bytes,\n            carrier_offset,\n            table_header(carrier_offset, carrier_vaddr.0, new_table_len),\n        )?;\n    }\n    for item in input.program_headers() {\n        let new_index = item.index + usize::from(insert_phdr);\n        original_to_output_header.push(new_index);\n        let old_offset = add(\n            old_table.start().0,\n            item.index as u64 * 56,\n            "old program-header offset",\n        )?;\n        let new_offset = add(\n            carrier_offset,\n            new_index as u64 * 56,\n            "new program-header offset",\n        )?;\n        if item.kind == SegmentType::ProgramHeaders {\n'),
            (26905, 26937, '                new_offset,\n'),
            (27031, 27031, '        } else {\n            let source = &input.bytes()[host_index(old_offset)?..host_index(old_offset + 56)?];\n            bytes[host_index(new_offset)?..host_index(new_offset + 56)?].copy_from_slice(source);\n'),
            (27041, 28783, '    }\n    for (position, load) in added.iter().enumerate() {\n        let index = header_base + position;\n        encode_phdr(\n            &mut bytes,\n            add(carrier_offset, index as u64 * 56, "appended load header")?,\n            EncodedHeader {\n                kind: 1,\n                flags: load.flags,\n                offset: load.offset,\n                vaddr: load.vaddr,\n                file_size: load.size,\n                memory_size: load.size,\n                alignment: policy.page_size,\n            },\n        )?;\n        if let Some(image) = load.image {\n            image_placements[image].program_header = index;\n'),
            (30404, 30740, ''),
            (32118, 33133, ''),
        ],
    },
    'tools/elf-rewrite/src/lib.rs': {
        'current_sha256': '26844d6c499c2e5cfb7667f39fcdc2aa4b113d25f47118d38f9335a4fe3246a9',
        'previous_sha256': '8d918e27afb71ec808cb0cf794ccdab175643fe433ebd86e8d52d7aaa4b552c5',
        'edits': [
            (15166, 15482, '        let result = carrier::append_carrier_with_images(\n'),
        ],
    },
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_before_core223(path, data, error):
    if path not in PROJECTIONS:
        return data
    row = PROJECTIONS[path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for first, end, original in reversed(row['edits']):
        require(0 <= first <= end <= last, error)
        data = data[:first] + original.encode() + data[end:]
        last = first
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_current_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected in SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
        except OSError:
            require(False, 'core223_source_inventory_differs')
        require(hashlib.sha256(data).hexdigest() == expected, 'core223_source_inventory_differs')
        if path in RUST_METHODS:
            text = data.decode()
            require(re.findall(r'#\[test\]\s*fn\s+(\w+)\s*\(', text) == list(RUST_METHODS[path])
                    and not re.search(r'#\[ignore(?:\]|\()', text), 'core223_source_inventory_differs')


def before_core223(declared):
    require(type(declared) is dict and digest(declared) == CURRENT, 'core223_inventory_differs')
    previous = copy.deepcopy(declared)
    rows = previous['harness_test_counts']['workspace_tests']
    for identity, (old, current) in CHANGED_HARNESSES.items():
        require(rows[identity] == {'tests': current, 'ignored': 0}, 'core223_inventory_differs')
        rows[identity] = {'tests': old, 'ignored': 0}
    require(digest(previous) == PREVIOUS, 'core223_inventory_differs')
    require_current_sources()
    return previous


def peel_current(declared):
    return before_core223(declared) if type(declared) is dict and digest(declared) == CURRENT else declared
