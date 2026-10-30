//! Additive controls outside the frozen old LeafSet test inventory.
macro_rules! controls {
    ($module:ident: $($name:ident),+ $(,)?) => {$(
        #[test]
        fn $name() { super::leaf_set::$module::$name(); }
    )+};
}
controls! { selected_controls:
   labels_are_fixed_copyable_csv_safe_identifiers,
   labels_refuse_framing_injection_non_ascii_and_excess,
   frozen_rows_keep_exact_raw_csv_bytes_and_full_u64_values,
   returned_row_owns_its_frozen_inputs_after_table_retirement,
   table_framing_requires_exact_version_spaces_lf_and_terminal_end,
   all_cardinalities_preserve_exact_record_and_call_caps,
   dimensions_reject_zero_overflow_and_disagreement,
   function_rows_are_complete_unique_and_ordered,
   record_rows_refuse_missing_duplicate_extra_or_reordered_ids,
   value_columns_refuse_missing_extra_noncanonical_or_overflowed_values,
   payloads_preserve_existing_printable_csv_grammar_and_64_byte_bound,
   row_lookup_binds_input_id_bytes_and_complete_population,
   returned_row_rechecks_input_and_column_before_exposing_expected_value,
   completion_refuses_early_eof_and_excess_even_with_valid_prefix,
   argument_loading_uses_exact_selected_functions_and_separate_table_path,
   argument_limits_and_canonical_numbers_remain_closed,
   selections_reject_duplicate_ids_labels_overlap_order_and_extent_overflow,
   preparation_policies_keep_exact_extent_bounds,
   complete_table_load_failure_cannot_fall_back_to_derived_operations,
}
controls! { expected_controls:
    builtin_models_protocol_and_completion_stay_exact,
    frozen_witnesses_bind_complete_row_function_and_dimension,
    frozen_witnesses_retain_oracle_and_reject_early_completion,
}
controls! { selected_worker_controls:
    selected_guarded_returns_reject_each_value_and_guard_drift,
}
controls! { selected_output_controls:
    selected_full_u64_wire_keeps_old_bounds_and_old_refusal,
}
