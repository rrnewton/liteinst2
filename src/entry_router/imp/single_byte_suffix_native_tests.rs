// Separate registrations reuse the sole existing oracle and production router.
// The selected-RET body exercises the general observation API, not the narrower
// jump/PUSH/POP corpus selection grammar or an offline ELF execution claim.
use super::routed_jmp_native_tests::{ProductionRoutes, min5_size_certificate, oracle};
use crate::isolated_native_test as isolated;

#[test]
fn single_byte_suffix_every_selected_and_unselected_entry_uses_production_router() {
    isolated::run(
        "entry_router::imp::single_byte_suffix_native_tests::single_byte_suffix_every_selected_and_unselected_entry_uses_production_router",
        "LI2_SINGLE_BYTE_SUFFIX_NATIVE_ENTRIES_V1",
        || {
            oracle::min5_native::single_byte_suffix_entries::<ProductionRoutes>(
                min5_size_certificate,
                false,
            )
        },
    );
}
#[test]
fn single_byte_suffix_page_last_byte_is_ud_with_guarded_successor() {
    isolated::run(
        "entry_router::imp::single_byte_suffix_native_tests::single_byte_suffix_page_last_byte_is_ud_with_guarded_successor",
        "LI2_SINGLE_BYTE_SUFFIX_NATIVE_PAGE_EDGE_V1",
        || {
            oracle::min5_native::single_byte_suffix_entries::<ProductionRoutes>(
                min5_size_certificate,
                true,
            )
        },
    );
}
#[test]
fn single_byte_suffix_later_ret_fault_preserves_prior_pop_and_callback_state() {
    isolated::run(
        "entry_router::imp::single_byte_suffix_native_tests::single_byte_suffix_later_ret_fault_preserves_prior_pop_and_callback_state",
        "LI2_SINGLE_BYTE_SUFFIX_NATIVE_RET_FAULT_V1",
        || {
            oracle::min5_native::single_byte_suffix_ret_faults::<ProductionRoutes>(
                min5_size_certificate,
                false,
            )
        },
    );
}
#[test]
fn single_byte_suffix_page_edge_later_ret_fault_preserves_uncommitted_state() {
    isolated::run(
        "entry_router::imp::single_byte_suffix_native_tests::single_byte_suffix_page_edge_later_ret_fault_preserves_uncommitted_state",
        "LI2_SINGLE_BYTE_SUFFIX_NATIVE_PAGE_EDGE_RET_FAULT_V1",
        || {
            oracle::min5_native::single_byte_suffix_ret_faults::<ProductionRoutes>(
                min5_size_certificate,
                true,
            )
        },
    );
}
