// One sibling registration set, sharing the existing oracle and production router.
// Required actual physical-window controls; no corpus/ELF/runtime qualification.
use super::routed_jmp_native_tests::{ProductionRoutes, min5_size_certificate, oracle};
use crate::isolated_native_test as isolated;

#[test]
fn physical_min5_every_entry_routes_through_production() {
    isolated::run(
        "entry_router::imp::physical_window_native_tests::physical_min5_every_entry_routes_through_production",
        "LI2_PHYSICAL_WINDOW_MIN5_NATIVE_ENTRIES_V1",
        || oracle::min5_native::physical_entries::<ProductionRoutes>(min5_size_certificate),
    );
}
#[test]
fn physical_min5_ret_fault_preserves_prior_pop_and_callbacks() {
    isolated::run(
        "entry_router::imp::physical_window_native_tests::physical_min5_ret_fault_preserves_prior_pop_and_callbacks",
        "LI2_PHYSICAL_WINDOW_MIN5_NATIVE_RET_FAULT_V1",
        || oracle::min5_native::physical_ret_faults::<ProductionRoutes>(min5_size_certificate),
    );
}
#[test]
fn physical_min5_non06_pop_fault_preserves_uncommitted_state() {
    isolated::run(
        "entry_router::imp::physical_window_native_tests::physical_min5_non06_pop_fault_preserves_uncommitted_state",
        "LI2_PHYSICAL_WINDOW_MIN5_NATIVE_POP_FAULT_V1",
        || oracle::min5_native::physical_pop_faults::<ProductionRoutes>(min5_size_certificate),
    );
}
