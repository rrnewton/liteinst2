// Sibling registrations reuse the one retained oracle and production router.
// These finite in-memory cases grant no ELF, corpus or runtime qualification.
use super::routed_jmp_native_tests::{
    ProductionRoutes, min5_size_certificate, oracle, skip_unless_xcr0_within_preserved,
};
use crate::isolated_native_test as isolated;

#[test]
fn alphabet_min5_every_entry_routes_through_production() {
    if skip_unless_xcr0_within_preserved() {
        return;
    }
    isolated::run(
        "entry_router::imp::entry_alphabet_native_tests::alphabet_min5_every_entry_routes_through_production",
        "LI2_ALPHABET_MIN5_NATIVE_ENTRIES_V1",
        || oracle::min5_native::alphabet_entries::<ProductionRoutes>(min5_size_certificate),
    );
}
#[test]
fn alphabet_min5_ret_fault_preserves_prior_pop_and_callbacks() {
    if skip_unless_xcr0_within_preserved() {
        return;
    }
    isolated::run(
        "entry_router::imp::entry_alphabet_native_tests::alphabet_min5_ret_fault_preserves_prior_pop_and_callbacks",
        "LI2_ALPHABET_MIN5_NATIVE_RET_FAULT_V1",
        || oracle::min5_native::alphabet_ret_faults::<ProductionRoutes>(min5_size_certificate),
    );
}
#[test]
fn alphabet_min5_non06_pop_fault_preserves_uncommitted_state() {
    if skip_unless_xcr0_within_preserved() {
        return;
    }
    isolated::run(
        "entry_router::imp::entry_alphabet_native_tests::alphabet_min5_non06_pop_fault_preserves_uncommitted_state",
        "LI2_ALPHABET_MIN5_NATIVE_POP_FAULT_V1",
        || oracle::min5_native::alphabet_pop_faults::<ProductionRoutes>(min5_size_certificate),
    );
}
