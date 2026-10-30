//! Exact inherited oracle calibrations, separately counted from native cohorts.
#![deny(warnings)]
#[path = "normal/check.rs"]
mod normal_check;
// Preserve this entrypoint's original fixture module registrations.
#[macro_use]
#[path = "../../../tests/support/native_fixture_registration.rs"]
mod native_fixture_registration;
#[allow(dead_code)]
#[path = "../../../tests/support/native_interval_oracle.rs"]
mod oracle;

// Exact37 body predicates share the one truth instance in this test target.
#[path = "ordinary/exact_body.rs"]
mod exact_body;
#[path = "../exact-work/truth.rs"]
mod exact_truth;

// Distinct four-call module accounting; old normal-check census is unchanged.
#[path = "normal/module/check.rs"]
mod normal_module_check;
#[path = "normal/copied_rust/check.rs"]
mod normal_rust_invoke_check;

#[allow(dead_code)] // Production owner methods are not executed by pure calibrations.
#[path = "normal/rust_invoke_artifact.rs"]
mod normal_rust_invoke_artifact;

// Distinct all-subset LeafSet accounting; existing calibrations remain literal.
#[path = "normal/leaf_set_copied/check.rs"]
mod normal_leaf_set_copied_check;

// Distinct fixed selected compiled LeafSet joins; inherited controls stay exact.
#[path = "normal/selected_leaf_set/check.rs"]
mod selected_leaf_set_check;
