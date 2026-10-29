//! Exact inherited oracle calibrations, separately counted from native cohorts.
#![deny(warnings)]
#[path = "normal/check.rs"]
mod normal_check;
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
