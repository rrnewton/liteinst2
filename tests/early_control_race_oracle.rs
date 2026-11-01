#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Four exec-isolated, same-process writer races. Existing static/fork oracles
//! and their architectural comparator are unchanged.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

#[test]
fn early_control_real_writer_races() {
    oracle::early_control_race::run("early_control_real_writer_races");
}
