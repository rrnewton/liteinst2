#![deny(warnings)]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod artifact_emission_tests;
mod artifact_fixups;
mod artifact_fragments;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod artifact_overlay_tests;
pub mod backedge_clock;
pub mod bundle;
pub mod cache_line;
pub mod composition;
pub mod contracts;
pub mod controls;
pub mod emission;
pub mod engine;
mod entry_router;
pub mod eviction;
pub mod eviction_chain;
pub mod frame_trace;
/// Optional source-certified generated CFI and normal backtrace publication.
pub mod generated_unwind;
pub mod grouping;
pub mod neighbor;
pub mod patcher;
pub mod planner;
pub mod precontext;
pub mod probe;
pub mod quiescent;
pub mod rapid;
pub mod scanner;
pub mod search;
pub mod sync_core;
pub mod trampoline;
mod trap;
