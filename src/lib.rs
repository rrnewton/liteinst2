#![deny(warnings)]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod bundle;
pub mod cache_line;
pub mod composition;
pub mod contracts;
pub mod controls;
pub mod engine;
mod entry_router;
pub mod eviction;
pub mod grouping;
pub mod neighbor;
pub mod patcher;
pub mod planner;
pub mod probe;
pub mod quiescent;
pub mod rapid;
pub mod scanner;
pub mod search;
pub mod trampoline;
mod trap;
