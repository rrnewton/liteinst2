//! Online x86-64 instrumentation using instruction punning.
//!
//! The crate is intentionally split along correctness boundaries: cache-line
//! classification, patch publication, probe state, and trampoline generation.
//! Unsafe code mutation will stay behind those boundaries as the implementation
//! is built out.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod cache_line;
pub mod patcher;
pub mod probe;
pub mod trampoline;
