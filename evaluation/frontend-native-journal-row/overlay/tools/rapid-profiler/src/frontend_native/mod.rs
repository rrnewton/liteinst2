//! Opt-in fixed-leaf native intervals on an authenticated, normally loaded DSO.
//!
//! This module observes the real entry and original RET. It never rewrites a
//! return word, implements an unwind shim, or treats epoch drain as code drain.
//! The DSO, controls, generated image and callback code remain process-lived.
//! Only the separately declared fixed assembly grammar is admitted. There is no
//! generic function discovery, signal-safe path, native tail/exception support,
//! clock measurement, unload operation or transparent arbitrary-stack claim.

mod module;
mod pair;

pub use module::{LoadedLeaf, SetupRefusal, SubjectContract};
pub use pair::{
    Attach, Journal, NativeError, NativeThread, NativeTotals, entry_callback, exit_callback,
};
