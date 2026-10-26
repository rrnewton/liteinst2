//! Opt-in fixed-leaf native intervals on an authenticated, normally loaded DSO.
//!
//! This module observes the real entry and original RET paths of two fixed
//! assembly grammars: a one-return leaf and a zero/nonzero two-return leaf. It
//! never rewrites a return word, implements an unwind shim, or treats epoch drain
//! as code drain. The DSO, controls, generated image and callback code remain
//! process-lived. Only these separately declared grammars are admitted. There is no
//! generic function discovery, signal-safe path, native tail/exception support,
//! clock measurement, unload operation or transparent arbitrary-stack claim.

mod module;
mod pair;

pub use module::{
    BranchSubjectContract, LoadedBranchLeaf, LoadedLeaf, SetupRefusal, SubjectContract,
    TwoExitCertificate,
};
pub use pair::{
    Attach, BranchAttach, Journal, NativeError, NativeThread, NativeTotals, entry_callback,
    exit_callback,
};
