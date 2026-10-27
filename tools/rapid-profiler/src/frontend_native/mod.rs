//! Opt-in native intervals on authenticated, normally loaded scalar DSOs.
//!
//! The original profiles observe the real entry and original RET paths of two fixed
//! assembly grammars: a one-return leaf and a zero/nonzero two-return leaf. It
//! never rewrites a return word, implements an unwind shim, or treats epoch drain
//! as code drain. The DSO, controls, generated image and callback code remain
//! process-lived. Only these separately declared grammars are admitted. There is no
//! generic function discovery, signal-safe path, native tail/exception support,
//! clock measurement, unload operation or transparent arbitrary-stack claim.
//!
//! `LoadedIntegerLeaf` separately admits a bounded ordinary integer leaf.
//! `OrdinarySitePreparation` requires an instrumentable entry and every RET,
//! and uses the library's real CALL gate. Its timestamps are raw, uncalibrated
//! callback endpoints. The certificate alone grants no publication authority;
//! ABI, input-memory, entry closure and normal-return obligations remain unsafe.

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

mod always_on;
pub use always_on::site::{InstalledIntervalSite, IntervalSitePreparation, SiteError};
pub use always_on::{
    BridgeError, IntervalClient, IntervalController, IntervalEpoch, IntervalJournal,
    IntervalThread, PairTotals, PreparedIntervalController, ReadableStack,
};

/// Separate bounded scalar-symbol admission; no publication or interval execution.
pub use module::ordinary::{IntegerLeafCertificate, IntegerLeafContract, LoadedIntegerLeaf};

/// Separate ordinary scalar-function interval profile; raw, uncalibrated timing.
pub use always_on::site::ordinary::{OrdinarySitePreparation, PreparedOriginalCall};
pub use always_on::{
    CallGate, CallResult, GateError, OriginalCallResult, RawInterval, RawIntervalOwner,
    RawTimestamp,
};
