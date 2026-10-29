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

//!
//! The tree preparation, client, attached thread and original-call guard belong to the actual
//! calling thread. None can be transferred or shared with another thread:
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::TreeSitePreparation;
//! fn need_send<T: Send>() {}
//! need_send::<TreeSitePreparation>();
//! ```
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::TreeSitePreparation;
//! fn need_sync<T: Sync>() {}
//! need_sync::<TreeSitePreparation>();
//! ```
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::TreeClient;
//! fn need_send<T: Send>() {}
//! need_send::<TreeClient>();
//! ```
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::TreeClient;
//! fn need_sync<T: Sync>() {}
//! need_sync::<TreeClient>();
//! ```
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::TreeThread;
//! fn need_send<T: Send>() {}
//! need_send::<TreeThread>();
//! ```
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::TreeThread;
//! fn need_sync<T: Sync>() {}
//! need_sync::<TreeThread>();
//! ```
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::PreparedOriginalTreeCall;
//! fn need_send<T: Send>() {}
//! need_send::<PreparedOriginalTreeCall<'static>>();
//! ```
//! ```compile_fail,E0277
//! use rapid_profiler::frontend_native::PreparedOriginalTreeCall;
//! fn need_sync<T: Sync>() {}
//! need_sync::<PreparedOriginalTreeCall<'static>>();
//! ```
//! The original-call guard holds the preparation's exclusive borrow until it is
//! consumed or dropped; the preparation cannot be inspected while it is live:
//! ```compile_fail,E0502
//! use rapid_profiler::frontend_native::TreeSitePreparation;
//! fn inspect(prep: &mut TreeSitePreparation) {
//!     let call = unsafe { prep.prepare_original_call() }.unwrap();
//!     let _ = prep.plan();
//!     drop(call);
//! }
//! ```
//! Consuming that guard grants exactly one original invocation:
//! ```compile_fail,E0382
//! use rapid_profiler::frontend_native::{PreparedOriginalTreeCall, ReadableStack};
//! unsafe fn twice(call: PreparedOriginalTreeCall<'_>, bytes: &[u8], stack: &ReadableStack) {
//!     let _ = unsafe { call.invoke(bytes, stack) };
//!     let _ = unsafe { call.invoke(bytes, stack) };
//! }
//! ```
//! The metadata controller can be transferred to a controller thread. This
//! does not transfer the local caller, source preparation or original-call guard:
//! ```
//! use rapid_profiler::frontend_native::TreeController;
//! fn need_send<T: Send>() {}
//! need_send::<TreeController>();
//! ```

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
    BridgeError, EpochStorageReclaimError, HistoryBatch, HistoryBinding, HistoryFormat,
    HistoryStream, HistoryWindow, IntervalBatch, IntervalClient, IntervalController, IntervalEpoch,
    IntervalEpochStorage, IntervalJournal, IntervalThread, PairTotals, PreparedIntervalController,
    ReadableStack,
};

/// Explicit final-ELF-bound selection; loading still requires its unsafe contract.
pub use module::ordinary::TrustedFunctionSelection;
/// Separate bounded scalar-symbol admission; no publication or interval execution.
pub use module::ordinary::{IntegerLeafCertificate, IntegerLeafContract, LoadedIntegerLeaf};
/// Separate ordinary-caller admission without a per-call library gate.
pub use module::ordinary::{LoadedNormalLeaf, NormalLeafContract};
pub use module::ordinary::{LoadedTwoCallerNormalLeaf, TwoCallerNormalLeafContract};

/// Closed two-function admission only; execution awaits its separate tree profile.
pub use module::ordinary::{
    CallTreeCertificate, LoadedCallTree, TreeCallEdge, TreeContract, TreeRootCertificate,
};

pub use always_on::normal::{
    NormalAcknowledgement, NormalBatch, NormalClient, NormalRecord, NormalThread, NormalTotals,
    PreparedNormalController, PreparedTwoCallerNormalController,
};
pub use always_on::site::ordinary::{InstalledNormalSite, NormalSitePreparation};
pub use always_on::site::ordinary::{InstalledTwoCallerNormalSite, TwoCallerNormalSitePreparation};
/// Separate ordinary scalar-function interval profile; raw, uncalibrated timing.
pub use always_on::site::ordinary::{OrdinarySitePreparation, PreparedOriginalCall};
pub use always_on::{
    CallGate, CallResult, GateError, GateProfile, OriginalCallResult, RawInterval,
    RawIntervalOwner, RawTimestamp, ReferenceCallResult, ReferenceInterval, ReferenceLeg,
    ReferenceOriginalCallResult, ReferenceTimestamp,
};

/// Finite independent backoff control with bounded owned exports; hooks stay on.
pub mod backoff;

/// Separate optional ordinary observation with an authenticated real fast return.
pub use always_on::optional::{
    InstalledOptionalSite, OptionalCallGate, OptionalCallResult, OptionalClient,
    OptionalController, OptionalIntervalBatch, OptionalPath, OptionalSitePreparation,
    OptionalThread, OptionalTotals, PreparedOptionalController, PreparedOptionalOriginalCall,
};

/// Closed depth-two ordinary call tree with original CALL/return-word geometry.
/// Distinct from leaf admission; no recursion, tail calls or timing accuracy.
pub use always_on::tree::{
    InstalledTreeSite, OriginalTreeCallResult, OriginalTreeSourceBatch, PreparedOriginalTreeCall,
    PreparedTreeCall, PreparedTreeController, TreeBatch, TreeCallGate, TreeCallResult, TreeClient,
    TreeController, TreeError, TreeRecord, TreeSitePreparation, TreeSourceBatch,
    TreeSourceBatchError, TreeSourceBatchRequest, TreeSourceBatchVerification, TreeThread,
    TreeTotals,
};
