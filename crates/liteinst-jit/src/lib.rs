//! Bounded direct-block translation with folded branch counting.
//!
//! Phase P1a envelope: straight-line code plus direct branches over
//! private, non-writable source mappings, as asserted by the caller,
//! single-threaded guests. Admission checks the caller's
//! `RegionFacts::immutable_private` flag and does not read the
//! mapping's protections
//! (<https://github.com/rrnewton/liteinst2/issues/107>).
//! Self-modifying code is not tracked, and nothing invalidates a
//! translation when a mapping changes yet: dispatch looks
//! translations up by address
//! (<https://github.com/rrnewton/liteinst2/issues/104>).
//! P1b.1 adds in-region indirect jumps and calls, resolved through
//! the dispatcher (`indirect`); out-of-region and unsupported
//! indirect forms and `execve` successors refuse by name (see
//! [`Refuse`]). Syscall-class and
//! nondeterministic instructions end their block and exit to a
//! caller-supplied handler; they never execute natively from the
//! cache. The remote substrate (`remote`) adds the tested
//! genuine signal-delivery shapes (P1B I1-D through I1-G2, see
//! `P1B-DESIGN.md` §8) and stops every other shape as a
//! recovered outcome; its ptrace, cross-process memory and wait
//! requests go through the tracee seam (`tracee`). This crate
//! makes no whole-program claim.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("liteinst-jit requires Linux x86-64");

#[cfg(feature = "test-seams")]
pub mod attach;
pub mod cache;
pub mod decode;
pub mod exec;
pub mod fixtures;
pub mod handler;
pub mod harness;
pub mod indirect;
pub mod o1;
pub mod pcmap;
pub mod recovery;
pub mod refuse;
pub mod remote;
pub mod state;
pub mod tracee;
pub mod translate;
pub mod types;

pub use cache::{CacheIndex, CacheRecord};
pub use exec::{
    Executable, Fault, FaultKind, GuestMemory, Handler, Outcome, ProcessMemory, Resume, RunError,
};
pub use pcmap::{CallStage, CommonStage, ExitStage, PcMap, PcMapEntry, Phase, Recovery, StubStage};
pub use recovery::{FaultInput, RecoveredStop, RecoveryInput, recover};
pub use refuse::Refuse;
pub use state::GuestState;
pub use translate::{
    Block, ExitStyle, Terminator, Translation, translate, translate_with_exit_style,
};
pub use types::{CacheKey, CountProfile, Generation, RegionFacts, byte_hash};
