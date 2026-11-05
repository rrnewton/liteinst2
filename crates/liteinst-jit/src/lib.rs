//! Bounded direct-block translation with folded branch counting.
//!
//! Phase P1a envelope: straight-line code plus direct branches over
//! private, non-writable source mappings, single-threaded guests.
//! Indirect control flow, self-modifying code, and `execve`
//! successors refuse by name (see [`Refuse`]). Syscall-class and
//! nondeterministic instructions end their block and exit to a
//! caller-supplied handler; they never execute natively from the
//! cache. This crate makes no whole-program claim.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("liteinst-jit requires Linux x86-64");

pub mod cache;
pub mod decode;
pub mod exec;
pub mod fixtures;
pub mod handler;
pub mod harness;
pub mod o1;
pub mod pcmap;
pub mod recovery;
pub mod refuse;
pub mod remote;
pub mod state;
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
