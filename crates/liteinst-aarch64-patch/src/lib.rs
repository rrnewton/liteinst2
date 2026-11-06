//! Stopped-executor runtime patching for AArch64 Linux, built on the
//! fact-only `liteinst-aarch64` decoder/emitter.
//!
//! This crate owns the unsafe runtime surface (dual RW/RX mappings,
//! cache maintenance, and — in a later slice — the aligned site store)
//! so the fact crate stays `no_std` and `forbid(unsafe_code)`. The
//! protocol contract is `crates/liteinst-aarch64/RUNTIME-PATCHER-DESIGN.md`:
//! exclusive publication lease, both-valid invariant, retained custody
//! on post-store failure, and no lock-free or BLR low-page claim.
//!
//! Slice 2 surface: error taxonomy, page-size query, [`cache`]
//! maintenance + environment probe, [`island::Island`] RAII, and the
//! [`site`] custody/state types the flip slice will drive. Flip and
//! rollback execution are intentionally not present yet.

#![warn(missing_docs)]

pub mod cache;
pub mod island;
pub mod site;

pub use island::Island;
pub use site::{
    FallbackPermission, PendingWord, ResumeState, Site, SiteRegistry, SiteState, StopControl,
    StrategyPreference, TrapRoute,
};

/// Everything that can refuse or fail before a store, plus the named
/// custody outcomes after one. Pre-store variants are no-write
/// refusals; post-store outcomes are represented by [`SiteState`],
/// never collapsed into a plain failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// The operation is not available on this target/environment.
    Unsupported(&'static str),
    /// An OS call failed; `errno` is its raw error number (0 if the
    /// platform reported none).
    Os {
        /// Which call failed (static name, e.g. `"mmap rx"`).
        op: &'static str,
        /// Raw OS error number.
        errno: i32,
    },
    /// EL0 cache maintenance is unavailable (probe child died or the
    /// environment precondition was never established).
    CacheOpsUnavailable,
    /// An island must contain at least one word.
    EmptyIsland,
    /// Address/length arithmetic overflowed.
    RangeOverflow,
    /// A second live site already names this address.
    DuplicateSite {
        /// The duplicated site address.
        addr: u64,
    },
    /// A helper child could not be reaped even after `SIGKILL` and a
    /// bounded retry window; custody of `pid` is explicitly retained
    /// by the caller, who keeps termination/reaping responsibility for
    /// it. (Caller exit merely reparents a still-live child to init or
    /// a subreaper, which reaps it only when it eventually terminates;
    /// nothing is auto-reaped on the caller's behalf.) Returned instead
    /// of silently losing the PID.
    ChildCustodyRetained {
        /// The unreaped child process id.
        pid: i32,
    },
}

impl PatchError {
    pub(crate) fn os(op: &'static str) -> Self {
        Self::Os {
            op,
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        }
    }
}

impl core::fmt::Display for PatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::Os { op, errno } => write!(f, "{op} failed (errno {errno})"),
            Self::CacheOpsUnavailable => write!(f, "EL0 cache maintenance unavailable"),
            Self::EmptyIsland => write!(f, "island must contain at least one word"),
            Self::RangeOverflow => write!(f, "address range overflow"),
            Self::DuplicateSite { addr } => {
                write!(f, "a live site already names address {addr:#x}")
            }
            Self::ChildCustodyRetained { pid } => {
                write!(
                    f,
                    "helper child {pid} could not be reaped; custody retained"
                )
            }
        }
    }
}

impl std::error::Error for PatchError {}

/// Runtime OS page size (`sysconf(_SC_PAGESIZE)` on Linux), queried
/// never assumed. The emit facts' page arithmetic takes this value as
/// a parameter; nothing here hardcodes 4 KiB or 64 KiB.
#[cfg(target_os = "linux")]
pub fn page_size() -> Result<u64, PatchError> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(PatchError::os("sysconf(_SC_PAGESIZE)"));
    }
    Ok(value as u64)
}

/// Runtime OS page size (see the Linux form).
#[cfg(not(target_os = "linux"))]
pub fn page_size() -> Result<u64, PatchError> {
    Err(PatchError::Unsupported("page size query requires Linux"))
}

/// Patcher session: cache attestation plus the site registry. Flip
/// execution arrives in the next slice; construction already occupies
/// the design's attestation point so call sites do not change shape.
#[derive(Debug, Default)]
pub struct Patcher {
    registry: SiteRegistry,
    attested: Option<cache::CacheAttested>,
}

impl Patcher {
    /// New patcher without cache attestation (protocol-host use and
    /// tests; execution paths will require attestation).
    pub fn new() -> Self {
        Self::default()
    }

    /// New patcher after establishing the cache-op environment
    /// precondition before any store (forked-child probe).
    pub fn attested() -> Result<Self, PatchError> {
        Ok(Self {
            registry: SiteRegistry::new(),
            attested: Some(cache::probe_environment()?),
        })
    }

    /// Whether construction attested cache-op availability.
    pub fn is_attested(&self) -> bool {
        self.attested.is_some()
    }

    /// The owned site registry.
    pub fn registry(&mut self) -> &mut SiteRegistry {
        &mut self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn page_size_is_a_power_of_two() {
        let page = page_size().unwrap();
        assert!(page.is_power_of_two());
        assert!(page >= 4096);
    }

    #[test]
    fn patcher_starts_unattested_with_empty_registry() {
        let mut patcher = Patcher::new();
        assert!(!patcher.is_attested());
        assert!(patcher.registry().is_empty());
    }
}
