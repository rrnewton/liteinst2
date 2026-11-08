//! Stopped-executor runtime patching for AArch64 Linux, built on the
//! fact-only `liteinst-aarch64` decoder/emitter.
//!
//! This crate owns the unsafe runtime surface (dual RW/RX mappings,
//! cache maintenance, and the aligned site store)
//! so the fact crate stays `no_std` and `forbid(unsafe_code)`. The
//! protocol contract is `crates/liteinst-aarch64/RUNTIME-PATCHER-DESIGN.md`:
//! exclusive publication lease, both-valid invariant, retained custody
//! on post-store failure, and no lock-free or BLR low-page claim.
//!
//! The surface covers the error taxonomy, page-size query,
//! [`cache`] maintenance and environment probe,
//! [`island::Island`], the [`site`] custody types, the [`store`]
//! seam, mapping qualification, and the [`flip`] protocol
//! (flip / complete_sync / rollback), all driven through the
//! [`gate`] syscall entry.

#![warn(missing_docs)]

pub mod cache;
pub mod flip;
pub mod gate;
pub mod island;
pub mod mapping;
pub mod site;
pub mod store;

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
    /// Words were offered to an island that is already published.
    AlreadyPublished,
    /// Address/length arithmetic overflowed.
    RangeOverflow,
    /// More words were offered than a reserved island can hold.
    CapacityExceeded {
        /// Words the island was reserved for.
        capacity_words: usize,
        /// Words offered to fill.
        offered: usize,
    },
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
    /// The site address is not word aligned; no strategy can repair
    /// that, so the flip refuses before any fallback is considered.
    MisalignedSite {
        /// The offending site address.
        addr: u64,
    },
    /// The word recorded at construction is not an `SVC`.
    NotSvc {
        /// The recorded site word.
        word: u32,
    },
    /// Under the lease the site no longer holds the exact word (or,
    /// for rollback, the flipped word) revalidation requires.
    SiteWordChanged {
        /// The word revalidation expected.
        expected: u32,
        /// The word found instead.
        found: u32,
    },
    /// The site is not in a state this operation may start from.
    WrongState {
        /// The state the site was found in.
        state: site::SiteState,
    },
    /// No permitted strategy can serve this site (for example
    /// BranchOnly with no reachable island).
    StrategyUnavailable(&'static str),
    /// Trap was selected (or needed as fallback) without a pre-armed
    /// owned route for this site/generation.
    TrapNotArmed,
    /// The site's mapping may not be windowed (shared, unknown,
    /// non-executable, or absent). Named before any construction.
    MappingRefused(&'static str),
    /// Presented mapping facts belong to a different generation than
    /// the site was qualified under.
    StaleGeneration {
        /// The site's recorded generation.
        site: u64,
        /// The generation of the presented facts.
        facts: u64,
    },
    /// This patcher was constructed before a fork; its registry and
    /// custodies are the parent's. The child must construct a new
    /// patcher instead of operating this one.
    ForkedRegistry,
    /// The single site store failed after the window opened. The
    /// word may or may not have landed; the site stays in
    /// `SyncPending` custody and `complete_sync` settles it by
    /// re-reading (original word -> back to `Unpatched`, patch word
    /// -> `Flipped`, anything else refuses still stopped).
    StoreFailed {
        /// The underlying store error.
        source: Box<PatchError>,
    },
    /// The store landed but cache synchronization failed; the site is
    /// in `SyncPending`/`RetainedStop` custody, never "not flipped".
    /// The underlying sync error is preserved, not swallowed.
    SyncFailed {
        /// The synchronization error that left publication pending.
        source: Box<PatchError>,
    },
    /// The store window itself was refused at open, before this
    /// operation issued a store (for example a platform-policy
    /// mprotect denial). Downstream store selection keys on
    /// exactly this variant. A rollback of an already-flipped
    /// site can also produce it when re-opening the window for
    /// the restoring store. Executor state depends on the site's
    /// state: from `Unpatched`/`Flipped` the lease was released
    /// before this error returns, but a rollback out of
    /// `SyncPending`/`RetainedStop` custody returns it with the
    /// stop still HELD — executors remain stopped and the caller
    /// must not resume them onto the pending page.
    WindowRefused {
        /// The window-open error from the store backend.
        source: Box<PatchError>,
    },
    /// The store landed and synced, but restoring the window's
    /// original protections failed; the site is in
    /// `SyncPending`/`RetainedStop` custody with the window still
    /// open. The custody STATE still reuses SyncPending (settled
    /// design); only the error names the failing stage.
    RestoreFailed {
        /// The restore error that left publication pending.
        source: Box<PatchError>,
    },
    /// A pre-store refusal under the lease could not cleanly release
    /// it (resume errored or left an executor unacknowledged). The
    /// site was not written; stop custody outcome is named, not
    /// silently treated as released.
    CleanupFailed {
        /// The word revalidation expected.
        expected: u32,
        /// The word found instead.
        found: u32,
    },
    /// Resume did not produce a synchronization acknowledgement from
    /// every executor; custody (and any retained stop) persists.
    ResumeIncomplete,
}

impl core::fmt::Display for PatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::Os { op, errno } => write!(f, "{op} failed (errno {errno})"),
            Self::CacheOpsUnavailable => write!(f, "EL0 cache maintenance unavailable"),
            Self::EmptyIsland => write!(f, "island must contain at least one word"),
            Self::AlreadyPublished => write!(f, "island is already published"),
            Self::RangeOverflow => write!(f, "address range overflow"),
            Self::CapacityExceeded {
                capacity_words,
                offered,
            } => write!(f, "island holds {capacity_words} words, {offered} offered"),
            Self::DuplicateSite { addr } => {
                write!(f, "a live site already names address {addr:#x}")
            }
            Self::ChildCustodyRetained { pid } => {
                write!(
                    f,
                    "helper child {pid} could not be reaped; custody retained"
                )
            }
            Self::MisalignedSite { addr } => {
                write!(f, "patch site {addr:#x} is not word aligned")
            }
            Self::NotSvc { word } => write!(f, "site word {word:#010x} is not SVC"),
            Self::SiteWordChanged { expected, found } => {
                write!(
                    f,
                    "site word changed: expected {expected:#010x}, found {found:#010x}"
                )
            }
            Self::WrongState { state } => write!(f, "site is in state {state:?}"),
            Self::StrategyUnavailable(why) => write!(f, "no strategy available: {why}"),
            Self::TrapNotArmed => write!(f, "trap selected without an armed owned route"),
            Self::MappingRefused(why) => write!(f, "mapping refused: {why}"),
            Self::StaleGeneration { site, facts } => {
                write!(f, "mapping generation mismatch: site {site}, facts {facts}")
            }
            Self::ForkedRegistry => {
                write!(
                    f,
                    "patcher registry predates a fork; construct a new patcher"
                )
            }
            Self::StoreFailed { source } => write!(f, "site store failed: {source}"),
            Self::SyncFailed { source } => {
                write!(f, "post-store cache synchronization failed: {source}")
            }
            Self::RestoreFailed { source } => {
                write!(f, "post-store protection restore failed: {source}")
            }
            Self::WindowRefused { source } => {
                write!(
                    f,
                    "store window refused before this operation's store: {source}"
                )
            }
            Self::CleanupFailed { expected, found } => {
                write!(
                    f,
                    "site word changed (expected {expected:#010x}, found {found:#010x}) \
                     and lease cleanup did not fully acknowledge"
                )
            }
            Self::ResumeIncomplete => {
                write!(f, "resume without full synchronization acknowledgement")
            }
        }
    }
}

impl std::error::Error for PatchError {}

/// Runtime OS page size (`AT_PAGESZ` on Linux), queried
/// never assumed. The emit facts' page arithmetic takes this value as
/// a parameter; nothing here hardcodes 4 KiB or 64 KiB.
#[cfg(target_os = "linux")]
pub fn page_size() -> Result<u64, PatchError> {
    // AT_PAGESZ from the auxiliary vector: getauxval reads process
    // memory only, issuing no syscall a guest filter could see.
    let value = unsafe { libc::getauxval(libc::AT_PAGESZ) };
    if value == 0 {
        return Err(PatchError::Unsupported("AT_PAGESZ absent"));
    }
    Ok(value)
}

/// Runtime OS page size (see the Linux form).
#[cfg(not(target_os = "linux"))]
pub fn page_size() -> Result<u64, PatchError> {
    Err(PatchError::Unsupported("page size query requires Linux"))
}

/// Patcher session: cache attestation plus the site registry.
/// Construction occupies the design's attestation point, so flip,
/// completion, and rollback callers do not change shape when the
/// environment probe result changes.
pub struct Patcher {
    registry: SiteRegistry,
    attested: Option<cache::CacheAttested>,
    sync: unsafe fn(*mut u8, *mut u8, usize) -> Result<(), PatchError>,
    owner_pid: u32,
}

impl core::fmt::Debug for Patcher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Patcher")
            .field("registry", &self.registry)
            .field("is_attested", &self.is_attested())
            .finish_non_exhaustive()
    }
}

impl Default for Patcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Patcher {
    /// New patcher without cache attestation. Flip and rollback
    /// refuse before any store until attested (the capability gate is
    /// production behavior, not a test bypass).
    pub fn new() -> Self {
        Self {
            registry: SiteRegistry::new(),
            attested: None,
            sync: cache::sync_icache,
            owner_pid: gate::getpid(),
        }
    }

    /// New patcher after establishing the cache-op environment
    /// precondition before any store (forked-child probe).
    pub fn attested() -> Result<Self, PatchError> {
        Ok(Self {
            registry: SiteRegistry::new(),
            attested: Some(cache::probe_environment()?),
            sync: cache::sync_icache,
            owner_pid: gate::getpid(),
        })
    }

    /// Attested patcher with an injected cache-sync function, so
    /// downstream custody tests can drive sync/restore failures
    /// through production flip paths. The attestation gate is not
    /// bypassed: construction still probes the environment.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn attested_with_sync(
        sync: unsafe fn(*mut u8, *mut u8, usize) -> Result<(), PatchError>,
    ) -> Result<Self, PatchError> {
        let mut patcher = Self::attested()?;
        patcher.sync = sync;
        Ok(patcher)
    }

    /// Test-only seam: attested patcher with an injected sync function,
    /// so host fault injection exercises post-store custody without
    /// bypassing the production attestation gate or real sync.
    #[cfg(test)]
    pub(crate) fn for_test(
        sync: unsafe fn(*mut u8, *mut u8, usize) -> Result<(), PatchError>,
    ) -> Self {
        Self::with_test_token(sync)
    }

    /// Downstream test-support seam: the same synthetic attestation
    /// as `for_test`, available only with the `test-support`
    /// feature so downstream custody tests can construct pending
    /// sites on hosts where the real probe is unsupported.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_with_sync(
        sync: unsafe fn(*mut u8, *mut u8, usize) -> Result<(), PatchError>,
    ) -> Self {
        Self::with_test_token(sync)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn with_test_token(sync: unsafe fn(*mut u8, *mut u8, usize) -> Result<(), PatchError>) -> Self {
        Self {
            registry: SiteRegistry::new(),
            attested: Some(cache::CacheAttested::for_test()),
            sync,
            owner_pid: gate::getpid(),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_owner_pid_for_test(&mut self, pid: u32) {
        self.owner_pid = pid;
    }

    pub(crate) fn sync_range(
        &self,
        rw: *mut u8,
        rx: *mut u8,
        len: usize,
    ) -> Result<(), PatchError> {
        // SAFETY: forwarded to the configured sync with its contract;
        // callers pass dual aliases of one valid range.
        unsafe { (self.sync)(rw, rx, len) }
    }

    /// Whether construction attested cache-op availability.
    pub fn is_attested(&self) -> bool {
        self.attested.is_some()
    }

    /// The attestation token publication requires, when present.
    pub(crate) fn attested_token(&self) -> Option<cache::CacheAttested> {
        self.attested
    }

    /// Refuse if this patcher outlived a fork: registries, islands,
    /// and custodies are parent-image state (see the design note).
    pub(crate) fn check_fork(&self) -> Result<(), PatchError> {
        if gate::getpid() != self.owner_pid {
            return Err(PatchError::ForkedRegistry);
        }
        Ok(())
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
