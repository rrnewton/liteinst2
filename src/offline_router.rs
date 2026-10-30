//! Opt-in static-ET_EXEC constructor bootstrap using the production SIGILL router.
//!
//! Structural catalogs do not prove semantic qualification or a startup lease.
//! The only activation entry is unsafe; there is no generic safe route publisher.
use liteinst_artifact::startup::{Catalog, Error as CatalogError};
use std::sync::atomic::{AtomicBool, Ordering};

mod compiler;
mod host;
pub use compiler::{catalog_from_plans, catalog_from_plans_absolute_prerequisites};

/// Typed startup failure. The constructor must terminate on every error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    /// Invalid, incomplete or mismatched authenticated catalog.
    Catalog(CatalogError),
    /// Kernel auxv/main mapping/file ownership is incompatible.
    Ownership,
    /// CPU/xstate/CET, stack, environment or single-thread state is incompatible.
    Platform,
    /// The actual production router refused signal or route ownership.
    Signal,
    /// Required Linux sync-core preparation or barrier failed.
    Synchronization,
    /// This process already attempted initialization; no retry is permitted.
    AlreadyAttempted,
    /// Bounded file or observation operation failed.
    Io,
}
impl From<CatalogError> for StartupError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}
static ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Authenticate and activate one offline main at its DSO constructor boundary.
///
/// This does not patch or map executable bytes. All main LOADs already belong to
/// kernel exec. Every error is terminal for the caller: it MUST exit before main.
/// The catalog byte slice must be the immutable, embedded RO object in the owned
/// bootstrap DSO. An arbitrary heap catalog fails the mapping checks.
///
/// # Safety
/// The package owner has independently qualified the complete catalog's plans,
/// heads, ISA, immediate provenance, null-hook ABI and code-as-data contract. No
/// unwind, exception, asynchronous handler, stack switch beyond the catalog's
/// authored 64KiB stack, or unsupported xstate use may enter generated code.
/// The original main and every saved main continuation are still unreachable:
/// this is the sole bootstrap constructor under the reviewed pinned interpreter
/// and dependency graph, not dlopen, preload, or a normal function call. No earlier
/// resolver/constructor may call main code, spawn a thread, replace a signal
/// disposition, or retain a main continuation. Observed one-thread state cannot
/// prove that history or exclude a concurrent unobserved executor by itself.
/// The admitted loader configuration has CET/IBT disabled, eagerly binds this DSO,
/// initializes Rust/libc/TLS before this constructor, and transfers only to the
/// original AT_ENTRY after success. Kernel SHSTK status is checked independently.
/// Loader-injection environment and secure-exec/file capabilities are excluded
/// BEFORE exec; constructor checks cannot undo execution of an injected loader.
/// The whole main, generated images, this DSO/router and all dependencies remain
/// mapped, unmodified and owned until process exit. No dlclose, fork, new threads,
/// SIGILL masking/replacement or address reuse is allowed. This is install-once,
/// not an inferred lifetime or general live-publication capability.
/// Kernel/app stack headroom and bounded application depth remain within the
/// checked reserve for production SA_SIGINFO delivery and generated hook frames.
/// The caller must enforce these remaining facts through the reviewed package
/// construction/launch contract identified in the catalog, not unchecked booleans.
pub unsafe fn initialize_static_exec(catalog_bytes: &'static [u8]) -> Result<(), StartupError> {
    if ATTEMPTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(StartupError::AlreadyAttempted);
    }
    let catalog = Catalog::decode(catalog_bytes)?;
    let owned = host::observe(&catalog, catalog_bytes)?;
    let sync = crate::sync_core::SyncCore::prepare().map_err(|_| StartupError::Synchronization)?;
    crate::entry_router::prepare().map_err(|_| StartupError::Signal)?;
    let routes = catalog
        .routes()
        .into_iter()
        .map(|(original, generated)| crate::contracts::EntryRoute {
            original,
            generated,
        })
        .collect::<Vec<_>>();
    let mut registration = if routes.is_empty() {
        None
    } else {
        // SAFETY: caller's exclusive startup/lifetime contract plus the complete
        // file/map/byte/target checks above cover every source and destination.
        Some(unsafe { crate::entry_router::stage(&routes) }.map_err(|_| StartupError::Signal)?)
    };
    sync.synchronize()
        .map_err(|_| StartupError::Synchronization)?;
    owned.recheck(&catalog)?;
    crate::entry_router::verify().map_err(|_| StartupError::Signal)?;
    if let Some(r) = &mut registration {
        r.commit();
    }
    // The production registry retains its immutable batch; retain authenticated
    // file descriptors and catalog evidence for the same process lifetime.
    std::mem::forget((owned, catalog));
    Ok(())
}
