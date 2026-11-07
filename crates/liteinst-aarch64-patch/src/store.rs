//! The store seam for foreign text: how the patcher opens, writes,
//! and closes the single-word store window around a site it does not
//! own through a dual mapping.
//!
//! The patch crate defines this trait and ships only the
//! `DualAliasStore` for managed dual mappings. Foreign backends
//! (leased `mprotect` window; `/proc/self/mem` under an explicit
//! selector permission) are implemented by the downstream
//! integration (reverie-liteinst) against its own mapping census,
//! per the settled hookup boundary.

use crate::PatchError;

/// How one site's word gets written. The three operations pair up:
/// `begin_write` opens the store window, exactly one `store_word`
/// issues the design's single aligned store, and `finish_write`
/// restores the pre-window state. The patcher calls cache
/// synchronization between store and finish; backends never sync.
///
/// # Safety
/// Implementors guarantee that `store_word` writes the same physical
/// word the CPU executes at the site's RX address, for the mapping
/// generation the site was qualified under. `begin_write` MUST be
/// idempotent (succeeding again on an already-open window):
/// rollback and completion paths legitimately call it a second
/// time on a window whose first finish failed. A window MUST keep
/// the page executable throughout (RWX, with BTI preserved): other
/// stopped-set executors may already be parked on the page, and an
/// RW-only window faults them. `finish_write` is idempotent (a
/// no-op once the window is closed) so completion paths may retry
/// it. A backend that names a different word makes every flip
/// publish into unrelated memory.
pub unsafe trait SiteStore: Send {
    /// Read the current site word (RX view of the same physical word).
    fn read_word(&self) -> u32;
    /// The address DC maintenance cleans through (the written VA).
    fn write_addr(&self) -> u64;
    /// Open the store window (e.g. lease `mprotect` RWX over the
    /// minimal page span, recording exact original protections).
    /// Idempotent: opening an already-open window succeeds.
    fn begin_write(&mut self) -> Result<(), PatchError>;
    /// Issue the single aligned 4-byte store. A partial write is an
    /// error and is never retried blindly by the patcher.
    fn store_word(&mut self, word: u32) -> Result<(), PatchError>;
    /// Close the window, restoring exact original protections.
    /// Idempotent: succeeding twice is success.
    fn finish_write(&mut self) -> Result<(), PatchError>;
}

/// The shipped managed-mapping backend: store through the RW alias of
/// a dual mapping. No window: begin/finish are no-ops.
pub(crate) struct DualAliasStore {
    rw: *mut u32,
}

impl DualAliasStore {
    pub(crate) fn new(rw: *mut u32) -> Self {
        Self { rw }
    }
}

// SAFETY: the alias pointer is only dereferenced under the Site
// construction contract (same physical word, shared backing outlives
// the site); the store itself carries no thread-affine state.
unsafe impl Send for DualAliasStore {}

// SAFETY: volatile store through the RW alias names exactly the word
// executed via the RX alias of the same shared backing.
unsafe impl SiteStore for DualAliasStore {
    fn read_word(&self) -> u32 {
        // SAFETY: alias validity is the Site construction contract.
        unsafe { self.rw.read_volatile() }
    }
    fn write_addr(&self) -> u64 {
        self.rw as u64
    }
    fn begin_write(&mut self) -> Result<(), PatchError> {
        Ok(())
    }
    fn store_word(&mut self, word: u32) -> Result<(), PatchError> {
        // SAFETY: alias validity is the Site construction contract.
        unsafe { self.rw.write_volatile(word) };
        Ok(())
    }
    fn finish_write(&mut self) -> Result<(), PatchError> {
        Ok(())
    }
}
