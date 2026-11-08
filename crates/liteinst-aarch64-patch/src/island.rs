//! Dual RW/RX island mappings: the only executable memory this crate
//! creates. One memfd backing is mapped twice (`MAP_SHARED`), writable
//! through the RW alias and executable through the RX alias, so no
//! virtual address is ever writable and executable at once.

use crate::PatchError;
use crate::cache::CacheAttested;
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use crate::cache::sync_icache;
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use liteinst_aarch64::emit::page_span;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
/// `MFD_EXEC` (kernel 6.3+); defined locally so the locked libc version
/// need not carry the constant. Retried without it on `EINVAL`
/// (pre-6.3 kernels reject the unknown flag; their memfds are
/// executable by default).
const L_MFD_EXEC: libc::c_uint = 0x0010;

/// An owned island mapping. While any flipped site branches here, the
/// owning `Site` custody holds this value; `Drop` unmaps both aliases,
/// so slice-1 retirement rules (deferred until no executor can enter,
/// permanent retention on uncertainty) are the caller's protocol duty
/// the flip protocol binds lifetimes in the Site type.
pub struct Island {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    rw: *mut u8,
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    rx: *mut u8,
    len: usize,
    words: usize,
    capacity_words: usize,
    published: bool,
}

impl core::fmt::Debug for Island {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Island")
            .field("entry", &self.entry_addr())
            .field("len", &self.len)
            .field("words", &self.words)
            .finish()
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn memfd_exec() -> Result<libc::c_int, PatchError> {
    let name = c"liteinst-island";
    let base = (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as u64;
    // SAFETY: name is a valid C string; flags are the kernel's.
    let fd = unsafe {
        crate::gate::gate6(
            libc::SYS_memfd_create,
            [name.as_ptr() as u64, base | L_MFD_EXEC as u64, 0, 0, 0, 0],
        )
    };
    if fd >= 0 {
        return Ok(fd as libc::c_int);
    }
    if fd == -(libc::EINVAL as i64) {
        // SAFETY: same name; retry without the post-6.3 flag.
        let fd = unsafe {
            crate::gate::gate6(
                libc::SYS_memfd_create,
                [name.as_ptr() as u64, base, 0, 0, 0, 0],
            )
        };
        if fd >= 0 {
            return Ok(fd as libc::c_int);
        }
        // Report the retry's errno: it, not the flag rejection, is why
        // creation ultimately failed.
        return crate::gate::check(fd, "memfd_create (no MFD_EXEC retry)")
            .map(|v| v as libc::c_int);
    }
    crate::gate::check(fd, "memfd_create").map(|v| v as libc::c_int)
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn gate_close(fd: libc::c_int) {
    // SAFETY: fd was just created above and is closed exactly once.
    unsafe {
        crate::gate::gate6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]);
    }
}

impl Island {
    /// Map a fresh island of `page_span(page_size, words*4)` bytes and
    /// write `words` via the RW alias. The island is fresh (created
    /// here), unreachable (nothing branches to it yet), and exclusively
    /// owned — the three conditions under which pre-lease writes are
    /// sound. Call [`Island::publish`] before any branch targets it.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub fn build(words: &[u32]) -> Result<Self, PatchError> {
        if words.is_empty() {
            return Err(PatchError::EmptyIsland);
        }
        let mut island = Self::reserve(words.len())?;
        island.fill(words)?;
        Ok(island)
    }

    /// Map a fresh island with room for `capacity_words` words and no
    /// payload yet, so entry-dependent words (branches back to a site)
    /// can be computed from the real entry address and then filled
    /// with [`fill`](Self::fill) before publication.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub fn reserve(capacity_words: usize) -> Result<Self, PatchError> {
        if capacity_words == 0 {
            return Err(PatchError::EmptyIsland);
        }
        let page = crate::page_size()?;
        let payload = (capacity_words as u64)
            .checked_mul(4)
            .ok_or(PatchError::RangeOverflow)?;
        let len = page_span(page, payload).ok_or(PatchError::RangeOverflow)? as usize;
        let fd = memfd_exec()?;
        // SAFETY: fd is the memfd just created; len is its size.
        let rc =
            unsafe { crate::gate::gate6(libc::SYS_ftruncate, [fd as u64, len as u64, 0, 0, 0, 0]) };
        if rc != 0 {
            let e = crate::gate::check(rc, "ftruncate").unwrap_err();
            gate_close(fd);
            return Err(e);
        }
        // SAFETY: fresh sized memfd; the two shared mappings are the
        // island's dual aliases for `len` bytes.
        let map = |prot: libc::c_int| unsafe {
            crate::gate::gate6(
                libc::SYS_mmap,
                [
                    0,
                    len as u64,
                    prot as u64,
                    libc::MAP_SHARED as u64,
                    fd as u64,
                    0,
                ],
            )
        };
        let rw = map(libc::PROT_READ | libc::PROT_WRITE);
        if (-4095..0).contains(&rw) {
            let e = crate::gate::check(rw, "mmap rw").unwrap_err();
            gate_close(fd);
            return Err(e);
        }
        let rx = map(libc::PROT_READ | libc::PROT_EXEC);
        if (-4095..0).contains(&rx) {
            let e = crate::gate::check(rx, "mmap rx").unwrap_err();
            // SAFETY: rw is the live mapping just created above.
            unsafe {
                crate::gate::gate6(libc::SYS_munmap, [rw as u64, len as u64, 0, 0, 0, 0]);
            }
            gate_close(fd);
            return Err(e);
        }
        // The mappings keep the memfd alive; close the fd now so a
        // published island (retained for process lifetime) never
        // leaks a guest-visible fd number per flipped site.
        gate_close(fd);
        Ok(Self {
            rw: rw as *mut u8,
            rx: rx as *mut u8,
            len,
            words: 0,
            capacity_words,
            published: false,
        })
    }

    /// Reserve a fresh island (see the Linux form).
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    pub fn reserve(_capacity_words: usize) -> Result<Self, PatchError> {
        Err(PatchError::Unsupported("islands require AArch64 Linux"))
    }

    /// Write the payload words of a reserved island (may be called
    /// repeatedly before publication to revise them). After
    /// [`publish`](Self::publish) this returns
    /// `PatchError::AlreadyPublished`: published text is immutable.
    pub fn fill(&mut self, words: &[u32]) -> Result<(), PatchError> {
        if self.published {
            return Err(PatchError::AlreadyPublished);
        }
        if words.is_empty() {
            return Err(PatchError::EmptyIsland);
        }
        if words.len() > self.capacity_words {
            return Err(PatchError::CapacityExceeded {
                capacity_words: self.capacity_words,
                offered: words.len(),
            });
        }
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        {
            for (i, word) in words.iter().enumerate() {
                self.write_word(i * 4, *word);
            }
            self.words = words.len();
            Ok(())
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
        Err(PatchError::Unsupported("islands require AArch64 Linux"))
    }

    /// Map a fresh island (see the Linux form).
    /// `PatchError::Unsupported` off Linux.
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    pub fn build(_words: &[u32]) -> Result<Self, PatchError> {
        Err(PatchError::Unsupported("islands require AArch64 Linux"))
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn write_word(&self, byte_off: usize, word: u32) {
        // SAFETY: byte_off+4 lies inside the island by construction and
        // the island is exclusively owned and unreachable here.
        unsafe { (self.rw.add(byte_off) as *mut u32).write_volatile(word) };
    }

    /// Publish the written words for execution: dual-alias cache sync
    /// over the whole mapping. Requires the construction-time cache
    /// attestation token (environment established before any store).
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub fn publish(&mut self, _attested: CacheAttested) -> Result<(), PatchError> {
        // SAFETY: both aliases name this island's full shared range.
        unsafe { sync_icache(self.rw, self.rx, self.len)? };
        self.published = true;
        // Published text is immutable (fill now refuses), so the
        // RW alias has no remaining purpose: unmap it so a live
        // island is never writable through any VA. The RX alias
        // keeps the backing alive.
        // SAFETY: rw is this island's own mapping, unmapped once.
        unsafe {
            crate::gate::gate6(
                libc::SYS_munmap,
                [self.rw as u64, self.len as u64, 0, 0, 0, 0],
            );
        }
        self.rw = core::ptr::null_mut();
        Ok(())
    }

    /// Publish the written words (see the AArch64 Linux form).
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    pub fn publish(&mut self, _attested: CacheAttested) -> Result<(), PatchError> {
        Err(PatchError::Unsupported("islands require AArch64 Linux"))
    }

    /// Deliberately leak this island's mappings forever (its fd was
    /// already closed at reserve time)
    /// (bounded by the session). Used by `Site` custody when a live
    /// branch may still target the island: unmapping would be a
    /// correctness defect, leaking is the documented safe outcome.
    pub(crate) fn disarm(self) {
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        core::mem::forget(self);
        #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
        {
            // No mappings exist off-target; consuming self is enough.
        }
    }

    /// Executable (RX) address of the island entry (offset 0).
    pub fn entry_addr(&self) -> u64 {
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        {
            self.rx as u64
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
        {
            0
        }
    }

    /// Mapped length in bytes (page-rounded).
    pub fn mapped_len(&self) -> usize {
        self.len
    }

    /// Number of instruction words written at build time.
    pub fn words(&self) -> usize {
        self.words
    }

    /// Payload extent in bytes (`words * 4`), distinct from the
    /// page-rounded [`mapped_len`](Self::mapped_len): return-reach
    /// validation must use the actual last payload word as the return
    /// branch location, never the padded mapping end.
    pub fn payload_len(&self) -> u64 {
        self.words as u64 * 4
    }

    /// Read one word back through the RX alias (contents check; never
    /// used to decide publication by itself).
    pub fn read_rx_word(&self, index: usize) -> Option<u32> {
        if index >= self.words {
            return None;
        }
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        {
            Some(unsafe { (self.rx.add(index * 4) as *const u32).read_volatile() })
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
        {
            None
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
impl Drop for Island {
    fn drop(&mut self) {
        // SAFETY: both aliases are this island's own live mappings.
        unsafe {
            if !self.rw.is_null() {
                crate::gate::gate6(
                    libc::SYS_munmap,
                    [self.rw as u64, self.len as u64, 0, 0, 0, 0],
                );
            }
            crate::gate::gate6(
                libc::SYS_munmap,
                [self.rx as u64, self.len as u64, 0, 0, 0, 0],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    fn island_round_trips_words_through_both_aliases() {
        let words = [0xd400_0001, 0xd503_24df, 42];
        let island = Island::build(&words).unwrap();
        assert_eq!(island.entry_addr() % 4, 0);
        assert!(island.mapped_len() >= 12);
        for (i, w) in words.iter().enumerate() {
            assert_eq!(island.read_rx_word(i), Some(*w));
        }
        assert_eq!(island.read_rx_word(3), None);
        assert_eq!(Island::build(&[]).unwrap_err(), PatchError::EmptyIsland);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    fn reserve_closes_the_memfd() {
        // Count ONLY island memfds: the whole-table census races
        // sibling tests opening unrelated fds in parallel.
        fn island_fd_count() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    std::fs::read_link(e.path())
                        .map(|t| t.to_string_lossy().contains("memfd:liteinst-island"))
                        .unwrap_or(false)
                })
                .count()
        }
        let before = island_fd_count();
        let island = Island::reserve(2).unwrap();
        assert_eq!(island_fd_count(), before, "reserve leaked the memfd");
        drop(island);
        assert_eq!(island_fd_count(), before);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    fn fill_after_publish_is_already_published() {
        let token = crate::cache::CacheAttested::for_test();
        let mut island = Island::build(&[0xd400_0001, 0xd65f_03c0]).unwrap();
        island.publish(token).unwrap();
        assert_eq!(
            island.fill(&[0xd503_201f]),
            Err(PatchError::AlreadyPublished)
        );
        assert_eq!(
            Island::reserve(1).unwrap().fill(&[1, 2]),
            Err(PatchError::CapacityExceeded {
                capacity_words: 1,
                offered: 2
            })
        );
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    #[test]
    fn island_refuses_off_linux() {
        assert!(matches!(
            Island::build(&[0]),
            Err(PatchError::Unsupported(_))
        ));
    }
}
