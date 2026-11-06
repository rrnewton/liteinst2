//! Dual RW/RX island mappings: the only executable memory this crate
//! creates. One memfd backing is mapped twice (`MAP_SHARED`), writable
//! through the RW alias and executable through the RX alias, so no
//! virtual address is ever writable and executable at once.

use crate::PatchError;
use crate::cache::{CacheAttested, sync_icache};
use liteinst_aarch64::emit::page_span;

#[cfg(target_os = "linux")]
/// `MFD_EXEC` (kernel 6.3+); defined locally so the locked libc version
/// need not carry the constant. Retried without it on `EINVAL`
/// (pre-6.3 kernels reject the unknown flag; their memfds are
/// executable by default).
const L_MFD_EXEC: libc::c_uint = 0x0010;

/// An owned island mapping. While any flipped site branches here, the
/// owning `Site` custody holds this value; `Drop` unmaps both aliases,
/// so slice-1 retirement rules (deferred until no executor can enter,
/// permanent retention on uncertainty) are the caller's protocol duty
/// until the flip slice binds lifetimes in the type.
pub struct Island {
    #[cfg(target_os = "linux")]
    fd: libc::c_int,
    #[cfg(target_os = "linux")]
    rw: *mut u8,
    #[cfg(target_os = "linux")]
    rx: *mut u8,
    len: usize,
    words: usize,
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

#[cfg(target_os = "linux")]
fn memfd_exec() -> Result<libc::c_int, PatchError> {
    let name = c"liteinst-island";
    let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), base | L_MFD_EXEC) };
    if fd >= 0 {
        return Ok(fd);
    }
    let first_err = std::io::Error::last_os_error();
    if first_err.raw_os_error() == Some(libc::EINVAL) {
        let fd = unsafe { libc::memfd_create(name.as_ptr(), base) };
        if fd >= 0 {
            return Ok(fd);
        }
        // Report the retry's errno: it, not the flag rejection, is why
        // creation ultimately failed.
        let retry_err = std::io::Error::last_os_error();
        return Err(PatchError::Os {
            op: "memfd_create (no MFD_EXEC retry)",
            errno: retry_err.raw_os_error().unwrap_or(0),
        });
    }
    Err(PatchError::Os {
        op: "memfd_create",
        errno: first_err.raw_os_error().unwrap_or(0),
    })
}

impl Island {
    /// Map a fresh island of `page_span(page_size, words*4)` bytes and
    /// write `words` via the RW alias. The island is fresh (created
    /// here), unreachable (nothing branches to it yet), and exclusively
    /// owned — the three conditions under which pre-lease writes are
    /// sound. Call [`Island::publish`] before any branch targets it.
    #[cfg(target_os = "linux")]
    pub fn build(words: &[u32]) -> Result<Self, PatchError> {
        if words.is_empty() {
            return Err(PatchError::EmptyIsland);
        }
        let page = crate::page_size()?;
        let payload = (words.len() as u64)
            .checked_mul(4)
            .ok_or(PatchError::RangeOverflow)?;
        let len = page_span(page, payload).ok_or(PatchError::RangeOverflow)? as usize;
        let fd = memfd_exec()?;
        let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
        if rc != 0 {
            let e = PatchError::os("ftruncate");
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let map = |prot: libc::c_int| unsafe {
            libc::mmap(std::ptr::null_mut(), len, prot, libc::MAP_SHARED, fd, 0)
        };
        let rw = map(libc::PROT_READ | libc::PROT_WRITE);
        if rw == libc::MAP_FAILED {
            let e = PatchError::os("mmap rw");
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let rx = map(libc::PROT_READ | libc::PROT_EXEC);
        if rx == libc::MAP_FAILED {
            let e = PatchError::os("mmap rx");
            unsafe {
                libc::munmap(rw, len);
                libc::close(fd);
            }
            return Err(e);
        }
        let island = Self {
            fd,
            rw: rw as *mut u8,
            rx: rx as *mut u8,
            len,
            words: words.len(),
        };
        for (i, word) in words.iter().enumerate() {
            island.write_word(i * 4, *word);
        }
        Ok(island)
    }

    /// Map a fresh island (see the Linux form).
    /// `PatchError::Unsupported` off Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn build(_words: &[u32]) -> Result<Self, PatchError> {
        Err(PatchError::Unsupported("islands require Linux memfd"))
    }

    fn write_word(&self, byte_off: usize, word: u32) {
        #[cfg(target_os = "linux")]
        // SAFETY: byte_off+4 lies inside the island by construction and
        // the island is exclusively owned and unreachable here.
        unsafe {
            (self.rw.add(byte_off) as *mut u32).write_volatile(word)
        };
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (byte_off, word);
        }
    }

    /// Publish the written words for execution: dual-alias cache sync
    /// over the whole mapping. Requires the construction-time cache
    /// attestation token (environment established before any store).
    pub fn publish(&self, _attested: CacheAttested) -> Result<(), PatchError> {
        #[cfg(target_os = "linux")]
        // SAFETY: both aliases name this island's full shared range.
        unsafe {
            sync_icache(self.rw, self.rx, self.len)
        }
        #[cfg(not(target_os = "linux"))]
        Err(PatchError::Unsupported("islands require Linux memfd"))
    }

    /// Executable (RX) address of the island entry (offset 0).
    pub fn entry_addr(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.rx as u64
        }
        #[cfg(not(target_os = "linux"))]
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

    /// Read one word back through the RX alias (contents check; never
    /// used to decide publication by itself).
    pub fn read_rx_word(&self, index: usize) -> Option<u32> {
        if index >= self.words {
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            Some(unsafe { (self.rx.add(index * 4) as *const u32).read_volatile() })
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Island {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.rw as *mut libc::c_void, self.len);
            libc::munmap(self.rx as *mut libc::c_void, self.len);
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
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

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn island_refuses_off_linux() {
        assert!(matches!(
            Island::build(&[0]),
            Err(PatchError::Unsupported(_))
        ));
    }
}
