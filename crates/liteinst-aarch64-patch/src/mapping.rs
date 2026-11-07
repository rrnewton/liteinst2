//! Mapping qualification for foreign text: what mapping currently
//! contains a candidate site, whether it may be windowed at all, and
//! which mapping generation that answer belongs to. Generation
//! ownership stays with the promoter/backend mapping authority; this
//! module only parses and classifies.

use crate::PatchError;

/// Where a site's mapping came from. Only the private variants may
/// ever be windowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// `MAP_PRIVATE` file mapping (COW keeps the file untouched).
    PrivateFile,
    /// `MAP_PRIVATE` anonymous mapping.
    PrivateAnon,
    /// `MAP_SHARED` mapping: refused by name.
    Shared,
    /// Indeterminate provenance: refused by name.
    Unknown,
}

/// Qualified facts about the mapping containing one site address, as
/// of qualification time. Freshness is the caller's generation
/// discipline: `Site` refuses to flip against facts whose generation
/// no longer matches its own when fresh facts are presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingFacts {
    /// Page-aligned span `(base, len)` a store window may touch:
    /// exactly the pages covering the site word.
    pub page_span: (u64, u64),
    /// Original `PROT_*` bits to restore after an mprotect window.
    pub orig_prot: i32,
    /// Mapping provenance class.
    pub provenance: Provenance,
    /// Promoter-owned mapping generation these facts belong to.
    pub generation: u64,
    /// Whether the mapping is BTI-guarded (`bt` in smaps VmFlags).
    /// `/proc/self/maps` perms cannot express this and an
    /// `mprotect` that omits `PROT_BTI` clears `VM_ARM64_BTI`, so
    /// window backends must OR the flag back into both the window
    /// and the restore protections when this is set.
    pub bti: bool,
}

impl MappingFacts {
    /// Whether `addr` lies inside the qualified page span.
    pub fn contains(&self, addr: u64) -> bool {
        let (base, len) = self.page_span;
        addr >= base && addr - base < len
    }

    /// Whether this provenance may be windowed at all.
    pub fn windowable(&self) -> bool {
        matches!(
            self.provenance,
            Provenance::PrivateFile | Provenance::PrivateAnon
        )
    }
}

/// Parse one `/proc/self/maps` line into facts for `addr` (which the
/// line must contain), or `None` if the line does not cover it.
/// `generation` is stamped through from the mapping authority.
#[cfg(target_os = "linux")]
fn parse_maps_line(line: &str, addr: u64, generation: u64) -> Option<MappingFacts> {
    let (range, rest) = line.split_once(' ')?;
    let (lo, hi) = range.split_once('-')?;
    let lo = u64::from_str_radix(lo, 16).ok()?;
    let hi = u64::from_str_radix(hi, 16).ok()?;
    if addr < lo || addr >= hi {
        return None;
    }
    let mut fields = rest.split_whitespace();
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let pathname = fields.next().unwrap_or("");
    let bytes = perms.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    let mut prot = 0;
    if bytes[0] == b'r' {
        prot |= libc::PROT_READ;
    }
    if bytes[1] == b'w' {
        prot |= libc::PROT_WRITE;
    }
    if bytes[2] == b'x' {
        prot |= libc::PROT_EXEC;
    }
    let provenance = match bytes[3] {
        b's' => Provenance::Shared,
        b'p' if pathname.is_empty() => Provenance::PrivateAnon,
        // Bracketed names are kernel pseudo-mappings ([vdso],
        // [vvar], [heap], [stack], ...): never windowed, whatever
        // their perms claim.
        b'p' if pathname.starts_with('[') => Provenance::Unknown,
        b'p' => Provenance::PrivateFile,
        _ => Provenance::Unknown,
    };
    // File offset within the VMA does not change the page span: the
    // window covers exactly the site word's page(s) — one page, since
    // the word is 4-byte aligned and at most page-sized alignment
    // keeps it inside a single page.
    let page = crate::page_size().ok()?;
    let base = addr & !(page - 1);
    Some(MappingFacts {
        page_span: (base, page),
        orig_prot: prot,
        provenance,
        generation,
        // Filled from smaps by the caller; maps perms cannot say.
        bti: false,
    })
}

/// Read a small `/proc/self` file through the syscall gate (the
/// std::fs path would issue the same syscalls from libc PLT
/// addresses a guest filter does not admit).
#[cfg(target_os = "linux")]
fn read_proc_file(path: &core::ffi::CStr) -> Result<String, PatchError> {
    // SAFETY: path is a valid C string; flags are O_RDONLY|O_CLOEXEC.
    let fd = unsafe {
        crate::gate::gate6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                path.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    let fd = crate::gate::check(fd, "openat /proc/self maps")? as libc::c_int;
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    let result = loop {
        // SAFETY: chunk is a valid out buffer of its full length.
        let n = unsafe {
            crate::gate::gate6(
                libc::SYS_read,
                [
                    fd as u64,
                    chunk.as_mut_ptr() as u64,
                    chunk.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if n < 0 {
            if n == -(libc::EINTR as i64) {
                continue;
            }
            break Err(crate::gate::check(n, "read /proc/self maps").unwrap_err());
        }
        if n == 0 {
            break Ok(());
        }
        out.extend_from_slice(&chunk[..n as usize]);
        if out.len() > 64 * 1024 * 1024 {
            break Err(PatchError::MappingRefused("maps image implausibly large"));
        }
    };
    // SAFETY: fd is the one just opened, closed exactly once.
    unsafe {
        crate::gate::gate6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]);
    }
    result?;
    String::from_utf8(out).map_err(|_| PatchError::MappingRefused("maps image is not UTF-8"))
}

/// Whether the smaps block containing `addr` carries the `bt`
/// (BTI-guarded) VmFlag, or `None` when no VMA contains `addr` or
/// the block has no VmFlags line. Callers must refuse on `None`:
/// assuming unguarded could strip BTI from a guarded page.
#[cfg(target_os = "linux")]
fn smaps_bti(smaps: &str, addr: u64) -> Option<bool> {
    let mut inside = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ')
            && let Some((lo, hi)) = range.split_once('-')
            && let (Ok(lo), Ok(hi)) = (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16))
        {
            if inside {
                // The target block ended without a VmFlags line.
                return None;
            }
            inside = addr >= lo && addr < hi;
            continue;
        }
        if inside && let Some(flags) = line.strip_prefix("VmFlags:") {
            return Some(flags.split_whitespace().any(|f| f == "bt"));
        }
    }
    None
}

/// Qualify from one smaps image: header perms/pathname give the
/// maps facts and the same block's VmFlags give BTI, so perms and
/// flags can never disagree about which VMA they describe.
#[cfg(target_os = "linux")]
fn qualify_from_smaps(smaps: &str, addr: u64, generation: u64) -> Result<MappingFacts, PatchError> {
    for line in smaps.lines() {
        if let Some(mut facts) = parse_maps_line(line, addr, generation) {
            if !facts.windowable() {
                return Err(match facts.provenance {
                    Provenance::Shared => {
                        PatchError::MappingRefused("MAP_SHARED text is never windowed")
                    }
                    _ => PatchError::MappingRefused("indeterminate mapping provenance"),
                });
            }
            if facts.orig_prot & libc::PROT_EXEC == 0 {
                return Err(PatchError::MappingRefused("mapping is not executable"));
            }
            if facts.orig_prot & libc::PROT_READ == 0 {
                return Err(PatchError::MappingRefused(
                    "execute-only mapping cannot be revalidated",
                ));
            }
            facts.bti = smaps_bti(smaps, addr).ok_or(PatchError::MappingRefused(
                "BTI state indeterminate (no smaps VmFlags for the site VMA)",
            ))?;
            return Ok(facts);
        }
    }
    Err(PatchError::MappingRefused("no mapping contains the site"))
}

/// Qualify the mapping containing `addr` from a single
/// `/proc/self/smaps` read (perms, pathname and BTI VmFlags from
/// the same VMA block), in promoter ordinary context only (never
/// a handler). Refusals are named: shared/unknown or
/// pseudo-mapping provenance, non-executable or non-readable
/// (execute-only) mappings, indeterminate BTI, and addresses no
/// mapping contains all return `PatchError::MappingRefused`.
#[cfg(target_os = "linux")]
pub fn qualify_mapping(addr: u64, generation: u64) -> Result<MappingFacts, PatchError> {
    let smaps = read_proc_file(c"/proc/self/smaps")?;
    qualify_from_smaps(&smaps, addr, generation)
}

/// Qualify a mapping (see the Linux form). Unsupported off Linux.
#[cfg(not(target_os = "linux"))]
pub fn qualify_mapping(_addr: u64, _generation: u64) -> Result<MappingFacts, PatchError> {
    Err(PatchError::Unsupported(
        "mapping qualification requires Linux",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_private_file_and_shared_lines() {
        let line = "7f000000-7f001000 r-xp 00000000 08:02 1234 /lib/libc.so.6";
        let facts = parse_maps_line(line, 0x7f00_0800, 9).unwrap();
        assert_eq!(facts.provenance, Provenance::PrivateFile);
        assert_eq!(facts.orig_prot, libc::PROT_READ | libc::PROT_EXEC);
        assert_eq!(facts.generation, 9);
        assert!(facts.contains(0x7f00_0800));
        assert!(facts.windowable());
        let shared = "7f000000-7f001000 r-xs 00000000 08:02 1234 /lib/libc.so.6";
        let facts = parse_maps_line(shared, 0x7f00_0800, 9).unwrap();
        assert_eq!(facts.provenance, Provenance::Shared);
        assert!(!facts.windowable());
        assert!(parse_maps_line(line, 0x1234, 9).is_none());
    }

    #[test]
    fn parses_vdso_as_refused_unknown() {
        let line = "7f000000-7f001000 r-xp 00000000 00:00 0 [vdso]";
        let facts = parse_maps_line(line, 0x7f00_0800, 9).unwrap();
        assert_eq!(facts.provenance, Provenance::Unknown);
        assert!(!facts.windowable());
    }

    #[cfg(target_os = "linux")]
    fn map_page(prot: libc::c_int) -> u64 {
        let page = crate::page_size().unwrap();
        // SAFETY: fresh anonymous page for this test.
        let p = unsafe {
            crate::gate::gate6(
                libc::SYS_mmap,
                [
                    0,
                    page,
                    prot as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                    u64::MAX,
                    0,
                ],
            )
        };
        assert!(p > 0, "mmap failed: {p}");
        p as u64
    }

    #[cfg(target_os = "linux")]
    fn unmap(addr: u64) {
        let page = crate::page_size().unwrap();
        // SAFETY: addr is this test's own mapping above.
        unsafe {
            crate::gate::gate6(libc::SYS_munmap, [addr, page, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn qualify_real_rx_rw_and_xonly_pages() {
        let rx = map_page(libc::PROT_READ | libc::PROT_EXEC);
        let facts = qualify_mapping(rx, 3).unwrap();
        assert!(facts.windowable());
        assert_eq!(facts.generation, 3);
        unmap(rx);
        let rw = map_page(libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(
            qualify_mapping(rw, 3),
            Err(PatchError::MappingRefused("mapping is not executable"))
        );
        unmap(rw);
        let xo = map_page(libc::PROT_EXEC);
        assert_eq!(
            qualify_mapping(xo, 3),
            Err(PatchError::MappingRefused(
                "execute-only mapping cannot be revalidated"
            ))
        );
        unmap(xo);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn qualify_bti_page_agrees_with_smaps() {
        const PROT_BTI: libc::c_int = 0x10;
        let page = crate::page_size().unwrap();
        // SAFETY: fresh anonymous page; PROT_BTI may be EINVAL on
        // kernels/hosts without BTI.
        let p = unsafe {
            crate::gate::gate6(
                libc::SYS_mmap,
                [
                    0,
                    page,
                    (libc::PROT_READ | libc::PROT_EXEC | PROT_BTI) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                    u64::MAX,
                    0,
                ],
            )
        };
        if p <= 0 {
            return; // host/kernel has no BTI mmap; nothing to agree on
        }
        let addr = p as u64;
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        match smaps_bti(&smaps, addr) {
            // Host exposes the flag: qualification must report it.
            Some(true) => assert!(qualify_mapping(addr, 1).unwrap().bti),
            Some(false) => assert!(!qualify_mapping(addr, 1).unwrap().bti),
            // Emulator smaps without VmFlags: refuse, never guess.
            None => assert!(matches!(
                qualify_mapping(addr, 1),
                Err(PatchError::MappingRefused(_))
            )),
        }
        unmap(addr);
    }

    #[test]
    fn smaps_bti_flag_is_per_vma() {
        let smaps = "1000-2000 r-xp 00000000 08:02 1 /a\n\
                     Size: 4 kB\nVmFlags: rd ex bt mr\n\
                     2000-3000 r-xp 00000000 08:02 1 /b\n\
                     Size: 4 kB\nVmFlags: rd ex mr\n";
        assert_eq!(smaps_bti(smaps, 0x1000), Some(true));
        assert_eq!(smaps_bti(smaps, 0x1ffc), Some(true));
        assert_eq!(smaps_bti(smaps, 0x2000), Some(false));
        assert_eq!(smaps_bti(smaps, 0x9000), None);
        let noflags = "1000-2000 r-xp 00000000 08:02 1 /a\nSize: 4 kB\n";
        assert_eq!(smaps_bti(noflags, 0x1000), None);
    }
}
