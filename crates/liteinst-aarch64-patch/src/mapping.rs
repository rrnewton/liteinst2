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
        b'p' if pathname.is_empty() || pathname.starts_with('[') => Provenance::PrivateAnon,
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
    })
}

/// Qualify the mapping containing `addr` from `/proc/self/maps`, in
/// promoter ordinary context only (never a handler). Refusals are
/// named: shared/unknown provenance, non-executable mappings, and
/// addresses no mapping contains all return
/// `PatchError::MappingRefused`.
#[cfg(target_os = "linux")]
pub fn qualify_mapping(addr: u64, generation: u64) -> Result<MappingFacts, PatchError> {
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|_| PatchError::Os {
        op: "read /proc/self/maps",
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    })?;
    for line in maps.lines() {
        if let Some(facts) = parse_maps_line(line, addr, generation) {
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
            return Ok(facts);
        }
    }
    Err(PatchError::MappingRefused("no mapping contains the site"))
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
}
