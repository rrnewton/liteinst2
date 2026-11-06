//! Host-capability probes for native tests whose recorded evidence is
//! environment-shaped (xstate layout, pagemap PFN exposure).
//!
//! A probe detects the actual capability the record comparison assumes;
//! it never keys on hostnames, environment names, or CI identity. When a
//! capability is absent the affected test prints a named reason and
//! returns without running its body; where the capability exists the
//! test runs exactly as before. See the launch runner-environment
//! follow-up (11 native record tests failing on GitHub-hosted runners
//! while passing on bare metal).

/// Capabilities a native record comparison may require.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Capabilities {
    /// Pagemap entries carry a nonzero PFN for a resident anonymous page.
    pub pagemap_pfn: bool,
    /// PKU is exposed and enabled: CPUID leaf 7 ECX.PKU + ECX.OSPKE and
    /// the PKRU xstate component (leaf 0xD subleaf 9) has nonzero size.
    pub pku_xstate: bool,
}

/// Pure decision from raw observations, unit-testable without hardware.
///
/// `pagemap_entry` is the raw 64-bit entry for a just-touched anonymous
/// page (bit 63 = present, bits 0..55 = PFN). `cpuid7_ecx` is
/// CPUID.(EAX=7, ECX=0):ECX. `xstate9_eax` is CPUID.(EAX=0xD, ECX=9):EAX
/// (PKRU component size in bytes, 0 when absent).
pub(crate) fn classify(pagemap_entry: u64, cpuid7_ecx: u32, xstate9_eax: u32) -> Capabilities {
    let present = pagemap_entry >> 63 == 1;
    let pfn = pagemap_entry & ((1u64 << 55) - 1);
    Capabilities {
        pagemap_pfn: present && pfn != 0,
        pku_xstate: cpuid7_ecx & (1 << 3) != 0 && cpuid7_ecx & (1 << 4) != 0 && xstate9_eax != 0,
    }
}

/// Probe this host once and cache the result.
pub(crate) fn probe() -> Capabilities {
    static CACHE: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| classify(own_pagemap_entry(), cpuid7_ecx(), xstate9_eax()))
}

/// Print the named skip reason and report whether the caller must return.
pub(crate) fn skip_without(what: &'static str, present: bool) -> bool {
    if present {
        return false;
    }
    eprintln!("SKIP: capability absent: {what}; native record comparison requires it");
    true
}

fn cpuid7_ecx() -> u32 {
    core::arch::x86_64::__cpuid_count(7, 0).ecx
}

fn xstate9_eax() -> u32 {
    // Leaf 0xD subleaf 9 is the PKRU component descriptor.
    core::arch::x86_64::__cpuid_count(0xD, 9).eax
}

fn own_pagemap_entry() -> u64 {
    const PAGE: usize = 4096;
    // SAFETY: one anonymous page, touched, read via our own pagemap, unmapped.
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            return 0;
        }
        std::ptr::write_volatile(page.cast::<u8>(), 1);
        let entry = read_pagemap_entry(page as u64);
        libc::munmap(page, PAGE);
        entry
    }
}

fn read_pagemap_entry(address: u64) -> u64 {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open("/proc/self/pagemap") else {
        return 0;
    };
    if file.seek(SeekFrom::Start(address / 4096 * 8)).is_err() {
        return 0;
    }
    let mut bytes = [0u8; 8];
    if file.read_exact(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::classify;

    const PRESENT: u64 = 1 << 63;
    const PKU_OSPKE: u32 = (1 << 3) | (1 << 4);

    #[test]
    fn classify_requires_present_and_nonzero_pfn() {
        assert!(classify(PRESENT | 0x1234, PKU_OSPKE, 8).pagemap_pfn);
        assert!(!classify(PRESENT, PKU_OSPKE, 8).pagemap_pfn);
        assert!(!classify(0x1234, PKU_OSPKE, 8).pagemap_pfn);
        assert!(!classify(0, PKU_OSPKE, 8).pagemap_pfn);
    }

    #[test]
    fn classify_requires_pku_ospke_and_component() {
        assert!(classify(PRESENT | 1, PKU_OSPKE, 8).pku_xstate);
        assert!(!classify(PRESENT | 1, 1 << 3, 8).pku_xstate);
        assert!(!classify(PRESENT | 1, 1 << 4, 8).pku_xstate);
        assert!(!classify(PRESENT | 1, PKU_OSPKE, 0).pku_xstate);
    }
}
