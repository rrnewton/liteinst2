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
    /// XCR0 enables no user component beyond liteinst's preserved mask
    /// (in practice AMX bits 17/18 clear), via
    /// `liteinst::trampoline::SavedExtendedStateLayout::xcr0_within_preserved_mask`.
    pub xcr0_within_preserved: bool,
}

/// Pure decision from raw observations, unit-testable without hardware.
///
/// `pagemap_entry` is the raw 64-bit entry for a just-touched anonymous
/// page (bit 63 = present, bits 0..55 = PFN). `cpuid7_ecx` is
/// CPUID.(EAX=7, ECX=0):ECX. `xstate9_eax` is CPUID.(EAX=0xD, ECX=9):EAX
/// (PKRU component size in bytes, 0 when absent). `xcr0_within_preserved`
/// is liteinst's own value-form verdict for this thread's XCR0
/// (`SavedExtendedStateLayout::xcr0_within_preserved_mask_value`); the
/// mask itself is defined once in liteinst, never duplicated here.
pub(crate) fn classify(
    pagemap_entry: u64,
    cpuid7_ecx: u32,
    xstate9_eax: u32,
    xcr0_within_preserved: bool,
) -> Capabilities {
    let present = pagemap_entry >> 63 == 1;
    let pfn = pagemap_entry & ((1u64 << 55) - 1);
    Capabilities {
        pagemap_pfn: present && pfn != 0,
        pku_xstate: cpuid7_ecx & (1 << 3) != 0 && cpuid7_ecx & (1 << 4) != 0 && xstate9_eax != 0,
        xcr0_within_preserved,
    }
}

/// Probe this host once and cache the result.
pub(crate) fn probe() -> Capabilities {
    static CACHE: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        classify(
            own_pagemap_entry(),
            cpuid7_ecx(),
            xstate9_eax(),
            liteinst::trampoline::SavedExtendedStateLayout::xcr0_within_preserved_mask(),
        )
    })
}

/// Print the named skip reason and report whether the caller must return.
pub(crate) fn skip_without(what: &'static str, present: bool) -> bool {
    if present {
        return false;
    }
    eprintln!("SKIP: capability absent: {what}; native record comparison requires it");
    true
}

/// Capability bits a case kind may require (see [`required_caps`]).
pub(crate) const CAP_PAGEMAP_PFN: u8 = 1;
/// See [`CAP_PAGEMAP_PFN`].
pub(crate) const CAP_PKU_XSTATE: u8 = 2;
/// See [`CAP_PAGEMAP_PFN`].
pub(crate) const CAP_XCR0_WITHIN_PRESERVED: u8 = 4;

/// Native-test case families with distinct capability requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaseKind {
    /// admitted-exec happy-path native cases (byte-exact xstate).
    ExecNative,
    /// admitted-exec failure-injection native cases (same records).
    ExecFailure,
    /// gate coverage-failure cases (byte-exact xstate evidence).
    GateCoverage,
    /// runtime selected native cases (control-state xstate first).
    SelectedNative,
    /// runtime-stack native cases (pagemap-backed records).
    StackNative,
    /// ordinary runtime native cases (no environment-shaped records).
    OrdinaryRuntime,
}

/// The capabilities each case kind's record comparisons assume. Pure
/// decision: pinned by unit tests so gating placement cannot drift
/// silently when cases move.
pub(crate) fn required_caps(kind: CaseKind) -> u8 {
    match kind {
        CaseKind::ExecNative
        | CaseKind::ExecFailure
        | CaseKind::GateCoverage
        | CaseKind::SelectedNative => CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED,
        CaseKind::StackNative => CAP_PAGEMAP_PFN | CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED,
        CaseKind::OrdinaryRuntime => 0,
    }
}

/// Classify an isolation case name into its kind (pure).
pub(crate) fn isolation_kind(name: &str) -> CaseKind {
    if name.contains("::stack::native_tests::") {
        CaseKind::StackNative
    } else if name.ends_with("::runtime_selected_syscall_refuses_without_ordinary_fallback")
        || name.ends_with("::runtime_selected_cpu_and_ordinary_keep_exact_control_lineage")
    {
        // Both selected cases assert complete-state equality whose first
        // compared field is the full xstate byte string
        // (control_unchanged, runtime_native/runner.rs).
        CaseKind::SelectedNative
    } else {
        CaseKind::OrdinaryRuntime
    }
}

/// Whether `caps` satisfies `required` (pure).
pub(crate) fn caps_satisfied(caps: Capabilities, required: u8) -> bool {
    (required & CAP_PAGEMAP_PFN == 0 || caps.pagemap_pfn)
        && (required & CAP_PKU_XSTATE == 0 || caps.pku_xstate)
        && (required & CAP_XCR0_WITHIN_PRESERVED == 0 || caps.xcr0_within_preserved)
}

/// Skip (with named printed reasons) when this host lacks a required
/// capability for `kind`. Returns true when the caller must return.
pub(crate) fn skip_without_caps(kind: CaseKind) -> bool {
    let caps = probe();
    let required = required_caps(kind);
    let mut skip = false;
    if required & CAP_PAGEMAP_PFN != 0 {
        skip |= skip_without(
            "PFN-bearing pagemap (present bit + nonzero PFN for a resident page)",
            caps.pagemap_pfn,
        );
    }
    if required & CAP_PKU_XSTATE != 0 {
        skip |= skip_without(
            "PKU xstate component (CPUID leaf 7 PKU/OSPKE + leaf 0xD subleaf 9)",
            caps.pku_xstate,
        );
    }
    if required & CAP_XCR0_WITHIN_PRESERVED != 0 {
        skip |= skip_without(
            "XCR0 within preserved user-state mask (no AMX bits 17/18)",
            caps.xcr0_within_preserved,
        );
    }
    skip
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
    use super::{
        CAP_PAGEMAP_PFN, CAP_PKU_XSTATE, CAP_XCR0_WITHIN_PRESERVED, Capabilities, CaseKind,
        caps_satisfied, classify, isolation_kind, required_caps,
    };

    const PRESENT: u64 = 1 << 63;
    const PKU_OSPKE: u32 = (1 << 3) | (1 << 4);

    #[test]
    fn classify_requires_present_and_nonzero_pfn() {
        assert!(classify(PRESENT | 0x1234, PKU_OSPKE, 8, true).pagemap_pfn);
        assert!(!classify(PRESENT, PKU_OSPKE, 8, true).pagemap_pfn);
        assert!(!classify(0x1234, PKU_OSPKE, 8, true).pagemap_pfn);
        assert!(!classify(0, PKU_OSPKE, 8, true).pagemap_pfn);
    }

    #[test]
    fn classify_requires_pku_ospke_and_component() {
        assert!(classify(PRESENT | 1, PKU_OSPKE, 8, true).pku_xstate);
        assert!(!classify(PRESENT | 1, 1 << 3, 8, true).pku_xstate);
        assert!(!classify(PRESENT | 1, 1 << 4, 8, true).pku_xstate);
        assert!(!classify(PRESENT | 1, PKU_OSPKE, 0, true).pku_xstate);
    }

    #[test]
    fn required_caps_enumeration_is_pinned() {
        assert_eq!(
            required_caps(CaseKind::ExecNative),
            CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED
        );
        assert_eq!(
            required_caps(CaseKind::ExecFailure),
            CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED
        );
        assert_eq!(
            required_caps(CaseKind::GateCoverage),
            CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED
        );
        assert_eq!(
            required_caps(CaseKind::SelectedNative),
            CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED
        );
        assert_eq!(
            required_caps(CaseKind::StackNative),
            CAP_PAGEMAP_PFN | CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED
        );
        assert_eq!(required_caps(CaseKind::OrdinaryRuntime), 0);
    }

    #[test]
    fn isolation_kind_enumeration_is_pinned() {
        assert_eq!(
            isolation_kind(
                "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_after_a_ac_refuses_before_private_effects"
            ),
            CaseKind::StackNative
        );
        assert_eq!(
            isolation_kind(
                "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_syscall_refuses_without_ordinary_fallback"
            ),
            CaseKind::SelectedNative
        );
        assert_eq!(
            isolation_kind(
                "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::allocation::runtime_ordinary_allocation_errors_retain_actual_pending_custody"
            ),
            CaseKind::OrdinaryRuntime
        );
        assert_eq!(
            isolation_kind(
                "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_cpu_and_ordinary_keep_exact_control_lineage"
            ),
            CaseKind::SelectedNative
        );
    }

    #[test]
    fn caps_satisfied_checks_each_conjunct() {
        let none = Capabilities {
            pagemap_pfn: false,
            pku_xstate: false,
            xcr0_within_preserved: false,
        };
        let pfn_only = Capabilities {
            pagemap_pfn: true,
            pku_xstate: false,
            xcr0_within_preserved: false,
        };
        let pku_only = Capabilities {
            pagemap_pfn: false,
            pku_xstate: true,
            xcr0_within_preserved: false,
        };
        let both = Capabilities {
            pagemap_pfn: true,
            pku_xstate: true,
            xcr0_within_preserved: true,
        };
        assert!(caps_satisfied(none, 0));
        assert!(!caps_satisfied(none, CAP_PAGEMAP_PFN));
        assert!(!caps_satisfied(none, CAP_PKU_XSTATE));
        assert!(caps_satisfied(pfn_only, CAP_PAGEMAP_PFN));
        assert!(!caps_satisfied(pfn_only, CAP_PKU_XSTATE));
        assert!(!caps_satisfied(pfn_only, CAP_PAGEMAP_PFN | CAP_PKU_XSTATE));
        assert!(caps_satisfied(pku_only, CAP_PKU_XSTATE));
        assert!(!caps_satisfied(pku_only, CAP_PAGEMAP_PFN | CAP_PKU_XSTATE));
        assert!(caps_satisfied(both, CAP_PAGEMAP_PFN | CAP_PKU_XSTATE));
        assert!(caps_satisfied(both, CAP_XCR0_WITHIN_PRESERVED));
        assert!(!caps_satisfied(none, CAP_XCR0_WITHIN_PRESERVED));
        assert!(!caps_satisfied(pfn_only, CAP_XCR0_WITHIN_PRESERVED));
        assert!(!caps_satisfied(pku_only, CAP_XCR0_WITHIN_PRESERVED));
        assert!(!caps_satisfied(
            pku_only,
            CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED
        ));
        assert!(caps_satisfied(
            both,
            CAP_PAGEMAP_PFN | CAP_PKU_XSTATE | CAP_XCR0_WITHIN_PRESERVED
        ));
        // The XCR0 input passes through classify unchanged.
        assert!(classify(PRESENT | 1, PKU_OSPKE, 8, true).xcr0_within_preserved);
        assert!(!classify(PRESENT | 1, PKU_OSPKE, 8, false).xcr0_within_preserved);
    }
}
