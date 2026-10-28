//! New-profile admission only. The old callback clock contract is unchanged.
//! AMD64 APM volume 3, publication 24594 rev. 3.33 (November 2021),
//! pp. 214, 435–436 and 632: LFENCEAlwaysSerializing, RDTSCP and TSC policy.
//! AMD-authored manual mirror: https://kib.kiev.ua/x86docs/AMD/AMD64/24594_APM_v3-r3.33.pdf
//! These features grant no frequency, cross-CPU synchronization or accuracy claim.
use super::GateError;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Features {
    basic_max: u32,
    extended_max: u32,
    vendor: [u8; 12],
    basic_ecx: u32,
    basic_edx: u32,
    extended_edx: u32,
    power_edx: u32,
    extended21_eax: u32,
}

fn admitted(f: Features, user_tsc: bool) -> bool {
    f.basic_max >= 1
        && f.extended_max >= 0x8000_0021
        && f.vendor == *b"AuthenticAMD"
        && f.basic_ecx & (1 << 31) == 0 // No advertised hypervisor profile.
        && f.basic_edx & (1 << 4) != 0 // TSC.
        && f.basic_edx & (1 << 26) != 0 // SSE2/LFENCE.
        && f.extended_edx & (1 << 27) != 0 // RDTSCP.
        && f.power_edx & (1 << 8) != 0 // Invariant TSC, not a frequency estimate.
        && f.extended21_eax & (1 << 2) != 0 // LFENCEAlwaysSerializing.
        && user_tsc
}

// CPUID intrinsics were unsafe at the crate's Rust 1.85 minimum version.
#[allow(unused_unsafe)]
fn cpuid(leaf: u32) -> std::arch::x86_64::CpuidResult {
    // SAFETY: x86-64 supports CPUID; unsupported leaves are never queried below.
    unsafe { std::arch::x86_64::__cpuid(leaf) }
}

pub(super) fn check() -> Result<(), GateError> {
    let basic = cpuid(0);
    let extended = cpuid(0x8000_0000);
    if basic.eax < 1 || extended.eax < 0x8000_0021 {
        return Err(GateError::ReferenceClock);
    }
    let one = cpuid(1);
    let mut vendor = [0; 12];
    vendor[..4].copy_from_slice(&basic.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&basic.edx.to_le_bytes());
    vendor[8..].copy_from_slice(&basic.ecx.to_le_bytes());
    let features = Features {
        basic_max: basic.eax,
        extended_max: extended.eax,
        vendor,
        basic_ecx: one.ecx,
        basic_edx: one.edx,
        extended_edx: cpuid(0x8000_0001).edx,
        power_edx: cpuid(0x8000_0007).edx,
        extended21_eax: cpuid(0x8000_0021).eax,
    };
    let mut mode: libc::c_int = 0;
    // SAFETY: Linux writes one initialized c_int. This observes the current
    // thread's user-TSC policy; it does not enable TSC or alter process policy.
    let enabled = unsafe {
        libc::prctl(
            libc::PR_GET_TSC,
            core::ptr::addr_of_mut!(mode),
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } == 0
        && mode == libc::PR_TSC_ENABLE;
    if admitted(features, enabled) {
        Ok(())
    } else {
        Err(GateError::ReferenceClock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_requires_every_explicit_feature_and_user_access() {
        let f = Features {
            basic_max: 1,
            extended_max: 0x8000_0021,
            vendor: *b"AuthenticAMD",
            basic_ecx: 0,
            basic_edx: (1 << 4) | (1 << 26),
            extended_edx: 1 << 27,
            power_edx: 1 << 8,
            extended21_eax: 1 << 2,
        };
        assert!(admitted(f, true));
        assert!(!admitted(f, false));
        for field in 0..9 {
            let mut bad = f;
            match field {
                0 => bad.basic_max = 0,
                1 => bad.extended_max -= 1,
                2 => bad.vendor = *b"GenuineIntel",
                3 => bad.basic_ecx = 1 << 31,
                4 => bad.basic_edx &= !(1 << 4),
                5 => bad.basic_edx &= !(1 << 26),
                6 => bad.extended_edx = 0,
                7 => bad.power_edx = 0,
                _ => bad.extended21_eax = 0,
            }
            assert!(!admitted(bad, true), "field {field}");
        }
    }
}
