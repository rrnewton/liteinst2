//! Fresh-main-thread state oracle. No ptrace, signal-based capture, or emulator.
//! Architectural XSAVE projection follows tests/support/native_interval_oracle.rs.
use core::arch::{asm, global_asm};
use std::ptr::{addr_of, addr_of_mut};

const MAX_XSTATE: usize = 65536;
const KNOWN: u64 = 0x2e7; // x87, SSE, AVX, AVX-512, PKRU.
pub const PAGE: usize = 4096;
const STACK: usize = 256 * 1024;

#[repr(C, align(64))]
struct Image([u8; MAX_XSTATE]);

#[unsafe(no_mangle)]
static mut LI2_INPUT: [u64; 17] = [0; 17];
#[unsafe(no_mangle)]
static mut LI2_OUTPUT: [u64; 17] = [0; 17];
#[unsafe(no_mangle)]
static mut LI2_HOST: [u64; 8] = [0; 8];
#[unsafe(no_mangle)]
static mut LI2_TARGET: u64 = 0;
#[unsafe(no_mangle)]
static mut LI2_MASK: u64 = 0;
#[unsafe(no_mangle)]
static mut LI2_OUTPUT_XINUSE: u64 = 0;
#[unsafe(no_mangle)]
static mut LI2_SEED_XSTATE: Image = Image([0; MAX_XSTATE]);
#[unsafe(no_mangle)]
static mut LI2_OUTPUT_XSTATE: Image = Image([0; MAX_XSTATE]);
#[unsafe(no_mangle)]
static mut LI2_HOST_XSTATE: Image = Image([0; MAX_XSTATE]);

global_asm!(include_str!("machine.S"));
unsafe extern "C" {
    fn li2_probe_invoke();
    fn li2_probe_return();
    fn li2_probe_repeat(entry: usize, count: usize) -> u64;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub registers: [u64; 17],
    pub xstate: Vec<u8>,
    pub red_zone_and_return: [u8; 136],
}

pub struct Machine {
    stack: *mut u8,
    pub initial: [u64; 17],
    mask: u64,
    enabled: u64,
    image_len: usize,
    components: Vec<(u32, usize, usize)>,
    seed_canonical: Vec<u8>,
}

#[allow(unused_unsafe)] // CPUID was unsafe on the workspace Rust 1.85 MSRV.
fn cpuid(leaf: u32, subleaf: u32) -> core::arch::x86_64::CpuidResult {
    unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) }
}

fn xinuse() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("xgetbv", in("ecx") 1_u32, out("eax") low, out("edx") high,
        options(nostack, preserves_flags));
    }
    u64::from(low) | (u64::from(high) << 32)
}

impl Machine {
    pub fn new() -> Self {
        let features = cpuid(1, 0);
        assert_eq!(features.ecx & (3 << 26), 3 << 26, "XSAVE/OSXSAVE required");
        assert_ne!(
            cpuid(0xd, 1).eax & 4,
            0,
            "XGETBV(1) required for full state scope"
        );
        let enabled = unsafe { core::arch::x86_64::_xgetbv(0) };
        let supported = cpuid(0xd, 0);
        assert_eq!(
            enabled & !(u64::from(supported.eax) | (u64::from(supported.edx) << 32)),
            0
        );
        let mask = enabled & KNOWN;
        assert_eq!(mask & 3, 3);
        assert_eq!(
            xinuse() & enabled & !KNOWN,
            0,
            "unowned extended state is active"
        );
        let mut components = Vec::new();
        let mut image_len = 576;
        for bit in 2..64 {
            if mask & (1_u64 << bit) != 0 {
                let extent = cpuid(0xd, bit);
                let start = extent.ebx as usize;
                let len = extent.eax as usize;
                assert!(start >= 576 && len > 0 && start + len <= MAX_XSTATE);
                assert_eq!(extent.ecx & 1, 0, "supervisor component in user mask");
                components.push((bit, start, len));
                image_len = image_len.max(start + len);
            }
        }
        let stack = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                STACK + 2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(stack, libc::MAP_FAILED);
        assert_eq!(unsafe { libc::mprotect(stack, PAGE, libc::PROT_NONE) }, 0);
        assert_eq!(
            unsafe {
                libc::mprotect(
                    stack.cast::<u8>().add(PAGE + STACK).cast(),
                    PAGE,
                    libc::PROT_NONE,
                )
            },
            0
        );
        let stack = stack.cast::<u8>();
        let mut initial = [0_u64; 17];
        for (index, value) in initial[..16].iter_mut().enumerate() {
            *value = 0x8765_4321_1000_0000 | (index as u64 * 0x101);
        }
        initial[7] = stack as u64 + (PAGE + STACK - 24) as u64;
        initial[16] = 0x246; // Exact user flags: IF, ZF, PF, reserved bit 1.
        unsafe {
            LI2_MASK = mask;
            // Preserve actual PKRU; arbitrary keys could deny our own buffers.
            asm!("xsave64 [{}]", in(reg) addr_of_mut!(LI2_SEED_XSTATE),
                in("eax") mask as u32, in("edx") (mask >> 32) as u32,
                options(nostack, preserves_flags));
            let seed = std::slice::from_raw_parts_mut(
                addr_of_mut!(LI2_SEED_XSTATE).cast::<u8>(),
                MAX_XSTATE,
            );
            seed[..24].fill(0);
            seed[..2].copy_from_slice(&0x037f_u16.to_le_bytes());
            seed[4] = 0xff;
            seed[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
            for i in 0..8 {
                seed[32 + i * 16..40 + i * 16]
                    .copy_from_slice(&(0x8000_0000_1234_0000_u64 | i as u64).to_le_bytes());
                seed[40 + i * 16..42 + i * 16].copy_from_slice(&0x3fff_u16.to_le_bytes());
            }
            for (i, byte) in seed[160..416].iter_mut().enumerate() {
                *byte = (i * 29 + 7) as u8;
            }
            let mut in_use = u64::from_le_bytes(seed[512..520].try_into().unwrap()) | 3;
            for &(bit, start, len) in &components {
                if matches!(bit, 2 | 5 | 6 | 7) {
                    for (i, byte) in seed[start..start + len].iter_mut().enumerate() {
                        *byte = (i * 17 + bit as usize + 11) as u8;
                    }
                    in_use |= 1 << bit;
                }
            }
            seed[512..520].copy_from_slice(&in_use.to_le_bytes());
            seed[520..576].fill(0);
        }
        let mut value = Self {
            stack,
            initial,
            mask,
            enabled,
            image_len,
            components,
            seed_canonical: Vec::new(),
        };
        let mut seed = vec![0; value.canonical_len()];
        let raw = unsafe {
            std::slice::from_raw_parts(addr_of!(LI2_SEED_XSTATE).cast::<u8>(), image_len)
        };
        value.canonical_into(raw, &mut seed);
        value.seed_canonical = seed;
        value
    }

    /// Allocate all result storage before arming; capture only fills these bytes.
    pub fn empty_snapshot(&self) -> Snapshot {
        Snapshot {
            registers: [0; 17],
            xstate: vec![0; self.canonical_len()],
            red_zone_and_return: [0; 136],
        }
    }

    pub fn capture_into(&mut self, entry: usize, result: &mut Snapshot) {
        assert_eq!(xinuse() & self.enabled & !KNOWN, 0);
        let start = (self.initial[7] - 128) as *mut u8;
        unsafe {
            for i in 0..128 {
                start.add(i).write((i * 37 + 0x31) as u8);
            }
            (self.initial[7] as *mut u64).write(li2_probe_return as *const () as u64);
            LI2_INPUT = self.initial;
            LI2_TARGET = entry as u64;
            std::ptr::write_bytes(addr_of_mut!(LI2_OUTPUT_XSTATE).cast::<u8>(), 0, MAX_XSTATE);
            li2_probe_invoke();
            assert_eq!(
                LI2_OUTPUT_XINUSE & self.enabled & !KNOWN,
                0,
                "unowned state became active"
            );
            let registers = LI2_OUTPUT;
            assert_eq!(registers[7], self.initial[7] + 8, "unbalanced actual RET");
            let raw = std::slice::from_raw_parts(
                addr_of!(LI2_OUTPUT_XSTATE).cast::<u8>(),
                self.image_len,
            );
            std::ptr::copy_nonoverlapping(start, result.red_zone_and_return.as_mut_ptr(), 136);
            for (i, actual) in result.red_zone_and_return[..128].iter().enumerate() {
                assert_eq!(
                    *actual,
                    (i * 37 + 0x31) as u8,
                    "application red zone changed"
                );
            }
            assert_eq!(
                &result.red_zone_and_return[128..],
                &(li2_probe_return as *const () as u64).to_ne_bytes()
            );
            self.canonical_into(raw, &mut result.xstate);
            assert_eq!(
                result.xstate, self.seed_canonical,
                "seeded architectural extended state changed"
            );
            result.registers = registers;
        }
    }

    pub fn repeat(&self, entry: usize, count: usize) -> u64 {
        assert!(count > 0);
        unsafe {
            LI2_INPUT = self.initial;
            li2_probe_repeat(entry, count)
        }
    }

    pub fn mask(&self) -> u64 {
        self.mask
    }

    fn canonical_len(&self) -> usize {
        // Defined architectural bytes, excluding reserved/software slots.
        23 + 80
            + 4
            + 256
            + self
                .components
                .iter()
                .map(|(_, _, len)| 12 + len)
                .sum::<usize>()
    }

    fn canonical_into(&self, bytes: &[u8], output: &mut [u8]) {
        assert_eq!(output.len(), self.canonical_len());
        assert_eq!(&bytes[520..528], &[0; 8], "standard XSAVE format required");
        let in_use = u64::from_le_bytes(bytes[512..520].try_into().unwrap());
        assert_eq!(in_use & !self.mask, 0);
        output.fill(0);
        let mut cursor = 0;
        let mut append = |part: &[u8]| {
            output[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        };
        let mut x87 = [0; 24];
        x87[..2].copy_from_slice(&0x037f_u16.to_le_bytes());
        if in_use & 1 != 0 {
            x87.copy_from_slice(&bytes[..24]);
        }
        append(&x87[..5]);
        append(&x87[6..]);
        for i in 0..8 {
            if in_use & 1 != 0 {
                append(&bytes[32 + 16 * i..42 + 16 * i]);
            } else {
                append(&[0; 10]);
            }
        }
        append(&bytes[24..28]);
        if in_use & 2 != 0 {
            append(&bytes[160..416]);
        } else {
            append(&[0; 256]);
        }
        // End the short closure borrow before directly filling arbitrary-length
        // components in the already allocated output.
        for &(bit, start, len) in &self.components {
            output[cursor..cursor + 4].copy_from_slice(&bit.to_le_bytes());
            cursor += 4;
            output[cursor..cursor + 8].copy_from_slice(&(len as u64).to_le_bytes());
            cursor += 8;
            if in_use & (1 << bit) != 0 {
                output[cursor..cursor + len].copy_from_slice(&bytes[start..start + len]);
            }
            cursor += len;
        }
        assert_eq!(cursor, output.len());
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::munmap(self.stack.cast(), STACK + 2 * PAGE) },
            0
        );
    }
}

/// A real serialized bracket, used only for the changed RDTSC result.
pub fn tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("lfence", "rdtsc", "lfence", out("eax") low, out("edx") high,
        options(nostack, preserves_flags));
    }
    u64::from(low) | (u64::from(high) << 32)
}
