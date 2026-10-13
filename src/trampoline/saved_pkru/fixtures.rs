//! Shared emitted-code fixtures; compiled only for unit tests or the explicit probe.

use core::arch::global_asm;

pub(super) const PAGE: usize = 4096;
const SENTINEL: u64 = 0x1357_9bdf_2468_ace0;

global_asm!(
    ".text",
    ".global pkru_view_invoke",
    "pkru_view_invoke:",
    "push rbx",
    "mov r10, rdi",
    "mov rbx, rsi",
    "mov rax, 0x13579bdf2468ace0",
    "movq xmm0, rax",
    "punpcklqdq xmm0, xmm0",
    "cmp eax, eax",
    "call r10",
    "mov [rbx], rax",
    "movdqu [rbx + 16], xmm0",
    "pushfq",
    "pop qword ptr [rbx + 8]",
    "pop rbx",
    "ret",
);

#[repr(C)]
#[derive(Default)]
struct ReturnProbe {
    rax: u64,
    flags: u64,
    xmm0: [u8; 16],
}

unsafe extern "C" {
    #[cfg(test)]
    fn pkru_view_invoke(entry: *const u8, result: *mut ReturnProbe);
}

#[allow(unused_unsafe)]
pub(super) fn ospke() -> bool {
    // CPUID is always available on x86-64, including the older crate MSRV.
    unsafe { core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 4) != 0 }
}

pub(super) struct Mapping {
    pub(super) writable: *mut u8,
    pub(super) executable: *mut u8,
}

impl Mapping {
    pub(super) fn new(code: &[u8]) -> Self {
        assert_eq!(
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
            PAGE as libc::c_long
        );
        let fd = unsafe { libc::memfd_create(c"saved-pkru-fixture".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::ftruncate(fd, PAGE as libc::off_t) }, 0);
        let writable = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        let executable = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_eq!(unsafe { libc::close(fd) }, 0);
        assert_ne!(writable, libc::MAP_FAILED);
        assert_ne!(executable, libc::MAP_FAILED);
        assert!(code.len() <= PAGE);
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), writable.cast(), code.len()) };
        Self {
            writable: writable.cast(),
            executable: executable.cast(),
        }
    }

    pub(super) fn address(&self) -> u64 {
        self.executable as usize as u64
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::munmap(self.writable.cast(), PAGE) }, 0);
        assert_eq!(unsafe { libc::munmap(self.executable.cast(), PAGE) }, 0);
    }
}

#[cfg(test)]
pub(super) fn invoke(entry: *const u8) {
    let mut result = ReturnProbe::default();
    unsafe { pkru_view_invoke(entry, &mut result) };
    assert_eq!(result.rax, SENTINEL);
    assert_eq!(result.flags & (1 | 4 | 16 | 64 | 128 | 2048), 4 | 64);
    let mut xmm = [0_u8; 16];
    xmm[..8].copy_from_slice(&SENTINEL.to_le_bytes());
    xmm[8..].copy_from_slice(&SENTINEL.to_le_bytes());
    assert_eq!(result.xmm0, xmm);
}

// Poison the exact future save-frame word with no Rust call or spill between
// the poison and entry. The temporary RSP owns the complete save extent.
#[cfg(feature = "saved-pkru-probe")]
global_asm!(
    ".text",
    ".global pkru_view_invoke_poisoned",
    "pkru_view_invoke_poisoned:",
    "push rbx",
    "mov r10, rdi",
    "mov rbx, rsi",
    "mov r8, rsp",
    "lea r11, [rsp - {distance}]",
    "and r11, -64",
    "sub r11, rdx",
    "mov rsp, r11",
    "mov dword ptr [rsp + rcx + 4], 0xdeadbeef",
    "mov [rbx + 32], r11",
    "mov eax, dword ptr [rsp + rcx + 4]",
    "mov [rbx + 40], eax",
    "mov rsp, r8",
    "mov rax, 0x13579bdf2468ace0",
    "movq xmm0, rax",
    "punpcklqdq xmm0, xmm0",
    "cmp eax, eax",
    "call r10",
    "mov [rbx], rax",
    "movdqu [rbx + 16], xmm0",
    "pushfq",
    "pop qword ptr [rbx + 8]",
    "pop rbx",
    "ret",
    distance = const 8 + crate::trampoline::SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES
        + crate::trampoline::SYSTEM_V_RED_ZONE_BYTES
        + crate::trampoline::SAVED_INTEGER_BYTES
        + crate::trampoline::HOOK_METADATA_BYTES,
);

#[cfg(feature = "saved-pkru-probe")]
#[repr(C)]
#[derive(Default)]
struct PoisonReturnProbe {
    registers: ReturnProbe,
    image_address: u64,
    poisoned: u32,
}

#[cfg(feature = "saved-pkru-probe")]
const _: () = {
    assert!(core::mem::offset_of!(PoisonReturnProbe, image_address) == 32);
    assert!(core::mem::offset_of!(PoisonReturnProbe, poisoned) == 40);
};

#[cfg(feature = "saved-pkru-probe")]
unsafe extern "C" {
    fn pkru_view_invoke_poisoned(
        entry: *const u8,
        result: *mut PoisonReturnProbe,
        allocation_len: u64,
        pkru_offset: u64,
    );
}

#[cfg(feature = "saved-pkru-probe")]
pub(super) fn invoke_poisoned(
    entry: *const u8,
    layout: crate::trampoline::SavedExtendedStateLayout,
) -> u64 {
    assert_eq!(
        layout.format(),
        crate::trampoline::SavedExtendedStateFormat::XSAVE64_STANDARD
    );
    assert!(layout.len() <= 64 * 1024);
    let component = layout
        .components()
        .iter()
        .find(|component| component.xfeature() == crate::trampoline::PKRU_XFEATURE)
        .unwrap();
    assert_eq!(component.size(), 8);
    assert!(component.offset().checked_add(8).unwrap() <= layout.len());
    let mut result = PoisonReturnProbe::default();
    unsafe { pkru_view_invoke_poisoned(entry, &mut result, layout.len(), component.offset()) };
    assert_eq!(result.poisoned, 0xdead_beef);
    assert_ne!(result.image_address, 0);
    assert_eq!(result.registers.rax, SENTINEL);
    assert_eq!(
        result.registers.flags & (1 | 4 | 16 | 64 | 128 | 2048),
        4 | 64
    );
    let mut xmm = [0_u8; 16];
    xmm[..8].copy_from_slice(&SENTINEL.to_le_bytes());
    xmm[8..].copy_from_slice(&SENTINEL.to_le_bytes());
    assert_eq!(result.registers.xmm0, xmm);
    result.image_address
}
