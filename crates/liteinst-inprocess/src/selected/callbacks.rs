//! Native class-specific callbacks. No registry, allocator or trapping shim.

use core::arch::asm;
use liteinst2::trampoline::{HookCallback, HookContext};

use super::{REJECTED_SYSCALL_EXIT_STATUS, SelectedKind};

pub(super) fn for_kind(kind: SelectedKind) -> HookCallback {
    match kind {
        SelectedKind::Cpuid => cpuid,
        SelectedKind::Rdtsc => rdtsc,
        SelectedKind::Syscall => syscall,
    }
}

// SAFETY: only the genuine core trampoline invokes these callbacks, supplying
// its live exclusive HookContext. The embedding contract excludes asynchronous
// application signals and unsupported extended-state/stack/CET environments.
unsafe extern "C" fn cpuid(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    let mut eax = context.rax as u32;
    let mut ecx = context.rcx as u32;
    let ebx: u64;
    let edx: u32;
    // LLVM reserves RBX in some code models. Preserve the callback's RBX in a
    // distinct early-clobber output, then exchange in the actual CPUID result.
    // CPUID, MOV and XCHG leave RFLAGS unchanged.
    unsafe {
        asm!(
            "mov {saved_rbx}, rbx",
            "cpuid",
            "xchg {saved_rbx}, rbx",
            saved_rbx = out(reg) ebx,
            inout("eax") eax,
            inout("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    context.rax = u64::from(eax);
    context.rbx = u64::from(ebx as u32);
    context.rcx = u64::from(ecx);
    context.rdx = u64::from(edx);
}

unsafe extern "C" fn rdtsc(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    let eax: u32;
    let edx: u32;
    // This is one actual RDTSC, with no substituted clock or added LFENCE.
    unsafe {
        asm!("rdtsc", out("eax") eax, out("edx") edx,
            options(nostack, preserves_flags));
    }
    context.rax = u64::from(eax);
    context.rdx = u64::from(edx);
}

unsafe extern "C" fn syscall(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    let number = context.rax;
    if number != libc::SYS_read as u64
        && number != libc::SYS_write as u64
        && number != libc::SYS_getpid as u64
        && number != libc::SYS_gettid as u64
    {
        refuse();
    }
    // Ordinary user arithmetic flags plus IF/DF and the fixed architectural
    // bit. TF/RF/AC and every system/virtualization flag remain excluded.
    const FLAGS: u64 = (1 << 0)
        | (1 << 1)
        | (1 << 2)
        | (1 << 4)
        | (1 << 6)
        | (1 << 7)
        | (1 << 9)
        | (1 << 10)
        | (1 << 11);
    const REQUIRED: u64 = (1 << 1) | (1 << 9);
    let flags = context.rflags;
    if flags & !FLAGS != 0 || flags & REQUIRED != REQUIRED {
        refuse();
    }
    let Some(next) = context.instruction_pointer.checked_add(2) else {
        refuse()
    };
    let result: u64;
    // All six original Linux arguments are forwarded, including the ones the
    // chosen kernel operation ignores. Raw negative errno stays in RAX; no TLS
    // errno access, wrapper, allocation, retry, or invented success is involved.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") context.rdi,
            in("rsi") context.rsi,
            in("rdx") context.rdx,
            in("r10") context.r10,
            in("r8") context.r8,
            in("r9") context.r9,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    context.rax = result;
    context.rcx = next;
    context.r11 = flags;
    // The saved original RFLAGS and every other original GPR remain exact;
    // the core restores them after this callback returns on its incoming stack.
}

fn refuse() -> ! {
    // Terminate before executing the unsupported requested syscall. If a
    // seccomp policy refuses termination, UD2 still cannot return success.
    unsafe {
        asm!(
            "syscall",
            "ud2",
            in("rax") libc::SYS_exit_group as u64,
            in("rdi") REJECTED_SYSCALL_EXIT_STATUS as u64,
            options(noreturn, nostack),
        );
    }
}
