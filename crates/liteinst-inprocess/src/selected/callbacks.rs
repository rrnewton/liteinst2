//! Native class-specific callbacks. No registry, allocator or trapping shim.

use core::arch::asm;
use liteinst2::contracts::Refusal;
use liteinst2::trampoline::{HookCallback, HookContext};

use super::{
    REJECTED_SYSCALL_EXIT_STATUS, SelectedDestination, SelectedInstruction, SelectedKind,
    SelectedWidth, metrics,
};

pub(super) fn for_instruction(instruction: &SelectedInstruction) -> Result<HookCallback, Refusal> {
    match instruction.kind() {
        SelectedKind::Cpuid => Ok(cpuid),
        SelectedKind::Rdtsc => Ok(rdtsc),
        SelectedKind::Syscall => Ok(syscall),
        SelectedKind::Rdtscp => Ok(rdtscp),
        SelectedKind::Rdrand | SelectedKind::Rdseed => {
            let destination = instruction.destination().ok_or(Refusal::InvalidPlan)?;
            let width = instruction.width().ok_or(Refusal::InvalidPlan)?;
            if instruction.kind() == SelectedKind::Rdrand {
                random_for::<false>(destination, width)
            } else {
                random_for::<true>(destination, width)
            }
        }
        SelectedKind::Rdpid => rdpid_for(instruction.destination().ok_or(Refusal::InvalidPlan)?),
    }
}

fn entered(kind: SelectedKind, context: &HookContext) {
    if !metrics::for_kind(kind).enter(context.instruction_pointer) {
        refuse();
    }
}

fn completed(kind: SelectedKind, carry_clear: bool) {
    if !metrics::for_kind(kind).complete(carry_clear) {
        refuse();
    }
}

// SAFETY: only the genuine core trampoline invokes these callbacks, supplying
// its live exclusive HookContext. The embedding contract excludes asynchronous
// application signals and unsupported extended-state/stack/CET environments.
unsafe extern "C" fn cpuid(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    entered(SelectedKind::Cpuid, context);
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
    completed(SelectedKind::Cpuid, false);
}

unsafe extern "C" fn rdtsc(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    entered(SelectedKind::Rdtsc, context);
    let eax: u32;
    let edx: u32;
    // This is one actual RDTSC, with no substituted clock or added LFENCE.
    unsafe {
        asm!("rdtsc", out("eax") eax, out("edx") edx,
            options(nostack, preserves_flags));
    }
    context.rax = u64::from(eax);
    context.rdx = u64::from(edx);
    completed(SelectedKind::Rdtsc, false);
}

unsafe extern "C" fn syscall(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    entered(SelectedKind::Syscall, context);
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
    completed(SelectedKind::Syscall, false);
    // The saved original RFLAGS and every other original GPR remain exact;
    // the core restores them after this callback returns on its incoming stack.
}

// The current core restores an ordinary completion, not an original #DB/RF
// fault transition. Those modes are explicitly outside this callback profile.
fn require_completion_flags(context: &HookContext) {
    if context.rflags & ((1 << 8) | (1 << 16)) != 0 {
        refuse();
    }
}

fn random_for<const SEED: bool>(
    destination: SelectedDestination,
    width: SelectedWidth,
) -> Result<HookCallback, Refusal> {
    match width {
        SelectedWidth::Bits16 => random_destination::<SEED, 16>(destination),
        SelectedWidth::Bits32 => random_destination::<SEED, 32>(destination),
        SelectedWidth::Bits64 => random_destination::<SEED, 64>(destination),
    }
}

fn random_destination<const SEED: bool, const WIDTH: u8>(
    destination: SelectedDestination,
) -> Result<HookCallback, Refusal> {
    macro_rules! select {
        ($($name:ident),+ $(,)?) => {
            match destination {
                $(SelectedDestination::$name => Ok(random::<SEED, WIDTH, { SelectedDestination::$name as u8 }>),)+
                SelectedDestination::Rsp => Err(Refusal::InvalidPlan),
            }
        };
    }
    select! { Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15 }
}

unsafe extern "C" fn random<const SEED: bool, const WIDTH: u8, const DEST: u8>(
    context: *mut HookContext,
) {
    let context = unsafe { &mut *context };
    let kind = if SEED {
        SelectedKind::Rdseed
    } else {
        SelectedKind::Rdrand
    };
    entered(kind, context);
    require_completion_flags(context);
    let carry: u8;
    // Each instantiation executes exactly one actual instruction at its
    // original operand width. SETC captures that instruction's carry without
    // intervening flag changes. Distinct early-clobber outputs prevent overlap.
    // There is no capability-based deselection, retry, or substituted sample.
    let (value, width) = match WIDTH {
        16 => {
            let value: u16;
            unsafe {
                if SEED {
                    asm!("rdseed {value:x}", "setc {carry}", value = out(reg) value, carry = out(reg_byte) carry, options(nostack));
                } else {
                    asm!("rdrand {value:x}", "setc {carry}", value = out(reg) value, carry = out(reg_byte) carry, options(nostack));
                }
            }
            (u64::from(value), SelectedWidth::Bits16)
        }
        32 => {
            let value: u32;
            unsafe {
                if SEED {
                    asm!("rdseed {value:e}", "setc {carry}", value = out(reg) value, carry = out(reg_byte) carry, options(nostack));
                } else {
                    asm!("rdrand {value:e}", "setc {carry}", value = out(reg) value, carry = out(reg_byte) carry, options(nostack));
                }
            }
            (u64::from(value), SelectedWidth::Bits32)
        }
        64 => {
            let value: u64;
            unsafe {
                if SEED {
                    asm!("rdseed {value}", "setc {carry}", value = out(reg) value, carry = out(reg_byte) carry, options(nostack));
                } else {
                    asm!("rdrand {value}", "setc {carry}", value = out(reg) value, carry = out(reg_byte) carry, options(nostack));
                }
            }
            (value, SelectedWidth::Bits64)
        }
        _ => refuse(),
    };
    if !apply_random(context, DEST, width, value, carry != 0) {
        refuse();
    }
    completed(kind, carry == 0);
}

// This private supplied-value helper is used by the real callback and pure
// outcome controls. It does not execute hardware, produce a completion seal,
// increment a native count, or constitute a public replacement-provider API.
pub(super) fn apply_random(
    context: &mut HookContext,
    destination: u8,
    width: SelectedWidth,
    value: u64,
    carry: bool,
) -> bool {
    let maximum = match width {
        SelectedWidth::Bits16 => u64::from(u16::MAX),
        SelectedWidth::Bits32 => u64::from(u32::MAX),
        SelectedWidth::Bits64 => u64::MAX,
    };
    if value > maximum || (!carry && value != 0) {
        return false;
    }
    let Some(output) = register_mut(context, destination) else {
        return false;
    };
    *output = match width {
        SelectedWidth::Bits16 => (*output & !u64::from(u16::MAX)) | value,
        SelectedWidth::Bits32 | SelectedWidth::Bits64 => value,
    };
    // Defined architectural RDRAND/RDSEED flags: only CF reports success;
    // OF/SF/ZF/AF/PF are zero and all other admitted input bits remain exact.
    const ARITHMETIC: u64 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    context.rflags = (context.rflags & !ARITHMETIC) | u64::from(carry);
    true
}

fn rdpid_for(destination: SelectedDestination) -> Result<HookCallback, Refusal> {
    macro_rules! select {
        ($($name:ident),+ $(,)?) => {
            match destination {
                $(SelectedDestination::$name => Ok(rdpid::<{ SelectedDestination::$name as u8 }>),)+
                SelectedDestination::Rsp => Err(Refusal::InvalidPlan),
            }
        };
    }
    select! { Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15 }
}

unsafe extern "C" fn rdpid<const DEST: u8>(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    entered(SelectedKind::Rdpid, context);
    require_completion_flags(context);
    let value: u64;
    unsafe {
        asm!("rdpid {value}", value = out(reg) value, options(nostack, preserves_flags));
    }
    // Long-mode RDPID zero-extends TSC_AUX into the complete destination.
    if value > u64::from(u32::MAX) || !apply_rdpid(context, DEST, value as u32) {
        refuse();
    }
    completed(SelectedKind::Rdpid, false);
}

pub(super) fn apply_rdpid(context: &mut HookContext, destination: u8, auxiliary: u32) -> bool {
    let Some(output) = register_mut(context, destination) else {
        return false;
    };
    *output = u64::from(auxiliary);
    true
}

unsafe extern "C" fn rdtscp(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    entered(SelectedKind::Rdtscp, context);
    require_completion_flags(context);
    let eax: u32;
    let edx: u32;
    let ecx: u32;
    // Actual RDTSCP ordering, timestamp and AUX; no replacement clock or LFENCE.
    unsafe {
        asm!("rdtscp", out("eax") eax, out("edx") edx, out("ecx") ecx, options(nostack, preserves_flags));
    }
    apply_rdtscp(context, eax, edx, ecx);
    completed(SelectedKind::Rdtscp, false);
}

pub(super) fn apply_rdtscp(context: &mut HookContext, eax: u32, edx: u32, ecx: u32) {
    context.rax = u64::from(eax);
    context.rdx = u64::from(edx);
    context.rcx = u64::from(ecx);
}

fn register_mut(context: &mut HookContext, destination: u8) -> Option<&mut u64> {
    // No RSP branch: stack_pointer is metadata and is never treated as output.
    match destination {
        0 => Some(&mut context.rax),
        1 => Some(&mut context.rcx),
        2 => Some(&mut context.rdx),
        3 => Some(&mut context.rbx),
        5 => Some(&mut context.rbp),
        6 => Some(&mut context.rsi),
        7 => Some(&mut context.rdi),
        8 => Some(&mut context.r8),
        9 => Some(&mut context.r9),
        10 => Some(&mut context.r10),
        11 => Some(&mut context.r11),
        12 => Some(&mut context.r12),
        13 => Some(&mut context.r13),
        14 => Some(&mut context.r14),
        15 => Some(&mut context.r15),
        _ => None,
    }
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
