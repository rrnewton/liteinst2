#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Standalone exact-syscall plans: no source patch, copied tail, or PKRU rewind.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, Register};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{
    ExecutableTrampoline, HookCallback, HookContext, SavedExtendedStateFormat,
    SavedExtendedStateLayout, TrampolineArena, TrampolineError, TrampolineImage, TrampolinePlan,
};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PKRU: u64 = 1 << 9;
const PAGE: usize = 4096;
static EXECUTION: Mutex<()> = Mutex::new(());
static TAIL: AtomicUsize = AtomicUsize::new(0);
static CONTEXT: [AtomicU64; 11] = [const { AtomicU64::new(0) }; 11];
static DESCRIPTOR_MASK: AtomicU64 = AtomicU64::new(0);
static DESCRIPTOR_LEN: AtomicU64 = AtomicU64::new(0);
static DESCRIPTOR_FORMAT: AtomicU64 = AtomicU64::new(0);
static DESCRIPTOR_VALID: AtomicUsize = AtomicUsize::new(0);
static NEXT_PKRU: AtomicU32 = AtomicU32::new(0);
static SIGNAL_PKRU_OFFSET: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_FRAME_STATUS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn noop(_: *mut HookContext) {}

#[allow(unused_unsafe)]
fn cpuid(leaf: u32, subleaf: u32) -> core::arch::x86_64::CpuidResult {
    // CPUID is available on x86-64. This also supports the crate's older
    // minimum Rust version, where the intrinsic is unsafe.
    unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) }
}

fn plan(code: &[u8], base: u64, callback: HookCallback) -> TrampolinePlan {
    let scan = InstructionScanner::default().scan(code, base).unwrap();
    TrampolinePlan::from_scan_replacing_exact_syscall(&scan, base, callback).unwrap()
}

fn logical_pc(image: &TrampolineImage, address: u64) -> Option<u64> {
    image
        .program_counter_mappings()
        .iter()
        .find_map(|mapping| mapping.translate(address))
}

#[test]
fn exact_constructor_requires_the_literal_two_byte_syscall() {
    let scanner = InstructionScanner::default();
    let base = 0x200000;
    let scan = scanner.scan(&[0x0f, 0x05], base).unwrap();
    let exact = TrampolinePlan::from_scan_replacing_exact_syscall(&scan, base, noop).unwrap();
    assert!(exact.replaces_first());
    assert_eq!(exact.execute_address(), base);
    assert_eq!(exact.displaced_len(), 2);
    assert_eq!(exact.return_address(), base + 2);
    assert!(matches!(
        TrampolinePlan::from_scan_replacing_first(&scan, base, noop),
        Err(TrampolineError::InstructionTooShort {
            instruction_len: 2,
            ..
        })
    ));
    assert!(matches!(
        TrampolinePlan::from_scan_replacing_exact_syscall(&scan, base + 1, noop),
        Err(TrampolineError::SiteNotFound { .. })
    ));
    for bytes in [
        &[0x48, 0x0f, 0x05][..], // REX-prefixed syscall
        &[0x66, 0x0f, 0x05][..], // operand-size-prefixed syscall
        &[0x0f, 0x34][..],       // sysenter
        &[0x0f, 0x0b][..],       // ud2
        &[0x90][..],             // nop
    ] {
        let scan = scanner.scan(bytes, base).unwrap();
        assert!(
            matches!(
                TrampolinePlan::from_scan_replacing_exact_syscall(&scan, base, noop),
                Err(TrampolineError::NotExactSyscall { .. })
            ),
            "accepted {bytes:02x?}"
        );
    }
    let scan = scanner.scan(&[0x90, 0x0f, 0x05, 0xc3], base).unwrap();
    assert_eq!(
        TrampolinePlan::from_scan_replacing_exact_syscall(&scan, base + 1, noop)
            .unwrap()
            .return_address(),
        base + 3
    );
    // ScanResult cannot represent an overflowing source extent. This is a
    // scanner rejection, not invented coverage of the constructor's guard.
    assert!(scanner.scan(&[0x0f, 0x05], u64::MAX - 1).is_err());
}

#[test]
fn exact_emission_has_zero_tail_and_truthful_save_restore_masks() {
    let base = 0x200000;
    let destination = 0x300000;
    let code = [0x0f, 0x05, 0x83, 0xc0, 0x01, 0xc3];
    let image = plan(&code, base, noop).emit_at(destination).unwrap();
    let layout = image.layout();
    assert_eq!(layout.relocated_len, 0);
    assert_eq!(layout.entry_stop_len, 0);
    assert_eq!(layout.completion_stop_len, 0);
    let saved = layout.saved_extended_state;
    let ordinary = SavedExtendedStateLayout::detect().unwrap();
    assert_eq!(saved.format(), ordinary.format());
    assert_eq!(saved.mask(), ordinary.mask() & !PKRU);
    assert_eq!(
        saved
            .components()
            .iter()
            .map(|c| c.xfeature())
            .collect::<Vec<_>>(),
        ordinary
            .components()
            .iter()
            .filter(|c| c.xfeature() != PKRU)
            .map(|c| c.xfeature())
            .collect::<Vec<_>>()
    );
    for component in saved.components() {
        assert_eq!(
            Some(component),
            ordinary
                .components()
                .iter()
                .find(|other| other.xfeature() == component.xfeature())
        );
        assert!(component.offset() + component.size() <= saved.image_len());
    }
    assert!(saved.image_len() <= ordinary.image_len());
    assert_eq!(
        saved.len() % saved.format().required_alignment().unwrap(),
        0
    );

    let return_offset = layout.instrumentation_len + layout.restore_len;
    let instructions: Vec<_> = Decoder::with_ip(
        64,
        &image.bytes()[..return_offset],
        destination,
        DecoderOptions::NONE,
    )
    .into_iter()
    .collect();
    assert!(
        !instructions.iter().any(|instruction| matches!(
            instruction.mnemonic(),
            Mnemonic::Syscall | Mnemonic::Int3
        ))
    );
    if saved.format() == SavedExtendedStateFormat::XSAVE64_STANDARD {
        let mut supplied_masks = Vec::new();
        for (index, instruction) in instructions.iter().enumerate() {
            if matches!(instruction.code(), Code::Xsave64_mem | Code::Xrstor64_mem) {
                let low = &instructions[index - 2];
                let high = &instructions[index - 1];
                assert_eq!(low.code(), Code::Mov_r32_imm32);
                assert_eq!(low.op0_register(), Register::EAX);
                assert_eq!(high.code(), Code::Mov_r32_imm32);
                assert_eq!(high.op0_register(), Register::EDX);
                supplied_masks
                    .push(u64::from(low.immediate32()) | (u64::from(high.immediate32()) << 32));
            }
        }
        assert_eq!(supplied_masks, [saved.mask(), saved.mask()]);
    } else {
        assert_eq!(
            instructions
                .iter()
                .filter(|i| i.code() == Code::Fxsave64_m512byte)
                .count(),
            1
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|i| i.code() == Code::Fxrstor64_m512byte)
                .count(),
            1
        );
    }
    let scan = InstructionScanner::default().scan(&code, base).unwrap();
    let legacy = TrampolinePlan::from_scan_replacing_first(&scan, base, noop).unwrap();
    let legacy_image = legacy.emit_at(destination).unwrap();
    assert_eq!(legacy.displaced_len(), 5);
    assert_eq!(legacy.return_address(), base + 5);
    assert!(legacy_image.layout().relocated_len > 0);
    assert_eq!(legacy_image.layout().saved_extended_state, ordinary);
}

#[test]
fn exact_pc_maps_cover_only_capture_restore_and_the_neutral_return() {
    let base = 0x200000;
    for destination in [0x300000, 0x4_0000_0000] {
        let image = plan(&[0x0f, 0x05], base, noop)
            .emit_at(destination)
            .unwrap();
        let start = image.layout().instrumentation_len + image.layout().restore_len;
        for offset in 0..start {
            assert_eq!(logical_pc(&image, destination + offset as u64), Some(base));
        }
        let mut decoder = Decoder::with_ip(
            64,
            &image.bytes()[start..],
            destination + start as u64,
            DecoderOptions::NONE,
        );
        let jump = decoder.decode();
        assert_eq!(jump.mnemonic(), Mnemonic::Jmp);
        if destination == 0x300000 {
            assert_eq!(jump.code(), Code::Jmp_rel32_64);
            assert_eq!(jump.near_branch_target(), base + 2);
            assert_eq!(jump.len(), image.layout().return_len);
        } else {
            assert_eq!(jump.code(), Code::Jmp_rm64);
            assert_eq!(jump.segment_prefix(), Register::DS); // CET NOTRACK
            let offset = (jump.ip_rel_memory_address() - destination) as usize;
            assert_eq!(
                u64::from_le_bytes(image.bytes()[offset..offset + 8].try_into().unwrap()),
                base + 2
            );
            assert_eq!(jump.len() + 8, image.layout().return_len);
            for offset in offset..offset + 8 {
                assert_eq!(logical_pc(&image, destination + offset as u64), None);
            }
        }
        for pc in jump.ip()..jump.next_ip() {
            assert_eq!(logical_pc(&image, pc), Some(base + 2));
        }
        assert_eq!(
            logical_pc(&image, destination + image.bytes().len() as u64),
            None
        );
    }
}

struct SourceMapping {
    writable: *mut u8,
    executable: *mut u8,
}

impl SourceMapping {
    fn new(code: &[u8]) -> Self {
        let name = c"liteinst2-exact-syscall-test";
        // SAFETY: a fresh memfd backs distinct RW and RX aliases.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
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
        let result = Self {
            writable: writable.cast(),
            executable: executable.cast(),
        };
        result.write(0, code);
        result
    }

    fn write(&self, offset: usize, bytes: &[u8]) {
        assert!(offset + bytes.len() <= PAGE);
        // SAFETY: only the test owns and writes this RW alias.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.writable.add(offset), bytes.len())
        }
    }

    fn address(&self) -> u64 {
        self.executable as usize as u64
    }
}

impl Drop for SourceMapping {
    fn drop(&mut self) {
        // No invocation remains. Arena mappings, unlike these source fixtures,
        // retain their existing process-lifetime policy.
        assert_eq!(unsafe { libc::munmap(self.writable.cast(), PAGE) }, 0);
        assert_eq!(unsafe { libc::munmap(self.executable.cast(), PAGE) }, 0);
    }
}

fn allocate(
    mapping: &SourceMapping,
    code: &[u8],
    callback: HookCallback,
    legacy: bool,
) -> ExecutableTrampoline {
    let scan = InstructionScanner::default()
        .scan(code, mapping.address())
        .unwrap();
    let plan = if legacy {
        TrampolinePlan::from_scan_replacing_first(&scan, mapping.address(), callback).unwrap()
    } else {
        TrampolinePlan::from_scan_replacing_exact_syscall(&scan, mapping.address(), callback)
            .unwrap()
    };
    let arena = TrampolineArena::allocate_near(mapping.address(), 1).unwrap();
    let trampoline = arena.allocate(&plan).unwrap();
    assert_eq!(
        unsafe { core::slice::from_raw_parts(mapping.executable, code.len()) },
        code
    );
    trampoline
}

unsafe fn record_descriptor(context: &HookContext) {
    let saved = context.saved_extended_state();
    DESCRIPTOR_MASK.store(saved.mask(), Ordering::Relaxed);
    DESCRIPTOR_LEN.store(saved.len(), Ordering::Relaxed);
    DESCRIPTOR_FORMAT.store(saved.format().raw(), Ordering::Relaxed);
    let aligned = saved
        .format()
        .required_alignment()
        .is_some_and(|alignment| saved.address() % alignment == 0);
    DESCRIPTOR_VALID.store(
        usize::from(aligned && saved.len() >= 512),
        Ordering::Relaxed,
    );
}

fn assert_descriptor(trampoline: &ExecutableTrampoline) {
    let layout = trampoline.layout().saved_extended_state;
    assert_eq!(DESCRIPTOR_MASK.load(Ordering::Relaxed), layout.mask());
    assert_eq!(DESCRIPTOR_LEN.load(Ordering::Relaxed), layout.len());
    assert_eq!(
        DESCRIPTOR_FORMAT.load(Ordering::Relaxed),
        layout.format().raw()
    );
    assert_eq!(DESCRIPTOR_VALID.load(Ordering::Relaxed), 1);
}

unsafe extern "C" fn live_tail_hook(context: *mut HookContext) {
    // SAFETY: the generated callback owns this live context until return.
    let context = unsafe { &mut *context };
    unsafe { record_descriptor(context) };
    for (slot, value) in CONTEXT.iter().zip([
        context.instruction_pointer,
        context.stack_pointer,
        context.rdi,
        context.rsi,
        context.rdx,
        context.rcx,
        context.r8,
        context.r9,
        context.r10,
        context.rflags,
        u64::from((1..=16).all(|i| unsafe {
            core::ptr::read((context.stack_pointer as *const u64).sub(i)) == 0x1234_5678
        })),
    ]) {
        slot.store(value, Ordering::Relaxed);
    }
    let tail = TAIL.load(Ordering::Relaxed);
    if tail != 0 {
        // SAFETY: the serialized fixture owns a live four-byte RW immediate.
        unsafe { core::ptr::write_unaligned(tail as *mut u32, 22) };
        // Serialize this controlled self-modification before returning to the
        // RX alias. A copied old tail would still return eleven.
        let _ = cpuid(0, 0);
    }
    context.rax = 0xaa;
    context.rcx = context.instruction_pointer + 2;
    context.r11 = context.rflags;
    unsafe { asm!("clc", "pxor xmm0, xmm0", out("xmm0") _, options(nostack)) };
}

global_asm!(
    ".global liteinst2_exact_invoke",
    ".type liteinst2_exact_invoke,@function",
    "liteinst2_exact_invoke:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "push rsi",
    "mov rax, rdi",
    "mov [rsi], rsp",
    "mov r10d, 0x12345678",
    "mov [rsp-16], r10",
    "mov [rsp-24], r10",
    "mov [rsp-32], r10",
    "mov [rsp-40], r10",
    "mov [rsp-48], r10",
    "mov [rsp-56], r10",
    "mov [rsp-64], r10",
    "mov [rsp-72], r10",
    "mov [rsp-80], r10",
    "mov [rsp-88], r10",
    "mov [rsp-96], r10",
    "mov [rsp-104], r10",
    "mov [rsp-112], r10",
    "mov [rsp-120], r10",
    "mov [rsp-128], r10",
    "mov [rsp-136], r10",
    "mov ebx, 0xb1",
    "mov ebp, 0xb2",
    "mov r12d, 0xb3",
    "mov r13d, 0xb4",
    "mov r14d, 0xb5",
    "mov r15d, 0xb6",
    "mov edi, 11",
    "mov esi, 12",
    "mov edx, 13",
    "mov ecx, 14",
    "mov r8d, 15",
    "mov r9d, 16",
    "mov r10d, 17",
    "cmp edi, 11",
    "call rax",
    "mov rdi, [rsp]",
    "mov [rdi+8], rsp",
    "mov [rdi+16], rax",
    "mov [rdi+24], rcx",
    "mov [rdi+32], r11",
    "pushfq",
    "pop rax",
    "mov [rdi+40], rax",
    "mov [rdi+48], rbx",
    "mov [rdi+56], rbp",
    "mov [rdi+64], r12",
    "mov [rdi+72], r13",
    "mov [rdi+80], r14",
    "mov [rdi+88], r15",
    "add rsp, 8",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    ".size liteinst2_exact_invoke, .-liteinst2_exact_invoke",
);

unsafe extern "C" {
    fn liteinst2_exact_invoke(entry: usize, output: *mut [u64; 12]);
}

#[test]
fn exact_execution_uses_the_live_tail_and_preserves_abi_flags_and_red_zone() {
    let _lock = EXECUTION.lock().unwrap();
    let code = [0x0f, 0x05, 0xb8, 11, 0, 0, 0, 0xc3];
    // The old plan intentionally copies the MOV into its patch window. This
    // control proves that the observer distinguishes copied eleven from live
    // twenty-two without changing the old plan's state policy.
    let legacy_source = SourceMapping::new(&code);
    let legacy = allocate(&legacy_source, &code, live_tail_hook, true);
    TAIL.store(
        unsafe { legacy_source.writable.add(3) } as usize,
        Ordering::Relaxed,
    );
    let mut old_output = [0_u64; 12];
    unsafe { liteinst2_exact_invoke(legacy.address() as usize, &mut old_output) };
    TAIL.store(0, Ordering::Relaxed);
    assert_eq!(old_output[2], 11);
    assert_eq!(
        unsafe { core::ptr::read_unaligned(legacy_source.writable.add(3).cast::<u32>()) },
        22
    );
    assert_descriptor(&legacy);
    let mapping = SourceMapping::new(&code);
    let trampoline = allocate(&mapping, &code, live_tail_hook, false);
    TAIL.store(
        unsafe { mapping.writable.add(3) } as usize,
        Ordering::Relaxed,
    );
    let mut output = [0_u64; 12];
    // SAFETY: the wrapper makes one balanced C-ABI call and records all seeds.
    unsafe { liteinst2_exact_invoke(trampoline.address() as usize, &mut output) };
    TAIL.store(0, Ordering::Relaxed);
    let context: Vec<_> = CONTEXT
        .iter()
        .map(|slot| slot.load(Ordering::Relaxed))
        .collect();
    assert_eq!(context[0], mapping.address());
    assert_eq!(context[1], output[0] - 8);
    assert_eq!(&context[2..9], &[11, 12, 13, 14, 15, 16, 17]);
    assert_eq!(
        context[10], 1,
        "all 128 red-zone bytes must survive the callback"
    );
    assert_eq!(output[0], output[1], "entry/return RSP differs");
    assert_eq!(output[2], 22, "executed a stale copied tail");
    assert_eq!(output[3], mapping.address() + 2);
    assert_eq!(output[4], context[9]);
    assert_eq!(output[5], context[9]);
    assert_descriptor(&trampoline);
    assert_ne!(output[5] & (1 << 6), 0, "ZF was lost");
    assert_eq!(&output[6..], &[0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6]);
    assert_eq!(DESCRIPTOR_VALID.load(Ordering::Relaxed), 1);
    assert_eq!(DESCRIPTOR_MASK.load(Ordering::Relaxed) & PKRU, 0);
    assert_eq!(
        unsafe { core::slice::from_raw_parts(mapping.executable, 2) },
        &[0x0f, 0x05]
    );
    assert_eq!(trampoline.layout().relocated_len, 0);
    trampoline.publish_program_counter_mappings();
    assert_eq!(
        liteinst2::trampoline::translate_program_counter(trampoline.address()),
        Some(mapping.address())
    );
}

unsafe extern "C" fn clobber_xmm(context: *mut HookContext) {
    unsafe { record_descriptor(&*context) };
    unsafe { asm!("pxor xmm0, xmm0", out("xmm0") _, options(nostack)) };
}

#[target_feature(enable = "avx2")]
unsafe extern "C" fn clobber_ymm(context: *mut HookContext) {
    unsafe { record_descriptor(&*context) };
    unsafe { asm!("vpxor ymm1, ymm1, ymm1", out("ymm1") _, options(nostack)) };
}

#[test]
fn exact_execution_preserves_xmm_and_enabled_avx_upper_lanes() {
    let _lock = EXECUTION.lock().unwrap();
    let code = [0x0f, 0x05, 0xf2, 0x0f, 0x58, 0xc0, 0xc3];
    let mapping = SourceMapping::new(&code);
    let trampoline = allocate(&mapping, &code, clobber_xmm, false);
    let double: unsafe extern "C" fn(f64) -> f64 =
        unsafe { core::mem::transmute(trampoline.address() as usize) };
    assert_eq!(unsafe { double(3.25) }, 6.5);
    assert_descriptor(&trampoline);
    assert_eq!(DESCRIPTOR_VALID.load(Ordering::Relaxed), 1);
    if !std::is_x86_feature_detected!("avx2") {
        println!("CAPABILITY_UNAVAILABLE avx2; XMM execution completed, AVX execution did not run");
        return;
    }
    use iced_x86::code_asm::{CodeAssembler, rax, xmm0, ymm1};
    let mut assembler = CodeAssembler::new(64).unwrap();
    assembler.vextracti128(xmm0, ymm1, 1).unwrap();
    assembler.vmovq(rax, xmm0).unwrap();
    assembler.vzeroupper().unwrap();
    assembler.ret().unwrap();
    let mut code = vec![0x0f, 0x05];
    code.extend(assembler.assemble(0).unwrap());
    let mapping = SourceMapping::new(&code);
    let trampoline = allocate(&mapping, &code, clobber_ymm, false);
    let function: unsafe extern "C" fn() -> u64 =
        unsafe { core::mem::transmute(trampoline.address() as usize) };
    let result: u64;
    unsafe {
        asm!("vpcmpeqd ymm1, ymm1, ymm1", "call {entry}", entry = in(reg) function,
        lateout("rax") result, clobber_abi("C"))
    };
    assert_eq!(result, u64::MAX);
    assert_descriptor(&trampoline);
    assert_ne!(DESCRIPTOR_MASK.load(Ordering::Relaxed) & (1 << 2), 0);
    println!("CAPABILITY_EXECUTED avx2 upper-lane restoration");
}

unsafe fn raw_syscall(number: i64, a: u64, b: u64, c: u64) -> i64 {
    unsafe { raw_syscall4(number, a, b, c, 0) }
}

unsafe fn raw_syscall4(number: i64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let result: i64;
    unsafe {
        asm!("syscall", inlateout("rax") number => result, in("rdi") a,
        in("rsi") b, in("rdx") c, in("r10") d, lateout("rcx") _, lateout("r11") _, options(nostack))
    };
    result
}

unsafe fn read_pkru() -> u32 {
    let result: u32;
    unsafe {
        asm!("rdpkru", in("ecx") 0_u32, lateout("eax") result,
        lateout("edx") _, options(nostack, preserves_flags))
    };
    result
}

unsafe fn write_pkru(value: u32) {
    unsafe {
        asm!("wrpkru", in("eax") value, in("ecx") 0_u32, in("edx") 0_u32,
        options(nostack, preserves_flags))
    };
}

fn pkey() -> Option<i32> {
    // SAFETY: CPUID is unconditionally available on x86-64. OSPKE proves that
    // RDPKRU/WRPKRU are enabled; the syscall separately proves key availability.
    let cpu = cpuid(7, 0);
    if cpu.ecx & (1 << 4) == 0 {
        println!("CAPABILITY_UNAVAILABLE ospke; no PKRU execution occurred");
        return None;
    }
    let key = unsafe { raw_syscall(libc::SYS_pkey_alloc, 0, 0, 0) };
    if key < 0 {
        println!("CAPABILITY_UNAVAILABLE pkey_alloc={key}; no PKRU execution occurred");
        return None;
    }
    assert!((1..16).contains(&key));
    Some(key as i32)
}

unsafe extern "C" fn native_read(context: *mut HookContext) {
    let context = unsafe { &mut *context };
    unsafe { record_descriptor(context) };
    context.rax =
        unsafe { raw_syscall(libc::SYS_read, context.rdi, context.rsi, context.rdx) } as u64;
    context.rcx = context.instruction_pointer + 2;
    context.r11 = context.rflags;
}

unsafe extern "C" fn change_pkru(context: *mut HookContext) {
    unsafe { record_descriptor(&*context) };
    unsafe { write_pkru(NEXT_PKRU.load(Ordering::Relaxed)) };
}

fn call_void(mapping: &SourceMapping, callback: HookCallback, legacy: bool) {
    let code = [0x0f, 0x05, 0x90, 0x90, 0x90, 0xc3];
    let trampoline = allocate(mapping, &code, callback, legacy);
    let function: unsafe extern "C" fn() =
        unsafe { core::mem::transmute(trampoline.address() as usize) };
    unsafe { function() };
    assert_descriptor(&trampoline);
}

fn denied_and_changed_pkru() {
    let Some(key) = pkey() else {
        return;
    };
    let initial = unsafe { read_pkru() };
    let denied = initial | (3 << (key * 2));
    let buffer = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(buffer, libc::MAP_FAILED);
    assert_eq!(
        unsafe {
            raw_syscall4(
                libc::SYS_pkey_mprotect,
                buffer as u64,
                PAGE as u64,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                key as u64,
            )
        },
        0
    );
    let mut pipe = [-1_i32; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    assert_eq!(
        unsafe { raw_syscall(libc::SYS_write, pipe[1] as u64, b"q".as_ptr() as u64, 1) },
        1
    );
    let code = [0x0f, 0x05, 0x90, 0x90, 0x90, 0xc3];
    let mapping = SourceMapping::new(&code);
    let trampoline = allocate(&mapping, &code, native_read, false);
    let read: unsafe extern "C" fn(u64, u64, u64) -> i64 =
        unsafe { core::mem::transmute(trampoline.address() as usize) };
    unsafe { write_pkru(denied) };
    let denied_result = unsafe { read(pipe[0] as u64, buffer as u64, 1) };
    let after_denied = unsafe { read_pkru() };
    unsafe { write_pkru(initial) };
    assert_eq!(denied_result, -i64::from(libc::EFAULT));
    assert_eq!(after_denied, denied);
    assert_eq!(unsafe { read(pipe[0] as u64, buffer as u64, 1) }, 1);
    assert_eq!(unsafe { core::ptr::read(buffer.cast::<u8>()) }, b'q');
    assert_descriptor(&trampoline);
    assert_eq!(DESCRIPTOR_MASK.load(Ordering::Relaxed) & PKRU, 0);
    NEXT_PKRU.store(denied, Ordering::Relaxed);
    call_void(&mapping, change_pkru, false);
    let exact = unsafe { read_pkru() };
    unsafe { write_pkru(initial) };
    assert_eq!(exact, denied);
    call_void(&mapping, change_pkru, true);
    let legacy = unsafe { read_pkru() };
    unsafe { write_pkru(initial) };
    assert_eq!(legacy, initial, "legacy full-state policy changed");
    assert_ne!(DESCRIPTOR_MASK.load(Ordering::Relaxed) & PKRU, 0);
    assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
    assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
    assert_eq!(unsafe { libc::munmap(buffer, PAGE) }, 0);
    assert_eq!(
        unsafe { raw_syscall(libc::SYS_pkey_free, key as u64, 0, 0) },
        0
    );
    println!(
        "CAPABILITY_EXECUTED PKRU key={key} denied-read=EFAULT allowed-read=1 exact={exact:#x} legacy={legacy:#x}"
    );
}

unsafe extern "C" fn signal_pkru(_: i32, _: *mut libc::siginfo_t, raw: *mut libc::c_void) {
    let context = unsafe { &mut *raw.cast::<libc::ucontext_t>() };
    let state = context.uc_mcontext.fpregs.cast::<u8>();
    let offset = SIGNAL_PKRU_OFFSET.load(Ordering::Relaxed);
    if state.is_null() || offset < 576 {
        SIGNAL_FRAME_STATUS.store(2, Ordering::Relaxed);
        return;
    }
    let magic = unsafe { core::ptr::read_unaligned(state.add(464).cast::<u32>()) };
    let bytes = unsafe { core::ptr::read_unaligned(state.add(480).cast::<u32>()) } as usize;
    let features = unsafe { core::ptr::read_unaligned(state.add(472).cast::<u64>()) };
    if magic != 0x4650_5853 || bytes < offset + 4 || features & PKRU == 0 {
        SIGNAL_FRAME_STATUS.store(3, Ordering::Relaxed);
        return;
    }
    let compact = unsafe { core::ptr::read_unaligned(state.add(520).cast::<u64>()) };
    if compact != 0 {
        SIGNAL_FRAME_STATUS.store(4, Ordering::Relaxed);
        return;
    }
    unsafe {
        core::ptr::write_unaligned(
            state.add(offset).cast::<u32>(),
            NEXT_PKRU.load(Ordering::Relaxed),
        );
        let present = state.add(512).cast::<u64>();
        core::ptr::write_unaligned(present, core::ptr::read_unaligned(present) | PKRU);
    }
    SIGNAL_FRAME_STATUS.store(1, Ordering::Relaxed);
}

unsafe extern "C" fn signal_during_callback(context: *mut HookContext) {
    unsafe { record_descriptor(&*context) };
    let pid = unsafe { raw_syscall(libc::SYS_getpid, 0, 0, 0) };
    let tid = unsafe { raw_syscall(libc::SYS_gettid, 0, 0, 0) };
    unsafe {
        (*context).rax = raw_syscall(
            libc::SYS_tgkill,
            pid as u64,
            tid as u64,
            libc::SIGUSR1 as u64,
        ) as u64
    };
}

fn signal_return_pkru() {
    let Some(key) = pkey() else {
        return;
    };
    let initial = unsafe { read_pkru() };
    let desired = initial | (3 << (key * 2));
    let geometry = cpuid(0xD, 9);
    assert!(geometry.ebx >= 576 && geometry.eax >= 4 && geometry.ecx & 1 == 0);
    SIGNAL_PKRU_OFFSET.store(geometry.ebx as usize, Ordering::Relaxed);
    NEXT_PKRU.store(desired, Ordering::Relaxed);
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = signal_pkru as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut old) },
        0
    );
    let mut unblock: libc::sigset_t = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { libc::sigemptyset(&mut unblock) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut unblock, libc::SIGUSR1) }, 0);
    assert_eq!(
        unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, core::ptr::null_mut()) },
        0
    );
    let mapping = SourceMapping::new(&[0x0f, 0x05, 0x90, 0x90, 0x90, 0xc3]);
    call_void(&mapping, signal_during_callback, false);
    let exact = unsafe { read_pkru() };
    unsafe { write_pkru(initial) };
    assert_eq!(
        SIGNAL_FRAME_STATUS.load(Ordering::Relaxed),
        1,
        "kernel frame was not changed"
    );
    assert_eq!(
        exact, desired,
        "XRSTOR erased the genuine sigreturn's live rights"
    );
    assert_eq!(DESCRIPTOR_MASK.load(Ordering::Relaxed) & PKRU, 0);
    SIGNAL_FRAME_STATUS.store(0, Ordering::Relaxed);
    call_void(&mapping, signal_during_callback, true);
    let legacy = unsafe { read_pkru() };
    unsafe { write_pkru(initial) };
    assert_eq!(SIGNAL_FRAME_STATUS.load(Ordering::Relaxed), 1);
    assert_eq!(legacy, initial, "legacy full-state policy changed");
    assert_ne!(DESCRIPTOR_MASK.load(Ordering::Relaxed) & PKRU, 0);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &old, core::ptr::null_mut()) },
        0
    );
    assert_eq!(
        unsafe { raw_syscall(libc::SYS_pkey_free, key as u64, 0, 0) },
        0
    );
    println!(
        "CAPABILITY_EXECUTED genuine-sigreturn-PKRU key={key} exact={exact:#x} legacy={legacy:#x}"
    );
}

fn isolated(test: &str, child: fn()) {
    const CHILD: &str = "LITEINST2_EXACT_SYSCALL_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        child();
        return;
    }
    let mut process = Command::new(std::env::current_exe().unwrap());
    process
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, test)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut process = process.spawn().unwrap();
    let total = Arc::new(AtomicUsize::new(0));
    let collect = |mut input: Box<dyn Read + Send>| {
        let total = total.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let n = input.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                let before = total.fetch_add(n, Ordering::Relaxed);
                let retained = n.min((64_usize * 1024).saturating_sub(before));
                bytes.extend_from_slice(&buffer[..retained]);
            }
            bytes
        })
    };
    let stdout = collect(Box::new(process.stdout.take().unwrap()));
    let stderr = collect(Box::new(process.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut breached = false;
    let status = loop {
        if let Some(status) = process.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline || total.load(Ordering::Relaxed) > 64 * 1024 {
            // This process group belongs only to this isolated fixture.
            unsafe { libc::kill(-(process.id() as i32), libc::SIGKILL) };
            breached = true;
            break process.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    print!("{}", String::from_utf8_lossy(&stdout));
    eprint!("{}", String::from_utf8_lossy(&stderr));
    assert!(
        !breached,
        "{test}: child exceeded wall/output bound; status={status}"
    );
    assert!(
        total.load(Ordering::Relaxed) <= 64 * 1024,
        "child output exceeded bound"
    );
    assert!(status.success(), "{test}: child failed: {status}");
}

#[test]
fn exact_execution_respects_denied_rights_and_retains_changed_pkru() {
    isolated(
        "exact_execution_respects_denied_rights_and_retains_changed_pkru",
        denied_and_changed_pkru,
    );
}

#[test]
fn exact_execution_retains_genuine_signal_return_pkru() {
    isolated(
        "exact_execution_retains_genuine_signal_return_pkru",
        signal_return_pkru,
    );
}
