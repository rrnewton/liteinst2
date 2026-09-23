#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Adjacent instruction windows must preserve one another's physical store tails.

use liteinst2::patcher::{
    JumpPatchPlan, LiveJumpPatch, PatchError, PatchStrategy, StalenessBudget,
};
use liteinst2::rapid::{RapidProbe, RapidToggleError, RapidTogglePlan};
use liteinst2::scanner::{InstructionScanner, ScanResult};
use liteinst2::trampoline::{HookCallback, HookContext, HookSite, InstalledHook};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const CHILD_ENV: &str = "LITEINST_CONCURRENT_OVERLAP_CHILD";
const BODY_COMPLETE: i32 = 102;
const CPUID_VALUE: u64 = 0x2233_4455;
const TSC_VALUE: u64 = 0x5566_7788_1122_3344;
static CALLS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static SITES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static BAD_CONTEXT: AtomicU64 = AtomicU64::new(0);

fn isolated(name: &str, cases: usize, executions: usize, body: fn() -> (usize, usize)) {
    if std::env::var(CHILD_ENV).as_deref() == Ok(name) {
        let (completed, executed) = body();
        println!("overlap-complete:{name}:cases={completed}:executions={executed}");
        std::io::stdout().flush().unwrap();
        // Only completing the actual body produces this exit status. A filter
        // selecting zero tests returns zero and cannot authenticate success.
        unsafe { libc::_exit(BODY_COMPLETE) };
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, name)
        .env("RUST_BACKTRACE", "0")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: this post-fork closure only changes a resource limit.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(10) {
            timed_out = true;
            // SAFETY: this test owns the live child's dedicated process group.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(65_537)
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .take(65_537)
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stdout.len() <= 65_536 && stderr.len() <= 65_536,
        "child output limit"
    );
    assert!(
        !timed_out && status.code() == Some(BODY_COMPLETE),
        "{name}: status={status}; timeout={timed_out}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let receipt = format!("overlap-complete:{name}:cases={cases}:executions={executions}");
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.ends_with(&receipt))
            .count(),
        1,
        "{stdout}"
    );
}

// These aliases intentionally remain mapped until the isolated process exits:
// Concurrent registrations and published trampolines have process lifetime.
struct Mapping {
    writable: *mut u8,
    executable: *mut u8,
}

impl Mapping {
    fn new(code: &[u8]) -> Self {
        assert!(code.len() <= PAGE);
        unsafe {
            let fd = libc::memfd_create(c"liteinst-overlap-test".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, PAGE as libc::off_t), 0);
            let writable = libc::mmap(
                ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            let executable = libc::mmap(
                ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(writable, libc::MAP_FAILED);
            assert_ne!(executable, libc::MAP_FAILED);
            assert_eq!(libc::close(fd), 0);
            ptr::copy_nonoverlapping(code.as_ptr(), writable.cast(), code.len());
            Self {
                writable: writable.cast(),
                executable: executable.cast(),
            }
        }
    }

    fn address(&self, offset: usize) -> u64 {
        assert!(offset < PAGE);
        unsafe { self.executable.add(offset) as u64 }
    }

    fn writable(&self, offset: usize) -> *mut u8 {
        assert!(offset < PAGE);
        unsafe { self.writable.add(offset) }
    }

    fn bytes(&self, len: usize) -> Vec<u8> {
        assert!(len <= PAGE);
        // Called only with all publishers stopped; this is not a racy oracle.
        unsafe { std::slice::from_raw_parts(self.executable, len).to_vec() }
    }

    fn write_byte(&self, offset: usize, byte: u8) {
        // Deliberate negative-control corruption with no executing reader or
        // publisher; tests restore it before resuming either.
        unsafe { self.writable(offset).write_volatile(byte) };
    }
}

fn budget() -> StalenessBudget {
    StalenessBudget::new(20_000).unwrap()
}

unsafe fn observe(context: *mut HookContext, index: usize) {
    let context = unsafe { &mut *context };
    if context.instruction_pointer != SITES[index].load(Ordering::Relaxed) {
        BAD_CONTEXT.fetch_add(1, Ordering::Relaxed);
    }
    CALLS[index].fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn observe_a(context: *mut HookContext) {
    unsafe { observe(context, 0) };
}

unsafe extern "C" fn observe_b(context: *mut HookContext) {
    unsafe { observe(context, 1) };
}

unsafe extern "C" fn replace_cpuid(context: *mut HookContext) {
    unsafe { observe(context, 0) };
    let context = unsafe { &mut *context };
    if context.rax != 7 || context.rcx != 0 {
        BAD_CONTEXT.fetch_add(1, Ordering::Relaxed);
    }
    context.rax = 0;
    context.rbx = CPUID_VALUE;
    context.rcx = 0;
    context.rdx = 0;
}

unsafe extern "C" fn replace_rdtsc(context: *mut HookContext) {
    unsafe { observe(context, 1) };
    let context = unsafe { &mut *context };
    context.rax = TSC_VALUE & 0xffff_ffff;
    context.rdx = TSC_VALUE >> 32;
}

struct Fixture {
    mapping: Mapping,
    code: Vec<u8>,
    scanner: InstructionScanner,
    scan: ScanResult,
    sites: [usize; 2],
    cpuid: bool,
}

impl Fixture {
    fn new(offset: usize, gap: usize, cpuid: bool) -> Self {
        assert!((5..=7).contains(&gap));
        let mut code = vec![0x90; 128];
        if cpuid {
            assert_eq!((offset, gap), (23, 5));
            // Preserve SysV's RBX/R12, prepare CPUID leaf 7, and retain the
            // exact forensic CPUID/XCHG/RDTSC/MOV bytes at offsets 23 and 28.
            code[..13].copy_from_slice(&[
                0x53, 0x41, 0x54, 0xb8, 7, 0, 0, 0, 0x31, 0xc9, 0x49, 0x89, 0xdc,
            ]);
            let tail = [
                0x0f, 0xa2, 0x4c, 0x87, 0xe3, 0x0f, 0x31, 0x49, 0x89, 0xd0, 0x49, 0xc1, 0xe0, 0x20,
                0x49, 0x09, 0xc0, // build full timestamp
                0x4c, 0x89, 0x27, // mov [rdi],r12 (CPUID EBX result)
                0x4c, 0x89, 0x47, 8, // mov [rdi+8],r8 (timestamp)
                0x41, 0x5c, 0x5b, 0xc3,
            ];
            code[offset..offset + tail.len()].copy_from_slice(&tail);
        } else {
            code[offset..offset + 5].copy_from_slice(&[0xb8, 11, 0, 0, 0]);
            code[offset + gap..offset + gap + 9]
                .copy_from_slice(&[0x83, 0xc0, 7, 0x90, 0x90, 0x48, 0x89, 0x07, 0xc3]);
        }
        let mapping = Mapping::new(&code);
        let scanner = InstructionScanner::default();
        let scan = scanner.scan(&code, mapping.address(0)).unwrap();
        Self {
            mapping,
            code,
            scanner,
            scan,
            sites: [offset, offset + gap],
            cpuid,
        }
    }

    fn install(&self, index: usize) -> InstalledHook {
        let address = self.mapping.address(self.sites[index]);
        let site = HookSite::new(
            &self.scanner,
            &self.scan,
            &self.code,
            self.mapping.address(0),
            address,
            self.mapping.writable(self.sites[index]),
        );
        let callback: HookCallback = match (self.cpuid, index) {
            (true, 0) => replace_cpuid,
            (true, 1) => replace_rdtsc,
            (false, 0) => observe_a,
            (false, 1) => observe_b,
            _ => unreachable!(),
        };
        // No control flow enters either five-byte displaced window's interior.
        // Aliases/callbacks outlive the process; snapshots describe original code.
        unsafe {
            if self.cpuid {
                InstalledHook::install_replacing_first(site, callback, budget())
            } else {
                InstalledHook::install(site, callback, budget())
            }
        }
        .unwrap_or_else(|error| panic!("bind neighbor {index} at {address:#x}: {error:?}"))
    }

    fn execute(&self, active: [bool; 2]) {
        let before = CALLS.each_ref().map(|count| count.load(Ordering::Relaxed));
        let mut result = [0_u64; 2];
        let entry = if self.cpuid { 0 } else { self.sites[0] };
        // Fixture saves callee-saved registers and writes exactly two u64s at
        // most through its sole argument. Mapping remains executable.
        let function: unsafe extern "C" fn(*mut u64) =
            unsafe { std::mem::transmute(self.mapping.address(entry) as usize) };
        unsafe { function(result.as_mut_ptr()) };
        for index in 0..2 {
            assert_eq!(
                CALLS[index].load(Ordering::Relaxed),
                before[index] + u64::from(active[index]),
                "callback {index}; active={active:?}"
            );
        }
        assert_eq!(BAD_CONTEXT.load(Ordering::Relaxed), 0);
        if self.cpuid {
            // CPUID is available on x86-64. The intrinsic is unsafe on our
            // Rust 1.85 MSRV and safe on newer compilers.
            #[allow(unused_unsafe)]
            let native_cpuid = unsafe { core::arch::x86_64::__cpuid_count(7, 0) }.ebx as u64;
            assert_eq!(
                result[0],
                if active[0] { CPUID_VALUE } else { native_cpuid }
            );
            if active[1] {
                assert_eq!(
                    result[1], TSC_VALUE,
                    "RDTSC replacement and relocated MOV/shift/or"
                );
            } else {
                assert_ne!(
                    result[1], 0,
                    "native RDTSC must execute while its hook is inactive"
                );
            }
        } else {
            assert_eq!(result, [18, 0], "original deterministic arithmetic changed");
        }
    }
}

fn redirect(address: u64, target: u64) -> [u8; 5] {
    let mut bytes = [0xe9, 0, 0, 0, 0];
    bytes[1..].copy_from_slice(
        &i32::try_from(i128::from(target) - i128::from(address + 5))
            .unwrap()
            .to_le_bytes(),
    );
    bytes
}

fn toggle(
    fixture: &Fixture,
    hook: &InstalledHook,
    index: usize,
    active: &mut [bool; 2],
    model: &mut [u8],
    enabled: bool,
) {
    let changed = if enabled {
        hook.activate()
    } else {
        hook.deactivate()
    }
    .unwrap();
    assert_eq!(changed, active[index] != enabled);
    active[index] = enabled;
    assert_eq!(hook.is_active(), enabled);
    let offset = fixture.sites[index];
    let bytes = if enabled {
        redirect(fixture.mapping.address(offset), hook.trampoline().address())
    } else {
        fixture.code[offset..offset + 5].try_into().unwrap()
    };
    model[offset..offset + 5].copy_from_slice(&bytes);
    assert_eq!(
        fixture.mapping.bytes(model.len()),
        model,
        "neighbor bytes/canaries changed"
    );
}

fn lifecycle(
    offset: usize,
    gap: usize,
    cpuid: bool,
    reverse: bool,
    first_already_active: bool,
) -> usize {
    let fixture = Fixture::new(offset, gap, cpuid);
    for index in 0..2 {
        CALLS[index].store(0, Ordering::Relaxed);
        SITES[index].store(
            fixture.mapping.address(fixture.sites[index]),
            Ordering::Relaxed,
        );
    }
    BAD_CONTEXT.store(0, Ordering::Relaxed);
    let order = if reverse { [1, 0] } else { [0, 1] };
    let mut hooks = [None, None];
    let mut active = [false; 2];
    let mut model = fixture.code.clone();
    hooks[order[0]] = Some(fixture.install(order[0]));
    if first_already_active {
        toggle(
            &fixture,
            hooks[order[0]].as_ref().unwrap(),
            order[0],
            &mut active,
            &mut model,
            true,
        );
    }
    hooks[order[1]] = Some(fixture.install(order[1]));
    assert_eq!(
        fixture.mapping.bytes(model.len()),
        model,
        "binding changed code"
    );
    fixture.execute(active);
    let mut executions = 1;
    for (index, enabled) in [
        (order[0], true),
        (order[1], true),
        (order[0], false),
        (order[0], true),
        (order[1], false),
        (order[1], true),
        (order[0], false),
        (order[1], false),
    ] {
        toggle(
            &fixture,
            hooks[index].as_ref().unwrap(),
            index,
            &mut active,
            &mut model,
            enabled,
        );
        fixture.execute(active);
        executions += 1;
    }
    assert_eq!(executions, 9);
    assert_eq!(fixture.mapping.bytes(fixture.code.len()), fixture.code);
    executions
}

#[test]
fn cpuid_rdtsc_atomic_neighbors_preserve_both_hooks() {
    isolated(
        "cpuid_rdtsc_atomic_neighbors_preserve_both_hooks",
        4,
        36,
        || {
            let mut cases = 0;
            let mut executions = 0;
            for reverse in [false, true] {
                for late in [false, true] {
                    executions += lifecycle(23, 5, true, reverse, late);
                    cases += 1;
                }
            }
            (cases, executions)
        },
    );
}

#[test]
fn atomic_neighbors_gaps_and_line_edges_preserve_each_state() {
    isolated(
        "atomic_neighbors_gaps_and_line_edges_preserve_each_state",
        36,
        324,
        || {
            let mut cases = 0;
            let mut executions = 0;
            for gap in [5, 6, 7] {
                for offset in [0, 23, 56 - gap] {
                    for reverse in [false, true] {
                        for late in [false, true] {
                            executions += lifecycle(offset, gap, false, reverse, late);
                            cases += 1;
                        }
                    }
                }
            }
            (cases, executions)
        },
    );
}

fn plan(mapping: &Mapping, code: &[u8], offset: usize, target: usize) -> JumpPatchPlan {
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(code, mapping.address(0)).unwrap();
    JumpPatchPlan::from_scan(
        &scanner,
        &scan,
        code,
        mapping.address(0),
        mapping.address(offset),
        mapping.address(target),
    )
    .unwrap()
}

fn bind(mapping: &Mapping, code: &[u8], offset: usize, target: usize) -> LiveJumpPatch {
    unsafe {
        LiveJumpPatch::bind(
            plan(mapping, code, offset, target),
            mapping.writable(offset),
            budget(),
        )
    }
    .unwrap()
}

#[test]
fn unexplained_neighbor_and_unowned_tail_bytes_are_refused() {
    isolated(
        "unexplained_neighbor_and_unowned_tail_bytes_are_refused",
        24,
        0,
        || {
            let code = vec![0x90; 128];
            let mapping = Mapping::new(&code);
            let a = bind(&mapping, &code, 23, 96);
            let b = bind(&mapping, &code, 28, 104);
            let mut cases = 0;
            for offset in 23..31 {
                // Cover every owned byte and every inactive-neighbor tail byte.
                mapping.write_byte(offset, code[offset] ^ 1);
                let corrupted = mapping.bytes(code.len());
                assert!(
                    matches!(unsafe { a.apply() }, Err(PatchError::ExpectedBytesMismatch)),
                    "inactive offset={offset}"
                );
                assert_eq!(mapping.bytes(code.len()), corrupted);
                mapping.write_byte(offset, code[offset]);
                unsafe {
                    a.apply().unwrap();
                    a.revert().unwrap();
                }
                assert_eq!(mapping.bytes(code.len()), code);
                cases += 1;
            }

            unsafe {
                a.apply().unwrap();
                b.apply().unwrap();
            }
            let committed = mapping.bytes(code.len());
            for offset in 23..31 {
                // Cover every owned byte and every active-neighbor jump byte.
                mapping.write_byte(offset, committed[offset] ^ 1);
                let corrupted = mapping.bytes(code.len());
                assert!(
                    matches!(
                        unsafe { a.revert() },
                        Err(PatchError::ExpectedBytesMismatch)
                    ),
                    "active offset={offset}"
                );
                assert_eq!(mapping.bytes(code.len()), corrupted);
                mapping.write_byte(offset, committed[offset]);
                unsafe {
                    a.revert().unwrap();
                    a.apply().unwrap();
                }
                assert_eq!(mapping.bytes(code.len()), committed);
                cases += 1;
            }
            unsafe {
                a.revert().unwrap();
                b.revert().unwrap();
            }
            assert_eq!(mapping.bytes(code.len()), code);
            for offset in 28..36 {
                // Includes B's three trailing physical bytes owned by neither
                // logical jump; neighbor normalization must not excuse them.
                mapping.write_byte(offset, code[offset] ^ 1);
                let corrupted = mapping.bytes(code.len());
                assert!(
                    matches!(unsafe { b.apply() }, Err(PatchError::ExpectedBytesMismatch)),
                    "unowned-tail offset={offset}"
                );
                assert_eq!(mapping.bytes(code.len()), corrupted);
                mapping.write_byte(offset, code[offset]);
                unsafe {
                    b.apply().unwrap();
                    b.revert().unwrap();
                }
                assert_eq!(mapping.bytes(code.len()), code);
                cases += 1;
            }
            (cases, 0)
        },
    );
}

#[test]
fn live_neighbor_snapshot_is_normalized_and_mixed_snapshots_are_refused() {
    isolated(
        "live_neighbor_snapshot_is_normalized_and_mixed_snapshots_are_refused",
        5,
        0,
        || {
            let code = vec![0x90; 128];
            let mapping = Mapping::new(&code);
            let upper = bind(&mapping, &code, 28, 104);
            unsafe { upper.apply().unwrap() };
            let live = mapping.bytes(code.len());
            let lower = bind(&mapping, &live, 23, 96);
            assert_eq!(mapping.bytes(code.len()), live);
            unsafe {
                upper.revert().unwrap();
                lower.apply().unwrap();
            }
            let mut expected = code.clone();
            expected[23..28].copy_from_slice(&redirect(mapping.address(23), mapping.address(96)));
            assert_eq!(
                mapping.bytes(code.len()),
                expected,
                "bind-time active neighbor leaked into later publication"
            );
            unsafe {
                lower.revert().unwrap();
                upper.apply().unwrap();
                lower.apply().unwrap();
                upper.revert().unwrap();
            }
            assert_eq!(mapping.bytes(code.len()), expected);
            unsafe { lower.revert().unwrap() };
            assert_eq!(mapping.bytes(code.len()), code);
            let mut cases = 1;
            for changed in [Some(28), Some(29), Some(30), None] {
                let mapping = Mapping::new(&code);
                let upper = bind(&mapping, &code, 28, 104);
                unsafe { upper.apply().unwrap() };
                let live = mapping.bytes(code.len());
                let mut snapshot = live.clone();
                if let Some(offset) = changed {
                    snapshot[offset] ^= 1;
                } else {
                    // Neither complete canonical bytes nor complete current bytes.
                    snapshot[29] = code[29];
                }
                let candidate = plan(&mapping, &snapshot, 23, 96);
                let result =
                    unsafe { LiveJumpPatch::bind(candidate, mapping.writable(23), budget()) };
                assert!(
                    matches!(result, Err(PatchError::OverlappingPatchSite)),
                    "snapshot corruption={changed:?}"
                );
                assert_eq!(
                    mapping.bytes(code.len()),
                    live,
                    "rejected binding modified the active neighbor"
                );
                unsafe { upper.revert().unwrap() };
                assert_eq!(mapping.bytes(code.len()), code);
                cases += 1;
            }
            (cases, 0)
        },
    );
}

fn reserve_rapid_target(site: u64) -> *mut libc::c_void {
    // A just-unmapped default mmap allocation can be reused for the
    // trampoline's writable alias before its fixed RX allocation. Reserve a
    // deliberately distant rel32 page, as the existing rapid stress fixture
    // does, so the refusal control reaches registration rather than ENOMEM.
    let page = site as usize & !(PAGE - 1);
    for distance in [0x1000_0000_usize, 0x2000_0000, 0x3000_0000] {
        for address in [page.checked_add(distance), page.checked_sub(distance)]
            .into_iter()
            .flatten()
        {
            let target = unsafe {
                libc::mmap(
                    address as *mut _,
                    PAGE,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            if target != libc::MAP_FAILED {
                assert_eq!(target as usize, address);
                return target;
            }
        }
    }
    panic!("no rel32 reservation for Rapid overlap control");
}

#[test]
fn displaced_window_and_guarded_split_overlaps_are_refused() {
    isolated(
        "displaced_window_and_guarded_split_overlaps_are_refused",
        4,
        0,
        || {
            let mut cases = 0;
            for (first, second) in [(23, 27), (27, 23), (55, 60), (60, 55)] {
                let code = vec![0x90; 128];
                let mapping = Mapping::new(&code);
                let _first = bind(&mapping, &code, first, 96);
                let second_plan = plan(&mapping, &code, second, 104);
                if second == 60 {
                    assert!(matches!(
                        second_plan.strategy(),
                        PatchStrategy::GuardedSplit { .. }
                    ));
                }
                let result =
                    unsafe { LiveJumpPatch::bind(second_plan, mapping.writable(second), budget()) };
                assert!(
                    matches!(result, Err(PatchError::OverlappingPatchSite)),
                    "first={first} second={second}"
                );
                assert_eq!(mapping.bytes(code.len()), code);
                cases += 1;
            }
            (cases, 0)
        },
    );
}

#[test]
fn rapid_and_atomic_word_neighbors_still_refuse_overlap() {
    isolated(
        "rapid_and_atomic_word_neighbors_still_refuse_overlap",
        2,
        0,
        || {
            let mut cases = 0;
            for rapid_first in [false, true] {
                let mut code = vec![0x90; 128];
                let mapping = Mapping::new(&code);
                // Reserve then release a nearby exact destination for the rapid
                // instruction pun. No other test runs in this isolated process.
                let target = reserve_rapid_target(mapping.address(28));
                let displacement =
                    i32::try_from(target as i128 + 128 - i128::from(mapping.address(33))).unwrap();
                code[28] = 0xb8;
                code[29..33].copy_from_slice(&displacement.to_le_bytes());
                unsafe { ptr::copy_nonoverlapping(code.as_ptr(), mapping.writable(0), code.len()) };
                let scanner = InstructionScanner::default();
                let scan = scanner.scan(&code, mapping.address(0)).unwrap();
                let rapid = RapidTogglePlan::from_scan(
                    &scanner,
                    &scan,
                    &code,
                    mapping.address(0),
                    mapping.address(28),
                    observe_b,
                )
                .unwrap();
                assert_eq!(unsafe { libc::munmap(target, PAGE) }, 0);
                if rapid_first {
                    let _rapid =
                        unsafe { RapidProbe::install(rapid, mapping.writable(28)) }.unwrap();
                    let result = unsafe {
                        LiveJumpPatch::bind(
                            plan(&mapping, &code, 23, 96),
                            mapping.writable(23),
                            budget(),
                        )
                    };
                    assert!(matches!(result, Err(PatchError::OverlappingPatchSite)));
                } else {
                    let _atomic = bind(&mapping, &code, 23, 96);
                    let result = unsafe { RapidProbe::install(rapid, mapping.writable(28)) };
                    assert!(matches!(
                        result,
                        Err(RapidToggleError::OverlappingPatchSite)
                    ));
                }
                assert_eq!(mapping.bytes(code.len()), code);
                cases += 1;
            }
            (cases, 0)
        },
    );
}

#[test]
fn concurrent_handles_keep_neighbor_state_across_quiescent_calls() {
    isolated(
        "concurrent_handles_keep_neighbor_state_across_quiescent_calls",
        2,
        0,
        || {
            let mut cases = 0;
            for reverse in [false, true] {
                let code = vec![0x90; 128];
                let mapping = Mapping::new(&code);
                let a = bind(&mapping, &code, 23, 96);
                let b = bind(&mapping, &code, 28, 104);
                let hooks = if reverse { [&b, &a] } else { [&a, &b] };
                // Actual exclusion: no reader or other code writer exists here.
                unsafe {
                    hooks[0].apply_quiescent().unwrap();
                    hooks[1].apply().unwrap();
                }
                let both = mapping.bytes(code.len());
                assert_eq!(
                    &both[23..28],
                    &redirect(mapping.address(23), mapping.address(96))
                );
                assert_eq!(
                    &both[28..33],
                    &redirect(mapping.address(28), mapping.address(104))
                );
                unsafe {
                    hooks[0].revert_quiescent().unwrap();
                    hooks[0].apply().unwrap();
                }
                assert_eq!(mapping.bytes(code.len()), both);
                unsafe {
                    hooks[1].revert_quiescent().unwrap();
                    hooks[0].revert().unwrap();
                }
                assert_eq!(mapping.bytes(code.len()), code);
                cases += 1;
            }
            (cases, 0)
        },
    );
}

#[test]
fn explicit_quiescent_binding_retains_strict_snapshot_contract() {
    isolated(
        "explicit_quiescent_binding_retains_strict_snapshot_contract",
        1,
        0,
        || {
            let code = vec![0x90; 128];
            let mapping = Mapping::new(&code);
            let a = unsafe {
                LiveJumpPatch::bind_quiescent(plan(&mapping, &code, 23, 96), mapping.writable(23))
            }
            .unwrap();
            let b = unsafe {
                LiveJumpPatch::bind_quiescent(plan(&mapping, &code, 28, 104), mapping.writable(28))
            }
            .unwrap();
            unsafe {
                a.apply_quiescent().unwrap();
                b.apply_quiescent().unwrap();
            }
            let before = mapping.bytes(code.len());
            assert!(matches!(
                unsafe { a.revert_quiescent() },
                Err(PatchError::ExpectedBytesMismatch)
            ));
            assert_eq!(mapping.bytes(code.len()), before);
            unsafe {
                b.revert_quiescent().unwrap();
                a.revert_quiescent().unwrap();
            }
            assert_eq!(mapping.bytes(code.len()), code);
            (1, 0)
        },
    );
}

#[test]
fn active_e9_rebind_preserves_nested_redirect_and_original_interval() {
    isolated(
        "active_e9_rebind_preserves_nested_redirect_and_original_interval",
        2,
        0,
        || {
            let mut code = vec![0x90; 128];
            // A six-byte displaced interval, longer than the replacement jump.
            code[23..29].copy_from_slice(&[0x90, 0xb8, 11, 0, 0, 0]);
            let mapping = Mapping::new(&code);
            let first_plan = plan(&mapping, &code, 23, 96);
            assert_eq!(first_plan.displaced_len(), 6);
            let first =
                unsafe { LiveJumpPatch::bind(first_plan, mapping.writable(23), budget()) }.unwrap();
            unsafe { first.apply().unwrap() };
            let active = mapping.bytes(code.len());
            let replacement = plan(&mapping, &active, 23, 104);
            assert_eq!(replacement.displaced_len(), 5);
            let second =
                unsafe { LiveJumpPatch::bind(replacement, mapping.writable(23), budget()) }
                    .unwrap();
            assert_eq!(mapping.bytes(code.len()), active);
            // The visible E9 is five bytes, but rebinding must retain the original
            // six-byte displaced interval. Offset 28 is now a decoded head in the
            // active snapshot, yet remains owned by the original instruction.
            let interior = plan(&mapping, &active, 28, 112);
            let conflict = unsafe { LiveJumpPatch::bind(interior, mapping.writable(28), budget()) };
            assert!(matches!(conflict, Err(PatchError::OverlappingPatchSite)));
            assert_eq!(mapping.bytes(code.len()), active);
            unsafe { second.apply().unwrap() };
            let nested = mapping.bytes(code.len());
            assert_eq!(
                &nested[23..28],
                &redirect(mapping.address(23), mapping.address(104))
            );
            assert!(matches!(
                unsafe { first.revert() },
                Err(PatchError::ExpectedBytesMismatch)
            ));
            assert_eq!(mapping.bytes(code.len()), nested);
            unsafe { second.revert().unwrap() };
            assert_eq!(mapping.bytes(code.len()), active);
            unsafe { first.revert().unwrap() };
            assert_eq!(mapping.bytes(code.len()), code);
            (2, 0)
        },
    );
}

#[test]
fn preplanned_e9_redirect_requires_its_expected_first_bytes() {
    isolated(
        "preplanned_e9_redirect_requires_its_expected_first_bytes",
        1,
        0,
        || {
            let mut code = vec![0x90; 128];
            code[23..29].copy_from_slice(&[0x90, 0xb8, 11, 0, 0, 0]);
            let mapping = Mapping::new(&code);
            let first = bind(&mapping, &code, 23, 96);
            let mut planned_active = code.clone();
            planned_active[23..28]
                .copy_from_slice(&redirect(mapping.address(23), mapping.address(96)));
            // Planning ahead is supported: binding need not find the first E9
            // live yet, but publication must still require its exact expected head.
            let second = bind(&mapping, &planned_active, 23, 104);
            assert!(matches!(
                unsafe { second.apply() },
                Err(PatchError::ExpectedBytesMismatch)
            ));
            assert_eq!(mapping.bytes(code.len()), code);
            unsafe {
                first.apply().unwrap();
                second.apply().unwrap();
            }
            let mut nested = planned_active.clone();
            nested[23..28].copy_from_slice(&redirect(mapping.address(23), mapping.address(104)));
            assert_eq!(mapping.bytes(code.len()), nested);
            assert!(matches!(
                unsafe { first.revert() },
                Err(PatchError::ExpectedBytesMismatch)
            ));
            assert_eq!(mapping.bytes(code.len()), nested);
            unsafe { second.revert().unwrap() };
            assert_eq!(mapping.bytes(code.len()), planned_active);
            unsafe { first.revert().unwrap() };
            assert_eq!(mapping.bytes(code.len()), code);
            (1, 0)
        },
    );
}

#[test]
fn later_neighbor_cannot_authenticate_an_existing_stale_tail() {
    isolated(
        "later_neighbor_cannot_authenticate_an_existing_stale_tail",
        1,
        0,
        || {
            let code = vec![0x90; 128];
            let mapping = Mapping::new(&code);
            let canonical = bind(&mapping, &code, 23, 96);
            let mut stale = code.clone();
            stale[30] ^= 1;
            let stale_handle = bind(&mapping, &stale, 23, 104);
            // This neighbor did not exist when the stale handle was bound. Its
            // authenticated current bytes must not retroactively excuse that
            // handle's unrelated original-byte mismatch.
            let neighbor = bind(&mapping, &code, 28, 112);
            assert!(matches!(
                unsafe { stale_handle.apply() },
                Err(PatchError::ExpectedBytesMismatch)
            ));
            assert_eq!(mapping.bytes(code.len()), code);
            unsafe {
                canonical.apply().unwrap();
                neighbor.apply().unwrap();
            }
            let mut expected = code.clone();
            expected[23..28].copy_from_slice(&redirect(mapping.address(23), mapping.address(96)));
            expected[28..33].copy_from_slice(&redirect(mapping.address(28), mapping.address(112)));
            assert_eq!(mapping.bytes(code.len()), expected);
            unsafe { canonical.revert().unwrap() };
            expected[23..28].copy_from_slice(&code[23..28]);
            assert_eq!(mapping.bytes(code.len()), expected);
            unsafe { neighbor.revert().unwrap() };
            assert_eq!(mapping.bytes(code.len()), code);
            (1, 0)
        },
    );
}
