//! Fresh-process lazypoline (slice 5) test.
//!
//! The child installs the SUD discovery substrate in lazypoline mode, traps
//! two fixture sites from a registered worker thread, applies certified
//! patches for one of them from the unregistered installing thread, and then
//! proves whichever disposition the host allows, completely:
//!
//! - VA-0-capable host: the certified site is rewritten (`ff d0`), later
//!   executions take the gateway fast path with no new guest trap, and the
//!   uncertified site keeps re-trapping (`LAZYPOLINE_REWRITTEN`).
//! - Low-page-denied host: the apply is ledgered as `Trap` under the default
//!   trap fallback, bytes stay `0f 05`, and later executions keep trapping
//!   and forwarding exactly once (`LAZYPOLINE_TRAP_SERVED`).
//!
//! An install-time environment refusal exits 42 by name. A second child
//! proves the strict-refuse validation: a certificate whose syscall number
//! disagrees with the trapped observation is refused before any write.
#![deny(unsafe_op_in_unsafe_fn)]

use liteinst::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    QuiescenceLease, ResumeObligation, SourceIdentity,
};
use liteinst_inprocess::syscall::sud::{LazyPatchState, SudInstallation};
use liteinst_inprocess::syscall::zpoline::ZpolineSite;
use liteinst_inprocess::syscall::{
    DiscoverySubstrate, FallbackPolicy, SiteOutcome, SyscallRefusal, SyscallStrategy,
    SyscallStrategyConfig,
};
use std::ffi::c_void;
use std::process::Command;

const CHILD_ENV: &str = "LITEINST_LAZY_CHILD";
const REFUSE_ENV: &str = "LITEINST_LAZY_REFUSE_CHILD";
static POSITIVE_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
const CODE: [u8; 6] = [0x0f, 0x05, 0xc3, 0x0f, 0x05, 0xc3];

core::arch::global_asm!(
    r#"
    .global lazy_probe_invoke
    .type lazy_probe_invoke, @function
lazy_probe_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsi
    mov r15, rdi
    mov qword ptr [rbx], rsp
    mov rdi, qword ptr [rbx + 104]
    mov rsi, qword ptr [rbx + 112]
    mov rdx, qword ptr [rbx + 120]
    mov r10, qword ptr [rbx + 128]
    mov r8, qword ptr [rbx + 136]
    mov r9, qword ptr [rbx + 144]
    mov eax, dword ptr [rbx + 96]
    mov ecx, 14
    cmp edi, edi
    call r15
    mov qword ptr [rbx + 8], rsp
    mov qword ptr [rbx + 16], rax
    mov qword ptr [rbx + 24], rcx
    mov qword ptr [rbx + 32], r11
    pushfq
    pop rax
    mov qword ptr [rbx + 40], rax
    mov qword ptr [rbx + 48], rdi
    mov qword ptr [rbx + 56], rsi
    mov qword ptr [rbx + 64], rdx
    mov qword ptr [rbx + 72], r10
    mov qword ptr [rbx + 80], r8
    mov qword ptr [rbx + 88], r9
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
"#
);

unsafe extern "C" {
    fn lazy_probe_invoke(entry: usize, state: *mut u64);
}

struct Region {
    address: *mut u8,
    len: usize,
}

impl Region {
    fn new(page: usize) -> Self {
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        let address = raw.cast::<u8>();
        unsafe { std::ptr::copy_nonoverlapping(CODE.as_ptr(), address, CODE.len()) };
        let region = Self { address, len: page };
        region.permissions(libc::PROT_READ | libc::PROT_EXEC);
        region
    }
    fn permissions(&self, flags: i32) {
        assert_eq!(
            unsafe { libc::mprotect(self.address.cast::<c_void>(), self.len, flags) },
            0
        );
    }
    fn bytes(&self) -> [u8; CODE.len()] {
        unsafe { std::ptr::read(self.address.cast::<[u8; CODE.len()]>()) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.address.cast::<c_void>(), self.len) };
    }
}

fn invoke(entry: usize, nr: u32) -> [u64; 19] {
    let mut state = [0_u64; 19];
    state[12] = u64::from(nr);
    unsafe { lazy_probe_invoke(entry, state.as_mut_ptr()) };
    state
}

fn check(state: [u64; 19], entry: usize, expected: u64) {
    assert_eq!(state[0], state[1], "rsp round-trip");
    assert_eq!(state[2], expected, "syscall result");
    assert_eq!(state[3], entry as u64 + 2, "RCX");
    assert_eq!(state[4], state[5], "R11/flags");
}

fn lazy_config(fallback: FallbackPolicy) -> SyscallStrategyConfig {
    SyscallStrategyConfig::new(SyscallStrategy::Lazypoline)
        .with_discovery(DiscoverySubstrate::Sud)
        .unwrap()
        .with_fallback(fallback)
        .unwrap()
        .with_max_sites(16)
        .unwrap()
        .with_placement(
            liteinst_inprocess::syscall::PlacementBudget::new(256, 16, 1_048_576).unwrap(),
        )
        .unwrap()
}

/// Runs `calls` fixture invocations on a fresh registered worker thread and
/// returns their checked results. The thread unregisters before joining.
fn run_registered(installation: &SudInstallation, calls: &[(usize, u64)]) {
    let installation_addr = (installation as *const SudInstallation) as usize;
    let calls: Vec<(usize, u64)> = calls.to_vec();
    let worker = std::thread::spawn(move || {
        // SAFETY: the installing thread retains the installation and joins
        // this thread before any uninstall or patch application.
        let installation = unsafe { &*(installation_addr as *const SudInstallation) };
        let registration = installation.register_current_thread().unwrap();
        POSITIVE_STARTED.store(true, std::sync::atomic::Ordering::Release);
        for &(entry, expected) in &calls {
            check(invoke(entry, libc::SYS_getpid as u32), entry, expected);
        }
        registration.unregister().unwrap();
    });
    worker.join().unwrap();
}

fn child_main() -> Result<(), SyscallRefusal> {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let mut region = Region::new(page);
    let base = region.address as usize;
    let site_a = base;
    let site_b = base + 3;
    let pid = u64::try_from(unsafe { libc::getpid() }).unwrap();

    // Native oracle before registration.
    check(invoke(site_a, libc::SYS_getpid as u32), site_a, pid);

    let mut installation = SudInstallation::install(lazy_config(FallbackPolicy::Trap))?;
    run_registered(
        &installation,
        &[(site_a, pid), (site_a, pid), (site_b, pid)],
    );

    let counters = installation.counters();
    assert_eq!((counters.traps, counters.forwarded), (3, 3), "{counters:?}");
    assert_eq!(counters.pending_patches, 2, "{counters:?}");
    let lazy = installation.lazy_sites();
    assert_eq!(lazy.len(), 2, "{lazy:?}");
    assert_eq!(lazy[0].site_pc, site_a as u64);
    assert_eq!(lazy[0].hits, 2);
    assert_eq!(lazy[0].patch_state, LazyPatchState::Pending);
    assert_eq!(lazy[1].site_pc, site_b as u64);
    assert_eq!(lazy[1].hits, 1);
    assert_eq!(lazy[1].patch_state, LazyPatchState::Pending);

    let identity = CodeIdentity {
        source: SourceIdentity([0x6e; 32]),
        mapping: base as u64,
        generation: 1,
    };
    let source_range = AddressRange::new(base as u64, CODE.len()).unwrap();
    let entries = LegalEntrySet {
        identity,
        scope: source_range,
        provenance: EntryProvenance::Declared("lazypoline probe two getpid sites".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![
            LegalEntry {
                address: site_a as u64,
                requires_endbr: false,
            },
            LegalEntry {
                address: site_b as u64,
                requires_endbr: false,
            },
        ],
        resumes: ResumeObligation::NoneExist,
    };
    let cert = ZpolineSite {
        config: lazy_config(FallbackPolicy::Trap),
        identity,
        code: &CODE,
        base_address: base as u64,
        logical_pc: site_a as u64,
        entries: &entries,
        syscall_nr: libc::SYS_getpid as u32,
    };

    region.permissions(libc::PROT_READ | libc::PROT_WRITE);
    let address = region.address;
    let len = region.len;
    let mut lease = unsafe { QuiescenceLease::new(&mut region, identity, vec![source_range]) };
    let report = unsafe {
        installation.apply_pending_patches(vec![cert], address, &mut lease, || {
            if libc::mprotect(
                address.cast::<c_void>(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            ) == 0
            {
                Ok(())
            } else {
                Err(SyscallRefusal::AllocationUnavailable)
            }
        })
    }
    .expect("trap-fallback apply must succeed with ledgered outcomes");
    assert_eq!(report.outcomes.len(), 1, "{:?}", report.outcomes);
    let outcome = report.outcomes[0].1;

    region.permissions(libc::PROT_READ | libc::PROT_EXEC);
    let rewritten = outcome == SiteOutcome::RewrittenLazypoline;
    if rewritten {
        assert_eq!(region.bytes(), [0xff, 0xd0, 0xc3, 0x0f, 0x05, 0xc3]);
        let before = installation.counters();
        run_registered(&installation, &[(site_a, pid)]);
        let after = installation.counters();
        assert_eq!(after.traps, before.traps, "patched site must not re-trap");
        assert_eq!(after.fast_path_calls, before.fast_path_calls + 1);
        // The uncertified site discovered before the batch still re-traps.
        run_registered(&installation, &[(site_b, pid)]);
        assert_eq!(installation.counters().traps, before.traps + 1);

        // Retire restores the original bytes and the site traps again.
        region.permissions(libc::PROT_READ | libc::PROT_WRITE);
        let mut lease = unsafe { QuiescenceLease::new(&mut region, identity, vec![source_range]) };
        unsafe {
            installation.retire_lazy_batch(address, &mut lease, || {
                if libc::mprotect(
                    address.cast::<c_void>(),
                    len,
                    libc::PROT_READ | libc::PROT_EXEC,
                ) == 0
                {
                    Ok(())
                } else {
                    Err(SyscallRefusal::AllocationUnavailable)
                }
            })
        }
        .expect("retire must restore the batch");
        assert_eq!(region.bytes(), CODE);
        let before = installation.counters();
        run_registered(&installation, &[(site_a, pid)]);
        assert_eq!(installation.counters().traps, before.traps + 1);
        println!("LAZYPOLINE_REWRITTEN pid={pid}");
    } else {
        assert_eq!(outcome, SiteOutcome::Trap, "{:?}", report.outcomes);
        assert_eq!(region.bytes(), CODE);
        let lazy = installation.lazy_sites();
        assert_eq!(lazy[0].patch_state, LazyPatchState::TrapPermanent);
        assert_eq!(lazy[1].patch_state, LazyPatchState::Pending);
        let before = installation.counters();
        run_registered(&installation, &[(site_a, pid)]);
        let after = installation.counters();
        assert_eq!(
            (after.traps, after.forwarded),
            (before.traps + 1, before.forwarded + 1)
        );
        assert_eq!(after.fast_path_calls, 0);
        println!("LAZYPOLINE_TRAP_SERVED pid={pid}");
    }

    installation.uninstall()?;
    check(invoke(site_a, libc::SYS_getpid as u32), site_a, pid);
    Ok(())
}

fn refuse_child_main() -> Result<(), SyscallRefusal> {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let mut region = Region::new(page);
    let base = region.address as usize;
    let pid = u64::try_from(unsafe { libc::getpid() }).unwrap();
    let mut installation = SudInstallation::install(lazy_config(FallbackPolicy::Refuse))?;
    run_registered(&installation, &[(base, pid)]);
    assert_eq!(installation.counters().pending_patches, 1);

    let identity = CodeIdentity {
        source: SourceIdentity([0x6e; 32]),
        mapping: base as u64,
        generation: 1,
    };
    let source_range = AddressRange::new(base as u64, CODE.len()).unwrap();
    let entries = LegalEntrySet {
        identity,
        scope: source_range,
        provenance: EntryProvenance::Declared("lazypoline refuse probe".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![
            LegalEntry {
                address: base as u64,
                requires_endbr: false,
            },
            LegalEntry {
                address: base as u64 + 3,
                requires_endbr: false,
            },
        ],
        resumes: ResumeObligation::NoneExist,
    };
    // The trap observed getpid; certifying gettid must refuse by name.
    let cert = ZpolineSite {
        config: lazy_config(FallbackPolicy::Refuse),
        identity,
        code: &CODE,
        base_address: base as u64,
        logical_pc: base as u64,
        entries: &entries,
        syscall_nr: libc::SYS_gettid as u32,
    };
    region.permissions(libc::PROT_READ | libc::PROT_WRITE);
    let address = region.address;
    let len = region.len;
    let mut lease = unsafe { QuiescenceLease::new(&mut region, identity, vec![source_range]) };
    let result = unsafe {
        installation.apply_pending_patches(vec![cert], address, &mut lease, || {
            if libc::mprotect(
                address.cast::<c_void>(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            ) == 0
            {
                Ok(())
            } else {
                Err(SyscallRefusal::AllocationUnavailable)
            }
        })
    };
    assert_eq!(
        result.unwrap_err(),
        SyscallRefusal::SyscallNumberRangeUnproven
    );
    assert_eq!(region.bytes(), CODE);
    assert_eq!(
        installation.lazy_sites()[0].patch_state,
        LazyPatchState::Pending
    );
    region.permissions(libc::PROT_READ | libc::PROT_EXEC);
    installation.uninstall()?;
    println!("LAZYPOLINE_REFUSE_OK");
    Ok(())
}

fn run_child(env: &str, test: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .env(env, "1")
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .output()
        .unwrap()
}

fn is_named_refusal(output: &std::process::Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let text = format!("{stderr}{stdout}");
    [
        "SudUnavailable",
        "SignalContract",
        "CetUnsupported",
        "StrategyUnavailableOnArch",
    ]
    .iter()
    .any(|name| text.contains(name))
}

#[test]
fn lazypoline_positive_or_named_environment_refusal() {
    if std::env::var_os(CHILD_ENV).is_some() {
        match child_main() {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                if POSITIVE_STARTED.load(std::sync::atomic::Ordering::Acquire) {
                    panic!("positive path failed after registration: {error:?}");
                }
                eprintln!("LAZYPOLINE_ENV_REFUSAL {error:?}");
                std::process::exit(42);
            }
        }
    }
    let output = run_child(
        CHILD_ENV,
        "lazypoline_positive_or_named_environment_refusal",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.code() == Some(42) {
        assert!(is_named_refusal(&output), "unnamed refusal: {output:?}");
        return;
    }
    assert!(output.status.success(), "child failed: {output:?}");
    assert!(
        stdout.contains("LAZYPOLINE_REWRITTEN") || stdout.contains("LAZYPOLINE_TRAP_SERVED"),
        "missing disposition marker: {stdout}"
    );
}

#[test]
fn lazypoline_certificate_mismatch_refuses_before_write() {
    if std::env::var_os(REFUSE_ENV).is_some() {
        match refuse_child_main() {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                if POSITIVE_STARTED.load(std::sync::atomic::Ordering::Acquire) {
                    panic!("refuse path failed after registration: {error:?}");
                }
                eprintln!("LAZYPOLINE_ENV_REFUSAL {error:?}");
                std::process::exit(42);
            }
        }
    }
    let output = run_child(
        REFUSE_ENV,
        "lazypoline_certificate_mismatch_refuses_before_write",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.code() == Some(42) {
        assert!(is_named_refusal(&output), "unnamed refusal: {output:?}");
        return;
    }
    assert!(output.status.success(), "child failed: {output:?}");
    assert!(stdout.contains("LAZYPOLINE_REFUSE_OK"), "{stdout}");
}
