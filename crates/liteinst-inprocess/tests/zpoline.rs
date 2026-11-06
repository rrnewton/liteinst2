//! Fresh-process zpoline environment test.
//!
//! The test binary re-executes itself once. The child either proves positive
//! low-page execution on a VA-0-capable host or exits 42 with the named
//! low-page refusal. The parent never treats that refusal as a positive run.
#![deny(unsafe_op_in_unsafe_fn)]

use liteinst::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    QuiescenceLease, ResumeObligation, SourceIdentity,
};
use liteinst_inprocess::selected::{SelectedKind, selected_counters};
use liteinst_inprocess::syscall::zpoline::{PreparedZpoline, ZpolineSite};
use liteinst_inprocess::syscall::{SyscallRefusal, SyscallStrategy, SyscallStrategyConfig};
use std::ffi::c_void;
use std::process::Command;

const CHILD_ENV: &str = "LITEINST_ZPOLINE_CHILD";
const CODE: [u8; 3] = [0x0f, 0x05, 0xc3];
const PATCHED: [u8; 3] = [0xff, 0xd0, 0xc3];

core::arch::global_asm!(
    r#"
    .global zpoline_probe_invoke
    .type zpoline_probe_invoke, @function
zpoline_probe_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsi
    mov r15, rdi
    mov qword ptr [rbx], rsp
    mov edi, 11
    mov esi, 12
    mov edx, 13
    mov ecx, 14
    mov r8d, 15
    mov r9d, 16
    mov r10d, 17
    mov eax, 39
    cmp edi, 11
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
    fn zpoline_probe_invoke(entry: usize, output: *mut u64);
}

struct ApplicationSignals {
    mask: libc::sigset_t,
    segv: libc::sigaction,
}

impl ApplicationSignals {
    fn block() -> Self {
        let mut mask = unsafe { std::mem::zeroed() };
        let mut old = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sigfillset(&mut mask) }, 0);
        assert_eq!(unsafe { libc::sigdelset(&mut mask, libc::SIGSEGV) }, 0);
        assert_eq!(unsafe { libc::sigdelset(&mut mask, libc::SIGILL) }, 0);
        assert_eq!(
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &mask, &mut old) },
            0
        );
        let mut segv = unsafe { std::mem::zeroed() };
        let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
        default.sa_sigaction = libc::SIG_DFL;
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGSEGV, &default, &mut segv) },
            0
        );
        Self { mask: old, segv }
    }
}

impl Drop for ApplicationSignals {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGSEGV, &self.segv, std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.mask, std::ptr::null_mut()) },
            0
        );
    }
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

fn invoke(entry: usize) -> [u64; 12] {
    let mut output = [0_u64; 12];
    unsafe { zpoline_probe_invoke(entry, output.as_mut_ptr()) };
    output
}

fn check_output(output: [u64; 12], entry: usize, pid: u64) {
    assert_eq!(output[0], output[1], "stack pointer must round-trip");
    assert_eq!(output[2], pid, "getpid result");
    assert_eq!(output[3], entry as u64 + 2, "RCX return PC");
    assert_eq!(output[4], output[5], "R11 must equal restored flags");
    assert_eq!(&output[6..], &[11, 12, 13, 17, 15, 16]);
}

fn child_main() -> ! {
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP) }, 0);
    let _signals = ApplicationSignals::block();
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    assert!(page.is_power_of_two() && page >= 4096);
    let mut region = Region::new(page);
    let entry = region.address as usize;
    let pid = u64::try_from(unsafe { libc::getpid() }).unwrap();
    check_output(invoke(entry), entry, pid);
    assert_eq!(region.bytes(), CODE);

    let identity = CodeIdentity {
        source: SourceIdentity([0x5a; 32]),
        mapping: entry as u64,
        generation: 1,
    };
    let source_range = AddressRange::new(entry as u64, CODE.len()).unwrap();
    let entries = LegalEntrySet {
        identity,
        scope: source_range,
        provenance: EntryProvenance::Declared("zpoline probe syscall;ret".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![LegalEntry {
            address: entry as u64,
            requires_endbr: false,
        }],
        resumes: ResumeObligation::NoneExist,
    };
    let prepared = PreparedZpoline::prepare(ZpolineSite {
        config: SyscallStrategyConfig::new(SyscallStrategy::Zpoline),
        identity,
        code: &CODE,
        base_address: entry as u64,
        logical_pc: entry as u64,
        entries: &entries,
        syscall_nr: libc::SYS_getpid as u32,
    })
    .unwrap();
    assert_eq!(selected_counters(SelectedKind::Syscall).entered, 0);

    region.permissions(libc::PROT_READ | libc::PROT_WRITE);
    let address = region.address;
    let len = region.len;
    let mut lease = unsafe { QuiescenceLease::new(&mut region, identity, vec![source_range]) };
    let installed = unsafe {
        prepared.publish_with(address, &mut lease, || {
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
    let installed = match installed {
        Ok(value) => value,
        Err(failure) => {
            let unchanged = failure.retained.observed_source() == Some(CODE.as_slice());
            eprintln!(
                "ZPOLINE_ENV_REFUSAL {:?} stage={:?} source_unchanged={unchanged}",
                failure.failure.reason, failure.failure.stage
            );
            if matches!(
                failure.failure.reason,
                SyscallRefusal::LowPageUnavailable { .. } | SyscallRefusal::LowPageOccupied
            ) && failure.failure.stage == liteinst::contracts::FailureStage::BeforeWrite
                && unchanged
            {
                std::process::exit(42);
            }
            std::process::abort();
        }
    };
    assert!(installed.verified());
    assert_eq!(region.bytes(), PATCHED);
    assert_eq!(installed.observed_source().unwrap(), PATCHED);
    assert!(installed.observed_sled().is_some_and(|sled| {
        sled[..installed.prepared().sled_layout().common_entry()]
            .iter()
            .all(|byte| *byte == 0x90)
    }));

    check_output(invoke(entry), entry, pid);
    let counters = selected_counters(SelectedKind::Syscall);
    assert_eq!(counters.entered, 1);
    assert_eq!(counters.completed, 1);

    region.permissions(libc::PROT_READ | libc::PROT_WRITE);
    let address = region.address;
    let len = region.len;
    let mut lease = unsafe { QuiescenceLease::new(&mut region, identity, vec![source_range]) };
    if let Err(failure) = unsafe {
        installed.retire(address, &mut lease, || {
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
    } {
        eprintln!("ZPOLINE_RETIRE_FAILURE {:?}", failure.failure);
        std::process::abort();
    }
    assert_eq!(region.bytes(), CODE);
    check_output(invoke(entry), entry, pid);
    println!("ZPOLINE_POSITIVE pid={pid} entry={entry:#x}");
    std::process::exit(0);
}

#[test]
fn zpoline_probe_positive_or_named_environment_refusal() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child_main();
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .env(CHILD_ENV, "1")
        .args([
            "--exact",
            "zpoline_probe_positive_or_named_environment_refusal",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mmap_min_addr = std::fs::read_to_string("/proc/sys/vm/mmap_min_addr")
        .unwrap()
        .trim()
        .to_string();

    if output.status.success() {
        assert!(
            stdout.contains("ZPOLINE_POSITIVE"),
            "stdout={stdout} stderr={stderr}"
        );
        return;
    }

    assert_eq!(
        output.status.code(),
        Some(42),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("ZPOLINE_ENV_REFUSAL LowPageUnavailable")
            || stderr.contains("ZPOLINE_ENV_REFUSAL LowPageOccupied"),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(stderr.contains("source_unchanged=true"), "stderr={stderr}");
    assert_ne!(
        mmap_min_addr, "0",
        "VA0 was advertised available but zpoline still refused: {stderr}"
    );
    eprintln!("zpoline positive not run: mmap_min_addr={mmap_min_addr}; {stderr}");
}
