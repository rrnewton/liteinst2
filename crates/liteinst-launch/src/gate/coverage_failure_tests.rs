//! Real-child error-path evidence for test-only coverage operation failures.

use super::failure::{Phase, State};
use crate::gate::{GateError, ImageFacts, SelectedPageGate};
use crate::selected::{
    InstructionProvider, ProviderDecision, SelectedInput, SemanticsError, SyscallAliases,
};
use crate::{ExecCheckpoint, LaunchCommand, RegisterSnapshot};
use liteinst_admission::scan::{Policy, SiteClass};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const DATA: u64 = 0x600000;
const TIMEOUT: Duration = Duration::from_secs(3);
const MOV_VALUE: u64 = 0x9090_9090_90a2_0f90;
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct CountNative {
    calls: usize,
    input: Option<RegisterSnapshot>,
}

impl InstructionProvider for CountNative {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        self.calls += 1;
        assert!(self.input.replace(*input.registers()).is_none());
        Ok(ProviderDecision::Native)
    }
}

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    image: Vec<u8>,
    heads: BTreeSet<u64>,
    site: u64,
    guards: [u64; 2],
    instruction_len: usize,
}

impl Fixture {
    fn new(phase: Phase) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&root).unwrap();
        let directory = root.join(format!(
            "coverage-failure-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("fixture");
        let mut image = vec![0xcc; 3 * PAGE];
        image[..PAGE].fill(0);
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut image, 16, 2);
        put16(&mut image, 18, 62);
        put32(&mut image, 20, 1);
        let site = BASE
            + if phase == Phase::PageExecutable {
                2 * PAGE - 1
            } else {
                PAGE
            } as u64;
        put64(&mut image, 24, site);
        put64(&mut image, 32, 64);
        put16(&mut image, 52, 64);
        put16(&mut image, 54, 56);
        put16(&mut image, 56, 3);
        put32(&mut image, 64, 1);
        put32(&mut image, 68, 5);
        put64(&mut image, 80, BASE);
        put64(&mut image, 96, (3 * PAGE) as u64);
        put64(&mut image, 104, (3 * PAGE) as u64);
        put64(&mut image, 112, PAGE as u64);
        put32(&mut image, 120, 1);
        put32(&mut image, 124, 6);
        put64(&mut image, 128, (3 * PAGE) as u64);
        put64(&mut image, 136, DATA);
        put64(&mut image, 152, PAGE as u64);
        put64(&mut image, 160, PAGE as u64);
        put64(&mut image, 168, PAGE as u64);
        put32(&mut image, 176, 0x6474_e551);
        put32(&mut image, 180, 6);
        put64(&mut image, 224, 16);
        let collateral = matches!(
            phase,
            Phase::CollateralRestored | Phase::CollateralCompleted
        );
        let instruction = if collateral {
            let mut bytes = vec![0x48, 0xb8];
            bytes.extend_from_slice(&MOV_VALUE.to_le_bytes());
            bytes
        } else {
            // Prefix and suffix are both selected CPUID candidates. No CPU
            // capability-dependent random instruction is needed for these paths.
            vec![0x66, 0x0f, 0xa2]
        };
        let instruction_len = instruction.len();
        let offset = (site - BASE) as usize;
        image[offset..offset + instruction_len].copy_from_slice(&instruction);
        let marker = site + instruction_len as u64;
        let mut store = vec![0xc6, 0x05]; // MOV byte ptr [RIP+disp32], 0x7f.
        store.extend_from_slice(
            &i32::try_from(DATA as i64 - (marker + 7) as i64)
                .unwrap()
                .to_le_bytes(),
        );
        store.push(0x7f);
        image[offset + instruction_len..offset + instruction_len + 7].copy_from_slice(&store);
        image[offset + instruction_len + 7..offset + instruction_len + 9]
            .copy_from_slice(&[0x0f, 0x0b]);
        let heads = BTreeSet::from([site, marker, marker + 7]);
        let guards = [site, site + if collateral { 3 } else { 1 }];
        let mut file_image = image.clone();
        file_image.resize(4 * PAGE, 0);
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&file_image).unwrap();
        drop(file);
        Self {
            directory,
            path,
            image,
            heads,
            site,
            guards,
            instruction_len,
        }
    }

    fn launch(&self, phase: Phase) -> SelectedPageGate<CountNative> {
        let checkpoint = {
            let _guard = crate::TEST_FILE_FORK.lock().unwrap();
            ExecCheckpoint::launch(&LaunchCommand::new(&self.path), TIMEOUT).unwrap()
        };
        // SAFETY: this fixed private ELF has one task, immutable code, an exact
        // reachable-head census and no aliases, code reads, signal handlers or
        // mapping changes. Only the declared first stream is entered. All
        // guarded entries have clear TF/RF; we exclusively own tracing/reaping.
        let mut gate = unsafe {
            SelectedPageGate::new_with_coverage(
                checkpoint,
                vec![ImageFacts {
                    start: BASE,
                    bytes: self.image.clone(),
                    heads: self.heads.clone(),
                }],
                Policy::default(),
                SyscallAliases::new(),
                CountNative::default(),
                TIMEOUT,
                Default::default(),
            )
        }
        .unwrap();
        gate.inject_coverage_failure(phase);
        gate
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn state(gate: &SelectedPageGate<CountNative>) -> State {
    State {
        registers: gate.read_registers().unwrap(),
        xstate: gate.read_xstate().unwrap(),
    }
}

fn executable(pid: libc::pid_t, address: u64) -> bool {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        if u64::from_str_radix(start, 16).unwrap() <= address
            && address < u64::from_str_radix(end, 16).unwrap()
        {
            return fields.next().unwrap().as_bytes()[2] == b'x';
        }
    }
    panic!("expected fixture mapping");
}

fn pidfd(pid: libc::pid_t) -> OwnedFd {
    // SAFETY: opens a stable handle to this fixture's still-owned child.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0);
    // SAFETY: successful pidfd_open returned a new owned descriptor.
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn assert_reaped(handle: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pollfd storage is valid; the finite wait targets this child only.
    assert_eq!(
        unsafe { libc::poll(&mut poll, 1, TIMEOUT.as_millis() as i32) },
        1
    );
    assert_ne!(poll.revents & libc::POLLIN, 0);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        // SAFETY: zeroed siginfo is output storage for a non-destructive wait.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: P_PIDFD targets the original owned process even if its numeric
        // PID is later reused. WNOWAIT cannot accidentally conceal an orphan.
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                handle.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        };
        if result == -1 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            break;
        }
        assert_eq!(result, 0);
        assert!(
            Instant::now() < deadline,
            "owner left a waitable child after teardown"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn exercise(phase: Phase) {
    let fixture = Fixture::new(phase);
    let mut gate = fixture.launch(phase);
    let handle = pidfd(gate.pid());
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused("injected coverage operation failure"))
    ));
    let evidence = gate.coverage_failure_evidence().clone();
    assert_eq!(evidence.phase, phase);
    let before = evidence.before.unwrap();
    let failed = evidence.at_failure.unwrap();
    assert_eq!(state(&gate), failed);
    assert_eq!(failed.xstate, before.xstate);
    let mut expected_source = fixture.image.clone();
    let selected = matches!(phase, Phase::SelectedRestored | Phase::SelectedCompleted);
    if phase == Phase::GuardWritten {
        expected_source[(fixture.guards[0] - BASE) as usize] = 0xcc;
    } else if phase == Phase::PageExecutable {
        for address in fixture.guards {
            expected_source[(address - BASE) as usize] = 0xcc;
        }
    }
    assert_eq!(
        gate.read_memory(BASE, expected_source.len()).unwrap(),
        expected_source
    );
    assert_eq!(
        gate.read_memory(DATA, 1).unwrap(),
        [0],
        "continuation marker must not execute"
    );
    match phase {
        Phase::GuardWritten | Phase::PageExecutable => {
            assert_eq!(
                failed, before,
                "publication control must preserve all state"
            );
            assert_eq!(failed.registers.rip, fixture.site);
            assert!(!gate.is_admitted(fixture.site));
            assert!(!gate.is_admitted(fixture.site + fixture.instruction_len as u64 - 1));
            assert_eq!(gate.gate_metrics().admitted_pages, 0);
            assert_eq!(
                executable(gate.pid(), fixture.site),
                phase == Phase::PageExecutable
            );
            assert!(!executable(gate.pid(), BASE + 2 * PAGE as u64));
        }
        Phase::SelectedRestored | Phase::CollateralRestored => {
            assert_eq!(
                failed, before,
                "restoration and sync must preserve all state"
            );
            assert_eq!(failed.registers.rip, fixture.site);
            assert!(gate.is_admitted(fixture.site));
            assert!(executable(gate.pid(), fixture.site));
        }
        Phase::SelectedCompleted => {
            // The fixture's literal CPUID may change only these four outputs.
            // Keep every other GPR, flag, segment, kernel field and XSTATE byte
            // exact; this check does not call the production transition helper.
            let mut expected = before.clone();
            for value in [
                failed.registers.rax,
                failed.registers.rbx,
                failed.registers.rcx,
                failed.registers.rdx,
            ] {
                assert!(value <= u32::MAX as u64);
            }
            expected.registers.rax = failed.registers.rax;
            expected.registers.rbx = failed.registers.rbx;
            expected.registers.rcx = failed.registers.rcx;
            expected.registers.rdx = failed.registers.rdx;
            expected.registers.rip += fixture.instruction_len as u64;
            assert_eq!(failed, expected, "exact CPUID completion before rearm");
            assert!(gate.is_admitted(fixture.site));
            assert!(executable(gate.pid(), fixture.site));
        }
        Phase::CollateralCompleted => {
            let mut expected = before.clone();
            expected.registers.rax = MOV_VALUE;
            expected.registers.rip += fixture.instruction_len as u64;
            assert_eq!(
                failed, expected,
                "exact original MOV completion before rearm"
            );
            assert!(gate.is_admitted(fixture.site));
            assert!(executable(gate.pid(), fixture.site));
        }
    }
    let calls = usize::from(selected);
    assert_eq!(gate.provider().calls, calls);
    if selected {
        assert_eq!(gate.provider().input, Some(before.registers));
        assert_eq!(gate.metrics().callbacks.get(&SiteClass::Cpuid), Some(&1));
        assert_eq!(gate.metrics().callbacks.len(), 1);
    } else {
        assert!(gate.provider().input.is_none());
        assert!(gate.metrics().callbacks.is_empty());
    }
    assert_eq!(gate.metrics().native_completions, 0);
    assert_eq!(gate.metrics().scripted_completions, 0);
    assert_eq!(gate.gate_metrics().collateral_completions, 0);
    assert_eq!(gate.metrics().refusals, 1);
    let callbacks = gate.metrics().callbacks.clone();
    for _ in 0..2 {
        assert!(matches!(
            gate.next_event(),
            Err(GateError::Refused("selected execution loop is closed"))
        ));
        assert_eq!(state(&gate), failed);
        assert_eq!(
            gate.read_memory(BASE, expected_source.len()).unwrap(),
            expected_source
        );
        assert_eq!(gate.read_memory(DATA, 1).unwrap(), [0]);
        assert_eq!(gate.provider().calls, calls);
        assert_eq!(gate.metrics().callbacks, callbacks);
        assert_eq!(gate.metrics().refusals, 1);
        assert_eq!(gate.metrics().native_completions, 0);
        assert_eq!(gate.gate_metrics().collateral_completions, 0);
    }
    drop(gate);
    assert_reaped(&handle);
}

#[test]
fn first_guard_write_failure_keeps_original_execution_excluded() {
    exercise(Phase::GuardWritten);
}

#[test]
fn first_mprotect_failure_keeps_two_page_publication_closed() {
    exercise(Phase::PageExecutable);
}

#[test]
fn selected_restoration_failure_keeps_all_original_bytes_held() {
    exercise(Phase::SelectedRestored);
}

#[test]
fn selected_completion_failure_cannot_resume_without_rearming() {
    exercise(Phase::SelectedCompleted);
}

#[test]
fn collateral_restoration_failure_keeps_all_original_bytes_held() {
    exercise(Phase::CollateralRestored);
}

#[test]
fn collateral_completion_failure_preserves_completed_state_and_exclusion() {
    exercise(Phase::CollateralCompleted);
}
