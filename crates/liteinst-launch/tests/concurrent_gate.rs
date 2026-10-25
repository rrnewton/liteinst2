#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Native, fixed-membership shared-mm fixtures with exhaustive hand-authored
//! instruction heads. Every worker has a separate private writable stack.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use liteinst_admission::scan::{Policy, SiteClass};
use liteinst_launch::gate::{
    ConcurrentConfig, ConcurrentEvent, ConcurrentPageGate, GateError, ImageFacts,
};
use liteinst_launch::{
    ExecCheckpoint, FIXED_CLONE_FLAGS, LaunchCommand, LaunchError, RegisterSnapshot,
};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const STACK_BASE: u64 = 0x600000;
const STACK_SIZE: u64 = 64 * 1024;
const WORKERS: usize = 4;
const TIMEOUT: Duration = Duration::from_secs(3);
const CPUID: &[u8] = &[0x0f, 0xa2];
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
// Exclude forks while a writable fixture descriptor could be inherited.
static FIXTURE_FORK_LOCK: Mutex<()> = Mutex::new(());

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&root).unwrap();
        for _ in 0..100 {
            let path = root.join(format!(
                "concurrent-gate-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("fixture directory: {error}"),
            }
        }
        panic!("fixture directory allocation exhausted");
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ElfBuilder {
    bytes: Vec<u8>,
    heads: BTreeSet<usize>,
    cursor: usize,
}

impl ElfBuilder {
    fn new(code_pages: usize) -> Self {
        let mut bytes = vec![0xcc; code_pages * PAGE];
        bytes[..PAGE].fill(0);
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 24, BASE + PAGE as u64);
        put64(&mut bytes, 32, 64);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 3);
        // RX headers/factory/worker code, with complete original VMA facts.
        put32(&mut bytes, 64, 1);
        put32(&mut bytes, 68, 5);
        put64(&mut bytes, 80, BASE);
        put64(&mut bytes, 96, (code_pages * PAGE) as u64);
        put64(&mut bytes, 104, (code_pages * PAGE) as u64);
        put64(&mut bytes, 112, PAGE as u64);
        // Separate private RW/NX PT_LOAD. Its first page is file-backed zeros;
        // the remaining BSS supplies eight distinct 64-KiB worker stacks.
        put32(&mut bytes, 120, 1);
        put32(&mut bytes, 124, 6);
        put64(&mut bytes, 128, (code_pages * PAGE) as u64);
        put64(&mut bytes, 136, STACK_BASE);
        put64(&mut bytes, 152, PAGE as u64);
        put64(&mut bytes, 160, STACK_SIZE * (WORKERS * 2) as u64);
        put64(&mut bytes, 168, PAGE as u64);
        put32(&mut bytes, 176, 0x6474_e551); // GNU_STACK: RW, never X.
        put32(&mut bytes, 180, 6);
        put64(&mut bytes, 224, 16);
        Self {
            bytes,
            heads: BTreeSet::new(),
            cursor: PAGE,
        }
    }

    fn seek(&mut self, address: usize) {
        assert!(address >= PAGE && address < self.bytes.len());
        self.cursor = address;
    }

    fn instruction(&mut self, bytes: &[u8]) -> usize {
        let start = self.cursor;
        assert!(!bytes.is_empty() && self.heads.insert(start));
        self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        start
    }

    fn mov64(&mut self, register: u8, value: u64) {
        assert!(register < 16);
        let mut bytes = vec![0x48 | (register >> 3), 0xb8 | (register & 7)];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.instruction(&bytes);
    }

    fn mov32(&mut self, register: u8, value: u32) {
        assert!(register < 16);
        let mut bytes = Vec::new();
        if register >= 8 {
            bytes.push(0x41);
        }
        bytes.push(0xb8 | (register & 7));
        bytes.extend_from_slice(&value.to_le_bytes());
        self.instruction(&bytes);
    }

    fn branch(&mut self, opcode: &[u8], target: usize) {
        let next = self.cursor + opcode.len() + 4;
        let displacement = i32::try_from(target as i64 - next as i64).unwrap();
        let mut bytes = opcode.to_vec();
        bytes.extend_from_slice(&displacement.to_le_bytes());
        self.instruction(&bytes);
    }

    fn exit_worker(&mut self) {
        self.mov32(7, 0);
        self.instruction(&[0x44, 0x01, 0xe7]); // add edi,r12d: logical worker ID
        self.mov32(0, libc::SYS_exit as u32);
        self.instruction(&[0x0f, 0x05]);
        // The controller also authenticates syscall-stop return PCs.
        self.instruction(&[0x0f, 0x0b]);
    }

    fn write(
        self,
        directory: &FixtureDirectory,
        name: &str,
        freeze: usize,
        site: usize,
        marker: Option<usize>,
    ) -> ElfImage {
        let path = directory.0.join(name);
        let _fork_guard = FIXTURE_FORK_LOCK.lock().unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&self.bytes).unwrap();
        file.write_all(&vec![0; PAGE]).unwrap();
        drop(file);
        ElfImage {
            path,
            bytes: self.bytes,
            heads: self.heads,
            freeze,
            site,
            marker,
        }
    }
}

struct ElfImage {
    path: PathBuf,
    bytes: Vec<u8>,
    heads: BTreeSet<usize>,
    freeze: usize,
    site: usize,
    marker: Option<usize>,
}

impl ElfImage {
    fn facts(&self) -> ImageFacts {
        ImageFacts {
            start: BASE,
            bytes: self.bytes.clone(),
            heads: self
                .heads
                .iter()
                .map(|offset| BASE + *offset as u64)
                .collect(),
        }
    }
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Copy)]
enum WorkerProgram {
    Exit,
    Spinner,
    CloneAgain,
    Differential,
    SavedReturn,
}

fn fixture(directory: &FixtureDirectory, cross_page: bool, program: WorkerProgram) -> ElfImage {
    const CHILD_TRANSITION: usize = PAGE + 1024;
    const SPINNER: usize = PAGE + 1536;
    let site = if cross_page { 3 * PAGE - 2 } else { 2 * PAGE };
    let mut builder = ElfBuilder::new(
        if cross_page || matches!(program, WorkerProgram::SavedReturn) {
            4
        } else {
            3
        },
    );
    for id in 1..=WORKERS {
        builder.mov32(12, id as u32);
        builder.mov64(13, STACK_BASE + STACK_SIZE * (WORKERS + id) as u64);
        builder.mov32(7, FIXED_CLONE_FLAGS as u32);
        builder.mov64(6, STACK_BASE + STACK_SIZE * id as u64);
        builder.instruction(&[0x31, 0xd2]); // xor edx,edx
        builder.instruction(&[0x45, 0x31, 0xd2]); // xor r10d,r10d
        builder.instruction(&[0x45, 0x31, 0xc0]); // xor r8d,r8d
        builder.mov32(0, libc::SYS_clone as u32);
        builder.instruction(&[0x0f, 0x05]);
        builder.instruction(&[0x48, 0x85, 0xc0]); // test rax,rax
        builder.branch(&[0x0f, 0x84], CHILD_TRANSITION);
    }
    let freeze = builder.instruction(&[0xcc]);
    builder.instruction(&[0x0f, 0x0b]);
    assert!(builder.cursor < CHILD_TRANSITION);
    builder.seek(CHILD_TRANSITION);
    if matches!(program, WorkerProgram::Spinner) {
        builder.instruction(&[0x41, 0x83, 0xfc, 1]); // cmp r12d,1
        builder.branch(&[0x0f, 0x84], SPINNER);
    }
    if matches!(program, WorkerProgram::Differential) {
        builder.instruction(&[0x48, 0x83, 0xec, 32]); // sub rsp,32
        for (offset, value) in [
            (0, 0x1122_3344_u32),
            (8, 0x5566_7788),
            (16, 0x1357_2468),
            (24, 0x0246_1357),
        ] {
            let mut bytes = vec![0x48, 0xc7, 0x44, 0x24, offset];
            bytes.extend_from_slice(&value.to_le_bytes());
            builder.instruction(&bytes);
        }
        builder.instruction(&[0xdb, 0xe3]); // fninit
        builder.instruction(&[0xd9, 0xe8]); // fld1
        builder.instruction(&[0x66, 0x0f, 0x76, 0xc9]); // pcmpeqd xmm1,xmm1
        builder.instruction(&[0x66, 0x0f, 0x6f, 0xd1]); // movdqa xmm2,xmm1
        for register in 0..16 {
            if !matches!(register, 4 | 12) {
                builder.mov64(register, 0x1000 + u64::from(register));
            }
        }
    }
    builder.mov32(0, 0);
    builder.mov32(1, 0);
    builder.instruction(&[0x68, 0x02, 0x02, 0, 0]);
    builder.instruction(&[0x9d]);
    builder.branch(&[0xe9], site);
    if matches!(program, WorkerProgram::Spinner) {
        builder.seek(SPINNER);
        builder.instruction(&[0xf3, 0x90]); // pause
        builder.branch(&[0xe9], SPINNER);
    }
    if matches!(program, WorkerProgram::SavedReturn) {
        let call = 3 * PAGE - 5;
        let callee = 2 * PAGE + 64;
        let destination = 3 * PAGE;
        builder.seek(site);
        builder.branch(&[0xe9], call);
        builder.seek(callee);
        builder.instruction(CPUID);
        builder.mov32(7, 0); // Complete, immutable pun successor.
        builder.instruction(&[0xc3]);
        builder.seek(call);
        builder.branch(&[0xe8], callee);
        assert_eq!(builder.cursor, destination);
        builder.instruction(CPUID);
        builder.exit_worker();
        return builder.write(directory, "workers", freeze, callee, Some(destination));
    }
    builder.seek(site);
    builder.instruction(CPUID);
    let marker = if matches!(program, WorkerProgram::Differential) {
        builder.instruction(&[0x48, 0x89, 0x04, 0x24]);
        builder.instruction(&[0x48, 0x89, 0x5c, 0x24, 8]);
        builder.instruction(&[0x48, 0x89, 0x4c, 0x24, 16]);
        builder.instruction(&[0x48, 0x89, 0x54, 0x24, 24]);
        let marker = 2 * PAGE + 512;
        builder.branch(&[0xe9], marker);
        builder.seek(marker);
        builder.instruction(CPUID);
        Some(marker)
    } else {
        None
    };
    if matches!(program, WorkerProgram::CloneAgain) {
        builder.mov32(7, FIXED_CLONE_FLAGS as u32);
        builder.instruction(&[0x4c, 0x89, 0xee]); // mov rsi,r13
        builder.instruction(&[0x31, 0xd2]);
        builder.instruction(&[0x45, 0x31, 0xd2]);
        builder.instruction(&[0x45, 0x31, 0xc0]);
        builder.mov32(0, libc::SYS_clone as u32);
        builder.instruction(&[0x0f, 0x05]);
    }
    builder.exit_worker();
    builder.write(directory, "workers", freeze, site, marker)
}

fn gate(image: &ElfImage, timeout: Duration) -> ConcurrentPageGate {
    let checkpoint = {
        let _fork_guard = FIXTURE_FORK_LOCK.lock().unwrap();
        ExecCheckpoint::launch(&LaunchCommand::new(&image.path), TIMEOUT).unwrap()
    };
    // SAFETY: the uniquely owned immutable ELF explicitly declares every head,
    // clone continuation and worker stack. Only the fixed factory may clone;
    // its leader is permanently frozen. All workers use the native System V
    // ABI and this host's exact qualified xstate layout, no CET/AMX, aliases,
    // external accesses, handlers, code-as-data, private-frame inspection or
    // direct generated-code entry. Each stack has 64 KiB of mapped private RW
    // storage. Negative fixtures deliberately exercise refusal before an
    // additional clone executes, or termination when cooperation is absent.
    unsafe {
        ConcurrentPageGate::new(
            checkpoint,
            vec![image.facts()],
            Policy {
                version: 1,
                selected: [SiteClass::Cpuid].into_iter().collect(),
            },
            ConcurrentConfig {
                worker_count: WORKERS,
                freeze_pc: BASE + image.freeze as u64,
            },
            timeout,
        )
    }
    .unwrap()
}

fn assert_kernel_nx(pid: libc::pid_t, address: u64) {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16).unwrap();
        if start <= address && address < end {
            assert_ne!(fields.next().unwrap().as_bytes()[2], b'x');
            return;
        }
    }
    panic!("missing NX mapping at {address:#x}");
}

fn assert_reaped(tids: &[libc::pid_t]) {
    let deadline = Instant::now() + TIMEOUT;
    while tids
        .iter()
        .any(|tid| Path::new(&format!("/proc/{tid}")).exists())
    {
        assert!(Instant::now() < deadline, "owned task survived cleanup");
        std::thread::sleep(Duration::from_millis(1));
    }
    for &tid in tids {
        let mut status = 0;
        // SAFETY: this checks only the previously owned task after /proc removal.
        let result = unsafe { libc::waitpid(tid, &mut status, libc::WNOHANG | libc::__WALL) };
        assert_eq!(result, -1, "owned task {tid} was not already reaped");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

fn run_race(cross_page: bool) {
    let directory = FixtureDirectory::new();
    let image = fixture(&directory, cross_page, WorkerProgram::Exit);
    let mut gate = gate(&image, TIMEOUT);
    let mut owned = gate.worker_ids().to_vec();
    assert_eq!(
        owned.iter().copied().collect::<BTreeSet<_>>().len(),
        WORKERS
    );
    owned.push(gate.pid());
    let source = BASE + image.site as u64;
    assert_kernel_nx(gate.pid(), source);
    if cross_page {
        assert_kernel_nx(gate.pid(), source + 2);
    }
    assert_eq!(gate.metrics().gate.admitted_pages, 1);
    assert_eq!(gate.metrics().publication_bundles, 0);
    let mut observed = BTreeMap::new();
    let mut exited = BTreeMap::new();
    loop {
        match gate.next_event().unwrap() {
            ConcurrentEvent::Observe { tid, observation } => {
                let id = observation.registers.r12;
                assert!((1..=WORKERS as u64).contains(&id));
                assert!(gate.worker_ids().contains(&tid));
                assert!(observed.insert(tid, id).is_none(), "duplicate callback");
                assert_eq!(observation.site.address, source);
                assert_eq!(observation.site.len, 2);
                assert_eq!(observation.registers.rip, source);
                assert_eq!(observation.registers.rax, 0);
                assert_eq!(observation.registers.rcx, 0);
                assert_eq!(observation.registers.eflags, 0x202);
                assert_eq!(observation.registers.rsp, STACK_BASE + STACK_SIZE * id);
                assert!(gate.is_admitted(source));
                if cross_page {
                    assert!(gate.is_admitted(source + 2));
                }
                let bytes = gate.read_memory(source, 5).unwrap();
                assert_eq!(bytes[0], 0xe9);
                assert_eq!(&bytes[2..], &image.bytes[image.site + 2..image.site + 5]);
            }
            ConcurrentEvent::WorkerExited { tid, code } => {
                assert_eq!(code as u64, *observed.get(&tid).unwrap());
                assert!(exited.insert(tid, code).is_none());
            }
            ConcurrentEvent::Complete => break,
        }
    }
    assert_eq!(observed.len(), WORKERS);
    assert_eq!(
        observed.values().copied().collect::<BTreeSet<_>>(),
        (1..=4).collect()
    );
    assert_eq!(exited.len(), WORKERS);
    assert_eq!(gate.metrics().gate.observations, WORKERS);
    assert_eq!(
        gate.metrics().gate.admitted_pages,
        if cross_page { 3 } else { 2 }
    );
    assert_eq!(gate.metrics().publication_bundles, 1);
    assert!(
        gate.metrics()
            .faults_per_rendezvous
            .iter()
            .any(|&faults| faults >= 2)
    );
    assert_eq!(
        gate.metrics().rendezvous.len(),
        gate.metrics().faults_per_rendezvous.len()
    );
    if std::env::var_os("LITEINST_TEST_GATE_METRICS").is_some() {
        let metrics = gate.metrics();
        let first_touch_ns: Vec<_> = metrics
            .gate
            .first_touch
            .iter()
            .map(Duration::as_nanos)
            .collect();
        let rendezvous_ns: Vec<_> = metrics.rendezvous.iter().map(Duration::as_nanos).collect();
        eprintln!(
            "LITEINST_GATE_METRICS {{\"cross_page\":{cross_page},\"workers\":{WORKERS},\"startup_ns\":{},\"first_touch_ns\":{first_touch_ns:?},\"rendezvous_ns\":{rendezvous_ns:?},\"admitted_pages\":{},\"untouched_pages\":{},\"publications\":{},\"callbacks\":{},\"faults_per_rendezvous\":{:?}}}",
            metrics.gate.startup.as_nanos(),
            metrics.gate.admitted_pages,
            metrics.gate.untouched_pages,
            metrics.publication_bundles,
            metrics.gate.observations,
            metrics.faults_per_rendezvous,
        );
    }
    assert_reaped(&owned);
    assert!(gate.next_event().is_err());
}

#[test]
fn four_workers_fault_one_nx_page_before_one_publication() {
    run_race(false);
}

#[test]
fn four_workers_share_one_publication_with_cross_page_e9_fetch() {
    run_race(true);
}

#[test]
fn noncooperating_worker_hits_collective_deadline_and_all_tasks_are_reaped() {
    let directory = FixtureDirectory::new();
    let image = fixture(&directory, false, WorkerProgram::Spinner);
    let budget = Duration::from_millis(250);
    let hard_limit = budget + Duration::from_secs(2);
    let mut gate = gate(&image, budget);
    let mut owned = gate.worker_ids().to_vec();
    owned.push(gate.pid());
    // A pidfd binds the independent regression watchdog to this exact group.
    // SAFETY: zero flags and the owned thread-group ID are valid pidfd_open args.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, gate.pid(), 0) };
    assert!(
        descriptor >= 0,
        "pidfd_open: {}",
        io::Error::last_os_error()
    );
    // SAFETY: pidfd_open returned a new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
    let (complete, waiting) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if waiting.recv_timeout(hard_limit) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            // SAFETY: this stable descriptor identifies only the owned group.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            true
        } else {
            false
        }
    });
    let started = Instant::now();
    let event = gate.next_event();
    let elapsed = started.elapsed();
    let _ = complete.send(());
    assert!(
        !watchdog.join().unwrap(),
        "collective deadline needed external watchdog"
    );
    assert!(
        elapsed < hard_limit,
        "collective deadline exceeded cleanup margin: {elapsed:?}"
    );
    assert!(
        matches!(
            event,
            Err(GateError::Control(LaunchError::Timeout(
                "collective worker rendezvous"
            )))
        ),
        "spinner did not produce the exact collective deadline refusal: {event:?}"
    );
    assert_eq!(gate.metrics().publication_bundles, 0);
    assert_eq!(gate.metrics().gate.admitted_pages, 1);
    assert_eq!(gate.metrics().gate.observations, 0);
    assert!(!gate.is_admitted(BASE + image.site as u64));
    assert_reaped(&owned);
    assert!(gate.next_event().is_err());
}

#[test]
fn valid_clone_after_membership_freeze_is_refused_and_all_tasks_are_reaped() {
    let directory = FixtureDirectory::new();
    let image = fixture(&directory, false, WorkerProgram::CloneAgain);
    let mut gate = gate(&image, TIMEOUT);
    let mut owned = gate.worker_ids().to_vec();
    owned.push(gate.pid());
    let mut observed = BTreeSet::new();
    for _ in 0..WORKERS {
        let ConcurrentEvent::Observe { tid, observation } = gate.next_event().unwrap() else {
            panic!("worker did not reach its CPUID before attempting clone");
        };
        assert!(observed.insert(tid));
        assert_eq!(observation.site.address, BASE + image.site as u64);
    }
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Control(LaunchError::Invalid(
            "syscall is outside fixed-membership worker allowlist"
        )))
    ));
    assert_eq!(gate.metrics().gate.observations, WORKERS);
    assert_reaped(&owned);
    assert!(gate.next_event().is_err());
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeEvidence {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    initialized_stack: Vec<u8>,
}

/// Independent native oracle: raw ptrace clone collection and an ordinary
/// breakpoint, without any production controller, page gate or A1 publisher.
struct NativeGroup {
    child: Option<Child>,
    tids: BTreeSet<libc::pid_t>,
    kill_handle: Option<OwnedFd>,
}

impl NativeGroup {
    fn launch(image: &ElfImage) -> Self {
        let _fork_guard = FIXTURE_FORK_LOCK.lock().unwrap();
        let mut command = Command::new(&image.path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the post-fork closure only calls ptrace and reads errno.
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let child = command.spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        let mut result = Self {
            child: Some(child),
            tids: BTreeSet::from([pid]),
            kill_handle: None,
        };
        // SAFETY: pidfd_open names the just-created owned thread group.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(
            descriptor >= 0,
            "native pidfd_open: {}",
            io::Error::last_os_error()
        );
        // SAFETY: this successful syscall returned a new descriptor.
        result.kill_handle = Some(unsafe { OwnedFd::from_raw_fd(descriptor as i32) });
        let status = native_wait(pid, Instant::now() + TIMEOUT);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        native_trace(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            (libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_EXITKILL) as usize,
        );
        result
    }

    fn pid(&self) -> libc::pid_t {
        self.child.as_ref().unwrap().id() as libc::pid_t
    }

    fn run_factory(&mut self, image: &ElfImage) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            native_trace(libc::PTRACE_CONT, self.pid(), 0, 0);
            let status = native_wait(self.pid(), deadline);
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            if status >> 16 == libc::PTRACE_EVENT_CLONE {
                let mut raw = 0_u64;
                native_trace(
                    libc::PTRACE_GETEVENTMSG,
                    self.pid(),
                    0,
                    (&raw mut raw) as usize,
                );
                let tid = libc::pid_t::try_from(raw).unwrap();
                assert!(self.tids.insert(tid), "native duplicate clone TID");
                // Retain cleanup ownership before inspecting the new child.
                let status = native_wait(tid, deadline);
                assert!(libc::WIFSTOPPED(status));
                assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
                assert_eq!(status >> 16, 0);
            } else {
                assert_eq!(status >> 16, 0);
                assert_eq!(
                    native_registers(self.pid()).rip,
                    BASE + image.freeze as u64 + 1
                );
                assert_eq!(self.tids.len(), WORKERS + 1);
                break;
            }
        }
    }

    fn run_to_exit(mut self, image: &ElfImage) {
        self.run_factory(image);
        let workers: Vec<_> = self
            .tids
            .iter()
            .copied()
            .filter(|tid| *tid != self.pid())
            .map(|tid| (tid, native_registers(tid).r12))
            .collect();
        for &(tid, _) in &workers {
            native_trace(libc::PTRACE_CONT, tid, 0, 0);
        }
        let deadline = Instant::now() + TIMEOUT;
        for (tid, id) in workers {
            let status = native_wait(tid, deadline);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status) as u64, id);
            assert!((1..=WORKERS as u64).contains(&id));
            self.tids.remove(&tid);
        }
    }

    fn after_native_cpuid(mut self, image: &ElfImage) -> BTreeMap<u64, NativeEvidence> {
        self.run_factory(image);
        let marker = BASE + image.marker.unwrap() as u64;
        let aligned = marker & !7;
        let mut word: [u8; 8] = native_memory(self.pid(), aligned, 8).try_into().unwrap();
        let within = (marker - aligned) as usize;
        assert_eq!(word[within], CPUID[0]);
        word[within] = 0xcc;
        // This independent one-byte breakpoint stops before the second CPUID.
        // Every first CPUID executes natively at its original unmodified site.
        native_trace(
            libc::PTRACE_POKEDATA,
            self.pid(),
            aligned as usize,
            u64::from_le_bytes(word) as usize,
        );
        let workers: Vec<_> = self
            .tids
            .iter()
            .copied()
            .filter(|tid| *tid != self.pid())
            .collect();
        for &tid in &workers {
            native_trace(libc::PTRACE_CONT, tid, 0, 0);
        }
        let deadline = Instant::now() + TIMEOUT;
        let mut evidence = BTreeMap::new();
        for tid in workers {
            let status = native_wait(tid, deadline);
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert_eq!(status >> 16, 0);
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
            native_trace(libc::PTRACE_GETSIGINFO, tid, 0, info.as_mut_ptr() as usize);
            // SAFETY: successful GETSIGINFO initialized the entire output.
            let info = unsafe { info.assume_init() };
            assert_eq!(info.si_signo, libc::SIGTRAP);
            assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
            let mut registers = native_registers(tid);
            assert_eq!(registers.rip, marker + 1);
            // INT3 reports its next byte. Translate only this authenticated PC
            // back to the original instruction head, as the gate observation does.
            registers.rip = marker;
            let id = registers.r12;
            assert!((1..=WORKERS as u64).contains(&id));
            assert_eq!(registers.rsp, STACK_BASE + STACK_SIZE * id - 32);
            assert_ne!(
                registers.rax, 0,
                "native leaf zero must not look like skipped CPUID"
            );
            let snapshot = NativeEvidence {
                registers,
                xstate: native_xstate(tid),
                initialized_stack: native_memory(tid, registers.rsp, 32),
            };
            assert!(evidence.insert(id, snapshot).is_none());
        }
        assert_eq!(evidence.len(), WORKERS);
        evidence
    }
}

impl Drop for NativeGroup {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let tgid = child.id() as libc::pid_t;
        discover_native_tasks(tgid, &mut self.tids);
        if let Some(handle) = &self.kill_handle {
            // SAFETY: the pidfd retains this group's identity across cleanup.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        } else {
            let _ = child.kill();
        }
        let mut pending = std::mem::take(&mut self.tids);
        let until = Instant::now() + TIMEOUT;
        while !reap_native_group(tgid, &mut pending) {
            if Instant::now() >= until {
                let handle = self.kill_handle.take();
                std::thread::spawn(move || {
                    let _identity = handle;
                    while !reap_native_group(tgid, &mut pending) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    let _ = child.wait();
                });
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let _ = child.wait(); // Raw terminal waits already consumed the statuses.
    }
}

fn discover_native_tasks(tgid: libc::pid_t, pending: &mut BTreeSet<libc::pid_t>) {
    if let Ok(directory) = fs::read_dir(format!("/proc/{tgid}/task")) {
        for entry in directory.flatten() {
            if let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse().ok())
            {
                pending.insert(tid);
            }
        }
    }
}

fn reap_native_group(tgid: libc::pid_t, pending: &mut BTreeSet<libc::pid_t>) -> bool {
    // Discover a clone whose event was pending if a baseline assertion failed.
    // Stop discovery once the leader has been reaped, so PID reuse cannot add
    // another process's tasks to this cleanup owner.
    if pending.contains(&tgid) {
        discover_native_tasks(tgid, pending);
    }
    for tid in pending.clone() {
        let mut status = 0;
        // SAFETY: each ID belongs to this oracle's recorded thread group.
        let result = unsafe { libc::waitpid(tid, &mut status, libc::WNOHANG | libc::__WALL) };
        if (result == tid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)))
            || (result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
        {
            pending.remove(&tid);
        }
    }
    pending.is_empty()
}

fn native_wait(tid: libc::pid_t, deadline: Instant) -> i32 {
    loop {
        let mut status = 0;
        // SAFETY: the independent observer exclusively owns this exact task.
        let result = unsafe { libc::waitpid(tid, &mut status, libc::WNOHANG | libc::__WALL) };
        if result == tid {
            return status;
        }
        assert!(
            result != -1 || io::Error::last_os_error().raw_os_error() == Some(libc::EINTR),
            "native group wait: {}",
            io::Error::last_os_error()
        );
        assert!(
            Instant::now() < deadline,
            "native group wait exceeded deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn native_trace(request: u32, tid: libc::pid_t, address: usize, data: usize) {
    // SAFETY: callers own a stopped task and supply request-valid scalar args
    // or writable local output storage; child addresses remain numeric.
    let result = unsafe { libc::ptrace(request, tid, address, data) };
    assert_ne!(
        result,
        -1,
        "native ptrace {request}: {}",
        io::Error::last_os_error()
    );
}

fn native_registers(tid: libc::pid_t) -> RegisterSnapshot {
    let mut raw = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    native_trace(libc::PTRACE_GETREGS, tid, 0, raw.as_mut_ptr() as usize);
    // SAFETY: successful GETREGS initialized the complete structure.
    unsafe { raw.assume_init() }.into()
}

fn native_xstate(tid: libc::pid_t) -> Vec<u8> {
    let mut bytes = vec![0; 64 * 1024];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    native_trace(
        libc::PTRACE_GETREGSET,
        tid,
        0x202,
        (&raw mut vector) as usize,
    );
    assert!(vector.iov_len >= 512 && vector.iov_len < bytes.len());
    bytes.truncate(vector.iov_len);
    bytes
}

fn native_memory(tid: libc::pid_t, address: u64, len: usize) -> Vec<u8> {
    assert_eq!(address % 8, 0);
    assert_eq!(len % 8, 0);
    let mut bytes = Vec::new();
    for offset in (0..len).step_by(8) {
        // SAFETY: errno is thread-local; PEEKDATA only reads this owned task.
        let word = unsafe {
            *libc::__errno_location() = 0;
            let word = libc::ptrace(libc::PTRACE_PEEKDATA, tid, address as usize + offset, 0);
            assert!(word != -1 || *libc::__errno_location() == 0);
            word as u64
        };
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[test]
fn concurrent_cpuid_matches_independent_native_group_state_for_every_worker() {
    let directory = FixtureDirectory::new();
    let image = fixture(&directory, false, WorkerProgram::Differential);
    let native = NativeGroup::launch(&image).after_native_cpuid(&image);
    let marker = BASE + image.marker.unwrap() as u64;
    let mut gate = gate(&image, TIMEOUT);
    let mut owned = gate.worker_ids().to_vec();
    owned.push(gate.pid());
    let mut first = BTreeMap::new();
    let mut compared = BTreeSet::new();
    let mut exited = BTreeSet::new();
    loop {
        match gate.next_event().unwrap() {
            ConcurrentEvent::Observe { tid, observation } => {
                let id = observation.registers.r12;
                assert!((1..=WORKERS as u64).contains(&id));
                if observation.site.address == BASE + image.site as u64 {
                    assert!(first.insert(tid, id).is_none());
                    assert_eq!(observation.registers.rax, 0);
                    assert_eq!(observation.registers.rcx, 0);
                    assert_eq!(observation.registers.rsp, STACK_BASE + STACK_SIZE * id - 32);
                } else {
                    assert_eq!(observation.site.address, marker);
                    assert_eq!(first.get(&tid), Some(&id));
                    assert!(compared.insert(id), "worker was compared twice");
                    let actual = NativeEvidence {
                        registers: observation.registers,
                        xstate: observation.xstate,
                        initialized_stack: gate.read_memory(observation.registers.rsp, 32).unwrap(),
                    };
                    let expected = native.get(&id).unwrap();
                    // Worker stacks have fixed ELF addresses: no GPR, flags,
                    // xstate byte, memory byte or RSP delta is normalized.
                    assert_eq!(
                        &actual, expected,
                        "worker {id} diverged from native execution"
                    );
                    let mut wrong = expected.clone();
                    wrong.registers.rsp += 16;
                    assert_ne!(actual, wrong, "RSP+16 must not pass the comparator");
                    let mut wrong = expected.clone();
                    wrong.registers.r11 ^= 1;
                    assert_ne!(actual, wrong);
                    let mut wrong = expected.clone();
                    wrong.registers.eflags ^= 1;
                    assert_ne!(actual, wrong);
                    let mut wrong = expected.clone();
                    wrong.xstate[160] ^= 1;
                    assert_ne!(actual, wrong);
                    let mut wrong = expected.clone();
                    wrong.initialized_stack[0] ^= 1;
                    assert_ne!(actual, wrong);
                }
            }
            ConcurrentEvent::WorkerExited { tid, code } => {
                let id = *first.get(&tid).unwrap();
                assert_eq!(code as u64, id);
                assert!(compared.contains(&id));
                assert!(exited.insert(tid));
            }
            ConcurrentEvent::Complete => break,
        }
    }
    assert_eq!(first.len(), WORKERS);
    assert_eq!(compared.len(), WORKERS);
    assert_eq!(exited.len(), WORKERS);
    assert_eq!(gate.metrics().gate.observations, WORKERS * 2);
    assert_eq!(gate.metrics().publication_bundles, 1);
    assert_eq!(gate.metrics().gate.admitted_pages, 2);
    assert!(
        gate.metrics()
            .faults_per_rendezvous
            .iter()
            .any(|&faults| faults >= 2)
    );
    assert_reaped(&owned);
}

#[test]
fn concurrent_saved_call_returns_refuse_selected_destination_while_still_nx() {
    let directory = FixtureDirectory::new();
    let image = fixture(&directory, false, WorkerProgram::SavedReturn);
    // Original code is valid for every actual worker; the later gate refusal
    // cannot be explained by a broken CALL/RET fixture.
    NativeGroup::launch(&image).run_to_exit(&image);
    let destination = BASE + image.marker.unwrap() as u64;
    let mut gate = gate(&image, TIMEOUT);
    let mut owned = gate.worker_ids().to_vec();
    owned.push(gate.pid());
    let mut observed = BTreeSet::new();
    for _ in 0..WORKERS {
        let ConcurrentEvent::Observe { tid, observation } = gate.next_event().unwrap() else {
            panic!("worker did not reach the callee before its saved return");
        };
        assert!(observed.insert(tid));
        assert_eq!(observation.site.address, BASE + image.site as u64);
        let id = observation.registers.r12;
        assert!((1..=WORKERS as u64).contains(&id));
        assert_eq!(observation.registers.rsp, STACK_BASE + STACK_SIZE * id - 8);
        let saved: [u8; 8] = gate
            .read_memory(observation.registers.rsp, 8)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(u64::from_le_bytes(saved), destination);
        assert!(!gate.is_admitted(destination));
        assert_kernel_nx(gate.pid(), destination);
        let obligations: Vec<_> = gate
            .call_returns()
            .obligations_in(
                liteinst_admission::AddressRange::new(destination, destination + PAGE as u64)
                    .unwrap(),
            )
            .collect();
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].call_address, destination - 5);
        assert_eq!(obligations[0].return_pc, destination);
        assert_eq!(obligations[0].call_bytes[0], 0xe8);
    }
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused(
            "potential saved CALL return intersects selected publication"
        ))
    ));
    assert!(!gate.is_admitted(destination));
    assert_kernel_nx(gate.pid(), destination);
    assert_eq!(
        gate.read_memory(destination, PAGE).unwrap(),
        image.bytes[3 * PAGE..4 * PAGE]
    );
    assert_eq!(gate.metrics().gate.observations, WORKERS);
    assert_eq!(gate.metrics().gate.admitted_pages, 2);
    assert_eq!(gate.metrics().publication_bundles, 1);
    assert!(gate.next_event().is_err());
    drop(gate);
    assert_reaped(&owned);
}
