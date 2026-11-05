// Included beneath ordered_trace solely to reuse its unchanged private ptrace,
// XSAVE, event-recording and complete architectural comparison primitives.
use super::*;
use liteinst::controls::{
    ControlIdentity, ControlledAction, PointObservationAction, ProbeControl,
};
use liteinst::scanner::InstructionScanner;
use liteinst::trampoline::{HookContext, TrampolinePlan};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

const ENV: &str = "LITEINST_EARLY_REAL_WRITER_CASE";
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const CODE: [u8; 12] = [
    0x48, 0x89, 0xc8, 0x48, 0x01, 0xd8, 0x48, 0x8b, 0x54, 0x24, 0xf8, 0xc3,
];
const MAGIC: u64 = 0x4c49324541524c59;
const ATTACH: u64 = 1;
const STORE: u64 = 2;
const FINISH: u64 = 3;
const DONE: u64 = 4;

core::arch::global_asm!(
    ".pushsection .text",
    ".global liteinst_early_race_ready",
    ".type liteinst_early_race_ready,@function",
    "liteinst_early_race_ready:",
    "int3",
    ".global liteinst_early_race_parked",
    "liteinst_early_race_parked:",
    "ret",
    ".size liteinst_early_race_ready, .-liteinst_early_race_ready",
    ".popsection",
);
unsafe extern "C" {
    fn liteinst_early_race_ready();
    fn liteinst_early_race_parked();
}
thread_local! {
    static EXPECTED_CONTROL: RefCell<Option<ProbeControl>> = const { RefCell::new(None) };
}

unsafe extern "C" fn observe(context: *mut HookContext, identity: ControlIdentity<'_>) {
    let matches = EXPECTED_CONTROL.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|control| control.has_identity(identity))
    });
    if !matches {
        // SAFETY: no unwinding through an actual generated callback.
        unsafe { libc::_exit(122) };
    }
    // SAFETY: this worker retains its own active bounded TLS log and live frame.
    unsafe {
        record_hook_event(10, (*context).instruction_pointer);
        core::arch::asm!("add rax, 1", "pxor xmm0, xmm0", "fninit", out("rax") _, out("xmm0") _, options(nostack));
    }
}

// One fixed socket, fixed-size records, and one shared case deadline. It never
// reads a pipe waiting for EOF before reaping or refreshes a timeout on progress.
struct Link {
    stream: UnixStream,
    deadline: Instant,
}
impl Link {
    fn new(stream: UnixStream, deadline: Instant) -> Self {
        stream.set_nonblocking(true).unwrap();
        Self { stream, deadline }
    }
    fn transfer(&mut self, bytes: &mut [u8], writing: bool) {
        let mut used = 0;
        while used != bytes.len() {
            assert!(
                Instant::now() < self.deadline,
                "race protocol deadline exhausted"
            );
            let result = if writing {
                self.stream.write(&bytes[used..])
            } else {
                self.stream.read(&mut bytes[used..])
            };
            match result {
                Ok(0) => panic!("race protocol premature EOF/write-zero"),
                Ok(n) => used += n,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_micros(100))
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(error) => panic!("race protocol: {error}"),
            }
        }
    }
    fn send(&mut self, words: &[u64]) {
        let mut bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        self.transfer(&mut bytes, true);
    }
    fn receive<const N: usize>(&mut self) -> [u64; N] {
        let mut bytes = vec![0; N * 8];
        self.transfer(&mut bytes, false);
        std::array::from_fn(|index| {
            u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
        })
    }
}

// Fixed remote geometry; these are addresses in the exec child, never borrowed
// as local Mapping owners. The emitted page and metadata are authenticated both
// by its live emitter owner and by the external tracer before native execution.
#[derive(Clone, Copy)]
struct Geometry {
    words: [u64; 25],
}
impl Geometry {
    fn pid(self) -> i32 {
        i32::try_from(self.words[1]).unwrap()
    }
    fn tid(self) -> i32 {
        i32::try_from(self.words[2]).unwrap()
    }
    fn code(self) -> u64 {
        self.words[4]
    }
    fn image(self) -> u64 {
        self.words[5]
    }
    fn entry(self) -> u64 {
        self.words[6]
    }
    fn post_load(self) -> u64 {
        self.words[7]
    }
    fn observer(self) -> u64 {
        self.words[8]
    }
    fn body(self) -> u64 {
        self.words[9]
    }
    fn data(self) -> u64 {
        self.words[10]
    }
    fn stack(self) -> u64 {
        self.words[11]
    }
    fn rsp(self) -> u64 {
        self.words[12]
    }
    fn terminal(self) -> u64 {
        self.words[13]
    }
    fn log(self) -> u64 {
        self.words[14]
    }
    fn control(self) -> u64 {
        self.words[15]
    }
    fn parked(self) -> u64 {
        self.words[16]
    }
    fn boundaries(self, candidate: bool) -> [u64; 5] {
        if candidate {
            [
                self.body(),
                self.words[17],
                self.words[18],
                self.code() + 11,
                self.terminal(),
            ]
        } else {
            [
                self.code(),
                self.code() + 3,
                self.code() + 6,
                self.code() + 11,
                self.terminal(),
            ]
        }
    }
}

fn tracee_process(index: usize) {
    assert!(index < 4);
    let initial = index & 1 == 0;
    let deadline = Instant::now() + CHILD_BUDGET;
    // SAFETY: the exec parent alone installed this private socket at fd 3.
    let mut link = Link::new(unsafe { UnixStream::from_raw_fd(3) }, deadline);
    let (setup_tx, setup_rx) = mpsc::sync_channel(1);
    let (attach_tx, attach_rx) = mpsc::sync_channel(1);
    let controller_tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    let worker = std::thread::spawn(move || {
        let (oracle, mut adjacent) = NativeOracle::with_adjacent_code_mappings(&CODE, &[PAGE]);
        let mapping = adjacent.pop().unwrap();
        let (control, writer) = ProbeControl::new_managed_bound(observe, initial);
        let control = Box::new(control);
        EXPECTED_CONTROL.with(|slot| *slot.borrow_mut() = Some((*control).clone()));
        let base = oracle.code.address();
        let scan = InstructionScanner::default()
            .scan(&CODE[..11], base)
            .unwrap();
        let action = PointObservationAction::EarlyIfEnabled(ControlledAction {
            logical_pc: base,
            control: (*control).clone(),
        });
        let plan =
            TrampolinePlan::from_point_observation_actions(&scan, base, base + 11, &[action])
                .unwrap();
        let image = plan.emit_at(mapping.address()).unwrap();
        assert!(image.bytes().len() <= PAGE);
        assert_eq!(image.early_control_gates().len(), 1);
        assert_eq!(image.entry_routes().len(), 3);
        assert_eq!(image.instruction_boundaries().len(), 3);
        let gate = image.early_control_gates()[0];
        assert_eq!(gate.logical_pc, base);
        let entry = |pc| {
            image
                .entry_routes()
                .iter()
                .find(|(logical, _)| *logical == pc)
                .unwrap()
                .1
        };
        let body = |pc| {
            image
                .instruction_boundaries()
                .iter()
                .find(|(logical, _)| *logical == pc)
                .unwrap()
                .1
        };
        assert_eq!((entry(base), body(base)), (gate.entry, gate.original_body));
        mapping.initialize(0, &vec![0xcc; PAGE]);
        mapping.initialize(0, image.bytes());
        mapping.protect(libc::PROT_READ | libc::PROT_EXEC);
        oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        let log = HookEventLog::with_capacity(1);
        let activation = log.activate(); // Worker-local TLS, before attachment.
        let geometry = Geometry {
            words: [
                MAGIC,
                unsafe { libc::getpid() } as u64,
                unsafe { libc::syscall(libc::SYS_gettid) } as u64,
                controller_tid,
                base,
                mapping.address(),
                gate.entry,
                gate.post_load,
                gate.observing_entry,
                gate.original_body,
                oracle.data.address(),
                oracle.stack.address(),
                oracle.initial_rsp,
                oracle.return_pc(),
                log.memory.address(),
                (&*control as *const ProbeControl) as u64,
                liteinst_early_race_parked as *const () as u64,
                body(base + 3),
                body(base + 6),
                image.bytes().len() as u64,
                u64::from(control.is_enabled()),
                SEEDS[index / 2],
                index as u64,
                PAGE as u64,
                (STACK_BYTES + PAGE) as u64,
            ],
        };
        setup_tx
            .send((
                writer,
                (*control).clone(),
                geometry,
                mapping.bytes().to_vec(),
            ))
            .unwrap();
        attach_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap();
        // SAFETY: the parent has attached to this worker alone. The dedicated
        // trap is outside all application/image code; its parked state is later
        // restored exactly so RET resumes this worker and drops its TLS guard.
        unsafe { liteinst_early_race_ready() };
        assert_eq!(oracle.code.bytes(), oracle.original_code);
        assert_eq!(&mapping.bytes()[..image.bytes().len()], image.bytes());
        drop(activation);
        EXPECTED_CONTROL.with(|slot| *slot.borrow_mut() = None);
    });
    let (mut writer, control, geometry, mut image) = setup_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap();
    link.send(&geometry.words);
    link.transfer(&mut image, true);
    assert_eq!(link.receive::<4>(), [ATTACH, 0, 0, geometry.control()]);
    attach_tx.send(()).unwrap();
    for sequence in [1, 2] {
        let enabled = if sequence == 1 { !initial } else { true };
        assert_eq!(
            link.receive::<4>(),
            [STORE, sequence, u64::from(enabled), geometry.control()]
        );
        // The only write capability is held here, in the same process as the
        // worker. This is a real release store, not a tracer/parent-side poke.
        writer.set_enabled(enabled);
        assert_eq!(control.is_enabled(), enabled);
        link.send(&[
            STORE,
            sequence,
            u64::from(control.is_enabled()),
            geometry.control(),
        ]);
    }
    assert_eq!(link.receive::<4>(), [FINISH, 3, 0, geometry.control()]);
    while !worker.is_finished() {
        assert!(Instant::now() < deadline, "worker join deadline exhausted");
        std::thread::sleep(Duration::from_micros(100));
    }
    worker.join().unwrap();
    link.send(&[DONE, 3, 0, geometry.control()]);
}

// Own the entire exec process group as well as the one seized worker. Reuse
// Tracee's requests/step/state reads, but not its single-fork-child Drop: this
// adapter must reap both the attached TID and the real process under one bound.
struct CaseOwner {
    process: Child,
    worker: Option<ManuallyDrop<Tracee>>,
    complete: bool,
}
impl CaseOwner {
    fn close(&mut self, kill: bool, deadline: Instant) {
        let pid = self.process.id() as i32;
        if kill {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        loop {
            assert!(
                Instant::now() < deadline,
                "race process/thread cleanup incomplete"
            );
            if let Some(worker) = &self.worker {
                let mut status = 0;
                let got =
                    unsafe { libc::waitpid(worker.pid, &mut status, libc::__WALL | libc::WNOHANG) };
                if got == worker.pid && libc::WIFSTOPPED(status) && kill {
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_CONT,
                            worker.pid,
                            0_usize,
                            libc::SIGKILL as usize,
                        );
                    }
                }
                assert!(
                    got >= 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                );
            }
            if let Some(status) = self.process.try_wait().unwrap() {
                if !kill {
                    assert!(status.success(), "race tracee failed: {status}");
                }
                if !std::path::Path::new(&format!("/proc/{pid}")).exists()
                    && unsafe { libc::kill(-pid, 0) } == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    let mut status = 0;
                    for owned in
                        std::iter::once(pid).chain(self.worker.as_ref().map(|worker| worker.pid))
                    {
                        assert_eq!(
                            unsafe {
                                libc::waitpid(owned, &mut status, libc::__WALL | libc::WNOHANG)
                            },
                            -1
                        );
                        assert_eq!(
                            std::io::Error::last_os_error().raw_os_error(),
                            Some(libc::ECHILD)
                        );
                    }
                    self.complete = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for CaseOwner {
    fn drop(&mut self) {
        if !self.complete {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.close(true, Instant::now() + Duration::from_secs(2))
            }));
            if result.is_err() {
                // Cleanup failure cannot become a successful test or a second
                // panic which loses ownership. The isolated outer test fails.
                eprintln!("early-control race: owned group cleanup failed");
                std::process::abort();
            }
        }
    }
}

fn mapped(pid: i32, address: u64, len: usize, permissions: &str) {
    let end = address.checked_add(len as u64).unwrap();
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    assert!(
        maps.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let (start, stop) = fields.next().unwrap().split_once('-').unwrap();
            u64::from_str_radix(start, 16).unwrap() <= address
                && end <= u64::from_str_radix(stop, 16).unwrap()
                && fields.next() == Some(permissions)
        }),
        "unexpected mapping {address:#x}+{len:#x} {permissions}"
    );
}

fn write_memory(child: &Tracee, address: u64, bytes: &[u8]) {
    let local = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: only fixture data/accessible stack/log ranges are reset, while
    // their sole worker is stopped. No control/code/TLS storage is written.
    assert_eq!(
        unsafe { libc::process_vm_writev(child.pid, &local, 1, &remote, 1, 0) },
        bytes.len() as isize
    );
}

fn seeded_registers(
    mut registers: libc::user_regs_struct,
    geometry: Geometry,
    seed: u64,
) -> libc::user_regs_struct {
    let mut state = seed;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    registers.rax = next();
    registers.rbx = next();
    registers.rcx = next();
    registers.rdx = next();
    registers.rbp = next();
    registers.rsi = geometry.data() + 512;
    registers.rdi = geometry.data();
    registers.r8 = next();
    registers.r9 = next();
    registers.r10 = next();
    registers.r11 = next();
    registers.r12 = next();
    registers.r13 = next();
    registers.r14 = next();
    registers.r15 = next();
    registers.rsp = geometry.rsp();
    registers.rip = geometry.code();
    registers.orig_rax = u64::MAX;
    registers.eflags = 0xad7 | ((seed & 1) << 10);
    registers
}

fn immutable(child: &Tracee, geometry: Geometry, source: &[u8], image: &[u8]) {
    assert_eq!(
        child.memory(geometry.code(), PAGE),
        source,
        "source bytes changed"
    );
    assert_eq!(
        child.memory(geometry.image(), PAGE),
        image,
        "image bytes changed"
    );
}
fn snapshot(child: &Tracee, geometry: Geometry, logical_pc: u64) -> Snapshot {
    Snapshot {
        logical_pc,
        registers: child.registers(),
        xstate: canonical_xstate(&child.xstate()),
        data: child.memory(geometry.data(), PAGE),
        application_stack: child.memory(
            geometry.rsp() - 128,
            (geometry.stack() + (STACK_BYTES + PAGE) as u64 - (geometry.rsp() - 128)) as usize,
        ),
    }
}
fn assert_log(child: &Tracee, geometry: Geometry, observed: bool) {
    // Same complete-page representation/unused-zero/overflow requirement as
    // HookEventLog::assert_events; capacity is exactly one, never masked.
    let mut expected = vec![0; PAGE];
    if observed {
        expected[..8].copy_from_slice(&1_u64.to_ne_bytes());
        expected[16..24].copy_from_slice(&10_u64.to_ne_bytes());
        expected[24..32].copy_from_slice(&geometry.code().to_ne_bytes());
    }
    assert_eq!(
        child.memory(geometry.log(), PAGE),
        expected,
        "complete hook log mismatch"
    );
}

fn trace(
    child: &Tracee,
    link: &mut Link,
    geometry: Geometry,
    invocation: usize,
    initial: bool,
    source: &[u8],
    image: &[u8],
) -> Vec<Snapshot> {
    let logical = geometry.boundaries(false);
    let boundaries = geometry.boundaries(invocation != 0);
    let mut next = 0;
    let mut points = Vec::new();
    let (mut entries, mut loads, mut helpers) = (0, 0, 0);
    let mut load_address = None;
    for step in 0..=MAX_STEPS {
        assert!(
            Instant::now() < child.deadline,
            "shared case deadline exhausted"
        );
        let registers = child.registers();
        let pc = registers.rip;
        if invocation != 0 {
            if pc == geometry.entry() {
                entries += 1;
            }
            if pc.checked_add(3) == Some(geometry.post_load()) {
                assert_eq!(
                    child.memory(pc, 3),
                    [0x0f, 0xb6, 0x09],
                    "not the exact byte-sized MOVZX ECX,[RCX]"
                );
                mapped(geometry.pid(), registers.rcx, 1, "rw-p");
                assert_eq!(
                    child.memory(registers.rcx, 1),
                    [u8::from(if invocation == 1 { initial } else { true })]
                );
                load_address = Some(registers.rcx);
            }
            if pc == geometry.post_load() {
                loads += 1;
                assert_eq!(loads, 1);
                let address = load_address.expect("post-load without actual MOVZX witness");
                assert_eq!(
                    registers.rcx,
                    u64::from(if invocation == 1 { initial } else { true })
                );
                if invocation == 1 {
                    let stopped = snapshot(child, geometry, geometry.code());
                    assert_log(child, geometry, false);
                    let command = [STORE, 1, u64::from(!initial), geometry.control()];
                    link.send(&command);
                    assert_eq!(link.receive::<4>(), command);
                    assert_eq!(
                        child.memory(address, 1),
                        [u8::from(!initial)],
                        "real writer did not change the actual loaded byte"
                    );
                    assert_eq!(
                        child.registers().rcx,
                        u64::from(initial),
                        "stopped load result changed during acknowledgement"
                    );
                    assert_state(&stopped, &snapshot(child, geometry, geometry.code()));
                    assert_log(child, geometry, false);
                    immutable(child, geometry, source, image);
                }
            }
            if pc == geometry.observer() {
                helpers += 1;
            }
            if invocation == 1 && !initial {
                assert!(
                    !(geometry.observer()..geometry.body()).contains(&pc),
                    "loaded-false path entered full helper"
                );
            }
        }
        if pc == boundaries[next] {
            immutable(child, geometry, source, image);
            assert_log(child, geometry, invocation == 2);
            points.push(snapshot(child, geometry, logical[next]));
            next += 1;
            if next == boundaries.len() {
                break;
            }
        } else {
            assert!(
                !boundaries.contains(&pc),
                "reordered/repeated restored visit"
            );
        }
        assert!(step < MAX_STEPS, "race trace instruction budget exhausted");
        child.step(&[]);
    }
    assert_eq!(points.len(), 5);
    if invocation != 0 {
        assert_eq!(
            (entries, loads, helpers),
            (1, 1, usize::from(invocation == 2 || initial))
        );
    }
    points
}

fn case(test: &str, index: usize) {
    let deadline = Instant::now() + CHILD_BUDGET;
    let (parent_socket, child_socket) = UnixStream::pair().unwrap();
    let fd = child_socket.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(ENV, index.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0);
    // SAFETY: post-fork hook only duplicates the owned socket and clears CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut owner = CaseOwner {
        process: command.spawn().unwrap(),
        worker: None,
        complete: false,
    };
    drop(child_socket);
    let mut link = Link::new(parent_socket, deadline);
    let geometry = Geometry {
        words: link.receive(),
    };
    let mut image = vec![0; PAGE];
    link.transfer(&mut image, false);
    let initial = index & 1 == 0;
    assert_eq!(geometry.words[0], MAGIC);
    assert_eq!(geometry.pid(), owner.process.id() as i32);
    assert_eq!(
        geometry.words[20..],
        [
            u64::from(initial),
            SEEDS[index / 2],
            index as u64,
            PAGE as u64,
            (STACK_BYTES + PAGE) as u64
        ]
    );
    let threads = [geometry.words[1], geometry.words[2], geometry.words[3]];
    assert_eq!(threads.into_iter().collect::<BTreeSet<_>>().len(), 3);
    let actual: BTreeSet<_> = std::fs::read_dir(format!("/proc/{}/task", geometry.pid()))
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .collect();
    assert_eq!(actual, threads.into_iter().collect());
    assert_eq!(unsafe { libc::getpgid(geometry.pid()) }, geometry.pid());
    assert_eq!(geometry.rsp(), geometry.stack() + STACK_BYTES as u64 - 8);
    assert_eq!(geometry.terminal(), geometry.code() + (PAGE / 2) as u64);
    assert_eq!(geometry.image(), geometry.code() + PAGE as u64);
    assert!((1..=PAGE as u64).contains(&geometry.words[19]));
    assert!(
        geometry.entry() < geometry.post_load()
            && geometry.post_load() < geometry.observer()
            && geometry.observer() < geometry.body()
    );
    for address in [
        geometry.entry(),
        geometry.post_load(),
        geometry.observer(),
        geometry.body(),
        geometry.words[17],
        geometry.words[18],
    ] {
        assert!((geometry.image()..geometry.image() + geometry.words[19]).contains(&address));
    }
    for address in [geometry.code(), geometry.image()] {
        mapped(geometry.pid(), address, PAGE, "r-xp");
    }
    for address in [geometry.data(), geometry.log()] {
        mapped(geometry.pid(), address, PAGE, "rw-p");
    }
    mapped(
        geometry.pid(),
        geometry.control(),
        std::mem::size_of::<ProbeControl>(),
        "rw-p",
    );
    mapped(geometry.pid(), geometry.stack(), PAGE, "---p");
    mapped(
        geometry.pid(),
        geometry.stack() + PAGE as u64,
        STACK_BYTES,
        "rw-p",
    );
    mapped(geometry.pid(), geometry.parked() - 1, 2, "r-xp");
    let child = Tracee {
        pid: geometry.tid(),
        deadline,
        reaped: Cell::new(false),
    };
    // Install ownership before attaching: failure cleanup always covers both
    // the exact exec group and this TID, including an early seize/trap failure.
    owner.worker = Some(ManuallyDrop::new(child));
    let child = owner.worker.as_ref().unwrap();
    child.request(libc::PTRACE_SEIZE, 0, libc::PTRACE_O_EXITKILL as usize);
    link.send(&[ATTACH, 0, 0, geometry.control()]);
    let status = child.wait();
    assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP);
    let parked = child.registers();
    let parked_xstate = child.xstate();
    assert_eq!(parked.rip, geometry.parked());
    assert_eq!(child.memory(geometry.parked() - 1, 2), [0xcc, 0xc3]);
    let mut source = vec![0xcc; PAGE];
    source[..CODE.len()].copy_from_slice(&CODE);
    immutable(child, geometry, &source, &image);
    let data = child.memory(geometry.data(), PAGE);
    assert_eq!(
        data,
        (0..PAGE).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>()
    );
    let stack = child.memory(geometry.stack() + PAGE as u64, STACK_BYTES);
    let mut expected_stack = vec![0x5a; STACK_BYTES];
    let ret = (geometry.rsp() - geometry.stack() - PAGE as u64) as usize;
    expected_stack[ret..ret + 8].copy_from_slice(&geometry.terminal().to_ne_bytes());
    assert_eq!(stack, expected_stack);
    assert_log(child, geometry, false);
    let parked_state = snapshot(child, geometry, geometry.parked());
    let mut initial_registers = seeded_registers(parked, geometry, SEEDS[index / 2]);
    child.set_xstate(&seeded_xstate(parked_xstate.clone(), SEEDS[index / 2]));
    let initial_xstate = child.xstate();
    let mut baseline = Vec::new();
    for invocation in 0..3 {
        if invocation == 2 {
            let command = [STORE, 2, 1, geometry.control()];
            link.send(&command);
            assert_eq!(link.receive::<4>(), command);
        }
        write_memory(child, geometry.data(), &data);
        write_memory(child, geometry.stack() + PAGE as u64, &stack);
        write_memory(child, geometry.log(), &vec![0; PAGE]);
        initial_registers.rip = if invocation == 0 {
            geometry.code()
        } else {
            geometry.entry()
        };
        child.set_registers(&initial_registers);
        child.set_xstate(&initial_xstate);
        let actual = trace(
            child, &mut link, geometry, invocation, initial, &source, &image,
        );
        if invocation == 0 {
            baseline = actual;
        } else {
            for (expected, observed) in baseline.iter().zip(&actual) {
                assert_state(expected, observed);
            }
        }
    }
    immutable(child, geometry, &source, &image);
    write_memory(child, geometry.data(), &data);
    write_memory(child, geometry.stack() + PAGE as u64, &stack);
    child.set_registers(&parked);
    child.set_xstate(&parked_xstate);
    assert_eq!(child.registers().rip, parked.rip);
    assert_state(&parked_state, &snapshot(child, geometry, geometry.parked()));
    child.request(libc::PTRACE_DETACH, 0, 0);
    link.send(&[FINISH, 3, 0, geometry.control()]);
    assert_eq!(link.receive::<4>(), [DONE, 3, 0, geometry.control()]);
    owner.close(false, deadline);
    let mut extra = [0];
    assert_eq!(
        link.stream.read(&mut extra).unwrap(),
        0,
        "extra race protocol bytes after owned process closure"
    );
    eprintln!(
        "early control race case {index}: original=1 candidates=2 state_boundaries=10 post_load_store=1 worker_joined=true process_reaped=true"
    );
}

pub fn run(test: &str) {
    if let Ok(index) = std::env::var(ENV) {
        tracee_process(index.parse().unwrap());
        return;
    }
    for index in 0..4 {
        case(test, index);
    }
    eprintln!(
        "early controlled real-writer race: four cases, four original traces, eight candidate comparisons, 40 complete state boundaries, four post-load stores, four enabled callbacks; all workers joined and exec groups reaped"
    );
}
