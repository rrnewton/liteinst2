//! Finite real byte point controls. No interval, coalesced redirect, Word,
//! concurrent publication, saved-PC translation or performance qualification.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[allow(dead_code)]
#[path = "../../../tests/support/native_interval_oracle.rs"]
mod oracle;

use liteinst2::contracts::{Epoch, Refusal, ToggleProbe, Visibility};
use liteinst2::controls::ControlledAction;
use liteinst2::rapid::{RapidProbe, RapidTogglePlan};
use liteinst2::scanner::InstructionScanner;
use liteinst2::sync_core::{SyncCore, SyncCoreError, SyncCoreOperation};
use liteinst2::trampoline::{HookContext, TrampolinePlan};
use oracle::native_point::{PointOracle, Published};
use oracle::{HookEvent, record_hook_event};
use rapid_profiler::data_flag::code_toggle::{
    Builder, CodePointSession, Error, Operation, Progress, Status,
};
use rapid_profiler::data_flag::{PointOutcome, PointSpec, PointThread};
use rapid_profiler::frontend::{EntryError, Limits, Observation, PayloadOutcome};
use rapid_profiler::frontend_tls::BridgeError;
use rapid_profiler::generation::{Completion, Config, Disposition, FunctionId, Terminal};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

const PAGE: usize = 4096;
const OFFSETS: [usize; 4] = [64, 128, 192, 256];
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const INSTALL: u64 = 0x504f_494e_5401;
static COUNTS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static REARM: AtomicPtr<Rearm> = AtomicPtr::new(std::ptr::null_mut());
struct Rearm {
    controller: *mut CodePointSession,
    old: Epoch,
    new: Epoch,
    fired: AtomicBool,
    old_report_pending: AtomicBool,
    old_drain_refused: AtomicBool,
}
fn callback_require(value: bool) {
    if !value {
        unsafe { libc::_exit(124) };
    }
}
fn callback_ok<T, E>(value: Result<T, E>) -> T {
    match value {
        Ok(v) => v,
        Err(_) => unsafe { libc::_exit(125) },
    }
}
unsafe fn event(context: *mut HookContext, member: usize) {
    callback_require(!context.is_null());
    let pc = unsafe { (*context).instruction_pointer };
    COUNTS[member].fetch_add(1, Ordering::SeqCst);
    unsafe { record_hook_event(member as u64, pc) };
    if member == 0 {
        let p = REARM.load(Ordering::Acquire);
        if !p.is_null() {
            // One fixture thread, stable Boxes, no outstanding reference to
            // CodePointSession during the native call. The callback's Binding
            // reservation is separate from this exclusively owned controller.
            let rearm = unsafe { &*p };
            callback_require(!rearm.fired.swap(true, Ordering::SeqCst));
            let c = unsafe { &mut *rearm.controller };
            let ticket = callback_ok(callback_ok(c.begin_arm(rearm.new)).execute());
            callback_require(
                callback_ok(CodePointSession::complete(c, &ticket)) == Visibility::Complete,
            );
            let pending = callback_ok(c.report(rearm.old)).is_none();
            rearm.old_report_pending.store(pending, Ordering::SeqCst);
            callback_require(pending);
            let refused = matches!(ToggleProbe::close_and_drain(c, rearm.old),
                Err(Refusal::Backend(message)) if message == "Metadata(\"point callbacks still admitted\")");
            rearm.old_drain_refused.store(refused, Ordering::SeqCst);
            callback_require(refused);
        }
    }
}
unsafe extern "C" fn a(c: *mut HookContext) {
    unsafe { event(c, 0) };
}
unsafe extern "C" fn b(c: *mut HookContext) {
    unsafe { event(c, 1) };
}
unsafe extern "C" fn c(c: *mut HookContext) {
    unsafe { event(c, 2) };
}
unsafe extern "C" fn mandatory(c: *mut HookContext) {
    unsafe { event(c, 3) };
}
fn counts() -> [usize; 4] {
    std::array::from_fn(|i| COUNTS[i].load(Ordering::SeqCst))
}
fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 4,
        max_invocations: 16,
    }
}
fn specs(base: u64) -> [PointSpec; 4] {
    let callbacks: [liteinst2::trampoline::HookCallback; 4] = [a, b, c, mandatory];
    std::array::from_fn(|i| PointSpec {
        pc: base + OFFSETS[i] as u64,
        group: i / 2,
        function: (i < 3).then_some(FunctionId(11 + i as u64)),
        callback: callbacks[i],
    })
}
fn builder(base: u64) -> Builder {
    Builder::new(
        INSTALL,
        &specs(base),
        Limits {
            epochs: 4,
            threads: 2,
            depth: 4,
            records_per_epoch: 16,
            actions: 32,
        },
    )
    .unwrap()
}

struct Placeholder {
    base: usize,
}
impl Placeholder {
    fn reserve(next: u64) -> Self {
        let page = next as usize & !(PAGE - 1);
        for step in 1..=2047_usize {
            for candidate in [
                page.checked_add(step * 1024 * 1024),
                page.checked_sub(step * 1024 * 1024),
            ]
            .into_iter()
            .flatten()
            {
                if candidate < PAGE
                    || i32::try_from(candidate as i128 + 128 - i128::from(next)).is_err()
                {
                    continue;
                }
                let p = unsafe {
                    libc::mmap(
                        candidate as *mut _,
                        PAGE,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    )
                };
                if p == libc::MAP_FAILED {
                    continue;
                }
                if p as usize == candidate {
                    return Self { base: candidate };
                }
                assert_eq!(unsafe { libc::munmap(p, PAGE) }, 0);
            }
        }
        panic!("required finite rel32 reservation unavailable");
    }
    fn target(&self) -> u64 {
        (self.base + 128) as u64
    }
    fn release_in_child(&self) {
        assert_eq!(unsafe { libc::munmap(self.base as *mut _, PAGE) }, 0);
    }
}
impl Drop for Placeholder {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::munmap(self.base as *mut _, PAGE) }, 0);
    }
}

// Child-owned permanent RW/RX aliases. Only the inherited, exact fixture page
// is replaced; no original callback, PC, TLS or physical owner exists yet.
struct Aliases {
    rx: u64,
    rw: *mut u8,
}
impl Aliases {
    fn child(base: u64, bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), PAGE);
        let fd = unsafe { libc::memfd_create(c"a4-point-child".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::ftruncate(fd, PAGE as libc::off_t) }, 0);
        let rw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(rw, libc::MAP_FAILED);
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), rw.cast(), PAGE) };
        let rx = unsafe {
            libc::mmap(
                base as usize as *mut _,
                PAGE,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                0,
            )
        };
        assert_eq!(rx as usize as u64, base);
        assert_eq!(unsafe { libc::close(fd) }, 0);
        let result = Self {
            rx: base,
            rw: rw.cast(),
        };
        result.assert_bytes(bytes);
        result.permissions();
        result
    }
    fn assert_bytes(&self, expected: &[u8]) {
        assert_eq!(
            unsafe { std::slice::from_raw_parts(self.rw, PAGE) },
            expected
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(self.rx as *const u8, PAGE) },
            expected
        );
    }
    fn permissions(&self) {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let row = |address: u64, len: usize| -> Vec<&str> {
            maps.lines()
                .find_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    let (low, high) = fields[0].split_once('-').unwrap();
                    (u64::from_str_radix(low, 16).unwrap() <= address
                        && address + len as u64 <= u64::from_str_radix(high, 16).unwrap())
                    .then_some(fields)
                })
                .unwrap()
        };
        let rx = row(self.rx, PAGE);
        let rw = row(self.rw as usize as u64, PAGE);
        assert_eq!(rx[1], "r-xs");
        assert_eq!(rw[1], "rw-s");
        assert_eq!(&rx[2..5], &rw[2..5]); // Same offset/dev/inode, two distinct permissions.
        assert_ne!(rx[4], "0");
    }
}
struct Plans {
    builder: Builder,
    actions: Vec<ControlledAction>,
    rapid: Vec<RapidTogglePlan>,
    images: Vec<(u64, Vec<u8>)>,
    boundaries: Vec<(u64, u64)>,
}
fn plans(oracle: &PointOracle, targets: &[Placeholder]) -> Plans {
    let builder = builder(oracle.base());
    let actions = builder.actions();
    let mut rapid = Vec::new();
    let mut images = Vec::new();
    let mut boundaries = Vec::new();
    for (i, action) in actions.iter().enumerate() {
        let pc = action.logical_pc;
        let code = &oracle.source()[OFFSETS[i]..OFFSETS[i] + 6];
        let scanner = InstructionScanner::default();
        let scan = scanner.scan(code, pc).unwrap();
        let plan =
            RapidTogglePlan::from_controlled_scan(&scanner, &scan, code, pc, pc, action).unwrap();
        assert_eq!(plan.target_address(), targets[i].target());
        let template = TrampolinePlan::from_controlled_actions(
            &scan,
            pc,
            pc + 5,
            std::slice::from_ref(action),
        )
        .unwrap();
        let image = template.emit_at(targets[i].target()).unwrap();
        assert!(image.bytes().len() <= PAGE - 128);
        assert_eq!(image.instruction_boundaries().len(), 1);
        assert_eq!(image.instruction_boundaries()[0].0, pc);
        boundaries.extend_from_slice(image.instruction_boundaries());
        images.push((targets[i].target(), image.bytes().to_vec()));
        rapid.push(plan);
    }
    Plans {
        builder,
        actions,
        rapid,
        images,
        boundaries,
    }
}
fn source(original: &[u8], active: [bool; 4]) -> Vec<u8> {
    let mut bytes = original.to_vec();
    for (i, &enabled) in active.iter().enumerate() {
        bytes[OFFSETS[i]] = if enabled { 0xe9 } else { 0xb8 };
    }
    bytes
}
fn images_unchanged(images: &[(u64, Vec<u8>)]) {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    for (address, bytes) in images {
        assert_eq!(
            unsafe { std::slice::from_raw_parts(*address as *const u8, bytes.len()) },
            bytes
        );
        let row = maps
            .lines()
            .find(|line| {
                let (low, high) = line
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                u64::from_str_radix(low, 16).unwrap() <= *address
                    && *address + bytes.len() as u64 <= u64::from_str_radix(high, 16).unwrap()
            })
            .unwrap();
        assert_eq!(row.split_whitespace().nth(1), Some("r-xp"));
    }
}
fn install(
    oracle: &PointOracle,
    targets: &[Placeholder],
    plans: Vec<RapidTogglePlan>,
) -> (Aliases, Vec<RapidProbe>) {
    let aliases = Aliases::child(oracle.base(), oracle.source());
    let mut probes = Vec::new();
    for (i, plan) in plans.into_iter().enumerate() {
        targets[i].release_in_child();
        // Exact exclusive alias/image lifetime, complete MOV/RET heads, no
        // foreign callers or resumes and no allocator thread during handoff.
        let probe = unsafe { RapidProbe::install(plan, aliases.rw.add(OFFSETS[i])) }.unwrap();
        assert!(!probe.is_enabled());
        probe.enable();
        assert!(probe.is_enabled());
        probes.push(probe);
    }
    aliases.assert_bytes(&source(oracle.source(), [true; 4]));
    (aliases, probes)
}
fn call(oracle: &PointOracle, member: usize) {
    let pc = oracle.base() + OFFSETS[member] as u64;
    let function: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(pc as usize) };
    let expected = u32::from_le_bytes(
        oracle.source()[OFFSETS[member] + 1..OFFSETS[member] + 5]
            .try_into()
            .unwrap(),
    );
    assert_eq!(unsafe { function() }, expected);
}
fn completion(thread: &PointThread, epoch: Epoch, member: usize, pc: u64) -> Completion {
    let PointOutcome::Completed {
        completion,
        payload,
    } = thread.diagnostics().unwrap().last.unwrap()
    else {
        panic!("missing real point completion")
    };
    assert_eq!(completion.admission, payload.admission);
    assert_eq!(completion.admission.generation.get(), epoch.0);
    assert_eq!(
        completion.admission.function,
        FunctionId(11 + member as u64)
    );
    assert_eq!(completion.admission.entry_value, pc);
    assert!(payload.thread > 0);
    assert_eq!(completion.disposition, Disposition::Retained { rank: 0 });
    assert_eq!(
        payload.outcome,
        PayloadOutcome::Completed {
            end: Observation::Value(pc),
            completed_children: 0
        }
    );
    assert!(completion.deactivate.is_some());
    completion
}
fn report(c: &CodePointSession, epoch: Epoch, members: &[usize], base: u64) {
    let report = c.report(epoch).unwrap().unwrap();
    assert_eq!(report.generation().get(), epoch.0);
    let rows: Vec<_> = report.records().collect();
    assert_eq!(rows.len(), members.len());
    for (invocation, (row, &member)) in rows.iter().zip(members).enumerate() {
        let pc = base + OFFSETS[member] as u64;
        assert_eq!(row.record.admission.generation.get(), epoch.0);
        assert_eq!(row.record.admission.invocation, invocation);
        assert_eq!(
            row.record.admission.function,
            FunctionId(11 + member as u64)
        );
        assert_eq!(row.record.admission.entry_value, pc);
        assert_eq!(
            row.record.terminal,
            Some(Terminal::Completed {
                value: pc,
                disposition: Disposition::Retained { rank: 0 }
            })
        );
        let payload = row.payload.unwrap();
        assert_eq!(payload.admission, row.record.admission);
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(pc),
                completed_children: 0
            }
        );
    }
}
fn scan(c: &CodePointSession) {
    let t = c.begin_scan().unwrap().execute().unwrap();
    assert_eq!(c.complete(&t), Ok(Visibility::Complete));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Armed,
    Closed,
    Rearmed,
    OldReservation,
}
fn prepare<'a>(
    oracle: &'a PointOracle,
    targets: &'a [Placeholder],
    p: Plans,
    phase: Phase,
    member: usize,
    ret_entry: bool,
    output: PathBuf,
) -> impl FnOnce() + 'a {
    let Plans {
        builder,
        actions,
        rapid,
        images,
        ..
    } = p;
    let (aliases, probes) = install(oracle, targets, rapid);
    for action in &actions {
        assert!(action.control.is_enabled());
        assert!(action.control.clone().try_set_enabled(false).is_err());
        assert!(action.control.is_enabled());
    }
    let capability = SyncCore::prepare().unwrap(); // Prepared in this child, never inherited.
    let mut controller = Box::new(unsafe { builder.bind_bytes(probes, capability) }.unwrap());
    let thread = controller.attach_current_thread().unwrap();
    assert!(controller.attach_current_thread().is_err());
    call(oracle, 0); // Before ARM: optional work refused, mandatory still active.
    assert_eq!(
        thread.diagnostics().unwrap().last,
        Some(PointOutcome::AdmissionRefused(BridgeError::Entry(
            EntryError::NoCurrent
        )))
    );
    call(oracle, 3);
    assert_eq!(counts(), [0, 0, 0, 1]);
    let old = controller.stage(config()).unwrap();
    let new = controller.stage(config()).unwrap();
    let old_ticket = controller.begin_arm(old).unwrap().execute().unwrap();
    assert_eq!(controller.complete(&old_ticket), Ok(Visibility::Complete));
    let mut current = old;
    if matches!(phase, Phase::Closed | Phase::Rearmed) {
        call(oracle, 0);
        let a = completion(&thread, old, 0, oracle.base() + OFFSETS[0] as u64);
        scan(&controller);
        aliases.assert_bytes(&source(oracle.source(), [true; 4])); // B still open.
        call(oracle, 1);
        completion(&thread, old, 1, oracle.base() + OFFSETS[1] as u64);
        scan(&controller);
        aliases.assert_bytes(&source(oracle.source(), [false, false, true, true]));
        call(oracle, 2);
        completion(&thread, old, 2, oracle.base() + OFFSETS[2] as u64);
        scan(&controller);
        aliases.assert_bytes(&source(oracle.source(), [false, false, true, true])); // M forbids removal.
        let t = controller.begin_disarm(old).unwrap().execute().unwrap();
        assert_eq!(controller.complete(&t), Ok(Visibility::Complete));
        report(&controller, old, &[0, 1, 2], oracle.base());
        call(oracle, 2);
        assert_eq!(
            thread.diagnostics().unwrap().last,
            Some(PointOutcome::AdmissionRefused(BridgeError::Entry(
                EntryError::NoCurrent
            )))
        );
        call(oracle, 3);
        assert_eq!(counts(), [1, 1, 1, 2]);
        if phase == Phase::Rearmed {
            let t = controller.begin_arm(new).unwrap().execute().unwrap();
            assert_eq!(controller.complete(&t), Ok(Visibility::Complete));
            current = new;
            let before = controller.history().unwrap();
            assert!(
                controller
                    .begin_deactivate(a.deactivate.unwrap())
                    .unwrap()
                    .is_none()
            );
            assert_eq!(controller.history().unwrap(), before);
            assert_eq!(controller.complete(&old_ticket), Err(Error::Stale));
            aliases.assert_bytes(&source(oracle.source(), [true; 4]));
        }
    }
    let active = if phase == Phase::Closed {
        [false, false, true, true]
    } else {
        [true; 4]
    };
    let expected_source = source(oracle.source(), active);
    aliases.assert_bytes(&expected_source);
    aliases.permissions();
    images_unchanged(&images);
    let before_counts = counts();
    let before_diagnostics = thread.diagnostics().unwrap();
    let rearm = Box::new(Rearm {
        controller: &mut *controller,
        old,
        new,
        fired: AtomicBool::new(false),
        old_report_pending: AtomicBool::new(false),
        old_drain_refused: AtomicBool::new(false),
    });
    if phase == Phase::OldReservation {
        assert_eq!(member, 0);
        REARM.store((&*rearm as *const Rearm).cast_mut(), Ordering::Release);
    }
    move || {
        REARM.store(std::ptr::null_mut(), Ordering::Release);
        let invoked = !ret_entry && (member == 3 || phase != Phase::Closed);
        let mut expected_counts = before_counts;
        expected_counts[member] += usize::from(invoked);
        assert_eq!(counts(), expected_counts);
        if invoked && member < 3 {
            completion(
                &thread,
                current,
                member,
                oracle.base() + OFFSETS[member] as u64,
            );
        } else if !ret_entry && phase == Phase::Closed && member == 2 {
            let d = thread.diagnostics().unwrap();
            assert_eq!(
                d.last,
                Some(PointOutcome::AdmissionRefused(BridgeError::Entry(
                    EntryError::NoCurrent
                )))
            );
            assert_eq!(d.refusals, before_diagnostics.refusals + 1);
        } else {
            assert_eq!(thread.diagnostics().unwrap(), before_diagnostics);
        }
        if phase == Phase::OldReservation && !ret_entry {
            assert!(rearm.fired.load(Ordering::SeqCst));
            assert!(rearm.old_report_pending.load(Ordering::SeqCst));
            assert!(rearm.old_drain_refused.load(Ordering::SeqCst));
            report(&controller, old, &[0], oracle.base());
            let retained_old_report = controller.report(old).unwrap().unwrap();
            let retained_old_records: Vec<_> = retained_old_report.records().collect();
            assert_eq!(retained_old_report.generation().get(), old.0);
            call(oracle, 0);
            completion(&thread, new, 0, oracle.base() + OFFSETS[0] as u64);
            assert_eq!(retained_old_report.generation().get(), old.0);
            assert_eq!(
                retained_old_report.records().collect::<Vec<_>>(),
                retained_old_records
            );
            let fresh_old_report = controller.report(old).unwrap().unwrap();
            assert_eq!(fresh_old_report.generation().get(), old.0);
            assert_eq!(
                fresh_old_report.records().collect::<Vec<_>>(),
                retained_old_records
            );
            current = new;
        } else {
            assert!(!rearm.fired.load(Ordering::SeqCst));
        }
        aliases.assert_bytes(&expected_source);
        images_unchanged(&images);
        let history = controller.history().unwrap();
        assert!(
            history
                .iter()
                .all(|r| r.status == Status::Complete && r.failure.is_none())
        );
        for row in &history {
            assert_eq!(
                row.progress,
                if row.changed_points.is_empty() {
                    Progress::NoStore
                } else {
                    Progress::Bytes {
                        stores_completed: row.changed_points.len(),
                        store_may_have_started: true,
                        synchronized: true,
                    }
                }
            );
        }
        std::fs::write(
            output,
            format!(
                "phase={phase:?}\ncounts={:?}\ndiagnostics={:?}\nhistory={history:#?}\n",
                counts(),
                thread.diagnostics().unwrap()
            ),
        )
        .unwrap();
        // Only after final full-state comparison: close metadata, detach the
        // exact TLS owner, and prove a fresh idle attachment can be made.
        ToggleProbe::close_and_drain(&mut *controller, current).unwrap();
        drop(thread);
        drop(controller.attach_current_thread().unwrap());
        aliases.assert_bytes(&source(oracle.source(), [false, false, true, true]));
        drop(rearm);
        drop(controller); // Process-lifetime code/aliases are not reclaimed.
    }
}

fn mkdir(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    std::fs::create_dir(&path).unwrap();
    path
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "MODE MEMBER_OR_CONTROL SEED_INDEX NEW_OUTPUT"
    );
    let seed: usize = args[3].parse().unwrap();
    assert!(seed < SEEDS.len());
    let output = PathBuf::from(&args[4]);
    assert!(!output.exists());
    std::fs::create_dir(&output).unwrap();
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let mut targets = Vec::new();
    let oracle = PointOracle::new(|base| {
        let mut bytes = vec![0xcc; 512];
        for offset in OFFSETS {
            let pc = base + offset as u64;
            let target = Placeholder::reserve(pc + 5);
            bytes[offset] = 0xb8;
            bytes[offset + 1..offset + 5].copy_from_slice(
                &i32::try_from(i128::from(target.target()) - i128::from(pc + 5))
                    .unwrap()
                    .to_le_bytes(),
            );
            bytes[offset + 5] = 0xc3;
            targets.push(target);
        }
        bytes
    });
    match args[1].as_str() {
        "bytes-real-lifecycle" => {
            let crossing = args[2] == "old-reservation";
            let member: usize = if crossing {
                0
            } else {
                args[2].parse().unwrap()
            };
            assert!(member < 4);
            let phases: &[Phase] = if crossing {
                &[Phase::OldReservation]
            } else {
                &[Phase::Armed, Phase::Closed, Phase::Rearmed]
            };
            let pc = oracle.base() + OFFSETS[member] as u64;
            for ret_entry in [false, true] {
                let entry_dir = mkdir(&output, if ret_entry { "ret-entry" } else { "mov-entry" });
                let heads = if ret_entry {
                    vec![pc + 5, oracle.return_pc()]
                } else {
                    vec![pc, pc + 5, oracle.return_pc()]
                };
                let original =
                    oracle.original(&heads, SEEDS[seed], &entry_dir.join("original.json"));
                for &phase in phases {
                    let phase_dir = mkdir(&entry_dir, &format!("{phase:?}"));
                    let p = plans(&oracle, &targets);
                    let images = p.images.clone();
                    let active = phase != Phase::Closed || member >= 2;
                    let boundaries = if active {
                        p.boundaries.clone()
                    } else {
                        Vec::new()
                    };
                    let events: Vec<_> = (!ret_entry && (member == 3 || phase != Phase::Closed))
                        .then_some(HookEvent {
                            probe_id: member as u64,
                            logical_pc: pc,
                        })
                        .into_iter()
                        .collect();
                    let expected_source = source(
                        oracle.source(),
                        if phase == Phase::Closed {
                            [false, false, true, true]
                        } else {
                            [true; 4]
                        },
                    );
                    oracle.candidate(
                        &original,
                        Published {
                            source: &expected_source,
                            images: &images,
                            boundaries: &boundaries,
                            events: &events,
                        },
                        || {
                            prepare(
                                &oracle,
                                &targets,
                                p,
                                phase,
                                member,
                                ret_entry,
                                phase_dir.join("lifecycle.txt"),
                            )
                        },
                        &phase_dir.join("child.json"),
                    );
                }
            }
            let comparisons = 5 * phases.len();
            println!(
                "{{\"mode\":\"bytes-real-lifecycle\",\"member\":\"{}\",\"seed_index\":{},\"children\":{},\"full_state_comparisons\":{},\"status\":\"PASS\"}}",
                args[2],
                seed,
                2 + 2 * phases.len(),
                comparisons
            );
        }
        "bytes-real-sync-refusal" | "byte-owner-refusals" => {
            negative(&args[1], &args[2], seed, &oracle, &targets, &output)
        }
        _ => panic!("unsupported mode: Word and coalesced modes are UNIMPLEMENTED"),
    }
}

// Exact finite seccomp filter from the existing word-native barrier control.
fn deny_membarrier() {
    // BPF checks x86-64 architecture, denies only SYS_membarrier with EPERM,
    // and allows the signal-mask/route queries and ownership checks afterward.
    let mut filters = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0xc000003e,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x80000000,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::SYS_membarrier as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
    ];
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    // SAFETY: dedicated fresh process, valid finite filter retained for prctl.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
}

fn negative(
    mode: &str,
    control: &str,
    seed: usize,
    oracle: &PointOracle,
    targets: &[Placeholder],
    output: &Path,
) {
    assert_eq!(seed, 0);
    assert!(matches!(
        (mode, control),
        ("bytes-real-sync-refusal", "membarrier")
            | ("byte-owner-refusals", "wrong-owner" | "inactive")
    ));
    let p = plans(oracle, targets);
    let control_output = output.join("control.txt");
    oracle.control(
        || {
            let Plans {
                builder: b,
                actions,
                rapid,
                images,
                ..
            } = p;
            let (aliases, probes) = install(oracle, targets, rapid);
            for (probe, action) in probes.iter().zip(&actions) {
                assert_eq!(
                    probe.plan().controlled_actions(),
                    std::slice::from_ref(action)
                );
            }
            let capability = SyncCore::prepare().unwrap();
            if mode == "byte-owner-refusals" {
                let (b, expected) = if control == "wrong-owner" {
                    let foreign = builder(oracle.base());
                    for (old, new) in actions.iter().zip(foreign.actions()) {
                        assert_eq!(old.logical_pc, new.logical_pc);
                        assert_ne!(old.control, new.control);
                    }
                    (foreign, source(oracle.source(), [true; 4]))
                } else {
                    probes[0].disable();
                    (b, source(oracle.source(), [false, true, true, true]))
                };
                aliases.assert_bytes(&expected);
                assert!(matches!(
                    unsafe { b.bind_bytes(probes, capability) },
                    Err(Error::InvalidInstallation)
                ));
                aliases.assert_bytes(&expected);
                images_unchanged(&images);
                std::fs::write(
                    &control_output,
                    format!("{control}\nInvalidInstallation\nno_store=true\n"),
                )
                .unwrap();
            } else {
                let c = unsafe { b.bind_bytes(probes, capability) }.unwrap();
                let epoch = c.stage(config()).unwrap();
                let ticket = c.begin_arm(epoch).unwrap().execute().unwrap();
                assert_eq!(c.complete(&ticket), Ok(Visibility::Complete));
                let before = c.history().unwrap();
                deny_membarrier();
                let error = Error::Synchronize(SyncCoreError::SystemCall {
                    operation: SyncCoreOperation::Synchronize,
                    errno: libc::EPERM,
                });
                assert!(matches!(c.begin_disarm(epoch).unwrap().execute(), Err(e) if e == error));
                let after = c.history().unwrap();
                assert_eq!(&after[..before.len()], before);
                assert_eq!(after.len(), before.len() + 1);
                let last = after.last().unwrap();
                assert_eq!(last.operation, Operation::Disarm);
                assert_eq!(last.status, Status::Failed);
                assert_eq!(last.failure, Some(error));
                assert_eq!(last.changed_points, vec![0, 1]);
                assert_eq!(last.before_groups, vec![true, true]);
                assert_eq!(last.desired_groups, vec![false, true]);
                assert_eq!(
                    last.progress,
                    Progress::Bytes {
                        stores_completed: 2,
                        store_may_have_started: true,
                        synchronized: false
                    }
                );
                assert_eq!(c.complete(&ticket), Err(Error::Stale));
                assert!(matches!(c.begin_arm(epoch), Err(Error::Terminal)));
                assert_eq!(c.history().unwrap(), after);
                aliases.assert_bytes(&source(oracle.source(), [false, false, true, true]));
                images_unchanged(&images);
                std::fs::write(
                    &control_output,
                    format!("{after:#?}\nno_poisoned_execution=true\n"),
                )
                .unwrap();
                drop(c);
                aliases.assert_bytes(&source(oracle.source(), [false, false, true, true]));
                images_unchanged(&images); // Does not claim private history visibility after Drop.
            }
            || {}
        },
        &output.join("child.json"),
    );
    println!(
        "{{\"mode\":\"{mode}\",\"control\":\"{control}\",\"children\":1,\"full_state_comparisons\":0,\"status\":\"PASS\"}}"
    );
}
