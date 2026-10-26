#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Four finite original-signal trajectories and a strict corruption control.
//! Pristine expected frames never pass through production signal parsing.
#[path = "support/b3_signal/mod.rs"]
mod oracle;
use liteinst_launch::gate::SelectedExecution;
use liteinst_launch::selected::{
    InstructionProvider, ProviderDecision, SelectedInput, SemanticsError,
};
use liteinst_launch::{
    DynamicAdmissionCompletion, DynamicAdmissionEvent, DynamicAdmissionOptions,
    DynamicAdmissionSession, DynamicAdmissionState, DynamicSignalEntry, DynamicSignalFrameEdits,
    DynamicSignalProfile, DynamicSignalReturn, DynamicSignalSession, LaunchCommand,
};
use oracle::image::*;
use oracle::*;
use std::fs;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::time::Instant;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/evaluation/signal-fixtures");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[derive(Default)]
struct Provider {
    inputs: Vec<SelectedInput>,
}
impl InstructionProvider for Provider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        self.inputs.push(input.clone());
        Ok(ProviderDecision::Native)
    }
}
type Session = DynamicSignalSession<Provider>;
fn profile(image: &Image) -> DynamicSignalProfile {
    DynamicSignalProfile {
        signal: SIGNAL as u8,
        queued_value: PAYLOAD,
        action_mask: ACTION_MASK,
        handler: HANDLER,
        restorer: RESTORER,
        delivery_pc: image.ready_pc,
        normal_stack: NORMAL..NORMAL + STACK_LEN as u64,
        alternate_stack: image
            .trajectory
            .altstack()
            .then_some(ALT..ALT + STACK_LEN as u64),
        frame_edits: image
            .trajectory
            .edited()
            .then_some(DynamicSignalFrameEdits {
                landing_pc: LANDING,
                rax: EDITED_RAX,
                clear_carry: true,
                signal_mask: RETURN_MASK,
                xmm0: XMM_EDIT,
            }),
    }
}
fn state(session: &mut Session, observed: &DynamicAdmissionState) -> State {
    let task = observed.task.task;
    let current = session.state(task).unwrap();
    assert_eq!(&current, observed);
    State {
        registers: observed.registers,
        xstate: observed.xstate.clone(),
        mask: observed.signal_mask,
        data: session.read_memory(task, DATA, PAGE).unwrap(),
        normal: session.read_memory(task, NORMAL, STACK_LEN).unwrap(),
        alternate: session.read_memory(task, ALT, STACK_LEN).unwrap(),
    }
}
fn completion(session: &mut Session) -> (DynamicAdmissionCompletion, State) {
    let event = session.next_event().unwrap();
    let DynamicAdmissionEvent::Completed(done) = event else {
        panic!("expected selected completion: {event:?}")
    };
    assert_eq!(done.selected.execution, SelectedExecution::Native);
    let observed = DynamicAdmissionState {
        task: done.after_task,
        registers: done.selected.after,
        xstate: done.selected.xstate.clone(),
        signal_mask: done.signal_mask,
    };
    let actual = state(session, &observed);
    (*done, actual)
}
fn executable(pid: i32, pin: &OwnedFd, address: u64) -> bool {
    live(pin);
    let file = fs::File::open(format!("/proc/{pid}/maps")).unwrap();
    let mut text = String::new();
    file.take(128 * 1024 + 1).read_to_string(&mut text).unwrap();
    assert!(text.len() <= 128 * 1024);
    live(pin);
    let mut permission = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16).unwrap();
        if start <= address && address + PAGE as u64 <= end {
            let p = fields.next().unwrap().as_bytes();
            assert_eq!(p.len(), 4);
            assert_eq!(p[0], b'r');
            assert_eq!(p[1], b'-');
            assert_eq!(p[3], b'p');
            assert!(permission.replace(p[2] == b'x').is_none());
        }
    }
    permission.unwrap()
}
struct GatedTrace {
    setup: Vec<(DynamicAdmissionCompletion, State)>,
    pending: State,
    signal: [u8; 128],
    entry: DynamicSignalEntry,
    handler: State,
    handler_completion: DynamicAdmissionCompletion,
    after_handler: State,
    returned: DynamicSignalReturn,
    return_state: State,
    landing: Option<(DynamicAdmissionCompletion, State)>,
    callbacks: Vec<SelectedInput>,
}
fn gated(image: &Image, ready: SyncSender<raw::Ready>) -> GatedTrace {
    // This client worker is not a wait-domain owner. The production launcher
    // performs its own atomic pre-spawn masking; the supplied app mask is exact.
    let app_mask = Mask::set(APP_MASK);
    let file_fork = FILE_FORK.lock().unwrap();
    // SAFETY: this immutable private fixed ELF has exactly the declared heads,
    // one closed-user delivery loop, one original action/optional altstack, one
    // queued signal and declared literal edits. No competing sender/writer,
    // mappings, tasks, nested frames or unlisted continuation exists.
    let launched = unsafe {
        DynamicAdmissionSession::launch_with_signals(
            &LaunchCommand::new(&image.path),
            vec![image.facts()],
            DynamicAdmissionOptions::default(),
            profile(image),
            Provider::default(),
            TIMEOUT,
        )
    };
    drop(file_fork);
    drop(app_mask);
    let mut session = match launched {
        Ok(session) => session,
        Err(failure) => {
            // A constructor error is not a cleanup receipt. If the native owner
            // started, keep its archive alive under the existing cleanup phase
            // bound before reporting the original failed launch. No PID reopen.
            if failure.native_owner_started() {
                let until = Instant::now() + TIMEOUT;
                let Some(anchor) = failure.anchor.as_ref() else {
                    std::process::abort()
                };
                loop {
                    match anchor.snapshot().cleanup_complete {
                        Some(true) => break,
                        Some(false) => std::process::abort(),
                        None => {}
                    }
                    if Instant::now() >= until {
                        std::process::abort();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            panic!("original signal launch failed after cleanup accounting: {failure:?}");
        }
    };
    let pid = session.pid();
    let pin = match std::panic::catch_unwind(|| pin_live(pid)) {
        Ok(pin) => pin,
        Err(panic) => {
            if session.terminate(TIMEOUT).is_err() {
                std::process::abort();
            }
            std::panic::resume_unwind(panic)
        }
    };
    let original_task = session.initial_state().task;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut setup = Vec::new();
        for call in &image.setup {
            let (done, observed) = completion(&mut session);
            assert_eq!(
                done.selected.input.instruction().logical_pc,
                call.instruction
            );
            assert_eq!(done.selected.input.instruction().bytes(), [0x0f, 0x05]);
            assert_eq!(done.selected.input.registers().rax, call.number);
            assert_eq!(done.selected.after.rax, 0);
            setup.push((done, observed));
        }
        let (first, _) = completion(&mut session);
        assert_eq!(
            first.selected.input.instruction().logical_pc,
            image.pre_signal_cpuid
        );
        assert_eq!(first.selected.input.instruction().bytes(), [0x0f, 0xa2]);
        ready
            .send(raw::Ready {
                pid,
                pin: duplicate(&pin),
            })
            .unwrap();
        let event = session.next_event().unwrap();
        let DynamicAdmissionEvent::SignalPending(pending) = event else {
            panic!("expected exact original queued delivery: {event:?}")
        };
        let signal = *pending.signal.raw_bytes();
        assert_eq!(pending.signal.signal(), SIGNAL);
        assert_eq!(pending.signal.code(), libc::SI_QUEUE);
        assert_eq!(pending.signal.value(), Some(PAYLOAD));
        let pending_state = state(&mut session, &pending.state);
        compare::seeded(image, &pending_state);
        assert!(!executable(pid, &pin, HANDLER));
        assert!(!executable(pid, &pin, RESTORER));
        assert!(!executable(pid, &pin, LANDING));
        for (page, offset) in [
            (HANDLER, 2 * PAGE),
            (RESTORER, 3 * PAGE),
            (LANDING, 4 * PAGE),
        ] {
            assert_eq!(
                session
                    .read_memory(pending.state.task.task, page, PAGE)
                    .unwrap(),
                image.source[offset..offset + PAGE]
            );
        }
        let before = session.metrics().unwrap();
        assert!(before.fetch_faults >= 1);
        assert!(before.guard_stops >= image.setup.len() + 1);
        let entry = session.deliver_signal(&pending.token).unwrap();
        assert_eq!(entry.interrupted, pending.state);
        assert_eq!(entry.signal, pending.signal);
        assert_eq!(entry.raw_frame.id, entry.projected_frame.id);
        assert_eq!(entry.raw_frame.version, 0);
        assert_eq!(entry.projected_frame.version, 1);
        let handler = state(&mut session, &entry.handler);
        assert_eq!(handler.registers.rip, HANDLER);
        let mut armed_handler = image.source[2 * PAGE..3 * PAGE].to_vec();
        armed_handler[0] = 0xcc;
        assert_eq!(
            session
                .read_memory(entry.handler.task.task, HANDLER, PAGE)
                .unwrap(),
            armed_handler
        );
        assert!(!executable(pid, &pin, RESTORER));
        assert!(!executable(pid, &pin, LANDING));
        let actual_frame = Frame::from_state(&handler, handler.registers.rsp);
        assert_eq!(actual_frame.address, entry.projected_frame.address);
        assert_eq!(actual_frame.fpstate, entry.projected_frame.fpstate);
        assert_eq!(actual_frame.bytes, entry.projected_frame.bytes);
        let (handler_completion, after_handler) = completion(&mut session);
        assert_eq!(
            handler_completion.selected.input.instruction().logical_pc,
            HANDLER
        );
        assert_eq!(
            handler_completion.selected.input.registers(),
            &handler.registers
        );
        assert_eq!(handler_completion.selected.before_xstate, handler.xstate);
        compare::cpuid(&handler, &after_handler);
        let event = session.next_event().unwrap();
        let DynamicAdmissionEvent::SignalReturned(returned) = event else {
            panic!("expected distinct genuine signal return, not ordinary Completed: {event:?}")
        };
        assert_eq!(returned.frame, entry.projected_frame.id);
        assert_eq!(returned.input.instruction().logical_pc, image.sigreturn);
        assert_eq!(
            returned.input.registers().rax,
            libc::SYS_rt_sigreturn as u64
        );
        assert_eq!(returned.returned.task.task, original_task.task);
        assert_eq!(returned.returned.task.process, original_task.process);
        assert_eq!(
            returned.returned.task.address_space,
            original_task.address_space
        );
        assert!(returned.returned.task.generation > original_task.generation);
        let return_state = state(&mut session, &returned.returned);
        let frame = Frame::from_state(&return_state, entry.projected_frame.address);
        compare::edited_frame(image, &actual_frame, &frame);
        let landing = if image.trajectory.edited() {
            assert_eq!(return_state.registers.rax, EDITED_RAX);
            assert!(returned.information.is_error);
            assert!(!executable(pid, &pin, LANDING));
            let faults = session.metrics().unwrap().fetch_faults;
            let result = completion(&mut session);
            assert_eq!(result.0.selected.input.instruction().logical_pc, LANDING);
            assert_eq!(result.0.selected.input.registers(), &return_state.registers);
            assert_eq!(result.0.selected.before_xstate, return_state.xstate);
            compare::cpuid(&return_state, &result.1);
            assert_eq!(session.metrics().unwrap().fetch_faults, faults + 1);
            Some(result)
        } else {
            assert_eq!(return_state.registers.rip, image.ready_pc);
            None
        };
        let callbacks = session.provider().inputs.clone();
        let mut expected = image
            .setup
            .iter()
            .map(|call| call.instruction)
            .collect::<Vec<_>>();
        expected.extend([image.pre_signal_cpuid, HANDLER, image.sigreturn]);
        if image.trajectory.edited() {
            expected.push(LANDING);
        }
        assert_eq!(
            callbacks
                .iter()
                .map(|input| input.instruction().logical_pc)
                .collect::<Vec<_>>(),
            expected
        );
        let metrics = session.metrics().unwrap();
        assert_eq!(
            metrics.selected.callbacks.values().sum::<usize>(),
            expected.len()
        );
        assert_eq!(metrics.selected.scripted_completions, 0);
        assert_eq!(metrics.selected.provider_faults, 0);
        assert_eq!(metrics.selected.refusals, 0);
        GatedTrace {
            setup,
            pending: pending_state,
            signal,
            entry,
            handler,
            handler_completion,
            after_handler,
            returned: *returned,
            return_state,
            landing,
            callbacks,
        }
    }));
    // Every assertion/panic path retains this actual session until explicit
    // physical cleanup. Compare cross-lane outcomes only after both joins.
    let cleaned = session.terminate(TIMEOUT);
    match cleaned {
        Ok(receipt) => {
            assert_eq!(receipt.reaped, [pid]);
            reaped(&pin);
        }
        Err(_) => std::process::abort(),
    }
    match result {
        Ok(trace) => trace,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn compare_pair(image: &Image, raw: &raw::Trace, gated: &GatedTrace, nonzero: Option<Metadata>) {
    assert_eq!(raw.rseq_before_exec, [0; 24]);
    assert_eq!(raw.rseq_after_exec, [0; 24]);
    assert_eq!(raw.setup.len(), image.setup.len());
    assert_eq!(gated.setup.len(), raw.setup.len());
    for (observed, expected) in gated.setup.iter().zip(&raw.setup) {
        assert_eq!(observed.1, expected.2);
        assert_eq!(observed.0.selected.after, expected.2.registers);
        assert_eq!(observed.0.selected.xstate, expected.2.xstate);
        assert_eq!(observed.0.signal_mask, expected.2.mask);
        assert_eq!(expected.1.bytes[0], 1);
        assert_eq!(expected.3.bytes[0], 2);
    }
    assert_eq!(gated.pending, raw.before);
    assert_eq!(gated.signal, raw.signal);
    assert_eq!(raw.handler_trap.registers.rip, HANDLER + 1);
    assert_eq!(
        gated.entry.handler_guard.registers,
        raw.handler_trap.registers
    );
    assert_eq!(gated.entry.handler_guard.xstate, raw.handler_trap.xstate);
    assert_eq!(gated.entry.handler_guard.signal_mask, raw.handler_trap.mask);
    assert_eq!(
        gated.entry.handler_guard_signal.raw_bytes(),
        &raw.handler_trap_info
    );
    // This distinct actual NX observation is never used as the logical-head
    // oracle. Its RF remains set; the later real guard consumes it naturally.
    assert_eq!(gated.entry.handler_fetch.registers.rip, HANDLER);
    assert_eq!(
        gated.entry.handler_fetch.registers.eflags,
        FLAGS - (1 << 10) + (1 << 16)
    );
    let mut fetch_expected = raw.handler.registers;
    fetch_expected.eflags = FLAGS - (1 << 10) + (1 << 16);
    assert_eq!(gated.entry.handler_fetch.registers, fetch_expected);
    assert_eq!(gated.entry.handler_fetch.xstate, raw.handler.xstate);
    assert_eq!(gated.entry.handler_fetch.signal_mask, raw.handler.mask);
    assert_eq!(gated.handler, raw.handler);
    let projected = Frame {
        address: gated.entry.projected_frame.address,
        fpstate: gated.entry.projected_frame.fpstate,
        bytes: gated.entry.projected_frame.bytes.clone(),
    };
    assert!(compare::exact(
        &raw.handler,
        &gated.handler,
        &raw.frame,
        &projected
    ));
    let original = raw.frame.metadata();
    assert_eq!(
        (
            gated.entry.original_metadata.trapno,
            gated.entry.original_metadata.error_code,
            gated.entry.original_metadata.cr2
        ),
        (original.trap, original.error, original.cr2)
    );
    if let Some(expected) = nonzero {
        assert_eq!(original, expected);
        assert_eq!(
            (
                gated.entry.original_metadata.trapno,
                gated.entry.original_metadata.error_code,
                gated.entry.original_metadata.cr2
            ),
            (expected.trap, expected.error, expected.cr2)
        );
    }
    let mut raw_kernel = gated.entry.raw_frame.bytes.clone();
    assert_ne!(
        raw_kernel, projected.bytes,
        "instrumentation tuple projection must be nonvacuous"
    );
    for offset in [
        FRAME_UC + UC_CONTEXT + SC_TRAP,
        FRAME_UC + UC_CONTEXT + SC_ERROR,
        FRAME_UC + UC_CONTEXT + SC_CR2,
    ] {
        raw_kernel[offset..offset + 8].copy_from_slice(&raw.frame.bytes[offset..offset + 8]);
    }
    assert_eq!(
        raw_kernel, raw.frame.bytes,
        "only the three declared metadata fields may differ"
    );
    assert_eq!(gated.after_handler, raw.after_handler);
    assert_eq!(
        gated.handler_completion.selected.input.registers(),
        &raw.handler.registers
    );
    assert_eq!(
        gated.returned.input.registers(),
        &raw.return_input.registers
    );
    assert_eq!(gated.returned.entry.registers, raw.return_entry.registers);
    assert_eq!(gated.returned.entry.xstate, raw.return_entry.xstate);
    assert_eq!(gated.returned.entry.signal_mask, raw.return_entry.mask);
    assert_eq!(raw.entry_info.bytes[0], 1);
    assert_eq!(gated.return_state, raw.returned);
    assert_eq!(
        Frame::from_state(&gated.return_state, projected.address),
        raw.edited_frame
    );
    let info = &gated.returned.information;
    assert_eq!(info.architecture, dword(&raw.return_info.bytes, 4));
    assert_eq!(info.instruction_pointer, word(&raw.return_info.bytes, 8));
    assert_eq!(info.stack_pointer, word(&raw.return_info.bytes, 16));
    assert_eq!(info.result, word(&raw.return_info.bytes, 24) as i64);
    assert_eq!(info.is_error, raw.return_info.bytes[32] != 0);
    assert_eq!(
        gated.landing.as_ref().map(|(_, state)| state),
        raw.landing.as_ref()
    );
    assert_eq!(
        gated
            .callbacks
            .iter()
            .filter(|input| input.instruction().logical_pc == image.sigreturn)
            .count(),
        1
    );
}
fn run_pair(trajectory: Trajectory, nonzero: Option<Metadata>, corrupt: bool) {
    let directory = Directory::new();
    let fork = FILE_FORK.lock().unwrap();
    let image = Arc::new(Image::write(&directory.0, trajectory));
    drop(fork);
    let (raw_ready_tx, raw_ready_rx) = mpsc::sync_channel(1);
    let (gated_ready_tx, gated_ready_rx) = mpsc::sync_channel(1);
    let (sent_tx, sent_rx) = mpsc::sync_channel(1);
    // Same controlled creator, before any original observation CPU trap. The
    // two lane threads inherit the same tuple; neither expected tuple is copied.
    let raw_image = Arc::clone(&image);
    let gated_image = Arc::clone(&image);
    let raw_worker = spawn_masked(move || raw::run(&raw_image, raw_ready_tx, sent_rx));
    let gated_worker = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        spawn_masked(move || gated(&gated_image, gated_ready_tx))
    }));
    let gated_worker = match gated_worker {
        Ok(worker) => worker,
        Err(panic) => {
            // A failure creating lane two must not detach lane one's owner.
            drop(sent_tx);
            let _ = raw_worker.join();
            std::panic::resume_unwind(panic);
        }
    };
    let sent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let raw = raw_ready_rx.recv_timeout(TIMEOUT * 2).unwrap();
        let gated = gated_ready_rx.recv_timeout(TIMEOUT * 2).unwrap();
        let until = Instant::now() + TIMEOUT;
        wait_ready(raw.pid, &raw.pin, until);
        wait_ready(gated.pid, &gated.pin, until);
        let info = signal_bytes();
        queue(&raw.pin, &info);
        queue(&gated.pin, &info);
        sent_tx.send(info).unwrap();
        (raw.pin, gated.pin)
    }));
    drop(sent_tx); // Wake a raw waiter even if controller assertions failed.
    let raw = raw_worker.join();
    let gated = gated_worker.join();
    if let Ok((raw_pin, gated_pin)) = &sent {
        reaped(raw_pin);
        reaped(gated_pin);
    }
    let raw = match raw {
        Ok(trace) => trace,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let gated = match gated {
        Ok(trace) => trace,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    if let Err(panic) = sent {
        std::panic::resume_unwind(panic);
    }
    compare_pair(&image, &raw, &gated, nonzero);
    if corrupt {
        compare::corruptions(&raw.handler, &raw.frame);
    }
}

#[test]
fn ordinary_stack_frame_matches_pristine_original() {
    run_pair(Trajectory::Ordinary, None, false);
}
#[test]
fn configured_altstack_frame_matches_pristine_original() {
    run_pair(Trajectory::Altstack, None, false);
}
#[test]
fn edited_frame_returns_to_untouched_nx_landing() {
    run_pair(Trajectory::Edited, None, false);
}
#[test]
fn inherited_nonzero_exception_metadata_matches_pristine_original() {
    if predecessor::is_inner() {
        let completion = predecessor::Completion::inherited();
        let metadata = predecessor::establish();
        run_pair(Trajectory::Ordinary, Some(metadata), false);
        completion.finish(metadata);
    } else {
        let directory = Directory::new();
        predecessor::isolated(&directory.0);
    }
}
#[test]
fn pristine_comparator_rejects_metadata_and_unrelated_state_corruption() {
    run_pair(Trajectory::Ordinary, None, true);
}
