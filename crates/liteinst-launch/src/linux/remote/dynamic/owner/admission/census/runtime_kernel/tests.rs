//! Pure model controls: no ptrace, source-read binding, or native seal constructor.
use super::super::super::super::trusted::AdmissionStop;
use super::super::super::runtime::kernel::namespace::NativeNamespaceIdentity;
use super::super::super::runtime_capture::SourceWindowId;
use super::super::super::runtime_kernel_native::{
    RuntimeFixedReads, RuntimeRawWaitView, RuntimeStateReadView,
};
use super::super::super::runtime_native::ControlProfile;
use super::*;
use crate::lifecycle::{ExitStatus, LifecycleRegistry};
use crate::selected::{SelectedResult, SyscallAliases, decode};
use liteinst2::contracts::SourceIdentity;
use std::time::Duration;

const PC: u64 = 0x401000;
const SESSION: u64 = 191;
const TID: i32 = 101;
const OK: Request = Request {
    result: 0,
    errno: None,
};
fn before(operation: RuntimeKernelOperation) -> ObservedStop {
    let registry = LifecycleRegistry::new(crate::lifecycle::Limits::default(), TID, PC).unwrap();
    let task = registry.task(registry.root_task()).unwrap();
    ObservedStop {
        token: DynamicStop {
            session: SESSION,
            sequence: 10,
            tid: TID,
            task: Some(task.id),
        },
        task: DynamicTask {
            task: task.id,
            process: task.process,
            address_space: task.address_space,
            generation: 0,
        },
        logical_pc: PC,
        registers: RegisterSnapshot {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            rbp: 11,
            rbx: 10,
            r11: 9,
            r10: 8,
            r9: 7,
            r8: 6,
            rax: operation.number(),
            rcx: 4,
            rdx: 3,
            rsi: 2,
            rdi: 0x123,
            orig_rax: u64::MAX,
            rip: PC,
            cs: 0x33,
            eflags: 0x202,
            rsp: 0x600000,
            ss: 0x2b,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        },
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    }
}
fn limits() -> Limits {
    Limits {
        epochs: 32,
        source_fact_bytes: 64 * 1024 * 1024,
        reports: 64,
        origins: 64,
        witnesses: 128,
        plan_history: 64,
    }
}
fn seeded(operation: RuntimeKernelOperation) -> (ResumeCensus, OriginId) {
    let before = before(operation);
    let mut census = ResumeCensus::new(SESSION, before.task.address_space, 0, limits()).unwrap();
    let reservation = census
        .reserve(super::super::runtime::initial_runtime_origin_charge(MAX_XSTATE_BYTES).unwrap())
        .unwrap();
    let origin = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, before)
        .unwrap();
    census.finish_reservation(reservation).unwrap();
    (census, origin)
}
fn identity(
    census: &ResumeCensus,
    origin: OriginId,
    operation: RuntimeKernelOperation,
) -> RuntimeKernelIdentity {
    let before = census.current_observation(origin).unwrap();
    RuntimeKernelIdentity::synthetic_for_census(
        RuntimePendingToken {
            stop: before.token.clone(),
            task: before.task,
            generation: Generation(0),
            mapping: MappingId(17),
            window: 2,
            pc: before.logical_pc,
            invocation: 1,
        },
        SourceWindowId::synthetic_for_test(
            CodeIdentity {
                source: SourceIdentity([0x31; 32]),
                mapping: 17,
                generation: 0,
            },
            2,
        ),
        origin,
        ExecutionId::from_owner(SESSION, 1).unwrap(),
        operation,
        validate::arguments(&before.registers),
        Instant::now() + Duration::from_secs(60),
    )
}
fn encode_registers(r: RegisterSnapshot) -> [u8; 216] {
    let words = [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ];
    let mut raw = [0; 216];
    for (index, word) in words.iter().enumerate() {
        raw[index * 8..index * 8 + 8].copy_from_slice(&word.to_ne_bytes());
    }
    raw
}
#[derive(Clone)]
struct Raw {
    ordinal: usize,
    tid: i32,
    status: i32,
    queries: bool,
    registers: [u8; 216],
    substrate: Vec<u8>,
    mask: [u8; 8],
    info: [u8; 88],
    signal: [u8; 128],
    reads: [Option<Request>; 3],
    info_request: Option<Request>,
    requested: usize,
    returned: usize,
    pointer: usize,
    returned_pointer: usize,
    complete: bool,
    message: u64,
    message_request: Option<Request>,
}
impl Raw {
    fn new(state: &TaskStateSnapshot, id: &RuntimeKernelIdentity, entry: bool) -> Self {
        let mut info = [0; 88];
        info[0] = if entry { 1 } else { 2 };
        info[4..8].copy_from_slice(&0xc000003eu32.to_ne_bytes());
        info[8..16].copy_from_slice(&id.next_pc().to_ne_bytes());
        info[16..24].copy_from_slice(&state.registers.rsp.to_ne_bytes());
        if entry {
            info[24..32].copy_from_slice(&id.number().to_ne_bytes());
            for (index, arg) in id.arguments().iter().enumerate() {
                info[32 + index * 8..40 + index * 8].copy_from_slice(&arg.to_ne_bytes());
            }
        } else {
            info[24..32].copy_from_slice(&state.registers.rax.to_ne_bytes());
        }
        let mut substrate = vec![0; MAX_XSTATE_BYTES];
        substrate[..state.xstate.len()].copy_from_slice(&state.xstate);
        Self {
            ordinal: if entry { 3 } else { 4 },
            tid: TID,
            status: ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
            queries: true,
            registers: encode_registers(state.registers),
            substrate,
            mask: state.mask.to_ne_bytes(),
            info,
            signal: [0; 128],
            reads: [Some(OK); 3],
            info_request: Some(Request {
                result: if entry { 80 } else { 33 },
                errno: None,
            }),
            requested: MAX_XSTATE_BYTES,
            returned: state.xstate.len(),
            pointer: 0x1000,
            returned_pointer: 0x1000,
            complete: true,
            message: 0,
            message_request: None,
        }
    }
    fn view<'a>(
        &'a self,
        state: &'a TaskStateSnapshot,
        control: &'a ControlProfile,
    ) -> RuntimeRawWaitView<'a> {
        RuntimeRawWaitView {
            ordinal: self.ordinal,
            tid: self.tid,
            status: self.status,
            queries_started: self.queries,
            state: Some(RuntimeStateReadView {
                registers: &self.registers,
                registers_request: self.reads[0],
                xstate_initialized: &self.substrate,
                xstate_request: self.reads[1],
                requested_pointer: self.pointer,
                returned_pointer: self.returned_pointer,
                requested_length: self.requested,
                returned_length: self.returned,
                mask: &self.mask,
                mask_request: self.reads[2],
                complete: self.complete,
                state: Some(state),
            }),
            fixed: RuntimeFixedReads {
                syscall_info: &self.info,
                syscall_info_request: self.info_request,
                event_message: self.message,
                event_message_request: self.message_request,
                signal: &self.signal,
                signal_request: None,
            },
            maps: None,
            control,
            failure: None,
        }
    }
}
struct Fixture {
    identity: RuntimeKernelIdentity,
    stops: [AdmissionStop; 8],
    states: [TaskStateSnapshot; 10],
    entry: DynamicEvent,
    exit: DynamicEvent,
    exiting: DynamicEvent,
    terminal: DynamicEvent,
    raw: [Raw; 2],
    control: ControlProfile,
    returned: NativeKernelReturnTrace,
    terminated: NativeKernelTerminalTrace,
}
impl Fixture {
    fn new(prepared: &PreparedRuntimeKernelCensus) -> Self {
        let b = &prepared.before;
        let id = &prepared.binding.identity;
        let original = TaskStateSnapshot {
            registers: b.registers,
            xstate: b.xstate.clone(),
            mask: b.signal_mask,
        };
        let mut states = std::array::from_fn(|_| original.clone());
        // Literal native64 syscall architectural changes; these are synthetic
        // expected facts and never a production native outcome constructor.
        states[4].registers = RegisterSnapshot {
            rip: PC + 2,
            rcx: PC + 2,
            orig_rax: id.number(),
            rax: (-i64::from(libc::ENOSYS)) as u64,
            r11: b.registers.eflags,
            ..b.registers
        };
        states[5] = states[4].clone();
        if id.operation().returns() {
            states[5].registers.rax = TID as u64;
        }
        let after = states[5].clone();
        for state in &mut states[6..] {
            *state = after.clone();
        }
        let stops = std::array::from_fn(|i| AdmissionStop {
            token: DynamicStop {
                sequence: b.token.sequence + if i < 4 { i as u64 } else { i as u64 + 2 },
                ..b.token.clone()
            },
            identity: b.task,
            phase: if i == 0 {
                AdmissionPhase::EntryReady
            } else {
                AdmissionPhase::Restored
            },
            signal: None,
        });
        let token = |sequence| DynamicStop {
            sequence,
            ..b.token.clone()
        };
        let entry = DynamicEvent {
            tid: TID,
            task: Some(b.task),
            kind: DynamicEventKind::SyscallEntry {
                number: id.number(),
                arguments: id.arguments(),
            },
            stop: Some(token(14)),
        };
        let exit = DynamicEvent {
            tid: TID,
            task: Some(b.task),
            kind: DynamicEventKind::SyscallExit {
                result: i64::from(TID),
                is_error: false,
            },
            stop: Some(token(15)),
        };
        let code = (id.arguments()[0] & 0xff) as u8;
        let exiting = DynamicEvent {
            tid: TID,
            task: Some(b.task),
            kind: DynamicEventKind::TaskExiting {
                status: ExitStatus::Code(code),
            },
            stop: None,
        };
        let terminal = DynamicEvent {
            tid: TID,
            task: Some(b.task),
            kind: DynamicEventKind::TaskTerminal {
                status: ExitStatus::Code(code),
            },
            stop: None,
        };
        let namespace = NativeNamespaceIdentity {
            device: 11,
            inode: 12,
        };
        let returned = NativeKernelReturnTrace {
            attempt: id.attempt(),
            entry_ordinal: 3,
            exit_ordinal: 4,
            bridge_ordinal: 5,
            closed_ordinal: 8,
            released: KernelStopIdentity::from(&stops[3].token),
            entry: KernelStopIdentity::from(entry.stop_token().unwrap()),
            exit: KernelStopIdentity::from(exit.stop_token().unwrap()),
            bridge: KernelStopIdentity::from(&stops[4].token),
            closed: KernelStopIdentity::from(&stops[7].token),
            original_release: OK,
            entry_release: OK,
            namespace,
            dr6: 0xffff0ff0,
        };
        let pre_exit_status = (libc::PTRACE_EVENT_EXIT << 16) | (libc::SIGTRAP << 8) | 0x7f;
        let terminated = NativeKernelTerminalTrace {
            attempt: id.attempt(),
            released: returned.released,
            entry: returned.entry,
            pre_exit_ordinal: 4,
            pre_exit_tid: TID,
            pre_exit_status,
            event_message: u64::from(code) << 8,
            event_message_request: OK,
            original_release: OK,
            entry_release: OK,
            pre_exit_release: OK,
            exiting_sequence: 15,
            terminal_ordinal: 5,
            terminal_tid: TID,
            terminal_status: i32::from(code) << 8,
            terminal_sequence: 16,
            physical_status: i32::from(code) << 8,
            pin_fd: 17,
            pin_poll: Request {
                result: 1,
                errno: None,
            },
            pin_revents: libc::POLLIN | libc::POLLHUP,
            namespace,
        };
        let mut raw = [
            Raw::new(&states[4], id, true),
            Raw::new(&states[5], id, false),
        ];
        if !id.operation().returns() {
            raw[1].status = pre_exit_status;
            raw[1].message = terminated.event_message;
            raw[1].message_request = Some(OK);
            raw[1].info_request = None;
        }
        Self {
            identity: id.clone(),
            stops,
            states,
            entry,
            exit,
            exiting,
            terminal,
            raw,
            control: ControlProfile::default(),
            returned,
            terminated,
        }
    }
    fn checkpoint(&self, i: usize) -> NativeCheckpoint<'_> {
        NativeCheckpoint {
            stop: &self.stops[i],
            state: &self.states[if i < 4 { i } else { i + 2 }],
        }
    }
    fn syscall(&self, entry: bool) -> NativeSyscallCheckpoint<'_> {
        let index = usize::from(!entry);
        NativeSyscallCheckpoint {
            event: if entry { &self.entry } else { &self.exit },
            state: &self.states[index + 4],
            raw: self.raw[index].view(&self.states[index + 4], &self.control),
        }
    }
    fn model(&self) -> Model<'_> {
        let outcome = if self.identity.operation().returns() {
            Outcome {
                returned: Some(ReturnModel {
                    exit: self.syscall(false),
                    bridge: self.checkpoint(4),
                    closing: std::array::from_fn(|i| self.checkpoint(i + 5)),
                    trace: self.returned,
                }),
                terminal: None,
            }
        } else {
            Outcome {
                returned: None,
                terminal: Some(TerminalModel {
                    pre_exit: NativePreExitCheckpoint {
                        raw: self.raw[1].view(&self.states[5], &self.control),
                        state: &self.states[5],
                        event_message: self.raw[1].message,
                        event_message_request: self.raw[1].message_request.unwrap_or(OK),
                    },
                    exiting: &self.exiting,
                    terminal: &self.terminal,
                    trace: self.terminated,
                }),
            }
        };
        Model {
            identity: &self.identity,
            logical: self.checkpoint(0),
            opening: std::array::from_fn(|i| self.checkpoint(i + 1)),
            entry: self.syscall(true),
            outcome,
        }
    }
}
struct Case {
    census: ResumeCensus,
    reservation: Reservation,
    prepared: Box<PreparedRuntimeKernelCensus>,
    actual: Fixture,
}
impl Case {
    fn new(operation: RuntimeKernelOperation) -> Self {
        let (mut census, origin) = seeded(operation);
        let id = identity(&census, origin, operation);
        let reservation = census
            .reserve(runtime_kernel_census_charge(operation).unwrap())
            .unwrap();
        let prepared = census.prepare_kernel_model(reservation, &id).unwrap();
        let actual = Fixture::new(&prepared);
        Self {
            census,
            reservation,
            prepared,
            actual,
        }
    }
    fn reject(&mut self, expected: CensusError) {
        let state = self.census.state.clone();
        let before = self.prepared.before.clone();
        let buffers = pointers(&self.prepared);
        let evidence = self.prepared.evidence.clone();
        assert_eq!(
            self.census
                .commit_kernel_model_for_test(
                    self.reservation,
                    &self.actual.model(),
                    &mut self.prepared
                )
                .err(),
            Some(expected)
        );
        assert_eq!(self.census.state, state);
        assert_eq!(self.prepared.before, before);
        assert_eq!(pointers(&self.prepared), buffers);
        assert_eq!(self.prepared.evidence, evidence);
        assert!(self.prepared.receipt.is_none());
    }
    fn commit(&mut self) -> Option<OriginId> {
        self.census
            .commit_kernel_model_for_test(
                self.reservation,
                &self.actual.model(),
                &mut self.prepared,
            )
            .unwrap()
            .current
    }
}
fn pointers(prepared: &PreparedRuntimeKernelCensus) -> Vec<(usize, usize, usize)> {
    std::iter::once(&prepared.before.xstate)
        .chain(prepared.buffers.iter())
        .map(|v| (v.as_ptr() as usize, v.len(), v.capacity()))
        .collect()
}
fn assert_state(observed: &ObservedStop, expected: &TaskStateSnapshot) {
    assert_eq!(observed.registers, expected.registers);
    assert_eq!(observed.xstate, expected.xstate);
    assert_eq!(observed.signal_mask, expected.mask);
    assert_eq!(observed.logical_pc, expected.registers.rip);
}
pub(in super::super) fn synthetic_returned_for_lineage() -> (ResumeCensus, OriginId) {
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    let id = case.commit().unwrap();
    case.census.finish_reservation(case.reservation).unwrap();
    (case.census, id)
}

#[test]
fn runtime_kernel_return_preserves_actual_entry_exit_and_all_refreshes() {
    for operation in [
        RuntimeKernelOperation::Getpid,
        RuntimeKernelOperation::Gettid,
    ] {
        let mut case = Case::new(operation);
        let before = case.census.state.clone();
        let charged = case.census.charged();
        let old = case.prepared.binding.identity.origin();
        let remaining = case.prepared.remaining_charge().unwrap();
        let original_pointers = pointers(&case.prepared);
        let id = case.commit().unwrap();
        assert_ne!(id, old);
        assert_eq!(case.census.active().count(), 1);
        assert!(!case.census.state.origins[0].active);
        assert_eq!(case.census.state.origins[0].row, before.origins[0].row);
        assert_eq!(case.census.history().len(), before.history.len() + 8);
        assert_eq!(case.census.charged(), charged);
        assert_eq!(case.census.used(), before.used.add(remaining).unwrap());
        assert_eq!(case.census.used().witnesses - before.used.witnesses, 8);
        assert_eq!(case.census.used().origins - before.used.origins, 1);
        assert_eq!(
            (
                case.census.used().epochs,
                case.census.used().reports,
                case.census.used().plan_history
            ),
            (
                before.used.epochs,
                before.used.reports,
                before.used.plan_history
            )
        );
        for (i, record) in case.census.history()[before.history.len()..]
            .iter()
            .enumerate()
        {
            if i == 3 {
                let HistoryRecord::Consumed { origin, evidence } = record else {
                    panic!("actual kernel consumption absent");
                };
                assert_eq!(*origin, old);
                assert_state(&evidence.before, &case.actual.states[3]);
                assert_state(&evidence.successor, &case.actual.states[5]);
                assert_eq!(
                    evidence.successor.phase,
                    StopPhase::ParentSyscallExit {
                        syscall: operation.number(),
                        result: i64::from(TID),
                        is_error: false
                    }
                );
                let Consumption::RuntimeKernel(records) = &evidence.evidence else {
                    panic!("wrong evidence family");
                };
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].identity, case.actual.identity);
                assert_state(records[0].entry.as_ref().unwrap(), &case.actual.states[4]);
                assert_eq!(
                    records[0].entry.as_ref().unwrap().phase,
                    StopPhase::SyscallEntry {
                        syscall: operation.number()
                    }
                );
                assert_eq!(
                    records[0].outcome.as_ref().unwrap().returned,
                    Some((id, case.actual.returned))
                );
            } else {
                let HistoryRecord::Refreshed {
                    origin,
                    before,
                    after,
                } = record
                else {
                    panic!("private refresh absent");
                };
                assert_eq!(*origin, if i < 3 { old } else { id });
                assert!(after.token.sequence > before.token.sequence);
                assert_eq!(after.registers, before.registers);
                assert_eq!(after.xstate, before.xstate);
                assert_eq!(after.signal_mask, before.signal_mask);
            }
        }
        let row = case.census.active().next().unwrap();
        assert_state(&row.row.initial, &case.actual.states[5]);
        assert_state(row.current, &case.actual.states[9]);
        assert_eq!(row.current.token, case.actual.stops[7].token);
        assert_eq!(
            case.census
                .runtime_register_provenance(id)
                .unwrap()
                .unwrap()
                .returned,
            id
        );
        let receipt = case.prepared.receipt.as_ref().unwrap().view();
        assert_eq!(receipt.attempt, case.actual.identity.attempt());
        assert_eq!(receipt.pending, case.actual.identity.pending());
        let RuntimeKernelCommitOutcome::Returned { current, stop } = receipt.outcome else {
            panic!("wrong receipt");
        };
        assert_eq!(current, id.journal_identity());
        assert_eq!(stop, &case.actual.stops[7].token);
        let mut retained = Vec::new();
        for record in &case.census.state.history {
            match record {
                HistoryRecord::Refreshed { before, after, .. } => {
                    retained.extend([&before.xstate, &after.xstate])
                }
                HistoryRecord::Consumed { evidence, .. } => {
                    retained.extend([&evidence.before.xstate, &evidence.successor.xstate]);
                    if let Consumption::RuntimeKernel(records) = &evidence.evidence {
                        retained.push(&records[0].entry.as_ref().unwrap().xstate);
                    }
                }
                _ => panic!("unexpected history"),
            }
        }
        let new = case.census.state.origins.last().unwrap();
        retained.extend([&new.row.initial.xstate, &new.current.xstate]);
        assert_eq!(retained.len(), 19);
        let mut moved = retained
            .iter()
            .map(|v| (v.as_ptr() as usize, v.capacity()))
            .collect::<Vec<_>>();
        moved.sort_unstable();
        let mut allocated = original_pointers
            .iter()
            .map(|(p, _, c)| (*p, *c))
            .collect::<Vec<_>>();
        allocated.sort_unstable();
        assert_eq!(moved, allocated);
        assert!(case.prepared.buffers.iter().all(|v| v.capacity() == 0));
    }
}

#[test]
fn runtime_kernel_terminal_keeps_real_terminal_without_a_user_successor() {
    for operation in [
        RuntimeKernelOperation::Exit,
        RuntimeKernelOperation::ExitGroup,
    ] {
        let mut case = Case::new(operation);
        let before = case.census.state.clone();
        let charged = case.census.charged();
        let remaining = case.prepared.remaining_charge().unwrap();
        let slots = pointers(&case.prepared);
        assert_eq!(
            slots
                .iter()
                .filter(|(_, _, cap)| *cap == MAX_XSTATE_BYTES)
                .count(),
            8
        );
        assert_eq!(case.commit(), None);
        assert_eq!(case.census.active().count(), 0);
        assert_eq!(case.census.state.origins.len(), before.origins.len());
        assert_eq!(case.census.used(), before.used.add(remaining).unwrap());
        assert_eq!(case.census.used().origins, before.used.origins);
        assert_eq!(case.census.used().witnesses - before.used.witnesses, 4);
        assert_eq!(case.census.state.next_serial, before.next_serial);
        assert_eq!(case.census.charged(), charged);
        assert_eq!(case.census.history().len(), before.history.len() + 4);
        let HistoryRecord::RuntimeKernelTerminal {
            origin,
            before: final_before,
            evidence,
        } = case.census.history().last().unwrap()
        else {
            panic!("terminal record absent");
        };
        assert_eq!(*origin, case.actual.identity.origin());
        assert_state(final_before, &case.actual.states[3]);
        assert_eq!(
            evidence[0].entry.as_ref().unwrap().phase,
            StopPhase::SyscallEntry {
                syscall: operation.number()
            }
        );
        let terminal = evidence[0]
            .outcome
            .as_ref()
            .unwrap()
            .terminal
            .as_ref()
            .unwrap();
        assert_eq!(terminal.exiting, case.actual.exiting);
        assert_eq!(terminal.terminal, case.actual.terminal);
        assert_eq!(terminal.trace, case.actual.terminated);
        assert!(evidence[0].outcome.as_ref().unwrap().returned.is_none());
        let RuntimeKernelCommitOutcome::Terminal {
            event,
            sequence,
            wait_status,
            physical_status,
            pin_revents,
        } = case.prepared.receipt.as_ref().unwrap().view().outcome
        else {
            panic!("wrong receipt");
        };
        assert_eq!(event, &case.actual.terminal);
        assert!(event.stop_token().is_none());
        assert_eq!(sequence, 16);
        assert_eq!(wait_status, 0x2300);
        assert_eq!(physical_status, wait_status);
        assert_eq!(pin_revents, libc::POLLIN | libc::POLLHUP);
        assert_eq!(
            case.prepared.allocated_bytes().unwrap(),
            size_of::<PreparedRuntimeKernelCensus>()
        );
    }
}
fn axis(value: &mut BudgetCharge, index: usize) -> &mut usize {
    match index {
        0 => &mut value.epochs,
        1 => &mut value.source_fact_bytes,
        2 => &mut value.reports,
        3 => &mut value.origins,
        4 => &mut value.witnesses,
        _ => &mut value.plan_history,
    }
}
fn limit_axis(value: &mut Limits, index: usize) -> &mut usize {
    match index {
        0 => &mut value.epochs,
        1 => &mut value.source_fact_bytes,
        2 => &mut value.reports,
        3 => &mut value.origins,
        4 => &mut value.witnesses,
        _ => &mut value.plan_history,
    }
}
#[test]
fn runtime_kernel_reservation_enforces_all_six_limits_before_preparation() {
    let charge = runtime_kernel_census_charge(RuntimeKernelOperation::Getpid)
        .unwrap()
        .add(BudgetCharge {
            epochs: 1,
            reports: 1,
            plan_history: 1,
            ..BudgetCharge::default()
        })
        .unwrap();
    for index in 0..6 {
        let (mut census, _) = seeded(RuntimeKernelOperation::Getpid);
        let mut total = census.charged().add(charge).unwrap();
        *limit_axis(&mut census.limits, index) = *axis(&mut total, index) - 1;
        let before = census.state.clone();
        assert_eq!(census.reserve(charge), Err(CensusError::Capacity));
        assert_eq!(census.state, before);
    }
    let (mut census, origin) = seeded(RuntimeKernelOperation::Getpid);
    let mut total = census.charged().add(charge).unwrap();
    for index in 0..6 {
        *limit_axis(&mut census.limits, index) = *axis(&mut total, index);
    }
    let reservation = census.reserve(charge).unwrap();
    let id = identity(&census, origin, RuntimeKernelOperation::Getpid);
    let prepared = census.prepare_kernel_model(reservation, &id).unwrap();
    assert_eq!(
        prepared.preparation_debit,
        prepared.allocated_bytes().unwrap()
    );
    assert_eq!(census.charged(), total);
    let used = census.used();
    census.finish_reservation(reservation).unwrap();
    assert_eq!(census.charged(), total);
    assert_eq!(census.used(), used);
}
#[test]
fn runtime_kernel_six_axis_overflow_refuses_without_mutation() {
    for index in 0..6 {
        let (mut census, _) = seeded(RuntimeKernelOperation::Getpid);
        *axis(&mut census.state.charged, index) = usize::MAX;
        let mut charge = BudgetCharge::default();
        *axis(&mut charge, index) = 1;
        let before = census.state.clone();
        assert_eq!(census.reserve(charge), Err(CensusError::Capacity));
        assert_eq!(census.state, before);
    }
    assert_eq!(add(usize::MAX, 1), Err(CensusError::Capacity));
    assert_eq!(mul(usize::MAX, 2), Err(CensusError::Capacity));
}
#[test]
fn runtime_kernel_preparation_requires_exact_source_invocation_and_current_state() {
    for mutation in 0..12 {
        let (mut census, origin) = seeded(RuntimeKernelOperation::Getpid);
        let base = identity(&census, origin, RuntimeKernelOperation::Getpid);
        let mut pending = base.pending().clone();
        let mut source = base.source_id();
        let mut old = origin;
        let mut execution = base.execution();
        let mut arguments = base.arguments();
        let mut until = base.until();
        match mutation {
            0 => pending.stop.session += 1,
            1 => pending.stop.sequence += 1,
            2 => pending.pc += 1,
            3 => pending.invocation += 1,
            4 => pending.generation.0 += 1,
            5 => pending.mapping.0 += 1,
            6 => pending.window += 1,
            7 => {
                source = SourceWindowId::synthetic_for_test(
                    CodeIdentity {
                        mapping: 18,
                        ..source.identity()
                    },
                    source.index(),
                )
            }
            8 => old.census += 1,
            9 => execution.serial += 1,
            10 => arguments[3] ^= 1,
            _ => until = Instant::now() - Duration::from_secs(1),
        }
        let id = RuntimeKernelIdentity::synthetic_for_census(
            pending,
            source,
            old,
            execution,
            base.operation(),
            arguments,
            until,
        );
        let reservation = census
            .reserve(runtime_kernel_census_charge(base.operation()).unwrap())
            .unwrap();
        let before = census.state.clone();
        assert!(
            census.prepare_kernel_model(reservation, &id).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(census.state, before);
    }
}
#[test]
fn runtime_kernel_return_rejects_full_observation_changes_atomically() {
    for slot in 0..10 {
        for field in 0..5 {
            let mut case = Case::new(RuntimeKernelOperation::Getpid);
            match field {
                0 => case.actual.states[slot].registers.r15 ^= 1,
                1 => case.actual.states[slot].registers.orig_rax ^= 1,
                2 => case.actual.states[slot].registers.rsp ^= 8,
                3 => case.actual.states[slot].xstate[511] ^= 1,
                _ => case.actual.states[slot].mask ^= 1,
            }
            case.reject(CensusError::InvalidConsumption);
        }
    }
}
#[test]
fn runtime_kernel_raw_reads_preserve_exact_success_substrates_and_lengths() {
    for ordinal in 0..2 {
        for mutation in 0..15 {
            let mut case = Case::new(RuntimeKernelOperation::Getpid);
            let raw = &mut case.actual.raw[ordinal];
            match mutation {
                0 => raw.queries = false,
                1 => raw.complete = false,
                2 => raw.ordinal += 1,
                3 => raw.tid += 1,
                4 => raw.status = (libc::SIGTRAP << 8) | 0x7f,
                5 => raw.reads[0] = None,
                6 => {
                    raw.reads[1] = Some(Request {
                        result: -1,
                        errno: Some(libc::EIO),
                    })
                }
                7 => raw.reads[2] = None,
                8 => raw.pointer = 0,
                9 => raw.returned_pointer += 8,
                10 => raw.requested -= 1,
                11 => raw.returned += 1,
                12 => raw.substrate[511] ^= 1,
                13 => raw.registers[0] ^= 1,
                _ => raw.mask[0] ^= 1,
            }
            case.reject(CensusError::InvalidConsumption);
        }
    }
}
#[test]
fn runtime_kernel_syscall_info_and_actual_event_are_both_required() {
    for ordinal in 0..2 {
        for mutation in 0..10 {
            let mut case = Case::new(RuntimeKernelOperation::Getpid);
            let raw = &mut case.actual.raw[ordinal];
            match mutation {
                0 => raw.info[0] ^= 1,
                1 => raw.info[4] ^= 1,
                2 => raw.info[8] ^= 1,
                3 => raw.info[16] ^= 1,
                4 => raw.info[24] ^= 1,
                5 => raw.info_request = None,
                6 => {
                    raw.info_request = Some(Request {
                        result: if ordinal == 0 { 79 } else { 32 },
                        errno: None,
                    })
                }
                7 => {
                    raw.info_request = Some(Request {
                        result: 89,
                        errno: None,
                    })
                }
                8 => {
                    raw.info_request = Some(Request {
                        result: 88,
                        errno: Some(libc::EIO),
                    })
                }
                _ => {
                    if ordinal == 0 {
                        case.actual.entry.kind = DynamicEventKind::SyscallEntry {
                            number: libc::SYS_gettid as u64,
                            arguments: case.actual.identity.arguments(),
                        }
                    } else {
                        case.actual.exit.kind = DynamicEventKind::SyscallExit {
                            result: i64::from(TID),
                            is_error: true,
                        }
                    }
                }
            }
            case.reject(CensusError::InvalidConsumption);
        }
    }
    for offset in (32..80).step_by(8) {
        let mut case = Case::new(RuntimeKernelOperation::Getpid);
        case.actual.raw[0].info[offset] ^= 1;
        case.reject(CensusError::InvalidConsumption);
    }
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.actual.raw[1].info[32] = 1;
    case.reject(CensusError::InvalidConsumption);
}
#[test]
fn runtime_kernel_return_trace_and_each_stop_identity_remain_binding() {
    for mutation in 0..12 {
        let mut case = Case::new(RuntimeKernelOperation::Getpid);
        let trace = &mut case.actual.returned;
        match mutation {
            0 => trace.attempt.invocation += 1,
            1 => trace.entry_ordinal += 1,
            2 => trace.exit_ordinal += 1,
            3 => trace.bridge_ordinal += 1,
            4 => trace.closed_ordinal += 1,
            5 => trace.released.sequence += 1,
            6 => trace.entry.sequence += 1,
            7 => trace.exit.sequence += 1,
            8 => trace.bridge.sequence += 1,
            9 => trace.closed.sequence += 1,
            10 => trace.original_release.result = -1,
            _ => trace.entry_release.errno = Some(libc::EIO),
        }
        case.reject(CensusError::InvalidConsumption);
    }
    for slot in 0..8 {
        let mut case = Case::new(RuntimeKernelOperation::Getpid);
        case.actual.stops[slot].token.task = None;
        case.reject(CensusError::InvalidConsumption);
    }
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.actual.entry.stop.as_mut().unwrap().sequence = 13;
    case.reject(CensusError::InvalidConsumption);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.actual.exit.stop = None;
    case.reject(CensusError::InvalidConsumption);
}
#[test]
fn runtime_kernel_terminal_requires_real_status_eventmsg_and_original_pin_completion() {
    for mutation in 0..19 {
        let mut case = Case::new(RuntimeKernelOperation::Exit);
        let trace = &mut case.actual.terminated;
        match mutation {
            0 => trace.attempt.invocation += 1,
            1 => trace.pre_exit_ordinal += 1,
            2 => trace.pre_exit_tid += 1,
            3 => trace.pre_exit_status ^= 1,
            4 => trace.event_message ^= 1,
            5 => trace.event_message_request.result = -1,
            6 => trace.original_release.errno = Some(libc::EIO),
            7 => trace.entry_release.result = -1,
            8 => trace.pre_exit_release.result = -1,
            9 => trace.exiting_sequence = 14,
            10 => trace.terminal_sequence = 15,
            11 => trace.terminal_ordinal += 1,
            12 => trace.terminal_tid += 1,
            13 => trace.terminal_status = libc::SIGKILL,
            14 => trace.physical_status ^= 1,
            15 => trace.pin_fd = -1,
            16 => trace.pin_poll.result = 0,
            17 => trace.pin_poll.errno = Some(libc::EIO),
            _ => trace.pin_revents = libc::POLLHUP,
        }
        case.reject(CensusError::InvalidConsumption);
    }
    let mut case = Case::new(RuntimeKernelOperation::Exit);
    case.actual.exiting.stop = case.actual.entry.stop.clone();
    case.reject(CensusError::InvalidConsumption);
    let mut case = Case::new(RuntimeKernelOperation::Exit);
    case.actual.terminal.kind = DynamicEventKind::TaskTerminal {
        status: ExitStatus::Code(0),
    };
    case.reject(CensusError::InvalidConsumption);
    let mut case = Case::new(RuntimeKernelOperation::Exit);
    case.actual.raw[1].message_request = None;
    case.reject(CensusError::InvalidConsumption);
    let mut case = Case::new(RuntimeKernelOperation::Exit);
    case.actual.raw[1].reads[0] = None;
    case.reject(CensusError::InvalidConsumption);
}
#[test]
fn runtime_kernel_late_capacity_serial_and_reservation_refusals_keep_all_prepared_data() {
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.census.state.next_serial += 1;
    case.reject(CensusError::StaleObservation);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.census.state.next_serial = u64::MAX;
    case.prepared.binding.candidate_serial = case.census.state.next_serial;
    case.reject(CensusError::Capacity);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.census
        .state
        .reservation
        .as_mut()
        .unwrap()
        .1
        .source_fact_bytes = 0;
    case.reject(CensusError::ReservationExhausted);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.prepared.buffers[0] = Vec::new();
    case.reject(CensusError::Capacity);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.prepared.preparation_debit -= 1;
    case.reject(CensusError::Capacity);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.prepared.binding.census += 1;
    case.reject(CensusError::IdentityMismatch);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.reservation.serial += 1;
    case.reject(CensusError::IdentityMismatch);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.census.state.history = Vec::new();
    case.reject(CensusError::Capacity);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.census.state.origins[0].current.token.sequence += 1;
    case.reject(CensusError::StaleObservation);
}
#[test]
fn runtime_kernel_original_deadline_and_one_use_remain_exact() {
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    let old = &case.actual.identity;
    let expired = RuntimeKernelIdentity::synthetic_for_census(
        old.pending().clone(),
        old.source_id(),
        old.origin(),
        old.execution(),
        old.operation(),
        old.arguments(),
        Instant::now() - Duration::from_secs(1),
    );
    case.actual.identity = expired.clone();
    case.prepared.binding.identity = expired.clone();
    case.prepared.evidence.as_mut().unwrap()[0].identity = expired;
    case.reject(CensusError::StaleObservation);
    let mut case = Case::new(RuntimeKernelOperation::Getpid);
    case.commit();
    let state = case.census.state.clone();
    assert_eq!(
        case.census
            .commit_kernel_model_for_test(
                case.reservation,
                &case.actual.model(),
                &mut case.prepared
            )
            .err(),
        Some(CensusError::IdentityMismatch)
    );
    assert_eq!(case.census.state, state);
    assert_eq!(
        case.prepared.remaining_charge(),
        Err(CensusError::InvalidConsumption)
    );
}

#[test]
fn runtime_kernel_inherited_register_tag_requires_full_retained_lineage() {
    for mutation in 0..12 {
        let (mut census, id) = synthetic_returned_for_lineage();
        let active = census.active_index(id).unwrap();
        match mutation {
            0 => census.state.origins[active].runtime_kernel = None,
            1 => {
                census.state.origins[active]
                    .runtime_kernel
                    .as_mut()
                    .unwrap()
                    .returned
                    .census += 1
            }
            2 => {
                census.state.origins[active]
                    .runtime_kernel
                    .as_mut()
                    .unwrap()
                    .returned
                    .serial += 1
            }
            3 => {
                census.state.origins[active]
                    .runtime_kernel
                    .as_mut()
                    .unwrap()
                    .parent = Some(id)
            }
            4 => census.state.origins[active].current.registers.orig_rax = libc::SYS_gettid as u64,
            5 => census.state.origins[active].current.registers.r15 ^= 1,
            6 => census.state.origins[active].current.xstate[511] ^= 1,
            7 => census.state.origins[active].row.initial.signal_mask ^= 1,
            8 => {
                let HistoryRecord::Refreshed { after, .. } = &mut census.state.history[4] else {
                    panic!()
                };
                after.token.task = None;
            }
            9 => {
                let HistoryRecord::Consumed { evidence, .. } = &mut census.state.history[3] else {
                    panic!()
                };
                let Consumption::RuntimeKernel(records) = &mut evidence.evidence else {
                    panic!()
                };
                records[0].entry.as_mut().unwrap().registers.orig_rax ^= 1;
            }
            10 => {
                let HistoryRecord::Consumed { evidence, .. } = &mut census.state.history[3] else {
                    panic!()
                };
                let Consumption::RuntimeKernel(records) = &mut evidence.evidence else {
                    panic!()
                };
                records[0]
                    .outcome
                    .as_mut()
                    .unwrap()
                    .returned
                    .as_mut()
                    .unwrap()
                    .0
                    .serial += 1;
            }
            _ => {
                let HistoryRecord::Consumed { evidence, .. } = &mut census.state.history[3] else {
                    panic!()
                };
                let Consumption::RuntimeKernel(records) = &mut evidence.evidence else {
                    panic!()
                };
                let old = &records[0].identity;
                let mut arguments = old.arguments();
                arguments[0] ^= 1;
                records[0].identity = RuntimeKernelIdentity::synthetic_for_census(
                    old.pending().clone(),
                    old.source_id(),
                    old.origin(),
                    old.execution(),
                    old.operation(),
                    arguments,
                    old.until(),
                );
            }
        }
        let state = census.state.clone();
        assert!(
            census.runtime_register_provenance(id).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(census.state, state);
    }
    let (mut census, id) = seeded(RuntimeKernelOperation::Getpid);
    census.state.origins[0].runtime_kernel = Some(KernelOriginLineage {
        returned: id,
        parent: None,
    });
    assert!(census.runtime_register_provenance(id).is_err());
}
fn selected(
    census: &ResumeCensus,
    id: OriginId,
) -> (
    SelectedInput,
    CompletedInstruction,
    ExecutionId,
    ObservedStop,
) {
    let before = census.current_observation(id).unwrap();
    let input = SelectedInput::new(
        decode(before.logical_pc, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap(),
        before.registers,
    )
    .unwrap();
    let completed = input
        .complete(SelectedResult::Cpuid {
            eax: 1,
            ebx: 2,
            ecx: 3,
            edx: 4,
        })
        .unwrap();
    let invocation = ExecutionId::from_owner(SESSION, 2).unwrap();
    let mut actual = before.clone();
    actual.token.sequence += 1;
    actual.registers = completed.after;
    actual.logical_pc = completed.after.rip;
    actual.phase = StopPhase::SelectedComplete { invocation };
    (input, completed, invocation, actual)
}
#[test]
fn runtime_kernel_cpu_successor_preserves_provenance_and_rejects_changed_bookkeeping() {
    let (mut census, id) = synthetic_returned_for_lineage();
    let (input, completed, invocation, actual) = selected(&census, id);
    let reservation = census
        .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
        .unwrap();
    let mut prepared = census
        .prepare_runtime_selected(reservation, id, invocation, &input, &completed)
        .unwrap();
    let original = census.state.clone();
    let mut wrong = actual.clone();
    wrong.registers.orig_rax = u64::MAX;
    assert_eq!(
        census.commit_runtime_selected(&mut prepared, &wrong),
        Err(CensusError::InvalidConsumption)
    );
    assert_eq!(census.state, original);
    let next = census
        .commit_runtime_selected(&mut prepared, &actual)
        .unwrap();
    assert_ne!(id, next);
    let link = census.runtime_register_provenance(next).unwrap().unwrap();
    assert_eq!(link.returned, id);
    assert_eq!(link.parent, Some(id));
    assert_eq!(
        census.current_observation(next).unwrap().registers.orig_rax,
        libc::SYS_getpid as u64
    );
    let history = census.history().to_vec();
    census.finish_reservation(reservation).unwrap();
    assert_eq!(census.history(), history);
    let index = census.active_index(next).unwrap();
    census.state.origins[index]
        .runtime_kernel
        .as_mut()
        .unwrap()
        .parent = Some(next);
    assert_eq!(
        census.runtime_register_provenance(next),
        Err(CensusError::InvalidConsumption)
    );
}
#[test]
fn runtime_kernel_unsealed_nonmax_or_changed_selected_model_never_prepares() {
    let (mut census, id) = seeded(RuntimeKernelOperation::Getpid);
    census.state.origins[0].current.registers.orig_rax = libc::SYS_getpid as u64;
    let (input, completed, invocation, _) = selected(&census, id);
    let reservation = census
        .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
        .unwrap();
    let state = census.state.clone();
    assert!(matches!(
        census.prepare_runtime_selected(reservation, id, invocation, &input, &completed),
        Err(CensusError::StaleObservation)
    ));
    assert_eq!(census.state, state);
    let (mut census, id) = synthetic_returned_for_lineage();
    let (input, mut completed, invocation, _) = selected(&census, id);
    let reservation = census
        .reserve(PreparedRuntimeSelected::reservation_charge().unwrap())
        .unwrap();
    let state = census.state.clone();
    completed.after.orig_rax = u64::MAX;
    assert!(matches!(
        census.prepare_runtime_selected(reservation, id, invocation, &input, &completed),
        Err(CensusError::InvalidConsumption)
    ));
    assert_eq!(census.state, state);
}
