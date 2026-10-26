//! Original-site SYSCALL, exact real ENTRY, then return or physical terminal.
use super::super::super::lifecycle::admission::{RuntimeKernelExitMessage, RuntimeKernelPreExit};
use super::super::mapping::maps::ParsedMaps;
use super::io::{checked, request};
use super::*;
use std::os::fd::AsRawFd;

mod validate;
use validate::{entry_state, exit_state, next_stop, syscall_event, terminal_status};

fn mapped(error: GateError) -> LaunchError {
    match error {
        GateError::Refused(reason) => LaunchError::Invalid(reason),
        _ => LaunchError::Invalid("runtime kernel map proof differs"),
    }
}
fn require_state(state: &TaskStateSnapshot) -> Result<(), LaunchError> {
    // orig_rax is deliberately not normalized. The binding/control lineage
    // authenticates its exact current provenance; ENTRY derives the new value.
    if state.registers.cs != 0x33
        || state.registers.eflags & (0x100 | 0x10000) != 0
        || state.registers.eflags & 2 == 0
        || !(512..MAX_XSTATE).contains(&state.xstate.len())
    {
        return Err(LaunchError::Invalid("runtime kernel state profile differs"));
    }
    Ok(())
}
fn ready(
    owner: &Owner,
    native: &NativeLifecycle,
    binding: &RuntimeKernelBinding<'_>,
    p: &mut PreparedRuntimeKernel,
    stop: &AdmissionStop,
) -> Result<(), LaunchError> {
    native.require_initial_source_mm(
        owner,
        stop,
        p.until,
        p.membership
            .as_mut()
            .expect("allocated membership")
            .as_mut_slice(),
    )?;
    if stop.identity != binding.stop().identity
        || stop.token.session != owner.session
        || stop.token.tid != owner.pid
        || stop.signal.is_some()
        || stop.identity.generation != 0
        || native.admission_interrupt_credit(owner.pid)? != 0
    {
        return Err(LaunchError::Invalid(
            "runtime kernel settled identity differs",
        ));
    }
    let island = binding.island();
    if island.address_space != stop.identity.address_space
        || island.generation != 0
        || island.page_size != 4096
    {
        return Err(LaunchError::Invalid(
            "runtime kernel trusted island identity differs",
        ));
    }
    p.maps[WORK_MAP].capture(owner, p.until)?;
    let maps = ParsedMaps::parse(p.maps[WORK_MAP].bytes(), 512)
        .map_err(|_| LaunchError::Invalid("runtime kernel current maps malformed"))?;
    if !maps.entries().any(|row| {
        row.start <= island.range.start
            && island.range.end <= row.end
            && row.permissions.bytes() == *b"r-xp"
            && row.pathname.is_none()
    }) {
        return Err(LaunchError::Invalid(
            "runtime kernel immutable island differs",
        ));
    }
    bootstrap::verify_memory(
        owner,
        island.range.start,
        &bootstrap::island_code_fixed(),
        &mut p.memory,
        p.until,
    )?;
    bootstrap::physical(owner, p.until)
}
fn same_observation(state: &TaskStateSnapshot, observation: &ObservedStop) -> bool {
    state.registers == observation.registers
        && state.xstate == observation.xstate
        && state.mask == observation.signal_mask
}
fn readback(
    observer: &mut dyn RuntimeKernelObservation,
    p: &PreparedRuntimeKernel,
) -> Result<(), LaunchError> {
    let (kind, stop, view) = p
        .last_readback_view()
        .ok_or(LaunchError::Invalid("runtime kernel readback absent"))?;
    observer.readback(p.binding(), kind, stop, view)
}
fn capture_work(
    owner: &Owner,
    p: &mut PreparedRuntimeKernel,
    observer: &mut dyn RuntimeKernelObservation,
) -> Result<(), LaunchError> {
    // Reusing WORK must never leave a prior successful readback tag attached
    // to new request bytes. The journal copies this slot only on failure/unwind
    // or at an explicitly named validated restoration boundary.
    p.last_readback = Some(Readback {
        kind: RuntimeKernelReadback::Unexpected,
        stop: None,
        state: WORK,
    });
    let captured = p.states[WORK].capture(owner, p.until);
    if captured.is_err() {
        let _ = readback(observer, p);
    }
    captured
}
pub(super) fn before_provider(
    owner: &Owner,
    native: &NativeLifecycle,
    binding: &RuntimeKernelBinding<'_>,
    p: &mut PreparedRuntimeKernel,
    observer: &mut dyn RuntimeKernelObservation,
) -> Result<(), LaunchError> {
    owner.time_left(p.until, "runtime kernel before provider")?;
    if !p.allocated
        || p.provider_ready
        || p.identity.is_some()
        || p.first_failure.is_some()
        || p.until != binding.until()
        || p.shape.operation != binding.operation()
        || p.shape.fetch_start != binding.geometry().pages().start()
        || p.shape.fetch_end != binding.geometry().pages().end()
        || binding.identity().encoding() != [0x0f, 0x05]
        || binding.identity().pc().checked_add(2) != Some(binding.identity().next_pc())
        || binding.stop().token != binding.before().token
        || binding.stop().identity != binding.before().task
        || binding.before().signal.is_some()
        || binding.stop().signal.is_some()
        || binding.before().logical_pc != binding.identity().pc()
        || binding.before().registers.rip != binding.identity().pc()
        || binding.before().registers.rax != binding.identity().number()
    {
        return Err(LaunchError::Invalid(
            "runtime kernel bound preparation differs",
        ));
    }
    p.identity = Some(binding.identity().clone());
    p.initial = Some(binding.stop().clone());
    p.phase = RuntimeKernelPhase::BeforeProvider;
    ready(owner, native, binding, p, binding.stop())?;
    p.last_readback = Some(Readback {
        kind: RuntimeKernelReadback::Unexpected,
        stop: Some(binding.stop().clone()),
        state: BEFORE,
    });
    let captured = p.states[BEFORE].capture(owner, p.until).and_then(|()| {
        require_state(&p.states[BEFORE].state)?;
        if !same_observation(&p.states[BEFORE].state, binding.before()) {
            return Err(LaunchError::Invalid(
                "runtime kernel original full state differs",
            ));
        }
        Ok(())
    });
    if captured.is_ok() {
        p.last_readback.as_mut().expect("installed readback").kind =
            RuntimeKernelReadback::Original;
    }
    let copied = readback(observer, p);
    captured?;
    copied?;
    p.maps[BASELINE].capture(owner, p.until)?;
    if p.maps[BASELINE].bytes() != binding.baseline_maps() {
        return Err(LaunchError::Invalid(
            "runtime kernel original map bytes differ",
        ));
    }
    binding
        .geometry()
        .projected_rows(p.maps[BASELINE].bytes())
        .map_err(mapped)?;
    bootstrap::verify_memory(
        owner,
        binding.identity().pc(),
        binding.identity().encoding(),
        &mut p.memory,
        p.until,
    )?;
    p.profiles[0].capture(owner, p.until)?;
    binding
        .lineage()
        .authenticate(binding.stop(), &p.profiles[0])?;
    binding
        .lineage()
        .require_orig_rax(binding.stop(), p.states[BEFORE].state.registers.orig_rax)?;
    p.namespace = Some(capture_namespace(owner, p.until, &mut p.namespaces[0])?);
    capture_work(owner, p, observer)?;
    if p.states[WORK].state != p.states[BEFORE].state {
        return Err(LaunchError::Invalid(
            "runtime kernel profile changed original state",
        ));
    }
    ready(owner, native, binding, p, binding.stop())?;
    verify_closed(p.maps[BASELINE].bytes(), p.maps[WORK_MAP].bytes()).map_err(mapped)?;
    p.provider_ready = true;
    p.phase = RuntimeKernelPhase::Pending;
    Ok(())
}

#[derive(Clone, Copy)]
enum Context {
    Settled {
        index: Option<usize>,
        canonical: usize,
    },
    Syscall(usize),
    PreExit,
}
fn context(p: &PreparedRuntimeKernel, at: Context) -> RuntimeKernelEffectContext<'_> {
    match at {
        Context::Settled { index, canonical } => {
            RuntimeKernelEffectContext::Settled(NativeCheckpoint {
                stop: match index {
                    Some(index) => p.stops[index].as_ref().expect("retained settled stop"),
                    None => p.initial.as_ref().expect("retained original stop"),
                },
                state: &p.states[canonical].state,
            })
        }
        Context::Syscall(ordinal) => RuntimeKernelEffectContext::Syscall(p.syscall(ordinal)),
        Context::PreExit => RuntimeKernelEffectContext::PreExit(p.pre_exit()),
    }
}
struct Driver<'a, 'b> {
    owner: &'a mut Owner,
    native: &'a mut NativeLifecycle,
    binding: &'a RuntimeKernelBinding<'b>,
    p: &'a mut PreparedRuntimeKernel,
    observer: &'a mut dyn RuntimeKernelObservation,
}
// Sum the named aggregate source-evidence values across the finite runner,
// conservatively including sequential alternatives. Buffers and query records
// installed in PreparedRuntimeKernel are already in H, never added again here.
pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
    let terms = [
        (1, size_of::<Driver<'_, '_>>()),
        (1, size_of::<Context>()),
        (1, size_of::<RuntimeKernelEffectContext<'_>>()),
        (1, size_of::<[NativeCheckpoint<'_>; 3]>()),
        (2, size_of::<NativeCheckpoint<'_>>()),
        (1, size_of::<NativeSyscallCheckpoint<'_>>()),
        (1, size_of::<NativePreExitCheckpoint<'_>>()),
        (1, size_of::<RuntimeWaitCustody>()),
        (2, size_of::<RuntimeRawWaitView<'_>>()),
        (1, size_of::<RuntimeStateReadView<'_>>()),
        (5, size_of::<AdmissionStop>()),
        (3, size_of::<DynamicEvent>()),
        (1, size_of::<NativeKernelReturnTrace>()),
        (1, size_of::<NativeKernelTerminalTrace>()),
        (1, size_of::<RuntimeKernelPreExit<'_>>()),
        (1, size_of::<RuntimeKernelExitMessage<'_>>()),
        (8, size_of::<RegisterSnapshot>()),
        (1, size_of::<libc::user_regs_struct>()),
        (1, size_of::<libc::iovec>()),
        (1, size_of::<libc::pollfd>()),
        (4, size_of::<Request>()),
        (8, size_of::<Result<(), LaunchError>>()),
        // island_code_fixed's expected and verify_memory's actual arrays.
        (2, size_of::<[u8; 68]>()),
        (1, size_of::<MemoryObservation>()),
        // Existing allocation-free full-inventory projection's borrowed views.
        (3, size_of::<ParsedMaps<'_>>()),
        (2, size_of::<super::super::mapping::maps::MapEntries<'_>>()),
        (4, size_of::<super::super::mapping::maps::MapEntry<'_>>()),
    ];
    terms
        .into_iter()
        .try_fold(0, |total, (count, bytes)| add(total, mul(count, bytes)?))
}
impl Driver<'_, '_> {
    fn begin(&mut self, effect: RuntimeKernelEffect, at: Context) -> Result<(), LaunchError> {
        let p = &mut self.p;
        if !p.can_begin_effect() {
            return Err(LaunchError::Invalid(
                "runtime kernel effect capacity or ordering differs",
            ));
        }
        // The attempt header exists even when the observer refuses or unwinds.
        p.effects[p.effects_len] = Some(RuntimeKernelEffectRecord {
            effect,
            result: None,
            complete: false,
        });
        p.effects_len += 1;
        self.owner.time_left(p.until, "runtime kernel effect")?;
        self.observer.before_effect(
            self.owner,
            self.native,
            p.binding(),
            effect,
            context(p, at),
            p.until,
        )?;
        self.owner.time_left(p.until, "runtime kernel effect")
    }
    fn finish(&mut self, actual: Request) -> Result<(), LaunchError> {
        let index = self.p.effects_len - 1;
        let record = self.p.effects[index].as_mut().expect("installed effect");
        record.result = Some(actual);
        let effect = record.effect;
        let result = checked(actual, "runtime kernel effect");
        record.complete = result.is_ok();
        let copied = self
            .observer
            .effect_result(self.p.binding(), effect, actual);
        result?;
        copied
    }
    fn finish_external(
        &mut self,
        native_result: Result<(), LaunchError>,
    ) -> Result<(), LaunchError> {
        let actual = self.p.effects[self.p.effects_len - 1]
            .as_ref()
            .expect("installed external effect")
            .result;
        let copied = actual.map(|actual| self.finish(actual)).transpose();
        native_result?;
        copied?.ok_or(LaunchError::Invalid(
            "runtime kernel helper omitted actual effect",
        ))
    }
    fn set_registers(
        &mut self,
        registers: RegisterSnapshot,
        effect: RuntimeKernelEffect,
        at: Context,
    ) -> Result<(), LaunchError> {
        self.begin(effect, at)?;
        let raw = libc::user_regs_struct::from(registers);
        let actual = request(
            libc::PTRACE_SETREGS,
            self.owner.pid,
            0,
            (&raw const raw) as usize,
        );
        self.finish(actual)
    }
    fn custody(&self, tid: i32) -> RuntimeWaitCustody {
        RuntimeWaitCustody {
            session: self.owner.session,
            expected_tid: self.owner.pid,
            retained_pin: self.owner.handles.get(&tid).map(AsRawFd::as_raw_fd),
            process_pin: self
                .owner
                .pin_kinds
                .get(&tid)
                .map(|kind| *kind == PinKind::Process),
            owned: self.owner.owned.contains(&tid),
            stopped_status: self.owner.stopped.get(&tid).copied(),
            tracer_terminal: self.owner.tracer_terminal.get(&tid).copied(),
            lost_wait: self.owner.lost_wait,
            missing_pin: self.owner.missing_pin,
        }
    }
    fn wait(&mut self, ordinal: usize, terminal: bool) -> Result<(i32, i32), LaunchError> {
        if ordinal >= WAITS || self.p.raw[ordinal].wait.is_some() {
            return Err(LaunchError::Invalid("runtime kernel raw wait slot reused"));
        }
        let (tid, status) = self
            .owner
            .wait_raw(self.p.until, "runtime kernel actual wait")?;
        let custody = self.custody(tid);
        self.p.raw[ordinal].wait = Some((tid, status));
        self.p.raw[ordinal].custody = Some(custody);
        let recorded = self
            .observer
            .wait(self.p.binding(), ordinal, tid, status, custody);
        let captured = (|| {
            recorded?;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                // The real consumed terminal status retired numeric authority.
                // No ptrace, procfs or memory read is attempted on this branch.
                self.owner
                    .time_left(self.p.until, "runtime kernel terminal wait")?;
                if !terminal || tid != self.owner.pid {
                    return Err(LaunchError::Invalid(
                        "runtime kernel expected terminal wait differs",
                    ));
                }
                return Ok(());
            }
            bootstrap::raw_held(self.owner, tid, status, self.p.until)?;
            self.p.raw[ordinal].queries_started = true;
            // All independent read families run before interpreting a failure.
            let state = self.p.states[ordinal + 1].capture_tid(tid);
            let fixed = self.p.raw[ordinal].fixed.capture(tid);
            let maps = self.p.maps[ordinal + 1].capture(self.owner, self.p.until);
            let profile = self.p.profiles[ordinal + 2].capture(self.owner, self.p.until);
            state?;
            fixed?;
            maps?;
            profile?;
            if terminal {
                return Err(LaunchError::Invalid(
                    "runtime kernel expected terminal wait differs",
                ));
            }
            self.owner
                .time_left(self.p.until, "runtime kernel actual wait")
        })();
        if let Err(error) = &captured {
            self.p.raw[ordinal].failure = Some(RuntimeKernelFailure::from_error(error));
        }
        let copied = self.observer.raw(
            self.p.binding(),
            self.p.raw_view(ordinal).expect("retained actual wait"),
        );
        captured?;
        copied?;
        if !terminal {
            self.p
                .raw_view(ordinal)
                .expect("retained actual wait")
                .control
                .require(self.p.profiles[0].debug.values[4])?;
        }
        Ok((tid, status))
    }
    fn namespace(&mut self, index: usize) -> Result<(), LaunchError> {
        let observed = capture_namespace(self.owner, self.p.until, &mut self.p.namespaces[index])?;
        if Some(observed) != self.p.namespace {
            return Err(LaunchError::Invalid("runtime kernel namespace changed"));
        }
        Ok(())
    }
    fn work(&mut self) -> Result<(), LaunchError> {
        capture_work(self.owner, self.p, self.observer)
    }
    fn restore(
        &mut self,
        ordinal: usize,
        canonical: usize,
        at: Context,
    ) -> Result<(), LaunchError> {
        self.work()?;
        if self.p.states[WORK].state.xstate != self.p.states[canonical].state.xstate {
            self.begin(RuntimeKernelEffect::RestoreXstate { ordinal }, at)?;
            let mut vector = libc::iovec {
                iov_base: self.p.states[canonical]
                    .state
                    .xstate
                    .as_ptr()
                    .cast_mut()
                    .cast(),
                iov_len: self.p.states[canonical].state.xstate.len(),
            };
            let actual = request(
                libc::PTRACE_SETREGSET,
                self.owner.pid,
                NT_X86_XSTATE,
                (&raw mut vector) as usize,
            );
            self.finish(actual)?;
        }
        self.set_registers(
            self.p.states[canonical].state.registers,
            RuntimeKernelEffect::RestoreRegisters { ordinal },
            at,
        )?;
        self.work()?;
        if self.p.states[WORK].state.registers != self.p.states[canonical].state.registers
            || self.p.states[WORK].state.xstate != self.p.states[canonical].state.xstate
        {
            return Err(LaunchError::Invalid(
                "runtime kernel trusted restoration differs",
            ));
        }
        if self.p.states[WORK].state.mask != self.p.states[canonical].state.mask {
            self.begin(RuntimeKernelEffect::RestoreMask { ordinal }, at)?;
            let actual = request(
                libc::PTRACE_SETSIGMASK,
                self.owner.pid,
                8,
                (&raw const self.p.states[canonical].state.mask) as usize,
            );
            self.finish(actual)?;
        }
        self.work()?;
        if self.p.states[WORK].state != self.p.states[canonical].state {
            return Err(LaunchError::Invalid(
                "runtime kernel complete restored state differs",
            ));
        }
        Ok(())
    }
    fn projection(&self, ordinal: usize, maps: usize) -> Result<(), LaunchError> {
        if ordinal == 0 || ordinal >= 7 {
            verify_closed(self.p.maps[BASELINE].bytes(), self.p.maps[maps].bytes()).map_err(mapped)
        } else {
            self.binding
                .geometry()
                .verify_open(self.p.maps[BASELINE].bytes(), self.p.maps[maps].bytes())
                .map_err(mapped)
        }
    }
    fn private_call(
        &mut self,
        ordinal: usize,
        number: libc::c_long,
        arguments: [u64; 6],
    ) -> Result<(), LaunchError> {
        let canonical = if ordinal < ENTRY { BEFORE } else { EXIT + 1 };
        let previous = match ordinal {
            0 => None,
            1 => Some(0),
            2 => Some(1),
            6 => Some(3),
            7 => Some(4),
            8 => Some(5),
            _ => {
                return Err(LaunchError::Invalid(
                    "runtime kernel private ordinal differs",
                ));
            }
        };
        let at = Context::Settled {
            index: previous,
            canonical,
        };
        let stop = self
            .native
            .admission_current(self.binding.stop().identity.task)?;
        let RuntimeKernelEffectContext::Settled(expected) = context(self.p, at) else {
            unreachable!()
        };
        if *expected.stop != stop {
            return Err(LaunchError::Invalid(
                "runtime kernel private current stop differs",
            ));
        }
        ready(self.owner, self.native, self.binding, self.p, &stop)?;
        self.work()?;
        if self.p.states[WORK].state != self.p.states[canonical].state {
            return Err(LaunchError::Invalid(
                "runtime kernel private before state differs",
            ));
        }
        let pc = self.binding.island().range.start;
        let mut registers = trusted::temporary(&self.p.states[canonical].state.registers, pc);
        registers.rax = number as u64;
        registers.rdi = arguments[0];
        registers.rsi = arguments[1];
        registers.rdx = arguments[2];
        registers.r10 = arguments[3];
        registers.r8 = arguments[4];
        registers.r9 = arguments[5];
        bootstrap::verify_memory(self.owner, pc, &STUB, &mut self.p.memory, self.p.until)?;
        if registers.rip != pc
            || registers.cs != 0x33
            || registers.orig_rax != u64::MAX
            || registers.eflags & (0x100 | 0x10000 | 0x40000) != 0
            || STUB != [0x0f, 0x05, 0xcc]
        {
            return Err(LaunchError::Invalid("runtime kernel private setup differs"));
        }
        self.set_registers(registers, RuntimeKernelEffect::SetRegisters { ordinal }, at)?;
        self.work()?;
        if self.p.states[WORK].state.registers != registers
            || self.p.states[WORK].state.xstate != self.p.states[canonical].state.xstate
            || self.p.states[WORK].state.mask != self.p.states[canonical].state.mask
        {
            return Err(LaunchError::Invalid(
                "runtime kernel private setup changed unrelated state",
            ));
        }
        self.begin(RuntimeKernelEffect::PrivateRelease { ordinal }, at)?;
        self.native.begin_admission_execution(&stop)?;
        self.owner
            .time_left(self.p.until, "runtime kernel private release")?;
        let actual = request(libc::PTRACE_CONT, self.owner.pid, 0, 0);
        // Custody reflects an actual successful release even if journal copy fails.
        if actual
            == (Request {
                result: 0,
                errno: None,
            })
        {
            self.owner.released(self.owner.pid);
        }
        self.finish(actual)?;
        let (tid, status) = self.wait(ordinal, false)?;
        self.owned_trap(ordinal, tid, status)?;
        let observed = self.p.states[ordinal + 1].state.registers;
        let mut expected = registers;
        expected.rip = pc
            .checked_add(STUB.len() as u64)
            .ok_or(LaunchError::Invalid("runtime kernel trap address overflow"))?;
        expected.rax = 0;
        expected.rcx = pc + 2;
        expected.r11 = registers.eflags;
        if observed != expected
            || self.p.states[ordinal + 1].state.mask != self.p.states[canonical].state.mask
        {
            return Err(LaunchError::Invalid(
                "runtime kernel private completion differs",
            ));
        }
        bootstrap::verify_memory(self.owner, pc, &STUB, &mut self.p.memory, self.p.until)?;
        self.projection(ordinal, ordinal + 1)?;
        self.restore(ordinal, canonical, at)?;
        let restored = self.native.finish_admission_execution(
            tid,
            self.p.states[canonical].state.registers.rip,
            AdmissionPhase::Restored,
        )?;
        next_stop(&stop, &restored)?;
        let index = if ordinal < ENTRY {
            ordinal
        } else {
            ordinal - 2
        };
        self.p.stops[index] = Some(restored.clone());
        ready(self.owner, self.native, self.binding, self.p, &restored)?;
        self.projection(ordinal, WORK_MAP)
    }
    fn owned_trap(&mut self, ordinal: usize, tid: i32, status: i32) -> Result<(), LaunchError> {
        if tid != self.owner.pid
            || !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || status >> 16 != 0
            || self.native.consume_admission_interrupt(tid)?
        {
            return Err(LaunchError::Invalid(
                "runtime kernel private trap phase differs",
            ));
        }
        self.p.raw[ordinal].fixed.owned_trap()
    }
    fn open(&mut self) -> Result<(), LaunchError> {
        self.p.phase = RuntimeKernelPhase::Opening;
        self.private_call(0, libc::SYS_membarrier, [SYNC_CORE, 0, 0, 0, 0, 0])?;
        self.private_call(
            1,
            libc::SYS_mprotect,
            [
                self.p.shape.fetch_start,
                self.p.shape.fetch_end - self.p.shape.fetch_start,
                (libc::PROT_READ | libc::PROT_EXEC) as u64,
                0,
                0,
                0,
            ],
        )?;
        self.private_call(2, libc::SYS_membarrier, [SYNC_CORE, 0, 0, 0, 0, 0])?;
        self.p.phase = RuntimeKernelPhase::Opened;
        self.namespace(1)?;
        bootstrap::verify_memory(
            self.owner,
            self.binding.identity().pc(),
            self.binding.identity().encoding(),
            &mut self.p.memory,
            self.p.until,
        )?;
        self.work()?;
        if self.p.states[WORK].state != self.p.states[BEFORE].state {
            return Err(LaunchError::Invalid(
                "runtime kernel open changed original state",
            ));
        }
        self.observer.opened(
            self.owner,
            self.native,
            self.p.binding(),
            self.p.opening()[2],
            self.p.maps[WORK_MAP].bytes(),
            self.p.until,
        )?;
        Ok(())
    }
    fn original_entry(&mut self) -> Result<(), LaunchError> {
        let release = self.p.stops[2].as_ref().expect("actual opening").clone();
        ready(self.owner, self.native, self.binding, self.p, &release)?;
        self.projection(2, WORK_MAP)?;
        self.work()?;
        if self.p.states[WORK].state != self.p.states[BEFORE].state {
            return Err(LaunchError::Invalid(
                "runtime kernel original release state differs",
            ));
        }
        self.begin(
            RuntimeKernelEffect::OriginalRelease,
            Context::Settled {
                index: Some(2),
                canonical: BEFORE,
            },
        )?;
        let result = unsafe {
            self.native.begin_runtime_kernel_original(
                self.owner,
                &release,
                &mut self.p.effects[self.p.effects_len - 1]
                    .as_mut()
                    .expect("original effect")
                    .result,
            )
        };
        self.finish_external(result)?;
        let (tid, status) = self.wait(ENTRY, false)?;
        syscall_event(tid, self.owner.pid, status)?;
        let event = self
            .native
            .observe_admission_other(self.owner, tid, status)?
            .ok_or(LaunchError::Invalid("runtime kernel ENTRY event absent"))?;
        self.p.events[0] = Some(event);
        let entry = self.p.events[0].as_ref().expect("retained ENTRY");
        if entry
            .stop_token()
            .is_none_or(|token| token.sequence <= release.token.sequence)
        {
            return Err(LaunchError::Invalid(
                "runtime kernel ENTRY sequence did not advance",
            ));
        }
        self.native.require_runtime_kernel_event(
            self.owner,
            self.binding.stop(),
            entry,
            self.p.until,
            self.p
                .membership
                .as_mut()
                .expect("membership")
                .as_mut_slice(),
        )?;
        entry_state(
            self.p.binding(),
            &self.p.states[BEFORE].state,
            entry,
            &self.p.states[ENTRY + 1].state,
        )?;
        self.p.raw[ENTRY]
            .fixed
            .syscall(true, &self.p.states[ENTRY + 1].state, self.p.binding())?;
        self.projection(ENTRY, ENTRY + 1)?;
        self.namespace(2)?;
        self.p.phase = RuntimeKernelPhase::Entry;
        self.observer.entry(
            self.owner,
            self.native,
            self.p.binding(),
            self.p.syscall(ENTRY),
            self.p.until,
        )?;
        self.native.require_runtime_kernel_event(
            self.owner,
            self.binding.stop(),
            self.p.events[0].as_ref().expect("ENTRY"),
            self.p.until,
            self.p
                .membership
                .as_mut()
                .expect("membership")
                .as_mut_slice(),
        )?;
        self.work()?;
        if self.p.states[WORK].state != self.p.states[ENTRY + 1].state {
            return Err(LaunchError::Invalid(
                "runtime kernel ENTRY callback changed current state",
            ));
        }
        self.p.maps[WORK_MAP].capture(self.owner, self.p.until)?;
        self.projection(ENTRY, WORK_MAP)?;
        bootstrap::verify_memory(
            self.owner,
            self.binding.identity().pc(),
            self.binding.identity().encoding(),
            &mut self.p.memory,
            self.p.until,
        )?;
        self.begin(RuntimeKernelEffect::EntryRelease, Context::Syscall(ENTRY))?;
        let result = unsafe {
            self.native.resume_runtime_kernel_entry(
                self.owner,
                self.p.events[0].as_ref().expect("ENTRY"),
                &mut self.p.effects[self.p.effects_len - 1]
                    .as_mut()
                    .expect("entry effect")
                    .result,
            )
        };
        self.finish_external(result)
    }
    fn returned(&mut self) -> Result<(), LaunchError> {
        let (tid, status) = self.wait(EXIT, false)?;
        syscall_event(tid, self.owner.pid, status)?;
        let event = self
            .native
            .observe_admission_other(self.owner, tid, status)?
            .ok_or(LaunchError::Invalid("runtime kernel EXIT event absent"))?;
        self.p.events[1] = Some(event);
        let exit = self.p.events[1].as_ref().expect("retained EXIT");
        if exit.stop_token().is_none_or(|token| {
            token.sequence
                <= self.p.events[0]
                    .as_ref()
                    .expect("ENTRY")
                    .stop_token()
                    .expect("ENTRY token")
                    .sequence
        }) {
            return Err(LaunchError::Invalid(
                "runtime kernel EXIT sequence did not advance",
            ));
        }
        self.native.require_runtime_kernel_event(
            self.owner,
            self.binding.stop(),
            exit,
            self.p.until,
            self.p
                .membership
                .as_mut()
                .expect("membership")
                .as_mut_slice(),
        )?;
        exit_state(
            self.p.binding(),
            &self.p.states[BEFORE].state,
            exit,
            &self.p.states[EXIT + 1].state,
        )?;
        self.p.raw[EXIT]
            .fixed
            .syscall(false, &self.p.states[EXIT + 1].state, self.p.binding())?;
        self.projection(EXIT, EXIT + 1)?;
        self.namespace(3)?;
        self.p.phase = RuntimeKernelPhase::Exit;
        self.p.original_completed = true;
        self.observer.exit(self.p.binding(), self.p.syscall(EXIT))?;
        self.bridge()?;
        self.p.phase = RuntimeKernelPhase::Closing;
        self.private_call(6, libc::SYS_membarrier, [SYNC_CORE, 0, 0, 0, 0, 0])?;
        self.private_call(
            7,
            libc::SYS_mprotect,
            [
                self.p.shape.fetch_start,
                self.p.shape.fetch_end - self.p.shape.fetch_start,
                libc::PROT_READ as u64,
                0,
                0,
                0,
            ],
        )?;
        self.private_call(8, libc::SYS_membarrier, [SYNC_CORE, 0, 0, 0, 0, 0])?;
        self.namespace(4)?;
        let closed = self.p.stops[6].as_ref().expect("actual close").clone();
        ready(self.owner, self.native, self.binding, self.p, &closed)?;
        verify_closed(self.p.maps[BASELINE].bytes(), self.p.maps[WORK_MAP].bytes())
            .map_err(mapped)?;
        self.p.last_readback = Some(Readback {
            kind: RuntimeKernelReadback::Unexpected,
            stop: Some(closed.clone()),
            state: WORK,
        });
        let captured = self.p.states[WORK]
            .capture(self.owner, self.p.until)
            .and_then(|()| {
                if self.p.states[WORK].state != self.p.states[EXIT + 1].state {
                    return Err(LaunchError::Invalid(
                        "runtime kernel closed state differs from actual EXIT",
                    ));
                }
                Ok(())
            });
        if captured.is_ok() {
            self.p
                .last_readback
                .as_mut()
                .expect("installed close readback")
                .kind = RuntimeKernelReadback::Closed;
        }
        let copied = readback(self.observer, self.p);
        captured?;
        copied?;
        self.observer.closed(
            self.owner,
            self.native,
            self.p.binding(),
            NativeCheckpoint {
                stop: &closed,
                state: &self.p.states[EXIT + 1].state,
            },
            self.p.maps[WORK_MAP].bytes(),
            self.p.until,
        )?;
        self.owner
            .time_left(self.p.until, "runtime kernel closed completion")?;
        self.native.require_initial_source_mm(
            self.owner,
            &closed,
            self.p.until,
            self.p
                .membership
                .as_mut()
                .expect("membership")
                .as_mut_slice(),
        )?;
        self.p.return_trace = Some(NativeKernelReturnTrace {
            attempt: self.p.binding().attempt(),
            entry_ordinal: ENTRY,
            exit_ordinal: EXIT,
            bridge_ordinal: BRIDGE,
            closed_ordinal: 8,
            released: (&self.p.stops[2].as_ref().expect("release").token).into(),
            entry: self.p.events[0]
                .as_ref()
                .expect("ENTRY")
                .stop_token()
                .expect("ENTRY token")
                .into(),
            exit: self.p.events[1]
                .as_ref()
                .expect("EXIT")
                .stop_token()
                .expect("EXIT token")
                .into(),
            bridge: (&self.p.stops[3].as_ref().expect("bridge").token).into(),
            closed: (&closed.token).into(),
            original_release: self.effect(RuntimeKernelEffect::OriginalRelease)?,
            entry_release: self.effect(RuntimeKernelEffect::EntryRelease)?,
            namespace: self.p.namespace.expect("actual namespace"),
            dr6: self.p.profiles[0].debug.values[4],
        });
        self.p.nx_closed = true;
        self.p.phase = RuntimeKernelPhase::Closed;
        Ok(())
    }
    fn bridge(&mut self) -> Result<(), LaunchError> {
        self.p.phase = RuntimeKernelPhase::Bridge;
        let exit = self.p.events[1].as_ref().expect("actual EXIT").clone();
        self.native.require_runtime_kernel_event(
            self.owner,
            self.binding.stop(),
            &exit,
            self.p.until,
            self.p
                .membership
                .as_mut()
                .expect("membership")
                .as_mut_slice(),
        )?;
        let pc = self.binding.island().trap();
        bootstrap::verify_memory(
            self.owner,
            self.binding.island().range.start,
            &bootstrap::island_code_fixed(),
            &mut self.p.memory,
            self.p.until,
        )?;
        bootstrap::verify_memory(self.owner, pc, &[0xcc], &mut self.p.memory, self.p.until)?;
        self.work()?;
        if self.p.states[WORK].state != self.p.states[EXIT + 1].state {
            return Err(LaunchError::Invalid(
                "runtime kernel bridge lost EXIT state",
            ));
        }
        let temporary = trusted::temporary(&self.p.states[EXIT + 1].state.registers, pc);
        // The legacy helper authenticates genuine EXIT before any register edit.
        self.native
            .begin_admission_return_bridge(exit.stop_token().expect("actual EXIT token"))?;
        self.set_registers(
            temporary,
            RuntimeKernelEffect::SetRegisters { ordinal: BRIDGE },
            Context::Syscall(EXIT),
        )?;
        self.work()?;
        if self.p.states[WORK].state.registers != temporary
            || self.p.states[WORK].state.xstate != self.p.states[EXIT + 1].state.xstate
            || self.p.states[WORK].state.mask != self.p.states[EXIT + 1].state.mask
        {
            return Err(LaunchError::Invalid(
                "runtime kernel bridge setup changed unrelated state",
            ));
        }
        self.begin(
            RuntimeKernelEffect::PrivateRelease { ordinal: BRIDGE },
            Context::Syscall(EXIT),
        )?;
        let actual = request(libc::PTRACE_CONT, self.owner.pid, 0, 0);
        if actual
            == (Request {
                result: 0,
                errno: None,
            })
        {
            self.owner.released(self.owner.pid);
        }
        self.finish(actual)?;
        let (tid, status) = self.wait(BRIDGE, false)?;
        self.owned_trap(BRIDGE, tid, status)?;
        let mut expected = temporary;
        expected.rip = pc
            .checked_add(1)
            .ok_or(LaunchError::Invalid("runtime kernel bridge PC overflow"))?;
        if self.p.states[BRIDGE + 1].state.registers != expected
            || self.p.states[BRIDGE + 1].state.mask != self.p.states[EXIT + 1].state.mask
        {
            return Err(LaunchError::Invalid(
                "runtime kernel neutral bridge state differs",
            ));
        }
        self.projection(BRIDGE, BRIDGE + 1)?;
        bootstrap::verify_memory(self.owner, pc, &[0xcc], &mut self.p.memory, self.p.until)?;
        self.restore(BRIDGE, EXIT + 1, Context::Syscall(EXIT))?;
        let bridge = self.native.finish_admission_execution(
            tid,
            self.p.states[EXIT + 1].state.registers.rip,
            AdmissionPhase::Restored,
        )?;
        let exit_token = exit.stop_token().expect("actual EXIT token");
        if bridge.identity != self.binding.stop().identity
            || bridge.token.session != exit_token.session
            || bridge.token.tid != exit_token.tid
            || bridge.token.task != exit_token.task
            || bridge.token.sequence <= exit_token.sequence
            || bridge.signal.is_some()
        {
            return Err(LaunchError::Invalid(
                "runtime kernel bridge stop lineage differs",
            ));
        }
        self.p.stops[3] = Some(bridge.clone());
        self.p.last_readback = Some(Readback {
            kind: RuntimeKernelReadback::RestoredReturn,
            stop: Some(bridge.clone()),
            state: WORK,
        });
        readback(self.observer, self.p)?;
        ready(self.owner, self.native, self.binding, self.p, &bridge)?;
        self.projection(BRIDGE, WORK_MAP)
    }
    fn effect(&self, effect: RuntimeKernelEffect) -> Result<Request, LaunchError> {
        let mut matching = self.p.effects[..self.p.effects_len]
            .iter()
            .flatten()
            .filter(|record| record.effect == effect);
        let record = matching.next().ok_or(LaunchError::Invalid(
            "runtime kernel actual release missing",
        ))?;
        if matching.next().is_some() || !record.complete {
            return Err(LaunchError::Invalid(
                "runtime kernel release incomplete or duplicate",
            ));
        }
        record.result.ok_or(LaunchError::Invalid(
            "runtime kernel actual release result absent",
        ))
    }
    fn terminated(&mut self) -> Result<(), LaunchError> {
        let (tid, status) = self.wait(EXIT, false)?;
        self.p.phase = RuntimeKernelPhase::PreExit;
        let entry = self.p.events[0].as_ref().expect("actual ENTRY").clone();
        let observed = RuntimeKernelPreExit {
            original: self.binding.stop(),
            entry: &entry,
            tid,
            status,
        };
        self.native.require_runtime_kernel_pre_exit(
            self.owner,
            observed,
            self.p.until,
            self.p
                .membership
                .as_mut()
                .expect("membership")
                .as_mut_slice(),
        )?;
        self.projection(EXIT, EXIT + 1)?;
        // No EXIT or user successor is synthesized. Preserve the complete
        // actual pre-exit image without substituting an ENTRY-derived state.
        let message = self.p.raw[EXIT].fixed.event_message;
        let message_request =
            self.p.raw[EXIT]
                .fixed
                .event_message_request
                .ok_or(LaunchError::Invalid(
                    "runtime kernel pre-exit message absent",
                ))?;
        checked(message_request, "PTRACE_GETEVENTMSG")?;
        if message != ((self.p.binding().arguments()[0] & 0xff) << 8) {
            return Err(LaunchError::Invalid(
                "runtime kernel pre-exit status differs",
            ));
        }
        self.observer
            .pre_exit(self.p.binding(), self.p.pre_exit())?;
        self.begin(RuntimeKernelEffect::PreExitRelease, Context::PreExit)?;
        let continued = unsafe {
            self.native.continue_runtime_kernel_pre_exit(
                self.owner,
                RuntimeKernelExitMessage {
                    observation: observed,
                    event_message: message,
                },
                self.p.until,
                self.p
                    .membership
                    .as_mut()
                    .expect("membership")
                    .as_mut_slice(),
                &mut self.p.effects[self.p.effects_len - 1]
                    .as_mut()
                    .expect("pre-exit effect")
                    .result,
            )
        };
        let actual = self.p.effects[self.p.effects_len - 1]
            .as_ref()
            .expect("effect")
            .result;
        let exiting_sequence = match continued {
            Ok((exiting, sequence)) => {
                // Store the real event before an observer can fail or unwind.
                self.p.events[1] = Some(exiting);
                self.p.exiting_sequence = Some(sequence);
                sequence
            }
            Err(error) => {
                if let Some(actual) = actual {
                    let _ = self.finish(actual);
                }
                return Err(error);
            }
        };
        let copied = actual.map(|actual| self.finish(actual)).transpose();
        copied?.ok_or(LaunchError::Invalid(
            "runtime kernel pre-exit actual CONT absent",
        ))?;
        self.p.phase = RuntimeKernelPhase::Terminal;
        let (terminal_tid, terminal_status_raw) = self.wait(BRIDGE, true)?;
        terminal_status(self.p.binding(), terminal_tid, terminal_status_raw)?;
        let terminal = self
            .native
            .observe_admission_other(self.owner, terminal_tid, terminal_status_raw)?
            .ok_or(LaunchError::Invalid("runtime kernel terminal event absent"))?;
        self.p.events[2] = Some(terminal);
        let terminal = self.p.events[2].as_ref().expect("actual terminal");
        if terminal.task != Some(self.p.binding().task())
            || terminal.stop_token().is_some()
            || terminal.kind
                != (DynamicEventKind::TaskTerminal {
                    status: crate::lifecycle::ExitStatus::Code(
                        (self.p.binding().arguments()[0] & 0xff) as u8,
                    ),
                })
        {
            return Err(LaunchError::Invalid(
                "runtime kernel terminal identity differs",
            ));
        }
        let terminal_sequence = self
            .native
            .runtime_kernel_sequence(self.p.binding().task())?;
        self.p.terminal_sequence = Some(terminal_sequence);
        if terminal_sequence <= exiting_sequence {
            return Err(LaunchError::Invalid(
                "runtime kernel terminal sequence did not advance",
            ));
        }
        self.p.phase = RuntimeKernelPhase::Physical;
        self.owner
            .wait_physical(terminal_tid, terminal_status_raw, self.p.until)?;
        let fd = self
            .owner
            .handles
            .get(&terminal_tid)
            .ok_or(LaunchError::Invalid(
                "runtime kernel original pin absent at terminal",
            ))?
            .as_raw_fd();
        if self.p.raw[ENTRY]
            .custody
            .and_then(|custody| custody.retained_pin)
            != Some(fd)
        {
            return Err(LaunchError::Invalid(
                "runtime kernel terminal pin differs from ENTRY",
            ));
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        unsafe {
            *libc::__errno_location() = 0;
        }
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        let errno = unsafe { *libc::__errno_location() };
        let pin_poll = Request {
            result: result as i64,
            errno: (result < 0).then_some(errno),
        };
        let trace = NativeKernelTerminalTrace {
            attempt: self.p.binding().attempt(),
            released: (&self.p.stops[2].as_ref().expect("opening").token).into(),
            entry: entry.stop_token().expect("ENTRY token").into(),
            pre_exit_ordinal: EXIT,
            pre_exit_tid: tid,
            pre_exit_status: status,
            event_message: message,
            event_message_request: message_request,
            original_release: self.effect(RuntimeKernelEffect::OriginalRelease)?,
            entry_release: self.effect(RuntimeKernelEffect::EntryRelease)?,
            pre_exit_release: self.effect(RuntimeKernelEffect::PreExitRelease)?,
            exiting_sequence,
            terminal_ordinal: BRIDGE,
            terminal_tid,
            terminal_status: terminal_status_raw,
            terminal_sequence,
            physical_status: terminal_status_raw,
            pin_fd: fd,
            pin_poll,
            pin_revents: poll.revents,
            namespace: self.p.namespace.expect("actual namespace"),
        };
        // Retain the actual failed poll too; only the flags below create a seal.
        self.p.terminal_trace = Some(trace);
        if pin_poll
            != (Request {
                result: 1,
                errno: None,
            })
            || poll.revents != (libc::POLLIN | libc::POLLHUP)
        {
            return Err(LaunchError::Invalid(
                "runtime kernel physical pin completion differs",
            ));
        }
        self.owner
            .time_left(self.p.until, "runtime kernel terminal completion")?;
        self.observer.terminal(
            self.p.binding(),
            self.p.events[2].as_ref().expect("terminal"),
            trace,
        )?;
        self.p.physical_complete = true;
        Ok(())
    }
}
pub(super) fn execute(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    binding: &RuntimeKernelBinding<'_>,
    p: &mut PreparedRuntimeKernel,
    observer: &mut dyn RuntimeKernelObservation,
) -> Result<(), LaunchError> {
    owner.time_left(p.until, "runtime kernel after provider")?;
    if !p.provider_ready
        || !p.allocated
        || p.first_failure.is_some()
        || p.effects_len != 0
        || p.identity.as_ref() != Some(binding.identity())
        || p.until != binding.until()
        || p.initial.as_ref() != Some(binding.stop())
    {
        return Err(LaunchError::Invalid(
            "runtime kernel pending binding changed",
        ));
    }
    p.phase = RuntimeKernelPhase::AfterProvider;
    ready(owner, native, binding, p, binding.stop())?;
    verify_closed(p.maps[BASELINE].bytes(), p.maps[WORK_MAP].bytes()).map_err(mapped)?;
    capture_work(owner, p, observer)?;
    if p.states[WORK].state != p.states[BEFORE].state {
        return Err(LaunchError::Invalid(
            "runtime kernel provider changed current state",
        ));
    }
    p.profiles[1].capture(owner, p.until)?;
    binding
        .lineage()
        .authenticate(binding.stop(), &p.profiles[1])?;
    binding
        .lineage()
        .require_orig_rax(binding.stop(), p.states[WORK].state.registers.orig_rax)?;
    let mut driver = Driver {
        owner,
        native,
        binding,
        p,
        observer,
    };
    driver.open()?;
    driver.original_entry()?;
    if driver.p.shape.operation.returns() {
        driver.returned()
    } else {
        driver.terminated()
    }
}
