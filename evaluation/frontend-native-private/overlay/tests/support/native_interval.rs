//! Additive borrowed-live-DSO adapter. All old oracle functions stay literal.
//! One persistent owned tracee per cohort retains TLS/K/generation history.
//! Its unchanged 15-second deadline and 20,000-step budget cover the ENTIRE
//! cohort, not each invocation. Explicit initialization happens only before an
//! invocation, after the preceding actual RET state was fully compared.
use super::*;
use std::mem::ManuallyDrop;
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub struct Invocation {
    pub argument: u64,
    pub state_seed: u64,
}
pub struct CohortTrace {
    states: Vec<Vec<Snapshot>>,
    calls: Vec<(Snapshot, Snapshot)>,
    initial: Vec<libc::user_regs_struct>,
    xstate: Vec<Vec<u8>>,
    invocations: Vec<Invocation>,
}
pub struct PhaseExpectation<'a> {
    pub journal: u64,
    pub events: &'a [[u64; 7]],
    pub owned_threads: usize,
}
pub struct BorrowedLeafOracle {
    inner: ManuallyDrop<NativeOracle>,
    entry: u64,
    invoke: u64,
    immutable: Vec<(u64, Vec<u8>)>,
}
impl BorrowedLeafOracle {
    /// # Safety
    /// The complete page and declared immutable ranges are live ld.so mappings
    /// retained for process lifetime. No unrelated execution/publication occurs.
    pub unsafe fn new(
        page: u64,
        entry: u64,
        invoke: u64,
        terminal: u64,
        immutable: &[(u64, usize)],
    ) -> Self {
        assert_eq!(page % PAGE as u64, 0);
        assert!(entry >= page && entry + 19 <= page + PAGE as u64);
        assert!(
            terminal >= page
                && terminal < page + PAGE as u64
                && !(entry..entry + 19).contains(&terminal)
        );
        assert!(invoke >= entry + 19 && invoke + 5 == terminal);
        let code = ManuallyDrop::new(Mapping {
            address: page as usize as *mut u8,
            len: PAGE,
        });
        let data = Mapping::new(PAGE);
        data.initialize(
            0,
            &(0..PAGE).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>(),
        );
        let stack = Mapping::new(STACK_BYTES + PAGE);
        stack.initialize(0, &vec![0x5a; STACK_BYTES + PAGE]);
        assert_eq!(
            unsafe { libc::mprotect(stack.writable().cast(), PAGE, libc::PROT_NONE) },
            0
        );
        let initial_rsp = stack.address() + STACK_BYTES as u64 - 8;
        // The first return slot stays 0x5a: only the actual CALL may create it.
        let original_code = code.bytes().to_vec();
        let immutable = immutable
            .iter()
            .map(|&(address, len)| {
                assert!(len > 0 && len <= 65536);
                assert!(address + len as u64 <= page || address >= page + PAGE as u64);
                (
                    address,
                    unsafe { std::slice::from_raw_parts(address as usize as *const u8, len) }
                        .to_vec(),
                )
            })
            .collect();
        Self {
            inner: ManuallyDrop::new(NativeOracle {
                code: ManuallyDrop::into_inner(code),
                data,
                stack,
                initial_rsp,
                return_pc: terminal,
                original_code,
                seeded_arithmetic_flags: false,
            }),
            entry,
            invoke,
            immutable,
        }
    }
    pub fn stack_range(&self) -> (u64, u64) {
        (
            self.inner.stack.address() + PAGE as u64,
            self.inner.stack.address() + self.inner.stack.len as u64,
        )
    }
    pub fn rsp(&self) -> u64 {
        self.inner.initial_rsp
    }
    pub fn terminal(&self) -> u64 {
        self.inner.return_pc
    }
    pub fn assert_publication(&self, edits: &[(u64, Vec<u8>)]) {
        self.inner.assert_publication(edits);
    }
    fn snapshot(&self, child: &Tracee, logical: u64, code: &[u8]) -> Snapshot {
        for (address, bytes) in &self.immutable {
            assert_eq!(
                child.memory(*address, bytes.len()),
                *bytes,
                "loader-owned immutable range changed"
            );
        }
        // EXACT existing comparison input and masks, not a parallel comparator.
        self.inner.snapshot(child, logical, code)
    }
    fn heads(&self) -> [u64; 6] {
        [
            self.entry,
            self.entry + 5,
            self.entry + 12,
            self.entry + 15,
            self.entry + 18,
            self.terminal(),
        ]
    }
    pub fn original<F, G>(
        &self,
        invocations: &[Invocation],
        journal: u64,
        setup: F,
        captures: &Path,
    ) -> CohortTrace
    where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        self.assert_publication(&[]);
        assert!((1..=3).contains(&invocations.len()));
        let prepared = Prepared::fork(setup, 1);
        let child = &prepared.child;
        let mut trace = CohortTrace {
            states: Vec::new(),
            calls: Vec::new(),
            initial: Vec::new(),
            xstate: Vec::new(),
            invocations: invocations.to_vec(),
        };
        let mut steps = 0;
        for (index, invocation) in invocations.iter().enumerate() {
            let mut initial = prepared.resume;
            let mut state = invocation.state_seed;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            initial.rax = next();
            initial.rbx = next();
            initial.rcx = next();
            initial.rdx = next();
            initial.rbp = next();
            initial.rsi = self.inner.data.address() + 512;
            initial.rdi = invocation.argument;
            initial.r8 = next();
            initial.r9 = next();
            initial.r10 = next();
            initial.r11 = next();
            initial.r12 = next();
            initial.r13 = next();
            initial.r14 = next();
            initial.r15 = next();
            initial.rsp = self.rsp() + 8;
            initial.rip = self.invoke;
            initial.orig_rax = u64::MAX;
            initial.eflags = 0xad7 | ((invocation.state_seed & 1) << 10);
            let xstate = seeded_xstate(prepared.xstate.clone(), invocation.state_seed);
            child.set_registers(&initial);
            child.set_xstate(&xstate);
            trace.initial.push(initial);
            trace.xstate.push(child.xstate());
            let call = self.call(child, &mut steps, captures, index);
            assert_journal(child, journal, &[]);
            trace.calls.push(call);
            let mut states = Vec::new();
            for (position, &head) in self.heads().iter().enumerate() {
                assert_eq!(
                    child.registers().rip,
                    head,
                    "independent original head/return order"
                );
                let snapshot = self.snapshot(child, head, self.inner.code.bytes());
                assert_journal(child, journal, &[]);
                if position == 5 {
                    self.assert_return(&snapshot, *invocation);
                }
                save_snapshot(captures, index, position, &snapshot);
                states.push(snapshot);
                if position != 5 {
                    bounded_step(child, &mut steps);
                }
            }
            // The final RET snapshot is retained BEFORE next-call initialization.
            trace.states.push(states);
        }
        std::fs::write(captures.join("journal.bin"), child.memory(journal, PAGE)).unwrap();
        prepared.finish(captures, steps);
        trace
    }
    pub fn compare<F, G>(
        &self,
        trace: &CohortTrace,
        map: &TraceMap,
        expectation: PhaseExpectation<'_>,
        setup: F,
        captures: &Path,
    ) where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        let PhaseExpectation {
            journal,
            events: expected_events,
            owned_threads,
        } = expectation;
        assert_eq!(trace.initial.len(), trace.states.len());
        assert_eq!(trace.calls.len(), trace.states.len());
        let code = self.inner.code.bytes().to_vec();
        let heads = self.heads();
        assert_eq!(map.boundaries.len(), 6);
        for head in heads {
            assert_eq!(
                map.boundaries
                    .iter()
                    .filter(|&&(logical, _)| logical == head)
                    .count(),
                1
            );
        }
        let prepared = Prepared::fork(setup, owned_threads);
        let child = &prepared.child;
        let mut steps = 0;
        let mut seen_events = 0;
        for (index, expected) in trace.states.iter().enumerate() {
            // Only this initial write is allowed. No SETREGS/SETREGSET occurs
            // after entering until all five heads AND actual RET are compared.
            child.set_registers(&trace.initial[index]);
            child.set_xstate(&trace.xstate[index]);
            assert_journal(child, journal, &expected_events[..seen_events]);
            let (before_call, after_call) = self.call(child, &mut steps, captures, index);
            assert_state(&trace.calls[index].0, &before_call);
            assert_state(&trace.calls[index].1, &after_call);
            assert_journal(child, journal, &expected_events[..seen_events]);
            let mut next = 0;
            loop {
                assert!(
                    Instant::now() < child.deadline,
                    "whole persistent cohort deadline"
                );
                let pc = child.registers().rip;
                if let Some(&(logical, _)) =
                    map.boundaries.iter().find(|&&(_, physical)| physical == pc)
                {
                    let before = expected
                        .get(next)
                        .expect("unexpected extra restored boundary");
                    assert_eq!(
                        logical, before.logical_pc,
                        "ordered original/installed visit"
                    );
                    let actual = self.snapshot(child, logical, &code);
                    assert_state(before, &actual);
                    save_snapshot(captures, index, next, &actual);
                    if (logical == self.entry || logical == self.entry + 18)
                        && !expected_events.is_empty()
                    {
                        seen_events += 1;
                    }
                    assert_journal(child, journal, &expected_events[..seen_events]);
                    next += 1;
                    if logical == self.terminal() {
                        assert_eq!(next, 6, "omitted source visit");
                        self.assert_return(&actual, trace.invocations[index]);
                        break;
                    }
                } else if (self.inner.code.address()..self.inner.code.address() + PAGE as u64)
                    .contains(&pc)
                {
                    assert!(map.gateways.contains(&pc), "undeclared source PC");
                }
                bounded_step(child, &mut steps);
            }
        }
        assert_eq!(seen_events, expected_events.len());
        std::fs::write(captures.join("journal.bin"), child.memory(journal, PAGE)).unwrap();
        prepared.finish(captures, steps);
    }
    fn assert_return(&self, point: &Snapshot, invocation: Invocation) {
        assert_eq!(
            point.registers.rsp,
            self.rsp() + 8,
            "real original RET stack consumption"
        );
        assert_eq!(
            point.registers.rip,
            self.terminal(),
            "real original return target"
        );
        assert_eq!(point.registers.rax, 3 * invocation.argument + 18);
        assert_eq!(
            u64::from_le_bytes(point.data[512..520].try_into().unwrap()),
            3 * invocation.argument + 18
        );
        assert_eq!(
            &point.application_stack[128..136],
            &self.terminal().to_le_bytes(),
            "application return word was changed"
        );
    }
    fn call(
        &self,
        child: &Tracee,
        steps: &mut usize,
        captures: &Path,
        invocation: usize,
    ) -> (Snapshot, Snapshot) {
        let code = self.inner.code.bytes();
        let before = self.snapshot(child, self.invoke, code);
        assert_eq!(before.registers.rip, self.invoke);
        assert_eq!(before.registers.rsp, self.rsp() + 8);
        assert_eq!(
            before.registers.rsp % 16,
            0,
            "actual SysV caller stack alignment"
        );
        if invocation == 0 {
            assert_eq!(
                &before.application_stack[128..136],
                &[0x5a; 8],
                "first return slot has no planted continuation"
            );
        } else {
            assert_eq!(
                &before.application_stack[128..136],
                &self.terminal().to_le_bytes(),
                "prior complete RET left the same owned word"
            );
        }
        let bytes = child.memory(self.invoke, 5);
        assert_eq!(bytes[0], 0xe8);
        assert_eq!(
            i128::from(self.invoke)
                + 5
                + i128::from(i32::from_le_bytes(bytes[1..].try_into().unwrap())),
            i128::from(self.entry)
        );
        bounded_step(child, steps);
        let after = self.snapshot(child, self.entry, code);
        assert_eq!(after.registers.rip, self.entry, "real CALL destination");
        assert_eq!(after.registers.rsp, self.rsp(), "real CALL stack effect");
        assert_eq!(
            child.memory(after.registers.rsp, 8),
            self.terminal().to_le_bytes(),
            "real CALL pushed return word"
        );
        // An independent ISA expectation changes ONLY RIP, RSP and the eight
        // bytes owned by this actual direct CALL. Every other old GPR, flags,
        // XSAVE, application-page and stack/red-zone assertion remains active.
        let mut expected_registers = before.registers;
        expected_registers.rip = self.entry;
        expected_registers.rsp -= 8;
        let mut expected_stack = before.application_stack.clone();
        expected_stack[128..136].copy_from_slice(&self.terminal().to_le_bytes());
        let expected = Snapshot {
            logical_pc: self.entry,
            registers: expected_registers,
            xstate: before.xstate.clone(),
            data: before.data.clone(),
            application_stack: expected_stack,
        };
        assert_state(&expected, &after);
        save_named_snapshot(captures, &format!("call-{invocation}-before"), &before);
        save_named_snapshot(captures, &format!("call-{invocation}-after"), &after);
        std::fs::write(captures.join(format!("call-{invocation}.json")), format!(
            "{{\"caller\":{},\"entry\":{},\"return_pc\":{},\"rsp_before\":{},\"rsp_after\":{}}}\n",
            before.registers.rip, after.registers.rip, self.terminal(), before.registers.rsp, after.registers.rsp)).unwrap();
        (before, after)
    }
}
impl Drop for BorrowedLeafOracle {
    fn drop(&mut self) {
        // Only these allocations are owned. Never munmap ld.so's source page.
        unsafe {
            std::ptr::drop_in_place(&mut self.inner.data);
            std::ptr::drop_in_place(&mut self.inner.stack);
            std::ptr::drop_in_place(&mut self.inner.original_code);
        }
    }
}
fn bounded_step(child: &Tracee, steps: &mut usize) {
    assert!(
        *steps < MAX_STEPS,
        "whole persistent cohort 20000-step budget"
    );
    assert!(Instant::now() < child.deadline);
    *steps += 1;
    child.step(&[]);
}
fn assert_journal(child: &Tracee, address: u64, expected: &[[u64; 7]]) {
    let mut bytes = vec![0_u8; PAGE];
    bytes[..8].copy_from_slice(&(expected.len() as u64).to_ne_bytes());
    // The observed writer is this exact ptrace-owned actual application thread.
    bytes[16..24].copy_from_slice(&(child.pid as u64).to_ne_bytes());
    let depth = expected
        .last()
        .map_or(0_u64, |e| if matches!(e[0], 1 | 3) { 1 } else { 0 });
    bytes[24..32].copy_from_slice(&depth.to_ne_bytes());
    for (i, row) in expected.iter().enumerate() {
        for (j, word) in row.iter().enumerate() {
            let offset = 32 + i * 56 + j * 8;
            bytes[offset..offset + 8].copy_from_slice(&word.to_ne_bytes());
        }
    }
    assert_eq!(
        child.memory(address, PAGE),
        bytes,
        "complete journal prefix/header/zero-tail"
    );
}
fn save_snapshot(directory: &Path, invocation: usize, point: usize, snapshot: &Snapshot) {
    let stem = format!("call-{invocation}-point-{point}");
    save_named_snapshot(directory, &stem, snapshot);
}
fn save_named_snapshot(directory: &Path, stem: &str, snapshot: &Snapshot) {
    // Every native register field remains in the old assert_state comparison.
    let r = &snapshot.registers;
    let registers = [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ];
    let bytes: Vec<u8> = registers.iter().flat_map(|r| r.to_le_bytes()).collect();
    std::fs::write(directory.join(format!("{stem}.regs")), bytes).unwrap();
    std::fs::write(directory.join(format!("{stem}.xstate")), &snapshot.xstate).unwrap();
    std::fs::write(directory.join(format!("{stem}.data")), &snapshot.data).unwrap();
    std::fs::write(
        directory.join(format!("{stem}.stack")),
        &snapshot.application_stack,
    )
    .unwrap();
}

struct Prepared {
    child: Tracee,
    resume: libc::user_regs_struct,
    xstate: Vec<u8>,
    tasks: Vec<u32>,
}
impl Prepared {
    fn fork<F, G>(setup: F, expected_tasks: usize) -> Self
    where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        // This API is confined to the ordinary single-main-thread fixture.
        let tasks: Vec<_> = std::fs::read_dir("/proc/self/task").unwrap().collect();
        assert_eq!(tasks.len(), 1, "fork only a certified single-thread parent");
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // The parent has one thread and no foreign fixture callers/locks.
            // All model/thread setup is before application entry and ptrace stop.
            let finish = setup();
            unsafe {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) != 0 {
                    libc::_exit(120);
                }
                libc::raise(libc::SIGSTOP);
            }
            // The tracer restores this exact saved setup context ONLY AFTER
            // final RET comparison. The closure joins the owned controller.
            finish();
            assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
            unsafe { libc::_exit(0) };
        }
        let child = Tracee {
            pid,
            deadline: Instant::now() + CHILD_BUDGET,
            reaped: Cell::new(false),
        };
        let status = child.wait();
        assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
        child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        assert!(matches!(expected_tasks, 1 | 2));
        let mut tasks: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap()
            })
            .collect();
        tasks.sort();
        assert_eq!(
            tasks.len(),
            expected_tasks,
            "exact owned controller inventory at stop"
        );
        assert!(tasks.contains(&(pid as u32)));
        assert!(tasks.windows(2).all(|pair| pair[0] < pair[1]));
        let resume = child.registers();
        let xstate = child.xstate();
        Self {
            child,
            resume,
            xstate,
            tasks,
        }
    }
    fn finish(self, captures: &Path, steps: usize) {
        let before = self.child.memory(self.resume.rsp, 8);
        self.child.set_registers(&self.resume);
        self.child.set_xstate(&self.xstate);
        self.child.request(libc::PTRACE_CONT, 0, 0);
        let status = self.child.wait();
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "owned child/join failed {status:#x}"
        );
        assert!(self.child.reaped.get());
        std::fs::write(captures.join("child.json"), format!(
            "{{\"pid\":{},\"status\":{},\"steps\":{},\"trace_wall_bound\":15,\"step_bound\":20000,\"tasks_at_stop\":{:?},\"setup_stack_word\":{:?}}}\n",
            self.child.pid, status, steps, self.tasks, before)).unwrap();
    }
}
