//! Closed eight-call Legacy tree route. First/last are full state comparisons;
//! the middle six authenticate real transfers and complete functional returns.
//! Continued instructions are not counted as SINGLESTEP instructions.
use super::hardware::{self, Role, Target};
use super::*;

const ROUNDS: usize = 8;
const SELECTED: [usize; 2] = [0, 7];
const RF: u64 = 1 << 16;

pub struct BatchPairResult {
    /// Index and unchanged PairResult shape. Step fields are this round's
    /// deltas, including its outer RET; cumulative counters are below.
    pub selected: [(usize, PairResult); 2],
    pub original_steps: usize,
    pub candidate_steps: usize,
    pub hardware_stops: [usize; 2],
    pub calls: [usize; 2],
    pub tree_transfers: [usize; 2],
    pub outer_calls: [usize; 2],
    pub outer_returns: [usize; 2],
    /// Exit zero follows successful API finish and child-side complete joins.
    /// The parent observes normal reaps, not a synthetic finish receipt.
    pub normal_reaps: usize,
}

fn sequence(round: usize) -> u64 {
    assert!(round < ROUNDS, "exact eight calls, no ninth call");
    round as u64 + 1
}
fn words(child: &Tracee, address: u64) -> Vec<u64> {
    child
        .memory(address, 112)
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect()
}
fn check_armed(
    w: &[u64],
    round: usize,
    pid: u64,
    entry: u64,
    stack: (u64, u64),
    identity: Option<u64>,
) {
    assert_eq!(w.len(), 14);
    assert_eq!(
        &w[..2],
        &[1, sequence(round)],
        "actual ARMED lifetime sequence"
    );
    assert_ne!(w[2], 0);
    if let Some(identity) = identity {
        assert_eq!(w[2], identity, "retained gate identity");
    }
    assert_eq!(&w[3..6], &[pid, pid, entry]);
    assert_eq!(&w[6..9], &[0; 3]);
    assert_eq!(&w[9..11], &[stack.0, stack.1]);
    assert_eq!(&w[11..], &[0; 3]);
}
fn check_idle(w: &[u64], round: usize) {
    let mut expected = [0; 14];
    expected[1] = sequence(round);
    assert_eq!(
        w, &expected,
        "whole canonical IDLE after actual returned call"
    );
}
fn check_checkpoint(status: i32, signo: i32, code: i32, sender: i32, pid: i32) {
    assert_eq!(
        status,
        (libc::SIGSTOP << 8) | 0x7f,
        "one plain checkpoint stop"
    );
    assert_eq!((signo, code, sender), (libc::SIGSTOP, libc::SI_TKILL, pid));
}
fn check_rf(after: &libc::user_regs_struct) {
    // HW-RF-TRANSFER-1: observe the actual retired CALL/RET state; never repair it.
    assert_eq!(
        after.eflags & RF,
        0,
        "RF clear after actual transfer SINGLESTEP"
    );
}
fn check_outer_before(
    before: &libc::user_regs_struct,
    bytes: &[u8],
    gate: u64,
    root: u64,
    rsp: u64,
) {
    assert_eq!(before.rip, gate + 22);
    assert_eq!(bytes, [0x41, 0xff, 0xd3]);
    assert_eq!((before.rsp, before.r11), (rsp - 8, root));
}
fn check_outer_after(
    before: &libc::user_regs_struct,
    after: &libc::user_regs_struct,
    saved: u64,
    gate: u64,
    root: u64,
    rsp: u64,
) {
    assert_eq!(
        (after.rip, after.rsp, after.rax),
        (root, rsp - 16, before.rax)
    );
    assert_eq!(saved, gate + 25, "real outer CALL saved continuation");
    check_rf(after);
}
fn outer_before(child: &Tracee, ready: &Ready, rsp: u64) -> libc::user_regs_struct {
    let before = child.registers();
    check_outer_before(
        &before,
        &child.memory(before.rip, 3),
        ready.gate,
        ready.entry,
        rsp,
    );
    before
}
fn outer_after(child: &Tracee, ready: &Ready, rsp: u64, before: &libc::user_regs_struct) {
    let saved = u64::from_le_bytes(child.memory(rsp - 16, 8).try_into().unwrap());
    check_outer_after(
        before,
        &child.registers(),
        saved,
        ready.gate,
        ready.entry,
        rsp,
    );
}
fn memory(oracle: &OrdinaryOracle, child: &Tracee, ready: &Ready) {
    check_gate(ready, &child.memory(ready.gate, GATE_BYTES.len()));
    for (address, bytes) in &ready.immutable {
        assert_eq!(
            child.memory(*address, bytes.len()),
            *bytes,
            "whole source/image bytes"
        );
    }
    assert_eq!(
        child.memory(oracle.data.address(), PAGE),
        oracle.data.bytes(),
        "whole input page including both guards"
    );
}
fn hardware_stop(
    oracle: &OrdinaryOracle,
    child: &Tracee,
    ready: &Ready,
    candidate: bool,
    role: Role,
    count: &mut usize,
) -> hardware::HardwareStop {
    let target = Target::ready(ready, candidate, role).expect("closed Legacy tree target");
    let stop =
        hardware::stop_at(child, target).expect("owned hardware stop and exact DR restoration");
    *count += 1;
    memory(oracle, child, ready);
    stop
}

/// Complete single-step traversal for one selected pair. The inherited
/// snapshot and assert_state are used literally, including their stack range.
fn selected(
    oracle: &OrdinaryOracle,
    walks: &mut [Walk<'_>; 2],
    ready: &[Ready; 2],
    maps: &[BTreeMap<u64, u64>; 2],
    transfers: &mut [usize; 2],
    outer_calls: &mut [usize; 2],
) -> (Vec<Snapshot>, PairResult) {
    let mut witnesses = [
        call_tree::Witness::new(&ready[0], oracle.gate_rsp()),
        call_tree::Witness::new(&ready[1], oracle.gate_rsp()),
    ];
    let mut points = Vec::new();
    let mut visits = Vec::new();
    let mut returns = BTreeSet::new();
    loop {
        let child = walks[0].child;
        let pc = child.registers().rip;
        let logical = if GATE_HEADS.iter().any(|p| ready[0].gate + p == pc) {
            pc
        } else {
            *maps[0]
                .get(&pc)
                .expect("original escaped fixed tree heads/gate")
        };
        if ready[0].heads.contains(&logical) {
            visits.push(logical);
        }
        if ready[0].returns.contains(&logical) {
            returns.insert(logical);
        }
        points.push(oracle.snapshot(child, &ready[0], logical));
        if pc == ready[0].gate + OUTER_RET {
            break;
        }
        let transfer = witnesses[0].before(child, pc);
        let outer =
            (pc == ready[0].gate + 22).then(|| outer_before(child, &ready[0], oracle.gate_rsp()));
        walks[0].step("batch_selected_original");
        if let Some(before) = outer {
            outer_after(child, &ready[0], oracle.gate_rsp(), &before);
            outer_calls[0] += 1;
        }
        if let Some(transfer) = transfer {
            witnesses[0].after(child, transfer);
        }
    }
    let mut next = 0;
    loop {
        let child = walks[1].child;
        let pc = child.registers().rip;
        let logical = if GATE_HEADS.iter().any(|p| ready[1].gate + p == pc) {
            Some(pc)
        } else {
            maps[1].get(&pc).copied()
        };
        if let Some(logical) = logical {
            let point = oracle.snapshot(child, &ready[1], logical);
            let expected = points.get(next).expect("extra candidate restored boundary");
            assert_eq!(logical, expected.logical_pc, "all ordered original visits");
            assert_state(expected, &point);
            next += 1;
            if pc == ready[1].gate + OUTER_RET {
                break;
            }
        }
        let transfer = witnesses[1].before(child, pc);
        let outer =
            (pc == ready[1].gate + 22).then(|| outer_before(child, &ready[1], oracle.gate_rsp()));
        walks[1].step("batch_selected_candidate");
        if let Some(before) = outer {
            outer_after(child, &ready[1], oracle.gate_rsp(), &before);
            outer_calls[1] += 1;
        }
        if let Some(transfer) = transfer {
            witnesses[1].after(child, transfer);
        }
    }
    assert_eq!(next, points.len());
    assert_eq!(next, 343);
    assert_eq!(visits.len(), 332);
    assert_eq!(
        returns,
        BTreeSet::from([ready[0].entry + 22, ready[0].entry + 70])
    );
    for index in 0..2 {
        transfers[index] += witnesses[index].finish();
    }
    (
        points,
        PairResult {
            comparisons: next,
            original_steps: 0,
            candidate_steps: 0,
            visits: visits.len(),
            returns,
            declared_returns: ready[0].returns.iter().copied().collect(),
            value: 0,
        },
    )
}

fn middle(
    oracle: &OrdinaryOracle,
    walk: &mut Walk<'_>,
    ready: &Ready,
    candidate: bool,
    stops: &mut usize,
    transfers: &mut usize,
    outer_calls: &mut usize,
) {
    let mut witness = call_tree::Witness::new(ready, oracle.gate_rsp());
    hardware_stop(oracle, walk.child, ready, candidate, Role::OuterCall, stops);
    let before = outer_before(walk.child, ready, oracle.gate_rsp());
    walk.step("batch_middle_outer_call");
    outer_after(walk.child, ready, oracle.gate_rsp(), &before);
    *outer_calls += 1;
    for role in [Role::TreeCall, Role::ChildRet, Role::RootRet] {
        let stop = hardware_stop(oracle, walk.child, ready, candidate, role, stops);
        let transfer = witness
            .before(walk.child, stop.raw().rip)
            .expect("exact physical tree transfer");
        walk.step("batch_middle_tree_transfer");
        witness.after(walk.child, transfer);
        check_rf(&walk.child.registers());
    }
    *transfers += witness.finish();
    hardware_stop(oracle, walk.child, ready, candidate, Role::OuterRet, stops);
}

struct Harness<'a> {
    saved: libc::user_regs_struct,
    xstate: &'a [u8],
    word: &'a [u8],
}

/// Execute this call's actual outer C3 on its saved Rust stack, then observe
/// its own post-return checkpoint or final normal exit. There is one waiter.
fn returned(
    oracle: &OrdinaryOracle,
    walk: &mut Walk<'_>,
    ready: &Ready,
    harness: Harness<'_>,
    round: usize,
    value: u64,
) {
    let Harness {
        saved,
        xstate,
        word,
    } = harness;
    let actual = walk.child.registers();
    assert_eq!(
        (actual.rip, actual.rsp, actual.rax),
        (ready.gate + OUTER_RET, oracle.gate_rsp(), value)
    );
    memory(oracle, walk.child, ready);
    assert_eq!(
        walk.child.memory(saved.rsp, 8),
        word,
        "own harness return word unchanged"
    );
    let continuation = u64::from_le_bytes(word.try_into().unwrap());
    let mut restored = saved;
    restored.rax = actual.rax;
    restored.rip = actual.rip; // Still the physical outer C3.
    walk.child.set_registers(&restored);
    walk.child.set_xstate(xstate);
    walk.step("batch_outer_return");
    let after = walk.child.registers();
    assert_eq!(
        (after.rip, after.rsp, after.rax),
        (continuation, saved.rsp.checked_add(8).unwrap(), value)
    );
    assert_eq!(
        walk.child.memory(saved.rsp, 8),
        word,
        "actual RET preserved saved word"
    );
    check_rf(&after);
    let mut resumed = after;
    resumed.eflags = harness_resume_flags(saved.eflags, after.eflags);
    walk.child.set_registers(&resumed);
    assert!(Instant::now() < walk.child.deadline);
    walk.child.request(libc::PTRACE_CONT, 0, 0);
    let status = walk.child.wait();
    assert!(
        Instant::now() < walk.child.deadline,
        "same absolute batch deadline after wait"
    );
    if round + 1 < ROUNDS {
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        walk.child
            .request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
        check_checkpoint(
            status,
            info.si_signo,
            info.si_code,
            unsafe { info.si_pid() },
            walk.child.pid,
        );
        check_idle(&words(walk.child, saved.rdi), round);
        memory(oracle, walk.child, ready);
    } else {
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "eighth invoke, successful finish and complete child checks required: {status:#x}"
        );
        assert!(walk.child.reaped.get());
        let mut status = 0;
        assert_eq!(
            unsafe {
                libc::waitpid(
                    walk.child.pid,
                    &raw mut status,
                    libc::WNOHANG | libc::__WALL,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

impl OrdinaryOracle {
    /// Closed tree only. setup must begin exactly eight requests before ready,
    /// signal seven self-SIGSTOP checkpoints after returned-call validation,
    /// and finish/export successfully before returning. Both inspected traces
    /// are borrowed only after both normal reaps; no native evidence is mocked.
    pub fn pair_tree_batch<F, O>(&self, setup: F, mut inspect: O) -> BatchPairResult
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnMut(usize, OriginalObservation<'a>),
    {
        let (case, deadline) = match self.subject {
            Subject::Tree { case, deadline } => (case, deadline),
            _ => panic!("batch route requires the closed tree constructor"),
        };
        let length = call_tree::truth::INPUT_BYTES;
        assert_eq!(length, 1024);
        assert!(
            Instant::now() < deadline,
            "batch deadline began before oracle allocation"
        );
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        let mut pipes = [Pipe::new(), Pipe::new()];
        let mut pids = [0; 2];
        for index in 0..2 {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                for (n, pipe) in pipes.iter().enumerate() {
                    unsafe {
                        libc::close(pipe.0[0]);
                    }
                    if n != index {
                        unsafe {
                            libc::close(pipe.0[1]);
                        }
                    }
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    setup(
                        index == 1,
                        ChildContext {
                            oracle: self,
                            write: pipes[index].0[1],
                            output: None,
                            length,
                        },
                    );
                }));
                // Never unwind inherited mappings or sibling custody in a child.
                unsafe {
                    libc::_exit(if result.is_ok() { 0 } else { 122 });
                }
            }
            if pid < 0 {
                if index == 1 {
                    drop(Tracee {
                        pid: pids[0],
                        deadline,
                        reaped: Cell::new(false),
                    });
                }
                panic!("batch fixture fork failed");
            }
            pids[index] = pid;
        }
        // No parent allocation/read/validation between the two forks.
        let children = pids.map(|pid| Tracee {
            pid,
            deadline,
            reaped: Cell::new(false),
        });
        for pipe in &mut pipes {
            pipe.close_write();
        }
        let ready = [pipes[0].read(&children[0]), pipes[1].read(&children[1])];
        for child in &children {
            let status = child.wait();
            assert!(Instant::now() < deadline);
            assert_eq!(status, (libc::SIGSTOP << 8) | 0x7f);
            child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        }
        let maps = [ready[0].validate(false), ready[1].validate(true)];
        same_ready(&ready[0], &ready[1]);
        assert_eq!(ready[0].profile, Profile::Legacy);
        // Authenticate the entire fixed source and the original physical E8.
        for r in &ready {
            let _ = call_tree::Witness::new(r, self.gate_rsp());
        }
        assert_eq!(
            &self.data.bytes()[128..128 + length],
            &call_tree::truth::input(case, self.seed)
        );
        let value = call_tree::truth::scalar(case, self.seed);
        let mut walks = [
            Walk {
                child: &children[0],
                steps: 0,
            },
            Walk {
                child: &children[1],
                steps: 0,
            },
        ];
        let mut stops = [0; 2];
        let mut calls = [0; 2];
        let mut transfers = [0; 2];
        let mut outer_calls = [0; 2];
        let mut outer_returns = [0; 2];
        let mut identities = [None; 2];
        let mut first_arguments: [Option<libc::user_regs_struct>; 2] = [None, None];
        let mut captured = Vec::with_capacity(2);
        for round in 0..ROUNDS {
            let start = [walks[0].steps, walks[1].steps];
            let gates = [
                hardware_stop(
                    self,
                    walks[0].child,
                    &ready[0],
                    false,
                    Role::GateEntry,
                    &mut stops[0],
                ),
                hardware_stop(
                    self,
                    walks[1].child,
                    &ready[1],
                    true,
                    Role::GateEntry,
                    &mut stops[1],
                ),
            ];
            let saved = [
                gates[0].harness().expect("authenticated RF-only harness"),
                gates[1].harness().expect("authenticated RF-only harness"),
            ];
            same_arguments(&saved[0], &saved[1]);
            let xstate = [walks[0].child.xstate(), walks[1].child.xstate()];
            assert_eq!(xstate[0].len(), xstate[1].len());
            let return_words = [
                walks[0].child.memory(saved[0].rsp, 8),
                walks[1].child.memory(saved[1].rsp, 8),
            ];
            let armed = [
                words(walks[0].child, saved[0].rdi),
                words(walks[1].child, saved[1].rdi),
            ];
            for index in 0..2 {
                if let Some(previous) = &first_arguments[index] {
                    same_arguments(previous, &saved[index]);
                } else {
                    first_arguments[index] = Some(saved[index]);
                }
                check_armed(
                    &armed[index],
                    round,
                    children[index].pid as u64,
                    ready[index].entry,
                    (
                        self.stack.address() + PAGE as u64,
                        self.stack.address() + STACK_BYTES as u64,
                    ),
                    identities[index],
                );
                identities[index] = Some(armed[index][2]);
                self.seed(walks[index].child, saved[index], length);
            }
            let observation = if SELECTED.contains(&round) {
                Some(selected(
                    self,
                    &mut walks,
                    &ready,
                    &maps,
                    &mut transfers,
                    &mut outer_calls,
                ))
            } else {
                for index in 0..2 {
                    middle(
                        self,
                        &mut walks[index],
                        &ready[index],
                        index == 1,
                        &mut stops[index],
                        &mut transfers[index],
                        &mut outer_calls[index],
                    );
                }
                None
            };
            self.frame_after(walks[0].child, &saved[0], &ready[0], &armed[0], None);
            call_tree::frame_after(
                walks[1].child,
                &saved[1],
                &ready[1],
                &armed[1],
                self.gate_rsp(),
            );
            for index in 0..2 {
                returned(
                    self,
                    &mut walks[index],
                    &ready[index],
                    Harness {
                        saved: saved[index],
                        xstate: &xstate[index],
                        word: &return_words[index],
                    },
                    round,
                    value,
                );
                calls[index] += 1;
                outer_returns[index] += 1;
            }
            if let Some((points, mut result)) = observation {
                result.original_steps = walks[0].steps - start[0];
                result.candidate_steps = walks[1].steps - start[1];
                result.value = value;
                captured.push((round, result, points));
            }
        }
        assert_eq!(stops, [38; 2]);
        assert_eq!(calls, [8; 2]);
        assert_eq!(transfers, [24; 2]);
        assert_eq!(outer_calls, [8; 2]);
        assert_eq!(outer_returns, [8; 2]);
        assert!(children.iter().all(|child| child.reaped.get()));
        assert!(
            Instant::now() < deadline,
            "both normal batch reaps within original deadline"
        );
        assert_eq!(captured.len(), 2);
        for (round, _, points) in &captured {
            inspect(
                *round,
                OriginalObservation {
                    entry: ready[0].entry,
                    continuation: ready[0].continuation,
                    source_address: ready[0].immutable[0].0,
                    source: &ready[0].original_source,
                    input_address: self.data.address() + 128,
                    input: &self.data.bytes()[128..128 + length],
                    data_address: self.data.address(),
                    stack_address: self.stack_start(Profile::Legacy),
                    points,
                },
            );
            assert!(
                Instant::now() < deadline,
                "selected trace/model inspection shares deadline"
            );
        }
        let (last, last_result, _) = captured.pop().unwrap();
        let (first, first_result, _) = captured.pop().unwrap();
        assert_eq!([first, last], SELECTED);
        BatchPairResult {
            selected: [(first, first_result), (last, last_result)],
            original_steps: walks[0].steps,
            candidate_steps: walks[1].steps,
            hardware_stops: stops,
            calls,
            tree_transfers: transfers,
            outer_calls,
            outer_returns,
            normal_reaps: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn regs() -> libc::user_regs_struct {
        unsafe { core::mem::zeroed() }
    }
    #[test]
    fn batch_armed_all_fields_and_retained_lifetime_refuse_corruption() {
        let valid = [1, 8, 99, 42, 42, 0x3000, 0, 0, 0, 0x1000, 0x9000, 0, 0, 0];
        check_armed(&valid, 7, 42, 0x3000, (0x1000, 0x9000), Some(99));
        for i in 0..14 {
            let mut bad = valid;
            bad[i] ^= 1;
            assert!(
                std::panic::catch_unwind(|| check_armed(
                    &bad,
                    7,
                    42,
                    0x3000,
                    (0x1000, 0x9000),
                    Some(99)
                ))
                .is_err()
            );
        }
        assert!(std::panic::catch_unwind(|| sequence(8)).is_err());
        assert!(
            std::panic::catch_unwind(|| check_armed(
                &valid,
                6,
                42,
                0x3000,
                (0x1000, 0x9000),
                Some(99)
            ))
            .is_err()
        );
    }
    #[test]
    fn batch_checkpoint_exact_idle_refuses_missing_or_early_return() {
        let mut valid = [0; 14];
        valid[1] = 4;
        check_idle(&valid, 3);
        for i in 0..14 {
            let mut bad = valid;
            bad[i] ^= 1;
            assert!(std::panic::catch_unwind(|| check_idle(&bad, 3)).is_err());
        }
        assert!(std::panic::catch_unwind(|| check_idle(&valid, 2)).is_err());
        assert!(std::panic::catch_unwind(|| check_idle(&valid, 4)).is_err());
    }
    #[test]
    fn batch_checkpoint_requires_exact_self_thread_signal() {
        let good = (
            (libc::SIGSTOP << 8) | 0x7f,
            libc::SIGSTOP,
            libc::SI_TKILL,
            42,
        );
        check_checkpoint(good.0, good.1, good.2, good.3, 42);
        for bad in [
            (0, good.1, good.2, good.3),
            (good.0 | (1 << 16), good.1, good.2, good.3),
            (good.0, libc::SIGTRAP, good.2, good.3),
            (good.0, good.1, libc::SI_USER, good.3),
            (good.0, good.1, good.2, 43),
        ] {
            assert!(
                std::panic::catch_unwind(|| check_checkpoint(bad.0, bad.1, bad.2, bad.3, 42))
                    .is_err()
            );
        }
    }
    #[test]
    fn batch_outer_call_checks_actual_instruction_successor_word_and_rf() {
        let mut before = regs();
        before.rip = 0x2016;
        before.rsp = 0x7ff8;
        before.r11 = 0x3000;
        before.rax = 73;
        check_outer_before(&before, &[0x41, 0xff, 0xd3], 0x2000, 0x3000, 0x8000);
        let mut after = before;
        after.rip = 0x3000;
        after.rsp = 0x7ff0;
        after.eflags = 0x303;
        check_outer_after(&before, &after, 0x2019, 0x2000, 0x3000, 0x8000);
        for i in 0..4 {
            let mut bad = after;
            match i {
                0 => bad.rip += 1,
                1 => bad.rsp += 8,
                2 => bad.rax += 1,
                _ => bad.eflags |= RF,
            }
            assert!(
                std::panic::catch_unwind(|| check_outer_after(
                    &before, &bad, 0x2019, 0x2000, 0x3000, 0x8000
                ))
                .is_err()
            );
        }
        assert!(
            std::panic::catch_unwind(|| check_outer_after(
                &before, &after, 0x2020, 0x2000, 0x3000, 0x8000
            ))
            .is_err()
        );
        for i in 0..3 {
            let mut bad = before;
            match i {
                0 => bad.rip += 1,
                1 => bad.rsp += 8,
                _ => bad.r11 += 1,
            }
            assert!(
                std::panic::catch_unwind(|| check_outer_before(
                    &bad,
                    &[0x41, 0xff, 0xd3],
                    0x2000,
                    0x3000,
                    0x8000
                ))
                .is_err()
            );
        }
        assert!(
            std::panic::catch_unwind(|| check_outer_before(
                &before,
                &[0x41, 0xff, 0xd2],
                0x2000,
                0x3000,
                0x8000
            ))
            .is_err()
        );
    }
}
