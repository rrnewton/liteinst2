//! Pure seal-preparation controls. Registry identities and census bindings are
//! real model values; all stop/state facts below are synthetic. No case calls
//! the native seal constructor, observes exec, or authorizes a release.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::selected::{SyscallAbi, SyscallAliases, decode};

const SESSION: u64 = 71;
const PC: u64 = 0x401000;

fn registers() -> RegisterSnapshot {
    RegisterSnapshot {
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
        rax: libc::SYS_execve as u64,
        rcx: 4,
        rdx: 0x1180,
        rsi: 0x1100,
        rdi: 0x1000,
        orig_rax: u64::MAX,
        rip: PC,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x2f00,
        ss: 0x2b,
        fs_base: 0x3500,
        gs_base: 0x4500,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

fn selected(registers: RegisterSnapshot) -> SelectedInput {
    SelectedInput::new(
        decode(PC, &[0x0f, 0x05], &SyscallAliases::new()).unwrap(),
        registers,
    )
    .unwrap()
}

fn fixture() -> (PendingInvocation, ExecCensusBinding) {
    let registry = LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 2,
            obligations: 8,
        },
        100,
        PC,
    )
    .unwrap();
    let row = registry.task(registry.root_task()).unwrap();
    let task = DynamicTask {
        task: row.id,
        process: row.process,
        address_space: row.address_space,
        generation: 0,
    };
    let stop = DynamicStop {
        session: SESSION,
        sequence: 23,
        tid: 100,
        task: Some(task.task),
    };
    let before = ObservedStop {
        token: stop.clone(),
        task,
        logical_pc: PC,
        registers: registers(),
        xstate: (0..832).map(|i| (i % 251) as u8).collect(),
        signal_mask: 0x600,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    };
    let mut census = ResumeCensus::new(
        SESSION,
        task.address_space,
        0,
        census::Limits {
            epochs: 8,
            source_fact_bytes: 64 * 1024 * 1024,
            reports: 8,
            origins: 8,
            witnesses: 8,
            plan_history: 8,
        },
    )
    .unwrap();
    let reservation = census
        .reserve(BudgetCharge {
            epochs: 2,
            source_fact_bytes: 1024 * 1024,
            reports: 2,
            origins: 2,
            witnesses: 2,
            plan_history: 2,
        })
        .unwrap();
    let origin = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, before.clone())
        .unwrap();
    let binding = census
        .prepare_exec_mm(
            reservation,
            origin,
            ExecutionId::from_owner(SESSION, 9).unwrap(),
        )
        .unwrap()
        .binding();
    (
        PendingInvocation {
            token: PendingToken {
                stop: stop.clone(),
                task,
                epoch: 0,
                plan: 7,
                invocation: 9,
            },
            stop: AdmissionStop {
                token: stop,
                identity: task,
                phase: AdmissionPhase::Restored,
                signal: None,
            },
            before,
            input: selected(registers()),
            until: Instant::now() + Duration::from_secs(60),
        },
        binding,
    )
}

#[derive(Debug, Eq, PartialEq)]
struct PendingSnapshot {
    token: PendingToken,
    stop: AdmissionStop,
    before: ObservedStop,
    input: SelectedInput,
    until: Instant,
}
fn pending_snapshot(p: &PendingInvocation) -> PendingSnapshot {
    PendingSnapshot {
        token: p.token.clone(),
        stop: p.stop.clone(),
        before: p.before.clone(),
        input: p.input.clone(),
        until: p.until,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct SealSnapshot {
    binding: ExecCensusBinding,
    original: PendingToken,
    next_pc: u64,
    until: Instant,
    before: ObservedStop,
    bound: bool,
    new_xstate: Vec<u8>,
    capacities: (usize, usize),
}
fn seal_snapshot(s: &PreparedExecSeal) -> SealSnapshot {
    SealSnapshot {
        binding: s.binding,
        original: s.original.clone(),
        next_pc: s.next_pc,
        until: s.until,
        before: s.before.clone(),
        bound: s.bound,
        new_xstate: s.new_xstate.clone(),
        capacities: (s.before.xstate.capacity(), s.new_xstate.capacity()),
    }
}
fn refused<T>(result: Result<T, GateError>, expected: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(actual)) if actual == expected));
}

// Every native GPR/selector/base/flags field participates in the unchanged-state
// comparator. These mutations do not seed expected values from seal output.
fn register_mutations() -> [fn(&mut RegisterSnapshot); 27] {
    [
        |r| r.r15 ^= 1,
        |r| r.r14 ^= 1,
        |r| r.r13 ^= 1,
        |r| r.r12 ^= 1,
        |r| r.rbp ^= 1,
        |r| r.rbx ^= 1,
        |r| r.r11 ^= 1,
        |r| r.r10 ^= 1,
        |r| r.r9 ^= 1,
        |r| r.r8 ^= 1,
        |r| r.rax ^= 1,
        |r| r.rcx ^= 1,
        |r| r.rdx ^= 1,
        |r| r.rsi ^= 1,
        |r| r.rdi ^= 1,
        |r| r.orig_rax ^= 1,
        |r| r.rip ^= 1,
        |r| r.cs ^= 1,
        |r| r.eflags ^= 1,
        |r| r.rsp ^= 1,
        |r| r.ss ^= 1,
        |r| r.fs_base ^= 1,
        |r| r.gs_base ^= 1,
        |r| r.ds ^= 1,
        |r| r.es ^= 1,
        |r| r.fs ^= 1,
        |r| r.gs ^= 1,
    ]
}

#[test]
fn preparation_owns_exact_full_state_and_preserves_the_original_deadline() {
    let (mut pending, binding) = fixture();
    let original = pending_snapshot(&pending);
    let mut seal = PreparedExecSeal::prepare(binding, &pending).unwrap();
    assert_eq!(pending_snapshot(&pending), original);
    assert_eq!(seal.binding, binding);
    assert_eq!(seal.original, original.token);
    assert_eq!(seal.next_pc, PC + 2);
    assert_eq!(seal.until, original.until);
    assert_eq!(seal.before, original.before);
    assert!(!seal.bound);
    assert!(seal.new_xstate.is_empty());
    assert_eq!(seal.before.xstate.capacity(), MAX_XSTATE);
    assert_eq!(seal.new_xstate.capacity(), MAX_XSTATE);
    assert_ne!(seal.before.xstate.as_ptr(), pending.before.xstate.as_ptr());
    assert_eq!(
        seal.retained_bytes().unwrap(),
        size_of::<PreparedExecSeal>() + 2 * MAX_XSTATE
    );
    pending.before.registers.r15 ^= 1;
    pending.before.xstate[0] ^= 1;
    pending.before.signal_mask ^= 1;
    pending.until += Duration::from_secs(1);
    assert_eq!(seal.before, original.before);
    assert_eq!(seal.until, original.until);
    let mut restored = original.before.clone();
    restored.token.sequence += 4;
    seal.bind_before(&restored).unwrap();
    assert_eq!(seal.before, restored);
    assert_eq!(seal.until, original.until);
    assert_eq!(seal.original, original.token);

    // This pure object records an expired deadline without renewing it. Only
    // the separate native seal/release path can validate time or grant effect.
    let (mut expired, binding) = fixture();
    expired.until = Instant::now() - Duration::from_secs(1);
    let prepared = PreparedExecSeal::prepare(binding, &expired).unwrap();
    assert_eq!(prepared.until, expired.until);
    assert!(!prepared.bound);
}

#[test]
fn preparation_rejects_inconsistent_original_identity_abi_and_full_state() {
    for row in 0..25 {
        let (mut pending, mut binding) = fixture();
        let (foreign, _) = fixture();
        match row {
            0 => binding.session += 1,
            1 => binding.space = foreign.token.task.address_space,
            2 => binding.generation += 1,
            3 => binding.invocation = ExecutionId::from_owner(SESSION + 1, 9).unwrap(),
            4 => binding.invocation = ExecutionId::from_owner(SESSION, 10).unwrap(),
            5 => pending.token.invocation = 0,
            6 => pending.token.epoch += 1,
            7 => pending.stop.token.sequence += 1,
            8 => pending.stop.identity.generation += 1,
            9 => pending.before.token.sequence += 1,
            10 => pending.before.task.generation += 1,
            11 => pending.before.logical_pc += 1,
            12 => pending.before.phase = StopPhase::Interrupted,
            13 => pending.before.signal = Some(DynamicSignalInfo { raw: [0; 128] }),
            14 => pending.before.xstate.truncate(511),
            15 => pending.before.xstate.resize(MAX_XSTATE, 0),
            16 => {
                pending.before.registers.orig_rax = libc::SYS_execve as u64;
                pending.input = selected(pending.before.registers);
            }
            17 => {
                pending.before.registers.rax = libc::SYS_getpid as u64;
                pending.input = selected(pending.before.registers);
            }
            18 => {
                pending.before.registers.rax |= 0x4000_0000;
                pending.input = selected(pending.before.registers);
            }
            19 => {
                let mut aliases = SyscallAliases::new();
                aliases.declare(PC, SyscallAbi::LinuxI386Int80).unwrap();
                pending.input = SelectedInput::new(
                    decode(PC, &[0xcd, 0x80], &aliases).unwrap(),
                    pending.before.registers,
                )
                .unwrap();
            }
            20 => {
                pending.input = SelectedInput::new(
                    decode(PC, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap(),
                    pending.before.registers,
                )
                .unwrap()
            }
            21 => pending.token.stop.session += 1,
            22 => pending.token.stop.tid += 1,
            23 => pending.before.token.task = Some(foreign.token.task.task),
            24 => pending.before.task.process = foreign.token.task.process,
            _ => unreachable!(),
        }
        let before = pending_snapshot(&pending);
        refused(
            PreparedExecSeal::prepare(binding, &pending),
            "exec seal preparation has a different original invocation",
        );
        assert_eq!(pending_snapshot(&pending), before, "row {row}");
    }
    for mutate in register_mutations() {
        let (mut pending, binding) = fixture();
        mutate(&mut pending.before.registers);
        let before = pending_snapshot(&pending);
        refused(
            PreparedExecSeal::prepare(binding, &pending),
            "exec seal preparation has a different original invocation",
        );
        assert_eq!(pending_snapshot(&pending), before);
    }
}

#[test]
fn last_old_checkpoint_binding_is_full_state_atomic_and_single_use() {
    let (pending, binding) = fixture();
    let (foreign, _) = fixture();
    let mut seal = PreparedExecSeal::prepare(binding, &pending).unwrap();
    let pristine = seal_snapshot(&seal);
    for row in 0..19 {
        let mut before = pending.before.clone();
        match row {
            0 => before.logical_pc += 1,
            1 => before.xstate[831] ^= 1,
            2 => before.xstate.truncate(831),
            3 => before.xstate.push(0),
            4 => before.signal_mask ^= 1,
            5 => before.task.task = foreign.token.task.task,
            6 => before.task.process = foreign.token.task.process,
            7 => before.task.address_space = foreign.token.task.address_space,
            8 => before.task.generation += 1,
            9 => before.token.session += 1,
            10 => before.token.tid += 1,
            11 => before.token.task = None,
            12 => before.token.sequence -= 1,
            13 => before.phase = StopPhase::OwnedGuard,
            14 => before.signal = Some(DynamicSignalInfo { raw: [0; 128] }),
            15 => before.xstate.clear(),
            16 => before.xstate.resize(MAX_XSTATE, 0),
            17 => before.registers.eflags |= 0x100,
            18 => before.registers.eflags |= 0x10000,
            _ => unreachable!(),
        }
        refused(
            seal.bind_before(&before),
            "exec seal lacks its exact last old-mm checkpoint",
        );
        assert_eq!(seal_snapshot(&seal), pristine, "row {row}");
    }
    for mutate in register_mutations() {
        let mut before = pending.before.clone();
        mutate(&mut before.registers);
        refused(
            seal.bind_before(&before),
            "exec seal lacks its exact last old-mm checkpoint",
        );
        assert_eq!(seal_snapshot(&seal), pristine);
    }
    let mut before = pending.before.clone();
    before.token.sequence += 3;
    seal.bind_before(&before).unwrap();
    let accepted = seal_snapshot(&seal);
    assert!(accepted.bound);
    assert_eq!(accepted.before, before);
    assert_eq!(accepted.until, pristine.until);
    assert_eq!(accepted.binding, pristine.binding);
    assert_eq!(accepted.original, pristine.original);
    assert_eq!(accepted.next_pc, pristine.next_pc);
    assert_eq!(accepted.capacities, pristine.capacities);
    assert_eq!(accepted.new_xstate, pristine.new_xstate);
    refused(
        seal.bind_before(&before),
        "exec seal lacks its exact last old-mm checkpoint",
    );
    assert_eq!(seal_snapshot(&seal), accepted);
}
