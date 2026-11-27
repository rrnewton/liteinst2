//! Backend-neutral generated-PC recovery core (P1b I1-A).
//!
//! This module is the single place where an interrupted
//! generated PC is turned back into exact source state: next
//! source PC, registers, flags, stack effects, and pending
//! versus committed branch/instruction credit. It is pure: it
//! reads a [`Translation`]'s PC map and block layout plus a
//! plain [`RecoveryInput`] record, and returns a
//! [`RecoveredStop`]. It touches no signal state, no cache data
//! page, and no dispatcher globals, so a future remote backend
//! can consume the same authored recovery rules by filling the
//! record from its own interrupted-state source instead of
//! forking this logic.
//!
//! The in-process executor adapts its `JitData` snapshot into
//! [`RecoveryInput`] and maps [`RecoveredStop`] back into its
//! custody-carrying `Fault` type; that mapping is the only
//! backend-specific step left in `exec`.

use crate::pcmap::{CallStage, CommonStage, ExitStage, Recovery, StubStage};
use crate::state::{GuestState, exit_kind};
use crate::translate::Translation;
use crate::types::CountProfile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultKind {
    /// Synchronous guest fault at the recovered source PC.
    GuestFault,
    /// A signal with asynchronous provenance stopped the run:
    /// either a nonpositive `si_code` (the existing asynchronous
    /// code class), or a positive `si_code` on a number outside
    /// the fault set (see [`is_fault_signal`]), such as SIGALRM
    /// from `setitimer`, SIGCHLD, or an `F_SETSIG` signal. State
    /// is recovered but no guest delivery is claimed.
    AsyncSignal,
    /// The executor's own machinery faulted (common exit, data
    /// page, unmapped generated PC): not a guest-visible fault.
    ExecutorError,
}

/// The fault set: the only signal numbers whose positive `si_code`
/// is taken as a synchronous fault or trap. A positive code on any
/// other number has asynchronous provenance and stops as
/// [`FaultKind::AsyncSignal`]. This is a number-and-code policy, not
/// a proof of synchrony: an asynchronous positive code on a
/// fault-set number (for example SIGBUS `BUS_MCEERR_AO`) keeps the
/// fault path.
pub fn is_fault_signal(sig: i32) -> bool {
    matches!(
        sig,
        libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGTRAP | libc::SIGSYS
    )
}

/// Interrupted-PC provenance supplied by the backend's fault
/// capture path.
#[derive(Clone, Copy, Debug)]
pub struct FaultInput {
    pub gen_pc: u64,
    pub addr: u64,
    pub signum: i32,
    pub si_code: i32,
    /// Page-fault error code (`REG_ERR`); bit 0x10 = fetch.
    pub err: u64,
}

/// Backend-neutral interrupted-state snapshot: everything the
/// recovery rules may read, with no cache-page or process
/// layout attached. A backend fills this from whatever state
/// capture it has (the in-process `JitData` page today; a
/// remote tracer's register/counter reads in a later stage).
#[derive(Clone, Copy, Debug)]
pub struct RecoveryInput {
    pub provenance: FaultInput,
    /// Raw interrupted registers at the generated PC.
    pub interrupted: GuestState,
    /// The common-exit's staged guest-state saves, used only
    /// when the stop lands mid-epilogue (`CommonExit` stages).
    pub saved: GuestState,
    pub spill_rax: u64,
    pub spill_flags: u64,
    /// Counter totals as credited so far, including any
    /// block-head pre-credit recovery must resolve.
    pub branches: u64,
    pub instructions: u64,
    /// Exit-stub fields needed only by the common-exit arm.
    pub exit_kind: u64,
    pub exit_src: u64,
}

/// Exact recovered stop: source state and resolved counters.
/// Custody bookkeeping (pending-signal ownership on return) is
/// a dispatcher concern and deliberately absent here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredStop {
    pub kind: FaultKind,
    pub src_pc: u64,
    pub addr: u64,
    pub signum: i32,
    pub state: GuestState,
    pub branches: u64,
    pub instructions: u64,
}

fn flags_from_spill(saved: u64, current: u64) -> u64 {
    const STATUS: u64 = 0x8d5; // OF|SF|ZF|AF|PF|CF
    (current & !STATUS) | ((saved >> 8) & 0xd5) | ((saved & 1) << 11)
}

/// `(retired-before, total)` instruction counts for the block
/// containing `src_pc`, or `None` outside every block.
pub(crate) fn block_retired_before(t: &Translation, src_pc: u64) -> Option<(u64, u64)> {
    for block in t.blocks.values() {
        let pcs = block.insn_pcs();
        if let Some(pos) = pcs.iter().position(|&p| p == src_pc) {
            return Some((pos as u64, block.instruction_total()));
        }
        if block.term_pc() == Some(src_pc) {
            return Some((pcs.len() as u64, block.instruction_total()));
        }
    }
    None
}

/// Retired-instruction total when execution stopped *before*
/// the instruction at `src_pc`, correcting the block-head
/// pre-credit under the instruction-counting profile.
///
/// `None` when `counted` is smaller than the pre-credit it must
/// remove. Every stop inside a block carries that block's head
/// credit, so a smaller count means the executor's own count is
/// inconsistent; the caller reports the stop as
/// [`FaultKind::ExecutorError`] with the raw count (see
/// [`kind_and_retired`]), never a wrapped total.
pub fn instructions_retired_at(
    t: &Translation,
    profile: CountProfile,
    counted: u64,
    src_pc: u64,
) -> Option<u64> {
    if profile != CountProfile::BranchesAndInstructions {
        return Some(counted);
    }
    match block_retired_before(t, src_pc) {
        Some((pos, total)) => total
            .checked_sub(pos)
            .and_then(|owed| counted.checked_sub(owed)),
        None => Some(counted),
    }
}

/// The kind and retired-instruction total for a stop reported as
/// `kind` at `src_pc`: `kind` with the corrected total, or
/// [`FaultKind::ExecutorError`] with the raw `counted` when the
/// block-head credit is missing ([`instructions_retired_at`]).
pub fn kind_and_retired(
    t: &Translation,
    profile: CountProfile,
    kind: FaultKind,
    counted: u64,
    src_pc: u64,
) -> (FaultKind, u64) {
    match instructions_retired_at(t, profile, counted, src_pc) {
        Some(retired) => (kind, retired),
        None => (FaultKind::ExecutorError, counted),
    }
}

/// Exact interrupted-state reconstruction for a stop at
/// generated PC `input.provenance.gen_pc` (an entry start).
/// This is the single place where pending branch/instruction
/// credit is resolved; every backend goes through it.
pub fn recover(t: &Translation, profile: CountProfile, input: RecoveryInput) -> RecoveredStop {
    let (gen_pc, addr, signum, si_code, fault_err) = (
        input.provenance.gen_pc,
        input.provenance.addr,
        input.provenance.signum,
        input.provenance.si_code,
        input.provenance.err,
    );
    let raw = input.interrupted;
    let mut state = raw;
    let mut branches = input.branches;
    let mut instructions = input.instructions;
    let async_kind = si_code <= 0 || !is_fault_signal(signum);
    let Some(entry) = t.pcmap.lookup(gen_pc) else {
        state.rip = 0;
        return RecoveredStop {
            kind: FaultKind::ExecutorError,
            src_pc: 0,
            addr,
            signum,
            state,
            branches,
            instructions,
        };
    };
    // A missing block-head credit makes the stop an executor error
    // with the raw count (see `instructions_retired_at`).
    let mut credit_missing = false;
    let mut retired_at = |counted: u64, src: u64| {
        instructions_retired_at(t, profile, counted, src).unwrap_or_else(|| {
            credit_missing = true;
            counted
        })
    };
    let kind = if async_kind {
        FaultKind::AsyncSignal
    } else if matches!(
        entry.recovery,
        Recovery::BranchStub { .. }
            | Recovery::InsnCountStub { .. }
            | Recovery::PollStub { .. }
            | Recovery::ExitStub { .. }
            | Recovery::PollExitStub { .. }
            | Recovery::CommonExit { .. }
    ) || matches!(
        entry.recovery,
        Recovery::Call {
            stage: CallStage::Pristine | CallStage::CommittedSpilled,
            ..
        }
    ) {
        // Private spill/counter/exit/state accesses are executor
        // machinery, whatever source successor they recover to.
        FaultKind::ExecutorError
    } else {
        FaultKind::GuestFault
    };
    let src_pc = match entry.recovery {
        Recovery::Copied => {
            instructions = retired_at(instructions, entry.src_pc);
            entry.src_pc
        }
        Recovery::BranchStub {
            successor, stage, ..
        } => {
            match stage {
                StubStage::BeforeCreditPristine => branches += 1,
                StubStage::BeforeCreditSpilled => {
                    state.rax = input.spill_rax;
                    branches += 1;
                }
                StubStage::AfterCreditSpilled => {
                    state.rax = input.spill_rax;
                    state.rflags = flags_from_spill(input.spill_flags, raw.rflags);
                }
                StubStage::AfterCreditFlagsRestored => {
                    state.rax = input.spill_rax;
                }
                StubStage::Committed => {}
            }
            successor
        }
        Recovery::InsnCountStub { block, stage } => {
            let total = t
                .blocks
                .get(&block)
                .map(|b| b.instruction_total())
                .unwrap_or(0);
            match stage {
                StubStage::BeforeCreditPristine => {}
                StubStage::BeforeCreditSpilled => state.rax = input.spill_rax,
                StubStage::AfterCreditSpilled => {
                    state.rax = input.spill_rax;
                    state.rflags = flags_from_spill(input.spill_flags, raw.rflags);
                    instructions -= total;
                }
                StubStage::AfterCreditFlagsRestored => {
                    state.rax = input.spill_rax;
                    instructions -= total;
                }
                StubStage::Committed => instructions -= total,
            }
            block
        }
        Recovery::PollExitStub { stage } => {
            if stage == ExitStage::Spilled {
                state.rax = input.spill_rax;
            }
            // No retirement adjustment: the poll stub precedes
            // the block's instruction precredit by construction.
            entry.src_pc
        }
        Recovery::PollStub { block, stage } => {
            match stage {
                StubStage::BeforeCreditPristine => {}
                StubStage::BeforeCreditSpilled => state.rax = input.spill_rax,
                StubStage::AfterCreditSpilled => {
                    state.rax = input.spill_rax;
                    state.rflags = flags_from_spill(input.spill_flags, raw.rflags);
                }
                StubStage::AfterCreditFlagsRestored => {
                    state.rax = input.spill_rax;
                }
                StubStage::Committed => {}
            }
            block
        }
        Recovery::Call {
            call_pc,
            target,
            stage,
        } => match stage {
            CallStage::Pristine => {
                instructions = retired_at(instructions, call_pc);
                call_pc
            }
            CallStage::RaxSpilled => {
                state.rax = input.spill_rax;
                instructions = retired_at(instructions, call_pc);
                call_pc
            }
            CallStage::RspDecremented => {
                state.rax = input.spill_rax;
                state.rsp = state.rsp.wrapping_add(8);
                instructions = retired_at(instructions, call_pc);
                call_pc
            }
            CallStage::CommittedSpilled => {
                state.rax = input.spill_rax;
                target
            }
            CallStage::Committed => target,
        },
        Recovery::ExitStub { stage } => {
            if stage == ExitStage::Spilled {
                state.rax = input.spill_rax;
            }
            instructions = retired_at(instructions, entry.src_pc);
            entry.src_pc
        }
        Recovery::CommonExit { stage } => {
            // Kind already decided by provenance above: a positive
            // synchronous code here is machinery; an asynchronous
            // signal stays AsyncSignal at any location.
            match stage {
                CommonStage::BeforeRspSave => {}
                CommonStage::RspSaved => state.rsp = input.saved.rsp,
                CommonStage::FlagsSaved => {
                    state.rsp = input.saved.rsp;
                    state.rflags = input.saved.rflags;
                }
                CommonStage::AllSaved => state = input.saved,
            }
            if input.exit_kind != exit_kind::POLL {
                instructions = retired_at(instructions, input.exit_src);
            }
            input.exit_src
        }
        Recovery::Fallthrough { next } => next,
    };
    let kind = if credit_missing {
        FaultKind::ExecutorError
    } else {
        kind
    };
    state.rip = src_pc;
    // Preserve siginfo address semantics by access provenance,
    // never by numerical equality: SIGFPE/SIGILL name the
    // faulting instruction, and a page-fault error code with the
    // instruction-fetch bit (0x10) names the fetch PC. Those
    // translate to source addresses; a guest data-operand
    // address — even one numerically equal to a generated PC —
    // never does.
    let addr = if signum == libc::SIGFPE || signum == libc::SIGILL || fault_err & 0x10 != 0 {
        t.pcmap.lookup(addr).map_or(src_pc, |e| e.recover(addr))
    } else {
        addr
    };
    RecoveredStop {
        kind,
        src_pc,
        addr,
        signum,
        state,
        branches,
        instructions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Generation, RegionFacts};

    #[test]
    fn core_recovers_from_plain_snapshot_without_jit_data() {
        // The core consumes only the plain record: no cache
        // data page, signal state, or dispatcher globals.
        let fix = crate::fixtures::by_name("sum_loop");
        let region = RegionFacts {
            base: 0x10_0000,
            bytes: fix.bytes,
            generation: Generation(1),
            immutable_private: true,
        };
        let t = crate::translate::translate(
            &region,
            0x10_0000,
            CountProfile::BranchesAndInstructions,
            0x80_0000,
            0x81_0000,
        )
        .unwrap();
        let interrupted = GuestState {
            rip: 0x1234,
            ..GuestState::default()
        };
        let stop = recover(
            &t,
            CountProfile::BranchesAndInstructions,
            RecoveryInput {
                provenance: FaultInput {
                    gen_pc: 0xdead_0000,
                    addr: 0x44,
                    signum: libc::SIGSEGV,
                    si_code: 1,
                    err: 0,
                },
                interrupted,
                saved: GuestState::default(),
                spill_rax: 0,
                spill_flags: 0,
                branches: 7,
                instructions: 9,
                exit_kind: 0,
                exit_src: 0x10_0000,
            },
        );
        assert_eq!(stop.kind, FaultKind::ExecutorError);
        assert_eq!(stop.src_pc, 0);
        assert_eq!(stop.state.rip, 0);
        assert_eq!(stop.branches, 7);
        assert_eq!(stop.instructions, 9);
        assert_eq!(stop.addr, 0x44);
    }

    /// H3k: a positive code on a number outside the fault set
    /// recovers as `AsyncSignal` at every mapped PC class, as the
    /// existing asynchronous-code class does; fault-set positive codes
    /// keep `GuestFault` at copied code and `ExecutorError` in the
    /// executor's machinery. An unmapped generated PC is
    /// `ExecutorError` for every code. Rows in a fixed order; each
    /// assertion names its row.
    #[test]
    fn recover_kernel_async_at_every_pc_class() {
        use crate::pcmap::Recovery as R;
        let fix = crate::fixtures::by_name("sum_loop");
        let region = RegionFacts {
            base: 0x10_0000,
            bytes: fix.bytes,
            generation: Generation(1),
            immutable_private: true,
        };
        let profile = CountProfile::BranchesAndInstructions;
        let t =
            crate::translate::translate(&region, 0x10_0000, profile, 0x80_0000, 0x81_0000).unwrap();
        let first = |want: fn(&R) -> bool| {
            t.pcmap
                .entries()
                .iter()
                .find(|e| want(&e.recovery))
                .map(|e| e.gen_start)
                .expect("sum_loop has every PC class")
        };
        let classes = [
            ("Copied", first(|r| matches!(r, R::Copied))),
            ("BranchStub", first(|r| matches!(r, R::BranchStub { .. }))),
            ("PollStub", first(|r| matches!(r, R::PollStub { .. }))),
            ("CommonExit", first(|r| matches!(r, R::CommonExit { .. }))),
            ("Unmapped", 0xdead_0000),
        ];
        let kind = |gen_pc: u64, signum: i32, si_code: i32| {
            recover(
                &t,
                profile,
                RecoveryInput {
                    provenance: FaultInput {
                        gen_pc,
                        addr: 0,
                        signum,
                        si_code,
                        err: 0,
                    },
                    interrupted: GuestState::default(),
                    saved: GuestState::default(),
                    spill_rax: 0,
                    spill_flags: 0,
                    branches: 0,
                    // A real stop carries at least its block's head
                    // credit; below that, the count correction would
                    // underflow (a debug-build panic). The kind does
                    // not depend on the counts.
                    instructions: 1_000,
                    exit_kind: 0,
                    exit_src: 0x10_0000,
                },
            )
            .kind
        };
        type Row<'a> = (&'a [(i32, i32)], [FaultKind; 5]);
        let rows: [Row; 3] = [
            (
                &[(14, 128), (10, 1), (17, 1)],
                [
                    FaultKind::AsyncSignal,
                    FaultKind::AsyncSignal,
                    FaultKind::AsyncSignal,
                    FaultKind::AsyncSignal,
                    FaultKind::ExecutorError,
                ],
            ),
            (
                &[(11, -6), (11, 0)],
                [
                    FaultKind::AsyncSignal,
                    FaultKind::AsyncSignal,
                    FaultKind::AsyncSignal,
                    FaultKind::AsyncSignal,
                    FaultKind::ExecutorError,
                ],
            ),
            (
                &[(11, 1), (7, 2), (7, 5)],
                [
                    FaultKind::GuestFault,
                    FaultKind::ExecutorError,
                    FaultKind::ExecutorError,
                    FaultKind::ExecutorError,
                    FaultKind::ExecutorError,
                ],
            ),
        ];
        for (codes, want) in rows {
            for &(sig, code) in codes {
                for (i, (class, gen_pc)) in classes.iter().enumerate() {
                    assert_eq!(
                        kind(*gen_pc, sig, code),
                        want[i],
                        "recover {class} sig {sig} code {code}"
                    );
                }
            }
        }
    }

    /// A count without its block's head credit is refused, never
    /// wrapped: `instructions_retired_at` gives `None` one below the
    /// credit and the exact remainder at it, and `recover` at a
    /// copied PC reports `ExecutorError` with the raw count, where an
    /// unchecked subtraction would wrap (release) or panic (debug).
    #[test]
    fn missing_block_head_credit_refuses_as_executor_error() {
        use crate::pcmap::Recovery as R;
        let fix = crate::fixtures::by_name("sum_loop");
        let region = RegionFacts {
            base: 0x10_0000,
            bytes: fix.bytes,
            generation: Generation(1),
            immutable_private: true,
        };
        let profile = CountProfile::BranchesAndInstructions;
        let t =
            crate::translate::translate(&region, 0x10_0000, profile, 0x80_0000, 0x81_0000).unwrap();
        // The first copied instruction that owes a pre-credit.
        let (gen_pc, src_pc, owed) = t
            .pcmap
            .entries()
            .iter()
            .filter(|e| matches!(e.recovery, R::Copied))
            .find_map(|e| {
                let (pos, total) = block_retired_before(&t, e.src_pc)?;
                (total > pos).then_some((e.gen_start, e.src_pc, total - pos))
            })
            .expect("sum_loop has a copied instruction inside a block");
        assert_eq!(
            instructions_retired_at(&t, profile, owed - 1, src_pc),
            None,
            "retired-before total refuses a count below the block credit"
        );
        assert_eq!(
            instructions_retired_at(&t, profile, owed, src_pc),
            Some(0),
            "retired-before total at exactly the block credit"
        );
        let stop = |instructions: u64| {
            recover(
                &t,
                profile,
                RecoveryInput {
                    provenance: FaultInput {
                        gen_pc,
                        addr: 0,
                        signum: libc::SIGSEGV,
                        si_code: 1,
                        err: 0,
                    },
                    interrupted: GuestState::default(),
                    saved: GuestState::default(),
                    spill_rax: 0,
                    spill_flags: 0,
                    branches: 0,
                    instructions,
                    exit_kind: 0,
                    exit_src: 0x10_0000,
                },
            )
        };
        let missing = stop(owed - 1);
        assert_eq!(
            (missing.kind, missing.instructions),
            (FaultKind::ExecutorError, owed - 1),
            "recover refuses a missing block credit as ExecutorError with the raw count"
        );
        let credited = stop(owed + 5);
        assert_eq!(
            (credited.kind, credited.instructions),
            (FaultKind::GuestFault, 5),
            "recover with the block credit present"
        );
    }
}
