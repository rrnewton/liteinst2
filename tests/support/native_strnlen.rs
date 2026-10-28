//! Actual original strnlen read-domain and complete finite CFG coverage checks.
//! No timing/cache claim; synthetic controls never supply native completion.
use super::{CHILD_BUDGET, Instant, MAX_STEPS, OriginalObservation, OriginalStep, PairResult};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use std::collections::{BTreeMap, BTreeSet};
#[path = "../../tools/rapid-profiler/strnlen-work/cases.rs"]
pub mod cases;
pub use super::selected::SEEDS;
pub use cases::{CASES, Case};
pub const LABEL: &str = cases::LABEL;
pub const HEADER: &str = "seed,case,bound,status,children,comparisons,original_visits,original_steps,candidate_steps,value,input_reads,input_bytes,observed_heads,observed_edges,declared_heads,declared_edges,declared_returns,ret_offset\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arguments {
    pub elf_va: u64,
    pub length: usize,
}
impl Arguments {
    pub fn parse(elf_va: &str, length: &str) -> Self {
        // Preserve the old selected parser, then add the exact new profile bound.
        let parsed = super::selected::Arguments::parse(elf_va, length);
        assert!((5..=80).contains(&parsed.length), "whole-function extent");
        Self {
            elf_va: parsed.elf_va,
            length: parsed.length,
        }
    }
}
#[derive(Clone, Copy)]
pub struct Deadline(Instant);
impl Deadline {
    pub fn start() -> Self {
        Self(Instant::now() + CHILD_BUDGET)
    }
    pub fn check(self) {
        self.check_at(Instant::now());
    }
    fn check_at(self, now: Instant) {
        assert!(now < self.0, "strnlen original absolute deadline");
    }
    pub(super) fn end(self) -> Instant {
        self.0
    }
    pub(super) fn request(self, reference: Option<(Instant, u64)>, native_noop: Option<u64>) {
        self.request_at(reference, native_noop, Instant::now());
    }
    fn request_at(self, reference: Option<(Instant, u64)>, native_noop: Option<u64>, now: Instant) {
        assert!(
            reference.is_none() && native_noop.is_none(),
            "strnlen Legacy gate only"
        );
        self.check_at(now);
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Coverage {
    heads: BTreeSet<u64>,
    edges: BTreeSet<(u64, u64)>,
    returns: BTreeSet<u64>,
}
impl Coverage {
    fn extend(&mut self, other: &Self) {
        self.heads.extend(&other.heads);
        self.edges.extend(&other.edges);
        self.returns.extend(&other.returns);
    }
    fn subset(&self, declared: &Self) -> bool {
        self.heads.is_subset(&declared.heads)
            && self.edges.is_subset(&declared.edges)
            && self.returns.is_subset(&declared.returns)
    }
}
struct Graph {
    instructions: BTreeMap<u64, Instruction>,
    declared: Coverage,
}
fn gpr(r: Register) -> bool {
    matches!(
        r.full_register(),
        Register::RAX
            | Register::RCX
            | Register::RDX
            | Register::RSI
            | Register::RDI
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
    ) && r.is_gpr()
}
fn address_register(r: Register) -> bool {
    r == Register::None || (r.is_gpr64() && gpr(r))
}
fn scalar_instruction(i: &Instruction) {
    assert!(matches!(
        i.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Lea
            | Mnemonic::Xor
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Test
            | Mnemonic::Cmp
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Nop
    ));
    for n in 0..i.op_count() {
        match i.op_kind(n) {
            OpKind::Register => assert!(gpr(i.op_register(n))),
            OpKind::Memory => {
                assert!(
                    n != 0
                        || matches!(i.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Nop)
                );
                assert!(i.memory_base() != Register::None && address_register(i.memory_base()));
                assert!(address_register(i.memory_index()));
            }
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {}
            _ => panic!("unhandled strnlen operand"),
        }
    }
}
impl Graph {
    fn decode(code: &[u8]) -> Self {
        assert!((5..=80).contains(&code.len()));
        let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
        let mut instructions = BTreeMap::new();
        while decoder.can_decode() {
            let i = decoder.decode();
            assert!(!i.is_invalid());
            assert!(!i.has_lock_prefix() && !i.has_rep_prefix() && !i.has_repne_prefix());
            assert_eq!(i.segment_prefix(), Register::None);
            assert!(!i.is_privileged());
            assert!(i.next_ip() <= code.len() as u64);
            assert!(instructions.insert(i.ip(), i).is_none());
        }
        assert_eq!(decoder.position(), code.len());
        let mut next = BTreeMap::new();
        for (&pc, i) in &instructions {
            let raw = &code[pc as usize..i.next_ip() as usize];
            let successors = match i.flow_control() {
                FlowControl::Next => {
                    scalar_instruction(i);
                    BTreeSet::from([i.next_ip()])
                }
                FlowControl::Return => {
                    assert_eq!(raw, [0xc3]);
                    BTreeSet::new()
                }
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    assert!(matches!(
                        raw,
                        [0x70..=0x7f, _]
                            | [0x0f, 0x80..=0x8f, _, _, _, _]
                            | [0xeb, _]
                            | [0xe9, _, _, _, _]
                    ));
                    assert_eq!(i.op_count(), 1);
                    assert_eq!(i.op_kind(0), OpKind::NearBranch64);
                    assert_ne!(i.near_branch_target(), pc);
                    let mut targets = BTreeSet::from([i.near_branch_target()]);
                    if i.flow_control() == FlowControl::ConditionalBranch {
                        targets.insert(i.next_ip());
                    }
                    targets
                }
                _ => panic!("strnlen escaped admitted scalar CFG"),
            };
            assert!(successors.iter().all(|p| instructions.contains_key(p)));
            next.insert(pc, successors);
        }
        let mut declared = Coverage::default();
        let mut pending = vec![0];
        while let Some(pc) = pending.pop() {
            if declared.heads.insert(pc) {
                let i = &instructions[&pc];
                if i.flow_control() == FlowControl::Return {
                    declared.returns.insert(pc);
                }
                for &to in &next[&pc] {
                    declared.edges.insert((pc, to));
                    pending.push(to);
                }
            }
        }
        assert!((1..=4).contains(&declared.returns.len()));
        assert!(
            !declared.returns.contains(&0),
            "distinct whole-function entry and RET roles"
        );
        for (&pc, i) in &instructions {
            assert!(
                declared.heads.contains(&pc) || i.mnemonic() == Mnemonic::Nop,
                "only already unreachable NOPs are padding"
            );
        }
        let mut reaches_ret = declared.returns.clone();
        for _ in 0..instructions.len() {
            for &(from, to) in &declared.edges {
                if reaches_ret.contains(&to) {
                    reaches_ret.insert(from);
                }
            }
        }
        assert_eq!(
            reaches_ret, declared.heads,
            "all reachable heads can reach RET"
        );
        Self {
            instructions,
            declared,
        }
    }
}
fn bytes_at(bytes: &[u8], base: u64, address: u64, width: usize) -> &[u8] {
    let offset = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    &bytes[offset..offset.checked_add(width).unwrap()]
}
fn register(r: Register, state: &libc::user_regs_struct) -> u64 {
    match r {
        Register::None => 0,
        Register::RAX => state.rax,
        Register::RCX => state.rcx,
        Register::RDX => state.rdx,
        Register::RSI => state.rsi,
        Register::RDI => state.rdi,
        Register::R8 => state.r8,
        Register::R9 => state.r9,
        Register::R10 => state.r10,
        Register::R11 => state.r11,
        _ => panic!("nonadmitted address register"),
    }
}
fn read_domain(input: u64, bound: usize, address: u64, width: usize) {
    assert!(matches!(width, 1 | 2 | 4 | 8));
    let end = input.checked_add(bound as u64).unwrap();
    assert!(
        input <= address && address.checked_add(width as u64).unwrap() <= end,
        "complete actual operand must be within the declared input"
    );
}
fn input_operand(
    i: &Instruction,
    before: &libc::user_regs_struct,
    input: u64,
    bound: usize,
) -> Option<(u64, usize)> {
    assert_eq!(i.flow_control(), FlowControl::Next);
    scalar_instruction(i);
    let explicit = (0..i.op_count())
        .filter(|&n| i.op_kind(n) == OpKind::Memory)
        .count();
    assert!(explicit <= 1);
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(i);
    if explicit == 0 || matches!(i.mnemonic(), Mnemonic::Lea | Mnemonic::Nop) {
        assert!(
            info.used_memory().is_empty(),
            "no hidden scalar memory access"
        );
        return None;
    }
    assert_eq!(info.used_memory().len(), 1);
    assert_eq!(info.used_memory()[0].access(), OpAccess::Read);
    let width = i.memory_size().size();
    // 64-bit address arithmetic, including signed displacements, is modular;
    // the final full-width interval must still be nonwrapping and in bounds.
    let address = register(i.memory_base(), before)
        .wrapping_add(
            register(i.memory_index(), before).wrapping_mul(u64::from(i.memory_index_scale())),
        )
        .wrapping_add(i.memory_displacement64());
    read_domain(input, bound, address, width);
    Some((address, width))
}

pub struct Trace {
    entry: u64,
    code: Vec<u8>,
    declared: Coverage,
    observed: Coverage,
    pub visits: usize,
    pub input_reads: usize,
    pub input_bytes: usize,
    pub ret_offset: u64,
}
impl Trace {
    pub fn observed_heads(&self) -> usize {
        self.observed.heads.len()
    }
    pub fn observed_edges(&self) -> usize {
        self.observed.edges.len()
    }
    pub fn declared_heads(&self) -> usize {
        self.declared.heads.len()
    }
    pub fn declared_edges(&self) -> usize {
        self.declared.edges.len()
    }
    pub fn declared_returns(&self) -> usize {
        self.declared.returns.len()
    }
}
fn inspect_body(
    case: Case,
    entry: u64,
    continuation: u64,
    input_address: u64,
    code: &[u8],
    body: &[OriginalStep<'_>],
) -> Trace {
    let graph = Graph::decode(code);
    assert!(!body.is_empty() && body.len() <= MAX_STEPS);
    let first = &body[0];
    assert_eq!(first.before.rip, entry);
    assert_eq!(
        (first.before.rdi, first.before.rsi),
        (input_address, case.bound as u64)
    );
    let rsp = first.before.rsp;
    let expected_input = cases::input(case);
    let mut trace = Trace {
        entry,
        code: code.to_vec(),
        declared: graph.declared,
        observed: Coverage::default(),
        visits: body.len(),
        input_reads: 0,
        input_bytes: 0,
        ret_offset: u64::MAX,
    };
    for (index, step) in body.iter().enumerate() {
        let pc = step.before.rip.checked_sub(entry).unwrap();
        assert!(
            trace.declared.heads.contains(&pc),
            "actual reachable original head"
        );
        trace.observed.heads.insert(pc);
        let i = &graph.instructions[&pc];
        assert_eq!(step.before.rsp, rsp, "ordinary leaf stack remains intact");
        assert_eq!(
            bytes_at(step.data, step.data_address, input_address, 64),
            expected_input
        );
        if index != 0 {
            assert_eq!(body[index - 1].after.rip, step.before.rip);
        }
        if i.flow_control() == FlowControl::Return {
            assert_eq!(index + 1, body.len(), "exactly the final real subject RET");
            let word = u64::from_le_bytes(
                bytes_at(step.stack, step.stack_address, rsp, 8)
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(word, continuation);
            assert_eq!(
                (step.after.rip, step.after.rsp, step.after.rax),
                (
                    continuation,
                    rsp.checked_add(8).unwrap(),
                    cases::scalar(case)
                )
            );
            trace.observed.returns.insert(pc);
            trace.ret_offset = pc;
        } else {
            let next = step.after.rip.checked_sub(entry).unwrap();
            assert!(
                trace.declared.edges.contains(&(pc, next)),
                "actual decoded successor"
            );
            trace.observed.edges.insert((pc, next));
            if i.flow_control() == FlowControl::Next {
                if let Some((address, width)) =
                    input_operand(i, &step.before, input_address, case.bound)
                {
                    // Read the complete operand from the actual captured page.
                    let _bytes = bytes_at(step.data, step.data_address, address, width);
                    trace.input_reads = trace.input_reads.checked_add(1).unwrap();
                    trace.input_bytes = trace.input_bytes.checked_add(width).unwrap();
                }
            }
        }
    }
    assert_eq!(trace.observed.returns.len(), 1);
    if case.bound == 0 {
        assert_eq!((trace.input_reads, trace.input_bytes), (0, 0));
    } else {
        assert!(trace.input_reads > 0 && trace.input_bytes >= trace.input_reads);
    }
    assert!(trace.observed.subset(&trace.declared));
    trace
}
/// Called only by the shared pair's inspector AFTER both exit0 reaps/ECHILD.
pub fn inspect(case: Case, extent: usize, observed: OriginalObservation<'_>) -> Trace {
    let code = bytes_at(
        observed.source,
        observed.source_address,
        observed.entry,
        extent,
    );
    let input = cases::input(case);
    assert_eq!(observed.input, &input[..case.bound]);
    let steps: Vec<_> = observed.steps().collect();
    let starts: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(n, s)| (s.before.rip == observed.entry).then_some(n))
        .collect();
    assert_eq!(starts, [8], "unchanged Legacy gate before one real entry");
    let graph = Graph::decode(code);
    let finish = (8..steps.len())
        .find(|&n| {
            steps[n]
                .before
                .rip
                .checked_sub(observed.entry)
                .is_some_and(|pc| graph.declared.returns.contains(&pc))
        })
        .expect("actual subject RET");
    assert_eq!(
        steps.len(),
        finish + 3,
        "unchanged two Legacy steps after subject RET"
    );
    assert_eq!(steps[finish + 1].before.rip, observed.continuation);
    inspect_body(
        case,
        observed.entry,
        observed.continuation,
        observed.input_address,
        code,
        &steps[8..=finish],
    )
}

#[derive(Default)]
pub struct Population {
    next: usize,
    declared: Option<(Vec<u8>, Coverage)>,
    observed: Coverage,
    comparisons: usize,
    input_reads: usize,
    input_bytes: usize,
}
pub struct Totals {
    pub comparisons: usize,
    pub input_reads: usize,
    pub input_bytes: usize,
}
impl Population {
    pub fn record(&mut self, seed: u64, case: Case, pair: &PairResult, trace: &Trace) {
        assert!(self.next < 16);
        assert_eq!(seed, SEEDS[self.next / 8]);
        assert_eq!(case, CASES[self.next % 8]);
        assert_eq!(pair.value, cases::scalar(case));
        assert_eq!(pair.visits, trace.visits);
        assert!(pair.visits > 0);
        assert_eq!(pair.comparisons, pair.visits.checked_add(11).unwrap());
        assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
        assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
        let absolute = |offset: &u64| trace.entry.checked_add(*offset).unwrap();
        assert_eq!(
            pair.returns,
            trace.observed.returns.iter().map(absolute).collect()
        );
        assert_eq!(
            pair.declared_returns,
            trace.declared.returns.iter().map(absolute).collect()
        );
        assert_eq!(trace.observed.returns, BTreeSet::from([trace.ret_offset]));
        assert!(trace.observed.subset(&trace.declared));
        if case.bound == 0 {
            assert_eq!((trace.input_reads, trace.input_bytes), (0, 0));
        } else {
            assert!(trace.input_reads > 0);
        }
        assert!(trace.input_reads <= trace.visits);
        assert!(
            (trace.input_reads..=trace.input_reads.checked_mul(8).unwrap())
                .contains(&trace.input_bytes)
        );
        if let Some((code, declared)) = &self.declared {
            assert_eq!(
                code, &trace.code,
                "same authenticated full function across all pairs"
            );
            assert_eq!(declared, &trace.declared);
        } else {
            self.declared = Some((trace.code.clone(), trace.declared.clone()));
        }
        self.observed.extend(&trace.observed);
        if self.next % 8 == 7 {
            assert_eq!(
                &self.observed,
                &self.declared.as_ref().unwrap().1,
                "complete reachable heads/edges/RETs for this seed"
            );
            self.observed = Coverage::default();
        }
        self.comparisons = self.comparisons.checked_add(pair.comparisons).unwrap();
        self.input_reads = self.input_reads.checked_add(trace.input_reads).unwrap();
        self.input_bytes = self.input_bytes.checked_add(trace.input_bytes).unwrap();
        self.next += 1;
    }
    pub fn finish(self) -> Totals {
        assert_eq!(self.next, 16);
        assert_eq!(self.observed, Coverage::default());
        assert!(self.declared.is_some());
        Totals {
            comparisons: self.comparisons,
            input_reads: self.input_reads,
            input_bytes: self.input_bytes,
        }
    }
}

// The normal caller has two distinct physical return words and no Legacy gate.
// Reuse the exact body validator without changing old inspect/Population rules.
pub(super) fn inspect_normal_body(
    case: Case,
    entry: u64,
    continuation: u64,
    input_address: u64,
    code: &[u8],
    body: &[OriginalStep<'_>],
) -> super::normal_caller::BodyTrace {
    use super::normal_caller::{BodyCoverage, BodyTrace};
    let t = inspect_body(case, entry, continuation, input_address, code, body);
    BodyTrace {
        entry: t.entry,
        code: t.code,
        declared: BodyCoverage {
            heads: t.declared.heads,
            edges: t.declared.edges,
            returns: t.declared.returns,
        },
        observed: BodyCoverage {
            heads: t.observed.heads,
            edges: t.observed.edges,
            returns: t.observed.returns,
        },
        visits: t.visits,
        input_reads: t.input_reads,
        input_bytes: t.input_bytes,
        ret_offset: t.ret_offset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    const CODE: &[u8] = &[
        0x31, 0xc0, 0x48, 0x85, 0xf6, 0x74, 9, 0x80, 0x3f, 0, 0x74, 4, 0x48, 0xff, 0xc0, 0xc3, 0xc3,
    ];
    fn state() -> libc::user_regs_struct {
        unsafe { core::mem::zeroed() }
    }
    fn rejects(f: impl FnOnce()) {
        assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
    }
    #[test]
    fn strnlen_cases_preserve_zero_early_last_and_nonzero_bytes() {
        assert_eq!(CASES.map(|c| c.bound), [0, 1, 1, 2, 17, 64, 64, 64]);
        assert_eq!(CASES.map(cases::scalar), [0, 0, 1, 1, 8, 0, 63, 64]);
        let plain = cases::input(CASES[7]);
        assert!(plain.iter().all(|&v| v != 0));
        assert_eq!(plain.iter().filter(|&&v| v >= 128).count(), 33);
        for case in CASES {
            for (i, &value) in cases::input(case).iter().enumerate() {
                assert_eq!(value, if Some(i) == case.nul { 0 } else { plain[i] });
            }
        }
        for bad in [
            Case {
                expected: 1,
                ..CASES[0]
            },
            Case {
                bound: 65,
                ..CASES[7]
            },
            Case {
                nul: Some(64),
                ..CASES[7]
            },
            Case {
                name: "other",
                ..CASES[0]
            },
        ] {
            rejects(|| {
                cases::scalar(bad);
            });
        }
    }
    #[test]
    fn strnlen_arguments_and_deadline_preserve_exact_bounds() {
        assert_eq!(Arguments::parse("4096", "5").length, 5);
        assert_eq!(Arguments::parse("4096", "80").length, 80);
        for (a, n) in [
            ("4096", "4"),
            ("4096", "81"),
            ("01", "5"),
            ("+1", "5"),
            ("1", "05"),
            ("1", "5\n"),
            ("18446744073709551615", "5"),
        ] {
            rejects(|| {
                Arguments::parse(a, n);
            });
        }
        let start = Instant::now();
        let d = Deadline(start + CHILD_BUDGET);
        assert_eq!(d.end(), start + std::time::Duration::from_secs(15));
        d.request_at(None, None, start);
        d.check_at(d.end() - std::time::Duration::from_nanos(1));
        rejects(|| d.check_at(d.end()));
        rejects(|| d.check_at(d.end() + std::time::Duration::from_nanos(1)));
        rejects(|| d.request_at(Some((d.end(), 1)), None, start));
        rejects(|| d.request_at(None, Some(1), start));
        rejects(|| d.request_at(None, None, d.end()));
    }
    fn instruction(bytes: &[u8]) -> Instruction {
        let mut d = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
        let i = d.decode();
        assert!(!i.is_invalid());
        assert_eq!(d.position(), bytes.len());
        i
    }
    #[test]
    fn strnlen_operand_validator_joins_real_base_index_width_and_domain() {
        let mut regs = state();
        regs.rdi = 0x2000;
        regs.rcx = 2;
        let byte = instruction(&[0x80, 0x3f, 0]); // CMP byte [RDI],0
        assert_eq!(input_operand(&byte, &regs, 0x2000, 1), Some((0x2000, 1)));
        rejects(|| {
            input_operand(&byte, &regs, 0x2000, 0);
        });
        let qword = instruction(&[0x48, 0x8b, 0x44, 0xcf, 0xf8]); // MOV RAX,[RDI+RCX*8-8]
        assert_eq!(input_operand(&qword, &regs, 0x2000, 16), Some((0x2008, 8)));
        rejects(|| {
            input_operand(&qword, &regs, 0x2000, 15);
        });
        regs.rcx = 0;
        rejects(|| {
            input_operand(&qword, &regs, 0x2000, 64);
        });
        regs.rdi = u64::MAX;
        rejects(|| {
            input_operand(&byte, &regs, u64::MAX, 1);
        });
        let lea = instruction(&[0x48, 0x8d, 0x47, 0x7f]);
        assert_eq!(input_operand(&lea, &regs, 0x2000, 0), None);
        let store = instruction(&[0x48, 0x89, 0x07]);
        rejects(|| {
            input_operand(&store, &regs, 0x2000, 8);
        });
        let stack_read = instruction(&[0x48, 0x8b, 0x04, 0x24]);
        rejects(|| {
            input_operand(&stack_read, &regs, 0x2000, 8);
        });
        for (base, bound, address, width) in [
            (0x2000, 8, 0x2000, 0),
            (0x2000, 8, 0x2000, 16),
            (0x2000, 8, 0x1fff, 1),
            (0x2000, 8, 0x2008, 1),
            (u64::MAX, 1, u64::MAX, 1),
        ] {
            rejects(|| read_domain(base, bound, address, width));
        }
    }
    #[test]
    fn strnlen_cfg_refuses_unknown_transfers_and_nonpadding_unreachable_code() {
        let graph = Graph::decode(CODE);
        assert_eq!(
            graph.declared.heads,
            BTreeSet::from([0, 2, 5, 7, 10, 12, 15, 16])
        );
        assert_eq!(graph.declared.returns, BTreeSet::from([15, 16]));
        assert!(graph.declared.edges.contains(&(5, 7)) && graph.declared.edges.contains(&(5, 16)));
        let mut missed_head = CODE.to_vec();
        missed_head[6] = 7;
        rejects(|| {
            Graph::decode(&missed_head);
        }); // branch into INC encoding
        for code in [
            &[0xeb, 0xfe, 0x90, 0x90, 0xc3][..],
            &[0xe8, 0, 0, 0, 0, 0xc3][..],
            &[0xc3, 0x31, 0xc0, 0x90, 0xc3][..],
            &[0x48, 0x8b, 0x04, 0x24, 0xc3][..],
        ] {
            rejects(|| {
                Graph::decode(code);
            });
        }
    }
    // Hand-authored snapshots test the ACTUAL inspector predicate only. They
    // are not inserted into the native pair, Ready or child exit protocol.
    fn body<'a>(case: Case, data: &'a [u8], stack: &'a [u8]) -> Vec<OriginalStep<'a>> {
        let path: &[u64] = match case {
            c if c == CASES[0] => &[0, 2, 5, 16],
            c if c == CASES[1] => &[0, 2, 5, 7, 10, 16],
            c if c == CASES[2] => &[0, 2, 5, 7, 10, 12, 15],
            _ => panic!("control trace only"),
        };
        path.iter()
            .enumerate()
            .map(|(n, &pc)| {
                let mut before = state();
                before.rip = 0x1000 + pc;
                before.rdi = 0x2000;
                before.rsi = case.bound as u64;
                before.rsp = 0x3000;
                let mut after = before;
                after.rip = path.get(n + 1).map_or(0x4000, |next| 0x1000 + next);
                if n + 1 == path.len() {
                    after.rsp += 8;
                    after.rax = case.expected;
                }
                OriginalStep {
                    before,
                    after,
                    data_address: 0x2000,
                    data,
                    stack_address: 0x3000,
                    stack,
                }
            })
            .collect()
    }
    #[test]
    fn strnlen_trace_refuses_wrong_arguments_successor_return_and_input() {
        let stack = 0x4000_u64.to_le_bytes();
        for case in &CASES[..3] {
            let input = cases::input(*case);
            let valid = body(*case, &input, &stack);
            let trace = inspect_body(*case, 0x1000, 0x4000, 0x2000, CODE, &valid);
            assert_eq!(trace.input_reads, usize::from(case.bound != 0));
        }
        let case = CASES[2];
        let input = cases::input(case);
        for mutation in 0..9 {
            let mut rows = body(case, &input, &stack);
            match mutation {
                0 => rows[0].before.rdi += 1,
                1 => rows[0].before.rsi = 0,
                2 => rows[2].after.rip = 0x1001,
                3 => rows[3].before.rdi += 1,
                4 => rows.last_mut().unwrap().after.rip += 1,
                5 => rows.last_mut().unwrap().after.rsp += 8,
                6 => rows.last_mut().unwrap().after.rax = 0,
                7 => {
                    rows.pop();
                }
                _ => rows[1].before.rsp += 8,
            }
            rejects(|| {
                inspect_body(case, 0x1000, 0x4000, 0x2000, CODE, &rows);
            });
        }
        let mut wrong_input = input;
        wrong_input[63] ^= 1;
        let rows = body(case, &wrong_input, &stack);
        rejects(|| {
            inspect_body(case, 0x1000, 0x4000, 0x2000, CODE, &rows);
        });
        let wrong_word = 0x4001_u64.to_le_bytes();
        let rows = body(case, &input, &wrong_word);
        rejects(|| {
            inspect_body(case, 0x1000, 0x4000, 0x2000, CODE, &rows);
        });
    }
    fn metadata(case: Case) -> (PairResult, Trace) {
        let declared = Graph::decode(CODE).declared;
        let mut observed = declared.clone();
        observed.returns = BTreeSet::from([if case.bound == 0 { 16 } else { 15 }]);
        let trace = Trace {
            entry: 0x1000,
            code: CODE.to_vec(),
            declared,
            observed,
            visits: 20,
            input_reads: usize::from(case.bound != 0),
            input_bytes: usize::from(case.bound != 0),
            ret_offset: if case.bound == 0 { 16 } else { 15 },
        };
        let pair = PairResult {
            comparisons: 31,
            original_steps: 40,
            candidate_steps: 100,
            visits: 20,
            returns: BTreeSet::from([0x1000 + trace.ret_offset]),
            declared_returns: BTreeSet::from([0x100f, 0x1010]),
            value: cases::scalar(case),
        };
        (pair, trace)
    }
    #[test]
    fn strnlen_population_refuses_order_scalar_steps_and_incomplete_coverage() {
        let mut p = Population::default();
        for seed in SEEDS {
            for case in CASES {
                let (pair, trace) = metadata(case);
                p.record(seed, case, &pair, &trace);
            }
        }
        let (extra, trace) = metadata(CASES[0]);
        rejects(|| p.record(SEEDS[0], CASES[0], &extra, &trace));
        let totals = p.finish();
        assert_eq!(
            (totals.comparisons, totals.input_reads, totals.input_bytes),
            (496, 14, 14)
        );
        rejects(|| {
            Population::default().finish();
        });
        for mutation in 0..14 {
            let mut p = Population::default();
            let (mut pair, mut trace) = metadata(CASES[0]);
            let mut seed = SEEDS[0];
            let mut case = CASES[0];
            match mutation {
                0 => seed = SEEDS[1],
                1 => case = CASES[1],
                2 => pair.value = 1,
                3 => pair.visits -= 1,
                4 => pair.comparisons -= 1,
                5 => pair.original_steps = MAX_STEPS + 1,
                6 => pair.candidate_steps = 30,
                7 => pair.returns.clear(),
                8 => {
                    pair.declared_returns.remove(&0x1010);
                }
                9 => {
                    trace.observed.edges.insert((0, 16));
                }
                10 => trace.ret_offset = 15,
                11 => trace.input_reads = 1,
                12 => trace.input_bytes = 1,
                _ => pair.candidate_steps = MAX_STEPS + 1,
            };
            rejects(|| p.record(seed, case, &pair, &trace));
        }
        for omitted in 0..3 {
            rejects(|| {
                let mut p = Population::default();
                for case in CASES {
                    let (mut pair, mut trace) = metadata(case);
                    match omitted {
                        0 => {
                            trace.observed.heads.remove(&2);
                        }
                        1 => {
                            trace.observed.edges.remove(&(5, 7));
                        }
                        _ => {
                            trace.observed.returns = BTreeSet::from([15]);
                            trace.ret_offset = 15;
                            pair.returns = BTreeSet::from([0x100f]);
                        }
                    }
                    p.record(SEEDS[0], case, &pair, &trace);
                }
            });
        }
        rejects(|| {
            let mut p = Population::default();
            let (pair, trace) = metadata(CASES[0]);
            p.record(SEEDS[0], CASES[0], &pair, &trace);
            p.record(SEEDS[0], CASES[0], &pair, &trace);
        });
        rejects(|| {
            let mut p = Population::default();
            for (n, case) in CASES.into_iter().enumerate() {
                let (pair, mut trace) = metadata(case);
                if n == 1 {
                    trace.code[1] ^= 1;
                }
                p.record(SEEDS[0], case, &pair, &trace);
            }
        });
    }
}
