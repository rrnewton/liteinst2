//! Checked normal-flow facts for the ordinary compiled C caller fixture.
//!
//! This is not a CFI, memory, loaded-code, function-pointer or ABI certificate.
//! The owner must authenticate the complete caller function and labels, admit
//! its sole external entry, and prove its entire original CFI/caller recovery.
//! Support CALLs require separately owned SysV callees that return normally with
//! RSP and the six callee registers preserved. The target under test instead
//! requires actual runtime observations and comparisons of RSP and all six
//! registers; its preservation is never an admission premise. Every CALL still
//! needs its actual target/ordinary-return binding, without exceptions, stack
//! switching, callbacks/reentry into this caller or asynchronous entry.
//! No dynamic CALL target or argument value is inferred from a label or opcode.
#![forbid(unsafe_code)]

use formats::ContentId;
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};

pub const BYTE_LIMIT: usize = 64 * 1024;
pub const INSTRUCTION_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Labels {
    pub sample: u64,
    pub configured: u64,
    pub canary_before: u64,
    pub pre: u64,
    pub post: u64,
    pub canary_after: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Decode,
    Flow,
    BranchTarget,
    Label,
    Sample,
    CallCount,
    ObservationOrder,
    Cycle,
    ReturnBypass,
    StackWrite,
    CalleeWrite,
}
type Result<T> = std::result::Result<T, Error>;

/// A CALL whose target/ordinary-return contract is still owed by the owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallSite {
    pub address: u64,
    pub return_pc: u64,
    /// None denotes an indirect r/m64 operand, not an authenticated callee.
    pub direct_target: Option<u64>,
}

/// Immutable, source-bound graph facts, never runtime/CFI qualification.
#[derive(Clone, Debug)]
pub struct Proof {
    identity: ContentId,
    base: u64,
    bytes: usize,
    labels: Labels,
    heads: Vec<u64>,
    target: CallSite,
    calls: Vec<CallSite>,
}
impl Proof {
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    pub const fn base(&self) -> u64 {
        self.base
    }
    pub const fn byte_len(&self) -> usize {
        self.bytes
    }
    pub const fn labels(&self) -> Labels {
        self.labels
    }
    pub fn heads(&self) -> &[u64] {
        &self.heads
    }
    /// Actual CALL/next_ip binding; target preservation must be measured.
    pub const fn target_call(&self) -> CallSite {
        self.target
    }
    pub const fn return_pc(&self) -> u64 {
        self.target.return_pc
    }
    /// Includes all decoded calls, even outside the proved observation window.
    pub fn calls(&self) -> &[CallSite] {
        &self.calls
    }
    /// Only support calls owe prior RSP/callee-register preservation admission.
    /// The exact target CALL remains in `calls()` and must be measured instead.
    pub fn support_calls_requiring_preservation(&self) -> impl Iterator<Item = &CallSite> {
        self.calls
            .iter()
            .filter(move |call| call.address != self.target.address)
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

struct Graph {
    instructions: Vec<Instruction>,
    heads: Vec<u64>,
    edges: Vec<Vec<usize>>,
    reverse: Vec<Vec<usize>>,
}
impl Graph {
    fn decode(bytes: &[u8], base: u64) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > BYTE_LIMIT {
            return Err(Error::Bounds);
        }
        let end = base.checked_add(bytes.len() as u64).ok_or(Error::Bounds)?;
        let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            if instructions.len() == INSTRUCTION_LIMIT {
                return Err(Error::Bounds);
            }
            let instruction = decoder.decode();
            if instruction.is_invalid()
                || instruction.is_privileged()
                || instruction.next_ip() > end
            {
                return Err(Error::Decode);
            }
            instructions.push(instruction);
        }
        if instructions.last().map(Instruction::next_ip) != Some(end) {
            return Err(Error::Decode);
        }
        let heads: Vec<_> = instructions.iter().map(Instruction::ip).collect();
        let head = |address| {
            heads
                .binary_search(&address)
                .map_err(|_| Error::BranchTarget)
        };
        let mut edges = Vec::with_capacity(instructions.len());
        for instruction in &instructions {
            let mut next = Vec::with_capacity(2);
            match instruction.flow_control() {
                FlowControl::Next => next.push(head(instruction.next_ip())?),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                    if instruction.op0_kind() == OpKind::NearBranch64 =>
                {
                    next.push(head(instruction.near_branch_target())?);
                    if instruction.flow_control() == FlowControl::ConditionalBranch {
                        let fallthrough = head(instruction.next_ip())?;
                        if next[0] != fallthrough {
                            next.push(fallthrough);
                        }
                    }
                }
                FlowControl::Call if instruction.code() == Code::Call_rel32_64 => {
                    // No internal CALL entry/recursion is hidden behind the
                    // separately admitted external-callee abstraction.
                    let target = instruction.near_branch_target();
                    if base <= target && target < end {
                        return Err(Error::Flow);
                    }
                    next.push(head(instruction.next_ip())?);
                }
                FlowControl::IndirectCall if instruction.code() == Code::Call_rm64 => {
                    next.push(head(instruction.next_ip())?);
                }
                FlowControl::Return if instruction.code() == Code::Retnq => (),
                _ => return Err(Error::Flow),
            }
            edges.push(next);
        }
        let mut reverse = vec![Vec::new(); instructions.len()];
        for (from, next) in edges.iter().enumerate() {
            for &to in next {
                reverse[to].push(from);
            }
        }
        Ok(Self {
            instructions,
            heads,
            edges,
            reverse,
        })
    }

    fn head(&self, address: u64) -> Result<usize> {
        self.heads.binary_search(&address).map_err(|_| Error::Label)
    }

    /// Stop is an observation boundary: its instruction is not yet executed.
    fn reachable(&self, start: usize, stop: Option<usize>, blocked: Option<usize>) -> Vec<bool> {
        walk(&self.edges, start, stop, blocked)
    }

    fn dominates(&self, earlier: usize, later: usize) -> bool {
        self.reachable(0, None, None)[later] && !self.reachable(0, None, Some(earlier))[later]
    }

    fn acyclic(&self, included: &[bool], stop: Option<usize>) -> Result<()> {
        let mut incoming = vec![0_usize; self.instructions.len()];
        let mut expected = 0;
        for (from, next) in self.edges.iter().enumerate() {
            if !included[from] {
                continue;
            }
            expected += 1;
            if Some(from) != stop {
                for &to in next {
                    if included[to] {
                        incoming[to] += 1;
                    }
                }
            }
        }
        let mut ready: Vec<_> = incoming
            .iter()
            .enumerate()
            .filter_map(|(index, &count)| (included[index] && count == 0).then_some(index))
            .collect();
        let mut removed = 0;
        while let Some(from) = ready.pop() {
            removed += 1;
            if Some(from) != stop {
                for &to in &self.edges[from] {
                    if included[to] {
                        incoming[to] -= 1;
                        if incoming[to] == 0 {
                            ready.push(to);
                        }
                    }
                }
            }
        }
        if removed != expected {
            return Err(Error::Cycle);
        }
        Ok(())
    }
}

fn walk(
    edges: &[Vec<usize>],
    start: usize,
    stop: Option<usize>,
    blocked: Option<usize>,
) -> Vec<bool> {
    let mut seen = vec![false; edges.len()];
    let mut work = Vec::new();
    if Some(start) != blocked {
        seen[start] = true;
        work.push(start);
    }
    while let Some(from) = work.pop() {
        if Some(from) == stop {
            continue;
        }
        for &to in &edges[from] {
            if !seen[to] && Some(to) != blocked {
                seen[to] = true;
                work.push(to);
            }
        }
    }
    seen
}

fn call(instruction: &Instruction) -> Option<CallSite> {
    match instruction.code() {
        Code::Call_rel32_64 | Code::Call_rm64 => Some(CallSite {
            address: instruction.ip(),
            return_pc: instruction.next_ip(),
            direct_target: (instruction.code() == Code::Call_rel32_64)
                .then(|| instruction.near_branch_target()),
        }),
        _ => None,
    }
}

fn sample(instruction: &Instruction) -> bool {
    instruction.mnemonic() == Mnemonic::Mov
        && instruction.op_count() == 2
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && instruction.op0_register().is_gpr64()
        && instruction.op0_register() != Register::RSP
        && instruction.op1_register() == Register::RSP
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Prove the mechanical register/control-flow part of caller.c's contract.
/// External entries, memory aliases/return words, canary values and stores,
/// actual indirect targets/arguments and complete original caller CFI remain
/// independently mandatory. Support calls require separate SysV preservation
/// admission. Target RSP and six-register outcomes must instead be observed and
/// compared at runtime, never assumed from the expected outcome. CALL edges
/// describe normal return to decoded next_ip; the local no-write proof excludes
/// CALL effects and proves neither actual return nor preservation by a callee.
pub fn prove(bytes: &[u8], base: u64, labels: Labels) -> Result<Proof> {
    let graph = Graph::decode(bytes, base)?;
    let addresses = [
        labels.sample,
        labels.configured,
        labels.canary_before,
        labels.pre,
        labels.post,
        labels.canary_after,
    ];
    let mut points = [0; 6];
    for (position, &address) in addresses.iter().enumerate() {
        if addresses[..position].contains(&address) {
            return Err(Error::Label);
        }
        points[position] = graph.head(address)?;
    }
    let [initial, configured, before, pre, post, after] = points;
    for index in [initial, configured, pre, post] {
        if !sample(&graph.instructions[index]) {
            return Err(Error::Sample);
        }
    }

    let from_pre = graph.reachable(pre, None, None);
    let to_post = walk(&graph.reverse, post, None, None);
    let candidates: Vec<_> = graph
        .instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (from_pre[index] && to_post[index] && call(instruction).is_some()).then_some(index)
        })
        .collect();
    if candidates.len() != 1 {
        return Err(Error::CallCount);
    }
    let target = candidates[0];
    if graph.instructions[target].code() != Code::Call_rm64 {
        return Err(Error::CallCount);
    }
    let target_call = call(&graph.instructions[target]).ok_or(Error::CallCount)?;
    let returned = graph.head(target_call.return_pc)?;
    let chain = [initial, configured, before, pre, target];
    for pair in chain.windows(2) {
        if pair[0] == pair[1] || !graph.dominates(pair[0], pair[1]) {
            return Err(Error::ObservationOrder);
        }
    }
    // A route to the post/after labels without the intended CALL is not a
    // successful invocation merely because another route contains that CALL.
    if !graph.dominates(target, post) || !graph.dominates(post, after) {
        return Err(Error::ObservationOrder);
    }

    let to_call = walk(&graph.reverse, target, None, None);
    let from_initial = graph.reachable(initial, None, None);
    let from_before = graph.reachable(before, None, None);
    let prefix: Vec<_> = from_initial
        .iter()
        .zip(&to_call)
        .map(|(&from, &to)| from && to)
        .collect();
    graph.acyclic(&prefix, None)?;

    let suffix = graph.reachable(returned, Some(after), None);
    if !suffix[post] || !suffix[after] || graph.reachable(returned, Some(after), Some(post))[after]
    {
        return Err(Error::ObservationOrder);
    }
    graph.acyclic(&suffix, Some(after))?;
    for (index, &included) in suffix.iter().enumerate() {
        // An acyclic finite graph with no other terminal must reach `after`
        // on every path, not merely have one favorable route to it.
        if included && index != after && graph.edges[index].is_empty() {
            return Err(Error::ReturnBypass);
        }
    }

    let mut information = InstructionInfoFactory::new();
    for (index, instruction) in graph.instructions.iter().enumerate() {
        let returned_window = suffix[index] && index != after;
        if !(prefix[index] || returned_window) || call(instruction).is_some() {
            continue;
        }
        let check_callee = (from_before[index] && to_call[index]) || returned_window;
        let effects = information.info(instruction);
        for register in effects.used_registers() {
            if !writes(register.access()) {
                continue;
            }
            match register.register().full_register() {
                Register::RSP => return Err(Error::StackWrite),
                Register::RBX
                | Register::RBP
                | Register::R12
                | Register::R13
                | Register::R14
                | Register::R15
                    if check_callee =>
                {
                    return Err(Error::CalleeWrite);
                }
                _ => (),
            }
        }
    }
    let calls = graph.instructions.iter().filter_map(call).collect();
    Ok(Proof {
        identity: ContentId::of(bytes),
        base,
        bytes: bytes.len(),
        labels,
        heads: graph.heads,
        target: target_call,
        calls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: u64 = 0x1000;

    // Pure byte puzzle, not asserted to be compiler output or a CFI witness.
    fn fixture() -> (Vec<u8>, Labels) {
        (
            vec![
                0x48, 0x83, 0xec, 8, // 0: prologue outside observation window
                0x48, 0x89, 0xe0, // 4: sample MOV RAX,RSP
                0xff, 0xd1, // 7: separately admitted configuration CALL RCX
                0x48, 0x89, 0xe0, // 9: configured sample
                0x90, // 12: before observation boundary
                0x48, 0x89, 0xe0, // 13: pre sample
                0x41, 0xff, 0xd3, // 16: intended CALL R11
                0x48, 0x89, 0xe0, // 19: true return PC and post sample
                0x90, // 22: after observation boundary
                0x48, 0x83, 0xc4, 8,    // 23: epilogue after observations
                0xc3, // 27
            ],
            Labels {
                sample: BASE + 4,
                configured: BASE + 9,
                canary_before: BASE + 12,
                pre: BASE + 13,
                post: BASE + 19,
                canary_after: BASE + 22,
            },
        )
    }

    fn insert(bytes: &mut Vec<u8>, labels: &mut Labels, at: usize, extra: &[u8]) {
        let tail = bytes.split_off(at);
        bytes.extend_from_slice(extra);
        bytes.extend_from_slice(&tail);
        for point in [
            &mut labels.sample,
            &mut labels.configured,
            &mut labels.canary_before,
            &mut labels.pre,
            &mut labels.post,
            &mut labels.canary_after,
        ] {
            if *point >= BASE + at as u64 {
                *point += extra.len() as u64;
            }
        }
    }

    #[test]
    fn ordinary_indirect_call_returns_its_decoded_next_ip_and_retains_dependencies() {
        let (bytes, labels) = fixture();
        let proof = prove(&bytes, BASE, labels).unwrap();
        assert_eq!(proof.identity(), ContentId::of(&bytes));
        assert_eq!(
            (proof.base(), proof.byte_len(), proof.labels()),
            (BASE, 28, labels)
        );
        assert_eq!(proof.target_call().address, BASE + 16);
        assert_eq!(proof.return_pc(), BASE + 19);
        assert_eq!(proof.calls().len(), 2);
        assert_eq!(proof.calls()[0].address, BASE + 7);
        assert_eq!(proof.calls()[1], proof.target_call());
        assert_eq!(
            proof
                .support_calls_requiring_preservation()
                .copied()
                .collect::<Vec<_>>(),
            vec![proof.calls()[0]]
        );
        assert_eq!(proof.heads().last(), Some(&(BASE + 27)));
        assert!(!proof.qualification_complete());
    }

    #[test]
    fn equal_samples_do_not_hide_intermediate_rsp_changes() {
        let (mut bytes, mut labels) = fixture();
        insert(
            &mut bytes,
            &mut labels,
            12,
            &[0x48, 0x83, 0xec, 8, 0x48, 0x83, 0xc4, 8],
        );
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::StackWrite));
    }

    #[test]
    fn callee_reload_or_rematerialization_cannot_hide_corruption() {
        for at in [13, 19] {
            let (mut bytes, mut labels) = fixture();
            insert(&mut bytes, &mut labels, at, &[0x48, 0x8b, 0x5c, 0x24, 8]);
            assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::CalleeWrite));
        }
        let (mut bytes, mut labels) = fixture();
        insert(&mut bytes, &mut labels, 19, &[0x31, 0xdb]); // EBX also writes RBX.
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::CalleeWrite));
    }

    #[test]
    fn bypassed_prefix_or_return_observations_and_early_return_refuse() {
        for (at, branch) in [
            (4, [0x75, 5]),
            (12, [0x75, 1]),
            (16, [0x75, 3]), // Bypass CALL while still reaching post.
            (19, [0x75, 3]),
        ] {
            let (mut bytes, mut labels) = fixture();
            insert(&mut bytes, &mut labels, at, &branch);
            assert_eq!(
                prove(&bytes, BASE, labels).err(),
                Some(Error::ObservationOrder)
            );
        }
        let (mut bytes, mut labels) = fixture();
        insert(&mut bytes, &mut labels, 19, &[0x75, 8]); // One route goes straight to RET.
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::ReturnBypass));
    }

    #[test]
    fn multiple_calls_and_a_repeatable_call_cycle_refuse() {
        let (mut bytes, mut labels) = fixture();
        insert(&mut bytes, &mut labels, 16, &[0x41, 0xff, 0xd2]);
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::CallCount));
        let (mut bytes, mut labels) = fixture();
        insert(&mut bytes, &mut labels, 19, &[0x75, 0xfb]); // Back to the CALL head.
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::Cycle));
    }

    #[test]
    fn middle_byte_targets_and_non_mov_rsp_labels_refuse() {
        let (mut bytes, mut labels) = fixture();
        insert(&mut bytes, &mut labels, 4, &[0x75, 1]);
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::BranchTarget));
        let (mut bytes, labels) = fixture();
        bytes[6] = 0xc0; // MOV RAX,RAX is not an RSP observation.
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::Sample));
        let (bytes, mut labels) = fixture();
        labels.post += 1;
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::Label));
    }

    #[test]
    fn a_failure_path_that_never_reaches_target_call_remains_valid() {
        let (mut bytes, mut labels) = fixture();
        insert(&mut bytes, &mut labels, 16, &[0x74, 7]); // Refusal goes to epilogue.
        let proof = prove(&bytes, BASE, labels).unwrap();
        assert_eq!(proof.target_call().address, BASE + 18);
        assert_eq!(proof.return_pc(), BASE + 21);
        assert!(!proof.qualification_complete());
    }

    #[test]
    fn complete_decode_bounds_and_unsupported_control_flow_are_not_skipped() {
        let (_, labels) = fixture();
        assert_eq!(
            prove(&vec![0x90; BYTE_LIMIT + 1], BASE, labels).err(),
            Some(Error::Bounds)
        );
        let mut many = vec![0x90; INSTRUCTION_LIMIT];
        many.push(0xc3);
        assert_eq!(prove(&many, BASE, labels).err(), Some(Error::Bounds));
        let (mut bytes, labels) = fixture();
        bytes[7] = 0xff;
        bytes[8] = 0xe1; // JMP RCX, not an admitted normal CALL.
        assert_eq!(prove(&bytes, BASE, labels).err(), Some(Error::Flow));
        assert_eq!(prove(&[], BASE, labels).err(), Some(Error::Bounds));
        assert_eq!(prove(&bytes, u64::MAX, labels).err(), Some(Error::Bounds));
    }
}
