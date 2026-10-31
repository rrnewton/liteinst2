//! Finite stack/CFI facts for the fixed compiled collector and its wrappers.
//!
//! These are independent expected values, never a projection of a native
//! Trace. Exact immutable code/metadata owners and actual loader/dependency
//! bindings remain mandatory. In particular every recorded external CALL must
//! have its actual target admitted as an ordinary SysV returning dependency;
//! no exception, longjmp, signal reentry, stack switch or aliasing write into
//! this activation's saved words is covered by the local instruction analysis.
//! Non-RSP memory writes are retained as explicit owner obligations, not proved
//! disjoint by a register name. The fixed collector's config/records/context
//! disjointness and all libc/libgcc dependencies must establish those facts.
#![forbid(unsafe_code)]

use super::{caller, caller_dataflow, cfi, observations, prepare};
use formats::ContentId;
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};
use li2core::frame_trace::{
    FrameCallKind, FrameEntryOrigin, FrameInstructionKind, OriginalRegisterLocation,
};
use li2core::generated_unwind::artifact::OriginalArtifactCfi;
use li2core::trampoline::ObservationStackProfile;
use std::ops::Range;

const MAX_BYTES: usize = 64 * 1024;
const MAX_HEADS: usize = 4096;
const MAX_STACK: i64 = 64 * 1024;
const SIX: [Register; 6] = [
    Register::RBX,
    Register::RBP,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Decode,
    Flow,
    Target,
    Stack,
    Merge,
    Cfi,
    ConsumerRestore,
    Undefined,
    Recovery,
    Call,
    Shape,
    Arithmetic,
}
type Result<T> = std::result::Result<T, Error>;

/// The entire function, not a prefix ending conveniently at an observed CALL.
/// Owner identity and complete exact CFI byte/coordinate joins are separate.
pub struct Function<'a> {
    pub address: u64,
    pub bytes: &'a [u8],
    pub record: &'a OriginalArtifactCfi,
    pub metadata: cfi::Metadata<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Call {
    pub address: u64,
    pub return_pc: u64,
    pub target: u64,
    /// RSP immediately before CALL, relative to this function's entry RSP.
    pub rsp_delta: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalWrite {
    pub instruction: u64,
    pub base: Register,
    pub index: Register,
    pub displacement: u64,
    pub bytes: usize,
}

/// Mechanical proof, conditional on the precise dependency/memory obligations
/// documented above. No loaded-code or actual normal-return authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionProof {
    code: ContentId,
    cie: ContentId,
    fde: ContentId,
    function: Range<u64>,
    calls: Vec<Call>,
    external_writes: Vec<ExternalWrite>,
    repeatable_calls: Vec<u64>,
    heads: usize,
}
impl FunctionProof {
    pub const fn code_identity(&self) -> ContentId {
        self.code
    }
    pub const fn cie_identity(&self) -> ContentId {
        self.cie
    }
    pub const fn fde_identity(&self) -> ContentId {
        self.fde
    }
    pub fn function(&self) -> Range<u64> {
        self.function.clone()
    }
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }
    pub fn external_writes(&self) -> &[ExternalWrite] {
        &self.external_writes
    }
    pub const fn reachable_heads(&self) -> usize {
        self.heads
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }
    fn unique_call(&self, target: u64) -> Result<Call> {
        let mut matches = self.calls.iter().filter(|c| c.target == target);
        let first = *matches.next().ok_or(Error::Call)?;
        if matches.next().is_some() || self.repeatable_calls.contains(&first.address) {
            return Err(Error::Call);
        }
        Ok(first)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stack {
    rsp: i64,
    /// Whether the live register still contains this function's entry value.
    live: [bool; 6],
    /// Exact saved-word location relative to entry RSP, if preserved.
    saved: [Option<i64>; 6],
}
impl Stack {
    const ENTRY: Self = Self {
        rsp: 0,
        live: [true; 6],
        saved: [None; 6],
    };
    fn change(&mut self, delta: i64) -> Result<()> {
        self.rsp = self.rsp.checked_add(delta).ok_or(Error::Arithmetic)?;
        if !(-MAX_STACK..=0).contains(&self.rsp) || self.rsp % 8 != 0 {
            return Err(Error::Stack);
        }
        Ok(())
    }
    fn recover(&self, row: cfi::Row) -> Result<()> {
        if row.cfa.register != 7
            || self.rsp.checked_add(row.cfa.offset) != Some(8)
            || row.columns[6] != cfi::Rule::Offset(-8)
        {
            return Err(Error::Recovery);
        }
        for (column, rule) in row.columns[..6].iter().enumerate() {
            match rule {
                cfi::Rule::Undefined => return Err(Error::Undefined),
                // This is a named pinned GNU consumer policy, not a rewrite of
                // the CFI row. Both variants remain distinct in the table.
                cfi::Rule::Unspecified | cfi::Rule::Same if self.live[column] => {}
                cfi::Rule::Offset(offset)
                    if self.saved[column]
                        .is_some_and(|slot| 8_i64.checked_add(*offset) == Some(slot)) => {}
                _ => return Err(Error::Recovery),
            }
        }
        Ok(())
    }
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}
fn register_column(register: Register) -> Option<usize> {
    SIX.iter().position(|&r| r == register.full_register())
}
fn immediate(i: &Instruction) -> Result<i64> {
    match i.op1_kind() {
        OpKind::Immediate8to64 | OpKind::Immediate32to64 => Ok(i.immediate(1) as i64),
        _ => Err(Error::Stack),
    }
}

/// GNU 11.5 execute_cfa_program implements restore as REG_UNSAVED, unlike
/// arbitrary CIE-baseline restoration. Check every restored column, including
/// operations in the complete tail, before admitting this consumer profile.
fn consumer(table: &cfi::Table) -> Result<()> {
    let baseline = table.cie_baseline();
    for (column, used) in table.restored_columns().into_iter().enumerate() {
        if used && !matches!(baseline[column], cfi::Rule::Unspecified | cfi::Rule::Same) {
            return Err(Error::ConsumerRestore);
        }
    }
    if table
        .rows()
        .iter()
        .any(|r| r.columns.contains(&cfi::Rule::Undefined))
    {
        return Err(Error::Undefined);
    }
    Ok(())
}

struct Graph {
    instructions: Vec<Instruction>,
    edges: Vec<Vec<usize>>,
}
impl Graph {
    fn decode(function: &Function<'_>) -> Result<Self> {
        Self::decode_with_caller(function, None)
    }
    // Only the separate conditional caller API may admit indirect calls. The
    // old subject/collector route supplies None and keeps its exact grammar.
    fn decode_with_caller(function: &Function<'_>, caller: Option<&caller::Proof>) -> Result<Self> {
        if function.bytes.is_empty() || function.bytes.len() > MAX_BYTES {
            return Err(Error::Bounds);
        }
        let end = function
            .address
            .checked_add(function.bytes.len() as u64)
            .ok_or(Error::Bounds)?;
        let mut decoder =
            Decoder::with_ip(64, function.bytes, function.address, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            if instructions.len() == MAX_HEADS {
                return Err(Error::Bounds);
            }
            let i = decoder.decode();
            if i.is_invalid()
                || i.is_privileged()
                || i.next_ip() > end
                || i.has_lock_prefix()
                || matches!(i.segment_prefix(), Register::FS | Register::GS)
            {
                return Err(Error::Decode);
            }
            instructions.push(i);
        }
        if instructions.last().map(Instruction::next_ip) != Some(end) {
            return Err(Error::Decode);
        }
        let heads: Vec<_> = instructions.iter().map(Instruction::ip).collect();
        let head = |ip| heads.binary_search(&ip).map_err(|_| Error::Target);
        let mut edges = Vec::new();
        for i in &instructions {
            let mut next = Vec::new();
            match i.flow_control() {
                FlowControl::Next => next.push(head(i.next_ip())?),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                    if i.op0_kind() == OpKind::NearBranch64 =>
                {
                    next.push(head(i.near_branch_target())?);
                    if i.flow_control() == FlowControl::ConditionalBranch {
                        let fallthrough = head(i.next_ip())?;
                        if !next.contains(&fallthrough) {
                            next.push(fallthrough);
                        }
                    }
                }
                FlowControl::Call if i.code() == Code::Call_rel32_64 => {
                    if (function.address..end).contains(&i.near_branch_target()) {
                        return Err(Error::Flow);
                    }
                    next.push(head(i.next_ip())?);
                }
                FlowControl::IndirectCall if i.code() == Code::Call_rm64 && caller.is_some() => {
                    next.push(head(i.next_ip())?);
                }
                FlowControl::Return if i.code() == Code::Retnq => {}
                _ => return Err(Error::Flow),
            }
            edges.push(next);
        }
        if let Some(proof) = caller {
            let calls: Vec<_> = instructions
                .iter()
                .filter(|i| is_call(i))
                .map(|i| caller::CallSite {
                    address: i.ip(),
                    return_pc: i.next_ip(),
                    direct_target: (i.code() == Code::Call_rel32_64)
                        .then(|| i.near_branch_target()),
                })
                .collect();
            if heads != proof.heads() || calls != proof.calls() {
                return Err(Error::Call);
            }
        }
        Ok(Self {
            instructions,
            edges,
        })
    }
}

fn is_call(i: &Instruction) -> bool {
    matches!(i.code(), Code::Call_rel32_64 | Code::Call_rm64)
}

fn preserved_call(state: Stack) -> Result<Stack> {
    // Support calls owe this normal-return contract. In the conditional caller
    // route the tested target instead owes the independent raw-return check;
    // this abstract continuation does not establish that target's outcome.
    if state.saved.iter().flatten().any(|&slot| slot < state.rsp) {
        return Err(Error::Stack);
    }
    Ok(state)
}

fn effect(i: &Instruction, mut state: Stack) -> Result<Stack> {
    // CALL and RET are ordinary stack edges with separately mandatory actual
    // target, return-word and dependency ownership. No callee-clobber premise
    // is silently applied to the tested application function.
    if i.code() == Code::Call_rel32_64 {
        // A subsequent callee may use everything below pre-CALL RSP. A
        // stale, popped save there cannot remain a recovery dependency merely
        // because no explicit local store has overwritten it yet.
        return preserved_call(state);
    }
    if i.code() == Code::Retnq {
        if state.rsp != 0 || state.live != [true; 6] {
            return Err(Error::Stack);
        }
        return Ok(state);
    }
    if matches!(i.mnemonic(), Mnemonic::Push | Mnemonic::Pop) {
        if i.op0_kind() != OpKind::Register || !i.op0_register().is_gpr64() {
            return Err(Error::Stack);
        }
        let column = register_column(i.op0_register()).ok_or(Error::Stack)?;
        if i.mnemonic() == Mnemonic::Push {
            if !state.live[column] {
                return Err(Error::Stack);
            }
            state.change(-8)?;
            if state.saved.iter().flatten().any(|&p| p == state.rsp) {
                return Err(Error::Stack);
            }
            state.saved[column] = Some(state.rsp);
        } else {
            if state.saved[column] != Some(state.rsp) {
                return Err(Error::Stack);
            }
            state.live[column] = true;
            state.change(8)?;
        }
        return Ok(state);
    }
    if matches!(i.mnemonic(), Mnemonic::Add | Mnemonic::Sub)
        && i.op0_kind() == OpKind::Register
        && i.op0_register() == Register::RSP
    {
        let amount = immediate(i)?;
        if amount <= 0 {
            return Err(Error::Stack);
        }
        state.change(if i.mnemonic() == Mnemonic::Sub {
            -amount
        } else {
            amount
        })?;
        return Ok(state);
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(i);
    for used in info.used_registers() {
        if !writes(used.access()) {
            continue;
        }
        if used.register().full_register() == Register::RSP {
            return Err(Error::Stack);
        }
        if let Some(column) = register_column(used.register()) {
            state.live[column] = false;
        }
    }
    for memory in info.used_memory() {
        if !writes(memory.access()) || memory.base().full_register() != Register::RSP {
            continue;
        }
        if memory.index() != Register::None {
            return Err(Error::Stack);
        }
        let bytes = i64::try_from(memory.memory_size().size()).map_err(|_| Error::Bounds)?;
        let start = state
            .rsp
            .checked_add(memory.displacement() as i64)
            .ok_or(Error::Arithmetic)?;
        let end = start.checked_add(bytes).ok_or(Error::Arithmetic)?;
        // Only currently reserved local scratch, never the entry return word,
        // popped saved slots, or an imprecisely sized stack store.
        if bytes == 0 || start < state.rsp || end > 0 {
            return Err(Error::Stack);
        }
        if state
            .saved
            .iter()
            .flatten()
            .any(|&p| start < p + 8 && p < end)
        {
            return Err(Error::Stack);
        }
    }
    Ok(state)
}

/// Decode the complete function, interpret its complete original CFI, and
/// compare entry-relative RSP/saved-column facts at every reachable head.
/// Cycles are admitted only when the exact abstract stack/recovery state joins;
/// no iteration limit or sampled path substitutes for checking an edge.
pub fn prove_function(function: Function<'_>) -> Result<FunctionProof> {
    let graph = Graph::decode(&function)?;
    analyze_function(function, graph, false)
}

// The caller-only path uses this same full CFI/state engine. Its distinct
// result below cannot escape as an unconditional FunctionProof.
fn analyze_function(
    function: Function<'_>,
    graph: Graph,
    conditional_caller: bool,
) -> Result<FunctionProof> {
    let range = function.address
        ..function
            .address
            .checked_add(function.bytes.len() as u64)
            .ok_or(Error::Bounds)?;
    let table = cfi::parse(
        function.record,
        function.metadata,
        range.clone(),
        cfi::Limits::default(),
    )
    .map_err(|_| Error::Cfi)?;
    consumer(&table)?;
    let heads: Vec<_> = graph.instructions.iter().map(Instruction::ip).collect();
    if table.rows().iter().any(|row| {
        heads.binary_search(&row.start).is_err()
            || (row.end != range.end && heads.binary_search(&row.end).is_err())
    }) {
        return Err(Error::Cfi);
    }
    let mut states = vec![None; graph.instructions.len()];
    states[0] = Some(Stack::ENTRY);
    let mut pending = vec![0];
    while let Some(index) = pending.pop() {
        let state = states[index].ok_or(Error::Merge)?;
        let instruction = &graph.instructions[index];
        let next = if conditional_caller && instruction.code() == Code::Call_rm64 {
            preserved_call(state)?
        } else {
            effect(instruction, state)?
        };
        for &to in &graph.edges[index] {
            if let Some(previous) = states[to] {
                if previous.rsp != next.rsp {
                    return Err(Error::Merge);
                }
                let mut joined = previous;
                for column in 0..6 {
                    joined.live[column] &= next.live[column];
                    if previous.saved[column] != next.saved[column] {
                        joined.saved[column] = None;
                    }
                }
                if joined != previous {
                    states[to] = Some(joined);
                    pending.push(to);
                }
            } else {
                states[to] = Some(next);
                pending.push(to);
            }
        }
    }
    let mut calls = Vec::new();
    let mut repeatable_calls = Vec::new();
    let mut external_writes = Vec::new();
    let mut heads = 0;
    for (index, (i, state)) in graph.instructions.iter().zip(states).enumerate() {
        let Some(state) = state else {
            continue;
        };
        state.recover(table.row_at(i.ip()).map_err(|_| Error::Cfi)?)?;
        heads += 1;
        if is_call(i) {
            // x86 ordinary-call RSP must satisfy SysV pre-CALL alignment;
            // the entry RSP is 8 modulo16 under the separately owned ABI.
            if (8 + state.rsp).rem_euclid(16) != 0 {
                return Err(Error::Stack);
            }
            let mut seen = vec![false; graph.instructions.len()];
            let mut pending = graph.edges[index].clone();
            while let Some(at) = pending.pop() {
                if seen[at] {
                    continue;
                }
                seen[at] = true;
                pending.extend_from_slice(&graph.edges[at]);
            }
            if seen[index] {
                repeatable_calls.push(i.ip());
            }
            calls.push(Call {
                address: i.ip(),
                return_pc: i.next_ip(),
                target: if i.code() == Code::Call_rel32_64 {
                    i.near_branch_target()
                } else {
                    0
                },
                rsp_delta: state.rsp,
            });
            continue;
        }
        if matches!(i.mnemonic(), Mnemonic::Push | Mnemonic::Pop | Mnemonic::Ret) {
            continue;
        }
        let mut factory = InstructionInfoFactory::new();
        for memory in factory.info(i).used_memory() {
            if writes(memory.access()) && memory.base().full_register() != Register::RSP {
                external_writes.push(ExternalWrite {
                    instruction: i.ip(),
                    base: memory.base(),
                    index: memory.index(),
                    displacement: memory.displacement(),
                    bytes: memory.memory_size().size(),
                });
            }
        }
    }
    Ok(FunctionProof {
        code: ContentId::of(function.bytes),
        cie: ContentId::of(&function.record.cie),
        fde: ContentId::of(&function.record.fde),
        function: range,
        calls,
        external_writes,
        repeatable_calls,
        heads,
    })
}

/// Full caller CFI/stack analysis under a retained, unfulfilled target-return
/// obligation. It is deliberately not a FunctionProof. All support calls still
/// owe normal SysV return and exact protected-memory ownership; the tested CALL
/// never receives that preservation premise. Its abstract continuation is valid
/// only after check_return succeeds on independently captured actual values.
/// Even that numeric comparison does not establish loaded ownership, pointer
/// provenance, absence of alias writes, or the source/build contracts.
#[derive(Clone, Debug)]
pub struct ConditionalCallerCfi {
    facts: FunctionProof,
    target: caller::CallSite,
    supports: Vec<caller::CallSite>,
    raw: caller_dataflow::RawCapture,
    kind: caller_dataflow::Kind,
    frame_offset: i64,
}
impl ConditionalCallerCfi {
    pub const fn code_identity(&self) -> ContentId {
        self.facts.code
    }
    pub const fn cie_identity(&self) -> ContentId {
        self.facts.cie
    }
    pub const fn fde_identity(&self) -> ContentId {
        self.facts.fde
    }
    pub fn function(&self) -> Range<u64> {
        self.facts.function.clone()
    }
    pub const fn target_call(&self) -> caller::CallSite {
        self.target
    }
    pub const fn raw_capture(&self) -> caller_dataflow::RawCapture {
        self.raw
    }
    pub const fn pre_call_frame_offset(&self) -> i64 {
        self.frame_offset
    }
    pub fn support_calls_requiring_preservation(&self) -> &[caller::CallSite] {
        &self.supports
    }
    pub fn external_writes(&self) -> &[ExternalWrite] {
        &self.facts.external_writes
    }
    pub const fn reachable_heads(&self) -> usize {
        self.facts.heads
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }

    /// Discharge only the conditional target RSP/six-register continuation.
    /// The owner supplies the actual loaded bias and observation/raw objects
    /// from this exact invocation and code identity. Existing check_call and
    /// check_raw_return remain mandatory, as do the complete trace comparator
    /// and support/target no-alias proof. A nonreturning/corrupting invocation is
    /// a failed process; this method is not a recovery path or an ABI promise.
    pub fn check_return(
        &self,
        bias: u64,
        observation: &observations::CallerObservation,
        raw: &observations::RawReturn,
    ) -> Result<()> {
        let returned = bias
            .checked_add(self.target.return_pc)
            .ok_or(Error::Arithmetic)?;
        let expected_kind = if self.kind == caller_dataflow::Kind::Work {
            1
        } else {
            2
        };
        if returned == 0
            || returned > isize::MAX as u64
            || observation.caller_return as u64 != returned
            || observation.kind != expected_kind
            || observation.invocation_dispatched != 1
            || observation.normal_returned != 1
        {
            return Err(Error::Call);
        }
        let before = observation.rsp_sample as u64;
        if before < 8
            || before % 16 != 0
            || before > isize::MAX as u64
            || [
                observation.rsp_configured,
                observation.rsp_pre,
                observation.rsp_post,
            ]
            .iter()
            .any(|&p| p as u64 != before)
            || observation.caller_return_slot as u64 != before - 8
            || raw.rsp != before
        {
            return Err(Error::Stack);
        }
        if observation.callee_before != observations::CANARIES
            || observation.callee_after != observations::CANARIES
            || raw.callee != observations::CANARIES
        {
            return Err(Error::Recovery);
        }
        Ok(())
    }
}

/// Separate caller-only admission. The original collector/function API remains
/// direct-call-only. Every decoded call/head must join the exact caller graph;
/// dataflow and tail proofs bind the same entire bytes and tested/compare CALLs.
/// No partial CFI target lookup substitutes for the complete-program analysis.
pub fn prove_conditional_caller(
    function: Function<'_>,
    graph: &caller::Proof,
    data: &caller_dataflow::Dataflow,
    tail: &caller_dataflow::TailProof,
) -> Result<ConditionalCallerCfi> {
    let identity = ContentId::of(function.bytes);
    if graph.base() != function.address
        || graph.byte_len() != function.bytes.len()
        || graph.identity() != identity
        || data.identity() != identity
        || tail.identity() != identity
        || graph.target_call() != data.target_call()
        || tail.compare().call() != data.unproved_tail_entry()
        || tail.finish_contracts().is_empty()
        || tail.return_instructions().is_empty()
        || tail
            .finish_contracts()
            .iter()
            .any(|c| !data.remaining_support_calls().contains(&c.call))
        || data.raw_store_instructions().len() != 8
    {
        return Err(Error::Shape);
    }
    let raw = data.raw_capture().ok_or(Error::Shape)?;
    let decoded = Graph::decode_with_caller(&function, Some(graph))?;
    let facts = analyze_function(function, decoded, true)?;
    let target = graph.target_call();
    let call = facts
        .calls
        .iter()
        .find(|c| c.address == target.address)
        .ok_or(Error::Call)?;
    if call.return_pc != target.return_pc
        || call.rsp_delta != data.pre_call_frame_offset()
        || facts.repeatable_calls.contains(&target.address)
    {
        return Err(Error::Call);
    }
    Ok(ConditionalCallerCfi {
        facts,
        target,
        supports: graph
            .support_calls_requiring_preservation()
            .copied()
            .collect(),
        raw,
        kind: data.kind(),
        frame_offset: data.pre_call_frame_offset(),
    })
}

/// The four actual subject functions and their unique owned chain edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subject {
    collect: FunctionProof,
    original: FunctionProof,
    hook: FunctionProof,
    reference: FunctionProof,
    backtrace: Call,
    original_to_collect: Call,
    hook_to_collect: Call,
    reference_to_original: Call,
}
impl Subject {
    pub fn collect(&self) -> &FunctionProof {
        &self.collect
    }
    pub fn original(&self) -> &FunctionProof {
        &self.original
    }
    pub fn hook(&self) -> &FunctionProof {
        &self.hook
    }
    pub fn reference(&self) -> &FunctionProof {
        &self.reference
    }
    pub fn prove(
        collect: Function<'_>,
        original: Function<'_>,
        hook: Function<'_>,
        reference: Function<'_>,
        backtrace_target: u64,
    ) -> Result<Self> {
        let inputs = [&collect, &original, &hook, &reference];
        for (index, input) in inputs.iter().enumerate() {
            if input.metadata.address != collect.metadata.address
                || input.metadata.bytes != collect.metadata.bytes
            {
                return Err(Error::Shape);
            }
            let end = input
                .address
                .checked_add(input.bytes.len() as u64)
                .ok_or(Error::Arithmetic)?;
            for other in &inputs[..index] {
                let other_end = other
                    .address
                    .checked_add(other.bytes.len() as u64)
                    .ok_or(Error::Arithmetic)?;
                if input.address < other_end && other.address < end {
                    return Err(Error::Shape);
                }
            }
        }
        // Full literal wrapper/reference shapes independently establish their
        // live-register state at the owned CALL, beyond mere CFI validity.
        wrapper(&original, collect.address, true)?;
        wrapper(&hook, collect.address, false)?;
        reference_shape(&reference, original.address)?;
        let collect = prove_function(collect)?;
        let original = prove_function(original)?;
        let hook = prove_function(hook)?;
        let reference = prove_function(reference)?;
        let backtrace = collect.unique_call(backtrace_target)?;
        let original_to_collect = original.unique_call(collect.function.start)?;
        let hook_to_collect = hook.unique_call(collect.function.start)?;
        let reference_to_original = reference.unique_call(original.function.start)?;
        if original.calls.len() != 1 || hook.calls.len() != 1 || reference.calls.len() != 1 {
            return Err(Error::Call);
        }
        Ok(Self {
            collect,
            original,
            hook,
            reference,
            backtrace,
            original_to_collect,
            hook_to_collect,
            reference_to_original,
        })
    }
    pub const fn backtrace_call(&self) -> Call {
        self.backtrace
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }

    /// Exact complete four-frame reference trace. `entry` must be captured
    /// before the real C target CALL and joined to its authenticated next_ip;
    /// none of these inputs may be copied from the unwind trace being checked.
    pub fn reference_frames(
        &self,
        bias: u64,
        entry: Entry,
        nonce: u64,
    ) -> Result<[observations::Frame; 4]> {
        entry.check()?;
        let reference_rsp = add(entry.pre_call_rsp, -8)?;
        let wrapper_rsp = add(reference_rsp, self.reference_to_original.rsp_delta - 8)?;
        let collect_rsp = add(wrapper_rsp, self.original_to_collect.rsp_delta - 8)?;
        let mut live = entry.callee;
        live[0] = nonce; // independently checked MOV RBX,RDI before reference CALL
        Ok([
            frame(
                biased(bias, self.backtrace.return_pc)?,
                add(collect_rsp, self.backtrace.rsp_delta)?,
                [0; 6],
                0,
            ),
            frame(
                biased(bias, self.original_to_collect.return_pc)?,
                add(collect_rsp, 8)?,
                [0; 6],
                0,
            ),
            frame(
                biased(bias, self.reference_to_original.return_pc)?,
                add(wrapper_rsp, 8)?,
                live,
                2,
            ),
            frame(entry.return_pc, add(reference_rsp, 8)?, entry.callee, 8),
        ])
    }
}

/// Independently measured entry coordinates/values, not unwind observations.
/// `return_pc` is the actual compiled target CALL.next_ip plus caller bias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub pre_call_rsp: u64,
    pub return_pc: u64,
    pub callee: [u64; 6],
}
impl Entry {
    fn check(self) -> Result<()> {
        if self.pre_call_rsp == 0 || self.pre_call_rsp % 16 != 0 || self.return_pc == 0 {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
fn biased(bias: u64, pc: u64) -> Result<u64> {
    bias.checked_add(pc).ok_or(Error::Arithmetic)
}
fn add(base: u64, delta: i64) -> Result<u64> {
    base.checked_add_signed(delta).ok_or(Error::Arithmetic)
}
fn frame(ip: u64, cfa: u64, callee: [u64; 6], owned: u32) -> observations::Frame {
    observations::Frame {
        ip,
        cfa,
        callee,
        before_instruction: 0,
        owned,
    }
}
fn rel_call(bytes: &[u8], address: u64, expected: u64) -> Result<()> {
    let i = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE).decode();
    if i.code() != Code::Call_rel32_64
        || i.len() != bytes.len()
        || i.near_branch_target() != expected
    {
        return Err(Error::Shape);
    }
    Ok(())
}
fn wrapper(function: &Function<'_>, target: u64, original: bool) -> Result<()> {
    let prefix: &[u8] = if original {
        &[0x48, 0x83, 0xec, 8, 0x31, 0xff]
    } else {
        &[0x48, 0x83, 0xec, 8]
    };
    let n = prefix.len();
    if function.bytes.len() != n + 10
        || &function.bytes[..n] != prefix
        || function.bytes[n + 5..] != [0x48, 0x83, 0xc4, 8, 0xc3]
    {
        return Err(Error::Shape);
    }
    rel_call(
        &function.bytes[n..n + 5],
        function
            .address
            .checked_add(n as u64)
            .ok_or(Error::Arithmetic)?,
        target,
    )
}
fn reference_shape(function: &Function<'_>, target: u64) -> Result<()> {
    if function.bytes.len() != 24
        || function.bytes[..4] != [0x53, 0x48, 0x89, 0xfb]
        || function.bytes[9..]
            != [
                0x48, 0xb8, 0x43, 0x4e, 0x45, 0x52, 0x45, 0x46, 0x45, 0x52, 0x48, 0x31, 0xd8, 0x5b,
                0xc3,
            ]
    {
        return Err(Error::Shape);
    }
    rel_call(
        &function.bytes[4..9],
        function.address.checked_add(4).ok_or(Error::Arithmetic)?,
        target,
    )
}

/// The pinned GNU _Unwind_Backtrace returns _URC_FATAL_PHASE1_ERROR when this
/// fixture's callback deliberately returns _URC_NORMAL_STOP at the caller.
pub const BACKTRACE_STOP_RESULT: i32 = 3;

#[derive(Clone, Debug)]
pub struct Generated {
    selected: u64,
    return_pc: u64,
    subject: Subject,
    prefix: u64,
    alignment: u64,
    state_bytes: u64,
    state_mask: u64,
    state_format: u64,
}
pub struct GeneratedExpectation {
    pub frames: [observations::Frame; 4],
    pub context: observations::ContextExpectation,
}
impl Generated {
    /// Consume the core's opaque exact-image trace/CFI binding. This does not
    /// recreate or bypass its general verifier or unsafe source/hook authority.
    /// Check only the fixture-specific live registers, stack alignment, and
    /// exact expression row required for this one generated observer CALL.
    pub fn prove(candidate: &prepare::Candidate, subject: &Subject) -> Result<Self> {
        let trace = candidate.trace.trace();
        if !candidate.records.matches_trace(&candidate.trace)
            || trace.origin() != FrameEntryOrigin::ApplicationStack
            || trace.observation_stack_profile() != ObservationStackProfile::Legacy128
            || trace.calls().len() != 1
        {
            return Err(Error::Shape);
        }
        let call = trace.calls()[0];
        if call.kind() != FrameCallKind::Observer
            || candidate.trace.symbolic_hook().address != Some(subject.hook.function.start)
        {
            return Err(Error::Call);
        }
        let row = trace
            .instructions()
            .iter()
            .find(|r| r.start() == call.call_pc() && r.end() == call.return_pc())
            .ok_or(Error::Call)?;
        let FrameInstructionKind::Helper(helper) = row.kind() else {
            return Err(Error::Shape);
        };
        let instruction = helper.instruction();
        if instruction.code() != Code::Call_rel32_64
            || instruction.near_branch_target() != subject.hook.function.start
            || instruction.ip() != call.call_pc()
            || instruction.next_ip() != call.return_pc()
        {
            return Err(Error::Call);
        }
        let prefix = trace
            .observation_stack_profile()
            .context_stack_prefix_bytes() as u64;
        if prefix != 304 || helper.before().original_rsp_rule() != (Register::R12, 304) {
            return Err(Error::Shape);
        }
        let locations: [i32; 6] = [104, 96, 40, 32, 24, 16];
        for (register, offset) in SIX.into_iter().zip(locations) {
            if helper.before().original_register(register)
                != Some(OriginalRegisterLocation::Stack(offset - 304))
            {
                return Err(Error::Shape);
            }
        }
        let alignment = candidate
            .target_state
            .format()
            .required_alignment()
            .ok_or(Error::Shape)?;
        let state_bytes = candidate.target_state.len();
        if !matches!(alignment, 16 | 64)
            || state_bytes == 0
            || state_bytes > MAX_STACK as u64
            || state_bytes % alignment != 0
        {
            return Err(Error::Shape);
        }
        // The existing typed core trace binds every instruction to actual
        // image bytes. The only six-register write before CALL must be its
        // context anchor. After that anchor, exact AND/SUB implement X.
        let mut anchored = false;
        let mut rsp_ops = Vec::new();
        for row in trace
            .instructions()
            .iter()
            .take_while(|r| r.start() < call.call_pc())
        {
            let FrameInstructionKind::Helper(h) = row.kind() else {
                return Err(Error::Shape);
            };
            let i = h.instruction();
            let mut factory = InstructionInfoFactory::new();
            for used in factory.info(i).used_registers() {
                if !writes(used.access()) {
                    continue;
                }
                if register_column(used.register()).is_some() {
                    if anchored
                        || i.mnemonic() != Mnemonic::Mov
                        || i.op0_kind() != OpKind::Register
                        || i.op0_register() != Register::R12
                        || i.op1_kind() != OpKind::Register
                        || i.op1_register() != Register::RSP
                    {
                        return Err(Error::Recovery);
                    }
                    anchored = true;
                }
                if anchored && used.register().full_register() == Register::RSP {
                    rsp_ops.push(*i);
                }
            }
        }
        if !anchored
            || rsp_ops.len() != 2
            || rsp_ops[0].mnemonic() != Mnemonic::And
            || rsp_ops[1].mnemonic() != Mnemonic::Sub
            || rsp_ops
                .iter()
                .any(|i| i.op0_kind() != OpKind::Register || i.op0_register() != Register::RSP)
            || immediate(&rsp_ops[0])? != -(alignment as i64)
            || immediate(&rsp_ops[1])? != state_bytes as i64
        {
            return Err(Error::Stack);
        }
        let program = generated_call_program();
        generated_rows(candidate, call.call_pc(), call.return_pc(), &program)?;
        Ok(Self {
            selected: call.original_pc(),
            return_pc: call.return_pc(),
            subject: subject.clone(),
            prefix,
            alignment,
            state_bytes,
            state_mask: candidate.target_state.mask(),
            state_format: candidate.target_state.format().raw(),
        })
    }

    pub fn frames(
        &self,
        subject: &Subject,
        bias: u64,
        entry: Entry,
    ) -> Result<GeneratedExpectation> {
        entry.check()?;
        if subject != &self.subject {
            return Err(Error::Shape);
        }
        let application_rsp = add(entry.pre_call_rsp, -8)?;
        let context = application_rsp
            .checked_sub(self.prefix)
            .ok_or(Error::Arithmetic)?;
        // Actual emitter: AND RSP,-alignment; SUB RSP,state_bytes.
        let xstate = (context & !(self.alignment - 1))
            .checked_sub(self.state_bytes)
            .ok_or(Error::Arithmetic)?;
        let hook_rsp = add(xstate, -8)?;
        let collect_rsp = add(hook_rsp, subject.hook_to_collect.rsp_delta - 8)?;
        let mut live = entry.callee;
        live[2] = context;
        Ok(GeneratedExpectation {
            frames: [
                frame(
                    biased(bias, subject.backtrace.return_pc)?,
                    add(collect_rsp, subject.backtrace.rsp_delta)?,
                    [0; 6],
                    0,
                ),
                frame(
                    biased(bias, subject.hook_to_collect.return_pc)?,
                    add(collect_rsp, 8)?,
                    [0; 6],
                    0,
                ),
                frame(biased(bias, self.return_pc)?, add(hook_rsp, 8)?, live, 4),
                frame(entry.return_pc, add(application_rsp, 8)?, entry.callee, 8),
            ],
            context: observations::ContextExpectation::Generated {
                address: usize::try_from(context).map_err(|_| Error::Arithmetic)?,
                selected: biased(bias, self.selected)?,
                xstate: [xstate, self.state_bytes, self.state_mask, self.state_format],
            },
        })
    }
}

fn sleb(mut value: i64, out: &mut Vec<u8>) {
    loop {
        let byte = (value as u8) & 0x7f;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        out.push(byte | if done { 0 } else { 0x80 });
        if done {
            break;
        }
    }
}
fn generated_call_program() -> Vec<u8> {
    // Independent layout: original RSP = R12+304; caller CFA adds8.
    // Saved six slots are context+[104,96,40,32,24,16]; RA stays CFA-8.
    let mut cfa = vec![0x7c];
    sleb(304, &mut cfa);
    cfa.extend_from_slice(&[0x11, 8, 0x22]);
    let mut out = vec![0x0f, cfa.len() as u8];
    out.extend(cfa);
    for (column, offset) in [3, 6, 12, 13, 14, 15]
        .into_iter()
        .zip([104, 96, 40, 32, 24, 16])
    {
        let mut location = vec![0x7c];
        sleb(offset, &mut location);
        out.extend_from_slice(&[0x10, column, location.len() as u8]);
        out.extend(location);
    }
    out.extend_from_slice(&[0x11, 16, 1]);
    out
}

struct Bytes<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Arithmetic)?;
        let b = self.bytes.get(self.at..end).ok_or(Error::Cfi)?;
        self.at = end;
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Cfi)?,
        ))
    }
    fn block(&mut self) -> Result<()> {
        // Every expression emitted for this finite fixture fits one byte.
        let n = usize::from(self.byte()?);
        if n == 0 || n > 48 {
            return Err(Error::Cfi);
        }
        self.take(n)?;
        Ok(())
    }
    fn signed(&mut self) -> Result<()> {
        // Full operands are consumed even for nonselected rows. Semantics of
        // those rows remain bound to PreparedArtifactUnwind's core contract.
        for n in 0..10 {
            let b = self.byte()?;
            if b & 0x80 == 0 {
                if n == 9 && b != 0 && b != 0x7f {
                    return Err(Error::Cfi);
                }
                return Ok(());
            }
        }
        Err(Error::Cfi)
    }
}

/// Inspect the complete generated FDE containing CALL and its continuation,
/// keeping the exact typed core image/metadata binding. This is a tiny fixed
/// encoding check, not an expression interpreter or permission to admit an
/// expression in the separate original-CFI parser. Only the selected row and
/// continuation row receive the independent literal layout comparison here.
fn generated_rows(
    candidate: &prepare::Candidate,
    call: u64,
    returned: u64,
    expected: &[u8],
) -> Result<()> {
    let records = &candidate.records;
    let bytes = records.bytes();
    let cie: &[u8] = &[
        16, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0, 0, 0,
    ];
    if bytes.len() > 1024 * 1024 || !bytes.starts_with(cie) {
        return Err(Error::Cfi);
    }
    let found: Vec<_> = records
        .fdes()
        .iter()
        .filter(|&&(start, end, _)| start <= call && returned < end)
        .collect();
    if found.len() != 1 {
        return Err(Error::Cfi);
    }
    let (start, end, offset) = *found[0];
    let required: Vec<_> = candidate
        .trace
        .trace()
        .instructions()
        .iter()
        .filter(|r| start <= r.start() && r.end() <= end)
        .map(|r| r.start())
        .collect();
    generated_row_bytes(
        bytes,
        records.address(),
        (start, end, offset),
        &required,
        call,
        returned,
        expected,
    )
}

fn generated_row_bytes(
    bytes: &[u8],
    address: u64,
    (start, end, offset): (u64, u64, usize),
    required: &[u64],
    call: u64,
    returned: u64,
    expected: &[u8],
) -> Result<()> {
    if start >= end
        || !(start..end).contains(&call)
        || !(start..end).contains(&returned)
        || call >= returned
        || offset < 20
    {
        return Err(Error::Cfi);
    }
    let mut header = Bytes {
        bytes: bytes.get(offset..).ok_or(Error::Cfi)?,
        at: 0,
    };
    let length = usize::try_from(header.word()?).map_err(|_| Error::Bounds)?;
    if length > 64 * 1024
        || header.word()? as usize != offset.checked_add(4).ok_or(Error::Arithmetic)?
    {
        return Err(Error::Cfi);
    }
    let relative = i64::from(header.word()? as i32);
    let field = address
        .checked_add(offset as u64)
        .and_then(|p| p.checked_add(8))
        .ok_or(Error::Arithmetic)?;
    if field.checked_add_signed(relative) != Some(start)
        || u64::try_from(header.word()? as i32).map_err(|_| Error::Cfi)? != end - start
        || header.byte()? != 0
    {
        return Err(Error::Cfi);
    }
    let body_end = offset
        .checked_add(4)
        .and_then(|p| p.checked_add(length))
        .ok_or(Error::Arithmetic)?;
    let begin = offset.checked_add(header.at).ok_or(Error::Arithmetic)?;
    let mut reader = Bytes {
        bytes: bytes.get(begin..body_end).ok_or(Error::Cfi)?,
        at: 0,
    };
    if required.is_empty() || required.len() > MAX_HEADS {
        return Err(Error::Cfi);
    }
    let mut pc = start;
    let mut matched = 0;
    for (index, &wanted) in required.iter().enumerate() {
        if index != 0 {
            if reader.byte()? != 4 {
                return Err(Error::Cfi);
            }
            pc = pc
                .checked_add(u64::from(reader.word()?))
                .ok_or(Error::Arithmetic)?;
        }
        if pc != wanted {
            return Err(Error::Cfi);
        }
        let row_start = reader.at;
        if reader.byte()? != 0x0f {
            return Err(Error::Cfi);
        }
        reader.block()?;
        for column in [3, 6, 12, 13, 14, 15, 16] {
            let op = reader.byte()?;
            if reader.byte()? != column {
                return Err(Error::Cfi);
            }
            match op {
                8 => {}
                0x10 => reader.block()?,
                0x11 => reader.signed()?,
                _ => return Err(Error::Cfi),
            }
        }
        if pc == call || pc == returned {
            if &reader.bytes[row_start..reader.at] != expected {
                return Err(Error::Recovery);
            }
            matched += 1;
        }
    }
    if matched != 2
        || reader.bytes.len() - reader.at > 3
        || reader.bytes[reader.at..].iter().any(|&b| b != 0)
    {
        return Err(Error::Cfi);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Literal machine/metadata bytes from the authenticated closed subject
    // afd3cc12... (not native observations); every instruction path is decoded
    // by the production helper. The test owner below preserves the full stream.
    const METADATA: &str = "1400000000000000017a5200017810011b0c070890010000240000001c00000048efffff90000000000e10460e184a0f
0b770880003f1a3b2a332422000000001c0000004400000070f0ffff39000000004308030806080c080d080e080f0000
1c0000006400000090f0ffff1800000000410e108302560e0800000000000000780000008400000090f0ffffd7010000
00420e108f02420e188e03420e208d04420e288c05410e308606440e388307440e50032c010a0e38410e30410e28420e
20420e18420e10420e08490b570a0e38460e30410e28420e20420e18420e10420e084a0b5d0a0e38410e30410e28420e
20420e18420e10420e08490b5c00000000010000f4f1ffff180500000002420e108f02450e188e03420e208d04420e28
8c05410e308606440e388307440e5002ce0e38410e30410e28420e20420e18420e10420e0844c3c6cccdcecf500e5083
0786068c058d048e038f02004800000060010000b4f6ffff5503000000600e108e02420e188d03420e208c04410e2886
05410e308306760e28410e20420e18420e10420e0845c3c6cccdce500e30830686058c048d038e0210000000ac010000
c8f9ffff0f0000000000000010000000c0010000c4f9ffff670000000000000014000000d401000020faffff10000000
00440e104b0e080014000000ec01000018faffff0e00000000440e10490e0800100000000402000010faffff37000000
0000000014000000180200003cfaffff2200000000440e305d0e080000000000";
    const COLLECT: &str = "8b05722c00008b35642c000083c80285f60f84220100008b055b2c00008b0d592c000083c80485c90f850b0100008b05
402c00003b05fe2c00000f84f000000041578d5001415641554154554889fd534883ec1889151a2c0000488d1440c705
142c000001000000488d1c9031c048c1e30848031db72c0000488d7b084889d948c783f80c0000000000004883e7f848
c703000000004829f981c1000d0000c1e903f348abc783fc0c0000ffffffff4885ed0f8488000000488b05112c000048
3b05122c0000c783f40c0000020000004c8b35092c00000f92c24889ab600c00004885c00f95c04c89b3c80c000084c2
740d4881fd4fffffff0f86e1010000c783f80c000010000000b8100000000905642b0000c7055e2b0000000000004883
c4185b5d415c415d415e415fc30f1f008b05422b000083c8088905392b0000c3488b35992b0000488b159a2b0000c783
f40c0000010000004c8dab600a00004c89ef4889b3c80c0000e842fbffff488b057b2b00008b93f80c0000488b304889
b3d00c00004839356c2b000089d00f851c03000085d275154889de488d3d7efcffffe8d9faffff8983fc0c00004c8b3d
342b00004c8b05252b0000488b0d2e2b00004c8d8b600b00004c89c64c89fa48894c24084c89cfe8d4faffff488b4c24
084c89ef4c89fa4989c1488b014c89ce488983d80c0000e8a4faffff85c00f95c0410f95c50fb6c08983f00c00004885
ed0f84a10000004c8da300090000f30f6f5d00488db3b0090000bab00000004c89e70f119bb0090000f30f6f65100f11
6610f30f6f6d200f116e20f30f6f75300f117630f30f6f7d400f117e40f30f6f45500f114650f30f6f4d600f114e60f3
0f6f55700f115670f30f6f9d800000000f119e80000000f30f6fa5900000000f11a690000000f30f6fada00000000f11
aea0000000e8f6f9ffff85c00f95c00fb6c08983ec0c00008b83f80c00004584ed750e8b93ec0c000085d20f843dfeff
ff83c8408983f80c0000e92ffeffff90488b05a9290000488b15aa2900004885c00f8408feffff4839d00f83fffdffff
4839e80f87f6fdffff488d85b00000004839d00f87e6fdffff4c8b3dc82900004c8dab600a00004c89f64c897424084c
89ef4c8da3000900004c89fae86ff9ffff4c8b0da82900004c8b44240831c0ba68000000488d3d01090000498b314c89
c94889b3d00c0000f30f6f45000f118300090000f30f6f4d10410f114c2410f30f6f5520410f11542420f30f6f5d3041
0f115c2430f30f6f6540410f11642440f30f6f6d50410f116c2450f30f6f7560410f11742460f30f6f7d70410f117c24
70f30f6f8580000000410f11842480000000f30f6f8d90000000410f118c2490000000f30f6f95a0000000410f119424
a00000004c8b93000900004c8b9b080900004c8993680c00004c899b700c0000eb09660f1f4400008b1487498b141448
8994c3780c00004883c0014883f80675e7488b83900900004c3915c12800008b93f80c0000488b3dac280000488983a8
0c0000488b8398090000488983b00c0000488b83a0090000488983b80c0000488b83a8090000488983c00c000075094d
39cb0f84fdfcffff89d083c8108983f80c00004839f7742f83c8208983f80c0000e91cfdffff662e0f1f840000000000
4c8b3d312800004c8b0522280000488b0d2b280000ebd14c8d83600b00004c89fa4c89f64c894c24084c89c7e8cff7ff
ff4c8b4c24084c89ef4c89fa4989c0498b014c89c6488983d80c0000e89ff7ffff85c00f95c0410f95c50fb6c08983f0
0c0000e906fdffff";
    const ORIGINAL: &str = "4883ec0831ffe8f5f6ffff4883c408c3";
    const HOOK: &str = "4883ec08e8e7f6ffff4883c408c3";
    const REFERENCE: &str = "534889fbe8f70a000048b8434e4552454645524831d85bc3";
    fn hex(input: &str) -> Vec<u8> {
        let text: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(text.len() % 2, 0);
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    struct Owned {
        address: u64,
        code: Vec<u8>,
        record: OriginalArtifactCfi,
        metadata: Vec<u8>,
    }
    impl Owned {
        fn function(&self) -> Function<'_> {
            Function {
                address: self.address,
                bytes: &self.code,
                record: &self.record,
                metadata: cfi::Metadata {
                    address: 0x20b8,
                    bytes: &self.metadata,
                },
            }
        }
        fn refresh_record(&mut self) {
            self.metadata[..self.record.cie.len()].copy_from_slice(&self.record.cie);
            let offset = (self.record.fde_address - 0x20b8) as usize;
            self.metadata[offset..offset + self.record.fde.len()].copy_from_slice(&self.record.fde);
        }
    }
    fn owned(code: &str, address: u64, fde: u64) -> Owned {
        let metadata = hex(METADATA);
        let offset = (fde - 0x20b8) as usize;
        let n = u32::from_le_bytes(metadata[offset..offset + 4].try_into().unwrap()) as usize + 4;
        Owned {
            address,
            code: hex(code),
            record: OriginalArtifactCfi {
                cie_address: 0x20b8,
                cie: metadata[..24].to_vec(),
                fde_address: fde,
                fde: metadata[offset..offset + n].to_vec(),
            },
            metadata,
        }
    }
    fn subject() -> Subject {
        let collect = owned(COLLECT, 0x13b0, 0x21b4);
        let original = owned(ORIGINAL, 0x1cb0, 0x2288);
        let hook = owned(HOOK, 0x1cc0, 0x22a0);
        let reference = owned(REFERENCE, 0x11b0, 0x2118);
        Subject::prove(
            collect.function(),
            original.function(),
            hook.function(),
            reference.function(),
            0x1030,
        )
        .unwrap()
    }
    fn entry() -> Entry {
        Entry {
            pre_call_rsp: 0x10000,
            return_pc: 0x9000,
            callee: [11, 22, 33, 44, 55, 66],
        }
    }

    #[test]
    fn compiled_collector_all_paths_join_exact_stack_cfi_and_call_dependencies() {
        let source = owned(COLLECT, 0x13b0, 0x21b4);
        let p = prove_function(source.function()).unwrap();
        assert_eq!(p.function(), 0x13b0..0x18c8);
        assert_eq!(p.code_identity(), ContentId::of(&hex(COLLECT)));
        assert_eq!(p.calls().len(), 8);
        assert_eq!(
            p.unique_call(0x1030).unwrap(),
            Call {
                address: 0x1552,
                return_pc: 0x1557,
                target: 0x1030,
                rsp_delta: -72
            }
        );
        assert!(p.calls().iter().all(|c| c.rsp_delta == -72));
        assert!(p.external_writes().iter().any(|w| w.instruction == 0x1452));
        assert!(p.external_writes().iter().all(|w| w.base != Register::RSP));
        assert!(!p.qualification_complete());
    }

    #[test]
    fn full_reference_chain_uses_entry_coordinates_and_nonce_not_trace_fields() {
        let p = subject();
        let frames = p.reference_frames(0x100000, entry(), 77).unwrap();
        assert_eq!(
            frames,
            [
                frame(0x101557, 0xff90, [0; 6], 0),
                frame(0x101cbb, 0xffe0, [0; 6], 0),
                frame(0x1011b9, 0xfff0, [77, 22, 33, 44, 55, 66], 2),
                frame(0x9000, 0x10000, [11, 22, 33, 44, 55, 66], 8),
            ]
        );
        assert_eq!(BACKTRACE_STOP_RESULT, 3);
        assert!(!p.qualification_complete());
        let mut bad = entry();
        bad.pre_call_rsp += 8;
        assert_eq!(p.reference_frames(0, bad, 77), Err(Error::Shape));
        assert_eq!(
            p.reference_frames(u64::MAX, entry(), 77),
            Err(Error::Arithmetic)
        );
    }

    #[test]
    fn compiler_stack_or_saved_word_changes_cannot_preserve_admission() {
        let mut missing = owned(COLLECT, 0x13b0, 0x21b4);
        missing.code[0x13f0 - 0x13b0..0x13f2 - 0x13b0].copy_from_slice(&[0x66, 0x90]);
        assert!(prove_function(missing.function()).is_err());
        let mut overwrite = owned(COLLECT, 0x13b0, 0x21b4);
        assert_eq!(overwrite.code[0x1583 - 0x13b0], 8);
        overwrite.code[0x1583 - 0x13b0] = 24; // local scratch now aliases saved RBX
        assert_eq!(
            prove_function(overwrite.function()).err(),
            Some(Error::Stack)
        );
        let mut changed = owned(COLLECT, 0x13b0, 0x21b4);
        let at = changed
            .record
            .fde
            .windows(3)
            .position(|b| b == [0x44, 0x0e, 0x50])
            .unwrap()
            + 2;
        changed.record.fde[at] = 0x58;
        changed.refresh_record();
        assert!(prove_function(changed.function()).is_err());
        let mut wrapper = owned(HOOK, 0x1cc0, 0x22a0);
        wrapper.code[3] = 16;
        assert!(prove_function(wrapper.function()).is_err());
    }

    #[test]
    fn explicit_undefined_nondefault_restore_and_mid_instruction_cfi_refuse() {
        let mut input = owned(REFERENCE, 0x11b0, 0x2118);
        // Change unused padding into an explicit undefined after the last row.
        let n = input.record.fde.len();
        input.record.fde[n - 2..].copy_from_slice(&[7, 3]);
        input.refresh_record();
        assert_eq!(
            prove_function(input.function()).err(),
            Some(Error::Undefined)
        );
        let mut input = owned(COLLECT, 0x13b0, 0x21b4);
        // The last two canonical CIE padding bytes now give RBX a nondefault
        // baseline. Existing primary restore RBX must refuse GNU equivalence.
        input.record.cie[22..24].copy_from_slice(&[0x83, 1]);
        input.refresh_record();
        assert_eq!(
            prove_function(input.function()).err(),
            Some(Error::ConsumerRestore)
        );
        let mut input = owned(COLLECT, 0x13b0, 0x21b4);
        assert_eq!(input.record.fde[18], 0x42);
        input.record.fde[18] = 0x41;
        input.refresh_record();
        assert_eq!(prove_function(input.function()).err(), Some(Error::Cfi));
        let mut input = owned(COLLECT, 0x13b0, 0x21b4);
        *input.record.fde.last_mut().unwrap() = 0x0f;
        input.refresh_record();
        assert_eq!(prove_function(input.function()).err(), Some(Error::Cfi));
    }

    #[test]
    fn repeated_walk_wrong_targets_and_wrapper_register_changes_refuse() {
        let mut input = owned(COLLECT, 0x13b0, 0x21b4);
        input.code[0x1557 - 0x13b0..0x155d - 0x13b0]
            .copy_from_slice(&[0xe9, 0xf6, 0xff, 0xff, 0xff, 0x90]);
        let p = prove_function(input.function()).unwrap();
        assert_eq!(p.unique_call(0x1030), Err(Error::Call));
        assert_eq!(p.unique_call(0x1050), Err(Error::Call));
        let mut original = owned(ORIGINAL, 0x1cb0, 0x2288);
        original.code[4..6].copy_from_slice(&[0x31, 0xdb]);
        assert_eq!(
            wrapper(&original.function(), 0x13b0, true),
            Err(Error::Shape)
        );
        let reference = owned(REFERENCE, 0x11b0, 0x2118);
        assert_eq!(
            reference_shape(&reference.function(), 0x1cc0),
            Err(Error::Shape)
        );
    }

    fn generated_bytes(program: &[u8]) -> Vec<u8> {
        let mut out = vec![
            16, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0, 0, 0,
        ];
        let mut body = 24_u32.to_le_bytes().to_vec();
        body.extend_from_slice(&(-0x101c_i32).to_le_bytes()); // field0x201c -> start0x1000
        body.extend_from_slice(&6_u32.to_le_bytes());
        body.push(0);
        body.extend(program);
        body.push(4);
        body.extend_from_slice(&5_u32.to_le_bytes());
        body.extend(program);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend(body);
        out.extend([0; 4]);
        out
    }
    #[test]
    fn exact_generated_expression_row_and_complete_tail_are_checked() {
        let program = generated_call_program();
        assert_eq!(
            program,
            hex(
                "0f067cb0021108221003037ce8001006037ce000100c027c28100d027c20100e027c18100f027c10111001"
            )
        );
        let good = generated_bytes(&program);
        let read = |b: &[u8]| {
            generated_row_bytes(
                b,
                0x2000,
                (0x1000, 0x1006, 20),
                &[0x1000, 0x1005],
                0x1000,
                0x1005,
                &program,
            )
        };
        assert_eq!(read(&good), Ok(()));
        let mut wrong = program.clone();
        wrong[4] ^= 1;
        assert_eq!(read(&generated_bytes(&wrong)), Err(Error::Recovery));
        let mut extra = good.clone();
        let end = 24 + u32::from_le_bytes(extra[20..24].try_into().unwrap()) as usize;
        extra[end - 1] = 0xff;
        assert_eq!(read(&extra), Err(Error::Cfi));
        let mut pointer = good.clone();
        pointer[24] ^= 1;
        assert_eq!(read(&pointer), Err(Error::Cfi));
    }

    #[test]
    fn generated_frame_arithmetic_uses_exact_alignment_and_bound_subject() {
        let p = subject();
        // A synthetic layout for arithmetic only, not a manufactured core
        // ArtifactFrameTrace or permission to execute generated code.
        let g = Generated {
            selected: 0x1173,
            return_pc: 0x5000,
            subject: p.clone(),
            prefix: 304,
            alignment: 64,
            state_bytes: 512,
            state_mask: 7,
            state_format: 2,
        };
        let expected = g.frames(&p, 0x100000, entry()).unwrap();
        assert_eq!(
            expected.frames,
            [
                frame(0x101557, 0xfc60, [0; 6], 0),
                frame(0x101cc9, 0xfcb0, [0; 6], 0),
                frame(0x105000, 0xfcc0, [11, 22, 0xfec8, 44, 55, 66], 4),
                frame(0x9000, 0x10000, [11, 22, 33, 44, 55, 66], 8)
            ]
        );
        match expected.context {
            observations::ContextExpectation::Generated {
                address,
                selected,
                xstate,
            } => {
                assert_eq!(address, 0xfec8);
                assert_eq!(selected, 0x101173);
                assert_eq!(xstate, [0xfcc0, 512, 7, 2]);
            }
            _ => panic!("generated context"),
        }
        let mut wrong = p.clone();
        wrong.hook_to_collect.return_pc += 1;
        assert!(matches!(g.frames(&wrong, 0, entry()), Err(Error::Shape)));
        let mut low = entry();
        low.pre_call_rsp = 16;
        assert!(matches!(g.frames(&p, 0, low), Err(Error::Arithmetic)));
    }

    // Independently retained original code/CFI from closed caller ELF
    // f9cc81653396f83b3f20fa6edcc5dcadc5ad87142f29d6dffb0fb40b67f3f60c.
    // These controls never load/execute its instructions or derive values from
    // an unwind Trace. The complete original metadata stream remains present.
    const CALLER_METADATA: &str = concat!(
        "1400000000000000017a5200017810011b0c070890010000240000001c000000b8efffff20000000000e10460e184a0f",
        "0b770880003f1a3b2a332422000000001c0000004400000070f0ffff6b00000000410e108302025a0a0e08450b4a0e08",
        "4000000064000000c0f0ffffcc00000000410e108602410e188303470e20027a0a0e18430e10410e08490b4d0a0e1841",
        "0e10410e08410b550a0e18410e10410e08490b0028000000a80000004cf1ffffb900000000410e108602440e18830347",
        "0e20025a0a0e18410e10410e08480b0010000000d4000000e0f1ffffc90000000000000048000000e80000009cf2ffff",
        "ba03000000420e108f02420e188e03420e208d04420e288c05410e308606410e388307470ed00202610a0e38410e3041",
        "0e28420e20420e18420e10420e08440b480000003401000010f6ffffaf03000000420e108f02420e188e03420e208d04",
        "420e288c05410e308606410e388307470ec00202570a0e38410e30410e28420e20420e18420e10420e08460b00000000",
    );
    const CALLER_WORK: &str = concat!(
        "415741564155415455534881ec180100004889142448894c24084c894424104d85c974454989fab92b00000031c04c89",
        "cff348ab41c7813c010000010000004885f6743c48833c2400743548897424284c89d74c89ce4c894c24204c89542418",
        "e8cbfcffff85c0752731c04881c4180100005b5d415c415d415e415fc30f1f0041c781400100000100000031c0ebdc90",
        "48b888776655443322114c8b4c24204c8b542418488944243048b81122334455667788488944243848b8696996965a5a",
        "c3c3488944244048b8f0debc9a78563412488944244848b81032547698badcfe4889442450488b442430498981900000",
        "00488b44243849898198000000488b442440498981d0000000488b442448498981a0000000488b442450498981a80000",
        "00f3410f6f0af3410f6f5210f3410f6f5a20f3410f6f6230f3410f6f6a400f294c2460f3410f6f7250f3410f6f7a600f",
        "29542470f3410f6f42700f299c24800000000f29a424900000000f29ac24a00000000f29b424b00000000f29bc24c000",
        "00000f298424d0000000f3410f6f8a80000000f3410f6f9290000000f3410f6f9aa00000000f298c24e00000000f2994",
        "24f00000000f299c24000100004889e0498901488d7424604c89ca4c89d74c894c24204c89542418e8c3fbffff85c00f",
        "8484feffff4889e04c8b4c24204c8b5424184c8b5c2428493b0149894108742041838940010000084c89ce4c89d7e85d",
        "fcffffe951feffff0f1f840000000000418b894001000085c975dd48bbe1ac6824df9b571348bddf9b5713e1ac682449",
        "bc939758532659413149bd459045281828182749be9911ee77cc33aa5549bf119977ee33cc55aa49895930498969384d",
        "8961404d8969484d8971504d8979584889e049894110493b010f8571ffffff660fefc04c89542420488b542410488d4c",
        "24400f2905e7290000488b742408488b3c240f2905e729000041c78148010000010000000f2905e52900004c894c2418",
        "0f2905e929000041ffd34889e2488905ac290000488925ad29000048891dae29000048892daf2900004c8925b0290000",
        "4c892db12900004c8935b22900004c893db32900004c8b4c241849895118498981e0000000488b4424304c89cf4c89ce",
        "49895960498981b0000000488b44243849896968498981b8000000488b4424404d896170498981d8000000488b442448",
        "4d896978498981c0000000488b4424504d89b180000000498981c80000004d89b98800000041c7814c01000001000000",
        "e89bfbffff488b7c24204c890c24e8cdfaffff4c8b0c2431c0418b914001000085d20f94c0e9b1fcffff",
    );
    const CALLER_REFERENCE: &str = concat!(
        "415741564155415455534881ec08010000488914244885c974454989c84989f9b92b00000031c04c89c7f348ab41c780",
        "3c010000020000004885f60f84bf01000048897424184c89cf4c89c64c894424104c894c2408e815f9ffff85c0751931",
        "c04881c4080100005b5d415c415d415e415fc30f1f44000048b888776655443322114c8b4424104c8b4c240848894424",
        "2048b81122334455667788488944242848b8696996965a5ac3c3488944243048b8f0debc9a78563412488944243848b8",
        "1032547698badcfe4889442440488b44242049898090000000488b44242849898098000000488b442430498980d00000",
        "00488b442438498980a0000000488b442440498980a8000000f3410f6f09f3410f6f5110f3410f6f5920f3410f6f6130",
        "f3410f6f69400f294c2450f3410f6f7150f3410f6f79600f29542460f3410f6f41700f295c24700f29a424800000000f",
        "29ac24900000000f29b424a00000000f29bc24b00000000f298424c0000000f3410f6f8980000000f3410f6f91900000",
        "00f3410f6f99a00000000f298c24d00000000f299424e00000000f299c24f00000004889e0498900488d7424504c89c2",
        "4c89cf4c894424104c894c2408e81ef8ffff85c00f8495feffff4889e04c8b4424104c8b4c24084c8b542418493b0049",
        "894008742b41838840010000084c89c64c89cfe8b8f8ffffe962feffff0f1f0041c7804001000001000000e951feffff",
        "418b884001000085c975d248bbe1ac6824df9b571348bddf9b5713e1ac682449bc939758532659413149bd4590452818",
        "28182749be9911ee77cc33aa5549bf119977ee33cc55aa49895830498968384d8960404d8968484d8970504d89785848",
        "89e049894010493b000f8566ffffff660fefc04c894c2410488b3c240f2905fd25000041c78048010000010000000f29",
        "05fb2500004c894424080f2905ff2500000f29050826000041ffd24889e2488905cb250000488925cc25000048891dcd",
        "25000048892dce2500004c8925cf2500004c892dd02500004c8935d12500004c893dd22500004c8b4424084989501849",
        "8980e0000000488b4424204c89c749895860498980b0000000488b442428488b74243049896868498980b8000000488b",
        "4424384d896070498980c0000000488b4424404d8968784d89b0800000004d89b88800000041c7804c01000001000000",
        "4989b0d8000000498980c8000000e8fdf7ffff4939b0d00000004c8b4c2410740841838840010000204c89c64c89cf4c",
        "890424e818f7ffff4c8b042431c0418b904001000085d20f94c0e9b2fcffff",
    );
    const CALLER_COMPARE: &str = concat!(
        "48b8df9b5713e1ac682448bae1ac6824df9b571348894424d048b8939758532659413148894424d848b8459045281828",
        "182748894424e048b89911ee77cc33aa5548894424e848b8119977ee33cc55aa48894424f031c0eb1d0f1f8000000000",
        "4883c001838f40010000104883f806741f488b54c4c8483954c73075e3483954c76075dc4883c0014883f80675e36690",
        "488d8790000000488d97b0000000488b48204839087407838f40010000204883c0084839d075e7488b47104839471874",
        "07838f4001000008c3",
    );

    struct CallerFixture {
        code: Vec<u8>,
        metadata: Vec<u8>,
        record: OriginalArtifactCfi,
        graph: caller::Proof,
        data: caller_dataflow::Dataflow,
        tail: caller_dataflow::TailProof,
    }
    impl CallerFixture {
        fn function(&self) -> Function<'_> {
            Function {
                address: self.graph.base(),
                bytes: &self.code,
                record: &self.record,
                metadata: cfi::Metadata {
                    address: 0x2048,
                    bytes: &self.metadata,
                },
            }
        }
        fn prove(&self) -> Result<ConditionalCallerCfi> {
            prove_conditional_caller(self.function(), &self.graph, &self.data, &self.tail)
        }
    }
    fn compiled_caller(kind: caller_dataflow::Kind) -> CallerFixture {
        use caller_dataflow::Kind;
        let (code, base, fde, labels, raw) = match kind {
            Kind::Work => (
                hex(CALLER_WORK),
                0x13d0,
                228,
                caller::Labels {
                    sample: 0x158d,
                    configured: 0x15b5,
                    canary_before: 0x1637,
                    pre: 0x164f,
                    post: 0x16aa,
                    canary_after: 0x16ee,
                },
                0x4060,
            ),
            Kind::Reference => (
                hex(CALLER_REFERENCE),
                0x1790,
                304,
                caller::Labels {
                    sample: 0x1932,
                    configured: 0x195a,
                    canary_before: 0x19e7,
                    pre: 0x19ff,
                    post: 0x1a4b,
                    canary_after: 0x1a8f,
                },
                0x4020,
            ),
        };
        let metadata = hex(CALLER_METADATA);
        let size = u32::from_le_bytes(metadata[fde..fde + 4].try_into().unwrap()) as usize + 4;
        let record = OriginalArtifactCfi {
            cie_address: 0x2048,
            cie: metadata[..24].to_vec(),
            fde_address: 0x2048 + fde as u64,
            fde: metadata[fde..fde + size].to_vec(),
        };
        let graph = caller::prove(&code, base, labels).unwrap();
        let data = caller_dataflow::prove(
            &code,
            &graph,
            kind,
            Some(caller_dataflow::RawCapture { address: raw }),
        )
        .unwrap();
        let compare = caller_dataflow::compare_effects(&hex(CALLER_COMPARE), 0x1300).unwrap();
        let tail = data.prove_tail(&code, &compare).unwrap();
        CallerFixture {
            code,
            metadata,
            record,
            graph,
            data,
            tail,
        }
    }
    #[test]
    fn conditional_caller_checks_full_compiled_cfi_without_broadening_subject_calls() {
        for kind in [
            caller_dataflow::Kind::Work,
            caller_dataflow::Kind::Reference,
        ] {
            let f = compiled_caller(kind);
            assert_eq!(prove_function(f.function()).unwrap_err(), Error::Flow);
            let conditional = f.prove().unwrap();
            assert_eq!(conditional.code_identity(), ContentId::of(&f.code));
            assert_eq!(conditional.cie_identity(), ContentId::of(&f.record.cie));
            assert_eq!(conditional.fde_identity(), ContentId::of(&f.record.fde));
            assert_eq!(conditional.target_call(), f.graph.target_call());
            assert_eq!(
                conditional.pre_call_frame_offset(),
                f.data.pre_call_frame_offset()
            );
            assert_eq!(conditional.raw_capture(), f.data.raw_capture().unwrap());
            assert_eq!(
                conditional.support_calls_requiring_preservation().len() + 1,
                f.graph.calls().len()
            );
            assert!(conditional.reachable_heads() > 100);
            assert!(!conditional.external_writes().is_empty());
            assert!(!conditional.qualification_complete());
        }
    }
    #[test]
    fn conditional_caller_refuses_mixed_code_graph_dataflow_and_tail_identities() {
        let work = compiled_caller(caller_dataflow::Kind::Work);
        let reference = compiled_caller(caller_dataflow::Kind::Reference);
        assert_eq!(
            prove_conditional_caller(work.function(), &reference.graph, &work.data, &work.tail)
                .unwrap_err(),
            Error::Shape
        );
        assert_eq!(
            prove_conditional_caller(work.function(), &work.graph, &reference.data, &work.tail)
                .unwrap_err(),
            Error::Shape
        );
        assert_eq!(
            prove_conditional_caller(work.function(), &work.graph, &work.data, &reference.tail)
                .unwrap_err(),
            Error::Shape
        );
        let mut changed = work.code.clone();
        changed[0] ^= 1;
        let mut input = work.function();
        input.bytes = &changed;
        assert_eq!(
            prove_conditional_caller(input, &work.graph, &work.data, &work.tail).unwrap_err(),
            Error::Shape
        );
        let mut input = work.function();
        input.address += 0x1000;
        assert_eq!(
            prove_conditional_caller(input, &work.graph, &work.data, &work.tail).unwrap_err(),
            Error::Shape
        );
    }
    #[test]
    fn conditional_caller_retains_complete_cfi_and_explicit_undefined_refusal() {
        let mut f = compiled_caller(caller_dataflow::Kind::Work);
        // Replace a complete original CIE padding pair with DW_CFA_undefined rbx.
        assert_eq!(&f.record.cie[22..24], &[0, 0]);
        f.record.cie[22..24].copy_from_slice(&[7, 3]);
        f.metadata[..24].copy_from_slice(&f.record.cie);
        assert_eq!(f.prove().unwrap_err(), Error::Undefined);
        let mut f = compiled_caller(caller_dataflow::Kind::Reference);
        // Every original FDE byte is still parsed after the tested target.
        let n = f.record.fde.len();
        assert_eq!(f.record.fde[n - 1], 0x0b);
        f.record.fde[n - 1] = 0xff;
        let offset = (f.record.fde_address - 0x2048) as usize;
        f.metadata[offset..offset + n].copy_from_slice(&f.record.fde);
        assert!(f.prove().is_err());
    }
    #[test]
    fn conditional_caller_requires_actual_bound_raw_rsp_and_every_six_register_value() {
        for kind in [
            caller_dataflow::Kind::Work,
            caller_dataflow::Kind::Reference,
        ] {
            let f = compiled_caller(kind);
            let p = f.prove().unwrap();
            let bias = 0x100000;
            let o = observations::CallerObservation {
                rsp_sample: 0x8000,
                rsp_configured: 0x8000,
                rsp_pre: 0x8000,
                rsp_post: 0x8000,
                caller_return_slot: 0x7ff8,
                caller_return: (bias + p.target_call().return_pc) as usize,
                kind: if kind == caller_dataflow::Kind::Work {
                    1
                } else {
                    2
                },
                invocation_dispatched: 1,
                normal_returned: 1,
                callee_before: observations::CANARIES,
                callee_after: observations::CANARIES,
                ..observations::CallerObservation::default()
            };
            let raw = observations::RawReturn {
                result: 0,
                rsp: 0x8000,
                callee: observations::CANARIES,
            };
            p.check_return(bias, &o, &raw).unwrap();
            assert_eq!(p.check_return(bias + 1, &o, &raw), Err(Error::Call));
            let mut bad = raw;
            bad.rsp += 8;
            assert_eq!(p.check_return(bias, &o, &bad), Err(Error::Stack));
            for i in 0..6 {
                let mut bad = raw;
                bad.callee[i] ^= 1;
                assert_eq!(p.check_return(bias, &o, &bad), Err(Error::Recovery));
            }
            let mut bad = o.clone();
            bad.normal_returned = 0;
            assert_eq!(p.check_return(bias, &bad, &raw), Err(Error::Call));
            let mut bad = o.clone();
            bad.rsp_configured += 16;
            assert_eq!(p.check_return(bias, &bad, &raw), Err(Error::Stack));
            let mut bad = o.clone();
            bad.callee_before[3] ^= 1;
            assert_eq!(p.check_return(bias, &bad, &raw), Err(Error::Recovery));
        }
    }
}
