//! Producer-recorded frame transitions, without CFI or unwind admission.
//!
//! These records describe emitted instructions and temporary instrumentation
//! storage. They do not establish original CFI validity at a new hook point,
//! register an FDE, or authorize exception propagation or asynchronous unwinding.

use crate::trampoline::{ObservationStackProfile, TrampolineImage};
use iced_x86::{BlockEncoderResult, Instruction, Register};

/// Stack origin selected by the emitter constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameEntryOrigin {
    /// The trampoline entered with the application's architectural RSP.
    ApplicationStack,
    /// A ptrace controller supplied an independent owned stack and saved RSP.
    ControllerOwnedStack,
}

/// Additional metadata refusal; it never replaces ordinary emission success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameTraceRefusal {
    /// This stack origin has no modeled original-stack recovery yet.
    UnsupportedEntryOrigin,
    /// Replacement semantics need an additional frame-state contract.
    ReplacementRequiresFrameContract,
    /// Exact-syscall replacement has not been qualified for frame metadata.
    ExactSyscallRequiresFrameContract,
    /// The block encoder expanded an instruction or emitted branch relay data.
    ExpandedRelocation,
    /// An annotation did not match the producer's instruction inventory.
    InvalidProducerAnnotation,
    /// Producer labels did not describe every byte exactly once.
    IncompleteByteOwnership,
    /// A helper's bytes were not preserved at its final coalesced location.
    HelperBytesChanged,
    /// A declared independent metadata resource limit was reached.
    ResourceLimit,
    /// Checked metadata address or stack-offset arithmetic overflowed.
    ArithmeticOverflow,
}

/// Output-record limits for this optional metadata product.
///
/// These do not replace the existing emission work/allocation bounds. Temporary
/// assembler and annotation storage is constructed before final output checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameTraceLimits {
    /// Maximum number of generated instruction records.
    pub instructions: usize,
    /// Maximum number of instrumentation call-site records.
    pub calls: usize,
}

impl Default for FrameTraceLimits {
    fn default() -> Self {
        Self {
            instructions: 4096,
            calls: 64,
        }
    }
}

/// Where an application register's value at the logical head is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRegisterLocation {
    /// The named live architectural register still carries the value.
    Live(Register),
    /// A saved word at this signed offset from original application RSP.
    Stack(i32),
    /// Compute the value from [`FrameState::original_rsp_rule`].
    OriginalStackPointer,
}

const GPRS: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::RSP,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

/// Temporary storage relation to application state at one logical head.
///
/// This is not the caller's CFA. Original function rules must still be
/// independently proved valid at that exact head and composed with these facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameState {
    profile: ObservationStackProfile,
    anchor: Register,
    original_rsp_offset: i32,
    registers: [OriginalRegisterLocation; 16],
    flags_offset: Option<i32>,
}

impl FrameState {
    fn entry() -> Self {
        let mut registers = GPRS.map(OriginalRegisterLocation::Live);
        registers[7] = OriginalRegisterLocation::OriginalStackPointer;
        Self {
            profile: ObservationStackProfile::Legacy128,
            anchor: Register::RSP,
            original_rsp_offset: 0,
            registers,
            flags_offset: None,
        }
    }

    fn saved() -> Self {
        let mut state = Self::entry();
        state.apply(FrameEffect::Reserve(128)).unwrap();
        state.apply(FrameEffect::Reserve(32)).unwrap();
        state.apply(FrameEffect::SaveFlags).unwrap();
        for register in GPRS
            .into_iter()
            .filter(|register| *register != Register::RSP)
        {
            state.apply(FrameEffect::SaveRegister(register)).unwrap();
        }
        state.apply(FrameEffect::MetadataWord).unwrap();
        state.apply(FrameEffect::MetadataWord).unwrap();
        state.apply(FrameEffect::AnchorContext).unwrap();
        state
    }

    fn entry_for_profile(profile: ObservationStackProfile) -> Self {
        Self {
            profile,
            ..Self::entry()
        }
    }

    fn saved_for_profile(profile: ObservationStackProfile) -> Self {
        if profile == ObservationStackProfile::Legacy128 {
            return Self::saved();
        }
        let mut state = Self::entry_for_profile(profile);
        state
            .apply(FrameEffect::Reserve(profile.reserved_bytes() as i32))
            .unwrap();
        state.apply(FrameEffect::Reserve(32)).unwrap();
        state.apply(FrameEffect::SaveFlags).unwrap();
        for register in GPRS
            .into_iter()
            .filter(|register| *register != Register::RSP)
        {
            state.apply(FrameEffect::SaveRegister(register)).unwrap();
        }
        state.apply(FrameEffect::MetadataWord).unwrap();
        state.apply(FrameEffect::MetadataWord).unwrap();
        state.apply(FrameEffect::AnchorContext).unwrap();
        state
    }

    /// Exact storage profile; a legacy rule is never a tree rule or vice versa.
    pub const fn observation_stack_profile(&self) -> ObservationStackProfile {
        self.profile
    }

    /// Original application RSP is the named live register plus this offset.
    pub const fn original_rsp_rule(&self) -> (Register, i32) {
        (self.anchor, self.original_rsp_offset)
    }

    /// Returns the saved-value rule for one 64-bit application GPR.
    pub fn original_register(&self, register: Register) -> Option<OriginalRegisterLocation> {
        GPRS.iter()
            .position(|candidate| *candidate == register)
            .map(|index| self.registers[index])
    }

    /// Saved flags offset from original RSP, or None while flags are live.
    pub const fn saved_flags_offset(&self) -> Option<i32> {
        self.flags_offset
    }

    fn adjust_rsp(&mut self, bytes: i32) -> Result<(), FrameTraceRefusal> {
        if self.anchor != Register::RSP {
            return Err(FrameTraceRefusal::InvalidProducerAnnotation);
        }
        self.original_rsp_offset = self
            .original_rsp_offset
            .checked_add(bytes)
            .ok_or(FrameTraceRefusal::ArithmeticOverflow)?;
        if !(0..=self.profile.context_stack_prefix_bytes() as i32)
            .contains(&self.original_rsp_offset)
        {
            return Err(FrameTraceRefusal::InvalidProducerAnnotation);
        }
        Ok(())
    }

    fn apply(&mut self, effect: FrameEffect) -> Result<(), FrameTraceRefusal> {
        match effect {
            FrameEffect::Reserve(bytes) => self.adjust_rsp(bytes)?,
            FrameEffect::SaveFlags => {
                self.adjust_rsp(8)?;
                self.flags_offset = Some(-self.original_rsp_offset);
            }
            FrameEffect::SaveRegister(register) => {
                self.adjust_rsp(8)?;
                let index = GPRS
                    .iter()
                    .position(|candidate| *candidate == register)
                    .ok_or(FrameTraceRefusal::InvalidProducerAnnotation)?;
                if register == Register::RSP
                    || self.registers[index] != OriginalRegisterLocation::Live(register)
                {
                    return Err(FrameTraceRefusal::InvalidProducerAnnotation);
                }
                self.registers[index] = OriginalRegisterLocation::Stack(-self.original_rsp_offset);
            }
            FrameEffect::MetadataWord => self.adjust_rsp(8)?,
            FrameEffect::AnchorContext => {
                if self.anchor != Register::RSP
                    || self.original_rsp_offset != self.profile.context_stack_prefix_bytes() as i32
                {
                    return Err(FrameTraceRefusal::InvalidProducerAnnotation);
                }
                self.anchor = Register::R12;
            }
            FrameEffect::RestoreStack => {
                if self.anchor != Register::R12
                    || self.original_rsp_offset != self.profile.context_stack_prefix_bytes() as i32
                {
                    return Err(FrameTraceRefusal::InvalidProducerAnnotation);
                }
                self.anchor = Register::RSP;
            }
            FrameEffect::SkipMetadata => self.adjust_rsp(-16)?,
            FrameEffect::RestoreRegister(register) => {
                let index = GPRS
                    .iter()
                    .position(|candidate| *candidate == register)
                    .ok_or(FrameTraceRefusal::InvalidProducerAnnotation)?;
                if self.registers[index]
                    != OriginalRegisterLocation::Stack(-self.original_rsp_offset)
                {
                    return Err(FrameTraceRefusal::InvalidProducerAnnotation);
                }
                self.adjust_rsp(-8)?;
                self.registers[index] = OriginalRegisterLocation::Live(register);
            }
            FrameEffect::RestoreFlags => {
                if self.flags_offset != Some(-self.original_rsp_offset) {
                    return Err(FrameTraceRefusal::InvalidProducerAnnotation);
                }
                self.adjust_rsp(-8)?;
                self.flags_offset = None;
            }
            FrameEffect::Release(bytes) => self.adjust_rsp(-bytes)?,
        }
        Ok(())
    }
}

/// Producer phase for a generated save/restore instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameStage {
    /// Save the application state and invoke the instrumentation callback.
    SaveAndCall,
    /// Restore the application state after that call returns normally.
    Restore,
}

/// One producer instruction and its exact pre/post temporary storage facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperFrame {
    stage: FrameStage,
    instruction: Instruction,
    before: FrameState,
    after: FrameState,
}

impl HelperFrame {
    /// Returns the producer phase.
    pub const fn stage(&self) -> FrameStage {
        self.stage
    }
    /// Returns the source assembler instruction, before final encoding.
    pub const fn instruction(&self) -> &Instruction {
        &self.instruction
    }
    /// Returns facts at this instruction's entry.
    pub const fn before(&self) -> &FrameState {
        &self.before
    }
    /// Returns facts after this instruction completes normally.
    pub const fn after(&self) -> &FrameState {
        &self.after
    }
}

/// Provenance of one exact generated instruction extent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameInstructionKind {
    /// A producer-annotated instrumentation instruction.
    Helper(Box<HelperFrame>),
    /// One original instruction; original CFI semantics remain unqualified.
    Relocated(Instruction),
    /// A producer-owned final jump to the original continuation.
    ReturnTransfer(u64),
}

/// Exact half-open generated instruction extent and its original identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameInstruction {
    start: u64,
    end: u64,
    original_pc: u64,
    kind: FrameInstructionKind,
}

impl FrameInstruction {
    /// First generated instruction byte.
    pub const fn start(&self) -> u64 {
        self.start
    }
    /// First address after this generated instruction.
    pub const fn end(&self) -> u64 {
        self.end
    }
    /// Original instruction or continuation identity, not a CFA prescription.
    pub const fn original_pc(&self) -> u64 {
        self.original_pc
    }
    /// Producer facts for this extent.
    pub const fn kind(&self) -> &FrameInstructionKind {
        &self.kind
    }
}

/// Target category of a real instrumentation call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameCallKind {
    /// A static observer callback.
    Observer,
    /// The independent-control dispatcher, which may call the observer.
    ControlDispatcher,
}

/// Exact generated call and return addresses; this is not a synthetic frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCallSite {
    original_pc: u64,
    call_pc: u64,
    return_pc: u64,
    kind: FrameCallKind,
}

impl FrameCallSite {
    /// Original logical instruction whose callback is invoked.
    pub const fn original_pc(self) -> u64 {
        self.original_pc
    }
    /// Actual generated CALL instruction address.
    pub const fn call_pc(self) -> u64 {
        self.call_pc
    }
    /// Actual instruction address pushed by CALL.
    pub const fn return_pc(self) -> u64 {
        self.return_pc
    }
    /// Static callback or controlled dispatcher.
    pub const fn kind(self) -> FrameCallKind {
        self.kind
    }
}

/// Required qualifications that this producer-only metadata does not establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameTraceRequirement {
    /// Correct original CFI at each exact newly introduced/relocated point.
    ExactSourceRows,
    /// The hook preserves context fields and caller-rule dependent memory.
    FramePreservingHook,
    /// Qualified consumer semantics, actual FDE generation and registration.
    ConsumerAndRegistration,
    /// Source module, generated code and metadata lifetime ownership.
    LifetimeOwnership,
}

/// Immutable metadata bound to one exact image, with no registered unwind state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameTrace {
    origin: FrameEntryOrigin,
    identity: TrampolineImage,
    instructions: Vec<FrameInstruction>,
    data: Vec<(u64, u64)>,
    calls: Vec<FrameCallSite>,
}

impl FrameTrace {
    /// Explicit producer stack origin.
    pub const fn origin(&self) -> FrameEntryOrigin {
        self.origin
    }
    /// Immutable image storage profile used by every helper row.
    pub const fn observation_stack_profile(&self) -> ObservationStackProfile {
        self.identity.layout().observation_stack_profile
    }
    /// Per-instruction producer records, excluding data bytes.
    pub fn instructions(&self) -> &[FrameInstruction] {
        &self.instructions
    }
    /// Exact non-code literal ranges; they receive no frame authority.
    pub fn data_ranges(&self) -> &[(u64, u64)] {
        &self.data
    }
    /// Exact real instrumentation call/return records.
    pub fn calls(&self) -> &[FrameCallSite] {
        &self.calls
    }
    /// Qualifications still required before producing usable unwind metadata.
    ///
    /// Save/restore facts are conditional on these obligations. In particular,
    /// arbitrary existing callbacks may modify saved context; their ordinary
    /// validity does not establish the additional frame-preserving contract.
    pub fn requirements(&self) -> &[FrameTraceRequirement] {
        if self.calls.is_empty() {
            &[
                FrameTraceRequirement::ExactSourceRows,
                FrameTraceRequirement::ConsumerAndRegistration,
                FrameTraceRequirement::LifetimeOwnership,
            ]
        } else {
            &[
                FrameTraceRequirement::ExactSourceRows,
                FrameTraceRequirement::FramePreservingHook,
                FrameTraceRequirement::ConsumerAndRegistration,
                FrameTraceRequirement::LifetimeOwnership,
            ]
        }
    }
    /// Checks the complete immutable image identity, including maps and controls.
    /// No publication or contract generation is implied.
    pub fn matches_image(&self, image: &TrampolineImage) -> bool {
        self.identity == *image
    }
}

/// Ordinary emitted image plus the independently fallible metadata product.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameEmission {
    origin: FrameEntryOrigin,
    image: TrampolineImage,
    trace: Result<FrameTrace, FrameTraceRefusal>,
}

impl FrameEmission {
    pub(crate) fn new(
        origin: FrameEntryOrigin,
        image: TrampolineImage,
        trace: Result<FrameTrace, FrameTraceRefusal>,
    ) -> Self {
        Self {
            origin,
            image,
            trace,
        }
    }
    /// Explicit requested origin, including when metadata is unsupported.
    pub const fn origin(&self) -> FrameEntryOrigin {
        self.origin
    }
    /// Returns the ordinary image, including when frame metadata was refused.
    pub const fn image(&self) -> &TrampolineImage {
        &self.image
    }
    /// Returns producer metadata or its typed, independent refusal.
    pub fn trace(&self) -> Result<&FrameTrace, FrameTraceRefusal> {
        self.trace.as_ref().map_err(|error| *error)
    }
    /// Consumes the wrapper while preserving ordinary image ownership.
    pub fn into_image(self) -> TrampolineImage {
        self.image
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameEffect {
    Reserve(i32),
    SaveFlags,
    SaveRegister(Register),
    MetadataWord,
    AnchorContext,
    RestoreStack,
    SkipMetadata,
    RestoreRegister(Register),
    RestoreFlags,
    Release(i32),
}

pub(crate) struct HelperFrames {
    profile: ObservationStackProfile,
    stage: FrameStage,
    effects: Vec<(usize, FrameEffect)>,
    call: Option<(usize, FrameCallKind)>,
    result: Option<Result<HelperImage, FrameTraceRefusal>>,
}

struct HelperImage {
    bytes: Vec<u8>,
    rows: Vec<(usize, usize, HelperFrame)>,
    call: Option<(usize, usize, FrameCallKind)>,
}

impl HelperFrames {
    pub(crate) fn new(stage: FrameStage) -> Self {
        Self {
            profile: ObservationStackProfile::Legacy128,
            stage,
            effects: Vec::new(),
            call: None,
            result: None,
        }
    }
    pub(crate) fn with_profile(stage: FrameStage, profile: ObservationStackProfile) -> Self {
        Self {
            profile,
            ..Self::new(stage)
        }
    }
    pub(crate) fn after(&mut self, instruction_count: usize, effect: FrameEffect) {
        self.effects.push((instruction_count, effect));
    }
    pub(crate) fn call(&mut self, instruction_count: usize, kind: FrameCallKind) {
        self.call = instruction_count.checked_sub(1).map(|index| (index, kind));
    }
    pub(crate) fn finish(&mut self, source: &[Instruction], encoded: &BlockEncoderResult) {
        self.result = Some(self.resolve(source, encoded));
    }
    // Tree annotations must describe the actual producer instructions, not
    // merely a plausible 320-byte final offset. Legacy metadata is unchanged.
    fn validate_tree_instructions(&self, source: &[Instruction]) -> Result<(), FrameTraceRefusal> {
        self.validate_reserved_instructions(source, 144)
    }
    // Same instruction/annotation checks, with only the reserved prefix varied.
    fn validate_reserved_instructions(
        &self,
        source: &[Instruction],
        reserve: i32,
    ) -> Result<(), FrameTraceRefusal> {
        use iced_x86::{Mnemonic, OpKind};
        let bad = FrameTraceRefusal::InvalidProducerAnnotation;
        let lea = |i: &Instruction, dst, displacement: i64| {
            i.mnemonic() == Mnemonic::Lea
                && i.op_count() == 2
                && i.op0_kind() == OpKind::Register
                && i.op0_register() == dst
                && i.op1_kind() == OpKind::Memory
                && i.memory_base() == Register::RSP
                && i.memory_index() == Register::None
                && i.memory_displacement64() as i64 == displacement
        };
        let reg = |i: &Instruction, mnemonic, register| {
            i.mnemonic() == mnemonic
                && i.op_count() == 1
                && i.op0_kind() == OpKind::Register
                && i.op0_register() == register
        };
        let mov = |i: &Instruction, dst, src| {
            i.mnemonic() == Mnemonic::Mov
                && i.op_count() == 2
                && i.op0_kind() == OpKind::Register
                && i.op0_register() == dst
                && i.op1_kind() == OpKind::Register
                && i.op1_register() == src
        };
        let registers: Vec<_> = GPRS.into_iter().filter(|r| *r != Register::RSP).collect();
        let mut expected = Vec::new();
        match self.stage {
            FrameStage::SaveAndCall => {
                expected.extend([
                    FrameEffect::Reserve(reserve),
                    FrameEffect::Reserve(32),
                    FrameEffect::SaveFlags,
                ]);
                expected.extend(registers.iter().copied().map(FrameEffect::SaveRegister));
                expected.extend([
                    FrameEffect::MetadataWord,
                    FrameEffect::MetadataWord,
                    FrameEffect::AnchorContext,
                ]);
                if self.effects.first().map(|row| row.0) != Some(1) {
                    return Err(bad);
                }
                let first_metadata = self
                    .effects
                    .iter()
                    .find(|(_, e)| matches!(e, FrameEffect::MetadataWord))
                    .ok_or(bad)?
                    .0;
                let recovery = first_metadata
                    .checked_sub(2)
                    .and_then(|index| source.get(index))
                    .ok_or(bad)?;
                if !lea(recovery, Register::RAX, i64::from(reserve) + 160) {
                    return Err(bad);
                }
            }
            FrameStage::Restore => {
                expected.extend([FrameEffect::RestoreStack, FrameEffect::SkipMetadata]);
                expected.extend(
                    registers
                        .iter()
                        .rev()
                        .copied()
                        .map(FrameEffect::RestoreRegister),
                );
                expected.extend([
                    FrameEffect::RestoreFlags,
                    FrameEffect::Release(32),
                    FrameEffect::Release(reserve),
                ]);
                if self.effects.last().map(|row| row.0) != Some(source.len()) {
                    return Err(bad);
                }
            }
        }
        if self.effects.len() != expected.len() {
            return Err(bad);
        }
        let mut previous = 0;
        for (&(boundary, effect), expected) in self.effects.iter().zip(expected) {
            if boundary <= previous || effect != expected {
                return Err(bad);
            }
            previous = boundary;
            let i = boundary
                .checked_sub(1)
                .and_then(|index| source.get(index))
                .ok_or(bad)?;
            let matches = match effect {
                FrameEffect::Reserve(bytes) => lea(i, Register::RSP, -i64::from(bytes)),
                FrameEffect::Release(bytes) => lea(i, Register::RSP, i64::from(bytes)),
                FrameEffect::SaveFlags => i.mnemonic() == Mnemonic::Pushfq,
                FrameEffect::RestoreFlags => i.mnemonic() == Mnemonic::Popfq,
                FrameEffect::SaveRegister(r) => reg(i, Mnemonic::Push, r),
                FrameEffect::RestoreRegister(r) => reg(i, Mnemonic::Pop, r),
                FrameEffect::MetadataWord => reg(i, Mnemonic::Push, Register::RAX),
                FrameEffect::AnchorContext => mov(i, Register::R12, Register::RSP),
                FrameEffect::RestoreStack => mov(i, Register::RSP, Register::R12),
                FrameEffect::SkipMetadata => {
                    i.mnemonic() == Mnemonic::Add
                        && i.op_count() == 2
                        && i.op0_register() == Register::RSP
                        && matches!(
                            i.op1_kind(),
                            OpKind::Immediate8to64 | OpKind::Immediate32to64
                        )
                        && i.immediate(1) == 16
                }
            };
            if !matches {
                return Err(bad);
            }
        }
        Ok(())
    }
    fn resolve(
        &self,
        source: &[Instruction],
        encoded: &BlockEncoderResult,
    ) -> Result<HelperImage, FrameTraceRefusal> {
        let offsets = &encoded.new_instruction_offsets;
        if offsets.len() != source.len()
            || offsets.first() != Some(&0)
            || !encoded.reloc_infos.is_empty()
            || self
                .effects
                .iter()
                .any(|(index, _)| *index == 0 || *index > source.len())
        {
            return Err(FrameTraceRefusal::InvalidProducerAnnotation);
        }
        if self.profile == ObservationStackProfile::Tree144 {
            self.validate_tree_instructions(source)?;
        }
        if self.profile == ObservationStackProfile::CallPair240 {
            self.validate_reserved_instructions(source, 240)?;
        }
        let mut rows = Vec::new();
        let mut state = match self.stage {
            FrameStage::SaveAndCall => FrameState::entry_for_profile(self.profile),
            FrameStage::Restore => FrameState::saved_for_profile(self.profile),
        };
        let mut call = None;
        for (index, instruction) in source.iter().enumerate() {
            let start = offsets[index] as usize;
            let end = offsets
                .get(index + 1)
                .map_or(encoded.code_buffer.len(), |offset| *offset as usize);
            if start == u32::MAX as usize
                || end <= start
                || end - start > 15
                || end > encoded.code_buffer.len()
            {
                return Err(FrameTraceRefusal::InvalidProducerAnnotation);
            }
            let before = state.clone();
            for &(_, effect) in self
                .effects
                .iter()
                .filter(|(boundary, _)| *boundary == index + 1)
            {
                state.apply(effect)?;
            }
            rows.push((
                start,
                end,
                HelperFrame {
                    stage: self.stage,
                    instruction: *instruction,
                    before,
                    after: state.clone(),
                },
            ));
            if let Some((call_index, kind)) = self.call {
                if index == call_index {
                    if instruction.mnemonic() != iced_x86::Mnemonic::Call
                        || instruction.op0_register() != Register::RAX
                    {
                        return Err(FrameTraceRefusal::InvalidProducerAnnotation);
                    }
                    call = Some((start, end, kind));
                }
            }
        }
        let expected = match self.stage {
            FrameStage::SaveAndCall => FrameState::saved_for_profile(self.profile),
            FrameStage::Restore => FrameState::entry_for_profile(self.profile),
        };
        if state != expected
            || (self.stage == FrameStage::SaveAndCall && call.is_none())
            || (self.stage == FrameStage::Restore && call.is_some())
        {
            return Err(FrameTraceRefusal::InvalidProducerAnnotation);
        }
        Ok(HelperImage {
            bytes: encoded.code_buffer.clone(),
            rows,
            call,
        })
    }
}

pub(crate) struct FrameRecorder {
    profile: ObservationStackProfile,
    origin: FrameEntryOrigin,
    limits: FrameTraceLimits,
    refusal: Option<FrameTraceRefusal>,
    instructions: Vec<FrameInstruction>,
    data: Vec<(u64, u64)>,
    calls: Vec<FrameCallSite>,
}

impl FrameRecorder {
    pub(crate) fn new(origin: FrameEntryOrigin, limits: FrameTraceLimits) -> Self {
        Self {
            profile: ObservationStackProfile::Legacy128,
            origin,
            limits,
            refusal: None,
            instructions: Vec::new(),
            data: Vec::new(),
            calls: Vec::new(),
        }
    }
    pub(crate) fn with_profile(
        origin: FrameEntryOrigin,
        limits: FrameTraceLimits,
        profile: ObservationStackProfile,
    ) -> Self {
        Self {
            profile,
            ..Self::new(origin, limits)
        }
    }
    pub(crate) fn refuse(&mut self, error: FrameTraceRefusal) {
        self.refusal.get_or_insert(error);
    }
    pub(crate) fn recording(&self) -> bool {
        self.refusal.is_none()
    }
    fn push(&mut self, instruction: FrameInstruction) {
        if !self.recording() {
            return;
        }
        if !instruction
            .end
            .checked_sub(instruction.start)
            .is_some_and(|len| (1..=15).contains(&len))
        {
            self.refuse(FrameTraceRefusal::InvalidProducerAnnotation);
        } else if self.instructions.len() >= self.limits.instructions {
            self.refuse(FrameTraceRefusal::ResourceLimit);
        } else {
            self.instructions.push(instruction);
        }
    }
    pub(crate) fn relocated(&mut self, original: Instruction, start: u64, end: u64) {
        self.push(FrameInstruction {
            start,
            end,
            original_pc: original.ip(),
            kind: FrameInstructionKind::Relocated(original),
        });
    }
    pub(crate) fn helper(
        &mut self,
        original_pc: u64,
        address: u64,
        bytes: &[u8],
        frames: HelperFrames,
    ) {
        if !self.recording() {
            return;
        }
        if frames.profile != self.profile {
            self.refuse(FrameTraceRefusal::InvalidProducerAnnotation);
            return;
        }
        let result = frames
            .result
            .unwrap_or(Err(FrameTraceRefusal::InvalidProducerAnnotation));
        let helper = match result {
            Ok(helper) => helper,
            Err(error) => {
                self.refuse(error);
                return;
            }
        };
        if helper.bytes != bytes {
            self.refuse(FrameTraceRefusal::HelperBytesChanged);
            return;
        }
        for (start, end, row) in helper.rows {
            let Some(start) = address.checked_add(start as u64) else {
                self.refuse(FrameTraceRefusal::ArithmeticOverflow);
                return;
            };
            let Some(end) = address.checked_add(end as u64) else {
                self.refuse(FrameTraceRefusal::ArithmeticOverflow);
                return;
            };
            self.push(FrameInstruction {
                start,
                end,
                original_pc,
                kind: FrameInstructionKind::Helper(Box::new(row)),
            });
        }
        if let Some((start, end, kind)) = helper.call {
            let Some(call_pc) = address.checked_add(start as u64) else {
                self.refuse(FrameTraceRefusal::ArithmeticOverflow);
                return;
            };
            let Some(return_pc) = address.checked_add(end as u64) else {
                self.refuse(FrameTraceRefusal::ArithmeticOverflow);
                return;
            };
            if self.calls.len() >= self.limits.calls {
                self.refuse(FrameTraceRefusal::ResourceLimit);
                return;
            }
            self.calls.push(FrameCallSite {
                original_pc,
                call_pc,
                return_pc,
                kind,
            });
        }
    }
    pub(crate) fn return_jump(&mut self, address: u64, bytes: usize, target: u64) {
        if !self.recording() {
            return;
        }
        let code_len = match bytes {
            5 => 5,
            15 => 7,
            _ => {
                self.refuse(FrameTraceRefusal::InvalidProducerAnnotation);
                return;
            }
        };
        let Some(end) = address.checked_add(code_len) else {
            self.refuse(FrameTraceRefusal::ArithmeticOverflow);
            return;
        };
        self.push(FrameInstruction {
            start: address,
            end,
            original_pc: target,
            kind: FrameInstructionKind::ReturnTransfer(target),
        });
        if bytes == 15 {
            let Some(data_end) = end.checked_add(8) else {
                self.refuse(FrameTraceRefusal::ArithmeticOverflow);
                return;
            };
            self.data.push((end, data_end));
        }
    }
    pub(crate) fn finish(
        mut self,
        image: &TrampolineImage,
    ) -> Result<FrameTrace, FrameTraceRefusal> {
        if let Some(error) = self.refusal {
            return Err(error);
        }
        if self.origin != FrameEntryOrigin::ApplicationStack {
            return Err(FrameTraceRefusal::UnsupportedEntryOrigin);
        }
        if image.layout().observation_stack_profile != self.profile {
            return Err(FrameTraceRefusal::InvalidProducerAnnotation);
        }
        self.instructions.sort_by_key(|row| row.start);
        self.data.sort_unstable();
        self.calls.sort_by_key(|row| row.call_pc);
        let mut extents: Vec<_> = self
            .instructions
            .iter()
            .map(|row| (row.start, row.end))
            .chain(self.data.iter().copied())
            .collect();
        extents.sort_unstable();
        let mut cursor = image.address();
        for (start, end) in extents {
            if start != cursor || end <= start {
                return Err(FrameTraceRefusal::IncompleteByteOwnership);
            }
            cursor = end;
        }
        if image.address().checked_add(image.bytes().len() as u64) != Some(cursor) {
            return Err(FrameTraceRefusal::IncompleteByteOwnership);
        }
        for call in &self.calls {
            if !self
                .instructions
                .iter()
                .any(|row| row.start == call.return_pc)
            {
                return Err(FrameTraceRefusal::InvalidProducerAnnotation);
            }
        }
        Ok(FrameTrace {
            origin: self.origin,
            identity: image.clone(),
            instructions: self.instructions,
            data: self.data,
            calls: self.calls,
        })
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
