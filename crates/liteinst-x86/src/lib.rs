//! Shared descriptive x86 facts, never instruction-head or execution authority.
//!
//! Walkers choose their own linear/all-start policy, bounds and error mapping.
//! Selected families do not grant CPU support, an emitter ABI, entry ownership,
//! mapping freshness or a complete control-flow graph.
//!
//! The default feature selects iced's `std` support. A freestanding consumer
//! disables defaults and must select iced's `no_std` support in its independent
//! dependency graph. This crate adds no allocator or decoder-table policy.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "instr-info")]
use iced_x86::InstructionInfoFactory as IcedInstructionInfoFactory;
pub use iced_x86::{
    Code, Decoder, DecoderError, DecoderOptions, Instruction, Mnemonic, OpKind, Register,
};
#[cfg(feature = "instr-info")]
pub use iced_x86::{CodeSize, ConditionCode, FlowControl, MemorySize, OpAccess};

/// Creates the ordinary 64-bit decoder without changing sequential traversal.
pub fn decoder64(bytes: &[u8], pc: u64) -> Decoder<'_> {
    Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE)
}

/// Raw result of one decode, including invalid/truncated instruction metadata.
#[derive(Clone, Copy, Debug)]
pub struct Decoded {
    /// The original iced instruction, including its length and wrapping IPs.
    pub instruction: Instruction,
    /// The decoder's original error; callers retain their own error policy.
    pub error: DecoderError,
}

/// Decodes one instruction without imposing a source-length or overflow policy.
///
/// Empty input, a truncated encoding and a wrapping next IP remain descriptive
/// results. Callers must preserve their own prechecks and refusal order.
pub fn decode64(pc: u64, bytes: &[u8]) -> Decoded {
    let mut decoder = decoder64(bytes, pc);
    let instruction = decoder.decode();
    Decoded {
        instruction,
        error: decoder.last_error(),
    }
}

/// Architectural family, independent of any consumer's selection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedClass {
    /// CPUID.
    Cpuid,
    /// RDRAND.
    Rdrand,
    /// RDSEED.
    Rdseed,
    /// RDPID.
    Rdpid,
    /// RDTSC.
    Rdtsc,
    /// RDTSCP.
    Rdtscp,
    /// SYSCALL.
    Syscall,
    /// SYSENTER; a fact does not establish its calling convention.
    Sysenter,
    /// INT 80h; a fact does not establish its calling convention.
    Int80,
}

/// Classifies the existing exact selected Code forms, including syscall aliases.
///
/// RDPID's 32-bit-mode encoding is deliberately absent from this exact-form
/// view. This function does not validate a constructed Instruction's operands.
pub fn selected_code(instruction: &Instruction) -> Option<SelectedClass> {
    Some(match instruction.code() {
        Code::Cpuid => SelectedClass::Cpuid,
        Code::Rdrand_r16 | Code::Rdrand_r32 | Code::Rdrand_r64 => SelectedClass::Rdrand,
        Code::Rdseed_r16 | Code::Rdseed_r32 | Code::Rdseed_r64 => SelectedClass::Rdseed,
        Code::Rdpid_r64 => SelectedClass::Rdpid,
        Code::Rdtsc => SelectedClass::Rdtsc,
        Code::Rdtscp => SelectedClass::Rdtscp,
        Code::Syscall => SelectedClass::Syscall,
        Code::Sysenter => SelectedClass::Sysenter,
        Code::Int_imm8 if instruction.immediate8() == 0x80 => SelectedClass::Int80,
        _ => return None,
    })
}

/// Preserves the admission scanner's broader mnemonic-family classification.
///
/// This view is distinct from exact encoding support, even when both coincide
/// for a particular valid 64-bit decode. Neither view filters CPU capabilities.
pub fn selected_mnemonic(instruction: &Instruction) -> Option<SelectedClass> {
    Some(match instruction.mnemonic() {
        Mnemonic::Cpuid => SelectedClass::Cpuid,
        Mnemonic::Rdrand => SelectedClass::Rdrand,
        Mnemonic::Rdseed => SelectedClass::Rdseed,
        Mnemonic::Rdpid => SelectedClass::Rdpid,
        Mnemonic::Rdtsc => SelectedClass::Rdtsc,
        Mnemonic::Rdtscp => SelectedClass::Rdtscp,
        Mnemonic::Syscall => SelectedClass::Syscall,
        Mnemonic::Sysenter => SelectedClass::Sysenter,
        Mnemonic::Int if instruction.immediate8() == 0x80 => SelectedClass::Int80,
        _ => return None,
    })
}

/// The existing `j*` mnemonic population, not all control transfers.
///
/// This includes unusual/far jump forms without granting relocation support.
/// CALL, RET, LOOP and XBEGIN are not members of this descriptive family.
pub fn is_jump_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Jcxz
            | Mnemonic::Je
            | Mnemonic::Jecxz
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jmp
            | Mnemonic::Jmpe
            | Mnemonic::Jne
            | Mnemonic::Jno
            | Mnemonic::Jnp
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jp
            | Mnemonic::Jrcxz
            | Mnemonic::Js
            | Mnemonic::Jknzd
            | Mnemonic::Jkzd
    )
}

/// Descriptive members of the jumps plus exact register-stack union.
/// This does not establish helper-stack safety or an instruction's admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JumpStackClass {
    /// Any member of the existing `j*` mnemonic population.
    Jump,
    /// Exactly `Code::Push_r64`, including RSP.
    PushRegister64,
    /// Exactly `Code::Pop_r64`, including RSP.
    PopRegister64,
}

impl JumpStackClass {
    /// Canonical descriptive class label for the separately bound population.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Jump => "jump",
            Self::PushRegister64 => "push-r64",
            Self::PopRegister64 => "pop-r64",
        }
    }
}

/// Classifies the complete union without filtering prefixes or registers.
///
/// Other PUSH/POP encodings, including register operands encoded with r/m
/// opcodes, are excluded. Constructed operands and execution support remain
/// consumer obligations; the Code fact is not a new qualification rule.
pub fn jump_or_register_stack(instruction: &Instruction) -> Option<JumpStackClass> {
    match instruction.code() {
        Code::Push_r64 => Some(JumpStackClass::PushRegister64),
        Code::Pop_r64 => Some(JumpStackClass::PopRegister64),
        _ if is_jump_mnemonic(instruction.mnemonic()) => Some(JumpStackClass::Jump),
        _ => None,
    }
}

/// General-purpose register identity in architectural encoding order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Gpr {
    /// RAX.
    Rax,
    /// RCX.
    Rcx,
    /// RDX.
    Rdx,
    /// RBX.
    Rbx,
    /// RSP. Consumers may impose a separate callback-ABI refusal.
    Rsp,
    /// RBP.
    Rbp,
    /// RSI.
    Rsi,
    /// RDI.
    Rdi,
    /// R8.
    R8,
    /// R9.
    R9,
    /// R10.
    R10,
    /// R11.
    R11,
    /// R12.
    R12,
    /// R13.
    R13,
    /// R14.
    R14,
    /// R15.
    R15,
}

/// Width of a selected full-GPR operand; byte registers are not included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Width {
    /// Sixteen bits.
    Bits16 = 16,
    /// Thirty-two bits.
    Bits32 = 32,
    /// Sixty-four bits.
    Bits64 = 64,
}

/// Architectural full-GPR operand facts, without an emitter acceptance policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GprOperand {
    /// Register identity, including RSP.
    pub register: Gpr,
    /// Operand width as reported by the decoded register.
    pub width: Width,
}

/// Maps a 16/32/64-bit iced GPR to its architectural identity and width.
pub fn gpr(register: Register) -> Option<GprOperand> {
    macro_rules! registers {
        ($($name:ident => ($r16:ident, $r32:ident, $r64:ident)),+ $(,)?) => {
            match register {
                $(Register::$r16 => Some(GprOperand { register: Gpr::$name, width: Width::Bits16 }),
                  Register::$r32 => Some(GprOperand { register: Gpr::$name, width: Width::Bits32 }),
                  Register::$r64 => Some(GprOperand { register: Gpr::$name, width: Width::Bits64 }),)+
                _ => None,
            }
        };
    }
    registers! {
        Rax => (AX, EAX, RAX), Rcx => (CX, ECX, RCX), Rdx => (DX, EDX, RDX),
        Rbx => (BX, EBX, RBX), Rsp => (SP, ESP, RSP), Rbp => (BP, EBP, RBP),
        Rsi => (SI, ESI, RSI), Rdi => (DI, EDI, RDI), R8 => (R8W, R8D, R8),
        R9 => (R9W, R9D, R9), R10 => (R10W, R10D, R10), R11 => (R11W, R11D, R11),
        R12 => (R12W, R12D, R12), R13 => (R13W, R13D, R13),
        R14 => (R14W, R14D, R14), R15 => (R15W, R15D, R15),
    }
}

/// Which descriptive instruction-use facts a reusable factory collects.
///
/// This selects decoder metadata only. It does not change instruction
/// admission, CPU support, or execution policy.
#[cfg(feature = "instr-info")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstructionInfoOptions {
    include_registers: bool,
    include_memory: bool,
}

#[cfg(feature = "instr-info")]
impl InstructionInfoOptions {
    /// Collect register and memory facts.
    pub const ALL: Self = Self {
        include_registers: true,
        include_memory: true,
    };
    /// Collect register facts and omit memory facts.
    pub const REGISTERS_ONLY: Self = Self {
        include_registers: true,
        include_memory: false,
    };
    /// Collect memory facts and omit register facts. Registers used only by
    /// memory operands remain visible through those memory facts.
    pub const MEMORY_ONLY: Self = Self {
        include_registers: false,
        include_memory: true,
    };
    /// Collect only operand-access facts.
    pub const NONE: Self = Self {
        include_registers: false,
        include_memory: false,
    };

    fn to_iced(self) -> u32 {
        let mut options = iced_x86::InstructionInfoOptions::NONE;
        if !self.include_registers {
            options |= iced_x86::InstructionInfoOptions::NO_REGISTER_USAGE;
        }
        if !self.include_memory {
            options |= iced_x86::InstructionInfoOptions::NO_MEMORY_USAGE;
        }
        options
    }
}

/// One register access reported for an instruction.
#[cfg(feature = "instr-info")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UsedRegister {
    register: Register,
    access: OpAccess,
}

#[cfg(feature = "instr-info")]
impl UsedRegister {
    /// Returns the accessed register.
    pub const fn register(self) -> Register {
        self.register
    }

    /// Returns how the instruction accesses the register.
    pub const fn access(self) -> OpAccess {
        self.access
    }
}

/// One memory access reported for an instruction.
///
/// Segment, base, and index registers are reported exactly as iced reports
/// them; `Register::None` means that component is absent or ignored.
#[cfg(feature = "instr-info")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UsedMemory {
    segment: Register,
    base: Register,
    index: Register,
    scale: u32,
    displacement: u64,
    memory_size: MemorySize,
    access: OpAccess,
    address_size: CodeSize,
    vsib_size: u32,
}

#[cfg(feature = "instr-info")]
impl UsedMemory {
    /// Returns the effective segment register.
    pub const fn segment(self) -> Register {
        self.segment
    }

    /// Returns the base register.
    pub const fn base(self) -> Register {
        self.base
    }

    /// Returns the index register.
    pub const fn index(self) -> Register {
        self.index
    }

    /// Returns the index scale.
    pub const fn scale(self) -> u32 {
        self.scale
    }

    /// Returns the displacement.
    pub const fn displacement(self) -> u64 {
        self.displacement
    }

    /// Returns the accessed memory size.
    pub const fn memory_size(self) -> MemorySize {
        self.memory_size
    }

    /// Returns how the instruction accesses memory.
    pub const fn access(self) -> OpAccess {
        self.access
    }

    /// Returns the addressing code size.
    pub const fn address_size(self) -> CodeSize {
        self.address_size
    }

    /// Returns the VSIB element size in bytes, or zero when not applicable.
    pub const fn vsib_size(self) -> u32 {
        self.vsib_size
    }
}

/// Descriptive register, memory, and operand-access facts for one instruction.
///
/// The facts borrow reusable storage owned by [`InstructionInfoFactory`]; they
/// remain valid until that factory analyzes another instruction.
#[cfg(feature = "instr-info")]
#[derive(Clone, Copy, Debug)]
pub struct InstructionInfo<'a> {
    inner: &'a iced_x86::InstructionInfo,
}

#[cfg(feature = "instr-info")]
impl InstructionInfo<'_> {
    /// Returns every reported register access in iced's order.
    pub fn used_registers(&self) -> impl ExactSizeIterator<Item = UsedRegister> + '_ {
        self.inner.used_registers().iter().map(|used| UsedRegister {
            register: used.register(),
            access: used.access(),
        })
    }

    /// Returns every reported memory access in iced's order.
    pub fn used_memory(&self) -> impl ExactSizeIterator<Item = UsedMemory> + '_ {
        self.inner.used_memory().iter().map(|used| UsedMemory {
            segment: used.segment(),
            base: used.base(),
            index: used.index(),
            scale: used.scale(),
            displacement: used.displacement(),
            memory_size: used.memory_size(),
            access: used.access(),
            address_size: used.address_size(),
            vsib_size: used.vsib_size(),
        })
    }

    /// Returns the access for operand `operand`, or `OpAccess::None` when the
    /// operand index is outside iced's tracked range.
    pub fn op_access(&self, operand: u32) -> OpAccess {
        self.inner.op_access(operand)
    }

    /// Returns true when any reported register is neither `Register::None`, a
    /// general-purpose register, nor an instruction-pointer register.
    pub fn has_non_gpr_register_effect(&self) -> bool {
        self.used_registers().any(|used| {
            let register = used.register();
            register != Register::None && !register.is_gpr() && !register.is_ip()
        })
    }
}

/// Reusable factory for descriptive instruction-use facts.
///
/// Reusing one factory retains iced's internal result storage across calls;
/// each returned [`InstructionInfo`] borrows that storage until the next call.
#[cfg(feature = "instr-info")]
#[derive(Debug)]
pub struct InstructionInfoFactory {
    inner: IcedInstructionInfoFactory,
}

#[cfg(feature = "instr-info")]
impl Default for InstructionInfoFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "instr-info")]
impl InstructionInfoFactory {
    /// Creates a reusable instruction-info factory.
    pub fn new() -> Self {
        Self {
            inner: IcedInstructionInfoFactory::new(),
        }
    }

    /// Returns all register, memory, and operand-access facts for
    /// `instruction`.
    pub fn info(&mut self, instruction: &Instruction) -> InstructionInfo<'_> {
        InstructionInfo {
            inner: self.inner.info(instruction),
        }
    }

    /// Returns the facts selected by `options` for `instruction`.
    pub fn info_options(
        &mut self,
        instruction: &Instruction,
        options: InstructionInfoOptions,
    ) -> InstructionInfo<'_> {
        InstructionInfo {
            inner: self.inner.info_options(instruction, options.to_iced()),
        }
    }
}

#[cfg(test)]
mod tests;
