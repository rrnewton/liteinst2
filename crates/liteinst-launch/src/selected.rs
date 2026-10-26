//! Pure selected-instruction decoding and architectural register effects.
//!
//! This module neither executes instructions nor grants permission to execute.
//! Native decisions require a separately qualified child execution mechanism.
//! Scripted syscall success covers only the separate side-effect-free x64 and
//! long-mode i386 INT80 getpid/gettid profiles below. Other alias declarations
//! identify inputs without inventing return conventions. Memory effects, signal
//! delivery, debug traps, mapping changes and process lifecycle remain
//! execution-owner obligations.

use std::collections::{BTreeMap, VecDeque};

use iced_x86::{Code, Decoder, DecoderOptions, Register};
use liteinst_admission::scan::SiteClass;

use crate::RegisterSnapshot;

const CF: u64 = 1;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const IF: u64 = 1 << 9;
const DF: u64 = 1 << 10;
const OF: u64 = 1 << 11;
const RF: u64 = 1 << 16;
const ARITHMETIC_FLAGS: u64 = CF | PF | AF | ZF | SF | OF;
const ORDINARY_SYSCALL_FLAGS: u64 = ARITHMETIC_FLAGS | IF | DF | 2;

/// A refusal from pure decoding, dispatch or completion validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticsError {
    /// Empty, truncated, invalid or unsupported instruction encoding.
    InvalidEncoding,
    /// The first decoded instruction is outside the selected classes.
    NotSelected,
    /// An instruction address or continuation wrapped the address space.
    AddressOverflow,
    /// A syscall alias lacks an explicit declaration at this exact site.
    UndeclaredAlias,
    /// A per-site declaration does not match the decoded alias class.
    AliasClassMismatch,
    /// The site already has an alias declaration.
    DuplicateAlias,
    /// A declared input convention lacks a nonzero identity.
    InvalidAliasDeclaration,
    /// The supplied snapshot is not at the original selected head.
    ProgramCounterMismatch,
    /// This layer decodes only the declared native Linux x86-64 user mode.
    UnsupportedExecutionMode,
    /// Result and instruction classes differ.
    ResultClassMismatch,
    /// A result does not fit the instruction's architectural output width.
    ResultOutOfRange,
    /// A failed random instruction must return a zero destination value.
    NonzeroFailedRandom,
    /// Flags fall outside the explicitly frozen syscall return profile.
    UnqualifiedSyscallFlags,
    /// No return/clobber convention is qualified for this syscall ABI.
    UnqualifiedSyscallCompletion,
    /// Scripted syscall success would require effects outside getpid/gettid.
    UnsupportedScriptedSyscall,
    /// getpid/gettid must return a positive representable Linux pid_t.
    InvalidProcessIdentifier,
    /// A complete native snapshot differs from the exact modeled result.
    NativeStateMismatch,
    /// No scripted row remains for this invocation.
    ScriptExhausted,
    /// The next row does not match the entire site and input snapshot.
    ScriptMismatch,
    /// The caller finished while expected invocations remain.
    ScriptRemaining,
}

impl std::fmt::Display for SemanticsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SemanticsError {}

/// Full architectural integer-register identity, including RSP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gpr {
    /// RAX.
    Rax,
    /// RCX.
    Rcx,
    /// RDX.
    Rdx,
    /// RBX.
    Rbx,
    /// RSP.
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

impl Gpr {
    /// Reads all 64 bits of this register without applying operand width.
    pub fn read(self, registers: &RegisterSnapshot) -> u64 {
        match self {
            Self::Rax => registers.rax,
            Self::Rcx => registers.rcx,
            Self::Rdx => registers.rdx,
            Self::Rbx => registers.rbx,
            Self::Rsp => registers.rsp,
            Self::Rbp => registers.rbp,
            Self::Rsi => registers.rsi,
            Self::Rdi => registers.rdi,
            Self::R8 => registers.r8,
            Self::R9 => registers.r9,
            Self::R10 => registers.r10,
            Self::R11 => registers.r11,
            Self::R12 => registers.r12,
            Self::R13 => registers.r13,
            Self::R14 => registers.r14,
            Self::R15 => registers.r15,
        }
    }

    fn write(self, registers: &mut RegisterSnapshot, value: u64) {
        match self {
            Self::Rax => registers.rax = value,
            Self::Rcx => registers.rcx = value,
            Self::Rdx => registers.rdx = value,
            Self::Rbx => registers.rbx = value,
            Self::Rsp => registers.rsp = value,
            Self::Rbp => registers.rbp = value,
            Self::Rsi => registers.rsi = value,
            Self::Rdi => registers.rdi = value,
            Self::R8 => registers.r8 = value,
            Self::R9 => registers.r9 = value,
            Self::R10 => registers.r10 = value,
            Self::R11 => registers.r11 = value,
            Self::R12 => registers.r12 = value,
            Self::R13 => registers.r13 = value,
            Self::R14 => registers.r14 = value,
            Self::R15 => registers.r15 = value,
        }
    }
}

/// Width of a selected operand or explicitly declared alias input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperandWidth {
    /// Replace low sixteen bits while preserving the upper forty-eight.
    Bits16,
    /// Write thirty-two bits and clear the upper thirty-two.
    Bits32,
    /// Replace the full register.
    Bits64,
}

impl OperandWidth {
    /// Mask selecting this width's value bits.
    pub const fn mask(self) -> u64 {
        match self {
            Self::Bits16 => u16::MAX as u64,
            Self::Bits32 => u32::MAX as u64,
            Self::Bits64 => u64::MAX,
        }
    }

    fn apply(self, old: u64, value: u64) -> Result<u64, SemanticsError> {
        if value & !self.mask() != 0 {
            return Err(SemanticsError::ResultOutOfRange);
        }
        Ok(match self {
            Self::Bits16 => (old & !self.mask()) | value,
            Self::Bits32 | Self::Bits64 => value,
        })
    }
}

/// Caller-declared SYSENTER input registers, without any inferred kernel ABI.
///
/// This supports dispatch and explicit fault outcomes only. It supplies no
/// successful return, stack, mode-switch, flag or clobber semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SysenterConvention {
    identity: u64,
    number: Gpr,
    arguments: [Gpr; 6],
    width: OperandWidth,
}

impl SysenterConvention {
    /// Gives one nonzero application-defined identity to an exact input layout.
    pub fn new(
        identity: u64,
        number: Gpr,
        arguments: [Gpr; 6],
        width: OperandWidth,
    ) -> Result<Self, SemanticsError> {
        if identity == 0 {
            return Err(SemanticsError::InvalidAliasDeclaration);
        }
        Ok(Self {
            identity,
            number,
            arguments,
            width,
        })
    }
    /// Application-defined convention identity; it is not a Linux ABI version.
    pub const fn identity(self) -> u64 {
        self.identity
    }
    /// Register containing the declared request number.
    pub const fn number(self) -> Gpr {
        self.number
    }
    /// Registers containing the six declared inputs, in order.
    pub const fn arguments(self) -> [Gpr; 6] {
        self.arguments
    }
    /// Width used when reading every declared input.
    pub const fn width(self) -> OperandWidth {
        self.width
    }
}

/// Explicit instruction-entry ABI; alias input decoding is not return support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallAbi {
    /// Native Linux x86-64 SYSCALL register convention.
    LinuxX64,
    /// Long-mode INT 80 with Linux i386 request and argument registers.
    LinuxI386Int80,
    /// A caller-declared SYSENTER input layout; no kernel equivalence is assumed.
    DeclaredSysenter(SysenterConvention),
}

/// Exact per-site declarations required for selected syscall aliases.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyscallAliases {
    sites: BTreeMap<u64, SyscallAbi>,
}

impl SyscallAliases {
    /// Creates an empty declaration set; ordinary SYSCALL needs no declaration.
    pub fn new() -> Self {
        Self::default()
    }
    /// Declares one INT 80 or SYSENTER site. Existing declarations are immutable.
    pub fn declare(&mut self, address: u64, abi: SyscallAbi) -> Result<(), SemanticsError> {
        if abi == SyscallAbi::LinuxX64 {
            return Err(SemanticsError::InvalidAliasDeclaration);
        }
        if self.sites.contains_key(&address) {
            return Err(SemanticsError::DuplicateAlias);
        }
        self.sites.insert(address, abi);
        Ok(())
    }
    /// Returns the declaration at this exact original address, if any.
    pub fn get(&self, address: u64) -> Option<SyscallAbi> {
        self.sites.get(&address).copied()
    }
}

/// Fully decoded selected operation; register operands retain their exact width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// CPUID with EAX/ECX inputs.
    Cpuid,
    /// RDRAND with one register output.
    Rdrand {
        /// Full destination register identity.
        destination: Gpr,
        /// Architectural operand width.
        width: OperandWidth,
    },
    /// RDSEED with one register output.
    Rdseed {
        /// Full destination register identity.
        destination: Gpr,
        /// Architectural operand width.
        width: OperandWidth,
    },
    /// Long-mode RDPID writes zero-extended TSC_AUX into a full register.
    Rdpid {
        /// Full 64-bit destination, independent of redundant REX.W.
        destination: Gpr,
    },
    /// RDTSC writes EDX:EAX.
    Rdtsc,
    /// RDTSCP writes EDX:EAX and ECX=TSC_AUX.
    Rdtscp,
    /// SYSCALL or a separately declared alias.
    Syscall {
        /// Exact input and permitted completion ABI.
        abi: SyscallAbi,
    },
}

impl Operation {
    /// Corresponding scanner policy class.
    pub const fn class(self) -> SiteClass {
        match self {
            Self::Cpuid => SiteClass::Cpuid,
            Self::Rdrand { .. } => SiteClass::Rdrand,
            Self::Rdseed { .. } => SiteClass::Rdseed,
            Self::Rdpid { .. } => SiteClass::Rdpid,
            Self::Rdtsc => SiteClass::Rdtsc,
            Self::Rdtscp => SiteClass::Rdtscp,
            Self::Syscall {
                abi: SyscallAbi::LinuxX64,
            } => SiteClass::Syscall,
            Self::Syscall {
                abi: SyscallAbi::LinuxI386Int80,
            } => SiteClass::Int80,
            Self::Syscall {
                abi: SyscallAbi::DeclaredSysenter(_),
            } => SiteClass::Sysenter,
        }
    }
}

/// Validated original bytes, operation and exact next instruction address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedSelected {
    logical_pc: u64,
    next_pc: u64,
    bytes: Vec<u8>,
    operation: Operation,
}

impl DecodedSelected {
    /// Original selected instruction head.
    pub const fn logical_pc(&self) -> u64 {
        self.logical_pc
    }
    /// Original fallthrough; includes every decoded prefix byte.
    pub const fn next_pc(&self) -> u64 {
        self.next_pc
    }
    /// Exact selected instruction bytes, excluding subsequent instructions.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Decoded class, operand and ABI information.
    pub const fn operation(&self) -> Operation {
        self.operation
    }
}

/// Decodes exactly the first instruction in native 64-bit mode.
///
/// A valid ignored prefix remains part of the logical instruction length.
/// Alias declarations are checked even when attached to the wrong opcode.
pub fn decode(
    address: u64,
    bytes: &[u8],
    aliases: &SyscallAliases,
) -> Result<DecodedSelected, SemanticsError> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() > bytes.len() {
        return Err(SemanticsError::InvalidEncoding);
    }
    let next_pc = address
        .checked_add(instruction.len() as u64)
        .ok_or(SemanticsError::AddressOverflow)?;
    let declaration = aliases.get(address);
    if declaration.is_some()
        && instruction.code() != Code::Sysenter
        && !(instruction.code() == Code::Int_imm8 && instruction.immediate8() == 0x80)
    {
        return Err(SemanticsError::AliasClassMismatch);
    }
    let operation = match instruction.code() {
        Code::Cpuid => Operation::Cpuid,
        Code::Rdtsc => Operation::Rdtsc,
        Code::Rdtscp => Operation::Rdtscp,
        Code::Rdrand_r16 | Code::Rdrand_r32 | Code::Rdrand_r64 => {
            let (destination, width) = register_operand(instruction.op0_register())?;
            Operation::Rdrand { destination, width }
        }
        Code::Rdseed_r16 | Code::Rdseed_r32 | Code::Rdseed_r64 => {
            let (destination, width) = register_operand(instruction.op0_register())?;
            Operation::Rdseed { destination, width }
        }
        Code::Rdpid_r64 => {
            let (destination, width) = register_operand(instruction.op0_register())?;
            if width != OperandWidth::Bits64 {
                return Err(SemanticsError::InvalidEncoding);
            }
            Operation::Rdpid { destination }
        }
        Code::Syscall => Operation::Syscall {
            abi: SyscallAbi::LinuxX64,
        },
        Code::Int_imm8 if instruction.immediate8() == 0x80 => match declaration {
            Some(SyscallAbi::LinuxI386Int80) => Operation::Syscall {
                abi: SyscallAbi::LinuxI386Int80,
            },
            None => return Err(SemanticsError::UndeclaredAlias),
            _ => return Err(SemanticsError::AliasClassMismatch),
        },
        Code::Sysenter => match declaration {
            Some(abi @ SyscallAbi::DeclaredSysenter(_)) => Operation::Syscall { abi },
            None => return Err(SemanticsError::UndeclaredAlias),
            _ => return Err(SemanticsError::AliasClassMismatch),
        },
        _ => return Err(SemanticsError::NotSelected),
    };
    Ok(DecodedSelected {
        logical_pc: address,
        next_pc,
        bytes: bytes[..instruction.len()].to_vec(),
        operation,
    })
}

/// Class-specific inputs in addition to the complete retained register file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedArguments {
    /// CPUID request leaf and subleaf; upper input halves are not operands.
    Cpuid {
        /// EAX leaf.
        leaf: u32,
        /// ECX subleaf.
        subleaf: u32,
    },
    /// A destination-only operation with no explicit input operands.
    None,
    /// ABI-specific syscall number and six input values.
    Syscall {
        /// Declared entry convention.
        abi: SyscallAbi,
        /// Number read at the ABI's width.
        number: u64,
        /// Arguments in ABI order, read at the ABI's width.
        arguments: [u64; 6],
    },
}

/// Exact logical pre-instruction state, including otherwise unchanged registers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedInput {
    instruction: DecodedSelected,
    registers: RegisterSnapshot,
}

impl SelectedInput {
    /// Authenticates logical PC and the supported native user-code selector.
    pub fn new(
        instruction: DecodedSelected,
        registers: RegisterSnapshot,
    ) -> Result<Self, SemanticsError> {
        if registers.rip != instruction.logical_pc {
            return Err(SemanticsError::ProgramCounterMismatch);
        }
        if registers.cs != 0x33 {
            return Err(SemanticsError::UnsupportedExecutionMode);
        }
        Ok(Self {
            instruction,
            registers,
        })
    }
    /// Exact original instruction identity and decode.
    pub const fn instruction(&self) -> &DecodedSelected {
        &self.instruction
    }
    /// Full original GPR, flags, segment and kernel-bookkeeping snapshot.
    pub const fn registers(&self) -> &RegisterSnapshot {
        &self.registers
    }
    /// Extracts inputs with the exact declared width and register order.
    pub fn arguments(&self) -> SelectedArguments {
        let r = &self.registers;
        match self.instruction.operation {
            Operation::Cpuid => SelectedArguments::Cpuid {
                leaf: r.rax as u32,
                subleaf: r.rcx as u32,
            },
            Operation::Syscall { abi } => {
                let (number, arguments, mask) = match abi {
                    SyscallAbi::LinuxX64 => (
                        Gpr::Rax,
                        [Gpr::Rdi, Gpr::Rsi, Gpr::Rdx, Gpr::R10, Gpr::R8, Gpr::R9],
                        u64::MAX,
                    ),
                    SyscallAbi::LinuxI386Int80 => (
                        Gpr::Rax,
                        [Gpr::Rbx, Gpr::Rcx, Gpr::Rdx, Gpr::Rsi, Gpr::Rdi, Gpr::Rbp],
                        u32::MAX as u64,
                    ),
                    SyscallAbi::DeclaredSysenter(convention) => (
                        convention.number,
                        convention.arguments,
                        convention.width.mask(),
                    ),
                };
                SelectedArguments::Syscall {
                    abi,
                    number: number.read(r) & mask,
                    arguments: arguments.map(|register| register.read(r) & mask),
                }
            }
            _ => SelectedArguments::None,
        }
    }

    /// Applies one typed result without executing code or changing memory.
    ///
    /// Successful instructions clear RF. Random operations additionally define
    /// CF and clear OF/SF/ZF/AF/PF. Every other bit and unrelated register is
    /// retained exactly. Kernel `orig_rax` bookkeeping is retained; native
    /// syscall entry/exit authentication must account for its separate changes.
    /// RSP outputs are modeled even if a particular emitter cannot restore them.
    pub fn complete(&self, result: SelectedResult) -> Result<CompletedInstruction, SemanticsError> {
        let mut after = self.registers;
        after.rip = self.instruction.next_pc;
        after.eflags &= !RF;
        match (self.instruction.operation, result) {
            (Operation::Cpuid, SelectedResult::Cpuid { eax, ebx, ecx, edx }) => {
                after.rax = u64::from(eax);
                after.rbx = u64::from(ebx);
                after.rcx = u64::from(ecx);
                after.rdx = u64::from(edx);
            }
            (Operation::Rdrand { destination, width }, SelectedResult::Rdrand { value, carry })
            | (Operation::Rdseed { destination, width }, SelectedResult::Rdseed { value, carry }) =>
            {
                if !carry && value != 0 {
                    return Err(SemanticsError::NonzeroFailedRandom);
                }
                let output = width.apply(destination.read(&self.registers), value)?;
                destination.write(&mut after, output);
                after.eflags = (after.eflags & !ARITHMETIC_FLAGS) | u64::from(carry);
            }
            (Operation::Rdpid { destination }, SelectedResult::Rdpid { auxiliary }) => {
                destination.write(&mut after, u64::from(auxiliary));
            }
            (Operation::Rdtsc, SelectedResult::Rdtsc { counter }) => {
                write_counter(&mut after, counter);
            }
            (Operation::Rdtscp, SelectedResult::Rdtscp { counter, auxiliary }) => {
                write_counter(&mut after, counter);
                after.rcx = u64::from(auxiliary);
            }
            (
                Operation::Syscall { abi },
                SelectedResult::Syscall(SyscallResult::LinuxX64GetId { value }),
            ) => {
                if abi != SyscallAbi::LinuxX64 {
                    return Err(SemanticsError::UnqualifiedSyscallCompletion);
                }
                if !matches!(
                    self.registers.rax as libc::c_long,
                    libc::SYS_getpid | libc::SYS_gettid
                ) {
                    return Err(SemanticsError::UnsupportedScriptedSyscall);
                }
                if self.registers.eflags & !ORDINARY_SYSCALL_FLAGS != 0
                    || self.registers.eflags & (IF | 2) != IF | 2
                {
                    return Err(SemanticsError::UnqualifiedSyscallFlags);
                }
                if value == 0 || value > i32::MAX as u32 {
                    return Err(SemanticsError::InvalidProcessIdentifier);
                }
                after.rax = u64::from(value);
                after.rcx = self.instruction.next_pc;
                after.r11 = self.registers.eflags;
            }
            (
                Operation::Syscall { abi },
                SelectedResult::Syscall(SyscallResult::LinuxI386Int80GetId { value }),
            ) => {
                if abi != SyscallAbi::LinuxI386Int80 {
                    return Err(SemanticsError::UnqualifiedSyscallCompletion);
                }
                if !matches!(self.registers.rax as u32, 20 | 224) {
                    return Err(SemanticsError::UnsupportedScriptedSyscall);
                }
                if self.registers.eflags & !ORDINARY_SYSCALL_FLAGS != 0
                    || self.registers.eflags & (IF | 2) != IF | 2
                {
                    return Err(SemanticsError::UnqualifiedSyscallFlags);
                }
                if value == 0 || value > i32::MAX as u32 {
                    return Err(SemanticsError::InvalidProcessIdentifier);
                }
                // Long-mode Linux INT80 returns to its original CS and next
                // PC. It does not have SYSCALL's RCX/R11 clobbers. A scripted
                // replacement performs no kernel entry, so orig_rax stays put.
                after.rax = u64::from(value);
            }
            _ => return Err(SemanticsError::ResultClassMismatch),
        }
        Ok(CompletedInstruction {
            instruction: self.instruction.clone(),
            before: self.registers,
            after,
        })
    }

    /// Records a fault before instruction completion without changing any
    /// logical pre-state, including RF, RIP, outputs, or kernel metadata.
    /// No application signal is delivered by this pure operation.
    pub fn fault(&self, fault: InstructionFault) -> FaultedInstruction {
        FaultedInstruction {
            input: self.clone(),
            fault,
        }
    }

    /// Extracts the actual native output fields from a completion snapshot.
    ///
    /// This does not certify unrelated state or kernel metadata. Use
    /// `validate_native_completion` for an exact complete-snapshot comparison.
    pub fn native_result(
        &self,
        after: &RegisterSnapshot,
    ) -> Result<SelectedResult, SemanticsError> {
        let result = match self.instruction.operation {
            Operation::Cpuid => SelectedResult::Cpuid {
                eax: after.rax as u32,
                ebx: after.rbx as u32,
                ecx: after.rcx as u32,
                edx: after.rdx as u32,
            },
            Operation::Rdrand { destination, width } => SelectedResult::Rdrand {
                value: destination.read(after) & width.mask(),
                carry: after.eflags & CF != 0,
            },
            Operation::Rdseed { destination, width } => SelectedResult::Rdseed {
                value: destination.read(after) & width.mask(),
                carry: after.eflags & CF != 0,
            },
            Operation::Rdpid { destination } => SelectedResult::Rdpid {
                auxiliary: destination.read(after) as u32,
            },
            Operation::Rdtsc => SelectedResult::Rdtsc {
                counter: counter_from(after),
            },
            Operation::Rdtscp => SelectedResult::Rdtscp {
                counter: counter_from(after),
                auxiliary: after.rcx as u32,
            },
            Operation::Syscall {
                abi: SyscallAbi::LinuxX64,
            } => SelectedResult::Syscall(SyscallResult::LinuxX64GetId {
                value: u32::try_from(after.rax)
                    .map_err(|_| SemanticsError::InvalidProcessIdentifier)?,
            }),
            Operation::Syscall {
                abi: SyscallAbi::LinuxI386Int80,
            } => SelectedResult::Syscall(SyscallResult::LinuxI386Int80GetId {
                value: u32::try_from(after.rax)
                    .map_err(|_| SemanticsError::InvalidProcessIdentifier)?,
            }),
            Operation::Syscall { .. } => return Err(SemanticsError::UnqualifiedSyscallCompletion),
        };
        self.complete(result)?;
        Ok(result)
    }

    /// Requires exact equality of every field, including untouched outputs,
    /// flags, RSP, segments and `orig_rax`. No output register is masked away.
    /// Native syscall bookkeeping differs at kernel entry/exit; callers must
    /// authenticate that separately rather than treating this method as an
    /// exemption from a full architectural comparison.
    pub fn validate_native_completion(
        &self,
        after: &RegisterSnapshot,
    ) -> Result<CompletedInstruction, SemanticsError> {
        let completed = self.complete(self.native_result(after)?)?;
        if completed.after != *after {
            return Err(SemanticsError::NativeStateMismatch);
        }
        Ok(completed)
    }
}

/// Narrow, side-effect-free scripted syscall result profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallResult {
    /// Successful native getpid/gettid return. No memory, descriptor, lifecycle,
    /// mapping, errno, alias or signal-return effects are represented.
    LinuxX64GetId {
        /// Positive identifier representable by Linux pid_t.
        value: u32,
    },
    /// Long-mode Linux i386 INT80 getpid (20) or gettid (224), with ordinary
    /// TF/RF-clear user flags. Only RAX and the logical next PC change; this
    /// replacement retains kernel bookkeeping and performs no memory effects.
    /// Native execution must independently authenticate its low32 orig_rax.
    LinuxI386Int80GetId {
        /// Positive identifier representable by Linux pid_t.
        value: u32,
    },
}

/// Typed architectural output, kept distinct for every selected class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedResult {
    /// Four zero-extended CPUID outputs.
    Cpuid {
        /// EAX output.
        eax: u32,
        /// EBX output.
        ebx: u32,
        /// ECX output.
        ecx: u32,
        /// EDX output.
        edx: u32,
    },
    /// RDRAND result; failure requires value zero.
    Rdrand {
        /// Value before architectural destination-width application.
        value: u64,
        /// Success bit copied to CF.
        carry: bool,
    },
    /// RDSEED result; failure requires value zero.
    Rdseed {
        /// Value before architectural destination-width application.
        value: u64,
        /// Success bit copied to CF.
        carry: bool,
    },
    /// Zero-extended TSC_AUX result.
    Rdpid {
        /// IA32_TSC_AUX value.
        auxiliary: u32,
    },
    /// Full RDTSC timestamp, split into EDX:EAX.
    Rdtsc {
        /// Timestamp value.
        counter: u64,
    },
    /// Full RDTSCP timestamp and independent AUX output.
    Rdtscp {
        /// Timestamp value.
        counter: u64,
        /// IA32_TSC_AUX value.
        auxiliary: u32,
    },
    /// An explicitly qualified syscall completion profile.
    Syscall(SyscallResult),
}

/// A completed register transition; memory and XSTATE remain owner obligations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedInstruction {
    /// Original selected instruction and exact fallthrough.
    pub instruction: DecodedSelected,
    /// Exact logical input snapshot.
    pub before: RegisterSnapshot,
    /// Complete output snapshot; unrelated fields are retained exactly.
    pub after: RegisterSnapshot,
}

/// Architectural fault before selected-instruction completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionFault {
    /// Invalid opcode, including an unavailable CPU feature.
    InvalidOpcode,
    /// General-protection fault.
    GeneralProtection {
        /// Architectural exception error code.
        error_code: u32,
    },
    /// Page fault at an explicitly supplied architectural address.
    PageFault {
        /// Faulting linear address.
        address: u64,
        /// Architectural exception error code.
        error_code: u32,
    },
}

/// Fault evidence retaining the exact uncompleted logical state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultedInstruction {
    /// Original instruction, full register file and faulting logical PC.
    pub input: SelectedInput,
    /// Explicit fault; not an errno return or a completed instruction.
    pub fault: InstructionFault,
}

/// Provider choice; requesting native execution does not perform it locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDecision {
    /// Ask the execution owner to run one actual original operation in the child.
    Native,
    /// Supply one typed result for checked architectural completion.
    Complete(SelectedResult),
    /// Report an uncompleted architectural fault at the original logical PC.
    Fault(InstructionFault),
}

/// Standalone provider boundary with no process-control or memory-write handle.
pub trait InstructionProvider {
    /// Decides once for one authenticated logical selected invocation.
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError>;
}

/// Default observer policy: request actual native execution in the owned child.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeProvider;
impl InstructionProvider for NativeProvider {
    fn decide(&mut self, _: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        Ok(ProviderDecision::Native)
    }
}

/// One exact script row; it matches the site, bytes, ABI and full input snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptEntry {
    /// Exact expected invocation, including every otherwise unaffected register.
    pub input: SelectedInput,
    /// Decision delivered once after matching and any completion validation.
    pub decision: ProviderDecision,
}

/// Strict deterministic provider; mismatches and invalid completions never
/// consume or skip a row. Native decisions request execution without certifying
/// that an execution backend supports the instruction.
#[derive(Clone, Debug, Default)]
pub struct ScriptedProvider {
    remaining: VecDeque<ScriptEntry>,
    consumed: usize,
}
impl ScriptedProvider {
    /// Retains the exact supplied sequence without wildcard rows or implicit repeats.
    pub fn new(entries: impl IntoIterator<Item = ScriptEntry>) -> Self {
        Self {
            remaining: entries.into_iter().collect(),
            consumed: 0,
        }
    }
    /// Number of matched invocations whose valid decisions were delivered.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }
    /// Number of expected invocations that have not occurred.
    pub fn remaining(&self) -> usize {
        self.remaining.len()
    }
    /// Requires every script row to have been consumed exactly once.
    pub fn finish(&self) -> Result<(), SemanticsError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(SemanticsError::ScriptRemaining)
        }
    }
}
impl InstructionProvider for ScriptedProvider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let expected = self
            .remaining
            .front()
            .ok_or(SemanticsError::ScriptExhausted)?;
        if &expected.input != input {
            return Err(SemanticsError::ScriptMismatch);
        }
        if let ProviderDecision::Complete(result) = expected.decision {
            input.complete(result)?;
        }
        let row = self.remaining.pop_front().expect("front was present");
        self.consumed += 1;
        Ok(row.decision)
    }
}

fn write_counter(registers: &mut RegisterSnapshot, counter: u64) {
    registers.rax = u64::from(counter as u32);
    registers.rdx = u64::from((counter >> 32) as u32);
}
fn counter_from(registers: &RegisterSnapshot) -> u64 {
    (u64::from(registers.rdx as u32) << 32) | u64::from(registers.rax as u32)
}

fn register_operand(register: Register) -> Result<(Gpr, OperandWidth), SemanticsError> {
    macro_rules! registers {
        ($($gpr:ident => ($r16:ident, $r32:ident, $r64:ident)),+ $(,)?) => {
            match register {
                $(Register::$r16 => Ok((Gpr::$gpr, OperandWidth::Bits16)),
                  Register::$r32 => Ok((Gpr::$gpr, OperandWidth::Bits32)),
                  Register::$r64 => Ok((Gpr::$gpr, OperandWidth::Bits64)),)+
                _ => Err(SemanticsError::InvalidEncoding),
            }
        };
    }
    registers! {
        Rax => (AX, EAX, RAX), Rcx => (CX, ECX, RCX), Rdx => (DX, EDX, RDX), Rbx => (BX, EBX, RBX),
        Rsp => (SP, ESP, RSP), Rbp => (BP, EBP, RBP), Rsi => (SI, ESI, RSI), Rdi => (DI, EDI, RDI),
        R8 => (R8W, R8D, R8), R9 => (R9W, R9D, R9), R10 => (R10W, R10D, R10), R11 => (R11W, R11D, R11),
        R12 => (R12W, R12D, R12), R13 => (R13W, R13D, R13), R14 => (R14W, R14D, R14), R15 => (R15W, R15D, R15),
    }
}
