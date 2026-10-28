//! Private real-instruction stencil; no image-byte surgery or guessed TLS layout.
use super::*;
use crate::precontext::{
    ARMED, CallScratch, ENTERED, FAST, PreContextAction, PreContextRole, RETURN_OBSERVED, SLOW,
};
use iced_x86::{Encoder, MemoryOperand, Register};

const SAVED: u64 = core::mem::offset_of!(CallScratch, saved_rcx) as u64;
const PHASE: u64 = core::mem::offset_of!(CallScratch, phase) as u64;
const CHOICE: u64 = core::mem::offset_of!(CallScratch, disposition) as u64;
const ENTRY_PC: u64 = core::mem::offset_of!(CallScratch, entry_pc) as u64;
const ENTRY_RSP: u64 = core::mem::offset_of!(CallScratch, entry_rsp) as u64;
const ENTRY_WORD: u64 = core::mem::offset_of!(CallScratch, entry_word) as u64;
const RETURN_PC: u64 = core::mem::offset_of!(CallScratch, return_pc) as u64;
const RETURN_RSP: u64 = core::mem::offset_of!(CallScratch, return_rsp) as u64;
const RETURN_WORD: u64 = core::mem::offset_of!(CallScratch, return_word) as u64;
const _: () = assert!(
    SAVED == 0
        && PHASE == 8
        && CHOICE == 16
        && ENTRY_PC == 24
        && ENTRY_RSP == 32
        && ENTRY_WORD == 40
        && RETURN_PC == 48
        && RETURN_RSP == 56
        && RETURN_WORD == 64
);

pub(super) struct GateSpec {
    indices: Vec<usize>,
    pub(super) fault_index: usize,
}

struct Builder<'a, F> {
    output: &'a mut Vec<Instruction>,
    identity: &'a mut F,
    indices: Vec<usize>,
    fault: u64,
}

fn memory(base: Register, displacement: u64) -> MemoryOperand {
    MemoryOperand::with_base_displ(base, displacement as i64)
}

// A window-level refusal guard, not the caller's complete leaf/CFG certificate.
pub(super) fn validate_window(
    scan: &ScanResult,
    instructions: &[Instruction],
    actions: &[PreContextAction],
) -> Result<(), TrampolineError> {
    use iced_x86::FlowControl;
    let gpr = |r: Register| {
        r.is_gpr()
            && matches!(
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
            )
    };
    for i in instructions {
        let item = scan
            .instructions()
            .iter()
            .find(|item| item.address() == i.ip())
            .ok_or_else(|| encoding_error("pre-context original head missing"))?;
        let raw = scan
            .snapshot()
            .get(item.offset()..item.offset() + item.len())
            .ok_or_else(|| encoding_error("pre-context original bytes missing"))?;
        let role = actions
            .iter()
            .find(|a| a.logical_pc == i.ip())
            .map(|a| a.role);
        if i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || i.is_privileged()
            || (role == Some(PreContextRole::Return) && raw != [0xc3])
        {
            return Err(encoding_error(
                "pre-context prefix/RET/source profile differs",
            ));
        }
        match i.flow_control() {
            FlowControl::Return if raw == [0xc3] && role == Some(PreContextRole::Return) => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                if matches!(
                    raw,
                    [0x70..=0x7f, _]
                        | [0x0f, 0x80..=0x8f, _, _, _, _]
                        | [0xeb, _]
                        | [0xe9, _, _, _, _]
                ) && i.op_count() == 1
                    && i.op0_kind() == OpKind::NearBranch64 => {}
            FlowControl::Next
                if matches!(
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
                ) =>
            {
                for n in 0..i.op_count() {
                    let allowed = match i.op_kind(n) {
                        OpKind::Register => gpr(i.op_register(n)),
                        OpKind::Memory => {
                            (n != 0
                                || matches!(
                                    i.mnemonic(),
                                    Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Nop
                                ))
                                && i.memory_base().is_gpr64()
                                && gpr(i.memory_base())
                                && (i.memory_index() == Register::None
                                    || (i.memory_index().is_gpr64() && gpr(i.memory_index())))
                        }
                        OpKind::Immediate8
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate64
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                        | OpKind::Immediate32to64 => true,
                        _ => false,
                    };
                    if !allowed {
                        return Err(encoding_error("pre-context non-leaf operand"));
                    }
                }
            }
            _ => return Err(encoding_error("pre-context non-leaf transfer/instruction")),
        }
    }
    Ok(())
}

impl<F: FnMut() -> Result<u64, TrampolineError>> Builder<'_, F> {
    fn push(&mut self, mut instruction: Instruction) -> Result<(), TrampolineError> {
        instruction.set_ip((self.identity)()?);
        self.indices.push(self.output.len());
        self.output.push(instruction);
        Ok(())
    }
    fn mark(&mut self, label: u64) {
        let mut marker = Instruction::with(Code::Zero_bytes);
        marker.set_ip(label);
        self.output.push(marker);
    }
    fn load(&mut self, offset: u64) -> Result<(), TrampolineError> {
        self.push(
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                memory(Register::RBX, offset),
            )
            .map_err(encoding_error)?,
        )
    }
    fn store(&mut self, offset: u64) -> Result<(), TrampolineError> {
        self.push(
            Instruction::with2(
                Code::Mov_rm64_r64,
                memory(Register::RBX, offset),
                Register::RCX,
            )
            .map_err(encoding_error)?,
        )
    }
    fn set(&mut self, offset: u64, value: u64) -> Result<(), TrampolineError> {
        let value = i32::try_from(value).map_err(encoding_error)?;
        self.push(
            Instruction::with2(Code::Mov_rm64_imm32, memory(Register::RBX, offset), value)
                .map_err(encoding_error)?,
        )
    }
    fn immediate(&mut self, value: u64) -> Result<(), TrampolineError> {
        self.push(
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, value)
                .map_err(encoding_error)?,
        )
    }
    fn lea(&mut self, delta: i64) -> Result<(), TrampolineError> {
        self.push(
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RCX,
                MemoryOperand::with_base_displ(Register::RCX, delta),
            )
            .map_err(encoding_error)?,
        )
    }
    fn branch(&mut self, code: Code, target: u64) -> Result<(), TrampolineError> {
        self.push(Instruction::with_branch(code, target).map_err(encoding_error)?)
    }
    fn check(&mut self, offset: u64, value: u64) -> Result<(), TrampolineError> {
        let next = (self.identity)()?;
        self.load(offset)?;
        if value != 0 {
            self.lea(-(value as i64))?;
        }
        // JRCXZ only crosses this one local JMP, never the full slow helper.
        self.branch(Code::Jrcxz_rel8_64, next)?;
        self.branch(Code::Jmp_rel32_64, self.fault)?;
        self.mark(next);
        Ok(())
    }
    fn record(&mut self, pc: u64, offsets: [u64; 3]) -> Result<(), TrampolineError> {
        self.immediate(pc)?;
        self.store(offsets[0])?;
        self.push(
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, Register::RSP)
                .map_err(encoding_error)?,
        )?;
        self.store(offsets[1])?;
        self.push(
            Instruction::with2(Code::Mov_r64_rm64, Register::RCX, memory(Register::RSP, 0))
                .map_err(encoding_error)?,
        )?;
        self.store(offsets[2])
    }
    fn resume(&mut self, target: u64) -> Result<(), TrampolineError> {
        self.load(SAVED)?;
        self.branch(Code::Jmp_rel32_64, target)
    }
}

pub(super) fn append(
    output: &mut Vec<Instruction>,
    action: &PreContextAction,
    observer: u64,
    body: u64,
    identity: &mut impl FnMut() -> Result<u64, TrampolineError>,
) -> Result<GateSpec, TrampolineError> {
    let fault = identity()?;
    let fast = identity()?;
    let slow = identity()?;
    let mut b = Builder {
        output,
        identity,
        indices: Vec::new(),
        fault,
    };
    b.store(SAVED)?;
    match action.role {
        PreContextRole::Entry => {
            b.check(PHASE, ARMED)?;
            b.check(CHOICE, 0)?;
            b.record(action.logical_pc, [ENTRY_PC, ENTRY_RSP, ENTRY_WORD])?;
            b.immediate(action.selector.address())?;
            // x86-64 aligned MOV implements this AtomicU64 acquire load; the
            // selector is separate retained data and has no non-atomic writer.
            b.push(
                Instruction::with2(Code::Mov_r64_rm64, Register::RCX, memory(Register::RCX, 0))
                    .map_err(encoding_error)?,
            )?;
            b.branch(Code::Jrcxz_rel8_64, fast)?;
            b.lea(-1)?;
            b.branch(Code::Jrcxz_rel8_64, slow)?;
            b.branch(Code::Jmp_rel32_64, fault)?;
            b.mark(fast);
            b.set(CHOICE, FAST)?;
            b.set(PHASE, ENTERED)?;
            b.resume(body)?;
            b.mark(slow);
            b.set(CHOICE, SLOW)?;
            b.set(PHASE, ENTERED)?;
            b.resume(observer)?;
        }
        PreContextRole::Return => {
            b.check(PHASE, ENTERED)?;
            // Check both exact choices before any RET acknowledgement. The
            // exclusive per-call header cannot race with a controller store.
            b.load(CHOICE)?;
            b.lea(-1)?;
            b.branch(Code::Jrcxz_rel8_64, slow)?;
            b.lea(-1)?;
            b.branch(Code::Jrcxz_rel8_64, slow)?;
            b.branch(Code::Jmp_rel32_64, fault)?;
            b.mark(slow);
            b.record(action.logical_pc, [RETURN_PC, RETURN_RSP, RETURN_WORD])?;
            b.set(PHASE, RETURN_OBSERVED)?;
            b.load(CHOICE)?;
            b.lea(-1)?;
            b.branch(Code::Jrcxz_rel8_64, fast)?;
            b.resume(observer)?;
            b.mark(fast);
            b.resume(body)?;
        }
    }
    b.mark(fault);
    let fault_index = b.output.len();
    // A distinct local fail-stop, never a source entry-router key. Invalid RBX
    // itself is outside the unsafe contract; this guards readable corrupt tags.
    b.push(Instruction::with(Code::Ud2))?;
    Ok(GateSpec {
        indices: b.indices,
        fault_index,
    })
}

fn actual_address(
    index: usize,
    address: u64,
    encoded: &BlockEncoderResult,
) -> Result<u64, TrampolineError> {
    let offset = *encoded
        .new_instruction_offsets
        .get(index)
        .filter(|&&value| value != u32::MAX)
        .ok_or_else(|| encoding_error("pre-context gate lost exact instruction"))?;
    address
        .checked_add(u64::from(offset))
        .ok_or_else(|| encoding_error("pre-context gate address overflow"))
}

/// Canonically re-encode every final instruction against exact local labels.
/// Only direct JMP rel8/rel32 relaxation is allowed. JRCXZ stays exactly two
/// bytes; there is no far/indirect gate expansion, prefix, guessed displacement,
/// changed scratch/selector address, or byte patching after the real encoder.
pub(super) fn verify(
    spec: &GateSpec,
    original: &[Instruction],
    address: u64,
    encoded: &BlockEncoderResult,
) -> Result<(), TrampolineError> {
    for &index in &spec.indices {
        let mut expected = original[index];
        let pc = actual_address(index, address, encoded)?;
        let offset = usize::try_from(pc - address).map_err(encoding_error)?;
        let bytes = encoded
            .code_buffer
            .get(offset..)
            .ok_or_else(|| encoding_error("pre-context gate offset exceeds image"))?;
        let observed = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE).decode();
        let jump = expected.code() == Code::Jmp_rel32_64
            && matches!(observed.code(), Code::Jmp_rel8_64 | Code::Jmp_rel32_64);
        if (!jump && observed.code() != expected.code())
            || observed.rflags_modified() != 0
            || !matches!(
                expected.code(),
                Code::Mov_r64_rm64
                    | Code::Mov_rm64_r64
                    | Code::Mov_r64_imm64
                    | Code::Mov_rm64_imm32
                    | Code::Lea_r64_m
                    | Code::Jrcxz_rel8_64
                    | Code::Jmp_rel32_64
                    | Code::Ud2
            )
            || (expected.code() == Code::Ud2 && index != spec.fault_index)
        {
            return Err(encoding_error("pre-context gate opcode/flags changed"));
        }
        if expected.op0_kind() == OpKind::NearBranch64 {
            let target = original
                .iter()
                .position(|i| i.ip() == expected.near_branch_target())
                .ok_or_else(|| encoding_error("pre-context gate target is not a local label"))?;
            expected.set_near_branch64(actual_address(target, address, encoded)?);
        }
        if jump {
            expected.set_code(observed.code());
        }
        let mut encoder = Encoder::new(64);
        encoder.encode(&expected, pc).map_err(encoding_error)?;
        let canonical = encoder.take_buffer();
        if observed.len() != canonical.len()
            || bytes.get(..canonical.len()) != Some(canonical.as_slice())
            || (expected.code() == Code::Jrcxz_rel8_64 && canonical.len() != 2)
        {
            return Err(encoding_error(
                "pre-context gate bytes/operands/width changed",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
