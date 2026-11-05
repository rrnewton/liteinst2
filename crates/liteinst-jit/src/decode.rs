//! Instruction classification for block formation.
//!
//! Classification is descriptive only; the translator decides what it
//! can copy and refuses everything else by name.

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsnClass {
    Ordinary,
    /// Direct conditional branch (including `LOOPcc`/`JRCXZ`, flagged
    /// loop-like because they have no near encoding).
    CondBranch {
        target: u64,
        loop_like: bool,
    },
    DirectJump {
        target: u64,
    },
    DirectCall {
        target: u64,
    },
    Return,
    Indirect,
    Syscall,
    Nondet,
}

#[derive(Clone, Debug)]
pub struct DecodedInsn {
    pub pc: u64,
    pub len: usize,
    pub class: InsnClass,
    pub instruction: Instruction,
}

fn is_nondet(code: Code) -> bool {
    matches!(
        code,
        Code::Cpuid
            | Code::Rdtsc
            | Code::Rdtscp
            | Code::Rdrand_r16
            | Code::Rdrand_r32
            | Code::Rdrand_r64
            | Code::Rdseed_r16
            | Code::Rdseed_r32
            | Code::Rdseed_r64
            | Code::Rdpid_r64
            | Code::Xgetbv
    )
}

fn is_syscall_class(code: Code, mnemonic: Mnemonic) -> bool {
    matches!(
        code,
        Code::Syscall | Code::Sysenter | Code::Sysretd | Code::Sysretq
    ) || mnemonic == Mnemonic::Int
        || mnemonic == Mnemonic::Into
        || mnemonic == Mnemonic::Iret
}

fn is_loop_like(code: Code, mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne
    ) || matches!(code, Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64)
}

/// Decode one instruction at `pc` from `bytes` (the bytes at `pc`).
/// Returns `None` for invalid or truncated encodings.
pub fn decode_one(bytes: &[u8], pc: u64) -> Option<DecodedInsn> {
    let mut decoder = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let ins = decoder.decode();
    if ins.is_invalid() || ins.len() == 0 || ins.len() > bytes.len() {
        return None;
    }
    let code = ins.code();
    let class = if is_syscall_class(code, ins.mnemonic()) {
        InsnClass::Syscall
    } else if is_nondet(code) {
        InsnClass::Nondet
    } else if ins.mnemonic() == Mnemonic::Ret {
        InsnClass::Return
    } else if is_loop_like(code, ins.mnemonic()) || code.is_jcc_short() || code.is_jcc_near() {
        if ins.op_count() == 1 && ins.op0_kind() == OpKind::NearBranch64 {
            InsnClass::CondBranch {
                target: ins.near_branch64(),
                loop_like: is_loop_like(code, ins.mnemonic()),
            }
        } else {
            InsnClass::Indirect
        }
    } else if code.is_jmp_short() || code.is_jmp_near() {
        if ins.op_count() == 1 && ins.op0_kind() == OpKind::NearBranch64 {
            InsnClass::DirectJump {
                target: ins.near_branch64(),
            }
        } else {
            InsnClass::Indirect
        }
    } else if code.is_call_near() {
        if ins.op_count() == 1 && ins.op0_kind() == OpKind::NearBranch64 {
            InsnClass::DirectCall {
                target: ins.near_branch64(),
            }
        } else {
            InsnClass::Indirect
        }
    } else if ins.mnemonic() == Mnemonic::Jmp || ins.mnemonic() == Mnemonic::Call {
        InsnClass::Indirect
    } else {
        InsnClass::Ordinary
    };
    Some(DecodedInsn {
        pc,
        len: ins.len(),
        class,
        instruction: ins,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_forms() {
        // nop; add rax,1
        assert_eq!(
            decode_one(&[0x90], 0x1000).unwrap().class,
            InsnClass::Ordinary
        );
        // je +2 (short)
        let d = decode_one(&[0x74, 0x02], 0x1000).unwrap();
        assert_eq!(
            d.class,
            InsnClass::CondBranch {
                target: 0x1004,
                loop_like: false
            }
        );
        // syscall
        assert_eq!(
            decode_one(&[0x0f, 0x05], 0x1000).unwrap().class,
            InsnClass::Syscall
        );
        // cpuid
        assert_eq!(
            decode_one(&[0x0f, 0xa2], 0x1000).unwrap().class,
            InsnClass::Nondet
        );
        // jmp rax
        assert_eq!(
            decode_one(&[0xff, 0xe0], 0x1000).unwrap().class,
            InsnClass::Indirect
        );
        // ret
        assert_eq!(
            decode_one(&[0xc3], 0x1000).unwrap().class,
            InsnClass::Return
        );
        // loop -2
        let d = decode_one(&[0xe2, 0xfe], 0x1000).unwrap();
        assert_eq!(
            d.class,
            InsnClass::CondBranch {
                target: 0x1000,
                loop_like: true
            }
        );
        // invalid: truncated mov rax,imm64
        assert!(decode_one(&[0x48, 0xb8, 0x01], 0x1000).is_none());
    }
}
