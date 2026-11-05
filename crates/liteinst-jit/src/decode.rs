//! Instruction classification for block formation.
//!
//! Classification is descriptive only; the translator decides what it
//! can copy and refuses everything else by name.

use iced_x86::InstructionInfoFactory;
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

use crate::refuse::Refuse;

/// Nondeterministic/system instructions that end a block and exit
/// to the handler. Identity travels with the exit so a handler can
/// only serve instructions it actually implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NondetKind {
    Cpuid,
    Rdtsc,
    Rdtscp,
    Rdrand,
    Rdseed,
    Rdpid,
    Xgetbv,
}

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
    Nondet(NondetKind),
}

#[derive(Clone, Debug)]
pub struct DecodedInsn {
    pub pc: u64,
    pub len: usize,
    pub class: InsnClass,
    pub instruction: Instruction,
}

fn nondet_kind(code: Code) -> Option<NondetKind> {
    Some(match code {
        Code::Cpuid => NondetKind::Cpuid,
        Code::Rdtsc => NondetKind::Rdtsc,
        Code::Rdtscp => NondetKind::Rdtscp,
        Code::Rdrand_r16 | Code::Rdrand_r32 | Code::Rdrand_r64 => NondetKind::Rdrand,
        Code::Rdseed_r16 | Code::Rdseed_r32 | Code::Rdseed_r64 => NondetKind::Rdseed,
        Code::Rdpid_r64 => NondetKind::Rdpid,
        Code::Xgetbv => NondetKind::Xgetbv,
        _ => return None,
    })
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
    } else if let Some(kind) = nondet_kind(code) {
        InsnClass::Nondet(kind)
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

/// Instructions whose effects are outside the P1a envelope even
/// though they decode: system/state-save/trap forms that copied
/// native execution in the executor process would not serve with
/// guest semantics.
fn refused_mnemonic(m: Mnemonic) -> Option<&'static str> {
    Some(match m {
        Mnemonic::Hlt => "HLT outside P1a envelope",
        Mnemonic::Rdpmc => "RDPMC outside P1a envelope",
        Mnemonic::Rdmsr | Mnemonic::Wrmsr => "MSR access outside P1a envelope",
        Mnemonic::Rdfsbase
        | Mnemonic::Rdgsbase
        | Mnemonic::Wrfsbase
        | Mnemonic::Wrgsbase
        | Mnemonic::Swapgs => "FS/GS base access outside P1a envelope",
        Mnemonic::Getsec | Mnemonic::Invd | Mnemonic::Wbinvd | Mnemonic::Invlpg => {
            "system instruction outside P1a envelope"
        }
        Mnemonic::Monitor
        | Mnemonic::Mwait
        | Mnemonic::Monitorx
        | Mnemonic::Mwaitx
        | Mnemonic::Umonitor
        | Mnemonic::Umwait
        | Mnemonic::Tpause
        | Mnemonic::Rdpru => "counter/wait instruction outside P1a envelope",
        Mnemonic::Rdpkru | Mnemonic::Wrpkru => "PKRU access outside P1a envelope",
        Mnemonic::Ldmxcsr | Mnemonic::Stmxcsr | Mnemonic::Vldmxcsr | Mnemonic::Vstmxcsr => {
            "MXCSR access outside P1a envelope"
        }
        Mnemonic::Ldtilecfg
        | Mnemonic::Sttilecfg
        | Mnemonic::Tileloadd
        | Mnemonic::Tileloaddt1
        | Mnemonic::Tilestored
        | Mnemonic::Tilezero
        | Mnemonic::Tilerelease => "AMX tile state outside P1a envelope",
        Mnemonic::In | Mnemonic::Out => "port I/O outside P1a envelope",
        Mnemonic::Encls | Mnemonic::Serialize => "system instruction outside P1a envelope",
        Mnemonic::Clflush | Mnemonic::Clflushopt | Mnemonic::Clwb | Mnemonic::Cldemote => {
            "cache maintenance outside P1a envelope"
        }
        Mnemonic::Fxsave
        | Mnemonic::Fxsave64
        | Mnemonic::Fxrstor
        | Mnemonic::Fxrstor64
        | Mnemonic::Xsavec
        | Mnemonic::Xsavec64
        | Mnemonic::Xrstor64
        | Mnemonic::Xrstors64
        | Mnemonic::Xsaves64
        | Mnemonic::Xsave
        | Mnemonic::Xsave64
        | Mnemonic::Xsaveopt
        | Mnemonic::Xsaves
        | Mnemonic::Xrstor
        | Mnemonic::Xrstors
        | Mnemonic::Xsetbv => "extended-state save/restore outside P1a envelope",
        Mnemonic::Pushf | Mnemonic::Pushfq | Mnemonic::Popf | Mnemonic::Popfq => {
            "direct flags stack access outside P1a envelope"
        }
        _ => return None,
    })
}

/// First opcode byte(s) after legacy/REX prefixes, for the
/// opcode-space partition below.
fn refused_opcode_space(bytes: &[u8]) -> Option<&'static str> {
    // Skip every legacy prefix and REX byte in any order or
    // repetition: the validated decoder accepts redundant forms
    // (e.g. `40 40`, `40 66`), so a single-REX walk disagrees
    // with it and is unsound. Only the instruction's own decoded
    // byte extent is scanned by callers.
    let mut i = 0;
    while i < bytes.len()
        && (matches!(
            bytes[i],
            0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67
        ) || (0x40..=0x4f).contains(&bytes[i]))
    {
        i += 1;
    }
    match bytes.get(i) {
        Some(0x0f) => match bytes.get(i + 1) {
            Some(0x01) => Some("0F 01 system opcode space outside P1a envelope"),
            Some(0xae) => Some("0F AE system/save opcode space outside P1a envelope"),
            _ => None,
        },
        Some(0xd8..=0xdf) => Some("x87 opcode space outside P1a envelope"),
        // Two-byte VEX: implied 0F map, opcode follows.
        Some(0xc5) => match bytes.get(i + 2) {
            Some(0x01) => Some("VEX 0F 01 system opcode space outside P1a envelope"),
            Some(0xae) => Some("VEX 0F AE system/save opcode space outside P1a envelope"),
            _ => None,
        },
        // Three-byte VEX / XOP: low five bits of byte 1 select the map.
        Some(0xc4) | Some(0x8f) => {
            let map = bytes.get(i + 1).map_or(0, |b| b & 0x1f);
            if map == 1 {
                match bytes.get(i + 3) {
                    Some(0x01) => Some("VEX 0F 01 system opcode space outside P1a envelope"),
                    Some(0xae) => Some("VEX 0F AE system/save opcode space outside P1a envelope"),
                    _ => None,
                }
            } else {
                None
            }
        }
        // EVEX: mm bits (byte 2, bits 1:0) select the map.
        Some(0x62) => {
            let map = bytes.get(i + 1).map_or(0, |b| b & 0x03);
            if map == 1 {
                match bytes.get(i + 4) {
                    Some(0x01) => Some("EVEX 0F 01 system opcode space outside P1a envelope"),
                    Some(0xae) => Some("EVEX 0F AE system/save opcode space outside P1a envelope"),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}
/// Decode one instruction and admit it only if its effects are
/// inside the explicit P1a envelope. Ordinary instructions must be
/// plain next-instruction flow over GPRs/memory: no privilege, no
/// segment/CR/DR/TR/vector/x87/mask registers (explicit or
/// implicit), no segment override, no transactional prefixes, and
/// no refused mnemonic. Control/syscall/nondet classes keep their
/// existing exit semantics; anything else refuses by name. A
/// permissive decoder fallback is not a relocation proof.
pub fn decode_supported(bytes: &[u8], pc: u64) -> Result<DecodedInsn, Refuse> {
    let d = decode_one(bytes, pc).ok_or(Refuse::Decode { src_pc: pc })?;
    let ins = &d.instruction;
    match d.class {
        InsnClass::Ordinary => {
            if ins.flow_control() != FlowControl::Next {
                return Err(Refuse::Unrelocatable {
                    src_pc: pc,
                    reason: "unsupported control flow outside P1a envelope",
                });
            }
            if ins.is_privileged() {
                return Err(Refuse::Unrelocatable {
                    src_pc: pc,
                    reason: "privileged instruction outside P1a envelope",
                });
            }
            if let Some(reason) = refused_mnemonic(ins.mnemonic()) {
                return Err(Refuse::Unrelocatable { src_pc: pc, reason });
            }
            if ins.segment_prefix() != Register::None {
                return Err(Refuse::Unrelocatable {
                    src_pc: pc,
                    reason: "segment override outside P1a envelope",
                });
            }
            if ins.is_save_restore_instruction() {
                return Err(Refuse::Unrelocatable {
                    src_pc: pc,
                    reason: "save/restore instruction outside P1a envelope",
                });
            }
            // Family/encoding coverage for hidden architectural
            // state that register-use metadata does not enumerate:
            // the 0F 01 (system: PKRU, counters, SGX, serialize,
            // shadow-stack) and 0F AE (save/restore, MXCSR, fences,
            // WAITPKG) maps and the x87 ESC map are refused as
            // spaces, not example-by-example.
            if let Some(reason) = refused_opcode_space(bytes) {
                return Err(Refuse::Unrelocatable { src_pc: pc, reason });
            }
            if ins.has_xacquire_prefix() || ins.has_xrelease_prefix() {
                return Err(Refuse::Unrelocatable {
                    src_pc: pc,
                    reason: "transactional prefix outside P1a envelope",
                });
            }
            let mut factory = InstructionInfoFactory::new();
            let info = factory.info(ins);
            for used in info.used_registers() {
                let r: Register = used.register();
                if r != Register::None && !r.is_gpr() && !r.is_ip() {
                    return Err(Refuse::Unrelocatable {
                        src_pc: pc,
                        reason: "non-GPR register effect outside P1a envelope",
                    });
                }
            }
        }
        InsnClass::Return if !matches!(ins.code(), Code::Retnq | Code::Retnq_imm16) => {
            return Err(Refuse::Unrelocatable {
                src_pc: pc,
                reason: "far/other return outside P1a envelope",
            });
        }
        InsnClass::Return => {}
        _ => {}
    }
    Ok(d)
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
            InsnClass::Nondet(NondetKind::Cpuid)
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
