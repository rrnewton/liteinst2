//! Instruction classification for block formation.
//!
//! Classification is descriptive only; the translator decides what it
//! can copy and refuses everything else by name.

use liteinst_x86::{
    Code, Decoder, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register, decoder64,
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

fn classify(ins: &Instruction) -> InsnClass {
    let code = ins.code();
    if is_syscall_class(code, ins.mnemonic()) {
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
    }
}

fn decoded_from(ins: Instruction, pc: u64, remaining_len: usize) -> Option<DecodedInsn> {
    if ins.is_invalid() || ins.len() == 0 || ins.len() > remaining_len {
        return None;
    }
    Some(DecodedInsn {
        pc,
        len: ins.len(),
        class: classify(&ins),
        instruction: ins,
    })
}

/// Decode one instruction at `pc` from `bytes` (the bytes at `pc`).
/// Returns `None` for invalid or truncated encodings.
pub fn decode_one(bytes: &[u8], pc: u64) -> Option<DecodedInsn> {
    let mut decoder = decoder64(bytes, pc);
    if !decoder.can_decode() {
        return None;
    }
    decoded_from(decoder.decode(), pc, bytes.len())
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
        Mnemonic::Emms | Mnemonic::Femms | Mnemonic::Wait => {
            "x87/MMX state instruction outside P1a envelope"
        }
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

/// A segment register as an explicit operand: `mov` to or from a
/// segment register and `push`/`pop` of one. These read or write a
/// selector, not an address.
const SEGMENT_REGISTER_OPERAND: &str = "segment register operand outside P1a envelope";
/// An FS/GS override on a string instruction. String operands are
/// implicit (`[rsi]`, `[rdi]`); P1a admits FS/GS only on an explicit
/// memory operand.
const FS_GS_ON_STRING: &str = "FS/GS override on string instruction outside P1a envelope";
/// An FS/GS override on a RIP-relative operand. Relocation re-encodes
/// RIP-relative operands; this form has no known compiler source and
/// is refused instead of relocated.
const FS_GS_RIP_RELATIVE: &str = "FS/GS override on RIP-relative operand outside P1a envelope";
/// An FS/GS override that forms no address through the segment: no
/// memory operand, or one iced does not report as formed through it
/// (`lea`, `nop r/m`; a prefetch hint does, and is admitted).
const FS_GS_WITHOUT_MEMORY_ACCESS: &str =
    "FS/GS override without a memory access outside P1a envelope";
/// A segment override register outside ES, CS, SS, DS, FS and GS.
const SEGMENT_OVERRIDE_UNKNOWN: &str = "segment override outside P1a envelope";

/// Refuse any explicit segment-register operand, read or write.
/// Together with the allowlist (which already refuses `lfs`, `lgs`,
/// `lss`, `rdfsbase`, `rdgsbase`, `wrfsbase`, `wrgsbase` and
/// `swapgs`), this keeps every write to a segment register or a
/// segment base outside the envelope.
fn refused_segment_register_operand(ins: &Instruction) -> Option<&'static str> {
    (0..ins.op_count())
        .any(|i| ins.op_kind(i) == OpKind::Register && ins.op_register(i).is_segment_register())
        .then_some(SEGMENT_REGISTER_OPERAND)
}

/// Segment-override admission (P1a). Returns the admitted FS or
/// GS override, `None` for no override or an ES, CS, SS or DS one,
/// or the refusal reason.
///
/// - ES, CS, SS and DS overrides are admitted: 64-bit mode ignores
///   them for address formation (base 0, no limit check), and the
///   copied instruction keeps the prefix byte, so it behaves exactly
///   as it does natively. A RIP-relative operand is re-encoded with
///   the prefix kept; a re-encode that changes length refuses.
/// - FS and GS select the executing thread's TLS base. The copy runs
///   on the thread state a native run would see: in remote mode the
///   tracee thread's own FS/GS bases, which the dispatcher never
///   writes (it sets only the general registers, RIP and RFLAGS); in
///   process the host thread's, which is the thread the code runs
///   on. An FS/GS override is admitted only where it forms the
///   address of an explicit memory operand (load, store, RMW,
///   push/pop r/m, moffs, prefetch hint): this returns it, and the
///   caller requires iced to report that segment as read (iced does
///   for an address-forming operand, not for `lea` or `nop r/m`) and
///   allows it as the one non-GPR register.
/// - Refused, each by name: FS/GS on a string instruction or on a
///   RIP-relative operand (here), and FS/GS without a memory access
///   (in the caller: no memory operand, or `lea`/`nop r/m`).
/// - `rdfsbase`/`rdgsbase` stay refused (by the allowlist). They
///   expose the TLS base as a data value rather than forming an
///   address with it, and user-mode FSGSBASE access depends on the
///   kernel enabling it (#UD otherwise), a host property this
///   envelope does not model.
fn admitted_segment_override(ins: &Instruction) -> Result<Option<Register>, &'static str> {
    let seg = ins.segment_prefix();
    match seg {
        Register::None | Register::ES | Register::CS | Register::SS | Register::DS => Ok(None),
        Register::FS | Register::GS => {
            if (0..ins.op_count()).any(|i| {
                matches!(
                    ins.op_kind(i),
                    OpKind::MemorySegSI
                        | OpKind::MemorySegESI
                        | OpKind::MemorySegRSI
                        | OpKind::MemoryESDI
                        | OpKind::MemoryESEDI
                        | OpKind::MemorySegDI
                        | OpKind::MemorySegEDI
                        | OpKind::MemorySegRDI
                        | OpKind::MemoryESRDI
                )
            }) {
                return Err(FS_GS_ON_STRING);
            }
            if ins.is_ip_rel_memory_operand() {
                return Err(FS_GS_RIP_RELATIVE);
            }
            Ok(Some(seg))
        }
        _ => Err(SEGMENT_OVERRIDE_UNKNOWN),
    }
}

/// Positive admission list for Ordinary instructions: every
/// mnemonic here has effects only on GPRs, RFLAGS, the guest
/// stack, and ordinary memory operands, which copied native
/// execution reproduces exactly. Anything not listed refuses by
/// name — a denylist of hidden-state families cannot prove
/// totality (round-3/5 reviews), so admission is allowlist-first
/// and the family guards below are a second layer.
fn allowed_ordinary(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Movbe
            | Mnemonic::Lea
            | Mnemonic::Xchg
            | Mnemonic::Xadd
            | Mnemonic::Cmpxchg
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Leave
            | Mnemonic::Nop
            | Mnemonic::Pause
            | Mnemonic::Endbr64
            | Mnemonic::Endbr32
            | Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::Sub
            | Mnemonic::Sbb
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Not
            | Mnemonic::Imul
            | Mnemonic::Mul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Bt
            | Mnemonic::Bts
            | Mnemonic::Btr
            | Mnemonic::Btc
            | Mnemonic::Bsf
            | Mnemonic::Bsr
            | Mnemonic::Tzcnt
            | Mnemonic::Lzcnt
            | Mnemonic::Popcnt
            | Mnemonic::Bswap
            | Mnemonic::Cbw
            | Mnemonic::Cwde
            | Mnemonic::Cdqe
            | Mnemonic::Cwd
            | Mnemonic::Cdq
            | Mnemonic::Cqo
            | Mnemonic::Lahf
            | Mnemonic::Sahf
            | Mnemonic::Cld
            | Mnemonic::Std
            | Mnemonic::Cmova
            | Mnemonic::Cmovae
            | Mnemonic::Cmovb
            | Mnemonic::Cmovbe
            | Mnemonic::Cmove
            | Mnemonic::Cmovg
            | Mnemonic::Cmovge
            | Mnemonic::Cmovl
            | Mnemonic::Cmovle
            | Mnemonic::Cmovne
            | Mnemonic::Cmovno
            | Mnemonic::Cmovnp
            | Mnemonic::Cmovns
            | Mnemonic::Cmovo
            | Mnemonic::Cmovp
            | Mnemonic::Cmovs
            | Mnemonic::Seta
            | Mnemonic::Setae
            | Mnemonic::Setb
            | Mnemonic::Setbe
            | Mnemonic::Sete
            | Mnemonic::Setg
            | Mnemonic::Setge
            | Mnemonic::Setl
            | Mnemonic::Setle
            | Mnemonic::Setne
            | Mnemonic::Setno
            | Mnemonic::Setnp
            | Mnemonic::Setns
            | Mnemonic::Seto
            | Mnemonic::Setp
            | Mnemonic::Sets
            | Mnemonic::Movsb
            | Mnemonic::Movsw
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
            | Mnemonic::Prefetchnta
            | Mnemonic::Prefetcht0
            | Mnemonic::Prefetcht1
            | Mnemonic::Prefetcht2
            | Mnemonic::Prefetchw
    )
}

/// Decode one instruction and admit it only if its effects are
/// inside the explicit P1a envelope. Ordinary instructions must be
/// plain next-instruction flow over GPRs/memory: no privilege, no
/// segment/CR/DR/TR/vector/x87/mask registers (explicit or
/// implicit), no segment override except those
/// `admitted_segment_override` admits (ES/CS/SS/DS, and FS/GS
/// forming a memory operand's address), no transactional prefixes,
/// and no refused mnemonic. Control/syscall/nondet classes keep their
/// existing exit semantics; anything else refuses by name. A
/// permissive decoder fallback is not a relocation proof.
pub fn decode_supported(bytes: &[u8], pc: u64) -> Result<DecodedInsn, Refuse> {
    let d = decode_one(bytes, pc).ok_or(Refuse::Decode { src_pc: pc })?;
    let mut factory = InstructionInfoFactory::new();
    admit_supported(d, bytes, &mut factory)
}

fn admit_supported(
    d: DecodedInsn,
    bytes: &[u8],
    factory: &mut InstructionInfoFactory,
) -> Result<DecodedInsn, Refuse> {
    let pc = d.pc;
    let ins = &d.instruction;
    match d.class {
        InsnClass::Ordinary => {
            if !allowed_ordinary(ins.mnemonic()) {
                return Err(Refuse::Unrelocatable {
                    src_pc: pc,
                    reason: "mnemonic outside modeled P1a envelope",
                });
            }
            for i in 0..ins.op_count() {
                match ins.op_kind(i) {
                    OpKind::Register
                    | OpKind::Memory
                    | OpKind::MemorySegSI
                    | OpKind::MemorySegESI
                    | OpKind::MemorySegRSI
                    | OpKind::MemoryESDI
                    | OpKind::MemoryESEDI
                    | OpKind::MemorySegDI
                    | OpKind::MemorySegEDI
                    | OpKind::MemorySegRDI
                    | OpKind::MemoryESRDI
                    | OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64 => {}
                    _ => {
                        return Err(Refuse::Unrelocatable {
                            src_pc: pc,
                            reason: "operand kind outside modeled P1a envelope",
                        });
                    }
                }
            }
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
            if let Some(reason) = refused_segment_register_operand(ins) {
                return Err(Refuse::Unrelocatable { src_pc: pc, reason });
            }
            let tls_segment = match admitted_segment_override(ins) {
                Ok(seg) => seg,
                Err(reason) => return Err(Refuse::Unrelocatable { src_pc: pc, reason }),
            };
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
            let info = factory.info(ins);
            // An FS/GS read stands for an address-forming operand only
            // because explicit segment-register operands (`push fs`,
            // `mov eax, fs`, which also report an FS read) are refused
            // above, by `refused_segment_register_operand`.
            if let Some(seg) = tls_segment
                && !info
                    .used_registers()
                    .any(|u| u.register() == seg && u.access() == OpAccess::Read)
            {
                return Err(Refuse::Unrelocatable {
                    src_pc: pc,
                    reason: FS_GS_WITHOUT_MEMORY_ACCESS,
                });
            }
            for used in info.used_registers() {
                let r: Register = used.register();
                // The admitted FS/GS override: the segment is read to
                // form the memory operand's address, and nothing else.
                if Some(r) == tls_segment && used.access() == OpAccess::Read {
                    continue;
                }
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

/// Reusable streaming form of [`decode_supported`] over one source
/// region. It retains a single iced decoder and instruction-info
/// factory across block discovery; `reset` repositions both the
/// byte cursor and IP for a new block start. Admission semantics
/// are shared with `decode_supported` through `admit_supported`.
pub struct SupportedDecoder<'a> {
    decoder: Decoder<'a>,
    factory: InstructionInfoFactory,
    bytes: &'a [u8],
    base: u64,
}

impl<'a> SupportedDecoder<'a> {
    pub fn new(bytes: &'a [u8], base: u64) -> Self {
        Self {
            decoder: decoder64(bytes, base),
            factory: InstructionInfoFactory::new(),
            bytes,
            base,
        }
    }

    /// Position the stream at source PC `pc` inside the region.
    pub fn reset(&mut self, pc: u64) -> Result<(), Refuse> {
        let offset = pc
            .checked_sub(self.base)
            .and_then(|o| usize::try_from(o).ok())
            .ok_or(Refuse::Decode { src_pc: pc })?;
        self.decoder
            .set_position(offset)
            .map_err(|_| Refuse::Decode { src_pc: pc })?;
        self.decoder.set_ip(pc);
        Ok(())
    }

    /// Decode and admit the next instruction in the stream.
    pub fn next_supported(&mut self) -> Result<DecodedInsn, Refuse> {
        let pc = self.decoder.ip();
        let offset = self.decoder.position();
        let all: &'a [u8] = self.bytes;
        let Some(bytes) = all.get(offset..) else {
            return Err(Refuse::Decode { src_pc: pc });
        };
        if !self.decoder.can_decode() {
            return Err(Refuse::Decode { src_pc: pc });
        }
        let d = decoded_from(self.decoder.decode(), pc, bytes.len())
            .ok_or(Refuse::Decode { src_pc: pc })?;
        if self.decoder.position() != offset + d.len
            || self.decoder.ip() != pc.wrapping_add(d.len as u64)
        {
            return Err(Refuse::Decode { src_pc: pc });
        }
        admit_supported(d, bytes, &mut self.factory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_decode_corpus_admits_only_allowlisted_mnemonics() {
        // Walk legacy, 0F, prefix-repeated, VEX2/VEX3 and EVEX
        // template spaces. Any Ordinary instruction the envelope
        // admits from this corpus must be on the positive list;
        // anything else must have refused in decode_supported.
        let mut admitted = 0u32;
        let mut check = |bytes: &[u8]| {
            if let Ok(d) = decode_supported(bytes, 0x1000)
                && matches!(d.class, InsnClass::Ordinary)
            {
                admitted += 1;
                assert!(
                    allowed_ordinary(d.instruction.mnemonic()),
                    "admitted non-allowlisted {:?} from {bytes:02x?}",
                    d.instruction.mnemonic()
                );
            }
        };
        for b0 in 0u16..=0xff {
            let b = b0 as u8;
            check(&[b, 0, 0, 0, 0, 0, 0, 0, 0xc3]);
            check(&[0x48, b, 0, 0, 0, 0, 0, 0, 0xc3]);
            check(&[0xf3, b, 0, 0, 0, 0, 0, 0, 0xc3]);
            check(&[0x0f, b, 0, 0, 0, 0, 0, 0, 0xc3]);
            check(&[0x0f, 0x38, b, 0, 0, 0, 0, 0, 0xc3]);
            check(&[0x0f, 0x3a, b, 0, 0, 0, 0, 0, 0xc3]);
            check(&[0x40, 0x40, b, 0, 0, 0, 0, 0, 0xc3]);
            check(&[0xc5, 0xf8, b, 0, 0, 0, 0xc3]);
            check(&[0xc4, 0xe1, 0x78, b, 0, 0xc3]);
            check(&[0xc4, 0xe2, 0x79, b, 0, 0xc3]);
            check(&[0x62, 0xf1, 0x7c, 0x48, b, 0, 0xc3]);
        }
        for b0 in 0u16..=0xff {
            check(&[0xd8 + (b0 % 8) as u8, b0 as u8, 0, 0, 0xc3]);
        }
        assert!(admitted > 100, "corpus walk is vacuous: {admitted}");
    }

    /// The `Unrelocatable` reason `bytes` refuses with, or `None`
    /// when admitted. Any other refusal fails the caller.
    fn seg_refusal(bytes: &[u8]) -> Option<&'static str> {
        match decode_supported(bytes, 0x1000) {
            Ok(d) => {
                assert_eq!(d.len, bytes.len(), "{bytes:02x?}: one whole instruction");
                None
            }
            Err(Refuse::Unrelocatable { reason, .. }) => Some(reason),
            Err(e) => panic!("{bytes:02x?}: unexpected refusal {e:?}"),
        }
    }

    /// Segment overrides: FS/GS forming an explicit memory operand's address is
    /// admitted (every shape a TLS read, a TLS write or the
    /// stack-protector canary takes), and so are ES, CS, SS and DS,
    /// which 64-bit mode ignores. One case per prefix form and operand
    /// shape; each must also decode as Ordinary with that prefix.
    #[test]
    fn segment_override_admits() {
        let cases: &[(&str, &[u8], Register)] = &[
            (
                "mov rax, fs:[0x28]",
                &[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            (
                "mov rax, fs:[0]",
                &[0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0],
                Register::FS,
            ),
            (
                "mov rax, fs:moffs64",
                &[0x64, 0x48, 0xa1, 0x28, 0, 0, 0, 0, 0, 0, 0],
                Register::FS,
            ),
            (
                "mov fs:[0x28], rcx",
                &[0x64, 0x48, 0x89, 0x0c, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            (
                "xor rdx, fs:[0x28]",
                &[0x64, 0x48, 0x33, 0x14, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            (
                "sub rax, fs:[0x28]",
                &[0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            (
                "cmp rcx, fs:[0x28]",
                &[0x64, 0x48, 0x3b, 0x0c, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            ("mov rdx, fs:[rcx]", &[0x64, 0x48, 0x8b, 0x11], Register::FS),
            ("mov eax, fs:[eax]", &[0x64, 0x67, 0x8b, 0x00], Register::FS),
            (
                "xchg fs:[0x28], rax",
                &[0x64, 0x48, 0x87, 0x04, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            (
                "lock cmpxchg fs:[0x10], rcx",
                &[0xf0, 0x64, 0x48, 0x0f, 0xb1, 0x0c, 0x25, 0x10, 0, 0, 0],
                Register::FS,
            ),
            (
                "push qword fs:[0x10]",
                &[0x64, 0xff, 0x34, 0x25, 0x10, 0, 0, 0],
                Register::FS,
            ),
            (
                "pop qword fs:[0x10]",
                &[0x64, 0x8f, 0x04, 0x25, 0x10, 0, 0, 0],
                Register::FS,
            ),
            (
                "mov rax, gs:[0x40]",
                &[0x65, 0x48, 0x8b, 0x04, 0x25, 0x40, 0, 0, 0],
                Register::GS,
            ),
            ("mov rax, gs:[rax]", &[0x65, 0x48, 0x8b, 0x00], Register::GS),
            // Redundant prefixes: the copy is byte-exact, and 64-bit
            // mode lets FS win over an ignored DS in either order.
            ("fs ds mov", &[0x64, 0x3e, 0x48, 0x8b, 0x03], Register::FS),
            ("ds fs mov", &[0x3e, 0x64, 0x48, 0x8b, 0x03], Register::FS),
            ("fs fs mov", &[0x64, 0x64, 0x48, 0x8b, 0x03], Register::FS),
            // FS and GS together: iced takes the last one.
            ("fs gs mov", &[0x64, 0x65, 0x48, 0x8b, 0x03], Register::GS),
            ("gs fs mov", &[0x65, 0x64, 0x48, 0x8b, 0x03], Register::FS),
            (
                "cmove rax, fs:[0x28]",
                &[0x64, 0x48, 0x0f, 0x44, 0x04, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            (
                "sete byte fs:[0x10]",
                &[0x64, 0x0f, 0x94, 0x04, 0x25, 0x10, 0, 0, 0],
                Register::FS,
            ),
            (
                "movzx eax, byte fs:[0x10]",
                &[0x64, 0x0f, 0xb6, 0x04, 0x25, 0x10, 0, 0, 0],
                Register::FS,
            ),
            (
                "movsxd rax, dword fs:[0x10]",
                &[0x64, 0x48, 0x63, 0x04, 0x25, 0x10, 0, 0, 0],
                Register::FS,
            ),
            (
                "bt dword fs:[0x10], 3",
                &[0x64, 0x0f, 0xba, 0x24, 0x25, 0x10, 0, 0, 0, 0x03],
                Register::FS,
            ),
            (
                "mov ax, fs:[0x28] (66h)",
                &[0x64, 0x66, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0],
                Register::FS,
            ),
            // A prefetch forms its address through FS (iced reports the
            // read); it is a hint that cannot fault, copied natively.
            (
                "prefetcht0 fs:[rax]",
                &[0x64, 0x0f, 0x18, 0x08],
                Register::FS,
            ),
            ("mov rax, ds:[rbx]", &[0x3e, 0x48, 0x8b, 0x03], Register::DS),
            ("mov rax, cs:[rbx]", &[0x2e, 0x48, 0x8b, 0x03], Register::CS),
            ("mov rax, es:[rbx]", &[0x26, 0x48, 0x8b, 0x03], Register::ES),
            ("mov rax, ss:[rbx]", &[0x36, 0x48, 0x8b, 0x03], Register::SS),
            (
                "mov rax, ds:[rip+0x10]",
                &[0x3e, 0x48, 0x8b, 0x05, 0x10, 0, 0, 0],
                Register::DS,
            ),
            (
                "nopw cs:[rax+rax] (compiler padding)",
                &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0, 0, 0, 0],
                Register::CS,
            ),
            ("cs nop", &[0x2e, 0x90], Register::CS),
            ("ds movsb", &[0x3e, 0xa4], Register::DS),
            ("es lea", &[0x26, 0x48, 0x8d, 0x03], Register::ES),
        ];
        for (name, bytes, seg) in cases {
            assert_eq!(seg_refusal(bytes), None, "{name}: must be admitted");
            let d = decode_one(bytes, 0x1000).unwrap();
            assert_eq!(d.class, InsnClass::Ordinary, "{name}: class");
            assert_eq!(d.instruction.segment_prefix(), *seg, "{name}: prefix");
        }
    }

    /// Segment overrides: every segment form outside the envelope refuses with its
    /// own reason: segment-register operands (selector reads and
    /// writes), FS/GS on string instructions, on RIP-relative
    /// operands and without a memory access. Writes to a segment base
    /// and segment loads stay refused by the allowlist, by name.
    #[test]
    fn segment_override_refuses_by_name() {
        const MNEMONIC: &str = "mnemonic outside modeled P1a envelope";
        let cases: &[(&str, &[u8], &str)] = &[
            ("mov fs, eax", &[0x8e, 0xe0], SEGMENT_REGISTER_OPERAND),
            ("mov gs, eax", &[0x8e, 0xe8], SEGMENT_REGISTER_OPERAND),
            ("mov ss, eax", &[0x8e, 0xd0], SEGMENT_REGISTER_OPERAND),
            ("mov fs, [rbx]", &[0x8e, 0x23], SEGMENT_REGISTER_OPERAND),
            ("mov eax, fs", &[0x8c, 0xe0], SEGMENT_REGISTER_OPERAND),
            ("mov [rbx], gs", &[0x8c, 0x2b], SEGMENT_REGISTER_OPERAND),
            // The FS read here is a selector store through an FS
            // address: the operand check runs first.
            (
                "mov fs:[rbx], fs",
                &[0x64, 0x8c, 0x23],
                SEGMENT_REGISTER_OPERAND,
            ),
            ("pop fs", &[0x0f, 0xa1], SEGMENT_REGISTER_OPERAND),
            ("pop gs", &[0x0f, 0xa9], SEGMENT_REGISTER_OPERAND),
            ("push fs", &[0x0f, 0xa0], SEGMENT_REGISTER_OPERAND),
            ("push gs", &[0x0f, 0xa8], SEGMENT_REGISTER_OPERAND),
            ("lfs eax, [rbx]", &[0x0f, 0xb4, 0x03], MNEMONIC),
            ("lgs eax, [rbx]", &[0x0f, 0xb5, 0x03], MNEMONIC),
            ("lss eax, [rbx]", &[0x0f, 0xb2, 0x03], MNEMONIC),
            ("rdfsbase rax", &[0xf3, 0x48, 0x0f, 0xae, 0xc0], MNEMONIC),
            ("rdgsbase rax", &[0xf3, 0x48, 0x0f, 0xae, 0xc8], MNEMONIC),
            ("wrfsbase rax", &[0xf3, 0x48, 0x0f, 0xae, 0xd0], MNEMONIC),
            ("wrgsbase rax", &[0xf3, 0x48, 0x0f, 0xae, 0xd8], MNEMONIC),
            ("swapgs", &[0x0f, 0x01, 0xf8], MNEMONIC),
            ("fs movsb", &[0x64, 0xa4], FS_GS_ON_STRING),
            ("gs lodsq", &[0x65, 0x48, 0xad], FS_GS_ON_STRING),
            ("fs cmpsb", &[0x64, 0xa6], FS_GS_ON_STRING),
            ("rep fs stosb", &[0xf3, 0x64, 0xaa], FS_GS_ON_STRING),
            (
                "mov rax, fs:[rip+0x10]",
                &[0x64, 0x48, 0x8b, 0x05, 0x10, 0, 0, 0],
                FS_GS_RIP_RELATIVE,
            ),
            (
                "mov gs:[rip+0x10], rax",
                &[0x65, 0x48, 0x89, 0x05, 0x10, 0, 0, 0],
                FS_GS_RIP_RELATIVE,
            ),
            ("fs nop", &[0x64, 0x90], FS_GS_WITHOUT_MEMORY_ACCESS),
            (
                "gs add rax, rcx",
                &[0x65, 0x48, 0x01, 0xc8],
                FS_GS_WITHOUT_MEMORY_ACCESS,
            ),
            (
                "lea rax, fs:[0x28]",
                &[0x64, 0x48, 0x8d, 0x04, 0x25, 0x28, 0, 0, 0],
                FS_GS_WITHOUT_MEMORY_ACCESS,
            ),
            (
                "nopw fs:[rax+rax]",
                &[0x66, 0x64, 0x0f, 0x1f, 0x84, 0x00, 0, 0, 0, 0],
                FS_GS_WITHOUT_MEMORY_ACCESS,
            ),
        ];
        for (name, bytes, reason) in cases {
            assert_eq!(seg_refusal(bytes), Some(*reason), "{name}: refusal reason");
        }
    }

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

    #[test]
    fn streaming_decoder_matches_supported_reference() {
        fn assert_same(actual: &DecodedInsn, expected: &DecodedInsn) {
            assert_eq!(actual.pc, expected.pc);
            assert_eq!(actual.len, expected.len);
            assert_eq!(actual.class, expected.class);
            assert_eq!(actual.instruction.code(), expected.instruction.code());
            assert_eq!(
                actual.instruction.mnemonic(),
                expected.instruction.mnemonic()
            );
            assert_eq!(actual.instruction.ip(), expected.instruction.ip());
            assert_eq!(actual.instruction.next_ip(), expected.instruction.next_ip());
            assert_eq!(
                actual.instruction.op_count(),
                expected.instruction.op_count()
            );
        }

        // xor eax,eax; inc eax; cmp eax,3; jne -6; ret
        let bytes = [0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x03, 0x75, 0xf9, 0xc3];
        let mut stream = SupportedDecoder::new(&bytes, 0x1000);
        let mut offset = 0usize;
        for _ in 0..5 {
            let pc = 0x1000 + offset as u64;
            let expected = decode_supported(&bytes[offset..], pc).unwrap();
            let actual = stream.next_supported().unwrap();
            assert_same(&actual, &expected);
            offset += expected.len;
        }
        assert_eq!(offset, bytes.len());

        // Reset repositions both byte cursor and IP to a later
        // block start, matching a fresh supported decode there.
        stream.reset(0x1002).unwrap();
        let expected = decode_supported(&bytes[2..], 0x1002).unwrap();
        let actual = stream.next_supported().unwrap();
        assert_same(&actual, &expected);

        // Admission errors are also shared, not just successes:
        // EMMS is outside the Ordinary envelope.
        let emms = [0x0f, 0x77, 0xc3];
        let mut stream = SupportedDecoder::new(&emms, 0x1000);
        assert_eq!(
            stream.next_supported().unwrap_err(),
            decode_supported(&emms, 0x1000).unwrap_err()
        );
    }
}
