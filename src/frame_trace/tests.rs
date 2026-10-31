use super::*;
use crate::controls::{ControlledAction, ProbeControl};
use crate::scanner::InstructionScanner;
use crate::trampoline::{HookContext, TrampolinePlan};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use std::collections::BTreeMap;

const BASE: u64 = 0x4000_0000;
const NEAR: u64 = BASE + 0x100_0000;
const FAR: u64 = 0x80_0000_0000;

unsafe extern "C" fn observer(_: *mut HookContext) {}

fn scan(code: &[u8]) -> crate::scanner::ScanResult {
    InstructionScanner::default().scan(code, BASE).unwrap()
}

// Independent integer/stack model driven by final decoded machine instructions.
// It never interprets producer effects or uses the recorded offsets to execute.
struct Machine {
    registers: [u64; 16],
    original: [u64; 16],
    memory: BTreeMap<u64, u8>,
    flags: u64,
    original_flags: u64,
    calls: usize,
}

impl Machine {
    fn new(seed: u64) -> Self {
        let mut registers = [0; 16];
        for (index, value) in registers.iter_mut().enumerate() {
            *value = seed ^ (index as u64 + 1).wrapping_mul(0x0110_0010_0020_0030);
        }
        registers[7] = 0x10_0008;
        let flags = if seed & 1 == 0 { 0x646 } else { 0x293 };
        Self {
            original: registers,
            registers,
            memory: BTreeMap::new(),
            flags,
            original_flags: flags,
            calls: 0,
        }
    }
    fn index(register: Register) -> usize {
        let register = match register {
            Register::EAX => Register::RAX,
            Register::EDX => Register::RDX,
            value => value,
        };
        GPRS.iter()
            .position(|candidate| *candidate == register)
            .unwrap()
    }
    fn read(&self, register: Register) -> u64 {
        let value = self.registers[Self::index(register)];
        if matches!(register, Register::EAX | Register::EDX) {
            value as u32 as u64
        } else {
            value
        }
    }
    fn set(&mut self, register: Register, value: u64) {
        self.registers[Self::index(register)] = if matches!(register, Register::EAX | Register::EDX)
        {
            value as u32 as u64
        } else {
            value
        };
    }
    fn store(&mut self, address: u64, value: u64, bytes: usize) {
        for (index, byte) in value.to_le_bytes().into_iter().take(bytes).enumerate() {
            self.memory.insert(address + index as u64, byte);
        }
    }
    fn load(&self, address: u64) -> u64 {
        if address & 7 == 0 {
            // One tree search; adjacent bytes must still exist individually.
            // An aligned u64 address always leaves room for offsets 0..=7.
            let mut entries = self.memory.range(address..);
            let mut bytes = [0; 8];
            let mut complete = true;
            for (index, byte) in bytes.iter_mut().enumerate() {
                match entries.next() {
                    Some((&at, &value)) if at == address + index as u64 => *byte = value,
                    _ => {
                        complete = false;
                        break;
                    }
                }
            }
            if complete {
                return u64::from_le_bytes(bytes);
            }
        }
        // Preserve the original failure and unaligned-address semantics.
        u64::from_le_bytes(core::array::from_fn(|index| {
            self.memory[&(address + index as u64)]
        }))
    }
    fn memory_address(&self, instruction: &Instruction) -> u64 {
        assert_eq!(instruction.memory_index(), Register::None);
        self.read(instruction.memory_base())
            .wrapping_add(instruction.memory_displacement64())
    }
    fn check(&self, state: &FrameState) {
        let original_rsp = self.original[7];
        let (anchor, offset) = state.original_rsp_rule();
        assert_eq!(
            self.read(anchor).wrapping_add_signed(i64::from(offset)),
            original_rsp
        );
        for (index, register) in GPRS.iter().enumerate() {
            let value = match state.original_register(*register).unwrap() {
                OriginalRegisterLocation::Live(register) => self.read(register),
                OriginalRegisterLocation::Stack(offset) => {
                    self.load(original_rsp.wrapping_add_signed(i64::from(offset)))
                }
                OriginalRegisterLocation::OriginalStackPointer => original_rsp,
            };
            assert_eq!(value, self.original[index], "original {register:?}");
        }
        let flags = state.saved_flags_offset().map_or(self.flags, |offset| {
            self.load(original_rsp.wrapping_add_signed(i64::from(offset)))
        });
        assert_eq!(flags, self.original_flags);
    }
    fn step(&mut self, instruction: &Instruction, image: &TrampolineImage) {
        match instruction.mnemonic() {
            Mnemonic::Lea => {
                let address = self.memory_address(instruction);
                self.set(instruction.op0_register(), address);
            }
            Mnemonic::Push => {
                let value = self.read(instruction.op0_register());
                let rsp = self.read(Register::RSP) - 8;
                self.set(Register::RSP, rsp);
                self.store(rsp, value, 8);
            }
            Mnemonic::Pushfq => {
                let rsp = self.read(Register::RSP) - 8;
                self.set(Register::RSP, rsp);
                self.store(rsp, self.flags, 8);
            }
            Mnemonic::Pop => {
                let rsp = self.read(Register::RSP);
                self.set(instruction.op0_register(), self.load(rsp));
                self.set(Register::RSP, rsp + 8);
            }
            Mnemonic::Popfq => {
                let rsp = self.read(Register::RSP);
                self.flags = self.load(rsp);
                self.set(Register::RSP, rsp + 8);
            }
            Mnemonic::Mov => {
                let value = if instruction.op1_kind() == OpKind::Register {
                    self.read(instruction.op1_register())
                } else {
                    instruction.immediate(1)
                };
                if instruction.op0_kind() == OpKind::Register {
                    self.set(instruction.op0_register(), value);
                } else {
                    assert_eq!(instruction.op0_kind(), OpKind::Memory);
                    let bytes = instruction.memory_size().size();
                    assert!(matches!(bytes, 4 | 8));
                    self.store(self.memory_address(instruction), value, bytes);
                }
            }
            Mnemonic::And | Mnemonic::Add | Mnemonic::Sub => {
                assert_eq!(instruction.op0_register(), Register::RSP);
                let old = self.read(Register::RSP);
                let immediate = instruction.immediate(1);
                let value = match instruction.mnemonic() {
                    Mnemonic::And => old & immediate,
                    Mnemonic::Add => old.wrapping_add(immediate),
                    Mnemonic::Sub => old.wrapping_sub(immediate),
                    _ => unreachable!(),
                };
                self.set(Register::RSP, value);
                self.flags = 0x202;
            }
            Mnemonic::Xor => {
                assert_eq!(instruction.op0_register(), Register::EAX);
                assert_eq!(instruction.op1_register(), Register::EAX);
                self.set(Register::EAX, 0);
                self.flags = 0x246;
            }
            Mnemonic::Cld => self.flags &= !(1 << 10),
            Mnemonic::Fxsave64 | Mnemonic::Xsave64 | Mnemonic::Fxrstor64 | Mnemonic::Xrstor64 => {
                assert_eq!(instruction.memory_base(), Register::RSP);
                assert!(
                    self.read(Register::RSP) + image.layout().saved_extended_state.image_len()
                        <= self.original[7] - 304
                );
            }
            Mnemonic::Call => {
                assert_eq!(instruction.op0_register(), Register::RAX);
                // Model a normal ABI call and return with every caller-saved
                // GPR/flags clobbered. Saved application context stays intact.
                for register in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::RSI,
                    Register::RDI,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    self.set(register, 0xbadc_0ffe_e000_0000 | register as u64);
                }
                self.flags = 0x602;
                self.calls += 1;
            }
            mnemonic => panic!("unmodeled helper opcode {mnemonic:?}"),
        }
    }
}

fn checked(plan: &TrampolinePlan, address: u64, calls: usize) -> FrameEmission {
    let plain = plan.emit_at(address).unwrap();
    let emitted = plan.emit_with_frame_trace_at(address).unwrap();
    assert_eq!(
        emitted.image(),
        &plain,
        "ordinary image, maps and controls must be exact"
    );
    let trace = emitted.trace().unwrap();
    assert!(trace.matches_image(&plain));
    assert_eq!(trace.origin(), FrameEntryOrigin::ApplicationStack);
    assert_eq!(trace.calls().len(), calls);
    assert!(
        trace
            .requirements()
            .contains(&FrameTraceRequirement::ExactSourceRows)
    );
    assert!(
        trace
            .requirements()
            .contains(&FrameTraceRequirement::ConsumerAndRegistration)
    );
    assert_eq!(
        trace
            .requirements()
            .contains(&FrameTraceRequirement::FramePreservingHook),
        calls != 0
    );
    for seed in [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
        let mut machine = None;
        let mut helper_pc = None;
        let mut completed_calls = 0;
        for row in trace.instructions() {
            let start = usize::try_from(row.start() - address).unwrap();
            let end = usize::try_from(row.end() - address).unwrap();
            assert!(start < end && end - start <= 15);
            let mut decoder = Decoder::with_ip(
                64,
                &plain.bytes()[start..end],
                row.start(),
                DecoderOptions::NONE,
            );
            let decoded = decoder.decode();
            assert!(!decoded.is_invalid() && !decoder.can_decode());
            assert_eq!(decoded.next_ip(), row.end());
            match row.kind() {
                FrameInstructionKind::Helper(helper) => {
                    if helper_pc != Some(row.original_pc()) {
                        assert!(machine.is_none());
                        machine = Some(Machine::new(seed ^ row.original_pc()));
                        helper_pc = Some(row.original_pc());
                    }
                    assert_eq!(decoded.code(), helper.instruction().code());
                    let current = machine.as_mut().unwrap();
                    current.check(helper.before());
                    current.step(&decoded, &plain);
                    current.check(helper.after());
                    if helper.stage() == FrameStage::Restore
                        && helper.after() == &FrameState::entry()
                    {
                        assert_eq!(current.registers, current.original);
                        assert_eq!(current.flags, current.original_flags);
                        assert_eq!(current.calls, 1);
                        completed_calls += current.calls;
                        machine = None;
                        helper_pc = None;
                    }
                }
                FrameInstructionKind::Relocated(original) => {
                    assert!(machine.is_none());
                    assert_eq!(decoded.mnemonic(), original.mnemonic());
                    assert_eq!(row.original_pc(), original.ip());
                }
                FrameInstructionKind::ReturnTransfer(target) => {
                    assert!(machine.is_none());
                    assert_eq!(decoded.mnemonic(), Mnemonic::Jmp);
                    assert_eq!(*target, plan.return_address());
                    if end - start == 5 {
                        assert_eq!(decoded.near_branch_target(), *target);
                    } else {
                        assert_eq!(end - start, 7);
                        assert!(decoded.is_ip_rel_memory_operand());
                        assert_eq!(decoded.ip_rel_memory_address(), row.end());
                        assert!(trace.data_ranges().contains(&(row.end(), row.end() + 8)));
                        assert_eq!(
                            u64::from_le_bytes(plain.bytes()[end..end + 8].try_into().unwrap()),
                            *target
                        );
                    }
                }
            }
        }
        assert!(machine.is_none());
        assert_eq!(completed_calls, calls);
    }
    for call in trace.calls() {
        let row = trace
            .instructions()
            .iter()
            .find(|row| row.start() == call.call_pc())
            .unwrap();
        assert_eq!(row.end(), call.return_pc());
        assert_eq!(row.original_pc(), call.original_pc());
        assert!(
            matches!(row.kind(), FrameInstructionKind::Helper(helper) if helper.instruction().mnemonic() == Mnemonic::Call)
        );
        assert!(
            matches!(trace.instructions().iter().find(|row| row.start() == call.return_pc()).unwrap().kind(), FrameInstructionKind::Helper(helper) if helper.stage() == FrameStage::Restore)
        );
    }
    emitted
}

#[test]
fn normal_helper_rows_match_decoded_effects_and_live_bytes() {
    let first = Machine::new(0x1234_5678_8765_4320);
    let second = Machine::new(0xfedc_ba98_0123_4567);
    assert_eq!((first.flags, second.flags), (0x646, 0x293));
    assert_ne!(first.flags, second.flags);
    let plan = TrampolinePlan::from_scan(&scan(&[0x0f, 0x1f, 0x44, 0, 0]), BASE, observer).unwrap();
    let near = checked(&plan, NEAR, 1);
    assert!(near.trace().unwrap().data_ranges().is_empty());
    let far = checked(&plan, FAR, 1);
    assert_eq!(far.trace().unwrap().data_ranges().len(), 1);
    let (start, end) = far.trace().unwrap().data_ranges()[0];
    assert_eq!(end - start, 8);
    assert_eq!(
        u64::from_le_bytes(
            far.image().bytes()[(start - FAR) as usize..]
                .try_into()
                .unwrap()
        ),
        BASE + 5
    );
}

#[test]
fn short_selected_and_upstream_records_keep_distinct_original_heads() {
    for bytes in [
        &[0x89, 0xc0][..],
        &[0x48, 0x89, 0xc0][..],
        &[0x48, 0x8d, 0x40, 0][..],
    ] {
        let plan =
            TrampolinePlan::from_short_instruction(&scan(bytes), BASE, observer, false).unwrap();
        let emitted = checked(&plan, NEAR, 1);
        assert_eq!(emitted.trace().unwrap().calls()[0].original_pc(), BASE);
    }
    let code = [0x48, 0x8d, 0x41, 1, 0x90, 0x90];
    let plan = TrampolinePlan::from_window(&scan(&code), BASE, BASE + 4, BASE + 6, observer, false)
        .unwrap();
    let emitted = checked(&plan, NEAR, 1);
    assert_eq!(emitted.trace().unwrap().calls()[0].original_pc(), BASE + 4);
    assert!(
        matches!(emitted.trace().unwrap().instructions()[0].kind(), FrameInstructionKind::Relocated(original) if original.ip() == BASE)
    );
}

#[test]
fn coalesced_static_and_controlled_helpers_have_fresh_rows_and_call_returns() {
    let code = [0xb8, 1, 2, 3, 4, 0xb9, 5, 6, 7, 8, 0xba, 9, 10, 11, 12];
    let scan = scan(&code);
    let actions = [
        (BASE, observer as crate::trampoline::HookCallback, false),
        (BASE + 5, observer, false),
        (BASE + 10, observer, false),
    ];
    let plan = TrampolinePlan::from_actions(&scan, BASE, BASE + 15, &actions).unwrap();
    let emitted = checked(&plan, NEAR, 3);
    assert_eq!(
        emitted
            .trace()
            .unwrap()
            .calls()
            .iter()
            .map(|call| call.original_pc())
            .collect::<Vec<_>>(),
        [BASE, BASE + 5, BASE + 10]
    );
    assert!(
        emitted
            .trace()
            .unwrap()
            .calls()
            .iter()
            .all(|call| call.kind() == FrameCallKind::Observer)
    );
    let controls: Vec<_> = [BASE, BASE + 5, BASE + 10]
        .into_iter()
        .map(|logical_pc| ControlledAction {
            logical_pc,
            control: ProbeControl::new(observer, true),
        })
        .collect();
    let plan = TrampolinePlan::from_controlled_actions(&scan, BASE, BASE + 15, &controls).unwrap();
    let emitted = checked(&plan, NEAR, 3);
    assert!(
        emitted
            .trace()
            .unwrap()
            .calls()
            .iter()
            .all(|call| call.kind() == FrameCallKind::ControlDispatcher)
    );
}

#[test]
fn callback_free_rows_have_no_invented_instrumentation_or_frame_contract() {
    for code in [
        &[0x90][..],
        &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8][..],
        &[0x75, 0][..],
        &[0xc3][..],
    ] {
        let plan = TrampolinePlan::from_instruction(&scan(code), BASE).unwrap();
        let emitted = checked(&plan, NEAR, 0);
        assert_eq!(emitted.trace().unwrap().instructions().len(), 2);
        assert!(matches!(
            emitted.trace().unwrap().instructions()[0].kind(),
            FrameInstructionKind::Relocated(_)
        ));
    }
}

fn refused(plan: &TrampolinePlan, address: u64, expected: FrameTraceRefusal) {
    let plain = plan.emit_at(address).unwrap();
    let emitted = plan.emit_with_frame_trace_at(address).unwrap();
    assert_eq!(emitted.image(), &plain);
    assert_eq!(emitted.trace(), Err(expected));
}

#[test]
fn unsupported_origins_and_replacements_keep_ordinary_emission_success() {
    let decoded = scan(&[0x0f, 0x1f, 0x44, 0, 0]);
    let replaced = TrampolinePlan::from_scan_replacing_first(&decoded, BASE, observer).unwrap();
    refused(
        &replaced,
        NEAR,
        FrameTraceRefusal::ReplacementRequiresFrameContract,
    );
    let ptrace =
        TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(&decoded, BASE, observer)
            .unwrap();
    refused(&ptrace, NEAR, FrameTraceRefusal::UnsupportedEntryOrigin);
    assert_eq!(
        ptrace.emit_with_frame_trace_at(NEAR).unwrap().origin(),
        FrameEntryOrigin::ControllerOwnedStack
    );
    let syscall =
        TrampolinePlan::from_scan_replacing_exact_syscall(&scan(&[0x0f, 0x05]), BASE, observer)
            .unwrap();
    refused(
        &syscall,
        NEAR,
        FrameTraceRefusal::ExactSyscallRequiresFrameContract,
    );
}

#[test]
fn expanded_branch_metadata_refusal_does_not_reject_supported_code() {
    let plan = TrampolinePlan::from_instruction(&scan(&[0x75, 0x7e]), BASE).unwrap();
    refused(&plan, FAR, FrameTraceRefusal::ExpandedRelocation);
}

#[test]
fn metadata_limits_do_not_change_normal_image_or_ordinary_errors() {
    let plan = TrampolinePlan::from_scan(&scan(&[0x0f, 0x1f, 0x44, 0, 0]), BASE, observer).unwrap();
    for limits in [
        FrameTraceLimits {
            instructions: 0,
            calls: 64,
        },
        FrameTraceLimits {
            instructions: 4096,
            calls: 0,
        },
    ] {
        let emitted = plan.emit_with_frame_trace_limits_at(NEAR, limits).unwrap();
        assert_eq!(emitted.image(), &plan.emit_at(NEAR).unwrap());
        assert_eq!(emitted.trace(), Err(FrameTraceRefusal::ResourceLimit));
    }
    let old = plan.emit_at(u64::MAX - 4).unwrap_err().to_string();
    let new = plan
        .emit_with_frame_trace_at(u64::MAX - 4)
        .unwrap_err()
        .to_string();
    assert_eq!(new, old);
}

#[test]
fn model_rejects_wrong_intermediate_rsp_and_saved_register_rules() {
    let plan = TrampolinePlan::from_scan(&scan(&[0x0f, 0x1f, 0x44, 0, 0]), BASE, observer).unwrap();
    let emitted = checked(&plan, NEAR, 1);
    let mut machine = Machine::new(7);
    for row in emitted.trace().unwrap().instructions() {
        let FrameInstructionKind::Helper(helper) = row.kind() else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            64,
            &emitted.image().bytes()[(row.start() - NEAR) as usize..(row.end() - NEAR) as usize],
            row.start(),
            DecoderOptions::NONE,
        );
        machine.step(&decoder.decode(), emitted.image());
        if helper.after().original_rsp_rule() == (Register::R12, 304) {
            let mut wrong_rsp = helper.after().clone();
            wrong_rsp.original_rsp_offset = 296;
            assert!(std::panic::catch_unwind(|| machine.check(&wrong_rsp)).is_err());
            let mut wrong_register = helper.after().clone();
            wrong_register.registers[12] = OriginalRegisterLocation::Live(Register::R12);
            assert!(std::panic::catch_unwind(|| machine.check(&wrong_register)).is_err());
            return;
        }
    }
    panic!("required stable-context boundary absent");
}

#[test]
fn invalid_producer_rows_and_uncovered_bytes_are_explicit_metadata_failures() {
    let mut assembler = iced_x86::code_asm::CodeAssembler::new(64).unwrap();
    assembler.nop().unwrap();
    let encoded = assembler
        .assemble_options(
            NEAR,
            iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .unwrap();
    let mut bad = HelperFrames::new(FrameStage::SaveAndCall);
    bad.after(2, FrameEffect::Reserve(128));
    bad.finish(assembler.instructions(), &encoded.inner);
    assert!(matches!(
        bad.result,
        Some(Err(FrameTraceRefusal::InvalidProducerAnnotation))
    ));
    let plan = TrampolinePlan::from_instruction(&scan(&[0x90]), BASE).unwrap();
    let image = plan.emit_at(NEAR).unwrap();
    let incomplete = FrameRecorder::new(
        FrameEntryOrigin::ApplicationStack,
        FrameTraceLimits::default(),
    );
    assert_eq!(
        incomplete.finish(&image),
        Err(FrameTraceRefusal::IncompleteByteOwnership)
    );
    let mut oversized = FrameRecorder::new(
        FrameEntryOrigin::ApplicationStack,
        FrameTraceLimits::default(),
    );
    oversized.relocated(
        *scan(&[0x90]).instructions()[0].instruction(),
        NEAR,
        NEAR + 16,
    );
    assert_eq!(
        oversized.finish(&image),
        Err(FrameTraceRefusal::InvalidProducerAnnotation)
    );
    let emitted = checked(&plan, NEAR, 0);
    let other = plan.emit_at(NEAR + 4096).unwrap();
    assert!(!emitted.trace().unwrap().matches_image(&other));
}

mod artifact;
mod call_pair_stack;
mod memory;
mod stack_profile;
