//! Decoder/encoder controls only; no generated code, callback or native RET runs.
use super::*;
use crate::controls::ControlIdentity;
use crate::precontext::{Disposition, PreContextSelector, ScratchPhase};
use std::collections::BTreeMap;

unsafe extern "C" fn preserving(_: *mut HookContext, _: ControlIdentity<'_>) {}

const IMAGE: u64 = 0x0200_0000;
const FRAME: u64 = 0x0400_0000;
const STACK: u64 = 0x0500_0000;
const CONTINUATION: u64 = 0x0600_0000;

struct Program {
    original: Vec<Instruction>,
    spec: GateSpec,
    encoded: BlockEncoderResult,
    observer: u64,
    body: u64,
}
fn program(action: &PreContextAction) -> Program {
    let mut next = 10_u64;
    let mut identity = || {
        next += 1;
        Ok(next)
    };
    let mut original = Vec::new();
    let spec = append(&mut original, action, 1, 2, &mut identity).unwrap();
    let observer_index = original.len();
    let mut observer = Instruction::with(Code::Nopd);
    observer.set_ip(1);
    original.push(observer);
    // Long opaque slow body forces both short local and near body JMP forms.
    for _ in 0..16 {
        let mut bytes = Instruction::with_declare_byte(&[0x90; 16]).unwrap();
        bytes.set_ip(identity().unwrap());
        original.push(bytes);
    }
    let body_index = original.len();
    let mut body = Instruction::with(Code::Nopd);
    body.set_ip(2);
    original.push(body);
    let encoded = BlockEncoder::encode(
        64,
        InstructionBlock::new(&original, IMAGE),
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
            | BlockEncoderOptions::RETURN_RELOC_INFOS,
    )
    .unwrap();
    verify(&spec, &original, IMAGE, &encoded).unwrap();
    assert!(encoded.reloc_infos.is_empty());
    Program {
        observer: actual_address(observer_index, IMAGE, &encoded).unwrap(),
        body: actual_address(body_index, IMAGE, &encoded).unwrap(),
        original,
        spec,
        encoded,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Exit {
    Observer,
    Body,
    Fault,
}

// Deliberately small interpreter of the final decoded stencil, with a bounded
// address dictionary. It is not an XSAVE/state/native-execution oracle.
struct Machine {
    rcx: u64,
    words: BTreeMap<u64, u64>,
}
impl Machine {
    fn new(selector: &PreContextSelector) -> Self {
        let mut words = BTreeMap::from([(STACK, CONTINUATION), (selector.address(), 0)]);
        for offset in (0..72).step_by(8) {
            words.insert(FRAME + offset, 0);
        }
        words.insert(FRAME + PHASE, ARMED);
        Self {
            rcx: 0xfeed_8421_dead_ffff,
            words,
        }
    }
    fn reg(&self, r: Register) -> u64 {
        match r {
            Register::RCX => self.rcx,
            Register::RBX => FRAME,
            Register::RSP => STACK,
            _ => panic!("unexpected register {r:?}"),
        }
    }
    fn address(&self, i: &Instruction) -> u64 {
        assert_eq!(i.memory_index(), Register::None);
        self.reg(i.memory_base())
            .wrapping_add(i.memory_displacement64())
    }
    fn run(&mut self, p: &Program) -> Exit {
        let mut pc = IMAGE;
        for _ in 0..96 {
            if pc == p.observer {
                return Exit::Observer;
            }
            if pc == p.body {
                return Exit::Body;
            }
            let i = Decoder::with_ip(
                64,
                &p.encoded.code_buffer[(pc - IMAGE) as usize..],
                pc,
                DecoderOptions::NONE,
            )
            .decode();
            assert_eq!(i.rflags_modified(), 0);
            let mut next = i.next_ip();
            match i.code() {
                Code::Mov_rm64_r64 => {
                    assert_eq!(i.op1_register(), Register::RCX);
                    let address = self.address(&i);
                    assert!((FRAME..FRAME + 72).contains(&address));
                    *self.words.get_mut(&address).unwrap() = self.rcx;
                }
                Code::Mov_r64_rm64 => {
                    assert_eq!(i.op0_register(), Register::RCX);
                    self.rcx = if i.op1_kind() == OpKind::Register {
                        self.reg(i.op1_register())
                    } else {
                        self.words[&self.address(&i)]
                    };
                }
                Code::Mov_rm64_imm32 => {
                    let address = self.address(&i);
                    assert!((FRAME..FRAME + 72).contains(&address));
                    *self.words.get_mut(&address).unwrap() = i.immediate32to64() as u64;
                }
                Code::Mov_r64_imm64 => {
                    assert_eq!(i.op0_register(), Register::RCX);
                    self.rcx = i.immediate64();
                }
                Code::Lea_r64_m => {
                    assert_eq!(i.op0_register(), Register::RCX);
                    self.rcx = self.address(&i);
                }
                Code::Jrcxz_rel8_64 => {
                    if self.rcx == 0 {
                        next = i.near_branch_target();
                    }
                }
                Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => next = i.near_branch_target(),
                Code::Ud2 => return Exit::Fault,
                _ => panic!("unexpected stencil instruction {i:?}"),
            }
            pc = next;
        }
        panic!("stencil exceeded fixed control bound");
    }
}

#[test]
fn encoded_choice_is_immutable_and_rcx_stack_words_are_preserved() {
    let (selector, mut writer) = PreContextSelector::new(false);
    let entry = PreContextAction::new(0x0100_0000, PreContextRole::Entry, &selector, preserving);
    let ret = PreContextAction::new(0x0100_0010, PreContextRole::Return, &selector, preserving);
    let a = program(&entry);
    let b = program(&ret);
    for (enable, choice, exit) in [(0, FAST, Exit::Body), (1, SLOW, Exit::Observer)] {
        let mut m = Machine::new(&selector);
        let initial_rcx = m.rcx;
        m.words.insert(selector.address(), enable);
        assert_eq!(m.run(&a), exit);
        assert_eq!(m.rcx, initial_rcx);
        assert_eq!(m.words[&(FRAME + PHASE)], ENTERED);
        assert_eq!(m.words[&(FRAME + CHOICE)], choice);
        assert_eq!(m.words[&(FRAME + ENTRY_PC)], entry.logical_pc);
        assert_eq!(m.words[&(FRAME + ENTRY_RSP)], STACK);
        assert_eq!(m.words[&(FRAME + ENTRY_WORD)], CONTINUATION);
        // RET must never read even a now-malformed selector word.
        m.words.remove(&selector.address());
        writer.set_enabled(enable == 0);
        assert!(entry.control().is_enabled() && ret.control().is_enabled());
        assert!(entry.control().try_set_enabled(false).is_err());
        m.rcx ^= 0x1234;
        let return_rcx = m.rcx;
        assert_eq!(m.run(&b), exit);
        assert_eq!(m.rcx, return_rcx);
        assert_eq!(m.words[&(FRAME + PHASE)], RETURN_OBSERVED);
        assert_eq!(m.words[&(FRAME + CHOICE)], choice);
        assert_eq!(m.words[&(FRAME + RETURN_PC)], ret.logical_pc);
        assert_eq!(m.words[&(FRAME + RETURN_RSP)], STACK);
        assert_eq!(m.words[&(FRAME + RETURN_WORD)], CONTINUATION);
        assert_eq!(m.words[&STACK], CONTINUATION);
    }
}

#[test]
fn malformed_tags_fault_before_any_original_or_observer_path() {
    let (selector, _) = PreContextSelector::new(false);
    for role in [PreContextRole::Entry, PreContextRole::Return] {
        let p = program(&PreContextAction::new(
            0x0100_0000,
            role,
            &selector,
            preserving,
        ));
        let valid_phase = if role == PreContextRole::Entry {
            ARMED
        } else {
            ENTERED
        };
        for phase in [0, ARMED, ENTERED, RETURN_OBSERVED, u64::MAX] {
            for choice in [0, FAST, SLOW, 3, u64::MAX] {
                let valid_choice = if role == PreContextRole::Entry {
                    choice == 0
                } else {
                    choice == FAST || choice == SLOW
                };
                if phase == valid_phase && valid_choice {
                    continue;
                }
                let mut m = Machine::new(&selector);
                m.words.insert(FRAME + PHASE, phase);
                m.words.insert(FRAME + CHOICE, choice);
                assert_eq!(m.run(&p), Exit::Fault, "{role:?} {phase} {choice}");
                assert_eq!(m.words[&STACK], CONTINUATION);
            }
        }
    }
    let entry = program(&PreContextAction::new(
        0x0100_0000,
        PreContextRole::Entry,
        &selector,
        preserving,
    ));
    for value in [2, u64::MAX] {
        let mut m = Machine::new(&selector);
        m.words.insert(selector.address(), value);
        assert_eq!(m.run(&entry), Exit::Fault);
    }
}

#[test]
fn final_verifier_rejects_every_single_bit_gate_mutation_and_missing_offset() {
    let (selector, _) = PreContextSelector::new(false);
    for role in [PreContextRole::Entry, PreContextRole::Return] {
        let mut p = program(&PreContextAction::new(
            0x0100_0000,
            role,
            &selector,
            preserving,
        ));
        for &index in &p.spec.indices {
            let offset = p.encoded.new_instruction_offsets[index] as usize;
            let i = Decoder::with_ip(
                64,
                &p.encoded.code_buffer[offset..],
                IMAGE + offset as u64,
                DecoderOptions::NONE,
            )
            .decode();
            for local in 0..i.len() {
                let byte = offset + local;
                for bit in 0..8 {
                    p.encoded.code_buffer[byte] ^= 1 << bit;
                    assert!(
                        verify(&p.spec, &p.original, IMAGE, &p.encoded).is_err(),
                        "{role:?} byte {byte} bit {bit}"
                    );
                    p.encoded.code_buffer[byte] ^= 1 << bit;
                }
            }
        }
        let old = p.encoded.new_instruction_offsets[0];
        p.encoded.new_instruction_offsets[0] = u32::MAX;
        assert!(verify(&p.spec, &p.original, IMAGE, &p.encoded).is_err());
        p.encoded.new_instruction_offsets[0] = old;
        verify(&p.spec, &p.original, IMAGE, &p.encoded).unwrap();
    }
}

fn plan(selector: &PreContextSelector) -> TrampolinePlan {
    let base = 0x0100_0000;
    let scan = InstructionScanner::default()
        .scan(&[0x31, 0xc0, 0x31, 0xc9, 0x90, 0xc3], base)
        .unwrap();
    let actions = [
        PreContextAction::new(base, PreContextRole::Entry, selector, preserving),
        PreContextAction::new(base + 5, PreContextRole::Return, selector, preserving),
    ];
    // SAFETY: this control only constructs/encodes and never publishes/executes.
    unsafe { TrampolinePlan::from_precontext_actions(&scan, base, base + 6, &actions) }.unwrap()
}

#[test]
fn observing_image_keeps_original_routes_bodies_controls_and_selector_owner() {
    let (selector, writer) = PreContextSelector::new(false);
    let weak = selector.downgrade();
    let p = plan(&selector);
    let image = p.emit_at(IMAGE).unwrap();
    assert_eq!(image.controls().len(), 2);
    assert_eq!(image.precontext_selector(), Some(&selector));
    assert_eq!(image.precontext_gates().len(), 2);
    assert_eq!(image.entry_routes().len(), 4);
    assert_eq!(image.instruction_boundaries().len(), 4);
    let source = [0x31, 0xc0, 0x31, 0xc9, 0x90, 0xc3];
    let scan = InstructionScanner::default()
        .scan(&source, 0x0100_0000)
        .unwrap();
    for (head, &(pc, body)) in scan
        .instructions()
        .iter()
        .zip(image.instruction_boundaries())
    {
        assert_eq!(head.address(), pc);
        assert_eq!(
            &image.bytes()[(body - IMAGE) as usize..][..head.len()],
            &source[head.offset()..head.offset() + head.len()]
        );
    }
    for gate in image.precontext_gates() {
        assert!(
            image
                .entry_routes()
                .contains(&(gate.logical_pc, gate.entry))
        );
        assert!(
            image
                .instruction_boundaries()
                .contains(&(gate.logical_pc, gate.original_body))
        );
        assert!(!image.entry_routes().iter().any(|&(pc, _)| pc == gate.fault));
        assert_eq!(
            &image.bytes()[(gate.fault - IMAGE) as usize..][..2],
            &[0x0f, 0x0b]
        );
        assert!(
            image
                .program_counter_mappings()
                .iter()
                .any(|m| m.translate(gate.entry) == Some(gate.logical_pc))
        );
    }
    assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
    drop(p);
    drop(selector);
    drop(writer);
    assert!(weak.upgrade().is_some());
    drop(image);
    assert!(weak.upgrade().is_none());
}

#[test]
fn profile_refuses_mixed_sources_modes_and_repeated_control_identity() {
    let (selector, _) = PreContextSelector::new(false);
    let base = 0x0100_0000;
    let entry = PreContextAction::new(base, PreContextRole::Entry, &selector, preserving);
    for bytes in [
        &[0x48, 0x89, 0xd8, 0x90, 0x90][..], // MOV from RBX
        &[0x48, 0x8b, 0x03, 0x90, 0x90],     // RBX address
        &[0x48, 0x89, 0xc4, 0x90, 0x90],     // RSP write
        &[0x0f, 0xa2, 0x90, 0x90, 0x90],     // implicit RBX CPUID
        &[0xe8, 0, 0, 0, 0],
        &[0x0f, 0x05, 0x90, 0x90, 0x90], // CALL/SYSCALL
        &[0x90, 0x90, 0x90, 0x90, 0xc3],
    ]
    // unobserved RET
    {
        let scan = InstructionScanner::default().scan(bytes, base).unwrap();
        // SAFETY: no publication/execution; malformed source is deliberately refused.
        assert!(
            unsafe {
                TrampolinePlan::from_precontext_actions(
                    &scan,
                    base,
                    base + bytes.len() as u64,
                    core::slice::from_ref(&entry),
                )
            }
            .is_err()
        );
    }
    let scan = InstructionScanner::default()
        .scan(&[0x90; 5], base)
        .unwrap();
    let (foreign, _) = PreContextSelector::new(false);
    let bad_ret = PreContextAction::new(base + 4, PreContextRole::Return, &selector, preserving);
    let foreign_ret = PreContextAction::new(base + 4, PreContextRole::Return, &foreign, preserving);
    for actions in [
        [entry.clone(), entry.clone()],
        [entry.clone(), bad_ret],
        [entry, foreign_ret],
    ] {
        // SAFETY: no publication/execution.
        assert!(
            unsafe { TrampolinePlan::from_precontext_actions(&scan, base, base + 5, &actions) }
                .is_err()
        );
    }
    let mut p = plan(&selector);
    assert!(p.emit_with_frame_trace_at(IMAGE).is_err());
    p.ptrace_stops = true;
    assert!(p.emit_at(IMAGE).is_err());
}

#[test]
fn scratch_snapshot_is_not_a_return_token_and_tags_never_default_to_fast() {
    let mut s = CallScratch::armed();
    assert_eq!(s.snapshot().unwrap().phase, ScratchPhase::Armed);
    assert_eq!(s.snapshot().unwrap().disposition, None);
    s.phase = ENTERED;
    s.disposition = FAST;
    assert_eq!(
        s.snapshot().unwrap().disposition,
        Some(Disposition::FastBypass)
    );
    s.return_pc = 1;
    assert_eq!(s.snapshot(), Err(crate::precontext::ScratchError));
    s.phase = RETURN_OBSERVED;
    assert_eq!(s.snapshot().unwrap().phase, ScratchPhase::ReturnObserved);
    s.disposition = 3;
    assert_eq!(s.snapshot(), Err(crate::precontext::ScratchError));
}
