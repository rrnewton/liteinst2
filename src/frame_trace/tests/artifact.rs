//! Independent decoded-byte model at two runtime biases, never native execution.
use super::*;
use crate::emission::artifact_frame_tests::{BASE, HOOK, fixture};
use crate::planner::HookSemantics;
use crate::trampoline::SavedExtendedStateLayout;

fn checked_artifact(state: SavedExtendedStateLayout) {
    let (plan, input) = fixture(state, HookSemantics::Observe);
    let emitted = plan
        .frame_trace_nop5(&input, FrameTraceLimits::default())
        .unwrap();
    let image = emitted.exact_image();
    let trace = emitted.trace();
    assert_eq!(trace.calls().len(), 1);
    assert_eq!(trace.data_ranges(), &[]);
    for bias in [0x400000_u64, 0x7000_0000_0000] {
        for seed in [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
            let mut machine = Machine::new(seed);
            // Caller-owned return/rule memory and the complete red zone must
            // survive each helper instruction, not just the final restore.
            let caller: Vec<_> = (machine.original[7] - 128..machine.original[7] + 64)
                .map(|at| (at, (at as u8).wrapping_mul(17).wrapping_add(3)))
                .collect();
            machine.memory.extend(caller.iter().copied());
            let mut completed = false;
            let mut logical_fragments = 0;
            for row in trace.instructions() {
                let start = usize::try_from(row.start() - image.address()).unwrap();
                let end = usize::try_from(row.end() - image.address()).unwrap();
                let mut decoder = Decoder::with_ip(
                    64,
                    &image.bytes()[start..end],
                    row.start() + bias,
                    DecoderOptions::NONE,
                );
                let decoded = decoder.decode();
                assert!(!decoded.is_invalid() && !decoder.can_decode());
                assert_eq!(decoded.next_ip(), row.end() + bias);
                match row.kind() {
                    FrameInstructionKind::Helper(helper) => {
                        assert!(!completed);
                        assert_eq!(decoded.code(), helper.instruction().code());
                        machine.check(helper.before());
                        match decoded.mnemonic() {
                            Mnemonic::Lea if decoded.is_ip_rel_memory_operand() => {
                                assert_eq!(decoded.op0_register(), Register::RAX);
                                assert_eq!(decoded.ip_rel_memory_address(), decoded.next_ip());
                                machine.set(Register::RAX, decoded.ip_rel_memory_address());
                                logical_fragments += 1;
                            }
                            Mnemonic::Add if decoded.op0_register() == Register::RAX => {
                                assert_eq!(decoded.op1_kind(), OpKind::Register);
                                assert_eq!(decoded.op1_register(), Register::RDX);
                                machine.set(
                                    Register::RAX,
                                    machine
                                        .read(Register::RAX)
                                        .wrapping_add(machine.read(Register::RDX)),
                                );
                                machine.flags = 0x202;
                                assert_eq!(machine.read(Register::RAX), BASE + bias);
                            }
                            Mnemonic::Call => {
                                assert_eq!(decoded.op0_kind(), OpKind::NearBranch64);
                                assert_eq!(decoded.near_branch_target(), HOOK + bias);
                                assert_eq!(helper.instruction().ip(), row.start());
                                assert_eq!(helper.instruction().next_ip(), row.end());
                                assert_eq!(helper.instruction().near_branch_target(), HOOK);
                                let context = machine.read(Register::RDI);
                                assert_eq!(context, machine.read(Register::R12));
                                assert_eq!(machine.load(context), BASE + bias);
                                assert_eq!(machine.load(context + 8), machine.original[7]);
                                let rsp = machine.read(Register::RSP);
                                assert_eq!(rsp % 16, 0);
                                machine.set(Register::RSP, rsp - 8);
                                machine.store(rsp - 8, decoded.next_ip(), 8);
                                // A real normal CALL/RET enclosure; the observer
                                // clobbers every caller-saved GPR and flags while
                                // preserving application/caller memory and R12.
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
                                    machine.set(register, 0xbadc_0ffe_e000_0000 | register as u64);
                                }
                                machine.flags = 0x602;
                                assert_eq!(
                                    machine.load(machine.read(Register::RSP)),
                                    decoded.next_ip()
                                );
                                machine.set(Register::RSP, rsp);
                                machine.calls += 1;
                            }
                            _ => machine.step(&decoded, image),
                        }
                        machine.check(helper.after());
                        for &(at, byte) in &caller {
                            assert_eq!(machine.memory.get(&at), Some(&byte));
                        }
                        if helper.stage() == FrameStage::Restore
                            && helper.after() == &FrameState::entry()
                        {
                            assert_eq!(machine.registers, machine.original);
                            assert_eq!(machine.flags, machine.original_flags);
                            assert_eq!(machine.calls, 1);
                            completed = true;
                        }
                    }
                    FrameInstructionKind::Relocated(original) => {
                        assert!(completed);
                        assert_eq!(decoded.mnemonic(), Mnemonic::Nop);
                        assert_eq!(decoded.len(), 5);
                        assert_eq!(original.ip(), BASE);
                    }
                    FrameInstructionKind::ReturnTransfer(target) => {
                        assert!(completed);
                        assert_eq!(*target, BASE + 5);
                        assert_eq!(decoded.mnemonic(), Mnemonic::Jmp);
                        assert_eq!(decoded.near_branch_target(), BASE + 5 + bias);
                    }
                }
            }
            assert!(completed);
            assert_eq!(logical_fragments, 1);
        }
    }
}

#[test]
fn final_artifact_fxsave_rows_match_machine_state_and_targets_at_two_biases() {
    checked_artifact(SavedExtendedStateLayout::describe_target_fxsave64());
}

#[test]
fn final_artifact_xsave_rows_match_machine_state_and_targets_at_two_biases() {
    checked_artifact(
        SavedExtendedStateLayout::describe_target_xsave64(7, &[(4, 576, 256)]).unwrap(),
    );
}
