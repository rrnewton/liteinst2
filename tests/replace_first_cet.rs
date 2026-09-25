#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Decode-only checks for far branches to a replaced application entry.

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, InstructionBlock, Mnemonic,
    OpKind, Register,
};
use liteinst2::patcher::JumpPatchPlan;
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookContext, TrampolineImage, TrampolinePlan};

unsafe extern "C" fn noop(_: *mut HookContext) {}

const CASES: &[(&str, &[u8])] = &[
    ("jmp", &[0x90, 0xe9, 0xfa, 0xff, 0xff, 0xff]),
    ("call", &[0x90, 0xe8, 0xfa, 0xff, 0xff, 0xff]),
    ("jne", &[0x90, 0x75, 0xfd, 0x90, 0x90]),
    ("loop", &[0x90, 0xe2, 0xfd, 0x90, 0x90]),
    ("loope", &[0x90, 0xe1, 0xfd, 0x90, 0x90]),
    ("loopne", &[0x90, 0xe0, 0xfd, 0x90, 0x90]),
    ("jrcxz", &[0x90, 0xe3, 0xfd, 0x90, 0x90]),
    ("jecxz", &[0x90, 0x67, 0xe3, 0xfc, 0x90]),
    ("syscall_jne", &[0x0f, 0x05, 0x75, 0xfc, 0x90]),
    ("two_branches", &[0x90, 0x75, 0xfd, 0x74, 0xfb]),
];

fn make_plan(code: &[u8], base: u64, stops: bool) -> TrampolinePlan {
    let scan = InstructionScanner::default().scan(code, base).unwrap();
    if stops {
        TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(&scan, base, noop).unwrap()
    } else {
        TrampolinePlan::from_scan_replacing_first(&scan, base, noop).unwrap()
    }
}

fn relocated_offset(image: &TrampolineImage) -> usize {
    let layout = image.layout();
    layout.entry_stop_len
        + layout.instrumentation_len
        + layout.restore_len
        + layout.completion_stop_len
}

fn logical_pc(image: &TrampolineImage, pc: u64) -> Option<u64> {
    image
        .program_counter_mappings()
        .iter()
        .find_map(|mapping| mapping.translate(pc))
}

#[test]
fn far_replace_first_entry_branches_use_one_cet_relay() {
    for &(name, code) in CASES {
        for stops in [false, true] {
            for (base, destination) in [(0x200ffc, 0x80201000), (0x200000, 0x4_0000_0000)] {
                if base == 0x200ffc {
                    assert_eq!(destination - (base + 5), i32::MAX as u64);
                    assert_eq!(destination % 4096, 0);
                    let mut patch_code = code.to_vec();
                    patch_code.resize(8, 0x90);
                    let scanner = InstructionScanner::default();
                    let scan = scanner.scan(&patch_code, base).unwrap();
                    JumpPatchPlan::from_scan(&scanner, &scan, &patch_code, base, base, destination)
                        .unwrap();
                }
                let plan = make_plan(code, base, stops);
                let image = plan.emit_at(destination).unwrap();
                assert!(plan.replaces_first());
                assert_eq!(plan.displaced_len(), code.len());
                let start = relocated_offset(&image);
                let return_stub = destination + (start + image.layout().relocated_len) as u64;
                let mut decoder = Decoder::with_ip(
                    64,
                    &image.bytes()[start..],
                    destination + start as u64,
                    DecoderOptions::NONE,
                );
                let originals: Vec<_> = Decoder::with_ip(64, code, base, DecoderOptions::NONE)
                    .into_iter()
                    .collect();
                let mut relays = Vec::new();
                for original in &originals[1..] {
                    let first = decoder.decode();
                    if original.op0_kind() == OpKind::NearBranch64 {
                        assert_eq!(original.near_branch_target(), base);
                        let mut transfers = vec![first];
                        for _ in 0..2 {
                            if transfers.last().unwrap().op0_kind() == OpKind::Memory {
                                break;
                            }
                            transfers.push(decoder.decode());
                        }
                        let indirect = transfers.last().unwrap();
                        assert_eq!(indirect.op0_kind(), OpKind::Memory);
                        assert_eq!(
                            indirect.code(),
                            if original.mnemonic() == Mnemonic::Call {
                                Code::Call_rm64
                            } else {
                                Code::Jmp_rm64
                            }
                        );
                        let literal = (indirect.ip_rel_memory_address() - destination) as usize;
                        let relay = u64::from_le_bytes(
                            image.bytes()[literal..literal + 8].try_into().unwrap(),
                        );
                        assert!(
                            (destination..return_stub).contains(&relay),
                            "{name}, stops={stops}: entry branch literal {relay:#x} needs a local CET relay"
                        );
                        relays.push(relay);
                        for pc in first.ip()..indirect.next_ip() {
                            assert_eq!(logical_pc(&image, pc), Some(original.ip()));
                        }
                        for pc in
                            indirect.ip_rel_memory_address()..indirect.ip_rel_memory_address() + 8
                        {
                            assert_eq!(logical_pc(&image, pc), None);
                        }
                        match original.mnemonic() {
                            Mnemonic::Je | Mnemonic::Jne => {
                                assert_eq!(
                                    first.mnemonic(),
                                    if original.mnemonic() == Mnemonic::Je {
                                        Mnemonic::Jne
                                    } else {
                                        Mnemonic::Je
                                    }
                                );
                                assert_eq!(first.near_branch_target(), indirect.next_ip());
                            }
                            Mnemonic::Loop
                            | Mnemonic::Loope
                            | Mnemonic::Loopne
                            | Mnemonic::Jrcxz
                            | Mnemonic::Jecxz => {
                                assert_eq!(first.mnemonic(), original.mnemonic());
                                assert_eq!(first.near_branch_target(), indirect.ip());
                                assert_eq!(transfers[1].code(), Code::Jmp_rel8_64);
                                assert_eq!(transfers[1].near_branch_target(), indirect.next_ip());
                            }
                            Mnemonic::Call | Mnemonic::Jmp => assert_eq!(transfers.len(), 1),
                            _ => unreachable!(),
                        }
                    } else {
                        assert_eq!(original.code(), Code::Nopd);
                        assert_eq!(first.code(), original.code());
                        for pc in first.ip()..first.next_ip() {
                            assert_eq!(logical_pc(&image, pc), Some(original.ip()));
                        }
                    }
                }
                let terminal = decoder.decode();
                assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                assert_eq!(terminal.near_branch_target(), return_stub);
                for pc in terminal.ip()..terminal.next_ip() {
                    assert_eq!(logical_pc(&image, pc), Some(plan.return_address()));
                }
                let relay = relays[0];
                assert!(relays.iter().all(|target| *target == relay));
                let offset = (relay - destination) as usize;
                assert_eq!(
                    &image.bytes()[offset..offset + 11],
                    &[0xf3, 0x0f, 0x1e, 0xfa, 0x3e, 0xff, 0x25, 0, 0, 0, 0]
                );
                let mut relay_decoder =
                    Decoder::with_ip(64, &image.bytes()[offset..], relay, DecoderOptions::NONE);
                assert_eq!(relay_decoder.decode().code(), Code::Endbr64);
                let jump = relay_decoder.decode();
                assert_eq!(jump.code(), Code::Jmp_rm64);
                assert_eq!(jump.segment_prefix(), Register::DS);
                assert_eq!(jump.ip_rel_memory_address(), relay + 11);
                assert_eq!(
                    u64::from_le_bytes(image.bytes()[offset + 11..offset + 19].try_into().unwrap()),
                    base
                );
                assert_eq!(relay + 19, return_stub);
                for pc in terminal.next_ip()..relay {
                    assert_eq!(logical_pc(&image, pc), None);
                }
                for pc in relay..relay + 11 {
                    assert_eq!(logical_pc(&image, pc), Some(base));
                }
                for pc in relay + 11..relay + 19 {
                    assert_eq!(logical_pc(&image, pc), None);
                }
            }
        }
    }
}

#[test]
fn near_replace_first_entry_branches_keep_the_original_encoding() {
    let base = 0x200000;
    let destination = 0x300000;
    for &(_, code) in CASES {
        for stops in [false, true] {
            let image = make_plan(code, base, stops).emit_at(destination).unwrap();
            let start = relocated_offset(&image);
            let originals: Vec<_> = Decoder::with_ip(64, code, base, DecoderOptions::NONE)
                .into_iter()
                .collect();
            let expected = BlockEncoder::encode(
                64,
                InstructionBlock::new(&originals[1..], destination + start as u64),
                BlockEncoderOptions::RETURN_RELOC_INFOS,
            )
            .unwrap();
            assert!(expected.reloc_infos.is_empty());
            assert_eq!(
                &image.bytes()[start..start + image.layout().relocated_len],
                expected.code_buffer
            );
        }
    }
}
