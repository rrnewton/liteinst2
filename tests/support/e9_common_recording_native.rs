//! Shared bounded hardware callback walk. No state repair or endpoint search.
use super::*;
use iced_x86::{Decoder, DecoderOptions, FlowControl};

pub(super) struct Callback<'a> {
    pub start: u64,
    pub code: &'a [u8],
    pub return_pc: u64,
    pub logical: u64,
    pub core: bool,
}

pub(super) fn callback(
    child: &Tracee,
    callback: Callback<'_>,
    steps: &mut usize,
    trace: &mut File,
) {
    let Callback {
        start,
        code,
        return_pc,
        logical,
        core,
    } = callback;
    assert!(!code.is_empty() && code.len() <= 4096);
    let stop = start.checked_add(code.len() as u64).unwrap();
    let mut decoder = Decoder::with_ip(64, code, start, DecoderOptions::NONE);
    let mut instructions = std::collections::BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        assert!(!i.is_invalid() && i.len() > 0);
        assert!(matches!(
            i.flow_control(),
            FlowControl::Next
                | FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::Return
        ));
        assert!(!matches!(
            i.mnemonic(),
            iced_x86::Mnemonic::Syscall
                | iced_x86::Mnemonic::Sysenter
                | iced_x86::Mnemonic::Int
                | iced_x86::Mnemonic::Int3
                | iced_x86::Mnemonic::Hlt
        ));
        let at = usize::try_from(i.ip() - start).unwrap();
        let raw = code[at..at + i.len()].to_vec();
        if i.flow_control() == FlowControl::Return {
            assert_eq!(raw, [0xc3]);
        }
        assert!(instructions.insert(i.ip(), (i, raw)).is_none());
    }
    assert_eq!(decoder.ip(), stop);
    for (i, _) in instructions.values() {
        if matches!(
            i.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) {
            assert!(
                instructions.contains_key(&i.near_branch_target()),
                "closed callback direct target"
            );
        }
    }
    let entry = child.registers();
    assert_eq!(entry.rip, start);
    assert_eq!(word(&child.memory(entry.rsp, 8), 0), return_pc);
    if core {
        assert_eq!(word(&child.memory(entry.rdi, 8), 0), logical);
    } else {
        assert_eq!(entry.rdi, logical);
    }
    writeln!(
        trace,
        "journal-hook\t{start}\t{return_pc}\t{logical}\t{}",
        code.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
    .unwrap();
    loop {
        let before = child.registers();
        let (i, raw) = instructions
            .get(&before.rip)
            .expect("only authenticated callback instruction heads");
        assert_eq!(
            before.rsp, entry.rsp,
            "callback must be stackless before literal RET"
        );
        assert_eq!(child.memory(before.rip, raw.len()), *raw);
        step(child, steps); // Existing 15 second / 20,000 stop bound; no private budget.
        let after = child.registers();
        let hex = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
        writeln!(trace, "journal-step\t{}\t{}\t{hex}", before.rip, after.rip).unwrap();
        trace.flush().unwrap();
        if i.flow_control() == FlowControl::Return {
            assert_eq!(after.rip, return_pc);
            assert_eq!(after.rsp, entry.rsp.checked_add(8).unwrap());
            break;
        }
        assert_eq!(after.rsp, entry.rsp, "no callback stack allocation or push");
        match i.flow_control() {
            FlowControl::Next => assert_eq!(after.rip, i.next_ip()),
            FlowControl::UnconditionalBranch => assert_eq!(after.rip, i.near_branch_target()),
            FlowControl::ConditionalBranch => {
                assert!(after.rip == i.next_ip() || after.rip == i.near_branch_target())
            }
            _ => unreachable!(),
        }
    }
}
