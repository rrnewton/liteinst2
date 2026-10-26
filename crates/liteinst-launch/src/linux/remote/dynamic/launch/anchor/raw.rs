use super::*;
use std::mem::offset_of;
use storage::Context;

core::arch::global_asm!(include_str!("raw.S"),
    stack_top = const offset_of!(Context, stack_top),
    stack_low = const offset_of!(Context, stack_low),
    parent_channel = const offset_of!(Context, parent_channel),
    parent_release = const offset_of!(Context, parent_release),
    error_read = const offset_of!(Context, error_read),
    error_write = const offset_of!(Context, error_write),
    channel = const offset_of!(Context, channel),
    release = const offset_of!(Context, release),
    release_byte = const offset_of!(Context, release_byte),
    tid = const offset_of!(Context, tid),
    signal = const offset_of!(Context, signal),
    signal_pid = const offset_of!(Context, signal) + 16,
    old_mask = const offset_of!(Context, old_mask),
    current_mask = const offset_of!(Context, current_mask),
    probe_mask = const offset_of!(Context, probe_mask),
    old_stack = const offset_of!(Context, old_stack),
    check_stack = const offset_of!(Context, check_stack),
    old_action = const offset_of!(Context, old_action),
    probe_action = const offset_of!(Context, probe_action),
    check_action = const offset_of!(Context, check_action),
    pending = const offset_of!(Context, pending),
    prepared = const offset_of!(Context, prepared),
    prepared_tid = const offset_of!(Context, prepared) + 32,
    anchor = const offset_of!(Context, anchor),
    anchor_tid = const offset_of!(Context, anchor) + 32,
    frame = const offset_of!(Context, frame),
    ucontext = const offset_of!(Context, ucontext),
    siginfo = const offset_of!(Context, siginfo),
    metadata = const offset_of!(Context, metadata),
    metadata_error = const offset_of!(Context, metadata) + 8,
    metadata_cr2 = const offset_of!(Context, metadata) + 16,
    program = const offset_of!(Context, program),
    argv = const offset_of!(Context, argv),
    envp = const offset_of!(Context, envp),
    error = const offset_of!(Context, error),
    error_errno = const offset_of!(Context, error) + 4,
    blocked = const BLOCKED,
    probe = const PROBE_SIGNAL,
    options(att_syntax),
);

unsafe extern "C" {
    fn li2_anchor_enter(context: *mut Context) -> !;
    fn li2_anchor_handler();
    fn li2_anchor_restorer();
    fn li2_anchor_code_begin();
    fn li2_anchor_code_end();
    fn li2_anchor_prepared_return();
    fn li2_anchor_read_insn();
    fn li2_anchor_read();
    fn li2_anchor_close_release();
    fn li2_anchor_install();
    fn li2_anchor_query_installed();
    fn li2_anchor_pending_before();
    fn li2_anchor_queue();
    fn li2_anchor_unmask();
    fn li2_anchor_reblock();
    fn li2_anchor_query_mask();
    fn li2_anchor_pending_restore();
    fn li2_anchor_restore_action();
    fn li2_anchor_query_restored();
    fn li2_anchor_query_stack();
    fn li2_anchor_pending_after();
    fn li2_anchor_write_anchor();
    fn li2_anchor_close_channel();
    fn li2_anchor_exec();
}
pub(super) unsafe fn enter(context: *mut Context) -> ! {
    unsafe { li2_anchor_enter(context) }
}
pub(super) fn handler_address() -> u64 {
    li2_anchor_handler as *const () as u64
}
pub(super) fn restorer_address() -> u64 {
    li2_anchor_restorer as *const () as u64
}
pub(super) fn code_range() -> std::ops::Range<u64> {
    li2_anchor_code_begin as *const () as u64..li2_anchor_code_end as *const () as u64
}
pub(super) fn read_prefix() -> std::ops::Range<u64> {
    li2_anchor_prepared_return as *const () as u64..li2_anchor_read_insn as *const () as u64
}
pub(super) fn read_instruction() -> u64 {
    li2_anchor_read_insn as *const () as u64
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CallKind {
    Read,
    CloseRelease,
    Install,
    QueryInstalled,
    PendingBefore,
    Queue,
    Unmask,
    Reblock,
    QueryMask,
    PendingRestore,
    RestoreAction,
    QueryRestored,
    QueryStack,
    PendingAfter,
    WriteAnchor,
    CloseChannel,
    Exec,
}
#[derive(Clone, Copy)]
pub(super) struct Call {
    pub(super) kind: CallKind,
    pub(super) pc: u64,
    pub(super) number: u64,
    pub(super) args: [Option<u64>; 6],
    pub(super) result: i64,
}
pub(super) fn calls(context: u64, c: &Context) -> [Call; 17] {
    let at = |offset: usize| context + offset as u64;
    let none = None;
    let some = Some;
    [
        Call {
            kind: CallKind::Read,
            pc: li2_anchor_read as *const () as u64,
            number: 0,
            args: [
                some(c.release),
                some(at(offset_of!(Context, release_byte))),
                some(1),
                none,
                none,
                none,
            ],
            result: 1,
        },
        Call {
            kind: CallKind::CloseRelease,
            pc: li2_anchor_close_release as *const () as u64,
            number: 3,
            args: [some(c.release), none, none, none, none, none],
            result: 0,
        },
        Call {
            kind: CallKind::Install,
            pc: li2_anchor_install as *const () as u64,
            number: 13,
            args: [
                some(PROBE_SIGNAL as u64),
                some(at(offset_of!(Context, probe_action))),
                some(0),
                some(8),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::QueryInstalled,
            pc: li2_anchor_query_installed as *const () as u64,
            number: 13,
            args: [
                some(PROBE_SIGNAL as u64),
                some(0),
                some(at(offset_of!(Context, check_action))),
                some(8),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::PendingBefore,
            pc: li2_anchor_pending_before as *const () as u64,
            number: 127,
            args: [
                some(at(offset_of!(Context, pending))),
                some(8),
                none,
                none,
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::Queue,
            pc: li2_anchor_queue as *const () as u64,
            number: 297,
            args: [
                some(c.tid),
                some(c.tid),
                some(PROBE_SIGNAL as u64),
                some(at(offset_of!(Context, signal))),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::Unmask,
            pc: li2_anchor_unmask as *const () as u64,
            number: 14,
            args: [
                some(2),
                some(at(offset_of!(Context, probe_mask))),
                some(0),
                some(8),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::Reblock,
            pc: li2_anchor_reblock as *const () as u64,
            number: 14,
            args: [
                some(2),
                some(at(offset_of!(Context, old_mask))),
                some(0),
                some(8),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::QueryMask,
            pc: li2_anchor_query_mask as *const () as u64,
            number: 14,
            args: [
                some(2),
                some(0),
                some(at(offset_of!(Context, current_mask))),
                some(8),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::PendingRestore,
            pc: li2_anchor_pending_restore as *const () as u64,
            number: 127,
            args: [
                some(at(offset_of!(Context, pending))),
                some(8),
                none,
                none,
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::RestoreAction,
            pc: li2_anchor_restore_action as *const () as u64,
            number: 13,
            args: [
                some(PROBE_SIGNAL as u64),
                some(at(offset_of!(Context, old_action))),
                some(0),
                some(8),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::QueryRestored,
            pc: li2_anchor_query_restored as *const () as u64,
            number: 13,
            args: [
                some(PROBE_SIGNAL as u64),
                some(0),
                some(at(offset_of!(Context, check_action))),
                some(8),
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::QueryStack,
            pc: li2_anchor_query_stack as *const () as u64,
            number: 131,
            args: [
                some(0),
                some(at(offset_of!(Context, check_stack))),
                none,
                none,
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::PendingAfter,
            pc: li2_anchor_pending_after as *const () as u64,
            number: 127,
            args: [
                some(at(offset_of!(Context, pending))),
                some(8),
                none,
                none,
                none,
                none,
            ],
            result: 0,
        },
        Call {
            kind: CallKind::WriteAnchor,
            pc: li2_anchor_write_anchor as *const () as u64,
            number: 1,
            args: [
                some(c.channel),
                some(at(offset_of!(Context, anchor))),
                some(64),
                none,
                none,
                none,
            ],
            result: 64,
        },
        Call {
            kind: CallKind::CloseChannel,
            pc: li2_anchor_close_channel as *const () as u64,
            number: 3,
            args: [some(c.channel), none, none, none, none, none],
            result: 0,
        },
        Call {
            kind: CallKind::Exec,
            pc: li2_anchor_exec as *const () as u64,
            number: 59,
            args: [
                some(c.program),
                some(c.argv),
                some(c.envp),
                none,
                none,
                none,
            ],
            result: 0,
        },
    ]
}
