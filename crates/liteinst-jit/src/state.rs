//! Guest state and the cache-resident data block shared with emitted
//! code. Field order is ABI: the entry bridge and emitted sequences
//! address these fields by the `OFF_*` constants, which are derived
//! from the struct definitions and asserted in tests.

/// Exit kinds written by emitted exit stubs into `JitData::exit_kind`.
pub mod exit_kind {
    pub const RETURN: u64 = 1;
    pub const INDIRECT: u64 = 2;
    pub const SYSCALL: u64 = 3;
    pub const NONDET: u64 = 4;
    pub const POLL: u64 = 5;
}

/// Full general-purpose guest state transferred at cache entry/exit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    /// Source PC the state belongs to (next guest instruction).
    pub rip: u64,
}

/// Data living at a fixed offset in every cache allocation. Emitted
/// stubs reach it RIP-relatively; the dispatcher reaches it directly.
pub const SCRATCH_LEN: usize = 65536;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct JitData {
    pub state: GuestState,
    /// Raw interrupted registers written by the fault handler.
    /// Kept separate from `state` so common-exit saves already made
    /// into `state` survive a fault mid-epilogue.
    pub interrupted: GuestState,
    pub branch_count: u64,
    pub instruction_count: u64,
    pub poll_remaining: u64,
    pub spill_rax: u64,
    pub spill_flags: u64,
    pub exit_kind: u64,
    pub exit_src: u64,
    pub exit_next: u64,
    pub host_rsp: u64,
    pub host_rbx: u64,
    pub host_rbp: u64,
    pub host_r12: u64,
    pub host_r13: u64,
    pub host_r14: u64,
    pub host_r15: u64,
    pub tmp_entry: u64,
    pub scratch: [u8; SCRATCH_LEN],
}

impl JitData {
    pub fn new(state: GuestState) -> JitData {
        JitData {
            state,
            interrupted: GuestState::default(),
            branch_count: 0,
            instruction_count: 0,
            poll_remaining: 0,
            spill_rax: 0,
            spill_flags: 0,
            exit_kind: 0,
            exit_src: 0,
            exit_next: 0,
            host_rsp: 0,
            host_rbx: 0,
            host_rbp: 0,
            host_r12: 0,
            host_r13: 0,
            host_r14: 0,
            host_r15: 0,
            tmp_entry: 0,
            scratch: [0; SCRATCH_LEN],
        }
    }
    /// Address of the private scratch stack top (inside `scratch`).
    ///
    /// # Safety
    /// `self` must point at a live allocation-resident `JitData`.
    pub unsafe fn scratch_top(this: *const JitData) -> u64 {
        // SAFETY: caller guarantees `this` is live; the offset is
        // inside the struct by construction.
        unsafe {
            (this as *const u8).add(core::mem::offset_of!(JitData, scratch) + SCRATCH_LEN) as u64
        }
    }
}

pub const OFF_STATE: usize = core::mem::offset_of!(JitData, state);
pub const OFF_BRANCH_COUNT: usize = core::mem::offset_of!(JitData, branch_count);
pub const OFF_INSTRUCTION_COUNT: usize = core::mem::offset_of!(JitData, instruction_count);
pub const OFF_POLL: usize = core::mem::offset_of!(JitData, poll_remaining);
pub const OFF_SPILL_RAX: usize = core::mem::offset_of!(JitData, spill_rax);
pub const OFF_SPILL_FLAGS: usize = core::mem::offset_of!(JitData, spill_flags);
pub const OFF_EXIT_KIND: usize = core::mem::offset_of!(JitData, exit_kind);
pub const OFF_EXIT_SRC: usize = core::mem::offset_of!(JitData, exit_src);
pub const OFF_EXIT_NEXT: usize = core::mem::offset_of!(JitData, exit_next);
pub const OFF_HOST_RSP: usize = core::mem::offset_of!(JitData, host_rsp);
pub const OFF_HOST_RBX: usize = core::mem::offset_of!(JitData, host_rbx);
pub const OFF_HOST_RBP: usize = core::mem::offset_of!(JitData, host_rbp);
pub const OFF_HOST_R12: usize = core::mem::offset_of!(JitData, host_r12);
pub const OFF_HOST_R13: usize = core::mem::offset_of!(JitData, host_r13);
pub const OFF_HOST_R14: usize = core::mem::offset_of!(JitData, host_r14);
pub const OFF_HOST_R15: usize = core::mem::offset_of!(JitData, host_r15);
pub const OFF_TMP_ENTRY: usize = core::mem::offset_of!(JitData, tmp_entry);
pub const OFF_SCRATCH: usize = core::mem::offset_of!(JitData, scratch);

pub const ST_RAX: usize = core::mem::offset_of!(GuestState, rax);
pub const ST_RBX: usize = core::mem::offset_of!(GuestState, rbx);
pub const ST_RCX: usize = core::mem::offset_of!(GuestState, rcx);
pub const ST_RDX: usize = core::mem::offset_of!(GuestState, rdx);
pub const ST_RSI: usize = core::mem::offset_of!(GuestState, rsi);
pub const ST_RDI: usize = core::mem::offset_of!(GuestState, rdi);
pub const ST_RBP: usize = core::mem::offset_of!(GuestState, rbp);
pub const ST_RSP: usize = core::mem::offset_of!(GuestState, rsp);
pub const ST_R8: usize = core::mem::offset_of!(GuestState, r8);
pub const ST_R9: usize = core::mem::offset_of!(GuestState, r9);
pub const ST_R10: usize = core::mem::offset_of!(GuestState, r10);
pub const ST_R11: usize = core::mem::offset_of!(GuestState, r11);
pub const ST_R12: usize = core::mem::offset_of!(GuestState, r12);
pub const ST_R13: usize = core::mem::offset_of!(GuestState, r13);
pub const ST_R14: usize = core::mem::offset_of!(GuestState, r14);
pub const ST_R15: usize = core::mem::offset_of!(GuestState, r15);
pub const ST_RFLAGS: usize = core::mem::offset_of!(GuestState, rflags);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn offsets_are_distinct_and_ordered() {
        assert_eq!(OFF_STATE, 0);
        assert!(OFF_BRANCH_COUNT > OFF_STATE);
        assert!(OFF_SPILL_RAX > OFF_BRANCH_COUNT);
        assert!(OFF_EXIT_KIND > OFF_SPILL_FLAGS);
        assert!(OFF_SCRATCH > OFF_TMP_ENTRY);
        assert_eq!(core::mem::size_of::<GuestState>(), 18 * 8);
    }
}
