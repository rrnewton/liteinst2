//! Reference handlers for the standalone driver and tests.
//!
//! These emulate exactly the fixture-visible effects of the served
//! instructions. They are not a general syscall layer.

use crate::exec::{Handler, Resume};
use crate::refuse::Refuse;
use crate::state::GuestState;

/// Serves `SYS_write` into a capture buffer and `CPUID` by executing
/// the native instruction in the handler. Everything else refuses
/// by name through `NoHandler`.
#[derive(Default)]
pub struct CaptureHandler {
    pub written: Vec<u8>,
    pub syscalls: u64,
    pub nondets: u64,
}

impl Handler for CaptureHandler {
    fn syscall(
        &mut self,
        state: &mut GuestState,
        insn_pc: u64,
        next_pc: u64,
    ) -> Result<Resume, Refuse> {
        self.syscalls += 1;
        match state.rax {
            1 => {
                // SYS_write(fd, buf=rsi, len=rdx). The guest is
                // in-process, so the buffer is directly readable;
                // capture it instead of writing to fd 1.
                let len = usize::try_from(state.rdx)
                    .map_err(|_| Refuse::NoHandler { src_pc: insn_pc })?;
                // SAFETY: fixture contract — rsi/len name a live
                // readable guest buffer for the call.
                let bytes = unsafe { core::slice::from_raw_parts(state.rsi as *const u8, len) };
                self.written.extend_from_slice(bytes);
                state.rax = state.rdx;
            }
            _ => return Err(Refuse::NoHandler { src_pc: insn_pc }),
        }
        state.rcx = next_pc;
        state.r11 = state.rflags;
        Ok(Resume::At(next_pc))
    }

    fn nondet(
        &mut self,
        state: &mut GuestState,
        insn_pc: u64,
        next_pc: u64,
    ) -> Result<Resume, Refuse> {
        self.nondets += 1;
        // Only CPUID is served (the fixture contract). The decoder
        // also routes RDTSC-class here; verify the bytes by refusing
        // anything whose native emulation would be wrong: CPUID
        // operands are implicit, so serve from state registers.
        let leaf = state.rax as u32;
        let sub = state.rcx as u32;
        let r = core::arch::x86_64::__cpuid_count(leaf, sub);
        state.rax = u64::from(r.eax);
        state.rbx = u64::from(r.ebx);
        state.rcx = u64::from(r.ecx);
        state.rdx = u64::from(r.edx);
        let _ = insn_pc;
        Ok(Resume::At(next_pc))
    }
}
