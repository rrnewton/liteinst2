//! Exact native setup inputs. These checks do not replace the real original
//! ENTRY/EXIT, provider callback, complete-state comparator or memory evidence.
use super::*;
use crate::selected::{Operation, SyscallAbi};
// Linux x86 UAPI: include/uapi/asm-generic/signal-defs.h and x86 signal.h.
const SA_RESTORER: u64 = 0x0400_0000;

fn writable_input(tid: i32, address: u64, length: usize) -> Result<Vec<u8>, GateError> {
    let end = address
        .checked_add(length as u64)
        .ok_or(GateError::Refused("signal setup input overflows"))?;
    if address == 0
        || !read_maps(tid)?.iter().any(|mapping| {
            mapping.start <= address
                && end <= mapping.end
                && mapping.permissions.as_bytes().starts_with(b"rw-p")
        })
    {
        return Err(GateError::Refused(
            "signal setup input is not one complete private RW/NX object",
        ));
    }
    Ok(read_memory(tid, address, length)?)
}

impl SignalTransaction {
    pub(super) fn is_setup(input: &SelectedInput) -> bool {
        matches!(
            input.instruction().operation(),
            Operation::Syscall {
                abi: SyscallAbi::LinuxX64
            }
        ) && matches!(
            input.registers().rax as libc::c_long,
            libc::SYS_rt_sigaction | libc::SYS_sigaltstack
        )
    }

    pub(super) fn check_setup(&self, tid: i32, input: &SelectedInput) -> Result<(), GateError> {
        let r = input.registers();
        if !Self::is_setup(input) || self.delivered || self.live.is_some() || self.pending.is_some()
        {
            return Err(GateError::Refused(
                "signal setup is outside its original native phase",
            ));
        }
        if r.rax == libc::SYS_rt_sigaction as u64 {
            if self.action_installed
                || r.rdi != u64::from(self.profile.signal)
                || r.rdx != 0
                || r.r10 != 8
            {
                return Err(GateError::Refused(
                    "signal action setup arguments differ from the fixed profile",
                ));
            }
            let actual = writable_input(tid, r.rsi, 32)?;
            let flags = libc::SA_SIGINFO as u64
                | SA_RESTORER
                | if self.profile.alternate_stack.is_some() {
                    libc::SA_ONSTACK as u64
                } else {
                    0
                };
            let words = [
                self.profile.handler,
                flags,
                self.profile.restorer,
                self.profile.action_mask,
            ];
            for (chunk, expected) in actual.chunks_exact(8).zip(words) {
                if chunk != expected.to_le_bytes() {
                    return Err(GateError::Refused(
                        "signal action bytes differ from the fixed profile",
                    ));
                }
            }
        } else {
            let range = self
                .profile
                .alternate_stack
                .as_ref()
                .ok_or(GateError::Refused(
                    "signal alternate-stack setup was not declared",
                ))?;
            if self.alternate_installed || r.rsi != 0 {
                return Err(GateError::Refused(
                    "signal alternate-stack setup arguments differ",
                ));
            }
            let actual = writable_input(tid, r.rdi, 24)?;
            let words = [range.start, 0, range.end - range.start];
            for (chunk, expected) in actual.chunks_exact(8).zip(words) {
                if chunk != expected.to_le_bytes() {
                    return Err(GateError::Refused(
                        "signal alternate-stack bytes differ from the fixed profile",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn accept_setup_result(
        &mut self,
        tid: i32,
        input: &SelectedInput,
        result: i64,
        is_error: bool,
    ) -> Result<(), GateError> {
        // The input structure remains unmodified by both accepted syscalls:
        // their old-value output pointers are exactly null. Reread it after the
        // real EXIT rather than treating the configured intent as a result.
        self.check_setup(tid, input)?;
        if result != 0 || is_error {
            return Err(GateError::Refused(
                "native signal setup did not actually succeed",
            ));
        }
        if input.registers().rax == libc::SYS_rt_sigaction as u64 {
            self.action_installed = true;
        } else {
            self.alternate_installed = true;
        }
        Ok(())
    }
}
