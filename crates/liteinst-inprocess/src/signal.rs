//! Setup uses libc only to obtain its genuine signal restorer and map the
//! altstack. Exact kernel action/mask snapshots are restored with raw syscalls:
//! libc may otherwise add SA_RESTORER or filter its reserved signal bits.
use crate::{GateError, fault, raw};
use core::ptr;

const PAGE: usize = 4096;
const STACK: usize = 256 * 1024;

#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct KernelAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

fn errno(operation: &'static str) -> GateError {
    // SAFETY: only ordinary setup/teardown calls this libc TLS accessor.
    GateError::Os {
        operation,
        errno: unsafe { *libc::__errno_location() },
    }
}
fn action() -> Result<KernelAction, GateError> {
    let mut action = KernelAction::default();
    // SAFETY: exact Linux x86-64 rt_sigaction layout and 8-byte kernel mask.
    let rc = unsafe {
        raw::syscall4(
            libc::SYS_rt_sigaction as usize,
            libc::SIGSEGV as usize,
            0,
            (&mut action as *mut KernelAction) as usize,
            8,
        )
    };
    if raw::result(rc, "query kernel SIGSEGV")? != 0 {
        return Err(GateError::Invalid("kernel SIGSEGV query result"));
    }
    Ok(action)
}
fn restore_action(action: &KernelAction) -> Result<(), GateError> {
    // SAFETY: restores exactly the actual retained kernel action.
    let rc = unsafe {
        raw::syscall4(
            libc::SYS_rt_sigaction as usize,
            libc::SIGSEGV as usize,
            (action as *const KernelAction) as usize,
            0,
            8,
        )
    };
    if raw::result(rc, "restore kernel SIGSEGV")? != 0 {
        return Err(GateError::Invalid("kernel SIGSEGV restore result"));
    }
    Ok(())
}
fn current_mask() -> Result<u64, GateError> {
    let mut mask = 0_u64;
    // SAFETY: kernel mask is exactly one initialized u64 on this target.
    let rc = unsafe {
        raw::syscall4(
            libc::SYS_rt_sigprocmask as usize,
            libc::SIG_SETMASK as usize,
            0,
            (&mut mask as *mut u64) as usize,
            8,
        )
    };
    if raw::result(rc, "query kernel signal mask")? != 0 {
        return Err(GateError::Invalid("kernel mask query result"));
    }
    Ok(mask)
}
fn set_mask(mask: u64) -> Result<(), GateError> {
    // SAFETY: the kernel ignores SIGKILL/SIGSTOP bits; no libc filtering occurs.
    let rc = unsafe {
        raw::syscall4(
            libc::SYS_rt_sigprocmask as usize,
            libc::SIG_SETMASK as usize,
            (&mask as *const u64) as usize,
            0,
            8,
        )
    };
    if raw::result(rc, "set kernel signal mask")? != 0 {
        return Err(GateError::Invalid("kernel mask set result"));
    }
    Ok(())
}

pub(crate) struct SignalOwner {
    prior_action: KernelAction,
    installed_action: KernelAction,
    prior_mask: u64,
    prior_stack: libc::stack_t,
    mapping: *mut libc::c_void,
    mapped: bool,
    stack_installed: bool,
    action_installed: bool,
    blocked: bool,
    closed: bool,
}

impl SignalOwner {
    pub(crate) fn install() -> Result<Self, GateError> {
        let mut owner = Self {
            prior_action: action()?,
            installed_action: KernelAction::default(),
            prior_mask: current_mask()?,
            // SAFETY: initialized complete native output structure.
            prior_stack: unsafe { core::mem::zeroed() },
            mapping: ptr::null_mut(),
            mapped: false,
            stack_installed: false,
            action_installed: false,
            blocked: false,
            closed: true,
        };
        // SAFETY: query writes a complete initialized stack_t.
        if unsafe { libc::sigaltstack(ptr::null(), &mut owner.prior_stack) } != 0 {
            return Err(errno("query altstack"));
        }
        if owner.prior_action.handler != libc::SIG_DFL
            || owner.prior_mask & (1 << (libc::SIGSEGV - 1)) != 0
            || owner.prior_stack.ss_flags & libc::SS_ONSTACK != 0
        {
            return Err(GateError::Invalid(
                "SIGSEGV/default/unblocked/altstack contract",
            ));
        }
        // AT_MINSIGSTKSZ is Linux UAPI 51. A nested SIGSEGV reaches only the
        // immediate fail-stop guard, but still needs a second genuine frame.
        let minimum = unsafe { libc::getauxval(51) } as usize;
        if minimum == 0
            || minimum
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(64 * 1024))
                .filter(|bytes| *bytes <= STACK)
                .is_none()
        {
            return Err(GateError::Invalid(
                "host signal frames exceed altstack profile",
            ));
        }
        owner.closed = false;
        owner.block()?;
        // SAFETY: new private anonymous guard mapping, no application aliases.
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                STACK + 2 * PAGE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(errno("map altstack"));
        }
        owner.mapping = mapping;
        owner.mapped = true;
        let stack = (mapping as usize + PAGE) as *mut libc::c_void;
        let protection = raw::result(
            raw::protect(stack as usize, STACK, libc::PROT_READ | libc::PROT_WRITE),
            "altstack protection",
        )?;
        if protection != 0 {
            return Err(GateError::Invalid("altstack protection result"));
        }
        // SAFETY: touch every owned writable data page before NX activation.
        for offset in (0..STACK).step_by(PAGE) {
            unsafe {
                ptr::write_volatile((stack as *mut u8).add(offset), 0);
            }
        }
        let next_stack = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: STACK,
        };
        // SAFETY: mapped storage stays owned through exact prior restoration.
        if unsafe { libc::sigaltstack(&next_stack, ptr::null_mut()) } != 0 {
            return Err(errno("install altstack"));
        }
        owner.stack_installed = true;
        let mut next_action: libc::sigaction = unsafe { core::mem::zeroed() };
        next_action.sa_sigaction = fault::handler as *const () as usize;
        next_action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
        // Only SIGSEGV may reenter; the atomic guard immediately poisons and
        // exits before any nested source access or permission operation.
        if unsafe { libc::sigfillset(&mut next_action.sa_mask) } != 0
            || unsafe { libc::sigdelset(&mut next_action.sa_mask, libc::SIGSEGV) } != 0
        {
            return Err(errno("handler mask"));
        }
        // SIGILL disposition is never changed. libc installs its genuine
        // rt_sigreturn restorer; capture the exact resulting kernel action.
        if unsafe { libc::sigaction(libc::SIGSEGV, &next_action, ptr::null_mut()) } != 0 {
            return Err(errno("install SIGSEGV"));
        }
        owner.action_installed = true;
        owner.installed_action = action().unwrap_or_else(|_| raw::fatal());
        Ok(owner)
    }

    pub(crate) fn block(&mut self) -> Result<(), GateError> {
        if self.blocked {
            return Ok(());
        }
        if current_mask()? != self.prior_mask {
            return Err(GateError::Invalid(
                "caller changed signal mask while owning gate",
            ));
        }
        set_mask(u64::MAX)?;
        self.blocked = true;
        Ok(())
    }

    pub(crate) fn release_mask(&mut self) -> Result<(), GateError> {
        if self.blocked {
            set_mask(self.prior_mask)?;
            self.blocked = false;
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) -> Result<(), GateError> {
        if self.closed {
            return Ok(());
        }
        if !self.blocked && !self.mapped && !self.stack_installed && !self.action_installed {
            self.closed = true;
            return Ok(());
        }
        self.block()?;
        if self.action_installed {
            if action()? != self.installed_action {
                return Err(GateError::Invalid("SIGSEGV ownership changed"));
            }
            restore_action(&self.prior_action)?;
            if action()? != self.prior_action {
                return Err(GateError::Invalid("SIGSEGV restoration differs"));
            }
            self.action_installed = false;
        }
        if self.stack_installed {
            let mut actual: libc::stack_t = unsafe { core::mem::zeroed() };
            if unsafe { libc::sigaltstack(ptr::null(), &mut actual) } != 0 {
                return Err(errno("verify altstack"));
            }
            if actual.ss_sp as usize != self.mapping as usize + PAGE
                || actual.ss_size != STACK
                || actual.ss_flags != 0
            {
                return Err(GateError::Invalid("altstack ownership changed"));
            }
            if unsafe { libc::sigaltstack(&self.prior_stack, ptr::null_mut()) } != 0 {
                return Err(errno("restore altstack"));
            }
            let mut restored: libc::stack_t = unsafe { core::mem::zeroed() };
            if unsafe { libc::sigaltstack(ptr::null(), &mut restored) } != 0 {
                return Err(errno("verify restored altstack"));
            }
            if restored.ss_sp != self.prior_stack.ss_sp
                || restored.ss_size != self.prior_stack.ss_size
                || restored.ss_flags != self.prior_stack.ss_flags
            {
                return Err(GateError::Invalid("altstack restoration differs"));
            }
            self.stack_installed = false;
        }
        if self.mapped {
            if unsafe { libc::munmap(self.mapping, STACK + 2 * PAGE) } != 0 {
                return Err(errno("unmap altstack"));
            }
            self.mapped = false;
        }
        self.release_mask()?;
        if current_mask()? != self.prior_mask {
            return Err(GateError::Invalid("signal mask restoration differs"));
        }
        self.closed = true;
        Ok(())
    }
}

impl Drop for SignalOwner {
    fn drop(&mut self) {
        if self.close().is_err() {
            raw::fatal();
        }
    }
}
