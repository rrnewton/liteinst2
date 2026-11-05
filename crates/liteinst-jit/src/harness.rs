//! In-process guest setup shared by the driver and tests: fixture
//! bytes mapped RX (the admitted source region), a private guest
//! stack with a zero return sentinel, and initial state construction.

use crate::refuse::Refuse;
use crate::state::GuestState;
use crate::types::{Generation, RegionFacts};

pub const RETURN_SENTINEL: u64 = 0;
pub const REDZONE_MARKER: u64 = 0x1122_3344_5566_7788;

pub struct MappedGuest {
    code: *mut u8,
    code_len: usize,
    stack: *mut u8,
    stack_len: usize,
    pub base: u64,
}

impl MappedGuest {
    pub fn map(bytes: &[u8]) -> Result<MappedGuest, Refuse> {
        let page = 4096usize;
        let code_len = bytes.len().div_ceil(page) * page;
        let stack_len = 64 * 1024usize;
        let map = |len: usize| -> Result<*mut u8, Refuse> {
            // SAFETY: anonymous private mapping of `len` bytes.
            let p = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                return Err(Refuse::MappingPolicy {
                    operation: "mmap guest",
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                });
            }
            Ok(p.cast())
        };
        let code = map(code_len.max(page))?;
        let stack = map(stack_len)?;
        // SAFETY: both mappings are RW with the recorded lengths.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), code, bytes.len());
            if libc::mprotect(
                code.cast(),
                code_len.max(page),
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
            {
                return Err(Refuse::MappingPolicy {
                    operation: "mprotect guest RX",
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                });
            }
            let top = stack.add(stack_len - 8);
            (top as *mut u64).write(RETURN_SENTINEL);
        }
        Ok(MappedGuest {
            code,
            code_len: code_len.max(page),
            stack,
            stack_len,
            base: code as u64,
        })
    }

    pub fn region(&self, bytes: &[u8], generation: Generation) -> RegionFacts {
        RegionFacts {
            base: self.base,
            bytes: bytes.to_vec(),
            generation,
            immutable_private: true,
        }
    }

    /// Plant a witness qword immediately below the initial RSP
    /// (the red-zone slot a correct entry transfer must not write).
    pub fn plant_below_rsp(&self, value: u64) {
        // SAFETY: the slot is inside the owned stack mapping.
        unsafe {
            ((self.stack_top() - 8) as *mut u64).write(value);
        }
    }

    /// Stack bytes `[top-128, top+8]` for full-state comparison.
    pub fn stack_window(&self) -> Vec<u8> {
        // SAFETY: inside the owned stack mapping.
        unsafe { core::slice::from_raw_parts((self.stack_top() - 128) as *const u8, 136).to_vec() }
    }

    pub fn stack_top(&self) -> u64 {
        (self.stack as u64) + (self.stack_len as u64) - 8
    }

    /// Per-fixture argument registers `(rdi, rsi, rdx, rax, rcx)`,
    /// shared verbatim by the JIT driver, the oracle child setup,
    /// and the tests so both engines see identical inputs.
    pub fn fixture_args(
        name: &str,
        base: u64,
        data: u64,
        dst: u64,
        src: u64,
    ) -> (u64, u64, u64, u64, u64) {
        match name {
            "sum_loop" | "branchy_even_sum" | "call_helper" => (data, 16, 0, 0, 0),
            "flags_adc" => (3, 5, 0, 10, 0),
            "rip_data" => (1, 0, 0, 0, 0),
            "rep_movsb" => (dst, src, 32, 0, 0),
            "rep_zero" => (dst, src, 0, 0, 0),
            "rep_movsw_prefix" => (dst, src, 16, 0, 0),
            "compiled_c" => (data, 16, 0, 0, 0),
            "cpuid_loop" => (0, 20_000, 0, 0, 0),
            "loop_insn" | "loopne_insn" | "loope_insn" => (0, 7, 0, 0, 0),
            "rep_stosb_ok" => (dst, 0, 32, 0, 0),
            "repne_scasb" => (src, 0, 32, 0, 0),
            "rep_lodsq" => (0, src, 0, 0, 0),
            "jrcxz" => (0, 0, 0, 0, 0),
            "syscall_write" => (0, src, 5, 0, 0),
            "fault_load" | "redzone_reentry" => (data, 0, 0, 0, 0),
            "indirect_jmp" => (base, 0, 0, 0, 0),
            _ => (0, 0, 0, 0, 0),
        }
    }

    /// Initial guest state: entry at the fixture base, stack planted
    /// with the return sentinel, flags at the architectural reset
    /// value used by the oracle child as well (`0x202`).
    pub fn initial_state(&self) -> GuestState {
        GuestState {
            rsp: self.stack_top(),
            // IF set, all status bits clear: matches the oracle,
            // whose ptrace SETREGS rejects a cleared IF.
            rflags: 0x202,
            rip: self.base,
            ..GuestState::default()
        }
    }
}

impl Drop for MappedGuest {
    fn drop(&mut self) {
        // SAFETY: owned mappings from `map`.
        unsafe {
            libc::munmap(self.code.cast(), self.code_len);
            libc::munmap(self.stack.cast(), self.stack_len);
        }
    }
}

/// A destination buffer whose writable tail ends exactly at a
/// PROT_NONE page, for partial-progress REP fault fixtures.
pub struct GuardedDst {
    base: *mut u8,
    pub ptr: u64,
}

impl GuardedDst {
    pub fn new() -> Result<GuardedDst, Refuse> {
        // SAFETY: two-page anonymous mapping owned by the result.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(Refuse::MappingPolicy {
                operation: "mmap guarded dst",
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: second page of our fresh mapping.
        let rc =
            unsafe { libc::mprotect((base as *mut u8).add(4096).cast(), 4096, libc::PROT_NONE) };
        assert_eq!(rc, 0, "mprotect guard page");
        let base = base as *mut u8;
        Ok(GuardedDst {
            ptr: base as u64 + 4096 - 16,
            base,
        })
    }
    pub fn head16(&self) -> Vec<u8> {
        // SAFETY: the 16 bytes before the guard page are ours.
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, 16).to_vec() }
    }
}

impl Drop for GuardedDst {
    fn drop(&mut self) {
        // SAFETY: owned mapping from `new`.
        unsafe {
            libc::munmap(self.base.cast(), 8192);
        }
    }
}
