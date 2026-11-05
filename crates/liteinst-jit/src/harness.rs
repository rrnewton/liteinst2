//! In-process guest setup shared by the driver and tests: fixture
//! bytes mapped RX (the admitted source region), a private guest
//! stack with a zero return sentinel, and initial state construction.

use crate::refuse::Refuse;
use crate::state::GuestState;
use crate::types::{Generation, RegionFacts};

pub const RETURN_SENTINEL: u64 = 0;

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

    pub fn stack_top(&self) -> u64 {
        (self.stack as u64) + (self.stack_len as u64) - 8
    }

    /// Initial guest state: entry at the fixture base, stack planted
    /// with the return sentinel, flags at the architectural reset
    /// value used by the oracle child as well (`0x2`).
    pub fn initial_state(&self) -> GuestState {
        GuestState {
            rsp: self.stack_top(),
            rflags: 0x2,
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
