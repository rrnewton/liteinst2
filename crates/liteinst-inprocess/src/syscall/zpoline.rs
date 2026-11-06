//! One certified eager x86-64 zpoline site.
//!
//! A proven native `syscall` (`0f 05`) is replaced in place by the
//! same-length `call *%rax` (`ff d0`). For every admitted canonical syscall
//! number, that call lands in a one-page NOP sled at virtual address zero.
//! The sled restores the pre-call stack pointer with `lea` and jumps to the
//! core exact-syscall trampoline; the trampoline's callback authenticates the
//! call return slot left in the red zone before delegating to the existing
//! selected-syscall forwarding callback.
//!
//! This is deliberately one certified site, not a census, lazypoline, or
//! whole-program mechanism. Mapping virtual address zero is a run-level
//! prerequisite and is reported as a named environment refusal when denied.

use std::collections::BTreeMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use liteinst::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, FailureStage, LegalEntrySet, QuiescenceLease,
    Refusal, ResumeObligation,
};
use liteinst::scanner::{InstructionScanner, ScanError};
use liteinst::sync_core::{SyncCore, SyncCoreError};
use liteinst::trampoline::{
    ExecutableTrampoline, HookCallback, HookContext, TrampolineError, TrampolinePlan,
};
use liteinst::x86::OpKind;

use crate::selected::{
    REJECTED_SYSCALL_EXIT_STATUS, SelectedInstruction, SelectedKind, decode_selected,
    syscall_callback,
};
use crate::syscall::{
    SyscallRefusal, SyscallStrategy, SyscallStrategyConfig, first_profile_supports,
};

const ORIGINAL_SYSCALL: [u8; 2] = [0x0f, 0x05];
const ZPOLINE_CALL_RAX: [u8; 2] = [0xff, 0xd0];
const COMMON_STUB_LEN: usize = 19;
// Both aliases are unmapped before this seal set is added, so retaining
// F_SEAL_WRITE leaves no writable path: the RW alias is gone, future writes
// and writable mappings are sealed, and only then is VA 0 remapped RX.
const SLED_SEALS: c_int = libc::F_SEAL_WRITE
    | libc::F_SEAL_FUTURE_WRITE
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SEAL;
const OWNER_EMPTY: u8 = 0;
const OWNER_INSTALLING: u8 = 1;
const OWNER_INSTALLED: u8 = 2;
const OWNER_POISONED: u8 = 3;

static ZPOLINE_OWNER: AtomicU8 = AtomicU8::new(OWNER_EMPTY);

#[derive(Clone, Copy)]
struct HookSite {
    logical_pc: u64,
    return_pc: u64,
    syscall_nr: u32,
    delegate: HookCallback,
}

static ZPOLINE_HOOK_SITES: AtomicPtr<HookSite> = AtomicPtr::new(std::ptr::null_mut());
static ZPOLINE_HOOK_SITES_LEN: AtomicUsize = AtomicUsize::new(0);

fn publish_hook_sites(sites: &[HookSite]) {
    ZPOLINE_HOOK_SITES_LEN.store(sites.len(), Ordering::Release);
    ZPOLINE_HOOK_SITES.store(sites.as_ptr().cast_mut(), Ordering::Release);
}

/// Exact low-page sled geometry for one validated config and host page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZpolineSledLayout {
    page_size: usize,
    max_syscall_nr: u32,
    common_entry: usize,
}

impl ZpolineSledLayout {
    /// Size of the single sled page.
    pub const fn page_size(self) -> usize {
        self.page_size
    }

    /// Inclusive largest syscall number that lands in the NOP sled.
    pub const fn max_syscall_nr(self) -> u32 {
        self.max_syscall_nr
    }

    /// Offset of the stack-adjusting common stub within virtual page zero.
    pub const fn common_entry(self) -> usize {
        self.common_entry
    }

    fn new(page_size: usize, max_syscall_nr: u32) -> Result<Self, SyscallRefusal> {
        if !page_size.is_power_of_two() || page_size < 4096 {
            return Err(SyscallRefusal::InvalidConfig {
                field: "page_size",
                reason: "must be a power of two and at least 4096",
            });
        }
        let first_stub_offset =
            (max_syscall_nr as usize)
                .checked_add(1)
                .ok_or(SyscallRefusal::InvalidConfig {
                    field: "max_syscall_nr",
                    reason: "common-entry offset overflows",
                })?;
        let common_entry = first_stub_offset.next_multiple_of(16);
        if common_entry
            .checked_add(COMMON_STUB_LEN)
            .is_none_or(|end| end > page_size)
        {
            return Err(SyscallRefusal::InvalidConfig {
                field: "max_syscall_nr",
                reason: "sled common stub does not fit in one host page",
            });
        }
        Ok(Self {
            page_size,
            max_syscall_nr,
            common_entry,
        })
    }

    fn build(self, handler: u64) -> Vec<u8> {
        let mut sled = vec![0x90; self.page_size];
        let stub = &mut sled[self.common_entry..self.common_entry + COMMON_STUB_LEN];
        // lea rsp, [rsp+8]; jmp qword ptr [rip+0]; handler address.
        stub[0..5].copy_from_slice(&[0x48, 0x8d, 0x64, 0x24, 0x08]);
        stub[5..11].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
        stub[11..19].copy_from_slice(&handler.to_le_bytes());
        sled
    }
}

fn host_page_size() -> Result<usize, SyscallRefusal> {
    // SAFETY: sysconf with the page-size name has no pointer arguments.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = usize::try_from(value).map_err(|_| SyscallRefusal::AllocationUnavailable)?;
    ZpolineSledLayout::new(page_size, 0).map(|_| page_size)
}

pub(crate) struct DualMapping {
    fd: c_int,
    writable: *mut u8,
    executable: *mut u8,
    executable_mapped: bool,
    address: u64,
    len: usize,
    committed: bool,
}

impl DualMapping {
    fn probe_sled(len: usize) -> Result<Self, SyscallRefusal> {
        Self::probe_at(len, 0, b"liteinst-zpoline-sled\0")
    }

    pub(crate) fn probe_at(len: usize, address: u64, name: &[u8]) -> Result<Self, SyscallRefusal> {
        let mut mapping = Self::new_memfd(len, address, name)?;
        mapping.map_executable()?;
        Ok(mapping)
    }

    pub(crate) fn probe_anywhere(len: usize, name: &[u8]) -> Result<Self, SyscallRefusal> {
        let mut mapping = Self::new_memfd(len, 0, name)?;
        // SAFETY: a fresh shared executable alias of the sized owned memfd;
        // the kernel chooses its address.
        let executable = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                mapping.fd,
                0,
            )
        };
        if executable == libc::MAP_FAILED {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        mapping.address = executable as u64;
        mapping.executable = executable.cast::<u8>();
        mapping.executable_mapped = true;
        Ok(mapping)
    }

    fn new_memfd(len: usize, address: u64, name: &[u8]) -> Result<Self, SyscallRefusal> {
        // SAFETY: the name is NUL-terminated and memfd creation returns either
        // a new owned descriptor or -1 with errno.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                libc::MFD_CLOEXEC | 0x0002,
            )
        };
        if fd < 0 || fd > i64::from(c_int::MAX) {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        let fd = fd as c_int;
        let mut mapping = Self {
            fd,
            writable: std::ptr::null_mut(),
            executable: std::ptr::null_mut(),
            executable_mapped: false,
            address,
            len,
            committed: false,
        };
        // SAFETY: fd is the owned memfd created above.
        if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: a fresh shared writable alias of the sized owned memfd.
        let writable = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if writable == libc::MAP_FAILED {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        mapping.writable = writable.cast::<u8>();
        Ok(mapping)
    }

    fn map_executable(&mut self) -> Result<(), SyscallRefusal> {
        if self.executable_mapped || self.fd < 0 {
            return Err(SyscallRefusal::AllocationUnavailable);
        }
        // SAFETY: MAP_FIXED_NOREPLACE asks for exactly self.address and
        // cannot replace an existing mapping on supported kernels.
        let executable = unsafe {
            libc::mmap(
                self.address as *mut c_void,
                self.len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                self.fd,
                0,
            )
        };
        if executable == libc::MAP_FAILED {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(if self.address == 0 && errno == libc::EEXIST {
                SyscallRefusal::LowPageOccupied
            } else if self.address == 0 {
                SyscallRefusal::LowPageUnavailable { errno }
            } else {
                SyscallRefusal::AllocationUnavailable
            });
        }
        if executable as u64 != self.address {
            // An old kernel ignoring NOREPLACE could relocate or replace; do
            // not retain a mapping anywhere except the exact requested page.
            // SAFETY: executable is the mapping just returned.
            unsafe { libc::munmap(executable, self.len) };
            return Err(if self.address == 0 {
                SyscallRefusal::LowPageUnavailable {
                    errno: libc::EADDRNOTAVAIL,
                }
            } else {
                SyscallRefusal::AllocationUnavailable
            });
        }
        self.executable = executable.cast::<u8>();
        self.executable_mapped = true;
        Ok(())
    }

    fn unmap_writable(&mut self) -> Result<(), SyscallRefusal> {
        if self.writable.is_null() {
            return Ok(());
        }
        // SAFETY: writable is still this mapping's owned alias.
        if unsafe { libc::munmap(self.writable.cast::<c_void>(), self.len) } != 0 {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        self.writable = std::ptr::null_mut();
        Ok(())
    }

    fn unmap_executable(&mut self) -> Result<(), SyscallRefusal> {
        if !self.executable_mapped {
            return Ok(());
        }
        // SAFETY: executable is exactly address zero for len bytes. The
        // separate boolean distinguishes it from an absent mapping.
        if unsafe { libc::munmap(self.executable.cast::<c_void>(), self.len) } != 0 {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        self.executable_mapped = false;
        Ok(())
    }

    fn read_back(&self) -> Result<Vec<u8>, SyscallRefusal> {
        if self.fd < 0 {
            return Err(SyscallRefusal::AllocationUnavailable);
        }
        let mut observed = vec![0; self.len];
        let mut offset = 0_usize;
        while offset < self.len {
            // SAFETY: fd is the owned memfd; the output slice and file offset
            // cover exactly the remaining sled bytes. This deliberately does
            // not form or dereference a Rust pointer at VA 0.
            let read = unsafe {
                libc::pread(
                    self.fd,
                    observed[offset..].as_mut_ptr().cast::<c_void>(),
                    self.len - offset,
                    offset as libc::off_t,
                )
            };
            if read > 0 {
                offset += read as usize;
            } else if read == 0 {
                return Err(SyscallRefusal::MemfdDualMapFailed { errno: libc::EIO });
            } else {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno != libc::EINTR {
                    return Err(SyscallRefusal::MemfdDualMapFailed { errno });
                }
            }
        }
        Ok(observed)
    }

    pub(crate) fn publish_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, SyscallRefusal> {
        if bytes.len() != self.len
            || self.writable.is_null()
            || !self.executable_mapped
            || self.committed
        {
            return Err(SyscallRefusal::AllocationUnavailable);
        }
        // SAFETY: the writable alias covers exactly len bytes from the owned
        // memfd. Verification below uses pread, never a VA-0 pointer read.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.writable, bytes.len());
        }
        if self.read_back()? != bytes {
            return Err(SyscallRefusal::ExpectedBytesChanged);
        }

        // F_SEAL_WRITE requires both shared aliases to be gone. Remove RW
        // first, then RX, seal the backing, and only then remap RX at VA 0.
        self.unmap_writable()?;
        self.unmap_executable()?;
        let seals = SLED_SEALS;
        // SAFETY: fd remains the owned memfd and neither alias remains.
        if unsafe { libc::fcntl(self.fd, libc::F_ADD_SEALS, seals) } != 0 {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: querying seals does not mutate the backing.
        let observed_seals = unsafe { libc::fcntl(self.fd, libc::F_GET_SEALS) };
        if observed_seals < 0 || observed_seals & seals != seals {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        self.map_executable()?;
        let observed = self.read_back()?;
        // SAFETY: the remapped executable alias retains the backing after
        // descriptor close.
        unsafe { libc::close(self.fd) };
        self.fd = -1;
        if observed != bytes {
            return Err(SyscallRefusal::ExpectedBytesChanged);
        }
        Ok(observed)
    }

    pub(crate) fn unmap(&mut self) -> Result<(), SyscallRefusal> {
        let writable = self.unmap_writable();
        let executable = self.unmap_executable();
        if self.fd >= 0 {
            // SAFETY: fd is still owned here.
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
        writable.and(executable)
    }

    pub(crate) fn address(&self) -> u64 {
        self.address
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn commit(mut self) -> Self {
        self.committed = true;
        self
    }
}

fn align_up(value: u64, align: u64) -> Option<u64> {
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

/// Builds the sled-to-handler dispatcher for a batch. The sled jumps here;
/// this veneer authenticates only routing by the call return address, then
/// restores flags/R11 and the pre-call RSP before entering the exact
/// per-site trampoline. Temporary state is below the red zone, in the same
/// writable stack area the exact trampoline is already certified to use.
fn build_dispatcher(sites: &[(u64, u64)]) -> Result<Vec<u8>, SyscallRefusal> {
    if sites.is_empty() {
        return Err(SyscallRefusal::InvalidConfig {
            field: "sites",
            reason: "dispatcher requires at least one site",
        });
    }
    let header_len = 19usize;
    let compare_len = 13usize;
    let fail_len = 13usize;
    let found_len = 17usize;
    let fail_offset = header_len + compare_len * sites.len();
    let found_offset = fail_offset + fail_len;
    let constants_offset = (found_offset + found_len * sites.len()).next_multiple_of(8);
    let handler_constants = constants_offset + sites.len() * 8;
    let total = handler_constants + sites.len() * 8;
    let mut bytes = vec![0x90; total];
    // lea rsp,[rsp-144]; pushfq; push r11; mov r11,[rsp+160]
    bytes[0..8].copy_from_slice(&[0x48, 0x8d, 0xa4, 0x24, 0x70, 0xff, 0xff, 0xff]);
    bytes[8] = 0x9c;
    bytes[9..11].copy_from_slice(&[0x41, 0x53]);
    bytes[11..19].copy_from_slice(&[0x4c, 0x8b, 0x9c, 0x24, 0x98, 0x00, 0x00, 0x00]);

    for (index, &(return_pc, handler)) in sites.iter().enumerate() {
        let compare = header_len + index * compare_len;
        bytes[compare..compare + 3].copy_from_slice(&[0x4d, 0x3b, 0x1d]);
        let constant = constants_offset + index * 8;
        let disp = i32::try_from(constant as i64 - (compare + 7) as i64)
            .map_err(|_| SyscallRefusal::AllocationUnavailable)?;
        bytes[compare + 3..compare + 7].copy_from_slice(&disp.to_le_bytes());
        bytes[compare + 7..compare + 9].copy_from_slice(&[0x0f, 0x84]);
        let found = found_offset + index * found_len;
        let rel = i32::try_from(found as i64 - (compare + compare_len) as i64)
            .map_err(|_| SyscallRefusal::AllocationUnavailable)?;
        bytes[compare + 9..compare + 13].copy_from_slice(&rel.to_le_bytes());
        bytes[constant..constant + 8].copy_from_slice(&return_pc.to_le_bytes());
        let handler_constant = handler_constants + index * 8;
        bytes[handler_constant..handler_constant + 8].copy_from_slice(&handler.to_le_bytes());

        bytes[found..found + 2].copy_from_slice(&[0x41, 0x5b]);
        bytes[found + 2] = 0x9d;
        bytes[found + 3..found + 11]
            .copy_from_slice(&[0x48, 0x8d, 0xa4, 0x24, 0x90, 0x00, 0x00, 0x00]);
        bytes[found + 11..found + 13].copy_from_slice(&[0xff, 0x25]);
        let jump_disp = i32::try_from(handler_constant as i64 - (found + found_len) as i64)
            .map_err(|_| SyscallRefusal::AllocationUnavailable)?;
        bytes[found + 13..found + 17].copy_from_slice(&jump_disp.to_le_bytes());
    }

    // pop r11; popfq; lea rsp,[rsp+152]; ud2
    bytes[fail_offset..fail_offset + 2].copy_from_slice(&[0x41, 0x5b]);
    bytes[fail_offset + 2] = 0x9d;
    bytes[fail_offset + 3..fail_offset + 11]
        .copy_from_slice(&[0x48, 0x8d, 0xa4, 0x24, 0x90, 0x00, 0x00, 0x00]);
    bytes[fail_offset + 11..fail_offset + 13].copy_from_slice(&[0x0f, 0x0b]);
    Ok(bytes)
}

struct DispatcherAllocation {
    mapping: DualMapping,
    family: crate::syscall::PlacementFamily,
    attempts: usize,
}

fn occupied_and_executable_ranges() -> Result<(Vec<AddressRange>, Vec<AddressRange>), SyscallRefusal>
{
    let text = std::fs::read_to_string("/proc/self/maps")
        .map_err(|_| SyscallRefusal::AllocationUnavailable)?;
    if text.len() > 2 * 1024 * 1024 {
        return Err(SyscallRefusal::AllocationUnavailable);
    }
    let mut occupied = Vec::new();
    let mut executable = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(addresses) = fields.next() else {
            continue;
        };
        let Some((start, end)) = addresses.split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end, 16) else {
            continue;
        };
        let Some(len) = end
            .checked_sub(start)
            .and_then(|len| usize::try_from(len).ok())
        else {
            continue;
        };
        let Ok(range) = AddressRange::new(start, len) else {
            continue;
        };
        occupied.push(range);
        if fields.next().is_some_and(|perms| perms.contains('x')) {
            executable.push(range);
        }
    }
    Ok((occupied, executable))
}

fn near_candidates(
    objects: &[AddressRange],
    occupied: &[AddressRange],
    executable: &[AddressRange],
    len: usize,
    page_size: usize,
    max_candidates: usize,
) -> Vec<u64> {
    let page = page_size as u64;
    let aligned_len = align_up(len as u64, page).unwrap_or(u64::MAX);
    let candidate_range = |start: u64| AddressRange::new(start, len).ok();
    let mut out: Vec<u64> = Vec::new();
    let push = |candidate: u64, out: &mut Vec<u64>| {
        if out.len() >= max_candidates || candidate < page || out.contains(&candidate) {
            return;
        }
        let Some(range) = candidate_range(candidate) else {
            return;
        };
        if occupied.iter().any(|used| used.overlaps(range)) {
            return;
        }
        out.push(candidate);
    };
    let mut anchors: Vec<AddressRange> = objects.to_vec();
    anchors.extend_from_slice(executable);
    for anchor in anchors {
        for delta_pages in [0_u64, 1, 2, 4, 8, 16, 32, 64, 256] {
            if let Some(after) = anchor
                .end()
                .checked_add(delta_pages * page)
                .and_then(|value| align_up(value, page))
            {
                push(after, &mut out);
            }
            if let Some(end_before) = anchor.start().checked_sub(delta_pages * page) {
                let before = align_down(end_before.saturating_sub(aligned_len), page);
                push(before, &mut out);
            }
            if out.len() >= max_candidates {
                return out;
            }
        }
    }
    out
}

fn allocate_dispatcher(
    len: usize,
    objects: &[AddressRange],
    budget: crate::syscall::PlacementBudget,
    page_size: usize,
) -> Result<DispatcherAllocation, SyscallRefusal> {
    let aligned_len = align_up(len as u64, page_size as u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(SyscallRefusal::AllocationUnavailable)?;
    let (occupied, executable) = occupied_and_executable_ranges()?;
    let candidates = near_candidates(
        objects,
        &occupied,
        &executable,
        aligned_len,
        page_size,
        budget.max_candidates(),
    );
    let mut attempts = 0usize;
    for candidate in candidates {
        attempts += 1;
        match DualMapping::probe_at(aligned_len, candidate, b"liteinst-zpoline-dispatcher\0") {
            Ok(mapping) => {
                return Ok(DispatcherAllocation {
                    mapping,
                    family: crate::syscall::PlacementFamily::NearAllocation,
                    attempts,
                });
            }
            Err(SyscallRefusal::AllocationUnavailable) => {}
            Err(error) => return Err(error),
        }
    }
    attempts += 1;
    let mapping = DualMapping::probe_anywhere(aligned_len, b"liteinst-zpoline-dispatcher\0")?;
    Ok(DispatcherAllocation {
        mapping,
        family: crate::syscall::PlacementFamily::MemfdDualMap,
        attempts,
    })
}

impl Drop for DualMapping {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.unmap();
        }
    }
}

fn qualify_host() -> Result<usize, SyscallRefusal> {
    let page_size = host_page_size()?;
    let leaf = core::arch::x86_64::__cpuid_count(7, 1);
    if leaf.edx & (1 << 21) != 0 {
        return Err(SyscallRefusal::StrategyUnavailableOnArch);
    }
    let cpu = core::arch::x86_64::__cpuid(1).eax;
    let model = ((cpu >> 4) & 15) | ((cpu >> 12) & 0xf0);
    if ((cpu >> 8) & 15) == 6 && matches!(model, 0x57 | 0x85) {
        return Err(SyscallRefusal::StrategyUnavailableOnArch);
    }
    // Linux ARCH_SHSTK_STATUS. Unsupported kernels return an error; any
    // successful nonzero feature word is outside this no-CET profile.
    let mut status = 0_u64;
    // SAFETY: status points to one writable u64 for the arch_prctl query.
    let result = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut status) };
    if result == 0 && status != 0 {
        return Err(SyscallRefusal::CetUnsupported);
    }
    Ok(page_size)
}

unsafe fn refuse_hook() -> ! {
    // SAFETY: this is the selected callback's fail-closed process exit. The
    // generated trampoline context is abandoned and no Rust state is reused.
    unsafe {
        core::arch::asm!(
            "syscall",
            "ud2",
            in("rax") libc::SYS_exit_group as u64,
            in("rdi") REJECTED_SYSCALL_EXIT_STATUS as u64,
            options(noreturn, nostack)
        );
    }
}

unsafe extern "C" fn zpoline_hook(context: *mut HookContext) {
    // SAFETY: the exact trampoline passes one live HookContext. The sled has
    // restored the original RSP; the zpoline call return remains at RSP-8 in
    // the untouched red zone for authentication here.
    let context = unsafe { &mut *context };
    let sites_ptr = ZPOLINE_HOOK_SITES.load(Ordering::Acquire);
    let sites_len = ZPOLINE_HOOK_SITES_LEN.load(Ordering::Acquire);
    if sites_ptr.is_null() || sites_len == 0 {
        // SAFETY: authentication failed before any genuine syscall.
        unsafe { refuse_hook() }
    }
    // SAFETY: publication stores the length before the pointer and retains
    // the boxed sorted table in the installed owner for every admitted route.
    let sites = unsafe { std::slice::from_raw_parts(sites_ptr, sites_len) };
    let Ok(index) =
        sites.binary_search_by_key(&context.instruction_pointer, |site| site.logical_pc)
    else {
        // SAFETY: unauthenticated sled entry is refused before forwarding.
        unsafe { refuse_hook() }
    };
    let expected = sites[index];
    let Some(return_slot) = context.stack_pointer.checked_sub(8) else {
        // SAFETY: authentication failed before any genuine syscall.
        unsafe { refuse_hook() }
    };
    // SAFETY: the publish contract keeps the original red-zone word readable
    // and the exact trampoline does not overwrite it.
    let observed_return = unsafe { std::ptr::read_volatile(return_slot as *const u64) };
    if context.rax != u64::from(expected.syscall_nr) || observed_return != expected.return_pc {
        // SAFETY: unauthenticated sled entry is refused before forwarding.
        unsafe { refuse_hook() }
    }
    // SAFETY: context remains the live trampoline context for this call.
    unsafe { (expected.delegate)(context) }
}

fn claim_owner() -> Result<(), SyscallRefusal> {
    match ZPOLINE_OWNER.compare_exchange(
        OWNER_EMPTY,
        OWNER_INSTALLING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Ok(()),
        Err(OWNER_INSTALLED) => Err(SyscallRefusal::StrategyAlreadyInstalled),
        Err(OWNER_POISONED) => Err(SyscallRefusal::PublicationPoisoned),
        Err(_) => Err(SyscallRefusal::ConflictingStrategyInstalled),
    }
}

fn release_owner() {
    let _ = ZPOLINE_OWNER.compare_exchange(
        OWNER_INSTALLING,
        OWNER_EMPTY,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

fn core_refusal(error: Refusal) -> SyscallRefusal {
    match error {
        Refusal::NotInstructionHead => SyscallRefusal::NotInstructionHead,
        Refusal::ExpectedBytesChanged => SyscallRefusal::ExpectedBytesChanged,
        Refusal::StaleGeneration => SyscallRefusal::StaleGeneration,
        Refusal::DependencyNotHeld => SyscallRefusal::DependencyNotHeld,
        Refusal::OwnershipConflict => SyscallRefusal::OwnershipConflict,
        Refusal::AllocationUnavailable => SyscallRefusal::AllocationUnavailable,
        Refusal::SignalContract => SyscallRefusal::SignalContract,
        Refusal::Synchronization => SyscallRefusal::SynchronizationFailed,
        Refusal::InvalidRange | Refusal::InvalidPlan => SyscallRefusal::InvalidConfig {
            field: "site",
            reason: "core rejected the certified site or plan",
        },
        Refusal::UnsupportedSemantics(_) => SyscallRefusal::NotSyscallSite,
        _ => SyscallRefusal::StrategyUnavailableOnBackend,
    }
}

fn trampoline_refusal(error: TrampolineError) -> SyscallRefusal {
    match error {
        TrampolineError::SiteNotFound { .. } => SyscallRefusal::NotInstructionHead,
        TrampolineError::NotExactSyscall { .. } => SyscallRefusal::NotSyscallSite,
        TrampolineError::NoReachableMapping => SyscallRefusal::NearAllocationExhausted,
        TrampolineError::BackingStore { .. }
        | TrampolineError::ProcessMaps { .. }
        | TrampolineError::ExactAddressUnavailable { .. }
        | TrampolineError::ArenaFull
        | TrampolineError::CodeTooLarge { .. }
        | TrampolineError::InvalidPageSize => SyscallRefusal::AllocationUnavailable,
        TrampolineError::UnsupportedPlatform => SyscallRefusal::StrategyUnavailableOnArch,
        TrampolineError::ReturnAddressOverflow { .. }
        | TrampolineError::AddressNotRepresentable { .. } => SyscallRefusal::InvalidConfig {
            field: "logical_pc",
            reason: "address or return address is not representable",
        },
        _ => SyscallRefusal::StrategyUnavailableOnBackend,
    }
}

fn scan_refusal(error: ScanError) -> SyscallRefusal {
    match error {
        ScanError::InvalidInstruction { .. } => SyscallRefusal::NotInstructionHead,
        ScanError::AddressRangeOverflow { .. } | ScanError::AddressNotRepresentable { .. } => {
            SyscallRefusal::InvalidConfig {
                field: "code",
                reason: "snapshot address range is not representable",
            }
        }
        ScanError::PrefixTooShort { .. } | ScanError::UnsupportedCacheLineGeometry { .. } => {
            SyscallRefusal::InvalidConfig {
                field: "code",
                reason: "snapshot scan geometry is unsupported",
            }
        }
    }
}

/// Caller-certified facts for the one eager zpoline site in this slice.
///
/// `syscall_nr` certifies that every execution reaching `logical_pc` holds
/// that exact canonical, zero-extended syscall number in RAX. A generic
/// dynamic syscall wrapper therefore needs a stronger future certificate and
/// is not admitted by merely naming one observed number as a guess.
pub struct ZpolineSite<'a> {
    /// Frozen strategy selection; its strategy must be `Zpoline`.
    pub config: SyscallStrategyConfig,
    /// Actual mapping incarnation and generation.
    pub identity: CodeIdentity,
    /// Immutable original snapshot, authenticated again during publication.
    pub code: &'a [u8],
    /// Executable address corresponding to the first snapshot byte.
    pub base_address: u64,
    /// Actual native `syscall` instruction head.
    pub logical_pc: u64,
    /// Complete entry and resume facts for this exact generation.
    pub entries: &'a LegalEntrySet,
    /// Exact canonical syscall number certified for every execution.
    pub syscall_nr: u32,
}

/// Exact handler plan and source/sled facts for one certified zpoline site.
/// Preparation maps and patches nothing.
pub struct PreparedZpoline {
    config: SyscallStrategyConfig,
    instruction: SelectedInstruction,
    identity: CodeIdentity,
    base_address: u64,
    logical_pc: u64,
    return_pc: u64,
    syscall_nr: u32,
    source: Vec<u8>,
    expected_source: Vec<u8>,
    plan: TrampolinePlan,
    delegate: HookCallback,
    sled_layout: ZpolineSledLayout,
}

impl PreparedZpoline {
    /// Validates the certified site and builds the exact-syscall handler plan.
    pub fn prepare(site: ZpolineSite<'_>) -> Result<Self, SyscallRefusal> {
        site.config.validate()?;
        if site.config.strategy() != SyscallStrategy::Zpoline {
            return Err(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "zpoline site requires the zpoline strategy",
            });
        }
        if site.syscall_nr > site.config.max_syscall_nr() {
            return Err(SyscallRefusal::SyscallNumberRangeUnproven);
        }
        if !first_profile_supports(site.syscall_nr) {
            return Err(SyscallRefusal::UnsupportedSyscallSemantics {
                nr: site.syscall_nr,
            });
        }
        let page_size = qualify_host()?;
        let sled_layout = ZpolineSledLayout::new(page_size, site.config.max_syscall_nr())?;

        let source_range =
            AddressRange::new(site.base_address, site.code.len()).map_err(core_refusal)?;
        if site.entries.identity != site.identity || !site.entries.scope.covers(source_range) {
            return Err(SyscallRefusal::DependencyNotHeld);
        }
        if site.entries.completeness == EntryCompleteness::Incomplete
            || matches!(site.entries.resumes, ResumeObligation::Unresolved)
        {
            return Err(SyscallRefusal::DependencyNotHeld);
        }
        let return_pc = site
            .logical_pc
            .checked_add(2)
            .ok_or(SyscallRefusal::InvalidConfig {
                field: "logical_pc",
                reason: "return address overflows",
            })?;
        if site.entries.entries.iter().any(|entry| {
            entry.address == site.logical_pc + 1
                || entry.requires_endbr && entry.address == site.logical_pc
        }) {
            return Err(SyscallRefusal::InteriorBranchTarget);
        }
        if let ResumeObligation::Enumerated(addresses) = &site.entries.resumes
            && addresses.contains(&(site.logical_pc + 1))
        {
            return Err(SyscallRefusal::InteriorBranchTarget);
        }
        if site.entries.completeness == EntryCompleteness::Complete
            && !site
                .entries
                .entries
                .iter()
                .any(|entry| entry.address == site.logical_pc)
        {
            return Err(SyscallRefusal::NotInstructionHead);
        }

        let offset = site
            .logical_pc
            .checked_sub(site.base_address)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(SyscallRefusal::InvalidConfig {
                field: "logical_pc",
                reason: "site is outside the snapshot",
            })?;
        let site_bytes = site
            .code
            .get(offset..offset + 2)
            .ok_or(SyscallRefusal::NotSyscallSite)?;
        if site_bytes != ORIGINAL_SYSCALL {
            let decoded = liteinst::x86::decode64(
                site.logical_pc,
                site.code.get(offset..).unwrap_or_default(),
            );
            return Err(match liteinst::x86::selected_code(&decoded.instruction) {
                Some(
                    liteinst::x86::SelectedClass::Sysenter | liteinst::x86::SelectedClass::Int80,
                ) => SyscallRefusal::UnsupportedSyscallEntry,
                _ => SyscallRefusal::NotSyscallSite,
            });
        }
        let instruction = decode_selected(
            SelectedKind::Syscall,
            site.logical_pc,
            site.code
                .get(offset..)
                .ok_or(SyscallRefusal::InvalidConfig {
                    field: "logical_pc",
                    reason: "site is outside the snapshot",
                })?,
        )
        .map_err(core_refusal)?;
        let delegate = syscall_callback(&instruction).map_err(core_refusal)?;

        let scan = InstructionScanner::default()
            .scan(site.code, site.base_address)
            .map_err(scan_refusal)?;
        if scan.site(site.logical_pc).is_none() {
            return Err(SyscallRefusal::NotInstructionHead);
        }
        if scan.instructions().iter().any(|scanned| {
            let instruction = scanned.instruction();
            instruction.op0_kind() == OpKind::NearBranch64
                && instruction.near_branch_target() == site.logical_pc + 1
        }) {
            return Err(SyscallRefusal::InteriorBranchTarget);
        }

        let plan =
            TrampolinePlan::from_scan_replacing_exact_syscall(&scan, site.logical_pc, zpoline_hook)
                .map_err(trampoline_refusal)?;
        let source = site.code.to_vec();
        let mut expected_source = source.clone();
        expected_source[offset..offset + 2].copy_from_slice(&ZPOLINE_CALL_RAX);

        Ok(Self {
            config: site.config,
            instruction,
            identity: site.identity,
            base_address: site.base_address,
            logical_pc: site.logical_pc,
            return_pc,
            syscall_nr: site.syscall_nr,
            source,
            expected_source,
            plan,
            delegate,
            sled_layout,
        })
    }

    /// Frozen strategy config used by this plan.
    pub const fn config(&self) -> SyscallStrategyConfig {
        self.config
    }

    /// Exact decoded selected syscall instruction.
    pub const fn instruction(&self) -> &SelectedInstruction {
        &self.instruction
    }

    /// Exact handler trampoline plan; this is not installed yet.
    pub fn plan(&self) -> &TrampolinePlan {
        &self.plan
    }

    /// Exact sled geometry derived from the config and host page size.
    pub const fn sled_layout(&self) -> ZpolineSledLayout {
        self.sled_layout
    }

    /// Builds the complete sled image for an allocated handler address.
    pub fn sled_image(&self, handler: u64) -> Vec<u8> {
        self.sled_layout.build(handler)
    }

    fn source_range(&self) -> Result<AddressRange, SyscallRefusal> {
        AddressRange::new(self.base_address, self.source.len()).map_err(core_refusal)
    }

    fn offset(&self) -> usize {
        usize::try_from(self.logical_pc - self.base_address)
            .expect("prepared zpoline offset was checked during preparation")
    }
}

fn sync_refusal(error: SyncCoreError) -> SyscallRefusal {
    match error {
        SyncCoreError::MissingCapability { .. } | SyncCoreError::UnsupportedPlatform => {
            SyscallRefusal::SyncCoreUnavailable
        }
        SyncCoreError::SystemCall { .. }
        | SyncCoreError::UnexpectedResult { .. }
        | SyncCoreError::DifferentProcess { .. } => SyscallRefusal::SynchronizationFailed,
    }
}

unsafe fn read_live(source: *const u8, out: &mut [u8]) {
    // SAFETY: callers hold the lease and guarantee source aliases out.len()
    // readable bytes for this copy.
    unsafe { std::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len()) }
}

unsafe fn write_site_word(address: *mut u8, bytes: [u8; 2]) {
    let value = u16::from_le_bytes(bytes);
    // SAFETY: callers hold the publication lease, provide a writable alias
    // for both bytes, and synchronize instruction fetch before admission.
    unsafe {
        core::arch::asm!(
            "mov word ptr [{address}], {value:x}",
            address = in(reg) address,
            value = in(reg) value,
            options(nostack)
        );
    }
}

fn clear_hook_state() {
    ZPOLINE_HOOK_SITES.store(std::ptr::null_mut(), Ordering::Release);
    ZPOLINE_HOOK_SITES_LEN.store(0, Ordering::Release);
}

/// Exact zpoline publication failure, retaining the strategy-level name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZpolineFailure {
    /// Named strategy refusal.
    pub reason: SyscallRefusal,
    /// Whether the failure happened before any source write or whether the
    /// lease must remain gated after one was attempted.
    pub stage: FailureStage,
}

/// Publication or retirement failure retaining all genuine owners.
pub struct ZpolinePublicationFailure {
    /// Exact named failure and stage.
    pub failure: ZpolineFailure,
    /// Prepared plan, handler/sled owners, and observations, including failed
    /// prefixes. Dropping an uncommitted sled owner unmaps its low page.
    pub retained: Box<InstalledZpoline>,
}

impl std::fmt::Debug for ZpolinePublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZpolinePublicationFailure")
            .field("failure", &self.failure)
            .field("logical_pc", &self.retained.prepared.logical_pc)
            .field("verified", &self.retained.verified())
            .finish()
    }
}

impl std::fmt::Display for ZpolinePublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "zpoline publication {:?}: {}",
            self.failure.stage, self.failure.reason
        )
    }
}

impl std::error::Error for ZpolinePublicationFailure {}

/// Process-lifetime owner for one installed zpoline site and its sled.
///
/// Retain this owner until `retire` succeeds under a fresh lease. Dropping a
/// verified owner intentionally does not unmap reachable handler or sled code.
pub struct InstalledZpoline {
    prepared: PreparedZpoline,
    hook_sites: Box<[HookSite]>,
    trampoline: Option<ExecutableTrampoline>,
    sled: Option<DualMapping>,
    observed_source: Vec<u8>,
    observed_handler: Vec<u8>,
    observed_sled: Vec<u8>,
    captured: bool,
    verified: bool,
    write_attempted: bool,
}

impl InstalledZpoline {
    /// Prepared plan retained with the genuine owners.
    pub const fn prepared(&self) -> &PreparedZpoline {
        &self.prepared
    }

    /// Allocated handler trampoline address, when allocation was reached.
    pub fn handler_address(&self) -> Option<u64> {
        self.trampoline
            .as_ref()
            .map(|trampoline| trampoline.address())
    }

    /// Whether source, handler, and sled observations all matched.
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Actual complete source bytes after the latest captured state.
    pub fn observed_source(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_source.as_slice())
    }

    /// Actual handler bytes read from the executable mapping.
    pub fn observed_handler(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_handler.as_slice())
    }

    /// Actual sled bytes read back with `pread` on the sealed memfd.
    pub fn observed_sled(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_sled.as_slice())
    }
}

impl PreparedZpoline {
    /// Allocates the low sled and exact handler, publishes `ff d0`, and
    /// verifies all three actual images before returning their owner.
    ///
    /// # Safety
    /// `writable_base` aliases the entire prepared snapshot and remains valid
    /// for the installed lifetime. The lease must represent actual exclusion
    /// of execution, mutation, aliases, threads/signals that can observe the
    /// temporary sled/handler state, and saved continuations. `finalize`
    /// establishes final readable/RX permissions without admitting execution,
    /// changing bytes/identity, panicking, or unwinding.
    ///
    /// The certified site must execute with a writable System V stack below
    /// its red zone satisfying the core exact trampoline, no active CET, no
    /// application signal delivery in generated code, no recursion or
    /// nonlocal exit through the callback, and no syscall buffers overlapping
    /// source/runtime/saved-state storage. Only one zpoline site may be
    /// installed process-wide in this slice.
    pub unsafe fn publish_with(
        self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<Box<InstalledZpoline>, ZpolinePublicationFailure> {
        let source_len = self.source.len();
        let page_size = self.sled_layout.page_size();
        let hook_sites = vec![HookSite {
            logical_pc: self.logical_pc,
            return_pc: self.return_pc,
            syscall_nr: self.syscall_nr,
            delegate: self.delegate,
        }]
        .into_boxed_slice();
        let mut retained = Box::new(InstalledZpoline {
            prepared: self,
            hook_sites,
            trampoline: None,
            sled: None,
            observed_source: vec![0; source_len],
            observed_handler: Vec::new(),
            observed_sled: vec![0; page_size],
            captured: false,
            verified: false,
            write_attempted: false,
        });
        if let Err(reason) = claim_owner() {
            return Err(ZpolinePublicationFailure {
                failure: ZpolineFailure {
                    reason,
                    stage: FailureStage::BeforeWrite,
                },
                retained,
            });
        }
        // SAFETY: the caller supplies the complete alias, lease, finalizer,
        // stack, signal, CET, and process-lifetime contract above.
        let result = unsafe { publish_inner(&mut retained, writable_base, lease, finalize) };
        match result {
            Ok(()) => {
                ZPOLINE_OWNER.store(OWNER_INSTALLED, Ordering::Release);
                Ok(retained)
            }
            Err(failure) => {
                if failure.stage == FailureStage::KeepGated || retained.write_attempted {
                    ZPOLINE_OWNER.store(OWNER_POISONED, Ordering::Release);
                } else {
                    clear_hook_state();
                    release_owner();
                }
                Err(ZpolinePublicationFailure { failure, retained })
            }
        }
    }
}

unsafe fn publish_inner(
    retained: &mut InstalledZpoline,
    writable_base: *mut u8,
    lease: &mut QuiescenceLease<'_>,
    mut finalize: impl FnMut() -> Result<(), SyscallRefusal>,
) -> Result<(), ZpolineFailure> {
    let before = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    };
    let keep = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::KeepGated,
    };
    qualify_host().map_err(before)?;
    let sync = SyncCore::prepare().map_err(|error| before(sync_refusal(error)))?;
    let prepared = &retained.prepared;
    let source_range = prepared.source_range().map_err(before)?;
    if writable_base.is_null() {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "must not be null",
        }));
    }
    if writable_base as usize % 64 != prepared.base_address as usize % 64 {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "cache-line offset differs from executable alias",
        }));
    }
    if lease.is_poisoned() || lease.identity() != prepared.identity || !lease.covers(source_range) {
        return Err(before(SyscallRefusal::DependencyNotHeld));
    }
    let placement = prepared.config.placement();
    let handler_upper = prepared.sled_layout.page_size().max(16_384);
    if placement.max_mappings() < 2
        || prepared
            .sled_layout
            .page_size()
            .checked_add(handler_upper)
            .is_none_or(|needed| needed > placement.max_mapped_bytes())
    {
        return Err(before(SyscallRefusal::AllocationUnavailable));
    }
    // SAFETY: lease and alias validity are the caller's contract.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    retained.captured = true;
    if retained.observed_source != retained.prepared.source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    let sled = DualMapping::probe_sled(prepared.sled_layout.page_size()).map_err(before)?;
    retained.sled = Some(sled);
    let trampoline = ExecutableTrampoline::allocate(&retained.prepared.plan)
        .map_err(|error| before(trampoline_refusal(error)))?;
    let handler_address = trampoline.address();
    let handler_allocation = trampoline.allocation_len();
    retained.trampoline = Some(trampoline);
    if retained
        .prepared
        .sled_layout
        .page_size()
        .checked_add(handler_allocation)
        .is_none_or(|needed| needed > placement.max_mapped_bytes())
    {
        return Err(before(SyscallRefusal::AllocationUnavailable));
    }
    let handler_image = retained
        .prepared
        .plan
        .emit_at(handler_address)
        .map_err(|error| before(trampoline_refusal(error)))?;
    retained.observed_handler = vec![0; retained.trampoline.as_ref().unwrap().code_len()];
    // SAFETY: the retained trampoline mapping is readable for code_len bytes.
    unsafe { read_live(handler_address as *const u8, &mut retained.observed_handler) };
    if retained.observed_handler != handler_image.bytes() {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    let sled_bytes = retained.prepared.sled_image(handler_address);
    retained.observed_sled = retained
        .sled
        .as_mut()
        .expect("sled was just retained")
        .publish_bytes(&sled_bytes)
        .map_err(before)?;

    publish_hook_sites(&retained.hook_sites);

    // SAFETY: the lease still excludes every observer of the live alias.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    retained.write_attempted = true;
    // SAFETY: writable alias covers both site bytes and fetch is excluded.
    unsafe {
        write_site_word(
            writable_base.add(retained.prepared.offset()),
            ZPOLINE_CALL_RAX,
        )
    };
    // From this point the source may route to the sled even if a later check
    // fails, so a retained failure must not drop/unmap it.
    if let Some(sled) = retained.sled.take() {
        retained.sled = Some(sled.commit());
    }
    if let Err(error) = sync.synchronize() {
        lease.poison();
        return Err(keep(sync_refusal(error)));
    }
    if let Err(reason) = finalize() {
        lease.poison();
        return Err(keep(reason));
    }
    // SAFETY: the lease remains held through final observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.expected_source {
        lease.poison();
        return Err(keep(SyscallRefusal::ExpectedBytesChanged));
    }

    let sled = retained
        .sled
        .take()
        .expect("sled was retained through publication")
        .commit();
    retained.sled = Some(sled);
    retained
        .trampoline
        .as_ref()
        .expect("handler was retained through publication")
        .publish_program_counter_mappings();
    retained.verified = true;
    retained.write_attempted = false;
    Ok(())
}

impl InstalledZpoline {
    /// Restores the original `syscall` bytes, synchronizes, verifies them,
    /// and unmaps the sled under a fresh lease.
    ///
    /// The handler mapping itself follows the core trampoline process-lifetime
    /// rule and is left unreachable after the source is restored.
    ///
    /// # Safety
    /// The same alias, exclusion, finalizer, stack, signal, CET, and
    /// saved-continuation obligations as publication apply until retirement
    /// returns. No thread may execute or resume through the site during it.
    pub unsafe fn retire(
        mut self: Box<Self>,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<(), ZpolinePublicationFailure> {
        // SAFETY: the caller supplies the same complete contract as publish.
        let result = unsafe { retire_inner(&mut self, writable_base, lease, finalize) };
        match result {
            Ok(()) => {
                clear_hook_state();
                ZPOLINE_OWNER.store(OWNER_EMPTY, Ordering::Release);
                Ok(())
            }
            Err(failure) => {
                if failure.stage == FailureStage::KeepGated || self.write_attempted {
                    ZPOLINE_OWNER.store(OWNER_POISONED, Ordering::Release);
                }
                Err(ZpolinePublicationFailure {
                    failure,
                    retained: self,
                })
            }
        }
    }
}

unsafe fn retire_inner(
    retained: &mut InstalledZpoline,
    writable_base: *mut u8,
    lease: &mut QuiescenceLease<'_>,
    mut finalize: impl FnMut() -> Result<(), SyscallRefusal>,
) -> Result<(), ZpolineFailure> {
    let before = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    };
    let keep = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::KeepGated,
    };
    if !retained.verified {
        return Err(before(SyscallRefusal::StrategyUnavailableOnBackend));
    }
    qualify_host().map_err(before)?;
    let sync = SyncCore::prepare().map_err(|error| before(sync_refusal(error)))?;
    let source_range = retained.prepared.source_range().map_err(before)?;
    if writable_base.is_null() {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "must not be null",
        }));
    }
    if writable_base as usize % 64 != retained.prepared.base_address as usize % 64 {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "cache-line offset differs from executable alias",
        }));
    }
    if lease.is_poisoned()
        || lease.identity() != retained.prepared.identity
        || !lease.covers(source_range)
    {
        return Err(before(SyscallRefusal::DependencyNotHeld));
    }
    // SAFETY: the lease and alias remain valid through observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    retained.captured = true;
    if retained.observed_source != retained.prepared.expected_source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    retained.write_attempted = true;
    // SAFETY: the alias covers both bytes and fetch is excluded by lease.
    unsafe {
        write_site_word(
            writable_base.add(retained.prepared.offset()),
            ORIGINAL_SYSCALL,
        )
    };
    if let Err(error) = sync.synchronize() {
        lease.poison();
        return Err(keep(sync_refusal(error)));
    }
    if let Err(reason) = finalize() {
        lease.poison();
        return Err(keep(reason));
    }
    // SAFETY: the lease remains held through restored-byte observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.source {
        lease.poison();
        return Err(keep(SyscallRefusal::ExpectedBytesChanged));
    }
    if let Some(sled) = retained.sled.as_mut()
        && let Err(reason) = sled.unmap()
    {
        lease.poison();
        return Err(keep(reason));
    }
    retained.captured = true;
    retained.verified = false;
    retained.write_attempted = false;
    Ok(())
}

/// Counts of placement families actually used by an installed batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlacementCounts {
    /// Near handler/dispatcher allocations.
    pub near_allocation: usize,
    /// Memfd dual-mapped backings retained for the sled, dispatcher, and
    /// each per-site handler trampoline.
    pub memfd_dual_map: usize,
    /// Low-page sled mappings (zero or one in this slice).
    pub low_page: usize,
    /// Sled-to-dispatcher-to-handler veneers.
    pub two_hop_veneer: usize,
    /// Sites left to the trap outcome.
    pub trap: usize,
}

/// Outcome and placement summary for a prepared or installed batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZpolineMetrics {
    /// Sites currently rewritten by zpoline.
    pub rewritten_zpoline: usize,
    /// Sites currently rewritten by lazypoline (always zero in slice 3).
    pub rewritten_lazypoline: usize,
    /// Sites left to a trap substrate.
    pub trap: usize,
    /// Sites refused by exact name.
    pub refused: usize,
    /// Installed rewritten sites whose generation has been marked stale.
    pub stale_sites: usize,
    /// Placement families used by the installed batch.
    pub placement: PlacementCounts,
}

fn metrics_for(
    outcomes: &[(u64, crate::syscall::SiteOutcome)],
    stale: bool,
    placement: PlacementCounts,
) -> ZpolineMetrics {
    let mut metrics = ZpolineMetrics {
        placement,
        ..ZpolineMetrics::default()
    };
    for (_, outcome) in outcomes {
        match outcome {
            crate::syscall::SiteOutcome::RewrittenZpoline => metrics.rewritten_zpoline += 1,
            crate::syscall::SiteOutcome::RewrittenLazypoline => metrics.rewritten_lazypoline += 1,
            crate::syscall::SiteOutcome::Trap => metrics.trap += 1,
            crate::syscall::SiteOutcome::Refused(_) => metrics.refused += 1,
        }
    }
    if stale {
        metrics.stale_sites = metrics.rewritten_zpoline + metrics.rewritten_lazypoline;
    }
    metrics
}

/// Prepared multi-site batch for one snapshot and one code identity.
pub struct PreparedZpolineSet {
    config: SyscallStrategyConfig,
    identity: CodeIdentity,
    base_address: u64,
    source: Vec<u8>,
    expected_source: Vec<u8>,
    sled_layout: ZpolineSledLayout,
    sites: Vec<PreparedZpoline>,
    outcomes: Vec<(u64, crate::syscall::SiteOutcome)>,
}

impl PreparedZpolineSet {
    fn from_prepared(
        config: SyscallStrategyConfig,
        identity: CodeIdentity,
        base_address: u64,
        source: Vec<u8>,
        sled_layout: ZpolineSledLayout,
        mut sites: Vec<PreparedZpoline>,
        mut outcomes: Vec<(u64, crate::syscall::SiteOutcome)>,
    ) -> Result<Self, SyscallRefusal> {
        sites.sort_by_key(|site| site.logical_pc);
        if sites.len() > config.max_sites() {
            return Err(SyscallRefusal::RegistryExhausted);
        }
        let mut expected_source = source.clone();
        for site in &sites {
            if site.config != config
                || site.identity != identity
                || site.base_address != base_address
                || site.source != source
            {
                return Err(SyscallRefusal::DependencyNotHeld);
            }
            expected_source[site.offset()..site.offset() + 2].copy_from_slice(&ZPOLINE_CALL_RAX);
        }
        outcomes.sort_by_key(|(address, _)| *address);
        Ok(Self {
            config,
            identity,
            base_address,
            source,
            expected_source,
            sled_layout,
            sites,
            outcomes,
        })
    }

    /// Prepares an explicitly certified batch in one snapshot/identity.
    /// Every named site must be eligible; use `census` for mixed outcomes.
    pub fn prepare_batch(mut sites: Vec<ZpolineSite<'_>>) -> Result<Self, SyscallRefusal> {
        let first = sites.first().ok_or(SyscallRefusal::InvalidConfig {
            field: "sites",
            reason: "batch requires at least one site",
        })?;
        let config = first.config;
        let identity = first.identity;
        let base_address = first.base_address;
        let source = first.code.to_vec();
        sites.sort_by_key(|site| site.logical_pc);
        if sites
            .windows(2)
            .any(|pair| pair[0].logical_pc == pair[1].logical_pc)
        {
            return Err(SyscallRefusal::OwnershipConflict);
        }
        let mut prepared = Vec::with_capacity(sites.len());
        let mut outcomes = Vec::with_capacity(sites.len());
        for site in sites {
            if site.config != config
                || site.identity != identity
                || site.base_address != base_address
                || site.code != source.as_slice()
            {
                return Err(SyscallRefusal::DependencyNotHeld);
            }
            outcomes.push((site.logical_pc, crate::syscall::SiteOutcome::Trap));
            prepared.push(PreparedZpoline::prepare(site)?);
        }
        let sled_layout = prepared[0].sled_layout;
        Self::from_prepared(
            config,
            identity,
            base_address,
            source,
            sled_layout,
            prepared,
            outcomes,
        )
    }

    /// Scans one snapshot, prepares every certified eligible native syscall,
    /// and records a trap/refused outcome for every other syscall-class site.
    pub fn census(
        config: SyscallStrategyConfig,
        identity: CodeIdentity,
        code: &[u8],
        base_address: u64,
        entries: &LegalEntrySet,
        certificates: &BTreeMap<u64, u32>,
    ) -> Result<Self, SyscallRefusal> {
        config.validate()?;
        if config.strategy() != SyscallStrategy::Zpoline {
            return Err(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "zpoline census requires the zpoline strategy",
            });
        }
        let page_size = qualify_host()?;
        let sled_layout = ZpolineSledLayout::new(page_size, config.max_syscall_nr())?;
        let scan = InstructionScanner::default()
            .scan(code, base_address)
            .map_err(scan_refusal)?;
        let mut prepared = Vec::new();
        let mut outcomes = Vec::new();
        let fallback = |reason: SyscallRefusal| {
            if config.fallback() == crate::syscall::FallbackPolicy::Trap {
                crate::syscall::SiteOutcome::Trap
            } else {
                crate::syscall::SiteOutcome::Refused(reason)
            }
        };
        for scanned in scan.instructions() {
            let instruction = scanned.instruction();
            let Some(class) = liteinst::x86::selected_code(instruction) else {
                continue;
            };
            if !matches!(
                class,
                liteinst::x86::SelectedClass::Syscall
                    | liteinst::x86::SelectedClass::Sysenter
                    | liteinst::x86::SelectedClass::Int80
            ) {
                continue;
            }
            let address = instruction.ip();
            if outcomes.len() >= config.max_sites() {
                return Err(SyscallRefusal::RegistryExhausted);
            }
            if class != liteinst::x86::SelectedClass::Syscall {
                outcomes.push((address, fallback(SyscallRefusal::UnsupportedSyscallEntry)));
                continue;
            }
            let Some(&syscall_nr) = certificates.get(&address) else {
                outcomes.push((
                    address,
                    fallback(SyscallRefusal::SyscallNumberRangeUnproven),
                ));
                continue;
            };
            if syscall_nr > config.max_syscall_nr() {
                outcomes.push((
                    address,
                    fallback(SyscallRefusal::SyscallNumberRangeUnproven),
                ));
                continue;
            }
            if !first_profile_supports(syscall_nr) {
                outcomes.push((
                    address,
                    fallback(SyscallRefusal::UnsupportedSyscallSemantics { nr: syscall_nr }),
                ));
                continue;
            }
            match PreparedZpoline::prepare(ZpolineSite {
                config,
                identity,
                code,
                base_address,
                logical_pc: address,
                entries,
                syscall_nr,
            }) {
                Ok(site) => {
                    outcomes.push((address, crate::syscall::SiteOutcome::Trap));
                    prepared.push(site);
                }
                Err(
                    reason @ (SyscallRefusal::DependencyNotHeld
                    | SyscallRefusal::CetUnsupported
                    | SyscallRefusal::StrategyUnavailableOnArch),
                ) => {
                    return Err(reason);
                }
                Err(reason) => outcomes.push((address, fallback(reason))),
            }
        }
        Self::from_prepared(
            config,
            identity,
            base_address,
            code.to_vec(),
            sled_layout,
            prepared,
            outcomes,
        )
    }

    /// Frozen batch config.
    pub const fn config(&self) -> SyscallStrategyConfig {
        self.config
    }

    /// Prepared eligible sites in logical-PC order.
    pub fn sites(&self) -> &[PreparedZpoline] {
        &self.sites
    }

    /// Census outcomes; eligible sites remain `Trap` until installed.
    pub fn outcomes(&self) -> &[(u64, crate::syscall::SiteOutcome)] {
        &self.outcomes
    }

    /// Outcome summary before installation.
    pub fn metrics(&self) -> ZpolineMetrics {
        metrics_for(&self.outcomes, false, PlacementCounts::default())
    }
}

struct InstalledSiteState {
    trampoline: Option<ExecutableTrampoline>,
    observed_handler: Vec<u8>,
}

/// Process-lifetime owner for one installed multi-site zpoline batch.
pub struct InstalledZpolineSet {
    prepared: PreparedZpolineSet,
    hook_sites: Box<[HookSite]>,
    sled: Option<DualMapping>,
    dispatcher: Option<DualMapping>,
    dispatcher_address: u64,
    dispatcher_family: crate::syscall::PlacementFamily,
    dispatcher_attempts: usize,
    sites: Vec<InstalledSiteState>,
    observed_source: Vec<u8>,
    observed_sled: Vec<u8>,
    observed_dispatcher: Vec<u8>,
    outcomes: Vec<(u64, crate::syscall::SiteOutcome)>,
    placement: PlacementCounts,
    stale: bool,
    captured: bool,
    verified: bool,
    write_attempted: bool,
}

/// Batch publication/retirement failure retaining all genuine owners.
pub struct ZpolineSetPublicationFailure {
    /// Exact named failure and stage.
    pub failure: ZpolineFailure,
    /// Retained batch owners and observations.
    pub retained: Box<InstalledZpolineSet>,
}

impl std::fmt::Debug for ZpolineSetPublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZpolineSetPublicationFailure")
            .field("failure", &self.failure)
            .field("sites", &self.retained.prepared.sites.len())
            .field("verified", &self.retained.verified)
            .finish()
    }
}

impl std::fmt::Display for ZpolineSetPublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "zpoline batch publication {:?}: {}",
            self.failure.stage, self.failure.reason
        )
    }
}

impl std::error::Error for ZpolineSetPublicationFailure {}

impl InstalledZpolineSet {
    /// Prepared batch retained with the genuine owners.
    pub const fn prepared(&self) -> &PreparedZpolineSet {
        &self.prepared
    }

    /// Dispatcher veneer address, when allocation was reached.
    pub const fn dispatcher_address(&self) -> u64 {
        self.dispatcher_address
    }

    /// Placement family used for the dispatcher island.
    pub const fn dispatcher_family(&self) -> crate::syscall::PlacementFamily {
        self.dispatcher_family
    }

    /// Exact dispatcher candidate attempts, including the anywhere attempt.
    pub const fn dispatcher_attempts(&self) -> usize {
        self.dispatcher_attempts
    }

    /// Current outcomes for every census candidate.
    pub fn outcomes(&self) -> &[(u64, crate::syscall::SiteOutcome)] {
        &self.outcomes
    }

    /// Outcome and placement summary.
    pub fn metrics(&self) -> ZpolineMetrics {
        let mut placement = self.placement;
        placement.trap = self
            .outcomes
            .iter()
            .filter(|(_, outcome)| *outcome == crate::syscall::SiteOutcome::Trap)
            .count();
        metrics_for(&self.outcomes, self.stale, placement)
    }

    /// Whether source, handler, sled, and dispatcher observations matched.
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Whether this installed batch has been marked generation-stale.
    pub const fn is_stale(&self) -> bool {
        self.stale
    }

    /// Marks the batch stale when the caller observes a different current
    /// code identity. Installed bytes are not changed; retire under a fresh
    /// lease before admitting the new generation.
    pub fn mark_stale_if(&mut self, current_identity: CodeIdentity) -> bool {
        if current_identity != self.prepared.identity {
            self.stale = true;
        }
        self.stale
    }

    /// Actual complete source bytes after the latest captured state.
    pub fn observed_source(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_source.as_slice())
    }

    /// Actual sled bytes read back with `pread`.
    pub fn observed_sled(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_sled.as_slice())
    }

    /// Actual dispatcher bytes read back with `pread`.
    pub fn observed_dispatcher(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_dispatcher.as_slice())
    }

    /// Actual handler bytes for an eligible logical PC.
    pub fn observed_handler(&self, logical_pc: u64) -> Option<&[u8]> {
        if !self.captured {
            return None;
        }
        self.prepared
            .sites
            .iter()
            .position(|site| site.logical_pc == logical_pc)
            .map(|index| self.sites[index].observed_handler.as_slice())
    }
}

impl PreparedZpolineSet {
    /// Allocates handlers, dispatcher, and sled; publishes every eligible
    /// site in this one snapshot; and verifies all actual images.
    ///
    /// # Safety
    /// The same alias, lease, finalizer, stack, signal, CET, recursion, and
    /// lifetime obligations as the one-site publisher apply to every site in
    /// the batch. All sites share the set's one identity and snapshot. Only
    /// one zpoline owner may be installed process-wide.
    pub unsafe fn publish_with(
        self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<Box<InstalledZpolineSet>, ZpolineSetPublicationFailure> {
        let hook_sites: Vec<HookSite> = self
            .sites
            .iter()
            .map(|site| HookSite {
                logical_pc: site.logical_pc,
                return_pc: site.return_pc,
                syscall_nr: site.syscall_nr,
                delegate: site.delegate,
            })
            .collect();
        let outcomes = self.outcomes.clone();
        let source_len = self.source.len();
        let site_count = self.sites.len();
        let mut retained = Box::new(InstalledZpolineSet {
            prepared: self,
            hook_sites: hook_sites.into_boxed_slice(),
            sled: None,
            dispatcher: None,
            dispatcher_address: 0,
            dispatcher_family: crate::syscall::PlacementFamily::Trap,
            dispatcher_attempts: 0,
            sites: (0..site_count)
                .map(|_| InstalledSiteState {
                    trampoline: None,
                    observed_handler: Vec::new(),
                })
                .collect(),
            observed_source: vec![0; source_len],
            observed_sled: Vec::new(),
            observed_dispatcher: Vec::new(),
            outcomes,
            placement: PlacementCounts::default(),
            stale: false,
            captured: false,
            verified: false,
            write_attempted: false,
        });
        if retained.prepared.sites.is_empty() {
            return Err(ZpolineSetPublicationFailure {
                failure: ZpolineFailure {
                    reason: SyscallRefusal::InvalidConfig {
                        field: "sites",
                        reason: "batch requires at least one eligible site",
                    },
                    stage: FailureStage::BeforeWrite,
                },
                retained,
            });
        }
        if let Err(reason) = claim_owner() {
            return Err(ZpolineSetPublicationFailure {
                failure: ZpolineFailure {
                    reason,
                    stage: FailureStage::BeforeWrite,
                },
                retained,
            });
        }
        // SAFETY: the caller supplies the complete contract above.
        let result = unsafe { publish_set_inner(&mut retained, writable_base, lease, finalize) };
        match result {
            Ok(()) => {
                ZPOLINE_OWNER.store(OWNER_INSTALLED, Ordering::Release);
                Ok(retained)
            }
            Err(failure) => {
                if failure.stage == FailureStage::KeepGated || retained.write_attempted {
                    ZPOLINE_OWNER.store(OWNER_POISONED, Ordering::Release);
                } else {
                    clear_hook_state();
                    release_owner();
                }
                Err(ZpolineSetPublicationFailure { failure, retained })
            }
        }
    }
}

unsafe fn publish_set_inner(
    retained: &mut InstalledZpolineSet,
    writable_base: *mut u8,
    lease: &mut QuiescenceLease<'_>,
    mut finalize: impl FnMut() -> Result<(), SyscallRefusal>,
) -> Result<(), ZpolineFailure> {
    let before = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    };
    let keep = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::KeepGated,
    };
    let page_size = qualify_host().map_err(before)?;
    if page_size != retained.prepared.sled_layout.page_size() {
        return Err(before(SyscallRefusal::AllocationUnavailable));
    }
    let sync = SyncCore::prepare().map_err(|error| before(sync_refusal(error)))?;
    let source_range = AddressRange::new(
        retained.prepared.base_address,
        retained.prepared.source.len(),
    )
    .map_err(|error| before(core_refusal(error)))?;
    if writable_base.is_null() {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "must not be null",
        }));
    }
    if writable_base as usize % 64 != retained.prepared.base_address as usize % 64 {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "cache-line offset differs from executable alias",
        }));
    }
    if lease.is_poisoned()
        || lease.identity() != retained.prepared.identity
        || !lease.covers(source_range)
    {
        return Err(before(SyscallRefusal::DependencyNotHeld));
    }
    let budget = retained.prepared.config.placement();
    let dispatcher_pairs: Vec<(u64, u64)> = retained
        .prepared
        .sites
        .iter()
        .map(|site| (site.return_pc, 0))
        .collect();
    let dispatcher_len = build_dispatcher(&dispatcher_pairs).map_err(before)?.len();
    let dispatcher_aligned = align_up(dispatcher_len as u64, page_size as u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(SyscallRefusal::AllocationUnavailable)
        .map_err(before)?;
    let handler_upper = page_size.max(16_384);
    let mapped_upper = page_size
        .checked_add(dispatcher_aligned)
        .and_then(|value| {
            value.checked_add(handler_upper.checked_mul(retained.prepared.sites.len())?)
        })
        .ok_or(SyscallRefusal::AllocationUnavailable)
        .map_err(before)?;
    if budget.max_mappings() < retained.prepared.sites.len() + 2
        || mapped_upper > budget.max_mapped_bytes()
    {
        return Err(before(SyscallRefusal::AllocationUnavailable));
    }
    // SAFETY: the lease and alias cover the complete snapshot.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    retained.captured = true;
    if retained.observed_source != retained.prepared.source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    // Probe VA0 first so a low-page refusal allocates no handlers/dispatcher.
    retained.sled = Some(DualMapping::probe_sled(page_size).map_err(before)?);

    let mut handler_addresses = Vec::with_capacity(retained.prepared.sites.len());
    for index in 0..retained.prepared.sites.len() {
        let trampoline = ExecutableTrampoline::allocate(&retained.prepared.sites[index].plan)
            .map_err(|error| before(trampoline_refusal(error)))?;
        handler_addresses.push(trampoline.address());
        retained.sites[index].trampoline = Some(trampoline);
    }
    let pairs: Vec<(u64, u64)> = retained
        .prepared
        .sites
        .iter()
        .map(|site| site.return_pc)
        .zip(handler_addresses.iter().copied())
        .collect();
    let mut dispatcher_bytes = build_dispatcher(&pairs).map_err(before)?;
    let allocation =
        allocate_dispatcher(dispatcher_bytes.len(), &[source_range], budget, page_size)
            .map_err(before)?;
    dispatcher_bytes.resize(allocation.mapping.len(), 0x90);
    retained.dispatcher_address = allocation.mapping.address;
    retained.dispatcher_family = allocation.family;
    retained.dispatcher_attempts = allocation.attempts;
    retained.dispatcher = Some(allocation.mapping);
    retained.observed_dispatcher = retained
        .dispatcher
        .as_mut()
        .expect("dispatcher was just retained")
        .publish_bytes(&dispatcher_bytes)
        .map_err(before)?;

    for ((prepared, state), handler_address) in retained
        .prepared
        .sites
        .iter()
        .zip(retained.sites.iter_mut())
        .zip(handler_addresses.iter().copied())
    {
        let image = prepared
            .plan
            .emit_at(handler_address)
            .map_err(|error| before(trampoline_refusal(error)))?;
        state.observed_handler = vec![0; state.trampoline.as_ref().unwrap().code_len()];
        // SAFETY: the retained handler mapping is readable for code_len bytes.
        unsafe { read_live(handler_address as *const u8, &mut state.observed_handler) };
        if state.observed_handler != image.bytes() {
            return Err(before(SyscallRefusal::ExpectedBytesChanged));
        }
    }

    let sled_bytes = retained
        .prepared
        .sled_layout
        .build(retained.dispatcher_address);
    retained.observed_sled = retained
        .sled
        .as_mut()
        .expect("sled was just retained")
        .publish_bytes(&sled_bytes)
        .map_err(before)?;
    publish_hook_sites(&retained.hook_sites);

    // SAFETY: the lease still excludes every observer of the live alias.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    retained.write_attempted = true;
    for site in &retained.prepared.sites {
        // SAFETY: the writable alias covers every site and fetch is excluded.
        unsafe { write_site_word(writable_base.add(site.offset()), ZPOLINE_CALL_RAX) };
    }
    if let Some(sled) = retained.sled.take() {
        retained.sled = Some(sled.commit());
    }
    if let Some(dispatcher) = retained.dispatcher.take() {
        retained.dispatcher = Some(dispatcher.commit());
    }
    if let Err(error) = sync.synchronize() {
        lease.poison();
        return Err(keep(sync_refusal(error)));
    }
    if let Err(reason) = finalize() {
        lease.poison();
        return Err(keep(reason));
    }
    // SAFETY: the lease remains held through aggregate final observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.expected_source {
        lease.poison();
        return Err(keep(SyscallRefusal::ExpectedBytesChanged));
    }
    for site in &retained.sites {
        site.trampoline
            .as_ref()
            .expect("handler was retained through publication")
            .publish_program_counter_mappings();
    }
    for outcome in &mut retained.outcomes {
        if retained
            .prepared
            .sites
            .iter()
            .any(|site| site.logical_pc == outcome.0)
        {
            outcome.1 = crate::syscall::SiteOutcome::RewrittenZpoline;
        }
    }
    retained.placement = PlacementCounts {
        near_allocation: retained.prepared.sites.len()
            + usize::from(
                retained.dispatcher_family == crate::syscall::PlacementFamily::NearAllocation,
            ),
        memfd_dual_map: retained.prepared.sites.len() + 2,
        low_page: 1,
        two_hop_veneer: 1,
        trap: retained
            .outcomes
            .iter()
            .filter(|(_, outcome)| *outcome == crate::syscall::SiteOutcome::Trap)
            .count(),
    };
    retained.verified = true;
    retained.write_attempted = false;
    Ok(())
}

impl InstalledZpolineSet {
    /// Restores every rewritten site, synchronizes, verifies the original
    /// aggregate snapshot, and unmaps sled plus dispatcher under a fresh lease.
    ///
    /// # Safety
    /// The same obligations as batch publication apply until retirement
    /// returns.
    pub unsafe fn retire(
        mut self: Box<Self>,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<(), ZpolineSetPublicationFailure> {
        // SAFETY: the caller supplies the same complete contract as publish.
        let result = unsafe { retire_set_inner(&mut self, writable_base, lease, finalize) };
        match result {
            Ok(()) => {
                clear_hook_state();
                ZPOLINE_OWNER.store(OWNER_EMPTY, Ordering::Release);
                Ok(())
            }
            Err(failure) => {
                if failure.stage == FailureStage::KeepGated || self.write_attempted {
                    ZPOLINE_OWNER.store(OWNER_POISONED, Ordering::Release);
                }
                Err(ZpolineSetPublicationFailure {
                    failure,
                    retained: self,
                })
            }
        }
    }
}

unsafe fn retire_set_inner(
    retained: &mut InstalledZpolineSet,
    writable_base: *mut u8,
    lease: &mut QuiescenceLease<'_>,
    mut finalize: impl FnMut() -> Result<(), SyscallRefusal>,
) -> Result<(), ZpolineFailure> {
    let before = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    };
    let keep = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::KeepGated,
    };
    if !retained.verified {
        return Err(before(SyscallRefusal::StrategyUnavailableOnBackend));
    }
    qualify_host().map_err(before)?;
    let sync = SyncCore::prepare().map_err(|error| before(sync_refusal(error)))?;
    let source_range = AddressRange::new(
        retained.prepared.base_address,
        retained.prepared.source.len(),
    )
    .map_err(|error| before(core_refusal(error)))?;
    if writable_base.is_null()
        || writable_base as usize % 64 != retained.prepared.base_address as usize % 64
    {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "must be non-null with the executable cache-line offset",
        }));
    }
    if lease.is_poisoned()
        || lease.identity() != retained.prepared.identity
        || !lease.covers(source_range)
    {
        return Err(before(SyscallRefusal::DependencyNotHeld));
    }
    // SAFETY: the lease and alias cover the complete snapshot.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    retained.captured = true;
    if retained.observed_source != retained.prepared.expected_source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }
    retained.write_attempted = true;
    for site in retained.prepared.sites.iter().rev() {
        // SAFETY: the alias covers every site and fetch is excluded.
        unsafe { write_site_word(writable_base.add(site.offset()), ORIGINAL_SYSCALL) };
    }
    if let Err(error) = sync.synchronize() {
        lease.poison();
        return Err(keep(sync_refusal(error)));
    }
    if let Err(reason) = finalize() {
        lease.poison();
        return Err(keep(reason));
    }
    // SAFETY: the lease remains held through restored-byte observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.source {
        lease.poison();
        return Err(keep(SyscallRefusal::ExpectedBytesChanged));
    }
    if let Some(sled) = retained.sled.as_mut()
        && let Err(reason) = sled.unmap()
    {
        lease.poison();
        return Err(keep(reason));
    }
    if let Some(dispatcher) = retained.dispatcher.as_mut()
        && let Err(reason) = dispatcher.unmap()
    {
        lease.poison();
        return Err(keep(reason));
    }
    for outcome in &mut retained.outcomes {
        if outcome.1 == crate::syscall::SiteOutcome::RewrittenZpoline {
            outcome.1 = crate::syscall::SiteOutcome::Trap;
        }
    }
    retained.verified = false;
    retained.write_attempted = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use liteinst::contracts::{EntryProvenance, LegalEntry, SourceIdentity};

    const BASE: u64 = 0x40_0000;

    fn identity() -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([7; 32]),
            mapping: 11,
            generation: 3,
        }
    }

    fn entries(code: &[u8], heads: &[u64]) -> LegalEntrySet {
        LegalEntrySet {
            identity: identity(),
            scope: AddressRange::new(BASE, code.len()).unwrap(),
            provenance: EntryProvenance::Declared("zpoline unit fixture".into()),
            completeness: EntryCompleteness::Complete,
            entries: heads
                .iter()
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        }
    }

    fn site<'a>(
        code: &'a [u8],
        entries: &'a LegalEntrySet,
        logical_pc: u64,
        syscall_nr: u32,
    ) -> ZpolineSite<'a> {
        ZpolineSite {
            config: SyscallStrategyConfig::new(SyscallStrategy::Zpoline),
            identity: identity(),
            code,
            base_address: BASE,
            logical_pc,
            entries,
            syscall_nr,
        }
    }

    #[test]
    fn sled_layout_and_bytes_are_exact() {
        let layout = ZpolineSledLayout::new(4096, 1023).unwrap();
        assert_eq!(layout.page_size(), 4096);
        assert_eq!(layout.max_syscall_nr(), 1023);
        assert_eq!(layout.common_entry(), 1024);
        let handler = 0x1122_3344_5566_7788;
        let sled = layout.build(handler);
        assert_eq!(sled.len(), 4096);
        assert!(
            sled[..layout.common_entry()]
                .iter()
                .all(|byte| *byte == 0x90)
        );
        for nr in 0..=layout.max_syscall_nr() {
            assert_eq!(sled[nr as usize], 0x90, "syscall {nr}");
        }
        let stub = &sled[layout.common_entry()..layout.common_entry() + COMMON_STUB_LEN];
        assert_eq!(&stub[0..5], &[0x48, 0x8d, 0x64, 0x24, 0x08]);
        assert_eq!(&stub[5..11], &[0xff, 0x25, 0, 0, 0, 0]);
        assert_eq!(&stub[11..19], &handler.to_le_bytes());
        let first = liteinst::x86::decode64(layout.common_entry() as u64, stub);
        assert_eq!(first.error, liteinst::x86::DecoderError::None);
        assert_eq!(first.instruction.mnemonic(), liteinst::x86::Mnemonic::Lea);
        assert_eq!(first.instruction.len(), 5);
        let second = liteinst::x86::decode64((layout.common_entry() + 5) as u64, &stub[5..]);
        assert_eq!(second.error, liteinst::x86::DecoderError::None);
        assert_eq!(second.instruction.mnemonic(), liteinst::x86::Mnemonic::Jmp);
        assert_eq!(second.instruction.len(), 6);
    }

    #[test]
    fn sled_seals_retain_write_seal_for_unmapped_backing() {
        assert_ne!(SLED_SEALS & libc::F_SEAL_WRITE, 0);
        assert_ne!(SLED_SEALS & libc::F_SEAL_FUTURE_WRITE, 0);
        assert_ne!(SLED_SEALS & libc::F_SEAL_SHRINK, 0);
        assert_ne!(SLED_SEALS & libc::F_SEAL_GROW, 0);
        assert_ne!(SLED_SEALS & libc::F_SEAL_SEAL, 0);
    }

    #[test]
    fn sled_layout_refuses_unrepresentable_geometry() {
        assert_eq!(
            ZpolineSledLayout::new(2048, 39),
            Err(SyscallRefusal::InvalidConfig {
                field: "page_size",
                reason: "must be a power of two and at least 4096",
            })
        );
        assert_eq!(
            ZpolineSledLayout::new(4096, 4079),
            Err(SyscallRefusal::InvalidConfig {
                field: "max_syscall_nr",
                reason: "sled common stub does not fit in one host page",
            })
        );
        assert!(ZpolineSledLayout::new(65_536, 4079).is_ok());
    }

    #[test]
    fn prepare_accepts_one_exact_first_profile_syscall() {
        let code = [0x0f, 0x05, 0xc3];
        let entries = entries(&code, &[BASE]);
        let prepared = PreparedZpoline::prepare(site(&code, &entries, BASE, 39)).unwrap();
        assert_eq!(prepared.config().strategy(), SyscallStrategy::Zpoline);
        assert_eq!(prepared.instruction().kind(), SelectedKind::Syscall);
        assert_eq!(prepared.sled_layout().max_syscall_nr(), 1023);
        assert_eq!(prepared.expected_source, [0xff, 0xd0, 0xc3]);
        assert_eq!(prepared.logical_pc, BASE);
    }

    #[test]
    fn prepare_refuses_wrong_strategy_profile_and_range() {
        let code = [0x0f, 0x05, 0xc3];
        let entries = entries(&code, &[BASE]);
        let mut wrong = site(&code, &entries, BASE, 39);
        wrong.config = SyscallStrategyConfig::new(SyscallStrategy::Trap);
        assert_eq!(
            PreparedZpoline::prepare(wrong).err(),
            Some(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "zpoline site requires the zpoline strategy",
            })
        );
        assert_eq!(
            PreparedZpoline::prepare(site(&code, &entries, BASE, 59)).err(),
            Some(SyscallRefusal::UnsupportedSyscallSemantics { nr: 59 })
        );
        assert_eq!(
            PreparedZpoline::prepare(site(&code, &entries, BASE, 2000)).err(),
            Some(SyscallRefusal::SyscallNumberRangeUnproven)
        );
    }

    #[test]
    fn prepare_refuses_other_entries_and_second_byte_targets() {
        let int80 = [0xcd, 0x80, 0xc3];
        let int_entries = entries(&int80, &[BASE]);
        assert_eq!(
            PreparedZpoline::prepare(site(&int80, &int_entries, BASE, 39)).err(),
            Some(SyscallRefusal::UnsupportedSyscallEntry)
        );

        let branch = [0xeb, 0x01, 0x0f, 0x05, 0xc3];
        let branch_entries = entries(&branch, &[BASE, BASE + 2]);
        assert_eq!(
            PreparedZpoline::prepare(site(&branch, &branch_entries, BASE + 2, 39)).err(),
            Some(SyscallRefusal::InteriorBranchTarget)
        );

        let shifted = [0x90, 0x0f, 0x05, 0xc3];
        let missing = entries(&shifted, &[BASE]);
        assert_eq!(
            PreparedZpoline::prepare(site(&shifted, &missing, BASE + 1, 39)).err(),
            Some(SyscallRefusal::NotInstructionHead)
        );
    }

    #[test]
    fn dispatcher_bytes_route_each_return_to_its_handler() {
        let sites = [(BASE + 2, 0x500000), (BASE + 0x1002, 0x600000)];
        let bytes = build_dispatcher(&sites).unwrap();
        assert_eq!(
            &bytes[0..8],
            &[0x48, 0x8d, 0xa4, 0x24, 0x70, 0xff, 0xff, 0xff]
        );
        assert_eq!(&bytes[8..11], &[0x9c, 0x41, 0x53]);
        let load_return = liteinst::x86::decode64(0x70000b, &bytes[11..]);
        assert_eq!(load_return.error, liteinst::x86::DecoderError::None);
        assert_eq!(
            load_return.instruction.mnemonic(),
            liteinst::x86::Mnemonic::Mov
        );
        assert_eq!(
            load_return.instruction.op0_register(),
            liteinst::x86::Register::R11
        );
        assert_eq!(
            load_return.instruction.memory_base(),
            liteinst::x86::Register::RSP
        );
        assert_eq!(load_return.instruction.memory_displacement64(), 152);
        let constants = (19 + 13 * sites.len() + 13 + 17 * sites.len()).next_multiple_of(8);
        for (index, &(return_pc, handler)) in sites.iter().enumerate() {
            let constant = constants + index * 8;
            assert_eq!(
                u64::from_le_bytes(bytes[constant..constant + 8].try_into().unwrap()),
                return_pc
            );
            let handler_constant = constants + sites.len() * 8 + index * 8;
            assert_eq!(
                u64::from_le_bytes(
                    bytes[handler_constant..handler_constant + 8]
                        .try_into()
                        .unwrap()
                ),
                handler
            );
            let compare = 19 + index * 13;
            let disp = i32::from_le_bytes(bytes[compare + 3..compare + 7].try_into().unwrap());
            assert_eq!((compare + 7) as i64 + i64::from(disp), constant as i64);
            let rel = i32::from_le_bytes(bytes[compare + 9..compare + 13].try_into().unwrap());
            let found = 19 + 13 * sites.len() + 13 + index * 17;
            assert_eq!((compare + 13) as i64 + i64::from(rel), found as i64);
            let jump_disp = i32::from_le_bytes(bytes[found + 13..found + 17].try_into().unwrap());
            assert_eq!(
                (found + 17) as i64 + i64::from(jump_disp),
                handler_constant as i64
            );
        }
    }

    #[test]
    fn dispatcher_allocation_publishes_and_unmaps() {
        let object = AddressRange::new(BASE, 4096).unwrap();
        let budget = crate::syscall::PlacementBudget::new(256, 4, 1_048_576).unwrap();
        let mut bytes = build_dispatcher(&[(BASE + 2, 0x500000)]).unwrap();
        let mut allocation = allocate_dispatcher(bytes.len(), &[object], budget, 4096).unwrap();
        assert!(allocation.mapping.address != 0);
        assert!(allocation.attempts >= 1);
        bytes.resize(allocation.mapping.len(), 0x90);
        let observed = allocation.mapping.publish_bytes(&bytes).unwrap();
        assert_eq!(observed, bytes);
        allocation.mapping.unmap().unwrap();
    }

    #[test]
    fn near_candidates_probe_around_objects_without_overlap() {
        let object = AddressRange::new(BASE, 4096).unwrap();
        let candidates = near_candidates(&[object], &[object], &[object], 4096, 4096, 4);
        assert_eq!(&candidates[..2], &[BASE + 4096, BASE - 4096]);
        assert!(candidates.iter().all(|candidate| {
            let range = AddressRange::new(*candidate, 4096).unwrap();
            !range.overlaps(object)
        }));
    }

    #[test]
    fn census_records_mixed_outcomes_and_strict_refusals() {
        let code = [0x0f, 0x05, 0x0f, 0x05, 0x0f, 0x34, 0x0f, 0x05, 0xc3];
        let entries = entries(&code, &[BASE, BASE + 2, BASE + 4, BASE + 6, BASE + 8]);
        let certificates = BTreeMap::from([(BASE, 39), (BASE + 6, 59)]);
        let config = SyscallStrategyConfig::new(SyscallStrategy::Zpoline)
            .with_placement(crate::syscall::PlacementBudget::new(256, 16, 1_048_576).unwrap())
            .unwrap();
        let prepared =
            PreparedZpolineSet::census(config, identity(), &code, BASE, &entries, &certificates)
                .unwrap();
        assert_eq!(prepared.sites().len(), 1);
        assert_eq!(
            prepared.outcomes(),
            [
                (BASE, crate::syscall::SiteOutcome::Trap),
                (BASE + 2, crate::syscall::SiteOutcome::Trap),
                (BASE + 4, crate::syscall::SiteOutcome::Trap),
                (BASE + 6, crate::syscall::SiteOutcome::Trap),
            ]
        );
        assert_eq!(prepared.metrics().trap, 4);
        assert_eq!(prepared.expected_source[..2], [0xff, 0xd0]);

        let strict = config
            .with_fallback(crate::syscall::FallbackPolicy::Refuse)
            .unwrap();
        let prepared =
            PreparedZpolineSet::census(strict, identity(), &code, BASE, &entries, &certificates)
                .unwrap();
        assert_eq!(
            prepared.outcomes()[1].1,
            crate::syscall::SiteOutcome::Refused(SyscallRefusal::SyscallNumberRangeUnproven)
        );
        assert_eq!(
            prepared.outcomes()[2].1,
            crate::syscall::SiteOutcome::Refused(SyscallRefusal::UnsupportedSyscallEntry)
        );
        assert_eq!(
            prepared.outcomes()[3].1,
            crate::syscall::SiteOutcome::Refused(SyscallRefusal::UnsupportedSyscallSemantics {
                nr: 59
            })
        );
    }

    #[test]
    fn explicit_batch_aggregates_expected_bytes() {
        let code = [0x0f, 0x05, 0x0f, 0x05, 0xc3];
        let entries = entries(&code, &[BASE, BASE + 2, BASE + 4]);
        let config = SyscallStrategyConfig::new(SyscallStrategy::Zpoline)
            .with_placement(crate::syscall::PlacementBudget::new(256, 16, 1_048_576).unwrap())
            .unwrap();
        let mut first = site(&code, &entries, BASE, 39);
        first.config = config;
        let mut second = site(&code, &entries, BASE + 2, 186);
        second.config = config;
        let prepared = PreparedZpolineSet::prepare_batch(vec![second, first]).unwrap();
        assert_eq!(prepared.sites().len(), 2);
        assert_eq!(prepared.sites()[0].logical_pc, BASE);
        assert_eq!(prepared.expected_source, [0xff, 0xd0, 0xff, 0xd0, 0xc3]);
        assert_eq!(prepared.metrics().trap, 2);
    }

    #[test]
    fn stale_metrics_count_only_rewritten_sites() {
        let outcomes = [
            (BASE, crate::syscall::SiteOutcome::RewrittenZpoline),
            (BASE + 2, crate::syscall::SiteOutcome::Trap),
            (
                BASE + 4,
                crate::syscall::SiteOutcome::Refused(SyscallRefusal::NotSyscallSite),
            ),
        ];
        let metrics = metrics_for(&outcomes, true, PlacementCounts::default());
        assert_eq!(metrics.rewritten_zpoline, 1);
        assert_eq!(metrics.trap, 1);
        assert_eq!(metrics.refused, 1);
        assert_eq!(metrics.stale_sites, 1);
    }
}
