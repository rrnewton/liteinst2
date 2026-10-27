//! Fixed descriptive C ABI. No value is an execution or entry certificate.

pub const VERSION: u32 = 1;
pub const OK: u32 = 0;
pub const BAD_ARGUMENT: u32 = 1;
pub const NOT_READY: u32 = 2;
pub const BUSY: u32 = 3;
pub const ALREADY_INITIALIZED: u32 = 4;
pub const ADDRESS_OVERFLOW: u32 = 5;
pub const MISSING_BOUNDARY: u32 = 6;
pub const OUTPUT_CAPACITY: u32 = 7;

pub const VALID: u32 = 0;
pub const INVALID: u32 = 1;
pub const TRUNCATED: u32 = 2;

pub const NONE: u32 = 0;
pub const CPUID: u32 = 1;
pub const RDRAND: u32 = 2;
pub const RDSEED: u32 = 3;
pub const RDPID: u32 = 4;
pub const RDTSC: u32 = 5;
pub const RDTSCP: u32 = 6;
pub const SYSCALL: u32 = 7;
// These are decoded aliases, not selected by this prototype's fixed policy.
pub const SYSENTER: u32 = 8;
pub const INT80: u32 = 9;
pub const NO_REGISTER: u32 = 16;

pub const STEP_UNSUPPORTED: u32 = 0;
pub const STEP_CANDIDATE: u32 = 1;
pub const STEP_FLAGS_OBSERVED: u32 = 2;
pub const STEP_FLAGS_RESTORED: u32 = 3;
pub const STEP_DEBUG_INHIBITION: u32 = 4;
pub const STEP_KERNEL_TRANSFER: u32 = 5;
pub const STEP_RSP_WRITE: u32 = 6;
pub const STEP_PREFIX_UNQUALIFIED: u32 = 7;
pub const STEP_SELECTED: u32 = 8;
pub const STEP_INVALID: u32 = 9;
pub const STEP_TRANSACTION: u32 = 10;
pub const STEP_CONTROL_STATE: u32 = 11;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DecoderStats {
    pub abi_version: u32,
    pub phase: u32,
    pub first_fatal_reason: u32,
    pub reserved: u32,
    pub arena_bytes: u64,
    pub retained_high_water: u64,
    pub allocation_calls: u64,
    pub deallocation_calls: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Decoded {
    pub pc: u64,
    pub next_pc: u64,
    pub abi_version: u32,
    pub decode_status: u32,
    pub code: u32,
    pub kind: u32,
    pub destination: u32,
    pub width_bits: u32,
    pub step_disposition: u32,
    pub available: u32,
    pub length: u32,
    pub reserved: u32,
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Scan {
    pub page: u64,
    pub dependency_first: u64,
    pub dependency_end: u64,
    pub abi_version: u32,
    pub complete: u32,
    pub starts: u32,
    pub invalid_starts: u32,
    pub truncated_starts: u32,
    pub candidates: u32,
    pub written: u32,
    pub reserved: u32,
    pub by_class: [u32; 7],
    pub padding: u32,
}
