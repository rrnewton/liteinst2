//! Qualification fixture only: complete optimized calling body from caller.c.
//! A changed compiler body requires a new source/geometry review; it is not an
//! allowlist for production callers. The normal profile does not inspect callers.

pub const SYMBOL: &str = "normal_caller";
pub const BYTES: &[u8] = &[
    0x41, 0x55, 0x49, 0x89, 0xfd, 0x41, 0x54, 0x49, 0x89, 0xd4, 0x55, 0x48, 0x89, 0xf5, 0x53, 0x48,
    0x83, 0xec, 0x08, 0x48, 0x8b, 0x7d, 0x00, 0x48, 0x8b, 0x76, 0x08, 0x41, 0xff, 0xd5, 0x48, 0x8b,
    0x7d, 0x10, 0x49, 0x89, 0x04, 0x24, 0x48, 0x89, 0xc3, 0x48, 0x8b, 0x75, 0x18, 0x41, 0xff, 0xd5,
    0x49, 0x89, 0x44, 0x24, 0x08, 0x48, 0x83, 0xc4, 0x08, 0x48, 0x01, 0xd8, 0x5b, 0x5d, 0x41, 0x5c,
    0x41, 0x5d, 0xc3,
];
pub const HEADS: &[u64] = &[
    0, 2, 5, 7, 10, 11, 14, 15, 19, 23, 27, 30, 34, 38, 41, 45, 48, 53, 57, 60, 61, 62, 64, 66,
];
pub const CALLS: [u64; 2] = [27, 45];
pub const CONTINUATIONS: [u64; 2] = [30, 48];
pub const OUTER_RET: u64 = 66;
// Four 8-byte saves and an 8-byte alignment slot, then a real 8-byte CALL push.
pub const SUBJECT_RSP_DELTA: u64 = 48;
pub const PROTECTED_STACK_BELOW_CALLER: u64 = SUBJECT_RSP_DELTA + 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Request {
    pub data: *const u8,
    pub bound: u64,
}
pub type Target = unsafe extern "C" fn(*const u8, usize) -> u64;
pub type Caller = unsafe extern "C" fn(Target, *const Request, *mut u64) -> u64;
