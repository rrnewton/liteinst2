//! Fixture-private calling profile shared by qualification and timed execution.
//! This is not a library API or a callable capability derived from admission.
use rapid_profiler::frontend_native::LoadedCallTree;
use std::marker::PhantomData;
use std::rc::Rc;

core::arch::global_asm!(
    ".pushsection .text",
    ".balign 16",
    ".global __rapid_profiler_native_tree_call_v1",
    ".hidden __rapid_profiler_native_tree_call_v1",
    ".type __rapid_profiler_native_tree_call_v1,@function",
    "__rapid_profiler_native_tree_call_v1:",
    "push rbx",
    "mov r11, rdi",
    "mov rdi, rsi",
    "mov rsi, rdx",
    "call r11",
    "pop rbx",
    "ret",
    ".global __rapid_profiler_native_tree_call_end_v1",
    ".hidden __rapid_profiler_native_tree_call_end_v1",
    "__rapid_profiler_native_tree_call_end_v1:",
    ".size __rapid_profiler_native_tree_call_v1,.-__rapid_profiler_native_tree_call_v1",
    ".popsection",
);
unsafe extern "C" {
    fn __rapid_profiler_native_tree_call_v1(target: u64, data: *const u8, length: usize) -> u64;
    static __rapid_profiler_native_tree_call_end_v1: u8;
}

// Independent literal encoding: the qualifier and client authenticate the whole
// linked symbol before entry. The actual benchmark retains this shim's cost.
pub const STENCIL: &[u8] = &[
    0x53, 0x49, 0x89, 0xfb, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x41, 0xff, 0xd3, 0x5b, 0xc3,
];

pub struct NativeCall {
    owner: &'static mut LoadedCallTree,
    entry: u64,
    _local: PhantomData<Rc<()>>,
}
impl NativeCall {
    /// # Safety
    /// The fixed, independently trusted two-function tree and exact SysV ABI
    /// remain exclusively owned on this actual thread through the final return.
    /// No foreign entry, source/file/alias writer, signal, nonlocal exit, fork,
    /// unload or CET is permitted. Source admission alone does not prove these
    /// execution premises. This private profile needs separate native validation.
    pub unsafe fn new(owner: &'static mut LoadedCallTree) -> Self {
        owner.verify_original().unwrap();
        let entry = owner.certificate().root().entry();
        assert_ne!(entry, 0);
        let gate = Self::gate();
        assert_eq!(
            (&raw const __rapid_profiler_native_tree_call_end_v1 as usize as u64).checked_sub(gate),
            Some(STENCIL.len() as u64),
            "complete native calling symbol extent"
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(gate as usize as *const u8, STENCIL.len()) },
            STENCIL,
            "entire immutable native calling stencil"
        );
        Self {
            owner,
            entry,
            _local: PhantomData,
        }
    }
    pub fn gate() -> u64 {
        __rapid_profiler_native_tree_call_v1 as *const () as usize as u64
    }
    pub fn owner(&self) -> &LoadedCallTree {
        self.owner
    }
    pub fn verify_original(&mut self) {
        self.owner.verify_original().unwrap();
    }
    /// # Safety
    /// All constructor premises continue to hold. The input is immutable and
    /// contains the authenticated count64 bounded linked offsets and payloads;
    /// all actual reads and the complete bounded stack remain mapped. The
    /// qualifier alone may use its owned, fully preserving Tree144 no-op bundle
    /// in place of original code, with the same closed ABI and real CALL/RETs.
    /// No source/input verification or TLS operation occurs inside this call.
    pub unsafe fn invoke(&mut self, input: &[u8]) -> u64 {
        unsafe { __rapid_profiler_native_tree_call_v1(self.entry, input.as_ptr(), input.len()) }
    }
}
