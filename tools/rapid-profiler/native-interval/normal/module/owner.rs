//! Private four-call fixture; the old 67-byte owner and loader core are unchanged.
use super::super::caller::{
    CallerError, FixtureOwner, FixtureSpec, Parsed, Result, parse_spec, require, sealed,
};
use super::*;
struct Profile;
impl sealed::Sealed for Profile {}
impl FixtureSpec for Profile {
    fn name() -> &'static str {
        bytes::SYMBOL
    }
    fn symbol() -> &'static std::ffi::CStr {
        c"normal_module_caller"
    }
    fn bytes() -> &'static [u8] {
        bytes::BYTES
    }
    fn body(code: &[u8]) -> Result<()> {
        require(code == bytes::BYTES, CallerError::SourceBytes)
    }
    fn symbols(_trusted: &[u8], _entry: u64, _file_offset: u64) -> Result<()> {
        Ok(())
    }
    fn parse(trusted: &[u8]) -> Result<Parsed> {
        parse_spec::<Self>(trusted)
    }
}
pub(super) struct Caller {
    inner: FixtureOwner<Profile>,
}
impl Caller {
    /// # Safety
    /// Independent complete final module_caller.c ELF, no active CET, signals,
    /// fork, alias writer, unload or loader changes through last invocation. The
    /// process-lived loader core checks all old file/ELF/live-page predicates.
    pub(super) unsafe fn load(path: &Path, trusted: &[u8]) -> Self {
        Self {
            inner: unsafe { FixtureOwner::<Profile>::load(path, trusted) }.unwrap(),
        }
    }
    pub(super) fn entry(&self) -> u64 {
        self.inner.entry()
    }
    pub(super) fn source(&self) -> (u64, &[u8]) {
        self.inner.source()
    }
    pub(super) fn verify(&mut self) {
        self.inner.verify().unwrap();
    }
    /// # Safety
    /// Two retained, admitted targets in semantic CSV/length order, two distinct
    /// live readable inputs, disjoint target/request/result arrays. One sequential
    /// caller, depth one, ordinary returns only; actual publication/attachment and
    /// postflight/checkpoint authority is the surrounding child, not this owner.
    pub(super) unsafe fn invoke(
        &mut self,
        targets: &[bytes::Target; 2],
        requests: &[bytes::Request; 2],
        results: &mut [u64; 4],
    ) -> u64 {
        assert_eq!(self.inner.pid(), std::process::id());
        assert!(targets.iter().all(|p| *p as usize != 0));
        let call: bytes::Caller = unsafe { std::mem::transmute(self.inner.entry() as usize) };
        let value = unsafe { call(targets.as_ptr(), requests.as_ptr(), results.as_mut_ptr()) };
        assert_eq!(value, results.iter().copied().fold(0, u64::wrapping_add));
        value
    }
}
