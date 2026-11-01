//! First owned-batch caller profile: the existing compiled four-call C body.
//! Exact recognition is deliberately finite; it grants no arbitrary-C admission.
use super::{
    Retained, SetupRefusal, TrustedFunctionSelection, retain_sealed_loader, selection,
    verify_expected_bodies,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};

// Reuse the unchanged qualification oracle, not its unsafe fixture owner. A
// separate sealed loader and explicit whole-ELF contract are supplied below.
#[path = "../../../normal-work/module_caller_bytes.rs"]
mod bytes;

fn admit(code: &[u8], entry: u64) -> Result<(), SetupRefusal> {
    if code != bytes::BYTES
        || entry == 0
        || entry.checked_add(code.len() as u64).is_none()
        || bytes::SUBJECT_RSP_DELTA.checked_add(128) != Some(bytes::PROTECTED_STACK_BELOW_CALLER)
    {
        return Err(SetupRefusal::EntryExit);
    }
    let mut decoder = Decoder::with_ip(64, code, entry, DecoderOptions::NONE);
    let mut heads = Vec::new();
    let mut calls = Vec::new();
    let mut stores = Vec::new();
    let mut returns = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() {
            return Err(SetupRefusal::EntryExit);
        }
        let at = i.ip() - entry;
        heads.push(at);
        match i.flow_control() {
            FlowControl::IndirectCall => calls.push((at, i.next_ip() - entry)),
            FlowControl::Return => returns.push(at),
            FlowControl::Next => {}
            _ => return Err(SetupRefusal::EntryExit),
        }
        if i.mnemonic() == Mnemonic::Mov && i.op0_kind() == OpKind::Memory {
            stores.push(at);
        }
    }
    if heads != bytes::HEADS
        || calls
            != bytes::CALLS
                .into_iter()
                .zip(bytes::CONTINUATIONS)
                .collect::<Vec<_>>()
        || stores != bytes::RESULT_STORES
        || returns != [bytes::OUTER_RET]
    {
        return Err(SetupRefusal::EntryExit);
    }
    Ok(())
}

// The existing fixed compiler recipe uses -Bsymbolic: exactly one
// DT_SYMBOLIC=0 before DT_NULL is required here. With all dependencies,
// relocations, PLT, constructors and IFUNC behavior still refused, this binding
// marker introduces no loader call or relocation write. Default scalar/module
// admission continues to use the unchanged parent dynamic() and rejects tag16.
pub(super) fn dynamic(bytes: &[u8]) -> Result<(), SetupRefusal> {
    use super::{BTreeMap, u64_at};
    if bytes.is_empty() || bytes.len() > 4096 || bytes.len() % 16 != 0 {
        return Err(SetupRefusal::Format);
    }
    let mut tags = BTreeMap::new();
    let mut ended = false;
    for row in bytes.chunks_exact(16) {
        let (tag, value) = (u64_at(row, 0)?, u64_at(row, 8)?);
        if tag == 0 {
            if value != 0 {
                return Err(SetupRefusal::Format);
            }
            ended = true;
        } else if ended
            || tags.insert(tag, value).is_some()
            || !matches!(
                tag,
                4 | 5 | 6 | 10 | 11 | 14 | 16 | 24 | 30 | 0x6fff_fef5 | 0x6fff_fffb
            )
            || (matches!(tag, 16 | 24) && value != 0)
            || (tag == 30 && value & !8 != 0)
            || (tag == 0x6fff_fffb && value & !1 != 0)
        {
            return Err(SetupRefusal::Format);
        }
    }
    if !ended
        || tags.get(&16) != Some(&0)
        || ![5, 6, 10, 11].iter().all(|t| tags.contains_key(t))
        || tags.get(&11) != Some(&24)
        || tags.get(&10).is_none_or(|&n| n == 0 || n > 65536)
        || !(tags.contains_key(&4) || tags.contains_key(&0x6fff_fef5))
        || !(tags.contains_key(&24)
            || tags.get(&30).is_some_and(|v| v & 8 != 0)
            || tags.get(&0x6fff_fffb).is_some_and(|v| v & 1 != 0))
    {
        return Err(SetupRefusal::Format);
    }
    Ok(())
}

/// Sealed, retained native caller for one four-call batch; no callable pointer,
/// fd, loader handle or writer is exposed. This is the first finite application
/// shape, not general caller discovery or a replacement for module admission.
pub struct LoadedNormalModuleCaller {
    _owner: &'static mut Retained,
    entry: u64,
    pid: u32,
    #[cfg(any(test, feature = "frontend-native-qualification"))]
    qualification_source: (u64, Box<[u8]>),
}
impl LoadedNormalModuleCaller {
    /// Recognize the complete `normal-work/module_caller.c` body and original
    /// CALL/continuation/store/outer-RET oracle, then use the sealed-source loader
    /// and unchanged complete LOAD/RELRO/file/live-page provenance predicates.
    /// No selected or caller entry is invoked by construction.
    ///
    /// # Safety
    /// `selection` describes the complete independently trusted final caller
    /// ELF and exact complete function, including safe loader initialization and
    /// dependencies. Its ABI is the original C target/request/result-array ABI.
    /// Its only entries are future owned batches, with ordinary CALL/RET, no
    /// callbacks except the admitted target hooks, no signals/reentry/unwind,
    /// nonlocal exit, fork, active CET, foreign mapping/protection changes or
    /// writers. The loaded mappings remain process-lived and immutable; memfd
    /// seals protect backing bytes, not arbitrary hostile in-process code.
    /// The later `attach_owned` contract separately covers the target functions
    /// and *every* safe-accepted input. Body equality is not that semantic proof.
    pub unsafe fn load_sealed(
        selection: &TrustedFunctionSelection<'_>,
    ) -> Result<Self, SetupRefusal> {
        if selection.label() != bytes::SYMBOL {
            return Err(SetupRefusal::EntryExit);
        }
        let parsed = selection::parse_module_caller(selection, admit)?;
        // SAFETY: complete final ELF/loader and continuous native contract above.
        let owner = unsafe { retain_sealed_loader(selection.trusted_final_elf())? };
        let (entry, bias) = selection::resolve(owner, &parsed)?;
        admit(&parsed.code, entry)?;
        let source_start = bias.checked_add(parsed.page).ok_or(SetupRefusal::Format)?;
        verify_expected_bodies(owner, &parsed, entry, source_start, &parsed.code, None)?;
        Ok(Self {
            _owner: owner,
            entry,
            pid: std::process::id(),
            #[cfg(any(test, feature = "frontend-native-qualification"))]
            qualification_source: (source_start, parsed.source.into_boxed_slice()),
        })
    }
    pub(in crate::frontend_native) fn process_matches(&self) -> bool {
        self.pid == std::process::id()
    }
    pub(in crate::frontend_native) fn continuations(&self) -> [u64; 4] {
        bytes::CONTINUATIONS.map(|offset| self.entry + offset)
    }
    /// The private owner adapter has acquired its batch lease and retains all
    /// slices, selected mappings and separate result memory through checkpoint.
    /// The once-admitted universal ABI/input contract holds; no pointer escapes.
    pub(in crate::frontend_native) unsafe fn invoke(
        &mut self,
        entries: [u64; 2],
        inputs: [&[u8]; 2],
        results: &mut [u64; 4],
    ) -> u64 {
        let targets = entries.map(|entry| {
            // SAFETY: matching installed selected entry and exact admitted ABI.
            unsafe { std::mem::transmute::<usize, bytes::Target>(entry as usize) }
        });
        let requests = inputs.map(|input| bytes::Request {
            data: input.as_ptr(),
            bound: input.len() as u64,
        });
        // SAFETY: complete authenticated caller and live disjoint private arrays.
        let call = unsafe { std::mem::transmute::<usize, bytes::Caller>(self.entry as usize) };
        // One genuine compiled application call; there is no per-target SDK call.
        unsafe { call(targets.as_ptr(), requests.as_ptr(), results.as_mut_ptr()) }
    }
}

#[cfg(any(test, feature = "frontend-native-qualification"))]
impl LoadedNormalModuleCaller {
    /// Diagnostic address of the exact retained caller; not a safe invocation capability.
    pub fn qualification_entry(&self) -> u64 {
        self.entry
    }
    /// Original full source page authenticated by the same sealed loader.
    pub fn qualification_source(&self) -> (u64, &[u8]) {
        (self.qualification_source.0, &self.qualification_source.1)
    }
    /// Oracle-only exact arrays. The private caller capability is never exposed.
    /// # Safety
    /// All ordinary invoke contracts hold. The three arrays have the exact
    /// admitted C layouts, and the qualification adapter owns and checks them.
    pub(in crate::frontend_native) unsafe fn invoke_qualification(
        &mut self,
        targets: *const u64,
        requests: *const u8,
        results: *mut u64,
    ) -> u64 {
        // SAFETY: retained exact caller, checked arrays and continuous contract.
        let call = unsafe { std::mem::transmute::<usize, bytes::Caller>(self.entry as usize) };
        unsafe { call(targets.cast(), requests.cast(), results) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_caller_preserves_complete_native_oracle_and_refuses_every_byte_mutation() {
        admit(bytes::BYTES, 0x1000).unwrap();
        assert_eq!(bytes::BYTES.len(), 123);
        assert_eq!(bytes::CALLS, [31, 50, 70, 93]);
        assert_eq!(bytes::CONTINUATIONS, [35, 54, 74, 97]);
        assert_eq!(bytes::RESULT_STORES, [39, 58, 81, 100]);
        assert_eq!(bytes::OUTER_RET, 122);
        assert_eq!(bytes::SUBJECT_RSP_DELTA, 64);
        assert_eq!(bytes::PROTECTED_STACK_BELOW_CALLER, 192);
        for index in 0..bytes::BYTES.len() {
            let mut changed = bytes::BYTES.to_vec();
            changed[index] ^= 1;
            assert!(admit(&changed, 0x1000).is_err());
        }
        assert!(admit(&bytes::BYTES[..122], 0x1000).is_err());
        let mut extended = bytes::BYTES.to_vec();
        extended.push(0x90);
        assert!(admit(&extended, 0x1000).is_err());
        assert!(admit(bytes::BYTES, 0).is_err());
        assert!(admit(bytes::BYTES, u64::MAX - 122).is_err());
    }
}

#[cfg(test)]
#[path = "module_caller_format_tests.rs"]
mod format_tests;
