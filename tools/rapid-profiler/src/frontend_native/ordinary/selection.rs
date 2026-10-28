//! Explicit range selection within one independently trusted final ELF.
//! No function-boundary discovery, runtime-address input or symbol fallback.
use super::{
    IntegerLeafContract, LoadedIntegerLeaf, Parsed, Retained, SetupRefusal, cfg,
    parse_admitted_selection, retain_loader,
};
use std::path::Path;

/// Immutable selection metadata bound to the complete final ELF bytes.
///
/// This descriptor is not a certificate, loader owner or execution authority.
/// Its safe constructor checks only representation bounds. The independent
/// authority and completeness requirements are the unsafe contract of
/// [`LoadedIntegerLeaf::load_selected`]. In particular, a digest or range copied
/// from the candidate at load time does not supply independent trust.
pub struct TrustedFunctionSelection<'a> {
    trusted_final_elf: &'a [u8],
    elf_virtual_address: u64,
    length: usize,
    label: &'a str,
}
impl<'a> TrustedFunctionSelection<'a> {
    /// Bind an ELF virtual address and complete extent to the exact final file.
    /// `label` is stable printable ASCII metadata, never a symbol lookup key.
    /// The range is neither a file offset nor an already relocated address.
    /// Successful construction does not inspect ELF, instructions or provenance.
    pub fn new(
        trusted_final_elf: &'a [u8],
        elf_virtual_address: u64,
        length: usize,
        label: &'a str,
    ) -> Result<Self, SetupRefusal> {
        if label.is_empty() || label.len() > 255 || !label.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(SetupRefusal::Format);
        }
        if !(1..=256).contains(&length) {
            return Err(SetupRefusal::SymbolOwner);
        }
        elf_virtual_address
            .checked_add(length as u64)
            .ok_or(SetupRefusal::Format)?;
        Ok(Self {
            trusted_final_elf,
            elf_virtual_address,
            length,
            label,
        })
    }
    pub fn trusted_final_elf(&self) -> &[u8] {
        self.trusted_final_elf
    }
    /// Complete half-open extent in ELF virtual-address coordinates.
    pub fn elf_range(&self) -> (u64, u64) {
        (
            self.elf_virtual_address,
            self.elf_virtual_address + self.length as u64,
        )
    }
    pub fn label(&self) -> &str {
        self.label
    }
}

pub(super) fn parse(selection: &TrustedFunctionSelection<'_>) -> Result<Parsed, SetupRefusal> {
    parse_admitted_selection(
        selection.trusted_final_elf,
        selection.label,
        Some((selection.elf_virtual_address, selection.length)),
        |code, entry| cfg::admit(code, entry).map(|_| ()),
    )
}

// Pure predicates shared with the metadata controls; no injected loader API.
pub(super) fn relocated_entry(bias: u64, entry: u64) -> Result<u64, SetupRefusal> {
    let address = bias.checked_add(entry).ok_or(SetupRefusal::SymbolOwner)?;
    if bias % 4096 != 0 || address == 0 {
        return Err(SetupRefusal::SymbolOwner);
    }
    Ok(address)
}
pub(super) fn object_identity(bias: u64, found: bool, base: u64) -> Result<(), SetupRefusal> {
    if !found || base != bias {
        return Err(SetupRefusal::SymbolOwner);
    }
    Ok(())
}

fn resolve(owner: &Retained, parsed: &Parsed) -> Result<(u64, u64), SetupRefusal> {
    let mut link: *const u64 = std::ptr::null();
    // SAFETY: the retained normal-loader handle remains live. RTLD_DI_LINKMAP
    // writes a borrowed link_map pointer; its first ELF64 ABI field is l_addr.
    if unsafe { libc::dlinfo(owner._handle, 2, (&raw mut link).cast()) } != 0 || link.is_null() {
        return Err(SetupRefusal::SymbolOwner);
    }
    // SAFETY: successful dlinfo above supplies this live read-only loader field.
    let bias = unsafe { link.read() };
    let address = relocated_entry(bias, parsed.entry)?;
    // SAFETY: initialized loader output; dladdr identifies the containing object
    // without executing the selected code or requiring an exported symbol.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let found = unsafe { libc::dladdr(address as usize as *const libc::c_void, &mut info) } != 0;
    object_identity(bias, found, info.dli_fbase as usize as u64)?;
    Ok((address, bias))
}

impl LoadedIntegerLeaf {
    /// Admit an explicitly selected internal scalar function, then retain the
    /// same normal-loader owner used by the named route. No subject is called.
    /// Whole ELF, CFG, source pages and live mapping checks precede success.
    /// No name lookup or fallback is attempted; `load` remains named-only.
    ///
    /// # Safety
    /// The selection's **complete final ELF** must be independently trusted
    /// compiler/linker output, including any stripping transformation. The
    /// selected ELF virtual address, complete function extent and stable label
    /// must come from trusted metadata for those exact final bytes. A pre-strip
    /// address is insufficient without proof that final geometry is unchanged.
    /// File offsets/runtime PCs must not be substituted, even when numerically
    /// plausible. Decoding cannot prove completeness or universally detect an
    /// arbitrary interior selection that happens to be a valid smaller CFG.
    ///
    /// The caller establishes sole external entry and complete entry/resume
    /// closure, one controlled calling thread, exact SysV
    /// `(*const u8, usize) -> u64` ABI, quiescence until qualified publication,
    /// and valid readable input bounds for every actual subject read. Inspection
    /// does not prove pointer provenance, checksum semantics or termination.
    /// Ordinary returns and no active CET, signal entry, unwind/nonlocal exit,
    /// fork, cancellation, alias writer, unload or mapping/protection change
    /// must hold through last use. The original file stays immutable. Calling
    /// and publishing retain their separate existing unsafe contracts.
    ///
    /// The descriptor's bytes are copied into the retained owner; its borrowed
    /// label is selection metadata only. Handles/fds remain process-lived on
    /// later refusal, exactly as in the named path. No writable or callable
    /// pointer is exposed by successful loading.
    pub unsafe fn load_selected(
        path: &Path,
        selection: &TrustedFunctionSelection<'_>,
        contract: IntegerLeafContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        let parsed = parse(selection)?;
        // SAFETY: complete private parser and continuous external contract above.
        let retained = unsafe { retain_loader(path, selection.trusted_final_elf)? };
        let (address, bias) = resolve(retained, &parsed)?;
        let source_start = bias.checked_add(parsed.page).ok_or(SetupRefusal::Format)?;
        let certificate = cfg::admit(&parsed.code, address)?;
        let loaded = Box::leak(Box::new(Self {
            owner: retained,
            parsed,
            certificate,
            source_start,
        }));
        loaded.verify_original()?;
        Ok(loaded)
    }
}
