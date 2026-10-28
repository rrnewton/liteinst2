//! Normal-loader admission for a bounded scalar symbol, separate from the two
//! fixed interval fixtures. This module neither publishes nor calls code.
use super::{
    Load, Relro, SetupRefusal, bounded_read, file_range, load_permissions, map_rows, mount_device,
    u16_at, u32_at, u64_at,
};
use object::{Object, ObjectSection, ObjectSymbol, SymbolFlags, SymbolKind};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

mod cfg;
mod selection;
mod tree;
pub use selection::TrustedFunctionSelection;
pub(in crate::frontend_native) use tree::TreeSourceProof;
pub use tree::{
    CallTreeCertificate, LoadedCallTree, TreeCallEdge, TreeContract, TreeRootCertificate,
};

/// Explicit external facts; byte inspection does not establish these claims.
#[derive(Clone, Copy, Debug)]
pub struct IntegerLeafContract {
    /// The symbol entry is the sole external entry; no saved interior resume,
    /// signal entry, alias entry or foreign caller can bypass the client gate.
    pub single_external_entry: bool,
    /// Every invocation returns normally; no unwind, longjmp or cancellation.
    pub ordinary_ret_only: bool,
    /// Caller certifies no active IBT or shadow stack; neither is disabled here.
    pub no_active_cet: bool,
}
impl IntegerLeafContract {
    fn check(self) -> Result<(), SetupRefusal> {
        if !self.single_external_entry {
            return Err(SetupRefusal::EntryExit);
        }
        if !self.ordinary_ret_only {
            return Err(SetupRefusal::ExitSemantics);
        }
        if !self.no_active_cet {
            return Err(SetupRefusal::Cet);
        }
        Ok(())
    }
}

/// Immutable decoded geometry minted by the complete selected-symbol check.
/// It is not a publication receipt, quiescence lease or callable function.
#[derive(Debug)]
pub struct IntegerLeafCertificate {
    entry: u64,
    end: u64,
    heads: Vec<u64>,
    entries: Vec<u64>,
    padding: Vec<u64>,
    returns: Vec<u64>,
    blocks: Vec<(u64, u64)>,
    edges: Vec<(u64, u64)>,
}
impl IntegerLeafCertificate {
    pub fn entry(&self) -> u64 {
        self.entry
    }
    /// Complete half-open symbol extent, at most 256 bytes.
    pub fn range(&self) -> (u64, u64) {
        (self.entry, self.end)
    }
    /// Every decoded head, including explicitly classified unreachable NOPs.
    pub fn heads(&self) -> &[u64] {
        &self.heads
    }
    /// Symbol entry plus reachable branch targets and conditional fallthroughs.
    /// Interior heads are not thereby declared externally callable.
    pub fn entries(&self) -> &[u64] {
        &self.entries
    }
    pub fn padding_heads(&self) -> &[u64] {
        &self.padding
    }
    /// Every reachable original ordinary C3; none may be omitted by installation.
    pub fn returns(&self) -> &[u64] {
        &self.returns
    }
    /// Half-open reachable basic blocks; padding gaps are not planning windows.
    pub fn blocks(&self) -> &[(u64, u64)] {
        &self.blocks
    }
    /// Every reachable decoded successor, including ordinary fallthroughs.
    pub fn edges(&self) -> &[(u64, u64)] {
        &self.edges
    }
}

struct Parsed {
    loads: Vec<Load>,
    relro: Option<Relro>,
    code: Vec<u8>,
    entry: u64,
    page: u64,
    page_offset: u64,
    source: Vec<u8>,
}

fn dynamic(bytes: &[u8]) -> Result<(), SetupRefusal> {
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
        } else if ended || tags.insert(tag, value).is_some()
            // No dependency, constructor/destructor, IFUNC relocation, REL[A/R],
            // PLT, TEXTREL, RPATH/RUNPATH or TLS-loader behavior in this profile.
            || !matches!(tag, 4 | 5 | 6 | 10 | 11 | 14 | 24 | 30 | 0x6fff_fef5 | 0x6fff_fffb)
            || (tag == 24 && value != 0) || (tag == 30 && value & !8 != 0)
            || (tag == 0x6fff_fffb && value & !1 != 0)
        {
            return Err(SetupRefusal::Format);
        }
    }
    if !ended
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

// The leaf callback preserves the existing complete CFG check. The only other
// callers are this module's closed tree validators; no unchecked parse escapes.
fn parse(bytes: &[u8], name: &str) -> Result<Parsed, SetupRefusal> {
    parse_admitted(bytes, name, |code, entry| {
        cfg::admit(code, entry).map(|_| ())
    })
}

fn parse_admitted(
    bytes: &[u8],
    name: &str,
    admit_code: fn(&[u8], u64) -> Result<(), SetupRefusal>,
) -> Result<Parsed, SetupRefusal> {
    parse_admitted_selection(bytes, name, None, admit_code)
}

// Named callers keep their complete old predicate order below. Only the new
// trusted scalar descriptor supplies a range; it cannot supply an admit callback.
fn parse_admitted_selection(
    bytes: &[u8],
    name: &str,
    range: Option<(u64, usize)>,
    admit_code: fn(&[u8], u64) -> Result<(), SetupRefusal>,
) -> Result<Parsed, SetupRefusal> {
    if bytes.len() > 1024 * 1024
        || bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16_at(bytes, 16)? != 3
        || u16_at(bytes, 18)? != 62
        || u32_at(bytes, 20)? != 1
        || u16_at(bytes, 54)? != 56
        || !(1..=16).contains(&u16_at(bytes, 56)?)
        || name.is_empty()
        || name.len() > 255
    {
        return Err(SetupRefusal::Format);
    }
    let elf_entry = u64_at(bytes, 24)?;
    let phoff = usize::try_from(u64_at(bytes, 32)?).map_err(|_| SetupRefusal::Format)?;
    let phend = phoff
        .checked_add(usize::from(u16_at(bytes, 56)?) * 56)
        .ok_or(SetupRefusal::Format)?;
    bytes.get(phoff..phend).ok_or(SetupRefusal::Format)?;
    let mut loads = Vec::new();
    let mut dynamics = Vec::new();
    let mut relros = Vec::new();
    let mut stacks = 0;
    for n in 0..usize::from(u16_at(bytes, 56)?) {
        let p = phoff.checked_add(n * 56).ok_or(SetupRefusal::Format)?;
        let kind = u32_at(bytes, p)?;
        if matches!(kind, 3 | 7) {
            return Err(SetupRefusal::Format);
        } // interpreter/TLS
        if kind == 0x6474_e551 {
            stacks += 1;
            if u32_at(bytes, p + 4)? != 6 {
                return Err(SetupRefusal::Format);
            }
        }
        if kind == 2 {
            dynamics.push((
                u64_at(bytes, p + 8)?,
                u64_at(bytes, p + 16)?,
                u64_at(bytes, p + 32)?,
            ));
        }
        if kind == 0x6474_e552 {
            relros.push((u64_at(bytes, p + 16)?, u64_at(bytes, p + 40)?));
        }
        if kind != 1 {
            continue;
        }
        let load = Load {
            flags: u32_at(bytes, p + 4)?,
            offset: u64_at(bytes, p + 8)?,
            address: u64_at(bytes, p + 16)?,
            file_size: u64_at(bytes, p + 32)?,
            memory_size: u64_at(bytes, p + 40)?,
        };
        if !matches!(load.flags, 4..=6)
            // An unaligned empty interval can still have a nonempty rounded
            // mapping extent, so it cannot be omitted from ownership below.
            || (load.file_size == 0 && load.address % 4096 != 0)
            || load.file_size > 65536
            || load.memory_size != load.file_size
            || u64_at(bytes, p + 48)? != 4096
            || load.offset % 4096 != load.address % 4096
            || load
                .offset
                .checked_add(load.file_size)
                .is_none_or(|end| end > bytes.len() as u64)
            || load
                .address
                .checked_add(load.memory_size)
                .and_then(|end| end.checked_add(4095))
                .is_none()
        {
            return Err(SetupRefusal::Format);
        }
        // All fields above are checked even for empty LOADs. Only a zero
        // file/memory AND page-rounded extent contributes no mapping owner.
        if load.file_size != 0 {
            loads.push(load);
        }
    }
    if loads.is_empty()
        || dynamics.len() != 1
        || stacks != 1
        || loads
            .iter()
            .filter(|r| r.address == 0 && r.offset == 0 && r.flags == 4)
            .count()
            != 1
    {
        return Err(SetupRefusal::Format);
    }
    for (n, a) in loads.iter().enumerate() {
        if loads[..n].iter().any(|b| {
            (a.address & !4095) < ((b.address + b.file_size + 4095) & !4095)
                && (b.address & !4095) < ((a.address + a.file_size + 4095) & !4095)
        }) {
            return Err(SetupRefusal::Format);
        }
    }
    // This dlopen-only profile never invokes e_entry. A nonzero value is
    // nevertheless constrained to one real executable file interval; the
    // explicit selection below remains the only admitted callable entry.
    if elf_entry != 0
        && loads
            .iter()
            .filter(|r| {
                r.flags == 5 && elf_entry >= r.address && elf_entry < r.address + r.file_size
            })
            .count()
            != 1
    {
        return Err(SetupRefusal::Format);
    }
    if relros.len() > 1 {
        return Err(SetupRefusal::Format);
    }
    let relro = if let Some(&(start, size)) = relros.first() {
        let end = start.checked_add(size).ok_or(SetupRefusal::Format)?;
        let owners: Vec<_> = loads
            .iter()
            .enumerate()
            .filter(|(_, r)| r.flags == 6 && start >= r.address && end <= r.address + r.memory_size)
            .collect();
        if size == 0 || owners.len() != 1 || (start & !4095) >= (end & !4095) {
            return Err(SetupRefusal::Format);
        }
        Some(Relro {
            start: start & !4095,
            end: end & !4095,
            owner: owners[0].0,
        })
    } else {
        None
    };
    let (offset, address, length) = dynamics[0];
    let length = usize::try_from(length).map_err(|_| SetupRefusal::Format)?;
    if file_range(&loads, address, length)? as u64 != offset {
        return Err(SetupRefusal::Format);
    }
    let offset = usize::try_from(offset).map_err(|_| SetupRefusal::Format)?;
    dynamic(
        bytes
            .get(offset..offset.checked_add(length).ok_or(SetupRefusal::Format)?)
            .ok_or(SetupRefusal::Format)?,
    )?;
    let file = object::File::parse(bytes).map_err(|_| SetupRefusal::Format)?;
    if file.section_by_name(".note.gnu.property").is_some() {
        return Err(SetupRefusal::Cet);
    }
    // A relocation-free scalar DSO is sufficient for the first client. Refuse
    // static as well as dynamic relocation records rather than ignore targets.
    if file.sections().any(|s| s.relocations().next().is_some()) {
        return Err(SetupRefusal::Relocation);
    }
    let (entry, length) = if let Some((entry, length)) = range {
        // Do not silently broaden this profile to sectionless ELF: the same
        // inspectable symbol/section metadata must remain available to the
        // relocation, IFUNC and contradictory-definition checks. The subject
        // itself need not appear in either symbol table.
        if file.dynamic_symbol_table().is_none() || !(1..=256).contains(&length) {
            return Err(SetupRefusal::SymbolOwner);
        }
        (entry, length)
    } else {
        let rows: Vec<_> = file
            .dynamic_symbols()
            .filter(|s| s.name() == Ok(name) && s.is_definition())
            .collect();
        if rows.len() != 1
            || rows[0].kind() != SymbolKind::Text
            || !(1..=256).contains(&rows[0].size())
            || !matches!(
                rows[0].flags(),
                SymbolFlags::Elf {
                    st_info: 0x12,
                    st_other: 0 | 3
                }
            )
        {
            return Err(SetupRefusal::SymbolOwner);
        }
        let entry = rows[0].address();
        let length = usize::try_from(rows[0].size()).map_err(|_| SetupRefusal::Format)?;
        (entry, length)
    };
    let end = entry
        .checked_add(length as u64)
        .ok_or(SetupRefusal::Format)?;
    if file
        .dynamic_symbols()
        .any(|s| matches!(s.flags(), SymbolFlags::Elf { st_info, .. } if st_info & 15 == 10))
    {
        return Err(SetupRefusal::Relocation);
    }
    // Symbols cannot certify the absence of unknown external machine-code
    // entries, but a visible interior or overlapping definition must refuse.
    for s in file.symbols().chain(file.dynamic_symbols()) {
        if !s.is_definition() || matches!(s.kind(), SymbolKind::Section | SymbolKind::File) {
            continue;
        }
        let selected = match range {
            None => {
                s.name() == Ok(name)
                    && s.address() == entry
                    && s.size() == length as u64
                    && s.kind() == SymbolKind::Text
            }
            Some(_) => {
                s.address() == entry && s.size() == length as u64 && s.kind() == SymbolKind::Text
            }
        };
        let other_end = s
            .address()
            .checked_add(s.size())
            .ok_or(SetupRefusal::Format)?;
        if !selected
            && ((entry..end).contains(&s.address())
                || (s.size() != 0 && s.address() < end && entry < other_end))
        {
            return Err(SetupRefusal::EntryExit);
        }
    }
    let owners: Vec<_> = loads
        .iter()
        .filter(|r| r.flags == 5 && entry >= r.address && end <= r.address + r.file_size)
        .collect();
    if owners.len() != 1 {
        return Err(SetupRefusal::SymbolOwner);
    }
    let at = file_range(&loads, entry, length)?;
    let code = bytes
        .get(at..at + length)
        .ok_or(SetupRefusal::SourceBytes)?
        .to_vec();
    admit_code(&code, entry)?;
    let page = entry & !4095;
    let source_len =
        usize::try_from(((end + 4095) & !4095) - page).map_err(|_| SetupRefusal::Format)?;
    if !matches!(source_len, 4096 | 8192) {
        return Err(SetupRefusal::Format);
    }
    let page_offset = u64::try_from(
        i128::from(owners[0].offset) + i128::from(page) - i128::from(owners[0].address),
    )
    .map_err(|_| SetupRefusal::Format)?;
    let start = usize::try_from(page_offset).map_err(|_| SetupRefusal::Format)?;
    let available = bytes
        .len()
        .checked_sub(start)
        .ok_or(SetupRefusal::Format)?
        .min(source_len);
    let mut source = vec![0; source_len];
    source[..available].copy_from_slice(&bytes[start..start + available]);
    Ok(Parsed {
        loads,
        relro,
        code,
        entry,
        page,
        page_offset,
        source,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn stamp(file: &File) -> Result<Stamp, SetupRefusal> {
    let m = file.metadata().map_err(|_| SetupRefusal::OperatingSystem)?;
    if !m.is_file() {
        return Err(SetupRefusal::Format);
    }
    Ok(Stamp {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        mode: m.mode(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}
struct Retained {
    _handle: *mut libc::c_void,
    file: File,
    expected: Vec<u8>,
    original: Stamp,
    device: (u32, u32),
    pid: u32,
}
// The caller must have completed the private whole-ELF/code parser and retain
// its explicit no-constructor/no-writer/no-unload contract. No subject is called.
unsafe fn retain_loader(
    path: &Path,
    expected: &[u8],
) -> Result<&'static mut Retained, SetupRefusal> {
    let mut file = File::open(path).map_err(|_| SetupRefusal::OperatingSystem)?;
    let original = stamp(&file)?;
    if bounded_read(&mut file)? != expected
        || original != stamp(&file)?
        || original.size != expected.len() as u64
    {
        return Err(SetupRefusal::SourceBytes);
    }
    let device = mount_device(file.as_raw_fd())?;
    let mut shstk = 0_u64;
    // SAFETY: read-only status query; never changes CET state.
    let status = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut shstk) };
    if status == 0 && shstk != 0 {
        return Err(SetupRefusal::Cet);
    }
    if status != 0
        && !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL | libc::ENOSYS)
        )
    {
        return Err(SetupRefusal::OperatingSystem);
    }
    let fd_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    // SAFETY: whole trusted DSO and explicit caller obligations above.
    let handle = unsafe { libc::dlopen(fd_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(SetupRefusal::OperatingSystem);
    }
    // Keep the original fd/handle on every subsequent refusal as well.
    let retained = Box::leak(Box::new(Retained {
        _handle: handle,
        file,
        expected: expected.to_vec(),
        original,
        device,
        pid: std::process::id(),
    }));
    Ok(retained)
}

fn loaded_symbol(
    owner: &Retained,
    parsed: &Parsed,
    symbol: &CStr,
) -> Result<(u64, u64), SetupRefusal> {
    let handle = owner._handle;
    // SAFETY: live retained loader handle and terminated symbol name.
    let address = unsafe { libc::dlsym(handle, symbol.as_ptr()) } as usize as u64;
    let bias = address
        .checked_sub(parsed.entry)
        .ok_or(SetupRefusal::SymbolOwner)?;
    if address == 0 || bias % 4096 != 0 {
        return Err(SetupRefusal::SymbolOwner);
    }
    // SAFETY: initialized loader outputs; addresses remain owned by dlopen.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(address as usize as *const libc::c_void, &mut info) } == 0
        || info.dli_fbase as usize as u64 != bias
        || info.dli_saddr as usize as u64 != address
        || info.dli_sname.is_null()
        || unsafe { CStr::from_ptr(info.dli_sname) } != symbol
    {
        return Err(SetupRefusal::SymbolOwner);
    }
    let mut link: *const u64 = std::ptr::null();
    // RTLD_DI_LINKMAP: l_addr is the first ELF64 link_map ABI field.
    if unsafe { libc::dlinfo(handle, 2, (&raw mut link).cast()) } != 0
        || link.is_null()
        || unsafe { link.read() } != bias
    {
        return Err(SetupRefusal::SymbolOwner);
    }
    Ok((address, bias))
}

/// A process-lived normal-loader owner. No Drop, dlclose, executable function
/// pointer, publication receipt or writable code view is exposed.
pub struct LoadedIntegerLeaf {
    owner: &'static mut Retained,
    parsed: Parsed,
    certificate: IntegerLeafCertificate,
    source_start: u64,
}
impl LoadedIntegerLeaf {
    /// Authenticate a pinned dependency/constructor-free scalar DSO, then load
    /// it using the system loader. No subject instruction is called here.
    ///
    /// # Safety
    /// `expected` is independently pinned trusted compiler output, not bytes
    /// read from this candidate and accepted as their own authority. The caller
    /// establishes complete entry/resume closure, one controlled calling thread,
    /// the exact SysV `(*const u8, usize) -> u64` ABI, and quiescence until later
    /// qualified publication/attachment. Every actual subject memory read must
    /// stay within valid readable input storage for every invocation (LEA/NOP
    /// address forms do not read that memory); code inspection does
    /// not prove pointer provenance, input bounds, checksum semantics or loop
    /// termination. No active CET, signal entry, unwind/nonlocal exit, fork,
    /// cancellation, alias writer, unload or mapping/protection change may
    /// invalidate this owner through its last use. The original file remains
    /// immutable. Calling and publishing require their own contracts.
    pub unsafe fn load(
        path: &Path,
        expected: &[u8],
        symbol: &CStr,
        contract: IntegerLeafContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        let name = symbol.to_str().map_err(|_| SetupRefusal::SymbolOwner)?;
        let parsed = parse(expected, name)?;
        // SAFETY: the complete unchanged leaf parser and caller contract above.
        let retained = unsafe { retain_loader(path, expected)? };
        let (address, bias) = loaded_symbol(retained, &parsed, symbol)?;
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
    pub fn entry(&self) -> u64 {
        self.certificate.entry
    }
    pub fn code(&self) -> &[u8] {
        &self.parsed.code
    }
    pub fn certificate(&self) -> &IntegerLeafCertificate {
        &self.certificate
    }
    /// Complete containing RX pages, not just the displaced instruction span.
    pub fn source_range(&self) -> (u64, u64) {
        (
            self.source_start,
            self.source_start + self.parsed.source.len() as u64,
        )
    }
    pub fn original_source(&self) -> &[u8] {
        &self.parsed.source
    }
    pub fn verify_original(&mut self) -> Result<(), SetupRefusal> {
        let code = self.parsed.code.clone();
        self.verify_expected_patch(&code)
    }
    // Only a later sealed factory may supply its validated complete body
    // overlay. Same owner and every byte outside that body are always checked.
    pub(in crate::frontend_native) fn verify_expected_patch(
        &mut self,
        expected: &[u8],
    ) -> Result<(), SetupRefusal> {
        let entry = self.entry();
        verify_expected_bodies(
            self.owner,
            &self.parsed,
            entry,
            self.source_start,
            expected,
            None,
        )
    }
}

// Only the closed tree's private verifier supplies the second disjoint body.
struct BodyOverlay<'a> {
    entry: u64,
    expected: &'a [u8],
}

fn verify_expected_bodies(
    owner: &mut Retained,
    parsed: &Parsed,
    entry: u64,
    source_start: u64,
    expected: &[u8],
    additional: Option<BodyOverlay<'_>>,
) -> Result<(), SetupRefusal> {
    verify_source_provenance(owner, parsed, entry, source_start, expected.len())?;
    let whole = expected_source_page(parsed, entry, source_start, expected, additional)?;
    // SAFETY: retained readable mapping contract and current complete provenance.
    unsafe { verify_live_source(source_start, &whole) }
}

fn verify_source_provenance(
    owner: &mut Retained,
    parsed: &Parsed,
    entry: u64,
    source_start: u64,
    expected_len: usize,
) -> Result<(), SetupRefusal> {
    if owner.pid != std::process::id()
        || expected_len != parsed.code.len()
        || stamp(&owner.file)? != owner.original
        || bounded_read(&mut owner.file)? != owner.expected
        || stamp(&owner.file)? != owner.original
        || mount_device(owner.file.as_raw_fd())? != owner.device
    {
        return Err(SetupRefusal::SourceBytes);
    }
    for load in &parsed.loads {
        let bias = entry - parsed.entry;
        let end = load.address + load.memory_size;
        let mut cursor = load.address;
        while cursor < end {
            let (next, permissions) = match &parsed.relro {
                Some(r) if cursor < r.start => (end.min(r.start), load_permissions(load.flags)?),
                Some(r) if cursor < r.end => {
                    if load.flags != 6 {
                        return Err(SetupRefusal::Format);
                    }
                    (end.min(r.end), "r--p")
                }
                _ => (end, load_permissions(load.flags)?),
            };
            map_rows(
                bias.checked_add(cursor).ok_or(SetupRefusal::Format)?,
                next - cursor,
                owner.device,
                owner.original.inode,
                Some(permissions),
                Some(load.offset + cursor - load.address),
            )?;
            cursor = next;
        }
    }
    if let Some(r) = &parsed.relro {
        let load = &parsed.loads[r.owner];
        let offset =
            u64::try_from(i128::from(load.offset) + i128::from(r.start) - i128::from(load.address))
                .map_err(|_| SetupRefusal::Format)?;
        let address = (entry - parsed.entry)
            .checked_add(r.start)
            .ok_or(SetupRefusal::Format)?;
        map_rows(
            address,
            r.end - r.start,
            owner.device,
            owner.original.inode,
            Some("r--p"),
            Some(offset),
        )?;
    }
    map_rows(
        source_start,
        parsed.source.len() as u64,
        owner.device,
        owner.original.inode,
        Some("r-xp"),
        Some(parsed.page_offset),
    )?;
    Ok(())
}

fn expected_source_page(
    parsed: &Parsed,
    entry: u64,
    source_start: u64,
    expected: &[u8],
    additional: Option<BodyOverlay<'_>>,
) -> Result<Vec<u8>, SetupRefusal> {
    let mut whole = parsed.source.clone();
    let at = usize::try_from(entry - source_start).map_err(|_| SetupRefusal::Format)?;
    whole
        .get_mut(at..at + expected.len())
        .ok_or(SetupRefusal::Format)?
        .copy_from_slice(expected);
    if let Some(body) = additional {
        let end = body
            .entry
            .checked_add(body.expected.len() as u64)
            .ok_or(SetupRefusal::Format)?;
        let first_end = entry
            .checked_add(expected.len() as u64)
            .ok_or(SetupRefusal::Format)?;
        if body.entry < first_end && entry < end {
            return Err(SetupRefusal::EntryExit);
        }
        let at = usize::try_from(
            body.entry
                .checked_sub(source_start)
                .ok_or(SetupRefusal::Format)?,
        )
        .map_err(|_| SetupRefusal::Format)?;
        let end = at
            .checked_add(body.expected.len())
            .ok_or(SetupRefusal::Format)?;
        whole
            .get_mut(at..end)
            .ok_or(SetupRefusal::Format)?
            .copy_from_slice(body.expected);
    }
    Ok(whole)
}

// The actual retained owner must keep this entire mapping readable. Endpoint
// provenance and a byte comparison cannot protect against forbidden unmapping.
unsafe fn verify_live_source(source_start: u64, whole: &[u8]) -> Result<(), SetupRefusal> {
    // SAFETY: the private caller holds the complete continuing mapping contract.
    if unsafe { std::slice::from_raw_parts(source_start as usize as *const u8, whole.len()) }
        != whole
    {
        return Err(SetupRefusal::SourceBytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
