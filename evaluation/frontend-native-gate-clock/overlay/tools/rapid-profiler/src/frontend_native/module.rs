//! Strict fixed-ELF admission. Successful loading retains its handle forever.
use object::{Object, ObjectSection, ObjectSymbol};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Fixed setup refusals; none is a replacement for required positive execution.
pub enum SetupRefusal {
    /// Whole file or complete declared instruction bytes differ.
    SourceBytes,
    /// A selected address is not owned by the exact loaded file/segment.
    SymbolOwner,
    /// The selected dynamic relocation or resulting pointer is not exact.
    Relocation,
    /// The complete five-head/one-exit subject grammar was not certified.
    EntryExit,
    /// The caller/kernel indicates an unsupported CET profile.
    Cet,
    /// A caller requests tail/nonlocal/foreign-unwind behavior outside this leaf.
    ExitSemantics,
    /// Bounded file/ELF/mapping/protection admission failed.
    Format,
    /// A syscall, file identity operation or normal dynamic-loader call failed.
    OperatingSystem,
}

#[derive(Clone, Copy)]
/// Explicit caller facts for this authored closed-world leaf, not discovery.
pub struct SubjectContract {
    /// Exact declared five original instruction-head offsets.
    pub heads: [u64; 5],
    /// Exact declared sole exit offset.
    pub exit: u64,
    /// Admits only the ordinary original RET path.
    pub ordinary_ret_only: bool,
    /// Caller certifies no active IBT; no attempt is made to disable protection.
    pub no_active_ibt: bool,
}
impl SubjectContract {
    /// The one fixed positive input. Its bytes are independently checked below.
    pub const LEAF: Self = Self {
        heads: [0, 5, 12, 15, 18],
        exit: 18,
        ordinary_ret_only: true,
        no_active_ibt: true,
    };
    fn check(self) -> Result<(), SetupRefusal> {
        if !self.ordinary_ret_only {
            return Err(SetupRefusal::ExitSemantics);
        }
        if !self.no_active_ibt {
            return Err(SetupRefusal::Cet);
        }
        if self.heads != [0, 5, 12, 15, 18] || self.exit != 18 {
            return Err(SetupRefusal::EntryExit);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Load {
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
    flags: u32,
}
struct Relro {
    start: u64,
    end: u64,
    owner: usize,
}
struct Elf {
    loads: Vec<Load>,
    entry: u64,
    invoke: u64,
    terminal: u64,
    pointer: u64,
    bias_value: u64,
    code: [u8; 19],
    relro: Relro,
}
fn u16_at(b: &[u8], p: usize) -> Result<u16, SetupRefusal> {
    Ok(u16::from_le_bytes(
        b.get(p..p + 2)
            .ok_or(SetupRefusal::Format)?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(b: &[u8], p: usize) -> Result<u32, SetupRefusal> {
    Ok(u32::from_le_bytes(
        b.get(p..p + 4)
            .ok_or(SetupRefusal::Format)?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(b: &[u8], p: usize) -> Result<u64, SetupRefusal> {
    Ok(u64::from_le_bytes(
        b.get(p..p + 8)
            .ok_or(SetupRefusal::Format)?
            .try_into()
            .unwrap(),
    ))
}
fn file_range(loads: &[Load], address: u64, len: usize) -> Result<usize, SetupRefusal> {
    let end = address
        .checked_add(len as u64)
        .ok_or(SetupRefusal::Format)?;
    let rows: Vec<_> = loads
        .iter()
        .filter(|r| address >= r.address && end <= r.address + r.file_size)
        .collect();
    if rows.len() != 1 {
        return Err(SetupRefusal::SymbolOwner);
    }
    usize::try_from(rows[0].offset + address - rows[0].address).map_err(|_| SetupRefusal::Format)
}
fn parse(bytes: &[u8]) -> Result<Elf, SetupRefusal> {
    if bytes.len() > 1024 * 1024
        || bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16_at(bytes, 16)? != 3
        || u16_at(bytes, 18)? != 62
        || u16_at(bytes, 54)? != 56
        || !(1..=16).contains(&u16_at(bytes, 56)?)
    {
        return Err(SetupRefusal::Format);
    }
    let phoff = usize::try_from(u64_at(bytes, 32)?).map_err(|_| SetupRefusal::Format)?;
    let mut loads = Vec::new();
    let mut relro_headers = Vec::new();
    for i in 0..usize::from(u16_at(bytes, 56)?) {
        let p = phoff.checked_add(i * 56).ok_or(SetupRefusal::Format)?;
        if u32_at(bytes, p)? == 0x6474_e552 {
            let start = u64_at(bytes, p + 16)?;
            let size = u64_at(bytes, p + 40)?;
            let end = start.checked_add(size).ok_or(SetupRefusal::Format)?;
            if size == 0 || size > 65536 {
                return Err(SetupRefusal::Format);
            }
            relro_headers.push((start, end));
        }
        if u32_at(bytes, p)? != 1 {
            continue;
        }
        let load = Load {
            flags: u32_at(bytes, p + 4)?,
            offset: u64_at(bytes, p + 8)?,
            address: u64_at(bytes, p + 16)?,
            file_size: u64_at(bytes, p + 32)?,
            memory_size: u64_at(bytes, p + 40)?,
        };
        if load.file_size == 0
            || load.memory_size < load.file_size
            || load.memory_size > 65536
            || load
                .offset
                .checked_add(load.file_size)
                .is_none_or(|n| n > bytes.len() as u64)
            || load.address.checked_add(load.memory_size).is_none()
            || load.flags & 3 == 3
            || load.flags & 4 == 0
        {
            return Err(SetupRefusal::Format);
        }
        loads.push(load);
    }
    if loads.len() != 4 {
        return Err(SetupRefusal::Format);
    }
    // The authored DSO has a unique read-only header page and one RELRO
    // interval inside a writable load. Reject any different geometry rather
    // than inferring a permissive mapping policy from current live mappings.
    if loads
        .iter()
        .filter(|r| r.address == 0 && r.offset == 0 && r.flags == 4 && r.memory_size <= 4096)
        .count()
        != 1
        || loads
            .iter()
            .any(|r| !matches!(r.flags, 4..=6) || r.offset % 4096 != r.address % 4096)
        || loads.iter().filter(|r| r.address < 4096).count() != 1
        || relro_headers.len() != 1
    {
        return Err(SetupRefusal::Format);
    }
    let (relro_address, relro_end) = relro_headers[0];
    let owners: Vec<_> = loads
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.flags == 6 && relro_address >= r.address && relro_end <= r.address + r.memory_size
        })
        .collect();
    if owners.len() != 1 {
        return Err(SetupRefusal::Format);
    }
    // glibc protects [page_floor(start), page_floor(end)). In particular, a
    // partial trailing page is not silently rounded up into RELRO coverage.
    let relro = Relro {
        start: relro_address & !4095,
        end: relro_end & !4095,
        owner: owners[0].0,
    };
    if relro.start >= relro.end
        || loads.iter().enumerate().any(|(i, r)| {
            i != relro.owner
                && (r.address & !4095) < relro.end
                && ((r.address + r.memory_size - 1) & !4095) >= relro.start
        })
    {
        return Err(SetupRefusal::Format);
    }
    let file = object::File::parse(bytes).map_err(|_| SetupRefusal::Format)?;
    if file.section_by_name(".note.gnu.property").is_some() {
        return Err(SetupRefusal::Cet);
    }
    // This closed fixture has no dependencies, constructors, destructors,
    // interposed calls, IFUNC, TEXTREL, RPATH or runtime code acquisition.
    let dynamic = file
        .section_by_name(".dynamic")
        .ok_or(SetupRefusal::Format)?;
    let dynamic = dynamic.data().map_err(|_| SetupRefusal::Format)?;
    if dynamic.is_empty() || dynamic.len() > 4096 || dynamic.len() % 16 != 0 {
        return Err(SetupRefusal::Format);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut ended = false;
    let mut bind_now = false;
    for row in dynamic.chunks_exact(16) {
        let tag = u64_at(row, 0)?;
        let value = u64_at(row, 8)?;
        if tag == 0 {
            if value != 0 {
                return Err(SetupRefusal::Format);
            }
            ended = true;
        } else if ended
            || !seen.insert(tag)
            || !matches!(
                tag,
                4..=11 | 14 | 16 | 24 | 30 | 0x6fff_fef5 | 0x6fff_fff9 | 0x6fff_fffb
            )
            || (tag == 16 && value != 0)
            || (tag == 24 && value != 0)
            || (tag == 30 && value & !10 != 0)
            || (tag == 0x6fff_fffb && value & !1 != 0)
        {
            return Err(SetupRefusal::Format);
        }
        // DT_BIND_NOW has no payload. Either it or an allowed NOW flag
        // requires eager binding; zero FLAGS values alone do not establish it.
        bind_now |=
            tag == 24 || (tag == 30 && value & 8 != 0) || (tag == 0x6fff_fffb && value & 1 != 0);
    }
    if !ended || !bind_now {
        return Err(SetupRefusal::Format);
    }
    let symbol = |name: &str, size: u64| -> Result<u64, SetupRefusal> {
        let rows: Vec<_> = file
            .symbols()
            .filter(|s| s.name() == Ok(name) && s.is_definition())
            .collect();
        if rows.len() != 1 || rows[0].size() != size {
            return Err(SetupRefusal::SymbolOwner);
        }
        Ok(rows[0].address())
    };
    let entry = symbol("interval_leaf", 19)?;
    let invoke = symbol("interval_invoke", 5)?;
    let terminal = symbol("interval_terminal", 1)?;
    let pointer = symbol("interval_bias_pointer", 8)?;
    let bias_value = symbol("interval_bias", 8)?;
    if file.symbols().any(|s| {
        s.is_definition()
            && (entry..entry + 19).contains(&s.address())
            && s.name() != Ok("interval_leaf")
    }) {
        return Err(SetupRefusal::EntryExit);
    }
    let functions: Vec<_> = file
        .dynamic_symbols()
        .filter(|s| s.is_definition() && s.kind() == object::SymbolKind::Text)
        .map(|s| s.name().map(str::to_string))
        .collect::<Result<_, _>>()
        .map_err(|_| SetupRefusal::Format)?;
    if functions.len() != 3
        || !functions.iter().any(|s| s == "interval_leaf")
        || !functions.iter().any(|s| s == "interval_invoke")
        || !functions.iter().any(|s| s == "interval_terminal")
    {
        return Err(SetupRefusal::SymbolOwner);
    }
    if entry % 4096 == 0
        || entry % 16 != 0
        || entry / 4096 != terminal / 4096
        || terminal != invoke + 5
        || invoke < entry + 19
    {
        return Err(SetupRefusal::SymbolOwner);
    }
    for pc in [entry, entry + 18, invoke, terminal] {
        if loads
            .iter()
            .filter(|r| r.flags == 5 && pc >= r.address && pc < r.address + r.file_size)
            .count()
            != 1
        {
            return Err(SetupRefusal::SymbolOwner);
        }
    }
    let p = file_range(&loads, entry, 19)?;
    let call = file_range(&loads, invoke, 5)?;
    let call_bytes = bytes.get(call..call + 5).ok_or(SetupRefusal::SourceBytes)?;
    if call_bytes[0] != 0xe8
        || i128::from(invoke)
            + 5
            + i128::from(i32::from_le_bytes(call_bytes[1..].try_into().unwrap()))
            != i128::from(entry)
    {
        return Err(SetupRefusal::SourceBytes);
    }
    if bytes[file_range(&loads, terminal, 1)?] != 0xcc {
        return Err(SetupRefusal::SourceBytes);
    }
    let code: [u8; 19] = bytes
        .get(p..p + 19)
        .ok_or(SetupRefusal::SourceBytes)?
        .try_into()
        .unwrap();
    if code[..8] != [0x48, 0x8d, 0x44, 0x7f, 0x07, 0x4c, 0x8b, 0x15]
        || code[12..] != [0x49, 0x03, 0x02, 0x48, 0x89, 0x06, 0xc3]
    {
        return Err(SetupRefusal::SourceBytes);
    }
    let displacement = i32::from_le_bytes(code[8..12].try_into().unwrap());
    if i128::from(entry) + 12 + i128::from(displacement) != i128::from(pointer)
        || u64_at(bytes, file_range(&loads, bias_value, 8)?)? != 11
    {
        return Err(SetupRefusal::Relocation);
    }
    let rela = file
        .section_by_name(".rela.dyn")
        .ok_or(SetupRefusal::Relocation)?;
    let data = rela.data().map_err(|_| SetupRefusal::Relocation)?;
    if data.len() != 24
        || u64_at(data, 0)? != pointer
        || u64_at(data, 8)? != 8
        || u64_at(data, 16)? != bias_value
        || file.section_by_name(".rela.plt").is_some()
    {
        return Err(SetupRefusal::Relocation);
    }
    Ok(Elf {
        loads,
        entry,
        invoke,
        terminal,
        pointer,
        bias_value,
        code,
        relro,
    })
}

fn bounded_read(file: &mut File) -> Result<Vec<u8>, SetupRefusal> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SetupRefusal::OperatingSystem)?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SetupRefusal::OperatingSystem)?;
    if bytes.len() > 1024 * 1024 {
        return Err(SetupRefusal::Format);
    }
    Ok(bytes)
}

/// A live ld.so-owned leaf. Successful handles and their original file are
/// intentionally pinned forever; no Drop implementation calls dlclose.
pub struct LoadedLeaf {
    _handle: *mut libc::c_void,
    file: File,
    expected: Vec<u8>,
    elf: Elf,
    bias: u64,
    entry: u64,
    terminal: u64,
    map_device: (u32, u32),
    inode: u64,
    file_device: u64,
    original_page: Vec<u8>,
}
impl LoadedLeaf {
    /// Authenticate the complete file and fixed grammar, then normally load it.
    ///
    /// # Safety
    /// The caller certifies no active IBT and no foreign subject callers, signal
    /// entries or saved execution contexts; the input is the fixed authored DSO.
    /// `expected` must be pinned independently before this call, not reread from
    /// the candidate and accepted as its own authority.
    pub unsafe fn load(
        path: &Path,
        expected: &[u8],
        contract: SubjectContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        let mut shstk = 0_u64;
        // SAFETY: Linux read-only ARCH_SHSTK_STATUS, never disables protection.
        let result = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut shstk) };
        if result == 0 && shstk != 0 {
            return Err(SetupRefusal::Cet);
        }
        if result != 0
            && !matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL | libc::ENOSYS)
            )
        {
            return Err(SetupRefusal::OperatingSystem);
        }
        let mut file = File::open(path).map_err(|_| SetupRefusal::OperatingSystem)?;
        let bytes = bounded_read(&mut file)?;
        if bytes != expected {
            return Err(SetupRefusal::SourceBytes);
        }
        let elf = parse(&bytes)?;
        let metadata = file.metadata().map_err(|_| SetupRefusal::OperatingSystem)?;
        if !metadata.is_file() || metadata.len() != bytes.len() as u64 {
            return Err(SetupRefusal::SourceBytes);
        }
        let map_device = mount_device(file.as_raw_fd())?;
        let fd_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        // SAFETY: authenticated closed fixture; libc normal loader owns mappings.
        let handle = unsafe { libc::dlopen(fd_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(SetupRefusal::OperatingSystem);
        }
        // From this point the handle is retained even on refusal: no unmap race.
        let symbol = |name: &'static CStr| -> Result<u64, SetupRefusal> {
            let p = unsafe { libc::dlsym(handle, name.as_ptr()) };
            if p.is_null() {
                return Err(SetupRefusal::SymbolOwner);
            }
            Ok(p as usize as u64)
        };
        let entry = symbol(c"interval_leaf")?;
        let terminal = symbol(c"interval_terminal")?;
        let bias = entry
            .checked_sub(elf.entry)
            .ok_or(SetupRefusal::SymbolOwner)?;
        if bias % 4096 != 0 || terminal != bias + elf.terminal {
            return Err(SetupRefusal::SymbolOwner);
        }
        // SAFETY: initialized dladdr output and live admitted address.
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        if unsafe { libc::dladdr(entry as usize as *const libc::c_void, &mut info) } == 0
            || info.dli_fbase as usize as u64 != bias
            || info.dli_saddr as usize as u64 != entry
            || info.dli_sname.is_null()
            || unsafe { CStr::from_ptr(info.dli_sname) } != c"interval_leaf"
        {
            return Err(SetupRefusal::SymbolOwner);
        }
        // RTLD_DI_LINKMAP l_addr is the first ABI field of link_map.
        let mut link_map: *const u64 = std::ptr::null();
        if unsafe { libc::dlinfo(handle, 2, (&raw mut link_map).cast()) } != 0
            || link_map.is_null()
            || unsafe { link_map.read() } != bias
        {
            return Err(SetupRefusal::SymbolOwner);
        }
        let page = entry & !4095;
        let original_page =
            unsafe { std::slice::from_raw_parts(page as usize as *const u8, 4096) }.to_vec();
        let leaf = Box::leak(Box::new(Self {
            _handle: handle,
            file,
            expected: bytes,
            elf,
            bias,
            entry,
            terminal,
            map_device,
            inode: metadata.ino(),
            file_device: metadata.dev(),
            original_page,
        }));
        leaf.verify(false)?;
        Ok(leaf)
    }
    /// Real loaded entry, never an anonymous copy.
    pub fn entry(&self) -> u64 {
        self.entry
    }
    /// Certified actual return target within the same pinned executable page.
    pub fn terminal(&self) -> u64 {
        self.terminal
    }
    /// Exact five-byte direct CALL which produces that real return word.
    pub fn invoke(&self) -> u64 {
        self.bias + self.elf.invoke
    }
    /// Page containing the exact source, for the closed quiescent fixture only.
    pub fn page(&self) -> u64 {
        self.entry & !4095
    }
    /// Original linked instruction bytes, derived before any execution.
    pub fn code(&self) -> &[u8; 19] {
        &self.elf.code
    }
    /// Original full source page, including all bytes outside the selected body.
    pub fn original_page(&self) -> &[u8] {
        &self.original_page
    }
    /// Exact static source address of the loader-resolved bias pointer.
    pub fn pointer(&self) -> u64 {
        self.bias + self.elf.pointer
    }
    /// Exact source address of the immutable bias object.
    pub fn bias_object(&self) -> u64 {
        self.bias + self.elf.bias_value
    }
    /// Authenticated read-only ELF header page, for isolated permission controls.
    /// It is disjoint from the executable page and the unique RELRO interval.
    pub fn header_page(&self) -> u64 {
        self.bias
    }
    /// Authenticate caller-selected source/relocation facts without publishing.
    /// This is also the exact seam used by the fixed before-write refusals.
    pub fn admit(
        &self,
        entry: u64,
        pointer_value: u64,
        contract: SubjectContract,
    ) -> Result<(), SetupRefusal> {
        contract.check()?;
        if entry != self.entry {
            return Err(SetupRefusal::SymbolOwner);
        }
        if pointer_value != self.bias_object()
            || unsafe { (self.pointer() as usize as *const u64).read_unaligned() } != pointer_value
        {
            return Err(SetupRefusal::Relocation);
        }
        Ok(())
    }
    /// Exact readable file-backed non-code extents, each authenticated to this
    /// fd/loaded bias. The oracle compares every byte throughout execution.
    pub fn immutable_extents(&self) -> Vec<(u64, usize)> {
        self.elf
            .loads
            .iter()
            .filter(|r| r.flags & 1 == 0)
            .map(|r| (self.bias + r.address, r.file_size as usize))
            .collect()
    }
    /// A private identity record, retaining both VFS and mapping-device domains.
    pub fn identity_record(&self) -> String {
        format!(
            "{{\"file_device\":{},\"inode\":{},\"map_major\":{},\"map_minor\":{},\"load_bias\":{},\"entry\":{},\"invoke\":{},\"terminal\":{},\"pointer\":{},\"bias_object\":{},\"file_bytes\":{}}}\n",
            self.file_device,
            self.inode,
            self.map_device.0,
            self.map_device.1,
            self.bias,
            self.entry,
            self.invoke(),
            self.terminal,
            self.pointer(),
            self.bias_object(),
            self.expected.len()
        )
    }
    /// Authenticate file/fd and every selected live loader value again.
    pub fn verify(&mut self, patched: bool) -> Result<(), SetupRefusal> {
        let meta = self
            .file
            .metadata()
            .map_err(|_| SetupRefusal::OperatingSystem)?;
        if meta.ino() != self.inode
            || meta.dev() != self.file_device
            || meta.len() != self.expected.len() as u64
            || bounded_read(&mut self.file)? != self.expected
            || mount_device(self.file.as_raw_fd())? != self.map_device
        {
            return Err(SetupRefusal::SourceBytes);
        }
        verify_mapping(self.entry, 19, self.map_device, self.inode, "r-xp")?;
        verify_mapping(self.pointer(), 8, self.map_device, self.inode, "r--p")?;
        verify_mapping(self.bias_object(), 8, self.map_device, self.inode, "r--p")?;
        if unsafe { (self.pointer() as usize as *const u64).read_unaligned() } != self.bias_object()
            || unsafe { (self.bias_object() as usize as *const u64).read_unaligned() } != 11
        {
            return Err(SetupRefusal::Relocation);
        }
        if !patched
            && unsafe { std::slice::from_raw_parts(self.page() as usize as *const u8, 4096) }
                != self.original_page
        {
            return Err(SetupRefusal::SourceBytes);
        }
        // Every declared load has an owned, nonempty file range. Code mutation
        // is authenticated separately against the exact publication edit.
        for load in &self.elf.loads {
            let address = self
                .bias
                .checked_add(load.address)
                .ok_or(SetupRefusal::Format)?;
            verify_mapping_owner(
                address,
                load.file_size,
                self.map_device,
                self.inode,
                load.offset,
            )?;
            self.verify_load_permissions(load)?;
        }
        // Cover the complete protected pages, including the leading page bytes
        // before the declared writable load's first byte. Preserve the exact
        // file offset and mapping owner, not just r--p at the pointer object.
        let relro = &self.elf.relro;
        let owner = &self.elf.loads[relro.owner];
        let offset = u64::try_from(
            i128::from(owner.offset) + i128::from(relro.start) - i128::from(owner.address),
        )
        .map_err(|_| SetupRefusal::Format)?;
        map_rows(
            self.bias
                .checked_add(relro.start)
                .ok_or(SetupRefusal::Format)?,
            relro.end - relro.start,
            self.map_device,
            self.inode,
            Some("r--p"),
            Some(offset),
        )?;
        Ok(())
    }
    fn verify_load_permissions(&self, load: &Load) -> Result<(), SetupRefusal> {
        let mut cursor = load.address;
        let end = load
            .address
            .checked_add(load.memory_size)
            .ok_or(SetupRefusal::Format)?;
        let relro = &self.elf.relro;
        while cursor < end {
            let (next, permissions) = if cursor < relro.start {
                (end.min(relro.start), load_permissions(load.flags)?)
            } else if cursor < relro.end {
                if load.flags != 6 {
                    return Err(SetupRefusal::Format);
                }
                (end.min(relro.end), "r--p")
            } else {
                (end, load_permissions(load.flags)?)
            };
            // Each segment is nonempty and their union is the entire p_memsz
            // extent. A non-file-backed/foreign tail is a refusal in this fixed
            // DSO, not a new anonymous-owner exemption.
            verify_mapping(
                self.bias.checked_add(cursor).ok_or(SetupRefusal::Format)?,
                next - cursor,
                self.map_device,
                self.inode,
                permissions,
            )?;
            cursor = next;
        }
        Ok(())
    }
}

fn load_permissions(flags: u32) -> Result<&'static str, SetupRefusal> {
    match flags {
        4 => Ok("r--p"),
        5 => Ok("r-xp"),
        6 => Ok("rw-p"),
        _ => Err(SetupRefusal::Format),
    }
}

fn bounded_text(path: &str, bound: u64) -> Result<String, SetupRefusal> {
    let file = File::open(path).map_err(|_| SetupRefusal::OperatingSystem)?;
    let mut text = String::new();
    file.take(bound + 1)
        .read_to_string(&mut text)
        .map_err(|_| SetupRefusal::OperatingSystem)?;
    if text.len() as u64 > bound {
        return Err(SetupRefusal::Format);
    }
    Ok(text)
}
fn mount_device(fd: i32) -> Result<(u32, u32), SetupRefusal> {
    let info = bounded_text(&format!("/proc/self/fdinfo/{fd}"), 4096)?;
    let ids: Vec<_> = info
        .lines()
        .filter_map(|l| l.strip_prefix("mnt_id:\t"))
        .collect();
    if ids.len() != 1 {
        return Err(SetupRefusal::SymbolOwner);
    }
    let table = bounded_text("/proc/self/mountinfo", 1024 * 1024)?;
    let rows: Vec<_> = table
        .lines()
        .filter(|l| l.split_whitespace().next() == Some(ids[0]))
        .collect();
    if rows.len() != 1 {
        return Err(SetupRefusal::SymbolOwner);
    }
    let field = rows[0]
        .split_whitespace()
        .nth(2)
        .ok_or(SetupRefusal::Format)?;
    let (major, minor) = field.split_once(':').ok_or(SetupRefusal::Format)?;
    Ok((
        major.parse().map_err(|_| SetupRefusal::Format)?,
        minor.parse().map_err(|_| SetupRefusal::Format)?,
    ))
}
fn map_rows(
    address: u64,
    length: u64,
    device: (u32, u32),
    inode: u64,
    permissions: Option<&str>,
    file_offset: Option<u64>,
) -> Result<(), SetupRefusal> {
    let end = address.checked_add(length).ok_or(SetupRefusal::Format)?;
    let maps = bounded_text("/proc/self/maps", 1024 * 1024)?;
    let mut covered = address;
    for line in maps.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() < 5 {
            return Err(SetupRefusal::Format);
        }
        let (low, high) = f[0].split_once('-').ok_or(SetupRefusal::Format)?;
        let low = u64::from_str_radix(low, 16).map_err(|_| SetupRefusal::Format)?;
        let high = u64::from_str_radix(high, 16).map_err(|_| SetupRefusal::Format)?;
        if high <= covered || low >= end {
            continue;
        }
        let (major, minor) = f[3].split_once(':').ok_or(SetupRefusal::Format)?;
        let actual = (
            u32::from_str_radix(major, 16).map_err(|_| SetupRefusal::Format)?,
            u32::from_str_radix(minor, 16).map_err(|_| SetupRefusal::Format)?,
        );
        if low > covered
            || actual != device
            || f[4].parse::<u64>().map_err(|_| SetupRefusal::Format)? != inode
            || permissions.is_some_and(|p| p != f[1])
        {
            return Err(SetupRefusal::SymbolOwner);
        }
        if let Some(offset) = file_offset {
            let mapped_offset = u64::from_str_radix(f[2], 16).map_err(|_| SetupRefusal::Format)?;
            if mapped_offset + covered - low != offset + covered - address {
                return Err(SetupRefusal::SymbolOwner);
            }
        }
        covered = high.min(end);
        if covered == end {
            return Ok(());
        }
    }
    Err(SetupRefusal::SymbolOwner)
}
fn verify_mapping(
    address: u64,
    length: u64,
    device: (u32, u32),
    inode: u64,
    permissions: &str,
) -> Result<(), SetupRefusal> {
    map_rows(address, length, device, inode, Some(permissions), None)
}
fn verify_mapping_owner(
    address: u64,
    length: u64,
    device: (u32, u32),
    inode: u64,
    offset: u64,
) -> Result<(), SetupRefusal> {
    map_rows(address, length, device, inode, None, Some(offset))
}

#[cfg(test)]
#[path = "module_tests.rs"]
mod tests;
