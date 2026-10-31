//! Fixture-only retained-FD loading, never native or CFI qualification.
//! All immutable LOAD bytes are checked, including the active PHDR/CFI/index.
//! Writable LOADs remain distinct: relocation/global bytes are not file equality.

use formats::ContentId;
use liteinst_rewrite::carrier::elf64::{
    Elf64, FileOffset, ObjectType, ParseLimits, SegmentType, Storage,
};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Read,
    marker::PhantomData,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    rc::Rc,
    thread::ThreadId,
};

pub const BYTE_LIMIT: u64 = 16 * 1024 * 1024;
const PAGE: u64 = 4096;
const MAP_LIMIT: usize = 2 * 1024 * 1024;
const ROW_LIMIT: usize = 65536;
const GNU_EH_FRAME: SegmentType = SegmentType::Other(0x6474_e550);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Io(std::io::ErrorKind),
    Elf(liteinst_rewrite::carrier::elf64::Error),
    Identity,
    Bounds,
    Format,
    Ownership,
    Mapping,
    Loader,
}
type Result<T> = std::result::Result<T, Error>;
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<liteinst_rewrite::carrier::elf64::Error> for Error {
    fn from(e: liteinst_rewrite::carrier::elf64::Error) -> Self {
        Self::Elf(e)
    }
}
fn require(ok: bool, error: Error) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(Error::Bounds)
}
fn page_end(end: u64) -> Result<u64> {
    Ok(add(end, PAGE - 1)? & !(PAGE - 1))
}

/// Explicit code/CFI/index requirements from the separately admitted artifact.
/// Coordinates carry no instruction-entry, hook or unwind semantic authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImmutableRange {
    pub address: u64,
    pub length: u64,
    pub executable: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Load {
    pub address: u64,
    pub offset: u64,
    pub file_bytes: u64,
    pub memory_bytes: u64,
    pub flags: u32,
}

pub struct BoundImage {
    bytes: Vec<u8>,
    identity: ContentId,
    loads: Vec<Load>,
    required: Vec<ImmutableRange>,
}
impl BoundImage {
    /// `identity` is independently expected, not a hash trusted from this file.
    /// Parse actual LOADs; never accept a caller-invented mapping inventory.
    pub fn new(expected: &[u8], identity: ContentId, required: &[ImmutableRange]) -> Result<Self> {
        require(
            expected.len() as u64 <= BYTE_LIMIT && required.len() <= 4096,
            Error::Bounds,
        )?;
        require(ContentId::of(expected) == identity, Error::Identity)?;
        let elf = Elf64::parse(
            expected,
            ParseLimits {
                max_program_headers: 4096,
            },
        )?;
        require(
            elf.header().object_type == ObjectType::Dynamic && elf.header().entry.0 == 0,
            Error::Format,
        )?;
        elf.check_load_page_congruence(PAGE)?;
        let mut loads = Vec::new();
        let (mut mapped, mut previous_end) = (0, 0);
        for p in elf.segments(SegmentType::Load) {
            require(
                p.memory_size != 0 && matches!(p.flags.0, 4..=6),
                Error::Ownership,
            )?;
            let begin = p.vaddr.0 & !(PAGE - 1);
            let end = page_end(add(p.vaddr.0, p.memory_size)?)?;
            require(loads.is_empty() || begin >= previous_end, Error::Ownership)?;
            mapped = add(mapped, end - begin)?;
            require(mapped <= BYTE_LIMIT, Error::Bounds)?;
            previous_end = end;
            if !p.flags.writable() {
                require(p.file_size == p.memory_size, Error::Ownership)?;
            }
            if p.file_size != 0 {
                let inverse = elf.file_to_virtual(p.offset, p.file_size)?;
                require(
                    inverse.program_header == p.index && inverse.virtual_range.start() == p.vaddr,
                    Error::Ownership,
                )?;
            }
            loads.push(Load {
                address: p.vaddr.0,
                offset: p.offset.0,
                file_bytes: p.file_size,
                memory_bytes: p.memory_size,
                flags: p.flags.0,
            });
        }
        require(
            !loads.is_empty() && loads.iter().any(|p| p.flags == 5),
            Error::Ownership,
        )?;
        require(
            previous_end - (loads[0].address & !(PAGE - 1)) <= BYTE_LIMIT,
            Error::Bounds,
        )?;
        let immutable_file = |offset, length| -> Result<()> {
            let mapping = elf.file_to_virtual(FileOffset(offset), length)?;
            require(mapping.flags.0 == 4, Error::Ownership)
        };
        immutable_file(0, 64)?;
        immutable_file(
            elf.header().program_offset.0,
            u64::from(elf.header().program_count) * 56,
        )?;
        let indexes: Vec<_> = elf.segments(GNU_EH_FRAME).collect();
        require(indexes.len() == 1, Error::Ownership)?;
        let index = indexes[0];
        require(
            index.flags.0 == 4 && index.file_size != 0 && index.file_size == index.memory_size,
            Error::Ownership,
        )?;
        let owner = elf.virtual_to_storage(index.vaddr, index.file_size)?;
        require(
            owner.flags.0 == 4 && owner.storage == Storage::FileBacked(index.file_range()?),
            Error::Ownership,
        )?;
        immutable_file(index.offset.0, index.file_size)?;
        let result = Self {
            bytes: expected.to_vec(),
            identity,
            loads,
            required: required.to_vec(),
        };
        for &range in required {
            result.owner(range)?;
        }
        Ok(result)
    }
    fn owner(&self, range: ImmutableRange) -> Result<&Load> {
        let end = add(range.address, range.length)?;
        require(range.length != 0, Error::Bounds)?;
        self.loads
            .iter()
            .find(|p| {
                p.flags == if range.executable { 5 } else { 4 }
                    && p.address <= range.address
                    && end <= p.address + p.file_bytes
            })
            .ok_or(Error::Ownership)
    }
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    /// Includes writable LOADs, without a live-byte-equality assertion for them.
    pub fn loads(&self) -> &[Load] {
        &self.loads
    }
    pub fn required(&self) -> &[ImmutableRange] {
        &self.required
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    bytes: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn stamp(file: &File) -> Result<Stamp> {
    let m = file.metadata()?;
    require(m.is_file() && m.len() <= BYTE_LIMIT, Error::Bounds)?;
    Ok(Stamp {
        device: m.dev(),
        inode: m.ino(),
        bytes: m.len(),
        mode: m.mode(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}
fn open(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?)
}
fn file_matches(file: &File, original: Stamp, bytes: &[u8]) -> Result<()> {
    require(
        stamp(file)? == original && original.bytes == bytes.len() as u64,
        Error::Identity,
    )?;
    let mut actual = vec![0; bytes.len()];
    file.read_exact_at(&mut actual, 0)?;
    require(actual == bytes && stamp(file)? == original, Error::Identity)
}
fn text(path: &str, cap: usize) -> Result<String> {
    let mut value = String::new();
    open(Path::new(path))?
        .take(cap as u64 + 1)
        .read_to_string(&mut value)?;
    require(value.len() <= cap, Error::Bounds)?;
    Ok(value)
}
fn device(file: &File, expected_inode: u64) -> Result<(u32, u32)> {
    let info = text(&format!("/proc/self/fdinfo/{}", file.as_raw_fd()), 4096)?;
    let field = |name: &str| -> Result<u64> {
        let rows: Vec<_> = info
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| *k == name)
            .collect();
        require(rows.len() == 1, Error::Ownership)?;
        rows[0].1.trim().parse().map_err(|_| Error::Format)
    };
    require(field("ino")? == expected_inode, Error::Identity)?;
    let id = field("mnt_id")?;
    require(id != 0, Error::Ownership)?;
    let mounts = text("/proc/self/mountinfo", MAP_LIMIT)?;
    let rows: Vec<_> = mounts
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                == Some(id)
        })
        .collect();
    require(rows.len() == 1, Error::Ownership)?;
    let (a, b) = rows[0]
        .split_whitespace()
        .nth(2)
        .and_then(|s| s.split_once(':'))
        .ok_or(Error::Format)?;
    Ok((
        a.parse().map_err(|_| Error::Format)?,
        b.parse().map_err(|_| Error::Format)?,
    ))
}

#[derive(Debug)]
struct Map {
    start: u64,
    end: u64,
    offset: u64,
    device: (u32, u32),
    inode: u64,
    permissions: [u8; 4],
}
fn maps(text: &str) -> Result<Vec<Map>> {
    require(text.len() <= MAP_LIMIT, Error::Bounds)?;
    let mut result: Vec<Map> = Vec::new();
    for line in text.lines() {
        require(result.len() < ROW_LIMIT, Error::Bounds)?;
        let mut fields = line.split_whitespace();
        let mut next = || fields.next().ok_or(Error::Format);
        let hex = |s| u64::from_str_radix(s, 16).map_err(|_| Error::Format);
        let (lo, hi) = next()?.split_once('-').ok_or(Error::Format)?;
        let (start, end) = (hex(lo)?, hex(hi)?);
        let permissions: [u8; 4] = next()?.as_bytes().try_into().map_err(|_| Error::Format)?;
        require(
            matches!(permissions[0], b'r' | b'-')
                && matches!(permissions[1], b'w' | b'-')
                && matches!(permissions[2], b'x' | b'-')
                && matches!(permissions[3], b'p' | b's'),
            Error::Format,
        )?;
        let offset = hex(next()?)?;
        let (major, minor) = next()?.split_once(':').ok_or(Error::Format)?;
        let device = (
            u32::from_str_radix(major, 16).map_err(|_| Error::Format)?,
            u32::from_str_radix(minor, 16).map_err(|_| Error::Format)?,
        );
        let inode = next()?.parse().map_err(|_| Error::Format)?;
        require(
            start < end
                && start % PAGE == 0
                && end % PAGE == 0
                && offset % PAGE == 0
                && result.last().is_none_or(|old| old.end <= start),
            Error::Mapping,
        )?;
        result.push(Map {
            start,
            end,
            offset,
            device,
            inode,
            permissions,
        });
    }
    require(!result.is_empty(), Error::Mapping)?;
    Ok(result)
}
fn mapping(
    rows: &[Map],
    start: u64,
    length: u64,
    offset: u64,
    permissions: [u8; 4],
    dev: (u32, u32),
    inode: u64,
) -> Result<()> {
    let end = add(start, length)?;
    require(length != 0 && inode != 0, Error::Mapping)?;
    let mut covered = start;
    for row in rows {
        if row.end <= covered || row.start >= end {
            continue;
        }
        require(
            row.start <= covered
                && row.permissions == permissions
                && row.device == dev
                && row.inode == inode,
            Error::Mapping,
        )?;
        require(
            add(row.offset, covered - row.start)? == add(offset, covered - start)?,
            Error::Mapping,
        )?;
        covered = row.end.min(end);
        if covered == end {
            return Ok(());
        }
    }
    Err(Error::Mapping)
}

struct Retained {
    file: File,
    path: PathBuf,
    image: BoundImage,
    stamp: Stamp,
    device: (u32, u32),
    handle: *mut libc::c_void,
    pid: u32,
    thread: ThreadId,
}
/// No Drop/dlclose, transferable owner or callable function pointer is supplied.
/// Failed post-load admissions retain the descriptor/bytes/handle to process exit.
pub struct Loaded {
    retained: &'static Retained,
    bias: u64,
    _local: PhantomData<Rc<()>>,
}
impl Loaded {
    /// # Safety
    /// The caller independently owns this complete compiler/link/CRT/dependency
    /// graph, including loader initialization, relocation/resolver effects and
    /// exact source/hook/CFI/entry semantics. These are not proved by a receipt,
    /// hash, zero entry or dlopen flags. No unadmitted interposition/preload/audit,
    /// constructor/registration path or resolver is permitted. All required
    /// code, PHDR, original/generated CFI/index ranges are supplied and immutable;
    /// loader writes stay exclusively in separately admitted writable LOADs.
    /// The loader, libc and dependencies are trusted process-lived owners.
    /// The original file/path and all mappings/permissions remain immutable;
    /// no alias writer, mprotect, split/merge, unmap, unload, fork or competing
    /// loader action occurs. A single controlled thread owns all operations;
    /// no signal handler, cancellation, longjmp or reentry can invalidate them.
    /// Actual CPU/XCR0/CET/stack and later call/consumer/ABI admission remain
    /// separate requirements. These premises persist even after Err or panic.
    pub unsafe fn open(path: &Path, image: BoundImage) -> Result<Self> {
        require(
            path.is_absolute() && std::fs::canonicalize(path)? == path,
            Error::Identity,
        )?;
        // SAFETY: read-only platform query; this fixture supports 4 KiB pages.
        require(
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) } == PAGE as libc::c_long,
            Error::Format,
        )?;
        let file = open(path)?;
        let original = stamp(&file)?;
        file_matches(&file, original, &image.bytes)?;
        let dev = device(&file, original.inode)?;
        let fd_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| Error::Format)?;
        // Retain before dlopen. No later Rust refusal can close its original fd.
        let retained = Box::leak(Box::new(Retained {
            file,
            path: path.to_path_buf(),
            image,
            stamp: original,
            device: dev,
            handle: std::ptr::null_mut(),
            pid: std::process::id(),
            thread: std::thread::current().id(),
        }));
        // SAFETY: complete unsafe load contract above; no selected call here.
        retained.handle = unsafe {
            libc::dlopen(
                fd_path.as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_NODELETE,
            )
        };
        require(!retained.handle.is_null(), Error::Loader)?;
        let result = Self {
            bias: bias(retained.handle)?,
            retained,
            _local: PhantomData,
        };
        result.verify()?;
        Ok(result)
    }
    pub const fn identity(&self) -> ContentId {
        self.retained.image.identity
    }
    pub const fn load_bias(&self) -> u64 {
        self.bias
    }
    pub fn image(&self) -> &BoundImage {
        &self.retained.image
    }
    /// Checked immutable ELF coordinates only; not symbol or invocation authority.
    pub fn address(&self, range: ImmutableRange) -> Result<u64> {
        self.retained.image.owner(range)?;
        runtime(self.bias, range.address, range.length)
    }
    /// Read one fixed return-capture cell from a retained writable file page.
    /// File-backed data and the final zero-filled file-page tail are distinct
    /// checked profiles. Anonymous BSS pages are refused.
    /// The separate symbol/code proof must identify the intended 64-byte object
    /// and its eight stores; this method establishes its live storage only.
    /// The controlled-thread/no-handler/no-alias-writer contract of open() must
    /// hold, and the fixture invocation must have returned before this read.
    pub fn raw_return_words(&self, address: u64) -> Result<[u64; 8]> {
        self.verify()?;
        let p = raw_capture_owner(&self.retained.image.loads, address)?;
        let start = runtime(self.bias, address, 64)?;
        let offset = add(p.offset, address - p.address)?;
        let rows = maps(&text("/proc/self/maps", MAP_LIMIT)?)?;
        mapping(
            &rows,
            start,
            64,
            offset,
            *b"rw-p",
            self.retained.device,
            self.retained.stamp.inode,
        )?;
        // SAFETY: exact 64-byte aligned live writable-page ownership above,
        // continuous mapping and single-writer contract retained by open().
        // Every bit pattern of these eight integers is valid; compare all words
        // independently after reading. This never compares mutable BSS to file.
        let words = unsafe { (start as usize as *const [u64; 8]).read_volatile() };
        Ok(words)
    }
    /// Read an aligned resolved GOT word from its retained file owner. RELRO
    /// may make it read-only. Its value is checked against the actual qualified
    /// consumer separately; immutable file equality never applies here.
    pub fn relocated_word(&self, address: u64) -> Result<u64> {
        self.verify()?;
        require(address % 8 == 0, Error::Bounds)?;
        let end = add(address, 8)?;
        let p = self
            .retained
            .image
            .loads
            .iter()
            .find(|p| p.flags == 6 && p.address <= address && end <= p.address + p.file_bytes)
            .ok_or(Error::Ownership)?;
        let start = runtime(self.bias, address, 8)?;
        let offset = add(p.offset, address - p.address)?;
        let rows = maps(&text("/proc/self/maps", MAP_LIMIT)?)?;
        let owner = rows
            .iter()
            .find(|r| r.start <= start && start + 8 <= r.end)
            .ok_or(Error::Mapping)?;
        require(
            matches!(&owner.permissions, b"r--p" | b"rw-p"),
            Error::Mapping,
        )?;
        mapping(
            &rows,
            start,
            8,
            offset,
            owner.permissions,
            self.retained.device,
            self.retained.stamp.inode,
        )?;
        // SAFETY: retained inode/offset/range and continuous no-writer mapping
        // contract. Integer reads do not assume that the word is callable.
        Ok(unsafe { (start as usize as *const u64).read_volatile() })
    }
    /// Boundary observation, not a lock against forbidden concurrent changes.
    pub fn verify(&self) -> Result<()> {
        let r = self.retained;
        require(
            r.pid == std::process::id() && r.thread == std::thread::current().id(),
            Error::Ownership,
        )?;
        require(bias(r.handle)? == self.bias, Error::Loader)?;
        file_matches(&r.file, r.stamp, &r.image.bytes)?;
        require(device(&r.file, r.stamp.inode)? == r.device, Error::Identity)?;
        require(std::fs::canonicalize(&r.path)? == r.path, Error::Identity)?;
        file_matches(&open(&r.path)?, r.stamp, &r.image.bytes)?;
        let rows = maps(&text("/proc/self/maps", MAP_LIMIT)?)?;
        for p in &r.image.loads {
            if p.flags == 6 {
                // Their mappings/relocation destinations/global storage need
                // separate admission. No writable address or equality is granted.
                continue;
            }
            let start = runtime(self.bias, p.address, p.file_bytes)?;
            mapping(
                &rows,
                start,
                p.file_bytes,
                p.offset,
                if p.flags == 5 { *b"r-xp" } else { *b"r--p" },
                r.device,
                r.stamp.inode,
            )?;
            let expected = &r.image.bytes[p.offset as usize..(p.offset + p.file_bytes) as usize];
            // SAFETY: checked file-backed VMAs plus continuous immutable mapping
            // contract; /proc observations alone would not make this read safe.
            let actual =
                unsafe { std::slice::from_raw_parts(start as usize as *const u8, expected.len()) };
            require(actual == expected, Error::Identity)?;
        }
        file_matches(&r.file, r.stamp, &r.image.bytes)
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}
fn raw_capture_owner(loads: &[Load], address: u64) -> Result<&Load> {
    let end = add(address, 64)?;
    require(address % 8 == 0, Error::Bounds)?;
    let mut found = None;
    for p in loads {
        if p.flags == 6 && p.address <= address && end <= add(p.address, p.file_bytes)? {
            require(found.replace(p).is_none(), Error::Ownership)?;
        }
    }
    if let Some(p) = found {
        return Ok(p);
    }
    raw_tail_owner(loads, address)
}
fn raw_tail_owner(loads: &[Load], address: u64) -> Result<&Load> {
    let end = add(address, 64)?;
    require(address % 8 == 0, Error::Bounds)?;
    let mut found = None;
    for p in loads {
        let file_end = add(p.address, p.file_bytes)?;
        let memory_end = add(p.address, p.memory_bytes)?;
        if p.flags == 6 && p.file_bytes != 0 && file_end <= address && end <= memory_end {
            require(found.replace(p).is_none(), Error::Ownership)?;
        }
    }
    let p = found.ok_or(Error::Ownership)?;
    // This witness only needs the inode-backed final page. Anonymous extended
    // BSS pages require a different ownership proof and are refused here.
    require(
        end <= page_end(add(p.address, p.file_bytes)?)?,
        Error::Ownership,
    )?;
    Ok(p)
}
fn runtime(bias: u64, address: u64, length: u64) -> Result<u64> {
    let start = add(bias, address)?;
    let end = add(start, length)?;
    require(
        bias % PAGE == 0 && start != 0 && length != 0 && end <= isize::MAX as u64,
        Error::Bounds,
    )?;
    Ok(start)
}
fn bias(handle: *mut libc::c_void) -> Result<u64> {
    let mut link: *const u64 = std::ptr::null();
    // SAFETY: retained live dlopen handle; RTLD_DI_LINKMAP exposes l_addr as its
    // first ELF64 ABI field. No dynamic symbol is needed for hidden functions.
    require(
        !handle.is_null()
            && unsafe { libc::dlinfo(handle, 2, (&raw mut link).cast()) } == 0
            && !link.is_null(),
        Error::Loader,
    )?;
    let result = unsafe { link.read() };
    require(result % PAGE == 0, Error::Loader)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_file_backed_raw_cells_require_exact_writable_owner() {
        let p = Load {
            address: 0x3de8,
            offset: 0x2de8,
            file_bytes: 0x298,
            memory_bytes: 0x2a0,
            flags: 6,
        };
        assert_eq!(raw_capture_owner(&[p], 0x4000).unwrap(), &p);
        assert_eq!(raw_capture_owner(&[p], 0x4040).unwrap(), &p);
        for address in [0x3de0, 0x4041, 0x4070, u64::MAX - 7] {
            assert!(raw_capture_owner(&[p], address).is_err());
        }
        assert_eq!(raw_capture_owner(&[p, p], 0x4000), Err(Error::Ownership));
        for flags in [4, 5, 7] {
            assert_eq!(
                raw_capture_owner(&[Load { flags, ..p }], 0x4000),
                Err(Error::Ownership)
            );
        }
        // The former fixture's page-aligned file end leaves anonymous BSS.
        let old = Load {
            file_bytes: 0x218,
            memory_bytes: 0x2b8,
            ..p
        };
        assert_eq!(raw_capture_owner(&[old], 0x4020), Err(Error::Ownership));
        assert_eq!(raw_capture_owner(&[old], 0x4060), Err(Error::Ownership));
    }
    #[test]
    fn raw_capture_requires_one_aligned_inode_backed_bss_tail() {
        let p = Load {
            address: 0x3da0,
            offset: 0x2da0,
            file_bytes: 0x268,
            memory_bytes: 0x300,
            flags: 6,
        };
        assert_eq!(raw_tail_owner(&[p], 0x4060).unwrap(), &p);
        for address in [0x4000, 0x4061, 0x4080, u64::MAX - 7] {
            assert!(raw_tail_owner(&[p], address).is_err());
        }
        assert!(matches!(
            raw_tail_owner(&[p, p], 0x4060),
            Err(Error::Ownership)
        ));
        for flags in [4, 5, 7] {
            assert!(matches!(
                raw_tail_owner(&[Load { flags, ..p }], 0x4060),
                Err(Error::Ownership)
            ));
        }
        let extended = Load {
            memory_bytes: 0x3000,
            ..p
        };
        assert!(matches!(
            raw_tail_owner(&[extended], 0x5000),
            Err(Error::Ownership)
        ));
    }
    // A synthetic ownership-only ELF, not a valid CFI/native admission fixture.
    fn image() -> Vec<u8> {
        let mut b = vec![0; 0x3000];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (p, v) in [(16, 3_u16), (18, 62), (52, 64), (54, 56), (56, 4)] {
            b[p..p + 2].copy_from_slice(&v.to_le_bytes());
        }
        b[20..24].copy_from_slice(&1_u32.to_le_bytes());
        b[32..40].copy_from_slice(&64_u64.to_le_bytes());
        for (i, (kind, flags, off, va, size)) in [
            (1_u32, 4_u32, 0_u64, 0_u64, 0x1000_u64),
            (1, 5, 0x1000, 0x1000, 0x1000),
            (1, 6, 0x2000, 0x2000, 0x1000),
            (0x6474_e550, 4, 0x300, 0x300, 0x20),
        ]
        .into_iter()
        .enumerate()
        {
            let p = 64 + i * 56;
            b[p..p + 4].copy_from_slice(&kind.to_le_bytes());
            b[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
            for (field, value) in [
                (8, off),
                (16, va),
                (32, size),
                (40, size),
                (48, if i == 3 { 4 } else { PAGE }),
            ] {
                b[p + field..p + field + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        b
    }
    fn range(address: u64, length: u64, executable: bool) -> ImmutableRange {
        ImmutableRange {
            address,
            length,
            executable,
        }
    }
    #[test]
    fn immutable_inventory_includes_headers_code_and_explicit_cfi_without_rw_claim() {
        let b = image();
        let required = [range(0x300, 32, false), range(0x1100, 16, true)];
        let bound = BoundImage::new(&b, ContentId::of(&b), &required).unwrap();
        assert_eq!(bound.loads().len(), 3);
        assert_eq!(bound.loads()[2].flags, 6);
        assert_eq!(bound.required(), required);
        assert_eq!(bound.identity(), ContentId::of(&b));
        for bad in [
            range(0x2000, 8, false),
            range(0x1000, 8, false),
            range(0xff0, 32, false),
            range(0, 0, false),
            range(u64::MAX, 2, false),
        ] {
            assert!(BoundImage::new(&b, ContentId::of(&b), &[bad]).is_err());
        }
    }
    #[test]
    fn whole_identity_and_load_alias_or_metadata_owner_mutations_refuse() {
        let b = image();
        let id = ContentId::of(&b);
        let mut changed = b.clone();
        changed[0x1100] = 1;
        assert!(matches!(
            BoundImage::new(&changed, id, &[]),
            Err(Error::Identity)
        ));
        for (at, value) in [
            (64 + 56 + 16, 0_u64),
            (64 + 56 + 8, 0),
            (64 + 3 * 56 + 16, 0x2000),
            (64 + 3 * 56 + 8, 0x2000),
        ] {
            let mut bad = b.clone();
            bad[at..at + 8].copy_from_slice(&value.to_le_bytes());
            assert!(BoundImage::new(&bad, ContentId::of(&bad), &[]).is_err());
        }
    }
    #[test]
    fn split_vmas_preserve_exact_offset_and_owner() {
        let rows = maps(
            "10000-11000 r-xp 00000000 00:30 7 /one\n11000-12000 r-xp 00001000 00:30 7 /two\n",
        )
        .unwrap();
        assert_eq!(
            mapping(&rows, 0x10800, 0x1000, 0x800, *b"r-xp", (0, 48), 7),
            Ok(())
        );
        for (dev, ino, off) in [
            ((0, 49), 7, 0x800),
            ((0, 48), 8, 0x800),
            ((0, 48), 7, 0x801),
        ] {
            assert!(mapping(&rows, 0x10800, 0x1000, off, *b"r-xp", dev, ino).is_err());
        }
    }
    #[test]
    fn all_permission_and_later_owner_mismatches_refuse() {
        for perm in ["rw-p", "rwxp", "r-xs", "--xp", "r--p"] {
            let rows = maps(&format!("10000-11000 {perm} 00000000 00:30 7\n")).unwrap();
            assert_eq!(
                mapping(&rows, 0x10000, 16, 0, *b"r-xp", (0, 48), 7),
                Err(Error::Mapping)
            );
        }
        for tail in [
            "11000-12000 r-xp 00001000 00:30 8",
            "12000-13000 r-xp 00001000 00:30 7",
            "11000-12000 r-xp 00002000 00:30 7",
        ] {
            let rows = maps(&format!("10000-11000 r-xp 00000000 00:30 7\n{tail}\n")).unwrap();
            assert!(mapping(&rows, 0x10800, 0x1000, 0x800, *b"r-xp", (0, 48), 7).is_err());
        }
    }
    #[test]
    fn malformed_overlapping_or_unordered_maps_are_not_ignored() {
        for input in [
            "",
            "10000-11000 rxp 0 00:30 7",
            "10000-10000 r-xp 0 00:30 7",
            "10001-11000 r-xp 0 00:30 7",
            "10000-12000 r-xp 0 00:30 7\n11000-13000 r-xp 1000 00:30 7",
            "11000-12000 r-xp 0 00:30 7\n10000-11000 r-xp 0 00:30 7",
        ] {
            assert!(maps(input).is_err(), "{input}");
        }
    }
    #[test]
    fn runtime_translation_never_wraps_or_accepts_empty_nonuser_ranges() {
        assert_eq!(runtime(0x10000, 0x123, 5), Ok(0x10123));
        for (base, address, size) in [
            (1, 0, 1),
            (0, 0, 1),
            (0x1000, u64::MAX, 1),
            (0x1000, 1, 0),
            (0, isize::MAX as u64, 2),
        ] {
            assert!(runtime(base, address, size).is_err());
        }
    }

    #[test]
    fn file_mapped_span_and_requirement_budgets_are_independent() {
        let oversized = vec![0; BYTE_LIMIT as usize + 1];
        assert!(matches!(
            BoundImage::new(&oversized, ContentId::of(b"unrelated"), &[]),
            Err(Error::Bounds)
        ));
        let original = image();
        for (field, value) in [(40, BYTE_LIMIT), (16, BYTE_LIMIT * 2)] {
            let mut bad = original.clone();
            let at = 64 + 2 * 56 + field;
            bad[at..at + 8].copy_from_slice(&value.to_le_bytes());
            assert!(matches!(
                BoundImage::new(&bad, ContentId::of(&bad), &[]),
                Err(Error::Bounds)
            ));
        }
        assert!(matches!(
            BoundImage::new(
                &original,
                ContentId::of(&original),
                &vec![range(0, 1, false); 4097]
            ),
            Err(Error::Bounds)
        ));
    }
}
