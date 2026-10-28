//! Fixture-private owner for the independently built two-call C helper.
//! This is not scalar-subject admission and exposes no safe native invocation.
use object::{Object, ObjectSection, ObjectSymbol, SymbolFlags, SymbolKind};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::rc::Rc;

use super::caller_bytes as bytes;
pub use bytes::{
    BYTES, CALLS, CONTINUATIONS, HEADS, OUTER_RET, PROTECTED_STACK_BELOW_CALLER, Request,
    SUBJECT_RSP_DELTA, SYMBOL,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerError {
    Format,
    SourceBytes,
    SymbolOwner,
    OperatingSystem,
    Cet,
}
type Result<T> = std::result::Result<T, CallerError>;
const PAGE: u64 = 4096;
const LIMIT: usize = 1024 * 1024;
fn require(ok: bool, error: CallerError) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
fn slice(b: &[u8], at: u64, len: u64) -> Result<&[u8]> {
    let end = at.checked_add(len).ok_or(CallerError::Format)?;
    b.get(
        usize::try_from(at).map_err(|_| CallerError::Format)?
            ..usize::try_from(end).map_err(|_| CallerError::Format)?,
    )
    .ok_or(CallerError::Format)
}
fn u16_at(b: &[u8], at: u64) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(b, at, 2)?.try_into().unwrap()))
}
fn u32_at(b: &[u8], at: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(b, at, 4)?.try_into().unwrap()))
}
fn u64_at(b: &[u8], at: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(slice(b, at, 8)?.try_into().unwrap()))
}

fn body(code: &[u8]) -> Result<()> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Register};
    require(
        code == BYTES && code.len() == 67 && HEADS.len() == 24,
        CallerError::SourceBytes,
    )?;
    require(
        CALLS == [27, 45]
            && CONTINUATIONS == [30, 48]
            && OUTER_RET == 66
            && SUBJECT_RSP_DELTA == 48
            && PROTECTED_STACK_BELOW_CALLER == 176
            && std::mem::size_of::<Request>() == 16,
        CallerError::Format,
    )?;
    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    for &pc in HEADS {
        let i = decoder.decode();
        require(!i.is_invalid() && i.ip() == pc, CallerError::Format)?;
        if let Some(n) = CALLS.iter().position(|&p| p == pc) {
            require(
                i.flow_control() == FlowControl::IndirectCall
                    && i.op0_register() == Register::R13
                    && i.next_ip() == CONTINUATIONS[n],
                CallerError::Format,
            )?;
        } else {
            require(
                i.flow_control()
                    == if pc == OUTER_RET {
                        FlowControl::Return
                    } else {
                        FlowControl::Next
                    },
                CallerError::Format,
            )?;
        }
    }
    require(
        !decoder.can_decode() && decoder.position() == code.len(),
        CallerError::Format,
    )
}

// Closed no-dependency/no-constructor/no-relocation dynamic profile.
fn dynamic(data: &[u8]) -> Result<()> {
    require(
        !data.is_empty() && data.len() <= 4096 && data.len() % 16 == 0,
        CallerError::Format,
    )?;
    let mut tags = BTreeMap::new();
    let mut ended = false;
    for row in data.chunks_exact(16) {
        let (tag, value) = (u64_at(row, 0)?, u64_at(row, 8)?);
        if tag == 0 {
            require(value == 0, CallerError::Format)?;
            ended = true;
        } else {
            require(
                !ended
                    && tags.insert(tag, value).is_none()
                    && matches!(
                        tag,
                        4 | 5 | 6 | 10 | 11 | 14 | 16 | 24 | 30 | 0x6fff_fef5 | 0x6fff_fffb
                    )
                    && (!matches!(tag, 16 | 24) || value == 0)
                    && (tag != 30 || value & !10 == 0)
                    && (tag != 0x6fff_fffb || value & !1 == 0),
                CallerError::Format,
            )?;
        }
    }
    require(
        ended
            && [5, 6, 10, 11].iter().all(|t| tags.contains_key(t))
            && tags.get(&11) == Some(&24)
            && tags.get(&10).is_some_and(|&n| (1..=65536).contains(&n))
            && (tags.contains_key(&4) || tags.contains_key(&0x6fff_fef5))
            && (tags.contains_key(&24)
                || tags.get(&30).is_some_and(|v| v & 8 != 0)
                || tags.get(&0x6fff_fffb).is_some_and(|v| v & 1 != 0)),
        CallerError::Format,
    )
}
#[derive(Clone, Copy)]
struct Load {
    offset: u64,
    address: u64,
    size: u64,
    flags: u32,
}
struct Parsed {
    entry: u64,
    page_offset: u64,
    source: Vec<u8>,
}
fn parse(trusted: &[u8]) -> Result<Parsed> {
    require(
        trusted.len() <= LIMIT
            && trusted.get(..7) == Some(b"\x7fELF\x02\x01\x01")
            && u16_at(trusted, 16)? == 3
            && u16_at(trusted, 18)? == 62
            && u32_at(trusted, 20)? == 1
            && u16_at(trusted, 52)? == 64
            && u16_at(trusted, 54)? == 56,
        CallerError::Format,
    )?;
    let count = u16_at(trusted, 56)?;
    require((1..=16).contains(&count), CallerError::Format)?;
    let phoff = u64_at(trusted, 32)?;
    slice(trusted, phoff, u64::from(count) * 56)?;
    let mut loads: Vec<Load> = Vec::new();
    let mut dyns = Vec::new();
    let mut stacks = 0;
    for n in 0..count {
        let p = phoff + u64::from(n) * 56;
        let kind = u32_at(trusted, p)?;
        let flags = u32_at(trusted, p + 4)?;
        require(
            matches!(
                kind,
                0 | 1 | 2 | 4 | 0x6474_e550 | 0x6474_e551 | 0x6474_e552
            ),
            CallerError::Format,
        )?;
        if kind == 0x6474_e551 {
            stacks += 1;
            require(flags == 6, CallerError::Cet)?;
        }
        let (offset, address, size) = (
            u64_at(trusted, p + 8)?,
            u64_at(trusted, p + 16)?,
            u64_at(trusted, p + 32)?,
        );
        if kind == 2 {
            dyns.push((offset, address, size));
        }
        if kind != 1 {
            continue;
        }
        require(
            matches!(flags, 4..=6)
                && size <= 65536
                && size == u64_at(trusted, p + 40)?
                && u64_at(trusted, p + 48)? == PAGE
                && offset % PAGE == address % PAGE
                && (size != 0 || address % PAGE == 0),
            CallerError::Format,
        )?;
        slice(trusted, offset, size)?;
        let end = address
            .checked_add(size)
            .and_then(|e| e.checked_add(PAGE - 1))
            .ok_or(CallerError::Format)?
            & !(PAGE - 1);
        if size != 0 {
            for other in &loads {
                let other_end = (other.address + other.size + PAGE - 1) & !(PAGE - 1);
                require(
                    end <= (other.address & !(PAGE - 1)) || other_end <= (address & !(PAGE - 1)),
                    CallerError::Format,
                )?;
            }
            loads.push(Load {
                offset,
                address,
                size,
                flags,
            });
        }
    }
    require(
        stacks == 1
            && dyns.len() == 1
            && loads
                .iter()
                .filter(|l| l.offset == 0 && l.address == 0 && l.flags == 4)
                .count()
                == 1,
        CallerError::Format,
    )?;
    let (offset, address, size) = dyns[0];
    let dyn_end = address.checked_add(size).ok_or(CallerError::Format)?;
    require(
        loads
            .iter()
            .filter(|l| {
                address >= l.address
                    && dyn_end <= l.address + l.size
                    && offset == l.offset + address - l.address
            })
            .count()
            == 1,
        CallerError::Format,
    )?;
    dynamic(slice(trusted, offset, size)?)?;
    let file = object::File::parse(trusted).map_err(|_| CallerError::Format)?;
    require(
        file.section_by_name(".note.gnu.property").is_none(),
        CallerError::Cet,
    )?;
    for s in file.sections() {
        require(s.relocations().next().is_none(), CallerError::Format)?;
        if matches!(
            s.name(),
            Ok(".init"
                | ".fini"
                | ".init_array"
                | ".fini_array"
                | ".preinit_array"
                | ".tdata"
                | ".tbss")
        ) {
            require(s.size() == 0, CallerError::Format)?;
        }
    }
    let mut selected = Vec::new();
    for s in file.dynamic_symbols() {
        if s.name() == Ok("") && s.address() == 0 && s.size() == 0 {
            require(
                s.is_undefined()
                    && matches!(
                        s.flags(),
                        SymbolFlags::Elf {
                            st_info: 0,
                            st_other: 0
                        }
                    ),
                CallerError::SymbolOwner,
            )?;
            continue;
        }
        require(
            s.name() == Ok(SYMBOL)
                && s.is_definition()
                && s.kind() == SymbolKind::Text
                && s.size() == BYTES.len() as u64
                && matches!(
                    s.flags(),
                    SymbolFlags::Elf {
                        st_info: 0x12,
                        st_other: 0
                    }
                ),
            CallerError::SymbolOwner,
        )?;
        selected.push(s.address());
    }
    require(selected.len() == 1, CallerError::SymbolOwner)?;
    let entry = selected[0];
    // ET_DYN entry metadata is not invocation authority for dlopen. The pinned
    // linker can set it to this same independently selected helper; no other
    // nonzero entry, interior address or executable interval is accepted.
    let elf_entry = u64_at(trusted, 24)?;
    require(elf_entry == 0 || elf_entry == entry, CallerError::Format)?;
    let rx: Vec<_> = loads.iter().filter(|l| l.flags == 5).collect();
    require(
        rx.len() == 1
            && rx[0].address == entry
            && entry % PAGE == 0
            && rx[0].offset % PAGE == 0
            && rx[0].size == BYTES.len() as u64,
        CallerError::Format,
    )?;
    body(slice(trusted, rx[0].offset, rx[0].size)?)?;
    for s in file.symbols() {
        require(
            !matches!(s.flags(),SymbolFlags::Elf {st_info,..} if st_info & 15 == 10),
            CallerError::Format,
        )?;
        if s.is_definition() && s.kind() == SymbolKind::Text {
            require(
                s.name() == Ok(SYMBOL) && s.address() == entry && s.size() == BYTES.len() as u64,
                CallerError::SymbolOwner,
            )?;
        }
    }
    let start = usize::try_from(rx[0].offset).map_err(|_| CallerError::Format)?;
    let available = (trusted.len() - start).min(PAGE as usize);
    let mut source = vec![0; PAGE as usize];
    source[..available].copy_from_slice(&trusted[start..start + available]);
    Ok(Parsed {
        entry,
        page_offset: rx[0].offset,
        source,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn stamp(file: &File) -> Result<Stamp> {
    let m = file.metadata().map_err(|_| CallerError::OperatingSystem)?;
    require(m.is_file(), CallerError::Format)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mode: m.mode(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}
fn read(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| CallerError::OperatingSystem)?;
    let mut b = Vec::new();
    file.take(LIMIT as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| CallerError::OperatingSystem)?;
    require(b.len() <= LIMIT, CallerError::Format)?;
    Ok(b)
}
fn text(path: &str, limit: u64) -> Result<String> {
    let mut b = String::new();
    File::open(path)
        .map_err(|_| CallerError::OperatingSystem)?
        .take(limit + 1)
        .read_to_string(&mut b)
        .map_err(|_| CallerError::OperatingSystem)?;
    require(b.len() as u64 <= limit, CallerError::Format)?;
    Ok(b)
}
fn device(fd: i32) -> Result<(u32, u32)> {
    let info = text(&format!("/proc/self/fdinfo/{fd}"), 4096)?;
    let ids: Vec<_> = info
        .lines()
        .filter_map(|l| l.strip_prefix("mnt_id:\t"))
        .collect();
    require(ids.len() == 1, CallerError::SymbolOwner)?;
    let mounts = text("/proc/self/mountinfo", LIMIT as u64)?;
    let rows: Vec<_> = mounts
        .lines()
        .filter(|l| l.split_whitespace().next() == Some(ids[0]))
        .collect();
    require(rows.len() == 1, CallerError::SymbolOwner)?;
    let (a, b) = rows[0]
        .split_whitespace()
        .nth(2)
        .and_then(|f| f.split_once(':'))
        .ok_or(CallerError::Format)?;
    Ok((
        a.parse().map_err(|_| CallerError::Format)?,
        b.parse().map_err(|_| CallerError::Format)?,
    ))
}
fn maps_match(
    maps: &str,
    address: u64,
    length: u64,
    dev: (u32, u32),
    inode: u64,
    offset: u64,
) -> Result<()> {
    let end = address.checked_add(length).ok_or(CallerError::Format)?;
    require(length != 0, CallerError::Format)?;
    let mut covered = address;
    for row in maps.lines() {
        let f: Vec<_> = row.split_whitespace().collect();
        require(f.len() >= 5, CallerError::Format)?;
        let hex = |s: &str| u64::from_str_radix(s, 16).map_err(|_| CallerError::Format);
        let (lo, hi) = f[0].split_once('-').ok_or(CallerError::Format)?;
        let (lo, hi) = (hex(lo)?, hex(hi)?);
        require(lo < hi, CallerError::Format)?;
        if hi <= covered || lo >= end {
            continue;
        }
        let (major, minor) = f[3].split_once(':').ok_or(CallerError::Format)?;
        require(lo <= covered, CallerError::SymbolOwner)?;
        let actual_offset = hex(f[2])?
            .checked_add(covered - lo)
            .ok_or(CallerError::Format)?;
        let expected_offset = offset
            .checked_add(covered - address)
            .ok_or(CallerError::Format)?;
        require(
            lo <= covered
                && f[1] == "r-xp"
                && (hex(major)?, hex(minor)?) == (u64::from(dev.0), u64::from(dev.1))
                && f[4].parse::<u64>().map_err(|_| CallerError::Format)? == inode
                && actual_offset == expected_offset,
            CallerError::SymbolOwner,
        )?;
        covered = hi.min(end);
        if covered == end {
            return Ok(());
        }
    }
    Err(CallerError::SymbolOwner)
}
struct Retained {
    handle: *mut libc::c_void,
    file: File,
    trusted: Vec<u8>,
    stamp: Stamp,
    device: (u32, u32),
    pid: u32,
}
/// Local fixture handle; its fd and loader reference remain retained even on later refusal/Drop.
pub struct CallerOwner {
    retained: &'static mut Retained,
    parsed: Parsed,
    entry: u64,
    _local: PhantomData<Rc<()>>,
}
impl CallerOwner {
    /// Authenticate independent complete compiler output before dlopen; no caller executes here.
    ///
    /// # Safety
    /// `trusted` is the independently frozen output of the pinned caller.c/compiler command,
    /// never candidate-derived self-authority. Only the controlled calling thread may
    /// invoke this helper; loader operations occur outside active helper calls. No active CET,
    /// signals, fork, source/alias writer, mapping change or unload through last use. The
    /// loader, its code and dependencies themselves are trusted. No constructors/dependencies
    /// or relocations are admitted in this helper DSO. This is a fixture, not a public SDK owner.
    pub unsafe fn load(candidate: &Path, trusted: &[u8]) -> Result<Self> {
        let parsed = parse(trusted)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(candidate)
            .map_err(|_| CallerError::OperatingSystem)?;
        let original = stamp(&file)?;
        require(
            original.len == trusted.len() as u64
                && read(&mut file)? == trusted
                && stamp(&file)? == original,
            CallerError::SourceBytes,
        )?;
        let dev = device(file.as_raw_fd())?;
        let mut shstk = 0_u64;
        let status = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut shstk) };
        if status == 0 {
            require(shstk == 0, CallerError::Cet)?;
        } else {
            require(
                matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS)
                ),
                CallerError::OperatingSystem,
            )?;
        }
        let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        // Allocate/copy and retain fd BEFORE acquiring a live loader handle. Even later
        // panics/refusals cannot drop the file or unmap a successfully opened helper.
        let retained = Box::leak(Box::new(Retained {
            handle: std::ptr::null_mut(),
            file,
            trusted: trusted.to_vec(),
            stamp: original,
            device: dev,
            pid: std::process::id(),
        }));
        retained.handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        require(!retained.handle.is_null(), CallerError::OperatingSystem)?;
        let mut owner = Self {
            retained,
            parsed,
            entry: 0,
            _local: PhantomData,
        };
        owner.entry = owner.resolve()?;
        owner.verify()?;
        Ok(owner)
    }
    fn resolve(&self) -> Result<u64> {
        let name = c"normal_caller";
        let address = unsafe { libc::dlsym(self.retained.handle, name.as_ptr()) } as usize as u64;
        let bias = address
            .checked_sub(self.parsed.entry)
            .ok_or(CallerError::SymbolOwner)?;
        require(address != 0 && bias % PAGE == 0, CallerError::SymbolOwner)?;
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::dladdr(address as usize as *const _, &mut info) } != 0
                && info.dli_fbase as usize as u64 == bias
                && info.dli_saddr as usize as u64 == address
                && !info.dli_sname.is_null()
                && unsafe { CStr::from_ptr(info.dli_sname) } == name,
            CallerError::SymbolOwner,
        )?;
        let mut link: *const u64 = std::ptr::null();
        require(
            unsafe { libc::dlinfo(self.retained.handle, 2, (&raw mut link).cast()) } == 0
                && !link.is_null()
                && unsafe { link.read() } == bias,
            CallerError::SymbolOwner,
        )?;
        Ok(address)
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }
    /// Complete independently expected RX page, not a snapshot accepted as its own authority.
    pub fn source(&self) -> (u64, &[u8]) {
        (self.entry, &self.parsed.source)
    }
    /// Caller-owned boundary check; it is deliberately outside the unsafe native invoke.
    pub fn verify(&mut self) -> Result<()> {
        require(
            self.retained.pid == std::process::id(),
            CallerError::SymbolOwner,
        )?;
        require(
            stamp(&self.retained.file)? == self.retained.stamp
                && read(&mut self.retained.file)? == self.retained.trusted
                && stamp(&self.retained.file)? == self.retained.stamp
                && device(self.retained.file.as_raw_fd())? == self.retained.device,
            CallerError::SourceBytes,
        )?;
        require(self.resolve()? == self.entry, CallerError::SymbolOwner)?;
        maps_match(
            &text("/proc/self/maps", LIMIT as u64)?,
            self.entry,
            PAGE,
            self.retained.device,
            self.retained.stamp.ino,
            self.parsed.page_offset,
        )?;
        // SAFETY: retained loader owner plus the continuous no-unmap/no-writer contract.
        require(
            unsafe { std::slice::from_raw_parts(self.entry as usize as *const u8, PAGE as usize) }
                == self.parsed.source,
            CallerError::SourceBytes,
        )
    }
    /// Execute the same actual C helper used by the separate state qualification.
    ///
    /// # Safety
    /// All load contracts remain true. `target` is a retained admitted normal leaf with
    /// exactly the declared SysV ABI and normal returns. Both request pointers remain
    /// valid/readable for their full bounds; requests/results/input are disjoint, immutable
    /// where read and live through both returns. Adequate writable callback stack is present.
    /// Publication/attachment/checkpoint authority belongs to the surrounding consumer.
    /// No SDK invoke, source scan, automatic checkpoint or native eligibility proof is supplied.
    pub unsafe fn invoke(
        &mut self,
        target: u64,
        requests: &[Request; 2],
        results: &mut [u64; 2],
    ) -> u64 {
        assert_eq!(self.retained.pid, std::process::id());
        assert_ne!(target, 0);
        let caller: bytes::Caller = unsafe { std::mem::transmute(self.entry as usize) };
        let target: bytes::Target = unsafe { std::mem::transmute(target as usize) };
        let value = unsafe { caller(target, requests.as_ptr(), results.as_mut_ptr()) };
        // Real post-call work prevents a tail transfer into the helper. The
        // oracle separately authenticates the actual CALL and its pushed word.
        assert_eq!(value, results[0].wrapping_add(results[1]));
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normal_caller_literal_body_and_every_changed_byte_refuse() {
        assert_eq!(body(BYTES), Ok(()));
        for i in 0..BYTES.len() {
            let mut b = BYTES.to_vec();
            b[i] ^= 1;
            assert_eq!(body(&b), Err(CallerError::SourceBytes));
        }
        assert!(body(&BYTES[..66]).is_err());
        let mut b = BYTES.to_vec();
        b.push(0x90);
        assert!(body(&b).is_err());
    }
    fn dyn_bytes(rows: &[(u64, u64)]) -> Vec<u8> {
        rows.iter()
            .flat_map(|&(a, b)| a.to_le_bytes().into_iter().chain(b.to_le_bytes()))
            .collect()
    }
    #[test]
    fn normal_caller_dynamic_refuses_load_time_execution_and_dependencies() {
        let good = [
            (4, 0x3c0),
            (5, 0x380),
            (6, 0x300),
            (10, 15),
            (11, 24),
            (30, 8),
            (0, 0),
        ];
        assert_eq!(dynamic(&dyn_bytes(&good)), Ok(()));
        // The separately pinned -Bsymbolic command may name only local symbol
        // binding in addition to NOW; neither flag introduces executable work.
        let mut symbolic = good.to_vec();
        symbolic.insert(0, (16, 0));
        symbolic[6].1 = 10;
        assert_eq!(dynamic(&dyn_bytes(&symbolic)), Ok(()));
        symbolic[0].1 = 1;
        assert!(dynamic(&dyn_bytes(&symbolic)).is_err());
        let mut flags = good.to_vec();
        flags[5].1 = 12;
        assert!(dynamic(&dyn_bytes(&flags)).is_err());
        for tag in [
            1, 7, 8, 9, 12, 13, 17, 18, 19, 22, 23, 25, 26, 27, 28, 29, 32, 33, 35, 36, 37,
        ] {
            let mut rows = good.to_vec();
            rows.insert(0, (tag, 1));
            assert!(dynamic(&dyn_bytes(&rows)).is_err());
        }
        for index in [1, 2, 3, 4, 5, 6] {
            let mut rows = good.to_vec();
            rows.remove(index);
            assert!(dynamic(&dyn_bytes(&rows)).is_err());
        }
        let mut rows = good.to_vec();
        rows[4].1 = 16;
        assert!(dynamic(&dyn_bytes(&rows)).is_err());
        let mut rows = good.to_vec();
        rows.push((4, 1));
        assert!(dynamic(&dyn_bytes(&rows)).is_err());
    }
    #[test]
    fn normal_caller_mapping_requires_complete_exact_rx_owner() {
        let good =
            "1000-2000 r-xp 00001000 00:01 7 /fixture\n2000-3000 r-xp 00002000 00:01 7 /fixture\n";
        assert_eq!(maps_match(good, 0x1000, 8192, (0, 1), 7, 0x1000), Ok(()));
        for bad in [
            good.replace("r-xp", "rw-p"),
            good.replace("00:01", "00:02"),
            good.replace(" 7 ", " 8 "),
            good.replace("00002000", "00003000"),
            good.replace("2000-3000", "2100-3000"),
            good.lines().next().unwrap().to_owned(),
        ] {
            assert!(maps_match(&bad, 0x1000, 8192, (0, 1), 7, 0x1000).is_err());
        }
        assert!(maps_match(good, u64::MAX, 2, (0, 1), 7, 0x1000).is_err());
        assert!(maps_match(good, 0x1000, 0, (0, 1), 7, 0x1000).is_err());
        assert!(maps_match(good, 0x1000, 8192, (0, 1), 7, u64::MAX).is_err());
    }
    fn elf() -> Vec<u8> {
        let mut b = vec![0_u8; 0x3300];
        fn w(b: &mut [u8], at: usize, n: u64, size: usize) {
            b[at..at + size].copy_from_slice(&n.to_le_bytes()[..size]);
        }
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, n, size) in [
            (16, 3, 2),
            (18, 62, 2),
            (20, 1, 4),
            (32, 64, 8),
            (40, 0x3100, 8),
            (52, 64, 2),
            (54, 56, 2),
            (56, 5, 2),
            (58, 64, 2),
            (60, 6, 2),
            (62, 5, 2),
        ] {
            w(&mut b, at, n, size);
        }
        for (i, (kind, flags, off, addr, size, align)) in [
            (1, 4, 0, 0, 4096, 4096),
            (1, 5, 0x1000, 0x1000, 67, 4096),
            (1, 6, 0x2f00, 0x2f00, 256, 4096),
            (2, 6, 0x2f00, 0x2f00, 112, 8),
            (0x6474e551, 6, 0, 0, 0, 16),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 64 + i * 56;
            for (delta, n, width) in [
                (0, kind, 4),
                (4, flags, 4),
                (8, off, 8),
                (16, addr, 8),
                (32, size, 8),
                (40, size, 8),
                (48, align, 8),
            ] {
                w(&mut b, at + delta, n, width);
            }
        }
        b[0x1000..0x1043].copy_from_slice(BYTES);
        let names = b"\0.dynsym\0.dynstr\0.text\0.dynamic\0.shstrtab\0";
        b[0x3050..0x3050 + names.len()].copy_from_slice(names);
        let strings = b"\0normal_caller\0";
        b[0x380..0x380 + strings.len()].copy_from_slice(strings);
        for (i, n) in [1, 2, 1, 0, 0].into_iter().enumerate() {
            w(&mut b, 0x3c0 + i * 4, n, 4);
        }
        w(&mut b, 0x318, 1, 4);
        b[0x31c] = 0x12;
        w(&mut b, 0x31e, 3, 2);
        w(&mut b, 0x320, 0x1000, 8);
        w(&mut b, 0x328, 67, 8);
        let dynamic = dyn_bytes(&[
            (4, 0x3c0),
            (5, 0x380),
            (6, 0x300),
            (10, strings.len() as u64),
            (11, 24),
            (30, 8),
            (0, 0),
        ]);
        b[0x2f00..0x2f00 + dynamic.len()].copy_from_slice(&dynamic);
        for (i, (name, kind, flags, addr, off, size, link, align, entsize)) in [
            (1, 11, 2, 0x300, 0x300, 48, 2, 8, 24),
            (9, 3, 2, 0x380, 0x380, strings.len() as u64, 0, 1, 0),
            (17, 1, 6, 0x1000, 0x1000, 67, 0, 16, 0),
            (23, 6, 3, 0x2f00, 0x2f00, 112, 2, 8, 16),
            (32, 3, 0, 0, 0x3050, names.len() as u64, 0, 1, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 0x3100 + (i + 1) * 64;
            for (delta, n, width) in [
                (0, name, 4),
                (4, kind, 4),
                (8, flags, 8),
                (16, addr, 8),
                (24, off, 8),
                (32, size, 8),
                (40, link, 4),
                (48, align, 8),
                (56, entsize, 8),
            ] {
                w(&mut b, at + delta, n, width);
            }
        }
        b
    }
    #[test]
    fn normal_caller_complete_elf_refuses_wrong_symbol_body_load_and_dynamic() {
        let good = elf();
        let p = parse(&good).unwrap();
        assert_eq!(
            (p.entry, p.page_offset, p.source.len()),
            (0x1000, 0x1000, 4096)
        );
        assert_eq!(&p.source[..67], BYTES);
        let mut named_entry = good.clone();
        named_entry[24..32].copy_from_slice(&0x1000_u64.to_le_bytes());
        assert_eq!(parse(&named_entry).unwrap().source, p.source);
        for entry in [1_u64, 0x1001, 0x1042, 0x2000, u64::MAX] {
            named_entry[24..32].copy_from_slice(&entry.to_le_bytes());
            assert!(parse(&named_entry).is_err());
        }
        for (at, value) in [
            (18, 3),
            (64 + 56 + 4, 7),
            (64 + 56 + 16, 1),
            (0x31c, 0x1a),
            (0x328, 66),
            (0x1000, 0x90),
            (0x2f00, 1),
        ] {
            let mut b = good.clone();
            b[at] = value;
            assert!(parse(&b).is_err(), "mutation at {at:#x}");
        }
        assert!(parse(&good[..0x1020]).is_err());
        assert!(parse(&vec![0; LIMIT + 1]).is_err());
    }
}
