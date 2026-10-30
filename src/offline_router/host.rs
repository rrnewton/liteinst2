//! Linux observations; all executable ownership is checked before route staging.
use super::StartupError as E;
use liteinst_artifact::{
    ContentId,
    elf64::SegmentType,
    startup::{self as c, Catalog},
};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
};

const OBSERVATION_BYTES: usize = 1024 * 1024;
const DEPENDENCY_BYTES: usize = 128 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtimens: i64,
    ctime: i64,
    ctimens: i64,
}
fn stamp(f: &File) -> Result<Stamp, E> {
    let m = f.metadata().map_err(|_| E::Io)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
        mtime: m.mtime(),
        mtimens: m.mtime_nsec(),
        ctime: m.ctime(),
        ctimens: m.ctime_nsec(),
    })
}
fn bytes(f: &File, cap: usize) -> Result<Vec<u8>, E> {
    let before = stamp(f)?;
    if before.len > cap as u64
        || before.mode & libc::S_IFMT != libc::S_IFREG
        || before.mode & 0o6000 != 0
    {
        return Err(E::Ownership);
    }
    let mut b = vec![0; before.len as usize];
    f.read_exact_at(&mut b, 0).map_err(|_| E::Io)?;
    if stamp(f)? != before {
        return Err(E::Ownership);
    }
    Ok(b)
}
fn no_capability(f: &File) -> Result<(), E> {
    // SAFETY: the descriptor remains owned, name is terminated; zero length queries only.
    let n = unsafe {
        libc::fgetxattr(
            f.as_raw_fd(),
            c"security.capability".as_ptr(),
            core::ptr::null_mut(),
            0,
        )
    };
    if n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
        return Err(E::Ownership);
    }
    Ok(())
}
fn observation(path: &str, cap: usize) -> Result<Vec<u8>, E> {
    let f = File::open(path).map_err(|_| E::Io)?;
    let mut b = Vec::new();
    f.take(cap as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| E::Io)?;
    if b.len() > cap {
        return Err(E::Ownership);
    }
    Ok(b)
}
#[derive(Debug, Clone, Eq, PartialEq)]
struct Map {
    start: u64,
    end: u64,
    flags: u32,
    offset: u64,
    major: u64,
    minor: u64,
    inode: u64,
    name: Vec<u8>,
}
fn maps(raw: &[u8]) -> Result<Vec<Map>, E> {
    let text = std::str::from_utf8(raw).map_err(|_| E::Ownership)?;
    if !text.ends_with('\n') {
        return Err(E::Ownership);
    }
    let mut result = Vec::new();
    let mut end = 0;
    for line in text.lines() {
        if result.len() >= 8192 {
            return Err(E::Ownership);
        }
        let p: Vec<_> = line.split_whitespace().collect();
        if !(5..=6).contains(&p.len()) {
            return Err(E::Ownership);
        }
        let (lo, hi) = p[0].split_once('-').ok_or(E::Ownership)?;
        let start = hex(lo)?;
        let stop = hex(hi)?;
        let (major, minor) = p[3].split_once(':').ok_or(E::Ownership)?;
        let mode = p[1].as_bytes();
        if mode.len() != 4
            || mode[3] != b'p'
            || !matches!(mode[0], b'r' | b'-')
            || !matches!(mode[1], b'w' | b'-')
            || !matches!(mode[2], b'x' | b'-')
            || start < end
            || start >= stop
        {
            return Err(E::Ownership);
        }
        let flags = u32::from(mode[0] == b'r') * 4
            + u32::from(mode[1] == b'w') * 2
            + u32::from(mode[2] == b'x');
        if flags & 3 == 3 {
            return Err(E::Ownership);
        }
        result.push(Map {
            start,
            end: stop,
            flags,
            offset: hex(p[2])?,
            major: hex(major)?,
            minor: hex(minor)?,
            inode: p[4].parse().map_err(|_| E::Ownership)?,
            name: p.get(5).map_or(&[][..], |s| s.as_bytes()).to_vec(),
        });
        end = stop;
    }
    Ok(result)
}
fn hex(s: &str) -> Result<u64, E> {
    u64::from_str_radix(s, 16).map_err(|_| E::Ownership)
}
fn same_file(m: &Map, s: Stamp) -> bool {
    m.inode == s.ino
        && m.major == u64::from(libc::major(s.dev))
        && m.minor == u64::from(libc::minor(s.dev))
}
fn cover(maps: &[Map], start: u64, len: u64) -> Result<&Map, E> {
    let end = start.checked_add(len).ok_or(E::Ownership)?;
    maps.iter()
        .find(|m| m.start <= start && end <= m.end)
        .ok_or(E::Ownership)
}
fn auxv(raw: &[u8]) -> Result<std::collections::BTreeMap<u64, u64>, E> {
    if raw.len() & 15 != 0 || raw.len() > 4096 {
        return Err(E::Ownership);
    }
    let mut a = std::collections::BTreeMap::new();
    let mut ended = false;
    for p in raw.chunks_exact(16) {
        let k = u64::from_ne_bytes(p[..8].try_into().map_err(|_| E::Ownership)?);
        let v = u64::from_ne_bytes(p[8..].try_into().map_err(|_| E::Ownership)?);
        if ended || (k == 0 && v != 0) || a.insert(k, v).is_some() {
            return Err(E::Ownership);
        }
        ended = k == 0;
    }
    if !ended {
        return Err(E::Ownership);
    }
    Ok(a)
}
fn single_thread() -> Result<(), E> {
    // SAFETY: these syscalls take no pointers and inspect the current process.
    let pid = unsafe { libc::getpid() };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if i64::from(pid) != tid {
        return Err(E::Platform);
    }
    let mut tasks = std::fs::read_dir("/proc/self/task").map_err(|_| E::Io)?;
    let first = tasks.next().ok_or(E::Platform)?.map_err(|_| E::Io)?;
    if first.file_name() != std::ffi::OsString::from(pid.to_string()) || tasks.next().is_some() {
        return Err(E::Platform);
    }
    Ok(())
}
fn environment() -> Result<(), E> {
    let mut n = 0usize;
    let mut bytes = 0usize;
    for (key, value) in std::env::vars_os() {
        n += 1;
        bytes = bytes
            .checked_add(key.as_bytes().len() + value.as_bytes().len())
            .ok_or(E::Platform)?;
        if n > 256
            || bytes > 65536
            || key.as_bytes().starts_with(b"LD_")
            || key == "GLIBC_TUNABLES"
            || key == "LIBC_FATAL_STDERR_"
        {
            return Err(E::Platform);
        }
    }
    Ok(())
}
fn state(catalog: &Catalog) -> Result<(), E> {
    let s = &catalog.input().policy.state;
    let expected = match s.format {
        1 => crate::trampoline::SavedExtendedStateLayout::describe_target_fxsave64(),
        2 => crate::trampoline::SavedExtendedStateLayout::describe_target_xsave64(
            s.mask,
            &s.components,
        )
        .map_err(|_| E::Platform)?,
        _ => return Err(E::Platform),
    };
    if expected.len() != s.allocation
        || expected.image_len() != s.image
        || expected.mask() != s.mask
        || crate::trampoline::SavedExtendedStateLayout::detect().map_err(|_| E::Platform)?
            != expected
    {
        return Err(E::Platform);
    }
    // Linux ARCH_SHSTK_STATUS. EINVAL means this kernel has no userspace SHSTK API;
    // IBT absence still belongs to the explicitly unsafe pinned-loader contract.
    let mut status = 0u64;
    // SAFETY: status is valid writable storage for the documented unsigned-long output.
    let rc = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut status as *mut u64) };
    if (rc == 0 && status != 0)
        || (rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL))
    {
        return Err(E::Platform);
    }
    Ok(())
}
struct Pinned {
    file: File,
    stamp: Stamp,
}
pub(super) struct Owned {
    main: Pinned,
    dependencies: Vec<Pinned>,
    bootstrap: Pinned,
}
impl Owned {
    pub(super) fn recheck(&self, catalog: &Catalog) -> Result<(), E> {
        single_thread()?;
        state(catalog)?;
        for p in std::iter::once(&self.main)
            .chain(&self.dependencies)
            .chain(std::iter::once(&self.bootstrap))
        {
            if stamp(&p.file)? != p.stamp {
                return Err(E::Ownership);
            }
        }
        if bytes(&self.main.file, c::MAX_FILE)? != catalog.input().main {
            return Err(E::Ownership);
        }
        check_main(
            catalog,
            &self.main,
            &maps(&observation("/proc/self/maps", OBSERVATION_BYTES)?)?,
        )
    }
}
fn open_pin(path: &[u8]) -> Result<Pinned, E> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(std::ffi::OsStr::from_bytes(path)))
        .map_err(|_| E::Io)?;
    no_capability(&f)?;
    let s = stamp(&f)?;
    if s.mode & libc::S_IFMT != libc::S_IFREG || s.mode & 0o6000 != 0 {
        return Err(E::Ownership);
    }
    Ok(Pinned { file: f, stamp: s })
}
pub(super) fn observe(catalog: &Catalog, embedded: &'static [u8]) -> Result<Owned, E> {
    single_thread()?;
    environment()?;
    state(catalog)?;
    // /proc/self/exe is intentionally a kernel magic link. Its FD, not a caller
    // pathname or argv[0], remains the authoritative main-file owner.
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/proc/self/exe")
        .map_err(|_| E::Io)?;
    no_capability(&f)?;
    let main = Pinned {
        stamp: stamp(&f)?,
        file: f,
    };
    if bytes(&main.file, c::MAX_FILE)? != catalog.input().main {
        return Err(E::Ownership);
    }
    let elf = c::parse(&catalog.input().main)?;
    let a = auxv(&observation("/proc/self/auxv", 4096)?)?;
    let get = |k| a.get(&k).copied().ok_or(E::Ownership);
    if get(3)? != catalog.validate_startup(&elf)?
        || get(4)? != 56
        || get(5)? != u64::from(elf.header().program_count)
        || get(6)? != c::PAGE
        || get(9)? != elf.header().entry.0
        || get(23)? != 0
        || get(7)? == 0
    {
        return Err(E::Ownership);
    }
    // Real/effective IDs must agree even when AT_SECURE was forged in a data input.
    if get(11)? != get(12)? || get(13)? != get(14)? {
        return Err(E::Ownership);
    }
    let mapped = maps(&observation("/proc/self/maps", OBSERVATION_BYTES)?)?;
    check_main(catalog, &main, &mapped)?;
    let policy = &catalog.input().policy;
    let bootstrap = open_pin(&policy.bootstrap_dso)?;
    let here = observe as *const () as usize as u64;
    let code = cover(&mapped, here, 1)?;
    let data = cover(
        &mapped,
        embedded.as_ptr() as usize as u64,
        embedded.len() as u64,
    )?;
    if code.flags != 5
        || data.flags != 4
        || !same_file(code, bootstrap.stamp)
        || !same_file(data, bootstrap.stamp)
    {
        return Err(E::Ownership);
    }
    let mut dependencies = Vec::new();
    let mut total = 0usize;
    let mut runtime_pages = std::collections::BTreeSet::new();
    let mut identities = std::collections::BTreeSet::new();
    identities.insert((main.stamp.dev, main.stamp.ino));
    if !identities.insert((bootstrap.stamp.dev, bootstrap.stamp.ino)) {
        return Err(E::Ownership);
    }
    for d in &policy.dependencies {
        let p = open_pin(&d.path)?;
        let b = bytes(&p.file, c::MAX_FILE)?;
        total = total.checked_add(b.len()).ok_or(E::Ownership)?;
        if total > DEPENDENCY_BYTES
            || ContentId::of(&b) != d.identity
            || !mapped.iter().any(|m| same_file(m, p.stamp))
        {
            return Err(E::Ownership);
        }
        if !identities.insert((p.stamp.dev, p.stamp.ino)) {
            return Err(E::Ownership);
        }
        runtime_elf(&b, &p, &mapped, &mut runtime_pages)?;
        dependencies.push(p);
    }
    let bootstrap_bytes = bytes(&bootstrap.file, c::MAX_FILE)?;
    total = total
        .checked_add(bootstrap_bytes.len())
        .ok_or(E::Ownership)?;
    if total > DEPENDENCY_BYTES {
        return Err(E::Ownership);
    }
    runtime_elf(&bootstrap_bytes, &bootstrap, &mapped, &mut runtime_pages)?;
    let loader = policy
        .dependencies
        .iter()
        .position(|d| d.path == policy.interpreter)
        .ok_or(E::Ownership)?;
    if !same_file(cover(&mapped, get(7)?, 1)?, dependencies[loader].stamp) {
        return Err(E::Ownership);
    }
    for m in &mapped {
        if same_file(m, main.stamp) {
            continue;
        }
        if m.inode != 0 {
            if !same_file(m, bootstrap.stamp) && !dependencies.iter().any(|p| same_file(m, p.stamp))
            {
                return Err(E::Ownership);
            }
            for page in (m.start..m.end).step_by(4096) {
                if !runtime_pages.contains(&page) {
                    return Err(E::Ownership);
                }
            }
        } else if m.flags & 1 != 0
            && m.name != b"[vdso]"
            && !(m.name == b"[vsyscall]"
                && m.start == 0xffff_ffff_ff60_0000
                && m.end == 0xffff_ffff_ff60_1000
                && matches!(m.flags, 1 | 5))
        {
            return Err(E::Ownership);
        }
    }
    if runtime_pages.len() > 256 * 1024 * 1024 / 4096 {
        return Err(E::Ownership);
    }
    let min_signal = get(51)?;
    let reserve = min_signal
        .checked_mul(2)
        .and_then(|n| n.checked_add(policy.state.allocation))
        .and_then(|n| n.checked_add(8192))
        .ok_or(E::Platform)?;
    let marker = 0u8;
    let current = &marker as *const u8 as usize as u64;
    let stack = cover(&mapped, current, 1)?;
    if min_signal == 0
        || reserve >= policy.app_stack.len
        || stack.name != b"[stack]"
        || stack.flags != 6
        || current - stack.start < reserve
    {
        return Err(E::Platform);
    }
    Ok(Owned {
        main,
        dependencies,
        bootstrap,
    })
}
fn runtime_elf(
    bytes: &[u8],
    owner: &Pinned,
    maps: &[Map],
    pages: &mut std::collections::BTreeSet<u64>,
) -> Result<(), E> {
    let elf = c::parse(bytes)?;
    if elf.header().object_type != liteinst_artifact::elf64::ObjectType::Dynamic
        || elf.segments(SegmentType::GnuRelro).count() != 1
        || elf
            .segments(SegmentType::GnuStack)
            .any(|p| p.flags.executable())
        || elf
            .segments(SegmentType::Load)
            .any(|p| p.flags.writable() && p.flags.executable())
    {
        return Err(E::Ownership);
    }
    let bases = maps
        .iter()
        .filter(|m| same_file(m, owner.stamp) && m.offset == 0)
        .collect::<Vec<_>>();
    let first = elf
        .segments(SegmentType::Load)
        .find(|p| p.offset.0 == 0 && p.file_size != 0)
        .ok_or(E::Ownership)?;
    if bases.len() != 1 {
        return Err(E::Ownership);
    }
    let bias = bases[0]
        .start
        .checked_sub(first.vaddr.0 & !4095)
        .ok_or(E::Ownership)?;
    let relro = elf
        .segments(SegmentType::GnuRelro)
        .next()
        .ok_or(E::Ownership)?;
    let relro_start = bias
        .checked_add(relro.vaddr.0 & !4095)
        .ok_or(E::Ownership)?;
    let relro_end = bias
        .checked_add(
            relro
                .vaddr
                .0
                .checked_add(relro.memory_size)
                .ok_or(E::Ownership)?
                & !4095,
        )
        .ok_or(E::Ownership)?;
    for p in elf
        .segments(SegmentType::Load)
        .filter(|p| p.memory_size != 0)
    {
        let start = bias.checked_add(p.vaddr.0 & !4095).ok_or(E::Ownership)?;
        let end = bias
            .checked_add(
                p.vaddr
                    .0
                    .checked_add(p.memory_size)
                    .and_then(|n| n.checked_add(4095))
                    .ok_or(E::Ownership)?
                    & !4095,
            )
            .ok_or(E::Ownership)?;
        if end > 1 << 47
            || end < start
            || (end - start) / 4096 > 65536
            || pages
                .len()
                .checked_add(((end - start) / 4096) as usize)
                .ok_or(E::Ownership)?
                > 65536
        {
            return Err(E::Ownership);
        }
        let file_end = bias
            .checked_add(
                p.vaddr
                    .0
                    .checked_add(p.file_size)
                    .and_then(|n| n.checked_add(4095))
                    .ok_or(E::Ownership)?
                    & !4095,
            )
            .ok_or(E::Ownership)?;
        for page in (start..end).step_by(4096) {
            if !pages.insert(page) {
                return Err(E::Ownership);
            }
            let m = cover(maps, page, 4096)?;
            let flags = if p.flags.0 == 6 && relro_start <= page && page + 4096 <= relro_end {
                4
            } else {
                p.flags.0
            };
            if m.flags != flags {
                return Err(E::Ownership);
            }
            if p.file_size != 0 && page < file_end {
                let offset = (p.offset.0 & !4095) + (page - start);
                if !same_file(m, owner.stamp) || m.offset + page - m.start != offset {
                    return Err(E::Ownership);
                }
            } else if m.inode != 0 || m.major != 0 || m.minor != 0 {
                return Err(E::Ownership);
            }
        }
    }
    Ok(())
}
fn check_main(catalog: &Catalog, main: &Pinned, maps: &[Map]) -> Result<(), E> {
    let file = &catalog.input().main;
    let elf = c::parse(file)?;
    let mem = File::open("/proc/self/mem").map_err(|_| E::Io)?;
    let mut expected_owners = std::collections::BTreeSet::new();
    for p in elf
        .segments(SegmentType::Load)
        .filter(|p| p.memory_size != 0)
    {
        let start = p.vaddr.0 & !(c::PAGE - 1);
        let end = (p.vaddr.0 + p.memory_size + c::PAGE - 1) & !(c::PAGE - 1);
        let file_start = p.offset.0 & !(c::PAGE - 1);
        let file_end = p.vaddr.0 + p.file_size;
        let rounded_file_end = (file_end + c::PAGE - 1) & !(c::PAGE - 1);
        for page in (start..end).step_by(c::PAGE as usize) {
            let m = cover(maps, page, c::PAGE)?;
            if m.flags != p.flags.0 {
                return Err(E::Ownership);
            }
            let file_backed = p.file_size != 0 && page < rounded_file_end;
            if file_backed {
                let offset = file_start + (page - start);
                if !same_file(m, main.stamp) || m.offset + page - m.start != offset {
                    return Err(E::Ownership);
                }
                expected_owners.insert(page);
            } else if m.inode != 0 || m.major != 0 || m.minor != 0 {
                return Err(E::Ownership);
            }
            let mut expected = [0u8; 4096];
            if file_backed {
                let offset = (file_start + page - start) as usize;
                let len = file.len().saturating_sub(offset).min(4096);
                if len != 0 {
                    expected[..len].copy_from_slice(&file[offset..offset + len]);
                }
                if p.memory_size > p.file_size && file_end < page + c::PAGE {
                    expected[(file_end.saturating_sub(page)) as usize..].fill(0);
                }
            }
            let mut actual = [0u8; 4096];
            mem.read_exact_at(&mut actual, page).map_err(|_| E::Io)?;
            if actual != expected {
                return Err(E::Ownership);
            }
        }
    }
    for m in maps.iter().filter(|m| same_file(m, main.stamp)) {
        for page in (m.start..m.end).step_by(4096) {
            if !expected_owners.remove(&page) {
                return Err(E::Ownership);
            }
        }
    }
    if !expected_owners.is_empty() {
        return Err(E::Ownership);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_maps_and_auxv_shapes() {
        let raw = b"00400000-00401000 r-xp 00000000 08:01 7 /pkg/main\n";
        let m = maps(raw).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].start, m[0].flags, m[0].inode), (0x400000, 5, 7));
        assert!(maps(b"00400000-00401000 rwxp 00000000 08:01 7 /pkg/main\n").is_err());
        assert!(maps(b"00400000-00401000 r-xs 00000000 08:01 7 /pkg/main\n").is_err());
        assert!(maps(b"00400000-00401000 r-xp 00000000 08:01 7 /pkg/main (deleted)\n").is_err());
        let mut a = Vec::new();
        for (k, v) in [(3u64, 0x400040u64), (0, 0)] {
            a.extend_from_slice(&k.to_ne_bytes());
            a.extend_from_slice(&v.to_ne_bytes());
        }
        assert_eq!(auxv(&a).unwrap().get(&3), Some(&0x400040));
        let mut duplicate = a[..16].to_vec();
        duplicate.extend_from_slice(&a);
        assert!(auxv(&duplicate).is_err());
        assert!(auxv(&a[..16]).is_err());
        let mut trailing = a.clone();
        trailing.extend_from_slice(&[0; 16]);
        assert!(auxv(&trailing).is_err());
    }
}
