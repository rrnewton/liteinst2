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
// stat(2) and proc maps can use different device namespaces (Btrfs subvolumes
// are one example). This witness is derived only from an owned mapping of the
// retained fd. Its full stat pin and exact dentry path remain part of identity;
// a proc device/inode pair alone cannot distinguish subvolumes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct MappedIdentity {
    stamp: Stamp,
    path: Vec<u8>,
    major: u64,
    minor: u64,
}
fn canonical_path(path: &[u8]) -> bool {
    (2..=4095).contains(&path.len())
        && path[0] == b'/'
        && path.iter().all(|b| (0x21..=0x7e).contains(b))
        && path[1..]
            .split(|b| *b == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}
fn link_target_with(read: impl FnOnce(&mut [u8]) -> Result<usize, E>) -> Result<Vec<u8>, E> {
    let mut raw = [0u8; 4096];
    let n = read(&mut raw)?;
    if n == 0 || n >= raw.len() || !canonical_path(&raw[..n]) {
        return Err(E::Ownership);
    }
    Ok(raw[..n].to_vec())
}
fn link_target(path: &str) -> Result<Vec<u8>, E> {
    let path = std::ffi::CString::new(path).map_err(|_| E::Ownership)?;
    link_target_with(|raw| {
        // SAFETY: the path is terminated and raw is bounded writable storage.
        let n = unsafe { libc::readlink(path.as_ptr(), raw.as_mut_ptr().cast(), raw.len()) };
        if n < 0 { Err(E::Io) } else { Ok(n as usize) }
    })
}
fn fd_target(file: &File) -> Result<Vec<u8>, E> {
    link_target(&format!("/proc/self/fd/{}", file.as_raw_fd()))
}
fn mapping_target(mapping: &Map) -> Result<Vec<u8>, E> {
    // The link names the complete actual VMA, never an individual covered page.
    // Following map_files needs privileges on some kernels; readlink suffices.
    // An unavailable link refuses. There is no stat-device or pathname fallback.
    link_target(&format!(
        "/proc/self/map_files/{:x}-{:x}",
        mapping.start, mapping.end
    ))
}
fn same_file_with(
    mapping: &Map,
    identity: &MappedIdentity,
    target: impl FnOnce(&Map) -> Result<Vec<u8>, E>,
) -> Result<bool, E> {
    if mapping.inode != identity.stamp.ino
        || mapping.major != identity.major
        || mapping.minor != identity.minor
    {
        return Ok(false);
    }
    let actual = target(mapping)?;
    if !canonical_path(&actual) || actual != mapping.name {
        return Err(E::Ownership);
    }
    // Equal proc device/inode numbers on different subvolumes do not grant
    // ownership. A declared owner must additionally match this exact dentry.
    Ok(actual == identity.path)
}
fn same_file(mapping: &Map, owner: &Pinned) -> Result<bool, E> {
    same_file_with(mapping, &owner.identity, mapping_target)
}
fn file_maps<'a>(maps: &'a [Map], owner: &Pinned) -> Result<Vec<&'a Map>, E> {
    let mut owned = Vec::new();
    for mapping in maps {
        if same_file(mapping, owner)? {
            owned.push(mapping);
        }
    }
    Ok(owned)
}
fn calibrated_identity(
    pin: Stamp,
    path: &[u8],
    address: u64,
    maps: &[Map],
    target: &[u8],
) -> Result<MappedIdentity, E> {
    let end = address.checked_add(c::PAGE).ok_or(E::Ownership)?;
    let rows = maps
        .iter()
        .filter(|m| m.start <= address && end <= m.end)
        .collect::<Vec<_>>();
    if rows.len() != 1 || !canonical_path(path) || target != path {
        return Err(E::Ownership);
    }
    let row = rows[0];
    if row.start != address
        || row.end != end
        || row.flags != 4
        || row.offset != 0
        || row.inode != pin.ino
        || row.name != path
    {
        return Err(E::Ownership);
    }
    Ok(MappedIdentity {
        stamp: pin,
        path: path.to_vec(),
        major: row.major,
        minor: row.minor,
    })
}
fn release_probe_with(
    base: &mut Option<usize>,
    unmap: impl FnOnce(usize, usize) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(address) = *base {
        unmap(address, 3 * c::PAGE as usize)?;
        *base = None;
    }
    Ok(())
}
struct ProbeReservation {
    base: Option<usize>,
}
impl ProbeReservation {
    fn close(&mut self) -> Result<(), E> {
        release_probe_with(&mut self.base, |address, length| {
            // SAFETY: this whole reservation remains exclusively owned here.
            if unsafe { libc::munmap(address as *mut libc::c_void, length) } != 0 {
                return Err(E::Io);
            }
            Ok(())
        })
    }
}
impl Drop for ProbeReservation {
    fn drop(&mut self) {
        // Every ordinary path explicitly checks close; this is an error/unwind
        // backstop. A failed explicit close can never become successful admission.
        let _ = self.close();
    }
}
fn open_file(path: &[u8]) -> Result<File, E> {
    if !canonical_path(path) {
        return Err(E::Ownership);
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(std::ffi::OsStr::from_bytes(path)))
        .map_err(|_| E::Io)
}
fn check_file(file: &File, pin: Stamp, path: &[u8]) -> Result<(), E> {
    no_capability(file)?;
    if stamp(file)? != pin || fd_target(file)? != path {
        return Err(E::Ownership);
    }
    // The retained fd remains authoritative. Reopening only checks that its
    // exact canonical dentry still names the same complete stat identity.
    let reopened = open_file(path)?;
    no_capability(&reopened)?;
    if stamp(&reopened)? != pin || fd_target(&reopened)? != path {
        return Err(E::Ownership);
    }
    Ok(())
}
fn calibrate_file(file: &File, pin: Stamp, path: &[u8]) -> Result<MappedIdentity, E> {
    check_file(file, pin, path)?;
    // SAFETY: a kernel-chosen private non-executable reservation; no existing
    // address is replaced by this initial allocation.
    let base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            3 * c::PAGE as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(E::Io);
    }
    let mut reservation = ProbeReservation {
        base: Some(base as usize),
    };
    let checked = (|| {
        let address = (base as usize)
            .checked_add(c::PAGE as usize)
            .ok_or(E::Ownership)?;
        // SAFETY: only the middle page of our own three-page reservation is
        // replaced. Guards prevent merging with any other file-backed VMA.
        let mapped = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                c::PAGE as usize,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                file.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(E::Io);
        }
        if mapped as usize != address {
            return Err(E::Ownership);
        }
        let maps = maps(&observation("/proc/self/maps", OBSERVATION_BYTES)?)?;
        let row = cover(&maps, address as u64, c::PAGE)?;
        let identity =
            calibrated_identity(pin, path, address as u64, &maps, &mapping_target(row)?)?;
        check_file(file, pin, path)?;
        Ok(identity)
    })();
    // Close before returning either success or failure. In particular, all such
    // mappings are gone before the complete executable/file ownership snapshot.
    reservation.close()?;
    checked
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
    identity: MappedIdentity,
    content: ContentId,
}
impl Pinned {
    fn from_file(file: File, expected_path: Option<&[u8]>) -> Result<Self, E> {
        no_capability(&file)?;
        let pin = stamp(&file)?;
        let path = fd_target(&file)?;
        if expected_path.is_some_and(|expected| expected != path.as_slice()) {
            return Err(E::Ownership);
        }
        let content = ContentId::of(&bytes(&file, c::MAX_FILE)?);
        let identity = calibrate_file(&file, pin, &path)?;
        Ok(Self {
            file,
            identity,
            content,
        })
    }
    fn check(&self) -> Result<(), E> {
        check_file(&self.file, self.identity.stamp, &self.identity.path)
    }
    fn read(&self) -> Result<Vec<u8>, E> {
        self.check()?;
        let result = bytes(&self.file, c::MAX_FILE)?;
        if ContentId::of(&result) != self.content {
            return Err(E::Ownership);
        }
        self.check()?;
        Ok(result)
    }
}
pub(super) struct Owned {
    main: Pinned,
    dependencies: Vec<Pinned>,
    bootstrap: Pinned,
    embedded: &'static [u8],
    loader_base: u64,
}
impl Owned {
    fn check_files(&self) -> Result<(), E> {
        for p in std::iter::once(&self.main)
            .chain(&self.dependencies)
            .chain(std::iter::once(&self.bootstrap))
        {
            p.check()?;
        }
        Ok(())
    }
    fn runtime_pages(
        &self,
        catalog: &Catalog,
        mapped: &[Map],
    ) -> Result<std::collections::BTreeSet<u64>, E> {
        let policy = &catalog.input().policy;
        if self.dependencies.len() != policy.dependencies.len()
            || self.bootstrap.identity.path != policy.bootstrap_dso
        {
            return Err(E::Ownership);
        }
        let here = observe as *const () as usize as u64;
        let code = cover(mapped, here, 1)?;
        let data = cover(
            mapped,
            self.embedded.as_ptr() as usize as u64,
            self.embedded.len() as u64,
        )?;
        if code.flags != 5
            || data.flags != 4
            || !same_file(code, &self.bootstrap)?
            || !same_file(data, &self.bootstrap)?
        {
            return Err(E::Ownership);
        }
        let mut total = 0usize;
        let mut runtime_pages = std::collections::BTreeSet::new();
        for (d, p) in policy.dependencies.iter().zip(&self.dependencies) {
            let b = p.read()?;
            total = total.checked_add(b.len()).ok_or(E::Ownership)?;
            if total > DEPENDENCY_BYTES
                || p.identity.path != d.path
                || ContentId::of(&b) != d.identity
                || file_maps(mapped, p)?.is_empty()
            {
                return Err(E::Ownership);
            }
            runtime_elf(&b, p, mapped, &mut runtime_pages)?;
        }
        let bootstrap_bytes = self.bootstrap.read()?;
        total = total
            .checked_add(bootstrap_bytes.len())
            .ok_or(E::Ownership)?;
        if total > DEPENDENCY_BYTES {
            return Err(E::Ownership);
        }
        runtime_elf(
            &bootstrap_bytes,
            &self.bootstrap,
            mapped,
            &mut runtime_pages,
        )?;
        let loader = policy
            .dependencies
            .iter()
            .position(|d| d.path == policy.interpreter)
            .ok_or(E::Ownership)?;
        if !same_file(
            cover(mapped, self.loader_base, 1)?,
            &self.dependencies[loader],
        )? {
            return Err(E::Ownership);
        }
        if runtime_pages.len() > 256 * 1024 * 1024 / 4096 {
            return Err(E::Ownership);
        }
        Ok(runtime_pages)
    }
    pub(super) fn recheck(&self, catalog: &Catalog) -> Result<(), E> {
        single_thread()?;
        state(catalog)?;
        self.check_files()?;
        if self.main.read()? != catalog.input().main {
            return Err(E::Ownership);
        }
        let mapped = maps(&observation("/proc/self/maps", OBSERVATION_BYTES)?)?;
        check_main(catalog, &self.main, &mapped)?;
        let runtime_pages = self.runtime_pages(catalog, &mapped)?;
        // Revalidate every declared runtime owner after staging. Do not apply
        // the initial anonymous-executable allowlist to staged router storage;
        // that whole-process check belongs only to the pre-staging boundary.
        for p in std::iter::once(&self.bootstrap).chain(&self.dependencies) {
            for m in file_maps(&mapped, p)? {
                for page in (m.start..m.end).step_by(4096) {
                    if !runtime_pages.contains(&page) {
                        return Err(E::Ownership);
                    }
                }
            }
        }
        self.check_files()
    }
}
fn open_pin(path: &[u8]) -> Result<Pinned, E> {
    Pinned::from_file(open_file(path)?, Some(path))
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
    let main = Pinned::from_file(f, None)?;
    if main.read()? != catalog.input().main {
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
    let policy = &catalog.input().policy;
    let mut dependencies = Vec::new();
    let mut total = 0usize;
    let mut identities = std::collections::BTreeSet::new();
    identities.insert((main.identity.stamp.dev, main.identity.stamp.ino));
    for d in &policy.dependencies {
        let p = open_pin(&d.path)?;
        total = total
            .checked_add(p.identity.stamp.len as usize)
            .ok_or(E::Ownership)?;
        if total > DEPENDENCY_BYTES || p.content != d.identity {
            return Err(E::Ownership);
        }
        if !identities.insert((p.identity.stamp.dev, p.identity.stamp.ino)) {
            return Err(E::Ownership);
        }
        dependencies.push(p);
    }
    let bootstrap = open_pin(&policy.bootstrap_dso)?;
    total = total
        .checked_add(bootstrap.identity.stamp.len as usize)
        .ok_or(E::Ownership)?;
    if total > DEPENDENCY_BYTES
        || !identities.insert((bootstrap.identity.stamp.dev, bootstrap.identity.stamp.ino))
    {
        return Err(E::Ownership);
    }
    let owned = Owned {
        main,
        dependencies,
        bootstrap,
        embedded,
        loader_base: get(7)?,
    };
    // Every retained fd has now been calibrated and every probe explicitly
    // unmapped. No calibration VMA can contaminate the complete file roster.
    owned.check_files()?;
    let mapped = maps(&observation("/proc/self/maps", OBSERVATION_BYTES)?)?;
    check_main(catalog, &owned.main, &mapped)?;
    let runtime_pages = owned.runtime_pages(catalog, &mapped)?;
    for m in &mapped {
        if same_file(m, &owned.main)? {
            continue;
        }
        if m.inode != 0 {
            let mut recognized = same_file(m, &owned.bootstrap)?;
            for p in &owned.dependencies {
                recognized |= same_file(m, p)?;
            }
            if !recognized {
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
    owned.check_files()?;
    Ok(owned)
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
    let bases = file_maps(maps, owner)?
        .into_iter()
        .filter(|m| m.offset == 0)
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
                if !same_file(m, owner)? || m.offset + page - m.start != offset {
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
                if !same_file(m, main)? || m.offset + page - m.start != offset {
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
    for m in file_maps(maps, main)? {
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

#[cfg(test)]
#[path = "host_identity_tests.rs"]
mod identity_tests;
