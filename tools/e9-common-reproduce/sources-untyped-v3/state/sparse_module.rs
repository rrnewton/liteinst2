//! Narrow sparse EXEC wrapper. The old contiguous FileModule stays unchanged.
use super::oracle::{FileLoad, FileModule};
use std::fs::File;
use std::ops::{Deref, DerefMut};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

const PAGE: u64 = 4096;
const MAX_BODY: u64 = 1024 * 1024;
const USER_END: u64 = 1 << 47;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Error {
    Geometry,
    Address,
    Budget,
    Loads,
    Backing,
    Mapping(i32),
    ReturnedAddress,
    Ownership,
    Phase,
}

#[derive(Clone, Copy)]
struct Layout {
    min: u64,
    max: u64,
    source: u64,
    sparse: bool,
}

impl Layout {
    fn checked(min: u64, max: u64, source: u64, roots: usize, bytes: u64) -> Result<Self, Error> {
        if roots == 0 || roots > 2 || bytes == 0 || bytes > MAX_BODY {
            return Err(Error::Budget);
        }
        let sparse = match (min, max, source) {
            (0, 0x6000, 0x1000) => false,
            (0x400000, 0x405000, 0x401000) => true,
            _ => return Err(Error::Geometry),
        };
        let result = Self { min, max, source, sparse };
        if result.root_count() > roots || result.owned_bytes() > bytes {
            return Err(Error::Budget);
        }
        if max.checked_sub(min).filter(|span| *span > 0 && *span <= MAX_BODY).is_none() {
            return Err(Error::Geometry);
        }
        Ok(result)
    }

    fn root_count(self) -> usize { if self.sparse { 2 } else { 1 } }
    fn owned_bytes(self) -> u64 { if self.sparse { 40960 } else { 32768 } }
    fn kind(self) -> &'static str { if self.sparse { "sparse-exec" } else { "compact" } }

    fn roots(self, bias: u64) -> Result<Vec<(u64, u64)>, Error> {
        let start = bias.checked_add(self.min).and_then(|n| n.checked_sub(PAGE)).ok_or(Error::Address)?;
        let end = bias.checked_add(self.max).and_then(|n| n.checked_add(PAGE)).ok_or(Error::Address)?;
        let mut roots = vec![(start, end)];
        if self.sparse {
            roots.push((bias.checked_add(0xf000).ok_or(Error::Address)?,
                        bias.checked_add(0x12000).ok_or(Error::Address)?));
        }
        validate_roots(&roots)?;
        Ok(roots)
    }
}

fn validate_roots(roots: &[(u64, u64)]) -> Result<(), Error> {
    if roots.is_empty() || roots.len() > 2 { return Err(Error::Budget); }
    let mut total = 0_u64;
    for (index, &(start, end)) in roots.iter().enumerate() {
        if start == 0 || start % PAGE != 0 || end % PAGE != 0 || end > USER_END {
            return Err(Error::Address);
        }
        let len = end.checked_sub(start).filter(|n| *n > 0).ok_or(Error::Address)?;
        total = total.checked_add(len).ok_or(Error::Budget)?;
        if len > MAX_BODY || total > MAX_BODY { return Err(Error::Budget); }
        if roots[..index].iter().any(|&(a, z)| start < z && a < end) { return Err(Error::Ownership); }
    }
    Ok(())
}

/// One acquisition owner; replacements never change its original base/extent.
struct Root { start: u64, len: usize }

impl Root {
    fn reserve(start: u64, len: usize) -> Result<Self, Error> {
        let end = start.checked_add(len as u64).ok_or(Error::Address)?;
        validate_roots(&[(start, end)])?;
        // SAFETY: this request never replaces another mapping. Exact return is
        // required before any fixed replacement can use the acquired owner.
        let returned = unsafe { libc::mmap(start as *mut _, len, libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE, -1, 0) };
        Self::capture_return(start, len, returned)
    }

    fn capture_return(start: u64, len: usize, returned: *mut libc::c_void) -> Result<Self, Error> {
        if returned == libc::MAP_FAILED {
            return Err(Error::Mapping(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        // The returned mapping is owned immediately, including on mismatch.
        // This private function only consumes successful mmap results.
        let owner = Self { start: returned as u64, len };
        if owner.start != start { return Err(Error::ReturnedAddress); }
        Ok(owner)
    }

    fn acquire_checked(start: u64, len: usize, check: impl FnOnce(&Self) -> Result<(), Error>) -> Result<Self, Error> {
        let owner = Self::reserve(start, len)?;
        check(&owner)?;
        Ok(owner)
    }

    fn middle(&self) -> u64 { self.start + PAGE }

    fn replace_middle(&self, file: Option<&File>) -> Result<(), Error> {
        if self.len != 3 * PAGE as usize { return Err(Error::Geometry); }
        let (protection, flags, fd, offset) = match file {
            Some(file) => (libc::PROT_READ | libc::PROT_EXEC, libc::MAP_PRIVATE | libc::MAP_FIXED, file.as_raw_fd(), 0x5000),
            None => (libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0),
        };
        // SAFETY: exactly the middle page of this still-live exclusive owner.
        // Neither guard nor any unowned gap is a replacement target.
        let result = unsafe { libc::mmap(self.middle() as *mut _, PAGE as usize, protection, flags, fd, offset) };
        if result == libc::MAP_FAILED {
            return Err(Error::Mapping(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
        }
        assert_eq!(result as u64, self.middle(), "MAP_FIXED returned a different address");
        Ok(())
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        // SAFETY: this exact returned acquisition is owned once. All trace
        // children end before the containing BodyModule is dropped.
        assert_eq!(unsafe { libc::munmap(self.start as *mut _, self.len) }, 0);
    }
}

fn checked_backing(file: &File, expected: &[u8]) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let before = file.metadata().map_err(|_| Error::Backing)?;
    if !before.is_file() || before.len() != expected.len() as u64 || expected.len() > 16 * 1024 * 1024 {
        return Err(Error::Backing);
    }
    let mut bytes = vec![0; expected.len()];
    file.read_exact_at(&mut bytes, 0).map_err(|_| Error::Backing)?;
    let after = file.metadata().map_err(|_| Error::Backing)?;
    if bytes != expected || (before.dev(), before.ino(), before.len(), before.mtime(), before.mtime_nsec()) !=
        (after.dev(), after.ino(), after.len(), after.mtime(), after.mtime_nsec()) { return Err(Error::Backing); }
    Ok(())
}

fn same_load(a: &FileLoad, b: &FileLoad) -> bool {
    (a.vaddr, a.offset, a.file_size, a.memory_size, a.flags) ==
        (b.vaddr, b.offset, b.file_size, b.memory_size, b.flags)
}

fn load_copy(row: &FileLoad) -> FileLoad {
    FileLoad { vaddr: row.vaddr, offset: row.offset, file_size: row.file_size,
        memory_size: row.memory_size, flags: row.flags }
}

pub struct BodyModule {
    inner: FileModule,
    extra: Option<Root>,
    layout: Layout,
    original_loads: Vec<FileLoad>,
    rewritten: bool,
    pub expected_pages: Vec<(u64, Vec<u8>)>,
}

impl Deref for BodyModule {
    type Target = FileModule;
    fn deref(&self) -> &Self::Target { &self.inner }
}
impl DerefMut for BodyModule {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl BodyModule {
    pub fn new(min: u64, max: u64, source: u64, file: &File, expected: &[u8], loads: &[FileLoad]) -> Self {
        Self::try_new(min, max, source, file, expected, loads).expect("required body ownership acquisition")
    }

    fn try_new(min: u64, max: u64, source: u64, file: &File, expected: &[u8], loads: &[FileLoad]) -> Result<Self, Error> {
        let layout = Layout::checked(min, max, source, 2, MAX_BODY)?;
        checked_backing(file, expected)?;
        if loads.len() != 4 { return Err(Error::Loads); }
        let inner = FileModule::new(min, max, source, file, expected, loads);
        let roots = layout.roots(inner.bias)?;
        let extra = if layout.sparse {
            Some(Root::acquire_checked(roots[1].0, (roots[1].1 - roots[1].0) as usize,
                |owner| require_none(&read_maps()?, owner.start, owner.start + owner.len as u64))?)
        } else { None };
        let expected_pages = inner.expected_pages.clone();
        let result = Self { inner, extra, layout, original_loads: loads.iter().map(load_copy).collect(),
            rewritten: false, expected_pages };
        result.assert_maps(&read_maps()?)?;
        Ok(result)
    }

    pub fn kind(&self) -> &'static str { self.layout.kind() }
    pub fn root_count(&self) -> usize { self.layout.root_count() }
    pub fn owned_bytes(&self) -> u64 { self.layout.owned_bytes() }

    pub fn load(&mut self, file: &File, expected: &[u8], loads: &[FileLoad]) {
        self.try_load(file, expected, loads).expect("complete required body phase");
    }

    fn validate_phase(&self, loads: &[FileLoad]) -> Result<bool, Error> {
        let rewritten = match loads.len() { 4 => false, 5 => true, _ => return Err(Error::Loads) };
        for (old, row) in self.original_loads.iter().zip(loads) {
            if rewritten && old.vaddr & !(PAGE - 1) == self.layout.source {
                if (row.vaddr, row.offset, row.file_size, row.memory_size, row.flags) !=
                    (self.layout.source, 0x4000, PAGE, PAGE, 5) { return Err(Error::Loads); }
            } else if !same_load(old, row) { return Err(Error::Loads); }
        }
        if rewritten {
            let image = &loads[4];
            let pc = if self.layout.sparse { 0x10000 } else { 0x5000 };
            if (image.vaddr, image.offset, image.file_size, image.memory_size, image.flags) !=
                (pc, 0x5000, PAGE, PAGE, 5) { return Err(Error::Loads); }
        }
        Ok(rewritten)
    }

    fn try_load(&mut self, file: &File, expected: &[u8], loads: &[FileLoad]) -> Result<(), Error> {
        checked_backing(file, expected)?;
        let rewritten = self.validate_phase(loads)?;
        if self.rewritten == rewritten { return Err(Error::Phase); }
        if rewritten && expected.get(0x5000..0x6000).is_none() { return Err(Error::Backing); }
        if let Some(extra) = &self.extra {
            // This reset occurs after the preceding trace cohort is reaped.
            extra.replace_middle(None)?;
        }
        let compact = if self.layout.sparse { &loads[..4] } else { loads };
        self.inner.load(file, expected, compact);
        self.expected_pages = self.inner.expected_pages.clone();
        if self.layout.sparse && rewritten {
            let extra = self.extra.as_ref().expect("sparse owner retained");
            extra.replace_middle(Some(file))?;
            let bytes = expected.get(0x5000..0x6000).ok_or(Error::Backing)?;
            // SAFETY: a successful exact RX file replacement made this owned
            // page readable. The full file fd was authenticated before writes.
            let actual = unsafe { core::slice::from_raw_parts(extra.middle() as *const u8, PAGE as usize) };
            if actual != bytes { return Err(Error::Backing); }
            self.expected_pages.push((extra.middle(), bytes.to_vec()));
            self.expected_pages.sort_by_key(|row| row.0);
        }
        self.rewritten = rewritten;
        if self.expected_pages.len() != if rewritten { 6 } else { 5 } { return Err(Error::Loads); }
        self.assert_maps(&read_maps()?)?;
        Ok(())
    }

    pub fn ownership_tsv(&self, maps: &str) -> String {
        self.assert_maps(maps).expect("all owned phase protections");
        let mut out = String::from("index\tstart\tend\tinterior_start\tinterior_end\tkind\trewritten\n");
        for (index, (start, end)) in self.layout.roots(self.bias).unwrap().into_iter().enumerate() {
            out.push_str(&format!("{index}\t{start}\t{end}\t{}\t{}\t{}\t{}\n",
                start + PAGE, end - PAGE, self.kind(), self.rewritten));
        }
        out
    }

    fn assert_maps(&self, maps: &str) -> Result<(), Error> {
        let roots = self.layout.roots(self.bias)?;
        for &(start, end) in &roots {
            require_none(maps, start, start + PAGE)?;
            require_none(maps, end - PAGE, end)?;
            for page in ((start + PAGE)..(end - PAGE)).step_by(PAGE as usize) {
                if !self.expected_pages.iter().any(|row| row.0 == page) {
                    require_none(maps, page, page + PAGE)?;
                }
            }
        }
        if self.layout.sparse {
            let extra = self.extra.as_ref().ok_or(Error::Ownership)?;
            if (extra.start, extra.start + extra.len as u64) != roots[1] { return Err(Error::Ownership); }
        }
        Ok(())
    }
}

fn read_maps() -> Result<String, Error> {
    use std::io::Read;
    let mut raw = String::new();
    File::open("/proc/self/maps").map_err(|_| Error::Ownership)?.take(1024 * 1024 + 1)
        .read_to_string(&mut raw).map_err(|_| Error::Ownership)?;
    if raw.len() > 1024 * 1024 || raw.lines().count() > 4096 { return Err(Error::Ownership); }
    Ok(raw)
}

fn require_none(maps: &str, start: u64, end: u64) -> Result<(), Error> {
    let mut cursor = start;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let bounds: Vec<_> = fields.first().ok_or(Error::Ownership)?.split('-').collect();
        if bounds.len() != 2 || fields.len() < 5 { return Err(Error::Ownership); }
        let low = u64::from_str_radix(bounds[0], 16).map_err(|_| Error::Ownership)?;
        let high = u64::from_str_radix(bounds[1], 16).map_err(|_| Error::Ownership)?;
        if low < end && start < high {
            if low > cursor || high <= cursor || fields.len() != 5 || fields[1] != "---p" ||
                fields[2] != "00000000" || fields[3] != "00:00" || fields[4] != "0" { return Err(Error::Ownership); }
            cursor = high.min(end);
        }
    }
    if cursor != end { return Err(Error::Ownership); }
    Ok(())
}

// Controls below execute only when root runs the separately bound control
// invocation. They do not launch application code or replace the old cohort.
fn anonymous(len: usize) -> Root {
    // SAFETY: a fresh anonymous allocation, no fixed address or replacement.
    let pointer = unsafe { libc::mmap(core::ptr::null_mut(), len, libc::PROT_NONE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
    assert_ne!(pointer, libc::MAP_FAILED);
    Root { start: pointer as u64, len }
}

fn assert_unmapped(start: u64, len: usize) {
    for address in (start..start + len as u64).step_by(PAGE as usize) {
        let mut residency = 0_u8;
        // SAFETY: mincore reports mapping status without reading application
        // memory. It does not acquire or modify the queried region.
        assert_eq!(unsafe { libc::mincore(address as *mut _, PAGE as usize, &mut residency) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOMEM));
    }
}

pub fn controls(fixtures: &[super::Fixture]) {
    let mut positives = 0;
    let mut negatives = 0;
    for kind in ["compact", "sparse-exec"] {
        let fixture = fixtures.iter().find(|f| f.body_kind == kind).unwrap();
        let original = File::open(fixture.original_path).unwrap();
        let rewritten = File::open(fixture.output_path).unwrap();
        let mut module = BodyModule::new(fixture.min_vaddr, fixture.max_vaddr, fixture.source_page,
            &original, fixture.original, fixture.original_loads);
        let roots = module.layout.roots(module.bias).unwrap();
        assert_eq!(module.expected_pages.len(), 5);
        module.load(&rewritten, fixture.rewritten, fixture.output_loads);
        assert_eq!(module.expected_pages.len(), 6);
        let saved = module.expected_pages.clone();
        let mut changed: Vec<_> = fixture.output_loads.iter().map(load_copy).collect();
        changed[4].offset += PAGE;
        assert_eq!(module.try_load(&rewritten, fixture.rewritten, &changed), Err(Error::Loads));
        assert_eq!(module.expected_pages, saved); negatives += 1;
        changed[4] = load_copy(&fixture.output_loads[4]); changed[4].flags = 6;
        assert_eq!(module.try_load(&rewritten, fixture.rewritten, &changed), Err(Error::Loads));
        assert_eq!(module.expected_pages, saved); negatives += 1;
        assert_eq!(module.try_load(&original, fixture.rewritten, fixture.original_loads), Err(Error::Backing));
        assert_eq!(module.expected_pages, saved); negatives += 1;
        module.load(&original, fixture.original, fixture.original_loads);
        assert_eq!(module.expected_pages.len(), 5);
        if let Some(extra) = &module.extra {
            // Required inactive-page negative, repaired only inside its owner.
            assert_eq!(unsafe { libc::mprotect(extra.middle() as *mut _, PAGE as usize, libc::PROT_READ) }, 0);
            assert_eq!(module.assert_maps(&read_maps().unwrap()), Err(Error::Ownership));
            extra.replace_middle(None).unwrap(); negatives += 1;
            assert_eq!(unsafe { libc::mprotect(extra.middle() as *mut _, PAGE as usize, libc::PROT_READ | libc::PROT_EXEC) }, 0);
            assert_eq!(module.assert_maps(&read_maps().unwrap()), Err(Error::Ownership));
            extra.replace_middle(None).unwrap(); negatives += 1;
        }
        module.assert_maps(&read_maps().unwrap()).unwrap();
        drop(module);
        for (start, end) in roots { assert_unmapped(start, (end - start) as usize); }
        positives += 1;
    }
    // Actual occupied middle and both guard offsets refuse the whole root.
    for page in 0..3 {
        let occupied = anonymous(3 * PAGE as usize);
        let base = occupied.start;
        let len = occupied.len;
        // Temporarily release only two non-occupied pages; retain exact owner
        // for the remaining page so no fixed operation can replace it.
        let owned = Root { start: base + page * PAGE, len: PAGE as usize };
        core::mem::forget(occupied);
        for index in 0..3 {
            if index != page { assert_eq!(unsafe { libc::munmap((base + index * PAGE) as *mut _, PAGE as usize) }, 0); }
        }
        assert!(matches!(Root::reserve(base, len), Err(Error::Mapping(libc::EEXIST))));
        require_none(&read_maps().unwrap(), owned.start, owned.start + PAGE).unwrap();
        drop(owned); assert_unmapped(base, len); negatives += 1;
    }
    let requested = anonymous(3 * PAGE as usize);
    let returned = anonymous(3 * PAGE as usize);
    let returned_start = returned.start; let returned_len = returned.len;
    core::mem::forget(returned);
    assert!(matches!(Root::capture_return(requested.start, returned_len, returned_start as *mut _), Err(Error::ReturnedAddress)));
    assert_unmapped(returned_start, returned_len);
    require_none(&read_maps().unwrap(), requested.start, requested.start + requested.len as u64).unwrap();
    drop(requested); negatives += 1;
    let seed = anonymous(3 * PAGE as usize); let start = seed.start; let len = seed.len;
    drop(seed);
    assert!(matches!(Root::acquire_checked(start, len, |_| Err(Error::Phase)), Err(Error::Phase)));
    assert_unmapped(start, len); negatives += 1;
    assert!(matches!(Layout::checked(0x400000, 0x405000, 0x401000, 1, MAX_BODY), Err(Error::Budget))); negatives += 1;
    assert!(matches!(Layout::checked(0x400000, 0x405000, 0x401000, 2, 40959), Err(Error::Budget))); negatives += 1;
    assert_eq!(validate_roots(&[(PAGE, 4 * PAGE), (3 * PAGE, 5 * PAGE)]), Err(Error::Ownership)); negatives += 1;
    assert_eq!(Layout::checked(0, 0x6000, 0x1000, 2, MAX_BODY).unwrap().roots(0), Err(Error::Address)); negatives += 1;
    assert_eq!(Layout::checked(0x400000, 0x405000, 0x401000, 2, MAX_BODY).unwrap().roots(u64::MAX - PAGE + 1), Err(Error::Address)); negatives += 1;
    assert_eq!(positives, 2); assert_eq!(negatives, 18);
    println!("SPARSE_OWNERSHIP_CONTROLS_PASS positives=2 negatives=18");
}
