use super::{Error, Plan, Result, require};
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::rc::Rc;

const PAGE: usize = 4096;
const ENTRY: usize = 128;
const MAPS_CAP: usize = 1024 * 1024;

/// Sealed private copy. The unsafe constructor's lifetime contract also applies
/// in inherited children; no callable function pointer or writable alias escapes.
pub struct CopiedInvoke {
    base: *mut libc::c_void,
    expected: Vec<u8>,
    plan: Plan,
    local: PhantomData<Rc<()>>,
}

fn image_matches(actual: &[u8], expected: &[u8], plan: &Plan) -> Result<()> {
    require(
        actual.len() == PAGE
            && expected.len() == PAGE
            && actual == expected
            && expected[..ENTRY].iter().all(|&v| v == 0xcc)
            && expected.get(ENTRY..ENTRY + plan.bytes().len()) == Some(plan.bytes())
            && expected[ENTRY + plan.bytes().len()..]
                .iter()
                .all(|&v| v == 0xcc),
        Error::Source,
    )
}

fn hex(s: &str) -> Result<u64> {
    require(
        !s.is_empty() && s.bytes().all(|v| v.is_ascii_hexdigit()),
        Error::Mapping,
    )?;
    u64::from_str_radix(s, 16).map_err(|_| Error::Mapping)
}

fn mapping_classes(text: &str, base: u64) -> Result<()> {
    require(
        !text.is_empty() && text.len() <= MAPS_CAP && text.ends_with('\n') && text.is_ascii(),
        Error::Mapping,
    )?;
    let end = base.checked_add(3 * PAGE as u64).ok_or(Error::Mapping)?;
    let mut seen = [false; 3];
    let mut previous_end = 0;
    for line in text.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        require(fields.len() >= 5, Error::Mapping)?;
        let (lo, hi) = fields[0].split_once('-').ok_or(Error::Mapping)?;
        let (lo, hi) = (hex(lo)?, hex(hi)?);
        require(
            lo < hi && lo >= previous_end && lo % PAGE as u64 == 0 && hi % PAGE as u64 == 0,
            Error::Mapping,
        )?;
        previous_end = hi;
        if hi <= base || lo >= end {
            continue;
        }
        require(
            fields.len() == 5
                && fields[2] == "00000000"
                && fields[3] == "00:00"
                && fields[4] == "0",
            Error::Mapping,
        )?;
        for (n, expected) in ["---p", "r-xp", "---p"].into_iter().enumerate() {
            let start = base + (n * PAGE) as u64;
            let stop = start + PAGE as u64;
            if lo < stop && start < hi {
                require(
                    !seen[n] && lo <= start && stop <= hi && fields[1] == expected,
                    Error::Mapping,
                )?;
                seen[n] = true;
            }
        }
    }
    require(seen == [true; 3], Error::Mapping)
}

impl CopiedInvoke {
    /// # Safety
    /// The caller owns exclusive mapping lifetime, permits no concurrent writer,
    /// remap, signal/cancellation or active CET, and retains this owner through
    /// both tracees' normal reaps. A returned owner is sealed before any fork.
    pub unsafe fn new(plan: Plan) -> Result<Self> {
        require(
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) } == PAGE as libc::c_long,
            Error::Mapping,
        )?;
        let mut expected = vec![0xcc; PAGE];
        expected[ENTRY..ENTRY + plan.bytes().len()].copy_from_slice(plan.bytes());
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE * 3,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        require(base != libc::MAP_FAILED, Error::Mapping)?;
        let owner = Self {
            base,
            expected,
            plan,
            local: PhantomData,
        };
        let middle = unsafe { base.cast::<u8>().add(PAGE) };
        require(
            unsafe { libc::mprotect(middle.cast(), PAGE, libc::PROT_READ | libc::PROT_WRITE) } == 0,
            Error::Mapping,
        )?;
        unsafe {
            std::ptr::copy_nonoverlapping(owner.expected.as_ptr(), middle, PAGE);
        }
        require(
            unsafe { libc::mprotect(middle.cast(), PAGE, libc::PROT_READ | libc::PROT_EXEC) } == 0,
            Error::Mapping,
        )?;
        owner.verify()?;
        Ok(owner)
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn entry(&self) -> u64 {
        self.base as u64 + (PAGE + ENTRY) as u64
    }
    pub fn source(&self) -> (u64, &[u8]) {
        (self.base as u64 + PAGE as u64, &self.expected)
    }
    pub fn verify(&self) -> Result<()> {
        let mut bytes = Vec::new();
        File::open("/proc/self/maps")
            .map_err(|_| Error::Io)?
            .take((MAPS_CAP + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io)?;
        let maps = std::str::from_utf8(&bytes).map_err(|_| Error::Mapping)?;
        mapping_classes(maps, self.base as u64)?;
        let actual = unsafe { std::slice::from_raw_parts(self.base.cast::<u8>().add(PAGE), PAGE) };
        image_matches(actual, &self.expected, &self.plan)
    }
}
impl Drop for CopiedInvoke {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base, PAGE * 3);
        }
    }
}

#[cfg(test)]
pub(super) fn check_image_for_test(actual: &[u8], expected: &[u8], plan: &Plan) -> Result<()> {
    image_matches(actual, expected, plan)
}
#[cfg(test)]
pub(super) fn check_maps_for_test(text: &str, base: u64) -> Result<()> {
    mapping_classes(text, base)
}
