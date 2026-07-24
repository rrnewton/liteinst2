//! Bounded rapid-probe profiling for compiler-marked x86-64 functions.

#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use core::ptr;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use liteinst2::rapid::{RapidProbe, RapidTogglePlan};
use liteinst2::scanner::InstructionScanner;
use object::{Object, ObjectSection, ObjectSymbol};

mod interval;
mod pmu;

pub use interval::{EpochReport, FunctionCount, MetricSummary, SampleClassSummary};
use interval::{FunctionEntry, ProfilerState, count_function};

/// Default maximum samples retained for one function in one epoch.
pub const DEFAULT_SAMPLE_LIMIT: u64 = 1_000;

const PATCHABLE_NOP: [u8; 5] = [0x0f, 0x1f, 0x44, 0x00, 0x08];
const PAGE_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 64 * 1024 * 1024;
const EXECUTABLE_BASE: usize = 0x4000_0000_0000;
const EXECUTABLE_STRIDE: usize = 0x2000_0000;
const EXECUTABLE_ATTEMPTS: usize = 32;

pub(crate) type BoxError = Box<dyn Error + Send + Sync + 'static>;

struct LoadedText {
    _writable: *mut u8,
    executable: *mut u8,
    _mapping_len: usize,
}

impl LoadedText {
    fn load(code: &[u8]) -> Result<Self, BoxError> {
        let mapping_len = code
            .len()
            .checked_add(PAGE_BYTES - 1)
            .map(|len| len / PAGE_BYTES * PAGE_BYTES)
            .ok_or("text mapping length overflow")?;
        let name = b"liteinst2-rapid-profiler\0";
        // SAFETY: the name is NUL terminated and flags are valid.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC,
            ) as libc::c_int
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fd is live and mapping_len fits off_t on x86-64.
        if unsafe { libc::ftruncate(fd, mapping_len as libc::off_t) } != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: fd is still live.
            unsafe { libc::close(fd) };
            return Err(error.into());
        }

        let executable = match map_executable(fd, mapping_len) {
            Ok(mapping) => mapping,
            Err(error) => {
                // SAFETY: fd is still live because no mapping retained it.
                unsafe { libc::close(fd) };
                return Err(error);
            }
        };
        // SAFETY: fd describes a mapping_len-byte memfd.
        let writable = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if writable == libc::MAP_FAILED {
            let error = std::io::Error::last_os_error();
            // SAFETY: executable and fd are live resources owned here.
            unsafe {
                libc::munmap(executable, mapping_len);
                libc::close(fd);
            }
            return Err(error.into());
        }
        // SAFETY: writable spans mapping_len bytes and code is no larger.
        unsafe { ptr::copy_nonoverlapping(code.as_ptr(), writable.cast::<u8>(), code.len()) };
        // SAFETY: both VMAs retain the memfd after close.
        if unsafe { libc::close(fd) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            _writable: writable.cast(),
            executable: executable.cast(),
            _mapping_len: mapping_len,
        })
    }

    fn writable_address(&self, offset: usize) -> *mut u8 {
        // SAFETY: validated function offsets fall inside the mapping.
        unsafe { self._writable.add(offset) }
    }

    fn executable_address(&self, offset: usize) -> u64 {
        // SAFETY: validated function offsets fall inside the mapping.
        unsafe { self.executable.add(offset) as usize as u64 }
    }
}

fn map_executable(fd: libc::c_int, mapping_len: usize) -> Result<*mut c_void, BoxError> {
    for attempt in 0..EXECUTABLE_ATTEMPTS {
        let address = EXECUTABLE_BASE
            .checked_add(attempt * EXECUTABLE_STRIDE)
            .ok_or("executable address overflow")?;
        // SAFETY: MAP_FIXED_NOREPLACE fails rather than replacing an existing VMA.
        let mapping = unsafe {
            libc::mmap(
                address as *mut c_void,
                mapping_len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            )
        };
        if mapping != libc::MAP_FAILED {
            return Ok(mapping);
        }
    }
    Err(format!(
        "could not reserve an executable mapping after {EXECUTABLE_ATTEMPTS} attempts: {}",
        std::io::Error::last_os_error()
    )
    .into())
}

#[derive(Clone, Debug)]
struct FunctionSymbol {
    name: String,
    offset: usize,
}

struct ParsedImage {
    code: Vec<u8>,
    functions: Vec<FunctionSymbol>,
}

fn parse_image(path: &Path) -> Result<ParsedImage, BoxError> {
    let bytes = fs::read(path)?;
    let file = object::File::parse(bytes.as_slice())?;
    if file.format() != object::BinaryFormat::Elf
        || file.architecture() != object::Architecture::X86_64
    {
        return Err("input must be a linked x86-64 ELF image".into());
    }
    let text = file
        .section_by_name(".text")
        .ok_or("input does not contain .text")?;
    if text.relocations().next().is_some() {
        return Err(".text still contains relocations; pass a linked ELF image".into());
    }
    let code = text.data()?.to_vec();
    if code.is_empty() || code.len() > MAX_TEXT_BYTES {
        return Err(format!(".text size must be in 1..={MAX_TEXT_BYTES} bytes").into());
    }
    let text_address = text.address();
    let text_index = text.index();
    let mut by_offset = BTreeMap::<usize, String>::new();
    for symbol in file.symbols() {
        if !symbol.is_definition()
            || symbol.kind() != object::SymbolKind::Text
            || symbol.section_index() != Some(text_index)
        {
            continue;
        }
        let name = symbol.name()?.to_owned();
        if name.is_empty() {
            continue;
        }
        let offset = symbol
            .address()
            .checked_sub(text_address)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("function {name} is outside .text"))?;
        let entry_end = offset
            .checked_add(PATCHABLE_NOP.len())
            .ok_or_else(|| format!("function {name} entry overflows its address space"))?;
        let entry = code
            .get(offset..entry_end)
            .ok_or_else(|| format!("function {name} has a truncated entry"))?;
        if entry != PATCHABLE_NOP {
            return Err(format!(
                "function {name} does not start with Clang -fpatchable-function-entry=5,0"
            )
            .into());
        }
        by_offset.entry(offset).or_insert(name);
    }
    if by_offset.is_empty() {
        return Err("no compiler-marked function symbols were found".into());
    }
    let functions = by_offset
        .into_iter()
        .map(|(offset, name)| FunctionSymbol { name, offset })
        .collect();
    Ok(ParsedImage { code, functions })
}

/// In-process profiler for a self-contained compiler-marked ELF text image.
pub struct RapidProfiler {
    _mapping: LoadedText,
    state: Box<ProfilerState>,
    workload_address: u64,
}

impl RapidProfiler {
    /// Loads `path`, discovers every marked function, and installs inactive probes.
    pub fn load(path: impl AsRef<Path>, workload: &str, limit: u64) -> Result<Self, BoxError> {
        if limit == 0 {
            return Err("sample limit must be greater than zero".into());
        }
        let image = parse_image(path.as_ref())?;
        let mapping = LoadedText::load(&image.code)?;
        validate_trampoline_pages(&mapping, &image.functions)?;
        let scanner = InstructionScanner::default();
        let region_base = mapping.executable_address(0);
        let scan = scanner.scan(&image.code, region_base)?;
        let mut entries = Vec::with_capacity(image.functions.len());
        let mut workload_address = None;
        for function in image.functions {
            let address = mapping.executable_address(function.offset);
            let plan = RapidTogglePlan::from_scan(
                &scanner,
                &scan,
                &image.code,
                region_base,
                address,
                count_function,
            )?;
            // SAFETY: LoadedText retains process-lifetime RW/RX aliases of the
            // immutable copied image, with matching page and cache-line offsets.
            let probe =
                unsafe { RapidProbe::install(plan, mapping.writable_address(function.offset))? };
            if function.name == workload {
                workload_address = Some(address);
            }
            entries.push(FunctionEntry::new(function.name, address, probe));
        }
        entries.sort_by_key(|entry| entry.address);
        let workload_address = workload_address
            .ok_or_else(|| format!("workload symbol {workload:?} was not found"))?;
        Ok(Self {
            _mapping: mapping,
            state: Box::new(ProfilerState::new(entries, limit)),
            workload_address,
        })
    }

    /// Resets, rearms, and runs one `extern "C" fn(u64) -> u64` workload epoch.
    pub fn run_epoch(&self, epoch: usize, iterations: u64) -> Result<EpochReport, BoxError> {
        self.state
            .run_epoch(epoch, iterations, self.workload_address)
    }

    /// Runs epochs whose start times are separated by at least `interval`.
    pub fn run_epochs(
        &self,
        epochs: usize,
        iterations: u64,
        interval: Duration,
    ) -> Result<Vec<EpochReport>, BoxError> {
        if epochs == 0 {
            return Err("epoch count must be greater than zero".into());
        }
        let mut reports = Vec::with_capacity(epochs);
        let mut next_start = Instant::now();
        for epoch in 1..=epochs {
            let now = Instant::now();
            if now < next_start {
                std::thread::sleep(next_start - now);
            }
            let started = Instant::now();
            reports.push(self.run_epoch(epoch, iterations)?);
            next_start = started
                .checked_add(interval)
                .ok_or("epoch interval exceeds Instant's representable range")?;
        }
        Ok(reports)
    }
}

fn validate_trampoline_pages(
    mapping: &LoadedText,
    functions: &[FunctionSymbol],
) -> Result<(), BoxError> {
    let displacement = i32::from_le_bytes(PATCHABLE_NOP[1..].try_into()?);
    let mut pages = BTreeMap::<u64, &str>::new();
    for function in functions {
        let address = mapping.executable_address(function.offset);
        let target = i128::from(address + 5) + i128::from(displacement);
        let target = u64::try_from(target)?;
        let page = target / PAGE_BYTES as u64;
        if let Some(previous) = pages.insert(page, &function.name) {
            return Err(format!(
                "functions {previous} and {} imply the same trampoline page; compile with -falign-functions=4096",
                function.name
            )
            .into());
        }
    }
    Ok(())
}
