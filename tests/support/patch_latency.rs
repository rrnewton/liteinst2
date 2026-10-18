//! Opt-in generic LiveJumpPatch activation and same-site runner measurements.
//! See patch_latency_README.md for the clock assumptions and raw-data contract.

use super::{DualMapping, next_random, run_isolated};
use core::arch::asm;
use core::arch::x86_64::{__cpuid, __cpuid_count, __rdtscp, CpuidResult};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, compiler_fence};
use liteinst2::patcher::{
    JumpPatchPlan, LiveJumpPatch, PatchError, PatchStrategy, StalenessBudget,
};
use liteinst2::scanner::InstructionScanner;
use std::ffi::OsString;
use std::fs::{self, File};
use std::hint::{black_box, spin_loop};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = "liteinst2-patch-latency/v1";
const TEST_NAME: &str = "patch_latency::patch_activation_latency_benchmark";
const PREFIX: &str = "LITEINST_PATCH_BENCH_";
const SITES: usize = 256;
const STRIDE: usize = 128;
const LINE: usize = 64;
const STALENESS_TICKS: u64 = 3_000;
const PRE_CALLS: usize = 16;
const POST_CALLS: usize = 16;
const CALIBRATION_ROUNDS: usize = 32;
const EMPTY_CONTROLS: usize = 4_096;

#[derive(Debug)]
struct Config {
    output: PathBuf,
    trials: usize,
    seed: u64,
    call_capacity: usize,
    max_calls_per_trial: usize,
    throughput_calls: usize,
    throughput_repeats: usize,
    wall_seconds: usize,
    explicit_cpus: Option<(usize, usize)>,
}

fn setting(name: &str) -> Option<OsString> {
    std::env::var_os(format!("{PREFIX}{name}"))
}

fn count(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    let value = setting(name).map_or(default, |value| {
        value
            .to_str()
            .expect("benchmark numeric setting is not UTF-8")
            .parse()
            .unwrap_or_else(|_| panic!("invalid {PREFIX}{name}"))
    });
    assert!(
        (minimum..=maximum).contains(&value),
        "{PREFIX}{name}={value} is outside {minimum}..={maximum}; no clamping"
    );
    value
}

impl Config {
    fn read() -> Self {
        let output =
            PathBuf::from(setting("OUTPUT").expect("LITEINST_PATCH_BENCH_OUTPUT is required"));
        assert!(output.is_absolute(), "benchmark output must be absolute");
        let trials = count("TRIALS", 20_000, 1, 100_000);
        let seed = setting("SEED").map_or(0xD1B5_4A32_D192_ED03, |value| {
            let text = value.to_str().expect("benchmark seed is not UTF-8");
            if let Some(hex) = text.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).expect("invalid hexadecimal benchmark seed")
            } else {
                text.parse().expect("invalid decimal benchmark seed")
            }
        });
        assert_ne!(seed, 0, "xorshift seed must be nonzero");
        let call_capacity = count("CALL_CAPACITY", 4_000_000, 1, 16_000_000);
        assert!(
            call_capacity >= trials * (PRE_CALLS + POST_CALLS + 1),
            "call capacity cannot hold even the minimum configured trial samples"
        );
        let explicit_cpus = match (setting("RUNNER_CPU"), setting("PATCHER_CPU")) {
            (None, None) => None,
            (Some(runner), Some(patcher)) => Some((
                runner
                    .to_str()
                    .unwrap()
                    .parse()
                    .expect("invalid runner CPU"),
                patcher
                    .to_str()
                    .unwrap()
                    .parse()
                    .expect("invalid patcher CPU"),
            )),
            _ => panic!("set both RUNNER_CPU and PATCHER_CPU, or neither"),
        };
        Self {
            output,
            trials,
            seed,
            call_capacity,
            max_calls_per_trial: count("MAX_CALLS_PER_TRIAL", 4_096, 33, 65_536),
            throughput_calls: count("THROUGHPUT_CALLS", 1_000_000, 1, 10_000_000),
            throughput_repeats: count("THROUGHPUT_REPEATS", 5, 1, 32),
            wall_seconds: count("WALL_SECONDS", 180, 1, 900),
            explicit_cpus,
        }
    }
}

#[derive(Clone, Debug)]
struct Placement {
    cpu: usize,
    package: i32,
    die: i32,
    core: i32,
    siblings: Vec<usize>,
}

fn cpu_list(text: &str) -> Vec<usize> {
    let mut result = Vec::new();
    for item in text.trim().split(',') {
        if let Some((first, last)) = item.split_once('-') {
            let first: usize = first.parse().expect("invalid CPU range");
            let last: usize = last.parse().expect("invalid CPU range");
            assert!(first <= last && last < 1_048_576, "invalid CPU range");
            result.extend(first..=last);
        } else {
            result.push(item.parse().expect("invalid CPU number"));
        }
    }
    result
}

fn placement(cpu: usize) -> Placement {
    let root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/topology"));
    let number = |name: &str| -> i32 {
        fs::read_to_string(root.join(name))
            .unwrap_or_else(|error| panic!("cannot prove CPU topology {cpu}/{name}: {error}"))
            .trim()
            .parse()
            .expect("invalid CPU topology number")
    };
    let die = if root.join("die_id").is_file() {
        number("die_id")
    } else {
        0
    };
    Placement {
        cpu,
        package: number("physical_package_id"),
        die,
        core: number("core_id"),
        siblings: cpu_list(&fs::read_to_string(root.join("thread_siblings_list")).unwrap()),
    }
}

fn allowed_cpus() -> Vec<usize> {
    // SAFETY: a zeroed cpu_set_t is valid writable storage for this query.
    let mut mask: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, core::mem::size_of_val(&mask), &mut mask) },
        0,
        "cannot read affinity (including masks wider than cpu_set_t)"
    );
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &mask) })
        .collect()
}

fn distinct_physical(a: &Placement, b: &Placement) -> bool {
    a.cpu != b.cpu
        && (a.package, a.die, a.core) != (b.package, b.die, b.core)
        && !a.siblings.contains(&b.cpu)
        && !b.siblings.contains(&a.cpu)
}

fn choose_cpus(config: &Config, allowed: &[usize]) -> (Placement, Placement) {
    let placements: Vec<_> = allowed.iter().copied().map(placement).collect();
    let chosen = if let Some((runner, patcher)) = config.explicit_cpus {
        (
            placements.iter().find(|p| p.cpu == runner),
            placements.iter().find(|p| p.cpu == patcher),
        )
    } else {
        let pair = placements.iter().find_map(|a| {
            placements
                .iter()
                .find(|b| distinct_physical(a, b))
                .map(|b| (a, b))
        });
        pair.map_or((None, None), |(a, b)| (Some(a), Some(b)))
    };
    let (Some(a), Some(b)) = chosen else {
        panic!("two allowed, verifiably distinct physical CPUs are required")
    };
    assert!(
        distinct_physical(a, b),
        "SMT siblings are not distinct physical cores"
    );
    (a.clone(), b.clone())
}

#[derive(Clone, Debug)]
struct Identity {
    placement: Placement,
    aux: u32,
    cpuid15: (u32, u32, u32),
    vendor: String,
    signature: u32,
    amd_80000021_eax: u32,
}

/// Keep the Rust 1.85 intrinsic contract while accepting newer safe CPUID APIs.
#[allow(unused_unsafe)]
fn cpuid(leaf: u32) -> CpuidResult {
    // SAFETY: CPUID is always available on x86-64, including the crate MSRV.
    unsafe { __cpuid(leaf) }
}

/// Keep the Rust 1.85 intrinsic contract for CPUID queries with a subleaf.
#[allow(unused_unsafe)]
fn cpuid_count(leaf: u32, subleaf: u32) -> CpuidResult {
    // SAFETY: CPUID is always available on x86-64; newer Rust makes this safe.
    unsafe { __cpuid_count(leaf, subleaf) }
}

fn pin(cpu: &Placement) -> Identity {
    // SAFETY: the initialized mask contains exactly the requested allowed CPU.
    let mut mask: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    unsafe { libc::CPU_SET(cpu.cpu, &mut mask) };
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, core::mem::size_of_val(&mask), &mask) },
        0,
        "cannot pin benchmark thread"
    );
    assert_eq!(allowed_cpus(), vec![cpu.cpu], "affinity is not a singleton");
    assert_eq!(unsafe { libc::sched_getcpu() }, cpu.cpu as i32);
    // Extended leaves are checked before querying their feature bits.
    let basic = cpuid(0);
    let extended = cpuid(0x8000_0000);
    assert!(basic.eax >= 1 && extended.eax >= 0x8000_0007);
    let leaf1 = cpuid(1);
    assert_ne!(leaf1.edx & (1 << 4), 0, "TSC unavailable");
    assert_ne!(cpuid(0x8000_0001).edx & (1 << 27), 0, "RDTSCP unavailable");
    assert_ne!(
        cpuid(0x8000_0007).edx & (1 << 8),
        0,
        "invariant TSC unavailable"
    );
    assert_eq!(
        ((leaf1.ebx >> 8) & 0xff) * 8,
        LINE as u32,
        "requires 64-byte coherency lines"
    );
    if basic.eax >= 4 {
        for subleaf in 0..32 {
            let cache = cpuid_count(4, subleaf);
            if cache.eax & 31 == 0 {
                break;
            }
            assert_eq!(
                (cache.ebx & 0xfff) + 1,
                LINE as u32,
                "cache geometry differs from scanner"
            );
        }
    }
    let mut vendor = Vec::new();
    vendor.extend(basic.ebx.to_le_bytes());
    vendor.extend(basic.edx.to_le_bytes());
    vendor.extend(basic.ecx.to_le_bytes());
    let vendor = String::from_utf8(vendor).unwrap();
    let amd_80000021_eax = if extended.eax >= 0x8000_0021 {
        cpuid(0x8000_0021).eax
    } else {
        0
    };
    assert!(
        vendor == "GenuineIntel" || (vendor == "AuthenticAMD" && amd_80000021_eax & (1 << 2) != 0),
        "requires Intel execution-serializing LFENCE or AMD CPUID.80000021:EAX LFENCEAlwaysSerializing"
    );
    let mut aux = 0;
    unsafe { __rdtscp(&mut aux) };
    let mut again = 0;
    unsafe { __rdtscp(&mut again) };
    assert_eq!(aux, again, "unstable initial TSC_AUX");
    let cpuid15 = if basic.eax >= 0x15 {
        let leaf = cpuid(0x15);
        (leaf.eax, leaf.ebx, leaf.ecx)
    } else {
        (0, 0, 0)
    };
    Identity {
        placement: cpu.clone(),
        aux,
        cpuid15,
        vendor,
        signature: leaf1.eax,
        amd_80000021_eax,
    }
}

fn still_pinned(identity: &Identity) -> bool {
    let mut aux = 0;
    unsafe { __rdtscp(&mut aux) };
    allowed_cpus() == vec![identity.placement.cpu]
        && unsafe { libc::sched_getcpu() } == identity.placement.cpu as i32
        && aux == identity.aux
}

#[derive(Clone, Copy, Debug, Default)]
struct Stamp {
    ticks: u64,
    aux: u32,
}

// The preliminary RDTSCP reads TSC_AUX outside the measured interval. Every
// reported interval uses LFENCE/RDTSC/LFENCE ... RDTSCP/LFENCE. The asm blocks
// intentionally do NOT use nomem, readonly or pure: they are compiler memory
// barriers in addition to the explicit compiler fences. The post-RDTSC LFENCE
// prevents later payload execution before the starting read.
#[inline(always)]
fn begin() -> Stamp {
    compiler_fence(Ordering::SeqCst);
    let low: u32;
    let high: u32;
    let aux: u32;
    unsafe {
        asm!("rdtscp", "mov {aux:e}, ecx", "lfence", "rdtsc", "lfence",
            aux = out(reg) aux, out("eax") low, out("edx") high, out("ecx") _,
            options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    Stamp {
        ticks: (u64::from(high) << 32) | u64::from(low),
        aux,
    }
}

#[inline(always)]
fn end() -> Stamp {
    compiler_fence(Ordering::SeqCst);
    let low: u32;
    let high: u32;
    let aux: u32;
    unsafe {
        asm!("rdtscp", "lfence", out("eax") low, out("edx") high, out("ecx") aux,
            options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    Stamp {
        ticks: (u64::from(high) << 32) | u64::from(low),
        aux,
    }
}

#[inline(always)]
fn end_stores() -> Stamp {
    compiler_fence(Ordering::SeqCst);
    // Include completion of apply's stores, not just execution before RDTSCP.
    let low: u32;
    let high: u32;
    let aux: u32;
    unsafe {
        asm!("mfence", "rdtscp", "lfence", out("eax") low, out("edx") high, out("ecx") aux,
            options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    Stamp {
        ticks: (u64::from(high) << 32) | u64::from(low),
        aux,
    }
}

fn interval_ok(first: Stamp, last: Stamp, aux: u32) -> bool {
    first.aux == aux && last.aux == aux && last.ticks >= first.ticks
}

fn raw_ns() -> u64 {
    let mut stamp: libc::timespec = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut stamp) },
        0
    );
    u64::try_from(stamp.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(stamp.tv_nsec).unwrap()
}

#[derive(Debug)]
struct FrequencySample {
    raw0: u64,
    raw1: u64,
    raw2: u64,
    raw3: u64,
    first: Stamp,
    last: Stamp,
    low_hz: f64,
    high_hz: f64,
}

#[derive(Debug)]
struct Frequency {
    source: &'static str,
    low_hz: f64,
    high_hz: f64,
    samples: Vec<FrequencySample>,
}

fn frequency(identity: &Identity) -> Frequency {
    let (denominator, numerator, crystal) = identity.cpuid15;
    if denominator != 0 && numerator != 0 && crystal != 0 {
        let hz = f64::from(crystal) * f64::from(numerator) / f64::from(denominator);
        return Frequency {
            source: "CPUID.15H ratio/crystal",
            low_hz: hz,
            high_hz: hz,
            samples: vec![],
        };
    }
    let mut samples = Vec::with_capacity(5);
    for _ in 0..5 {
        let raw0 = raw_ns();
        let first = begin();
        let raw1 = raw_ns();
        thread::sleep(Duration::from_millis(20));
        let raw2 = raw_ns();
        let last = end();
        let raw3 = raw_ns();
        assert!(interval_ok(first, last, identity.aux) && raw2 > raw1 && raw3 >= raw0);
        let ticks = (last.ticks - first.ticks) as f64;
        samples.push(FrequencySample {
            raw0,
            raw1,
            raw2,
            raw3,
            first,
            last,
            low_hz: ticks * 1e9 / (raw3 - raw0) as f64,
            high_hz: ticks * 1e9 / (raw2 - raw1) as f64,
        });
    }
    Frequency {
        source: "CLOCK_MONOTONIC_RAW timestamp brackets; observed range",
        low_hz: samples
            .iter()
            .map(|s| s.low_hz)
            .fold(f64::INFINITY, f64::min),
        high_hz: samples.iter().map(|s| s.high_hz).fold(0.0, f64::max),
        samples,
    }
}

#[derive(Clone, Copy, Debug)]
enum Cohort {
    AtomicWord,
    GuardedSplit,
}

impl Cohort {
    fn name(self) -> &'static str {
        match self {
            Self::AtomicWord => "atomic-word",
            Self::GuardedSplit => "guarded-split",
        }
    }
    fn offset(self) -> usize {
        match self {
            Self::AtomicWord => 16,
            Self::GuardedSplit => 60,
        }
    }
    fn strategy(self) -> PatchStrategy {
        match self {
            Self::AtomicWord => PatchStrategy::AtomicWord,
            Self::GuardedSplit => PatchStrategy::GuardedSplit {
                front_len: 4,
                back_len: 4,
            },
        }
    }
}

struct Spec {
    plan: JumpPatchPlan,
    writable: usize,
}
type Function = unsafe extern "C" fn() -> u32;

struct Fixture {
    executable: usize,
    writable: usize,
    original: Vec<u8>,
    plans: Vec<JumpPatchPlan>,
    final_image: Option<Vec<u8>>,
}
struct Image {
    _mapping: DualMapping,
    functions: Vec<Function>,
    specs: Vec<Spec>,
    fixture: Fixture,
}

fn image(cohort: Cohort) -> Image {
    let mapping = DualMapping::new(SITES * STRIDE);
    assert_eq!(mapping.executable_address(0) as usize % LINE, 0);
    assert_eq!(mapping.writable_address(0) % LINE, 0);
    let mut code = vec![0x90; SITES * STRIDE];
    for index in 0..SITES {
        let site = index * STRIDE + cohort.offset();
        let entry = site - 9;
        code[entry..entry + 9].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 1, 0, 0, 0]);
        code[site..site + 5].copy_from_slice(&[0x0f, 0x1f, 0x44, 0, 0]); // five-byte NOP
        code[site + 5] = 0xc3;
        let trampoline = index * STRIDE + 96;
        code[trampoline..trampoline + 5].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0xe9]);
        let relative = i32::try_from(site as i64 + 5 - (trampoline as i64 + 9)).unwrap();
        code[trampoline + 5..trampoline + 9].copy_from_slice(&relative.to_le_bytes());
    }
    mapping.write(&code);
    // SAFETY: immutable initialization precedes registration and every call.
    assert_eq!(
        unsafe {
            core::slice::from_raw_parts(mapping.executable_address(0) as *const u8, code.len())
        },
        code
    );
    let scanner = InstructionScanner::default();
    assert_eq!(scanner.cache_line_size().get(), LINE);
    let base = mapping.executable_address(0);
    let scan = scanner.scan(&code, base).unwrap();
    let mut functions = Vec::with_capacity(SITES);
    let mut specs = Vec::with_capacity(SITES);
    let mut plans = Vec::with_capacity(SITES);
    for index in 0..SITES {
        let offset = index * STRIDE + cohort.offset();
        let site = mapping.executable_address(offset);
        assert_eq!(site as usize % LINE, cohort.offset());
        if matches!(cohort, Cohort::AtomicWord) {
            assert_eq!(site % 8, 0);
        }
        let plan = JumpPatchPlan::from_scan(
            &scanner,
            &scan,
            &code,
            base,
            site,
            mapping.executable_address(index * STRIDE + 96),
        )
        .unwrap();
        assert_eq!(plan.strategy(), cohort.strategy());
        assert_eq!(plan.displaced_len(), 5);
        assert_eq!(
            plan.original_bytes(),
            [0x0f, 0x1f, 0x44, 0, 0, 0xc3, 0x90, 0x90]
        );
        // SAFETY: entry is ENDBR64; mov eax,1; NOP5; ret, with a preserving
        // direct trampoline when patched. The dual mapping is never unmapped.
        functions.push(unsafe {
            core::mem::transmute::<usize, Function>(mapping.executable_address(offset - 9) as usize)
        });
        plans.push(plan.clone());
        specs.push(Spec {
            plan,
            writable: mapping.writable_address(offset),
        });
    }
    let fixture = Fixture {
        executable: base as usize,
        writable: mapping.writable_address(0),
        original: code,
        plans,
        final_image: None,
    };
    Image {
        _mapping: mapping,
        functions,
        specs,
        fixture,
    }
}

#[repr(align(64))]
struct Line<T>(T);

#[derive(Clone, Copy, Debug)]
enum Operation {
    Calibrate,
    EmptyApply,
    Trial,
    ApplyState,
    RevertState,
}

#[derive(Clone, Copy, Debug)]
struct Command {
    operation: Operation,
    site: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct Response {
    serial: u64,
    site: usize,
    first: Stamp,
    last: Stamp,
    apply_error: Option<PatchError>,
    reset_error: Option<PatchError>,
    traps_before: u64,
    traps_after: u64,
    apply_observed: bool,
    reset_observed: bool,
    apply_bytes: [u8; 8],
    reset_bytes: [u8; 8],
    apply_bytes_match: bool,
    reset_bytes_match: bool,
}

fn observed_bytes(patch: &LiveJumpPatch) -> [u8; 8] {
    let address = patch.plan().execute_address() as *const u8;
    let mut bytes = [0; 8];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        // SAFETY: the complete RX patch window is readable and process-live.
        // This sole writer has returned from publication before these reads.
        *byte = unsafe { core::ptr::read_volatile(address.add(offset)) };
    }
    bytes
}

struct Shared {
    command: Line<Mutex<Command>>,
    request: Line<AtomicU64>,
    ready: Line<AtomicU64>,
    go: Line<AtomicU64>,
    complete: Line<AtomicU64>,
    quiescent: Line<AtomicU64>,
    reset: Line<AtomicU64>,
    stop: Line<AtomicBool>,
    response: Line<Mutex<Response>>,
}

impl Shared {
    fn new() -> Self {
        Self {
            command: Line(Mutex::new(Command {
                operation: Operation::Calibrate,
                site: 0,
            })),
            request: Line(AtomicU64::new(0)),
            ready: Line(AtomicU64::new(0)),
            go: Line(AtomicU64::new(0)),
            complete: Line(AtomicU64::new(0)),
            quiescent: Line(AtomicU64::new(0)),
            reset: Line(AtomicU64::new(0)),
            stop: Line(AtomicBool::new(false)),
            response: Line(Mutex::new(Response::default())),
        }
    }
    fn issue(&self, serial: &mut u64, operation: Operation, site: usize) -> u64 {
        *serial += 1;
        *self.command.0.lock().unwrap() = Command { operation, site };
        self.request.0.store(*serial, Ordering::Release);
        *serial
    }
    fn response(&self) -> Response {
        *self.response.0.lock().unwrap()
    }
}

fn wait(
    flag: &AtomicU64,
    serial: u64,
    shared: &Shared,
    deadline: Instant,
) -> Result<(), &'static str> {
    let mut spins = 0_u32;
    loop {
        if flag.load(Ordering::Acquire) == serial {
            return Ok(());
        }
        if shared.stop.0.load(Ordering::Acquire) {
            return Err("patcher stopped before acknowledgment");
        }
        spins = spins.wrapping_add(1);
        if spins & 1023 == 0 && Instant::now() >= deadline {
            return Err("configured wall budget exhausted waiting for acknowledgment");
        }
        spin_loop();
    }
}

fn patcher(
    shared: &Shared,
    specs: Vec<Spec>,
    cpu: Placement,
    deadline: Instant,
    ready: mpsc::SyncSender<Identity>,
) -> Result<Identity, &'static str> {
    let identity = pin(&cpu);
    let budget = StalenessBudget::new(STALENESS_TICKS).unwrap();
    let patches: Vec<_> = specs
        .into_iter()
        .map(|spec| {
            // SAFETY: the process-lifetime RX/RW aliases cover the asserted atomic
            // envelope. Only this thread writes, and runners enter at entry only.
            unsafe { LiveJumpPatch::bind(spec.plan, spec.writable as *mut u8, budget) }.unwrap()
        })
        .collect();
    ready.send(identity.clone()).unwrap();
    let mut previous = 0;
    while !shared.stop.0.load(Ordering::Acquire) {
        let serial = shared.request.0.load(Ordering::Acquire);
        if serial == previous {
            if Instant::now() >= deadline {
                return Err("patcher wall budget exhausted");
            }
            spin_loop();
            continue;
        }
        let command = *shared.command.0.lock().unwrap();
        let mut response = Response {
            serial,
            site: command.site,
            ..Response::default()
        };
        match command.operation {
            Operation::Calibrate | Operation::EmptyApply => {
                response.first = begin();
                response.last = if matches!(command.operation, Operation::EmptyApply) {
                    end_stores()
                } else {
                    end()
                };
                *shared.response.0.lock().unwrap() = response;
                shared.complete.0.store(serial, Ordering::Release);
            }
            Operation::Trial => {
                let patch = &patches[command.site];
                response.traps_before = patch.handled_guard_traps();
                shared.ready.0.store(serial, Ordering::Release);
                wait(&shared.go.0, serial, shared, deadline)?;
                response.first = begin();
                // SAFETY: sole registered writer; runner accesses only this
                // same function through the concurrent publication protocol.
                let result = unsafe { patch.apply() };
                response.last = end_stores();
                response.apply_error = result.err();
                response.apply_bytes = observed_bytes(patch);
                response.apply_observed = true;
                response.apply_bytes_match =
                    response.apply_bytes == patch.plan().replacement_bytes();
                *shared.response.0.lock().unwrap() = response;
                shared.complete.0.store(serial, Ordering::Release);
                wait(&shared.quiescent.0, serial, shared, deadline)?;
                response.traps_after = patch.handled_guard_traps();
                if response.apply_error.is_none() {
                    // SAFETY: runner's release acknowledges return from every
                    // call, and it will make no further call until reset ACK.
                    response.reset_error = unsafe { patch.revert() }.err();
                    response.reset_bytes = observed_bytes(patch);
                    response.reset_observed = true;
                    response.reset_bytes_match =
                        response.reset_bytes == patch.plan().original_bytes();
                }
                *shared.response.0.lock().unwrap() = response;
                shared.reset.0.store(serial, Ordering::Release);
            }
            Operation::ApplyState | Operation::RevertState => {
                let patch = &patches[command.site];
                // SAFETY: the runner is quiescent throughout this command and
                // until its ACK; the same concurrent API is used unmeasured.
                response.apply_error = unsafe {
                    if matches!(command.operation, Operation::ApplyState) {
                        patch.apply()
                    } else {
                        patch.revert()
                    }
                }
                .err();
                if matches!(command.operation, Operation::ApplyState) {
                    response.apply_bytes = observed_bytes(patch);
                    response.apply_observed = true;
                    response.apply_bytes_match =
                        response.apply_bytes == patch.plan().replacement_bytes();
                } else {
                    response.reset_bytes = observed_bytes(patch);
                    response.reset_observed = true;
                    response.reset_bytes_match =
                        response.reset_bytes == patch.plan().original_bytes();
                }
                *shared.response.0.lock().unwrap() = response;
                shared.complete.0.store(serial, Ordering::Release);
            }
        }
        previous = serial;
    }
    if !still_pinned(&identity) {
        return Err("patcher affinity/TSC_AUX changed");
    }
    Ok(identity)
}

#[derive(Clone, Copy, Debug)]
struct Calibration {
    runner_first: Stamp,
    runner_last: Stamp,
    patcher_first: Stamp,
    patcher_last: Stamp,
}

impl Calibration {
    // theta = patcher TSC - runner TSC. Causality places the two patcher
    // reads inside the runner's request/ack envelope; no half-RTT guess.
    fn bounds(self, runner_aux: u32, patcher_aux: u32) -> Option<(i128, i128)> {
        if !interval_ok(self.runner_first, self.runner_last, runner_aux)
            || !interval_ok(self.patcher_first, self.patcher_last, patcher_aux)
        {
            return None;
        }
        let low = i128::from(self.patcher_last.ticks) - i128::from(self.runner_last.ticks);
        let high = i128::from(self.patcher_first.ticks) - i128::from(self.runner_first.ticks);
        (low <= high).then_some((low, high))
    }
}

fn calibrate(
    shared: &Shared,
    serial: &mut u64,
    deadline: Instant,
    output: &mut Vec<Calibration>,
) -> Result<(), &'static str> {
    for _ in 0..CALIBRATION_ROUNDS {
        let runner_first = begin();
        let request = shared.issue(serial, Operation::Calibrate, 0);
        wait(&shared.complete.0, request, shared, deadline)?;
        let runner_last = end();
        let response = shared.response();
        output.push(Calibration {
            runner_first,
            runner_last,
            patcher_first: response.first,
            patcher_last: response.last,
        });
    }
    Ok(())
}

fn intersect(rows: &[Calibration], runner_aux: u32, patcher_aux: u32) -> Option<(i128, i128)> {
    if rows.len() != CALIBRATION_ROUNDS {
        return None;
    }
    let mut low = i128::MIN;
    let mut high = i128::MAX;
    for row in rows {
        let (a, b) = row.bounds(runner_aux, patcher_aux)?;
        low = low.max(a);
        high = high.min(b);
    }
    (low <= high).then_some((low, high))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Pre,
    DuringEnvelopeOverlap,
    Post,
    Uncertain,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Pre => "pre",
            Self::DuringEnvelopeOverlap => "during-envelope-overlap",
            Self::Post => "post",
            Self::Uncertain => "uncertain",
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Pre => 0,
            Self::DuringEnvelopeOverlap => 1,
            Self::Post => 2,
            Self::Uncertain => 3,
        }
    }
}

fn phase(
    call_first: u64,
    call_last: u64,
    patch_first: u64,
    patch_last: u64,
    offset: (i128, i128),
) -> Phase {
    if call_first > call_last || patch_first > patch_last || offset.0 > offset.1 {
        return Phase::Uncertain;
    }
    let first = i128::from(call_first);
    let last = i128::from(call_last);
    let earliest_start = i128::from(patch_first) - offset.1;
    let latest_start = i128::from(patch_first) - offset.0;
    let earliest_end = i128::from(patch_last) - offset.1;
    let latest_end = i128::from(patch_last) - offset.0;
    if last < earliest_start {
        Phase::Pre
    } else if first > latest_end {
        Phase::Post
    } else if last > latest_start && first < earliest_end {
        Phase::DuringEnvelopeOverlap
    } else {
        Phase::Uncertain
    }
}

fn nearest_rank(sorted: &[u64], numerator: usize, denominator: usize) -> Option<u64> {
    assert!(numerator > 0 && numerator <= denominator);
    if sorted.is_empty() {
        return None;
    }
    let rank = ((sorted.len() as u128 * numerator as u128).div_ceil(denominator as u128)) as usize;
    Some(sorted[rank - 1])
}

#[derive(Clone, Copy, Debug)]
struct CallSample {
    trial: u32,
    site: u16,
    first: Stamp,
    last: Stamp,
    value: u32,
}

#[derive(Debug)]
struct Trial {
    number: usize,
    site: usize,
    first_call: usize,
    last_call: usize,
    response: Response,
    reset_ack: bool,
}

#[derive(Debug)]
struct Control {
    kind: &'static str,
    first: Stamp,
    last: Stamp,
}

#[derive(Debug)]
struct Throughput {
    repeat: usize,
    patched: bool,
    site: usize,
    calls: usize,
    first: Stamp,
    last: Stamp,
    raw_first: u64,
    raw_last: u64,
    checksum: u64,
    bad_values: u32,
}

struct Evidence {
    cohort: Cohort,
    runner: Identity,
    patcher: Identity,
    before: Vec<Calibration>,
    after: Vec<Calibration>,
    calls: Vec<CallSample>,
    trials: Vec<Trial>,
    controls: Vec<Control>,
    throughput: Vec<Throughput>,
    state_changes: Vec<(bool, Response)>,
    fixture: Fixture,
    errors: Vec<&'static str>,
    worker_joined: bool,
}

fn record_call(
    data: &mut Evidence,
    config: &Config,
    function: Function,
    trial: usize,
    site: usize,
    first_call: usize,
) -> Result<(), &'static str> {
    // Check BEFORE executing: every timed call has a preallocated raw slot.
    if data.calls.len() == config.call_capacity {
        return Err("call capacity exhausted; partial raw samples retained");
    }
    if data.calls.len() - first_call == config.max_calls_per_trial {
        return Err("per-trial call capacity exhausted; partial raw samples retained");
    }
    let first = begin();
    // SAFETY: this is the selected process-lifetime fixture entry, shared with
    // the sole patcher for the entire trial. No harness work occurs in it.
    let value = unsafe { function() };
    let last = end();
    data.calls.push(CallSample {
        trial: trial as u32,
        site: site as u16,
        first,
        last,
        value,
    });
    if value != 1 {
        return Err("runner observed a result other than one");
    }
    if !interval_ok(first, last, data.runner.aux) {
        return Err("runner TSC_AUX migration or backwards timestamp");
    }
    Ok(())
}

fn batched(
    function: Function,
    config: &Config,
    repeat: usize,
    site: usize,
    patched: bool,
) -> Throughput {
    // Warming, choosing the function and all publication happen outside the
    // batch. The measured loop contains an indirect call and branchless local
    // checksum validation, with no timestamp, callback or atomic per call.
    let mut bad_values = 0_u32;
    for _ in 0..16 {
        bad_values |= unsafe { function() } ^ 1;
    }
    let function = black_box(function);
    let mut checksum = 0_u64;
    let raw_first = raw_ns();
    let first = begin();
    for _ in 0..config.throughput_calls {
        let value = unsafe { function() };
        checksum = checksum.wrapping_add(u64::from(value));
        bad_values |= value ^ 1;
    }
    let last = end();
    let raw_last = raw_ns();
    black_box((checksum, bad_values));
    Throughput {
        repeat,
        patched,
        site,
        calls: config.throughput_calls,
        first,
        last,
        raw_first,
        raw_last,
        checksum,
        bad_values,
    }
}

fn state(
    shared: &Shared,
    serial: &mut u64,
    deadline: Instant,
    site: usize,
    patched: bool,
    records: &mut Vec<(bool, Response)>,
) -> Result<(), &'static str> {
    let request = shared.issue(
        serial,
        if patched {
            Operation::ApplyState
        } else {
            Operation::RevertState
        },
        site,
    );
    wait(&shared.complete.0, request, shared, deadline)?;
    let response = shared.response();
    records.push((patched, response));
    if response.serial != request || response.site != site {
        return Err("throughput command identity differs");
    }
    if response.apply_error.is_some() {
        return Err("unmeasured throughput state API failed");
    }
    if patched && (!response.apply_observed || !response.apply_bytes_match)
        || !patched && (!response.reset_observed || !response.reset_bytes_match)
    {
        return Err("unmeasured throughput state byte observation differs");
    }
    Ok(())
}

fn collect(
    config: &Config,
    cohort: Cohort,
    runner: &Identity,
    patcher_cpu: &Placement,
    deadline: Instant,
) -> Evidence {
    let Image {
        _mapping,
        functions,
        specs,
        fixture,
    } = image(cohort);
    let mut selected = Vec::with_capacity(config.trials);
    let mut random = config.seed;
    for _ in 0..config.trials {
        selected.push(next_random(&mut random) as usize % SITES);
    }
    let shared = Arc::new(Shared::new());
    let (ready_send, ready_receive) = mpsc::sync_channel(1);
    let worker_shared = Arc::clone(&shared);
    let cpu = patcher_cpu.clone();
    let handle = thread::spawn(move || {
        let result = patcher(&worker_shared, specs, cpu, deadline, ready_send);
        worker_shared.stop.0.store(true, Ordering::Release);
        result
    });
    let patcher = ready_receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .expect("patcher initialization failed or exceeded the wall budget");
    let mut data = Evidence {
        cohort,
        runner: runner.clone(),
        patcher,
        before: Vec::with_capacity(CALIBRATION_ROUNDS),
        after: Vec::with_capacity(CALIBRATION_ROUNDS),
        calls: Vec::with_capacity(config.call_capacity),
        trials: Vec::with_capacity(config.trials),
        controls: Vec::with_capacity(2 * EMPTY_CONTROLS),
        throughput: Vec::with_capacity(2 * config.throughput_repeats),
        state_changes: Vec::with_capacity(2 * config.throughput_repeats),
        fixture,
        errors: Vec::with_capacity(16),
        worker_joined: false,
    };
    if data.runner.placement.cpu == data.patcher.placement.cpu
        || !distinct_physical(&data.runner.placement, &data.patcher.placement)
    {
        data.errors
            .push("runner and patcher do not occupy distinct physical CPUs");
    }
    if data.runner.cpuid15 != data.patcher.cpuid15 {
        data.errors
            .push("runner and patcher CPUID.15H clock domains differ");
    }
    for function in &functions {
        for _ in 0..16 {
            assert_eq!(unsafe { function() }, 1);
        }
    }
    let mut serial = 0;
    if let Err(error) = calibrate(&shared, &mut serial, deadline, &mut data.before) {
        data.errors.push(error);
    }
    if intersect(&data.before, data.runner.aux, data.patcher.aux).is_none() {
        data.errors
            .push("initial cross-core clock bounds are inconsistent or migrated");
    }
    if data.errors.is_empty() {
        for _ in 0..EMPTY_CONTROLS {
            let first = begin();
            let last = end();
            data.controls.push(Control {
                kind: "runner-call-bracket",
                first,
                last,
            });
            let request = shared.issue(&mut serial, Operation::EmptyApply, 0);
            if let Err(error) = wait(&shared.complete.0, request, &shared, deadline) {
                data.errors.push(error);
                break;
            }
            let response = shared.response();
            if response.serial != request || response.site != 0 {
                data.errors.push("empty control command identity differs");
                break;
            }
            data.controls.push(Control {
                kind: "patcher-apply-bracket",
                first: response.first,
                last: response.last,
            });
        }
    }
    if data.errors.is_empty() {
        for (number, &site) in selected.iter().enumerate() {
            if Instant::now() >= deadline {
                data.errors
                    .push("configured wall budget exhausted before trial");
                break;
            }
            let request = shared.issue(&mut serial, Operation::Trial, site);
            if let Err(error) = wait(&shared.ready.0, request, &shared, deadline) {
                data.errors.push(error);
                break;
            }
            let first_call = data.calls.len();
            let mut error = None;
            for _ in 0..PRE_CALLS {
                if let Err(why) =
                    record_call(&mut data, config, functions[site], number, site, first_call)
                {
                    data.errors.push(why);
                    error = Some(why);
                    break;
                }
            }
            // The patcher has the selected site already and is waiting only
            // for GO. Planning, bind, reset and this signaling are unmeasured.
            shared.go.0.store(request, Ordering::Release);
            while error.is_none() {
                if let Err(why) =
                    record_call(&mut data, config, functions[site], number, site, first_call)
                {
                    data.errors.push(why);
                    error = Some(why);
                    break;
                }
                if shared.complete.0.load(Ordering::Acquire) == request {
                    break;
                }
                if Instant::now() >= deadline {
                    error = Some("configured wall budget exhausted while runner collected calls");
                }
            }
            let completed = wait(&shared.complete.0, request, &shared, deadline);
            let mut response = shared.response();
            if let Err(why) = completed {
                error = Some(why);
            }
            if response.serial != request || response.site != site {
                error = Some("patcher trial/site identity differs; no site attribution is valid");
            }
            if response.apply_error.is_some() {
                error = Some("measured LiveJumpPatch::apply failed");
            }
            if !response.apply_observed || !response.apply_bytes_match {
                error = Some("measured apply byte observation differs");
            }
            if error.is_none() {
                for _ in 0..POST_CALLS {
                    if let Err(why) =
                        record_call(&mut data, config, functions[site], number, site, first_call)
                    {
                        data.errors.push(why);
                        error = Some(why);
                        break;
                    }
                }
            }
            // Every call has returned. The worker cannot revert until this
            // release, and no next call occurs until reset acknowledgment.
            shared.quiescent.0.store(request, Ordering::Release);
            let reset = wait(&shared.reset.0, request, &shared, deadline);
            if reset.is_ok() {
                response = shared.response();
            } else {
                error = Some("patcher failed to acknowledge quiescent reset");
            }
            if response.reset_error.is_some() {
                error = Some("unmeasured LiveJumpPatch::revert failed");
            }
            if !response.reset_observed || !response.reset_bytes_match {
                error = Some("quiescent revert byte observation differs");
            }
            data.trials.push(Trial {
                number,
                site,
                first_call,
                last_call: data.calls.len(),
                response,
                reset_ack: reset.is_ok(),
            });
            if let Some(why) = error {
                if data.errors.last().copied() != Some(why) {
                    data.errors.push(why);
                }
                break;
            }
        }
    }
    if data.errors.is_empty() {
        for repeat in 0..config.throughput_repeats {
            let site = next_random(&mut random) as usize % SITES;
            for patched in [false, true] {
                if Instant::now() >= deadline {
                    data.errors
                        .push("configured wall budget exhausted before throughput batch");
                    break;
                }
                if patched {
                    if let Err(error) = state(
                        &shared,
                        &mut serial,
                        deadline,
                        site,
                        true,
                        &mut data.state_changes,
                    ) {
                        data.errors.push(error);
                        break;
                    }
                }
                let row = batched(functions[site], config, repeat, site, patched);
                let valid = row.checksum == row.calls as u64
                    && row.bad_values == 0
                    && interval_ok(row.first, row.last, data.runner.aux)
                    && row.raw_last > row.raw_first;
                data.throughput.push(row);
                // The complete batch has returned before restoration starts.
                if patched {
                    if let Err(error) = state(
                        &shared,
                        &mut serial,
                        deadline,
                        site,
                        false,
                        &mut data.state_changes,
                    ) {
                        data.errors.push(error);
                        break;
                    }
                }
                if !valid {
                    data.errors
                        .push("throughput checksum, clock or migration validation failed");
                    break;
                }
            }
            if !data.errors.is_empty() {
                break;
            }
        }
    }
    if let Err(error) = calibrate(&shared, &mut serial, deadline, &mut data.after) {
        data.errors.push(error);
    }
    shared.stop.0.store(true, Ordering::Release);
    // The global measurement deadline also bounds cleanup. A wedged worker
    // is detached only in an INVALID isolated child; its mappings remain live.
    while !handle.is_finished() && Instant::now() < deadline {
        spin_loop();
    }
    if handle.is_finished() {
        match handle.join() {
            Ok(Ok(identity)) if identity.aux == data.patcher.aux => {
                data.worker_joined = true;
            }
            _ => data
                .errors
                .push("patcher panicked, migrated or refused cleanup"),
        }
    } else {
        data.errors
            .push("patcher did not exit within configured wall budget");
    }
    if data.worker_joined {
        // SAFETY: writer joined and runner is quiescent; these RX mappings
        // remain process-live. Retain actual final bytes, even on refusal.
        data.fixture.final_image = Some(
            unsafe {
                core::slice::from_raw_parts(
                    data.fixture.executable as *const u8,
                    data.fixture.original.len(),
                )
            }
            .to_vec(),
        );
    }
    if !still_pinned(&data.runner) {
        data.errors.push("runner affinity/TSC_AUX changed");
    }
    // DualMapping intentionally has no unmap/drop: all registered sites stay
    // mapped for this isolated process's complete remaining lifetime.
    data
}

fn clock_bounds(data: &Evidence) -> Option<(i128, i128)> {
    let before = intersect(&data.before, data.runner.aux, data.patcher.aux)?;
    let after = intersect(&data.after, data.runner.aux, data.patcher.aux)?;
    if before.0 > after.1 || after.0 > before.1 {
        return None;
    }
    // Use the wider BEFORE/AFTER envelope, not their tighter intersection.
    // This still assumes no intervening offset excursion outside that envelope.
    Some((before.0.min(after.0), before.1.max(after.1)))
}

fn writer(root: &Path, name: &str) -> io::Result<BufWriter<File>> {
    Ok(BufWriter::new(File::create_new(root.join(name))?))
}

fn field<T: core::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "NA".to_owned(), |value| value.to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        use core::fmt::Write;
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn identity_rows(output: &mut impl Write, role: &str, identity: &Identity) -> io::Result<()> {
    writeln!(output, "{role}_cpu\t{}", identity.placement.cpu)?;
    writeln!(
        output,
        "{role}_package_die_core\t{},{},{}",
        identity.placement.package, identity.placement.die, identity.placement.core
    )?;
    writeln!(
        output,
        "{role}_thread_siblings\t{:?}",
        identity.placement.siblings
    )?;
    writeln!(output, "{role}_tsc_aux\t{}", identity.aux)?;
    writeln!(output, "{role}_vendor\t{}", identity.vendor)?;
    writeln!(output, "{role}_cpuid_signature\t{:#x}", identity.signature)?;
    writeln!(
        output,
        "{role}_cpuid15_denominator_numerator_crystal\t{},{},{}",
        identity.cpuid15.0, identity.cpuid15.1, identity.cpuid15.2
    )?;
    writeln!(
        output,
        "{role}_amd_80000021_eax\t{:#x}",
        identity.amd_80000021_eax
    )
}

fn quantiles(
    output: &mut impl Write,
    metric: &str,
    samples: &mut [u64],
    valid: bool,
    frequency: &Frequency,
) -> io::Result<()> {
    samples.sort_unstable();
    let p50 = nearest_rank(samples, 50, 100);
    let p99 = nearest_rank(samples, 99, 100);
    let p999 = nearest_rank(samples, 999, 1000);
    let maximum = samples.last().copied();
    let converted = maximum.map(|ticks| ticks as f64 * 1e9 / frequency.high_hz);
    let converted_high = maximum.map(|ticks| ticks as f64 * 1e9 / frequency.low_hz);
    writeln!(
        output,
        "{metric}\t{valid}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        samples.len(),
        field(p50),
        field(p99),
        field(p999),
        field(maximum),
        field(converted),
        field(converted_high)
    )
}

fn report(
    root: &Path,
    config: &Config,
    data: &Evidence,
    frequency: &Frequency,
) -> io::Result<bool> {
    let directory = root.join(data.cohort.name());
    fs::create_dir(&directory)?;
    let bounds = clock_bounds(data);
    let apply_errors = data
        .trials
        .iter()
        .filter(|t| {
            t.response.apply_error.is_some() || t.response.reset_error.is_some() || !t.reset_ack
        })
        .count();
    let apply_clock_errors = data
        .trials
        .iter()
        .filter(|t| !interval_ok(t.response.first, t.response.last, data.patcher.aux))
        .count();
    let call_clock_errors = data
        .calls
        .iter()
        .filter(|s| !interval_ok(s.first, s.last, data.runner.aux))
        .count();
    let return_errors = data.calls.iter().filter(|s| s.value != 1).count();
    let control_clock_errors = data
        .controls
        .iter()
        .filter(|s| {
            !interval_ok(
                s.first,
                s.last,
                if s.kind == "runner-call-bracket" {
                    data.runner.aux
                } else {
                    data.patcher.aux
                },
            )
        })
        .count();
    let attribution_errors = data
        .trials
        .iter()
        .filter(|t| t.site != t.response.site || t.number >= config.trials)
        .count();
    let byte_errors = data
        .trials
        .iter()
        .filter(|t| {
            !t.response.apply_observed
                || !t.response.reset_observed
                || !t.response.apply_bytes_match
                || !t.response.reset_bytes_match
        })
        .count();
    let guard_counter_errors = data
        .trials
        .iter()
        .filter(|t| t.response.traps_after < t.response.traps_before)
        .count();
    let state_errors = data
        .state_changes
        .iter()
        .filter(|(patched, r)| {
            r.apply_error.is_some()
                || (*patched && (!r.apply_observed || !r.apply_bytes_match))
                || (!*patched && (!r.reset_observed || !r.reset_bytes_match))
        })
        .count();
    let final_restored = data.fixture.final_image.as_ref() == Some(&data.fixture.original);
    let valid = data.errors.is_empty()
        && data.worker_joined
        && bounds.is_some()
        && data.trials.len() == config.trials
        && data.controls.len() == 2 * EMPTY_CONTROLS
        && data.throughput.len() == 2 * config.throughput_repeats
        && apply_errors == 0
        && apply_clock_errors == 0
        && call_clock_errors == 0
        && return_errors == 0
        && control_clock_errors == 0
        && attribution_errors == 0
        && byte_errors == 0
        && guard_counter_errors == 0
        && state_errors == 0
        && final_restored;
    let mut metadata = writer(&directory, "metadata.tsv")?;
    writeln!(metadata, "key\tvalue")?;
    writeln!(metadata, "version\t{VERSION}")?;
    writeln!(metadata, "cohort\t{}", data.cohort.name())?;
    writeln!(metadata, "site_line_offset\t{}", data.cohort.offset())?;
    writeln!(metadata, "actual_strategy\t{:?}", data.cohort.strategy())?;
    writeln!(metadata, "fixture_final_restored\t{final_restored}")?;
    writeln!(
        metadata,
        "status\t{}",
        if valid { "VALID" } else { "INVALID" }
    )?;
    identity_rows(&mut metadata, "runner", &data.runner)?;
    identity_rows(&mut metadata, "patcher", &data.patcher)?;
    for (phase, rows) in [("before", &data.before), ("after", &data.after)] {
        let interval = intersect(rows, data.runner.aux, data.patcher.aux);
        writeln!(
            metadata,
            "{phase}_offset_low\t{}",
            field(interval.map(|v| v.0))
        )?;
        writeln!(
            metadata,
            "{phase}_offset_high\t{}",
            field(interval.map(|v| v.1))
        )?;
    }
    writeln!(
        metadata,
        "classification_offset_low\t{}",
        field(bounds.map(|v| v.0))
    )?;
    writeln!(
        metadata,
        "classification_offset_high\t{}",
        field(bounds.map(|v| v.1))
    )?;
    writeln!(
        metadata,
        "clock_assumption\tconstant rate; offset stays within before/after bound envelope; endpoint checks do not prove intervening stability"
    )?;
    writeln!(
        metadata,
        "during_definition\tcall timestamp envelope definitely intersects apply timestamp envelope for every admitted offset; not instruction-fetch attribution"
    )?;
    writeln!(
        metadata,
        "activation_definition\tfull LiveJumpPatch::apply plus bracket and MFENCE completion; not remote instruction-fetch acknowledgment"
    )?;
    metadata.flush()?;

    let mut fixture = File::create_new(directory.join("fixture-original.bin"))?;
    fixture.write_all(&data.fixture.original)?;
    fixture.flush()?;
    if let Some(bytes) = &data.fixture.final_image {
        let mut final_image = File::create_new(directory.join("fixture-final.bin"))?;
        final_image.write_all(bytes)?;
        final_image.flush()?;
    }
    let mut sites = writer(&directory, "fixture-sites.tsv")?;
    writeln!(
        sites,
        "site\tentry_rx\tpatch_rx\tpatch_rw\ttarget_rx\toriginal_word\treplacement_word\tentry_bytes\ttrampoline_bytes"
    )?;
    for (index, plan) in data.fixture.plans.iter().enumerate() {
        let offset = index * STRIDE + data.cohort.offset();
        let trampoline = index * STRIDE + 96;
        writeln!(
            sites,
            "{index}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            data.fixture.executable + offset - 9,
            plan.execute_address(),
            data.fixture.writable + offset,
            plan.target_address(),
            hex(&plan.original_bytes()),
            hex(&plan.replacement_bytes()),
            hex(&data.fixture.original[offset - 9..offset]),
            hex(&data.fixture.original[trampoline..trampoline + 9])
        )?;
    }
    sites.flush()?;

    let mut calibration = writer(&directory, "calibration.tsv")?;
    writeln!(
        calibration,
        "phase\tround\trunner_first\trunner_last\tpatcher_first\tpatcher_last\trunner_first_aux\trunner_last_aux\tpatcher_first_aux\tpatcher_last_aux\toffset_low\toffset_high"
    )?;
    for (phase, rows) in [("before", &data.before), ("after", &data.after)] {
        for (number, row) in rows.iter().enumerate() {
            let interval = row.bounds(data.runner.aux, data.patcher.aux);
            writeln!(
                calibration,
                "{phase}\t{number}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                row.runner_first.ticks,
                row.runner_last.ticks,
                row.patcher_first.ticks,
                row.patcher_last.ticks,
                row.runner_first.aux,
                row.runner_last.aux,
                row.patcher_first.aux,
                row.patcher_last.aux,
                field(interval.map(|v| v.0)),
                field(interval.map(|v| v.1))
            )?;
        }
    }
    calibration.flush()?;

    let mut calls = writer(&directory, "calls.tsv")?;
    writeln!(
        calls,
        "trial\tsite\tphase\tfirst\tlast\tfirst_aux\tlast_aux\tvalue\tticks\tclock_ok"
    )?;
    let mut phases: [Vec<u64>; 4] = core::array::from_fn(|_| Vec::new());
    let mut overlap_trials = vec![false; data.trials.len()];
    let mut phase_counts = [0_usize; 4];
    for sample in &data.calls {
        let trial = data.trials.get(sample.trial as usize);
        let clock_ok = interval_ok(sample.first, sample.last, data.runner.aux);
        let attributable = trial.is_some_and(|t| {
            t.site == sample.site as usize
                && t.response.site == t.site
                && t.reset_ack
                && t.response.apply_error.is_none()
                && interval_ok(t.response.first, t.response.last, data.patcher.aux)
        });
        let category = if clock_ok && attributable {
            bounds.map_or(Phase::Uncertain, |offset| {
                let response = trial.unwrap().response;
                phase(
                    sample.first.ticks,
                    sample.last.ticks,
                    response.first.ticks,
                    response.last.ticks,
                    offset,
                )
            })
        } else {
            Phase::Uncertain
        };
        phase_counts[category.index()] += 1;
        let ticks = sample.last.ticks.checked_sub(sample.first.ticks);
        if let Some(ticks) = ticks {
            phases[category.index()].push(ticks);
        }
        if category == Phase::DuringEnvelopeOverlap {
            overlap_trials[sample.trial as usize] = true;
        }
        writeln!(
            calls,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{clock_ok}",
            sample.trial,
            sample.site,
            category.name(),
            sample.first.ticks,
            sample.last.ticks,
            sample.first.aux,
            sample.last.aux,
            sample.value,
            field(ticks)
        )?;
    }
    calls.flush()?;

    let mut apply = writer(&directory, "apply.tsv")?;
    writeln!(
        apply,
        "trial\tsite\tworker_serial\tworker_site\tfirst_call\tlast_call_exclusive\tfirst\tlast\tfirst_aux\tlast_aux\tticks\tapply_error\treset_error\treset_ack\tguard_traps_before\tguard_traps_after\tactivation_guard_traps\tapply_observed\tapply_bytes\tapply_bytes_match\treset_observed\treset_bytes\treset_bytes_match"
    )?;
    let mut apply_ticks = Vec::with_capacity(data.trials.len());
    for trial in &data.trials {
        let r = trial.response;
        let ticks = r.last.ticks.checked_sub(r.first.ticks);
        if let Some(ticks) = ticks {
            apply_ticks.push(ticks);
        }
        writeln!(
            apply,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            trial.number,
            trial.site,
            r.serial,
            r.site,
            trial.first_call,
            trial.last_call,
            r.first.ticks,
            r.last.ticks,
            r.first.aux,
            r.last.aux,
            field(ticks),
            r.apply_error,
            r.reset_error,
            trial.reset_ack,
            r.traps_before,
            r.traps_after,
            field(r.traps_after.checked_sub(r.traps_before)),
            r.apply_observed,
            hex(&r.apply_bytes),
            r.apply_bytes_match,
            r.reset_observed,
            hex(&r.reset_bytes),
            r.reset_bytes_match
        )?;
    }
    apply.flush()?;

    let mut controls = writer(&directory, "controls.tsv")?;
    writeln!(controls, "kind\tfirst\tlast\tfirst_aux\tlast_aux\tticks")?;
    let mut call_controls = Vec::with_capacity(EMPTY_CONTROLS);
    let mut apply_controls = Vec::with_capacity(EMPTY_CONTROLS);
    for row in &data.controls {
        let ticks = row.last.ticks.checked_sub(row.first.ticks);
        if let Some(ticks) = ticks {
            if row.kind == "runner-call-bracket" {
                call_controls.push(ticks);
            } else {
                apply_controls.push(ticks);
            }
        }
        writeln!(
            controls,
            "{}\t{}\t{}\t{}\t{}\t{}",
            row.kind,
            row.first.ticks,
            row.last.ticks,
            row.first.aux,
            row.last.aux,
            field(ticks)
        )?;
    }
    controls.flush()?;

    let mut throughput = writer(&directory, "throughput.tsv")?;
    writeln!(
        throughput,
        "repeat\tstate\tsite\tcalls\tfirst\tlast\tfirst_aux\tlast_aux\traw_first_ns\traw_last_ns\tchecksum\tbad_values_or\tticks\tcalls_per_second_raw_bracket"
    )?;
    for row in &data.throughput {
        let seconds = row
            .raw_last
            .checked_sub(row.raw_first)
            .filter(|&ns| ns != 0)
            .map(|ns| ns as f64 / 1e9);
        writeln!(
            throughput,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.repeat,
            if row.patched { "patched" } else { "unpatched" },
            row.site,
            row.calls,
            row.first.ticks,
            row.last.ticks,
            row.first.aux,
            row.last.aux,
            row.raw_first,
            row.raw_last,
            row.checksum,
            row.bad_values,
            field(row.last.ticks.checked_sub(row.first.ticks)),
            field(seconds.map(|seconds| row.calls as f64 / seconds))
        )?;
    }
    throughput.flush()?;

    let mut states = writer(&directory, "state-changes.tsv")?;
    writeln!(
        states,
        "state\tserial\tsite\tapi_error\tapply_observed\tapply_bytes\tapply_bytes_match\treset_observed\treset_bytes\treset_bytes_match"
    )?;
    for (patched, r) in &data.state_changes {
        writeln!(
            states,
            "{}\t{}\t{}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{}",
            if *patched { "patched" } else { "unpatched" },
            r.serial,
            r.site,
            r.apply_error,
            r.apply_observed,
            hex(&r.apply_bytes),
            r.apply_bytes_match,
            r.reset_observed,
            hex(&r.reset_bytes),
            r.reset_bytes_match
        )?;
    }
    states.flush()?;

    let mut summary = writer(&directory, "summary.tsv")?;
    writeln!(
        summary,
        "metric\tcohort_valid\tN\tp50_ticks\tp99_ticks\tp99_9_ticks\tmax_ticks\tmax_approx_ns_low\tmax_approx_ns_high"
    )?;
    quantiles(&mut summary, "apply", &mut apply_ticks, valid, frequency)?;
    for category in [
        Phase::Pre,
        Phase::DuringEnvelopeOverlap,
        Phase::Post,
        Phase::Uncertain,
    ] {
        quantiles(
            &mut summary,
            category.name(),
            &mut phases[category.index()],
            valid,
            frequency,
        )?;
    }
    quantiles(
        &mut summary,
        "empty-runner-call-bracket",
        &mut call_controls,
        valid,
        frequency,
    )?;
    quantiles(
        &mut summary,
        "empty-patcher-apply-bracket",
        &mut apply_controls,
        valid,
        frequency,
    )?;
    summary.flush()?;

    let mut diagnostics = writer(&directory, "diagnostics.tsv")?;
    writeln!(diagnostics, "key\tvalue")?;
    for (key, value) in [
        ("trials_requested", config.trials),
        ("trials_retained", data.trials.len()),
        ("calls_retained", data.calls.len()),
        ("pre_envelopes", phase_counts[0]),
        ("during_envelope_overlaps", phase_counts[1]),
        ("post_envelopes", phase_counts[2]),
        ("uncertain_envelopes", phase_counts[3]),
        (
            "empty_overlap_trials",
            overlap_trials.iter().filter(|&&overlap| !overlap).count(),
        ),
        ("apply_or_reset_errors", apply_errors),
        ("apply_clock_or_migration_errors", apply_clock_errors),
        ("call_clock_or_migration_errors", call_clock_errors),
        ("return_errors", return_errors),
        ("control_clock_or_migration_errors", control_clock_errors),
        ("attribution_errors", attribution_errors),
        ("publication_byte_errors", byte_errors),
        ("guard_counter_errors", guard_counter_errors),
        ("state_api_or_byte_errors", state_errors),
        (
            "calls_with_backwards_timestamp",
            data.calls
                .iter()
                .filter(|s| s.last.ticks < s.first.ticks)
                .count(),
        ),
        (
            "calls_with_zero_ticks",
            data.calls
                .iter()
                .filter(|s| s.last.ticks == s.first.ticks)
                .count(),
        ),
    ] {
        writeln!(diagnostics, "{key}\t{value}")?;
    }
    let guard_traps: u128 = data
        .trials
        .iter()
        .filter_map(|t| t.response.traps_after.checked_sub(t.response.traps_before))
        .map(u128::from)
        .sum();
    writeln!(diagnostics, "activation_guard_traps\t{guard_traps}")?;
    writeln!(diagnostics, "fixture_final_restored\t{final_restored}")?;
    for error in &data.errors {
        writeln!(diagnostics, "error\t{error}")?;
    }
    if bounds.is_none() {
        writeln!(
            diagnostics,
            "error\tbefore/after cross-core offset bounds are inconsistent, incomplete or migrated"
        )?;
    }
    writeln!(diagnostics, "worker_joined\t{}", data.worker_joined)?;
    writeln!(
        diagnostics,
        "status\t{}",
        if valid { "VALID" } else { "INVALID" }
    )?;
    diagnostics.flush()?;
    println!(
        "patch-latency {} status={} trials={} calls={} during={} uncertain={} empty-overlap-trials={}",
        data.cohort.name(),
        if valid { "VALID" } else { "INVALID" },
        data.trials.len(),
        data.calls.len(),
        phase_counts[1],
        phase_counts[3],
        overlap_trials.iter().filter(|&&overlap| !overlap).count()
    );
    Ok(valid)
}

fn benchmark_body() {
    let config = Config::read();
    let deadline = Instant::now() + Duration::from_secs(config.wall_seconds as u64);
    fs::create_dir(&config.output)
        .expect("output must be a new directory whose parent exists; never overwrite evidence");
    let allowed = allowed_cpus();
    let (runner_cpu, patcher_cpu) = choose_cpus(&config, &allowed);
    let runner = pin(&runner_cpu);
    let frequency = frequency(&runner);
    let mut metadata = writer(&config.output, "metadata.tsv").unwrap();
    writeln!(metadata, "key\tvalue").unwrap();
    for (key, value) in [
        ("version", VERSION.to_owned()), ("package_version", env!("CARGO_PKG_VERSION").to_owned()),
        ("seed", config.seed.to_string()), ("trials_per_cohort", config.trials.to_string()),
        ("sites_per_cohort", SITES.to_string()), ("site_stride_bytes", STRIDE.to_string()),
        ("cache_line_bytes", LINE.to_string()), ("staleness_ticks", STALENESS_TICKS.to_string()),
        ("pre_calls_per_trial", PRE_CALLS.to_string()), ("post_calls_per_trial", POST_CALLS.to_string()),
        ("call_capacity_per_cohort", config.call_capacity.to_string()),
        ("max_calls_per_trial", config.max_calls_per_trial.to_string()),
        ("calibration_rounds_before_and_after", CALIBRATION_ROUNDS.to_string()),
        ("empty_controls_per_bracket", EMPTY_CONTROLS.to_string()),
        ("throughput_calls_per_batch", config.throughput_calls.to_string()),
        ("throughput_repeats", config.throughput_repeats.to_string()),
        ("measurement_wall_budget_seconds", config.wall_seconds.to_string()),
        ("isolated_body_wall_cap_seconds", (config.wall_seconds + 60).to_string()),
        ("original_allowed_affinity", format!("{allowed:?}")),
        ("tsc_frequency_source", frequency.source.to_owned()),
        ("tsc_frequency_low_hz", frequency.low_hz.to_string()),
        ("tsc_frequency_high_hz", frequency.high_hz.to_string()),
        ("timing_unit", "TSC ticks, not core cycles".to_owned()),
        ("start_bracket", "RDTSCP(AUX outside interval); LFENCE/RDTSC/LFENCE; compiler memory barriers".to_owned()),
        ("call_end_bracket", "RDTSCP/LFENCE; compiler memory barriers".to_owned()),
        ("apply_end_bracket", "MFENCE/RDTSCP/LFENCE; compiler memory barriers".to_owned()),
        ("lfence_contract", "Intel execution-serializing LFENCE or AMD LFENCEAlwaysSerializing CPUID flag required".to_owned()),
        ("staleness_policy", "configured empirical 3000-tick stress policy; NOT architectural instruction-fetch coherence proof".to_owned()),
        ("measurement_scope", "generic LiveJumpPatch only; bare direct-jump trampoline; no RapidProbe callback or Tool work".to_owned()),
        ("tail_policy", "all raw samples retained, exact nearest-rank quantiles with N; no trimming or empty-control subtraction".to_owned()),
        ("external_capture_required", "compiler/build flags/executable SHA/command/host CPU and mitigations/load; root recipe owns capture".to_owned()),
    ] { writeln!(metadata, "{key}\t{value}").unwrap(); }
    identity_rows(&mut metadata, "runner", &runner).unwrap();
    metadata.flush().unwrap();
    drop(metadata);
    let mut frequency_raw = writer(&config.output, "frequency-calibration.tsv").unwrap();
    writeln!(frequency_raw, "sample\traw0_ns\traw1_ns\traw2_ns\traw3_ns\tfirst\tlast\tfirst_aux\tlast_aux\tlow_hz\thigh_hz").unwrap();
    for (index, s) in frequency.samples.iter().enumerate() {
        writeln!(
            frequency_raw,
            "{index}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            s.raw0,
            s.raw1,
            s.raw2,
            s.raw3,
            s.first.ticks,
            s.last.ticks,
            s.first.aux,
            s.last.aux,
            s.low_hz,
            s.high_hz
        )
        .unwrap();
    }
    frequency_raw.flush().unwrap();
    drop(frequency_raw);
    let mut status = writer(&config.output, "status.tsv").unwrap();
    writeln!(status, "cohort\tstatus").unwrap();
    status.flush().unwrap();
    let mut valid = true;
    for cohort in [Cohort::AtomicWord, Cohort::GuardedSplit] {
        let data = collect(&config, cohort, &runner, &patcher_cpu, deadline);
        let accepted = report(&config.output, &config, &data, &frequency)
            .expect("cannot write complete raw benchmark evidence");
        writeln!(
            status,
            "{}\t{}",
            cohort.name(),
            if accepted { "VALID" } else { "INVALID" }
        )
        .unwrap();
        status.flush().unwrap();
        valid &= accepted;
        if !accepted {
            break;
        }
    }
    writeln!(
        status,
        "overall\t{}",
        if valid { "VALID" } else { "INVALID" }
    )
    .unwrap();
    status.flush().unwrap();
    drop(status);
    io::stdout().flush().unwrap();
    io::stderr().flush().unwrap();
    // All owned BufWriters have been flushed/dropped before run_isolated uses
    // _exit(102). A refusal remains a failed test with retained partial data.
    assert!(
        valid,
        "INVALID patch-latency measurement; inspect retained raw evidence"
    );
}

#[test]
#[ignore = "opt-in release-mode cross-core LiveJumpPatch latency distribution"]
fn patch_activation_latency_benchmark() {
    let config = Config::read();
    run_isolated(
        TEST_NAME,
        Some(Duration::from_secs((config.wall_seconds + 60) as u64)),
        benchmark_body,
    );
}

#[test]
fn nearest_rank_keeps_tail_and_handles_empty() {
    assert_eq!(nearest_rank(&[], 999, 1000), None);
    assert_eq!(nearest_rank(&[7], 999, 1000), Some(7));
    let thousand: Vec<u64> = (1..=1000).collect();
    assert_eq!(nearest_rank(&thousand, 50, 100), Some(500));
    assert_eq!(nearest_rank(&thousand, 99, 100), Some(990));
    assert_eq!(nearest_rank(&thousand, 999, 1000), Some(999));
    assert_eq!(nearest_rank(&thousand, 100, 100), Some(1000));
    let odd: Vec<u64> = (1..=1001).collect();
    assert_eq!(nearest_rank(&odd, 50, 100), Some(501));
    assert_eq!(nearest_rank(&odd, 999, 1000), Some(1000));
}

#[test]
fn window_classifier_matches_every_offset_in_small_envelopes() {
    for low in -3_i128..=3 {
        for high in low..=3 {
            for first in 4_u64..=18 {
                for last in first..=20 {
                    let expected_at = |offset: i128| {
                        let a = 10 - offset;
                        let b = 14 - offset;
                        if i128::from(last) < a {
                            Phase::Pre
                        } else if i128::from(first) > b {
                            Phase::Post
                        } else if i128::from(last) > a && i128::from(first) < b {
                            Phase::DuringEnvelopeOverlap
                        } else {
                            Phase::Uncertain
                        }
                    };
                    let first_expected = expected_at(low);
                    let expected =
                        if (low..=high).all(|offset| expected_at(offset) == first_expected) {
                            first_expected
                        } else {
                            Phase::Uncertain
                        };
                    assert_eq!(
                        phase(first, last, 10, 14, (low, high)),
                        expected,
                        "call=[{first},{last}] offset=[{low},{high}]"
                    );
                }
            }
        }
    }
    assert_eq!(phase(0, 8, 10, 20, (0, 0)), Phase::Pre);
    assert_eq!(phase(9, 21, 10, 20, (0, 0)), Phase::DuringEnvelopeOverlap);
    assert_eq!(phase(22, 23, 10, 20, (0, 0)), Phase::Post);
    assert_eq!(phase(8, 9, 10, 20, (0, 2)), Phase::Uncertain);
    assert_eq!(phase(12, 11, 10, 20, (0, 0)), Phase::Uncertain);
}
