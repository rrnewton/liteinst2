# Testing your instrumentation

Instrumentation fails in ways ordinary code does not: it can corrupt
the program it observes, or observe it incompletely while looking
healthy. This chapter is about testing against both.

## Test the uninstrumented behaviour first

Your oracle is the program *without* your hooks. Record its outputs,
exit codes, and relevant state transitions; then require the
instrumented run to match everywhere your tool claims transparency.
LiteInst's own suite is built this way: native oracle drivers run the
same workload patched and unpatched and compare full machine state —
one `#[test]` oracle often performs hundreds of state comparisons.
Borrow that shape even at small scale: one workload, two modes, exact
comparison.

Run the library's suite the way CI does (`.github/workflows/ci.yml`:
format and clippy gates, then debug *and* release workspace tests):

```console
$ cargo fmt --all -- --check
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ cargo test --locked --workspace --all-targets --all-features
$ cargo test --locked --release --workspace --all-targets --all-features
$ cargo package --locked
```

## Test the refusals, not just the successes

For every site class your client handles, write the test where the
planner *refuses* — a straddler with no sound pun, an interior entry, a
split site without a staleness budget — and assert your fallback (trap,
skip, or abort) engages. A client that has never exercised
`TrapRequired` in testing will meet it first in production.

## Test under concurrency and signals

The interesting failures are races: a thread fetching mid-publication,
a signal landing on a relocated PC, a neighbour site sharing a store
tail. LiteInst's opt-in stress tests exist for exactly this and make
good templates:

```console
$ cargo test --release --test stress live_probe_stress_matrix -- --ignored --exact --nocapture
$ cargo test --release --test stress probe_overhead_benchmark -- --ignored --exact --nocapture
$ cargo test --release --lib rapid::tests::live::benchmark_single_byte_toggle_latency -- --ignored --exact --nocapture
```

`live_probe_stress_matrix` runs 128 rapid probes, a million opcode
stores, guarded jump probes, 10,000 activation cycles, and concurrent
signal delivery at default scale (scalable via `LITEINST_STRESS_*`
environment variables). Note also what the suite does for hygiene:
the test that deliberately faults (`relocated_fault_pc_translation`)
delegates its SIGSEGV to a bounded child process so it cannot mutate
the harness's signal state. Steal that pattern for your own
fault-injection tests.

## Test at the right layer

If you build on LiteInst directly, the above is your job. If you build
a Reverie tool, test the *tool* across backends instead: the same tool
must produce the same observable behaviour under ptrace and in-guest
execution, and Reverie's conformance harness exists for that. The
Reverie guide's testing chapter covers it; do not re-implement it at
the patching layer.

## A copyable skeleton

One integration-test file is enough to borrow all three shapes. It
needs `liteinst` and `libc` as dev-dependencies and no fixture-driver
environment variables; save the two listings below, in order, as a
single `tests/oracle.rs` in your crate. The file as printed was run
standalone against this repository (`3 passed`).

Listing LTS-1 is the harness plus the first two tests. The dual-mode
oracle replays [Getting started](getting-started.md)'s hook as
assertions: the unhooked result is the oracle, activation must
change exactly the hooked result *and* be observed (the hook-call
count), and deactivation must restore the oracle result. The refusal
test never touches memory: a lone `ret` has no complete patch
window, so `plan_hook` must answer `TrapRequired` — planning is pure,
which makes refusal classes cheap to table-test.

<span class="filename">Listing LTS-1: tests/oracle.rs (part 1)</span>

```rust,ignore
//! Copyable oracle tests for a LiteInst client: dual-mode state
//! comparison, one planner refusal, one faulting relocated-PC
//! translation in an isolated child. Needs `liteinst` + `libc`
//! dev-dependencies; no fixture-driver environment variables.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use liteinst::patcher::StalenessBudget;
use liteinst::planner::{plan_hook, HookSemantics, PunPlan};
use liteinst::scanner::InstructionScanner;
use liteinst::trampoline::{
    translate_program_counter, HookContext, HookSite, InstalledHook, TrampolineArena,
};

const PAGE_BYTES: usize = 4096;
static HOOK_CALLS: AtomicU64 = AtomicU64::new(0);
static FAULT_ORIGINAL_PC: AtomicU64 = AtomicU64::new(0);
static FAULT_GENERATED_PC: AtomicU64 = AtomicU64::new(0);

struct DualMapping {
    writable: *mut u8,
    executable: *mut u8,
    len: usize,
}

impl DualMapping {
    fn new(byte_len: usize) -> Self {
        let len = byte_len.div_ceil(PAGE_BYTES) * PAGE_BYTES;
        let name = b"liteinst-client-test\0";
        // SAFETY: NUL-terminated name, scalar flags.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC,
            ) as libc::c_int
        };
        assert!(fd >= 0, "memfd_create failed");
        assert_eq!(unsafe { libc::ftruncate(fd, len as libc::off_t) }, 0);
        // SAFETY: shared writable (non-exec) and read-exec aliases of
        // the same sealed-by-size memfd.
        let writable = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        let executable = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(writable, libc::MAP_FAILED);
        assert_ne!(executable, libc::MAP_FAILED);
        // SAFETY: both mappings retain the backing object.
        assert_eq!(unsafe { libc::close(fd) }, 0);
        Self {
            writable: writable.cast(),
            executable: executable.cast(),
            len,
        }
    }

    fn write_at(&self, offset: usize, bytes: &[u8]) {
        // SAFETY: callers keep writes inside the mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.writable.add(offset), bytes.len());
        }
    }

    fn writable_at(&self, offset: usize) -> *mut u8 {
        // SAFETY: callers keep offsets inside the mapping.
        unsafe { self.writable.add(offset) }
    }

    fn executable_address(&self, offset: usize) -> u64 {
        // SAFETY: callers keep offsets inside the mapping.
        unsafe { self.executable.add(offset) as usize as u64 }
    }
}

impl Drop for DualMapping {
    fn drop(&mut self) {
        // SAFETY: both aliases came from mmap with this length and are
        // unmapped once. Hooks into the mapping must already be gone.
        unsafe {
            libc::munmap(self.writable.cast(), self.len);
            libc::munmap(self.executable.cast(), self.len);
        }
    }
}

unsafe extern "C" fn replace_zero(context: *mut HookContext) {
    HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: liteinst passes exclusive access to the saved frame.
    unsafe {
        (*context).rax = 40;
    }
}

unsafe extern "C" fn noop(_context: *mut HookContext) {}

#[test]
fn dual_mode_oracle_inactive_active_restored() {
    // xor eax,eax; inc eax; nop; ret; padding — returns 1 unhooked.
    let code = [0x31, 0xC0, 0xFF, 0xC0, 0x90, 0xC3, 0x90, 0x90];
    let mapping = DualMapping::new(PAGE_BYTES);
    mapping.write_at(0, &code);
    let address = mapping.executable_address(0);
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&code, address).unwrap();
    let arena = TrampolineArena::allocate_near(address, 1).unwrap();
    // SAFETY: mapping and arena outlive every call below.
    let hook = unsafe {
        InstalledHook::install_replacing_first_in_arena(
            HookSite::new(
                &scanner,
                &scan,
                &code,
                address,
                address,
                mapping.writable_at(0),
            ),
            replace_zero,
            StalenessBudget::new(3_000).unwrap(),
            &arena,
        )
        .unwrap()
    };
    // SAFETY: the fixture is an extern "C" fn returning u32.
    let function: unsafe extern "C" fn() -> u32 =
        unsafe { std::mem::transmute(mapping.executable_address(0) as usize) };

    assert_eq!(unsafe { function() }, 1, "oracle (inactive) result");
    hook.activate().unwrap();
    assert_eq!(unsafe { function() }, 41, "hooked result");
    assert_eq!(HOOK_CALLS.load(Ordering::Relaxed), 1);
    hook.deactivate().unwrap();
    assert_eq!(unsafe { function() }, 1, "restored result matches oracle");
}

#[test]
fn incomplete_window_is_refused_by_name() {
    // A lone `ret` has no complete patch window: planning must refuse
    // and leave trapping to the client, never guess.
    let base = 0x30_0000;
    let code = [0xC3];
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&code, base).unwrap();
    let plan = plan_hook(
        &scanner,
        &scan,
        &code,
        base,
        base,
        noop,
        HookSemantics::Observe,
    );
    match plan {
        PunPlan::TrapRequired(fallback) => {
            assert_eq!(fallback.address(), base);
            assert!(fallback.rapid_error().is_some());
        }
        _ => panic!("incomplete window must retain trapping"),
    }
}

```

Listing LTS-2 is the signal test. A relocated load from address 0
faults on purpose; the handler checks that
`translate_program_counter` maps the generated fault PC back to the
original site, then `_exit`s with a success receipt the parent
asserts on. Everything runs in a re-exec'd child of the test binary,
so neither the deliberate `SIGSEGV` nor the process-global handler
can touch the harness.

<span class="filename">Listing LTS-2: tests/oracle.rs (part 2)</span>

```rust,ignore
// ---- Fault-PC translation, isolated so the deliberate SIGSEGV and
// the process-global handler cannot mutate the harness's state. ----

const ISOLATED_ENV: &str = "CLIENT_ISOLATED_TEST";
const BODY_SUCCESS_EXIT: libc::c_int = 102;

fn run_isolated(test_name: &str, body: fn()) {
    if std::env::var(ISOLATED_ENV).as_deref() == Ok(test_name) {
        body();
        // SAFETY: this process exists only to isolate the test body.
        unsafe { libc::_exit(BODY_SUCCESS_EXIT) };
    }
    let executable = std::env::current_exe().expect("test executable");
    let mut child = Command::new(executable)
        .args(["--exact", test_name, "--include-ignored", "--nocapture"])
        .env(ISOLATED_ENV, test_name)
        .spawn()
        .expect("launch isolated child");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("isolated test {test_name} timed out");
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("failed to poll isolated test {test_name}: {error}");
            }
        }
    };
    assert_eq!(
        status.code(),
        Some(BODY_SUCCESS_EXIT),
        "isolated test {test_name} did not return its success receipt: {status}"
    );
}

extern "C" fn translate_fault_pc(
    signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    context: *mut std::ffi::c_void,
) {
    if signal != libc::SIGSEGV || context.is_null() {
        // SAFETY: _exit is async-signal-safe.
        unsafe { libc::_exit(100) };
    }
    // SAFETY: Linux supplies a live ucontext to an SA_SIGINFO handler.
    let context = unsafe { &*context.cast::<libc::ucontext_t>() };
    let generated = context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
    let matches = generated == FAULT_GENERATED_PC.load(Ordering::Relaxed)
        && translate_program_counter(generated) == Some(FAULT_ORIGINAL_PC.load(Ordering::Relaxed));
    // SAFETY: _exit is async-signal-safe.
    unsafe { libc::_exit(if matches { BODY_SUCCESS_EXIT } else { 101 }) };
}

fn install_fault_handler() {
    // SAFETY: the action is fully initialized before publication.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = translate_fault_pc as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()),
            0
        );
    }
}

unsafe extern "C" fn record_hook(_context: *mut HookContext) {}

fn relocated_fault_pc_body() {
    const FAULT_OFFSET: usize = 128;
    // movabs rax, [0]; ret — the relocated load faults at address 0.
    let code = [0x48, 0xA1, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3];
    let mapping = DualMapping::new(PAGE_BYTES);
    mapping.write_at(FAULT_OFFSET, &code);
    let execute_address = mapping.executable_address(FAULT_OFFSET);
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&code, execute_address).unwrap();
    // SAFETY: both aliases and the callback outlive the fault.
    let hook = unsafe {
        InstalledHook::install(
            HookSite::new(
                &scanner,
                &scan,
                &code,
                execute_address,
                execute_address,
                mapping.writable_at(FAULT_OFFSET),
            ),
            record_hook,
            StalenessBudget::new(10_000).unwrap(),
        )
        .unwrap()
    };
    FAULT_ORIGINAL_PC.store(execute_address, Ordering::Relaxed);
    FAULT_GENERATED_PC.store(
        hook.trampoline().relocated_tail_address(),
        Ordering::Relaxed,
    );
    install_fault_handler();
    hook.activate().unwrap();
    // SAFETY: fixture is a no-argument function that faults by design.
    let function: extern "C" fn() =
        unsafe { std::mem::transmute(mapping.executable_address(FAULT_OFFSET) as usize) };
    function();
    panic!("faulting relocated instruction unexpectedly returned");
}

#[test]
fn relocated_fault_pc_translation() {
    run_isolated("relocated_fault_pc_translation", relocated_fault_pc_body);
}
```
