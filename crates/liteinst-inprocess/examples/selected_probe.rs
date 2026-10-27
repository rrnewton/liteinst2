//! Separate release-only native selected-output fixture. No libtest or ptrace.
#![deny(unsafe_op_in_unsafe_fn)]
#[path = "selected_probe/machine.rs"]
mod machine;
#[path = "selected_probe/masked.rs"]
mod masked;
#[path = "selected_probe/program.rs"]
mod program;
use liteinst_inprocess::selected::{InstalledSelected, SelectedKind, selected_counters};
use liteinst_inprocess::{InstructionExtent, PageBundle, PreparedGate};
use machine::{Machine, Snapshot, tsc};
use program::{Case, Region};
use std::mem::ManuallyDrop;
use std::time::Instant;
const BATCHES: usize = 17;
struct Owner {
    region: Region,
    installed: Box<InstalledSelected>,
}
fn ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap()
}
fn is_random(case: &Case) -> bool {
    matches!(case.kind, SelectedKind::Rdrand | SelectedKind::Rdseed)
}
fn carry_json(case: &Case, state: &Snapshot) -> String {
    if is_random(case) {
        (state.registers[16] & 1 != 0).to_string()
    } else {
        "null".into()
    }
}

// Independent literal semantics: each native/hooked sample is checked against
// the same complete seeded input. Random samples and their carry may differ.
fn semantics(case: &Case, machine: &Machine, actual: &Snapshot, bracket: (u64, u64)) {
    let mut expected = machine.initial;
    expected[7] += 8;
    match case.kind {
        SelectedKind::Rdrand | SelectedKind::Rdseed => {
            let index = case.register_index();
            let actual_value = actual.registers[index];
            let mask = match case.width {
                16 => 0xffff,
                32 => 0xffff_ffff,
                64 => u64::MAX,
                _ => unreachable!(),
            };
            let value = actual_value & mask;
            let carry = actual.registers[16] & 1;
            if carry == 0 {
                assert_eq!(value, 0, "actual carry-clear result must be zero");
            }
            match case.width {
                16 => assert_eq!(actual_value & !mask, machine.initial[index] & !mask),
                32 => assert_eq!(actual_value >> 32, 0),
                64 => {}
                _ => unreachable!(),
            }
            expected[index] = actual_value;
            expected[16] = (machine.initial[16] & !0x8d5) | carry;
        }
        SelectedKind::Rdpid => {
            let index = case.register_index();
            assert_eq!(actual.registers[index] >> 32, 0);
            expected[index] = actual.registers[index];
        }
        SelectedKind::Rdtscp => {
            for index in [0, 2, 3] {
                assert_eq!(actual.registers[index] >> 32, 0);
                expected[index] = actual.registers[index];
            }
            let value = actual.registers[0] | (actual.registers[3] << 32);
            assert!(
                (bracket.0..=bracket.1).contains(&value),
                "actual RDTSCP outside serialized brackets"
            );
        }
        _ => unreachable!(),
    }
    assert_eq!(
        actual.registers, expected,
        "complete literal selected semantics"
    );
}
fn compare(case: &Case, original: &Snapshot, actual: &Snapshot) {
    for index in 0..17 {
        let variable = match case.kind {
            SelectedKind::Rdrand | SelectedKind::Rdseed => {
                index == case.register_index() || index == 16
            }
            SelectedKind::Rdtscp => index == 0 || index == 3,
            SelectedKind::Rdpid => false,
            _ => unreachable!(),
        };
        if !variable {
            assert_eq!(
                original.registers[index], actual.registers[index],
                "unaffected native/selected register {index}"
            );
        }
    }
    // RDPID and RDTSCP AUX compare to actual native output on the pinned CPU.
    // RNG flags were independently checked above, including all unaffected bits.
    assert_eq!(original.xstate, actual.xstate);
    assert_eq!(original.red_zone_and_return, actual.red_zone_and_return);
}
struct ApplicationSignals {
    mask: libc::sigset_t,
    segv: libc::sigaction,
}
impl ApplicationSignals {
    fn block() -> Self {
        let mut mask = unsafe { std::mem::zeroed() };
        let mut old = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sigfillset(&mut mask) }, 0);
        assert_eq!(unsafe { libc::sigdelset(&mut mask, libc::SIGSEGV) }, 0);
        assert_eq!(unsafe { libc::sigdelset(&mut mask, libc::SIGILL) }, 0);
        assert_eq!(
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &mask, &mut old) },
            0
        );
        // This fresh-process fixture owns signal disposition. Rust installs a
        // stack-overflow SIGSEGV handler before main; explicitly transfer that
        // ownership to the gate's required default profile and restore it after
        // disarm. The library continues to refuse an existing handler.
        let mut segv = unsafe { std::mem::zeroed() };
        let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
        default.sa_sigaction = libc::SIG_DFL;
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGSEGV, &default, &mut segv) },
            0
        );
        Self { mask: old, segv }
    }
}
impl Drop for ApplicationSignals {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGSEGV, &self.segv, std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.mask, std::ptr::null_mut()) },
            0
        );
    }
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("release binary required");
        std::process::exit(2);
    }
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "selected_probe CASE ITERATIONS");
    let iterations: usize = args[2].parse().unwrap();
    assert!((1..=100_000).contains(&iterations));
    assert_eq!(unsafe { libc::getpid() } as i64, unsafe {
        libc::syscall(libc::SYS_gettid)
    });
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let mut affinity = [0_u8; 128];
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, affinity.len(), affinity.as_mut_ptr().cast()) },
        0
    );
    assert_eq!(
        affinity.iter().map(|v| v.count_ones()).sum::<u32>(),
        1,
        "pin one reserved CPU"
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_SECCOMP) },
        0,
        "seccomp-free fixture required"
    );
    let _signals = ApplicationSignals::block();
    if args[1] == "refusal_controls" {
        assert_eq!(iterations, 1);
        program::refusal_controls();
        return;
    }
    let case = Case::parse(&args[1]);
    // This is a genuine returned CPUID replacement observation, not a boolean
    // pretending the host advertised fewer features. Execute selected code
    // unconditionally afterward; a hardware refusal remains a failed process.
    let mask = case.masked.then(|| masked::observe(case.kind));
    let mask_json = match mask {
        Some(value) => format!(
            "{{\"leaf\":{},\"subleaf\":{},\"outputs\":{:?},\"calls\":{},\"feature_bit_clear\":true}}",
            value.leaf, value.subleaf, value.outputs, value.calls
        ),
        None => "null".into(),
    };
    let start = Instant::now();
    let mut region = ManuallyDrop::new(Region::new(&case.bytes, case.crossing));
    let mut machine = Machine::new();
    // Every arithmetic flag begins set: RNG must actually clear five and set
    // CF from its actual result. The other new classes retain this exact value.
    machine.initial[16] = 0xad7;
    let mut original = machine.empty_snapshot();
    let mut first = machine.empty_snapshot();
    let mut last = machine.empty_snapshot();
    let fixture_preparation_ns = ns(start);
    let entry = region.entry() as usize;
    let before = tsc();
    let start = Instant::now();
    machine.capture_into(entry, &mut original);
    let native_capture_ns = ns(start);
    let after = tsc();
    semantics(&case, &machine, &original, (before, after));
    assert_eq!(region.bytes(), region.original);
    let mut native_steady_ns = [0_u64; BATCHES];
    for value in &mut native_steady_ns {
        let start = Instant::now();
        std::hint::black_box(machine.repeat(entry, iterations));
        *value = ns(start);
    }
    let counters_before = selected_counters(case.kind);
    assert_eq!(counters_before.entered, 0);
    assert_eq!(counters_before.completed, 0);
    let (installed, selected_preparation_ns, publication_ns) = region.publish(case.kind);
    assert_eq!(installed.instruction().bytes(), case.bytes);
    assert_eq!(installed.instruction().logical_pc(), entry as u64);
    let offset = region.offset;
    let end = region.end;
    let pages = region.original.len() / machine::PAGE;
    let mut owner = ManuallyDrop::new(Owner {
        region: ManuallyDrop::into_inner(region),
        installed,
    });
    let final_bytes = owner.region.bytes().to_vec();
    let address = owner.region.address;
    let extents = [
        InstructionExtent {
            offset,
            len: 5,
            bundle: 0,
        },
        InstructionExtent {
            offset: end,
            len: 1,
            bundle: 0,
        },
    ];
    let bundles = [PageBundle {
        first_page: 0,
        page_count: pages,
    }];
    let prepared =
        unsafe { PreparedGate::new(&mut *owner, address, &final_bytes, &extents, &bundles) }
            .unwrap();
    let armed = unsafe { prepared.arm() }.unwrap();
    assert_eq!(armed.metrics().faults, 0);
    let before = tsc();
    let start = Instant::now();
    machine.capture_into(entry, &mut first);
    let first_call_ns = ns(start);
    let after = tsc();
    semantics(&case, &machine, &first, (before, after));
    compare(&case, &original, &first);
    let first_metrics = armed.metrics();
    assert_eq!(first_metrics.faults, 1);
    assert_eq!(first_metrics.admitted_pages, pages as u64);
    let mut patched_steady_ns = [0_u64; BATCHES];
    for value in &mut patched_steady_ns {
        let start = Instant::now();
        std::hint::black_box(machine.repeat(entry, iterations));
        *value = ns(start);
    }
    assert_eq!(
        armed.metrics(),
        first_metrics,
        "no further steady-state NX faults"
    );
    let before = tsc();
    machine.capture_into(entry, &mut last);
    let after = tsc();
    semantics(&case, &machine, &last, (before, after));
    compare(&case, &original, &last);
    assert_eq!(armed.metrics(), first_metrics);
    let counters = selected_counters(case.kind);
    let patched_calls = (BATCHES * iterations + 2) as u64;
    assert_eq!(counters.entered, patched_calls);
    assert_eq!(counters.completed, patched_calls);
    assert_eq!(counters.first_logical_pc, Some(entry as u64));
    assert_eq!(counters.last_logical_pc, Some(entry as u64));
    if is_random(&case) {
        let observed_failures =
            u64::from(first.registers[16] & 1 == 0) + u64::from(last.registers[16] & 1 == 0);
        assert!(counters.carry_clear >= observed_failures && counters.carry_clear <= patched_calls);
    } else {
        assert_eq!(counters.carry_clear, 0);
    }
    let metrics = armed.disarm().unwrap();
    assert_eq!(metrics, first_metrics);
    assert_eq!(owner.region.bytes(), final_bytes);
    assert!(owner.installed.verified());
    let width = if case.width == 0 {
        "null".into()
    } else {
        case.width.to_string()
    };
    println!(
        concat!(
            "{{\"schema_version\":1,\"profile\":\"native_outputs\",\"case\":\"{}\",\"status\":\"passed\",\"class\":\"{}\",\"width\":{},\"destination\":{},",
            "\"iterations\":{},\"batches\":{},\"native_calls\":{},\"patched_calls\":{},\"entered\":{},\"completed\":{},\"carry_clear\":{},\"first_logical_pc_match\":true,\"last_logical_pc_match\":true,",
            "\"native_carry\":{},\"first_carry\":{},\"last_carry\":{},\"cpuid_mask\":{},\"native_state_checks\":1,\"patched_state_checks\":2,\"register_words\":17,\"xstate_mask\":{},\"xstate_compared_bytes\":{},\"red_zone_bytes\":128,",
            "\"published_verified\":true,\"source_unchanged_outside_plan\":true,\"disarmed\":true,\"fixture_preparation_ns\":{},\"selected_preparation_ns\":{},\"publication_ns\":{},\"gate_preparation_ns\":{},\"arm_ns\":{},\"native_capture_ns\":{},\"first_call_ns\":{},",
            "\"handler_first_touch_ns\":{},\"handler_max_first_touch_ns\":{},\"faults\":{},\"admitted_pages\":{},\"native_steady_ns\":{:?},\"patched_steady_ns\":{:?}}}"
        ),
        case.name,
        case.class(),
        width,
        case.destination_json(),
        iterations,
        BATCHES,
        BATCHES * iterations + 1,
        patched_calls,
        counters.entered,
        counters.completed,
        counters.carry_clear,
        carry_json(&case, &original),
        carry_json(&case, &first),
        carry_json(&case, &last),
        mask_json,
        machine.mask(),
        original.xstate.len(),
        fixture_preparation_ns,
        selected_preparation_ns,
        publication_ns,
        metrics.preparation_ns,
        metrics.arm_ns,
        native_capture_ns,
        first_call_ns,
        metrics.first_touch_ns,
        metrics.max_first_touch_ns,
        metrics.faults,
        metrics.admitted_pages,
        native_steady_ns,
        patched_steady_ns
    );
}
