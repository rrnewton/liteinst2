//! Explicit release-only, fresh-exec singleton probe; not a libtest harness.
#![deny(unsafe_op_in_unsafe_fn)]

#[path = "native_probe/machine.rs"]
mod machine;
#[path = "native_probe/program.rs"]
mod program;

use liteinst_inprocess::selected::{
    InstalledSelected, PreparedSelected, SelectedKind, SelectedSite,
};
use liteinst_inprocess::{InstructionExtent, PageBundle, PreparedGate};
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use machine::{Machine, Snapshot, tsc};
use program::{Kind, Program, Region};
use std::mem::ManuallyDrop;
use std::time::Instant;

const BATCHES: usize = 17;

struct Owner {
    region: Region,
    installed: Option<Box<InstalledSelected>>,
}

fn ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap()
}

fn permissions(address: *mut u8, length: usize, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(address.cast(), length, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend("fixture mprotect failed".into()))
    }
}

fn publish(region: &mut Region, program: &Program) -> (Option<Box<InstalledSelected>>, u64, u64) {
    if program.kind == Kind::Ordinary {
        return (None, 0, 0);
    }
    let start = Instant::now();
    assert_eq!(
        program.heads,
        vec![
            (program.offset, 2),
            (program.offset + 2, 1),
            (program.offset + 3, 1),
            (program.offset + 4, 1),
            (program.offset + 5, 1)
        ]
    );
    let entry = program.entry() as u64;
    let block = AddressRange::new(entry, 6).unwrap();
    // One mapping per fresh process, never reused. This is a caller-supplied
    // incarnation identity, not a claimed cryptographic digest of source bytes.
    let mut source = [0_u8; 32];
    let domain = b"li2-native-v1:";
    source[..domain.len()].copy_from_slice(domain);
    source[domain.len()..domain.len() + program.name.len()]
        .copy_from_slice(program.name.as_bytes());
    let identity = CodeIdentity {
        source: SourceIdentity(source),
        mapping: region.address.as_ptr() as u64,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: block,
        provenance: EntryProvenance::Declared("literal singleton selected/NOP/RET fixture".into()),
        completeness: EntryCompleteness::Complete,
        // Closed assembly has one external entry, no interior branch/alias,
        // and every invocation has returned before publication. The complete
        // decoded heads below remain separate from legal external entries.
        entries: vec![LegalEntry {
            address: entry,
            requires_endbr: false,
        }],
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy::near(entry).unwrap();
    let kind = match program.kind {
        Kind::Cpuid => SelectedKind::Cpuid,
        Kind::Rdtsc => SelectedKind::Rdtsc,
        Kind::Syscall => SelectedKind::Syscall,
        Kind::Ordinary => unreachable!(),
    };
    let prepared = PreparedSelected::prepare(SelectedSite {
        kind,
        identity,
        code: &program.original[program.offset..program.offset + 6],
        base_address: entry,
        function: block,
        block,
        logical_pc: entry,
        entries: &entries,
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 5,
            max_sites: 1,
        },
    })
    .unwrap();
    assert_eq!(prepared.plan().parts().kind, PlanKind::Relocation);
    assert_eq!(prepared.plan().parts().physical_pc, entry);
    assert_eq!(prepared.plan().parts().displaced.len(), 5);
    let prepare_ns = ns(start);
    let start = Instant::now();
    let address = region.address.as_ptr();
    let len = region.len;
    // Genuine exclusion: this main thread owns the sole private mapping,
    // every invocation has returned, no threads/aliases/resumes exist.
    let mut lease = unsafe {
        QuiescenceLease::new(
            region,
            identity,
            vec![AddressRange::new(address as u64, len).unwrap()],
        )
    };
    permissions(address, len, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    let installed = unsafe {
        prepared.publish_with(address.add(program.offset), &mut lease, || {
            permissions(address, len, libc::PROT_READ | libc::PROT_EXEC)
        })
    };
    let installed = match installed {
        Ok(value) => value,
        Err(failure) => {
            // No unwind/drop may make uncertain published code available.
            eprintln!("selected publication failed: {:?}", failure.failure);
            std::process::abort();
        }
    };
    assert!(!lease.is_poisoned());
    assert!(
        installed.verified() && installed.installed().is_some() && installed.receipt().is_some()
    );
    assert_eq!(
        installed.observed_source().unwrap(),
        &program.bytes()[program.offset..program.offset + 6]
    );
    assert!(!installed.observed_generated().unwrap().is_empty());
    assert_eq!(
        program.bytes()[program.offset],
        0xe9,
        "required actual E9 redirect"
    );
    assert_eq!(program.bytes()[program.offset + 5], 0xc3);
    // The entire source outside the exact authorized window remains literal.
    assert_eq!(
        &program.bytes()[..program.offset],
        &program.original[..program.offset]
    );
    assert_eq!(
        &program.bytes()[program.offset + 5..],
        &program.original[program.offset + 5..]
    );
    (Some(installed), prepare_ns, ns(start))
}

#[allow(unused_unsafe)] // Rust1.85 CPUID intrinsic signature.
fn baseline(program: &Program, machine: &Machine, actual: &Snapshot, bracket: (u64, u64)) {
    let mut expected = machine.initial;
    expected[7] += 8;
    match program.kind {
        Kind::Cpuid => {
            let cpu = unsafe { core::arch::x86_64::__cpuid_count(0, 0) };
            expected[0] = u64::from(cpu.eax);
            expected[1] = u64::from(cpu.ebx);
            expected[2] = u64::from(cpu.ecx);
            expected[3] = u64::from(cpu.edx);
        }
        Kind::Syscall => {
            // Independent real effects/result checks are performed immediately.
            expected[0] = actual.registers[0];
            expected[2] = program.entry() as u64 + 2;
            expected[11] = machine.initial[16];
        }
        Kind::Rdtsc => {
            assert_eq!(actual.registers[0] >> 32, 0);
            assert_eq!(actual.registers[3] >> 32, 0);
            let value = actual.registers[0] | (actual.registers[3] << 32);
            assert!((bracket.0..=bracket.1).contains(&value));
            expected[0] = actual.registers[0];
            expected[3] = actual.registers[3];
        }
        Kind::Ordinary => {}
    }
    assert_eq!(
        actual.registers, expected,
        "native literal instruction semantics differ"
    );
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
        eprintln!("release binary required; no debug timing fallback");
        std::process::exit(2);
    }
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "native_probe CASE ITERATIONS");
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
        "pin to one reserved CPU"
    );
    // This closed native profile never asks a policy installed for original
    // syscall PCs to authorize callback-PC syscalls. A fresh exec has no SUD
    // selector; seccomp filters are refused rather than assumed insensitive.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_SECCOMP) },
        0,
        "seccomp-free probe required"
    );
    let _signals = ApplicationSignals::block();
    if args[1] == "boundary_call" {
        program::boundary_call(iterations);
        return;
    }
    let preparation = Instant::now();
    let (region, mut program) = Program::new(&args[1]);
    // Once publication starts, active core routes retain the source identity
    // for process lifetime, including any later assertion-unwind path.
    let mut region = ManuallyDrop::new(region);
    let mut machine = Machine::new();
    let mut original = machine.empty_snapshot();
    let mut first = machine.empty_snapshot();
    let mut last = machine.empty_snapshot();
    let fixture_preparation_ns = ns(preparation);
    program.seed(&mut machine, false);
    let before = tsc();
    let start = Instant::now();
    machine.capture_into(program.entry(), &mut original);
    let native_capture_ns = ns(start);
    let after = tsc();
    baseline(&program, &machine, &original, (before, after));
    program.check_effect(&original);
    let original_data = *program.buffer;
    assert_eq!(program.bytes(), program.original);
    program.seed(&mut machine, true);
    let mut native_ns = [0_u64; BATCHES];
    for elapsed in &mut native_ns {
        let start = Instant::now();
        let result = machine.repeat(program.entry(), iterations);
        *elapsed = ns(start);
        program.check_repeated_result(std::hint::black_box(result));
    }
    let (installed, selected_preparation_ns, publication_ns) = publish(&mut region, &program);
    // Core active routes/generated mappings are process-lifetime resources.
    // Retain source and installed owners even on an assertion unwind; no source
    // address can be unmapped/reused while an active route still names it.
    let mut owner = ManuallyDrop::new(Owner {
        region: ManuallyDrop::into_inner(region),
        installed,
    });
    let final_bytes = program.bytes().to_vec();
    let extents = [
        InstructionExtent {
            offset: program.offset,
            len: 5,
            bundle: 0,
        },
        InstructionExtent {
            offset: program.offset + 5,
            len: 1,
            bundle: 0,
        },
    ];
    let bundles = [PageBundle {
        first_page: 0,
        page_count: program.pages,
    }];
    let address = owner.region.address;
    // The owner retains both the actual source and installed core mapping.
    let prepared =
        unsafe { PreparedGate::new(&mut *owner, address, &final_bytes, &extents, &bundles) }
            .unwrap();
    program.seed(&mut machine, false);
    let armed = unsafe { prepared.arm() }.unwrap();
    assert_eq!(armed.metrics().faults, 0);
    let before = tsc();
    let start = Instant::now();
    machine.capture_into(program.entry(), &mut first);
    let first_call_ns = ns(start);
    let after = tsc();
    program.compare(&original, &first, (before, after));
    program.check_effect(&first);
    assert_eq!(*program.buffer, original_data);
    let first_metrics = armed.metrics();
    assert_eq!(first_metrics.faults, 1);
    assert_eq!(first_metrics.admitted_pages, program.pages as u64);
    program.seed(&mut machine, true);
    let mut gated_ns = [0_u64; BATCHES];
    for elapsed in &mut gated_ns {
        let start = Instant::now();
        let result = machine.repeat(program.entry(), iterations);
        *elapsed = ns(start);
        program.check_repeated_result(std::hint::black_box(result));
    }
    assert_eq!(
        armed.metrics(),
        first_metrics,
        "steady execution caused another gate fault"
    );
    program.seed(&mut machine, false);
    let before = tsc();
    machine.capture_into(program.entry(), &mut last);
    let after = tsc();
    program.compare(&original, &last, (before, after));
    program.check_effect(&last);
    assert_eq!(*program.buffer, original_data);
    assert_eq!(armed.metrics(), first_metrics);
    let metrics = armed.disarm().unwrap();
    assert_eq!(metrics, first_metrics);
    assert_eq!(program.bytes(), final_bytes);
    if let Some(installed) = &owner.installed {
        assert!(installed.verified());
    }
    println!(
        "{{\"schema_version\":1,\"case\":\"{}\",\"status\":\"passed\",\"iterations\":{},\"batches\":{},\"register_words\":17,\"xstate_mask\":{},\"xstate_compared_bytes\":{},\"red_zone_bytes\":128,\"comparisons\":2,\"pushed_return_ok\":null,\"return_page_pending\":null,\"fixture_preparation_ns\":{},\"selected_preparation_ns\":{},\"publication_ns\":{},\"gate_preparation_ns\":{},\"arm_ns\":{},\"native_capture_ns\":{},\"first_call_ns\":{},\"handler_first_touch_ns\":{},\"handler_max_first_touch_ns\":{},\"faults\":{},\"admitted_pages\":{},\"native_steady_ns\":{:?},\"gated_steady_ns\":{:?}}}",
        program.name,
        iterations,
        BATCHES,
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
        native_ns,
        gated_ns
    );
}
