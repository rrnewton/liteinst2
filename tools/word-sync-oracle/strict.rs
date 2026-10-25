//! Additive finite Word-sync oracle, never a replacement for the 35-cycle suite.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate liteinst2;

use liteinst2::patcher::synchronized::{Direction, Phase, SyncJumpPatch, SynchronizedBatch};
use liteinst2::patcher::{JumpPatchPlan, PatchStrategy};
use liteinst2::scanner::InstructionScanner;
use liteinst2::sync_core::SyncCore;
use liteinst2::trampoline::{TrampolineImage, TrampolinePlan};
mod neighbors;
#[path = "../../tests/support/quiescent_oracle.rs"]
pub mod oracle;
use oracle::{
    HookEventLog, HookExpectation, Mapping, NativeOracle, ScheduleKind, TraceMap, WordPublication,
};

const PAGE: usize = 4096;
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
// Independent literal grammar: ADD EAX/ECX/RCX,imm32; the CS prefix on
// register-direct ADD has no effect. Arithmetic flags are all defined.
const INSTRUCTIONS: [&[u8]; 4] = [
    &[0x05, 0x78, 0x56, 0x34, 0x12],
    &[0x81, 0xc1, 0x78, 0x56, 0x34, 0x12],
    &[0x48, 0x81, 0xc1, 0x78, 0x56, 0x34, 0x12],
    &[0x2e, 0x48, 0x81, 0xc1, 0x78, 0x56, 0x34, 0x12],
];

fn bytes(address: u64, len: usize) -> Vec<u8> {
    // SAFETY: callers pass only a complete fixture-owned readable mapping.
    unsafe { std::slice::from_raw_parts(address as *const u8, len).to_vec() }
}

fn put(mapping: &Mapping, offset: usize, data: &[u8]) {
    assert!(offset + data.len() <= PAGE);
    // SAFETY: fixture owns writable storage and has excluded all execution.
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), mapping.writable().add(offset), data.len())
    };
}

struct Fixture {
    native: &'static NativeOracle,
    image_memory: &'static Mapping,
    image: TrampolineImage,
    plan: JumpPatchPlan,
    original: Vec<u8>,
    site: usize,
    length: usize,
}

impl Fixture {
    fn new(length: usize, front: usize) -> Self {
        assert!((5..=8).contains(&length) && (1..=8).contains(&front));
        let site = if front == 8 { 32 } else { 64 - front };
        let instruction = INSTRUCTIONS[length - 5];
        assert_eq!(instruction.len(), length);
        let mut code = vec![0x90; site];
        code.extend_from_slice(instruction);
        code.extend_from_slice(&[0x48, 0x89, 0x07, 0xc3]); // MOV [RDI],RAX; RET
        // Registry bindings and all target/source mappings are deliberately
        // process-lifetime. Each fresh mode owns only its finite fixed cohort.
        let native = Box::leak(Box::new(NativeOracle::new(&code)));
        let original = bytes(native.code.address(), PAGE);
        let image_memory = Box::leak(Box::new(Mapping::new(PAGE)));
        put(image_memory, 0, &[0; PAGE]);
        let pc = native.code.address() + site as u64;
        let scanner = InstructionScanner::default();
        let scan = scanner.scan(&code[site..], pc).unwrap();
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|i| i.len())
                .collect::<Vec<_>>(),
            vec![length, 3, 1]
        );
        let image = TrampolinePlan::from_instruction(&scan, pc)
            .unwrap()
            .emit_at(image_memory.address())
            .unwrap();
        assert_eq!(image.instruction_boundaries().len(), 1);
        assert_eq!(image.instruction_boundaries(), &[(pc, image.address())]);
        assert_eq!(image.layout().relocated_prefix_len, 0);
        assert_eq!(image.entry_routes(), image.instruction_boundaries());
        assert!(image.controls().is_empty());
        assert_eq!(image.layout().instrumentation_len, 0);
        assert_eq!(image.layout().restore_len, 0);
        assert_eq!(image.layout().entry_stop_len, 0);
        assert_eq!(image.layout().completion_stop_len, 0);
        assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
        put(image_memory, 0, image.bytes());
        image_memory.protect(libc::PROT_READ | libc::PROT_EXEC);
        let plan =
            JumpPatchPlan::from_scan(&scanner, &scan, &code[site..], pc, pc, image.address())
                .unwrap();
        assert_eq!(plan.displaced_len(), length);
        assert_eq!(plan.execute_address(), pc);
        let redirect = plan.replacement_bytes();
        assert_eq!(redirect[0], 0xe9);
        let delta = i32::from_le_bytes(redirect[1..5].try_into().unwrap());
        assert_eq!(
            i128::from(pc) + 5 + i128::from(delta),
            i128::from(image.address())
        );
        assert_eq!(plan.original_bytes().as_slice(), &original[site..site + 8]);
        match plan.strategy() {
            PatchStrategy::AtomicWord => {
                assert_eq!(front, 8);
                assert_eq!(
                    plan.guarded_byte_offsets().collect::<Vec<_>>(),
                    Vec::<usize>::new()
                );
            }
            PatchStrategy::GuardedSplit {
                front_len,
                back_len,
            } => {
                assert_eq!((front_len, back_len), (front, 8 - front));
                assert_eq!(
                    plan.guarded_byte_offsets().collect::<Vec<_>>(),
                    (0..front).collect::<Vec<_>>()
                );
            }
        }
        let result = Self {
            native,
            image_memory,
            image,
            plan,
            original,
            site,
            length,
        };
        result.check_image();
        result
    }

    fn heads(&self) -> [u64; 3] {
        let site = self.plan.execute_address();
        [
            site,
            site + self.length as u64,
            site + self.length as u64 + 3,
        ]
    }

    fn check_image(&self) {
        let mut expected = vec![0; PAGE];
        expected[..self.image.bytes().len()].copy_from_slice(self.image.bytes());
        assert_eq!(bytes(self.image_memory.address(), PAGE), expected);
        for &(logical, physical) in self.image.instruction_boundaries() {
            let translations: Vec<_> = self
                .image
                .program_counter_mappings()
                .iter()
                .filter_map(|m| m.translate(physical))
                .collect();
            assert_eq!(translations, vec![logical]);
        }
    }

    fn map(&self, installed: bool) -> TraceMap {
        let mut result = TraceMap::default();
        for head in self.heads().into_iter().chain([self.native.return_pc()]) {
            if installed && head == self.plan.execute_address() {
                result
                    .boundaries
                    .extend_from_slice(self.image.instruction_boundaries());
                result.gateways.push(head);
            } else {
                result.boundaries.push((head, head));
            }
        }
        if installed {
            result
                .generated_ranges
                .push(self.image.address()..self.image.address() + self.image.bytes().len() as u64);
        }
        result
    }

    fn transition(&self, patch: &SyncJumpPatch, direction: Direction) {
        // These completed-phase fixtures have no child executing while parent
        // writes. Separate child-owned guard/frame schedules test live gates.
        self.native.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        let before = bytes(self.native.code.address(), PAGE);
        let mut expected = before.clone();
        let refs = [patch];
        // SAFETY: fixture owns all permanent aliases/targets, original heads,
        // router/masks and the sole current writer; no executing child exists.
        let mut batch = unsafe { SynchronizedBatch::prepare(&refs, direction).unwrap() };
        assert_eq!(batch.receipt().phase, Phase::Prepared);
        let replacement = match direction {
            Direction::Apply => patch.plan().replacement_bytes(),
            Direction::Revert => patch.plan().original_bytes(),
        };
        let front = match patch.plan().strategy() {
            PatchStrategy::AtomicWord => 8,
            PatchStrategy::GuardedSplit { front_len, .. } => front_len,
        };
        for (index, phase) in [
            Phase::GuardsPublished,
            Phase::GuardsSynchronized,
            Phase::BacksPublished,
            Phase::BacksSynchronized,
            Phase::FrontsPublished,
            Phase::Complete,
        ]
        .into_iter()
        .enumerate()
        {
            let receipt = unsafe { batch.advance().unwrap() };
            if phase == Phase::GuardsPublished && front != 8 {
                expected[self.site..self.site + front].fill(0xcc);
            }
            if phase == Phase::BacksPublished && front != 8 {
                expected[self.site + front..self.site + 8].copy_from_slice(&replacement[front..]);
            }
            if phase == Phase::FrontsPublished {
                expected[self.site..self.site + 8].copy_from_slice(&replacement);
            }
            assert_eq!(receipt.phase, phase);
            assert_eq!(receipt.members, 1);
            assert_eq!(
                receipt.mutated,
                front != 8 || matches!(phase, Phase::FrontsPublished | Phase::Complete)
            );
            assert_eq!(receipt.synchronizations, index.div_ceil(2));
            assert_eq!(receipt.failure, None);
            assert_eq!(receipt.writer_ownership_retained, phase != Phase::Complete);
            assert_eq!(bytes(self.native.code.address(), PAGE), expected);
            self.check_image();
        }
        self.native.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        let edits = if direction == Direction::Apply {
            vec![(
                patch.plan().execute_address(),
                patch.plan().replacement_bytes().to_vec(),
            )]
        } else {
            vec![]
        };
        self.native.assert_publication(&edits);
        assert_eq!(&expected[..self.site], &self.original[..self.site]);
        assert_eq!(&expected[self.site + 5..], &self.original[self.site + 5..]);
    }
}

fn completed(length: usize) {
    let capability = SyncCore::prepare().unwrap();
    let mut original = 0;
    let mut installed = 0;
    let mut retired = 0;
    let mut phases = 0;
    for front in 1..=8 {
        let fixture = Fixture::new(length, front);
        let mut traces = Vec::new();
        for head in fixture.heads() {
            for (seed_index, seed) in SEEDS.into_iter().enumerate() {
                let trace = fixture.native.trace_original(
                    head,
                    &fixture.heads(),
                    &[fixture.native.return_pc()],
                    seed,
                );
                let expected = fixture
                    .heads()
                    .into_iter()
                    .skip_while(|pc| *pc != head)
                    .chain([fixture.native.return_pc()])
                    .collect::<Vec<_>>();
                assert_eq!(trace.visits(), expected);
                traces.push((head, seed_index, trace));
                original += 1;
                println!(
                    "case completed-L{length}-F{front}-H{}-S{seed_index}-original",
                    head - fixture.plan.execute_address()
                );
            }
        }
        // SAFETY: same permanent closed fixture contracts as transition.
        let patch = unsafe {
            SyncJumpPatch::bind(
                fixture.plan.clone(),
                fixture.native.code.writable().add(fixture.site),
                capability,
            )
            .unwrap()
        };
        fixture.transition(&patch, Direction::Apply);
        phases += 6;
        for (head, seed_index, trace) in &traces {
            fixture
                .native
                .assert_trace(trace, *head, &fixture.map(true), &[], None);
            fixture.check_image();
            installed += 1;
            println!(
                "case completed-L{length}-F{front}-H{}-S{seed_index}-installed",
                head - fixture.plan.execute_address()
            );
        }
        fixture.transition(&patch, Direction::Revert);
        phases += 6;
        for (head, seed_index, trace) in &traces {
            fixture
                .native
                .assert_trace(trace, *head, &fixture.map(false), &[], None);
            fixture.check_image();
            retired += 1;
            println!(
                "case completed-L{length}-F{front}-H{}-S{seed_index}-reverted",
                head - fixture.plan.execute_address()
            );
        }
        assert_eq!(patch.handled_guard_traps(), 0);
    }
    assert_eq!((original, installed, retired, phases), (48, 48, 48, 96));
    println!(
        "completed length={length} geometries=8 original=48 installed=48 reverted=48 phases=96"
    );
}

fn scheduled(length: usize, kind: ScheduleKind) {
    let mut count = 0;
    let mut actual_roundtrips = 0;
    let mut actual_guards = 0;
    for front in 1..=8 {
        if kind == ScheduleKind::Guard && front == 8 {
            continue;
        }
        let fixture = Fixture::new(length, front);
        let mut entries = vec![fixture.heads()[0]];
        if kind == ScheduleKind::Guard && length < front {
            entries.push(fixture.heads()[1]);
        }
        for entry in entries {
            for direction in [Direction::Apply, Direction::Revert] {
                for (seed_index, seed) in SEEDS.into_iter().enumerate() {
                    let trace = fixture.native.trace_original(
                        entry,
                        &fixture.heads(),
                        &[fixture.native.return_pc()],
                        seed,
                    );
                    let log = HookEventLog::new();
                    // SAFETY: fresh main-thread, closed handwritten application,
                    // no inherited writer/lock holder; every child is reaped.
                    let publication = unsafe {
                        WordPublication::new(
                            fixture.plan.clone(),
                            &fixture.native.code,
                            &fixture.image,
                            direction,
                            kind,
                            entry,
                        )
                    };
                    fixture.native.assert_trace_word_publication(
                        &trace,
                        entry,
                        &fixture.map(direction == Direction::Apply),
                        &[],
                        Some(HookExpectation {
                            log: &log,
                            enabled: &[],
                        }),
                        &publication,
                    );
                    assert_eq!(publication.completed(), 1);
                    actual_roundtrips += publication.signal_roundtrips();
                    actual_guards += publication.guard_deliveries();
                    fixture.native.assert_publication(&[]);
                    fixture.check_image();
                    count += 1;
                    println!(
                        "case scheduled-{kind:?}-L{length}-F{front}-H{}-{direction:?}-S{seed_index}",
                        entry - fixture.plan.execute_address()
                    );
                }
            }
        }
    }
    let expected = if kind == ScheduleKind::Guard {
        [36, 32, 28, 28][length - 5]
    } else {
        32
    };
    assert_eq!(count, expected);
    assert_eq!(actual_roundtrips, expected);
    assert_eq!(
        actual_guards,
        if kind == ScheduleKind::Guard {
            expected
        } else {
            0
        }
    );
    println!(
        "scheduled kind={kind:?} length={length} comparisons={count} actual_rt_sigreturns={actual_roundtrips} owned_guards={actual_guards}"
    );
}

fn main() {
    const {
        assert!(cfg!(all(target_os = "linux", target_arch = "x86_64")));
    }
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    assert_eq!(
        unsafe { libc::sysconf(libc::_SC_LEVEL1_DCACHE_LINESIZE) },
        64
    );
    assert_eq!(
        unsafe { libc::sysconf(libc::_SC_LEVEL1_ICACHE_LINESIZE) },
        64
    );
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "neighbors" {
        neighbors::run();
        return;
    }
    assert_eq!(args.len(), 3);
    let length: usize = args[2].parse().unwrap();
    assert!((5..=8).contains(&length));
    match args[1].as_str() {
        "completed" => completed(length),
        "guard" => scheduled(length, ScheduleKind::Guard),
        "parked" => scheduled(length, ScheduleKind::Parked),
        _ => panic!("unknown required mode"),
    }
}
