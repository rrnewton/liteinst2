//! Real reference CALL/RET state qualification, independent of timing accuracy.
use super::{Path, STATE_SEEDS, current_single_main, oracle, ordinary};
use oracle::native_ordinary::{OrdinaryOracle, reference};
use rapid_profiler::frontend_native::{
    ReferenceCallResult, ReferenceInterval, ReferenceLeg, ReferenceOriginalCallResult,
};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

fn allowed_cpus() -> Vec<usize> {
    let mut mask: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, core::mem::size_of_val(&mask), &raw mut mask) },
        0
    );
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&n| unsafe { libc::CPU_ISSET(n, &mask) })
        .collect()
}
pub(super) fn check_cpu(cpu: usize) {
    assert_eq!(allowed_cpus(), vec![cpu]);
}
fn pin_single() -> usize {
    let cpu = *allowed_cpus()
        .first()
        .expect("nonempty inherited CPU permission");
    let mut mask: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    unsafe {
        libc::CPU_SET(cpu, &mut mask);
    }
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, core::mem::size_of_val(&mask), &raw const mask) },
        0
    );
    check_cpu(cpu);
    cpu
}

unsafe extern "C" {
    static __rapid_profiler_reference_call_v1: u8;
    static __rapid_profiler_reference_before_start_v1: u8;
    static __rapid_profiler_reference_after_start_v1: u8;
    static __rapid_profiler_reference_after_call_v1: u8;
    static __rapid_profiler_reference_before_end_v1: u8;
    static __rapid_profiler_reference_after_end_v1: u8;
    static __rapid_profiler_reference_call_end_v1: u8;
}
pub(super) fn gate_address() -> u64 {
    let gate = &raw const __rapid_profiler_reference_call_v1 as usize as u64;
    let labels = [
        &raw const __rapid_profiler_reference_before_start_v1,
        &raw const __rapid_profiler_reference_after_start_v1,
        &raw const __rapid_profiler_reference_after_call_v1,
        &raw const __rapid_profiler_reference_before_end_v1,
        &raw const __rapid_profiler_reference_after_end_v1,
        &raw const __rapid_profiler_reference_call_end_v1,
    ]
    .map(|p| p as usize as u64);
    // SAFETY: immutable library symbols; bounded extent checked against the
    // independently hand-encoded full stencil, not a product decoder result.
    let bytes = unsafe { std::slice::from_raw_parts(gate as usize as *const u8, 194) };
    reference::check_layout(gate, labels, bytes);
    gate
}

fn record(
    r: &ReferenceInterval,
    value: u64,
    entry: u64,
    ret: u64,
) -> [u64; reference::RESULT_WORDS] {
    [
        r.leg() as u64,
        r.external_id(),
        r.gate_identity(),
        r.gate_sequence(),
        r.pid(),
        r.tid(),
        r.target(),
        r.continuation(),
        r.pre_call_rsp(),
        r.resumed_rsp(),
        r.start().ticks,
        u64::from(r.start().aux),
        r.end().ticks,
        u64::from(r.end().aux),
        value,
        entry,
        ret,
    ]
}
pub(super) fn installed_record(result: &ReferenceCallResult) -> [u64; reference::RESULT_WORDS] {
    assert_eq!(result.reference.leg(), ReferenceLeg::Installed);
    assert_eq!(result.reference.pre_call_rsp(), result.call.pre_call_rsp);
    assert_eq!(result.reference.resumed_rsp(), result.call.resumed_rsp);
    record(
        &result.reference,
        result.call.value,
        result.call.entry_rsp,
        result.call.return_pc,
    )
}
pub(super) fn original_record(
    result: &ReferenceOriginalCallResult,
) -> [u64; reference::RESULT_WORDS] {
    assert_eq!(result.reference.leg(), ReferenceLeg::Original);
    assert_eq!(result.reference.pre_call_rsp(), result.call.pre_call_rsp);
    assert_eq!(result.reference.resumed_rsp(), result.call.resumed_rsp);
    record(&result.reference, result.call.value, 0, 0)
}

// Same independent expected-ELF input contract as the existing ordinary mode.
fn expected_bytes(subject: &Path, expected: &Path) -> Vec<u8> {
    let mut file = File::open(expected).unwrap();
    let before = file.metadata().unwrap();
    let other = std::fs::metadata(subject).unwrap();
    assert!(before.is_file() && other.is_file());
    assert_ne!(
        (before.dev(), before.ino()),
        (other.dev(), other.ino()),
        "independent expected ELF"
    );
    assert!((1..=1024 * 1024).contains(&before.len()));
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    assert_eq!(stamp(&before), stamp(&file.metadata().unwrap()));
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}

pub fn run(subject: &Path, expected: &Path, output: &Path) {
    current_single_main();
    let cpu = pin_single();
    let expected_elf = expected_bytes(subject, expected);
    let mut csv = String::from(
        "seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,reader_checks,timestamp_joins,returned_records,value\n",
    );
    let (mut comparisons, mut readers, mut timestamps, mut records) = (0, 0, 0, 0);
    let mut truth = (0, 0, 0, 0);
    let mut id = 0_u64;
    let mut last_deadline = None;
    for seed in STATE_SEEDS {
        let mut visited = BTreeSet::new();
        let mut declared = None;
        for length in [1, 64] {
            id = id.checked_add(1).unwrap(); // Fixed before either actual invocation.
            let deadline = reference::deadline();
            let oracle = OrdinaryOracle::new(seed);
            let mut counts = None;
            let (result, observed) = oracle.pair_reference(
                length,
                id,
                deadline,
                |candidate, context| {
                    ordinary::child_reference(candidate, context, subject, &expected_elf, id, cpu)
                },
                |actual| {
                    counts = Some(ordinary::check_exact(actual));
                },
            );
            let counts = counts.expect("complete independent original instruction/read trace");
            assert_eq!(result.visits, counts.0);
            assert_eq!(
                result.comparisons,
                result.visits + 18,
                "all restored reference gate heads"
            );
            assert_eq!(
                (
                    observed.reader_checks,
                    observed.timestamp_joins,
                    observed.records
                ),
                (4, 4, 2)
            );
            if let Some(previous) = &declared {
                assert_eq!(previous, &result.declared_returns);
            } else {
                declared = Some(result.declared_returns.clone());
            }
            visited.extend(result.returns);
            comparisons += result.comparisons;
            readers += observed.reader_checks;
            timestamps += observed.timestamp_joins;
            records += observed.records;
            truth.0 += counts.0;
            truth.1 += counts.1;
            truth.2 += counts.2;
            truth.3 += counts.3;
            csv.push_str(&format!(
                "{seed},{length},PASS,2,{},{},{},{},{},{},{},{}\n",
                result.comparisons,
                result.visits,
                result.original_steps,
                result.candidate_steps,
                observed.reader_checks,
                observed.timestamp_joins,
                observed.records,
                result.value
            ));
            std::fs::write(output.join("reference-pairs.csv"), &csv).unwrap();
            assert!(
                std::time::Instant::now() < deadline,
                "reference CSV deadline"
            );
            drop(oracle);
            assert!(
                std::time::Instant::now() < deadline,
                "reference owner release deadline"
            );
            last_deadline = Some(deadline);
        }
        assert_eq!(
            visited,
            declared.unwrap(),
            "every actual certified RET per seed"
        );
    }
    assert_eq!(
        (id, comparisons, readers, timestamps, records),
        (4, 872, 16, 16, 8)
    );
    assert_eq!(truth, (800, 130, 126, 134)); // 130 input bytes plus four RET-word reads.
    current_single_main();
    check_cpu(cpu);
    let deadline = last_deadline.expect("four completed reference pairs");
    assert!(
        std::time::Instant::now() < deadline,
        "reference final accounting deadline"
    );
    println!(
        "native-exact-reference:required=4:pairs=4:children=8:comparisons=872:reader-checks=16:timestamp-joins=16:returned-records=8:truth-instructions=800:conditional=130:taken=126:input-reads=130:return-reads=4:subject-ret=8:real-outer-ret=8:complete"
    );
    assert!(
        std::time::Instant::now() < deadline,
        "reference terminal deadline"
    );
}
