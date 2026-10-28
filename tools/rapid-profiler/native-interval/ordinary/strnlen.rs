//! Explicit final-ELF strnlen selection with the whole-function preparation.
use super::{
    ChildOwner, File, MetadataExt, OrdinaryOracle, Path, Read, child_admitted, current_single_main,
    oracle,
};
use oracle::native_ordinary::{
    Profile,
    strnlen::{Arguments, CASES, Deadline, HEADER, LABEL, Population, SEEDS},
};
use rapid_profiler::frontend_native::TrustedFunctionSelection;
use std::io::Write;

pub fn run(
    subject: &Path,
    expected: &Path,
    arguments: Arguments,
    output: &Path,
    mut deadline: Deadline,
) {
    // First budget was started by the CLI BEFORE path/output/file setup. Later
    // budgets start before the next pair's mappings. Output never renews either.
    deadline.check();
    current_single_main();
    let mut file = File::open(expected).unwrap();
    let before = file.metadata().unwrap();
    let other = std::fs::metadata(subject).unwrap();
    assert!(before.is_file() && other.is_file());
    assert_ne!(
        (before.dev(), before.ino()),
        (other.dev(), other.ino()),
        "independent final ELF"
    );
    assert!((1..=1024 * 1024).contains(&before.len()));
    let mut expected_elf = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut expected_elf)
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
    assert_eq!(expected_elf.len() as u64, before.len());
    drop(file);
    // The separate provenance recipe authenticates PRESTRIP -> FINAL full ELF,
    // selected extent and RX/LOAD geometry before making this candidate copy.
    // Canonical CLI metadata alone is not source/boundary authority.
    let selection =
        TrustedFunctionSelection::new(&expected_elf, arguments.elf_va, arguments.length, LABEL)
            .unwrap();
    let mut population = Population::default();
    let mut csv = String::from(HEADER);
    let mut index = 0;
    for seed in SEEDS {
        for case in CASES {
            if index != 0 {
                deadline = Deadline::start();
            }
            let oracle = OrdinaryOracle::new_strnlen(case, seed, deadline);
            let (result, trace) = oracle.pair_strnlen(arguments.length, |candidate, context| {
                child_admitted(
                    candidate,
                    context,
                    subject,
                    ChildOwner::Strnlen(&selection),
                    false,
                    Profile::Legacy,
                );
            });
            // Both original and candidate have already returned and exited0,
            // both normal reaps/ECHILD precede the original trace inspector.
            population.record(seed, case, &result, &trace);
            csv.push_str(&format!(
                "{seed},{},{},PASS,2,{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                case.name,
                case.bound,
                result.comparisons,
                result.visits,
                result.original_steps,
                result.candidate_steps,
                result.value,
                trace.input_reads,
                trace.input_bytes,
                trace.observed_heads(),
                trace.observed_edges(),
                trace.declared_heads(),
                trace.declared_edges(),
                trace.declared_returns(),
                trace.ret_offset
            ));
            std::fs::write(output.join("strnlen-pairs.csv"), &csv).unwrap();
            drop(oracle);
            deadline.check();
            index += 1;
        }
    }
    assert_eq!(index, 16);
    let totals = population.finish();
    current_single_main();
    deadline.check();
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "native-strnlen:selection={LABEL}:required=16:pairs=16:children=32:comparisons={}:input-reads={}:input-bytes={}:coverage-seeds=2:real-outer-ret=32:complete",
        totals.comparisons, totals.input_reads, totals.input_bytes).unwrap();
    stdout.flush().unwrap();
    deadline.check(); // A printed terminal is never success without normal closure.
}
