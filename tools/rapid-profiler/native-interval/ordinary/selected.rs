//! Explicit hidden/stripped selection, with the unchanged ordinary child body.
use super::{
    ChildOwner, File, MetadataExt, OrdinaryOracle, Path, Read, STATE_SEEDS, child_admitted,
    current_single_main, oracle,
};
use oracle::native_ordinary::{
    Profile,
    selected::{Arguments, Deadline, HEADER, LABEL, Population, SEEDS},
};
use rapid_profiler::frontend_native::TrustedFunctionSelection;
use std::io::Write;

pub fn run(subject: &Path, expected: &Path, arguments: Arguments, output: &Path) {
    // First-pair file/selection setup is included, as are all later allocations,
    // fork/readiness waits, continuous 20K steps, normal reaps and row output.
    let mut deadline = Deadline::start();
    current_single_main();
    assert_eq!(STATE_SEEDS, SEEDS);
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
    // The root-owned fixture recipe authenticates this complete FINAL file and
    // VA/extent against PRESTRIP before launch. CLI representation is not that
    // proof. This parent never creates/forks a PID-bound loaded owner.
    let selection =
        TrustedFunctionSelection::new(&expected_elf, arguments.elf_va, arguments.length, LABEL)
            .unwrap();
    let mut population = Population::default();
    let mut csv = String::from(HEADER);
    let mut index = 0;
    for seed in STATE_SEEDS {
        for length in [1, 64] {
            if index != 0 {
                deadline = Deadline::start();
            }
            let oracle = OrdinaryOracle::new_selected(seed, deadline);
            let result = oracle.pair_selected(length, |candidate, context| {
                child_admitted(
                    candidate,
                    context,
                    subject,
                    ChildOwner::Selected(&selection),
                    false,
                    Profile::Legacy,
                );
            });
            // This independently joins scalar/population/counts and the complete
            // RET union per seed after BOTH normal child reaps and ECHILD.
            population.record(seed, length, &result);
            csv.push_str(&format!(
                "{seed},{length},PASS,2,{},{},{},{},{}\n",
                result.comparisons,
                result.visits,
                result.original_steps,
                result.candidate_steps,
                result.value
            ));
            std::fs::write(output.join("selected-pairs.csv"), &csv).unwrap();
            drop(oracle);
            deadline.check();
            index += 1;
        }
    }
    assert_eq!(index, 4);
    let comparisons = population.finish();
    current_single_main();
    deadline.check();
    // A printed terminal is insufficient by itself: the recipe must also join
    // normal process closure. A late/failed write retains failure status.
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "native-selected:selection={LABEL}:required=4:pairs=4:children=8:comparisons={comparisons}:real-outer-ret=8:complete").unwrap();
    stdout.flush().unwrap();
    deadline.check();
}
