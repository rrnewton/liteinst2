//! Twelve fixed loaded linked-memory pairs. No hardware cache/timing claim.
use super::{Path, STATE_SEEDS, current_single_main, oracle, ordinary};
use oracle::native_ordinary::{OrdinaryOracle, cache};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

// Same separately trusted complete-ELF contract as the old ordinary driver.
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
    let expected_elf = expected_bytes(subject, expected);
    let mut csv = String::from(
        "seed,case,status,children,comparisons,original_visits,original_steps,candidate_steps,instructions,conditional_branches,taken_branches,input_reads,return_reads,model_events,model_hits,model_misses,model_hit_bits,value\n",
    );
    let mut totals = [0_usize; 10];
    let mut last_deadline = None;
    for seed in STATE_SEEDS {
        let mut observed_returns = BTreeSet::new();
        let mut declared_returns = None;
        for case in cache::truth::ALL {
            // This establishes (seed,case) before either real call; the closed
            // context carries this exact input/identity into both child paths.
            let oracle = OrdinaryOracle::new_cache(case, seed);
            let deadline = oracle.cache_deadline();
            let mut stats = None;
            let result = oracle.pair_cache(
                |candidate, context| {
                    ordinary::child_cache(candidate, context, subject, &expected_elf)
                },
                |actual| {
                    stats = Some(cache::inspect(case, seed, actual));
                },
            );
            assert!(Instant::now() < deadline);
            let cache::Stats { counts, model } = stats.expect("actual original trace inspected");
            assert_eq!(result.visits, counts.instructions);
            assert_eq!(
                result.comparisons,
                result.visits + 11,
                "all Legacy gate and subject boundaries"
            );
            assert!((1..=20_000).contains(&result.original_steps));
            assert!((1..=20_000).contains(&result.candidate_steps));
            assert_eq!(result.value, cache::truth::scalar(case, seed));
            assert_eq!(result.returns.len(), 1);
            assert_eq!(result.returns, result.declared_returns);
            if let Some(previous) = &declared_returns {
                assert_eq!(previous, &result.declared_returns);
            } else {
                declared_returns = Some(result.declared_returns.clone());
            }
            observed_returns.extend(result.returns);
            let bits: String = model
                .hit_by_read
                .iter()
                .map(|&hit| if hit { '1' } else { '0' })
                .collect();
            assert_eq!(bits.len(), model.accesses);
            csv.push_str(&format!(
                "{seed},{},PASS,2,{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                case.name(),
                result.comparisons,
                result.visits,
                result.original_steps,
                result.candidate_steps,
                counts.instructions,
                counts.conditional,
                counts.taken,
                counts.input_reads,
                counts.return_reads,
                model.accesses,
                model.hits,
                model.misses,
                bits,
                result.value
            ));
            let values = [
                1,
                result.comparisons,
                counts.instructions,
                counts.conditional,
                counts.taken,
                counts.input_reads,
                counts.return_reads,
                model.accesses,
                model.hits,
                model.misses,
            ];
            for (total, value) in totals.iter_mut().zip(values) {
                *total = total.checked_add(value).unwrap();
            }
            std::fs::write(output.join("cache-pairs.csv"), &csv).unwrap();
            assert!(Instant::now() < deadline, "cache complete output deadline");
            last_deadline = Some(deadline);
        }
        assert_eq!(
            observed_returns,
            declared_returns.unwrap(),
            "complete actual RET union per seed"
        );
    }
    assert_eq!(
        totals,
        [12, 3564, 3432, 672, 660, 1356, 12, 1368, 1040, 328]
    );
    current_single_main();
    assert!(
        Instant::now() < last_deadline.unwrap(),
        "cache final output deadline"
    );
    println!(
        "native-cache:required=12:pairs=12:children=24:comparisons={}:instructions=3432:conditional=672:taken=660:input-reads=1356:return-reads=12:model-events=1368:model-misses=328:real-outer-ret=24:complete",
        totals[1]
    );
    assert!(
        Instant::now() < last_deadline.unwrap(),
        "cache terminal output deadline"
    );
}
