//! Thirty-two CSV body pairs under the existing 67-byte ordinary caller.
use super::*;
use native::csv::{
    Arguments as CsvArguments, Case, LABEL as CSV_LABEL, Population as CsvPopulation,
};
const HEADER: &str = "seed,case,length,status,children,comparisons,visits0,visits1,original_steps,candidate_steps,value0,value1,outer_value,ret_offset0,ret_offset1,heads0,heads1,edges0,edges1,declared_returns,target_calls,target_returns,outer_returns,normal_reaps\n";
const COVERAGE: &str = "seed,cases,observed_heads,declared_heads,observed_edges,declared_edges,observed_returns,declared_returns\n";

pub(crate) fn run(
    subject: &Path,
    expected: &Path,
    arguments: CsvArguments,
    caller_path: &Path,
    caller_expected: &Path,
    output: &Path,
    mut deadline: Deadline,
) {
    deadline.check();
    current_single_main();
    let elf = trusted(subject, expected);
    let caller_elf = trusted(caller_path, caller_expected);
    let selection =
        TrustedFunctionSelection::new(&elf, arguments.elf_va, arguments.length, CSV_LABEL).unwrap();
    let mut population = CsvPopulation::default();
    let mut csv = String::from(HEADER);
    let mut coverage = String::from(COVERAGE);
    let mut count = 0;
    let mut covered = 0;
    for seed in SEEDS {
        for index in 0..16 {
            if count != 0 {
                deadline = Deadline::start();
            }
            let case = Case::new(index);
            let oracle = NormalOracle::new_csv(seed, case, arguments.length, deadline);
            let (pair, trace) = oracle.pair_csv(|candidate, context| {
                // Each callback runs only in its dedicated freshly forked child.
                // Abort before unwinding any child-local code/input/SDK owners.
                // The parent independently requires normal exit-zero/reap/ECHILD.
                std::panic::set_hook(Box::new(|info| {
                    eprintln!("native CSV child FAILED: {info}");
                    std::process::abort();
                }));
                child(
                    candidate,
                    context,
                    subject,
                    &selection,
                    caller_path,
                    &caller_elf,
                    Mode::Stable,
                )
            });
            if let Some(c) = population.record(seed, case, &pair, &trace) {
                assert_eq!(index, 15);
                coverage.push_str(&format!(
                    "{seed},16,{},{},{},{},{},{}\n",
                    c.heads, c.declared_heads, c.edges, c.declared_edges, c.returns, c.returns
                ));
                covered += 1;
            }
            let [a, b] = &trace.bodies;
            csv.push_str(&format!(
                "{seed},{},{},PASS,2,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},4,4,2,2\n",
                case.id(),
                case.length(),
                pair.comparisons,
                pair.visits[0],
                pair.visits[1],
                pair.original_steps,
                pair.candidate_steps,
                pair.values[0],
                pair.values[1],
                pair.outer_value,
                a.ret_offset,
                b.ret_offset,
                a.heads.len(),
                b.heads.len(),
                a.edges.len(),
                b.edges.len(),
                pair.declared_returns.len()
            ));
            // Complete bounded rows only, after BOTH normal reaps and body inspection.
            std::fs::write(output.join("normal-csv-pairs.csv"), &csv).unwrap();
            std::fs::write(output.join("normal-csv-coverage.csv"), &coverage).unwrap();
            drop(oracle);
            deadline.check();
            count += 1;
        }
    }
    assert_eq!((count, covered), (32, 2));
    let comparisons = population.finish();
    current_single_main();
    deadline.check();
    let mut out = std::io::stdout().lock();
    writeln!(out,"native-normal-csv:selection={CSV_LABEL}:required=32:pairs=32:children=64:comparisons={comparisons}:coverage-seeds=2:cases-per-seed=16:target-calls=128:target-returns=128:real-outer-ret=64:normal-reaps=64:complete").unwrap();
    out.flush().unwrap();
    deadline.check();
}
