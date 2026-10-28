//! Four fixed original/installed ordinary C caller pairs, not a timing reference.
use super::*;
use crate::{exact_truth as truth, ordinary::exact_body};
use native::ExactCase;
pub(super) const LABEL: &str = "normal-exact-37-v1";
const HEADER: &str = "seed,length,status,children,comparisons,visits0,visits1,original_steps,candidate_steps,value0,value1,outer_value,instructions,conditional_branches,taken_branches,input_reads,return_reads,return_read_bytes,ret_offset0,ret_offset1,target_calls,target_returns,outer_returns,normal_reaps\n";

pub(crate) fn run(
    subject: &Path,
    expected: &Path,
    arguments: Arguments,
    caller_path: &Path,
    caller_expected: &Path,
    output: &Path,
    mut deadline: Deadline,
) {
    deadline.check();
    current_single_main();
    assert_eq!(arguments.length, truth::BYTES.len());
    let elf = trusted(subject, expected);
    let caller_elf = trusted(caller_path, caller_expected);
    let selection =
        TrustedFunctionSelection::new(&elf, arguments.elf_va, arguments.length, LABEL).unwrap();
    let mut csv = String::from(HEADER);
    let mut pairs = 0;
    let (
        mut comparisons,
        mut instructions,
        mut conditional,
        mut taken,
        mut input_reads,
        mut return_reads,
    ) = (0, 0, 0, 0, 0, 0);
    for seed in SEEDS {
        for length in [1, 64] {
            if pairs != 0 {
                deadline = Deadline::start();
            }
            let case = ExactCase::new(seed, length);
            let input = case.input();
            assert_eq!(case.scalar(), truth::checksum(&input[..length]).unwrap());
            assert_eq!(case.counts(), truth::counts(length).unwrap());
            let oracle = NormalOracle::new_exact(seed, length, deadline);
            let mut next_body = 0;
            let mut ret_offsets = [0; 2];
            let (pair, counts) = oracle.pair_exact(
                |candidate, context| {
                    child(
                        candidate,
                        context,
                        subject,
                        &selection,
                        caller_path,
                        &caller_elf,
                        Mode::Stable,
                    )
                },
                |index, body| {
                    assert_eq!(index, next_body);
                    next_body += 1;
                    ret_offsets[index] = body
                        .steps
                        .last()
                        .unwrap()
                        .before
                        .rip
                        .checked_sub(body.entry)
                        .unwrap();
                    assert_eq!(body.input, &input[..length]);
                    exact_body::check(
                        body.code,
                        body.input,
                        body.entry,
                        body.input_address,
                        body.continuation,
                        body.steps,
                    )
                },
            );
            assert_eq!(next_body, 2);
            assert_eq!(ret_offsets, [36; 2]);
            assert_eq!(counts, [truth::counts(length).unwrap(); 2]);
            assert_eq!(pair.values, [truth::checksum(&input[..length]).unwrap(); 2]);
            assert_eq!(
                pair.outer_value,
                pair.values[0].wrapping_add(pair.values[1])
            );
            assert_eq!(pair.comparisons, 24 + 2 * (6 * length + 5));
            let work = counts[0];
            comparisons += pair.comparisons;
            instructions += 2 * work.0;
            conditional += 2 * work.1;
            taken += 2 * work.2;
            input_reads += 2 * (work.3 - 1);
            return_reads += 2;
            csv.push_str(&format!(
                "{seed},{length},PASS,2,{},{},{},{},{},{},{},{},{},{},{},{},2,16,{},{},4,4,2,2\n",
                pair.comparisons,
                pair.visits[0],
                pair.visits[1],
                pair.original_steps,
                pair.candidate_steps,
                pair.values[0],
                pair.values[1],
                pair.outer_value,
                2 * work.0,
                2 * work.1,
                2 * work.2,
                2 * (work.3 - 1),
                ret_offsets[0],
                ret_offsets[1]
            ));
            std::fs::write(output.join("normal-exact-pairs.csv"), &csv).unwrap();
            drop(oracle);
            deadline.check();
            pairs += 1;
        }
    }
    assert_eq!(
        (
            pairs,
            comparisons,
            instructions,
            conditional,
            taken,
            input_reads,
            return_reads
        ),
        (4, 1696, 1600, 260, 252, 260, 8)
    );
    current_single_main();
    deadline.check();
    let mut out = std::io::stdout().lock();
    writeln!(out, "native-normal-exact:selection={LABEL}:required=4:pairs=4:children=8:comparisons=1696:instructions=1600:conditional=260:taken=252:input-reads=260:return-reads=8:return-read-bytes=64:target-calls=16:target-returns=16:real-outer-ret=8:normal-reaps=8:complete").unwrap();
    out.flush().unwrap();
    deadline.check();
}
