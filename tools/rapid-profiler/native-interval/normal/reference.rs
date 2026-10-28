//! Fixed original/installed reference enclosure witnesses. No duration accuracy claim.
use super::caller::{
    CallerError, FixtureOwner, FixtureSpec, Parsed, Result, parse_spec, require, sealed,
};
use super::*;
use native::reference::{self as witness, bytes as reference_bytes};
use rapid_profiler::frontend_native::GateError;
#[path = "../../normal-work/reference_owner.rs"]
mod owner;
// Literal existing ReferenceAmdV1 admission, applied on each actual child thread.
#[path = "../../src/frontend_native/always_on/gate/reference/hardware.rs"]
mod hardware;
use crate::{exact_truth as truth, ordinary::exact_body};
use native::ExactCase;

pub(super) const LABEL: &str = "normal-reference-exact-37-v1";
#[derive(Clone, Copy)]
pub(super) enum Profile {
    Legacy(Mode),
    Reference { cpu: usize },
}
impl Profile {
    pub(super) fn mode(self) -> Mode {
        match self {
            Self::Legacy(mode) => mode,
            Self::Reference { .. } => Mode::Stable,
        }
    }
    pub(super) fn exact_label(self) -> &'static str {
        match self {
            Self::Legacy(_) => exact::LABEL,
            Self::Reference { .. } => LABEL,
        }
    }
}
pub(super) struct ReferenceCall {
    owner: owner::CallerOwner,
    cells: u64,
    cpu: usize,
    output: Option<witness::Output>,
    checked_cells: Option<[reference_bytes::ReferenceCell; 2]>,
}
pub(super) enum Helper {
    Legacy(CallerOwner),
    Reference(Box<ReferenceCall>),
}
impl Helper {
    /// # Safety
    /// Same complete trusted ELF/loader/custody contract as the concrete owners.
    /// Reference cells are parent-owned, pre-fork initialized and private to this
    /// child; the fixed oracle envelope must authenticate the exact same address.
    pub(super) unsafe fn load(
        profile: Profile,
        context: &mut NormalContext<'_>,
        path: &Path,
        trusted: &[u8],
    ) -> Self {
        match profile {
            Profile::Legacy(_) => {
                Self::Legacy(unsafe { CallerOwner::load(path, trusted) }.unwrap())
            }
            Profile::Reference { cpu } => {
                assert!(context.exact_case().is_some());
                hardware::check().unwrap();
                check_cpu(cpu);
                let cells = context
                    .reference_cells_address()
                    .expect("owned reference cells");
                let output = context.reference_output();
                let owner = unsafe { owner::CallerOwner::load(path, trusted) }.unwrap();
                Self::Reference(Box::new(ReferenceCall {
                    owner,
                    cells,
                    cpu,
                    output: Some(output),
                    checked_cells: None,
                }))
            }
        }
    }
    pub(super) fn entry(&self) -> u64 {
        match self {
            Self::Legacy(c) => c.entry(),
            Self::Reference(c) => c.owner.entry(),
        }
    }
    pub(super) fn source(&self) -> (u64, &[u8]) {
        match self {
            Self::Legacy(c) => c.source(),
            Self::Reference(c) => c.owner.source(),
        }
    }
    pub(super) fn verify(&mut self) -> Result<()> {
        match self {
            Self::Legacy(c) => c.verify(),
            Self::Reference(c) => c.owner.verify(),
        }
    }
    pub(super) fn ready(&self, context: NormalContext<'_>, ready: &NormalReady) {
        match self {
            Self::Legacy(_) => context.ready(ready),
            Self::Reference(c) => {
                assert_eq!(context.reference_cells_address(), Some(c.cells));
                let mut protected = vec![
                    (
                        context.data_address(),
                        context
                            .data_address()
                            .checked_add(context.data_len() as u64)
                            .unwrap(),
                    ),
                    context.stack_range(),
                ];
                for (address, bytes) in ready.caller_immutable.iter().chain(&ready.immutable) {
                    protected.push((*address, address.checked_add(bytes.len() as u64).unwrap()));
                }
                if let Some(journal) = &ready.journal {
                    protected.push((journal.address, journal.address.checked_add(4096).unwrap()));
                }
                reference_bytes::validate_cell_area(c.cells, &protected).unwrap();
                let page = c.cells.checked_sub(128).unwrap();
                let end = page.checked_add(4096).unwrap();
                assert_eq!(page % 4096, 0);
                assert!(protected.iter().all(|&(a, b)| end <= a || b <= page));
                let actual = read_cells(c.cells);
                assert_eq!(actual, reference_bytes::fresh_cells(1, [1, 2]).unwrap());
                hardware::check().unwrap();
                check_cpu(c.cpu);
                let envelope = witness::ReferenceReady {
                    normal: ready.clone(),
                    cells: c.cells,
                };
                context.ready_reference(&envelope);
            }
        }
    }
    /// # Safety
    /// The actual helper/target/requests/results/cell owners remain live and
    /// disjoint through both ordinary CALL/RET pairs and real outer return.
    pub(super) unsafe fn invoke(
        &mut self,
        target: u64,
        requests: &[Request; 2],
        results: &mut [u64; 2],
    ) -> u64 {
        match self {
            Self::Legacy(caller) => unsafe { caller.invoke(target, requests, results) },
            Self::Reference(c) => {
                let cells =
                    unsafe { &mut *(c.cells as usize as *mut [reference_bytes::ReferenceCell; 2]) };
                unsafe { c.owner.invoke(target, requests, results, cells) }
            }
        }
    }
    // This runs only after actual helper return and complete common source/input
    // checks. A returned cell phase alone is never used as a physical-return proof.
    pub(super) fn postflight(&mut self, caller_rsp: u64, value: u64) {
        if let Self::Reference(c) = self {
            hardware::check().unwrap();
            check_cpu(c.cpu);
            assert!(c.checked_cells.is_none());
            let cells = read_cells(c.cells);
            check::reference_cells_match(&cells, caller_rsp, value)
                .expect("exact returned reference cells");
            c.checked_cells = Some(cells);
        }
    }
    pub(super) fn batch(&self, completed: &NormalBatch, facts: &Facts<'_>) {
        match self {
            Self::Legacy(_) => batch(completed, facts),
            Self::Reference(_) => {
                assert!(!facts.crossed);
                assert_eq!(
                    (
                        completed.pid(),
                        completed.tid(),
                        completed.registration(),
                        completed.install(),
                        completed.function()
                    ),
                    (std::process::id(), facts.tid, 1, INSTALL, FUNCTION)
                );
                assert_eq!(
                    (
                        completed.number(),
                        completed.next_ordinal(),
                        completed.completed_sequences()
                    ),
                    (1, 3, (0, 2))
                );
                assert_eq!(completed.totals(), (NormalTotals::default(), totals(2)));
                assert!(check::reference_rows_match(
                    completed.records(),
                    completed.journal(),
                    facts
                ));
            }
        }
    }
    // Complete the one owned packet only after all original postflight or the
    // installed checkpoint/Report/history/detach joins. Parent authenticates it
    // against every observed store after both ordinary successful child reaps.
    pub(super) fn finish(self) {
        if let Self::Reference(mut c) = self {
            let cells = c.checked_cells.take().expect("postflight before export");
            assert_eq!(read_cells(c.cells), cells);
            c.output.take().expect("one output packet").complete(&cells);
        }
    }
}
// The CLOSED oracle initializes a distinct 4096-byte page with 0x6d guards
// and puts the two cells at offset128 before fork. Authenticate that entire
// owned page before readiness, after real return and again before packet export.
fn read_cells(address: u64) -> [reference_bytes::ReferenceCell; 2] {
    let base = address.checked_sub(128).unwrap();
    assert_eq!(base % 4096, 0);
    // SAFETY: only the owned context's cell address reaches this private helper;
    // the mapping stays live/exclusive and disjoint throughout the child route.
    let page = unsafe { std::slice::from_raw_parts(base as usize as *const u8, 4096) };
    assert!(page[..128].iter().all(|&b| b == 0x6d));
    assert!(
        page[128 + reference_bytes::CELLS_BYTES..]
            .iter()
            .all(|&b| b == 0x6d)
    );
    unsafe { (address as usize as *const [reference_bytes::ReferenceCell; 2]).read() }
}
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
fn check_cpu(cpu: usize) {
    assert_eq!(allowed_cpus(), vec![cpu]);
    assert_eq!(unsafe { libc::sched_getcpu() }, i32::try_from(cpu).unwrap());
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

const HEADER: &str = "seed,length,status,children,comparisons,visits0,visits1,original_steps,candidate_steps,value0,value1,outer_value,instructions,conditional_branches,taken_branches,input_reads,return_reads,return_read_bytes,ret_offset0,ret_offset1,target_calls,target_returns,outer_returns,normal_reaps,reader_checks,output_stores,helper_heads,interior_heads,returned_cells,original0_start_ticks,original0_start_aux,original0_end_ticks,original0_end_aux,original1_start_ticks,original1_start_aux,original1_end_ticks,original1_end_aux,candidate0_start_ticks,candidate0_start_aux,candidate0_end_ticks,candidate0_end_aux,candidate1_start_ticks,candidate1_start_aux,candidate1_end_ticks,candidate1_end_aux\n";
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
    let cpu = pin_single();
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
    let mut observed = [0_usize; 5];
    for seed in SEEDS {
        for length in [1, 64] {
            if pairs != 0 {
                deadline = Deadline::start();
            }
            check_cpu(cpu);
            let case = ExactCase::new(seed, length);
            let input = case.input();
            assert_eq!(case.scalar(), truth::checksum(&input[..length]).unwrap());
            assert_eq!(case.counts(), truth::counts(length).unwrap());
            let oracle = NormalOracle::new_reference_exact(seed, length, deadline);
            let mut next_body = 0;
            let mut ret_offsets = [0; 2];
            let (pair, counts, stats) = oracle.pair_reference_exact(
                |candidate, context| {
                    child_with(
                        candidate,
                        context,
                        subject,
                        &selection,
                        caller_path,
                        &caller_elf,
                        Profile::Reference { cpu },
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
            assert_eq!(pair.visits, [6 * length + 5; 2]);
            assert_eq!(pair.comparisons, 34 + 2 * (6 * length + 5));
            assert_eq!(
                (
                    pair.target_calls,
                    pair.target_returns,
                    pair.outer_returns,
                    pair.normal_reaps
                ),
                (4, 4, 2, 2)
            );
            assert!((pair.comparisons + 46..=20_000).contains(&pair.original_steps));
            assert!((pair.comparisons + 46..=20_000).contains(&pair.candidate_steps));
            let witnesses = [
                stats.reader_checks,
                stats.output_stores,
                stats.helper_heads,
                stats.interior_heads,
                stats.returned_cells,
            ];
            assert_eq!(witnesses, [8, 24, 160, 92, 4]);
            for (total, count) in observed.iter_mut().zip(witnesses) {
                *total += count;
            }
            let work = counts[0];
            comparisons += pair.comparisons;
            instructions += 2 * work.0;
            conditional += 2 * work.1;
            taken += 2 * work.2;
            input_reads += 2 * (work.3 - 1);
            return_reads += 2;
            csv.push_str(&format!(
                "{seed},{length},PASS,2,{},{},{},{},{},{},{},{},{},{},{},{},2,16,{},{},4,4,2,2,8,24,160,92,4",
                pair.comparisons, pair.visits[0], pair.visits[1], pair.original_steps, pair.candidate_steps,
                pair.values[0], pair.values[1], pair.outer_value, 2*work.0, 2*work.1, 2*work.2, 2*(work.3-1), ret_offsets[0], ret_offsets[1]
            ));
            for endpoints in stats.endpoints {
                assert_eq!(endpoints[0].start.aux, endpoints[0].end.aux);
                assert_eq!(endpoints[0].start.aux, endpoints[1].start.aux);
                assert_eq!(endpoints[0].start.aux, endpoints[1].end.aux);
                assert!(endpoints[0].start.ticks <= endpoints[0].end.ticks);
                assert!(endpoints[0].end.ticks <= endpoints[1].start.ticks);
                assert!(endpoints[1].start.ticks <= endpoints[1].end.ticks);
                for e in endpoints {
                    csv.push_str(&format!(
                        ",{},{},{},{}",
                        e.start.ticks, e.start.aux, e.end.ticks, e.end.aux
                    ));
                }
            }
            csv.push('\n');
            check_cpu(cpu);
            assert!(csv.len() <= 65536);
            std::fs::write(output.join("normal-reference-pairs.csv"), &csv).unwrap();
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
        (4, 1736, 1600, 260, 252, 260, 8)
    );
    assert_eq!(observed, [32, 96, 640, 368, 16]);
    current_single_main();
    deadline.check();
    let mut out = std::io::stdout().lock();
    writeln!(out, "native-normal-reference:selection=normal-reference-exact-37-v1:required=4:pairs=4:children=8:comparisons=1736:instructions=1600:conditional=260:taken=252:input-reads=260:return-reads=8:return-read-bytes=64:target-calls=16:target-returns=16:real-outer-ret=8:normal-reaps=8:reader-checks=32:output-stores=96:helper-heads=640:interior-heads=368:returned-cells=16:complete").unwrap();
    out.flush().unwrap();
    deadline.check();
}
