//! Fixed ordinary-call collector. Raw enclosures are not calibrated durations.
use super::caller::{reference::CallerOwner as ReferenceOwner, reference_bytes as bytes};
use super::*;
use crate::exact::truth;
use rapid_profiler::frontend_native::GateError;
mod check;
#[path = "../../src/frontend_native/always_on/gate/reference/hardware.rs"]
mod hardware;

const LABEL: &str = "normal-reference-exact-37-v1";
const INSTALL: u64 = 0x6e72_6566;
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const CALLS: usize = 24;
const PAIRS: usize = CALLS / 2;
const GUARD: u8 = 0xa7;
const HEADER: &str = "leg,id,repeat,seed_index,seed,length,input_fnv1a64,value,instructions,conditional_branches,taken_branches,input_bytes,ret_bytes,reference_sequence,reference_start_ticks,reference_end_ticks,reference_start_aux,reference_end_aux,reference_rsp,reference_ticks,pid,tid,registration,install,function,generation,ordinal,owner,invocation,history_prefix,entry_pc,return_pc,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,entry_gap_ticks,return_gap_ticks,ack,ack_ordinal";
const SCOPE: &str = "# normal reference collector; raw same-call endpoints are uncalibrated; no accuracy or performance claim";
const TERMINAL: &str = "normal-reference-work FUNCTIONAL_PASS selection=normal-reference-exact-37-v1 originals=24 installed=24 helper_calls=24 reference_cells=48 batches=1 events=48 reports=1 records=24 actions=2 entered=24 ret_observed=24 confirmed=24 completed=24 unsampled=0 whole_journal_words=512 per_leg_instructions=4800 per_leg_conditional=780 per_leg_taken=756 per_leg_input_bytes=780 per_leg_ret_bytes=192 input_unchanged=true joined=true";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Case {
    repeat: usize,
    seed: usize,
    length: usize,
    value: u64,
}
fn case(pair: usize) -> Case {
    assert!(pair < PAIRS);
    let seed = pair % 4 / 2;
    let length = if pair % 2 == 0 { 1 } else { 64 };
    let input = input(seed);
    let value = input[16..16 + length]
        .iter()
        .map(|b| u64::from(b ^ 0x5a))
        .sum::<u64>()
        ^ 0x9e37_79b9_7f4a_7c15;
    assert_eq!(value, truth::checksum(&input[16..16 + length]).unwrap());
    Case {
        repeat: pair / 4 + 1,
        seed,
        length,
        value,
    }
}
fn input(seed: usize) -> [u8; 96] {
    assert!(seed < SEEDS.len());
    let mut input = [GUARD; 96];
    for (j, byte) in input[16..80].iter_mut().enumerate() {
        *byte = (37 * j + 11 + seed) as u8;
    }
    input
}
fn digest(input: &[u8]) -> u64 {
    assert_eq!(input.len(), 64);
    input.iter().fold(14_695_981_039_346_656_037, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(1_099_511_628_211)
    })
}

#[repr(C, align(4096))]
struct CellPage {
    before: [u8; 128],
    cells: [bytes::ReferenceCell; 2],
    after: [u8; 3680],
}
impl CellPage {
    fn new(pair: usize) -> Self {
        let id = ((pair % PAIRS) * 2 + 1) as u64;
        Self {
            before: [GUARD; 128],
            cells: bytes::fresh_cells((pair * 2 + 1) as u64, [id, id + 1]).unwrap(),
            after: [GUARD; 3680],
        }
    }
    fn guarded(&self) -> bool {
        self.before == [GUARD; 128] && self.after == [GUARD; 3680]
    }
    fn area(&self) -> (u64, u64) {
        let start = self as *const Self as usize as u64;
        assert_eq!(start % 4096, 0);
        (start, start.checked_add(4096).unwrap())
    }
    fn separate(&self, protected: &[(u64, u64)]) -> bool {
        let (a, b) = self.area();
        self.guarded()
            && protected.iter().all(|&(x, y)| x < y && (b <= x || y <= a))
            && bytes::validate_cell_area(self.cells.as_ptr() as usize as u64, protected).is_ok()
    }
}
const _: () = assert!(std::mem::size_of::<CellPage>() == 4096);

fn range<T: ?Sized>(value: &T) -> (u64, u64) {
    let start = std::ptr::from_ref(value).cast::<()>() as usize as u64;
    (
        start,
        start
            .checked_add(std::mem::size_of_val(value) as u64)
            .unwrap(),
    )
}
fn cpu_is(cpu: usize) {
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) },
        0
    );
    assert_eq!(unsafe { libc::CPU_COUNT(&mask) }, 1);
    assert!(unsafe { libc::CPU_ISSET(cpu, &mask) });
    assert_eq!(unsafe { libc::sched_getcpu() }, i32::try_from(cpu).unwrap());
}

// Private consumer copy of the actual-VMA observation, retaining its bounds for
// returned-cell consistency. The old stack() and public opaque type stay literal.
fn readable_stack() -> (ReadableStack, (u64, u64)) {
    establish_callback_stack();
    let rsp: u64;
    unsafe {
        std::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let rows: Vec<_> = maps
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (a, b) = words.next()?.split_once('-')?;
            let (a, b) = (
                u64::from_str_radix(a, 16).ok()?,
                u64::from_str_radix(b, 16).ok()?,
            );
            (a <= rsp && rsp < b).then(|| (a, b, words.next().unwrap()))
        })
        .collect();
    assert_eq!(rows.len(), 1);
    let (a, b, permissions) = rows[0];
    assert_eq!(permissions, "rw-p");
    assert!(rsp.checked_sub(a).is_some_and(|n| n >= 128 * 1024));
    // SAFETY: this sole actual thread retains its mapped stack through all real
    // returns, with no signal, cancellation, unmap or nonlocal exit.
    (unsafe { ReadableStack::new(a, b) }.unwrap(), (a, b))
}
fn files(candidate: &Path, trusted: &Path, expected: &[u8]) {
    assert_eq!(expected_file(candidate, trusted), expected);
    let mut actual = Vec::new();
    File::open(candidate)
        .unwrap()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, expected);
}
fn completed_storage(
    pages: &[CellPage],
    snapshots: &[[bytes::ReferenceCell; 2]],
    results: &[[u64; 2]],
) {
    assert_eq!(pages.len(), PAIRS * 2);
    assert_eq!(results.len(), PAIRS * 2);
    assert!(snapshots.len() <= pages.len());
    for (i, page) in pages.iter().enumerate() {
        assert!(page.guarded());
        if let Some(saved) = snapshots.get(i) {
            assert_eq!(&page.cells, saved);
            assert_eq!(results[i], [case(i % PAIRS).value; 2]);
        } else {
            assert_eq!(page.cells, CellPage::new(i).cells);
            assert_eq!(results[i], [u64::MAX; 2]);
        }
    }
}
fn pending(n: u64) -> NormalTotals {
    assert!((1..=CALLS as u64).contains(&n));
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed: n - 1,
        completed: n - 1,
        unsampled: 0,
    }
}
fn complete() -> NormalTotals {
    NormalTotals {
        entered: 24,
        ret_observed: 24,
        confirmed: 24,
        completed: 24,
        unsampled: 0,
    }
}

// Declared after the live controller/attachment and before any installed CALL.
// A failed assertion cannot unwind those owners first. Callback fatal policy is
// untouched. This guard never manufactures successful cleanup or a checkpoint.
struct FailStop(bool);
impl Drop for FailStop {
    fn drop(&mut self) {
        if self.0 {
            std::process::abort();
        }
    }
}

pub(crate) fn run(
    candidate: &Path,
    trusted: &Path,
    elf_va: u64,
    length: u64,
    caller_candidate: &Path,
    caller_trusted: &Path,
) {
    single_main();
    let cpu = pin(None);
    cpu_is(cpu);
    hardware::check().unwrap();
    let pid = std::process::id();
    let tid = u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
    assert_eq!(tid, u64::from(pid));
    assert_eq!(length, 37);
    let trusted_bytes = expected_file(candidate, trusted);
    let helper_bytes = expected_file(caller_candidate, caller_trusted);
    // SAFETY: the recipe supplies independent complete trusted ELFs. This finite
    // process has no writer, signals, CET, reentry, fork, cancellation or unload.
    // All calls are readonly scalar leaves, one actual caller, full bounded input.
    let mut calling = unsafe { ReferenceOwner::load(caller_candidate, &helper_bytes) }.unwrap();
    let selection = TrustedFunctionSelection::new(&trusted_bytes, elf_va, 37, LABEL).unwrap();
    let owner =
        unsafe { LoadedNormalLeaf::load_selected(candidate, &selection, NORMAL_CONTRACT) }.unwrap();
    truth::check_bytes(owner.code()).unwrap();
    let entry = owner.entry();
    assert_eq!(
        owner.certificate().heads(),
        truth::HEADS.map(|o| entry + u64::from(o))
    );
    assert_eq!(
        owner.certificate().returns(),
        [entry.checked_add(36).unwrap()]
    );
    assert_eq!(
        owner.certificate().range(),
        (entry, entry.checked_add(37).unwrap())
    );
    let caller_entry = calling.entry();
    let mut spans = vec![
        (owner.source_range().0, owner.original_source().to_vec()),
        (calling.source().0, calling.source().1.to_vec()),
    ];
    let cases: [Case; PAIRS] = std::array::from_fn(case);
    let expected_input: [[u8; 96]; PAIRS] = std::array::from_fn(|p| input(cases[p].seed));
    let inputs = Box::new(expected_input);
    let requests: Box<[[bytes::Request; 2]; PAIRS]> = Box::new(std::array::from_fn(|p| {
        [bytes::Request {
            data: inputs[p][16..80].as_ptr(),
            bound: cases[p].length as u64,
        }; 2]
    }));
    let mut results = Box::new([[u64::MAX; 2]; PAIRS * 2]);
    let mut pages: Box<[CellPage]> = (0..PAIRS * 2).map(CellPage::new).collect();
    let mut snapshots = Vec::with_capacity(PAIRS * 2);
    let mut original = Vec::with_capacity(CALLS);
    let mut installed = Vec::with_capacity(CALLS);
    let (readable, stack_bounds) = readable_stack();
    let journal = IntervalJournal::allocate();
    let journal_range = (
        journal.address(),
        journal.address().checked_add(4096).unwrap(),
    );
    let mut protected = vec![
        stack_bounds,
        range(inputs.as_ref()),
        range(requests.as_ref()),
        range(results.as_ref()),
        journal_range,
    ];
    protected.extend(
        spans
            .iter()
            .map(|(a, b)| (*a, a.checked_add(b.len() as u64).unwrap())),
    );
    for page in pages.iter() {
        assert!(page.separate(&protected));
    }
    for p in 0..PAIRS {
        owner.verify_original().unwrap();
        calling.verify().unwrap();
        unsafe { immutable(&spans) };
        cpu_is(cpu);
        hardware::check().unwrap();
        // SAFETY: all source/stack/data/cell extents are retained and disjoint;
        // both requests share exactly this immutable input and length. This is
        // one actual helper call with two ordinary subject CALLs and an outer RET.
        let sum =
            unsafe { calling.invoke(entry, &requests[p], &mut results[p], &mut pages[p].cells) };
        assert_eq!(sum, cases[p].value.wrapping_add(cases[p].value));
        assert_eq!(results[p], [cases[p].value; 2]);
        assert_eq!(*inputs, expected_input);
        owner.verify_original().unwrap();
        calling.verify().unwrap();
        files(candidate, trusted, &trusted_bytes);
        files(caller_candidate, caller_trusted, &helper_bytes);
        unsafe { immutable(&spans) };
        cpu_is(cpu);
        hardware::check().unwrap();
        assert!(pages.iter().all(CellPage::guarded));
        for (i, saved) in snapshots.iter().enumerate() {
            assert_eq!(&pages[i].cells, saved);
        }
        let views = std::array::from_fn::<_, 2, _>(|j| {
            let id = (2 * p + j + 1) as u64;
            pages[p].cells[j]
                .returned_view(id, id, results[p][j], stack_bounds)
                .unwrap()
        });
        assert_eq!(
            views[0].observed_pre_call_rsp,
            views[1].observed_pre_call_rsp
        );
        for view in views {
            original.push(check::Collected {
                seed_index: cases[p].seed,
                length: cases[p].length,
                value: cases[p].value,
                reference: view,
            });
        }
        snapshots.push(pages[p].cells);
        completed_storage(&pages, &snapshots, results.as_ref());
    }
    owner.verify_original().unwrap();
    let prep = NormalSitePreparation::new_whole_function(owner, identity(entry)).unwrap();
    assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, entry + 36]);
    spans = prep
        .plan()
        .plan()
        .final_bytes()
        .iter()
        .map(|s| (s.address, s.bytes.clone()))
        .collect();
    spans.extend(
        prep.plan()
            .images()
            .iter()
            .map(|i| (i.address(), i.bytes().to_vec())),
    );
    spans.push((calling.source().0, calling.source().1.to_vec()));
    protected.extend(
        spans
            .iter()
            .map(|(a, b)| (*a, a.checked_add(b.len() as u64).unwrap())),
    );
    for page in pages.iter() {
        assert!(page.separate(&protected));
    }
    let site = publish(prep);
    unsafe { immutable(&spans) };
    let mut prepared = PreparedNormalController::new(
        site,
        INSTALL,
        FUNCTION,
        Limits {
            epochs: 1,
            threads: 1,
            depth: 1,
            records_per_epoch: 24,
            actions: 2,
        },
    )
    .unwrap();
    let epoch = prepared
        .stage(Config {
            retained_per_function: 24,
            max_inflight: 1,
            max_invocations: 24,
        })
        .unwrap();
    let generation = epoch.generation().get();
    // SAFETY: sole actual calling/controller thread, no active subject or callback.
    let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
    controller.arm(&epoch).unwrap();
    let mut attached = unsafe { client.attach(1, readable, journal) }.unwrap();
    assert_eq!(attached.totals().unwrap(), NormalTotals::default());
    let mut fail_stop = FailStop(true);
    for p in 0..PAIRS {
        let at = PAIRS + p;
        calling.verify().unwrap();
        unsafe { immutable(&spans) };
        cpu_is(cpu);
        hardware::check().unwrap();
        // SAFETY: same complete custody as the original leg; the NormalThread
        // stays attached on this actual thread. There is no per-call SDK gate.
        let sum =
            unsafe { calling.invoke(entry, &requests[p], &mut results[at], &mut pages[at].cells) };
        assert_eq!(sum, cases[p].value.wrapping_add(cases[p].value));
        assert_eq!(results[at], results[p]);
        assert_eq!(results[at], [cases[p].value; 2]);
        assert_eq!(*inputs, expected_input);
        calling.verify().unwrap();
        files(candidate, trusted, &trusted_bytes);
        files(caller_candidate, caller_trusted, &helper_bytes);
        unsafe { immutable(&spans) };
        cpu_is(cpu);
        hardware::check().unwrap();
        assert!(pages.iter().all(CellPage::guarded));
        for (i, saved) in snapshots.iter().enumerate() {
            assert_eq!(&pages[i].cells, saved);
        }
        let views = std::array::from_fn::<_, 2, _>(|j| {
            let id = (2 * p + j + 1) as u64;
            pages[at].cells[j]
                .returned_view(id + 24, id, results[at][j], stack_bounds)
                .unwrap()
        });
        assert_eq!(
            views[0].observed_pre_call_rsp,
            views[1].observed_pre_call_rsp
        );
        for view in views {
            installed.push(check::Collected {
                seed_index: cases[p].seed,
                length: cases[p].length,
                value: cases[p].value,
                reference: view,
            });
        }
        snapshots.push(pages[at].cells);
        completed_storage(&pages, &snapshots, results.as_ref());
        assert_eq!(attached.totals().unwrap(), pending((2 * p + 2) as u64));
    }
    assert_eq!(*inputs, expected_input);
    for (i, saved) in snapshots.iter().enumerate() {
        assert_eq!(&pages[i].cells, saved);
    }
    assert!(pages.iter().all(CellPage::guarded));
    calling.verify().unwrap();
    files(candidate, trusted, &trusted_bytes);
    files(caller_candidate, caller_trusted, &helper_bytes);
    unsafe { immutable(&spans) };
    cpu_is(cpu);
    hardware::check().unwrap();
    // SAFETY: all 12 real installed helper invocations returned normally; complete
    // postflight above precedes acknowledgement. Neither a cell phase nor the
    // pending counter is being treated as an observed physical RET.
    let batch = unsafe { attached.checkpoint_after_returns() }
        .unwrap()
        .expect("24 returned calls");
    assert_eq!(attached.totals().unwrap(), complete());
    assert!(
        unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .is_none()
    );
    assert_eq!(attached.detach().unwrap(), complete());
    controller.disarm(&epoch).unwrap();
    let report = controller
        .report(&epoch)
        .unwrap()
        .expect("24 confirmed retained records");
    let history = controller.history().unwrap();
    let expected = check::Expected {
        pid,
        tid,
        install: INSTALL,
        function: FUNCTION,
        registration: 1,
        entry,
        caller: caller_entry,
        generation,
    };
    let gaps = check::validate(expected, &original, &installed, &batch, &report, &history).unwrap();
    assert_eq!(*inputs, expected_input);
    completed_storage(&pages, &snapshots, results.as_ref());
    single_main();
    cpu_is(cpu);
    calling.verify().unwrap();
    unsafe { immutable(&spans) };
    // Every source/data/owner join passed and the attachment is really detached.
    // No code reclamation permission follows; sealed owners remain process-lived.
    fail_stop.0 = false;
    println!("{SCOPE}\n{HEADER}");
    for (i, observed) in original.iter().enumerate() {
        println!(
            "{}",
            row(i, observed, pid, tid, &inputs[i / 2][16..80], None)
        );
    }
    for (i, observed) in installed.iter().enumerate() {
        println!(
            "{}",
            row(
                i,
                observed,
                pid,
                tid,
                &inputs[i / 2][16..80],
                Some((&batch.records()[i], gaps[i], generation))
            )
        );
    }
    println!("{TERMINAL}");
}

fn row(
    i: usize,
    observed: &check::Collected,
    pid: u32,
    tid: u64,
    input: &[u8],
    installed: Option<(
        &rapid_profiler::frontend_native::NormalRecord,
        check::Gaps,
        u64,
    )>,
) -> String {
    let c = case(i / 2);
    let r = observed.reference;
    let (a, b) = (r.enclosure.start, r.enclosure.end);
    let mut fields = vec![
        if installed.is_some() {
            "installed"
        } else {
            "original"
        }
        .to_owned(),
        (i + 1).to_string(),
        c.repeat.to_string(),
        c.seed.to_string(),
        SEEDS[c.seed].to_string(),
        c.length.to_string(),
        digest(input).to_string(),
        observed.value.to_string(),
        (6 * c.length + 5).to_string(),
        c.length.to_string(),
        (c.length - 1).to_string(),
        c.length.to_string(),
        "8".to_owned(),
        r.sequence.to_string(),
        a.ticks.to_string(),
        b.ticks.to_string(),
        a.aux.to_string(),
        b.aux.to_string(),
        r.observed_pre_call_rsp.to_string(),
        b.ticks.checked_sub(a.ticks).unwrap().to_string(),
        pid.to_string(),
        tid.to_string(),
    ];
    if let Some((record, gap, generation)) = installed {
        assert_eq!(gap.enclosure, b.ticks.checked_sub(a.ticks).unwrap());
        fields.extend([
            "1".to_owned(),
            INSTALL.to_string(),
            FUNCTION.0.to_string(),
            generation.to_string(),
            record.raw.ordinal.to_string(),
            "sampled".to_owned(),
            i.to_string(),
            record.history_prefix.to_string(),
            record.raw.entry_pc.to_string(),
            record.raw.return_pc.to_string(),
            record.entry_rsp.to_string(),
            record.return_word.to_string(),
            record.raw.start.ticks.to_string(),
            record.raw.end.ticks.to_string(),
            record.raw.start.aux.to_string(),
            record.raw.end.aux.to_string(),
            gap.raw.to_string(),
            gap.entry.to_string(),
            gap.exit.to_string(),
        ]);
        let ack = match record.acknowledgement {
            NormalAcknowledgement::NextEntry { ordinal } => ("next-entry", ordinal.to_string()),
            NormalAcknowledgement::CallerCheckpoint => ("caller-checkpoint", String::new()),
        };
        fields.extend([ack.0.to_owned(), ack.1]);
    } else {
        fields.resize(43, String::new());
    }
    assert_eq!(fields.len(), 43);
    fields.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_population_preserves_inputs_scalars_and_complete_work() {
        let mut total = [0; 5];
        for p in 0..PAIRS {
            let c = case(p);
            assert_eq!(c.repeat, p / 4 + 1);
            assert_eq!(c.seed, p % 4 / 2);
            assert_eq!(c.length, [1, 64][p % 2]);
            let actual = input(c.seed);
            assert_eq!(&actual[..16], &[GUARD; 16]);
            assert_eq!(&actual[80..], &[GUARD; 16]);
            for (j, byte) in actual[16..80].iter().enumerate() {
                assert_eq!(*byte, (37 * j + 11 + c.seed) as u8);
            }
            let (instructions, branches, taken, reads) = truth::counts(c.length).unwrap();
            let quantities = [instructions, branches, taken, reads - 1, 8];
            for (sum, count) in total.iter_mut().zip(quantities) {
                *sum += 2 * count;
            }
            assert_eq!(
                c.value,
                truth::checksum(&actual[16..16 + c.length]).unwrap()
            );
        }
        assert_eq!(total, [4800, 780, 756, 780, 192]);
        assert!(std::panic::catch_unwind(|| case(PAIRS)).is_err());
    }
    #[test]
    fn full_cell_page_guards_and_disjoint_extents_are_required() {
        let mut page = Box::new(CellPage::new(0));
        let (a, b) = page.area();
        assert!(page.separate(&[(a - 1, a), (b, b + 1)]));
        for overlap in [(a, a + 1), (a + 127, a + 128), (b - 1, b)] {
            assert!(!page.separate(&[overlap]));
        }
        assert!(!page.separate(&[(a, a)]));
        assert!(!page.separate(&[]));
        for i in 0..128 {
            page.before[i] ^= 1;
            assert!(!page.guarded());
            page.before[i] ^= 1;
        }
        for i in 0..3680 {
            page.after[i] ^= 1;
            assert!(!page.guarded());
            page.after[i] ^= 1;
        }
        assert!(page.guarded());
    }
    #[test]
    fn original_rows_keep_sdk_fields_absent_and_full_width_endpoints() {
        let c = case(0);
        for ticks in [0, u64::MAX] {
            let observed = check::Collected {
                seed_index: c.seed,
                length: c.length,
                value: c.value,
                reference: bytes::ReturnedView {
                    sequence: 1,
                    external_id: 1,
                    observed_pre_call_rsp: 0x2000,
                    enclosure: bytes::Enclosure {
                        start: bytes::Timestamp {
                            ticks,
                            aux: u32::MAX,
                        },
                        end: bytes::Timestamp {
                            ticks,
                            aux: u32::MAX,
                        },
                    },
                },
            };
            let line = row(0, &observed, 7, 7, &input(0)[16..80], None);
            let fields: Vec<_> = line.split(',').collect();
            assert_eq!(fields.len(), 43);
            assert_eq!(fields[0], "original");
            assert_eq!(fields[14], ticks.to_string());
            assert_eq!(fields[15], ticks.to_string());
            assert_eq!(fields[19], "0");
            assert!(fields[22..].iter().all(|s| s.is_empty()));
        }
    }
}
