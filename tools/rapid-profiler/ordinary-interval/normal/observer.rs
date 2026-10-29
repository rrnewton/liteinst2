//! Finite common work through the existing ordinary C caller. No timing estimate.
//! Native has no SDK observation; installed RSP/continuation rows are checked
//! against the actual retained main stack and qualified 67-byte caller geometry.
use super::*;
use crate::exact::truth;
use rapid_profiler::frontend::{ActionKind, ControllerSnapshot, ControllerStatus};
use rapid_profiler::frontend_native::NormalRecord;
use std::fmt::Write as _;
use std::io::Write as _;
pub(crate) mod throughput;

const LABEL: &str = "normal-exact-37-v1";
const INSTALL: u64 = 0x6e6f_6273;
const BLOCK: usize = 24;
const BLOCKS: usize = 128;
const CALLS: usize = BLOCK * BLOCKS;
const PAIRS: usize = CALLS / 2;
const GUARD: u8 = 0xa7;
const CONFIG: Config = Config {
    retained_per_function: CALLS,
    max_inflight: 1,
    max_invocations: CALLS,
};
const SCOPE: &str = "# normal observer work; semantic counts and raw callback ticks only; no accuracy or performance claim";
const HEADER: &str = "id,repetition,case,seed_index,length,input_fnv1a64,value,instructions,conditional,taken,input_bytes,ret_bytes,batch,owner,generation,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,ack,ack_ordinal";
const ROW_BYTES: usize = 256;
const OUTPUT_BYTES: usize = CALLS * ROW_BYTES + 4096;
const _: () = assert!(OUTPUT_BYTES < 1024 * 1024);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Native,
    AlwaysOn,
}
impl Mode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "native" => Some(Self::Native),
            "always-on" => Some(Self::AlwaysOn),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::AlwaysOn => "always-on",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Case {
    seed: usize,
    length: usize,
    value: u64,
}
fn input(seed: usize) -> [u8; 96] {
    assert!(seed < 2);
    let mut bytes = [GUARD; 96];
    for (j, byte) in bytes[16..80].iter_mut().enumerate() {
        *byte = (37 * j + 11 + seed) as u8;
    }
    bytes
}
fn case(g: usize) -> Case {
    assert!(g < CALLS);
    let seed = (g % 8) / 4;
    let length = if (g / 2) % 2 == 0 { 1 } else { 64 };
    let bytes = input(seed);
    let value = bytes[16..16 + length]
        .iter()
        .map(|b| u64::from(b ^ 0x5a))
        .sum::<u64>()
        ^ 0x9e37_79b9_7f4a_7c15;
    assert_eq!(value, truth::checksum(&bytes[16..16 + length]).unwrap());
    Case {
        seed,
        length,
        value,
    }
}
fn work(n: usize) -> [usize; 5] {
    assert!(matches!(n, 1 | 64));
    let (instructions, branches, taken, reads) = truth::counts(n).unwrap();
    assert_eq!(
        (instructions, branches, taken, reads),
        (6 * n + 5, n, n - 1, n + 1)
    );
    [instructions, branches, taken, n, 8]
}
fn digest(bytes: &[u8]) -> u64 {
    assert_eq!(bytes.len(), 64);
    bytes.iter().fold(14_695_981_039_346_656_037, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(1_099_511_628_211)
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Returned {
    id: u64,
    value: u64,
}
fn population(rows: &[Returned]) -> bool {
    rows.len() == CALLS
        && rows
            .iter()
            .enumerate()
            .all(|(g, r)| r.id == g as u64 + 1 && r.value == case(g).value)
}

#[repr(C)]
struct Results {
    before: [u64; 2],
    values: [u64; 2],
    after: [u64; 2],
}
impl Results {
    fn new() -> Self {
        Self {
            before: [0xa7a7; 2],
            values: [u64::MAX; 2],
            after: [0x5a5a; 2],
        }
    }
    fn guarded(&self) -> bool {
        self.before == [0xa7a7; 2] && self.after == [0x5a5a; 2]
    }
}
struct Data {
    inputs: Box<[[u8; 96]; 2]>,
    requests: Box<[[Request; 2]]>,
    results: Box<[Results]>,
}
impl Data {
    fn new() -> Self {
        // Three nonempty owned allocations keep requests, outputs and inputs
        // disjoint. Both requests intentionally share one readonly input slice.
        let inputs = Box::new([input(0), input(1)]);
        let requests = (0..PAIRS)
            .map(|p| {
                let c = case(2 * p);
                [Request {
                    data: inputs[c.seed][16..80].as_ptr(),
                    bound: c.length as u64,
                }; 2]
            })
            .collect();
        Self {
            inputs,
            requests,
            results: (0..PAIRS).map(|_| Results::new()).collect(),
        }
    }
    fn check(&self, p: usize, returned: bool) {
        assert_eq!(*self.inputs, [input(0), input(1)]);
        let c = case(2 * p);
        for r in self.requests[p] {
            assert_eq!(r.data, self.inputs[c.seed][16..80].as_ptr());
            assert_eq!(r.bound, c.length as u64);
        }
        assert!(self.results[p].guarded());
        assert_eq!(
            self.results[p].values,
            if returned {
                [c.value; 2]
            } else {
                [u64::MAX; 2]
            }
        );
    }
}

fn complete(n: u64) -> NormalTotals {
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed: n,
        completed: n,
        unsampled: 0,
    }
}
fn pending(n: u64) -> NormalTotals {
    assert!(n > 0 && n <= CALLS as u64);
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed: n - 1,
        completed: n - 1,
        unsampled: 0,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Expected {
    pid: u32,
    tid: u64,
    entry: u64,
    caller: u64,
    generation: u64,
    stack: (u64, u64),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Metadata {
    legacy: bool,
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    function: FunctionId,
    number: u64,
    totals: (NormalTotals, NormalTotals),
    sequences: (u64, u64),
    next: u64,
}
impl Metadata {
    fn from_batch(b: &NormalBatch) -> Self {
        Self {
            legacy: b.history_stream().is_none() && b.history_high_water().is_none(),
            pid: b.pid(),
            tid: b.tid(),
            registration: b.registration(),
            install: b.install(),
            function: b.function(),
            number: b.number(),
            totals: b.totals(),
            sequences: b.completed_sequences(),
            next: b.next_ordinal(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Error {
    Identity,
    Population,
    Record,
    Stack,
    Clock,
    Journal,
    Report,
    History,
}
type Check<T = ()> = std::result::Result<T, Error>;
fn require(ok: bool, e: Error) -> Check {
    if ok { Ok(()) } else { Err(e) }
}
fn metadata(e: Expected, b: usize) -> Metadata {
    let before = (b * BLOCK) as u64;
    let after = before + BLOCK as u64;
    Metadata {
        legacy: true,
        pid: e.pid,
        tid: e.tid,
        registration: 1,
        install: INSTALL,
        function: FUNCTION,
        number: b as u64 + 1,
        totals: (complete(before), complete(after)),
        sequences: (before, after),
        next: after + 1,
    }
}
fn batch(e: Expected, b: usize, m: Metadata, rows: &[NormalRecord], words: &[u64]) -> Check {
    require(b < BLOCKS && rows.len() == BLOCK, Error::Population)?;
    require(
        e.pid != 0
            && e.tid == u64::from(e.pid)
            && e.generation != 0
            && e.entry != 0
            && e.entry.checked_add(37).is_some()
            && e.caller != 0
            && e.caller.checked_add(67).is_some()
            && e.stack.0 != 0
            && e.stack.0 < e.stack.1
            && m == metadata(e, b),
        Error::Identity,
    )?;
    let mut journal = [0; 512];
    journal[..4].copy_from_slice(&[48, 0, e.tid, 0]);
    for (i, r) in rows.iter().enumerate() {
        let g = b * BLOCK + i;
        let ordinal = g as u64 + 1;
        require(
            r.raw.ordinal == ordinal
                && r.raw.entry_pc == e.entry
                && r.raw.return_pc == e.entry + 36
                && r.raw.owner
                    == RawIntervalOwner::Sampled {
                        generation: e.generation,
                        invocation: g,
                    }
                && r.history_prefix == 1
                && r.acknowledgement
                    == (if i == BLOCK - 1 {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: ordinal + 1,
                        }
                    }),
            Error::Record,
        )?;
        require(
            r.entry_rsp % 16 == 8
                && r.entry_rsp.checked_sub(128).is_some_and(|x| x >= e.stack.0)
                && r.entry_rsp.checked_add(8).is_some_and(|x| x <= e.stack.1)
                && r.return_word == e.caller + caller_bytes::CONTINUATIONS[i % 2]
                && (i % 2 == 0 || r.entry_rsp == rows[i - 1].entry_rsp),
            Error::Stack,
        )?;
        require(r.raw.elapsed_ticks().is_some(), Error::Clock)?;
        let bits = ordinal | (1 << 13);
        let at = 4 + i * 14;
        journal[at..at + 7].copy_from_slice(&[
            1,
            ordinal,
            e.entry,
            r.entry_rsp,
            r.return_word,
            e.generation,
            bits,
        ]);
        journal[at + 7..at + 14].copy_from_slice(&[
            2,
            ordinal,
            e.entry + 36,
            r.entry_rsp,
            r.return_word,
            e.generation,
            bits,
        ]);
    }
    require(words == journal, Error::Journal)
}
fn report(
    e: Expected,
    rows: &[NormalRecord],
    generation: u64,
    records: &[RecordObservation],
    h: &ControllerSnapshot,
) -> Check {
    require(
        rows.len() == CALLS && records.len() == CALLS,
        Error::Population,
    )?;
    require(generation == e.generation, Error::Report)?;
    for (g, (row, record)) in rows.iter().zip(records).enumerate() {
        let a = record.record.admission;
        require(
            a.generation.get() == e.generation
                && a.function == FUNCTION
                && a.invocation == g
                && a.entry_value == row.raw.start.ticks
                && record.record.terminal
                    == Some(Terminal::Completed {
                        value: g as u64,
                        disposition: Disposition::Retained { rank: g },
                    }),
            Error::Report,
        )?;
        let p = record.payload.ok_or(Error::Report)?;
        require(
            p.admission == a
                && p.thread == 1
                && p.start_sequence == g as u64
                && p.outcome
                    == PayloadOutcome::Completed {
                        end: Observation::Value(row.raw.end.ticks),
                        completed_children: 0,
                    },
            Error::Report,
        )?;
    }
    require(
        h.status == ControllerStatus::Ready
            && h.current.is_none()
            && h.enabled == [true]
            && h.retained_failed_generation.is_none()
            && h.actions.len() == 2,
        Error::History,
    )?;
    for (i, a) in h.actions.iter().enumerate() {
        require(
            a.generation.get() == e.generation
                && a.function.is_none()
                && a.group.is_none()
                && a.kind
                    == (if i == 0 {
                        ActionKind::Published
                    } else {
                        ActionKind::Removed
                    })
                && a.current.map(|g| g.get()) == (if i == 0 { Some(e.generation) } else { None }),
            Error::History,
        )?;
    }
    Ok(())
}

// No new assembly: stack() observes RSP and establishes callback headroom.
// This separate observation retains the containing main-stack VMA, not a target
// RSP witness. Native stack semantics rely on the unchanged full-state oracle.
fn stack_bounds() -> (u64, u64) {
    let mut marker = 0_u64;
    std::hint::black_box(&mut marker);
    let at = std::ptr::from_ref(&marker) as usize as u64;
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let matches: Vec<_> = maps
        .lines()
        .filter_map(|line| {
            let mut w = line.split_whitespace();
            let (a, b) = w.next()?.split_once('-')?;
            let a = u64::from_str_radix(a, 16).ok()?;
            let b = u64::from_str_radix(b, 16).ok()?;
            let permissions = w.next()?;
            (a <= at && at < b).then_some((a, b, permissions, line.ends_with("[stack]")))
        })
        .collect();
    assert_eq!(matches.len(), 1);
    let (a, b, permissions, main) = matches[0];
    assert_eq!(permissions, "rw-p");
    assert!(main);
    (a, b)
}
struct Custody<'a> {
    candidate: &'a Path,
    trusted: &'a Path,
    subject: &'a [u8],
    caller_candidate: &'a Path,
    caller_trusted: &'a Path,
    helper: &'a [u8],
    cpu: usize,
    stack: (u64, u64),
    spans: Vec<(u64, Vec<u8>)>,
}
impl Custody<'_> {
    fn check(&self, calling: &mut CallerOwner) {
        calling.verify().unwrap();
        for (candidate, trusted, expected) in [
            (self.candidate, self.trusted, self.subject),
            (self.caller_candidate, self.caller_trusted, self.helper),
        ] {
            assert_eq!(expected_file(candidate, trusted), expected);
            let mut actual = Vec::new();
            File::open(candidate)
                .unwrap()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
        }
        unsafe { immutable(&self.spans) };
        assert_eq!(stack_bounds(), self.stack);
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) },
            0
        );
        assert_eq!(unsafe { libc::CPU_COUNT(&mask) }, 1);
        assert!(unsafe { libc::CPU_ISSET(self.cpu, &mask) });
        assert_eq!(
            unsafe { libc::sched_getcpu() },
            i32::try_from(self.cpu).unwrap()
        );
        single_main();
    }
}
struct FailStop(bool);
impl Drop for FailStop {
    fn drop(&mut self) {
        if self.0 {
            std::process::abort();
        }
    }
}

pub(crate) fn run(args: &[std::ffi::OsString]) {
    assert_eq!(
        args.len(),
        7,
        "normal-observer-work MODE CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
    );
    let mode = Mode::parse(args[0].to_str().unwrap()).expect("native or always-on");
    let candidate = Path::new(&args[1]);
    let trusted = Path::new(&args[2]);
    let elf_va = strnlen::number(args[3].to_str().unwrap());
    assert_eq!(strnlen::number(args[4].to_str().unwrap()), 37);
    let caller_candidate = Path::new(&args[5]);
    let caller_trusted = Path::new(&args[6]);
    single_main();
    let cpu = pin(None);
    let subject = expected_file(candidate, trusted);
    let helper = expected_file(caller_candidate, caller_trusted);
    // SAFETY: independently authenticated complete trusted ELFs and immutable
    // sources; sole actual main caller, no signals, writer, CET, fork, unload,
    // nonlocal exit or reentry. Requests retain all readable input for all calls.
    let mut calling = unsafe { CallerOwner::load(caller_candidate, &helper) }.unwrap();
    let selection = TrustedFunctionSelection::new(&subject, elf_va, 37, LABEL).unwrap();
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
    let caller = calling.entry();
    let mut original = Some(owner);
    let readable = stack();
    let stack = stack_bounds();
    let mut custody = Custody {
        candidate,
        trusted,
        subject: &subject,
        caller_candidate,
        caller_trusted,
        helper: &helper,
        cpu,
        stack,
        spans: vec![
            (
                original.as_ref().unwrap().source_range().0,
                original.as_ref().unwrap().original_source().to_vec(),
            ),
            (calling.source().0, calling.source().1.to_vec()),
        ],
    };
    let mut data = Data::new();
    let mut returned = Vec::with_capacity(CALLS);
    let mut batches = Vec::with_capacity(if mode == Mode::AlwaysOn { BLOCKS } else { 0 });
    let mut state = if mode == Mode::AlwaysOn {
        original.as_mut().unwrap().verify_original().unwrap();
        let prep =
            NormalSitePreparation::new_whole_function(original.take().unwrap(), identity(entry))
                .unwrap();
        assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, entry + 36]);
        custody.spans = prep
            .plan()
            .plan()
            .final_bytes()
            .iter()
            .map(|s| (s.address, s.bytes.clone()))
            .collect();
        custody.spans.extend(
            prep.plan()
                .images()
                .iter()
                .map(|i| (i.address(), i.bytes().to_vec())),
        );
        custody
            .spans
            .push((calling.source().0, calling.source().1.to_vec()));
        let site = publish(prep);
        let mut prepared = PreparedNormalController::new(
            site,
            INSTALL,
            FUNCTION,
            Limits {
                epochs: 1,
                threads: 1,
                depth: 1,
                records_per_epoch: CALLS,
                actions: 2,
            },
        )
        .unwrap();
        let epoch = prepared.stage(CONFIG).unwrap();
        let generation = epoch.generation().get();
        let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
        controller.arm(&epoch).unwrap();
        let attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        Some((controller, client, epoch, attached, generation))
    } else {
        None
    };
    // All live controller/attachment/input/code owners precede this guard.
    // Failed checks abort before their teardown; no failure manufactures a
    // checkpoint or successful detach. Setup failures above precede all calls.
    let mut fail_stop = FailStop(true);
    custody.check(&mut calling);
    if let Some(owner) = original.as_mut() {
        owner.verify_original().unwrap();
    }
    let e = Expected {
        pid: std::process::id(),
        tid: u64::from(std::process::id()),
        entry,
        caller,
        generation: state.as_ref().map_or(0, |s| s.4),
        stack,
    };
    for p in 0..PAIRS {
        data.check(p, false);
        unsafe { immutable(&custody.spans) };
        // SAFETY: exact closed readonly subject, retained inputs and real normal
        // stack. The unchanged helper makes two ordinary CALLs; no SDK invoke.
        let sum = unsafe { calling.invoke(entry, &data.requests[p], &mut data.results[p].values) };
        let c = case(2 * p);
        assert_eq!(sum, c.value.wrapping_add(c.value));
        data.check(p, true);
        unsafe { immutable(&custody.spans) };
        for (j, &value) in data.results[p].values.iter().enumerate() {
            returned.push(Returned {
                id: (2 * p + j + 1) as u64,
                value,
            });
        }
        let n = (2 * p + 2) as u64;
        if let Some((_, _, _, attached, _)) = state.as_ref() {
            assert_eq!(attached.totals().unwrap(), pending(n));
        }
        if n % BLOCK as u64 == 0 {
            // Complete file/source/generated/helper/input/stack/CPU postflight
            // is shared by both modes at every fixed24 boundary. Immutable
            // custody is continuous; scans do not substitute for that contract.
            custody.check(&mut calling);
            assert_eq!(*data.inputs, [input(0), input(1)]);
            for q in p + 1 - BLOCK / 2..=p {
                data.check(q, true);
            }
            if let Some(owner) = original.as_mut() {
                owner.verify_original().unwrap();
            }
            if let Some((_, _, _, attached, _)) = state.as_mut() {
                // SAFETY: all actual helper calls above returned normally on
                // this attached thread; postflight precedes last receipt finish.
                let observed = unsafe { attached.checkpoint_after_returns() }
                    .unwrap()
                    .expect("24 returned calls");
                assert_eq!(attached.totals().unwrap(), complete(n));
                batch(
                    e,
                    batches.len(),
                    Metadata::from_batch(&observed),
                    observed.records(),
                    observed.journal(),
                )
                .unwrap();
                batches.push(observed);
            }
        }
    }
    assert!(population(&returned));
    for p in 0..PAIRS {
        data.check(p, true);
    }
    custody.check(&mut calling);
    if let Some(owner) = original.as_mut() {
        owner.verify_original().unwrap();
    }
    if let Some((controller, _, epoch, attached, _)) = state.as_mut() {
        assert_eq!(batches.len(), BLOCKS);
        assert_eq!(attached.totals().unwrap(), complete(CALLS as u64));
        assert!(
            unsafe { attached.checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        assert_eq!(attached.detach().unwrap(), complete(CALLS as u64));
        controller.disarm(epoch).unwrap();
        let observed = controller
            .report(epoch)
            .unwrap()
            .expect("all3072 retained calls");
        let history = controller.history().unwrap();
        let mut rows = Vec::with_capacity(CALLS);
        for (b, observed) in batches.iter().enumerate() {
            batch(
                e,
                b,
                Metadata::from_batch(observed),
                observed.records(),
                observed.journal(),
            )
            .unwrap();
            rows.extend_from_slice(observed.records());
        }
        report(
            e,
            &rows,
            observed.generation().get(),
            &observed.records().collect::<Vec<_>>(),
            &history,
        )
        .unwrap();
    } else {
        assert!(batches.is_empty());
    }
    custody.check(&mut calling);
    let mut output = String::with_capacity(OUTPUT_BYTES);
    writeln!(output, "{SCOPE}\n{HEADER}").unwrap();
    for (g, r) in returned.iter().enumerate() {
        let record = (mode == Mode::AlwaysOn).then(|| &batches[g / BLOCK].records()[g % BLOCK]);
        let line = row(g, *r, record);
        assert!(line.len() < ROW_BYTES);
        writeln!(output, "{line}").unwrap();
    }
    writeln!(output, "{}", terminal(mode, e)).unwrap();
    assert!(output.is_ascii() && output.len() <= OUTPUT_BYTES && OUTPUT_BYTES < 1024 * 1024);
    std::io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .unwrap();
    fail_stop.0 = false;
}

fn row(g: usize, observed: Returned, sdk: Option<&NormalRecord>) -> String {
    assert!(g < CALLS && observed.id == g as u64 + 1 && observed.value == case(g).value);
    let c = case(g);
    let w = work(c.length);
    let mut line = format!(
        "{},{},{},{},{},{},{},{},{},{},{},{}",
        observed.id,
        g / BLOCK + 1,
        g % BLOCK + 1,
        c.seed,
        c.length,
        digest(&input(c.seed)[16..80]),
        observed.value,
        w[0],
        w[1],
        w[2],
        w[3],
        w[4]
    );
    if let Some(r) = sdk {
        let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = r.raw.owner
        else {
            panic!("sampled")
        };
        let (ack, ordinal) = match r.acknowledgement {
            NormalAcknowledgement::CallerCheckpoint => ("C", String::new()),
            NormalAcknowledgement::NextEntry { ordinal } => ("N", ordinal.to_string()),
        };
        write!(
            line,
            ",{},sampled,{},{},{},{},{},{},{},{},{},{},{},{}",
            g / BLOCK + 1,
            generation,
            invocation,
            r.history_prefix,
            r.entry_rsp,
            r.return_word,
            r.raw.start.ticks,
            r.raw.end.ticks,
            r.raw.start.aux,
            r.raw.end.aux,
            r.raw.elapsed_ticks().unwrap(),
            ack,
            ordinal
        )
        .unwrap();
    } else {
        line.push_str(",,,,,,,,,,,,,,");
    }
    assert_eq!(line.split(',').count(), 26);
    line
}
fn terminal(mode: Mode, e: Expected) -> String {
    let installed = mode == Mode::AlwaysOn;
    let factor = usize::from(installed);
    format!(
        "normal-observer-work FUNCTIONAL_PASS mode={} selection={LABEL} repetitions=128 calls=3072 helper_calls=1536 instructions=614400 conditional=99840 taken=96768 input_bytes=99840 ret_bytes=24576 pid={} tid={} entry={} caller={} install={} function={} generation={} batches={} events={} reports={} records={} actions={} journal_words={} next_entry_acknowledgements={} checkpoint_acknowledgements={} input_unchanged=true joined=true",
        mode.name(),
        e.pid,
        e.tid,
        e.entry,
        e.caller,
        if installed {
            INSTALL.to_string()
        } else {
            "none".into()
        },
        if installed { "1" } else { "none" },
        if installed {
            e.generation.to_string()
        } else {
            "none".into()
        },
        BLOCKS * factor,
        2 * CALLS * factor,
        factor,
        CALLS * factor,
        2 * factor,
        512 * BLOCKS * factor,
        (CALLS - BLOCKS) * factor,
        BLOCKS * factor
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapid_profiler::frontend::{Action, Payload};
    use rapid_profiler::frontend_native::RawTimestamp;
    use rapid_profiler::generation::{Admission, Epoch, Record};

    struct Fixture {
        e: Expected,
        rows: Vec<NormalRecord>,
        reports: Vec<RecordObservation>,
        history: ControllerSnapshot,
    }
    impl Fixture {
        fn new() -> Self {
            // Opaque generation identity only; no fabricated native Batch,
            // attachment, executable owner or actual-return evidence.
            let generation = Epoch::new(&[FUNCTION], CONFIG).unwrap().id();
            let e = Expected {
                pid: 17,
                tid: 17,
                entry: 0x1000,
                caller: 0x2000,
                generation: generation.get(),
                stack: (0x7000, 0x9000),
            };
            let mut rows = Vec::new();
            let mut reports = Vec::new();
            for g in 0..CALLS {
                let r = NormalRecord {
                    raw: RawInterval {
                        ordinal: g as u64 + 1,
                        entry_pc: e.entry,
                        return_pc: e.entry + 36,
                        owner: RawIntervalOwner::Sampled {
                            generation: e.generation,
                            invocation: g,
                        },
                        start: RawTimestamp {
                            ticks: g as u64 * 100,
                            aux: 3,
                        },
                        end: RawTimestamp {
                            ticks: g as u64 * 100 + 90,
                            aux: 3,
                        },
                    },
                    entry_rsp: 0x7ff8,
                    return_word: e.caller + [30, 48][g % 2],
                    history_prefix: 1,
                    acknowledgement: if g % BLOCK == BLOCK - 1 {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: g as u64 + 2,
                        }
                    },
                };
                let admission = Admission {
                    generation,
                    function: FUNCTION,
                    invocation: g,
                    entry_value: r.raw.start.ticks,
                };
                reports.push(RecordObservation {
                    record: Record {
                        admission,
                        terminal: Some(Terminal::Completed {
                            value: g as u64,
                            disposition: Disposition::Retained { rank: g },
                        }),
                    },
                    payload: Some(Payload {
                        admission,
                        thread: 1,
                        start_sequence: g as u64,
                        outcome: PayloadOutcome::Completed {
                            end: Observation::Value(r.raw.end.ticks),
                            completed_children: 0,
                        },
                    }),
                });
                rows.push(r);
            }
            Self {
                e,
                rows,
                reports,
                history: ControllerSnapshot {
                    status: ControllerStatus::Ready,
                    current: None,
                    enabled: vec![true],
                    retained_failed_generation: None,
                    actions: vec![
                        Action {
                            kind: ActionKind::Published,
                            generation,
                            function: None,
                            current: Some(generation),
                            group: None,
                        },
                        Action {
                            kind: ActionKind::Removed,
                            generation,
                            function: None,
                            current: None,
                            group: None,
                        },
                    ],
                },
            }
        }
        fn words(&self, b: usize) -> [u64; 512] {
            let mut words = [0; 512];
            words[..4].copy_from_slice(&[48, 0, 17, 0]);
            for (i, r) in self.rows[b * BLOCK..(b + 1) * BLOCK].iter().enumerate() {
                let ordinal = (b * BLOCK + i + 1) as u64;
                for event in 0..2 {
                    let at = 4 + 14 * i + 7 * event;
                    words[at..at + 7].copy_from_slice(&[
                        event as u64 + 1,
                        ordinal,
                        self.e.entry + if event == 0 { 0 } else { 36 },
                        r.entry_rsp,
                        r.return_word,
                        self.e.generation,
                        ordinal | (1 << 13),
                    ]);
                }
            }
            words
        }
        fn batch(&self, b: usize) -> Check {
            batch(
                self.e,
                b,
                metadata(self.e, b),
                &self.rows[b * BLOCK..(b + 1) * BLOCK],
                &self.words(b),
            )
        }
        fn report(&self) -> Check {
            report(
                self.e,
                &self.rows,
                self.e.generation,
                &self.reports,
                &self.history,
            )
        }
    }

    #[test]
    fn fixed_population_modes_and_scalar_work_are_exact() {
        assert_eq!(Mode::parse("native"), Some(Mode::Native));
        assert_eq!(Mode::parse("always-on"), Some(Mode::AlwaysOn));
        for word in ["", "perf", "back-off", "Native", "always-on "] {
            assert_eq!(Mode::parse(word), None);
        }
        let mut totals = [0; 5];
        let mut cases = [[0; 2]; 2];
        for g in 0..CALLS {
            let c = case(g);
            assert_eq!(c, case(g ^ 1));
            cases[c.seed][usize::from(c.length == 64)] += 1;
            for (sum, value) in totals.iter_mut().zip(work(c.length)) {
                *sum += value;
            }
        }
        assert_eq!(cases, [[768; 2]; 2]);
        assert_eq!(totals, [614400, 99840, 96768, 99840, 24576]);
        assert_eq!((BLOCKS, BLOCK, CALLS, PAIRS), (128, 24, 3072, 1536));
        assert_eq!(caller_bytes::CONTINUATIONS, [30, 48]);
        assert_ne!(digest(&input(0)[16..80]), digest(&input(1)[16..80]));
    }
    #[test]
    fn batch_metadata_keeps_lifetime_identity_across_all128_drains() {
        let f = Fixture::new();
        for b in 0..BLOCKS {
            assert_eq!(f.batch(b), Ok(()));
            let mut m = metadata(f.e, b);
            let rows = &f.rows[b * BLOCK..(b + 1) * BLOCK];
            let words = f.words(b);
            m.number += 1;
            assert_eq!(batch(f.e, b, m, rows, &words), Err(Error::Identity));
            m = metadata(f.e, b);
            m.sequences.0 += 1;
            assert_eq!(batch(f.e, b, m, rows, &words), Err(Error::Identity));
            m = metadata(f.e, b);
            m.next -= 1;
            assert_eq!(batch(f.e, b, m, rows, &words), Err(Error::Identity));
            m = metadata(f.e, b);
            m.totals.1.completed -= 1;
            assert_eq!(batch(f.e, b, m, rows, &words), Err(Error::Identity));
        }
        let rows = &f.rows[..BLOCK];
        let words = f.words(0);
        assert_eq!(
            batch(f.e, 0, metadata(f.e, 0), &rows[..BLOCK - 1], &words),
            Err(Error::Population)
        );
        assert_eq!(
            batch(f.e, 1, metadata(f.e, 0), rows, &words),
            Err(Error::Identity)
        );
        for field in 0..6 {
            let mut m = metadata(f.e, 0);
            match field {
                0 => m.legacy = false,
                1 => m.pid += 1,
                2 => m.tid += 1,
                3 => m.registration += 1,
                4 => m.install += 1,
                _ => m.function = FunctionId(2),
            }
            assert_eq!(batch(f.e, 0, m, rows, &words), Err(Error::Identity));
        }
    }
    #[test]
    fn records_refuse_wrong_owner_continuation_stack_and_acknowledgement() {
        let mut f = Fixture::new();
        for g in [0, 1, 23, 24, CALLS - 1] {
            let saved = f.rows[g];
            for field in 0..12 {
                let r = &mut f.rows[g];
                match field {
                    0 => r.raw.ordinal += 1,
                    1 => {
                        r.raw.owner = RawIntervalOwner::Sampled {
                            generation: f.e.generation + 1,
                            invocation: g,
                        }
                    }
                    2 => {
                        r.raw.owner = RawIntervalOwner::Sampled {
                            generation: f.e.generation,
                            invocation: g ^ 1,
                        }
                    }
                    3 => r.return_word += 1,
                    4 => r.entry_rsp = 0x7008,
                    5 => r.acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 1 },
                    6 => r.history_prefix = 2,
                    7 => r.raw.end.aux += 1,
                    8 => {
                        r.raw.start.ticks = 1;
                        r.raw.end.ticks = 0;
                    }
                    9 => {
                        r.raw.owner = RawIntervalOwner::FunctionClosed {
                            generation: f.e.generation,
                        }
                    }
                    10 => r.raw.entry_pc += 1,
                    _ => r.raw.return_pc += 1,
                }
                assert!(f.batch(g / BLOCK).is_err(), "field {field}, row {g}");
                f.rows[g] = saved;
            }
        }
        let saved = f.rows[1];
        f.rows[1].entry_rsp -= 16;
        assert_eq!(f.batch(0), Err(Error::Stack));
        f.rows[1] = saved;
        f.rows[0].raw.start.ticks = u64::MAX;
        f.rows[0].raw.end.ticks = u64::MAX;
        assert_eq!(f.batch(0), Ok(())); // Zero duration and maximal endpoints remain observations.
    }
    #[test]
    fn journal_checks_all512_words_including_tail_and_absolute_slots() {
        let f = Fixture::new();
        for b in [0, 1, BLOCKS - 1] {
            let rows = &f.rows[b * BLOCK..(b + 1) * BLOCK];
            let mut words = f.words(b);
            for at in 0..512 {
                words[at] ^= 1;
                assert_eq!(
                    batch(f.e, b, metadata(f.e, b), rows, &words),
                    Err(Error::Journal)
                );
                words[at] ^= 1;
            }
            assert_eq!(
                batch(f.e, b, metadata(f.e, b), rows, &words[..511]),
                Err(Error::Journal)
            );
        }
        assert_ne!(f.words(0)[5], f.words(1)[5]);
        assert_eq!(f.words(BLOCKS - 1)[4 + 23 * 14 + 6], 3072 | (1 << 13));
    }
    #[test]
    fn reports_and_history_require_all3072_payloads_and_two_actions() {
        let mut f = Fixture::new();
        assert_eq!(f.report(), Ok(()));
        for at in [0, 24, CALLS - 1] {
            let saved = f.reports[at];
            for field in 0..7 {
                let r = &mut f.reports[at];
                match field {
                    0 => r.record.admission.invocation ^= 1,
                    1 => {
                        r.record.terminal = Some(Terminal::Completed {
                            value: at as u64,
                            disposition: Disposition::Retained { rank: at ^ 1 },
                        })
                    }
                    2 => {
                        r.record.terminal = Some(Terminal::Completed {
                            value: at as u64 + 1,
                            disposition: Disposition::Retained { rank: at },
                        })
                    }
                    3 => r.payload.as_mut().unwrap().start_sequence += 1,
                    4 => r.payload.as_mut().unwrap().thread = 2,
                    5 => {
                        r.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                            end: Observation::Value(0),
                            completed_children: 1,
                        }
                    }
                    _ => r.payload = None,
                }
                assert_eq!(f.report(), Err(Error::Report));
                f.reports[at] = saved;
            }
        }
        let tail = f.reports.pop().unwrap();
        assert_eq!(f.report(), Err(Error::Population));
        f.reports.push(tail);
        f.reports.swap(0, 1);
        assert_eq!(f.report(), Err(Error::Report));
        f.reports.swap(0, 1);
        f.history.actions.swap(0, 1);
        assert_eq!(f.report(), Err(Error::History));
        f.history.actions.swap(0, 1);
        f.history.current = Some(f.history.actions[0].generation);
        assert_eq!(f.report(), Err(Error::History));
        f.history.current = None;
        f.history.actions[0].group = Some(0);
        assert_eq!(f.report(), Err(Error::History));
    }
    #[test]
    fn population_refuses_missing_duplicate_and_changed_returns() {
        let mut rows: Vec<_> = (0..CALLS)
            .map(|g| Returned {
                id: g as u64 + 1,
                value: case(g).value,
            })
            .collect();
        assert!(population(&rows));
        assert!(!population(&rows[..CALLS - 1]));
        let saved = rows[24];
        rows[24] = rows[0];
        assert!(!population(&rows));
        rows[24] = saved;
        rows[CALLS - 1].value ^= 1;
        assert!(!population(&rows));
        let mut data = Data::new();
        data.check(0, false);
        data.results[0].values = [case(0).value; 2];
        data.check(0, true);
        data.results[0].after[1] ^= 1;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.check(0, true))).is_err()
        );
    }
    #[test]
    fn wire_native_absence_and_raw_full_width_endpoints_are_exact() {
        let mut f = Fixture::new();
        let native = row(
            0,
            Returned {
                id: 1,
                value: case(0).value,
            },
            None,
        );
        let columns: Vec<_> = native.split(',').collect();
        assert_eq!(columns.len(), 26);
        assert!(columns[12..].iter().all(|v| v.is_empty()));
        for (start, end) in [(0, 0), (0, u64::MAX), (u64::MAX, u64::MAX)] {
            f.rows[0].raw.start = RawTimestamp {
                ticks: start,
                aux: u32::MAX,
            };
            f.rows[0].raw.end = RawTimestamp {
                ticks: end,
                aux: u32::MAX,
            };
            let line = row(
                0,
                Returned {
                    id: 1,
                    value: case(0).value,
                },
                Some(&f.rows[0]),
            );
            let cols: Vec<_> = line.split(',').collect();
            assert_eq!(cols.len(), 26);
            assert_eq!(cols[23], (end - start).to_string());
            assert_eq!(cols[24..], ["N", "2"]);
            assert!(line.len() < ROW_BYTES);
        }
        let checkpoint = row(
            23,
            Returned {
                id: 24,
                value: case(23).value,
            },
            Some(&f.rows[23]),
        );
        assert_eq!(
            checkpoint.split(',').skip(24).collect::<Vec<_>>(),
            ["C", ""]
        );
        let widths = [
            4, 3, 2, 1, 2, 20, 20, 3, 2, 2, 2, 1, 3, 7, 20, 4, 1, 20, 20, 20, 20, 10, 10, 20, 1, 4,
        ];
        assert_eq!(widths.iter().sum::<usize>() + 26, 248);
        assert!(widths.iter().sum::<usize>() + 26 <= ROW_BYTES);
        let maximum = Expected {
            pid: u32::MAX,
            tid: u64::from(u32::MAX),
            entry: u64::MAX - 37,
            caller: u64::MAX - 67,
            generation: u64::MAX,
            stack: f.e.stack,
        };
        for mode in [Mode::Native, Mode::AlwaysOn] {
            let tail = terminal(mode, maximum);
            assert!(SCOPE.len() + HEADER.len() + tail.len() + 3 < 4096);
            assert!(tail.contains("calls=3072 helper_calls=1536 instructions=614400"));
            if mode == Mode::Native {
                assert!(tail.contains("install=none function=none generation=none"));
            }
        }
    }
}
