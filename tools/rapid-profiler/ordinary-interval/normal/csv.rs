//! A bounded CSV application: ordinary direct calls, complete SDK accounting.
//! This is a functional example, not native state or timing qualification.
use super::*;
use std::fmt::Write as _;
use std::io::Write as _;
mod check;
#[cfg(test)]
mod tests;

const CALLS: usize = 16;
const INSTALL: u64 = 0x6373_7601;
const LABEL: &str = "normal-csv-fields-v1";
const GUARD: u8 = 0xa7;
const HEADER: &str = "id,length,expected,original,installed,return_offset,ordinal,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,ack,ack_ordinal";
const OUTPUT_CAP: usize = 8192;
const CONFIG: Config = Config {
    retained_per_function: CALLS,
    max_inflight: 1,
    max_invocations: CALLS,
};
// Literal expected counts, independent of the C scanner. An empty record has
// one empty field. These valid records do not define a general CSV validator.
pub(super) const CASES: [(&[u8], u64); CALLS] = [
    (b"", 1),
    (b"a", 1),
    (b"a,b,c", 3),
    (b",", 2),
    (b",,", 3),
    (b"a,", 2),
    (b",a", 2),
    (b"\"\"", 1),
    (b"\"a,b\"", 1),
    (b"\"a\",\"b\"", 2),
    (b"a,\"b,c\",d", 3),
    (b"\"a\"\"b\",c", 2),
    (b"\"\"\"\"", 1),
    (b"\"\",\"\"", 2),
    (b"plain,\"say \"\"hi\"\"\",,tail", 4),
    (b"\"comma,, and \"\"quote\"\"\",last,", 3),
];
pub(super) fn inputs() -> [[u8; 96]; CALLS] {
    std::array::from_fn(|i| {
        let mut bytes = [GUARD; 96];
        assert!(CASES[i].0.len() <= 64);
        bytes[16..16 + CASES[i].0.len()].copy_from_slice(CASES[i].0);
        bytes
    })
}
#[repr(C)]
struct Results {
    before: [u64; 2],
    values: [u64; CALLS],
    after: [u64; 2],
}
impl Results {
    fn new() -> Self {
        Self {
            before: [0xa7a7; 2],
            values: [u64::MAX; CALLS],
            after: [0x5a5a; 2],
        }
    }
}
struct Data {
    // Distinct live nonempty allocations: no input/output alias is supplied.
    input: Box<[[u8; 96]; CALLS]>,
    results: Box<[Results; 2]>,
}
impl Data {
    fn new() -> Self {
        Self {
            input: Box::new(inputs()),
            results: Box::new([Results::new(), Results::new()]),
        }
    }
    fn check(&self, original: usize, installed: usize) -> check::Check {
        check::require(
            original <= CALLS && installed <= CALLS,
            check::Error::Population,
        )?;
        check::require(*self.input == inputs(), check::Error::Input)?;
        for (leg, done) in [original, installed].into_iter().enumerate() {
            let r = &self.results[leg];
            check::require(
                r.before == [0xa7a7; 2] && r.after == [0x5a5a; 2],
                check::Error::Input,
            )?;
            for (i, &value) in r.values.iter().enumerate() {
                check::require(
                    value == if i < done { CASES[i].1 } else { u64::MAX },
                    check::Error::Value,
                )?;
                if leg == 1 && i < done {
                    check::require(value == self.results[0].values[i], check::Error::Value)?;
                }
            }
        }
        Ok(())
    }
}
pub(super) type Csv = unsafe extern "C" fn(*const u8, usize) -> u64;
#[inline(never)]
#[unsafe(export_name = "liteinst_csv_call_and_store")]
pub(super) unsafe fn invoke(target: Csv, input: &[u8], output: &mut u64) {
    // SAFETY: this caller retains the selected scalar ABI and readable input.
    let value = unsafe { target(input.as_ptr(), input.len()) };
    // A real post-call side effect forbids a tail transfer. Root must inspect the
    // compiled CALL, continuation and store; this source is not a state oracle.
    unsafe { std::ptr::write_volatile(output, value) };
}

pub(super) fn mapping(address: u64, permissions: &str) -> (u64, u64) {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    mapping_in(&maps, address, permissions).expect("exact owned mapping class")
}
fn mapping_in(maps: &str, address: u64, permissions: &str) -> Option<(u64, u64)> {
    let found: Vec<_> = maps
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (a, b) = fields.next()?.split_once('-')?;
            let (a, b) = (
                u64::from_str_radix(a, 16).ok()?,
                u64::from_str_radix(b, 16).ok()?,
            );
            let mode = fields.next()?;
            (a <= address && address < b).then_some((a, b, mode))
        })
        .collect();
    match found.as_slice() {
        [(a, b, mode)] if *mode == permissions => Some((*a, *b)),
        _ => None,
    }
}
// This borrowed view exists only inside one local check. It cannot escape the
// higher-ranked, unit-returning closure or become retained Custody state.
// Reusing a view requires the existing continuous immutable mapping/permission
// contract; it does not detect forbidden mprotect, VMA split/merge or unmapping
// that occurs after the read. It must not be reused across custody passes.
pub(super) struct MappingSnapshot<'maps> {
    maps: &'maps str,
    rows: &'maps [MappingRow],
}
impl MappingSnapshot<'_> {
    pub(super) fn mapping(&self, address: u64, permissions: &str) -> (u64, u64) {
        self.lookup(address, permissions)
            .expect("exact owned mapping class")
    }
    fn lookup(&self, address: u64, permissions: &str) -> Option<(u64, u64)> {
        let mut found = None;
        for row in self.rows {
            if row.start <= address && address < row.end {
                // Any second containing row refuses, even with another mode.
                if found.is_some() {
                    return None;
                }
                found = Some(row);
            }
        }
        let row = found?;
        (self.maps[row.permissions.clone()] == *permissions).then_some((row.start, row.end))
    }
}
struct MappingRow {
    start: u64,
    end: u64,
    permissions: std::ops::Range<usize>,
}
// Only empty capacity may persist in exclusive worker scratch. No captured
// answer or borrowed view survives a pass. Every use clears both logical
// lengths before opening a fresh maps file.
#[derive(Default)]
pub(super) struct MappingScratch {
    maps: String,
    rows: Vec<MappingRow>,
}
impl MappingScratch {
    // Storage hygiene for an enclosing custody pass, including unwind. This
    // never publishes a snapshot or replaces the fresh-read path below.
    pub(super) fn clear(&mut self) {
        self.maps.clear();
        self.rows.clear();
    }
    pub(super) fn with_snapshot(&mut self, check: impl for<'maps> FnOnce(MappingSnapshot<'maps>)) {
        self.with_snapshot_from(
            |maps| {
                File::open("/proc/self/maps")?
                    .read_to_string(maps)
                    .map(|_| ())
            },
            check,
        );
    }
    fn with_snapshot_from(
        &mut self,
        read: impl FnOnce(&mut String) -> std::io::Result<()>,
        check: impl for<'maps> FnOnce(MappingSnapshot<'maps>),
    ) {
        self.maps.clear();
        self.rows.clear();
        let result = read(&mut self.maps);
        if result.is_err() {
            // A partial read never becomes a snapshot, including after reuse.
            self.maps.clear();
        }
        result.unwrap();
        let maps = self.maps.as_str();
        self.rows.extend(maps.lines().filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (a, b) = fields.next()?.split_once('-')?;
            let (start, end) = (
                u64::from_str_radix(a, 16).ok()?,
                u64::from_str_radix(b, 16).ok()?,
            );
            let mode = fields.next()?;
            // mode is a slice returned from this String: these safe numeric
            // offsets delimit its exact UTF-8 token, without normalizing it.
            let offset = (mode.as_ptr() as usize)
                .checked_sub(maps.as_ptr() as usize)
                .unwrap();
            let limit = offset.checked_add(mode.len()).unwrap();
            assert!(limit <= maps.len());
            Some(MappingRow {
                start,
                end,
                permissions: offset..limit,
            })
        }));
        check(MappingSnapshot {
            maps: &self.maps,
            rows: &self.rows,
        });
        self.rows.clear();
        self.maps.clear();
        // If check unwinds, the next invocation still clears before reading;
        // the higher-ranked borrowed view cannot escape that failed check.
    }
}
#[cfg(test)]
fn with_mapping_snapshot_from(
    read: impl FnOnce() -> std::io::Result<String>,
    check: impl for<'maps> FnOnce(MappingSnapshot<'maps>),
) {
    MappingScratch::default()
        .with_snapshot_from(|maps| read().map(|text| maps.push_str(&text)), check);
}
pub(super) fn stack_bounds() -> (u64, u64) {
    let mut marker = 0_u64;
    std::hint::black_box(&mut marker);
    mapping(std::ptr::from_ref(&marker) as usize as u64, "rw-p")
}
pub(super) struct Custody<'a> {
    pub(super) candidate: &'a Path,
    pub(super) trusted: &'a Path,
    pub(super) bytes: &'a [u8],
    pub(super) cpu: usize,
    pub(super) pid: u32,
    pub(super) stack: (u64, u64),
    pub(super) caller: (u64, u64),
    pub(super) source: Vec<(u64, Vec<u8>)>,
    pub(super) generated: Vec<(u64, Vec<u8>)>,
    pub(super) deadline: Instant,
}
impl Custody<'_> {
    pub(super) fn check(&self) {
        assert!(Instant::now() < self.deadline, "CSV absolute deadline");
        single_main();
        assert_eq!(std::process::id(), self.pid);
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
        assert_eq!(stack_bounds(), self.stack);
        assert_eq!(
            mapping(invoke as *const () as usize as u64, "r-xp"),
            self.caller
        );
        assert_eq!(expected_file(self.candidate, self.trusted), self.bytes);
        let mut actual = Vec::new();
        File::open(self.candidate)
            .unwrap()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, self.bytes);
        // Loaded ELF source remains private. Planned executable images come
        // from the core's shared memfd trampoline owner. Select the exact class
        // by that owner provenance, never by accepting whichever mode appears.
        for (spans, permissions) in [(&self.source, "r-xp"), (&self.generated, "r-xs")] {
            for (address, bytes) in spans {
                let (a, b) = mapping(*address, permissions);
                assert!(
                    a <= *address
                        && address
                            .checked_add(bytes.len() as u64)
                            .is_some_and(|end| end <= b)
                );
            }
        }
        // SAFETY: process-lived loaded/sealed owners and continuous no-unmap,
        // no-writer contract; scans do not establish those lifetime facts.
        unsafe {
            immutable(&self.source);
            immutable(&self.generated);
        };
        assert!(Instant::now() < self.deadline, "CSV postflight deadline");
    }
}
// The real postflight closure runs to success before the checkpoint closure is
// even entered. Neither this sequencing helper nor metadata establishes return.
fn after_postflight<T>(
    postflight: impl FnOnce() -> check::Check,
    transfer: impl FnOnce() -> T,
) -> Result<T, check::Error> {
    postflight()?;
    Ok(transfer())
}
pub(super) struct FailStop(pub(super) bool);
impl Drop for FailStop {
    fn drop(&mut self) {
        if self.0 {
            std::process::abort();
        }
    }
}

pub(crate) fn run(args: &[std::ffi::OsString]) {
    let deadline = Instant::now().checked_add(Duration::from_secs(15)).unwrap();
    assert_eq!(
        args.len(),
        4,
        "normal-csv-work CANDIDATE TRUSTED_FINAL ELF_VA LENGTH"
    );
    let (candidate, trusted) = (Path::new(&args[0]), Path::new(&args[1]));
    let elf_va = strnlen::number(args[2].to_str().unwrap());
    let length = usize::try_from(strnlen::number(args[3].to_str().unwrap())).unwrap();
    single_main();
    let cpu = pin(None);
    let pid = std::process::id();
    let bytes = expected_file(candidate, trusted);
    let selection = TrustedFunctionSelection::new(&bytes, elf_va, length, LABEL).unwrap();
    // SAFETY: independently trusted complete final ELF and selected extent,
    // exact CSV scalar ABI, sole normal main caller, no reentry/signals/CET,
    // fork/nonlocal exit/cancellation/alias writer/unload. The outer owner uses
    // a fresh strict environment. Known active shadow stack is refused by load;
    // all other unsafe custody obligations remain the caller's responsibility.
    let owner =
        unsafe { LoadedNormalLeaf::load_selected(candidate, &selection, NORMAL_CONTRACT) }.unwrap();
    let entry = owner.entry();
    assert_eq!(
        owner.certificate().range(),
        (entry, entry.checked_add(length as u64).unwrap())
    );
    let returns = owner.certificate().returns().to_vec();
    let target: Csv = unsafe { std::mem::transmute(usize::try_from(entry).unwrap()) };
    let readable = stack(); // Establish and touch callback headroom first.
    let mut custody = Custody {
        candidate,
        trusted,
        bytes: &bytes,
        cpu,
        pid,
        stack: stack_bounds(),
        caller: mapping(invoke as *const () as usize as u64, "r-xp"),
        source: vec![(owner.source_range().0, owner.original_source().to_vec())],
        generated: Vec::new(),
        deadline,
    };
    let mut data = Data::new();
    // All long-lived owners live outside the fallible calling scope. These slots
    // precede FailStop, so failure aborts before an installed attachment drops.
    let mut original = Some(owner);
    let mut state = None;
    let mut batch = None;
    let mut report = None;
    let mut fail_stop = FailStop(true);
    for (i, case) in CASES.iter().enumerate() {
        data.check(i, 0).unwrap();
        custody.check();
        original.as_mut().unwrap().verify_original().unwrap();
        assert!(Instant::now() < deadline, "CSV pre-call deadline");
        // SAFETY: complete original scalar input and real ordinary caller.
        unsafe {
            invoke(
                target,
                &data.input[i][16..16 + case.0.len()],
                &mut data.results[0].values[i],
            )
        };
        data.check(i + 1, 0).unwrap();
        original.as_mut().unwrap().verify_original().unwrap();
        custody.check();
    }
    let prep =
        NormalSitePreparation::new_certified_blocks(original.take().unwrap(), identity(entry))
            .unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    custody.source = prep
        .plan()
        .plan()
        .final_bytes()
        .iter()
        .map(|s| (s.address, s.bytes.clone()))
        .collect();
    custody.generated = prep
        .plan()
        .images()
        .iter()
        .map(|i| (i.address(), i.bytes().to_vec()))
        .collect();
    let site = publish(prep); // Existing full transaction and partial-publication abort.
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
    // SAFETY: sole actual main caller/controller, no active subject or callback.
    let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
    controller.arm(&epoch).unwrap();
    let attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    assert!(
        state
            .replace((controller, client, epoch, attached))
            .is_none()
    );
    assert_eq!(
        state.as_ref().unwrap().3.totals().unwrap(),
        NormalTotals::default()
    );
    for (i, case) in CASES.iter().enumerate() {
        data.check(CALLS, i).unwrap();
        custody.check();
        // SAFETY: same real application CALL; attachment and all immutable
        // source/input/stack owners remain live on this exact main thread.
        unsafe {
            invoke(
                target,
                &data.input[i][16..16 + case.0.len()],
                &mut data.results[1].values[i],
            )
        };
        data.check(CALLS, i + 1).unwrap();
        custody.check();
        assert_eq!(
            state.as_ref().unwrap().3.totals().unwrap(),
            check::pending(i as u64 + 1)
        );
    }
    let (controller, _, epoch, attached) = state.as_mut().unwrap();
    assert_eq!(attached.totals().unwrap(), check::pending(CALLS as u64));
    assert!(
        batch
            .replace(
                after_postflight(
                    || {
                        custody.check();
                        data.check(CALLS, CALLS)
                    },
                    || {
                        // SAFETY: all sixteen installed invoke calls actually returned and
                        // their post-call stores/full postflight succeeded on this thread.
                        unsafe { attached.checkpoint_after_returns() }
                            .unwrap()
                            .expect("sixteen actual returned calls")
                    }
                )
                .unwrap()
            )
            .is_none()
    );
    assert_eq!(attached.totals().unwrap(), check::complete());
    custody.check();
    data.check(CALLS, CALLS).unwrap();
    assert!(
        unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .is_none()
    );
    assert_eq!(attached.detach().unwrap(), check::complete());
    controller.disarm(epoch).unwrap();
    assert!(
        report
            .replace(
                controller
                    .report(epoch)
                    .unwrap()
                    .expect("sixteen completed retained records")
            )
            .is_none()
    );
    let history = controller.history().unwrap();
    let expected = check::Expected {
        pid,
        tid: u64::from(pid),
        entry,
        end: entry.checked_add(length as u64).unwrap(),
        returns: &returns,
        generation,
        stack: custody.stack,
        caller: custody.caller,
    };
    check::validate(
        expected,
        batch.as_ref().unwrap(),
        report.as_ref().unwrap(),
        &history,
    )
    .unwrap();
    data.check(CALLS, CALLS).unwrap();
    custody.check();
    let output = output(
        &data,
        batch.as_ref().unwrap().records(),
        expected,
        cpu,
        invoke as *const () as usize as u64,
    );
    std::io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .unwrap();
    assert!(Instant::now() < deadline, "CSV final deadline");
    fail_stop.0 = false;
}

fn output(
    data: &Data,
    rows: &[rapid_profiler::frontend_native::NormalRecord],
    e: check::Expected<'_>,
    cpu: usize,
    caller_entry: u64,
) -> String {
    assert!(e.caller.0 <= caller_entry && caller_entry < e.caller.1);
    data.check(CALLS, CALLS).unwrap();
    assert_eq!(rows.len(), CALLS);
    let mut text = String::with_capacity(OUTPUT_CAP);
    writeln!(text, "{HEADER}").unwrap();
    let mut covered = BTreeSet::new();
    for (i, r) in rows.iter().enumerate() {
        let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = r.raw.owner
        else {
            panic!("sampled CSV record")
        };
        assert_eq!(generation, e.generation);
        covered.insert(r.raw.return_pc);
        let (ack, next) = match r.acknowledgement {
            NormalAcknowledgement::NextEntry { ordinal } => (1, ordinal),
            NormalAcknowledgement::CallerCheckpoint => (2, 0),
        };
        writeln!(
            text,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            i + 1,
            CASES[i].0.len(),
            CASES[i].1,
            data.results[0].values[i],
            data.results[1].values[i],
            r.raw.return_pc.checked_sub(e.entry).unwrap(),
            r.raw.ordinal,
            invocation,
            r.history_prefix,
            r.entry_rsp,
            r.return_word,
            r.raw.start.ticks,
            r.raw.end.ticks,
            r.raw.start.aux,
            r.raw.end.aux,
            ack,
            next
        )
        .unwrap();
    }
    writeln!(text, "normal-csv-work CSV_FUNCTIONAL_PASS originals=16 installed=16 fields_per_leg=33 batches=1 events=32 records=16 actions=2 journal_words=512 entered=16 ret_observed=16 confirmed=16 completed=16 unsampled=0 next_entry=15 checkpoints=1 declared_returns={} observed_returns={} pid={} tid={} cpu={} generation={} entry={} caller_entry={} length={} install={INSTALL} function=1 registration=1",
        e.returns.len(), covered.len(), e.pid, e.tid, cpu, e.generation, e.entry, caller_entry, e.end.checked_sub(e.entry).unwrap()).unwrap();
    // 16 rows of at most 17 twenty-digit integers + separators, a <256-byte
    // header and a <1024-byte terminal fit below the fixed 8192-byte cap.
    assert!(text.is_ascii() && text.len() <= OUTPUT_CAP);
    text
}
