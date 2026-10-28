//! One fresh process, one fixed24-call leg. No estimator or implicit warmup.
use super::*;
use std::ffi::OsString;

const COMMENT: &str = "# normal reference leg; raw same-call endpoints are uncalibrated; no accuracy or performance claim";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Qualification,
    Calibration,
    Holdout,
    Comparison,
}
impl Phase {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "qualification" => Some(Self::Qualification),
            "calibration" => Some(Self::Calibration),
            "holdout" => Some(Self::Holdout),
            "comparison" => Some(Self::Comparison),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Qualification => "qualification",
            Self::Calibration => "calibration",
            Self::Holdout => "holdout",
            Self::Comparison => "comparison",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Leg {
    Original,
    Installed,
}
impl Leg {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "original" => Some(Self::Original),
            "installed" => Some(Self::Installed),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Installed => "installed",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Key {
    phase: Phase,
    trial: u64,
    leg: Leg,
}
impl Key {
    fn parse(phase: &str, trial: &str, leg: &str) -> Option<Self> {
        let n = trial.parse::<u64>().ok()?;
        (n != 0 && n.to_string() == trial).then_some(Self {
            phase: Phase::parse(phase)?,
            trial: n,
            leg: Leg::parse(leg)?,
        })
    }
    fn row(self, suffix: String) -> String {
        assert_eq!(suffix.split(',').next(), Some(self.leg.name()));
        assert_eq!(suffix.split(',').count(), 43);
        format!("{},{},{}", self.phase.name(), self.trial, suffix)
    }
    fn terminal(self) -> String {
        let (batches, events, reports, records, actions, count, words) = match self.leg {
            Leg::Original => (0, 0, 0, 0, 0, 0, 0),
            Leg::Installed => (1, 48, 1, 24, 2, 24, 512),
        };
        format!(
            "normal-reference-leg FUNCTIONAL_PASS phase={} trial={} leg={} selection=normal-reference-exact-37-v1 calls=24 helper_calls=12 reference_cells=24 batches={batches} events={events} reports={reports} records={records} actions={actions} entered={count} ret_observed={count} confirmed={count} completed={count} unsampled=0 whole_journal_words={words} instructions=4800 conditional=780 taken=756 input_bytes=780 ret_bytes=192 input_unchanged=true joined=true",
            self.phase.name(),
            self.trial,
            self.leg.name()
        )
    }
}

// Exact one-leg storage. Parent completed_storage continues to require24 pairs.
fn storage(
    pages: &[CellPage],
    snapshots: &[[bytes::ReferenceCell; 2]],
    results: &[[u64; 2]],
) -> bool {
    pages.len() == PAIRS
        && results.len() == PAIRS
        && snapshots.len() <= PAIRS
        && pages.iter().enumerate().all(|(i, page)| {
            page.guarded()
                && if let Some(saved) = snapshots.get(i) {
                    page.cells == *saved && results[i] == [case(i).value; 2]
                } else {
                    page.cells == CellPage::new(i).cells && results[i] == [u64::MAX; 2]
                }
        })
}

pub(crate) fn run(args: &[OsString]) {
    assert_eq!(
        args.len(),
        9,
        "ordinary-interval normal-reference-leg PHASE TRIAL LEG CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
    );
    let key = Key::parse(
        args[0].to_str().unwrap(),
        args[1].to_str().unwrap(),
        args[2].to_str().unwrap(),
    )
    .expect("closed phase/leg and canonical nonzero trial");
    let (candidate, trusted) = (Path::new(&args[3]), Path::new(&args[4]));
    let elf_va = crate::strnlen::number(args[5].to_str().unwrap());
    let length = crate::strnlen::number(args[6].to_str().unwrap());
    let (caller_candidate, caller_trusted) = (Path::new(&args[7]), Path::new(&args[8]));
    assert_eq!(length, 37);
    single_main();
    let cpu = pin(None);
    cpu_is(cpu);
    hardware::check().unwrap();
    let pid = std::process::id();
    let tid = u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
    assert_eq!(tid, u64::from(pid));
    let trusted_bytes = expected_file(candidate, trusted);
    let helper_bytes = expected_file(caller_candidate, caller_trusted);
    // SAFETY: independently trusted whole ELFs; sole actual caller, readonly
    // bounded inputs, no signals/CET/reentry/fork/cancellation/writer/unload.
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
    let mut results = Box::new([[u64::MAX; 2]; PAIRS]);
    let mut pages: Box<[CellPage]> = (0..PAIRS).map(CellPage::new).collect();
    let mut snapshots = Vec::with_capacity(PAIRS);
    let mut observed = Vec::with_capacity(CALLS);
    let (readable, stack_bounds) = readable_stack();
    let journal = (key.leg == Leg::Installed).then(IntervalJournal::allocate);
    let mut protected = vec![
        stack_bounds,
        range(inputs.as_ref()),
        range(requests.as_ref()),
        range(results.as_ref()),
    ];
    if let Some(journal) = &journal {
        protected.push((
            journal.address(),
            journal.address().checked_add(4096).unwrap(),
        ));
    }
    protected.extend(
        spans
            .iter()
            .map(|(a, b)| (*a, a.checked_add(b.len() as u64).unwrap())),
    );
    for page in pages.iter() {
        assert!(page.separate(&protected));
    }
    let mut original_owner = Some(owner);
    let mut state = if key.leg == Leg::Installed {
        let owner = original_owner.take().unwrap();
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
        // SAFETY: source publication complete; no subject has been called, no
        // active callback; controller and sole calling thread are this thread.
        let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
        controller.arm(&epoch).unwrap();
        let attached = unsafe { client.attach(1, readable, journal.unwrap()) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        Some((controller, client, epoch, attached, generation))
    } else {
        None
    };
    // All live controller/client/epoch/attachment owners precede this guard.
    // Errors abort before their teardown; no error creates a successful ack.
    let mut fail_stop = FailStop(state.is_some());
    assert!(storage(&pages, &snapshots, results.as_ref()));
    for p in 0..PAIRS {
        if let Some(owner) = original_owner.as_deref_mut() {
            owner.verify_original().unwrap();
        }
        calling.verify().unwrap();
        unsafe { immutable(&spans) };
        cpu_is(cpu);
        hardware::check().unwrap();
        // SAFETY: same immutable exact target/guarded shared input in both
        // requests; disjoint fresh cells/results, retained stack/source owners.
        // Installed state stays attached on this actual thread. One helper
        // invocation makes exactly two ordinary CALLs and actually returns.
        let sum =
            unsafe { calling.invoke(entry, &requests[p], &mut results[p], &mut pages[p].cells) };
        assert_eq!(sum, cases[p].value.wrapping_add(cases[p].value));
        assert_eq!(results[p], [cases[p].value; 2]);
        assert_eq!(*inputs, expected_input);
        if let Some(owner) = original_owner.as_deref_mut() {
            owner.verify_original().unwrap();
        }
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
            observed.push(check::Collected {
                seed_index: cases[p].seed,
                length: cases[p].length,
                value: cases[p].value,
                reference: view,
            });
        }
        snapshots.push(pages[p].cells);
        assert!(storage(&pages, &snapshots, results.as_ref()));
        if let Some((_, _, _, attached, _)) = &state {
            assert_eq!(attached.totals().unwrap(), pending((2 * p + 2) as u64));
        }
    }
    assert_eq!(observed.len(), CALLS);
    assert_eq!(*inputs, expected_input);
    assert!(storage(&pages, &snapshots, results.as_ref()));
    if let Some(owner) = original_owner.as_mut() {
        owner.verify_original().unwrap();
    }
    calling.verify().unwrap();
    files(candidate, trusted, &trusted_bytes);
    files(caller_candidate, caller_trusted, &helper_bytes);
    unsafe { immutable(&spans) };
    cpu_is(cpu);
    hardware::check().unwrap();
    let joined = if let Some((controller, _, epoch, attached, generation)) = state.as_mut() {
        // SAFETY: every actual helper invocation returned and full source/input/
        // cells postflight above passed. No cell phase is treated as RET proof.
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
        controller.disarm(epoch).unwrap();
        let report = controller
            .report(epoch)
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
            generation: *generation,
        };
        let gaps =
            check::validate_installed_leg(expected, &observed, &batch, &report, &history).unwrap();
        Some((batch, gaps, *generation))
    } else {
        assert_eq!(key.leg, Leg::Original);
        check::validate_original_leg(&observed).unwrap();
        None
    };
    assert_eq!(*inputs, expected_input);
    assert!(storage(&pages, &snapshots, results.as_ref()));
    single_main();
    cpu_is(cpu);
    calling.verify().unwrap();
    unsafe { immutable(&spans) };
    // All actual returns/joins completed, attachment explicitly detached. Sealed
    // source/code owners remain process-lived; this grants no code reclamation.
    fail_stop.0 = false;
    println!("{COMMENT}\nphase,trial,{HEADER}");
    for (i, observation) in observed.iter().enumerate() {
        let installed = joined
            .as_ref()
            .map(|(batch, gaps, generation)| (&batch.records()[i], gaps[i], *generation));
        println!(
            "{}",
            key.row(super::row(
                i,
                observation,
                pid,
                tid,
                &inputs[i / 2][16..80],
                installed
            ))
        );
    }
    println!("{}", key.terminal());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn leg_arguments_require_closed_phase_mode_and_canonical_nonzero_trial() {
        for phase in ["qualification", "calibration", "holdout", "comparison"] {
            for leg in ["original", "installed"] {
                for trial in ["1", "18446744073709551615"] {
                    let k = Key::parse(phase, trial, leg).unwrap();
                    assert_eq!(
                        (k.phase.name(), k.trial.to_string(), k.leg.name()),
                        (phase, trial.to_owned(), leg)
                    );
                }
            }
        }
        for bad in ["", "Qualification", "qualification ", "warmup"] {
            assert!(Key::parse(bad, "1", "original").is_none());
        }
        for bad in ["", "both", "Original", "installed "] {
            assert!(Key::parse("qualification", "1", bad).is_none());
        }
        for bad in [
            "",
            "0",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1.0",
            "1\n",
            "18446744073709551616",
        ] {
            assert!(Key::parse("qualification", bad, "original").is_none());
        }
    }
    #[test]
    fn leg_storage_requires_exact_fresh_or_completed_prefix() {
        let mut pages: Vec<_> = (0..PAIRS).map(CellPage::new).collect();
        let mut results = [[u64::MAX; 2]; PAIRS];
        assert!(storage(&pages, &[], &results));
        assert!(!storage(&pages[..PAIRS - 1], &[], &results));
        assert!(!storage(&pages, &[], &results[..PAIRS - 1]));
        pages[0].cells = CellPage::new(PAIRS).cells;
        assert!(!storage(&pages, &[], &results));
        pages[0].cells = CellPage::new(0).cells;
        let mut snapshots = Vec::new();
        for (i, page) in pages.iter().enumerate() {
            results[i] = [case(i).value; 2];
            assert!(!storage(&pages, &snapshots, &results));
            snapshots.push(page.cells);
            assert!(storage(&pages, &snapshots, &results));
        }
        results[0][1] ^= 1;
        assert!(!storage(&pages, &snapshots, &results));
        results[0][1] ^= 1;
        pages[3].before[0] ^= 1;
        assert!(!storage(&pages, &snapshots, &results));
        pages[3].before[0] ^= 1;
        pages[4].after[3679] ^= 1;
        assert!(!storage(&pages, &snapshots, &results));
        pages[4].after[3679] ^= 1;
        pages[5].cells = CellPage::new(6).cells;
        assert!(!storage(&pages, &snapshots, &results));
        pages[5].cells = snapshots[5];
        assert!(storage(&pages, &snapshots, &results));
        snapshots.push(pages[0].cells);
        assert!(!storage(&pages, &snapshots, &results));
    }
    #[test]
    fn leg_rows_and_terminal_preserve_manifest_and_original_absence() {
        let k = Key::parse("holdout", "18446744073709551615", "original").unwrap();
        for ticks in [0, u64::MAX] {
            let c = case(0);
            let v = check::Collected {
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
            let line = k.row(super::super::row(0, &v, 7, 7, &input(0)[16..80], None));
            let fields: Vec<_> = line.split(',').collect();
            assert_eq!(fields.len(), 45);
            assert_eq!(
                &fields[..3],
                ["holdout", "18446744073709551615", "original"]
            );
            assert_eq!(fields[15], "1");
            assert_eq!(fields[16], ticks.to_string());
            assert_eq!(fields[17], ticks.to_string());
            assert_eq!(fields[21], "0");
            assert!(fields[24..].iter().all(|s| s.is_empty()));
            let installed = Key {
                leg: Leg::Installed,
                ..k
            };
            assert!(
                std::panic::catch_unwind(
                    || installed.row(line.splitn(3, ',').nth(2).unwrap().to_owned())
                )
                .is_err()
            );
        }
        let original = k.terminal();
        assert!(original.starts_with("normal-reference-leg FUNCTIONAL_PASS phase=holdout trial=18446744073709551615 leg=original "));
        assert!(original.contains("batches=0 events=0 reports=0 records=0 actions=0 entered=0 ret_observed=0 confirmed=0 completed=0 unsampled=0 whole_journal_words=0 "));
        let installed = Key {
            leg: Leg::Installed,
            ..k
        }
        .terminal();
        assert!(installed.contains("batches=1 events=48 reports=1 records=24 actions=2 entered=24 ret_observed=24 confirmed=24 completed=24 unsampled=0 whole_journal_words=512 "));
        for terminal in [original, installed] {
            assert!(terminal.contains("calls=24 helper_calls=12 reference_cells=24 "));
            assert!(terminal.ends_with("instructions=4800 conditional=780 taken=756 input_bytes=780 ret_bytes=192 input_unchanged=true joined=true"));
        }
    }
}
