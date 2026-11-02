//! Qualification-feature only. Same production begin/returned/checkpoint/finish,
//! oracle-owned arrays/stack; default safe-wrapper integration is a separate gate.
use super::*;
mod publisher;
pub(crate) mod wide;
use native_module::early_entry::{self as early, Extra, Scenario, WITNESS_WORDS};
use rapid_profiler::frontend::HistoryBinding;
use rapid_profiler::frontend_native::{
    EarlyEntryModuleSessionController, EarlyEntryModuleSitePreparation,
    InstalledEarlyEntryModuleSite, IntervalEpoch, LoadedNormalModuleCaller,
    PreparedEarlyEntryModuleSessionController,
    early_entry_qualification::{
        self as qualification, OwnerSnapshot, PauseKind, QualificationRequest,
        QualificationSnapshot,
    },
};

fn publish(prep: EarlyEntryModuleSitePreparation) -> InstalledEarlyEntryModuleSite {
    current_single_main();
    let planned = prep.plan();
    assert_eq!(planned.plan().originals().len(), 1);
    let source = &planned.plan().originals()[0];
    assert_eq!(source.bytes.len(), 4096);
    let range = AddressRange::new(source.address, source.bytes.len()).unwrap();
    let mut ranges = vec![range];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|s| s.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    protect(range, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: pristine single-threaded child, exact retained source/allocations;
    // no caller exists until the real production transaction and final RX finish.
    let alias = unsafe { WritableAlias::new(range, range.start() as usize as *mut u8) }.unwrap();
    let mut lease =
        unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
    let result = unsafe {
        planned.publish_with(&[alias], &mut lease, || {
            protect(range, libc::PROT_READ | libc::PROT_EXEC)
        })
    };
    if result.is_err() {
        std::process::abort();
    }
    assert!(!lease.is_poisoned());
    drop(lease);
    let (installed, receipt) = result.unwrap();
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
fn totals(t: NormalTotals) -> [u64; 5] {
    [
        t.entered,
        t.ret_observed,
        t.confirmed,
        t.completed,
        t.unsampled,
    ]
}
fn raw_owner(owner: RawIntervalOwner) -> [u64; 3] {
    match owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => [1, generation, invocation as u64],
        RawIntervalOwner::InitialDisarmed => [2, 0, 0],
        RawIntervalOwner::Removed { generation } => [3, generation, 0],
        RawIntervalOwner::FunctionClosed { generation } => [4, generation, 0],
    }
}
fn owner_words(o: OwnerSnapshot) -> [u64; 8] {
    let [kind, generation, invocation] = raw_owner(o.owner);
    let (binding, index, bound_generation) = match o.binding {
        HistoryBinding::Initial => (0, 0, 0),
        HistoryBinding::Published {
            action_index,
            generation,
        } => (1, action_index, generation.get()),
        HistoryBinding::Removed {
            action_index,
            generation,
        } => (2, action_index, generation.get()),
    };
    [
        kind,
        generation,
        invocation,
        o.history_len as u64,
        binding,
        index,
        bound_generation,
        o.closed_function.map_or(0, |f| f.0),
    ]
}
fn encode_into(
    kind: PauseKind,
    sequence: u64,
    s: &QualificationSnapshot,
    h: &mut [u64; early::JOURNAL],
) {
    h.fill(0);
    h[..15].copy_from_slice(&[
        0x6561_726c_796d_6f64,
        match kind {
            PauseKind::AfterEntryPublished => 1,
            PauseKind::AfterPreRetPublished => 2,
        },
        sequence,
        s.binding_key as u64,
        u64::from(s.pid),
        s.tid,
        s.registration,
        s.completed_batches,
        s.completed_calls,
        s.active_batch.unwrap(),
        s.position.unwrap() as u64,
        s.next_ordinal,
        s.model_depth as u64,
        s.completed_sequence,
        s.interval_batch,
    ]);
    h[15..20].copy_from_slice(&totals(s.totals));
    h[20..25].copy_from_slice(&totals(s.interval_cursor_totals));
    for (i, n) in s.entry_seen.iter().enumerate() {
        h[25 + i] = n.unwrap_or(0);
    }
    for (i, row) in s.pre_rets.iter().enumerate() {
        if let Some(r) = row {
            h[29 + i * 7..36 + i * 7].copy_from_slice(&[
                r.batch,
                r.position as u64,
                r.function.0,
                r.observed_ordinal.unwrap_or(0),
                r.return_pc,
                r.entry_rsp,
                r.return_word,
            ]);
        }
    }
    if let Some(p) = s.pending {
        h[57..67].copy_from_slice(&[
            1,
            p.physical_batch,
            p.physical_position as u64,
            p.function.0,
            p.ordinal,
            p.entry_pc,
            p.rsp,
            p.word,
            p.start.ticks,
            u64::from(p.start.aux),
        ]);
        h[73] = p.slot.identity;
        h[74] = p.slot.word;
        if let Some(owner) = p.summary {
            h[75] = 1;
            h[76..84].copy_from_slice(&owner_words(owner));
        }
        if let Some(owner) = p.actual_summary {
            h[84] = 1;
            h[85..93].copy_from_slice(&owner_words(owner));
            let [_, generation, invocation] = raw_owner(owner.owner);
            h[71] = generation;
            h[72] = invocation;
        }
        if let Some(r) = p.returned {
            h[67] = 1;
            h[68] = r.return_pc;
            h[69] = r.end.ticks;
            h[70] = u64::from(r.end.aux);
            let [kind, generation, invocation] = raw_owner(r.owner);
            h[93..103].copy_from_slice(&[
                r.ordinal,
                r.entry_pc,
                r.return_pc,
                kind,
                generation,
                invocation,
                r.start.ticks,
                u64::from(r.start.aux),
                r.end.ticks,
                u64::from(r.end.aux),
            ]);
        }
    }
}
#[inline(never)]
fn snapshot_ready() {
    let _ = std::hint::black_box(0_u64);
}

struct Controller {
    controller: EarlyEntryModuleSessionController,
    a: IntervalEpoch,
    b: IntervalEpoch,
}
impl Controller {
    fn operation(&mut self, scenario: Scenario) {
        match scenario {
            Scenario::LoadedTrueDisarm | Scenario::ReturnedDisarm => {
                self.controller.disarm(&self.a).unwrap()
            }
            Scenario::LoadedFalseArm => self.controller.arm(&self.a).unwrap(),
            Scenario::AdmittedRearm => {
                self.controller.disarm(&self.a).unwrap();
                assert!(self.controller.report(&self.a).unwrap().is_none());
                self.controller.arm(&self.b).unwrap();
            }
            _ => panic!("no scheduled operation in static cohort"),
        }
    }
    fn finish(
        &mut self,
        scenario: Scenario,
        rows: &[rapid_profiler::frontend_native::NormalModuleRecord],
    ) {
        match scenario {
            Scenario::Enabled | Scenario::LoadedFalseArm => {
                self.controller.disarm(&self.a).unwrap()
            }
            Scenario::AdmittedRearm => self.controller.disarm(&self.b).unwrap(),
            Scenario::Bypass | Scenario::LoadedTrueDisarm | Scenario::ReturnedDisarm => {}
        }
        for epoch in [&self.a, &self.b] {
            let expected:Vec<_>=rows.iter().filter(|r|matches!(r.record.raw.owner,RawIntervalOwner::Sampled{generation,..} if generation==epoch.generation().get())).collect();
            let report = self.controller.report(epoch).unwrap();
            let closed = epoch.generation() == self.a.generation() && scenario != Scenario::Bypass
                || epoch.generation() == self.b.generation() && scenario == Scenario::AdmittedRearm;
            assert_eq!(report.is_some(), closed);
            if let Some(report) = report {
                assert_eq!(report.generation(), epoch.generation());
                let actual = report.records().collect::<Vec<_>>();
                assert_eq!(actual.len(), expected.len());
                let mut per_function = [0_usize; 2];
                for (invocation, (actual, normal)) in actual.iter().zip(&expected).enumerate() {
                    let raw = &normal.record.raw;
                    let admission = actual.record.admission;
                    assert_eq!(
                        (
                            admission.generation.get(),
                            admission.function,
                            admission.invocation,
                            admission.entry_value
                        ),
                        (
                            epoch.generation().get(),
                            normal.function,
                            invocation,
                            raw.start.ticks
                        )
                    );
                    assert_eq!(
                        raw.owner,
                        RawIntervalOwner::Sampled {
                            generation: epoch.generation().get(),
                            invocation
                        }
                    );
                    let index = FUNCTIONS
                        .iter()
                        .position(|f| *f == normal.function)
                        .unwrap();
                    assert_eq!(
                        actual.record.terminal,
                        Some(Terminal::Completed {
                            value: invocation as u64,
                            disposition: Disposition::Retained {
                                rank: per_function[index]
                            }
                        })
                    );
                    per_function[index] += 1;
                    let payload = actual.payload.unwrap();
                    assert_eq!(payload.admission, admission);
                    assert_eq!(
                        (payload.thread, payload.start_sequence),
                        (1, raw.ordinal - 1)
                    );
                    let end = if raw.start.aux != raw.end.aux {
                        Observation::Unavailable(1)
                    } else if raw.end.ticks < raw.start.ticks {
                        Observation::Unavailable(2)
                    } else {
                        Observation::Value(raw.end.ticks)
                    };
                    assert_eq!(
                        payload.outcome,
                        PayloadOutcome::Completed {
                            end,
                            completed_children: 0
                        }
                    );
                }
            }
        }
    }
}
fn child(
    candidate: bool,
    mut context: NormalContext<'_>,
    elf: &[u8],
    selections: [&TrustedFunctionSelection<'_>; 2],
    caller_elf: &[u8],
    caller_va: u64,
) -> i32 {
    current_single_main();
    let deadline = context.deadline();
    deadline.check();
    let case = context.module_session_case();
    let scenario = context.early_entry_scenario();
    let endpoint = context.take_early_entry_control();
    assert_eq!(endpoint.is_some(), candidate && scenario.scheduled());
    // SAFETY: independently admitted complete original C source and final ELF;
    // fresh same-process retained maps, one caller, no signals/CET/foreign entry.
    let loaded =
        unsafe { LoadedNormalModule::load_sealed_selected_pair(selections, CONTRACT) }.unwrap();
    let caller_selection =
        TrustedFunctionSelection::new(caller_elf, caller_va, 123, "normal_module_caller").unwrap();
    let caller = unsafe { LoadedNormalModuleCaller::load_sealed(&caller_selection) }.unwrap();
    let caller_entry = caller.qualification_entry();
    let caller_source = caller.qualification_source();
    let source = &loaded.source_pages()[0];
    assert_eq!(loaded.source_pages().len(), 1);
    assert_eq!(source.bytes.len(), 4096);
    let mut ready = Ready {
        caller: caller_entry,
        caller_immutable: vec![(caller_source.0, caller_source.1.to_vec())],
        functions: loaded.functions().each_ref().map(|f| Function {
            entry: f.entry(),
            heads: f.certificate().heads().to_vec(),
            returns: f.certificate().returns().to_vec(),
            boundaries: f.certificate().heads().iter().map(|p| (*p, *p)).collect(),
        }),
        immutable: vec![(source.address, source.bytes.clone())],
        original_source: source.bytes.clone(),
        journal: None,
        case,
    };
    assert!(!elf.is_empty());
    let data = context.data_address();
    let requests_address = context.requests_address();
    let results_address = context.results_address();
    let targets_address = context.targets_address();
    let entries = ready.functions.each_ref().map(|f| f.entry);
    assert_eq!(
        (requests_address, targets_address, results_address),
        (data + 256, data + 288, data + 320)
    );
    assert_eq!(context.input(), case.csv.input());
    assert_eq!(context.length_input(), cases::input(case.length));
    unsafe {
        (targets_address as usize as *mut [u64; 2]).write(case.order.map(|i| entries[i]));
    }
    let targets = unsafe { &*(targets_address as usize as *const [u64; 2]) };
    let requests = unsafe { &*(requests_address as usize as *const [QualificationRequest; 2]) };
    for (i, r) in requests.iter().enumerate() {
        assert_eq!(
            (r.data as usize as u64, r.bound),
            (data + if i == 0 { 128 } else { 512 }, case.bound(i))
        );
    }
    assert_eq!(
        unsafe { (results_address as usize as *const [u64; 4]).read() },
        [0; 4]
    );
    let mut expected =
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) }.to_vec();
    for i in 0..4 {
        expected[320 + i * 8..328 + i * 8].copy_from_slice(&case.value(i).to_le_bytes());
    }
    if !candidate {
        loaded.verify_original().unwrap();
        check_live(&ready.immutable);
        check_live(&ready.caller_immutable);
        context.ready_early_entry(&early::Ready {
            module: ready.clone(),
            extra: Extra::original(),
        });
        // SAFETY: original-only fixture reference, same retained sealed 123-byte
        // caller and original targets/arrays. No new runtime state is simulated.
        let function: bytes::Caller = unsafe { std::mem::transmute(caller_entry as usize) };
        let sum = unsafe {
            function(
                targets.as_ptr().cast(),
                requests.as_ptr().cast(),
                results_address as usize as *mut u64,
            )
        };
        assert_eq!(sum, case.sum());
        assert_eq!(
            unsafe { (results_address as usize as *const [u64; 4]).read() },
            case.values()
        );
        loaded.verify_original().unwrap();
        check_live(&ready.immutable);
        check_live(&ready.caller_immutable);
    } else {
        let mut policies = [NormalModulePreparationPolicy::WholeFunction; 2];
        policies[case.order[0]] = NormalModulePreparationPolicy::CertifiedBlocks;
        let prep = EarlyEntryModuleSitePreparation::new_with_policies(
            loaded,
            identity(entries[0]),
            policies,
        )
        .unwrap();
        let gates = prep.gates().to_vec();
        assert_eq!(gates.len(), 2);
        let publisher = publisher::Publisher::for_preparation(&prep);
        let planned = prep.plan();
        assert_eq!(planned.plan().final_bytes().len(), 1);
        let final_source = &planned.plan().final_bytes()[0];
        ready.immutable[0] = (final_source.address, final_source.bytes.clone());
        for f in &mut ready.functions {
            f.boundaries.clear();
        }
        for image in planned.images() {
            for &(logical, physical) in image.instruction_boundaries() {
                let owners: Vec<_> = ready
                    .functions
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| f.heads.contains(&logical).then_some(i))
                    .collect();
                assert_eq!(owners.len(), 1);
                ready.functions[owners[0]]
                    .boundaries
                    .push((logical, physical));
            }
            ready
                .immutable
                .push((image.address(), image.bytes().to_vec()));
        }
        for f in &mut ready.functions {
            for &head in &f.heads {
                if !f.boundaries.iter().any(|(a, _)| *a == head) {
                    f.boundaries.push((head, head));
                }
            }
        }
        let gate_words = std::array::from_fn(|i| {
            let g = gates[i];
            assert_eq!(g.logical_pc, entries[i]);
            let (base, image) = ready.immutable[1..]
                .iter()
                .find(|(base, image)| {
                    *base <= g.post_load - 13 && g.post_load <= *base + image.len() as u64
                })
                .unwrap();
            let at = (g.post_load - 13 - *base) as usize;
            let bytes = &image[at..at + 13];
            assert_eq!(&bytes[..2], &[0x48, 0xb9]);
            assert_eq!(&bytes[10..], &[0x0f, 0xb6, 0x09]);
            [
                g.logical_pc,
                g.entry,
                g.post_load,
                g.observing_entry,
                g.original_body,
                u64::from_le_bytes(bytes[2..10].try_into().unwrap()),
            ]
        });
        let site = publish(prep);
        let controls: Vec<_> = site
            .role_controls()
            .filter(|(r, _)| r.kind == NormalModuleRoleKind::Entry)
            .map(|(_, c)| c.clone())
            .collect();
        assert_eq!(controls.len(), 2);
        let mut prep =
            PreparedEarlyEntryModuleSessionController::new(site, INSTALL, FUNCTIONS, case.k)
                .unwrap();
        let mut banks = prep.prepare_epoch_storage().unwrap();
        assert_eq!(banks.len(), 3);
        let (mut control, client) = unsafe { prep.activate_concurrent() }.unwrap();
        let a = control.stage_prepared(banks.pop().unwrap()).unwrap();
        let b = control.stage_prepared(banks.pop().unwrap()).unwrap();
        let generations = [a.generation().get(), b.generation().get()];
        if scenario.initial() {
            control.arm(&a).unwrap();
        }
        assert!(
            controls
                .iter()
                .all(|c| c.is_enabled() == scenario.initial())
        );
        let journal = IntervalJournal::allocate();
        let journal_address = journal.address();
        let (low, high) = context.stack_range();
        let stack = unsafe { ReadableStack::new(low, high) }.unwrap();
        let mut worker =
            unsafe { client.attach_owned(caller, case.order, 1, stack, journal) }.unwrap();
        let witness = Box::new([0_u64; WITNESS_WORDS]);
        let witness_address = witness.as_ptr() as usize as u64;
        let mut sequence = 0;
        let mut witness = witness;
        unsafe {
            qualification::install_observer(move |kind, snapshot| {
                sequence += 1;
                let mut header = [0; 128];
                encode_into(kind, sequence, snapshot, &mut header);
                let (header_out, journal_out) = witness.split_at_mut(early::JOURNAL);
                publisher.publish_words(header_out.try_into().unwrap(), &header);
                publisher.publish_words(journal_out.try_into().unwrap(), &snapshot.journal);
                snapshot_ready();
            })
        }
        .unwrap();
        ready.journal = Some(JournalReady {
            address: journal_address,
            a_generation: generations[0],
            b_generation: None,
            helper_tid: None,
        });
        let bundle = Controller {
            controller: control,
            a,
            b,
        };
        let (helper, mut local, helper_tid) = if let Some(endpoint) = endpoint {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let handle = std::thread::spawn(move || {
                let tid = unsafe { libc::syscall(libc::SYS_gettid) as u64 };
                send.send(tid).unwrap();
                let mut bundle = bundle;
                endpoint.receive(scenario);
                bundle.operation(scenario);
                let enabled = [controls[0].is_enabled(), controls[1].is_enabled()];
                let report_closed = bundle.controller.report(&bundle.a).unwrap().is_some();
                endpoint.acknowledge(scenario, generations, enabled, report_closed);
                bundle
            });
            (
                Some(handle),
                None,
                receive.recv_timeout(Duration::from_secs(1)).unwrap(),
            )
        } else {
            (None, Some(bundle), 0)
        };
        let extra = Extra {
            gates: gate_words,
            marker: snapshot_ready as *const () as usize as u64,
            witness: witness_address,
            helper_tid,
            generations,
        };
        check_live(&ready.immutable);
        check_live(&ready.caller_immutable);
        deadline.check();
        let output = unsafe {
            worker.qualification_run_batch(|call| {
                assert_eq!(call.entries(), *targets);
                assert_eq!(
                    call.continuations(),
                    bytes::CONTINUATIONS.map(|o| caller_entry + o)
                );
                context.ready_early_entry(&early::Ready {
                    module: ready.clone(),
                    extra,
                });
                let results = &mut *(results_address as usize as *mut [u64; 4]);
                let sum = call.invoke_arrays(targets, requests, results).unwrap();
                assert_eq!((sum, *results), (case.sum(), case.values()));
                assert_eq!(
                    std::slice::from_raw_parts(data as usize as *const u8, 4096),
                    expected
                );
                check_live(&ready.immutable);
                check_live(&ready.caller_immutable);
                (sum, *results)
            })
        }
        .unwrap();
        let observed = scenario.observed();
        let count = observed.iter().filter(|b| **b).count();
        assert_eq!(
            (
                output.batch,
                output.completed_calls,
                output.sum,
                output.values
            ),
            (1, 4, case.sum(), case.values())
        );
        for (i, row) in output.physical.iter().enumerate() {
            assert_eq!(
                (row.batch, row.position, row.function),
                (1, i, FUNCTIONS[case.function(i)])
            );
            assert_eq!(
                row.observed_ordinal,
                observed[i].then(|| observed[..=i].iter().filter(|b| **b).count() as u64)
            );
            assert!(ready.target(i).returns.contains(&row.return_pc));
            assert_eq!(row.return_word, caller_entry + bytes::CONTINUATIONS[i]);
            if i != 0 {
                assert_eq!(row.entry_rsp, output.physical[0].entry_rsp);
            }
        }
        assert_eq!(output.observations.is_some(), count != 0);
        let records = output
            .observations
            .as_ref()
            .map_or(&[][..], |o| o.records());
        if let Some(observations) = &output.observations {
            assert_eq!(observations.next_ordinal(), count as u64 + 1);
            assert_eq!(observations.totals().0, NormalTotals::default());
        }
        assert_eq!(records.len(), count);
        for (record, (i, row)) in records.iter().zip(
            output
                .physical
                .iter()
                .enumerate()
                .filter(|(i, _)| observed[*i]),
        ) {
            assert_eq!(record.function, row.function);
            assert_eq!(record.record.raw.ordinal, row.observed_ordinal.unwrap());
            let ordinal = record.record.raw.ordinal;
            assert_eq!(
                record.record.acknowledgement,
                if ordinal == count as u64 {
                    rapid_profiler::frontend_native::NormalAcknowledgement::CallerCheckpoint
                } else {
                    rapid_profiler::frontend_native::NormalAcknowledgement::NextEntry {
                        ordinal: ordinal + 1,
                    }
                }
            );
            assert_eq!(
                (record.record.raw.entry_pc, record.record.raw.return_pc),
                (ready.target(i).entry, row.return_pc)
            );
            let expected_generation = if scenario == Scenario::AdmittedRearm && i != 0 {
                generations[1]
            } else {
                generations[0]
            };
            assert!(
                matches!(record.record.raw.owner,RawIntervalOwner::Sampled{generation,..} if generation==expected_generation)
            );
        }
        let mut bundle = if let Some(helper) = helper {
            while !helper.is_finished() {
                deadline.check();
                std::thread::yield_now();
            }
            helper.join().unwrap()
        } else {
            local.take().unwrap()
        };
        bundle.finish(scenario, records);
        let closed = qualification::qualification_snapshot().unwrap();
        assert_eq!(
            (
                closed.completed_batches,
                closed.completed_calls,
                closed.active_batch,
                closed.position
            ),
            (1, 4, None, None)
        );
        assert!(closed.pending.is_none());
        assert_eq!(
            (closed.model_depth, closed.completed_sequence),
            (0, count as u64)
        );
        assert_eq!(
            closed.totals,
            NormalTotals {
                entered: count as u64,
                ret_observed: count as u64,
                confirmed: count as u64,
                completed: count as u64,
                unsampled: 0
            }
        );
        assert_eq!(closed.next_ordinal, count as u64 + 1);
        assert_eq!(
            &closed.journal[..4],
            &[0, 0, u64::from(std::process::id()), 0]
        );
        assert!(closed.journal[4..].iter().all(|n| *n == 0));
        worker.finish().unwrap();
        drop((worker, output, bundle, banks));
    }
    assert_eq!(
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) },
        expected
    );
    current_single_main();
    deadline.check();
    0
}

fn save_plan(
    output: &Path,
    plan: &[(u64, Scenario, usize)],
    statuses: &[&str],
    k: usize,
    order: usize,
) {
    assert_eq!(plan.len(), statuses.len());
    let mut text = String::from("profile,index,scenario,k,seed,case,csv_index,status\n");
    for (index, ((seed, scenario, case), status)) in plan.iter().zip(statuses).enumerate() {
        text.push_str(&format!(
            "qualification-feature-v1,{index},{},{k},{seed},{},{order},{status}\n",
            scenario.name(),
            case + 1
        ));
    }
    assert!(text.len() <= 65536);
    std::fs::write(output.join("early-entry-plan.csv"), text).unwrap();
}
pub(crate) struct Inputs<'a> {
    pub subject: &'a Path,
    pub expected: &'a Path,
    pub caller_path: &'a Path,
    pub caller_expected: &'a Path,
    pub caller_va: u64,
}
pub(crate) fn run(
    inputs: Inputs<'_>,
    arguments: native_module::SessionArguments,
    mode: &str,
    output: &Path,
    mut deadline: Deadline,
) {
    let Inputs {
        subject,
        expected,
        caller_path,
        caller_expected,
        caller_va,
    } = inputs;
    current_single_main();
    let elf = trusted(subject, expected);
    let caller = trusted(caller_path, caller_expected);
    let csv = TrustedFunctionSelection::new(
        &elf,
        arguments.csv.elf_va,
        arguments.csv.length,
        native_module::CSV_LABEL,
    )
    .unwrap();
    let length = TrustedFunctionSelection::new(
        &elf,
        arguments.length.elf_va,
        arguments.length.length,
        native_module::LENGTH_LABEL,
    )
    .unwrap();
    let selections = if arguments.csv.elf_va < arguments.length.elf_va {
        [&csv, &length]
    } else {
        [&length, &csv]
    };
    let scenarios: &[Scenario] = match mode {
        "enabled" => &[Scenario::Enabled],
        "bypass" => &[Scenario::Bypass],
        "scheduled" => &[
            Scenario::LoadedTrueDisarm,
            Scenario::LoadedFalseArm,
            Scenario::AdmittedRearm,
            Scenario::ReturnedDisarm,
        ],
        _ => panic!("fixed early-entry qualification mode"),
    };
    let mut plan = Vec::new();
    for seed in SEEDS {
        for &scenario in scenarios {
            for index in 0..if scenario.scheduled() { 1 } else { 16 } {
                plan.push((
                    seed,
                    scenario,
                    if scenario.scheduled() { 15 } else { index },
                ));
            }
        }
    }
    let expected = if mode == "scheduled" { 8 } else { 32 };
    assert_eq!(plan.len(), expected);
    let mut statuses = vec!["UNOBSERVED"; plan.len()];
    let order = arguments.case(0).order[0];
    save_plan(output, &plan, &statuses, arguments.k, order);
    let mut rows = String::from(
        "profile,scenario,k,seed,case,csv_index,status,children,comparisons,original_steps,candidate_steps,candidate_physical_calls,candidate_observed_entries,candidate_pre_rets,controller_handshakes,value0,value1,value2,value3,sum\n",
    );
    let mut coverage = String::from(
        "profile,k,seed,csv_cases,length_cases,csv_observed_heads,csv_declared_heads,csv_observed_edges,csv_declared_edges,csv_returns,length_heads,length_edges,length_returns\n",
    );
    let mut population = native_module::SessionPopulation::default();
    let mut covered = 0;
    for (count, &(seed, scenario, index)) in plan.iter().enumerate() {
        if count != 0 {
            deadline = Deadline::start();
        }
        statuses[count] = "DISPATCHED";
        save_plan(output, &plan, &statuses, arguments.k, order);
        // Scheduled cases use the concrete nonempty maximum bounded fixtures;
        // all-return/head coverage is supplied by both full32 static populations.
        let case = arguments.case(index);
        let oracle = NormalOracle::new_early_entry(seed, case, scenario, deadline);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            oracle.pair_early_entry(|candidate, context| {
                std::panic::set_hook(Box::new(|info| {
                    eprintln!("early-entry qualification FAILED: {info}");
                    std::process::abort();
                }));
                child(candidate, context, &elf, selections, &caller, caller_va)
            })
        }));
        let (pair, trace) = match result {
            Ok(pair) => pair,
            Err(error) => {
                statuses[count] = "FAILED";
                save_plan(output, &plan, &statuses, arguments.k, order);
                std::panic::resume_unwind(error)
            }
        };
        if !scenario.scheduled() {
            if let Some(c) = population.record(seed, case, &pair, &trace) {
                covered += 1;
                coverage.push_str(&format!(
                    "qualification-feature-v1,{},{seed},16,8,{},{},{},{},{},{},{},{}\n",
                    arguments.k,
                    c.csv_heads,
                    c.csv_declared_heads,
                    c.csv_edges,
                    c.csv_declared_edges,
                    c.csv_returns,
                    c.length_heads,
                    c.length_edges,
                    c.length_returns
                ));
                std::fs::write(output.join("early-entry-coverage.csv"), &coverage).unwrap();
            }
        }
        rows.push_str(&format!(
            "qualification-feature-v1,{},{},{},{},{},PASS,2,{},{},{},4,{},4,{},{},{},{},{},{}\n",
            scenario.name(),
            arguments.k,
            seed,
            case.csv.id(),
            case.order[0],
            pair.comparisons,
            pair.original_steps,
            pair.candidate_steps,
            scenario.observed().iter().filter(|b| **b).count(),
            usize::from(scenario.scheduled()),
            pair.values[0],
            pair.values[1],
            pair.values[2],
            pair.values[3],
            pair.outer_value
        ));
        assert!(rows.len() <= 65536);
        std::fs::write(output.join("early-entry-pairs.csv"), &rows).unwrap();
        statuses[count] = "PASS";
        save_plan(output, &plan, &statuses, arguments.k, order);
        drop(oracle);
        deadline.check();
    }
    assert!(statuses.iter().all(|s| *s == "PASS"));
    if mode != "scheduled" {
        assert_eq!(covered, 2);
        assert!(population.finish() > 0);
    } else {
        assert_eq!(covered, 0);
    }
    current_single_main();
    println!(
        "EARLY_ENTRY_QUALIFICATION profile=qualification-feature-v1 mode={mode} k={} pairs={expected} children={} PASS",
        arguments.k,
        expected * 2
    );
}
