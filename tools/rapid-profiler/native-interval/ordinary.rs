//! Four finite ordinary CALL/RET state pairs; separate from the old fixed modes.
use super::{Path, STATE_SEEDS, current_single_main, exact_truth as truth, oracle};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use oracle::native_ordinary::{
    ChildContext, GATE_BYTES, OrdinaryOracle, OriginalObservation, Ready,
};
use rapid_profiler::frontend::{Limits, Observation, PayloadOutcome};
use rapid_profiler::frontend_native::{
    CallGate, IntegerLeafContract, IntervalJournal, LoadedIntegerLeaf, OrdinarySitePreparation,
    PairTotals, PreparedIntervalController, RawIntervalOwner, ReadableStack, SiteError,
};
use rapid_profiler::generation::{Config, Disposition, FunctionId, Terminal};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

unsafe extern "C" {
    // Address-only linkage to the actual library assembly. Never called here.
    static __rapid_profiler_ordinary_call_v1: u8;
}
const CONTRACT: IntegerLeafContract = IntegerLeafContract {
    single_external_entry: true,
    ordinary_ret_only: true,
    no_active_cet: true,
};
const FUNCTION: FunctionId = FunctionId(1);

fn identity(entry: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0x6e; 32]),
        mapping: entry,
        generation: 1,
    }
}
fn protect(range: AddressRange, flags: i32) -> Result<(), Refusal> {
    // SAFETY: this sole child owns the exact full source page(s) and no caller.
    if unsafe {
        libc::mprotect(
            range.start() as usize as *mut libc::c_void,
            range.len() as usize,
            flags,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}
fn publish(
    prep: OrdinarySitePreparation,
) -> rapid_profiler::frontend_native::InstalledIntervalSite {
    current_single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|s| s.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: sole actual child, no concurrent entry/signal/writer/resume; the
    // complete preparation remains borrowed and cannot be invoked here.
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let result = unsafe {
            planned.publish_with(&[alias], &mut lease, || {
                protect(source, libc::PROT_READ | libc::PROT_EXEC)
            })
        };
        if result.is_ok() {
            assert!(!lease.is_poisoned());
        }
        result
    };
    let (installed, receipt) = match result {
        Ok(pair) => pair,
        Err(failure) => {
            eprintln!("ordinary oracle publication FAILED: {failure:?}");
            // Never unwind live published code/control owners after partial work.
            std::process::abort();
        }
    };
    // SAFETY: exact published owners, final RX, child-local process lifetime.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

fn child(
    candidate: bool,
    context: ChildContext<'_>,
    subject: &Path,
    expected_elf: &[u8],
    symbol: &std::ffi::CStr,
    concurrent: bool,
) {
    current_single_main();
    // SAFETY: independently pinned exact fixed C/assembly DSO output.
    // The selected symbol is one of the two nonempty checksum implementations. Child-local load precedes any application call; no constructors,
    // foreign callers, CET, signal/nonlocal entry, unload or source writer.
    let owner =
        unsafe { LoadedIntegerLeaf::load(subject, expected_elf, symbol, CONTRACT) }.unwrap();
    if symbol == c"exact_work_nonempty" {
        truth::check_bytes(owner.code()).unwrap();
    } else {
        assert_eq!(symbol, c"ordinary_checksum_nonempty");
    }
    let entry = owner.entry();
    let heads = owner.certificate().heads().to_vec();
    let returns = owner.certificate().returns().to_vec();
    let gate = CallGate::new(owner.certificate()).unwrap();
    let gate_address = &raw const __rapid_profiler_ordinary_call_v1 as usize as u64;
    // SAFETY: immutable text symbol, exact bounded assembly extent.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(gate_address as usize as *const u8, GATE_BYTES.len()) },
        GATE_BYTES
    );
    assert_eq!(gate.continuation(), gate_address + 25);
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let original = &prep.plan().plan().originals()[0];
    let original_source = original.bytes.clone();
    let mut immutable = vec![(original.address, original.bytes.clone())];
    let mut boundaries: Vec<_> = heads.iter().map(|p| (*p, *p)).collect();
    if candidate {
        let planned = prep.plan();
        assert_eq!(planned.plan().originals().len(), 1);
        assert_eq!(planned.plan().final_bytes().len(), 1);
        let final_source = &planned.plan().final_bytes()[0];
        immutable[0] = (final_source.address, final_source.bytes.clone());
        boundaries.clear();
        for image in planned.images() {
            boundaries.extend_from_slice(image.instruction_boundaries());
            immutable.push((image.address(), image.bytes().to_vec()));
        }
        for &pc in &heads {
            if !boundaries.iter().any(|(head, _)| *head == pc) {
                boundaries.push((pc, pc));
            }
        }
    }
    let ready = Ready {
        entry,
        gate: gate_address,
        continuation: prep.gate().continuation(),
        heads,
        returns,
        boundaries,
        immutable,
        original_source,
    };
    let data = context.input().as_ptr();
    let length = context.input().len();
    let expected = context
        .input()
        .iter()
        .map(|b| u64::from(b ^ 0x5a))
        .sum::<u64>()
        ^ 0x9e37_79b9_7f4a_7c15;
    let gate_rsp = context.gate_rsp();
    let (start, end) = context.stack_range();
    // SAFETY: the ptrace qualification boundary moves only the actual armed
    // gate invocation to this inherited private, mapped, guarded stack. Its
    // real CALL/RET slot stays in this range through the qualified region.
    let stack = unsafe { ReadableStack::new(start, end) }.unwrap();
    if candidate {
        let site = publish(prep);
        let mut prepared = PreparedIntervalController::new(
            site,
            0x6e61_7401,
            FUNCTION,
            Limits {
                epochs: 1,
                threads: 1,
                depth: 1,
                records_per_epoch: 1,
                actions: 2,
            },
        )
        .unwrap();
        let epoch = prepared
            .stage(Config {
                retained_per_function: 1,
                max_inflight: 1,
                max_invocations: 1,
            })
            .unwrap();
        let generation = epoch.generation().get();
        // SAFETY: this actual single child owns all code before attaching TLS.
        let (mut controller, client) = unsafe {
            if concurrent {
                prepared.activate_concurrent()
            } else {
                prepared.activate()
            }
        }
        .unwrap();
        controller.arm(&epoch).unwrap();
        let mut attached = unsafe { client.attach(1, stack, IntervalJournal::allocate()) }.unwrap();
        let totals = PairTotals {
            entries: 1,
            returns: 1,
            completed: 1,
            unsampled: 0,
        };
        context.ready(&ready);
        // SAFETY: live inherited immutable input, 1/64 nonempty scalar leaf,
        // exact attached gate and controlled stack; the tracer restores only
        // the outer harness context AFTER complete application comparisons.
        let result =
            unsafe { attached.invoke_integer_leaf(std::slice::from_raw_parts(data, length)) }
                .unwrap();
        assert_eq!(result.value, expected);
        assert_eq!(result.pre_call_rsp, gate_rsp - 8);
        assert_eq!(result.entry_rsp, gate_rsp - 16);
        assert_eq!(result.resumed_rsp, gate_rsp - 8);
        assert!(ready.returns.contains(&result.return_pc));
        assert_eq!(attached.totals().unwrap(), totals);
        let rows = attached.raw_intervals().unwrap();
        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!(row.ordinal, 1);
        assert_eq!(row.entry_pc, entry);
        assert_eq!(row.return_pc, result.return_pc);
        assert_eq!(
            row.owner,
            RawIntervalOwner::Sampled {
                generation,
                invocation: 0
            }
        );
        assert_eq!(attached.detach().unwrap(), totals);
        controller.disarm(&epoch).unwrap();
        let report = controller.report(&epoch).unwrap().unwrap();
        assert_eq!(report.generation().get(), generation);
        let records: Vec<_> = report.records().collect();
        assert_eq!(records.len(), 1);
        let admission = records[0].record.admission;
        assert_eq!(admission.generation.get(), generation);
        assert_eq!(admission.function, FUNCTION);
        assert_eq!(admission.invocation, 0);
        assert_eq!(admission.entry_value, row.start.ticks);
        assert_eq!(
            records[0].record.terminal,
            Some(Terminal::Completed {
                value: 0,
                disposition: Disposition::Retained { rank: 0 },
            })
        );
        let payload = records[0].payload.unwrap();
        assert_eq!(payload.admission, admission);
        assert_eq!(payload.thread, 1);
        assert_eq!(payload.start_sequence, 0);
        let end = if row.start.aux != row.end.aux {
            Observation::Unavailable(1)
        } else if row.end.ticks < row.start.ticks {
            Observation::Unavailable(2)
        } else {
            Observation::Value(row.end.ticks)
        };
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end,
                completed_children: 0
            }
        );
        // Raw timestamps are joined as private owner data, never compared
        // across children or used to relax any application-state predicate.
    } else {
        // SAFETY: same sole-child original-only ownership contract. The complete
        // before-check precedes readiness; no writer/fork/reentry intervenes.
        let call = unsafe { prep.prepare_original_call() }.unwrap();
        // The tracer-owned SIGSTOP runs no handler and changes no owner/code;
        // actual gate execution keeps its no-signal/no-reentry contract.
        context.ready(&ready);
        // SAFETY: the consuming original-only guard uses the unchanged private
        // arming/assembly and full after-check, with no callback/completion credit.
        let result = unsafe { call.invoke(data, length, &stack) }.unwrap();
        assert_eq!(result.value, expected);
        assert_eq!(result.pre_call_rsp, gate_rsp - 8);
        assert_eq!(result.resumed_rsp, gate_rsp - 8);
    }
    current_single_main();
}

fn bytes_at(bytes: &[u8], base: u64, address: u64, count: usize) -> &[u8] {
    let offset = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    &bytes[offset..offset.checked_add(count).unwrap()]
}

// Independent expected trace uses no Ready heads, certificate or emitted map.
// The original path is an actual normal uninstrumented subject invocation.
fn check_exact(observed: OriginalObservation<'_>) -> (usize, usize, usize, usize) {
    let code = bytes_at(
        observed.source,
        observed.source_address,
        observed.entry,
        truth::BYTES.len(),
    );
    truth::check_bytes(code).unwrap();
    let steps: Vec<_> = observed.steps().collect();
    let starts: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(i, s)| (s.before.rip == observed.entry).then_some(i))
        .collect();
    assert_eq!(starts.len(), 1, "one actual external entry");
    let first = &steps[starts[0]];
    assert_eq!(
        (first.before.rdi, first.before.rsi),
        (observed.input_address, observed.input.len() as u64)
    );
    let input = bytes_at(
        first.data,
        first.data_address,
        first.before.rdi,
        observed.input.len(),
    );
    assert_eq!(input, observed.input);
    let return_word = u64::from_le_bytes(
        bytes_at(first.stack, first.stack_address, first.before.rsp, 8)
            .try_into()
            .unwrap(),
    );
    assert_eq!(return_word, observed.continuation);
    let expected = truth::interpret(
        code,
        input,
        observed.entry,
        first.before.rdi,
        first.before.rsp,
        return_word,
    )
    .unwrap();
    let body = &steps[starts[0]..starts[0].checked_add(expected.steps.len()).unwrap()];
    assert_eq!(
        body.iter()
            .map(|s| s.before.rip - observed.entry)
            .collect::<BTreeSet<_>>(),
        truth::HEADS
            .iter()
            .map(|&p| u64::from(p))
            .collect::<BTreeSet<_>>()
    );
    let (mut conditional, mut taken, mut reads) = (0, 0, 0);
    for (actual, predicted) in body.iter().zip(&expected.steps) {
        assert_eq!(
            (actual.before.rip, actual.after.rip),
            (predicted.pc, predicted.next_pc)
        );
        assert_eq!(
            bytes_at(
                actual.data,
                actual.data_address,
                observed.input_address,
                input.len()
            ),
            input
        );
        if let Some(branch) = predicted.branch_taken {
            conditional += 1;
            let actual_taken = actual.before.eflags & 1 != 0; // Fixed JB consumes CMP's CF.
            assert_eq!(actual_taken, branch);
            taken += usize::from(actual_taken);
        }
        if let Some(read) = predicted.read {
            reads += 1;
            match read.kind {
                truth::ReadKind::InputByte => {
                    assert_eq!((read.address, read.width), (actual.before.rdi, 1));
                    assert_eq!(
                        read.value,
                        u64::from(
                            bytes_at(actual.data, actual.data_address, actual.before.rdi, 1)[0]
                        )
                    );
                    assert_eq!(actual.after.rcx, read.value); // MOVZX really consumed that byte.
                }
                truth::ReadKind::ReturnWord => {
                    assert_eq!((read.address, read.width), (actual.before.rsp, 8));
                    assert_eq!(
                        read.value,
                        u64::from_le_bytes(
                            bytes_at(actual.stack, actual.stack_address, actual.before.rsp, 8)
                                .try_into()
                                .unwrap()
                        )
                    );
                    assert_eq!(actual.after.rip, read.value);
                    assert_eq!(actual.after.rsp, actual.before.rsp.checked_add(8).unwrap());
                }
            }
        }
    }
    let last = body.last().unwrap();
    assert_eq!(last.before.rip, observed.entry + 36);
    assert_eq!(
        (last.after.rip, last.after.rsp, last.after.rax),
        (return_word, expected.resumed_rsp, expected.value)
    );
    assert_eq!(last.after.rax, truth::checksum(input).unwrap());
    assert_eq!(
        steps[starts[0] + body.len()].before.rip,
        observed.continuation,
        "subject RET followed immediately by actual gate continuation"
    );
    let counts = (body.len(), conditional, taken, reads);
    assert_eq!(counts, truth::counts(input.len()).unwrap());
    counts
}

pub fn run(subject: &Path, expected: &Path, output: &Path) {
    run_selected(subject, expected, output, false, false);
}

pub fn run_exact(subject: &Path, expected: &Path, output: &Path) {
    run_selected(subject, expected, output, true, false);
}

pub fn run_exact_concurrent(subject: &Path, expected: &Path, output: &Path) {
    run_selected(subject, expected, output, true, true);
}

fn run_selected(subject: &Path, expected: &Path, output: &Path, exact: bool, concurrent: bool) {
    current_single_main();
    // The root-owned recipe supplies a separately trusted exact compiler ELF;
    // these bytes are not generated from the candidate by this native fixture.
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
    let mut csv = String::from(
        "seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value\n",
    );
    let mut trace_csv = String::from(
        "seed,length,status,instructions,conditional_branches,taken_branches,input_reads,return_reads,value\n",
    );
    let mut comparisons = 0;
    for seed in STATE_SEEDS {
        let mut observed = BTreeSet::new();
        let mut declared = None;
        for length in [1, 64] {
            let oracle = OrdinaryOracle::new(seed);
            let result = if exact {
                let mut counts = None;
                let result = oracle.pair_with_original(
                    length,
                    |candidate, context| {
                        child(
                            candidate,
                            context,
                            subject,
                            &expected_elf,
                            c"exact_work_nonempty",
                            concurrent,
                        )
                    },
                    |observed| {
                        counts = Some(check_exact(observed));
                    },
                );
                let (instructions, conditional, taken, reads) =
                    counts.expect("actual original inspected");
                assert_eq!(result.visits, instructions);
                trace_csv.push_str(&format!(
                    "{seed},{length},PASS,{instructions},{conditional},{taken},{},1,{}\n",
                    reads - 1,
                    result.value
                ));
                std::fs::write(output.join("exact-truth.csv"), &trace_csv).unwrap();
                result
            } else {
                oracle.pair(length, |candidate, context| {
                    child(
                        candidate,
                        context,
                        subject,
                        &expected_elf,
                        c"ordinary_checksum_nonempty",
                        concurrent,
                    )
                })
            };
            if let Some(previous) = &declared {
                assert_eq!(previous, &result.declared_returns);
            } else {
                declared = Some(result.declared_returns.clone());
            }
            observed.extend(result.returns);
            comparisons += result.comparisons;
            csv.push_str(&format!(
                "{seed},{length},PASS,2,{},{},{},{},{}\n",
                result.comparisons,
                result.visits,
                result.original_steps,
                result.candidate_steps,
                result.value
            ));
            std::fs::write(
                output.join(if exact {
                    "exact-pairs.csv"
                } else {
                    "ordinary-pairs.csv"
                }),
                &csv,
            )
            .unwrap();
        }
        assert_eq!(
            observed,
            declared.unwrap(),
            "actual RET union covers the complete certificate for this seed"
        );
    }
    // Run after ALL pair forks: no parent PID-bound loader owner enters a child.
    let negative =
        unsafe { LoadedIntegerLeaf::load(subject, &expected_elf, c"ordinary_checksum", CONTRACT) }
            .unwrap();
    assert!(
        negative
            .certificate()
            .returns()
            .iter()
            .any(|&ret| negative.certificate().blocks().contains(&(ret, ret + 1))),
        "required real compiler one-byte RET block"
    );
    let entry = negative.entry();
    let gate = CallGate::new(negative.certificate()).unwrap();
    assert!(
        matches!(
            OrdinarySitePreparation::new(negative, gate, identity(entry)),
            Err(SiteError::Core(Refusal::NoPatchWindow))
        ),
        "complete short-RET factory refusal"
    );
    std::fs::write(
        output.join(if exact {
            "exact-refusals.csv"
        } else {
            "ordinary-refusals.csv"
        }),
        "case,status,reason\nempty_capable_symbol,PASS,NoPatchWindow\n",
    )
    .unwrap();
    current_single_main();
    if exact {
        let mode = if concurrent {
            "exact-concurrent"
        } else {
            "exact"
        };
        println!(
            "native-{mode}:required=4:pairs=4:children=8:comparisons={comparisons}:truth-instructions=800:conditional=130:taken=126:input-reads=130:return-reads=4:short-ret-refusals=1:real-outer-ret=8:complete"
        );
    } else {
        println!(
            "native-ordinary:required=4:pairs=4:children=8:comparisons={comparisons}:short-ret-refusals=1:real-outer-ret=8:complete"
        );
    }
}
