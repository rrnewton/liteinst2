//! Pure scripted-System controls; no Linux, perf fd, CPUID or native subject.
use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const FD: i32 = 41;
const ID: u64 = 0x0102_0304_0506_0708;
const EXTERNAL: u64 = 73;

fn cpu() -> CpuIdentity {
    CpuIdentity {
        cpu: 7,
        pid: 101,
        tid: 103,
        vendor: *b"AuthenticAMD",
        family: 26,
        model: 17,
        stepping: 0,
    }
}
fn ok(result: i64) -> Syscall {
    Syscall {
        result,
        errno: None,
    }
}
fn failed(errno: i32) -> Syscall {
    Syscall {
        result: -1,
        errno: Some(errno),
    }
}
fn bytes(words: [u64; 4]) -> Vec<u8> {
    words.into_iter().flat_map(u64::to_ne_bytes).collect()
}
fn attributes() -> Vec<u8> {
    // Independent literal ABI encoding, not FLAGS/READ_FORMAT/RAW_CONFIG.
    let mut a = vec![0; ATTR_BYTES];
    a[..4].copy_from_slice(&[4, 0, 0, 0]); // PERF_TYPE_RAW.
    a[4..8].copy_from_slice(&(ATTR_BYTES as u32).to_le_bytes());
    a[8..10].copy_from_slice(&[0x64, 0x09]);
    a[32] = 7; // ENABLED | RUNNING | ID.
    a[40] = 0x65; // disabled, pinned, exclude_kernel, exclude_hv.
    a[42] = 0x10; // exclude_guest; every other flag remains zero.
    a
}

#[derive(Clone, Debug)]
enum Step {
    Cpu(Result<CpuIdentity, CpuFailure>),
    Open {
        reply: Syscall,
        write_size: Option<u32>,
    },
    Op {
        fd: i32,
        operation: Operation,
        reply: Syscall,
        data: Vec<u8>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
enum Seen {
    Cpu,
    Open,
    Op(i32, Operation),
    Invoke,
}
impl Step {
    fn seen(&self) -> Seen {
        match self {
            Self::Cpu(_) => Seen::Cpu,
            Self::Open { .. } => Seen::Open,
            Self::Op { fd, operation, .. } => Seen::Op(*fd, *operation),
        }
    }
}
fn op(operation: Operation, reply: Syscall, data: Vec<u8>) -> Step {
    Step::Op {
        fd: FD,
        operation,
        reply,
        data,
    }
}
fn closed() -> Step {
    op(Operation::Close, ok(0), vec![])
}
fn success(end: [u64; 3]) -> Vec<Step> {
    vec![
        Step::Cpu(Ok(cpu())),
        Step::Open {
            reply: ok(i64::from(FD)),
            write_size: None,
        },
        op(Operation::Id, ok(0), ID.to_ne_bytes().to_vec()),
        op(Operation::ReadDisabledStart, ok(32), bytes([0, 0, 0, ID])),
        op(Operation::Enable, ok(0), vec![]),
        op(Operation::Disable, ok(0), vec![]),
        op(
            Operation::ReadDisabledEnd,
            ok(32),
            bytes([end[0], end[1], end[2], ID]),
        ),
        Step::Cpu(Ok(cpu())),
        closed(),
    ]
}
fn expected(steps: &[Step], invoked: bool) -> Vec<Seen> {
    let mut result: Vec<_> = steps.iter().map(Step::seen).collect();
    if invoked {
        let enable = result
            .iter()
            .position(|s| matches!(s, Seen::Op(_, Operation::Enable)))
            .unwrap();
        result.insert(enable + 1, Seen::Invoke);
    }
    result
}
struct Script {
    pending: VecDeque<Step>,
    seen: Rc<RefCell<Vec<Seen>>>,
    mismatches: Vec<String>,
}
impl Script {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            pending: steps.into(),
            seen: Rc::new(RefCell::new(vec![])),
            mismatches: vec![],
        }
    }
    fn finish(&self, expected: &[Seen]) {
        assert!(self.pending.is_empty(), "unused steps: {:?}", self.pending);
        assert!(self.mismatches.is_empty(), "{:?}", self.mismatches);
        assert_eq!(self.seen.borrow().as_slice(), expected);
    }
    fn mismatch(&mut self, value: impl std::fmt::Debug) {
        // Do not panic inside Flight::drop: report unexpected cleanup safely at
        // the final assertion, including a retry after an EINTR close result.
        self.mismatches.push(format!("{value:?}"));
    }
}
impl System for Script {
    fn cpu(&mut self) -> Result<CpuIdentity, CpuFailure> {
        self.seen.borrow_mut().push(Seen::Cpu);
        match self.pending.pop_front() {
            Some(Step::Cpu(reply)) => reply,
            other => {
                self.mismatch(other);
                Err(CpuFailure::NotSingleton)
            }
        }
    }
    fn open(&mut self, request: &mut Request) -> Syscall {
        self.seen.borrow_mut().push(Seen::Open);
        if request.0.as_slice() != attributes() {
            self.mismatch("request bytes changed");
        }
        match self.pending.pop_front() {
            Some(Step::Open { reply, write_size }) => {
                if let Some(size) = write_size {
                    request.0[4..8].copy_from_slice(&size.to_le_bytes());
                }
                reply
            }
            other => {
                self.mismatch(other);
                failed(libc::EIO)
            }
        }
    }
    fn operate(&mut self, fd: i32, operation: Operation, output: &mut [u8; READ_BYTES]) -> Syscall {
        self.seen.borrow_mut().push(Seen::Op(fd, operation));
        if *output != [0; READ_BYTES] {
            self.mismatch("output buffer was not initialized");
        }
        match self.pending.pop_front() {
            Some(Step::Op {
                fd: want_fd,
                operation: want_op,
                reply,
                data,
            }) => {
                if (fd, operation) != (want_fd, want_op) {
                    self.mismatch((fd, operation, want_fd, want_op));
                }
                if data.len() > READ_BYTES {
                    self.mismatch("script payload too large");
                }
                for (destination, source) in output.iter_mut().zip(data) {
                    *destination = source;
                }
                reply
            }
            other => {
                self.mismatch(other);
                failed(libc::EIO)
            }
        }
    }
}
fn exercise(steps: Vec<Step>, invoked: bool) -> ProbeObservation<u64> {
    let order = expected(&steps, invoked);
    let mut script = Script::new(steps);
    let seen = Rc::clone(&script.seen);
    let observed = run(&mut script, EXTERNAL, || {
        seen.borrow_mut().push(Seen::Invoke);
        991_u64
    });
    script.finish(&order);
    assert_eq!(observed.invocation, invoked.then_some(991));
    assert_eq!(observed.receipt.external_id, EXTERNAL);
    assert_eq!(observed.receipt.requested_attributes, attributes());
    observed
}
fn row(receipt: &ProbeReceipt, operation: Operation) -> OperationResult {
    let mut rows = receipt
        .operations
        .iter()
        .filter(|r| r.operation == operation);
    let result = *rows.next().expect("required operation");
    assert!(rows.next().is_none(), "operation was retried");
    result
}
fn reading(value: u64, enabled: u64, running: u64) -> CounterReading {
    CounterReading {
        value,
        time_enabled: enabled,
        time_running: running,
    }
}

#[test]
fn request_wire_bytes_are_exact_and_fresh_storage_is_zero() {
    assert_eq!(request().0.as_slice(), attributes());
    let mut changed = request();
    changed.0.fill(0xff);
    assert_eq!(request().0.as_slice(), attributes());
    assert_eq!(core::mem::align_of::<Request>(), 8);
}

#[test]
fn successful_zero_count_retains_every_endpoint_id_and_operation() {
    let observed = exercise(success([0, 11, 11]), true);
    let receipt = observed.receipt;
    assert!(receipt.issues.is_empty());
    assert_eq!(
        (receipt.cpu_before, receipt.cpu_after),
        (Some(cpu()), Some(cpu()))
    );
    assert_eq!(receipt.event_id, Some(ID));
    assert_eq!(receipt.attributes_after_open, attributes());
    assert_eq!(
        receipt
            .operations
            .iter()
            .map(|r| r.operation)
            .collect::<Vec<_>>(),
        [
            Operation::Open,
            Operation::Id,
            Operation::ReadDisabledStart,
            Operation::Enable,
            Operation::Disable,
            Operation::ReadDisabledEnd,
            Operation::Close,
        ]
    );
    assert_eq!(receipt.counters.start(), Some(reading(0, 0, 0)));
    assert_eq!(receipt.counters.end(), Some(reading(0, 11, 11)));
    assert_eq!(
        receipt.full_running_delta,
        Some(CounterDelta {
            value: 0,
            time_enabled: 11,
            time_running: 11
        })
    );
    for operation in [
        Operation::Id,
        Operation::ReadDisabledStart,
        Operation::ReadDisabledEnd,
    ] {
        let r = row(&receipt, operation);
        assert_eq!(r.syscall.errno, None);
        assert_eq!(r.data_len, if operation == Operation::Id { 8 } else { 32 });
    }
    assert_eq!(
        &row(&receipt, Operation::ReadDisabledEnd).data,
        bytes([0, 11, 11, ID]).as_slice()
    );
}

#[test]
fn invalid_label_and_every_cpu_before_failure_invoke_nothing() {
    let mut script = Script::new(vec![]);
    let observed: ProbeObservation<()> =
        run(&mut script, 0, || panic!("invalid label invoked work"));
    script.finish(&[]);
    assert!(observed.invocation.is_none());
    assert_eq!(observed.receipt.issues, [Issue::ExternalId]);
    assert!(observed.receipt.operations.is_empty());
    assert!(observed.receipt.cpu_before.is_none());
    for error in [
        CpuFailure::Affinity(failed(libc::EINVAL)),
        CpuFailure::NotSingleton,
        CpuFailure::CurrentCpu(failed(libc::ENOSYS)),
        CpuFailure::Identity(failed(libc::ESRCH)),
        CpuFailure::UnsupportedVendorOrFamily,
    ] {
        let observed = exercise(vec![Step::Cpu(Err(error))], false);
        assert_eq!(observed.receipt.issues, [Issue::CpuBefore(error)]);
        assert!(observed.receipt.operations.is_empty());
        assert!(observed.receipt.attributes_after_open.is_empty());
        assert!(observed.receipt.full_running_delta.is_none());
    }
}

#[test]
fn open_failure_retains_errno_and_kernel_modified_attribute_size_without_close() {
    let observed = exercise(
        vec![
            Step::Cpu(Ok(cpu())),
            Step::Open {
                reply: failed(libc::E2BIG),
                write_size: Some(64),
            },
        ],
        false,
    );
    let receipt = observed.receipt;
    assert_eq!(receipt.issues, [Issue::Operation(Operation::Open)]);
    let mut after = attributes();
    after[4..8].copy_from_slice(&64_u32.to_le_bytes());
    assert_eq!(receipt.attributes_after_open, after);
    assert_eq!(receipt.operations.len(), 1);
    assert_eq!(row(&receipt, Operation::Open).syscall, failed(libc::E2BIG));
    assert!(receipt.event_id.is_none());
    assert!(receipt.full_running_delta.is_none());
}

#[test]
fn id_and_enable_refusals_close_once_and_never_invoke() {
    for (index, operation, errno) in [
        (2, Operation::Id, libc::EIO),
        (4, Operation::Enable, libc::EBUSY),
    ] {
        let mut steps = success([7, 10, 10]);
        steps.truncate(index + 1);
        steps[index] = op(operation, failed(errno), vec![]);
        steps.push(closed());
        let observed = exercise(steps, false);
        assert_eq!(observed.receipt.issues, [Issue::Operation(operation)]);
        assert_eq!(row(&observed.receipt, operation).syscall, failed(errno));
        assert_eq!(row(&observed.receipt, Operation::Close).syscall, ok(0));
        assert!(observed.receipt.full_running_delta.is_none());
    }
}

#[test]
fn every_incomplete_read_preserves_only_its_actual_prefix_and_never_decodes_it() {
    // Oversize 33 is an impossible Linux read result but a separate wire-length
    // refusal; it must not become a complete endpoint through the clamp to 32.
    for (reply, prefix) in [
        (failed(libc::EINTR), 0),
        (ok(0), 0),
        (ok(1), 1),
        (ok(7), 7),
        (ok(8), 8),
        (ok(23), 23),
        (ok(31), 31),
        (ok(33), 32),
    ] {
        for operation in [Operation::ReadDisabledStart, Operation::ReadDisabledEnd] {
            let mut steps = success([7, 10, 10]);
            let index = if operation == Operation::ReadDisabledStart {
                3
            } else {
                6
            };
            let payload = bytes([7, 10, 10, ID])[..prefix].to_vec();
            steps[index] = op(operation, reply, payload.clone());
            let invoked = operation == Operation::ReadDisabledEnd;
            if !invoked {
                steps.truncate(4);
                steps.push(closed());
            }
            let observed = exercise(steps, invoked);
            let receipt = observed.receipt;
            let r = row(&receipt, operation);
            assert_eq!(r.syscall, reply);
            assert_eq!(r.data_len, prefix);
            assert_eq!(&r.data[..prefix], payload.as_slice());
            assert_eq!(&r.data[prefix..], vec![0; 32 - prefix]);
            let first = if reply.result < 0 {
                Issue::Operation(operation)
            } else {
                Issue::ReadSize(operation)
            };
            let mut issues = vec![first];
            if invoked {
                issues.push(Issue::Arithmetic);
            }
            assert_eq!(receipt.issues, issues);
            if invoked {
                assert!(receipt.counters.end().is_none());
            } else {
                assert!(receipt.counters.start().is_none());
            }
            assert!(receipt.full_running_delta.is_none());
        }
    }
}

#[test]
fn wrong_start_or_end_id_retains_full_raw_words_without_qualification() {
    for operation in [Operation::ReadDisabledStart, Operation::ReadDisabledEnd] {
        let mut steps = success([7, 10, 10]);
        let (index, values, invoked) = if operation == Operation::ReadDisabledStart {
            (3, [0, 0, 0, ID + 1], false)
        } else {
            (6, [7, 10, 10, ID + 1], true)
        };
        steps[index] = op(operation, ok(32), bytes(values));
        if !invoked {
            steps.truncate(4);
            steps.push(closed());
        }
        let observed = exercise(steps, invoked);
        let receipt = observed.receipt;
        assert_eq!(receipt.event_id, Some(ID));
        assert_eq!(receipt.issues, [Issue::EventId(operation)]);
        assert_eq!(row(&receipt, operation).data.as_slice(), bytes(values));
        assert_eq!(receipt.counters.start(), Some(reading(0, 0, 0)));
        if invoked {
            assert_eq!(receipt.counters.end(), Some(reading(7, 10, 10)));
        }
        assert!(receipt.full_running_delta.is_none());
    }
}

#[test]
fn each_nonfresh_baseline_word_refuses_before_enable_and_keeps_the_reading() {
    for values in [[1, 0, 0, ID], [0, 1, 0, ID], [0, 0, 1, ID]] {
        let mut steps = success([7, 10, 10]);
        steps.truncate(4);
        steps[3] = op(Operation::ReadDisabledStart, ok(32), bytes(values));
        steps.push(closed());
        let observed = exercise(steps, false);
        assert_eq!(observed.receipt.issues, [Issue::NotFresh]);
        assert_eq!(
            observed.receipt.counters.start(),
            Some(reading(values[0], values[1], values[2]))
        );
        assert!(observed.receipt.counters.end().is_none());
        assert!(observed.receipt.full_running_delta.is_none());
    }
}

#[test]
fn disable_read_close_failures_all_survive_in_order_without_retries() {
    let mut steps = success([7, 10, 10]);
    steps[5] = op(Operation::Disable, failed(libc::EIO), vec![]);
    steps[6] = op(Operation::ReadDisabledEnd, failed(libc::EFAULT), vec![]);
    steps[7] = Step::Cpu(Err(CpuFailure::NotSingleton));
    steps[8] = op(Operation::Close, failed(libc::EINTR), vec![]);
    let observed = exercise(steps, true);
    assert_eq!(
        observed.receipt.issues,
        [
            Issue::Operation(Operation::Disable),
            Issue::Operation(Operation::ReadDisabledEnd),
            Issue::CpuAfter(CpuFailure::NotSingleton),
            Issue::Operation(Operation::Close),
            Issue::Arithmetic,
        ]
    );
    for (operation, errno) in [
        (Operation::Disable, libc::EIO),
        (Operation::ReadDisabledEnd, libc::EFAULT),
        (Operation::Close, libc::EINTR),
    ] {
        assert_eq!(row(&observed.receipt, operation).syscall, failed(errno));
    }
    assert_eq!(observed.receipt.counters.start(), Some(reading(0, 0, 0)));
    assert!(observed.receipt.counters.end().is_none());
    assert!(observed.receipt.full_running_delta.is_none());
}

#[test]
fn each_cleanup_error_prevents_full_running_without_erasing_valid_endpoints() {
    for (index, operation) in [(5, Operation::Disable), (8, Operation::Close)] {
        let mut steps = success([7, 10, 10]);
        steps[index] = op(operation, failed(libc::EINTR), vec![]);
        let observed = exercise(steps, true);
        assert_eq!(observed.receipt.issues, [Issue::Operation(operation)]);
        assert_eq!(observed.receipt.counters.end(), Some(reading(7, 10, 10)));
        assert!(matches!(
            observed.receipt.counters.arithmetic(),
            Arithmetic::FullRunning { .. }
        ));
        assert!(observed.receipt.full_running_delta.is_none());
    }
}

#[test]
fn zero_running_multiplexing_and_invalid_time_relationships_are_not_scaled() {
    for (words, kind) in [
        ([0, 0, 0], "zero"),
        ([0, 10, 0], "zero"),
        ([1, 10, 0], "rejected"),
        ([7, 10, 4], "multiplexed"),
        ([7, 3, 4], "rejected"),
    ] {
        let observed = exercise(success(words), true);
        let receipt = observed.receipt;
        assert_eq!(
            receipt.counters.end(),
            Some(reading(words[0], words[1], words[2]))
        );
        assert_eq!(receipt.issues, [Issue::Arithmetic]);
        assert!(receipt.full_running_delta.is_none());
        match (kind, receipt.counters.arithmetic()) {
            ("zero", Arithmetic::ZeroRunning { .. })
            | ("rejected", Arithmetic::Rejected { .. }) => {}
            ("multiplexed", Arithmetic::Multiplexed { delta, estimate }) => {
                assert_eq!(delta.value, 7);
                assert_eq!((estimate.numerator(), estimate.denominator()), (70, 4));
                // The exact arithmetic ratio remains available, but is not
                // promoted to a probe full-running result or integer estimate.
            }
            other => panic!("wrong arithmetic class: {other:?}"),
        }
    }
    let observed = exercise(success([u64::MAX, u64::MAX, u64::MAX]), true);
    assert!(observed.receipt.issues.is_empty());
    assert_eq!(
        observed.receipt.full_running_delta,
        Some(CounterDelta {
            value: u64::MAX,
            time_enabled: u64::MAX,
            time_running: u64::MAX,
        })
    );
}

#[test]
fn saved_endpoint_regressions_remain_visible_without_modular_subtraction() {
    // A successful run starts at zero, so regression is not a reachable native
    // run case. This directly exercises its endpoint decoder + shared arithmetic.
    let mut receipt = exercise(success([7, 10, 10]), true).receipt;
    let start = reading(100, 20, 10);
    for (end, flags) in [
        (reading(99, 30, 20), (true, false, false)),
        (reading(101, 19, 15), (false, true, false)),
        (reading(101, 30, 9), (false, false, true)),
    ] {
        let mut raw = [0; READ_BYTES];
        raw.copy_from_slice(&bytes([end.value, end.time_enabled, end.time_running, ID]));
        let decoded = endpoint(
            OperationResult {
                operation: Operation::ReadDisabledEnd,
                syscall: ok(32),
                data_len: 32,
                data: raw,
            },
            &mut receipt,
        );
        let record = CounterRecord::new(Some(start), decoded);
        assert_eq!(record.start(), Some(start));
        assert_eq!(record.end(), Some(end));
        let Arithmetic::Rejected { issues, deltas } = record.arithmetic() else {
            panic!("regression accepted");
        };
        assert_eq!(
            (
                issues.value_regressed,
                issues.time_enabled_regressed,
                issues.time_running_regressed
            ),
            flags
        );
        assert_eq!(deltas.value.is_none(), flags.0);
        assert_eq!(deltas.time_enabled.is_none(), flags.1);
        assert_eq!(deltas.time_running.is_none(), flags.2);
    }
    assert!(receipt.issues.is_empty());
}

#[test]
fn all_post_cpu_errors_and_every_changed_identity_field_refuse_after_real_invocation() {
    for error in [
        CpuFailure::Affinity(failed(libc::EINVAL)),
        CpuFailure::NotSingleton,
        CpuFailure::CurrentCpu(failed(libc::ENOSYS)),
        CpuFailure::Identity(failed(libc::ESRCH)),
        CpuFailure::UnsupportedVendorOrFamily,
    ] {
        let mut steps = success([7, 10, 10]);
        steps[7] = Step::Cpu(Err(error));
        let observed = exercise(steps, true);
        assert_eq!(observed.receipt.issues, [Issue::CpuAfter(error)]);
        assert!(observed.receipt.cpu_after.is_none());
        assert!(observed.receipt.full_running_delta.is_none());
    }
    for field in 0..7 {
        let mut changed = cpu();
        match field {
            0 => changed.cpu += 1,
            1 => changed.pid += 1,
            2 => changed.tid += 1,
            3 => changed.vendor = *b"GenuineIntel",
            4 => changed.family += 1,
            5 => changed.model += 1,
            _ => changed.stepping += 1,
        }
        let mut steps = success([7, 10, 10]);
        steps[7] = Step::Cpu(Ok(changed));
        let observed = exercise(steps, true);
        assert_eq!(observed.receipt.issues, [Issue::CpuChanged]);
        assert_eq!(
            (observed.receipt.cpu_before, observed.receipt.cpu_after),
            (Some(cpu()), Some(changed))
        );
        assert_eq!(observed.receipt.counters.end(), Some(reading(7, 10, 10)));
        assert!(observed.receipt.full_running_delta.is_none());
    }
}

#[test]
fn closure_error_is_preserved_independently_and_normal_cleanup_still_finishes() {
    let steps = success([7, 10, 10]);
    let order = expected(&steps, true);
    let mut script = Script::new(steps);
    let seen = Rc::clone(&script.seen);
    let observed = run(&mut script, EXTERNAL, || {
        seen.borrow_mut().push(Seen::Invoke);
        Err::<u64, _>("actual invocation failure")
    });
    script.finish(&order);
    assert_eq!(observed.invocation, Some(Err("actual invocation failure")));
    assert!(observed.receipt.issues.is_empty());
    assert_eq!(
        observed.receipt.full_running_delta,
        Some(CounterDelta {
            value: 7,
            time_enabled: 10,
            time_running: 10,
        })
    ); // Counter success must not rewrite the closure's Err as workload success.
}

#[test]
fn unwind_disables_and_closes_exactly_once_even_when_both_cleanup_calls_fail() {
    for cleanup_fails in [false, true] {
        let mut steps = success([7, 10, 10]);
        steps.truncate(5);
        let reply = if cleanup_fails {
            failed(libc::EINTR)
        } else {
            ok(0)
        };
        steps.push(op(Operation::Disable, reply, vec![]));
        steps.push(op(Operation::Close, reply, vec![]));
        let order = expected(&steps, true);
        let mut script = Script::new(steps);
        let seen = Rc::clone(&script.seen);
        let outcome: Result<ProbeObservation<()>, _> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(&mut script, EXTERNAL, || {
                    seen.borrow_mut().push(Seen::Invoke);
                    panic!("scripted invocation unwind");
                })
            }));
        assert!(outcome.is_err());
        script.finish(&order);
    }
}

#[test]
fn disabled_flight_drop_only_closes_and_fd_zero_is_still_owned() {
    let steps = vec![closed()];
    let order = expected(&steps, false);
    let mut script = Script::new(steps);
    {
        let _flight = Flight {
            system: &mut script,
            fd: Some(FD),
            enabled: false,
        };
    }
    script.finish(&order);

    let mut steps = success([7, 10, 10]);
    steps[1] = Step::Open {
        reply: ok(0),
        write_size: None,
    };
    for step in &mut steps {
        if let Step::Op { fd, .. } = step {
            *fd = 0;
        }
    }
    let observed = exercise(steps, true);
    assert_eq!(row(&observed.receipt, Operation::Open).syscall, ok(0));
    assert!(observed.receipt.issues.is_empty());
    assert!(observed.receipt.full_running_delta.is_some());
}
