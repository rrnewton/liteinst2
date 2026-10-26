//! Additive finite dynamic-admission CPU matrix. The expected decoder and
//! register transitions below are handwritten and do not call production
//! decode/complete/native-result helpers. The initial held checkpoint is the
//! baseline for unchanged segments, kernel metadata, XSTATE and signal mask;
//! this does not independently qualify the bootstrap which produced it.
//!
//! Native timestamp, random and processor-ID values are sampled only from their
//! architectural output fields. They are not compared with another run. Native
//! random CF=0 is checked if it occurs, never required or inferred. Every native
//! row must actually complete: an unavailable-instruction signal fails the row.
use super::*;
use liteinst_admission::scan::SiteClass;

const FLAGS_SET: u64 = 0xed7;
const FLAGS_CLEAR: u64 = 0x202;
const RANDOM_FLAGS: u64 = 0x8d5;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Cpuid {
        leaf: u32,
        subleaf: u32,
    },
    Rdtsc,
    Rdtscp,
    Random {
        seed: bool,
        bits: u8,
        destination: u8,
    },
    Rdpid {
        destination: u8,
        rex_w: bool,
    },
}

#[derive(Clone, Copy, Debug)]
struct Case {
    kind: Kind,
    flags: u64,
}

#[derive(Clone, Copy, Debug)]
enum Output {
    Cpuid([u32; 4]),
    Counter { value: u64, auxiliary: Option<u32> },
    Random { value: u64, carry: bool },
    Processor(u32),
}

impl Case {
    fn class(self) -> SiteClass {
        match self.kind {
            Kind::Cpuid { .. } => SiteClass::Cpuid,
            Kind::Rdtsc => SiteClass::Rdtsc,
            Kind::Rdtscp => SiteClass::Rdtscp,
            Kind::Random { seed: false, .. } => SiteClass::Rdrand,
            Kind::Random { seed: true, .. } => SiteClass::Rdseed,
            Kind::Rdpid { .. } => SiteClass::Rdpid,
        }
    }

    fn encoding(self) -> Vec<u8> {
        let (prefix, bits, destination, extension, rex_w) = match self.kind {
            Kind::Cpuid { .. } => return vec![0x0f, 0xa2],
            Kind::Rdtsc => return vec![0x0f, 0x31],
            Kind::Rdtscp => return vec![0x0f, 0x01, 0xf9],
            Kind::Random {
                seed,
                bits,
                destination,
            } => (
                if bits == 16 { Some(0x66) } else { None },
                bits,
                destination,
                if seed { 0xf8 } else { 0xf0 },
                bits == 64,
            ),
            Kind::Rdpid { destination, rex_w } => (Some(0xf3), 32, destination, 0xf8, rex_w),
        };
        assert!(destination < 16);
        assert!(matches!(bits, 16 | 32 | 64));
        let mut bytes = Vec::new();
        if let Some(prefix) = prefix {
            bytes.push(prefix);
        }
        let rex = 0x40 | if rex_w { 8 } else { 0 } | if destination >= 8 { 1 } else { 0 };
        if rex != 0x40 {
            bytes.push(rex);
        }
        bytes.extend_from_slice(&[0x0f, 0xc7, extension | (destination & 7)]);
        bytes
    }

    fn options(self) -> DynamicAdmissionOptions {
        let covered = matches!(self.kind, Kind::Rdpid { .. })
            || matches!(self.kind, Kind::Random { bits, destination, .. } if bits != 32 || destination >= 8);
        DynamicAdmissionOptions {
            backend: if covered {
                DynamicAdmissionBackend::CoverageTrap(TrapCoverageBudget::default())
            } else {
                DynamicAdmissionBackend::StrictTrap
            },
            ..DynamicAdmissionOptions::default()
        }
    }

    fn seed(self, register: u8) -> u64 {
        if let Kind::Cpuid { leaf, subleaf } = self.kind {
            if register == 0 {
                return 0x1234_5678_0000_0000 | u64::from(leaf);
            }
            if register == 1 {
                return 0x1234_5678_0000_0000 | u64::from(subleaf);
            }
        }
        0x8877_6655_4433_2200 | u64::from(register)
    }

    fn scripted(self, carry: bool) -> Output {
        match self.kind {
            Kind::Cpuid { leaf: 0, .. } => Output::Cpuid([0x1234, 0x2345, 0x3456, 0x4567]),
            // Deliberately mask RDRAND and RDSEED feature bits. There is no
            // policy mutation and no inference that later opcodes disappear.
            Kind::Cpuid { leaf: 1, .. } => Output::Cpuid([0x123, 0x456, 0, 0x789]),
            Kind::Cpuid { .. } => Output::Cpuid([7, 0, 0x2468, 0x3579]),
            Kind::Rdtsc => Output::Counter {
                value: 0x1234_5678_abcd_ef98,
                auxiliary: None,
            },
            Kind::Rdtscp => Output::Counter {
                value: 0x7654_3210_fedc_ba98,
                auxiliary: Some(0xf1e2_d3c4),
            },
            Kind::Random { bits, .. } => Output::Random {
                value: if !carry {
                    0
                } else {
                    match bits {
                        16 => 0x9876,
                        32 => 0xfedc_9876,
                        64 => 0xfedc_ba98_7654_3210,
                        _ => panic!("unqualified width"),
                    }
                },
                carry,
            },
            Kind::Rdpid { .. } => Output::Processor(0xfedc_ba98),
        }
    }

    fn typed(self, output: Output) -> SelectedResult {
        match (self.kind, output) {
            (Kind::Cpuid { .. }, Output::Cpuid([eax, ebx, ecx, edx])) => {
                SelectedResult::Cpuid { eax, ebx, ecx, edx }
            }
            (
                Kind::Rdtsc,
                Output::Counter {
                    value,
                    auxiliary: None,
                },
            ) => SelectedResult::Rdtsc { counter: value },
            (
                Kind::Rdtscp,
                Output::Counter {
                    value,
                    auxiliary: Some(auxiliary),
                },
            ) => SelectedResult::Rdtscp {
                counter: value,
                auxiliary,
            },
            (Kind::Random { seed: false, .. }, Output::Random { value, carry }) => {
                SelectedResult::Rdrand { value, carry }
            }
            (Kind::Random { seed: true, .. }, Output::Random { value, carry }) => {
                SelectedResult::Rdseed { value, carry }
            }
            (Kind::Rdpid { .. }, Output::Processor(auxiliary)) => {
                SelectedResult::Rdpid { auxiliary }
            }
            _ => panic!("fixture output class differs"),
        }
    }
}

fn register(state: &RegisterSnapshot, register: u8) -> u64 {
    match register {
        0 => state.rax,
        1 => state.rcx,
        2 => state.rdx,
        3 => state.rbx,
        4 => state.rsp,
        5 => state.rbp,
        6 => state.rsi,
        7 => state.rdi,
        8 => state.r8,
        9 => state.r9,
        10 => state.r10,
        11 => state.r11,
        12 => state.r12,
        13 => state.r13,
        14 => state.r14,
        15 => state.r15,
        _ => panic!("fixture register is not a GPR"),
    }
}

fn write_register(state: &mut RegisterSnapshot, register: u8, value: u64) {
    let field = match register {
        0 => &mut state.rax,
        1 => &mut state.rcx,
        2 => &mut state.rdx,
        3 => &mut state.rbx,
        4 => &mut state.rsp,
        5 => &mut state.rbp,
        6 => &mut state.rsi,
        7 => &mut state.rdi,
        8 => &mut state.r8,
        9 => &mut state.r9,
        10 => &mut state.r10,
        11 => &mut state.r11,
        12 => &mut state.r12,
        13 => &mut state.r13,
        14 => &mut state.r14,
        15 => &mut state.r15,
        _ => panic!("fixture register is not a GPR"),
    };
    *field = value;
}

fn mask(bits: u8) -> u64 {
    match bits {
        16 => u64::from(u16::MAX),
        32 => u64::from(u32::MAX),
        64 => u64::MAX,
        _ => panic!("fixture width"),
    }
}

fn expected_after(case: Case, mut before: RegisterSnapshot, output: Output) -> RegisterSnapshot {
    before.rip = before
        .rip
        .checked_add(case.encoding().len() as u64)
        .unwrap();
    // Setup and the owned source guard require RF clear. No flag normalization
    // occurs in the comparison: the entire original field is compared below.
    assert_eq!(before.eflags & 0x10000, 0);
    match (case.kind, output) {
        (Kind::Cpuid { .. }, Output::Cpuid([eax, ebx, ecx, edx])) => {
            before.rax = u64::from(eax);
            before.rbx = u64::from(ebx);
            before.rcx = u64::from(ecx);
            before.rdx = u64::from(edx);
        }
        (
            Kind::Rdtsc,
            Output::Counter {
                value,
                auxiliary: None,
            },
        ) => {
            before.rax = u64::from(value as u32);
            before.rdx = value >> 32;
        }
        (
            Kind::Rdtscp,
            Output::Counter {
                value,
                auxiliary: Some(auxiliary),
            },
        ) => {
            before.rax = u64::from(value as u32);
            before.rdx = value >> 32;
            before.rcx = u64::from(auxiliary);
        }
        (
            Kind::Random {
                bits, destination, ..
            },
            Output::Random { value, carry },
        ) => {
            assert_eq!(value & !mask(bits), 0);
            if !carry {
                assert_eq!(value, 0);
            }
            let result = if bits == 16 {
                (register(&before, destination) & !0xffff) | value
            } else {
                value
            };
            write_register(&mut before, destination, result);
            before.eflags = (before.eflags & !RANDOM_FLAGS) | u64::from(carry);
        }
        (Kind::Rdpid { destination, .. }, Output::Processor(value)) => {
            write_register(&mut before, destination, u64::from(value))
        }
        _ => panic!("fixture completion class differs"),
    }
    before
}

fn native_output(case: Case, after: &RegisterSnapshot) -> Output {
    // Only defined outputs enter this value. Untouched expectations always
    // originate in the separate before snapshot and handwritten setup model.
    match case.kind {
        Kind::Cpuid { .. } => Output::Cpuid([
            u32::try_from(after.rax).unwrap(),
            u32::try_from(after.rbx).unwrap(),
            u32::try_from(after.rcx).unwrap(),
            u32::try_from(after.rdx).unwrap(),
        ]),
        Kind::Rdtsc | Kind::Rdtscp => Output::Counter {
            value: (u64::from(u32::try_from(after.rdx).unwrap()) << 32)
                | u64::from(u32::try_from(after.rax).unwrap()),
            auxiliary: if matches!(case.kind, Kind::Rdtscp) {
                Some(u32::try_from(after.rcx).unwrap())
            } else {
                None
            },
        },
        Kind::Random {
            bits, destination, ..
        } => {
            let actual = register(after, destination);
            if bits == 32 {
                assert!(actual <= u64::from(u32::MAX));
            }
            Output::Random {
                value: actual & mask(bits),
                carry: after.eflags & 1 != 0,
            }
        }
        Kind::Rdpid { destination, .. } => {
            Output::Processor(u32::try_from(register(after, destination)).unwrap())
        }
    }
}

fn setup(image: &mut Image, case: Case) {
    image.mov(4, STACK);
    for register in 0..16 {
        if register != 4 {
            image.mov(register, case.seed(register));
        }
    }
    let mut flags = vec![0x68];
    flags.extend_from_slice(&(case.flags as u32).to_le_bytes());
    image.emit(&flags);
    image.emit(&[0x9d]);
    // Even RSP starts with nonzero high halves. All following original
    // instructions avoid the stack, including after a selected RSP write.
    image.mov(4, case.seed(4));
}

fn before_state(initial: RegisterSnapshot, case: Case, pc: u64) -> RegisterSnapshot {
    let mut before = initial;
    for register in 0..16 {
        write_register(&mut before, register, case.seed(register));
    }
    before.eflags = case.flags;
    before.rip = pc;
    before.orig_rax = u64::MAX;
    before
}

#[derive(Clone)]
struct Row {
    case: Case,
    pc: u64,
    before: RegisterSnapshot,
    after: Option<RegisterSnapshot>,
    output: Option<Output>,
}

struct MatrixProvider {
    rows: Vec<Row>,
    next: usize,
}
impl InstructionProvider for MatrixProvider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let row = self
            .rows
            .get(self.next)
            .ok_or(SemanticsError::ScriptMismatch)?;
        if input.instruction().logical_pc() != row.pc
            || input.instruction().bytes() != row.case.encoding()
            || *input.registers() != row.before
        {
            return Err(SemanticsError::ScriptMismatch);
        }
        self.next += 1;
        Ok(match row.output {
            Some(output) => ProviderDecision::Complete(row.case.typed(output)),
            None => ProviderDecision::Native,
        })
    }
}

fn assert_result(
    done: &DynamicAdmissionCompletion,
    row: &Row,
    initial: &liteinst_launch::DynamicAdmissionState,
) {
    assert_eq!(done.before_task.task, initial.task.task);
    assert_eq!(done.after_task.task, initial.task.task);
    assert_eq!(done.before_task.process, initial.task.process);
    assert_eq!(done.after_task.process, initial.task.process);
    assert_eq!(done.before_task.address_space, initial.task.address_space);
    assert_eq!(done.after_task.address_space, initial.task.address_space);
    assert_eq!(done.after_task.generation, done.before_task.generation + 1);
    assert_eq!(done.selected.input.instruction().logical_pc(), row.pc);
    assert_eq!(*done.selected.input.registers(), row.before);
    assert_eq!(
        done.selected.input.instruction().bytes(),
        row.case.encoding()
    );
    let expected = row.after.unwrap_or_else(|| {
        expected_after(
            row.case,
            row.before,
            native_output(row.case, &done.selected.after),
        )
    });
    assert_eq!(
        done.selected.after, expected,
        "independent full transition: {:?}",
        row.case
    );
    assert_eq!(done.selected.before_xstate, initial.xstate);
    assert_eq!(done.selected.xstate, initial.xstate);
    assert_eq!(done.before_signal_mask, initial.signal_mask);
    assert_eq!(done.signal_mask, initial.signal_mask);
    assert_eq!(
        done.selected.execution,
        if row.output.is_some() {
            SelectedExecution::Scripted
        } else {
            SelectedExecution::Native
        }
    );
}

fn assert_initial(initial: &liteinst_launch::DynamicAdmissionState) {
    // These entry facts are independently specified even though other untouched
    // fields use this actual checkpoint as their preservation baseline.
    assert_eq!(initial.registers.rip, BASE + PAGE as u64);
    assert_eq!(initial.registers.rax, 0);
    assert_eq!(initial.registers.orig_rax, u64::MAX);
    assert_eq!(initial.registers.cs, 0x33);
}

fn run_case(
    case: Case,
    scripted: Option<Output>,
    evaluation: &mut Vec<EvaluationRow>,
) -> Option<bool> {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    setup(&mut image, case);
    let pc = image.emit(&case.encoding());
    image.spin();
    let path = image.write(&directory, "cpu-matrix");
    let mut session = launch(
        &path,
        vec![image.facts()],
        case.options(),
        MatrixProvider {
            rows: Vec::new(),
            next: 0,
        },
    );
    let pin = pin(session.pid());
    let initial = session.initial_state().clone();
    let before = before_state(initial.registers, case, pc);
    let row = Row {
        case,
        pc,
        before,
        after: scripted.map(|output| expected_after(case, before, output)),
        output: scripted,
    };
    session.provider_mut().rows.push(row.clone());
    let initial_stack = session
        .read_memory(initial.task.task, initial.registers.rsp, 256)
        .unwrap();
    let mut expected_data = session
        .read_memory(initial.task.task, DATA, 2 * PAGE)
        .unwrap();
    let flags_offset = usize::try_from(STACK - 8 - DATA).unwrap();
    expected_data[flags_offset..flags_offset + 8].copy_from_slice(&case.flags.to_le_bytes());
    let mut events = Vec::new();
    let done = completion_with_events(&mut session, &mut events);
    let data = session
        .read_memory(initial.task.task, DATA, 2 * PAGE)
        .unwrap();
    let stack = session
        .read_memory(initial.task.task, initial.registers.rsp, 256)
        .unwrap();
    let held = session.state(initial.task.task).unwrap();
    let metrics = session.metrics().unwrap();
    let calls = session.provider().next;
    cleanup(session, &pin);
    assert_initial(&initial);
    assert!(events.is_empty());
    assert_eq!(calls, 1);
    assert_result(&done, &row, &initial);
    assert_eq!(held.task, done.after_task);
    assert_eq!(held.registers, done.selected.after);
    assert_eq!(held.xstate, initial.xstate);
    assert_eq!(held.signal_mask, initial.signal_mask);
    assert_eq!(data, expected_data);
    assert_eq!(stack, initial_stack);
    assert_eq!(metrics.selected.callbacks.len(), 1);
    assert_eq!(metrics.selected.callbacks.get(&case.class()), Some(&1));
    assert_eq!(
        metrics.selected.scripted_completions,
        usize::from(scripted.is_some())
    );
    assert_eq!(
        metrics.selected.native_completions,
        usize::from(scripted.is_none())
    );
    assert_eq!(metrics.selected.provider_faults, 0);
    assert_eq!(metrics.selected.native_signals, 0);
    assert_eq!(metrics.selected.refusals, 0);
    evaluation.push(EvaluationRow::validated(RowGroup::Seeded, &row, &done));
    if matches!(case.kind, Kind::Random { .. }) {
        Some(done.selected.after.eflags & 1 != 0)
    } else {
        None
    }
}

#[test]
fn scripted_random_all_widths_all_gprs_and_both_carry_results() {
    let mut evaluation = Vec::new();
    let mut count = 0;
    for seed in [false, true] {
        for bits in [16, 32, 64] {
            for destination in 0..16 {
                for carry in [false, true] {
                    let case = Case {
                        kind: Kind::Random {
                            seed,
                            bits,
                            destination,
                        },
                        flags: FLAGS_SET,
                    };
                    assert_eq!(
                        run_case(case, Some(case.scripted(carry)), &mut evaluation),
                        Some(carry)
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 192);
    emit_evaluation(&evaluation);
}

#[test]
fn native_random_all_widths_all_gprs_preserve_exact_unrelated_state() {
    let mut evaluation = Vec::new();
    let mut carry = [0_usize; 2];
    for seed in [false, true] {
        for bits in [16, 32, 64] {
            for destination in 0..16 {
                let case = Case {
                    kind: Kind::Random {
                        seed,
                        bits,
                        destination,
                    },
                    flags: FLAGS_SET,
                };
                let actual =
                    run_case(case, None, &mut evaluation).expect("random result has a carry bit");
                carry[usize::from(actual)] += 1;
            }
        }
    }
    // Hardware is permitted to report success for every invocation. CF=0 is
    // checked whenever observed, but no success-only sample is renamed failure
    // coverage. Scripted rows above exercise both transition branches exactly.
    assert_eq!(carry[0] + carry[1], 96);
    emit_evaluation(&evaluation);
}

#[test]
fn scripted_cpuid_and_timestamp_outputs_have_exact_flags_and_extensions() {
    let mut evaluation = Vec::new();
    for flags in [FLAGS_CLEAR, FLAGS_SET] {
        for kind in [
            Kind::Cpuid {
                leaf: 0,
                subleaf: 0,
            },
            Kind::Cpuid {
                leaf: 1,
                subleaf: 0,
            },
            Kind::Cpuid {
                leaf: 7,
                subleaf: 0,
            },
            Kind::Rdtsc,
            Kind::Rdtscp,
        ] {
            let case = Case { kind, flags };
            assert_eq!(
                run_case(case, Some(case.scripted(true)), &mut evaluation),
                None
            );
        }
    }
    emit_evaluation(&evaluation);
}

#[test]
fn native_cpuid_and_timestamps_check_defined_outputs_and_every_untouched_field() {
    let mut evaluation = Vec::new();
    for flags in [FLAGS_CLEAR, FLAGS_SET] {
        for kind in [
            Kind::Cpuid {
                leaf: 0,
                subleaf: 0,
            },
            Kind::Cpuid {
                leaf: 1,
                subleaf: 0,
            },
            Kind::Cpuid {
                leaf: 7,
                subleaf: 0,
            },
            Kind::Rdtsc,
            Kind::Rdtscp,
        ] {
            assert_eq!(run_case(Case { kind, flags }, None, &mut evaluation), None);
        }
    }
    emit_evaluation(&evaluation);
}

#[test]
fn default_policy_rdpid_all_gprs_and_rex_w_forms_use_explicit_coverage() {
    let mut evaluation = Vec::new();
    let mut count = 0;
    for destination in 0..16 {
        for rex_w in [false, true] {
            for scripted in [false, true] {
                let case = Case {
                    kind: Kind::Rdpid { destination, rex_w },
                    flags: FLAGS_SET,
                };
                assert_eq!(
                    run_case(case, scripted.then(|| case.scripted(true)), &mut evaluation),
                    None
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 64);
    emit_evaluation(&evaluation);
}

#[test]
fn masked_cpuid_does_not_remove_deliberate_random_callbacks() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    let cases = [
        Case {
            kind: Kind::Cpuid {
                leaf: 1,
                subleaf: 0,
            },
            flags: FLAGS_SET,
        },
        Case {
            kind: Kind::Cpuid {
                leaf: 7,
                subleaf: 0,
            },
            flags: FLAGS_SET,
        },
        Case {
            kind: Kind::Random {
                seed: false,
                bits: 32,
                destination: 0,
            },
            flags: FLAGS_SET,
        },
        Case {
            kind: Kind::Random {
                seed: true,
                bits: 32,
                destination: 0,
            },
            flags: FLAGS_SET,
        },
    ];
    setup(&mut image, cases[0]);
    let first = image.emit(&cases[0].encoding());
    image.mov(0, cases[1].seed(0));
    image.mov(1, cases[1].seed(1));
    let second = image.emit(&cases[1].encoding());
    image.mov(0, cases[2].seed(0));
    let third = image.emit(&cases[2].encoding());
    image.mov(0, cases[3].seed(0));
    let fourth = image.emit(&cases[3].encoding());
    image.spin();
    let path = image.write(&directory, "masked-cpuid-random");
    let mut session = launch(
        &path,
        vec![image.facts()],
        DynamicAdmissionOptions::default(),
        MatrixProvider {
            rows: Vec::new(),
            next: 0,
        },
    );
    let pin = pin(session.pid());
    let initial = session.initial_state().clone();
    let initial_stack = session
        .read_memory(initial.task.task, initial.registers.rsp, 256)
        .unwrap();
    let mut expected_data = session
        .read_memory(initial.task.task, DATA, 2 * PAGE)
        .unwrap();
    let flags_offset = usize::try_from(STACK - 8 - DATA).unwrap();
    expected_data[flags_offset..flags_offset + 8].copy_from_slice(&FLAGS_SET.to_le_bytes());
    let mut rows = Vec::new();
    let mut before = before_state(initial.registers, cases[0], first);
    for (index, pc) in [first, second, third, fourth].into_iter().enumerate() {
        if index == 1 {
            before.rax = cases[1].seed(0);
            before.rcx = cases[1].seed(1);
        }
        if index >= 2 {
            before.rax = cases[index].seed(0);
        }
        before.rip = pc;
        let output = cases[index].scripted(index != 3);
        let after = expected_after(cases[index], before, output);
        rows.push(Row {
            case: cases[index],
            pc,
            before,
            after: Some(after),
            output: Some(output),
        });
        before = after;
    }
    session.provider_mut().rows = rows.clone();
    let mut completed = Vec::new();
    let mut events = Vec::new();
    for _ in 0..4 {
        completed.push(completion_with_events(&mut session, &mut events));
    }
    let data = session
        .read_memory(initial.task.task, DATA, 2 * PAGE)
        .unwrap();
    let stack = session
        .read_memory(initial.task.task, initial.registers.rsp, 256)
        .unwrap();
    let metrics = session.metrics().unwrap();
    let callbacks = session.provider().next;
    cleanup(session, &pin);
    assert_initial(&initial);
    assert!(events.is_empty());
    assert_eq!(callbacks, 4);
    for (done, row) in completed.iter().zip(&rows) {
        assert_result(done, row, &initial);
    }
    assert_eq!(completed[0].selected.after.rcx & (1 << 30), 0);
    assert_eq!(completed[1].selected.after.rbx & (1 << 18), 0);
    assert_eq!(completed[2].selected.after.rax, 0xfedc_9876);
    assert_eq!(completed[2].selected.after.eflags & 1, 1);
    assert_eq!(completed[3].selected.after.rax, 0);
    assert_eq!(completed[3].selected.after.eflags & 1, 0);
    assert_eq!(metrics.selected.callbacks.len(), 3);
    assert_eq!(metrics.selected.callbacks.get(&SiteClass::Cpuid), Some(&2));
    assert_eq!(metrics.selected.callbacks.get(&SiteClass::Rdrand), Some(&1));
    assert_eq!(metrics.selected.callbacks.get(&SiteClass::Rdseed), Some(&1));
    assert_eq!(metrics.selected.scripted_completions, 4);
    assert_eq!(metrics.selected.native_completions, 0);
    assert_eq!(metrics.selected.provider_faults, 0);
    assert_eq!(metrics.selected.native_signals, 0);
    assert_eq!(metrics.selected.refusals, 0);
    assert_eq!(data, expected_data);
    assert_eq!(stack, initial_stack);
    // This four-row batch is emitted only after the entire session, exact
    // callback inventory, all state assertions and physical cleanup pass.
    let evaluation = completed
        .iter()
        .zip(&rows)
        .enumerate()
        .map(|(index, (done, row))| {
            EvaluationRow::validated(RowGroup::MaskedChain(index), row, done)
        })
        .collect::<Vec<_>>();
    emit_evaluation(&evaluation);
}

#[derive(Clone, Copy)]
enum RowGroup {
    Seeded,
    MaskedChain(usize),
    LiteralFirst,
}

/// Constructed only after this row's complete state/memory/callback assertions
/// and the actual physical-cleanup helper succeed. Emission is further delayed
/// until the containing test's aggregate assertions have all succeeded.
struct EvaluationRow {
    case_id: String,
    class: &'static str,
    width: u8,
    destination: Option<u8>,
    input_flags: u64,
    path: &'static str,
    actual_cf: Option<u8>,
}

impl EvaluationRow {
    fn validated(group: RowGroup, row: &Row, done: &DynamicAdmissionCompletion) -> Self {
        let (class, width, destination, shape) = match row.case.kind {
            Kind::Cpuid { leaf, subleaf } => (
                "cpuid",
                32,
                None,
                format!("cpuid-leaf{leaf}-subleaf{subleaf}"),
            ),
            Kind::Rdtsc => ("rdtsc", 64, None, "rdtsc".to_owned()),
            Kind::Rdtscp => ("rdtscp", 64, None, "rdtscp".to_owned()),
            Kind::Random {
                seed,
                bits,
                destination,
            } => {
                let class = if seed { "rdseed" } else { "rdrand" };
                (
                    class,
                    bits,
                    Some(destination),
                    format!("{class}-w{bits}-gpr{destination:02}"),
                )
            }
            Kind::Rdpid { destination, rex_w } => (
                "rdpid",
                32,
                Some(destination),
                format!("rdpid-w32-gpr{destination:02}-rexw{}", u8::from(rex_w)),
            ),
        };
        let path = match done.selected.execution {
            SelectedExecution::Native => "native",
            SelectedExecution::Scripted => "scripted",
        };
        let branch = match row.output {
            Some(Output::Random { carry: false, .. }) => "cf0",
            Some(Output::Random { carry: true, .. }) => "cf1",
            Some(_) => "typed",
            None => "hardware",
        };
        let case_id = match group {
            RowGroup::Seeded => {
                format!("seeded-{shape}-{path}-{branch}-flags{:04x}", row.case.flags)
            }
            RowGroup::MaskedChain(index) => format!("masked-chain-{index}-{shape}-{path}-{branch}"),
            RowGroup::LiteralFirst => format!("first-{shape}-{path}-{branch}"),
        };
        Self {
            case_id,
            class,
            width,
            destination,
            input_flags: row.before.eflags,
            path,
            actual_cf: if matches!(row.case.kind, Kind::Random { .. }) {
                Some((done.selected.after.eflags & 1) as u8)
            } else {
                None
            },
        }
    }
}

fn emit_evaluation(rows: &[EvaluationRow]) {
    if !std::env::var("LITEINST_EVALUATION").is_ok_and(|value| value == "1") {
        return;
    }
    let number_or_null =
        |value: Option<u8>| value.map_or_else(|| "null".to_owned(), |value| value.to_string());
    for row in rows {
        // All text comes from fixed local enums/numeric case definitions.
        // No PC, PID, GPR output, memory, XSTATE, path or raw error is emitted.
        eprintln!(
            concat!(
                "LITEINST_EVALUATION_DYNAMIC_MATRIX ",
                "{{\"schema_version\":1,\"case_id\":\"{}\",\"class\":\"{}\",\"width\":{},",
                "\"destination\":{},\"input_flags\":{},\"path\":\"{}\",\"actual_cf\":{},",
                "\"completed\":1,\"cleanup\":true}}"
            ),
            row.case_id,
            row.class,
            row.width,
            number_or_null(row.destination),
            row.input_flags,
            row.path,
            number_or_null(row.actual_cf)
        );
    }
}

fn literal_first_case(kind: Kind, scripted: bool) -> EvaluationRow {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    // The selected opcode is literally the ELF entry instruction. There is no
    // original MOV, flags setup, or other ordinary instruction before it.
    let encoding = Case {
        kind,
        flags: FLAGS_CLEAR,
    }
    .encoding();
    let pc = image.emit(&encoding);
    image.spin();
    let path = image.write(&directory, "literal-first-cpu");
    let options = Case {
        kind,
        flags: FLAGS_CLEAR,
    }
    .options();
    let mut session = launch(
        &path,
        vec![image.facts()],
        options,
        MatrixProvider {
            rows: Vec::new(),
            next: 0,
        },
    );
    let pin = pin(session.pid());
    let initial = session.initial_state().clone();
    let case = Case {
        kind,
        flags: initial.registers.eflags,
    };
    let mut before = initial.registers;
    // These values are original-entry expectations, not copied from a returned
    // selected completion. Remaining fields are exact initial-state baselines.
    before.rip = BASE + PAGE as u64;
    before.rax = 0;
    before.orig_rax = u64::MAX;
    let output = scripted.then(|| case.scripted(true));
    let row = Row {
        case,
        pc,
        before,
        after: output.map(|value| expected_after(case, before, value)),
        output,
    };
    session.provider_mut().rows.push(row.clone());
    let expected_data = session
        .read_memory(initial.task.task, DATA, 2 * PAGE)
        .unwrap();
    let expected_stack = session
        .read_memory(initial.task.task, initial.registers.rsp, 256)
        .unwrap();
    let mut events = Vec::new();
    let done = completion_with_events(&mut session, &mut events);
    let data = session
        .read_memory(initial.task.task, DATA, 2 * PAGE)
        .unwrap();
    let stack = session
        .read_memory(initial.task.task, initial.registers.rsp, 256)
        .unwrap();
    let held = session.state(initial.task.task).unwrap();
    let metrics = session.metrics().unwrap();
    let callbacks = session.provider().next;
    cleanup(session, &pin);
    assert_initial(&initial);
    assert_eq!(pc, BASE + PAGE as u64);
    if let Kind::Cpuid { leaf, subleaf } = kind {
        assert_eq!(initial.registers.rax as u32, leaf);
        assert_eq!(initial.registers.rcx as u32, subleaf);
    }
    assert_eq!(row.before, initial.registers);
    assert!(events.is_empty());
    assert_eq!(callbacks, 1);
    assert_result(&done, &row, &initial);
    assert_eq!(held.task, done.after_task);
    assert_eq!(held.registers, done.selected.after);
    assert_eq!(held.xstate, initial.xstate);
    assert_eq!(held.signal_mask, initial.signal_mask);
    assert_eq!(data, expected_data);
    assert_eq!(stack, expected_stack);
    assert_eq!(metrics.selected.callbacks.len(), 1);
    assert_eq!(metrics.selected.callbacks.get(&case.class()), Some(&1));
    assert_eq!(metrics.selected.scripted_completions, usize::from(scripted));
    assert_eq!(metrics.selected.native_completions, usize::from(!scripted));
    assert_eq!(metrics.selected.provider_faults, 0);
    assert_eq!(metrics.selected.native_signals, 0);
    assert_eq!(metrics.selected.refusals, 0);
    EvaluationRow::validated(RowGroup::LiteralFirst, &row, &done)
}

#[test]
fn literal_first_cpu_instructions_complete_once_native_and_scripted() {
    let mut evaluation = Vec::new();
    for kind in [
        Kind::Cpuid {
            leaf: 0,
            subleaf: 0,
        },
        Kind::Rdtsc,
        Kind::Rdtscp,
        Kind::Random {
            seed: false,
            bits: 32,
            destination: 0,
        },
        Kind::Random {
            seed: true,
            bits: 32,
            destination: 0,
        },
        Kind::Rdpid {
            destination: 0,
            rex_w: false,
        },
    ] {
        for scripted in [false, true] {
            evaluation.push(literal_first_case(kind, scripted));
        }
    }
    assert_eq!(evaluation.len(), 12);
    emit_evaluation(&evaluation);
}
