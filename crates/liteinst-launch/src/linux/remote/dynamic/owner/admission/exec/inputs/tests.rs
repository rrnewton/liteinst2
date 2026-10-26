//! Synthetic byte-reader controls only. They provide no ptrace, native exec,
//! source completeness, exclusion, kernel-copy or physical-cleanup evidence.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::selected::{SyscallAliases, decode};
use std::cell::RefCell;
use std::time::Duration;

const BASE: u64 = 0x1000;
const ARGV: u64 = 0x1100;
const ENVP: u64 = 0x1180;
const ARG: u64 = 0x1200;
const ENV: u64 = 0x1280;
const PC: u64 = 0x401000;

fn profile(p: usize, s: usize) -> DynamicExecProfile {
    DynamicExecProfile {
        max_capture_images: 1,
        max_capture_bytes: 4096,
        max_total_capture_bytes: 4096,
        max_argument_pointers: p,
        max_string_bytes: s,
    }
}

fn registers() -> RegisterSnapshot {
    RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 11,
        rbx: 10,
        r11: 9,
        r10: 8,
        r9: 7,
        r8: 6,
        rax: libc::SYS_execve as u64,
        rcx: 4,
        rdx: ENVP,
        rsi: ARGV,
        rdi: BASE,
        orig_rax: u64::MAX,
        rip: PC,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x2f00,
        ss: 0x2b,
        fs_base: 0x3500,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

fn selected(registers: RegisterSnapshot) -> SelectedInput {
    SelectedInput::new(
        decode(PC, &[0x0f, 0x05], &SyscallAliases::new()).unwrap(),
        registers,
    )
    .unwrap()
}

struct Fixture {
    input: SelectedInput,
    task: DynamicTask,
    stop: DynamicStop,
    maps: Vec<MemoryMapping>,
    bytes: Vec<u8>,
    calls: RefCell<Vec<(u64, usize)>>,
    until: Instant,
}

impl Fixture {
    fn new() -> Self {
        let registry = LifecycleRegistry::new(
            crate::lifecycle::Limits {
                tasks: 2,
                processes: 2,
                address_spaces: 2,
                obligations: 8,
            },
            100,
            PC,
        )
        .unwrap();
        let record = registry.task(registry.root_task()).unwrap();
        let task = DynamicTask {
            task: record.id,
            process: record.process,
            address_space: record.address_space,
            generation: 7,
        };
        let mut f = Self {
            input: selected(registers()),
            task,
            stop: DynamicStop {
                session: 91,
                sequence: 23,
                tid: 100,
                task: Some(task.task),
            },
            maps: vec![MemoryMapping {
                start: BASE,
                end: 0x3000,
                permissions: "rw-p".into(),
                file_offset: 0,
                pathname: None,
            }],
            bytes: vec![0; 0x2000],
            calls: RefCell::new(Vec::new()),
            until: Instant::now() + Duration::from_secs(60),
        };
        f.put(BASE, b"x\0");
        f.put(ARG, b"A\0");
        f.put(ENV, b"K=V\0");
        f.put(ARGV, &ARG.to_le_bytes());
        f.put(ARGV + 8, &0u64.to_le_bytes());
        f.put(ENVP, &ENV.to_le_bytes());
        f.put(ENVP + 8, &0u64.to_le_bytes());
        f
    }
    fn put(&mut self, address: u64, bytes: &[u8]) {
        let offset = (address - BASE) as usize;
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    fn memory<'a>(&'a self, stop: &'a DynamicStop, forbidden: &'a [Range<u64>]) -> InputMemory<'a> {
        InputMemory {
            task: self.task,
            stop,
            mappings: &self.maps,
            forbidden,
            until: self.until,
        }
    }
    fn read(&self, address: u64, target: &mut [u8]) -> InputReadOutcome {
        self.calls.borrow_mut().push((address, target.len()));
        let offset = usize::try_from(address - BASE).unwrap();
        target.copy_from_slice(&self.bytes[offset..offset + target.len()]);
        InputReadOutcome {
            copied: target.len(),
            error: None,
        }
    }
    fn capture(&self, inputs: &mut ExecInputs) -> Result<(), GateError> {
        inputs.capture(&self.input, self.memory(&self.stop, &[]), |a, t| {
            self.read(a, t)
        })
    }
    fn later(&self) -> DynamicStop {
        DynamicStop {
            sequence: self.stop.sequence + 1,
            ..self.stop.clone()
        }
    }
    fn recheck(&self, inputs: &mut ExecInputs) -> Result<(), GateError> {
        inputs.recheck(&self.input, self.memory(&self.later(), &[]), |a, t| {
            self.read(a, t)
        })
    }
}

fn refusal(result: Result<(), GateError>, expected: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(reason)) if reason == expected));
}

#[test]
fn original_rw_inputs_keep_exact_pointers_bytes_and_full_inline_binding() {
    let f = Fixture::new();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    let allocated = inputs.allocated_bytes().unwrap();
    let expected = size_of::<ExecInputs>()
        + 4 * size_of::<PointerInput>()
        + 3 * size_of::<StringInput>()
        + 8
        + 4 * 8
        + 8;
    assert_eq!(allocated, expected);
    assert_eq!(
        ExecInputs::reservation_bytes(&profile(4, 8)).unwrap(),
        expected
    );
    f.capture(&mut inputs).unwrap();
    let view = inputs.view();
    assert_eq!(view.binding.unwrap().registers, *f.input.registers());
    assert_eq!(&view.binding.unwrap().instruction[..2], &[0x0f, 0x05]);
    assert_eq!(view.logical_pointer_slots, 4);
    assert_eq!(
        view.pointers
            .iter()
            .map(|r| (r.address, u64::from_le_bytes(r.initialized)))
            .collect::<Vec<_>>(),
        vec![(ARGV, ARG), (ARGV + 8, 0), (ENVP, ENV), (ENVP + 8, 0)]
    );
    assert_eq!(view.initialized_strings, b"x\0A\0K=V\0");
    assert!(view.capture_complete && !view.recheck_complete && view.failure.is_none());
    assert_eq!(view.task, Some(f.task));
    assert_eq!(view.capture_stop, Some(&f.stop));
    assert!(view.recheck_stop.is_none());
    assert!(view.pointers.iter().all(|r| r.capture
        == ReadProgress {
            attempted: true,
            reported_bytes: 8,
            complete: true
        }));
    assert!(
        view.strings
            .iter()
            .all(|r| r.terminated && r.requested_bytes == r.observed_bytes)
    );
    f.recheck(&mut inputs).unwrap();
    let view = inputs.view();
    assert!(view.capture_complete && view.recheck_complete && view.failure.is_none());
    assert_eq!(view.recheck_stop, Some(&f.later()));
    assert_eq!(view.recheck_string_offset, 32);
    assert_eq!(&view.initialized_recheck[32..], view.initialized_strings);
    assert!(
        view.pointers
            .iter()
            .all(|r| r.recheck.complete && r.recheck_equal)
    );
    assert!(
        view.strings
            .iter()
            .all(|r| r.recheck.complete && r.recheck_equal)
    );
    assert_eq!(inputs.allocated_bytes().unwrap(), allocated);
}

#[test]
fn null_vectors_and_first_nul_do_not_invent_reads_or_empty_argv_storage() {
    let mut f = Fixture::new();
    let mut r = registers();
    r.rsi = 0;
    r.rdx = 0;
    f.input = selected(r);
    f.put(BASE, b"x\0ignored");
    let mut inputs = ExecInputs::prepare(&profile(2, 2)).unwrap();
    f.capture(&mut inputs).unwrap();
    assert_eq!(*f.calls.borrow(), vec![(BASE, 1), (BASE + 1, 1)]);
    let view = inputs.view();
    assert_eq!(view.logical_pointer_slots, 2);
    assert!(view.pointers.is_empty());
    assert_eq!(view.strings.len(), 1);
    assert_eq!(view.strings[0].role, StringRole::Filename);
    assert_eq!(view.initialized_strings, b"x\0");
    assert_eq!(view.binding.unwrap().registers.rsi, 0);
    assert_eq!(view.binding.unwrap().registers.rdx, 0);
    f.recheck(&mut inputs).unwrap();
    assert_eq!(*f.calls.borrow(), vec![(BASE, 1), (BASE + 1, 1), (BASE, 2)]);
    assert_eq!(inputs.view().strings.len(), 1);
    // An empty original filename is retained; the real kernel decides ENOENT.
    let mut empty = Fixture::new();
    empty.input = selected(r);
    empty.put(BASE, b"\0after");
    let mut inputs = ExecInputs::prepare(&profile(2, 1)).unwrap();
    empty.capture(&mut inputs).unwrap();
    empty.recheck(&mut inputs).unwrap();
    assert_eq!(inputs.view().initialized_strings, b"\0");
    assert_eq!(*empty.calls.borrow(), vec![(BASE, 1), (BASE, 1)]);
}

#[test]
fn adjacent_readable_private_maps_and_ordinary_pointer_aliases_are_supported() {
    let mut f = Fixture::new();
    let mut r = registers();
    r.rsi = 0x1ffc;
    r.rdx = 0;
    f.input = selected(r);
    f.put(0x1ffc, &BASE.to_le_bytes());
    f.put(0x2004, &0u64.to_le_bytes());
    f.maps = vec![
        MemoryMapping {
            start: BASE,
            end: 0x2000,
            permissions: "r--p".into(),
            file_offset: 0,
            pathname: None,
        },
        MemoryMapping {
            start: 0x2000,
            end: 0x3000,
            permissions: "rw-p".into(),
            file_offset: 0,
            pathname: None,
        },
    ];
    let mut inputs = ExecInputs::prepare(&profile(3, 4)).unwrap();
    f.capture(&mut inputs).unwrap();
    f.recheck(&mut inputs).unwrap();
    assert_eq!(inputs.view().initialized_strings, b"x\0x\0");
    assert_eq!(inputs.view().logical_pointer_slots, 3);
    assert_eq!(inputs.view().pointers.len(), 2);
    assert!(f.calls.borrow().contains(&(0x1ffc, 8)));
    assert_eq!(inputs.view().strings[1].address, BASE);
}

#[test]
fn exact_combined_pointer_and_string_bounds_include_all_terminators() {
    let f = Fixture::new();
    let mut pointer_short = ExecInputs::prepare(&profile(3, 8)).unwrap();
    refusal(
        f.capture(&mut pointer_short),
        "exec combined pointer bound lacks required terminators",
    );
    assert_eq!(pointer_short.view().logical_pointer_slots, 3);
    assert_eq!(pointer_short.view().pointers.len(), 3);
    assert_eq!(pointer_short.view().strings.len(), 2);
    assert!(!pointer_short.view().capture_complete);
    assert!(!f.calls.borrow().iter().any(|(a, _)| *a == ENV));
    let mut string_short = ExecInputs::prepare(&profile(4, 7)).unwrap();
    refusal(
        f.capture(&mut string_short),
        "exec combined string bound lacks a terminating NUL",
    );
    assert_eq!(string_short.view().initialized_strings, b"x\0A\0K=V");
    assert_eq!(string_short.view().strings[2].observed_bytes, 3);
    assert!(!string_short.view().strings[2].terminated);
    assert!(!string_short.view().capture_complete);
    let mut exact = ExecInputs::prepare(&profile(4, 8)).unwrap();
    f.capture(&mut exact).unwrap();
    assert!(exact.view().capture_complete);
}

#[test]
fn invalid_limits_and_checked_allocation_products_refuse_before_reads() {
    for (p, s) in [
        (0, 8),
        (1, 8),
        (4097, 8),
        (usize::MAX, 8),
        (4, 0),
        (4, 65537),
        (4, usize::MAX),
    ] {
        assert!(matches!(
            ExecInputs::prepare(&profile(p, s)),
            Err(GateError::Refused("exec input limits are invalid"))
        ));
        assert!(matches!(
            ExecInputs::reservation_bytes(&profile(p, s)),
            Err(GateError::Refused("exec input limits are invalid"))
        ));
    }
    assert!(storage_bytes(usize::MAX, 1, 1, 1).is_err());
    assert!(storage_bytes(1, usize::MAX, 1, 1).is_err());
    assert!(storage_bytes(1, 1, usize::MAX, 1).is_err());
    assert!(storage_bytes(1, 1, 1, usize::MAX).is_err());
    assert!(recheck_len(usize::MAX, 1).is_err());
    assert!(recheck_len(1, usize::MAX).is_err());
    let large = ExecInputs::prepare(&profile(4096, 65536)).unwrap();
    assert_eq!(
        large.allocated_bytes().unwrap(),
        size_of::<ExecInputs>()
            + 4096 * size_of::<PointerInput>()
            + 4095 * size_of::<StringInput>()
            + 65536 * 2
            + 4096 * 8
    );
    assert!(
        large
            .view()
            .initialized_strings
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        large
            .view()
            .initialized_recheck
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn unknown_syscall_alias_x32_and_changed_full_input_binding_refuse() {
    for number in [
        libc::SYS_execveat as u64,
        libc::SYS_getpid as u64,
        (1 << 30) | libc::SYS_execve as u64,
        u64::MAX,
    ] {
        let f = Fixture::new();
        let mut r = registers();
        r.rax = number;
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        refusal(
            inputs.capture(&selected(r), f.memory(&f.stop, &[]), |a, t| f.read(a, t)),
            "exec inputs require exact native64 SYS_execve",
        );
        assert!(f.calls.borrow().is_empty());
    }
    let f = Fixture::new();
    let mut aliases = SyscallAliases::new();
    aliases.declare(PC, SyscallAbi::LinuxI386Int80).unwrap();
    let alias =
        SelectedInput::new(decode(PC, &[0xcd, 0x80], &aliases).unwrap(), registers()).unwrap();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    refusal(
        inputs.capture(&alias, f.memory(&f.stop, &[]), |a, t| f.read(a, t)),
        "exec inputs require exact native64 SYS_execve",
    );
    assert!(f.calls.borrow().is_empty());
    for field in 0..5 {
        let f = Fixture::new();
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        f.capture(&mut inputs).unwrap();
        f.calls.borrow_mut().clear();
        let mut r = registers();
        match field {
            0 => r.rdi += 1,
            1 => r.rsi += 1,
            2 => r.rdx += 1,
            3 => r.r10 ^= 1,
            4 => r.eflags ^= 1,
            _ => unreachable!(),
        }
        refusal(
            inputs.recheck(&selected(r), f.memory(&f.later(), &[]), |a, t| f.read(a, t)),
            "exec input binding changed before original ENTRY release",
        );
        assert!(f.calls.borrow().is_empty());
    }
}

#[test]
fn null_noncanonical_overflow_gap_and_nonprivate_memory_never_reach_reader() {
    for address in [0, USER_END, 0x0000_ffff_ffff_ffff, u64::MAX] {
        let f = Fixture::new();
        let mut r = registers();
        r.rdi = address;
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        assert!(
            inputs
                .capture(&selected(r), f.memory(&f.stop, &[]), |a, t| f.read(a, t))
                .is_err()
        );
        assert!(f.calls.borrow().is_empty());
        assert!(!inputs.view().capture_complete && inputs.view().failure.is_some());
    }
    for mode in ["-w-p", "r--s", "rw-s"] {
        let mut f = Fixture::new();
        f.maps[0].permissions = mode.into();
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        refusal(
            f.capture(&mut inputs),
            "exec input is not wholly private readable memory",
        );
        assert!(f.calls.borrow().is_empty());
    }
    let f = Fixture::new();
    assert!(readable(f.memory(&f.stop, &[]), u64::MAX - 3, 8).is_err());
    let mut f = Fixture::new();
    f.maps[0].start += 1;
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    refusal(
        f.capture(&mut inputs),
        "exec input is not wholly private readable memory",
    );
    assert!(f.calls.borrow().is_empty());
}

#[test]
fn source_guard_island_aliases_and_changed_reread_ranges_refuse_exact_intersections() {
    for forbidden in [
        BASE..BASE + 1,
        ARGV + 7..ARGV + 8,
        ARG..ARG + 1,
        ENV..ENV + 1,
    ] {
        let f = Fixture::new();
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        let ranges = [forbidden.clone()];
        refusal(
            inputs.capture(&f.input, f.memory(&f.stop, &ranges), |a, t| f.read(a, t)),
            "exec input aliases an instrumented or trusted interval",
        );
        assert!(
            f.calls
                .borrow()
                .iter()
                .all(|(a, n)| !(*a < forbidden.end && forbidden.start < *a + *n as u64))
        );
        assert!(!inputs.view().capture_complete);
    }
    let f = Fixture::new();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    f.capture(&mut inputs).unwrap();
    f.calls.borrow_mut().clear();
    let ranges: Vec<_> = std::iter::once(ARGV..ARGV + 8).collect();
    refusal(
        inputs.recheck(&f.input, f.memory(&f.later(), &ranges), |a, t| f.read(a, t)),
        "exec input aliases an instrumented or trusted interval",
    );
    assert!(f.calls.borrow().is_empty());
    assert!(inputs.view().capture_complete && !inputs.view().recheck_complete);
    for permission in ["-w-p", "rw-s"] {
        let mut f = Fixture::new();
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        f.capture(&mut inputs).unwrap();
        f.calls.borrow_mut().clear();
        f.maps[0].permissions = permission.into();
        refusal(
            f.recheck(&mut inputs),
            "exec input is not wholly private readable memory",
        );
        assert!(f.calls.borrow().is_empty());
        assert!(inputs.view().capture_complete && !inputs.view().recheck_complete);
    }
}

#[test]
fn stale_pointer_and_string_bytes_keep_both_observations_without_following_new_pointers() {
    for pointer in [true, false] {
        let mut f = Fixture::new();
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        f.capture(&mut inputs).unwrap();
        f.calls.borrow_mut().clear();
        let original = inputs.view().initialized_strings.to_vec();
        if pointer {
            f.put(ARGV, &0xdead_beefu64.to_le_bytes());
        } else {
            f.put(ENV, b"Z=V\0");
        }
        refusal(
            f.recheck(&mut inputs),
            if pointer {
                "exec pointer bytes changed before original ENTRY release"
            } else {
                "exec string bytes changed before original ENTRY release"
            },
        );
        let view = inputs.view();
        assert_eq!(view.initialized_strings, original);
        assert!(view.capture_complete && !view.recheck_complete && view.failure.is_some());
        assert!(!f.calls.borrow().iter().any(|(a, _)| *a == 0xdead_beef));
        if pointer {
            assert_eq!(
                &view.initialized_recheck[..8],
                &0xdead_beefu64.to_le_bytes()
            );
            assert_eq!(view.pointers[0].initialized, ARG.to_le_bytes());
            assert!(view.pointers[0].recheck.complete && !view.pointers[0].recheck_equal);
        } else {
            assert_eq!(
                &view.initialized_recheck[view.recheck_string_offset + 4..],
                b"Z=V\0"
            );
            assert!(view.strings[2].recheck.complete && !view.strings[2].recheck_equal);
        }
    }
}

#[test]
fn partial_reads_retain_initialized_prefixes_first_error_and_cannot_retry() {
    let f = Fixture::new();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    let allocated = inputs.allocated_bytes().unwrap();
    let result = inputs.capture(&f.input, f.memory(&f.stop, &[]), |address, target| {
        if address == ARGV {
            target[..4].copy_from_slice(&ARG.to_le_bytes()[..4]);
            InputReadOutcome {
                copied: 4,
                error: Some(LaunchError::System {
                    operation: "synthetic input read",
                    source: std::io::Error::from_raw_os_error(libc::EIO),
                }),
            }
        } else {
            f.read(address, target)
        }
    });
    assert!(matches!(
        result,
        Err(GateError::Control(LaunchError::System { .. }))
    ));
    let view = inputs.view();
    assert_eq!(view.pointers[0].initialized, ARG.to_le_bytes());
    assert_eq!(
        view.pointers[0].capture,
        ReadProgress {
            attempted: true,
            reported_bytes: 4,
            complete: false
        }
    );
    assert_eq!(&view.initialized_strings[..2], b"x\0");
    assert!(view.initialized_strings[2..].iter().all(|b| *b == 0));
    let first = view.failure.unwrap();
    assert!(matches!(
        first.cause,
        InputFailureCause::NativeSystem {
            errno: Some(libc::EIO),
            ..
        }
    ));
    refusal(f.capture(&mut inputs), "exec input capture is one-use");
    refusal(
        f.recheck(&mut inputs),
        "exec input recheck requires one complete unused capture",
    );
    assert_eq!(inputs.view().failure, Some(first));
    assert_eq!(inputs.allocated_bytes().unwrap(), allocated);

    let f = Fixture::new();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    f.capture(&mut inputs).unwrap();
    let result = inputs.recheck(&f.input, f.memory(&f.later(), &[]), |address, target| {
        if address == BASE {
            target[0] = b'x';
            InputReadOutcome {
                copied: 1,
                error: None,
            }
        } else {
            f.read(address, target)
        }
    });
    refusal(
        result,
        "exec input reader did not return the exact requested bytes",
    );
    let view = inputs.view();
    assert!(view.capture_complete && !view.recheck_complete);
    assert_eq!(
        view.strings[0].recheck,
        ReadProgress {
            attempted: true,
            reported_bytes: 1,
            complete: false
        }
    );
    assert_eq!(
        &view.initialized_recheck[view.recheck_string_offset..view.recheck_string_offset + 2],
        b"x\0"
    );

    // Retain a known string prefix and the failed byte's initialized substrate.
    let f = Fixture::new();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    let result = inputs.capture(&f.input, f.memory(&f.stop, &[]), |address, target| {
        if address == BASE + 1 {
            InputReadOutcome {
                copied: 0,
                error: Some(LaunchError::Timeout("synthetic input read")),
            }
        } else {
            f.read(address, target)
        }
    });
    assert!(matches!(
        result,
        Err(GateError::Control(LaunchError::Timeout(
            "synthetic input read"
        )))
    ));
    assert_eq!(&inputs.view().initialized_strings[..2], b"x\0");
    assert_eq!(inputs.view().strings[0].requested_bytes, 2);
    assert_eq!(inputs.view().strings[0].observed_bytes, 1);
    assert_eq!(
        inputs.view().strings[0].capture,
        ReadProgress {
            attempted: true,
            reported_bytes: 0,
            complete: false
        }
    );
    assert!(!inputs.view().strings[0].terminated);

    // A reader's oversized count never certifies initialized bytes as a read.
    let f = Fixture::new();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    refusal(
        inputs.capture(&f.input, f.memory(&f.stop, &[]), |_, target| {
            InputReadOutcome {
                copied: target.len() + 1,
                error: None,
            }
        }),
        "exec input reader did not return the exact requested bytes",
    );
    assert_eq!(inputs.view().strings[0].observed_bytes, 0);
    assert_eq!(inputs.view().strings[0].capture.reported_bytes, 2);
    assert!(!inputs.view().strings[0].capture.complete);

    // The coordinator owns panic classification; this object keeps the actual
    // attempt and initialized destination without claiming an unreturned read.
    for pointer in [false, true] {
        let f = Fixture::new();
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            inputs.capture(&f.input, f.memory(&f.stop, &[]), |address, target| {
                if address == (if pointer { ARGV } else { BASE }) {
                    target[0] = 0x7f;
                    panic!("synthetic reader unwind");
                }
                f.read(address, target)
            })
        }));
        assert!(outcome.is_err());
        let view = inputs.view();
        assert!(!view.capture_complete && view.failure.is_none());
        let (progress, initialized) = if pointer {
            (view.pointers[0].capture, view.pointers[0].initialized[0])
        } else {
            (view.strings[0].capture, view.initialized_strings[0])
        };
        assert_eq!(
            progress,
            ReadProgress {
                attempted: true,
                reported_bytes: 0,
                complete: false
            }
        );
        assert_eq!(initialized, 0x7f);
    }
}

#[test]
fn changed_identity_epoch_deadline_or_task_cannot_read_replacement_memory() {
    for case in 0..7 {
        let f = Fixture::new();
        let foreign = Fixture::new();
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        f.capture(&mut inputs).unwrap();
        f.calls.borrow_mut().clear();
        let mut stop = f.later();
        let mut task = f.task;
        let mut until = f.until;
        match case {
            0 => stop.session += 1,
            1 => stop.tid += 1,
            2 => {
                task = foreign.task;
                stop.task = Some(task.task);
            }
            3 => task.generation += 1,
            4 => stop.sequence = f.stop.sequence,
            5 => until += Duration::from_secs(1),
            6 => task.address_space = foreign.task.address_space,
            _ => unreachable!(),
        }
        let memory = InputMemory {
            task,
            stop: &stop,
            mappings: &f.maps,
            forbidden: &[],
            until,
        };
        refusal(
            inputs.recheck(&f.input, memory, |a, t| f.read(a, t)),
            "exec input recheck is not the later original old-mm stop",
        );
        assert!(f.calls.borrow().is_empty());
        assert!(inputs.view().capture_complete && !inputs.view().recheck_complete);
    }
    let mut f = Fixture::new();
    f.until = Instant::now();
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    assert!(matches!(
        f.capture(&mut inputs),
        Err(GateError::Control(LaunchError::Timeout(
            "original exec input capture"
        )))
    ));
    assert!(f.calls.borrow().is_empty());
    assert!(matches!(
        inputs.view().failure.unwrap().cause,
        InputFailureCause::Timeout("original exec input capture")
    ));
}

#[test]
fn malformed_inventory_and_unterminated_inputs_preserve_refusal_prefixes() {
    for case in 0..3 {
        let mut f = Fixture::new();
        match case {
            0 => f.maps.push(f.maps[0].clone()),
            1 => f.maps[0].permissions = "rwxq".into(),
            2 => f.maps[0].end = f.maps[0].start,
            _ => unreachable!(),
        }
        let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
        refusal(
            f.capture(&mut inputs),
            "exec input mapping inventory is malformed",
        );
        assert!(f.calls.borrow().is_empty());
    }
    let mut f = Fixture::new();
    f.put(BASE, b"abcdefgh");
    let mut inputs = ExecInputs::prepare(&profile(4, 8)).unwrap();
    refusal(
        f.capture(&mut inputs),
        "exec combined string bound lacks a terminating NUL",
    );
    assert_eq!(inputs.view().initialized_strings, b"abcdefgh");
    assert_eq!(inputs.view().strings[0].observed_bytes, 8);
    assert!(!inputs.view().strings[0].terminated);
    assert!(inputs.view().pointers.is_empty());
}
