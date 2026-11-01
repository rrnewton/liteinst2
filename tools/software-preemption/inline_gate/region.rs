//! Two-site sibling oracle. Reuses the unchanged architectural comparator and
//! bounded ptrace owner; every child constructs and leases its own clock.
use super::*;
use crate::region_clock::{CODE, HEADS, RegionProgram, SITES};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RegionReady {
    native: u64,
    source: u64,
    clock: u64,
    image: u64,
    image_len: u64,
    routes: [u64; 9],
    bodies: [u64; 9],
    // entry, zero-before-save, restored-original-body for each source key.
    gates: [[u64; 3]; 2],
}
struct RegionSpawned {
    child: Tracee,
    read_pipe: OwnedFd,
}

impl Tracee {
    fn spawn_region(mode: ClockMode, quantum: u64) -> RegionSpawned {
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: fresh pipe descriptors each acquire exactly one owner.
        let read_pipe = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let write_pipe = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        // Both siblings fork before the parent allocates capture/decoder state.
        // No parent clock/control/lease crosses this boundary.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(read_pipe);
            let _ = std::panic::catch_unwind(|| {
                let program = RegionProgram::new(mode);
                let lease = unsafe { program.clock.acquire(quantum, 15) }.unwrap();
                let call = lease.begin_call().unwrap();
                let ready = RegionReady {
                    native: program.native,
                    source: program.source,
                    clock: program.clock.address(),
                    image: program.image,
                    image_len: program.image_len as u64,
                    routes: program.routes,
                    bodies: program.bodies,
                    gates: program
                        .gates
                        .map(|g| [g.gate.entry, g.gate.observing_entry, g.gate.original_body]),
                };
                // One fixed PIPE_BUF-sized handoff; no callable pointer escapes
                // to a running process. The tracer starts at the sole entry.
                unsafe {
                    if libc::write(
                        write_pipe.as_raw_fd(),
                        (&raw const ready).cast(),
                        std::mem::size_of::<RegionReady>(),
                    ) != std::mem::size_of::<RegionReady>() as isize
                    {
                        libc::_exit(120);
                    }
                    drop(write_pipe);
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, 0usize, 0usize) == -1 {
                        libc::_exit(120);
                    }
                    libc::kill(libc::getpid(), libc::SIGSTOP);
                    std::hint::black_box((&program, &lease, &call));
                    libc::_exit(121);
                }
            });
            // Never unwind through inherited parent child/pipe owners.
            unsafe { libc::_exit(120) }
        }
        drop(write_pipe);
        RegionSpawned {
            child: Self {
                pid,
                deadline: Instant::now() + CHILD_BUDGET,
                reaped: Cell::new(false),
            },
            read_pipe,
        }
    }
}
impl RegionSpawned {
    fn ready(self) -> (Tracee, RegionReady) {
        let Self { child, read_pipe } = self;
        let status = child.wait();
        assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
        let mut ready = RegionReady::default();
        let n = unsafe {
            libc::read(
                read_pipe.as_raw_fd(),
                (&raw mut ready).cast(),
                std::mem::size_of::<RegionReady>(),
            )
        };
        drop(read_pipe);
        assert_eq!(n, std::mem::size_of::<RegionReady>() as isize);
        child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        assert!(ready.image_len > 0 && ready.image_len <= 8192);
        assert_eq!(ready.routes[0], ready.image);
        for i in 0..HEADS.len() {
            assert!(ready.image <= ready.routes[i] && ready.routes[i] <= ready.bodies[i]);
            assert!(ready.bodies[i] < ready.image + ready.image_len);
            if i + 1 < HEADS.len() {
                assert!(ready.bodies[i] < ready.routes[i + 1]);
            }
            if let Some(site) = SITES.iter().position(|&offset| offset == HEADS[i]) {
                assert_eq!(ready.gates[site][0], ready.routes[i]);
                assert_eq!(ready.gates[site][2], ready.bodies[i]);
                assert!(
                    ready.gates[site][0] < ready.gates[site][1]
                        && ready.gates[site][1] < ready.gates[site][2]
                );
            } else {
                assert_eq!(ready.routes[i], ready.bodies[i]);
            }
        }
        assert_eq!(child.memory(ready.native, CODE.len()), CODE);
        (child, ready)
    }
}

fn advance(child: &Tracee, ready: &RegionReady, target: u64, forbidden: u64, steps: &mut usize) {
    while child.registers().rip != target {
        let pc = child.registers().rip;
        assert_ne!(pc, forbidden, "wrong fast/slow region boundary");
        assert!(
            pc == ready.source || (ready.image..ready.image + ready.image_len).contains(&pc),
            "region prefix escaped owned source/image"
        );
        assert!(*steps < MAX_STEPS, "unchanged instruction budget exhausted");
        child.step(&[]);
        *steps += 1;
    }
}

// Independently authored dynamic original-head sequence. Both near branches
// execute four/one times per outer iteration; all three outer iterations run.
fn visits() -> Vec<u64> {
    let mut result = vec![0, 5];
    for _ in 0..3 {
        result.push(11);
        for _ in 0..4 {
            result.extend([16, 18, 20]);
        }
        result.extend([26, 29]);
    }
    result.push(35);
    assert_eq!(result.len(), 48);
    result
}

fn pair(mode: ClockMode, quantum: u64, seed: u64) -> usize {
    single_main();
    let arena = Arena::new(seed);
    let original = Tracee::spawn_region(mode, quantum);
    let candidate = Tracee::spawn_region(mode, quantum);
    let (original, first) = original.ready();
    let (candidate, second) = candidate.ready();
    assert_eq!(first, second, "exact pristine sibling address geometry");
    let mut regs = original.registers();
    regs.rax = 0x1234_5678_9abc_0000 | seed;
    regs.rbx = 0x1122_3344_5566_0000 | seed;
    regs.rcx = 0x9988_7766_5544_0000 | seed;
    regs.rdx = 0x8877_6655_4433_0000 | seed;
    regs.rsi = arena.data + 64;
    regs.rdi = arena.data;
    regs.rbp = arena.stack + 512;
    regs.r8 = 0x101 + seed;
    regs.r9 = 0x202 + seed;
    regs.r10 = 0x303 + seed;
    regs.r11 = 0x404 + seed;
    regs.r12 = 0x505 + seed;
    regs.r13 = 0x606 + seed;
    regs.r14 = 0x707 + seed;
    regs.r15 = 0x808 + seed;
    // SysV function-entry alignment, even though this prefix/full-counter
    // oracle ends at a pre-save or final-RET boundary rather than calling Rust.
    regs.rsp = arena.stack + STACK_BYTES as u64 - 264;
    regs.orig_rax = u64::MAX;
    regs.eflags = 0x202 | ((seed & 1) * 0x8d5);
    regs.rip = first.native;
    let xstate = seeded_xstate(original.xstate(), seed);
    original.set_registers(&regs);
    original.set_xstate(&xstate);
    regs.rip = second.source;
    candidate.set_registers(&regs);
    candidate.set_xstate(&xstate);
    let source = candidate.memory(second.source, CODE.len());
    let image = candidate.memory(second.image, second.image_len as usize);
    assert_eq!(source, original.memory(first.source, CODE.len()));
    assert_eq!(
        image,
        original.memory(first.image, first.image_len as usize)
    );
    let initial_clock: Vec<_> = [0, 0, 0, quantum]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .chain([CLOCK_CANARY; 4064])
        .collect();
    assert_eq!(candidate.memory(second.clock, PAGE), initial_clock);
    let mut steps = 0;
    let mut comparisons = 0;
    let mut encounters = 0;
    let mut counted = 0;
    let mut gate_visits = [0, 0];
    let mut stopped = None;
    for offset in visits() {
        let head = HEADS.iter().position(|&h| h == offset).unwrap();
        assert_eq!(original.registers().rip, first.native + offset);
        let expected = snapshot(&original, &arena, first.native + offset);
        advance(&candidate, &second, second.routes[head], 0, &mut steps);
        assert_state(
            &expected,
            &snapshot(&candidate, &arena, first.native + offset),
        );
        comparisons += 1;
        if let Some(site) = SITES.iter().position(|&h| h == offset) {
            gate_visits[site] += 1;
            encounters += 1;
            let taken = if site == 0 {
                expected.registers.rcx != 0
            } else {
                expected.registers.r8 != 0
            };
            assert_eq!(expected.registers.eflags & (1 << 6) == 0, taken);
            counted += u64::from(taken);
            let zero = mode == ClockMode::Stop && taken && counted == quantum;
            let (boundary, forbidden) = if zero {
                (second.gates[site][1], second.gates[site][2])
            } else {
                (second.gates[site][2], second.gates[site][1])
            };
            advance(&candidate, &second, boundary, forbidden, &mut steps);
            assert_state(
                &expected,
                &snapshot(&candidate, &arena, first.native + offset),
            );
            comparisons += 1;
            let remaining = if mode == ClockMode::Counter {
                quantum
            } else {
                quantum - counted
            };
            let clock: Vec<_> = [expected.registers.rcx, encounters, counted, remaining]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .chain([CLOCK_CANARY; 4064])
                .collect();
            assert_eq!(candidate.memory(second.clock, PAGE), clock);
            if zero {
                stopped = Some((offset, encounters, counted));
            }
        }
        assert_eq!(candidate.memory(second.source, source.len()), source);
        assert_eq!(candidate.memory(second.image, image.len()), image);
        assert_eq!(original.memory(first.native, CODE.len()), CODE);
        if stopped.is_some() {
            break;
        }
        assert_eq!(candidate.registers().rip, second.bodies[head]);
        if offset == 35 {
            // End at the final RET boundary: the independent same-process
            // stop cohort separately requires the actual return value 12.
            assert_eq!(
                (
                    expected.registers.rax,
                    expected.registers.rcx,
                    expected.registers.r8
                ),
                (12, 0, 0)
            );
            break;
        }
        original.step(&[]);
        candidate.step(&[]);
        steps += 2;
        assert!(steps <= MAX_STEPS);
    }
    match (mode, quantum) {
        (ClockMode::Counter, 2) => {
            assert_eq!(stopped, None);
            assert_eq!(
                (encounters, counted, gate_visits, comparisons),
                (15, 11, [12, 3], 63)
            );
        }
        (ClockMode::Stop, 2) => {
            assert_eq!(stopped, Some((20, 2, 2)));
            assert_eq!((gate_visits, comparisons), ([2, 0], 11));
        }
        (ClockMode::Stop, 4) => {
            assert_eq!(stopped, Some((29, 5, 4)));
            assert_eq!((gate_visits, comparisons), ([4, 1], 22));
        }
        _ => unreachable!("fixed oracle cohort"),
    }
    original.finish();
    candidate.finish();
    comparisons
}

pub(super) fn qualify(output: &Path) {
    let mut rows = String::from("mode,quantum,seed,full_state_comparisons,status\n");
    let mut comparisons = 0;
    let mut pairs = 0;
    for seed in [7, 42] {
        for (mode, quantum, label) in [
            (ClockMode::Counter, 2, "counter-whole-trace"),
            (ClockMode::Stop, 2, "inner-zero-before-save"),
            (ClockMode::Stop, 4, "outer-zero-before-save"),
        ] {
            let count = pair(mode, quantum, seed);
            comparisons += count;
            pairs += 1;
            rows.push_str(&format!("{label},{quantum},{seed},{count},PASS\n"));
        }
    }
    assert_eq!((pairs, comparisons), (6, 192));
    std::fs::write(output.join("region-gates.csv"), rows).unwrap();
    println!("preemption:region-gates:6-pairs:12-children:192-full-state-comparisons");
}
