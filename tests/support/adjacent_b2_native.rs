//! Explicit native sibling of the fixed MOV oracle. Its CLI admission is in
//! tools/elf-rewrite/examples/adjacent_b2_native.rs; this is not a hash verifier.
use super::*;
use std::collections::BTreeMap;
#[path = "adjacent_b2_fixture.rs"]
pub mod fixture;
use fixture::{ImageWitness, Request};

pub struct Input {
    pub request: Request,
    pub state: SavedExtendedStateLayout,
    pub images: [Vec<u8>; 2],
    pub elves: [Vec<u8>; 3],
}

fn copy_admitted(bytes: &[u8], path: &Path) -> Executable {
    assert_eq!(bytes.len(), fixture::FILE_BYTES);
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(path)
        .unwrap();
    writer.write_all(bytes).unwrap();
    writer.sync_all().unwrap();
    drop(writer);
    let file = File::open(path).unwrap();
    let stat = file.metadata().unwrap();
    assert_eq!(stat.mode() & 0o777, 0o500);
    assert_eq!(stat.len(), bytes.len() as u64);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    let (_, provider) = observe_provider(&file);
    Executable {
        file,
        path: path.canonicalize().unwrap(),
        bytes: bytes.to_vec(),
        loads: fixture::LOADS
            .iter()
            .map(|&(offset, address, len, flags)| Load {
                offset,
                address,
                len,
                flags,
            })
            .collect(),
        phoff: 64,
        phnum: 11,
        dev: stat.dev(),
        inode: stat.ino(),
        provider,
    }
}
fn maps(exe: &Executable, child: &Tracee, directory: &Path, phase: &str) {
    exe.maps(child, directory, phase);
    let text = std::fs::read_to_string(format!("/proc/{}/maps", child.pid)).unwrap();
    fixture::close_owners(&text, exe.inode);
    assert_eq!(
        std::fs::read(directory.join(format!("{phase}.maps"))).unwrap(),
        text.as_bytes(),
        "stopped child's mapping closure is one exact observation"
    );
}
fn exec_four(exe: &Executable, head: usize) -> Tracee {
    assert!(head < 4);
    let tasks: Vec<_> = std::fs::read_dir("/proc/self/task").unwrap().collect();
    assert_eq!(tasks.len(), 1, "standalone main-thread driver only");
    // SAFETY: gettid has no pointer argument.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(std::process::id())
    );
    let argv = [
        CString::new("adjacent-b2-native").unwrap(),
        CString::new(head.to_string()).unwrap(),
    ];
    let argv_ptrs = [argv[0].as_ptr(), argv[1].as_ptr(), std::ptr::null()];
    let env = [
        CString::new("LC_ALL=C").unwrap(),
        CString::new("PATH=/usr/bin:/bin").unwrap(),
    ];
    let env_ptrs = [env[0].as_ptr(), env[1].as_ptr(), std::ptr::null()];
    let fd = exe.file.as_raw_fd();
    // SAFETY: allocation precedes fork; child runs only these async-signal-safe calls.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: retained executable fd and argv/env arrays are live in this child.
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) != 0 {
                libc::_exit(120);
            }
            libc::fexecve(fd, argv_ptrs.as_ptr(), env_ptrs.as_ptr());
            libc::_exit(121);
        }
    }
    let child = Tracee {
        pid,
        deadline: Instant::now() + CHILD_BUDGET,
        reaped: Cell::new(false),
    };
    let status = child.wait();
    assert!(
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP,
        "kernel exec stop required"
    );
    assert_eq!(child.registers().rip, ENTRY);
    child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
    child
}
struct FixedAddress;
impl FixedAddress {
    fn address(&self) -> u64 {
        fixture::LOG
    }
}
struct Journal {
    memory: FixedAddress,
    capacity: usize,
}
impl Journal {
    // Literal body from native_interval_oracle.rs:550-569, with fixed private ownership.
    fn assert_events(&self, child: &Tracee, expected: &[HookEvent]) {
        let bytes = child.memory(self.memory.address(), PAGE);
        let word =
            |index: usize| u64::from_ne_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
        assert_eq!(word(1), 0, "hook event log overflow");
        let count = usize::try_from(word(0)).unwrap();
        assert!(count <= self.capacity, "invalid hook event count");
        let actual: Vec<_> = (0..count)
            .map(|index| HookEvent {
                probe_id: word(2 + 2 * index),
                logical_pc: word(3 + 2 * index),
            })
            .collect();
        assert_eq!(actual, expected, "hook event trace mismatch");
        assert!(
            bytes[(2 + 2 * count) * 8..].iter().all(|&byte| byte == 0),
            "hook event log wrote beyond its declared entries"
        );
    }
}
fn events(child: &Tracee, req: Request, observed: &[HookEvent]) {
    Journal {
        memory: FixedAddress,
        capacity: 2,
    }
    .assert_events(child, if req.recording { observed } else { &[] });
}
fn arrive(
    exe: &Executable,
    head: usize,
    directory: &Path,
    state: SavedExtendedStateLayout,
) -> (Tracee, usize) {
    std::fs::create_dir(directory).unwrap();
    let child = exec_four(exe, head);
    maps(exe, &child, directory, "exec");
    let boot = fixture::bootstrap();
    let mut steps = 0;
    let mut startup = Vec::new();
    while child.registers().rip != fixture::call_pc(head) {
        let pc = child.registers().rip;
        assert!((ENTRY..ENTRY + 0x80).contains(&pc));
        let instruction = boot
            .instructions
            .get(&pc)
            .expect("authored startup instruction start");
        assert_eq!(child.memory(pc, instruction.bytes.len()), instruction.bytes);
        startup.extend_from_slice(&pc.to_le_bytes());
        step(&child, &mut steps);
        assert!(
            instruction.next.contains(&child.registers().rip),
            "startup transition"
        );
    }
    write_new(&directory.join("startup-pcs.bin"), &startup);
    assert_eq!(child.registers().rsp, CALLER_RSP);
    assert_eq!(
        (child.registers().fs_base, child.registers().gs_base),
        (0, 0)
    );
    let mut loaded = Vec::new();
    for load in &exe.loads {
        for address in (load.address..page_end(load.address + load.len)).step_by(PAGE) {
            let bytes = child.memory(address, PAGE);
            assert_eq!(bytes, exe.page(load, address));
            loaded.extend_from_slice(&bytes);
        }
    }
    assert_eq!(loaded.len(), fixture::FILE_BYTES);
    write_new(&directory.join("loaded.bin"), &loaded);
    assert_eq!(
        target(),
        state,
        "runtime target must match frozen producer manifest"
    );
    let xstate = child.xstate();
    assert!(xstate.len() as u64 >= state.image_len());
    for c in state.components() {
        assert!(components(&xstate).contains(&(
            c.xfeature().trailing_zeros(),
            c.offset() as usize,
            c.size() as usize
        )));
    }
    (child, steps)
}
/// Sole pre-CALL seed transaction. No setters are called after this function.
fn seed_scenario(child: &Tracee, seed: u64, zf: bool) -> (libc::user_regs_struct, Vec<u8>) {
    let mut initial = child.registers();
    let rip = initial.rip;
    let mut state = seed;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    initial.rax = next();
    initial.rbx = next();
    initial.rcx = next();
    initial.rdx = next();
    initial.rbp = next();
    initial.rsi = DATA + 512;
    initial.rdi = DATA + 256;
    initial.r8 = next();
    initial.r9 = next();
    initial.r10 = next();
    initial.r11 = next();
    initial.r12 = next();
    initial.r13 = next();
    initial.r14 = next();
    initial.r15 = next();
    initial.orig_rax = u64::MAX;
    initial.eflags = fixture::flags(seed, zf);
    assert_eq!(initial.rsp, CALLER_RSP);
    assert_eq!(initial.rip, rip);
    let xstate = seeded_xstate(child.xstate(), seed);
    child.set_registers(&initial);
    child.set_xstate(&xstate);
    let actual = child.registers();
    assert_eq!(
        actual.eflags & !DEBUGGER_FLAGS,
        initial.eflags & !DEBUGGER_FLAGS
    );
    assert_eq!(actual.rip, rip);
    assert_eq!(actual.rsp, CALLER_RSP);
    let actual_xstate = child.xstate();
    // Seed readback is a register/XSAVE transaction. Boundary snapshots below
    // still use the unchanged full data and application-stack coverage.
    let intended = Snapshot {
        logical_pc: rip,
        registers: initial,
        xstate: canonical_xstate(&xstate),
        data: Vec::new(),
        application_stack: Vec::new(),
    };
    let observed = Snapshot {
        logical_pc: rip,
        registers: actual,
        xstate: canonical_xstate(&actual_xstate),
        data: Vec::new(),
        application_stack: Vec::new(),
    };
    assert_state(&intended, &observed);
    (actual, actual_xstate)
}
fn save_snapshot(bytes: &mut Vec<u8>, s: &Snapshot) {
    let r = &s.registers;
    let regs = [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ];
    bytes.extend_from_slice(&s.logical_pc.to_le_bytes());
    for n in [
        regs.len() * 8,
        s.xstate.len(),
        s.data.len(),
        s.application_stack.len(),
    ] {
        bytes.extend_from_slice(&(n as u64).to_le_bytes());
    }
    for r in regs {
        bytes.extend_from_slice(&r.to_le_bytes());
    }
    bytes.extend_from_slice(&s.xstate);
    bytes.extend_from_slice(&s.data);
    bytes.extend_from_slice(&s.application_stack);
    assert!(
        bytes.len() <= fixture::LIMIT,
        "bounded complete state capture"
    );
}
struct Baseline {
    before: Snapshot,
    after: Snapshot,
    points: Vec<Snapshot>,
    xstate: Vec<u8>,
}
fn copy_snapshot(s: &Snapshot) -> Snapshot {
    Snapshot {
        logical_pc: s.logical_pc,
        registers: s.registers,
        xstate: s.xstate.clone(),
        data: s.data.clone(),
        application_stack: s.application_stack.clone(),
    }
}
fn state_controls(s: &Snapshot, directory: &Path) {
    assert_state(s, s); // A real pristine native state is the positive control.
    let mut report = String::from("LI2ADJSTATECONTROLS\t2\npositive_actual_snapshot\ttrue\n");
    let mut reject = |name: &str, bad: Snapshot| {
        fixture::expect_refusal(&format!("state mutant {name}"), || assert_state(s, &bad));
        report.push_str(&format!("rejected\t{name}\n"));
    };
    type RegisterMutation = (&'static str, fn(&mut libc::user_regs_struct));
    let registers: &[RegisterMutation] = &[
        ("rax", |r| r.rax ^= 1),
        ("rbx", |r| r.rbx ^= 1),
        ("rcx", |r| r.rcx ^= 1),
        ("rdx", |r| r.rdx ^= 1),
        ("rsi", |r| r.rsi ^= 1),
        ("rdi", |r| r.rdi ^= 1),
        ("rbp", |r| r.rbp ^= 1),
        ("rsp", |r| r.rsp ^= 1),
        ("r8", |r| r.r8 ^= 1),
        ("r9", |r| r.r9 ^= 1),
        ("r10", |r| r.r10 ^= 1),
        ("r11", |r| r.r11 ^= 1),
        ("r12", |r| r.r12 ^= 1),
        ("r13", |r| r.r13 ^= 1),
        ("r14", |r| r.r14 ^= 1),
        ("r15", |r| r.r15 ^= 1),
        ("orig_rax", |r| r.orig_rax ^= 1),
        ("cs", |r| r.cs ^= 1),
        ("ss", |r| r.ss ^= 1),
        ("ds", |r| r.ds ^= 1),
        ("es", |r| r.es ^= 1),
        ("fs", |r| r.fs ^= 1),
        ("gs", |r| r.gs ^= 1),
        ("fs_base", |r| r.fs_base ^= 1),
        ("gs_base", |r| r.gs_base ^= 1),
    ];
    for &(name, mutate) in registers {
        let mut bad = copy_snapshot(s);
        mutate(&mut bad.registers);
        reject(name, bad);
    }
    for bit in 0..64 {
        if DEBUGGER_FLAGS & (1_u64 << bit) != 0 {
            continue;
        }
        let mut bad = copy_snapshot(s);
        bad.registers.eflags ^= 1_u64 << bit;
        reject(&format!("rflags-{bit}"), bad);
    }
    let mut bad = copy_snapshot(s);
    bad.logical_pc ^= 1;
    reject("logical-pc", bad);
    let mut bad = copy_snapshot(s);
    bad.xstate[0] ^= 1;
    reject("architectural-xstate", bad);
    let mut bad = copy_snapshot(s);
    bad.data[PAGE - 1] ^= 1;
    reject("last-data-byte", bad);
    let mut bad = copy_snapshot(s);
    bad.application_stack[0] ^= 1;
    reject("redzone-first-byte", bad);
    let mut bad = copy_snapshot(s);
    *bad.application_stack.last_mut().unwrap() ^= 1;
    reject("stack-last-byte", bad);
    report.push_str("mutation_location\tparent_owned_captured_state_only\nEND\n");
    write_new(&directory.join("state-controls.tsv"), report.as_bytes());
}
fn immutable_controls(exe: &Executable, child: &Tracee, directory: &Path) {
    exe.immutable(child);
    let mut report = String::from("LI2ADJIMMUTABLECONTROLS\t2\npositive_actual_pages\ttrue\n");
    for load in exe.loads.iter().filter(|l| l.flags & 2 == 0) {
        let mut bytes = exe.bytes.clone();
        bytes[load.offset as usize + PAGE - 1] ^= 1;
        let mutant = Executable {
            file: exe.file.try_clone().unwrap(),
            path: exe.path.clone(),
            bytes,
            loads: exe.loads.clone(),
            phoff: exe.phoff,
            phnum: exe.phnum,
            dev: exe.dev,
            inode: exe.inode,
            provider: exe.provider.clone(),
        };
        fixture::expect_refusal("immutable-page mutant", || mutant.immutable(child));
        report.push_str(&format!("rejected_page\t{}\n", load.address));
    }
    report.push_str("mutation_location\tparent_expected_page_only\nEND\n");
    write_new(&directory.join("immutable-controls.tsv"), report.as_bytes());
}
fn subject_call(
    exe: &Executable,
    child: &Tracee,
    steps: &mut usize,
    head: usize,
) -> (Snapshot, Snapshot) {
    let pc = fixture::call_pc(head);
    assert_eq!(child.registers().rip, pc);
    assert_eq!(
        child.memory(pc, 5),
        fixture::transfer(0xe8, pc, fixture::HEADS[head])
    );
    assert_eq!(child.memory(CALLER_RSP - 8, 8), [0x5a; 8]);
    let before = snapshot(exe, child, pc);
    step(child, steps);
    assert_eq!(child.registers().rip, fixture::HEADS[head]);
    assert_eq!(child.registers().rsp, CALLER_RSP - 8);
    assert_eq!(child.memory(CALLER_RSP - 8, 8), (pc + 5).to_le_bytes());
    (before, snapshot(exe, child, fixture::HEADS[head]))
}
fn finish(
    exe: &Executable,
    child: &Tracee,
    steps: usize,
    head: usize,
    directory: &Path,
    captures: &[u8],
    calls: usize,
) {
    assert_eq!(child.registers().rip, fixture::call_pc(head) + 5);
    assert_eq!(child.registers().rsp, CALLER_RSP);
    assert_eq!(
        child.memory(CALLER_RSP - 8, 8),
        (fixture::call_pc(head) + 5).to_le_bytes()
    );
    maps(exe, child, directory, "terminal");
    exe.unchanged();
    write_new(&directory.join("states.bin"), captures);
    write_new(
        &directory.join("journal.bin"),
        &child.memory(fixture::LOG, PAGE),
    );
    // SAFETY: exact still-owned tracee; unchanged Tracee Drop also handles every failure.
    assert_eq!(unsafe { libc::kill(child.pid, libc::SIGKILL) }, 0);
    let status = child.wait();
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL && child.reaped.get()
    );
    write_new(&directory.join("result.tsv"), format!("LI2ADJTRACE\t2\nsteps\t{steps}\nhook_calls_and_returns\t{calls}\nowned_child_reaped\ttrue\nlive_retirement\tNOT_COVERED\nstatus\tpassed\n").as_bytes());
}
fn original(
    exe: &Executable,
    req: Request,
    state: SavedExtendedStateLayout,
    head: usize,
    seed: u64,
    zf: bool,
    directory: &Path,
) -> Baseline {
    let (child, mut steps) = arrive(exe, head, directory, state);
    let calibrate = head == 0 && seed == fixture::SEEDS[0] && !zf;
    if calibrate {
        immutable_controls(exe, &child, directory);
    }
    let (_, xstate) = seed_scenario(&child, seed, zf);
    let (before, after) = subject_call(exe, &child, &mut steps, head);
    let visits = req.visits(head, zf);
    let mut points = Vec::new();
    let mut captures = Vec::new();
    save_snapshot(&mut captures, &before);
    save_snapshot(&mut captures, &after);
    for (i, &logical) in visits.iter().enumerate() {
        assert_eq!(child.registers().rip, logical, "authored pristine walk");
        events(&child, req, &[]);
        if logical == fixture::B || logical == fixture::B + 2 {
            assert_eq!((child.registers().eflags >> 6) & 1, u64::from(zf));
        }
        let s = snapshot(exe, &child, logical);
        save_snapshot(&mut captures, &s);
        points.push(s);
        if i + 1 != visits.len() {
            step(&child, &mut steps);
        }
    }
    if calibrate {
        state_controls(&points[0], directory);
    }
    finish(exe, &child, steps, head, directory, &captures, 0);
    Baseline {
        before,
        after,
        points,
        xstate,
    }
}
struct HookCapture<'a> {
    seeded: &'a [u8],
    state: SavedExtendedStateLayout,
    directory: &'a Path,
    ordinal: usize,
}
fn hook_context(
    exe: &Executable,
    child: &Tracee,
    expected: &Snapshot,
    image: &ImageWitness,
    capture: HookCapture<'_>,
) {
    let HookCapture {
        seeded,
        state,
        directory,
        ordinal,
    } = capture;
    exe.immutable(child);
    let registers = child.registers();
    assert_eq!(registers.rip, fixture::HOOK);
    assert_eq!(registers.rsp % 16, 8);
    assert!(registers.rsp >= STACK && registers.rsp + 8 <= CALLER_RSP - 8 - 128);
    assert_eq!(word(&child.memory(registers.rsp, 8), 0), image.returned);
    assert!(registers.rdi >= STACK && registers.rdi + 176 <= CALLER_RSP - 8 - 128);
    let context = child.memory(registers.rdi, 176);
    let r = &expected.registers;
    let words = [
        expected.logical_pc,
        r.rsp,
        r.r15,
        r.r14,
        r.r13,
        r.r12,
        r.r11,
        r.r10,
        r.r9,
        r.r8,
        r.rdi,
        r.rsi,
        r.rbp,
        r.rbx,
        r.rdx,
        r.rcx,
        r.rax,
    ];
    for (i, value) in words.iter().enumerate() {
        assert_eq!(word(&context, i * 8), *value);
    }
    assert_eq!(
        word(&context, 136) & !DEBUGGER_FLAGS,
        r.eflags & !DEBUGGER_FLAGS
    );
    let address = word(&context, 144);
    assert_eq!(address % 64, 0);
    assert_eq!(
        (
            word(&context, 152),
            word(&context, 160),
            word(&context, 168)
        ),
        (state.len(), state.mask(), state.format().raw())
    );
    assert!(address >= STACK && address + state.len() <= registers.rdi);
    let image = child.memory(address, state.len() as usize);
    let image_len = state.image_len() as usize;
    assert!(seeded.len() >= image_len);
    assert_eq!(
        canonical_xstate(&image[..image_len]),
        canonical_xstate(&seeded[..image_len])
    );
    let mut capture = context;
    capture.extend_from_slice(&image);
    write_new(&directory.join(format!("hook-{ordinal}.bin")), &capture);
}
#[derive(Clone, Copy)]
struct Scenario {
    head: usize,
    seed: u64,
    zf: bool,
}
fn compare(
    exe: &Executable,
    input: &Input,
    baseline: &Baseline,
    phase: usize,
    scenario: Scenario,
    directory: &Path,
) -> usize {
    let Scenario { head, seed, zf } = scenario;
    let req = input.request;
    let installed = phase == 1;
    let images = [
        fixture::image_witness(req, input.state, true),
        fixture::image_witness(req, input.state, false),
    ];
    let hook = fixture::hook(req.recording);
    let (child, mut steps) = arrive(exe, head, directory, input.state);
    let (_, xstate) = seed_scenario(&child, seed, zf);
    assert_eq!(
        canonical_xstate(&xstate),
        canonical_xstate(&baseline.xstate)
    );
    let (before, after) = subject_call(exe, &child, &mut steps, head);
    assert_state(&baseline.before, &before);
    assert_state(&baseline.after, &after);
    let mut captures = Vec::new();
    save_snapshot(&mut captures, &before);
    save_snapshot(&mut captures, &after);
    let mut observed = Vec::<HookEvent>::new();
    let mut boundaries = BTreeMap::new();
    for &pc in &fixture::HEADS {
        if !installed || pc >= fixture::B + 4 {
            assert!(boundaries.insert(pc, pc).is_none());
        }
    }
    if installed {
        for image in &images {
            assert!(boundaries.insert(image.body, image.logical).is_none());
        }
    }
    assert!(
        boundaries
            .insert(fixture::call_pc(head) + 5, fixture::call_pc(head) + 5)
            .is_none()
    );
    for (index, expected) in baseline.points.iter().enumerate() {
        while !boundaries.contains_key(&child.registers().rip) {
            assert!(
                installed,
                "source-restored execution may not enter retained images"
            );
            let pc = child.registers().rip;
            if pc == fixture::B || pc == fixture::B + 2 {
                assert_eq!(pc, expected.logical_pc, "unexpected source gateway");
                let target = if pc == fixture::B {
                    fixture::LOWER
                } else {
                    fixture::UPPER
                };
                assert_eq!(child.memory(pc, 5), fixture::transfer(0xe9, pc, target));
                exe.immutable(&child);
                step(&child, &mut steps);
                assert_eq!(child.registers().rip, target);
                continue;
            }
            let image = images
                .iter()
                .find(|i| i.code.instructions.contains_key(&pc))
                .expect("unexpected executable PC owner");
            let insn = &image.code.instructions[&pc];
            assert_eq!(child.memory(pc, insn.bytes.len()), insn.bytes);
            if pc == image.call {
                assert_eq!(image.logical, expected.logical_pc);
                assert!(observed.len() < 2);
                assert!(
                    !observed.iter().any(|e| e.logical_pc == image.logical),
                    "extra callback"
                );
                events(&child, req, &observed);
                exe.immutable(&child);
                let rsp = child.registers().rsp;
                step(&child, &mut steps);
                assert_eq!(child.registers().rip, fixture::HOOK);
                assert_eq!(child.registers().rsp, rsp - 8);
                assert_eq!(word(&child.memory(rsp - 8, 8), 0), image.returned);
                hook_context(
                    exe,
                    &child,
                    expected,
                    image,
                    HookCapture {
                        seeded: &baseline.xstate,
                        state: input.state,
                        directory,
                        ordinal: observed.len(),
                    },
                );
                loop {
                    let hp = child.registers().rip;
                    let hi = hook.instructions.get(&hp).expect("hook instruction start");
                    assert_eq!(child.memory(hp, hi.bytes.len()), hi.bytes);
                    exe.immutable(&child);
                    if hi.bytes == [0xc3] {
                        let mut pending = observed.clone();
                        pending.push(HookEvent {
                            probe_id: if image.logical == fixture::B { 1 } else { 2 },
                            logical_pc: image.logical,
                        });
                        events(&child, req, &pending);
                        let rsp = child.registers().rsp;
                        assert_eq!(word(&child.memory(rsp, 8), 0), image.returned);
                        step(&child, &mut steps);
                        assert_eq!(child.registers().rip, image.returned);
                        assert_eq!(child.registers().rsp, rsp + 8);
                        break;
                    }
                    step(&child, &mut steps);
                    assert!(hi.next.contains(&child.registers().rip), "hook transition");
                }
                observed.push(HookEvent {
                    probe_id: if image.logical == fixture::B { 1 } else { 2 },
                    logical_pc: image.logical,
                });
                events(&child, req, &observed);
                exe.immutable(&child);
                continue;
            }
            step(&child, &mut steps);
            assert!(
                insn.next.contains(&child.registers().rip),
                "generated transition"
            );
        }
        let pc = child.registers().rip;
        assert_eq!(
            boundaries[&pc], expected.logical_pc,
            "first restored boundary must be next logical visit"
        );
        let actual = snapshot(exe, &child, expected.logical_pc);
        assert_state(expected, &actual);
        save_snapshot(&mut captures, &actual);
        let required: Vec<_> = baseline.points[..=index]
            .iter()
            .filter(|p| installed && (p.logical_pc == fixture::B || p.logical_pc == fixture::B + 2))
            .map(|p| HookEvent {
                probe_id: if p.logical_pc == fixture::B { 1 } else { 2 },
                logical_pc: p.logical_pc,
            })
            .collect();
        assert_eq!(observed, required);
        events(&child, req, &observed);
        if index + 1 != baseline.points.len() {
            if expected.logical_pc == fixture::B || expected.logical_pc == fixture::B + 2 {
                assert_eq!((child.registers().eflags >> 6) & 1, u64::from(zf));
                if installed {
                    let image = images.iter().find(|i| i.body == pc).unwrap();
                    step(&child, &mut steps);
                    assert_eq!(
                        child.registers().rip,
                        if zf {
                            image.body + 6
                        } else {
                            image.branch_target
                        }
                    );
                    continue;
                }
            }
            step(&child, &mut steps);
        }
    }
    if installed && head == 0 && seed == fixture::SEEDS[0] && zf {
        journal_calibration::run(
            child.memory(fixture::LOG, PAGE),
            if req.recording { &observed } else { &[] },
            directory,
        );
    }
    finish(
        exe,
        &child,
        steps,
        head,
        directory,
        &captures,
        observed.len(),
    );
    observed.len()
}

// A captured-page reader lets hostile controls exercise the same literal log
// comparator without any post-seed tracee write. Its body is pinned alongside
// the live reader's body in this source packet.
mod journal_calibration {
    use super::{FixedAddress, HookEvent, PAGE, Path, write_new};
    struct Tracee {
        page: Vec<u8>,
    }
    impl Tracee {
        fn memory(&self, address: u64, len: usize) -> Vec<u8> {
            assert_eq!(address, super::fixture::LOG);
            assert_eq!(len, PAGE);
            self.page.clone()
        }
    }
    struct Journal {
        memory: FixedAddress,
        capacity: usize,
    }
    impl Journal {
        fn assert_events(&self, child: &Tracee, expected: &[HookEvent]) {
            let bytes = child.memory(self.memory.address(), PAGE);
            let word = |index: usize| {
                u64::from_ne_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
            };
            assert_eq!(word(1), 0, "hook event log overflow");
            let count = usize::try_from(word(0)).unwrap();
            assert!(count <= self.capacity, "invalid hook event count");
            let actual: Vec<_> = (0..count)
                .map(|index| HookEvent {
                    probe_id: word(2 + 2 * index),
                    logical_pc: word(3 + 2 * index),
                })
                .collect();
            assert_eq!(actual, expected, "hook event trace mismatch");
            assert!(
                bytes[(2 + 2 * count) * 8..].iter().all(|&byte| byte == 0),
                "hook event log wrote beyond its declared entries"
            );
        }
    }
    pub(super) fn run(page: Vec<u8>, expected: &[HookEvent], directory: &Path) {
        let log = Journal {
            memory: FixedAddress,
            capacity: 2,
        };
        log.assert_events(&Tracee { page: page.clone() }, expected);
        let mut report = String::from("LI2ADJLOGCONTROLS\t2\npositive_actual_captured_log\ttrue\n");
        let mut reject = |name: &str, bytes: Vec<u8>| {
            super::fixture::expect_refusal(&format!("journal mutant {name}"), || {
                log.assert_events(&Tracee { page: bytes }, expected)
            });
            report.push_str(&format!("rejected\t{name}\n"));
        };
        let mut bad = page.clone();
        bad[8] = 1;
        reject("overflow", bad);
        let mut bad = page.clone();
        bad[..8].copy_from_slice(&3_u64.to_le_bytes());
        reject("capacity", bad);
        let mut bad = page.clone();
        bad[PAGE - 1] = 1;
        reject("nonzero-tail", bad);
        if expected.len() == 2 {
            reject("dropped-events", vec![0; PAGE]);
            let mut bad = page.clone();
            bad[16..32].copy_from_slice(&page[32..48]);
            bad[32..48].copy_from_slice(&page[16..32]);
            reject("swapped-events", bad);
            let mut bad = page.clone();
            bad[16] ^= 1;
            reject("forged-probe", bad);
            let mut bad = page.clone();
            bad[24] ^= 1;
            reject("forged-logical-pc", bad);
        } else {
            assert!(expected.is_empty());
            let mut bad = page;
            bad[..8].copy_from_slice(&1_u64.to_le_bytes());
            reject("unexpected-null-event", bad);
        }
        report.push_str("mutation_location\tparent_owned_captured_page_only\nEND\n");
        write_new(&directory.join("journal-controls.tsv"), report.as_bytes());
    }
}

/// Execution worker, invoked only after concrete closed-packet verification by the
/// tool entrypoint. Revalidates bytes/shape; makes no independent SHA-256 claim.
pub fn run(input: Input, output: &Path) {
    assert_eq!(target(), input.state);
    for (index, &upper) in [true, false].iter().enumerate() {
        assert_eq!(
            input.images[index],
            fixture::image_witness(input.request, input.state, upper)
                .code
                .bytes
        );
    }
    std::fs::create_dir(output).unwrap();
    let mut executables = Vec::new();
    for phase in 0..3 {
        let descriptor: [u8; 512] = input.elves[phase][0x400..0x600].try_into().unwrap();
        assert_eq!(
            input.elves[phase],
            fixture::elf(
                input.request,
                phase,
                [&input.images[0], &input.images[1]],
                &descriptor
            )
        );
        executables.push(copy_admitted(
            &input.elves[phase],
            &output.join(format!("phase-{phase}.elf")),
        ));
    }
    assert_eq!(executables.len(), 3);
    let mut traces = 0;
    let mut calls = 0;
    for (si, &seed) in fixture::SEEDS.iter().enumerate() {
        for zf in [false, true] {
            for head in 0..4 {
                let row = output.join(format!("seed-{si}-zf-{}-head-{head}", u8::from(zf)));
                std::fs::create_dir(&row).unwrap();
                let baseline = original(
                    &executables[0],
                    input.request,
                    input.state,
                    head,
                    seed,
                    zf,
                    &row.join("phase-0"),
                );
                traces += 1;
                for (phase, executable) in executables.iter().enumerate().skip(1) {
                    calls += compare(
                        executable,
                        &input,
                        &baseline,
                        phase,
                        Scenario { head, seed, zf },
                        &row.join(format!("phase-{phase}")),
                    );
                    traces += 1;
                }
            }
        }
    }
    assert_eq!(traces, 48);
    assert_eq!(calls, 10);
    write_new(&output.join("result.tsv"), format!("LI2ADJNATIVE\t2\nscenarios\t16\nchild_traces\t48\nhook_call_ret_events\t10\nrecorded_events\t{}\nstate_mutants\t92\nimmutable_page_mutants\t6\njournal_mutants\t{}\nsource_restored_artifact_only\ttrue\nlive_retirement\tNOT_COVERED\nqualification_complete\tfalse\nstatus\tpassed\n", if input.request.recording { 10 } else { 0 }, if input.request.recording { 7 } else { 4 }).as_bytes());
}

pub fn target_manifest() -> Vec<u8> {
    fixture::target_text(target())
}
