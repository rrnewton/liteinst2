//! Finite synthetic mechanism controls, never common-app/candidate authority.
use super::*;

const PC: u64 = 0x401100;
const DEST: u64 = 0x500000;
fn snapshot(child: &Tracee, logical_pc: u64) -> Snapshot {
    Snapshot {
        logical_pc,
        registers: child.registers(),
        xstate: canonical_xstate(&child.xstate()),
        data: child.memory(ARRAY, PAGE),
        application_stack: child.memory(STACK_START, seed::STACK_BYTES),
    }
}
fn reaped(child: Tracee) {
    let pid = child.pid;
    drop(child);
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
fn write_source(owned: &OwnedImage, bytes: &[u8]) {
    owned.image.protect(libc::PROT_READ | libc::PROT_WRITE);
    owned.image.initialize((PC - IMAGE_START) as usize, bytes);
    for &(_, address, _, len, flags) in &LOADS {
        let lo = address & !4095;
        protect(
            lo,
            (page_end(address + len) - lo) as usize,
            protection(flags),
        );
    }
}

pub(super) fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args.len(), 3);
    assert_eq!(args[1], "common-core-router-controls");
    let dir = Path::new(&args[2]);
    assert!(dir.is_absolute());
    assert_eq!(
        dir.parent().unwrap().canonicalize().unwrap(),
        dir.parent().unwrap()
    );
    std::fs::create_dir(dir).unwrap();
    let bootstrap = router_native::Bootstrap::new();
    let mut original = vec![0; (IMAGE_END - IMAGE_START) as usize];
    original[(PC - IMAGE_START) as usize..(PC - IMAGE_START) as usize + 64].fill(0x90);
    let owned = OwnedImage::new(original);
    let generated = reserve(DEST, PAGE);
    generated.protect(libc::PROT_READ | libc::PROT_WRITE);
    generated.initialize(0, &vec![0x90; PAGE]);
    generated.protect(libc::PROT_READ | libc::PROT_EXEC);
    let ranges: Vec<_> = seed::ORIGINAL_RANGES
        .iter()
        .map(|r| seed::SourceRange {
            function: r.function,
            pc: r.pc,
            file_offset: r.file_offset,
            bytes: r.bytes,
        })
        .collect();
    let inventory =
        seed::authenticate(include_bytes!("e9_common_seed.instructions.tsv"), &ranges).unwrap();
    let anchors = seed::Anchors::new(ARRAY, FRAME).unwrap();
    let mut comparisons = 0;
    for (encoding, fetch) in [
        ("legacy", vec![0x06]),
        ("evex", {
            let mut b = vec![0; 15];
            b[0] = 0x62;
            b
        }),
    ] {
        for state in 0..2 {
            let spec = inventory.case(state, anchors).unwrap();
            owned.initialize(&spec);
            let reference = Tracee::fork();
            reference.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
            let mut wanted = apply(&spec, reference.registers());
            wanted.rip = PC;
            let xstate = seeded_xstate(reference.xstate(), spec.seed);
            reference.set_registers(&wanted);
            reference.set_xstate(&xstate);
            let before = snapshot(&reference, PC);
            let mut steps = 0;
            step(&reference, &mut steps);
            assert_eq!(reference.registers().rip, PC + 1);
            let after = snapshot(&reference, PC + 1);
            reaped(reference);
            write_source(&owned, &fetch);
            let route = Route {
                pc: PC,
                target: DEST,
                source_start: PC,
                source_end: PC + 64,
                fetch: fetch.clone(),
            };
            let router = router_native::Router::new(std::slice::from_ref(&route));
            let child = Tracee::fork();
            child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
            assert_eq!(inherited(&child.registers()), inherited(&wanted));
            child.set_registers(&wanted);
            child.set_xstate(&xstate);
            assert_state(&before, &snapshot(&child, PC));
            let source = child.memory(IMAGE_START, owned.pages.len());
            let code = child.memory(DEST, PAGE);
            let mut trace = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(format!("{encoding}-{state}.tsv")))
                .unwrap();
            trace.write_all(router.descriptor().as_bytes()).unwrap();
            router.observed(&child, "before", &mut trace);
            let mut steps = 0;
            router.deliver(&child, &route, &mut steps, &mut trace);
            assert_eq!(child.registers().rip, DEST);
            assert_state(&before, &snapshot(&child, PC));
            step(&child, &mut steps);
            assert_eq!(child.registers().rip, DEST + 1);
            assert_state(&after, &snapshot(&child, PC + 1));
            assert_eq!(child.memory(IMAGE_START, source.len()), source);
            assert_eq!(child.memory(DEST, PAGE), code);
            router.observed(&child, "after", &mut trace);
            assert_eq!(steps, 34);
            reaped(child);
            router.verify();
            drop(router);
            write_source(&owned, &[0x90; 15]);
            comparisons += 3;
        }
    }
    // Genuine child deliveries exercise the same handler's failure path. A
    // user-injected signal and an unowned hardware #UD must both exit 124.
    for user_signal in [false, true] {
        let spec = inventory.case(0, anchors).unwrap();
        owned.initialize(&spec);
        write_source(&owned, &[0x06]);
        let route = Route {
            pc: if user_signal { PC } else { PC + 16 },
            target: DEST,
            source_start: PC,
            source_end: PC + 64,
            fetch: vec![0x06],
        };
        // The declared route's source byte is independently present too.
        owned.image.protect(libc::PROT_READ | libc::PROT_WRITE);
        owned
            .image
            .initialize((PC + 16 - IMAGE_START) as usize, &[0x06]);
        for &(_, address, _, len, flags) in &LOADS {
            let lo = address & !4095;
            protect(
                lo,
                (page_end(address + len) - lo) as usize,
                protection(flags),
            );
        }
        let router = router_native::Router::new(&[route]);
        let child = Tracee::fork();
        child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        let mut wanted = apply(&spec, child.registers());
        wanted.rip = PC;
        child.set_registers(&wanted);
        if !user_signal {
            assert_eq!(child.synchronous_fault(), (libc::SIGILL, 2, PC));
        }
        child.request(libc::PTRACE_CONT, 0, libc::SIGILL as usize);
        let captured = child.wait();
        assert!(libc::WIFSTOPPED(captured) && libc::WSTOPSIG(captured) == libc::SIGTRAP);
        child.request(libc::PTRACE_CONT, 0, 0);
        let end = child.wait();
        assert!(libc::WIFEXITED(end));
        assert_eq!(libc::WEXITSTATUS(end), 124);
        reaped(child);
        router.verify();
        drop(router);
        write_source(&owned, &[0x90; 64]);
    }
    assert_eq!(comparisons, 12);
    drop(bootstrap);
    write_new(&dir.join("complete.tsv"),b"LI2COMMONROUTERCONTROLS\t1\nsynthetic_roundtrips\t4\nfull_state_comparisons\t12\nrefused_deliveries\t2\nchildren\t10\ncommon_corpus_credit\tfalse\nqualification_complete\tfalse\n");
}
