//! I1-C registry differentials: guest registry syscalls are
//! stepped genuinely in the child, so every value the guest
//! queries back is a kernel answer; the tracer mirror must
//! equal those answers exactly. One sequential test: ptrace
//! children and process-global signal state must not overlap.

use liteinst_jit::exec::{FaultKind, RunError};
use liteinst_jit::harness::RETURN_SENTINEL;
use liteinst_jit::remote::{GuestAction, RemoteExecutable};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};

const CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");

// Handler: inc qword [rbx+512]; ret. Restorer: rt_sigreturn.
const HEADER: &[u8] = &[
    0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, 0xc3, // 0: handler
    0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05, // 8: restorer
];
const MAIN_OFF: u64 = 15;

// Build the install-struct writes at [rbx]: handler=rbp,
// flags=SA_RESTORER|SA_SIGINFO, restorer=r12, mask=SIGUSR2 bit.
const BUILD_ACT: &[u8] = &[
    0x48, 0x89, 0x2b, // mov [rbx], rbp
    0x48, 0xc7, 0x43, 0x08, 0x04, 0x00, 0x00, 0x04, // mov qword [rbx+8], 0x04000004
    0x4c, 0x89, 0x63, 0x10, // mov [rbx+16], r12
    0x48, 0xc7, 0x43, 0x18, 0x00, 0x08, 0x00, 0x00, // mov qword [rbx+24], 0x800
];
// rt_sigaction(USR1, rbx, rbx+32, 8); record rax at [rbx+64].
const INSTALL: &[u8] = &[
    0xbf, 0x0a, 0x00, 0x00, 0x00, // mov edi, 10
    0x48, 0x89, 0xde, // mov rsi, rbx
    0x48, 0x8d, 0x53, 0x20, // lea rdx, [rbx+32]
    0x41, 0xba, 0x08, 0x00, 0x00, 0x00, // mov r10d, 8
    0xb8, 0x0d, 0x00, 0x00, 0x00, // mov eax, 13
    0x0f, 0x05, // syscall
    0x48, 0x89, 0x43, 0x40, // mov [rbx+64], rax
];
// rt_sigprocmask(SIG_BLOCK, {USR1|USR2} at rbx+128, rbx+136, 8);
// record rax at [rbx+80].
const MASK_BLOCK: &[u8] = &[
    0x48, 0xc7, 0x83, 0x80, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x00, // mov qword [rbx+128], 0xa00
    0x31, 0xff, // xor edi, edi
    0x48, 0x8d, 0xb3, 0x80, 0x00, 0x00, 0x00, // lea rsi, [rbx+128]
    0x48, 0x8d, 0x93, 0x88, 0x00, 0x00, 0x00, // lea rdx, [rbx+136]
    0x41, 0xba, 0x08, 0x00, 0x00, 0x00, // mov r10d, 8
    0xb8, 0x0e, 0x00, 0x00, 0x00, // mov eax, 14
    0x0f, 0x05, // syscall
    0x48, 0x89, 0x43, 0x50, // mov [rbx+80], rax
];

fn guest_bytes(main: &[&[u8]]) -> Vec<u8> {
    let mut v = HEADER.to_vec();
    for seg in main {
        v.extend_from_slice(seg);
    }
    v
}

fn prepare_bytes(bytes: &[u8]) -> (RemoteExecutable, liteinst_jit::remote::RemoteChildInfo) {
    let mut remote =
        RemoteExecutable::spawn_bytes(std::path::Path::new(CHILD), bytes).expect("spawn");
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: bytes.to_vec(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + MAIN_OFF,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare");
    (remote, info)
}

fn guest_state(
    remote: &RemoteExecutable,
    info: liteinst_jit::remote::RemoteChildInfo,
) -> liteinst_jit::GuestState {
    let mut s = remote.initial_state();
    s.rip = info.base + MAIN_OFF;
    s.rbx = info.data;
    s.rbp = info.base; // handler at offset 0
    s.r12 = info.base + 8; // restorer
    s.r13 = info.src; // altstack buffer
    s
}

fn word(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

fn check_registry_round_trip() {
    let query_act: &[u8] = &[
        0xbf, 0x0a, 0x00, 0x00, 0x00, // mov edi, 10
        0x31, 0xf6, // xor esi, esi
        0x48, 0x8d, 0x93, 0x10, 0x01, 0x00, 0x00, // lea rdx, [rbx+272]
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89,
        0x43, 0x48, // mov [rbx+72], rax
    ];
    let mask_query: &[u8] = &[
        0x31, 0xff, 0x31, 0xf6, // xor edi,edi; xor esi,esi
        0x48, 0x8d, 0x93, 0x90, 0x00, 0x00, 0x00, // lea rdx, [rbx+144]
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0e, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89,
        0x43, 0x58, // mov [rbx+88], rax
    ];
    let alt_build_install_query: &[u8] = &[
        0x4c, 0x89, 0xab, 0xa0, 0x00, 0x00, 0x00, // mov [rbx+160], r13
        0x48, 0xc7, 0x83, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov qword [rbx+168], 0
        0x48, 0xc7, 0x83, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, // mov qword [rbx+176], 8192
        0x48, 0x8d, 0xbb, 0xa0, 0x00, 0x00, 0x00, // lea rdi, [rbx+160]
        0x48, 0x8d, 0xb3, 0xb8, 0x00, 0x00, 0x00, // lea rsi, [rbx+184]
        0xb8, 0x83, 0x00, 0x00, 0x00, 0x0f, 0x05, // sigaltstack
        0x48, 0x89, 0x43, 0x60, // mov [rbx+96], rax
        0x31, 0xff, // xor edi, edi
        0x48, 0x8d, 0xb3, 0xd0, 0x00, 0x00, 0x00, // lea rsi, [rbx+208]
        0xb8, 0x83, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43,
        0x68, // mov [rbx+104], rax
    ];
    let failed_install_and_requery: &[u8] = &[
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x89, 0xde, 0x31, 0xd2, // edi=10, rsi=rbx, edx=0
        0x41, 0xba, 0x10, 0x00, 0x00, 0x00, // r10d=16 (wrong sigsetsize)
        0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43,
        0x70, // mov [rbx+112], rax
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0x31, 0xf6, 0x48, 0x8d, 0x93, 0xe8, 0x00, 0x00,
        0x00, // lea rdx, [rbx+232]
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ];
    let sigpending: &[u8] = &[
        0x48, 0x8d, 0xbb, 0x08, 0x01, 0x00, 0x00, // lea rdi, [rbx+264]
        0xbe, 0x08, 0x00, 0x00, 0x00, // mov esi, 8
        0xb8, 0x7f, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43,
        0x78, // mov [rbx+120], rax
        0xc3, // ret
    ];
    let bytes = guest_bytes(&[
        BUILD_ACT,
        INSTALL,
        query_act,
        MASK_BLOCK,
        mask_query,
        alt_build_install_query,
        failed_install_and_requery,
        sigpending,
    ]);
    let (mut remote, info) = prepare_bytes(&bytes);
    let out = remote
        .run(guest_state(&remote, info), RETURN_SENTINEL)
        .expect("registry round trip run");
    let mut data = vec![0u8; 576];
    assert!(remote.read_mem(info.data, &mut data));
    // Syscall results recorded by the guest.
    assert_eq!(word(&data, 64), 0, "install result");
    assert_eq!(word(&data, 72), 0, "query result");
    assert_eq!(word(&data, 80), 0, "sigprocmask result");
    assert_eq!(word(&data, 88), 0, "mask query result");
    assert_eq!(word(&data, 96), 0, "sigaltstack result");
    assert_eq!(word(&data, 104), 0, "altstack query result");
    assert_eq!(word(&data, 112) as i64, -22, "failed install is EINVAL");
    assert_eq!(word(&data, 120), 0, "sigpending result");
    // Kernel-queried values (the genuine guest answers).
    assert_eq!(word(&data, 32), 0, "oldact at install was default handler");
    assert_eq!(word(&data, 272), info.base, "queried handler");
    assert_eq!(word(&data, 280), 0x0400_0004, "queried flags");
    assert_eq!(word(&data, 288), info.base + 8, "queried restorer");
    assert_eq!(word(&data, 296), 0x800, "queried sa_mask");
    assert_eq!(word(&data, 136), 0, "old mask at block time");
    assert_eq!(word(&data, 144), 0xa00, "queried blocked mask");
    assert_eq!(word(&data, 208), info.src, "queried altstack sp");
    assert_eq!(word(&data, 224), 8192, "queried altstack size");
    assert_eq!(word(&data, 264), 0, "pending set empty");
    assert_eq!(
        &data[232..264],
        &data[272..304],
        "failed install changed nothing"
    );
    assert_eq!(word(&data, 512), 0, "handler never ran");
    let _ = out;
    // The tracer mirror equals the kernel answers exactly.
    let reg = remote.registry();
    assert_eq!(
        reg.action(libc::SIGUSR1),
        GuestAction::Handler {
            addr: info.base,
            flags: 0x0400_0004,
            sa_mask: 0x800,
            restorer: info.base + 8,
        }
    );
    assert!(reg.is_blocked(libc::SIGUSR1) && reg.is_blocked(libc::SIGUSR2));
    assert_eq!(reg.mask(), 0xa00);
    assert_eq!(reg.altstack().sp, info.src);
    assert_eq!(reg.altstack().size, 8192);
    assert_eq!(reg.altstack().flags & libc::SS_DISABLE, 0);
}

fn check_poll_with_handler_installed() {
    let loop_tail: &[u8] = &[
        0x48, 0xff, 0xc9, 0x75, 0xfb, 0xc3, // dec rcx; jne loop; ret
    ];
    let bytes = guest_bytes(&[BUILD_ACT, INSTALL, MASK_BLOCK, loop_tail]);
    let (mut remote, info) = prepare_bytes(&bytes);
    let pid = remote.child_pid_for_test();
    // The guest itself blocks both signals via a stepped
    // rt_sigprocmask early in main; queue them from the host
    // after a fill delay so they are pending (not delivered)
    // well before the first poll boundary.
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done2 = done.clone();
    let killer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        for _ in 0..40 {
            if done2.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            // SAFETY: signalling the test's traced child.
            unsafe {
                libc::kill(pid, libc::SIGUSR2);
                libc::kill(pid, libc::SIGUSR1);
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    });
    let mut state = guest_state(&remote, info);
    state.rcx = 5_000_000;
    let r = remote.run(state, RETURN_SENTINEL);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    killer.join().expect("killer thread");
    let f = match r {
        Err(RunError::Fault(f)) => f,
        other => panic!("poll with handler: expected fault, got {other:?}"),
    };
    assert_eq!(f.kind, FaultKind::AsyncSignal);
    assert_eq!(f.signum, libc::SIGUSR1);
    assert_eq!(f.also_pending, vec![libc::SIGUSR2]);
    assert!(f.branches >= 1_000, "poll progress: {}", f.branches);
    let mut counter = [0u8; 8];
    assert!(remote.read_mem(info.data + 512, &mut counter));
    assert_eq!(
        u64::from_le_bytes(counter),
        0,
        "handler must not run in I1-C"
    );
    assert!(matches!(
        remote.registry().action(libc::SIGUSR1),
        GuestAction::Handler { .. }
    ));
    assert!(remote.registry().is_blocked(libc::SIGUSR1));
}

/// One sequential test: ptrace children and process-global
/// signal state must not overlap.
#[test]
fn remote_registry_all() {
    check_registry_round_trip();
    check_poll_with_handler_installed();
}
