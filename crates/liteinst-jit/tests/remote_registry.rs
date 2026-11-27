//! I1-C registry differentials: guest registry syscalls are
//! stepped genuinely in the child, so every value the guest
//! queries back is a kernel answer; the tracer mirror must
//! equal those answers exactly. One sequential test: ptrace
//! children and process-global signal state must not overlap.

#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/deadline.rs"]
mod deadline;

use liteinst_jit::Refuse;
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

/// `id`: the fixture's SIGNAL-CORPUS.md ID, checked first. The
/// caller holds the returned deadline across its run.
fn prepare_bytes(
    id: &str,
    bytes: &[u8],
) -> (
    RemoteExecutable,
    liteinst_jit::remote::RemoteChildInfo,
    deadline::Deadline,
) {
    corpus::check(id, bytes);
    let (mut remote, deadline) = deadline::remote_bytes(CHILD, bytes).expect("spawn");
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
    (remote, info, deadline)
}

fn guest_state(
    remote: &RemoteExecutable,
    info: liteinst_jit::remote::RemoteChildInfo,
) -> liteinst_jit::GuestState {
    let mut s = remote.initial_state();
    s.rip = info.base + MAIN_OFF;
    // All registry structures and the handler counter live in
    // the owned, zero-initialized 8192-byte dst buffer.
    s.rbx = info.dst;
    s.rbp = info.base; // handler at offset 0
    s.r12 = info.base + 8; // restorer
    s.r13 = info.src; // altstack buffer
    s
}

fn word(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

fn run_registry_bytes(
    id: &str,
    bytes: &[u8],
) -> (
    RemoteExecutable,
    liteinst_jit::remote::RemoteChildInfo,
    Vec<u8>,
) {
    let (mut remote, info, _deadline) = prepare_bytes(id, bytes);
    remote
        .run(guest_state(&remote, info), RETURN_SENTINEL)
        .expect("registry guest run");
    let mut data = vec![0u8; 576];
    assert!(remote.read_mem(info.dst, &mut data));
    (remote, info, data)
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
    let (mut remote, info, _deadline) = prepare_bytes("C1 registry round trip", &bytes);
    let out = remote
        .run(guest_state(&remote, info), RETURN_SENTINEL)
        .expect("registry round trip run");
    let mut data = vec![0u8; 576];
    assert!(remote.read_mem(info.dst, &mut data));
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
    assert_eq!(
        word(&data, 216) as i64,
        i64::from(remote.registry().altstack().flags),
        "queried altstack flags exact vs mirror"
    );
    assert_eq!(word(&data, 216), 0, "queried altstack flags");
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
        GuestAction {
            handler: info.base,
            flags: 0x0400_0004,
            restorer: info.base + 8,
            sa_mask: 0x800,
        }
    );
    assert!(reg.is_blocked(libc::SIGUSR1) && reg.is_blocked(libc::SIGUSR2));
    assert_eq!(reg.mask(), 0xa00);
    assert_eq!(reg.altstack().sp, info.src);
    assert_eq!(reg.altstack().size, 8192);
    assert_eq!(reg.altstack().flags & libc::SS_DISABLE, 0);
}

fn check_poll_with_handler_installed() {
    // I1-H W4: with a handler installed and both signals BLOCKED
    // and pending, poll exits do not stop the run (a blocked
    // pending signal is not an event natively), the handler does
    // not run, and the signals stay pending. The guest sends both
    // to itself after blocking them (deterministic; `kill` passes
    // through gated to the child's own pid), then loops 40000
    // times: the counter is loaded AFTER the guest's syscalls,
    // which clobber rcx. (Until W4 the first poll exit stopped
    // this run, which is also the only reason the old version's
    // rcx-preset loop, clobbered to a return address by those
    // syscalls, ever ended.)
    let self_send: &[u8] = &[
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, 39 (getpid)
        0x0f, 0x05, // syscall
        0x49, 0x89, 0xc6, // mov r14, rax
        0x4c, 0x89, 0xf7, // mov rdi, r14
        0xbe, 0x0c, 0x00, 0x00, 0x00, // mov esi, 12 (SIGUSR2)
        0xb8, 0x3e, 0x00, 0x00, 0x00, // mov eax, 62 (kill)
        0x0f, 0x05, // syscall
        0x4c, 0x89, 0xf7, // mov rdi, r14
        0xbe, 0x0a, 0x00, 0x00, 0x00, // mov esi, 10 (SIGUSR1)
        0xb8, 0x3e, 0x00, 0x00, 0x00, // mov eax, 62 (kill)
        0x0f, 0x05, // syscall
    ];
    // Causal counter control: main flow increments the same
    // owned counter word the handler would, exactly once,
    // before the loop. Afterwards the word must read exactly 1:
    // a delivered handler would make it 2, and an unowned or
    // unwritable word could not read back 1.
    let inc_counter: &[u8] = &[0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00];
    let loop_tail: &[u8] = &[
        0xb9, 0x40, 0x9c, 0x00, 0x00, // mov ecx, 40000
        0x48, 0xff, 0xc9, 0x75, 0xfb, 0xc3, // dec rcx; jne loop; ret
    ];
    let bytes = guest_bytes(&[
        BUILD_ACT,
        INSTALL,
        MASK_BLOCK,
        self_send,
        inc_counter,
        loop_tail,
    ]);
    let (mut remote, info, _deadline) = prepare_bytes("C2 poll with handler", &bytes);
    let pid = remote.child_pid_for_test();
    let out = remote
        .run(guest_state(&remote, info), RETURN_SENTINEL)
        .unwrap_or_else(|e| panic!("blocked pending signals with a handler installed: {e:?}"));
    assert!(
        out.branches > 2 * liteinst_jit::exec::POLL_BUDGET,
        "crossed poll exits: {} branches",
        out.branches
    );
    let mut counter = [0u8; 8];
    assert!(remote.read_mem(info.dst + 512, &mut counter));
    assert_eq!(
        u64::from_le_bytes(counter),
        1,
        "only main's own increment landed; the blocked signals were not delivered"
    );
    let both = (1u64 << (libc::SIGUSR1 - 1)) | (1u64 << (libc::SIGUSR2 - 1));
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("child status");
    let pending = status
        .lines()
        .filter_map(|l| {
            l.strip_prefix("SigPnd:")
                .or_else(|| l.strip_prefix("ShdPnd:"))
        })
        .map(|v| u64::from_str_radix(v.trim(), 16).expect("pending hex"))
        .fold(0, |acc, v| acc | v);
    assert_eq!(pending & both, both, "both still pending in the kernel");
    assert_eq!(
        remote.registry().action(libc::SIGUSR1),
        GuestAction {
            handler: info.base,
            flags: 0x0400_0004,
            restorer: info.base + 8,
            sa_mask: 0x800,
        },
        "exact installed handler tuple still mirrored after the polls"
    );
    assert!(remote.registry().is_blocked(libc::SIGUSR1));
    assert!(remote.registry().is_blocked(libc::SIGUSR2));
}

fn check_oldfault_mutations() {
    // Valid new state with a bad old-output pointer: the
    // kernel installs first, then returns -EFAULT on copy-out.
    // Each EFAULT case is its own run that ENDS right after
    // the failed call, and the mirror is asserted with no
    // subsequent guest syscall in that run (a following guest
    // query would itself reconcile and could heal a
    // success-only mirror). Kernel-state controls are the
    // paired runs with a query appended.
    let build_b: &[u8] = &[
        0x4c, 0x89, 0x23, // mov [rbx], r12 (handler B)
        0x48, 0xc7, 0x43, 0x08, 0x04, 0x00, 0x00, 0x04, // flags
        0x4c, 0x89, 0x63, 0x10, // mov [rbx+16], r12
        0x48, 0xc7, 0x43, 0x18, 0x00, 0x00, 0x00, 0x00, // mask 0
    ];
    // Install with oldact=1, record rax at [rbx+288]; END.
    let action_old1_end: &[u8] = &[
        0xbf, 0x0a, 0x00, 0x00, 0x00, // edi=10
        0x48, 0x89, 0xde, // rsi=rbx
        0xba, 0x01, 0x00, 0x00, 0x00, // edx=1 (bad oldact)
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89,
        0x83, 0x20, 0x01, 0x00, 0x00, // mov [rbx+288], rax
    ];
    let action_query_320: &[u8] = &[
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0x31, 0xf6, // edi=10, rsi=0
        0x48, 0x8d, 0x93, 0x40, 0x01, 0x00, 0x00, // lea rdx, [rbx+320]
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ];
    // Mask with oldset=1, record rax at [rbx+296]; END.
    let mask_old1_end: &[u8] = &[
        0x48, 0xc7, 0x83, 0x80, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, // mov qword [rbx+128], 0x200
        0x31, 0xff, // edi=SIG_BLOCK
        0x48, 0x8d, 0xb3, 0x80, 0x00, 0x00, 0x00, // lea rsi, [rbx+128]
        0xba, 0x01, 0x00, 0x00, 0x00, // edx=1 (bad oldset)
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0e, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89,
        0x83, 0x28, 0x01, 0x00, 0x00, // mov [rbx+296], rax
    ];
    let mask_query_304: &[u8] = &[
        0x31, 0xff, 0x31, 0xf6, // query mask
        0x48, 0x8d, 0x93, 0x30, 0x01, 0x00, 0x00, // lea rdx, [rbx+304]
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0e, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ];
    // Altstack install with old=1, record rax at [rbx+312]; END.
    let alt_old1_end: &[u8] = &[
        0x4c, 0x89, 0xab, 0xa0, 0x00, 0x00, 0x00, // mov [rbx+160], r13
        0x48, 0xc7, 0x83, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // flags 0
        0x48, 0xc7, 0x83, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, // size 8192
        0x48, 0x8d, 0xbb, 0xa0, 0x00, 0x00, 0x00, // lea rdi, [rbx+160]
        0xbe, 0x01, 0x00, 0x00, 0x00, // esi=1 (bad old stack)
        0xb8, 0x83, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x83, 0x38, 0x01, 0x00,
        0x00, // mov [rbx+312], rax
    ];
    let alt_query_352: &[u8] = &[
        0x31, 0xff, // query altstack
        0x48, 0x8d, 0xb3, 0x60, 0x01, 0x00, 0x00, // lea rsi, [rbx+352]
        0xb8, 0x83, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ];

    // Action: run ends at the copy-out EFAULT; mirror already B.
    let bytes = guest_bytes(&[BUILD_ACT, INSTALL, build_b, action_old1_end, &[0xc3]]);
    let (remote, info, data) = run_registry_bytes("C3 oldact EFAULT action", &bytes);
    assert_eq!(
        word(&data, 288) as i64,
        -14,
        "action copy-out EFAULT preserved"
    );
    assert_eq!(
        remote.registry().action(libc::SIGUSR1).handler,
        info.base + 8,
        "mirror handler B before any later guest syscall"
    );
    // Action control: same bytes plus a guest query (separate run).
    let bytes = guest_bytes(&[
        BUILD_ACT,
        INSTALL,
        build_b,
        action_old1_end,
        action_query_320,
        &[0xc3],
    ]);
    let (_remote, info2, data) = run_registry_bytes("C3 oldact EFAULT action control", &bytes);
    assert_eq!(word(&data, 320), info2.base + 8, "kernel has handler B");

    // Mask: run ends at the copy-out EFAULT; mirror already set.
    let bytes = guest_bytes(&[mask_old1_end, &[0xc3]]);
    let (remote, _info, data) = run_registry_bytes("C3 oldmask EFAULT", &bytes);
    assert_eq!(
        word(&data, 296) as i64,
        -14,
        "mask copy-out EFAULT preserved"
    );
    assert!(
        remote.registry().is_blocked(libc::SIGUSR1),
        "mirror mask before any later guest syscall"
    );
    // Mask control: + guest mask query.
    let bytes = guest_bytes(&[mask_old1_end, mask_query_304, &[0xc3]]);
    let (_remote, _info, data) = run_registry_bytes("C3 oldmask EFAULT control", &bytes);
    assert_eq!(word(&data, 304), 0x200, "kernel mask has SIGUSR1");

    // Altstack: run ends at the copy-out EFAULT; mirror set.
    let bytes = guest_bytes(&[alt_old1_end, &[0xc3]]);
    let (remote, info, data) = run_registry_bytes("C3 oldalt EFAULT", &bytes);
    assert_eq!(
        word(&data, 312) as i64,
        -14,
        "altstack copy-out EFAULT preserved"
    );
    assert_eq!(
        remote.registry().altstack().sp,
        info.src,
        "mirror altstack before any later guest syscall"
    );
    // Altstack control: + guest query.
    let bytes = guest_bytes(&[alt_old1_end, alt_query_352, &[0xc3]]);
    let (_remote, info2, data) = run_registry_bytes("C3 oldalt EFAULT control", &bytes);
    assert_eq!(word(&data, 352), info2.src, "kernel altstack sp");
}

fn check_normalization_and_bad_inputs() {
    // Successful-call normalization: dirty flags/mask and an
    // SS_ONSTACK altstack install query back sanitized; the
    // mirror must equal the kernel answers word for word.
    let build_dirty: &[u8] = &[
        0x48, 0x89, 0x2b, 0x48, 0xc7, 0x43, 0x08, 0x84, 0x04, 0x00, 0x04, // flags 0x04000484
        0x4c, 0x89, 0x63, 0x10, 0x48, 0xc7, 0x43, 0x18, 0x00, 0x09, 0x04,
        0x00, // mask 0x40900
    ];
    let query_act_272: &[u8] = &[
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0x31, 0xf6, 0x48, 0x8d, 0x93, 0x10, 0x01, 0x00,
        0x00, // lea rdx, [rbx+272]
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ];
    let alt_onstack: &[u8] = &[
        0x4c, 0x89, 0xab, 0xa0, 0x00, 0x00, 0x00, // mov [rbx+160], r13
        0x48, 0xc7, 0x83, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, // flags = SS_ONSTACK (1)
        0x48, 0xc7, 0x83, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, // size 8192
        0x48, 0x8d, 0xbb, 0xa0, 0x00, 0x00, 0x00, // lea rdi, [rbx+160]
        0x48, 0x8d, 0xb3, 0xb8, 0x00, 0x00, 0x00, // lea rsi, [rbx+184]
        0xb8, 0x83, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x60, // mov [rbx+96], rax
        0x31, 0xff, // query altstack
        0x48, 0x8d, 0xb3, 0xd0, 0x00, 0x00, 0x00, // lea rsi, [rbx+208]
        0xb8, 0x83, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ];
    let bytes = guest_bytes(&[build_dirty, INSTALL, query_act_272, alt_onstack, &[0xc3]]);
    let (mut remote, info, _deadline) = prepare_bytes("C4 normalization", &bytes);
    remote
        .run(guest_state(&remote, info), RETURN_SENTINEL)
        .expect("normalization run");
    let mut data = vec![0u8; 576];
    assert!(remote.read_mem(info.dst, &mut data));
    assert_eq!(word(&data, 280), 0x0400_0004, "kernel sanitized flags");
    assert_eq!(word(&data, 296), 0x800, "kernel sanitized sa_mask");
    assert_eq!(word(&data, 216), 0, "kernel altstack flags not on-stack");
    let reg = remote.registry();
    assert_eq!(
        reg.action(libc::SIGUSR1).flags,
        word(&data, 280),
        "mirror flags = kernel"
    );
    assert_eq!(
        reg.action(libc::SIGUSR1).sa_mask,
        word(&data, 296),
        "mirror mask = kernel"
    );
    assert_eq!(
        i64::from(reg.altstack().flags),
        word(&data, 216) as i64,
        "mirror altstack flags exact"
    );

    // Bad and partial inputs reach the kernel and return its
    // -EFAULT to the guest (never an observer refusal); a later
    // valid install still lands and is mirrored. Partial cases
    // place the act struct in the child's owned guarded
    // allocation: exactly the first 8 bytes are readable, the
    // second page is explicitly PROT_NONE.
    let bad_act: &[u8] = &[
        // bad: rt_sigaction(USR1, act=1, NULL, 8) -> [rbx+80]
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x41, 0xba, 0x08,
        0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x50,
    ];
    let partial_call: &[u8] = &[
        // partial: rt_sigaction(USR1, act=r12, NULL, 8) -> [rbx+88]
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xe6, 0x31, 0xd2, 0x41, 0xba, 0x08, 0x00, 0x00,
        0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x58,
    ];
    let write_default_word: &[u8] = &[0x49, 0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00];
    let write_handler_word: &[u8] = &[0x49, 0x89, 0x2c, 0x24];
    for (label, write_word) in [
        ("partial-default", write_default_word),
        ("partial-handler", write_handler_word),
    ] {
        let bytes = guest_bytes(&[
            bad_act,
            write_word,
            partial_call,
            BUILD_ACT,
            INSTALL,
            &[0xc3],
        ]);
        corpus::check(&format!("C5 partial act {label}"), &bytes);
        let (mut remote, _deadline) =
            deadline::remote_bytes_guarded(CHILD, &bytes).expect("spawn guarded");
        let info = remote.info();
        let region = RegionFacts {
            base: info.base,
            bytes: bytes.clone(),
            generation: Generation(1),
            immutable_private: true,
        };
        remote
            .prepare(
                &region,
                info.base + MAIN_OFF,
                CountProfile::BranchesAndInstructions,
            )
            .expect("prepare partial fixture");
        let mut state = guest_state(&remote, info);
        // Records and the valid act live in the 128-byte data
        // box; only the partial act sits in the guarded tail
        // (dst usable tail is 16 bytes, so +8 leaves exactly 8).
        state.rbx = info.data;
        state.r12 = info.dst + 8;
        remote
            .run(state, RETURN_SENTINEL)
            .expect("bad/partial inputs complete as guest errnos");
        let mut data = vec![0u8; 128];
        assert!(remote.read_mem(info.data, &mut data));
        assert_eq!(
            word(&data, 80) as i64,
            -14,
            "{label}: bad act pointer is guest -EFAULT"
        );
        assert_eq!(
            word(&data, 88) as i64,
            -14,
            "{label}: partial act is guest -EFAULT"
        );
        assert_eq!(word(&data, 64), 0, "{label}: later valid install succeeds");
        assert_eq!(
            remote.registry().action(libc::SIGUSR1).handler,
            info.base,
            "{label}: mirror holds the valid install only"
        );
    }
}

fn check_seed_controls() {
    // Reserved 32/33 cannot be honored by libc mask APIs: the
    // request is refused by name instead of mirrored as set.
    let refused = deadline::remote_named_with_blocked(CHILD, "sum_loop", &[32, 33]);
    match refused {
        Err(Refuse::RemoteSubstrate { operation, .. }) => {
            assert_eq!(operation, "initial blocked mask not honored");
        }
        Err(other) => panic!("seed32: wrong refusal {other:?}"),
        Ok(_) => panic!("seed32: spawn must refuse unhonorable mask"),
    }
    // Positive controls: normalization reset the inherited
    // ignored SIGPIPE, and an ordinary requested mask seeds
    // exactly from the child's actual SigBlk.
    let (remote, _deadline) =
        deadline::remote_named_with_blocked(CHILD, "sum_loop", &[libc::SIGUSR1])
            .expect("spawn with USR1 blocked");
    assert!(
        remote.registry().action(libc::SIGPIPE).is_default(),
        "SIGPIPE reset to default"
    );
    // Snapshot before any guest query: full four-word tuples
    // seeded from the child's kernel dump are exactly zero
    // (the child verified the same via raw rt_sigaction
    // before the handshake, so spawn itself is the proof).
    assert_eq!(
        remote.registry().action(libc::SIGUSR1),
        GuestAction::default(),
        "initial SIGUSR1 tuple from kernel dump"
    );
    assert_eq!(
        remote.registry().action(libc::SIGPIPE),
        GuestAction::default(),
        "initial SIGPIPE tuple from kernel dump"
    );
    assert!(
        remote.registry().is_blocked(libc::SIGUSR1),
        "requested USR1 block seeded"
    );
    assert_eq!(remote.registry().mask(), 1u64 << (libc::SIGUSR1 - 1));
}

/// One sequential test: ptrace children and process-global
/// signal state must not overlap.
#[test]
fn remote_registry_all() {
    let _bound = deadline::TestBound::arm();
    // Every fixture this test builds is pinned (see `corpus`).
    let _corpus = corpus::guard();
    check_registry_round_trip();
    check_poll_with_handler_installed();
    check_oldfault_mutations();
    check_normalization_and_bad_inputs();
    check_seed_controls();
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("remote_registry.rs"), "remote_registry.rs");
}

/// Bound census (I1-H H2d): every test here arms a `TestBound`
/// (`common/deadline.rs`).
#[test]
fn bound_census() {
    deadline::bound_census(
        include_str!("remote_registry.rs"),
        "remote_registry.rs",
        &["spawn_census", "bound_census"],
    );
}
