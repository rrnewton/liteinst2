//! Lifecycle syscall dispatch reservation (PR-1 N2 wiring).
//!
//! Isolated in its own test binary because `Executable::run`
//! uses process-global signal state under the P1a envelope.

use liteinst_jit::exec::{Executable, Handler, ProcessMemory, Resume, RunError};
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::types::{CountProfile, Generation};
use liteinst_jit::{GuestState, Refuse};

#[derive(Default)]
struct CountingHandler {
    calls: usize,
    last_rax: u64,
}

impl Handler for CountingHandler {
    fn syscall(
        &mut self,
        state: &mut GuestState,
        _insn_pc: u64,
        _next_pc: u64,
    ) -> Result<Resume, Refuse> {
        self.calls += 1;
        self.last_rax = state.rax;
        Ok(Resume::Done)
    }
}

fn syscall_bytes(nr: u32) -> Vec<u8> {
    let mut v = vec![0xb8];
    v.extend_from_slice(&nr.to_le_bytes());
    v.extend_from_slice(&[0x0f, 0x05, 0xc3]);
    v
}

fn entry_bytes_movabs(value: u64, tail: &[u8]) -> Vec<u8> {
    let mut v = vec![0x48, 0xb8];
    v.extend_from_slice(&value.to_le_bytes());
    v.extend_from_slice(tail);
    v
}

fn syscall_bytes_movabs(value: u64) -> Vec<u8> {
    entry_bytes_movabs(value, &[0x0f, 0x05, 0xc3])
}

fn run_syscall(nr: u32) -> (Result<liteinst_jit::Outcome, RunError>, usize) {
    let (result, calls, _) = run_guest(syscall_bytes(nr));
    (result, calls)
}

fn run_guest(bytes: Vec<u8>) -> (Result<liteinst_jit::Outcome, RunError>, usize, u64) {
    let guest = MappedGuest::map(&bytes).expect("map guest");
    let region = guest.region(&bytes, Generation(1));
    let mut exec =
        Executable::prepare(&region, guest.base, CountProfile::Branches).expect("prepare");
    let mut handler = CountingHandler::default();
    let result = exec.run(
        guest.initial_state(),
        &mut handler,
        &ProcessMemory,
        RETURN_SENTINEL,
    );
    (result, handler.calls, handler.last_rax)
}

#[test]
fn lifecycle_syscalls_refuse_before_handler() {
    let cases: [(u32, Option<Refuse>); 7] = [
        (59, Some(Refuse::ExecSuccessor)),
        (322, Some(Refuse::ExecSuccessor)),
        (56, Some(Refuse::ThreadLifecycle { what: "clone" })),
        (57, Some(Refuse::ThreadLifecycle { what: "fork" })),
        (58, Some(Refuse::ThreadLifecycle { what: "vfork" })),
        (435, Some(Refuse::ThreadLifecycle { what: "clone3" })),
        // Positive control: an ordinary syscall still dispatches.
        (1, None),
    ];
    for (nr, expected) in cases {
        let (result, calls) = run_syscall(nr);
        match expected {
            Some(refusal) => {
                assert_eq!(
                    result,
                    Err(RunError::Refuse(refusal)),
                    "syscall {nr} exact refusal"
                );
                assert_eq!(calls, 0, "syscall {nr} handler must not be called");
            }
            None => {
                assert!(result.is_ok(), "syscall {nr} control: {result:?}");
                assert_eq!(calls, 1, "syscall {nr} positive control");
            }
        }
    }

    // Native aliases: Linux dispatch examines the low 32 bits, so
    // a nonzero high dword must not bypass the reservation.
    let reserved: [(u32, Refuse); 6] = [
        (59, Refuse::ExecSuccessor),
        (322, Refuse::ExecSuccessor),
        (56, Refuse::ThreadLifecycle { what: "clone" }),
        (57, Refuse::ThreadLifecycle { what: "fork" }),
        (58, Refuse::ThreadLifecycle { what: "vfork" }),
        (435, Refuse::ThreadLifecycle { what: "clone3" }),
    ];
    for (nr, refusal) in reserved {
        let value = (1u64 << 32) | u64::from(nr);
        let (result, calls, _) = run_guest(syscall_bytes_movabs(value));
        assert_eq!(
            result,
            Err(RunError::Refuse(refusal)),
            "syscall alias {value:#x} exact refusal"
        );
        assert_eq!(calls, 0, "syscall alias {value:#x} handler calls");
    }

    // High bits alone do not refuse an ordinary syscall, and the
    // handler still observes the raw 64-bit RAX.
    let value = (1u64 << 32) | 1;
    let (result, calls, last_rax) = run_guest(syscall_bytes_movabs(value));
    assert!(result.is_ok(), "ordinary alias control: {result:?}");
    assert_eq!(calls, 1, "ordinary alias positive control");
    assert_eq!(last_rax, value, "raw RAX retained for handler");

    // Entry kind decides the number space. An int 0x80 carrying
    // the ia32 execve number (11, with a nonzero high dword) is
    // not judged as x86-64 munmap and never reaches the handler.
    let ia32_execve = (1u64 << 32) | 11;
    let (result, calls, _) = run_guest(entry_bytes_movabs(ia32_execve, &[0xcd, 0x80, 0xc3]));
    assert_eq!(
        result,
        Err(RunError::Refuse(Refuse::Arch {
            what: "ia32 compat syscall entry outside P1a envelope"
        })),
        "int 0x80 must refuse as compat entry, not native munmap"
    );
    assert_eq!(calls, 0, "int 0x80 handler must not be called");

    // Sysenter is a compat entry on Linux (or invalid where
    // compat is unavailable), never native dispatch: both a
    // reserved alias and an ordinary alias refuse by its own
    // distinct name before any number interpretation.
    for nr in [59u64, 1] {
        let value = (1u64 << 32) | nr;
        let (result, calls, _) = run_guest(entry_bytes_movabs(value, &[0x0f, 0x34, 0xc3]));
        assert_eq!(
            result,
            Err(RunError::Refuse(Refuse::Arch {
                what: "sysenter compat entry outside P1a envelope"
            })),
            "sysenter value {value:#x} exact refusal"
        );
        assert_eq!(calls, 0, "sysenter value {value:#x} handler calls");
    }
}
