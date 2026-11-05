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
}

impl Handler for CountingHandler {
    fn syscall(
        &mut self,
        _state: &mut GuestState,
        _insn_pc: u64,
        _next_pc: u64,
    ) -> Result<Resume, Refuse> {
        self.calls += 1;
        Ok(Resume::Done)
    }
}

fn syscall_bytes(nr: u32) -> Vec<u8> {
    let mut v = vec![0xb8];
    v.extend_from_slice(&nr.to_le_bytes());
    v.extend_from_slice(&[0x0f, 0x05, 0xc3]);
    v
}

fn run_syscall(nr: u32) -> (Result<liteinst_jit::Outcome, RunError>, usize) {
    let bytes = syscall_bytes(nr);
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
    (result, handler.calls)
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
}
