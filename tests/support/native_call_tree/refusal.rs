//! One intentional malformed-word child; never a positive state comparison.
//! Exit123 is the inherited undifferentiated fatal policy, not a runtime cause.
use super::super::{Cell, Instant, MAX_STEPS, Snapshot, assert_state};
use super::super::{ChildContext, OrdinaryOracle, Pipe, Profile, Subject, Tracee, Walk};
use super::{Witness, call_store, truth, word};
use std::collections::BTreeMap;

pub const SEED: u64 = 0x1234_5678_8765_4320;
const WRONG_WORD: u64 = 0xfeed_face_dead_beef;

pub struct ResultRow {
    pub steps: usize,
}

fn expected_injection(mut before: Snapshot, stack_start: u64, address: u64) -> Snapshot {
    assert_eq!(address % 8, 0);
    let offset = usize::try_from(address.checked_sub(stack_start).unwrap()).unwrap();
    before.application_stack[offset..offset.checked_add(8).unwrap()]
        .copy_from_slice(&WRONG_WORD.to_le_bytes());
    before
}
fn check_injection(expected: &Snapshot, actual: &Snapshot) {
    // POKEDATA executes no instruction, so even debugger flags/physical RIP stay
    // exact here; the inherited complete comparator checks everything else.
    assert_eq!(actual.registers.rip, expected.registers.rip);
    assert_eq!(actual.registers.eflags, expected.registers.eflags);
    assert_state(expected, actual);
}
fn check_not_resumed(pc: u64, restored: &BTreeMap<u64, u64>, gate: u64) {
    assert!(
        !restored.contains_key(&pc),
        "malformed child entry reached restored application work"
    );
    assert!(
        !(gate..gate + 31).contains(&pc),
        "malformed child returned through the outer gate"
    );
}
fn check_exit(status: i32) {
    assert!(
        libc::WIFEXITED(status),
        "refusal must be a normal production fatal exit"
    );
    assert_eq!(libc::WEXITSTATUS(status), 123);
    assert_eq!(
        status,
        123 << 8,
        "no stop/signal/extra wait-status annotation"
    );
}

impl OrdinaryOracle {
    /// One fixed negative subject. No successful return, Report or full-state
    /// pair is counted. All failures before injection remain failures.
    pub fn refuse_tree_child_return<F>(&self, setup: F) -> ResultRow
    where
        F: for<'a> Fn(ChildContext<'a>),
    {
        assert!(matches!(
            self.subject,
            Subject::Tree {
                case: truth::Case::Fit2,
                ..
            }
        ));
        assert_eq!(self.seed, SEED);
        let deadline = self.tree_deadline();
        assert!(Instant::now() < deadline);
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        let mut pipe = Pipe::new();
        // SAFETY: sole-main inactive parent; the actual child constructs all
        // loader/publication/Session/TLS ownership after this one fork.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::close(pipe.0[0]);
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                setup(ChildContext {
                    oracle: self,
                    write: pipe.0[1],
                    output: None,
                    length: truth::INPUT_BYTES,
                });
            }));
            // Setup/panic/returned success cannot impersonate production fatal123.
            unsafe {
                libc::_exit(if result.is_ok() { 0 } else { 122 });
            }
        }
        assert!(pid > 0, "refusal fixture fork failed");
        let child = Tracee {
            pid,
            deadline,
            reaped: Cell::new(false),
        };
        pipe.close_write();
        let ready = pipe.read(&child);
        let stopped = child.wait();
        assert!(libc::WIFSTOPPED(stopped) && libc::WSTOPSIG(stopped) == libc::SIGSTOP);
        child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        let restored = ready.validate(true);
        assert_eq!(ready.profile, Profile::Legacy);
        let mut witness = Witness::new(&ready, self.gate_rsp());
        let mut walk = Walk {
            child: &child,
            steps: 0,
        };
        let actual = walk.reach_gate(&ready, "tree_refusal_reach_gate");
        let _armed = self.armed_frame(&child, &actual, &ready);
        self.seed(&child, actual, truth::INPUT_BYTES);
        let expected: Vec<_> = [0, 1, 4, 7, 10, 14, 18, 22]
            .into_iter()
            .map(|p| ready.gate + p)
            .chain([ready.entry, ready.entry + 4, ready.entry + 9])
            .collect();
        let mut next = 0;
        loop {
            let pc = child.registers().rip;
            let logical = if (ready.gate..ready.gate + 31).contains(&pc) {
                Some(pc)
            } else {
                restored.get(&pc).copied()
            };
            if let Some(logical) = logical {
                assert_eq!(
                    Some(&logical),
                    expected.get(next),
                    "exact pre-fault gate/root visits"
                );
                let snapshot = self.snapshot(&child, &ready, logical);
                assert_eq!(snapshot.data, self.data.bytes());
                next += 1;
            }
            if pc == ready.entry + 9 {
                break;
            }
            walk.step("tree_refusal_before_call");
        }
        assert_eq!(next, expected.len());
        let before = self.snapshot(&child, &ready, ready.entry + 9);
        assert_eq!(
            (
                before.registers.rdi,
                before.registers.rsi,
                before.registers.rax
            ),
            (self.data.address() + 128, 1024, 0)
        );
        let transfer = witness
            .before(&child, ready.entry + 9)
            .expect("actual original E8");
        walk.step("tree_refusal_actual_call");
        witness.after(&child, transfer);
        assert_eq!(witness.next, 1);
        let correct = self.snapshot(&child, &ready, ready.entry + 32);
        let address = self.gate_rsp() - 32;
        let stack_start = self.stack_start(Profile::Legacy);
        assert_eq!(
            (correct.registers.rip, correct.registers.rsp),
            (ready.entry + 32, address)
        );
        assert_eq!(
            word(&correct.application_stack, stack_start, address),
            ready.entry + 14
        );
        assert_ne!(ready.entry + 14, WRONG_WORD);
        call_store(
            &before.application_stack,
            &correct.application_stack,
            stack_start,
            address,
            ready.entry + 14,
        );
        assert_eq!(correct.data, self.data.bytes());
        let expected = expected_injection(correct, stack_start, address);
        // This is the ONLY mutation after the authenticated CALL. POKEDATA writes
        // one native8-byte word at this aligned private stack address. Never repair it.
        assert_eq!(core::mem::size_of::<libc::c_long>(), 8);
        child.request(libc::PTRACE_POKEDATA, address as usize, WRONG_WORD as usize);
        let injected = self.snapshot(&child, &ready, ready.entry + 32);
        check_injection(&expected, &injected);
        assert_eq!(
            word(&injected.application_stack, stack_start, address),
            WRONG_WORD
        );

        loop {
            let pc = child.registers().rip;
            check_not_resumed(pc, &restored, ready.gate);
            assert_eq!(
                word(&child.memory(address, 8), address, address),
                WRONG_WORD,
                "no repaired return word"
            );
            assert!(
                walk.steps < MAX_STEPS,
                "whole refusal child20000-step budget: steps={} rip={pc:#x}",
                walk.steps
            );
            assert!(Instant::now() < deadline);
            walk.steps += 1; // The SAME counter includes approach, CALL and failure.
            child.request(libc::PTRACE_SINGLESTEP, 0, 0);
            let status = child.wait();
            if libc::WIFEXITED(status) {
                check_exit(status);
                break;
            }
            assert!(
                libc::WIFSTOPPED(status),
                "wrong signal/death cannot qualify refusal"
            );
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        }
        assert!(child.reaped.get());
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG | libc::__WALL) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(Instant::now() < deadline, "refusal normal reap deadline");
        ResultRow { steps: walk.steps }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::PAGE;
    use super::*;
    fn snapshot() -> Snapshot {
        Snapshot {
            logical_pc: 0x1020,
            registers: unsafe { core::mem::zeroed() },
            xstate: vec![1; 64],
            data: vec![2; PAGE],
            application_stack: vec![3; 168],
        }
    }
    fn rejected(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    #[test]
    fn tree_refusal_injection_changes_only_the_authenticated_word() {
        let expected = expected_injection(snapshot(), 0x3000, 0x3080);
        let actual = expected_injection(snapshot(), 0x3000, 0x3080);
        check_injection(&expected, &actual);
        for at in 0..168 {
            let mut bad = expected_injection(snapshot(), 0x3000, 0x3080);
            bad.application_stack[at] ^= 1;
            rejected(|| check_injection(&expected, &bad));
        }
        for field in 0..5 {
            let mut bad = expected_injection(snapshot(), 0x3000, 0x3080);
            match field {
                0 => bad.registers.rip ^= 1,
                1 => bad.registers.eflags ^= 1 << 8,
                2 => bad.registers.rax ^= 1,
                3 => bad.data[0] ^= 1,
                _ => bad.xstate[0] ^= 1,
            }
            rejected(|| check_injection(&expected, &bad));
        }
    }
    #[test]
    fn tree_refusal_requires_normal_exact_exit123() {
        check_exit(123 << 8);
        for status in [
            0,
            122 << 8,
            124 << 8,
            libc::SIGABRT,
            libc::SIGSEGV,
            (libc::SIGTRAP << 8) | 0x7f,
            (123 << 8) | (1 << 16),
        ] {
            rejected(|| check_exit(status));
        }
    }
    #[test]
    fn tree_refusal_rejects_application_or_gate_resumption() {
        let restored = BTreeMap::from([(0x6020, 0x1020), (0x6070, 0x1046), (0x6014, 0x100e)]);
        check_not_resumed(0x1020, &restored, 0x5000); // Original redirect, before callback.
        check_not_resumed(0x7000, &restored, 0x5000); // Callback body, not application.
        for pc in restored.keys().copied().chain(0x5000..0x501f) {
            rejected(|| check_not_resumed(pc, &restored, 0x5000));
        }
    }
}
