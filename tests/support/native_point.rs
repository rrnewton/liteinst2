// Additive fresh-child point setup. Included inside ordered_trace so its exact
// existing log, state comparator, xstate canonicalizer and Tracee remain shared.
use super::*;
use std::path::Path;

pub struct PointOracle {
    inner: NativeOracle,
    log: HookEventLog,
}
pub struct Original {
    initial: libc::user_regs_struct,
    xstate: Vec<u8>,
    points: Vec<Snapshot>,
}
pub struct Published<'a> {
    pub source: &'a [u8],
    pub images: &'a [(u64, Vec<u8>)],
    pub boundaries: &'a [(u64, u64)],
    pub events: &'a [HookEvent],
}

impl PointOracle {
    /// The closure authors the entire finite source before any child exists.
    pub fn new(make: impl FnOnce(u64) -> Vec<u8>) -> Self {
        let mut inner = NativeOracle::new(&[]);
        let code = make(inner.code.address());
        assert!(!code.is_empty() && code.len() < PAGE / 2);
        inner.code.initialize(0, &code);
        inner.original_code = inner.code.bytes().to_vec();
        inner.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        Self {
            inner,
            log: HookEventLog::with_capacity(32),
        }
    }
    pub fn base(&self) -> u64 {
        self.inner.code.address()
    }
    pub fn source(&self) -> &[u8] {
        &self.inner.original_code
    }
    pub fn return_pc(&self) -> u64 {
        self.inner.return_pc
    }

    /// Fresh-child refusal without executing source after the failed operation.
    pub fn control<F, G>(&self, setup: F, output: &Path)
    where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        let prepared = Prepared::fork(setup, &self.log);
        prepared.finish(output, 0, 0, 0);
        assert_eq!(self.inner.code.bytes(), self.source());
    }

    pub fn original(&self, heads: &[u64], seed: u64, output: &Path) -> Original {
        assert!(!heads.is_empty());
        let prepared = Prepared::fork(|| || {}, &self.log);
        let child = &prepared.child;
        let mut initial = child.registers();
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
        initial.rsi = self.inner.data.address() + 512;
        initial.rdi = self.inner.data.address();
        initial.r8 = next();
        initial.r9 = next();
        initial.r10 = next();
        initial.r11 = next();
        initial.r12 = next();
        initial.r13 = next();
        initial.r14 = next();
        initial.r15 = next();
        initial.rsp = self.inner.initial_rsp;
        initial.rip = heads[0];
        initial.orig_rax = u64::MAX;
        initial.eflags = 0xad7 | ((seed & 1) << 10);
        let xstate = seeded_xstate(child.xstate(), seed);
        child.set_registers(&initial);
        child.set_xstate(&xstate);
        let xstate = child.xstate();
        let published = Published {
            source: self.source(),
            images: &[],
            boundaries: &[],
            events: &[],
        };
        let (points, steps) = self.walk(child, heads, &published);
        prepared.finish(output, steps, points.len(), 0);
        Original {
            initial,
            xstate,
            points,
        }
    }

    pub fn candidate<F, G>(
        &self,
        original: &Original,
        published: Published<'_>,
        setup: F,
        output: &Path,
    ) where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        assert_eq!(published.source.len(), PAGE);
        let prepared = Prepared::fork(setup, &self.log);
        let child = &prepared.child;
        let setup_registers = child.registers();
        assert_eq!(setup_registers.fs_base, original.initial.fs_base);
        assert_eq!(setup_registers.gs_base, original.initial.gs_base);
        child.set_registers(&original.initial);
        child.set_xstate(&original.xstate);
        let heads: Vec<_> = original.points.iter().map(|p| p.logical_pc).collect();
        let (actual, steps) = self.walk(child, &heads, &published);
        assert_eq!(actual.len(), original.points.len());
        for (expected, observed) in original.points.iter().zip(&actual) {
            assert_state(expected, observed);
        }
        prepared.finish(output, steps, actual.len(), actual.len());
        assert_eq!(
            self.inner.code.bytes(),
            self.source(),
            "child changed parent source"
        );
    }

    fn walk(
        &self,
        child: &Tracee,
        heads: &[u64],
        published: &Published<'_>,
    ) -> (Vec<Snapshot>, usize) {
        let mut points = Vec::new();
        let mut steps = 0;
        for &logical in heads {
            let physical = published
                .boundaries
                .iter()
                .find(|&&(original, _)| original == logical)
                .map_or(logical, |&(_, p)| p);
            while child.registers().rip != physical {
                assert!(steps < MAX_STEPS, "oracle instruction budget exhausted");
                child.step(&[]); // No routed, faulting, or alternate trap entry in these MOV leaves.
                steps += 1;
            }
            points.push(self.inner.snapshot(child, logical, published.source));
            for (address, bytes) in published.images {
                assert_eq!(
                    child.memory(*address, bytes.len()),
                    *bytes,
                    "immutable image changed"
                );
            }
            self.log.assert_events(child, published.events);
        }
        (points, steps)
    }
}

struct Prepared {
    child: Tracee,
    resume: libc::user_regs_struct,
    xstate: Vec<u8>,
}
impl Prepared {
    fn fork<F, G>(setup: F, log: &HookEventLog) -> Self
    where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        // The event-log pointer/storage are inherited private/COW. No model
        // registration, PointThread or physical owner is inherited. Each
        // child performs those distinct setup operations before seed.
        let _active = log.activate();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let finish = setup();
            let _trace_log = log.activate(); // Exclude, but do not hide, separately asserted setup calls.
            unsafe {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) != 0 {
                    libc::_exit(120);
                }
                libc::raise(libc::SIGSTOP);
            }
            // Only after all application comparisons, restore the saved setup
            // continuation to check reports/drop TLS. Never repair an app state.
            finish();
            assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
            unsafe { libc::_exit(0) };
        }
        let child = Tracee {
            pid,
            deadline: Instant::now() + CHILD_BUDGET,
            reaped: Cell::new(false),
        };
        let status = child.wait();
        assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
        child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        let tasks: Vec<_> = std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(tasks, vec![std::ffi::OsString::from(pid.to_string())]);
        Self {
            resume: child.registers(),
            xstate: child.xstate(),
            child,
        }
    }
    fn finish(self, output: &Path, steps: usize, boundaries: usize, comparisons: usize) {
        self.child.set_registers(&self.resume);
        self.child.set_xstate(&self.xstate);
        self.child.request(libc::PTRACE_CONT, 0, 0);
        let status = self.child.wait();
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert!(self.child.reaped.get());
        let mut unused = 0;
        assert_eq!(
            unsafe { libc::waitpid(self.child.pid, &mut unused, libc::WNOHANG | libc::__WALL) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        std::fs::write(output, format!(
            "{{\"pid\":{},\"wait_status\":{},\"echild\":true,\"steps\":{},\"boundaries\":{},\"full_state_comparisons\":{},\"trace_seconds\":15,\"max_steps\":20000}}\n",
            self.child.pid, status, steps, boundaries, comparisons)).unwrap();
    }
}
