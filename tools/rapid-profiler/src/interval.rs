use core::cell::RefCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

use liteinst2::rapid::RapidProbe;
use liteinst2::trampoline::HookContext;

use crate::BoxError;
use crate::pmu::{CounterDelta, CounterSet, CounterSnapshot};

core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .globl rapid_profiler_exit_trampoline
    .type rapid_profiler_exit_trampoline,@function
rapid_profiler_exit_trampoline:
    sub rsp, 48
    mov [rsp], rax
    mov [rsp + 8], rdx
    movdqu [rsp + 16], xmm0
    movdqu [rsp + 32], xmm1
    mov rdi, rax
    call rapid_profiler_finish
    mov r11, rax
    mov rax, [rsp]
    mov rdx, [rsp + 8]
    movdqu xmm0, [rsp + 16]
    movdqu xmm1, [rsp + 32]
    add rsp, 48
    jmp r11
    .size rapid_profiler_exit_trampoline, .-rapid_profiler_exit_trampoline
"#
);

unsafe extern "C" {
    fn rapid_profiler_exit_trampoline();
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricSummary {
    pub samples: u64,
    pub total: u64,
    pub min: u64,
    pub max: u64,
}

impl MetricSummary {
    pub fn average(self) -> u64 {
        self.total.checked_div(self.samples).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SampleClassSummary {
    pub samples: u64,
    pub instructions: MetricSummary,
    pub branches: MetricSummary,
    pub l2_misses: MetricSummary,
    pub elapsed_ticks: MetricSummary,
    pub other_samples: MetricSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionCount {
    pub function: String,
    pub count: u64,
    pub self_disabled: bool,
    pub leaf: SampleClassSummary,
    pub non_leaf: SampleClassSummary,
    pub last_return_value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochReport {
    pub epoch: usize,
    pub workload_result: u64,
    pub functions: Vec<FunctionCount>,
}

struct AtomicDistribution {
    samples: AtomicU64,
    total: AtomicU64,
    min: AtomicU64,
    max: AtomicU64,
}

impl AtomicDistribution {
    fn new() -> Self {
        Self {
            samples: AtomicU64::new(0),
            total: AtomicU64::new(0),
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
        }
    }

    fn record(&self, value: u64) {
        self.samples.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .total
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(value))
            });
        self.min.fetch_min(value, Ordering::Relaxed);
        self.max.fetch_max(value, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.samples.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        self.min.store(u64::MAX, Ordering::Relaxed);
        self.max.store(0, Ordering::Relaxed);
    }

    fn summary(&self) -> MetricSummary {
        let samples = self.samples.load(Ordering::Acquire);
        MetricSummary {
            samples,
            total: self.total.load(Ordering::Acquire),
            min: if samples == 0 {
                0
            } else {
                self.min.load(Ordering::Acquire)
            },
            max: self.max.load(Ordering::Acquire),
        }
    }
}

struct SampleClassStats {
    samples: AtomicU64,
    instructions: AtomicDistribution,
    branches: AtomicDistribution,
    l2_misses: AtomicDistribution,
    elapsed_ticks: AtomicDistribution,
    other_samples: AtomicDistribution,
}

impl SampleClassStats {
    fn new() -> Self {
        Self {
            samples: AtomicU64::new(0),
            instructions: AtomicDistribution::new(),
            branches: AtomicDistribution::new(),
            l2_misses: AtomicDistribution::new(),
            elapsed_ticks: AtomicDistribution::new(),
            other_samples: AtomicDistribution::new(),
        }
    }

    fn record(&self, counters: CounterDelta, other_samples: u64) {
        self.samples.fetch_add(1, Ordering::Relaxed);
        if let Some(value) = counters.instructions {
            self.instructions.record(value);
        }
        if let Some(value) = counters.branches {
            self.branches.record(value);
        }
        if let Some(value) = counters.l2_misses {
            self.l2_misses.record(value);
        }
        self.elapsed_ticks.record(counters.elapsed_ticks);
        self.other_samples.record(other_samples);
    }

    fn reset(&self) {
        self.samples.store(0, Ordering::Relaxed);
        self.instructions.reset();
        self.branches.reset();
        self.l2_misses.reset();
        self.elapsed_ticks.reset();
        self.other_samples.reset();
    }

    fn summary(&self) -> SampleClassSummary {
        SampleClassSummary {
            samples: self.samples.load(Ordering::Acquire),
            instructions: self.instructions.summary(),
            branches: self.branches.summary(),
            l2_misses: self.l2_misses.summary(),
            elapsed_ticks: self.elapsed_ticks.summary(),
            other_samples: self.other_samples.summary(),
        }
    }
}

pub(crate) struct FunctionEntry {
    name: String,
    pub(crate) address: u64,
    count: AtomicU64,
    self_disabled: AtomicBool,
    leaf: SampleClassStats,
    non_leaf: SampleClassStats,
    last_return_value: AtomicU64,
    probe: RapidProbe,
}

impl FunctionEntry {
    pub(crate) fn new(name: String, address: u64, probe: RapidProbe) -> Self {
        Self {
            name,
            address,
            count: AtomicU64::new(0),
            self_disabled: AtomicBool::new(false),
            leaf: SampleClassStats::new(),
            non_leaf: SampleClassStats::new(),
            last_return_value: AtomicU64::new(0),
            probe,
        }
    }

    fn reset(&self) {
        self.count.store(0, Ordering::Release);
        self.self_disabled.store(false, Ordering::Release);
        self.leaf.reset();
        self.non_leaf.reset();
        self.last_return_value.store(0, Ordering::Release);
    }

    fn report(&self) -> FunctionCount {
        FunctionCount {
            function: self.name.clone(),
            count: self.count.load(Ordering::Acquire),
            self_disabled: self.self_disabled.load(Ordering::Acquire),
            leaf: self.leaf.summary(),
            non_leaf: self.non_leaf.summary(),
            last_return_value: self.last_return_value.load(Ordering::Acquire),
        }
    }
}

pub(crate) struct ProfilerState {
    entries: Vec<FunctionEntry>,
    limit: u64,
}

impl ProfilerState {
    pub(crate) fn new(entries: Vec<FunctionEntry>, limit: u64) -> Self {
        Self { entries, limit }
    }

    fn begin(&self, context: &HookContext) {
        let Ok(index) = self
            .entries
            .binary_search_by_key(&context.instruction_pointer, |entry| entry.address)
        else {
            return;
        };
        let entry = &self.entries[index];
        if entry.count.load(Ordering::Acquire) >= self.limit {
            entry.probe.disable();
            return;
        }
        let return_slot = context.stack_pointer as *mut u64;
        if return_slot.is_null() {
            return;
        }
        // SAFETY: the callback runs at a System V function entry, where RSP
        // points to the caller's live return-address slot.
        let original_return = unsafe { return_slot.read() };
        let frame = THREAD_STATE.with(|thread| {
            let thread = thread.borrow_mut();
            Frame {
                function_index: index,
                original_return,
                start: thread.counters.snapshot(),
                completed_at_start: thread.completed_sequence,
            }
        });
        THREAD_STATE.with(|thread| thread.borrow_mut().frames.push(frame));
        // SAFETY: return_slot remains the live return address for this dynamic
        // invocation until the function executes RET.
        unsafe { return_slot.write(exit_trampoline_address()) };
    }

    fn finish(&self, frame: Frame, end: CounterSnapshot, other_samples: u64, return_value: u64) {
        let entry = &self.entries[frame.function_index];
        let Some(reached_limit) = take_sample(&entry.count, self.limit) else {
            return;
        };
        let counters = end.delta(frame.start);
        if other_samples == 0 {
            entry.leaf.record(counters, 0);
        } else {
            entry.non_leaf.record(counters, other_samples);
        }
        entry
            .last_return_value
            .store(return_value, Ordering::Release);
        if reached_limit {
            entry.self_disabled.store(true, Ordering::Release);
            entry.probe.disable();
        }
    }

    fn rearm(&self) {
        for entry in &self.entries {
            entry.reset();
            entry.probe.enable();
        }
    }

    fn disable_all(&self) {
        for entry in &self.entries {
            entry.probe.disable();
        }
    }

    fn report(&self) -> Vec<FunctionCount> {
        let mut functions = self
            .entries
            .iter()
            .map(FunctionEntry::report)
            .collect::<Vec<_>>();
        functions.sort_by(|left, right| left.function.cmp(&right.function));
        functions
    }

    pub(crate) fn run_epoch(
        &self,
        epoch: usize,
        iterations: u64,
        workload_address: u64,
    ) -> Result<EpochReport, BoxError> {
        prepare_thread_epoch()?;
        let state = ptr::from_ref(self).cast_mut();
        ACTIVE_PROFILER
            .compare_exchange(ptr::null_mut(), state, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "another rapid profiler epoch is active")?;
        self.rearm();
        // SAFETY: the loader validates this symbol inside the copied image and
        // Phase 2 retains the Phase 1 workload ABI contract.
        let workload: unsafe extern "C" fn(u64) -> u64 =
            unsafe { core::mem::transmute(workload_address as usize) };
        // SAFETY: the input contract supplies the required workload signature.
        let workload_result = unsafe { workload(iterations) };
        self.disable_all();
        ACTIVE_PROFILER.store(ptr::null_mut(), Ordering::Release);
        ensure_thread_epoch_finished()?;
        Ok(EpochReport {
            epoch,
            workload_result,
            functions: self.report(),
        })
    }
}

#[derive(Clone, Copy)]
struct Frame {
    function_index: usize,
    original_return: u64,
    start: CounterSnapshot,
    completed_at_start: u64,
}

struct ThreadState {
    frames: Vec<Frame>,
    counters: CounterSet,
    completed_sequence: u64,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            frames: Vec::new(),
            counters: CounterSet::open(),
            completed_sequence: 0,
        }
    }
}

thread_local! {
    static THREAD_STATE: RefCell<ThreadState> = RefCell::new(ThreadState::default());
}

static ACTIVE_PROFILER: AtomicPtr<ProfilerState> = AtomicPtr::new(ptr::null_mut());

pub(crate) unsafe extern "C" fn count_function(context: *const HookContext) {
    if context.is_null() {
        return;
    }
    let profiler = ACTIVE_PROFILER.load(Ordering::Acquire);
    if profiler.is_null() {
        return;
    }
    // SAFETY: run_epoch publishes the state while it is boxed and context is
    // owned by the active liteinst2 trampoline callback.
    unsafe { (*profiler).begin(&*context) };
}

#[unsafe(no_mangle)]
extern "C" fn rapid_profiler_finish(return_value: u64) -> u64 {
    let profiler = ACTIVE_PROFILER.load(Ordering::Acquire);
    if profiler.is_null() {
        std::process::abort();
    }
    let (frame, end, other_samples) = THREAD_STATE.with(|thread| {
        let mut thread = thread.borrow_mut();
        let end = thread.counters.snapshot();
        let Some(frame) = thread.frames.pop() else {
            std::process::abort();
        };
        let other_samples = thread
            .completed_sequence
            .wrapping_sub(frame.completed_at_start);
        thread.completed_sequence = thread.completed_sequence.wrapping_add(1);
        (frame, end, other_samples)
    });
    // SAFETY: the state remains published until the synchronous workload returns.
    unsafe { (*profiler).finish(frame, end, other_samples, return_value) };
    frame.original_return
}

fn exit_trampoline_address() -> u64 {
    rapid_profiler_exit_trampoline as usize as u64
}

fn take_sample(counter: &AtomicU64, limit: u64) -> Option<bool> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < limit).then_some(current + 1)
        })
        .ok()
        .map(|previous| previous + 1 == limit)
}

fn prepare_thread_epoch() -> Result<(), BoxError> {
    THREAD_STATE.with(|thread| {
        let mut thread = thread.borrow_mut();
        if !thread.frames.is_empty() {
            return Err("cannot rearm with unfinished function samples".into());
        }
        thread.completed_sequence = 0;
        Ok(())
    })
}

fn ensure_thread_epoch_finished() -> Result<(), BoxError> {
    THREAD_STATE.with(|thread| {
        if thread.borrow().frames.is_empty() {
            Ok(())
        } else {
            Err("workload returned with unfinished function samples".into())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{AtomicDistribution, take_sample};
    use core::sync::atomic::AtomicU64;

    #[test]
    fn sample_slot_saturates_and_identifies_the_kth_completion() {
        let count = AtomicU64::new(998);
        assert_eq!(take_sample(&count, 1_000), Some(false));
        assert_eq!(take_sample(&count, 1_000), Some(true));
        assert_eq!(take_sample(&count, 1_000), None);
    }

    #[test]
    fn distribution_tracks_constant_space_summary() {
        let distribution = AtomicDistribution::new();
        for value in [9, 2, 7] {
            distribution.record(value);
        }
        let summary = distribution.summary();
        assert_eq!(summary.samples, 3);
        assert_eq!(summary.total, 18);
        assert_eq!(summary.min, 2);
        assert_eq!(summary.max, 9);
        assert_eq!(summary.average(), 6);
    }
}
