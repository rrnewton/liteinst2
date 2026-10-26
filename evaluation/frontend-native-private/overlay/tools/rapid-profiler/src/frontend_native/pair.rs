//! Bounded native-pair metadata. Every original model body remains unchanged.
use crate::frontend::{EntryError, ModelReturnSlot, Observation, Session, ThreadModel};
use crate::generation::{Admission, AdmissionRefusal, FunctionId};
use liteinst2::trampoline::HookContext;
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::rc::Rc;
use std::thread::{self, ThreadId};

const PAIRS: usize = 4;
const EVENTS: usize = 64;
const TOKEN: u64 = 0x71a1_5eaf_1188_2244;
type EntryGate = unsafe extern "C" fn(u64);
type EntryOutcome = (u64, Option<EntryGate>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Explicit failure; no invariant violation is reported as an observation.
pub enum NativeError {
    /// TLS is unavailable, borrowed, already attached or previously poisoned.
    Attachment,
    /// Setup has inconsistent identities, addresses or bounds.
    InvalidSetup,
    /// The existing session refused its bounded model registration.
    ModelSetup,
    /// The actual callback thread, PC or stack is outside its certified owner.
    CallbackIdentity,
    /// The bounded pair stack, journal or nonwrapping ordinal is exhausted.
    Capacity,
    /// The real return identity is not the top pair; no frame was popped.
    ReturnIdentity,
    /// The original model refused completion or returned a foreign identity.
    Completion,
    /// Detach has an outstanding native/model frame.
    Outstanding,
}

/// One private 4-KiB journal. It is deliberately separate from application
/// memory, with a complete exact byte inventory and zero unused tail.
pub struct Journal {
    address: *mut u64,
}
impl Journal {
    /// Allocate before callbacks. This object is intentionally process-lived;
    /// its owner never unmaps memory reachable from a callback or tracee.
    pub fn allocate() -> Result<&'static Self, NativeError> {
        // SAFETY: fresh anonymous private mapping; no fixed address or alias.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(NativeError::Capacity);
        }
        Ok(Box::leak(Box::new(Self { address: p.cast() })))
    }
    /// Exact process-local journal address, for an owned ptrace reader only.
    pub fn address(&self) -> u64 {
        self.address as usize as u64
    }
    fn header(&self, tid: u64, depth: usize) {
        // SAFETY: only the attached application thread writes this private page.
        unsafe {
            self.address.add(2).write_volatile(tid);
            self.address.add(3).write_volatile(depth as u64);
        }
    }
    fn record(&self, row: [u64; 7]) -> Result<(), NativeError> {
        // SAFETY: a checked fixed row fits inside the exclusive 4096-byte page.
        unsafe {
            let n = self.address.read_volatile() as usize;
            if n >= EVENTS {
                return Err(NativeError::Capacity);
            }
            for (i, value) in row.iter().enumerate() {
                self.address.add(4 + n * 7 + i).write_volatile(*value);
            }
            self.address.write_volatile((n + 1) as u64);
        }
        Ok(())
    }
    fn poison(&self) {
        // SAFETY: retained page; only this thread owns the poison cell.
        unsafe { self.address.add(1).write_volatile(1) };
    }
}

#[derive(Clone, Copy)]
/// Setup authority for exactly one fixed installation on the current thread.
pub struct Attach {
    /// Existing session installation identity.
    pub install: u64,
    /// Existing function identity.
    pub function: FunctionId,
    /// Real loaded entry.
    pub entry: u64,
    /// Real loaded sole RET.
    pub ret: u64,
    /// Inclusive lower bound of the caller-certified readable stack range.
    pub stack_start: u64,
    /// Exclusive upper bound, including the complete original return word.
    pub stack_end: u64,
    /// Explicit session registration key, never retried on collision.
    pub registration: u64,
    /// Optional non-unwinding test gate, called AFTER releasing the TLS borrow.
    pub after_entry: Option<unsafe extern "C" fn(u64)>,
}

#[derive(Clone, Copy)]
struct Pair {
    ordinal: u64,
    rsp: u64,
    return_word: u64,
    slot: ModelReturnSlot,
    admission: Result<Admission, EntryError>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Exact paired outcomes, separate from the count of machine instructions.
pub struct NativeTotals {
    /// Entry callbacks which created pairs.
    pub entries: u64,
    /// RET callbacks which consumed those exact pairs.
    pub returns: u64,
    /// Original-owner model completions.
    pub completed: u64,
    /// Paired entry refusals caused by an already closed per-function budget.
    pub refused: u64,
}

struct State {
    actual_thread: ThreadId,
    tid: u64,
    setup: Attach,
    model: ThreadModel,
    pairs: [Option<Pair>; PAIRS],
    depth: usize,
    next: u64,
    totals: NativeTotals,
    journal: &'static Journal,
}
thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static POISONED: Cell<bool> = const { Cell::new(false) };
}

/// Actual-thread attachment, with no ticket/epoch/model extraction API.
/// A forgotten attachment stays in TLS. Poison retains its model until ordinary
/// TLS destruction; it never grants native return repair or code reclamation.
pub struct NativeThread {
    thread: ThreadId,
    active: bool,
    _local: PhantomData<Rc<()>>,
}
impl NativeThread {
    /// Install preallocated model state before the first machine entry.
    ///
    /// # Safety
    /// The declared stack is readable through every matching RET. Entry/RET
    /// belong to the same authenticated fixed leaf; no nonlocal exits, signals,
    /// recursive writers or foreign unwind may cross this callback boundary.
    pub unsafe fn attach(
        session: &Session,
        setup: Attach,
        journal: &'static Journal,
    ) -> Result<Self, NativeError> {
        if setup.install == 0
            || setup.registration == 0
            || setup.entry.checked_add(18) != Some(setup.ret)
            || setup
                .stack_start
                .checked_add(8)
                .is_none_or(|end| end > setup.stack_end)
        {
            return Err(NativeError::InvalidSetup);
        }
        let model = session
            .register_thread(setup.registration)
            .map_err(|_| NativeError::ModelSetup)?;
        let actual_thread = thread::current().id();
        // SAFETY: read-only kernel thread identity.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        STATE
            .try_with(|cell| {
                if POISONED.get() {
                    return Err(NativeError::Attachment);
                }
                let mut state = cell.try_borrow_mut().map_err(|_| NativeError::Attachment)?;
                if state.is_some() {
                    return Err(NativeError::Attachment);
                }
                journal.header(tid, 0);
                *state = Some(State {
                    actual_thread,
                    tid,
                    setup,
                    model,
                    pairs: [None; PAIRS],
                    depth: 0,
                    next: 1,
                    totals: NativeTotals::default(),
                    journal,
                });
                Ok(Self {
                    thread: actual_thread,
                    active: true,
                    _local: PhantomData,
                })
            })
            .unwrap_or(Err(NativeError::Attachment))
    }
    /// Read final paired totals after machine execution is quiescent.
    pub fn totals(&self) -> Result<NativeTotals, NativeError> {
        if thread::current().id() != self.thread {
            return Err(NativeError::Attachment);
        }
        STATE
            .try_with(|cell| {
                let state = cell.try_borrow().map_err(|_| NativeError::Attachment)?;
                let state = state.as_ref().ok_or(NativeError::Attachment)?;
                if POISONED.get() || state.depth != 0 || state.model.depth() != 0 {
                    return Err(NativeError::Outstanding);
                }
                Ok(state.totals)
            })
            .unwrap_or(Err(NativeError::Attachment))
    }
    /// Detach only an empty, unpoisoned native/model stack.
    pub fn detach(mut self) -> Result<NativeTotals, NativeError> {
        let totals = self.totals()?;
        STATE.with(|cell| {
            cell.borrow_mut().take();
        });
        self.active = false;
        Ok(totals)
    }
}
impl Drop for NativeThread {
    fn drop(&mut self) {
        if self.active {
            if self.totals().is_ok() {
                let _ = STATE.try_with(|cell| {
                    cell.borrow_mut().take();
                });
            } else {
                let _ = POISONED.try_with(|p| p.set(true));
            }
        }
    }
}

fn identity(state: &State, context: &HookContext, pc: u64) -> Result<u64, NativeError> {
    if state.actual_thread != thread::current().id()
        || context.instruction_pointer != pc
        || context.stack_pointer < state.setup.stack_start
        || context
            .stack_pointer
            .checked_add(8)
            .is_none_or(|end| end > state.setup.stack_end)
    {
        return Err(NativeError::CallbackIdentity);
    }
    // SAFETY: setup certifies the live readable stack; comparison never writes it.
    Ok(unsafe { (context.stack_pointer as usize as *const u64).read_unaligned() })
}

fn entry(context: &HookContext) -> Result<EntryOutcome, NativeError> {
    STATE
        .try_with(|cell| {
            if POISONED.get() {
                return Err(NativeError::Attachment);
            }
            let mut storage = cell.try_borrow_mut().map_err(|_| NativeError::Attachment)?;
            let state = storage.as_mut().ok_or(NativeError::Attachment)?;
            let return_word = identity(state, context, state.setup.entry)?;
            if state.depth == PAIRS {
                return Err(NativeError::Capacity);
            }
            let ordinal = state.next;
            state.next = ordinal.checked_add(1).ok_or(NativeError::Capacity)?;
            let mut slot = ModelReturnSlot {
                identity: ordinal,
                word: TOKEN,
            };
            let admission = state.model.enter(
                state.setup.install,
                state.setup.function,
                ordinal,
                &mut slot,
            );
            let (kind, generation, invocation) = match admission {
                Ok(a) => (1, a.generation.get(), a.invocation as u64 + 1),
                Err(EntryError::Generation(AdmissionRefusal::FunctionClosed)) => (3, 0, 1),
                Err(_) => return Err(NativeError::Completion),
            };
            state.pairs[state.depth] = Some(Pair {
                ordinal,
                rsp: context.stack_pointer,
                return_word,
                slot,
                admission,
            });
            state.depth += 1;
            state.totals.entries += 1;
            state.journal.header(state.tid, state.depth);
            state.journal.record([
                kind,
                ordinal,
                context.instruction_pointer,
                context.stack_pointer,
                return_word,
                generation,
                invocation,
            ])?;
            Ok((ordinal, state.setup.after_entry))
        })
        .unwrap_or(Err(NativeError::Attachment))
}

fn finish(context: &HookContext) -> Result<(), NativeError> {
    STATE
        .try_with(|cell| {
            if POISONED.get() {
                return Err(NativeError::Attachment);
            }
            let mut storage = cell.try_borrow_mut().map_err(|_| NativeError::Attachment)?;
            let state = storage.as_mut().ok_or(NativeError::Attachment)?;
            let return_word = identity(state, context, state.setup.ret)?;
            let index = state
                .depth
                .checked_sub(1)
                .ok_or(NativeError::ReturnIdentity)?;
            let pair = state.pairs[index]
                .as_mut()
                .ok_or(NativeError::ReturnIdentity)?;
            if pair.rsp != context.stack_pointer || pair.return_word != return_word {
                return Err(NativeError::ReturnIdentity);
            }
            let (kind, generation, invocation) = match pair.admission {
                Ok(a) => {
                    let (completion, payload) = state
                        .model
                        .finish(&mut pair.slot, Observation::Value(pair.ordinal))
                        .map_err(|_| NativeError::Completion)?;
                    if completion.admission != a
                        || payload.admission != a
                        || payload.thread != state.setup.registration
                        || pair.slot.word != TOKEN
                    {
                        return Err(NativeError::Completion);
                    }
                    state.totals.completed += 1;
                    (2, a.generation.get(), a.invocation as u64 + 1)
                }
                Err(EntryError::Generation(AdmissionRefusal::FunctionClosed)) => {
                    if pair.slot.word != TOKEN {
                        return Err(NativeError::Completion);
                    }
                    state.totals.refused += 1;
                    (4, 0, 1)
                }
                Err(_) => return Err(NativeError::Completion),
            };
            state.journal.record([
                kind,
                pair.ordinal,
                context.instruction_pointer,
                context.stack_pointer,
                return_word,
                generation,
                invocation,
            ])?;
            state.pairs[index] = None;
            state.depth = index;
            state.totals.returns += 1;
            state.journal.header(state.tid, state.depth);
            Ok(())
        })
        .unwrap_or(Err(NativeError::Attachment))
}

fn fatal() -> ! {
    let _ = POISONED.try_with(|p| p.set(true));
    let _ = STATE.try_with(|cell| {
        if let Ok(state) = cell.try_borrow() {
            if let Some(state) = state.as_ref() {
                state.journal.poison();
            }
        }
    });
    // SAFETY: isolated fixture failure; no Rust panic crosses the C ABI.
    unsafe { libc::_exit(123) }
}

/// Real generated-entry callback; preserves the application's return word.
///
/// # Safety
/// Called only by the admitted full-state trampoline, with a live saved frame
/// and the current thread's matching pre-registered native attachment.
pub unsafe extern "C" fn entry_callback(context: *mut HookContext) {
    if context.is_null() {
        fatal();
    }
    // SAFETY: the generated dispatcher owns the supplied live saved frame.
    let (ordinal, gate) = match entry(unsafe { &*context }) {
        Ok(x) => x,
        Err(_) => fatal(),
    };
    if let Some(gate) = gate {
        // SAFETY: setup admits a non-unwinding fixture gate. No TLS borrow lives.
        unsafe { gate(ordinal) };
    }
}

/// Real pre-RET callback; completes only the matching admitting owner.
///
/// # Safety
/// Same saved-frame contract as entry_callback, at the exact admitted RET.
pub unsafe extern "C" fn exit_callback(context: *mut HookContext) {
    if context.is_null() || finish(unsafe { &*context }).is_err() {
        fatal();
    }
}
