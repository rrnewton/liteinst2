use crate::{
    gate::{ARMED, PENDING, READY, State},
    plan::{Fetch, PAGE, fetch_instruction},
    raw,
};
use core::sync::atomic::{AtomicPtr, Ordering};

pub(crate) static ACTIVE: AtomicPtr<State> = AtomicPtr::new(core::ptr::null_mut());

pub(crate) extern "C" fn handler(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    let pointer = ACTIVE.load(Ordering::Acquire);
    if pointer.is_null() {
        raw::fatal();
    }
    // SAFETY: published state remains owned until the handler is removed under
    // blocked signals. It is immutable except for fixed atomic state/counters.
    let state = unsafe { &*pointer };
    if state.phase.load(Ordering::Acquire) != ARMED
        || state.handling.swap(true, Ordering::AcqRel)
        || raw::tid() != state.tid
        || signal != libc::SIGSEGV
        || info.is_null()
        || context.is_null()
    {
        state.poison();
    }
    let started = raw::now().unwrap_or_else(|| state.poison());
    // SAFETY: authenticated nonnull native kernel signal ABI arguments.
    let info = unsafe { &*info };
    let context = unsafe { &*context.cast::<libc::ucontext_t>() };
    let registers = &context.uc_mcontext.gregs;
    let register = |index: usize| -> u64 {
        match registers.get(index) {
            Some(value) => *value as u64,
            None => state.poison(),
        }
    };
    if info.si_signo != signal {
        state.poison();
    }
    let fetch = Fetch {
        signal,
        code: info.si_code,
        trap: register(libc::REG_TRAPNO as usize),
        error: register(libc::REG_ERR as usize),
        pc: register(libc::REG_RIP as usize) as usize,
        // SAFETY: synchronous SIGSEGV selects the fault-address union member.
        address: unsafe { info.si_addr() } as usize,
    };
    let instruction = fetch_instruction(state.base, state.len, &state.plan.instructions, fetch)
        .unwrap_or_else(|| state.poison());
    let page = (fetch.address - state.base) / PAGE;
    match state.pages.get(page) {
        Some(status) if status.load(Ordering::Acquire) == PENDING => (),
        _ => state.poison(),
    }
    let bundle = match state.plan.bundles.get(instruction.bundle) {
        Some(bundle) => *bundle,
        None => state.poison(),
    };
    let start = bundle.first_page * PAGE;
    let len = bundle.page_count * PAGE;
    if !state.equal_bytes(start, len) {
        state.poison();
    }
    let mut opened = 0_u64;
    for index in bundle.first_page..bundle.first_page + bundle.page_count {
        match state
            .pages
            .get(index)
            .map(|status| status.load(Ordering::Acquire))
        {
            Some(PENDING) => opened += 1,
            Some(READY) => (),
            _ => state.poison(),
        }
    }
    if opened == 0
        || raw::protect(state.base + start, len, libc::PROT_READ | libc::PROT_EXEC) != 0
        || raw::synchronize() != 0
    {
        state.poison();
    }
    let elapsed = raw::now()
        .and_then(|end| end.checked_sub(started))
        .unwrap_or_else(|| state.poison());
    for index in bundle.first_page..bundle.first_page + bundle.page_count {
        match state.pages.get(index) {
            Some(status) => status.store(READY, Ordering::Release),
            None => state.poison(),
        }
    }
    add(&state.faults, 1, state);
    add(&state.admitted_pages, opened, state);
    add(&state.first_touch_ns, elapsed, state);
    if elapsed > state.max_first_touch_ns.load(Ordering::Relaxed) {
        state.max_first_touch_ns.store(elapsed, Ordering::Release);
    }
    state.handling.store(false, Ordering::Release);
    // The kernel ucontext was never modified: the genuine signal restorer
    // resumes the same fetch with the complete original machine state/mask.
}

fn add(counter: &core::sync::atomic::AtomicU64, value: u64, state: &State) {
    let next = counter
        .load(Ordering::Relaxed)
        .checked_add(value)
        .unwrap_or_else(|| state.poison());
    counter.store(next, Ordering::Release);
}
