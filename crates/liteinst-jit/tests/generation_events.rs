//! Mapping events reported by the caller, in-process: the
//! generation-based invalidation P1B-DESIGN.md §2/§3 relies on.
//!
//! - `remap_runs_new_bytes_inprocess`: the handler replaces the code
//!   page with different bytes during a syscall and reports it; the
//!   guest then resumes at a block start in that page and runs the NEW
//!   bytes (the old translation must not run).
//! - `unmapped_return_refuses_inprocess`: the handler unmaps the page
//!   and reports it; resuming into it refuses `UnmappedCode`.
//! - `retranslate_after_event_keeps_generation`: after the event the
//!   executable is at the event's generation, retranslated once, and a
//!   later run does not retranslate again.
//! - `stale_event_refuses`: an event that is not strictly newer
//!   refuses `StaleGeneration`, naming both generations.
//! - `no_event_unchanged`: a handler that reports nothing runs as
//!   before, with no retranslation.
//! - `direct_edge_into_hole_refuses`: a direct jump into a range
//!   reported unmapped refuses at the jump; nothing is chained into the
//!   old code.
//! - `whole_region_unmapped_refuses`: `invalidate` over the whole
//!   region, then a run refuses `UnmappedCode` at the entry.
//!
//! The in-process dispatcher has process-global state, so every test
//! holds the serial lock.

use liteinst_jit::exec::{Executable, Handler, ProcessMemory, Resume, RunError};
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::types::{CountProfile, Generation, MappingEvent};
use liteinst_jit::{GuestState, Refuse};

#[path = "common/deadline.rs"]
mod deadline;

const PAGE: usize = 4096;

/// `mov eax, 39; syscall; mov eax, 1; ret`: the block at +7 starts
/// right after the syscall exit.
const OLD: &[u8] = &[
    0xb8, 0x27, 0x00, 0x00, 0x00, // 00 mov eax, 39 (getpid)
    0x0f, 0x05, // 05 syscall
    0xb8, 0x01, 0x00, 0x00, 0x00, // 07 mov eax, 1
    0xc3, // 0c ret
];
/// OLD with `mov eax, 2` at +7.
const NEW: &[u8] = &[
    0xb8, 0x27, 0x00, 0x00, 0x00, // 00 mov eax, 39 (getpid)
    0x0f, 0x05, // 05 syscall
    0xb8, 0x02, 0x00, 0x00, 0x00, // 07 mov eax, 2
    0xc3, // 0c ret
];
const AFTER_SYSCALL: u64 = 0x07;

/// A direct jump from +7 to +0x20, which a later event unmaps.
const JUMP_INTO: &[u8] = &[
    0xb8, 0x27, 0x00, 0x00, 0x00, // 00 mov eax, 39 (getpid)
    0x0f, 0x05, // 05 syscall
    0xe9, 0x14, 0x00, 0x00, 0x00, // 07 jmp 0x20
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 0c nop (never reached)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 14 nop
    0x90, 0x90, 0x90, 0x90, // 1c nop
    0xb8, 0x03, 0x00, 0x00, 0x00, // 20 mov eax, 3
    0xc3, // 25 ret
];
const JUMP_TARGET: u64 = 0x20;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One test's hold: the serial lock, then the test's bound (see
/// `common/deadline.rs`).
struct Serial {
    _lock: std::sync::MutexGuard<'static, ()>,
    _bound: deadline::TestBound,
}

fn lock() -> Serial {
    Serial {
        _lock: deadline::serial_lock(&SERIAL),
        _bound: deadline::TestBound::arm(),
    }
}

/// Replace the guest code page at `base` with `bytes`, as a guest's
/// `munmap` then `mmap(MAP_FIXED)` of different bytes would.
fn remap(base: u64, bytes: &[u8]) {
    // SAFETY: `base` is the test's own guest code page, PAGE bytes long.
    unsafe {
        assert_eq!(libc::munmap(base as *mut libc::c_void, PAGE), 0);
        let p = libc::mmap(
            base as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );
        assert_eq!(p as u64, base);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, bytes.len());
        assert_eq!(
            libc::mprotect(
                base as *mut libc::c_void,
                PAGE,
                libc::PROT_READ | libc::PROT_EXEC
            ),
            0
        );
    }
}

/// Serves the fixture's one `getpid` exit as native execution would,
/// makes the scripted mapping change, and reports the scripted event.
struct MapHandler {
    base: u64,
    /// Replace the code page with these bytes during the syscall.
    remap_to: Option<&'static [u8]>,
    /// Unmap the code page during the syscall.
    unmap: bool,
    /// The event reported after the syscall, once.
    event: Option<MappingEvent>,
    served: u32,
}

impl MapHandler {
    fn new(base: u64) -> MapHandler {
        MapHandler {
            base,
            remap_to: None,
            unmap: false,
            event: None,
            served: 0,
        }
    }
}

impl Handler for MapHandler {
    fn syscall(
        &mut self,
        state: &mut GuestState,
        _insn_pc: u64,
        next_pc: u64,
    ) -> Result<Resume, Refuse> {
        // SAFETY: getpid has no arguments and cannot fail.
        state.rax = unsafe { libc::getpid() } as u64;
        state.rcx = next_pc;
        state.r11 = state.rflags;
        if let Some(bytes) = self.remap_to.take() {
            remap(self.base, bytes);
        }
        if self.unmap {
            self.unmap = false;
            // SAFETY: the test's own guest code page.
            assert_eq!(
                unsafe { libc::munmap(self.base as *mut libc::c_void, PAGE) },
                0
            );
        }
        self.served += 1;
        Ok(Resume::At(next_pc))
    }

    fn take_mapping_events(&mut self) -> Vec<MappingEvent> {
        self.event.take().into_iter().collect()
    }
}

/// A prepared executable over `bytes` at generation 1.
fn prepared(bytes: &[u8]) -> (MappedGuest, Executable) {
    let guest = MappedGuest::map(bytes).expect("map");
    let region = guest.region(bytes, Generation(1));
    let exec = Executable::prepare(&region, guest.base, CountProfile::Branches).expect("prepare");
    (guest, exec)
}

/// The remap scenario: OLD prepared, NEW mapped and reported (at
/// generation 2) during the syscall.
fn remap_handler(guest: &MappedGuest) -> MapHandler {
    let mut h = MapHandler::new(guest.base);
    h.remap_to = Some(NEW);
    h.event = Some(MappingEvent {
        start: guest.base,
        end: guest.base + PAGE as u64,
        region: Some(guest.region(NEW, Generation(2))),
    });
    h
}

#[test]
fn remap_runs_new_bytes_inprocess() {
    let _g = lock();
    let (guest, mut exec) = prepared(OLD);
    let mut h = remap_handler(&guest);
    let out = exec
        .run(
            guest.initial_state(),
            &mut h,
            &ProcessMemory,
            RETURN_SENTINEL,
        )
        .expect("run");
    assert_eq!(h.served, 1, "remap: the syscall exit was not served once");
    assert_eq!(
        out.state.rax, 2,
        "remap: want the new bytes (rax 2), got {}",
        out.state.rax
    );
    assert_eq!(exec.retranslations(), 1, "remap: want one retranslation");
    assert_eq!(exec.generation(), Generation(2));
}

#[test]
fn unmapped_return_refuses_inprocess() {
    let _g = lock();
    let (guest, mut exec) = prepared(OLD);
    let mut h = MapHandler::new(guest.base);
    h.unmap = true;
    h.event = Some(MappingEvent {
        start: guest.base,
        end: guest.base + PAGE as u64,
        region: None,
    });
    let r = exec.run(
        guest.initial_state(),
        &mut h,
        &ProcessMemory,
        RETURN_SENTINEL,
    );
    let want = guest.base + AFTER_SYSCALL;
    assert!(
        matches!(
            r,
            Err(RunError::Refuse(Refuse::UnmappedCode { src_pc, generation: 2 })) if src_pc == want
        ),
        "unmapped: want UnmappedCode at {want:#x} under generation 2, got {r:?}"
    );
    assert_eq!(h.served, 1);
}

#[test]
fn retranslate_after_event_keeps_generation() {
    let _g = lock();
    let (guest, mut exec) = prepared(OLD);
    let mut h = remap_handler(&guest);
    let first = exec
        .run(
            guest.initial_state(),
            &mut h,
            &ProcessMemory,
            RETURN_SENTINEL,
        )
        .expect("first run");
    assert_eq!(first.state.rax, 2);
    // A second run with no event: the translation is current, so it
    // is reused and the generation stays the event's.
    let mut quiet = MapHandler::new(guest.base);
    let second = exec
        .run(
            guest.initial_state(),
            &mut quiet,
            &ProcessMemory,
            RETURN_SENTINEL,
        )
        .expect("second run");
    assert_eq!(
        second.state.rax, 2,
        "generation: the new bytes must still run"
    );
    assert_eq!(
        exec.retranslations(),
        1,
        "generation: want one retranslation in all, got {}",
        exec.retranslations()
    );
    assert_eq!(exec.generation(), Generation(2));
}

#[test]
fn stale_event_refuses() {
    let _g = lock();
    let (guest, mut exec) = prepared(OLD);
    let mut h = MapHandler::new(guest.base);
    h.event = Some(MappingEvent {
        start: guest.base,
        end: guest.base + PAGE as u64,
        region: Some(guest.region(NEW, Generation(1))),
    });
    let r = exec.run(
        guest.initial_state(),
        &mut h,
        &ProcessMemory,
        RETURN_SENTINEL,
    );
    assert!(
        matches!(
            r,
            Err(RunError::Refuse(Refuse::StaleGeneration {
                expected: 2,
                found: 1
            }))
        ),
        "stale: want StaleGeneration {{ expected: 2, found: 1 }}, got {r:?}"
    );
}

#[test]
fn no_event_unchanged() {
    let _g = lock();
    let (guest, mut exec) = prepared(OLD);
    let mut h = MapHandler::new(guest.base);
    let out = exec
        .run(
            guest.initial_state(),
            &mut h,
            &ProcessMemory,
            RETURN_SENTINEL,
        )
        .expect("run");
    assert_eq!(out.state.rax, 1);
    assert_eq!(exec.retranslations(), 0);
    assert_eq!(exec.generation(), Generation(1));
}

#[test]
fn direct_edge_into_hole_refuses() {
    let _g = lock();
    let (guest, mut exec) = prepared(JUMP_INTO);
    let mut h = MapHandler::new(guest.base);
    h.event = Some(MappingEvent {
        start: guest.base + JUMP_TARGET,
        end: guest.base + JUMP_INTO.len() as u64,
        region: None,
    });
    let r = exec.run(
        guest.initial_state(),
        &mut h,
        &ProcessMemory,
        RETURN_SENTINEL,
    );
    let jmp = guest.base + AFTER_SYSCALL;
    assert!(
        matches!(
            r,
            Err(RunError::Refuse(Refuse::UnmappedCode { src_pc, generation: 2 })) if src_pc == jmp
        ),
        "hole: want UnmappedCode at the jump {jmp:#x}, got {r:?}"
    );
}

#[test]
fn whole_region_unmapped_refuses() {
    let _g = lock();
    let (guest, mut exec) = prepared(OLD);
    exec.invalidate(guest.base, guest.base + PAGE as u64, Generation(2))
        .expect("invalidate");
    let mut h = MapHandler::new(guest.base);
    let r = exec.run(
        guest.initial_state(),
        &mut h,
        &ProcessMemory,
        RETURN_SENTINEL,
    );
    let entry = guest.base;
    assert!(
        matches!(
            r,
            Err(RunError::Refuse(Refuse::UnmappedCode { src_pc, generation: 2 })) if src_pc == entry
        ),
        "unmapped: want UnmappedCode at the entry, got {r:?}"
    );
    assert_eq!(h.served, 0, "unmapped: nothing may run");
}

/// Spawn census (I1-H H2c): this binary starts no child.
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("generation_events.rs"), "generation_events.rs");
}

/// Bound census (I1-H H2d): every test here arms a `TestBound`
/// (`common/deadline.rs`).
#[test]
fn bound_census() {
    deadline::bound_census(
        include_str!("generation_events.rs"),
        "generation_events.rs",
        &["spawn_census", "bound_census"],
    );
}
