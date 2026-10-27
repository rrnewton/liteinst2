//! Disclosed positive-fixture paging preparation, before runtime startup.
//! These records never supply a production stack operand or completion seal.
use super::*;
use crate::linux::remote::dynamic::DynamicEvent;
use fixture::InitialStackPreparation;
use std::ops::Range;
mod io;

const PRELUDE_MAPS: usize = 0;
const PRE_READ: usize = 1;
const BASE_MAPS: usize = 2;
const BASE_SOURCE: usize = 3;
const BASE_STACK: usize = 4;
const PRE_POKE: usize = 5;
const POST_POKE: usize = 6;
const POST_MAPS: usize = 7;
const POST_SOURCE: usize = 8;
const POST_STACK: usize = 9;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Context {
    initial: DynamicEvent,
    until: Instant,
    custody: (i32, i32, i32, bool, bool),
}
impl Context {
    fn require(&self, owner: &Owner) {
        support::held(owner, self.until);
        assert_eq!(support::diagnostic_held(owner, self.until), self.custody);
        assert_eq!(self.initial.tid, owner.pid);
        owner
            .require_stop(self.initial.stop_token().unwrap())
            .unwrap();
        assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
        assert_eq!(self.custody.2 >> 16, libc::PTRACE_EVENT_EXEC);
        assert_eq!(libc::WSTOPSIG(self.custody.2), libc::SIGTRAP);
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Shape {
    entry: u64,
    call_pc: u64,
    next: u64,
    target: u64,
    encoding: [u8; 5],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Poke {
    tid: i32,
    address: u64,
    value: u64,
    result: Option<io::Outcome>,
}
pub(super) struct Evidence {
    policy: InitialStackPreparation,
    started: bool,
    complete: bool,
    context: Option<Context>,
    shape: Option<Shape>,
    stack: Option<Range<u64>>,
    rsp: Option<u64>,
    word: Option<[u8; 8]>,
    poke: Option<Poke>,
    states: [Option<StateSlot>; 3],
    files: [io::FileCapture; 10],
}
impl Evidence {
    pub(super) fn empty(policy: InitialStackPreparation) -> Self {
        Self {
            policy,
            started: false,
            complete: false,
            context: None,
            shape: None,
            stack: None,
            rsp: None,
            word: None,
            poke: None,
            states: std::array::from_fn(|_| None),
            files: std::array::from_fn(|_| io::FileCapture::default()),
        }
    }
    pub(super) fn prepare(
        &mut self,
        owner: &Owner,
        initial: &DynamicEvent,
        program: &Program,
        until: Instant,
        read_stack: bool,
    ) {
        assert_eq!(self.policy, program.preparation);
        assert!(!self.started && !self.complete && self.poke.is_none());
        if self.policy == InitialStackPreparation::Unchanged {
            return;
        }
        self.started = true;
        assert!(read_stack);
        assert_eq!(program.setup, 0);
        assert!(!program.cross_page_stack());
        assert_eq!(program.encoding[0], 0xe8);
        assert_eq!(program.next, program.call_pc.checked_add(5).unwrap());
        self.shape = Some(Shape {
            entry: program.entry,
            call_pc: program.call_pc,
            next: program.next,
            target: program.target,
            encoding: program.encoding,
        });
        self.context = Some(Context {
            initial: initial.clone(),
            until,
            custody: support::diagnostic_held(owner, until),
        });
        let context = self.context.as_ref().unwrap();
        context.require(owner);
        // StateSlot is not Clone. Its installed initialized storage and all
        // three independent query outcomes survive any later error or unwind.
        for slot in &mut self.states {
            *slot = Some(StateSlot::allocate().unwrap());
        }
        capture_state(self.states[0].as_mut().unwrap(), owner, context);
        let initial_state = &self.states[0].as_ref().unwrap().state;
        assert_eq!(initial_state.registers.rip, self.shape.unwrap().entry);
        assert_eq!(initial_state.registers.orig_rax, libc::SYS_execve as u64);
        let rsp = initial_state.registers.rsp;
        self.rsp = Some(rsp);
        assert_eq!(rsp & 15, 0);
        let address = rsp.checked_sub(8).unwrap();
        assert_eq!(address & 7, 0);
        assert_eq!(address / 4096, (rsp - 1) / 4096);
        self.files[PRELUDE_MAPS].capture(owner, context, c"maps", None, MAX_XSTATE);
        let inventory = rows(self.files[PRELUDE_MAPS].bytes());
        let stacks = inventory
            .iter()
            .filter(|r| r.raw.ends_with(b"[stack]"))
            .collect::<Vec<_>>();
        assert_eq!(stacks.len(), 1);
        let stack = stacks[0];
        assert_eq!(stack.permissions, *b"rw-p");
        let columns = stack
            .raw
            .split(|b| b.is_ascii_whitespace())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(columns.len(), 6);
        assert_eq!(columns[2], b"00000000");
        assert_eq!(columns[3], b"00:00");
        assert_eq!(columns[4], b"0");
        assert_eq!(columns[5], b"[stack]");
        let range = stack.start..stack.end;
        self.stack = Some(range.clone());
        assert!(range.start <= address && rsp <= range.end);
        let length = usize::try_from(range.end - range.start).unwrap();
        assert!((1..=1024 * 1024).contains(&length));
        let offset = (address / 4096).checked_mul(8).unwrap();
        // First pagemap observation precedes every source/stack byte read.
        self.files[PRE_READ].capture(owner, context, c"pagemap", Some(offset), 8);
        capture_state(self.states[1].as_mut().unwrap(), owner, context);
        self.files[BASE_MAPS].capture(owner, context, c"maps", None, MAX_XSTATE);
        self.files[BASE_SOURCE].capture(owner, context, c"mem", Some(BASE), 8192);
        self.files[BASE_STACK].capture(owner, context, c"mem", Some(range.start), length);
        assert_eq!(
            self.states[1].as_ref().unwrap().state,
            self.states[0].as_ref().unwrap().state
        );
        assert_eq!(
            self.files[BASE_MAPS].bytes(),
            self.files[PRELUDE_MAPS].bytes()
        );
        let code = usize::try_from(program.call_pc.checked_sub(BASE).unwrap()).unwrap();
        assert_eq!(
            &self.files[BASE_SOURCE].bytes()[code..code.checked_add(5).unwrap()],
            &program.encoding[..]
        );
        let relative = i32::from_le_bytes(program.encoding[1..].try_into().unwrap());
        assert_eq!(
            program
                .next
                .checked_add_signed(i64::from(relative))
                .unwrap(),
            program.target
        );
        let word_offset = usize::try_from(address - range.start).unwrap();
        let word: [u8; 8] = self.files[BASE_STACK].bytes()[word_offset..word_offset + 8]
            .try_into()
            .unwrap();
        self.word = Some(word);
        // The baseline read may affect residency. Keep a distinct actual
        // pre-POKE observation, without interpreting either prior entry as a pass.
        self.files[PRE_POKE].capture(owner, context, c"pagemap", Some(offset), 8);
        assert!(self.poke.is_none());
        self.poke = Some(Poke {
            tid: owner.pid,
            address,
            value: u64::from_ne_bytes(word),
            result: None,
        });
        context.require(owner);
        let result = io::observe(|| unsafe {
            // SAFETY: one native word in the actual held original stack. The
            // numeric tracee address is passed only to ptrace, never dereferenced.
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                owner.pid,
                address as usize as *mut libc::c_void,
                u64::from_ne_bytes(word) as usize as *mut libc::c_void,
            )
        });
        self.poke.as_mut().unwrap().result = Some(result);
        context.require(owner);
        io::zero(result);
        self.files[POST_POKE].capture(owner, context, c"pagemap", Some(offset), 8);
        let entry = u64::from_le_bytes(self.files[POST_POKE].bytes().try_into().unwrap());
        const PRESENT: u64 = 1 << 63;
        const EXCLUSIVE: u64 = 1 << 56;
        const ALLOWED: u64 = PRESENT | EXCLUSIVE | (1 << 55) | ((1 << 55) - 1);
        assert_eq!(entry & (PRESENT | EXCLUSIVE), PRESENT | EXCLUSIVE);
        assert_eq!(entry & !ALLOWED, 0);
        capture_state(self.states[2].as_mut().unwrap(), owner, context);
        self.files[POST_MAPS].capture(owner, context, c"maps", None, MAX_XSTATE);
        self.files[POST_SOURCE].capture(owner, context, c"mem", Some(BASE), 8192);
        self.files[POST_STACK].capture(owner, context, c"mem", Some(range.start), length);
        assert_eq!(
            self.states[2].as_ref().unwrap().state,
            self.states[1].as_ref().unwrap().state
        );
        for (after, before) in [
            (POST_MAPS, BASE_MAPS),
            (POST_SOURCE, BASE_SOURCE),
            (POST_STACK, BASE_STACK),
        ] {
            assert_eq!(self.files[after].bytes(), self.files[before].bytes());
        }
        assert_eq!(
            &self.files[POST_STACK].bytes()[word_offset..word_offset + 8],
            &word[..]
        );
        context.require(owner);
        self.complete = true;
    }
    pub(super) fn require_before(&self, before: &Before) {
        if self.policy == InitialStackPreparation::Unchanged {
            assert!(!self.started);
            return;
        }
        assert!(self.started && self.complete);
        assert_eq!(before.state, self.states[1].as_ref().unwrap().state);
        assert_eq!(before.maps.as_slice(), self.files[BASE_MAPS].bytes());
        assert_eq!(before.source.as_slice(), self.files[BASE_SOURCE].bytes());
        assert_eq!(&before.stack_range, self.stack.as_ref().unwrap());
        assert_eq!(
            before.stack.as_ref().unwrap().as_slice(),
            self.files[BASE_STACK].bytes()
        );
        let poke = self.poke.unwrap();
        assert_eq!(poke.tid, self.context.as_ref().unwrap().initial.tid);
        assert_eq!(poke.address, self.rsp.unwrap().checked_sub(8).unwrap());
        assert_eq!(poke.value.to_ne_bytes(), self.word.unwrap());
        io::zero(poke.result.unwrap());
    }
    /// Read-only historical linkage; may also run after physical cleanup. No
    /// raw read, live token assertion or new permit is made here.
    pub(super) fn require_attempts(&self, owner: &Owner) {
        if !self.complete {
            return;
        }
        let Some(stack) = owner.runtime.as_ref().and_then(|r| r.stack.as_ref()) else {
            return;
        };
        let rsp = self.rsp.unwrap();
        let shape = self.shape.unwrap();
        for attempt in stack.attempts.iter().flatten() {
            if !attempt.operand.progress().complete {
                continue;
            }
            let operand = attempt.operand.operand().unwrap();
            let description = operand.description();
            let geometry = &description.geometry;
            assert_eq!(description.until, self.context.as_ref().unwrap().until);
            assert_eq!(&geometry.stack, self.stack.as_ref().unwrap());
            assert_eq!(geometry.slot, rsp - 8..rsp);
            assert_eq!(geometry.envelope, rsp - 8..rsp);
            if attempt.is_call {
                assert_eq!(geometry.original_rsp, rsp);
                assert_eq!(geometry.pc, shape.call_pc);
                assert_eq!(geometry.next_pc, shape.next);
                assert_eq!(geometry.encoding, shape.encoding);
                assert_eq!(geometry.length, 5);
                assert_eq!(description.target, shape.target);
                assert_eq!(description.value.to_ne_bytes(), self.word.unwrap());
            } else {
                assert_eq!(geometry.original_rsp, rsp - 8);
                assert_eq!(geometry.pc, shape.target);
                assert_eq!(description.value, shape.next);
            }
        }
    }
    pub(super) fn retained(&self) -> impl Fn(&Self) + use<> {
        let header = (
            self.policy,
            self.started,
            self.complete,
            self.context.clone(),
            self.shape,
            self.stack.clone(),
            self.rsp,
            self.word,
            self.poke,
        );
        let states = self
            .states
            .iter()
            .map(|s| s.as_ref().map(retention::slot))
            .collect::<Vec<_>>();
        let files = self
            .files
            .iter()
            .map(io::FileCapture::retained)
            .collect::<Vec<_>>();
        move |actual| {
            assert_eq!(
                (
                    actual.policy,
                    actual.started,
                    actual.complete,
                    actual.context.clone(),
                    actual.shape,
                    actual.stack.clone(),
                    actual.rsp,
                    actual.word,
                    actual.poke
                ),
                header
            );
            assert_eq!(
                actual
                    .states
                    .iter()
                    .map(|s| s.as_ref().map(retention::slot))
                    .collect::<Vec<_>>(),
                states
            );
            for (check, file) in files.iter().zip(&actual.files) {
                check(file);
            }
            if actual.policy == InitialStackPreparation::Unchanged {
                assert!(!actual.started && !actual.complete);
                assert!(
                    actual.context.is_none() && actual.shape.is_none() && actual.stack.is_none()
                );
                assert!(actual.rsp.is_none() && actual.word.is_none() && actual.poke.is_none());
                assert!(actual.states.iter().all(Option::is_none));
            }
        }
    }
}
fn capture_state(slot: &mut StateSlot, owner: &Owner, context: &Context) {
    context.require(owner);
    let result = slot.capture(owner, context.until);
    context.require(owner);
    result.unwrap();
    compare::slot(slot);
}
