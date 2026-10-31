//! Pure ABI mirrors and exact numeric comparisons for the compiled C witness.
//! No pointer is dereferenced or C function invoked here. These checks do not
//! establish mappings, target/argument dataflow, CFI, consumer identity or ABI
//! authority. Frame expectations must come from independently admitted code/CFI,
//! never from the observed trace. Target preservation is measured, not assumed.
#![forbid(unsafe_code)]

use li2core::trampoline::{HookContext, SavedExtendedStateDescriptor};
use std::mem::{offset_of, size_of};

pub const MAX_FRAMES: usize = 32;
pub const MAX_CAPTURES: usize = 2;
pub const CONTEXT_BYTES: usize = 176;
pub const CALLER_BYTES: usize = 256;
pub const CANARIES: [u64; 6] = [
    0x13579bdf2468ace1,
    0x2468ace113579bdf,
    0x3141592653589793,
    0x2718281828459045,
    0x55aa33cc77ee1199,
    0xaa55cc33ee779911,
];
pub const GUARDS: [u64; 4] = [
    0x1122334455667788,
    0x8877665544332211,
    0x123456789abcdef0,
    0xfedcba9876543210,
];
pub const OUTPUT_POISON: u64 = 0xc3c35a5a96966969;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Range {
    pub begin: usize,
    pub end: usize,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Layout {
    pub bytes: u32,
    pub pc: u32,
    pub rsp: u32,
    pub callee: [u32; 6],
    pub xstate: u32,
}
pub const LAYOUT: Layout = Layout {
    bytes: size_of::<HookContext>() as u32,
    pc: offset_of!(HookContext, instruction_pointer) as u32,
    rsp: offset_of!(HookContext, stack_pointer) as u32,
    callee: [
        offset_of!(HookContext, rbx) as u32,
        offset_of!(HookContext, rbp) as u32,
        offset_of!(HookContext, r12) as u32,
        offset_of!(HookContext, r13) as u32,
        offset_of!(HookContext, r14) as u32,
        offset_of!(HookContext, r15) as u32,
    ],
    xstate: (size_of::<HookContext>() - size_of::<SavedExtendedStateDescriptor>()) as u32,
};
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Frame {
    pub ip: u64,
    pub cfa: u64,
    pub callee: [u64; 6],
    pub before_instruction: i32,
    pub owned: u32,
}
impl Frame {
    pub const ZERO: Self = Self {
        ip: 0,
        cfa: 0,
        callee: [0; 6],
        before_instruction: 0,
        owned: 0,
    };
}
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trace {
    pub frames: [Frame; MAX_FRAMES],
    pub context_before: [u8; CONTEXT_BYTES],
    pub context_after: [u8; CONTEXT_BYTES],
    pub caller_before: [u8; CALLER_BYTES],
    pub caller_after: [u8; CALLER_BYTES],
    pub context_address: usize,
    pub saved_pc: u64,
    pub saved_rsp: u64,
    pub saved_callee: [u64; 6],
    pub saved_xstate: [u64; 4],
    pub caller_address: usize,
    pub original_return_before: u64,
    pub original_return_after: u64,
    pub frame_count: u32,
    pub reached_caller: u32,
    pub overflow: u32,
    pub context_changed: u32,
    pub caller_changed: u32,
    pub kind: u32,
    pub flags: u32,
    pub result: i32,
}
impl Trace {
    pub const ZERO: Self = Self {
        frames: [Frame::ZERO; MAX_FRAMES],
        context_before: [0; CONTEXT_BYTES],
        context_after: [0; CONTEXT_BYTES],
        caller_before: [0; CALLER_BYTES],
        caller_after: [0; CALLER_BYTES],
        context_address: 0,
        saved_pc: 0,
        saved_rsp: 0,
        saved_callee: [0; 6],
        saved_xstate: [0; 4],
        caller_address: 0,
        original_return_before: 0,
        original_return_after: 0,
        frame_count: 0,
        reached_caller: 0,
        overflow: 0,
        context_changed: 0,
        caller_changed: 0,
        kind: 0,
        flags: 0,
        result: 0,
    };
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    pub stack: Range,
    pub source: Range,
    pub reference: Range,
    pub caller: Range,
    pub generated: Range,
    pub caller_memory: usize,
    pub caller_bytes: usize,
    pub caller_return_slot: usize,
    pub caller_return: usize,
    pub selected: usize,
    pub layout: Layout,
    pub records: *mut Trace,
    pub capacity: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Status {
    pub configured: u32,
    pub count: u32,
    pub failure: u32,
    pub busy: u32,
}
pub type WorkFn = unsafe extern "C" fn(*const u8, usize, u64, *mut u64) -> u64;
pub type ReferenceFn = unsafe extern "C" fn(u64) -> u64;
pub type ConfigureFn = unsafe extern "C" fn(*const Config) -> i32;
pub type StatusFn = unsafe extern "C" fn() -> Status;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CallerControl {
    pub config: Config,
    pub configure: Option<ConfigureFn>,
    pub status: Option<StatusFn>,
    pub end: Option<StatusFn>,
    pub return_pc: usize,
}
#[repr(C)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CallerObservation {
    pub rsp_sample: usize,
    pub rsp_configured: usize,
    pub rsp_pre: usize,
    pub rsp_post: usize,
    pub caller_return_slot: usize,
    pub caller_return: usize,
    pub callee_before: [u64; 6],
    pub callee_after: [u64; 6],
    pub guard_before: [u64; 4],
    pub guard_after: [u64; 4],
    pub output_before: u64,
    pub output_after: u64,
    pub result: u64,
    pub status_before: Status,
    pub status_configured: Status,
    pub status_after: Status,
    pub status_end: Status,
    pub status_final: Status,
    pub configure_result: i32,
    pub kind: u32,
    pub failures: u32,
    pub configure_attempted: u32,
    pub invocation_dispatched: u32,
    pub normal_returned: u32,
    pub end_attempted: u32,
}
pub type CallWorkFn = unsafe extern "C" fn(
    *const CallerControl,
    Option<WorkFn>,
    *const u8,
    usize,
    u64,
    *mut CallerObservation,
) -> i32;
pub type CallReferenceFn = unsafe extern "C" fn(
    *const CallerControl,
    Option<ReferenceFn>,
    u64,
    *mut CallerObservation,
) -> i32;

const _: () = {
    assert!(size_of::<usize>() == 8);
    assert!(size_of::<Layout>() == 40 && size_of::<Frame>() == 72);
    assert!(size_of::<Trace>() == 3328 && size_of::<Config>() == 176);
    assert!(size_of::<Status>() == 16 && size_of::<CallerControl>() == 208);
    assert!(size_of::<CallerObservation>() == 344);
    assert!(LAYOUT.bytes == 176 && LAYOUT.pc == 0 && LAYOUT.rsp == 8 && LAYOUT.xstate == 144);
    assert!(LAYOUT.callee[0] == 104 && LAYOUT.callee[1] == 96);
    assert!(LAYOUT.callee[2] == 40 && LAYOUT.callee[3] == 32);
    assert!(LAYOUT.callee[4] == 24 && LAYOUT.callee[5] == 16);
    assert!(offset_of!(Trace, context_before) == 2304);
    assert!(offset_of!(Trace, caller_address) == 3272 && offset_of!(Trace, result) == 3324);
    assert!(offset_of!(Config, layout) == 120 && offset_of!(Config, records) == 160);
    assert!(offset_of!(CallerControl, return_pc) == 200);
    assert!(offset_of!(CallerObservation, status_before) == 232);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Case {
    MixedBytes,
    TextAndZeros,
}
impl Case {
    pub const ALL: [Self; 2] = [Self::MixedBytes, Self::TextAndZeros];
    pub const fn input(self) -> &'static [u8] {
        match self {
            Self::MixedBytes => &[0, 1, 2, 3, 127, 128, 254, 255],
            Self::TextAndZeros => b"LiteInst indexed DSO\0\xff",
        }
    }
    pub const fn seed(self) -> u64 {
        match self {
            Self::MixedBytes => 0x0123456789abcdef,
            Self::TextAndZeros => 0xfedcba9876543210,
        }
    }
    pub fn work(self) -> (u64, u64) {
        let length = u64::try_from(self.input().len()).expect("two fixed bounded inputs");
        let value = self
            .input()
            .iter()
            .fold(self.seed(), |v, &b| v.wrapping_mul(33) ^ u64::from(b));
        (value, value ^ length)
    }
    pub const fn reference(self) -> u64 {
        self.seed() ^ 0x5245464552454e43
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    OriginalWork,
    CandidateWork,
    Reference,
}
impl Mode {
    const fn count(self) -> u32 {
        match self {
            Self::OriginalWork => 0,
            _ => 1,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct CallExpectation {
    pub mode: Mode,
    pub case: Case,
    pub return_pc: usize,
    /// The previous closed invocation's retained count, or zero for a fresh
    /// collector. Capture-end clears configured but deliberately retains count.
    pub previous_count: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Expectation,
    Lifecycle,
    Counts,
    Stack,
    Callee,
    Guards,
    Result,
    Trace,
    Context,
    CallerMemory,
    Frames,
}
type Result<T> = std::result::Result<T, Error>;

/// Only local numeric comparisons. Trace/CFI/loaded-runtime admission is still
/// separate; original work has no trace and cannot establish unwind success.
pub struct CallChecks<'a> {
    expected: CallExpectation,
    observation: &'a CallerObservation,
    records: &'a [Trace; MAX_CAPTURES],
}
pub fn check_call<'a>(
    expected: CallExpectation,
    returned: i32,
    observation: &'a CallerObservation,
    // The driver supplies fresh zeroed records for each invocation; accepting
    // a count-sized slice could conceal a write to an unused capture.
    records: &'a [Trace; MAX_CAPTURES],
) -> Result<CallChecks<'a>> {
    let o = observation;
    if expected.return_pc == 0 || expected.previous_count > 1 {
        return Err(Error::Expectation);
    }
    let count = expected.mode.count();
    let status = |configured, count| Status {
        configured,
        count,
        failure: 0,
        busy: 0,
    };
    if returned != 1
        || o.failures != 0
        || o.configure_result != 1
        || o.configure_attempted != 1
        || o.invocation_dispatched != 1
        || o.normal_returned != 1
        || o.end_attempted != 1
        || o.kind
            != if expected.mode == Mode::Reference {
                2
            } else {
                1
            }
        || o.status_before != status(0, expected.previous_count)
        || o.status_configured != status(1, 0)
        || o.status_after != status(1, count)
        || o.status_end != status(1, count)
        || o.status_final != status(0, count)
    {
        return Err(Error::Lifecycle);
    }
    if records[count as usize..].iter().any(|r| r != &Trace::ZERO) {
        return Err(Error::Counts);
    }
    if o.rsp_sample < 8
        || o.rsp_sample % 16 != 0
        || [o.rsp_configured, o.rsp_pre, o.rsp_post]
            .iter()
            .any(|&p| p != o.rsp_sample)
        || o.caller_return_slot != o.rsp_sample - 8
        || o.caller_return != expected.return_pc
    {
        return Err(Error::Stack);
    }
    if o.callee_before != CANARIES || o.callee_after != CANARIES {
        return Err(Error::Callee);
    }
    if o.guard_before != GUARDS || o.guard_after != GUARDS || o.output_before != OUTPUT_POISON {
        return Err(Error::Guards);
    }
    let (result, output) = if expected.mode == Mode::Reference {
        (expected.case.reference(), OUTPUT_POISON)
    } else {
        expected.case.work()
    };
    if o.result != result || o.output_after != output {
        return Err(Error::Result);
    }
    Ok(CallChecks {
        expected,
        observation,
        records,
    })
}

#[derive(Clone, Copy, Debug)]
pub enum ContextExpectation {
    Absent,
    Generated {
        address: usize,
        selected: u64,
        xstate: [u64; 4],
    },
}
/// Exact ordered values derived independently from admitted code/CFI and the
/// loaded consumer. `result` is that consumer's raw stop result, not a guessed
/// success enum. Passing these comparisons does not authenticate their source.
pub struct TraceExpectation<'a> {
    pub frames: &'a [Frame],
    pub result: i32,
    pub context: ContextExpectation,
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed ABI offset"),
    )
}
impl CallChecks<'_> {
    pub fn check_trace(&self, expected: &TraceExpectation<'_>) -> Result<()> {
        if self.expected.mode == Mode::OriginalWork {
            return Err(Error::Counts);
        }
        let t = &self.records[0];
        let o = self.observation;
        let generated = self.expected.mode == Mode::CandidateWork;
        if t.kind != if generated { 2 } else { 1 }
            || t.reached_caller != 1
            || t.overflow != 0
            || t.flags != 0
            || t.context_changed != 0
            || t.caller_changed != 0
            || t.result != expected.result
            || expected.result < 0
        {
            return Err(Error::Trace);
        }
        if t.caller_address != o.caller_return_slot
            || t.original_return_before != o.caller_return as u64
            || t.original_return_after != o.caller_return as u64
            || t.caller_before != t.caller_after
            || word(&t.caller_before, 0) != o.caller_return as u64
            || t.caller_before[8..].iter().any(|&b| b != 0)
        {
            return Err(Error::CallerMemory);
        }
        if t.context_before != t.context_after {
            return Err(Error::Context);
        }
        match (generated, expected.context) {
            (
                true,
                ContextExpectation::Generated {
                    address,
                    selected,
                    xstate,
                },
            ) => {
                if address == 0
                    || selected == 0
                    || t.context_address != address
                    || t.saved_pc != selected
                    || t.saved_rsp != o.caller_return_slot as u64
                    || t.saved_callee != CANARIES
                    || t.saved_xstate != xstate
                    || word(&t.context_before, LAYOUT.pc as usize) != t.saved_pc
                    || word(&t.context_before, LAYOUT.rsp as usize) != t.saved_rsp
                    || LAYOUT
                        .callee
                        .iter()
                        .zip(t.saved_callee)
                        .any(|(&p, v)| word(&t.context_before, p as usize) != v)
                    || (0..4).any(|i| {
                        word(&t.context_before, LAYOUT.xstate as usize + i * 8) != xstate[i]
                    })
                {
                    return Err(Error::Context);
                }
            }
            (false, ContextExpectation::Absent) => {
                if t.context_address != 0
                    || t.context_before != [0; CONTEXT_BYTES]
                    || t.saved_pc != 0
                    || t.saved_rsp != 0
                    || t.saved_callee != [0; 6]
                    || t.saved_xstate != [0; 4]
                {
                    return Err(Error::Context);
                }
            }
            _ => return Err(Error::Expectation),
        }
        let n = t.frame_count as usize;
        if !(2..=MAX_FRAMES).contains(&n)
            || expected.frames.len() != n
            || &t.frames[..n] != expected.frames
            || t.frames[n..].iter().any(|f| f != &Frame::ZERO)
        {
            return Err(Error::Frames);
        }
        for (i, f) in t.frames[..n].iter().enumerate() {
            let owned = if i + 1 == n {
                8
            } else if i + 2 == n {
                if generated { 4 } else { 2 }
            } else {
                0
            };
            if f.ip == 0
                || f.cfa == 0
                || !matches!(f.before_instruction, 0 | 1)
                || f.owned != owned
                || (owned == 0 && f.callee != [0; 6])
            {
                return Err(Error::Frames);
            }
        }
        let caller = &t.frames[n - 1];
        if caller.ip != o.caller_return as u64
            || caller.before_instruction != 0
            || caller.callee != CANARIES
        {
            return Err(Error::Frames);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are invented numeric records, never asserted to be a native trace.
    type Fixture = (
        CallExpectation,
        CallerObservation,
        [Trace; 2],
        [Frame; 2],
        ContextExpectation,
    );
    fn fixture(mode: Mode, case: Case) -> Fixture {
        let e = CallExpectation {
            mode,
            case,
            return_pc: 0x5010,
            previous_count: 1,
        };
        let status = |configured, count| Status {
            configured,
            count,
            failure: 0,
            busy: 0,
        };
        let (result, output) = if mode == Mode::Reference {
            (case.reference(), OUTPUT_POISON)
        } else {
            case.work()
        };
        let o = CallerObservation {
            rsp_sample: 0x8000,
            rsp_configured: 0x8000,
            rsp_pre: 0x8000,
            rsp_post: 0x8000,
            caller_return_slot: 0x7ff8,
            caller_return: e.return_pc,
            callee_before: CANARIES,
            callee_after: CANARIES,
            guard_before: GUARDS,
            guard_after: GUARDS,
            output_before: OUTPUT_POISON,
            output_after: output,
            result,
            status_before: status(0, 1),
            status_configured: status(1, 0),
            status_after: status(1, mode.count()),
            status_end: status(1, mode.count()),
            status_final: status(0, mode.count()),
            configure_result: 1,
            kind: if mode == Mode::Reference { 2 } else { 1 },
            failures: 0,
            configure_attempted: 1,
            invocation_dispatched: 1,
            normal_returned: 1,
            end_attempted: 1,
        };
        let frames = [
            Frame {
                ip: 0x3010,
                cfa: 0x8000,
                callee: if mode == Mode::Reference {
                    [17; 6]
                } else {
                    CANARIES
                },
                before_instruction: 0,
                owned: if mode == Mode::Reference { 2 } else { 4 },
            },
            Frame {
                ip: 0x5010,
                cfa: 0x8100,
                callee: CANARIES,
                before_instruction: 0,
                owned: 8,
            },
        ];
        let mut records = [Trace::ZERO, Trace::ZERO];
        let mut context = ContextExpectation::Absent;
        if mode != Mode::OriginalWork {
            let t = &mut records[0];
            t.kind = if mode == Mode::Reference { 1 } else { 2 };
            t.reached_caller = 1;
            t.result = 3;
            t.frame_count = 2;
            t.frames[..2].copy_from_slice(&frames);
            t.caller_address = o.caller_return_slot;
            t.original_return_before = o.caller_return as u64;
            t.original_return_after = o.caller_return as u64;
            t.caller_before[..8].copy_from_slice(&(o.caller_return as u64).to_le_bytes());
            t.caller_after = t.caller_before;
            if mode == Mode::CandidateWork {
                let xstate = [0x6000, 512, 3, 1];
                context = ContextExpectation::Generated {
                    address: 0x7000,
                    selected: 0x3000,
                    xstate,
                };
                t.context_address = 0x7000;
                t.saved_pc = 0x3000;
                t.saved_rsp = o.caller_return_slot as u64;
                t.saved_callee = CANARIES;
                t.saved_xstate = xstate;
                t.context_before = [0xa5; CONTEXT_BYTES];
                let words = [(LAYOUT.pc, t.saved_pc), (LAYOUT.rsp, t.saved_rsp)]
                    .into_iter()
                    .chain(LAYOUT.callee.into_iter().zip(CANARIES))
                    .chain(
                        xstate
                            .into_iter()
                            .enumerate()
                            .map(|(i, value)| (LAYOUT.xstate + i as u32 * 8, value)),
                    );
                for (offset, value) in words {
                    t.context_before[offset as usize..offset as usize + 8]
                        .copy_from_slice(&value.to_le_bytes());
                }
                t.context_after = t.context_before;
            }
        }
        (e, o, records, frames, context)
    }

    #[test]
    fn abi_offsets_and_independently_fixed_model_literals_match() {
        // The ABI offsets are asserted in the module's const block, so a
        // layout drift refuses compilation before these runtime controls.
        assert_eq!(
            Case::MixedBytes.work(),
            (0xf5c28dfd19d4fc71, 0xf5c28dfd19d4fc79)
        );
        assert_eq!(
            Case::TextAndZeros.work(),
            (0x18c11a2cfc84d73c, 0x18c11a2cfc84d72a)
        );
        assert_eq!(Case::MixedBytes.reference(), 0x53660322dbee83ac);
        assert_eq!(Case::TextAndZeros.reference(), 0xac99fcdd24117c53);
    }

    #[test]
    fn every_fixed_case_and_mode_has_exact_counts_and_prior_status() {
        for case in Case::ALL {
            for mode in [Mode::OriginalWork, Mode::CandidateWork, Mode::Reference] {
                let (e, mut o, mut records, frames, context) = fixture(mode, case);
                let checked = check_call(e, 1, &o, &records).unwrap();
                let trace = checked.check_trace(&TraceExpectation {
                    frames: &frames,
                    result: 3,
                    context,
                });
                assert_eq!(
                    trace,
                    if mode == Mode::OriginalWork {
                        Err(Error::Counts)
                    } else {
                        Ok(())
                    }
                );
                assert_eq!(check_call(e, 0, &o, &records).err(), Some(Error::Lifecycle));
                o.status_before.count = 0;
                assert_eq!(check_call(e, 1, &o, &records).err(), Some(Error::Lifecycle));
                assert!(
                    check_call(
                        CallExpectation {
                            previous_count: 0,
                            ..e
                        },
                        1,
                        &o,
                        &records
                    )
                    .is_ok()
                );
                o.status_before.count = 1;
                records[1].flags = 1;
                assert_eq!(check_call(e, 1, &o, &records).err(), Some(Error::Counts));
            }
        }
    }

    #[test]
    fn local_return_flags_status_counts_and_registers_cannot_hide_failure() {
        let (e, o, records, _, _) = fixture(Mode::CandidateWork, Case::MixedBytes);
        let changes: &[fn(&mut CallerObservation)] = &[
            |o| o.normal_returned = 0,
            |o| o.invocation_dispatched = 0,
            |o| o.configure_result = 0,
            |o| o.end_attempted = 0,
            |o| o.failures = 1,
            |o| o.status_after.count = 0,
            |o| o.status_end.busy = 1,
            |o| o.status_final.configured = 1,
            |o| o.status_configured.failure = 1,
        ];
        for change in changes {
            let mut bad = o.clone();
            change(&mut bad);
            assert_eq!(
                check_call(e, 1, &bad, &records).err(),
                Some(Error::Lifecycle)
            );
        }
        for column in 0..6 {
            for before in [false, true] {
                let mut bad = o.clone();
                if before {
                    bad.callee_before[column] ^= 1;
                } else {
                    bad.callee_after[column] ^= 1;
                }
                assert_eq!(check_call(e, 1, &bad, &records).err(), Some(Error::Callee));
            }
        }
        let mut bad = o.clone();
        bad.rsp_post += 16;
        assert_eq!(check_call(e, 1, &bad, &records).err(), Some(Error::Stack));
        let mut bad = o.clone();
        bad.guard_after[3] ^= 1;
        assert_eq!(check_call(e, 1, &bad, &records).err(), Some(Error::Guards));
        let mut bad = o;
        bad.output_after ^= 1;
        assert_eq!(check_call(e, 1, &bad, &records).err(), Some(Error::Result));
    }

    #[test]
    fn every_context_byte_and_every_return_slot_byte_must_be_unchanged() {
        let (e, o, records, frames, context) = fixture(Mode::CandidateWork, Case::MixedBytes);
        let expected = TraceExpectation {
            frames: &frames,
            result: 3,
            context,
        };
        for byte in 0..CONTEXT_BYTES {
            let mut bad = records.clone();
            bad[0].context_after[byte] ^= 1;
            assert_eq!(
                check_call(e, 1, &o, &bad).unwrap().check_trace(&expected),
                Err(Error::Context)
            );
        }
        for byte in 0..8 {
            let mut bad = records.clone();
            bad[0].caller_after[byte] ^= 1;
            assert_eq!(
                check_call(e, 1, &o, &bad).unwrap().check_trace(&expected),
                Err(Error::CallerMemory)
            );
        }
    }

    #[test]
    fn reference_context_is_absent_and_generated_saved_copies_join_the_bytes() {
        for mode in [Mode::Reference, Mode::CandidateWork] {
            let (e, o, mut records, frames, context) = fixture(mode, Case::TextAndZeros);
            let expected = TraceExpectation {
                frames: &frames,
                result: 3,
                context,
            };
            if mode == Mode::Reference {
                records[0].context_before[90] = 1;
                records[0].context_after[90] = 1;
            } else {
                records[0].context_before[LAYOUT.callee[0] as usize] ^= 1;
                records[0].context_after = records[0].context_before;
            }
            assert_eq!(
                check_call(e, 1, &o, &records)
                    .unwrap()
                    .check_trace(&expected),
                Err(Error::Context)
            );
        }
    }

    #[test]
    fn frame_order_full_population_raw_result_and_expectations_remain_exact() {
        let (e, o, records, frames, context) = fixture(Mode::CandidateWork, Case::MixedBytes);
        let expected = TraceExpectation {
            frames: &frames,
            result: 3,
            context,
        };
        for n in [0, 1, 33] {
            let mut bad = records.clone();
            bad[0].frame_count = n;
            assert_eq!(
                check_call(e, 1, &o, &bad).unwrap().check_trace(&expected),
                Err(Error::Frames)
            );
        }
        let mut bad = records.clone();
        bad[0].frames.swap(0, 1);
        let reversed = [frames[1], frames[0]];
        assert_eq!(
            check_call(e, 1, &o, &bad)
                .unwrap()
                .check_trace(&TraceExpectation {
                    frames: &reversed,
                    result: 3,
                    context
                }),
            Err(Error::Frames)
        );
        let mut bad = records.clone();
        bad[0].frames[2].ip = 1;
        assert_eq!(
            check_call(e, 1, &o, &bad).unwrap().check_trace(&expected),
            Err(Error::Frames)
        );
        let mut bad = records.clone();
        bad[0].result = 5;
        assert_eq!(
            check_call(e, 1, &o, &bad).unwrap().check_trace(&expected),
            Err(Error::Trace)
        );
        assert_eq!(
            check_call(e, 1, &o, &records)
                .unwrap()
                .check_trace(&TraceExpectation {
                    frames: &frames[..1],
                    result: 3,
                    context
                }),
            Err(Error::Frames)
        );
        assert_eq!(
            check_call(e, 1, &o, &records)
                .unwrap()
                .check_trace(&TraceExpectation {
                    frames: &frames,
                    result: 3,
                    context: ContextExpectation::Absent
                }),
            Err(Error::Expectation)
        );
    }
}
