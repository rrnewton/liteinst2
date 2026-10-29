//! One admitted copied Rust FUNC, separate from every existing caller profile.
use super::*;
use rust_invoke::Plan;
#[path = "native_copied_rust/effects.rs"]
mod effects;
#[path = "native_copied_rust/trace.rs"]
mod trace;
pub use trace::Trace;
pub type Coverage = trace::Coverage;
pub type Population = trace::Population;
pub(super) use effects::{caller_effects, caller_effects_view, outer_effect};
const VERSION: &[u8] = b"COPIED-RUST-INVOKE-V1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    function: usize,
    index: usize,
    extents: [usize; 2],
    order: [usize; 2],
}
impl Case {
    pub fn new(
        function: usize,
        index: usize,
        csv_extent: usize,
        length_extent: usize,
        csv_index: usize,
    ) -> Self {
        assert!(function < 2 && index < if function == 0 { 16 } else { 8 });
        assert!((5..=256).contains(&csv_extent) && (5..=80).contains(&length_extent));
        assert!(csv_index < 2);
        Self {
            function,
            index,
            extents: [csv_extent, length_extent],
            order: [csv_index, 1 - csv_index],
        }
    }
    pub(super) fn assert_valid(self) {
        assert_eq!(
            self,
            Self::new(
                self.function,
                self.index,
                self.extents[0],
                self.extents[1],
                self.order[0]
            )
        );
    }
    pub fn function(self) -> usize {
        self.function
    }
    pub fn index(self) -> usize {
        self.index
    }
    pub fn selected(self) -> usize {
        self.order[self.function]
    }
    pub fn extents(self) -> [usize; 2] {
        self.extents
    }
    pub fn order(self) -> [usize; 2] {
        self.order
    }
    pub fn bound(self) -> usize {
        self.body().bound()
    }
    pub fn value(self) -> u64 {
        self.body().scalar()
    }
    pub fn input(self) -> [u8; 64] {
        self.body().input()
    }
    fn body(self) -> Body {
        self.assert_valid();
        if self.function == 0 {
            Body::Csv(csv::Case::new(self.index))
        } else {
            Body::Strnlen(CASES[self.index])
        }
    }
}
pub(super) struct Profile {
    pub(super) case: Case,
    pub(super) plan: Plan,
    caller: u64,
    source: (u64, Vec<u8>),
}
impl Profile {
    fn new(case: Case, plan: Plan, caller: u64, source: (u64, Vec<u8>)) -> Self {
        case.assert_valid();
        assert_eq!(rust_invoke::admit(plan.bytes()).unwrap(), plan);
        assert_eq!(source.0 % PAGE as u64, 0);
        assert_eq!(source.1.len(), PAGE);
        assert_eq!(caller, source.0.checked_add(128).unwrap());
        let mut expected = vec![0xcc; PAGE];
        expected[128..128 + plan.bytes().len()].copy_from_slice(plan.bytes());
        assert_eq!(source.1, expected);
        Self {
            case,
            plan,
            caller,
            source,
        }
    }
}
#[derive(Clone)]
pub struct Ready {
    pub caller: u64,
    pub caller_immutable: Vec<(u64, Vec<u8>)>,
    pub functions: [module::Function; 2],
    pub immutable: Vec<(u64, Vec<u8>)>,
    pub original_source: Vec<u8>,
    pub journal: Option<JournalReady>,
    pub case: Case,
    pub plan: Plan,
}
/// The same admitted four-origin machine obligations, borrowed from either
/// authenticated Ready profile. This is not a loaded-owner constructor.
#[derive(Clone, Copy)]
pub(super) struct CallerView<'a> {
    pub(super) caller: u64,
    pub(super) plan: &'a Plan,
    pub(super) target: &'a module::Function,
    pub(super) bound: usize,
    pub(super) value: u64,
    pub(super) journal: Option<&'a JournalReady>,
}
impl CallerView<'_> {
    fn target(&self) -> &module::Function {
        self.target
    }
}
impl Ready {
    pub(super) fn view(&self) -> CallerView<'_> {
        CallerView {
            caller: self.caller,
            plan: &self.plan,
            target: self.target(),
            bound: self.case.bound(),
            value: self.case.value(),
            journal: self.journal.as_ref(),
        }
    }
}
impl Ready {
    pub fn target(&self) -> &module::Function {
        &self.functions[self.case.selected()]
    }
    pub(super) fn validate(&self, candidate: bool, expected: &Profile) -> BTreeMap<u64, u64> {
        self.case.assert_valid();
        assert_eq!(self.case, expected.case);
        assert_eq!(self.plan, expected.plan);
        assert_eq!(self.caller, expected.caller);
        assert_eq!(
            self.caller_immutable.as_slice(),
            std::slice::from_ref(&expected.source)
        );
        assert_eq!(rust_invoke::admit(self.plan.bytes()).unwrap(), self.plan);
        module::validate_geometry(
            module::Geometry {
                caller: self.caller,
                caller_immutable: &self.caller_immutable,
                functions: &self.functions,
                immutable: &self.immutable,
                original_source: &self.original_source,
                journal: self.journal.as_ref(),
            },
            candidate,
            self.case.order,
            self.case.extents,
            self.plan.bytes(),
        )
    }
    pub(super) fn same_source(&self, other: &Self) {
        assert_eq!((self.case, &self.plan), (other.case, &other.plan));
        assert_eq!(self.caller, other.caller);
        assert_eq!(self.caller_immutable, other.caller_immutable);
        assert_eq!(self.immutable[0].0, other.immutable[0].0);
        assert_eq!(self.original_source, other.original_source);
        for (a, b) in self.functions.iter().zip(&other.functions) {
            assert_eq!(
                (a.entry, &a.heads, &a.returns),
                (b.entry, &b.heads, &b.returns)
            );
        }
    }
    fn encode(&self) -> Vec<u8> {
        self.case.assert_valid();
        assert_eq!(rust_invoke::admit(self.plan.bytes()).unwrap(), self.plan);
        let mut out = VERSION.to_vec();
        for n in [
            self.caller,
            self.case.function as u64,
            self.case.index as u64,
            self.case.extents[0] as u64,
            self.case.extents[1] as u64,
            self.case.order[0] as u64,
        ] {
            word(&mut out, n);
        }
        word(&mut out, self.plan.bytes().len() as u64);
        out.extend(self.plan.bytes());
        for f in &self.functions {
            word(&mut out, f.entry);
            for list in [&f.heads, &f.returns] {
                word(&mut out, list.len() as u64);
                for &n in list {
                    word(&mut out, n);
                }
            }
            word(&mut out, f.boundaries.len() as u64);
            for &(a, b) in &f.boundaries {
                word(&mut out, a);
                word(&mut out, b);
            }
        }
        for list in [&self.caller_immutable, &self.immutable] {
            word(&mut out, list.len() as u64);
            for (a, b) in list {
                word(&mut out, *a);
                word(&mut out, b.len() as u64);
                out.extend(b);
            }
        }
        word(&mut out, self.original_source.len() as u64);
        out.extend(&self.original_source);
        word(&mut out, u64::from(self.journal.is_some()));
        if let Some(j) = &self.journal {
            assert!(j.b_generation.is_none() && j.helper_tid.is_none());
            word(&mut out, j.address);
            word(&mut out, j.a_generation);
        }
        assert!(out.len() <= WIRE_LIMIT);
        out
    }
    pub(super) fn decode(wire: &[u8], case: Case, plan: &Plan) -> Self {
        assert!(wire.len() <= WIRE_LIMIT);
        let mut wire = wire
            .strip_prefix(VERSION)
            .expect("copied Rust Ready version");
        let caller = take_word(&mut wire);
        let mut n = || usize::try_from(take_word(&mut wire)).unwrap();
        let actual = Case::new(n(), n(), n(), n(), n());
        assert_eq!(actual, case);
        let bytes = take_data(&mut wire);
        assert!(bytes.len() <= rust_invoke::MAX_BYTES);
        let actual_plan = rust_invoke::admit(&bytes).unwrap();
        assert_eq!(&actual_plan, plan);
        let functions = std::array::from_fn(|_| {
            let entry = take_word(&mut wire);
            let mut list = |limit| {
                let n = usize::try_from(take_word(&mut wire)).unwrap();
                assert!(n <= limit);
                (0..n).map(|_| take_word(&mut wire)).collect::<Vec<_>>()
            };
            let heads = list(256);
            let returns = list(4);
            let n = usize::try_from(take_word(&mut wire)).unwrap();
            assert!(n <= 256);
            let boundaries = (0..n)
                .map(|_| (take_word(&mut wire), take_word(&mut wire)))
                .collect();
            module::Function {
                entry,
                heads,
                returns,
                boundaries,
            }
        });
        let mut pages = |limit| {
            let n = usize::try_from(take_word(&mut wire)).unwrap();
            assert!(n <= limit);
            (0..n)
                .map(|_| (take_word(&mut wire), take_data(&mut wire)))
                .collect::<Vec<_>>()
        };
        let caller_immutable = pages(1);
        let immutable = pages(11);
        let original_source = take_data(&mut wire);
        let journal = match take_word(&mut wire) {
            0 => None,
            1 => Some(JournalReady {
                address: take_word(&mut wire),
                a_generation: take_word(&mut wire),
                b_generation: None,
                helper_tid: None,
            }),
            _ => panic!("copied Rust journal tag"),
        };
        assert!(wire.is_empty());
        Self {
            caller,
            caller_immutable,
            functions,
            immutable,
            original_source,
            journal,
            case: actual,
            plan: actual_plan,
        }
    }
}
impl NormalOracle {
    pub fn new_copied_rust(
        seed: u64,
        case: Case,
        plan: Plan,
        caller: u64,
        caller_source: (u64, Vec<u8>),
        deadline: Deadline,
    ) -> Self {
        deadline.check();
        case.assert_valid();
        assert!(SEEDS.contains(&seed));
        assert_eq!(rust_invoke::admit(plan.bytes()).unwrap(), plan);
        let mut oracle = Self::new_body(
            seed,
            case.body(),
            case.extents[case.function],
            deadline,
            Mode::Stable,
        );
        oracle.copied_rust = Some(Profile::new(case, plan, caller, caller_source));
        oracle
    }
    pub fn pair_copied_rust<F>(&self, setup: F) -> (NormalPairResult<1>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let p = self.copied_rust.as_ref().expect("copied Rust oracle");
        p.case.assert_valid();
        assert!(self.leaf_set_copied.is_none());
        assert!(self.module.is_none() && self.reference.is_none());
        assert_eq!(self.mode, Mode::Stable);
        let (pair, trace, stats) = self.pair_engine::<F, _, _, 1>(setup, |r, points| {
            let trace = trace::inspect(self, r.copied_rust(), points);
            let visits = [trace.visits()];
            (trace, visits)
        });
        assert!(stats.is_none());
        trace::validate_pair(p.case, &p.plan, &pair, &trace);
        (pair, trace)
    }
}
impl NormalContext<'_> {
    pub fn copied_rust_case(&self) -> Case {
        assert!(self.oracle.leaf_set_copied.is_none());
        assert!(self.oracle.module.is_none() && self.oracle.reference.is_none());
        assert_eq!(self.oracle.mode, Mode::Stable);
        let c = self
            .oracle
            .copied_rust
            .as_ref()
            .expect("copied Rust context")
            .case;
        c.assert_valid();
        c
    }
    pub fn ready_copied_rust(self, ready: &Ready) {
        assert_eq!(ready.case, self.copied_rust_case());
        assert_eq!(ready.plan, self.oracle.copied_rust.as_ref().unwrap().plan);
        assert!(self.control.is_none() && self.output.is_none());
        write_all(self.write.0, &ready.encode(), self.oracle.deadline);
        drop(self.write);
        self.oracle.deadline.check();
        unsafe {
            assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
            assert_eq!(libc::raise(libc::SIGSTOP), 0);
        }
    }
}
pub(super) fn entry_arguments(r: &libc::user_regs_struct, ready: &Ready, data: u64) {
    entry_arguments_view(r, ready.view(), data)
}
pub(super) fn entry_arguments_view(r: &libc::user_regs_struct, ready: CallerView<'_>, data: u64) {
    assert_eq!(
        (r.rdi, r.rsi, r.rdx, r.rcx),
        (
            ready.target().entry,
            data + INPUT as u64,
            ready.bound as u64,
            data + RESULTS as u64
        )
    );
}
pub(super) fn call_order(calls: usize, returns: usize, index: usize) {
    assert_eq!((calls, returns, index), (0, 0, 0));
}
pub(super) fn ret_order(calls: usize, returns: usize) {
    assert_eq!((calls, returns), (1, 0));
}
pub(super) fn call_before(
    r: &libc::user_regs_struct,
    ready: &Ready,
    index: usize,
    rsp: u64,
    data: u64,
    bound: usize,
) {
    call_before_view(r, ready.view(), index, rsp, data, bound)
}
pub(super) fn call_before_view(
    r: &libc::user_regs_struct,
    ready: CallerView<'_>,
    index: usize,
    rsp: u64,
    data: u64,
    bound: usize,
) {
    assert_eq!(index, 0);
    assert_eq!(bound, ready.bound);
    let step = ready
        .plan
        .steps()
        .iter()
        .find(|s| s.offset == ready.plan.calls()[0])
        .unwrap();
    let rust_invoke::Operation::Call { target } = step.operation else {
        panic!("admitted call")
    };
    assert_eq!(effects::register(r, target), ready.target().entry);
    assert_eq!(
        (r.rdi, r.rsi, r.rsp),
        (
            data + INPUT as u64,
            bound as u64,
            effects::offset(rsp, step.rsp_before)
        )
    );
}
pub(super) fn call_after(
    r: &libc::user_regs_struct,
    ready: &Ready,
    index: usize,
    rsp: u64,
    word: u64,
) {
    call_after_view(r, ready.view(), index, rsp, word)
}
pub(super) fn call_after_view(
    r: &libc::user_regs_struct,
    ready: CallerView<'_>,
    index: usize,
    rsp: u64,
    word: u64,
) {
    assert_eq!(index, 0);
    assert_eq!(
        (r.rip, r.rsp, word),
        (
            ready.target().entry,
            rsp.checked_sub(ready.plan.subject_rsp_delta()).unwrap(),
            ready.caller + ready.plan.continuations()[0]
        )
    );
}
pub(super) fn ret_before(
    r: &libc::user_regs_struct,
    ready: &Ready,
    index: usize,
    rsp: u64,
    value: u64,
    word: u64,
) {
    ret_before_view(r, ready.view(), index, rsp, value, word)
}
pub(super) fn ret_before_view(
    r: &libc::user_regs_struct,
    ready: CallerView<'_>,
    index: usize,
    rsp: u64,
    value: u64,
    word: u64,
) {
    assert_eq!(index, 0);
    assert_eq!(value, ready.value);
    assert!(
        ready
            .target()
            .boundaries
            .iter()
            .any(|&(a, b)| b == r.rip && ready.target().returns.contains(&a))
    );
    assert_eq!(
        (r.rsp, r.rax, word),
        (
            rsp.checked_sub(ready.plan.subject_rsp_delta()).unwrap(),
            value,
            ready.caller + ready.plan.continuations()[0]
        )
    );
}
pub(super) fn ret_after(
    r: &libc::user_regs_struct,
    ready: &Ready,
    index: usize,
    rsp: u64,
    value: u64,
    word: u64,
) {
    ret_after_view(r, ready.view(), index, rsp, value, word)
}
pub(super) fn ret_after_view(
    r: &libc::user_regs_struct,
    ready: CallerView<'_>,
    index: usize,
    rsp: u64,
    value: u64,
    word: u64,
) {
    assert_eq!(index, 0);
    assert_eq!(value, ready.value);
    assert_eq!(
        (r.rip, r.rsp, r.rax, word),
        (
            ready.caller + ready.plan.continuations()[0],
            rsp.checked_sub(ready.plan.subject_rsp_delta())
                .unwrap()
                .checked_add(8)
                .unwrap(),
            value,
            ready.caller + ready.plan.continuations()[0]
        )
    );
}
pub(super) fn check_data(initial: &[u8], actual: &[u8], value: u64, final_check: bool) {
    assert_eq!((initial.len(), actual.len()), (PAGE, PAGE));
    assert_eq!(&actual[..RESULTS], &initial[..RESULTS]);
    assert_eq!(&actual[RESULTS + 8..], &initial[RESULTS + 8..]);
    if final_check {
        assert_eq!(&actual[RESULTS..RESULTS + 8], &value.to_le_bytes());
    }
}
pub fn journal_words(
    ready: &Ready,
    pid: u64,
    rsp: u64,
    returns: &[u64],
    pending: bool,
) -> [u64; 512] {
    journal_words_view(ready.view(), pid, rsp, returns, pending)
}
pub(super) fn journal_words_view(
    ready: CallerView<'_>,
    pid: u64,
    rsp: u64,
    returns: &[u64],
    pending: bool,
) -> [u64; 512] {
    assert_eq!(returns.len(), 1);
    assert!(ready.target().returns.contains(&returns[0]));
    let j = ready.journal.unwrap();
    assert_ne!(j.a_generation, 0);
    let mut out = [0; 512];
    out[..4].copy_from_slice(&[2, 0, pid, u64::from(pending)]);
    for (event, pc, at) in [(1, ready.target().entry, 4), (2, returns[0], 11)] {
        out[at..at + 7].copy_from_slice(&[
            event,
            1,
            pc,
            rsp.checked_sub(ready.plan.subject_rsp_delta()).unwrap(),
            ready.caller + ready.plan.continuations()[0],
            j.a_generation,
            1 | (1 << 13),
        ]);
    }
    out
}
#[cfg(test)]
#[path = "native_copied_rust/tests.rs"]
mod tests;
