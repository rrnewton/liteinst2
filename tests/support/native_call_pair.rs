//! Original-address nested call pair. Distinct from every copied/gated profile.
use super::*;
#[path = "native_call_pair/parent.rs"]
mod parent;
#[path = "native_call_pair/phase.rs"]
pub(super) mod phase;
#[path = "native_call_pair/trace.rs"]
mod trace;
#[path = "native_call_pair/trace_join.rs"]
pub mod trace_join;
#[path = "native_call_pair/witness.rs"]
pub mod witness;
pub use trace::Trace;
pub type Coverage = trace::Coverage;
pub type Population = trace::Population;
pub(super) use phase::Phase;
use rust_invoke::Plan;
const VERSION: &[u8] = b"CALL-PAIR-ORIGINAL-RUST-V1\0";
pub fn parent_delta(code: &[u8], entry: u64, child: u64) -> u64 {
    parent::Parent::decode(code, entry, child).delta
}
pub fn absolute_end(deadline: Deadline) -> Instant {
    deadline.end()
}
pub const PROFILE: &str = "normal-call-pair-original-rust-v1";
pub const FUNCTIONS: [u64; 2] = [501, 502];
pub const INSTALL: u64 = 0x6361_6c6c_7061_6972;
pub const POSTFLIGHT_LIMIT: usize = 4096;
pub(super) fn postflight_pipe() -> [Fd; 2] {
    let endpoints = pipe();
    let capacity = unsafe { libc::fcntl(endpoints[1].0, libc::F_GETPIPE_SZ) };
    assert!(capacity >= POSTFLIGHT_LIMIT as i32);
    let atomic_limit = unsafe { libc::fpathconf(endpoints[1].0, libc::_PC_PIPE_BUF) };
    assert!(atomic_limit >= POSTFLIGHT_LIMIT as libc::c_long);
    endpoints
}
/// Candidate-only, once-consumed export after the application's full postflight.
/// The receiving parent authenticates the packet after both normal child reaps.
pub struct PostflightOutput {
    fd: Fd,
    deadline: Deadline,
}
impl PostflightOutput {
    pub fn finish(self, bytes: &[u8]) {
        assert!(!bytes.is_empty() && bytes.len() <= POSTFLIGHT_LIMIT);
        write_all(self.fd.0, bytes, self.deadline);
        self.deadline.check();
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Scenario {
    StableA,
    RearmB,
    RemovedChild,
}
impl Scenario {
    pub fn id(self) -> u64 {
        match self {
            Self::StableA => 1,
            Self::RearmB => 2,
            Self::RemovedChild => 3,
        }
    }
    pub fn from_id(id: u64) -> Self {
        match id {
            1 => Self::StableA,
            2 => Self::RearmB,
            3 => Self::RemovedChild,
            _ => panic!("call-pair scenario"),
        }
    }
    pub fn helper(self) -> bool {
        self != Self::StableA
    }
    pub fn sampled_child(self) -> bool {
        self != Self::RemovedChild
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    pub k: usize,
    pub index: usize,
    pub scenario: Scenario,
    pub selections: [u64; 2],
    pub extents: [usize; 2],
}
impl Case {
    pub fn new(
        k: usize,
        index: usize,
        scenario: Scenario,
        selections: [u64; 2],
        extents: [usize; 2],
    ) -> Self {
        assert!(matches!(k, 10 | 1000) && index < 16);
        assert!((5..=80).contains(&extents[0]) && (5..=256).contains(&extents[1]));
        let ends = std::array::from_fn::<_, 2, _>(|i| {
            selections[i].checked_add(extents[i] as u64).unwrap()
        });
        assert!(
            selections.iter().all(|&a| a != 0)
                && (ends[0] <= selections[1] || ends[1] <= selections[0])
        );
        Self {
            k,
            index,
            scenario,
            selections,
            extents,
        }
    }
    pub fn assert_valid(self) {
        assert_eq!(
            self,
            Self::new(
                self.k,
                self.index,
                self.scenario,
                self.selections,
                self.extents
            )
        );
    }
    pub fn csv(self) -> csv::Case {
        csv::Case::new(self.index)
    }
    pub fn bound(self) -> usize {
        self.csv().length()
    }
    pub fn fields(self) -> u64 {
        self.csv().expected()
    }
    pub fn value(self) -> u64 {
        (self.bound() as u64) << 32 | self.fields()
    }
}
pub fn keys() -> Vec<(usize, u64, usize, Scenario)> {
    let mut keys = Vec::with_capacity(192);
    for k in [10, 1000] {
        for seed in SEEDS {
            for index in 0..16 {
                for scenario in [Scenario::StableA, Scenario::RearmB, Scenario::RemovedChild] {
                    keys.push((k, seed, index, scenario));
                }
            }
        }
    }
    assert_eq!(keys.len(), 192);
    keys
}
pub(super) struct Profile {
    pub(super) case: Case,
    pub(super) plan: Plan,
    parent: parent::Parent,
    caller: u64,
    caller_pages: Vec<(u64, Vec<u8>)>,
    code: [Vec<u8>; 2],
    diagnostic_origin: Option<(u64, u64)>,
}
impl Profile {
    fn new(
        case: Case,
        plan: Plan,
        caller: u64,
        caller_pages: Vec<(u64, Vec<u8>)>,
        code: [Vec<u8>; 2],
    ) -> Self {
        case.assert_valid();
        assert_eq!(rust_invoke::admit(plan.bytes()).unwrap(), plan);
        assert_eq!(code.each_ref().map(|b| b.len()), case.extents);
        validate_caller(caller, &plan, &caller_pages);
        let parent = parent::Parent::decode(&code[0], case.selections[0], case.selections[1]);
        let _ = csv::graph(&code[1]);
        Self {
            case,
            plan,
            parent,
            caller,
            caller_pages,
            code,
            diagnostic_origin: None,
        }
    }
    fn set_diagnostic_origin(&mut self, (elf_va, load_bias): (u64, u64)) {
        assert!(self.diagnostic_origin.is_none());
        assert_eq!(self.caller.checked_sub(elf_va), Some(load_bias));
        self.diagnostic_origin = Some((elf_va, load_bias));
    }
    pub(super) fn stack_below(&self) -> u64 {
        let b = self.plan.protected_stack_below().max(
            self.plan
                .subject_rsp_delta()
                .checked_add(self.parent.delta)
                .unwrap()
                .checked_add(128)
                .unwrap(),
        );
        assert!(b <= 448);
        b
    }
}
fn validate_caller(caller: u64, plan: &Plan, pages: &[(u64, Vec<u8>)]) {
    assert!(caller != 0 && (1..=2).contains(&pages.len()));
    let end = caller.checked_add(plan.bytes().len() as u64).unwrap();
    let expected: BTreeSet<_> = [caller & !4095, (end - 1) & !4095].into_iter().collect();
    assert_eq!(
        pages.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
        expected.into_iter().collect::<Vec<_>>()
    );
    assert!(
        pages
            .iter()
            .all(|(a, b)| *a != 0 && a % 4096 == 0 && b.len() == PAGE)
    );
    assert_eq!(
        leaf_set_copied::source_bytes(pages, caller, plan.bytes().len()),
        plan.bytes()
    );
}
#[derive(Clone)]
pub struct Ready {
    pub caller: u64,
    pub caller_immutable: Vec<(u64, Vec<u8>)>,
    pub functions: [module::Function; 2],
    pub immutable: Vec<(u64, Vec<u8>)>,
    pub original_sources: Vec<(u64, Vec<u8>)>,
    pub journal: Option<JournalReady>,
    pub case: Case,
    pub plan: Plan,
    /// Exact sealed profile metadata: reserve,context,descriptor,recovery.
    pub layout: [u64; 4],
}
impl Ready {
    pub fn parent(&self) -> &module::Function {
        &self.functions[0]
    }
    pub fn child(&self) -> &module::Function {
        &self.functions[1]
    }
    fn parent_plan(&self) -> parent::Parent {
        parent::Parent::decode(
            &leaf_set_copied::source_bytes(
                &self.original_sources,
                self.parent().entry,
                self.case.extents[0],
            ),
            self.parent().entry,
            self.child().entry,
        )
    }
    pub(super) fn view(&self) -> copied_rust::CallerView<'_> {
        copied_rust::CallerView {
            caller: self.caller,
            plan: &self.plan,
            target: self.parent(),
            bound: self.case.bound(),
            value: self.case.value(),
            journal: self.journal.as_ref(),
        }
    }
    pub(super) fn validate(&self, candidate: bool, p: &Profile) -> BTreeMap<u64, u64> {
        self.case.assert_valid();
        assert_eq!(self.case, p.case);
        assert_eq!(self.plan, p.plan);
        assert_eq!(self.caller, p.caller);
        assert_eq!(self.caller_immutable, p.caller_pages);
        assert_eq!(rust_invoke::admit(self.plan.bytes()).unwrap(), self.plan);
        validate_caller(self.caller, &self.plan, &self.caller_immutable);
        assert_eq!(self.layout, [240, 416, 144, 400]);
        let bias = self
            .parent()
            .entry
            .checked_sub(self.case.selections[0])
            .unwrap();
        assert_eq!(bias % 4096, 0);
        let page_set: BTreeSet<_> = (0..2)
            .flat_map(|i| {
                let a = bias.checked_add(self.case.selections[i]).unwrap();
                [
                    a & !4095,
                    (a.checked_add(self.case.extents[i] as u64).unwrap() - 1) & !4095,
                ]
            })
            .collect();
        assert!((1..=2).contains(&page_set.len()));
        assert_eq!(
            self.original_sources
                .iter()
                .map(|(a, _)| *a)
                .collect::<Vec<_>>(),
            page_set.into_iter().collect::<Vec<_>>()
        );
        let count = self.original_sources.len();
        assert!((count..=count + 10).contains(&self.immutable.len()));
        assert!(
            self.original_sources
                .iter()
                .all(|(a, b)| a % 4096 == 0 && b.len() == PAGE)
        );
        assert!(
            self.immutable[count..]
                .iter()
                .map(|(_, b)| b.len())
                .sum::<usize>()
                <= 81920
        );
        let mut ranges: Vec<_> = self
            .caller_immutable
            .iter()
            .map(|(a, b)| (*a, a.checked_add(b.len() as u64).unwrap()))
            .collect();
        for (n, (a, b)) in self.immutable.iter().enumerate() {
            if n < count {
                assert_eq!(*a, self.original_sources[n].0);
                assert_eq!(b.len(), PAGE);
            } else {
                assert!(candidate && !b.is_empty() && b.len() <= 8192);
            }
            let end = a.checked_add(b.len() as u64).unwrap();
            assert!(ranges.iter().all(|&(x, y)| end <= x || y <= *a));
            ranges.push((*a, end));
        }
        let parent = self.parent_plan();
        assert_eq!(parent.delta, p.parent.delta);
        let mut map = BTreeMap::new();
        let mut extents = Vec::new();
        for (n, f) in self.functions.iter().enumerate() {
            assert_eq!(f.entry, bias.checked_add(self.case.selections[n]).unwrap());
            let end = f.entry.checked_add(self.case.extents[n] as u64).unwrap();
            extents.push((f.entry, end));
            let code = leaf_set_copied::source_bytes(
                &self.original_sources,
                f.entry,
                self.case.extents[n],
            );
            assert_eq!(code, p.code[n]);
            let (heads, returns) = if n == 0 {
                (parent.heads(), vec![parent.ret()])
            } else {
                let g = csv::graph(&code);
                (
                    g.heads.into_iter().collect(),
                    g.returns.into_iter().collect(),
                )
            };
            assert_eq!(
                f.heads,
                heads.iter().map(|h| f.entry + h).collect::<Vec<_>>()
            );
            assert_eq!(
                f.returns,
                returns.iter().map(|r| f.entry + r).collect::<Vec<_>>()
            );
            assert_eq!(f.boundaries.len(), f.heads.len());
            let mut logical = BTreeSet::new();
            for &(a, b) in &f.boundaries {
                assert!(f.heads.contains(&a) && logical.insert(a));
                assert!(map.insert(b, a).is_none());
                assert!(b==a||candidate&&self.immutable[count..].iter().any(|(x,y)|*x<=b&&b<x.checked_add(y.len()as u64).unwrap()));
            }
            assert_eq!(logical, f.heads.iter().copied().collect());
        }
        assert!(extents[0].1 <= extents[1].0 || extents[1].1 <= extents[0].0);
        let call = self.parent().entry + parent.call;
        assert_eq!(map.get(&call), Some(&call));
        if candidate {
            for role in [
                self.parent().entry,
                self.parent().entry + parent.continuation,
                self.parent().returns[0],
                self.child().entry,
            ]
            .into_iter()
            .chain(self.child().returns.iter().copied())
            {
                assert!(
                    !map.contains_key(&role),
                    "managed role is observed only after callback restoration"
                );
            }
        }
        assert_eq!(
            leaf_set_copied::source_bytes(&self.immutable[..count], call, 5),
            parent.code[parent.call as usize..parent.call as usize + 5]
        );
        for ((a, b), (_, actual)) in self.original_sources.iter().zip(&self.immutable) {
            for (i, (&old, &new)) in b.iter().zip(actual).enumerate() {
                let pc = a.checked_add(i as u64).unwrap();
                if !extents.iter().any(|&(x, y)| x <= pc && pc < y) {
                    assert_eq!(old, new);
                }
            }
        }
        if candidate {
            let j = self.journal.as_ref().expect("actual call-pair journal");
            assert_eq!(j.address % 4096, 0);
            assert_ne!(j.address, 0);
            let end = j.address.checked_add(4096).unwrap();
            assert!(ranges.iter().all(|&(a, b)| end <= a || b <= j.address));
            assert_ne!(j.a_generation, 0);
            if self.case.scenario == Scenario::RearmB {
                assert!(
                    j.b_generation
                        .is_some_and(|b| b != 0 && b != j.a_generation)
                );
            } else {
                assert!(j.b_generation.is_none());
            }
            assert_eq!(j.helper_tid.is_some(), self.case.scenario.helper());
            assert!(j.helper_tid.is_none_or(|t| t != 0));
        } else {
            assert!(self.journal.is_none());
            assert_eq!(self.immutable, self.original_sources);
            assert!(
                self.functions
                    .iter()
                    .all(|f| f.boundaries.iter().all(|(a, b)| a == b))
            );
        }
        map
    }
    pub(super) fn same_source(&self, b: &Self) {
        assert_eq!(
            (self.case, &self.plan, self.caller, self.layout),
            (b.case, &b.plan, b.caller, b.layout)
        );
        assert_eq!(self.caller_immutable, b.caller_immutable);
        assert_eq!(self.original_sources, b.original_sources);
        for (a, b) in self.functions.iter().zip(&b.functions) {
            assert_eq!(
                (a.entry, &a.heads, &a.returns),
                (b.entry, &b.heads, &b.returns)
            );
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = VERSION.to_vec();
        for v in [
            self.caller,
            self.case.k as u64,
            self.case.index as u64,
            self.case.scenario.id(),
            self.case.selections[0],
            self.case.selections[1],
            self.case.extents[0] as u64,
            self.case.extents[1] as u64,
        ] {
            word(&mut out, v);
        }
        for v in self.layout {
            word(&mut out, v);
        }
        word(&mut out, self.plan.bytes().len() as u64);
        out.extend(self.plan.bytes());
        for f in &self.functions {
            word(&mut out, f.entry);
            for list in [&f.heads, &f.returns] {
                word(&mut out, list.len() as u64);
                for &v in list {
                    word(&mut out, v);
                }
            }
            word(&mut out, f.boundaries.len() as u64);
            for &(a, b) in &f.boundaries {
                word(&mut out, a);
                word(&mut out, b);
            }
        }
        for pages in [
            &self.caller_immutable,
            &self.immutable,
            &self.original_sources,
        ] {
            word(&mut out, pages.len() as u64);
            for (a, b) in pages {
                word(&mut out, *a);
                word(&mut out, b.len() as u64);
                out.extend(b);
            }
        }
        word(&mut out, u64::from(self.journal.is_some()));
        if let Some(j) = &self.journal {
            for v in [
                j.address,
                j.a_generation,
                j.b_generation.unwrap_or(0),
                j.helper_tid.unwrap_or(0),
            ] {
                word(&mut out, v);
            }
        }
        assert!(out.len() <= WIRE_LIMIT);
        out
    }
    pub(super) fn decode(wire: &[u8], expected: &Profile) -> Self {
        assert!(wire.len() <= WIRE_LIMIT);
        let mut b = wire
            .strip_prefix(VERSION)
            .expect("original call-pair Ready version");
        let caller = take_word(&mut b);
        let k = usize::try_from(take_word(&mut b)).unwrap();
        let index = usize::try_from(take_word(&mut b)).unwrap();
        let scenario = Scenario::from_id(take_word(&mut b));
        let selections = std::array::from_fn(|_| take_word(&mut b));
        let extents = std::array::from_fn(|_| usize::try_from(take_word(&mut b)).unwrap());
        let case = Case::new(k, index, scenario, selections, extents);
        assert_eq!(case, expected.case);
        let layout = std::array::from_fn(|_| take_word(&mut b));
        let plan = rust_invoke::admit(&take_data(&mut b)).unwrap();
        assert_eq!(plan, expected.plan);
        let functions = std::array::from_fn(|_| {
            let entry = take_word(&mut b);
            let mut list = |cap| {
                let n = usize::try_from(take_word(&mut b)).unwrap();
                assert!((1..=cap).contains(&n));
                (0..n).map(|_| take_word(&mut b)).collect::<Vec<_>>()
            };
            let heads = list(256);
            let returns = list(4);
            let n = take_word(&mut b);
            assert!((1..=256).contains(&n));
            let boundaries = (0..n)
                .map(|_| (take_word(&mut b), take_word(&mut b)))
                .collect();
            module::Function {
                entry,
                heads,
                returns,
                boundaries,
            }
        });
        let mut pages = |cap| {
            let n = usize::try_from(take_word(&mut b)).unwrap();
            assert!((1..=cap).contains(&n));
            (0..n)
                .map(|_| (take_word(&mut b), take_data(&mut b)))
                .collect()
        };
        let caller_immutable = pages(2);
        let immutable = pages(12);
        let original_sources = pages(2);
        let journal = match take_word(&mut b) {
            0 => None,
            1 => {
                let address = take_word(&mut b);
                let a_generation = take_word(&mut b);
                let bg = take_word(&mut b);
                let t = take_word(&mut b);
                Some(JournalReady {
                    address,
                    a_generation,
                    b_generation: (bg != 0).then_some(bg),
                    helper_tid: (t != 0).then_some(t),
                })
            }
            _ => panic!("call-pair journal tag"),
        };
        assert!(b.is_empty());
        Self {
            caller,
            caller_immutable,
            functions,
            immutable,
            original_sources,
            journal,
            case,
            plan,
            layout,
        }
    }
}
impl NormalOracle {
    pub fn new_call_pair(
        seed: u64,
        case: Case,
        plan: Plan,
        caller: u64,
        caller_pages: Vec<(u64, Vec<u8>)>,
        code: [Vec<u8>; 2],
        deadline: Deadline,
    ) -> Self {
        deadline.check();
        assert!(SEEDS.contains(&seed));
        let p = Profile::new(case, plan, caller, caller_pages, code);
        let mut oracle = Self::new_body(
            seed,
            Body::Csv(case.csv()),
            case.extents[1],
            deadline,
            Mode::Stable,
        );
        oracle.call_pair = Some(p);
        oracle
    }
    /// Diagnostic metadata only; callers supply the already authenticated ELF origin.
    /// This does not replace any Ready, file, mapping, or instruction identity check.
    pub fn with_call_pair_diagnostic_origin(mut self, origin: (u64, u64)) -> Self {
        self.call_pair
            .as_mut()
            .expect("call-pair diagnostic profile")
            .set_diagnostic_origin(origin);
        self
    }
    pub fn pair_call_pair<F>(
        &self,
        setup: F,
    ) -> (NormalPairResult<2>, Trace, [trace_join::WorkRow; 2])
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let p = self.call_pair.as_ref().expect("call-pair profile");
        assert!(self.module.is_none() && self.reference.is_none() && !self.has_copied_caller());
        let (pair, (trace, work), stats) =
            self.pair_engine_ready::<F, _, _, 2>(setup, |r, candidate, points, postflight| {
                let trace = trace::inspect(self, r.call_pair(), candidate.call_pair(), points);
                let work = trace_join::join(
                    self.seed,
                    r.call_pair(),
                    candidate.call_pair(),
                    points,
                    &trace,
                    postflight.expect("candidate postflight after both normal reaps"),
                );
                let visits = [trace.parent_visits, trace.child.visits];
                ((trace, work), visits)
            });
        assert!(stats.is_none());
        trace::validate_pair(p.case, &p.plan, &pair, &trace);
        (pair, trace, work)
    }
}
impl NormalContext<'_> {
    pub fn take_call_pair_output(&mut self) -> Option<PostflightOutput> {
        assert!(self.oracle.call_pair.is_some());
        self.call_pair_output.take().map(|fd| PostflightOutput {
            fd,
            deadline: self.oracle.deadline,
        })
    }
    pub fn call_pair_case(&self) -> Case {
        self.oracle
            .call_pair
            .as_ref()
            .expect("call-pair context")
            .case
    }
    pub fn ready_call_pair(self, ready: &Ready) {
        assert_eq!(ready.case, self.call_pair_case());
        let p = self.oracle.call_pair.as_ref().unwrap();
        assert_eq!(ready.plan, p.plan);
        assert_eq!(ready.caller, p.caller);
        assert_eq!(ready.caller_immutable, p.caller_pages);
        assert!(self.control.is_none() && self.output.is_none() && self.call_pair_output.is_none());
        write_all(self.write.0, &ready.encode(), self.oracle.deadline);
        drop(self.write);
        self.oracle.deadline.check();
        unsafe {
            assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
            assert_eq!(libc::raise(libc::SIGSTOP), 0);
        }
    }
}
/// Full physical journal at the declared phase; no new event on acknowledgement.
pub fn journal(
    ready: &Ready,
    pid: u64,
    rsp: u64,
    child_ret: Option<u64>,
    parent_ret: Option<u64>,
    used: usize,
    depth: u64,
) -> [u64; 512] {
    assert!((0..=4).contains(&used));
    let p = ready.parent_plan();
    let j = ready.journal.as_ref().unwrap();
    let prsp = rsp.checked_sub(ready.plan.subject_rsp_delta()).unwrap();
    let crsp = prsp.checked_sub(p.delta).unwrap();
    let cont = ready.parent().entry + p.continuation;
    let (kind, cgen, cbits) = match ready.case.scenario {
        Scenario::StableA => (1, j.a_generation, 2 | (1 << 13)),
        Scenario::RearmB => (1, j.b_generation.unwrap(), 1 | (2 << 13)),
        Scenario::RemovedChild => (3, j.a_generation, (2 << 13) | (2 << 22)),
    };
    let events = [
        [
            1,
            1,
            ready.parent().entry,
            prsp,
            ready.caller + ready.plan.continuations()[0],
            j.a_generation,
            1 | (1 << 13),
        ],
        [kind, 2, ready.child().entry, crsp, cont, cgen, cbits],
        [kind + 1, 2, child_ret.unwrap_or(0), crsp, cont, cgen, cbits],
        [
            2,
            1,
            parent_ret.unwrap_or(0),
            prsp,
            ready.caller + ready.plan.continuations()[0],
            j.a_generation,
            1 | (1 << 13),
        ],
    ];
    if used >= 3 {
        assert!(ready.child().returns.contains(&child_ret.unwrap()));
    }
    if used == 4 {
        assert_eq!(parent_ret, Some(ready.parent().returns[0]));
    }
    let allowed = matches!(
        (used, depth),
        (0, 0) | (1, 1) | (2, 2) | (3, 2) | (3, 1) | (4, 1) | (4, 0)
    );
    assert!(allowed);
    let mut out = [0; 512];
    out[..4].copy_from_slice(&[used as u64, 0, pid, depth]);
    for (i, e) in events.iter().take(used).enumerate() {
        out[4 + i * 7..11 + i * 7].copy_from_slice(e);
    }
    out
}
pub(super) fn check_ack(words: &[u64], stage: usize, pid: u64, ready: &Ready) {
    assert!((1..=2).contains(&stage));
    let j = ready.journal.as_ref().unwrap();
    assert!(ready.case.scenario.helper());
    let helper = j.helper_tid.unwrap();
    assert!(helper != 0 && helper != pid);
    let rearm = ready.case.scenario == Scenario::RearmB;
    let expected = [
        ACK_MAGIC,
        stage as u64,
        pid,
        helper,
        j.a_generation,
        j.b_generation.unwrap_or(0),
        0,
        u64::from(rearm && stage == 2),
        if rearm && stage == 2 { 3 } else { 2 },
        if rearm && stage == 1 {
            j.b_generation.unwrap()
        } else {
            0
        },
    ];
    assert_eq!(words, &expected);
}
#[cfg(test)]
#[path = "native_call_pair/tests.rs"]
mod tests;
