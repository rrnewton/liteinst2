//! Distinct Exact37 accuracy SDK copied-caller profile. All runtime results are external.
pub use super::selected_leaf_set::Selection;
use super::*;
use rust_invoke::Plan;
#[path = "native_exact_accuracy/trace.rs"]
mod trace;
pub use trace::Trace;
const VERSION: &[u8] = b"EXACT37-ACCURACY-COPIED-STATE-V1\0";
pub const PROFILE: &str = "exact37-accuracy-copied-state-v1";
pub const LABEL: &str = "exact37-accuracy-state-v1";
pub const FUNCTION_ID: u64 = 41;
// Same immutable original symbol as tools/rapid-profiler/exact-work/truth.rs.
// The runtime original-body callback independently invokes that interpreter.
pub const BODY: [u8; 37] = [
    0x31, 0xc0, 0x4c, 0x8d, 0x04, 0x37, 0x0f, 0xb6, 0x0f, 0x83, 0xf1, 0x5a, 0x48, 0x01, 0xc8, 0x48,
    0xff, 0xc7, 0x4c, 0x39, 0xc7, 0x72, 0xef, 0x48, 0xba, 0x15, 0x7c, 0x4a, 0x7f, 0xb9, 0x79, 0x37,
    0x9e, 0x48, 0x31, 0xd0, 0xc3,
];
pub const HEADS: [u64; 11] = [0, 2, 6, 9, 12, 15, 18, 21, 23, 33, 36];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    seed: u64,
    length: usize,
    selection: Selection,
}
fn number(s: &str) -> u64 {
    assert!(!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    assert!(s.len() == 1 || !s.starts_with('0'));
    s.parse().unwrap()
}
impl Case {
    pub fn parse(args: &[&str]) -> Self {
        assert_eq!(args.len(), 4);
        Self::new(
            number(args[0]),
            usize::try_from(number(args[1])).unwrap(),
            number(args[2]),
            usize::try_from(number(args[3])).unwrap(),
        )
    }
    pub fn new(seed: u64, length: usize, elf_va: u64, extent: usize) -> Self {
        assert!(SEEDS.contains(&seed) && (1..=64).contains(&length));
        assert_eq!(extent, BODY.len());
        assert_ne!(elf_va, 0);
        elf_va.checked_add(extent as u64).unwrap();
        assert!(elf_va % PAGE as u64 + extent as u64 <= PAGE as u64);
        Self {
            seed,
            length,
            selection: Selection { elf_va, extent },
        }
    }
    pub(super) fn assert_valid(self) {
        assert_eq!(
            self,
            Self::new(
                self.seed,
                self.length,
                self.selection.elf_va,
                self.selection.extent
            )
        );
    }
    pub fn seed(self) -> u64 {
        self.seed
    }
    pub fn k(self) -> usize {
        10
    }
    pub fn function_id(self) -> u64 {
        FUNCTION_ID
    }
    pub fn bound(self) -> usize {
        self.length
    }
    pub fn selected(self) -> usize {
        0
    }
    pub fn n(self) -> usize {
        1
    }
    pub fn table(self) -> [(usize, Selection); 1] {
        [(0, self.selection)]
    }
    pub fn selections(self) -> [Selection; 1] {
        [self.selection]
    }
    pub fn input(self) -> [u8; 64] {
        self.assert_valid();
        let index = SEEDS.iter().position(|&s| s == self.seed).unwrap();
        std::array::from_fn(|j| (37 * j + 11 + index) as u8)
    }
    pub fn value(self) -> u64 {
        self.input()[..self.length]
            .iter()
            .map(|&b| u64::from(b ^ 0x5a))
            .sum::<u64>()
            ^ 0x9e37_79b9_7f4a_7c15
    }
    pub fn counts(self) -> (usize, usize, usize, usize) {
        self.assert_valid();
        (
            6 * self.length + 5,
            self.length,
            self.length - 1,
            self.length + 1,
        )
    }
    pub fn itinerary(self) -> Vec<u64> {
        self.assert_valid();
        let mut v = vec![0, 2];
        for _ in 0..self.length {
            v.extend([6, 9, 12, 15, 18, 21]);
        }
        v.extend([23, 33, 36]);
        assert_eq!(v.len(), self.counts().0);
        v
    }
}
pub fn keys() -> Vec<(u64, usize)> {
    SEEDS
        .into_iter()
        .flat_map(|seed| (1..=64).map(move |length| (seed, length)))
        .collect()
}
fn caller_plan(plan: &Plan) {
    assert_eq!(rust_invoke::admit(plan.bytes()).unwrap(), *plan);
    assert_eq!(plan.bytes().len(), 20);
    assert_eq!(plan.heads(), [0, 1, 4, 7, 10, 13, 15, 18, 19]);
    assert_eq!(plan.calls(), &[13]);
    assert_eq!(plan.continuations(), &[15]);
    assert_eq!(plan.outer_ret(), 19);
    assert_eq!(
        (plan.subject_rsp_delta(), plan.protected_stack_below() + 8),
        (16, 152)
    );
}
pub(super) struct Profile {
    pub(super) case: Case,
    pub(super) plan: Plan,
    caller: u64,
    source: (u64, Vec<u8>),
    leaf_page: Vec<u8>,
}
impl Profile {
    fn new(
        case: Case,
        plan: Plan,
        caller: u64,
        source: (u64, Vec<u8>),
        leaf_page: Vec<u8>,
    ) -> Self {
        case.assert_valid();
        caller_plan(&plan);
        assert_eq!(leaf_page.len(), PAGE);
        let at = (case.selection.elf_va % PAGE as u64) as usize;
        assert_eq!(&leaf_page[at..at + BODY.len()], BODY);
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
            leaf_page,
        }
    }
}
#[derive(Clone)]
pub struct Ready {
    pub caller: u64,
    pub caller_immutable: Vec<(u64, Vec<u8>)>,
    pub functions: Vec<module::Function>,
    pub immutable: Vec<(u64, Vec<u8>)>,
    pub original_sources: Vec<(u64, Vec<u8>)>,
    pub journal: Option<JournalReady>,
    pub case: Case,
    pub plan: Plan,
}
/// Copy only a checked complete range; no synthetic gap between noncontiguous pages.
pub fn source_bytes(pages: &[(u64, Vec<u8>)], address: u64, length: usize) -> Vec<u8> {
    let end = address.checked_add(length as u64).unwrap();
    (address..end)
        .map(|pc| {
            let matches: Vec<_> = pages
                .iter()
                .filter(|(a, b)| *a <= pc && pc < a.checked_add(b.len() as u64).unwrap())
                .collect();
            assert_eq!(matches.len(), 1);
            let (a, b) = matches[0];
            b[(pc - *a) as usize]
        })
        .collect()
}
impl Ready {
    pub fn target(&self) -> &module::Function {
        &self.functions[self.case.selected()]
    }
    pub(super) fn view(&self) -> copied_rust::CallerView<'_> {
        copied_rust::CallerView {
            caller: self.caller,
            plan: &self.plan,
            target: self.target(),
            bound: self.case.bound(),
            value: self.case.value(),
            journal: self.journal.as_ref(),
        }
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
        assert_eq!(self.functions.len(), self.case.n());
        let table = self.case.table();
        let bias = self.functions[0]
            .entry
            .checked_sub(table[0].1.elf_va)
            .unwrap();
        assert_eq!(bias % PAGE as u64, 0);
        let page_set: BTreeSet<_> = table
            .iter()
            .flat_map(|(_, s)| {
                let a = bias.checked_add(s.elf_va).unwrap();
                [
                    a & !(PAGE as u64 - 1),
                    (a.checked_add(s.extent as u64).unwrap() - 1) & !(PAGE as u64 - 1),
                ]
            })
            .collect();
        assert_eq!(page_set.len(), 1);
        assert_eq!(
            self.original_sources
                .iter()
                .map(|(a, _)| *a)
                .collect::<Vec<_>>(),
            page_set.iter().copied().collect::<Vec<_>>()
        );
        assert_eq!(self.original_sources[0].1, expected.leaf_page);
        let count = self.original_sources.len();
        assert_eq!(
            self.immutable.len(),
            if candidate { count + 1 } else { count }
        );
        assert!(
            self.immutable[count..]
                .iter()
                .map(|(_, b)| b.len())
                .sum::<usize>()
                <= 8192
        );
        let mut ranges = vec![(
            expected.source.0,
            expected.source.0.checked_add(PAGE as u64).unwrap(),
        )];
        for (i, (a, b)) in self.immutable.iter().enumerate() {
            if i < count {
                assert_eq!(*a, self.original_sources[i].0);
                assert_eq!(b.len(), PAGE);
                assert_eq!(self.original_sources[i].1.len(), PAGE);
            } else {
                assert!(candidate && !b.is_empty() && b.len() <= 8192);
            }
            let end = a.checked_add(b.len() as u64).unwrap();
            assert!(ranges.iter().all(|&(x, y)| end <= x || y <= *a));
            ranges.push((*a, end));
        }
        let mut physical = BTreeMap::new();
        let mut extents = Vec::new();
        for ((_, selection), f) in table.iter().zip(&self.functions) {
            assert_eq!(f.entry, bias.checked_add(selection.elf_va).unwrap());
            let end = f.entry.checked_add(selection.extent as u64).unwrap();
            let code = source_bytes(&self.original_sources, f.entry, selection.extent);
            let mut decoder = Decoder::with_ip(64, &code, f.entry, DecoderOptions::NONE);
            let mut heads = Vec::new();
            let mut returns = Vec::new();
            while decoder.can_decode() {
                let instruction = decoder.decode();
                assert!(!instruction.is_invalid() && instruction.next_ip() <= end);
                heads.push(instruction.ip());
                if instruction.flow_control() == FlowControl::Return {
                    assert_eq!(
                        &code[(instruction.ip() - f.entry) as usize
                            ..(instruction.next_ip() - f.entry) as usize],
                        &[0xc3]
                    );
                    returns.push(instruction.ip());
                }
            }
            assert_eq!(decoder.position(), selection.extent);
            assert_eq!(f.heads, heads);
            assert_eq!(f.returns, returns);
            assert_eq!(f.heads.first(), Some(&f.entry));
            assert!((1..=256).contains(&heads.len()) && (1..=4).contains(&returns.len()));
            assert_eq!(code, BODY);
            assert_eq!(
                heads,
                HEADS.iter().map(|&at| f.entry + at).collect::<Vec<_>>()
            );
            assert_eq!(
                returns,
                [36].iter()
                    .map(|&at| f.entry + at as u64)
                    .collect::<Vec<_>>()
            );
            assert_eq!(f.boundaries.len(), f.heads.len());
            let mut logical = BTreeSet::new();
            for &(a, b) in &f.boundaries {
                assert!(f.heads.contains(&a) && logical.insert(a));
                assert!(physical.insert(b, a).is_none());
                assert!(b == a || candidate && self.immutable[count..].iter().any(|(x, y)| *x <= b && b < x.checked_add(y.len() as u64).unwrap()));
                // The complete Exact37 body is displaced by WholeFunction. Every
                // original head must therefore have a distinct generated owner.
                if candidate {
                    assert_ne!(a, b, "displaced head cannot use identity");
                }
            }
            assert_eq!(logical, f.heads.iter().copied().collect());
            extents.push((f.entry, end));
        }
        for pair in extents.windows(2) {
            assert!(pair[0].1 <= pair[1].0);
        }
        for ((a, original), (b, actual)) in self.original_sources.iter().zip(&self.immutable) {
            assert_eq!(a, b);
            for (offset, (&before, &after)) in original.iter().zip(actual).enumerate() {
                let pc = a.checked_add(offset as u64).unwrap();
                if !extents.iter().any(|&(x, y)| x <= pc && pc < y) {
                    assert_eq!(before, after);
                }
            }
        }
        if candidate {
            let j = self.journal.as_ref().expect("actual LeafSet journal");
            assert_eq!(j.address % PAGE as u64, 0);
            let end = j.address.checked_add(PAGE as u64).unwrap();
            assert!(ranges.iter().all(|&(a, b)| end <= a || b <= j.address));
            assert_ne!(j.a_generation, 0);
            assert!(j.b_generation.is_none() && j.helper_tid.is_none());
        } else {
            assert!(self.journal.is_none());
            assert_eq!(self.immutable, self.original_sources);
            for f in &self.functions {
                assert!(f.boundaries.iter().all(|(a, b)| a == b));
            }
        }
        physical
    }
    pub(super) fn same_source(&self, other: &Self) {
        assert_eq!(
            (self.case, &self.plan, self.caller),
            (other.case, &other.plan, other.caller)
        );
        assert_eq!(self.caller_immutable, other.caller_immutable);
        assert_eq!(self.original_sources, other.original_sources);
        assert_eq!(self.functions.len(), other.functions.len());
        for (a, b) in self.functions.iter().zip(&other.functions) {
            assert_eq!(
                (a.entry, &a.heads, &a.returns),
                (b.entry, &b.heads, &b.returns)
            );
        }
    }
    fn encode(&self) -> Vec<u8> {
        self.case.assert_valid();
        let mut out = VERSION.to_vec();
        for n in [
            self.caller,
            self.case.seed,
            self.case.length as u64,
            self.case.selection.elf_va,
            self.case.selection.extent as u64,
            10,
            41,
            1,
        ] {
            word(&mut out, n);
        } // Closed K, function ID and WholeFunction policy.
        assert!(out.len() <= 1024);
        word(&mut out, self.plan.bytes().len() as u64);
        out.extend(self.plan.bytes());
        word(&mut out, self.functions.len() as u64);
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
            .expect("Exact37 accuracy Ready version");
        let caller = take_word(&mut wire);
        let seed = take_word(&mut wire);
        let length = usize::try_from(take_word(&mut wire)).unwrap();
        let va = take_word(&mut wire);
        let extent = usize::try_from(take_word(&mut wire)).unwrap();
        assert_eq!(
            [
                take_word(&mut wire),
                take_word(&mut wire),
                take_word(&mut wire)
            ],
            [10, 41, 1]
        );
        let actual = Case::new(seed, length, va, extent);
        assert_eq!(actual, case);
        let bytes = take_data(&mut wire);
        assert!(bytes.len() <= rust_invoke::MAX_BYTES);
        let actual_plan = rust_invoke::admit(&bytes).unwrap();
        assert_eq!(&actual_plan, plan);
        let n = usize::try_from(take_word(&mut wire)).unwrap();
        assert_eq!(n, case.n());
        let functions = (0..n)
            .map(|_| {
                let entry = take_word(&mut wire);
                let mut list = |cap| {
                    let n = usize::try_from(take_word(&mut wire)).unwrap();
                    assert!(n <= cap);
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
            })
            .collect();
        let mut pages = |cap| {
            let n = usize::try_from(take_word(&mut wire)).unwrap();
            assert!(n <= cap);
            (0..n)
                .map(|_| (take_word(&mut wire), take_data(&mut wire)))
                .collect::<Vec<_>>()
        };
        let caller_immutable = pages(1);
        let immutable = pages(2);
        let original_sources = pages(1);
        let journal = match take_word(&mut wire) {
            0 => None,
            1 => Some(JournalReady {
                address: take_word(&mut wire),
                a_generation: take_word(&mut wire),
                b_generation: None,
                helper_tid: None,
            }),
            _ => panic!("Exact37 accuracy journal tag"),
        };
        assert!(wire.is_empty());
        Self {
            caller,
            caller_immutable,
            functions,
            immutable,
            original_sources,
            journal,
            case,
            plan: actual_plan,
        }
    }
}
impl NormalOracle {
    pub fn new_exact_accuracy(
        case: Case,
        plan: Plan,
        caller: u64,
        source: (u64, Vec<u8>),
        leaf_page: Vec<u8>,
        deadline: Deadline,
    ) -> Self {
        deadline.check();
        case.assert_valid();
        let profile = Profile::new(case, plan, caller, source, leaf_page);
        let mut oracle = Self::new_body(
            case.seed,
            Body::ExactAccuracy(case),
            BODY.len(),
            deadline,
            Mode::Stable,
        );
        oracle.exact_accuracy = Some(profile);
        oracle
    }
    pub fn pair_exact_accuracy<F, O>(&self, setup: F, inspect: O) -> (NormalPairResult<1>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
        O: for<'a> FnOnce(OriginalBody<'a>) -> (usize, usize, usize, usize),
    {
        let p = self
            .exact_accuracy
            .as_ref()
            .expect("separate Exact37 accuracy profile");
        p.case.assert_valid();
        assert!(
            self.selected_leaf_set.is_none()
                && self.copied_rust.is_none()
                && self.leaf_set_copied.is_none()
                && self.call_pair.is_none()
                && self.module.is_none()
                && self.reference.is_none()
        );
        assert_eq!(self.mode, Mode::Stable);
        let (pair, trace, stats) = self.pair_engine::<F, _, _, 1>(setup, |r, points| {
            let t = trace::inspect(self, r.exact_accuracy(), points, inspect);
            let visits = [t.visits];
            (t, visits)
        });
        assert!(stats.is_none());
        trace::validate_pair(p.case, &p.plan, &pair, &trace);
        (pair, trace)
    }
}
impl NormalContext<'_> {
    pub fn exact_accuracy_case(&self) -> Case {
        assert!(
            self.oracle.selected_leaf_set.is_none()
                && self.oracle.leaf_set_copied.is_none()
                && self.oracle.copied_rust.is_none()
                && self.oracle.call_pair.is_none()
                && self.oracle.module.is_none()
                && self.oracle.reference.is_none()
        );
        assert_eq!(self.oracle.mode, Mode::Stable);
        let c = self.oracle.exact_accuracy.as_ref().unwrap().case;
        c.assert_valid();
        c
    }
    pub fn ready_exact_accuracy(self, ready: &Ready) {
        assert_eq!(ready.case, self.exact_accuracy_case());
        assert_eq!(
            ready.plan,
            self.oracle.exact_accuracy.as_ref().unwrap().plan
        );
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
pub fn journal_words(
    ready: &Ready,
    pid: u64,
    rsp: u64,
    returns: &[u64],
    pending: bool,
) -> [u64; 512] {
    copied_rust::journal_words_view(ready.view(), pid, rsp, returns, pending)
}
pub const HEADER: &str = "profile,k,seed,function_id,length,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,instructions,conditional_branches,taken_branches,input_reads,return_reads,return_read_bytes,ret_offset,decoded_heads,observed_heads,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps\n";
pub fn pair_row(case: Case, plan: &Plan, pair: &NormalPairResult<1>, trace: &Trace) -> String {
    trace::validate_pair(case, plan, pair, trace);
    let mut fields = vec![
        PROFILE.into(),
        "10".into(),
        case.seed.to_string(),
        "41".into(),
        case.length.to_string(),
        "PASS".into(),
        "2".into(),
    ];
    fields.extend(
        [
            pair.comparisons as u64,
            pair.visits[0] as u64,
            pair.original_steps as u64,
            pair.candidate_steps as u64,
            pair.values[0],
            pair.outer_value,
            trace.counts.0 as u64,
            trace.counts.1 as u64,
            trace.counts.2 as u64,
            case.length as u64,
            1,
            8,
            36,
            11,
            11,
            plan.bytes().len() as u64,
            plan.heads().len() as u64,
            plan.calls()[0],
            plan.continuations()[0],
            plan.outer_ret(),
            plan.subject_rsp_delta(),
            2,
            2,
            2,
            2,
        ]
        .map(|n| n.to_string()),
    );
    let mut row = String::new();
    leaf_set_copied::append_row(&mut row, &fields, 32, 768, 1024 * 1024);
    row
}
pub fn terminal(case: Case, comparisons: usize) -> String {
    case.assert_valid();
    assert_eq!(comparisons, case.counts().0 + 10);
    let line = format!(
        "native-exact37-accuracy:profile={PROFILE}:k=10:seed={}:function=41:length={}:required=1:pairs=1:children=2:comparisons={comparisons}:target-calls=2:target-returns=2:real-outer-ret=2:normal-reaps=2:scope=copied-body-only:complete\n",
        case.seed, case.length
    );
    assert!(line.len() <= 1024);
    line
}
#[cfg(test)]
#[path = "native_exact_accuracy/tests.rs"]
mod tests;
