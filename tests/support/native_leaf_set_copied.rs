//! Separate E3 LeafSet profile of the existing full-state copied-caller oracle.
//! No loaded authority can be constructed by the metadata calibration fixtures.
use super::*;
use rust_invoke::Plan;
#[path = "native_leaf_set_copied/scanner.rs"]
pub mod scanner;
#[path = "native_leaf_set_copied/trace.rs"]
mod trace;
pub use trace::Trace;
pub type Coverage = trace::Coverage;
pub type Population = trace::Population;
const VERSION: &[u8] = b"LEAF-SET-WHOLE-RUST-V1\0";
pub const PROFILE: &str = "leaf-set-whole-rust-v1";
pub const LABELS: [&str; 4] = [
    "native-leaf-csv-v1",
    "native-leaf-length-v1",
    "native-leaf-digits-v1",
    "native-leaf-spaces-v1",
];
pub const FUNCTION_IDS: [u64; 4] = [301, 302, 303, 304];
pub const CASE_COUNTS: [usize; 4] = [16, 8, 8, 8];
/// Fixed explicit policy of this separately versioned qualification profile.
/// Canonical selected index never chooses policy: original operation identity does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanningPolicy {
    CertifiedBlocks,
    WholeFunction,
}
pub fn policy(operation: usize) -> PlanningPolicy {
    match operation {
        0 => PlanningPolicy::CertifiedBlocks,
        1..=3 => PlanningPolicy::WholeFunction,
        _ => panic!("closed operation"),
    }
}
pub fn maximum_extent(operation: usize) -> usize {
    match policy(operation) {
        PlanningPolicy::CertifiedBlocks => 256,
        PlanningPolicy::WholeFunction => 80,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    pub elf_va: u64,
    pub extent: usize,
}
impl Selection {
    pub fn parse(va: &str, extent: &str, operation: usize) -> Self {
        fn number(s: &str) -> u64 {
            assert!(!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
            assert!(s.len() == 1 || !s.starts_with('0'));
            s.parse().unwrap()
        }
        let s = Self {
            elf_va: number(va),
            extent: usize::try_from(number(extent)).unwrap(),
        };
        s.check(operation);
        s
    }
    fn check(self, operation: usize) {
        assert!(operation < 4 && self.elf_va != 0);
        assert!((5..=maximum_extent(operation)).contains(&self.extent));
        self.elf_va.checked_add(self.extent as u64).unwrap();
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    subset: u8,
    k: usize,
    operation: usize,
    index: usize,
    selections: [Selection; 4],
}
impl Case {
    pub fn new(
        subset: u8,
        k: usize,
        operation: usize,
        index: usize,
        selections: [Selection; 4],
    ) -> Self {
        assert!((1..=15).contains(&subset) && matches!(k, 10 | 1000));
        assert!(operation < 4 && subset & (1 << operation) != 0 && index < CASE_COUNTS[operation]);
        for (i, s) in selections.iter().enumerate() {
            s.check(i);
            let end = s.elf_va.checked_add(s.extent as u64).unwrap();
            for p in &selections[..i] {
                assert!(
                    end <= p.elf_va || p.elf_va.checked_add(p.extent as u64).unwrap() <= s.elf_va
                );
            }
        }
        let c = Self {
            subset,
            k,
            operation,
            index,
            selections,
        };
        let pages: BTreeSet<_> = c
            .table()
            .iter()
            .flat_map(|&(_, s)| {
                [
                    s.elf_va / PAGE as u64,
                    (s.elf_va + s.extent as u64 - 1) / PAGE as u64,
                ]
            })
            .collect();
        assert!((1..=2).contains(&pages.len()));
        c
    }
    pub(super) fn assert_valid(self) {
        assert_eq!(
            self,
            Self::new(
                self.subset,
                self.k,
                self.operation,
                self.index,
                self.selections
            )
        );
    }
    pub fn subset(self) -> u8 {
        self.subset
    }
    pub fn k(self) -> usize {
        self.k
    }
    pub fn operation(self) -> usize {
        self.operation
    }
    pub fn index(self) -> usize {
        self.index
    }
    pub fn n(self) -> usize {
        self.subset.count_ones() as usize
    }
    pub fn function_id(self) -> u64 {
        FUNCTION_IDS[self.operation]
    }
    pub fn selections(self) -> [Selection; 4] {
        self.selections
    }
    pub fn table(self) -> Vec<(usize, Selection)> {
        let mut table: Vec<_> = self
            .selections
            .into_iter()
            .enumerate()
            .filter(|(i, _)| self.subset & (1 << i) != 0)
            .collect();
        table.sort_by_key(|(_, s)| s.elf_va);
        table
    }
    pub fn selected(self) -> usize {
        self.table()
            .iter()
            .position(|(i, _)| *i == self.operation)
            .unwrap()
    }
    pub fn bound(self) -> usize {
        self.body().bound()
    }
    pub fn input(self) -> [u8; 64] {
        self.body().input()
    }
    pub fn value(self) -> u64 {
        self.body().scalar()
    }
    fn body(self) -> Body {
        match self.operation {
            0 => Body::Csv(csv::Case::new(self.index)),
            1 => Body::Strnlen(CASES[self.index]),
            2 => Body::Scanner(scanner::Operation::Digits, scanner::Case::new(self.index)),
            3 => Body::Scanner(scanner::Operation::Spaces, scanner::Case::new(self.index)),
            _ => panic!("closed operation"),
        }
    }
}
pub fn keys() -> Vec<(u8, usize, u64, usize, usize)> {
    let mut out = Vec::with_capacity(1280);
    for subset in 1..=15 {
        for k in [10, 1000] {
            for seed in SEEDS {
                for (operation, &count) in CASE_COUNTS.iter().enumerate() {
                    if subset & (1 << operation) != 0 {
                        for index in 0..count {
                            out.push((subset, k, seed, operation, index));
                        }
                    }
                }
            }
        }
    }
    assert_eq!(out.len(), 1280);
    out
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
        assert!((1..=2).contains(&page_set.len()));
        assert_eq!(
            self.original_sources
                .iter()
                .map(|(a, _)| *a)
                .collect::<Vec<_>>(),
            page_set.iter().copied().collect::<Vec<_>>()
        );
        let count = self.original_sources.len();
        assert!((count..=count + 10).contains(&self.immutable.len()));
        assert!(
            self.immutable[count..]
                .iter()
                .map(|(_, b)| b.len())
                .sum::<usize>()
                <= 81920
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
        for ((operation, selection), f) in table.iter().zip(&self.functions) {
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
            if *operation == 0 {
                csv::validate_geometry(f.entry, &f.heads, &f.returns, &code);
            }
            if *operation >= 2 {
                let plan = scanner::Plan::decode(&code);
                assert_eq!(
                    plan.heads().iter().map(|p| f.entry + p).collect::<Vec<_>>(),
                    f.heads
                );
                assert_eq!(
                    plan.declared()
                        .returns
                        .iter()
                        .map(|p| f.entry + p)
                        .collect::<Vec<_>>(),
                    f.returns
                );
            }
            assert_eq!(f.boundaries.len(), f.heads.len());
            let mut logical = BTreeSet::new();
            for &(a, b) in &f.boundaries {
                assert!(f.heads.contains(&a) && logical.insert(a));
                assert!(physical.insert(b, a).is_none());
                assert!(b == a || candidate && self.immutable[count..].iter().any(|(x, y)| *x <= b && b < x.checked_add(y.len() as u64).unwrap()));
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
            self.case.subset as u64,
            self.case.k as u64,
            self.case.operation as u64,
            self.case.index as u64,
        ] {
            word(&mut out, n);
        }
        for s in self.case.selections {
            word(&mut out, s.elf_va);
            word(&mut out, s.extent as u64);
        }
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
        let mut wire = wire.strip_prefix(VERSION).expect("LeafSet Ready version");
        let caller = take_word(&mut wire);
        let subset = u8::try_from(take_word(&mut wire)).unwrap();
        let k = usize::try_from(take_word(&mut wire)).unwrap();
        let operation = usize::try_from(take_word(&mut wire)).unwrap();
        let index = usize::try_from(take_word(&mut wire)).unwrap();
        let selections = std::array::from_fn(|_| Selection {
            elf_va: take_word(&mut wire),
            extent: usize::try_from(take_word(&mut wire)).unwrap(),
        });
        let actual = Case::new(subset, k, operation, index, selections);
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
        let immutable = pages(12);
        let original_sources = pages(2);
        let journal = match take_word(&mut wire) {
            0 => None,
            1 => Some(JournalReady {
                address: take_word(&mut wire),
                a_generation: take_word(&mut wire),
                b_generation: None,
                helper_tid: None,
            }),
            _ => panic!("LeafSet journal tag"),
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
    pub fn new_leaf_set_copied(
        seed: u64,
        case: Case,
        plan: Plan,
        caller: u64,
        source: (u64, Vec<u8>),
        deadline: Deadline,
    ) -> Self {
        deadline.check();
        case.assert_valid();
        assert!(SEEDS.contains(&seed));
        let mut oracle = Self::new_body(
            seed,
            case.body(),
            case.selections[case.operation].extent,
            deadline,
            Mode::Stable,
        );
        oracle.leaf_set_copied = Some(Profile::new(case, plan, caller, source));
        oracle
    }
    pub fn pair_leaf_set_copied<F>(&self, setup: F) -> (NormalPairResult<1>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let p = self
            .leaf_set_copied
            .as_ref()
            .expect("distinct LeafSet profile");
        p.case.assert_valid();
        assert!(self.copied_rust.is_none() && self.module.is_none() && self.reference.is_none());
        assert_eq!(self.mode, Mode::Stable);
        let (pair, trace, stats) = self.pair_engine::<F, _, _, 1>(setup, |r, points| {
            let t = trace::inspect(self, r.leaf_set_copied(), points);
            let visits = [t.visits()];
            (t, visits)
        });
        assert!(stats.is_none());
        trace::validate_pair(p.case, &p.plan, &pair, &trace);
        (pair, trace)
    }
}
impl NormalContext<'_> {
    pub fn leaf_set_copied_case(&self) -> Case {
        assert!(
            self.oracle.copied_rust.is_none()
                && self.oracle.module.is_none()
                && self.oracle.reference.is_none()
        );
        assert_eq!(self.oracle.mode, Mode::Stable);
        let c = self.oracle.leaf_set_copied.as_ref().unwrap().case;
        c.assert_valid();
        c
    }
    pub fn ready_leaf_set_copied(self, ready: &Ready) {
        assert_eq!(ready.case, self.leaf_set_copied_case());
        assert_eq!(
            ready.plan,
            self.oracle.leaf_set_copied.as_ref().unwrap().plan
        );
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
pub fn journal_words(
    ready: &Ready,
    pid: u64,
    rsp: u64,
    returns: &[u64],
    pending: bool,
) -> [u64; 512] {
    copied_rust::journal_words_view(ready.view(), pid, rsp, returns, pending)
}

pub const HEADER: &str = "profile,subset,n,k,selected_index,function_id,seed,function,case,bound,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,input_reads,input_bytes,ret_offset,observed_heads,declared_heads,observed_edges,declared_edges,declared_returns,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps\n";
pub const COVERAGE_HEADER: &str = "profile,subset,n,k,selected_index,function_id,seed,function,cases,observed_heads,declared_heads,observed_edges,declared_edges,observed_returns,declared_returns,comparisons\n";
pub fn append_row(
    table: &mut String,
    fields: &[String],
    columns: usize,
    row_cap: usize,
    table_cap: usize,
) {
    assert_eq!(fields.len(), columns);
    assert!(
        fields
            .iter()
            .all(|s| !s.contains([',', '\r', '\n']) && s.is_ascii())
    );
    let row = fields.join(",") + "\n";
    assert!(row.len() <= row_cap);
    assert!(table.len().checked_add(row.len()).unwrap() <= table_cap);
    table.push_str(&row);
}
pub fn pair_fields(
    seed: u64,
    case: Case,
    plan: &Plan,
    pair: &NormalPairResult<1>,
    trace: &Trace,
) -> Vec<String> {
    trace::validate_pair(case, plan, pair, trace);
    let (h, dh, e, de, r) = trace.counts();
    let mut f = vec![
        PROFILE.into(),
        case.subset.to_string(),
        case.n().to_string(),
        case.k.to_string(),
        case.selected().to_string(),
        case.function_id().to_string(),
        seed.to_string(),
        (case.operation + 1).to_string(),
        (case.index + 1).to_string(),
        case.bound().to_string(),
        "PASS".into(),
        "2".into(),
    ];
    f.extend(
        [
            pair.comparisons as u64,
            pair.visits[0] as u64,
            pair.original_steps as u64,
            pair.candidate_steps as u64,
            pair.values[0],
            pair.outer_value,
        ]
        .map(|x| x.to_string()),
    );
    let reads = trace.input_reads();
    f.push(reads.map_or_else(String::new, |x| x.0.to_string()));
    f.push(reads.map_or_else(String::new, |x| x.1.to_string()));
    f.extend(
        [
            trace.ret_offset(),
            h as u64,
            dh as u64,
            e as u64,
            de as u64,
            r as u64,
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
        .map(|x| x.to_string()),
    );
    assert_eq!(f.len(), 36);
    f
}
pub fn coverage_fields(seed: u64, case: Case, c: &Coverage) -> Vec<String> {
    let mut f = vec![PROFILE.into()];
    f.extend(
        [
            case.subset as u64,
            case.n() as u64,
            case.k as u64,
            case.selected() as u64,
            case.function_id(),
            seed,
            (case.operation + 1) as u64,
            CASE_COUNTS[case.operation] as u64,
            c.heads as u64,
            c.declared_heads as u64,
            c.edges as u64,
            c.declared_edges as u64,
            c.returns as u64,
            c.declared_returns as u64,
            c.comparisons as u64,
        ]
        .map(|x| x.to_string()),
    );
    assert_eq!(f.len(), 16);
    f
}
pub fn terminal(comparisons: usize) -> String {
    assert!(comparisons > 0);
    let out = format!(
        "native-leaf-set-rust:profile=leaf-set-whole-rust-v1:required=1280:pairs=1280:children=2560:comparisons={comparisons}:coverage-groups=128:subsets=15:k-values=2:seeds=2:target-calls=2560:target-returns=2560:real-outer-ret=2560:normal-reaps=2560:scope=copied-body-only:complete\n"
    );
    assert!(out.len() <= 1024);
    out
}

#[cfg(test)]
#[path = "native_leaf_set_copied/tests.rs"]
mod tests;
