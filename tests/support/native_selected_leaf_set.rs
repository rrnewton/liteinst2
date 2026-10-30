//! Separate fixed compiled-leaf SDK profile; FORM is an externally joined key,
//! never authority inferred from a name. Old LeafSet wire/population stay exact.
use super::*;
use rust_invoke::Plan;
#[allow(dead_code)]
#[path = "compiled_selected_fixtures.rs"]
mod compiled;
#[path = "native_selected_leaf_set/trace.rs"]
mod trace;
pub use trace::Trace;
const VERSION: &[u8] = b"SELECTED-LEAF-SET-COPIED-STATE-V1\0";
pub const PROFILE: &str = "selected-leaf-set-copied-state-v1";
pub const LABELS: [&str; 2] = [
    "selected-first-equal-state-v1",
    "selected-uppercase-state-v1",
];
pub const FUNCTION_IDS: [u64; 2] = [101, 202];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    pub elf_va: u64,
    pub extent: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    form: u8,
    k: usize,
    seed: u64,
    operation: usize,
    index: usize,
    selections: [Selection; 2],
}
fn number(s: &str) -> u64 {
    assert!(!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    assert!(s.len() == 1 || !s.starts_with('0'));
    s.parse().unwrap()
}
impl Case {
    pub fn parse(args: &[&str]) -> Self {
        assert_eq!(args.len(), 9);
        let form = match args[0] {
            "unstripped" => 0,
            "stripped" => 1,
            _ => panic!("closed DSO form key"),
        };
        let operation = match number(args[3]) {
            101 => 0,
            202 => 1,
            _ => panic!("closed function ID"),
        };
        Self::new(
            form,
            usize::try_from(number(args[1])).unwrap(),
            number(args[2]),
            operation,
            usize::try_from(number(args[4])).unwrap(),
            std::array::from_fn(|i| Selection {
                elf_va: number(args[5 + 2 * i]),
                extent: usize::try_from(number(args[6 + 2 * i])).unwrap(),
            }),
        )
    }
    pub fn new(
        form: u8,
        k: usize,
        seed: u64,
        operation: usize,
        index: usize,
        selections: [Selection; 2],
    ) -> Self {
        assert!(form < 2 && matches!(k, 10 | 1000) && SEEDS.contains(&seed));
        assert!(operation < 2 && index < 12);
        assert!(selections[0].elf_va != 0 && selections[0].elf_va % 4096 == 0);
        assert_eq!(
            selections[1].elf_va,
            selections[0].elf_va.checked_add(48).unwrap()
        );
        assert_eq!([selections[0].extent, selections[1].extent], [41, 55]);
        selections[1].elf_va.checked_add(55).unwrap();
        Self {
            form,
            k,
            seed,
            operation,
            index,
            selections,
        }
    }
    pub(super) fn assert_valid(self) {
        assert_eq!(
            self,
            Self::new(
                self.form,
                self.k,
                self.seed,
                self.operation,
                self.index,
                self.selections
            )
        );
    }
    pub fn form(self) -> &'static str {
        self.assert_valid();
        if self.form == 0 {
            "unstripped"
        } else {
            "stripped"
        }
    }
    pub fn seed(self) -> u64 {
        self.seed
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
    pub fn selected(self) -> usize {
        self.operation
    }
    pub fn function_id(self) -> u64 {
        FUNCTION_IDS[self.operation]
    }
    pub fn n(self) -> usize {
        2
    }
    pub fn selections(self) -> [Selection; 2] {
        self.selections
    }
    pub fn table(self) -> [(usize, Selection); 2] {
        [(0, self.selections[0]), (1, self.selections[1])]
    }
    pub fn bound(self) -> usize {
        compiled::INPUTS[self.index].len()
    }
    pub fn input(self) -> [u8; 64] {
        let mut bytes = [0xa5; 64];
        bytes[..self.bound()].copy_from_slice(compiled::INPUTS[self.index]);
        bytes
    }
    pub fn value(self) -> u64 {
        compiled::expected(compiled::INPUTS[self.index], self.operation).answer
    }
}
pub fn keys() -> Vec<(u8, usize, u64, usize, usize)> {
    let mut keys = Vec::new();
    for form in 0..2 {
        for k in [10, 1000] {
            for seed in SEEDS {
                for operation in 0..2 {
                    for index in 0..12 {
                        keys.push((form, k, seed, operation, index));
                    }
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
        assert_eq!(leaf_page.len(), PAGE);
        for f in 0..2 {
            assert_eq!(
                &leaf_page[compiled::OFFSETS[f]..compiled::OFFSETS[f] + compiled::BODIES[f].len()],
                compiled::BODIES[f]
            );
        }
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
            assert_eq!(code, compiled::BODIES[*operation]);
            assert_eq!(
                heads,
                compiled::HEADS[*operation]
                    .iter()
                    .map(|&at| f.entry + at as u64)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                returns,
                compiled::RETURNS[*operation]
                    .iter()
                    .map(|&at| f.entry + at as u64)
                    .collect::<Vec<_>>()
            );
            assert_eq!(f.boundaries.len(), f.heads.len());
            let mut logical = BTreeSet::new();
            for &(a, b) in &f.boundaries {
                assert!(f.heads.contains(&a) && logical.insert(a));
                assert!(physical.insert(b, a).is_none());
                assert!(b == a || candidate && self.immutable[count..].iter().any(|(x, y)| *x <= b && b < x.checked_add(y.len() as u64).unwrap()));
                // Both complete bodies are displaced by WholeFunction. Every
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
            self.case.form as u64,
            self.case.seed,
            self.case.k as u64,
            self.case.operation as u64,
            self.case.index as u64,
        ] {
            word(&mut out, n);
        }
        for policy in [1, 1] {
            word(&mut out, policy);
        } // Exact WholeFunction per selection.
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
        let form = u8::try_from(take_word(&mut wire)).unwrap();
        let seed = take_word(&mut wire);
        let k = usize::try_from(take_word(&mut wire)).unwrap();
        let operation = usize::try_from(take_word(&mut wire)).unwrap();
        let index = usize::try_from(take_word(&mut wire)).unwrap();
        assert_eq!([take_word(&mut wire), take_word(&mut wire)], [1, 1]);
        let selections = std::array::from_fn(|_| Selection {
            elf_va: take_word(&mut wire),
            extent: usize::try_from(take_word(&mut wire)).unwrap(),
        });
        let actual = Case::new(form, k, seed, operation, index, selections);
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
    pub fn new_selected_leaf_set(
        case: Case,
        plan: Plan,
        caller: u64,
        source: (u64, Vec<u8>),
        leaf_page: Vec<u8>,
        deadline: Deadline,
    ) -> Self {
        deadline.check();
        case.assert_valid();
        let seed = case.seed;
        assert!(SEEDS.contains(&seed));
        let mut oracle = Self::new_body(
            seed,
            Body::SelectedLeafSet(case),
            case.selections[case.operation].extent,
            deadline,
            Mode::Stable,
        );
        oracle.selected_leaf_set = Some(Profile::new(case, plan, caller, source, leaf_page));
        oracle
    }
    pub fn pair_selected_leaf_set<F>(&self, setup: F) -> (NormalPairResult<1>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let p = self
            .selected_leaf_set
            .as_ref()
            .expect("distinct LeafSet profile");
        p.case.assert_valid();
        assert!(
            self.copied_rust.is_none()
                && self.leaf_set_copied.is_none()
                && self.call_pair.is_none()
                && self.module.is_none()
                && self.reference.is_none()
        );
        assert_eq!(self.mode, Mode::Stable);
        let (pair, trace, stats) = self.pair_engine::<F, _, _, 1>(setup, |r, points| {
            let t = trace::inspect(self, r.selected_leaf_set(), points);
            let visits = [t.visits()];
            (t, visits)
        });
        assert!(stats.is_none());
        trace::validate_pair(p.case, &p.plan, &pair, &trace);
        (pair, trace)
    }
}
impl NormalContext<'_> {
    pub fn selected_leaf_set_case(&self) -> Case {
        assert!(
            self.oracle.leaf_set_copied.is_none()
                && self.oracle.call_pair.is_none()
                && self.oracle.copied_rust.is_none()
                && self.oracle.module.is_none()
                && self.oracle.reference.is_none()
        );
        assert_eq!(self.oracle.mode, Mode::Stable);
        let c = self.oracle.selected_leaf_set.as_ref().unwrap().case;
        c.assert_valid();
        c
    }
    pub fn ready_selected_leaf_set(self, ready: &Ready) {
        assert_eq!(ready.case, self.selected_leaf_set_case());
        assert_eq!(
            ready.plan,
            self.oracle.selected_leaf_set.as_ref().unwrap().plan
        );
        assert!(self.control.is_none() && self.output.is_none());
        assert!(self.call_pair_output.is_none());
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

pub const HEADER: &str = "profile,form,k,seed,function_id,input_index,functions,policies,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,input_reads,ret_offset,observed_heads,reachable_heads,observed_edges,reachable_edges,declared_returns,observed_head_set,observed_edge_set,reachable_head_set,reachable_edge_set,return_set,decoded_heads,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps\n";
pub fn pair_row(case: Case, plan: &Plan, pair: &NormalPairResult<1>, trace: &Trace) -> String {
    trace::validate_pair(case, plan, pair, trace);
    let mut fields = vec![
        PROFILE.into(),
        case.form().into(),
        case.k.to_string(),
        case.seed.to_string(),
        case.function_id().to_string(),
        case.index.to_string(),
        "2".into(),
        "whole+whole".into(),
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
        ]
        .map(|n| n.to_string()),
    );
    fields.extend(trace::fields(trace));
    fields.extend(
        [
            compiled::HEADS[case.operation].len() as u64,
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
    leaf_set_copied::append_row(&mut row, &fields, 39, 768, 1024 * 1024);
    row
}
pub fn terminal(case: Case, comparisons: usize) -> String {
    case.assert_valid();
    assert!(comparisons > 0 && comparisons <= MAX_STEPS);
    let out = format!(
        "native-selected-leaf-set:profile={PROFILE}:form={}:k={}:seed={}:function={}:input={}:required=1:pairs=1:children=2:comparisons={comparisons}:target-calls=2:target-returns=2:real-outer-ret=2:normal-reaps=2:scope=copied-body-only:complete\n",
        case.form(),
        case.k,
        case.seed,
        case.function_id(),
        case.index
    );
    assert!(out.len() <= 1024);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    fn refuses(f: impl FnOnce()) {
        assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
    }
    pub(super) fn case(operation: usize, index: usize) -> Case {
        Case::new(
            0,
            10,
            SEEDS[0],
            operation,
            index,
            [
                Selection {
                    elf_va: 0x4000,
                    extent: 41,
                },
                Selection {
                    elf_va: 0x4030,
                    extent: 55,
                },
            ],
        )
    }
    fn ready(candidate: bool) -> (Ready, Profile) {
        let case = case(0, 4);
        let plan = rust_invoke::admit(&[
            0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff,
            0xd0, 0x48, 0x89, 0x03, 0x5b, 0xc3,
        ])
        .unwrap();
        let mut caller = vec![0xcc; PAGE];
        caller[128..128 + plan.bytes().len()].copy_from_slice(plan.bytes());
        let mut page = vec![0; PAGE];
        for f in 0..2 {
            page[compiled::OFFSETS[f]..compiled::OFFSETS[f] + compiled::BODIES[f].len()]
                .copy_from_slice(compiled::BODIES[f]);
        }
        let profile = Profile::new(
            case,
            plan.clone(),
            0x1080,
            (0x1000, caller.clone()),
            page.clone(),
        );
        let source = 0x104000;
        let original_sources = vec![(source, page.clone())];
        let functions = (0..2)
            .map(|f| {
                let entry = source + compiled::OFFSETS[f] as u64;
                let heads: Vec<_> = compiled::HEADS[f]
                    .iter()
                    .map(|&at| entry + at as u64)
                    .collect();
                let boundaries = heads
                    .iter()
                    .enumerate()
                    .map(|(i, &pc)| {
                        (
                            pc,
                            if candidate {
                                0x200000 + f as u64 * 4096 + i as u64 * 3
                            } else {
                                pc
                            },
                        )
                    })
                    .collect();
                module::Function {
                    entry,
                    heads,
                    returns: compiled::RETURNS[f]
                        .iter()
                        .map(|&at| entry + at as u64)
                        .collect(),
                    boundaries,
                }
            })
            .collect();
        let mut immutable = original_sources.clone();
        if candidate {
            for f in 0..2 {
                immutable[0].1
                    [compiled::OFFSETS[f]..compiled::OFFSETS[f] + compiled::BODIES[f].len()]
                    .fill(0xcc);
            }
            immutable.extend([(0x200000, vec![0x90; 128]), (0x201000, vec![0x90; 128])]);
        }
        (
            Ready {
                caller: 0x1080,
                caller_immutable: vec![(0x1000, caller)],
                functions,
                immutable,
                original_sources,
                journal: candidate.then_some(JournalReady {
                    address: 0x300000,
                    a_generation: 1,
                    b_generation: None,
                    helper_tid: None,
                }),
                case,
                plan,
            },
            profile,
        )
    }
    #[test]
    fn selected_keys_are_exact_192_and_cli_rejects_noncanonical_or_unknown_values() {
        let keys = keys();
        assert_eq!(keys.len(), 192);
        assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), 192);
        let seed = SEEDS[0].to_string();
        let args = [
            "unstripped",
            "10",
            seed.as_str(),
            "101",
            "0",
            "16384",
            "41",
            "16432",
            "55",
        ];
        assert_eq!(Case::parse(&args), case(0, 0));
        for (field, value) in [
            (0, "unstrip"),
            (1, "010"),
            (1, "16"),
            (2, "+1"),
            (2, "1"),
            (3, "0"),
            (3, "301"),
            (4, "12"),
            (4, "00"),
            (5, "0"),
            (5, "16385"),
            (6, "40"),
            (7, "16433"),
            (8, "54"),
        ] {
            let mut bad = args;
            bad[field] = value;
            refuses(|| {
                Case::parse(&bad);
            });
        }
        refuses(|| {
            Case::parse(&args[..8]);
        });
        for (form, k, seed, operation, index) in keys {
            let mut c = case(operation, index);
            c.form = form;
            c.k = k;
            c.seed = seed;
            c.assert_valid();
            assert_eq!(c.table().len(), 2);
            assert_eq!(c.function_id(), [101, 202][operation]);
        }
    }
    #[test]
    fn selected_wire_roundtrips_and_refuses_old_profiles_wrong_keys_and_policies() {
        for candidate in [false, true] {
            let (r, p) = ready(candidate);
            let wire = r.encode();
            let decoded = Ready::decode(&wire, r.case, &r.plan);
            decoded.validate(candidate, &p);
            refuses(|| {
                NormalReady::decode(&wire);
            });
            refuses(|| {
                module::Ready::decode(&wire);
            });
            let mut other = r.case;
            other.form = 1;
            refuses(|| {
                Ready::decode(&wire, other, &r.plan);
            });
            other = r.case;
            other.seed = SEEDS[1];
            refuses(|| {
                Ready::decode(&wire, other, &r.plan);
            });
            other = r.case;
            other.k = 1000;
            refuses(|| {
                Ready::decode(&wire, other, &r.plan);
            });
            other = r.case;
            other.operation = 1;
            refuses(|| {
                Ready::decode(&wire, other, &r.plan);
            });
            other = r.case;
            other.index += 1;
            refuses(|| {
                Ready::decode(&wire, other, &r.plan);
            });
            for field in [0, 6, 7] {
                // caller and two explicit WholeFunction policy words.
                let mut bad = wire.clone();
                bad[VERSION.len() + field * 8] ^= 1;
                refuses(|| {
                    let d = Ready::decode(&bad, r.case, &r.plan);
                    d.validate(candidate, &p);
                });
            }
            let mut bad = wire.clone();
            bad[0] ^= 1;
            refuses(|| {
                Ready::decode(&bad, r.case, &r.plan);
            });
            let mut bad = wire;
            bad.push(0);
            refuses(|| {
                Ready::decode(&bad, r.case, &r.plan);
            });
            let tagged = WalkReady::SelectedLeafSet(r);
            refuses(|| {
                tagged.leaf_set_copied();
            });
            refuses(|| {
                tagged.copied_rust();
            });
        }
    }
    #[test]
    fn selected_complete_source_heads_returns_physical_owners_and_caller_are_joined() {
        for candidate in [false, true] {
            let (r, p) = ready(candidate);
            r.validate(candidate, &p);
            for field in 0..13 {
                let mut bad = r.clone();
                match field {
                    0 => bad.functions[0].entry += 1,
                    1 => {
                        bad.functions[0].heads.pop();
                        bad.functions[0].boundaries.pop();
                    }
                    2 => bad.functions[0].heads.swap(0, 1),
                    3 => bad.functions[0].returns[0] += 1,
                    4 => bad.functions[0].boundaries[1] = bad.functions[0].boundaries[0],
                    5 => bad.functions[1].boundaries[0].1 = bad.functions[0].boundaries[0].1,
                    6 => bad.original_sources[0].1[0] ^= 1,
                    7 => bad.original_sources[0].1[4095] ^= 1,
                    8 => bad.caller_immutable[0].1[4095] ^= 1,
                    9 => bad.caller += 1,
                    10 => bad.immutable[0].1[4095] ^= 1,
                    11 => {
                        bad.original_sources.push(bad.original_sources[0].clone());
                    }
                    _ => bad.case.operation = 1,
                }
                refuses(|| {
                    bad.validate(candidate, &p);
                });
            }
        }
        let (r, p) = ready(true);
        for function in 0..2 {
            for head in 0..r.functions[function].heads.len() {
                let mut bad = r.clone();
                let pc = bad.functions[function].heads[head];
                bad.functions[function].boundaries[head] = (pc, pc);
                // Even repairing original bytes cannot turn a whole-displaced head into identity.
                bad.immutable[0].1 = r.original_sources[0].1.clone();
                refuses(|| {
                    bad.validate(true, &p);
                });
            }
        }
        for field in 0..5 {
            let mut bad = r.clone();
            let j = bad.journal.as_mut().unwrap();
            match field {
                0 => j.address = 0x200000,
                1 => j.a_generation = 0,
                2 => j.b_generation = Some(1),
                3 => j.helper_tid = Some(1),
                _ => bad.journal = None,
            }
            refuses(|| {
                bad.validate(true, &p);
            });
        }
    }
}
