//! Closed four-call, two-function profile of the one normal state oracle.
//! Union readiness is distinct from single-leaf authority. No execution claim.
use super::*;
#[path = "../../tools/rapid-profiler/normal-work/module_caller_bytes.rs"]
pub mod bytes;
#[path = "native_normal_module/trace.rs"]
mod trace;
pub use trace::Trace;
pub type Population = trace::Population;
pub type SessionPopulation = trace::SessionPopulation;
pub type Coverage = trace::Coverage;
#[path = "native_normal_module/witness.rs"]
mod witness;
pub(super) fn caller_effects(points: &[Snapshot], ready: &Ready, data: u64, stack: u64) {
    witness::caller_effects(points, ready, data, stack);
}
pub const LENGTH_INPUT: usize = 512;
pub const TARGETS: usize = 288;
pub const CSV_LABEL: &str = "normal-module-csv-v1";
pub const LENGTH_LABEL: &str = "normal-module-length-v1";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arguments {
    pub k: usize,
    pub csv: csv::Arguments,
    pub length: strnlen::Arguments,
}
impl Arguments {
    pub fn parse(k: &str, csv_va: &str, csv_len: &str, length_va: &str, length_len: &str) -> Self {
        let k = match k {
            "1" => 1,
            "16" => 16,
            _ => panic!("module K must be 1 or 16"),
        };
        let csv = csv::Arguments::parse(csv_va, csv_len);
        let length = strnlen::Arguments::parse(length_va, length_len);
        assert!((5..=256).contains(&csv.length));
        assert!((5..=80).contains(&length.length));
        let a = csv.elf_va.checked_add(csv.length as u64).unwrap();
        let b = length.elf_va.checked_add(length.length as u64).unwrap();
        assert!(a <= length.elf_va || b <= csv.elf_va);
        Self { k, csv, length }
    }
    pub fn case(self, index: usize) -> Case {
        Case::new(
            index,
            self.k,
            self.csv.length,
            self.length.length,
            usize::from(self.csv.elf_va > self.length.elf_va),
        )
    }
}
/// Explicit Absolute/Concurrent session arguments; no finite-K substitution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionArguments {
    pub k: usize,
    pub csv: csv::Arguments,
    pub length: strnlen::Arguments,
}
impl SessionArguments {
    pub fn parse(k: &str, csv_va: &str, csv_len: &str, length_va: &str, length_len: &str) -> Self {
        let k = match k {
            "10" => 10,
            "1000" => 1000,
            _ => panic!("session K must be 10 or 1000"),
        };
        let csv = csv::Arguments::parse(csv_va, csv_len);
        let length = strnlen::Arguments::parse(length_va, length_len);
        assert!((5..=256).contains(&csv.length));
        assert!((5..=80).contains(&length.length));
        let a = csv.elf_va.checked_add(csv.length as u64).unwrap();
        let b = length.elf_va.checked_add(length.length as u64).unwrap();
        assert!(a <= length.elf_va || b <= csv.elf_va);
        Self { k, csv, length }
    }
    pub fn case(self, index: usize) -> Case {
        Case::new_session(
            index,
            self.k,
            self.csv.length,
            self.length.length,
            usize::from(self.csv.elf_va > self.length.elf_va),
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    FiniteLegacy,
    SessionAbsolute,
}
const SESSION_WIRE: u64 = 0x6d6f_6473_6573_7331;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    profile: Profile,
    pub csv: csv::Case,
    pub length: strnlen::Case,
    pub k: usize,
    /// Semantic CSV/length to canonical increasing-address indices.
    pub order: [usize; 2],
    pub extents: [usize; 2],
}
impl Case {
    pub fn new(
        index: usize,
        k: usize,
        csv_extent: usize,
        length_extent: usize,
        csv_index: usize,
    ) -> Self {
        assert!(index < 16 && matches!(k, 1 | 16) && csv_index < 2);
        assert!((5..=256).contains(&csv_extent) && (5..=80).contains(&length_extent));
        Self::work(
            index,
            k,
            csv_extent,
            length_extent,
            csv_index,
            Profile::FiniteLegacy,
        )
    }
    pub fn new_session(
        index: usize,
        k: usize,
        csv_extent: usize,
        length_extent: usize,
        csv_index: usize,
    ) -> Self {
        assert!(index < 16 && matches!(k, 10 | 1000) && csv_index < 2);
        assert!((5..=256).contains(&csv_extent) && (5..=80).contains(&length_extent));
        Self::work(
            index,
            k,
            csv_extent,
            length_extent,
            csv_index,
            Profile::SessionAbsolute,
        )
    }
    pub fn is_session(self) -> bool {
        self.profile == Profile::SessionAbsolute
    }
    fn assert_session(self) {
        assert_eq!(
            self,
            Self::new_session(
                self.csv.id() - 1,
                self.k,
                self.extents[0],
                self.extents[1],
                self.order[0]
            )
        );
    }
    fn work(
        index: usize,
        k: usize,
        csv_extent: usize,
        length_extent: usize,
        csv_index: usize,
        profile: Profile,
    ) -> Self {
        Self {
            profile,
            csv: csv::Case::new(index),
            length: CASES[index % 8],
            k,
            order: [csv_index, 1 - csv_index],
            extents: [csv_extent, length_extent],
        }
    }
    pub fn function(self, call: usize) -> usize {
        assert!(call < 4);
        self.order[call % 2]
    }
    pub fn bound(self, call: usize) -> usize {
        assert!(call < 4);
        if call % 2 == 0 {
            self.csv.length()
        } else {
            self.length.bound
        }
    }
    pub fn value(self, call: usize) -> u64 {
        assert!(call < 4);
        if call % 2 == 0 {
            self.csv.expected()
        } else {
            strnlen::cases::scalar(self.length)
        }
    }
    pub fn values(self) -> [u64; 4] {
        std::array::from_fn(|i| self.value(i))
    }
    pub fn sum(self) -> u64 {
        self.values().into_iter().fold(0, u64::wrapping_add)
    }
    pub fn admitted(self) -> usize {
        if self.k == 1 { 2 } else { 4 }
    }
}
#[derive(Clone, Debug)]
pub struct Function {
    pub entry: u64,
    pub heads: Vec<u64>,
    pub returns: Vec<u64>,
    pub boundaries: Vec<(u64, u64)>,
}
#[derive(Clone)]
pub struct Ready {
    pub caller: u64,
    pub caller_immutable: Vec<(u64, Vec<u8>)>,
    pub functions: [Function; 2],
    pub immutable: Vec<(u64, Vec<u8>)>,
    pub original_source: Vec<u8>,
    pub journal: Option<JournalReady>,
    pub case: Case,
}
/// Closed adapter, not a conversion between leaf and module certificates.
pub(super) enum WalkReady {
    CallPair(call_pair::Ready),
    Single(NormalReady),
    Module(Ready),
    CopiedRust(copied_rust::Ready),
    LeafSetCopied(leaf_set_copied::Ready),
}
impl WalkReady {
    pub(super) fn call_pair(&self) -> &call_pair::Ready {
        match self {
            Self::CallPair(r) => r,
            _ => panic!("nested original caller readiness required"),
        }
    }
    pub(super) fn single(&self) -> &NormalReady {
        match self {
            Self::Single(r) => r,
            _ => panic!("single readiness required"),
        }
    }
    pub(super) fn module(&self) -> &Ready {
        match self {
            Self::Module(r) => r,
            _ => panic!("module readiness required"),
        }
    }
    pub(super) fn copied_rust(&self) -> &copied_rust::Ready {
        match self {
            Self::CopiedRust(r) => r,
            _ => panic!("copied Rust readiness required"),
        }
    }
    pub(super) fn leaf_set_copied(&self) -> &leaf_set_copied::Ready {
        match self {
            Self::LeafSetCopied(r) => r,
            _ => panic!("LeafSet readiness required"),
        }
    }
    pub(super) fn copied_view(&self) -> copied_rust::CallerView<'_> {
        match self {
            Self::CopiedRust(r) => r.view(),
            Self::LeafSetCopied(r) => r.view(),
            _ => panic!("admitted copied machine profile required"),
        }
    }
    pub(super) fn caller(&self) -> u64 {
        match self {
            Self::Single(r) => r.caller,
            Self::Module(r) => r.caller,
            Self::CopiedRust(r) => r.caller,
            Self::LeafSetCopied(r) => r.caller,
            Self::CallPair(r) => r.caller,
        }
    }
    pub(super) fn caller_immutable(&self) -> &Vec<(u64, Vec<u8>)> {
        match self {
            Self::Single(r) => &r.caller_immutable,
            Self::Module(r) => &r.caller_immutable,
            Self::CopiedRust(r) => &r.caller_immutable,
            Self::LeafSetCopied(r) => &r.caller_immutable,
            Self::CallPair(r) => &r.caller_immutable,
        }
    }
    pub(super) fn immutable(&self) -> &Vec<(u64, Vec<u8>)> {
        match self {
            Self::Single(r) => &r.immutable,
            Self::Module(r) => &r.immutable,
            Self::CopiedRust(r) => &r.immutable,
            Self::LeafSetCopied(r) => &r.immutable,
            Self::CallPair(r) => &r.immutable,
        }
    }
    pub(super) fn journal(&self) -> Option<&JournalReady> {
        match self {
            Self::Single(r) => r.journal.as_ref(),
            Self::Module(r) => r.journal.as_ref(),
            Self::CopiedRust(r) => r.journal.as_ref(),
            Self::LeafSetCopied(r) => r.journal.as_ref(),
            Self::CallPair(r) => r.journal.as_ref(),
        }
    }
    pub(super) fn is_return(&self, pc: u64) -> bool {
        match self {
            Self::Single(r) => r.returns.contains(&pc),
            Self::Module(r) => r.functions.iter().any(|f| f.returns.contains(&pc)),
            Self::CopiedRust(r) => r.target().returns.contains(&pc),
            Self::LeafSetCopied(r) => r.target().returns.contains(&pc),
            Self::CallPair(r) => r.functions.iter().any(|f| f.returns.contains(&pc)),
        }
    }
    pub(super) fn declared_returns(&self) -> BTreeSet<u64> {
        match self {
            Self::Single(r) => r.returns.iter().copied().collect(),
            Self::CopiedRust(r) => r.target().returns.iter().copied().collect(),
            Self::LeafSetCopied(r) => r.target().returns.iter().copied().collect(),
            Self::CallPair(r) => r
                .functions
                .iter()
                .flat_map(|f| f.returns.iter().copied())
                .collect(),
            Self::Module(r) => r
                .functions
                .iter()
                .flat_map(|f| f.returns.iter().copied())
                .collect(),
        }
    }
    pub(super) fn same_source(&self, other: &Self) {
        match (self, other) {
            (Self::Single(a), Self::Single(b)) => a.same_source(b),
            (Self::Module(a), Self::Module(b)) => a.same_source(b),
            (Self::CopiedRust(a), Self::CopiedRust(b)) => a.same_source(b),
            (Self::LeafSetCopied(a), Self::LeafSetCopied(b)) => a.same_source(b),
            (Self::CallPair(a), Self::CallPair(b)) => a.same_source(b),
            _ => panic!("profile mismatch"),
        }
    }
}
impl Ready {
    pub fn target(&self, call: usize) -> &Function {
        &self.functions[self.case.function(call)]
    }
    pub(super) fn validate(&self, candidate: bool, case: Case) -> BTreeMap<u64, u64> {
        assert_eq!(self.case, case);
        validate_geometry(
            Geometry {
                caller: self.caller,
                caller_immutable: &self.caller_immutable,
                functions: &self.functions,
                immutable: &self.immutable,
                original_source: &self.original_source,
                journal: self.journal.as_ref(),
            },
            candidate,
            case.order,
            case.extents,
            bytes::BYTES,
        )
    }
    fn same_source(&self, other: &Self) {
        assert_eq!(self.case, other.case);
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
        assert!(!self.case.is_session());
        self.encode_fields()
    }
    fn encode_session(&self) -> Vec<u8> {
        self.case.assert_session();
        let fields = self.encode_fields();
        let mut out = Vec::new();
        word(&mut out, SESSION_WIRE);
        out.extend(fields);
        assert!(out.len() <= WIRE_LIMIT);
        out
    }
    fn encode_fields(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for n in [
            self.caller,
            self.case.csv.id() as u64 - 1,
            self.case.k as u64,
            self.case.extents[0] as u64,
            self.case.extents[1] as u64,
            self.case.order[0] as u64,
        ] {
            word(&mut out, n);
        }
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
    pub(super) fn decode(wire: &[u8]) -> Self {
        Self::decode_fields(wire, Case::new)
    }
    pub(super) fn decode_session(mut wire: &[u8]) -> Self {
        assert!(wire.len() <= WIRE_LIMIT);
        assert_eq!(take_word(&mut wire), SESSION_WIRE);
        Self::decode_fields(wire, Case::new_session)
    }
    fn decode_fields(mut wire: &[u8], make: fn(usize, usize, usize, usize, usize) -> Case) -> Self {
        assert!(wire.len() <= WIRE_LIMIT);
        let caller = take_word(&mut wire);
        let mut usize_word = || usize::try_from(take_word(&mut wire)).unwrap();
        let case = make(
            usize_word(),
            usize_word(),
            usize_word(),
            usize_word(),
            usize_word(),
        );
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
            Function {
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
            _ => panic!("module journal discriminator"),
        };
        assert!(wire.is_empty());
        Self {
            caller,
            caller_immutable,
            functions,
            immutable,
            original_source,
            journal,
            case,
        }
    }
}

// Shared exact geometry predicate; profile-specific wire and Case guards stay above it.
pub(super) struct Geometry<'a> {
    pub(super) caller: u64,
    pub(super) caller_immutable: &'a [(u64, Vec<u8>)],
    pub(super) functions: &'a [Function; 2],
    pub(super) immutable: &'a [(u64, Vec<u8>)],
    pub(super) original_source: &'a [u8],
    pub(super) journal: Option<&'a JournalReady>,
}
pub(super) fn validate_geometry(
    g: Geometry<'_>,
    candidate: bool,
    order: [usize; 2],
    extents: [usize; 2],
    caller_bytes: &[u8],
) -> BTreeMap<u64, u64> {
    let Geometry {
        caller,
        caller_immutable,
        functions,
        immutable,
        original_source,
        journal,
    } = g;
    assert_eq!(caller_immutable.len(), 1);
    let (caller_page, caller_data) = &caller_immutable[0];
    assert_eq!(*caller_page % PAGE as u64, 0);
    assert_eq!(caller_data.len(), PAGE);
    assert_eq!(
        bytes_at(caller_data, *caller_page, caller, caller_bytes.len()),
        caller_bytes
    );
    assert!((1..=11).contains(&immutable.len()));
    let (source, source_bytes) = &immutable[0];
    assert_eq!(*source % PAGE as u64, 0);
    assert_eq!(source_bytes.len(), PAGE);
    assert_eq!(original_source.len(), PAGE);
    let mut ranges = vec![(*caller_page, caller_page.checked_add(PAGE as u64).unwrap())];
    for (i, (a, b)) in immutable.iter().enumerate() {
        assert!(!b.is_empty() && b.len() <= 8192 && (i == 0 || candidate));
        let end = a.checked_add(b.len() as u64).unwrap();
        assert!(ranges.iter().all(|&(x, y)| end <= x || y <= *a));
        ranges.push((*a, end));
    }
    let mut physical = BTreeMap::new();
    let mut ends = [0; 2];
    for (semantic, &index) in order.iter().enumerate() {
        let f = &functions[index];
        let extent = extents[semantic];
        let end = f.entry.checked_add(extent as u64).unwrap();
        ends[index] = end;
        let code = bytes_at(original_source, *source, f.entry, extent);
        let _ = bytes_at(source_bytes, *source, f.entry, extent);
        let mut decoder = Decoder::with_ip(64, code, f.entry, DecoderOptions::NONE);
        let mut heads = Vec::new();
        let mut returns = Vec::new();
        while decoder.can_decode() {
            let i = decoder.decode();
            assert!(!i.is_invalid() && i.next_ip() <= end);
            heads.push(i.ip());
            if i.flow_control() == FlowControl::Return {
                assert_eq!(
                    &code[(i.ip() - f.entry) as usize..(i.next_ip() - f.entry) as usize],
                    &[0xc3]
                );
                returns.push(i.ip());
            }
        }
        assert_eq!(decoder.position(), extent);
        assert_eq!(f.heads, heads);
        assert_eq!(f.heads.first(), Some(&f.entry));
        assert_eq!(f.returns, returns);
        assert!((1..=4).contains(&f.returns.len()));
        assert_eq!(f.boundaries.len(), f.heads.len());
        let mut logical = BTreeSet::new();
        for &(a, b) in &f.boundaries {
            assert!(f.heads.contains(&a) && logical.insert(a));
            assert!(
                physical.insert(b, a).is_none(),
                "injective complete union map"
            );
            assert!(
                b == a
                    || candidate
                        && immutable[1..]
                            .iter()
                            .any(|(x, y)| *x <= b && b < x.checked_add(y.len() as u64).unwrap())
            );
        }
        assert_eq!(logical, f.heads.iter().copied().collect());
        // The same complete closed-flow census used by the old CSV body.
        if semantic == 0 {
            csv::validate_geometry(f.entry, &f.heads, &f.returns, code);
        }
    }
    assert!(ends[0] <= functions[1].entry);
    // No modified byte outside either declared function, including the gap.
    for (offset, (&before, &after)) in original_source.iter().zip(source_bytes).enumerate() {
        let pc = source.checked_add(offset as u64).unwrap();
        if !(0..2).any(|i| functions[i].entry <= pc && pc < ends[i]) {
            assert_eq!(before, after);
        }
    }
    if candidate {
        let j = journal.expect("module journal");
        assert_eq!(j.address % PAGE as u64, 0);
        let end = j.address.checked_add(PAGE as u64).unwrap();
        assert!(ranges.iter().all(|&(a, b)| end <= a || b <= j.address));
        assert_ne!(j.a_generation, 0);
        assert!(j.b_generation.is_none() && j.helper_tid.is_none());
    } else {
        assert!(journal.is_none());
        assert_eq!(immutable.len(), 1);
        assert_eq!(source_bytes.as_slice(), original_source);
        assert!(
            functions
                .iter()
                .all(|f| f.boundaries.iter().all(|(a, b)| a == b))
        );
    }
    physical
}
impl NormalOracle {
    pub fn new_module(seed: u64, case: Case, deadline: Deadline) -> Self {
        deadline.check();
        csv::profile(seed, case.csv, case.extents[0]);
        assert_eq!(
            case,
            Case::new(
                case.csv.id() - 1,
                case.k,
                case.extents[0],
                case.extents[1],
                case.order[0]
            )
        );
        Self::new_module_data(seed, case, deadline)
    }
    pub fn new_module_session(seed: u64, case: Case, deadline: Deadline) -> Self {
        deadline.check();
        csv::profile(seed, case.csv, case.extents[0]);
        assert_eq!(
            case,
            Case::new_session(
                case.csv.id() - 1,
                case.k,
                case.extents[0],
                case.extents[1],
                case.order[0]
            )
        );
        Self::new_module_data(seed, case, deadline)
    }
    fn new_module_data(seed: u64, case: Case, deadline: Deadline) -> Self {
        let mut oracle = Self::new_body(
            seed,
            Body::Csv(case.csv),
            case.extents[0],
            deadline,
            Mode::Stable,
        );
        let mut data = oracle.data.bytes().to_vec();
        data[LENGTH_INPUT..LENGTH_INPUT + 64].copy_from_slice(&strnlen::cases::input(case.length));
        put_word(
            &mut data,
            0,
            (REQUESTS + 16) as u64,
            oracle.data.address() + LENGTH_INPUT as u64,
        );
        put_word(
            &mut data,
            0,
            (REQUESTS + 24) as u64,
            case.length.bound as u64,
        );
        data[TARGETS..TARGETS + 16].fill(0);
        data[RESULTS..RESULTS + 32].fill(0);
        oracle.data.initialize(0, &data);
        oracle.module = Some(case);
        deadline.check();
        oracle
    }
    pub(super) fn stack_below(&self) -> u64 {
        if let Some(p) = &self.call_pair {
            return p.stack_below();
        }
        if let Some(p) = &self.leaf_set_copied {
            p.plan.protected_stack_below()
        } else if let Some(p) = &self.copied_rust {
            p.plan.protected_stack_below()
        } else if self.module.is_some() {
            bytes::PROTECTED_STACK_BELOW_CALLER
        } else {
            PROTECTED_STACK_BELOW_CALLER
        }
    }
    pub(super) fn subject_delta(&self) -> u64 {
        if let Some(p) = &self.call_pair {
            return p.plan.subject_rsp_delta();
        }
        if let Some(p) = &self.leaf_set_copied {
            p.plan.subject_rsp_delta()
        } else if let Some(p) = &self.copied_rust {
            p.plan.subject_rsp_delta()
        } else if self.module.is_some() {
            bytes::SUBJECT_RSP_DELTA
        } else {
            SUBJECT_RSP_DELTA
        }
    }
    pub(super) fn bound(&self, n: usize) -> usize {
        self.module
            .map_or_else(|| self.body.bound(), |c| c.bound(n))
    }
    pub(super) fn value(&self, n: usize) -> u64 {
        self.module
            .map_or_else(|| self.body.scalar(), |c| c.value(n))
    }
    pub(super) fn sum(&self) -> u64 {
        self.module
            .map_or_else(|| self.body.scalar().wrapping_mul(2), Case::sum)
    }
    pub(super) fn first_argument(&self, ready: &WalkReady) -> u64 {
        match ready {
            WalkReady::Single(r) => r.entry,
            WalkReady::Module(_) => self.data.address() + TARGETS as u64,
            WalkReady::CopiedRust(r) => r.target().entry,
            WalkReady::LeafSetCopied(r) => r.target().entry,
            WalkReady::CallPair(r) => r.parent().entry,
        }
    }
    pub(super) fn check_data(&self, ready: &WalkReady, actual: &[u8], final_check: bool) {
        if let WalkReady::CallPair(r) = ready {
            copied_rust::check_data(self.data.bytes(), actual, r.case.value(), final_check);
        } else if let WalkReady::LeafSetCopied(r) = ready {
            copied_rust::check_data(self.data.bytes(), actual, r.case.value(), final_check);
        } else if let WalkReady::CopiedRust(r) = ready {
            copied_rust::check_data(self.data.bytes(), actual, r.case.value(), final_check);
        } else if let WalkReady::Module(r) = ready {
            check_data(self.data.bytes(), actual, r, final_check);
        } else if final_check {
            final_data(self.data.bytes(), actual, self.body.scalar());
        } else {
            guard_data(self.data.bytes(), actual);
        }
    }
    pub fn pair_module<F>(&self, setup: F) -> (NormalPairResult<4>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let case = self.module.expect("module profile");
        assert!(!case.is_session());
        self.pair_module_common(setup)
    }
    pub fn pair_module_session<F>(&self, setup: F) -> (NormalPairResult<4>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        self.module
            .expect("session module profile")
            .assert_session();
        self.pair_module_common(setup)
    }
    fn pair_module_common<F>(&self, setup: F) -> (NormalPairResult<4>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let case = self.module.expect("module profile");
        let (pair, trace, reference) = self.pair_engine::<F, _, _, 4>(setup, |ready, points| {
            let trace = trace::inspect(self, ready.module(), points);
            let visits = trace.visits();
            (trace, visits)
        });
        assert!(reference.is_none());
        trace::validate_pair(case, &pair, &trace);
        self.deadline.check();
        (pair, trace)
    }
}
impl NormalContext<'_> {
    pub fn module_case(&self) -> Case {
        assert!(self.oracle.leaf_set_copied.is_none());
        assert!(self.oracle.copied_rust.is_none());
        let case = self.any_module_case();
        assert!(!case.is_session());
        case
    }
    pub fn module_session_case(&self) -> Case {
        assert!(self.oracle.leaf_set_copied.is_none());
        assert!(self.oracle.copied_rust.is_none());
        let case = self.any_module_case();
        case.assert_session();
        case
    }
    fn any_module_case(&self) -> Case {
        self.oracle.module.expect("module context")
    }
    pub fn length_input(&self) -> &[u8] {
        let _ = self.any_module_case();
        &self.oracle.data.bytes()[LENGTH_INPUT..LENGTH_INPUT + 64]
    }
    pub fn targets_address(&self) -> u64 {
        let _ = self.any_module_case();
        self.data_address() + TARGETS as u64
    }
    pub fn ready_module(self, ready: &Ready) {
        assert_eq!(self.module_case(), ready.case);
        assert!(self.oracle.reference.is_none() && self.output.is_none() && self.control.is_none());
        self.ready_module_wire(ready.encode());
    }
    pub fn ready_module_session(self, ready: &Ready) {
        assert_eq!(self.module_session_case(), ready.case);
        assert!(self.oracle.reference.is_none() && self.output.is_none() && self.control.is_none());
        self.ready_module_wire(ready.encode_session());
    }
    fn ready_module_wire(self, wire: Vec<u8>) {
        assert!(self.call_pair_output.is_none());
        write_all(self.write.0, &wire, self.oracle.deadline);
        drop(self.write);
        self.oracle.deadline.check();
        // SAFETY: dedicated child, same existing trace handshake; no tracing of
        // supervisory clock code. Parent owns the unchanged absolute deadline.
        unsafe {
            assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
            assert_eq!(libc::raise(libc::SIGSTOP), 0);
        }
    }
}
pub(super) fn check_data(initial: &[u8], actual: &[u8], ready: &Ready, final_check: bool) {
    assert_eq!(initial.len(), PAGE);
    assert_eq!(actual.len(), PAGE);
    assert_eq!(&actual[..TARGETS], &initial[..TARGETS]);
    for (i, &index) in ready.case.order.iter().enumerate() {
        assert_eq!(
            word_at(actual, 0, (TARGETS + i * 8) as u64),
            ready.functions[index].entry
        );
    }
    assert_eq!(
        &actual[TARGETS + 16..RESULTS],
        &initial[TARGETS + 16..RESULTS]
    );
    assert_eq!(&actual[RESULTS + 32..], &initial[RESULTS + 32..]);
    if final_check {
        for i in 0..4 {
            assert_eq!(
                word_at(actual, 0, (RESULTS + i * 8) as u64),
                ready.case.value(i)
            );
        }
    }
}
pub(super) fn call_order(calls: usize, returns: usize, index: usize) {
    assert!(index < 4);
    assert_eq!((calls, returns), (index, index));
}
pub(super) fn ret_order(calls: usize, returns: usize) {
    assert!(returns < 4 && calls == returns + 1);
}
pub(super) fn call_bytes(index: usize) -> [u8; 4] {
    assert!(index < 4);
    [0x41, 0xff, 0x55, if index % 2 == 0 { 0 } else { 8 }]
}
pub(super) fn call_before(
    r: &libc::user_regs_struct,
    ready: &Ready,
    index: usize,
    rsp: u64,
    data: u64,
    bound: usize,
) {
    assert_eq!(bound, ready.case.bound(index));
    assert_eq!(
        (r.rip, r.r13, r.rbp, r.r12, r.rdi, r.rsi, r.rsp),
        (
            ready.caller + bytes::CALLS[index],
            data + TARGETS as u64,
            data + REQUESTS as u64,
            data + RESULTS as u64,
            data + (if index % 2 == 0 { INPUT } else { LENGTH_INPUT }) as u64,
            bound as u64,
            rsp - bytes::SUBJECT_RSP_DELTA + 8
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
    assert_eq!(
        (r.rip, r.rsp, word),
        (
            ready.target(index).entry,
            rsp - bytes::SUBJECT_RSP_DELTA,
            ready.caller + bytes::CONTINUATIONS[index]
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
    let f = ready.target(index);
    assert!(
        f.boundaries
            .iter()
            .any(|(a, b)| *b == r.rip && f.returns.contains(a))
    );
    assert_eq!(value, ready.case.value(index));
    assert_eq!(
        (r.rsp, r.rax, word),
        (
            rsp - bytes::SUBJECT_RSP_DELTA,
            value,
            ready.caller + bytes::CONTINUATIONS[index]
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
    assert_eq!(
        (r.rip, r.rsp, r.rax, word),
        (
            ready.caller + bytes::CONTINUATIONS[index],
            rsp - bytes::SUBJECT_RSP_DELTA + 8,
            value,
            ready.caller + bytes::CONTINUATIONS[index]
        )
    );
}
pub fn journal_words(
    ready: &Ready,
    pid: u64,
    rsp: u64,
    returns: &[u64],
    pending: bool,
) -> [u64; 512] {
    assert!((1..=4).contains(&returns.len()));
    let j = ready.journal.as_ref().unwrap();
    let mut out = [0; 512];
    out[..4].copy_from_slice(&[returns.len() as u64 * 2, 0, pid, u64::from(pending)]);
    for (n, &ret) in returns.iter().enumerate() {
        assert!(ready.target(n).returns.contains(&ret));
        let sampled = n < ready.case.admitted();
        let bits = if sampled {
            (n as u64 + 1) | (1 << 13)
        } else {
            (1 << 13) | (3 << 22)
        };
        let start = 4 + n * 14;
        for (event, pc, at) in [
            (if sampled { 1 } else { 3 }, ready.target(n).entry, start),
            (if sampled { 2 } else { 4 }, ret, start + 7),
        ] {
            out[at..at + 7].copy_from_slice(&[
                event,
                n as u64 + 1,
                pc,
                rsp - bytes::SUBJECT_RSP_DELTA,
                ready.caller + bytes::CONTINUATIONS[n],
                j.a_generation,
                bits,
            ]);
        }
    }
    out
}
#[cfg(test)]
#[path = "native_normal_module/session_tests.rs"]
mod session_tests;
#[cfg(test)]
#[path = "native_normal_module/tests.rs"]
mod tests;
