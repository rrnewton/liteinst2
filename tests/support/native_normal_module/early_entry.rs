//! Explicit qualification-feature profile. The ordinary caller/body comparator
//! and its mandatory journal expectation remain unchanged in the parent.
use super::*;

const MAGIC: u64 = 0x6561_726c_796d_6f64;
const ACK: u64 = 0x6561_726c_7961_636b;
pub const WITNESS_WORDS: usize = 640;
pub const JOURNAL: usize = 128;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum Scenario {
    Enabled = 0,
    Bypass = 1,
    LoadedTrueDisarm = 2,
    LoadedFalseArm = 3,
    AdmittedRearm = 4,
    ReturnedDisarm = 5,
}
impl Scenario {
    pub fn scheduled(self) -> bool {
        (self as u64) >= 2
    }
    pub fn initial(self) -> bool {
        !matches!(self, Self::Bypass | Self::LoadedFalseArm)
    }
    pub fn observed(self) -> [bool; 4] {
        match self {
            Self::Enabled | Self::AdmittedRearm => [true; 4],
            Self::Bypass | Self::LoadedTrueDisarm => [false; 4],
            Self::LoadedFalseArm => [false, true, true, true],
            Self::ReturnedDisarm => [true, false, false, false],
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Bypass => "bypass",
            Self::LoadedTrueDisarm => "loaded-true-disarm",
            Self::LoadedFalseArm => "loaded-false-arm",
            Self::AdmittedRearm => "admitted-rearm",
            Self::ReturnedDisarm => "returned-disarm",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Extra {
    /// logical entry, gate entry, actual post-MOVZX JRCXZ, observing span,
    /// original body, actual byte address encoded by the immutable stencil.
    pub gates: [[u64; 6]; 2],
    pub marker: u64,
    pub witness: u64,
    pub helper_tid: u64,
    pub generations: [u64; 2],
}
impl Extra {
    pub fn original() -> Self {
        Self {
            gates: [[0; 6]; 2],
            marker: 0,
            witness: 0,
            helper_tid: 0,
            generations: [0; 2],
        }
    }
    fn words(&self) -> Vec<u64> {
        self.gates
            .iter()
            .flatten()
            .copied()
            .chain([self.marker, self.witness, self.helper_tid])
            .chain(self.generations)
            .collect()
    }
    pub(in super::super) fn validate(
        &self,
        ready: &WalkReady,
        candidate: bool,
        scenario: Scenario,
    ) {
        if !candidate {
            assert_eq!(self.words(), Self::original().words());
            return;
        }
        let r = ready.module();
        assert_ne!(self.marker, 0);
        assert_ne!(self.witness, 0);
        assert_eq!(self.witness & 7, 0);
        assert_eq!(self.helper_tid != 0, scenario.scheduled());
        assert!(self.generations[0] != 0 && self.generations[1] > self.generations[0]);
        assert_eq!(
            r.journal.as_ref().unwrap().a_generation,
            self.generations[0]
        );
        for (index, g) in self.gates.iter().enumerate() {
            assert_eq!(g[0], r.functions[index].entry);
            assert!(g.iter().all(|v| *v != 0));
            assert!(g[1] < g[2] && g[2] < g[3] && g[3] < g[4]);
            assert!(r.functions[index].boundaries.contains(&(g[0], g[4])));
            for pc in &g[1..5] {
                assert!(
                    r.immutable[1..]
                        .iter()
                        .any(|(a, b)| *a <= *pc && *pc < *a + b.len() as u64)
                );
            }
        }
        let end = self
            .witness
            .checked_add((WITNESS_WORDS * 8) as u64)
            .unwrap();
        assert!(
            r.immutable
                .iter()
                .chain(&r.caller_immutable)
                .all(|(a, b)| end <= *a || *a + b.len() as u64 <= self.witness)
        );
    }
}
pub struct Ready {
    pub module: super::Ready,
    pub extra: Extra,
}
impl Ready {
    fn encode(&self, scenario: Scenario) -> Vec<u8> {
        let body = self.module.encode_session();
        let mut out = Vec::new();
        for n in [MAGIC, scenario as u64, body.len() as u64] {
            word(&mut out, n);
        }
        out.extend(body);
        for n in self.extra.words() {
            word(&mut out, n);
        }
        assert!(out.len() <= WIRE_LIMIT);
        out
    }
    pub(in super::super) fn decode(mut wire: &[u8], case: Case, scenario: Scenario) -> Self {
        assert!(wire.len() <= WIRE_LIMIT);
        assert_eq!(take_word(&mut wire), MAGIC);
        assert_eq!(take_word(&mut wire), scenario as u64);
        // This is a complete nested session, not one immutable blob. Its
        // decoder retains the 8192-byte bound on each individual blob.
        let body_len = usize::try_from(take_word(&mut wire)).unwrap();
        // Extra is twelve gate words, marker/witness/helper words and two generations.
        assert_eq!(body_len.checked_add(17 * 8), Some(wire.len()));
        let (body, mut wire) = wire.split_at(body_len);
        let module = super::Ready::decode_session(body);
        assert_eq!(module.case, case);
        let gates = std::array::from_fn(|_| std::array::from_fn(|_| take_word(&mut wire)));
        let extra = Extra {
            gates,
            marker: take_word(&mut wire),
            witness: take_word(&mut wire),
            helper_tid: take_word(&mut wire),
            generations: [take_word(&mut wire), take_word(&mut wire)],
        };
        assert!(wire.is_empty());
        Self { module, extra }
    }
}
/// One bounded real-controller operation. No worker TLS crosses this endpoint.
pub struct Child {
    command: Fd,
    ack: Fd,
    deadline: Deadline,
}
pub(in super::super) struct Parent {
    command: Fd,
    ack: Fd,
    done: bool,
}
impl Child {
    pub(in super::super) fn new(command: Fd, ack: Fd, deadline: Deadline) -> Self {
        Self {
            command,
            ack,
            deadline,
        }
    }
    pub fn receive(&self, scenario: Scenario) {
        let mut b = [0; 16];
        read_exact(self.command.0, &mut b, self.deadline);
        assert_eq!(
            &b[..],
            [1_u64.to_le_bytes(), (scenario as u64).to_le_bytes()]
                .concat()
                .as_slice()
        );
    }
    pub fn acknowledge(
        self,
        scenario: Scenario,
        generations: [u64; 2],
        enabled: [bool; 2],
        report_a_closed: bool,
    ) {
        let words = [
            ACK,
            1,
            scenario as u64,
            std::process::id() as u64,
            unsafe { libc::syscall(libc::SYS_gettid) as u64 },
            generations[0],
            generations[1],
            u64::from(enabled[0]),
            u64::from(enabled[1]),
            u64::from(report_a_closed),
        ];
        let data: Vec<_> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        write_all(self.ack.0, &data, self.deadline);
    }
}
impl Parent {
    pub(in super::super) fn new(command: Fd, ack: Fd) -> Self {
        Self {
            command,
            ack,
            done: false,
        }
    }
    fn request(&mut self, scenario: Scenario, child: &Tracee, extra: &Extra, deadline: Deadline) {
        assert!(!self.done);
        let b: Vec<_> = [1, scenario as u64]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        write_all(self.command.0, &b, deadline);
        let mut b = [0; 80];
        read_exact(self.ack.0, &mut b, deadline);
        let w: Vec<_> = b
            .chunks_exact(8)
            .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
            .collect();
        let enabled = matches!(scenario, Scenario::LoadedFalseArm | Scenario::AdmittedRearm);
        let closed = matches!(scenario, Scenario::LoadedTrueDisarm);
        assert_eq!(
            w,
            [
                ACK,
                1,
                scenario as u64,
                child.pid as u64,
                extra.helper_tid,
                extra.generations[0],
                extra.generations[1],
                u64::from(enabled),
                u64::from(enabled),
                u64::from(closed)
            ]
        );
        assert_ne!(extra.helper_tid, child.pid as u64);
        self.done = true;
    }
    fn finish(self, deadline: Deadline) {
        assert!(self.done);
        assert!(read_closed(self.ack.0, deadline, 0).is_empty());
    }
}
/// Fixed data-only wire. Each marker copies the actual production snapshot;
/// timestamps are retained, never used as architectural-state tolerances.
pub fn witness_words(header: &[u64], journal: &[u64; 512]) -> [u64; WITNESS_WORDS] {
    assert!(header.len() <= JOURNAL);
    let mut out = [0; WITNESS_WORDS];
    out[..header.len()].copy_from_slice(header);
    out[JOURNAL..].copy_from_slice(journal);
    out
}
pub(in super::super) struct Witness {
    scenario: Scenario,
    extra: Extra,
    loaded: usize,
    callbacks: usize,
    returns: usize,
    entry: Option<Snapshot>,
    loaded_state: Option<Snapshot>,
    took_observing: bool,
    prior: Option<Vec<u64>>,
    retained: Option<Vec<u64>>,
    binding: Option<u64>,
    command: bool,
    after_branch: Option<u64>,
}
impl Witness {
    pub(in super::super) fn new(scenario: Scenario, extra: Extra) -> Self {
        Self {
            scenario,
            extra,
            loaded: 0,
            callbacks: 0,
            returns: 0,
            entry: None,
            loaded_state: None,
            took_observing: false,
            prior: None,
            retained: None,
            binding: None,
            command: false,
            after_branch: None,
        }
    }
    fn read(&self, child: &Tracee) -> Vec<u64> {
        child
            .memory(self.extra.witness, WITNESS_WORDS * 8)
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect()
    }
    fn command(
        &mut self,
        oracle: &NormalOracle,
        child: &Tracee,
        ready: &WalkReady,
        parent: &mut Option<Parent>,
    ) {
        let pc = child.registers().rip;
        let before = oracle.snapshot(child, ready, pc);
        let witness = self.read(child);
        let journal = child.memory(ready.journal().unwrap().address, PAGE);
        parent
            .as_mut()
            .unwrap()
            .request(self.scenario, child, &self.extra, oracle.deadline);
        assert_eq!(child.registers().rip, pc);
        assert_state(&before, &oracle.snapshot(child, ready, pc));
        assert_eq!(self.read(child), witness);
        assert_eq!(
            child.memory(ready.journal().unwrap().address, PAGE),
            journal
        );
        let enabled = matches!(
            self.scenario,
            Scenario::LoadedFalseArm | Scenario::AdmittedRearm
        );
        for gate in &self.extra.gates {
            assert_eq!(child.memory(gate[5], 1), [u8::from(enabled)]);
        }
        self.command = true;
    }
    pub(in super::super) fn before(
        &mut self,
        oracle: &NormalOracle,
        child: &Tracee,
        ready: &WalkReady,
        returns: &[u64],
        parent: &mut Option<Parent>,
    ) {
        let pc = child.registers().rip;
        if let Some(expected) = self.after_branch.take() {
            assert_eq!(
                pc, expected,
                "actual JRCXZ successor must follow the loaded register"
            );
        }
        let call = self.returns;
        if call < 4 {
            let g = self.extra.gates[ready.module().case.function(call)];
            if pc == g[1] {
                assert_eq!(self.loaded, call);
                self.entry = Some(oracle.snapshot(child, ready, g[0]));
                self.took_observing = false;
            }
            if pc == g[2] {
                let before = self.entry.as_ref().unwrap();
                let r = child.registers();
                assert_eq!(child.memory(pc - 3, 3), [0x0f, 0xb6, 0x09]);
                assert_eq!(child.memory(pc, 1), [0xe3]);
                assert_eq!(child.memory(pc - 13, 2), [0x48, 0xb9]);
                assert_eq!(
                    u64::from_le_bytes(child.memory(pc - 11, 8).try_into().unwrap()),
                    g[5]
                );
                let enabled = if call == 0 {
                    self.scenario.initial()
                } else {
                    self.scenario.observed()[call]
                };
                assert_eq!(r.rcx, u64::from(enabled));
                assert_eq!(child.memory(g[5], 1), [u8::from(enabled)]);
                assert_eq!(r.rsp, before.registers.rsp - 136);
                assert_eq!(child.memory(r.rsp, 8), before.registers.rcx.to_le_bytes());
                assert_eq!(
                    r.eflags & !DEBUGGER_FLAGS,
                    before.registers.eflags & !DEBUGGER_FLAGS
                );
                let branch = child.memory(pc, 2);
                let fallthrough = pc.checked_add(2).unwrap();
                let disabled = fallthrough
                    .checked_add_signed(i64::from(branch[1] as i8))
                    .unwrap();
                assert!(fallthrough < disabled && disabled < g[3]);
                self.after_branch = Some(if enabled { fallthrough } else { disabled });
                self.loaded += 1;
                self.loaded_state = Some(oracle.snapshot(child, ready, pc));
                if call == 0
                    && matches!(
                        self.scenario,
                        Scenario::LoadedTrueDisarm | Scenario::LoadedFalseArm
                    )
                {
                    self.command(oracle, child, ready, parent);
                }
            }
            if pc == g[3] {
                assert!(self.loaded_state.is_some() && !self.took_observing);
                assert_state(
                    self.entry.as_ref().unwrap(),
                    &oracle.snapshot(child, ready, g[0]),
                );
                self.took_observing = true;
            }
            if pc == g[4] {
                let before = self.entry.take().unwrap();
                assert_state(&before, &oracle.snapshot(child, ready, g[0]));
                let loaded = if call == 0 {
                    self.scenario.initial()
                } else {
                    self.scenario.observed()[call]
                };
                assert_eq!(
                    self.took_observing, loaded,
                    "actual early branch, independent of dispatcher recheck"
                );
                self.loaded_state.take().unwrap();
            }
        }
        if pc == self.extra.marker {
            let words = self.read(child);
            self.snapshot(
                &words,
                ready.module(),
                child.pid as u64,
                oracle.caller_rsp(),
                returns,
            );
            if !self.command
                && ((self.scenario == Scenario::AdmittedRearm && words[1] == 1)
                    || (self.scenario == Scenario::ReturnedDisarm && words[1] == 2))
            {
                self.command(oracle, child, ready, parent);
            }
            self.prior = Some(words);
        }
    }
    fn snapshot(&mut self, w: &[u64], r: &super::Ready, pid: u64, rsp: u64, returns: &[u64]) {
        assert_eq!(w.len(), WITNESS_WORDS);
        assert_eq!(w[0], MAGIC);
        self.callbacks += 1;
        assert_eq!(w[2], self.callbacks as u64);
        let binding = *self.binding.get_or_insert(w[3]);
        assert_ne!(binding, 0);
        assert_eq!(w[3], binding);
        assert_eq!(
            &w[4..11],
            &[
                pid,
                pid,
                1,
                0,
                0,
                1,
                self.returns as u64 + u64::from(w[1] == 2)
            ]
        );
        let observed = self.scenario.observed();
        let admitted = observed[..=self.returns].iter().filter(|b| **b).count();
        let retired = observed[..self.returns].iter().filter(|b| **b).count();
        assert_eq!(w[11], admitted as u64 + 1);
        assert_eq!(w[12], u64::from(admitted != 0));
        assert_eq!(w[13], admitted.saturating_sub(1) as u64);
        assert_eq!(w[14], 0); // no caller checkpoint before the real outer return
        assert_eq!(
            &w[15..20],
            &[
                admitted as u64,
                (retired + usize::from(w[1] == 2 && observed[self.returns])) as u64,
                admitted.saturating_sub(1) as u64,
                admitted.saturating_sub(1) as u64,
                0
            ]
        );
        assert_eq!(&w[20..25], &[0; 5]);
        assert!(matches!(w[1], 1 | 2));
        if w[1] == 1 {
            assert!(observed[self.returns]);
        }
        let upto = self.returns + usize::from(w[1] == 2);
        for (n, &observed_n) in observed.iter().enumerate() {
            let seen = n < self.returns || (n == self.returns && (w[1] == 1 || w[1] == 2));
            let ordinal = if seen && observed_n {
                observed[..=n].iter().filter(|b| **b).count() as u64
            } else {
                0
            };
            assert_eq!(w[25 + n], ordinal);
            let row = &w[29 + n * 7..36 + n * 7];
            if n < upto {
                assert_eq!(
                    &row[..4],
                    &[1, n as u64, r.case.function(n) as u64 + 71, ordinal]
                );
                assert!(r.target(n).returns.contains(&row[4]));
                if n < returns.len() {
                    assert_eq!(row[4], returns[n]);
                }
                assert_eq!(
                    &row[5..],
                    &[
                        rsp - bytes::SUBJECT_RSP_DELTA,
                        r.caller + bytes::CONTINUATIONS[n]
                    ]
                );
            } else {
                assert_eq!(row, &[0; 7]);
            }
        }
        if admitted == 0 {
            assert!(w[57..128].iter().all(|n| *n == 0));
        } else {
            let last = (0..=self.returns).rev().find(|&n| observed[n]).unwrap();
            assert_eq!(
                &w[57..65],
                &[
                    1,
                    1,
                    last as u64,
                    r.case.function(last) as u64 + 71,
                    admitted as u64,
                    r.target(last).entry,
                    rsp - bytes::SUBJECT_RSP_DELTA,
                    r.caller + bytes::CONTINUATIONS[last]
                ]
            );
            assert_ne!(w[65], 0);
            assert_eq!(w[67], u64::from(w[1] == 2 || last < self.returns));
            let generation = if self.scenario == Scenario::AdmittedRearm && last != 0 {
                self.extra.generations[1]
            } else {
                self.extra.generations[0]
            };
            assert_eq!(w[71], generation);
            let invocation = if self.scenario == Scenario::AdmittedRearm && last != 0 {
                admitted - 2
            } else {
                admitted - 1
            };
            let history = if self.scenario == Scenario::AdmittedRearm && last != 0 {
                3
            } else {
                1
            };
            assert_eq!(w[72], invocation as u64);
            assert_eq!(w[73], admitted as u64);
            assert_ne!(w[74], 0);
            assert_eq!((w[75], w[84]), (1, 1));
            assert_eq!(
                &w[76..84],
                &w[85..93],
                "copied and actual immutable receipt summary"
            );
            assert_eq!(
                &w[76..84],
                &[
                    1,
                    generation,
                    invocation as u64,
                    history,
                    1,
                    history - 1,
                    generation,
                    0
                ]
            );
            if w[67] == 1 {
                assert_eq!(
                    &w[93..103],
                    &[
                        admitted as u64,
                        r.target(last).entry,
                        w[68],
                        1,
                        generation,
                        invocation as u64,
                        w[65],
                        w[66],
                        w[69],
                        w[70]
                    ]
                );
            } else {
                assert_eq!(&w[93..103], &[0; 10]);
            }
            assert!(w[103..128].iter().all(|n| *n == 0));
            if self.scenario == Scenario::ReturnedDisarm && w[1] == 2 {
                if let Some(prior) = &self.retained {
                    assert_eq!(
                        &w[57..128],
                        prior.as_slice(),
                        "old Returned owner/endpoints survive every bypass and stack reuse"
                    );
                } else {
                    self.retained = Some(w[57..128].to_vec());
                }
            }
        }
        let mut expected = [0; 512];
        let event_count = admitted + retired + usize::from(w[1] == 2 && observed[self.returns]);
        expected[..4].copy_from_slice(&[event_count as u64, 0, pid, u64::from(admitted != 0)]);
        let mut event = 0;
        for (n, &observed_n) in observed.iter().enumerate().take(self.returns + 1) {
            if !observed_n {
                continue;
            }
            let ordinal = observed[..=n].iter().filter(|b| **b).count() as u64;
            let generation = if self.scenario == Scenario::AdmittedRearm && n != 0 {
                self.extra.generations[1]
            } else {
                self.extra.generations[0]
            };
            let invocation = if self.scenario == Scenario::AdmittedRearm && n != 0 {
                ordinal - 1
            } else {
                ordinal
            };
            let history = if self.scenario == Scenario::AdmittedRearm && n != 0 {
                3
            } else {
                1
            };
            let bits = invocation | (history << 13);
            for (kind, pc) in [(1, r.target(n).entry), (2, w[29 + n * 7 + 4])] {
                if kind == 2 && !(n < self.returns || w[1] == 2) {
                    continue;
                }
                let at = 4 + event * 7;
                expected[at..at + 7].copy_from_slice(&[
                    kind,
                    ordinal,
                    pc,
                    rsp - bytes::SUBJECT_RSP_DELTA,
                    r.caller + bytes::CONTINUATIONS[n],
                    generation,
                    bits,
                ]);
                event += 1;
            }
        }
        assert_eq!(&w[JOURNAL..], expected);
    }
    pub(in super::super) fn boundary(&self, child: &Tracee, ready: &WalkReady) {
        let mut empty = [0_u64; 512];
        empty[2] = child.pid as u64;
        let expected = self.prior.as_ref().map_or(&empty[..], |w| &w[JOURNAL..]);
        let bytes: Vec<_> = expected.iter().flat_map(|n| n.to_le_bytes()).collect();
        assert_eq!(
            child.memory(ready.journal().unwrap().address, PAGE),
            bytes,
            "complete event prefix at every original/caller boundary"
        );
        if let Some(prior) = &self.prior {
            assert_eq!(self.read(child), *prior);
        } else {
            assert!(self.read(child).iter().all(|n| *n == 0));
        }
    }
    pub(in super::super) fn at_return(
        &mut self,
        oracle: &NormalOracle,
        child: &Tracee,
        ready: &WalkReady,
        returns: &[u64],
    ) {
        assert_eq!(returns.len(), self.returns + 1);
        let w = self
            .prior
            .as_ref()
            .expect("mandatory real pre-RET callback");
        assert_eq!(w[1], 2);
        assert_eq!(w[10], returns.len() as u64);
        assert_eq!(w[29 + self.returns * 7 + 4], *returns.last().unwrap());
        assert_eq!(
            child.memory(ready.journal().unwrap().address, PAGE),
            w[JOURNAL..]
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        );
        assert_eq!(self.read(child), *w);
        assert!(self.entry.is_none() && self.loaded_state.is_none());
        oracle.deadline.check();
        self.returns += 1;
    }
    pub(in super::super) fn finish(self, parent: &mut Option<Parent>, deadline: Deadline) {
        assert_eq!((self.loaded, self.returns), (4, 4));
        assert!(self.after_branch.is_none());
        assert_eq!(
            self.callbacks,
            4 + self.scenario.observed().iter().filter(|b| **b).count()
        );
        assert_eq!(self.command, self.scenario.scheduled());
        if let Some(parent) = parent.take() {
            parent.finish(deadline);
        }
    }
}
impl NormalOracle {
    pub fn new_early_entry(seed: u64, case: Case, scenario: Scenario, deadline: Deadline) -> Self {
        let mut result = Self::new_module_session(seed, case, deadline);
        result.early_entry = Some(scenario);
        result
    }
    pub fn pair_early_entry<F>(&self, setup: F) -> (NormalPairResult<4>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        assert!(self.early_entry.is_some());
        self.pair_module_common(setup)
    }
}
impl NormalContext<'_> {
    pub fn early_entry_scenario(&self) -> Scenario {
        self.oracle
            .early_entry
            .expect("explicit early entry qualification")
    }
    pub fn take_early_entry_control(&mut self) -> Option<Child> {
        self.early_entry_control.take()
    }
    pub fn ready_early_entry(self, ready: &Ready) {
        assert_eq!(ready.module.case, self.module_session_case());
        assert!(
            self.control.is_none() && self.early_entry_control.is_none() && self.output.is_none()
        );
        let wire = ready.encode(self.early_entry_scenario());
        self.ready_module_wire(wire);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn refuses(f: impl FnOnce()) {
        assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
    }

    // Fabricated protocol data only: no native execution or gate authority.
    fn ready(k: usize, order: usize) -> Ready {
        let code = [0xb8, 1, 0, 0, 0, 0xc3];
        let mut source = vec![0; PAGE];
        source[..6].copy_from_slice(&code);
        source[64..70].copy_from_slice(&code);
        let mut caller = vec![0; PAGE];
        caller[..bytes::BYTES.len()].copy_from_slice(bytes::BYTES);
        let functions = [0x3000, 0x3040].map(|entry| Function {
            entry,
            heads: vec![entry, entry + 5],
            returns: vec![entry + 5],
            boundaries: vec![(entry, entry), (entry + 5, entry + 5)],
        });
        Ready {
            module: super::super::Ready {
                caller: 0x1000,
                caller_immutable: vec![(0x1000, caller)],
                functions,
                immutable: vec![(0x3000, source.clone()), (0x5000, vec![0xa5; 8192])],
                original_source: source,
                journal: Some(JournalReady {
                    address: 0x9000,
                    a_generation: 11,
                    b_generation: None,
                    helper_tid: None,
                }),
                case: Case::new_session(0, k, 6, 6, order),
            },
            extra: Extra {
                gates: [[1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12]],
                marker: 13,
                witness: 14,
                helper_tid: 15,
                generations: [16, 17],
            },
        }
    }

    #[test]
    fn nested_session_frame_roundtrips_multiple_immutable_blobs() {
        for k in [10, 1000] {
            for order in 0..2 {
                let ready = ready(k, order);
                let body = ready.module.encode_session();
                assert!(body.len() > 8192);
                assert!(
                    ready
                        .module
                        .caller_immutable
                        .iter()
                        .chain(&ready.module.immutable)
                        .all(|(_, bytes)| (1..=8192).contains(&bytes.len()))
                );
                assert!((1..=8192).contains(&ready.module.original_source.len()));
                assert_eq!(ready.extra.words().len(), 17);
                for scenario in [
                    Scenario::Enabled,
                    Scenario::Bypass,
                    Scenario::LoadedTrueDisarm,
                    Scenario::LoadedFalseArm,
                    Scenario::AdmittedRearm,
                    Scenario::ReturnedDisarm,
                ] {
                    let wire = ready.encode(scenario);
                    assert_eq!(wire.len(), 3 * 8 + body.len() + 17 * 8);
                    assert!(wire.len() <= WIRE_LIMIT);
                    let decoded = Ready::decode(&wire, ready.module.case, scenario);
                    assert_eq!(decoded.module.validate(true, ready.module.case).len(), 4);
                    assert_eq!(decoded.module.encode_session(), body);
                    assert_eq!(decoded.extra.words(), ready.extra.words());
                    assert_eq!(decoded.encode(scenario), wire);
                }
            }
        }
    }

    #[test]
    fn nested_session_frame_rejects_truncation_and_bad_lengths() {
        let ready = ready(10, 0);
        let scenario = Scenario::Enabled;
        let wire = ready.encode(scenario);
        let body_len = ready.module.encode_session().len();
        let suffix = 3 * 8 + body_len;
        let reject = |bad: &[u8]| {
            refuses(|| {
                Ready::decode(bad, ready.module.case, scenario);
            });
        };
        for end in [0, 7, 8, 15, 16, 23, 24, suffix - 1, suffix, wire.len() - 1] {
            reject(&wire[..end]);
        }
        let mut missing_suffix_word = wire.clone();
        drop(missing_suffix_word.drain(suffix..suffix + 8));
        reject(&missing_suffix_word);
        let mut extra_suffix_word = wire.clone();
        extra_suffix_word.extend_from_slice(&0_u64.to_le_bytes());
        reject(&extra_suffix_word);
        for declared in [0, body_len as u64 - 1, body_len as u64 + 1, u64::MAX] {
            let mut bad = wire.clone();
            bad[16..24].copy_from_slice(&declared.to_le_bytes());
            reject(&bad);
        }
        // Even self-consistent outer lengths cannot hide a truncated/extra inner byte.
        let mut inner_short = wire.clone();
        inner_short.remove(suffix - 1);
        inner_short[16..24].copy_from_slice(&(body_len as u64 - 1).to_le_bytes());
        reject(&inner_short);
        let mut inner_extra = wire.clone();
        inner_extra.insert(suffix, 0);
        inner_extra[16..24].copy_from_slice(&(body_len as u64 + 1).to_le_bytes());
        reject(&inner_extra);
        let mut oversized = wire.clone();
        oversized.resize(WIRE_LIMIT + 1, 0);
        let oversized_body_len = (oversized.len() - 20 * 8) as u64;
        oversized[16..24].copy_from_slice(&oversized_body_len.to_le_bytes());
        reject(&oversized);
        for (at, value) in [(0, 0_u64), (8, Scenario::Bypass as u64)] {
            let mut bad = wire.clone();
            bad[at..at + 8].copy_from_slice(&value.to_le_bytes());
            reject(&bad);
        }
        refuses(|| {
            Ready::decode(&wire, Case::new_session(1, 10, 6, 6, 0), scenario);
        });
    }

    #[test]
    fn nested_session_frame_preserves_individual_blob_limit() {
        for length in [0, 8193] {
            for field in 0..4 {
                let mut ready = ready(10, 0);
                let bytes = match field {
                    0 => &mut ready.module.caller_immutable[0].1,
                    1 => &mut ready.module.immutable[0].1,
                    2 => &mut ready.module.immutable[1].1,
                    _ => &mut ready.module.original_source,
                };
                bytes.resize(length, 0);
                let wire = ready.encode(Scenario::Enabled);
                assert!(wire.len() <= WIRE_LIMIT);
                refuses(|| {
                    Ready::decode(&wire, ready.module.case, Scenario::Enabled);
                });
            }
        }
    }
}
