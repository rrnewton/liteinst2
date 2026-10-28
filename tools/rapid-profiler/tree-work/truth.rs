//! Literal work and operands for a fixed caller and linked-memory child.
//! This is evaluation truth, with no certificate, planner or callback input.
//! An interpreter prediction is not evidence that a native CALL/RET executed.

#[path = "../cache-work/truth.rs"]
pub mod leaf;

pub const INPUT_BYTES: usize = 1024;
pub const ROOT_NODE: u8 = 0;
pub const CHILD_NODE: u8 = 1;
pub const CHILD_OFFSET: u64 = 32;
pub const ROOT_BYTES: [u8; 23] = [
    0x48, 0x83, 0xec, 0x08, 0xb8, 0, 0, 0, 0, 0xe8, 0x12, 0, 0, 0, 0x48, 0x83, 0xc0, 0x01, 0x48,
    0x83, 0xc4, 0x08, 0xc3,
];
pub const GAP_BYTES: [u8; 9] = [0xcc; 9];
pub const CHILD_BYTES: [u8; 39] = leaf::BYTES;
pub const ROOT_HEADS: [u8; 6] = [0, 4, 9, 14, 18, 22];
pub const CHILD_HEADS: [u8; 11] = leaf::HEADS;
pub const MAX_STEPS: usize = 332;
pub const EVENTS: usize = 132;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Case {
    Fit2,
    Conflict3,
}
pub const ALL: [Case; 2] = [Case::Fit2, Case::Conflict3];
impl Case {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fit2 => "fit2",
            Self::Conflict3 => "conflict3",
        }
    }
    pub fn cycle(self) -> &'static [usize] {
        match self {
            Self::Fit2 => &[0, 4],
            Self::Conflict3 => &[0, 4, 8],
        }
    }
    fn leaf(self) -> leaf::Case {
        match self {
            Self::Fit2 => leaf::Case::Fit2,
            Self::Conflict3 => leaf::Case::Conflict3,
        }
    }
}
pub fn input(case: Case, seed: u64) -> [u8; INPUT_BYTES] {
    leaf::input(case.leaf(), seed)
}
pub fn scalar(case: Case, seed: u64) -> u64 {
    leaf::scalar(case.leaf(), seed).wrapping_add(1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Counts {
    pub instructions: usize,
    pub root_instructions: usize,
    pub child_instructions: usize,
    pub conditional: usize,
    pub taken: usize,
    pub input_reads: usize,
    pub return_reads: usize,
    pub call_stores: usize,
}
pub fn counts(_case: Case) -> Counts {
    Counts {
        instructions: 332,
        root_instructions: 6,
        child_instructions: 326,
        conditional: 64,
        taken: 63,
        input_reads: 129,
        return_reads: 2,
        call_stores: 1,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bytes,
    Length,
    Count,
    Address,
    Operand,
    Child(leaf::Error),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    CallStore,
    Count,
    Payload,
    Link,
    ChildReturn,
    RootReturn,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub node: u8,
    pub kind: EventKind,
    pub address: u64,
    pub width: u8,
    pub value: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step {
    pub node: u8,
    pub pc: u64,
    pub next_pc: u64,
    pub branch_taken: Option<bool>,
    pub event: Option<Event>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Truth {
    pub steps: Vec<Step>,
    pub value: u64,
    pub resumed_rsp: u64,
}

pub fn check_bytes(root: &[u8], child: &[u8]) -> Result<(), Error> {
    if root == ROOT_BYTES && child == CHILD_BYTES {
        Ok(())
    } else {
        Err(Error::Bytes)
    }
}
// Return the actual child's RSP. All additions used below are covered here.
fn addresses(root: u64, data: u64, rsp: u64) -> Result<u64, Error> {
    root.checked_add(CHILD_OFFSET + CHILD_BYTES.len() as u64)
        .ok_or(Error::Address)?;
    let input_end = data.checked_add(INPUT_BYTES as u64).ok_or(Error::Address)?;
    let stack_end = rsp.checked_add(8).ok_or(Error::Address)?;
    let child_rsp = rsp.checked_sub(16).ok_or(Error::Address)?;
    if data % 64 != 0 || rsp % 16 != 8 || !(input_end <= child_rsp || stack_end <= data) {
        return Err(Error::Address);
    }
    Ok(child_rsp)
}
fn child_event(read: leaf::Read) -> Event {
    Event {
        node: CHILD_NODE,
        kind: match read.kind {
            leaf::ReadKind::Count => EventKind::Count,
            leaf::ReadKind::Payload => EventKind::Payload,
            leaf::ReadKind::Link => EventKind::Link,
            leaf::ReadKind::ReturnWord => EventKind::ChildReturn,
        },
        address: read.address,
        width: read.width,
        value: read.value,
    }
}
fn root_event(kind: EventKind, address: u64, value: u64) -> Event {
    Event {
        node: ROOT_NODE,
        kind,
        address,
        width: 8,
        value,
    }
}
fn root_step(root: u64, pc: u64, next: u64, event: Option<Event>) -> Step {
    Step {
        node: ROOT_NODE,
        pc: root + pc,
        next_pc: next,
        branch_taken: None,
        event,
    }
}

/// Interpret the literal caller around the separately implemented child.
/// Checked integers describe expected addresses; they grant no memory authority.
pub fn interpret(
    root_bytes: &[u8],
    child_bytes: &[u8],
    input: &[u8],
    root: u64,
    data: u64,
    root_rsp: u64,
    outer_return: u64,
) -> Result<Truth, Error> {
    check_bytes(root_bytes, child_bytes)?;
    if input.len() != INPUT_BYTES {
        return Err(Error::Length);
    }
    if input[16..24] != 64_u64.to_le_bytes() {
        return Err(Error::Count);
    }
    let child_rsp = addresses(root, data, root_rsp)?;
    let child = leaf::interpret(
        child_bytes,
        input,
        root + CHILD_OFFSET,
        data,
        child_rsp,
        root + 14,
    )
    .map_err(Error::Child)?;
    if child.steps.len() != 326 || child.resumed_rsp != root_rsp - 8 {
        return Err(Error::Operand);
    }
    let mut steps = Vec::with_capacity(MAX_STEPS);
    steps.push(root_step(root, 0, root + 4, None));
    steps.push(root_step(root, 4, root + 9, None));
    steps.push(root_step(
        root,
        9,
        root + CHILD_OFFSET,
        Some(root_event(EventKind::CallStore, child_rsp, root + 14)),
    ));
    steps.extend(child.steps.into_iter().map(|s| Step {
        node: CHILD_NODE,
        pc: s.pc,
        next_pc: s.next_pc,
        branch_taken: s.branch_taken,
        event: s.read.map(child_event),
    }));
    steps.push(root_step(root, 14, root + 18, None));
    steps.push(root_step(root, 18, root + 22, None));
    steps.push(root_step(
        root,
        22,
        outer_return,
        Some(root_event(EventKind::RootReturn, root_rsp, outer_return)),
    ));
    Ok(Truth {
        steps,
        value: child.value.wrapping_add(1),
        resumed_rsp: root_rsp + 8,
    })
}

/// Independent cycle/stack formula. It does not walk fixture links or consume
/// interpreter steps, decoded certificates, relocation maps or native events.
pub fn expected_events(
    case: Case,
    seed: u64,
    root: u64,
    data: u64,
    root_rsp: u64,
    outer_return: u64,
) -> Result<Vec<Event>, Error> {
    let child_rsp = addresses(root, data, root_rsp)?;
    let mut events = Vec::with_capacity(EVENTS);
    events.push(root_event(EventKind::CallStore, child_rsp, root + 14));
    events.extend(
        leaf::expected_reads(case.leaf(), seed, data, child_rsp, root + 14)
            .map_err(Error::Child)?
            .into_iter()
            .map(child_event),
    );
    events.push(root_event(EventKind::RootReturn, root_rsp, outer_return));
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROOT: u64 = 0x1000;
    const DATA: u64 = 0x2080;
    const RSP: u64 = 0x3fe8;
    const RET: u64 = 0x5000;
    fn run(case: Case, seed: u64) -> Truth {
        interpret(
            &ROOT_BYTES,
            &CHILD_BYTES,
            &input(case, seed),
            ROOT,
            DATA,
            RSP,
            RET,
        )
        .unwrap()
    }
    #[test]
    fn tree_truth_real_call_two_returns_and_nested_order() {
        for case in ALL {
            for seed in [0, 0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
                let t = run(case, seed);
                assert_eq!(t.steps.len(), 332);
                assert_eq!(t.value, scalar(case, seed));
                assert_eq!(t.resumed_rsp, RSP + 8);
                assert_eq!(t.steps.iter().filter(|s| s.node == ROOT_NODE).count(), 6);
                assert_eq!(t.steps.iter().filter(|s| s.node == CHILD_NODE).count(), 326);
                assert_eq!(
                    t.steps.iter().filter(|s| s.branch_taken.is_some()).count(),
                    64
                );
                assert_eq!(
                    t.steps
                        .iter()
                        .filter(|s| s.branch_taken == Some(true))
                        .count(),
                    63
                );
                let events: Vec<_> = t.steps.iter().filter_map(|s| s.event).collect();
                assert_eq!(
                    events,
                    expected_events(case, seed, ROOT, DATA, RSP, RET).unwrap()
                );
                assert_eq!(events.len(), 132);
                assert_eq!(
                    events[0],
                    root_event(EventKind::CallStore, RSP - 16, ROOT + 14)
                );
                assert_eq!(
                    events[130],
                    Event {
                        node: CHILD_NODE,
                        kind: EventKind::ChildReturn,
                        address: RSP - 16,
                        width: 8,
                        value: ROOT + 14
                    }
                );
                assert_eq!(events[131], root_event(EventKind::RootReturn, RSP, RET));
                assert_eq!(
                    t.steps[..3].iter().map(|s| s.pc - ROOT).collect::<Vec<_>>(),
                    [0, 4, 9]
                );
                assert_eq!(t.steps[2].next_pc, ROOT + 32);
                assert_eq!(t.steps[328].pc, ROOT + 70);
                assert_eq!(t.steps[328].next_pc, ROOT + 14);
                assert_eq!(
                    t.steps[329..]
                        .iter()
                        .map(|s| s.pc - ROOT)
                        .collect::<Vec<_>>(),
                    [14, 18, 22]
                );
                assert_eq!(t.steps[331].next_pc, RET);
            }
        }
        assert_eq!(run(Case::Fit2, 0).value, 0x37ac_32a6_0897_73d6);
        assert_eq!(run(Case::Conflict3, 0).value, 0xd24d_3940_60bb_55fa);
    }
    #[test]
    fn tree_truth_every_opcode_bit_refuses_and_case_cannot_be_relabelled() {
        let input = input(Case::Fit2, 7);
        for i in 0..ROOT_BYTES.len() + CHILD_BYTES.len() {
            for bit in 0..8 {
                let mut root = ROOT_BYTES;
                let mut child = CHILD_BYTES;
                if i < root.len() {
                    root[i] ^= 1 << bit;
                } else {
                    child[i - root.len()] ^= 1 << bit;
                }
                assert_eq!(
                    interpret(&root, &child, &input, ROOT, DATA, RSP, RET),
                    Err(Error::Bytes)
                );
            }
        }
        let t = run(Case::Fit2, 7);
        assert_ne!(
            t.steps.iter().filter_map(|s| s.event).collect::<Vec<_>>(),
            expected_events(Case::Conflict3, 7, ROOT, DATA, RSP, RET).unwrap()
        );
        let mut changed = input;
        changed[..8].copy_from_slice(&0_u64.to_le_bytes());
        let t = interpret(&ROOT_BYTES, &CHILD_BYTES, &changed, ROOT, DATA, RSP, RET).unwrap();
        assert_ne!(t.value, scalar(Case::Fit2, 7));
    }
    #[test]
    fn tree_truth_boundaries_and_non64_count_refuse() {
        let input = input(Case::Fit2, 0);
        for count in [0_u64, 16, 63, 65, u64::MAX] {
            let mut changed = input;
            changed[16..24].copy_from_slice(&count.to_le_bytes());
            assert_eq!(
                interpret(&ROOT_BYTES, &CHILD_BYTES, &changed, ROOT, DATA, RSP, RET),
                Err(Error::Count)
            );
        }
        assert_eq!(
            interpret(
                &ROOT_BYTES,
                &CHILD_BYTES,
                &input[..1023],
                ROOT,
                DATA,
                RSP,
                RET
            ),
            Err(Error::Length)
        );
        for (root, data, rsp) in [
            (u64::MAX - 50, DATA, RSP),
            (ROOT, u64::MAX - 63, RSP),
            (ROOT, DATA + 1, RSP),
            (ROOT, DATA, 8),
            (ROOT, DATA, u64::MAX - 7),
            (ROOT, DATA, DATA + 24),
            (ROOT, DATA, RSP + 8),
        ] {
            assert_eq!(
                interpret(&ROOT_BYTES, &CHILD_BYTES, &input, root, data, rsp, RET),
                Err(Error::Address)
            );
        }
        let mut changed = input;
        changed[..8].copy_from_slice(&1024_u64.to_le_bytes());
        assert_eq!(
            interpret(&ROOT_BYTES, &CHILD_BYTES, &changed, ROOT, DATA, RSP, RET),
            Err(Error::Child(leaf::Error::Offset))
        );
    }
}
