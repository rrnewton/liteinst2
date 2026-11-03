//! Descriptive control-flow construction over one immutable linear scan.
//!
//! Callers retain instruction, entry, ownership and error-order policies. These
//! facts neither discover external entries nor authorize code publication.

use crate::contracts::AddressRange;
use crate::scanner::{ScanResult, ScannedInstruction};
use iced_x86::{FlowControl, Instruction, OpKind};
use std::collections::{BTreeMap, BTreeSet};

/// A decoded local successor, including an explicit unresolved coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    /// Index of an instruction in the same scan.
    Head(usize),
    /// The coordinate is not an instruction head in this scan.
    NotHead(u64),
}

impl Target {
    /// Returns the local index without treating a missing head as an edge exit.
    pub const fn head(self) -> Option<usize> {
        match self {
            Self::Head(index) => Some(index),
            Self::NotHead(_) => None,
        }
    }
}

/// Pure transfer facts for one instruction; unsupported transfers stay explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowFacts {
    successors: Vec<Target>,
    branch_target: Option<Target>,
    call_target: Option<u64>,
    continuation: Option<Target>,
    unresolved_transfer: bool,
}

impl RowFacts {
    /// Ordered local edges: a conditional target precedes its fallthrough.
    /// Equal destinations retain two edges. A direct callee is not in this list.
    pub fn successors(&self) -> &[Target] {
        &self.successors
    }

    /// The near conditional/unconditional target, when encoded as such.
    pub const fn branch_target(&self) -> Option<Target> {
        self.branch_target
    }

    /// Separately recorded direct call destination, without callee ownership.
    pub const fn call_target(&self) -> Option<u64> {
        self.call_target
    }

    /// Conditional fallthrough or call continuation, including a missing head.
    pub const fn continuation(&self) -> Option<Target> {
        self.continuation
    }

    /// Whether this transfer cannot be represented as known local edges/exits.
    /// Returns are terminals; callers still enforce their exact return forms.
    pub const fn unresolved_transfer(&self) -> bool {
        self.unresolved_transfer
    }
}

/// Facts derived from the same borrowed scan used by the caller's validation.
#[derive(Debug)]
pub struct GraphFacts<'a> {
    scan: &'a ScanResult,
    rows: Vec<RowFacts>,
    branch_entries: BTreeSet<usize>,
}

/// Refusals from index conversion or public traversal dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphError {
    /// An instruction has an unsupported or indirect transfer.
    UnresolvedTransfer(usize),
    /// A local edge from the first index targets the non-head address.
    UnresolvedTarget(usize, u64),
    /// A requested entry or return index is outside the graph.
    InvalidIndex(usize),
    /// The supplied coverage length differs from the number of graph rows.
    CoverageLength,
}

/// Every local edge is indexed; this is not external-entry or callee authority.
#[derive(Debug)]
pub struct IndexedGraph<'g, 's> {
    facts: &'g GraphFacts<'s>,
    successors: Vec<Vec<usize>>,
}

/// Which source heads participate in a block partition.
#[derive(Clone, Copy, Debug)]
pub enum Coverage<'a> {
    /// Partition all decoded heads using the caller's already validated owner.
    AllDecoded(AddressRange),
    /// Partition only marked heads; gaps remain outside every returned block.
    Reachable(&'a [bool]),
}

/// Returns an encoded near operand, independently of the transfer category.
///
/// This includes direct CALL and XBEGIN as well as branches. It proves neither
/// local head membership nor target ownership, reachability or qualification.
pub fn direct_target(instruction: &Instruction) -> Option<u64> {
    (instruction.op_count() > 0
        && matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ))
    .then(|| instruction.near_branch_target())
}

/// Collects owner boundaries, following cuts and admitted direct-target cuts.
///
/// Instructions are visited in their supplied order. For each non-`Next` row,
/// `include_following` chooses its next-IP cut. The direct-target callback then
/// validates that row's encoded near operand and chooses whether it is a cut;
/// its first error stops collection. Indirect transfers still get a following
/// cut but have no invented target. No local-head, reachability or callee rule
/// is implicit: callers retain those policies, including cross-owner targets.
pub fn collect_block_cuts<'a, E>(
    owners: impl IntoIterator<Item = AddressRange>,
    instructions: impl IntoIterator<Item = &'a Instruction>,
    mut include_following: impl FnMut(usize, u64) -> bool,
    mut include_direct: impl FnMut(usize, u64) -> Result<bool, E>,
) -> Result<BTreeSet<u64>, E> {
    let mut cuts = owners
        .into_iter()
        .flat_map(|owner| [owner.start(), owner.end()])
        .collect::<BTreeSet<_>>();
    for (index, instruction) in instructions.into_iter().enumerate() {
        if instruction.flow_control() != FlowControl::Next
            && include_following(index, instruction.next_ip())
        {
            cuts.insert(instruction.next_ip());
        }
        if let Some(target) = direct_target(instruction)
            && include_direct(index, target)?
        {
            cuts.insert(target);
        }
    }
    Ok(cuts)
}

/// Builds pure rows and invokes caller validation once per head in source order.
///
/// After indexing heads, each callback runs before its row is accepted or the
/// next row's transfer is derived or validated.
/// Unsupported rows and missing heads are facts, not eager errors. Empty scans
/// have no invented entry. No decoder, reachability or entry policy runs here.
pub fn build<'a, E>(
    scan: &'a ScanResult,
    mut check: impl FnMut(usize, &ScannedInstruction, &RowFacts) -> Result<(), E>,
) -> Result<GraphFacts<'a>, E> {
    let heads: BTreeMap<_, _> = scan
        .instructions()
        .iter()
        .enumerate()
        .map(|(index, item)| (item.address(), index))
        .collect();
    let resolve = |address| {
        heads
            .get(&address)
            .copied()
            .map_or(Target::NotHead(address), Target::Head)
    };
    let mut rows = Vec::with_capacity(scan.instructions().len());
    let mut branch_entries = BTreeSet::new();
    if !scan.instructions().is_empty() {
        branch_entries.insert(0);
    }
    for (index, item) in scan.instructions().iter().enumerate() {
        let instruction = item.instruction();
        let flow = instruction.flow_control();
        let near = direct_target(instruction);
        let next = resolve(instruction.next_ip());
        let mut row = RowFacts {
            successors: Vec::new(),
            branch_target: None,
            call_target: None,
            continuation: None,
            unresolved_transfer: false,
        };
        match flow {
            FlowControl::Next => row.successors.push(next),
            FlowControl::Call | FlowControl::IndirectCall => {
                row.call_target = near;
                row.continuation = Some(next);
                row.successors.push(next);
                row.unresolved_transfer = near.is_none();
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                row.branch_target = near.map(resolve);
                if let Some(target) = row.branch_target {
                    row.successors.push(target);
                } else {
                    row.unresolved_transfer = true;
                }
                if flow == FlowControl::ConditionalBranch {
                    row.continuation = Some(next);
                    row.successors.push(next);
                }
            }
            FlowControl::Return => {}
            _ => row.unresolved_transfer = true,
        }
        check(index, item, &row)?;
        if let Some(Target::Head(target)) = row.branch_target {
            branch_entries.insert(target);
        }
        if let (FlowControl::ConditionalBranch, Some(Target::Head(target))) =
            (flow, row.continuation)
        {
            branch_entries.insert(target);
        }
        rows.push(row);
    }
    Ok(GraphFacts {
        scan,
        rows,
        branch_entries,
    })
}

impl<'s> GraphFacts<'s> {
    /// Returns a row without panicking on an out-of-range index.
    pub fn row(&self, index: usize) -> Option<&RowFacts> {
        self.rows.get(index)
    }

    /// Entry plus local branch targets/conditional fallthroughs in source order.
    /// Post-return/call block cuts are not thereby declared legal entries.
    pub fn branch_entries(&self) -> &BTreeSet<usize> {
        &self.branch_entries
    }

    /// Returns cuts over the caller's decoded owner without requiring indexing.
    ///
    /// Every non-`Next` instruction keeps its following cut below the owner end.
    /// The callback only selects which local branch targets also become cuts;
    /// it does not remove rows, diagnose transfers or establish ownership.
    /// Unresolved branch targets never become cuts. As with `AllDecoded`, the
    /// caller supplies the owner.
    pub fn block_cuts(
        &self,
        owner: AddressRange,
        mut include_branch: impl FnMut(usize) -> bool,
    ) -> BTreeSet<u64> {
        match collect_block_cuts(
            [owner],
            self.scan
                .instructions()
                .iter()
                .map(|item| item.instruction()),
            |_, next| next < owner.end(),
            |index, _| {
                Ok::<_, core::convert::Infallible>(
                    matches!(self.rows[index].branch_target, Some(Target::Head(_)))
                        && include_branch(index),
                )
            },
        ) {
            Ok(cuts) => cuts,
            Err(never) => match never {},
        }
    }

    /// Resolves every local edge without dropping unknown transfers or targets.
    /// Direct callee coordinates are deliberately outside this local check.
    pub fn indexed(&self) -> Result<IndexedGraph<'_, 's>, GraphError> {
        let mut successors = Vec::with_capacity(self.rows.len());
        for (index, row) in self.rows.iter().enumerate() {
            if row.unresolved_transfer {
                return Err(GraphError::UnresolvedTransfer(index));
            }
            let mut edges = Vec::with_capacity(row.successors.len());
            for target in &row.successors {
                match *target {
                    Target::Head(head) => edges.push(head),
                    Target::NotHead(address) => {
                        return Err(GraphError::UnresolvedTarget(index, address));
                    }
                }
            }
            successors.push(edges);
        }
        Ok(IndexedGraph {
            facts: self,
            successors,
        })
    }
}

impl IndexedGraph<'_, '_> {
    /// Ordered indexed successors for all heads, retaining edge multiplicity.
    pub fn successors(&self) -> &[Vec<usize>] {
        &self.successors
    }

    /// Computes reachability with the existing source-order edge DFS.
    pub fn reachable_from(&self, entry: usize) -> Result<Vec<bool>, GraphError> {
        if entry >= self.successors.len() {
            return Err(GraphError::InvalidIndex(entry));
        }
        let mut reached = vec![false; self.successors.len()];
        let mut pending = vec![entry];
        while let Some(index) = pending.pop() {
            if !reached[index] {
                reached[index] = true;
                pending.extend(self.successors[index].iter().copied());
            }
        }
        Ok(reached)
    }

    /// Computes structural paths to the supplied exits, not input termination.
    pub fn can_reach_any(&self, exits: &[usize]) -> Result<Vec<bool>, GraphError> {
        for &index in exits {
            if index >= self.successors.len() {
                return Err(GraphError::InvalidIndex(index));
            }
        }
        let mut can_return = vec![false; self.successors.len()];
        for &index in exits {
            can_return[index] = true;
        }
        for _ in 0..self.successors.len() {
            for (index, next) in self.successors.iter().enumerate() {
                let reaches = next.iter().any(|&target| can_return[target]);
                can_return[index] |= reaches;
            }
        }
        Ok(can_return)
    }

    /// Partitions complete decoded ownership or an exactly sized reached mask.
    pub fn blocks(&self, coverage: Coverage<'_>) -> Result<Vec<(u64, u64)>, GraphError> {
        let items = self.facts.scan.instructions();
        let reached = match coverage {
            Coverage::AllDecoded(owner) => {
                let cuts: Vec<_> = self.facts.block_cuts(owner, |_| true).into_iter().collect();
                return Ok(cuts.windows(2).map(|pair| (pair[0], pair[1])).collect());
            }
            Coverage::Reachable(reached) => reached,
        };
        if reached.len() != items.len() {
            return Err(GraphError::CoverageLength);
        }
        let mut blocks = Vec::new();
        let mut index = 0;
        while index < items.len() {
            if !reached[index] {
                index += 1;
                continue;
            }
            let first = index;
            loop {
                let terminal = items[index].instruction().flow_control() != FlowControl::Next
                    || index + 1 == items.len()
                    || !reached[index + 1]
                    || self.facts.branch_entries.contains(&(index + 1));
                index += 1;
                if terminal {
                    break;
                }
            }
            blocks.push((
                items[first].address(),
                items[index - 1].instruction().next_ip(),
            ));
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests;
