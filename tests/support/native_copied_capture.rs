//! Private copied-caller derivation and fresh stopped-tracee captures.
//! No observed bytes or machine state are cached between snapshots.
use super::*;

const MAX_RANGES: usize = 15;
const MAX_BYTES: usize = 98_704;
const MAX_STACK: usize = 400;

pub(super) struct Dispatch {
    heads: BTreeSet<u64>,
    call: u64,
    outer: u64,
    step: rust_invoke::Step,
}
impl Dispatch {
    pub(super) fn new(plan: &rust_invoke::Plan, caller: u64) -> Self {
        caller.checked_add(plan.bytes().len() as u64).unwrap();
        let heads: BTreeSet<_> = plan
            .heads()
            .iter()
            .map(|&offset| caller.checked_add(offset).unwrap())
            .collect();
        assert_eq!(heads.len(), plan.heads().len());
        let call = caller.checked_add(plan.calls()[0]).unwrap();
        let outer = caller.checked_add(plan.outer_ret()).unwrap();
        assert!(heads.contains(&call) && heads.contains(&outer));
        let step = *plan
            .steps()
            .iter()
            .find(|s| s.offset == plan.calls()[0])
            .unwrap();
        assert_eq!(
            step.offset.checked_add(u64::from(step.length)),
            Some(plan.continuations()[0])
        );
        Self {
            heads,
            call,
            outer,
            step,
        }
    }
    pub(super) fn is_head(&self, pc: u64) -> bool {
        self.heads.contains(&pc)
    }
    pub(super) fn call(&self, pc: u64) -> Option<usize> {
        (pc == self.call).then_some(0)
    }
    pub(super) fn outer(&self) -> u64 {
        self.outer
    }
    pub(super) fn call_step(&self) -> &rust_invoke::Step {
        &self.step
    }
}

struct CapturePlan {
    ranges: Vec<(usize, usize)>,
    total: usize,
}
impl CapturePlan {
    fn new(ranges: &[(u64, usize)]) -> Self {
        Self::with_limits(ranges, MAX_RANGES, MAX_BYTES)
    }
    fn with_limits(ranges: &[(u64, usize)], max_ranges: usize, max_bytes: usize) -> Self {
        assert!(!ranges.is_empty() && ranges.len() <= max_ranges);
        let mut ends = Vec::with_capacity(ranges.len());
        let mut checked = Vec::with_capacity(ranges.len());
        let mut total = 0_usize;
        for &(address, len) in ranges {
            assert!(len != 0);
            let end = address.checked_add(u64::try_from(len).unwrap()).unwrap();
            let start = usize::try_from(address).unwrap();
            assert_eq!(start.checked_add(len), Some(usize::try_from(end).unwrap()));
            assert!(ends.iter().all(|&(a, b)| end <= a || b <= address));
            ends.push((address, end));
            total = total.checked_add(len).unwrap();
            assert!(total <= max_bytes && isize::try_from(total).is_ok());
            checked.push((start, len));
        }
        Self {
            ranges: checked,
            total,
        }
    }
    fn read(&self, child: &Tracee) -> Vec<Vec<u8>> {
        self.read_with(|local, remote| {
            // SAFETY: fresh local buffers below are disjoint, live and stable;
            // remote ranges are exact validated fixture ranges of this owned,
            // stopped single-thread child. No atomic-snapshot claim is made.
            unsafe {
                libc::process_vm_readv(
                    child.pid,
                    local.as_ptr(),
                    local.len().try_into().unwrap(),
                    remote.as_ptr(),
                    remote.len().try_into().unwrap(),
                    0,
                )
            }
        })
    }
    fn read_with(
        &self,
        read: impl FnOnce(&[libc::iovec], &[libc::iovec]) -> isize,
    ) -> Vec<Vec<u8>> {
        let mut buffers: Vec<_> = self
            .ranges
            .iter()
            .map(|&(_, len)| vec![0_u8; len])
            .collect();
        let mut local = Vec::with_capacity(self.ranges.len());
        let mut remote = Vec::with_capacity(self.ranges.len());
        let mut local_ends = Vec::with_capacity(self.ranges.len());
        for (buffer, &(address, len)) in buffers.iter_mut().zip(&self.ranges) {
            assert_eq!(buffer.len(), len);
            let start = buffer.as_mut_ptr() as usize;
            let end = start.checked_add(len).unwrap();
            assert!(local_ends.iter().all(|&(a, b)| end <= a || b <= start));
            local_ends.push((start, end));
            local.push(libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: len,
            });
            remote.push(libc::iovec {
                iov_base: address as *mut libc::c_void,
                iov_len: len,
            });
        }
        assert_eq!(local.len(), self.ranges.len());
        assert_eq!(remote.len(), self.ranges.len());
        // One attempt only: negative, zero, short and excessive returns all
        // refuse before any captured bytes can become a successful Snapshot.
        let actual = read(&local, &remote);
        assert_eq!(
            actual,
            isize::try_from(self.total).unwrap(),
            "copied vector read incomplete"
        );
        buffers
    }
}

fn compare_images(captured: &[Vec<u8>], caller: &[(u64, Vec<u8>)], images: &[(u64, Vec<u8>)]) {
    let expected = caller.iter().chain(images);
    assert_eq!(captured.len(), expected.clone().count());
    for (actual, (_, bytes)) in captured.iter().zip(expected) {
        assert_eq!(actual, bytes, "complete normal caller/source/image bytes");
    }
}

pub(super) fn snapshot(
    oracle: &NormalOracle,
    child: &Tracee,
    ready: &WalkReady,
    logical: u64,
) -> Snapshot {
    assert!(matches!(
        ready,
        WalkReady::CopiedRust(_)
            | WalkReady::LeafSetCopied(_)
            | WalkReady::SelectedLeafSet(_)
            | WalkReady::ExactAccuracy(_)
    ));
    let stack_len = usize::try_from(oracle.stack_below().checked_add(8).unwrap()).unwrap();
    assert!(stack_len <= MAX_STACK);
    let mut ranges: Vec<_> = ready
        .caller_immutable()
        .iter()
        .chain(ready.immutable())
        .map(|(address, bytes)| (*address, bytes.len()))
        .collect();
    ranges.push((oracle.data.address(), PAGE));
    ranges.push((oracle.stack_start(), stack_len));
    let mut captured = CapturePlan::new(&ranges).read(child);
    let stack = captured.pop().unwrap();
    let data = captured.pop().unwrap();
    compare_images(&captured, ready.caller_immutable(), ready.immutable());
    // Same semantic comparison order. Transport faults in a later range can
    // precede an earlier image mismatch; either outcome remains a refusal.
    let point = Snapshot {
        logical_pc: logical,
        registers: child.registers(),
        xstate: canonical_xstate(&child.xstate()),
        data,
        application_stack: stack,
    };
    oracle.check_data(ready, &point.data, false);
    oracle.deadline.check();
    point
}

#[cfg(test)]
#[path = "native_copied_capture/tests.rs"]
mod tests;

// Separate nested capture envelope. Old copied MAX_STACK and its profile guard
// remain unchanged. Bounds include2 caller pages,2 source pages,10 images,
// one data page and the full456-byte enclosing-caller/tree stack window.
fn nested_plan(ranges: &[(u64, usize)]) -> CapturePlan {
    CapturePlan::with_limits(ranges, 16, 102_856)
}
#[cfg(test)]
pub(super) fn nested_bounds(ranges: &[(u64, usize)]) {
    let _ = nested_plan(ranges);
}
pub(super) fn nested_snapshot(
    oracle: &NormalOracle,
    child: &Tracee,
    ready: &WalkReady,
    logical: u64,
) -> Snapshot {
    assert!(matches!(ready, WalkReady::CallPair(_)));
    let stack_len = usize::try_from(oracle.stack_below().checked_add(8).unwrap()).unwrap();
    assert!(stack_len <= 456);
    let mut ranges: Vec<_> = ready
        .caller_immutable()
        .iter()
        .chain(ready.immutable())
        .map(|(a, b)| (*a, b.len()))
        .collect();
    ranges.push((oracle.data.address(), PAGE));
    ranges.push((oracle.stack_start(), stack_len));
    let mut captured = nested_plan(&ranges).read(child);
    let stack = captured.pop().unwrap();
    let data = captured.pop().unwrap();
    compare_images(&captured, ready.caller_immutable(), ready.immutable());
    let point = Snapshot {
        logical_pc: logical,
        registers: child.registers(),
        xstate: canonical_xstate(&child.xstate()),
        data,
        application_stack: stack,
    };
    oracle.check_data(ready, &point.data, false);
    oracle.deadline.check();
    point
}
