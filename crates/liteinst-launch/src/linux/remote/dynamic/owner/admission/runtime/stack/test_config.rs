//! Closed test configurations. They never construct a native authority, and
//! actual allocations and intervention syscalls remain in their real owners.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StackAllocationTarget {
    Profile,
    Root,
    Native,
    Word(usize),
    Operand,
    Census,
    Call,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StackAllocationFault {
    pub(super) target: StackAllocationTarget,
    pub(super) ordinal: usize,
    pub(super) unwind: bool,
}
impl StackAllocationFault {
    fn validate(self) {
        let bound = match self.target {
            StackAllocationTarget::Profile | StackAllocationTarget::Operand => 3,
            StackAllocationTarget::Word(index) => {
                assert!(index < 3);
                3
            }
            StackAllocationTarget::Root => 12,
            StackAllocationTarget::Native => 18,
            StackAllocationTarget::Census => 17,
            StackAllocationTarget::Call => 1,
        };
        assert!(self.ordinal < bound);
    }
    pub(super) fn pair(self) -> (Option<usize>, Option<usize>) {
        self.validate();
        (
            (!self.unwind).then_some(self.ordinal),
            self.unwind.then_some(self.ordinal),
        )
    }
}
impl RuntimeStackState {
    pub(super) fn configure_allocation(&mut self, fault: StackAllocationFault) {
        fault.validate();
        assert!(self.allocation_config.is_none() && !self.allocation_config_used);
        assert_eq!(self.count, 0);
        assert!(
            self.pending.is_none() && self.failure.is_none() && self.settlement_failure.is_none()
        );
        if fault.target == StackAllocationTarget::Profile {
            assert!(!self.startup_started);
            let (before, after) = fault.pair();
            self.profile.set_allocation_fault(before, after);
            self.allocation_config_used = true;
        }
        self.allocation_config = Some(fault);
    }
}
impl RuntimeStackAttempt {
    pub(super) fn configure_allocation(&mut self, fault: StackAllocationFault) {
        fault.validate();
        assert!(!self.allocation_started && !self.allocated);
        assert!(
            self.nested_fault.is_none()
                && self.failure.is_none()
                && self.settlement_failure.is_none()
        );
        let (before, after) = fault.pair();
        match fault.target {
            StackAllocationTarget::Profile => panic!("startup profile fault reached an attempt"),
            StackAllocationTarget::Root => {
                assert!(fault.ordinal < if self.is_call { 12 } else { 10 });
                self.allocation_fault = AllocationFault { before, after };
            }
            StackAllocationTarget::Native => self.native.set_allocation_fault(before, after),
            StackAllocationTarget::Word(index) => {
                self.native.set_word_allocation_fault(index, before, after)
            }
            StackAllocationTarget::Operand => self.operand.set_allocation_fault(before, after),
            StackAllocationTarget::Census => {}
            StackAllocationTarget::Call => assert!(self.is_call),
        }
        self.nested_fault = Some(fault);
    }
}
