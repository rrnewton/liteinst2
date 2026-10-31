// Read-only observations on an actual original JRCXZ step. Capture/seeding,
// publication checks and the full architectural comparator remain unchanged.
impl NativeTrace {
    pub fn assert_jrcxz_boundary_state(&self, pc: u64, expected_rcx: u64) {
        let at = usize::try_from(pc.checked_sub(self.source_base).unwrap()).unwrap();
        assert_eq!(&self.original_code[at..at + 2], &[0xe3, 4]);
        let indices: Vec<_> = self
            .baseline
            .points
            .iter()
            .enumerate()
            .filter(|(_, point)| point.logical_pc == pc)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(indices.len(), 1, "exact single original JRCXZ visit");
        let before = &self.baseline.points[indices[0]];
        let after = &self.baseline.points[indices[0] + 1];
        assert_eq!(before.registers.rip, pc);
        assert_eq!(before.registers.rcx, expected_rcx, "native MOV RCX input");
        let destination = pc + if expected_rcx == 0 { 6 } else { 2 };
        assert_eq!(after.logical_pc, destination, "independent JRCXZ successor");
        assert_eq!(after.registers.rip, destination);
        // Only the logical PC changes across this actual native instruction.
        // Reuse the whole comparator on observed state, not an emulated result.
        let observed = Snapshot {
            logical_pc: before.logical_pc,
            registers: after.registers,
            xstate: after.xstate.clone(),
            data: after.data.clone(),
            application_stack: after.application_stack.clone(),
        };
        assert_state(before, &observed);
    }
}
