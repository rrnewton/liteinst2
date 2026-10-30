// Additive immutable semantic observations; the capture and full comparator are unchanged.
#[derive(Clone, Copy)]
pub struct CompiledLeafExpectation<'a> {
    pub entry: u64,
    pub chosen_return: u64,
    pub seed: u64,
    pub input: &'a [u8],
    pub itinerary: &'a [u64],
    pub read_indices: &'a [usize],
    pub answer: u64,
    pub uppercase: bool,
}

impl NativeTrace {
    pub fn assert_compiled_leaf_state(&self, expected: &CompiledLeafExpectation<'_>) {
        let e = expected;
        assert!(e.input.len() <= 64);
        assert_eq!(self.visits(), e.itinerary, "independent complete itinerary");
        assert_eq!(self.terminals.len(), 1);
        let points = &self.baseline.points;
        let terminal = points.last().unwrap();
        assert!(self.terminals.contains(&terminal.logical_pc));
        assert_eq!(
            points
                .iter()
                .filter(|p| self.terminals.contains(&p.logical_pc))
                .count(),
            1
        );
        let entry_index = points.iter().position(|p| p.logical_pc == e.entry).unwrap();
        assert_eq!(points.iter().filter(|p| p.logical_pc == e.entry).count(), 1);
        let entry = &points[entry_index];
        let base = self.baseline.initial.rdi;
        assert_eq!(points[0].registers.rdi, base);
        assert_eq!(entry.registers.rdi, base);
        assert_eq!(entry.registers.rsi, e.input.len() as u64);
        assert_eq!(
            entry.registers.eflags & !DEBUGGER_FLAGS,
            0x202 | (e.seed & 0xcd5)
        );
        assert_eq!(&entry.data[..e.input.len()], e.input);
        assert!(entry.data[e.input.len()..64].iter().all(|&b| b == 0xa5));
        assert_eq!(&entry.data[64..], &points[0].data[64..]);
        assert_eq!(entry.application_stack, points[0].application_stack);
        assert_eq!(entry.registers.rsp, self.baseline.initial.rsp);
        assert_eq!(
            u64::from_le_bytes(entry.application_stack[128..136].try_into().unwrap()),
            terminal.logical_pc
        );
        let returns: Vec<_> = points
            .iter()
            .filter(|p| p.logical_pc == e.chosen_return)
            .collect();
        assert_eq!(returns.len(), 1, "exact chosen RET");
        assert_eq!(
            returns[0].registers.rax, e.answer,
            "independent scalar answer"
        );
        assert_eq!(terminal.registers.rax, e.answer);
        assert_eq!(terminal.registers.rsp, entry.registers.rsp + 8);
        for point in &points[entry_index..] {
            assert_eq!(point.data, entry.data, "read-only leaf data");
            assert_eq!(
                point.application_stack, entry.application_stack,
                "leaf stack and red zone"
            );
            if point.logical_pc != terminal.logical_pc {
                assert_eq!(point.registers.rsp, entry.registers.rsp);
            }
        }
        let read_pc = e.entry + if e.uppercase { 16 } else { 25 };
        let opcode: &[u8] = if e.uppercase {
            &[0x0f, 0xb6, 0x07]
        } else {
            &[0x80, 0x3c, 0x17, 0x3d]
        };
        let at = (read_pc - self.source_base) as usize;
        assert_eq!(&self.original_code[at..at + opcode.len()], opcode);
        let reads: Vec<_> = points.iter().filter(|p| p.logical_pc == read_pc).collect();
        assert_eq!(reads.len(), e.read_indices.len());
        for (point, &index) in reads.iter().zip(e.read_indices) {
            assert!(index < e.input.len());
            let address = if e.uppercase {
                point.registers.rdi
            } else {
                point
                    .registers
                    .rdi
                    .checked_add(point.registers.rdx)
                    .unwrap()
            };
            assert_eq!(address, base + index as u64, "exact bounded read address");
            assert_eq!(point.data[index], e.input[index]);
        }
        if e.uppercase {
            let adc: Vec<_> = points
                .iter()
                .filter(|p| p.logical_pc == e.entry + 24)
                .collect();
            let after: Vec<_> = points
                .iter()
                .filter(|p| p.logical_pc == e.entry + 28)
                .collect();
            assert_eq!(adc.len(), e.input.len());
            assert_eq!(after.len(), e.input.len());
            let mut count = 0;
            for ((before, after), &byte) in adc.iter().zip(after).zip(e.input) {
                let carry = u64::from(byte.is_ascii_uppercase());
                assert_eq!(before.registers.eflags & 1, carry);
                assert_eq!(before.registers.r8, count);
                count += carry;
                assert_eq!(after.registers.r8, count);
            }
            assert_eq!(count, e.answer);
        }
    }
}
