// Additive observations for the finite ADC campaign; captures, seeding and the
// full-state comparator remain unchanged. This exposes no mutable snapshot.

impl NativeTrace {
    pub fn assert_adc_boundary_state(
        &self,
        input_pc: u64,
        output_pc: u64,
        destination_is_r8: bool,
        incoming_carry: bool,
        expected_destination: u64,
        expected_arithmetic_flags: u64,
    ) {
        const ARITHMETIC_FLAGS: u64 = 0x8d5; // OF,SF,ZF,AF,PF,CF, all defined.
        assert_eq!(expected_arithmetic_flags & !ARITHMETIC_FLAGS, 0);
        let point = |pc| {
            let mut points = self
                .baseline
                .points
                .iter()
                .filter(|point| point.logical_pc == pc);
            let point = points.next().expect("ADC boundary was not observed");
            assert!(
                points.next().is_none(),
                "ADC boundary was observed repeatedly"
            );
            (
                point.registers.rax,
                point.registers.r8,
                point.registers.eflags,
            )
        };
        let before = point(input_pc);
        let after = point(output_pc);
        assert_eq!(
            before.2 & 1,
            u64::from(incoming_carry),
            "ADC input CF was not forced"
        );
        assert_eq!(
            if destination_is_r8 { after.1 } else { after.0 },
            expected_destination
        );
        assert_eq!(after.2 & ARITHMETIC_FLAGS, expected_arithmetic_flags);
        assert_eq!(
            after.2 & !(ARITHMETIC_FLAGS | DEBUGGER_FLAGS),
            before.2 & !(ARITHMETIC_FLAGS | DEBUGGER_FLAGS),
            "ADC changed a non-arithmetic architectural flag"
        );
    }
}
