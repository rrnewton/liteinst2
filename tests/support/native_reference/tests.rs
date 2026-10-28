use super::*;

fn refuses(f: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(std::panic::catch_unwind(f).is_err());
}
fn snapshot(pc: u64) -> Snapshot {
    let mut registers: libc::user_regs_struct = unsafe { core::mem::zeroed() };
    registers.rip = pc;
    registers.rsp = 0x7fe0;
    registers.rax = 0xaabb_ccdd_0102_0304;
    registers.rcx = 0x1234_5678_8765_4321;
    registers.rdx = 0x9abc_def0_0123_4567;
    registers.eflags = 0xed7;
    Snapshot {
        logical_pc: pc,
        registers,
        xstate: vec![0x35; 832],
        data: vec![0x9a; PAGE],
        application_stack: vec![0x5a; 168],
    }
}
fn witness() -> Witness {
    let mut expected = [0; WORDS];
    expected[..9].copy_from_slice(&[1, 1, 0x700, 77, 77, 0x2000, 0x1065, 91, 2]);
    expected[21] = CANARY;
    Witness {
        cell: 0x4000,
        frame: 0x5000,
        expected,
        gate: 0x1000,
        s: 0x8008,
        previous: None,
        before_start: None,
        before_end: None,
        outputs: [None; 2],
        checks: 0,
        last_pc: 0,
        initial_callee: None,
        callee_checked: false,
    }
}
fn complete() -> Witness {
    let mut w = witness();
    let mut entry = snapshot(w.gate);
    entry.registers.rsp = w.s;
    w.observe_entry(&entry);
    let mut outer = copy_snapshot(&entry);
    outer.logical_pc = w.gate + OUTER_RET;
    outer.registers.rip = outer.logical_pc;
    w.check_callee_return(&outer);
    w.expected[0] = 2;
    w.expected[9..15].copy_from_slice(&[100, 1, 3, 200, 1, 3]);
    w.expected[18] = 123;
    w.outputs = [Some([100, 1, 3]), Some([200, 1, 3])];
    w.checks = 2;
    w.last_pc = w.gate + OUTER_RET;
    w
}

#[test]
fn reference_layout_requires_every_byte_and_actual_label() {
    let gate = 0x1000;
    let labels = [32, 98, 101, 105, 185, 194].map(|n| gate + n);
    check_layout(gate, labels, STENCIL);
    assert_eq!(HEADS.len(), 41);
    assert_eq!(
        HEADS
            .iter()
            .filter(|n| !transient(gate, gate + **n))
            .count(),
        18
    );
    for n in 0..STENCIL.len() {
        let mut bytes = STENCIL.to_vec();
        bytes[n] ^= 1;
        refuses(|| check_layout(gate, labels, &bytes));
    }
    for n in 0..labels.len() {
        let mut wrong = labels;
        wrong[n] += 1;
        refuses(|| check_layout(gate, wrong, STENCIL));
    }
    refuses(|| check_layout(gate, labels, GATE_BYTES));
}

#[test]
fn reference_profile_and_complete_ret_inventory_refuse_substitution() {
    let ready = || Ready {
        profile: Profile::Reference { external_id: 91 },
        entry: 0x2000,
        gate: 0x1000,
        continuation: 0x1065,
        heads: vec![0x2000, 0x2005],
        returns: vec![0x2005],
        boundaries: vec![(0x2000, 0x2000), (0x2005, 0x2005)],
        immutable: vec![(0x2000, vec![0x90; PAGE])],
        original_source: vec![0x90; PAGE],
    };
    ready().validate(false);
    same_ready(&ready(), &Ready::decode(&ready().encode()));
    let mut missing = ready();
    missing.boundaries.pop();
    refuses(|| {
        missing.validate(false);
    });
    let mut legacy = ready();
    legacy.profile = Profile::Legacy;
    refuses(|| {
        legacy.validate(false);
    });
    let mut other = ready();
    other.profile = Profile::Reference { external_id: 92 };
    refuses(|| same_ready(&ready(), &other));
    let mut bytes = ready().encode();
    bytes[..8].copy_from_slice(&2_u64.to_le_bytes());
    refuses(|| {
        Ready::decode(&bytes);
    });
}

#[test]
fn reference_reader_transparency_keeps_full_state_and_physical_pcs() {
    let before = snapshot(0x1020);
    let after = snapshot(0x1062);
    transparent(&before, &after, (0x1020, 0x1062));
    for mutation in 0..11 {
        let mut bad = copy_snapshot(&after);
        match mutation {
            0 => bad.registers.rax ^= 1 << 48,
            1 => bad.registers.rcx ^= 1 << 48,
            2 => bad.registers.rdx ^= 1 << 48,
            3 => bad.registers.rbx ^= 1,
            4 => bad.registers.r12 ^= 1,
            5 => bad.registers.rsp += 16,
            6 => bad.registers.eflags ^= 1 << 10,
            7 => bad.xstate[831] ^= 1,
            8 => bad.data[PAGE - 1] ^= 1,
            9 => bad.registers.rip += 1,
            _ => bad.logical_pc += 1,
        }
        refuses(|| transparent(&before, &bad, (0x1020, 0x1062)));
    }
    // Every one of the sixteen newly covered low stack bytes is material.
    for n in 0..16 {
        let mut bad = copy_snapshot(&after);
        bad.application_stack[n] ^= 1;
        refuses(|| transparent(&before, &bad, (0x1020, 0x1062)));
    }

    // Independent whole-gate callee-save check, before harness restoration.
    // Caller-saved results may differ, while every callee-save and RSP is exact.
    let mut entry = snapshot(0x1000);
    entry.registers.rsp = 0x8008;
    entry.registers.rbx = 11;
    entry.registers.rbp = 22;
    entry.registers.r12 = 33;
    entry.registers.r13 = 44;
    entry.registers.r14 = 55;
    entry.registers.r15 = 66;
    let mut outer = copy_snapshot(&entry);
    outer.logical_pc = 0x1000 + OUTER_RET;
    outer.registers.rip = outer.logical_pc;
    outer.registers.rax ^= 1;
    outer.registers.rcx ^= 1;
    outer.registers.rdx ^= 1;
    let mut valid = witness();
    valid.observe_entry(&entry);
    valid.check_callee_return(&outer);
    assert!(valid.callee_checked);
    for n in 0..7 {
        let mut bad = copy_snapshot(&outer);
        match n {
            0 => bad.registers.rbx ^= 1 << 48,
            1 => bad.registers.rbp ^= 1 << 48,
            2 => bad.registers.r12 ^= 1 << 48,
            3 => bad.registers.r13 ^= 1 << 48,
            4 => bad.registers.r14 ^= 1 << 48,
            5 => bad.registers.r15 ^= 1 << 48,
            _ => bad.registers.rsp += 16,
        }
        refuses(|| {
            let mut x = witness();
            x.observe_entry(&entry);
            x.check_callee_return(&bad);
        });
    }
    refuses(|| {
        witness().check_callee_return(&outer);
    });
    refuses(|| {
        let mut bad = copy_snapshot(&entry);
        bad.registers.rsp += 16;
        witness().observe_entry(&bad);
    });
    refuses(|| {
        let mut x = witness();
        x.observe_entry(&entry);
        x.observe_entry(&entry);
    });
    refuses(|| {
        let mut x = witness();
        x.observe_entry(&entry);
        x.check_callee_return(&outer);
        x.check_callee_return(&outer);
    });
    for physical in [true, false] {
        let mut bad = copy_snapshot(&outer);
        if physical {
            bad.registers.rip += 1;
        } else {
            bad.logical_pc += 1;
        }
        refuses(|| {
            let mut x = witness();
            x.observe_entry(&entry);
            x.check_callee_return(&bad);
        });
        let mut bad = copy_snapshot(&entry);
        if physical {
            bad.registers.rip += 1;
        } else {
            bad.logical_pc += 1;
        }
        refuses(|| {
            witness().observe_entry(&bad);
        });
    }
}

#[test]
fn reference_cell_cannot_alias_frame_data_stack_or_executable_ranges() {
    let ranges = [(0x1000, 0x1100), (0x2000, 0x3000), (0x7000, 0x9000)];
    independent_ranges(0x4000, 0x5000, &ranges);
    for cell in [0, 0x4001, 0x5000, 0x1ff8, 0x2000, 0x7000, u64::MAX - 7] {
        refuses(|| independent_ranges(cell, 0x5000, &ranges));
    }
    refuses(|| independent_ranges(0x4000, 0x7000, &ranges));
    assert_eq!(Profile::Legacy.entry_delta(), 16);
    assert_eq!(Profile::Reference { external_id: 1 }.entry_delta(), 32);
}

#[test]
fn reference_complete_cell_identity_spills_and_canary_are_material() {
    let expected = complete().expected;
    exact_cell(&expected, &expected);
    for n in 0..WORDS {
        let mut actual = expected;
        actual[n] ^= 1;
        refuses(|| exact_cell(&actual, &expected));
    }
}

#[test]
fn reference_stores_require_actual_unique_rdtscp_outputs() {
    let make = || {
        let mut point = snapshot(0x103b);
        point.registers.rax = 123;
        point.registers.rdx = 456;
        point.registers.rcx = 7;
        point
    };
    let mut w = witness();
    let point = make();
    w.transition(0x1038, snapshot(0x1038).registers, &point);
    assert_eq!(w.outputs[0], Some([123, 456, 7]));
    let mut store = snapshot(0x1043);
    store.registers.rax = 123;
    w.transition(0x103e, store.registers, &store);
    assert_eq!(w.expected[9], 123);
    refuses(|| {
        let mut x = witness();
        let p = make();
        x.transition(0x103e, p.registers, &p);
    });
    refuses(|| {
        let mut x = witness();
        let p = make();
        x.transition(0x1038, p.registers, &p);
        x.transition(0x1038, p.registers, &p);
    });
    refuses(|| {
        let mut x = witness();
        let p = make();
        x.transition(0x1038, p.registers, &p);
        let mut wrong = p.registers;
        wrong.rax += 1;
        x.transition(0x103e, wrong, &p);
    });
    refuses(|| {
        let mut x = witness();
        let mut p = make();
        p.registers.rax |= 1 << 40;
        x.transition(0x1038, p.registers, &p);
    });
    refuses(|| {
        let mut x = witness();
        let mut p = make();
        p.registers.rip += 1;
        x.transition(0x1038, p.registers, &p);
    });
}

#[test]
fn reference_result_requires_both_restorations_real_rax_and_leg() {
    let w = complete();
    let valid = w.record(123, Some(0x2005));
    check_record(&valid, &valid);
    refuses(|| {
        let mut x = complete();
        x.callee_checked = false;
        x.record(123, Some(0x2005));
    });
    refuses(|| {
        let mut x = complete();
        x.initial_callee = None;
        x.record(123, Some(0x2005));
    });
    refuses(|| {
        complete().record(124, Some(0x2005));
    });
    refuses(|| {
        complete().record(123, None);
    });
    refuses(|| {
        let mut x = complete();
        x.checks = 1;
        x.record(123, Some(0x2005));
    });
    refuses(|| {
        let mut x = complete();
        x.outputs[1] = None;
        x.record(123, Some(0x2005));
    });
    refuses(|| {
        let mut x = complete();
        x.expected[12] += 1;
        x.record(123, Some(0x2005));
    });
    refuses(|| {
        let mut x = complete();
        x.last_pc -= 1;
        x.record(123, Some(0x2005));
    });
    refuses(|| {
        let mut x = complete();
        x.expected[0] = 1;
        x.record(123, Some(0x2005));
    });
    for n in 0..RESULT_WORDS {
        let mut wrong = valid;
        wrong[n] ^= 1;
        refuses(|| check_record(&wrong, &valid));
    }
}

#[test]
fn reference_result_wire_rejects_clock_geometry_missing_duplicate_and_tail() {
    let valid = complete().record(123, Some(0x2005));
    let bytes: Vec<_> = valid.iter().flat_map(|n| n.to_le_bytes()).collect();
    assert_eq!(decode_record(&bytes), valid);
    refuses(|| {
        decode_record(&bytes[..bytes.len() - 1]);
    });
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&bytes);
    refuses(|| {
        decode_record(&duplicate);
    });
    let mut trailing = bytes.clone();
    trailing.push(0);
    refuses(|| {
        decode_record(&trailing);
    });
    for case in 0..5 {
        let mut wrong = valid;
        match case {
            0 => wrong[13] += 1,
            1 => wrong[12] = wrong[10] - 1,
            2 => wrong[11] |= 1 << 32,
            3 => {
                wrong[8] += 8;
                wrong[9] += 8;
                wrong[15] += 8;
            }
            _ => {
                wrong[0] = 1;
            }
        }
        refuses(|| check_record(&wrong, &wrong));
    }
}
