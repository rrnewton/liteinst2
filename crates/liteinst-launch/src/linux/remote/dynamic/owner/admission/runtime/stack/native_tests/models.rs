//! Copied-real-data sensitivity only. No model constructs an acquisition stamp
//! or completion, changes a live owner, or counts as a hardware fault.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_stack::{
    access::validate_state,
    metadata::validate_smaps,
    operand::{OperandGeometry, validate_effect},
};

fn replace_once(bytes: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let matches = bytes
        .windows(old.len())
        .enumerate()
        .filter(|(_, v)| *v == old)
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
    let start = matches[0];
    let mut out = bytes[..start].to_vec();
    out.extend_from_slice(new);
    out.extend_from_slice(&bytes[start + old.len()..]);
    out
}
pub(super) fn sensitivity(owner: &Owner, ordinal: usize) {
    let runtime = owner.runtime.as_ref().unwrap();
    let stack = runtime.stack.as_ref().unwrap();
    let attempt = stack.attempts[ordinal].as_ref().unwrap();
    let native = attempt.native.diagnostics();
    let initial = stack.profile.identity().unwrap();
    let operand = attempt.operand.operand().unwrap();
    // These private helpers change only owned copies and compare them with the
    // same typed Eq used by retention; actual census and ledger stay unchanged.
    runtime
        .census
        .as_ref()
        .unwrap()
        .test_stack_snapshot_sensitivity();
    stack.calls.test_row_sensitivity(native.call_id.unwrap());
    let description = operand.description();
    let geometry = &description.geometry;
    let a = attempt.operand.view();
    let c = native.words[1];
    assert_eq!(
        validate_effect(
            &native.states[0].state,
            &native.states[4].state,
            description,
            &a.word.bytes,
            &c.word.bytes
        ),
        Ok(())
    );
    macro_rules! registers {($($field:ident),* $(,)?)=>{$(
        {let mut changed=native.states[4].state.clone();changed.registers.$field^=1;
         assert!(validate_effect(&native.states[0].state,&changed,description,&a.word.bytes,&c.word.bytes).is_err(),stringify!($field));}
    )*};}
    registers!(
        r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs,
        eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs
    );
    let mut changed = native.states[4].state.clone();
    changed.mask ^= 1;
    assert!(
        validate_effect(
            &native.states[0].state,
            &changed,
            description,
            &a.word.bytes,
            &c.word.bytes
        )
        .is_err()
    );
    for index in 0..native.states[4].state.xstate.len() {
        let mut changed = native.states[4].state.clone();
        changed.xstate[index] ^= 1;
        assert!(
            validate_effect(
                &native.states[0].state,
                &changed,
                description,
                &a.word.bytes,
                &c.word.bytes
            )
            .is_err()
        );
    }
    for case in 0..6 {
        let mut changed = description.clone();
        match case {
            0 => changed.target ^= 1,
            1 => changed.geometry.next_pc += 1,
            2 => changed.geometry.slot.start += 1,
            3 => changed.geometry.envelope.end += 8,
            4 => changed.geometry.stack.end = changed.geometry.slot.start,
            _ => changed.geometry.island = changed.target & !4095..(changed.target & !4095) + 4096,
        }
        assert!(
            validate_effect(
                &native.states[0].state,
                &native.states[4].state,
                &changed,
                &a.word.bytes,
                &c.word.bytes
            )
            .is_err()
        );
    }
    for index in 0..16 {
        let mut changed = *c.word;
        changed.bytes[index] ^= 1;
        assert!(
            validate_effect(
                &native.states[0].state,
                &native.states[4].state,
                description,
                &a.word.bytes,
                &changed.bytes
            )
            .is_err()
        );
    }
    for index in 0..a.word.pagemap.copied / 8 {
        for bit in [63, 56, 62, 61, 60, 59, 58, 57] {
            let mut changed = a.word.pagemap;
            changed.bytes[index * 8 + bit / 8] ^= 1 << (bit % 8);
            assert!(changed.validate(&geometry.envelope).is_err());
        }
    }
    for case in 0..8 {
        let mut changed = *a.word;
        match case {
            0 => changed.complete = false,
            1 => changed.copied -= 1,
            2 => changed.peek[0] = None,
            3 => changed.peek[0].as_mut().unwrap().address += 8,
            4 => changed.peek[0].as_mut().unwrap().request.errno = Some(libc::EIO),
            5 => changed.pagemap.offset += 8,
            6 => changed.pagemap.copied -= 1,
            _ => changed.pagemap.fd = -1,
        }
        assert!(changed.validate(geometry).is_err());
    }
    let raw = *initial.layout_evidence();
    let layout = raw.validate().unwrap();
    for index in 0..5 {
        let mut changed = raw;
        changed.records[index] = None;
        assert!(changed.validate().is_err());
        let mut changed = raw;
        changed.records[index].as_mut().unwrap().subleaf ^= 1;
        assert!(changed.validate().is_err());
    }
    for case in 0..8 {
        let mut changed = raw;
        match case {
            0 => changed.records[0].as_mut().unwrap().registers[0] = 12,
            1 => changed.records[1].as_mut().unwrap().registers[2] &= !(1 << 26),
            2 => changed.records[1].as_mut().unwrap().registers[2] &= !(1 << 27),
            3 => changed.records[2].as_mut().unwrap().registers[2] &= !(1 << 3),
            4 => changed.records[2].as_mut().unwrap().registers[2] &= !(1 << 4),
            5 => changed.records[3].as_mut().unwrap().registers[0] &= !(1 << 9),
            6 => changed.records[4].as_mut().unwrap().registers[0] = 16,
            _ => changed.records[4].as_mut().unwrap().registers[2] |= 1,
        }
        assert!(changed.validate().is_err());
    }
    for case in 0..21 {
        // The copied diagnostic has its own real allocation; pointer fields
        // are first bound to that copy, then exactly one predicate is broken.
        let mut changed = StateSlot::allocate().unwrap();
        changed.state = native.states[0].state.clone();
        let mut exact = Vec::with_capacity(MAX_XSTATE);
        exact.extend_from_slice(&changed.state.xstate);
        assert_eq!(exact.capacity(), MAX_XSTATE);
        changed.state.xstate = exact;
        changed.complete = true;
        changed.registers_request = Some(NativeRequest {
            result: 0,
            errno: None,
        });
        changed.xstate_request = changed.registers_request;
        changed.mask_request = changed.registers_request;
        changed.requested_pointer = changed.state.xstate.as_ptr() as usize;
        changed.returned_pointer = changed.requested_pointer;
        changed.returned_length = changed.state.xstate.len();
        assert!(validate_state(&changed, layout).is_ok());
        let pkru = raw.records[4].unwrap().registers[1] as usize;
        match case {
            0 => changed.complete = false,
            1 => changed.registers_request = None,
            2 => changed.xstate_request.as_mut().unwrap().result = -1,
            3 => changed.mask_request.as_mut().unwrap().errno = Some(libc::EIO),
            4 => changed.requested_pointer += 8,
            5 => changed.returned_pointer += 8,
            6 => changed.returned_length -= 8,
            7 => changed.state.xstate[465] &= !2,
            8 => changed.state.xstate[513] &= !2,
            9 => changed.state.xstate[520] = 1,
            10 => changed.state.xstate[528] = 1,
            11 => changed.state.xstate[pkru] |= 1,
            12 => changed.state.xstate[pkru + 4] = 1,
            13 => changed.state.registers.eflags |= 1 << 18,
            14 => changed.state.registers.cs = 0x23,
            15 => changed.state.registers.eflags |= 1 << 8,
            16 => changed.state.registers.eflags |= 1 << 16,
            17 => changed.state.registers.eflags |= 1 << 17,
            18 => changed.state.registers.ss = 0x23,
            19 => {
                changed.state.xstate.truncate(576);
                changed.returned_length = 576;
            }
            _ => changed.state.xstate[pkru] |= 2,
        }
        assert!(validate_state(&changed, layout).is_err());
    }
    let encoding = &geometry.encoding[..geometry.length];
    assert_eq!(
        OperandGeometry::derive(
            geometry.pc,
            encoding,
            geometry.original_rsp,
            &geometry.stack,
            &geometry.island
        )
        .unwrap(),
        *geometry
    );
    for code in [
        &[0x66, 0xe8, 0, 0, 0, 0][..],
        &[0xf3, 0xc3][..],
        &[0xff, 0xd0][..],
        &[0xff, 0x10][..],
        &[0xc2, 8, 0][..],
        &[0xcb][..],
    ] {
        assert!(
            OperandGeometry::derive(
                geometry.pc,
                code,
                geometry.original_rsp,
                &geometry.stack,
                &geometry.island
            )
            .is_err()
        );
    }
    for pc in [
        0,
        4095,
        (1_u64 << 47) - 4,
        1_u64 << 47,
        u64::MAX - 4,
        0xffffffffff600000,
    ] {
        assert!(
            OperandGeometry::derive(
                pc,
                encoding,
                geometry.original_rsp,
                &geometry.stack,
                &geometry.island
            )
            .is_err()
        );
    }
    for rsp in [
        0,
        geometry.stack.start,
        geometry.stack.start + 4,
        geometry.stack.end + 8,
        1_u64 << 47,
    ] {
        assert!(
            OperandGeometry::derive(
                geometry.pc,
                encoding,
                rsp,
                &geometry.stack,
                &geometry.island
            )
            .is_err()
        );
    }
    for address in [geometry.pc, geometry.next_pc, description.target] {
        let private = address..address + 4096;
        assert!(
            OperandGeometry::derive(
                geometry.pc,
                encoding,
                geometry.original_rsp,
                &geometry.stack,
                &private
            )
            .is_err()
        );
    }
    let mut zero = [0xe8, 0, 0, 0, 0];
    zero[1..].copy_from_slice(
        &i32::try_from(-(geometry.next_pc as i64))
            .unwrap()
            .to_le_bytes(),
    );
    assert!(
        OperandGeometry::derive(
            geometry.pc,
            &zero,
            geometry.original_rsp,
            &geometry.stack,
            &geometry.island
        )
        .is_err()
    );
    // RET target comes from the actual word. These copied descriptions are
    // rejected as values; no constructor authenticates a hardware observation.
    for target in [
        0,
        4095,
        1_u64 << 47,
        u64::MAX,
        0xffffffffff600000,
        geometry.island.start,
    ] {
        let mut changed = description.clone();
        changed.target = target;
        assert!(
            validate_effect(
                &native.states[0].state,
                &native.states[4].state,
                &changed,
                &a.word.bytes,
                &c.word.bytes
            )
            .is_err()
        );
    }
    let descriptor = initial.description().stack;
    let original = runtime.sources.original_maps();
    let original = &original.0[..original.1.copied_bytes];
    let baseline = a
        .observation
        .maps_capture
        .bytes(&a.observation.maps)
        .unwrap();
    let smaps = a
        .observation
        .smaps_capture
        .bytes(&a.observation.smaps)
        .unwrap();
    let index = descriptor.require_current(original, baseline).unwrap();
    assert!(validate_smaps(smaps, baseline, index).is_ok());
    let target = rows(baseline)[index].raw.clone();
    // All changed map rows remain independent model text; none is used as a
    // native map observation. Missing/extra/alias/path/offset/perms refuse.
    for case in 0..12 {
        let mut row = target.clone();
        let first = row.iter().position(|b| *b == b' ').unwrap();
        match case {
            0 => row[first + 1] = b'-',
            1 => row[first + 2] = b'-',
            2 => row[first + 3] = b'x',
            3 => row[first + 4] = b's',
            4 => row[first + 6 + 7] = b'1',
            5 => row.extend_from_slice(b" changed"),
            6 => row[0] ^= 1,
            7 => {
                row.extend_from_slice(b"\n");
                row.extend_from_slice(&target);
            }
            8 => row.clear(),
            9 => {
                let device =
                    first + 6 + row[first + 6..].iter().position(|b| *b == b' ').unwrap() + 1;
                row[device] ^= 1;
            }
            10 => {
                let offset_end =
                    first + 6 + row[first + 6..].iter().position(|b| *b == b' ').unwrap();
                let device_end = offset_end
                    + 1
                    + row[offset_end + 1..]
                        .iter()
                        .position(|b| *b == b' ')
                        .unwrap();
                let inode = device_end + 1;
                assert_eq!(row[inode], b'0');
                row[inode] = b'1';
            }
            _ => {
                let hyphen = row.iter().position(|b| *b == b'-').unwrap();
                row[hyphen + 1] ^= 1;
            }
        }

        let changed = replace_once(baseline, &target, &row);
        assert!(descriptor.require_current(original, &changed).is_err());
    }
    let mut smap_rows = Vec::new();
    let mut current = usize::MAX;
    for line in smaps.split_inclusive(|b| *b == b'\n') {
        let space = line.iter().position(|b| *b == b' ').unwrap_or(line.len());
        if !line[..space].contains(&b':') {
            current = if current == usize::MAX {
                0
            } else {
                current + 1
            };
        }
        if current == index {
            smap_rows.push(line.to_vec());
        }
    }
    let key = smap_rows
        .iter()
        .find(|line| line.starts_with(b"ProtectionKey:"))
        .unwrap();
    let flags = smap_rows
        .iter()
        .find(|line| line.starts_with(b"VmFlags:"))
        .unwrap();
    let block = smap_rows.concat();
    for replacement in [
        b"".to_vec(),
        [key.as_slice(), key.as_slice()].concat(),
        b"ProtectionKey: 1\n".to_vec(),
    ] {
        let changed = replace_once(&block, key, &replacement);
        let changed = replace_once(smaps, &block, &changed);
        assert!(validate_smaps(&changed, baseline, index).is_err());
    }
    for replacement in [
        b"".to_vec(),
        [flags.as_slice(), flags.as_slice()].concat(),
        b"VmFlags: rd wr mr mw me gd\n".to_vec(),
        b"VmFlags: rd wr mr mw me gd ac dd\n".to_vec(),
        b"VmFlags: rd wr mr mw me gd ac ac\n".to_vec(),
    ] {
        let changed = replace_once(&block, flags, &replacement);
        let changed = replace_once(smaps, &block, &changed);
        assert!(validate_smaps(&changed, baseline, index).is_err());
    }
}
