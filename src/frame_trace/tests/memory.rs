//! Byte-memory equivalence only; no emitted helper or native subject executes.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

// Independent old byte-index implementation, deliberately not a range walk.
fn reference_load(memory: &BTreeMap<u64, u8>, address: u64) -> u64 {
    u64::from_le_bytes(core::array::from_fn(|index| {
        memory[&(address + index as u64)]
    }))
}

fn reference_store(memory: &mut BTreeMap<u64, u8>, address: u64, value: u64, bytes: usize) {
    for (index, byte) in value.to_le_bytes().into_iter().take(bytes).enumerate() {
        memory.insert(address + index as u64, byte);
    }
}

fn same_load(machine: &Machine, reference: &BTreeMap<u64, u8>, address: u64) {
    let actual = catch_unwind(|| machine.load(address));
    let expected = catch_unwind(|| reference_load(reference, address));
    assert_eq!(actual.is_err(), expected.is_err(), "address {address:#x}");
    if let Ok(value) = expected {
        assert_eq!(actual.unwrap(), value, "address {address:#x}");
    }
    assert_eq!(&machine.memory, reference);
}

#[test]
fn aligned_word_loads_match_byte_reference_for_every_initialization_mask() {
    let mut zero = Machine::new(5);
    let mut reference = BTreeMap::new();
    zero.store(0, 0, 8);
    reference_store(&mut reference, 0, 0, 8);
    same_load(&zero, &reference, 0);
    assert_eq!(zero.load(0), 0);
    for base in [0_u64, 16, u64::MAX - 7] {
        for mask in 0_u16..=255 {
            let mut machine = Machine::new(7);
            let mut reference = BTreeMap::new();
            // A later byte must not fill a gap merely because it is next in order.
            if base < u64::MAX - 7 {
                machine.memory.insert(base + 16, 0xee);
                reference.insert(base + 16, 0xee);
            }
            for offset in 0_u64..8 {
                if mask & (1 << offset) != 0 {
                    let byte = (offset as u8).wrapping_mul(37).wrapping_add(0x10);
                    machine.memory.insert(base + offset, byte);
                    reference.insert(base + offset, byte);
                }
            }
            same_load(&machine, &reference, base);
            assert_eq!(
                reference.len(),
                mask.count_ones() as usize + if base < u64::MAX - 7 { 1 } else { 0 }
            );
            assert_eq!(catch_unwind(|| machine.load(base)).is_ok(), mask == 255);
        }
    }
}

#[test]
fn unaligned_and_overlapping_stores_match_byte_reference() {
    for offset in 0_u64..8 {
        for width in [0_usize, 1, 4, 7, 8, 9] {
            let mut machine = Machine::new(9);
            let mut reference = BTreeMap::new();
            for address in 0_u64..48 {
                let byte = (address as u8).wrapping_mul(13);
                machine.memory.insert(address, byte);
                reference.insert(address, byte);
            }
            for (address, value, bytes) in [
                (16, 0x0123_4567_89ab_cdef, 8),
                (16 + offset, 0xfedc_ba98_7654_3210, width),
                (23, 0x5566_7788_1122_3344, 4),
                (20, 0xa1b2_c3d4_e5f6_0708, 8),
            ] {
                machine.store(address, value, bytes);
                reference_store(&mut reference, address, value, bytes);
                assert_eq!(machine.memory, reference);
                for start in 8..=32 {
                    same_load(&machine, &reference, start);
                }
            }
        }
    }
    // A four-byte store must not initialize its untouched upper four bytes.
    let mut machine = Machine::new(11);
    let mut reference = BTreeMap::new();
    machine.store(16, u64::MAX, 4);
    reference_store(&mut reference, 16, u64::MAX, 4);
    same_load(&machine, &reference, 16);
    assert!(catch_unwind(|| machine.load(16)).is_err());
    machine.store(20, 0x1234_5678, 4);
    reference_store(&mut reference, 20, 0x1234_5678, 4);
    same_load(&machine, &reference, 16);
    assert_eq!(machine.load(16), 0x1234_5678_ffff_ffff);
}

#[test]
fn byte_map_access_and_extension_preserve_missing_keys() {
    let mut machine = Machine::new(13);
    let mut reference = BTreeMap::new();
    for (address, byte) in [(16, 1), (23, 2), (16, 3), (19, 4)] {
        assert_eq!(
            machine.memory.insert(address, byte),
            reference.insert(address, byte)
        );
    }
    let extension = [(18, 5), (17, 6), (20, 7), (21, 8), (22, 9), (18, 10)];
    machine.memory.extend(extension);
    for (address, byte) in extension {
        reference.insert(address, byte);
    }
    assert_eq!(
        machine.memory.keys().copied().collect::<Vec<_>>(),
        reference.keys().copied().collect::<Vec<_>>()
    );
    for address in 8..=31 {
        assert_eq!(machine.memory.get(&address), reference.get(&address));
        let actual = catch_unwind(|| machine.memory[&address]);
        let expected = catch_unwind(|| reference[&address]);
        assert_eq!(actual.is_err(), expected.is_err());
        if let Ok(byte) = expected {
            assert_eq!(actual.unwrap(), byte);
        }
        same_load(&machine, &reference, address);
    }
    assert_eq!(machine.load(16).to_le_bytes(), [3, 6, 10, 4, 7, 8, 9, 2]);
}

#[test]
fn word_load_edges_preserve_reference_success_and_refusal() {
    let mut machine = Machine::new(15);
    let mut reference = BTreeMap::new();
    for address in (0_u64..16).chain(u64::MAX - 15..=u64::MAX) {
        let byte = (address ^ 0x5a) as u8;
        machine.memory.insert(address, byte);
        reference.insert(address, byte);
    }
    for address in (0_u64..=9).chain(u64::MAX - 15..=u64::MAX) {
        // Overflow behavior on the unaligned fallback remains the original
        // Rust addition behavior, including builds with overflow checks off.
        same_load(&machine, &reference, address);
    }
    assert_eq!(
        machine.load(u64::MAX - 7),
        reference_load(&reference, u64::MAX - 7)
    );
    let actual = catch_unwind(AssertUnwindSafe(|| {
        machine.store(u64::MAX - 2, 0x1234_5678_9abc_def0, 8)
    }));
    let expected = catch_unwind(AssertUnwindSafe(|| {
        reference_store(&mut reference, u64::MAX - 2, 0x1234_5678_9abc_def0, 8)
    }));
    assert_eq!(actual.is_err(), expected.is_err());
    // Match partial writes before an overflow panic as well as wrapping builds.
    assert_eq!(machine.memory, reference);
    same_load(&machine, &reference, 0);
    same_load(&machine, &reference, u64::MAX - 7);
}
