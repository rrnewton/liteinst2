//! Source/emission checks. Native execution lives in the software-clock oracle.
use super::*;
use crate::backedge_clock::{BackedgeClock, BackedgeClockRegion, ClockMode};
use crate::contracts::{CodeIdentity, SourceIdentity};
use crate::controls::ControlIdentity;
use crate::scanner::InstructionScanner;

// Independent authored 3-by-4 register loop: 15 branch encounters, 11 taken.
const SOURCE: &[u8] = &[
    0xb8, 0, 0, 0, 0, // EAX = 0
    0x41, 0xb8, 3, 0, 0, 0, // R8D = 3
    0xb9, 4, 0, 0, 0, // ECX = 4 (outer target)
    0xff, 0xc0, // INC EAX (inner target)
    0xff, 0xc9, // DEC ECX
    0x0f, 0x85, 0xf6, 0xff, 0xff, 0xff, // JNZ inner
    0x41, 0xff, 0xc8, // DEC R8D
    0x0f, 0x85, 0xe8, 0xff, 0xff, 0xff, // JNZ outer
    0xc3,
];
const HEADS: &[u64] = &[0, 5, 11, 16, 18, 20, 26, 29, 35];
const SITES: &[u64] = &[20, 29];

unsafe extern "C" fn callback(_: *mut HookContext, _: ControlIdentity<'_>) {}

fn fixture(mode: ClockMode) -> (BackedgeClockRegion, ScanResult) {
    // One kernel-chosen private data page. Source/emission addresses are only
    // encoder coordinates, never requested fixed-address mappings or executed.
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    // SAFETY: exclusive exact page ownership transfers to this clock.
    let clock = unsafe { BackedgeClock::from_owned_mapping(page as usize as u64, 4096) }.unwrap();
    let base = clock.address() + 0x10000;
    let managed = [20, 29].map(|offset| {
        let (control, writer) = ProbeControl::new_managed_bound(callback, true);
        (base + offset, control, writer)
    });
    let region = BackedgeClockRegion::new_owned_region(
        CodeIdentity {
            source: SourceIdentity([0x73; 32]),
            mapping: base,
            generation: 1,
        },
        base,
        SOURCE,
        managed,
        clock,
        mode,
    )
    .unwrap();
    let scan = InstructionScanner::default().scan(SOURCE, base).unwrap();
    (region, scan)
}

#[test]
fn two_clock_gates_are_keyed_to_exact_source_heads_and_share_one_owner() {
    for mode in [ClockMode::Counter, ClockMode::Stop] {
        let (region, scan) = fixture(mode);
        let base = region.actions[0].base;
        let image = TrampolinePlan::from_owned_clock_region(&scan, &region)
            .unwrap()
            .emit_at(base + 0x10000)
            .unwrap();
        assert_eq!(image.clock_gate(), None);
        assert_eq!(image.clock(), Some(region.clock()));
        assert_eq!(image.controls().len(), 2);
        assert_ne!(image.controls()[0], image.controls()[1]);
        assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
        assert_eq!(image.layout().return_len, 5);
        assert_eq!(image.entry_routes().len(), HEADS.len());
        assert_eq!(image.instruction_boundaries().len(), HEADS.len());
        assert_eq!(image.program_counter_mappings().len(), HEADS.len() + 1);
        let gates = image.clock_region_gates();
        assert_eq!(gates.len(), 2);
        for (index, (&site, keyed)) in SITES.iter().zip(gates).enumerate() {
            assert_eq!(keyed.logical_pc, base + site);
            assert_eq!(image.controls()[index], region.actions[index].control);
            let gate = keyed.gate;
            assert_eq!(
                gate.entry,
                image
                    .entry_routes()
                    .iter()
                    .find(|x| x.0 == base + site)
                    .unwrap()
                    .1
            );
            assert_eq!(
                gate.original_body,
                image
                    .instruction_boundaries()
                    .iter()
                    .find(|x| x.0 == base + site)
                    .unwrap()
                    .1
            );
            assert!(image.address() < gate.entry);
            assert!(gate.entry < gate.observing_entry && gate.observing_entry < gate.original_body);
            let start = (gate.entry - image.address()) as usize;
            let end = (gate.observing_entry - image.address()) as usize;
            let instructions: Vec<_> = Decoder::with_ip(
                64,
                &image.bytes()[start..end],
                gate.entry,
                DecoderOptions::NONE,
            )
            .into_iter()
            .collect();
            assert_eq!(
                instructions
                    .iter()
                    .filter(|i| i.code() == Code::Jrcxz_rel8_64)
                    .count(),
                usize::from(mode == ClockMode::Stop)
            );
            for instruction in instructions {
                assert!(!instruction.is_invalid());
                assert_eq!(instruction.rflags_modified(), 0);
                assert!(matches!(
                    instruction.mnemonic(),
                    Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Je | Mnemonic::Jrcxz | Mnemonic::Jmp
                ));
                if instruction.is_ip_rel_memory_operand() {
                    assert!(
                        [0, 8, 16, 24]
                            .iter()
                            .any(|offset| instruction.ip_rel_memory_address()
                                == region.clock().address() + offset)
                    );
                }
            }
        }
        for (index, &head) in HEADS.iter().enumerate() {
            let (logical_pc, entry) = image.entry_routes()[index];
            let (body_pc, body) = image.instruction_boundaries()[index];
            assert_eq!(logical_pc, base + head);
            assert_eq!(body_pc, logical_pc);
            assert_eq!(entry == body, !SITES.contains(&head));
            let next = image
                .entry_routes()
                .get(index + 1)
                .map_or(image.address() + image.bytes().len() as u64 - 5, |x| x.1);
            let bytes = &image.bytes()
                [(body - image.address()) as usize..(next - image.address()) as usize];
            let original = scan.instructions()[index].instruction();
            let decoded = Decoder::with_ip(64, bytes, body, DecoderOptions::NONE).decode();
            assert_eq!(decoded.code(), original.code());
            assert_eq!(decoded.next_ip(), next);
            if SITES.contains(&head) {
                let target = if head == 20 { 16 } else { 11 };
                assert_eq!(
                    decoded.near_branch_target(),
                    image
                        .entry_routes()
                        .iter()
                        .find(|x| x.0 == base + target)
                        .unwrap()
                        .1
                );
            } else {
                assert_eq!(
                    bytes,
                    &SOURCE[head as usize..head as usize + original.len()]
                );
            }
        }
    }
}

#[test]
fn region_emission_refuses_malformed_bindings_and_unreachable_clock() {
    let (region, scan) = fixture(ClockMode::Stop);
    let base = region.actions[0].base;
    let plan = TrampolinePlan::from_owned_clock_region(&scan, &region).unwrap();
    assert!(plan.emit_at(base + 0x10000).is_ok());
    assert!(plan.emit_at(base + 3 * 1024 * 1024 * 1024).is_err());
    assert!(plan.emit_with_frame_trace_at(base + 0x10000).is_err());
    for mutation in 0..7 {
        let mut invalid = region.clone();
        match mutation {
            0 => invalid.actions[1].logical_pc = invalid.actions[0].logical_pc,
            1 => invalid.actions[1].identity.generation += 1,
            2 => invalid.actions[1].base += 1,
            3 => invalid.actions[1].source[0] ^= 1,
            4 => invalid.actions[1].mode = ClockMode::Counter,
            5 => invalid.actions[1].condition = Some(2),
            6 => invalid.actions[1].control = invalid.actions[0].control.clone(),
            _ => unreachable!(),
        }
        assert!(
            TrampolinePlan::from_owned_clock_region(&scan, &invalid).is_err(),
            "mutation {mutation}"
        );
    }
}
