// Included only inside rapid::tests::live; all prior tests and helpers stay literal.
mod managed {
    use super::*;
    use crate::controls::{ControlIdentity, ControlWriter, ControlledAction, ProbeControl};
    use std::cell::{Cell, RefCell};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Event {
        callback: u8,
        pc: u64,
        expected_owner: bool,
        foreign_owner: bool,
    }

    type Owners = (ProbeControl, ProbeControl);
    thread_local! {
        static OWNERS: RefCell<Option<Owners>> = const { RefCell::new(None) };
        static EVENT: Cell<Option<Event>> = const { Cell::new(None) };
    }

    unsafe fn record(context: *mut HookContext, identity: ControlIdentity<'_>, callback: u8) {
        let (expected_owner, foreign_owner) = OWNERS.with(|owners| {
            let owners = owners.borrow();
            match owners.as_ref() {
                Some((expected, foreign)) => (
                    expected.has_identity(identity),
                    foreign.has_identity(identity),
                ),
                None => (false, false),
            }
        });
        // SAFETY: generated dispatch or this test's direct dispatch owns the frame.
        let pc = unsafe { (*context).instruction_pointer };
        EVENT.with(|event| {
            event.set(Some(Event {
                callback,
                pc,
                expected_owner,
                foreign_owner,
            }))
        });
    }

    unsafe extern "C" fn first(context: *mut HookContext, identity: ControlIdentity<'_>) {
        // SAFETY: same managed-dispatch frame and borrowed identity.
        unsafe { record(context, identity, 1) };
    }

    unsafe extern "C" fn second(context: *mut HookContext, identity: ControlIdentity<'_>) {
        // SAFETY: same managed-dispatch frame and borrowed identity.
        unsafe { record(context, identity, 2) };
    }

    fn take_event() -> Option<Event> {
        EVENT.with(|event| event.take())
    }

    fn controls() -> (ProbeControl, ControlWriter, ProbeControl, ControlWriter) {
        let (first, writer) = ProbeControl::new_managed_bound(first, true);
        let (second, other_writer) = ProbeControl::new_managed_bound(second, true);
        (first, writer, second, other_writer)
    }

    fn emitted_bytes(probe: &RapidProbe) -> &[u8] {
        // SAFETY: the installed probe retains its initialized immutable RX image.
        unsafe {
            core::slice::from_raw_parts(
                probe.trampoline().address() as *const u8,
                probe.trampoline().code_len(),
            )
        }
    }

    fn controlled_fixture(
        mapping: &DualMapping,
        control: &ProbeControl,
    ) -> (RapidTogglePlan, Placeholder, Vec<u8>, u32) {
        let (ordinary, placeholder, code, expected) = plan_fixture(mapping);
        let base = mapping.executable_address(SITE_OFFSET);
        let scanner = InstructionScanner::default();
        let scan = scanner.scan(&code, base).unwrap();
        let action = ControlledAction {
            logical_pc: base,
            control: control.clone(),
        };
        let plan =
            RapidTogglePlan::from_controlled_scan(&scanner, &scan, &code, base, base, &action)
                .unwrap();
        assert_eq!(plan.original_window(), ordinary.original_window());
        assert_eq!(plan.target_address(), ordinary.target_address());
        assert_eq!(plan.trampoline.return_address(), base + 5);
        (plan, placeholder, code, expected)
    }

    #[test]
    fn plan_and_image_retain_exact_managed_identity_and_callback() {
        let _guard = serial_guard();
        let base = 0x10_0000;
        // MOV EAX,0x12345678; RET: one complete five-byte observed instruction.
        let code = [0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3];
        let scanner = InstructionScanner::default();
        let scan = scanner.scan(&code, base).unwrap();
        let (control, writer, foreign, other_writer) = controls();
        let weak = control.downgrade();
        let foreign_weak = foreign.downgrade();
        let action = ControlledAction {
            logical_pc: base,
            control: control.clone(),
        };
        let foreign_action = ControlledAction {
            logical_pc: base,
            control: foreign.clone(),
        };
        let plan =
            RapidTogglePlan::from_controlled_scan(&scanner, &scan, &code, base, base, &action)
                .unwrap();
        let foreign_plan = RapidTogglePlan::from_controlled_scan(
            &scanner,
            &scan,
            &code,
            base,
            base,
            &foreign_action,
        )
        .unwrap();
        assert_eq!(plan.target_address(), 0x1244_567d);
        assert_eq!(plan.trampoline.return_address(), base + 5);
        let image = plan.trampoline.emit_at(plan.target_address()).unwrap();
        let foreign_image = foreign_plan
            .trampoline
            .emit_at(foreign_plan.target_address())
            .unwrap();
        assert_eq!(image.controls(), core::slice::from_ref(&control));
        assert_eq!(foreign_image.controls(), core::slice::from_ref(&foreign));
        assert_ne!(image.controls(), foreign_image.controls());
        let image_bytes = image.bytes().to_vec();

        OWNERS.with(|owners| *owners.borrow_mut() = Some((control.clone(), foreign.clone())));
        let mut context = HookContext::default();
        // SAFETY: the image retains the exact block and the local frame is exclusive.
        // This checks dispatch association; it does not execute emitted bytes.
        unsafe {
            crate::controls::dispatch(
                &mut context,
                image.controls()[0].block_address() as *const _,
            )
        };
        assert_eq!(
            take_event(),
            Some(Event {
                callback: 1,
                pc: 0,
                expected_owner: true,
                foreign_owner: false,
            })
        );
        // A second valid control at the same PC is a different caller-selected owner.
        unsafe {
            crate::controls::dispatch(
                &mut context,
                foreign_image.controls()[0].block_address() as *const _,
            )
        };
        assert_eq!(
            take_event(),
            Some(Event {
                callback: 2,
                pc: 0,
                expected_owner: false,
                foreign_owner: true,
            })
        );
        assert!(control.try_set_enabled(false).is_err());
        assert!(control.is_enabled());
        assert_eq!(image.bytes(), image_bytes);
        OWNERS.with(|owners| *owners.borrow_mut() = None);

        drop((writer, action, control, plan));
        assert_eq!(
            weak.strong_count(),
            1,
            "only the unallocated emitted image retains this control"
        );
        drop(image);
        assert!(weak.upgrade().is_none());
        drop((
            other_writer,
            foreign_action,
            foreign,
            foreign_plan,
            foreign_image,
        ));
        assert!(foreign_weak.upgrade().is_none());
    }

    #[test]
    fn controlled_planning_preserves_geometry_and_stale_byte_refusals() {
        let _guard = serial_guard();
        let base = 0x20_0000;
        struct Case {
            old: &'static [u8],
            now: &'static [u8],
            head: u64,
            kind: u8,
        }
        let cases = [
            Case {
                old: &[0xb8, 1, 0, 0, 0],
                now: &[0xb8, 2, 0, 0, 0],
                head: base,
                kind: 0,
            },
            Case {
                old: &[0x40, 0x05, 1, 0, 0, 0],
                now: &[0x42, 0x05, 1, 0, 0, 0],
                head: base,
                kind: 0,
            },
            Case {
                old: &[0x90; 5],
                now: &[0x90; 5],
                head: base,
                kind: 1,
            },
            Case {
                old: &[0xb8, 0, 0, 0, 0, 0xeb, 0xfa],
                now: &[0xb8, 0, 0, 0, 0, 0xeb, 0xfa],
                head: base,
                kind: 2,
            },
            Case {
                old: &[0xe9, 0, 0, 0, 0],
                now: &[0xe9, 0, 0, 0, 0],
                head: base,
                kind: 3,
            },
            Case {
                old: &[0xb8, 0, 0, 0, 0, 0xc3],
                now: &[0xb8, 0, 0, 0, 0, 0xc3],
                head: base + 5,
                kind: 4,
            },
        ];
        let scanner = InstructionScanner::default();
        let (control, _writer, _foreign, _other_writer) = controls();
        let weak = control.downgrade();
        for case in cases {
            let scan = scanner.scan(case.old, base).unwrap();
            let action = ControlledAction {
                logical_pc: case.head,
                control: control.clone(),
            };
            let owners = weak.strong_count();
            let error = RapidTogglePlan::from_controlled_scan(
                &scanner, &scan, case.now, base, base, &action,
            )
            .unwrap_err();
            match case.kind {
                0 => assert!(
                    matches!(error, RapidToggleError::RegionMismatch { address } if address == base)
                ),
                1 => assert!(
                    matches!(error, RapidToggleError::PatchWindowContainsInstructionHead { address, instruction_head } if address == base && instruction_head == base + 1)
                ),
                2 => assert!(
                    matches!(error, RapidToggleError::PatchWindowContainsBranchTarget { address, branch_address, target_address } if address == base && branch_address == base + 5 && target_address == base + 1)
                ),
                3 => assert!(
                    matches!(error, RapidToggleError::AlreadyNearJump { address } if address == base)
                ),
                4 => assert!(
                    matches!(error, RapidToggleError::Trampoline(TrampolineError::SiteNotFound { address }) if address == base + 5)
                ),
                _ => panic!("unexpected authored refusal case"),
            }
            assert_eq!(
                weak.strong_count(),
                owners,
                "refusal must not retain a hidden control"
            );
        }
    }

    #[test]
    fn managed_rapid_dispatch_changes_only_the_source_opcode() {
        let _guard = serial_guard();
        let (control, mut writer, foreign, mut other_writer) = controls();
        OWNERS.with(|owners| *owners.borrow_mut() = Some((control.clone(), foreign.clone())));
        assert_eq!(take_event(), None);
        let mapping = DualMapping::new();
        let (plan, placeholder, code, expected) = controlled_fixture(&mapping, &control);
        placeholder.release();
        // SAFETY: the unchanged fixture owns permanent exact RX/RW aliases and code.
        let probe =
            unsafe { RapidProbe::install(plan, mapping.writable_address(SITE_OFFSET)).unwrap() };
        let pc = mapping.executable_address(SITE_OFFSET);
        // SAFETY: exact MOV EAX,imm32; RET fixture and process-lifetime mappings.
        let function: unsafe extern "C" fn() -> u32 = unsafe { core::mem::transmute(pc as usize) };
        let image_bytes = emitted_bytes(&probe).to_vec();
        let mut active = code.clone();
        active[0] = NEAR_JUMP_OPCODE;
        assert_eq!(mapping.bytes(SITE_OFFSET, code.len()), code);
        assert_eq!(unsafe { function() }, expected);
        assert_eq!(take_event(), None);

        probe.enable();
        assert_eq!(mapping.bytes(SITE_OFFSET, code.len()), active);
        assert_eq!(mapping.bytes(SITE_OFFSET + 1, 4), &code[1..5]);
        assert_eq!(unsafe { function() }, expected);
        let wanted = Some(Event {
            callback: 1,
            pc,
            expected_owner: true,
            foreign_owner: false,
        });
        assert_eq!(take_event(), wanted);
        assert!(control.clone().try_set_enabled(false).is_err());
        other_writer.set_enabled(false);
        assert!(control.is_enabled());
        assert!(!foreign.is_enabled());
        assert_eq!(unsafe { function() }, expected);
        assert_eq!(take_event(), wanted);

        writer.set_enabled(false);
        assert_eq!(mapping.bytes(SITE_OFFSET, code.len()), active);
        assert_eq!(unsafe { function() }, expected);
        assert_eq!(
            take_event(),
            None,
            "disabled observing control must still execute MOV"
        );
        writer.set_enabled(true);
        assert_eq!(unsafe { function() }, expected);
        assert_eq!(take_event(), wanted);
        probe.disable();
        assert_eq!(mapping.bytes(SITE_OFFSET, code.len()), code);
        assert_eq!(unsafe { function() }, expected);
        assert_eq!(take_event(), None);
        assert_eq!(emitted_bytes(&probe), image_bytes);
        assert_eq!(probe.trampoline().address(), probe.plan().target_address());
        OWNERS.with(|owners| *owners.borrow_mut() = None);
    }

    #[test]
    fn controlled_install_refuses_each_changed_byte_and_an_owned_tail() {
        let _guard = serial_guard();
        let (control, _writer, _foreign, _other_writer) = controls();
        for changed_byte in 0..NEAR_JUMP_BYTES {
            let mapping = DualMapping::new();
            let (plan, placeholder, code, _) = controlled_fixture(&mapping, &control);
            let expected: [u8; NEAR_JUMP_BYTES] = code[..NEAR_JUMP_BYTES].try_into().unwrap();
            let mut changed = code.clone();
            changed[changed_byte] ^= 1;
            mapping.write(SITE_OFFSET, &changed);
            let observed: [u8; NEAR_JUMP_BYTES] = changed[..NEAR_JUMP_BYTES].try_into().unwrap();
            // SAFETY: live aliases; the stale preimage must refuse before allocation.
            let error =
                match unsafe { RapidProbe::install(plan, mapping.writable_address(SITE_OFFSET)) } {
                    Err(error) => error,
                    Ok(_) => panic!("changed byte {changed_byte} unexpectedly installed"),
                };
            if changed_byte == 0 {
                assert!(
                    matches!(error, RapidToggleError::ExpectedOpcodeMismatch { expected: a, observed: b } if a == expected[0] && b == observed[0])
                );
            } else {
                assert!(
                    matches!(error, RapidToggleError::ExpectedWindowMismatch { expected: a, observed: b } if a == expected && b == observed)
                );
            }
            assert_eq!(mapping.bytes(SITE_OFFSET, code.len()), changed);
            assert_eq!(
                permissions(placeholder.address as u64).as_deref(),
                Some("---p")
            );
            placeholder.release();
        }

        let mapping = DualMapping::new();
        let (plan, placeholder, code, _) = controlled_fixture(&mapping, &control);
        let tail_address = mapping.executable_address(SITE_OFFSET) as usize + 4;
        let blocker =
            crate::trap::register(tail_address, tail_address, tail_address + 1, 0).unwrap();
        blocker.begin().unwrap();
        let tail = mapping.writable_address(SITE_OFFSET + 4).cast::<AtomicU8>();
        // SAFETY: blocker owns this byte throughout the deliberately stale observation.
        unsafe { &*tail }.store(code[4] ^ 0xff, Ordering::Release);
        let error =
            match unsafe { RapidProbe::install(plan, mapping.writable_address(SITE_OFFSET)) } {
                Err(error) => error,
                Ok(_) => panic!("registered tail overlap unexpectedly installed"),
            };
        let mut blocked = code.clone();
        blocked[4] ^= 0xff;
        assert_eq!(mapping.bytes(SITE_OFFSET, code.len()), blocked);
        // SAFETY: restore the owned tail before releasing this writer.
        unsafe { &*tail }.store(code[4], Ordering::Release);
        blocker.finish();
        assert!(matches!(error, RapidToggleError::OverlappingPatchSite));
        assert_eq!(mapping.bytes(SITE_OFFSET, code.len()), code);
        assert_eq!(
            permissions(placeholder.address as u64).as_deref(),
            Some("---p")
        );
        placeholder.release();
    }
}
