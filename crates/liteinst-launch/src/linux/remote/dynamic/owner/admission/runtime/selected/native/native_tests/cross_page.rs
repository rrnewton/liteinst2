//! Selected decoding crosses a page; the original CPU opcode remains NX.
//! Its result is explicitly scripted, not claimed as native CPUID evidence.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::cross_page::with_entry;

#[test]
fn runtime_selected_cross_page_cpuid_preserves_nx_and_successor() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::cross_page::runtime_selected_cross_page_cpuid_preserves_nx_and_successor",
        || {
            let code = [
                0x0f, 0xa2, 0x49, 0xbc, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xeb, 0xfe,
            ];
            with_entry(
                4095,
                &code,
                |owner, app, context, until| {
                    assert_eq!(context.entry, BASE + 4095);
                    assert_eq!(&context.source[4095..4097], &[0x0f, 0xa2]);
                    assert_eq!(context.before.registers.rip, context.entry);
                    let memory = Memory::capture(owner.pid, app, context.closed_maps.clone());
                    assert_eq!(memory.source, context.source);
                    let before = current(owner, app, &memory);
                    assert_eq!(before.actual, context.before);
                    assert_ne!(before.actual.registers.r12, MARK12);
                    let input = pending(owner, until);
                    check_pending(owner, &before, &input, &[0x0f, 0xa2], until);
                    assert_eq!(input.token.pc, BASE + 4095);
                    assert_eq!(input.input.instruction().bytes().len(), 2);
                    assert_eq!(input.input.instruction().logical_pc() + 2, BASE + 4097);
                    same_current(&before, &current(owner, app, &memory));
                    context.unchanged(owner, app, until);
                    let expected = cpuid_expected(&before.actual);
                    let after = finish(
                        owner,
                        &input,
                        SCRIPT,
                        &before,
                        &expected,
                        (app, &memory, until),
                    );
                    assert_eq!(after.actual.registers.rip, BASE + 4097);
                    assert_eq!(after.actual.registers.r12, before.actual.registers.r12);
                    assert_eq!(&context.source[4097..4107], &code[2..12]);
                    context.unchanged(owner, app, until);
                    let runtime = owner.runtime.as_ref().unwrap();
                    assert_eq!(runtime.selected_attempts.len(), 1);
                    assert!(runtime.ordinary_attempts.is_empty());
                    assert_eq!(runtime.metrics.selected.scripted_completions, 1);
                    assert_eq!(
                        runtime
                            .metrics
                            .selected
                            .callbacks
                            .values()
                            .copied()
                            .sum::<usize>(),
                        1
                    );
                    assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_BASE, 0]);
                    let attempt = &runtime.selected_attempts[0];
                    for map in &attempt.native.maps {
                        assert!(map.complete);
                        assert_eq!(map.length, map.bytes().len());
                        assert_eq!(
                            map.request,
                            Some(Request {
                                result: 0,
                                errno: None
                            })
                        );
                        assert_eq!(map.filesystem, Some(libc::PROC_SUPER_MAGIC));
                        assert_eq!(map.bytes(), context.closed_maps);
                    }
                    for source in &attempt.source_bytes {
                        assert_eq!(source, &context.source);
                    }
                    for usage in [
                        runtime.census.as_ref().unwrap().charged(),
                        runtime.census.as_ref().unwrap().used(),
                    ] {
                        assert_eq!(
                            (
                                usage.epochs,
                                usage.origins,
                                usage.reports,
                                usage.witnesses,
                                usage.plan_history
                            ),
                            (1, 2, 0, 1, 0)
                        );
                        assert!(
                            usage.source_fact_bytes > 0
                                && usage.source_fact_bytes <= 64 * 1024 * 1024
                        );
                    }
                    assert_unreleased(runtime, &[]);
                    selected_retained(owner)
                },
                |owner, expected| assert_eq!(selected_retained(owner), *expected),
            );
        },
    );
}
