//! Closed policy and storage controls, without source or native seal factories.
use super::*;
use crate::linux::remote::dynamic::owner::kernel_journal::KernelJournalWriter;

fn input(number: u64, encoding: &[u8], abi: Option<SyscallAbi>) -> SelectedInput {
    let mut aliases = SyscallAliases::default();
    if let Some(abi) = abi {
        aliases.declare(0x401000, abi).unwrap();
    }
    let registers = crate::RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 11,
        rbx: 10,
        r11: 9,
        r10: 8,
        r9: 7,
        r8: 6,
        rax: number,
        rcx: 4,
        rdx: 3,
        rsi: 2,
        rdi: 1,
        orig_rax: u64::MAX,
        rip: 0x401000,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x700000,
        ss: 0x2b,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    };
    SelectedInput::new(
        crate::selected::decode(0x401000, encoding, &aliases).unwrap(),
        registers,
    )
    .unwrap()
}
#[test]
fn runtime_kernel_default_profile_keeps_native_effects_refused() {
    assert_eq!(
        RuntimeKernelProfile::default(),
        RuntimeKernelProfile::Refuse
    );
    assert_eq!(
        crate::linux::remote::dynamic::admission::DynamicRuntimeOptions::default().kernel,
        RuntimeKernelProfile::Refuse
    );
}
#[test]
fn runtime_kernel_policy_accepts_only_four_exact_native64_operations() {
    let cases = [
        (libc::SYS_getpid, RuntimeKernelOperation::Getpid, true),
        (libc::SYS_gettid, RuntimeKernelOperation::Gettid, true),
        (libc::SYS_exit, RuntimeKernelOperation::Exit, false),
        (
            libc::SYS_exit_group,
            RuntimeKernelOperation::ExitGroup,
            false,
        ),
    ];
    for (number, operation, returns) in cases {
        let input = input(number as u64, &[0x0f, 0x05], None);
        assert_eq!(
            RuntimeKernelOperation::from_input(&input).unwrap(),
            operation
        );
        assert_eq!(operation.number(), number as u64);
        assert_eq!(operation.returns(), returns);
    }
    for number in (0..450).chain([u64::MAX, 0x4000_0027, 0x4000_00ba, 0x4000_003c, 0x4000_00e7]) {
        if cases
            .iter()
            .any(|(allowed, _, _)| *allowed as u64 == number)
        {
            continue;
        }
        assert!(RuntimeKernelOperation::from_number(number).is_none());
        assert!(RuntimeKernelOperation::from_input(&input(number, &[0x0f, 0x05], None)).is_err());
    }
}
#[test]
fn runtime_kernel_policy_rejects_aliases_and_cpu_instructions() {
    for number in [20, 224, 1, 252, libc::SYS_getpid as u64] {
        let alias = input(number, &[0xcd, 0x80], Some(SyscallAbi::LinuxI386Int80));
        assert!(RuntimeKernelOperation::from_input(&alias).is_err());
    }
    for encoding in [&[0x0f, 0xa2][..], &[0x0f, 0x31][..]] {
        assert!(
            RuntimeKernelOperation::from_input(&input(libc::SYS_getpid as u64, encoding, None))
                .is_err()
        );
    }
}
#[test]
fn runtime_kernel_complete_reservation_separates_return_and_terminal_storage() {
    let writer = KernelJournalWriter::new(71);
    let shape = writer.runtime_shape().unwrap();
    let returned = reservation_charge(4096, 1, RuntimeKernelOperation::Getpid, &shape).unwrap();
    assert_eq!(
        returned,
        reservation_charge(4096, 1, RuntimeKernelOperation::Gettid, &shape).unwrap()
    );
    let terminal = reservation_charge(4096, 1, RuntimeKernelOperation::Exit, &shape).unwrap();
    assert_eq!(
        terminal,
        reservation_charge(4096, 1, RuntimeKernelOperation::ExitGroup, &shape).unwrap()
    );
    assert_eq!(
        (
            returned.epochs,
            returned.reports,
            returned.origins,
            returned.witnesses,
            returned.plan_history
        ),
        (0, 0, 1, 8, 0)
    );
    assert_eq!(
        (
            terminal.epochs,
            terminal.reports,
            terminal.origins,
            terminal.witnesses,
            terminal.plan_history
        ),
        (0, 0, 0, 4, 0)
    );
    let return_census = runtime_kernel_census_charge(RuntimeKernelOperation::Getpid).unwrap();
    let terminal_census = runtime_kernel_census_charge(RuntimeKernelOperation::Exit).unwrap();
    assert_eq!(
        returned.source_fact_bytes - terminal.source_fact_bytes,
        return_census.source_fact_bytes - terminal_census.source_fact_bytes
            + size_of::<DynamicAdmissionCompletion>()
            + 2 * MAX_XSTATE
            + 15
    );
    let replacement = reservation_charge(4096, 7, RuntimeKernelOperation::Getpid, &shape).unwrap();
    assert_eq!(
        replacement.source_fact_bytes - returned.source_fact_bytes,
        6 * size_of::<Box<RuntimeKernelAttempt>>()
    );
    let full_window =
        reservation_charge(MAP_BYTES, 1, RuntimeKernelOperation::Getpid, &shape).unwrap();
    assert_eq!(
        full_window.source_fact_bytes - returned.source_fact_bytes,
        SOURCE_READS * (MAP_BYTES - 4096)
    );
}
#[test]
fn runtime_kernel_reservation_refuses_one_short_and_overflow_before_allocation() {
    let writer = KernelJournalWriter::new(71);
    let shape = writer.runtime_shape().unwrap();
    for operation in [
        RuntimeKernelOperation::Getpid,
        RuntimeKernelOperation::ExitGroup,
    ] {
        let charge = reservation_charge(MAP_BYTES, 1, operation, &shape).unwrap();
        let configured = DynamicAdmissionLimits::default();
        let mut limits = super::super::super::census::Limits {
            epochs: configured.epochs,
            source_fact_bytes: configured.source_fact_bytes,
            reports: configured.reports,
            origins: configured.origins,
            witnesses: configured.witnesses,
            plan_history: configured.plan_history,
        };
        limits.source_fact_bytes = charge.source_fact_bytes - 1;
        let mut reserve =
            super::super::super::census::InitialRuntimeReservation::new(limits).unwrap();
        let before = reserve.charged();
        assert!(reserve.reserve(charge).is_err());
        assert_eq!(reserve.charged(), before);
    }
    for window in [0, MAP_BYTES + 1, usize::MAX] {
        assert!(reservation_charge(window, 1, RuntimeKernelOperation::Getpid, &shape).is_err());
    }
    assert!(reservation_charge(4096, usize::MAX, RuntimeKernelOperation::Getpid, &shape).is_err());
}
#[test]
fn runtime_kernel_exact_allocation_owns_only_initialized_elements() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Count(Arc<AtomicUsize>);
    impl Drop for Count {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let mut values = exact_vec::<Count>(3).unwrap();
    assert_eq!(values.capacity(), 3);
    assert_eq!(values.len(), 0);
    values.push(Count(Arc::clone(&drops)));
    values.push(Count(Arc::clone(&drops)));
    drop(values);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(exact_vec::<u64>(usize::MAX).is_err());
    assert!(exact_vec::<()>(1).is_err());
    assert_eq!(exact_vec::<u8>(0).unwrap().capacity(), 0);

    // Exercise the census's safe allocation boundary without weakening any
    // existing owner-vector assertions above.
    use super::super::super::exact_storage::{self, AllocationError};
    let mut bytes = exact_storage::empty_bytes(MAX_XSTATE).unwrap();
    assert_eq!((bytes.len(), bytes.capacity()), (0, MAX_XSTATE));
    bytes.extend_from_slice(&[1, 2, 3]);
    assert_eq!(bytes, [1, 2, 3]);
    assert_eq!(bytes.capacity(), MAX_XSTATE);
    assert_eq!(
        exact_storage::empty_bytes(usize::MAX),
        Err(AllocationError::Capacity)
    );
    assert_eq!(exact_storage::empty_bytes(0).unwrap().capacity(), 0);
    assert_eq!(exact_storage::one(()), Err(AllocationError::Capacity));
    let drops = Arc::new(AtomicUsize::new(0));
    let value = exact_storage::one(Count(Arc::clone(&drops))).unwrap();
    assert_eq!(value.len(), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(value);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
