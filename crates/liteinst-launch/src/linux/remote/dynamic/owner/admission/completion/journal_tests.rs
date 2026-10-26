//! Real lifetime-accounting transactions with synthetic journal input. No test
//! here launches a process or establishes that a native effect occurred.
use super::super::super::kernel_journal::{KernelJournalWriter, tests::binding};
use super::super::census::{CensusError, Limits};
use super::*;

fn census(binding: &KernelAttemptBinding, bytes: usize) -> ResumeCensus {
    ResumeCensus::new(
        binding.pending.stop.session,
        binding.pending.task.address_space,
        binding.pending.epoch,
        Limits {
            epochs: 2,
            source_fact_bytes: bytes,
            reports: 4,
            origins: 4,
            witnesses: 4,
            plan_history: 4,
        },
    )
    .unwrap()
}
fn charge(bytes: usize) -> BudgetCharge {
    BudgetCharge {
        source_fact_bytes: bytes,
        ..BudgetCharge::default()
    }
}

#[test]
fn journal_storage_requires_its_entire_lifetime_prefix_before_attachment() {
    let input = binding();
    let mut writer = KernelJournalWriter::new(input.pending.stop.session);
    let mut census = census(&input, 1 << 20);
    let prepared = writer.prepare(input).unwrap();
    let bytes = prepared.retained_bytes();
    assert!(bytes > 8 * MAX_XSTATE);
    let before_archive = writer.reader().snapshot();
    let before_charged = census.charged();
    let before_used = census.used();
    let reservation = census.reserve(charge(bytes - 1)).unwrap();
    assert_eq!(
        census.account_external(reservation, charge(bytes)),
        Err(CensusError::ReservationExhausted)
    );
    assert_eq!(writer.reader().snapshot(), before_archive);
    assert_eq!(census.used(), before_used);
    assert_eq!(
        census.charged().source_fact_bytes,
        before_charged.source_fact_bytes + bytes - 1
    );
    assert!(writer.reader().snapshot().attempts.is_empty());
    drop(prepared);
}

#[test]
fn exact_journal_debit_attaches_once_and_failure_never_refunds_storage() {
    let input = binding();
    let mut writer = KernelJournalWriter::new(input.pending.stop.session);
    let prepared = writer.prepare(input.clone()).unwrap();
    let bytes = prepared.retained_bytes();
    let mut census = census(&input, bytes);
    let reservation = census.reserve(charge(bytes)).unwrap();
    census.account_external(reservation, charge(bytes)).unwrap();
    let _handle = writer.attach(prepared).unwrap();
    assert_eq!(writer.reader().snapshot().attempts.len(), 1);
    assert_eq!(writer.reader().snapshot().attempts[0].reserved_bytes, bytes);
    assert_eq!(census.used().source_fact_bytes, bytes);
    writer.fail_active(KernelFailureKind::Timeout);
    census.finish_reservation(reservation).unwrap();
    assert_eq!(census.charged().source_fact_bytes, bytes);
    assert_eq!(census.used().source_fact_bytes, bytes);
    assert_eq!(census.reserve(charge(1)), Err(CensusError::Capacity));
    assert_eq!(
        writer.reader().snapshot().attempts[0].failure.unwrap().kind,
        KernelFailureKind::Timeout
    );
}

#[test]
fn exhausted_lifetime_reservation_leaves_archive_unattached_and_census_unchanged() {
    let input = binding();
    let mut writer = KernelJournalWriter::new(input.pending.stop.session);
    let prepared = writer.prepare(input.clone()).unwrap();
    let bytes = prepared.retained_bytes();
    let mut census = census(&input, bytes - 1);
    let before_archive = writer.reader().snapshot();
    let before_charged = census.charged();
    let before_used = census.used();
    assert_eq!(census.reserve(charge(bytes)), Err(CensusError::Capacity));
    assert_eq!(census.charged(), before_charged);
    assert_eq!(census.used(), before_used);
    assert_eq!(writer.reader().snapshot(), before_archive);
    assert_eq!(census.active().count(), 0);
    assert!(census.history().is_empty());
    drop(prepared);
}
