//! Synthetic archive transactions only: no native map, wait or cleanup proof.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn id() -> KernelAttemptId {
    KernelAttemptId {
        session: 83,
        invocation: 1,
    }
}
fn buffer(prefix: &[u8]) -> Arc<[u8]> {
    let mut bytes = vec![0; MAPPING_CAPTURE_BYTES];
    bytes[..prefix.len()].copy_from_slice(prefix);
    Arc::from(bytes)
}
fn prepared_mapping() -> (KernelJournalWriter, KernelAttemptHandle) {
    let mut binding = super::super::tests::binding();
    let mut registers = *binding.input.registers();
    registers.rax = libc::SYS_mprotect as u64;
    binding.input = SelectedInput::new(binding.input.instruction().clone(), registers).unwrap();
    binding.before.registers = registers;
    let mut writer = KernelJournalWriter::new(id().session);
    let prepared = writer.prepare(binding).unwrap();
    let handle = writer.attach(prepared).unwrap();
    (writer, handle)
}
fn attached() -> (
    KernelJournalWriter,
    KernelAttemptHandle,
    MappingCaptureArchive,
) {
    let (mut writer, handle) = prepared_mapping();
    let mapping = MappingCaptureArchive::new(handle.id()).unwrap();
    writer.attach_mapping(handle, mapping.clone()).unwrap();
    (writer, handle, mapping)
}
fn refusal(result: Result<(), LaunchError>, expected: &'static str) {
    assert!(matches!(result, Err(LaunchError::Invalid(message)) if message == expected));
}

#[test]
fn mapping_archive_is_additive_and_charged_before_release() {
    let binding = super::super::tests::binding();
    let mut legacy = KernelJournalWriter::new(id().session);
    let prepared = legacy.prepare(binding.clone()).unwrap();
    let handle = legacy.attach(prepared).unwrap();
    let old = legacy.reader().snapshot();
    assert_eq!(old.attempts[0].mapping, None);
    let mapping = MappingCaptureArchive::new(handle.id()).unwrap();
    refusal(
        legacy.attach_mapping(handle, mapping),
        "mapping archive must attach before its original release",
    );
    assert_eq!(legacy.reader().snapshot(), old);

    let mut native = binding;
    let mut registers = *native.input.registers();
    registers.rax = libc::SYS_mmap as u64;
    native.input = SelectedInput::new(native.input.instruction().clone(), registers).unwrap();
    native.before.registers = registers;
    let mut writer = KernelJournalWriter::new(id().session);
    let prepared = writer.prepare(native).unwrap();
    let charge = prepared.retained_bytes();
    let handle = writer.attach(prepared).unwrap();
    let before = writer.reader().snapshot();
    let mapping = MappingCaptureArchive::new(handle.id()).unwrap();
    let added = mapping.retained_bytes();
    assert!(added > 5 * MAPPING_CAPTURE_BYTES);
    writer.attach_mapping(handle, mapping).unwrap();
    let after = writer.reader().snapshot();
    assert_eq!(after.attempts[0].reserved_bytes, charge + added);
    assert_eq!(after.attempts[0].facts, before.attempts[0].facts);
    assert_eq!(after.attempts[0].states, before.attempts[0].states);
    assert_eq!(after.attempts[0].failure, None);
    let capture = after.attempts[0].mapping.as_ref().unwrap();
    assert_eq!(capture.attempt, handle.id());
    assert_eq!(capture.records.len(), 5);
    assert!(
        capture
            .records
            .iter()
            .all(|record| record.status == MappingCaptureStatus::Unused
                && record.tid.is_none()
                && record.wait_status.is_none()
                && record.bytes().is_none())
    );
}

#[test]
fn mapping_capture_retains_exact_failed_prefix_and_shared_storage() {
    let (writer, _, mapping) = attached();
    let status = (libc::SIGTRAP | 0x80) << 8 | 0x7f;
    mapping
        .begin(MappingCaptureSlot::FirstWait, 100, Some(status))
        .unwrap();
    let in_progress = writer.reader().snapshot();
    let row = &in_progress.attempts[0].mapping.as_ref().unwrap().records[2];
    assert_eq!(row.tid, Some(100));
    assert_eq!(row.wait_status, Some(status));
    assert_eq!(row.status, MappingCaptureStatus::InProgress);
    assert_eq!(row.bytes(), None);

    let bytes = buffer(b"actual partial maps");
    let expected = MappingCaptureStatus::Failed {
        phase: MappingCapturePhase::Read,
        errno: Some(libc::EIO),
        read_complete: false,
    };
    mapping
        .commit(
            MappingCaptureSlot::FirstWait,
            Arc::clone(&bytes),
            18,
            expected,
        )
        .unwrap();
    let reader = writer.reader();
    let snapshot = reader.snapshot();
    let row = &snapshot.attempts[0].mapping.as_ref().unwrap().records[2];
    assert_eq!(row.status, expected);
    assert_eq!(row.bytes(), Some(&b"actual partial maps"[..]));
    assert_eq!(
        row.initialized_storage().unwrap().len(),
        MAPPING_CAPTURE_BYTES
    );
    assert!(
        row.initialized_storage().unwrap()[18..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(Arc::ptr_eq(row.bytes.as_ref().unwrap(), &bytes));
    assert!(snapshot.attempts[0].facts.is_empty());
    drop(mapping);
    drop(writer);
    assert_eq!(reader.snapshot(), snapshot);
}

#[test]
fn mapping_capture_terminal_refusals_leave_header_and_prefix_unchanged() {
    let (_, _, mapping) = attached();
    let initial = mapping.snapshot();
    for (slot, tid, wait) in [
        (MappingCaptureSlot::BeforeWindow, 0, None),
        (MappingCaptureSlot::BeforeWindow, 100, Some(0)),
        (MappingCaptureSlot::FirstWait, 100, None),
    ] {
        refusal(
            mapping.begin(slot, tid, wait),
            "mapping capture cannot begin in this archive state",
        );
        assert_eq!(mapping.snapshot(), initial);
    }
    mapping
        .begin(MappingCaptureSlot::BeforeWindow, 100, None)
        .unwrap();
    let progress = mapping.snapshot();
    for (bytes, len, status) in [
        (
            Arc::<[u8]>::from([0_u8; 4]),
            4,
            MappingCaptureStatus::Complete,
        ),
        (
            buffer(b"x"),
            MAPPING_CAPTURE_BYTES + 1,
            MappingCaptureStatus::Complete,
        ),
        (buffer(b"x"), 1, MappingCaptureStatus::InProgress),
        (
            buffer(b"x"),
            1,
            MappingCaptureStatus::Failed {
                phase: MappingCapturePhase::Read,
                errno: Some(0),
                read_complete: false,
            },
        ),
        (
            buffer(b"x"),
            1,
            MappingCaptureStatus::Failed {
                phase: MappingCapturePhase::ProcIdentity,
                errno: None,
                read_complete: false,
            },
        ),
        (
            buffer(b"x"),
            1,
            MappingCaptureStatus::Failed {
                phase: MappingCapturePhase::Parse,
                errno: None,
                read_complete: false,
            },
        ),
    ] {
        refusal(
            mapping.commit(MappingCaptureSlot::BeforeWindow, bytes, len, status),
            "mapping capture cannot commit this terminal prefix",
        );
        assert_eq!(mapping.snapshot(), progress);
    }
    mapping
        .commit(
            MappingCaptureSlot::BeforeWindow,
            buffer(b"x\n"),
            2,
            MappingCaptureStatus::Complete,
        )
        .unwrap();
    let complete = mapping.snapshot();
    refusal(
        mapping.begin(MappingCaptureSlot::BeforeWindow, 100, None),
        "mapping capture cannot begin in this archive state",
    );
    refusal(
        mapping.commit(
            MappingCaptureSlot::BeforeWindow,
            buffer(b"changed"),
            7,
            MappingCaptureStatus::Failed {
                phase: MappingCapturePhase::Read,
                errno: Some(libc::EFAULT),
                read_complete: false,
            },
        ),
        "mapping capture cannot commit this terminal prefix",
    );
    assert_eq!(mapping.snapshot(), complete);
}

#[test]
fn mapping_malformed_overflow_and_unwind_are_distinct_noncomplete_facts() {
    let (writer, _, mapping) = attached();
    let rows = [
        (
            MappingCaptureSlot::BeforeWindow,
            None,
            b"bad table\n".as_slice(),
            10,
            MappingCaptureStatus::Failed {
                phase: MappingCapturePhase::Parse,
                errno: None,
                read_complete: true,
            },
        ),
        (
            MappingCaptureSlot::LogicalWindow,
            None,
            b"overflow".as_slice(),
            MAPPING_CAPTURE_BYTES,
            MappingCaptureStatus::Failed {
                phase: MappingCapturePhase::Overflow,
                errno: None,
                read_complete: false,
            },
        ),
        (
            MappingCaptureSlot::FirstWait,
            Some(0x857f),
            b"prefix".as_slice(),
            6,
            MappingCaptureStatus::Unwound {
                phase: MappingCapturePhase::Read,
                read_complete: false,
            },
        ),
        (
            MappingCaptureSlot::SecondWait,
            Some(0x857f),
            b"abandoned".as_slice(),
            9,
            MappingCaptureStatus::Abandoned {
                phase: MappingCapturePhase::Read,
                read_complete: false,
            },
        ),
        (
            MappingCaptureSlot::Quarantined,
            None,
            b"".as_slice(),
            0,
            MappingCaptureStatus::Failed {
                phase: MappingCapturePhase::Open,
                errno: Some(libc::ENOENT),
                read_complete: false,
            },
        ),
    ];
    for (slot, wait, prefix, len, status) in rows {
        mapping.begin(slot, 100, wait).unwrap();
        mapping.commit(slot, buffer(prefix), len, status).unwrap();
    }
    let snapshot = writer.reader().snapshot();
    let retained = snapshot.attempts[0].mapping.as_ref().unwrap();
    for (slot, wait, prefix, len, status) in rows {
        let record = &retained.records[slot.index()];
        assert_eq!(record.wait_status, wait);
        assert_eq!(record.status, status);
        assert_eq!(record.initialized_len, len);
        assert_eq!(&record.bytes().unwrap()[..prefix.len()], prefix);
        assert_ne!(record.status, MappingCaptureStatus::Complete);
    }
    assert!(snapshot.attempts[0].facts.is_empty());
    assert_eq!(snapshot.writer, KernelWriterStatus::Active);
}

#[test]
fn mapping_attachment_rejects_foreign_duplicate_and_post_release_without_mutation() {
    let (mut writer, handle, mapping) = attached();
    let before = writer.reader().snapshot();
    refusal(
        writer.attach_mapping(handle, mapping.clone()),
        "mapping archive must attach before its original release",
    );
    assert_eq!(writer.reader().snapshot(), before);

    let (mut other, other_handle) = prepared_mapping();
    let before_other = other.reader().snapshot();
    refusal(
        other.attach_mapping(other_handle, mapping),
        "mapping archive is foreign, used or incomplete",
    );
    assert_eq!(other.reader().snapshot(), before_other);
    let foreign = MappingCaptureArchive::new(KernelAttemptId {
        session: 84,
        invocation: 1,
    })
    .unwrap();
    refusal(
        other.attach_mapping(other_handle, foreign),
        "mapping archive is foreign, used or incomplete",
    );
    assert_eq!(other.reader().snapshot(), before_other);
    let token = super::super::tests::binding().original_stop.token;
    other
        .release_attempt(other_handle, KernelReleasePhase::Original, &token)
        .unwrap();
    let released = other.reader().snapshot();
    refusal(
        other.attach_mapping(
            other_handle,
            MappingCaptureArchive::new(other_handle.id()).unwrap(),
        ),
        "mapping archive must attach before its original release",
    );
    assert_eq!(other.reader().snapshot(), released);
}

#[test]
fn mapping_archive_poison_preserves_prior_capture_and_refuses_new_mutation() {
    let (writer, _, mapping) = attached();
    mapping
        .begin(MappingCaptureSlot::BeforeWindow, 100, None)
        .unwrap();
    mapping
        .commit(
            MappingCaptureSlot::BeforeWindow,
            buffer(b"saved\n"),
            6,
            MappingCaptureStatus::Complete,
        )
        .unwrap();
    let saved = mapping.snapshot().records[0].clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _guard = mapping.archive.lock().unwrap();
        panic!("intentional mapping archive poison");
    }));
    assert!(result.is_err());
    let poisoned = writer.reader().snapshot();
    assert!(
        poisoned.attempts[0]
            .mapping
            .as_ref()
            .unwrap()
            .archive_poisoned
    );
    assert_eq!(
        poisoned.attempts[0].mapping.as_ref().unwrap().records[0],
        saved
    );
    refusal(
        mapping.begin(MappingCaptureSlot::LogicalWindow, 100, None),
        "mapping capture cannot begin in this archive state",
    );
    assert_eq!(writer.reader().snapshot(), poisoned);
    assert!(poisoned.attempts[0].facts.is_empty());
}
