//! Pure bounded task/status interpretation; no fixture fabricates native pin,
//! procfs or registry authority, and no native request is executed here.
use super::*;

fn record(name: &[u8]) -> Vec<u8> {
    let length = (19 + name.len() + 1 + 7) & !7;
    let mut bytes = vec![0; length];
    bytes[16..18].copy_from_slice(&(length as u16).to_ne_bytes());
    bytes[18] = libc::DT_DIR;
    bytes[19..19 + name.len()].copy_from_slice(name);
    bytes
}

#[test]
fn initial_task_census_requires_one_exact_numeric_member_and_full_records() {
    let mut seen = false;
    let mut count = 0;
    let mut rows = record(b".");
    rows.extend(record(b".."));
    task_records(&rows, b"123", &mut seen, &mut count).unwrap();
    assert!(!seen);
    task_records(&record(b"123"), b"123", &mut seen, &mut count).unwrap();
    assert!(seen);
    assert_eq!(count, 3);
    assert!(task_records(&record(b"124"), b"123", &mut seen, &mut count).is_err());
    for name in [b"124".as_slice(), b"1234", b"x123", b""] {
        assert!(task_records(&record(name), b"123", &mut false, &mut 0).is_err());
    }
    for length in 0..record(b"123").len() {
        if length == 0 {
            continue;
        }
        assert!(task_records(&record(b"123")[..length], b"123", &mut false, &mut 0).is_err());
    }
    let mut malformed = record(b"123");
    malformed[16..18].copy_from_slice(&20_u16.to_ne_bytes());
    assert!(task_records(&malformed, b"123", &mut false, &mut 0).is_err());
    let mut duplicate = record(b"123");
    duplicate.extend(record(b"123"));
    assert!(task_records(&duplicate, b"123", &mut false, &mut 0).is_err());
}

#[test]
fn initial_task_status_preserves_exact_single_tgid_gate() {
    status_tgid(b"Name:\tfixture\nTgid:\t123\nPid:\t123\n", 123).unwrap();
    for bytes in [
        b"Tgid:\t124\n".as_slice(),
        b"Pid:\t123\n",
        b"Tgid:\t123\nTgid:\t123\n",
        b"Tgid:\t123x\n",
        b"Tgid:\t999999999999999999999\n",
        b"\xff\nTgid:\t123\n",
    ] {
        assert!(status_tgid(bytes, 123).is_err());
    }
}

#[test]
fn initial_proc_pid_component_uses_fixed_exact_decimal_storage() {
    let mut storage = [0_u8; 11];
    assert_eq!(pid_component(1, &mut storage).unwrap(), b"1");
    assert_eq!(
        pid_component(i32::MAX, &mut storage).unwrap(),
        b"2147483647"
    );
    assert!(pid_component(0, &mut storage).is_err());
    assert!(pid_component(-1, &mut storage).is_err());
    assert_eq!(
        InitialReadScratch::reservation_bytes(),
        size_of::<InitialReadScratch>() + MAP_BYTES
    );
}
