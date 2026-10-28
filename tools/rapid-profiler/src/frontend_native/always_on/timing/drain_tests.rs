//! No native timing credit: complete prefix/tail and preallocation checks only.
use super::*;

#[test]
fn drain_copy_rejects_hidden_missing_and_unreserved_storage_without_writes() {
    let row = RawInterval {
        ordinal: 1,
        entry_pc: 0x1000,
        return_pc: 0x1012,
        owner: RawIntervalOwner::InitialDisarmed,
        start: RawTimestamp { ticks: 9, aux: 7 },
        end: RawTimestamp { ticks: 8, aux: 8 },
    };
    for which in 0..3 {
        let mut rows = Rows::new();
        rows.push(row).unwrap();
        match which {
            0 => rows.rows[0] = None,
            1 => rows.rows[31] = Some(row),
            _ => rows.len = 33,
        }
        let before = (rows.rows, rows.len);
        let mut output = Vec::with_capacity(32);
        assert_eq!(
            rows.copy_committed(&mut output),
            Err(error(Cause::Invariant))
        );
        assert!(output.is_empty());
        assert_eq!((rows.rows, rows.len), before);
    }
    let mut rows = Rows::new();
    rows.push(row).unwrap();
    assert_eq!(
        rows.copy_committed(&mut Vec::new()),
        Err(error(Cause::Capacity))
    );
    let mut output = Vec::with_capacity(32);
    rows.copy_committed(&mut output).unwrap();
    assert_eq!(output, [row]);
    assert_eq!(
        rows.copy_committed(&mut output),
        Err(error(Cause::Invariant))
    );
    assert_eq!(output, [row]);
    assert_eq!(rows.snapshot(), [row]);
}
