//! Literal raw serialization controls. Synthetic evidence is never native credit.
use super::*;
use rapid_profiler::frontend_native::{NormalCounterIdentity, NormalCounterSyscall, RawTimestamp};

fn read(
    op: NormalCounterOperation,
    result: i64,
    errno: Option<i32>,
    len: usize,
) -> NormalCounterRead {
    NormalCounterRead {
        operation: op,
        syscall: NormalCounterSyscall { result, errno },
        data_len: len,
        data: std::array::from_fn(|i| i as u8),
    }
}
fn acquisition() -> NormalCounterAcquisition {
    NormalCounterAcquisition {
        owner: NormalCounterIdentity { pid: 17, tid: 29 },
        requested_attributes: std::array::from_fn(|i| i as u8),
        attributes_after_open: std::array::from_fn(|i| 255 - i as u8),
        open: NormalCounterSyscall {
            result: -1,
            errno: Some(13),
        },
        id: None,
        enable: None,
    }
}
fn endpoint() -> NormalCounterEndpoint {
    NormalCounterEndpoint {
        observer: NormalCounterIdentity { pid: 17, tid: 29 },
        before: RawTimestamp { ticks: 100, aux: 3 },
        after: RawTimestamp { ticks: 110, aux: 4 },
        read: Some(read(NormalCounterOperation::Read, 7, None, 7)),
        event_id_matches: None,
        owner_matches: false,
    }
}
#[test]
fn failed_acquisition_and_close_keep_all_raw_attribute_bytes_and_absences() {
    let a = acquisition();
    let lines = acquisition_lines(a);
    assert_eq!(lines.len(), 7);
    assert_eq!(lines[0], "PMUOPEN,17,29,-1,13\n");
    assert_eq!(lines[5], "PMUCTL,0,0,-,-,-,-,-\n");
    assert_eq!(lines[6], "PMUCTL,1,0,-,-,-,-,-\n");
    for (row, (kind, offset, bytes)) in lines[1..5].iter().zip([
        (0, 0, &a.requested_attributes[..64]),
        (0, 64, &a.requested_attributes[64..]),
        (1, 0, &a.attributes_after_open[..64]),
        (1, 64, &a.attributes_after_open[64..]),
    ]) {
        let fields: Vec<_> = row.trim_end_matches('\n').split(',').collect();
        assert_eq!(
            fields[..3],
            ["PMUATTR", &kind.to_string(), &offset.to_string()]
        );
        let decoded: Vec<_> = fields[3]
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(decoded, bytes);
    }
    let close = NormalCounterClose {
        acquisition: a,
        observer: a.owner,
        disable: None,
        close: None,
    };
    assert_eq!(
        close_lines(close),
        vec![
            "PMUCLOSE,17,29\n",
            "PMUCTL,3,0,-,-,-,-,-\n",
            "PMUCTL,4,0,-,-,-,-,-\n"
        ]
    );
}
#[test]
fn short_and_failed_reads_preserve_return_errno_length_buffer_and_both_clocks() {
    let e = endpoint();
    let line = endpoint_line(37, 3, 1, e);
    let suffix = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    assert_eq!(
        line,
        format!("PMU,37,3,1,17,29,100,3,110,4,0,-,1,2,7,-,7,{suffix}\n")
    );
    let failed = NormalCounterEndpoint {
        read: Some(read(NormalCounterOperation::Read, -1, Some(4), 0)),
        event_id_matches: Some(false),
        ..e
    };
    assert_eq!(
        endpoint_line(37, 3, 0, failed),
        format!("PMU,37,3,0,17,29,100,3,110,4,0,0,1,2,-1,4,0,{suffix}\n")
    );
    let absent = NormalCounterEndpoint { read: None, ..e };
    assert_eq!(
        endpoint_line(37, 3, 0, absent),
        "PMU,37,3,0,17,29,100,3,110,4,0,-,0,-,-,-,-,-\n"
    );
}
#[test]
fn numeric_extremes_fit_350_without_scaling_id_loss_or_debug_fields() {
    let e = NormalCounterEndpoint {
        observer: NormalCounterIdentity {
            pid: u32::MAX,
            tid: u64::MAX,
        },
        before: RawTimestamp {
            ticks: u64::MAX,
            aux: u32::MAX,
        },
        after: RawTimestamp {
            ticks: u64::MAX,
            aux: u32::MAX,
        },
        read: Some(read(
            NormalCounterOperation::Read,
            i64::MIN,
            Some(i32::MIN),
            32,
        )),
        event_id_matches: Some(true),
        owner_matches: true,
    };
    for side in [0, 1] {
        let line = endpoint_line(u64::MAX, 3, side, e);
        assert!(line.len() <= 350);
        let fields: Vec<_> = line.trim_end_matches('\n').split(',').collect();
        assert_eq!(fields.len(), 18);
        assert_eq!(fields[1], u64::MAX.to_string());
        assert_eq!(fields[14], i64::MIN.to_string());
        assert_eq!(fields[15], i32::MIN.to_string());
        assert_eq!(fields[16], "32");
        assert_eq!(fields[17].len(), 64);
    }
    let mut a = acquisition();
    a.open = NormalCounterSyscall {
        result: i64::MIN,
        errno: Some(i32::MIN),
    };
    a.id = Some(read(NormalCounterOperation::Id, -1, Some(5), 0));
    a.enable = Some(read(NormalCounterOperation::Enable, -1, Some(9), 0));
    let c = NormalCounterClose {
        acquisition: a,
        observer: e.observer,
        disable: Some(read(NormalCounterOperation::Disable, -1, Some(4), 0)),
        close: Some(read(NormalCounterOperation::Close, -1, Some(4), 0)),
    };
    let mut lines = acquisition_lines(a);
    lines.extend(close_lines(c));
    assert_eq!(lines.len(), 10);
    assert!(lines.iter().all(|l| l.len() <= 350));
    assert!(lines.iter().any(|l| l.starts_with("PMUCTL,4,1,4,-1,4,0,")));
}
