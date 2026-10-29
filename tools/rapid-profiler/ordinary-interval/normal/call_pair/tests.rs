use super::*;
fn refuse(f: impl FnOnce()) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
}
fn args() -> Vec<std::ffi::OsString> {
    [
        "candidate",
        "trusted",
        "10",
        "520",
        "101",
        "8192",
        "64",
        "202",
        "4096",
        "128",
    ]
    .into_iter()
    .map(Into::into)
    .collect()
}
#[test]
fn exact_cli_preserves_logical_roles_both_address_orders_and_all_bounds() {
    for (k, epochs, parent, child) in [("10", "1", "8192", "4096"), ("1000", "520", "4096", "8192")]
    {
        let mut a = args();
        a[2] = k.into();
        a[3] = epochs.into();
        a[5] = parent.into();
        a[8] = child.into();
        let (actual_k, e, s) = arguments(&a).unwrap();
        assert_eq!(actual_k, k.parse::<usize>().unwrap());
        assert_eq!(e, epochs.parse::<u32>().unwrap());
        assert_eq!(s.map(|s| s.function), [FunctionId(101), FunctionId(202)]);
        assert_eq!(
            s.map(|s| s.va),
            [
                parent.parse::<u64>().unwrap(),
                child.parse::<u64>().unwrap()
            ]
        );
        for (at, value) in [
            (2, "1"),
            (3, "0"),
            (3, "521"),
            (4, "0202"),
            (4, "202"),
            (5, "0"),
            (6, "4"),
            (6, "81"),
            (8, "8192"),
            (9, "0"),
            (9, "257"),
            (5, "18446744073709551615"),
            (7, "-1"),
            (8, "+1"),
            (5, " 1"),
            (7, ""),
        ] {
            let mut bad = args();
            bad[at] = value.into();
            assert!(arguments(&bad).is_err(), "{at}={value}");
        }
        let mut extra = a.clone();
        extra.push("0".into());
        assert!(arguments(&extra).is_err());
        let mut short = a;
        short.pop();
        assert!(arguments(&short).is_err());
    }
    for s in ["0", "1", "18446744073709551615"] {
        assert_eq!(
            number(std::ffi::OsStr::new(s)).unwrap(),
            s.parse::<u64>().unwrap()
        );
    }
    for s in ["00", "01", "18446744073709551616", "1\n", "１２"] {
        assert!(number(std::ffi::OsStr::new(s)).is_err());
    }
}
#[test]
fn typed_input_outcomes_remain_nonzero_after_finalization_and_preserve_empty_record() {
    let mut input = input::Input::default();
    assert_eq!(input.status(), "INPUT_INCOMPLETE");
    assert_eq!(
        completion_stderr(input.completion().unwrap_err()),
        "normal-call-pair-session INPUT_INCOMPLETE\n"
    );
    input.eof = true;
    assert_eq!(input.status(), "COMPLETE");
    assert_eq!(input.completion(), Ok(()));
    for why in [
        input::Refusal::Syntax,
        input::Refusal::Overlong,
        input::Refusal::Unterminated,
        input::Refusal::RecordLimit,
    ] {
        for eof in [false, true] {
            input.eof = eof;
            input.error = Some(why);
            assert_eq!(input.status(), "INPUT_REFUSED");
            assert_eq!(
                completion_stderr(input.completion().unwrap_err()),
                format!("normal-call-pair-session INPUT_REFUSED: {}\n", why.label())
            );
        }
    }
    let empty = input::Record::new(1, b"").unwrap();
    assert_eq!((empty.length, empty.fields, packed(&empty)), (0, 1, 1));
    let full = input::Record::new(2048, &[b','; 64]).unwrap();
    assert_eq!(
        (full.length, full.fields, packed(&full)),
        (64, 65, (64_u64 << 32) | 65)
    );
    assert!(input::Record::new(1, &[b'a'; 65]).is_err());
    for bytes in [b"a\"b".as_slice(), b"\"unfinished", b"a\nb", b"a\0b"] {
        assert!(input::Record::new(1, bytes).is_err());
    }
    let mut changed = full.clone();
    changed.length -= 1;
    refuse(|| {
        packed(&changed);
    });
    let mut changed = full;
    changed.fields -= 1;
    refuse(|| {
        packed(&changed);
    });
}
