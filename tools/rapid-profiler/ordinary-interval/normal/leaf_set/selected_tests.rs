//! Pure parser/ownership controls. These never open a candidate or invoke native code.
use super::*;
use std::cell::Cell;

fn ids(n: usize) -> Vec<FunctionId> {
    (1..=n).map(|i| FunctionId(i as u64 * 7)).collect()
}
fn table_text(functions: &[FunctionId], m: usize) -> String {
    let mut text = format!("LI2SELECTED 1 {} {m}\nfunctions", functions.len());
    for id in functions {
        text.push_str(&format!(" {}", id.0));
    }
    text.push('\n');
    for id in 1..=m {
        text.push_str(&format!("record {id} -"));
        for column in 0..functions.len() {
            text.push_str(&format!(" {}", id as u64 * 10 + column as u64));
        }
        text.push('\n');
    }
    text.push_str("END\n");
    text
}
fn parse(text: &str, functions: &[FunctionId]) -> Table {
    Table::parse(text.as_bytes(), functions).unwrap()
}
fn refused(text: &str, functions: &[FunctionId]) {
    assert!(Table::parse(text.as_bytes(), functions).is_err(), "{text}");
}
fn panics(f: impl FnOnce()) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
}
fn args(n: usize) -> Vec<OsString> {
    let mut args: Vec<_> = ["candidate.so", "independent.so", "frozen.txt", "10", "520"]
        .into_iter()
        .map(OsString::from)
        .collect();
    args.push(OsString::from(n.to_string()));
    for i in 0..n {
        args.extend([
            OsString::from(((i + 1) * 7).to_string()),
            OsString::from(format!("selected_{i}")),
            OsString::from((4096 + i * 256).to_string()),
            OsString::from("32"),
            OsString::from("certified"),
        ]);
    }
    args
}
fn parsed_args(args: &[OsString]) -> Result<ParsedArguments, String> {
    arguments_with(args, |path, functions| {
        assert_eq!(path, Path::new("frozen.txt"));
        Table::parse(table_text(functions, 1).as_bytes(), functions)
    })
}

pub(in crate::normal) fn labels_are_fixed_copyable_csv_safe_identifiers() {
    for text in ["A", "z", "First_equal_2", "abcdefghijklmnopqrstuvwx"] {
        let label = Label::new(text).unwrap();
        let copy = label;
        assert_eq!(label, copy);
        assert_eq!(copy.as_str(), text);
        assert!(copy.as_str().len() <= 24);
    }
}

pub(in crate::normal) fn labels_refuse_framing_injection_non_ascii_and_excess() {
    for text in [
        "",
        "1first",
        "_first",
        "first=",
        "first,second",
        "first second",
        "first-second",
        "a\tb",
        "a\nb",
        "a\rb",
        "a\0b",
        "é",
        "abcdefghijklmnopqrstuvwxy",
    ] {
        assert!(Label::new(text).is_err(), "{text:?}");
    }
}

pub(in crate::normal) fn frozen_rows_keep_exact_raw_csv_bytes_and_full_u64_values() {
    let functions = ids(2);
    let table = parse(
        "LI2SELECTED 1 2 2\nfunctions 7 14\nrecord 1 - 0 18446744073709551615\nrecord 2 22613d62222c63 3 7\nEND\n",
        &functions,
    );
    assert_eq!(table.functions(), functions);
    assert_eq!(table.count(), 2);
    let empty = input::Record::new(1, b"").unwrap();
    let row = table.row(&empty).unwrap();
    assert_eq!(row.expected(&empty, 0), 0);
    assert_eq!(row.expected(&empty, 1), u64::MAX);
    let quoted = input::Record::new(2, b"\"a=b\",c").unwrap();
    let row = table.row(&quoted).unwrap();
    assert_eq!(row.expected(&quoted, 0), 3);
    assert_eq!(row.expected(&quoted, 1), 7);
}

pub(in crate::normal) fn returned_row_owns_its_frozen_inputs_after_table_retirement() {
    let record = input::Record::new(1, b"").unwrap();
    let row = {
        let table = parse(&table_text(&ids(1), 1), &ids(1));
        let first = table.row(&record).unwrap();
        let second = table.row(&record).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        first
    };
    assert_eq!(row.expected(&record, 0), 10);
}

pub(in crate::normal) fn table_framing_requires_exact_version_spaces_lf_and_terminal_end() {
    let functions = ids(1);
    let good = table_text(&functions, 1);
    for bad in [
        good.replace("LI2SELECTED 1", "LI2SELECTED 2"),
        good.replace("LI2SELECTED", "LI2selected"),
        good.replace(" 1 1", " 01 1"),
        good.replace("functions 7", "functions  7"),
        good.replace("functions 7", " functions 7"),
        good.replace("functions 7", "functions 7 "),
        good.replace("functions 7", "functions\t7"),
        good.replace('\n', "\r\n"),
        good.trim_end_matches('\n').to_string(),
        format!("{good}\n"),
        format!("{good}END\n"),
        good.replace("END\n", "END \n"),
        good.replace("record 1", "\nrecord 1"),
        format!("\u{feff}{good}"),
        good.replace("record", "recörd"),
        good.replace("record", "rec\0ord"),
    ] {
        refused(&bad, &functions);
    }
    assert!(Table::parse(&[], &functions).is_err());
    assert!(Table::parse(&vec![b' '; TABLE_BYTES + 1], &functions).is_err());
}

pub(in crate::normal) fn all_cardinalities_preserve_exact_record_and_call_caps() {
    for n in 1..=4 {
        let functions = ids(n);
        let cap = record_cap(n);
        assert_eq!(cap, 2048.min(4096 / n));
        let table = parse(&table_text(&functions, cap), &functions);
        assert_eq!(table.count(), cap);
        assert_eq!(table.functions(), functions);
        assert!(table.complete(cap).is_ok());
        let last = input::Record::new(cap as u64, b"").unwrap();
        let row = table.row(&last).unwrap();
        for column in 0..n {
            assert_eq!(row.expected(&last, column), cap as u64 * 10 + column as u64);
        }
        let over = table_text(&functions, 1).replacen(
            &format!("LI2SELECTED 1 {n} 1"),
            &format!("LI2SELECTED 1 {n} {}", cap + 1),
            1,
        );
        refused(&over, &functions);
    }
}

pub(in crate::normal) fn dimensions_reject_zero_overflow_and_disagreement() {
    let functions = ids(1);
    for header in [
        "LI2SELECTED 1 0 1",
        "LI2SELECTED 1 5 1",
        "LI2SELECTED 1 2 1",
        "LI2SELECTED 1 1 0",
        "LI2SELECTED 1 1 2049",
        "LI2SELECTED 1 1 01",
        "LI2SELECTED 1 1 18446744073709551616",
        "LI2SELECTED 1 18446744073709551616 1",
    ] {
        refused(
            &format!("{header}\nfunctions 7\nrecord 1 - 0\nEND\n"),
            &functions,
        );
    }
    assert!(Table::parse(table_text(&functions, 1).as_bytes(), &[]).is_err());
    assert!(Table::parse(table_text(&ids(5), 1).as_bytes(), &ids(5)).is_err());
}

pub(in crate::normal) fn function_rows_are_complete_unique_and_ordered() {
    let functions = ids(2);
    let good = table_text(&functions, 1);
    for replacement in [
        "functions",
        "functions 7",
        "functions 7 14 21",
        "functions 14 7",
        "functions 7 7",
        "functions 7 15",
        "functions 07 14",
        "functions -7 14",
    ] {
        refused(&good.replace("functions 7 14", replacement), &functions);
    }
    let duplicate = [FunctionId(7), FunctionId(7)];
    assert!(Table::parse(good.as_bytes(), &duplicate).is_err());
}

pub(in crate::normal) fn record_rows_refuse_missing_duplicate_extra_or_reordered_ids() {
    let functions = ids(1);
    let good = table_text(&functions, 2);
    for bad in [
        good.replace("record 2 - 20\n", ""),
        good.replace("record 2", "record 1"),
        good.replace(
            "record 1 - 10\nrecord 2 - 20",
            "record 2 - 20\nrecord 1 - 10",
        ),
        good.replace("END\n", "record 3 - 30\nEND\n"),
        good.replace("record 1", "record 0"),
        good.replace("record 1", "record 01"),
        good.replace("record 1", "record 18446744073709551616"),
        good.replace("record 1", "RECORD 1"),
        good.replace("END\n", ""),
    ] {
        refused(&bad, &functions);
    }
}

pub(in crate::normal) fn value_columns_refuse_missing_extra_noncanonical_or_overflowed_values() {
    let functions = ids(2);
    let good = table_text(&functions, 1);
    for replacement in [
        "record 1 -",
        "record 1 - 10",
        "record 1 - 10 11 12",
        "record 1 - -1 11",
        "record 1 - +10 11",
        "record 1 - 010 11",
        "record 1 - 0x10 11",
        "record 1 - 18446744073709551616 11",
        "record 1 - 10 eleven",
    ] {
        refused(&good.replace("record 1 - 10 11", replacement), &functions);
    }
}

pub(in crate::normal) fn payloads_preserve_existing_printable_csv_grammar_and_64_byte_bound() {
    let functions = ids(1);
    let one = |hex: &str| format!("LI2SELECTED 1 1 1\nfunctions 7\nrecord 1 {hex} 0\nEND\n");
    for hex in ["-", "61", "613d622c63", "22613d62222c63"] {
        assert!(Table::parse(one(hex).as_bytes(), &functions).is_ok());
    }
    let exact = "61".repeat(64);
    let table = parse(&one(&exact), &functions);
    let record = input::Record::new(1, &[b'a'; 64]).unwrap();
    assert_eq!(table.row(&record).unwrap().expected(&record, 0), 0);
    for hex in [
        "", "a", "6A", "gg", "--", "00", "0a", "1f", "7f", "80", "612262", "2261", "22612278",
    ] {
        refused(&one(hex), &functions);
    }
    refused(&one(&"61".repeat(65)), &functions);
}

pub(in crate::normal) fn row_lookup_binds_input_id_bytes_and_complete_population() {
    let functions = ids(1);
    let table = parse(
        "LI2SELECTED 1 1 2\nfunctions 7\nrecord 1 61 1\nrecord 2 62 2\nEND\n",
        &functions,
    );
    let first = input::Record::new(1, b"a").unwrap();
    assert_eq!(table.row(&first).unwrap().expected(&first, 0), 1);
    for record in [
        input::Record::new(1, b"b").unwrap(),
        input::Record::new(2, b"a").unwrap(),
        input::Record::new(3, b"a").unwrap(),
        input::Record::new(1, b"").unwrap(),
    ] {
        assert!(table.row(&record).is_err());
    }
}

pub(in crate::normal) fn returned_row_rechecks_input_and_column_before_exposing_expected_value() {
    let table = parse(&table_text(&ids(1), 1), &ids(1));
    let record = input::Record::new(1, b"").unwrap();
    let row = table.row(&record).unwrap();
    panics(|| {
        row.expected(&record, 1);
    });
    panics(|| {
        row.expected(&record, usize::MAX);
    });
    panics(|| {
        row.expected(&input::Record::new(2, b"").unwrap(), 0);
    });
    panics(|| {
        row.expected(&input::Record::new(1, b"a").unwrap(), 0);
    });
    for dimension in [0, 2, 5] {
        let malformed = Row {
            record: record.clone(),
            dimension,
            values: vec![10].into_boxed_slice(),
        };
        panics(|| {
            malformed.expected(&record, 0);
        });
    }
}

pub(in crate::normal) fn completion_refuses_early_eof_and_excess_even_with_valid_prefix() {
    let table = parse(&table_text(&ids(1), 2), &ids(1));
    let first = input::Record::new(1, b"").unwrap();
    assert!(table.row(&first).is_ok());
    assert!(table.complete(0).is_err());
    assert!(table.complete(1).is_err());
    assert!(table.complete(2).is_ok());
    assert!(table.complete(3).is_err());
    assert!(table.complete(usize::MAX).is_err());
}

pub(in crate::normal) fn argument_loading_uses_exact_selected_functions_and_separate_table_path() {
    for n in 1..=4 {
        let calls = Cell::new(0);
        let (k, epochs, selections, table) = arguments_with(&args(n), |path, functions| {
            calls.set(calls.get() + 1);
            assert_eq!(path, Path::new("frozen.txt"));
            assert_eq!(functions, ids(n));
            Table::parse(table_text(functions, 1).as_bytes(), functions)
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!((k, epochs), (10, 520));
        assert_eq!(selections.len(), n);
        assert_eq!(table.functions(), ids(n));
        for (i, selection) in selections.iter().enumerate() {
            assert_eq!(selection.function, FunctionId((i as u64 + 1) * 7));
            assert_eq!(selection.label.as_str(), format!("selected_{i}"));
        }
    }
}

pub(in crate::normal) fn argument_limits_and_canonical_numbers_remain_closed() {
    for (index, value) in [
        (3, "0"),
        (3, "11"),
        (3, "010"),
        (3, "+10"),
        (4, "0"),
        (4, "521"),
        (4, "4294967296"),
        (5, "0"),
        (5, "5"),
        (5, "01"),
        (6, "-1"),
        (6, "18446744073709551616"),
        (8, "0"),
        (8, "4096x"),
    ] {
        let mut bad = args(1);
        bad[index] = OsString::from(value);
        let called = Cell::new(false);
        assert!(
            arguments_with(&bad, |_, _| {
                called.set(true);
                Err("unexpected loader".into())
            })
            .is_err()
        );
        assert!(!called.get());
    }
    let mut extra = args(1);
    extra.push(OsString::from("extra"));
    assert!(parsed_args(&extra).is_err());
    for length in 0..args(1).len() {
        assert!(parsed_args(&args(1)[..length]).is_err());
    }
    for k in ["10", "1000"] {
        for epochs in ["1", "520"] {
            let mut good = args(1);
            good[3] = OsString::from(k);
            good[4] = OsString::from(epochs);
            assert!(parsed_args(&good).is_ok());
        }
    }
}

pub(in crate::normal) fn selections_reject_duplicate_ids_labels_overlap_order_and_extent_overflow()
{
    for (index, value) in [
        (11, "7"),
        (12, "selected_0"),
        (13, "4096"),
        (13, "4127"),
        (13, "4000"),
        (13, "18446744073709551615"),
        (7, "has,comma"),
        (7, "_bad"),
        (7, "é"),
        (10, "unknown"),
    ] {
        let mut bad = args(2);
        bad[index] = OsString::from(value);
        let called = Cell::new(false);
        assert!(
            arguments_with(&bad, |_, _| {
                called.set(true);
                Err("unexpected loader".into())
            })
            .is_err()
        );
        assert!(!called.get());
    }
    let mut adjacent = args(2);
    adjacent[13] = OsString::from("4128");
    assert!(parsed_args(&adjacent).is_ok());
}

pub(in crate::normal) fn preparation_policies_keep_exact_extent_bounds() {
    for (policy, extent, accepted) in [
        ("certified", 0, false),
        ("certified", 1, true),
        ("certified", 256, true),
        ("certified", 257, false),
        ("whole", 4, false),
        ("whole", 5, true),
        ("whole", 80, true),
        ("whole", 81, false),
    ] {
        let mut input = args(1);
        input[9] = OsString::from(extent.to_string());
        input[10] = OsString::from(policy);
        assert_eq!(parsed_args(&input).is_ok(), accepted);
    }
}

pub(in crate::normal) fn complete_table_load_failure_cannot_fall_back_to_derived_operations() {
    let called = Cell::new(0);
    let result = arguments_with(&args(1), |path, functions| {
        called.set(called.get() + 1);
        assert_eq!(path, Path::new("frozen.txt"));
        assert_eq!(functions, ids(1));
        Err("exact frozen table acquisition refused".into())
    });
    assert_eq!(called.get(), 1);
    assert_eq!(
        result.err().as_deref(),
        Some("exact frozen table acquisition refused")
    );
}
