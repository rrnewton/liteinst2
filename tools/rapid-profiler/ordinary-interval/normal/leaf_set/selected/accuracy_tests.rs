//! Same immutable selection/table loader, no DSO open or native calls.
use super::*;
use std::cell::Cell;

fn args(k: usize, ms: u32, epochs: u32, n: usize) -> Vec<OsString> {
    let mut a: Vec<_> = [
        "candidate.so".into(),
        "trusted.so".into(),
        "table.txt".into(),
        k.to_string(),
        ms.to_string(),
        epochs.to_string(),
        n.to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for i in 0..n {
        a.extend(
            [
                ((i + 1) * 7).to_string(),
                format!("selected_{i}"),
                (4096 + i * 256).to_string(),
                "37".into(),
                "whole".into(),
            ]
            .map(OsString::from),
        );
    }
    a
}
fn table(functions: &[FunctionId]) -> Table {
    let n = functions.len();
    let count = record_cap(n);
    let mut raw = format!("LI2SELECTED 1 {n} {count}\nfunctions");
    for function in functions {
        raw.push_str(&format!(" {}", function.0));
    }
    raw.push('\n');
    for id in 1..=count {
        raw.push_str(&format!("record {id} 41"));
        for _ in 0..n {
            raw.push_str(" 65");
        }
        raw.push('\n');
    }
    raw.push_str("END\n");
    Table::parse(raw.as_bytes(), functions).unwrap()
}

#[test]
fn full_matrix_preserves_every_selected_function_and_full_input_denominator() {
    for k in [1, 10, 100, 1000] {
        for ms in [1, 10, 100] {
            for n in 1..=4 {
                let calls = Cell::new(0);
                let (policy, selected, frozen) =
                    accuracy_arguments_with(&args(k, ms, 520, n), |path, functions| {
                        calls.set(calls.get() + 1);
                        assert_eq!(path, Path::new("table.txt"));
                        assert_eq!(
                            functions,
                            (1..=n)
                                .map(|i| FunctionId(i as u64 * 7))
                                .collect::<Vec<_>>()
                        );
                        Ok(table(functions))
                    })
                    .unwrap();
                assert_eq!(calls.get(), 1);
                assert_eq!(policy, Policy::accuracy(k, ms, 520, 4096).unwrap());
                assert_eq!(selected.len(), n);
                assert_eq!(frozen.count(), 2048.min(4096 / n));
                assert!(frozen.complete(frozen.count()).is_ok());
                assert!(frozen.complete(frozen.count() - 1).is_err());
                assert_eq!(
                    frozen.functions(),
                    selected.iter().map(|s| s.function).collect::<Vec<_>>()
                );
                for (i, s) in selected.iter().enumerate() {
                    assert_eq!(s.va, 4096 + i as u64 * 256);
                    assert_eq!(s.extent, 37);
                    assert_eq!(s.policy, Preparation::Whole);
                }
            }
        }
    }
}

#[test]
fn invalid_accuracy_profile_and_selection_refuse_before_table_loading() {
    for (index, bad) in [
        (3, "0"),
        (3, "2"),
        (3, "1001"),
        (3, "+1"),
        (3, "01"),
        (4, "0"),
        (4, "2"),
        (4, "1000"),
        (4, "4294967296"),
        (5, "0"),
        (5, "521"),
        (6, "0"),
        (6, "5"),
        (7, "07"),
        (8, "bad,label"),
        (9, "0"),
        (10, "81"),
        (11, "fallback"),
        (12, "7"),
        (13, "selected_0"),
        (14, "4096"),
    ] {
        let mut a = args(1, 1, 520, 2);
        a[index] = bad.into();
        let called = Cell::new(false);
        assert!(
            accuracy_arguments_with(&a, |_, _| {
                called.set(true);
                Err("loader reached".into())
            })
            .is_err()
        );
        assert!(!called.get(), "{index} {bad}");
    }
    let a = args(1, 1, 1, 1);
    for len in 0..a.len() {
        assert!(accuracy_arguments_with(&a[..len], |_, _| panic!("loader reached")).is_err());
    }
    let mut extra = a;
    extra.push("extra".into());
    assert!(accuracy_arguments_with(&extra, |_, _| panic!("loader reached")).is_err());
}

#[test]
fn table_refusal_remains_terminal_and_old_parser_does_not_accept_new_k_or_grammar() {
    let calls = Cell::new(0);
    let refusal = accuracy_arguments_with(&args(100, 100, 1, 1), |_, _| {
        calls.set(calls.get() + 1);
        Err("frozen table changed".into())
    });
    assert_eq!(refusal.err().as_deref(), Some("frozen table changed"));
    assert_eq!(calls.get(), 1);
    for k in [1, 100] {
        let mut old_shape = args(k, 10, 520, 1);
        old_shape.remove(4);
        assert!(arguments_with(&old_shape, |_, _| panic!("old constructor widened")).is_err());
    }
    for k in [10, 1000] {
        assert!(arguments_with(&args(k, 10, 520, 1), |_, _| panic!("grammar confused")).is_err());
    }
}
