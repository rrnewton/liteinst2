//! Immutable application correctness inputs; these grant no target-code authority.
use super::*;

#[derive(Clone)]
pub(super) enum Expectations<const N: usize> {
    Builtin([Operation; N]),
    Frozen(Arc<selected::Table>),
}
pub(super) enum Expectation {
    Builtin(Operation),
    Frozen {
        row: Arc<selected::Row>,
        column: usize,
        functions: usize,
    },
}
impl Expectation {
    pub(super) fn value(&self, record: &input::Record, function: usize, n: usize) -> u64 {
        assert!((1..=4).contains(&n) && function < n);
        match self {
            Self::Builtin(operation) => operation.value(record),
            Self::Frozen {
                row,
                column,
                functions,
            } => {
                assert_eq!(*functions, n);
                assert_eq!(*column, function);
                row.expected(record, function)
            }
        }
    }
}
impl<const N: usize> Expectations<N> {
    pub(super) fn frozen(table: Arc<selected::Table>, functions: [FunctionId; N]) -> Self {
        assert!((1..=4).contains(&N));
        assert_eq!(table.functions(), &functions);
        Self::Frozen(table)
    }
    pub(super) fn command(&self) -> &'static str {
        match self {
            Self::Builtin(_) => "normal-leaf-set-session",
            Self::Frozen(_) => "normal-selected-session",
        }
    }
    pub(super) fn wire_version(&self) -> &'static str {
        match self {
            Self::Builtin(_) => "leaf-set-session-v1",
            Self::Frozen(_) => "selected-session-v1",
        }
    }
    pub(super) fn record(&self, record: &input::Record) -> Result<[Expectation; N], String> {
        record.check();
        match self {
            Self::Builtin(operations) => Ok(operations.map(Expectation::Builtin)),
            Self::Frozen(table) => {
                assert_eq!(table.functions().len(), N);
                let row = table.row(record)?;
                // Validate every column before constructing the first call witness.
                for column in 0..N {
                    row.expected(record, column);
                }
                Ok(std::array::from_fn(|column| Expectation::Frozen {
                    row: Arc::clone(&row),
                    column,
                    functions: N,
                }))
            }
        }
    }
    pub(super) fn complete(&self, accepted: usize) -> Result<(), String> {
        match self {
            Self::Builtin(_) => Ok(()),
            Self::Frozen(table) => table.complete(accepted),
        }
    }
}

#[cfg(test)]
pub(in crate::normal) mod controls {
    use super::*;
    fn refuse(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    pub(in crate::normal) fn builtin_models_protocol_and_completion_stay_exact() {
        let source = Expectations::Builtin([
            Operation::Csv,
            Operation::Length,
            Operation::Digits,
            Operation::Spaces,
        ]);
        let record = input::Record::new(1, b"\"1 2\", 3").unwrap();
        let witnesses = source.record(&record).unwrap();
        for (i, value) in [2, 8, 3, 2].into_iter().enumerate() {
            assert_eq!(witnesses[i].value(&record, i, 4), value);
        }
        assert_eq!(source.command(), "normal-leaf-set-session");
        assert_eq!(source.wire_version(), "leaf-set-session-v1");
        for count in [0, 1, 2048] {
            assert!(source.complete(count).is_ok());
        }
    }
    fn frozen() -> Expectations<2> {
        let table = selected::Table::parse(
            b"LI2SELECTED 1 2 2\nfunctions 71 72\nrecord 1 413d62 1 18446744073709551615\nrecord 2 - 0 66\nEND\n",
            &[FunctionId(71), FunctionId(72)],
        ).unwrap();
        Expectations::frozen(Arc::new(table), [FunctionId(71), FunctionId(72)])
    }
    pub(in crate::normal) fn frozen_witnesses_bind_complete_row_function_and_dimension() {
        let source = frozen();
        let record = input::Record::new(1, b"A=b").unwrap();
        let witnesses = source.record(&record).unwrap();
        assert_eq!(witnesses[0].value(&record, 0, 2), 1);
        assert_eq!(witnesses[1].value(&record, 1, 2), u64::MAX);
        for wrong in [b"A=c".as_slice(), b"A=b ", b""] {
            assert!(
                source
                    .record(&input::Record::new(1, wrong).unwrap())
                    .is_err()
            );
        }
        assert!(
            source
                .record(&input::Record::new(2, b"A=b").unwrap())
                .is_err()
        );
        assert!(source.record(&input::Record::new(3, b"").unwrap()).is_err());
        refuse(|| {
            witnesses[1].value(&record, 0, 2);
        });
        refuse(|| {
            witnesses[1].value(&record, 1, 3);
        });
        refuse(|| {
            witnesses[1].value(&record, 2, 2);
        });
        refuse(|| {
            witnesses[1].value(&input::Record::new(2, b"A=b").unwrap(), 1, 2);
        });
        let Expectations::Frozen(table) = source else {
            unreachable!()
        };
        refuse(|| {
            Expectations::frozen(Arc::clone(&table), [FunctionId(72), FunctionId(71)]);
        });
        refuse(|| {
            Expectations::frozen(Arc::clone(&table), [FunctionId(71)]);
        });
    }
    pub(in crate::normal) fn frozen_witnesses_retain_oracle_and_reject_early_completion() {
        let source = frozen();
        assert_eq!(source.command(), "normal-selected-session");
        assert_eq!(source.wire_version(), "selected-session-v1");
        for count in [0, 1, 3, 2048] {
            assert!(source.complete(count).is_err());
        }
        assert!(source.complete(2).is_ok());
        let record = input::Record::new(2, b"").unwrap();
        let worker = source.record(&record).unwrap();
        let controller = source.record(&record).unwrap();
        drop(source);
        for (i, value) in [0, 66].into_iter().enumerate() {
            assert_eq!(worker[i].value(&record, i, 2), value);
            assert_eq!(controller[i].value(&record, i, 2), value);
        }
    }
}
