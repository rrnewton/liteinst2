//! Closed semantic inputs for the byte-exact FreeBSD 14.1 strnlen source.
//! These definitions describe useful work, not emitted code or native evidence.
pub const LABEL: &str = "freebsd-strnlen-14.1-v1";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case {
    pub name: &'static str,
    pub bound: usize,
    pub nul: Option<usize>,
    pub expected: u64,
}
pub const CASES: [Case; 8] = [
    Case {
        name: "zero-bound",
        bound: 0,
        nul: None,
        expected: 0,
    },
    Case {
        name: "single-empty",
        bound: 1,
        nul: Some(0),
        expected: 0,
    },
    Case {
        name: "single-nonzero",
        bound: 1,
        nul: None,
        expected: 1,
    },
    Case {
        name: "last-of-two",
        bound: 2,
        nul: Some(1),
        expected: 1,
    },
    Case {
        name: "interior",
        bound: 17,
        nul: Some(8),
        expected: 8,
    },
    Case {
        name: "long-empty",
        bound: 64,
        nul: Some(0),
        expected: 0,
    },
    Case {
        name: "long-last",
        bound: 64,
        nul: Some(63),
        expected: 63,
    },
    Case {
        name: "full-bound",
        bound: 64,
        nul: None,
        expected: 64,
    },
];
pub fn input(case: Case) -> [u8; 64] {
    assert!(CASES.contains(&case), "closed strnlen case");
    let mut bytes = core::array::from_fn(|i| (1 + ((37 * i + 128) % 255)) as u8);
    if let Some(nul) = case.nul {
        bytes[nul] = 0;
    }
    bytes
}
pub fn scalar(case: Case) -> u64 {
    let bytes = input(case);
    let value = bytes[..case.bound]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(case.bound) as u64;
    assert_eq!(value, case.expected, "literal strnlen result");
    value
}
