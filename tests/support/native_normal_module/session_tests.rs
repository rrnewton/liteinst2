//! Fabricated inputs exercise real validators only; no CALL/reap/native credit.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn ready(k: usize, candidate: bool) -> Ready {
    let code = [0xb8, 1, 0, 0, 0, 0xc3];
    let mut source = vec![0; PAGE];
    source[..6].copy_from_slice(&code);
    source[64..70].copy_from_slice(&code);
    let mut helper = vec![0; PAGE];
    helper[..bytes::BYTES.len()].copy_from_slice(bytes::BYTES);
    let functions = [0x3000, 0x3040].map(|entry| Function {
        entry,
        heads: vec![entry, entry + 5],
        returns: vec![entry + 5],
        boundaries: vec![(entry, entry), (entry + 5, entry + 5)],
    });
    Ready {
        caller: 0x1000,
        caller_immutable: vec![(0x1000, helper)],
        functions,
        immutable: vec![(0x3000, source.clone())],
        original_source: source,
        journal: candidate.then_some(JournalReady {
            address: 0x7000,
            a_generation: 11,
            b_generation: None,
            helper_tid: None,
        }),
        case: Case::new_session(0, k, 6, 6, 0),
    }
}

#[test]
fn module_session_profile_and_ready_wire_keep_finite_modes_separate() {
    for k in [10, 1000] {
        let args = SessionArguments::parse(&k.to_string(), "4096", "256", "4352", "80");
        for index in 0..16 {
            for order in 0..2 {
                let c = Case::new_session(index, k, 256, 80, order);
                assert!(c.is_session());
                assert_eq!(c.admitted(), 4);
                assert_eq!(c.csv, csv::Case::new(index));
                assert_eq!(c.length, CASES[index % 8]);
                assert_eq!(c.order, [order, 1 - order]);
                assert_eq!(
                    c.values(),
                    [
                        c.csv.expected(),
                        strnlen::cases::scalar(c.length),
                        c.csv.expected(),
                        strnlen::cases::scalar(c.length)
                    ]
                );
                if order == 0 {
                    assert_eq!(args.case(index), c);
                }
            }
        }
        for candidate in [false, true] {
            let r = ready(k, candidate);
            let wire = r.encode_session();
            assert_eq!(&wire[..8], &SESSION_WIRE.to_le_bytes());
            let decoded = Ready::decode_session(&wire);
            r.same_source(&decoded);
            decoded.validate(candidate, r.case);
            refuses(|| {
                Ready::decode(&wire);
            });
            refuses(|| {
                r.encode();
            });
            let mut old = r.clone();
            old.case = Case::new(0, 16, 6, 6, 0);
            let oldwire = old.encode();
            refuses(|| {
                Ready::decode_session(&oldwire);
            });
            refuses(|| {
                old.encode_session();
            });
            refuses(|| {
                Ready::decode_session(&wire[8..]);
            });
            let mut extra = wire.clone();
            extra.push(0);
            refuses(|| {
                Ready::decode_session(&extra);
            });
            refuses(|| {
                Ready::decode_session(&wire[..wire.len() - 1]);
            });
            for (at, word) in [(0, 0), (24, 16), (64, 257)] {
                let mut bad = wire.clone();
                bad[at..at + 8].copy_from_slice(&u64::to_le_bytes(word));
                refuses(|| {
                    Ready::decode_session(&bad);
                });
            }
            refuses(|| {
                Ready::decode_session(&vec![0; WIRE_LIMIT + 1]);
            });
        }
    }
    for k in ["1", "16", "010", "0", "1001", "18446744073709551615"] {
        refuses(|| {
            SessionArguments::parse(k, "4096", "6", "4160", "6");
        });
    }
    for k in ["10", "1000"] {
        refuses(|| {
            Arguments::parse(k, "4096", "6", "4160", "6");
        });
    }
    for (a, b, c, d) in [
        ("4096", "257", "8192", "80"),
        ("4096", "256", "8192", "81"),
        ("4096", "4", "8192", "6"),
        ("4096", "6", "4097", "6"),
    ] {
        refuses(|| {
            SessionArguments::parse("10", a, b, c, d);
        });
    }
    refuses(|| {
        Case::new_session(16, 10, 6, 6, 0);
    });
    refuses(|| {
        Case::new_session(0, 10, 6, 6, 2);
    });
}
#[test]
fn module_session_ready_retains_complete_geometry_and_identity() {
    for k in [10, 1000] {
        for candidate in [false, true] {
            let r = ready(k, candidate);
            assert_eq!(r.validate(candidate, r.case).len(), 4);
            for mutation in 0..10 {
                let mut bad = r.clone();
                match mutation {
                    0 => bad.original_source[64] = 0xc3,
                    1 => {
                        let _ = bad.functions[1].heads.pop();
                    }
                    2 => bad.functions[1].boundaries[0].1 = bad.functions[0].entry,
                    3 => bad.functions[1].returns[0] = bad.functions[0].returns[0],
                    4 => bad.immutable[0].1[32] = 1,
                    5 => bad.immutable[0].1.push(0),
                    6 => bad.caller_immutable[0].1[31] ^= 1,
                    7 => bad.case.order.swap(0, 1),
                    8 => bad.case = Case::new(0, 16, 6, 6, 0),
                    _ => bad.functions[0].boundaries.clear(),
                };
                refuses(|| {
                    bad.validate(candidate, r.case);
                });
            }
            if candidate {
                for field in 0..4 {
                    let mut bad = r.clone();
                    let j = bad.journal.as_mut().unwrap();
                    match field {
                        0 => j.address = 0x3000,
                        1 => j.a_generation = 0,
                        2 => j.b_generation = Some(99),
                        _ => j.helper_tid = Some(17),
                    };
                    refuses(|| {
                        bad.validate(true, r.case);
                    });
                }
            }
            let mut wrong = r.clone();
            wrong.case = Case::new_session(1, k, 6, 6, 0);
            refuses(|| r.same_source(&wrong));
        }
    }
}
