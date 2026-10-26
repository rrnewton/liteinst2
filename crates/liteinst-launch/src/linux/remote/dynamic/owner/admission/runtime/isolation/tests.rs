//! Pure calibration of the private process protocol; no native sample credit.
use super::*;

const NAME: &str = "linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_expired_original_deadline_keeps_pristine_exec";

fn successful_output() -> String {
    format!(
        "\nrunning 1 test\ntest {NAME} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 490 filtered out; finished in 0.01s\n\n"
    )
}

#[test]
fn runtime_isolation_result_requires_one_exact_successful_test() {
    let good = successful_output();
    assert!(result_matches(good.as_bytes(), NAME));
    let bad = [
        String::new(),
        good.replace("running 1 test", "running 0 tests"),
        good.replace("running 1 test", "running 2 tests"),
        good.replace(" ... ok", " ... FAILED"),
        good.replace(" ... ok", " ... ignored"),
        good.replace("1 passed; 0 failed", "0 passed; 1 failed"),
        good.replace("1 passed; 0 failed", "2 passed; 0 failed"),
        good.replace("0 ignored", "1 ignored"),
        good.replace("0 measured", "1 measured"),
        good.replace("test result: ok.", "test result: FAILED."),
        good.replace("490 filtered out", "-1 filtered out"),
        good.replace("0.01s", "NaNs"),
        good.replace(&format!("test {NAME} ... ok\n"), ""),
        good.replace("test result:", "missing result:"),
        good.replace(NAME, CASES[1]),
        good.replace("\n", "\r\n"),
        format!("{good}test {NAME} ... ok\n"),
        format!("{good}{good}"),
        format!("{good}ignored body completion\n"),
        format!("{good}\0"),
        good.trim_end().to_owned(),
    ];
    for (index, bytes) in bad.iter().enumerate() {
        assert!(
            !result_matches(bytes.as_bytes(), NAME),
            "accepted malformed result {index}"
        );
    }
    assert!(!result_matches(good.as_bytes(), CASES[1]));
    assert!(!result_matches(good.as_bytes(), "unlisted"));
    assert!(!result_matches(&[0xff, b'\n'], NAME));
}

fn identity() -> Identity {
    Identity {
        case: 1,
        parent: 700,
        nonce: 9,
        device: 6,
        inode: 17,
    }
}

// Independent literal wire image: version1/case1/parent700/nonce9/dev6/ino17,
// followed by the matching completion for child701. No encoder makes this fixture.
const RECEIPT: [u8; 128] = [
    82, 84, 73, 83, 79, 72, 48, 49, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 188, 2, 0, 0,
    0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 82, 84, 73, 83, 79, 67, 48, 49, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    188, 2, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0,
    0, 189, 2, 0, 0, 0, 0, 0, 0,
];

#[test]
fn runtime_isolation_receipt_requires_complete_exact_body_identity() {
    let id = identity();
    assert_eq!(Identity::header(&RECEIPT[..64]), Some(id));
    assert_eq!(&RECEIPT[..64], id.bytes(None));
    assert_eq!(&RECEIPT[64..], id.bytes(Some(701)));
    assert!(receipt_matches(&RECEIPT, id, 701));
    for length in 0..128 {
        assert!(!receipt_matches(&RECEIPT[..length], id, 701));
    }
    for index in 0..128 {
        for bit in 0..8 {
            let mut changed = RECEIPT;
            changed[index] ^= 1 << bit;
            assert!(
                !receipt_matches(&changed, id, 701),
                "accepted receipt byte {index} bit {bit}"
            );
        }
    }
    let mut duplicated = RECEIPT.to_vec();
    duplicated.extend_from_slice(&RECEIPT[64..]);
    assert!(!receipt_matches(&duplicated, id, 701));
    assert!(!receipt_matches(&RECEIPT, id, 0));
    assert!(!receipt_matches(&RECEIPT, id, 702));
    for foreign in [
        Identity { case: 2, ..id },
        Identity { parent: 699, ..id },
        Identity { nonce: 10, ..id },
        Identity { device: 7, ..id },
        Identity { inode: 18, ..id },
    ] {
        assert!(!receipt_matches(&RECEIPT, foreign, 701));
    }
}

#[test]
fn runtime_isolation_role_requires_exact_test_and_parent_binding() {
    let id = identity();
    let args = [
        "--exact",
        NAME,
        "--test-threads=1",
        "--format=pretty",
        "--color=never",
    ]
    .map(str::to_owned);
    assert!(role_matches(NAME, NAME, &args, 700, id));
    for role in ["", "1", "owned", CASES[1]] {
        assert!(!role_matches(NAME, role, &args, 700, id));
    }
    for parent in [0, 699, 701] {
        assert!(!role_matches(NAME, NAME, &args, parent, id));
    }
    for length in 0..args.len() {
        assert!(!role_matches(NAME, NAME, &args[..length], 700, id));
    }
    for index in 0..args.len() {
        let mut changed = args.clone();
        changed[index].push('x');
        assert!(!role_matches(NAME, NAME, &changed, 700, id));
    }
    let mut extra = args.to_vec();
    extra.push("--ignored".to_owned());
    assert!(!role_matches(NAME, NAME, &extra, 700, id));
    for foreign in [
        Identity { case: 0, ..id },
        Identity { case: 2, ..id },
        Identity { case: 19, ..id },
        Identity { parent: 701, ..id },
        Identity { nonce: 0, ..id },
        Identity { inode: 0, ..id },
    ] {
        assert!(!role_matches(NAME, NAME, &args, 700, foreign));
    }
    assert!(!role_matches("unlisted", "unlisted", &args, 700, id));
    for index in [0, 8, 16, 24, 32, 48, 56] {
        let mut bad = RECEIPT[..64].to_vec();
        if index == 0 || index == 56 {
            bad[index] ^= 1;
        } else {
            bad[index..index + 8].fill(0);
        }
        assert_eq!(
            Identity::header(&bad),
            None,
            "accepted invalid header at {index}"
        );
    }
    assert_eq!(Identity::header(&[]), None);
    assert_eq!(Identity::header(&RECEIPT), None);
}
