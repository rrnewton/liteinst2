use super::*;

fn packed(f: &verify::tests::Fixture) -> Vec<u8> {
    let mut files = BTreeMap::from([("input/original".to_string(), f.original.clone())]);
    for (n, b) in &f.expected.files {
        files.insert(format!("expected/{n}"), b.clone());
    }
    for (n, b) in &f.product.0 {
        files.insert(format!("product/{n}"), b.clone());
    }
    let mut out =
        format!("LI2W01-INPUT\t1\t{}\t{}\n", f.expected.program, files.len()).into_bytes();
    for (name, b) in files {
        out.extend_from_slice(format!("{name}\t{}\t{}\n", b.len(), digest(&b)).as_bytes());
        out.extend_from_slice(&b);
    }
    out.extend_from_slice(b"END\n");
    out
}
#[test]
fn v06_bounded_transport_positive_then_identity_count_size_and_trailing_mutants() {
    let f = verify::tests::fixture("checksum", true);
    let bytes = packed(&f);
    let (p, o, e, product) = transport(&mut bytes.as_slice()).unwrap();
    indices(&o, &product).unwrap();
    assert!(verify::verify(&p, &o, &e, &product).is_ok());
    for offset in [0, 5, 10, bytes.len() - 2] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(transport(&mut bad.as_slice()).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(transport(&mut extra.as_slice()).is_err());
    for head in [
        "LI2W01-INPUT\t1\tchecksum\t263\n",
        "LI2W01-INPUT\t1\trle-roundtrip\t0\n",
        "LI2W01-INPUT\t1\tunknown\t6\n",
    ] {
        assert!(transport(&mut head.as_bytes()).is_err());
    }
    let oversized = format!(
        "LI2W01-INPUT\t1\tchecksum\t6\nexpected/selection.txt\t{}\t{}\n",
        TEXT + 1,
        "0".repeat(64)
    );
    assert!(transport(&mut oversized.as_bytes()).is_err());
    let line = vec![b'x'; 256];
    assert!(super::line(&mut line.as_slice()).is_err());
}

#[test]
fn c03_framing_is_separate_without_any_body_limit_increase() {
    assert_eq!(BODY_BYTES, 70 * 1_048_576);
    assert_eq!(FRAMING_BYTES, 264 * 256);
    transport_bound(TRANSPORT_BYTES as u64).unwrap();
    assert!(transport_bound(TRANSPORT_BYTES as u64 + 1).is_err());
    let mut body = vec![b'x'; 255];
    body.push(b'\n');
    assert_eq!(line(&mut body.as_slice()).unwrap().len(), 255);
    let mut too_long = vec![b'x'; 256];
    too_long.push(b'\n');
    assert!(line(&mut too_long.as_slice()).is_err());
    for program in ["checksum", "rle-roundtrip"] {
        let f = verify::tests::routed_fixture(program);
        let bytes = packed(&f);
        let (p, o, e, product) = transport(&mut bytes.as_slice()).unwrap();
        indices(&o, &product).unwrap();
        assert!(verify::verify(&p, &o, &e, &product).is_ok());
    }
}
