use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shape {
    B1,
    B2,
    T1,
    T2,
    T3,
    Upstream,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Semantics {
    Observe,
    Replace,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Api {
    Leaf,
    Engine,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scenario {
    Plain,
    Prefix { len: usize, prefixes: usize },
    PunLength(usize),
    T2Prefix,
    Preferred,
    Budget,
    Incomplete,
    Midpoint,
    Aggregate,
    NoSubstitute,
    T2Precedence,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Success,
    NoPatchWindow,
    AllocationUnavailable,
    UnresolvedEntry,
    NotInstructionHead,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub name: &'static str,
    pub shape: Shape,
    pub semantics: Semantics,
    pub api: Api,
    pub scenario: Scenario,
    pub expected: Outcome,
    pub images: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Image {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub metadata: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub name: String,
    pub expected: Outcome,
    pub source: Vec<u8>,
    pub inputs: String,
    pub result: String,
    pub images: Vec<Image>,
}
pub const ARENA_BASE: u64 = 0x3000_0000_0000;
pub const ARENA_STRIDE: u64 = 0x2_0000_0000;
pub const SELECTED_WITHIN_ARENA: u64 = 0x8000_0080;

pub fn compare(left: &[Record], right: &[Record]) -> Result<(), String> {
    if left.len() != right.len() {
        return Err("row count changed".into());
    }
    for (index, (a, b)) in left.iter().zip(right).enumerate() {
        if a != b {
            return Err(format!(
                "exact record mismatch at {index}: {} / {}",
                a.name, b.name
            ));
        }
    }
    Ok(())
}
pub fn comparator_calibrations() {
    let base = Record {
        name: "calibration".into(),
        expected: Outcome::Success,
        source: vec![0x90],
        inputs: "input".into(),
        result: "full contract and attempts".into(),
        images: vec![Image {
            address: 123,
            bytes: vec![0x90],
            metadata: "all PC maps".into(),
        }],
    };
    assert!(compare(std::slice::from_ref(&base), std::slice::from_ref(&base)).is_ok());
    for field in 0..9 {
        let mut bad = base.clone();
        match field {
            0 => bad.name.push('x'),
            1 => bad.expected = Outcome::NoPatchWindow,
            2 => bad.source[0] ^= 1,
            3 => bad.inputs.push('x'),
            4 => bad.result.push('x'),
            5 => bad.images[0].address += 1,
            6 => bad.images[0].bytes[0] ^= 1,
            7 => bad.images[0].metadata.push('x'),
            8 => bad.images.clear(),
            _ => unreachable!(),
        }
        assert!(compare(std::slice::from_ref(&base), &[bad]).is_err());
    }
    assert!(compare(std::slice::from_ref(&base), &[]).is_err());
    let mut second = base.clone();
    second.name = "second".into();
    assert!(compare(&[base.clone(), second.clone()], &[second, base]).is_err());
}
pub fn inventory(rows: &[Row]) -> String {
    let mut out = String::from("index\tname\tshape\tsemantics\tapi\tscenario\texpected\timages\n");
    for (index, row) in rows.iter().enumerate() {
        writeln!(
            &mut out,
            "{index}\t{}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{}",
            row.name, row.shape, row.semantics, row.api, row.scenario, row.expected, row.images
        )
        .unwrap();
    }
    out
}
