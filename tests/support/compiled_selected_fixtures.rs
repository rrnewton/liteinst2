//! Exact d696 release bodies, with their original 48-byte separation. See STATE.md.
//! All heads, control flow, reads and answers below are independent of a decoder.
pub const FIRST: &[u8] = &[
    0x48, 0x89, 0xf0, 0x48, 0x85, 0xf6, 0x74, 0x1a, 0x31, 0xd2, 0xeb, 0x0d, 0x0f, 0x1f, 0x40, 0x00,
    0x48, 0x83, 0xc2, 0x01, 0x48, 0x39, 0xd0, 0x74, 0x0f, 0x80, 0x3c, 0x17, 0x3d, 0x75, 0xf1, 0x48,
    0x89, 0xd0, 0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xc3,
];
pub const UPPER: &[u8] = &[
    0x48, 0x85, 0xf6, 0x74, 0x2b, 0x48, 0x01, 0xfe, 0x45, 0x31, 0xc0, 0x0f, 0x1f, 0x44, 0x00, 0x00,
    0x0f, 0xb6, 0x07, 0x83, 0xe8, 0x41, 0x3c, 0x1a, 0x49, 0x83, 0xd0, 0x00, 0x48, 0x83, 0xc7, 0x01,
    0x48, 0x39, 0xf7, 0x75, 0xeb, 0x4c, 0x89, 0xc0, 0xc3, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xc0, 0x4c, 0x89, 0xc0, 0xc3,
];
pub const BODIES: [&[u8]; 2] = [FIRST, UPPER];
pub const OFFSETS: [usize; 2] = [0, 48];
pub const HEADS: [&[usize]; 2] = [
    &[0, 3, 6, 8, 10, 12, 16, 20, 23, 25, 29, 31, 34, 35, 40],
    &[
        0, 3, 5, 8, 11, 16, 19, 22, 24, 28, 32, 35, 37, 40, 41, 48, 51, 54,
    ],
];
pub const LEADERS: [&[usize]; 2] = [&[0, 8, 16, 25, 31, 34, 40], &[0, 5, 16, 37, 48]];
pub const RETURNS: [[usize; 2]; 2] = [[34, 40], [40, 54]];
pub const INPUTS: [&[u8]; 12] = [
    b"",
    b"a",
    b"=",
    b"a=b",
    b"ABC=def",
    b"\"A=B\",C",
    b"\"\"",
    b"\"A\"\"B\",c",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    b"================================================================",
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
    b"                                                                ",
];
pub const SEEDS: [u64; 2] = [0x1234_5678_8765_0000, 0x1234_5678_8765_0cd5];
pub const SETUP: usize = 0x100;

pub fn fixture(input: &[u8], selected: usize) -> (Vec<u8>, Vec<usize>) {
    assert!(input.len() <= 64 && selected < 2);
    let mut bytes = FIRST.to_vec();
    bytes.extend_from_slice(&[0x0f, 0x1f, 0x80, 0, 0, 0, 0]);
    bytes.extend_from_slice(UPPER);
    assert_eq!(bytes.len(), 103);
    bytes.resize(SETUP, 0xcc);
    let mut heads = Vec::new();
    let mut data = [0xa5; 64];
    data[..input.len()].copy_from_slice(input);
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        heads.push(bytes.len());
        bytes.extend_from_slice(&[0xc7, 0x47, (i * 4) as u8]); // MOV dword [RDI+disp8],imm32.
        bytes.extend_from_slice(chunk);
    }
    heads.push(bytes.len());
    bytes.push(0xbe); // MOV ESI, length; all setup preserves flags and RDI.
    bytes.extend_from_slice(&(input.len() as u32).to_le_bytes());
    heads.push(bytes.len());
    let delta = OFFSETS[selected] as i32 - (bytes.len() as i32 + 5);
    bytes.push(0xe9);
    bytes.extend_from_slice(&delta.to_le_bytes());
    assert_eq!(heads.len(), 18);
    (bytes, heads)
}

pub struct Expected {
    pub visits: Vec<usize>,
    pub reads: Vec<usize>,
    pub ret: usize,
    pub answer: u64,
}

pub fn expected(input: &[u8], selected: usize) -> Expected {
    assert!(input.len() <= 64 && selected < 2);
    let answer = if selected == 0 {
        input.iter().position(|&b| b == b'=').unwrap_or(input.len()) as u64
    } else {
        input.iter().filter(|&&b| b.is_ascii_uppercase()).count() as u64
    };
    let mut visits = vec![0, 3];
    let mut reads = Vec::new();
    let ret;
    if selected == 0 {
        visits.push(6);
        if input.is_empty() {
            ret = 34;
        } else {
            visits.extend([8, 10]);
            let mut index = 0;
            loop {
                visits.extend([25, 29]);
                reads.push(index);
                if input[index] == b'=' {
                    visits.push(31);
                    ret = 34;
                    break;
                }
                visits.extend([16, 20, 23]);
                index += 1;
                if index == input.len() {
                    ret = 40;
                    break;
                }
            }
        }
    } else if input.is_empty() {
        visits.extend([48, 51]);
        ret = 54;
    } else {
        visits.extend([5, 8, 11]);
        for index in 0..input.len() {
            visits.extend([16, 19, 22, 24, 28, 32, 35]);
            reads.push(index);
        }
        visits.push(37);
        ret = 40;
    }
    visits.push(ret);
    Expected {
        visits,
        reads,
        ret,
        answer,
    }
}

#[test]
fn literal_answers_and_complete_reachable_population_are_frozen() {
    let answers = [
        [0, 1, 0, 1, 3, 2, 2, 8, 64, 0, 63, 64],
        [0, 0, 0, 0, 3, 3, 0, 2, 64, 0, 0, 0],
    ];
    for selected in 0..2 {
        let mut visited = std::collections::BTreeSet::new();
        let mut returns = std::collections::BTreeSet::new();
        for (index, input) in INPUTS.iter().enumerate() {
            let e = expected(input, selected);
            assert_eq!(e.answer, answers[selected][index]);
            assert!(e.reads.iter().all(|&at| at < input.len()));
            assert!(e.visits.iter().all(|at| HEADS[selected].contains(at)));
            visited.extend(e.visits);
            returns.insert(e.ret);
        }
        let padding: &[usize] = if selected == 0 { &[12, 35] } else { &[41] };
        assert_eq!(
            visited,
            HEADS[selected]
                .iter()
                .copied()
                .filter(|h| !padding.contains(h))
                .collect()
        );
        assert_eq!(returns, RETURNS[selected].into_iter().collect());
    }
}
