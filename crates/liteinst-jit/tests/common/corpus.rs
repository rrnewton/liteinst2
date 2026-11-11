//! I1-H corpus freeze: every signal fixture's bytes are pinned
//! by SHA-256 in `SIGNAL-CORPUS.md`, under a stable ID. Each test
//! calls [`check`] right after it builds its fixture and before
//! it runs anything, so a changed fixture fails here, by ID,
//! before any behavioural assertion. Updating a row is a visible,
//! reviewed edit of that file.
//!
//! Regenerating: set `LITEINST_CORPUS_RECORD` to a file path and
//! run the tests. `check` then appends `ID SHA256` lines there
//! instead of asserting. Review the diff before copying the
//! hashes into the table.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

const TABLE: &str = include_str!("../../SIGNAL-CORPUS.md");

/// IDs already checked in this process, with their hash: one ID
/// must always name the same bytes.
static SEEN: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

/// SHA-256 (FIPS 180-4), for fixture pinning only.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*c);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `ID -> sha256` from the table rows of `SIGNAL-CORPUS.md`
/// (`| ID | ... | sha256 |`, the last cell 64 hex digits).
pub fn table() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in TABLE.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 {
            continue;
        }
        let id = cells[1].trim_matches('`');
        let hash = cells[cells.len() - 2].trim_matches('`');
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            assert!(
                map.insert(id.to_string(), hash.to_string()).is_none(),
                "SIGNAL-CORPUS.md: duplicate ID {id}"
            );
        }
    }
    map
}

/// Pin `bytes` under `id`: the table's hash must match, and one
/// ID must never name two different fixtures in one process.
pub fn check(id: &str, bytes: &[u8]) {
    let got = hex(&sha256(bytes));
    {
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = seen.insert(id.to_string(), got.clone()) {
            assert_eq!(prev, got, "corpus ID {id} names two different fixtures");
        }
    }
    if let Ok(path) = std::env::var("LITEINST_CORPUS_RECORD") {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("corpus record file");
        // One write per line: concurrent tests append whole lines.
        f.write_all(format!("{id} {got}\n").as_bytes())
            .expect("corpus record");
        return;
    }
    let want = table().get(id).cloned();
    assert_eq!(
        want.as_deref(),
        Some(got.as_str()),
        "SIGNAL-CORPUS.md hash for fixture {id} (computed {got})"
    );
}
