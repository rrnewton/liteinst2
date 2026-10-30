//! New pure producer controls, not the authored corpus or runnable qualification.
//! Fixed complete 80/16 and 107/26 rosters; all selected instructions are five-byte
//! direct jumps to the final C3 head. No old fixture or cap is changed.
use formats::ContentId;
pub struct Case {
    pub original: Vec<u8>,
    pub ledger: Vec<u8>,
    pub planning: Vec<u8>,
    pub runtime: Vec<u8>,
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(b: &[u8]) -> String {
    hex(&ContentId::of(b).0)
}
fn p16(b: &mut [u8], n: usize, x: u16) {
    b[n..n + 2].copy_from_slice(&x.to_le_bytes());
}
fn p32(b: &mut [u8], n: usize, x: u32) {
    b[n..n + 4].copy_from_slice(&x.to_le_bytes());
}
fn p64(b: &mut [u8], n: usize, x: u64) {
    b[n..n + 8].copy_from_slice(&x.to_le_bytes());
}
pub fn case(program: u64) -> Case {
    assert!([1, 2].contains(&program));
    let (heads, selected, name) = if program == 1 {
        (80, 16, "checksum")
    } else {
        (107, 26, "rle-roundtrip")
    };
    let mut original = vec![0; 8192];
    original[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    p16(&mut original, 16, 2);
    p16(&mut original, 18, 62);
    p32(&mut original, 20, 1);
    p64(&mut original, 24, 0x401000);
    p64(&mut original, 32, 64);
    p16(&mut original, 52, 64);
    p16(&mut original, 54, 56);
    p16(&mut original, 56, 3);
    for (i, (kind, flags, off, va, files, mem, align)) in [
        (1, 5, 0, 0x400000, 8192, 8192, 4096),
        (1, 6, 8192, 0x600000, 0, 65536, 4096),
        (0x6474e551, 6, 0, 0, 0, 0, 16),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        p32(&mut original, at, kind);
        p32(&mut original, at + 4, flags);
        for (j, v) in [off, va, va, files, mem, align].into_iter().enumerate() {
            p64(&mut original, at + 8 + j * 8, v);
        }
    }
    let length = selected * 5 + (heads - selected);
    let hook = 0x401000 + length as u64 - 1;
    let mut rows = Vec::new();
    for i in 0..selected {
        let at = 4096 + i * 5;
        original[at] = 0xe9;
        let pc = 0x400000 + at as u64;
        let d = i32::try_from(hook - pc - 5).unwrap();
        original[at + 1..at + 5].copy_from_slice(&d.to_le_bytes());
        rows.push((pc, original[at..at + 5].to_vec()));
    }
    for i in selected * 5..length {
        original[4096 + i] = if i + 1 == length { 0xc3 } else { 0x90 };
        rows.push((0x401000 + i as u64, vec![original[4096 + i]]));
    }
    assert_eq!(rows.len(), heads);
    let mut ledger = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion 4198400 4096 {length}\n",
        digest(&original)
    );
    for (pc, bytes) in rows {
        ledger.push_str(&format!("head {pc} {}\n", hex(&bytes)));
    }
    let ledger = ledger.into_bytes();
    let mut planning = format!(
        "LI2DISASM-POLICY 6\noriginal {}\nledger {}\nneighbor-victims short-only\nneighbor-ownership inherited-t3\npending-selected full-instruction-ownership\nadjacent-pairs original-geometry-jcc-or-routed-jmp-v1\nadjacent-pair-budgets 2 1 2\ntarget fxsave64\ndomain 1\ncarrier 4718592\nlimits 1048576 32 64 262144 128 2097152 1048576 128 2147483648\nnull-hook {hook}\n",
        digest(&original),
        digest(&ledger)
    );
    for i in 0..selected {
        let id = i + 1;
        let page = 0x10000000 + i * 4096;
        let victim = 0x20000000 + i * 4096;
        planning.push_str(&format!("search {id} B1 0 5 1 none 0 0\nallocation {id} selected {page} 1 4096 {page}:4096\nallocation {id} victim {victim} 1 4096 {victim}:4096\n"));
    }
    let planning = planning.into_bytes();
    let runtime=format!("LI2BOOTSTRAP-POLICY 1\nprofile linux-x86-64-static-exec-router-bootstrap-v1\nprogram {name}\noriginal {}\ndisassembly {}\nplanning-policy {}\ninterpreter /pkg/ld.so\nbootstrap /pkg/{name}.so\napp-stack 6291456 65536\nqualification-contract {}\nstartup-limits 4096 4096 4097 112 4096 4096 65536 1048576\ndependency /pkg/ld.so {}\n",digest(&original),digest(&ledger),digest(&planning),digest(b"PURE CONTROL NO SEMANTIC OR NATIVE QUALIFICATION"),digest(b"prospectively pinned loader bytes")).into_bytes();
    Case {
        original,
        ledger,
        planning,
        runtime,
    }
}
