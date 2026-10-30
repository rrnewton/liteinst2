//! Frozen F24 complete-candidate input declaration; all required outcomes UNRUN.
//! Same primary geometry, selected cap 1 and independent U2/L1/J2 as F02.
//! No outcome-derived adjustment, alternate placement or enlarged resource cap.
pub const ORIGINAL_SHA256: &str =
    "8270f32b43b0d478635c0dd5248cd3b2fae9d8f9adf17c980e65816e77bbb7cb";
pub const LEDGER_SHA256: &str = "0475db093a7f1f3130928924cd69d3f894b3f66ed7473ea1f19981451b517991";
pub const POLICY_SHA256: &str = "ce89e603dae976270085e3650ab9085f44b4af82920e5bfd83980427d5e5b833";
pub const LEDGER: &[u8] = b"LI2DISASM 1\noriginal 8270f32b43b0d478635c0dd5248cd3b2fae9d8f9adf17c980e65816e77bbb7cb\ncontract complete-code no-overlap no-code-as-data private-image\nregion 268437241 1785 11\nhead 268437241 7502\nhead 268437243 7500\nhead 268437245 69c001000000\nhead 268437251 c3\n";
pub const POLICY: &[u8] = b"LI2DISASM-POLICY 5\noriginal 8270f32b43b0d478635c0dd5248cd3b2fae9d8f9adf17c980e65816e77bbb7cb\nledger 0475db093a7f1f3130928924cd69d3f894b3f66ed7473ea1f19981451b517991\nneighbor-victims short-only\nneighbor-ownership inherited-t3\npending-selected full-instruction-ownership\nadjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\ntarget fxsave64\ndomain 1\ncarrier 268439552\nlimits 1048576 32 32 131072 128 2097152 1048576 128 2147483648\nnull-hook 268437251\nsearch 1 B2 0 2 1 none 0 0\nallocation 1 selected 2030104576 1 4096 2030104576:4096\nallocation 1 victim 352325632 1 4096 352325632:4096\nsearch 2 B2 0 2 1 none 0 0\nallocation 2 selected 297824384 1 4096 297824256:4096\nallocation 2 victim 352329728 1 4096 352329728:4096\n";
const HEADER: &[u8; 120] = &[
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf9, 0x06, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub fn original() -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..120].copy_from_slice(HEADER);
    bytes[0x6f9..0x704].copy_from_slice(&[0x75, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3]);
    bytes
}
