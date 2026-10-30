//! Literal source-only framing checkpoint 99be9bad...; outcomes remain UNRUN.
//! Data members are frozen before tests and must not follow runtime outcomes.
pub struct Fixture {
    pub hex: &'static str,
    pub original_bytes: usize,
    pub ledger: &'static [u8],
    pub policy: &'static [u8],
    pub original_sha256: &'static str,
    pub ledger_sha256: &'static str,
    pub policy_sha256: &'static str,
    pub heads: usize,
    pub selected: usize,
}
impl Fixture {
    pub fn original(&self) -> Vec<u8> {
        let text = self.hex.trim_end();
        assert_eq!(text.len(), self.original_bytes * 2);
        text.as_bytes()
            .chunks_exact(2)
            .map(|p| {
                let digit = |b| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => panic!("literal lowercase hex"),
                };
                digit(p[0]) * 16 + digit(p[1])
            })
            .collect()
    }
}
pub const PRIMARY: Fixture = Fixture {
    original_bytes: 8192,
    hex: include_str!("adjacent_routed_jmp/primary.hex"),
    ledger: include_bytes!("adjacent_routed_jmp/primary.ledger"),
    policy: include_bytes!("adjacent_routed_jmp/primary.policy"),
    original_sha256: "ea26bfca02f17ec8920beb9b5a12a82fe536bcb38cfdc0628e4a02daecf8db86",
    ledger_sha256: "62b7bc103c2c4f9a28fce5e3760a686c73954dd2c0f8934b92648f0e3d66cc60",
    policy_sha256: "7bf21c4d913aa07605031d9c747496189e15ade41a566e072da5e05d45d70bbe",
    heads: 4082,
    selected: 2,
};
pub const PREDECESSOR: Fixture = Fixture {
    original_bytes: 8192,
    hex: include_str!("adjacent_routed_jmp/predecessor.hex"),
    ledger: include_bytes!("adjacent_routed_jmp/predecessor.ledger"),
    policy: include_bytes!("adjacent_routed_jmp/predecessor.policy"),
    original_sha256: "bece24c9f11867e9620873697f7f9e8940dac22459d37e448395e92e0ae3d283",
    ledger_sha256: "a182cf137c565184921b61c1ab9d4ea8c1fb4f01963e088e5db224b1c6ef1f91",
    policy_sha256: "465a842f6bffaef517560411268874746502174ce4f9c8b803965f3fe3e7140f",
    heads: 4078,
    selected: 3,
};

pub const COMBINED: Fixture = Fixture {
    original_bytes: 12288,
    hex: include_str!("adjacent_routed_jmp/combined.hex"),
    ledger: include_bytes!("adjacent_routed_jmp/combined.ledger"),
    policy: include_bytes!("adjacent_routed_jmp/combined.policy"),
    original_sha256: "cd63a537bbfe2d63ea288580c474dd057cd343de3f2af2368b0d70c744d0cf4e",
    ledger_sha256: "9995fbec7f11b773e93f538baf05e4ddbd46ff66407049cb3baed6f6d25ea6d3",
    policy_sha256: "d0c5d59f39b5daba2e2f31ad1bb1d2dc05f02983071ed2a5b0e60ccd5fcbb44e",
    heads: 4086,
    selected: 4,
};
