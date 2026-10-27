//! Four fully authored call-free loops. No arbitrary-byte admission is implied.
use iced_x86::{FlowControl, Mnemonic};
use liteinst2::scanner::InstructionScanner;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Case {
    Countdown,
    Signed,
    Unsigned,
    Direct,
}
pub const CASES: [Case; 4] = [Case::Countdown, Case::Signed, Case::Unsigned, Case::Direct];
impl Case {
    pub fn name(self) -> &'static str {
        match self {
            Self::Countdown => "countdown-jnz",
            Self::Signed => "signed-jg",
            Self::Unsigned => "unsigned-jb",
            Self::Direct => "direct-jmp",
        }
    }
    pub fn parse(name: &str) -> Self {
        CASES
            .into_iter()
            .find(|c| c.name() == name)
            .expect("exact declared case")
    }
    pub fn bytes(self) -> Vec<u8> {
        // SysV: n in RDI, the exclusive 4096-byte result page in RSI. n is 1..=4096.
        // RAX=accumulator, RCX=remaining/index, RDX=iterations. All other GPRs
        // are untouched by the authored function. No stack or external memory use.
        let mut b = vec![0x31, 0xc0, 0x31, 0xd2]; // xor eax,eax; xor edx,edx
        if self == Self::Unsigned {
            b.extend([0x31, 0xc9]);
        }
        // xor ecx,ecx
        else {
            b.extend([0x48, 0x89, 0xf9]);
        } // mov rcx,rdi
        let body = b.len();
        if self == Self::Unsigned {
            b.extend([0x48, 0x83, 0xc0, 0x03]);
        }
        // add rax,3
        else {
            b.extend([0x48, 0x01, 0xc8]);
        } // add rax,rcx
        b.extend([0x48, 0xff, 0xc2]); // inc rdx
        if self == Self::Unsigned {
            b.extend([0x48, 0xff, 0xc1]);
        }
        // inc rcx
        else {
            b.extend([0x48, 0xff, 0xc9]);
        } // dec rcx
        // MOV preserves the original branch flags. The controller observes these
        // exact words only after the worker has synchronously parked.
        b.extend([
            0x48, 0x89, 0x06, 0x48, 0x89, 0x4e, 0x08, 0x48, 0x89, 0x56, 0x10,
        ]);
        if self == Self::Unsigned {
            b.extend([0x48, 0x39, 0xf9]);
        } // cmp rcx,rdi
        if self == Self::Direct {
            b.extend([0x74, 0x05]);
        } // jz over the complete near JMP
        let branch = b.len();
        match self {
            Self::Countdown => b.extend([0x0f, 0x85]),
            Self::Signed => b.extend([0x0f, 0x8f]),
            Self::Unsigned => b.extend([0x0f, 0x82]),
            Self::Direct => b.push(0xe9),
        }
        let next = b.len() + 4;
        b.extend(
            i32::try_from(body as i64 - next as i64)
                .unwrap()
                .to_le_bytes(),
        );
        b.push(0xc3);
        let admitted = admit(&b, 0x10000).expect("authored corpus must admit");
        assert_eq!(admitted.offset, branch);
        b
    }
    pub fn expected(self, n: u64) -> (u64, [u64; 3], u64, u64) {
        assert!((1..=4096).contains(&n));
        let sum = if self == Self::Unsigned {
            3 * n
        } else {
            n * (n + 1) / 2
        };
        (
            sum,
            [sum, if self == Self::Unsigned { n } else { 0 }, n],
            n - 1,
            if self == Self::Direct { n - 1 } else { n },
        )
    }
}

#[derive(Clone, Debug)]
pub struct Site {
    pub offset: usize,
    pub length: usize,
    pub condition: Option<u8>,
    pub heads: Vec<u64>,
}
pub fn admit(bytes: &[u8], base: u64) -> Result<Site, &'static str> {
    if bytes.is_empty() || bytes.len() > 256 {
        return Err("finite source size");
    }
    let scan = InstructionScanner::default()
        .scan(bytes, base)
        .map_err(|_| "decode")?;
    let heads: Vec<_> = scan.instructions().iter().map(|x| x.address()).collect();
    let mut backward = Vec::new();
    for item in scan.instructions() {
        let i = item.instruction();
        match i.flow_control() {
            FlowControl::Next => {
                if !matches!(
                    i.mnemonic(),
                    Mnemonic::Mov
                        | Mnemonic::Xor
                        | Mnemonic::Add
                        | Mnemonic::Inc
                        | Mnemonic::Dec
                        | Mnemonic::Cmp
                ) {
                    return Err("unsupported ordinary instruction");
                }
            }
            FlowControl::Return
                if i.mnemonic() == Mnemonic::Ret && item.offset() + item.len() == bytes.len() => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if !heads.contains(&i.near_branch_target()) {
                    return Err("non-head target");
                }
                if i.near_branch_target() <= i.ip() {
                    let raw = &bytes[item.offset()..item.offset() + item.len()];
                    let condition = match raw {
                        [0xe9, _, _, _, _] => None,
                        [0x0f, cc @ 0x80..=0x8f, _, _, _, _] => Some(*cc & 15),
                        _ => return Err("backward branch requires exact near encoding"),
                    };
                    backward.push((item.offset(), item.len(), condition));
                }
            }
            _ => return Err("calls/indirect/faulting/system transfers unsupported"),
        }
    }
    if backward.len() != 1 {
        return Err("exactly one declared backward site");
    }
    let (offset, length, condition) = backward[0];
    Ok(Site {
        offset,
        length,
        condition,
        heads,
    })
}

pub fn taken(cc: Option<u8>, flags: u64) -> bool {
    let (c, p, z, s, o) = (
        flags & 1 != 0,
        flags & 4 != 0,
        flags & 64 != 0,
        flags & 128 != 0,
        flags & 2048 != 0,
    );
    match cc {
        None => true,
        Some(0) => o,
        Some(1) => !o,
        Some(2) => c,
        Some(3) => !c,
        Some(4) => z,
        Some(5) => !z,
        Some(6) => c || z,
        Some(7) => !c && !z,
        Some(8) => s,
        Some(9) => !s,
        Some(10) => p,
        Some(11) => !p,
        Some(12) => s != o,
        Some(13) => s == o,
        Some(14) => z || s != o,
        Some(15) => !z && s == o,
        _ => panic!("invalid condition identity"),
    }
}
