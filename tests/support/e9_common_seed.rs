//! Pure, prospective one-original-instruction seeds for the inspected kernel.
//!
//! This module performs no I/O, mapping, decoding, tracing or candidate admission.
//! Every caller must retain all CASE_COUNT cases, including unreachable NOPs and
//! the two read-only faults. See e9_common_seed.md for the remaining admissions.

pub const ORIGINAL_SHA256: &str =
    "987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8";
pub const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
pub const HEAD_COUNT: usize = 87;
pub const CASE_COUNT: usize = HEAD_COUNT * 2 + 2;
pub const EXPECTED_INSTRUCTIONS: &[u8] = include_bytes!("e9_common_seed.instructions.tsv");
pub const RETURN_PC: u64 = 0x401878;
pub const PAGE_BYTES: usize = 4096;
pub const STACK_BYTES: usize = 65536;
const LOW_END: u64 = 0x0000_8000_0000_0000;
const STACK_BELOW_E: u64 = 32776;
const STACK_ABOVE_E: u64 = 32760;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Function {
    Store,
    Sift,
    Heap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flow {
    Next,
    Jb(u64),
    Jae(u64),
    Jbe(u64),
    Jne(u64),
    Jump(u64),
    Call(u64),
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Memory {
    None,
    ArrayLoad {
        base: Reg,
        index: Option<Reg>,
        scale: u64,
        displacement: i64,
    },
    ArrayStore,
    Push(Reg),
    Pop(Reg),
    Call,
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Head {
    pub pc: u64,
    pub length: u8,
    pub function: Function,
    /// Synthetic containing-frame offset; not a claim of entry reachability.
    pub seed_rsp_minus_e: i64,
    pub entry_reachable: bool,
    /// Explicit and implicit GPR input operands; RIP is the fixed original PC.
    pub read_registers: &'static [Reg],
    pub flow: Flow,
    pub memory: Memory,
}

pub const HEADS: [Head; HEAD_COUNT] = [
    Head {
        pc: 0x401840,
        length: 4,
        function: Function::Store,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rdi, Reg::Rsi, Reg::Rdx],
        flow: Flow::Next,
        memory: Memory::ArrayStore,
    },
    Head {
        pc: 0x401844,
        length: 1,
        function: Function::Store,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Return,
        memory: Memory::Return,
    },
    Head {
        pc: 0x401850,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::R14],
        flow: Flow::Next,
        memory: Memory::Push(Reg::R14),
    },
    Head {
        pc: 0x401852,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -8,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::R13],
        flow: Flow::Next,
        memory: Memory::Push(Reg::R13),
    },
    Head {
        pc: 0x401854,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -16,
        entry_reachable: true,
        read_registers: &[Reg::Rdi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401857,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -16,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::R12],
        flow: Flow::Next,
        memory: Memory::Push(Reg::R12),
    },
    Head {
        pc: 0x401859,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40185c,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40185f,
        length: 1,
        function: Function::Sift,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::Push(Reg::Rbp),
    },
    Head {
        pc: 0x401860,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -32,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401863,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -32,
        entry_reachable: true,
        read_registers: &[Reg::Rdx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401866,
        length: 1,
        function: Function::Sift,
        seed_rsp_minus_e: -32,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::Push(Reg::Rbx),
    },
    Head {
        pc: 0x401867,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rdx, Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40186a,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jb(0x40188e),
        memory: Memory::None,
    },
    Head {
        pc: 0x40186c,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jump(0x4018c6),
        memory: Memory::None,
    },
    Head {
        pc: 0x40186e,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: false,
        read_registers: &[],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401870,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::R13],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401873,
        length: 5,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Call(0x401840),
        memory: Memory::Call,
    },
    Head {
        pc: 0x401878,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::R14],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40187b,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40187e,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::R13],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401881,
        length: 5,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Call(0x401840),
        memory: Memory::Call,
    },
    Head {
        pc: 0x401886,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rbx, Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401889,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jae(0x4018c6),
        memory: Memory::None,
    },
    Head {
        pc: 0x40188b,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40188e,
        length: 4,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401892,
        length: 4,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401896,
        length: 4,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rax],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40189a,
        length: 4,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rax],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40189e,
        length: 5,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::R13, Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::ArrayLoad {
            base: Reg::R13,
            index: Some(Reg::Rbx),
            scale: 8,
            displacement: 0,
        },
    },
    Head {
        pc: 0x4018a3,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rax, Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018a6,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jae(0x4018bc),
        memory: Memory::None,
    },
    Head {
        pc: 0x4018a8,
        length: 4,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rcx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018ac,
        length: 5,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::R13, Reg::Rcx],
        flow: Flow::Next,
        memory: Memory::ArrayLoad {
            base: Reg::R13,
            index: Some(Reg::Rcx),
            scale: 1,
            displacement: 0,
        },
    },
    Head {
        pc: 0x4018b1,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rcx, Reg::Rdx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018b4,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jbe(0x4018bc),
        memory: Memory::None,
    },
    Head {
        pc: 0x4018b6,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rcx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018b9,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rax],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018bc,
        length: 5,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::R13, Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::ArrayLoad {
            base: Reg::R13,
            index: Some(Reg::Rsi),
            scale: 8,
            displacement: 0,
        },
    },
    Head {
        pc: 0x4018c1,
        length: 3,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::R14, Reg::Rdx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018c4,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jb(0x401870),
        memory: Memory::None,
    },
    Head {
        pc: 0x4018c6,
        length: 1,
        function: Function::Sift,
        seed_rsp_minus_e: -40,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::Rbx),
    },
    Head {
        pc: 0x4018c7,
        length: 1,
        function: Function::Sift,
        seed_rsp_minus_e: -32,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::Rbp),
    },
    Head {
        pc: 0x4018c8,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::R12),
    },
    Head {
        pc: 0x4018ca,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -16,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::R13),
    },
    Head {
        pc: 0x4018cc,
        length: 2,
        function: Function::Sift,
        seed_rsp_minus_e: -8,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::R14),
    },
    Head {
        pc: 0x4018ce,
        length: 1,
        function: Function::Sift,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Return,
        memory: Memory::Return,
    },
    Head {
        pc: 0x4018d0,
        length: 4,
        function: Function::Heap,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018d4,
        length: 2,
        function: Function::Heap,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jbe(0x401950),
        memory: Memory::None,
    },
    Head {
        pc: 0x4018d6,
        length: 2,
        function: Function::Heap,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::R12],
        flow: Flow::Next,
        memory: Memory::Push(Reg::R12),
    },
    Head {
        pc: 0x4018d8,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -8,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018db,
        length: 1,
        function: Function::Heap,
        seed_rsp_minus_e: -8,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::Push(Reg::Rbp),
    },
    Head {
        pc: 0x4018dc,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -16,
        entry_reachable: true,
        read_registers: &[Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018df,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -16,
        entry_reachable: true,
        read_registers: &[Reg::Rdi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018e2,
        length: 1,
        function: Function::Heap,
        seed_rsp_minus_e: -16,
        entry_reachable: true,
        read_registers: &[Reg::Rsp, Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::Push(Reg::Rbx),
    },
    Head {
        pc: 0x4018e3,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018e6,
        length: 10,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018f0,
        length: 4,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018f4,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018f7,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018fa,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x4018fd,
        length: 5,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Call(0x401850),
        memory: Memory::Call,
    },
    Head {
        pc: 0x401902,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401905,
        length: 2,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jne(0x4018f0),
        memory: Memory::None,
    },
    Head {
        pc: 0x401907,
        length: 9,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401910,
        length: 5,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbp, Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::ArrayLoad {
            base: Reg::Rbp,
            index: Some(Reg::Rbx),
            scale: 8,
            displacement: -8,
        },
    },
    Head {
        pc: 0x401915,
        length: 4,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::ArrayLoad {
            base: Reg::Rbp,
            index: None,
            scale: 1,
            displacement: 0,
        },
    },
    Head {
        pc: 0x401919,
        length: 2,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsi],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40191b,
        length: 4,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40191f,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401922,
        length: 5,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Call(0x401840),
        memory: Memory::Call,
    },
    Head {
        pc: 0x401927,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::R12],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40192a,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40192d,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401930,
        length: 5,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Call(0x401840),
        memory: Memory::Call,
    },
    Head {
        pc: 0x401935,
        length: 2,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rdx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401937,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40193a,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbp],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x40193d,
        length: 5,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Call(0x401850),
        memory: Memory::Call,
    },
    Head {
        pc: 0x401942,
        length: 4,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rbx],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401946,
        length: 2,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[],
        flow: Flow::Jne(0x401910),
        memory: Memory::None,
    },
    Head {
        pc: 0x401948,
        length: 1,
        function: Function::Heap,
        seed_rsp_minus_e: -24,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::Rbx),
    },
    Head {
        pc: 0x401949,
        length: 1,
        function: Function::Heap,
        seed_rsp_minus_e: -16,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::Rbp),
    },
    Head {
        pc: 0x40194a,
        length: 2,
        function: Function::Heap,
        seed_rsp_minus_e: -8,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Next,
        memory: Memory::Pop(Reg::R12),
    },
    Head {
        pc: 0x40194c,
        length: 1,
        function: Function::Heap,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Return,
        memory: Memory::Return,
    },
    Head {
        pc: 0x40194d,
        length: 3,
        function: Function::Heap,
        seed_rsp_minus_e: 0,
        entry_reachable: false,
        read_registers: &[],
        flow: Flow::Next,
        memory: Memory::None,
    },
    Head {
        pc: 0x401950,
        length: 1,
        function: Function::Heap,
        seed_rsp_minus_e: 0,
        entry_reachable: true,
        read_registers: &[Reg::Rsp],
        flow: Flow::Return,
        memory: Memory::Return,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRange<'a> {
    pub function: Function,
    pub pc: u64,
    pub file_offset: u64,
    pub bytes: &'a [u8],
}

pub const ORIGINAL_RANGES: [SourceRange<'static>; 3] = [
    SourceRange { function: Function::Store, pc: 0x401840, file_offset: 0x1840, bytes: b"\x48\x89\x14\xf7\xc3" },
    SourceRange { function: Function::Sift, pc: 0x401850, file_offset: 0x1850, bytes: b"\x41\x56\x41\x55\x49\x89\xfd\x41\x54\x49\x89\xf4\x49\xd1\xec\x55\x48\x89\xf5\x48\x89\xd6\x53\x4c\x39\xe2\x72\x22\xeb\x58\x66\x90\x4c\x89\xef\xe8\xc8\xff\xff\xff\x4c\x89\xf2\x48\x89\xde\x4c\x89\xef\xe8\xba\xff\xff\xff\x4c\x39\xe3\x73\x3b\x48\x89\xde\x48\x8d\x04\x36\x48\x8d\x4e\x01\x48\x8d\x58\x01\x48\x83\xc0\x02\x49\x8b\x54\xdd\x00\x48\x39\xe8\x73\x14\x48\xc1\xe1\x04\x49\x8b\x4c\x0d\x00\x48\x39\xd1\x76\x06\x48\x89\xca\x48\x89\xc3\x4d\x8b\x74\xf5\x00\x49\x39\xd6\x72\xaa\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\xc3" },
    SourceRange { function: Function::Heap, pc: 0x4018d0, file_offset: 0x18d0, bytes: b"\x48\x83\xfe\x01\x76\x7a\x41\x54\x49\x89\xf4\x55\x49\xd1\xec\x48\x89\xfd\x53\x48\x89\xf3\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00\x49\x83\xec\x01\x48\x89\xde\x48\x89\xef\x4c\x89\xe2\xe8\x4e\xff\xff\xff\x4d\x85\xe4\x75\xe9\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x48\x8b\x54\xdd\xf8\x4c\x8b\x65\x00\x31\xf6\x48\x83\xeb\x01\x48\x89\xef\xe8\x19\xff\xff\xff\x4c\x89\xe2\x48\x89\xde\x48\x89\xef\xe8\x0b\xff\xff\xff\x31\xd2\x48\x89\xde\x48\x89\xef\xe8\x0e\xff\xff\xff\x48\x83\xfb\x01\x75\xc8\x5b\x5d\x41\x5c\xc3\x0f\x1f\x00\xc3" },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Inventory,
    SourceRanges,
    Anchors,
    CaseIndex,
    OperandDomain,
}

/// Constructible only after exact complete-table and three-range equality.
/// This is a byte-data token, not a whole-ELF or runtime authority.
pub struct Inventory {
    _private: (),
}

pub fn authenticate(table: &[u8], ranges: &[SourceRange<'_>]) -> Result<Inventory, Refusal> {
    if table != EXPECTED_INSTRUCTIONS {
        return Err(Refusal::Inventory);
    }
    if ranges.len() != ORIGINAL_RANGES.len() {
        return Err(Refusal::SourceRanges);
    }
    for (got, expected) in ranges.iter().zip(ORIGINAL_RANGES.iter()) {
        if got.function != expected.function
            || got.pc != expected.pc
            || got.file_offset != expected.file_offset
            || got.bytes != expected.bytes
        {
            return Err(Refusal::SourceRanges);
        }
    }
    Ok(Inventory { _private: () })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Permissions {
    None,
    Read,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub permissions: Permissions,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Image {
    pub region: Region,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Anchors {
    a: u64,
    e: u64,
}

fn overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

impl Anchors {
    /// Checks this specification's finite geometry only. The caller still owns
    /// proof that both siblings have identical admitted mappings at A and E.
    pub fn new(a: u64, e: u64) -> Result<Self, Refusal> {
        if a & 4095 != 0 || e & 4095 != 8 {
            return Err(Refusal::Anchors);
        }
        let data = (a.checked_sub(4096), a.checked_add(8192));
        let stack = (
            e.checked_sub(STACK_BELOW_E + 4096),
            e.checked_add(STACK_ABOVE_E + 4096),
        );
        let (Some(ds), Some(de), Some(ss), Some(se)) = (data.0, data.1, stack.0, stack.1) else {
            return Err(Refusal::Anchors);
        };
        if ds == 0 || ss == 0 || de > LOW_END || se > LOW_END
            || overlap((ds, de), (ss, se))
            // Page-rounded original PT_LOAD ownership, including journal/BSS.
            || overlap((ds, de), (0x400000, 0x425000))
            || overlap((ss, se), (0x400000, 0x425000))
        {
            return Err(Refusal::Anchors);
        }
        Ok(Self { a, e })
    }
    pub fn data_address(self) -> u64 {
        self.a
    }
    pub fn frame_anchor(self) -> u64 {
        self.e
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registers {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub orig_rax: u64,
}
impl Registers {
    pub fn get(&self, r: Reg) -> u64 {
        self.gpr[r as usize]
    }
    fn set(&mut self, r: Reg, value: u64) {
        self.gpr[r as usize] = value;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtendedState {
    /// The unchanged quiescent_oracle::seeded_xstate algorithm, with this seed.
    /// Its CPUID/regset prerequisites and kernel-normalized bytes remain required.
    ExistingSeededXstate { seed: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InheritedState {
    /// CS/SS/DS/ES/FS/GS and FS/GS bases from the same authenticated parent
    /// context, then verified equal in both children. Not sampled independently.
    SameParentSelectorsAndBases,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Read,
    Write,
    FaultingWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Domain {
    Array,
    Stack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryEffect {
    pub access: Access,
    pub domain: Domain,
    pub address: u64,
    pub bytes: [u8; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    OriginalPc {
        pc: u64,
        rsp: u64,
    },
    /// Linux x86-64 SIGSEGV/SEGV_ACCERR; no application bytes may change.
    Fault {
        pc: u64,
        rsp: u64,
        signal: i32,
        code: i32,
        address: u64,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct SeedSpec {
    pub case_index: usize,
    pub head_index: usize,
    pub state_index: usize,
    pub seed: u64,
    pub registers: Registers,
    pub extended_state: ExtendedState,
    pub inherited_state: InheritedState,
    pub data: Image,
    pub stack: Image,
    pub guards: [Region; 4],
    /// Always E-128, fixed before either execution and never moved by an RSP.
    pub compared_stack_start: u64,
    pub memory_effect: Option<MemoryEffect>,
    pub completion: Completion,
}

fn offset(base: u64, delta: i64) -> Result<u64, Refusal> {
    let sum = i128::from(base) + i128::from(delta);
    u64::try_from(sum).map_err(|_| Refusal::OperandDomain)
}

fn seeded_registers(seed: u64, a: u64, rsp: u64, pc: u64, state: usize) -> Registers {
    use Reg::*;
    let mut result = Registers {
        gpr: [0; 16],
        rip: pc,
        rflags: [0x202, 0xad7][state],
        orig_rax: u64::MAX,
    };
    let mut value = seed;
    // Exact historical PRNG assignment order. RSI/RDI retain their historical
    // A+512/A defaults until a declared live-operand override below.
    for r in [
        Rax, Rbx, Rcx, Rdx, Rbp, R8, R9, R10, R11, R12, R13, R14, R15,
    ] {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        result.set(r, value);
    }
    result.set(Rsi, a + 512);
    result.set(Rdi, a);
    result.set(Rsp, rsp);
    result
}

fn live_operands(r: &mut Registers, pc: u64, a: u64, state: usize, array: [u64; 4]) {
    use Reg::*;
    let assignments: Vec<(Reg, u64)> = match pc {
        0x401840 => vec![
            (Rdi, a),
            (Rsi, [1, 3][state]),
            (Rdx, [0x1122334455667788, 0x8877665544332211][state]),
        ],
        0x401854 => vec![(Rdi, a)],
        0x401859 | 0x401860 => vec![(Rsi, 4)],
        0x40185c => vec![(R12, 4)],
        0x401863 => vec![(Rdx, 0)],
        0x401867 => vec![(Rdx, 0), (R12, 2)],
        0x40186e => vec![
            (R13, a),
            (Rbp, 4),
            (R12, 2),
            (Rsi, 0),
            (Rbx, 1),
            (Rdx, array[1]),
            (R14, array[0]),
        ],
        0x401870 | 0x40187e => vec![(R13, a)],
        0x401873 => vec![(Rdi, a), (Rsi, 0), (Rdx, array[1])],
        0x401878 => vec![(R14, array[0])],
        0x40187b | 0x40188b => vec![(Rbx, 1)],
        0x401881 => vec![(Rdi, a), (Rsi, 1), (Rdx, array[0])],
        0x401886 => vec![(Rbx, 1), (R12, 2)],
        0x40188e | 0x401892 => vec![(Rsi, 0)],
        0x401896 | 0x40189a => vec![(Rax, 0)],
        0x40189e => vec![(R13, a), (Rbx, 1)],
        0x4018a3 => vec![(Rax, 2), (Rbp, 4)],
        0x4018a8 => vec![(Rcx, 1)],
        0x4018ac => vec![(R13, a), (Rcx, 16)],
        0x4018b1 => vec![(Rcx, array[2]), (Rdx, array[1])],
        0x4018b6 => vec![(Rcx, array[2])],
        0x4018b9 => vec![(Rax, 2)],
        0x4018bc => vec![(R13, a), (Rsi, 0)],
        0x4018c1 => vec![(R14, array[0]), (Rdx, array[1])],
        0x4018d0 | 0x4018d8 | 0x4018e3 => vec![(Rsi, 4)],
        0x4018dc => vec![(R12, 4)],
        0x4018df => vec![(Rdi, a)],
        0x4018e6 | 0x401907 => vec![(Rbp, a), (Rbx, 4), (R12, 2)],
        0x4018f0 => vec![(R12, 2)],
        0x4018f4 => vec![(Rbx, 4)],
        0x4018f7 | 0x40191f | 0x40192d | 0x40193a => vec![(Rbp, a)],
        0x4018fa | 0x401902 => vec![(R12, 1)],
        0x4018fd => vec![(Rdi, a), (Rsi, 4), (Rdx, 1)],
        0x401910 => vec![(Rbp, a), (Rbx, 4)],
        0x401915 => vec![(Rbp, a)],
        0x40191b => vec![(Rbx, 4)],
        0x401922 => vec![(Rdi, a), (Rsi, 0), (Rdx, array[3])],
        0x401927 => vec![(R12, array[0])],
        0x40192a | 0x401937 | 0x401942 => vec![(Rbx, 3)],
        0x401930 => vec![(Rdi, a), (Rsi, 3), (Rdx, array[0])],
        0x40193d => vec![(Rdi, a), (Rsi, 3), (Rdx, 0)],
        // Branches read the explicit flags; pushes read the historical seed;
        // pops/RET read the complete initialized stack. Other NOPs read no GPR.
        _ => vec![],
    };
    for (reg, value) in assignments {
        r.set(reg, value);
    }
}

fn put_word(image: &mut Image, address: u64, value: u64) -> Result<(), Refusal> {
    let start = address
        .checked_sub(image.region.start)
        .ok_or(Refusal::OperandDomain)?;
    let start = usize::try_from(start).map_err(|_| Refusal::OperandDomain)?;
    let end = start.checked_add(8).ok_or(Refusal::OperandDomain)?;
    let dest = image
        .bytes
        .get_mut(start..end)
        .ok_or(Refusal::OperandDomain)?;
    dest.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_word(image: &Image, address: u64) -> Result<[u8; 8], Refusal> {
    let start = address
        .checked_sub(image.region.start)
        .ok_or(Refusal::OperandDomain)?;
    let start = usize::try_from(start).map_err(|_| Refusal::OperandDomain)?;
    let end = start.checked_add(8).ok_or(Refusal::OperandDomain)?;
    image
        .bytes
        .get(start..end)
        .ok_or(Refusal::OperandDomain)?
        .try_into()
        .map_err(|_| Refusal::OperandDomain)
}

impl Inventory {
    /// Fixed order: head 0 state 0, head 0 state 1, ... head 86 state 1,
    /// then the same two store states with a read-only array page.
    pub fn case(&self, case_index: usize, anchors: Anchors) -> Result<SeedSpec, Refusal> {
        use Reg::*;
        if case_index >= CASE_COUNT {
            return Err(Refusal::CaseIndex);
        }
        let fault = case_index >= HEAD_COUNT * 2;
        let head_index = if fault { 0 } else { case_index / 2 };
        let state_index = case_index & 1;
        let head = HEADS[head_index];
        let seed = SEEDS[state_index];
        let Anchors { a, e } = anchors;
        let array = [[13, 5, 21, 8], [7, 19, 3, 29]][state_index];
        let rsp = offset(e, head.seed_rsp_minus_e)?;
        let mut registers = seeded_registers(seed, a, rsp, head.pc, state_index);
        let saved = registers.clone();
        live_operands(&mut registers, head.pc, a, state_index, array);
        let mut data = Image {
            region: Region {
                start: a,
                end: a + 4096,
                permissions: if fault {
                    Permissions::Read
                } else {
                    Permissions::ReadWrite
                },
            },
            bytes: (0..PAGE_BYTES)
                .map(|i| (i as u64 * 37 + (seed & 255)) as u8)
                .collect(),
        };
        for (index, word) in array.into_iter().enumerate() {
            put_word(&mut data, a + index as u64 * 8, word)?;
        }
        let mut stack = Image {
            region: Region {
                start: e - STACK_BELOW_E,
                end: e + STACK_ABOVE_E,
                permissions: Permissions::ReadWrite,
            },
            bytes: (0..STACK_BYTES)
                .map(|i| (i as u64 * 29 + (seed & 255)) as u8)
                .collect(),
        };
        let slots: &[(i64, Reg)] = match head.function {
            Function::Store => &[],
            Function::Sift => &[(-40, Rbx), (-32, Rbp), (-24, R12), (-16, R13), (-8, R14)],
            Function::Heap => &[(-24, Rbx), (-16, Rbp), (-8, R12)],
        };
        for &(delta, reg) in slots {
            put_word(&mut stack, offset(e, delta)?, saved.get(reg))?;
        }
        put_word(&mut stack, e, RETURN_PC)?;
        let mut rsp_after = rsp;
        let mut effect = None;
        let mut record = |access, domain, address, bytes| {
            effect = Some(MemoryEffect {
                access,
                domain,
                address,
                bytes,
            });
        };
        match head.memory {
            Memory::None => {}
            Memory::ArrayLoad {
                base,
                index,
                scale,
                displacement,
            } => {
                let index = index.map_or(0, |r| registers.get(r));
                let term = index.checked_mul(scale).ok_or(Refusal::OperandDomain)?;
                let address = offset(
                    registers
                        .get(base)
                        .checked_add(term)
                        .ok_or(Refusal::OperandDomain)?,
                    displacement,
                )?;
                if address < a || address.checked_add(8).ok_or(Refusal::OperandDomain)? > a + 32 {
                    return Err(Refusal::OperandDomain);
                }
                record(
                    Access::Read,
                    Domain::Array,
                    address,
                    read_word(&data, address)?,
                );
            }
            Memory::ArrayStore => {
                let term = registers
                    .get(Rsi)
                    .checked_mul(8)
                    .ok_or(Refusal::OperandDomain)?;
                let address = registers
                    .get(Rdi)
                    .checked_add(term)
                    .ok_or(Refusal::OperandDomain)?;
                if address < a || address.checked_add(8).ok_or(Refusal::OperandDomain)? > a + 32 {
                    return Err(Refusal::OperandDomain);
                }
                record(
                    if fault {
                        Access::FaultingWrite
                    } else {
                        Access::Write
                    },
                    Domain::Array,
                    address,
                    registers.get(Rdx).to_le_bytes(),
                );
            }
            Memory::Push(reg) => {
                rsp_after = rsp.checked_sub(8).ok_or(Refusal::OperandDomain)?;
                read_word(&stack, rsp_after)?;
                record(
                    Access::Write,
                    Domain::Stack,
                    rsp_after,
                    registers.get(reg).to_le_bytes(),
                );
            }
            Memory::Pop(_) | Memory::Return => {
                rsp_after = rsp.checked_add(8).ok_or(Refusal::OperandDomain)?;
                record(Access::Read, Domain::Stack, rsp, read_word(&stack, rsp)?);
            }
            Memory::Call => {
                rsp_after = rsp.checked_sub(8).ok_or(Refusal::OperandDomain)?;
                read_word(&stack, rsp_after)?;
                record(
                    Access::Write,
                    Domain::Stack,
                    rsp_after,
                    (head.pc + u64::from(head.length)).to_le_bytes(),
                );
            }
        }
        if let Some(m) = effect {
            if m.domain == Domain::Stack && (m.address < e - 128 || m.address + 8 > e + 8) {
                return Err(Refusal::OperandDomain);
            }
        }
        let next = head.pc + u64::from(head.length);
        let cf = registers.rflags & 1 != 0;
        let zf = registers.rflags & 0x40 != 0;
        let pc = match head.flow {
            Flow::Next => next,
            Flow::Jb(to) => {
                if cf {
                    to
                } else {
                    next
                }
            }
            Flow::Jae(to) => {
                if !cf {
                    to
                } else {
                    next
                }
            }
            Flow::Jbe(to) => {
                if cf || zf {
                    to
                } else {
                    next
                }
            }
            Flow::Jne(to) => {
                if !zf {
                    to
                } else {
                    next
                }
            }
            Flow::Jump(to) | Flow::Call(to) => to,
            Flow::Return => u64::from_le_bytes(read_word(&stack, rsp)?),
        };
        if !HEADS.iter().any(|h| h.pc == pc) {
            return Err(Refusal::OperandDomain);
        }
        let completion = if fault {
            Completion::Fault {
                pc: head.pc,
                rsp,
                signal: 11,
                code: 2,
                address: effect.ok_or(Refusal::OperandDomain)?.address,
            }
        } else {
            Completion::OriginalPc { pc, rsp: rsp_after }
        };
        Ok(SeedSpec {
            case_index,
            head_index,
            state_index,
            seed,
            registers,
            extended_state: ExtendedState::ExistingSeededXstate { seed },
            inherited_state: InheritedState::SameParentSelectorsAndBases,
            guards: [
                Region {
                    start: a - 4096,
                    end: a,
                    permissions: Permissions::None,
                },
                Region {
                    start: a + 4096,
                    end: a + 8192,
                    permissions: Permissions::None,
                },
                Region {
                    start: stack.region.start - 4096,
                    end: stack.region.start,
                    permissions: Permissions::None,
                },
                Region {
                    start: stack.region.end,
                    end: stack.region.end + 4096,
                    permissions: Permissions::None,
                },
            ],
            data,
            stack,
            compared_stack_start: e - 128,
            memory_effect: effect,
            completion,
        })
    }
}
