//! Handwritten scalar ADC encoding families. No decoder or production planner
//! supplies bytes, instruction heads, arithmetic answers or case membership.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    RegisterToRm,
    RegisterFromRm,
    AccumulatorImmediate,
    FullImmediate,
    SignedByteImmediate,
    ReadMemory,
    ReadIndexedMemory,
    HighDestination,
    HighSource,
    ExtendedByte,
    CompiledR8Zero,
}

pub fn forms(width: u32) -> Vec<Form> {
    assert!([8, 16, 32, 64].contains(&width));
    let mut forms = vec![
        Form::RegisterToRm,
        Form::RegisterFromRm,
        Form::AccumulatorImmediate,
        Form::FullImmediate,
        Form::ReadMemory,
        Form::ReadIndexedMemory,
    ];
    if width == 8 {
        forms.extend([Form::HighDestination, Form::HighSource, Form::ExtendedByte]);
    } else {
        forms.push(Form::SignedByteImmediate);
    }
    if width == 64 {
        forms.push(Form::CompiledR8Zero);
    }
    forms
}

pub fn mask(width: u32) -> u64 {
    assert!([8, 16, 32, 64].contains(&width));
    (u128::from(u64::MAX) >> (64 - width)) as u64
}

/// Six declared operand boundaries, each exercised with BOTH incoming carries.
/// The exact compiled R8/imm8=0 form has its own fixed zero-RHS population.
pub fn operands(width: u32, form: Form) -> [(u64, u64); 6] {
    let maximum = mask(width);
    let sign = 1_u64 << (width - 1);
    if form == Form::CompiledR8Zero {
        [
            (0, 0),
            (maximum, 0),
            (sign - 1, 0),
            (15, 0),
            (sign, 0),
            (85, 0),
        ]
    } else {
        [
            (0, 0),
            (maximum, 0),
            (sign - 1, 0),
            (15, 1),
            (sign, maximum),
            (maximum, 1),
        ]
    }
}

pub fn instruction(width: u32, form: Form, right: u64) -> Vec<u8> {
    assert!(forms(width).contains(&form));
    let mut bytes = match width {
        8 | 32 => vec![],
        16 => vec![0x66],
        64 => vec![0x48],
        _ => unreachable!(),
    };
    let byte = width == 8;
    match form {
        Form::RegisterToRm => bytes.extend([if byte { 0x10 } else { 0x11 }, 0xc8]),
        Form::RegisterFromRm => bytes.extend([if byte { 0x12 } else { 0x13 }, 0xc1]),
        Form::AccumulatorImmediate | Form::FullImmediate => {
            if form == Form::AccumulatorImmediate {
                bytes.push(if byte { 0x14 } else { 0x15 });
            } else {
                bytes.extend([if byte { 0x80 } else { 0x81 }, 0xd0]);
            }
            let immediate = right.to_le_bytes();
            let length = if width == 64 { 4 } else { (width / 8) as usize };
            bytes.extend_from_slice(&immediate[..length]);
        }
        Form::SignedByteImmediate => {
            assert!(right == 0 || right == 1 || right == mask(width));
            bytes.extend([0x83, 0xd0, right as u8]);
        }
        Form::ReadMemory => bytes.extend([if byte { 0x12 } else { 0x13 }, 0x07]),
        Form::ReadIndexedMemory => {
            // ADC accumulator,[RDI + RDX*2 + 16]. Native setup sets RDX=0.
            bytes.extend([if byte { 0x12 } else { 0x13 }, 0x44, 0x57, 0x10]);
        }
        Form::HighDestination => bytes.extend([0x12, 0xe1]), // ADC AH,CL
        Form::HighSource => bytes.extend([0x12, 0xc5]),      // ADC AL,CH
        Form::ExtendedByte => bytes.extend([0x45, 0x12, 0xc1]), // ADC R8B,R9B
        Form::CompiledR8Zero => {
            assert_eq!(right, 0);
            bytes = vec![0x49, 0x83, 0xd0, 0]; // Exact compiled ADC R8,0.
        }
    }
    bytes
}

pub fn extended(form: Form) -> bool {
    matches!(form, Form::ExtendedByte | Form::CompiledR8Zero)
}

/// Expected full destination value and every defined ADC arithmetic flag.
/// u128 addition is independent of both the CPU trace and the x86 decoder.
pub fn answer(width: u32, form: Form, left: u64, right: u64, carry: bool) -> (u64, u64) {
    let maximum = mask(width);
    let sign = 1_u64 << (width - 1);
    assert!(left <= maximum && right <= maximum);
    let sum = u128::from(left) + u128::from(right) + u128::from(carry);
    let value = (sum & u128::from(maximum)) as u64;
    let flags = u64::from(sum > u128::from(maximum))
        | (u64::from((value as u8).count_ones() % 2 == 0) << 2)
        | (u64::from((left ^ right ^ value) & 0x10 != 0) << 4)
        | (u64::from(value == 0) << 6)
        | (u64::from(value & sign != 0) << 7)
        | (u64::from((!(left ^ right) & (left ^ value)) & sign != 0) << 11);
    let original = initial_destination(width, form, left);
    let full = if form == Form::HighDestination {
        (original & !0xff00) | (value << 8)
    } else if width < 32 {
        (original & !maximum) | value
    } else {
        value // A 32-bit GPR write zero-extends; a 64-bit write replaces it.
    };
    (full, flags)
}

pub fn initial_destination(width: u32, form: Form, left: u64) -> u64 {
    if form == Form::HighDestination {
        0xa5f0_1234_9876_00a5 | (left << 8)
    } else if width < 64 {
        0xa5f0_1234_0000_0000 | left
    } else {
        left
    }
}

pub struct Fixture {
    pub bytes: Vec<u8>,
    pub heads: Vec<usize>,
    pub adc: usize,
    pub after_adc: usize,
}

/// MOV-only setup preserves the externally seeded CF until the selected ADC.
/// Writes initialize only this oracle's owned data page; they are scaffolding,
/// not an enlargement of the admitted read-only scalar leaf grammar.
pub fn fixture(width: u32, form: Form, left: u64, right: u64) -> Fixture {
    let mut bytes = Vec::new();
    let mut heads = Vec::new();
    let mut emit = |instruction: &[u8]| {
        heads.push(bytes.len());
        bytes.extend_from_slice(instruction);
    };
    let mov_imm = |prefix: [u8; 2], immediate: u64| {
        let mut instruction = prefix.to_vec();
        instruction.extend(immediate.to_le_bytes());
        instruction
    };
    emit(&mov_imm(
        if extended(form) {
            [0x49, 0xb8]
        } else {
            [0x48, 0xb8]
        },
        initial_destination(width, form, left),
    ));
    emit(&mov_imm(
        if form == Form::ExtendedByte {
            [0x49, 0xb9]
        } else {
            [0x48, 0xb9]
        },
        if form == Form::HighSource {
            right << 8
        } else {
            right
        },
    ));
    if form == Form::ReadMemory {
        emit(&[0x48, 0x89, 0x0f]); // MOV [RDI],RCX
    }
    if form == Form::ReadIndexedMemory {
        emit(&mov_imm([0x48, 0xba], 0)); // MOV RDX,0; keeps CF.
        emit(&[0x48, 0x89, 0x4f, 0x10]); // MOV [RDI+16],RCX
    }
    let adc_bytes = instruction(width, form, right);
    emit(&adc_bytes);
    // Eight one-byte NOPs give relocation a complete >=5-byte window without
    // displacing RET; every head remains an independent oracle boundary.
    for _ in 0..8 {
        emit(&[0x90]);
    }
    emit(&[0xc3]);
    let adc_index = heads.len() - 10;
    Fixture {
        adc: heads[adc_index],
        after_adc: heads[adc_index + 1],
        bytes,
        heads,
    }
}
