//! Independent iced decode/metadata component, never application execution.
use iced_x86::{Code, Decoder, DecoderOptions};

const CODES: [[Code; 3]; 8] = [
    [Code::Rol_rm16_1, Code::Rol_rm32_1, Code::Rol_rm64_1],
    [Code::Ror_rm16_1, Code::Ror_rm32_1, Code::Ror_rm64_1],
    [Code::Rcl_rm16_1, Code::Rcl_rm32_1, Code::Rcl_rm64_1],
    [Code::Rcr_rm16_1, Code::Rcr_rm32_1, Code::Rcr_rm64_1],
    [Code::Shl_rm16_1, Code::Shl_rm32_1, Code::Shl_rm64_1],
    [Code::Shr_rm16_1, Code::Shr_rm32_1, Code::Shr_rm64_1],
    [Code::Sal_rm16_1, Code::Sal_rm32_1, Code::Sal_rm64_1],
    [Code::Sar_rm16_1, Code::Sar_rm32_1, Code::Sar_rm64_1],
];
const PREFIXES: [u8; 27] = [
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
    0x66,0x67,0x26,0x2e,0x36,0x3e,0x64,0x65,0xf0,0xf2,0xf3,
];
fn check_offsets(bits: u32, options: u32, bytes: &[u8], count: &mut u64) {
    for at in 0..bytes.len() {
        let i = Decoder::new(bits, &bytes[at..], options).decode();
        *count += 1;
        // Invalid encodings cannot authorize HLE; no invalid-check bypass here.
        if !i.is_invalid() {
            assert!(!i.has_xacquire_prefix() && !i.has_xrelease_prefix(),
                    "valid HLE bits={bits} options={options} offset={at} bytes={bytes:02x?}");
        }
    }
}
fn main() {
    for row in CODES { for code in row {
        let info = code.op_code();
        assert!(!info.can_use_lock_prefix());
        assert!(!info.can_use_xacquire_prefix() && !info.can_use_xrelease_prefix());
    }}
    let forms: [(u32, &[u8], usize); 7] = [
        (16,&[],0), (16,&[0x66],1), (32,&[],1), (32,&[0x66],0),
        (64,&[],1), (64,&[0x66],0), (64,&[0x48],2),
    ];
    let (mut canonical,mut locked,mut offsets,mut real_hle) = (0u64,0u64,0u64,0u64);
    for (bits, prefix, width) in forms {
        for options in [DecoderOptions::NONE, DecoderOptions::AMD] {
            for m in 0u8..=255 {
                let expected = CODES[((m >> 3) & 7) as usize][width];
                let mut plain = prefix.to_vec(); plain.extend_from_slice(&[0xd1,m,0,0,0,0,0,0]);
                let i = Decoder::new(bits,&plain,options).decode();
                assert_eq!(i.code(),expected); assert!(!i.has_lock_prefix()); canonical += 1;
                for hint in [0xf2,0xf3] { for order in [false,true] {
                    let mut bytes = if order { vec![0xf0,hint] } else { vec![hint,0xf0] };
                    bytes.extend_from_slice(&plain);
                    assert!(Decoder::new(bits,&bytes,options).decode().is_invalid());
                    // This second decode describes the invalid LOCK target only.
                    // It never supplies positive validity or admission authority.
                    let unchecked = Decoder::new(bits,&bytes,options|DecoderOptions::NO_INVALID_CHECK).decode();
                    assert_eq!(unchecked.code(),expected); assert!(unchecked.has_lock_prefix());
                    assert!(!unchecked.code().op_code().can_use_lock_prefix()); locked += 1;
                }}
            }
        }
    }
    for bits in [16,32,64] { for options in [DecoderOptions::NONE,DecoderOptions::AMD] {
        for hint in [0xf2,0xf3] { for order in [false,true] { for m in 0u8..=255 {
            for pad in PREFIXES {
                let mut bytes = if order {vec![0xf0,pad,hint]} else {vec![hint,pad,0xf0]};
                bytes.extend_from_slice(&[0xd1,m,0,0,0,0,0,0]);
                check_offsets(bits,options,&bytes,&mut offsets);
            }
            for gap in 0..=12 {
                let mut bytes = vec![0x66;gap+4]; bytes[0] = if order {0xf0}else{hint};
                bytes[gap+1] = if order {hint}else{0xf0}; bytes[gap+2]=0xd1; bytes[gap+3]=m;
                bytes.extend_from_slice(&[0;6]);
                check_offsets(bits,options,&bytes,&mut offsets);
            }
        }}}
        for tail in [[0x48,0x21],[0x48,0x21],[0x48,0x21],[0x73,0x1d],[0x73,0x1b]] {
            let mut bytes=vec![0xc4,0xe2,0xf0,0xf3,0xd1];bytes.extend_from_slice(&tail);
            check_offsets(bits,options,&bytes,&mut offsets);
        }
    }}
    // The independent decoder must still identify actual HLE in every mode.
    for bits in [16,32,64] { for options in [DecoderOptions::NONE,DecoderOptions::AMD] {
        for hint in [0xf2,0xf3] { for order in [false,true] {
            let bytes = if order {[0xf0,hint,0x01,0x00]} else {[hint,0xf0,0x01,0x00]};
            let i = Decoder::new(bits,&bytes,options).decode();
            assert!(!i.is_invalid() && i.has_lock_prefix());
            assert_eq!(i.has_xacquire_prefix(),hint==0xf2);
            assert_eq!(i.has_xrelease_prefix(),hint==0xf3); real_hle += 1;
        }}
        for bytes in [[0xf2,0x87,0x00],[0xf3,0x87,0x00],[0xf3,0x89,0x00]] {
            let i = Decoder::new(bits,&bytes,options).decode();
            assert!(!i.is_invalid());
            assert_eq!(i.has_xacquire_prefix(),bytes[0]==0xf2);
            assert_eq!(i.has_xrelease_prefix(),bytes[0]==0xf3); real_hle += 1;
        }
    }}
    assert_eq!((canonical,locked,offsets,real_hle),(3584,14336,3102930,42));
    println!("{{\"version\":1,\"modes\":[16,32,64],\"vendor_options\":2,\"opcode_forms\":24,\"canonical\":{canonical},\"lock_invalid\":{locked},\"offset_decodes\":{offsets},\"actual_hle_decodes\":{real_hle}}}");
}
