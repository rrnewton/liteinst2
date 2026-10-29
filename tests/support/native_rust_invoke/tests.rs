use super::*;

// Fabricated closed grammar, not a prediction of emitted compiler bytes.
const BODY: &[u8] = &[
    0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0, 0x48,
    0x89, 0x03, 0x5b, 0xc3,
];

#[test]
fn rust_invoke_whole_body_and_four_origins_are_required() {
    let p = admit(BODY).unwrap();
    assert_eq!(p.bytes(), BODY);
    for (at, value) in [
        (3, 0xdb),
        (6, 0xf0),
        (9, 0xd7),
        (12, 0xfe),
        (14, 0xd1),
        (17, 0x07),
    ] {
        let mut b = BODY.to_vec();
        b[at] = value;
        assert!(admit(&b).is_err(), "{at}");
    }
    for n in 0..BODY.len() {
        assert!(admit(&BODY[..n]).is_err());
    }
    let mut tail = BODY.to_vec();
    tail.push(0xc3);
    assert!(admit(&tail).is_err());
    let mut full = Vec::new();
    for _ in 0..78 {
        full.extend([0x4d, 0x89, 0xd2]);
    }
    full.extend([0x50, 0x58]);
    full.extend(BODY);
    assert_eq!(full.len(), MAX_BYTES);
    assert_eq!(admit(&full).unwrap().bytes(), full);
    full.insert(0, 0x50);
    assert!(admit(&full).is_err());
}

#[test]
fn rust_invoke_call_clobbers_reject_volatile_output_and_reload() {
    let mut volatile = BODY.to_vec();
    volatile[1..4].copy_from_slice(&[0x49, 0x89, 0xcb]);
    volatile[15..18].copy_from_slice(&[0x49, 0x89, 0x03]);
    assert_eq!(admit(&volatile), Err(Error::Provenance)); // R11 is not preserved by CALL.
    let mut late = BODY.to_vec();
    late.splice(15..15, [0x48, 0x89, 0xd9]);
    assert_eq!(admit(&late), Err(Error::Provenance)); // No post-call reload before store.
    let mut result = BODY.to_vec();
    result[17] = 0x0b;
    assert_eq!(admit(&result), Err(Error::Provenance)); // Store RCX is not result RAX.
    let mut twice = BODY.to_vec();
    twice.splice(18..18, [0x48, 0x89, 0x03]);
    assert_eq!(admit(&twice), Err(Error::Provenance));
}

#[test]
fn rust_invoke_balanced_stack_and_callee_saves_are_required() {
    let mut missing = BODY.to_vec();
    missing.remove(18);
    assert_eq!(admit(&missing), Err(Error::Stack));
    let mut wrong = BODY.to_vec();
    wrong[18] = 0x5d;
    assert_eq!(admit(&wrong), Err(Error::Stack));
    let mut no_save = BODY[1..].to_vec();
    no_save.remove(17);
    assert_eq!(admit(&no_save), Err(Error::Stack));
    let mut frame = vec![0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec, 0x08];
    frame.extend(&BODY[1..18]);
    frame.extend([0x48, 0x83, 0xc4, 0x08, 0x5b, 0x5d, 0xc3]);
    let p = admit(&frame).unwrap();
    assert_eq!(p.subject_rsp_delta(), 32);
    assert_eq!(p.protected_stack_below(), 160);
    // Preserve output through an initialized allocated slot before CALL.
    let mut slots = vec![
        0x53, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x0c, 0x24, 0x48, 0x8b, 0x1c, 0x24,
    ];
    slots.extend(&BODY[4..18]);
    slots.extend([0x48, 0x83, 0xc4, 0x10, 0x5b, 0xc3]);
    assert!(admit(&slots).is_ok());
    let mut uninitialized = slots.clone();
    uninitialized.drain(5..9);
    assert!(admit(&uninitialized).is_err());
    let mut alias = slots.clone();
    alias.splice(9..13, [0x48, 0x8d, 0x1c, 0x24, 0x48, 0x8b, 0x1b]);
    assert!(admit(&alias).is_ok());
    let mut redzone = BODY.to_vec();
    redzone.splice(1..1, [0x48, 0x89, 0x4c, 0x24, 0xf8]);
    assert_eq!(admit(&redzone), Err(Error::Stack));
    let mut word = BODY.to_vec();
    word.splice(1..1, [0x48, 0x89, 0x4c, 0x24, 0x08]);
    assert_eq!(admit(&word), Err(Error::Stack));
}

#[test]
fn rust_invoke_unsupported_bytes_prefixes_flow_and_memory_refuse() {
    for prefix in [
        &[0x90][..],
        &[0x66],
        &[0xf3],
        &[0x64],
        &[0x40, 0x40],
        &[0xeb, 0x00],
        &[0xe8, 0, 0, 0, 0],
        &[0x48, 0x8b, 0x05, 0, 0, 0, 0],
        &[0x48, 0x8b, 0x04, 0x08],
        &[0x89, 0xd8],
    ] {
        let mut b = prefix.to_vec();
        b.extend(BODY);
        assert!(admit(&b).is_err(), "{prefix:?}");
    }
    let mut ret = BODY[..19].to_vec();
    ret.extend([0xc2, 0x08, 0]);
    assert!(admit(&ret).is_err());
    let mut external = BODY.to_vec();
    external.splice(1..1, [0x48, 0x8b, 0x06]);
    assert!(admit(&external).is_err());
    let mut overflow = BODY.to_vec();
    overflow.splice(1..1, [0x48, 0x81, 0xec, 0x08, 0x01, 0, 0]);
    assert!(admit(&overflow).is_err());
}

#[test]
fn rust_invoke_steps_keep_complete_heads_and_return_geometry() {
    let p = admit(BODY).unwrap();
    assert_eq!(p.heads(), [0, 1, 4, 7, 10, 13, 15, 18, 19]);
    assert_eq!(p.calls(), &[13]);
    assert_eq!(p.continuations(), &[15]);
    assert_eq!(p.outer_ret(), 19);
    assert_eq!(
        (p.subject_rsp_delta(), p.protected_stack_below()),
        (16, 144)
    );
    let mut end = 0;
    for step in p.steps() {
        assert_eq!(step.offset, end);
        end += u64::from(step.length);
    }
    assert_eq!(end, BODY.len() as u64);
    assert_eq!(p.steps()[0].operation, Operation::Push(Register::RBX));
    assert_eq!((p.steps()[0].rsp_before, p.steps()[0].rsp_after), (0, -8));
    assert_eq!(
        p.steps()[5].operation,
        Operation::Call {
            target: Register::RAX
        }
    );
    assert_eq!(
        p.steps()[6].operation,
        Operation::Move {
            destination: Operand::Memory {
                base: Register::RBX,
                displacement: 0
            },
            source: Operand::Register(Register::RAX)
        }
    );
    assert_eq!(p.steps()[8].code, Code::Retnq);
    assert_eq!(p, admit(BODY).unwrap());
}

#[test]
fn rust_invoke_copy_images_check_every_byte_and_padding() {
    let p = admit(BODY).unwrap();
    let mut expected = vec![0xcc; 4096];
    expected[128..148].copy_from_slice(BODY);
    assert!(copy::check_image_for_test(&expected, &expected, &p).is_ok());
    for at in 0..expected.len() {
        let mut b = expected.clone();
        b[at] ^= 1;
        assert!(copy::check_image_for_test(&b, &expected, &p).is_err());
    }
    let mut forged = expected.clone();
    forged[0] = 0;
    assert!(copy::check_image_for_test(&forged, &forged, &p).is_err());
    assert!(copy::check_image_for_test(&expected[..4095], &expected, &p).is_err());
    let maps = "1000-2000 ---p 00000000 00:00 0\n2000-3000 r-xp 00000000 00:00 0\n3000-5000 ---p 00000000 00:00 0\n";
    assert!(copy::check_maps_for_test(maps, 0x1000).is_ok());
    for bad in [
        maps.replace("r-xp", "rwxp"),
        maps.replace("r-xp", "r-xs"),
        maps.replace("2000-3000", "2000-2800"),
        maps.replace("00:00 0", "00:01 1"),
        maps.replace("3000-5000", "4000-5000"),
    ] {
        assert!(copy::check_maps_for_test(&bad, 0x1000).is_err());
    }
}
