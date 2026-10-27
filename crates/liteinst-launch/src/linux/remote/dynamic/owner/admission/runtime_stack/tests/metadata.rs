use super::*;
#[test]
fn stack_smaps_matches_complete_inventory_and_retains_raw_path_bytes() {
    let good = validate_smaps(SMAPS, BASELINE, 2).unwrap();
    assert_eq!(good.flags(), 0xff);
    for text in [
        String::from_utf8_lossy(SMAPS).replace("00402000", "00403000"),
        String::from_utf8_lossy(SMAPS).replace("08:01", "08:02"),
        String::from_utf8_lossy(SMAPS).replace("/code", "/other"),
        String::from_utf8_lossy(SMAPS).replace("r--p", "r-xp"),
        String::from_utf8_lossy(SMAPS).replace("00600000-00601000", "00600000 00601000"),
    ] {
        assert!(validate_smaps(text.as_bytes(), BASELINE, 2).is_err());
    }
    let mut nul = SMAPS.to_vec();
    nul[5] = 0;
    assert_eq!(validate_smaps(&nul, BASELINE, 2), Err(StackError::Framing));
    assert_eq!(
        validate_smaps(&SMAPS[..SMAPS.len() - 1], BASELINE, 2),
        Err(StackError::Framing)
    );
    assert_eq!(
        validate_smaps(&vec![b'0'; BYTES + 1], BASELINE, 2),
        Err(StackError::Framing)
    );
    let mut raw_maps = BASELINE.to_vec();
    let i = raw_maps.iter().position(|b| *b == b'/').unwrap();
    raw_maps[i + 1] = 0xff;
    let mut raw_smaps = SMAPS.to_vec();
    let i = raw_smaps.iter().position(|b| *b == b'/').unwrap();
    raw_smaps[i + 1] = 0xff;
    assert_eq!(validate_smaps(&raw_smaps, &raw_maps, 2), Ok(good));
}
#[test]
fn stack_smaps_key_and_vmflags_are_positive_closed_unique_facts() {
    for (old, new) in [
        ("ProtectionKey:          0\n", ""),
        ("ProtectionKey:          0", "ProtectionKey:          1"),
        (
            "ProtectionKey:          0",
            "ProtectionKey:          0\nProtectionKey:          0",
        ),
        ("rd wr mr mw me gd ac sd", "rd wr mr mw me gd sd"),
        ("rd wr mr mw me gd ac sd", "rd wr mr mw me gd ac ac"),
        ("rd wr mr mw me gd ac sd", "rd wr mr mw me gd ac ex"),
        ("rd wr mr mw me gd ac sd", "rd wr mr mw me gd ac zz"),
        (
            "VmFlags: rd wr mr mw me gd ac sd",
            "VmFlags: rd wr mr mw me gd ac sd\nVmFlags: rd wr mr mw me gd ac sd",
        ),
    ] {
        let changed = String::from_utf8_lossy(SMAPS).replace(old, new);
        assert!(
            validate_smaps(changed.as_bytes(), BASELINE, 2).is_err(),
            "{old} -> {new}"
        );
    }
    let optional = String::from_utf8_lossy(SMAPS).replace("ac sd", "ac nh");
    assert_eq!(
        validate_smaps(optional.as_bytes(), BASELINE, 2)
            .unwrap()
            .flags(),
        0x17f
    );
}
#[test]
fn stack_identity_uses_complete_original_row_not_stack_name_or_endpoints() {
    let descriptor =
        StackDescriptor::validate(ORIGINAL, BASELINE, 0x802010, &(0x600000..0x601000)).unwrap();
    assert_eq!(descriptor.range(), 0x800000..0x804000);
    assert_eq!(descriptor.original_index, 1);
    assert_eq!(descriptor.baseline_index, 2);
    assert_eq!(descriptor.require_current(ORIGINAL, BASELINE), Ok(2));
    for (old, new) in [
        ("00800000-00804000", "00800000-00805000"),
        ("[stack]", "[other]"),
        ("00:00 0 [stack]", "00:01 0 [stack]"),
        ("rw-p", "rw-s"),
        ("rw-p 00000000", "rw-p 00001000"),
        ("0 [stack]", "0  [stack]"),
    ] {
        let changed = String::from_utf8_lossy(BASELINE).replace(old, new);
        assert_eq!(
            descriptor.require_current(ORIGINAL, changed.as_bytes()),
            Err(StackError::Provenance)
        );
    }
    let original = String::from_utf8_lossy(ORIGINAL).replace("[stack]", "literal-name");
    let baseline = String::from_utf8_lossy(BASELINE).replace("[stack]", "literal-name");
    assert!(
        StackDescriptor::validate(
            original.as_bytes(),
            baseline.as_bytes(),
            0x802010,
            &(0x600000..0x601000)
        )
        .is_ok()
    );
    assert_eq!(
        StackDescriptor::validate(ORIGINAL, BASELINE, 0x804000, &(0x600000..0x601000)),
        Err(StackError::Provenance)
    );
    assert_eq!(
        StackDescriptor::validate(ORIGINAL, BASELINE, 0x802010, &(0x802000..0x803000)),
        Err(StackError::Provenance)
    );
}
#[test]
fn stack_file_capture_requires_complete_actual_request_prefix_and_closes() {
    let mut bytes = vec![0; BYTES];
    let mut capture = FileCapture::default();
    file(&mut bytes, &mut capture, BASELINE);
    assert_eq!(capture.bytes(&bytes).unwrap(), BASELINE);
    for change in 0..13 {
        let mut bad = capture;
        match change {
            0 => bad.started = false,
            1 => bad.complete = false,
            2 => bad.overflow = true,
            3 => bad.directory_open = None,
            4 => bad.directory_filesystem = Some(0),
            5 => {
                bad.file_statfs = Some(Request {
                    result: -1,
                    errno: Some(libc::EIO),
                })
            }
            6 => bad.file_close = None,
            7 => {
                bad.directory_close = Some(Request {
                    result: -1,
                    errno: Some(libc::EIO),
                })
            }
            8 => bad.first_read.as_mut().unwrap().destination += 1,
            9 => bad.last_read.as_mut().unwrap().request.result = 1,
            10 => bad.copied -= 1,
            11 => bad.read_calls = 1,
            12 => bad.first_failure = Some(StackError::Request),
            _ => unreachable!(),
        }
        assert!(bad.bytes(&bytes).is_err());
    }
    assert_eq!(&bytes[..BASELINE.len()], BASELINE);
    // Two calls mean one positive read followed by EOF; an unrecorded
    // positive byte cannot be attributed to that EOF request.
    let mut missing_read = capture;
    missing_read.first_read.as_mut().unwrap().request.result -= 1;
    assert_eq!(missing_read.bytes(&bytes), Err(StackError::Request));
    let mut no_progress = capture;
    no_progress.read_calls = 3;
    assert_eq!(no_progress.bytes(&bytes), Err(StackError::Request));
    let mut too_many = capture;
    too_many.first_read.as_mut().unwrap().request.result = 1;
    too_many.read_calls = capture.copied + 2;
    assert_eq!(too_many.bytes(&bytes), Err(StackError::Request));
    // Positive short reads remain permitted when their retained aggregate
    // admits that exact number of strictly positive intermediate reads.
    let mut short = capture;
    short.first_read.as_mut().unwrap().request.result -= 1;
    short.read_calls = 3;
    assert_eq!(short.bytes(&bytes), Ok(BASELINE));
    let mut single_bytes = capture;
    single_bytes.first_read.as_mut().unwrap().request.result = 1;
    single_bytes.read_calls = capture.copied + 1;
    assert_eq!(single_bytes.bytes(&bytes), Ok(BASELINE));
    assert_eq!(&bytes[..BASELINE.len()], BASELINE);
}
