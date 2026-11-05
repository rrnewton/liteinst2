//! Maintained external-encoding regressions and a generated
//! cross-check pinning the scanner tables to iced-x86 lengths
//! and liteinst-jit admission. Unknown (len 0) is a safe
//! conservative outcome in the generated sweep; a wrong
//! positive length or a movable claim outside admission fails.

use liteinst_jit::decode::{InsnClass, decode_one, decode_supported};
use minijit_scanner::scan_one;

#[derive(Default)]
struct Counts {
    valid: u64,
    modelled: u64,
    movable: u64,
}

fn oracle_flags(bytes: &[u8]) -> Option<(usize, bool, bool, bool, bool)> {
    let d = decode_one(bytes, 0x1000)?;
    let admitted = decode_supported(bytes, 0x1000);
    let relative = matches!(
        d.class,
        InsnClass::CondBranch { .. } | InsnClass::DirectJump { .. } | InsnClass::DirectCall { .. }
    );
    let rip = d.instruction.is_ip_rel_memory_operand();
    let intercept = matches!(d.class, InsnClass::Syscall | InsnClass::Nondet(_));
    let movable = matches!(&admitted, Ok(a) if a.class == InsnClass::Ordinary) && !rip;
    Some((d.len, relative, rip, intercept, movable))
}

fn check(bytes: &[u8], label: &str, counts: &mut Counts, require_modelled: bool) {
    let Some((len, relative, rip, intercept, oracle_movable)) = oracle_flags(bytes) else {
        return;
    };
    counts.valid += 1;
    let s = scan_one(bytes, 0x1000);
    if s.len == 0 {
        assert!(
            !require_modelled,
            "{label}: scanner left modelled case unknown, bytes={bytes:02x?}"
        );
        assert!(
            !s.allowlisted_movable,
            "{label}: unknown length must not be movable, bytes={bytes:02x?}"
        );
        return;
    }
    counts.modelled += 1;
    counts.movable += u64::from(s.allowlisted_movable);
    assert_eq!(
        s.len, len,
        "{label}: wrong positive length, bytes={bytes:02x?} scan={s:?}"
    );
    assert_eq!(
        s.relative_branch_or_call, relative,
        "{label}: relative mismatch, bytes={bytes:02x?} scan={s:?}"
    );
    assert_eq!(
        s.rip_relative, rip,
        "{label}: RIP-relative mismatch, bytes={bytes:02x?} scan={s:?}"
    );
    assert_eq!(
        s.interception_target, intercept,
        "{label}: intercept mismatch, bytes={bytes:02x?} scan={s:?}"
    );
    if s.allowlisted_movable {
        assert!(
            oracle_movable,
            "{label}: false movable outside admission, bytes={bytes:02x?} scan={s:?}"
        );
    }
}

#[test]
fn external_regression_cases_match_oracle() {
    let cases: &[(&str, &[u8])] = &[
        (
            "rexw-overrides-66-add",
            &[0x66, 0x48, 0x05, 0x11, 0x22, 0x33, 0x44],
        ),
        (
            "rexw-overrides-66-imul",
            &[0x66, 0x48, 0x69, 0xc0, 0x11, 0x22, 0x33, 0x44],
        ),
        (
            "rexw-overrides-66-test",
            &[0x66, 0x48, 0xf7, 0xc0, 0x11, 0x22, 0x33, 0x44],
        ),
        (
            "legacy-after-rex-mov",
            &[
                0x48, 0x66, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
        ),
        ("vex2-pinsrw-imm8", &[0xc5, 0xf9, 0xc4, 0xc0, 1]),
        ("vex2-pextrw-imm8", &[0xc5, 0xf9, 0xc5, 0xc0, 1]),
        ("vex3-pinsrw-imm8", &[0xc4, 0xe1, 0x79, 0xc4, 0xc0, 1]),
        (
            "evex-map2-op77-modrm",
            &[0x62, 0xf2, 0x7d, 0x48, 0x77, 0xc0],
        ),
        ("extrq-two-immediates", &[0x66, 0x0f, 0x78, 0xc0, 1, 2]),
        ("xlat-no-modrm", &[0xd7, 0xc0]),
        ("push-fs-no-modrm", &[0x0f, 0xa0, 0xc0]),
        ("xacquire-lock-add", &[0xf2, 0xf0, 0x01, 0x08]),
        ("xrelease-lock-add", &[0xf3, 0xf0, 0x01, 0x08]),
        ("xacquire-xchg", &[0xf2, 0x87, 0x08]),
        ("xacquire-xchg-byte", &[0xf2, 0x86, 0x08]),
        ("xrelease-xchg", &[0xf3, 0x87, 0x08]),
        ("xrelease-mov-store", &[0xf3, 0x89, 0x08]),
        ("vmptrld-not-intercept", &[0x0f, 0xc7, 0x30]),
        ("rdpid-no-rex", &[0xf3, 0x0f, 0xc7, 0xf8]),
        ("rdpid-66", &[0x66, 0xf3, 0x0f, 0xc7, 0xf8]),
        ("rdpid-cancelled-rex", &[0x48, 0xf3, 0x0f, 0xc7, 0xf8]),
        ("rdpid-effective-rexw", &[0xf3, 0x48, 0x0f, 0xc7, 0xf8]),
        ("sal-c0-imm", &[0xc0, 0xf0, 0x01]),
        ("sal-d0-mem", &[0xd0, 0x30]),
        ("shl-c0-control", &[0xc0, 0xe0, 0x01]),
        ("shl-d1-control", &[0xd1, 0xe0]),
        ("reservednop-0f1f-reg6", &[0x0f, 0x1f, 0x30]),
        ("nop-0f1f-reg0-control", &[0x0f, 0x1f, 0x00]),
        ("control-ordinary-add", &[0x01, 0x08]),
        ("control-lock-add", &[0xf0, 0x01, 0x08]),
        ("control-66-rel32-call", &[0x66, 0xe8, 1, 2, 3, 4]),
        ("control-66-rel32-jcc", &[0x66, 0x0f, 0x84, 1, 2, 3, 4]),
        ("control-legacy-pinsrw", &[0x66, 0x0f, 0xc4, 0xc0, 1]),
        ("control-legacy-pextrw", &[0x66, 0x0f, 0xc5, 0xc0, 1]),
        ("control-vzeroupper", &[0xc5, 0xf8, 0x77]),
        ("control-sib-disp32", &[0x48, 0x8b, 0x04, 0x25, 1, 2, 3, 4]),
        (
            "control-addr67-eip-rel",
            &[0x67, 0x48, 0x8b, 0x05, 1, 2, 3, 4],
        ),
        ("control-cr-register-modrm", &[0x0f, 0x22, 0xc0]),
        ("control-clts-no-modrm", &[0x0f, 0x06, 0xc3]),
    ];
    let mut counts = Counts::default();
    for &(name, bytes) in cases {
        check(bytes, name, &mut counts, true);
    }
    assert_eq!(
        counts.valid as usize,
        cases.len(),
        "all regression rows must be iced-valid"
    );
    for name in [
        "xacquire-lock-add",
        "xrelease-lock-add",
        "xacquire-xchg",
        "xacquire-xchg-byte",
        "xrelease-xchg",
        "xrelease-mov-store",
    ] {
        let bytes = cases.iter().find(|(n, _)| *n == name).unwrap().1;
        assert!(
            !scan_one(bytes, 0x1000).allowlisted_movable,
            "{name} must not be movable"
        );
    }
    assert!(
        scan_one(&[0x01, 0x08], 0x1000).allowlisted_movable,
        "ordinary ADD control"
    );
    assert!(
        scan_one(&[0xf0, 0x01, 0x08], 0x1000).allowlisted_movable,
        "LOCK ADD control"
    );
    assert!(
        !scan_one(&[0x0f, 0xc7, 0x30], 0x1000).interception_target,
        "VMPTRLD class"
    );
    for bytes in [
        &[0xf3, 0x0f, 0xc7, 0xf8][..],
        &[0x66, 0xf3, 0x0f, 0xc7, 0xf8][..],
        &[0x48, 0xf3, 0x0f, 0xc7, 0xf8][..],
        &[0xf3, 0x48, 0x0f, 0xc7, 0xf8][..],
    ] {
        assert!(
            scan_one(bytes, 0x1000).interception_target,
            "RDPID {bytes:02x?}"
        );
    }
    assert!(
        !scan_one(&[0xc0, 0xf0, 0x01], 0x1000).allowlisted_movable,
        "SAL C0 not movable"
    );
    assert!(
        !scan_one(&[0xd0, 0x30], 0x1000).allowlisted_movable,
        "SAL D0 not movable"
    );
    assert!(
        scan_one(&[0xc0, 0xe0, 0x01], 0x1000).allowlisted_movable,
        "SHL C0 control"
    );
    assert!(
        scan_one(&[0xd1, 0xe0], 0x1000).allowlisted_movable,
        "SHL D1 control"
    );
}

fn generated(prefix: &[u8], opcode: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(prefix.len() + opcode.len() + tail.len() + 4);
    v.extend_from_slice(prefix);
    v.extend_from_slice(opcode);
    v.extend_from_slice(tail);
    v.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]);
    v
}

#[test]
fn generated_encoding_cross_check() {
    // Fixed deterministic sweep (no RNG, no network): prefix/REX
    // orderings x legacy/0F/0F38/0F3A/VEX/EVEX opcode maps x
    // fixed ModRM/disp/imm tails. Positive scanner lengths must
    // equal iced exactly and movable must imply admission.
    let prefixes: &[&[u8]] = &[
        &[],
        &[0x66],
        &[0x48],
        &[0x66, 0x48],
        &[0x48, 0x66],
        &[0xf2],
        &[0xf3],
        &[0xf0],
        &[0xf2, 0xf0],
        &[0xf3, 0xf0],
        &[0x67],
        &[0x64],
        &[0xf3, 0x48],
        &[0x48, 0xf3],
        &[0x66, 0x66, 0x48],
    ];
    let tails: &[&[u8]] = &[
        &[0xc0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        &[0x05, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        &[0x84, 0x24, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        // Reg-variant tails so reg-sensitive classes (shift /6,
        // group opcodes) are covered, not only reg-0 forms.
        &[0x30, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        &[0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        &[0xe0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    ];
    let mut counts = Counts::default();
    for (pi, prefix) in prefixes.iter().enumerate() {
        for op in 0u16..=0xff {
            for (ti, tail) in tails.iter().enumerate() {
                let bytes = generated(prefix, &[op as u8], tail);
                check(
                    &bytes,
                    &format!("legacy p{pi} op{op:02x} t{ti}"),
                    &mut counts,
                    false,
                );
            }
        }
    }
    for (pi, prefix) in prefixes.iter().take(10).enumerate() {
        for op in 0u16..=0xff {
            for (ti, tail) in tails.iter().enumerate() {
                let bytes = generated(prefix, &[0x0f, op as u8], tail);
                check(
                    &bytes,
                    &format!("0f p{pi} op{op:02x} t{ti}"),
                    &mut counts,
                    false,
                );
            }
        }
    }
    for map in [0x38u8, 0x3a] {
        for (pi, prefix) in prefixes.iter().take(3).enumerate() {
            for op in 0u16..=0xff {
                let bytes = generated(prefix, &[0x0f, map, op as u8], tails[0]);
                check(
                    &bytes,
                    &format!("0f{map:02x} p{pi} op{op:02x}"),
                    &mut counts,
                    false,
                );
            }
        }
    }
    for pp in 0u8..4 {
        for op in 0u16..=0xff {
            let bytes = generated(&[], &[0xc5, 0xf8 | pp, op as u8], tails[0]);
            check(
                &bytes,
                &format!("vex2 pp{pp} op{op:02x}"),
                &mut counts,
                false,
            );
        }
    }
    for map in 1u8..=3 {
        for op in 0u16..=0xff {
            let v3 = generated(&[], &[0xc4, 0xe0 | map, 0x78, op as u8], tails[0]);
            check(&v3, &format!("vex3 m{map} op{op:02x}"), &mut counts, false);
        }
    }
    // EVEX P1 bit 2 is a mandatory fixed 1 bit: 0x7c, not 0x78.
    // Track this family separately so aggregate floors cannot
    // hide a vacuous EVEX sweep (the pre-fix generator yielded
    // 0 valid EVEX cases out of 768 attempts).
    let mut evex_counts = Counts::default();
    for map in 1u8..=3 {
        for op in 0u16..=0xff {
            let ev = generated(&[], &[0x62, 0xf0 | map, 0x7c, 0x48, op as u8], tails[0]);
            check(
                &ev,
                &format!("evex m{map} op{op:02x}"),
                &mut evex_counts,
                false,
            );
        }
    }
    eprintln!(
        "generated EVEX cross-check: valid={} modelled={} movable={} (of 768 attempts)",
        evex_counts.valid, evex_counts.modelled, evex_counts.movable
    );
    assert!(
        evex_counts.valid >= 10,
        "EVEX generated family is vacuous: valid={}",
        evex_counts.valid
    );
    counts.valid += evex_counts.valid;
    counts.modelled += evex_counts.modelled;
    counts.movable += evex_counts.movable;
    eprintln!(
        "generated cross-check: valid={} modelled={} movable={}",
        counts.valid, counts.modelled, counts.movable
    );
    assert!(
        counts.valid > 5_000,
        "generated sweep is vacuous: valid={}",
        counts.valid
    );
    assert!(
        counts.modelled > 4_000,
        "scanner modelled too little of the sweep"
    );
    assert!(
        counts.movable > 100,
        "no movable coverage in generated sweep"
    );
}

fn write_minimal_elf(code: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "minijit-scanner-test-{}-{:x}.elf",
        std::process::id(),
        code.iter().fold(0x811c9dc5u32, |h, b| (h ^ u32::from(*b))
            .wrapping_mul(0x01000193))
    ));
    let mut f = vec![0u8; 0x2c0];
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELFCLASS64
    f[5] = 1; // little endian
    f[6] = 1; // version
    let put16 = |f: &mut [u8], o: usize, v: u16| f[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |f: &mut [u8], o: usize, v: u32| f[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |f: &mut [u8], o: usize, v: u64| f[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put16(&mut f, 16, 2); // ET_EXEC
    put16(&mut f, 18, 62); // x86-64
    put32(&mut f, 20, 1);
    put64(&mut f, 24, 0x401000);
    put64(&mut f, 40, 0x200); // shoff
    put16(&mut f, 52, 64); // ehsize
    put16(&mut f, 58, 64); // shentsize
    put16(&mut f, 60, 3); // shnum
    put16(&mut f, 62, 2); // shstrndx
    f[0x100..0x100 + code.len()].copy_from_slice(code);
    let names = b"\0.text\0.shstrtab\0";
    f[0x120..0x120 + names.len()].copy_from_slice(names);
    let text_hdr = 0x200 + 64;
    put32(&mut f, text_hdr, 1);
    put32(&mut f, text_hdr + 4, 1); // PROGBITS
    put64(&mut f, text_hdr + 8, 6); // ALLOC|EXEC
    put64(&mut f, text_hdr + 16, 0x401000);
    put64(&mut f, text_hdr + 24, 0x100);
    put64(&mut f, text_hdr + 32, code.len() as u64);
    let str_hdr = 0x200 + 128;
    put32(&mut f, str_hdr, 7);
    put32(&mut f, str_hdr + 4, 3); // STRTAB
    put64(&mut f, str_hdr + 24, 0x120);
    put64(&mut f, str_hdr + 32, names.len() as u64);
    std::fs::write(&path, f).expect("write minimal ELF");
    path
}

#[test]
fn driver_fails_closed_on_invalid_boundary() {
    let bin = env!("CARGO_BIN_EXE_minijit-scanner");
    let bad = write_minimal_elf(&[0xf0, 0x90]);
    let out = std::process::Command::new(bin)
        .arg(&bad)
        .output()
        .expect("run driver");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "invalid ELF must fail: {stdout}");
    assert!(
        stdout.contains("BLOCKED"),
        "invalid ELF must report BLOCKED: {stdout}"
    );
    assert!(
        !stdout.contains(",scanner,"),
        "no speed cells on blocked input: {stdout}"
    );
    let _ = std::fs::remove_file(&bad);

    // Truncated headers must also take the BLOCKED path, not panic.
    let trunc = write_minimal_elf(&[0x90, 0x90, 0xc3]);
    let mut truncated = std::fs::read(&trunc).expect("read minimal ELF");
    truncated.truncate(80);
    std::fs::write(&trunc, truncated).expect("truncate minimal ELF");
    let out = std::process::Command::new(bin)
        .arg(&trunc)
        .output()
        .expect("run driver");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "truncated ELF must fail: {stdout}");
    assert!(
        stdout.contains("BLOCKED"),
        "truncated ELF must report BLOCKED: {stdout}"
    );
    assert!(
        !stdout.contains(",scanner,"),
        "no speed cells on truncated ELF: {stdout}"
    );
    assert!(
        !stderr.contains("panicked"),
        "truncated ELF must not panic: {stderr}"
    );
    let _ = std::fs::remove_file(&trunc);

    let good = write_minimal_elf(&[0x90, 0xc3]);
    let out = std::process::Command::new(bin)
        .arg(&good)
        .output()
        .expect("run driver");
    assert!(
        out.status.success(),
        "ordinary ELF control must pass: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let _ = std::fs::remove_file(&good);
}
