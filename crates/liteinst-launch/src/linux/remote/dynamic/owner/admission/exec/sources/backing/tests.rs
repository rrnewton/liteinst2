//! Pure gates over initialized model observations, not native fd/mmap evidence.
use super::*;

const PROBE: &str = "00004000-00005000 ---p 00000000 00:2a 700 /objects/main  image\n";

fn exact_refusal<T>(value: Result<T, GateError>, expected: &'static str) {
    assert!(matches!(value, Err(GateError::Refused(message)) if message == expected));
}

fn surface() -> libc::stat {
    // All substrate bytes are initialized; this is synthetic filesystem stat
    // evidence. It deliberately has a different device from the VMA record.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    stat.st_dev = libc::makedev(0, 48);
    stat.st_ino = 700;
    stat.st_mode = libc::S_IFREG | 0o555;
    stat.st_size = 8192;
    stat
}

#[test]
fn exec_backing_projection_preserves_distinct_exact_identity_spaces() {
    let raw = format!(
        "00001000-00002000 rw-p 00000000 00:00 0\n{PROBE}00008000-00009000 r-xp 00000000 08:01 900 /unrelated\n"
    );
    let vma = projection(raw.as_bytes(), 0x4000).unwrap();
    assert_eq!(
        vma,
        FileIdentity {
            major: 0,
            minor: 42,
            inode: 700
        }
    );
    let opened = descriptor_value(&surface()).unwrap();
    assert_eq!(
        opened.file,
        FileIdentity {
            major: 0,
            minor: 48,
            inode: 700
        }
    );
    assert_ne!(opened.file, vma);
    assert_eq!(opened.mode, libc::S_IFREG | 0o555);
    assert_eq!(opened.length, 8192);

    // Neither projection is rewritten to agree with the other. Each literal
    // maps field survives for the caller's unchanged exact child-row binding.
    for (from, to, expected) in [
        (
            "00:2a",
            "08:2a",
            FileIdentity {
                major: 8,
                minor: 42,
                inode: 700,
            },
        ),
        (
            "00:2a",
            "00:2b",
            FileIdentity {
                major: 0,
                minor: 43,
                inode: 700,
            },
        ),
        (
            " 700 ",
            " 701 ",
            FileIdentity {
                major: 0,
                minor: 42,
                inode: 701,
            },
        ),
    ] {
        let changed = PROBE.replace(from, to);
        let actual = projection(changed.as_bytes(), 0x4000).unwrap();
        assert_eq!(actual, expected);
        assert_ne!(actual, vma);
    }
    // Path spelling is descriptive; no whitelist participates in identity.
    assert_eq!(
        projection(
            PROBE
                .replace("/objects/main  image", "/different spelling")
                .as_bytes(),
            0x4000
        )
        .unwrap(),
        vma,
    );
}

#[test]
fn exec_backing_projection_rejects_wrong_owned_geometry_and_protection() {
    for address in [0, 0x4001, u64::MAX - (PAGE - 1)] {
        exact_refusal(
            projection(PROBE.as_bytes(), address),
            "exec identity probe geometry differs",
        );
    }
    exact_refusal(
        projection(PROBE.as_bytes(), 0x6000),
        "exec identity probe mapping is absent or merged",
    );
    for (from, to) in [
        ("00004000-00005000", "00003000-00005000"),
        ("00004000-00005000", "00004000-00006000"),
    ] {
        exact_refusal(
            projection(PROBE.replace(from, to).as_bytes(), 0x4000),
            "exec identity probe mapping is absent or merged",
        );
    }
    for (from, to) in [
        ("---p", "r--p"),
        ("---p", "-w-p"),
        ("---p", "--xp"),
        ("---p", "---s"),
        ("00000000", "00001000"),
        (" 700 ", " 0 "),
        (" /objects/main  image", ""),
    ] {
        exact_refusal(
            projection(PROBE.replace(from, to).as_bytes(), 0x4000),
            "exec identity probe mapping differs",
        );
    }
    assert_eq!(projection(PROBE.as_bytes(), 0x4000).unwrap().inode, 700);
}

#[test]
fn exec_backing_projection_rejects_invalid_suffix_duplicate_and_capture_overflow() {
    for malformed in [
        format!("{PROBE}invalid trailing row\n"),
        PROBE.trim_end_matches('\n').to_owned(),
        format!("{PROBE}{PROBE}"),
        PROBE.replace("00005000", "00004000"),
        PROBE.replace("---p", "---q"),
        PROBE.replace(" 700 ", " 18446744073709551616 "),
    ] {
        exact_refusal(
            projection(malformed.as_bytes(), 0x4000),
            "exec source maps are malformed or excessive",
        );
    }
    let mut excessive = PROBE.to_owned();
    for i in 0..MAP_ROWS {
        let start = 0x10000 + i as u64 * PAGE;
        excessive.push_str(&format!(
            "{start:016x}-{:016x} ---p 00000000 00:00 0\n",
            start + PAGE
        ));
    }
    assert!(excessive.len() <= MAP_BYTES);
    exact_refusal(
        projection(excessive.as_bytes(), 0x4000),
        "exec source maps are malformed or excessive",
    );
    let mut bytes = PROBE.as_bytes().to_vec();
    bytes.resize(MAP_BYTES + 1, b' ');
    exact_refusal(
        projection(&bytes, 0x4000),
        "exec source maps exceed fixed capture bound",
    );
}

#[test]
fn exec_backing_descriptor_requires_identified_regular_file_and_retains_metadata() {
    for case in 0..5 {
        let mut stat = surface();
        match case {
            0 => stat.st_mode = libc::S_IFDIR | 0o555,
            1 => stat.st_mode = libc::S_IFLNK | 0o555,
            2 => stat.st_ino = 0,
            3 => stat.st_size = 0,
            4 => stat.st_size = -1,
            _ => unreachable!(),
        }
        exact_refusal(
            descriptor_value(&stat),
            "exec identity descriptor is not an identified regular file",
        );
    }
    let original = descriptor_value(&surface()).unwrap();
    for case in 0..5 {
        let mut stat = surface();
        match case {
            0 => stat.st_dev = libc::makedev(1, 48),
            1 => stat.st_dev = libc::makedev(0, 49),
            2 => stat.st_ino += 1,
            3 => stat.st_mode ^= 0o020,
            4 => stat.st_size += 1,
            _ => unreachable!(),
        }
        assert_ne!(descriptor_value(&stat).unwrap(), original);
    }
    // Access metadata may change because the object is opened/mapped. It is
    // not substituted for stable descriptor identity or child byte equality.
    let mut access = surface();
    access.st_atime = 1;
    assert_eq!(descriptor_value(&access).unwrap(), original);
}
