//! Supplied descriptor/map records only. No file open, mmap, held owner,
//! process query, stop token, or successful ExecutableProjection is fabricated.
use super::super::super::artifact::tests as artifact_model;
use super::*;

const MAPS: &str = "00200000-00201000 r--p 00000000 00:2a 700 /artifact\n00201000-00202000 r-xp 00001000 00:2a 700 /artifact\n";

fn supplied() -> (DescriptorIdentity, ExecutableIdentity) {
    let pinned = DescriptorIdentity {
        file: source_identity::FileIdentity {
            major: 0,
            minor: 48,
            inode: 700,
        },
        mode: libc::S_IFREG | 0o555,
        length: 8904,
    };
    let observed = ExecutableIdentity {
        opened: pinned,
        vma: source_identity::FileIdentity {
            major: 0,
            minor: 42,
            inode: 700,
        },
    };
    (pinned, observed)
}
fn plan() -> ArtifactPlan {
    artifact_model::parse(&artifact_model::model()).unwrap()
}
fn invalid(result: Result<(), OracleError>, expected: &'static str) {
    assert!(matches!(result, Err(OracleError::Invalid(message)) if message == expected));
}

#[test]
fn consumer_raw_projection_keeps_distinct_descriptor_and_vma_identities() {
    let plan = plan();
    let (pinned, observed) = supplied();
    assert_ne!(pinned.file, observed.vma);
    require_descriptor(&pinned, &observed).unwrap();
    require_original_maps(&plan, observed.vma, MAPS.as_bytes()).unwrap();
    invalid(
        require_original_maps(&plan, pinned.file, MAPS.as_bytes()),
        "raw original executable rows absent",
    );
    // Path spelling remains descriptive; neither a pathname nor an unrelated
    // row substitutes for the exact supplied device/inode and two load rows.
    let other = MAPS.replace("/artifact", "/same object different spelling")
        + "00300000-00301000 r--p 00000000 00:2b 701 /unrelated\n";
    require_original_maps(&plan, observed.vma, other.as_bytes()).unwrap();
    assert_eq!(observed.opened, pinned);
    assert_eq!(observed.vma.minor, 42);
}

#[test]
fn consumer_raw_projection_rejects_each_opened_descriptor_field_change() {
    let (pinned, observed) = supplied();
    for changed in [
        DescriptorIdentity {
            file: source_identity::FileIdentity {
                major: 1,
                ..pinned.file
            },
            ..pinned
        },
        DescriptorIdentity {
            file: source_identity::FileIdentity {
                minor: 49,
                ..pinned.file
            },
            ..pinned
        },
        DescriptorIdentity {
            file: source_identity::FileIdentity {
                inode: 701,
                ..pinned.file
            },
            ..pinned
        },
        DescriptorIdentity {
            mode: libc::S_IFREG | 0o755,
            ..pinned
        },
        DescriptorIdentity {
            length: 8905,
            ..pinned
        },
    ] {
        assert_ne!(changed, pinned);
        invalid(
            require_descriptor(
                &pinned,
                &ExecutableIdentity {
                    opened: changed,
                    ..observed
                },
            ),
            "raw opened executable differs from pinned artifact",
        );
        // A correct VMA triple does not excuse a different opened object.
        require_original_maps(&plan(), observed.vma, MAPS.as_bytes()).unwrap();
        require_descriptor(&pinned, &observed).unwrap();
    }
}

#[test]
fn consumer_raw_projection_rejects_each_vma_identity_field_change() {
    let plan = plan();
    let (pinned, observed) = supplied();
    for changed in [
        source_identity::FileIdentity {
            major: 1,
            ..observed.vma
        },
        source_identity::FileIdentity {
            minor: 43,
            ..observed.vma
        },
        source_identity::FileIdentity {
            inode: 701,
            ..observed.vma
        },
    ] {
        assert_ne!(changed, observed.vma);
        let changed = ExecutableIdentity {
            vma: changed,
            ..observed
        };
        require_descriptor(&pinned, &changed).unwrap();
        invalid(
            require_original_maps(&plan, changed.vma, MAPS.as_bytes()),
            "raw original executable rows absent",
        );
        require_original_maps(&plan, observed.vma, MAPS.as_bytes()).unwrap();
    }
}

#[test]
fn consumer_raw_projection_preserves_exact_row_geometry_alias_and_count_refusals() {
    let plan = plan();
    let (_, observed) = supplied();
    let first = "00200000-00201000 r--p 00000000 00:2a 700 /artifact\n";
    let second = "00201000-00202000 r-xp 00001000 00:2a 700 /artifact\n";
    for (changed, expected) in [
        (
            MAPS.replace("00202000", "00203000"),
            "raw original executable mapping differs",
        ),
        (
            MAPS.replace("00200000-00201000", "001ff000-00201000"),
            "raw executable alias is outside two-load profile",
        ),
        (
            MAPS.replace("r--p 00000000", "r--p 00001000"),
            "raw original executable mapping differs",
        ),
        (
            MAPS.replace("r-xp 00001000", "r-xp 00002000"),
            "raw original executable mapping differs",
        ),
        (
            MAPS.replace("r--p", "rw-p"),
            "raw original executable mapping differs",
        ),
        (
            MAPS.replace("r-xp", "r--p"),
            "raw original executable mapping differs",
        ),
        (
            MAPS.replace("r-xp", "r-xs"),
            "raw original executable mapping differs",
        ),
        (
            format!("{MAPS}00300000-00301000 r--p 00000000 00:2a 700 /alias\n"),
            "raw executable alias is outside two-load profile",
        ),
        (first.to_string(), "raw original executable rows absent"),
        (second.to_string(), "raw original executable rows absent"),
        (
            MAPS.replace("r--p 00000000 00:2a", "r--p 00000000 00:2b"),
            "raw original executable rows absent",
        ),
        (
            MAPS.replace("r-xp 00001000 00:2a 700", "r-xp 00001000 00:2a 701"),
            "raw original executable rows absent",
        ),
        (
            "00200000-00202000 r--p 00000000 00:2a 700 /artifact\n".to_string(),
            "raw original executable mapping differs",
        ),
    ] {
        assert_ne!(changed, MAPS);
        invalid(
            require_original_maps(&plan, observed.vma, changed.as_bytes()),
            expected,
        );
        require_original_maps(&plan, observed.vma, MAPS.as_bytes()).unwrap();
    }
    assert!(require_original_maps(&plan, observed.vma, b"").is_err());
    let malformed = format!("{MAPS}not a maps row\n");
    assert!(require_original_maps(&plan, observed.vma, malformed.as_bytes()).is_err());
}
