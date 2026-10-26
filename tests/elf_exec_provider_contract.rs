//! Pure parser controls execute once, outside the shared native oracle module.
#[path = "support/elf_exec_provider.rs"]
mod provider;

use provider::{Provider, Refusal, map_owner, parse};
use std::path::Path;

const FD: &str = "pos:\t83496\nflags:\t02100000\nmnt_id:\t17\nino:\t12345\n";
const MOUNT: &str = "17 8 0:42 /subvolume /owned rw,noatime - btrfs /dev/device rw\n";

fn expected() -> Provider {
    parse(FD, MOUNT, 12345).unwrap()
}

#[test]
fn binds_exact_descriptor_mount_record() {
    let result = expected();
    assert_eq!(result.mount_id, 17);
    assert_eq!(result.device, (0, 42));
    assert_eq!(result.mount_record, MOUNT);
    let extra = format!("9 8 0:48 /other /other rw - tmpfs tmpfs rw\n{MOUNT}");
    assert_eq!(parse(FD, &extra, 12345), Ok(result));
}

#[test]
fn refuses_missing_ambiguous_or_wrong_descriptor_fields() {
    for text in [
        FD.replace("mnt_id:\t17\n", ""),
        format!("{FD}mnt_id:\t17\n"),
        FD.replace("mnt_id:\t17", "mnt_id:\t0"),
        FD.replace("mnt_id:\t17", "mnt_id:\t+17"),
        FD.replace("ino:\t12345", "ino:\t12346"),
        format!("{FD}ino:\t12345\n"),
        FD.trim_end().to_string(),
    ] {
        assert_eq!(parse(&text, MOUNT, 12345), Err(Refusal::FdInfo));
    }
}

#[test]
fn refuses_missing_or_duplicate_mount_owner() {
    assert_eq!(
        parse(FD, "9 8 0:42 / / rw - btrfs dev rw\n", 12345),
        Err(Refusal::MountInfo)
    );
    assert_eq!(
        parse(FD, &format!("{MOUNT}{MOUNT}"), 12345),
        Err(Refusal::MountInfo)
    );
}

#[test]
fn refuses_malformed_mount_record() {
    for text in [
        MOUNT.replace("0:42", "0:invalid"),
        MOUNT.replace("0:42", "+0:42"),
        MOUNT.replace(" - ", " "),
        MOUNT.replace("17 8", "17 invalid"),
        MOUNT.replace(" /owned ", " relative "),
        MOUNT.trim_end().to_string(),
    ] {
        assert_eq!(parse(FD, &text, 12345), Err(Refusal::MountInfo));
    }
}

#[test]
fn accepts_exact_map_device_inode_and_link_owner() {
    assert_eq!(
        map_owner(
            &expected(),
            Path::new("/owned/subject"),
            12345,
            (0, 42),
            12345,
            Path::new("/owned/subject")
        ),
        Ok(())
    );
}

#[test]
fn refuses_wrong_mapping_device() {
    assert_eq!(
        map_owner(
            &expected(),
            Path::new("/owned/subject"),
            12345,
            (0, 48),
            12345,
            Path::new("/owned/subject")
        ),
        Err(Refusal::MapDevice)
    );
}

#[test]
fn refuses_wrong_mapping_inode() {
    for inode in [0, 12346] {
        assert_eq!(
            map_owner(
                &expected(),
                Path::new("/owned/subject"),
                12345,
                (0, 42),
                inode,
                Path::new("/owned/subject")
            ),
            Err(Refusal::MapInode)
        );
    }
}

#[test]
fn refuses_foreign_or_deleted_mapping_link() {
    for path in [
        "/other-subvolume/subject",
        "/owned/subject (deleted)",
        "/owned/./subject",
        "/owned//subject",
        "/owned/subject/",
    ] {
        assert_eq!(
            map_owner(
                &expected(),
                Path::new("/owned/subject"),
                12345,
                (0, 42),
                12345,
                Path::new(path)
            ),
            Err(Refusal::MapPath)
        );
    }
}
