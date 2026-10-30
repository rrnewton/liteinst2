//! Additive mapped-file identity controls. Native bodies use fresh-exec isolation.
use super::*;
use crate::isolated_native_test as isolated;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const FIXTURE_PATH: &[u8] = b"/fixture/subvolume-a/object";

fn fixture_stamp() -> Stamp {
    Stamp {
        dev: 48,
        ino: 71,
        len: c::PAGE,
        mode: 0o100600,
        uid: 5,
        gid: 6,
        mtime: 7,
        mtimens: 8,
        ctime: 9,
        ctimens: 10,
    }
}

fn change_stamp(mut pin: Stamp, field: usize) -> Stamp {
    match field {
        0 => pin.dev ^= 1,
        1 => pin.ino += 1,
        2 => pin.len += 1,
        3 => pin.mode ^= 0o100,
        4 => pin.uid ^= 1,
        5 => pin.gid ^= 1,
        6 => pin.mtime += 1,
        7 => pin.mtimens ^= 1,
        8 => pin.ctime += 1,
        9 => pin.ctimens ^= 1,
        _ => panic!("unknown Stamp member"),
    }
    pin
}

fn fixture_map(address: u64) -> Map {
    Map {
        start: address,
        end: address + c::PAGE,
        flags: 4,
        offset: 0,
        major: 0,
        minor: 42,
        inode: 71,
        name: FIXTURE_PATH.to_vec(),
    }
}

fn fixture_identity() -> MappedIdentity {
    calibrated_identity(
        fixture_stamp(),
        FIXTURE_PATH,
        0x10000,
        &[fixture_map(0x10000)],
        FIXTURE_PATH,
    )
    .unwrap()
}

#[test]
fn calibration_retains_full_stat_and_independent_proc_device() {
    let identity = fixture_identity();
    assert_eq!(identity.stamp, fixture_stamp());
    assert_eq!(identity.stamp.dev, 48);
    assert_eq!((identity.major, identity.minor), (0, 42));
    assert_eq!(identity.path, FIXTURE_PATH);
    assert_eq!(
        same_file_with(&fixture_map(0x20000), &identity, |_| Ok(
            FIXTURE_PATH.to_vec()
        )),
        Ok(true)
    );
}

#[test]
fn calibration_retains_each_stamp_member_without_numeric_normalization() {
    for field in 0..10 {
        let pin = change_stamp(fixture_stamp(), field);
        let mut row = fixture_map(0x10000);
        row.inode = pin.ino;
        let identity =
            calibrated_identity(pin, FIXTURE_PATH, row.start, &[row], FIXTURE_PATH).unwrap();
        assert_eq!(identity.stamp, pin, "Stamp member {field}");
        assert_eq!((identity.major, identity.minor), (0, 42));
    }
}

#[test]
fn calibration_requires_exact_owned_readonly_offset_zero_page() {
    for fault in 0..9 {
        let mut row = fixture_map(0x10000);
        match fault {
            0 => row.start -= c::PAGE,
            1 => row.end += c::PAGE,
            2 => row.start += c::PAGE,
            3 => row.offset = c::PAGE,
            4 => row.inode += 1,
            5 => row.flags = 6,
            6 => row.flags = 5,
            7 => row.flags = 0,
            _ => row.name = b"/fixture/subvolume-b/object".to_vec(),
        }
        assert_eq!(
            calibrated_identity(fixture_stamp(), FIXTURE_PATH, 0x10000, &[row], FIXTURE_PATH),
            Err(E::Ownership),
            "calibration fault {fault}"
        );
    }
}

#[test]
fn calibration_rejects_missing_ambiguous_and_overflowing_ranges() {
    let pin = fixture_stamp();
    assert_eq!(
        calibrated_identity(pin, FIXTURE_PATH, 0x10000, &[], FIXTURE_PATH),
        Err(E::Ownership)
    );
    assert_eq!(
        calibrated_identity(
            pin,
            FIXTURE_PATH,
            0x10000,
            &[fixture_map(0x10000), fixture_map(0x10000)],
            FIXTURE_PATH
        ),
        Err(E::Ownership)
    );
    assert_eq!(
        calibrated_identity(pin, FIXTURE_PATH, u64::MAX, &[], FIXTURE_PATH),
        Err(E::Ownership)
    );
}

#[test]
fn canonical_dentries_reject_deleted_alias_and_truncated_names() {
    assert!(canonical_path(FIXTURE_PATH));
    for path in [
        b"".as_slice(),
        b"/",
        b"object",
        b"/fixture//object",
        b"/fixture/./object",
        b"/fixture/../object",
        b"/fixture/object/",
        b"/fixture/object (deleted)",
        b"/fixture/space name",
        b"/fixture/object\0",
        b"/fixture/\xff",
    ] {
        assert!(!canonical_path(path), "unexpected canonical path {path:?}");
    }
    let mut longest = vec![b'a'; 4095];
    longest[0] = b'/';
    assert!(canonical_path(&longest));
    longest.push(b'a');
    assert!(!canonical_path(&longest));
    for target in [
        b"/fixture/subvolume-b/object".as_slice(),
        b"/fixture/subvolume-a/object (deleted)",
        b"/fixture/subvolume-a/alias",
        b"/fixture/subvolume-a/./object",
        b"object",
        b"",
    ] {
        assert_eq!(
            calibrated_identity(
                fixture_stamp(),
                FIXTURE_PATH,
                0x10000,
                &[fixture_map(0x10000)],
                target
            ),
            Err(E::Ownership)
        );
    }
}

#[test]
fn proc_inode_collision_needs_both_actual_dentry_and_maps_name() {
    let identity = fixture_identity();
    let good = fixture_map(0x20000);
    let other = b"/fixture/subvolume-b/object";
    let mut other_row = fixture_map(0x30000);
    other_row.name = other.to_vec();
    assert!(good.end <= other_row.start);
    assert_eq!(
        same_file_with(&other_row, &identity, |_| Ok(other.to_vec())),
        Ok(false)
    );
    assert_eq!(
        same_file_with(&other_row, &identity, |_| Ok(FIXTURE_PATH.to_vec())),
        Err(E::Ownership)
    );
    assert_eq!(
        same_file_with(&good, &identity, |_| Ok(other.to_vec())),
        Err(E::Ownership)
    );
    assert_eq!(
        same_file_with(&good, &identity, |_| Ok(
            b"/fixture/object (deleted)".to_vec()
        )),
        Err(E::Ownership)
    );
}

#[test]
fn different_proc_identity_never_falls_back_to_stat_device_or_reads_a_link() {
    let identity = fixture_identity();
    for fault in 0..4 {
        let mut row = fixture_map(0x20000);
        match fault {
            0 => row.major += 1,
            1 => row.minor += 1,
            2 => row.inode += 1,
            _ => row.minor = u64::from(libc::minor(identity.stamp.dev)),
        }
        assert_eq!(
            same_file_with(&row, &identity, |_| panic!("unmatched owner read a link")),
            Ok(false)
        );
    }
}

#[test]
fn equal_stat_and_proc_device_does_not_bypass_path_or_inode_checks() {
    let mut pin = fixture_stamp();
    pin.dev = libc::makedev(0, 42);
    let row = fixture_map(0x10000);
    let identity = calibrated_identity(
        pin,
        FIXTURE_PATH,
        row.start,
        std::slice::from_ref(&row),
        FIXTURE_PATH,
    )
    .unwrap();
    assert_eq!(
        same_file_with(&row, &identity, |_| Ok(FIXTURE_PATH.to_vec())),
        Ok(true)
    );
    assert_eq!(
        same_file_with(&row, &identity, |_| Ok(b"/fixture/alias".to_vec())),
        Err(E::Ownership)
    );
    let mut wrong = row;
    wrong.inode += 1;
    assert_eq!(
        same_file_with(&wrong, &identity, |_| panic!("wrong inode read a link")),
        Ok(false)
    );
}

#[test]
fn link_errors_empty_and_truncated_reads_remain_exact_failures() {
    for error in [E::Io, E::Ownership, E::Platform] {
        assert_eq!(link_target_with(|_| Err(error)), Err(error));
    }
    for size in [0, 4096, 4097, usize::MAX] {
        assert_eq!(link_target_with(|_| Ok(size)), Err(E::Ownership));
    }
    let read = |raw: &[u8]| {
        link_target_with(|buffer| {
            buffer[..raw.len()].copy_from_slice(raw);
            Ok(raw.len())
        })
    };
    assert_eq!(read(FIXTURE_PATH), Ok(FIXTURE_PATH.to_vec()));
    for raw in [
        b"relative".as_slice(),
        b"/bad\0name",
        b"/object (deleted)",
        b"/bad/../name",
    ] {
        assert_eq!(read(raw), Err(E::Ownership));
    }
}

#[test]
fn matching_proc_identity_propagates_denied_or_unavailable_actual_link() {
    let row = fixture_map(0x20000);
    let identity = fixture_identity();
    for error in [E::Io, E::Ownership] {
        let mut calls = 0;
        assert_eq!(
            same_file_with(&row, &identity, |_| {
                calls += 1;
                Err(error)
            }),
            Err(error)
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn checked_release_consumes_only_its_exact_range_including_address_zero() {
    for address in [0, 0x70000000] {
        let mut token = Some(address);
        let mut calls = Vec::new();
        assert_eq!(
            release_probe_with(&mut token, |base, length| {
                calls.push((base, length));
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(calls, [(address, 3 * c::PAGE as usize)]);
        assert_eq!(token, None);
        assert_eq!(
            release_probe_with(&mut token, |_, _| panic!("released twice")),
            Ok(())
        );
    }
}

#[test]
fn failed_release_returns_error_and_preserves_the_owned_token() {
    let mut token = Some(0x70000000);
    assert_eq!(
        release_probe_with(&mut token, |base, length| {
            assert_eq!((base, length), (0x70000000, 3 * c::PAGE as usize));
            Err(E::Io)
        }),
        Err(E::Io)
    );
    assert_eq!(token, Some(0x70000000));
    assert_eq!(
        release_probe_with(&mut token, |base, length| {
            assert_eq!((base, length), (0x70000000, 3 * c::PAGE as usize));
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(token, None);
}

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct FixtureDirectory(PathBuf);
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct LiveFixture {
    directory: FixtureDirectory,
    path: Vec<u8>,
    file: File,
    content: Vec<u8>,
}
impl LiveFixture {
    fn new() -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let directory = parent.join(format!(
            "li2-host-identity-{}-{}",
            std::process::id(),
            FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("exclusive fixture directory");
        let directory = FixtureDirectory(directory);
        let path = directory.0.join("object");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .expect("exclusive fixture inode");
        let content = vec![0x5a; c::PAGE as usize];
        file.write_all_at(&content, 0).unwrap();
        file.sync_all().unwrap();
        let path = path.as_os_str().as_bytes().to_vec();
        assert!(canonical_path(&path));
        Self {
            directory,
            path,
            file,
            content,
        }
    }
    fn pin(&self) -> Pinned {
        Pinned::from_file(open_file(&self.path).unwrap(), Some(&self.path)).unwrap()
    }
}

struct LivePage {
    address: Option<usize>,
}
impl LivePage {
    fn new(file: &File) -> Self {
        // SAFETY: the kernel chooses an unused address. This unique fixture
        // inode has no other live mapping, so its VMA cannot merge with a peer.
        let address = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                c::PAGE as usize,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        Self {
            address: Some(address as usize),
        }
    }
    fn close(&mut self) {
        if let Some(address) = self.address {
            // SAFETY: this exact page is still owned by this test fixture.
            assert_eq!(
                unsafe { libc::munmap(address as *mut libc::c_void, c::PAGE as usize) },
                0
            );
            self.address = None;
        }
    }
}
impl Drop for LivePage {
    fn drop(&mut self) {
        self.close();
    }
}

fn current_maps() -> Vec<Map> {
    // Called only in the selected fresh-exec child, never the shared harness.
    maps(&observation("/proc/self/maps", OBSERVATION_BYTES).unwrap()).unwrap()
}

#[test]
fn actual_owned_fd_calibrates_rechecks_and_releases_its_mapping_identity() {
    fn body() {
        let fixture = LiveFixture::new();
        // None exercises authority derived from the retained descriptor's actual
        // dentry; no caller-provided executable name is substituted.
        let owner = Pinned::from_file(open_file(&fixture.path).unwrap(), None).unwrap();
        assert_eq!(owner.identity.stamp, stamp(&fixture.file).unwrap());
        assert_eq!(owner.identity.path, fixture.path);
        assert_eq!(owner.content, ContentId::of(&fixture.content));
        assert_eq!(owner.check(), Ok(()));
        assert_eq!(owner.read(), Ok(fixture.content.clone()));
        assert!(
            file_maps(&current_maps(), &owner).unwrap().is_empty(),
            "calibration left its fixture mapping"
        );

        let mut page = LivePage::new(&owner.file);
        let address = page.address.unwrap() as u64;
        let snapshot = current_maps();
        let rows = file_maps(&snapshot, &owner).unwrap();
        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!(
            (row.start, row.end, row.offset, row.flags),
            (address, address + c::PAGE, 0, 4)
        );
        assert_eq!(mapping_target(row), Ok(fixture.path.clone()));
        assert_eq!(same_file(row, &owner), Ok(true));
        let mut unavailable = (*row).clone();
        unavailable.end += 1; // No real VMA has this non-page-aligned endpoint.
        assert_eq!(
            file_maps(&[unavailable, (*row).clone()], &owner),
            Err(E::Io)
        );
        assert_eq!(
            calibrate_file(&owner.file, owner.identity.stamp, &owner.identity.path),
            Ok(owner.identity.clone())
        );
        assert_eq!(
            file_maps(&current_maps(), &owner).unwrap().len(),
            1,
            "calibration displaced or leaked an owner"
        );
        page.close();
        assert_eq!(page.address, None);
        page.close();
        // Check the unique fixture's ownership, not whether an address remains
        // empty after munmap. A different allocation may reuse that address.
        assert!(file_maps(&current_maps(), &owner).unwrap().is_empty());
        assert_eq!(owner.read(), Ok(fixture.content));
    }
    isolated::run(
        "offline_router::host::identity_tests::actual_owned_fd_calibrates_rechecks_and_releases_its_mapping_identity",
        "LITEINST_HOST_IDENTITY_CALIBRATION_CHILD_V1",
        body,
    );
}

#[test]
fn actual_pin_rejects_every_stamp_path_and_full_content_drift() {
    fn body() {
        let fixture = LiveFixture::new();
        let mut owner = fixture.pin();
        let saved = owner.identity.stamp;
        for field in 0..10 {
            owner.identity.stamp = change_stamp(saved, field);
            assert_eq!(owner.check(), Err(E::Ownership), "Stamp member {field}");
            owner.identity.stamp = saved;
            assert_eq!(owner.check(), Ok(()));
        }
        owner.identity.path.push(b'x');
        assert_eq!(owner.check(), Err(E::Ownership));
        owner.identity.path = fixture.path.clone();
        assert_eq!(owner.read(), Ok(fixture.content.clone()));
        // Alter only the private digest witness. The file and its complete
        // metadata pin stay unchanged, so this reaches the content comparison.
        let mut other_content = fixture.content.clone();
        other_content[0] ^= 1;
        owner.content = ContentId::of(&other_content);
        assert_eq!(stamp(&owner.file), Ok(saved));
        assert_eq!(bytes(&owner.file, c::MAX_FILE), Ok(fixture.content.clone()));
        assert_eq!(owner.check(), Ok(()));
        assert_eq!(owner.read(), Err(E::Ownership));
        owner.content = ContentId::of(&fixture.content);
        assert_eq!(owner.read(), Ok(fixture.content.clone()));
        fixture.file.write_all_at(&[0xa5], 0).unwrap();
        fixture.file.sync_all().unwrap();
        // Intentionally refresh only the test's private stat witness to isolate
        // the whole-content gate from the earlier metadata rejection.
        owner.identity.stamp = stamp(&owner.file).unwrap();
        assert_eq!(owner.check(), Ok(()));
        assert_eq!(owner.read(), Err(E::Ownership));
    }
    isolated::run(
        "offline_router::host::identity_tests::actual_pin_rejects_every_stamp_path_and_full_content_drift",
        "LITEINST_HOST_IDENTITY_CUSTODY_CHILD_V1",
        body,
    );
}

#[test]
fn actual_same_content_path_replacement_and_deleted_fd_refuse() {
    fn body() {
        let fixture = LiveFixture::new();
        let owner = fixture.pin();
        let original = Path::new(std::ffi::OsStr::from_bytes(&fixture.path));
        let renamed = fixture.directory.0.join("retained-object");
        std::fs::rename(original, &renamed).unwrap();
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(original)
            .unwrap();
        replacement.write_all_at(&fixture.content, 0).unwrap();
        replacement.sync_all().unwrap();
        assert_ne!(
            (
                stamp(&replacement).unwrap().dev,
                stamp(&replacement).unwrap().ino
            ),
            (owner.identity.stamp.dev, owner.identity.stamp.ino)
        );
        assert_eq!(bytes(&owner.file, c::MAX_FILE), Ok(fixture.content.clone()));
        assert_eq!(
            bytes(&replacement, c::MAX_FILE),
            Ok(fixture.content.clone())
        );
        assert_eq!(
            fd_target(&owner.file),
            Ok(renamed.as_os_str().as_bytes().to_vec())
        );
        assert_eq!(owner.check(), Err(E::Ownership));
        assert_eq!(owner.read(), Err(E::Ownership));
        std::fs::remove_file(&renamed).unwrap();
        assert_eq!(fd_target(&owner.file), Err(E::Ownership));
        assert_eq!(
            Pinned::from_file(owner.file.try_clone().unwrap(), None).err(),
            Some(E::Ownership)
        );
        assert_eq!(owner.check(), Err(E::Ownership));
    }
    isolated::run(
        "offline_router::host::identity_tests::actual_same_content_path_replacement_and_deleted_fd_refuse",
        "LITEINST_HOST_IDENTITY_REPLACEMENT_CHILD_V1",
        body,
    );
}
