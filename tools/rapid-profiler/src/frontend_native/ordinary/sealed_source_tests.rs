//! Real kernel/file and loader controls. No selected function is invoked.
use super::*;
use std::os::unix::fs::FileExt;

fn unsealed(bytes: &[u8]) -> File {
    // SAFETY: fixed name/options; this test takes sole ownership of the new fd.
    let fd = unsafe {
        libc::memfd_create(
            c"liteinst-source-control".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    // SAFETY: the descriptor was just created and has no other Rust owner.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).unwrap();
    file
}

fn contract() -> NormalModuleContract {
    NormalModuleContract {
        single_external_entry_per_function: true,
        sequential_call_ret_only: true,
        no_active_cet: true,
    }
}

#[test]
fn sealed_copy_kernel_refuses_write_resize_new_seals_and_shared_writer() {
    let expected = [1, 2, 3, 4];
    let mut file = copy_sealed_source(&expected).unwrap();
    let original = sealed_source_stamp(&mut file, &expected).unwrap();
    // SAFETY: read-only descriptor flags query.
    assert_ne!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    for result in [
        file.write_at(&[9], 0).map(|_| ()),
        file.set_len(3),
        file.set_len(5),
    ] {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
    }
    // SAFETY: valid fd; adding any new seal must fail after F_SEAL_SEAL.
    assert_eq!(
        unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_FUTURE_WRITE,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    // SAFETY: no requested address; a successful unexpected mapping is released
    // below before asserting refusal. No pointer is accessed.
    let pointer = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error();
    if pointer != libc::MAP_FAILED {
        // SAFETY: this call owns the complete unexpected mapping.
        assert_eq!(unsafe { libc::munmap(pointer, 4096) }, 0);
    }
    assert_eq!(pointer, libc::MAP_FAILED);
    assert_eq!(errno, Some(libc::EPERM));
    // A rejected pwrite can still update shmem mtime/ctime before the seal
    // check. Seals guarantee content/extent, not timestamp immutability. Keep
    // the complete byte/seal checks and compare every non-time identity field.
    let after = sealed_source_stamp(&mut file, &expected).unwrap();
    assert_eq!(
        (after.device, after.inode, after.size, after.mode),
        (original.device, original.inode, original.size, original.mode)
    );
}

#[test]
fn sealed_copy_requires_every_seal_and_exact_complete_bytes() {
    let expected = [1, 2, 3, 4];
    for missing in [
        libc::F_SEAL_WRITE,
        libc::F_SEAL_GROW,
        libc::F_SEAL_SHRINK,
        libc::F_SEAL_SEAL,
    ] {
        let mut file = unsealed(&expected);
        // SAFETY: the test owns this new unshared descriptor.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SOURCE_SEALS & !missing) },
            0
        );
        assert_eq!(
            sealed_source_stamp(&mut file, &expected).err(),
            Some(SetupRefusal::SourceBytes)
        );
    }
    let mut file = unsealed(&expected);
    assert_eq!(
        sealed_source_stamp(&mut file, &expected).err(),
        Some(SetupRefusal::SourceBytes)
    );
    for bytes in [&expected[..3], &[1, 2, 3, 9][..], &[1, 2, 3, 4, 5][..]] {
        let mut file = copy_sealed_source(bytes).unwrap();
        assert_eq!(
            sealed_source_stamp(&mut file, &expected).err(),
            Some(SetupRefusal::SourceBytes)
        );
    }
    assert_eq!(copy_sealed_source(&[]).err(), Some(SetupRefusal::Format));
    assert_eq!(
        copy_sealed_source(&vec![0; 1024 * 1024 + 1]).err(),
        Some(SetupRefusal::Format)
    );
}

#[test]
fn sealed_copy_retains_independent_bytes_and_distinct_inode() {
    let mut input = vec![3; 4096];
    let expected = input.clone();
    let mut first = copy_sealed_source(&input).unwrap();
    let mut second = copy_sealed_source(&input).unwrap();
    input.fill(7);
    let a = sealed_source_stamp(&mut first, &expected).unwrap();
    let b = sealed_source_stamp(&mut second, &expected).unwrap();
    assert_ne!((a.device, a.inode), (b.device, b.inode));
    assert_eq!(
        sealed_source_stamp(&mut first, &input).err(),
        Some(SetupRefusal::SourceBytes)
    );
    assert_eq!(bounded_read(&mut second).unwrap(), expected);
}

#[test]
fn sealed_leaf_set_loader_authenticates_actual_dso_without_calling_it() {
    let bytes = tests::fixture();
    let selected = TrustedFunctionSelection::new(&bytes, 0x1010, 28, "checksum").unwrap();
    // SAFETY: the existing exact relocation/dependency/constructor-free fixture
    // contains the complete scalar CFG. No entry is called/published, no address
    // or writer escapes this test, and the loader owners remain process-lived.
    let loaded =
        unsafe { LoadedNormalLeafSet::load_sealed_selected(&[&selected], contract()) }.unwrap();
    assert_eq!(loaded.functions().len(), 1);
    assert_eq!(loaded.functions()[0].code(), &bytes[0x1010..0x102c]);
    assert_eq!(loaded.functions()[0].elf_range(), (0x1010, 0x102c));
    assert_eq!(loaded.source_pages().len(), 1);
    assert_eq!(loaded.source_pages()[0].bytes, bytes[0x1000..0x2000]);
    loaded.verify_original().unwrap();
}

#[test]
fn sealed_pair_loader_preserves_complete_union_and_contract_refusals() {
    let mut bytes = tests::fixture();
    let code = [0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 1, 0xc3];
    bytes[0x1050..0x1058].copy_from_slice(&code);
    let text_size = 0x3200 + 64 + 32;
    bytes[text_size..text_size + 8].copy_from_slice(&0x48_u64.to_le_bytes());
    let a = TrustedFunctionSelection::new(&bytes, 0x1010, 28, "checksum").unwrap();
    let b = TrustedFunctionSelection::new(&bytes, 0x1050, 8, "length_plus_one").unwrap();
    // SAFETY: same nonexecuted complete fixture as above, with a second disjoint
    // scalar body; no runtime execution or publication is requested.
    let loaded =
        unsafe { LoadedNormalModule::load_sealed_selected_pair([&a, &b], contract()) }.unwrap();
    assert_eq!(loaded.functions()[0].code(), &bytes[0x1010..0x102c]);
    assert_eq!(loaded.functions()[1].code(), code);
    assert_eq!(loaded.source_pages().len(), 1);
    assert_eq!(loaded.source_pages()[0].bytes, bytes[0x1000..0x2000]);
    loaded.verify_original().unwrap();
    // SAFETY: invalid metadata/contracts must refuse before any loader call;
    // no function is invoked even if the refusal assertion fails.
    assert_eq!(
        unsafe { LoadedNormalModule::load_sealed_selected_pair([&b, &a], contract()) }.err(),
        Some(SetupRefusal::EntryExit)
    );
    // SAFETY: same preflight-only refusal control.
    assert_eq!(
        unsafe { LoadedNormalLeafSet::load_sealed_selected(&[], contract()) }.err(),
        Some(SetupRefusal::EntryExit)
    );
    // SAFETY: same preflight-only refusal control.
    assert_eq!(
        unsafe {
            LoadedNormalLeafSet::load_sealed_selected(
                &[&a],
                NormalModuleContract {
                    no_active_cet: false,
                    ..contract()
                },
            )
        }
        .err(),
        Some(SetupRefusal::Cet)
    );
}

#[test]
fn sealed_loader_mapping_identity_offsets_permissions_and_full_loads_remain_required() {
    let bytes = tests::fixture();
    let selected = TrustedFunctionSelection::new(&bytes, 0x1010, 28, "checksum").unwrap();
    let parsed = normal_module::preflight(&[&selected]).unwrap();
    // SAFETY: identical nonexecuted fixture/lifetime contract to the public
    // constructor tests. Private test access does not export an owner or fd.
    let parts = unsafe { normal_module::load_sealed_parts(&[&selected]) }.unwrap();
    let owner = parts.owner;
    assert!(matches!(owner.source, SourceBacking::SealedCopy));
    assert_eq!(retained_device(owner).unwrap(), owner.device);
    assert_eq!(bounded_read(&mut owner.file).unwrap(), bytes);
    let entry = parts.functions[0].entry();
    let source = parts.functions[0].source_range().0;
    verify_source_provenance(owner, &parsed[0], entry, source, 28).unwrap();
    let original = owner.original;
    owner.original.inode ^= 1;
    assert_eq!(
        verify_source_provenance(owner, &parsed[0], entry, source, 28),
        Err(SetupRefusal::SourceBytes)
    );
    owner.original = original;
    // The production owner still refuses *any* recorded timestamp mismatch;
    // the kernel mutation-refusal control above must not relax this guard.
    for field in [0, 1] {
        if field == 0 {
            owner.original.modified.1 ^= 1;
        } else {
            owner.original.changed.1 ^= 1;
        }
        assert_eq!(
            verify_source_provenance(owner, &parsed[0], entry, source, 28),
            Err(SetupRefusal::SourceBytes)
        );
        owner.original = original;
    }
    let device = owner.device;
    owner.device.1 ^= 1;
    assert_eq!(
        verify_source_provenance(owner, &parsed[0], entry, source, 28),
        Err(SetupRefusal::SourceBytes)
    );
    owner.device = device;
    for load in &parsed[0].loads {
        let address = entry - parsed[0].entry + load.address;
        let perms = if load.flags == 6 {
            "r--p"
        } else {
            load_permissions(load.flags).unwrap()
        };
        assert_eq!(
            map_rows(
                address,
                load.memory_size,
                device,
                original.inode,
                Some(perms),
                Some(load.offset)
            ),
            Ok(())
        );
        for (dev, inode, permissions, offset) in [
            ((device.0, device.1 ^ 1), original.inode, perms, load.offset),
            (device, original.inode ^ 1, perms, load.offset),
            (device, original.inode, "rw-p", load.offset),
            (device, original.inode, perms, load.offset + 1),
        ] {
            assert_eq!(
                map_rows(
                    address,
                    load.memory_size,
                    dev,
                    inode,
                    Some(permissions),
                    Some(offset)
                ),
                Err(SetupRefusal::SymbolOwner)
            );
        }
    }
    verify_source_provenance(owner, &parsed[0], entry, source, 28).unwrap();
}
