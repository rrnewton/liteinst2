//! Dedicated two-load R/RX ELF. Existing single-RX fixture constructors and
//! assertions remain unchanged; this constructor grants no production fact.
use super::*;

impl Fixture {
    pub(in crate::linux::remote::dynamic::owner) fn coalescing_pair(code: &[u8]) -> Self {
        assert!(!code.is_empty() && code.len() <= 4096);
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-coalescing-pair-{}-{}",
                std::process::id(),
                FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("fixture");
        let mut bytes = vec![0_u8; 8192];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 2)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        for (offset, value) in [(24, 0x401000_u64), (32, 64)] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        // The original main's header page is R, never RX. Both PT_LOADs map
        // adjacent file pages of the same held executable, without overlap.
        for (header, flags, offset, address, length) in [
            (64, 4_u32, 0_u64, 0x400000_u64, 288_u64),
            (120, 5_u32, 4096_u64, 0x401000_u64, 4096_u64),
        ] {
            bytes[header..header + 4].copy_from_slice(&1_u32.to_le_bytes());
            bytes[header + 4..header + 8].copy_from_slice(&flags.to_le_bytes());
            for (field, value) in [
                (8, offset),
                (16, address),
                (32, length),
                (40, length),
                (48, 4096),
            ] {
                bytes[header + field..header + field + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes[4096..4096 + code.len()].copy_from_slice(code);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        Self { directory, path }
    }
}
