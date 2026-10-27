//! Additive literal ELF constructor; existing Fixture constructors stay exact.
use super::*;

impl Harness {
    /// Fixed positive-only argv table; use the enclosing original deadline.
    /// Existing Harness::launch and every negative fixture remain unchanged.
    pub(in crate::linux::remote::dynamic::owner) fn launch_stack_pair(
        &mut self,
        fixture: &Fixture,
        until: Instant,
    ) -> Result<Ready, LaunchError> {
        let inherited = self.mask.as_ref().unwrap().original();
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        let mut command = LaunchCommand::new(&fixture.path);
        command.args = vec![std::ffi::OsString::new(); 512];
        launch::start(self.owner(), &command, inherited, until)
    }
}
impl Fixture {
    pub(in crate::linux::remote::dynamic::owner) fn stack_code(
        entry: usize,
        pieces: &[(usize, &[u8])],
    ) -> Self {
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        assert!((256..8192).contains(&entry));
        let mut bytes = vec![0_u8; 8192];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 1_u32), (64, 1), (68, 5)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (24, 0x400000_u64 + entry as u64),
            (32, 64),
            (80, 0x400000),
            (96, 8192),
            (104, 8192),
            (112, 4096),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut assigned = [false; 8192];
        for &(offset, code) in pieces {
            let end = offset.checked_add(code.len()).unwrap();
            assert!(offset >= 256 && end <= 8192 && !code.is_empty());
            assert!(assigned[offset..end].iter().all(|used| !used));
            assigned[offset..end].fill(true);
            bytes[offset..end].copy_from_slice(code);
        }
        assert!(assigned[entry]);
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-stack-{}-{}",
                std::process::id(),
                FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("fixture");
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
