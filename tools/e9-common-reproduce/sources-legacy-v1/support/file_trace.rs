// Additive file-image authentication and capture; no state normalization.
use super::*;
use std::path::Path;

pub struct FileHookWitness {
    pub pc: u64,
    pub logical_pc: u64,
    pub return_pc: u64,
    pub expected_calls: usize,
}

pub struct FileTraceEvidence<'a> {
    pub pages: &'a [(u64, Vec<u8>)],
    pub directory: &'a Path,
    pub hook: Option<FileHookWitness>,
}

impl FileTraceEvidence<'_> {
    pub(super) fn check_bytes(&self, child: &Tracee) {
        use std::io::Write;
        assert!(!self.pages.is_empty() && self.pages.len() <= 256);
        let directory = self.directory.join("file-pages");
        std::fs::create_dir_all(&directory).unwrap();
        for (address, bytes) in self.pages {
            assert_eq!(*address % PAGE as u64, 0);
            assert_eq!(bytes.len(), PAGE);
            let actual = child.memory(*address, PAGE);
            assert_eq!(
                actual, *bytes,
                "file-derived PT_LOAD page changed at {address:#x}"
            );
            let path = directory.join(format!("{address:016x}.bin"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => file.write_all(&actual).unwrap(),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    assert_eq!(std::fs::read(path).unwrap(), actual);
                }
                Err(error) => panic!("file-page capture failed: {error}"),
            }
        }
    }

    pub(super) fn capture(&self, index: usize, snapshot: &Snapshot) {
        use std::io::Write;
        let directory = self.directory.join(format!("point-{index:02}"));
        std::fs::create_dir(&directory).unwrap();
        let mut registers = String::new();
        use std::fmt::Write as _;
        macro_rules! field {
            ($name:ident) => {
                writeln!(
                    &mut registers,
                    "{}\t{}",
                    stringify!($name),
                    snapshot.registers.$name
                )
                .unwrap();
            };
        }
        writeln!(&mut registers, "logical_pc\t{}", snapshot.logical_pc).unwrap();
        field!(r15);
        field!(r14);
        field!(r13);
        field!(r12);
        field!(rbp);
        field!(rbx);
        field!(r11);
        field!(r10);
        field!(r9);
        field!(r8);
        field!(rax);
        field!(rcx);
        field!(rdx);
        field!(rsi);
        field!(rdi);
        field!(orig_rax);
        field!(rip);
        field!(cs);
        field!(eflags);
        field!(rsp);
        field!(ss);
        field!(fs_base);
        field!(gs_base);
        field!(ds);
        field!(es);
        field!(fs);
        field!(gs);
        for (name, bytes) in [
            ("registers.tsv", registers.as_bytes()),
            ("xstate.bin", snapshot.xstate.as_slice()),
            ("application-data.bin", snapshot.data.as_slice()),
            (
                "application-stack-redzone.bin",
                snapshot.application_stack.as_slice(),
            ),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
        }
    }

    pub(super) fn witness_hook(
        &self,
        native: &NativeOracle,
        child: &Tracee,
        calls: &mut usize,
    ) -> bool {
        let Some(hook) = &self.hook else {
            return false;
        };
        let registers = child.registers();
        if registers.rip != hook.pc {
            return false;
        }
        self.check_bytes(child);
        assert_eq!(
            child.memory(hook.pc, 1),
            [0xc3],
            "authorized fixture hook is not exact RET"
        );
        let reserve_start = native.stack.address() + PAGE as u64;
        let reserve_end = native.initial_rsp - 128;
        assert!(
            reserve_start <= registers.rsp && registers.rsp.checked_add(8).unwrap() <= reserve_end
        );
        assert!(
            reserve_start <= registers.rdi && registers.rdi.checked_add(16).unwrap() <= reserve_end
        );
        let context = child.memory(registers.rdi, 16);
        assert_eq!(
            u64::from_ne_bytes(context[..8].try_into().unwrap()),
            hook.logical_pc
        );
        assert_eq!(
            u64::from_ne_bytes(context[8..].try_into().unwrap()),
            native.initial_rsp
        );
        let return_bytes = child.memory(registers.rsp, 8);
        assert_eq!(
            u64::from_ne_bytes(return_bytes.try_into().unwrap()),
            hook.return_pc
        );
        *calls += 1;
        assert!(
            *calls <= hook.expected_calls,
            "unexpected duplicate RET-hook visit"
        );
        std::fs::write(
            self.directory.join(format!("hook-{calls:02}.txt")),
            format!(
                "pc={}\ncontext={}\nlogical_pc={}\nsaved_rsp={}\nreturn_pc={}\n",
                hook.pc, registers.rdi, hook.logical_pc, native.initial_rsp, hook.return_pc
            ),
        )
        .unwrap();
        true
    }

    pub(super) fn finish(&self, calls: usize, points: usize) {
        let required = self.hook.as_ref().map_or(0, |hook| hook.expected_calls);
        assert_eq!(calls, required, "missing/extra exact RET-hook witness");
        std::fs::write(self.directory.join("complete.tsv"), format!("points\t{points}\nhook_calls\t{calls}\nmanual_fixture_load\ttrue\nqualification_complete\tfalse\n")).unwrap();
    }
}
