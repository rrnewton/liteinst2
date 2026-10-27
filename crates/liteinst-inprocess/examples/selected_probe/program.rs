use super::machine::PAGE;
use liteinst_inprocess::selected::{
    InstalledSelected, PreparedSelected, SelectedKind, SelectedSite,
};
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use std::ptr::NonNull;

pub const REGISTERS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
pub const PREFIX_CASES: [&str; 8] = [
    "prefix_rdrand16_rax",
    "prefix_rdrand64_r8",
    "prefix_rdseed16_r9",
    "prefix_rdseed64_r15",
    "prefix_rdpid_rax",
    "prefix_rdpid_r8",
    "prefix_rdtscp_operand",
    "prefix_rdtscp_rexw",
];
pub struct Case {
    pub name: String,
    pub kind: SelectedKind,
    pub destination: u8,
    pub width: u8,
    pub bytes: Vec<u8>,
    pub masked: bool,
    pub crossing: bool,
}
impl Case {
    pub fn parse(name: &str) -> Self {
        let mut masked = false;
        let (kind, width, destination, bytes) = match name {
            "rdtscp" => (SelectedKind::Rdtscp, 0, 0, vec![0x0f, 0x01, 0xf9]),
            "masked_rdrand" => {
                masked = true;
                (
                    SelectedKind::Rdrand,
                    64,
                    0,
                    encode(SelectedKind::Rdrand, 64, 0),
                )
            }
            "masked_rdseed" => {
                masked = true;
                (
                    SelectedKind::Rdseed,
                    64,
                    0,
                    encode(SelectedKind::Rdseed, 64, 0),
                )
            }
            "masked_rdpid" => {
                masked = true;
                (
                    SelectedKind::Rdpid,
                    64,
                    0,
                    encode(SelectedKind::Rdpid, 32, 0),
                )
            }
            "masked_rdtscp" => {
                masked = true;
                (SelectedKind::Rdtscp, 0, 0, vec![0x0f, 0x01, 0xf9])
            }
            "prefix_rdrand16_rax" => (
                SelectedKind::Rdrand,
                16,
                0,
                vec![0x48, 0x66, 0x0f, 0xc7, 0xf0],
            ),
            "prefix_rdrand64_r8" => (
                SelectedKind::Rdrand,
                64,
                8,
                vec![0x66, 0x49, 0x0f, 0xc7, 0xf0],
            ),
            "prefix_rdseed16_r9" => (
                SelectedKind::Rdseed,
                16,
                9,
                vec![0x48, 0x66, 0x41, 0x0f, 0xc7, 0xf9],
            ),
            "prefix_rdseed64_r15" => (
                SelectedKind::Rdseed,
                64,
                15,
                vec![0x66, 0x49, 0x0f, 0xc7, 0xff],
            ),
            "prefix_rdpid_rax" => (
                SelectedKind::Rdpid,
                64,
                0,
                vec![0xf3, 0x48, 0x0f, 0xc7, 0xf8],
            ),
            "prefix_rdpid_r8" => (
                SelectedKind::Rdpid,
                64,
                8,
                vec![0xf3, 0x49, 0x0f, 0xc7, 0xf8],
            ),
            "prefix_rdtscp_operand" => (SelectedKind::Rdtscp, 0, 0, vec![0x66, 0x0f, 0x01, 0xf9]),
            "prefix_rdtscp_rexw" => (SelectedKind::Rdtscp, 0, 0, vec![0x48, 0x0f, 0x01, 0xf9]),
            _ => {
                let (class, register) = name.split_once('_').expect("closed CASE spelling");
                let destination = REGISTERS
                    .iter()
                    .position(|r| *r == register)
                    .expect("architectural register") as u8;
                assert_ne!(
                    destination, 4,
                    "RSP is a counted refusal, not a native case"
                );
                let (kind, width) = match class {
                    "rdrand16" => (SelectedKind::Rdrand, 16),
                    "rdrand32" => (SelectedKind::Rdrand, 32),
                    "rdrand64" => (SelectedKind::Rdrand, 64),
                    "rdseed16" => (SelectedKind::Rdseed, 16),
                    "rdseed32" => (SelectedKind::Rdseed, 32),
                    "rdseed64" => (SelectedKind::Rdseed, 64),
                    "rdpid" => (SelectedKind::Rdpid, 64),
                    _ => panic!("unknown selected CASE"),
                };
                let bytes = encode(
                    kind,
                    if kind == SelectedKind::Rdpid {
                        32
                    } else {
                        width
                    },
                    destination,
                );
                (kind, width, destination, bytes)
            }
        };
        Self {
            name: name.into(),
            kind,
            width,
            destination,
            bytes,
            masked,
            crossing: PREFIX_CASES.contains(&name),
        }
    }
    pub fn class(&self) -> &'static str {
        match self.kind {
            SelectedKind::Rdrand => "rdrand",
            SelectedKind::Rdseed => "rdseed",
            SelectedKind::Rdpid => "rdpid",
            SelectedKind::Rdtscp => "rdtscp",
            _ => unreachable!(),
        }
    }
    pub fn destination_json(&self) -> String {
        if self.kind == SelectedKind::Rdtscp {
            "null".into()
        } else {
            format!("\"{}\"", REGISTERS[usize::from(self.destination)])
        }
    }
    pub fn register_index(&self) -> usize {
        [0, 2, 3, 1, 7, 6, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15][usize::from(self.destination)]
    }
}
pub fn encode(kind: SelectedKind, width: u8, destination: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    if kind == SelectedKind::Rdpid {
        bytes.push(0xf3);
    }
    if width == 16 {
        bytes.push(0x66);
    }
    let rex = 0x40 | (if width == 64 { 8 } else { 0 }) | (if destination >= 8 { 1 } else { 0 });
    if rex != 0x40 {
        bytes.push(rex);
    }
    bytes.extend([
        0x0f,
        0xc7,
        (if kind == SelectedKind::Rdrand {
            0xf0
        } else {
            0xf8
        }) | (destination & 7),
    ]);
    bytes
}
pub struct Region {
    pub address: NonNull<u8>,
    pub original: Vec<u8>,
    pub offset: usize,
    pub end: usize,
}
impl Region {
    pub fn new(instruction: &[u8], crossing: bool) -> Self {
        let offset = if crossing { PAGE - 2 } else { 64 };
        let end = offset + instruction.len().max(5);
        let mut original = vec![0xcc; if crossing { 2 * PAGE } else { PAGE }];
        original[offset..offset + instruction.len()].copy_from_slice(instruction);
        original[offset + instruction.len()..end].fill(0x90);
        original[end] = 0xc3;
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                original.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        let address = NonNull::new(memory.cast::<u8>()).unwrap();
        unsafe {
            std::ptr::copy_nonoverlapping(original.as_ptr(), address.as_ptr(), original.len());
        }
        permissions(
            address.as_ptr(),
            original.len(),
            libc::PROT_READ | libc::PROT_EXEC,
        )
        .unwrap();
        Self {
            address,
            original,
            offset,
            end,
        }
    }
    pub fn entry(&self) -> u64 {
        self.address.as_ptr() as u64 + self.offset as u64
    }
    pub fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.original.len()) }
    }
    pub fn identity(&self) -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([0x53; 32]),
            mapping: self.address.as_ptr() as u64,
            generation: 1,
        }
    }
    pub fn entries(&self) -> LegalEntrySet {
        LegalEntrySet {
            identity: self.identity(),
            scope: AddressRange::new(self.entry(), self.end - self.offset + 1).unwrap(),
            provenance: EntryProvenance::Declared(
                "literal selected/NOP/RET; sole external entry; no outstanding resume".into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: vec![LegalEntry {
                address: self.entry(),
                requires_endbr: false,
            }],
            resumes: ResumeObligation::NoneExist,
        }
    }
    pub fn prepare(&self, kind: SelectedKind) -> Result<PreparedSelected, Refusal> {
        let entries = self.entries();
        let allocation = AllocationPolicy::near(self.entry()).unwrap();
        PreparedSelected::prepare(SelectedSite {
            kind,
            identity: self.identity(),
            code: &self.original[self.offset..=self.end],
            base_address: self.entry(),
            function: entries.scope,
            block: entries.scope,
            logical_pc: self.entry(),
            entries: &entries,
            allocation: &allocation,
            search: search(),
        })
    }
    pub fn publish(&mut self, kind: SelectedKind) -> (Box<InstalledSelected>, u64, u64) {
        let start = std::time::Instant::now();
        let prepared = self.prepare(kind).unwrap();
        assert_eq!(prepared.plan().parts().kind, PlanKind::Relocation);
        assert_eq!(prepared.plan().parts().physical_pc, self.entry());
        assert_eq!(
            prepared.plan().parts().displaced.len(),
            (self.end - self.offset) as u64
        );
        let preparation = super::ns(start);
        let start = std::time::Instant::now();
        let address = self.address.as_ptr();
        let len = self.original.len();
        let offset = self.offset;
        let identity = self.identity();
        let installed = {
            let mut lease = unsafe {
                QuiescenceLease::new(
                    self,
                    identity,
                    vec![AddressRange::new(address as u64, len).unwrap()],
                )
            };
            permissions(address, len, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            let result = unsafe {
                prepared.publish_with(address.add(offset), &mut lease, || {
                    permissions(address, len, libc::PROT_READ | libc::PROT_EXEC)
                })
            };
            let installed = match result {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("publication refused: {:?}", error.failure);
                    std::process::abort();
                }
            };
            assert!(!lease.is_poisoned());
            installed
        };
        assert!(
            installed.verified()
                && installed.receipt().is_some()
                && installed.installed().is_some()
        );
        assert_eq!(
            installed.observed_source().unwrap(),
            &self.bytes()[self.offset..=self.end]
        );
        assert!(!installed.observed_generated().unwrap().is_empty());
        assert_eq!(self.bytes()[self.offset], 0xe9);
        assert_eq!(self.bytes()[self.end], 0xc3);
        assert_eq!(&self.bytes()[..self.offset], &self.original[..self.offset]);
        assert_eq!(&self.bytes()[self.end..], &self.original[self.end..]);
        (installed, preparation, super::ns(start))
    }
}
impl Drop for Region {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::munmap(self.address.as_ptr().cast(), self.original.len()) },
            0
        );
    }
}
pub fn search() -> SearchPolicy {
    SearchPolicy {
        tactics: TacticPolicy::RelocationOnly,
        max_upstream_bytes: 0,
        max_displaced_bytes: 15,
        max_sites: 1,
    }
}
pub fn permissions(address: *mut u8, len: usize, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(address.cast(), len, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend("selected fixture mprotect".into()))
    }
}

pub fn refusal_controls() {
    let mut rsp = 0;
    let mut invalid = 0;
    for kind in [SelectedKind::Rdrand, SelectedKind::Rdseed] {
        for width in [16, 32, 64] {
            let region = Region::new(&encode(kind, width, 4), false);
            assert!(matches!(
                region.prepare(kind),
                Err(Refusal::UnsupportedSemantics(_))
            ));
            assert_eq!(region.bytes(), region.original);
            rsp += 1;
        }
    }
    let region = Region::new(&encode(SelectedKind::Rdpid, 32, 4), false);
    assert!(matches!(
        region.prepare(SelectedKind::Rdpid),
        Err(Refusal::UnsupportedSemantics(_))
    ));
    assert_eq!(region.bytes(), region.original);
    rsp += 1;
    let mut overlong = vec![0x66; 13];
    overlong.extend([0x0f, 0xc7, 0xf0]);
    for (kind, bytes) in [
        (SelectedKind::Rdrand, vec![0xf0, 0x0f, 0xc7, 0xf0]),
        (SelectedKind::Rdseed, vec![0xf0, 0x0f, 0xc7, 0xf8]),
        (SelectedKind::Rdrand, vec![0x0f, 0xc7, 0x30]),
        (SelectedKind::Rdseed, vec![0x0f, 0xc7, 0x38]),
        (SelectedKind::Rdrand, vec![0xf3, 0x0f, 0xc7, 0xf8]),
        (SelectedKind::Rdrand, overlong),
    ] {
        let region = Region::new(&bytes, false);
        assert!(matches!(
            region.prepare(kind),
            Err(Refusal::UnsupportedSemantics(_))
        ));
        assert_eq!(region.bytes(), region.original);
        invalid += 1;
    }
    assert_eq!((rsp, invalid), (7, 6));
    println!(
        "{{\"schema_version\":1,\"profile\":\"preparation_refusals\",\"case\":\"refusal_controls\",\"status\":\"passed\",\"rsp_refusals\":{rsp},\"invalid_refusals\":{invalid},\"source_unchanged\":true,\"native_executions\":0}}"
    );
}
