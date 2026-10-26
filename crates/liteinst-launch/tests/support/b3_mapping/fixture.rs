use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Map,
    SealA,
    CpuA,
    Write,
    SealB,
    CpuB,
    Unmap,
}
#[derive(Clone, Debug)]
pub struct Site {
    pub kind: Kind,
    pub pc: u64,
}

pub struct Fixture {
    pub directory: PathBuf,
    pub path: PathBuf,
    pub source: Vec<u8>,
    pub data: Vec<u8>,
    pub heads: BTreeSet<u64>,
    pub sites: Vec<Site>,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub a_heads: BTreeSet<u64>,
    pub b_heads: BTreeSet<u64>,
}

struct Code {
    bytes: Vec<u8>,
    heads: BTreeSet<u64>,
    cursor: usize,
}
impl Code {
    fn emit(&mut self, bytes: &[u8]) -> u64 {
        let pc = BASE + self.cursor as u64;
        assert!(self.heads.insert(pc));
        assert!(self.cursor + bytes.len() <= self.bytes.len());
        self.bytes[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        pc
    }
    fn mov(&mut self, reg: u8, value: u64) {
        let mut bytes = vec![0x48 | (reg >> 3), 0xb8 | (reg & 7)];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.emit(&bytes);
    }
    fn args(&mut self, number: u64, protection: u64) -> u64 {
        self.mov(0, number);
        self.mov(7, TARGET);
        self.mov(6, PAGE as u64);
        self.mov(2, protection);
        self.emit(&[0x0f, 0x05])
    }
    fn copy(&mut self, template: u64) {
        self.mov(6, template);
        self.mov(7, TARGET);
        self.mov(1, PAGE as u64);
        self.emit(&[0xf3, 0xa4]); // Original REP MOVSB; data templates are never executable.
    }
    fn jump_generated(&mut self, offset: u64) -> u64 {
        self.mov(0, 0);
        self.mov(1, 0);
        self.mov(15, TARGET + offset);
        self.emit(&[0x41, 0xff, 0xe7]);
        BASE + self.cursor as u64
    }
}
fn u16_at(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn u32_at(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn u64_at(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn generated(offset: usize, continuation: u64) -> (Vec<u8>, BTreeSet<u64>) {
    let mut bytes = vec![0; PAGE];
    bytes[offset..offset + 4].copy_from_slice(&[0x0f, 0xa2, 0x49, 0xbf]);
    bytes[offset + 4..offset + 12].copy_from_slice(&continuation.to_le_bytes());
    bytes[offset + 12..offset + 15].copy_from_slice(&[0x41, 0xff, 0xe7]);
    (
        bytes,
        [
            TARGET + offset as u64,
            TARGET + offset as u64 + 2,
            TARGET + offset as u64 + 12,
        ]
        .into_iter()
        .collect(),
    )
}

impl Fixture {
    pub fn new() -> Arc<Self> {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "b3-mapping-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let mut code = Code {
            bytes: vec![0; SOURCE_BYTES],
            heads: BTreeSet::new(),
            cursor: PAGE,
        };
        code.bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2), (18, 62), (52, 64), (54, 56), (56, 3)] {
            u16_at(&mut code.bytes, at, value);
        }
        for (at, value) in [
            (20, 1),
            (64, 1),
            (68, 5),
            (120, 1),
            (124, 6),
            (176, 0x6474e551),
            (180, 6),
        ] {
            u32_at(&mut code.bytes, at, value);
        }
        for (at, value) in [
            (24, BASE + PAGE as u64),
            (32, 64),
            (80, BASE),
            (96, SOURCE_BYTES as u64),
            (104, SOURCE_BYTES as u64),
            (112, PAGE as u64),
            (128, SOURCE_BYTES as u64),
            (136, DATA),
            (152, DATA_BYTES as u64),
            (160, DATA_BYTES as u64),
            (168, PAGE as u64),
            (224, 16),
        ] {
            u64_at(&mut code.bytes, at, value);
        }
        code.mov(4, SP);
        code.mov(15, FLAGS);
        code.emit(&[0x41, 0x57]);
        code.emit(&[0x9d]);
        code.emit(&[0xdb, 0xe3]);
        code.emit(&[0xd9, 0xe8]); // FNINIT; FLD1.
        code.emit(&[0x66, 0x0f, 0x76, 0xc0]); // PCMPEQD XMM0,XMM0.
        code.mov(15, DATA + 2 * PAGE as u64);
        code.emit(&[0x41, 0x0f, 0xae, 0x17]);
        for register in 0_u8..16 {
            code.mov(
                register,
                if register == 4 {
                    SP
                } else {
                    0x1234_5678_0000_0000 | u64::from(register)
                },
            );
        }
        code.mov(
            10,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
        );
        code.mov(8, u64::MAX);
        code.mov(9, 0);
        let mut sites = vec![Site {
            kind: Kind::Map,
            pc: code.args(libc::SYS_mmap as u64, 3),
        }];
        code.copy(DATA);
        sites.push(Site {
            kind: Kind::SealA,
            pc: code.args(libc::SYS_mprotect as u64, 5),
        });
        let return_a = code.jump_generated(0);
        sites.push(Site {
            kind: Kind::CpuA,
            pc: TARGET,
        });
        sites.push(Site {
            kind: Kind::Write,
            pc: code.args(libc::SYS_mprotect as u64, 3),
        });
        code.copy(DATA + PAGE as u64);
        sites.push(Site {
            kind: Kind::SealB,
            pc: code.args(libc::SYS_mprotect as u64, 5),
        });
        let return_b = code.jump_generated(16);
        sites.push(Site {
            kind: Kind::CpuB,
            pc: TARGET + 16,
        });
        sites.push(Site {
            kind: Kind::Unmap,
            pc: code.args(libc::SYS_munmap as u64, 0),
        });
        code.emit(&[0xeb, 0xfe]);
        let (a, a_heads) = generated(0, return_a);
        let (b, b_heads) = generated(16, return_b);
        let mut data = (0..DATA_BYTES)
            .map(|i| ((17 * i + 43) & 255) as u8)
            .collect::<Vec<_>>();
        data[..PAGE].copy_from_slice(&a);
        data[PAGE..2 * PAGE].copy_from_slice(&b);
        data[2 * PAGE..2 * PAGE + 4].copy_from_slice(&0x1f80_u32.to_le_bytes());
        let path = directory.join("mapping.elf");
        let file_fork = FILE_FORK.lock().unwrap();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&code.bytes).unwrap();
        file.write_all(&data).unwrap();
        drop(file);
        drop(file_fork);
        Arc::new(Self {
            directory,
            path,
            source: code.bytes,
            data,
            heads: code.heads,
            sites,
            a,
            b,
            a_heads,
            b_heads,
        })
    }
    pub fn facts(&self) -> Vec<ImageFacts> {
        vec![ImageFacts {
            start: BASE,
            bytes: self.source.clone(),
            heads: self.heads.clone(),
        }]
    }
    pub fn profile(&self) -> DynamicMappingProfile {
        DynamicMappingProfile {
            allowed_ranges: vec![TARGET..TARGET + PAGE as u64],
            max_operations: 5,
            max_live_mappings: 1,
            max_source_requests: 2,
            max_capture_bytes: PAGE,
        }
    }
    pub fn expected_data(&self) -> Vec<u8> {
        let mut data = self.data.clone();
        let offset = (SP - 8 - DATA) as usize;
        data[offset..offset + 8].copy_from_slice(&FLAGS.to_le_bytes());
        data
    }
    pub fn armed_source(&self, controller: bool) -> Vec<u8> {
        let mut bytes = self.source.clone();
        if controller {
            for site in &self.sites {
                if site.pc < TARGET {
                    assert_eq!(bytes[(site.pc - BASE) as usize], 0x0f);
                    bytes[(site.pc - BASE) as usize] = 0xcc;
                }
            }
        }
        bytes
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}
