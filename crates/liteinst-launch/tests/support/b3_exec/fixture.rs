use super::*;

#[derive(Debug)]
pub struct Fixture {
    pub directory: PathBuf,
    pub old_path: PathBuf,
    pub new_path: PathBuf,
    pub old_source: Vec<u8>,
    pub new_source: Vec<u8>,
    pub old_data: Vec<u8>,
    pub new_data: Vec<u8>,
    pub inputs: Vec<u8>,
    pub old_heads: BTreeSet<u64>,
    pub new_heads: BTreeSet<u64>,
    pub old_cpu: u64,
    pub exec: u64,
    pub call_return: u64,
    pub first_cpu: u64,
    pub final_cpu: u64,
    pub argv: u64,
    pub envp: u64,
}
struct Code {
    base: u64,
    bytes: Vec<u8>,
    cursor: usize,
    heads: BTreeSet<u64>,
}
impl Code {
    fn emit(&mut self, bytes: &[u8]) -> u64 {
        let pc = self.base + self.cursor as u64;
        assert!(self.heads.insert(pc) && self.cursor + bytes.len() <= self.bytes.len());
        self.bytes[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        pc
    }
    fn mov(&mut self, reg: u8, value: u64) {
        let mut bytes = vec![0x48 | (reg >> 3), 0xb8 | (reg & 7)];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.emit(&bytes);
    }
    fn seed(&mut self, data: u64) {
        self.mov(4, sp(data));
        self.mov(15, FLAGS);
        self.emit(&[0x41, 0x57]);
        self.emit(&[0x9d]);
        self.emit(&[0xdb, 0xe3]);
        self.emit(&[0xd9, 0xe8]);
        self.emit(&[0x66, 0x0f, 0x76, 0xc0]);
        self.mov(15, data + 128);
        self.emit(&[0x41, 0x0f, 0xae, 0x17]);
        for r in 0..16 {
            self.mov(
                r,
                if r == 4 {
                    sp(data)
                } else {
                    0x1234_5678_0000_0000 | u64::from(r)
                },
            );
        }
        self.mov(0, 0);
        self.mov(1, 0);
    }
}
fn u16_at(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}
fn u32_at(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
fn u64_at(b: &mut [u8], i: usize, v: u64) {
    b[i..i + 8].copy_from_slice(&v.to_le_bytes());
}
fn image(base: u64, data: u64, inputs: bool) -> Code {
    let mut b = vec![0; CODE];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (i, v) in [
        (16, 2),
        (18, 62),
        (52, 64),
        (54, 56),
        (56, if inputs { 4 } else { 3 }),
    ] {
        u16_at(&mut b, i, v);
    }
    u32_at(&mut b, 20, 1);
    u64_at(&mut b, 24, base + PAGE as u64);
    u64_at(&mut b, 32, 64);
    for (n, kind, flags, offset, address, length) in [
        (0, 1, 5, 0, base, CODE as u64),
        (1, 1, 6, CODE as u64, data, DATA_LEN as u64),
        (
            2,
            if inputs { 1 } else { 0x6474e551 },
            if inputs { 4 } else { 6 },
            if inputs { (CODE + DATA_LEN) as u64 } else { 0 },
            if inputs { INPUT } else { 0 },
            if inputs { PAGE as u64 } else { 0 },
        ),
    ] {
        let at = 64 + n * 56;
        u32_at(&mut b, at, kind);
        u32_at(&mut b, at + 4, flags);
        u64_at(&mut b, at + 8, offset);
        u64_at(&mut b, at + 16, address);
        u64_at(&mut b, at + 32, length);
        u64_at(&mut b, at + 40, length);
        u64_at(&mut b, at + 48, if kind == 1 { PAGE as u64 } else { 16 });
    }
    if inputs {
        u32_at(&mut b, 232, 0x6474e551);
        u32_at(&mut b, 236, 6);
        u64_at(&mut b, 280, 16);
    }
    Code {
        base,
        bytes: b,
        cursor: PAGE,
        heads: BTreeSet::new(),
    }
}
fn data() -> Vec<u8> {
    let mut data = (0..DATA_LEN)
        .map(|i| ((17 * i + 43) & 255) as u8)
        .collect::<Vec<_>>();
    data[128..132].copy_from_slice(&0x1f80_u32.to_le_bytes());
    data
}
fn write(path: &Path, source: &[u8], data: &[u8], inputs: &[u8]) {
    let lock = FILE_FORK.write().unwrap();
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o500)
        .open(path)
        .unwrap();
    file.write_all(source).unwrap();
    file.write_all(data).unwrap();
    file.write_all(inputs).unwrap();
    drop(file);
    drop(lock);
}
impl Fixture {
    pub fn new() -> Arc<Self> {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "b3-exec-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let old_path = directory.join("old.elf");
        let new_path = directory.join("new.elf");
        let mut inputs = vec![0xa5; PAGE];
        let filename = new_path.as_os_str().as_encoded_bytes();
        assert!(filename.len() < 512 && !filename.contains(&0));
        inputs[..filename.len()].copy_from_slice(filename);
        inputs[filename.len()] = 0;
        let argv = INPUT + 0x200;
        let envp = INPUT + 0x220;
        for (at, text) in [
            (0x300, b"logical-new\0".as_slice()),
            (0x320, b"payload-argument\0"),
            (0x340, b"FIRST=one\0"),
            (0x360, b"SECOND=two\0"),
        ] {
            inputs[at..at + text.len()].copy_from_slice(text);
        }
        for (at, value) in [
            (0x200, INPUT + 0x300),
            (0x208, INPUT + 0x320),
            (0x210, 0),
            (0x220, INPUT + 0x340),
            (0x228, INPUT + 0x360),
            (0x230, 0),
        ] {
            u64_at(&mut inputs, at, value);
        }
        let mut old = image(OLD, OLD_DATA, true);
        old.seed(OLD_DATA);
        let helper = OLD + 0x1800;
        let call = old.base + old.cursor as u64;
        let displacement = i32::try_from(helper - (call + 5)).unwrap();
        let mut encoding = vec![0xe8];
        encoding.extend_from_slice(&displacement.to_le_bytes());
        old.emit(&encoding);
        let call_return = old.base + old.cursor as u64;
        old.mov(0, libc::SYS_execve as u64);
        old.mov(7, INPUT);
        old.mov(6, argv);
        old.mov(2, envp);
        let exec = old.emit(&[0x0f, 0x05]);
        old.emit(&[0x0f, 0x0b]);
        assert!(old.cursor < 0x1800);
        old.cursor = 0x1800;
        let old_cpu = old.emit(&[0x0f, 0xa2]);
        old.emit(&[0xc3]);
        let mut new = image(NEW, NEW_DATA, false);
        let first_cpu = new.emit(&[0x0f, 0xa2]);
        new.mov(15, NEW_DATA);
        for opcode in [
            &[0x49, 0x89, 0x07][..],
            &[0x49, 0x89, 0x5f, 8],
            &[0x49, 0x89, 0x4f, 16],
            &[0x49, 0x89, 0x57, 24],
        ] {
            new.emit(opcode);
        }
        new.seed(NEW_DATA);
        let final_cpu = new.emit(&[0x0f, 0xa2]);
        new.emit(&[0xeb, 0xfe]);
        let old_data = data();
        let new_data = data();
        write(&new_path, &new.bytes, &new_data, &[]);
        write(&old_path, &old.bytes, &old_data, &inputs);
        Arc::new(Self {
            directory,
            old_path,
            new_path,
            old_source: old.bytes,
            new_source: new.bytes,
            old_data,
            new_data,
            inputs,
            old_heads: old.heads,
            new_heads: new.heads,
            old_cpu,
            exec,
            call_return,
            first_cpu,
            final_cpu,
            argv,
            envp,
        })
    }
    pub fn facts(&self) -> Vec<ImageFacts> {
        vec![ImageFacts {
            start: OLD,
            bytes: self.old_source.clone(),
            heads: self.old_heads.clone(),
        }]
    }
    pub fn profile(&self) -> DynamicExecProfile {
        DynamicExecProfile {
            max_capture_images: 1,
            max_capture_bytes: CODE,
            max_total_capture_bytes: CODE,
            max_argument_pointers: 8,
            max_string_bytes: PAGE,
        }
    }
    pub fn options(&self) -> DynamicAdmissionOptions {
        DynamicAdmissionOptions {
            backend: DynamicAdmissionBackend::CoverageTrap(
                liteinst_launch::trap_coverage::TrapCoverageBudget::default(),
            ),
            ..DynamicAdmissionOptions::default()
        }
    }
    pub fn old_memory(&self) -> Vec<u8> {
        let mut bytes = self.old_data.clone();
        let at = (sp(OLD_DATA) - 8 - OLD_DATA) as usize;
        bytes[at..at + 8].copy_from_slice(&self.call_return.to_le_bytes());
        bytes
    }
    pub fn new_memory(&self, outputs: [u64; 4]) -> Vec<u8> {
        let mut bytes = self.new_data.clone();
        for (i, value) in outputs.into_iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        let at = (sp(NEW_DATA) - 8 - NEW_DATA) as usize;
        bytes[at..at + 8].copy_from_slice(&FLAGS.to_le_bytes());
        bytes
    }
    pub fn armed(&self, new: bool) -> Vec<u8> {
        let (base, mut bytes, sites) = if new {
            (
                NEW,
                self.new_source.clone(),
                [self.first_cpu, self.final_cpu],
            )
        } else {
            (OLD, self.old_source.clone(), [self.old_cpu, self.exec])
        };
        for pc in sites {
            assert_eq!(bytes[(pc - base) as usize], 0x0f);
            bytes[(pc - base) as usize] = 0xcc;
        }
        bytes
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_file(&self.old_path).unwrap();
        fs::remove_file(&self.new_path).unwrap();
        fs::remove_dir(&self.directory).unwrap();
    }
}
