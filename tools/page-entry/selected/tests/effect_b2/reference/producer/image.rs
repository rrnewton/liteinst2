//! Additive high-address dynamic ELF generator. The old static generator stays unchanged.
use super::*;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const PAGE: usize = 4096;
pub(super) const BASE: u64 = 0x200400000;
pub(super) const DATA: u64 = 0x200600000;
pub(super) const DATA_LEN: usize = 2 * PAGE;
pub(super) const STACK: u64 = DATA + DATA_LEN as u64 - 128;
pub(super) const FLAGS: u64 = 0xed7;
pub(super) const MASK: u64 = 0xffffffffbffbfae7; // exact reusable-publication SELECTED_MASK (SIGILL unblocked)
const SETUP: usize = 4 * PAGE;
const SOURCE_LEN: usize = 5 * PAGE;
const SONAME: &[u8] = b"li2-b2-reference.so\0";
static NEXT: AtomicUsize = AtomicUsize::new(0);

pub(super) fn seed(register: usize) -> u64 {
    match register {
        0 => 0x1122_3344_0000_0001,
        1 => 0x5566_7788_0000_0000,
        4 => STACK,
        _ => 0x2233_4455_6677_8800 | register as u64,
    }
}
fn put16(b: &mut [u8], at: usize, v: u16) { b[at..at+2].copy_from_slice(&v.to_le_bytes()); }
fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at+4].copy_from_slice(&v.to_le_bytes()); }
fn put64(b: &mut [u8], at: usize, v: u64) { b[at..at+8].copy_from_slice(&v.to_le_bytes()); }
fn header(b: &mut [u8], kind: u16, entry: u64, phnum: u16) {
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at,v) in [(16,kind),(18,62),(52,64),(54,56),(56,phnum)] { put16(b,at,v); }
    put32(b,20,1); put64(b,24,entry); put64(b,32,64);
}
fn ph(b: &mut [u8], i: usize, kind: u32, flags: u32, off: u64, va: u64, n: u64, align: u64) {
    let at=64+i*56; put32(b,at,kind); put32(b,at+4,flags);
    for (o,v) in [(8,off),(16,va),(24,va),(32,n),(40,n),(48,align)] { put64(b,at+o,v); }
}
fn dynamic(b: &mut [u8], base: u64, interpreter: bool) {
    // One actual SONAME for the interpreter; one exact DT_NEEDED in main.
    for (i,(tag,value)) in [(5,base+0x600),(10,(SONAME.len()+1) as u64),
        (if interpreter {14} else {1},1),(0,0)].into_iter().enumerate() {
        put64(b,0x500+i*16,tag); put64(b,0x508+i*16,value);
    }
    b[0x601..0x601+SONAME.len()].copy_from_slice(SONAME);
}
fn write_new(path: &std::path::Path, bytes: &[u8], mode: u32) {
    let mut f=OpenOptions::new().write(true).create_new(true).mode(mode).open(path).unwrap();
    f.write_all(bytes).unwrap(); f.sync_all().unwrap();
}

pub(super) struct Builder {
    pub(super) bytes: Vec<u8>,
    pub(super) heads: BTreeSet<u64>,
    pub(super) blocks: BTreeSet<u64>,
    pub(super) cursor: usize,
    pub(super) marker: u64,
    pages: usize,
}
impl Builder {
    pub(super) fn new(pages: usize) -> Self {
        assert!((2..=4).contains(&pages));
        let mut this=Self { bytes:vec![0;SOURCE_LEN],heads:BTreeSet::new(),blocks:BTreeSet::new(),
            cursor:SETUP,marker:BASE+PAGE as u64,pages };
        // Identical seed instructions/values to the old fixture. The fixed clean
        // setup page can execute natively without weakening TF instruction gates.
        this.mov(4,STACK);
        this.emit(&[0xdb,0xe3]); this.emit(&[0xd9,0xe8]);
        this.emit(&[0x66,0x0f,0x76,0xc9]); this.emit(&[0x66,0x0f,0x6f,0xd1]);
        for r in 0..16 { if r!=4 { this.mov(r,seed(r)); } }
        this.emit(&[0x68,0xd7,0x0e,0,0]); this.emit(&[0x9d]);
        // The old raw observer still stops at marker+1, before the first real
        // trajectory instruction. Neither jump nor NOP changes seeded state.
        this.branch(0xe9,this.marker);
        this.bytes[PAGE]=0x90; this.heads.insert(this.marker);
        this.blocks.remove(&this.marker); this.blocks.insert(this.marker+1);
        this.cursor=PAGE+1; this
    }
    pub(super) fn pc(&self)->u64 { BASE+self.cursor as u64 }
    pub(super) fn emit(&mut self, bytes:&[u8])->u64 {
        let pc=self.pc(); assert!(self.heads.insert(pc));
        assert!(self.cursor+bytes.len()<=self.bytes.len());
        self.bytes[self.cursor..self.cursor+bytes.len()].copy_from_slice(bytes);
        self.cursor+=bytes.len(); pc
    }
    pub(super) fn mov(&mut self, register:usize,value:u64) {
        assert!(register<16);
        let mut b=vec![0x48|(register>>3) as u8,0xb8|(register&7) as u8];
        b.extend_from_slice(&value.to_le_bytes()); self.emit(&b);
    }
    pub(super) fn store(&mut self,register:usize,slot:usize) {
        assert!(register<16 && slot<32); let next=self.pc()+7;
        let mut b=vec![0x48|(((register>>3) as u8)<<2),0x89,0x05|(((register&7) as u8)<<3)];
        b.extend_from_slice(&i32::try_from((DATA+8*slot as u64) as i64-next as i64).unwrap().to_le_bytes());
        self.emit(&b);
    }
    pub(super) fn branch(&mut self,opcode:u8,target:u64)->u64 {
        assert!(matches!(opcode,0xe8|0xe9)); let next=self.pc()+5;
        let mut b=vec![opcode]; b.extend_from_slice(&i32::try_from(target as i64-next as i64).unwrap().to_le_bytes());
        let pc=self.emit(&b); self.blocks.insert(target); if opcode==0xe8 { self.blocks.insert(next); } pc
    }
    pub(super) fn finish(mut self)->Fixture {
        assert!(self.cursor<self.pages*PAGE); self.emit(&[0xeb,0xfe]);
        assert!(self.blocks.iter().all(|pc|self.heads.contains(pc)));
        let root=PathBuf::from(std::env::var_os("LI2_B2_REFERENCE_DIR").expect("explicit private output directory"));
        assert!(root.is_absolute() && root.is_dir());
        let directory=root.join(format!("case{}",NEXT.fetch_add(1,Ordering::Relaxed)));
        fs::create_dir(&directory).unwrap();
        let interpreter=directory.join(std::str::from_utf8(&SONAME[..SONAME.len()-1]).unwrap());
        let mut ib=vec![0;2*PAGE]; header(&mut ib,3,PAGE as u64,4);
        ph(&mut ib,0,1,4,0,0,PAGE as u64,PAGE as u64);
        ph(&mut ib,1,1,5,PAGE as u64,PAGE as u64,PAGE as u64,PAGE as u64);
        ph(&mut ib,2,2,4,0x500,0x500,64,8); ph(&mut ib,3,0x6474e551,6,0,0,0,16);
        dynamic(&mut ib,0,true);
        ib[PAGE..PAGE+2].copy_from_slice(&[0x48,0xb8]);
        put64(&mut ib,PAGE+2,BASE+SETUP as u64); ib[PAGE+10..PAGE+12].copy_from_slice(&[0xff,0xe0]);
        let name=interpreter.as_os_str().as_encoded_bytes();
        assert!(name.first()==Some(&b'/') && !name.contains(&0) && name.len()+1<=0x800);
        header(&mut self.bytes,2,BASE+SETUP as u64,6);
        ph(&mut self.bytes,0,6,4,64,BASE+64,6*56,8);
        ph(&mut self.bytes,1,1,5,0,BASE,SOURCE_LEN as u64,PAGE as u64);
        ph(&mut self.bytes,2,1,6,SOURCE_LEN as u64,DATA,DATA_LEN as u64,PAGE as u64);
        ph(&mut self.bytes,3,3,4,0x700,BASE+0x700,(name.len()+1) as u64,1);
        ph(&mut self.bytes,4,2,4,0x500,BASE+0x500,64,8);
        ph(&mut self.bytes,5,0x6474e551,6,0,0,0,16);
        dynamic(&mut self.bytes,BASE,false); self.bytes[0x700..0x700+name.len()].copy_from_slice(name);
        let path=directory.join("image"); let mut file=self.bytes.clone(); file.extend_from_slice(&vec![0x5a;DATA_LEN]);
        let _fork=FILE_FORK.lock().unwrap();
        write_new(&interpreter,&ib,0o500); write_new(&path,&file,0o500);
        Fixture {path,directory,bytes:self.bytes,heads:self.heads,blocks:self.blocks,marker:self.marker,interpreter,interpreter_bytes:ib}
    }
}
pub(super) struct Fixture {
    pub(super) path:PathBuf,pub(super) directory:PathBuf,pub(super) bytes:Vec<u8>,
    pub(super) heads:BTreeSet<u64>,pub(super) blocks:BTreeSet<u64>,pub(super) marker:u64,
    interpreter:PathBuf,interpreter_bytes:Vec<u8>,
}
impl Fixture {
    pub(super) fn facts(&self)->ImageFacts { ImageFacts {start:BASE,bytes:self.bytes.clone(),heads:self.heads.clone()} }
    pub(super) fn bytes_at(&self,pc:u64)->Option<&[u8]> { self.bytes.get(usize::try_from(pc.checked_sub(BASE)?).ok()?..) }
    pub(super) fn interpreter_facts(&self, checkpoint:&ExecCheckpoint)->ImageFacts {
        let e=checkpoint.entries(); assert_eq!(e.first_image,liteinst_launch::FirstImage::Interpreter);
        assert_eq!(e.executable_entry,BASE+SETUP as u64);
        assert_eq!(e.interpreter.as_ref(),Some(&self.interpreter));
        assert_eq!(e.initial_instruction,e.interpreter_base+PAGE as u64);
        assert!(e.interpreter_base>=0x200000000 && e.interpreter_base%PAGE as u64==0);
        assert_eq!(checkpoint.read_memory(e.interpreter_base,self.interpreter_bytes.len()).unwrap(),self.interpreter_bytes);
        // The census describes the executable VMA; the read-only ELF header
        // page remains covered by the complete image-byte check above.
        ImageFacts {start:e.interpreter_base+PAGE as u64,bytes:self.interpreter_bytes[PAGE..].to_vec(),
            heads:[e.initial_instruction,e.initial_instruction+10].into_iter().collect()}
    }
}
// Deliberately retain generated source and reference records on both success and
// failure. The outer bounded evaluator owns final hashing and directory custody.
