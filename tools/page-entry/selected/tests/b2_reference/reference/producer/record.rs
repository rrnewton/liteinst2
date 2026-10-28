//! Explicit field serialization; never Rust/C structure padding or Debug output.
use super::*;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
fn word(out:&mut Vec<u8>,n:u64) {out.extend_from_slice(&n.to_le_bytes());}
fn state(out:&mut Vec<u8>,s:&State) {
    let r=&s.registers;
    for n in [r.r15,r.r14,r.r13,r.r12,r.rbp,r.rbx,r.r11,r.r10,r.r9,r.r8,r.rax,r.rcx,r.rdx,r.rsi,r.rdi,
        r.orig_rax,r.rip,r.cs,r.eflags,r.rsp,r.ss,r.fs_base,r.gs_base,r.ds,r.es,r.fs,r.gs] {word(out,n);}
    assert!((512..65536).contains(&s.xstate.len()));assert_eq!(s.data.len(),DATA_LEN);
    word(out,s.mask);word(out,s.xstate.len() as u64);out.extend_from_slice(&s.xstate);out.extend_from_slice(&s.data);
}
pub(super) fn write(case:&cases::Case,trace:&Trace) {
    assert_eq!(trace.rows.len(),case.replies.len());assert!((2..=4).contains(&trace.rows.len()));
    let f=&case.fixture;let mut out=b"B2DYN001".to_vec();
    for n in [1,trace.rows.len() as u64,f.bytes.len() as u64,f.heads.len() as u64,f.blocks.len() as u64,
        f.marker,BASE,DATA,DATA_LEN as u64,STACK,FLAGS,MASK] {word(&mut out,n);}
    out.extend_from_slice(&f.bytes);
    for n in f.heads.iter().chain(&f.blocks) {word(&mut out,*n);}
    for row in &trace.rows {
        use model::Selected::*;
        let (kind,width,destination)=match row.selected {
            Cpuid=>(1,0,16),Rdrand{destination,width}=>(2,width as u64,destination as u64),
            Rdseed{destination,width}=>(3,width as u64,destination as u64),Rdpid{destination}=>(4,64,destination as u64),
            Rdtsc=>(5,0,16),Rdtscp=>(6,0,16),Syscall=>(7,0,16)};
        let (values,carry)=match row.reply {
            Reply::Cpuid(v)=>(v.map(u64::from),0),Reply::Rdrand{value,carry}|Reply::Rdseed{value,carry}=>([value,0,0,0],u64::from(carry)),
            Reply::Rdpid(v)|Reply::GetId(v)=>([u64::from(v),0,0,0],0),Reply::Rdtsc(v)=>([v,0,0,0],0),
            Reply::Rdtscp(v,a)=>([v,u64::from(a),0,0],0)};
        for n in [kind,width,destination,row.bytes.len() as u64,values[0],values[1],values[2],values[3],carry] {word(&mut out,n);}
        assert!(!row.bytes.is_empty() && row.bytes.len()<=15);
        let mut bytes=[0;16];bytes[..row.bytes.len()].copy_from_slice(&row.bytes);out.extend_from_slice(&bytes);
        state(&mut out,&row.before);state(&mut out,&row.after);
    }
    assert!(out.len()<16*1024*1024);
    let mut file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(f.directory.join("reference.bin")).unwrap();
    file.write_all(&out).unwrap();file.sync_all().unwrap();
    // This marker is emitted only after both real child owners have been reaped
    // and every old full-state predicate plus the case-specific checks passed.
    let note=format!("{}\nselected={}\nraw_reaped=1\ntrap_reaped=1\nmodel_equal=1\n",case.id,trace.rows.len());
    let mut file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(f.directory.join("reference-complete.txt")).unwrap();
    file.write_all(note.as_bytes()).unwrap();file.sync_all().unwrap();
}
