//! Private fixed-capacity contract prototype. No allocations, libc, TLS or syscalls.
//! Admission-owned: Rust core/no_std, NOT the A0 core's publication machinery.
//! Pure geometry/phase checks never supply a genuine frame, lease or receipt.
use core::sync::atomic::{compiler_fence, Ordering};

const ABI:u32=1;
const PAGE:u64=4096;
const MIN_EXEC:u64=0x2_0000_0000;
const ARG:i32=1500;
const ENCODING:i32=1501;
const GEOMETRY:i32=1502;
const REUSE:i32=1503;
#[repr(C)]
#[derive(Clone,Copy,Default)]
pub struct Page {pub address:u64,pub allocation:u64,pub generation:u64,pub offset:u64}
#[repr(C)]
#[derive(Clone,Copy)]
pub struct Plan {
    pub abi_version:u32,pub kind:u32,
    pub sequence:u64,pub pc:u64,pub next_pc:u64,pub landing:u64,
    pub landing_allocation:u64,pub landing_generation:u64,
    pub pages:[Page;2],pub page_count:u32,pub reserved:u32,
    pub original:[u8;5],pub redirect:[u8;5],pub reserved_bytes:[u8;6],
}
#[repr(C)]
pub struct State {
    pub phase:u32,pub first_error:u32,pub first_detail:i64,pub sequence:u64,
    pub mutation_started:u32,pub published:u32,pub restored:u32,pub reserved:u32,
}
const _:()=assert!(core::mem::size_of::<Plan>()==144);
const _:()=assert!(core::mem::size_of::<State>()==40);

fn checked(mut p:Plan)->Result<Plan,i32> {
    if p.abi_version!=ABI || p.sequence==0 || p.reserved!=0 ||
       p.reserved_bytes!=[0;6] || p.redirect!=[0;5] ||
       p.pc<MIN_EXEC || p.landing<MIN_EXEC ||
       p.landing_allocation==0 || p.landing_generation==0 {return Err(ARG)}
    let opcode=match p.kind {1=>[0x0f,0x05],2=>[0x0f,0x31],3=>[0x0f,0xa2],_=>return Err(ENCODING)};
    if p.original[..2]!=opcode {return Err(ENCODING)}
    let end=p.pc.checked_add(5).ok_or(GEOMETRY)?;
    if p.next_pc!=p.pc.checked_add(2).ok_or(GEOMETRY)? {return Err(GEOMETRY)}
    let first=p.pc&!(PAGE-1);
    let last=(end-1)&!(PAGE-1);
    let count=if first==last {1}else{2};
    if p.page_count!=count {return Err(GEOMETRY)}
    for i in 0..count as usize {
        let q=p.pages[i];
        let expected=first.checked_add((i as u64)*PAGE).ok_or(GEOMETRY)?;
        q.address.checked_add(PAGE).ok_or(GEOMETRY)?;
        q.offset.checked_add(PAGE).ok_or(GEOMETRY)?;
        if q.address!=expected || q.allocation==0 || q.generation==0 ||
           q.offset&(PAGE-1)!=0 {return Err(GEOMETRY)}
    }
    if count==1 {
        let q=p.pages[1];
        if q.address!=0 || q.allocation!=0 || q.generation!=0 || q.offset!=0 {return Err(ARG)}
    }
    let landing_page=p.landing&!(PAGE-1);
    landing_page.checked_add(PAGE).ok_or(GEOMETRY)?;
    if landing_page==first || landing_page==last ||
       (p.landing.checked_add(1).ok_or(GEOMETRY)? & !(PAGE-1))!=landing_page {
        return Err(GEOMETRY)
    }
    let d=i128::from(p.landing)-i128::from(end);
    let displacement=i32::try_from(d).map_err(|_|GEOMETRY)?.to_le_bytes();
    p.redirect=[0xe9,displacement[0],displacement[1],displacement[2],displacement[3]];
    Ok(p)
}

/// # Safety
/// Both pointers are valid for their complete object; output is private and
/// nonoverlapping. A successful result is descriptive only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_admission_oneshot_plan(input:*const Plan,out:*mut Plan)->i32 {
    if input.is_null() || out.is_null() {return ARG}
    let p=unsafe{core::ptr::read(input)};
    match checked(p) {Ok(v)=>{unsafe{core::ptr::write(out,v)};0},Err(e)=>e}
}
/// # Safety
/// The caller owns this fixed state, excludes concurrent/resumable reentry,
/// and has authenticated the separate runtime authority.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_admission_oneshot_bind(s:*mut State,sequence:u64)->i32 {
    if s.is_null() || sequence==0 {return ARG}
    // No Rust reference spans a possible reserved-signal interruption.
    unsafe {
        if core::ptr::read_volatile(core::ptr::addr_of!((*s).phase))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).first_error))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).first_detail))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).sequence))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).mutation_started))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).published))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).restored))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).reserved))!=0 {return REUSE}
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).sequence),sequence);
        compiler_fence(Ordering::Release);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).phase),1);
    }
    0
}
/// # Safety
/// The trusted backend completed every observation for this exact transition.
/// This validates ordering, not callback truth or permission ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_admission_oneshot_transition(s:*mut State,old:u32,new:u32)->i32 {
    if s.is_null() {return ARG}
    unsafe {
        if core::ptr::read_volatile(core::ptr::addr_of!((*s).first_error))!=0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).sequence))==0 ||
           core::ptr::read_volatile(core::ptr::addr_of!((*s).phase))!=old {return REUSE}
    }
    if !matches!((old,new),(1,2)|(2,3)|(3,4)|(4,5)|(5,6)|(6,7)|(7,8)) {return REUSE}
    unsafe {
        if new==2 {core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).mutation_started),1);}
        if new==3 {core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).published),1);}
        if new==7 {core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).restored),1);}
        compiler_fence(Ordering::Release);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).phase),new);
    }
    0
}
/// # Safety
/// State is retained private storage. A failed state never authorizes fallback
/// after mutation or execution. This does not perform or claim cleanup.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_admission_oneshot_fail(s:*mut State,code:u32,detail:i64) {
    if s.is_null() {return}
    unsafe {
        if core::ptr::read_volatile(core::ptr::addr_of!((*s).first_error))==0 {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).first_error),if code!=0 {code}else{ARG as u32});
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).first_detail),detail);
        }
        compiler_fence(Ordering::Release);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*s).phase),9);
    }
}
