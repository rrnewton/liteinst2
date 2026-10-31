//! Actual decoder source, descriptive tests only. The host test allocator is
//! std; this is not a post-seal allocation or native-execution qualification.
#![allow(dead_code)]
#[path = "../../decoder/src/abi.rs"] mod abi;
#[path = "../../decoder/src/arena.rs"] mod arena;
#[path = "../../decoder/src/decode.rs"] mod decode;
#[path = "../../decoder/src/tf.rs"] mod tf;
#[path = "../../decoder/src/write_footprint.rs"] mod write_footprint;
#[path = "../../decoder/src/region.rs"] mod region;
pub use write_footprint::Footprint as WriteFootprint;
use iced_x86::{Code, CodeSize, Decoder, DecoderOptions, InstructionInfoFactory,
    MemorySize, OpAccess, OpKind, Register, RflagsBits};

#[unsafe(no_mangle)]
extern "C" fn li2_decoder_abort(_: u32) -> ! { std::process::abort() }

fn refused(bytes: &[u8]) {
    let c=tf::one(0x4000,bytes).unwrap();
    assert_eq!((c.policy,c.flow,c.family),(0,0,0),"{bytes:02x?}");
    let w=write_footprint::one(0x4000,bytes,&write_footprint::Registers::default()).unwrap();
    assert_eq!((w.policy,w.first,w.end),(0,0,0),"{bytes:02x?}");
    assert_eq!((w.pc,w.next_pc,w.code,w.length),(c.pc,c.next_pc,c.code,c.length));
}

#[test]
fn canonical_metadata_and_implicit_read_effects() {
    assert_eq!(Code::Lodsq_RAX_m64 as u32,350);
    for pc in [0,0x4000,0x4fff,u64::MAX-15] {
        for n in 2..=15 {
            let mut bytes=[0xcc;15];bytes[..2].copy_from_slice(&[0x48,0xad]);
            let c=tf::one(pc,&bytes[..n]).unwrap();
            assert_eq!((c.pc,c.next_pc,c.abi_version,c.code,c.length,c.policy,c.flow,c.family),
                       (pc,pc+2,1,350,2,1,1,1));
            let old=decode::one(pc,&bytes[..n]).unwrap();
            assert_eq!((old.decode_status,old.kind,old.step_disposition),
                       (abi::VALID,abi::NONE,abi::STEP_UNSUPPORTED));
        }
    }
    let i=Decoder::with_ip(64,&[0x48,0xad],0x4000,DecoderOptions::NONE).decode();
    assert_eq!((i.op_count(),i.op0_kind(),i.op0_register(),i.op1_kind()),
               (2,OpKind::Register,Register::RAX,OpKind::MemorySegRSI));
    assert_eq!(i.rflags_read(),RflagsBits::DF);
    assert_eq!((i.rflags_modified(),i.rflags_written(),i.rflags_set(),i.rflags_cleared(),i.rflags_undefined()),(0,0,0,0,0));
    let mut factory=InstructionInfoFactory::new();let info=factory.info(&i);
    assert_eq!((info.op0_access(),info.op1_access()),(OpAccess::Write,OpAccess::Read));
    let actual:Vec<_>=info.used_registers().iter().map(|r|(r.register(),r.access())).collect();
    assert_eq!(actual,vec![(Register::RAX,OpAccess::Write),(Register::RSI,OpAccess::ReadWrite)]);
    assert_eq!(info.used_memory().len(),1);let m=info.used_memory()[0];
    assert_eq!((m.segment(),m.base(),m.index(),m.scale(),m.displacement()),
               (Register::DS,Register::RSI,Register::None,1,0));
    assert_eq!((m.memory_size(),m.access(),m.address_size(),m.vsib_size()),
               (MemorySize::UInt64,OpAccess::Read,CodeSize::Code64,0));
}

#[test]
fn noncanonical_width_prefix_and_string_forms_refuse() {
    for prefix in [0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3]
        .into_iter().chain(0x40..=0x4f) {
        refused(&[prefix,0x48,0xad]);
    }
    for rex in 0x40..=0x4f { if rex!=0x48 { refused(&[rex,0xad]); } }
    for bytes in [
        &[0xac][..],&[0xad],&[0x66,0xad],&[0x48,0xac],
        &[0xf3,0xac],&[0xf3,0xad],&[0xf3,0x66,0xad],&[0xf3,0x48,0xad],
        &[0xf2,0x48,0xad],&[0x48,0xf3,0xad],&[0x67,0x48,0xad],
        &[0x48,0xa5],&[0x48,0xab],&[0x48,0xaf],&[0x48],
    ] { refused(bytes); }
}

#[test]
fn no_memory_write_does_not_claim_read_address_validity() {
    for rsi in [0,1,0xff9,0xfff,0x1000,0x7fff_ffff_ffff,0x8000_0000_0000,u64::MAX-7,u64::MAX] {
        let state=write_footprint::Registers { gpr:[rsi;16],fs_base:u64::MAX,gs_base:u64::MAX };
        let w=write_footprint::one(0x4000,&[0x48,0xad],&state).unwrap();
        assert_eq!((w.pc,w.next_pc,w.abi_version,w.code,w.length,w.policy,w.first,w.end),
                   (0x4000,0x4002,1,350,2,1,0,0));
    }
}

#[test]
fn original_decode_argument_and_overflow_failures_stay_exact() {
    for bytes in [&[][..],&[0x48;16]] {
        assert_eq!(tf::one(0x4000,bytes).err(),Some(abi::BAD_ARGUMENT));
        assert_eq!(write_footprint::one(0x4000,bytes,&write_footprint::Registers::default()).err(),Some(abi::BAD_ARGUMENT));
    }
    assert_eq!(tf::one(u64::MAX-1,&[0x48,0xad]).err(),Some(abi::ADDRESS_OVERFLOW));
    assert_eq!(write_footprint::one(u64::MAX-1,&[0x48,0xad],&write_footprint::Registers::default()).err(),Some(abi::ADDRESS_OVERFLOW));
}

// Literal existing 336-byte span ABI; the production module asserts each
// boundary independently. No alternate module implementation is supplied.
#[repr(C)]
#[derive(Default)]
struct Span {
    decoded:abi::Decoded,target:u64,operands:[region::Operand;2],
    registers:[region::UsedRegister;4],address:region::Memory,rip_target:u64,
    version:u32,ready:u32,refusal:u32,flow:u32,condition:u32,operand_count:u32,
    register_count:u32,memory_count:u32,address_count:u32,flags_read:u32,
    flags_written:u32,flags_set:u32,flags_cleared:u32,flags_undefined:u32,
    gpr_read:u32,gpr_write:u32,relocation:u32,displacement_offset:u32,
    displacement_bytes:u32,reserved:u32,
}
unsafe extern "C" {
    fn li2_decoder_span_describe(pc:u64,bytes:*const u8,length:usize,out:*mut Span)->u32;
    fn li2_decoder_link_none(pc:u64,bytes:*const u8,length:usize,out:*mut WriteFootprint)->u32;
}

#[test]
fn copied_register_region_span_and_link_none_stay_closed() {
    assert_eq!(core::mem::size_of::<Span>(),336);
    // The real arena phase/Call guard is used; its allocator is not installed
    // as the host test allocator, so this test grants no allocation credit.
    let storage=Box::leak(Box::new([0u8;64]));
    assert_eq!(arena::begin(storage.as_mut_ptr(),storage.len()),abi::OK);
    decode::warm_tables();region::initialize();arena::seal();
    let bytes=[0x48,0xad];
    let old=decode::one(0x4000,&bytes).unwrap();
    assert_eq!(old.step_disposition,abi::STEP_UNSUPPORTED);
    { let call=arena::enter().unwrap();let d=region::one(0x4000,&bytes,&call).unwrap();
      assert_eq!((d.ready,d.refusal,d.decoded.code),(0,1,350)); }
    let mut span=Span::default();
    // SAFETY: complete live aligned distinct input/output allocations.
    assert_eq!(unsafe{li2_decoder_span_describe(0x4000,bytes.as_ptr(),bytes.len(),&mut span)},abi::OK);
    assert_eq!((span.ready,span.refusal,span.decoded.code),(0,1,350));
    let mut none=WriteFootprint::default();
    // SAFETY: same actual API contract, with a separate complete output.
    assert_eq!(unsafe{li2_decoder_link_none(0x4000,bytes.as_ptr(),bytes.len(),&mut none)},abi::OK);
    assert_eq!((none.pc,none.next_pc,none.code,none.length,none.policy,none.first,none.end),
               (0x4000,0x4002,350,2,0,0,0));
}
