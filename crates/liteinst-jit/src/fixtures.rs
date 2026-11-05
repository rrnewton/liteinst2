//! Corpus-v1 deterministic fixtures (P1a driver/oracle programs).
//!
//! Fixture ABI: entry at offset 0, arguments in `rdi`/`rsi`/`rdx`
//! (plus `rax` where noted), result in `rax`, terminated by `ret` to
//! the caller-planted sentinel. All bytes are position independent
//! except internal data, which is reached RIP-relatively.

use iced_x86::code_asm::*;

pub struct Fixture {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

fn asm(f: impl FnOnce(&mut CodeAssembler) -> Result<(), IcedError>) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).expect("64-bit assembler");
    f(&mut a).expect("fixture assembles");
    a.assemble(0).expect("fixture encodes")
}

pub fn all() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "sum_loop",
            bytes: asm(|a| {
                let mut lp = a.create_label();
                let mut done = a.create_label();
                a.xor(eax, eax)?;
                a.xor(ecx, ecx)?;
                a.set_label(&mut lp)?;
                a.cmp(rcx, rsi)?;
                a.jae(done)?;
                a.add(rax, qword_ptr(rdi + rcx * 8))?;
                a.inc(rcx)?;
                a.jmp(lp)?;
                a.set_label(&mut done)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            name: "branchy_even_sum",
            bytes: asm(|a| {
                let mut lp = a.create_label();
                let mut skip = a.create_label();
                let mut done = a.create_label();
                a.xor(eax, eax)?;
                a.xor(ecx, ecx)?;
                a.set_label(&mut lp)?;
                a.cmp(rcx, rsi)?;
                a.jae(done)?;
                a.test(cl, 1)?;
                a.jne(skip)?;
                a.add(rax, qword_ptr(rdi + rcx * 8))?;
                a.set_label(&mut skip)?;
                a.inc(rcx)?;
                a.jmp(lp)?;
                a.set_label(&mut done)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // Fallthrough and taken paths both consume CF from the
            // compare in an `adc` after the count stub: this is the
            // flag-neutrality witness. Preset rax is the accumulator.
            name: "flags_adc",
            bytes: asm(|a| {
                let mut eq = a.create_label();
                a.cmp(rdi, rsi)?;
                a.je(eq)?;
                a.adc(rax, 0)?;
                a.ret()?;
                a.set_label(&mut eq)?;
                a.adc(rax, 100)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            name: "call_helper",
            bytes: asm(|a| {
                let mut helper = a.create_label();
                let mut lp = a.create_label();
                let mut done = a.create_label();
                a.call(helper)?;
                a.add(rax, 1)?;
                a.ret()?;
                a.set_label(&mut helper)?;
                a.xor(eax, eax)?;
                a.xor(ecx, ecx)?;
                a.set_label(&mut lp)?;
                a.cmp(rcx, rsi)?;
                a.jae(done)?;
                a.add(rax, qword_ptr(rdi + rcx * 8))?;
                a.inc(rcx)?;
                a.jmp(lp)?;
                a.set_label(&mut done)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // mov rax,[rip+4]; add rax,rdi; ret; dq 41
            name: "rip_data",
            bytes: vec![
                0x48, 0x8b, 0x05, 0x04, 0x00, 0x00, 0x00, 0x48, 0x01, 0xf8, 0xc3, //
                41, 0, 0, 0, 0, 0, 0, 0,
            ],
        },
        Fixture {
            // test rdx,rdx; je ret; mov rcx,rdx; rep movsb; ret
            // (rdi=dst, rsi=src, rdx=count)
            name: "rep_movsb",
            bytes: vec![
                0x48, 0x85, 0xd2, 0x74, 0x05, 0x48, 0x89, 0xd1, 0xf3, 0xa4, 0xc3,
            ],
        },
        Fixture {
            // xor eax,eax; mov rcx,rsi; L: inc rax; loop L; ret
            name: "loop_insn",
            bytes: vec![0x31, 0xc0, 0x48, 0x89, 0xf1, 0xff, 0xc0, 0xe2, 0xfc, 0xc3],
        },
        Fixture {
            // jrcxz zero; mov eax,1; ret; zero: mov eax,2; ret
            // (rcx preset by the harness)
            name: "jrcxz",
            bytes: vec![
                0xe3, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, //
                0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,
            ],
        },
        Fixture {
            // write(1, rsi=buf, rdx=len) via handler; sign-check rax.
            name: "syscall_write",
            bytes: asm(|a| {
                let mut err = a.create_label();
                a.mov(eax, 1)?;
                a.mov(edi, 1)?;
                a.syscall()?;
                a.test(rax, rax)?;
                a.js(err)?;
                a.ret()?;
                a.set_label(&mut err)?;
                a.mov(eax, -1i32)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            name: "cpuid_leaf",
            bytes: asm(|a| {
                a.mov(eax, 0)?;
                a.cpuid()?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // Loop 3 times, then load through rdi (bad address in
            // the fault test; valid buffer otherwise).
            name: "fault_load",
            bytes: asm(|a| {
                let mut lp = a.create_label();
                a.xor(ecx, ecx)?;
                a.set_label(&mut lp)?;
                a.inc(rcx)?;
                a.cmp(rcx, 3)?;
                a.jne(lp)?;
                a.mov(rax, qword_ptr(rdi))?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            name: "indirect_jmp",
            bytes: asm(|a| {
                a.mov(rax, rdi)?;
                a.jmp(rax)?;
                Ok(())
            }),
        },
    ]
}

pub fn by_name(name: &str) -> Fixture {
    all()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("fixture {name}"))
}
