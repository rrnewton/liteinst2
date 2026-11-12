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
            // Reads the planted red-zone marker, exits via CPUID
            // (dispatcher re-entry), reads it again, returns the
            // difference: 0 only if neither entry overwrote [rsp-8].
            name: "redzone_reentry",
            bytes: asm(|a| {
                a.mov(rax, qword_ptr(rsp - 8))?;
                a.mov(qword_ptr(rdi), rax)?;
                a.xor(eax, eax)?;
                a.cpuid()?;
                a.mov(rax, qword_ptr(rsp - 8))?;
                a.sub(rax, qword_ptr(rdi))?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            name: "ret_imm16",
            bytes: vec![0xc2, 0x10, 0x00],
        },
        Fixture {
            // mov rsp,rdi; ret  (rdi is the bad stack in fault runs)
            name: "fault_ret",
            bytes: vec![0x48, 0x89, 0xfc, 0xc3],
        },
        Fixture {
            // rdtsc; ret — the reference handler must refuse it.
            name: "rdtsc_exit",
            bytes: vec![0x0f, 0x31, 0xc3],
        },
        Fixture {
            // mov rsp,rdi; call helper; ret; helper: ret
            // With rdi naming a read-only page the call's own
            // stack store faults; recovery must restore the
            // pre-call RAX/RSP exactly.
            name: "call_store_fault",
            bytes: vec![0x48, 0x89, 0xfc, 0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3],
        },
        Fixture {
            // mov rcx,rdx; rep movsb; mov eax,7; ret — REP itself
            // retires (not branched around) when rdx=0.
            name: "rep_zero",
            bytes: vec![
                0x48, 0x89, 0xd1, 0xf3, 0xa4, 0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3,
            ],
        },
        Fixture {
            // mov rcx,rdx; rep movsw (66 f3 a5 prefix order); ret
            name: "rep_movsw_prefix",
            bytes: vec![0x48, 0x89, 0xd1, 0x66, 0xf3, 0xa5, 0xc3],
        },
        Fixture {
            // mov ecx,64; mov al,0x5a; rep stosb; ret — faults
            // 16 bytes in against the guarded destination.
            name: "rep_stosb_partial",
            bytes: vec![0xb9, 0x40, 0x00, 0x00, 0x00, 0xb0, 0x5a, 0xf3, 0xaa, 0xc3],
        },
        Fixture {
            // mov eax,1; xor edx,edx; xor ecx,ecx; div ecx; ret
            name: "div_zero",
            bytes: vec![
                0xb8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x31, 0xc9, 0xf7, 0xf1, 0xc3,
            ],
        },
        Fixture {
            name: "int3_trap",
            bytes: vec![0xcc, 0xc3],
        },
        Fixture {
            // cc_sum compiled 2026-11-05, gcc 11.5.0:
            // gcc -O1 -fno-tree-vectorize -mno-sse -mno-mmx
            //   -fno-stack-protector -fcf-protection=none -c
            // long cc_sum(const long *a, long n) { long s = 0;
            //   for (long i = 0; i < n; i++)
            //     s = (a[i] & 1) ? s + a[i] : s - 1; return s; }
            // .text extracted with objcopy -O binary.
            name: "compiled_c",
            bytes: vec![
                0x48, 0x85, 0xf6, 0x7e, 0x28, 0x48, 0x89, 0xfa, 0x48, 0x8d, 0x3c, 0xf7, //
                0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x0a, 0x48, 0x8d, 0x34, 0x08, //
                0x48, 0x83, 0xe8, 0x01, 0xf6, 0xc1, 0x01, 0x48, 0x0f, 0x45, 0xc6, 0x48, //
                0x83, 0xc2, 0x08, 0x48, 0x39, 0xfa, 0x75, 0xe5, 0xc3, 0xb8, 0x00, 0x00, //
                0x00, 0x00, 0xc3,
            ],
        },
        Fixture {
            // std; xor eax,eax; cpuid; cld; ret — guest DF must be
            // set in saved state at the handler exit while host
            // code observes DF clear (review R2 shape).
            name: "std_cld",
            bytes: vec![0xfd, 0x31, 0xc0, 0x0f, 0xa2, 0xfc, 0xc3],
        },
        Fixture {
            // xor eax; mov rcx,rsi; L: inc rax; loopne L; ret
            name: "loopne_insn",
            bytes: vec![0x31, 0xc0, 0x48, 0x89, 0xf1, 0xff, 0xc0, 0xe0, 0xfc, 0xc3],
        },
        Fixture {
            // xor eax; mov rcx,rsi; L: inc rax; test al,0; loope L; ret
            name: "loope_insn",
            bytes: vec![
                0x31, 0xc0, 0x48, 0x89, 0xf1, 0xff, 0xc0, 0xf6, 0xc0, 0x00, 0xe1, 0xf9, 0xc3,
            ],
        },
        Fixture {
            // mov rcx,rdx; mov al,0x5a; rep stosb; ret (rdi=dst)
            name: "rep_stosb_ok",
            bytes: vec![0x48, 0x89, 0xd1, 0xb0, 0x5a, 0xf3, 0xaa, 0xc3],
        },
        Fixture {
            // mov rcx,rdx; xor eax,eax; repne scasb; mov rax,rdx;
            // sub rax,rcx; ret (rdi=src buffer, scans for NUL)
            name: "repne_scasb",
            bytes: vec![
                0x48, 0x89, 0xd1, 0x31, 0xc0, 0xf2, 0xae, 0x48, 0x89, 0xd0, 0x48, 0x29, 0xc8, 0xc3,
            ],
        },
        Fixture {
            // mov r11,0x100; mov rax,r11; ret — ordinary R11 data
            // must compare exactly, bit 8 included.
            name: "r11_data",
            bytes: vec![
                0x49, 0xc7, 0xc3, 0x00, 0x01, 0x00, 0x00, 0x4c, 0x89, 0xd8, 0xc3,
            ],
        },
        Fixture {
            // mov rax,[rip+8]; store/load fault vs RX page:
            // mov [rip+8],rdi; mov rax,[rip+1]; ret; dq 0
            name: "rip_store_fault",
            bytes: vec![
                0x48, 0x89, 0x3d, 0x08, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x01, 0x00, 0x00, 0x00,
                0xc3, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        },
        Fixture {
            name: "indirect_call",
            bytes: vec![0xff, 0xd0, 0xc3],
        },
        Fixture {
            // jmp qword [rip+0] with an inline table entry.
            name: "jump_table",
            bytes: vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
        },
        Fixture {
            // mov rax,[rdi]; cmp rax,0; jne done; done: ret — a
            // fault on the load must not credit the later branch.
            name: "fault_before_branch",
            bytes: vec![0x48, 0x8b, 0x07, 0x48, 0x83, 0xf8, 0x00, 0x75, 0x00, 0xc3],
        },
        Fixture {
            // mov r12,rsi; L: xor eax,eax; cpuid; dec r12; jne L; ret
            // One handler exit per iteration: poll-budget resets on
            // re-entry would defer a pending signal forever (T2).
            name: "cpuid_loop",
            bytes: vec![
                0x49, 0x89, 0xf4, 0x31, 0xc0, 0x0f, 0xa2, 0x49, 0xff, 0xcc, 0x75, 0xf7, 0xc3,
            ],
        },
        Fixture {
            // mov ecx,3; rep lodsq; ret (rsi=src) — wide REP
            // retirement: exactly 3 instructions total.
            name: "rep_lodsq",
            bytes: vec![0xb9, 0x03, 0x00, 0x00, 0x00, 0xf3, 0x48, 0xad, 0xc3],
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
