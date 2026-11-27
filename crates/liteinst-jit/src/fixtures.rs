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
            // code observes DF clear (external review R2 shape).
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
        // P1b.1 fixtures (dispatcher-resolved indirect transfers).
        // Hand-assembled so every offset below is explicit; rsi is
        // the loop count (16 in the corpus).
        Fixture {
            // 00 xor ecx,ecx; 02 top: cmp rcx,rsi; 05 jae done;
            // 07 inc rcx; 0a lea rax,[rip+top]; 11 jmp rax;
            // 13 done: mov rax,rcx; 16 ret. `top` is mid-block in
            // the entry block: the first jump splits it.
            name: "ind_jmp_reg",
            bytes: vec![
                0x31, 0xc9, 0x48, 0x39, 0xf1, 0x73, 0x0c, 0x48, 0xff, 0xc1, //
                0x48, 0x8d, 0x05, 0xf1, 0xff, 0xff, 0xff, 0xff, 0xe0, //
                0x48, 0x89, 0xc8, 0xc3,
            ],
        },
        Fixture {
            // 00 xor ecx,ecx; 02 xor edx,edx; 04 top: cmp rcx,rsi;
            // 07 jae done; 09 lea rax,[rip+helper]; 10 call rax;
            // 12 inc rcx; 15 jmp top; 17 done: mov rax,rdx; 1a ret;
            // 1b helper: test cl,1; 1e jz even; 20 inc rdx;
            // 23 even: ret. rax = the odd count below rsi.
            name: "ind_call_reg",
            bytes: vec![
                0x31, 0xc9, 0x31, 0xd2, 0x48, 0x39, 0xf1, 0x73, 0x0e, //
                0x48, 0x8d, 0x05, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xd0, //
                0x48, 0xff, 0xc1, 0xeb, 0xed, 0x48, 0x89, 0xd0, 0xc3, //
                0xf6, 0xc1, 0x01, 0x74, 0x03, 0x48, 0xff, 0xc2, 0xc3,
            ],
        },
        Fixture {
            // 00 xor ecx,ecx; 02 xor r8d,r8d; 05 top: cmp rcx,rsi;
            // 08 jae done; 0a mov rax,rcx; 0d and eax,3;
            // 10 lea rdx,[rip+table]; 17 movsxd rax,[rdx+rax*4];
            // 1b add rax,rdx; 1e jmp rax;
            // 20 c0: add r8,1; 24 jmp next; 26 c1: add r8,2;
            // 2a jmp next; 2c c2: add r8,3; 30 jmp next;
            // 32 c3: add r8,4; 36 jmp next; 38 next: inc rcx;
            // 3b jmp top; 3d done: mov rax,r8; 40 ret;
            // 41 table: dd c0-table, c1-table, c2-table, c3-table.
            name: "ind_jmp_table",
            bytes: vec![
                0x31, 0xc9, 0x45, 0x31, 0xc0, 0x48, 0x39, 0xf1, 0x73, 0x33, //
                0x48, 0x89, 0xc8, 0x83, 0xe0, 0x03, //
                0x48, 0x8d, 0x15, 0x2a, 0x00, 0x00, 0x00, //
                0x48, 0x63, 0x04, 0x82, 0x48, 0x01, 0xd0, 0xff, 0xe0, //
                0x49, 0x83, 0xc0, 0x01, 0xeb, 0x12, //
                0x49, 0x83, 0xc0, 0x02, 0xeb, 0x0c, //
                0x49, 0x83, 0xc0, 0x03, 0xeb, 0x06, //
                0x49, 0x83, 0xc0, 0x04, 0xeb, 0x00, //
                0x48, 0xff, 0xc1, 0xeb, 0xc8, 0x4c, 0x89, 0xc0, 0xc3, //
                0xdf, 0xff, 0xff, 0xff, 0xe5, 0xff, 0xff, 0xff, //
                0xeb, 0xff, 0xff, 0xff, 0xf1, 0xff, 0xff, 0xff,
            ],
        },
        Fixture {
            // As ind_call_reg, through memory: 09 lea rax,[rip+helper];
            // 10 push rax; 11 call qword [rsp]; 14 add rsp,8;
            // 18 inc rcx; 1b jmp top; 1d done: mov rax,rdx; 20 ret;
            // 21 helper: test cl,1; 24 jz even; 26 inc rdx;
            // 29 even: ret.
            name: "ind_call_mem",
            bytes: vec![
                0x31, 0xc9, 0x31, 0xd2, 0x48, 0x39, 0xf1, 0x73, 0x14, //
                0x48, 0x8d, 0x05, 0x11, 0x00, 0x00, 0x00, 0x50, 0xff, 0x14, 0x24, //
                0x48, 0x83, 0xc4, 0x08, 0x48, 0xff, 0xc1, 0xeb, 0xe7, //
                0x48, 0x89, 0xd0, 0xc3, //
                0xf6, 0xc1, 0x01, 0x74, 0x03, 0x48, 0xff, 0xc2, 0xc3,
            ],
        },
        Fixture {
            // 00 xor ecx,ecx; 02 top: cmp rcx,rsi; 05 jae done;
            // 07 inc rcx; 0a test rsi,rsi; 0d jz top (never taken:
            // `top` is a P1a block start); 0f lea rax,[rip+top];
            // 16 jmp rax; 18 done: mov rax,rcx; 1b ret.
            name: "ind_jmp_known",
            bytes: vec![
                0x31, 0xc9, 0x48, 0x39, 0xf1, 0x73, 0x11, 0x48, 0xff, 0xc1, //
                0x48, 0x85, 0xf6, 0x74, 0xf3, //
                0x48, 0x8d, 0x05, 0xec, 0xff, 0xff, 0xff, 0xff, 0xe0, //
                0x48, 0x89, 0xc8, 0xc3,
            ],
        },
        Fixture {
            // call rdi (rdi = 0: outside the region, refused before
            // any push).
            name: "ind_call_out",
            bytes: vec![0xff, 0xd7],
        },
        Fixture {
            // 00 xor ecx,ecx; 02 cmp rcx,rsi; 05 jae x;
            // 07 x: jmp qword [rdx] (rdx = 0x10: the read faults).
            name: "ind_fault_mem",
            bytes: vec![0x31, 0xc9, 0x48, 0x39, 0xf1, 0x73, 0x00, 0xff, 0x22],
        },
        Fixture {
            // 00 test rsi,rsi; 03 jz L (never taken: L is a P1a
            // block start); 05 lea rax,[rip+L+1]; 0c jmp rax;
            // 0e L: mov rax,0x9090909000000000; 18 ret. From L+1 the
            // bytes decode as mov eax,0, four nops and the same ret.
            name: "ind_interior",
            bytes: vec![
                0x48, 0x85, 0xf6, 0x74, 0x09, //
                0x48, 0x8d, 0x05, 0x03, 0x00, 0x00, 0x00, 0xff, 0xe0, //
                0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0xc3,
            ],
        },
        Fixture {
            // 00 xor ecx,ecx; 02 cmp rcx,rsi; 05 jae x;
            // 07 x: jmp rdi (rdi = 0: a budget run hands off here).
            name: "ind_jmp_out_budget",
            bytes: vec![0x31, 0xc9, 0x48, 0x39, 0xf1, 0x73, 0x00, 0xff, 0xe7],
        },
        // Segment-override fixtures. Each engine runs on its own
        // thread's TLS (in process: the test thread; remote and O1:
        // their own child), so every fixture that returns normally
        // cancels each TLS-derived value before `ret`.
        Fixture {
            // The stack-protector canary: 00 mov rcx,fs:[0x28];
            // 09 mov rax,fs:moffs64 0x28; 14 mov fs:[0x28],rcx (TLS
            // store of the same value); 1d mov rdx,rax;
            // 20 xor rdx,fs:[0x28] (0); 29 cmp rax,rcx; 2c jne bad;
            // 2e sub rax,fs:[0x28] (0, the check idiom); 37 jne bad;
            // 39 cmp rcx,fs:[0x28]; 42 jne bad; 44 xor ecx,ecx;
            // 46 or rax,rdx; 49 ret (rax 0); 4a bad: xor ecx,ecx;
            // 4c xor edx,edx; 4e mov eax,1; 53 ret.
            name: "seg_fs_canary",
            bytes: vec![
                0x64, 0x48, 0x8b, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00, //
                0x64, 0x48, 0xa1, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x64, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00, //
                0x48, 0x89, 0xc2, //
                0x64, 0x48, 0x33, 0x14, 0x25, 0x28, 0x00, 0x00, 0x00, //
                0x48, 0x39, 0xc8, 0x75, 0x1c, //
                0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0x75, 0x11, //
                0x64, 0x48, 0x3b, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00, 0x75, 0x06, //
                0x31, 0xc9, 0x48, 0x09, 0xd0, 0xc3, //
                0x31, 0xc9, 0x31, 0xd2, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
            ],
        },
        Fixture {
            // The TCB self pointer: 00 mov rax,fs:[0] (thread
            // pointer); 09 cmp rax,[rax] (a load through it: the
            // self pointer); 0c jne bad; 0e mov rcx,[rax+0x28];
            // 12 sub rcx,fs:[0x28] (0); 1b jne bad; 1d mov rdx,fs:[rcx]
            // (register base, rcx 0); 21 sub rax,rdx (0); 24 jne bad;
            // 26 xor edx,edx; 28 ret (rax 0); 29 bad: xor ecx,ecx;
            // 2b xor edx,edx; 2d mov eax,1; 32 ret.
            name: "seg_fs_tcb",
            bytes: vec![
                0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, //
                0x48, 0x3b, 0x00, 0x75, 0x1b, //
                0x48, 0x8b, 0x48, 0x28, //
                0x64, 0x48, 0x2b, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00, 0x75, 0x0c, //
                0x64, 0x48, 0x8b, 0x11, 0x48, 0x29, 0xd0, 0x75, 0x03, //
                0x31, 0xd2, 0xc3, //
                0x31, 0xc9, 0x31, 0xd2, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
            ],
        },
        Fixture {
            // GS base 0: 00 xor ecx,ecx; 02 lp: inc ecx; 04 cmp ecx,3;
            // 07 jne lp; 09 mov rax,gs:[0x40] faults at linear 0x40
            // (3 branches and 10 instructions retired first); 12 ret.
            name: "seg_gs_fault",
            bytes: vec![
                0x31, 0xc9, 0xff, 0xc1, 0x83, 0xf9, 0x03, 0x75, 0xf9, //
                0x65, 0x48, 0x8b, 0x04, 0x25, 0x40, 0x00, 0x00, 0x00, 0xc3,
            ],
        },
        Fixture {
            // ES, CS, SS and DS overrides (ignored in 64-bit mode):
            // 00 lea rbx,[rip+data]; 07 mov rax,ds:[rbx];
            // 0b add rax,cs:[rbx+8]; 10 add rax,es:[rbx+16];
            // 15 add rax,ss:[rbx+24]; 1a add rax,ds:[rip+data+32]
            // (re-encoded); 22 nopw cs:[rax+rax] (compiler padding,
            // executed); 2c mov ds:[rsp-0x10],rax; 32 cs nop;
            // 34 xor ebx,ebx; 36 ret (rax 31); 37 int3 (pad);
            // 38 data: dq 1, 2, 4, 8, 16.
            name: "seg_flat_overrides",
            bytes: vec![
                0x48, 0x8d, 0x1d, 0x31, 0x00, 0x00, 0x00, //
                0x3e, 0x48, 0x8b, 0x03, //
                0x2e, 0x48, 0x03, 0x43, 0x08, //
                0x26, 0x48, 0x03, 0x43, 0x10, //
                0x36, 0x48, 0x03, 0x43, 0x18, //
                0x3e, 0x48, 0x03, 0x05, 0x36, 0x00, 0x00, 0x00, //
                0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x3e, 0x48, 0x89, 0x44, 0x24, 0xf0, //
                0x2e, 0x90, 0x31, 0xdb, 0xc3, 0xcc, //
                1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, //
                4, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, //
                16, 0, 0, 0, 0, 0, 0, 0,
            ],
        },
        Fixture {
            // 00 mov rax,fs:[0]; 09 ret: returns the running thread's
            // TCB self pointer (its FS base). Not O1-comparable: the
            // value is per thread; tests pin it absolutely.
            name: "seg_fs_self",
            bytes: vec![0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0xc3],
        },
        // Call/return corpus: every one completes on today's code.
        // Each takes no arguments (the default all-zero ones) and
        // leaves no stack address in a register, so both engines
        // compare every register exactly. The counts in the comments
        // are worked out by hand from the code, not read from a run.
        Fixture {
            // fib(12) as a call tree: 465 calls (232 inner, 233
            // leaves), one `jb` each. rax = 144; branches = 465;
            // instructions = 3 + 14*232 + 4*233 = 4183; 466 rets.
            name: "ret_fib",
            bytes: asm(|a| {
                let mut fib = a.create_label();
                let mut base = a.create_label();
                a.mov(edi, 12)?;
                a.call(fib)?;
                a.ret()?;
                a.set_label(&mut fib)?;
                a.cmp(rdi, 2)?;
                a.jb(base)?;
                a.push(rbx)?;
                a.push(rdi)?;
                a.lea(rdi, ptr(rdi - 1))?;
                a.call(fib)?;
                a.mov(rbx, rax)?;
                a.mov(rdi, qword_ptr(rsp))?;
                a.lea(rdi, ptr(rdi - 2))?;
                a.call(fib)?;
                a.add(rax, rbx)?;
                a.pop(rdi)?;
                a.pop(rbx)?;
                a.ret()?;
                a.set_label(&mut base)?;
                a.mov(rax, rdi)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // Linear recursion 1000 frames deep: rsum(n) = n +
            // rsum(n-1). 1001 calls, one `jz` each. rax = 500500;
            // branches = 1001; instructions = 3 + 8*1000 + 4 =
            // 8007; 1002 rets, the deepest 1000 frames above the
            // first.
            name: "ret_deep_chain",
            bytes: asm(|a| {
                let mut rsum = a.create_label();
                let mut zero = a.create_label();
                a.mov(edi, 1000)?;
                a.call(rsum)?;
                a.ret()?;
                a.set_label(&mut rsum)?;
                a.test(rdi, rdi)?;
                a.jz(zero)?;
                a.push(rdi)?;
                a.dec(rdi)?;
                a.call(rsum)?;
                a.pop(rdi)?;
                a.add(rax, rdi)?;
                a.ret()?;
                a.set_label(&mut zero)?;
                a.xor(eax, eax)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // Mutual recursion even/odd from 20: 21 calls, each
            // returning straight into a caller's `ret` (a chain of
            // 21 returns). rax = 1; branches = 21; instructions =
            // 3 + 5*20 + 4 = 107; 22 rets.
            name: "ret_mutual",
            bytes: asm(|a| {
                let mut even = a.create_label();
                let mut odd = a.create_label();
                let mut e_yes = a.create_label();
                let mut o_no = a.create_label();
                a.mov(edi, 20)?;
                a.call(even)?;
                a.ret()?;
                a.set_label(&mut even)?;
                a.test(rdi, rdi)?;
                a.jz(e_yes)?;
                a.dec(rdi)?;
                a.call(odd)?;
                a.ret()?;
                a.set_label(&mut e_yes)?;
                a.mov(eax, 1)?;
                a.ret()?;
                a.set_label(&mut odd)?;
                a.test(rdi, rdi)?;
                a.jz(o_no)?;
                a.dec(rdi)?;
                a.call(even)?;
                a.ret()?;
                a.set_label(&mut o_no)?;
                a.xor(eax, eax)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // Tail calls through `jmp`: f and g jump to each other
            // ten times, then f's `ret` returns to the original
            // caller. rax = 55 + 2*10 + 1000 = 1075; branches = 11;
            // instructions = 5 + 5*10 + 2*10 + 3 = 78; 2 rets.
            name: "ret_tail_jmp",
            bytes: asm(|a| {
                let mut f = a.create_label();
                let mut f_done = a.create_label();
                let mut g = a.create_label();
                a.mov(edi, 10)?;
                a.xor(eax, eax)?;
                a.call(f)?;
                a.add(rax, 1000)?;
                a.ret()?;
                a.set_label(&mut f)?;
                a.test(rdi, rdi)?;
                a.jz(f_done)?;
                a.add(rax, rdi)?;
                a.dec(rdi)?;
                a.jmp(g)?;
                a.set_label(&mut f_done)?;
                a.ret()?;
                a.set_label(&mut g)?;
                a.add(rax, 2)?;
                a.jmp(f)?;
                Ok(())
            }),
        },
        Fixture {
            // push+ret used as a jump: the loop's back edge is
            // `lea rax,[rip+top]; push rax; ret`. The direct `jmp`
            // makes `top` a block start. rax = 8; branches = 9;
            // instructions = 2 + 6*8 + 4 = 54; 9 rets.
            name: "ret_push_jmp",
            bytes: asm(|a| {
                let mut top = a.create_label();
                let mut done = a.create_label();
                a.xor(ecx, ecx)?;
                a.jmp(top)?;
                a.set_label(&mut top)?;
                a.cmp(rcx, 8)?;
                a.jae(done)?;
                a.inc(rcx)?;
                a.lea(rax, ptr(top))?;
                a.push(rax)?;
                a.ret()?;
                a.set_label(&mut done)?;
                a.mov(rax, rcx)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // The callee overwrites its own return slot with `alt`
            // and returns there, skipping the call's return site.
            // The never-taken `jnz` makes `alt` a block start.
            // rax = 2; branches = 1; instructions = 4 + 3 + 2 = 9;
            // 2 rets.
            name: "ret_overwrite_slot",
            bytes: asm(|a| {
                let mut alt = a.create_label();
                let mut f = a.create_label();
                a.xor(ecx, ecx)?;
                a.test(ecx, ecx)?;
                a.jnz(alt)?;
                a.call(f)?;
                a.mov(eax, 1)?;
                a.ret()?;
                a.set_label(&mut alt)?;
                a.mov(eax, 2)?;
                a.ret()?;
                a.set_label(&mut f)?;
                a.lea(rcx, ptr(alt))?;
                a.mov(qword_ptr(rsp), rcx)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // longjmp-style: three calls deep, the innermost resets
            // rsp to the outer frame's saved slot and returns two
            // frames up at once (a and b never return). rdx, which
            // held a stack address, is cleared before the end.
            // rax = 107; branches = 0; instructions = 2 + 1 + 1 + 3
            // + 3 = 10; 2 rets.
            name: "ret_longjmp",
            bytes: asm(|a| {
                let mut fa = a.create_label();
                let mut fb = a.create_label();
                let mut fc = a.create_label();
                a.mov(rdx, rsp)?;
                a.call(fa)?;
                a.xor(edx, edx)?;
                a.add(rax, 100)?;
                a.ret()?;
                a.set_label(&mut fa)?;
                a.call(fb)?;
                a.ret()?;
                a.set_label(&mut fb)?;
                a.call(fc)?;
                a.ret()?;
                a.set_label(&mut fc)?;
                a.lea(rsp, ptr(rdx - 8))?;
                a.mov(eax, 7)?;
                a.ret()?;
                Ok(())
            }),
        },
        Fixture {
            // Callee-pops convention: five calls of add2(10, rcx),
            // each cleaning its two stack arguments with `ret 16`.
            // rax = rbx = (10+5)+(10+4)+...+(10+1) = 65; branches =
            // 5; instructions = 2 + 9*5 + 2 = 49; 6 rets.
            name: "ret_imm16_loop",
            bytes: asm(|a| {
                let mut top = a.create_label();
                let mut add2 = a.create_label();
                a.xor(ebx, ebx)?;
                a.mov(ecx, 5)?;
                a.set_label(&mut top)?;
                a.push(rcx)?;
                a.push(10i32)?;
                a.call(add2)?;
                a.add(rbx, rax)?;
                a.dec(rcx)?;
                a.jnz(top)?;
                a.mov(rax, rbx)?;
                a.ret()?;
                a.set_label(&mut add2)?;
                a.mov(rax, qword_ptr(rsp + 8))?;
                a.add(rax, qword_ptr(rsp + 16))?;
                a.ret_1(16u32)?;
                Ok(())
            }),
        },
    ]
}

/// Return-corpus fixtures whose expected outcome on today's code is
/// a named stop, not completion. They are reached through
/// [`by_name`] (the oracle and remote children, and the tests), but
/// are not listed in [`all`], whose every fixture the standalone
/// driver runs against its own expectation table.
pub fn named_stops() -> Vec<Fixture> {
    let mut remap = vec![0xccu8; 0x1000];
    // Page 0: 00 call helper (0x1000); 05 mov eax,1; 0a ret. The
    // rest of the page is int3.
    remap[..11].copy_from_slice(&[
        0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ]);
    // Page 1, the helper:
    // 1000 lea rbx,[rip-0x1007] (page 0's base);
    // 1007 munmap(rbx, 0x1000): mov eax,11; mov rdi,rbx;
    //      mov esi,0x1000; syscall;
    // 1016 mmap(rbx, 0x1000, PROT_READ|PROT_WRITE,
    //      MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0):
    //      mov eax,9; mov rdi,rbx; mov esi,0x1000; mov edx,3;
    //      mov r10d,0x100022; mov r8,-1; xor r9d,r9d; syscall;
    // 103a write page 0's new first 11 bytes, identical except
    //      that the return site now reads `mov eax,2`:
    //      mov rax,0x0002b800000ffbe8; mov [rbx],rax;
    //      mov dword [rbx+7],0xc3000000;
    // 104e mprotect(rbx, 0x1000, PROT_READ|PROT_EXEC): mov eax,10;
    //      mov rdi,rbx; mov esi,0x1000; mov edx,5; syscall;
    // 1062 xor ecx,ecx; xor r11d,r11d (the syscall clobbers);
    // 1067 ret, into the remapped page 0 at 05.
    remap.extend_from_slice(&[
        0x48, 0x8d, 0x1d, 0xf9, 0xef, 0xff, 0xff, //
        0xb8, 0x0b, 0x00, 0x00, 0x00, 0x48, 0x89, 0xdf, //
        0xbe, 0x00, 0x10, 0x00, 0x00, 0x0f, 0x05, //
        0xb8, 0x09, 0x00, 0x00, 0x00, 0x48, 0x89, 0xdf, //
        0xbe, 0x00, 0x10, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, //
        0x41, 0xba, 0x22, 0x00, 0x10, 0x00, //
        0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x45, 0x31, 0xc9, 0x0f, 0x05, //
        0x48, 0xb8, 0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xb8, 0x02, 0x00, //
        0x48, 0x89, 0x03, 0xc7, 0x43, 0x07, 0x00, 0x00, 0x00, 0xc3, //
        0xb8, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x89, 0xdf, //
        0xbe, 0x00, 0x10, 0x00, 0x00, 0xba, 0x05, 0x00, 0x00, 0x00, 0x0f, 0x05, //
        0x31, 0xc9, 0x45, 0x31, 0xdb, 0xc3,
    ]);
    vec![
        Fixture {
            // 00 lea rax,[rip+2]; 07 push rax; 08 ret; 09 mov eax,5;
            // 0e ret. The push+ret target 09 is in the region but no
            // direct edge reaches it, so it is not a block start.
            // Natively: rax = 5 after 5 instructions.
            name: "ret_push_unknown",
            bytes: vec![
                0x48, 0x8d, 0x05, 0x02, 0x00, 0x00, 0x00, 0x50, 0xc3, //
                0xb8, 0x05, 0x00, 0x00, 0x00, 0xc3,
            ],
        },
        Fixture {
            // 00 mov eax,0x1000; 05 push rax; 06 ret: a return that
            // leaves the admitted region for an address below
            // mmap_min_addr, which nothing can map. Natively the
            // fetch at 0x1000 faults after 3 instructions.
            name: "ret_out_of_region",
            bytes: vec![0xb8, 0x00, 0x10, 0x00, 0x00, 0x50, 0xc3],
        },
        Fixture {
            // Two pages. The helper on page 1 unmaps page 0, maps a
            // fresh page at the same address, writes page 0's bytes
            // back with one changed immediate, makes it executable
            // and returns into it. Natively: rax = 2 (the new
            // bytes), branches = 0, instructions = 1 + 24 + 2 = 27.
            name: "ret_remap",
            bytes: remap,
        },
    ]
}

pub fn by_name(name: &str) -> Fixture {
    all()
        .into_iter()
        .chain(named_stops())
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("fixture {name}"))
}
