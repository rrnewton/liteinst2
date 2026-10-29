//! Fabricated full snapshots exercise the actual decoder/effect/trace validators.
//! No loaded owner, callback, machine execution or candidate comparison is faked.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

const ENTRY: u64 = 0x1000;
const DATA: u64 = 0x2000;
const INPUT: u64 = DATA + 64;
const STACK: u64 = 0x3000;
const CONTINUATION: u64 = 0x9000;
#[derive(Clone)]
struct Point {
    registers: libc::user_regs_struct,
    xstate: Vec<u8>,
    data: Vec<u8>,
    stack: Vec<u8>,
}
impl Point {
    fn new(case: Case) -> Self {
        let registers = libc::user_regs_struct {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            rbp: 0x5555,
            rbx: 0x6666,
            r11: 11,
            r10: 10,
            r9: 9,
            r8: 8,
            rax: 0x8877_6655_4433_2211,
            rcx: 0x9988_7766_5544_3322,
            rdx: 0xaabb_ccdd_eeff_0011,
            rsi: case.bound() as u64,
            rdi: INPUT,
            orig_rax: u64::MAX,
            rip: ENTRY,
            cs: 0x33,
            eflags: 0x202,
            rsp: STACK + 248,
            ss: 0x2b,
            fs_base: 0x7000,
            gs_base: 0x8000,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        };
        let mut data = vec![0x5a; 4096];
        data[64..128].copy_from_slice(&case.input());
        let mut stack = vec![0x6b; 256];
        stack[248..].copy_from_slice(&CONTINUATION.to_le_bytes());
        Self {
            registers,
            xstate: vec![0x7c; 1024],
            data,
            stack,
        }
    }
    fn view(&self) -> State<'_> {
        State {
            registers: &self.registers,
            xstate: &self.xstate,
            data: &self.data,
            stack: &self.stack,
        }
    }
    fn next(&self, len: usize) -> Self {
        let mut p = self.clone();
        p.registers.rip += len as u64;
        p
    }
}
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn check_step(bytes: &[u8], before: &Point, after: &Point) -> (Option<(u64, usize)>, bool) {
    let mut decoder = Decoder::with_ip(64, bytes, before.registers.rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    assert_eq!(decoder.position(), bytes.len());
    let k = validate(&instruction, bytes);
    effect(
        &instruction,
        k,
        Step {
            before: before.view(),
            after: after.view(),
        },
        Domain {
            input: INPUT,
            bound: 64,
            data: DATA,
            stack: STACK,
            continuation: CONTINUATION,
        },
    )
}
fn trace(case: Case, code: &[u8], points: &[Point]) -> Trace {
    let steps: Vec<_> = points
        .windows(2)
        .map(|p| Step {
            before: p[0].view(),
            after: p[1].view(),
        })
        .collect();
    inspect(
        Operation::Digits,
        case,
        &Plan::decode(code),
        Observation {
            entry: ENTRY,
            continuation: CONTINUATION,
            input_address: INPUT,
            data_address: DATA,
            stack_address: STACK,
            code,
            input: &case.input()[..case.bound()],
            steps: &steps,
        },
    )
}
fn one_read() -> (Vec<u8>, Vec<Point>) {
    // movzx eax, byte [rdi]; xor eax,eax; ret. For literal '/' this reads
    // the whole one-byte input and independently returns the literal zero.
    let code = vec![0x0f, 0xb6, 0x07, 0x31, 0xc0, 0xc3];
    let a = Point::new(Case::new(3));
    let mut b = a.next(3);
    b.registers.rax = 0x2f;
    let mut c = b.next(2);
    c.registers.rax = 0;
    c.registers.eflags = 0x246;
    let mut d = c.clone();
    d.registers.rip = CONTINUATION;
    d.registers.rsp += 8;
    (code, vec![a, b, c, d])
}

#[test]
fn leaf_set_scanner_truth_preserves_all_literal_inputs_and_results() {
    let literals: [&[u8]; 8] = [
        b"",
        b"/09: ",
        b" ",
        b"/",
        &[0, 31, 32, 33, 9, 47, 48, 57, 58, 255],
        &[b'9'; 64],
        &[b' '; 64],
        b"0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
    ];
    let answers = [
        (0, 0),
        (2, 1),
        (0, 1),
        (0, 0),
        (2, 1),
        (64, 0),
        (0, 64),
        (32, 32),
    ];
    for (n, case) in CASES.into_iter().enumerate() {
        assert_eq!(Case::new(n), case);
        assert_eq!(case.index(), n);
        assert_eq!(case.bound(), literals[n].len());
        assert_eq!(&case.input()[..case.bound()], literals[n]);
        assert!(case.input()[case.bound()..].iter().all(|&b| b == 0xa7));
        assert_eq!(
            (
                case.expected(Operation::Digits),
                case.expected(Operation::Spaces)
            ),
            answers[n]
        );
        assert_eq!(
            (
                scalar(Operation::Digits, literals[n]),
                scalar(Operation::Spaces, literals[n])
            ),
            answers[n]
        );
    }
    for b in 0..=u8::MAX {
        let digits = match b {
            b'0'..=b'9' => 1,
            _ => 0,
        };
        assert_eq!(scalar(Operation::Digits, &[b]), digits);
        assert_eq!(scalar(Operation::Spaces, &[b]), u64::from(b == 32));
    }
    let mut digits = Case::new(5).input();
    digits[63] = b'/';
    assert_eq!(scalar(Operation::Digits, &digits), 63);
    let mut spaces = Case::new(6).input();
    spaces[63] = b'/';
    assert_eq!(scalar(Operation::Spaces, &spaces), 63);
    let mut mixed = Case::new(7).input();
    mixed[63] = b'9';
    assert_eq!(
        (
            scalar(Operation::Digits, &mixed),
            scalar(Operation::Spaces, &mixed)
        ),
        (33, 31)
    );
    refuses(|| {
        Case::new(8);
    });
    refuses(|| {
        scalar(Operation::Digits, &[b'0'; 65]);
    });
    let (code, points) = one_read();
    let t = trace(Case::new(3), &code, &points);
    assert_eq!(
        (t.entry(), t.code(), t.visits(), t.ret_offset(), t.value()),
        (ENTRY, code.as_slice(), 3, 5, 0)
    );
    assert_eq!(
        t.reads(),
        [Read {
            at: 0,
            address: INPUT,
            width: 1
        }]
    );
    assert_eq!((t.input_reads(), t.input_bytes()), (1, 1));
    assert_eq!(t.input_offsets(), &BTreeSet::from([0]));
    assert_eq!(t.observed(), t.declared());
    assert_eq!(t.effect_heads(), &BTreeSet::from([0, 3, 5]));
    assert_eq!(t.effects_checked(), 3);
    assert_eq!(t.undefined_flag_heads(), &BTreeSet::from([3]));
    let plan = Plan::decode(&code);
    assert_eq!(plan.heads(), [0, 3, 5]);
    assert!(plan.padding().is_empty());
    assert_eq!(
        plan.codes(),
        [
            (0, Code::Movzx_r32_rm8),
            (3, Code::Xor_rm32_r32),
            (5, Code::Retnq)
        ]
    );

    // Empty input makes no read, with all real modeled instructions retained.
    let code = [0x31, 0xc0, 0x90, 0x90, 0xc3];
    let a = Point::new(Case::new(0));
    let mut b = a.next(2);
    b.registers.rax = 0;
    b.registers.eflags = 0x246;
    let c = b.next(1);
    let d = c.next(1);
    let mut e = d.clone();
    e.registers.rip = CONTINUATION;
    e.registers.rsp += 8;
    let t = trace(Case::new(0), &code, &[a, b, c, d, e]);
    assert_eq!((t.value(), t.input_reads(), t.input_bytes()), (0, 0, 0));
    assert!(t.input_offsets().is_empty());
    assert_eq!(t.observed(), t.declared());
    // Nine concrete qword reads cover all 64 bytes; the repeated first word
    // remains counted, so union coverage never substitutes for event totals.
    let mut code = Vec::new();
    let mut points = vec![Point::new(Case::new(6))];
    for offset in [0, 8, 16, 24, 32, 40, 48, 56, 0] {
        code.extend_from_slice(&[0x48, 0x8b, 0x47, offset]);
        let mut next = points.last().unwrap().next(4);
        next.registers.rax = 0x2020_2020_2020_2020;
        points.push(next);
    }
    code.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    let mut zero = points.last().unwrap().next(2);
    zero.registers.rax = 0;
    zero.registers.eflags = 0x246;
    points.push(zero);
    let mut returned = points.last().unwrap().clone();
    returned.registers.rip = CONTINUATION;
    returned.registers.rsp += 8;
    points.push(returned);
    let t = trace(Case::new(6), &code, &points);
    assert_eq!(
        (t.value(), t.input_reads(), t.input_bytes(), t.visits()),
        (0, 9, 72, 11)
    );
    assert_eq!(t.input_offsets(), &(0..64).collect());
    assert_eq!(
        t.reads().first().unwrap().address,
        t.reads().last().unwrap().address
    );
    assert_eq!(t.observed(), t.declared());
    assert_eq!(t.effect_heads(), &t.observed().heads);
    // Same scalar and read count, but a duplicate replaces the last qword:
    // bytes56..64 were never read and cannot be covered by aggregate totals.
    code[7 * 4 + 3] = 48;
    refuses(|| {
        trace(Case::new(6), &code, &points);
    });
}

#[test]
fn leaf_set_scanner_effects_check_widths_flags_and_branches() {
    let a = Point::new(Case::new(7));
    // Literal expected full-register values distinguish partial writes from
    // zero extension, including the legacy high-byte register position.
    let moves: &[(&[u8], u64)] = &[
        (&[0xb0, 0xab], 0x8877_6655_4433_22ab),
        (&[0xb4, 0xab], 0x8877_6655_4433_ab11),
        (&[0x66, 0xb8, 0xcd, 0xab], 0x8877_6655_4433_abcd),
        (&[0xb8, 0x78, 0x56, 0x34, 0x12], 0x1234_5678),
        (&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8], 0x0807_0605_0403_0201),
        (&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff], u64::MAX),
        (&[0x0f, 0xb6, 0xc4], 0x22),         // movzx eax,ah
        (&[0x48, 0x0f, 0xb7, 0xc1], 0x3322), // movzx rax,cx
    ];
    for &(code, result) in moves {
        let mut b = a.next(code.len());
        b.registers.rax = result;
        assert_eq!(check_step(code, &a, &b), (None, false));
        b.registers.rax ^= 1;
        refuses(|| {
            check_step(code, &a, &b);
        });
    }
    for (code, result) in [
        (&[0x0f, 0xb6, 0x07][..], 0x30),
        (&[0x0f, 0xb7, 0x07][..], 0x2030),
        (&[0x8b, 0x07][..], 0x2030_2030),
        (&[0x48, 0x8b, 0x07][..], 0x2030_2030_2030_2030),
    ] {
        let mut b = a.next(code.len());
        b.registers.rax = result;
        let (read, undefined) = check_step(code, &a, &b);
        assert!(!undefined);
        assert_eq!(read.unwrap().0, INPUT);
        assert_eq!(
            read.unwrap().1,
            match code {
                [0x0f, 0xb6, _] => 1,
                [0x0f, 0xb7, _] => 2,
                [0x8b, _] => 4,
                _ => 8,
            }
        );
    }
    let code = [0x48, 0x8d, 0x47, 0x08]; // lea rax,[rdi+8], no read
    let mut b = a.next(4);
    b.registers.rax = INPUT + 8;
    assert_eq!(check_step(&code, &a, &b), (None, false));
    let code = [0x66, 0x8d, 0x47, 0x08]; // lea ax,[rdi+8] preserves upper bits
    let mut b = a.next(4);
    b.registers.rax = 0x8877_6655_4433_2048;
    assert_eq!(check_step(&code, &a, &b), (None, false));
    let code = [0x41, 0xb8, 1, 0, 0, 0]; // mov r8d,1 clears upper half
    let mut before = a.clone();
    before.registers.r8 = u64::MAX;
    let mut after = before.next(6);
    after.registers.r8 = 1;
    check_step(&code, &before, &after);
    after.registers.r8 = 0xffff_ffff_0000_0001;
    refuses(|| {
        check_step(&code, &before, &after);
    });
    // CMP on captured input changes flags but neither register nor memory.
    let mut after = a.next(3);
    after.registers.eflags = 0x246;
    assert_eq!(
        check_step(&[0x80, 0x3f, 0x30], &a, &after),
        (Some((INPUT, 1)), false)
    );
    // Scaled-index + signed displacement uses 64-bit hardware address math.
    let mut before = a.clone();
    before.registers.rcx = 2;
    let mut after = before.next(5);
    after.registers.rax = 0x30;
    assert_eq!(
        check_step(&[0x0f, 0xb6, 0x44, 0x4f, 0xfc], &before, &after),
        (Some((INPUT, 1)), false)
    );
    // Width-specific ADD carry/zero/AF and signed overflow; values and flags
    // are hand-written, not produced by arithmetic() or effect().
    for (code, start, result, flags) in [
        (
            &[0x04, 1][..],
            0x1122_3344_5566_77ff,
            0x1122_3344_5566_7700,
            0x257,
        ),
        (
            &[0x66, 0x83, 0xc0, 1][..],
            0x1122_3344_5566_ffff,
            0x1122_3344_5566_0000,
            0x257,
        ),
        (&[0x83, 0xc0, 1][..], 0x1122_3344_ffff_ffff, 0, 0x257),
        (&[0x48, 0x83, 0xc0, 1][..], u64::MAX, 0, 0x257),
        (&[0x04, 1][..], 0x7f, 0x80, 0xa92),
        (&[0x2c, 1][..], 0, 0xff, 0x297),
        (&[0x2c, 1][..], 0x80, 0x7f, 0xa12),
        (&[0x48, 0x83, 0xc0, 0xff][..], 1, 0, 0x257),
        (&[0x66, 0x83, 0xc0, 0xff][..], 1, 0, 0x257),
    ] {
        let mut b = a.clone();
        b.registers.rax = start;
        let mut c = b.next(code.len());
        c.registers.rax = result;
        c.registers.eflags = flags;
        assert_eq!(check_step(code, &b, &c), (None, false));
        for bit in [CF, PF, AF, ZF, SF, OF, 1 << 9, 1 << 10] {
            let mut wrong = c.clone();
            wrong.registers.eflags ^= bit;
            refuses(|| {
                check_step(code, &b, &wrong);
            });
        }
    }
    for (code, start, result, flags) in [
        (&[0xfe, 0xc0][..], 0xff, 0, 0x257), // INC preserves set CF
        (&[0xfe, 0xc8][..], 0, 0xff, 0x297), // DEC preserves set CF
        (&[0x48, 0xff, 0xc0][..], u64::MAX, 0, 0x257),
    ] {
        let mut b = a.clone();
        b.registers.rax = start;
        b.registers.eflags |= CF;
        let mut c = b.next(code.len());
        c.registers.rax = result;
        c.registers.eflags = flags;
        check_step(code, &b, &c);
        let mut wrong = c.clone();
        wrong.registers.eflags ^= CF;
        refuses(|| {
            check_step(code, &b, &wrong);
        });
    }
    let mut b = a.clone();
    b.registers.rax = 0x80;
    let mut c = b.next(2);
    c.registers.eflags = 0xa12;
    check_step(&[0x3c, 1], &b, &c); // CMP changes no register
    c.registers.rax = 0x7f;
    refuses(|| {
        check_step(&[0x3c, 1], &b, &c);
    });
    for (code, start, result, flags, writes) in [
        (&[0x24, 0x0f][..], 0xf0, 0, 0x246, true),
        (&[0x0c, 1][..], 0x80, 0x81, 0x286, true),
        (&[0x34, 0xff][..], 0xff, 0, 0x246, true),
        (&[0xa8, 0x0f][..], 0xf0, 0xf0, 0x246, false),
    ] {
        let mut b = a.clone();
        b.registers.rax = start;
        b.registers.eflags |= CF | OF;
        let mut c = b.next(code.len());
        c.registers.rax = result;
        c.registers.eflags = flags;
        assert_eq!(check_step(code, &b, &c), (None, true));
        c.registers.eflags ^= AF; // only independent logical prediction leaves AF unspecified
        check_step(code, &b, &c);
        for bit in [CF, PF, ZF, SF, OF, 1 << 9] {
            let mut wrong = c.clone();
            wrong.registers.eflags ^= bit;
            refuses(|| {
                check_step(code, &b, &wrong);
            });
        }
        if !writes {
            let mut wrong = c.clone();
            wrong.registers.rax = 0;
            refuses(|| {
                check_step(code, &b, &wrong);
            });
        }
    }
    // Both outcomes of every Jcc, using independent minimal flag fixtures.
    let taken = [OF, 0, CF, 0, ZF, 0, CF, 0, SF, 0, PF, 0, SF, 0, ZF, 0];
    let not_taken = [0, OF, 0, CF, 0, ZF, 0, CF, 0, SF, 0, PF, 0, SF, 0, ZF];
    for n in 0..16 {
        for (flags, yes) in [(taken[n], true), (not_taken[n], false)] {
            let mut b = a.clone();
            b.registers.eflags = 0x202 | flags;
            for code in [
                vec![0x70 + n as u8, 5],
                vec![0x0f, 0x80 + n as u8, 5, 0, 0, 0],
            ] {
                let mut c = b.next(code.len());
                if yes {
                    c.registers.rip += 5;
                }
                assert_eq!(check_step(&code, &b, &c), (None, false));
                let mut wrong = c.clone();
                wrong.registers.rip ^= 1;
                refuses(|| {
                    check_step(&code, &b, &wrong);
                });
            }
        }
    }
    for code in [&[0xeb, 5][..], &[0xe9, 5, 0, 0, 0][..]] {
        let mut b = a.next(code.len());
        b.registers.rip += 5;
        check_step(code, &a, &b);
    }
    let nop = a.next(1);
    check_step(&[0x90], &a, &nop);
    // Decoder coverage includes an unreachable admitted NOP, while the
    // complete reachable graph contains both conditional successors.
    let plan = Plan::decode(&[0x31, 0xc0, 0x74, 3, 0x90, 0xeb, 1, 0x90, 0xc3]);
    assert_eq!(plan.heads(), [0, 2, 4, 5, 7, 8]);
    assert_eq!(plan.declared().heads, BTreeSet::from([0, 2, 4, 5, 7, 8]));
    assert_eq!(
        plan.declared().edges,
        BTreeSet::from([(0, 2), (2, 4), (2, 7), (4, 5), (5, 8), (7, 8)])
    );
    let padded = Plan::decode(&[0x31, 0xc0, 0xeb, 1, 0x90, 0xc3]);
    assert_eq!(padded.padding(), &BTreeSet::from([4]));
    assert_eq!(padded.declared().heads, BTreeSet::from([0, 2, 5]));
}

#[test]
fn leaf_set_scanner_refuses_unsupported_and_out_of_bounds_effects() {
    // Each body ends with C3; refusal is on the actual unsupported form.
    for raw in [
        vec![0x11, 0xc0],             // ADC
        vec![0x19, 0xc0],             // SBB
        vec![0x0f, 0x94, 0xc0],       // SETE
        vec![0x0f, 0x44, 0xc1],       // CMOVE
        vec![0x66, 0x0f, 0xef, 0xc0], // vector
        vec![0x89, 0x07],             // store
        vec![0x01, 0x07],             // read/modify/write
        vec![0x8b, 0x04, 0x24],       // stack load
        vec![0x8b, 0x03],             // callee-saved address
        vec![0x8b, 0x05, 0, 0, 0, 0], // RIP-relative
        vec![0x89, 0xc3],             // callee-saved destination
        vec![0xb7, 0],                // BH
        vec![0x48, 0x89, 0xc4],       // RSP destination
        vec![0x67, 0x8b, 0x07],       // address-size prefix
        vec![0x66, 0x66, 0x89, 0xc0], // redundant prefix
        vec![0x48, 0x66, 0x89, 0xc0], // prefix order
        vec![0x40, 0x40, 0x89, 0xc0], // redundant REX
        vec![0xf3, 0x90],             // REP/PAUSE
        vec![0x64, 0x8b, 0x07],       // segment
        vec![0xff, 0xd0],             // CALL
        vec![0xff, 0xe0],             // indirect jump
        vec![0xe2, 0xfe],             // LOOP
        vec![0xeb, 0xfe],             // self-loop
        vec![0xc2, 8, 0],             // non-C3 RET
    ] {
        let mut code = raw;
        code.extend_from_slice(&[0x90, 0x90, 0xc3]);
        refuses(|| {
            Plan::decode(&code);
        });
    }
    refuses(|| {
        Plan::decode(&[0x90, 0x90, 0x90, 0xc3]);
    });
    refuses(|| {
        Plan::decode(&[0x90; 257]);
    });
    refuses(|| {
        Plan::decode(&[0x31, 0xc0, 0x90, 0x90, 0x90]);
    }); // fallthrough
    refuses(|| {
        Plan::decode(&[0xeb, 1, 0x31, 0xc0, 0xc3]);
    }); // middle-of-instruction
    refuses(|| {
        Plan::decode(&[0xeb, 2, 0x31, 0xc0, 0xc3]);
    }); // skipped non-NOP
    refuses(|| {
        Plan::decode(&[0xeb, 2, 0x90, 0x90, 0xeb, 0xfa]);
    }); // no reachable RET
    refuses(|| {
        Plan::decode(&[
            0x74, 7, 0x74, 6, 0x74, 5, 0x74, 4, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
        ]);
    }); // five reachable RETs
    let mut blocks = vec![0x31, 0xc0];
    for _ in 0..33 {
        blocks.extend_from_slice(&[0x74, 0]);
    }
    blocks.push(0xc3);
    refuses(|| {
        Plan::decode(&blocks);
    }); // complete graph exceeds32 blocks
    let (code, points) = one_read();
    let mut empty = points.clone();
    for p in &mut empty {
        p.registers.rsi = 0;
        p.data[64..128].copy_from_slice(&Case::new(0).input());
    }
    empty[1].registers.rax = 0xa7;
    refuses(|| {
        trace(Case::new(0), &code, &empty);
    }); // no read is legal at bound0
    // Every data/stack/XSAVE byte is compared, including guards and tail.
    for area in 0..3 {
        let length = [
            points[1].data.len(),
            points[1].stack.len(),
            points[1].xstate.len(),
        ][area];
        for at in 0..length {
            let mut wrong = points.clone();
            match area {
                0 => wrong[1].data[at] ^= 1,
                1 => wrong[1].stack[at] ^= 1,
                _ => wrong[1].xstate[at] ^= 1,
            }
            refuses(|| {
                trace(Case::new(3), &code, &wrong);
            });
        }
    }
    macro_rules! wrong_registers { ($($field:ident),+ $(,)?) => { $( {
        let mut wrong = points.clone(); wrong[1].registers.$field ^= 1;
        refuses(|| { trace(Case::new(3), &code, &wrong); });
    } )+ }; }
    wrong_registers!(
        rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15, rip,
        orig_rax, cs, ss, ds, es, fs, gs, fs_base, gs_base, eflags
    );
    for field in 0..3 {
        let mut wrong = points.clone();
        match field {
            0 => wrong[3].registers.rsp -= 8,
            1 => wrong[3].registers.rip ^= 1,
            _ => wrong[3].registers.rax = 1,
        }
        refuses(|| {
            trace(Case::new(3), &code, &wrong);
        });
    }
    refuses(|| {
        trace(Case::new(3), &code, &points[..3]);
    }); // missing actual RET
    let mut extra = points.clone();
    extra.push(points.last().unwrap().clone());
    refuses(|| {
        trace(Case::new(3), &code, &extra);
    });
    let mut wrong = points.clone();
    for p in &mut wrong {
        p.stack[248] ^= 1;
    }
    refuses(|| {
        trace(Case::new(3), &code, &wrong);
    });
    let mut wrong = points.clone();
    for p in &mut wrong {
        p.data[127] ^= 1;
    }
    refuses(|| {
        trace(Case::new(3), &code, &wrong);
    }); // coherent wrong input guard
    let mut wrong = points.clone();
    for p in &mut wrong {
        p.registers.rsi = 2;
    }
    refuses(|| {
        trace(Case::new(3), &code, &wrong);
    });
    // A correct scalar without any input read cannot satisfy coverage.
    let no_read = [0x31, 0xc0, 0x90, 0x90, 0xc3];
    let a = Point::new(Case::new(3));
    let mut b = a.next(2);
    b.registers.rax = 0;
    b.registers.eflags = 0x246;
    let c = b.next(1);
    let d = c.next(1);
    let mut e = d.clone();
    e.registers.rip = CONTINUATION;
    e.registers.rsp += 8;
    refuses(|| {
        trace(Case::new(3), &no_read, &[a, b, c, d, e]);
    });
    // Actual range check: one-past, underflow and an overflowing read end.
    for address in [INPUT + 64, INPUT - 1, u64::MAX] {
        let mut a = Point::new(Case::new(7));
        a.registers.rdi = address;
        let mut b = a.next(3);
        b.registers.rax = 0;
        refuses(|| {
            check_step(&[0x0f, 0xb6, 0x07], &a, &b);
        });
    }
    let mut a = Point::new(Case::new(7));
    a.registers.rdi = INPUT + 63;
    let mut b = a.next(3);
    b.registers.rax = 0;
    refuses(|| {
        check_step(&[0x48, 0x8b, 0x07], &a, &b);
    });
    // Adjacent windows must share full state, even when each local effect is
    // valid in isolation. This changes a preserved register only at a join.
    let mut separate = points[1].clone();
    separate.registers.r12 ^= 1;
    let mut next = points[2].clone();
    next.registers.r12 ^= 1;
    let mut last = points[3].clone();
    last.registers.r12 ^= 1;
    let steps = [
        Step {
            before: points[0].view(),
            after: points[1].view(),
        },
        Step {
            before: separate.view(),
            after: next.view(),
        },
        Step {
            before: next.view(),
            after: last.view(),
        },
    ];
    refuses(|| {
        inspect(
            Operation::Digits,
            Case::new(3),
            &Plan::decode(&code),
            Observation {
                entry: ENTRY,
                continuation: CONTINUATION,
                input_address: INPUT,
                data_address: DATA,
                stack_address: STACK,
                code: &code,
                input: b"/",
                steps: &steps,
            },
        );
    });
}

fn repeated_read() -> (Vec<u8>, Vec<Point>) {
    // xor eax,eax; mov ecx,2; load byte; dec ecx; jne load; ret.
    // Both visits read '/' and leave the independently known digit count zero.
    let code = vec![
        0x31, 0xc0, 0xb9, 2, 0, 0, 0, 0x0f, 0xb6, 0x17, 0xff, 0xc9, 0x75, 0xf9, 0xc3,
    ];
    let a = Point::new(Case::new(3));
    let mut b = a.next(2);
    b.registers.rax = 0;
    b.registers.eflags = 0x246;
    let mut c = b.next(5);
    c.registers.rcx = 2;
    let mut d = c.next(3);
    d.registers.rdx = 0x2f;
    let mut e = d.next(2);
    e.registers.rcx = 1;
    e.registers.eflags = 0x202;
    let mut f = e.clone();
    f.registers.rip = ENTRY + 7;
    let g = f.next(3);
    let mut h = g.next(2);
    h.registers.rcx = 0;
    h.registers.eflags = 0x246;
    let i = h.next(2);
    let mut j = i.clone();
    j.registers.rip = CONTINUATION;
    j.registers.rsp += 8;
    (code, vec![a, b, c, d, e, f, g, h, i, j])
}

#[test]
fn leaf_set_scanner_cache_matches_direct_decode_at_each_runtime_base() {
    let (code, _) = repeated_read();
    let plan = Plan::decode(&code);
    for entry in [ENTRY, ENTRY + 0x1_0000_0000] {
        let mut cached = Decoded::new(&plan, entry);
        for _ in 0..3 {
            for &pc in &plan.declared().heads {
                let mut decoder =
                    Decoder::with_ip(64, &code[pc as usize..], entry + pc, DecoderOptions::NONE);
                let direct = decoder.decode();
                let kind = validate(&direct, &code[pc as usize..pc as usize + direct.len()]);
                let (instruction, actual_kind) = cached.get(pc);
                assert_eq!(instruction, &direct);
                assert_eq!(*actual_kind, kind);
                assert_eq!(instruction.ip(), entry + pc);
            }
        }
        assert_eq!(cached.instructions.len(), plan.declared().heads.len());
        for pc in 0..=code.len() as u64 {
            if !plan.declared().heads.contains(&pc) {
                refuses(|| {
                    cached.get(pc);
                });
            }
        }
    }
    refuses(|| {
        Decoded::new(&plan, u64::MAX - 1);
    });
    let mut altered = code.clone();
    altered[7..10].copy_from_slice(&[0x0f, 0xb6, 0x0f]);
    let changed = Plan::decode(&altered);
    let mut a = Decoded::new(&plan, ENTRY);
    let mut b = Decoded::new(&changed, ENTRY);
    assert_ne!(a.get(7).0.op_register(0), b.get(7).0.op_register(0));
}

#[test]
fn leaf_set_scanner_cached_visits_recheck_all_dynamic_state() {
    let (code, points) = repeated_read();
    let result = trace(Case::new(3), &code, &points);
    assert_eq!(
        (
            result.visits(),
            result.effects_checked(),
            result.input_reads(),
            result.input_bytes()
        ),
        (9, 9, 2, 2)
    );
    assert_eq!(
        result
            .reads()
            .iter()
            .map(|r| (r.at, r.address, r.width))
            .collect::<Vec<_>>(),
        vec![(7, INPUT, 1), (7, INPUT, 1)]
    );
    assert_eq!(result.value(), 0);
    assert_eq!(result.observed(), result.declared());
    for which in 0..9 {
        let mut bad = points.clone();
        match which {
            0 => bad[6].registers.rdx ^= 1,
            1 => bad[6].registers.eflags ^= CF,
            2 => bad[6].xstate[1000] ^= 1,
            3 => bad[6].data[4095] ^= 1,
            4 => bad[6].stack[0] ^= 1,
            5 => bad[5].registers.rdi = INPUT + 1,
            6 => bad[8].registers.rip = ENTRY + 7,
            7 => {
                for p in &mut bad {
                    p.stack[248] ^= 1;
                }
            }
            _ => {
                for p in &mut bad {
                    p.data[64] = b'z';
                }
            }
        }
        refuses(|| {
            trace(Case::new(3), &code, &bad);
        });
    }
    // Invoke a reused descriptor directly with coherent before/after addresses,
    // so the failure is the actual per-visit complete-read bound, not adjacency.
    let plan = Plan::decode(&code);
    let mut cache = Decoded::new(&plan, ENTRY);
    let _ = cache.get(7);
    let (instruction, kind) = cache.get(7);
    for address in [INPUT - 1, INPUT + 1, u64::MAX] {
        let mut before = points[5].clone();
        before.registers.rdi = address;
        let mut after = points[6].clone();
        after.registers.rdi = address;
        refuses(|| {
            effect(
                instruction,
                *kind,
                Step {
                    before: before.view(),
                    after: after.view(),
                },
                Domain {
                    input: INPUT,
                    bound: 1,
                    data: DATA,
                    stack: STACK,
                    continuation: CONTINUATION,
                },
            );
        });
    }
}
