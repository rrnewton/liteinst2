//! Exact positive fixture descriptions and checks shared by correctness and cost runs.
use super::*;

pub(super) struct Case {
    pub(super) id: &'static str,
    pub(super) fixture: Fixture,
    pub(super) replies: Vec<Reply>,
    pub(super) covered: bool,
    pub(super) collateral: usize,
    marks: [u64; 2],
    check: fn(&Case, &Trace),
}
impl Case {
    pub(super) fn check_trace(&self, trace: &Trace) {
        assert_eq!(trace.rows.len(), self.replies.len(), "fixture {}", self.id);
        (self.check)(self, trace);
    }
}

pub(super) fn masked() -> Case {
    let mut b = Builder::new(2);
    let first = b.emit(&[0x0f, 0xa2]);
    b.store(1, 0);
    b.mov(0, 7);
    b.mov(1, 0);
    b.emit(&[0x0f, 0xa2]);
    b.store(3, 1);
    b.emit(&[0x0f, 0xc7, 0xf0]);
    b.store(0, 2);
    b.emit(&[0x0f, 0xc7, 0xfa]);
    let f = b.finish();
    Case {
        id: "masked_cpuid_random",
        fixture: f,
        replies: vec![
            Reply::Cpuid([0, 0, 0, 0]),
            Reply::Cpuid([0, 0, 0, 0]),
            Reply::Rdrand {
                value: 0x9988_7766,
                carry: true,
            },
            Reply::Rdseed {
                value: 0,
                carry: false,
            },
        ],
        covered: false,
        collateral: 0,
        marks: [first, 0],
        check: check_masked,
    }
}
fn check_masked(case: &Case, trace: &Trace) {
    let first = case.marks[0];
    assert_eq!(trace.rows.len(), 4);
    assert_eq!(trace.rows[0].before.registers.rip, first);
    assert_eq!(trace.rows[0].before.registers.rax as u32, 1);
    assert_eq!(trace.rows[0].after.registers.rcx & (1 << 30), 0);
    assert_eq!(trace.rows[1].before.registers.rax, 7);
    assert_eq!(trace.rows[1].before.registers.rcx, 0);
    assert_eq!(trace.rows[1].after.registers.rbx & (1 << 18), 0);
    assert_eq!(trace.rows[2].selected.class(), SiteClass::Rdrand);
    assert_eq!(trace.rows[3].selected.class(), SiteClass::Rdseed);
}

pub(super) fn timestamps() -> Case {
    let mut b = Builder::new(2);
    b.emit(&[0x0f, 0x31]);
    b.store(0, 0);
    b.store(2, 1);
    b.mov(0, 0x9988_7766_5544_3322);
    b.mov(1, 0x1234_5678_9abc_def0);
    b.mov(2, 0xffee_ddcc_bbaa_9988);
    b.emit(&[0x0f, 0x01, 0xf9]);
    b.store(1, 2);
    b.emit(&[0xf3, 0x41, 0x0f, 0xc7, 0xf9]);
    b.store(9, 3);
    b.mov(0, 39);
    b.emit(&[0x0f, 0x05]);
    let f = b.finish();
    Case {
        id: "timestamps_processor_syscall",
        fixture: f,
        replies: vec![
            Reply::Rdtsc(0x8877_6655_4433_2211),
            Reply::Rdtscp(0x1234_5678_9abc_def0, 0xabba_cafe),
            Reply::Rdpid(0xface_babe),
            Reply::GetId(173),
        ],
        covered: true,
        collateral: 0,
        marks: [0, 0],
        check: check_timestamps,
    }
}
fn check_timestamps(case: &Case, trace: &Trace) {
    let _ = case;
    assert_eq!(
        trace
            .rows
            .iter()
            .map(|r| r.selected.class())
            .collect::<Vec<_>>(),
        [
            SiteClass::Rdtsc,
            SiteClass::Rdtscp,
            SiteClass::Rdpid,
            SiteClass::Syscall
        ]
    );
    let syscall = trace.rows.last().unwrap();
    assert_eq!(
        syscall.after.registers.rcx,
        syscall.before.registers.rip + 2
    );
    assert_eq!(syscall.after.registers.r11, FLAGS);
    assert_eq!(syscall.after.registers.orig_rax, u64::MAX);
}

pub(super) fn prefixed() -> Case {
    // Width/high-register representatives, followed by an explicit suffix entry.
    let mut b = Builder::new(2);
    b.emit(&[0x66, 0x41, 0x0f, 0xc7, 0xf1]);
    b.store(9, 0);
    b.emit(&[0x48, 0x0f, 0xc7, 0xfb]);
    b.store(3, 1);
    let rdpid = b.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    b.heads.insert(rdpid + 1);
    b.branch(0xe9, rdpid + 1);
    let f = b.finish();
    Case {
        id: "prefixed_suffix",
        fixture: f,
        replies: vec![
            Reply::Rdrand {
                value: 0xbeef,
                carry: true,
            },
            Reply::Rdseed {
                value: 0,
                carry: false,
            },
            Reply::Rdpid(0xaabb_ccdd),
            Reply::Rdseed {
                value: 0x1234_5678,
                carry: true,
            },
        ],
        covered: true,
        collateral: 0,
        marks: [rdpid, 0],
        check: check_prefixed,
    }
}
fn check_prefixed(case: &Case, trace: &Trace) {
    let rdpid = case.marks[0];
    assert_eq!(
        trace.rows[0].after.registers.r9 & !0xffff,
        image::seed(9) & !0xffff
    );
    assert_eq!(trace.rows[3].before.registers.rip, rdpid + 1);
    assert_eq!(trace.rows[3].bytes, [0x0f, 0xc7, 0xfa]);
}

pub(super) fn embedded() -> Case {
    // A collateral MOV contains RDSEED in its immediate. It must execute as MOV
    // with zero callback first, and later dispatch only on an actual alternate
    // entry. Both trajectories use exactly the same immutable original bytes.
    let mut b = Builder::new(2);
    let mov = b.pc();
    b.mov(3, 0x9090_9090_f8c7_0f90);
    b.store(3, 0);
    b.emit(&[0x0f, 0x31]);
    b.heads
        .extend([mov + 3, mov + 6, mov + 7, mov + 8, mov + 9]);
    b.branch(0xe9, mov + 3);
    let f = b.finish();
    Case {
        id: "embedded_alternate",
        fixture: f,
        replies: vec![
            Reply::Rdtsc(0x1122_3344_5566_7788),
            Reply::Rdseed {
                value: 0xfedc_ba98,
                carry: true,
            },
            Reply::Rdtsc(0x8877_6655_4433_2211),
        ],
        covered: true,
        collateral: 1,
        marks: [mov, 0],
        check: check_embedded,
    }
}
fn check_embedded(case: &Case, trace: &Trace) {
    let mov = case.marks[0];
    assert_eq!(
        trace
            .rows
            .iter()
            .map(|r| r.selected.class())
            .collect::<Vec<_>>(),
        [SiteClass::Rdtsc, SiteClass::Rdseed, SiteClass::Rdtsc]
    );
    assert_eq!(trace.rows[0].before.registers.rbx, 0x9090_9090_f8c7_0f90);
    assert!(trace.ordinary.iter().any(|(pc, _)| *pc == mov));
}

pub(super) fn cross_page() -> Case {
    let mut b = Builder::new(4);
    let call = BASE + 2 * PAGE as u64 - 5;
    b.branch(0xe9, call);
    b.cursor = 2 * PAGE - 5;
    b.branch(0xe8, BASE + 3 * PAGE as u64);
    let returned = b.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    b.store(2, 0);
    b.emit(&[0x0f, 0x31]);
    let end = b.cursor;
    b.cursor = 3 * PAGE;
    b.emit(&[0xc3]);
    b.cursor = end;
    let f = b.finish();
    Case {
        id: "cross_page_call",
        fixture: f,
        replies: vec![
            Reply::Rdpid(0x1234_5678),
            Reply::Rdtsc(0x9988_7766_5544_3322),
        ],
        covered: true,
        collateral: 0,
        marks: [call, returned],
        check: check_cross_page,
    }
}
fn check_cross_page(case: &Case, trace: &Trace) {
    let [call, returned] = case.marks;
    let f = &case.fixture;
    assert_eq!(returned, BASE + 2 * PAGE as u64);
    assert_eq!(trace.rows[0].before.registers.rsp, STACK);
    let slot = (STACK - 8 - DATA) as usize;
    assert_eq!(
        &trace.rows[0].before.data[slot..slot + 8],
        &returned.to_le_bytes()
    );
    assert!(trace.ordinary.iter().any(|(pc, _)| *pc == call));
    assert!(
        trace
            .ordinary
            .iter()
            .any(|(pc, _)| *pc == BASE + 3 * PAGE as u64)
    );
    assert_eq!(
        trace.blocks,
        [f.marker + 1, call, BASE + 3 * PAGE as u64, returned]
    );
}
