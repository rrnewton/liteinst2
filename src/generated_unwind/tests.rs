use super::*;
use crate::scanner::InstructionScanner;
use crate::trampoline::{HookContext, TrampolinePlan};
use std::collections::BTreeMap;

fn record(body: &[u8]) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}
fn source(frame_pointer: bool) -> OriginalCfi {
    let mut cie = vec![
        0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0, 0x0c, 7, 8, 0x90, 1,
    ];
    for reg in [3, 6, 12, 13, 14, 15] {
        cie.extend_from_slice(&[8, reg]);
    }
    let cie_address = 0x4000_u64;
    let fde_address = 0x5000_u64;
    let mut fde = ((fde_address + 4 - cie_address) as u32)
        .to_le_bytes()
        .to_vec();
    fde.extend_from_slice(&0x1000_u64.to_le_bytes());
    fde.extend_from_slice(&64_u64.to_le_bytes());
    fde.push(0);
    if frame_pointer {
        fde.extend_from_slice(&[0x41, 0x0c, 7, 16, 0x86, 2, 0x43, 0x0d, 6, 0x41, 0x83, 3]);
    } else {
        fde.extend_from_slice(&[0x41, 0x0e, 16, 0x83, 2, 0x44, 0x0e, 48]);
    }
    OriginalCfi {
        cie_address,
        cie: record(&cie),
        fde_address,
        fde: record(&fde),
    }
}
fn parse(record: &OriginalCfi) -> Result<parser::Rows, Refusal> {
    parser::parse(
        record.cie_address,
        &record.cie,
        record.fde_address,
        &record.fde,
        Limits::default(),
    )
}

#[test]
fn original_rows_preserve_exact_caller_slots() {
    for fp in [false, true] {
        let rows = parse(&source(fp)).unwrap();
        let selected = rows.at(0x1013).unwrap();
        assert_eq!(selected.cfa, Some(if fp { (6, 16) } else { (7, 48) }));
        assert_eq!(
            selected.registers[3],
            parser::Rule::Offset(if fp { -24 } else { -16 })
        );
        assert_eq!(
            selected.registers[6],
            if fp {
                parser::Rule::Offset(-16)
            } else {
                parser::Rule::Same
            }
        );
        assert_eq!(selected.registers[16], parser::Rule::Offset(-8));
        assert!(rows.at(0x0fff).is_err());
        assert!(rows.at(0x1040).is_err());
    }
}

#[test]
fn malformed_and_unmodelled_source_records_refuse() {
    let good = source(false);
    let mutations: Vec<OriginalCfi> = vec![
        {
            let mut x = good.clone();
            x.cie[8] = 3;
            x
        },
        {
            let mut x = good.clone();
            x.cie[14] = 15;
            x
        },
        {
            let mut x = good.clone();
            x.cie[12] = 2;
            x
        },
        {
            let mut x = good.clone();
            x.cie[13] = 0x79;
            x
        },
        {
            let mut x = good.clone();
            x.cie[10] = b'P';
            x
        },
        {
            let mut x = good.clone();
            x.fde[4] ^= 1;
            x
        },
        {
            let mut x = good.clone();
            x.fde[16..24].fill(0);
            x
        },
        {
            let mut x = good.clone();
            x.fde[8..16].fill(0xff);
            x
        },
        {
            let mut x = good.clone();
            x.fde.push(0);
            x
        },
        {
            let mut x = good.clone();
            x.cie.truncate(5);
            x
        },
    ];
    assert_eq!(mutations.len(), 10);
    for record in mutations {
        assert!(parse(&record).is_err());
    }
    for instructions in [
        vec![0x0f, 1, 0],
        vec![0x0b],
        vec![0x0c, 0, 8],
        vec![4, 0xff, 0xff, 0xff, 0xff],
        vec![0x0a; 9],
        vec![
            5, 3, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ],
    ] {
        let mut changed = good.clone();
        changed.fde.truncate(25);
        changed.fde.extend(instructions);
        let length = (changed.fde.len() - 4) as u32;
        changed.fde[..4].copy_from_slice(&length.to_le_bytes());
        assert!(parse(&changed).is_err());
    }
}

// Independent evaluator for the small GENERATED expression grammar. This
// interprets encoded bytes, never calls the production composition functions.
fn signed(bytes: &[u8], at: &mut usize) -> i64 {
    let mut value = 0_u64;
    let mut shift = 0;
    loop {
        let b = bytes[*at];
        *at += 1;
        value |= u64::from(b & 127) << shift;
        shift += 7;
        if b & 128 == 0 {
            if shift < 64 && b & 64 != 0 {
                value |= !0_u64 << shift;
            }
            return value as i64;
        }
        assert!(shift < 64);
    }
}
fn unsigned(bytes: &[u8], at: &mut usize) -> usize {
    let mut value = 0;
    let mut shift = 0;
    loop {
        let b = bytes[*at];
        *at += 1;
        value |= usize::from(b & 127) << shift;
        shift += 7;
        if b & 128 == 0 {
            return value;
        }
        assert!(shift < 64);
    }
}
fn expression(bytes: &[u8], regs: &[u64; 16], memory: &BTreeMap<u64, u64>) -> u64 {
    let mut at = 0;
    let mut stack = Vec::new();
    while at < bytes.len() {
        let opcode = bytes[at];
        at += 1;
        match opcode {
            0x70..=0x7f => {
                let offset = signed(bytes, &mut at);
                stack.push(regs[usize::from(opcode - 0x70)].wrapping_add_signed(offset));
            }
            6 => {
                let address = stack.pop().unwrap();
                stack.push(memory[&address]);
            }
            0x11 => stack.push(signed(bytes, &mut at) as u64),
            0x22 => {
                let right = stack.pop().unwrap();
                let left = stack.pop().unwrap();
                stack.push(left.wrapping_add(right));
            }
            _ => panic!("unknown generated expression opcode"),
        }
    }
    assert_eq!(stack.len(), 1);
    stack[0]
}
fn interpret(
    bytes: &[u8],
    regs: &[u64; 16],
    memory: &BTreeMap<u64, u64>,
) -> (u64, BTreeMap<usize, u64>) {
    let mut at = 0;
    assert_eq!(bytes[at], 0x0f);
    at += 1;
    let n = unsigned(bytes, &mut at);
    let cfa = expression(&bytes[at..at + n], regs, memory);
    at += n;
    let mut recovered = BTreeMap::new();
    while at < bytes.len() {
        let op = bytes[at];
        at += 1;
        let reg = unsigned(bytes, &mut at);
        let value = match op {
            8 => regs[reg],
            9 => regs[unsigned(bytes, &mut at)],
            0x11 => {
                let offset = signed(bytes, &mut at) * -8;
                memory[&cfa.wrapping_add_signed(offset)]
            }
            0x10 | 0x16 => {
                let n = unsigned(bytes, &mut at);
                let value = expression(&bytes[at..at + n], regs, memory);
                at += n;
                if op == 0x10 { memory[&value] } else { value }
            }
            _ => panic!("unknown generated rule"),
        };
        assert!(recovered.insert(reg, value).is_none());
    }
    (cfa, recovered)
}
unsafe extern "C" fn hook(_: *mut HookContext) {}

#[test]
fn real_stable_ledger_composes_caller_memory_not_context_values() {
    let scan = InstructionScanner::default()
        .scan(&[0x0f, 0x1f, 0x44, 0, 0], 0x1000)
        .unwrap();
    let plan = TrampolinePlan::from_scan(&scan, 0x1000, hook).unwrap();
    let emitted = plan.emit_with_frame_trace_at(0x2000_0000).unwrap();
    let trace = emitted.trace().unwrap();
    let call = trace.calls()[0];
    let row = trace
        .instructions()
        .iter()
        .find(|row| row.start() == call.call_pc())
        .unwrap();
    let FrameInstructionKind::Helper(helper) = row.kind() else {
        panic!("missing actual helper")
    };
    assert_eq!(helper.before().original_rsp_rule(), (Register::R12, 304));
    for fp in [false, true] {
        let source = parse(&source(fp)).unwrap();
        let original = source.at(0x1013).unwrap();
        let composed = cfi::compose(
            row.start(),
            row.end(),
            original,
            Some(helper.before()),
            Limits::default(),
        )
        .unwrap();
        let r = 0x100000_u64;
        let c = r - 304;
        let mut regs = [0_u64; 16];
        regs[12] = c;
        let mut memory = BTreeMap::new();
        let mut expected = BTreeMap::new();
        for (reg, offset) in [(3, 104), (6, 96), (12, 40), (13, 32), (14, 24), (15, 16)] {
            let value = 0xabc0_0000 + reg as u64;
            memory.insert(c + offset, value);
            expected.insert(reg, value);
        }
        memory.insert(c + 104, 0x5a637c91e2d4b608); // application RBX differs from caller RBX
        memory.insert(r + if fp { 24 } else { 32 }, expected[&3]);
        if fp {
            memory.insert(c + 96, r + 32);
            memory.insert(r + 32, expected[&6]);
        }
        memory.insert(r + 40, 0x7777_1234);
        expected.insert(16, 0x7777_1234);
        let (cfa, recovered) = interpret(&composed.instructions, &regs, &memory);
        assert_eq!(cfa, r + 48);
        assert_eq!(recovered, expected);
        assert_ne!(recovered[&3], memory[&(c + 104)]);
        if fp {
            assert_ne!(recovered[&6], memory[&(c + 96)]);
        }
        let wrong_cfa = cfa + 8;
        assert_ne!(wrong_cfa, cfa);
    }
}

#[test]
fn expression_and_record_limits_remain_required_refusals() {
    let parsed = parse(&source(false)).unwrap();
    let row = parsed.at(0x1013).unwrap();
    assert_eq!(
        cfi::compose(
            1,
            2,
            row,
            None,
            Limits {
                expression_bytes: 0,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Refusal::Limit
    );
    let good = cfi::compose(1, 2, row, None, Limits::default()).unwrap();
    assert_eq!(
        cfi::encode(
            core::slice::from_ref(&good),
            Limits {
                fdes: 0,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Refusal::Limit
    );
    assert_eq!(
        cfi::encode(
            core::slice::from_ref(&good),
            Limits {
                metadata_bytes: 0,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Refusal::Limit
    );
    assert_eq!(
        cfi::encode(
            core::slice::from_ref(&good),
            Limits {
                rows: 0,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Refusal::Limit
    );
    let mut bad = row.clone();
    bad.cfa = None;
    assert_eq!(
        cfi::compose(1, 2, &bad, None, Limits::default()).unwrap_err(),
        Refusal::CallerRule
    );
    let mut bad = row.clone();
    bad.registers[16] = parser::Rule::Same;
    assert_eq!(
        cfi::compose(1, 2, &bad, None, Limits::default()).unwrap_err(),
        Refusal::CallerRule
    );
    let mut bad = row.clone();
    bad.registers[3] = parser::Rule::Undefined;
    assert_eq!(
        cfi::compose(1, 2, &bad, None, Limits::default()).unwrap_err(),
        Refusal::CallerRule
    );
    let mut bad = row.clone();
    bad.registers[3] = parser::Rule::Offset(-9);
    assert_eq!(
        cfi::compose(1, 2, &bad, None, Limits::default()).unwrap_err(),
        Refusal::CallerRule
    );
}

struct ModelOwner;
unsafe impl SourceOwner for ModelOwner {
    fn revalidate(&self) -> Result<(), Refusal> {
        Ok(())
    }
}
fn model_certificate() -> Arc<SourceCertificate> {
    // Private model construction grants no public SourceCertificate authority.
    // The public unsafe certificate is exercised only against actual ELF bytes.
    let records = vec![source(false)];
    let rows = vec![parse(&records[0]).unwrap()];
    Arc::new(SourceCertificate {
        identity: CodeIdentity {
            source: crate::contracts::SourceIdentity([0x73; 32]),
            mapping: 0x1000,
            generation: 1,
        },
        points: vec![0x1013],
        rows,
        _records: records,
        owner: Arc::new(ModelOwner),
    })
}
#[test]
fn interval_coverage_does_not_replace_exact_point_authority() {
    let certificate = model_certificate();
    assert!(certificate.row(0x1013).is_ok());
    assert_eq!(certificate.row(0x1014).unwrap_err(), Refusal::SourcePoint);
    assert_eq!(certificate.row(0x0fff).unwrap_err(), Refusal::SourcePoint);
    assert_eq!(certificate.row(0x1040).unwrap_err(), Refusal::SourcePoint);
}

#[test]
fn void_registration_lookup_failure_retains_exact_metadata_and_source() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static REGISTERED: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn register(pointer: *const u8) {
        assert_ne!(pointer, std::ptr::null());
        REGISTERED.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn absent(_: u64) -> *const u8 {
        std::ptr::null()
    }
    assert_eq!(REGISTERED.load(Ordering::SeqCst), 0);
    let source = model_certificate();
    let weak = Arc::downgrade(&source);
    let memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(memory, libc::MAP_FAILED);
    unsafe {
        std::ptr::write_bytes(memory.cast::<u8>(), 0x6d, 4096);
    }
    assert_eq!(unsafe { libc::mprotect(memory, 4096, libc::PROT_READ) }, 0);
    // Model-only functions are wired directly into private fields. They are
    // deliberately NOT passed through the unsafe qualified-consumer API.
    let backend = Arc::new(Backend {
        register,
        lookup: absent,
        _owner: Arc::new(()),
    });
    let staged = StagedRegistration {
        pointer: memory.cast(),
        len: 4096,
        source,
        backend,
        fdes: vec![(0x2000, 0x2003, 0)],
        calls: vec![(0x2000, 0x2002)],
    };
    assert!(matches!(staged.commit(), Err(Refusal::RegistrationLookup)));
    assert_eq!(REGISTERED.load(Ordering::SeqCst), 1);
    assert!(weak.upgrade().is_some());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(memory.cast::<u8>(), 4096) },
        vec![0x6d; 4096]
    );
    // A real commit cannot revoke registration; this bounded model page is
    // intentionally retained too. No unmap/deregister escape is exercised.
}
