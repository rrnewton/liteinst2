use super::*;

pub fn outputs(r: RegisterSnapshot) -> [u64; 4] {
    [r.rax, r.rbx, r.rcx, r.rdx]
}
pub fn cpu(before: &Architecture, after: &Architecture) {
    assert_eq!((before.registers.rax, before.registers.rcx), (0, 0));
    let h = std::arch::x86_64::__cpuid_count(0, 0);
    let mut expected = before.clone();
    expected.registers.rax = u64::from(h.eax);
    expected.registers.rbx = u64::from(h.ebx);
    expected.registers.rcx = u64::from(h.ecx);
    expected.registers.rdx = u64::from(h.edx);
    expected.registers.rip += 2;
    assert_eq!(*after, expected);
}
pub fn seeded(a: &Architecture, pc: u64, data: u64, stack: u64) {
    let mut r: RegisterSnapshot = unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
    r.rax = 0;
    r.rcx = 0;
    r.rdx = 0x1234_5678_0000_0002;
    r.rbx = 0x1234_5678_0000_0003;
    r.rsp = stack;
    r.rbp = 0x1234_5678_0000_0005;
    r.rsi = 0x1234_5678_0000_0006;
    r.rdi = 0x1234_5678_0000_0007;
    r.r8 = 0x1234_5678_0000_0008;
    r.r9 = 0x1234_5678_0000_0009;
    r.r10 = 0x1234_5678_0000_000a;
    r.r11 = 0x1234_5678_0000_000b;
    r.r12 = 0x1234_5678_0000_000c;
    r.r13 = 0x1234_5678_0000_000d;
    r.r14 = 0x1234_5678_0000_000e;
    r.r15 = 0x1234_5678_0000_000f;
    r.orig_rax = u64::MAX;
    r.rip = pc;
    r.cs = 0x33;
    r.ss = 0x2b;
    r.eflags = FLAGS;
    assert_eq!(a.registers, r);
    assert_eq!(a.mask, APP_MASK);
    assert!(a.xstate.len() >= 512 && a.xstate.len() < 65536);
    let x = &a.xstate;
    assert_eq!(&x[..2], &0x37f_u16.to_le_bytes());
    assert_eq!(&x[2..4], &0x3800_u16.to_le_bytes());
    assert_eq!(x[4], 0x80);
    assert_eq!(&x[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(&x[32..42], &[0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]);
    assert_eq!(&x[160..176], &[0xff; 16]);
    assert!(matches!(data, OLD_DATA | NEW_DATA));
}
pub fn entry(before: &Architecture, actual: &Architecture, pc: u64) {
    assert_eq!(before.registers.rip, pc);
    assert_eq!(before.registers.rax, libc::SYS_execve as u64);
    assert_eq!(before.registers.eflags & 0x10100, 0);
    let mut expected = before.clone();
    let r = &mut expected.registers;
    r.rip = pc + 2;
    r.rcx = pc + 2;
    r.r11 = r.eflags;
    r.orig_rax = libc::SYS_execve as u64;
    r.rax = (-libc::ENOSYS as i64) as u64;
    assert_eq!(*actual, expected);
}
pub fn arguments(f: &Fixture, r: &RegisterSnapshot, maps: &Maps, bytes: &[u8]) {
    assert_eq!([r.rdi, r.rsi, r.rdx], [INPUT, f.argv, f.envp]);
    assert_eq!(bytes, f.inputs);
    let map = maps.covering(INPUT, PAGE);
    assert_eq!(
        (map.start, map.end, map.offset),
        (INPUT, INPUT + PAGE as u64, (CODE + DATA_LEN) as u64)
    );
    assert_eq!(map.permissions, "r--p");
    assert_eq!(map.path.as_deref(), f.old_path.to_str());
    assert_ne!(map.inode, 0);
    let filename = f.new_path.as_os_str().as_encoded_bytes();
    assert_eq!(&bytes[..filename.len()], filename);
    assert_eq!(bytes[filename.len()], 0);
    for (base, values) in [
        (0x200, [INPUT + 0x300, INPUT + 0x320, 0]),
        (0x220, [INPUT + 0x340, INPUT + 0x360, 0]),
    ] {
        for (i, value) in values.into_iter().enumerate() {
            assert_eq!(
                u64::from_le_bytes(bytes[base + i * 8..base + i * 8 + 8].try_into().unwrap()),
                value
            );
        }
    }
    assert_eq!(&bytes[0x300..0x30c], b"logical-new\0");
    assert_eq!(&bytes[0x320..0x331], b"payload-argument\0");
    assert_eq!(&bytes[0x340..0x34a], b"FIRST=one\0");
    assert_eq!(&bytes[0x360..0x36b], b"SECOND=two\0");
}
fn word(stack: &Stack, at: usize) -> u64 {
    u64::from_le_bytes(stack.bytes[at..at + 8].try_into().unwrap())
}
fn string(stack: &Stack, address: u64) -> &[u8] {
    let index = usize::try_from(address.checked_sub(stack.start).unwrap()).unwrap();
    let rest = &stack.bytes[index..];
    let end = rest.iter().position(|b| *b == 0).unwrap();
    &rest[..end]
}
pub fn initial_stack(f: &Fixture, stack: &Stack) {
    assert_eq!(stack.map.path.as_deref(), Some("[stack]"));
    assert_eq!(stack.map.permissions, "rw-p");
    assert!(stack.map.start <= stack.start && stack.start % 16 == 0 && stack.bytes.len() <= 65536);
    assert_eq!(
        stack.start.checked_add(stack.bytes.len() as u64),
        Some(stack.map.end)
    );
    assert_eq!(word(stack, 0), 2);
    assert_eq!(string(stack, word(stack, 8)), b"logical-new");
    assert_eq!(string(stack, word(stack, 16)), b"payload-argument");
    assert_eq!(word(stack, 24), 0);
    assert_eq!(string(stack, word(stack, 32)), b"FIRST=one");
    assert_eq!(string(stack, word(stack, 40)), b"SECOND=two");
    assert_eq!(word(stack, 48), 0);
    let mut aux = BTreeMap::new();
    let mut cursor = 56;
    loop {
        assert!(cursor < 56 + 64 * 16);
        let key = word(stack, cursor);
        let value = word(stack, cursor + 8);
        cursor += 16;
        if key == 0 {
            assert_eq!(value, 0);
            break;
        }
        assert!(aux.insert(key, value).is_none());
    }
    for (key, value) in [
        (3, NEW + 64),
        (4, 56),
        (5, 3),
        (6, PAGE as u64),
        (7, 0),
        (9, NEW + PAGE as u64),
    ] {
        assert_eq!(aux.get(&key), Some(&value));
    }
    let random = *aux.get(&25).unwrap();
    assert!(random >= stack.start && random.checked_add(16).unwrap() <= stack.map.end);
    assert_eq!(
        string(stack, *aux.get(&31).unwrap()),
        f.new_path.as_os_str().as_encoded_bytes()
    );
}
pub fn exec_registers(stack: &Stack, pc: u64) -> RegisterSnapshot {
    let mut r: RegisterSnapshot = unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
    r.rip = pc;
    r.rsp = stack.start;
    r.rax = (-libc::ENOSYS as i64) as u64;
    r.orig_rax = libc::SYS_execve as u64;
    r.cs = 0x33;
    r.ss = 0x2b;
    r.eflags = 0x202;
    r
}
pub fn new_exec(f: &Fixture, record: &raw::Record) {
    assert_eq!(
        record.status,
        (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f
    );
    assert!(
        record
            .event
            .is_some_and(|tid| tid > 0 && tid <= i32::MAX as u64)
    );
    initial_stack(f, &record.stack);
    assert_eq!(
        record.architecture.registers,
        exec_registers(&record.stack, f.first_cpu)
    );
    assert_eq!(record.architecture.mask, APP_MASK);
    assert_eq!(record.source, f.new_source);
    assert_eq!(record.data, f.new_data);
    let x = &record.architecture.xstate;
    assert!(x.len() >= 512 && x.len() < 65536);
    assert_eq!(&x[..2], &0x37f_u16.to_le_bytes());
    assert_eq!(&x[2..4], &0_u16.to_le_bytes());
    assert_eq!(x[4], 0);
    assert_eq!(&x[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(&x[160..176], &[0; 16]);
    assert!(record.maps.rows.iter().all(|m| {
        ![
            (OLD, OLD + CODE as u64),
            (OLD_DATA, OLD_DATA + DATA_LEN as u64),
            (INPUT, INPUT + PAGE as u64),
        ]
        .iter()
        .any(|&(a, b)| m.start < b && a < m.end)
    }));
    let map = record.maps.covering(NEW, CODE);
    assert_eq!(
        (map.start, map.end, map.offset),
        (NEW, NEW + CODE as u64, 0)
    );
    assert_eq!(map.permissions, "r-xp");
    assert_eq!(map.path.as_deref(), f.new_path.to_str());
    assert_ne!(map.inode, 0);
}
pub fn new_exit(exec: &raw::Record, exit: &raw::Record) {
    assert_eq!(exit.status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
    let mut expected = exec.architecture.clone();
    expected.registers.rax = 0;
    assert_eq!(exit.architecture, expected);
    assert_eq!(exit.maps, exec.maps);
    assert_eq!(exit.stack, exec.stack);
    assert_eq!(exit.source, exec.source);
    assert_eq!(exit.data, exec.data);
    let (len, info) = exit.info.as_ref().unwrap();
    assert!((33..=88).contains(len));
    assert_eq!(info[0], 2);
    assert_eq!(i64::from_ne_bytes(info[24..32].try_into().unwrap()), 0);
    assert_eq!(info[32], 0);
}
pub fn first_trap(f: &Fixture, exit: &raw::Record, trap: &raw::Record) {
    assert_eq!(trap.status, (libc::SIGTRAP << 8) | 0x7f);
    let info = trap.siginfo.as_ref().unwrap();
    assert_eq!(
        i32::from_ne_bytes(info[..4].try_into().unwrap()),
        libc::SIGTRAP
    );
    assert_eq!(
        i32::from_ne_bytes(info[8..12].try_into().unwrap()),
        libc::SI_KERNEL
    );
    let mut expected = exit.architecture.registers;
    expected.rip = f.first_cpu + 1;
    expected.orig_rax = u64::MAX;
    assert_eq!(trap.architecture.registers, expected);
    assert_eq!(trap.architecture.mask, exit.architecture.mask);
    assert_eq!(trap.maps, exit.maps);
    assert_eq!(trap.stack, exit.stack);
    assert_eq!(trap.data, exit.data);
    let mut source = f.new_source.clone();
    source[(f.first_cpu - NEW) as usize] = 0xcc;
    assert_eq!(trap.source, source);
    // The actual trap XSTATE is deliberately retained; user-return PKRU may
    // differ from the kernel EXIT image. No byte or component is normalized.
    assert!(trap.architecture.xstate.len() >= 512 && trap.architecture.xstate.len() < 65536);
}
#[cfg(test)]
pub fn execute_bit(map: &mut Map, from: bool, to: bool) {
    assert_ne!(from, to);
    let expected = if from { "r-xp" } else { "r--p" };
    let result = if to { "r-xp" } else { "r--p" };
    assert_eq!(map.permissions, expected);
    let bytes = map.line.as_bytes();
    let end = bytes.iter().position(u8::is_ascii_whitespace).unwrap();
    let start = end
        + bytes[end..]
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap();
    assert_eq!(&bytes[start..start + 4], expected.as_bytes());
    map.line.replace_range(start + 2..start + 3, &result[2..3]);
    map.permissions = result.into();
}
#[cfg(test)]
pub fn quarantine(original: &Maps, current: &Maps) -> Map {
    let extra = current
        .rows
        .iter()
        .filter(|m| {
            !original
                .rows
                .iter()
                .any(|a| a.start == m.start && a.end == m.end)
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(extra.len(), 1);
    let island = extra[0].clone();
    assert_eq!(island.permissions, "r-xp");
    assert_eq!(island.offset, 0);
    assert_eq!(island.inode, 0);
    assert_eq!(island.device, "00:00");
    assert_eq!(island.path, None);
    assert!(
        !original
            .rows
            .iter()
            .any(|m| m.start < island.end && island.start < m.end)
    );
    let mut expected = original.rows.clone();
    for map in &mut expected {
        if map.start == 0xffff_ffff_ff60_0000 {
            assert_eq!(map.end, 0xffff_ffff_ff60_1000);
            assert_eq!(map.permissions, "--xp");
            assert_eq!(map.path.as_deref(), Some("[vsyscall]"));
        } else if map.permissions.as_bytes()[2] == b'x' {
            execute_bit(map, true, false);
        }
    }
    expected.push(island.clone());
    expected.sort_by_key(|m| m.start);
    assert_eq!(current.rows, expected);
    island
}
