//! Pure supplied-record and allocator models. These controls never launch a
//! task, issue CPUID/ptrace/procfs requests, or construct a native stack permit.
use super::access::*;
use super::metadata::*;
use super::operand::*;
use super::profile::*;
use super::storage::*;
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::linux::remote::dynamic::owner::bootstrap::BootstrapEvidence;
use crate::linux::remote::dynamic::owner::trusted::TrustedIsland;
use crate::linux::remote::dynamic::{DynamicStop, DynamicTask};

mod access;
mod allocation;
mod metadata;
mod validation;

const ORIGINAL: &[u8] = b"00400000-00402000 r-xp 00000000 08:01 7 /code\n00800000-00804000 rw-p 00000000 00:00 0 [stack]\n";
const BASELINE: &[u8] = b"00400000-00402000 r--p 00000000 08:01 7 /code\n00600000-00601000 r-xp 00000000 00:00 0\n00800000-00804000 rw-p 00000000 00:00 0 [stack]\n";
const SMAPS: &[u8] = b"00400000-00402000 r--p 00000000 08:01 7 /code\nSize:                  8 kB\nVmFlags: rd mr me\n00600000-00601000 r-xp 00000000 00:00 0\nSize:                  4 kB\nVmFlags: rd ex mr mw me\n00800000-00804000 rw-p 00000000 00:00 0 [stack]\nSize:                 16 kB\nProtectionKey:          0\nVmFlags: rd wr mr mw me gd ac sd\n";
fn layout() -> PkuLayoutEvidence {
    let mut records = [None; 5];
    let outputs = [
        [13, 0, 0, 0],
        [0, 0x2000_0000, (1 << 26) | (1 << 27), 0],
        [0, 0, (1 << 3) | (1 << 4), 0],
        [1 << 9, 0, 0, 0],
        [8, 832, 0, 0],
    ];
    for (index, (leaf, subleaf)) in CPUID_INPUTS.into_iter().enumerate() {
        records[index] = Some(CpuidRecord {
            leaf,
            subleaf,
            registers: outputs[index],
        });
    }
    PkuLayoutEvidence { records }
}
fn state() -> TaskStateSnapshot {
    let storage = StackObservationStorage::empty();
    let mut state = storage.state.state;
    state.registers.rip = 0x401000;
    state.registers.rsp = 0x802010;
    state.registers.cs = 0x33;
    state.registers.ss = 0x2b;
    state.registers.orig_rax = u64::MAX;
    state.registers.eflags = 0x202;
    state.mask = 0x200;
    state.xstate = vec![0; 840];
    state.xstate[464..472].copy_from_slice(&(1_u64 << 9).to_le_bytes());
    state.xstate[512..520].copy_from_slice(&(1_u64 << 9).to_le_bytes());
    state
}
fn slot(slot: &mut StateSlot, state: &TaskStateSnapshot) {
    assert_eq!(slot.state.xstate.capacity(), BYTES);
    slot.state.registers = state.registers;
    slot.state.mask = state.mask;
    slot.state.xstate.clear();
    slot.state.xstate.extend_from_slice(&state.xstate);
    let success = Some(Request {
        result: 0,
        errno: None,
    });
    slot.registers_request = success;
    slot.xstate_request = success;
    slot.mask_request = success;
    slot.requested_pointer = slot.state.xstate.as_ptr() as usize;
    slot.returned_pointer = slot.requested_pointer;
    slot.returned_length = state.xstate.len();
    slot.complete = true;
}
fn file(storage: &mut [u8], capture: &mut FileCapture, raw: &[u8]) {
    assert_eq!(storage.len(), BYTES);
    storage.fill(0);
    storage[..raw.len()].copy_from_slice(raw);
    let success = Some(Request {
        result: 0,
        errno: None,
    });
    *capture = FileCapture {
        started: true,
        complete: true,
        directory_open: Some(Request {
            result: 10,
            errno: None,
        }),
        directory_statfs: success,
        directory_filesystem: Some(libc::PROC_SUPER_MAGIC),
        file_open: Some(Request {
            result: 11,
            errno: None,
        }),
        file_statfs: success,
        file_filesystem: Some(libc::PROC_SUPER_MAGIC),
        first_read: Some(ReadRecord {
            fd: 11,
            destination: storage.as_ptr() as usize,
            count: BYTES,
            request: Request {
                result: raw.len() as i64,
                errno: None,
            },
        }),
        last_read: Some(ReadRecord {
            fd: 11,
            destination: storage.as_ptr() as usize + raw.len(),
            count: BYTES - raw.len(),
            request: Request {
                result: 0,
                errno: None,
            },
        }),
        read_calls: 2,
        copied: raw.len(),
        overflow: false,
        file_close: success,
        directory_close: success,
        first_failure: None,
    };
}
fn observation(storage: &mut StackObservationStorage, state: &TaskStateSnapshot) {
    file(&mut storage.maps, &mut storage.maps_capture, BASELINE);
    file(&mut storage.smaps, &mut storage.smaps_capture, SMAPS);
    slot(&mut storage.state, state);
}
fn model_bootstrap() -> BootstrapMm {
    let registry = LifecycleRegistry::new_after_exec_syscall_exit(
        crate::lifecycle::Limits::default(),
        101,
        0x401000,
    )
    .unwrap();
    let row = registry.task(registry.root_task()).unwrap();
    let identity = DynamicTask {
        task: row.id,
        process: row.process,
        address_space: row.address_space,
        generation: 0,
    };
    let restored = state();
    let mut entry = restored.clone();
    entry.registers.rip += 1;
    let mut exit = restored.clone();
    exit.registers.orig_rax = libc::SYS_execve as u64;
    // Historical EXEC/EXIT may lack the subsequently initialized user PKRU.
    exit.xstate = vec![0x5a; 832];
    let mut exec = exit.clone();
    exec.registers.rax = (-i64::from(libc::ENOSYS)) as u64;
    BootstrapMm {
        island: TrustedIsland {
            address_space: row.address_space,
            generation: 0,
            range: 0x600000..0x601000,
            page_size: 4096,
        },
        original_executables: Vec::new(),
        mappings: Vec::new(),
        stop: AdmissionStop {
            token: DynamicStop {
                session: 7,
                sequence: 19,
                tid: 101,
                task: Some(row.id),
            },
            identity,
            phase: AdmissionPhase::Restored,
            signal: None,
        },
        evidence: BootstrapEvidence {
            exec_event: exec,
            exec_exit: exit,
            entry_trap: entry,
            restored_entry: restored,
        },
    }
}
fn profile(boot: &BootstrapMm) -> PreparedStackProfile {
    let mut profile = PreparedStackProfile::empty();
    profile.allocate_payloads().unwrap();
    observation(&mut profile.observation, &boot.evidence.restored_entry);
    profile.layout_evidence = layout();
    profile
}
fn input(boot: &BootstrapMm) -> ProfileInput<'_> {
    ProfileInput {
        bootstrap: boot,
        original_maps: ORIGINAL,
        baseline_maps: BASELINE,
    }
}
fn pagemap(envelope: &Range<u64>) -> PagemapObservation {
    let count = (((envelope.end - 1) / PAGE - envelope.start / PAGE + 1) * 8) as usize;
    let mut bytes = [0; 16];
    for word in bytes[..count].chunks_exact_mut(8) {
        word.copy_from_slice(&((1_u64 << 63) | (1 << 56)).to_le_bytes());
    }
    PagemapObservation {
        fd: 15,
        offset: envelope.start / PAGE * 8,
        requested: count,
        copied: count,
        bytes,
        request: Some(Request {
            result: count as i64,
            errno: None,
        }),
    }
}
fn word(geometry: &OperandGeometry, value: u64) -> WordObservation {
    let mut bytes = [0_u8; 16];
    let length = geometry.envelope_length();
    bytes[..length].fill(0xa5);
    let offset = (geometry.slot.start - geometry.envelope.start) as usize;
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    let mut peek = [None; 2];
    for index in 0..length / 8 {
        peek[index] = Some(PeekRecord {
            address: geometry.envelope.start + (8 * index) as u64,
            request: Request {
                result: u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
                    as i64,
                errno: None,
            },
        });
    }
    WordObservation {
        bytes,
        copied: length,
        peek,
        complete: true,
        pagemap: pagemap(&geometry.envelope),
    }
}
