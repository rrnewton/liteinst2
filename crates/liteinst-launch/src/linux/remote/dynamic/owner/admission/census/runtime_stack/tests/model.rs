//! Supplied data only. No task, hardware observation, source/operand permit,
//! native completion constructor, or original release is created here.
use super::super::super::super::runtime_stack::access::{
    CPUID_INPUTS, CpuidRecord, PagemapObservation, PkuLayoutEvidence,
};
use super::super::super::super::runtime_stack::operand::{PeekRecord, WordObservation};
use super::super::super::super::runtime_stack::storage::{
    FileCapture, ReadRecord, StackObservationStorage,
};
use super::super::super::super::runtime_stack_native::acquire::{
    ModelPagemapAccess, StackCaptureFailure, StackCaptureStage,
};
use super::super::super::super::source_identity::{
    FileIdentity, ImageRole, InitialSourceVma, SourceVma,
};
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::linux::remote::dynamic::owner::bootstrap::{Request, StateSlot};
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};
use liteinst2::contracts::{CodeIdentity, SourceIdentity};
use std::time::Duration;

pub(in crate::linux::remote::dynamic::owner::admission::census) const PC: u64 = 0x400ffb;
pub(in crate::linux::remote::dynamic::owner::admission::census) const ORIGINAL: &[u8] = b"00400000-00402000 r-xp 00000000 08:01 7 /code\n00800000-00804000 rw-p 00000000 00:00 0 [stack]\n";
pub(super) const BASELINE: &[u8] = b"00400000-00402000 r--p 00000000 08:01 7 /code\n00600000-00601000 r-xp 00000000 00:00 0\n00800000-00804000 rw-p 00000000 00:00 0 [stack]\n";
pub(super) const OPEN: &[u8] = b"00400000-00401000 r-xp 00000000 08:01 7 /code\n00401000-00402000 r--p 00001000 08:01 7 /code\n00600000-00601000 r-xp 00000000 00:00 0\n00800000-00804000 rw-p 00000000 00:00 0 [stack]\n";
const SESSION: u64 = 91;
fn layout() -> PkuLayout {
    let outputs = [
        [13, 0, 0, 0],
        [0, 0, (1 << 26) | (1 << 27), 0],
        [0, 0, (1 << 3) | (1 << 4), 0],
        [1 << 9, 0, 0, 0],
        [8, 832, 0, 0],
    ];
    PkuLayoutEvidence {
        records: std::array::from_fn(|i| {
            Some(CpuidRecord {
                leaf: CPUID_INPUTS[i].0,
                subleaf: CPUID_INPUTS[i].1,
                registers: outputs[i],
            })
        }),
    }
    .validate()
    .unwrap()
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn limits() -> Limits {
    Limits {
        epochs: 32,
        source_fact_bytes: 64 * 1024 * 1024,
        reports: 64,
        origins: 64,
        witnesses: 128,
        plan_history: 64,
    }
}
fn state() -> TaskStateSnapshot {
    let mut state = StackObservationStorage::empty().state.state;
    state.registers.rip = PC;
    state.registers.rsp = 0x802013;
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
pub(in crate::linux::remote::dynamic::owner::admission::census) fn seeded()
-> (ResumeCensus, OriginId) {
    let registry = LifecycleRegistry::new(crate::lifecycle::Limits::default(), 101, PC).unwrap();
    let row = registry.task(registry.root_task()).unwrap();
    let state = state();
    let task = DynamicTask {
        task: row.id,
        process: row.process,
        address_space: row.address_space,
        generation: 0,
    };
    let before = ObservedStop {
        token: DynamicStop {
            session: SESSION,
            sequence: 10,
            tid: 101,
            task: Some(row.id),
        },
        task,
        logical_pc: PC,
        registers: state.registers,
        xstate: state.xstate,
        signal_mask: state.mask,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    };
    let mut census = ResumeCensus::new(SESSION, task.address_space, 0, limits()).unwrap();
    let reservation = census
        .reserve(
            super::super::super::runtime::initial_runtime_origin_charge(MAX_XSTATE_BYTES).unwrap(),
        )
        .unwrap();
    let origin = census
        .insert(reservation, OriginKind::CurrentHeldPc, PC, before)
        .unwrap();
    census.finish_reservation(reservation).unwrap();
    (census, origin)
}
fn slot(slot: &mut StateSlot, state: &TaskStateSnapshot) {
    assert_eq!(slot.state.xstate.capacity(), MAX_XSTATE_BYTES);
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
pub(super) fn file(storage: &mut [u8], capture: &mut FileCapture, raw: &[u8]) {
    assert_eq!(storage.len(), MAX_XSTATE_BYTES);
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
            count: storage.len(),
            request: Request {
                result: raw.len() as i64,
                errno: None,
            },
        }),
        last_read: Some(ReadRecord {
            fd: 11,
            destination: storage.as_ptr() as usize + raw.len(),
            count: storage.len() - raw.len(),
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
fn smaps(maps: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for line in std::str::from_utf8(maps).unwrap().lines() {
        output.extend_from_slice(line.as_bytes());
        output.push(b'\n');
        if line.ends_with("[stack]") {
            output.extend_from_slice(b"Size:                 16 kB\nProtectionKey:          0\nVmFlags: rd wr mr mw me gd ac sd\n");
        } else {
            output.extend_from_slice(b"Size:                  4 kB\nVmFlags: rd mr me\n");
        }
    }
    output
}
fn pagemap(geometry: &OperandGeometry) -> PagemapObservation {
    let range = &geometry.envelope;
    let count = (((range.end - 1) / 4096 - range.start / 4096 + 1) * 8) as usize;
    let mut bytes = [0; 16];
    for part in bytes[..count].chunks_exact_mut(8) {
        part.copy_from_slice(&((1_u64 << 63) | (1 << 56)).to_le_bytes());
    }
    PagemapObservation {
        fd: 15,
        offset: range.start / 4096 * 8,
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
    let length = geometry.envelope_length();
    let offset = (geometry.slot.start - geometry.envelope.start) as usize;
    let mut bytes = [0; 16];
    bytes[..length].fill(0xa5);
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    let mut peek = [None; 2];
    for (index, entry) in peek.iter_mut().enumerate().take(length / 8) {
        *entry = Some(PeekRecord {
            address: geometry.envelope.start + (index * 8) as u64,
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
        pagemap: pagemap(geometry),
    }
}
fn access() -> ModelPagemapAccess {
    let success = Some(Request {
        result: 0,
        errno: None,
    });
    ModelPagemapAccess {
        started: true,
        complete: true,
        directory_open: Some(Request {
            result: 14,
            errno: None,
        }),
        directory_statfs: success,
        directory_filesystem: Some(libc::PROC_SUPER_MAGIC),
        file_open: Some(Request {
            result: 15,
            errno: None,
        }),
        file_statfs: success,
        file_filesystem: Some(libc::PROC_SUPER_MAGIC),
        file_close: success,
        directory_close: success,
        first_failure: None,
    }
}
pub(super) struct Capture {
    pub(super) observation: StackObservationStorage,
    pub(super) word: WordObservation,
    pub(super) access: ModelPagemapAccess,
    pub(super) association: Option<StackCaptureAssociation>,
    pub(super) complete: bool,
    pub(super) first_failure: Option<(StackCaptureStage, StackCaptureFailure)>,
}
impl Capture {
    fn new(
        state: &TaskStateSnapshot,
        maps: &[u8],
        word: WordObservation,
        association: StackCaptureAssociation,
    ) -> Self {
        let mut observation = StackObservationStorage::empty();
        observation.allocate_payloads().unwrap();
        file(&mut observation.maps, &mut observation.maps_capture, maps);
        file(
            &mut observation.smaps,
            &mut observation.smaps_capture,
            &smaps(maps),
        );
        slot(&mut observation.state, state);
        Self {
            observation,
            word,
            access: access(),
            association: Some(association),
            complete: true,
            first_failure: None,
        }
    }
    fn view(&self) -> StackWordView<'_> {
        StackWordView {
            observation: &self.observation,
            word: &self.word,
            pagemap_access: &self.access,
            association: self.association.as_ref(),
            complete: self.complete,
            first_failure: self.first_failure,
        }
    }
}
pub(in crate::linux::remote::dynamic::owner::admission::census) struct Model {
    pub(in crate::linux::remote::dynamic::owner::admission::census) binding: Binding,
    pub(super) profile: ProfileDescription,
    pub(super) stops: [AdmissionStop; 8],
    pub(super) states: [TaskStateSnapshot; 8],
    pub(super) trace: NativeTrace,
    pub(super) captures: [Capture; 4],
    pub(in crate::linux::remote::dynamic::owner::admission::census) snapshot: Box<Snapshot>,
    pub(in crate::linux::remote::dynamic::owner::admission::census) call: Option<PotentialCallId>,
    pub(super) opened: Vec<u8>,
}
impl Model {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn new(
        census: &ResumeCensus,
        reservation: Reservation,
        origin: OriginId,
        operation: StackOperation,
    ) -> Self {
        let before = census.current_observation(origin).unwrap();
        let encoding = if operation == StackOperation::DirectCall {
            [
                vec![0xe8],
                (0x400800_i64 - 0x401000).to_le_bytes()[..4].to_vec(),
            ]
            .concat()
        } else {
            vec![0xc3]
        };
        let geometry = OperandGeometry::derive(
            PC,
            &encoding,
            before.registers.rsp,
            &(0x800000..0x804000),
            &(0x600000..0x601000),
        )
        .unwrap();
        let value = if operation == StackOperation::DirectCall {
            0x1234
        } else {
            0x400900
        };
        let until = Instant::now() + Duration::from_secs(60);
        let mut stops: [AdmissionStop; 8] = std::array::from_fn(|i| {
            let mut token = before.token.clone();
            token.sequence += i as u64;
            AdmissionStop {
                token,
                identity: before.task,
                phase: if i == 0 {
                    AdmissionPhase::Restored
                } else if i == 4 {
                    AdmissionPhase::NativeCompleted
                } else {
                    AdmissionPhase::Restored
                },
                signal: None,
            }
        });
        stops[0].phase = AdmissionPhase::Restored;
        let initial = TaskStateSnapshot {
            registers: before.registers,
            xstate: before.xstate.clone(),
            mask: before.signal_mask,
        };
        let mut states = std::array::from_fn(|_| initial.clone());
        for state in &mut states[4..] {
            state.registers.rip = geometry.call_target.unwrap_or(value);
            state.registers.rsp = if operation == StackOperation::DirectCall {
                geometry.slot.start
            } else {
                geometry.slot.end
            };
            state.registers.orig_rax = u64::MAX;
        }
        let stack = StackDescriptor::validate(
            ORIGINAL,
            BASELINE,
            before.registers.rsp,
            &(0x600000..0x601000),
        )
        .unwrap();
        let metadata = validate_smaps(&smaps(BASELINE), BASELINE, stack.baseline_index).unwrap();
        let profile = ProfileDescription {
            stack,
            metadata,
            layout: layout(),
            initial_rsp: before.registers.rsp,
            island: 0x600000..0x601000,
            restored: stops[0].clone(),
        };
        let operand = OperandDescription {
            geometry: geometry.clone(),
            value,
            target: geometry.call_target.unwrap_or(value),
            pkru: 0,
            stop: stops[0].clone(),
            until,
        };
        let span = ORIGINAL.iter().position(|b| *b == b'\n').unwrap();
        let source = InitialSourceVma::strict(SourceVma {
            original_index: 0,
            current_index: 0,
            original_span: (0, span),
            current_span: (0, span),
            start: 0x400000,
            end: 0x402000,
            offset: 0,
            file: FileIdentity {
                major: 8,
                minor: 1,
                inode: 7,
            },
            role: ImageRole::Executable,
        });
        let mut bytes = vec![0x90; 8192];
        let offset = (PC - 0x400000) as usize;
        bytes[offset..offset + encoding.len()].copy_from_slice(&encoding);
        let snapshot = Box::new(
            Snapshot::new(
                MappingId(17),
                Generation(0),
                0x400000,
                bytes,
                Boundary::Unknown,
                Boundary::Unknown,
                WriteControl::Owned,
            )
            .unwrap(),
        );
        let id = SourceWindowId::synthetic_for_test(
            CodeIdentity {
                source: SourceIdentity([0x31; 32]),
                mapping: 17,
                generation: 0,
            },
            0,
        );
        let record = SourceRecord::from_parts(
            id,
            source,
            AddressRange::new(0x400000, 0x402000).unwrap(),
            &snapshot,
        );
        let binding = Binding {
            census: census.identity,
            reservation,
            candidate_serial: census.state.next_serial,
            origin,
            execution: ExecutionId::from_owner(SESSION, 1).unwrap(),
            source: record,
            fetch: FetchGeometry::for_initial_source(
                source,
                AddressRange::new(PC, geometry.next_pc).unwrap(),
            )
            .unwrap(),
            operand,
            profile: ProfileRecord::from(&profile),
            until,
        };
        let mut raw = [0; 128];
        raw[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
        raw[8..12].copy_from_slice(&libc::TRAP_TRACE.to_ne_bytes());
        raw[16..24].copy_from_slice(&states[4].registers.rip.to_ne_bytes());
        let trace = NativeTrace {
            ordinal: 3,
            tid: before.token.tid,
            status: (libc::SIGTRAP << 8) | 0x7f,
            signal: raw,
            dr6: TRACE_DR6,
        };
        let first = word(&geometry, value);
        let mut after = first;
        if operation == StackOperation::DirectCall {
            let offset = (geometry.slot.start - geometry.envelope.start) as usize;
            after.bytes[offset..offset + 8].copy_from_slice(&geometry.next_pc.to_le_bytes());
            for i in 0..geometry.envelope_length() / 8 {
                after.peek[i].as_mut().unwrap().request.result =
                    u64::from_le_bytes(after.bytes[i * 8..i * 8 + 8].try_into().unwrap()) as i64;
            }
        }
        let captures = [
            Capture::new(
                &states[0],
                BASELINE,
                first,
                StackCaptureAssociation::A {
                    stop: stops[0].clone(),
                    source_id: id,
                    until,
                },
            ),
            Capture::new(
                &states[3],
                OPEN,
                first,
                StackCaptureAssociation::B {
                    stop: stops[3].clone(),
                    until,
                },
            ),
            Capture::new(
                &states[4],
                OPEN,
                after,
                StackCaptureAssociation::C {
                    original: stops[3].clone(),
                    raw_wait: (trace.tid, trace.status),
                    ordinal: 3,
                    until,
                },
            ),
            Capture::new(
                &states[7],
                BASELINE,
                after,
                StackCaptureAssociation::D {
                    stop: stops[7].clone(),
                    until,
                },
            ),
        ];
        Self {
            binding,
            profile,
            stops,
            states,
            trace,
            captures,
            snapshot,
            call: None,
            opened: OPEN.to_vec(),
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn view(
        &self,
    ) -> CompletionModel<'_> {
        let checkpoint = |i| NativeCheckpoint {
            stop: &self.stops[i],
            state: &self.states[i],
        };
        CompletionModel {
            source: self.binding.source.id,
            origin: self.binding.origin,
            execution: self.binding.execution,
            until: self.binding.until,
            operand: &self.binding.operand,
            profile: &self.profile,
            identity_stop: &self.binding.operand.stop,
            identity_initial: &self.profile.restored,
            identity_stack: self.profile.stack,
            identity_metadata: self.profile.metadata,
            identity_layout: self.profile.layout,
            identity_rsp: self.profile.initial_rsp,
            logical: checkpoint(0),
            opening: std::array::from_fn(|i| checkpoint(i + 1)),
            step: checkpoint(4),
            closing: std::array::from_fn(|i| checkpoint(i + 5)),
            trace: self.trace,
            words: StackWordViews {
                profile: &self.profile,
                operand: &self.binding.operand,
                original_maps: ORIGINAL,
                baseline_maps: BASELINE,
                opened_maps: &self.opened,
                captures: std::array::from_fn(|i| self.captures[i].view()),
            },
            call: self.call,
        }
    }
}
