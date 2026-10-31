//! Explicit, fresh-process native witness for the closed compiled-C fixture.
//!
//! This is a trusted-input experiment, not an arbitrary-ELF execution service.
//! The invoking recipe must authenticate the complete reviewed compiler/CRT/
//! dependency build, both ELF outputs and the consumer snapshot before dispatch.
//! A hash or a successful structural parse alone is never that admission.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/caller.rs"]
mod caller;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/caller_dataflow.rs"]
mod caller_dataflow;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/cfi.rs"]
mod cfi;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/chain.rs"]
mod chain;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/elf.rs"]
mod elf;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "../../unwind-oracle/consumer.rs"]
mod indexed_consumer;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/leaf.rs"]
mod leaf;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/loaded.rs"]
mod loaded;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/observations.rs"]
mod observations;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/prepare.rs"]
mod prepare;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/runtime.rs"]
mod runtime;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod host {
    use super::*;
    use formats::ContentId;
    use loaded::{BoundImage, ImmutableRange, Loaded};
    use observations as o;
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
        os::unix::fs::OpenOptionsExt,
        path::Path,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Mode {
        Inspect,
        RuntimeDiagnostic,
        Original,
        Intact,
        LookupNegative,
    }

    fn digest(text: &str) -> ContentId {
        assert_eq!(text.len(), 64);
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        ContentId(std::array::from_fn(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap()
        }))
    }
    fn no_gmon_provider() {
        // SAFETY: read-only lookup in this fresh process's current global
        // scope. The build admission separately excludes a provider in every
        // new local dependency. Do not call the returned address.
        unsafe {
            libc::dlerror();
            let value = libc::dlsym(libc::RTLD_DEFAULT, c"__gmon_start__".as_ptr());
            let error = libc::dlerror();
            assert!(
                value.is_null() && !error.is_null(),
                "unexpected gmon provider"
            );
        }
    }
    fn read(path: &Path, id: ContentId) -> Vec<u8> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        assert!(metadata.is_file() && metadata.len() <= elf::BYTE_LIMIT);
        let mut bytes = Vec::new();
        file.take(elf::BYTE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() as u64 <= elf::BYTE_LIMIT);
        assert_eq!(ContentId::of(&bytes), id);
        bytes
    }
    fn immutable(symbol: elf::Symbol) -> ImmutableRange {
        ImmutableRange {
            address: symbol.address,
            length: symbol.size,
            executable: true,
        }
    }
    fn address(image: &Loaded, symbol: elf::Symbol) -> usize {
        usize::try_from(image.address(immutable(symbol)).unwrap()).unwrap()
    }
    fn placed(image: &Loaded, symbol: elf::Symbol) -> o::Range {
        let begin = address(image, symbol);
        o::Range {
            begin,
            end: begin.checked_add(symbol.size as usize).unwrap(),
        }
    }

    /// Source-bound original chain, without loading or reading a native trace.
    fn original_chain(subject: &elf::Snapshot) -> chain::Subject {
        let symbols = [
            subject.named_function("collect", false).unwrap(),
            subject.symbols().collect_original,
            subject.symbols().hook,
            subject.symbols().reference,
        ];
        let records = symbols.map(|s| subject.source_record(s.address).unwrap());
        let (address, bytes) = subject.original_metadata().unwrap();
        let input = subject.elf().unwrap();
        let function = |i: usize| chain::Function {
            address: symbols[i].address,
            bytes: elf::owned_code(&input, symbols[i].address, symbols[i].size)
                .unwrap()
                .bytes,
            record: &records[i],
            metadata: cfi::Metadata { address, bytes },
        };
        chain::Subject::prove(
            function(0),
            function(1),
            function(2),
            function(3),
            subject.backtrace_plt().unwrap().0,
        )
        .unwrap()
    }

    fn caller_proofs(
        image: &elf::caller_image::CallerImage<'_>,
    ) -> [chain::ConditionalCallerCfi; 2] {
        let input = liteinst_rewrite::carrier::elf64::Elf64::parse(
            image.bytes(),
            liteinst_rewrite::carrier::elf64::ParseLimits {
                max_program_headers: 4096,
            },
        )
        .unwrap();
        let compare = image.named_function("compare_observations").unwrap();
        let effects = caller_dataflow::compare_effects(
            elf::owned_code(&input, compare.address, compare.size)
                .unwrap()
                .bytes,
            compare.address,
        )
        .unwrap();
        let (address, bytes) = elf::original_metadata(image.bytes()).unwrap();
        let proofs =
            [(false, image.work()), (true, image.reference())].map(|(reference, function)| {
                let symbol = function.symbol();
                let code = elf::owned_code(&input, symbol.address, symbol.size)
                    .unwrap()
                    .bytes;
                let metadata = cfi::Metadata { address, bytes };
                let raw = image.raw_return(reference).unwrap();
                let proof = caller_dataflow::prove(
                    code,
                    function.proof(),
                    if reference {
                        caller_dataflow::Kind::Reference
                    } else {
                        caller_dataflow::Kind::Work
                    },
                    Some(caller_dataflow::RawCapture {
                        address: raw.address,
                    }),
                )
                .unwrap();
                let tail = proof.prove_tail(code, &effects).unwrap();
                chain::prove_conditional_caller(
                    chain::Function {
                        address: symbol.address,
                        bytes: code,
                        record: function.original_cfi(),
                        metadata,
                    },
                    function.proof(),
                    &proof,
                    &tail,
                )
                .unwrap()
            });
        let a = image.raw_return(false).unwrap();
        let b = image.raw_return(true).unwrap();
        assert!(a.address + a.size <= b.address || b.address + b.size <= a.address);
        proofs
    }

    type FindFde = unsafe extern "C" fn(usize) -> *const u8;
    fn lookups(
        subject: &Loaded,
        caller: &Loaded,
        caller_view: &elf::caller_image::CallerImage<'_>,
        candidate: &prepare::Candidate,
        mode: Mode,
        find: FindFde,
    ) -> usize {
        let mut count = 0;
        let mut check = |bias: u64, point: u64, expected: u64| {
            // SAFETY: admitted normal GNU lookup wrapper, retained exact module
            // and consumer owners. No selected-work instruction is invoked.
            let observed = unsafe { find(usize::try_from(bias + point).unwrap()) } as usize as u64;
            assert_eq!(
                observed,
                if expected == 0 { 0 } else { bias + expected },
                "exact FDE lookup at module coordinate {point:#x}"
            );
            count += 1;
        };
        for &(start, end, fde) in &candidate.original_fdes {
            for point in [start, end - 1] {
                check(subject.load_bias(), point, fde);
            }
        }
        for &(start, end, fde) in caller_view.original_fdes() {
            for point in [start, end - 1] {
                check(caller.load_bias(), point, fde);
            }
        }
        // The original module owns no generated LOAD range. An arbitrary
        // address at that bias could belong to another DSO. Only the intact
        // and index-negative images own the generated lookup coordinates.
        if mode == Mode::Original {
            return count;
        }
        let base = candidate.output.unwind.as_ref().unwrap().records_address.0;
        let generated = candidate.records.fdes();
        let mut points = std::collections::BTreeSet::new();
        for &(start, end, _) in generated {
            points.extend([start, end - 1, end]);
        }
        for &(original, entry) in candidate.trace.image().entry_routes() {
            assert_eq!(original, candidate.trace.source_step().parts().logical_pc);
            points.insert(entry);
        }
        for call in candidate.trace.trace().calls() {
            points.extend([call.call_pc(), call.return_pc() - 1, call.return_pc()]);
        }
        for point in points {
            let expected = if mode == Mode::Intact {
                generated
                    .iter()
                    .find(|&&(start, end, _)| start <= point && point < end)
                    .map_or(0, |&(_, _, offset)| base + offset as u64)
            } else {
                0
            };
            check(subject.load_bias(), point, expected);
        }
        count
    }

    fn object_range<T>(p: &T) -> runtime::Range {
        runtime::Range::new(
            std::ptr::from_ref(p) as usize as u64,
            std::mem::size_of::<T>() as u64,
        )
        .unwrap()
    }
    fn disjoint(
        stack: runtime::Stack,
        subject: &Loaded,
        caller: &Loaded,
        control: &o::CallerControl,
        out: &o::CallerObservation,
        records: &[o::Trace; 2],
        input: &[u8],
    ) {
        let objects = [
            object_range(control),
            object_range(out),
            object_range(records),
            runtime::Range::new(input.as_ptr() as usize as u64, input.len() as u64).unwrap(),
        ];
        runtime::require_disjoint(&objects).unwrap();
        for object in objects {
            stack.exclude_object(object).unwrap();
            for image in [subject, caller] {
                for load in image.image().loads() {
                    let owner =
                        runtime::Range::new(image.load_bias() + load.address, load.memory_bytes)
                            .unwrap();
                    runtime::require_disjoint(&[object, owner]).unwrap();
                }
            }
        }
    }

    struct Invocation<'a> {
        loaded_mode: Mode,
        runtime: &'a runtime::Runtime,
        subject: &'a Loaded,
        caller: &'a Loaded,
        subject_view: &'a elf::Snapshot,
        caller_view: &'a elf::caller_image::CallerImage<'a>,
        caller_proofs: &'a [chain::ConditionalCallerCfi; 2],
        candidate: &'a prepare::Candidate,
        chain: &'a chain::Subject,
        generated: &'a chain::Generated,
        consumer: &'a indexed_consumer::IndexedConsumer,
    }
    impl Invocation<'_> {
        fn call(&self, mode: o::Mode, case: o::Case, previous_count: u32) -> u32 {
            let reference = mode == o::Mode::Reference;
            let function = if reference {
                self.caller_view.reference()
            } else {
                self.caller_view.work()
            };
            let return_pc =
                usize::try_from(self.caller.load_bias() + function.proof().return_pc()).unwrap();
            let symbols = self.subject_view.symbols();
            let input = Box::leak(case.input().to_vec().into_boxed_slice());
            let records = Box::leak(Box::new([o::Trace::ZERO, o::Trace::ZERO]));
            let out = Box::leak(Box::new(o::CallerObservation::default()));
            let stack = self.runtime.verify().unwrap();
            let generated = if self.loaded_mode == Mode::Original {
                o::Range::default()
            } else {
                let image = self.candidate.trace.image();
                o::Range {
                    begin: (self.subject.load_bias() + image.address()) as usize,
                    end: (self.subject.load_bias() + image.address() + image.bytes().len() as u64)
                        as usize,
                }
            };
            // SAFETY: exact authenticated typed C functions from this closed
            // fixture build, with owners retained and runtime premises checked.
            let (configure, status, end) = unsafe {
                (
                    std::mem::transmute::<usize, o::ConfigureFn>(address(
                        self.subject,
                        symbols.configure,
                    )),
                    std::mem::transmute::<usize, o::StatusFn>(address(
                        self.subject,
                        symbols.capture_status,
                    )),
                    std::mem::transmute::<usize, o::StatusFn>(address(
                        self.subject,
                        symbols.capture_end,
                    )),
                )
            };
            let control = Box::leak(Box::new(o::CallerControl {
                config: o::Config {
                    stack: o::Range {
                        begin: stack.usable.start() as usize,
                        end: stack.usable.end() as usize,
                    },
                    source: placed(self.subject, symbols.work),
                    reference: placed(self.subject, symbols.reference),
                    caller: placed(self.caller, function.symbol()),
                    generated,
                    selected: (self.subject.load_bias() + symbols.selected.address) as usize,
                    layout: o::LAYOUT,
                    records: records.as_mut_ptr(),
                    capacity: 2,
                    ..o::Config::default()
                },
                configure: Some(configure),
                status: Some(status),
                end: Some(end),
                return_pc,
            }));
            disjoint(
                stack,
                self.subject,
                self.caller,
                control,
                out,
                records,
                input,
            );
            self.consumer.revalidate();
            self.subject.verify().unwrap();
            self.caller.verify().unwrap();
            self.runtime.verify().unwrap();
            // SAFETY: reviewed ordinary-C callers and exact machine argument,
            // raw capture, helper and tail proofs; owned disjoint input/control/
            // output/capture storage; selected leaf and preserving collector
            // contracts of the closed build. Corruption or abnormal exit fails
            // the containing fresh-process attempt. Preservation is measured.
            let returned = unsafe {
                if reference {
                    let call = std::mem::transmute::<usize, o::CallReferenceFn>(address(
                        self.caller,
                        function.symbol(),
                    ));
                    let target = std::mem::transmute::<usize, o::ReferenceFn>(address(
                        self.subject,
                        symbols.reference,
                    ));
                    call(control, Some(target), case.seed(), out)
                } else {
                    let call = std::mem::transmute::<usize, o::CallWorkFn>(address(
                        self.caller,
                        function.symbol(),
                    ));
                    let target = std::mem::transmute::<usize, o::WorkFn>(address(
                        self.subject,
                        symbols.work,
                    ));
                    call(
                        control,
                        Some(target),
                        input.as_ptr(),
                        input.len(),
                        case.seed(),
                        out,
                    )
                }
            };
            self.runtime.verify().unwrap();
            self.subject.verify().unwrap();
            self.caller.verify().unwrap();
            self.consumer.revalidate();
            let words = self
                .caller
                .raw_return_words(self.caller_view.raw_return(reference).unwrap().address)
                .unwrap();
            let raw = o::RawReturn {
                result: words[0],
                rsp: words[1],
                callee: words[2..].try_into().unwrap(),
            };
            let checked = o::check_call(
                o::CallExpectation {
                    mode,
                    case,
                    return_pc,
                    previous_count,
                },
                returned,
                out,
                records,
            )
            .unwrap();
            checked.check_raw_return(&raw).unwrap();
            self.caller_proofs[usize::from(reference)]
                .check_return(self.caller.load_bias(), out, &raw)
                .unwrap();
            let entry = chain::Entry {
                pre_call_rsp: out.rsp_pre as u64,
                return_pc: return_pc as u64,
                callee: o::CANARIES,
            };
            if mode != o::Mode::OriginalWork {
                let expectation = if reference {
                    chain::GeneratedExpectation {
                        frames: self
                            .chain
                            .reference_frames(self.subject.load_bias(), entry, case.seed())
                            .unwrap(),
                        context: o::ContextExpectation::Absent,
                    }
                } else {
                    self.generated
                        .frames(self.chain, self.subject.load_bias(), entry)
                        .unwrap()
                };
                checked
                    .check_trace(&o::TraceExpectation {
                        frames: &expectation.frames,
                        result: chain::BACKTRACE_STOP_RESULT,
                        context: expectation.context,
                    })
                    .unwrap();
                for (index, frame) in records[0].frames[..records[0].frame_count as usize]
                    .iter()
                    .enumerate()
                {
                    println!(
                        "{{\"kind\":\"frame\",\"mode\":\"{mode:?}\",\"case\":\"{case:?}\",\"index\":{index},\"ip\":{},\"cfa\":{},\"before_instruction\":{},\"owned\":{},\"callee\":{:?}}}",
                        frame.ip, frame.cfa, frame.before_instruction, frame.owned, frame.callee
                    );
                }
            }
            println!(
                "{{\"kind\":\"call\",\"mode\":\"{mode:?}\",\"case\":\"{case:?}\",\"returned\":{returned},\"rsp_pre\":{},\"rsp_raw\":{},\"result\":{},\"output\":{},\"callee\":{:?}}}",
                out.rsp_pre, raw.rsp, raw.result, out.output_after, raw.callee
            );
            out.status_final.count
        }
    }

    pub fn run() {
        let args: Vec<_> = std::env::args().skip(1).collect();
        assert_eq!(
            args.len(),
            10,
            "MODE SUBJECT SHA256 CALLER SHA256 BUILD_RECORD SHA256 LIBGCC FROZEN_LIBGCC OUT_DIR"
        );
        let mode = match args[0].as_str() {
            "inspect" => Mode::Inspect,
            "runtime-diagnostic" => Mode::RuntimeDiagnostic,
            "original" => Mode::Original,
            "intact" => Mode::Intact,
            "lookup-negative" => Mode::LookupNegative,
            _ => panic!("unknown fixed native mode"),
        };
        let subject_path = std::fs::canonicalize(&args[1]).unwrap();
        let caller_path = std::fs::canonicalize(&args[3]).unwrap();
        let subject = elf::Snapshot::parse(read(&subject_path, digest(&args[2]))).unwrap();
        let caller_bytes = read(&caller_path, digest(&args[4]));
        let caller_view = elf::caller_image::CallerImage::inspect(&caller_bytes).unwrap();
        let caller_proofs = caller_proofs(&caller_view);
        let chain = original_chain(&subject);
        let build_id = digest(&args[6]);
        read(Path::new(&args[5]), build_id);
        if mode == Mode::Inspect {
            println!(
                "{{\"kind\":\"inspection\",\"caller_functions\":2,\"subject_functions\":4,\"native\":false}}"
            );
            return;
        }
        runtime::prepare_stack().unwrap();
        // SAFETY: this explicitly invoked experiment owns one fresh process,
        // its source-authenticated toolchain/dependency closure and all future
        // operations. No handlers, threads, unloading or reentry are introduced.
        let runtime = unsafe { runtime::Runtime::enter() }.unwrap();
        if mode == Mode::RuntimeDiagnostic {
            println!("runtime_admission_only {:?}", runtime.evidence());
            return;
        }
        let sources = [
            include_bytes!("../../unwind-oracle/indexed_dso/subject.c").as_slice(),
            include_bytes!("../../unwind-oracle/indexed_dso/collector.c").as_slice(),
            include_bytes!("../../unwind-oracle/indexed_dso/witness.h").as_slice(),
        ]
        .map(ContentId::of);
        // SAFETY: closed reviewed C leaf/collector/hook/CRT/dependency build,
        // complete original byte/CFI ownership and full chain checks above.
        // Compiler/source semantics and dependency contracts are prerequisites
        // of this trusted-input experiment, never inferred from these hashes.
        let candidate = unsafe {
            prepare::prepare_owned_fixture(
                &subject,
                prepare::BuildAttestation {
                    artifact: subject.identity(),
                    sources,
                    record: build_id,
                },
                runtime.evidence().xstate,
            )
        }
        .unwrap();
        let generated = chain::Generated::prove(&candidate, &chain).unwrap();
        let negative = if mode == Mode::LookupNegative {
            Some(candidate.original_index_only(&subject).unwrap())
        } else {
            None
        };
        let bytes = match mode {
            Mode::Inspect | Mode::RuntimeDiagnostic => {
                unreachable!("inspection returns before DSO preparation")
            }
            Mode::Original => subject.bytes(),
            Mode::Intact => candidate.output.bytes(),
            Mode::LookupNegative => &negative.as_ref().unwrap().bytes,
        };
        let path = if mode == Mode::Original {
            subject_path
        } else {
            let out = Path::new(&args[9]);
            assert!(out.is_absolute() && out.is_dir());
            let path = out.join("subject.so");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o500)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            path
        };
        let subject_bound = BoundImage::new(bytes, ContentId::of(bytes), &[]).unwrap();
        let caller_bound = BoundImage::new(&caller_bytes, caller_view.identity(), &[]).unwrap();
        runtime.verify().unwrap();
        no_gmon_provider();
        // SAFETY: source-authenticated CRT/init/dependency graph, immutable file
        // custody and one controlled thread; NODELETE owners persist to exit.
        let subject_loaded = unsafe { Loaded::open(&path, subject_bound).unwrap() };
        runtime.verify().unwrap();
        // SAFETY: same closed init/dependency contract as the subject above.
        let caller_loaded = unsafe { Loaded::open(&caller_path, caller_bound).unwrap() };
        runtime.verify().unwrap();
        subject_loaded.verify().unwrap();
        caller_loaded.verify().unwrap();
        let mut consumers = [0; 5];
        // SAFETY: authenticated fixed five-word export and actual GNU wrapper.
        let find = unsafe {
            let addresses = std::mem::transmute::<usize, unsafe extern "C" fn(*mut usize)>(
                address(&subject_loaded, subject.symbols().consumer_addresses),
            );
            addresses(consumers.as_mut_ptr());
            std::mem::transmute::<usize, FindFde>(address(
                &subject_loaded,
                subject.symbols().find_fde,
            ))
        };
        let consumer = indexed_consumer::IndexedConsumer::qualify(
            consumers,
            std::fs::canonicalize(&args[7]).unwrap(),
            std::fs::canonicalize(&args[8]).unwrap(),
        );
        runtime.verify().unwrap();
        subject_loaded.verify().unwrap();
        caller_loaded.verify().unwrap();
        assert_eq!(
            subject_loaded
                .relocated_word(subject.backtrace_plt().unwrap().1)
                .unwrap(),
            consumers[1] as u64
        );
        let lookup_count = lookups(
            &subject_loaded,
            &caller_loaded,
            &caller_view,
            &candidate,
            mode,
            find,
        );
        runtime.verify().unwrap();
        subject_loaded.verify().unwrap();
        caller_loaded.verify().unwrap();
        consumer.revalidate();
        if mode == Mode::LookupNegative {
            println!(
                "{{\"kind\":\"complete\",\"mode\":\"lookup-negative\",\"lookups\":{lookup_count},\"calls\":0}}"
            );
            return;
        }
        let invocation = Invocation {
            loaded_mode: mode,
            runtime: &runtime,
            subject: &subject_loaded,
            caller: &caller_loaded,
            subject_view: &subject,
            caller_view: &caller_view,
            caller_proofs: &caller_proofs,
            candidate: &candidate,
            chain: &chain,
            generated: &generated,
            consumer: &consumer,
        };
        let mut previous_count = 0;
        for case in o::Case::ALL {
            previous_count = invocation.call(o::Mode::Reference, case, previous_count);
            previous_count = invocation.call(
                if mode == Mode::Original {
                    o::Mode::OriginalWork
                } else {
                    o::Mode::CandidateWork
                },
                case,
                previous_count,
            );
        }
        runtime.verify().unwrap();
        subject_loaded.verify().unwrap();
        caller_loaded.verify().unwrap();
        consumer.revalidate();
        println!(
            "{{\"kind\":\"complete\",\"mode\":\"{mode:?}\",\"lookups\":{lookup_count},\"calls\":4}}"
        );
    }
}

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    host::run();
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    panic!("indexed DSO native witness requires Linux x86-64");
}
