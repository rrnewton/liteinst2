//! Full safe carrier API with a source-owned NOP5/RET model. No mappings,
//! generated execution, CFI registration or native-loader qualification.
use formats::ContentId;
use li2core::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    ResumeObligation, SourceIdentity,
};
use li2core::emission::{
    ArtifactEmission, ArtifactFrameTrace, ArtifactRequest, PlanningSite, SymbolicHook,
    TargetProfile,
};
use li2core::frame_trace::FrameTraceLimits;
use li2core::generated_unwind::Limits;
use li2core::generated_unwind::artifact::{
    ArtifactFramePreservingHook, ArtifactSourceCertificate, PreparedArtifactUnwind,
};
use li2core::planner::HookSemantics;
use li2core::quiescent::{
    AllocationPolicy, SearchPolicy, TacticPolicy, plan_install_with_emission,
};
use li2core::trampoline::SavedExtendedStateLayout;
use liteinst_rewrite::carrier::elf64::{Elf64, ElfVaddr, FileRange, ParseLimits};
use liteinst_rewrite::carrier::unwind::{self, IndexLimits, IndexedUnwindRequest, OriginalIndex};
use liteinst_rewrite::carrier::{
    CarrierOutput, CarrierPolicy, DeclaredEdit, ImagePolicy, ImageRequest, RxImage, dynamic,
};
use std::sync::Arc;

#[path = "../examples/indexed_dso_support/leaf.rs"]
mod leaf;
#[path = "indexed_unwind/model.rs"]
mod model;
use model::{HOOK, IMAGE, SITE, input, parse, policy};
const DOMAIN: u64 = 7;
const PAYLOAD: &[u8] = b"indexed-unwind-pure-fixture-v1";

fn identity(bytes: &[u8]) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity(ContentId::of(bytes).0),
        mapping: 3,
        generation: 1,
    }
}
fn trace(bytes: &[u8], hook: u64) -> ArtifactFrameTrace {
    let function = AddressRange::new(SITE, 6).unwrap();
    let entries = LegalEntrySet {
        identity: identity(bytes),
        scope: function,
        provenance: EntryProvenance::Declared("source-owned pure NOP5/RET model".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: [SITE, SITE + 5]
            .map(|address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(IMAGE, 8192).unwrap()],
        preferred_address: Some(IMAGE),
        max_candidates: 256,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            DOMAIN,
        )
        .unwrap(),
        SymbolicHook {
            identity: 11,
            address: Some(hook),
        },
        vec![AddressRange::new(0, bytes.len()).unwrap()],
    );
    let elf = parse(bytes);
    let code = elf.executable_bytes(ElfVaddr(SITE), 6).unwrap();
    plan_install_with_emission(&ArtifactRequest {
        site: PlanningSite {
            identity: identity(bytes),
            code,
            base_address: SITE,
            function,
            block: function,
            logical_pc: SITE,
            entries: &entries,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    })
    .unwrap()
    .frame_trace_nop5(&emission, FrameTraceLimits::default())
    .unwrap()
}
struct Fixture {
    bytes: Vec<u8>,
    trace: ArtifactFrameTrace,
    images: Vec<RxImage>,
    dependencies: Vec<FileRange>,
    edits: Vec<DeclaredEdit>,
    records: PreparedArtifactUnwind,
}
impl Fixture {
    fn request(&self) -> ImageRequest<'_> {
        ImageRequest {
            carrier_vaddr: ElfVaddr(0x8000),
            payload: PAYLOAD,
            images: &self.images,
            source_dependencies: &self.dependencies,
        }
    }
    fn prepare_at(&self, address: u64) -> PreparedArtifactUnwind {
        let elf = parse(&self.bytes);
        let index =
            OriginalIndex::inspect(&elf, IndexLimits::default(), dynamic::Limits::default())
                .unwrap();
        let record = index.source_record(SITE).unwrap();
        assert_eq!(
            leaf::prove(
                elf.executable_bytes(ElfVaddr(SITE), 6).unwrap(),
                SITE,
                SITE,
                &record
            )
            .unwrap(),
            [SITE, SITE + 5]
        );
        // SAFETY: this test owns the complete immutable model. SITE is NOP5,
        // SITE+5 is RET; there is no prefix, other entry or resume. The retained
        // source FDE covers these exact heads with entry CFA=RSP+8, RA=CFA-8
        // and six explicit SameValue rules. The unique byte owners are checked
        // by OriginalIndex. No emitted artifact is mapped or executed here.
        let source = Arc::new(unsafe {
            ArtifactSourceCertificate::certify(
                identity(&self.bytes),
                DOMAIN,
                vec![record],
                vec![SITE, SITE + 5],
                Limits::default(),
            )
            .unwrap()
        });
        // SAFETY: the source-owned observer is a single RET in this immutable
        // model. Under the required SysV entry it returns normally without any
        // context/caller memory changes or external dependencies. Runtime
        // admission/lifetimes remain unqualified; this test never executes it.
        let hook = unsafe {
            ArtifactFramePreservingHook::certify(
                identity(&self.bytes),
                DOMAIN,
                self.trace.symbolic_hook(),
            )
            .unwrap()
        };
        PreparedArtifactUnwind::prepare(&self.trace, source, hook, address, Limits::default())
            .unwrap()
    }
    fn new() -> Self {
        let bytes = input();
        let trace = trace(&bytes, HOOK);
        let elf = parse(&bytes);
        let images = vec![RxImage {
            entry: ElfVaddr(trace.image().address()),
            bytes: trace.image().bytes().to_vec(),
        }];
        let dependencies = trace
            .source_step()
            .parts()
            .dependencies
            .iter()
            .map(|range| {
                let mapping = elf
                    .virtual_to_storage(ElfVaddr(range.start()), range.len())
                    .unwrap();
                let liteinst_rewrite::carrier::elf64::Storage::FileBacked(file) = mapping.storage
                else {
                    panic!("source file dependency")
                };
                file
            })
            .collect::<Vec<_>>();
        let edits = trace
            .source_step()
            .parts()
            .writes
            .iter()
            .map(|write| {
                let mapping = elf
                    .virtual_to_storage(ElfVaddr(write.address), write.bytes.len() as u64)
                    .unwrap();
                let liteinst_rewrite::carrier::elf64::Storage::FileBacked(file) = mapping.storage
                else {
                    panic!("source file edit")
                };
                DeclaredEdit {
                    offset: file.start(),
                    expected: elf
                        .executable_bytes(ElfVaddr(write.address), write.bytes.len() as u64)
                        .unwrap()
                        .to_vec(),
                    replacement: write.bytes.clone(),
                }
            })
            .collect::<Vec<_>>();
        let request = ImageRequest {
            carrier_vaddr: ElfVaddr(0x8000),
            payload: PAYLOAD,
            images: &images,
            source_dependencies: &dependencies,
        };
        let address = unwind::metadata_address(&elf, &request, policy())
            .unwrap()
            .0;
        let index =
            OriginalIndex::inspect(&elf, IndexLimits::default(), dynamic::Limits::default())
                .unwrap();
        let source_record = index.source_record(SITE).unwrap();
        assert_eq!(
            leaf::prove(
                elf.executable_bytes(ElfVaddr(SITE), 6).unwrap(),
                SITE,
                SITE,
                &source_record
            )
            .unwrap(),
            [SITE, SITE + 5]
        );
        // SAFETY: identical source/hook model and point proof as prepare_at.
        let source = Arc::new(unsafe {
            ArtifactSourceCertificate::certify(
                identity(&bytes),
                DOMAIN,
                vec![source_record],
                vec![SITE, SITE + 5],
                Limits::default(),
            )
            .unwrap()
        });
        // SAFETY: the exact single-RET hook described in prepare_at.
        let hook = unsafe {
            ArtifactFramePreservingHook::certify(identity(&bytes), DOMAIN, trace.symbolic_hook())
                .unwrap()
        };
        let records =
            PreparedArtifactUnwind::prepare(&trace, source, hook, address, Limits::default())
                .unwrap();
        Self {
            bytes,
            trace,
            images,
            dependencies,
            edits,
            records,
        }
    }
    fn append(&self) -> Result<CarrierOutput, unwind::Error> {
        unwind::append_carrier_with_indexed_unwind(
            &parse(&self.bytes),
            self.request(),
            &self.edits,
            policy(),
            IndexedUnwindRequest {
                trace: &self.trace,
                records: &self.records,
                limits: IndexLimits::default(),
            },
        )
    }
}

#[test]
fn combined_index_preserves_originals_and_finds_generated_at_both_biases() {
    let fixture = Fixture::new();
    let output = fixture.append().unwrap();
    let original = parse(&fixture.bytes);
    let index = OriginalIndex::inspect(
        &original,
        IndexLimits::default(),
        dynamic::Limits::default(),
    )
    .unwrap();
    let placement = output.unwind.as_ref().unwrap();
    assert_eq!((placement.original_fdes, placement.generated_fdes), (2, 1));
    assert_eq!(placement.records_address.0, fixture.records.address());
    assert!(!fixture.records.qualification_complete());
    assert_eq!(placement.source_step, *fixture.trace.source_step());
    assert_eq!(placement.bias_domain, DOMAIN);
    assert_eq!(placement.symbolic_hook, fixture.trace.symbolic_hook());
    assert_eq!(
        placement.artifact_requirements,
        fixture.trace.image().metadata().requirements()
    );
    assert_eq!(
        placement.frame_requirements,
        fixture.trace.trace().requirements()
    );
    let mut expected = fixture.bytes.clone();
    for change in output.changes() {
        let at = change.edit.offset.0 as usize;
        assert_eq!(
            &expected[at..at + change.edit.expected.len()],
            &change.edit.expected
        );
        expected[at..at + change.edit.replacement.len()].copy_from_slice(&change.edit.replacement);
    }
    assert_eq!(&output.bytes()[..expected.len()], expected);
    for dependency in index.dependencies() {
        let range = dependency.start().0 as usize..dependency.end().0 as usize;
        assert_eq!(&output.bytes()[range.clone()], &fixture.bytes[range]);
    }
    assert_eq!(
        &output.bytes()[placement.records.start().0 as usize..placement.records.end().0 as usize],
        fixture.records.bytes()
    );
    let intervals: Vec<_> =
        index
            .intervals()
            .chain(fixture.records.fdes().iter().map(|&(start, end, offset)| {
                (start, end, fixture.records.address() + offset as u64)
            }))
            .collect();
    let cies = [model::STREAM, fixture.records.address()];
    for bias in [0, 0x7000_0000_0000] {
        for &(start, end, fde) in &intervals {
            for pc in [start, end - 1] {
                assert_eq!(
                    model::lookup(
                        output.bytes(),
                        placement.header_address.0,
                        bias,
                        bias + pc,
                        &cies
                    )
                    .unwrap(),
                    Some(bias + fde)
                );
            }
            assert_eq!(
                model::lookup(
                    output.bytes(),
                    placement.header_address.0,
                    bias,
                    bias + end,
                    &cies
                )
                .unwrap(),
                None
            );
        }
        let call = fixture.trace.trace().calls()[0];
        let fde = fixture.records.address() + fixture.records.fdes()[0].2 as u64;
        for pc in [call.call_pc(), call.return_pc() - 1, call.return_pc()] {
            assert_eq!(
                model::lookup(
                    output.bytes(),
                    placement.header_address.0,
                    bias,
                    bias + pc,
                    &cies
                )
                .unwrap(),
                Some(bias + fde)
            );
        }
        // Keeping only the original index really loses generated lookup. This
        // is a byte-reader control, not evidence about a loaded libgcc.
        assert_eq!(
            model::lookup(
                output.bytes(),
                index.header_address().0,
                bias,
                bias + IMAGE,
                &cies
            )
            .unwrap(),
            None
        );
        assert_eq!(
            model::lookup(
                output.bytes(),
                index.header_address().0,
                bias,
                bias + SITE,
                &cies
            )
            .unwrap(),
            Some(bias + intervals[0].2)
        );
    }
}

#[test]
fn complete_source_identity_rejects_unrelated_original_byte_change() {
    let mut fixture = Fixture::new();
    fixture.bytes[0x900] ^= 1;
    assert_eq!(fixture.append().err(), Some(unwind::Error::SourceBinding));
}

#[test]
fn image_and_source_edit_must_be_exact_planner_products() {
    let mut fixture = Fixture::new();
    fixture.images[0].bytes[0] ^= 1;
    assert_eq!(fixture.append().err(), Some(unwind::Error::ImageBinding));
    fixture.images[0].bytes[0] ^= 1;
    fixture.edits[0].replacement[1] ^= 1;
    assert_eq!(fixture.append().err(), Some(unwind::Error::EditBinding));
    fixture.edits[0].replacement[1] ^= 1;
    fixture.edits.clear();
    assert_eq!(fixture.append().err(), Some(unwind::Error::EditBinding));
}

#[test]
fn extra_images_and_incomplete_dependencies_refuse_without_output() {
    let mut fixture = Fixture::new();
    fixture.images.push(RxImage {
        entry: ElfVaddr(0x14000),
        bytes: vec![0xc3],
    });
    assert_eq!(fixture.append().err(), Some(unwind::Error::ImageBinding));
    fixture.images.pop();
    fixture.dependencies.clear();
    assert_eq!(fixture.append().err(), Some(unwind::Error::SourceBinding));
}

#[test]
fn records_stay_bound_to_exact_metadata_coordinate_and_trace() {
    let fixture = Fixture::new();
    let misplaced = fixture.prepare_at(fixture.records.address() + 8);
    assert_eq!(
        unwind::append_carrier_with_indexed_unwind(
            &parse(&fixture.bytes),
            fixture.request(),
            &fixture.edits,
            policy(),
            IndexedUnwindRequest {
                trace: &fixture.trace,
                records: &misplaced,
                limits: IndexLimits::default()
            }
        )
        .err(),
        Some(unwind::Error::MetadataAddress)
    );
    let different = trace(&fixture.bytes, HOOK + 1);
    assert_eq!(
        unwind::append_carrier_with_indexed_unwind(
            &parse(&fixture.bytes),
            fixture.request(),
            &fixture.edits,
            policy(),
            IndexedUnwindRequest {
                trace: &different,
                records: &fixture.records,
                limits: IndexLimits::default()
            }
        )
        .err(),
        Some(unwind::Error::SourceBinding)
    );
    let mut copied = fixture.records.source_records().to_vec();
    copied[0].cie[0] ^= 1;
    assert_ne!(copied[0].cie, fixture.records.source_records()[0].cie);
    assert!(
        fixture.append().is_ok(),
        "mutating a copied record grants no mutation authority"
    );
}

#[test]
fn exact_leaf_proof_distinguishes_undefined_rules_and_compiled_prefix_effects() {
    let bytes = input();
    let elf = parse(&bytes);
    let index =
        OriginalIndex::inspect(&elf, IndexLimits::default(), dynamic::Limits::default()).unwrap();
    let record = index.source_record(SITE).unwrap();
    let original = elf.executable_bytes(ElfVaddr(SITE), 6).unwrap();
    assert_eq!(
        leaf::prove(original, SITE, SITE, &record).unwrap(),
        [SITE, SITE + 5]
    );
    for column in [3, 6, 12, 13, 14, 15] {
        let mut undefined = record.clone();
        let at = undefined
            .cie
            .windows(2)
            .position(|bytes| bytes == [8, column])
            .unwrap();
        undefined.cie[at] = 7;
        assert_eq!(
            leaf::prove(original, SITE, SITE, &undefined),
            Err(leaf::Error::Row)
        );
    }
    let mut bad_cfa = record.clone();
    let at = bad_cfa
        .cie
        .windows(3)
        .position(|bytes| bytes == [0x0c, 7, 8])
        .unwrap();
    bad_cfa.cie[at + 2] = 16;
    assert_eq!(
        leaf::prove(original, SITE, SITE, &bad_cfa),
        Err(leaf::Error::Row)
    );
    let mut bad_return = record.clone();
    let at = bad_return
        .cie
        .windows(2)
        .position(|bytes| bytes == [0x90, 1])
        .unwrap();
    bad_return.cie[at + 1] = 2;
    assert_eq!(
        leaf::prove(original, SITE, SITE, &bad_return),
        Err(leaf::Error::Row)
    );
    for prefix in [
        &[0x48, 0x89, 0xc3][..],          // MOV RBX,RAX
        &[0x48, 0x89, 0x04, 0x24][..],    // MOV [RSP],RAX
        &[0x48, 0x8d, 0x64, 0x24, 8][..], // LEA RSP,[RSP+8]
        &[0x8e, 0xe0][..],                // MOV FS,AX (non-GPR state)
        &[0x53][..],                      // PUSH RBX
        &[0xe8, 0, 0, 0, 0][..],          // CALL next
        &[0xeb, 0][..],                   // JMP next
    ] {
        let mut code = prefix.to_vec();
        code.extend_from_slice(original);
        assert_eq!(
            leaf::prove(&code, SITE - prefix.len() as u64, SITE, &record),
            Err(leaf::Error::Prefix)
        );
    }
    let prefix = [0x89, 0xf8]; // MOV EAX,EDI preserves the entry frame.
    let mut code = prefix.to_vec();
    code.extend_from_slice(original);
    let base = SITE - prefix.len() as u64;
    let mut moved = record.clone();
    moved.fde[8..12].copy_from_slice(
        &i32::try_from(i128::from(base) - i128::from(moved.fde_address + 8))
            .unwrap()
            .to_le_bytes(),
    );
    moved.fde[12..16].copy_from_slice(&(code.len() as i32).to_le_bytes());
    assert_eq!(
        leaf::prove(&code, base, SITE, &moved).unwrap(),
        [base, SITE, SITE + 5]
    );
}

#[test]
fn exact_leaf_proof_refuses_internal_reentry_and_retains_later_loop() {
    let bytes = input();
    let elf = parse(&bytes);
    let index =
        OriginalIndex::inspect(&elf, IndexLimits::default(), dynamic::Limits::default()).unwrap();
    let mut record = index.source_record(SITE).unwrap();
    // NOP5; PUSH RBX; JMP back to NOP5; RET. A first-visit-only prefix
    // check accepts the false entry row on its second visit; this must refuse.
    for delta in [0xf8, 0xf9, 0xfd] {
        // selected, its interior, continuation
        let code = [0x0f, 0x1f, 0x44, 0, 0, 0x53, 0xeb, delta, 0xc3];
        record.fde[12..16].copy_from_slice(&(code.len() as i32).to_le_bytes());
        assert_eq!(
            leaf::prove(&code, SITE, SITE, &record),
            Err(leaf::Error::Flow)
        );
    }
    // NOP5; NOP; SUB EAX,1; JNZ SUB; RET. The later loop has no edge
    // into the protected prefix/points and leaves the entry frame intact.
    let code = [
        0x0f, 0x1f, 0x44, 0, 0, 0x90, 0x83, 0xe8, 1, 0x75, 0xfb, 0xc3,
    ];
    record.fde[12..16].copy_from_slice(&(code.len() as i32).to_le_bytes());
    assert_eq!(
        leaf::prove(&code, SITE, SITE, &record).unwrap(),
        [SITE, SITE + 5, SITE + 6, SITE + 9, SITE + 11]
    );
    // A direct target in the middle of SUB is also outside the closed CFG.
    let mut interior = code;
    interior[10] = 0xfc;
    assert_eq!(
        leaf::prove(&interior, SITE, SITE, &record),
        Err(leaf::Error::Flow)
    );
    let mut indirect = code[..6].to_vec();
    indirect.extend_from_slice(&[0xff, 0xe0]); // JMP RAX
    record.fde[12..16].copy_from_slice(&(indirect.len() as i32).to_le_bytes());
    assert_eq!(
        leaf::prove(&indirect, SITE, SITE, &record),
        Err(leaf::Error::Flow)
    );
}

#[test]
fn independent_lookup_refuses_wrong_cie_reference_or_encoding() {
    let fixture = Fixture::new();
    let output = fixture.append().unwrap();
    let placement = output.unwind.as_ref().unwrap();
    let cies = [model::STREAM, fixture.records.address()];
    let parsed = parse(output.bytes());
    let original = parse(&fixture.bytes);
    let original_index = OriginalIndex::inspect(
        &original,
        IndexLimits::default(),
        dynamic::Limits::default(),
    )
    .unwrap();
    let source_fde = original_index.source_record(SITE).unwrap().fde_address;
    let generated_fde = fixture.records.address() + fixture.records.fdes()[0].2 as u64;
    for (cie, fde, pc) in [
        (model::STREAM, source_fde, SITE),
        (fixture.records.address(), generated_fde, IMAGE),
    ] {
        for address in [cie + 16, fde + 4] {
            let mapped = parsed.virtual_to_storage(ElfVaddr(address), 1).unwrap();
            let liteinst_rewrite::carrier::elf64::Storage::FileBacked(file) = mapped.storage else {
                panic!("CFI byte owner")
            };
            let mut changed = output.bytes().to_vec();
            changed[file.start().0 as usize] ^= 1;
            assert_eq!(
                model::lookup(&changed, placement.header_address.0, 0, pc, &cies),
                Err(model::LookupError::Cie)
            );
        }
        assert_eq!(
            model::lookup(output.bytes(), placement.header_address.0, 0, pc, &cies).unwrap(),
            Some(fde)
        );
    }
}
