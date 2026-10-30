//! Source controls for the actual typed writer; no native-loader claim.
use super::*;

const INTERPRETER: &str = "/lib64/ld-linux-x86-64.so.2";
const BOOTSTRAP: &str = "/owned/router-bootstrap.so";

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

type RawHeader = (u32, u32, u64, u64, u64, u64, u64);

fn phdr(bytes: &mut [u8], index: usize, header: RawHeader) {
    let (kind, flags, offset, address, file_size, memory_size, alignment) = header;
    let at = 64 + index * 56;
    put32(bytes, at, kind);
    put32(bytes, at + 4, flags);
    for (delta, value) in [
        (8, offset),
        (16, address),
        (24, address),
        (32, file_size),
        (40, memory_size),
        (48, alignment),
    ] {
        put64(bytes, at + delta, value);
    }
}

fn original(with_phdr: bool, with_stack: bool) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x2000];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, 0x400300);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    let count = 2 + usize::from(with_phdr) + usize::from(with_stack);
    put16(&mut bytes, 56, count as u16);
    let first = usize::from(with_phdr);
    if with_phdr {
        phdr(
            &mut bytes,
            0,
            (6, 4, 64, 0x400040, count as u64 * 56, count as u64 * 56, 8),
        );
    }
    phdr(
        &mut bytes,
        first,
        (1, 5, 0, 0x400000, 0x1000, 0x1000, 0x1000),
    );
    phdr(
        &mut bytes,
        first + 1,
        (1, 6, 0x1000, 0x600000, 0x1000, 0x2800, 0x1000),
    );
    if with_stack {
        phdr(&mut bytes, first + 2, (0x6474_e551, 6, 0, 0, 0, 0, 16));
    }
    bytes[0x300..0x303].copy_from_slice(&[0x31, 0xc0, 0xc3]);
    bytes[0x1000..0x1010].copy_from_slice(b"original RW data");
    bytes
}

fn policy() -> ImagePolicy {
    ImagePolicy {
        layout: CarrierPolicy {
            page_size: 0x1000,
            user_address_limit: 1 << 47,
            max_added_file_bytes: 0x100000,
            max_output_file_bytes: 0x200000,
            max_program_headers: 64,
            max_virtual_span: 0x1000000,
        },
        dynamic: dynamic::Limits::default(),
        max_images: 8,
        max_new_load_pages: 64,
    }
}

fn startup() -> StaticExecStartup<'static> {
    StaticExecStartup {
        interpreter: INTERPRETER,
        bootstrap_dso: BOOTSTRAP,
        limits: StartupLimits {
            max_interpreter_bytes: 1024,
            max_needed_bytes: 1024,
            max_string_table_bytes: 2048,
            max_dynamic_bytes: 112,
            max_metadata_bytes: 8192,
            max_input_sections: 64,
            max_input_symbols: 128,
            max_input_string_bytes: 8192,
        },
    }
}

fn build_at(
    input: &[u8],
    startup: StaticExecStartup<'_>,
    policy: ImagePolicy,
    carrier: u64,
    image: u64,
) -> Result<CarrierOutput, Error> {
    let input = Elf64::parse(
        input,
        ParseLimits {
            max_program_headers: 64,
        },
    )
    .unwrap();
    let images = [RxImage {
        entry: ElfVaddr(image),
        bytes: vec![0x90, 0xc3],
    }];
    let edits = [DeclaredEdit {
        offset: FileOffset(0x300),
        expected: vec![0x31, 0xc0],
        replacement: vec![0x90, 0x90],
    }];
    let dependencies = [FileRange::checked(FileOffset(0x300), 2).unwrap()];
    append_static_exec_with_router_startup(
        &input,
        ImageRequest {
            carrier_vaddr: ElfVaddr(carrier),
            payload: b"catalog!",
            images: &images,
            source_dependencies: &dependencies,
        },
        &edits,
        policy,
        startup,
    )
}

fn build(
    input: &[u8],
    startup: StaticExecStartup<'_>,
    policy: ImagePolicy,
) -> Result<CarrierOutput, Error> {
    build_at(input, startup, policy, 0x500000, 0x700003)
}

fn bytes(output: &CarrierOutput, range: FileRange) -> &[u8] {
    &output.bytes()[range.start().0 as usize..range.end().0 as usize]
}

fn assert_preservation(original: &[u8], output: &CarrierOutput) {
    let before = Elf64::parse(original, ParseLimits::default()).unwrap();
    let after = Elf64::parse(output.bytes(), ParseLimits::default()).unwrap();
    assert_eq!(after.header().entry, before.header().entry);
    assert_eq!(output.changes().len(), 3);
    assert_eq!(output.changes()[0].kind, ChangeKind::ProgramHeaderOffset);
    assert_eq!(output.changes()[1].kind, ChangeKind::ProgramHeaderCount);
    assert_eq!(output.changes()[2].kind, ChangeKind::DeclaredSource);
    let mut expected = original.to_vec();
    for change in output.changes() {
        let at = change.edit.offset.0 as usize;
        assert_eq!(
            &original[at..at + change.edit.expected.len()],
            change.edit.expected
        );
        expected[at..at + change.edit.replacement.len()].copy_from_slice(&change.edit.replacement);
    }
    assert_eq!(&output.bytes()[..original.len()], expected);
    assert!(
        output
            .original_to_output_header
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    for old in before.program_headers() {
        let index = output.original_to_output_header[old.index];
        if old.kind != SegmentType::ProgramHeaders {
            let from = before.header().program_offset.0 as usize + old.index * 56;
            let to = after.header().program_offset.0 as usize + index * 56;
            assert_eq!(&original[from..from + 56], &output.bytes()[to..to + 56]);
        }
    }
    let loads: Vec<_> = after.segments(SegmentType::Load).collect();
    for pair in loads.windows(2) {
        let end = (pair[0].vaddr.0 + pair[0].memory_size + 0xfff) & !0xfff;
        assert!(end <= (pair[1].vaddr.0 & !0xfff));
    }
    assert_eq!(
        after.executable_bytes(ElfVaddr(0x700003), 2).unwrap(),
        &[0x90, 0xc3]
    );
}

#[test]
fn startup_minimal_static_exec_has_exact_loader_grammar_and_preservation() {
    let input = original(false, false);
    let output = build(&input, startup(), policy()).unwrap();
    assert_preservation(&input, &output);
    let elf = Elf64::parse(output.bytes(), ParseLimits::default()).unwrap();
    let layout = output.startup.as_ref().unwrap();
    assert_eq!(elf.header().program_count, 8);
    assert_eq!(output.new_load_pages, 2);
    assert_eq!(elf.segments(SegmentType::Load).count(), 4);
    assert_eq!(elf.segments(SegmentType::Interpreter).count(), 1);
    assert_eq!(elf.segments(SegmentType::Dynamic).count(), 1);
    assert_eq!(elf.segments(SegmentType::GnuStack).count(), 1);
    assert_eq!(layout.interpreter_index, 1);
    assert_eq!(layout.metadata.start(), output.payload.end());
    assert_eq!(layout.metadata.end(), layout.dynamic.end());
    assert_eq!(
        bytes(&output, layout.interpreter),
        [INTERPRETER.as_bytes(), &[0]].concat()
    );
    assert_eq!(
        bytes(&output, layout.string_table),
        [&[0], BOOTSTRAP.as_bytes(), &[0]].concat()
    );
    assert_eq!(bytes(&output, layout.symbol_table), &[0; 24]);
    assert_eq!(
        bytes(&output, layout.hash_table),
        &[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    let va = |range: FileRange| 0x500000 + range.start().0 - output.program_table.start().0;
    let expected = [
        (1, 1),
        (5, va(layout.string_table)),
        (10, layout.string_table.len()),
        (6, va(layout.symbol_table)),
        (11, 24),
        (4, va(layout.hash_table)),
        (0, 0),
    ];
    let table = bytes(&output, layout.dynamic);
    assert_eq!(table.len(), 112);
    for (index, (tag, value)) in expected.into_iter().enumerate() {
        assert_eq!(
            (word(table, index * 16), word(table, index * 16 + 8)),
            (tag, value)
        );
    }
    for range in [
        layout.interpreter,
        layout.string_table,
        layout.symbol_table,
        layout.hash_table,
        layout.dynamic,
    ] {
        let owner = elf.file_to_virtual(range.start(), range.len()).unwrap();
        assert_eq!(owner.program_header, output.carrier_index);
        assert_eq!(owner.flags.0, 4);
        assert_eq!(owner.virtual_range.start().0, va(range));
    }
    let carrier = &elf.program_headers()[output.carrier_index];
    assert_eq!(carrier.file_size, layout.dynamic.end().0 - carrier.offset.0);
    assert_eq!(carrier.memory_size, carrier.file_size);
    let stack = &elf.program_headers()[layout.stack_index];
    assert_eq!(
        (stack.flags.0, stack.file_size, stack.memory_size),
        (6, 0, 0)
    );
    let dynamic = dynamic::inspect(&elf, dynamic::Limits::default()).unwrap();
    assert_eq!(dynamic.dynamic_entries, 7);
    assert_eq!(dynamic.relocation_records, 0);
    assert!(dynamic.writes.is_empty() && dynamic.symbol_references.is_empty());
    assert!(
        output.dynamic.tables.is_empty(),
        "original inventory stays original"
    );
}

#[test]
fn startup_existing_phdr_and_stack_keep_literal_records_and_prefix_order() {
    for phdr in [false, true] {
        for stack in [false, true] {
            let input = original(phdr, stack);
            let output = build(&input, startup(), policy()).unwrap();
            assert_preservation(&input, &output);
            let elf = Elf64::parse(output.bytes(), ParseLimits::default()).unwrap();
            let layout = output.startup.as_ref().unwrap();
            let first = elf.segments(SegmentType::Load).next().unwrap().index;
            assert!(
                output.phdr_index < layout.interpreter_index && layout.interpreter_index < first
            );
            assert_eq!(elf.segments(SegmentType::ProgramHeaders).count(), 1);
            assert_eq!(elf.segments(SegmentType::GnuStack).count(), 1);
            assert_eq!(elf.header().program_count, 8);
        }
    }
}

#[test]
fn startup_empty_image_set_has_a_trigger_and_existing_apis_remain_plain() {
    let input = original(false, false);
    let elf = Elf64::parse(&input, ParseLimits::default()).unwrap();
    let output = append_static_exec_with_router_startup(
        &elf,
        ImageRequest {
            carrier_vaddr: ElfVaddr(0x500000),
            payload: b"",
            images: &[],
            source_dependencies: &[],
        },
        &[],
        policy(),
        startup(),
    )
    .unwrap();
    let parsed = Elf64::parse(output.bytes(), ParseLimits::default()).unwrap();
    assert!(output.startup.is_some());
    assert_eq!(output.new_load_pages, 1);
    assert_eq!(parsed.header().program_count, 7);
    assert_eq!(parsed.header().entry, elf.header().entry);
    assert_eq!(output.changes().len(), 2);
    assert_eq!(parsed.segments(SegmentType::Dynamic).count(), 1);
    let images = [RxImage {
        entry: ElfVaddr(0x700003),
        bytes: vec![0x90, 0xc3],
    }];
    let request = || ImageRequest {
        carrier_vaddr: ElfVaddr(0x800000),
        payload: b"catalog!",
        images: &images,
        source_dependencies: &[],
    };
    let append = append_carrier_with_images(&elf, request(), &[], policy()).unwrap();
    let interleaved =
        append_exec_carrier_with_interleaved_images(&elf, request(), &[], policy()).unwrap();
    let all = append_exec_carrier_with_interleaved_loads(&elf, request(), &[], policy()).unwrap();
    assert_eq!(append.bytes(), interleaved.bytes());
    assert_eq!(append.bytes(), all.bytes());
    let plain =
        append_read_only_carrier(&elf, ElfVaddr(0x800000), b"catalog!", &[], policy().layout)
            .unwrap();
    for legacy in [&append, &interleaved, &all, &plain] {
        let parsed = Elf64::parse(legacy.bytes(), ParseLimits::default()).unwrap();
        assert!(legacy.startup.is_none());
        assert_eq!(parsed.segments(SegmentType::Interpreter).count(), 0);
        assert_eq!(parsed.segments(SegmentType::Dynamic).count(), 0);
        assert_eq!(parsed.segments(SegmentType::GnuStack).count(), 0);
        assert_eq!(parsed.header().entry, elf.header().entry);
    }
}

#[test]
fn startup_path_and_metadata_limits_have_exact_boundaries() {
    let input = original(false, false);
    let output = build(&input, startup(), policy()).unwrap();
    let mut exact = startup();
    exact.limits.max_interpreter_bytes = INTERPRETER.len() as u64 + 1;
    exact.limits.max_needed_bytes = BOOTSTRAP.len() as u64 + 1;
    exact.limits.max_string_table_bytes = BOOTSTRAP.len() as u64 + 2;
    exact.limits.max_metadata_bytes = output.startup.as_ref().unwrap().metadata.len();
    assert!(build(&input, exact, policy()).is_ok());
    let cases = [
        (
            "startup interpreter bytes",
            exact.limits.max_interpreter_bytes,
        ),
        ("startup needed bytes", exact.limits.max_needed_bytes),
        (
            "startup string table bytes",
            exact.limits.max_string_table_bytes,
        ),
        ("startup dynamic bytes", 112),
        ("startup metadata bytes", exact.limits.max_metadata_bytes),
    ];
    for (index, (resource, required)) in cases.into_iter().enumerate() {
        let mut changed = exact;
        match index {
            0 => changed.limits.max_interpreter_bytes -= 1,
            1 => changed.limits.max_needed_bytes -= 1,
            2 => changed.limits.max_string_table_bytes -= 1,
            3 => changed.limits.max_dynamic_bytes -= 1,
            4 => changed.limits.max_metadata_bytes -= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            build(&input, changed, policy()).unwrap_err(),
            Error::Budget {
                resource,
                required,
                limit: required - 1
            }
        );
    }
    for bad in ["", "/", "relative.so", "/owned/with\0nul"] {
        let mut changed = startup();
        changed.interpreter = bad;
        assert_eq!(
            build(&input, changed, policy()).unwrap_err(),
            Error::Startup(startup::Error::InvalidPath {
                which: "interpreter"
            })
        );
        let mut changed = startup();
        changed.bootstrap_dso = bad;
        assert_eq!(
            build(&input, changed, policy()).unwrap_err(),
            Error::Startup(startup::Error::InvalidPath { which: "needed" })
        );
    }
}

#[test]
fn startup_all_main_resources_include_added_headers_pages_and_original_high_hull() {
    let mut input = original(false, false);
    phdr(
        &mut input,
        1,
        (1, 6, 0x1000, 0x900000, 0x1000, 0x2800, 0x1000),
    );
    let output = build(&input, startup(), policy()).unwrap();
    let mut exact = policy();
    exact.layout.max_program_headers = 8;
    exact.max_images = 1;
    exact.max_new_load_pages = 2;
    exact.layout.max_added_file_bytes = output.bytes().len() as u64 - input.len() as u64;
    exact.layout.max_output_file_bytes = output.bytes().len() as u64;
    exact.layout.max_virtual_span = 0x503000;
    exact.dynamic.metadata_records = 3;
    exact.dynamic.metadata_bytes = 48 + BOOTSTRAP.len() + 2;
    assert!(build(&input, startup(), exact).is_ok());
    let cases = [
        ("program headers", 8),
        ("images", 1),
        ("new load pages", 2),
        ("added file bytes", exact.layout.max_added_file_bytes),
        ("output file bytes", exact.layout.max_output_file_bytes),
        ("virtual span", 0x503000),
        ("startup dynamic entries", 7),
        ("startup metadata scan records", 3),
        (
            "startup metadata scan bytes",
            exact.dynamic.metadata_bytes as u64,
        ),
    ];
    for (index, (resource, required)) in cases.into_iter().enumerate() {
        let mut changed = exact;
        match index {
            0 => changed.layout.max_program_headers -= 1,
            1 => changed.max_images -= 1,
            2 => changed.max_new_load_pages -= 1,
            3 => changed.layout.max_added_file_bytes -= 1,
            4 => changed.layout.max_output_file_bytes -= 1,
            5 => changed.layout.max_virtual_span -= 1,
            6 => changed.dynamic.dynamic_entries = 6,
            7 => changed.dynamic.metadata_records = 2,
            8 => changed.dynamic.metadata_bytes -= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            build(&input, startup(), changed).unwrap_err(),
            Error::Budget {
                resource,
                required,
                limit: required - 1
            }
        );
    }
    let long = "/".to_owned() + &"a".repeat(4100);
    let mut larger = startup();
    larger.interpreter = &long;
    larger.limits.max_interpreter_bytes = 8192;
    let expanded = build(&input, larger, policy()).unwrap();
    assert_eq!(expanded.new_load_pages, 3);
    assert!(build_at(&input, startup(), policy(), 0x500000, 0x501003).is_ok());
    assert_eq!(
        build_at(&input, larger, policy(), 0x500000, 0x501003).unwrap_err(),
        Error::InvalidImage { index: 0 }
    );
    let mut no_extra_page = policy();
    no_extra_page.max_new_load_pages = 2;
    assert_eq!(
        build(&input, larger, no_extra_page).unwrap_err(),
        Error::Budget {
            resource: "new load pages",
            required: 3,
            limit: 2
        }
    );
}

#[test]
fn startup_refuses_existing_dynamic_tls_unsafe_permissions_and_wrong_object() {
    let mut input = original(false, false);
    put16(&mut input, 16, 3);
    assert_eq!(
        build(&input, startup(), policy()).unwrap_err(),
        Error::UnsupportedObjectType
    );
    for kind in [2, 3, 7] {
        let mut input = original(false, false);
        put16(&mut input, 56, 3);
        phdr(&mut input, 2, (kind, 4, 0x1000, 0x600000, 8, 8, 1));
        assert!(matches!(
            build(&input, startup(), policy()),
            Err(Error::Startup(startup::Error::UnsupportedInputSegment {
                index: 2,
                ..
            }))
        ));
    }
    let mut input = original(false, false);
    put32(&mut input, 64 + 4, 7);
    assert_eq!(
        build(&input, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::InvalidLoadPermissions { index: 0 })
    );
    let mut input = original(false, true);
    put32(&mut input, 64 + 2 * 56 + 4, 7);
    assert_eq!(
        build(&input, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::InvalidStack { index: 2 })
    );
    let mut input = original(false, true);
    put16(&mut input, 56, 4);
    phdr(&mut input, 3, (0x6474_e551, 6, 0, 0, 0, 0, 16));
    assert_eq!(
        build(&input, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::MultipleStacks)
    );
}

#[test]
fn startup_keeps_complete_bss_pages_metadata_and_source_ownership_guards() {
    let input = original(false, false);
    assert!(build_at(&input, startup(), policy(), 0x603000, 0x700003).is_ok());
    assert_eq!(
        build_at(&input, startup(), policy(), 0x602000, 0x700003).unwrap_err(),
        Error::CarrierPlacement
    );
    assert_eq!(
        build_at(&input, startup(), policy(), 0x500001, 0x700003).unwrap_err(),
        Error::CarrierPlacement
    );
    assert_eq!(
        build_at(&input, startup(), policy(), 0x500000, 0x602003).unwrap_err(),
        Error::InvalidImage { index: 0 }
    );
    let mut metadata = input.clone();
    put16(&mut metadata, 56, 3);
    phdr(&mut metadata, 2, (4, 4, 0x1000, 0x500100, 4, 4, 1));
    assert_eq!(
        build(&metadata, startup(), policy()).unwrap_err(),
        Error::CarrierMetadataOverlap { index: 2 }
    );
    let mut stale = input.clone();
    stale[0x300] = 0xcc;
    assert_eq!(
        build(&stale, startup(), policy()).unwrap_err(),
        Error::StaleEdit { index: 0 }
    );
    let mut low = policy();
    low.layout.user_address_limit = 0x700000;
    assert_eq!(
        build(&input, startup(), low).unwrap_err(),
        Error::AddressLimit { index: None }
    );
}

fn with_static_symbols() -> Vec<u8> {
    let mut bytes = original(false, false);
    bytes.resize(0x2200, 0);
    put64(&mut bytes, 40, 0x2100);
    put16(&mut bytes, 58, 64);
    put16(&mut bytes, 60, 4);
    bytes[0x2000..0x2008].copy_from_slice(b"\0_start\0");
    let strings = 0x2100 + 64;
    put32(&mut bytes, strings + 4, 3);
    put64(&mut bytes, strings + 24, 0x2000);
    put64(&mut bytes, strings + 32, 8);
    put64(&mut bytes, strings + 48, 1);
    let symbols = 0x2100 + 128;
    put32(&mut bytes, symbols + 4, 2);
    put64(&mut bytes, symbols + 24, 0x2020);
    put64(&mut bytes, symbols + 32, 48);
    put32(&mut bytes, symbols + 40, 1);
    put32(&mut bytes, symbols + 44, 1);
    put64(&mut bytes, symbols + 48, 8);
    put64(&mut bytes, symbols + 56, 24);
    let text = 0x2100 + 192;
    put32(&mut bytes, text + 4, 1);
    put64(&mut bytes, text + 8, 6);
    put64(&mut bytes, text + 16, 0x400300);
    put64(&mut bytes, text + 24, 0x300);
    put64(&mut bytes, text + 32, 3);
    put64(&mut bytes, text + 48, 1);
    put32(&mut bytes, 0x2038, 1);
    bytes[0x203c] = 0x12;
    put16(&mut bytes, 0x203e, 3);
    put64(&mut bytes, 0x2040, 0x400300);
    put64(&mut bytes, 0x2048, 3);
    bytes
}

#[test]
fn startup_preserves_static_symbols_and_refuses_dynamic_resolver_startup_sections() {
    let input = with_static_symbols();
    let output = build(&input, startup(), policy()).unwrap();
    assert_preservation(&input, &output);
    for kind in [4, 6, 9, 11, 14, 15, 16, 19] {
        let mut changed = input.clone();
        put32(&mut changed, 0x2100 + 128 + 4, kind);
        assert_eq!(
            build(&changed, startup(), policy()).unwrap_err(),
            Error::Startup(startup::Error::UnsupportedSection { index: 2, kind })
        );
    }
    let mut changed = input.clone();
    changed[0x203c] = 0x1a;
    assert_eq!(
        build(&changed, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::ResolverSymbol {
            section: 2,
            index: 1
        })
    );
    let mut changed = input.clone();
    changed[0x2001..0x2008].copy_from_slice(b"_init\0\0");
    assert_eq!(
        build(&changed, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::StartupSymbol {
            section: 2,
            index: 1
        })
    );
    let mut changed = input.clone();
    put64(&mut changed, 0x2100 + 192 + 8, 0x406);
    assert_eq!(
        build(&changed, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::StartupSection { index: 3 })
    );
    let mut changed = input.clone();
    changed[0x2001..0x2008].copy_from_slice(b".init\0\0");
    put16(&mut changed, 62, 1);
    put32(&mut changed, 0x2100 + 192, 1);
    assert_eq!(
        build(&changed, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::StartupSection { index: 3 })
    );
}

#[test]
fn startup_input_metadata_is_bounded_checked_and_protected_from_source_edits() {
    let input = with_static_symbols();
    let mut exact = startup();
    exact.limits.max_input_sections = 4;
    exact.limits.max_input_symbols = 2;
    exact.limits.max_input_string_bytes = 8;
    assert!(build(&input, exact, policy()).is_ok());
    for (index, resource, required) in [
        (0, "startup input sections", 4),
        (1, "startup input symbols", 2),
        (2, "startup input string bytes", 8),
    ] {
        let mut changed = exact;
        match index {
            0 => changed.limits.max_input_sections -= 1,
            1 => changed.limits.max_input_symbols -= 1,
            _ => changed.limits.max_input_string_bytes -= 1,
        }
        assert_eq!(
            build(&input, changed, policy()).unwrap_err(),
            Error::Budget {
                resource,
                required,
                limit: required - 1
            }
        );
    }
    for (at, value) in [
        (0x2100 + 128 + 40, 99),
        (0x2100 + 128 + 56, 16),
        (0x2038, 99),
    ] {
        let mut changed = input.clone();
        put32(&mut changed, at, value);
        assert!(matches!(
            build(&changed, startup(), policy()),
            Err(Error::Startup(startup::Error::InvalidSection { .. }))
        ));
    }
    let mut changed = input.clone();
    changed[0x2100] = 1;
    assert_eq!(
        build(&changed, startup(), policy()).unwrap_err(),
        Error::Startup(startup::Error::InvalidSection { index: 0 })
    );
    let mut changed = input.clone();
    put64(&mut changed, 0x2100 + 64 + 24, u64::MAX - 3);
    assert!(matches!(
        build(&changed, startup(), policy()),
        Err(Error::Arithmetic { .. })
    ));
    let mut changed = input.clone();
    changed[0x380..0x388].copy_from_slice(b"\0_start\0");
    put64(&mut changed, 0x2100 + 64 + 24, 0x380);
    let elf = Elf64::parse(&changed, ParseLimits::default()).unwrap();
    let dependency = [FileRange::checked(FileOffset(0x380), 8).unwrap()];
    let edit = [DeclaredEdit {
        offset: FileOffset(0x381),
        expected: b"_start".to_vec(),
        replacement: b"change".to_vec(),
    }];
    assert_eq!(
        append_static_exec_with_router_startup(
            &elf,
            ImageRequest {
                carrier_vaddr: ElfVaddr(0x500000),
                payload: b"",
                images: &[],
                source_dependencies: &dependency,
            },
            &edit,
            policy(),
            startup()
        )
        .unwrap_err(),
        Error::InvalidDependency { index: 0 }
    );
}
