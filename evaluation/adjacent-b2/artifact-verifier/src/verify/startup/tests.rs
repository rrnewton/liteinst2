//! Complete synthetic 80/16 and107/26 positives and bound-repaired negatives.
//! These are structural controls; they are not corpus/native executions.
use super::*;
use crate::Memory;

struct Writer(Vec<u8>);
impl Writer {
    fn n(&mut self, n: u64) {
        self.0.extend_from_slice(&n.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.n(b.len() as u64);
        self.0.extend_from_slice(b);
    }
    fn span(&mut self, s: boot::Span) {
        self.n(s.start);
        self.n(s.len);
    }
    fn blob(&mut self, b: &boot::Blob) {
        self.n(b.address);
        self.bytes(&b.bytes);
    }
    fn pairs(&mut self, p: &[(u64, u64)]) {
        self.n(p.len() as u64);
        for &(a, b) in p {
            self.n(a);
            self.n(b);
        }
    }
}
// Independent fixture encoder: never Catalog::new/decode or production compiler.
fn encode(x: &boot::Input) -> Vec<u8> {
    let mut w = Writer(b"LI2BOOT\0".to_vec());
    w.n(2);
    w.n(x.program);
    let p = &x.policy;
    w.bytes(&p.interpreter);
    w.bytes(&p.bootstrap_dso);
    w.n(p.dependencies.len() as u64);
    for d in &p.dependencies {
        w.bytes(&d.path);
        w.0.extend_from_slice(&d.identity.0);
    }
    w.span(p.app_stack);
    w.n(p.hook_pc);
    w.n(p.hook_id);
    w.0.extend_from_slice(&p.qualification_contract.0);
    let s = &p.state;
    for n in [s.domain, s.format, s.allocation, s.image, s.mask] {
        w.n(n);
    }
    w.n(s.components.len() as u64);
    for &(a, b, c) in &s.components {
        w.n(a);
        w.n(b);
        w.n(c);
    }
    for b in [
        &x.original,
        &x.main,
        &x.selection,
        &x.metadata,
        &x.target,
        &x.ledger,
    ] {
        w.bytes(b);
    }
    w.n(x.heads.len() as u64);
    for &h in &x.heads {
        w.n(h);
    }
    w.n(x.steps.len() as u64);
    for s in &x.steps {
        w.n(s.selected_id);
        w.n(s.logical);
        w.n(s.physical);
        w.span(s.displaced);
        match s.kind {
            boot::Kind::Relocation => w.n(0),
            boot::Kind::GeneralizedPun(p) | boot::Kind::PrefixedPun(p) => {
                w.n(if matches!(s.kind, boot::Kind::GeneralizedPun(_)) {
                    1
                } else {
                    2
                });
                w.n(p.instruction_len);
                w.n(p.prefixes);
                w.span(p.consumed);
                w.span(p.target_window);
                w.span(p.store);
            }
        }
        match s.neighbor {
            None => w.n(0),
            Some(n) => {
                w.n(1);
                for v in [
                    n.selected,
                    n.selected_len,
                    n.victim,
                    n.victim_len,
                    n.relay,
                    n.rel8 as u8 as u64,
                    n.selected_target,
                    n.victim_target,
                ] {
                    w.n(v);
                }
            }
        }
        for list in [&s.reads, &s.writes] {
            w.n(list.len() as u64);
            for b in list {
                w.blob(b);
            }
        }
        w.n(s.dependencies.len() as u64);
        for &d in &s.dependencies {
            w.span(d);
        }
        w.span(s.allocation);
        w.n(s.image);
        w.n(s.obligations.len() as u64);
        for o in &s.obligations {
            w.n(o.original);
            if let Some(g) = o.generated {
                w.n(1);
                w.n(g);
            } else {
                w.n(0);
                w.n(0);
            }
        }
    }
    w.n(x.images.len() as u64);
    for i in &x.images {
        w.blob(&i.body);
        w.pairs(&i.entries);
        w.pairs(&i.requirements);
    }
    let digest = ContentId::of(&w.0);
    w.0.extend_from_slice(&digest.0);
    w.0
}
fn dependency() -> Vec<u8> {
    let mut b = vec![0; 8192];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&3u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&4u16.to_le_bytes());
    for (i, (kind, flags, off, pc, len, align)) in [
        (1u32, 5u32, 0u64, 0u64, 4096u64, 4096u64),
        (1, 6, 4096, 4096, 4096, 4096),
        (0x6474e552, 4, 4096, 4096, 4096, 1),
        (0x6474e551, 6, 0, 0, 0, 16),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        b[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        for (j, v) in [off, pc, pc, len, len, align].into_iter().enumerate() {
            b[at + 8 + j * 8..at + 16 + j * 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    b
}
fn seal(original: &[u8], product: &mut Memory) {
    product.0.remove("COMPLETE");
    product.0.remove("bundle-index.tsv");
    let mut index = format!(
        "LI2BUNDLE\t1\noriginal_sha256\t{}\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n",
        digest(original)
    );
    for (name, b) in &product.0 {
        writeln!(&mut index, "file\t{name}\t{}\t{}", b.len(), digest(b)).unwrap();
    }
    product
        .0
        .insert("bundle-index.tsv".into(), index.into_bytes());
}
fn fixture(program: &str, pair: u8) -> (super::super::tests::Fixture, Inputs, boot::Input) {
    fixture_mode(program, pair, None)
}
fn fixture_mode(
    program: &str,
    pair: u8,
    image: Option<u64>,
) -> (super::super::tests::Fixture, Inputs, boot::Input) {
    let mut f = match image {
        Some(image) => super::super::tests::startup_fixture_with_image(program, image),
        None => super::super::tests::startup_fixture(program, pair),
    };
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
    let plan = f.product.0["plan-ledger.tsv"].clone();
    let joined = ledger::join(&f.original, &facts, &records, &plan, &f.product).unwrap();
    let dependency = dependency();
    let raw=format!("LI2BOOTSTRAP-POLICY 1\nprofile {RUNTIME_PROFILE}\nprogram {program}\noriginal {}\ndisassembly {}\nplanning-policy {}\ninterpreter /fixture/ld.so\nbootstrap /fixture/{program}.so\napp-stack 4481024 65536\nqualification-contract {}\nstartup-limits 4096 4096 4097 112 16384 4096 65536 1048576\ndependency /fixture/ld.so {}\n",digest(&f.original),digest(&f.expected.files["disassembly.txt"]),digest(&f.expected.files["disassembly-policy.txt"]),"01".repeat(32),digest(&dependency)).into_bytes();
    let inputs = Inputs {
        policy: raw,
        dependencies: vec![dependency],
    };
    let policy = policy(program, &inputs.policy, &f.original, &facts, &f.product).unwrap();
    let mut payload = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
    payload.extend_from_slice(&ContentId::of(&f.product.0["metadata.li2meta"]).0);
    payload.extend_from_slice(&ContentId::of(&plan).0);
    let elf = Elf64::parse(&f.original, ParseLimits::default()).unwrap();
    // Fixture construction can use the writer. The acceptance path independently
    // recomputes every byte/layout and never consumes this output as evidence.
    let output = carrier::append_static_exec_with_router_startup(
        &elf,
        carrier::ImageRequest {
            carrier_vaddr: ElfVaddr(0x480000),
            payload: &payload,
            images: &joined.images,
            source_dependencies: &joined.dependencies,
        },
        &joined.edits,
        carrier::ImagePolicy {
            layout: carrier::CarrierPolicy {
                page_size: 4096,
                user_address_limit: 1 << 47,
                max_added_file_bytes: TEXT as u64,
                max_output_file_bytes: OUTPUT as u64,
                max_program_headers: 128,
                max_virtual_span: 2147483648,
            },
            dynamic: Default::default(),
            max_images: 32,
            max_new_load_pages: 128,
        },
        carrier::StaticExecStartup {
            interpreter: "/fixture/ld.so",
            bootstrap_dso: std::str::from_utf8(&policy.runtime.bootstrap_dso).unwrap(),
            limits: carrier::StartupLimits {
                max_interpreter_bytes: 4096,
                max_needed_bytes: 4096,
                max_string_table_bytes: 4097,
                max_dynamic_bytes: 112,
                max_metadata_bytes: 16384,
                max_input_sections: 4096,
                max_input_symbols: 65536,
                max_input_string_bytes: 1048576,
            },
        },
    )
    .unwrap();
    let mut ledger = plan.clone();
    let mut suffix = format!(
        "CARRIER-EXTENSION\t1\ncandidate_sha256\t{}\nnew_load_pages\t{}\nphdr_file\t{}\t{}\nphdr_vaddr\t4718592\n",
        digest(output.bytes()),
        output.new_load_pages,
        output.program_table.start().0,
        output.program_table.len()
    );
    for (i, p) in output.images.iter().enumerate() {
        writeln!(
            &mut suffix,
            "elf-image\t{i}\t{}\t{}\t{}\t{}",
            p.entry.0,
            p.file.start().0,
            p.file.len(),
            p.program_header
        )
        .unwrap();
    }
    for c in output.changes() {
        writeln!(
            &mut suffix,
            "elf-change\t{:?}\t{}\t{}\t{}",
            c.kind,
            c.edit.offset.0,
            hex(&c.edit.expected),
            hex(&c.edit.replacement)
        )
        .unwrap();
    }
    ledger.extend_from_slice(suffix.as_bytes());
    // Actual catalog records are independently authored by the fixture renderer
    // before ledger validation; expected_records is never an actual-side oracle.
    let runtime = boot::Policy {
        interpreter: b"/fixture/ld.so".to_vec(),
        bootstrap_dso: format!("/fixture/{program}.so").into_bytes(),
        dependencies: vec![boot::Dependency {
            path: b"/fixture/ld.so".to_vec(),
            identity: ContentId::of(&inputs.dependencies[0]),
        }],
        app_stack: boot::Span {
            start: 0x446000,
            len: 65536,
        },
        hook_pc: 0x403000,
        hook_id: 1,
        state: boot::State {
            domain: 1,
            format: 1,
            allocation: 512,
            image: 512,
            mask: 3,
            components: Vec::new(),
        },
        qualification_contract: ContentId([1; 32]),
    };
    let catalog = boot::Input {
        program: if program == "checksum" { 1 } else { 2 },
        policy: runtime,
        original: f.original.clone(),
        main: output.bytes().to_vec(),
        selection: f.product.0["selection.txt"].clone(),
        metadata: f.product.0["metadata.li2meta"].clone(),
        target: f.product.0["target.tsv"].clone(),
        ledger: ledger.clone(),
        heads: f.startup_heads.clone(),
        steps: f.startup_steps.clone(),
        images: f.startup_images.clone(),
    };
    f.product
        .0
        .insert("candidate.elf".into(), output.bytes().to_vec());
    f.product.0.insert("ledger.tsv".into(), ledger);
    f.product
        .0
        .insert("catalog.li2boot".into(), encode(&catalog));
    f.product
        .0
        .insert("startup-policy.txt".into(), inputs.policy.clone());
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    f.product.0.insert(
        "startup-profile.tsv".into(),
        profile(program, &facts, &inputs.policy),
    );
    seal(&f.original, &mut f.product);
    (f, inputs, catalog)
}
#[test]
fn s03_both_complete_original_and_selected_rosters_join_in_all_pair_modes() {
    let mut totals = [0, 0];
    for program in ["checksum", "rle-roundtrip"] {
        for pair in 0..=4 {
            let (f, input, x) = fixture(program, pair);
            let (summary, startup) =
                verify(program, &f.original, &f.expected, &f.product, &input).unwrap();
            let (heads, selected) = denominator(program).unwrap();
            assert_eq!(summary.selected, selected);
            assert_eq!(startup.original_heads, heads);
            assert_eq!(summary.images, x.images.len());
            assert_eq!(startup.catalog_sha256, digest(&encode(&x)));
            if pair == 0 {
                totals[0] += heads;
                totals[1] += selected;
            }
        }
    }
    assert_eq!(totals, [187, 42]);
}
#[test]
fn s04_all_catalog_record_mutants_reseal_and_reach_the_exact_independent_join() {
    let (f, input, good) = fixture("checksum", 1);
    let mut cases: Vec<(boot::Input, &str)> = Vec::new();
    let mut x = good.clone();
    x.heads.pop();
    cases.push((x, "catalog complete original heads"));
    let mut x = good.clone();
    x.steps.pop();
    cases.push((x, "catalog complete selected and auxiliary steps"));
    let mut x = good.clone();
    x.steps[0].logical += 1;
    cases.push((x, "catalog exact ordered step role and displaced geometry"));
    let mut x = good.clone();
    x.steps[0].neighbor = Some(boot::Neighbor {
        selected: x.steps[0].logical,
        selected_len: 2,
        victim: 0x401002,
        victim_len: 6,
        relay: 0x401007,
        rel8: 5,
        selected_target: x.steps[0].image,
        victim_target: 0x600000,
    });
    cases.push((x, "catalog exact owned neighbor EB/E9 relay geometry"));
    let mut x = good.clone();
    x.steps[0].reads[0].bytes[0] ^= 1;
    cases.push((x, "catalog exact overlay reads/writes/dependencies"));
    let mut x = good.clone();
    x.steps[0].dependencies.clear();
    cases.push((x, "catalog exact overlay reads/writes/dependencies"));
    let mut x = good.clone();
    x.steps[0].allocation.len += 4096;
    cases.push((x, "catalog exact allocation/image bijection"));
    let mut x = good.clone();
    x.steps[0].obligations.clear();
    cases.push((x, "catalog complete preserved and routed obligations"));
    let mut x = good.clone();
    x.images.pop();
    cases.push((x, "catalog complete selected and auxiliary images"));
    let mut x = good.clone();
    x.images[0].body.bytes[0] ^= 1;
    cases.push((x, "catalog exact ordered image body"));
    let mut x = good.clone();
    x.images[0].entries[0].1 += 1;
    cases.push((x, "catalog exact image entry routes"));
    let mut x = good.clone();
    x.images[0].requirements.swap(0, 1);
    cases.push((x, "catalog exact ordered unresolved requirements"));
    let mut x = good.clone();
    x.ledger.pop();
    cases.push((
        x,
        "catalog complete source/main/selection/metadata/target/extended-ledger bytes",
    ));
    let mut x = good.clone();
    let at = x
        .steps
        .iter()
        .position(|s| matches!(s.kind, boot::Kind::GeneralizedPun(_)))
        .unwrap();
    if let boot::Kind::GeneralizedPun(ref mut p) = x.steps[at].kind {
        p.consumed.len -= 1;
    }
    cases.push((x, "catalog exact pun consumed/window/store geometry"));
    let mut x = good.clone();
    let at = x
        .images
        .iter()
        .position(|i| i.requirements.contains(&(6, 0)))
        .unwrap();
    x.images[at].requirements.retain(|r| *r != (6, 0));
    cases.push((x, "catalog exact ordered unresolved requirements"));
    for (x, why) in cases {
        let mut product = f.product.clone();
        product.0.insert("catalog.li2boot".into(), encode(&x));
        seal(&f.original, &mut product);
        bundle(&f.original, &product).unwrap();
        catalog::decode(&product.0["catalog.li2boot"]).unwrap();
        assert_eq!(
            verify("checksum", &f.original, &f.expected, &product, &input).err(),
            Some(why.into())
        );
    }
}
#[test]
fn s05_complete_candidate_mutants_rebind_catalog_ledger_index_then_fail_direct_check() {
    let (f, input, good) = fixture("checksum", 1);
    let elf = Elf64::parse(&good.main, ParseLimits::default()).unwrap();
    let dynamic = elf.segments(SegmentType::Dynamic).next().unwrap();
    let interp = elf.segments(SegmentType::Interpreter).next().unwrap();
    let phoff = elf.header().program_offset.0 as usize;
    let offsets = [
        (
            512,
            "all original bytes including old PHDRs, headers, padding, notes, data, and tail",
        ),
        (
            f.original.len() - 1,
            "all original bytes including old PHDRs, headers, padding, notes, data, and tail",
        ),
        (
            phoff + interp.index * 56 + 24,
            "all independent startup PHDR fields",
        ),
        (
            dynamic.offset.0 as usize,
            "exact appended payload/image bytes",
        ),
        (
            interp.offset.0 as usize,
            "exact appended payload/image bytes",
        ),
    ];
    for (offset, why) in offsets {
        let mut x = good.clone();
        x.main[offset] ^= 1;
        x.ledger = String::from_utf8(good.ledger.clone())
            .unwrap()
            .replace(&digest(&good.main), &digest(&x.main))
            .into_bytes();
        let mut product = f.product.clone();
        product.0.insert("candidate.elf".into(), x.main.clone());
        product.0.insert("ledger.tsv".into(), x.ledger.clone());
        product.0.insert("catalog.li2boot".into(), encode(&x));
        seal(&f.original, &mut product);
        bundle(&f.original, &product).unwrap();
        catalog::decode(&product.0["catalog.li2boot"]).unwrap();
        assert_eq!(
            verify("checksum", &f.original, &f.expected, &product, &input).err(),
            Some(why.into()),
            "offset {offset}"
        );
    }
}
#[test]
fn s06_pinned_invalid_policy_semantics_reach_exact_checker() {
    let (f, input, good) = fixture("checksum", 0);
    for (from, to, why) in [
        (
            "app-stack 4481024 65536",
            "app-stack 4481040 65536",
            "exact authored application stack coordinates",
        ),
        (
            "startup-limits 4096 4096 4097 112 16384",
            "startup-limits 4096 4096 4097 112 16385",
            "unchanged startup ceiling",
        ),
        (
            "startup-limits 4096 4096 4097 112 16384",
            "startup-limits 4096 4096 4097 112 1",
            "actual startup metadata charge",
        ),
        (
            "interpreter /fixture/ld.so",
            "interpreter /fixture/../ld.so",
            "canonical startup absolute path",
        ),
    ] {
        let mut input = input.clone();
        input.policy = String::from_utf8(input.policy)
            .unwrap()
            .replace(from, to)
            .into_bytes();
        let mut product = f.product.clone();
        product
            .0
            .insert("startup-policy.txt".into(), input.policy.clone());
        let facts = f.expected.facts(&f.original, &product).unwrap();
        product.0.insert(
            "startup-profile.tsv".into(),
            profile("checksum", &facts, &input.policy),
        );
        // Rebind every outer product identity; the expected input is deliberately
        // the malformed policy itself, not a stale identity of a valid policy.
        product.0.insert("catalog.li2boot".into(), encode(&good));
        seal(&f.original, &mut product);
        bundle(&f.original, &product).unwrap();
        assert_eq!(
            verify("checksum", &f.original, &f.expected, &product, &input).err(),
            Some(why.into())
        );
    }
}
#[test]
fn s07_dependency_byte_and_rebound_elf_semantics_refuse_exactly() {
    let (f, input, good) = fixture("checksum", 0);
    let mut changed = input.clone();
    changed.dependencies[0][1024] ^= 1;
    assert_eq!(
        verify("checksum", &f.original, &f.expected, &f.product, &changed).err(),
        Some("dependency independent full-byte identity".into())
    );
    let mut changed = input.clone();
    // Rebind a writable+executable LOAD all the way through policy and catalog.
    changed.dependencies[0][68..72].copy_from_slice(&7u32.to_le_bytes());
    let old = digest(&input.dependencies[0]);
    let new = digest(&changed.dependencies[0]);
    changed.policy = String::from_utf8(changed.policy)
        .unwrap()
        .replace(&old, &new)
        .into_bytes();
    let mut x = good;
    x.policy.dependencies[0].identity = ContentId::of(&changed.dependencies[0]);
    let mut product = f.product.clone();
    product
        .0
        .insert("startup-policy.txt".into(), changed.policy.clone());
    let facts = f.expected.facts(&f.original, &product).unwrap();
    product.0.insert(
        "startup-profile.tsv".into(),
        profile("checksum", &facts, &changed.policy),
    );
    product.0.insert("catalog.li2boot".into(), encode(&x));
    seal(&f.original, &mut product);
    bundle(&f.original, &product).unwrap();
    assert_eq!(
        verify("checksum", &f.original, &f.expected, &product, &changed).err(),
        Some("dependency readable non-WX LOAD permissions".into())
    );
}
#[test]
fn s08_catalog_wire_version_checksum_count_and_end_are_strict() {
    let (_, _, good) = fixture("checksum", 0);
    let valid = encode(&good);
    assert_eq!(catalog::decode(&valid).unwrap(), good);
    let mut bad = valid.clone();
    bad[8] = 1;
    let n = bad.len() - 32;
    let id = ContentId::of(&bad[..n]);
    bad[n..].copy_from_slice(&id.0);
    assert_eq!(
        catalog::decode(&bad).err(),
        Some("catalog explicit v2 wire".into())
    );
    let mut bad = valid.clone();
    bad[1024] ^= 1;
    assert_eq!(
        catalog::decode(&bad).err(),
        Some("catalog envelope checksum".into())
    );
    let mut bad = valid[..valid.len() - 32].to_vec();
    bad.push(0);
    let id = ContentId::of(&bad);
    bad.extend_from_slice(&id.0);
    assert_eq!(
        catalog::decode(&bad).err(),
        Some("catalog exact end".into())
    );
    let mut bad = valid;
    bad[24..32].copy_from_slice(&4096u64.to_le_bytes());
    let n = bad.len() - 32;
    let id = ContentId::of(&bad[..n]);
    bad[n..].copy_from_slice(&id.0);
    assert_eq!(
        catalog::decode(&bad).err(),
        Some("catalog count before allocation".into())
    );
}
#[test]
fn s09_membership_and_bundle_changes_never_become_complete_programs() {
    let (f, input, _) = fixture("rle-roundtrip", 0);
    for (name, why) in [
        ("catalog.li2boot", "complete actual artifact membership"),
        ("startup-profile.tsv", "complete actual artifact membership"),
        ("image-0000.bin", "missing image-0000.bin"),
    ] {
        let mut product = f.product.clone();
        product.0.remove(name);
        seal(&f.original, &mut product);
        assert_eq!(
            verify("rle-roundtrip", &f.original, &f.expected, &product, &input).err(),
            Some(why.into()),
            "missing {name}"
        );
    }
    let mut product = f.product.clone();
    product
        .0
        .insert("COMPLETE".into(), b"legacy forged marker\n".to_vec());
    assert_eq!(
        verify("rle-roundtrip", &f.original, &f.expected, &product, &input).err(),
        Some("complete actual artifact membership".into())
    );
    let mut product = f.product.clone();
    product.0.get_mut("bundle-index.tsv").unwrap().pop();
    assert_eq!(
        verify("rle-roundtrip", &f.original, &f.expected, &product, &input).err(),
        Some("complete exact startup bundle index".into())
    );
}
fn transport_members(f: &super::super::tests::Fixture, input: &Inputs) -> Vec<(String, Vec<u8>)> {
    let mut members = BTreeMap::from([
        ("input/original".to_string(), f.original.clone()),
        (
            "expected/startup-policy.txt".to_string(),
            input.policy.clone(),
        ),
    ]);
    for (name, bytes) in &f.expected.files {
        members.insert(format!("expected/{name}"), bytes.clone());
    }
    for (name, bytes) in &f.product.0 {
        members.insert(format!("product/{name}"), bytes.clone());
    }
    for (i, bytes) in input.dependencies.iter().enumerate() {
        members.insert(format!("dependency/{i:04}"), bytes.clone());
    }
    members.into_iter().collect()
}
fn transport_rows(program: &str, members: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out =
        format!("LI2W01-INPUT\t2\t{PROFILE}\t{program}\t{}\n", members.len()).into_bytes();
    for (name, bytes) in members {
        out.extend_from_slice(format!("{name}\t{}\t{}\n", bytes.len(), digest(bytes)).as_bytes());
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(b"END\n");
    out
}
fn transport(f: &super::super::tests::Fixture, input: &Inputs) -> Vec<u8> {
    transport_rows(&f.expected.program, &transport_members(f, input))
}
#[test]
fn s11_complete_transport_both_programs_and_strict_end() {
    for program in ["checksum", "rle-roundtrip"] {
        let (f, input, _) = fixture(program, 1);
        let raw = transport(&f, &input);
        let (name, original, expected, product, inputs) =
            crate::startup_transport::decode(&mut raw.as_slice()).unwrap();
        assert_eq!(name, program);
        assert_eq!(original, f.original);
        assert_eq!(expected.files, f.expected.files);
        assert_eq!(product.0, f.product.0);
        assert_eq!(inputs.policy, input.policy);
        assert_eq!(inputs.dependencies, input.dependencies);
        let (summary, startup) = verify(&name, &original, &expected, &product, &inputs).unwrap();
        assert_eq!(
            (startup.original_heads, summary.selected),
            denominator(program).unwrap()
        );
        let mut surplus = raw.clone();
        surplus.push(0);
        assert_eq!(
            crate::startup_transport::decode(&mut surplus.as_slice()).err(),
            Some("startup transport trailing bytes".into())
        );
        assert!(crate::transport(&mut raw.as_slice()).is_err());
    }
}
#[test]
fn r1_full_reservation_rebound_image_inside_and_at_boundary() {
    for program in ["checksum", "rle-roundtrip"] {
        for entry in [0x482000, 0x486000] {
            let (f, input, x) = fixture_mode(program, 0, Some(entry));
            let facts = f.expected.facts(&f.original, &f.product).unwrap();
            let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
            let plan = &f.product.0["plan-ledger.tsv"];
            let joined = ledger::join(&f.original, &facts, &records, plan, &f.product).unwrap();
            let policy = policy(program, &input.policy, &f.original, &facts, &f.product).unwrap();
            let elf = Elf64::parse(&x.main, ParseLimits::default()).unwrap();
            let carrier = elf
                .segments(SegmentType::Load)
                .find(|p| p.vaddr.0 == 0x480000)
                .unwrap();
            assert!(carrier.vaddr.0 + carrier.memory_size < 0x482000);
            assert_eq!(x.images[0].body.address, entry);
            assert_eq!(
                x.steps[0].allocation,
                boot::Span {
                    start: entry,
                    len: 4096
                }
            );
            // The coherent renderer has repaired source E9, every later read,
            // image fields/maps, sparse edits, payload, headers, extended ledger,
            // actual independently authored catalog and bundle membership.
            bundle(&f.original, &f.product).unwrap();
            candidate::join_startup(
                &Artifact {
                    program,
                    original: &f.original,
                    facts: &facts,
                    joined: &joined,
                    metadata: &x.metadata,
                    plan,
                    candidate: &x.main,
                    ledger: &x.ledger,
                    product: &f.product,
                },
                &policy,
            )
            .unwrap();
            catalog::join(
                &x,
                catalog::Expected {
                    policy: &policy,
                    original: &f.original,
                    facts: &facts,
                    joined: &joined,
                    metadata: &x.metadata,
                    candidate: &x.main,
                    ledger: &x.ledger,
                },
            )
            .unwrap();
            let outcome = verify(program, &f.original, &f.expected, &f.product, &input);
            if entry == 0x482000 {
                assert_eq!(
                    outcome.err(),
                    Some("allocation overlaps full prospective startup reservation".into())
                );
            } else {
                let (summary, startup) = outcome.unwrap();
                assert_eq!(
                    (startup.original_heads, summary.selected),
                    denominator(program).unwrap()
                );
                assert_eq!(
                    reservation(&policy, &facts, &joined).unwrap(),
                    Range::new(0x480000, 0x486000).unwrap()
                );
            }
        }
    }
}
#[test]
fn r2_complete_independent_t1_and_short_t3_catalogs_and_current_overlay() {
    for program in ["checksum", "rle-roundtrip"] {
        for family in [5, 6] {
            let (f, input, x) = fixture(program, family);
            let (summary, startup) =
                verify(program, &f.original, &f.expected, &f.product, &input).unwrap();
            assert_eq!(
                (startup.original_heads, summary.selected),
                denominator(program).unwrap()
            );
            assert_eq!(summary.images, summary.selected + usize::from(family == 6));
            let group = x
                .steps
                .iter()
                .filter(|s| s.selected_id == 1)
                .collect::<Vec<_>>();
            if family == 5 {
                assert_eq!(group.len(), 1);
                let s = group[0];
                let boot::Kind::PrefixedPun(p) = s.kind else {
                    panic!("full T1 kind");
                };
                assert_eq!(
                    (p.instruction_len, p.prefixes, p.consumed.len, p.store.len),
                    (3, 1, 6, 4)
                );
                assert_eq!(
                    s.obligations,
                    vec![
                        boot::Obligation {
                            original: 0x401000,
                            generated: None
                        },
                        boot::Obligation {
                            original: 0x401003,
                            generated: None
                        }
                    ]
                );
                assert_eq!(s.reads[0].bytes[3..6], [0xe9, 0x00, 0x50]);
                assert_ne!(s.reads[0].bytes[3..6], f.original[0x1003..0x1006]);
                assert_eq!(s.writes[1].bytes, [0x2e, 0xe9, 0x20, 0xe9]);
            } else {
                assert_eq!(group.len(), 2);
                assert_eq!((group[0].physical, group[1].physical), (0x401002, 0x401000));
                let geometry = boot::Neighbor {
                    selected: 0x401000,
                    selected_len: 2,
                    victim: 0x401002,
                    victim_len: 6,
                    relay: 0x401007,
                    rel8: 5,
                    selected_target: 0x802f1b,
                    victim_target: 0x500000,
                };
                assert!(group.iter().all(|s| s.neighbor == Some(geometry)));
                assert_eq!(
                    group[0].writes[0].bytes[5..],
                    [0xe9, 0x0f, 0x1f, 0x40, 0x00]
                );
                assert_eq!(group[1].writes[0].bytes, [0xeb, 5]);
                assert_eq!(&group[1].reads[0].bytes[2..12], group[0].writes[0].bytes);
                let auxiliary = x
                    .images
                    .iter()
                    .find(|i| i.body.address == geometry.victim_target)
                    .unwrap();
                let selected = x
                    .images
                    .iter()
                    .find(|i| i.body.address == geometry.selected_target)
                    .unwrap();
                assert_eq!(
                    auxiliary.requirements,
                    [(1, 0), (2, 0), (3, 0), (4, 0), (7, 0), (8, 0)]
                );
                assert_eq!(
                    selected.requirements,
                    [(1, 0), (2, 0), (3, 0), (4, 0), (7, 0), (8, 0), (5, 1)]
                );
            }
        }
    }
}
#[test]
fn r2_full_family_catalog_mutants_reseal_then_reach_exact_checks() {
    for family in [5, 6] {
        let (f, input, good) = fixture("checksum", family);
        let at = good.steps.iter().position(|s| s.selected_id == 1).unwrap();
        let mut cases = Vec::new();
        if family == 5 {
            let mut x = good.clone();
            if let boot::Kind::PrefixedPun(ref mut p) = x.steps[at].kind {
                p.consumed.len -= 1;
            }
            cases.push((x, "catalog exact pun consumed/window/store geometry"));
            let mut x = good.clone();
            if let boot::Kind::PrefixedPun(ref mut p) = x.steps[at].kind {
                p.store.start += 1;
            }
            cases.push((x, "catalog exact pun consumed/window/store geometry"));
            let mut x = good.clone();
            x.steps[at].obligations.pop();
            cases.push((x, "catalog complete preserved and routed obligations"));
            let mut x = good.clone();
            x.steps[at].writes[1].bytes[3] ^= 1;
            cases.push((x, "catalog exact overlay reads/writes/dependencies"));
            let mut x = good.clone();
            x.steps[at].reads[0].bytes[3..6].copy_from_slice(&f.original[0x1003..0x1006]);
            cases.push((x, "catalog exact overlay reads/writes/dependencies"));
        } else {
            for field in 0..4 {
                let mut x = good.clone();
                for step in &mut x.steps[at..at + 2] {
                    let n = step.neighbor.as_mut().unwrap();
                    match field {
                        0 => n.rel8 += 1,
                        1 => n.relay += 1,
                        2 => n.selected_target += 1,
                        _ => n.victim_target += 1,
                    }
                }
                cases.push((x, "catalog exact owned neighbor EB/E9 relay geometry"));
            }
            let mut x = good.clone();
            x.steps[at].selected_id += 1;
            cases.push((x, "catalog exact ordered step role and displaced geometry"));
            let mut x = good.clone();
            x.steps[at + 1].reads[0].bytes[2..12].copy_from_slice(&f.original[0x1002..0x100c]);
            cases.push((x, "catalog exact overlay reads/writes/dependencies"));
            let mut x = good.clone();
            let image = x
                .images
                .iter_mut()
                .find(|i| i.body.address == 0x500000)
                .unwrap();
            image.requirements.push((5, 1));
            cases.push((x, "catalog exact ordered unresolved requirements"));
            let mut x = good.clone();
            let image = x
                .images
                .iter_mut()
                .find(|i| i.body.address == 0x802f1b)
                .unwrap();
            image.requirements.pop();
            cases.push((x, "catalog exact ordered unresolved requirements"));
        }
        for (x, why) in cases {
            let mut product = f.product.clone();
            product.0.insert("catalog.li2boot".into(), encode(&x));
            seal(&f.original, &mut product);
            bundle(&f.original, &product).unwrap();
            catalog::decode(&product.0["catalog.li2boot"]).unwrap();
            assert_eq!(
                verify("checksum", &f.original, &f.expected, &product, &input).err(),
                Some(why.into())
            );
        }
    }
}

#[test]
fn r3_dependency_real_elf_load_pages_equal_cap_and_one_more() {
    let (_, _, good) = fixture("checksum", 0);
    for pages in [65536u64, 65537] {
        let mut bytes = dependency();
        // One RX file page plus this RW file+BSS extent. No huge allocation is
        // needed to test the real ELF page-accounting path.
        let second_load = 64 + 56;
        bytes[second_load + 40..second_load + 48]
            .copy_from_slice(&((pages - 1) * 4096).to_le_bytes());
        let mut p = Policy {
            program: 1,
            runtime: good.policy.clone(),
            caps: [4096, 4096, 4097, 112, 16384, 4096, 65536, 1048576],
        };
        p.runtime.dependencies[0].identity = ContentId::of(&bytes);
        let outcome = dependencies::join(&p, &[bytes]);
        if pages == 65536 {
            assert!(outcome.is_ok());
        } else {
            assert_eq!(
                outcome.err(),
                Some("dependency aggregate runtime LOAD page charge".into())
            );
        }
    }
}
#[test]
fn r3_v2_missing_extra_reordered_duplicate_and_trailing_members() {
    let (f, input, _) = fixture("checksum", 6);
    let good = transport_members(&f, &input);
    let mut cases = Vec::new();
    let mut missing = good.clone();
    missing.retain(|(name, _)| name != "expected/startup-policy.txt");
    cases.push((missing, "startup policy missing"));
    let mut missing = good.clone();
    missing.retain(|(name, _)| name != "input/original");
    cases.push((missing, "startup original missing"));
    let mut extra = good.clone();
    extra.push(("unknown/member".into(), vec![0]));
    extra.sort_by(|a, b| a.0.cmp(&b.0));
    cases.push((extra, "startup transport namespace"));
    let mut reordered = good.clone();
    reordered.swap(0, 1);
    cases.push((reordered, "startup ordered unique transport member/digest"));
    let mut duplicate = good.clone();
    duplicate.insert(1, duplicate[0].clone());
    cases.push((duplicate, "startup ordered unique transport member/digest"));
    for (members, why) in cases {
        let raw = transport_rows("checksum", &members);
        assert_eq!(
            crate::startup_transport::decode(&mut raw.as_slice()).err(),
            Some(why.into())
        );
    }
    let mut raw = transport_rows("checksum", &good);
    raw.extend_from_slice(b"surplus");
    assert_eq!(
        crate::startup_transport::decode(&mut raw.as_slice()).err(),
        Some("startup transport trailing bytes".into())
    );
    let mut extra = good;
    extra.push(("product/unknown.bin".into(), vec![0]));
    extra.sort_by(|a, b| a.0.cmp(&b.0));
    let raw = transport_rows("checksum", &extra);
    let (name, original, expected, product, inputs) =
        crate::startup_transport::decode(&mut raw.as_slice()).unwrap();
    assert_eq!(
        verify(&name, &original, &expected, &product, &inputs).err(),
        Some("complete actual artifact membership".into())
    );
}
