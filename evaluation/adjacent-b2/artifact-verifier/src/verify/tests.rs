//! Synthetic structural positives are never corpus or native outcomes. No binder,
//! planner, decoder, prepare call, or producer binary supplies expected facts.
use super::*;
use crate::Memory;
use formats::startup as boot;
pub(super) fn sparse_limits() -> formats::sparse::Limits {
    formats::sparse::Limits {
        edits: TEXT,
        edited_bytes: TEXT,
        pages: TEXT / 4096,
    }
}
pub(super) fn wire_limits() -> formats::sparse_wire::Limits {
    formats::sparse_wire::Limits {
        bytes: OUTPUT,
        content: sparse_limits(),
    }
}
fn envelope(bytes: &mut [u8]) {
    bytes[24..56].fill(0);
    let hash = ContentId::of(bytes);
    bytes[24..56].copy_from_slice(&hash.0);
}

pub(super) fn original() -> Vec<u8> {
    let mut b = vec![0; 0x56000];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&6u16.to_le_bytes());
    for (i, (kind, flags, offset, pc, size, align)) in [
        (6u32, 4u32, 64u64, 0x400040u64, 336u64, 8u64),
        (1, 4, 0, 0x400000, 4096, 4096),
        (1, 5, 4096, 0x401000, 12288, 4096),
        (1, 6, 16384, 0x404000, 335872, 4096),
        (4, 4, 512, 0x400200, 12, 4),
        (0x6474e551, 6, 0, 0, 0, 16),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + 56 * i;
        b[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        for (j, value) in [offset, pc, pc, size, size, align].into_iter().enumerate() {
            b[at + 8 + j * 8..at + 16 + j * 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    b[0x3000] = 0xc3;
    b
}
fn rel(address: u64, target: u64) -> Vec<u8> {
    let mut b = vec![0xe9];
    b.extend_from_slice(
        &i32::try_from(i128::from(target) - i128::from(address + 5))
            .unwrap()
            .to_le_bytes(),
    );
    b
}
pub(crate) struct Fixture {
    // Actual fixture records are written alongside the manually authored plan,
    // before independent ledger joins. They never call expected_records.
    pub startup_steps: Vec<boot::Step>,
    pub startup_images: Vec<boot::Image>,
    pub startup_heads: Vec<u64>,
    pub original: Vec<u8>,
    pub expected: Expected,
    pub product: Memory,
}
pub(crate) fn fixture(program: &str, t2: bool) -> Fixture {
    make_fixture(program, t2, 0, false)
}
pub(crate) fn routed_fixture(program: &str) -> Fixture {
    make_fixture(program, false, 1, false)
}
pub(crate) fn forward_fixture(program: &str) -> Fixture {
    make_fixture(program, false, 2, false)
}
fn upstream_fixture(program: &str) -> Fixture {
    make_fixture(program, false, 0, true)
}
fn make_fixture(program: &str, t2: bool, pair: u8, upstream: bool) -> Fixture {
    make_fixture_mode(program, t2, pair, upstream, false)
}
pub(super) fn startup_fixture(program: &str, pair: u8) -> Fixture {
    match pair {
        3 => make_fixture_mode(program, true, 0, false, true),
        4 => make_fixture_mode(program, false, 0, true, true),
        5 | 6 => make_fixture_options(program, false, 0, false, true, (pair, None)),
        _ => make_fixture_mode(program, false, pair, false, true),
    }
}
pub(super) fn startup_fixture_with_image(program: &str, image: u64) -> Fixture {
    make_fixture_options(program, false, 0, false, true, (0, Some(image)))
}
fn make_fixture_mode(program: &str, t2: bool, pair: u8, upstream: bool, startup: bool) -> Fixture {
    make_fixture_options(program, t2, pair, upstream, startup, (0, None))
}
fn make_fixture_options(
    program: &str,
    t2: bool,
    pair: u8,
    upstream: bool,
    startup: bool,
    extra: (u8, Option<u64>),
) -> Fixture {
    let (extra_family, image_override) = extra;
    let t1 = extra_family == 5;
    let t3 = extra_family == 6;
    let mut startup_steps = Vec::new();
    let mut startup_images = Vec::new();
    let routed = pair == 1;
    let forward = pair == 2;
    let (count, n) = denominator(program).unwrap();
    let mut original = original();
    if startup {
        original[0x46000..0x56000].fill(0x5a);
    }
    let mut heads = BTreeMap::new();
    let mut selected = Vec::new();
    let mut regions = Vec::new();
    for (base, population, picks) in [
        (0x401000u64, 61, 14),
        (0x402000, count - 62, n - 14),
        (0x403000, 1, 0),
    ] {
        let mut pc = base;
        let mut index = 0;
        let mut chosen = 0;
        while index < population {
            let bytes = if base == 0x403000 {
                vec![0xc3]
            } else if t1 && base == 0x401000 && index == 0 {
                selected.push(pc);
                chosen += 1;
                vec![0x66, 0x75, 0]
            } else if t3 && base == 0x401000 && index == 0 {
                selected.push(pc);
                chosen += 1;
                vec![0x75, 6]
            } else if t3 && base == 0x401000 && index == 1 {
                vec![0x69, 0xc0, 1, 0, 0, 0]
            } else if t3 && base == 0x401000 && index == 2 {
                vec![0x0f, 0x1f, 0x40, 0]
            } else if upstream && base == 0x401000 && index == 0 {
                vec![0x90]
            } else if upstream && base == 0x401000 && index == 1 {
                selected.push(pc);
                chosen += 1;
                vec![0x66, 0x66, 0x75, 0]
            } else if pair != 0 && base == 0x401000 && index == 0 {
                vec![0x90]
            } else if pair != 0 && base == 0x401000 && index == 1 {
                selected.push(pc);
                chosen += 1;
                if routed {
                    vec![0x76, 0xfd]
                } else {
                    vec![0x75, 5]
                }
            } else if pair != 0 && base == 0x401000 && index == 2 {
                selected.push(pc);
                chosen += 1;
                if routed { vec![0xeb, 3] } else { vec![0x74, 3] }
            } else if routed && base == 0x401000 && index == 3 {
                vec![0x4c, 0x89, 0xe7]
            } else if forward && base == 0x401000 && (3..=5).contains(&index) {
                vec![0x50]
            } else if t2 && base == 0x401000 && index == 0 {
                selected.push(pc);
                chosen += 1;
                vec![0x75, 6]
            } else if t2 && base == 0x401000 && index == 1 {
                vec![0x69, 0xc0, 1, 0, 0, 0]
            } else if chosen < picks {
                selected.push(pc);
                chosen += 1;
                vec![0xe9, 0, 0, 0, 0]
            } else {
                vec![0x90]
            };
            let off = (pc - 0x400000) as usize;
            original[off..off + bytes.len()].copy_from_slice(&bytes);
            let next = pc + bytes.len() as u64;
            heads.insert(pc, bytes);
            pc = next;
            index += 1;
        }
        regions.push(Range {
            start: base,
            end: pc,
        });
    }
    let mut disassembly = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\n",
        digest(&original)
    );
    for r in &regions {
        writeln!(
            &mut disassembly,
            "region {} {} {}",
            r.start,
            r.start - 0x400000,
            r.len()
        )
        .unwrap();
        for (pc, b) in heads.range(r.start..r.end) {
            writeln!(&mut disassembly, "head {pc} {}", hex(b)).unwrap();
        }
    }
    let family = "neighbor-victims short-only\nneighbor-ownership inherited-t3\npending-selected full-instruction-ownership\nadjacent-pairs original-geometry-jcc-or-routed-jmp-v1\nadjacent-pair-budgets 2 1 2\n";
    let globals = "target fxsave64\ndomain 1\ncarrier 4718592\nlimits 1048576 32 32 131072 128 2097152 1048576 128 2147483648\n";
    let mut manifest = format!(
        "LI2TOOL 1\noriginal {}\n{family}{globals}hook 1 4206592 1 {}\n",
        digest(&original),
        digest(&[0xc3])
    );
    let mut search = String::new();
    let family_tsv = "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nadjacent_pairs\toriginal-geometry-jcc-or-routed-jmp-v1\n";
    let mut inventory = format!(
        "LI2DISASSEMBLY-INVENTORY\t1\nprofile\t{PROFILE}\n{family_tsv}original_sha256\t{}\nledger_sha256\t{}\ncomplete_jump_count\t{n}\nqualification_complete\tfalse\nid\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\n",
        digest(&original),
        digest(disassembly.as_bytes())
    );
    for (i, pc) in selected.iter().enumerate() {
        let id = i + 1;
        let r = regions.iter().find(|r| r.contains(*pc)).unwrap();
        let len = heads[pc].len();
        writeln!(
            &mut manifest,
            "site {id} {pc} {len} {} {} {} {} {} {} {} 1 observe original-decode",
            pc - 0x400000,
            r.start,
            r.len(),
            r.start,
            r.len(),
            r.start,
            r.len()
        )
        .unwrap();
        write!(
            &mut manifest,
            "entries {id} complete {}",
            digest(disassembly.as_bytes())
        )
        .unwrap();
        for (head, _) in heads.range(r.start..r.end) {
            write!(&mut manifest, " {head}:0").unwrap();
        }
        writeln!(&mut manifest, "\nresumes {id} none").unwrap();
        writeln!(&mut search,"search {id} preferred 64 256 64 none 256 4096\nallocation {id} selected 6291456 1 4096 1:2147483647\nallocation {id} victim 6291456 1 4096 1:2147483647").unwrap();
        writeln!(
            &mut inventory,
            "{id}\t{pc}\t{len}\t{}\t{}\t{}\t{}\t{}",
            pc - 0x400000,
            r.start,
            r.len(),
            r.start,
            r.len()
        )
        .unwrap();
    }
    manifest.push_str(&search);
    let policy = format!(
        "LI2DISASM-POLICY 6\noriginal {}\nledger {}\n{family}{globals}null-hook 4206592\n{search}",
        digest(&original),
        digest(disassembly.as_bytes())
    );
    let profile = format!(
        "LI2PLANNING\t1\nprofile\t{PROFILE}\n{family_tsv}adjacent_upper\t2\nadjacent_lower\t1\nadjacent_joint\t2\nscope\tartifact-code-regions-not-functions\nentries\tall-verified-instruction-heads\noriginal_sha256\t{}\nledger_sha256\t{}\npolicy_sha256\t{}\nselection_sha256\t{}\ncomplete_jump_count\t{n}\nqualification_complete\tfalse\n",
        digest(&original),
        digest(disassembly.as_bytes()),
        digest(policy.as_bytes()),
        digest(manifest.as_bytes())
    );
    let files = BTreeMap::from([
        ("disassembly-inventory.tsv".into(), inventory.into_bytes()),
        ("disassembly-policy.txt".into(), policy.into_bytes()),
        ("disassembly.txt".into(), disassembly.into_bytes()),
        ("planning-profile.tsv".into(), profile.into_bytes()),
        ("selection.txt".into(), manifest.as_bytes().to_vec()),
    ]);
    let expected = Expected {
        program: program.into(),
        files: files.clone(),
    };
    let mut product = Memory(files);
    let rows: Vec<_> = manifest.lines().collect();
    let projected = format!("{}\n{}\n{}\n", rows[0], rows[1], rows[7..].join("\n"));
    let selection = selection::parse(projected.as_bytes()).unwrap();
    product
        .0
        .insert("target.tsv".into(), target_text(&selection));
    let facts = expected.facts(&original, &product).unwrap();
    let mut report = format!(
        "LI2REPORT\t1\noriginal_sha256\t{}\nselection_sha256\t{}\ncandidate_complete\ttrue\nqualification_complete\tfalse\nsite\tpc\tfile_offset\tlength\tcore_tactic\tcandidate_emitted\trefusal_code\tstage\tdetail_hex\n",
        digest(&original),
        digest(manifest.as_bytes())
    );
    let mut plan = format!(
        "LI2LEDGER\t1\noriginal_sha256\t{}\nselection_sha256\t{}\nbias_policy\tcommon-additive-module-relative-v1\nbias_domain\t1\nqualification_complete\tfalse\nexecution_authority\tnone\ngrouping\tseparate-backing-only\nrequirement\t0\t101\tdeclared-entry-completeness-not-proven\nunresolved\tloader-abi-cpu-unwind-cet\nhook\t1\t4206592\t1\t{}\n",
        digest(&original),
        digest(manifest.as_bytes()),
        digest(&[0xc3])
    );
    let mut current = original.clone();
    let mut locks = Vec::new();
    let mut deps = vec![(0x3000, 0x3001)];
    let mut image_id = 0;
    for s in &selection.sites {
        let tactic = if t1 && s.id == 1 {
            "T1"
        } else if t3 && s.id == 1 {
            "T3"
        } else if t2 && s.id == 1 {
            "T2"
        } else if (routed && s.id == 1) || (forward && s.id <= 2) {
            "B2"
        } else {
            "B1"
        };
        writeln!(
            &mut report,
            "{}\t{}\t{}\t{}\t{tactic}\ttrue\tnone\tnone\t",
            s.id, s.pc, s.file_offset, s.length
        )
        .unwrap();
        product.0.insert(
            format!("site-{}.diagnostics.txt", s.id),
            b"synthetic structural control\n".to_vec(),
        );
    }
    for s in selection.sites.iter().rev() {
        let mut image_rows = String::new();
        let members = if t1 && s.id == 1 {
            vec![(s.pc, 3, "prefixed-pun", s.pc + 6 + 0x5000e920, true)]
        } else if t1 && s.id == 2 {
            vec![(s.pc, 5, "relocation", s.pc + 5 + 0x00305000, true)]
        } else if t3 && s.id == 1 {
            vec![
                (s.pc + 2, 6, "relocation", 0x500000, false),
                (s.pc, 2, "relocation", s.pc + 12 + 0x00401f0f, true),
            ]
        } else if upstream && s.id == 1 {
            vec![(s.pc - 1, 5, "relocation", s.pc - 1 + 5 + 0x00300006, true)]
        } else if forward && s.id <= 2 {
            vec![(
                s.pc,
                2,
                "generalized-pun",
                s.pc + 5 + if s.id == 2 { 0x50505020 } else { 0x5020e920 },
                true,
            )]
        } else if routed && s.id == 2 {
            vec![(s.pc, 5, "relocation", s.pc + 5 + 0x00606000, true)]
        } else if routed && s.id == 1 {
            vec![(s.pc, 2, "generalized-pun", s.pc + 5 + 0x6000e920, true)]
        } else if t2 && s.id == 1 {
            vec![
                (s.pc + 2, 6, "relocation", 0x50100e, false),
                (s.pc, 2, "generalized-pun", 0x47f925, true),
            ]
        } else {
            vec![(
                s.pc,
                usize::from(s.length),
                "relocation",
                if image_id == 0 {
                    image_override.unwrap_or(0x600000)
                } else {
                    0x600000 + image_id as u64 * 4096
                },
                true,
            )]
        };
        for (local, (pc, len, kind, entry, hook)) in members.into_iter().enumerate() {
            let start = s.snapshot.start();
            let end = s.snapshot.end();
            let is_upstream = upstream && s.id == 1;
            let logical = if is_upstream { s.pc } else { pc };
            let router = (routed && s.id == 2) || is_upstream;
            let route_offset = if is_upstream { 1 } else { 2 };
            let body_offset = if is_upstream { 1 } else { 5 };
            let is_neighbor = t3 && s.id == 1;
            let write = if kind == "prefixed-pun" {
                vec![0x2e, 0xe9, 0x20]
            } else if kind == "generalized-pun" {
                vec![0xe9, 0x20]
            } else if is_neighbor && hook {
                vec![0xeb, 5]
            } else if is_neighbor {
                let mut b = rel(pc, entry);
                b.extend_from_slice(&rel(pc + 5, s.pc + 12 + 0x00401f0f));
                b
            } else {
                rel(pc, entry)
            };
            let observed = current[(start - 0x400000) as usize..(end - 0x400000) as usize].to_vec();
            let pun = kind != "relocation";
            let prefixes = usize::from(kind == "prefixed-pun");
            let store = if pun {
                let width = len.next_power_of_two();
                let mut b =
                    current[(pc - 0x400000) as usize..(pc - 0x400000) as usize + width].to_vec();
                b[..len].copy_from_slice(&write);
                Some(b)
            } else {
                None
            };
            writeln!(&mut plan,"step\t{}\t{local}\t{kind}\t{logical}\t{pc}\t{pc}\t{}\nlive-prerequisites-not-receipts\t{}\t{local}\ttrue\ttrue\t{router}\nstep-read\t{}\t{local}\t{start}\t{}\nsemantic-write\t{}\t{local}\t{pc}\t{}",s.id,pc+len as u64,s.id,s.id,hex(&current[(start-0x400000) as usize..(end-0x400000) as usize]),s.id,hex(&write)).unwrap();
            if let Some(store) = &store {
                writeln!(
                    &mut plan,
                    "live-store-span\t{}\t{local}\t{pc}\t{}",
                    s.id,
                    hex(store)
                )
                .unwrap();
            }
            writeln!(&mut plan, "entry-preserved\t{}\t{local}\t{pc}", s.id).unwrap();
            if pun {
                writeln!(
                    &mut plan,
                    "entry-preserved\t{}\t{local}\t{}",
                    s.id,
                    pc + len as u64
                )
                .unwrap();
            }
            if router {
                writeln!(
                    &mut plan,
                    "entry-router-required\t{}\t{local}\t{}\t{}",
                    s.id,
                    pc + route_offset,
                    entry + body_offset
                )
                .unwrap();
            }
            if pair != 0 && s.id == 1 {
                writeln!(&mut plan, "entry-preserved\t{}\t{local}\t{}", s.id, pc + 4).unwrap();
            }
            if forward && s.id == 2 {
                for extra in [3, 4] {
                    writeln!(
                        &mut plan,
                        "entry-preserved\t{}\t{local}\t{}",
                        s.id,
                        pc + extra
                    )
                    .unwrap();
                }
            }
            writeln!(
                &mut plan,
                "allocation\t{}\t{local}\t{}\t{}\t4096",
                s.id,
                entry & !4095,
                (entry & !4095) + 4096
            )
            .unwrap();
            current[(pc - 0x400000) as usize..(pc - 0x400000) as usize + write.len()]
                .copy_from_slice(&write);
            locks.push(Range {
                start: pc,
                end: pc + if pun { 5 + prefixes as u64 } else { len as u64 },
            });
            if is_neighbor {
                locks.push(Range::bytes(pc, write.len()).unwrap());
            }
            deps.push((start - 0x400000, end - 0x400000));
            let mut data = if is_upstream {
                let mut b = vec![0x90, 0x66, 0x66, 0x75, 0];
                b.extend_from_slice(&rel(entry + 5, pc + 5));
                b
            } else {
                rel(entry, pc + len as u64)
            };
            if router && !is_upstream {
                data.extend_from_slice(&[0x4c, 0x89, 0xe7]);
                data.extend_from_slice(&rel(entry + 8, pc + 5));
            }
            product
                .0
                .insert(format!("image-{image_id:04}.bin"), data.clone());
            writeln!(&mut image_rows,"image\t{image_id}\t{}\t{entry}\t{}\t{}\timage-{image_id:04}.bin\nroute\t{image_id}\t{pc}\t{entry}",s.id,data.len(),digest(&data)).unwrap();
            if router {
                writeln!(
                    &mut image_rows,
                    "route\t{image_id}\t{}\t{}",
                    pc + route_offset,
                    entry + body_offset
                )
                .unwrap();
            }
            writeln!(
                &mut image_rows,
                "restored-boundary\t{image_id}\t{pc}\t{entry}"
            )
            .unwrap();
            if router {
                writeln!(
                    &mut image_rows,
                    "restored-boundary\t{image_id}\t{}\t{}",
                    pc + route_offset,
                    entry + body_offset
                )
                .unwrap();
            }
            writeln!(
                &mut image_rows,
                "pc-range\t{image_id}\t{entry}\t{}\t{pc}",
                entry + if is_upstream { 1 } else { 5 }
            )
            .unwrap();
            if router {
                writeln!(
                    &mut image_rows,
                    "pc-range\t{image_id}\t{}\t{}\t{}",
                    entry + body_offset,
                    entry + data.len() as u64,
                    pc + route_offset
                )
                .unwrap();
            }
            let field_offset = if is_upstream { 6 } else { 1 };
            let field_origin = if is_upstream { 10 } else { 5 };
            writeln!(
                &mut image_rows,
                "field\t{image_id}\t{field_offset}\t4\tRelative\t{field_origin}\t{}\t1\t{}\t{}",
                pc + len as u64,
                hex(b"synthetic return field"),
                hex(&data[field_offset..field_offset + 4])
            )
            .unwrap();
            if router && !is_upstream {
                writeln!(
                    &mut image_rows,
                    "field\t{image_id}\t9\t4\tRelative\t13\t{}\t1\t{}\t{}",
                    pc + 5,
                    hex(b"synthetic suffix continuation"),
                    hex(&data[9..])
                )
                .unwrap();
            }
            if pair != 0 && (s.id == 1 || s.id == 2) {
                product.0.insert(format!("site-{}.diagnostics.txt",s.id),format!("pair_family={}\nadjacent_attempt=0 member={} role={} selected_id={} image_start={image_id} image_count=1 step_start={image_id} step_count=1\nopaque\n",if routed {"jbe-routed-jmp-mov-r12-rdi-v1"}else{"forward-jcc-b2-v1"},if s.id==2 {0}else{1},if s.id==2 {"upper"}else{"lower"},s.id).into_bytes());
            }
            let mut fixture_requirements = vec![(1, 0), (2, 0), (3, 0), (4, 0), (7, 0), (8, 0)];
            if hook {
                fixture_requirements.push((5, 1));
            }
            if router {
                fixture_requirements.push((6, 0));
            }
            for &(code, identity) in &fixture_requirements {
                writeln!(
                    &mut image_rows,
                    "unmet-requirement\t{image_id}\t{code}\t{identity}"
                )
                .unwrap();
            }
            if startup {
                let mut obligations = vec![boot::Obligation {
                    original: pc,
                    generated: None,
                }];
                if pun {
                    obligations.push(boot::Obligation {
                        original: pc + len as u64,
                        generated: None,
                    });
                }
                if router {
                    obligations.push(boot::Obligation {
                        original: pc + route_offset,
                        generated: Some(entry + body_offset),
                    });
                }
                if pair != 0 && s.id == 1 {
                    obligations.push(boot::Obligation {
                        original: pc + 4,
                        generated: None,
                    });
                }
                if forward && s.id == 2 {
                    for extra in [3, 4] {
                        obligations.push(boot::Obligation {
                            original: pc + extra,
                            generated: None,
                        });
                    }
                }
                let kind = if pun {
                    let free = len - prefixes - 1;
                    let displacement = u32::try_from(entry - (pc + 5 + prefixes as u64)).unwrap();
                    let low_mask = (1u32 << (free * 8)) - 1;
                    let p = boot::Pun {
                        instruction_len: len as u64,
                        prefixes: prefixes as u64,
                        consumed: boot::Span {
                            start: pc,
                            len: 5 + prefixes as u64,
                        },
                        target_window: boot::Span {
                            start: entry - u64::from(displacement & low_mask),
                            len: 1u64 << (free * 8),
                        },
                        store: boot::Span {
                            start: pc,
                            len: len.next_power_of_two() as u64,
                        },
                    };
                    if prefixes == 0 {
                        boot::Kind::GeneralizedPun(p)
                    } else {
                        boot::Kind::PrefixedPun(p)
                    }
                } else {
                    boot::Kind::Relocation
                };
                let mut writes = vec![boot::Blob {
                    address: pc,
                    bytes: write.clone(),
                }];
                if let Some(store) = store {
                    writes.push(boot::Blob {
                        address: pc,
                        bytes: store,
                    });
                }
                startup_steps.push(boot::Step {
                    selected_id: s.id,
                    logical,
                    physical: pc,
                    displaced: boot::Span {
                        start: pc,
                        len: len as u64,
                    },
                    kind,
                    neighbor: if is_neighbor {
                        Some(boot::Neighbor {
                            selected: s.pc,
                            selected_len: 2,
                            victim: s.pc + 2,
                            victim_len: 6,
                            relay: s.pc + 7,
                            rel8: 5,
                            selected_target: s.pc + 12 + 0x00401f0f,
                            victim_target: 0x500000,
                        })
                    } else {
                        None
                    },
                    reads: vec![boot::Blob {
                        address: start,
                        bytes: observed,
                    }],
                    writes,
                    dependencies: vec![boot::Span {
                        start,
                        len: end - start,
                    }],
                    allocation: boot::Span {
                        start: entry & !4095,
                        len: 4096,
                    },
                    image: entry,
                    obligations,
                });
                let mut entries = vec![(pc, entry)];
                if router {
                    entries.push((pc + route_offset, entry + body_offset));
                }
                startup_images.push(boot::Image {
                    body: boot::Blob {
                        address: entry,
                        bytes: data.clone(),
                    },
                    entries,
                    requirements: fixture_requirements,
                });
            }
            image_id += 1;
        }
        if t3 && s.id == 1 {
            writeln!(
                &mut plan,
                "source-relay-geometry-hex\t{}\t{}",
                s.id,
                hex(b"independently authored short neighbor fixture")
            )
            .unwrap();
        }
        plan.push_str(&image_rows);
    }
    for r in merge(locks, true) {
        writeln!(&mut plan, "byte-lock\t{}\t{}", r.start, r.end).unwrap();
    }
    for (a, b) in deps {
        writeln!(&mut plan, "original-file-dependency\t{a}\t{b}").unwrap();
    }
    let records = report_records(&original, &facts, report.as_bytes()).unwrap();
    let compatibility = Compatibility {
        planner: 3,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&facts.target),
        binding: ContentId::of(&facts.full_selection),
    };
    let meta = Metadata::new(
        &original,
        ContentId::of(&facts.full_selection),
        compatibility,
        records.clone(),
    )
    .unwrap()
    .encode(formats::Limits::default())
    .unwrap();
    let joined = ledger::join(&original, &facts, &records, plan.as_bytes(), &product).unwrap();
    let elf = Elf64::parse(&original, ParseLimits::default()).unwrap();
    let mut payload = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
    payload.extend_from_slice(&ContentId::of(&meta).0);
    payload.extend_from_slice(&ContentId::of(plan.as_bytes()).0);
    let output = carrier::append_exec_carrier_with_interleaved_loads(
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
    )
    .unwrap();
    let mut full = plan.clone();
    write!(&mut full,"CARRIER-EXTENSION\t1\ncandidate_sha256\t{}\nnew_load_pages\t{}\nphdr_file\t{}\t{}\nphdr_vaddr\t4718592\n",digest(output.bytes()),output.new_load_pages,output.program_table.start().0,output.program_table.len()).unwrap();
    for (id, i) in output.images.iter().enumerate() {
        writeln!(
            &mut full,
            "elf-image\t{id}\t{}\t{}\t{}\t{}",
            i.entry.0,
            i.file.start().0,
            i.file.len(),
            i.program_header
        )
        .unwrap();
    }
    for c in output.changes() {
        writeln!(
            &mut full,
            "elf-change\t{:?}\t{}\t{}\t{}",
            c.kind,
            c.edit.offset.0,
            hex(&c.edit.expected),
            hex(&c.edit.replacement)
        )
        .unwrap();
    }
    let sparse = formats::sparse::SparsePages::build(
        &original,
        joined
            .edits
            .iter()
            .map(|e| formats::sparse::FileEdit {
                offset: e.offset.0,
                expected: e.expected.clone(),
                replacement: e.replacement.clone(),
            })
            .collect(),
        sparse_limits(),
    )
    .unwrap();
    for (name,bytes) in [("report.tsv",report.into_bytes()),("metadata.li2meta",meta),("plan-ledger.tsv",plan.into_bytes()),("ledger.tsv",full.into_bytes()),("candidate.elf",output.bytes().to_vec()),("source.li2sparse",formats::sparse_wire::encode(&sparse,wire_limits()).unwrap()),("adjacent-routed-jmp-evidence.txt",format!("LI2ADJACENT-ROUTED-JMP-EVIDENCE\t1\nselection_sha256\t{}\nselected_count\t{n}\nbaseline_calls\t{n}\npair_calls\t0\nadjacent_counts\t0\t0\t0\nforward_jcc_calls\t0\nforward_jcc_counts\t0\t0\t0\nrouted_jmp_calls\t0\nrouted_jmp_counts\t0\t0\t0\nqualification_complete\tfalse\nclassification_complete\tfalse\nlegacy_image_slots\t{image_id}\ncombined_image_work_upper_bound\t{image_id}\nresources\tsynthetic control only\n",digest(manifest.as_bytes())).into_bytes())] {product.0.insert(name.into(),bytes);}
    if pair != 0 {
        let evidence = product
            .0
            .get_mut("adjacent-routed-jmp-evidence.txt")
            .unwrap();
        let text = String::from_utf8(evidence.clone()).unwrap();
        *evidence = text
            .replace("pair_calls\t0", "pair_calls\t1")
            .replace("adjacent_counts\t0\t0\t0", "adjacent_counts\t1\t1\t1")
            .replace(
                &format!(
                    "{}_calls\t0",
                    if routed { "routed_jmp" } else { "forward_jcc" }
                ),
                &format!(
                    "{}_calls\t1",
                    if routed { "routed_jmp" } else { "forward_jcc" }
                ),
            )
            .replace(
                &format!(
                    "{}_counts\t0\t0\t0",
                    if routed { "routed_jmp" } else { "forward_jcc" }
                ),
                &format!(
                    "{}_counts\t1\t1\t1",
                    if routed { "routed_jmp" } else { "forward_jcc" }
                ),
            )
            .replace(
                &format!("combined_image_work_upper_bound\t{image_id}"),
                &format!("combined_image_work_upper_bound\t{}", image_id + 2),
            )
            .into_bytes();
    }
    reseal(&original, &mut product);
    Fixture {
        startup_steps,
        startup_images,
        startup_heads: if startup {
            heads.keys().copied().collect()
        } else {
            Vec::new()
        },
        original,
        expected,
        product,
    }
}
pub(super) fn reseal(original: &[u8], product: &mut Memory) {
    product.0.remove("COMPLETE");
    product.0.remove("bundle-index.tsv");
    let mut bundle = format!(
        "LI2BUNDLE\t1\noriginal_sha256\t{}\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n",
        digest(original)
    );
    for (name, b) in &product.0 {
        writeln!(&mut bundle, "file\t{name}\t{}\t{}", b.len(), digest(b)).unwrap();
    }
    product
        .0
        .insert("bundle-index.tsv".into(), bundle.into_bytes());
    let mut complete = format!(
        "LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{PROFILE}\nobserved_original_sha256\t{}\ncandidate_complete\ttrue\nqualification_complete\tfalse\n",
        digest(original)
    );
    for (name, b) in &product.0 {
        writeln!(&mut complete, "file\t{name}\t{}\t{}", b.len(), digest(b)).unwrap();
    }
    product.0.insert("COMPLETE".into(), complete.into_bytes());
}
fn accepts(f: &Fixture) -> bool {
    crate::indices(&f.original, &f.product).is_ok()
        && verify(&f.expected.program, &f.original, &f.expected, &f.product).is_ok()
}

#[test]
fn v01_complete_independent_rosters_before_every_expected_row_mutation() {
    for program in ["checksum", "rle-roundtrip"] {
        let mut f = fixture(program, false);
        assert!(accepts(&f));
        for name in EXPECTED_FILES {
            let original = f.product.0[name].clone();
            for (at, _) in original
                .iter()
                .enumerate()
                .filter(|(i, _)| *i == 0 || original[*i - 1] == b'\n')
            {
                let mut changed = original.clone();
                changed[at] ^= 1;
                f.product.0.insert(name.into(), changed);
                reseal(&f.original, &mut f.product);
                assert!(!accepts(&f), "{program} {name} row {at}");
            }
            f.product.0.insert(name.into(), original);
            reseal(&f.original, &mut f.product);
            assert!(accepts(&f));
        }
    }
}
#[test]
fn v02_v03_v05_complete_positive_auxiliary_predecessor_and_repaired_mutations() {
    let mut f = fixture("checksum", true);
    assert!(accepts(&f));
    for name in [
        "target.tsv",
        "report.tsv",
        "plan-ledger.tsv",
        "adjacent-routed-jmp-evidence.txt",
    ] {
        let original = f.product.0[name].clone();
        for (at, _) in original
            .iter()
            .enumerate()
            .filter(|(i, _)| *i == 0 || original[*i - 1] == b'\n')
        {
            let mut changed = original.clone();
            changed[at] ^= 1;
            f.product.0.insert(name.into(), changed);
            reseal(&f.original, &mut f.product);
            assert!(!accepts(&f), "{name} row {at}");
        }
        f.product.0.insert(name.into(), original);
        reseal(&f.original, &mut f.product);
        assert!(accepts(&f));
    }
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    let report = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
    let compatibility = Compatibility {
        planner: 3,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&facts.target),
        binding: ContentId::of(&facts.full_selection),
    };
    let valid = f.product.0["metadata.li2meta"].clone();
    let joined = ledger::join(
        &f.original,
        &facts,
        &report,
        &f.product.0["plan-ledger.tsv"],
        &f.product,
    )
    .unwrap();
    for records in [
        Vec::new(),
        report[..report.len() - 1].to_vec(),
        {
            let mut r = report.clone();
            r[0].outcome = Outcome::Trap;
            r
        },
        {
            let mut r = report.clone();
            r[0].original_pc += 1;
            r
        },
        {
            let mut r = report.clone();
            r[0].outcome = Outcome::Rewritten(Tactic::Relocation);
            r
        },
    ] {
        let bytes = Metadata::new(
            &f.original,
            ContentId::of(&facts.full_selection),
            compatibility.clone(),
            records,
        )
        .unwrap()
        .encode(formats::Limits::default())
        .unwrap();
        f.product.0.insert("metadata.li2meta".into(), bytes);
        repair_outer(&mut f, &joined);
        assert_metadata_refusal(&f, &facts, &report);
        assert!(!accepts(&f));
    }
    f.product.0.insert("metadata.li2meta".into(), valid);
    repair_outer(&mut f, &joined);
    assert!(accepts(&f));
    let valid = f.product.0["metadata.li2meta"].clone();
    // Mutating a stored chunk digest does not change the original digest. The
    // checked decoder accepts this repaired envelope; verify_chunk must refuse.
    let mut bytes = valid.clone();
    bytes[56 + 176] ^= 1;
    envelope(&mut bytes);
    assert!(Metadata::decode(&bytes, &compatibility, formats::Limits::default()).is_ok());
    f.product.0.insert("metadata.li2meta".into(), bytes);
    repair_outer(&mut f, &joined);
    assert_metadata_refusal(&f, &facts, &report);
    assert!(!accepts(&f));
    f.product.0.insert("metadata.li2meta".into(), valid);
    repair_outer(&mut f, &joined);
    assert!(accepts(&f));
    let valid = f.product.0["source.li2sparse"].clone();
    let sparse = formats::sparse_wire::decode(&valid, &f.original, wire_limits()).unwrap();
    let edits = sparse.edits().to_vec();
    let mut added = edits.clone();
    added.push(formats::sparse::FileEdit {
        offset: 800,
        expected: vec![0],
        replacement: vec![1],
    });
    added.sort_by_key(|e| e.offset);
    for changed in [edits[1..].to_vec(), added, {
        let mut v = edits.clone();
        v[0].replacement[0] ^= 1;
        v
    }] {
        let altered =
            formats::sparse::SparsePages::build(&f.original, changed, sparse_limits()).unwrap();
        f.product.0.insert(
            "source.li2sparse".into(),
            formats::sparse_wire::encode(&altered, wire_limits()).unwrap(),
        );
        reseal(&f.original, &mut f.product);
        crate::indices(&f.original, &f.product).unwrap();
        assert_eq!(
            verify("checksum", &f.original, &f.expected, &f.product)
                .err()
                .as_deref(),
            Some("exact sparse/ledger source join")
        );
        assert!(!accepts(&f));
    }
    f.product.0.insert("source.li2sparse".into(), valid);
    reseal(&f.original, &mut f.product);
    assert!(accepts(&f));
}

#[test]
fn v03_valid_syntax_value_mutants_reject_repaired_hashes() {
    let mut f = fixture("checksum", true);
    assert!(accepts(&f));
    let valid = f.product.0["plan-ledger.tsv"].clone();
    let text = std::str::from_utf8(&valid).unwrap();
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
    let joined = ledger::join(&f.original, &facts, &records, &valid, &f.product).unwrap();
    for (tag, column) in [
        ("step", 1),
        ("step", 2),
        ("step", 4),
        ("step", 5),
        ("step", 7),
        ("allocation", 3),
        ("allocation", 4),
        ("image", 2),
        ("route", 2),
        ("route", 3),
        ("restored-boundary", 3),
        ("pc-range", 3),
        ("pc-range", 4),
        ("field", 2),
        ("field", 5),
        ("field", 6),
        ("field", 7),
        ("unmet-requirement", 2),
        ("unmet-requirement", 3),
        ("byte-lock", 2),
        ("original-file-dependency", 2),
    ] {
        let mut rows: Vec<String> = text.lines().map(str::to_string).collect();
        let at = rows
            .iter()
            .position(|r| r.split('\t').next() == Some(tag))
            .unwrap();
        let mut cells: Vec<String> = rows[at].split('\t').map(str::to_string).collect();
        cells[column] = (cells[column].parse::<u64>().unwrap() + 1).to_string();
        rows[at] = cells.join("\t");
        f.product.0.insert(
            "plan-ledger.tsv".into(),
            (rows.join("\n") + "\n").into_bytes(),
        );
        repair_outer(&mut f, &joined);
        assert!(
            ledger::join(
                &f.original,
                &facts,
                &records,
                &f.product.0["plan-ledger.tsv"],
                &f.product
            )
            .is_err(),
            "numeric ledger mutant accepted: {tag} column {column}"
        );
        let intended = matches!((tag, column), ("route" | "restored-boundary", 3))
            .then_some("entry/restored target is not a generated instruction head");
        assert_ledger_refusal(&f, &facts, &records, intended);
        assert!(!accepts(&f), "{tag} {column}");
    }
    for tag in ["step-read", "semantic-write", "live-store-span", "field"] {
        let mut rows: Vec<String> = text.lines().map(str::to_string).collect();
        let at = rows
            .iter()
            .rposition(|r| r.split('\t').next() == Some(tag))
            .unwrap();
        let mut cells: Vec<String> = rows[at].split('\t').map(str::to_string).collect();
        let last = cells.len() - 1;
        let mut bytes = unhex(&cells[last]).unwrap();
        bytes[0] ^= 1;
        cells[last] = hex(&bytes);
        rows[at] = cells.join("\t");
        f.product.0.insert(
            "plan-ledger.tsv".into(),
            (rows.join("\n") + "\n").into_bytes(),
        );
        repair_outer(&mut f, &joined);
        let intended = match tag {
            "step-read" => "predecessor current-overlay read",
            "semantic-write" => "literal supported pun prefix",
            "live-store-span" => "exact live store and preserved padding",
            "field" => "serialized fixup bounds/domain/actual bytes/uniqueness",
            _ => unreachable!(),
        };
        assert_ledger_refusal(&f, &facts, &records, Some(intended));
        assert!(!accepts(&f), "{tag}");
    }
    for code in [1, 2, 3, 4, 5, 7, 8] {
        let mut rows: Vec<String> = text.lines().map(str::to_string).collect();
        let at = rows
            .iter()
            .position(|r| {
                r.starts_with("unmet-requirement\t0\t")
                    && r.split('\t').nth(2) == Some(code.to_string().as_str())
            })
            .unwrap();
        rows.remove(at);
        f.product.0.insert(
            "plan-ledger.tsv".into(),
            (rows.join("\n") + "\n").into_bytes(),
        );
        repair_outer(&mut f, &joined);
        assert_ledger_refusal(
            &f,
            &facts,
            &records,
            Some("exact constructor-derived unmet requirements"),
        );
        assert!(!accepts(&f), "missing requirement {code}");
    }
    f.product.0.insert("plan-ledger.tsv".into(), valid);
    repair_outer(&mut f, &joined);
    assert!(accepts(&f));
}

fn assert_metadata_refusal(f: &Fixture, facts: &Facts, records: &[Site]) {
    crate::indices(&f.original, &f.product).unwrap();
    let refusal = metadata_join(
        &f.original,
        facts,
        records,
        &f.product.0["metadata.li2meta"],
    )
    .expect_err("intended metadata checker must refuse");
    assert_eq!(
        verify(&f.expected.program, &f.original, &f.expected, &f.product).err(),
        Some(refusal)
    );
}
fn assert_ledger_refusal(f: &Fixture, facts: &Facts, records: &[Site], intended: Option<&str>) {
    crate::indices(&f.original, &f.product).unwrap();
    let refusal = ledger::join(
        &f.original,
        facts,
        records,
        &f.product.0["plan-ledger.tsv"],
        &f.product,
    )
    .err()
    .expect("intended ledger checker must refuse");
    if let Some(intended) = intended {
        assert_eq!(refusal, intended);
    }
    assert_eq!(
        verify(&f.expected.program, &f.original, &f.expected, &f.product).err(),
        Some(refusal)
    );
}

// Repair the complete outer identity graph using the valid fixture's joined
// source edits/images. A corrupted ledger must fail its semantic join, not a
// stale payload, candidate, carrier-extension or directory digest.
fn repair_outer(f: &mut Fixture, joined: &ledger::Joined) {
    let plan = &f.product.0["plan-ledger.tsv"];
    let meta = &f.product.0["metadata.li2meta"];
    let mut payload = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
    payload.extend_from_slice(&ContentId::of(meta).0);
    payload.extend_from_slice(&ContentId::of(plan).0);
    let elf = Elf64::parse(&f.original, ParseLimits::default()).unwrap();
    let output = carrier::append_exec_carrier_with_interleaved_loads(
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
    )
    .unwrap();
    let mut full = String::from_utf8(plan.clone()).unwrap();
    write!(&mut full,"CARRIER-EXTENSION\t1\ncandidate_sha256\t{}\nnew_load_pages\t{}\nphdr_file\t{}\t{}\nphdr_vaddr\t4718592\n",digest(output.bytes()),output.new_load_pages,output.program_table.start().0,output.program_table.len()).unwrap();
    for (id, i) in output.images.iter().enumerate() {
        writeln!(
            &mut full,
            "elf-image\t{id}\t{}\t{}\t{}\t{}",
            i.entry.0,
            i.file.start().0,
            i.file.len(),
            i.program_header
        )
        .unwrap();
    }
    for c in output.changes() {
        writeln!(
            &mut full,
            "elf-change\t{:?}\t{}\t{}\t{}",
            c.kind,
            c.edit.offset.0,
            hex(&c.edit.expected),
            hex(&c.edit.replacement)
        )
        .unwrap();
    }
    f.product.0.insert("ledger.tsv".into(), full.into_bytes());
    f.product
        .0
        .insert("candidate.elf".into(), output.bytes().to_vec());
    reseal(&f.original, &mut f.product);
}
#[test]
fn c04_both_families_both_programs_complete_then_rebound_role_and_ledger_mutants() {
    for program in ["checksum", "rle-roundtrip"] {
        for routed in [false, true] {
            let mut f = if routed {
                routed_fixture(program)
            } else {
                forward_fixture(program)
            };
            assert!(accepts(&f));
            let facts = f.expected.facts(&f.original, &f.product).unwrap();
            let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
            let joined = ledger::join(
                &f.original,
                &facts,
                &records,
                &f.product.0["plan-ledger.tsv"],
                &f.product,
            )
            .unwrap();
            assert_eq!(
                (joined.associations.forward, joined.associations.routed),
                if routed { (0, 1) } else { (1, 0) }
            );
            let valid = f.product.clone();
            for (tag, col) in [
                ("step", 1),
                ("step", 2),
                ("step", 4),
                ("step", 5),
                ("step", 7),
                ("allocation", 3),
                ("allocation", 4),
                ("image", 2),
                ("route", 2),
                ("route", 3),
                ("restored-boundary", 3),
                ("pc-range", 3),
                ("pc-range", 4),
                ("field", 2),
                ("field", 5),
                ("field", 6),
                ("field", 7),
                ("unmet-requirement", 2),
                ("unmet-requirement", 3),
                ("byte-lock", 2),
                ("original-file-dependency", 2),
            ] {
                f.product = valid.clone();
                let mut rows: Vec<String> =
                    String::from_utf8(f.product.0["plan-ledger.tsv"].clone())
                        .unwrap()
                        .lines()
                        .map(str::to_string)
                        .collect();
                let at = rows
                    .iter()
                    .position(|r| r.split('\t').next() == Some(tag))
                    .unwrap();
                let mut cells: Vec<_> = rows[at].split('\t').map(str::to_string).collect();
                cells[col] = (cells[col].parse::<u64>().unwrap() + 1).to_string();
                rows[at] = cells.join("\t");
                f.product.0.insert(
                    "plan-ledger.tsv".into(),
                    (rows.join("\n") + "\n").into_bytes(),
                );
                repair_outer(&mut f, &joined);
                crate::indices(&f.original, &f.product).unwrap();
                let refusal = ledger::join(
                    &f.original,
                    &facts,
                    &records,
                    &f.product.0["plan-ledger.tsv"],
                    &f.product,
                )
                .err()
                .unwrap_or_else(|| panic!("numeric ledger mutant accepted: {program} routed={routed} {tag} column {col}"));
                if matches!((tag, col), ("route" | "restored-boundary", 3)) {
                    assert_eq!(
                        refusal,
                        "entry/restored target is not a generated instruction head"
                    );
                }
                assert_eq!(
                    verify(program, &f.original, &f.expected, &f.product).err(),
                    Some(refusal),
                    "{tag} {col}"
                );
            }
            for (before, after) in [
                ("member=0", "member=1"),
                ("role=upper", "role=lower"),
                ("selected_id=2", "selected_id=1"),
                ("image_count=1", "image_count=0"),
                ("step_count=1", "step_count=2"),
                ("adjacent_attempt=0", "adjacent_attempt=1"),
            ] {
                f.product = valid.clone();
                let key = "site-2.diagnostics.txt";
                let text = String::from_utf8(f.product.0[key].clone()).unwrap();
                assert!(text.contains(before));
                f.product
                    .0
                    .insert(key.into(), text.replace(before, after).into_bytes());
                repair_outer(&mut f, &joined);
                crate::indices(&f.original, &f.product).unwrap();
                assert!(!accepts(&f), "{before}");
            }
            f.product = valid.clone();
            f.product.0.insert(
                "site-1.diagnostics.txt".into(),
                b"singleton opaque\n".to_vec(),
            );
            repair_outer(&mut f, &joined);
            assert!(!accepts(&f));
            f.product = valid.clone();
            for id in [1, 2] {
                let key = format!("site-{id}.diagnostics.txt");
                let text = String::from_utf8(f.product.0[&key].clone()).unwrap();
                let changed = if routed {
                    text.replace("jbe-routed-jmp-mov-r12-rdi-v1", "forward-jcc-b2-v1")
                } else {
                    text.replace("forward-jcc-b2-v1", "jbe-routed-jmp-mov-r12-rdi-v1")
                };
                f.product.0.insert(key, changed.into_bytes());
            }
            repair_outer(&mut f, &joined);
            assert!(!accepts(&f));
            f.product = valid.clone();
            for id in [1, 2] {
                f.product.0.insert(
                    format!("site-{id}.diagnostics.txt"),
                    b"singleton opaque\n".to_vec(),
                );
            }
            repair_outer(&mut f, &joined);
            assert!(!accepts(&f));
            f.product = valid.clone();
            let name = "adjacent-routed-jmp-evidence.txt";
            let text = String::from_utf8(f.product.0[name].clone()).unwrap();
            f.product.0.insert(
                name.into(),
                text.replace("pair_calls\t1", "pair_calls\t0").into_bytes(),
            );
            reseal(&f.original, &mut f.product);
            assert!(!accepts(&f));
            f.product = valid;
            assert!(accepts(&f));
        }
    }
}

#[test]
fn c04_auxiliary_and_routed_requirements_omission_repaired_before_exact_join() {
    for mut f in [fixture("checksum", true), routed_fixture("checksum")] {
        assert!(accepts(&f));
        let facts = f.expected.facts(&f.original, &f.product).unwrap();
        let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
        let joined = ledger::join(
            &f.original,
            &facts,
            &records,
            &f.product.0["plan-ledger.tsv"],
            &f.product,
        )
        .unwrap();
        let valid = f.product.clone();
        let text = String::from_utf8(valid.0["plan-ledger.tsv"].clone()).unwrap();
        for (at, row) in text
            .lines()
            .enumerate()
            .filter(|(_, l)| l.starts_with("unmet-requirement\t"))
        {
            let mut lines: Vec<_> = text.lines().collect();
            lines.remove(at);
            f.product = valid.clone();
            f.product.0.insert(
                "plan-ledger.tsv".into(),
                (lines.join("\n") + "\n").into_bytes(),
            );
            repair_outer(&mut f, &joined);
            crate::indices(&f.original, &f.product).unwrap();
            assert_eq!(
                ledger::join(
                    &f.original,
                    &facts,
                    &records,
                    &f.product.0["plan-ledger.tsv"],
                    &f.product
                )
                .err()
                .as_deref(),
                Some("exact constructor-derived unmet requirements"),
                "{row}"
            );
        }
        f.product = valid;
        assert!(accepts(&f));
    }
    let mut f = routed_fixture("checksum");
    assert!(accepts(&f));
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
    let joined = ledger::join(
        &f.original,
        &facts,
        &records,
        &f.product.0["plan-ledger.tsv"],
        &f.product,
    )
    .unwrap();
    let text = String::from_utf8(f.product.0["plan-ledger.tsv"].clone()).unwrap();
    let rows: Vec<_> = text
        .lines()
        .filter(|row| {
            !row.starts_with("entry-router-required\t")
                && !(row.starts_with("unmet-requirement\t") && row.split('\t').nth(2) == Some("6"))
        })
        .collect();
    f.product.0.insert(
        "plan-ledger.tsv".into(),
        (rows.join("\n") + "\n").into_bytes(),
    );
    repair_outer(&mut f, &joined);
    crate::indices(&f.original, &f.product).unwrap();
    assert_eq!(
        ledger::join(
            &f.original,
            &facts,
            &records,
            &f.product.0["plan-ledger.tsv"],
            &f.product
        )
        .err()
        .as_deref(),
        Some("exact routed upper suffix route/marker")
    );
}

#[test]
fn c04_sparse_split_reordered_pages_and_repaired_wire_mutants() {
    let mut f = fixture("rle-roundtrip", true);
    assert!(accepts(&f));
    let valid = f.product.0["source.li2sparse"].clone();
    let sparse = formats::sparse_wire::decode(&valid, &f.original, wire_limits()).unwrap();
    let mut edits = sparse.edits().to_vec();
    let at = edits.iter().position(|e| e.expected.len() > 1).unwrap();
    let old = edits.remove(at);
    edits.insert(
        at,
        formats::sparse::FileEdit {
            offset: old.offset + 1,
            expected: old.expected[1..].to_vec(),
            replacement: old.replacement[1..].to_vec(),
        },
    );
    edits.insert(
        at,
        formats::sparse::FileEdit {
            offset: old.offset,
            expected: old.expected[..1].to_vec(),
            replacement: old.replacement[..1].to_vec(),
        },
    );
    let split = formats::sparse::SparsePages::build(&f.original, edits, sparse_limits()).unwrap();
    assert_eq!(split.pages(), sparse.pages());
    f.product.0.insert(
        "source.li2sparse".into(),
        formats::sparse_wire::encode(&split, wire_limits()).unwrap(),
    );
    reseal(&f.original, &mut f.product);
    assert!(!accepts(&f));
    assert!(sparse.pages().len() >= 2);
    let pages_at = 120
        + sparse
            .edits()
            .iter()
            .map(|e| 16 + 2 * e.expected.len())
            .sum::<usize>();
    let first_end = pages_at + 16 + sparse.pages()[0].bytes.len();
    let second_end = first_end + 16 + sparse.pages()[1].bytes.len();
    let mut reordered = valid[..pages_at].to_vec();
    reordered.extend_from_slice(&valid[first_end..second_end]);
    reordered.extend_from_slice(&valid[pages_at..first_end]);
    reordered.extend_from_slice(&valid[second_end..]);
    envelope(&mut reordered);
    assert!(matches!(
        formats::sparse_wire::decode(&reordered, &f.original, wire_limits()),
        Err(formats::sparse_wire::Error::Content(
            formats::sparse::Error::PageMismatch
        ))
    ));
    f.product.0.insert("source.li2sparse".into(), reordered);
    reseal(&f.original, &mut f.product);
    assert!(!accepts(&f));
    // Fixed envelope and body offsets from the pinned LI2SPRS v1 codec.
    for at in [56usize, 64, 96, 104, 112, 120, 128, 136, valid.len() - 1] {
        let mut bad = valid.clone();
        bad[at] ^= 1;
        envelope(&mut bad);
        f.product.0.insert("source.li2sparse".into(), bad);
        reseal(&f.original, &mut f.product);
        assert!(!accepts(&f), "sparse byte {at}");
    }
    f.product.0.insert("source.li2sparse".into(), valid);
    reseal(&f.original, &mut f.product);
    assert!(accepts(&f));
}

#[test]
fn f01_all_heads_mode_requires_exact_independent_region_roster() {
    for program in ["checksum", "rle-roundtrip"] {
        for routed in [false, true] {
            let f = if routed {
                routed_fixture(program)
            } else {
                forward_fixture(program)
            };
            assert!(accepts(&f));
            let facts = f.expected.facts(&f.original, &f.product).unwrap();
            assert!(facts.selection.sites.iter().all(|site| site.completeness
                == li2core::contracts::EntryCompleteness::AllInstructionHeads));
            for mutation in ["unknown", "wrong-provenance"] {
                let mut expected = f.expected.clone();
                let mut product = f.product.clone();
                let before = format!(
                    "entries 1 complete {}",
                    digest(&expected.files["disassembly.txt"])
                );
                let after = if mutation == "unknown" {
                    format!(
                        "entries 1 unknown {}",
                        digest(&expected.files["disassembly.txt"])
                    )
                } else {
                    format!("entries 1 complete {}", digest(b"different head ledger"))
                };
                let changed = String::from_utf8(expected.files["selection.txt"].clone())
                    .unwrap()
                    .replace(&before, &after)
                    .into_bytes();
                expected
                    .files
                    .insert("selection.txt".into(), changed.clone());
                product.0.insert("selection.txt".into(), changed);
                assert_eq!(
                    expected.facts(&f.original, &product).err().as_deref(),
                    Some("verified head provenance and textual entry contract"),
                    "{mutation}"
                );
            }
            let mut expected = f.expected.clone();
            let mut product = f.product.clone();
            let text = String::from_utf8(expected.files["selection.txt"].clone()).unwrap();
            let mut rows: Vec<String> = text.lines().map(str::to_string).collect();
            let at = rows
                .iter()
                .position(|row| row.starts_with("entries 1 "))
                .unwrap();
            let mut cells: Vec<_> = rows[at].split(' ').collect();
            cells.pop();
            rows[at] = cells.join(" ");
            let incomplete = (rows.join("\n") + "\n").into_bytes();
            expected
                .files
                .insert("selection.txt".into(), incomplete.clone());
            product.0.insert("selection.txt".into(), incomplete);
            assert_eq!(
                expected.facts(&f.original, &product).err().as_deref(),
                Some("full region heads")
            );
        }
    }
}

#[test]
fn f02_upstream_b1_trap_survives_complete_image_and_artifact_rebinding() {
    for program in ["checksum", "rle-roundtrip"] {
        let mut f = upstream_fixture(program);
        assert!(accepts(&f));
        let facts = f.expected.facts(&f.original, &f.product).unwrap();
        let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
        let mut joined = ledger::join(
            &f.original,
            &facts,
            &records,
            &f.product.0["plan-ledger.tsv"],
            &f.product,
        )
        .unwrap();
        let pc = facts.selection.sites[0].pc - 1;
        let id = joined.images.len() - 1;
        let before = joined.images[id].entry.0;
        let after = before + 0x8a;
        assert_eq!(rel(pc, before)[1], 0x06);
        assert_eq!(rel(pc, after)[1], 0x90);
        assert_eq!(
            hull(before, joined.images[id].bytes.len()).unwrap(),
            hull(after, joined.images[id].bytes.len()).unwrap()
        );
        let mut image = joined.images[id].bytes.clone();
        image[6..10].copy_from_slice(&rel(after + 5, pc + 5)[1..]);
        joined.images[id].entry = ElfVaddr(after);
        joined.images[id].bytes = image.clone();
        let offset = pc + 1 - 0x400000;
        let edit = joined
            .edits
            .iter_mut()
            .find(|edit| {
                edit.offset.0 <= offset && offset < edit.offset.0 + edit.replacement.len() as u64
            })
            .unwrap();
        edit.replacement[(offset - edit.offset.0) as usize] = 0x90;
        let old = String::from_utf8(f.product.0["plan-ledger.tsv"].clone()).unwrap();
        let mut rows = Vec::new();
        for row in old.lines() {
            let mut cells: Vec<String> = row.split('\t').map(str::to_string).collect();
            let tag = cells[0].clone();
            if tag == "semantic-write" && cells[1] == "1" {
                cells[4] = hex(&rel(pc, after));
            }
            if tag == "entry-router-required" && cells[1] == "1" {
                cells[4] = (after + 1).to_string();
            }
            if matches!(
                tag.as_str(),
                "image" | "route" | "restored-boundary" | "pc-range" | "field"
            ) && cells[1] == id.to_string()
            {
                match tag.as_str() {
                    "image" => {
                        cells[3] = after.to_string();
                        cells[5] = digest(&image);
                    }
                    "route" | "restored-boundary" => {
                        cells[3] = (number(&cells[3]).unwrap() + 0x8a).to_string();
                    }
                    "pc-range" => {
                        for at in [2, 3] {
                            cells[at] = (number(&cells[at]).unwrap() + 0x8a).to_string();
                        }
                    }
                    "field" => {
                        assert_eq!(cells[2], "6");
                        cells[9] = hex(&image[6..10]);
                    }
                    _ => unreachable!(),
                }
            }
            rows.push(cells.join("\t"));
        }
        f.product.0.insert(
            "plan-ledger.tsv".into(),
            (rows.join("\n") + "\n").into_bytes(),
        );
        f.product.0.insert(format!("image-{id:04}.bin"), image);
        let sparse = formats::sparse::SparsePages::build(
            &f.original,
            joined
                .edits
                .iter()
                .map(|e| formats::sparse::FileEdit {
                    offset: e.offset.0,
                    expected: e.expected.clone(),
                    replacement: e.replacement.clone(),
                })
                .collect(),
            sparse_limits(),
        )
        .unwrap();
        f.product.0.insert(
            "source.li2sparse".into(),
            formats::sparse_wire::encode(&sparse, wire_limits()).unwrap(),
        );
        repair_outer(&mut f, &joined);
        crate::indices(&f.original, &f.product).unwrap();
        // The complete source/image/candidate graph agrees with the mutated
        // target. Refusal must be the original-entry #UD obligation itself.
        candidate::join(
            &f.original,
            &facts,
            &joined,
            &f.product.0["metadata.li2meta"],
            &f.product.0["plan-ledger.tsv"],
            &f.product.0["candidate.elf"],
            &f.product.0["ledger.tsv"],
        )
        .unwrap();
        assert_ledger_refusal(
            &f,
            &facts,
            &records,
            Some("routed displacement byte is not guaranteed #UD"),
        );
        assert!(!accepts(&f));
    }
}

#[test]
fn f04_each_metadata_compatibility_identity_and_roster_field_rebound() {
    for program in ["checksum", "rle-roundtrip"] {
        let mut f = fixture(program, true);
        assert!(accepts(&f));
        let facts = f.expected.facts(&f.original, &f.product).unwrap();
        let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
        let joined = ledger::join(
            &f.original,
            &facts,
            &records,
            &f.product.0["plan-ledger.tsv"],
            &f.product,
        )
        .unwrap();
        let policy = Compatibility {
            planner: 3,
            encoder: 1,
            hook_abi: 1,
            arena: 1,
            target: ContentId::of(&facts.target),
            binding: ContentId::of(&facts.full_selection),
        };
        let valid = f.product.clone();
        for field in [
            "planner", "encoder", "hook_abi", "arena", "target", "binding",
        ] {
            let mut altered = policy.clone();
            match field {
                "planner" => altered.planner += 1,
                "encoder" => altered.encoder += 1,
                "hook_abi" => altered.hook_abi += 1,
                "arena" => altered.arena += 1,
                "target" => altered.target.0[0] ^= 1,
                "binding" => altered.binding.0[0] ^= 1,
                _ => unreachable!(),
            }
            f.product = valid.clone();
            f.product.0.insert(
                "metadata.li2meta".into(),
                Metadata::new(
                    &f.original,
                    ContentId::of(&facts.full_selection),
                    altered,
                    records.clone(),
                )
                .unwrap()
                .encode(formats::Limits::default())
                .unwrap(),
            );
            repair_outer(&mut f, &joined);
            assert_metadata_refusal(&f, &facts, &records);
            assert_eq!(
                metadata_join(
                    &f.original,
                    &facts,
                    &records,
                    &f.product.0["metadata.li2meta"]
                )
                .err()
                .as_deref(),
                Some("Incompatible"),
                "{field}"
            );
        }
        for field in ["file_offset", "length", "substitution"] {
            let mut altered = records.clone();
            match field {
                "file_offset" => altered[0].file_offset += 1,
                "length" => altered[0].length += 1,
                "substitution" => {
                    let id = altered[0].id;
                    altered[0] = altered[1].clone();
                    altered[0].id = id;
                }
                _ => unreachable!(),
            }
            f.product = valid.clone();
            f.product.0.insert(
                "metadata.li2meta".into(),
                Metadata::new(
                    &f.original,
                    ContentId::of(&facts.full_selection),
                    policy.clone(),
                    altered,
                )
                .unwrap()
                .encode(formats::Limits::default())
                .unwrap(),
            );
            repair_outer(&mut f, &joined);
            assert_metadata_refusal(&f, &facts, &records);
            assert_eq!(
                metadata_join(
                    &f.original,
                    &facts,
                    &records,
                    &f.product.0["metadata.li2meta"]
                )
                .err()
                .as_deref(),
                Some("metadata/report/original roster join"),
                "{field}"
            );
        }
        f.product = valid.clone();
        f.product.0.insert(
            "metadata.li2meta".into(),
            Metadata::new(
                &f.original,
                ContentId::of(b"different selected manifest"),
                policy.clone(),
                records.clone(),
            )
            .unwrap()
            .encode(formats::Limits::default())
            .unwrap(),
        );
        repair_outer(&mut f, &joined);
        assert_metadata_refusal(&f, &facts, &records);
        assert_eq!(
            metadata_join(
                &f.original,
                &facts,
                &records,
                &f.product.0["metadata.li2meta"]
            )
            .err()
            .as_deref(),
            Some("Selection")
        );
        // LI2META v1: 56-byte envelope, 176-byte fixed payload, 32-byte
        // original-chunk hashes, followed by exact 40-byte selected records.
        let first = 56 + 176 + f.original.len().div_ceil(65536) * 32;
        for mutation in ["order", "duplicate-id"] {
            f.product = valid.clone();
            let bytes = f.product.0.get_mut("metadata.li2meta").unwrap();
            if mutation == "order" {
                let a = bytes[first..first + 40].to_vec();
                let b = bytes[first + 40..first + 80].to_vec();
                bytes[first..first + 40].copy_from_slice(&b);
                bytes[first + 40..first + 80].copy_from_slice(&a);
            } else {
                bytes[first..first + 8].copy_from_slice(&2u64.to_le_bytes());
            }
            envelope(bytes);
            repair_outer(&mut f, &joined);
            assert_metadata_refusal(&f, &facts, &records);
            assert_eq!(
                metadata_join(
                    &f.original,
                    &facts,
                    &records,
                    &f.product.0["metadata.li2meta"]
                )
                .err()
                .as_deref(),
                Some("InvalidRecord"),
                "{mutation}"
            );
        }
        f.product = valid;
        assert!(accepts(&f));
    }
}

#[test]
fn f04_redirect_operand_refuses_after_outer_identity_repair() {
    let mut f = fixture("checksum", true);
    assert!(accepts(&f));
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
    let joined = ledger::join(
        &f.original,
        &facts,
        &records,
        &f.product.0["plan-ledger.tsv"],
        &f.product,
    )
    .unwrap();
    let text = String::from_utf8(f.product.0["plan-ledger.tsv"].clone()).unwrap();
    let mut rows: Vec<String> = text.lines().map(str::to_string).collect();
    let at = rows
        .iter()
        .rposition(|row| row.starts_with("semantic-write\t"))
        .unwrap();
    let mut cells: Vec<String> = rows[at].split('\t').map(str::to_string).collect();
    let mut bytes = unhex(&cells[4]).unwrap();
    assert_eq!(bytes[0], 0xe9);
    bytes[1] ^= 1;
    cells[4] = hex(&bytes);
    rows[at] = cells.join("\t");
    f.product.0.insert(
        "plan-ledger.tsv".into(),
        (rows.join("\n") + "\n").into_bytes(),
    );
    repair_outer(&mut f, &joined);
    assert_ledger_refusal(&f, &facts, &records, Some("source redirect/image binding"));
}
