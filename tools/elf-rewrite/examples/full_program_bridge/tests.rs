//! Pure fabricated bytes only; no file, decoder command, backend or native run.
use super::*;

const BASE: u64 = 0x400000;
const TABLE: usize = 0x3c00;
fn put(b: &mut [u8], at: usize, width: usize, value: u64) {
    b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn fixture(text: &[u8], sizes: &[usize]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(sizes.iter().sum::<usize>(), text.len());
    assert!(text.len() < 0x1f00);
    let mut b = vec![0; 16384];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, width, n) in [
        (16, 2, 3),
        (18, 2, 62),
        (20, 4, 1),
        (24, 8, BASE + 0x1100),
        (32, 8, 64),
        (40, 8, TABLE as u64),
        (52, 2, 64),
        (54, 2, 56),
        (56, 2, 1),
        (58, 2, 64),
        (60, 2, 5),
    ] {
        put(&mut b, at, width, n);
    }
    for (at, width, n) in [
        (64, 4, 1),
        (68, 4, 5),
        (80, 8, BASE),
        (88, 8, BASE),
        (96, 8, 16384),
        (104, 8, 16384),
        (112, 8, 4096),
    ] {
        put(&mut b, at, width, n);
    }
    let sections: Vec<(usize, Vec<u8>, Vec<usize>)> = vec![
        (0x1000, vec![0xc3], vec![1]),
        (0x1010, vec![0xff, 0xe0], vec![2]),
        (0x1100, text.to_vec(), sizes.to_vec()),
        (0x3000, vec![0xc3], vec![1]),
    ];
    let mut csv = String::from("address,offset,size\n");
    for (i, (offset, code, widths)) in sections.iter().enumerate() {
        let at = TABLE + (i + 1) * 64;
        for (field, width, n) in [
            (4, 4, 1),
            (8, 8, 6),
            (16, 8, BASE + *offset as u64),
            (24, 8, *offset as u64),
            (32, 8, code.len() as u64),
            (48, 8, 1),
        ] {
            put(&mut b, at + field, width, n);
        }
        b[*offset..*offset + code.len()].copy_from_slice(code);
        let mut cursor = *offset;
        for width in widths {
            writeln!(csv, "0x{:x},+{cursor},{width}", BASE + cursor as u64).unwrap();
            cursor += width;
        }
    }
    (b, csv.into_bytes())
}
fn ordinary() -> (Vec<u8>, Vec<u8>) {
    fixture(
        &[0x75, 0, 0xeb, 0, 0xe8, 0, 0, 0, 0, 0xe2, 0, 0xc3],
        &[2, 2, 5, 2, 1],
    )
}
fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

#[test]
fn full_program_sections_and_iced_roster_feed_exact_legacy_order() {
    let (original, csv) = ordinary();
    let m = bridge(&original, &csv, "/fixed/original").unwrap();
    assert_eq!((m.heads, m.sites), (8, 3));
    let ledger = text(&m.ledger);
    assert_eq!(ledger.matches("region ").count(), 4);
    assert_eq!(ledger.matches("head ").count(), 8);
    assert!(ledger.contains("head 4206592 c3\n")); // .fini, never omitted from ledger.
    let inventory = text(&m.inventory);
    assert!(inventory.contains("complete_jump_count\t3\n"));
    let rows: Vec<_> = inventory.lines().skip(7).collect();
    assert_eq!(
        rows.iter()
            .map(|r| r.split('\t').take(4).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        vec![
            vec!["1", "4198416", "2", "4112"],
            vec!["2", "4198656", "2", "4352"],
            vec!["3", "4198658", "2", "4354"]
        ]
    );
    let heads = csv_heads(&csv).unwrap();
    assert_eq!(
        events(&heads, &[1, 2, 3]).unwrap(),
        vec![
            Event::Instruction(3),
            Event::Instruction(2),
            Event::Instruction(4),
            Event::Instruction(5),
            Event::Instruction(6),
            Event::Patch(3),
            Event::Patch(2),
            Event::Instruction(1),
            Event::Instruction(0),
            Event::Patch(1)
        ]
    );
    let rpc = m.rpc.unwrap();
    let lines: Vec<_> = text(&rpc).lines().collect();
    assert_eq!(lines.len(), 13);
    assert_eq!(
        lines[0],
        r#"{"jsonrpc":"2.0","method":"binary","params":{"filename":"/fixed/original","mode":"exe"},"id":0}"#
    );
    assert_eq!(
        lines[1],
        r#"{"jsonrpc":"2.0","method":"trampoline","params":{"name":"passthru","template":["$instruction","$continue"]},"id":1}"#
    );
    assert_eq!(
        lines[12],
        r#"{"jsonrpc":"2.0","method":"emit","params":{"filename":"a.out","format":"binary","mapping_size":4096},"id":12}"#
    );
    let patches: Vec<_> = lines
        .iter()
        .copied()
        .filter(|l| l.contains("\"method\":\"patch\""))
        .collect();
    assert_eq!(
        patches,
        vec![
            r#"{"jsonrpc":"2.0","method":"patch","params":{"trampoline":"passthru","offset":4354},"id":7}"#,
            r#"{"jsonrpc":"2.0","method":"patch","params":{"trampoline":"passthru","offset":4352},"id":8}"#,
            r#"{"jsonrpc":"2.0","method":"patch","params":{"trampoline":"passthru","offset":4112},"id":11}"#
        ]
    );
    assert!(!text(&rpc).contains("4206592")); // Local context is deliberately not full code.
    assert!(text(&m.regions).contains("gap-caller-noncode"));
}

#[test]
fn full_program_csv_omissions_duplicates_overlap_order_and_grammar_refuse() {
    let (original, csv) = ordinary();
    let s = text(&csv);
    for bad in [
        s.replace("address,offset,size", "address,offset,size,mnemonic"),
        s.replace("0x401000,+4096,1\n", ""),
        s.replace("0x403000,+12288,1\n", ""),
        s.replace("0x401010,+4112,2\n", ""),
        s.replace("0x401010,+4112,2\n", "0x401010,+4112,2\n0x401010,+4112,2\n"),
        s.replace("0x401010,+4112,2", "0x401010,+4113,2"),
        s.replace("0x401010,+4112,2", "0x401010,+4112,0"),
        s.replace("0x401010,+4112,2", "0x401010,+4112,16"),
        s.replace("0x401010,+4112,2", "0x401010,4112,2"),
        s.replace("0x401010,+4112,2", "0x0401010,+4112,2"),
        s.replace("0x401010,+4112,2", "0x401010,+04112,2"),
        s.replace("0x401010,+4112,2", "0x401010,+4112,2,jmp"),
        s.replace('\n', "\r\n"),
        s.trim_end().to_owned(),
        s.to_owned() + "0x403001,+12289,1\n",
    ] {
        assert!(
            bridge(&original, bad.as_bytes(), "/fixed/original").is_err(),
            "accepted {bad:?}"
        );
    }
    let mut lines: Vec<_> = s.lines().collect();
    lines.swap(2, 3);
    assert!(
        bridge(
            &original,
            (lines.join("\n") + "\n").as_bytes(),
            "/fixed/original"
        )
        .is_err()
    );
}

#[test]
fn full_program_elf_section_metadata_and_all_permission_aliases_refuse() {
    let (original, csv) = ordinary();
    for (at, width, value) in [
        (40, 8, u64::MAX),
        (58, 2, 63),
        (60, 2, 0),
        (60, 2, 4097),
        (TABLE + 64 + 4, 4, 8),     // SHT_NOBITS cannot invent file code.
        (TABLE + 64 + 8, 8, 7),     // writeable executable section.
        (TABLE + 64 + 8, 8, 4),     // not allocated.
        (TABLE + 64 + 8, 8, 0x806), // compressed executable section.
        (TABLE + 128 + 16, 8, BASE + 0x1000), // overlap.
        (TABLE + 128 + 24, 8, 0x1000), // wrong inverse offset.
        (TABLE + 64 + 32, 8, u64::MAX),
        (24, 8, BASE + 0x2000),
        (68, 4, 7), // writable LOAD cannot be a source-code owner.
    ] {
        let mut bad = original.clone();
        put(&mut bad, at, width, value);
        assert!(
            bridge(&bad, &csv, "/fixed/original").is_err(),
            "accepted mutation at {at}"
        );
    }
    let mut alias = original.clone();
    let ph = alias[64..120].to_vec();
    alias[120..176].copy_from_slice(&ph);
    put(&mut alias, 56, 2, 2);
    put(&mut alias, 124, 4, 4);
    assert!(bridge(&alias, &csv, "/fixed/original").is_err());
}

#[test]
fn full_program_independent_importer_refuses_false_heads_and_unlisted_targets() {
    let (mut original, csv) = ordinary();
    let bad = text(&csv).replace("0x401100,+4352,2\n", "0x401100,+4352,1\n0x401101,+4353,1\n");
    assert!(
        bridge(&original, bad.as_bytes(), "/fixed/original")
            .err()
            .unwrap()
            .starts_with("independent importer:")
    );
    original[0x1101] = 0x7e; // JNE into an undeclared RX gap, not a known head.
    assert!(
        bridge(&original, &csv, "/fixed/original")
            .err()
            .unwrap()
            .contains("direct target contradicts complete ledger")
    );
    let (original, csv) = fixture(&[0x0f], &[1]);
    assert!(
        bridge(&original, &csv, "/fixed/original")
            .err()
            .unwrap()
            .starts_with("independent importer:")
    );
}

#[test]
fn full_program_context_boundary_and_emitted_bits_match_legacy_window() {
    let heads: Vec<_> = [1, 2, 145, 146, 289, 290, 291]
        .into_iter()
        .map(|pc| Head {
            pc,
            offset: pc,
            length: 1,
        })
        .collect();
    // Exact ±144 starts survive; ±145 do not. Earlier patch context stays emitted.
    assert_eq!(
        events(&heads, &[2, 3]).unwrap(),
        vec![
            Event::Instruction(3),
            Event::Instruction(2),
            Event::Instruction(1),
            Event::Instruction(4),
            Event::Instruction(5),
            Event::Patch(3),
            Event::Instruction(0),
            Event::Patch(2)
        ]
    );
    assert!(events(&heads, &[3, 2]).is_err());
    assert!(events(&heads, &[2, 2]).is_err());
}

#[test]
fn full_program_caps_preserve_complete_site_denominator_and_refuse_without_subset() {
    let mut code = Vec::new();
    for _ in 0..1024 {
        code.extend_from_slice(&[0x75, 0]);
    }
    code.push(0xc3);
    let mut widths = vec![2; 1024];
    widths.push(1);
    let (original, csv) = fixture(&code, &widths);
    let m = bridge(&original, &csv, "/fixed/original").unwrap();
    assert_eq!(m.sites, 1025); // Includes the indirect PLT jump.
    assert!(text(&m.inventory).contains("complete_jump_count\t1025\n"));
    assert_eq!(m.rpc.unwrap_err(), "site bound: required 1025, limit 1024");
    let heads: Vec<_> = (0..3070)
        .map(|pc| Head {
            pc,
            offset: pc,
            length: 1,
        })
        .collect();
    let selected: Vec<_> = (0..1023).map(|i| 3 * i).collect();
    assert_eq!(events(&heads, &selected).unwrap().len() + 3, 4096);
    let mut more = heads;
    more.push(Head {
        pc: 3070,
        offset: 3070,
        length: 1,
    });
    assert_eq!(
        events(&more, &selected).unwrap_err(),
        "RPC message bound: required 4097, limit 4096"
    );
    assert!(csv_heads(&vec![b'x'; TEXT_LIMIT + 1]).is_err());
    assert!(regions(&vec![0; FILE_LIMIT + 1]).is_err());
    let (mut original, csv) = fixture(&[0xc3], &[1]);
    original[0x1010..0x1012].copy_from_slice(&[0x66, 0x90]);
    let m = bridge(&original, &csv, "/fixed/original").unwrap();
    assert_eq!(m.sites, 0);
    assert!(m.rpc.unwrap_err().contains("required 0"));
}

#[test]
fn full_program_rpc_numbers_paths_and_byte_caps_are_explicit() {
    assert_eq!(integer(i32::MAX as u64), "2147483647");
    assert_eq!(integer(i32::MAX as u64 + 1), "\"0x80000000\"");
    assert_eq!(quoted_path("/a/\"b\\c").unwrap(), "\"/a/\\\"b\\\\c\"");
    for p in ["relative", "/a\nb", "/a\0b", "/é"] {
        assert!(quoted_path(p).is_err());
    }
    assert!(quoted_path(&format!("/{}", "a".repeat(4096))).is_err());
    let mut out = "x".repeat(TEXT_LIMIT - 1);
    append(&mut out, "x", TEXT_LIMIT, "ledger").unwrap();
    assert!(append(&mut out, "x", TEXT_LIMIT, "ledger").is_err());
    assert_eq!(out.len(), TEXT_LIMIT);
}

#[test]
fn full_program_whole_profile_keeps_2053_sites_and_old_default_refusal() {
    let mut code = [0x75, 0].repeat(2052);
    code.push(0xc3);
    let mut widths = vec![2; 2052];
    widths.push(1);
    let (original, csv) = fixture(&code, &widths);
    let legacy = bridge(&original, &csv, "/fixed/original").unwrap();
    let whole = bridge_profile(&original, &csv, "/fixed/original", Profile::Whole4096).unwrap();
    assert_eq!((whole.heads, whole.sites), (2056, 2053));
    assert_eq!(legacy.ledger, whole.ledger);
    assert_eq!(legacy.regions, whole.regions);
    assert_eq!(
        legacy.rpc.unwrap_err(),
        "site bound: required 2053, limit 1024"
    );
    assert_eq!(
        whole.inventory,
        text(&legacy.inventory)
            .replacen(disassembly::PROFILE, disassembly::whole::PROFILE, 1)
            .into_bytes()
    );
    let transport = whole.rpc.unwrap();
    let lines: Vec<_> = text(&transport).lines().collect();
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("\"method\":\"patch\""))
            .count(),
        2053
    );
    let heads = csv_heads(&csv).unwrap();
    let imported =
        disassembly::import(&original, &whole.ledger, ContentId::of(&whole.ledger)).unwrap();
    let selected: Vec<_> = imported
        .jumps()
        .iter()
        .map(|s| heads.binary_search_by_key(&s.pc, |h| h.pc).unwrap())
        .collect();
    let events = events_whole(&heads, &selected).unwrap();
    assert_eq!(
        events
            .iter()
            .filter_map(|e| match e {
                Event::Patch(i) => Some(*i),
                _ => None,
            })
            .collect::<Vec<_>>(),
        selected.iter().rev().copied().collect::<Vec<_>>()
    );
    assert_eq!(lines.len(), events.len() + 3);
    let (small, csv) = ordinary();
    assert_eq!(
        bridge(&small, &csv, "/fixed/original").unwrap().rpc,
        bridge_profile(&small, &csv, "/fixed/original", Profile::Whole4096)
            .unwrap()
            .rpc
    );
}

#[test]
fn full_program_whole_transport_preserves_complete_roster_and_all_caps() {
    // Synthetic transport census with the actual program's population sizes.
    // This is not a claim that these fabricated locations are the actual ELF.
    let heads: Vec<_> = (0..12941)
        .chain(20000..20202)
        .map(|pc| Head {
            pc,
            offset: pc,
            length: 1,
        })
        .collect();
    let selected: Vec<_> = (0..2053).map(|i| i * 12940 / 2052).collect();
    assert_eq!(heads.len(), 13143);
    let result = events_whole(&heads, &selected).unwrap();
    assert_eq!(result.len() + 3, 14997);
    let mut observed: Vec<_> = result
        .iter()
        .filter_map(|e| match e {
            Event::Instruction(i) => Some(*i),
            _ => None,
        })
        .collect();
    observed.sort_unstable();
    assert_eq!(observed, (0..12941).collect::<Vec<_>>());
    assert_eq!(
        result
            .iter()
            .filter_map(|e| match e {
                Event::Patch(i) => Some(*i),
                _ => None,
            })
            .collect::<Vec<_>>(),
        selected.iter().rev().copied().collect::<Vec<_>>()
    );
    assert_eq!(
        rpc_profile(&heads, &selected, "/fixed/original", Profile::Whole4096)
            .unwrap()
            .split(|b| *b == b'\n')
            .count()
            - 1,
        14997
    );
    assert_eq!(
        events(&heads, &selected).unwrap_err(),
        "site bound: required 2053, limit 1024"
    );
    let all: Vec<_> = (0..disassembly::whole::HEAD_LIMIT + 1)
        .map(|pc| Head {
            pc: pc as u64,
            offset: pc as u64,
            length: 1,
        })
        .collect();
    assert!(events_whole(&all[..disassembly::whole::HEAD_LIMIT], &[0]).is_ok());
    assert_eq!(
        events_whole(&all, &[0]).unwrap_err(),
        "head bound: required 16385, limit 16384"
    );
    let cap: Vec<_> = (0..disassembly::whole::SITE_LIMIT).collect();
    assert!(events_whole(&all[..disassembly::whole::HEAD_LIMIT], &cap).is_ok());
    let mut excess = cap;
    excess.push(disassembly::whole::SITE_LIMIT);
    assert_eq!(
        events_whole(&all[..disassembly::whole::HEAD_LIMIT], &excess).unwrap_err(),
        "site bound: required 4097, limit 4096"
    );
    assert!(events_whole(&heads, &[1, 0]).is_err());
    assert!(events_whole(&heads, &[1, 1]).is_err());
    assert!(events_whole(&heads, &[heads.len()]).is_err());
    assert!(events_whole(&heads, &[]).is_err());
    assert!(events_bounded(&heads, &selected, 4096, 14997).is_ok());
    assert_eq!(
        events_bounded(&heads, &selected, 4096, 14996).unwrap_err(),
        "RPC message bound: required 14997, limit 14996"
    );
    let mut out = "x".repeat(FILE_LIMIT - 1);
    append(&mut out, "x", FILE_LIMIT, "RPC").unwrap();
    assert!(append(&mut out, "x", FILE_LIMIT, "RPC").is_err());
    assert_eq!(out.len(), FILE_LIMIT);
}

#[test]
fn full_program_whole_profile_requires_explicit_cli_and_complete_import() {
    let old: Vec<String> = [
        "bridge",
        "--trusted-complete-code",
        "original",
        "dump.csv",
        "pin",
        "output",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(arguments(&old).unwrap(), (old.as_slice(), Profile::Legacy));
    let mut args = old.clone();
    args.insert(1, "--whole-program-4096".into());
    assert_eq!(arguments(&args).unwrap(), (&args[1..], Profile::Whole4096));
    let mut bad = args.clone();
    bad[2] = "--whole-program-4096".into();
    assert!(arguments(&bad).is_err());
    assert!(arguments(&args[..6]).is_err());
    let (original, csv) = ordinary();
    let omitted = text(&csv).replace("0x403000,+12288,1\n", "");
    assert!(
        bridge_profile(
            &original,
            omitted.as_bytes(),
            "/fixed/original",
            Profile::Whole4096
        )
        .is_err()
    );
    let false_head =
        text(&csv).replace("0x401100,+4352,2\n", "0x401100,+4352,1\n0x401101,+4353,1\n");
    assert!(
        bridge_profile(
            &original,
            false_head.as_bytes(),
            "/fixed/original",
            Profile::Whole4096
        )
        .is_err()
    );
    assert!(
        bridge_profile(&original, &csv, "relative", Profile::Whole4096)
            .unwrap()
            .rpc
            .is_err()
    );
}

#[path = "input_tests.rs"]
mod input_tests;
