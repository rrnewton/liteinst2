//! Exact extra admission for controlled B1 SIGILL routing; legacy stays closed.
use super::*;
use router_contract::{Route, RouterMode};

pub(super) fn declarations(mode: RouterMode, rows: &[Vec<&str>]) -> Vec<(u64, u64, u64, u64)> {
    let mut out = Vec::new();
    for r in rows.iter().filter(|r| r[0] == "entry-router-required") {
        assert!(mode.enabled());
        assert_eq!(r.len(), 5);
        out.push((n(r[1]), n(r[2]), n(r[3]), n(r[4])));
    }
    assert!(out.len() <= 87);
    let unique: BTreeSet<_> = out.iter().map(|r| r.2).collect();
    assert_eq!(unique.len(), out.len());
    out
}

pub(super) fn step(
    rows: &[Vec<&str>],
    step: &[&str],
    routes: &[(u64, u64, u64, u64)],
    original: &Elf64<'_>,
    original_bytes: &[u8],
    overlay: &[u8],
) {
    let declared: Vec<_> = routes
        .iter()
        .filter(|r| (r.0, r.1) == (n(step[1]), n(step[2])))
        .collect();
    if declared.is_empty() {
        return;
    }
    assert_eq!(step[3], "relocation");
    let (physical, lo, hi) = (n(step[5]), n(step[6]), n(step[7]));
    assert_eq!(physical, lo);
    let source = seed::ORIGINAL_RANGES
        .iter()
        .find(|r| r.pc <= lo && hi <= r.pc + r.bytes.len() as u64)
        .unwrap();
    let expected: BTreeSet<_> = seed::HEADS
        .iter()
        .filter(|h| lo < h.pc && h.pc < hi)
        .map(|h| h.pc)
        .collect();
    assert_eq!(
        declared.iter().map(|r| r.2).collect::<BTreeSet<_>>(),
        expected
    );
    let kept: Vec<_> = rows
        .iter()
        .filter(|r| r[0] == "entry-preserved" && r[1] == step[1] && r[2] == step[2])
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(n(kept[0][3]), physical);
    // Full current owner read remains mandatory, and the displaced original
    // interval must still be original before this step is applied.
    let reads: Vec<_> = rows
        .iter()
        .filter(|r| r[0] == "step-read" && r[1] == step[1] && r[2] == step[2])
        .collect();
    assert_eq!(reads.len(), 1);
    assert_eq!(n(reads[0][3]), source.pc);
    let at = file_at(original, source.pc, source.bytes.len());
    assert_eq!(unhex(reads[0][4]), overlay[at..at + source.bytes.len()]);
    let at = file_at(original, lo, usize::try_from(hi - lo).unwrap());
    assert_eq!(
        &overlay[at..at + (hi - lo) as usize],
        &original_bytes[at..at + (hi - lo) as usize]
    );
    let images: BTreeSet<_> = rows
        .iter()
        .filter(|r| r[0] == "image" && r[2] == step[1])
        .map(|r| n(r[1]))
        .collect();
    let entry: Vec<_> = rows
        .iter()
        .filter(|r| r[0] == "route" && images.contains(&n(r[1])) && n(r[2]) == physical)
        .collect();
    assert_eq!(entry.len(), 1);
    let target = n(entry[0][3]);
    let mut patch = original_bytes[at..at + (hi - lo) as usize].to_vec();
    assert!(patch.len() >= 5);
    patch[0] = 0xe9;
    patch[1..5].copy_from_slice(
        &i32::try_from(i128::from(target) - i128::from(physical + 5))
            .unwrap()
            .to_le_bytes(),
    );
    for &pc in expected.iter().rev() {
        if pc >= physical + 5 {
            let offset = (pc - physical) as usize;
            patch[offset] = 0x62;
            let source_at = file_at(original, source.pc, source.bytes.len());
            let current_source = &overlay[source_at..source_at + source.bytes.len()];
            let following = |delta: usize| {
                patch.get(offset + delta).copied().or_else(|| {
                    current_source
                        .get((pc - source.pc) as usize + delta)
                        .copied()
                })
            };
            if pc % 4096 > 4096 - 15
                || source.pc + source.bytes.len() as u64 - pc < 15
                || following(1).is_none()
                || !following(2).is_some_and(|p1| p1 & 4 == 0)
            {
                patch[offset] = 0x60;
            }
        }
    }
    let writes: Vec<_> = rows
        .iter()
        .filter(|r| r[0] == "semantic-write" && r[1] == step[1] && r[2] == step[2])
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(n(writes[0][3]), physical);
    assert_eq!(
        unhex(writes[0][4]),
        patch,
        "complete original-derived B1 source edit"
    );
}

pub(super) fn authenticate(
    rows: &[Vec<&str>],
    routes: &[(u64, u64, u64, u64)],
    heads: &BTreeMap<u64, Head>,
    elf: &Elf64<'_>,
) -> Vec<Route> {
    let mut out = Vec::new();
    for &(site, step, pc, target) in routes {
        let head = heads
            .get(&pc)
            .expect("router head has an authenticated original operation");
        assert_eq!(head.route, target);
        let source = seed::ORIGINAL_RANGES
            .iter()
            .find(|r| r.pc <= pc && pc < r.pc + r.bytes.len() as u64)
            .unwrap();
        let src = seed::HEADS.iter().find(|h| h.pc == pc).unwrap();
        assert!(!matches!(src.flow, seed::Flow::Call(_)));
        let images: Vec<_> = rows
            .iter()
            .filter(|r| {
                r[0] == "image"
                    && n(r[2]) == site
                    && n(r[3]) <= target
                    && target < n(r[3]) + n(r[4])
            })
            .collect();
        assert_eq!(images.len(), 1);
        let id = n(images[0][1]);
        assert_eq!(
            rows.iter()
                .filter(|r| r[0] == "route" && n(r[1]) == id && n(r[2]) == pc && n(r[3]) == target)
                .count(),
            1
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r[0] == "step" && n(r[1]) == site && n(r[2]) == step)
                .count(),
            1
        );
        let first = elf.executable_bytes(ElfVaddr(pc), 1).unwrap()[0];
        let fetch = elf
            .executable_bytes(ElfVaddr(pc), if first == 0x62 { 15 } else { 1 })
            .unwrap()
            .to_vec();
        out.push(Route {
            pc,
            target,
            source_start: source.pc,
            source_end: source.pc + source.bytes.len() as u64,
            fetch,
        });
    }
    out.sort_by_key(|r| r.pc);
    router_contract::check_routes(&out);
    out
}

pub(super) fn image_requires_router(
    rows: &[Vec<&str>],
    id: u64,
    routes: &[(u64, u64, u64, u64)],
) -> bool {
    // ledger::plans assigns every image of one ArtifactPlan the selected site's
    // ID. emission::record_router_requirement marks ALL those images when any
    // source step in that plan routes, including a callback-free T3 victim.
    let owners: Vec<_> = rows
        .iter()
        .filter(|r| r[0] == "image" && n(r[1]) == id)
        .collect();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].len(), 7);
    routes.iter().any(|r| r.0 == n(owners[0][2]))
}

// The exact whole requirement-list check is shared with the finite metadata
// control below. Hook and all non-router requirements remain mandatory.
pub(super) fn requirements(
    r: &[Vec<&str>],
    id: u64,
    hooks: usize,
    router: RouterMode,
    router_declarations: &[(u64, u64, u64, u64)],
) {
    let mut requirements: Vec<_> = r
        .iter()
        .filter(|x| x[0] == "unmet-requirement" && n(x[1]) == id)
        .map(|x| (n(x[2]), n(x[3])))
        .collect();
    requirements.sort();
    let mut expected: Vec<_> = [1, 2, 3, 4, 7, 8].map(|v| (v, 0)).to_vec();
    if hooks > 0 {
        expected.push((5, 2));
    }
    if image_requires_router(r, id, router_declarations) {
        assert!(router.enabled());
        expected.push((6, 0));
    }
    expected.sort();
    assert_eq!(requirements, expected);
}

pub(super) fn requirements_recording(
    r: &[Vec<&str>],
    id: u64,
    hooks: usize,
    router: RouterMode,
    router_declarations: &[(u64, u64, u64, u64)],
) {
    let mut requirements: Vec<_> = r
        .iter()
        .filter(|x| x[0] == "unmet-requirement" && n(x[1]) == id)
        .map(|x| (n(x[2]), n(x[3])))
        .collect();
    requirements.sort();
    let mut expected: Vec<_> = [1, 2, 3, 4, 7, 8].map(|v| (v, 0)).to_vec();
    if hooks > 0 {
        expected.push((5, 3));
    }
    if image_requires_router(r, id, router_declarations) {
        assert!(router.enabled());
        expected.push((6, 0));
    }
    expected.sort();
    assert_eq!(requirements, expected);
}

#[cfg(test)]
mod tests {
    use super::*;
    const PC: u64 = 0x401840;
    const DEST: u64 = 0x6401845;
    fn elf() -> Vec<u8> {
        let mut b = vec![0; 8192];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&2_u16.to_le_bytes());
        b[18..20].copy_from_slice(&62_u16.to_le_bytes());
        b[20..24].copy_from_slice(&1_u32.to_le_bytes());
        b[32..40].copy_from_slice(&64_u64.to_le_bytes());
        b[52..54].copy_from_slice(&64_u16.to_le_bytes());
        b[54..56].copy_from_slice(&56_u16.to_le_bytes());
        b[56..58].copy_from_slice(&1_u16.to_le_bytes());
        b[64..68].copy_from_slice(&1_u32.to_le_bytes());
        b[68..72].copy_from_slice(&5_u32.to_le_bytes());
        b[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
        b[96..104].copy_from_slice(&8192_u64.to_le_bytes());
        b[104..112].copy_from_slice(&8192_u64.to_le_bytes());
        b[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        for src in seed::ORIGINAL_RANGES {
            b[src.file_offset as usize..src.file_offset as usize + src.bytes.len()]
                .copy_from_slice(src.bytes);
        }
        b
    }
    fn ledger() -> Vec<Vec<String>> {
        let source = seed::ORIGINAL_RANGES.iter().find(|s| s.pc == PC).unwrap();
        format!("step\t1\t0\trelocation\t{PC}\t{PC}\t{PC}\t{}\nimage\t0\t1\t{DEST}\t64\tunused\timage-0000.bin\nroute\t0\t{PC}\t{DEST}\nroute\t0\t{}\t{}\nentry-preserved\t1\t0\t{PC}\nentry-router-required\t1\t0\t{}\t{}\nstep-read\t1\t0\t{PC}\t{}\nsemantic-write\t1\t0\t{PC}\te900000006\n",
            PC+5,PC+4,DEST+32,PC+4,DEST+32,hex(source.bytes)).lines()
            .map(|line|line.split('\t').map(str::to_owned).collect()).collect()
    }
    fn check(owned: &[Vec<String>], original: &[u8], current: &[u8]) {
        let r: Vec<Vec<_>> = owned
            .iter()
            .map(|r| r.iter().map(String::as_str).collect())
            .collect();
        let declarations = declarations(RouterMode::PrivateAltstack, &r);
        let original_elf = Elf64::parse(original, ParseLimits::default()).unwrap();
        step(&r, &r[0], &declarations, &original_elf, original, current);
        let mut candidate = original.to_vec();
        candidate[0x1840..0x1845].copy_from_slice(&unhex(&owned[7][4]));
        let candidate = Elf64::parse(&candidate, ParseLimits::default()).unwrap();
        let heads = BTreeMap::from([(
            PC + 4,
            Head {
                logical: PC + 4,
                route: DEST + 32,
                body: DEST + 32,
                bytes: vec![0xc3],
                target: 0,
                walk: vec![],
            },
        )]);
        let admitted = authenticate(&r, &declarations, &heads, &candidate);
        assert_eq!(
            admitted,
            vec![Route {
                pc: PC + 4,
                target: DEST + 32,
                source_start: PC,
                source_end: PC + 5,
                fetch: vec![6]
            }]
        );
        assert!(image_requires_router(&r, 0, &declarations));
    }

    #[test]
    fn plan_wide_two_image_requirements_and_mutations() {
        // Synthetic metadata contract: image 0 contains the authenticated B1
        // route; image 1 is its same-plan companion, with no routed head.
        // Image 2 is a different selected site's plan and must remain unmarked.
        // This is not a whole T3 product or a native execution fixture.
        let original = elf();
        let mut good = ledger();
        for (id, site, address) in [(1, 1, DEST + 0x100), (2, 2, DEST + 0x200)] {
            good.push(vec![
                "image".into(),
                id.to_string(),
                site.to_string(),
                address.to_string(),
                "64".into(),
                "unused".into(),
                format!("image-{id:04}.bin"),
            ]);
        }
        // Independent fixed expectations: both same-plan images require 6,
        // only the selected helper image requires hook 2, and site 2 has no 6.
        for (id, codes) in [
            (0, &[1, 2, 3, 4, 6, 7, 8][..]),
            (1, &[1, 2, 3, 4, 5, 6, 7, 8][..]),
            (2, &[1, 2, 3, 4, 7, 8][..]),
        ] {
            for code in codes {
                good.push(vec![
                    "unmet-requirement".into(),
                    id.to_string(),
                    code.to_string(),
                    if *code == 5 { "2".into() } else { "0".into() },
                ]);
            }
        }
        let checked = |owned: &[Vec<String>]| {
            check(owned, &original, &original);
            let r: Vec<Vec<_>> = owned
                .iter()
                .map(|r| r.iter().map(String::as_str).collect())
                .collect();
            let declared = declarations(RouterMode::PrivateAltstack, &r);
            for (id, hooks) in [(0, 0), (1, 1), (2, 0)] {
                requirements(&r, id, hooks, RouterMode::PrivateAltstack, &declared);
            }
        };
        checked(&good);
        for mutation in 0..10 {
            let mut bad = good.clone();
            match mutation {
                0 | 1 => bad.retain(|r| {
                    !(r[0] == "unmet-requirement" && r[1] == mutation.to_string() && r[2] == "6")
                }),
                2 => bad.push(vec![
                    "unmet-requirement".into(),
                    "2".into(),
                    "6".into(),
                    "0".into(),
                ]),
                3 => bad.push(vec![
                    "unmet-requirement".into(),
                    "1".into(),
                    "6".into(),
                    "0".into(),
                ]),
                4 => {
                    bad.iter_mut()
                        .find(|r| r[0] == "unmet-requirement" && r[1] == "1" && r[2] == "6")
                        .unwrap()[3] = "1".into()
                }
                5 => {
                    bad.iter_mut()
                        .find(|r| r[0] == "image" && r[1] == "1")
                        .unwrap()[2] = "2".into()
                }
                6 => {
                    bad.iter_mut()
                        .find(|r| r[0] == "entry-router-required")
                        .unwrap()[1] = "2".into()
                }
                7 => bad.retain(|r| !(r[0] == "unmet-requirement" && r[1] == "1" && r[2] == "3")),
                8 => bad.retain(|r| !(r[0] == "unmet-requirement" && r[1] == "1" && r[2] == "5")),
                9 => bad.push(
                    bad.iter()
                        .find(|r| r[0] == "image" && r[1] == "1")
                        .unwrap()
                        .clone(),
                ),
                _ => unreachable!(),
            }
            assert!(
                std::panic::catch_unwind(|| checked(&bad)).is_err(),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn whole_original_b1_route_and_current_read_are_authenticated() {
        let original = elf();
        let ledger = ledger();
        check(&ledger, &original, &original);
        for (row, field, value) in [
            (0, 5, (PC + 1).to_string()),
            (0, 7, (PC + 4).to_string()),
            (4, 3, (PC + 1).to_string()),
            (5, 3, (PC + 3).to_string()),
            (5, 4, (DEST + 33).to_string()),
            (6, 3, (PC + 1).to_string()),
            (7, 4, "e900000090".to_owned()),
        ] {
            let mut bad = ledger.clone();
            bad[row][field] = value;
            assert!(std::panic::catch_unwind(|| check(&bad, &original, &original)).is_err());
        }
        let mut changed = original.clone();
        changed[0x1840] ^= 1;
        assert!(std::panic::catch_unwind(|| check(&ledger, &original, &changed)).is_err());
    }
    #[test]
    fn legacy_and_duplicate_router_records_refuse() {
        let owned = ledger();
        let r: Vec<Vec<_>> = owned
            .iter()
            .map(|r| r.iter().map(String::as_str).collect())
            .collect();
        assert!(std::panic::catch_unwind(|| declarations(RouterMode::Absent, &r)).is_err());
        let mut duplicate = r.clone();
        duplicate.push(r[5].clone());
        assert!(
            std::panic::catch_unwind(|| declarations(RouterMode::PrivateAltstack, &duplicate))
                .is_err()
        );
    }
}
