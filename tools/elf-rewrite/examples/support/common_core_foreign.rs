//! Additional admission for explicit owned-foreign-neighbors-v1 products.
//! Uses only authenticated original declarations and serialized byte witnesses;
//! no planner call, Debug-geometry parsing, or inferred source owner.
use super::*;
use liteinst_rewrite::model::SelectedSite;

pub(super) struct ForeignPair {
    id: u64,
    selected: u64,
    victim: u64,
    selected_image: u64,
    victim_image: u64,
}

fn head(pc: u64) -> &'static seed::Head {
    seed::HEADS.iter().find(|h| h.pc == pc).unwrap()
}
fn source(pc: u64) -> &'static seed::SourceRange<'static> {
    let h = head(pc);
    seed::ORIGINAL_RANGES
        .iter()
        .find(|r| r.function == h.function)
        .unwrap()
}
fn owner(sites: &[SelectedSite], pc: u64) -> &SelectedSite {
    let src = source(pc);
    let owners: Vec<_> = sites.iter().filter(|s| s.function.contains(pc)).collect();
    assert!(
        !owners.is_empty(),
        "foreign function must be separately declared"
    );
    let first = owners[0];
    for s in owners {
        assert_eq!(
            (s.function.start(), s.function.end()),
            (src.pc, src.pc + src.bytes.len() as u64)
        );
        assert_eq!(s.snapshot, s.function);
        assert_eq!(s.heads, first.heads);
        assert_eq!(s.completeness, EntryCompleteness::Complete);
        assert_eq!(s.resumes, ResumeObligation::NoneExist);
        assert_eq!(s.provenance, first.provenance);
        assert_eq!((s.block.start(), s.block.end()), original_block(head(s.pc)));
        assert_eq!(
            s.heads
                .iter()
                .map(|h| (h.address, h.requires_endbr))
                .collect::<Vec<_>>(),
            seed::HEADS
                .iter()
                .filter(|h| h.function == src.function)
                .map(|h| (h.pc, false))
                .collect::<Vec<_>>()
        );
    }
    first
}
fn member_rows<'a>(rows: &'a [Vec<&'a str>], step: &[&str], tag: &str) -> Vec<&'a Vec<&'a str>> {
    rows.iter()
        .filter(|r| r[0] == tag && r[1] == step[1] && r[2] == step[2])
        .collect()
}
fn member_row<'a>(rows: &'a [Vec<&'a str>], step: &[&str], tag: &str) -> &'a Vec<&'a str> {
    let found = member_rows(rows, step, tag);
    assert_eq!(found.len(), 1, "one {tag} per foreign member");
    found[0]
}
fn current(overlay: &[u8], pc: u64, len: usize) -> &[u8] {
    let src = source(pc);
    let offset = usize::try_from(pc - src.pc).unwrap();
    assert!(offset.checked_add(len).unwrap() <= src.bytes.len());
    let at = usize::try_from(src.file_offset).unwrap() + offset;
    &overlay[at..at + len]
}
fn transfer(bytes: &[u8], pc: u64, opcode: u8, target: u64) {
    assert_eq!(bytes.len(), if opcode == 0xeb { 2 } else { 5 });
    assert_eq!(bytes[0], opcode);
    let decoded = decoded(bytes, pc);
    assert_eq!(decoded.len(), bytes.len());
    assert_eq!(decoded.flow_control(), FlowControl::UnconditionalBranch);
    assert_eq!(decoded.near_branch_target(), target);
}

/// Every new-profile source step retains its complete *current* owning-function
/// read. The unchanged outer verifier also checks all reads against ELF offsets.
/// Local T2 overlays are not treated as immutable displaced instructions here.
pub(super) fn check_current_read(
    sites: &[SelectedSite],
    rows: &[Vec<&str>],
    step: &[&str],
    overlay: &[u8],
) {
    let pc = n(step[6]);
    let own = owner(sites, pc);
    assert!(own.function.contains(n(step[4])) && own.function.contains(n(step[5])));
    assert!(n(step[7]) <= own.function.end());
    let read = member_row(rows, step, "step-read");
    assert_eq!(n(read[3]), own.snapshot.start());
    assert_eq!(
        unhex(read[4]),
        current(overlay, own.snapshot.start(), own.snapshot.len() as usize)
    );
}

/// Identify explicit foreign pairs from their two source steps. Profile
/// selection itself is exclusively the caller flag + whole indexed marker.
pub(super) fn pairs(
    sites: &[SelectedSite],
    rows: &[Vec<&str>],
    report: &[Vec<&str>],
) -> Vec<ForeignPair> {
    let mut out = Vec::new();
    for site in sites {
        let steps: Vec<_> = rows
            .iter()
            .filter(|r| r[0] == "step" && n(r[1]) == site.id)
            .collect();
        let reported: Vec<_> = report
            .iter()
            .skip(6)
            .filter(|r| n(r[0]) == site.id)
            .collect();
        assert_eq!(reported.len(), 1);
        if reported[0][4] == "T3" {
            assert_eq!(steps.len(), 2);
        }
        if steps
            .iter()
            .all(|r| site.function.contains(n(r[6])) && n(r[7]) <= site.function.end())
        {
            continue;
        }
        assert_eq!(
            reported[0][4], "T3",
            "foreign source is an explicit T3 member"
        );
        assert_eq!(steps.len(), 2);
        assert!(
            n(steps[0][5]) > n(steps[1][5]),
            "source members retain descending physical order"
        );
        let selected: Vec<_> = steps.iter().filter(|r| n(r[6]) == site.pc).collect();
        assert_eq!(selected.len(), 1);
        let selected = *selected[0];
        let victim = *steps.iter().find(|r| n(r[6]) != site.pc).unwrap();
        let v = n(victim[6]);
        let victim_owner = owner(sites, v);
        assert_ne!(victim_owner.function, site.function);
        assert!(disjoint(
            (site.function.start(), site.function.end()),
            (victim_owner.function.start(), victim_owner.function.end())
        ));
        assert!(
            !sites.iter().any(|s| s.pc == v),
            "auxiliary entry cannot acquire a selected callback"
        );
        let mut image_ids = Vec::new();
        for member in [selected, victim] {
            let pc = n(member[6]);
            let h = head(pc);
            let own = owner(sites, pc);
            assert_eq!(member[3], "relocation");
            assert_eq!(
                (n(member[4]), n(member[5]), n(member[7])),
                (pc, pc, pc + u64::from(h.length))
            );
            let block = original_block(h);
            assert!(block.0 <= pc && pc + u64::from(h.length) <= block.1);
            assert!(!matches!(h.flow, seed::Flow::Call(_)));
            // Complete heads and original near-targets cannot enter either
            // newly overwritten instruction interior, including cross-owner edges.
            assert!(
                !own.heads
                    .iter()
                    .any(|e| pc < e.address && e.address < n(member[7]))
            );
            for original in seed::HEADS {
                let target = match original.flow {
                    seed::Flow::Jb(t)
                    | seed::Flow::Jae(t)
                    | seed::Flow::Jbe(t)
                    | seed::Flow::Jne(t)
                    | seed::Flow::Jump(t)
                    | seed::Flow::Call(t) => Some(t),
                    _ => None,
                };
                assert!(!target.is_some_and(|t| pc < t && t < n(member[7])));
            }
            assert_eq!(n(member_row(rows, member, "entry-preserved")[3]), pc);
            assert!(member_rows(rows, member, "live-store-span").is_empty());
            let write = member_row(rows, member, "semantic-write");
            assert_eq!(n(write[3]), pc);
            let allocation = member_row(rows, member, "allocation");
            let (low, high) = (n(allocation[3]), n(allocation[4]));
            let permit = if pc == site.pc {
                &site.selected_allocation
            } else {
                &site.victim_allocation
            };
            assert!(
                permit
                    .ranges
                    .iter()
                    .any(|p| p.start() <= low && low < high && high <= p.end())
            );
            let images: Vec<_> = rows
                .iter()
                .filter(|r| {
                    r[0] == "image"
                        && n(r[2]) == site.id
                        && low <= n(r[3])
                        && n(r[3]).checked_add(n(r[4])).unwrap() <= high
                })
                .collect();
            assert_eq!(images.len(), 1);
            let image = images[0];
            let routes: Vec<_> = rows
                .iter()
                .filter(|r| r[0] == "route" && r[1] == image[1])
                .collect();
            assert_eq!(routes.len(), 1);
            assert_eq!((n(routes[0][2]), n(routes[0][3])), (pc, n(image[3])));
            let src = source(pc);
            assert!(rows.iter().any(|r| r[0] == "original-file-dependency"
                && n(r[1]) <= src.file_offset
                && src.file_offset + src.bytes.len() as u64 <= n(r[2])));
            image_ids.push(n(image[1]));
        }
        assert_ne!(image_ids[0], image_ids[1]);
        assert_eq!(
            rows.iter()
                .filter(|r| r[0] == "image" && n(r[2]) == site.id)
                .count(),
            2
        );
        assert!((2..=4).contains(&head(site.pc).length));
        assert!((10..=15).contains(&head(v).length));
        assert_eq!(head(v).flow, seed::Flow::Next);
        let selected_address = n(rows
            .iter()
            .find(|r| r[0] == "image" && n(r[1]) == image_ids[0])
            .unwrap()[3]);
        let victim_address = n(rows
            .iter()
            .find(|r| r[0] == "image" && n(r[1]) == image_ids[1])
            .unwrap()[3]);
        let selected_patch = unhex(member_row(rows, selected, "semantic-write")[4]);
        transfer(&selected_patch, site.pc, 0xeb, v.checked_add(5).unwrap());
        let victim_patch = unhex(member_row(rows, victim, "semantic-write")[4]);
        assert_eq!(victim_patch.len(), 10);
        transfer(&victim_patch[..5], v, 0xe9, victim_address);
        transfer(&victim_patch[5..], v + 5, 0xe9, selected_address);
        out.push(ForeignPair {
            id: site.id,
            selected: site.pc,
            victim: v,
            selected_image: image_ids[0],
            victim_image: image_ids[1],
        });
    }
    out
}

impl ForeignPair {
    /// Before the first of two disjoint source writes, both displaced original
    /// instructions must remain whole and both full reads must be current.
    pub(super) fn before_step(
        &self,
        sites: &[SelectedSite],
        rows: &[Vec<&str>],
        step: &[&str],
        overlay: &[u8],
    ) {
        if n(step[1]) != self.id || n(step[2]) != 0 {
            return;
        }
        for member in rows.iter().filter(|r| r[0] == "step" && n(r[1]) == self.id) {
            check_current_read(sites, rows, member, overlay);
            let pc = n(member[6]);
            let src = source(pc);
            let offset = (pc - src.pc) as usize;
            let len = usize::from(head(pc).length);
            assert_eq!(
                current(overlay, pc, len),
                &src.bytes[offset..offset + len],
                "whole original displaced interval"
            );
        }
    }
    /// The ordinary auxiliary route is never the selected helper or relay.
    /// The outer image reader still checks every byte, field and requirement.
    pub(super) fn images(&self, heads: &BTreeMap<u64, Head>, images: &[Image]) {
        let selected = &heads[&self.selected];
        let victim = &heads[&self.victim];
        let si = &images[self.selected_image as usize];
        let vi = &images[self.victim_image as usize];
        assert_eq!(selected.route, si.address);
        assert_eq!(
            selected
                .walk
                .iter()
                .filter(|(_, next, _)| *next == HOOK)
                .count(),
            1
        );
        assert_eq!((victim.route, victim.body), (vi.address, vi.address));
        assert!(victim.walk.is_empty());
        assert_eq!(victim.target, 0);
        let src = source(self.victim);
        let offset = (self.victim - src.pc) as usize;
        let len = usize::from(head(self.victim).length);
        assert_eq!(victim.bytes, src.bytes[offset..offset + len]);
        assert_eq!(vi.bytes.len(), len + 5);
        assert_eq!(vi.bytes[..len], victim.bytes);
        transfer(
            &vi.bytes[len..],
            vi.address + len as u64,
            0xe9,
            self.victim + len as u64,
        );
    }
    pub(super) fn images_recording(&self, heads: &BTreeMap<u64, Head>, images: &[Image]) {
        let selected = &heads[&self.selected];
        let victim = &heads[&self.victim];
        let si = &images[self.selected_image as usize];
        let vi = &images[self.victim_image as usize];
        assert_eq!(selected.route, si.address);
        assert_eq!(
            selected
                .walk
                .iter()
                .filter(|(_, next, _)| *next == recording::CORE_HOOK)
                .count(),
            1
        );
        assert_eq!((victim.route, victim.body), (vi.address, vi.address));
        assert!(victim.walk.is_empty());
        assert_eq!(victim.target, 0);
        let src = source(self.victim);
        let offset = (self.victim - src.pc) as usize;
        let len = usize::from(head(self.victim).length);
        assert_eq!(victim.bytes, src.bytes[offset..offset + len]);
        assert_eq!(vi.bytes.len(), len + 5);
        assert_eq!(vi.bytes[..len], victim.bytes);
        transfer(
            &vi.bytes[len..],
            vi.address + len as u64,
            0xe9,
            self.victim + len as u64,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use li2core::contracts::{AddressRange, LegalEntry};
    use li2core::planner::HookSemantics;
    use li2core::quiescent::{AllocationPolicy, SearchPolicy};

    const S: u64 = 0x40186c;
    const V: u64 = 0x4018e6;
    const SI: u64 = 0x6000000;
    const VI: u64 = 0x7000000;
    fn policy(pc: u64) -> AllocationPolicy {
        AllocationPolicy {
            ranges: vec![AddressRange::new(pc, 65536).unwrap()],
            preferred_address: Some(pc),
            max_candidates: 65536,
            max_mappings: 1,
            max_mapped_bytes: 65536,
        }
    }
    fn site(pc: u64) -> SelectedSite {
        let h = head(pc);
        let src = source(pc);
        let block = original_block(h);
        SelectedSite {
            id: seed::HEADS.iter().position(|h| h.pc == pc).unwrap() as u64 + 1,
            pc,
            length: h.length,
            file_offset: src.file_offset + pc - src.pc,
            snapshot: AddressRange::new(src.pc, src.bytes.len()).unwrap(),
            function: AddressRange::new(src.pc, src.bytes.len()).unwrap(),
            block: AddressRange::new(block.0, (block.1 - block.0) as usize).unwrap(),
            hook: 2,
            semantics: HookSemantics::Observe,
            forced: None,
            selected_allocation: policy(SI),
            victim_allocation: policy(VI),
            search: SearchPolicy {
                max_upstream_bytes: 64,
                max_displaced_bytes: 256,
                max_sites: 64,
                ..SearchPolicy::default()
            },
            forced_victim: None,
            max_victims: 256,
            max_pairs: 4096,
            heads: seed::HEADS
                .iter()
                .filter(|h| h.function == src.function)
                .map(|h| LegalEntry {
                    address: h.pc,
                    requires_endbr: false,
                })
                .collect(),
            completeness: EntryCompleteness::Complete,
            resumes: ResumeObligation::NoneExist,
            provenance: ContentId::of(b"synthetic owner declaration"),
        }
    }
    fn near(pc: u64, target: u64) -> Vec<u8> {
        let mut b = vec![0xe9];
        b.extend_from_slice(
            &i32::try_from(i128::from(target) - i128::from(pc + 5))
                .unwrap()
                .to_le_bytes(),
        );
        b
    }
    struct Fixture {
        sites: Vec<SelectedSite>,
        ledger: Vec<Vec<String>>,
        report: Vec<Vec<String>>,
        overlay: Vec<u8>,
        heads: BTreeMap<u64, Head>,
        images: Vec<Image>,
    }
    impl Fixture {
        fn new() -> Self {
            // Pure member-section fixture, not a complete artifact. Main still
            // requires whole ELF/metadata/all selected rows and router absence.
            let sites = vec![site(S), site(0x401946)];
            let mut overlay = vec![0; 0x2000];
            for src in seed::ORIGINAL_RANGES {
                overlay[src.file_offset as usize..src.file_offset as usize + src.bytes.len()]
                    .copy_from_slice(src.bytes);
            }
            // Prior disjoint edits in *both* owners must be retained in reads.
            overlay[0x186e] = 0x90;
            overlay[0x194d] = 0x90;
            let raw =
                &source(V).bytes[(V - source(V).pc) as usize..(V - source(V).pc) as usize + 10];
            assert_eq!(raw, &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]);
            let mut victim_image = raw.to_vec();
            victim_image.extend(near(VI + 10, V + 10));
            let mut selected_image =
                helper(SI, S, SavedExtendedStateLayout::describe_target_fxsave64());
            let body = SI + selected_image.len() as u64;
            let operation = near(body, 0x4018c6);
            selected_image.extend(&operation);
            selected_image.extend(near(body + 5, S + 2));
            let mut selected_walk = Vec::new();
            let mut at = SI;
            while at < body {
                let i = decoded(&selected_image[(at - SI) as usize..], at);
                let next = at + i.len() as u64;
                let b = selected_image[(at - SI) as usize..(next - SI) as usize].to_vec();
                if i.flow_control() == FlowControl::Call {
                    assert_eq!(i.near_branch_target(), HOOK);
                    selected_walk.push((at, HOOK, b));
                    selected_walk.push((HOOK, next, vec![0xc3]));
                } else {
                    selected_walk.push((at, next, b));
                }
                at = next;
            }
            let heads = BTreeMap::from([
                (
                    S,
                    Head {
                        logical: S,
                        route: SI,
                        body,
                        bytes: operation,
                        target: 0x4018c6,
                        walk: selected_walk,
                    },
                ),
                (
                    V,
                    Head {
                        logical: V,
                        route: VI,
                        body: VI,
                        bytes: raw.to_vec(),
                        target: 0,
                        walk: vec![],
                    },
                ),
            ]);
            // Physical victim and its image come first: image zero is NOT the hook image.
            let images = vec![
                Image {
                    address: VI,
                    bytes: victim_image,
                },
                Image {
                    address: SI,
                    bytes: selected_image,
                },
            ];
            let mut ledger = Vec::new();
            for (ordinal, pc, image, image_id) in [(0, V, VI, 0), (1, S, SI, 1)] {
                let src = source(pc);
                let patch = if pc == S {
                    vec![0xeb, 0x7d]
                } else {
                    let mut b = near(V, VI);
                    b.extend(near(V + 5, SI));
                    b
                };
                let texts = [
                    format!(
                        "step\t15\t{ordinal}\trelocation\t{pc}\t{pc}\t{pc}\t{}",
                        pc + u64::from(head(pc).length)
                    ),
                    format!(
                        "step-read\t15\t{ordinal}\t{}\t{}",
                        src.pc,
                        hex(current(&overlay, src.pc, src.bytes.len()))
                    ),
                    format!("semantic-write\t15\t{ordinal}\t{pc}\t{}", hex(&patch)),
                    format!("entry-preserved\t15\t{ordinal}\t{pc}"),
                    format!("allocation\t15\t{ordinal}\t{image}\t{}\t4096", image + 4096),
                    format!(
                        "original-file-dependency\t{}\t{}",
                        src.file_offset,
                        src.file_offset + src.bytes.len() as u64
                    ),
                    format!(
                        "image\t{image_id}\t15\t{image}\t{}\t{}\timage-{image_id:04}.bin",
                        images[image_id].bytes.len(),
                        hash(&images[image_id].bytes)
                    ),
                    format!("route\t{image_id}\t{pc}\t{image}"),
                ];
                ledger.extend(
                    texts
                        .iter()
                        .map(|r| r.split('\t').map(str::to_owned).collect::<Vec<_>>()),
                );
            }
            let mut report = vec![vec![String::new()]; 6];
            for (id, tactic) in [(15, "T3"), (81, "B1")] {
                report.push(vec![
                    id.to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    tactic.into(),
                ]);
            }
            Self {
                sites,
                ledger,
                report,
                overlay,
                heads,
                images,
            }
        }
        fn check(&self) {
            let ledger: Vec<Vec<_>> = self
                .ledger
                .iter()
                .map(|r| r.iter().map(String::as_str).collect())
                .collect();
            let report: Vec<Vec<_>> = self
                .report
                .iter()
                .map(|r| r.iter().map(String::as_str).collect())
                .collect();
            let pairs = pairs(&self.sites, &ledger, &report);
            assert_eq!(pairs.len(), 1);
            let mut overlay = self.overlay.clone();
            for step in ledger.iter().filter(|r| r[0] == "step") {
                check_current_read(&self.sites, &ledger, step, &overlay);
                pairs[0].before_step(&self.sites, &ledger, step, &overlay);
                let w = member_row(&ledger, step, "semantic-write");
                let pc = n(w[3]);
                let src = source(pc);
                let at = (src.file_offset + pc - src.pc) as usize;
                let b = unhex(w[4]);
                overlay[at..at + b.len()].copy_from_slice(&b);
            }
            pairs[0].images(&self.heads, &self.images);
        }
        fn row(&mut self, tag: &str, ordinal: &str) -> &mut Vec<String> {
            self.ledger
                .iter_mut()
                .find(|r| r[0] == tag && r[2] == ordinal)
                .unwrap()
        }
        fn refuses(self) {
            assert!(std::panic::catch_unwind(|| self.check()).is_err());
        }
    }

    #[test]
    fn two_declared_owners_keep_current_reads_and_callback_free_id57() {
        Fixture::new().check();
    }
    #[test]
    fn missing_conflicting_or_incomplete_owner_cannot_supply_a_victim() {
        let mut f = Fixture::new();
        f.sites.pop();
        f.report.pop();
        f.refuses();
        let mut f = Fixture::new();
        f.sites[1].heads.pop();
        f.refuses();
        let mut f = Fixture::new();
        f.sites[1].resumes = ResumeObligation::Unresolved;
        f.refuses();
        let mut f = Fixture::new();
        f.sites[1].block = AddressRange::new(0x401946, 2).unwrap();
        f.refuses();
        let mut f = Fixture::new();
        let mut duplicate = f.sites[1].clone();
        duplicate.provenance = ContentId::of(b"different owner");
        f.sites.push(duplicate);
        f.refuses();
    }
    #[test]
    fn full_current_reads_cannot_shrink_or_revert_inherited_edits() {
        let mut f = Fixture::new();
        f.row("step-read", "0")[4].truncate(20);
        f.refuses();
        let mut f = Fixture::new();
        f.row("step-read", "0")[4] = hex(source(V).bytes);
        f.refuses();
        let mut f = Fixture::new();
        f.row("step-read", "1")[4] = hex(source(S).bytes);
        f.refuses();
        let mut f = Fixture::new();
        f.row("step-read", "0")[3] = source(S).pc.to_string();
        f.refuses();
    }
    #[test]
    fn changed_original_in_either_displaced_interval_refuses_before_pair_writes() {
        for pc in [S, V] {
            let mut f = Fixture::new();
            let src = source(pc);
            f.overlay[(src.file_offset + pc - src.pc) as usize] ^= 1;
            let ordinal = if pc == V { "0" } else { "1" };
            let replacement = hex(current(&f.overlay, src.pc, src.bytes.len()));
            f.row("step-read", ordinal)[4] = replacement;
            f.refuses();
        }
    }
    #[test]
    fn entry_dependency_role_and_original_boundary_mutations_refuse() {
        let mut f = Fixture::new();
        f.row("entry-preserved", "0")[3] = (V + 5).to_string();
        f.refuses();
        let mut f = Fixture::new();
        f.row("step", "0")[7] = (V + 9).to_string();
        f.refuses();
        let mut f = Fixture::new();
        f.row("step", "0")[4] = S.to_string();
        f.refuses();
        let mut f = Fixture::new();
        f.ledger.retain(|r| r[0] != "original-file-dependency");
        f.refuses();
        let mut f = Fixture::new();
        f.sites[0].victim_allocation = policy(SI);
        f.refuses();
        let mut f = Fixture::new();
        f.report[6][4] = "B1".into();
        f.refuses();
    }
    #[test]
    fn selected_relay_and_both_e9_targets_are_exact() {
        let mut f = Fixture::new();
        f.row("semantic-write", "1")[4] = "eb7c".into();
        f.refuses();
        for at in [1, 6] {
            let mut f = Fixture::new();
            let mut b = unhex(&f.row("semantic-write", "0")[4]);
            b[at] ^= 1;
            f.row("semantic-write", "0")[4] = hex(&b);
            f.refuses();
        }
        let mut f = Fixture::new();
        f.row("route", &V.to_string())[3] = SI.to_string();
        f.refuses();
    }
    #[test]
    fn auxiliary_hook_operation_bytes_and_continuation_are_not_exempted() {
        let mut f = Fixture::new();
        f.heads
            .get_mut(&V)
            .unwrap()
            .walk
            .push((VI, HOOK, vec![0xe8]));
        f.refuses();
        let mut f = Fixture::new();
        f.heads.get_mut(&V).unwrap().body += 1;
        f.refuses();
        let mut f = Fixture::new();
        f.heads.get_mut(&V).unwrap().bytes[0] ^= 1;
        f.refuses();
        let mut f = Fixture::new();
        f.images[0].bytes[11] ^= 1;
        f.refuses();
    }
}
